/*
 * FreeBSD's process-management primitives, measured (explore-hard.yml, in a FreeBSD VM): process descriptors
 * (pdfork/pdkill/poll/EVFILT_PROCDESC, close-kills, PD_DAEMON, whether they show up in wait(-1) or send SIGCHLD),
 * the reaper (procctl PROC_REAP_*: orphans, status, pid list, tree kill, nested reapers, setsid escapees),
 * PROC_PDEATHSIG_CTL, kqueue NOTE_TRACK, and which posix_spawn extensions exist. One JSON line per case.
 */
#include "../posix/common.h"
#include <sys/param.h>
#include <sys/event.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <spawn.h>

#define P "fbsd_proc"

static volatile sig_atomic_t sigchld_count = 0;
static void on_chld(int s) { (void)s; sigchld_count++; }

static int alive(pid_t pid) { return kill(pid, 0) == 0 || errno == EPERM; }

static void pdfork_cases(void) {
  int pd = -1;
  sigchld_count = 0;
  pid_t pid = pdfork(&pd, 0);
  if (pid == 0) { sleep(60); _exit(0); }
  if (pid < 0) { emit(P, "pdfork", "\"errno\":\"%s\"", errno_name(errno)); return; }
  pid_t got = -1;
  pdgetpid(pd, &got);
  double t0 = now_ms();
  int kr = pdkill(pd, SIGTERM);
  struct pollfd pf = {pd, POLLHUP | POLLIN, 0};
  int pr = poll(&pf, 1, 5000);
  double t1 = now_ms();
  int st = 0;
  pid_t w = waitpid(pid, &st, WNOHANG);
  int werr = w < 0 ? errno : 0;
  char sts[64];
  status_text(st, sts, sizeof sts);
  emit(P, "pdfork_pdkill_poll", "\"pdgetpid_matches\":%s,\"pdkill\":%d,\"poll\":%d,\"revents\":%d,\"ms\":%.3f,"
       "\"waitpid_by_pid\":%d,\"waitpid_errno\":\"%s\",\"status\":\"%s\",\"sigchld\":%d",
       got == pid ? "true" : "false", kr, pr, pf.revents, t1 - t0, (int)(w == pid), errno_name(werr), sts, (int)sigchld_count);
  close(pd);

  /* does an exited pdfork child show up in wait(-1)? does it send SIGCHLD? */
  sigchld_count = 0;
  pid = pdfork(&pd, 0);
  if (pid == 0) _exit(7);
  sleep_ms(200);
  w = waitpid(-1, &st, WNOHANG);
  werr = w < 0 ? errno : 0;
  int w_matches = w == pid;
  struct kevent ev;
  int kq = kqueue();
  EV_SET(&ev, pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
  int kr2 = kevent(kq, &ev, 1, NULL, 0, NULL);
  int kerr = kr2 < 0 ? errno : 0;
  struct timespec ts = {1, 0};
  struct kevent out;
  int n = kevent(kq, NULL, 0, &out, 1, &ts);
  emit(P, "pdfork_exit_visibility", "\"wait_any_returned_it\":%s,\"wait_any_result\":%d,\"wait_any_errno\":\"%s\",\"sigchld\":%d,"
       "\"procdesc_kevent_add\":%d,\"add_errno\":\"%s\",\"events\":%d,\"exit_status_in_data\":%ld",
       w_matches ? "true" : "false", (int)w, errno_name(werr), (int)sigchld_count, kr2, errno_name(kerr), n, n == 1 ? (long)out.data : -1L);
  close(kq);
  close(pd);
  waitpid(pid, &st, WNOHANG);

  /* EVFILT_PROCDESC latency on a live child */
  pid = pdfork(&pd, 0);
  if (pid == 0) { sleep_ms(300); _exit(3); }
  kq = kqueue();
  EV_SET(&ev, pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
  kevent(kq, &ev, 1, NULL, 0, NULL);
  ts.tv_sec = 5;
  t0 = now_ms();
  n = kevent(kq, NULL, 0, &out, 1, &ts);
  emit(P, "pdfork_kevent_exit", "\"events\":%d,\"after_ms\":%.1f,\"data\":%ld,\"exit_code\":%d", n, now_ms() - t0,
       n == 1 ? (long)out.data : -1L, n == 1 ? WEXITSTATUS((int)out.data) : -1);
  close(kq);
  close(pd);

  /* closing the last descriptor kills the child, unless PD_DAEMON */
  for (int daemon = 0; daemon <= 1; daemon++) {
    pid = pdfork(&pd, daemon ? PD_DAEMON : 0);
    if (pid == 0) { sleep(60); _exit(0); }
    sleep_ms(50);
    t0 = now_ms();
    close(pd);
    int gone = 0;
    double waited = 0;
    while ((waited = now_ms() - t0) < 2000) {
      if (!alive(pid)) { gone = 1; break; }
      /* the zombie of a pdfork child: is it reaped by the kernel when the descriptor goes? */
      pid_t r = waitpid(pid, &st, WNOHANG);
      if (r == pid) { gone = 2; break; }
      sleep_ms(5);
    }
    status_text(st, sts, sizeof sts);
    emit(P, daemon ? "pdfork_close_pd_daemon" : "pdfork_close_kills", "\"gone\":%d,\"ms\":%.1f,\"status\":\"%s\"", gone, waited, gone == 2 ? sts : "");
    if (!gone) { kill(pid, SIGKILL); waitpid(pid, &st, 0); }
  }
}

/* writes pids of a tree to fd: middle forks a plain grandchild and a setsid() grandchild, reports both, exits */
static void make_orphans(int fd, int nested_reaper) {
  pid_t middle = fork();
  if (middle == 0) {
    if (nested_reaper) procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL);
    pid_t g1 = fork();
    if (g1 == 0) { sleep(60); _exit(0); }
    pid_t g2 = fork();
    if (g2 == 0) { setsid(); sleep(60); _exit(0); }
    pid_t pids[3] = {getpid(), g1, g2};
    write(fd, pids, sizeof pids);
    if (nested_reaper) { sleep(60); }
    _exit(0);
  }
}

static void reap_all(int timeout_ms, int *count) {
  double end = now_ms() + timeout_ms;
  int st;
  *count = 0;
  while (now_ms() < end) {
    pid_t r = waitpid(-1, &st, WNOHANG);
    if (r > 0) { (*count)++; continue; }
    if (r < 0 && errno == ECHILD) return;
    sleep_ms(2);
  }
}

static void reaper_cases(void) {
  int r = procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL);
  emit(P, "reap_acquire", "\"result\":%d,\"errno\":\"%s\"", r, errno_name(r == 0 ? 0 : errno));
  if (r != 0) return;

  for (int nested = 0; nested <= 1; nested++) {
    int p[2];
    pipe(p);
    make_orphans(p[1], nested);
    pid_t pids[3] = {0, 0, 0};
    read(p[0], pids, sizeof pids);
    close(p[0]); close(p[1]);
    int st;
    if (!nested) waitpid(pids[0], &st, 0);
    sleep_ms(100);

    struct procctl_reaper_status rs;
    memset(&rs, 0, sizeof rs);
    procctl(P_PID, getpid(), PROC_REAP_STATUS, &rs);
    struct procctl_reaper_pidinfo info[64];
    struct procctl_reaper_pids rp;
    memset(&rp, 0, sizeof rp);
    rp.rp_count = 64;
    rp.rp_pids = info;
    memset(info, 0, sizeof info);
    int gr = procctl(P_PID, getpid(), PROC_REAP_GETPIDS, &rp);
    char list[1024] = "";
    size_t len = 0;
    for (unsigned i = 0; gr == 0 && i < 64; i++) {
      if (!(info[i].pi_flags & REAPER_PIDINFO_VALID)) continue;
      len += (size_t)snprintf(list + len, sizeof list - len, "%s[%d,%d,%u]", len ? "," : "", (int)info[i].pi_pid,
                              (int)info[i].pi_subtree, info[i].pi_flags);
      if (len >= sizeof list) break;
    }
    struct procctl_reaper_kill rk;
    memset(&rk, 0, sizeof rk);
    rk.rk_sig = SIGKILL;
    rk.rk_flags = 0;
    double t0 = now_ms();
    int kr = procctl(P_PID, getpid(), PROC_REAP_KILL, &rk);
    int kerr = kr == 0 ? 0 : errno;
    double kill_ms = now_ms() - t0;
    /* each process's fate: reaped by us (with its status and when), or still not ours / alive after 2 s.
       A pid that is not our child yet (a nested reaper's descendant) answers ECHILD until it is reparented. */
    char fate[3][96];
    pid_t who[3] = {pids[0], pids[1], pids[2]};
    int done[3] = {nested ? 0 : 1, 0, 0};
    snprintf(fate[0], sizeof fate[0], "%s", nested ? "pending" : "reaped before the kill");
    snprintf(fate[1], sizeof fate[1], "pending");
    snprintf(fate[2], sizeof fate[2], "pending");
    double end = now_ms() + 2000;
    while (now_ms() < end && !(done[0] && done[1] && done[2])) {
      for (int i = 0; i < 3; i++) {
        if (done[i]) continue;
        int wst;
        pid_t r = waitpid(who[i], &wst, WNOHANG);
        if (r == who[i]) {
          char sts[64];
          status_text(wst, sts, sizeof sts);
          snprintf(fate[i], sizeof fate[i], "%s after %.2f ms", sts, now_ms() - t0);
          done[i] = 1;
        }
      }
      sleep_ms(1);
    }
    for (int i = 0; i < 3; i++) if (!done[i]) {
      int gone = kill(who[i], 0) != 0 && errno == ESRCH;
      snprintf(fate[i], sizeof fate[i], "%s", gone ? "gone, not reaped by us" : "still running after 2 s");
      if (!gone) kill(who[i], SIGKILL);
    }
    int leftovers;
    reap_all(500, &leftovers);
    emit(P, nested ? "reap_kill_nested_reaper" : "reap_kill_orphans",
         "\"status_children\":%u,\"status_descendants\":%u,\"status_flags\":%u,\"getpids\":%d,\"pids\":\"%s\","
         "\"kill_result\":%d,\"kill_errno\":\"%s\",\"rk_killed\":%u,\"rk_fpid\":%d,\"kill_call_ms\":%.3f,"
         "\"middle\":\"%s\",\"g1\":\"%s\",\"g2_setsid\":\"%s\",\"leftovers_reaped\":%d",
         rs.rs_children, rs.rs_descendants, rs.rs_flags, gr, list, kr, errno_name(kerr), rk.rk_killed, (int)rk.rk_fpid,
         kill_ms, fate[0], fate[1], fate[2], leftovers);
  }

  /* PROC_PDEATHSIG_CTL: a grandchild asks for SIGTERM when its parent dies; the parent then exits */
  int p[2];
  pipe(p);
  pid_t middle = fork();
  if (middle == 0) {
    pid_t g = fork();
    if (g == 0) {
      int sig = SIGTERM;
      int pr = procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sig);
      int got = 0;
      procctl(P_PID, 0, PROC_PDEATHSIG_STATUS, &got);
      int msg[3] = {(int)getpid(), pr, got};
      write(p[1], msg, sizeof msg);
      sleep(60);
      _exit(0);
    }
    sleep_ms(100);
    _exit(0);
  }
  int msg[3] = {0, -1, 0};
  read(p[0], msg, sizeof msg);
  int st;
  waitpid(middle, &st, 0);
  double t0 = now_ms();
  pid_t w = waitpid_timeout(msg[0], &st, 0, 2000);
  char sts[64];
  status_text(st, sts, sizeof sts);
  emit(P, "pdeathsig_ctl", "\"set_result\":%d,\"status_readback\":%d,\"grandchild_reaped\":%s,\"after_parent_exit_ms\":%.2f,\"status\":\"%s\"",
       msg[1], msg[2], w == msg[0] ? "true" : "false", now_ms() - t0, sts);
  if (w != msg[0]) { kill(msg[0], SIGKILL); waitpid(msg[0], &st, 0); }
  close(p[0]); close(p[1]);

  procctl(P_PID, getpid(), PROC_REAP_RELEASE, NULL);
}

/* kqueue NOTE_TRACK (removed on macOS): are forks of a watched child attached automatically? */
static void track_case(void) {
  int p[2];
  pipe(p);
  int go[2];
  pipe(go);
  pid_t child = fork();
  if (child == 0) {
    char c;
    read(go[0], &c, 1);
    pid_t g = fork();
    if (g == 0) { sleep_ms(200); _exit(5); }
    write(p[1], &g, sizeof g);
    int st;
    waitpid(g, &st, 0);
    _exit(0);
  }
  int kq = kqueue();
  struct kevent ev;
  EV_SET(&ev, child, EVFILT_PROC, EV_ADD, NOTE_EXIT | NOTE_FORK | NOTE_TRACK, 0, NULL);
  int ar = kevent(kq, &ev, 1, NULL, 0, NULL);
  int aerr = ar < 0 ? errno : 0;
  write(go[1], "x", 1);
  pid_t g = 0;
  read(p[0], &g, sizeof g);
  char seen[1024] = "";
  size_t len = 0;
  struct kevent out[8];
  struct timespec ts = {2, 0};
  for (int round = 0; round < 6; round++) {
    int n = kevent(kq, NULL, 0, out, 8, &ts);
    if (n <= 0) break;
    for (int i = 0; i < n; i++)
      len += (size_t)snprintf(seen + len, sizeof seen - len, "%s{\"ident\":%d,\"fflags\":\"0x%x\",\"data\":%ld,\"flags\":\"0x%x\"}",
                              len ? "," : "", (int)out[i].ident, out[i].fflags, (long)out[i].data, out[i].flags);
    if (len >= sizeof seen) break;
  }
  int st;
  waitpid(child, &st, 0);
  emit(P, "kqueue_note_track", "\"add\":%d,\"add_errno\":\"%s\",\"child\":%d,\"grandchild\":%d,\"events\":[%s]", ar,
       errno_name(aerr), (int)child, (int)g, seen);
  close(kq);
}

static void spawn_extensions(void) {
  emit(P, "posix_spawn_extensions", "\"POSIX_SPAWN_SETSID\":%s,\"addchdir_np\":%s,\"addclosefrom_np\":%s,\"addfchdir_np\":%s",
#ifdef POSIX_SPAWN_SETSID
       "true",
#else
       "false",
#endif
#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300000
       "true", "true", "true"
#else
       "false", "false", "false"
#endif
  );
}

int main(void) {
  watchdog(120);
  emit_header(P);
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_chld;
  sigaction(SIGCHLD, &sa, NULL);
  pdfork_cases();
  track_case();
  reaper_cases();
  spawn_extensions();
  return 0;
}
