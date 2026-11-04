/*
 * Linux-only supervision primitives (no cgroups): child subreaper, pidfd, PR_SET_PDEATHSIG's sharp edges, a PID
 * namespace as a kill-everything boundary, signalfd, and oom_score_adj. JSON lines; never asserts.
 * Build: cc -O1 -Wall -Wextra -pthread -o linux_proc linux_proc.c
 */
#include "../posix/common.h"
#include <pthread.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>

#define PROBE "linux_proc"

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif
static int pidfd_open_(pid_t pid, unsigned flags) { return (int)syscall(SYS_pidfd_open, pid, flags); }
static int pidfd_send_signal_(int fd, int sig) { return (int)syscall(SYS_pidfd_send_signal, fd, sig, NULL, 0); }
static const char *bstr(int b) { return b ? "true" : "false"; }

static double cpu_children_ms(void) {
  struct rusage ru;
  getrusage(RUSAGE_CHILDREN, &ru);
  return ru.ru_utime.tv_sec * 1000.0 + ru.ru_utime.tv_usec / 1000.0 + ru.ru_stime.tv_sec * 1000.0 + ru.ru_stime.tv_usec / 1000.0;
}

static void burn(int ms) { double end = now_ms() + ms; volatile unsigned long x = 0; while (now_ms() < end) for (int i = 0; i < 100000; i++) x += (unsigned long)i; }

/* ---------------------------------------------------------------- subreaper */
static void exp_subreaper(void) {
  fflush(stdout);
  pid_t S = fork(); /* run inside a child so the probe itself stays a normal process */
  if (S == 0) {
    int rc = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    int p[2];
    (void)!pipe(p);
    double cpu_before = cpu_children_ms();
    pid_t m = fork();
    if (m == 0) {
      int inherited = -1;
      prctl(PR_GET_CHILD_SUBREAPER, &inherited, 0, 0, 0);
      pid_t o = fork();
      if (o == 0) {
        pid_t mid_parent = getppid();
        sleep_ms(150); /* the middle process is gone by now */
        pid_t adopter = getppid();
        burn(300);
        char b[96];
        int n = snprintf(b, sizeof b, "%d %d %d %d\n", (int)getpid(), (int)mid_parent, (int)adopter, inherited);
        (void)!write(p[1], b, (size_t)n);
        _exit(5);
      }
      _exit(0);
    }
    close(p[1]);
    int st;
    waitpid(m, &st, 0);
    char b[96] = "";
    ssize_t n = read_timeout(p[0], b, sizeof b - 1, 3000);
    b[n > 0 ? n : 0] = 0;
    int opid = 0, midp = 0, adopter = 0, inh = -1;
    sscanf(b, "%d %d %d %d", &opid, &midp, &adopter, &inh);
    pid_t r = waitpid(-1, &st, 0); /* the orphan is now our child */
    char sbuf[64];
    status_text(st, sbuf, sizeof sbuf);
    double cpu_after = cpu_children_ms();
    emit(PROBE, "child_subreaper_adopts_orphans",
         "\"prctl_rc\":%d,\"orphan_parent_after_middle_exit_is_subreaper\":%s,\"subreaper_flag_in_forked_child\":%d,\"waitpid_minus1_got_orphan\":%s,\"orphan_status\":\"%s\","
         "\"rusage_children_gained_ms\":%.1f,\"orphan_burned_ms\":300",
         rc, bstr(adopter == getpid()), inh, bstr(r == opid), sbuf, cpu_after - cpu_before);
    _exit(0);
  }
  char st[64];
  reap_blocking(S, 5000, st, sizeof st);
}

/* ---------------------------------------------------------------- pidfd */
static void exp_pidfd(void) {
  /* a child, a pidfd for it, then: zombie, reaped */
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) { pause(); _exit(0); }
  int fd = pidfd_open_(c, 0);
  int fd_nb = pidfd_open_(c, PIDFD_NONBLOCK);
  siginfo_t si;
  memset(&si, 0, sizeof si);
  int wnb = waitid(P_PIDFD, (id_t)fd_nb, &si, WEXITED); /* nonblocking pidfd, no WNOHANG: EAGAIN while alive (5.10+) */
  int wnb_errno = wnb < 0 ? errno : 0;
  int wnb_reported = si.si_pid;
  int kill_rc = pidfd_send_signal_(fd, SIGKILL);
  struct pollfd pf = {fd, POLLIN, 0};
  int pr = poll(&pf, 1, 2000);
  /* now a zombie */
  int zombie_signal = pidfd_send_signal_(fd, 0);
  int zombie_signal_errno = zombie_signal < 0 ? errno : 0;
  memset(&si, 0, sizeof si);
  int w1 = waitid(P_PIDFD, (id_t)fd, &si, WEXITED);
  int w1_code = si.si_code, w1_status = si.si_status;
  int after_reap = pidfd_send_signal_(fd, 0);
  int after_reap_errno = after_reap < 0 ? errno : 0;
  int w2 = waitid(P_PIDFD, (id_t)fd, &si, WEXITED | WNOHANG);
  int w2_errno = w2 < 0 ? errno : 0;
  pf.revents = 0;
  int pr2 = poll(&pf, 1, 0);
  int reopen = pidfd_open_(c, 0);
  int reopen_errno = reopen < 0 ? errno : 0;
  emit(PROBE, "pidfd_lifecycle",
       "\"pidfd_open_ok\":%s,\"waitid_pidfd_nonblock_live\":\"%s\",\"waitid_nonblock_si_pid\":%d,\"pidfd_send_signal_kill\":%d,\"poll_readable_after_exit\":%s,"
       "\"signal0_to_zombie\":\"%s\",\"waitid_pidfd_reaps\":%s,\"si_code_CLD_KILLED\":%s,\"si_status\":%d,\"signal0_after_reap\":\"%s\",\"waitid_again\":\"%s\","
       "\"poll_after_reap_revents\":%d,\"pidfd_open_after_reap\":\"%s\"",
       bstr(fd >= 0), wnb < 0 ? errno_name(wnb_errno) : "returned 0", wnb_reported, kill_rc, bstr(pr == 1 && (pf.revents & POLLIN)),
       zombie_signal == 0 ? "OK" : errno_name(zombie_signal_errno), bstr(w1 == 0), bstr(w1_code == CLD_KILLED), w1_status,
       after_reap == 0 ? "OK" : errno_name(after_reap_errno), w2 < 0 ? errno_name(w2_errno) : "returned 0", pr2 > 0 ? pf.revents : 0,
       reopen >= 0 ? "OK" : errno_name(reopen_errno));
  close(fd); close(fd_nb);
  if (reopen >= 0) close(reopen);

  /* a pidfd for a process that is not our child (a grandchild) */
  int p[2];
  (void)!pipe(p);
  fflush(stdout);
  pid_t m = fork();
  if (m == 0) {
    pid_t g = fork();
    if (g == 0) { sleep_ms(400); _exit(3); }
    (void)!write(p[1], &g, sizeof g);
    pause();
    _exit(0);
  }
  pid_t g = 0;
  (void)!read(p[0], &g, sizeof g);
  int gfd = pidfd_open_(g, 0);
  double t0 = now_ms();
  struct pollfd gp = {gfd, POLLIN, 0};
  int gpr = poll(&gp, 1, 3000);
  double gdt = now_ms() - t0;
  int gw = waitid(P_PIDFD, (id_t)gfd, &si, WEXITED | WNOHANG);
  int gw_errno = gw < 0 ? errno : 0;
  emit(PROBE, "pidfd_for_a_grandchild",
       "\"pidfd_open_ok\":%s,\"poll_saw_exit\":%s,\"ms_waited\":%.0f,\"waitid_by_non_parent\":\"%s\"",
       bstr(gfd >= 0), bstr(gpr == 1), gdt, gw < 0 ? errno_name(gw_errno) : "returned 0");
  close(gfd);
  kill(m, SIGKILL);
  waitpid(m, NULL, 0);
  close(p[0]); close(p[1]);

  /* CLONE_PIDFD via clone3: a pidfd that exists before the child can run or be reaped */
  struct { uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; } ca;
  memset(&ca, 0, sizeof ca);
  int cfd = -1;
  ca.flags = 0x00001000 /* CLONE_PIDFD */;
  ca.pidfd = (uint64_t)(uintptr_t)&cfd;
  ca.exit_signal = SIGCHLD;
  fflush(stdout);
  long r = syscall(SYS_clone3, &ca, 64);
  if (r == 0) _exit(9);
  int ce = r < 0 ? errno : 0;
  int cw = -1, cstatus = -1;
  if (r > 0) { memset(&si, 0, sizeof si); cw = waitid(P_PIDFD, (id_t)cfd, &si, WEXITED); cstatus = si.si_status; }
  emit(PROBE, "clone3_clone_pidfd", "\"clone3_errno\":\"%s\",\"pidfd\":%d,\"waitid_pidfd_rc\":%d,\"exit_status\":%d", errno_name(ce), cfd, cw, cstatus);
  if (cfd >= 0) close(cfd);
}

/* ---------------------------------------------------------------- PR_SET_PDEATHSIG */
static volatile sig_atomic_t g_got;
static void on_usr1(int s) { (void)s; g_got = 1; }

/* "parent" means the thread that forked: the signal fires when that thread exits, even though the process lives */
static void *forking_thread(void *arg) {
  int *fds = (int *)arg;
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    prctl(PR_SET_PDEATHSIG, SIGUSR1);
    (void)!write(fds[1], "r", 1);
    for (int i = 0; i < 100 && !g_got; i++) sleep_ms(10);
    (void)!write(fds[1], g_got ? "S" : "N", 1);
    _exit(0);
  }
  char ch;
  (void)!read(fds[0], &ch, 1); /* child armed */
  return (void *)(intptr_t)c;  /* the thread exits; the process does not */
}

static void exp_pdeathsig(void) {
  int fds[2];
  (void)!pipe(fds);
  pthread_t t;
  pthread_create(&t, NULL, forking_thread, fds);
  void *ret;
  pthread_join(t, &ret);
  pid_t c = (pid_t)(intptr_t)ret;
  char ch = '?';
  read_timeout(fds[0], &ch, 1, 2000);
  char st[64];
  reap_blocking(c, 2000, st, sizeof st);
  emit(PROBE, "pdeathsig_fires_when_the_forking_thread_exits", "\"signal_received_while_parent_process_alive\":%s", bstr(ch == 'S'));
  close(fds[0]); close(fds[1]);

  /* armed after the parent already died: never fires; getppid shows it */
  int p[2];
  (void)!pipe(p);
  fflush(stdout);
  pid_t m = fork();
  if (m == 0) {
    pid_t c2 = fork();
    if (c2 == 0) {
      sleep_ms(150); /* parent m is gone */
      int ppid_before = getppid();
      struct sigaction sa;
      memset(&sa, 0, sizeof sa);
      sa.sa_handler = on_usr1;
      sigaction(SIGUSR1, &sa, NULL);
      prctl(PR_SET_PDEATHSIG, SIGUSR1);
      sleep_ms(300);
      char b[64];
      int n = snprintf(b, sizeof b, "%d %d\n", ppid_before, (int)g_got);
      (void)!write(p[1], b, (size_t)n);
      _exit(0);
    }
    _exit(0);
  }
  waitpid(m, NULL, 0);
  close(p[1]);
  char b[64] = "";
  ssize_t n = read_timeout(p[0], b, sizeof b - 1, 3000);
  b[n > 0 ? n : 0] = 0;
  int ppid_before = -1, got = -1;
  sscanf(b, "%d %d", &ppid_before, &got);
  emit(PROBE, "pdeathsig_armed_after_parent_died", "\"ppid_at_arming\":%d,\"signal_received\":%s,\"note\":\"check getppid() after prctl\"", ppid_before, bstr(got == 1));
  close(p[0]);

  /* survives exec? the child arms it, execs /bin/sh which prints whether it got the signal when the parent dies */
  int q[2];
  (void)!pipe(q);
  fflush(stdout);
  pid_t m2 = fork();
  if (m2 == 0) {
    pid_t c3 = fork();
    if (c3 == 0) {
      prctl(PR_SET_PDEATHSIG, SIGTERM);
      dup2(q[1], 1);
      execl("/bin/sh", "sh", "-c", "trap 'echo TERM; exit 0' TERM; echo up; i=0; while [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done; echo none", (char *)NULL);
      _exit(127);
    }
    sleep_ms(300);
    _exit(0); /* parent of the exec'd shell dies */
  }
  close(q[1]);
  waitpid(m2, NULL, 0);
  char out[128];
  int eof;
  size_t on = drain_until(q[0], out, sizeof out, 4000, &eof);
  out[on] = 0;
  for (char *x = out; *x; x++) if (*x == '\n') *x = ' ';
  emit(PROBE, "pdeathsig_kept_across_exec", "\"exec_d_shell_printed\":\"%s\"", out);
  close(q[0]);
}

/* ---------------------------------------------------------------- PID namespace */
static void exp_pidns(void) {
  int p[2];
  (void)!pipe(p);
  fflush(stdout);
  pid_t outer = fork();
  if (outer == 0) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    int u = unshare(CLONE_NEWUSER | CLONE_NEWPID);
    int ue = u < 0 ? errno : 0;
    int uidmap_errno = -1;
    if (u == 0) {
      char m[64];
      int fd = open("/proc/self/uid_map", O_WRONLY);
      int n = snprintf(m, sizeof m, "0 %d 1\n", (int)uid);
      uidmap_errno = fd < 0 ? errno : (write(fd, m, (size_t)n) < 0 ? errno : 0);
      if (fd >= 0) close(fd);
      fd = open("/proc/self/setgroups", O_WRONLY);
      if (fd >= 0) { (void)!write(fd, "deny", 4); close(fd); }
      fd = open("/proc/self/gid_map", O_WRONLY);
      n = snprintf(m, sizeof m, "0 %d 1\n", (int)gid);
      if (fd >= 0) { (void)!write(fd, m, (size_t)n); close(fd); }
    }
    char b[160];
    if (u < 0) {
      int n = snprintf(b, sizeof b, "unshare=%s\n", errno_name(ue));
      (void)!write(p[1], b, (size_t)n);
      _exit(0);
    }
    pid_t init = fork(); /* pid 1 of the new namespace */
    if (init == 0) {
      pid_t d = fork();
      if (d == 0) { setsid(); if (fork() == 0) { for (;;) pause(); } _exit(0); } /* a daemonized process inside */
      pid_t k = fork();
      if (k == 0) { for (;;) pause(); }
      sleep_ms(100);
      int n = snprintf(b, sizeof b, "unshare=OK uid_map_write=%s init_sees_itself_as=%d\n", errno_name(uidmap_errno), (int)getpid());
      (void)!write(p[1], b, (size_t)n);
      for (;;) pause();
    }
    /* report the host pids of everything in the namespace by walking /proc for our user is overkill: count via the
     * namespace's own init, which we kill now */
    sleep_ms(300);
    char ns_path[64];
    snprintf(ns_path, sizeof ns_path, "/proc/%d/ns/pid", (int)init);
    double t0 = now_ms();
    kill(init, SIGKILL);
    int st;
    waitpid(init, &st, 0);
    double dt = now_ms() - t0;
    sleep_ms(200);
    /* any process left in that namespace? scan /proc for processes whose ns/pid matches */
    (void)ns_path;
    int n = snprintf(b, sizeof b, "init_killed_ms=%.1f\n", dt);
    (void)!write(p[1], b, (size_t)n);
    _exit(0);
  }
  close(p[1]);
  char out[512];
  int eof;
  size_t n = drain_until(p[0], out, sizeof out, 5000, &eof);
  out[n] = 0;
  for (char *x = out; *x; x++) if (*x == '\n') *x = ' ';
  char st[64];
  reap_blocking(outer, 3000, st, sizeof st);
  char restrict_[16] = "absent", maxns[32] = "?";
  int fd = open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", O_RDONLY);
  if (fd >= 0) { ssize_t r = read(fd, restrict_, sizeof restrict_ - 1); restrict_[r > 0 ? r : 0] = 0; restrict_[strcspn(restrict_, "\n")] = 0; close(fd); }
  fd = open("/proc/sys/user/max_user_namespaces", O_RDONLY);
  if (fd >= 0) { ssize_t r = read(fd, maxns, sizeof maxns - 1); maxns[r > 0 ? r : 0] = 0; maxns[strcspn(maxns, "\n")] = 0; close(fd); }
  emit(PROBE, "pid_namespace_init_death", "\"apparmor_restrict_unprivileged_userns\":\"%s\",\"max_user_namespaces\":\"%s\",\"report\":\"%s\"", restrict_, maxns, out);
}

/* the namespace kill-all, measured from outside: are the namespace's processes gone after its init is killed? */
static void exp_pidns_survivors(void) {
  int p[2];
  (void)!pipe(p);
  fflush(stdout);
  pid_t outer = fork();
  if (outer == 0) {
    uid_t uid = getuid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID) < 0) { _exit(1); }
    char m[64];
    int fd = open("/proc/self/uid_map", O_WRONLY);
    int n = snprintf(m, sizeof m, "0 %d 1\n", (int)uid);
    if (fd >= 0) { (void)!write(fd, m, (size_t)n); close(fd); }
    pid_t init = fork();
    if (init == 0) {
      for (int i = 0; i < 3; i++) if (fork() == 0) { setsid(); for (;;) pause(); }
      for (;;) pause();
    }
    /* the outer process is outside the new namespace but sees host pids of its children */
    (void)!write(p[1], &init, sizeof init);
    for (;;) pause();
  }
  close(p[1]);
  pid_t init = 0;
  if (read_timeout(p[0], &init, sizeof init, 3000) != (ssize_t)sizeof init) {
    emit(PROBE, "pid_namespace_survivors", "\"skipped\":\"unshare failed\"");
    kill(outer, SIGKILL); waitpid(outer, NULL, 0);
    return;
  }
  sleep_ms(200);
  /* find the namespace members: processes whose /proc/<pid>/status NSpid has two entries and whose PPid chain is init */
  char nsself[128] = "";
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/ns/pid", (int)init);
  ssize_t l = readlink(path, nsself, sizeof nsself - 1);
  nsself[l > 0 ? l : 0] = 0;
  int members_before = 0, members_after = 0;
  for (int pass = 0; pass < 2; pass++) {
    if (pass == 1) { kill(init, SIGKILL); sleep_ms(300); }
    int count = 0;
    for (pid_t q = 2; q < 4194304 && q < init + 50; q++) {
      char lp[64], ln[128];
      snprintf(lp, sizeof lp, "/proc/%d/ns/pid", (int)q);
      ssize_t k = readlink(lp, ln, sizeof ln - 1);
      if (k <= 0) continue;
      ln[k] = 0;
      char sp[64], sb[64];
      snprintf(sp, sizeof sp, "/proc/%d/stat", (int)q);
      int sfd = open(sp, O_RDONLY);
      if (sfd < 0) continue;
      ssize_t sr = read(sfd, sb, sizeof sb - 1);
      close(sfd);
      sb[sr > 0 ? sr : 0] = 0;
      char *rp = strrchr(sb, ')');
      if (rp && rp[2] == 'Z') continue;
      if (strcmp(ln, nsself) == 0) count++;
    }
    if (pass == 0) members_before = count; else members_after = count;
  }
  emit(PROBE, "pid_namespace_survivors", "\"members_before_init_killed\":%d,\"members_alive_300ms_after\":%d", members_before, members_after);
  kill(outer, SIGKILL);
  waitpid(outer, NULL, 0);
  close(p[0]);
}

/* ---------------------------------------------------------------- signalfd */
static void exp_signalfd(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  sigprocmask(SIG_BLOCK, &set, NULL);
  int sfd = signalfd(-1, &set, SFD_CLOEXEC);
  int gate[2];
  (void)!pipe(gate);
  pid_t kids[12];
  fflush(stdout);
  for (int i = 0; i < 12; i++) {
    kids[i] = fork();
    if (kids[i] == 0) { char c; close(gate[1]); (void)!read(gate[0], &c, 1); _exit(i); }
  }
  close(gate[0]);
  sleep_ms(100);
  close(gate[1]);
  sleep_ms(300);
  struct signalfd_siginfo si[16];
  ssize_t n = read(sfd, si, sizeof si);
  int records = n > 0 ? (int)(n / (ssize_t)sizeof si[0]) : 0;
  int reaped = 0, st;
  while (waitpid(-1, &st, WNOHANG) > 0) reaped++;
  emit(PROBE, "signalfd_sigchld_coalescing", "\"children\":12,\"signalfd_records\":%d,\"reaped_in_one_loop\":%d", records, reaped);
  close(sfd);
  sigprocmask(SIG_UNBLOCK, &set, NULL);
}

/* ---------------------------------------------------------------- oom_score_adj */
static int write_file(const char *path, const char *v) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) return errno;
  int e = write(fd, v, strlen(v)) < 0 ? errno : 0;
  close(fd);
  return e;
}

static void exp_oom_score_adj(void) {
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) { pause(); _exit(0); }
  char path[64], b[32] = "";
  snprintf(path, sizeof path, "/proc/%d/oom_score_adj", (int)c);
  int fd = open(path, O_RDONLY);
  ssize_t n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
  if (fd >= 0) close(fd);
  b[n > 0 ? n : 0] = 0;
  b[strcspn(b, "\n")] = 0;
  int up = write_file(path, "1000");
  int down = write_file(path, "0");
  int below = write_file(path, "-500");
  emit(PROBE, "oom_score_adj_of_a_child", "\"initial\":\"%s\",\"raise_to_1000\":\"%s\",\"lower_back_to_0\":\"%s\",\"lower_to_minus_500\":\"%s\"",
       b, errno_name(up), errno_name(down), errno_name(below));
  kill(c, SIGKILL);
  waitpid(c, NULL, 0);
}

int main(void) {
  watchdog(120);
  emit_header(PROBE);
  exp_subreaper();
  exp_pidfd();
  exp_pdeathsig();
  exp_pidns();
  exp_pidns_survivors();
  exp_signalfd();
  exp_oom_score_adj();
  return 0;
}
