/*
 * Can a macOS supervisor learn about a child's descendants as they are created? macOS has no cgroup and no job:
 * the candidates are kqueue EVFILT_PROC (NOTE_FORK, NOTE_TRACK) and enumeration (proc_listchildpids). The child is
 * spawned with POSIX_SPAWN_START_SUSPENDED so the filter is registered before it runs a single instruction.
 * Records JSON lines, never asserts.
 *
 *   fork_events_no_track      NOTE_FORK|NOTE_EXEC|NOTE_EXIT on the child; it forks 30 children: how many events, do
 *                             they say which children, does enumeration find all 30
 *   fork_events_with_track    the same plus NOTE_TRACK: does the registration succeed, are there NOTE_CHILD events
 *                             naming each new child, any NOTE_TRACKERR
 *   tree_*                    a grandchild generation (the child forks a helper that forks 15 more)
 *   daemonize_*               the child double-forks and calls setsid, its intermediate process exits: where does the
 *                             grandchild end up (ppid), can enumeration from the supervisor still find it, do the
 *                             events name it
 *
 * Build: cc -O1 -Wall -Wextra -o kqueue_track kqueue_track.c   (macOS only)
 */
#include "../posix/common.h"

#ifndef __APPLE__
int main(void) { printf("{\"probe\":\"kqueue_track\",\"case\":\"_unsupported\"}\n"); return 0; }
#else

#include <libproc.h>
#include <limits.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#define PROBE "kqueue_track"

#ifdef NOTE_TRACK
#define TRACK_FROM_HEADER 1
#else
#define TRACK_FROM_HEADER 0
#define NOTE_TRACK 0x00000001
#endif
#ifndef NOTE_TRACKERR
#define NOTE_TRACKERR 0x00000002
#endif
#ifndef NOTE_CHILD
#define NOTE_CHILD 0x00000004
#endif

extern char **environ;
static char g_self[PATH_MAX];

static void report_pid(int fd, pid_t p) { int v = (int)p; (void)!write(fd, &v, sizeof v); }

/* --forker N MODE FD */
static int forker_main(int n, int mode, int fd) {
  if (mode == 0) {
    for (int i = 0; i < n; i++) {
      pid_t c = fork();
      if (c == 0) { sleep_ms(3500); _exit(0); }
      report_pid(fd, c);
    }
    sleep_ms(3500);
  } else if (mode == 1) {
    pid_t a = fork();
    if (a == 0) {
      for (int i = 0; i < n / 2; i++) {
        pid_t g = fork();
        if (g == 0) { sleep_ms(3500); _exit(0); }
        report_pid(fd, g);
      }
      sleep_ms(3500);
      _exit(0);
    }
    report_pid(fd, a);
    for (int i = 0; i < n / 2; i++) {
      pid_t c = fork();
      if (c == 0) { sleep_ms(3500); _exit(0); }
      report_pid(fd, c);
    }
    sleep_ms(3500);
  } else {
    pid_t a = fork();
    if (a == 0) {
      setsid();
      pid_t d = fork();
      if (d == 0) { sleep_ms(3500); _exit(0); }
      report_pid(fd, d);
      _exit(0);
    }
    waitpid(a, NULL, 0);
    sleep_ms(3500);
  }
  return 0;
}

/* count the live descendants of root found by proc_listchildpids, recursively */
static int enum_descendants(pid_t root, pid_t *out, int cap, int depth) {
  pid_t buf[1024];
  memset(buf, 0, sizeof buf);
  int rv = proc_listchildpids(root, buf, (int)sizeof buf);
  (void)rv;
  int n = 0;
  for (int i = 0; i < 1024; i++) {
    if (buf[i] <= 0) break;
    if (n < cap) out[n] = buf[i];
    n++;
    if (depth < 4 && n < cap) {
      int sub = enum_descendants(buf[i], out + (n < cap ? n : cap), cap - (n < cap ? n : cap), depth + 1);
      n += sub;
    }
  }
  return n;
}

static int contains(const pid_t *a, int n, pid_t p) {
  for (int i = 0; i < n; i++) if (a[i] == p) return 1;
  return 0;
}

static int bsd_ppid(pid_t p) {
  struct proc_bsdinfo bi;
  memset(&bi, 0, sizeof bi);
  return proc_pidinfo(p, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == (int)sizeof bi ? (int)bi.pbi_ppid : -1;
}


static int bytes_contain(const char *hay, size_t n, const char *needle) {
  size_t k = strlen(needle);
  if (k == 0 || n < k) return 0;
  for (size_t i = 0; i + k <= n; i++) if (hay[i] == needle[0] && memcmp(hay + i, needle, k) == 0) return 1;
  return 0;
}

/* every process of this user whose original argument/environment block (KERN_PROCARGS2) contains needle */
static int env_marker_scan(const char *needle, pid_t *found, int cap, int *scanned, double *ms) {
  double t0 = now_ms();
  int hits = 0;
  *scanned = 0;
  int n = proc_listallpids(NULL, 0);
  if (n > 0) {
    int room = n + 64;
    pid_t *all = malloc((size_t)room * sizeof(pid_t));
    size_t bufcap = 1 << 20;
    char *buf = malloc(bufcap);
    n = proc_listallpids(all, room * (int)sizeof(pid_t));
    for (int i = 0; i < n; i++) {
      pid_t p = all[i];
      if (p <= 0 || p == getpid()) continue;
      int mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)p};
      size_t len = bufcap;
      if (sysctl(mib, 3, buf, &len, NULL, 0) != 0) continue;
      (*scanned)++;
      if (bytes_contain(buf, len, needle)) {
        if (hits < cap) found[hits] = p;
        hits++;
      }
    }
    free(all);
    free(buf);
  }
  *ms = now_ms() - t0;
  return hits;
}

static void run_case(const char *name, int mode, int n, int track) {
  int p[2];
  if (pipe(p) != 0) return;
  char token[96], needle[128];
  snprintf(token, sizeof token, "%d-%s", (int)getpid(), name);
  snprintf(needle, sizeof needle, "KT_MARKER=%s", token);
  setenv("KT_MARKER", token, 1);   /* inherited by everything the forker creates */
  int rfd = p[0], wfd = fcntl(p[1], F_DUPFD, 10);
  close(p[1]);
  set_cloexec(rfd);
  char nbuf[16], mbuf[16];
  snprintf(nbuf, sizeof nbuf, "%d", n);
  snprintf(mbuf, sizeof mbuf, "%d", mode);
  char *argv[] = {g_self, "--forker", nbuf, mbuf, "3", NULL};

  posix_spawnattr_t at;
  posix_spawn_file_actions_t fa;
  posix_spawnattr_init(&at);
  posix_spawn_file_actions_init(&fa);
  posix_spawnattr_setflags(&at, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&at, 0);
  posix_spawn_file_actions_adddup2(&fa, wfd, 3);
  posix_spawn_file_actions_addclose(&fa, wfd);
  pid_t child = 0;
  int rc = posix_spawn(&child, g_self, &fa, &at, argv, environ);
  posix_spawnattr_destroy(&at);
  posix_spawn_file_actions_destroy(&fa);
  close(wfd);
  if (rc != 0) { emit(PROBE, name, "\"posix_spawn_rc\":\"%s\"", errno_name(rc)); close(rfd); return; }

  int kq = kqueue();
  struct kevent ch, rc_ev;
  uint32_t fflags = NOTE_FORK | NOTE_EXEC | NOTE_EXIT | (track ? NOTE_TRACK : 0);
  EV_SET(&ch, (uintptr_t)child, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR | EV_RECEIPT, fflags, 0, NULL);
  struct timespec zero = {0, 0};
  memset(&rc_ev, 0, sizeof rc_ev);
  int kr = kevent(kq, &ch, 1, &rc_ev, 1, &zero);
  int reg_errno = kr < 0 ? errno : (kr == 1 && (rc_ev.flags & EV_ERROR) ? (int)rc_ev.data : 0);

  kill(child, SIGCONT);

  pid_t reported[256];
  int nrep = 0, want = mode == 1 ? n / 2 + 1 + n / 2 : n;
  if (mode == 2) want = 1;
  double end = now_ms() + 2500;
  while (nrep < want && now_ms() < end) {
    int v;
    ssize_t k = read_timeout(rfd, &v, sizeof v, 50);
    if (k == (ssize_t)sizeof v && nrep < 256) reported[nrep++] = (pid_t)v;
    else if (k == 0) break;
  }

  /* what do the events say? read until quiet for 300 ms */
  int evs_total = 0, fork_ev = 0, child_ev = 0, trackerr = 0, exec_ev = 0, exit_ev = 0, named = 0, error_ev = 0;
  pid_t seen[256];
  int nseen = 0;
  struct kevent ev[64];
  struct timespec to = {0, 300 * 1000000L};
  for (;;) {
    int k = kevent(kq, NULL, 0, ev, 64, &to);
    if (k <= 0) break;
    for (int i = 0; i < k; i++) {
      evs_total++;
      if (ev[i].flags & EV_ERROR) error_ev++;
      if (ev[i].fflags & NOTE_FORK) fork_ev++;
      if (ev[i].fflags & NOTE_EXEC) exec_ev++;
      if (ev[i].fflags & NOTE_EXIT) exit_ev++;
      if (ev[i].fflags & NOTE_TRACKERR) trackerr++;
      if (ev[i].fflags & NOTE_CHILD) {
        child_ev++;
        if (nseen < 256) seen[nseen++] = (pid_t)ev[i].ident;
      }
    }
  }
  for (int i = 0; i < nrep; i++) if (contains(seen, nseen, reported[i])) named++;

  pid_t found[512];
  int nfound = enum_descendants(child, found, 512, 0);
  int enum_hits = 0;
  for (int i = 0; i < nrep; i++) if (contains(found, nfound < 512 ? nfound : 512, reported[i])) enum_hits++;
  int ppid_of_last = nrep ? bsd_ppid(reported[nrep - 1]) : -2;
  int sup_enum_sees_last = 0;
  if (nrep) {
    pid_t mine[512];
    int nm = enum_descendants(getpid(), mine, 512, 0);
    sup_enum_sees_last = contains(mine, nm < 512 ? nm : 512, reported[nrep - 1]);
  }

  pid_t mfound[256];
  int mscanned = 0;
  double mms = 0;
  int mn = env_marker_scan(needle, mfound, 256, &mscanned, &mms);
  int marker_hits = 0;
  for (int i = 0; i < nrep; i++) if (contains(mfound, mn < 256 ? mn : 256, reported[i])) marker_hits++;

  emit(PROBE, name,
       "\"NOTE_TRACK_in_header\":%d,\"track_requested\":%d,\"registration_errno\":\"%s\",\"descendants_reported_by_the_child\":%d,\"kevents_returned\":%d,\"with_NOTE_FORK\":%d,\"with_NOTE_EXEC\":%d,\"with_NOTE_EXIT\":%d,\"with_NOTE_CHILD\":%d,\"with_NOTE_TRACKERR\":%d,\"EV_ERROR\":%d,\"reported_pids_named_by_NOTE_CHILD_events\":%d,\"found_by_proc_listchildpids_from_the_child\":%d,\"reported_pids_in_that_enumeration\":%d,\"last_reported_pid_ppid\":%d,\"supervisor_enumeration_sees_last_reported_pid\":%d,\"env_marker_scan\":{\"processes_readable\":%d,\"processes_carrying_the_marker\":%d,\"reported_pids_among_them\":%d,\"scan_ms\":%.1f}",
       TRACK_FROM_HEADER, track, errno_name(reg_errno), nrep, evs_total, fork_ev, exec_ev, exit_ev, child_ev, trackerr, error_ev, named, nfound, enum_hits, ppid_of_last, sup_enum_sees_last, mscanned, mn, marker_hits, mms);

  for (int i = 0; i < nrep; i++) kill(reported[i], SIGKILL);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  close(kq);
  close(rfd);
}

int main(int argc, char **argv) {
  if (argc >= 5 && strcmp(argv[1], "--forker") == 0) return forker_main(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(90);
  emit_header(PROBE);
  run_case("fork_events_no_track", 0, 30, 0);
  run_case("fork_events_with_track", 0, 30, 1);
  run_case("tree_no_track", 1, 30, 0);
  run_case("daemonize_no_track", 2, 1, 0);
  return 0;
}

#endif /* __APPLE__ */
