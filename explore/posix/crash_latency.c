/*
 * How long after a process crashes does its supervisor learn about it? Crash reporters (macOS ReportCrash, Linux
 * apport / systemd-coredump through core_pattern) can hold a dying process while they write a report or a core
 * file, so the supervisor's wait() returns late. The child writes a monotonic timestamp to a pipe just before it
 * faults; the parent notes when the pipe reaches EOF and when waitpid reports the exit.
 *
 * Build: cc -O1 -Wall -Wextra -o crash_latency crash_latency.c
 */
#include "common.h"
#include <dirent.h>
#include <limits.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#ifdef __linux__
#include <sys/prctl.h>
#endif
#define PROBE "crash_latency"

enum { M_SEGV, M_ABORT, M_TRAP, M_KILL_SEGV, M_KILL_KILL, M_EXIT, M_QUIT, M_FPE, M_BUS, M_XCPU, M_SYS };

static const char *mode_name(int m) {
  switch (m) {
    case M_SEGV: return "null_dereference";
    case M_ABORT: return "abort";
    case M_TRAP: return "builtin_trap";
    case M_KILL_SEGV: return "kill_SIGSEGV_from_outside";
    case M_KILL_KILL: return "kill_SIGKILL_from_outside_baseline";
    case M_QUIT: return "raise_SIGQUIT";
#if defined(__x86_64__) || defined(__i386__)
    case M_FPE: return "integer_divide_by_zero_SIGFPE";
#else
    case M_FPE: return "raise_SIGFPE"; /* integer division by zero does not trap on arm64 */
#endif
    case M_BUS: return "access_beyond_truncated_mapping_SIGBUS";
    case M_XCPU: return "RLIMIT_CPU_1s_SIGXCPU";
    case M_SYS: return "raise_SIGSYS";
    default: return "exit_baseline";
  }
}

static int cmp_d(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}

static int count_reports(const char *dir, const char *prefix) {
  DIR *d = opendir(dir);
  if (!d) return -1;
  int n = 0;
  struct dirent *e;
  while ((e = readdir(d))) if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) n++;
  closedir(d);
  return n;
}

/* 0 = RLIMIT_CORE 0, 1 = raised to at most 256 MiB, 2 = exactly 1 byte (Linux skips a piped core_pattern helper for
 * that value: fs/coredump.c treats 1 as its recursion guard), 3 = RLIMIT_CORE 0 and PR_SET_DUMPABLE 0 (Linux) */
static int g_core_variant;
static int g_big_heap;           /* dirty 384 MiB before faulting, so the core takes a while to write (Linux) */
static int g_kill_during_dump_ms = -1; /* parent sends SIGKILL this long after the fault timestamp */
static const char *variant_name(int v) {
  switch (v) {
    case 1: return "_core_enabled";
    case 2: return "_RLIMIT_CORE_1_byte";
    case 3: return "_not_dumpable";
    default: return "_core_disabled";
  }
}

static void child_body(int mode, int wfd, const char *cwd) {
  struct rlimit rl;
  getrlimit(RLIMIT_CORE, &rl);
  if (g_core_variant == 1) {
    rlim_t cap = (rlim_t)256 << 20;
    rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > cap) ? cap : rl.rlim_max;
  } else if (g_core_variant == 2) {
    rl.rlim_cur = rl.rlim_max >= 1 ? 1 : 0;
  } else {
    rl.rlim_cur = 0;
  }
  setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
  if (g_core_variant == 3) prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L);
#endif
  if (cwd && chdir(cwd) != 0) _exit(120);
  signal(SIGSEGV, SIG_DFL); signal(SIGABRT, SIG_DFL); signal(SIGILL, SIG_DFL); signal(SIGTRAP, SIG_DFL);
  signal(SIGQUIT, SIG_DFL); signal(SIGFPE, SIG_DFL); signal(SIGBUS, SIG_DFL); signal(SIGXCPU, SIG_DFL); signal(SIGSYS, SIG_DFL);
  if (g_big_heap) {
    size_t sz = (size_t)384 << 20;
    volatile char *h = malloc(sz);
    if (h) for (size_t i = 0; i < sz; i += 4096) h[i] = (char)(i >> 12);
  }
  volatile char *bus_map = NULL;
  if (mode == M_BUS) {
    int fd = open("bus-probe.bin", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, 8192) != 0) _exit(123);
    void *m = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) _exit(124);
    if (ftruncate(fd, 0) != 0) _exit(125);
    bus_map = (volatile char *)m;
  }
  if (mode == M_XCPU) {
    struct rlimit cpu = {1, 4};
    setrlimit(RLIMIT_CPU, &cpu);
    /* write the timestamp just before the 1 s CPU limit is reached */
    for (;;) {
      struct rusage ru;
      getrusage(RUSAGE_SELF, &ru);
      double cpu_ms = ru.ru_utime.tv_sec * 1000.0 + ru.ru_utime.tv_usec / 1000.0 + ru.ru_stime.tv_sec * 1000.0 + ru.ru_stime.tv_usec / 1000.0;
      if (cpu_ms >= 990) break;
      for (volatile int i = 0; i < 100000; i++) {}
    }
  }
  double t = now_ms();
  (void)!write(wfd, &t, sizeof t);
  switch (mode) {
    case M_SEGV: { volatile int *p = (volatile int *)0; *p = 1; break; }
    case M_ABORT: abort();
    case M_TRAP: __builtin_trap();
    case M_EXIT: _exit(0);
    case M_QUIT: raise(SIGQUIT); break;
#if defined(__x86_64__) || defined(__i386__)
    case M_FPE: { volatile int n = 7, z = 0; volatile int x = n / z; (void)x; break; } /* not 1 / z: GCC turns that into a compare */
#else
    case M_FPE: raise(SIGFPE); break;
#endif
    case M_BUS: bus_map[0] = 1; break;
    case M_XCPU: for (;;) { for (volatile int i = 0; i < 100000; i++) {} }
    case M_SYS: raise(SIGSYS); break;
    default: for (;;) pause();
  }
  _exit(121);
}

typedef struct { double to_eof, to_wait; char status[64]; } trial_t;

static int run_trial(int mode, const char *cwd, trial_t *out) {
  int p[2];
  if (pipe(p) != 0) return -1;
  pid_t c = fork();
  if (c == 0) { close(p[0]); child_body(mode, p[1], cwd); _exit(122); }
  close(p[1]);
  double tfault = 0;
  if (read_timeout(p[0], &tfault, sizeof tfault, 5000) != (ssize_t)sizeof tfault) { kill(c, SIGKILL); waitpid(c, NULL, 0); close(p[0]); return -1; }
  if (mode == M_KILL_SEGV || mode == M_KILL_KILL) {
    sleep_ms(30);
    tfault = now_ms();
    kill(c, mode == M_KILL_SEGV ? SIGSEGV : SIGKILL);
  }
  if (g_kill_during_dump_ms >= 0) {
    double at = tfault + g_kill_during_dump_ms;
    while (now_ms() < at) sleep_ms(1);
    kill(c, SIGKILL);
  }
  /* EOF on the pipe (the child's write end closes when the process dies) */
  char buf[16];
  double teof = -1;
  for (;;) {
    ssize_t r = read_timeout(p[0], buf, sizeof buf, 20000);
    if (r == 0) { teof = now_ms(); break; }
    if (r == -2) break;
    if (r < 0 && errno != EINTR) break;
  }
  int st = 0;
  pid_t w = waitpid_timeout(c, &st, 0, 30000);
  double twait = now_ms();
  close(p[0]);
  if (w <= 0) { kill(c, SIGKILL); waitpid(c, NULL, 0); snprintf(out->status, sizeof out->status, "still_running_after_30s"); out->to_eof = teof < 0 ? -1 : teof - tfault; out->to_wait = -1; return 0; }
  status_text(st, out->status, sizeof out->status);
  out->to_eof = teof < 0 ? -1 : teof - tfault;
  out->to_wait = twait - tfault;
  return 0;
}

static void series(int mode, int core_variant, int n, const char *cwd) {
  g_core_variant = core_variant;
  double eof[16], wait[16];
  int k = 0;
  char status[64] = "";
  int statuses_differ = 0;
  for (int i = 0; i < n && k < 16; i++) {
    trial_t t;
    if (run_trial(mode, cwd, &t) != 0) continue;
    if (k > 0 && strcmp(status, t.status) != 0) statuses_differ = 1;
    snprintf(status, sizeof status, "%s", t.status);
    eof[k] = t.to_eof; wait[k] = t.to_wait; k++;
  }
  char kase[192];
  snprintf(kase, sizeof kase, "%s%s%s%s", mode_name(mode), variant_name(core_variant), g_big_heap ? "_384MiB_dirty" : "",
           g_kill_during_dump_ms >= 0 ? "_SIGKILL_20ms_after_fault" : "");
  if (k == 0) { emit(PROBE, kase, "\"n\":0"); return; }
  qsort(eof, (size_t)k, sizeof(double), cmp_d);
  qsort(wait, (size_t)k, sizeof(double), cmp_d);
  emit(PROBE, kase, "\"n\":%d,\"status\":\"%s\",\"status_varies\":%d,\"fault_to_pipe_eof_ms\":{\"min\":%.1f,\"median\":%.1f,\"max\":%.1f},\"fault_to_waitpid_ms\":{\"min\":%.1f,\"median\":%.1f,\"max\":%.1f}",
       k, status, statuses_differ, eof[0], eof[k / 2], eof[k - 1], wait[0], wait[k / 2], wait[k - 1]);
}

static void describe_system(void) {
  struct rlimit rl;
  getrlimit(RLIMIT_CORE, &rl);
#ifdef __APPLE__
  char corefile[256] = "";
  size_t l = sizeof corefile;
  sysctlbyname("kern.corefile", corefile, &l, NULL, 0);
  int coredump = -1;
  l = sizeof coredump;
  sysctlbyname("kern.coredump", &coredump, &l, NULL, 0);
  emit(PROBE, "system", "\"RLIMIT_CORE_soft\":%lld,\"RLIMIT_CORE_hard\":%lld,\"kern_corefile\":\"%s\",\"kern_coredump\":%d",
       (long long)rl.rlim_cur, (long long)rl.rlim_max, corefile, coredump);
#else
  char pattern[256] = "";
  FILE *f = fopen("/proc/sys/kernel/core_pattern", "r");
  if (f) { if (!fgets(pattern, sizeof pattern, f)) pattern[0] = 0; fclose(f); }
  size_t n = strlen(pattern);
  while (n > 0 && (pattern[n - 1] == '\n')) pattern[--n] = 0;
  /* JSON-escape: the pattern may contain | and %, but no quotes or backslashes in practice */
  long pipe_limit = -1;
  FILE *pl = fopen("/proc/sys/kernel/core_pipe_limit", "r");
  if (pl) { if (fscanf(pl, "%ld", &pipe_limit) != 1) pipe_limit = -1; fclose(pl); }
  emit(PROBE, "system", "\"RLIMIT_CORE_soft\":%lld,\"RLIMIT_CORE_hard\":%lld,\"core_pattern\":\"%s\",\"core_pipe_limit\":%ld",
       (long long)rl.rlim_cur, (long long)rl.rlim_max, pattern, pipe_limit);
#endif
}

int main(void) {
  watchdog(400);
  emit_header(PROBE);
  describe_system();

  char dir[PATH_MAX];
  const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
  snprintf(dir, sizeof dir, "%s/crash-latency-%d", tmp, (int)getpid());
  mkdir(dir, 0700);

  const char *home = getenv("HOME");
  char user_reports[PATH_MAX] = "";
  if (home) snprintf(user_reports, sizeof user_reports, "%s/Library/Logs/DiagnosticReports", home);
  int before_user = user_reports[0] ? count_reports(user_reports, "crash_latency") : -1;
  int before_sys = count_reports("/Library/Logs/DiagnosticReports", "crash_latency");

  series(M_EXIT, 0, 5, dir);
  series(M_KILL_KILL, 0, 5, dir);
  series(M_KILL_SEGV, 0, 5, dir);
  series(M_SEGV, 0, 5, dir);
  series(M_ABORT, 0, 5, dir);
  series(M_TRAP, 0, 5, dir);
  series(M_SEGV, 1, 5, dir);
  series(M_ABORT, 1, 3, dir);
  /* the other signals whose default action dumps core */
  series(M_QUIT, 0, 5, dir);
  series(M_FPE, 0, 5, dir);
  series(M_BUS, 0, 5, dir);
  series(M_XCPU, 0, 3, dir);
  series(M_SYS, 0, 5, dir);
  /* opting one child out of the crash handler */
  series(M_SEGV, 2, 5, dir);
  series(M_ABORT, 2, 3, dir);
#ifdef __linux__
  series(M_SEGV, 3, 5, dir);
  /* a large core, and SIGKILL while it is being written */
  g_big_heap = 1;
  series(M_SEGV, 1, 3, dir);
  g_kill_during_dump_ms = 20;
  series(M_SEGV, 1, 3, dir);
  g_kill_during_dump_ms = -1;
  g_big_heap = 0;
#endif

  /* core files left behind (Linux: in the working directory; macOS: /cores/core.<pid> is handled below) */
  DIR *d = opendir(dir);
  int cores = 0;
  long long bytes = 0;
  if (d) {
    struct dirent *e;
    while ((e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
      char path[PATH_MAX + 300];
      snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
      struct stat st;
      if (stat(path, &st) == 0) { cores++; bytes += st.st_size; }
      unlink(path);
    }
    closedir(d);
  }
  emit(PROBE, "core_files_in_cwd", "\"files\":%d,\"bytes\":%lld", cores, bytes);
  rmdir(dir);

  sleep_ms(3000); /* a crash reporter may write its report late */
  int after_user = user_reports[0] ? count_reports(user_reports, "crash_latency") : -1;
  int after_sys = count_reports("/Library/Logs/DiagnosticReports", "crash_latency");
  emit(PROBE, "crash_reports_written", "\"user_diagnostic_reports_before\":%d,\"after\":%d,\"system_diagnostic_reports_before\":%d,\"after\":%d",
       before_user, after_user, before_sys, after_sys);

#ifdef __APPLE__
  /* /cores: cores of a root-owned directory; report and remove any we caused */
  DIR *cd = opendir("/cores");
  int ncores = 0;
  long long cbytes = 0;
  if (cd) {
    struct dirent *e;
    while ((e = readdir(cd))) {
      if (strncmp(e->d_name, "core.", 5) != 0) continue;
      char path[PATH_MAX];
      snprintf(path, sizeof path, "/cores/%s", e->d_name);
      struct stat st;
      if (stat(path, &st) == 0 && st.st_uid == getuid()) { ncores++; cbytes += st.st_size; unlink(path); }
    }
    closedir(cd);
  }
  emit(PROBE, "cores_directory", "\"files_of_this_user\":%d,\"bytes\":%lld", ncores, cbytes);
#endif
  return 0;
}
