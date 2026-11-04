/*
 * Resource accounting for a child process tree: what can a supervisor learn about CPU time, peak memory and
 * I/O of a child, when, and does it include grandchildren? The Windows kit has Job-object accounting; on
 * POSIX the equivalents are wait4/getrusage (after the child is reaped), proc_pid_rusage (macOS, live and
 * maybe zombie) and /proc (Linux). The kit tested none of them.
 *
 * Build: cc -O1 -Wall -Wextra -o rusage rusage.c
 */
#include "common.h"
#include <limits.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <libproc.h>
#include <mach/mach_time.h>
#endif
#define PROBE "rusage"

static char g_self[PATH_MAX];

static double tv_ms(struct timeval tv) { return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0; }

static double cpu_ms_self(void) {
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ---------------- worker ---------------- */
/* --work <cpu_ms> <mem_mb> <write_mb> <mode> <ready_fd> <go_fd>
 * mode: plain | waited_grandchild | orphan_grandchild | both */
static void spawn_grandchild(int cpu_ms, int wait_for_it) {
  pid_t g = fork();
  if (g == 0) {
    char cpu[32];
    snprintf(cpu, sizeof cpu, "%d", cpu_ms);
    execl(g_self, g_self, "--work", cpu, "0", "0", "plain", "-1", "-1", (char *)NULL);
    _exit(127); /* the parent sees status 127 in "grandchild_status" */
  }
  if (wait_for_it && g > 0) {
    int st = 0;
    waitpid(g, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) _exit(90); /* surface a failed grandchild instead of hiding it */
  }
}

static int work_main(int argc, char **argv) {
  if (argc < 8) return 2;
  int cpu = atoi(argv[2]), mem = atoi(argv[3]), wr = atoi(argv[4]);
  const char *mode = argv[5];
  int ready_fd = atoi(argv[6]), go_fd = atoi(argv[7]);
  while (cpu_ms_self() < cpu) { /* spin */ }
  if (mem > 0) {
    size_t n = (size_t)mem * 1024 * 1024;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p != MAP_FAILED) for (size_t i = 0; i < n; i += 4096) p[i] = 1;
  }
  if (wr > 0) {
    const char *dir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char path[1024];
    snprintf(path, sizeof path, "%s/rusage-probe-%d.bin", dir, (int)getpid());
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    static char buf[1 << 20];
    memset(buf, 7, sizeof buf);
    for (int i = 0; i < wr; i++) (void)!write(fd, buf, sizeof buf);
    fsync(fd);
    close(fd);
    unlink(path);
  }
  if (strcmp(mode, "waited_grandchild") == 0 || strcmp(mode, "both") == 0) spawn_grandchild(200, 1);
  if (strcmp(mode, "orphan_grandchild") == 0 || strcmp(mode, "both") == 0) spawn_grandchild(400, 0);
  if (ready_fd >= 0) {
    (void)!write(ready_fd, "D", 1);
    char c;
    if (go_fd >= 0) (void)!read(go_fd, &c, 1); /* parent decides when we exit */
  }
  return 0;
}

/* ---------------- observation ---------------- */
#ifdef __linux__
static int proc_times(pid_t pid, double *u_ms, double *s_ms, long *rss_kib, int *err) {
  char path[64], buf[2048];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
  FILE *f = fopen(path, "r");
  if (!f) { *err = errno; return -1; }
  size_t n = fread(buf, 1, sizeof buf - 1, f);
  fclose(f);
  buf[n] = 0;
  char *rp = strrchr(buf, ')');
  if (!rp) { *err = EINVAL; return -1; }
  long utime, stime, rss;
  /* fields after the comm: state(3) ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime(14) stime(15) ... rss(24) */
  if (sscanf(rp + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld %*d %*d %*d %*d %*d %*d %*u %*u %ld", &utime, &stime, &rss) != 3) {
    *err = EINVAL; return -1;
  }
  long hz = sysconf(_SC_CLK_TCK);
  *u_ms = utime * 1000.0 / hz; *s_ms = stime * 1000.0 / hz; *rss_kib = rss * (sysconf(_SC_PAGESIZE) / 1024);
  return 0;
}

static int proc_io(pid_t pid, long long *rd, long long *wr, int *err) {
  char path[64], line[256];
  snprintf(path, sizeof path, "/proc/%d/io", (int)pid);
  FILE *f = fopen(path, "r");
  if (!f) { *err = errno; return -1; }
  *rd = *wr = -1;
  while (fgets(line, sizeof line, f)) {
    sscanf(line, "read_bytes: %lld", rd);
    sscanf(line, "write_bytes: %lld", wr);
  }
  fclose(f);
  return 0;
}
#endif

static void observe_live(const char *kase, const char *when, pid_t pid) {
#ifdef __APPLE__
  struct rusage_info_current ri;
  memset(&ri, 0, sizeof ri);
  int rc = proc_pid_rusage(pid, RUSAGE_INFO_CURRENT, (rusage_info_t *)&ri);
  int e = errno;
  mach_timebase_info_data_t tb;
  mach_timebase_info(&tb);
  double scale = (double)tb.numer / (double)tb.denom / 1e6; /* mach ticks -> ms */
  if (rc != 0) {
    emit(PROBE, kase, "\"phase\":\"%s\",\"source\":\"proc_pid_rusage\",\"rc\":%d,\"errno\":\"%s\"", when, rc, errno_name(e));
  } else {
    emit(PROBE, kase,
         "\"phase\":\"%s\",\"source\":\"proc_pid_rusage\",\"rc\":0,\"timebase\":\"%u/%u\",\"user_ms\":%.1f,\"system_ms\":%.1f,"
         "\"resident_bytes\":%llu,\"phys_footprint_bytes\":%llu,\"lifetime_max_footprint_bytes\":%llu,"
         "\"diskio_bytes_read\":%llu,\"diskio_bytes_written\":%llu,\"pageins\":%llu",
         when, tb.numer, tb.denom, (double)ri.ri_user_time * scale, (double)ri.ri_system_time * scale,
         (unsigned long long)ri.ri_resident_size, (unsigned long long)ri.ri_phys_footprint,
         (unsigned long long)ri.ri_lifetime_max_phys_footprint, (unsigned long long)ri.ri_diskio_bytesread,
         (unsigned long long)ri.ri_diskio_byteswritten, (unsigned long long)ri.ri_pageins);
  }
#elif defined(__linux__)
  double u = 0, s = 0; long rss = 0; int err = 0; long long rd = 0, wr = 0; int ioerr = 0;
  int a = proc_times(pid, &u, &s, &rss, &err);
  int b = proc_io(pid, &rd, &wr, &ioerr);
  emit(PROBE, kase,
       "\"phase\":\"%s\",\"source\":\"/proc\",\"stat_ok\":%s,\"stat_errno\":\"%s\",\"user_ms\":%.1f,\"system_ms\":%.1f,\"rss_kib\":%ld,"
       "\"io_ok\":%s,\"io_errno\":\"%s\",\"io_read_bytes\":%lld,\"io_write_bytes\":%lld",
       when, a == 0 ? "true" : "false", errno_name(err), u, s, rss, b == 0 ? "true" : "false", errno_name(ioerr), rd, wr);
#else
  (void)kase; (void)when; (void)pid;
#endif
}

static void run_scenario(const char *kase, int cpu, int mem, int wr, const char *mode, int hold_for_live) {
  int ready[2], go[2];
  if (pipe(ready) != 0 || pipe(go) != 0) return;
  pid_t pid = fork();
  if (pid == 0) {
    close(ready[0]); close(go[1]);
    char a[32], b[32], c[32], r[16], g[16];
    snprintf(a, sizeof a, "%d", cpu); snprintf(b, sizeof b, "%d", mem); snprintf(c, sizeof c, "%d", wr);
    snprintf(r, sizeof r, "%d", ready[1]); snprintf(g, sizeof g, "%d", go[0]);
    execl(g_self, g_self, "--work", a, b, c, mode, r, g, (char *)NULL);
    _exit(127);
  }
  close(ready[1]); close(go[0]);
  char d;
  ssize_t n = read_timeout(ready[0], &d, 1, 15000);
  double expected_cpu = cpu;
  if (n != 1) { emit(PROBE, kase, "\"error\":\"worker never reported ready\""); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return; }
  if (hold_for_live) observe_live(kase, "child_alive_after_work", pid);
  (void)!write(go[1], "x", 1);
  /* wait for exit without reaping */
  siginfo_t si;
  memset(&si, 0, sizeof si);
  int wr_ok = waitid(P_PID, (id_t)pid, &si, WEXITED | WNOWAIT) == 0;
  observe_live(kase, "child_zombie_not_reaped", pid);
  struct rusage before, after, ru;
  getrusage(RUSAGE_CHILDREN, &before);
  int st = 0;
  pid_t r = wait4(pid, &st, 0, &ru);
  getrusage(RUSAGE_CHILDREN, &after);
  char stt[64];
  status_text(st, stt, sizeof stt);
  emit(PROBE, kase,
       "\"phase\":\"wait4\",\"mode\":\"%s\",\"requested_cpu_ms\":%.0f,\"requested_mem_mb\":%d,\"requested_write_mb\":%d,"
       "\"waitid_wnowait_ok\":%s,\"wait4_pid_ok\":%s,\"status\":\"%s\",\"ru_utime_ms\":%.1f,\"ru_stime_ms\":%.1f,\"ru_maxrss_raw\":%ld,"
       "\"ru_inblock\":%ld,\"ru_oublock\":%ld,\"ru_minflt\":%ld,\"ru_majflt\":%ld,\"ru_nvcsw\":%ld,\"ru_nivcsw\":%ld,"
       "\"children_delta_utime_ms\":%.1f,\"children_delta_stime_ms\":%.1f",
       mode, expected_cpu, mem, wr, wr_ok ? "true" : "false", r == pid ? "true" : "false", stt, tv_ms(ru.ru_utime), tv_ms(ru.ru_stime),
       ru.ru_maxrss, ru.ru_inblock, ru.ru_oublock, ru.ru_minflt, ru.ru_majflt, ru.ru_nvcsw, ru.ru_nivcsw,
       tv_ms(after.ru_utime) - tv_ms(before.ru_utime), tv_ms(after.ru_stime) - tv_ms(before.ru_stime));
  observe_live(kase, "after_reap", pid);
}

int main(int argc, char **argv) {
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  if (argc > 1 && strcmp(argv[1], "--work") == 0) return work_main(argc, argv);
  watchdog(120);
  emit_header(PROBE);
  run_scenario("single_worker", 300, 64, 16, "plain", 1);
  run_scenario("tree_waited_grandchild", 100, 0, 0, "waited_grandchild", 0);
  run_scenario("tree_orphan_grandchild", 100, 0, 0, "orphan_grandchild", 0);
  struct rusage a, b;
  getrusage(RUSAGE_CHILDREN, &a);
  sleep_ms(900); /* the orphan grandchild burns 400 ms of CPU after the worker is gone */
  getrusage(RUSAGE_CHILDREN, &b);
  emit(PROBE, "orphan_grandchild_after_it_finished",
       "\"children_utime_ms_before\":%.1f,\"children_utime_ms_after\":%.1f,\"note\":\"unchanged means the orphan's CPU time is attributed to nobody\"",
       tv_ms(a.ru_utime) + tv_ms(a.ru_stime), tv_ms(b.ru_utime) + tv_ms(b.ru_stime));
  return 0;
}
