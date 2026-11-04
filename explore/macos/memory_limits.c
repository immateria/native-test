/*
 * Memory limits on macOS. RLIMIT_AS / RLIMIT_DATA below current usage are rejected (see rlimit.c); what else can cap
 * or watch a child's memory?
 *
 *   rlimit_rss_enforced      RLIMIT_RSS is accepted by setrlimit; is it enforced
 *   footprint_poll_kill      a supervisor polling proc_pid_rusage's phys_footprint and killing at a threshold:
 *                            poll cost, detection latency, overshoot, time for the kill to complete
 *   memorystatus_*           the kernel's per-process footprint limit (jetsam) through memorystatus_control, set on
 *                            the child itself, as this user (and as root when the probe runs under sudo): does the
 *                            call succeed, and is the child killed when it exceeds the limit
 *
 * memorystatus_control is private API (no public header); it is looked up with dlsym.
 *
 * Build: cc -O1 -Wall -Wextra -o memory_limits memory_limits.c
 */
#include "../posix/common.h"
#include <dlfcn.h>
#include <libproc.h>
#include <sys/sysctl.h>
#define PROBE "memory_limits"

#define MS_CMD_SET_JETSAM_TASK_LIMIT 6
#define MS_CMD_SET_MEMLIMIT_PROPERTIES 7
#define MS_CMD_GET_MEMLIMIT_PROPERTIES 8
#define MS_MEMLIMIT_ATTR_FATAL 0x1

typedef struct {
  int32_t memlimit_active;
  uint32_t memlimit_active_attr;
  int32_t memlimit_inactive;
  uint32_t memlimit_inactive_attr;
} ms_props_t;

typedef int (*memorystatus_control_fn)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
static memorystatus_control_fn g_msc;

#define MIB (1024ull * 1024ull)

typedef struct { uint32_t mib; double t_ms; } step_t;

static int footprint(pid_t pid, unsigned long long *fp, unsigned long long *rss) {
  rusage_info_current ri;
  if (proc_pid_rusage(pid, RUSAGE_INFO_CURRENT, (rusage_info_t *)&ri) != 0) return -1;
  *fp = ri.ri_phys_footprint;
  *rss = ri.ri_resident_size;
  return 0;
}

/* Remember every allocation in a volatile array: otherwise the compiler may delete a malloc whose contents are never read,
 * together with the stores that fill it, and the process never uses the memory at all (the first CI run of this probe
 * measured exactly that). */
static char *volatile g_keep[512];
static int g_keep_n;
static void keep(char *p) { if (g_keep_n < 512) g_keep[g_keep_n++] = p; }

/* Fill with data that neither the zero-page logic nor the compressor's same-value shortcut can collapse. */
static void fill_random(char *p, size_t sz, uint64_t seed) {
  uint64_t x = seed * 0x9E3779B97F4A7C15ull + 1;
  uint64_t *w = (uint64_t *)p;
  for (size_t i = 0; i < sz / 8; i++) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    w[i] = x;
  }
}

/* Allocates `total_mib` in 8 MiB steps, `gap_ms` apart, reporting each step on fd. Never returns. */
static void allocate_forever(int fd, uint32_t total_mib, int gap_ms) {
  uint32_t have = 0;
  while (have < total_mib) {
    size_t sz = 8 * MIB;
    char *p = malloc(sz);
    if (!p) { have = 0xFFFFFFFF; break; }
    fill_random(p, sz, have + 1);
    keep(p);
    have += 8;
    step_t s = {have, now_ms()};
    (void)!write(fd, &s, sizeof s);
    if (gap_ms) sleep_ms(gap_ms);
  }
  for (;;) pause();
}

static void rlimit_rss_enforced(void) {
  int p[2];
  if (pipe(p) != 0) return;
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    struct rlimit rl;
    getrlimit(RLIMIT_RSS, &rl);
    struct rlimit before = rl;
    rl.rlim_cur = 64 * MIB;
    int rc = setrlimit(RLIMIT_RSS, &rl);
    int e = errno;
    struct rlimit after;
    getrlimit(RLIMIT_RSS, &after);
    char line[256];
    int n = snprintf(line, sizeof line, "{\"before_soft\":%lld,\"before_hard\":%lld,\"setrlimit_64MiB_rc\":%d,\"errno\":\"%s\",\"after_soft\":%lld}",
                     (long long)before.rlim_cur, (long long)before.rlim_max, rc, errno_name(rc == 0 ? 0 : e), (long long)after.rlim_cur);
    (void)!write(p[1], line, (size_t)n);
    close(p[1]);
    size_t sz = 256 * MIB;
    char *buf = malloc(sz);
    int ok = buf != NULL;
    if (buf) { fill_random(buf, sz, 7); keep(buf); }
    unsigned long long fp = 0, rss = 0;
    int fprc = footprint(getpid(), &fp, &rss);
    _exit(!ok ? 3 : fprc != 0 ? 4 : rss >= 200 * MIB ? 0 : 5);
  }
  close(p[1]);
  char buf[512];
  int eof;
  size_t n = drain_until(p[0], buf, sizeof buf, 10000, &eof);
  close(p[0]);
  char st[64];
  reap_blocking(c, 20000, st, sizeof st);
  emit(PROBE, "rlimit_rss_enforced", "\"setrlimit\":%s,\"child_end\":\"%s\",\"meaning_of_exit_code\":\"0 = touched 256 MiB and stayed resident; 3 = malloc failed; 4 = proc_pid_rusage failed; 5 = resident < 200 MiB\"", n ? buf : "null", st);
}

static void footprint_poll_kill(void) {
  const unsigned long long threshold_mib = 256;
  int p[2];
  if (pipe(p) != 0) return;
  fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    allocate_forever(p[1], 1024, 3);
    _exit(0);
  }
  close(p[1]);
  long polls = 0, failures = 0;
  int last_errno = 0;
  double poll_time = 0, t_detect = 0, t_first_poll = now_ms();
  unsigned long long fp = 0, rss = 0, fp_detect = 0, rss_detect = 0, fp_max = 0;
  int failed = 0;
  for (;;) {
    double a = now_ms();
    int rc = footprint(c, &fp, &rss);
    poll_time += now_ms() - a;
    polls++;
    if (rc != 0) { last_errno = errno; failures++; if (++failed > 2000) break; sleep_ms(1); continue; }
    if (fp > fp_max) fp_max = fp;
    if (fp >= threshold_mib * MIB) { t_detect = now_ms(); fp_detect = fp; rss_detect = rss; break; }
    if (now_ms() - t_first_poll > 20000) break;
    sleep_ms(1);
  }
  double t_kill = now_ms();
  kill(c, SIGKILL);
  int st = 0;
  waitpid(c, &st, 0);
  double t_dead = now_ms();
  /* what the child had reported by then */
  step_t s;
  uint32_t last_mib = 0, cross_mib = 0;
  double t_cross = 0;
  while (read(p[0], &s, sizeof s) == (ssize_t)sizeof s) {
    last_mib = s.mib;
    if (!t_cross && s.mib >= threshold_mib) { t_cross = s.t_ms; cross_mib = s.mib; }
  }
  close(p[0]);
  emit(PROBE, "footprint_poll_kill",
       "\"threshold_MiB\":%llu,\"detected\":%d,\"polls\":%ld,\"failed_polls\":%ld,\"last_error\":\"%s\",\"largest_footprint_seen_MiB\":%.1f,\"avg_ms_per_proc_pid_rusage_call\":%.3f,\"footprint_at_detection_MiB\":%.1f,\"resident_at_detection_MiB\":%.1f,\"child_reported_MiB_when_killed\":%u,\"child_step_that_crossed_threshold_MiB\":%u,\"detection_after_crossing_ms\":%.1f,\"kill_to_reaped_ms\":%.1f,\"child_status\":\"%s\"",
       threshold_mib, t_detect != 0, polls, failures, errno_name(last_errno), (double)fp_max / MIB, polls ? poll_time / (double)polls : 0.0, (double)fp_detect / MIB, (double)rss_detect / MIB, last_mib, cross_mib,
       t_cross ? t_detect - t_cross : -1.0, t_dead - t_kill, WIFSIGNALED(st) ? sig_name(WTERMSIG(st)) : "exited");
}

/* Does the footprint count pages whose content is one repeated byte? Report from inside the child. */
static void footprint_uniform_vs_random(void) {
  int p[2];
  if (pipe(p) != 0) return;
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    unsigned long long fp, rss;
    char line[600];
    size_t sz = 128 * MIB;
    int rc0 = footprint(getpid(), &fp, &rss);
    unsigned long long fp0 = fp;
    char *a = malloc(sz), *b = malloc(sz);
    memset(a, 0x5a, sz);
    keep(a);
    int rc1 = footprint(getpid(), &fp, &rss);
    unsigned long long fp1 = fp, rss1 = rss;
    sleep_ms(1500);
    int rc2 = footprint(getpid(), &fp, &rss);
    unsigned long long fp2 = fp, rss2 = rss;
    fill_random(b, sz, 3);
    keep(b);
    int rc3 = footprint(getpid(), &fp, &rss);
    unsigned long long fp3 = fp, rss3 = rss;
    sleep_ms(1500);
    int rc4 = footprint(getpid(), &fp, &rss);
    int n = snprintf(line, sizeof line,
      "{\"rc\":[%d,%d,%d,%d,%d],\"footprint_MiB\":{\"start\":%.1f,\"after_128MiB_uniform_fill\":%.1f,\"1.5s_later\":%.1f,\"after_128MiB_random_fill_too\":%.1f,\"1.5s_later_again\":%.1f},\"resident_MiB\":{\"after_uniform\":%.1f,\"1.5s_later\":%.1f,\"after_random\":%.1f}}",
      rc0, rc1, rc2, rc3, rc4, (double)fp0 / MIB, (double)fp1 / MIB, (double)fp2 / MIB, (double)fp3 / MIB, (double)fp / MIB,
      (double)rss1 / MIB, (double)rss2 / MIB, (double)rss3 / MIB);
    (void)!write(p[1], line, (size_t)n);
    _exit(0);
  }
  close(p[1]);
  char buf[700];
  int eof;
  drain_until(p[0], buf, sizeof buf, 15000, &eof);
  close(p[0]);
  char st[64];
  reap_blocking(c, 5000, st, sizeof st);
  emit(PROBE, "footprint_uniform_vs_random_pages", "\"child_measured\":%s,\"child_end\":\"%s\"", buf[0] ? buf : "null", st);
}

/* The child applies `cmd` to itself, reports the result, then allocates 8 MiB steps up to 512 MiB. */
static void memorystatus_case(const char *kase, int cmd) {
  if (!g_msc) { emit(PROBE, kase, "\"error\":\"memorystatus_control not found with dlsym\""); return; }
  int p[2];
  if (pipe(p) != 0) return;
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    ms_props_t props = {64, MS_MEMLIMIT_ATTR_FATAL, 64, MS_MEMLIMIT_ATTR_FATAL};
    int rc, e;
    errno = 0;
    if (cmd == MS_CMD_SET_JETSAM_TASK_LIMIT) rc = g_msc(MS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 64, NULL, 0);
    else rc = g_msc(MS_CMD_SET_MEMLIMIT_PROPERTIES, getpid(), 0, &props, sizeof props);
    e = errno;
    ms_props_t got;
    memset(&got, 0xff, sizeof got);
    errno = 0;
    int grc = g_msc(MS_CMD_GET_MEMLIMIT_PROPERTIES, getpid(), 0, &got, sizeof got);
    int ge = errno;
    char line[400];
    int n = snprintf(line, sizeof line,
                     "{\"set_rc\":%d,\"set_errno\":\"%s\",\"get_rc\":%d,\"get_errno\":\"%s\",\"limit_active_MB\":%d,\"active_attr\":%u,\"limit_inactive_MB\":%d,\"inactive_attr\":%u}",
                     rc, errno_name(rc == 0 ? 0 : e), grc, errno_name(grc == 0 ? 0 : ge), got.memlimit_active, got.memlimit_active_attr,
                     got.memlimit_inactive, got.memlimit_inactive_attr);
    /* the result line goes first on the same pipe as the steps: a 4-byte length, then the text */
    uint32_t len = (uint32_t)n;
    (void)!write(p[1], &len, sizeof len);
    (void)!write(p[1], line, (size_t)n);
    allocate_forever(p[1], 512, 2);
    _exit(0);
  }
  close(p[1]);
  double t0 = now_ms();
  uint32_t len = 0;
  char line[512] = "";
  if (read_timeout(p[0], &len, sizeof len, 5000) == (ssize_t)sizeof len && len < sizeof line) {
    ssize_t got = 0;
    while (got < (ssize_t)len) {
      ssize_t k = read_timeout(p[0], line + got, (size_t)len - (size_t)got, 2000);
      if (k <= 0) break;
      got += k;
    }
    line[got] = 0;
  }
  /* watch the steps until the child dies or reaches 512 MiB */
  uint32_t last = 0;
  double t_last = t0;
  int dead = 0, st = 0;
  double end = now_ms() + 8000;
  while (now_ms() < end) {
    step_t s;
    ssize_t k = read_timeout(p[0], &s, sizeof s, 200);
    if (k == (ssize_t)sizeof s) { last = s.mib; t_last = s.t_ms; if (last >= 512) break; continue; }
    pid_t w = waitpid(c, &st, WNOHANG);
    if (w == c) { dead = 1; break; }
    if (k == 0) break;
  }
  if (!dead) {
    pid_t w = waitpid_timeout(c, &st, 0, 300);
    if (w == c) dead = 1;
  }
  char status[64];
  if (dead) status_text(st, status, sizeof status);
  else { snprintf(status, sizeof status, "still_running"); kill(c, SIGKILL); waitpid(c, &st, 0); }
  close(p[0]);
  emit(PROBE, kase, "\"child_reports\":%s,\"child_last_reported_MiB\":%u,\"child_end\":\"%s\",\"ms_from_start_to_last_step\":%.0f",
       line[0] ? line : "null", last, status, t_last - t0);
}

int main(void) {
  watchdog(150);
  emit_header(PROBE);
  g_msc = (memorystatus_control_fn)dlsym(RTLD_DEFAULT, "memorystatus_control");
  int mem_pressure_level = -1;
  size_t l = sizeof mem_pressure_level;
  sysctlbyname("kern.memorystatus_vm_pressure_level", &mem_pressure_level, &l, NULL, 0);
  uint64_t memsize = 0;
  l = sizeof memsize;
  sysctlbyname("hw.memsize", &memsize, &l, NULL, 0);
  emit(PROBE, "system", "\"hw_memsize_MiB\":%llu,\"memorystatus_vm_pressure_level\":%d,\"memorystatus_control_found\":%d",
       (unsigned long long)(memsize / MIB), mem_pressure_level, g_msc != NULL);
  rlimit_rss_enforced();
  footprint_uniform_vs_random();
  footprint_poll_kill();
  memorystatus_case("memorystatus_set_memlimit_properties_64MB_fatal", MS_CMD_SET_MEMLIMIT_PROPERTIES);
  memorystatus_case("memorystatus_set_jetsam_task_limit_64MB", MS_CMD_SET_JETSAM_TASK_LIMIT);
  return 0;
}
