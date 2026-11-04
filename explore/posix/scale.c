/*
 * Scale and timing of process creation, from a supervisor's point of view.
 *
 *   spawn_latency_*        how long fork+exec, vfork+exec and posix_spawn take (the call, and until the child is reaped),
 *                          with a small parent and with ~512 MiB resident; the first spawn of a freshly built binary
 *                          separately (macOS assesses new executables)
 *   limits                 the system and per-user limits that bound the number of children
 *   concurrent_children    children alive at once, until a bounded RLIMIT_NPROC refuses (so the runner's other
 *                          processes are never starved), with the fork time at the start and at the end
 *   zombies_*              exited, unreaped children: do they count against RLIMIT_NPROC, and how long to reap them
 *
 * Build: cc -O1 -Wall -Wextra -o scale scale.c
 */
#include "common.h"
#include <dirent.h>
#include <limits.h>
#include <spawn.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#define PROBE "scale"

extern char **environ;
static char g_self[PATH_MAX];

static int cmp_d(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}

static void stats(double *v, int n, double *mn, double *med, double *p90, double *mx) {
  qsort(v, (size_t)n, sizeof *v, cmp_d);
  *mn = v[0]; *med = v[n / 2]; *p90 = v[(n * 9) / 10 >= n ? n - 1 : (n * 9) / 10]; *mx = v[n - 1];
}

static void devnull_child(void) {
  int out = open("/dev/null", O_WRONLY);
  if (out >= 0) { dup2(out, 1); dup2(out, 2); }
}

/* One spawn through `how` (0 fork+exec, 1 vfork+exec, 2 posix_spawn). Sets *call_ms (until the call returns in the parent)
 * and *total_ms (until the child is reaped). Returns 0 on success. */
static int spawn_once(int how, const char *path, double *call_ms, double *total_ms) {
  char *argv[] = {(char *)"x", (char *)"--noop", NULL};
  pid_t p = -1;
  double t0 = now_ms();
  if (how == 0) {
    p = fork();
    if (p == 0) { devnull_child(); execve(path, argv, environ); _exit(127); }
  } else if (how == 1) {
    p = vfork();
    if (p == 0) { execve(path, argv, environ); _exit(127); }
  } else {
    int rc = posix_spawn(&p, path, NULL, NULL, argv, environ);
    if (rc != 0) p = -1;
  }
  *call_ms = now_ms() - t0;
  if (p < 0) return -1;
  int st;
  waitpid(p, &st, 0);
  *total_ms = now_ms() - t0;
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -2;
}

static void latency_series(const char *kase, int how, const char *path, int n) {
  double *call = calloc((size_t)n, sizeof(double)), *total = calloc((size_t)n, sizeof(double));
  int ok = 0;
  for (int i = 0; i < n; i++) {
    double c, t;
    if (spawn_once(how, path, &c, &t) == 0) { call[ok] = c; total[ok] = t; ok++; }
  }
  if (ok > 0) {
    double a, b, c2, d, e, f, g, h;
    stats(call, ok, &a, &b, &c2, &d);
    stats(total, ok, &e, &f, &g, &h);
    emit(PROBE, kase, "\"n\":%d,\"call_ms\":{\"min\":%.2f,\"median\":%.2f,\"p90\":%.2f,\"max\":%.2f},\"until_reaped_ms\":{\"min\":%.2f,\"median\":%.2f,\"p90\":%.2f,\"max\":%.2f}",
         ok, a, b, c2, d, e, f, g, h);
  } else {
    emit(PROBE, kase, "\"n\":0");
  }
  free(call); free(total);
}

static void spawn_latency(void) {
  /* a copy of this binary that has never been executed: the first exec of a new file */
  char fresh[PATH_MAX];
  const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
  snprintf(fresh, sizeof fresh, "%s/scale-fresh-%d", tmp, (int)getpid());
  {
    int in = open(g_self, O_RDONLY), out = open(fresh, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    char buf[65536];
    ssize_t r;
    while (in >= 0 && out >= 0 && (r = read(in, buf, sizeof buf)) > 0) (void)!write(out, buf, (size_t)r);
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    chmod(fresh, 0755);
  }
  double c, t;
  int rc = spawn_once(2, fresh, &c, &t);
  double c2, t2;
  int rc2 = spawn_once(2, fresh, &c2, &t2);
  double c3, t3;
  int rc3 = spawn_once(2, fresh, &c3, &t3);
  emit(PROBE, "first_exec_of_a_new_binary", "\"first_total_ms\":%.2f,\"second_total_ms\":%.2f,\"third_total_ms\":%.2f,\"first_ok\":%d,\"second_ok\":%d",
       t, t2, t3, rc == 0, rc2 == 0);
  (void)c; (void)c2; (void)c3; (void)rc3;
  unlink(fresh);

  latency_series("spawn_latency_fork_exec_small_parent", 0, g_self, 100);
  latency_series("spawn_latency_vfork_exec_small_parent", 1, g_self, 100);
  latency_series("spawn_latency_posix_spawn_small_parent", 2, g_self, 100);

  size_t sz = 512u << 20;
  char *big = malloc(sz);
  if (big) {
    for (size_t i = 0; i < sz; i += 4096) big[i] = 1;
    latency_series("spawn_latency_fork_exec_512MiB_parent", 0, g_self, 30);
    latency_series("spawn_latency_vfork_exec_512MiB_parent", 1, g_self, 30);
    latency_series("spawn_latency_posix_spawn_512MiB_parent", 2, g_self, 30);
    free(big);
  } else {
    emit(PROBE, "spawn_latency_512MiB_parent", "\"error\":\"malloc failed\"");
  }
}

/* ---- limits and process counting ---- */

static long read_long_file(const char *path) {
  FILE *f = fopen(path, "r");
  long v = -1;
  if (f) { if (fscanf(f, "%ld", &v) != 1) v = -1; fclose(f); }
  return v;
}

/* Number of tasks owned by this uid as the kernel counts them for RLIMIT_NPROC: processes on macOS; threads
 * (tasks) including zombies on Linux. */
static long count_uid_tasks(void) {
#ifdef __APPLE__
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_UID, (int)getuid()};
  size_t len = 0;
  if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return -1;
  return (long)(len / sizeof(struct kinfo_proc));
#else
  DIR *d = opendir("/proc");
  if (!d) return -1;
  long total = 0;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
    char path[PATH_MAX];
    snprintf(path, sizeof path, "/proc/%s", e->d_name);
    struct stat st;
    if (stat(path, &st) != 0 || st.st_uid != getuid()) continue;
    snprintf(path, sizeof path, "/proc/%s/task", e->d_name);
    DIR *t = opendir(path);
    if (!t) { total++; continue; }
    struct dirent *te;
    while ((te = readdir(t))) if (te->d_name[0] >= '0' && te->d_name[0] <= '9') total++;
    closedir(t);
  }
  closedir(d);
  return total;
#endif
}

static void report_limits(void) {
  struct rlimit rl;
  getrlimit(RLIMIT_NPROC, &rl);
  long uid_tasks = count_uid_tasks();
#ifdef __APPLE__
  int maxproc = 0, maxprocperuid = 0;
  size_t l = sizeof maxproc;
  sysctlbyname("kern.maxproc", &maxproc, &l, NULL, 0);
  l = sizeof maxprocperuid;
  sysctlbyname("kern.maxprocperuid", &maxprocperuid, &l, NULL, 0);
  emit(PROBE, "limits", "\"RLIMIT_NPROC_soft\":%llu,\"RLIMIT_NPROC_hard\":%llu,\"kern_maxproc\":%d,\"kern_maxprocperuid\":%d,\"uid_processes_now\":%ld",
       (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max, maxproc, maxprocperuid, uid_tasks);
#else
  emit(PROBE, "limits", "\"RLIMIT_NPROC_soft\":%llu,\"RLIMIT_NPROC_hard\":%llu,\"pid_max\":%ld,\"threads_max\":%ld,\"cgroup_pids_max\":\"%s\",\"uid_tasks_now\":%ld",
       (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max, read_long_file("/proc/sys/kernel/pid_max"),
       read_long_file("/proc/sys/kernel/threads-max"), "see cgroup_explore", uid_tasks);
#endif
}

static void set_nproc_soft(rlim_t v) {
  struct rlimit rl;
  getrlimit(RLIMIT_NPROC, &rl);
  rl.rlim_cur = (v > rl.rlim_max) ? rl.rlim_max : v;
  setrlimit(RLIMIT_NPROC, &rl);
}

static rlim_t g_orig_nproc_soft;

static void restore_nproc(void) {
  struct rlimit rl;
  getrlimit(RLIMIT_NPROC, &rl);
  rl.rlim_cur = g_orig_nproc_soft;
  setrlimit(RLIMIT_NPROC, &rl);
}

static void concurrent_children(void) {
  long base = count_uid_tasks();
  const int budget = 300;
  set_nproc_soft((rlim_t)(base + budget));
  pid_t *pids = calloc(1000, sizeof(pid_t));
  int n = 0, err = 0;
  double first_ms = 0, last_ms = 0, t_all0 = now_ms();
  for (; n < 1000; n++) {
    double t0 = now_ms();
    pid_t p = fork();
    if (p == 0) {
      for (;;) pause();
    }
    double dt = now_ms() - t0;
    if (p < 0) { err = errno; break; }
    pids[n] = p;
    if (n < 100) first_ms += dt;
    if (n >= 200 && n < 300) last_ms += dt;
  }
  double fork_phase_ms = now_ms() - t_all0;
  long uid_after = count_uid_tasks();
  restore_nproc();
  double tk = now_ms();
  for (int i = 0; i < n; i++) kill(pids[i], SIGKILL);
  int reaped = 0;
  for (int i = 0; i < n; i++) { int st; if (waitpid(pids[i], &st, 0) == pids[i]) reaped++; }
  double kill_reap_ms = now_ms() - tk;
  emit(PROBE, "concurrent_children_until_bounded_nproc",
       "\"tasks_of_uid_before\":%ld,\"nproc_soft_set_to\":%ld,\"children_created\":%d,\"stopped_by\":\"%s\",\"tasks_of_uid_after\":%ld,\"first_100_forks_total_ms\":%.1f,\"forks_200_to_300_total_ms\":%.1f,\"fork_phase_ms\":%.0f,\"kill_and_reap_all_ms\":%.0f,\"reaped\":%d",
       base, base + budget, n, n >= 1000 ? "limit_of_this_probe" : errno_name(err), uid_after, first_ms, last_ms, fork_phase_ms, kill_reap_ms, reaped);
  free(pids);
}

static void zombies(void) {
  /* 1. how long does reaping take, and do zombies keep a pid */
  const int N = 300;
  pid_t *pids = calloc((size_t)N, sizeof(pid_t));
  long before = count_uid_tasks();
  double t0 = now_ms();
  int made = 0;
  for (int i = 0; i < N; i++) {
    pid_t p = fork();
    if (p == 0) _exit(0);
    if (p < 0) break;
    pids[made++] = p;
  }
  double make_ms = now_ms() - t0;
  sleep_ms(200);
  long during = count_uid_tasks();
  double t1 = now_ms();
  int reaped = 0;
  for (int i = 0; i < made; i++) { int st; if (waitpid(pids[i], &st, 0) == pids[i]) reaped++; }
  double reap_ms = now_ms() - t1;
  long after = count_uid_tasks();
  emit(PROBE, "zombies_unreaped_then_reaped", "\"children\":%d,\"make_ms\":%.1f,\"uid_tasks_before\":%ld,\"uid_tasks_with_zombies\":%ld,\"uid_tasks_after_reaping\":%ld,\"reap_all_ms\":%.2f,\"reaped\":%d",
       made, make_ms, before, during, after, reap_ms, reaped);

  /* 2. do unreaped zombies count against RLIMIT_NPROC? Allow 20 more tasks, then create 40 children that exit at once. */
  long base = count_uid_tasks();
  set_nproc_soft((rlim_t)(base + 20));
  int created = 0, err = 0;
  pid_t z[64];
  for (int i = 0; i < 40; i++) {
    pid_t p = fork();
    if (p == 0) _exit(0);
    if (p < 0) { err = errno; break; }
    z[created++] = p;
    sleep_ms(2);
  }
  /* reap one, then try again */
  int after_reap_ok = -1, after_reap_err = 0;
  if (created > 0) {
    int st;
    waitpid(z[0], &st, 0);
    pid_t p = fork();
    if (p == 0) _exit(0);
    after_reap_ok = p > 0;
    if (p < 0) after_reap_err = errno; else { z[created++] = p; }
  }
  restore_nproc();
  for (int i = 1; i < created; i++) { int st; waitpid(z[i], &st, 0); }
  emit(PROBE, "zombies_count_against_RLIMIT_NPROC",
       "\"tasks_before\":%ld,\"allowed_extra\":20,\"exited_children_created_before_refusal\":%d,\"refused_with\":\"%s\",\"fork_succeeds_after_reaping_one\":%d,\"errno_after_reaping_one\":\"%s\"",
       base, created, errno_name(err), after_reap_ok, errno_name(after_reap_err));
  free(pids);
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--noop") == 0) return 0;
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(200);
  emit_header(PROBE);
  struct rlimit rl;
  getrlimit(RLIMIT_NPROC, &rl);
  g_orig_nproc_soft = rl.rlim_cur;
  report_limits();
  concurrent_children();
  zombies();
  spawn_latency();
  return 0;
}
