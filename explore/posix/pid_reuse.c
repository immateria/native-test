/*
 * PID allocation and reuse (macOS and Linux). Supervisors that hold a bare pid can signal a stranger once that pid is
 * recycled; how soon can that happen? JSON lines; never asserts.
 *   - allocation pattern: consecutive pids for back-to-back children?
 *   - a full wrap: fork/reap until the first pid comes back (bounded by time); whether a held zombie's pid is skipped
 *   - Linux: inside an unprivileged user+PID namespace, ns_last_pid hands a just-freed pid out again at once
 * Build: cc -O1 -Wall -Wextra -o pid_reuse pid_reuse.c
 */
#include "common.h"
#include <sched.h>
#ifdef __linux__
#include <sys/mount.h>
#endif

#define PROBE "pid_reuse"

static const char *bstr(int b) { return b ? "true" : "false"; }

static pid_t fork_exit(void) {
  pid_t p = fork();
  if (p == 0) _exit(0);
  if (p > 0) waitpid(p, NULL, 0);
  return p;
}

static long pid_max(void) {
#ifdef __linux__
  char b[32] = "";
  int fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
  if (fd < 0) return -1;
  ssize_t n = read(fd, b, sizeof b - 1);
  close(fd);
  b[n > 0 ? n : 0] = 0;
  return atol(b);
#else
  return 99999; /* PID_MAX in xnu bsd/sys/proc_internal.h */
#endif
}

static void exp_pattern(void) {
  pid_t prev = fork_exit(), first = prev;
  int consecutive = 0, n = 200;
  long max_gap = 0;
  for (int i = 0; i < n; i++) {
    pid_t p = fork_exit();
    long d = (long)p - (long)prev;
    if (d == 1) consecutive++;
    if (d > max_gap) max_gap = d;
    prev = p;
  }
  emit(PROBE, "allocation_pattern", "\"children\":%d,\"first\":%d,\"last\":%d,\"steps_of_exactly_1\":%d,\"largest_step\":%ld,\"pid_max\":%ld",
       n, (int)first, (int)prev, consecutive, max_gap, pid_max());
}

static void exp_wrap(int seconds) {
  /* hold one zombie: its pid must never be handed out while it is unreaped */
  pid_t zombie = fork();
  if (zombie == 0) _exit(0);
  sleep_ms(20);
  pid_t first = fork_exit();
  double t0 = now_ms();
  long forks = 0;
  int reused = 0, zombie_pid_given = 0, wrapped = 0;
  pid_t prev = first, p = 0;
  while (now_ms() - t0 < seconds * 1000.0) {
    p = fork_exit();
    if (p < 0) { sleep_ms(1); continue; }
    forks++;
    if (p < prev) wrapped++;
    prev = p;
    if (p == zombie) zombie_pid_given = 1;
    if (p == first) { reused = 1; break; }
  }
  double dt = now_ms() - t0;
  waitpid(zombie, NULL, 0);
  emit(PROBE, "time_until_a_pid_is_reused",
       "\"first_pid\":%d,\"reused\":%s,\"forks\":%ld,\"seconds\":%.1f,\"forks_per_second\":%.0f,\"wrapped_around\":%d,\"held_zombie_pid_handed_out\":%s,"
       "\"estimated_seconds_for_full_cycle\":%.0f",
       (int)first, bstr(reused), forks, dt / 1000.0, forks * 1000.0 / dt, wrapped, bstr(zombie_pid_given), (double)pid_max() / (forks * 1000.0 / dt));
}

#ifdef __linux__
static void exp_ns_last_pid(void) {
  int pp[2];
  (void)!pipe(pp);
  fflush(stdout);
  pid_t outer = fork();
  if (outer == 0) {
    uid_t uid = getuid();
    char b[256];
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID) < 0) {
      int n = snprintf(b, sizeof b, "unshare=%s", errno_name(errno));
      (void)!write(pp[1], b, (size_t)n);
      _exit(0);
    }
    char m[64];
    int fd = open("/proc/self/uid_map", O_WRONLY);
    int k = snprintf(m, sizeof m, "0 %d 1\n", (int)uid);
    int map_e = fd < 0 ? errno : (write(fd, m, (size_t)k) < 0 ? errno : 0);
    if (fd >= 0) close(fd);
    pid_t init = fork(); /* pid 1 in the namespace; it needs /proc for the namespace: mount it in a mount namespace */
    if (init == 0) {
      int mnt = unshare(CLONE_NEWNS);
      int mnt_e = mnt < 0 ? errno : 0;
      int mp = mnt == 0 ? mount("none", "/proc", NULL, MS_REC | MS_PRIVATE, NULL) : -1;
      int pr = mnt == 0 ? mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) : -1;
      int pr_e = pr < 0 ? errno : 0;
      (void)mp;
      pid_t a = fork_exit();
      int w = -2, we = 0;
      pid_t again = -1;
      int lf = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
      if (lf >= 0) {
        char v[32];
        int vn = snprintf(v, sizeof v, "%d", (int)a - 1);
        w = (int)write(lf, v, (size_t)vn);
        we = w < 0 ? errno : 0;
        close(lf);
        again = fork_exit();
      } else {
        we = errno;
      }
      int n = snprintf(b, sizeof b, "uid_map=%s mount_ns=%s proc_mount=%s first_child_pid=%d ns_last_pid_write=%s next_child_pid=%d",
                       errno_name(map_e), errno_name(mnt_e), errno_name(pr_e), (int)a, w >= 0 ? "OK" : errno_name(we), (int)again);
      (void)!write(pp[1], b, (size_t)n);
      _exit(0);
    }
    waitpid(init, NULL, 0);
    _exit(0);
  }
  close(pp[1]);
  char out[300] = "";
  ssize_t n = read_timeout(pp[0], out, sizeof out - 1, 5000);
  out[n > 0 ? n : 0] = 0;
  waitpid(outer, NULL, 0);
  close(pp[0]);
  emit(PROBE, "linux_ns_last_pid_reissues_a_freed_pid", "\"report\":\"%s\"", out);
}
#endif

int main(void) {
  watchdog(150);
  emit_header(PROBE);
  exp_pattern();
#ifdef __APPLE__
  exp_wrap(90);
#else
  exp_wrap(20);
  exp_ns_last_pid();
#endif
  return 0;
}
