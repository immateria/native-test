/*
 * setrlimit/getrlimit: what is inherited across fork+exec, which limits a supervisor can actually use to
 * contain a child (CPU, files, processes, address space, file size) and what the failure looks like when a
 * limit is hit - including whether spawning still works once the limit is exhausted. Untested in the kit.
 *
 * Build: cc -O1 -Wall -Wextra -o rlimit rlimit.c
 */
#include "common.h"
#include <limits.h>
#include <spawn.h>
#include <sys/mman.h>
#define PROBE "rlimit"

extern char **environ;
static char g_self[PATH_MAX];

static const struct { int res; const char *name; } k_limits[] = {
  {RLIMIT_CPU, "CPU"}, {RLIMIT_FSIZE, "FSIZE"}, {RLIMIT_DATA, "DATA"}, {RLIMIT_STACK, "STACK"}, {RLIMIT_CORE, "CORE"},
  {RLIMIT_AS, "AS"}, {RLIMIT_NOFILE, "NOFILE"}, {RLIMIT_NPROC, "NPROC"}, {RLIMIT_MEMLOCK, "MEMLOCK"}, {RLIMIT_RSS, "RSS"},
};

static void fmt_lim(rlim_t v, char *b, size_t n) {
  if (v == RLIM_INFINITY) snprintf(b, n, "infinity");
  else snprintf(b, n, "%llu", (unsigned long long)v);
}

static void limits_json(char *out, size_t n) {
  size_t len = 0;
  out[0] = 0;
  for (size_t i = 0; i < sizeof k_limits / sizeof k_limits[0]; i++) {
    struct rlimit rl;
    char s[32], h[32];
    if (getrlimit(k_limits[i].res, &rl) != 0) { snprintf(s, sizeof s, "err"); snprintf(h, sizeof h, "%s", errno_name(errno)); }
    else { fmt_lim(rl.rlim_cur, s, sizeof s); fmt_lim(rl.rlim_max, h, sizeof h); }
    len += (size_t)snprintf(out + len, n - len, "%s\"%s\":\"%s/%s\"", i ? "," : "", k_limits[i].name, s, h);
  }
}

static pid_t fork_run(void (*fn)(void)) {
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) { fn(); fflush(stdout); _exit(0); }
  return p;
}

static void wait_report(pid_t p, const char *kase, int timeout_ms) {
  char st[64];
  reap_blocking(p, timeout_ms, st, sizeof st);
  if (strcmp(st, "exited(0)") != 0) emit(PROBE, kase, "\"worker_status\":\"%s\"", st);
}

/* ---- individual experiments, each runs in its own forked process ---- */

static void exp_inherit(void) {
  struct rlimit rl;
  rl.rlim_cur = 64; rl.rlim_max = 128;
  int r1 = setrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = 0; rl.rlim_max = 0;
  int r2 = setrlimit(RLIMIT_CORE, &rl);
  rl.rlim_cur = 77; rl.rlim_max = 99;
  int r3 = setrlimit(RLIMIT_CPU, &rl);
  int pfd[2];
  if (pipe(pfd) != 0) return;
  /* fork + exec */
  pid_t p = fork();
  if (p == 0) {
    dup2(pfd[1], 1);
    execl(g_self, g_self, "--print-limits", "fork_exec", (char *)NULL);
    _exit(127);
  }
  char buf[2048];
  int eof;
  close(pfd[1]);
  drain_until(pfd[0], buf, sizeof buf, 3000, &eof);
  waitpid(p, NULL, 0);
  buf[strcspn(buf, "\n")] = 0;
  emit(PROBE, "inherit_set_nofile_core_cpu_in_parent", "\"setrlimit_rc\":[%d,%d,%d],\"child_printed\":%s", r1, r2, r3,
       buf[0] ? buf : "null");
  /* posix_spawn */
  int pfd2[2];
  if (pipe(pfd2) != 0) return;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, pfd2[1], 1);
  char *args[] = {g_self, (char *)"--print-limits", (char *)"posix_spawn", NULL};
  pid_t sp = 0;
  int rc = posix_spawn(&sp, g_self, &fa, NULL, args, environ);
  close(pfd2[1]);
  drain_until(pfd2[0], buf, sizeof buf, 3000, &eof);
  if (rc == 0) waitpid(sp, NULL, 0);
  buf[strcspn(buf, "\n")] = 0;
  emit(PROBE, "inherit_posix_spawn", "\"posix_spawn_rc\":\"%s\",\"child_printed\":%s", errno_name(rc), buf[0] ? buf : "null");
}

static volatile sig_atomic_t g_xcpu = 0;
static void on_xcpu(int s) { (void)s; g_xcpu++; }

static void spin_cpu_limit(int ignore_xcpu, const char *kase) {
  struct rlimit rl = {1, 3};
  setrlimit(RLIMIT_CPU, &rl);
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  if (ignore_xcpu == 1) { sa.sa_handler = SIG_IGN; sigaction(SIGXCPU, &sa, NULL); }
  else if (ignore_xcpu == 2) { sa.sa_handler = on_xcpu; sigaction(SIGXCPU, &sa, NULL); }
  double t0 = now_ms();
  struct timespec ts;
  for (;;) {
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    if (ts.tv_sec >= 8) break; /* give up; the limit never fired */
    if (ignore_xcpu == 2 && g_xcpu && ((long)(now_ms() - t0) % 1000) == 0) { /* keep spinning */ }
  }
  emit(PROBE, kase, "\"outcome\":\"limit never terminated the process within 8 s of CPU\",\"xcpu_handler_calls\":%d,\"wall_ms\":%.0f", (int)g_xcpu, now_ms() - t0);
}
static void exp_cpu_default(void) { spin_cpu_limit(0, "cpu_limit_default_sigxcpu"); }
static void exp_cpu_ignored(void) { spin_cpu_limit(1, "cpu_limit_sigxcpu_ignored"); }

static void run_cpu_trio(void) {
  /* run concurrently so the whole experiment costs ~4 s of wall time */
  double t0 = now_ms();
  fflush(stdout);
  pid_t a = fork_run(exp_cpu_default), b = fork_run(exp_cpu_ignored);
  char sa_[64], sb_[64];
  double ta = 0, tb = 0;
  reap_blocking(a, 12000, sa_, sizeof sa_); ta = now_ms() - t0;
  reap_blocking(b, 12000, sb_, sizeof sb_); tb = now_ms() - t0;
  emit(PROBE, "cpu_limit_soft1_hard3", "\"default_action_status\":\"%s\",\"default_action_wall_ms\":%.0f,"
       "\"sigxcpu_ignored_status\":\"%s\",\"sigxcpu_ignored_wall_ms\":%.0f", sa_, ta, sb_, tb);
}

static void nofile_exhausted(int cloexec, const char *kase) {
  struct rlimit rl = {32, 32};
  int sr = setrlimit(RLIMIT_NOFILE, &rl);
  int fds[64], n = 0, last_errno = 0;
  for (; n < 64; n++) {
    fds[n] = open("/dev/null", O_RDONLY | (cloexec ? O_CLOEXEC : 0));
    if (fds[n] < 0) { last_errno = errno; break; }
  }
  int pipe_fds[2];
  int pr = pipe(pipe_fds);
  int pe = errno;
  fflush(stdout);
  pid_t f = fork();
  if (f == 0) {
    dup2(2, 1);
    execl(g_self, g_self, "--noop", (char *)NULL);
    _exit(126); /* exec itself failed */
  }
  int fe = errno;
  char fst[64] = "";
  if (f > 0) reap_blocking(f, 3000, fst, sizeof fst);
  pid_t sp = 0;
  char *args[] = {g_self, (char *)"--noop", NULL};
  int rc = posix_spawn(&sp, g_self, NULL, NULL, args, environ);
  char sst[64] = "";
  if (rc == 0) reap_blocking(sp, 3000, sst, sizeof sst);
  emit(PROBE, kase,
       "\"fds_opened_with_cloexec\":%s,\"setrlimit_rc\":%d,\"opened_before_EMFILE\":%d,\"open_errno\":\"%s\",\"pipe_rc\":%d,\"pipe_errno\":\"%s\","
       "\"fork_ok\":%s,\"fork_errno\":\"%s\",\"fork_exec_status\":\"%s\",\"posix_spawn_rc\":\"%s\",\"posix_spawn_status\":\"%s\","
       "\"note\":\"exited(126) = exec failed; exited(127) = exec worked but the new program could not start (dynamic loader)\"",
       cloexec ? "true" : "false", sr, n, errno_name(last_errno), pr, pr ? errno_name(pe) : "OK", f > 0 ? "true" : "false",
       f > 0 ? "OK" : errno_name(fe), fst, errno_name(rc), sst);
}
static void exp_nofile_leaky(void) { nofile_exhausted(0, "nofile_exhausted_fds_inheritable"); }
static void exp_nofile_cloexec(void) { nofile_exhausted(1, "nofile_exhausted_fds_cloexec"); }

static void exp_nofile_infinity(void) {
  struct rlimit cur;
  getrlimit(RLIMIT_NOFILE, &cur);
  struct rlimit rl = cur;
  rl.rlim_cur = RLIM_INFINITY;
  int r1 = setrlimit(RLIMIT_NOFILE, &rl);
  int e1 = errno;
  rl = cur;
  rl.rlim_max = cur.rlim_max == RLIM_INFINITY ? cur.rlim_max : cur.rlim_max + 1000;
  int r2 = setrlimit(RLIMIT_NOFILE, &rl);
  int e2 = errno;
  rl.rlim_cur = 16; rl.rlim_max = 16;
  int r3 = setrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = 16; rl.rlim_max = 4096;
  int r4 = setrlimit(RLIMIT_NOFILE, &rl);
  int e4 = errno;
  char before[32], after[32];
  fmt_lim(cur.rlim_cur, before, sizeof before);
  fmt_lim(cur.rlim_max, after, sizeof after);
  emit(PROBE, "nofile_set_infinity_and_raise_hard",
       "\"initial_soft\":\"%s\",\"initial_hard\":\"%s\",\"soft_to_infinity\":\"%s\",\"hard_raise\":\"%s\",\"lower_both_to_16\":\"%s\",\"raise_hard_after_lowering\":\"%s\"",
       before, after, r1 == 0 ? "OK" : errno_name(e1), r2 == 0 ? "OK" : errno_name(e2), r3 == 0 ? "OK" : "fail", r4 == 0 ? "OK" : errno_name(e4));
}

static void exp_nproc(void) {
  struct rlimit rl = {1, 1};
  int sr = setrlimit(RLIMIT_NPROC, &rl);
  int se = errno;
  fflush(stdout);
  pid_t f = fork();
  if (f == 0) _exit(0);
  int fe = errno;
  char fst[64] = "";
  if (f > 0) reap_blocking(f, 3000, fst, sizeof fst);
  pid_t sp = 0;
  char *args[] = {(char *)"true", NULL};
  int rc = posix_spawn(&sp, "/usr/bin/true", NULL, NULL, args, environ);
  char sst[64] = "";
  if (rc == 0) reap_blocking(sp, 3000, sst, sizeof sst);
  emit(PROBE, "nproc_limit_1_then_fork_and_spawn",
       "\"setrlimit_rc\":\"%s\",\"fork_succeeded\":%s,\"fork_errno\":\"%s\",\"posix_spawn_rc\":\"%s\",\"posix_spawn_status\":\"%s\","
       "\"note\":\"root bypasses RLIMIT_NPROC on Linux\"",
       sr == 0 ? "OK" : errno_name(se), f > 0 ? "true" : "false", f > 0 ? "OK" : errno_name(fe), errno_name(rc), sst);
}

static void exp_address_space(void) {
  size_t big = (size_t)768 * 1024 * 1024;
  struct rlimit rl = {(rlim_t)512 * 1024 * 1024, (rlim_t)512 * 1024 * 1024};
  int r_as = setrlimit(RLIMIT_AS, &rl);
  int e_as = errno;
  void *p = mmap(NULL, big, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  int mmap_ok_as = p != MAP_FAILED;
  int mmap_errno_as = mmap_ok_as ? 0 : errno;
  if (mmap_ok_as) munmap(p, big);
  void *m = malloc(big);
  int malloc_ok_as = m != NULL;
  free(m);
  emit(PROBE, "rlimit_as_512MiB_then_768MiB_allocation",
       "\"setrlimit_rc\":\"%s\",\"mmap_ok\":%s,\"mmap_errno\":\"%s\",\"malloc_ok\":%s", r_as == 0 ? "OK" : errno_name(e_as),
       mmap_ok_as ? "true" : "false", errno_name(mmap_errno_as), malloc_ok_as ? "true" : "false");
}

static void exp_data(void) {
  size_t big = (size_t)768 * 1024 * 1024;
  struct rlimit rl = {(rlim_t)512 * 1024 * 1024, (rlim_t)512 * 1024 * 1024};
  int r = setrlimit(RLIMIT_DATA, &rl);
  int e = errno;
  void *p = mmap(NULL, big, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  int ok = p != MAP_FAILED;
  int me = ok ? 0 : errno;
  if (ok) { for (size_t i = 0; i < big; i += 4096) ((char *)p)[i] = 1; munmap(p, big); }
  void *m = malloc(big);
  int mok = m != NULL;
  if (m) { for (size_t i = 0; i < big; i += 4096) ((char *)m)[i] = 1; }
  free(m);
  emit(PROBE, "rlimit_data_512MiB_then_768MiB_allocation",
       "\"setrlimit_rc\":\"%s\",\"mmap_anon_ok\":%s,\"mmap_errno\":\"%s\",\"malloc_ok\":%s", r == 0 ? "OK" : errno_name(e),
       ok ? "true" : "false", errno_name(me), mok ? "true" : "false");
}

static void exp_fsize(void) {
  struct rlimit rl = {1024 * 1024, 1024 * 1024};
  setrlimit(RLIMIT_FSIZE, &rl);
  signal(SIGXFSZ, SIG_IGN);
  char path[256];
  snprintf(path, sizeof path, "%s/rlimit-fsize-%d.bin", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  static char buf[256 * 1024];
  long total = 0;
  int err = 0;
  for (int i = 0; i < 16; i++) {
    ssize_t w = write(fd, buf, sizeof buf);
    if (w < 0) { err = errno; break; }
    total += w;
    if ((size_t)w < sizeof buf) break;
  }
  close(fd);
  unlink(path);
  emit(PROBE, "fsize_1MiB_with_sigxfsz_ignored", "\"bytes_written\":%ld,\"write_errno\":\"%s\"", total, errno_name(err));
}

static int print_limits(const char *how) {
  char b[2048];
  limits_json(b, sizeof b);
  printf("{\"via\":\"%s\",%s}\n", how, b);
  return 0;
}

int main(int argc, char **argv) {
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  if (argc > 2 && strcmp(argv[1], "--print-limits") == 0) return print_limits(argv[2]);
  if (argc > 1 && strcmp(argv[1], "--noop") == 0) return 0;
  watchdog(120);
  emit_header(PROBE);
  char b[2048];
  limits_json(b, sizeof b);
  emit(PROBE, "defaults_soft_slash_hard", "%s", b);
  wait_report(fork_run(exp_inherit), "inherit", 8000);
  run_cpu_trio();
  wait_report(fork_run(exp_nofile_leaky), "nofile", 8000);
  wait_report(fork_run(exp_nofile_cloexec), "nofile", 8000);
  wait_report(fork_run(exp_nofile_infinity), "nofile_inf", 8000);
  wait_report(fork_run(exp_nproc), "nproc", 8000);
  wait_report(fork_run(exp_address_space), "as", 8000);
  wait_report(fork_run(exp_data), "data", 15000);
  wait_report(fork_run(exp_fsize), "fsize", 8000);
  return 0;
}
