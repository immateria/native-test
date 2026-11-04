/*
 * Putting a child into a cgroup: how much does "spawn, then write the pid to cgroup.procs" leak, and what are the
 * alternatives a Crystal supervisor could use? Records JSON lines, never asserts.
 *
 *   spawn_cgroup <D>        D = a delegated cgroup-v2 subtree (the CI step creates it, chowns it to the runner user)
 *
 * Race (escape_*): the child program forks 6 children as its first action (a shell starting background jobs does the
 * same). How many of those children end up outside the target cgroup, per way of getting the child into it?
 *   fork_attach_immediately     fork+exec, parent writes the pid to cgroup.procs right after fork() returns (best case)
 *   fork_attach_after_exec      fork+exec, parent waits for the exec to complete (CLOEXEC pipe closing, which is what
 *                               Crystal's Process.new does before it returns) and then attaches
 *   clone3_into_cgroup          clone3(CLONE_INTO_CGROUP), the child execs; it is in the cgroup before it runs
 *   sh_trampoline / bash_trampoline  fork+exec of `sh -c 'echo $$ > cgroup.procs && exec "$@"'`: the shell moves itself,
 *                               then execs the program
 * each idle and with 2 busy processes per CPU competing for the CPUs.
 *
 * Other cases: clone3_errors (the errno for each way it can be refused), clone3_frozen_target, clone3_pids_max,
 * clone3_pidfd_and_cgroup, populated_visibility, trampoline_fidelity (environment, arguments, fds, signals as the
 * program sees them, direct vs through sh/bash), trampoline_exit_codes, spawn_latency_vs_rss (fork vs posix_spawn vs
 * clone3 with a 0 / 256 / 1024 MiB parent).
 *
 * Build: cc -O1 -Wall -Wextra -o spawn_cgroup spawn_cgroup.c   (Linux only)
 */
#include "../posix/common.h"

#ifndef __linux__
int main(void) { printf("{\"probe\":\"spawn_cgroup\",\"case\":\"_unsupported\"}\n"); return 0; }
#else

#include <limits.h>
#include <sched.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/sched.h>

#define PROBE "spawn_cgroup"

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

extern char **environ;

struct clone_args_v2 {
  uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

static char g_root[512];   /* the delegated subtree D */
static char g_self[PATH_MAX];
static char g_prefix[] = "/sys/fs/cgroup";

typedef struct { double t; int pid; int pad; } rec_t;

/* ------------------------------------------------------------------ small helpers */
static int cg_write(const char *dir, const char *file, const char *value) {
  char p[1024];
  snprintf(p, sizeof p, "%s/%s", dir, file);
  int fd = open(p, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return errno;
  ssize_t n = write(fd, value, strlen(value));
  int e = n < 0 ? errno : 0;
  close(fd);
  return e;
}

static int cg_read(const char *dir, const char *file, char *buf, size_t cap) {
  char p[1024];
  snprintf(p, sizeof p, "%s/%s", dir, file);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { buf[0] = 0; return -1; }
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  buf[n > 0 ? n : 0] = 0;
  return (int)n;
}

static long long cg_key(const char *dir, const char *file, const char *key) {
  char b[4096];
  if (cg_read(dir, file, b, sizeof b) <= 0) return -1;
  size_t kl = strlen(key);
  for (char *l = b; l && *l;) {
    if (strncmp(l, key, kl) == 0 && l[kl] == ' ') return atoll(l + kl + 1);
    l = strchr(l, '\n');
    if (l) l++;
  }
  return -1;
}

/* the cgroup (unified hierarchy path) a pid is in, "" if the process is gone */
static int cgroup_of(pid_t pid, char *out, size_t cap) {
  char p[64], b[4096];
  snprintf(p, sizeof p, "/proc/%d/cgroup", (int)pid);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
  out[0] = 0;
  if (fd < 0) return -1;
  ssize_t n = read(fd, b, sizeof b - 1);
  close(fd);
  if (n <= 0) return -1;
  b[n] = 0;
  for (char *l = b; l && *l;) {
    if (strncmp(l, "0::", 3) == 0) {
      char *e = strchr(l, '\n');
      if (e) *e = 0;
      snprintf(out, cap, "%s", l + 3);
      return 0;
    }
    l = strchr(l, '\n');
    if (l) l++;
  }
  return -1;
}

static const char *rel_of(const char *abs) {
  size_t k = strlen(g_prefix);
  return strncmp(abs, g_prefix, k) == 0 ? abs + k : abs;
}

static int make_leaf(const char *name, char *out, size_t cap) {
  snprintf(out, cap, "%s/%s", g_root, name);
  if (mkdir(out, 0755) != 0 && errno != EEXIST) {
    emit(PROBE, "_setup_error", "\"mkdir\":\"%s\",\"errno\":\"%s\"", out, errno_name(errno));
    return -1;
  }
  return 0;
}

static void leaf_empty_and_remove(const char *dir) {
  cg_write(dir, "cgroup.kill", "1");
  double end = now_ms() + 1500;
  while (now_ms() < end && cg_key(dir, "cgroup.events", "populated") == 1) sleep_ms(1);
  rmdir(dir);
}

static int cmp_d(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}
static double pct(double *v, int n, double q) {
  if (n <= 0) return -1;
  qsort(v, (size_t)n, sizeof(double), cmp_d);
  int i = (int)(q * (n - 1) + 0.5);
  return v[i];
}

static long clone3_raw(uint64_t flags, int dirfd, int *pidfd_out, size_t size) {
  struct clone_args_v2 ca;
  memset(&ca, 0, sizeof ca);
  ca.flags = flags;
  ca.exit_signal = SIGCHLD;
  if (flags & CLONE_INTO_CGROUP) ca.cgroup = (uint64_t)(unsigned)dirfd;
  if (flags & CLONE_PIDFD) ca.pidfd = (uint64_t)(uintptr_t)pidfd_out;
  return syscall(SYS_clone3, &ca, size);
}

/* ------------------------------------------------------------------ child programs (re-exec'd copies of this binary) */
/* --burst N FD: report the start time, fork N children as fast as possible reporting each, then sleep */
static int burst_main(int n, int fd) {
  rec_t r = {now_ms(), 0, 0};
  (void)!write(fd, &r, sizeof r);
  for (int i = 0; i < n; i++) {
    double t = now_ms();
    pid_t c = fork();
    if (c == 0) { sleep_ms(4000); _exit(0); }
    rec_t q = {t, (int)c, 0};
    (void)!write(fd, &q, sizeof q);
  }
  sleep_ms(4000);
  return 0;
}

static void esc_to(FILE *f, const unsigned char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (s[i] >= 0x20 && s[i] < 0x7f && s[i] != '\\') fputc(s[i], f);
    else fprintf(f, "\\x%02x", s[i]);
  }
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* --dump: print what the program sees: argv, environment (sorted), fds, ignored/blocked signals, umask, cwd */
static int dump_main(int argc, char **argv) {
  for (int i = 0; i < argc; i++) { printf("arg[%d]=", i); esc_to(stdout, (unsigned char *)argv[i], strlen(argv[i])); printf("\n"); }
  int n = 0;
  while (environ[n]) n++;
  char **sorted = malloc((size_t)(n + 1) * sizeof *sorted);
  memcpy(sorted, environ, (size_t)n * sizeof *sorted);
  qsort(sorted, (size_t)n, sizeof *sorted, cmp_str);
  for (int i = 0; i < n; i++) { printf("env:"); esc_to(stdout, (unsigned char *)sorted[i], strlen(sorted[i])); printf("\n"); }
  printf("fds=");
  for (int fd = 0; fd < 64; fd++) if (fcntl(fd, F_GETFD) != -1) printf("%d,", fd);
  printf("\nignored=");
  for (int s = 1; s < 32; s++) {
    struct sigaction sa;
    if (sigaction(s, NULL, &sa) == 0 && sa.sa_handler == SIG_IGN) printf("%s,", sig_name(s));
  }
  sigset_t m;
  sigprocmask(SIG_BLOCK, NULL, &m);
  printf("\nblocked=");
  for (int s = 1; s < 32; s++) if (sigismember(&m, s) == 1) printf("%s,", sig_name(s));
  mode_t um = umask(022);
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) cwd[0] = 0;
  printf("\numask=%03o\ncwd=%s\n", (unsigned)um, cwd);
  return 0;
}

/* ------------------------------------------------------------------ the escape trials */
enum { K_FORK_NOW, K_FORK_AFTER_EXEC, K_CLONE3, K_SH, K_BASH };
static const char *kind_name(int k) {
  static const char *n[] = {"fork_attach_immediately", "fork_attach_after_exec", "clone3_into_cgroup", "sh_trampoline", "bash_trampoline"};
  return n[k];
}

typedef struct {
  int ok, grand, escaped, parent_in, populated_before_attach;
  double to_main_ms, attach_after_notice_us;
} trial_t;

static int g_burst_n = 6;
static char g_cgprocs[1100];

static pid_t spawn_kind(int kind, int dirfd, int rfd_w, int ep_w, int *clone_errno) {
  char nbuf[16], fbuf[16];
  snprintf(nbuf, sizeof nbuf, "%d", g_burst_n);
  snprintf(fbuf, sizeof fbuf, "%d", rfd_w);
  char *burst[] = {g_self, "--burst", nbuf, fbuf, NULL};
  char *viash[] = {"sh", "-c", "echo $$ > \"$0\" && exec \"$@\"", g_cgprocs, g_self, "--burst", nbuf, fbuf, NULL};
  char *viabash[] = {"bash", "-c", "echo $$ > \"$0\" && exec \"$@\"", g_cgprocs, g_self, "--burst", nbuf, fbuf, NULL};
  (void)ep_w;
  pid_t pid;
  *clone_errno = 0;
  if (kind == K_CLONE3) {
    pid = (pid_t)clone3_raw(CLONE_INTO_CGROUP, dirfd, NULL, sizeof(struct clone_args_v2));
    if (pid < 0) { *clone_errno = errno; return -1; }
  } else {
    pid = fork();
  }
  if (pid == 0) {
    if (kind == K_SH) execv("/bin/sh", viash);
    else if (kind == K_BASH) execv("/bin/bash", viabash);
    else execv(g_self, burst);
    _exit(127);
  }
  return pid;
}

static void run_trial(int kind, const char *leaf, int dirfd, trial_t *o) {
  memset(o, 0, sizeof *o);
  int rp[2], ep[2];
  if (pipe(rp) != 0) return;
  if (pipe2(ep, O_CLOEXEC) != 0) { close(rp[0]); close(rp[1]); return; }
  snprintf(g_cgprocs, sizeof g_cgprocs, "%s/cgroup.procs", leaf);
  const char *rel = rel_of(leaf);
  double t0 = now_ms();
  int ce;
  pid_t pid = spawn_kind(kind, dirfd, rp[1], ep[1], &ce);
  close(ep[1]);
  close(rp[1]);
  if (pid < 0) { close(ep[0]); close(rp[0]); return; }
  double t_attach_done = 0;
  if (kind == K_FORK_NOW || kind == K_FORK_AFTER_EXEC) {
    double t_notice = 0;
    if (kind == K_FORK_AFTER_EXEC) {
      char c;
      ssize_t k;
      do { k = read(ep[0], &c, 1); } while (k < 0 && errno == EINTR);   /* EOF = the exec happened */
      t_notice = now_ms();
    }
    char num[24];
    snprintf(num, sizeof num, "%d", (int)pid);
    cg_write(leaf, "cgroup.procs", num);
    t_attach_done = now_ms();
    if (kind == K_FORK_AFTER_EXEC) o->attach_after_notice_us = (t_attach_done - t_notice) * 1000.0;
  }
  close(ep[0]);

  rec_t recs[16];
  int got = 0, want = g_burst_n + 1;
  char raw[16 * sizeof(rec_t)];
  size_t have = 0;
  double end = now_ms() + 1500;
  while (got < want && now_ms() < end) {
    ssize_t k = read_timeout(rp[0], raw + have, sizeof raw - have, 50);
    if (k == 0) break;
    if (k < 0) continue;
    have += (size_t)k;
    while (have >= sizeof(rec_t) && got < 16) {
      memcpy(&recs[got++], raw, sizeof(rec_t));
      memmove(raw, raw + sizeof(rec_t), have - sizeof(rec_t));
      have -= sizeof(rec_t);
    }
  }
  close(rp[0]);

  char cg[512];
  if (got > 0) o->to_main_ms = recs[0].t - t0;
  o->ok = got == want;
  for (int i = 1; i < got; i++) {
    o->grand++;
    int r = cgroup_of((pid_t)recs[i].pid, cg, sizeof cg);
    if (r == 0 && strcmp(cg, rel) != 0) o->escaped++;
  }
  o->parent_in = cgroup_of(pid, cg, sizeof cg) == 0 && strcmp(cg, rel) == 0;
  (void)t_attach_done;
  for (int i = 1; i < got; i++) kill((pid_t)recs[i].pid, SIGKILL);
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
}

static pid_t g_load[64];
static int g_nload;
static void start_load(int n) {
  g_nload = 0;
  for (int i = 0; i < n && i < 64; i++) {
    pid_t c = fork();
    if (c == 0) { alarm(120); for (;;) {} }
    if (c > 0) g_load[g_nload++] = c;
  }
}
static void stop_load(void) {
  for (int i = 0; i < g_nload; i++) { kill(g_load[i], SIGKILL); waitpid(g_load[i], NULL, 0); }
  g_nload = 0;
}

static void escape_series(int kind, int loaded, int n) {
  char leaf[600];
  char name[64];
  snprintf(name, sizeof name, "esc-%d-%d", kind, loaded);
  if (make_leaf(name, leaf, sizeof leaf)) return;
  int dirfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  if (loaded) start_load((int)(cpus * 2));
  int ok = 0, with_escape = 0, grand = 0, escaped = 0, parent_not_in = 0;
  double main_ms[400], attach_us[400];
  int nm = 0, na = 0;
  for (int i = 0; i < n; i++) {
    trial_t t;
    run_trial(kind, leaf, dirfd, &t);
    if (!t.ok) continue;
    ok++;
    grand += t.grand;
    escaped += t.escaped;
    if (t.escaped) with_escape++;
    if (!t.parent_in) parent_not_in++;
    if (nm < 400) main_ms[nm++] = t.to_main_ms;
    if (kind == K_FORK_AFTER_EXEC && na < 400) attach_us[na++] = t.attach_after_notice_us;
  }
  if (loaded) stop_load();
  leaf_empty_and_remove(leaf);
  close(dirfd);
  char cname[96];
  snprintf(cname, sizeof cname, "escape_%s_%s", kind_name(kind), loaded ? "busy" : "idle");
  emit(PROBE, cname,
       "\"children_forked_first_thing\":%d,\"trials_completed\":%d,\"trials_with_an_escapee\":%d,\"children_total\":%d,\"children_outside_cgroup\":%d,\"program_itself_not_in_cgroup_at_end\":%d,\"cpus\":%ld,\"busy_processes\":%ld,\"spawn_to_program_main_ms\":{\"median\":%.3f,\"p95\":%.3f},\"attach_after_exec_notice_us\":{\"median\":%.1f,\"p95\":%.1f}",
       g_burst_n, ok, with_escape, grand, escaped, parent_not_in, cpus, loaded ? cpus * 2 : 0L,
       pct(main_ms, nm, 0.5), pct(main_ms, nm, 0.95), pct(attach_us, na, 0.5), pct(attach_us, na, 0.95));
}

/* ------------------------------------------------------------------ clone3 cases */
typedef struct { int err; pid_t pid; int rfd; int pidfd; } cp_t;

/* clone3 into dirfd (or not); the child writes one byte, holds for hold_ms, then exits. rfd is the read end. */
static void clone_probe(uint64_t flags, int dirfd, size_t size, int hold_ms, cp_t *o) {
  int pp[2];
  memset(o, 0, sizeof *o);
  o->pid = -1;
  o->rfd = -1;
  o->pidfd = -1;
  if (pipe2(pp, O_CLOEXEC) != 0) { o->err = errno; return; }
  fflush(stdout);
  long r = clone3_raw(flags, dirfd, &o->pidfd, size);
  if (r == 0) {
    (void)!write(pp[1], "x", 1);
    sleep_ms(hold_ms);
    _exit(0);
  }
  if (r < 0) { o->err = errno; close(pp[0]); close(pp[1]); return; }
  o->pid = (pid_t)r;
  close(pp[1]);
  o->rfd = pp[0];
}

static int ran(cp_t *c, int wait_ms) {
  char b;
  return c->rfd >= 0 && read_timeout(c->rfd, &b, 1, wait_ms) == 1;
}

static void finish(cp_t *c) {
  if (c->pid > 0) { kill(c->pid, SIGKILL); waitpid(c->pid, NULL, 0); }
  if (c->rfd >= 0) close(c->rfd);
  if (c->pidfd >= 0) close(c->pidfd);
  c->pid = -1;
  c->rfd = c->pidfd = -1;
}

static void add_result(char *buf, size_t cap, const char *what, cp_t *c, int in_leaf) {
  size_t l = strlen(buf);
  snprintf(buf + l, cap - l, "%s{\"what\":\"%s\",\"result\":\"%s\",\"child_in_target\":%d}", l > 1 ? "," : "", what,
           c->pid > 0 ? "OK" : errno_name(c->err), in_leaf);
}

static int child_in(cp_t *c, const char *leaf) {
  char cg[512];
  return c->pid > 0 && cgroup_of(c->pid, cg, sizeof cg) == 0 && strcmp(cg, rel_of(leaf)) == 0;
}

static void case_clone3_errors(void) {
  char leaf[600], gone[600];
  if (make_leaf("c3-ok", leaf, sizeof leaf) || make_leaf("c3-gone", gone, sizeof gone)) return;
  char buf[3000] = "[";
  cp_t c;
  int dfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

  clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 400, &c);
  int pop = c.pid > 0 ? (int)cg_key(leaf, "cgroup.events", "populated") : -1;
  char pcb[32] = "";
  cg_read(leaf, "pids.current", pcb, sizeof pcb);
  long long cur = c.pid > 0 ? atoll(pcb) : -1;
  char procs[256] = "";
  cg_read(leaf, "cgroup.procs", procs, sizeof procs);
  char want[24];
  snprintf(want, sizeof want, "%d\n", (int)c.pid);
  int in_procs = c.pid > 0 && strstr(procs, want) != NULL;
  add_result(buf, sizeof buf, "valid_dirfd_size88", &c, child_in(&c, leaf));
  finish(&c);

  clone_probe(CLONE_INTO_CGROUP, dfd, 64, 100, &c);
  add_result(buf, sizeof buf, "struct_size_64_with_into_cgroup", &c, child_in(&c, leaf));
  finish(&c);

  clone_probe(CLONE_INTO_CGROUP, 999, sizeof(struct clone_args_v2), 100, &c);
  add_result(buf, sizeof buf, "fd_not_open", &c, 0);
  finish(&c);

  int nul = open("/dev/null", O_RDONLY | O_CLOEXEC);
  clone_probe(CLONE_INTO_CGROUP, nul, sizeof(struct clone_args_v2), 100, &c);
  add_result(buf, sizeof buf, "fd_is_dev_null", &c, 0);
  finish(&c);
  close(nul);

  int tmpd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  clone_probe(CLONE_INTO_CGROUP, tmpd, sizeof(struct clone_args_v2), 100, &c);
  add_result(buf, sizeof buf, "fd_is_ordinary_directory", &c, 0);
  finish(&c);
  close(tmpd);

  int gfd = open(gone, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  rmdir(gone);
  clone_probe(CLONE_INTO_CGROUP, gfd, sizeof(struct clone_args_v2), 100, &c);
  add_result(buf, sizeof buf, "cgroup_removed_after_open", &c, 0);
  finish(&c);
  close(gfd);

  int rootfd = open(g_prefix, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  clone_probe(CLONE_INTO_CGROUP, rootfd, sizeof(struct clone_args_v2), 100, &c);
  add_result(buf, sizeof buf, "hierarchy_root", &c, 0);
  finish(&c);
  close(rootfd);

  int dd = open(g_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  clone_probe(CLONE_INTO_CGROUP, dd, sizeof(struct clone_args_v2), 100, &c);
  add_result(buf, sizeof buf, "delegated_root_with_controllers_in_subtree_control", &c, 0);
  finish(&c);
  close(dd);

  size_t l = strlen(buf);
  snprintf(buf + l, sizeof buf - l, "]");
  emit(PROBE, "clone3_errors", "\"results\":%s,\"first_case_populated_at_return\":%d,\"first_case_pids_current_at_return\":%lld,\"first_case_pid_listed_in_cgroup_procs_at_return\":%d", buf, pop, cur, in_procs);
  close(dfd);
  leaf_empty_and_remove(leaf);
}

static void case_clone3_frozen(void) {
  char leaf[600];
  if (make_leaf("c3-frozen", leaf, sizeof leaf)) return;
  int dfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int fr = cg_write(leaf, "cgroup.freeze", "1");
  double end = now_ms() + 500;
  while (now_ms() < end && cg_key(leaf, "cgroup.events", "frozen") == 0) sleep_ms(1);
  cp_t c;
  double t0 = now_ms();
  clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 200, &c);
  double t_ret = now_ms() - t0;
  int ran_frozen = ran(&c, 150);
  char stat[256] = "";
  char p[48];
  snprintf(p, sizeof p, "/proc/%d/stat", (int)c.pid);
  int sf = open(p, O_RDONLY);
  if (sf >= 0) { ssize_t n = read(sf, stat, sizeof stat - 1); stat[n > 0 ? n : 0] = 0; close(sf); }
  char *rp = strrchr(stat, ')');
  char state = rp && rp[1] == ' ' ? rp[2] : '?';
  long long frozen_ev = cg_key(leaf, "cgroup.events", "frozen");
  int st = 0;
  pid_t w = c.pid > 0 ? waitpid(c.pid, &st, WNOHANG) : -1;
  cg_write(leaf, "cgroup.freeze", "0");
  double t1 = now_ms();
  int ran_after = ran(&c, 500);
  double thaw_ms = now_ms() - t1;
  emit(PROBE, "clone3_into_frozen_cgroup",
       "\"freeze_write_errno\":\"%s\",\"clone3_errno\":\"%s\",\"clone3_returned_after_ms\":%.2f,\"child_ran_while_frozen\":%d,\"child_state_while_frozen\":\"%c\",\"cgroup_frozen_event\":%lld,\"waitpid_while_frozen\":%d,\"child_ran_after_thaw\":%d,\"thaw_to_first_byte_ms\":%.2f",
       errno_name(fr), errno_name(c.err), t_ret, ran_frozen, state, frozen_ev, (int)w, ran_after, thaw_ms);
  finish(&c);
  close(dfd);
  leaf_empty_and_remove(leaf);
}

static void case_clone3_pids_and_kill(void) {
  char leaf[600];
  if (make_leaf("c3-pids", leaf, sizeof leaf)) return;
  int dfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int pw = cg_write(leaf, "pids.max", "1");
  cp_t a, b;
  clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 1000, &a);
  clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 1000, &b);
  long long ev = cg_key(leaf, "pids.events", "max");
  emit(PROBE, "clone3_pids_max", "\"pids_max_write_errno\":\"%s\",\"first_clone3\":\"%s\",\"second_clone3\":\"%s\",\"pids_events_max\":%lld", errno_name(pw), a.pid > 0 ? "OK" : errno_name(a.err), b.pid > 0 ? "OK" : errno_name(b.err), ev);
  finish(&a);
  finish(&b);
  cg_write(leaf, "pids.max", "max");

  /* a child cloned in right after cgroup.kill: does it live? (delay between the kill and the clone3 varies) */
  int delays[] = {0, 1, 10, 100, 500};
  char kout[2000] = "[";
  for (size_t d = 0; d < sizeof delays / sizeof delays[0]; d++) {
    cp_t first, second;
    clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 3000, &first);
    ran(&first, 300);
    int kw = cg_write(leaf, "cgroup.kill", "1");
    int st1 = 0;
    waitpid(first.pid, &st1, 0);
    char s1[64], populated_txt[16];
    status_text(st1, s1, sizeof s1);
    snprintf(populated_txt, sizeof populated_txt, "%lld", cg_key(leaf, "cgroup.events", "populated"));
    if (delays[d]) sleep_ms(delays[d]);
    clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 3000, &second);
    int ran2 = second.pid > 0 && ran(&second, 300);
    int st2 = 0;
    pid_t w2 = second.pid > 0 ? waitpid(second.pid, &st2, WNOHANG) : -1;
    char s2[64] = "-";
    if (w2 > 0) status_text(st2, s2, sizeof s2);
    size_t l = strlen(kout);
    snprintf(kout + l, sizeof kout - l, "%s{\"delay_ms\":%d,\"kill_write\":\"%s\",\"first_end\":\"%s\",\"populated_after_kill\":%s,\"second_clone3\":\"%s\",\"second_ran\":%d,\"second_reaped_within_300ms\":%d,\"second_end\":\"%s\"}",
             l > 1 ? "," : "", delays[d], errno_name(kw), s1, populated_txt, second.pid > 0 ? "OK" : errno_name(second.err), ran2, w2 > 0, s2);
    finish(&first);
    finish(&second);
    cg_write(leaf, "cgroup.kill", "1");
    double e2 = now_ms() + 500;
    while (now_ms() < e2 && cg_key(leaf, "cgroup.events", "populated") == 1) sleep_ms(1);
  }
  size_t kl = strlen(kout);
  snprintf(kout + kl, sizeof kout - kl, "]");
  emit(PROBE, "clone3_after_cgroup_kill", "\"results\":%s", kout);
  close(dfd);
  leaf_empty_and_remove(leaf);
}

static void case_clone3_pidfd(void) {
  char leaf[600];
  if (make_leaf("c3-pidfd", leaf, sizeof leaf)) return;
  int dfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int pidfd = -1;
  int pp[2];
  (void)!pipe2(pp, O_CLOEXEC);
  long r = clone3_raw(CLONE_INTO_CGROUP | CLONE_PIDFD, dfd, &pidfd, sizeof(struct clone_args_v2));
  if (r == 0) { (void)!write(pp[1], "x", 1); sleep_ms(3000); _exit(0); }
  int e = r < 0 ? errno : 0;
  char cg[512] = "";
  int in = r > 0 && cgroup_of((pid_t)r, cg, sizeof cg) == 0 && strcmp(cg, rel_of(leaf)) == 0;
  int sig_rc = pidfd >= 0 ? (int)syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) : -1;
  siginfo_t si;
  memset(&si, 0, sizeof si);
  int wrc = pidfd >= 0 ? waitid((idtype_t)P_PIDFD, (id_t)pidfd, &si, WEXITED) : -1;
  int wp = r > 0 ? (int)waitpid((pid_t)r, NULL, WNOHANG) : -1;
  int werr = wp == -1 ? errno : 0;
  emit(PROBE, "clone3_pidfd_and_cgroup_together",
       "\"clone3_errno\":\"%s\",\"pidfd_valid\":%d,\"child_in_target\":%d,\"pidfd_send_signal_rc\":%d,\"waitid_pidfd_rc\":%d,\"si_code_is_CLD_KILLED\":%d,\"si_status\":%d,\"waitpid_afterwards\":\"%s\"",
       errno_name(e), pidfd >= 0, in, sig_rc, wrc, si.si_code == CLD_KILLED, si.si_status, wp == -1 ? errno_name(werr) : "returned_a_pid");
  if (pidfd >= 0) close(pidfd);
  close(pp[0]);
  close(pp[1]);
  close(dfd);
  leaf_empty_and_remove(leaf);
}

/* does the cgroup look populated the moment clone3 returns? (and what does fork+attach look like) */
static void case_populated_visibility(void) {
  char leaf[600];
  if (make_leaf("c3-pop", leaf, sizeof leaf)) return;
  int dfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int n = 100, pop_clone = 0, pop_fork = 0, pop_fork_after = 0;
  for (int i = 0; i < n; i++) {
    cp_t c;
    clone_probe(CLONE_INTO_CGROUP, dfd, sizeof(struct clone_args_v2), 200, &c);
    if (c.pid > 0 && cg_key(leaf, "cgroup.events", "populated") == 1) pop_clone++;
    finish(&c);
    double end = now_ms() + 500;
    while (now_ms() < end && cg_key(leaf, "cgroup.events", "populated") == 1) sleep_ms(1);
    pid_t f = fork();
    if (f == 0) { sleep_ms(200); _exit(0); }
    if (cg_key(leaf, "cgroup.events", "populated") == 1) pop_fork++;
    char num[24];
    snprintf(num, sizeof num, "%d", (int)f);
    cg_write(leaf, "cgroup.procs", num);
    if (cg_key(leaf, "cgroup.events", "populated") == 1) pop_fork_after++;
    kill(f, SIGKILL);
    waitpid(f, NULL, 0);
    end = now_ms() + 500;
    while (now_ms() < end && cg_key(leaf, "cgroup.events", "populated") == 1) sleep_ms(1);
  }
  emit(PROBE, "populated_visibility", "\"trials\":%d,\"clone3_populated_1_at_return\":%d,\"fork_populated_1_before_attach\":%d,\"fork_populated_1_after_attach\":%d", n, pop_clone, pop_fork, pop_fork_after);
  close(dfd);
  leaf_empty_and_remove(leaf);
}

/* ------------------------------------------------------------------ trampoline fidelity and exit codes */
static int capture(char **argv, char *out, size_t ocap, char *err, size_t ecap, int *exec_errno) {
  int po[2], pe[2], px[2];
  if (pipe(po) || pipe(pe) || pipe2(px, O_CLOEXEC)) return -1;
  pid_t c = fork();
  if (c == 0) {
    dup2(po[1], 1);
    dup2(pe[1], 2);
    close(po[0]); close(pe[0]);
    execvp(argv[0], argv);
    int e = errno;
    (void)!write(px[1], &e, sizeof e);
    _exit(126);
  }
  close(po[1]); close(pe[1]); close(px[1]);
  int eof;
  drain_until(po[0], out, ocap, 3000, &eof);
  drain_until(pe[0], err, ecap, 200, &eof);
  int e = 0;
  ssize_t k = read(px[0], &e, sizeof e);
  *exec_errno = k == (ssize_t)sizeof e ? e : 0;
  close(po[0]); close(pe[0]); close(px[0]);
  int st = 0;
  waitpid_timeout(c, &st, 0, 3000);
  return st;
}

static void json_str(const char *s, char *o, size_t cap) {
  size_t j = 0;
  for (size_t i = 0; s[i] && j + 8 < cap; i++) {
    unsigned char ch = (unsigned char)s[i];
    if (ch == '"' || ch == '\\') { o[j++] = '\\'; o[j++] = (char)ch; }
    else if (ch < 0x20) j += (size_t)snprintf(o + j, cap - j, "\\u%04x", ch);
    else o[j++] = (char)ch;
  }
  o[j] = 0;
}

static int in_lines(const char *hay, const char *line) {
  size_t n = strlen(line);
  for (const char *p = hay; p && *p;) {
    const char *e = strchr(p, '\n');
    size_t l = e ? (size_t)(e - p) : strlen(p);
    if (l == n && strncmp(p, line, n) == 0) return 1;
    p = e ? e + 1 : NULL;
  }
  return 0;
}

static void diff_lists(const char *a, const char *b, char *o, size_t cap) {
  size_t l = 0;
  char tmp[1024], esc[2200];
  o[0] = 0;
  char *copy = strdup(a);
  for (char *s = strtok(copy, "\n"); s; s = strtok(NULL, "\n")) {
    if (in_lines(b, s)) continue;
    snprintf(tmp, sizeof tmp, "%s", s);
    json_str(tmp, esc, sizeof esc);
    l += (size_t)snprintf(o + l, cap - l, "%s\"%s\"", l ? "," : "", esc);
    if (l + 2400 > cap) break;
  }
  free(copy);
}

static void case_trampoline_fidelity(void) {
  char leaf[600];
  if (make_leaf("tramp", leaf, sizeof leaf)) return;
  snprintf(g_cgprocs, sizeof g_cgprocs, "%s/cgroup.procs", leaf);
  setenv("MARK_A", "1", 1);
  setenv("MARK_B", "", 1);
  setenv("MARK_C", "a b=c", 1);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  int leak = open("/dev/null", O_RDONLY);   /* deliberately inheritable */
  (void)leak;
  mode_t old = umask(027);
  char *args[] = {"", " lead", "trail ", "a b", "-n", "--", "$HOME", "`id`", "line1\nline2", "\\", "*", "\xc3\xa9", "'q'", "\"dq\"", NULL};
  int na = 0;
  while (args[na]) na++;

  char *dv[32], *sv[32], *bv[32];
  int i = 0;
  dv[i++] = g_self; dv[i++] = "--dump";
  for (int k = 0; k < na; k++) dv[i++] = args[k];
  dv[i] = NULL;
  i = 0;
  sv[i++] = "sh"; sv[i++] = "-c"; sv[i++] = "echo $$ > \"$0\" && exec \"$@\""; sv[i++] = g_cgprocs; sv[i++] = g_self; sv[i++] = "--dump";
  for (int k = 0; k < na; k++) sv[i++] = args[k];
  sv[i] = NULL;
  memcpy(bv, sv, sizeof sv);
  bv[0] = "bash";

  static char od[16384], os[16384], ob[16384], e1[256];
  int x;
  capture(dv, od, sizeof od, e1, sizeof e1, &x);
  capture(sv, os, sizeof os, e1, sizeof e1, &x);
  capture(bv, ob, sizeof ob, e1, sizeof e1, &x);
  umask(old);
  static char d1[8000], d2[8000], d3[8000], d4[8000];
  diff_lists(od, os, d1, sizeof d1);
  diff_lists(os, od, d2, sizeof d2);
  diff_lists(od, ob, d3, sizeof d3);
  diff_lists(ob, od, d4, sizeof d4);
  char shl[256] = "";
  ssize_t n = readlink("/bin/sh", shl, sizeof shl - 1);
  if (n > 0) shl[n] = 0;
  emit(PROBE, "trampoline_fidelity",
       "\"bin_sh_is\":\"%s\",\"special_args_sent\":%d,\"sh\":{\"identical\":%d,\"only_direct\":[%s],\"only_via_trampoline\":[%s]},\"bash\":{\"identical\":%d,\"only_direct\":[%s],\"only_via_trampoline\":[%s]}",
       shl, na, d1[0] == 0 && d2[0] == 0, d1, d2, d3[0] == 0 && d4[0] == 0, d3, d4);
  leaf_empty_and_remove(leaf);
}

static void status_or_errno(int st, int xe, char *o, size_t cap) {
  if (xe) snprintf(o, cap, "exec_failed(%s)", errno_name(xe));
  else status_text(st, o, cap);
}

static void case_trampoline_exit_codes(void) {
  char leaf[600];
  if (make_leaf("tramp-exit", leaf, sizeof leaf)) return;
  snprintf(g_cgprocs, sizeof g_cgprocs, "%s/cgroup.procs", leaf);
  char noexec[600];
  snprintf(noexec, sizeof noexec, "%s/spawn-cgroup-not-executable-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
  FILE *f = fopen(noexec, "w");
  if (f) { fputs("x\n", f); fclose(f); chmod(noexec, 0644); }
  struct { const char *what; char *prog; char *a1; char *a2; const char *cgp; } tc[] = {
    {"program_exits_42", "/bin/sh", "-c", "exit 42", NULL},
    {"program_missing", "/nonexistent/prog", NULL, NULL, NULL},
    {"program_not_executable", noexec, NULL, NULL, NULL},
    {"program_is_a_directory", "/tmp", NULL, NULL, NULL},
    {"cgroup_file_in_missing_directory", "/bin/true", NULL, NULL, "/nonexistent/cgroup.procs"},
    {"cgroup_is_the_hierarchy_root", "/bin/true", NULL, NULL, "/sys/fs/cgroup/cgroup.procs"},
  };
  char out[2400] = "[";
  for (size_t t = 0; t < sizeof tc / sizeof tc[0]; t++) {
    char *dv[6], *sv[10], *bv[10];
    int i = 0;
    dv[i++] = tc[t].prog; if (tc[t].a1) dv[i++] = tc[t].a1; if (tc[t].a2) dv[i++] = tc[t].a2; dv[i] = NULL;
    i = 0;
    sv[i++] = "sh"; sv[i++] = "-c"; sv[i++] = "echo $$ > \"$0\" && exec \"$@\""; sv[i++] = (char *)(tc[t].cgp ? tc[t].cgp : g_cgprocs);
    sv[i++] = tc[t].prog; if (tc[t].a1) sv[i++] = tc[t].a1; if (tc[t].a2) sv[i++] = tc[t].a2; sv[i] = NULL;
    memcpy(bv, sv, sizeof sv);
    bv[0] = "bash";
    char o[256], e[256], sd[64], ss[64], sb[64], es[200], eb[200], esc_s[420], esc_b[420];
    int xd, xs, xb;
    o[0] = e[0] = 0;
    int st = capture(dv, o, sizeof o, e, sizeof e, &xd);
    status_or_errno(st, xd, sd, sizeof sd);
    o[0] = e[0] = 0;
    st = capture(sv, o, sizeof o, e, sizeof e, &xs);
    status_or_errno(st, xs, ss, sizeof ss);
    snprintf(es, sizeof es, "%.150s", e);
    o[0] = e[0] = 0;
    st = capture(bv, o, sizeof o, e, sizeof e, &xb);
    status_or_errno(st, xb, sb, sizeof sb);
    snprintf(eb, sizeof eb, "%.150s", e);
    json_str(es, esc_s, sizeof esc_s);
    json_str(eb, esc_b, sizeof esc_b);
    size_t l = strlen(out);
    snprintf(out + l, sizeof out - l, "%s{\"what\":\"%s\",\"direct_fork_exec\":\"%s\",\"via_sh\":\"%s\",\"sh_stderr\":\"%s\",\"via_bash\":\"%s\",\"bash_stderr\":\"%s\"}",
             l > 1 ? "," : "", tc[t].what, sd, ss, esc_s, sb, esc_b);
  }
  size_t l = strlen(out);
  snprintf(out + l, sizeof out - l, "]");
  emit(PROBE, "trampoline_exit_codes", "\"results\":%s", out);
  unlink(noexec);
  leaf_empty_and_remove(leaf);
}

/* ------------------------------------------------------------------ spawn cost against the parent's size */
static void case_latency_vs_rss(void) {
  int sizes[] = {0, 256, 1024};
  char out[3000] = "[";
  for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
    char *mem = NULL;
    if (sizes[s]) {
      mem = malloc((size_t)sizes[s] << 20);
      if (mem) memset(mem, 0xA5, (size_t)sizes[s] << 20);
    }
    const char *names[] = {"fork_then_exec", "posix_spawn", "clone3_plain_then_exec"};
    char body[900] = "";
    for (int m = 0; m < 3; m++) {
      double call[15], total[15];
      for (int t = 0; t < 15; t++) {
        char *argv[] = {"/bin/true", NULL};
        double t0 = now_ms();
        pid_t pid = -1;
        if (m == 0) { pid = fork(); if (pid == 0) { execv("/bin/true", argv); _exit(127); } }
        else if (m == 1) { if (posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ) != 0) pid = -1; }
        else { pid = (pid_t)clone3_raw(0, -1, NULL, sizeof(struct clone_args_v2)); if (pid == 0) { execv("/bin/true", argv); _exit(127); } }
        double t1 = now_ms();
        if (pid > 0) waitpid(pid, NULL, 0);
        call[t] = t1 - t0;
        total[t] = now_ms() - t0;
      }
      size_t l = strlen(body);
      snprintf(body + l, sizeof body - l, "%s\"%s\":{\"spawn_call_ms_median\":%.3f,\"spawn_call_ms_p95\":%.3f,\"until_child_reaped_ms_median\":%.3f}", l ? "," : "", names[m], pct(call, 15, 0.5), pct(call, 15, 0.95), pct(total, 15, 0.5));
    }
    size_t l = strlen(out);
    snprintf(out + l, sizeof out - l, "%s{\"parent_dirty_mib\":%d,%s}", l > 1 ? "," : "", sizes[s], body);
    free(mem);
  }
  size_t l = strlen(out);
  snprintf(out + l, sizeof out - l, "]");
  emit(PROBE, "spawn_latency_vs_parent_size", "\"results\":%s", out);
}

int main(int argc, char **argv) {
  if (argc >= 4 && strcmp(argv[1], "--burst") == 0) return burst_main(atoi(argv[2]), atoi(argv[3]));
  if (argc >= 2 && strcmp(argv[1], "--dump") == 0) return dump_main(argc, argv);
  if (argc < 2) { fprintf(stderr, "usage: spawn_cgroup <delegated cgroup dir>\n"); return 2; }
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  snprintf(g_root, sizeof g_root, "%s", argv[1]);
  watchdog(280);
  emit_header(PROBE);
  case_clone3_errors();
  case_clone3_frozen();
  case_clone3_pids_and_kill();
  case_clone3_pidfd();
  case_populated_visibility();
  case_trampoline_fidelity();
  case_trampoline_exit_codes();
  case_latency_vs_rss();
  int n = getenv("SPAWN_CGROUP_TRIALS") ? atoi(getenv("SPAWN_CGROUP_TRIALS")) : 150;
  for (int loaded = 0; loaded <= 1; loaded++)
    for (int kind = K_FORK_NOW; kind <= K_BASH; kind++) escape_series(kind, loaded, n);
  return 0;
}

#endif /* __linux__ */
