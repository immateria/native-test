/*
 * cgroup v2 as a supervision primitive (Linux). Records JSON lines, never asserts.
 *
 * Runs as an unprivileged user inside a delegated subtree D (the CI step creates D with sudo, chowns it to the
 * runner user, enables controllers in D's subtree_control, and moves the step's shell into D/supervisor):
 *   cgroup_explore <D>
 * Each experiment makes a leaf D/<name>, moves a gated child into it, and observes. Questions: does cgroup.kill
 * reach descendants that left the process group and session; how fast does cgroup.events report "empty" and do
 * zombies count; CLONE_INTO_CGROUP; the freezer; memory.max and the OOM killer; pids.max; cpu.max; accounting of
 * orphaned descendants; rmdir; and what a delegated child can do to escape.
 *
 * Build: cc -O1 -Wall -Wextra -o cgroup_explore cgroup_explore.c
 */
#include "../posix/common.h"
#include <dirent.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/sched.h>

#define PROBE "cgroup_explore"

static char g_root[512];

/* ---------------------------------------------------------------- file helpers */
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

/* value of "key N" in a flat-keyed file, -1 if absent */
static long long cg_key(const char *dir, const char *file, const char *key) {
  char b[4096];
  if (cg_read(dir, file, b, sizeof b) <= 0) return -1;
  size_t kl = strlen(key);
  for (char *l = b; l && *l; ) {
    if (strncmp(l, key, kl) == 0 && l[kl] == ' ') return atoll(l + kl + 1);
    l = strchr(l, '\n');
    if (l) l++;
  }
  return -1;
}

static const char *bstr(int b) { return b ? "true" : "false"; }

/* single-number file (pids.current, memory.peak, ...), -1 if absent */
static long long cg_num(const char *dir, const char *file) {
  char b[64];
  if (cg_read(dir, file, b, sizeof b) <= 0) return -1;
  return atoll(b);
}

static int procs_count(const char *dir) {
  char b[8192];
  if (cg_read(dir, "cgroup.procs", b, sizeof b) < 0) return -1;
  int n = 0;
  for (char *c = b; *c; c++) if (*c == '\n') n++;
  return n;
}

static void flat(char *s) { for (; *s; s++) if (*s == '\n') *s = ' '; }

static int leaf(const char *name, char *out, size_t cap) {
  snprintf(out, cap, "%s/%s", g_root, name);
  rmdir(out);
  return mkdir(out, 0755) == 0 ? 0 : errno;
}

/* wait until cgroup.events says populated 0; reports when poll() first signalled and when it became 0 */
static double wait_unpopulated(const char *dir, int timeout_ms, double t0, double *first_notify) {
  char p[1024];
  snprintf(p, sizeof p, "%s/cgroup.events", dir);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
  *first_notify = -1;
  double end = now_ms() + timeout_ms;
  char b[256];
  while (now_ms() < end) {
    ssize_t n = pread(fd, b, sizeof b - 1, 0);
    if (n > 0) { b[n] = 0; if (strstr(b, "populated 0")) { close(fd); return now_ms() - t0; } }
    struct pollfd pf = {fd, POLLPRI, 0};
    int r = poll(&pf, 1, (int)(end - now_ms()) > 0 ? (int)(end - now_ms()) : 0);
    if (r > 0 && *first_notify < 0) *first_notify = now_ms() - t0;
  }
  close(fd);
  return -1;
}

static int alive(pid_t p) { return kill(p, 0) == 0; }

/* /proc/<pid>/stat: state character and utime+stime in ms */
static char proc_state(pid_t p, double *cpu_ms) {
  char path[64], b[1024];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)p);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { if (cpu_ms) *cpu_ms = -1; return '-'; }
  ssize_t n = read(fd, b, sizeof b - 1);
  close(fd);
  if (n <= 0) return '?';
  b[n] = 0;
  char *rp = strrchr(b, ')');
  if (!rp) return '?';
  char st = rp[2];
  if (cpu_ms) {
    unsigned long ut = 0, stt = 0;
    char *f = rp + 2;
    for (int i = 0; i < 11 && f; i++) { f = strchr(f, ' '); if (f) f++; }
    if (f) sscanf(f, "%lu %lu", &ut, &stt);
    *cpu_ms = (double)(ut + stt) * 1000.0 / (double)sysconf(_SC_CLK_TCK);
  }
  return st;
}

/* ---------------------------------------------------------------- gated child */
typedef void (*body_fn)(int report_fd, void *arg);

typedef struct { pid_t pid; int report; } gated_t;

/* fork a child that waits on a gate; move it into `dir`; release it. The child runs body(report_fd). */
static int spawn_in(const char *dir, body_fn body, void *arg, gated_t *g, int *move_err) {
  int gate[2], rep[2];
  if (pipe(gate) || pipe(rep)) return -1;
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) {
    close(gate[1]); close(rep[0]);
    char c;
    if (read(gate[0], &c, 1) != 1) _exit(97);
    close(gate[0]);
    body(rep[1], arg);
    _exit(0);
  }
  close(gate[0]); close(rep[1]);
  char pidbuf[32];
  snprintf(pidbuf, sizeof pidbuf, "%d\n", (int)p);
  *move_err = dir ? cg_write(dir, "cgroup.procs", pidbuf) : 0;
  (void)!write(gate[1], "g", 1);
  close(gate[1]);
  g->pid = p;
  g->report = rep[0];
  return 0;
}

static void report(int fd, const char *fmt, ...) {
  char b[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b, sizeof b, fmt, ap);
  va_end(ap);
  if (n > 0) (void)!write(fd, b, (size_t)n);
}

/* ---------------------------------------------------------------- 1. kill reach */
/* child: own process group; one plain grandchild; one daemonized great-grandchild (setsid, double fork).
 * reports "C=<pid> G=<pid> D=<pid>" */
static void body_tree(int rep, void *arg) {
  (void)arg;
  setpgid(0, 0);
  int p2[2];
  (void)!pipe(p2);
  pid_t g = fork();
  if (g == 0) { for (;;) pause(); }
  pid_t m = fork();
  if (m == 0) {
    setsid();
    pid_t d = fork();
    if (d == 0) { for (;;) pause(); }
    (void)!write(p2[1], &d, sizeof d);
    _exit(0);
  }
  pid_t d = 0;
  (void)!read(p2[0], &d, sizeof d);
  waitpid(m, NULL, 0);
  report(rep, "C=%d G=%d D=%d\n", (int)getpid(), (int)g, (int)d);
  close(rep);
  for (;;) pause();
}

static int read_tree(int fd, pid_t *c, pid_t *g, pid_t *d) {
  char b[128];
  ssize_t n = read_timeout(fd, b, sizeof b - 1, 3000);
  if (n <= 0) return -1;
  b[n] = 0;
  int ci = 0, gi = 0, di = 0;
  if (sscanf(b, "C=%d G=%d D=%d", &ci, &gi, &di) != 3) return -1;
  *c = ci; *g = gi; *d = di;
  return 0;
}

static void exp_kill_reach(void) {
  char w[600];
  int e = leaf("kill", w, sizeof w);
  if (e) { emit(PROBE, "kill_reach", "\"mkdir_errno\":\"%s\"", errno_name(e)); return; }
  gated_t g;
  int me;
  spawn_in(w, body_tree, NULL, &g, &me);
  pid_t C, G, D;
  if (read_tree(g.report, &C, &G, &D)) { emit(PROBE, "kill_reach", "\"error\":\"tree did not report\",\"move_errno\":\"%s\"", errno_name(me)); return; }
  int procs_before = procs_count(w);
  pid_t D_pgid = getpgid(D), D_sid = getsid(D), C_pgid = getpgid(C);
  /* the process-group kill the kit's POSIX shard would do */
  killpg(C_pgid, SIGKILL);
  sleep_ms(150);
  int c_after_pg = alive(C) && proc_state(C, NULL) != 'Z', g_after_pg = alive(G) && proc_state(G, NULL) != 'Z', d_after_pg = alive(D) && proc_state(D, NULL) != 'Z';
  long long pop_after_pg = cg_key(w, "cgroup.events", "populated");
  double t0 = now_ms();
  int ke = cg_write(w, "cgroup.kill", "1");
  double notify;
  double empty_ms = wait_unpopulated(w, 3000, t0, &notify);
  int d_after = alive(D) && proc_state(D, NULL) != 'Z';
  char st[64];
  reap_blocking(g.pid, 2000, st, sizeof st);
  emit(PROBE, "kill_reach_daemonized_descendant",
       "\"move_errno\":\"%s\",\"procs_in_cgroup\":%d,\"daemon_in_other_pgrp\":%s,\"daemon_in_other_session\":%s,"
       "\"after_killpg_child_alive\":%s,\"after_killpg_grandchild_alive\":%s,\"after_killpg_daemon_alive\":%s,\"populated_after_killpg\":%lld,"
       "\"cgroup_kill_errno\":\"%s\",\"ms_to_populated_0\":%.1f,\"ms_to_first_events_notification\":%.1f,\"daemon_alive_after_cgroup_kill\":%s,\"child_status\":\"%s\"",
       errno_name(me), procs_before, bstr(D_pgid != C_pgid), bstr(D_sid != getsid(C)), bstr(c_after_pg), bstr(g_after_pg), bstr(d_after_pg), pop_after_pg,
       errno_name(ke), empty_ms, notify, bstr(d_after), st);
  close(g.report);
  rmdir(w);
}

/* do zombies keep a cgroup populated? kill our own child with cgroup.kill and do not reap it yet */
static void body_sleep(int rep, void *arg) { (void)arg; close(rep); for (;;) pause(); }

static void exp_zombie_population(void) {
  char w[600];
  if (leaf("zombie", w, sizeof w)) return;
  gated_t g;
  int me;
  spawn_in(w, body_sleep, NULL, &g, &me);
  sleep_ms(50);
  double t0 = now_ms(), notify;
  cg_write(w, "cgroup.kill", "1");
  double empty_ms = wait_unpopulated(w, 2000, t0, &notify);
  char state = proc_state(g.pid, NULL);
  int procs = procs_count(w);
  errno = 0;
  int rm = rmdir(w) == 0 ? 0 : errno;
  char st[64];
  reap_blocking(g.pid, 2000, st, sizeof st);
  int rm2 = rm ? (rmdir(w) == 0 ? 0 : errno) : 0;
  emit(PROBE, "zombie_counts_toward_populated",
       "\"child_state_before_reap\":\"%c\",\"populated_0_while_zombie_ms\":%.1f,\"procs_listed_while_zombie\":%d,\"rmdir_while_zombie\":\"%s\",\"rmdir_after_reap\":\"%s\",\"status\":\"%s\"",
       state, empty_ms, procs, errno_name(rm), errno_name(rm2), st);
  close(g.report);
}

/* ---------------------------------------------------------------- 2. CLONE_INTO_CGROUP */
struct clone_args_v2 {
  uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

static void exp_clone_into_cgroup(void) {
  char w[600];
  if (leaf("clone3", w, sizeof w)) return;
  int dfd = open(w, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int pp[2];
  (void)!pipe(pp);
  struct clone_args_v2 ca;
  memset(&ca, 0, sizeof ca);
  ca.flags = CLONE_INTO_CGROUP;
  ca.exit_signal = SIGCHLD;
  ca.cgroup = (uint64_t)dfd;
  fflush(stdout);
  long r = syscall(SYS_clone3, &ca, sizeof ca);
  if (r == 0) {
    char b[512];
    int fd = open("/proc/self/cgroup", O_RDONLY);
    ssize_t n = read(fd, b, sizeof b - 1);
    (void)!write(pp[1], b, n > 0 ? (size_t)n : 0);
    _exit(0);
  }
  int e = r < 0 ? errno : 0;
  close(pp[1]);
  char b[512] = "";
  if (r > 0) {
    ssize_t n = read_timeout(pp[0], b, sizeof b - 1, 2000);
    b[n > 0 ? n : 0] = 0;
    flat(b);
    waitpid((pid_t)r, NULL, 0);
  }
  close(pp[0]);
  emit(PROBE, "clone3_into_cgroup", "\"clone3_errno\":\"%s\",\"child_proc_self_cgroup\":\"%s\",\"expected_suffix\":\"/clone3\"", errno_name(e), b);
  close(dfd);
  rmdir(w);
}

/* ---------------------------------------------------------------- 3. freezer */
static volatile sig_atomic_t g_term;
static void on_term(int s) { (void)s; g_term = 1; }

static void body_spin_with_term_handler(int rep, void *arg) {
  int handler = arg != NULL;
  if (handler) { struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_term; sigaction(SIGTERM, &sa, NULL); }
  report(rep, "up\n");
  volatile unsigned long x = 0;
  for (;;) {
    for (int i = 0; i < 1000000; i++) x += (unsigned long)i;
    if (g_term) { report(rep, "TERM-handled\n"); g_term = 0; }
  }
}

static void exp_freezer(void) {
  char w[600];
  if (leaf("freeze", w, sizeof w)) return;
  gated_t a, b, c;
  int me1, me2, me3;
  spawn_in(w, body_spin_with_term_handler, NULL, &a, &me1);          /* will get SIGKILL while frozen */
  spawn_in(w, body_spin_with_term_handler, (void *)1, &b, &me2);     /* SIGTERM with a handler while frozen */
  spawn_in(w, body_spin_with_term_handler, NULL, &c, &me3);          /* SIGTERM default action while frozen */
  char tmp[16];
  read_timeout(a.report, tmp, sizeof tmp, 2000); read_timeout(b.report, tmp, sizeof tmp, 2000); read_timeout(c.report, tmp, sizeof tmp, 2000);
  sleep_ms(100);
  double t0 = now_ms();
  int fe = cg_write(w, "cgroup.freeze", "1");
  double frozen_ms = -1;
  while (now_ms() - t0 < 3000) { if (cg_key(w, "cgroup.events", "frozen") == 1) { frozen_ms = now_ms() - t0; break; } sleep_ms(1); }
  double cpu1, cpu2;
  char state = proc_state(b.pid, &cpu1);
  sleep_ms(500);
  proc_state(b.pid, &cpu2);
  int stw = 0;
  pid_t wr = waitpid(b.pid, &stw, WNOHANG | WUNTRACED);
  /* signals while frozen */
  kill(a.pid, SIGKILL);
  kill(b.pid, SIGTERM);
  kill(c.pid, SIGTERM);
  sleep_ms(300);
  char sa_[64] = "running", sc_[64] = "running";
  int st;
  if (waitpid(a.pid, &st, WNOHANG) == a.pid) status_text(st, sa_, sizeof sa_);
  if (waitpid(c.pid, &st, WNOHANG) == c.pid) status_text(st, sc_, sizeof sc_);
  char hb[64] = "";
  ssize_t hn = read_timeout(b.report, hb, sizeof hb - 1, 50);
  int handler_ran_while_frozen = hn > 0 && strstr(hb, "TERM-handled") != NULL;
  /* SIGCONT does not thaw */
  kill(b.pid, SIGCONT);
  sleep_ms(200);
  long long still_frozen = cg_key(w, "cgroup.events", "frozen");
  double t1 = now_ms();
  cg_write(w, "cgroup.freeze", "0");
  hn = read_timeout(b.report, hb, sizeof hb - 1, 2000);
  double handler_after_thaw_ms = hn > 0 ? now_ms() - t1 : -1;
  if (waitpid(c.pid, &st, WNOHANG) == c.pid && strcmp(sc_, "running") == 0) { char x[48]; status_text(st, x, sizeof x); snprintf(sc_, sizeof sc_, "after_thaw:%s", x); }
  emit(PROBE, "freezer",
       "\"freeze_errno\":\"%s\",\"ms_until_events_frozen_1\":%.1f,\"frozen_task_state\":\"%c\",\"cpu_ms_gained_in_500ms_frozen\":%.1f,\"waitpid_untraced_reports\":%d,"
       "\"sigkill_while_frozen\":\"%s\",\"sigterm_default_while_frozen\":\"%s\",\"sigterm_handler_ran_while_frozen\":%s,\"frozen_after_sigcont\":%lld,\"ms_from_thaw_to_handler\":%.1f",
       errno_name(fe), frozen_ms, state, cpu2 - cpu1, (int)wr, sa_, sc_, bstr(handler_ran_while_frozen), still_frozen, handler_after_thaw_ms);
  /* cgroup.kill on a frozen cgroup */
  cg_write(w, "cgroup.freeze", "1");
  sleep_ms(100);
  double t2 = now_ms(), notify;
  cg_write(w, "cgroup.kill", "1");
  double empty = wait_unpopulated(w, 3000, t2, &notify);
  emit(PROBE, "cgroup_kill_while_frozen", "\"ms_to_populated_0\":%.1f", empty);
  char s1[64];
  reap_blocking(a.pid, 1000, s1, sizeof s1); reap_blocking(b.pid, 1000, s1, sizeof s1); reap_blocking(c.pid, 1000, s1, sizeof s1);
  close(a.report); close(b.report); close(c.report);
  rmdir(w);
}

/* ---------------------------------------------------------------- 4. memory.max */
static void body_hog(int rep, void *arg) {
  long mib = (long)(intptr_t)arg;
  for (long i = 0; i < mib; i++) {
    char *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { report(rep, "mmap_failed_at=%ld errno=%d\n", i, errno); for (;;) pause(); }
    memset(p, 1, 1 << 20);
    report(rep, "%ld\n", i + 1);
  }
  report(rep, "done\n");
  for (;;) pause();
}

static long last_number(const char *b) {
  long v = -1;
  const char *p = b;
  while (*p) { char *end; long x = strtol(p, &end, 10); if (end != p) { v = x; p = end; } else p++; }
  return v;
}

static void exp_memory(int oom_group) {
  char w[600];
  if (leaf(oom_group ? "mem-group" : "mem", w, sizeof w)) return;
  int e1 = cg_write(w, "memory.max", "67108864");
  if (e1) { emit(PROBE, oom_group ? "memory_max_64MiB_oom_group_1" : "memory_max_64MiB", "\"memory_max_errno\":\"%s\",\"skipped\":true", errno_name(e1)); rmdir(w); return; }
  char swapfile[700];
  snprintf(swapfile, sizeof swapfile, "%s/memory.swap.max", w);
  int has_swap_knob = access(swapfile, F_OK) == 0;
  int e2 = has_swap_knob ? cg_write(w, "memory.swap.max", "0") : -1;
  int e3 = oom_group ? cg_write(w, "memory.oom.group", "1") : 0;
  gated_t bystander, hog;
  int me;
  spawn_in(w, body_sleep, NULL, &bystander, &me);
  double t0 = now_ms();
  spawn_in(w, body_hog, (void *)(intptr_t)256, &hog, &me);
  /* read progress until the hog is killed (EOF) or reports done */
  char b[16384];
  size_t n = 0;
  int eof = 0;
  double end = now_ms() + 15000;
  while (now_ms() < end && !eof && n + 1 < sizeof b) {
    ssize_t r = read_timeout(hog.report, b + n, sizeof b - 1 - n, 200);
    if (r == 0) eof = 1;
    else if (r > 0) { n += (size_t)r; b[n] = 0; if (strstr(b, "done")) break; }
  }
  b[n] = 0;
  double dt = now_ms() - t0;
  char st[64];
  if (!eof) kill(hog.pid, SIGKILL); /* not killed by the limit: stop it */
  reap_blocking(hog.pid, 3000, st, sizeof st);
  sleep_ms(200);
  int bystander_alive = alive(bystander.pid) && proc_state(bystander.pid, NULL) != 'Z';
  char ev[512];
  cg_read(w, "memory.events", ev, sizeof ev);
  flat(ev);
  emit(PROBE, oom_group ? "memory_max_64MiB_oom_group_1" : "memory_max_64MiB",
       "\"memory_max_errno\":\"%s\",\"swap_max_knob\":%s,\"swap_max_errno\":\"%s\",\"oom_group_errno\":\"%s\",\"hog_status\":\"%s\",\"ms\":%.0f,"
       "\"killed_by_limit\":%s,\"MiB_touched_before_kill\":%ld,\"bystander_alive\":%s,\"memory_events\":\"%s\",\"memory_peak\":%lld",
       errno_name(e1), bstr(has_swap_knob), has_swap_knob ? errno_name(e2) : "-", errno_name(e3), st, dt, bstr(eof), last_number(b), bstr(bystander_alive), ev,
       cg_num(w, "memory.peak"));
  cg_write(w, "cgroup.kill", "1");
  reap_blocking(bystander.pid, 2000, st, sizeof st);
  close(hog.report); close(bystander.report);
  rmdir(w);
}

/* ---------------------------------------------------------------- 5. pids.max */
static void body_forker(int rep, void *arg) {
  (void)arg;
  int made = 0, err = 0;
  for (int i = 0; i < 64; i++) {
    pid_t p = fork();
    if (p == 0) { for (;;) pause(); }
    if (p < 0) { err = errno; break; }
    made++;
  }
  report(rep, "made=%d errno=%d\n", made, err);
  for (;;) pause();
}

static void exp_pids(void) {
  char w[600];
  if (leaf("pids", w, sizeof w)) return;
  int e = cg_write(w, "pids.max", "5");
  if (e) { emit(PROBE, "pids_max_5", "\"pids_max_errno\":\"%s\",\"skipped\":true", errno_name(e)); rmdir(w); return; }
  gated_t g;
  int me;
  spawn_in(w, body_forker, NULL, &g, &me);
  char b[128] = "";
  ssize_t n = read_timeout(g.report, b, sizeof b - 1, 3000);
  b[n > 0 ? n : 0] = 0;
  flat(b);
  emit(PROBE, "pids_max_5", "\"pids_max_errno\":\"%s\",\"forker_reported\":\"%s\",\"pids_current\":%lld,\"pids_events_max\":%lld,\"fork_errno_name_EAGAIN_is_11\":%d",
       errno_name(e), b, cg_num(w, "pids.current"), cg_key(w, "pids.events", "max"), EAGAIN);
  cg_write(w, "cgroup.kill", "1");
  char st[64];
  reap_blocking(g.pid, 2000, st, sizeof st);
  close(g.report);
  sleep_ms(100);
  rmdir(w);
}

/* ---------------------------------------------------------------- 6. cpu.max */
static void body_spin_report_cpu(int rep, void *arg) {
  int ms = (int)(intptr_t)arg;
  double end = now_ms() + ms;
  volatile unsigned long x = 0;
  while (now_ms() < end) for (int i = 0; i < 100000; i++) x += (unsigned long)i;
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  report(rep, "%.1f\n", ru.ru_utime.tv_sec * 1000.0 + ru.ru_utime.tv_usec / 1000.0 + ru.ru_stime.tv_sec * 1000.0 + ru.ru_stime.tv_usec / 1000.0);
  close(rep);
  for (;;) pause();
}

static void exp_cpu(const char *limit, const char *kase) {
  char w[600];
  if (leaf("cpu", w, sizeof w)) return;
  int e = limit ? cg_write(w, "cpu.max", limit) : 0;
  if (e) { emit(PROBE, kase, "\"cpu_max_errno\":\"%s\",\"skipped\":true", errno_name(e)); rmdir(w); return; }
  gated_t g;
  int me;
  spawn_in(w, body_spin_report_cpu, (void *)(intptr_t)2000, &g, &me);
  char b[64] = "";
  ssize_t n = read_timeout(g.report, b, sizeof b - 1, 6000);
  b[n > 0 ? n : 0] = 0;
  emit(PROBE, kase, "\"cpu_max\":\"%s\",\"cpu_max_errno\":\"%s\",\"wall_ms\":2000,\"child_cpu_ms\":%.1f,\"nr_throttled\":%lld,\"throttled_usec\":%lld,\"usage_usec\":%lld",
       limit ? limit : "max", errno_name(e), atof(b), cg_key(w, "cpu.stat", "nr_throttled"), cg_key(w, "cpu.stat", "throttled_usec"), cg_key(w, "cpu.stat", "usage_usec"));
  cg_write(w, "cgroup.kill", "1");
  char st[64];
  reap_blocking(g.pid, 2000, st, sizeof st);
  close(g.report);
  sleep_ms(100);
  rmdir(w);
}

/* ---------------------------------------------------------------- 7. accounting of orphans */
static void body_orphan_burner(int rep, void *arg) {
  (void)arg;
  pid_t m = fork();
  if (m == 0) {
    pid_t o = fork();
    if (o == 0) {
      double end = now_ms() + 400;
      volatile unsigned long x = 0;
      while (now_ms() < end) for (int i = 0; i < 100000; i++) x += (unsigned long)i;
      _exit(0);
    }
    _exit(0);
  }
  waitpid(m, NULL, 0);
  close(rep);
  _exit(0);
}

static void exp_accounting(void) {
  char w[600];
  if (leaf("acct", w, sizeof w)) return;
  struct rusage before, after;
  getrusage(RUSAGE_CHILDREN, &before);
  gated_t g;
  int me;
  spawn_in(w, body_orphan_burner, NULL, &g, &me);
  char st[64];
  reap_blocking(g.pid, 3000, st, sizeof st);
  double notify;
  double empty = wait_unpopulated(w, 3000, now_ms(), &notify);
  getrusage(RUSAGE_CHILDREN, &after);
  double rus = (after.ru_utime.tv_sec - before.ru_utime.tv_sec) * 1000.0 + (after.ru_utime.tv_usec - before.ru_utime.tv_usec) / 1000.0 +
               (after.ru_stime.tv_sec - before.ru_stime.tv_sec) * 1000.0 + (after.ru_stime.tv_usec - before.ru_stime.tv_usec) / 1000.0;
  emit(PROBE, "orphan_cpu_is_charged_to_the_cgroup", "\"orphan_burned_ms\":400,\"cgroup_usage_ms\":%.1f,\"rusage_children_delta_ms\":%.1f,\"waited_for_empty_ms\":%.1f",
       cg_key(w, "cpu.stat", "usage_usec") / 1000.0, rus, empty);
  close(g.report);
  rmdir(w);
}

/* ---------------------------------------------------------------- 8. delegation boundary */
static void body_escape(int rep, void *arg) {
  (void)arg;
  char pid[32], sup[600], parent[600];
  snprintf(pid, sizeof pid, "%d\n", (int)getpid());
  snprintf(sup, sizeof sup, "%s/supervisor", g_root);
  snprintf(parent, sizeof parent, "%s/..", g_root);
  int to_root = cg_write("/sys/fs/cgroup", "cgroup.procs", pid);
  int to_parent = cg_write(parent, "cgroup.procs", pid);
  int to_sibling = cg_write(sup, "cgroup.procs", pid);
  char cg[256];
  int fd = open("/proc/self/cgroup", O_RDONLY);
  ssize_t n = read(fd, cg, sizeof cg - 1);
  cg[n > 0 ? n : 0] = 0;
  flat(cg);
  int mk = mkdir("/sys/fs/cgroup/explore-escape-attempt", 0755) == 0 ? 0 : errno;
  if (mk == 0) rmdir("/sys/fs/cgroup/explore-escape-attempt");
  report(rep, "%s|%s|%s|%s|%s\n", errno_name(to_root), errno_name(to_parent), errno_name(to_sibling), cg, errno_name(mk));
  close(rep);
  for (;;) pause();
}

static void exp_escape(void) {
  char w[600];
  if (leaf("escape", w, sizeof w)) return;
  gated_t g;
  int me;
  spawn_in(w, body_escape, NULL, &g, &me);
  char b[512] = "";
  ssize_t n = read_timeout(g.report, b, sizeof b - 1, 3000);
  b[n > 0 ? n : 0] = 0;
  char r1[32] = "", r2[32] = "", r3[32] = "", cg[300] = "", mk[32] = "";
  sscanf(b, "%31[^|]|%31[^|]|%31[^|]|%299[^|]|%31[^|\n]", r1, r2, r3, cg, mk);
  int left_leaf = procs_count(w) == 0;
  /* the no-internal-process rule: enable a controller in a leaf that has a process */
  char w2[600];
  leaf("internal", w2, sizeof w2);
  gated_t h;
  spawn_in(w2, body_sleep, NULL, &h, &me);
  sleep_ms(50);
  int ip = cg_write(w2, "cgroup.subtree_control", "+pids");
  emit(PROBE, "delegated_child_escape",
       "\"move_self_to_hierarchy_root\":\"%s\",\"move_self_to_parent_of_delegation\":\"%s\",\"move_self_to_sibling_inside_delegation\":\"%s\","
       "\"child_cgroup_afterwards\":\"%s\",\"leaf_now_empty\":%s,\"mkdir_in_hierarchy_root\":\"%s\",\"enable_controller_in_populated_leaf\":\"%s\"",
       r1, r2, r3, cg, bstr(left_leaf), mk, errno_name(ip));
  kill(g.pid, SIGKILL); kill(h.pid, SIGKILL);
  char st[64];
  reap_blocking(g.pid, 2000, st, sizeof st); reap_blocking(h.pid, 2000, st, sizeof st);
  close(g.report); close(h.report);
  sleep_ms(100);
  rmdir(w); rmdir(w2);
}

/* ---------------------------------------------------------------- environment */
static void exp_environment(void) {
  char ctl[512] = "", sub[512] = "", me[512] = "", rootctl[512] = "";
  cg_read(g_root, "cgroup.controllers", ctl, sizeof ctl);
  cg_read(g_root, "cgroup.subtree_control", sub, sizeof sub);
  cg_read("/sys/fs/cgroup", "cgroup.subtree_control", rootctl, sizeof rootctl);
  int fd = open("/proc/self/cgroup", O_RDONLY);
  ssize_t n = read(fd, me, sizeof me - 1);
  me[n > 0 ? n : 0] = 0;
  close(fd);
  flat(ctl); flat(sub); flat(me); flat(rootctl);
  char root_kill[600];
  snprintf(root_kill, sizeof root_kill, "/sys/fs/cgroup/cgroup.kill");
  emit(PROBE, "environment", "\"delegated_root\":\"%s\",\"controllers\":\"%s\",\"subtree_control\":\"%s\",\"hierarchy_root_subtree_control\":\"%s\",\"self\":\"%s\","
       "\"hierarchy_root_has_cgroup_kill\":%s", g_root, ctl, sub, rootctl, me, bstr(access(root_kill, F_OK) == 0));
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: cgroup_explore <delegated cgroup directory>\n"); return 2; }
  snprintf(g_root, sizeof g_root, "%s", argv[1]);
  watchdog(240);
  emit_header(PROBE);
  exp_environment();
  exp_kill_reach();
  exp_zombie_population();
  exp_clone_into_cgroup();
  exp_freezer();
  exp_memory(0);
  exp_memory(1);
  exp_pids();
  exp_cpu(NULL, "cpu_max_unlimited");
  exp_cpu("20000 100000", "cpu_max_20_percent");
  exp_accounting();
  exp_escape();
  return 0;
}
