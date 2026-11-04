/*
 * posix_spawn attributes (macOS and Linux): what a supervisor can arrange for a child before it runs, compared with
 * what a stdlib Process.new child gets (see FINDINGS: no process-group option, SIGPIPE ignored, ...). Records JSON
 * lines, never asserts.
 *
 *   child_view_*        the child reports its pgid / sid / ignored and blocked signals / open descriptors / cwd, for
 *                       a parent that ignores SIGPIPE and SIGHUP, blocks SIGUSR1, has umask 027 and an inheritable
 *                       descriptor open: baseline, SETPGROUP, SETSID, SETSIGDEF+SETSIGMASK, closing descriptors
 *                       (macOS CLOEXEC_DEFAULT, glibc addclosefrom_np), addchdir_np, all of them together
 *   pgroup_race         posix_spawn(SETPGROUP): is the child already in its own group when the call returns, vs a
 *                       parent that calls setpgid(child, child) after fork+exec
 *   start_suspended     macOS POSIX_SPAWN_START_SUSPENDED: the child exists but has not run; resume, kill, TERM
 *   spawn_errors        what posix_spawn returns for failures, and whether a child has to be reaped afterwards
 *
 * Build: cc -O1 -Wall -Wextra -o spawn_attrs spawn_attrs.c
 */
#include "../posix/common.h"
#include <limits.h>
#include <spawn.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#define PROBE "spawn_attrs"

extern char **environ;
static char g_self[PATH_MAX];

#if defined(__APPLE__)
#define HAVE_CLOSE_ALL 1
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
#define HAVE_CLOSE_ALL 1
#else
#define HAVE_CLOSE_ALL 0
#endif

/* ------------------------------------------------------------------ the child */
static int report_main(void) {
  printf("{\"pgid_equals_pid\":%d,\"sid_equals_pid\":%d,\"pgid_equals_parents\":%d,\"ignored\":[",
         getpgrp() == getpid(), getsid(0) == getpid(), getpgrp() == getppid() || getpgrp() == getpgid(getppid()));
  int first = 1;
  for (int s = 1; s < 32; s++) {
    struct sigaction sa;
    if (sigaction(s, NULL, &sa) == 0 && sa.sa_handler == SIG_IGN) { printf("%s\"%s\"", first ? "" : ",", sig_name(s)); first = 0; }
  }
  printf("],\"blocked\":[");
  first = 1;
  sigset_t m;
  sigprocmask(SIG_BLOCK, NULL, &m);
  for (int s = 1; s < 32; s++) if (sigismember(&m, s) == 1) { printf("%s\"%s\"", first ? "" : ",", sig_name(s)); first = 0; }
  printf("],\"fds\":[");
  first = 1;
  for (int fd = 0; fd < 64; fd++) {
    int f = fcntl(fd, F_GETFD);
    if (f != -1) { printf("%s%d", first ? "" : ",", fd); first = 0; }
  }
  mode_t um = umask(022);
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) cwd[0] = 0;
  printf("],\"umask\":\"%03o\",\"cwd_is_tmp\":%d}\n", (unsigned)um, strcmp(cwd, "/tmp") == 0 || strcmp(cwd, "/private/tmp") == 0);
  return 0;
}

/* ------------------------------------------------------------------ parent state that a child could inherit */
static int g_leak_fd = -1;
static void parent_state(void) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  sigset_t b;
  sigemptyset(&b);
  sigaddset(&b, SIGUSR1);
  sigprocmask(SIG_BLOCK, &b, NULL);
  umask(027);
  g_leak_fd = open("/dev/null", O_RDONLY);   /* inheritable on purpose */
}

typedef struct { int flags_pgroup, flags_setsid, flags_sigs, close_all, chdir_tmp, suspended; } cfg_t;

static int do_spawn(const cfg_t *c, char **argv, pid_t *pid, int out_fd) {
  posix_spawnattr_t at;
  posix_spawn_file_actions_t fa;
  posix_spawnattr_init(&at);
  posix_spawn_file_actions_init(&fa);
  short flags = 0;
  if (c->flags_pgroup) { flags |= POSIX_SPAWN_SETPGROUP; posix_spawnattr_setpgroup(&at, 0); }
#ifdef POSIX_SPAWN_SETSID
  if (c->flags_setsid) flags |= POSIX_SPAWN_SETSID;
#endif
  if (c->flags_sigs) {
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&at, &all);
    posix_spawnattr_setsigmask(&at, &none);
    flags |= POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
  }
#ifdef __APPLE__
  if (c->close_all) flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
  if (c->suspended) flags |= POSIX_SPAWN_START_SUSPENDED;
#endif
  posix_spawnattr_setflags(&at, flags);
  if (out_fd >= 0) {
    posix_spawn_file_actions_adddup2(&fa, out_fd, 1);
    if (out_fd != 1) posix_spawn_file_actions_addclose(&fa, out_fd);
  }
#ifdef __APPLE__
  if (c->close_all) {
    posix_spawn_file_actions_addinherit_np(&fa, 0);
    posix_spawn_file_actions_addinherit_np(&fa, 2);
    if (out_fd >= 0) posix_spawn_file_actions_addinherit_np(&fa, 1);
  }
#elif HAVE_CLOSE_ALL
  if (c->close_all) posix_spawn_file_actions_addclosefrom_np(&fa, 3);
#endif
  if (c->chdir_tmp) posix_spawn_file_actions_addchdir_np(&fa, "/tmp");
  int rc = posix_spawn(pid, argv[0], &fa, &at, argv, environ);
  posix_spawnattr_destroy(&at);
  posix_spawn_file_actions_destroy(&fa);
  return rc;
}

static void view_case(const char *name, cfg_t c) {
  int p[2];
  if (pipe(p) != 0) return;
  set_cloexec(p[0]);
  char *argv[] = {g_self, "--report", NULL};
  pid_t pid = 0;
  int rc = do_spawn(&c, argv, &pid, p[1]);
  close(p[1]);
  char buf[2048];
  int eof;
  drain_until(p[0], buf, sizeof buf, 3000, &eof);
  close(p[0]);
  char st[64] = "";
  if (rc == 0) reap_blocking(pid, 3000, st, sizeof st);
  size_t l = strlen(buf);
  while (l && (buf[l - 1] == '\n' || buf[l - 1] == ' ')) buf[--l] = 0;
  emit(PROBE, name, "\"posix_spawn_rc\":\"%s\",\"parent_pgid\":%d,\"parent_leak_fd\":%d,\"child_end\":\"%s\",\"child_view\":%s", errno_name(rc), (int)getpgrp(), g_leak_fd, st, l ? buf : "null");
}

/* ------------------------------------------------------------------ pgroup race */
static void pgroup_race(void) {
  int n = 300, spawn_in_group = 0, spawn_err = 0, setpgid_ok = 0, setpgid_eacces = 0, setpgid_other = 0, fork_in_group = 0;
  for (int i = 0; i < n; i++) {
    cfg_t c = {1, 0, 0, 0, 0, 0};
    char *argv[] = {g_self, "--sleep", "300", NULL};
    pid_t pid = 0;
    if (do_spawn(&c, argv, &pid, -1) == 0) {
      if (getpgid(pid) == pid) spawn_in_group++;
      kill(pid, SIGKILL);
      waitpid(pid, NULL, 0);
    } else spawn_err++;
  }
  for (int i = 0; i < n; i++) {
    int ep[2];
    (void)!pipe(ep);
    set_cloexec(ep[1]);
    pid_t c = fork();
    if (c == 0) { char *argv[] = {g_self, "--sleep", "300", NULL}; execv(g_self, argv); _exit(127); }
    close(ep[1]);
    char b;
    (void)!read(ep[0], &b, 1);   /* EOF: the exec happened (what Crystal's Process.new waits for) */
    close(ep[0]);
    if (setpgid(c, c) == 0) { setpgid_ok++; if (getpgid(c) == c) fork_in_group++; }
    else if (errno == EACCES) setpgid_eacces++;
    else setpgid_other++;
    kill(c, SIGKILL);
    waitpid(c, NULL, 0);
  }
  emit(PROBE, "pgroup_race", "\"trials\":%d,\"posix_spawn_SETPGROUP_child_already_in_own_group_on_return\":%d,\"posix_spawn_errors\":%d,\"fork_exec_then_parent_setpgid\":{\"ok\":%d,\"EACCES\":%d,\"other\":%d,\"in_own_group\":%d}",
       n, spawn_in_group, spawn_err, setpgid_ok, setpgid_eacces, setpgid_other, fork_in_group);
}

/* ------------------------------------------------------------------ start suspended (macOS) */
#ifdef __APPLE__
static int proc_stat(pid_t pid) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
  struct kinfo_proc kp;
  size_t len = sizeof kp;
  memset(&kp, 0, sizeof kp);
  if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) return -1;
  return kp.kp_proc.p_stat;
}

static void suspended_case(const char *name, int action) {
  /* action: 0 = SIGCONT, 1 = SIGKILL, 2 = SIGTERM then SIGCONT */
  int p[2];
  if (pipe(p) != 0) return;
  set_cloexec(p[0]);
  cfg_t c = {1, 0, 0, 0, 0, 1};
  char *argv[] = {g_self, "--report", NULL};
  pid_t pid = 0;
  double t0 = now_ms();
  int rc = do_spawn(&c, argv, &pid, p[1]);
  double t_ret = now_ms() - t0;
  close(p[1]);
  if (rc != 0) { emit(PROBE, name, "\"posix_spawn_rc\":\"%s\"", errno_name(rc)); close(p[0]); return; }
  int stat_now = proc_stat(pid);
  int st = 0;
  pid_t w = waitpid(pid, &st, WUNTRACED | WNOHANG);
  char wtxt[64] = "none";
  if (w == pid) status_text(st, wtxt, sizeof wtxt);
  char buf[2048];
  int eof = 0;
  size_t before = drain_until(p[0], buf, sizeof buf, 150, &eof);   /* has the child run? */
  int pgid_ok = getpgid(pid) == pid;
  double t1 = now_ms();
  char end[96] = "";
  size_t after = 0;
  int alive_after_term = -1;
  if (action == 0) {
    kill(pid, SIGCONT);
    after = drain_until(p[0], buf, sizeof buf, 2000, &eof);
    reap_blocking(pid, 2000, end, sizeof end);
  } else if (action == 1) {
    kill(pid, SIGKILL);
    reap_blocking(pid, 2000, end, sizeof end);
  } else {
    kill(pid, SIGTERM);
    sleep_ms(150);
    alive_after_term = waitpid(pid, &st, WNOHANG) == 0;
    kill(pid, SIGCONT);
    after = drain_until(p[0], buf, sizeof buf, 1000, &eof);
    reap_blocking(pid, 2000, end, sizeof end);
  }
  double t_done = now_ms() - t1;
  close(p[0]);
  emit(PROBE, name, "\"posix_spawn_rc\":\"OK\",\"returned_after_ms\":%.2f,\"p_stat_right_after_spawn\":%d,\"p_stat_SSTOP_is\":%d,\"waitpid_WUNTRACED\":\"%s\",\"child_output_bytes_while_suspended\":%zu,\"child_in_own_pgroup\":%d,\"after_action_output_bytes\":%zu,\"child_end\":\"%s\",\"alive_150ms_after_SIGTERM_while_suspended\":%d,\"action_to_end_ms\":%.2f",
       t_ret, stat_now, SSTOP, wtxt, before, pgid_ok, after, end, alive_after_term, t_done);
}
#endif

/* ------------------------------------------------------------------ errors */
static void err_case(const char *name, const char *prog, int kind) {
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  if (kind == 1) posix_spawn_file_actions_addchdir_np(&fa, "/nonexistent-directory");
  if (kind == 2) posix_spawn_file_actions_addclose(&fa, 77);
  if (kind == 3) posix_spawn_file_actions_adddup2(&fa, 77, 5);
  if (kind == 4) posix_spawn_file_actions_addopen(&fa, 5, "/nonexistent-directory/file", O_RDONLY, 0);
  char *argv[] = {(char *)prog, NULL};
  pid_t pid = -12345;
  int rc = posix_spawn(&pid, prog, &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  char child[96] = "no_pid_written";
  int stray = 0;
  if (pid > 0) {
    int st = 0;
    pid_t w = waitpid_timeout(pid, &st, 0, 1000);
    if (w == pid) { char t[64]; stray = 1; status_text(st, t, sizeof t); snprintf(child, sizeof child, "pid_written_and_reapable:%s", t); }
    else snprintf(child, sizeof child, "pid_written_but_waitpid_%s", w == 0 ? "timeout" : errno_name(errno));
  } else if (pid != -12345) snprintf(child, sizeof child, "pid_written_as_%d", (int)pid);
  emit(PROBE, name, "\"posix_spawn_rc\":\"%s\",\"pid_out\":\"%s\",\"a_child_had_to_be_reaped\":%d", errno_name(rc), child, stray);
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--report") == 0) return report_main();
  if (argc >= 3 && strcmp(argv[1], "--sleep") == 0) { sleep_ms(atoi(argv[2])); return 0; }
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(120);
  emit_header(PROBE);
#ifdef __APPLE__
  emit(PROBE, "_api", "\"POSIX_SPAWN_SETSID_defined\":%d,\"POSIX_SPAWN_CLOEXEC_DEFAULT\":1,\"START_SUSPENDED\":1,\"addclosefrom_np\":0",
#ifdef POSIX_SPAWN_SETSID
       1
#else
       0
#endif
  );
#else
  emit(PROBE, "_api", "\"POSIX_SPAWN_SETSID_defined\":%d,\"POSIX_SPAWN_CLOEXEC_DEFAULT\":0,\"START_SUSPENDED\":0,\"addclosefrom_np\":%d",
#ifdef POSIX_SPAWN_SETSID
       1,
#else
       0,
#endif
       HAVE_CLOSE_ALL);
#endif
  parent_state();
  view_case("child_view_baseline_no_attributes", (cfg_t){0, 0, 0, 0, 0, 0});
  view_case("child_view_SETPGROUP", (cfg_t){1, 0, 0, 0, 0, 0});
#ifdef POSIX_SPAWN_SETSID
  view_case("child_view_SETSID", (cfg_t){0, 1, 0, 0, 0, 0});
#endif
  view_case("child_view_SETSIGDEF_and_SETSIGMASK", (cfg_t){0, 0, 1, 0, 0, 0});
#if HAVE_CLOSE_ALL
  view_case("child_view_close_all_descriptors_above_2", (cfg_t){0, 0, 0, 1, 0, 0});
#endif
  view_case("child_view_addchdir_np_tmp", (cfg_t){0, 0, 0, 0, 1, 0});
  view_case("child_view_all_together", (cfg_t){1,
#ifdef POSIX_SPAWN_SETSID
                                               0,
#else
                                               0,
#endif
                                               1, HAVE_CLOSE_ALL, 1, 0});
  pgroup_race();
#ifdef __APPLE__
  suspended_case("start_suspended_then_SIGCONT", 0);
  suspended_case("start_suspended_then_SIGKILL", 1);
  suspended_case("start_suspended_SIGTERM_then_SIGCONT", 2);
#else
  emit(PROBE, "start_suspended", "\"supported\":false");
#endif
  err_case("spawn_error_program_missing", "/nonexistent/prog", 0);
  err_case("spawn_error_program_is_a_directory", "/tmp", 0);
  err_case("spawn_error_addchdir_missing_directory", "/bin/true", 1);
  err_case("spawn_error_addclose_unopened_fd", "/bin/true", 2);
  err_case("spawn_error_adddup2_unopened_fd", "/bin/true", 3);
  err_case("spawn_error_addopen_missing_file", "/bin/true", 4);
  return 0;
}
