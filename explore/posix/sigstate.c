/*
 * What a freshly spawned child inherits from its supervisor, and what the spawn attributes change:
 * signal mask, ignored and caught signals, process group, session, working directory, descriptors, and (macOS)
 * POSIX_SPAWN_START_SUSPENDED / POSIX_SPAWN_CLOEXEC_DEFAULT. A child that inherits a blocked or ignored
 * SIGTERM silently defeats the supervisor's graceful shutdown, which is why this matters. The child side is
 * this same binary run with --dump. Also used by crystal_spawn.cr to see what Crystal's Process.new does.
 *
 * Build: cc -O1 -Wall -Wextra -o sigstate sigstate.c
 */
#include "common.h"
#include <limits.h>
#include <spawn.h>
#define PROBE "sigstate"

extern char **environ;
static char g_self[PATH_MAX];

#ifndef POSIX_SPAWN_SETSID
#ifdef __APPLE__
#define POSIX_SPAWN_SETSID 0x0400
#endif
#endif

/* ---------------- child: dump what we inherited ---------------- */
static int dump_main(void) {
  char blocked[256] = "", ignored[256] = "", caught[256] = "", fds[256] = "";
  sigset_t cur;
  sigprocmask(SIG_BLOCK, NULL, &cur);
  for (int s = 1; s < 32; s++) {
    if (s == SIGKILL || s == SIGSTOP) continue;
    char tag[32];
    snprintf(tag, sizeof tag, "%s%s", sig_name(s), strcmp(sig_name(s), "other") == 0 ? "" : "");
    if (strcmp(sig_name(s), "other") == 0) snprintf(tag, sizeof tag, "%d", s);
    if (sigismember(&cur, s) == 1) { strncat(blocked, blocked[0] ? "," : "", sizeof blocked - strlen(blocked) - 1); strncat(blocked, tag, sizeof blocked - strlen(blocked) - 1); }
    struct sigaction sa;
    if (sigaction(s, NULL, &sa) == 0) {
      if (sa.sa_handler == SIG_IGN) { strncat(ignored, ignored[0] ? "," : "", sizeof ignored - strlen(ignored) - 1); strncat(ignored, tag, sizeof ignored - strlen(ignored) - 1); }
      else if (sa.sa_handler != SIG_DFL) { strncat(caught, caught[0] ? "," : "", sizeof caught - strlen(caught) - 1); strncat(caught, tag, sizeof caught - strlen(caught) - 1); }
    }
  }
  for (int fd = 3; fd < 64; fd++) {
    int fl = fcntl(fd, F_GETFD);
    if (fl == -1) continue;
    char t[16];
    snprintf(t, sizeof t, "%s%d%s", fds[0] ? "," : "", fd, (fl & FD_CLOEXEC) ? "c" : "");
    strncat(fds, t, sizeof fds - strlen(fds) - 1);
  }
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof cwd)) snprintf(cwd, sizeof cwd, "?");
  const char *base = strrchr(cwd, '/');
  printf("{\"blocked\":\"%s\",\"ignored\":\"%s\",\"caught\":\"%s\",\"pgid_is_pid\":%s,\"sid_is_pid\":%s,\"cwd_basename\":\"%s\",\"inherited_fds\":\"%s\"}\n",
         blocked, ignored, caught, getpgrp() == getpid() ? "true" : "false", getsid(0) == getpid() ? "true" : "false",
         base ? base + 1 : cwd, fds);
  return 0;
}

/* ---------------- driver ---------------- */
static void on_usr2(int s) { (void)s; }

static void setup_parent_state(void) {
  sigset_t m;
  sigemptyset(&m);
  sigaddset(&m, SIGUSR1);
  sigaddset(&m, SIGTERM);
  sigprocmask(SIG_BLOCK, &m, NULL);
  signal(SIGINT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = on_usr2;
  sigaction(SIGUSR2, &sa, NULL);
}

typedef struct {
  int use_fork_exec;
  int sigmask_empty;   /* POSIX_SPAWN_SETSIGMASK with an empty set */
  int sigdef_all;      /* POSIX_SPAWN_SETSIGDEF with every signal */
  int pgroup;
  int setsid;
  int cloexec_default;
  const char *chdir;
} opts_t;

static void run_case(const char *kase, const opts_t *o, int fd_without_cloexec) {
  int pfd[2];
  if (pipe(pfd) != 0) return;
  set_cloexec(pfd[0]);
  set_cloexec(pfd[1]);
  int plain = -1;
  if (fd_without_cloexec) plain = open("/dev/null", O_RDONLY); /* inheritable on purpose */
  int rc = 0, e = 0;
  pid_t pid = 0;
  fflush(stdout);
  if (o->use_fork_exec) {
    pid = fork();
    if (pid == 0) {
      dup2(pfd[1], 1);
      if (o->chdir && chdir(o->chdir) != 0) _exit(126);
      execl(g_self, g_self, "--dump", (char *)NULL);
      _exit(127);
    }
    if (pid < 0) { rc = errno; }
  } else {
    posix_spawnattr_t at;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_init(&at);
    posix_spawn_file_actions_init(&fa);
    short flags = 0;
    if (o->sigmask_empty) {
      sigset_t empty;
      sigemptyset(&empty);
      posix_spawnattr_setsigmask(&at, &empty);
      flags |= POSIX_SPAWN_SETSIGMASK;
    }
    if (o->sigdef_all) {
      sigset_t all;
      sigfillset(&all);
      posix_spawnattr_setsigdefault(&at, &all);
      flags |= POSIX_SPAWN_SETSIGDEF;
    }
    if (o->pgroup) { posix_spawnattr_setpgroup(&at, 0); flags |= POSIX_SPAWN_SETPGROUP; }
#ifdef POSIX_SPAWN_SETSID
    if (o->setsid) flags |= POSIX_SPAWN_SETSID;
#endif
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    if (o->cloexec_default) flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
    posix_spawnattr_setflags(&at, flags);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], 1);
#if defined(__APPLE__) || defined(__GLIBC__)
    if (o->chdir) posix_spawn_file_actions_addchdir_np(&fa, o->chdir);
#endif
    char *args[] = {g_self, (char *)"--dump", NULL};
    rc = posix_spawn(&pid, g_self, &fa, &at, args, environ);
  }
  close(pfd[1]);
  char buf[2048];
  int eof;
  if (rc == 0) drain_until(pfd[0], buf, sizeof buf, 3000, &eof); else buf[0] = 0;
  buf[strcspn(buf, "\n")] = 0;
  char st[64] = "";
  if (rc == 0 && pid > 0) reap_blocking(pid, 3000, st, sizeof st);
  (void)e;
  emit(PROBE, kase, "\"spawn_rc\":\"%s\",\"status\":\"%s\",\"child_dump\":%s", errno_name(rc), st, buf[0] ? buf : "null");
  close(pfd[0]);
  if (plain >= 0) close(plain);
}

#ifdef POSIX_SPAWN_START_SUSPENDED
static void case_start_suspended(void) {
  int pfd[2];
  if (pipe(pfd) != 0) return;
  set_cloexec(pfd[0]); set_cloexec(pfd[1]);
  posix_spawnattr_t at;
  posix_spawn_file_actions_t fa;
  posix_spawnattr_init(&at);
  posix_spawn_file_actions_init(&fa);
  posix_spawnattr_setflags(&at, POSIX_SPAWN_START_SUSPENDED);
  posix_spawn_file_actions_adddup2(&fa, pfd[1], 1);
  char *args[] = {g_self, (char *)"--dump", NULL};
  pid_t pid = 0;
  double t0 = now_ms();
  int rc = posix_spawn(&pid, g_self, &fa, &at, args, environ);
  close(pfd[1]);
  if (rc != 0) { emit(PROBE, "posix_spawn_start_suspended", "\"spawn_rc\":\"%s\"", errno_name(rc)); return; }
  int st = 0;
  pid_t r = waitpid_timeout(pid, &st, WUNTRACED, 2000);
  char s1[64] = "none";
  if (r > 0) status_text(st, s1, sizeof s1);
  char buf[2048];
  int eof;
  size_t early = drain_until(pfd[0], buf, sizeof buf, 300, &eof);
  double t_cont = now_ms();
  kill(pid, SIGCONT);
  r = waitpid_timeout(pid, &st, WCONTINUED, 1000);
  char s2[64] = "none";
  if (r > 0) status_text(st, s2, sizeof s2);
  drain_until(pfd[0], buf + early, sizeof buf - early, 2000, &eof);
  buf[strcspn(buf, "\n")] = 0;
  char s3[64];
  reap_blocking(pid, 3000, s3, sizeof s3);
  emit(PROBE, "posix_spawn_start_suspended",
       "\"spawn_rc\":\"OK\",\"first_wait\":\"%s\",\"ms_to_first_stop_report\":%.1f,\"child_output_bytes_while_suspended\":%zu,"
       "\"wait_after_sigcont\":\"%s\",\"final_status\":\"%s\",\"ms_from_cont_to_exit\":%.1f,\"child_dump\":%s",
       s1, t_cont - t0, early, s2, s3, now_ms() - t_cont, buf[0] ? buf : "null");
}
#endif

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--dump") == 0) return dump_main();
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(60);
  emit_header(PROBE);
  setup_parent_state();
  emit(PROBE, "parent_state_set_up", "\"blocked\":\"SIGUSR1,SIGTERM\",\"ignored\":\"SIGINT,SIGHUP\",\"caught\":\"SIGUSR2\"");
  opts_t base = {0};
  opts_t o;
  o = base; o.use_fork_exec = 1;
  run_case("fork_exec_inherits", &o, 1);
  o = base;
  run_case("posix_spawn_default_inherits", &o, 1);
  o = base; o.sigmask_empty = 1; o.sigdef_all = 1;
  run_case("posix_spawn_setsigmask_empty_and_setsigdef_all", &o, 0);
  o = base; o.pgroup = 1;
  run_case("posix_spawn_setpgroup_0", &o, 0);
#ifdef POSIX_SPAWN_SETSID
  o = base; o.setsid = 1;
  run_case("posix_spawn_setsid", &o, 0);
#else
  emit(PROBE, "posix_spawn_setsid", "\"unsupported\":\"POSIX_SPAWN_SETSID not defined by this libc\"");
#endif
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
  o = base; o.cloexec_default = 1;
  run_case("posix_spawn_cloexec_default_with_plain_fd_open", &o, 1);
#else
  emit(PROBE, "posix_spawn_cloexec_default_with_plain_fd_open", "\"unsupported\":\"POSIX_SPAWN_CLOEXEC_DEFAULT not defined by this libc\"");
#endif
  o = base; o.chdir = "/tmp";
  run_case("posix_spawn_addchdir_tmp", &o, 0);
  o = base; o.chdir = "/nonexistent-dir-for-probe";
  run_case("posix_spawn_addchdir_missing_dir", &o, 0);
  o = base; o.use_fork_exec = 1; o.chdir = "/nonexistent-dir-for-probe";
  run_case("fork_exec_chdir_missing_dir_child_status", &o, 0);
#ifdef POSIX_SPAWN_START_SUSPENDED
  case_start_suspended();
#else
  emit(PROBE, "posix_spawn_start_suspended", "\"unsupported\":\"POSIX_SPAWN_START_SUSPENDED not defined by this libc\"");
#endif
  return 0;
}
