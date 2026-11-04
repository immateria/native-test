/*
 * Which errno does a failed spawn report, and does fork+exec agree with posix_spawn? A supervisor has to map
 * these to "cannot start" errors; the kit only covers a missing executable, a missing cwd and an invalid
 * command. Each case runs the same request through fork+exec (the errno comes back over a CLOEXEC pipe, the
 * technique Crystal's stdlib uses) and through posix_spawn, and reports both.
 *
 * Build: cc -O1 -Wall -Wextra -o spawn_errors spawn_errors.c
 */
#include "common.h"
#include <limits.h>
#include <spawn.h>
#define PROBE "spawn_errors"

extern char **environ;
static char g_self[PATH_MAX];
static char g_dir[PATH_MAX - 64]; /* leaves room for file names so snprintf cannot truncate */

static void write_file(const char *name, const char *content, size_t n, mode_t mode, char *path_out) {
  snprintf(path_out, PATH_MAX, "%s/%s", g_dir, name);
  int fd = open(path_out, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd >= 0) { (void)!write(fd, content, n); close(fd); }
  chmod(path_out, mode);
}

/* returns errno from exec (0 if exec succeeded; then status holds how the program ended) */
static int forkexec_try(const char *path, char *const argv[], char *const envp[], int use_path, char *status, size_t sn) {
  int ep[2];
  if (pipe(ep) != 0) return -1;
  set_cloexec(ep[0]); set_cloexec(ep[1]);
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) {
    int out = open("/dev/null", O_WRONLY);
    dup2(out, 1); dup2(out, 2);
    /* execvpe is glibc-only; execvp after replacing environ is the portable equivalent */
    if (use_path) { environ = (char **)envp; execvp(path, argv); } else execve(path, argv, envp);
    int e = errno;
    (void)!write(ep[1], &e, sizeof e);
    _exit(127);
  }
  close(ep[1]);
  int e = 0;
  ssize_t n = read(ep[0], &e, sizeof e);
  close(ep[0]);
  if (n != (ssize_t)sizeof e) e = 0;
  reap_blocking(p, 5000, status, sn);
  return e;
}

static int posix_try(const char *path, char *const argv[], char *const envp[], int use_path, char *status, size_t sn) {
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
  posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  pid_t p = 0;
  int rc = use_path ? posix_spawnp(&p, path, &fa, NULL, argv, envp) : posix_spawn(&p, path, &fa, NULL, argv, envp);
  if (rc == 0) reap_blocking(p, 5000, status, sn); else status[0] = 0;
  return rc;
}

static void both(const char *kase, const char *path, char *const argv[], char *const envp[], int use_path) {
  char s1[64] = "", s2[64] = "";
  int e1 = forkexec_try(path, argv, envp, use_path, s1, sizeof s1);
  int e2 = posix_try(path, argv, envp, use_path, s2, sizeof s2);
  emit(PROBE, kase, "\"fork_exec_errno\":\"%s\",\"fork_exec_errno_num\":%d,\"fork_exec_status\":\"%s\",\"posix_spawn_rc\":\"%s\",\"posix_spawn_rc_num\":%d,\"posix_spawn_status\":\"%s\"",
       errno_name(e1), e1, e1 ? "(exec failed)" : s1, errno_name(e2), e2, e2 ? "(spawn failed)" : s2);
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--noop") == 0) return 0;
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(120);
  emit_header(PROBE);
  const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
  snprintf(g_dir, sizeof g_dir, "%s/spawn-errors-%d", tmp, (int)getpid());
  mkdir(g_dir, 0700);

  char p_noexec[PATH_MAX], p_noshebang[PATH_MAX], p_badinterp[PATH_MAX], p_interp_noexec[PATH_MAX], p_garbage[PATH_MAX],
       p_script_ok[PATH_MAX], p_loop[PATH_MAX], p_busy[PATH_MAX], p_through_file[PATH_MAX], p_missing[PATH_MAX];
  char *noop_argv[] = {(char *)"x", (char *)"--noop", NULL};
  char *empty_argv[] = {(char *)"x", NULL};

  write_file("not_executable", "#!/bin/sh\nexit 0\n", 17, 0644, p_noexec);
  write_file("no_shebang", "exit 0\n", 7, 0755, p_noshebang);
  write_file("bad_interpreter", "#!/nonexistent/interpreter\n", 27, 0755, p_badinterp);
  char body[PATH_MAX + 16];
  int bl = snprintf(body, sizeof body, "#!%s\n", p_noexec);
  write_file("interpreter_not_executable", body, (size_t)bl, 0755, p_interp_noexec);
  unsigned char junk[128];
  for (size_t i = 0; i < sizeof junk; i++) junk[i] = (unsigned char)(0x80 + i);
  write_file("garbage_binary", (const char *)junk, sizeof junk, 0755, p_garbage);
  write_file("script_ok", "#!/bin/sh\nexit 0\n", 17, 0755, p_script_ok);
  snprintf(p_loop, sizeof p_loop, "%s/loop", g_dir);
  (void)!symlink("loop", p_loop);
  snprintf(p_through_file, sizeof p_through_file, "%s/script_ok/child", g_dir);
  snprintf(p_missing, sizeof p_missing, "%s/does_not_exist", g_dir);

  both("sanity_script_with_shebang", p_script_ok, empty_argv, environ, 0);
  both("missing_file", p_missing, empty_argv, environ, 0);
  both("directory_as_executable", g_dir, empty_argv, environ, 0);
  both("file_without_exec_permission", p_noexec, empty_argv, environ, 0);
  both("script_without_shebang", p_noshebang, empty_argv, environ, 0);
  both("script_with_missing_interpreter", p_badinterp, empty_argv, environ, 0);
  both("script_whose_interpreter_is_not_executable", p_interp_noexec, empty_argv, environ, 0);
  both("garbage_bytes_marked_executable", p_garbage, empty_argv, environ, 0);
  both("path_component_is_a_file", p_through_file, empty_argv, environ, 0);
  both("symlink_loop", p_loop, empty_argv, environ, 0);

  char *longname = malloc(PATH_MAX + 2048);
  memset(longname, 'a', PATH_MAX + 2000);
  longname[PATH_MAX + 2000] = 0;
  both("path_longer_than_PATH_MAX", longname, empty_argv, environ, 0);
  free(longname);

  /* PATH search */
  both("bare_name_without_path_search", "true", empty_argv, environ, 0);
  both("bare_name_with_path_search", "true", empty_argv, environ, 1);
  both("bare_name_missing_with_path_search", "no-such-program-for-probe", empty_argv, environ, 1);

  /* argument / environment size */
  long arg_max = sysconf(_SC_ARG_MAX);
  size_t chunk = 100000, n_args = (size_t)(arg_max > 0 ? arg_max : 1048576) * 3 / chunk + 4;
  char **big_argv = calloc(n_args + 2, sizeof(char *));
  char *blob = malloc(chunk + 1);
  memset(blob, 'x', chunk); blob[chunk] = 0;
  big_argv[0] = (char *)"x"; big_argv[1] = (char *)"--noop";
  for (size_t i = 0; i < n_args; i++) big_argv[2 + i] = blob;
  both("argv_total_size_over_ARG_MAX", g_self, big_argv, environ, 0);
  char **big_env = calloc(n_args + 2, sizeof(char *));
  char *envblob = malloc(chunk + 8);
  snprintf(envblob, chunk + 8, "BIG=");
  memset(envblob + 4, 'y', chunk); envblob[chunk + 4] = 0;
  for (size_t i = 0; i < n_args; i++) big_env[i] = envblob;
  both("environment_total_size_over_ARG_MAX", g_self, noop_argv, big_env, 0);
  {
    char single[200000];
    memset(single, 'z', sizeof single - 1); single[sizeof single - 1] = 0;
    char *one_big[] = {(char *)"x", (char *)"--noop", single, NULL};
    both("single_argument_of_200000_bytes", g_self, one_big, environ, 0);
  }
  emit(PROBE, "_arg_max", "\"sysconf_ARG_MAX\":%ld", arg_max);

  /* text busy: executable open for writing */
  snprintf(p_busy, sizeof p_busy, "%s/busy_copy", g_dir);
  {
    int in = open(g_self, O_RDONLY), out = open(p_busy, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    char buf[65536];
    ssize_t r;
    while (in >= 0 && out >= 0 && (r = read(in, buf, sizeof buf)) > 0) (void)!write(out, buf, (size_t)r);
    if (in >= 0) close(in);
    chmod(p_busy, 0755);
    /* `out` stays open for writing */
    both("executable_open_for_writing_by_the_supervisor", p_busy, noop_argv, environ, 0);
    if (out >= 0) close(out);
    both("same_executable_after_closing_the_writer", p_busy, noop_argv, environ, 0);
  }

  /* file actions that cannot be satisfied */
  {
    posix_spawn_file_actions_t fa;
    pid_t p = 0;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addclose(&fa, 987);
    int rc = posix_spawn(&p, g_self, &fa, NULL, noop_argv, environ);
    char st[64] = "";
    if (rc == 0) reap_blocking(p, 3000, st, sizeof st);
    emit(PROBE, "file_action_close_of_fd_that_is_not_open", "\"posix_spawn_rc\":\"%s\",\"status\":\"%s\"", errno_name(rc), st);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, 987, 1);
    rc = posix_spawn(&p, g_self, &fa, NULL, noop_argv, environ);
    st[0] = 0;
    if (rc == 0) reap_blocking(p, 3000, st, sizeof st);
    emit(PROBE, "file_action_dup2_from_fd_that_is_not_open", "\"posix_spawn_rc\":\"%s\",\"status\":\"%s\"", errno_name(rc), st);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 5, "/nonexistent/for/probe", O_RDONLY, 0);
    rc = posix_spawn(&p, g_self, &fa, NULL, noop_argv, environ);
    st[0] = 0;
    if (rc == 0) reap_blocking(p, 3000, st, sizeof st);
    emit(PROBE, "file_action_open_of_missing_file", "\"posix_spawn_rc\":\"%s\",\"status\":\"%s\"", errno_name(rc), st);
  }

  char cmd[PATH_MAX + 16];
  snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
  (void)!system(cmd);
  return 0;
}
