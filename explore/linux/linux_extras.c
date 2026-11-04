/*
 * Linux details a supervisor can trip over (records, never asserts).
 *
 *   dumpable_across_exec       PR_SET_DUMPABLE 0 set before exec: what does the exec'd program read back? (fs/exec.c
 *                              resets dumpability for an ordinary same-uid exec, so a launcher cannot set it for the
 *                              child; RLIMIT_CORE survives exec)
 *   wnowait_observer_vs_reaper one thread observes an exited child with waitid(WNOWAIT), another thread reaps it:
 *                              WNOWAIT reserves nothing. Same with a pidfd (waitid P_PIDFD)
 *   fexecve_script_*           executing a #! script through a file descriptor: with FD_CLOEXEC the interpreter
 *                              cannot open /dev/fd/N and the exec fails (fs/binfmt_script.c); an ELF works either way
 *
 * Build: cc -O1 -Wall -Wextra -pthread -o linux_extras linux_extras.c
 */
#include "../posix/common.h"
#include <limits.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#define PROBE "linux_extras"

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

extern char **environ;
static char g_self[PATH_MAX];

static int report_dumpable(void) {
  int d = prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
  struct rlimit rl;
  getrlimit(RLIMIT_CORE, &rl);
  printf("%d %lld\n", d, (long long)rl.rlim_cur);
  return 0;
}

static void dumpable_across_exec(void) {
  int p[2];
  if (pipe(p) != 0) return;
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    dup2(p[1], 1);
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = rl.rlim_max >= 1 ? 1 : 0;
    setrlimit(RLIMIT_CORE, &rl);
    int set = prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L);
    int before = prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
    printf("%d %d ", set, before);
    fflush(stdout);
    char *args[] = {g_self, "--report-dumpable", NULL};
    execve(g_self, args, environ);
    _exit(127);
  }
  close(p[1]);
  char buf[128];
  int eof;
  drain_until(p[0], buf, sizeof buf, 3000, &eof);
  close(p[0]);
  char st[64];
  reap_blocking(c, 3000, st, sizeof st);
  int set = -9, before = -9, after = -9;
  long long core = -9;
  sscanf(buf, "%d %d %d %lld", &set, &before, &after, &core);
  emit(PROBE, "dumpable_across_exec", "\"prctl_set_rc\":%d,\"dumpable_before_exec\":%d,\"dumpable_after_exec\":%d,\"RLIMIT_CORE_soft_after_exec\":%lld,\"child_end\":\"%s\"",
       set, before, after, core, st);
}

typedef struct { pid_t pid; int pidfd; volatile int observed, reaped, go_reap, done; int observe_rc, observe_errno, final_rc, final_errno, reap_rc; pid_t observed_pid; } wn_t;

static void *reaper(void *a) {
  wn_t *w = a;
  while (!w->go_reap) sleep_ms(1);
  int st;
  w->reap_rc = (int)waitpid(w->pid, &st, 0);
  w->reaped = 1;
  return NULL;
}

static void wnowait_case(const char *kase, int use_pidfd) {
  wn_t w;
  memset(&w, 0, sizeof w);
  w.pidfd = -1;
  pid_t c = fork();
  if (c == 0) { sleep_ms(50); _exit(37); }
  w.pid = c;
  if (use_pidfd) w.pidfd = (int)syscall(SYS_pidfd_open, c, 0);
  pthread_t t;
  pthread_create(&t, NULL, reaper, &w);
  siginfo_t si;
  memset(&si, 0, sizeof si);
  errno = 0;
  w.observe_rc = use_pidfd ? waitid((idtype_t)P_PIDFD, (id_t)w.pidfd, &si, WEXITED | WNOWAIT) : waitid(P_PID, (id_t)c, &si, WEXITED | WNOWAIT);
  w.observe_errno = errno;
  w.observed_pid = si.si_pid;
  int observed_status = si.si_status;
  w.go_reap = 1;
  pthread_join(t, NULL);
  memset(&si, 0, sizeof si);
  errno = 0;
  w.final_rc = use_pidfd ? waitid((idtype_t)P_PIDFD, (id_t)w.pidfd, &si, WEXITED | WNOHANG) : waitid(P_PID, (id_t)c, &si, WEXITED | WNOHANG);
  w.final_errno = errno;
  if (w.pidfd >= 0) close(w.pidfd);
  emit(PROBE, kase, "\"pidfd\":%d,\"observer_waitid_wnowait_rc\":%d,\"observer_errno\":\"%s\",\"observed_pid_matches\":%d,\"observed_exit_status\":%d,\"sibling_waitpid_reaped\":%d,\"observer_collect_after_rc\":%d,\"observer_collect_errno\":\"%s\"",
       use_pidfd ? (w.pidfd >= 0 ? 1 : 0) : -1, w.observe_rc, errno_name(w.observe_rc == 0 ? 0 : w.observe_errno), w.observed_pid == c, observed_status,
       w.reap_rc == c, w.final_rc, errno_name(w.final_rc == 0 ? 0 : w.final_errno));
}

/* exec a file through its descriptor, from a forked child; returns "exited(N)" or the exec errno */
static void fexec_case(const char *kase, const char *path, int cloexec) {
  int fd = open(path, O_RDONLY | (cloexec ? O_CLOEXEC : 0));
  if (fd < 0) { emit(PROBE, kase, "\"open_errno\":\"%s\"", errno_name(errno)); return; }
  int p[2];
  if (pipe(p) != 0) { close(fd); return; }
  set_cloexec(p[1]);
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    char *args[] = {(char *)path, NULL};
    fexecve(fd, args, environ);
    int e = errno;
    (void)!write(p[1], &e, sizeof e);
    _exit(126);
  }
  close(p[1]);
  close(fd);
  int e = 0;
  ssize_t k = read_timeout(p[0], &e, sizeof e, 3000);
  close(p[0]);
  char st[64];
  reap_blocking(c, 3000, st, sizeof st);
  emit(PROBE, kase, "\"fd_cloexec\":%d,\"exec_failed\":%d,\"exec_errno\":\"%s\",\"child_end\":\"%s\"", cloexec, k == (ssize_t)sizeof e, k == (ssize_t)sizeof e ? errno_name(e) : "OK", st);
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--report-dumpable") == 0) return report_dumpable();
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(60);
  emit_header(PROBE);
  dumpable_across_exec();
  wnowait_case("wnowait_observer_vs_reaper", 0);
  wnowait_case("wnowait_observer_vs_reaper_pidfd", 1);

  char dir[PATH_MAX], script[PATH_MAX + 32];
  const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
  snprintf(dir, sizeof dir, "%s/linux-extras-%d", tmp, (int)getpid());
  mkdir(dir, 0700);
  snprintf(script, sizeof script, "%s/script.sh", dir);
  FILE *f = fopen(script, "w");
  if (f) { fputs("#!/bin/sh\nexit 23\n", f); fclose(f); chmod(script, 0755); }
  fexec_case("fexecve_script_without_cloexec", script, 0);
  fexec_case("fexecve_script_with_cloexec", script, 1);
  fexec_case("fexecve_elf_with_cloexec", "/bin/true", 1);
  unlink(script);
  rmdir(dir);
  return 0;
}
