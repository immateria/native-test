/*
 * Signals and threads. A runtime that installs a signal handler (Crystal's SIGCHLD/SIGINT handlers, a supervisor's
 * SIGTERM handler) needs to know which thread runs it, whether a blocking call in another thread is interrupted,
 * and what a pending signal does across fork and exec.
 *
 *   thread_selection_*   a process-directed signal (kill(pid) from another process) with different threads
 *                        blocking it: which thread's handler runs
 *   read_interrupted_*   a thread blocked in read(): does a process-directed signal give it EINTR
 *   pending_*            a blocked, pending signal across fork and across exec
 *   handler_in_fork_window  a signal sent to a forked child before it execs: whose handler runs
 *
 * Build: cc -O1 -Wall -Wextra -pthread -o signals_threads signals_threads.c
 */
#include "common.h"
#include <limits.h>
#include <pthread.h>
#define PROBE "signals_threads"
#define NT 4

static char g_self[PATH_MAX];
static volatile int g_hits[NT];
static volatile int g_total;
static volatile int g_stop;
static volatile int g_ready;
static volatile int g_unblock_now[NT];
static __thread int tl_idx = -1;
static int g_handler_pipe = -1;

static void on_usr1(int s) {
  (void)s;
  int i = tl_idx;
  if (i >= 0 && i < NT) g_hits[i]++;
  g_total++;
}

static void unblock_usr1(void) {
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &s, NULL);
}

static void block_usr1(void) {
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  pthread_sigmask(SIG_BLOCK, &s, NULL);
}

static void *worker(void *a) {
  int idx = (int)(intptr_t)a;
  int unblocked = 0;
  tl_idx = idx;
  __sync_fetch_and_add(&g_ready, 1);
  while (!g_stop) {
    if (g_unblock_now[idx] && !unblocked) { unblock_usr1(); unblocked = 1; }
    sleep_ms(1);
  }
  return NULL;
}

static void install_handler(int restart) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = restart ? SA_RESTART : 0;
  sigaction(SIGUSR1, &sa, NULL);
}

/* Child process that sends `count` SIGUSR1 to the parent, `gap_ms` apart; optionally writes a byte to wfd at the end. */
static pid_t spawn_sender(int count, int gap_ms, int wfd, int wfd_delay_ms) {
  pid_t p = fork();
  if (p == 0) {
    pid_t target = getppid();
    for (int i = 0; i < count; i++) {
      kill(target, SIGUSR1);
      sleep_ms(gap_ms);
    }
    if (wfd >= 0) { sleep_ms(wfd_delay_ms); (void)!write(wfd, "x", 1); }
    _exit(0);
  }
  return p;
}

/* unblock[i]: thread i has SIGUSR1 unblocked from the start (i = 0 is the main thread).
 * late_unblock: thread that unblocks only after all signals were sent (-1 = none). */
static void run_selection(const char *kase, const int unblock[NT], int late_unblock) {
  pthread_t th[NT];
  g_stop = 0; g_ready = 0; g_total = 0;
  for (int i = 0; i < NT; i++) { g_hits[i] = 0; g_unblock_now[i] = 0; }
  install_handler(0);
  tl_idx = 0;
  block_usr1();
  /* workers inherit the blocked mask; they unblock themselves when told to */
  for (int i = 1; i < NT; i++) pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
  while (g_ready < NT - 1) sleep_ms(1);
  for (int i = 1; i < NT; i++) if (unblock[i]) g_unblock_now[i] = 1;
  sleep_ms(20);
  if (unblock[0]) unblock_usr1();
  const int sent = 40;
  pid_t s = spawn_sender(sent, 5, -1, 0);
  int st;
  while (waitpid(s, &st, WNOHANG) == 0) sleep_ms(1);
  sleep_ms(50);
  sigset_t pend;
  sigemptyset(&pend);
  sigpending(&pend);
  int pending_visible_to_main = sigismember(&pend, SIGUSR1);
  int hits_before_late[NT];
  for (int i = 0; i < NT; i++) hits_before_late[i] = g_hits[i];
  if (late_unblock >= 0) {
    if (late_unblock == 0) unblock_usr1(); else g_unblock_now[late_unblock] = 1;
    sleep_ms(50);
  }
  emit(PROBE, kase,
       "\"sent\":%d,\"hits\":[%d,%d,%d,%d],\"total\":%d,\"pending_after_sending\":%d,\"hits_before_late_unblock\":[%d,%d,%d,%d]",
       sent, g_hits[0], g_hits[1], g_hits[2], g_hits[3], g_total, pending_visible_to_main,
       hits_before_late[0], hits_before_late[1], hits_before_late[2], hits_before_late[3]);
  g_stop = 1;
  for (int i = 1; i < NT; i++) pthread_join(th[i], NULL);
  /* back to a clean single-threaded state: SIGUSR1 default-blocked off */
  unblock_usr1();
}

static void run_pthread_kill(void) {
  pthread_t th[NT];
  g_stop = 0; g_ready = 0; g_total = 0;
  for (int i = 0; i < NT; i++) { g_hits[i] = 0; g_unblock_now[i] = 0; }
  install_handler(0);
  tl_idx = 0;
  for (int i = 1; i < NT; i++) pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
  while (g_ready < NT - 1) sleep_ms(1);
  for (int i = 0; i < 10; i++) { pthread_kill(th[3], SIGUSR1); sleep_ms(5); }
  sleep_ms(30);
  emit(PROBE, "pthread_kill_to_thread_3_all_unblocked", "\"sent\":10,\"hits\":[%d,%d,%d,%d],\"total\":%d",
       g_hits[0], g_hits[1], g_hits[2], g_hits[3], g_total);
  g_stop = 1;
  for (int i = 1; i < NT; i++) pthread_join(th[i], NULL);
}

/* The main thread blocks in read() on a pipe. A sender process sends one SIGUSR1 at +100 ms and unblocks the read with a
 * byte at +300 ms. main_unblocked / worker_unblocked choose who may take the signal. */
static void run_read(const char *kase, int main_unblocked, int worker_unblocked, int restart) {
  pthread_t th[NT];
  int p[2];
  if (pipe(p) != 0) return;
  g_stop = 0; g_ready = 0; g_total = 0;
  for (int i = 0; i < NT; i++) { g_hits[i] = 0; g_unblock_now[i] = 0; }
  install_handler(restart);
  tl_idx = 0;
  block_usr1();
  for (int i = 1; i < NT; i++) pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
  while (g_ready < NT - 1) sleep_ms(1);
  if (worker_unblocked) g_unblock_now[1] = 1;
  sleep_ms(20);
  if (main_unblocked) unblock_usr1();
  double t0 = now_ms();
  pid_t s;
  s = fork();
  if (s == 0) {
    pid_t target = getppid();
    close(p[0]);
    sleep_ms(100);
    kill(target, SIGUSR1);
    sleep_ms(200);
    (void)!write(p[1], "x", 1);
    _exit(0);
  }
  close(p[1]);
  char c;
  errno = 0;
  ssize_t r = read(p[0], &c, 1);
  int e = errno;
  double dt = now_ms() - t0;
  int hits_at_return[NT];
  for (int i = 0; i < NT; i++) hits_at_return[i] = g_hits[i];
  int st;
  waitpid(s, &st, 0);
  emit(PROBE, kase, "\"main_unblocked\":%d,\"worker_unblocked\":%d,\"sa_restart\":%d,\"read_returned\":%ld,\"errno\":\"%s\",\"read_returned_after_ms\":%.0f,\"handler_ran_in_thread\":[%d,%d,%d,%d]",
       main_unblocked, worker_unblocked, restart, (long)r, errno_name(e), dt,
       hits_at_return[0], hits_at_return[1], hits_at_return[2], hits_at_return[3]);
  close(p[0]);
  g_stop = 1;
  for (int i = 1; i < NT; i++) pthread_join(th[i], NULL);
  unblock_usr1();
}

/* ---- pending signals across fork and exec ---- */

static volatile sig_atomic_t g_got;
static void on_usr1_flag(int s) { (void)s; g_got = 1; }

static int exec_report_pending(const char *how) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1_flag;
  sigaction(SIGUSR1, &sa, NULL);
  sigset_t cur, pend;
  sigemptyset(&cur);
  sigprocmask(SIG_BLOCK, NULL, &cur);
  int blocked = sigismember(&cur, SIGUSR1);
  sigemptyset(&pend);
  sigpending(&pend);
  int pending = sigismember(&pend, SIGUSR1);
  unblock_usr1();
  for (int i = 0; i < 20 && !g_got; i++) sleep_ms(5);
  emit(PROBE, "pending_signal_after_exec", "\"sent_with\":\"%s\",\"blocked_mask_inherited\":%d,\"pending_before_unblock\":%d,\"delivered_after_unblock\":%d",
       how, blocked, pending, (int)g_got);
  return 0;
}

static void run_pending(void) {
  /* process-directed (kill(getpid)) and thread-directed (raise) pending signal, then fork */
  const char *how[2] = {"kill_self", "raise"};
  for (int variant = 0; variant < 2; variant++) {
    install_handler(0);
    block_usr1();
    if (variant == 0) kill(getpid(), SIGUSR1); else raise(SIGUSR1);
    sigset_t pend;
    sigemptyset(&pend);
    sigpending(&pend);
    int parent_pending = sigismember(&pend, SIGUSR1);
    pid_t c = fork();
    if (c == 0) {
      sigset_t cp;
      sigemptyset(&cp);
      sigpending(&cp);
      _exit(sigismember(&cp, SIGUSR1) ? 10 : 11);
    }
    int st = 0;
    waitpid(c, &st, 0);
    int child_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    char kase[64];
    snprintf(kase, sizeof kase, "pending_signal_across_fork_%s", how[variant]);
    emit(PROBE, kase, "\"pending_in_parent\":%d,\"child_sees_pending\":\"%s\"", parent_pending,
         child_code == 10 ? "yes" : child_code == 11 ? "no" : "unknown");

    /* exec: the child raises the signal while blocked, then execs this program in report mode */
    fflush(stdout);
    pid_t e = fork();
    if (e == 0) {
      if (variant == 0) kill(getpid(), SIGUSR1); else raise(SIGUSR1);
      char *argv[] = {g_self, (char *)"--report-pending", (char *)how[variant], NULL};
      execv(g_self, argv);
      _exit(127);
    }
    waitpid(e, &st, 0);
    /* consume the parent's own pending signal: handler ignores it */
    unblock_usr1();
    sleep_ms(5);
  }
}

/* A signal that reaches a forked child before it execs runs the handler the parent installed. */
static void fork_window_handler(int sig) {
  (void)sig;
  pid_t me = getpid();
  (void)!write(g_handler_pipe, &me, sizeof me);
}

static void run_fork_window(void) {
  int p[2];
  if (pipe(p) != 0) return;
  g_handler_pipe = p[1];
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = fork_window_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) {
    sleep_ms(200); /* a slow gap between fork and exec */
    char *argv[] = {g_self, (char *)"--noop", NULL};
    execv(g_self, argv);
    _exit(127);
  }
  sleep_ms(50);
  kill(c, SIGUSR1);
  pid_t who = 0;
  ssize_t r = read_timeout(p[0], &who, sizeof who, 1000);
  int st = 0;
  char status[64];
  reap_blocking(c, 3000, status, sizeof status);
  (void)st;
  emit(PROBE, "handler_in_fork_window", "\"handler_ran\":%d,\"ran_in_child\":%d,\"child_status\":\"%s\"",
       r == (ssize_t)sizeof who, r == (ssize_t)sizeof who && who == c, status);
  close(p[0]); close(p[1]);
  signal(SIGUSR1, SIG_DFL);
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--noop") == 0) return 0;
  if (argc > 1 && strcmp(argv[1], "--report-pending") == 0) return exec_report_pending(argc > 2 ? argv[2] : "?");
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  watchdog(120);
  emit_header(PROBE);

  { int u[NT] = {1, 1, 1, 1}; run_selection("thread_selection_all_unblocked", u, -1); }
  { int u[NT] = {0, 1, 1, 1}; run_selection("thread_selection_main_blocked", u, -1); }
  { int u[NT] = {1, 0, 0, 0}; run_selection("thread_selection_only_main_unblocked", u, -1); }
  { int u[NT] = {0, 0, 0, 1}; run_selection("thread_selection_only_thread_3_unblocked", u, -1); }
  { int u[NT] = {0, 0, 0, 0}; run_selection("thread_selection_all_blocked_then_thread_2_unblocks", u, 2); }
  { int u[NT] = {0, 0, 0, 0}; run_selection("thread_selection_all_blocked_then_main_unblocks", u, 0); }
  run_pthread_kill();

  run_read("read_interrupted_main_unblocked_only", 1, 0, 0);
  run_read("read_not_interrupted_when_other_thread_takes_signal", 0, 1, 0);
  run_read("read_interrupted_main_unblocked_with_sa_restart", 1, 0, 1);
  run_read("read_all_threads_unblocked", 1, 1, 0);

  run_pending();
  run_fork_window();
  return 0;
}
