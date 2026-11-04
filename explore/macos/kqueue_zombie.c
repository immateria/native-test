/*
 * Does EVFILT_PROC / NOTE_EXIT deliver an exit event when the registration is made after the
 * process has already exited (an unreaped zombie)?
 *
 * Why: the kit's kqueue_many_children_one_queue_all_exit_events spawns 8 children with exits ~180 ms
 * after their own start and registers for all of them only after all 8 are spawned. It passed in most
 * runs and failed once with 7 of 8 events (all 8 children did exit normally). If a registration on a
 * zombie succeeds but never delivers, a slow runner turns that test into a coin flip.
 *
 * Build: cc -O1 -Wall -Wextra -o kqueue_zombie kqueue_zombie.c   (macOS only; prints "skipped" elsewhere)
 */
#define _DARWIN_C_SOURCE
#include <stdio.h>

#ifdef __APPLE__
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int is_zombie(pid_t pid) {
  siginfo_t si;
  memset(&si, 0, sizeof si);
  return waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == pid;
}

static int wait_zombie(pid_t pid, int timeout_ms) {
  for (int i = 0; i < timeout_ms * 5; i++) {
    if (is_zombie(pid)) return 1;
    usleep(200);
  }
  return 0;
}

/* returns 0 on success, otherwise the errno reported for the registration */
static int register_exit(int kq, pid_t pid) {
  struct kevent change, out;
  struct timespec zero = {0, 0};
  EV_SET(&change, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ONESHOT | EV_RECEIPT, NOTE_EXIT, 0, NULL);
  int n = kevent(kq, &change, 1, &out, 1, &zero);
  if (n < 0) return errno;
  if (n == 1 && (out.flags & EV_ERROR)) return (int)out.data;
  return 0;
}

static int event_arrives(int kq, pid_t pid, int timeout_ms) {
  struct kevent ev;
  struct timespec ts = {timeout_ms / 1000, (long)(timeout_ms % 1000) * 1000000L};
  int n = kevent(kq, NULL, 0, &ev, 1, &ts);
  return n == 1 && ev.ident == (uintptr_t)pid && (ev.fflags & NOTE_EXIT) != 0;
}

static void trial_set(const char *label, int exited_before_register, int trials) {
  int registered = 0, reg_esrch = 0, reg_other = 0, delivered = 0;
  for (int i = 0; i < trials; i++) {
    pid_t p = fork();
    if (p == 0) {
      if (!exited_before_register) usleep(150000);
      _exit(0);
    }
    if (exited_before_register) wait_zombie(p, 1000);
    int kq = kqueue();
    int err = register_exit(kq, p);
    if (err == 0) {
      registered++;
      if (event_arrives(kq, p, exited_before_register ? 300 : 1500)) delivered++;
    } else if (err == ESRCH) {
      reg_esrch++;
    } else {
      reg_other++;
    }
    close(kq);
    int st;
    waitpid(p, &st, 0);
  }
  printf("{\"scenario\":\"kqueue_exit_registration\",\"case\":\"%s\",\"trials\":%d,\"registered_ok\":%d,"
         "\"registration_ESRCH\":%d,\"registration_other_error\":%d,\"event_delivered\":%d,"
         "\"registered_but_no_event\":%d}\n",
         label, trials, registered, reg_esrch, reg_other, delivered, registered - delivered);
  fflush(stdout);
}

/* The kit's 8-child case once got 7 events for 8 successful registrations. Crystal's runtime reaps children itself
 * (SIGCHLD -> waitpid(-1, WNOHANG)) while the program is registering and collecting, which kqueue_zombie never did.
 * Same pattern here: n children, each registered right after fork, then n events collected with a 2 s budget;
 * with and without a SIGCHLD handler that reaps concurrently, at the kit's exit delays and at tight ones. */
static volatile sig_atomic_t g_reaped;
static void reaper(int sig) {
  (void)sig;
  int saved = errno, st;
  while (waitpid(-1, &st, WNOHANG) > 0) g_reaped++;
  errno = saved;
}

static double mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void many_children(const char *label, int n, int concurrent_reap, int base_ms, int step_ms, int trials) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = concurrent_reap ? reaper : SIG_DFL;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGCHLD, &sa, NULL);
  int reg_ok = 0, reg_esrch = 0, reg_other = 0, events = 0, error_events = 0, other_events = 0, missing = 0, trials_missing = 0;
  char example[256] = "";
  for (int t = 0; t < trials; t++) {
    int kq = kqueue();
    pid_t pids[32];
    int registered[32], seen[32];
    for (int i = 0; i < n; i++) {
      pids[i] = fork();
      if (pids[i] == 0) {
        if (base_ms + i * step_ms > 0) usleep((useconds_t)(base_ms + i * step_ms) * 1000);
        _exit(i);
      }
      int e = register_exit(kq, pids[i]);
      registered[i] = e == 0;
      seen[i] = 0;
      if (e == 0) reg_ok++; else if (e == ESRCH) reg_esrch++; else reg_other++;
    }
    double deadline = mono_ms() + 2000;
    int want = 0;
    for (int i = 0; i < n; i++) want += registered[i];
    int got = 0;
    while (got < want && mono_ms() < deadline) {
      struct kevent ev[32];
      double left = deadline - mono_ms();
      struct timespec ts = {(time_t)(left / 1000), (long)((left - (time_t)(left / 1000) * 1000.0) * 1e6)};
      int r = kevent(kq, NULL, 0, ev, n, &ts);
      if (r < 0) { if (errno == EINTR) continue; break; }
      if (r == 0) break;
      for (int k = 0; k < r; k++) {
        if (ev[k].flags & EV_ERROR) { error_events++; continue; }
        if (!(ev[k].fflags & NOTE_EXIT)) { other_events++; continue; }
        events++;
        for (int i = 0; i < n; i++) if ((uintptr_t)pids[i] == ev[k].ident && !seen[i]) { seen[i] = 1; got++; }
      }
    }
    int miss_here = 0;
    for (int i = 0; i < n; i++) {
      if (registered[i] && !seen[i]) {
        miss_here++;
        if (!example[0]) {
          int st;
          pid_t w = waitpid(pids[i], &st, WNOHANG);
          snprintf(example, sizeof example, "trial %d child %d: waitpid(WNOHANG)=%d errno=%d (ECHILD means it was already reaped)", t, i, (int)w, w < 0 ? errno : 0);
        }
      }
    }
    missing += miss_here;
    if (miss_here) trials_missing++;
    close(kq);
    if (!concurrent_reap) for (int i = 0; i < n; i++) { int st; waitpid(pids[i], &st, 0); }
    else { double end = mono_ms() + 500; while (mono_ms() < end) { int st; if (waitpid(-1, &st, WNOHANG) < 0 && errno == ECHILD) break; usleep(1000); } }
  }
  sa.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &sa, NULL);
  printf("{\"scenario\":\"kqueue_many_children_one_queue\",\"case\":\"%s\",\"children\":%d,\"concurrent_reaper\":%s,\"exit_delays_ms\":\"%d+%d*i\","
         "\"trials\":%d,\"registered_ok\":%d,\"registration_ESRCH\":%d,\"registration_other_error\":%d,\"exit_events\":%d,"
         "\"error_events\":%d,\"other_events\":%d,\"registered_but_no_event\":%d,\"trials_with_a_missing_event\":%d,\"first_missing\":\"%s\"}\n",
         label, n, concurrent_reap ? "true" : "false", base_ms, step_ms, trials, reg_ok, reg_esrch, reg_other, events, error_events, other_events,
         missing, trials_missing, example);
  fflush(stdout);
}

int main(void) {
  trial_set("register_before_exit", 0, 100);
  trial_set("register_after_exit_zombie", 1, 200);
  many_children("kit_delays_no_reaper", 8, 0, 180, 25, 40);
  many_children("kit_delays_concurrent_reaper", 8, 1, 180, 25, 40);
  many_children("tight_delays_no_reaper", 8, 0, 2, 1, 300);
  many_children("tight_delays_concurrent_reaper", 8, 1, 2, 1, 300);
  many_children("immediate_exit_concurrent_reaper", 8, 1, 0, 0, 300);
  many_children("sixteen_tight_concurrent_reaper", 16, 1, 1, 1, 200);
  return 0;
}
#else
int main(void) {
  printf("{\"scenario\":\"kqueue_exit_registration\",\"skipped\":\"not macOS\"}\n");
  return 0;
}
#endif
