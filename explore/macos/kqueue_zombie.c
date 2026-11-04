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

int main(void) {
  trial_set("register_before_exit", 0, 100);
  trial_set("register_after_exit_zombie", 1, 200);
  return 0;
}
#else
int main(void) {
  printf("{\"scenario\":\"kqueue_exit_registration\",\"skipped\":\"not macOS\"}\n");
  return 0;
}
#endif
