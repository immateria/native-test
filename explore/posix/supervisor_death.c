/*
 * How can a child find out that its supervisor died, and what happens to it meanwhile?
 *
 * The supervisor S forks a child C (own process group) which forks a grandchild G. The driver SIGKILLs S.
 * C then measures, against the driver's kill instant (CLOCK_MONOTONIC is system-wide), when each detection
 * mechanism fires: EOF on a "lifeline" pipe whose write end only S holds, getppid() changing, a kqueue
 * EVFILT_PROC/NOTE_EXIT watch on S (macOS) or pidfd_open + poll (Linux), and PR_SET_PDEATHSIG (Linux).
 * It also records whether C and G keep running and who adopts them. Nothing in the kit tested this.
 *
 * Build: cc -O1 -Wall -Wextra -o supervisor_death supervisor_death.c
 */
#include "common.h"
#ifdef __APPLE__
#include <sys/event.h>
#endif
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif
#define PROBE "supervisor_death"

typedef struct {
  pid_t c, g;
  int mech_errno_kq;  /* registration errno of the kqueue watch (macOS) / pidfd_open (Linux) */
} ready_t;

typedef struct {
  double lifeline, ppid, watch, pdeathsig; /* ms of CLOCK_MONOTONIC, or -1 when never observed */
  int ppid_after;
  int sess_same_as_s;
} result_t;

static volatile double g_pdeath = -1;
#ifdef __linux__
static void on_usr1(int s) { (void)s; g_pdeath = now_ms(); }
#endif

static void child_main(pid_t S, int lifeline_r, int report_w) {
  ready_t rd;
  memset(&rd, 0, sizeof rd);
  rd.c = getpid();
  int watch_fd = -1;
#ifdef __APPLE__
  watch_fd = kqueue();
  struct kevent ch, out;
  struct timespec zero = {0, 0};
  EV_SET(&ch, (uintptr_t)S, EVFILT_PROC, EV_ADD | EV_ONESHOT | EV_RECEIPT, NOTE_EXIT, 0, NULL);
  int n = kevent(watch_fd, &ch, 1, &out, 1, &zero);
  rd.mech_errno_kq = n < 0 ? errno : (n == 1 && (out.flags & EV_ERROR)) ? (int)out.data : 0;
#endif
#ifdef __linux__
  watch_fd = (int)syscall(SYS_pidfd_open, S, 0);
  rd.mech_errno_kq = watch_fd < 0 ? errno : 0;
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1;
  sigaction(SIGUSR1, &sa, NULL);
  prctl(PR_SET_PDEATHSIG, SIGUSR1);
#endif
  pid_t G = fork();
  if (G == 0) {
    close(report_w);
    for (;;) pause();
  }
  rd.g = G;
  (void)!write(report_w, &rd, sizeof rd);
  result_t r = {-1, -1, -1, -1, 0, 0};
  double end = now_ms() + 3000;
  while (now_ms() < end && (r.lifeline < 0 || r.ppid < 0 || r.watch < 0)) {
    if (r.lifeline < 0) {
      struct pollfd p = {lifeline_r, POLLIN, 0};
      if (poll(&p, 1, 0) > 0 && (p.revents & (POLLIN | POLLHUP))) r.lifeline = now_ms();
    }
    if (r.ppid < 0 && getppid() != S) { r.ppid = now_ms(); r.ppid_after = (int)getppid(); }
    if (r.watch < 0 && watch_fd >= 0) {
#ifdef __APPLE__
      struct kevent ev;
      if (kevent(watch_fd, NULL, 0, &ev, 1, &zero) == 1 && ev.ident == (uintptr_t)S) r.watch = now_ms();
#else
      struct pollfd p = {watch_fd, POLLIN, 0};
      if (poll(&p, 1, 0) > 0) r.watch = now_ms();
#endif
    }
    usleep(100);
  }
  sleep_ms(50); /* give a pending PDEATHSIG a moment */
  r.pdeathsig = g_pdeath;
  if (r.ppid < 0) r.ppid_after = (int)getppid();
  (void)!write(report_w, &r, sizeof r);
  for (;;) pause();
}

int main(void) {
  watchdog(60);
  emit_header(PROBE);
  int lifeline[2], report[2], go[2];
  if (pipe(lifeline) != 0 || pipe(report) != 0 || pipe(go) != 0) return 1;
  pid_t S = fork();
  if (S == 0) {
    close(report[0]);
    setpgid(0, 0);
    pid_t C = fork();
    if (C == 0) {
      close(lifeline[1]); /* only S keeps the write end */
      setpgid(0, 0);
      child_main(getppid(), lifeline[0], report[1]);
    }
    close(report[1]);
    close(lifeline[0]);
    for (;;) pause();
  }
  close(report[1]); close(lifeline[0]); close(lifeline[1]);
  ready_t rd;
  if (read_timeout(report[0], &rd, sizeof rd, 5000) != (ssize_t)sizeof rd) {
    emit(PROBE, "setup", "\"error\":\"child not ready\"");
    kill(S, SIGKILL);
    return 0;
  }
  sleep_ms(100);
  pid_t pgrp_c = getpgid(rd.c);
  double t_kill = now_ms();
  kill(S, SIGKILL);
  char st[64];
  reap_blocking(S, 2000, st, sizeof st);
  result_t r;
  ssize_t n = read_timeout(report[0], &r, sizeof r, 6000);
  if (n != (ssize_t)sizeof r) {
    emit(PROBE, "supervisor_sigkilled", "\"error\":\"no result\"");
  } else {
    int c_alive = kill(rd.c, 0) == 0, g_alive = kill(rd.g, 0) == 0;
    emit(PROBE, "supervisor_sigkilled",
         "\"supervisor_status\":\"%s\",\"watch_registration_errno\":\"%s\",\"watch_mechanism\":\"%s\","
         "\"lifeline_eof_ms\":%.2f,\"getppid_changed_ms\":%.2f,\"watch_fired_ms\":%.2f,\"pdeathsig_ms\":%.2f,"
         "\"ppid_after\":%d,\"child_signalable\":%s,\"grandchild_signalable\":%s,\"child_pgrp_is_own_pid\":%s",
         st, errno_name(rd.mech_errno_kq),
#ifdef __APPLE__
         "kqueue EVFILT_PROC NOTE_EXIT on the supervisor",
#else
         "pidfd_open + poll on the supervisor",
#endif
         r.lifeline < 0 ? -1.0 : r.lifeline - t_kill, r.ppid < 0 ? -1.0 : r.ppid - t_kill,
         r.watch < 0 ? -1.0 : r.watch - t_kill, r.pdeathsig < 0 ? -1.0 : r.pdeathsig - t_kill, r.ppid_after,
         c_alive ? "true" : "false", g_alive ? "true" : "false", pgrp_c == rd.c ? "true" : "false");
  }
  kill(-pgrp_c, SIGKILL);
  kill(rd.c, SIGKILL);
  kill(rd.g, SIGKILL);
  return 0;
}
