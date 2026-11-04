/*
 * What happens to a stopped (or running) child when its supervisor exits or is killed?
 *
 * POSIX says that when a process group *becomes* orphaned (no member has a parent in another group of the
 * same session) and has a stopped member, every member gets SIGHUP and then SIGCONT. A supervisor that
 * stops children (SIGSTOP, job control) can therefore see them die or wake up when it crashes, depending on
 * session and group layout. The kit never tested this. Each variant records which signals a child received
 * (H = SIGHUP, c = SIGCONT), in order, and whether it survived (pipe EOF means it terminated).
 *
 * Build: cc -O1 -Wall -Wextra -o orphan_pgrp orphan_pgrp.c
 */
#include "common.h"
#define PROBE "orphan_pgrp"

static int g_fd = -1;
static void on_hup(int s) { (void)s; (void)!write(g_fd, "H", 1); }
static void on_cont(int s) { (void)s; (void)!write(g_fd, "c", 1); }

typedef struct {
  const char *name;
  int own_session;  /* supervisor calls setsid() (it is then a session leader) */
  int child_group;  /* 0: child shares the supervisor's (new) group; 1: child gets its own group */
  int stop_child;   /* child SIGSTOPs itself before the supervisor goes away */
  int hup_mode;     /* 0 default action, 1 handler, 2 ignored */
  int exit_mode;    /* 0 supervisor _exit(0), 1 supervisor SIGKILLed, 2 supervisor stays alive (control) */
} variant_t;

static void run_variant(const variant_t *v) {
  int ev[2], info[2];
  if (pipe(ev) != 0 || pipe(info) != 0) return;
  double t0 = now_ms();
  pid_t P = fork();
  if (P == 0) {
    close(ev[0]); close(info[0]);
    if (v->own_session) setsid();
    else if (!v->child_group) setpgid(0, 0);  /* otherwise the supervisor stays in the driver's group */
    else setpgid(0, 0);                       /* supervisor in its own group, child in yet another */
    pid_t C = fork();
    if (C == 0) {
      close(info[1]);
      if (v->child_group) setpgid(0, 0);
      g_fd = ev[1];
      struct sigaction sa;
      memset(&sa, 0, sizeof sa);
      sigemptyset(&sa.sa_mask);
      sa.sa_handler = on_cont;
      sigaction(SIGCONT, &sa, NULL);
      if (v->hup_mode == 1) { sa.sa_handler = on_hup; sigaction(SIGHUP, &sa, NULL); }
      else if (v->hup_mode == 2) { sa.sa_handler = SIG_IGN; sigaction(SIGHUP, &sa, NULL); }
      if (v->stop_child) raise(SIGSTOP);
      for (;;) pause();
    }
    int st = 0;
    if (v->stop_child) waitpid(C, &st, WUNTRACED);  /* returns once the child is stopped */
    else sleep_ms(200);                              /* let the handlers get installed */
    sleep_ms(50);
    (void)!write(info[1], &C, sizeof C);
    close(info[1]);
    close(ev[1]);
    if (v->exit_mode == 0) _exit(0);
    for (;;) pause();
  }
  close(ev[1]); close(info[1]);
  pid_t C = 0;
  ssize_t n = read_timeout(info[0], &C, sizeof C, 3000);
  if (n != (ssize_t)sizeof C) {
    emit(PROBE, v->name, "\"error\":\"no child pid\"");
    kill(P, SIGKILL); waitpid(P, NULL, 0);
    return;
  }
  double t_signal = now_ms();
  if (v->exit_mode == 1) kill(P, SIGKILL);
  char pst[64] = "";
  if (v->exit_mode != 2) reap_blocking(P, 2000, pst, sizeof pst);
  char letters[64];
  int eof = 0;
  drain_until(ev[0], letters, sizeof letters, v->exit_mode == 2 ? 600 : 800, &eof);
  double t_end = now_ms();
  pid_t pgrp_c = getpgid(C);
  int sess_c = (int)getsid(C);
  int alive_probe = kill(C, 0) == 0; /* pipe EOF comes before the reaper has collected the zombie */
  sleep_ms(150);
  int alive_later = kill(C, 0) == 0;
  emit(PROBE, v->name,
       "\"own_session\":%d,\"child_own_group\":%d,\"child_stopped\":%d,\"hup_mode\":\"%s\",\"supervisor_exit\":\"%s\","
       "\"supervisor_status\":\"%s\",\"letters\":\"%s\",\"child_terminated\":%s,\"kill0_succeeds_after\":%s,"
       "\"kill0_succeeds_150ms_later\":%s,\"child_pgrp_is_own_pid\":%s,\"child_session_same_as_driver\":%s,\"window_ms\":%.0f,\"setup_ms\":%.0f",
       v->own_session, v->child_group, v->stop_child, v->hup_mode == 0 ? "default" : v->hup_mode == 1 ? "handler" : "ignore",
       v->exit_mode == 0 ? "exit" : v->exit_mode == 1 ? "sigkill" : "alive", pst, letters, eof ? "true" : "false",
       alive_probe ? "true" : "false", alive_later ? "true" : "false", pgrp_c == C ? "true" : "false", sess_c == (int)getsid(0) ? "true" : "false",
       t_end - t_signal, t_signal - t0);
  kill(C, SIGKILL);
  if (v->exit_mode == 2) { kill(P, SIGKILL); reap_blocking(P, 1000, pst, sizeof pst); }
  close(ev[0]); close(info[0]);
}

int main(void) {
  watchdog(120);
  emit_header(PROBE);
  /* name, own_session, child_group, stop_child, hup_mode, exit_mode */
  static const variant_t vs[] = {
    {"stopped_child_handler_supervisor_exits",       0, 0, 1, 1, 0},
    {"stopped_child_handler_supervisor_sigkilled",   0, 0, 1, 1, 1},
    {"stopped_child_default_hup_supervisor_exits",   0, 0, 1, 0, 0},
    {"stopped_child_hup_ignored_supervisor_exits",   0, 0, 1, 2, 0},
    {"running_child_handler_supervisor_exits",       0, 0, 0, 1, 0},
    {"stopped_child_handler_supervisor_alive",       0, 0, 1, 1, 2},
    {"stopped_child_own_group_supervisor_exits",     0, 1, 1, 1, 0},
    {"stopped_child_own_group_supervisor_sigkilled", 0, 1, 1, 1, 1},
    {"supervisor_is_session_leader_exits",           1, 0, 1, 1, 0},
    {"supervisor_session_leader_child_own_group",    1, 1, 1, 1, 0},
  };
  for (size_t i = 0; i < sizeof vs / sizeof vs[0]; i++) run_variant(&vs[i]);
  return 0;
}
