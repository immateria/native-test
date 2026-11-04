/*
 * SIGSTOP / SIGCONT / SIGCHLD behaviour a supervisor depends on: how a stop and a continue are reported by
 * wait, what a termination signal does to a *stopped* child, whether killpg needs a SIGCONT, which si_code
 * values SIGCHLD carries, whether simultaneous exits coalesce into one SIGCHLD, and what SIG_IGN /
 * SA_NOCLDWAIT do to wait. The kit has one stop/continue case and no SIGCHLD cases.
 *
 * Build: cc -O1 -Wall -Wextra -o stopcont_chld stopcont_chld.c
 */
#include "common.h"
#define PROBE "stopcont_chld"

static int g_ev = -1;
static void on_term(int s) { (void)s; (void)!write(g_ev, "T", 1); }
static void on_cont(int s) { (void)s; (void)!write(g_ev, "c", 1); }

/* idle child; with handler_mode 1 it records SIGTERM ("T") and SIGCONT ("c") handler runs in order on ev[1] */
static pid_t spawn_idle(int handler_mode, int ev_w, pid_t pgid) {
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) {
    setpgid(0, pgid);
    g_ev = ev_w;
    if (handler_mode) {
      struct sigaction sa;
      memset(&sa, 0, sizeof sa);
      sigemptyset(&sa.sa_mask);
      sa.sa_handler = on_term; sigaction(SIGTERM, &sa, NULL);
      sa.sa_handler = on_cont; sigaction(SIGCONT, &sa, NULL);
    }
    for (;;) pause();
  }
  setpgid(p, pgid);
  return p;
}

static void wait_stopped(pid_t p) { int st; waitpid_timeout(p, &st, WUNTRACED, 2000); }

static void case_wait_statuses(void) {
  pid_t p = spawn_idle(0, -1, 0);
  sleep_ms(50);
  char s1[64] = "", s2[64] = "", s3[64] = "", s4[64] = "";
  int st;
  kill(p, SIGSTOP);
  pid_t r = waitpid_timeout(p, &st, WUNTRACED, 2000);
  if (r > 0) status_text(st, s1, sizeof s1); else snprintf(s1, sizeof s1, "none");
  r = waitpid(p, &st, WUNTRACED | WNOHANG);
  if (r > 0) status_text(st, s2, sizeof s2); else snprintf(s2, sizeof s2, r == 0 ? "nothing_new" : "error");
  kill(p, SIGCONT);
  r = waitpid_timeout(p, &st, WCONTINUED, 2000);
  if (r > 0) status_text(st, s3, sizeof s3); else snprintf(s3, sizeof s3, "none");
  kill(p, SIGTSTP);
  r = waitpid_timeout(p, &st, WUNTRACED, 2000);
  if (r > 0) status_text(st, s4, sizeof s4); else snprintf(s4, sizeof s4, "none");
  emit(PROBE, "wait_reports_stop_and_continue",
       "\"after_SIGSTOP\":\"%s\",\"second_wait_untraced_nohang\":\"%s\",\"after_SIGCONT_wcontinued\":\"%s\",\"after_SIGTSTP\":\"%s\"", s1, s2, s3, s4);
  kill(p, SIGKILL);
  waitpid(p, NULL, 0);
}

static void case_signal_to_stopped(int handler_mode, const char *kase) {
  int ev[2];
  if (pipe(ev) != 0) return;
  pid_t p = spawn_idle(handler_mode, ev[1], 0);
  close(ev[1]);
  sleep_ms(60);
  kill(p, SIGSTOP);
  wait_stopped(p);
  double t0 = now_ms();
  kill(p, SIGTERM);
  int st = 0;
  pid_t r = waitpid_timeout(p, &st, WNOHANG | WUNTRACED, 400);
  char after_term[64] = "";
  if (r > 0) status_text(st, after_term, sizeof after_term); else snprintf(after_term, sizeof after_term, "no_change_in_400ms");
  char letters[32];
  int eof;
  drain_until(ev[0], letters, sizeof letters, 50, &eof);
  char letters_after_term[32];
  snprintf(letters_after_term, sizeof letters_after_term, "%s", letters);
  double t_cont = now_ms();
  kill(p, SIGCONT);
  char after_cont[64] = "";
  if (handler_mode) {
    sleep_ms(200);
    drain_until(ev[0], letters, sizeof letters, 100, &eof);
    snprintf(after_cont, sizeof after_cont, "handlers_ran(%s)", letters);
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
  } else {
    r = waitpid_timeout(p, &st, 0, 1500);
    if (r > 0) status_text(st, after_cont, sizeof after_cont); else snprintf(after_cont, sizeof after_cont, "still_running");
  }
  emit(PROBE, kase,
       "\"handler\":%s,\"state_400ms_after_SIGTERM_to_stopped_child\":\"%s\",\"handler_letters_before_SIGCONT\":\"%s\","
       "\"after_SIGCONT\":\"%s\"",
       handler_mode ? "true" : "false", after_term, letters_after_term, after_cont);
  (void)t0; (void)t_cont;
  close(ev[0]);
}

static void case_kill_stopped(void) {
  pid_t p = spawn_idle(0, -1, 0);
  sleep_ms(50);
  kill(p, SIGSTOP);
  wait_stopped(p);
  double t = now_ms();
  kill(p, SIGKILL);
  char st[64];
  reap_blocking(p, 2000, st, sizeof st);
  emit(PROBE, "sigkill_to_stopped_child", "\"status\":\"%s\",\"ms_to_reap\":%.1f", st, now_ms() - t);
}

static void case_group(void) {
  /* three children in one group, all stopped */
  pid_t a = spawn_idle(0, -1, 0);
  pid_t b = spawn_idle(0, -1, a);
  pid_t c = spawn_idle(0, -1, a);
  sleep_ms(60);
  killpg(a, SIGSTOP);
  wait_stopped(a); wait_stopped(b); wait_stopped(c);
  int rc_term = killpg(a, SIGTERM);
  sleep_ms(300);
  int st, alive_after_term = 0;
  pid_t kids[3] = {a, b, c};
  for (int i = 0; i < 3; i++) if (waitpid(kids[i], &st, WNOHANG) == 0) alive_after_term++;
  int rc_cont = killpg(a, SIGCONT);
  sleep_ms(300);
  int alive_after_cont = 0;
  for (int i = 0; i < 3; i++) {
    pid_t r = waitpid(kids[i], &st, WNOHANG);
    if (r == 0) alive_after_cont++;
  }
  emit(PROBE, "killpg_term_to_stopped_group",
       "\"killpg_term_rc\":%d,\"still_alive_300ms_after_term\":%d,\"killpg_cont_rc\":%d,\"still_alive_300ms_after_cont\":%d",
       rc_term, alive_after_term, rc_cont, alive_after_cont);
  killpg(a, SIGKILL);
  for (int i = 0; i < 3; i++) waitpid(kids[i], NULL, 0);
}

/* ---- SIGCHLD ---- */
#define MAXREC 64
static volatile sig_atomic_t g_n = 0;
static volatile int g_code[MAXREC], g_status[MAXREC];
static void on_chld(int s, siginfo_t *si, void *u) {
  (void)s; (void)u;
  int i = g_n;
  if (i < MAXREC) { g_code[i] = si->si_code; g_status[i] = si->si_status; }
  g_n = i + 1;
}
static const char *cld_name(int c) {
  switch (c) {
    case CLD_EXITED: return "CLD_EXITED";
    case CLD_KILLED: return "CLD_KILLED";
    case CLD_DUMPED: return "CLD_DUMPED";
    case CLD_TRAPPED: return "CLD_TRAPPED";
    case CLD_STOPPED: return "CLD_STOPPED";
    case CLD_CONTINUED: return "CLD_CONTINUED";
    default: return "other";
  }
}

static void install_chld(int flags) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = on_chld;
  sa.sa_flags = SA_SIGINFO | flags;
  sigaction(SIGCHLD, &sa, NULL);
  g_n = 0;
}

static void restore_chld(void) { signal(SIGCHLD, SIG_DFL); }

static void case_sigchld_codes(int flags, const char *kase) {
  install_chld(flags);
  pid_t p = spawn_idle(0, -1, 0);
  sleep_ms(50);
  kill(p, SIGSTOP); sleep_ms(120);
  kill(p, SIGCONT); sleep_ms(120);
  kill(p, SIGTERM); sleep_ms(150);
  int st;
  waitpid(p, &st, 0);
  sleep_ms(30);
  char seq[512] = "";
  size_t len = 0;
  for (int i = 0; i < g_n && i < MAXREC; i++)
    len += (size_t)snprintf(seq + len, sizeof seq - len, "%s%s", i ? "," : "", cld_name(g_code[i]));
  emit(PROBE, kase, "\"handler_calls\":%d,\"si_code_sequence\":\"%s\",\"flags\":\"%s\"", (int)g_n, seq, flags & SA_NOCLDSTOP ? "SA_NOCLDSTOP" : "none");
  restore_chld();
}

static void case_sigchld_coalesce(void) {
  install_chld(0);
  int gate[2];
  if (pipe(gate) != 0) return;
  enum { N = 12 };
  pid_t kids[N];
  for (int i = 0; i < N; i++) {
    fflush(stdout);
    kids[i] = fork();
    if (kids[i] == 0) {
      close(gate[1]);
      char c;
      (void)!read(gate[0], &c, 1); /* EOF when the parent closes its end: all children exit together */
      _exit(i);
    }
  }
  close(gate[0]);
  sleep_ms(100);
  close(gate[1]);
  sleep_ms(500);
  int calls = g_n;
  int reaped = 0, st;
  while (waitpid(-1, &st, WNOHANG) > 0) reaped++;
  emit(PROBE, "sigchld_coalescing_12_simultaneous_exits", "\"children\":%d,\"sigchld_handler_calls\":%d,\"reaped_by_one_waitpid_loop\":%d", (int)N, calls, reaped);
  restore_chld();
}

static void case_sigchld_ignored(int nocldwait, const char *kase) {
  if (nocldwait) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &sa, NULL);
  } else {
    signal(SIGCHLD, SIG_IGN);
  }
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) _exit(7);
  sleep_ms(200);
  int st = 0;
  errno = 0;
  pid_t r = waitpid(p, &st, WNOHANG);
  int e = errno;
  char stt[64] = "";
  if (r > 0) status_text(st, stt, sizeof stt);
  int zombie_visible = 0;
  siginfo_t si;
  memset(&si, 0, sizeof si);
  if (waitid(P_PID, (id_t)p, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == p) zombie_visible = 1;
  emit(PROBE, kase, "\"waitpid_result\":%d,\"waitpid_errno\":\"%s\",\"status\":\"%s\",\"zombie_still_visible_to_waitid\":%s",
       (int)(r > 0 ? 1 : r), r < 0 ? errno_name(e) : "n/a", stt, zombie_visible ? "true" : "false");
  restore_chld();
}

int main(void) {
  watchdog(120);
  emit_header(PROBE);
  case_wait_statuses();
  case_signal_to_stopped(0, "sigterm_to_stopped_child_default_action");
  case_signal_to_stopped(1, "sigterm_to_stopped_child_with_handler");
  case_kill_stopped();
  case_group();
  case_sigchld_codes(0, "sigchld_si_codes_for_stop_continue_kill");
  case_sigchld_codes(SA_NOCLDSTOP, "sigchld_si_codes_with_nocldstop");
  case_sigchld_coalesce();
  case_sigchld_ignored(0, "sigchld_sig_ign_children_are_autoreaped");
  case_sigchld_ignored(1, "sigchld_sa_nocldwait_children_are_autoreaped");
  return 0;
}
