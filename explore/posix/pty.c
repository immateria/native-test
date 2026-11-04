/*
 * Pseudo-terminals and job control: the "supervisor behind a terminal" half of process supervision.
 * A forkpty() child is a session leader with a controlling terminal. It forks a foreground group member F,
 * a background member B and a background member BS that has stopped itself. The driver (the pty master)
 * then (1) makes a background process read and write the terminal (SIGTTIN / SIGTTOU, with and without
 * TOSTOP), (2) resizes the window (SIGWINCH), and (3) closes the master, i.e. hangs the terminal up,
 * recording which of them gets SIGHUP and SIGCONT (letters: L leader, F foreground, B background,
 * S stopped background; lower case = SIGCONT) and which survive. Nothing in the kit used a pty.
 *
 * Build: cc -O1 -Wall -Wextra -o pty pty.c -lutil     (macOS: no -lutil needed)
 */
#include "common.h"
#include <sys/ioctl.h>
#include <termios.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif
#define PROBE "pty"

static int g_rep = -1;
static char g_who = '?';
static void on_hup(int s) { (void)s; char c = g_who; (void)!write(g_rep, &c, 1); }
static void on_cont(int s) { (void)s; char c = (char)(g_who + 32); (void)!write(g_rep, &c, 1); }
static void on_winch(int s) {
  (void)s;
  char c = g_who == 'L' ? '1' : g_who == 'F' ? '2' : g_who == 'B' ? '3' : '4';
  (void)!write(g_rep, &c, 1);
}

static void install(char who, int rep) {
  g_rep = rep; g_who = who;
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = on_hup; sigaction(SIGHUP, &sa, NULL);
  sa.sa_handler = on_cont; sigaction(SIGCONT, &sa, NULL);
  sa.sa_handler = on_winch; sigaction(SIGWINCH, &sa, NULL);
}

typedef struct { pid_t leader, f, b, bs, tty_reader, tty_writer; } pids_t;

static void member_main(char who, int rep) {
  install(who, rep);
  if (who == 'S') raise(SIGSTOP);
  for (;;) pause();
}

/* runs inside the forkpty child (session leader) */
static void leader_main(int rep, int cmd_r) {
  install('L', rep);
  pids_t pd;
  memset(&pd, 0, sizeof pd);
  pd.leader = getpid();
  signal(SIGTTOU, SIG_IGN); /* so the leader itself may call tcsetpgrp */
  pid_t kids[3];
  const char who[3] = {'F', 'B', 'S'};
  for (int i = 0; i < 3; i++) {
    kids[i] = fork();
    if (kids[i] == 0) {
      setpgid(0, 0);
      member_main(who[i], rep); /* the leader (which ignores SIGTTOU) makes F the foreground group */
    }
    setpgid(kids[i], kids[i]);
  }
  pd.f = kids[0]; pd.b = kids[1]; pd.bs = kids[2];
  int st;
  waitpid(pd.bs, &st, WUNTRACED); /* S is stopped now */
  sleep_ms(50);
  tcsetpgrp(0, pd.f);
  /* report pids and the terminal's foreground group as seen by the leader */
  char line[256];
  int n = snprintf(line, sizeof line, "P %d %d %d %d fg=%d\n", (int)pd.leader, (int)pd.f, (int)pd.b, (int)pd.bs, (int)tcgetpgrp(0));
  (void)!write(rep, line, (size_t)n);
  /* commands from the driver over a plain pipe: 'i' = spawn a background reader, 'o' = background writer, 'x' = quit */
  for (;;) {
    char c;
    ssize_t r = read(cmd_r, &c, 1);
    if (r < 0 && errno == EINTR) continue; /* a signal handler ran */
    if (r <= 0) { pause(); continue; }
    if (c == 'i' || c == 'o' || c == 'O') {
      pid_t p = fork();
      if (p == 0) {
        signal(SIGTTOU, SIG_DFL);
        setpgid(0, 0);
        if (c == 'O') {
          struct termios t;
          tcgetattr(0, &t);
          t.c_lflag |= TOSTOP;
          struct sigaction ign;
          memset(&ign, 0, sizeof ign);
          ign.sa_handler = SIG_IGN;
          sigaction(SIGTTOU, &ign, NULL); /* the set below is itself a background op; allow it */
          tcsetattr(0, TCSANOW, &t);
          signal(SIGTTOU, SIG_DFL);
        }
        char buf[8];
        if (c == 'i') { ssize_t k = read(0, buf, sizeof buf); (void)k; }
        else { ssize_t k = write(1, "x", 1); (void)k; }
        _exit(0);
      }
      setpgid(p, p);
      int s2 = 0;
      pid_t w = waitpid_timeout(p, &s2, WUNTRACED, 1000);
      char t[64] = "none";
      if (w > 0) status_text(s2, t, sizeof t);
      kill(p, SIGKILL);
      waitpid(p, NULL, 0);
      n = snprintf(line, sizeof line, "R %c %s\n", c, t);
      (void)!write(rep, line, (size_t)n);
    } else if (c == 'x') {
      _exit(0);
    }
  }
}

int main(void) {
  watchdog(60);
  emit_header(PROBE);
  int rep[2], cmd[2];
  if (pipe(rep) != 0 || pipe(cmd) != 0) return 1;
  int master = -1;
  struct winsize ws = {24, 80, 0, 0};
  fflush(stdout);
  pid_t leader = forkpty(&master, NULL, NULL, &ws);
  if (leader < 0) {
    emit(PROBE, "forkpty", "\"error\":\"%s\"", errno_name(errno));
    return 0;
  }
  if (leader == 0) {
    close(rep[0]); close(cmd[1]);
    leader_main(rep[1], cmd[0]);
    _exit(0);
  }
  close(rep[1]); close(cmd[0]);
  char buf[512];
  int eof;
  drain_until(rep[0], buf, sizeof buf, 1500, &eof);
  pid_t f = 0, b = 0, s = 0, ldr = 0;
  int fg = 0;
  char *pl = strstr(buf, "P ");
  if (pl) sscanf(pl, "P %d %d %d %d fg=%d", (int *)&ldr, (int *)&f, (int *)&b, (int *)&s, &fg);
  emit(PROBE, "layout",
       "\"leader_is_session_leader\":%s,\"leader_has_controlling_tty\":%s,\"foreground_pgrp_is_F\":%s,\"B_pgrp_is_own\":%s,\"S_pgrp_is_own\":%s",
       getsid(ldr) == ldr ? "true" : "false", ioctl(master, TIOCGPGRP, &fg) == 0 ? "true" : "false", fg == f ? "true" : "false",
       getpgid(b) == b ? "true" : "false", getpgid(s) == s ? "true" : "false");

  /* window size: the master resizes, the foreground process group gets SIGWINCH */
  struct winsize nw = {40, 100, 0, 0};
  ioctl(master, TIOCSWINSZ, &nw);
  char wbuf[64];
  drain_until(rep[0], wbuf, sizeof wbuf, 300, &eof);
  emit(PROBE, "window_resize_signal_recipients", "\"digits_received\":\"%s\",\"meaning\":\"1 leader, 2 foreground, 3 background, 4 stopped background: whose SIGWINCH handler ran\"", wbuf);

  /* background read / write */
  char rb[128];
  (void)!write(cmd[1], "i", 1);
  drain_until(rep[0], rb, sizeof rb, 2500, &eof);
  char *rr = strstr(rb, "R i");
  emit(PROBE, "background_process_reads_terminal", "\"result\":\"%s\"", rr ? strtok(rr + 4, "\n") : "no report");
  (void)!write(cmd[1], "o", 1);
  drain_until(rep[0], rb, sizeof rb, 2500, &eof);
  rr = strstr(rb, "R o");
  emit(PROBE, "background_process_writes_terminal_without_tostop", "\"result\":\"%s\"", rr ? strtok(rr + 4, "\n") : "no report");
  (void)!write(cmd[1], "O", 1);
  drain_until(rep[0], rb, sizeof rb, 2500, &eof);
  rr = strstr(rb, "R O");
  emit(PROBE, "background_process_writes_terminal_with_tostop", "\"result\":\"%s\"", rr ? strtok(rr + 4, "\n") : "no report");

  /* hang up: close the master */
  char drain[64];
  (void)!read(master, drain, 0);
  double t0 = now_ms();
  close(master);
  char hb[64];
  drain_until(rep[0], hb, sizeof hb, 1200, &eof);
  int leader_gone = waitpid_timeout(leader, NULL, WNOHANG, 100) > 0;
  emit(PROBE, "master_closed_signals_received",
       "\"letters\":\"%s\",\"legend\":\"L leader,F foreground,B background,S stopped background; lower case = SIGCONT\",\"window_ms\":%.0f,"
       "\"F_alive_signalable\":%s,\"B_alive_signalable\":%s,\"S_alive_signalable\":%s,\"leader_reaped_by_driver\":%s",
       hb, now_ms() - t0, kill(f, 0) == 0 ? "true" : "false", kill(b, 0) == 0 ? "true" : "false", kill(s, 0) == 0 ? "true" : "false",
       leader_gone ? "true" : "false");
  /* phase 2: the session leader now exits; the terminal is already hung up */
  (void)!write(cmd[1], "x", 1);
  double t1 = now_ms();
  char hb2[64];
  drain_until(rep[0], hb2, sizeof hb2, 1500, &eof);
  int leader_exited = waitpid_timeout(leader, NULL, 0, 500) > 0;
  emit(PROBE, "session_leader_exits_after_hangup",
       "\"letters\":\"%s\",\"leader_exited\":%s,\"window_ms\":%.0f,\"F_still_signalable\":%s,\"B_still_signalable\":%s,\"S_still_signalable\":%s",
       hb2, leader_exited ? "true" : "false", now_ms() - t1, kill(f, 0) == 0 ? "true" : "false", kill(b, 0) == 0 ? "true" : "false",
       kill(s, 0) == 0 ? "true" : "false");
  kill(f, SIGKILL); kill(b, SIGKILL); kill(s, SIGKILL); kill(leader, SIGKILL);
  return 0;
}
