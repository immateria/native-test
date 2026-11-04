/*
 * Pipes and stdio between a supervisor and its child (macOS and Linux). JSON lines; never asserts.
 * Questions: how much a child can write before it blocks; the classic wait-before-read deadlock; what a child
 * sees when the supervisor closes its end (SIGPIPE vs EPIPE, also with SIGPIPE ignored as Crystal's children
 * inherit it); what happens when a child starts with descriptors 0-2 closed; and the shared-O_NONBLOCK trap.
 * Build: cc -O1 -Wall -Wextra -o pipes pipes.c
 */
#include "common.h"
#include <limits.h>

#define PROBE "pipes"

static const char *bstr(int b) { return b ? "true" : "false"; }

static char g_self[PATH_MAX];

/* write nonblocking until EAGAIN: the pipe's capacity for this write size */
static long capacity(int chunk) {
  int p[2];
  if (pipe(p)) return -1;
  fcntl(p[1], F_SETFL, O_NONBLOCK);
  char *b = calloc(1, (size_t)chunk);
  long total = 0;
  for (;;) {
    ssize_t n = write(p[1], b, (size_t)chunk);
    if (n <= 0) break;
    total += n;
    if (total > (64L << 20)) break;
  }
  free(b);
  close(p[0]); close(p[1]);
  return total;
}

static void exp_capacity(void) {
  long c1 = capacity(1), c512 = capacity(512), c4k = capacity(4096), c64k = capacity(65536);
#ifdef F_GETPIPE_SZ
  int p[2];
  (void)!pipe(p);
  int def = fcntl(p[0], F_GETPIPE_SZ);
  int grow = fcntl(p[0], F_SETPIPE_SZ, 1 << 20);
  int grow_e = grow < 0 ? errno : 0;
  int after = fcntl(p[0], F_GETPIPE_SZ);
  int huge = fcntl(p[0], F_SETPIPE_SZ, 64 << 20);
  int huge_e = huge < 0 ? errno : 0;
  close(p[0]); close(p[1]);
  char mx[32] = "";
  int fd = open("/proc/sys/fs/pipe-max-size", O_RDONLY);
  if (fd >= 0) { ssize_t r = read(fd, mx, sizeof mx - 1); mx[r > 0 ? r : 0] = 0; mx[strcspn(mx, "\n")] = 0; close(fd); }
  emit(PROBE, "capacity", "\"bytes_with_1_byte_writes\":%ld,\"with_512\":%ld,\"with_4096\":%ld,\"with_65536\":%ld,\"F_GETPIPE_SZ\":%d,"
       "\"F_SETPIPE_SZ_1MiB\":\"%s\",\"size_after\":%d,\"F_SETPIPE_SZ_64MiB\":\"%s\",\"pipe_max_size\":\"%s\"",
       c1, c512, c4k, c64k, def, grow < 0 ? errno_name(grow_e) : "OK", after, huge < 0 ? errno_name(huge_e) : "OK", mx);
#else
  emit(PROBE, "capacity", "\"bytes_with_1_byte_writes\":%ld,\"with_512\":%ld,\"with_4096\":%ld,\"with_65536\":%ld", c1, c512, c4k, c64k);
#endif
}

/* a child that writes `total` bytes to stdout in 4 KiB pieces, then exits 0 */
static int child_writer(long total) {
  char b[4096];
  memset(b, 'o', sizeof b);
  long done = 0;
  while (done < total) {
    ssize_t n = write(1, b, sizeof b);
    if (n < 0) return 10 + errno % 100;
    done += n;
  }
  return 0;
}

/* close_fd: the supervisor's read end, closed in the child unless we want to show the leak */
static pid_t spawn_writer(long total, int out_fd, int ignore_sigpipe, int close_fd) {
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) {
    if (close_fd >= 0) close(close_fd);
    /* explicit both ways: CI runners start every step with SIGPIPE already ignored */
    signal(SIGPIPE, ignore_sigpipe ? SIG_IGN : SIG_DFL);
    dup2(out_fd, 1);
    char t[32];
    snprintf(t, sizeof t, "%ld", total);
    execl(g_self, g_self, "--writer", t, (char *)NULL);
    _exit(127);
  }
  return p;
}

static void exp_blocked_writer_and_deadlock(void) {
  int p[2];
  (void)!pipe(p);
  pid_t c = spawn_writer(1 << 20, p[1], 0, p[0]);
  close(p[1]);
  /* the wait-before-read deadlock: the child cannot finish while nobody drains the pipe */
  int st = 0;
  pid_t r = waitpid_timeout(c, &st, 0, 1500);
  char state[8] = "?";
#ifdef __linux__
  char path[64], b[512];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)c);
  int fd = open(path, O_RDONLY);
  if (fd >= 0) { ssize_t n = read(fd, b, sizeof b - 1); b[n > 0 ? n : 0] = 0; char *rp = strrchr(b, ')'); if (rp) { state[0] = rp[2]; state[1] = 0; } close(fd); }
#endif
  /* now drain and let it finish */
  char buf[65536];
  long got = 0;
  double t0 = now_ms();
  for (;;) { ssize_t n = read(p[0], buf, sizeof buf); if (n <= 0) break; got += n; }
  char s2[64];
  reap_blocking(c, 3000, s2, sizeof s2);
  emit(PROBE, "child_writes_1MiB_while_supervisor_waits_first",
       "\"exited_within_1500ms_without_reading\":%s,\"child_state_while_blocked\":\"%s\",\"bytes_read_after\":%ld,\"ms_to_drain\":%.0f,\"status\":\"%s\"",
       bstr(r == c), state, got, now_ms() - t0, s2);
  close(p[0]);
}

static void exp_reader_closes(int ignore_sigpipe, int leak_read_end) {
  int p[2];
  (void)!pipe(p);
  pid_t c = spawn_writer(1 << 20, p[1], ignore_sigpipe, leak_read_end ? -1 : p[0]);
  close(p[1]);
  char buf[4096];
  (void)!read(p[0], buf, sizeof buf); /* the child is running and writing */
  close(p[0]);                        /* supervisor stops reading and closes */
  char st[64];
  reap_blocking(c, 2000, st, sizeof st);
  if (strcmp(st, "still_running") == 0) { kill(c, SIGKILL); char x[64]; reap_blocking(c, 2000, x, sizeof x); }
  emit(PROBE, leak_read_end ? "supervisor_closes_read_end_but_child_inherited_it" :
       ignore_sigpipe ? "supervisor_closes_read_end_child_ignores_sigpipe" : "supervisor_closes_read_end",
       "\"child_status_after_2s\":\"%s\",\"note\":\"exited(42) = write failed with EPIPE (10 + 32); still_running = blocked in write\"", st);
}

/* stdin: the supervisor closes the write end -> the child's read returns 0 */
static void exp_stdin_eof(void) {
  int p[2], r[2];
  (void)!pipe(p); (void)!pipe(r);
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) {
    close(p[1]); close(r[0]);
    char b[16];
    ssize_t n = read(p[0], b, sizeof b);
    char out[32];
    int k = snprintf(out, sizeof out, "%zd\n", n);
    (void)!write(r[1], out, (size_t)k);
    _exit(0);
  }
  close(p[0]); close(r[1]);
  sleep_ms(100);
  close(p[1]);
  char b[32] = "";
  ssize_t n = read_timeout(r[0], b, sizeof b - 1, 2000);
  b[n > 0 ? n : 0] = 0;
  b[strcspn(b, "\n")] = 0;
  char st[64];
  reap_blocking(c, 2000, st, sizeof st);
  emit(PROBE, "supervisor_closes_child_stdin", "\"child_read_returned\":\"%s\"", b);
  close(r[0]);
}

/* a child started with 0, 1, 2 closed: which descriptor does its first open() get, and where does "stdout" go? */
static int child_closed_stdio(const char *report_path) {
  int fd = open("/dev/null", O_RDONLY);
  int w1 = (int)write(1, "x", 1), e1 = w1 < 0 ? errno : 0;
  int w2 = (int)write(2, "x", 1), e2 = w2 < 0 ? errno : 0;
  int rp = open(report_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  char b[160];
  int n = snprintf(b, sizeof b, "first_open_fd=%d write1=%s write2=%s report_fd=%d\n", fd, w1 < 0 ? errno_name(e1) : "OK", w2 < 0 ? errno_name(e2) : "OK", rp);
  (void)!write(rp, b, (size_t)n);
  return 0;
}

static void exp_closed_stdio(void) {
  char rep[PATH_MAX];
  snprintf(rep, sizeof rep, "/tmp/pipes-closed-stdio-%d.txt", (int)getpid());
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) {
    close(0); close(1); close(2);
    execl(g_self, g_self, "--closed-stdio", rep, (char *)NULL);
    _exit(127);
  }
  char st[64];
  reap_blocking(c, 3000, st, sizeof st);
  char b[200] = "";
  int fd = open(rep, O_RDONLY);
  if (fd >= 0) { ssize_t n = read(fd, b, sizeof b - 1); b[n > 0 ? n : 0] = 0; b[strcspn(b, "\n")] = 0; close(fd); }
  unlink(rep);
  emit(PROBE, "child_started_with_0_1_2_closed", "\"status\":\"%s\",\"child_reported\":\"%s\"", st, b);
}

/* the shared open file description: O_NONBLOCK set by the supervisor on its copy also applies to the child's */
static void exp_shared_nonblock(void) {
  int p[2], r[2];
  (void)!pipe(p); (void)!pipe(r);
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) {
    close(p[1]); close(r[0]);
    sleep_ms(200); /* the supervisor sets O_NONBLOCK meanwhile */
    char b[8];
    ssize_t n = read(p[0], b, sizeof b);
    int e = n < 0 ? errno : 0;
    char out[64];
    int k = snprintf(out, sizeof out, "%zd %s\n", n, errno_name(e));
    (void)!write(r[1], out, (size_t)k);
    _exit(0);
  }
  close(r[1]);
  int fl = fcntl(p[0], F_GETFL);
  fcntl(p[0], F_SETFL, fl | O_NONBLOCK); /* the supervisor's copy of the child's stdin read end */
  char b[64] = "";
  ssize_t n = read_timeout(r[0], b, sizeof b - 1, 3000);
  b[n > 0 ? n : 0] = 0;
  b[strcspn(b, "\n")] = 0;
  char st[64];
  reap_blocking(c, 2000, st, sizeof st);
  emit(PROBE, "o_nonblock_on_supervisor_copy_affects_child", "\"child_read_on_empty_pipe\":\"%s\",\"note\":\"-1 EAGAIN = the flag was shared\"", b);
  close(p[0]); close(p[1]); close(r[0]);
}

/* a pipe write end inherited by a grandchild keeps EOF away until the grandchild closes it */
static void exp_eof_needs_every_writer(void) {
  int p[2];
  (void)!pipe(p);
  fflush(stdout);
  pid_t c = fork();
  if (c == 0) {
    close(p[0]);
    if (fork() == 0) { sleep_ms(600); _exit(0); } /* grandchild holds p[1] */
    _exit(0);
  }
  close(p[1]);
  waitpid(c, NULL, 0);
  double t0 = now_ms();
  char b[16];
  ssize_t n = read(p[0], b, sizeof b);
  emit(PROBE, "eof_waits_for_grandchild_holding_the_write_end", "\"read_returned\":%zd,\"ms_after_child_exit\":%.0f", n, now_ms() - t0);
  close(p[0]);
}

int main(int argc, char **argv) {
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  if (argc > 2 && strcmp(argv[1], "--writer") == 0) return child_writer(atol(argv[2]));
  if (argc > 2 && strcmp(argv[1], "--closed-stdio") == 0) return child_closed_stdio(argv[2]);
  watchdog(60);
  emit_header(PROBE);
  struct sigaction cur;
  sigaction(SIGPIPE, NULL, &cur);
  emit(PROBE, "inherited_sigpipe_disposition", "\"sigpipe\":\"%s\"", cur.sa_handler == SIG_IGN ? "ignored" : cur.sa_handler == SIG_DFL ? "default" : "handler");
  exp_capacity();
  exp_blocked_writer_and_deadlock();
  exp_reader_closes(0, 0);
  exp_reader_closes(1, 0);
  exp_reader_closes(0, 1);
  exp_stdin_eof();
  exp_closed_stdio();
  exp_shared_nonblock();
  exp_eof_needs_every_writer();
  return 0;
}
