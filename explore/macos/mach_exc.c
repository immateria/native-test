/*
 * Mach exception ports and crash timing on macOS. Whoever holds a task's EXC_BAD_ACCESS exception port (a debugger,
 * an in-process crash reporter) receives the exception before any Unix signal exists; while it keeps the message
 * unanswered, the faulting thread waits in the kernel. What does that do to the supervisor's waitpid, and do SIGTERM
 * and SIGKILL still end the process while the exception is held?
 *
 *   baseline_no_handler                    null dereference, nobody on the task's exception port
 *   handler_replies_failure_after_<N>ms    an in-process handler thread receives the exception, holds it N ms and
 *                                          replies KERN_FAILURE, so the kernel falls back to the Unix signal
 *   handler_never_replies_<SIG>_after_300ms  the handler keeps the message; the parent sends SIG 300 ms after the
 *                                          fault (SIGTERM is escalated to SIGKILL after 3 s)
 *
 * The child reports monotonic timestamps on a pipe: F (just before the fault), R (handler received the exception),
 * S (handler sent its reply). CLOCK_MONOTONIC is system-wide, so they compare with the parent's clock.
 *
 * Build: cc -O1 -Wall -Wextra -pthread -o mach_exc mach_exc.c
 */
#include "../posix/common.h"
#include <mach/mach.h>
#include <mach/ndr.h>
#include <pthread.h>
#define PROBE "mach_exc"

typedef struct { double t; int32_t tag; int32_t value; } rec_t;
typedef struct { mach_msg_header_t head; char body[4096]; } exc_req_t;
typedef struct { mach_msg_header_t head; NDR_record_t ndr; kern_return_t ret; } exc_reply_t;

static mach_port_t g_port = MACH_PORT_NULL;
static int g_fd = -1, g_hold_ms, g_reply;

static void put(char tag, double t, int value) {
  rec_t r = {t, tag, value};
  (void)!write(g_fd, &r, sizeof r);
}

static void *server(void *a) {
  (void)a;
  exc_req_t req;
  memset(&req, 0, sizeof req);
  kern_return_t kr = mach_msg(&req.head, MACH_RCV_MSG | MACH_RCV_LARGE, 0, sizeof req, g_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  put(kr == KERN_SUCCESS ? 'R' : 'E', now_ms(), kr == KERN_SUCCESS ? (int)req.head.msgh_id : (int)kr);
  if (kr != KERN_SUCCESS || !g_reply) for (;;) pause();
  if (g_hold_ms > 0) sleep_ms(g_hold_ms);
  /* the MIG reply for mach_exception_raise: header, NDR record, return code; id = request id + 100 */
  exc_reply_t rep;
  memset(&rep, 0, sizeof rep);
  rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.head.msgh_bits), 0);
  rep.head.msgh_remote_port = req.head.msgh_remote_port;
  rep.head.msgh_local_port = MACH_PORT_NULL;
  rep.head.msgh_size = sizeof rep;
  rep.head.msgh_id = req.head.msgh_id + 100;
  rep.ndr = NDR_record;
  rep.ret = KERN_FAILURE;
  put('S', now_ms(), 0);
  kern_return_t sk = mach_msg(&rep.head, MACH_SEND_MSG, sizeof rep, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  if (sk != KERN_SUCCESS) put('X', now_ms(), (int)sk);
  for (;;) pause();
  return NULL;
}

static void child(int fd, int handler, int hold_ms, int reply) {
  g_fd = fd;
  g_hold_ms = hold_ms;
  g_reply = reply;
  signal(SIGSEGV, SIG_DFL);
  signal(SIGBUS, SIG_DFL);
  struct rlimit rl = {0, 0};
  setrlimit(RLIMIT_CORE, &rl);
  if (handler) {
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_port);
    if (kr == KERN_SUCCESS) kr = mach_port_insert_right(mach_task_self(), g_port, g_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr == KERN_SUCCESS)
      kr = task_set_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS, g_port, (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), THREAD_STATE_NONE);
    put('P', now_ms(), (int)kr);
    pthread_t t;
    pthread_create(&t, NULL, server, NULL);
    sleep_ms(20);
  }
  put('F', now_ms(), 0);
  volatile int *p = (volatile int *)0;
  *p = 1;
  _exit(121);
}

typedef struct { double received, reply_sent, eof, reaped, sig_to_reaped; int set_kr, msg_id; char status[64]; } trial_t;

static int run_trial(int handler, int hold_ms, int reply, int sig, trial_t *o) {
  int p[2];
  if (pipe(p) != 0) return -1;
  pid_t c = fork();
  if (c == 0) { close(p[0]); child(p[1], handler, hold_ms, reply); _exit(122); }
  close(p[1]);
  double tf = -1, tr = -1, ts = -1, teof = -1, tsig = -1, start = now_ms();
  int sent = 0, escalated = 0;
  o->set_kr = -1;
  o->msg_id = -1;
  for (;;) {
    double now = now_ms();
    if (sig && !sent && tf > 0 && now >= tf + 300) { kill(c, sig); tsig = now_ms(); sent = 1; }
    if (sig && sent && !escalated && sig != SIGKILL && now >= tsig + 3000) { kill(c, SIGKILL); escalated = 1; }
    if (now - start > 15000) break;
    rec_t r;
    ssize_t k = read_timeout(p[0], &r, sizeof r, 5);
    if (k == 0) { teof = now_ms(); break; }
    if (k == (ssize_t)sizeof r) {
      if (r.tag == 'F') tf = r.t;
      else if (r.tag == 'R') { tr = r.t; o->msg_id = r.value; }
      else if (r.tag == 'S') ts = r.t;
      else if (r.tag == 'P') o->set_kr = r.value;
    }
  }
  int st = 0;
  pid_t w = waitpid_timeout(c, &st, 0, 10000);
  double tw = now_ms();
  close(p[0]);
  if (w != c) { kill(c, SIGKILL); waitpid(c, &st, 0); snprintf(o->status, sizeof o->status, "still_running_after_15s_then_killed"); }
  else status_text(st, o->status, sizeof o->status);
  if (escalated) strncat(o->status, "+escalated_to_SIGKILL", sizeof o->status - strlen(o->status) - 1);
  o->received = tr > 0 && tf > 0 ? tr - tf : -1;
  o->reply_sent = ts > 0 && tf > 0 ? ts - tf : -1;
  o->eof = teof > 0 && tf > 0 ? teof - tf : -1;
  o->reaped = tf > 0 ? tw - tf : -1;
  o->sig_to_reaped = tsig > 0 ? tw - tsig : -1;
  return tf > 0 ? 0 : -1;
}

static int cmp_d(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}
static double median(double *v, int n) { qsort(v, (size_t)n, sizeof(double), cmp_d); return n ? v[n / 2] : -1; }

static void series(const char *kase, int handler, int hold_ms, int reply, int sig, int n) {
  double rcv[8], rep[8], eof[8], rp[8], sg[8];
  int k = 0, set_kr = -1, msg_id = -1;
  char status[64] = "", statuses[400] = "";
  for (int i = 0; i < n && k < 8; i++) {
    trial_t t;
    memset(&t, 0, sizeof t);
    if (run_trial(handler, hold_ms, reply, sig, &t) != 0) continue;
    rcv[k] = t.received; rep[k] = t.reply_sent; eof[k] = t.eof; rp[k] = t.reaped; sg[k] = t.sig_to_reaped;
    set_kr = t.set_kr; msg_id = t.msg_id;
    if (strcmp(status, t.status) != 0) {
      snprintf(status, sizeof status, "%s", t.status);
      size_t l = strlen(statuses);
      snprintf(statuses + l, sizeof statuses - l, "%s%s", l ? "|" : "", t.status);
    }
    k++;
  }
  if (!k) { emit(PROBE, kase, "\"n\":0"); return; }
  emit(PROBE, kase,
       "\"n\":%d,\"task_set_exception_ports_kr\":%d,\"exception_msg_id\":%d,\"statuses\":\"%s\",\"median_ms_after_fault\":{\"handler_received\":%.1f,\"reply_sent\":%.1f,\"pipe_eof\":%.1f,\"reaped\":%.1f},\"median_signal_to_reaped_ms\":%.1f",
       k, set_kr, msg_id, statuses, median(rcv, k), median(rep, k), median(eof, k), median(rp, k), median(sg, k));
}

int main(void) {
  watchdog(150);
  emit_header(PROBE);
  series("baseline_no_handler", 0, 0, 0, 0, 5);
  series("handler_replies_failure_after_0ms", 1, 0, 1, 0, 5);
  series("handler_replies_failure_after_500ms", 1, 500, 1, 0, 3);
  series("handler_never_replies_SIGTERM_after_300ms", 1, 0, 0, SIGTERM, 3);
  series("handler_never_replies_SIGKILL_after_300ms", 1, 0, 0, SIGKILL, 3);
  return 0;
}
