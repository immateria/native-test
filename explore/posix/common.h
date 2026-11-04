/*
 * Shared helpers for the POSIX exploration probes (macOS and Linux). Every probe prints one JSON object per
 * line and records what it observed; none of them asserts. A global watchdog (alarm) keeps a hung probe
 * from stalling CI.
 */
#ifndef PROBE_COMMON_H
#define PROBE_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void sleep_ms(int ms) {
  struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
  while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
}

static const char *errno_name(int e) {
  switch (e) {
    case 0: return "OK";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case ESRCH: return "ESRCH";
    case EINTR: return "EINTR";
    case EIO: return "EIO";
    case E2BIG: return "E2BIG";
    case ENOEXEC: return "ENOEXEC";
    case EBADF: return "EBADF";
    case ECHILD: return "ECHILD";
    case EAGAIN: return "EAGAIN";
    case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES";
    case EFAULT: return "EFAULT";
    case EBUSY: return "EBUSY";
    case EEXIST: return "EEXIST";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EINVAL: return "EINVAL";
    case ENFILE: return "ENFILE";
    case EMFILE: return "EMFILE";
    case ENOTTY: return "ENOTTY";
    case ETXTBSY: return "ETXTBSY";
    case EFBIG: return "EFBIG";
    case ENOSPC: return "ENOSPC";
    case ESPIPE: return "ESPIPE";
    case EPIPE: return "EPIPE";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ELOOP: return "ELOOP";
    case ENOSYS: return "ENOSYS";
    case ENOTSUP: return "ENOTSUP";
    case EXDEV: return "EXDEV";
    case EROFS: return "EROFS";
#ifdef EBADARCH
    case EBADARCH: return "EBADARCH";
#endif
#ifdef EBADEXEC
    case EBADEXEC: return "EBADEXEC";
#endif
#ifdef EBADMACHO
    case EBADMACHO: return "EBADMACHO";
#endif
    default: return "other";
  }
}

static const char *sig_name(int s) {
  switch (s) {
    case 0: return "none";
    case SIGHUP: return "SIGHUP";
    case SIGINT: return "SIGINT";
    case SIGQUIT: return "SIGQUIT";
    case SIGILL: return "SIGILL";
    case SIGTRAP: return "SIGTRAP";
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGKILL: return "SIGKILL";
    case SIGUSR1: return "SIGUSR1";
    case SIGSEGV: return "SIGSEGV";
    case SIGUSR2: return "SIGUSR2";
    case SIGPIPE: return "SIGPIPE";
    case SIGALRM: return "SIGALRM";
    case SIGTERM: return "SIGTERM";
    case SIGCHLD: return "SIGCHLD";
    case SIGCONT: return "SIGCONT";
    case SIGSTOP: return "SIGSTOP";
    case SIGTSTP: return "SIGTSTP";
    case SIGTTIN: return "SIGTTIN";
    case SIGTTOU: return "SIGTTOU";
    case SIGXCPU: return "SIGXCPU";
    case SIGXFSZ: return "SIGXFSZ";
    case SIGWINCH: return "SIGWINCH";
    default: return "other";
  }
}

/* Where the process stopped, in words (for waitpid statuses). */
static void status_text(int st, char *buf, size_t n) {
  if (WIFEXITED(st)) snprintf(buf, n, "exited(%d)", WEXITSTATUS(st));
  else if (WIFSIGNALED(st)) snprintf(buf, n, "signaled(%s%s)", sig_name(WTERMSIG(st)), WCOREDUMP(st) ? ",core" : "");
  else if (WIFSTOPPED(st)) snprintf(buf, n, "stopped(%s)", sig_name(WSTOPSIG(st)));
#ifdef WIFCONTINUED
  else if (WIFCONTINUED(st)) snprintf(buf, n, "continued");
#endif
  else snprintf(buf, n, "status(0x%x)", st);
}

/* waitpid with a timeout (polling, 1 ms). Returns pid when something is reported, 0 on timeout, -1 on error. */
static pid_t waitpid_timeout(pid_t pid, int *st, int flags, int timeout_ms) {
  double end = now_ms() + timeout_ms;
  for (;;) {
    pid_t r = waitpid(pid, st, flags | WNOHANG);
    if (r != 0) return r;
    if (now_ms() >= end) return 0;
    sleep_ms(1);
  }
}

static pid_t reap_blocking(pid_t pid, int timeout_ms, char *buf, size_t n) {
  int st = 0;
  pid_t r = waitpid_timeout(pid, &st, 0, timeout_ms);
  if (r > 0) status_text(st, buf, n);
  else if (r == 0) snprintf(buf, n, "still_running");
  else snprintf(buf, n, "waitpid_error(%s)", errno_name(errno));
  return r;
}

static void emit_header(const char *probe) {
  struct utsname u;
  uname(&u);
  printf("{\"probe\":\"%s\",\"case\":\"_platform\",\"sysname\":\"%s\",\"release\":\"%s\",\"machine\":\"%s\",\"uid\":%d,\"euid\":%d}\n",
         probe, u.sysname, u.release, u.machine, (int)getuid(), (int)geteuid());
  fflush(stdout);
}

/* One JSON line: {"probe":P,"case":C, <fields>}. fields is a printf format producing `"k":v,"k2":v2` (no braces). */
static void emit(const char *probe, const char *kase, const char *fmt, ...) {
  char body[4096];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(body, sizeof body, fmt, ap);
  va_end(ap);
  printf("{\"probe\":\"%s\",\"case\":\"%s\",%s}\n", probe, kase, body);
  fflush(stdout);
}

static void watchdog(int seconds) {
  signal(SIGALRM, SIG_DFL);
  alarm((unsigned)seconds);
}

static void set_cloexec(int fd) { fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC); }

/* Reads up to n bytes (or until deadline) from fd; returns count read. */
static ssize_t read_timeout(int fd, void *buf, size_t n, int timeout_ms) {
  struct pollfd p = {fd, POLLIN, 0};
  int r = poll(&p, 1, timeout_ms);
  if (r <= 0) return r == 0 ? -2 : -1; /* -2 = timeout */
  return read(fd, buf, n);
}

/* Drain everything readable until EOF or the deadline. Sets *eof. */
static size_t drain_until(int fd, char *buf, size_t cap, int timeout_ms, int *eof) {
  size_t len = 0;
  double end = now_ms() + timeout_ms;
  *eof = 0;
  while (len + 1 < cap) {
    double left = end - now_ms();
    if (left <= 0) break;
    ssize_t r = read_timeout(fd, buf + len, cap - 1 - len, (int)left + 1);
    if (r == -2) break;
    if (r == 0) { *eof = 1; break; }
    if (r < 0) { if (errno == EINTR) continue; break; }
    len += (size_t)r;
  }
  buf[len] = 0;
  return len;
}

#endif
