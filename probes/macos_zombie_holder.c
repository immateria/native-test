#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int parse_int(const char *text, int fallback) {
  char *end = NULL;
  long value;
  errno = 0;
  value = strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value < 0 || value > 255) {
    return fallback;
  }
  return (int)value;
}

static int write_pid_marker(const char *path, pid_t pid) {
  char buffer[64];
  int length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)pid);
  if (length <= 0 || (size_t)length >= sizeof(buffer)) {
    return -1;
  }

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    return -1;
  }

  ssize_t written = write(fd, buffer, (size_t)length);
  int saved_errno = errno;
  if (close(fd) != 0 && written == length) {
    return -1;
  }
  errno = saved_errno;
  return written == length ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    fprintf(stderr, "usage: %s MARKER EXIT_CODE [HOLD_MS]\n", argv[0]);
    return 64;
  }

  int exit_code = parse_int(argv[2], 23);
  int hold_ms = argc == 4 ? parse_int(argv[3], 1400) : 1400;
  if (hold_ms < 100) {
    hold_ms = 100;
  }

  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    return 70;
  }
  if (child == 0) {
    _exit(exit_code);
  }

  siginfo_t info;
  memset(&info, 0, sizeof(info));
  if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT) != 0) {
    int saved_errno = errno;
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
    errno = saved_errno;
    perror("waitid(WNOWAIT)");
    return 71;
  }

  if (write_pid_marker(argv[1], child) != 0) {
    int saved_errno = errno;
    (void)waitpid(child, NULL, 0);
    errno = saved_errno;
    perror("marker");
    return 72;
  }

  /* waitid(..., WNOWAIT) proves the child has exited without reaping it. The
   * marker is published only after that point, and no Crystal SIGCHLD handler
   * is parent of this child. */
  (void)poll(NULL, 0, hold_ms);

  int status = 0;
  pid_t waited = waitpid(child, &status, 0);
  if (waited != child) {
    perror("waitpid");
    return 73;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != exit_code) {
    fprintf(stderr, "unexpected child status: 0x%x\n", status);
    return 74;
  }
  return 0;
}
