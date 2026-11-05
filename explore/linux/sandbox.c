/*
 * Sandboxing a child between fork and exec on Linux: Landlock (filesystem, TCP, signal scoping) and seccomp
 * (errno, kill, user notification to the supervisor). Measures what the hosted runners' kernels offer and what a
 * library has to do in the child before exec. One JSON line per case; nothing asserts. (explore-hard.yml)
 *
 * Usage: sandbox <scratch dir>
 *        sandbox --try-socket      (child mode: reports socket()'s errno)
 */
#include "../posix/common.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#define P "sandbox"

/* Landlock UAPI, spelled out so old headers do not matter */
#define LL_CREATE_RULESET_VERSION (1U << 0)
#define LL_RULE_PATH_BENEATH 1
#define LL_RULE_NET_PORT 2
#define LL_FS_EXECUTE (1ULL << 0)
#define LL_FS_WRITE_FILE (1ULL << 1)
#define LL_FS_READ_FILE (1ULL << 2)
#define LL_FS_READ_DIR (1ULL << 3)
#define LL_NET_BIND_TCP (1ULL << 0)
#define LL_NET_CONNECT_TCP (1ULL << 1)
#define LL_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LL_SCOPE_SIGNAL (1ULL << 1)
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

struct ll_ruleset_attr { uint64_t fs; uint64_t net; uint64_t scoped; };
struct ll_path_beneath { uint64_t allowed; int32_t parent_fd; } __attribute__((packed));
struct ll_net_port { uint64_t allowed; uint64_t port; };

static int ll_abi(void) { return (int)syscall(__NR_landlock_create_ruleset, NULL, 0, LL_CREATE_RULESET_VERSION); }

static uint64_t ll_fs_all(int abi) {
  uint64_t all = (1ULL << 13) - 1; /* ABI 1 */
  if (abi >= 2) all |= 1ULL << 13; /* REFER */
  if (abi >= 3) all |= 1ULL << 14; /* TRUNCATE */
  if (abi >= 5) all |= 1ULL << 15; /* IOCTL_DEV */
  return all;
}

static int ll_create(int abi, uint64_t fs, uint64_t net, uint64_t scoped) {
  struct ll_ruleset_attr a = {fs, net, scoped};
  size_t size = abi >= 6 ? 24 : abi >= 4 ? 16 : 8;
  return (int)syscall(__NR_landlock_create_ruleset, &a, size, 0);
}

static int ll_allow_path(int ruleset, const char *path, uint64_t access) {
  struct ll_path_beneath pb = {access, open(path, O_PATH | O_CLOEXEC)};
  if (pb.parent_fd < 0) return -1;
  int r = (int)syscall(__NR_landlock_add_rule, ruleset, LL_RULE_PATH_BENEATH, &pb, 0);
  int e = errno;
  close(pb.parent_fd);
  errno = e;
  return r;
}

/* runs `script` with /bin/sh in a child sandboxed by `setup` (which returns 0 or an errno); collects stdout */
typedef int (*setup_fn)(void *ctx);
static int run_sandboxed(setup_fn setup, void *ctx, const char *script, char *out, size_t cap, char *status, size_t sn) {
  int p[2];
  if (pipe(p) != 0) return -1;
  pid_t pid = fork();
  if (pid == 0) {
    dup2(p[1], 1);
    dup2(p[1], 2);
    close(p[0]);
    int e = setup(ctx);
    if (e != 0) { printf("setup_errno=%s", errno_name(e)); fflush(stdout); _exit(100); }
    execl("/bin/sh", "sh", "-c", script, (char *)NULL);
    _exit(127);
  }
  close(p[1]);
  int eof;
  size_t n = drain_until(p[0], out, cap, 10000, &eof);
  out[n] = 0;
  for (size_t i = 0; i < n; i++) if (out[i] == '\n' || out[i] == '"' || out[i] == '\\') out[i] = ' ';
  close(p[0]);
  reap_blocking(pid, 10000, status, sn);
  return 0;
}

struct fs_ctx { int abi; int nnp; const char *allowed_dir; };

static int fs_setup(void *v) {
  struct fs_ctx *c = v;
  if (c->nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return errno;
  int rs = ll_create(c->abi, ll_fs_all(c->abi), 0, 0);
  if (rs < 0) return errno;
  uint64_t ro = LL_FS_EXECUTE | LL_FS_READ_FILE | LL_FS_READ_DIR;
  if (ll_allow_path(rs, "/", ro) != 0) return errno;
  if (ll_allow_path(rs, c->allowed_dir, ll_fs_all(c->abi)) != 0) return errno;
  if (ll_allow_path(rs, "/dev/null", LL_FS_WRITE_FILE | LL_FS_READ_FILE) != 0) return errno;
  if (syscall(__NR_landlock_restrict_self, rs, 0) != 0) return errno;
  close(rs);
  return 0;
}

struct net_ctx { int abi; };
static int net_setup(void *v) {
  struct net_ctx *c = v;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return errno;
  int rs = ll_create(c->abi, 0, LL_NET_CONNECT_TCP | LL_NET_BIND_TCP, 0);
  if (rs < 0) return errno;
  if (syscall(__NR_landlock_restrict_self, rs, 0) != 0) return errno;
  close(rs);
  return 0;
}

static int scope_setup(void *v) {
  struct net_ctx *c = v;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return errno;
  int rs = ll_create(c->abi, 0, 0, LL_SCOPE_SIGNAL | LL_SCOPE_ABSTRACT_UNIX_SOCKET);
  if (rs < 0) return errno;
  if (syscall(__NR_landlock_restrict_self, rs, 0) != 0) return errno;
  close(rs);
  return 0;
}

/* ---- seccomp ---- */
#if defined(__x86_64__)
#define ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#endif

static int install_filter(int nr, uint32_t action, unsigned flags, int nnp) {
  if (nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -errno;
  struct sock_filter f[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)nr, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, action),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {(unsigned short)(sizeof f / sizeof f[0]), f};
  long r = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog);
  return r < 0 ? -errno : (int)r;
}

static const char *self_exe;

static void seccomp_case(const char *name, uint32_t action, int nnp) {
  int p[2];
  pipe(p);
  pid_t pid = fork();
  if (pid == 0) {
    dup2(p[1], 1);
    close(p[0]);
    int r = install_filter(__NR_socket, action, 0, nnp);
    if (r < 0) { printf("install_errno=%s", errno_name(-r)); fflush(stdout); _exit(100); }
    execl(self_exe, self_exe, "--try-socket", (char *)NULL);
    _exit(127);
  }
  close(p[1]);
  char out[256], status[128];
  int eof;
  size_t n = drain_until(p[0], out, sizeof out, 10000, &eof);
  out[n] = 0;
  close(p[0]);
  reap_blocking(pid, 10000, status, sizeof status);
  emit(P, name, "\"child_said\":\"%s\",\"status\":\"%s\"", out, status);
}

static int send_fd(int sock, int fd) {
  char c = 'x';
  struct iovec iov = {&c, 1};
  char ctrl[CMSG_SPACE(sizeof(int))];
  memset(ctrl, 0, sizeof ctrl);
  struct msghdr m = {0};
  m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = ctrl; m.msg_controllen = sizeof ctrl;
  struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
  cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cm), &fd, sizeof(int));
  return sendmsg(sock, &m, 0) == 1 ? 0 : -1;
}

static int recv_fd(int sock) {
  char c;
  struct iovec iov = {&c, 1};
  char ctrl[CMSG_SPACE(sizeof(int))];
  struct msghdr m = {0};
  m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = ctrl; m.msg_controllen = sizeof ctrl;
  if (recvmsg(sock, &m, 0) != 1) return -1;
  struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
  if (!cm || cm->cmsg_type != SCM_RIGHTS) return -1;
  int fd;
  memcpy(&fd, CMSG_DATA(cm), sizeof(int));
  return fd;
}

/* The child's mkdirat is decided by the supervisor: the child sends its listener to the parent, then calls mkdir;
   the parent receives the notification and answers EROFS. */
static void user_notif_case(const char *scratch) {
  int sv[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  int res[2];
  pipe(res);
  char target[512];
  snprintf(target, sizeof target, "%s/notif-dir", scratch);
  pid_t pid = fork();
  if (pid == 0) {
    close(sv[0]);
    close(res[0]);
    int listener = install_filter(__NR_mkdirat, SECCOMP_RET_USER_NOTIF, SECCOMP_FILTER_FLAG_NEW_LISTENER, 1);
    if (listener < 0) { int e = -listener; write(res[1], &e, sizeof e); _exit(100); }
    send_fd(sv[1], listener);
    close(listener);
    int r = (int)syscall(__NR_mkdirat, AT_FDCWD, target, 0700); /* glibc's mkdir uses __NR_mkdir on x86_64 */
    int e = r == 0 ? 0 : errno;
    write(res[1], &e, sizeof e);
    _exit(0);
  }
  close(sv[1]);
  close(res[1]);
  int listener = recv_fd(sv[0]);
  if (listener < 0) {
    int e = 0;
    read(res[0], &e, sizeof e);
    char st[128];
    reap_blocking(pid, 5000, st, sizeof st);
    emit(P, "seccomp_user_notif", "\"install_errno\":\"%s\",\"status\":\"%s\"", errno_name(e), st);
    return;
  }
  struct seccomp_notif_sizes sizes;
  syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
  struct seccomp_notif *req = calloc(1, sizes.seccomp_notif > sizeof *req ? sizes.seccomp_notif : sizeof *req);
  struct seccomp_notif_resp *resp = calloc(1, sizes.seccomp_notif_resp > sizeof *resp ? sizes.seccomp_notif_resp : sizeof *resp);
  double t0 = now_ms();
  int recv_ok = ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req);
  int recv_err = recv_ok == 0 ? 0 : errno;
  double t1 = now_ms();
  char path[256] = "";
  if (recv_ok == 0) {
    /* read the path argument out of the child's memory, then check the request is still alive (TOCTOU guard) */
    char mem[64];
    snprintf(mem, sizeof mem, "/proc/%d/mem", (int)req->pid);
    int mfd = open(mem, O_RDONLY);
    if (mfd >= 0) { pread(mfd, path, sizeof path - 1, (off_t)req->data.args[1]); close(mfd); }
    int valid = ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id);
    resp->id = req->id;
    resp->error = -EROFS;
    resp->val = 0;
    resp->flags = 0;
    int send_ok = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp);
    int e = -1;
    read(res[0], &e, sizeof e);
    char st[128];
    reap_blocking(pid, 5000, st, sizeof st);
    for (char *c = path; *c; c++) if (*c == '"' || *c == '\\') *c = ' ';
    emit(P, "seccomp_user_notif",
         "\"notified_pid_matches\":%s,\"nr_is_mkdirat\":%s,\"path_from_child_memory\":\"%s\",\"id_valid\":%d,\"send\":%d,"
         "\"child_mkdir_errno\":\"%s\",\"dir_exists\":%s,\"recv_wait_ms\":%.3f,\"notif_size\":%u,\"status\":\"%s\"",
         req->pid == (uint32_t)pid ? "true" : "false", req->data.nr == __NR_mkdirat ? "true" : "false", path, valid,
         send_ok, errno_name(e), access(target, F_OK) == 0 ? "true" : "false", t1 - t0, sizes.seccomp_notif, st);
  } else {
    emit(P, "seccomp_user_notif", "\"recv_errno\":\"%s\"", errno_name(recv_err));
  }
  close(listener);
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--try-socket") == 0) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    printf("socket_errno=%s", s >= 0 ? "OK" : errno_name(errno));
    return 0;
  }
  if (argc < 2) { fprintf(stderr, "usage: sandbox <scratch dir>\n"); return 2; }
  self_exe = "/proc/self/exe";
  watchdog(120);
  emit_header(P);
  const char *scratch = argv[1];
  char allowed[512], denied[512];
  snprintf(allowed, sizeof allowed, "%s/allowed", scratch);
  snprintf(denied, sizeof denied, "%s/denied", scratch);
  mkdir(scratch, 0755); mkdir(allowed, 0755); mkdir(denied, 0755);

  int abi = ll_abi();
  int abi_errno = abi < 0 ? errno : 0;
  char lsm[512] = "";
  FILE *f = fopen("/sys/kernel/security/lsm", "r");
  if (f) { fgets(lsm, sizeof lsm, f); fclose(f); }
  lsm[strcspn(lsm, "\n")] = 0;
  emit(P, "landlock_abi", "\"abi\":%d,\"errno\":\"%s\",\"lsm\":\"%s\"", abi, errno_name(abi_errno), lsm);

  char script[2048], out[1024], st[128];
  snprintf(script, sizeof script,
           "echo a > %s/ok && echo allowed_write_ok; echo b > %s/no 2>/dev/null && echo DENIED_DIR_WRITTEN || echo denied_write_refused;"
           " cat /etc/hostname > /dev/null && echo read_ok; ls %s > /dev/null && echo list_ok; true > /tmp/ll-$$ 2>/dev/null && echo TMP_WRITTEN || echo tmp_refused",
           allowed, denied, scratch);
  if (abi > 0) {
    for (int nnp = 1; nnp >= 0; nnp--) {
      struct fs_ctx c = {abi, nnp, allowed};
      run_sandboxed(fs_setup, &c, script, out, sizeof out, st, sizeof st);
      emit(P, nnp ? "landlock_fs" : "landlock_fs_without_no_new_privs", "\"output\":\"%s\",\"status\":\"%s\"", out, st);
    }
    if (abi >= 4) {
      int ls = socket(AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
      bind(ls, (struct sockaddr *)&a, sizeof a);
      listen(ls, 4);
      socklen_t al = sizeof a;
      getsockname(ls, (struct sockaddr *)&a, &al);
      char net_script[512];
      snprintf(net_script, sizeof net_script,
               "exec 3<>/dev/tcp/127.0.0.1/%d 2>/dev/null && echo CONNECTED || echo connect_refused", ntohs(a.sin_port));
      /* bash has /dev/tcp; dash does not, so call bash explicitly */
      char wrapped[600];
      snprintf(wrapped, sizeof wrapped, "bash -c '%s'", net_script);
      struct net_ctx c = {abi};
      run_sandboxed(net_setup, &c, wrapped, out, sizeof out, st, sizeof st);
      emit(P, "landlock_net_connect_denied", "\"output\":\"%s\",\"status\":\"%s\"", out, st);
      close(ls);
    } else {
      emit(P, "landlock_net_connect_denied", "\"skipped\":\"abi %d < 4\"", abi);
    }
    if (abi >= 6) {
      char sig_script[256];
      snprintf(sig_script, sizeof sig_script,
               "kill -0 %d 2>/dev/null && echo SIGNALLED_OUTSIDE || echo outside_refused; sleep 30 & kill $! && echo inside_ok", (int)getpid());
      struct net_ctx c = {abi};
      run_sandboxed(scope_setup, &c, sig_script, out, sizeof out, st, sizeof st);
      emit(P, "landlock_scope_signal", "\"output\":\"%s\",\"status\":\"%s\"", out, st);
    } else {
      emit(P, "landlock_scope_signal", "\"skipped\":\"abi %d < 6\"", abi);
    }
  }

  seccomp_case("seccomp_errno_survives_exec", SECCOMP_RET_ERRNO | EPERM, 1);
  seccomp_case("seccomp_without_no_new_privs", SECCOMP_RET_ERRNO | EPERM, 0);
  seccomp_case("seccomp_kill_process", SECCOMP_RET_KILL_PROCESS, 1);
  user_notif_case(scratch);
  return 0;
}
