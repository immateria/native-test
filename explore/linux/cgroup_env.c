/*
 * What can a supervisor do with cgroups in THIS environment? Run it unprivileged, as root, in a systemd unit with
 * Delegate=yes, in a systemd user manager, in a container (default, privileged, other seccomp) and on a different libc,
 * and compare. Records JSON lines, never asserts.
 *
 *   cgroup_env [--emit-dir FILE] [--emit-own FILE]
 *
 * --emit-dir  writes the first directory in which a cgroup could be created AND a child cloned into (or attached to)
 *             it; empty file if none (the caller then skips the probes that need a delegated cgroup)
 * --emit-own  writes this process's own cgroup directory (kit_linux uses it to see how the shard classifies a refusal)
 *
 * Cases: identity, cgroup_mounts, own_cgroup, syscalls, create_in_<candidate>, move_self.
 *
 * Build: cc -O1 -Wall -Wextra -o cgroup_env cgroup_env.c   (Linux only)
 */
#include "../posix/common.h"

#ifndef __linux__
int main(void) { printf("{\"probe\":\"cgroup_env\",\"case\":\"_unsupported\"}\n"); return 0; }
#else

#include <limits.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <linux/sched.h>

#define PROBE "cgroup_env"

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

struct clone_args_v2 {
  uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

static long clone3_raw(uint64_t flags, int dirfd, int *pidfd_out) {
  struct clone_args_v2 ca;
  memset(&ca, 0, sizeof ca);
  ca.flags = flags;
  ca.exit_signal = SIGCHLD;
  if (flags & CLONE_INTO_CGROUP) ca.cgroup = (uint64_t)(unsigned)dirfd;
  if (flags & CLONE_PIDFD) ca.pidfd = (uint64_t)(uintptr_t)pidfd_out;
  return syscall(SYS_clone3, &ca, sizeof ca);
}

static void json_str(const char *s, char *o, size_t cap) {
  size_t j = 0;
  for (size_t i = 0; s[i] && j + 8 < cap; i++) {
    unsigned char ch = (unsigned char)s[i];
    if (ch == '"' || ch == '\\') { o[j++] = '\\'; o[j++] = (char)ch; }
    else if (ch < 0x20) j += (size_t)snprintf(o + j, cap - j, "\\u%04x", ch);
    else o[j++] = (char)ch;
  }
  o[j] = 0;
}

static int slurp(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { buf[0] = 0; return -errno; }
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  buf[n > 0 ? n : 0] = 0;
  return (int)n;
}

static void trim(char *s) {
  size_t l = strlen(s);
  while (l && (s[l - 1] == '\n' || s[l - 1] == ' ')) s[--l] = 0;
}

static int write_file(const char *dir, const char *file, const char *v) {
  char p[1300];
  snprintf(p, sizeof p, "%s/%s", dir, file);
  int fd = open(p, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return errno;
  ssize_t n = write(fd, v, strlen(v));
  int e = n < 0 ? errno : 0;
  close(fd);
  return e;
}

static long long key(const char *dir, const char *file, const char *k) {
  char p[1300], b[2048];
  snprintf(p, sizeof p, "%s/%s", dir, file);
  if (slurp(p, b, sizeof b) <= 0) return -1;
  size_t kl = strlen(k);
  for (char *l = b; l && *l;) {
    if (strncmp(l, k, kl) == 0 && l[kl] == ' ') return atoll(l + kl + 1);
    l = strchr(l, '\n');
    if (l) l++;
  }
  return -1;
}

static const char *acc(const char *path, int mode) { return access(path, mode) == 0 ? "yes" : errno_name(errno); }

/* ------------------------------------------------------------------ discovery */
static char g_mount[512];   /* where cgroup2 is mounted, "" if nowhere */
static char g_own[1024];    /* this process's cgroup directory */

static void case_identity(void) {
  char st[4096], comm[64] = "", cg[256];
  slurp("/proc/self/status", st, sizeof st);
  unsigned long long capeff = 0;
  int nnp = -1, seccomp = -1;
  char *p;
  if ((p = strstr(st, "CapEff:"))) capeff = strtoull(p + 7, NULL, 16);
  if ((p = strstr(st, "NoNewPrivs:"))) nnp = atoi(p + 11);
  if ((p = strstr(st, "Seccomp:"))) seccomp = atoi(p + 8);
  slurp("/proc/1/comm", comm, sizeof comm);
  trim(comm);
  slurp("/proc/self/ns/cgroup", cg, 0);
  char link_self[128] = "", link_init[128] = "";
  ssize_t a = readlink("/proc/self/ns/cgroup", link_self, sizeof link_self - 1);
  ssize_t b = readlink("/proc/1/ns/cgroup", link_init, sizeof link_init - 1);
  if (a > 0) link_self[a] = 0;
  if (b > 0) link_init[b] = 0;
  emit(PROBE, "identity",
       "\"uid\":%d,\"euid\":%d,\"gid\":%d,\"CapEff\":\"%llx\",\"NoNewPrivs\":%d,\"Seccomp\":%d,\"pid1_comm\":\"%s\",\"dockerenv_file\":%d,\"containerenv_file\":%d,\"INVOCATION_ID_set\":%d,\"JOURNAL_STREAM_set\":%d,\"XDG_RUNTIME_DIR\":\"%s\",\"cgroup_ns_same_as_pid1\":%d",
       (int)getuid(), (int)geteuid(), (int)getgid(), capeff, nnp, seccomp, comm, access("/.dockerenv", F_OK) == 0, access("/run/.containerenv", F_OK) == 0,
       getenv("INVOCATION_ID") != NULL, getenv("JOURNAL_STREAM") != NULL, getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "", strcmp(link_self, link_init) == 0);
}

static void case_mounts(void) {
  char mi[65536];
  slurp("/proc/self/mountinfo", mi, sizeof mi);
  char out[3500] = "[";
  g_mount[0] = 0;
  for (char *l = strtok(mi, "\n"); l; l = strtok(NULL, "\n")) {
    char *dash = strstr(l, " - ");
    if (!dash) continue;
    char fstype[32] = "", src[64] = "", sup[256] = "";
    sscanf(dash + 3, "%31s %63s %255s", fstype, src, sup);
    if (strcmp(fstype, "cgroup2") != 0 && strcmp(fstype, "cgroup") != 0) continue;
    char mp[512] = "", opts[256] = "";
    int field = 0;
    char *save = NULL;
    char copy[2048];
    snprintf(copy, sizeof copy, "%.*s", (int)(dash - l), l);
    for (char *t = strtok_r(copy, " ", &save); t; t = strtok_r(NULL, " ", &save), field++) {
      if (field == 4) snprintf(mp, sizeof mp, "%s", t);
      if (field == 5) snprintf(opts, sizeof opts, "%s", t);
    }
    if (strcmp(fstype, "cgroup2") == 0 && !g_mount[0]) snprintf(g_mount, sizeof g_mount, "%s", mp);
    char emp[1100], eop[600], esu[600];
    json_str(mp, emp, sizeof emp);
    json_str(opts, eop, sizeof eop);
    json_str(sup, esu, sizeof esu);
    size_t n = strlen(out);
    if (n + 1500 < sizeof out)
      snprintf(out + n, sizeof out - n, "%s{\"fstype\":\"%s\",\"mountpoint\":\"%s\",\"mount_options\":\"%s\",\"super_options\":\"%s\"}", n > 1 ? "," : "", fstype, emp, eop, esu);
  }
  size_t n = strlen(out);
  snprintf(out + n, sizeof out - n, "]");
  struct statfs sf;
  long long magic = statfs("/sys/fs/cgroup", &sf) == 0 ? (long long)sf.f_type : -1;
  emit(PROBE, "cgroup_mounts", "\"cgroup_mounts\":%s,\"statfs_sys_fs_cgroup_f_type\":\"%llx\",\"is_cgroup2_super_magic\":%d,\"first_cgroup2_mount\":\"%s\"", out, magic < 0 ? 0 : magic, magic == 0x63677270, g_mount);
}

static void case_own(void) {
  char cg[2048], v2[512] = "";
  slurp("/proc/self/cgroup", cg, sizeof cg);
  for (char *l = strtok(cg, "\n"); l; l = strtok(NULL, "\n")) if (strncmp(l, "0::", 3) == 0) snprintf(v2, sizeof v2, "%s", l + 3);
  if (g_mount[0] && v2[0]) snprintf(g_own, sizeof g_own, "%s%s", g_mount, strcmp(v2, "/") == 0 ? "" : v2);
  else g_own[0] = 0;
  if (!g_own[0]) { emit(PROBE, "own_cgroup", "\"v2_path\":\"%s\",\"directory\":\"\",\"usable\":false", v2); return; }
  char p[1100], ctl[256], sub[256], typ[64], procs[2048];
  snprintf(p, sizeof p, "%s/cgroup.controllers", g_own); slurp(p, ctl, sizeof ctl); trim(ctl);
  snprintf(p, sizeof p, "%s/cgroup.subtree_control", g_own); slurp(p, sub, sizeof sub); trim(sub);
  snprintf(p, sizeof p, "%s/cgroup.type", g_own); slurp(p, typ, sizeof typ); trim(typ);
  snprintf(p, sizeof p, "%s/cgroup.procs", g_own); int pn = slurp(p, procs, sizeof procs);
  int count = 0;
  for (char *c = procs; pn > 0 && *c; c++) if (*c == '\n') count++;
  struct stat sb;
  stat(g_own, &sb);
  char pk[1100], pf[1100], pz[1100];
  snprintf(pk, sizeof pk, "%s/cgroup.kill", g_own);
  snprintf(pf, sizeof pf, "%s/cgroup.freeze", g_own);
  snprintf(pz, sizeof pz, "%s/cgroup.procs", g_own);
  char eown[1100], ev2[600];
  json_str(g_own, eown, sizeof eown);
  json_str(v2, ev2, sizeof ev2);
  emit(PROBE, "own_cgroup",
       "\"v2_path\":\"%s\",\"directory\":\"%s\",\"owner_uid\":%d,\"mode\":\"%o\",\"controllers\":\"%s\",\"subtree_control\":\"%s\",\"type\":\"%s\",\"processes_in_it\":%d,\"private_cgroup_namespace_root\":%d,\"directory_writable\":\"%s\",\"cgroup_procs_writable\":\"%s\",\"cgroup_kill_file\":\"%s\",\"cgroup_freeze_file\":\"%s\"",
       ev2, eown, (int)sb.st_uid, (unsigned)(sb.st_mode & 07777), ctl, sub, typ, count, strcmp(v2, "/") == 0,
       acc(g_own, W_OK), acc(pz, W_OK), acc(pk, F_OK), acc(pf, F_OK));
}

static void case_syscalls(void) {
  errno = 0;
  long r = clone3_raw(0, -1, NULL);
  int e_plain = r < 0 ? errno : 0;
  if (r == 0) _exit(0);
  if (r > 0) waitpid((pid_t)r, NULL, 0);
  int pfd = -1;
  r = clone3_raw(CLONE_PIDFD, -1, &pfd);
  int e_pidfd = r < 0 ? errno : 0;
  if (r == 0) _exit(0);
  if (r > 0) waitpid((pid_t)r, NULL, 0);
  if (pfd >= 0) close(pfd);
  errno = 0;
  int self = (int)syscall(SYS_pidfd_open, getpid(), 0);
  int e_open = self < 0 ? errno : 0;
  int e_sig = 0;
  if (self >= 0) { if (syscall(SYS_pidfd_send_signal, self, 0, NULL, 0) != 0) e_sig = errno; close(self); }
  errno = 0;
  int sr = prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L);
  int e_sr = sr != 0 ? errno : 0;
  emit(PROBE, "syscalls", "\"clone3_plain\":\"%s\",\"clone3_with_CLONE_PIDFD\":\"%s\",\"pidfd_open_self\":\"%s\",\"pidfd_send_signal_null\":\"%s\",\"PR_SET_CHILD_SUBREAPER\":\"%s\"",
       errno_name(e_plain), errno_name(e_pidfd), errno_name(e_open), errno_name(e_sig), errno_name(e_sr));
}

/* ------------------------------------------------------------------ creating a cgroup in a candidate directory */
static int try_candidate(const char *name, const char *cand, int *clone_ok, int *attach_ok) {
  *clone_ok = *attach_ok = 0;
  char leaf[1200], ecand[1100];
  snprintf(leaf, sizeof leaf, "%s/cgenv-%d", cand, (int)getpid());
  json_str(cand, ecand, sizeof ecand);
  int mk = mkdir(leaf, 0755) == 0 ? 0 : errno;
  char cname[120];
  snprintf(cname, sizeof cname, "create_in_%s", name);
  if (mk) {
    /* can the controllers even be touched here? (for a refusal this says why) */
    emit(PROBE, cname, "\"directory\":\"%s\",\"mkdir\":\"%s\",\"directory_exists\":%d,\"directory_writable\":\"%s\"", ecand, errno_name(mk), access(cand, F_OK) == 0, acc(cand, W_OK));
    return 0;
  }
  int dfd = open(leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int pp[2];
  (void)!pipe2(pp, O_CLOEXEC);
  long r = clone3_raw(CLONE_INTO_CGROUP, dfd, NULL);
  if (r == 0) { (void)!write(pp[1], "x", 1); sleep_ms(300); _exit(0); }
  int e_clone = r < 0 ? errno : 0;
  char own[256] = "";
  if (r > 0) {
    char b;
    read_timeout(pp[0], &b, 1, 500);
    char path[48], buf[512];
    snprintf(path, sizeof path, "/proc/%d/cgroup", (int)r);
    slurp(path, buf, sizeof buf);
    char *l = strstr(buf, "0::");
    if (l) { char *e = strchr(l, '\n'); if (e) *e = 0; snprintf(own, sizeof own, "%s", l + 3); }
    kill((pid_t)r, SIGKILL);
    waitpid((pid_t)r, NULL, 0);
  }
  *clone_ok = e_clone == 0 && strstr(own, "cgenv-") != NULL;
  /* the same through fork + write to cgroup.procs */
  pid_t f = fork();
  if (f == 0) { sleep_ms(300); _exit(0); }
  char num[24];
  snprintf(num, sizeof num, "%d", (int)f);
  int e_attach = write_file(leaf, "cgroup.procs", num);
  *attach_ok = e_attach == 0;
  /* kill, then remove */
  int e_kill = write_file(leaf, "cgroup.kill", "1");
  waitpid(f, NULL, 0);
  double end = now_ms() + 1000;
  while (now_ms() < end && key(leaf, "cgroup.events", "populated") == 1) sleep_ms(1);
  int e_rm = rmdir(leaf) == 0 ? 0 : errno;
  /* controllers in the candidate itself: the "no internal processes" rule */
  int e_ctl = write_file(cand, "cgroup.subtree_control", "+pids");
  if (e_ctl == 0) write_file(cand, "cgroup.subtree_control", "-pids");
  close(dfd);
  close(pp[0]); close(pp[1]);
  emit(PROBE, cname,
       "\"directory\":\"%s\",\"mkdir\":\"OK\",\"clone3_into_cgroup\":\"%s\",\"child_ended_up_in\":\"%s\",\"attach_by_cgroup_procs\":\"%s\",\"cgroup_kill\":\"%s\",\"rmdir\":\"%s\",\"enable_pids_controller_in_this_directory\":\"%s\"",
       ecand, errno_name(e_clone), own, errno_name(e_attach), errno_name(e_kill), errno_name(e_rm), errno_name(e_ctl));
  return 1;
}

static void case_move_self(const char *dir) {
  if (!dir[0]) { emit(PROBE, "move_self", "\"skipped\":\"no usable directory\""); return; }
  pid_t c = fork();
  if (c == 0) {
    char leaf[1200], before[256] = "", after[256] = "", back[256] = "", b[512];
    snprintf(leaf, sizeof leaf, "%s/cgenv-self-%d", dir, (int)getpid());
    int mk = mkdir(leaf, 0755) == 0 ? 0 : errno;
    char num[24];
    snprintf(num, sizeof num, "%d", (int)getpid());
    slurp("/proc/self/cgroup", b, sizeof b);
    char *l = strstr(b, "0::"); if (l) { char *e = strchr(l, '\n'); if (e) *e = 0; snprintf(before, sizeof before, "%s", l + 3); }
    int mv = mk ? -1 : write_file(leaf, "cgroup.procs", num);
    slurp("/proc/self/cgroup", b, sizeof b);
    l = strstr(b, "0::"); if (l) { char *e = strchr(l, '\n'); if (e) *e = 0; snprintf(after, sizeof after, "%s", l + 3); }
    int mb = -1;
    if (mv == 0) {
      mb = write_file(dir, "cgroup.procs", num);
      slurp("/proc/self/cgroup", b, sizeof b);
      l = strstr(b, "0::"); if (l) { char *e = strchr(l, '\n'); if (e) *e = 0; snprintf(back, sizeof back, "%s", l + 3); }
    }
    char eb[600], ea[600], ek[600];
    json_str(before, eb, sizeof eb); json_str(after, ea, sizeof ea); json_str(back, ek, sizeof ek);
    emit(PROBE, "move_self", "\"mkdir\":\"%s\",\"move_into_leaf\":\"%s\",\"cgroup_before\":\"%s\",\"cgroup_after_move\":\"%s\",\"move_back_to_parent\":\"%s\",\"cgroup_after_move_back\":\"%s\"",
         errno_name(mk), mv == -1 ? "skipped" : errno_name(mv), eb, ea, mb == -1 ? "skipped" : errno_name(mb), ek);
    if (mv == 0) write_file(dir, "cgroup.procs", num);
    rmdir(leaf);
    _exit(0);
  }
  waitpid(c, NULL, 0);
}

int main(int argc, char **argv) {
  const char *emit_dir = NULL, *emit_own = NULL;
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], "--emit-dir") == 0) emit_dir = argv[++i];
    else if (strcmp(argv[i], "--emit-own") == 0) emit_own = argv[++i];
  }
  watchdog(60);
  emit_header(PROBE);
  case_identity();
  case_mounts();
  case_own();
  case_syscalls();
  char usable[1100] = "";
  char parent[1100] = "";
  if (g_own[0]) {
    snprintf(parent, sizeof parent, "%s", g_own);
    char *sl = strrchr(parent, '/');
    if (sl && sl != parent) *sl = 0; else parent[0] = 0;
  }
  int c_ok, a_ok;
  if (g_own[0] && try_candidate("own_cgroup", g_own, &c_ok, &a_ok) && (c_ok || a_ok) && !usable[0]) snprintf(usable, sizeof usable, "%s", g_own);
  if (parent[0] && strcmp(parent, g_mount) != 0 && try_candidate("parent_of_own_cgroup", parent, &c_ok, &a_ok) && (c_ok || a_ok) && !usable[0]) snprintf(usable, sizeof usable, "%s", parent);
  if (g_mount[0] && strcmp(g_mount, g_own) != 0 && try_candidate("hierarchy_root", g_mount, &c_ok, &a_ok) && (c_ok || a_ok) && !usable[0]) snprintf(usable, sizeof usable, "%s", g_mount);
  case_move_self(usable);
  emit(PROBE, "summary", "\"usable_directory\":\"%s\",\"own_directory\":\"%s\"", usable, g_own);
  if (emit_dir) { FILE *f = fopen(emit_dir, "w"); if (f) { fputs(usable, f); fclose(f); } }
  if (emit_own) { FILE *f = fopen(emit_own, "w"); if (f) { fputs(g_own, f); fclose(f); } }
  return 0;
}

#endif /* __linux__ */
