/*
 * Finding the descendants of a process without process groups or cgroups. A supervisor that wants to kill "everything
 * this child started" has several ways to enumerate the tree; each misses something. The probe builds
 *
 *      probe ── A ──┬── A1                 plain descendants
 *                   └── X ── D             D's parent X exits at once: D is orphaned and reparented; D calls setsid()
 *
 * with an environment tag in every node's environment, then asks each method which of A, A1, D it finds.
 *
 *   walk_ppid            parent-pid table scan, recursively from the probe
 *   kernel_child_lists   macOS proc_listchildpids / Linux /proc/<pid>/task/<tid>/children, recursively
 *   same_process_group   pgid of the probe's own group (the probe is made a group leader first)
 *   same_session         session id of the probe
 *   environment_tag      read every process's environment and look for the tag
 *
 * Build: cc -O1 -Wall -Wextra -o tree_enum tree_enum.c
 */
#include "common.h"
#include <dirent.h>
#include <limits.h>
#include <spawn.h>
#ifdef __APPLE__
#include <libproc.h>
#include <sys/sysctl.h>
#endif
#define PROBE "tree_enum"

extern char **environ;
static char g_self[PATH_MAX];
static const char *g_tag_name = "NATIVE_TREE_TAG";

typedef struct { pid_t pid, ppid, pgid, sid; } procrec;
static procrec *g_tab;
static int g_n;
static int g_sid_errors;

/* ---- node processes ---- */

static pid_t spawn_node(const char *role, int report_fd) {
  char fdbuf[16];
  snprintf(fdbuf, sizeof fdbuf, "%d", report_fd);
  char *argv[] = {g_self, (char *)"--node", (char *)role, fdbuf, NULL};
  pid_t p = 0;
  if (posix_spawn(&p, g_self, NULL, NULL, argv, environ) != 0) return -1;
  return p;
}

static int node_main(const char *role, int fd) {
  alarm(60);
  if (strcmp(role, "D") == 0) setsid();
  char line[64];
  int n = snprintf(line, sizeof line, "%s %d\n", role, (int)getpid());
  (void)!write(fd, line, (size_t)n);
  if (strcmp(role, "A") == 0) {
    signal(SIGCHLD, SIG_IGN); /* X must not stay a zombie of A */
    spawn_node("A1", fd);
    spawn_node("X", fd);
  } else if (strcmp(role, "X") == 0) {
    spawn_node("D", fd);
    return 0;
  }
  for (;;) pause();
}

/* ---- process table ---- */

static unsigned long long linux_start_ticks(pid_t pid) {
#ifdef __linux__
  char path[64], buf[2048];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
  FILE *f = fopen(path, "r");
  if (!f) return 0;
  size_t n = fread(buf, 1, sizeof buf - 1, f);
  fclose(f);
  buf[n] = 0;
  char *rp = strrchr(buf, ')');
  if (!rp) return 0;
  char st;
  int ppid, pgrp, sess;
  unsigned long long start = 0;
  if (sscanf(rp + 2, "%c %d %d %d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu", &st, &ppid, &pgrp, &sess, &start) != 5) return 0;
  return start;
#else
  (void)pid;
  return 0;
#endif
}

static void load_table(void) {
  free(g_tab);
  g_tab = NULL; g_n = 0; g_sid_errors = 0;
#ifdef __APPLE__
  int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
  size_t len = 0;
  if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0) return;
  len += len / 8 + 32 * sizeof(struct kinfo_proc);
  struct kinfo_proc *kp = malloc(len);
  if (!kp || sysctl(mib, 3, kp, &len, NULL, 0) != 0) { free(kp); return; }
  int n = (int)(len / sizeof(struct kinfo_proc));
  g_tab = calloc((size_t)n, sizeof(procrec));
  for (int i = 0; i < n; i++) {
    pid_t pid = kp[i].kp_proc.p_pid;
    g_tab[i].pid = pid;
    g_tab[i].ppid = kp[i].kp_eproc.e_ppid;
    g_tab[i].pgid = kp[i].kp_eproc.e_pgid;
    pid_t s = getsid(pid);
    if (s < 0) { g_sid_errors++; s = -1; }
    g_tab[i].sid = s;
  }
  g_n = n;
  free(kp);
#else
  DIR *d = opendir("/proc");
  if (!d) return;
  int cap = 1024;
  g_tab = calloc((size_t)cap, sizeof(procrec));
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
    char path[300], buf[2048];
    snprintf(path, sizeof path, "/proc/%s/stat", e->d_name);
    FILE *f = fopen(path, "r");
    if (!f) continue;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *rp = strrchr(buf, ')');
    if (!rp) continue;
    char st;
    int ppid, pgrp, sess;
    if (sscanf(rp + 2, "%c %d %d %d", &st, &ppid, &pgrp, &sess) != 4) continue;
    if (g_n == cap) { cap *= 2; g_tab = realloc(g_tab, (size_t)cap * sizeof(procrec)); }
    g_tab[g_n].pid = atoi(e->d_name);
    g_tab[g_n].ppid = ppid;
    g_tab[g_n].pgid = pgrp;
    g_tab[g_n].sid = sess;
    g_n++;
  }
  closedir(d);
#endif
}

/* ---- the answers ---- */

typedef struct { pid_t A, A1, D, X; } truth_t;

static int in_list(const pid_t *l, int n, pid_t p) {
  for (int i = 0; i < n; i++) if (l[i] == p) return 1;
  return 0;
}

static void report(const char *kase, const pid_t *found, int nfound, const truth_t *t, double ms, const char *extra) {
  int extras = 0;
  for (int i = 0; i < nfound; i++) if (found[i] != t->A && found[i] != t->A1 && found[i] != t->D) extras++;
  emit(PROBE, kase, "\"finds_A\":%d,\"finds_A1\":%d,\"finds_D\":%d,\"other_processes_reported\":%d,\"processes_examined\":%d,\"ms\":%.2f%s%s",
       in_list(found, nfound, t->A), in_list(found, nfound, t->A1), in_list(found, nfound, t->D), extras, g_n, ms,
       extra[0] ? "," : "", extra);
}

static int walk_ppid(pid_t root, pid_t *out, int cap) {
  int n = 0;
  pid_t queue[4096];
  int qh = 0, qt = 0;
  queue[qt++] = root;
  while (qh < qt) {
    pid_t cur = queue[qh++];
    for (int i = 0; i < g_n; i++) {
      if (g_tab[i].ppid == cur && g_tab[i].pid != cur && qt < 4096 && n < cap) {
        queue[qt++] = g_tab[i].pid;
        out[n++] = g_tab[i].pid;
      }
    }
  }
  return n;
}

/* direct children according to the kernel's own list; -1 when the interface is missing */
static int kernel_children(pid_t pid, pid_t *out, int cap, int *raw_rc) {
#ifdef __APPLE__
  pid_t buf[512];
  memset(buf, 0, sizeof buf);
  int rc = proc_listchildpids(pid, buf, (int)sizeof buf);
  *raw_rc = rc;
  if (rc < 0) return -1;
  int n = 0;
  for (int i = 0; i < 512 && buf[i] != 0 && n < cap; i++) out[n++] = buf[i];
  return n;
#else
  (void)raw_rc;
  char tdir[64];
  snprintf(tdir, sizeof tdir, "/proc/%d/task", (int)pid);
  DIR *d = opendir(tdir);
  if (!d) return -1;
  int n = 0, any = 0;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
    char path[400];
    snprintf(path, sizeof path, "%s/%s/children", tdir, e->d_name);
    FILE *f = fopen(path, "r");
    if (!f) continue;
    any = 1;
    int c;
    while (fscanf(f, "%d", &c) == 1 && n < cap) out[n++] = c;
    fclose(f);
  }
  closedir(d);
  return any ? n : -1;
#endif
}

static int walk_kernel(pid_t root, pid_t *out, int cap, int *available, int *raw_rc) {
  int n = 0;
  pid_t queue[1024];
  int qh = 0, qt = 0;
  queue[qt++] = root;
  *available = 1;
  while (qh < qt) {
    pid_t cur = queue[qh++];
    pid_t kids[256];
    int k = kernel_children(cur, kids, 256, raw_rc);
    if (k < 0) { *available = 0; return n; }
    for (int i = 0; i < k && qt < 1024 && n < cap; i++) { queue[qt++] = kids[i]; out[n++] = kids[i]; }
  }
  return n;
}

static int has_tag(pid_t pid, const char *needle, char *buf, size_t cap, int *err) {
  size_t len = 0;
#ifdef __APPLE__
  int mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
  len = cap;
  if (sysctl(mib, 3, buf, &len, NULL, 0) != 0) { *err = errno; return 0; }
#else
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/environ", (int)pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { *err = errno; return 0; }
  ssize_t r;
  while (len < cap && (r = read(fd, buf + len, cap - len)) > 0) len += (size_t)r;
  close(fd);
#endif
  size_t nl = strlen(needle);
  for (size_t i = 0; i + nl <= len; i++) if (memcmp(buf + i, needle, nl) == 0) return 1;
  return 0;
}

static void start_times(const truth_t *t) {
#ifdef __APPLE__
  struct proc_bsdinfo bi;
  long long us[3] = {-1, -1, -1};
  pid_t ps[3] = {t->A, t->A1, t->D};
  for (int i = 0; i < 3; i++) {
    if (proc_pidinfo(ps[i], PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == (int)sizeof bi)
      us[i] = (long long)bi.pbi_start_tvsec * 1000000LL + (long long)bi.pbi_start_tvusec;
  }
  emit(PROBE, "start_times", "\"unit\":\"microseconds since epoch\",\"A\":%lld,\"A1_minus_A\":%lld,\"D_minus_A\":%lld",
       us[0], us[1] >= 0 && us[0] >= 0 ? us[1] - us[0] : -1, us[2] >= 0 && us[0] >= 0 ? us[2] - us[0] : -1);
#else
  unsigned long long a = linux_start_ticks(t->A), a1 = linux_start_ticks(t->A1), d = linux_start_ticks(t->D);
  emit(PROBE, "start_times", "\"unit\":\"clock ticks since boot (1/%ld s)\",\"A\":%llu,\"A1_minus_A\":%lld,\"D_minus_A\":%lld",
       sysconf(_SC_CLK_TCK), a, (long long)a1 - (long long)a, (long long)d - (long long)a);
#endif
}

int main(int argc, char **argv) {
  if (!realpath(argv[0], g_self)) snprintf(g_self, sizeof g_self, "%s", argv[0]);
  if (argc > 3 && strcmp(argv[1], "--node") == 0) return node_main(argv[2], atoi(argv[3]));
  watchdog(90);
  setpgid(0, 0); /* own process group, so "same group" means only the probe's tree */
  emit_header(PROBE);

  char tag[128];
  snprintf(tag, sizeof tag, "%s=%d-%ld", g_tag_name, (int)getpid(), (long)time(NULL));
  setenv(g_tag_name, tag + strlen(g_tag_name) + 1, 1);
  /* the nodes inherit the tag through environ at posix_spawn; the probe's own environment (set after exec) is not
     visible to the environment scan, so the probe is not reported as a tagged process */

  int rp[2];
  if (pipe(rp) != 0) return 1;
  pid_t a = spawn_node("A", rp[1]);
  truth_t t = {a, 0, 0, 0};
  char lines[512];
  size_t have = 0;
  int got = 0;
  double end = now_ms() + 8000;
  while (now_ms() < end && got < 3) {
    ssize_t r = read_timeout(rp[0], lines + have, sizeof lines - 1 - have, 200);
    if (r <= 0) continue;
    have += (size_t)r;
    lines[have] = 0;
    char copy[512];
    memcpy(copy, lines, have + 1);
    got = 0;
    char *save = NULL;
    for (char *ln = strtok_r(copy, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
      char role[16];
      int pid;
      if (sscanf(ln, "%15s %d", role, &pid) != 2) continue;
      if (!strcmp(role, "A")) { t.A = pid; got++; }
      else if (!strcmp(role, "A1")) { t.A1 = pid; got++; }
      else if (!strcmp(role, "D")) { t.D = pid; got++; }
    }
  }
  if (got < 3) {
    emit(PROBE, "setup", "\"error\":\"nodes did not report\",\"A\":%d,\"A1\":%d,\"D\":%d", (int)t.A, (int)t.A1, (int)t.D);
    if (t.A > 0) kill(t.A, SIGKILL);
    return 0;
  }
  sleep_ms(300); /* let X exit and D be reparented */

  /* where did D end up? */
  load_table();
  pid_t dparent = -1, a1parent = -1;
  for (int i = 0; i < g_n; i++) {
    if (g_tab[i].pid == t.D) dparent = g_tab[i].ppid;
    if (g_tab[i].pid == t.A1) a1parent = g_tab[i].ppid;
  }
  emit(PROBE, "tree", "\"probe\":%d,\"A\":%d,\"A1_parent\":%d,\"D\":%d,\"D_parent\":%d,\"D_reparented_to_pid_1\":%d",
       (int)getpid(), (int)t.A, (int)a1parent, (int)t.D, (int)dparent, dparent == 1);

  pid_t found[4096];
  double t0 = now_ms();
  load_table();
  int n = walk_ppid(getpid(), found, 4096);
  report("walk_ppid", found, n, &t, now_ms() - t0, "");

  t0 = now_ms();
  int avail = 1, raw = 0;
  n = walk_kernel(getpid(), found, 4096, &avail, &raw);
  char extra[256];
  snprintf(extra, sizeof extra, "\"interface_available\":%d,\"raw_return_of_last_call\":%d", avail, raw);
  report("kernel_child_lists", found, n, &t, now_ms() - t0, extra);

  t0 = now_ms();
  load_table();
  n = 0;
  pid_t mypg = getpgrp(), mysid = getsid(0);
  for (int i = 0; i < g_n && n < 4096; i++) if (g_tab[i].pgid == mypg && g_tab[i].pid != getpid()) found[n++] = g_tab[i].pid;
  report("same_process_group", found, n, &t, now_ms() - t0, "");

  t0 = now_ms();
  load_table();
  n = 0;
  for (int i = 0; i < g_n && n < 4096; i++) if (g_tab[i].sid == mysid && g_tab[i].pid != getpid()) found[n++] = g_tab[i].pid;
  snprintf(extra, sizeof extra, "\"getsid_failures_for_other_processes\":%d", g_sid_errors);
  report("same_session", found, n, &t, now_ms() - t0, extra);

  t0 = now_ms();
  load_table();
  size_t cap = 1u << 20;
  char *buf = malloc(cap);
  n = 0;
  int errs = 0, eacces = 0, other_err = 0;
  int hist_code[8] = {0}, hist_n[8] = {0}, hist_used = 0;
  char needle[160];
  snprintf(needle, sizeof needle, "%s=", g_tag_name);
  strncat(needle, getenv(g_tag_name), sizeof needle - strlen(needle) - 1);
  for (int i = 0; i < g_n && n < 4096; i++) {
    if (g_tab[i].pid == getpid()) continue;
    int err = 0;
    if (has_tag(g_tab[i].pid, needle, buf, cap, &err)) found[n++] = g_tab[i].pid;
    else if (err) {
      errs++;
      if (err == EACCES || err == EPERM) eacces++; else other_err++;
      int k = 0;
      while (k < hist_used && hist_code[k] != err) k++;
      if (k == hist_used && hist_used < 8) { hist_code[hist_used] = err; hist_n[hist_used] = 0; hist_used++; }
      if (k < hist_used) hist_n[k]++;
    }
  }
  {
    size_t el = (size_t)snprintf(extra, sizeof extra, "\"unreadable_processes\":%d,\"of_which_permission_denied\":%d,\"of_which_other_errors\":%d,\"errors\":{", errs, eacces, other_err);
    for (int k = 0; k < hist_used && el < sizeof extra - 40; k++)
      el += (size_t)snprintf(extra + el, sizeof extra - el, "%s\"%s(%d)\":%d", k ? "," : "", errno_name(hist_code[k]), hist_code[k], hist_n[k]);
    snprintf(extra + el, sizeof extra - el, "}");
  }
  report("environment_tag", found, n, &t, now_ms() - t0, extra);
  free(buf);

  start_times(&t);

  /* cleanup: kill by the tag-found set, as a supervisor would */
  kill(t.D, SIGKILL);
  kill(t.A1, SIGKILL);
  kill(t.A, SIGKILL);
  int st;
  waitpid(t.A, &st, 0);
  return 0;
}
