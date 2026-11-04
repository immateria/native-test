/*
 * Process-group signalling matrix. Standalone, no Crystal. Records, as JSON lines,
 * what kill()/killpg() return for process groups in each state the qualification kit's
 * group controller can meet: live, zombie (exited, not yet reaped), mixed, reaped.
 *
 * Question it answers: the kit saw killpg(KILL) fail with EPERM on macOS when it escalated
 * TERM -> KILL with a 0 ms / 10 ms grace. Is EPERM what macOS returns for a group whose
 * members are all zombies, and how does that differ from Linux?
 *
 * Build: cc -O1 -Wall -o signal_matrix signal_matrix.c      (macOS and Linux)
 * Every signal targets a process or group created by this program.
 */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *errname(int e) {
  switch (e) {
  case 0: return "-";
  case EPERM: return "EPERM";
  case ESRCH: return "ESRCH";
  case EINVAL: return "EINVAL";
  case ECHILD: return "ECHILD";
  case EACCES: return "EACCES";
  default: return "OTHER";
  }
}

static double mono_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void rec(const char *scenario, const char *state, const char *call, int rc, int err) {
  printf("{\"scenario\":\"%s\",\"state\":\"%s\",\"call\":\"%s\",\"rc\":%d,\"errno\":%d,\"errno_name\":\"%s\"}\n",
         scenario, state, call, rc, rc < 0 ? err : 0, rc < 0 ? errname(err) : "-");
  fflush(stdout);
}

#define CALL(scn, st, label, expr) do { errno = 0; int _rc = (expr); int _e = errno; rec(scn, st, label, _rc, _e); } while (0)

/* exited but not reaped? (does not reap) */
static int is_zombie(pid_t pid) {
  siginfo_t si;
  memset(&si, 0, sizeof si);
  int rc = waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT);
  return rc == 0 && si.si_pid == pid;
}

static int wait_zombie(pid_t pid, int timeout_ms) {
  double start = mono_us();
  while ((mono_us() - start) < timeout_ms * 1000.0) {
    if (is_zombie(pid)) return 1;
    usleep(200);
  }
  return 0;
}

static int wait_gone(pid_t pid, int timeout_ms) {
  double start = mono_us();
  while ((mono_us() - start) < timeout_ms * 1000.0) {
    errno = 0;
    if (kill(pid, 0) < 0 && errno == ESRCH) return 1;
    usleep(500);
  }
  return 0;
}

/* child in its own process group, alive until killed */
static pid_t spawn_leader(void) {
  pid_t p = fork();
  if (p == 0) {
    setpgid(0, 0);
    for (;;) sleep(30);
  }
  setpgid(p, p); /* also from the parent, so the group exists before we return */
  return p;
}

static void probe_group(const char *scn, const char *state, pid_t pid, pid_t pgid) {
  CALL(scn, state, "kill(pid,0)", kill(pid, 0));
  CALL(scn, state, "kill(-pgid,0)", kill(-pgid, 0));
  CALL(scn, state, "killpg(pgid,0)", killpg(pgid, 0));
}

static void signal_group(const char *scn, const char *state, pid_t pid, pid_t pgid) {
  CALL(scn, state, "kill(pid,SIGTERM)", kill(pid, SIGTERM));
  CALL(scn, state, "kill(pid,SIGKILL)", kill(pid, SIGKILL));
  CALL(scn, state, "killpg(pgid,SIGTERM)", killpg(pgid, SIGTERM));
  CALL(scn, state, "killpg(pgid,SIGKILL)", killpg(pgid, SIGKILL));
}

/* A: single child that is its own group leader */
static void scenario_a(void) {
  pid_t p = spawn_leader();
  pid_t g = p;
  usleep(20000);
  probe_group("A_leader_only", "alive", p, g);

  /* timeline: what do the probes return between SIGKILL and the zombie state? */
  double t0 = mono_us();
  kill(p, SIGKILL);
  int last_k = -2, last_kg = -2, last_z = -2, last_ek = -2, last_ekg = -2;
  for (int i = 0; i < 4000; i++) {
    errno = 0; int k = kill(p, 0); int ek = k < 0 ? errno : 0;
    errno = 0; int kg = kill(-g, 0); int ekg = kg < 0 ? errno : 0;
    int z = is_zombie(p);
    if (k != last_k || ek != last_ek || kg != last_kg || ekg != last_ekg || z != last_z) {
      printf("{\"scenario\":\"A_leader_only\",\"state\":\"transition\",\"t_us\":%.0f,"
             "\"kill_pid\":\"%s\",\"kill_group\":\"%s\",\"zombie\":%d}\n",
             mono_us() - t0, k == 0 ? "ok" : errname(ek), kg == 0 ? "ok" : errname(ekg), z);
      fflush(stdout);
      last_k = k; last_ek = ek; last_kg = kg; last_ekg = ekg; last_z = z;
    }
    if (z && i > 50) break;
    usleep(100);
  }
  wait_zombie(p, 1000);
  probe_group("A_leader_only", "zombie_unreaped", p, g);
  signal_group("A_leader_only", "zombie_unreaped", p, g);

  int st;
  waitpid(p, &st, 0);
  probe_group("A_leader_only", "reaped", p, g);
  signal_group("A_leader_only", "reaped", p, g);
}

/* B: group leader is a zombie while a member is still alive */
static void scenario_b(void) {
  int fds[2];
  if (pipe(fds) != 0) return;
  pid_t leader = fork();
  if (leader == 0) {
    setpgid(0, 0);
    pid_t m = fork();
    if (m == 0) {
      for (;;) sleep(30);
    }
    if (write(fds[1], &m, sizeof m) < 0) _exit(2);
    _exit(0); /* leader exits; its child keeps the group alive */
  }
  setpgid(leader, leader);
  pid_t member = 0;
  if (read(fds[0], &member, sizeof member) != sizeof member) return;
  pid_t g = leader;
  wait_zombie(leader, 1000);
  CALL("B_leader_zombie_member_alive", "leader_zombie", "kill(leader,0)", kill(leader, 0));
  CALL("B_leader_zombie_member_alive", "leader_zombie", "kill(member,0)", kill(member, 0));
  CALL("B_leader_zombie_member_alive", "leader_zombie", "kill(-pgid,0)", kill(-g, 0));
  CALL("B_leader_zombie_member_alive", "leader_zombie", "killpg(pgid,SIGKILL)", killpg(g, SIGKILL));
  int gone = wait_gone(member, 2000);
  printf("{\"scenario\":\"B_leader_zombie_member_alive\",\"state\":\"member_reaped_by_init\",\"gone\":%d}\n", gone);
  fflush(stdout);
  CALL("B_leader_zombie_member_alive", "only_leader_zombie_left", "kill(leader,0)", kill(leader, 0));
  CALL("B_leader_zombie_member_alive", "only_leader_zombie_left", "kill(-pgid,0)", kill(-g, 0));
  CALL("B_leader_zombie_member_alive", "only_leader_zombie_left", "killpg(pgid,SIGKILL)", killpg(g, SIGKILL));
  CALL("B_leader_zombie_member_alive", "only_leader_zombie_left", "killpg(pgid,SIGTERM)", killpg(g, SIGTERM));
  int st;
  waitpid(leader, &st, 0);
  CALL("B_leader_zombie_member_alive", "reaped", "kill(-pgid,0)", kill(-g, 0));
  CALL("B_leader_zombie_member_alive", "reaped", "killpg(pgid,SIGKILL)", killpg(g, SIGKILL));
}

/* D: a group made only of our own children, all killed, reaped one at a time (the kit's shape) */
static void scenario_d(void) {
  pid_t a = spawn_leader();
  pid_t g = a;
  pid_t b = fork();
  if (b == 0) {
    setpgid(0, g);
    for (;;) sleep(30);
  }
  setpgid(b, g);
  usleep(20000);
  kill(a, SIGKILL);
  kill(b, SIGKILL);
  wait_zombie(a, 1000);
  wait_zombie(b, 1000);
  CALL("D_two_children_one_group", "both_zombie", "kill(-pgid,0)", kill(-g, 0));
  CALL("D_two_children_one_group", "both_zombie", "killpg(pgid,SIGKILL)", killpg(g, SIGKILL));
  CALL("D_two_children_one_group", "both_zombie", "killpg(pgid,SIGTERM)", killpg(g, SIGTERM));
  int st;
  waitpid(a, &st, 0);
  CALL("D_two_children_one_group", "leader_reaped_member_zombie", "kill(-pgid,0)", kill(-g, 0));
  CALL("D_two_children_one_group", "leader_reaped_member_zombie", "killpg(pgid,SIGKILL)", killpg(g, SIGKILL));
  waitpid(b, &st, 0);
  CALL("D_two_children_one_group", "all_reaped", "kill(-pgid,0)", kill(-g, 0));
  CALL("D_two_children_one_group", "all_reaped", "killpg(pgid,SIGKILL)", killpg(g, SIGKILL));
}

/* E: the kit's escalation: SIGTERM, wait `gap_ms`, SIGKILL. Many trials, count outcomes of the KILL. */
static void scenario_e(int gap_ms, int trials) {
  int ok = 0, eperm = 0, esrch = 0, other = 0, zombie_at_kill = 0;
  for (int i = 0; i < trials; i++) {
    pid_t p = spawn_leader();
    pid_t g = p;
    usleep(2000);
    killpg(g, SIGTERM);
    if (gap_ms > 0) usleep(gap_ms * 1000);
    int z = is_zombie(p);
    errno = 0;
    int rc = killpg(g, SIGKILL);
    int e = errno;
    if (z) zombie_at_kill++;
    if (rc == 0) ok++;
    else if (e == EPERM) eperm++;
    else if (e == ESRCH) esrch++;
    else other++;
    int st;
    waitpid(p, &st, 0);
  }
  printf("{\"scenario\":\"E_term_then_kill\",\"gap_ms\":%d,\"trials\":%d,\"kill_ok\":%d,\"kill_EPERM\":%d,"
         "\"kill_ESRCH\":%d,\"kill_other\":%d,\"leader_already_zombie_at_kill\":%d}\n",
         gap_ms, trials, ok, eperm, esrch, other, zombie_at_kill);
  fflush(stdout);
}

int main(void) {
  struct utsname u;
  uname(&u);
  printf("{\"scenario\":\"environment\",\"sysname\":\"%s\",\"release\":\"%s\",\"machine\":\"%s\"}\n",
         u.sysname, u.release, u.machine);
  scenario_a();
  scenario_b();
  scenario_d();
  scenario_e(0, 300);
  scenario_e(1, 300);
  scenario_e(10, 300);
  scenario_e(50, 100);
  return 0;
}
