#define _DARWIN_C_SOURCE 1
/*
 * Independent macOS SDK/libproc qualification companion for checkpoint 0009, probe revision 12.
 * This intentionally does not share the Crystal FFI definitions. It exercises
 * the SDK's proc_bsdinfo layout and a bounded set of libproc behaviors using
 * only this process and children it creates. Never run elevated.
 */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <sys/proc_info.h>

#ifndef PROC_PIDT_SHORTBSDINFO
#define PROC_PIDT_SHORTBSDINFO 13
#endif

#define PROBE_SSTOP 4U
#define PROBE_SZOMB 5U

static int failures = 0;
static int cases = 0;

static void nap_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
}

static void record(const char *name, int pass, const char *details) {
    ++cases;
    if (!pass) ++failures;
    printf("{\"schema\":1,\"platform\":\"macos\",\"source\":\"native-sdk-c\",\"case\":\"%s\",\"status\":\"%s\",\"details\":{%s}}\n",
           name, pass ? "pass" : "fail", details ? details : "");
    fflush(stdout);
}

static int read_bsd(pid_t pid, struct proc_bsdinfo *info, int *saved_errno) {
    memset(info, 0, sizeof(*info));
    errno = 0;
    int rc = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, (int)sizeof(*info));
    *saved_errno = errno;
    return rc;
}

static int wait_for_status(pid_t pid, uint32_t wanted, struct proc_bsdinfo *out, int *last_errno) {
    for (int i = 0; i < 100; ++i) {
        int e = 0;
        int rc = read_bsd(pid, out, &e);
        if (rc == (int)sizeof(*out) && out->pbi_status == wanted) {
            *last_errno = e;
            return 1;
        }
        *last_errno = e;
        nap_ms(10);
    }
    return 0;
}

static int contains_pid(const int *pids, int count, int pid) {
    for (int i = 0; i < count; ++i) if (pids[i] == pid) return 1;
    return 0;
}

static int read_kinfo(pid_t pid, struct kinfo_proc *info, size_t *returned, int *saved_errno) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    size_t len = sizeof(*info);
    memset(info, 0, sizeof(*info));
    errno = 0;
    int rc = sysctl(mib, 4, info, &len, NULL, 0);
    *returned = len;
    *saved_errno = errno;
    return rc;
}

static int read_all_kinfo(struct kinfo_proc **entries, size_t *count, size_t *returned, int *saved_errno) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    *entries = NULL;
    *count = 0;
    *returned = 0;
    *saved_errno = 0;

    for (int attempt = 0; attempt < 4; ++attempt) {
        size_t len = 0;
        errno = 0;
        if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
            *saved_errno = errno;
            return -1;
        }
        size_t capacity = len + 4 * sizeof(struct kinfo_proc);
        struct kinfo_proc *buffer = calloc(1, capacity);
        if (!buffer) {
            *saved_errno = ENOMEM;
            return -1;
        }
        size_t actual = capacity;
        errno = 0;
        if (sysctl(mib, 4, buffer, &actual, NULL, 0) == 0) {
            *entries = buffer;
            *returned = actual;
            *count = actual / sizeof(struct kinfo_proc);
            return 0;
        }
        int e = errno;
        free(buffer);
        if (e != ENOMEM) {
            *saved_errno = e;
            return -1;
        }
    }
    *saved_errno = ENOMEM;
    return -1;
}

static struct kinfo_proc *find_kinfo(struct kinfo_proc *entries, size_t count, pid_t pid) {
    for (size_t i = 0; i < count; ++i) {
        if (entries[i].kp_proc.p_pid == pid) return &entries[i];
    }
    return NULL;
}

int main(void) {
    struct proc_bsdinfo self = {0};
    int self_errno = 0;
    const int self_rc = read_bsd(getpid(), &self, &self_errno);
    char d[2048];

    snprintf(d, sizeof(d),
             "\"sizeof\":%zu,\"returned\":%d,\"errno\":%d,"
             "\"offset_pid\":%zu,\"offset_status\":%zu,\"offset_ppid\":%zu,\"offset_pgid\":%zu,"
             "\"offset_start_sec\":%zu,\"offset_start_usec\":%zu",
             sizeof(struct proc_bsdinfo), self_rc, self_errno,
             offsetof(struct proc_bsdinfo, pbi_pid), offsetof(struct proc_bsdinfo, pbi_status),
             offsetof(struct proc_bsdinfo, pbi_ppid), offsetof(struct proc_bsdinfo, pbi_pgid),
             offsetof(struct proc_bsdinfo, pbi_start_tvsec), offsetof(struct proc_bsdinfo, pbi_start_tvusec));
    record("native_sdk_proc_bsdinfo_abi",
           sizeof(struct proc_bsdinfo) == 136 && self_rc == (int)sizeof(struct proc_bsdinfo) &&
           offsetof(struct proc_bsdinfo, pbi_start_tvsec) == 120 && offsetof(struct proc_bsdinfo, pbi_start_tvusec) == 128,
           d);

    snprintf(d, sizeof(d),
             "\"pid\":%u,\"expected_pid\":%d,\"ppid\":%u,\"expected_ppid\":%d,\"pgid\":%u,\"expected_pgid\":%d,\"status\":%u,\"start_sec\":%llu,\"start_usec\":%llu",
             (unsigned)self.pbi_pid, (int)getpid(), (unsigned)self.pbi_ppid, (int)getppid(),
             (unsigned)self.pbi_pgid, (int)getpgrp(), (unsigned)self.pbi_status,
             (unsigned long long)self.pbi_start_tvsec, (unsigned long long)self.pbi_start_tvusec);
    record("native_sdk_proc_bsdinfo_self_fields",
           self_rc == (int)sizeof(self) && self.pbi_pid == (uint32_t)getpid() &&
           self.pbi_ppid == (uint32_t)getppid() && self.pbi_pgid == (uint32_t)getpgrp() &&
           self.pbi_start_tvsec != 0 && self.pbi_start_tvusec < 1000000ULL,
           d);

    int repeat_ok = 1;
    for (int i = 0; i < 64; ++i) {
        struct proc_bsdinfo cur;
        int e = 0;
        int rc = read_bsd(getpid(), &cur, &e);
        if (rc != (int)sizeof(cur) || cur.pbi_start_tvsec != self.pbi_start_tvsec ||
            cur.pbi_start_tvusec != self.pbi_start_tvusec || cur.pbi_pid != self.pbi_pid) {
            repeat_ok = 0;
            break;
        }
    }
    snprintf(d, sizeof(d), "\"reads\":64,\"start_sec\":%llu,\"start_usec\":%llu",
             (unsigned long long)self.pbi_start_tvsec, (unsigned long long)self.pbi_start_tvusec);
    record("native_sdk_proc_bsdinfo_generation_stable_64_reads", repeat_ok, d);

    struct proc_bsdinfo missing;
    int missing_errno = 0;
    int missing_rc = read_bsd(INT_MAX, &missing, &missing_errno);
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d", missing_rc, missing_errno);
    record("native_sdk_proc_bsdinfo_missing_pid", missing_rc == 0 && (missing_errno == ESRCH || missing_errno == 0), d);

    struct proc_bsdinfo pid1;
    int pid1_errno = 0;
    int pid1_rc = read_bsd(1, &pid1, &pid1_errno);
    int pid1_ok = pid1_rc == (int)sizeof(pid1) || (pid1_rc == 0 && (pid1_errno == EPERM || pid1_errno == EACCES || pid1_errno == ESRCH || pid1_errno == 0));
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"status\":%u,\"pid\":%u", pid1_rc, pid1_errno, (unsigned)pid1.pbi_status, (unsigned)pid1.pbi_pid);
    record("native_sdk_proc_bsdinfo_pid1_permission_classification", pid1_ok, d);

    struct proc_bsdshortinfo shortinfo;
    memset(&shortinfo, 0, sizeof(shortinfo));
    errno = 0;
    int short_rc = proc_pidinfo(getpid(), PROC_PIDT_SHORTBSDINFO, 0, &shortinfo, (int)sizeof(shortinfo));
    int short_errno = errno;
    snprintf(d, sizeof(d), "\"sizeof\":%zu,\"returned\":%d,\"errno\":%d,\"pid\":%u,\"ppid\":%u,\"pgid\":%u,\"status\":%u",
             sizeof(shortinfo), short_rc, short_errno, (unsigned)shortinfo.pbsi_pid, (unsigned)shortinfo.pbsi_ppid,
             (unsigned)shortinfo.pbsi_pgid, (unsigned)shortinfo.pbsi_status);
    record("native_sdk_proc_bsdshortinfo_self_fields",
           short_rc == (int)sizeof(shortinfo) && shortinfo.pbsi_pid == (uint32_t)getpid() &&
           shortinfo.pbsi_ppid == (uint32_t)getppid() && shortinfo.pbsi_pgid == (uint32_t)getpgrp(), d);

    struct kinfo_proc self_kp;
    size_t self_kp_len = 0;
    int self_kp_errno = 0;
    int self_kp_rc = read_kinfo(getpid(), &self_kp, &self_kp_len, &self_kp_errno);
    size_t kp_stat_offset = offsetof(struct kinfo_proc, kp_proc) + offsetof(struct extern_proc, p_stat);
    size_t kp_pid_offset = offsetof(struct kinfo_proc, kp_proc) + offsetof(struct extern_proc, p_pid);
    size_t kp_start_offset = offsetof(struct kinfo_proc, kp_proc) + offsetof(struct extern_proc, p_starttime);
    size_t kp_start_usec_offset = kp_start_offset + offsetof(struct timeval, tv_usec);
    snprintf(d, sizeof(d),
             "\"sizeof\":%zu,\"returned\":%zu,\"rc\":%d,\"errno\":%d,"
             "\"offset_status\":%zu,\"offset_pid\":%zu,\"offset_start_sec\":%zu,\"offset_start_usec\":%zu,\"sizeof_timeval\":%zu",
             sizeof(struct kinfo_proc), self_kp_len, self_kp_rc, self_kp_errno, kp_stat_offset, kp_pid_offset,
             kp_start_offset, kp_start_usec_offset, sizeof(struct timeval));
    record("native_sdk_kinfo_proc_abi",
           self_kp_rc == 0 && self_kp_len == sizeof(struct kinfo_proc) &&
           kp_stat_offset == 36 && kp_pid_offset == 40 && kp_start_offset == 0 && kp_start_usec_offset == 8 &&
           sizeof(struct timeval) == 16, d);

    snprintf(d, sizeof(d),
             "\"pid\":%d,\"expected_pid\":%d,\"ppid\":%d,\"expected_ppid\":%d,\"pgid\":%d,\"expected_pgid\":%d,\"status\":%d,\"start_sec\":%lld,\"start_usec\":%d",
             self_kp.kp_proc.p_pid, (int)getpid(), self_kp.kp_eproc.e_ppid, (int)getppid(),
             self_kp.kp_eproc.e_pgid, (int)getpgrp(), self_kp.kp_proc.p_stat,
             (long long)self_kp.kp_proc.p_starttime.tv_sec, (int)self_kp.kp_proc.p_starttime.tv_usec);
    record("native_sdk_kern_proc_pid_self_fields",
           self_kp_rc == 0 && self_kp.kp_proc.p_pid == getpid() &&
           self_kp.kp_eproc.e_ppid == getppid() && self_kp.kp_eproc.e_pgid == getpgrp() &&
           self_kp.kp_proc.p_starttime.tv_sec > 0, d);

    pid_t kp_zombie = fork();
    if (kp_zombie == 0) _exit(31);
    if (kp_zombie > 0) {
        struct kinfo_proc zi;
        size_t zlen = 0;
        int ze = 0;
        int zrc = -1;
        int found = 0;
        for (int i = 0; i < 100; ++i) {
            zrc = read_kinfo(kp_zombie, &zi, &zlen, &ze);
            if (zrc == 0 && zlen == sizeof(zi) && zi.kp_proc.p_stat == PROBE_SZOMB) {
                found = 1;
                break;
            }
            nap_ms(10);
        }
        snprintf(d, sizeof(d),
                 "\"pid\":%d,\"found\":%s,\"rc\":%d,\"returned\":%zu,\"errno\":%d,\"status\":%d,\"reported_pid\":%d,\"start_sec\":%lld,\"start_usec\":%d",
                 (int)kp_zombie, found ? "true" : "false", zrc, zlen, ze, zi.kp_proc.p_stat,
                 zi.kp_proc.p_pid, (long long)zi.kp_proc.p_starttime.tv_sec, (int)zi.kp_proc.p_starttime.tv_usec);
        record("native_sdk_kern_proc_pid_zombie_state",
               found && zi.kp_proc.p_pid == kp_zombie && zi.kp_proc.p_starttime.tv_sec > 0, d);
        (void)waitpid(kp_zombie, NULL, 0);
    } else {
        record("native_sdk_kern_proc_pid_zombie_state", 0, "\"fork_errno\":1");
    }

    pid_t live = fork();
    if (live == 0) {
        nap_ms(1500);
        _exit(0);
    }
    if (live > 0) {
        struct proc_bsdinfo ci;
        int ce = 0;
        int crc = read_bsd(live, &ci, &ce);
        snprintf(d, sizeof(d), "\"pid\":%d,\"returned\":%d,\"errno\":%d,\"reported_pid\":%u,\"ppid\":%u,\"pgid\":%u,\"status\":%u",
                 (int)live, crc, ce, (unsigned)ci.pbi_pid, (unsigned)ci.pbi_ppid, (unsigned)ci.pbi_pgid, (unsigned)ci.pbi_status);
        record("native_sdk_proc_bsdinfo_live_child", crc == (int)sizeof(ci) && ci.pbi_pid == (uint32_t)live && ci.pbi_ppid == (uint32_t)getpid(), d);
        kill(live, SIGKILL);
        (void)waitpid(live, NULL, 0);
    } else {
        record("native_sdk_proc_bsdinfo_live_child", 0, "\"fork_errno\":1");
    }

    pid_t zombie = fork();
    if (zombie == 0) _exit(23);
    if (zombie > 0) {
        struct proc_bsdinfo zi;
        int ze = 0;
        int found = wait_for_status(zombie, PROBE_SZOMB, &zi, &ze);
        snprintf(d, sizeof(d), "\"pid\":%d,\"found\":%s,\"status\":%u,\"errno\":%d,\"start_sec\":%llu,\"start_usec\":%llu",
                 (int)zombie, found ? "true" : "false", (unsigned)zi.pbi_status, ze,
                 (unsigned long long)zi.pbi_start_tvsec, (unsigned long long)zi.pbi_start_tvusec);
        record("native_sdk_proc_bsdinfo_zombie_visibility_classification",
               (found && zi.pbi_status == PROBE_SZOMB) || (!found && ze == ESRCH), d);
        (void)waitpid(zombie, NULL, 0);
    } else {
        record("native_sdk_proc_bsdinfo_zombie_visibility_classification", 0, "\"fork_errno\":1");
    }

    pid_t stopped = fork();
    if (stopped == 0) {
        for (;;) pause();
    }
    if (stopped > 0) {
        kill(stopped, SIGSTOP);
        struct proc_bsdinfo si;
        int se = 0;
        int found = wait_for_status(stopped, PROBE_SSTOP, &si, &se);
        snprintf(d, sizeof(d), "\"pid\":%d,\"found\":%s,\"status\":%u,\"errno\":%d",
                 (int)stopped, found ? "true" : "false", (unsigned)si.pbi_status, se);
        record("native_sdk_proc_bsdinfo_stopped_state", found && si.pbi_status == PROBE_SSTOP, d);
        kill(stopped, SIGKILL);
        (void)waitpid(stopped, NULL, 0);
    } else {
        record("native_sdk_proc_bsdinfo_stopped_state", 0, "\"fork_errno\":1");
    }

    int group_pids[512];
    memset(group_pids, 0, sizeof(group_pids));
    errno = 0;
    int group_count = proc_listpgrppids(getpgrp(), group_pids, (int)sizeof(group_pids));
    int group_errno = errno;
    snprintf(d, sizeof(d), "\"count\":%d,\"errno\":%d,\"contains_self\":%s",
             group_count, group_errno, (group_count > 0 && contains_pid(group_pids, group_count, getpid())) ? "true" : "false");
    record("native_sdk_proc_listpgrppids_contains_self",
           group_count > 0 && contains_pid(group_pids, group_count, getpid()), d);

    int child_pids[512];
    memset(child_pids, 0, sizeof(child_pids));
    pid_t listed = fork();
    if (listed == 0) {
        nap_ms(1200);
        _exit(0);
    }
    if (listed > 0) {
        nap_ms(30);
        errno = 0;
        int child_count = proc_listchildpids(getpid(), child_pids, (int)sizeof(child_pids));
        int child_errno = errno;
        snprintf(d, sizeof(d), "\"count\":%d,\"errno\":%d,\"expected_child\":%d,\"contains_child\":%s",
                 child_count, child_errno, (int)listed,
                 (child_count > 0 && contains_pid(child_pids, child_count, listed)) ? "true" : "false");
        record("native_sdk_proc_listchildpids_contains_owned_child",
               child_count > 0 && contains_pid(child_pids, child_count, listed), d);
        kill(listed, SIGKILL);
        (void)waitpid(listed, NULL, 0);
    } else {
        record("native_sdk_proc_listchildpids_contains_owned_child", 0, "\"fork_errno\":1");
    }

    char namebuf[PROC_PIDPATHINFO_MAXSIZE];
    memset(namebuf, 0, sizeof(namebuf));
    errno = 0;
    int name_rc = proc_name(getpid(), namebuf, (uint32_t)sizeof(namebuf));
    int name_errno = errno;
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"nonempty\":%s",
             name_rc, name_errno, (name_rc > 0 && namebuf[0] != '\0') ? "true" : "false");
    record("native_sdk_proc_name_self", name_rc > 0 && namebuf[0] != '\0', d);


    /* Revision-6 independent SDK matrix. These checks intentionally use the
     * active SDK directly rather than the Crystal FFI declarations. */
    int all_pids[4096];
    memset(all_pids, 0, sizeof(all_pids));
    errno = 0;
    int all_count = proc_listallpids(all_pids, (int)sizeof(all_pids));
    int all_errno = errno;
    snprintf(d, sizeof(d), "\"count\":%d,\"errno\":%d,\"contains_self\":%s",
             all_count, all_errno, (all_count > 0 && contains_pid(all_pids, all_count, getpid())) ? "true" : "false");
    record("native_sdk_proc_listallpids_contains_self",
           all_count > 0 && contains_pid(all_pids, all_count, getpid()), d);

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    memset(pathbuf, 0, sizeof(pathbuf));
    errno = 0;
    int path_rc = proc_pidpath(getpid(), pathbuf, (uint32_t)sizeof(pathbuf));
    int path_errno = errno;
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"nonempty\":%s",
             path_rc, path_errno, (path_rc > 0 && pathbuf[0] != '\0') ? "true" : "false");
    record("native_sdk_proc_pidpath_self", path_rc > 0 && pathbuf[0] != '\0', d);

    memset(pathbuf, 0, sizeof(pathbuf));
    errno = 0;
    int missing_path_rc = proc_pidpath(INT_MAX, pathbuf, (uint32_t)sizeof(pathbuf));
    int missing_path_errno = errno;
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d", missing_path_rc, missing_path_errno);
    record("native_sdk_proc_pidpath_missing_pid_classification",
           missing_path_rc <= 0 && (missing_path_errno == ESRCH || missing_path_errno == EPERM || missing_path_errno == EINVAL || missing_path_errno == 0), d);

    memset(namebuf, 0, sizeof(namebuf));
    errno = 0;
    int missing_name_rc = proc_name(INT_MAX, namebuf, (uint32_t)sizeof(namebuf));
    int missing_name_errno = errno;
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d", missing_name_rc, missing_name_errno);
    record("native_sdk_proc_name_missing_pid_classification", missing_name_rc <= 0, d);

    struct proc_bsdinfo invalid_info;
    memset(&invalid_info, 0, sizeof(invalid_info));
    errno = 0;
    int invalid_flavor_rc = proc_pidinfo(getpid(), INT_MAX, 0, &invalid_info, (int)sizeof(invalid_info));
    int invalid_flavor_errno = errno;
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d", invalid_flavor_rc, invalid_flavor_errno);
    record("native_sdk_proc_pidinfo_invalid_flavor", invalid_flavor_rc != (int)sizeof(invalid_info), d);

    errno = 0;
    int zero_buffer_rc = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, NULL, 0);
    int zero_buffer_errno = errno;
    snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d", zero_buffer_rc, zero_buffer_errno);
    record("native_sdk_proc_pidinfo_zero_buffer_classification", zero_buffer_rc != (int)sizeof(struct proc_bsdinfo), d);

    unsigned char shortbuf[sizeof(struct proc_bsdinfo) - 1];
    memset(shortbuf, 0, sizeof(shortbuf));
    errno = 0;
    int short_buffer_rc = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, shortbuf, (int)sizeof(shortbuf));
    int short_buffer_errno = errno;
    snprintf(d, sizeof(d), "\"buffer_size\":%zu,\"returned\":%d,\"errno\":%d", sizeof(shortbuf), short_buffer_rc, short_buffer_errno);
    record("native_sdk_proc_pidinfo_short_buffer_classification", short_buffer_rc != (int)sizeof(struct proc_bsdinfo), d);

    int same_self_generation = self_kp_rc == 0 && self_rc == (int)sizeof(self) &&
                               self.pbi_start_tvsec == (uint64_t)self_kp.kp_proc.p_starttime.tv_sec &&
                               self.pbi_start_tvusec == (uint64_t)self_kp.kp_proc.p_starttime.tv_usec;
    snprintf(d, sizeof(d), "\"bsd_sec\":%llu,\"bsd_usec\":%llu,\"kinfo_sec\":%lld,\"kinfo_usec\":%d",
             (unsigned long long)self.pbi_start_tvsec, (unsigned long long)self.pbi_start_tvusec,
             (long long)self_kp.kp_proc.p_starttime.tv_sec, (int)self_kp.kp_proc.p_starttime.tv_usec);
    record("native_sdk_proc_bsdinfo_same_generation_as_kinfo_self", same_self_generation, d);

    pid_t matrix_child = fork();
    if (matrix_child == 0) {
        for (;;) pause();
    }
    if (matrix_child > 0) {
        nap_ms(40);
        struct proc_bsdshortinfo mshort;
        memset(&mshort, 0, sizeof(mshort));
        errno = 0;
        int mshort_rc = proc_pidinfo(matrix_child, PROC_PIDT_SHORTBSDINFO, 0, &mshort, (int)sizeof(mshort));
        int mshort_errno = errno;
        snprintf(d, sizeof(d), "\"pid\":%d,\"returned\":%d,\"errno\":%d,\"reported_pid\":%u,\"ppid\":%u,\"status\":%u",
                 (int)matrix_child, mshort_rc, mshort_errno, (unsigned)mshort.pbsi_pid, (unsigned)mshort.pbsi_ppid, (unsigned)mshort.pbsi_status);
        record("native_sdk_proc_bsdshortinfo_live_child",
               mshort_rc == (int)sizeof(mshort) && mshort.pbsi_pid == (uint32_t)matrix_child && mshort.pbsi_ppid == (uint32_t)getpid(), d);

        memset(namebuf, 0, sizeof(namebuf));
        errno = 0;
        int child_name_rc = proc_name(matrix_child, namebuf, (uint32_t)sizeof(namebuf));
        int child_name_errno = errno;
        snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"nonempty\":%s", child_name_rc, child_name_errno,
                 (child_name_rc > 0 && namebuf[0] != '\0') ? "true" : "false");
        record("native_sdk_proc_name_live_child", child_name_rc > 0 && namebuf[0] != '\0', d);

        memset(pathbuf, 0, sizeof(pathbuf));
        errno = 0;
        int child_path_rc = proc_pidpath(matrix_child, pathbuf, (uint32_t)sizeof(pathbuf));
        int child_path_errno = errno;
        snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"nonempty\":%s", child_path_rc, child_path_errno,
                 (child_path_rc > 0 && pathbuf[0] != '\0') ? "true" : "false");
        record("native_sdk_proc_pidpath_live_child", child_path_rc > 0 && pathbuf[0] != '\0', d);

        struct kinfo_proc mk;
        size_t mklen = 0;
        int mke = 0;
        int mkrc = read_kinfo(matrix_child, &mk, &mklen, &mke);
        snprintf(d, sizeof(d), "\"rc\":%d,\"returned\":%zu,\"errno\":%d,\"pid\":%d,\"ppid\":%d,\"status\":%d",
                 mkrc, mklen, mke, mk.kp_proc.p_pid, mk.kp_eproc.e_ppid, mk.kp_proc.p_stat);
        record("native_sdk_kern_proc_pid_live_child",
               mkrc == 0 && mklen == sizeof(mk) && mk.kp_proc.p_pid == matrix_child && mk.kp_eproc.e_ppid == getpid(), d);

        struct proc_bsdinfo mb;
        int mbe = 0;
        int mbrc = read_bsd(matrix_child, &mb, &mbe);
        int same_child_generation = mbrc == (int)sizeof(mb) && mkrc == 0 &&
                                    mb.pbi_start_tvsec == (uint64_t)mk.kp_proc.p_starttime.tv_sec &&
                                    mb.pbi_start_tvusec == (uint64_t)mk.kp_proc.p_starttime.tv_usec;
        snprintf(d, sizeof(d), "\"bsd_rc\":%d,\"kinfo_rc\":%d,\"same\":%s", mbrc, mkrc, same_child_generation ? "true" : "false");
        record("native_sdk_proc_bsdinfo_same_generation_as_kinfo_child", same_child_generation, d);

        kill(matrix_child, SIGSTOP);
        int stopped_status = 0;
        (void)waitpid(matrix_child, &stopped_status, WUNTRACED);

        memset(&mshort, 0, sizeof(mshort));
        errno = 0;
        int stopped_short_rc = proc_pidinfo(matrix_child, PROC_PIDT_SHORTBSDINFO, 0, &mshort, (int)sizeof(mshort));
        int stopped_short_errno = errno;
        snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"status\":%u", stopped_short_rc, stopped_short_errno, (unsigned)mshort.pbsi_status);
        record("native_sdk_proc_bsdshortinfo_stopped_child",
               stopped_short_rc == (int)sizeof(mshort) && mshort.pbsi_status == PROBE_SSTOP, d);

        mklen = 0; mke = 0; mkrc = read_kinfo(matrix_child, &mk, &mklen, &mke);
        snprintf(d, sizeof(d), "\"rc\":%d,\"returned\":%zu,\"errno\":%d,\"status\":%d", mkrc, mklen, mke, mk.kp_proc.p_stat);
        record("native_sdk_kern_proc_pid_stopped_child",
               mkrc == 0 && mklen == sizeof(mk) && mk.kp_proc.p_stat == PROBE_SSTOP, d);

        kill(matrix_child, SIGCONT);
        kill(matrix_child, SIGKILL);

        struct kinfo_proc zk;
        size_t zklen = 0;
        int zke = 0;
        int zkrc = -1;
        int zfound = 0;
        for (int i = 0; i < 100; ++i) {
            zkrc = read_kinfo(matrix_child, &zk, &zklen, &zke);
            if (zkrc == 0 && zklen == sizeof(zk) && zk.kp_proc.p_stat == PROBE_SZOMB) { zfound = 1; break; }
            nap_ms(10);
        }

        memset(&mshort, 0, sizeof(mshort));
        errno = 0;
        int zombie_short_rc = proc_pidinfo(matrix_child, PROC_PIDT_SHORTBSDINFO, 0, &mshort, (int)sizeof(mshort));
        int zombie_short_errno = errno;
        int zombie_short_ok = (zombie_short_rc == (int)sizeof(mshort) && mshort.pbsi_status == PROBE_SZOMB) ||
                              (zombie_short_rc == 0 && (zombie_short_errno == ESRCH || zombie_short_errno == 0));
        snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d,\"status\":%u,\"kinfo_zombie\":%s",
                 zombie_short_rc, zombie_short_errno, (unsigned)mshort.pbsi_status, zfound ? "true" : "false");
        record("native_sdk_proc_bsdshortinfo_zombie_classification", zombie_short_ok && zfound, d);

        memset(child_pids, 0, sizeof(child_pids));
        errno = 0;
        int zombie_child_count = proc_listchildpids(getpid(), child_pids, (int)sizeof(child_pids));
        int zombie_child_errno = errno;
        int zombie_list_contains = zombie_child_count > 0 && contains_pid(child_pids, zombie_child_count, matrix_child);
        snprintf(d, sizeof(d), "\"count\":%d,\"errno\":%d,\"contains_zombie\":%s",
                 zombie_child_count, zombie_child_errno, zombie_list_contains ? "true" : "false");
        record("native_sdk_proc_listchildpids_zombie_membership_classification",
               zombie_child_count >= 0, d);

        errno = 0;
        int zombie_kill0_rc = kill(matrix_child, 0);
        int zombie_kill0_errno = errno;
        snprintf(d, sizeof(d), "\"rc\":%d,\"errno\":%d,\"kinfo_zombie\":%s",
                 zombie_kill0_rc, zombie_kill0_errno, zfound ? "true" : "false");
        record("native_sdk_kill0_zombie_presence",
               zfound && (zombie_kill0_rc == 0 || (zombie_kill0_rc == -1 && zombie_kill0_errno == EPERM)), d);

        (void)waitpid(matrix_child, NULL, 0);

        errno = 0;
        int reaped_kill0_rc = kill(matrix_child, 0);
        int reaped_kill0_errno = errno;
        snprintf(d, sizeof(d), "\"rc\":%d,\"errno\":%d", reaped_kill0_rc, reaped_kill0_errno);
        record("native_sdk_kill0_reaped_absence", reaped_kill0_rc == -1 && reaped_kill0_errno == ESRCH, d);

        struct proc_bsdinfo rb;
        int rbe = 0;
        int rbrc = read_bsd(matrix_child, &rb, &rbe);
        snprintf(d, sizeof(d), "\"returned\":%d,\"errno\":%d", rbrc, rbe);
        record("native_sdk_proc_bsdinfo_reaped_child", rbrc == 0, d);

        struct kinfo_proc rk;
        size_t rklen = 0;
        int rke = 0;
        int rkrc = read_kinfo(matrix_child, &rk, &rklen, &rke);
        snprintf(d, sizeof(d), "\"rc\":%d,\"returned\":%zu,\"errno\":%d", rkrc, rklen, rke);
        record("native_sdk_kern_proc_pid_reaped_child",
               (rkrc == 0 && rklen == 0) || (rkrc == -1 && (rke == ESRCH || rke == ENOENT || rke == 0)), d);

        memset(child_pids, 0, sizeof(child_pids));
        int post_reap_count = proc_listchildpids(getpid(), child_pids, (int)sizeof(child_pids));
        int post_reap_contains = post_reap_count > 0 && contains_pid(child_pids, post_reap_count, matrix_child);
        snprintf(d, sizeof(d), "\"count\":%d,\"contains_reaped\":%s", post_reap_count, post_reap_contains ? "true" : "false");
        record("native_sdk_proc_listchildpids_excludes_reaped_child", post_reap_count >= 0 && !post_reap_contains, d);
    } else {
        record("native_sdk_proc_bsdshortinfo_live_child", 0, "\"fork_errno\":1");
        record("native_sdk_proc_name_live_child", 0, "\"fork_errno\":1");
        record("native_sdk_proc_pidpath_live_child", 0, "\"fork_errno\":1");
        record("native_sdk_kern_proc_pid_live_child", 0, "\"fork_errno\":1");
        record("native_sdk_proc_bsdinfo_same_generation_as_kinfo_child", 0, "\"fork_errno\":1");
        record("native_sdk_proc_bsdshortinfo_stopped_child", 0, "\"fork_errno\":1");
        record("native_sdk_kern_proc_pid_stopped_child", 0, "\"fork_errno\":1");
        record("native_sdk_proc_bsdshortinfo_zombie_classification", 0, "\"fork_errno\":1");
        record("native_sdk_proc_listchildpids_zombie_membership_classification", 0, "\"fork_errno\":1");
        record("native_sdk_kill0_zombie_presence", 0, "\"fork_errno\":1");
        record("native_sdk_kill0_reaped_absence", 0, "\"fork_errno\":1");
        record("native_sdk_proc_bsdinfo_reaped_child", 0, "\"fork_errno\":1");
        record("native_sdk_kern_proc_pid_reaped_child", 0, "\"fork_errno\":1");
        record("native_sdk_proc_listchildpids_excludes_reaped_child", 0, "\"fork_errno\":1");
    }

    struct kinfo_proc missing_kp;
    size_t missing_kp_len = 0;
    int missing_kp_errno = 0;
    int missing_kp_rc = read_kinfo(INT_MAX, &missing_kp, &missing_kp_len, &missing_kp_errno);
    snprintf(d, sizeof(d), "\"rc\":%d,\"returned\":%zu,\"errno\":%d", missing_kp_rc, missing_kp_len, missing_kp_errno);
    record("native_sdk_kern_proc_pid_missing",
           (missing_kp_rc == 0 && missing_kp_len == 0) || (missing_kp_rc == -1 && (missing_kp_errno == ESRCH || missing_kp_errno == ENOENT || missing_kp_errno == 0)), d);

    struct kinfo_proc *all_entries = NULL;
    size_t all_count = 0, all_bytes = 0;
    int all_errno = 0;
    int all_rc = read_all_kinfo(&all_entries, &all_count, &all_bytes, &all_errno);
    struct kinfo_proc *all_self = all_rc == 0 ? find_kinfo(all_entries, all_count, getpid()) : NULL;
    snprintf(d, sizeof(d), "\"rc\":%d,\"errno\":%d,\"count\":%zu,\"bytes\":%zu,\"contains_self\":%s",
             all_rc, all_errno, all_count, all_bytes, all_self ? "true" : "false");
    record("native_sdk_kern_proc_all_contains_self",
           all_rc == 0 && all_self != NULL && all_bytes == all_count * sizeof(struct kinfo_proc), d);
    free(all_entries);

    pid_t all_child = fork();
    if (all_child == 0) {
        for (;;) pause();
    }
    if (all_child > 0) {
        struct proc_bsdinfo all_bsd;
        int all_bsd_errno = 0;
        int all_bsd_rc = read_bsd(all_child, &all_bsd, &all_bsd_errno);

        all_entries = NULL; all_count = 0; all_bytes = 0; all_errno = 0;
        all_rc = read_all_kinfo(&all_entries, &all_count, &all_bytes, &all_errno);
        struct kinfo_proc *live_entry = all_rc == 0 ? find_kinfo(all_entries, all_count, all_child) : NULL;
        int live_ok = live_entry != NULL && live_entry->kp_eproc.e_ppid == getpid() &&
                      all_bsd_rc == (int)sizeof(all_bsd) &&
                      (uint64_t)live_entry->kp_proc.p_starttime.tv_sec == all_bsd.pbi_start_tvsec &&
                      (uint64_t)live_entry->kp_proc.p_starttime.tv_usec == all_bsd.pbi_start_tvusec;
        snprintf(d, sizeof(d), "\"rc\":%d,\"errno\":%d,\"count\":%zu,\"found\":%s,\"ppid\":%d,\"bsd_rc\":%d",
                 all_rc, all_errno, all_count, live_entry ? "true" : "false",
                 live_entry ? live_entry->kp_eproc.e_ppid : -1, all_bsd_rc);
        record("native_sdk_kern_proc_all_live_child_identity", live_ok, d);
        free(all_entries);

        kill(all_child, SIGSTOP);
        int all_stopped_status = 0;
        (void)waitpid(all_child, &all_stopped_status, WUNTRACED);
        all_entries = NULL; all_count = 0; all_bytes = 0; all_errno = 0;
        all_rc = read_all_kinfo(&all_entries, &all_count, &all_bytes, &all_errno);
        struct kinfo_proc *stopped_entry = all_rc == 0 ? find_kinfo(all_entries, all_count, all_child) : NULL;
        snprintf(d, sizeof(d), "\"rc\":%d,\"errno\":%d,\"found\":%s,\"status\":%d",
                 all_rc, all_errno, stopped_entry ? "true" : "false", stopped_entry ? stopped_entry->kp_proc.p_stat : -1);
        record("native_sdk_kern_proc_all_stopped_child",
               stopped_entry != NULL && stopped_entry->kp_proc.p_stat == PROBE_SSTOP, d);
        free(all_entries);

        kill(all_child, SIGCONT);
        kill(all_child, SIGKILL);
        struct kinfo_proc zombie_copy;
        memset(&zombie_copy, 0, sizeof(zombie_copy));
        int all_zombie_found = 0;
        size_t zombie_count = 0;
        for (int i = 0; i < 100 && !all_zombie_found; ++i) {
            all_entries = NULL; all_count = 0; all_bytes = 0; all_errno = 0;
            all_rc = read_all_kinfo(&all_entries, &all_count, &all_bytes, &all_errno);
            struct kinfo_proc *zombie_entry = all_rc == 0 ? find_kinfo(all_entries, all_count, all_child) : NULL;
            zombie_count = all_count;
            if (zombie_entry != NULL && zombie_entry->kp_proc.p_stat == PROBE_SZOMB) {
                zombie_copy = *zombie_entry;
                all_zombie_found = 1;
            }
            free(all_entries);
            if (!all_zombie_found) nap_ms(10);
        }
        snprintf(d, sizeof(d), "\"found\":%s,\"count\":%zu,\"status\":%d,\"pid\":%d",
                 all_zombie_found ? "true" : "false", zombie_count, zombie_copy.kp_proc.p_stat, zombie_copy.kp_proc.p_pid);
        record("native_sdk_kern_proc_all_zombie_child",
               all_zombie_found && zombie_copy.kp_proc.p_pid == all_child, d);

        (void)waitpid(all_child, NULL, 0);
        all_entries = NULL; all_count = 0; all_bytes = 0; all_errno = 0;
        all_rc = read_all_kinfo(&all_entries, &all_count, &all_bytes, &all_errno);
        struct kinfo_proc *reaped_entry = all_rc == 0 ? find_kinfo(all_entries, all_count, all_child) : NULL;
        snprintf(d, sizeof(d), "\"rc\":%d,\"errno\":%d,\"count\":%zu,\"contains_reaped\":%s",
                 all_rc, all_errno, all_count, reaped_entry ? "true" : "false");
        record("native_sdk_kern_proc_all_excludes_reaped_child", all_rc == 0 && reaped_entry == NULL, d);
        free(all_entries);
    } else {
        record("native_sdk_kern_proc_all_live_child_identity", 0, "\"fork_errno\":1");
        record("native_sdk_kern_proc_all_stopped_child", 0, "\"fork_errno\":1");
        record("native_sdk_kern_proc_all_zombie_child", 0, "\"fork_errno\":1");
        record("native_sdk_kern_proc_all_excludes_reaped_child", 0, "\"fork_errno\":1");
    }

    int syncpipe[2] = {-1, -1};
    pid_t group_child = -1;
    if (pipe(syncpipe) == 0) {
        group_child = fork();
        if (group_child == 0) {
            close(syncpipe[0]);
            int rc = setpgid(0, 0);
            char byte = rc == 0 ? '1' : '0';
            (void)write(syncpipe[1], &byte, 1);
            close(syncpipe[1]);
            for (;;) pause();
        }
        close(syncpipe[1]);
        char ready = '0';
        (void)read(syncpipe[0], &ready, 1);
        close(syncpipe[0]);
    }
    if (group_child > 0) {
        int gpids[64];
        memset(gpids, 0, sizeof(gpids));
        errno = 0;
        int gc = proc_listpgrppids(group_child, gpids, (int)sizeof(gpids));
        int ge = errno;
        int contains_group_child = gc > 0 && contains_pid(gpids, gc, group_child);
        snprintf(d, sizeof(d), "\"count\":%d,\"errno\":%d,\"pgid\":%d,\"contains_child\":%s", gc, ge, (int)group_child,
                 contains_group_child ? "true" : "false");
        record("native_sdk_proc_listpgrppids_contains_owned_group_child", contains_group_child, d);
        kill(group_child, SIGKILL);
        (void)waitpid(group_child, NULL, 0);
        memset(gpids, 0, sizeof(gpids));
        errno = 0;
        int empty_gc = proc_listpgrppids(group_child, gpids, (int)sizeof(gpids));
        int empty_ge = errno;
        int empty_contains = empty_gc > 0 && contains_pid(gpids, empty_gc, group_child);
        snprintf(d, sizeof(d), "\"count\":%d,\"errno\":%d,\"contains_reaped\":%s", empty_gc, empty_ge, empty_contains ? "true" : "false");
        record("native_sdk_proc_listpgrppids_after_group_empty_classification", empty_gc >= 0 && !empty_contains, d);
    } else {
        record("native_sdk_proc_listpgrppids_contains_owned_group_child", 0, "\"fork_or_pipe_error\":1");
        record("native_sdk_proc_listpgrppids_after_group_empty_classification", 0, "\"fork_or_pipe_error\":1");
    }

    printf("{\"schema\":1,\"platform\":\"macos\",\"source\":\"native-sdk-c\",\"case\":\"summary\",\"status\":\"%s\",\"details\":{\"cases\":%d,\"failures\":%d}}\n",
           failures == 0 ? "pass" : "fail", cases, failures);
    return failures == 0 ? 0 : 1;
}
