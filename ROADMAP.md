# Roadmap: what a complete process-management library still needs

Where `process-handle` + `process-supervision` stand today, and everything still missing before this is the best
process library available in any language. Each item is marked:

* **built**: in the shards, with native specs or kit cases;
* **measured**: the OS behaviour is established in `explore/FINDINGS.md`, but nothing in the shards uses it yet;
* **unexplored**: neither measured nor built.

The yardstick is the union of what serious process APIs offer: Go `os/exec` + `SysProcAttr` (Pdeathsig, Setsid,
Credential, Cloneflags, `UseCgroupFD`, `PidFD`), Python `subprocess` (`pass_fds`, `start_new_session`, `process_group`,
`user`/`group`/`umask`), Rust `std::process` / tokio / `command-fds`, libuv `uv_spawn`, Node `child_process` (IPC channel),
.NET `Process`, and the supervisors systemd, s6/runit, supervisord and Erlang/OTP.

## Status after the first pass over every gap

Everything below marked **first cut** now exists in the shards with specs (`spec/features_spec.cr`); "first cut" means
the API shape and edge cases still need review, as asked: "map out as much as possible, even if not quite right".

| Gap | Now | Where |
|---|---|---|
| CI that can fail | **built** | `shard-dev.yml` Gate step (spec summaries), plus a stress run |
| Hybrid cgroup hosts | **built** (it was a spec bug, not a library bug) | the spec cleans up and is pending where root may create at the hierarchy root |
| Event-driven waits | **built** for cgroups (inotify on `cgroup.events`); macOS handles still poll every 5 ms (Crystal's event loop cannot take a kqueue descriptor: it also registers `EVFILT_WRITE`, which the kernel refuses); process groups back off 5 → 100 ms | `CgroupV2#wait_empty`, `Readiness` |
| One kqueue per handle | open | |
| Versions / stale text | **built** | process-handle 0.9.0, process-supervision 0.8.0 |
| Arbitrary signals | **first cut** | `Group#signal`, `ProcessHandle#signal` (POSIX, cgroups via pidfd; Windows raises) |
| Graceful stop | **first cut** | `Group#request_stop`, `Group#stop` (CONT+TERM; CTRL_BREAK + WM_CLOSE on Windows with `SpawnOptions#console_group`) |
| Suspend / resume | **first cut** | `Group#suspend/resume` (SIGSTOP, `cgroup.freeze`, NtSuspendProcess per Job member), `ProcessHandle#suspend/resume` |
| Extra descriptors, IPC | **first cut** | `SpawnOptions#extra_fds`, `#ipc` (`Child#ipc`); Windows handles announced in `PROCESS_SUPERVISION_HANDLES` |
| Session options | **first cut** | `SpawnOptions#new_session`, `#console_group`, `#hide_window` |
| Credentials | **first cut** (Linux) | `SpawnOptions#uid/gid/groups/umask/no_new_privileges`; macOS/Windows raise Unsupported |
| Rlimits | **first cut** (Linux) | `SpawnOptions#rlimits`; macOS raises (posix_spawn has no rlimit attribute) |
| Cgroup limits and events | **first cut** | `CgroupV2#limits=`, `#stats`, `#memory_events`, `#members`, `CgroupV2.enable_controllers` (explicit opt-in) |
| Resource usage | **first cut** | `ProcessHandle#usage` (Linux /proc, macOS `proc_pid_rusage` v4, Windows times/memory/IO counters) |
| Exit status in full | **first cut** | `ExitOutcome`, `Child#outcome` |
| Supervisor death | **first cut** | `SpawnOptions#parent_death_signal` (Linux), `ProcessSupervision::Lifeline` (POSIX watcher), Job kill-on-close |
| Crash policy | **first cut** (Windows) | `Job::Limits#die_on_unhandled_exception`; core dumps via `rlimits[Core]`. Note: a Crystal child's access violation is caught by its own runtime and exits 1, so it is not seen as a crash |
| Process tree snapshot | **first cut** | `ProcessHandle.snapshot`, `.descendants` |
| Large command lines | **first cut** (Windows check) | `Job#spawn` raises `Error::Native` (206, as `CreateProcessW` would) past 32 767 units, before anything is created; quoting fuzz open |
| Restart policy, readiness, watchdog, logs, events, dependencies | **first cut** | `ProcessSupervision::Supervisor`, `LineLog` |
| IPC channel | **first cut** (socket pair; no framing) | `SpawnOptions#ipc` |
| systemd delegated scope | **first cut**, experimental: usable only by a supervisor inside the user's systemd tree or root (moving children needs write access at the common ancestor); `acquire` refuses otherwise | `Linux::SystemdScope.acquire` |
| Namespaces | **first cut** (clone3 path; no uid_map for user namespaces) | `SpawnOptions#namespaces` |
| Stress | **first cut** | `PROCESS_SUPERVISION_STRESS=1` spec, run in CI |
| launchd, Windows SCM, seccomp/Landlock, AppContainer, FreeBSD, musl runs, fuzzing, soak, benchmarks, one shared kqueue, reload/fd hand-over | open | |

## Built before the first pass (for reference)

| Area | What exists |
|---|---|
| Identity | `ProcessHandle` with generation-checked identity (pidfd on Linux, HANDLE on Windows, kqueue watch on macOS); `observe`/`lookup` |
| Containment at birth | Windows Job (`CREATE_SUSPENDED` + `JOB_LIST`), Linux cgroup v2 (`pidfd_spawn`+`setcgroup` / `clone3(CLONE_INTO_CGROUP)` / fork), POSIX process group |
| Spawning | argv/env/`clear_env`/`chdir`, caller-side PATH resolution, default signal dispositions, stdlib error classes, three Linux engines |
| Streams | Inherit / Close / Pipe / file descriptor / any `IO` (copy fibers), on all three systems |
| Lifecycle | single-collector `wait` with timeout, terminate/kill, group `shutdown` (TERM → grace → KILL → drain), close/effect admission |
| Escapees | environment marker, `ProcessGroup#escapees`, signalled on shutdown (Linux, macOS) |
| Windows Job | limits (memory, process count, CPU rate, priority, UI), accounting, limit events, kill-on-close |
| Detection | `strongest_mechanism`, `CgroupV2.usable?` / `delegated_parent` (by trying) |

---

## Tier 0: make what exists trustworthy (do first)

1. **CI that can fail.** Every `shard-dev` step ends in `exit 0` and the result lives only in artifacts; a regression
   turns nothing red. Fail the job on any spec failure (keep the artifacts), and run the Linux/macOS/Windows matrix on
   every push to the shard. *unexplored (process gap)*
2. **Hybrid cgroup hosts.** On a cgroup-v1/v2 hybrid host (this development container: `/sys/fs/cgroup/unified`),
   `CgroupV2.create` answers `File::AlreadyExistsError` for a directory that does not exist, instead of
   `Error::Unavailable`, so `ProcessSupervision.spawn`'s fallback does not engage. Classify it, and run the specs on a
   hybrid host. *measured (one host), not built*
3. **Event-driven waits everywhere.** `ProcessHandle::Kqueue#wait` and every `wait_empty` poll every 5–10 ms. Use the
   kernel's notifications: kqueue in the event loop (macOS), `cgroup.events` via inotify (Linux),
   `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` on the Job's completion port (Windows), pidfd readiness (Linux, done for
   handles). *measured in part, not built*
4. **One kqueue, not one per handle** (macOS): each `ProcessHandle::Kqueue` owns a descriptor; at thousands of children
   that is thousands of descriptors. *unexplored*
5. **Versions and stale text.** Both shards still say 0.7.0 / 0.8.0 after several API additions; the
   process-supervision README still says "not yet a race-free Linux spawn-into-cgroup primitive". *housekeeping*

## Tier 1: features every serious library has

| # | Feature | Status | Notes from the measurements |
|---|---|---|---|
| 1 | **Arbitrary signals** on handles and groups (HUP to reload, USR1, INT, STOP/CONT) | unexplored | only TERM/KILL today; `pidfd_send_signal` on Linux |
| 2 | **Portable graceful stop** (`request_stop`) | measured | Windows: `CTRL_BREAK_EVENT` reaches only a child started with `CREATE_NEW_PROCESS_GROUP`; `CTRL_C` to a group "succeeds" and delivers nothing; `WM_CLOSE` for GUI programs; a `DETACHED_PROCESS` child cannot be reached at all. POSIX: TERM, plus CONT for a stopped process (a stopped process does not act on TERM) |
| 3 | **Suspend / resume** of a child or a whole group | measured | `SIGSTOP`/`SIGCONT`, `cgroup.freeze` (atomic for the tree), Windows `NtSuspendProcess` / Job freeze |
| 4 | **Pass extra descriptors / handles** to the child (`pass_fds`, socket activation, `LISTEN_FDS`) | unexplored | the engines already place 0–2; a full table with "everything else closed" is the general form; Windows: extend the `HANDLE_LIST` |
| 5 | **Session and group options**: `setsid`, a new process group on Windows, controlling terminal | measured | `POSIX_SPAWN_SETSID` exists in glibc; integrates with the `pty` shard |
| 6 | **Credentials**: uid/gid/supplementary groups, `umask`, `no_new_privs`; Windows `CreateProcessAsUser` / restricted token | unexplored | |
| 7 | **Per-child resource limits** (rlimits) | measured | `RLIMIT_CPU`'s hard limit is never enforced on macOS and the soft limit loses time on syscall-heavy loads (XNU drops sub-µs remainders); `RLIMIT_AS`/`DATA` below usage is `EINVAL` on macOS. A CPU budget on macOS must be enforced by the supervisor (sample `proc_pid_rusage`, then kill) |
| 8 | **Cgroup resource limits and events**: `memory.max`/`high`, `cpu.max`, `pids.max`, `io.max`, `memory.events` (OOM kills), `cpu.stat` | measured (delegation), not built | needs controllers enabled in the delegated parent's `subtree_control`; current policy refuses to touch it, so this needs an explicit opt-in |
| 9 | **Resource usage per child and per group** (CPU user/sys, peak memory, I/O bytes) | measured | `ru_maxrss` is bytes on macOS and KiB on Linux; macOS I/O only via `proc_pid_rusage`; an orphaned grandchild's CPU is credited to nobody, except via cgroup `cpu.stat` or Job accounting |
| 10 | **Exit status in full**: signal, core dumped, Windows NTSTATUS names (`0xC000013A` = Ctrl+C exit, `0xC0000005`, ...) | partial (stdlib `Process::Status`) | a portable "crashed vs exited vs killed by us" classification |
| 11 | **Supervisor death guarantees** | measured | Windows Job kill-on-close is the only kernel guarantee built. Linux: `PR_SET_PDEATHSIG` (fires on the *thread's* exit, a known trap with Crystal's threads), `PR_SET_CHILD_SUBREAPER` to keep orphans, cgroup kill from a still-living service manager. macOS: nothing kernel-level, so a watchdog helper or lifeline pipe. All of these fired within 0.1–1.1 ms of a SIGKILL in the measurements |
| 12 | **Crash handling policy**: no WER dialog or debugger hang, core dump on or off, the crash-handler delay | measured | Linux's crash handler (apport/systemd-coredump) holds a crashing process; a macOS Mach exception handler holds the crashing thread; Windows WER can hang a child with a dialog (`SetErrorMode`, WER exclusion) |
| 13 | **Process tree snapshot** (pid, ppid, start time, command line) for diagnostics and `escapees` | measured | ppid walk, kernel child lists, environment tag; costs in FINDINGS |
| 14 | **Large argument and environment lists** (`E2BIG`, Windows 32 767-char command line), Windows quoting fuzzed against `CommandLineToArgvW` and MSVCRT rules | unexplored | |

## Tier 2: the supervision layer (what turns primitives into a supervisor)

1. **Restart policies**: one-for-one / one-for-all / rest-for-one, exponential backoff with jitter, restart-intensity
   limits (OTP `max_restarts` in `max_seconds`), "stop restarting after N failures". *unexplored*
2. **Readiness**: the `sd_notify` protocol (`NOTIFY_SOCKET`, `READY=1`, `STATUS=`, `WATCHDOG=1`), s6-style readiness
   descriptor, or a probe callback; start-up timeouts. *unexplored*
3. **Liveness**: watchdog pings, health-check commands, hang detection. *unexplored*
4. **Log capture**: line splitting without unbounded buffers, stdout/stderr interleaving with ordering, timestamps,
   ring buffer or rotation, back-pressure when the consumer is slow (today `IO::Memory` grows without limit).
   *unexplored*
5. **Graceful reload and upgrade**: signal or command to reload, descriptor hand-over to a new instance (zero-downtime
   restart). *unexplored*
6. **Event stream**: started / ready / exited(status) / restarted / limit-hit / OOM as a channel or callback, so callers
   do not poll. *unexplored*
7. **IPC channel** to the child (Node's `fork` with a message pipe): a framed pipe on an extra descriptor.
   *unexplored*
8. **Service-manager integration**: systemd transient scope or service over D-Bus (`StartTransientUnit` with
   `Delegate=yes`) to *obtain* a delegated cgroup instead of hoping for one; launchd jobs on macOS; Windows Service
   Control Manager (measured: a hung STOP handler blocks `ControlService` for 240 s). *measured in part*
9. **Dependency ordering and groups of services**, a declarative spec (like a unit file) on top of the API.
   *unexplored*

## Tier 3: isolation and sandboxing

| Item | Status |
|---|---|
| Linux namespaces at spawn (`CLONE_NEWPID`, user, mount, net, ipc, uts) and a PID-1 shim inside a new PID namespace | unexplored |
| seccomp filters, `no_new_privs`, Landlock | unexplored |
| Windows AppContainer / LPAC children, restricted and low-integrity tokens, mitigation policies | measured (AppContainer starts on 2022/2025/11-arm) |
| Windows `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (spawn "as" another parent) | measured |
| macOS sandbox profiles, `responsibility_spawnattrs_setdisclaim`, jetsam limits for children (`posix_spawnattr_setjetsam_ext`) | measured in part (jetsam for the direct child only) |

## Tier 4: platforms and environments

| Platform / environment | Status |
|---|---|
| FreeBSD: `pdfork` process descriptors, `procctl(PROC_REAP_ACQUIRE / REAP_KILL)` (a real kernel subreaper with tree kill) | unexplored, likely the strongest POSIX backend after cgroups |
| musl / Alpine running the shard specs (the engines' `posix_spawn` behaviour differs; `pidfd_spawn` is absent) | cgroup delegation measured on Alpine, shard not run there |
| cgroup v1-only and hybrid hosts | one hybrid host seen; Tier 0 item 2 |
| WSL 1/2, Kubernetes pods, rootless Docker/Podman, SELinux enforcing | not testable on hosted runners; needs self-hosted or VM runners |
| Windows on arm64 running the shards (only `explore/` ran there), Windows 10 / Server 2019 | partial |
| A glibc with BZ 31695 fixed (2.40+): confirm the leak workaround finds nothing to close | unexplored (Debian trixie / Ubuntu 25.04 container) |
| OpenBSD / NetBSD / illumos | unexplored |

## Tier 5: scale and assurance

1. **Scale**: thousands of concurrent children (descriptors per child: pidfd + pipes + kqueue), spawn throughput per
   engine, `escapees` scan cost with 5 000 processes (macOS Intel scans took 150 ms at 500). *measured for creation
   rate only*
2. **Soak tests**: hours of spawn/kill cycles checking descriptors, handles, memory and zombies stay flat. *unexplored*
3. **Race and stress tests under CPU contention** (the cgroup attach race was found exactly this way): shutdown during
   spawn, close during wait, kill during exec. *partial*
4. **Fuzzing**: argv/env round-trip (especially Windows quoting), environment block construction, KERN_PROCARGS2 parsing.
   *unexplored*
5. **Benchmarks against the stdlib `Process` and other languages' libraries**, published. *unexplored*
6. **Documentation**: API reference, a "which mechanism do I get and what does it guarantee" table per OS, migration
   guide from `Process`. *partial (READMEs)*
7. **Upstreaming**: parts of this (pidfd-based wait, `pidfd_spawn`, stream plumbing) belong in Crystal's stdlib; a
   proposal with the measurements. *unexplored*

## Open research questions (from `explore/FINDINGS.md`, "Still open")

* Why Windows' Job limit pass runs every 7.000 s on x64 but 7.04–7.16 s on arm64.
* Which code returns `ERROR_INVALID_PARAMETER` when `MaxBandwidth` is not a multiple of 4 KiB.
* Why a hung service STOP handler blocks `ControlService` for 240 s, and what ends the service then.
* Why `CLONE_INTO_CGROUP` into a killed cgroup kills the child at once (kernel source not read).
* Whether the environment marker survives programs that rewrite their environment, and whether `START_SUSPENDED` plus a
  marker is enough on macOS in practice.
* A shared-process (`svchost`-style) service, preshutdown and system-shutdown ordering; macOS jetsam limits for
  grandchildren and after `exec`; GitHub Actions' own cancellation timing.

## Suggested order

1. Tier 0 (all five): small, and everything after relies on CI that can fail.
2. Tier 1 items 1, 2, 3, 4, 10, 11: signals, graceful stop, suspend/resume, extra descriptors, exit-status
   classification and supervisor-death guarantees are the gaps a user hits first.
3. Tier 1 items 7, 8, 9: limits and accounting, the cgroup ones behind an explicit opt-in.
4. Tier 2 items 1, 2, 4, 6: restart policy, readiness, logs and events make it a supervisor.
5. FreeBSD and musl from Tier 4, then Tier 3 isolation, then Tier 5 assurance throughout.
