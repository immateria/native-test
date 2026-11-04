# process-supervision design

## Contract

A `Group` owns or controls a process collection. `mechanism` and
`kill_on_close?` are observable because the available guarantees differ by OS.
The API must not claim that a POSIX process group is equivalent to a Windows Job
Object or Linux cgroup v2.

`shutdown` is policy over backend primitives. POSIX uses TERM -> grace -> KILL ->
drain. Windows Jobs and Linux cgroup v2 currently skip the nonexistent generic
soft-tree tier and go directly to hard tree termination.

`Child` represents a directly spawned child with three distinct owners:

- Crystal `Process` owns child status/reaping and any Crystal-side streams;
- `ProcessHandle` owns stable process identity/control;
- `Group` owns collection/tree lifetime and may be shared by sibling children.

Closing a `Child` never closes its `Group`. `Child#wait` has one collector:
concurrent callers receive one cached `Process::Status` or one cached exception,
matching the PTY Unix/Windows Session wait ownership contract.

Wait/spawn/close paths that need Crystal's scheduler use the PTY raw-thread
bridge when no execution context is present. A raw-thread child-status wait still
requires Crystal's process-reaper/runtime to make progress; the PTY-tested usage
pattern observes the result before joining the raw waiter thread.

## Windows race-free spawn

The implementation is derived from the proven Windows PTY creation ordering.
Post-spawn `Job#adopt` cannot retroactively contain descendants, so `Job#spawn`
uses a stronger transaction:

```text
Job is open and locked
  -> build PROC_THREAD_ATTRIBUTE_JOB_LIST
  -> build PROC_THREAD_ATTRIBUTE_HANDLE_LIST for stdin/out/err only
  -> CreateProcessW(CREATE_SUSPENDED)
  -> explicit AssignProcessToJobObject while still suspended
  -> read creation-time identity
  -> open/revalidate stable ProcessHandle
  -> transfer PROCESS_INFORMATION to Crystal::System::Process
  -> Crystal resumes initial thread exactly once
```

The Job-list creation attribute closes the gap in which the supervisor itself
could die after process creation but before an ordinary assignment. The
explicit assignment is retained as a backstop/verification before resume. Job
close is serialized with the creation transaction so its native HANDLE cannot
be invalidated while it is embedded in the attribute list.

Only duplicated standard handles are inheritable and listed in the process
attribute. Hidden Windows per-drive environment entries are preserved when the
environment block is rebuilt. Direct batch-file execution is rejected.

Job cleanup follows the later PTY Session cleanup-completion rule. The owner
keeps the Job HANDLE attached until checked `CloseHandle(Job)` succeeds. Once
that closes, logical Job admission is over, but a limit-event completion port may
still need cleanup. The EventReader remains attached until its checked port close
succeeds; after its reader thread has stopped, a retry repeats only the port
close rather than reposting or restarting the reader. Constructor rollback and
other paths that already own a stronger primary error use no-throw cleanup so a
secondary close anomaly cannot mask the authoritative diagnosis.

## Linux cgroup v2

`Linux::CgroupV2` is a distinct strong-hard-containment mechanism. It discovers
cgroup v2 through `/proc/self/mountinfo`, accounts for mounts rooted at a
hierarchy subtree, and resolves the current process path using
`/proc/self/cgroup`.

Safety/policy rules:

- never accept the hierarchy root as a supervision kill target;
- require the kernel files used by the contract (`cgroup.procs`,
  `cgroup.events`, `cgroup.kill`);
- never mutate `cgroup.subtree_control` or invent host delegation policy;
- only create below an explicitly supplied delegated/writable parent;
- use recursive `cgroup.events` `populated` for drain observation;
- use `cgroup.kill` for recursive hard kill rather than enumerating `/proc`;
- expose a process-group fallback only when the caller explicitly requests one,
  and preserve `.process_group` as the returned mechanism;
- describe `attach(pid)` as post-spawn numeric migration, not stable/race-free
  process identity.

Owned cgroups are removed only when empty. A failed busy/removal close remains
retryable instead of falsely marking the controller closed.

## Extracted PTY lineage

The Windows implementation is derived from the current `pty` shard in Crystal
Systems checkpoint `20261027T000520747374Z-51c038478b01`:

- `src/pty/windows/job.cr`
- `src/pty/windows/job/limits.cr`
- `src/pty/windows/job/accounting.cr`
- `src/pty/windows/job/limit_events.cr`
- `src/pty/windows/session/spawn.cr`
- checked HANDLE cleanup and process identity from the adjacent Windows native
  and Session lifecycle code.

The portable shutdown policy is derived from `PTY::Session#shutdown` while
removing terminal-specific assumptions. Single-collector child wait/error fanout
and raw-thread execution bridging come from the Unix/Windows Session lifecycle
and `src/pty/raw_thread_bridge.cr`. Close-versus-effect serialization for the
Unix group backends applies the pty-server exact-lifetime effect-gate rule at the
lower resource owner rather than importing server/session policy.

The POSIX process-group controller is extracted from Unix foreground/process
-group signalling semantics but does not claim terminal ownership.

The cgroup-v2 backend is new to this lower-level workspace; it is not presented
as extracted PTY behavior.

## Not extracted

ConPTY/HPCON, PTY master/slave descriptors, foreground terminal job control,
`TIOCSIG`, Ctrl+Break brokerage, terminal resize, byte streams, and shell/VT
semantics remain with `pty`.

## Next slices

1. Native Windows runtime qualification of `Job#spawn`, Job close/crash
   containment, HANDLE allowlisting, argv/env/cwd, failure cleanup, limits,
   accounting and events.
2. Linux delegated-cgroup runtime qualification with real child migration,
   recursive descendants, `cgroup.kill`, drain and owned-directory teardown.
3. ~~Race-free Linux initial cgroup containment.~~ Done: `CgroupV2#spawn` (clone3 `CLONE_INTO_CGROUP`, fork fallback),
   qualified in plain, root, systemd `Delegate=yes`, user-manager and container environments.
4. FreeBSD process-reaper investigation. The macOS capability matrix is measured (kqueue tracking refused, environment
   marker scan works, `START_SUSPENDED` works); a macOS descendant tracker is not implemented.
5. Capability reporting is done by trying (`CgroupV2.usable?`, `delegated_parent`, `ProcessSupervision.strongest_mechanism`);
   adopting an already-running process into a group is still open.
6. Stdio redirection for supervised children; `posix_spawn` as the Linux engine for process groups.
