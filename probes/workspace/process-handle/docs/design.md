# process-handle design

## Contract

`ProcessHandle` identifies one process instance, not merely a numeric PID.
`ProcessHandle.lookup` is only a point-in-time identity snapshot; `observe` adds
explicit `Live` / `Zombie` / `Dead` / `Unknown` state; `open` retains the
platform's stable kernel reference where this checkpoint supports one.

Detached identity comparison is deliberately stricter than retained-handle
identity. `Identity#same_pid?` is numeric equality only. `same_process?` returns
true only when both identities carry generation tokens and those tokens match.
A pidfd can therefore remain a stable retained capability even when restricted
procfs forces its plain `Identity` to carry no generation token.

Observation follows the pty-server daemon-supervision rule: inability to prove a
live identity is `Unknown`, never optimistic `Live`. Linux uses `/proc` state plus
start time, Windows verifies creation time and non-signaled process state, and
macOS uses `proc_pidinfo(PROC_PIDTBSDINFO)` from XNU/libproc for status and
microsecond-resolution creation timestamp when available. That information is a
snapshot, not a stable kernel reference or permission to signal a PID later.
FreeBSD and other POSIX targets retain a conservative `kill(pid, 0)` probe.

`wait` reports process termination only. It does not promise an exit status,
because an arbitrary observed process is not necessarily a waitable child on
Unix. Child reaping/status remains with the spawning owner.

## Extracted PTY lineage

The initial implementation is derived from the current `pty` shard in Crystal
Systems checkpoint `20261027T000520747374Z-51c038478b01`:

- Linux pidfd acquisition/signalling from `src/pty/unix/native.cr` and the
  stable initial-process identity hardening.
- Windows PID + creation-FILETIME identity from
  `src/pty/windows/process_identity.cr`.
- Windows checked HANDLE ownership/duplication from `src/pty/windows/native.cr`
  and Session lifecycle code, including the distinction between checked
  owner-controlled close and no-throw temporary/rollback cleanup.
- Windows registered wait callback discipline from
  `src/pty/windows/fiber_process_wait.cr`.
- Raw-thread execution-context bridging from `src/pty/raw_thread_bridge.cr`.
- Linux owned-fd close error semantics from the Unix close hardening: report a
  native close error but never retry an fd number whose ownership was already
  relinquished.
- Point-in-time process state and conservative POSIX fallback from
  `pty-server` daemon supervision, plus the Windows termination-state check from
  `PTY::Windows::ProcessIdentity#alive?`. The same supervision evidence also
  supplies the rule that PID equality without start/generation evidence is not
  process identity.
- Primary-error precedence from PTY spawn/wait cleanup hardening: the public
  block-scoped `ProcessHandle.open` preserves an exception raised by the caller
  if owner cleanup also fails; temporary Windows HANDLE cleanup is no-throw when
  an operation already failed, and wait duplicate cleanup never replaces the
  observed wait outcome.
- Linux pidfd event-loop readiness is adapted from independent libuv/Swift
  Subprocess/psutil research; per-wait fd duplication preserves lifetime when
  the ProcessHandle owner closes concurrently.
- Darwin XNU `proc_bsdinfo` ABI (136 bytes with `MAXCOMLEN == 16`) and
  psutil/libproc process state research provide generation-bearing snapshots.
  This is not equivalent to retained pidfd/HANDLE identity.

PTY-specific terminal ownership, foreground process groups, `TIOCSIG`, ConPTY,
Ctrl+Break brokerage, terminal EOF/HUP, resize, and stream I/O are intentionally
not extracted.

## Deferred

- macOS stable process references remain unavailable. The `proc_pidinfo`/kinfo
  observer has native arm64 qualification on macOS 15.4.1, but broader macOS
  version/architecture coverage and FreeBSD/BSD stable references/generation
  evidence remain open (presence-only fallback still returns `Unknown`).
- event-loop backend qualification beyond the verified Linux epoll and io_uring
  lanes; cancellation, concurrent close and native parallel overlap tests.
- child exit-status integration without stealing the spawning owner's reap.
- explicit borrowed/adopted handle constructors.

Native macOS 15.4.1 evidence shows `PROC_PIDTBSDINFO` can report `ESRCH` for an unreaped zombie while `KERN_PROC_PID` still exposes `SZOMB`. The Darwin observer therefore uses a secondary `KERN_PROC_PID` snapshot only after its 64-bit `extern_proc` prefix offsets are runtime-validated against libproc for the current process. This can recover exact zombie/generation evidence without treating the legacy ABI as an unconditional compile-time promise. If that validation or secondary observation is unavailable, signal-presence still prevents a present but unclassifiable PID from being called `Dead`. Neither snapshot surface is a retained process-control capability.
