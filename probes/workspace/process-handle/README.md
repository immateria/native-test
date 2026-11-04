# process-handle

Stable native process identity and lifecycle primitives for Crystal.

This is an extracted systems shard, not a command runner. It separates a process
identity/control reference from `Process`, which represents a child started by
Crystal and owns its standard streams.

```crystal
require "process-handle"

handle = ProcessHandle.open(pid)
handle.identity
handle.alive?
handle.wait(500.milliseconds)
handle.terminate # Unix when meaningful
handle.kill      # forceful
handle.close
```

The block form guarantees cleanup without allowing a secondary close failure to
replace an exception already raised by the caller:

```crystal
ProcessHandle.open(pid) do |handle|
  # use handle
end
```

For point-in-time inspection without retaining a native handle:

```crystal
observation = ProcessHandle.observe(pid)
case observation.state
when .live?
  # identity was proved live at the instant of observation
when .zombie?
  # Unix zombie: still present, but already terminated
when .dead?
  # no live process remains at this PID
when .unknown?
  # PID presence could be established, but live identity could not
end
```

`Unknown` is intentionally fail-closed. On macOS, `proc_pidinfo` provides
point-in-time process status and a process-start generation token when available.
It does not supply an enduring process-control reference: even a matched token
cannot make a subsequent PID-addressed signal race-free. FreeBSD and other
POSIX targets retain the conservative `kill(pid, 0)` presence-only fallback.

Current backends:

- Linux x86-64/aarch64: `pidfd_open` + `pidfd_send_signal`; `/proc/<pid>/stat`
  start-time token when readable; event-loop-based pidfd termination waits with
  a private CLOEXEC duplicate for each waiter. The pidfd remains a stable retained process
  capability even when restricted/missing procfs means the detached
  `Identity#generation` cannot be recorded.
- Windows: owned observer process HANDLE + process creation `FILETIME`; point-in-time
  observation checks both creation identity and native termination state. Finite
  registered waits use the native wait timeout and bridge callback completion into
  Crystal's evented pipe path, so callback quiescence cannot turn a short timeout into
  a wait for process exit. Windows-specific consumers can request a block-scoped native
  HANDLE with explicit `Windows::Access` rights; admission is serialized with owner
  close, then the PID is re-opened and creation-time identity is revalidated before yield.
  `terminate` is intentionally
  unsupported because Windows has no general cooperative equivalent for an
  arbitrary process HANDLE; `kill` uses `TerminateProcess` after identity check.

Detached identity comparison is proof-based: `Identity#same_pid?` reports only
numeric PID equality, while `Identity#same_process?` requires generation evidence
on both sides. A tokenless identity therefore never promotes PID reuse risk into a
false same-process claim.

macOS still has no stable process-reference backend in 0.7.0, but it can now
return generation-bearing `lookup`/`observe` snapshots through `libproc`.
FreeBSD retains the conservative `observe` fallback; other targets do not gain
an unsupported stable handle merely from point-in-time process inspection.
Native macOS snapshot observation and ABI behavior have been exercised on macOS 15.4.1 arm64; broader version/architecture qualification remains outstanding.

Calls that suspend through Crystal's runtime are bridged onto an isolated
execution context when invoked from a raw `Thread`. Linux pidfd close also
preserves the PTY ownership rule: logical fd ownership is relinquished once,
and a native close error is reported rather than retrying a potentially recycled
integer fd. Block-scoped handle cleanup and Windows temporary HANDLE cleanup
follow PTY's error-precedence contract: a cleanup anomaly cannot replace an
already-owned caller/wait/control error,
while owner-controlled retained HANDLE close remains checked and retryable. See
`docs/design.md`.

Native Darwin qualification on macOS 15.4.1 showed that `proc_pidinfo(PROC_PIDTBSDINFO)` may return `ESRCH` for an unreaped zombie while `KERN_PROC_PID` still reports that process as `SZOMB`. Observation therefore has a secondary kinfo snapshot path whose legacy 64-bit prefix layout is first runtime-validated against libproc for the current process. If that validation is unavailable, signal-presence still prevents a present but unclassifiable PID from being falsely called `Dead`. Both mechanisms remain point-in-time observations and do not create a stable control handle.
