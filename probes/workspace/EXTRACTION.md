# Extraction provenance

Source authority studied: Crystal Systems Development checkpoint
`20261027T000520747374Z-51c038478b01`, fingerprint
`51c038478b016ab956ff30d43579a5a07213ed844f9b16270494828270d0f7f6`.

The extraction intentionally rewrites ownership and namespaces rather than
copying `PTY::*` names. It preserves the underlying lifecycle lessons:

- Linux pidfd identity/signalling.
- Windows PID + creation-time identity.
- checked/retryable native HANDLE ownership.
- foreign-thread registered wait callbacks that do not enter Crystal's runtime.
- Windows Job Object kill-on-close, limits, accounting and completion-port
  diagnostics.
- Windows Job-list-at-creation plus suspended creation and explicit assignment
  before resume for race-free direct-child containment.
- explicit inherited-HANDLE allowlists and preservation of hidden Windows
  per-drive environment entries for direct process creation.
- bounded TERM -> KILL -> drain shutdown policy where soft termination exists.
- explicit acknowledgement that POSIX process groups are weaker containment.
- raw-Thread execution-context bridging for scheduler/event-loop operations.
- one-collector child wait ownership with cached status/error fan-out.
- daemon-style point-in-time `Live` / `Zombie` / `Dead` / `Unknown` process
  observation, including fail-closed POSIX fallback semantics.
- lifecycle admission serialization so close cannot be crossed by a later
  group effect after it was admitted.
- Unix owned-fd close semantics: report close failure after logical ownership is
  relinquished, never retry a potentially recycled descriptor number.

The Linux cgroup-v2 backend is a new generic supervision mechanism rather than
code copied from PTY. It follows the same guarantee discipline: recursive
population is read from `cgroup.events`, hard subtree kill uses `cgroup.kill`,
root cgroups are rejected as kill targets, and an optional POSIX process-group
fallback remains visibly weaker through `Group#mechanism`. Numeric
`cgroup.procs` migration is explicit and is not represented as race-free
initial containment.

Excluded as terminal-owned: ConPTY/HPCON, PTY FDs, terminal foreground groups,
TIOCSIG, console Ctrl+Break brokerage, resize, terminal input/output, VT state.
