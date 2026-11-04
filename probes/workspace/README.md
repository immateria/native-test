# Crystal process primitives workspace

Development workspace containing two independently owned shards:

- `process-handle`: stable identity/control of one native process.
- `process-supervision`: process-group/tree lifecycle, containment, and supervised child creation.

The source was extracted from process-generic logic already proven inside the
current Crystal Systems `pty` stack. Terminal-specific mechanics remain in
`pty`; this workspace is intended to become their reusable lower-layer
dependency after API/runtime qualification, not a fork of PTY.

Current supervision mechanisms are deliberately distinguishable:

- Windows Job Objects: strong kernel containment and kill-on-close; direct
  children can be created suspended with Job membership established before
  their initial thread runs.
- Linux cgroup v2: recursive population observation and `cgroup.kill` when an
  existing delegated cgroup exposes the required interface.
- POSIX process groups: portable signalling/drain fallback, but escapable via
  session/group changes and not kill-on-owner-death containment.

See each shard README plus `EXTRACTION.md` for ownership and provenance.
The current research line includes event-loop Linux pidfd waits, Darwin
creation-time process observations, and Windows lifecycle hardening found by exhaustive
native qualification: finite registered-wait timeouts, close/effect admission, strict
post-close Job behavior, leak-free Job event-reader teardown, and first-error-wins
cleanup for both supervised-spawn rollback and block-scoped `ProcessHandle.open`. Linux
pidfd signalling diagnostics also retain the actual target PID through access-denied errors,
and Linux rejects out-of-range native PID values before conversion rather than leaking
an arithmetic overflow from the implementation.
Platform capability boundaries remain explicit. See the installed Skill references for external-source
comparison and exact native qualification receipts.
