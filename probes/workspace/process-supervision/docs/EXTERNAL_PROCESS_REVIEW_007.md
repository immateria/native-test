# External process-behavior review — checkpoint 0007

This pass compared the process primitives against thirteen additional pinned source snapshots supplied for review. They are evidence only; none becomes a runtime dependency.

## Production change

Windows supervised-spawn rollback now preserves the original setup exception if closing the partially-created stable `ProcessHandle` also fails. The former rescue path called `stable_handle.close` before re-raising the primary exception, so a secondary close failure could replace the actual containment/identity failure. A source-contract regression was added before the implementation change.

## Probe/API lessons accepted for qualification

- **Wine / ReactOS:** `JobObjectBasicProcessIdList` reports active members, has meaningful undersized-buffer behavior, and can retain accounting after processes disappear from the active list. Nested Job/completion behavior and partial side effects around failed multi-Job creation deserve explicit native evidence.
- **BuildXL:** ordinary Job completion-port messages are notifications, not universally guaranteed delivery. Notification-limit messages are the stronger documented path. PID-list readers must tolerate process-table churn and validate returned lengths rather than trusting one snapshot.
- **System Informer / Fs.Processes / JobExplorer:** Windows exposes substantially more Job observation than the current public shard surface, including process-ID lists, notification/violation information, end-of-job policy, freeze, memory-usage and newer container/silo classes. Only stable/documented classes relevant to supervision are candidates for future public APIs; newer/private classes remain comparative evidence.
- **CPython:** kqueue process waits must handle registration races, creation/control failures and very large timeouts without turning an exit notification into an assumption that a child is already reaped. Failed-spawn cleanup is stress-tested against concurrent descriptor creation/reuse.
- **Go:** process exit and inherited-pipe EOF are separate completion conditions; descendants can keep a pipe open after the direct child has exited. Concurrent exec must not cross-inherit spawn-status resources.
- **Rust / Swift Corelibs Foundation:** Windows implementations serialize or constrain inheritable-handle exposure during `CreateProcess`; this reinforces the shard's stronger explicit HANDLE allowlist. Native qualification now stresses separate Jobs spawning concurrently with unrelated inheritable sentinel handles.
- **OpenJDK:** macOS process-tree enumeration uses `KERN_PROC_ALL` with size/fetch retry and start-time identity; Windows parent/child checks compare creation times to reduce PID-reuse false ancestry. This supports future observational tree APIs without weakening stable-identity rules.
- **Apple Libc:** `posix_spawn`/`posix_spawnp` behavior is useful implementation evidence for future POSIX direct-spawn work, but shell/path fallback semantics are not imported into the current strong-supervision API.
- **win_safesubprocess:** suspended creation, assignment-before-resume, kill-on-last-Job-handle and explicit setup-versus-cleanup failure preservation closely match this shard's intended Windows contract.

## Deferred

No public process-tree enumeration API, Job PID-list API, guaranteed notification-limit API, macOS wait API, or POSIX `posix_spawn` API is added by checkpoint 0007. Revision-9 native probes collect evidence first. Newer Windows Job information classes (silo/container/freeze/network/I/O-rate, etc.) remain out of scope until a concrete consumer contract exists and supported-version behavior is qualified.
