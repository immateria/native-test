# Revision 11 behavior matrix

Revision 11 keeps every revision-9 behavior and adds one focused native regression for checkpoint 0008, bringing the matrix to **889** checks. The 36 source-driven revision-9 additions remain intact and are summarized below.

## Revision-10 closure

- **Block-scoped handle cleanup precedence:** a probe-only Windows helper invalidates the retained native process HANDLE inside `ProcessHandle.open { ... }`, then raises a caller error. The public wrapper must return the caller error rather than replacing it with `CloseHandle(process)`. This mirrors the Linux regression that exposed the production defect.
- **Handoff admission hardening:** both native wrappers verify the complete packaged `MANIFEST.sha256` before build, copy the admitted manifest into the handback, reject redirected build paths and recreate `.build`. This is a wrapper/evidence invariant rather than an additional behavioral case.

## Revision-9 retained additions

## Windows additions

- **Supervised-spawn rollback precedence:** inject an identity/setup failure followed by a stable-handle close failure; the primary setup diagnostic must survive.
- **Job active-process enumeration:** empty, 1/2/4/8/16/32 live members, dead-member exclusion with accounting retained, undersized buffers, descendant membership and concurrent exit/query churn.
- **Completion-port ownership:** second association rejection and completion-key roundtrip.
- **Guaranteed notification-limit path:** configure a write-byte notification threshold, receive `JOB_OBJECT_MSG_NOTIFICATION_LIMIT`, then query `JobObjectLimitViolationInformation`. Ordinary NEW/EXIT/ACTIVE_ZERO messages remain diagnostic rather than promoted to guaranteed delivery.
- **Concurrent HANDLE isolation:** separate Jobs spawn in native threads while unrelated inheritable sentinel HANDLEs exist; every child must see zero sentinels because the shard uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.

## macOS additions

- **Concurrent exec inheritance:** mixed long-lived stdin-owning children and short-lived exit children at 2/4/8/16 concurrency; short children must not stall behind unrelated spawn-status resources.
- **Exit versus stream drain:** direct-child exit and EVFILT_PROC/NOTE_EXIT are proven independently of EOF when a grandchild still retains inherited stdout.
- **Huge kqueue timeouts:** 86,400 s, 1,000,000 s and 1,000,000,000 s waits must return promptly on child exit without conversion overflow or early timeout.
- **Concurrent failed-spawn descriptor reuse:** repeated failing `Process.new` calls run while unrelated pipes are created/read/closed; no cross-close or descriptor-reuse corruption is permitted.

## Independent Darwin SDK additions

The C lane now uses the OpenJDK-style `KERN_PROC_ALL` size/fetch pattern with retry headroom and checks: self inclusion, live child identity/start-time agreement, stopped state, unreaped zombie state, and reaped-child exclusion. This remains observational process-table evidence, not a stable process-control handle.

## External evidence mapped to these additions

- CPython: kqueue registration/fallback/huge-timeout and failed-spawn FD cleanup.
- Wine + ReactOS: Job PID-list sizing/membership and completion behavior.
- OpenJDK: `KERN_PROC_ALL` enumeration with start-time identity.
- Go: process exit versus descendant-held pipe EOF and concurrent exec inheritance.
- Rust + Swift Corelibs Foundation: Windows inheritable-handle launch races.
- BuildXL: PID-list churn handling and non-guaranteed ordinary completion messages.
- System Informer + Fs.Processes + JobExplorer: broader Job query/notification surfaces.
- win_safesubprocess: setup-versus-cleanup error preservation and assignment-before-resume containment.
- Apple Libc: POSIX spawn/wait evidence for deferred future work.

## Still deliberately outside qualification

- deterministic PID reuse;
- cross-user/protected-process permission matrices requiring another identity;
- AppContainer/PPL/silo/private Job semantics;
- native Windows ARM64 and macOS x86-64 runtime lanes unless separately executed;
- proof of all possible scheduler/interleaving orders;
- Linux delegated-cgroup/atomic-spawn work, which belongs to a separate native lane.
