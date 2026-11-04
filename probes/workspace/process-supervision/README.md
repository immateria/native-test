# process-supervision

Native process-group and process-tree lifecycle primitives for Crystal.

This shard is intentionally separate from `process-handle`: a handle identifies
one process; supervision owns or controls a group/tree lifetime.

Current mechanisms:

- Windows `ProcessSupervision::Windows::Job`: Job Object with
  `KILL_ON_JOB_CLOSE`, checked ownership, optional memory/process/CPU/priority/UI
  limits, accounting, diagnostic limit events, whole-job kill, drain waiting,
  identity-revalidated adoption, and race-free direct-child spawn.
- Linux `ProcessSupervision::Linux::CgroupV2`: an existing or newly created
  non-root cgroup-v2 controller using recursive `cgroup.events` population and
  kernel `cgroup.kill`. Creation requires an already delegated/writable parent;
  this shard does not change controller delegation policy.
- POSIX `ProcessSupervision::POSIX::ProcessGroup`: controller for an existing
  process group, with TERM/KILL and drain observation. It explicitly reports
  `kill_on_close? == false`; a descendant that changes session/group can escape.

```crystal
require "process-supervision"

# POSIX: useful but explicitly weaker containment.
pg = ProcessSupervision.process_group(pgid)
pg.shutdown(grace: 2.seconds)

# Linux cgroup v2: strong recursive hard-kill when the host delegated a cgroup.
cgroup = ProcessSupervision::Linux::CgroupV2.create(parent, "worker-42")
cgroup.attach(pid) # explicit post-spawn PID migration; not race-free initial containment
cgroup.kill
cgroup.wait_empty(2.seconds)
cgroup.close

# Callers may deliberately request an observable weaker fallback.
group = ProcessSupervision.cgroup_v2(path, fallback_pgid: pgid)
case group.mechanism
when .cgroup_v2?
  # strong recursive cgroup semantics
when .process_group?
  # weaker POSIX fallback
else
end

# Windows: direct child is contained before its initial thread is resumed.
job = ProcessSupervision.job
child = job.spawn("worker.exe", ["--serve"], env: {"MODE" => "worker"})
status = child.wait(5.seconds)
job.shutdown(kill_after: 2.seconds)
child.close
```


## PTY-derived lifecycle semantics

`Child#wait` uses the same single-collector model as the PTY Session backends.
Concurrent callers do not independently reap the child: one collector owns the
`Process#wait`, publishes one cached `Process::Status` or one cached error, and
wakes every waiter. Repeated successful waits therefore return the exact same
status object.

Operations that require a Crystal execution context are callable from a raw
`Thread` through the PTY-style isolated-context bridge. For child status waits,
the Crystal child-reaper still needs runtime progress; callers should follow the
PTY contract of observing completion before joining a raw waiter thread rather
than blocking the runtime thread on the join itself. Stable pidfd-only waits do
not have that child-status dependency.

POSIX process-group and Linux cgroup effects are serialized with close. Once
close wins admission, later signal/attach/kill/observation operations are
rejected instead of slipping through a check-open/use gap. This is the lower
process primitive analogue of pty-server's exact-lifetime effect gate, without
importing its session/protocol state machine.

## Windows spawn contract

`Job#spawn` is direct executable/argv execution, not a shell-string API. It:

1. creates a Job-list process attribute and a standard-HANDLE allowlist;
2. calls `CreateProcessW` with `CREATE_SUSPENDED`;
3. establishes Job membership at process creation and explicitly verifies
   assignment while the initial thread is still suspended;
4. opens and validates a stable `ProcessHandle` identity before resume;
5. hands the already-contained child to Crystal's low-level process owner,
   which resumes the initial thread exactly once.

Direct `.bat`/`.cmd` execution is rejected; invoke `cmd.exe` explicitly when
shell semantics are actually required. Native Windows qualification has exercised
this spawn/containment path on build 17763; platform-version evidence remains explicit
rather than being promoted into a universal Windows guarantee.

## Linux cgroup-v2 contract

`CgroupV2.open` refuses the hierarchy root and requires `cgroup.procs`,
`cgroup.events`, and `cgroup.kill`. `empty?` uses recursive `populated` state;
`kill` writes to the kernel subtree-kill primitive. `attach(pid)` writes a
numeric PID to `cgroup.procs`; because that operation is PID-addressed, it is
not advertised as a race-free spawn mechanism. A future initial-containment
API must enter the target into the cgroup before untrusted child code can run.

0.7.0 therefore provides strong Windows initial containment, strong Linux
cgroup tree kill/observation, and PTY-derived wait/lifecycle ownership, but not
yet a race-free Linux spawn-into-cgroup primitive. Windows Job close also keeps
logical Job closure separate from completion-port cleanup completion: if the
secondary event-reader cleanup fails, a later close retries it instead of
forgetting that resource. Job limit-event reader access is synchronized with
Job ownership mutation, and post-close hard-kill/event queries fail closed. The
completion-port reader lets its dedicated raw Windows Thread perform its own system
cleanup instead of joining it, avoiding the per-reader HANDLE leak observed with
Crystal 1.22.x `Thread#join`. `Group#shutdown(close: true)` also attempts cleanup
when its *initial* state observation throws, preserving that error over any
secondary cleanup failure. Windows supervised-spawn rollback also preserves the original setup failure when closing a partially-created stable process handle fails, so cleanup cannot replace the primary diagnostic.
