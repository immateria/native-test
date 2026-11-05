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
  process group, with TERM/KILL and drain observation, and (Linux, macOS) a race-free
  `spawn` / `spawn_leader`. It explicitly reports `kill_on_close? == false`; a
  descendant that changes session/group can escape. Process group 1 is refused:
  `kill(-1, sig)` would signal every process.

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


## Spawning on Linux and macOS

Every backend can now create its child already contained, the way `Windows::Job#spawn` does:

```crystal
# Strongest containment this host offers; child.group.mechanism says which one was used
child = ProcessSupervision.spawn("worker", ["--serve"], env: {"MODE" => "x"}, chdir: "/srv")
child.group.shutdown(grace: 2.seconds)   # ends the whole tree and releases the group
child.close

# Talking to a child
child = ProcessSupervision.spawn("sort", input: Process::Redirect::Pipe, output: Process::Redirect::Pipe)
child.input.puts "b\na"
child.input.close
child.output.gets_to_end                 # => "a\nb\n"

# Any IO works; one that is not a file descriptor is copied through a pipe, and wait returns once the copy is done
out = IO::Memory.new
child = ProcessSupervision.spawn("sort", input: IO::Memory.new("b\na\n"), output: out)
child.wait                               # out.to_s == "a\nb\n"

# Explicitly
cg = ProcessSupervision::Linux::CgroupV2.create(parent, "job-1")
child = cg.spawn("worker")               # in the cgroup before it runs one instruction
leader = ProcessSupervision::POSIX::ProcessGroup.spawn_leader("worker")   # new group, child == leader
helper = leader.group.as(ProcessSupervision::POSIX::ProcessGroup).spawn("helper")  # joins that group
leader.group.as(ProcessSupervision::POSIX::ProcessGroup).escapees   # marked descendants that left the group (setsid)

ProcessSupervision.strongest_mechanism   # => CgroupV2 / ProcessGroup / JobObject, decided by trying
ProcessSupervision::Linux::CgroupV2.delegated_parent   # where this process may create a cgroup, or nil
```

Contract, all of it measured natively (explore/FINDINGS.md, "Spawning into containment" and "Where cgroups are usable"):

- `command` is resolved in the caller before `chdir` takes effect (a name is searched in the caller's `PATH`, a path with
  a slash is made absolute against the caller's directory). Standard streams 0-2 are inherited and nothing else is.
- The child starts with default signal dispositions and an empty signal mask. The stdlib's `Process.new` hands on an
  ignored `SIGPIPE`; a supervisor should not.
- Errors use the stdlib's classes: `File::NotFoundError`, `File::AccessDeniedError`, `IO::Error`, plus `ArgumentError`
  for NUL bytes and `Error::Unavailable` when a group cannot be joined or a cgroup is unusable.
- **Linux engines**, best first, each giving the pidfd together with the process (so a command that exits at once is
  still supervised): `pidfd_spawn` (glibc 2.39+, looked up at run time) with `SETPGROUP` / `posix_spawnattr_setcgroup_np`,
  which does not copy the supervisor's page tables (0.27-0.45 ms against 16-23 ms for fork at a 512 MiB heap on the hosted
  runners); `clone3(CLONE_PIDFD [| CLONE_INTO_CGROUP])` with the setup done in the child; fork, where a seccomp filter
  refuses clone3 (a default Docker profile on Ubuntu 22.04 answers `ENOSYS`). glibc 2.39 leaks the pidfd of a child whose
  exec failed (BZ 31695); the descriptor is identified (lowest free number before the call, a pidfd of a gone process
  after it) and closed. Writing the pid to `cgroup.procs` after the child exists lost children in 36-73% of trials under
  CPU contention, so nothing here does that. A cgroup that was killed accepts no new children (`Error::Killed`).
- **macOS:** `posix_spawn` with `SETPGROUP`, started suspended so the exit watch (`ProcessHandle::Kqueue`) exists before
  the child can exit, then resumed.
- **Descendants that leave a process group** (Linux and macOS): children spawned into a `ProcessGroup` carry
  `PROCESS_SUPERVISION_GROUP=<token>` (also with `clear_env`; `track_descendants: false` turns it off). `#escapees` finds
  marked processes outside the group by reading `/proc/<pid>/environ` or `sysctl(KERN_PROCARGS2)` (43 ms on the macOS 15
  arm64 runner); `terminate`, `kill` and `shutdown` signal them too, through a handle that watches the process before it
  re-checks the marker, so a recycled PID is never signalled; `empty?` stays false while one lives. A descendant that
  clears or rewrites its environment before it execs is not found; only a cgroup or a Job contains it.
- Detection is by trying: `CgroupV2.available?` only says a hierarchy is mounted (a default container mounts it read-only).
  `usable?(parent)` and `delegated_parent` create and remove a probe cgroup. A refused create (`EACCES`, `EROFS`) is
  `Error::Unavailable`, so `ProcessSupervision.cgroup_v2(path, fallback_pgid:)` falls back.
- **Standard streams** (`input:`, `output:`, `error:`), on Linux, macOS and Windows Jobs: `Process::Redirect::Inherit` (the default),
  `Close` (the null device), `Pipe` (read or write it through `child.input` / `child.output` / `child.error`, closed by
  `child.close`), an `IO::FileDescriptor` such as a `File`, or any other `IO` (`IO::Memory`, a wrapper), which gets a pipe
  and a copy fiber: `Child#wait` returns once the copies are done and raises a failed copy (the exit status stays in
  `Child#status`); a child that exits without reading its input is not an error. The parent's pipe ends are non-blocking
  (fiber-friendly), the child's are blocking, and the child's ends are closed in the parent as soon as the process exists,
  so EOF arrives when the child exits. On Windows each stream is its own inheritable duplicate in the
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` allow-list, the child's pipe ends are synchronous and the parent's overlapped (as in
  the stdlib), and a file opened for overlapped I/O is copied through a pipe like any other IO.

## Spawn options, control and supervision (first cut)

Built in one pass over the roadmap's gaps; every piece has specs that run natively (shard-dev), but the API is not
settled. See `ROADMAP.md` for what is built, what is a first cut and what is open.

```crystal
options = ProcessSupervision::SpawnOptions.new
options.new_session = true                               # Linux, macOS
options.extra_fds = {3 => some_file}                     # Linux, macOS; Windows: handle values in PROCESS_SUPERVISION_HANDLES
options.ipc = true                                       # Linux, macOS: socket pair, child's end in PROCESS_SUPERVISION_IPC_FD
options.rlimits = {ProcessSupervision::SpawnOptions::Rlimit::Nofile => {256_u64, 256_u64}}   # Linux
options.umask = 0o077_u32; options.no_new_privileges = true                                   # Linux
child = ProcessSupervision.spawn("worker", options: options)
child.ipc.puts "hello"

group = child.group
group.signal(Signal::HUP)          # every member (process group: killpg plus marked escapees; cgroup: pidfd per member)
group.suspend; group.resume        # SIGSTOP/SIGCONT, cgroup.freeze, NtSuspendProcess per Job member
group.stop(grace: 5.seconds)       # request_stop (TERM / CTRL_BREAK + WM_CLOSE), wait, then kill
child.outcome                      # ExitOutcome: exited(code) / signaled(signal, core) / crashed(NTSTATUS name)

child.handle.usage                 # ProcessHandle::Usage: cpu times, resident and peak bytes, I/O bytes
ProcessHandle.descendants(child.pid)                     # from a process snapshot (parent links)

lifeline = ProcessSupervision::Lifeline.arm(group)       # POSIX: a watcher kills the group if this process dies
lifeline.disarm

cg.limits = ProcessSupervision::Linux::CgroupV2::Limits.new(memory_max: 512_u64 << 20, pids_max: 64_i64)
cg.stats; cg.memory_events; cg.members; cg.frozen?
scope = ProcessSupervision::Linux::SystemdScope.acquire  # a delegated cgroup from systemd (experimental)

supervisor = ProcessSupervision::Supervisor.new
spec = ProcessSupervision::Supervisor::Spec.new("api", "/usr/bin/api")
spec.readiness = ProcessSupervision::Supervisor::Readiness::Notify   # sd_notify READY=1 on NOTIFY_SOCKET
spec.watchdog = 10.seconds                                           # WATCHDOG=1 expected within this
supervisor.add(spec); supervisor.start
supervisor.events.receive                                            # Starting / Started / Ready / Exited / Restarting ...
```

What building it found (details in explore/FINDINGS.md, "First pass over every roadmap gap"):

- With execution contexts a fiber can resume on another thread after any blocking call, so nothing here does blocking
  Crystal I/O, or anything that can yield, while it holds a `Thread::Mutex`; interface files under a lock use raw syscalls.
- A descriptor the event loop only waits on (a kqueue copy, an inotify instance) is wrapped with
  `IO::FileDescriptor.new(handle:)`: the public constructor sets its blocking mode, which macOS refuses on a kqueue
  (`ENOTTY`) and which turns a non-blocking inotify descriptor blocking on Linux.
- The socket library is required on POSIX only: on Windows it starts Winsock at program start, and a program built with
  it dies before `main` when spawned with `clear_env` (no `SystemRoot`).
- `SystemdScope` only helps a process that may move children into the scope: moving needs write access to `cgroup.procs`
  of the closest common ancestor, which a supervisor in a system service does not have; `acquire` says so.
- A Linux process group whose members are all zombies still answers `kill(-pgid, 0)`; `empty?` reads `/proc` to tell.

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

Race-free Linux spawn-into-cgroup is `CgroupV2#spawn` (see "Spawning on Linux and
macOS"); `attach` remains for processes that already exist. Windows Job close also keeps
logical Job closure separate from completion-port cleanup completion: if the
secondary event-reader cleanup fails, a later close retries it instead of
forgetting that resource. Job limit-event reader access is synchronized with
Job ownership mutation, and post-close hard-kill/event queries fail closed. The
completion-port reader lets its dedicated raw Windows Thread perform its own system
cleanup instead of joining it, avoiding the per-reader HANDLE leak observed with
Crystal 1.22.x `Thread#join`. `Group#shutdown(close: true)` also attempts cleanup
when its *initial* state observation throws, preserving that error over any
secondary cleanup failure. Windows supervised-spawn rollback also preserves the original setup failure when closing a partially-created stable process handle fails, so cleanup cannot replace the primary diagnostic.
