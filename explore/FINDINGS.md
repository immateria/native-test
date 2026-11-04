# What the native runs showed

Measured on GitHub-hosted runners. The kit and `job_explore` ran on **Windows Server 2025 x64** (`windows-2025`,
Crystal 1.21.1 MSVC) and **macOS 15 arm64** (`macos-15`, Crystal 1.21.1 universal) (`native-probes.yml`). The C
exploration probes and `crystal_spawn` ran on Windows Server 2025 and 2022 x64 and Windows 11 arm64, macOS 14/15/26
arm64 and 15/26 Intel, and Ubuntu 22.04/24.04 x64 and 24.04 arm64 (`explore-matrix.yml`). Every number below comes
from a CI run on branch `native-probes-ci`; run ids are given so the artifacts can be re-read. "Verified" means
observed directly; "inferred" means it fits the data but was not isolated.

Final state: kit r13 qualifies on **macOS** (386 Crystal + 45 C/SDK cases), on **Windows as the runner provides it
(elevated)** (459 cases) and on **Windows with a filtered, unelevated token** (459 cases) — run `41776017433`, all
three validators pass; again with the `kevent` EINTR fix (below) in run `41793011070`.

---

## Windows Job objects

### Limits are checked in a periodic, system-wide pass every 7.000 s (verified)

Not when a limit is crossed. Microsoft only says the system "periodically checks".

* Six job-time-limited CPU spinners started back to back were killed **7004.6 / 6998.6 / 7000.7 / 6998.9 / 6998.5 ms**
  apart (elevated) and 7001.5 / 6997.9 / 6999.5 / 7000.8 / 7002.4 ms apart (unelevated); the first kill landed at an
  arbitrary phase (6099 ms, 2163 ms after start). `explore` `cpu-period`.
* Two jobs started 2.5 s apart were killed at the **same instant** (both at 48102.4 ms in the elevated run, both at
  44166.8 ms in the unelevated run) — one global pass, not a per-job timer.
* The configured limit is irrelevant (50, 150, 300 ms behave identically); trials strictly alternated killed / not
  killed when each trial lasted ~3.5 s, because every firing ends the running trial and phase-locks the next one.
* The same pass delivers **notification limits**: `JOB_OBJECT_MSG_NOTIFICATION_LIMIT` for write-bytes, read-bytes and
  job-time limits arrived 0.2–6.3 s after the case started (it is just "whenever the next pass is"; the I/O itself was done within
  ~0.5 s), even when the child had already exited. Two messages for one limit were 6.995 s apart.
* I/O and CPU **accounting is immediate** (`QueryInformationJobObject` shows 4 MiB written within the first 0.5 s
  sample); only the limit/notification evaluation waits for the pass.
* The violation flags are consumed by the query: after the first non-zero `JobObjectLimitViolationInformation` read
  they read zero again, and no further message is sent until that query is made (documented).
* Consequence for tests: any assertion that a limit was enforced must allow **two periods (≥ 15 s)**. The kit's
  4 s spin / 7 s wait and 5 s notification wait passed or failed by where the tick happened to land.
* **Not specific to one build or to job limits** (`proc_explore period`, runs `41783031447`, `41783972189`, `41788061976`): successive
  kills were 6989.6–7015.1 ms apart on Server 2022 (20348) and 6998.3–7002.1 ms on Server 2025 (26100), elevated and
  unelevated, for a per-job **and** a per-process user-time limit; on Windows 11 arm64 (26200) 7042–7161 ms. A job
  with a job limit and a job with a process limit, started 2.5 s apart, were killed in the same millisecond on every
  build. The exit code is `0xC0000044` (`STATUS_QUOTA_EXCEEDED`).
* The longer arm64 period is **not a clock effect** (run `41788061976`): the same kills timed with
  `QueryPerformanceCounter` and with interrupt time agree with system time to 0.1 ms, and over the 90 s probe the
  three clocks ran at the same rate (system/QPC 1.000002 on arm64, 0.999988–1.000013 on x64). On arm64 the pass came
  every 7070–7161 ms in that run.

### A HIGH or REALTIME job priority class needs `SeIncreaseBasePriorityPrivilege` ENABLED (verified)

* An administrator token **holds** the privilege **disabled**. In a fresh process, the request fails with
  `ERROR_PRIVILEGE_NOT_HELD` (1314) for all three request shapes (basic, extended, extended + `KILL_ON_JOB_CLOSE`) —
  identically from the kit executable and from the exploration executable, with no thread token.
* After `AdjustTokenPrivileges` enables it (state read back from the token = `enabled`), HIGH is accepted at every
  step and the child gets class `0x80` (`r6_priority_applied_high`: `actual 128`).
* A filtered/unelevated token does not hold the privilege at all (its only privilege is `SeChangeNotify`), so HIGH and
  REALTIME give 1314 there from every caller priority class, while ABOVE_NORMAL and below are accepted.
* Microsoft's docs say "must enable"; a Stack Overflow report fixed the same 1314 by enabling it. The caller's own
  priority class is irrelevant.
* **Unexplained:** inside my exploration program, HIGH requests in one loop iteration reported success while
  `priority_trace` calls bracketing that iteration reported 1314. It sits in the tool, not the kit, and I did not find
  the cause.

### A job priority class is applied to a process created *into* the job, not to one assigned afterwards (verified, once)

The kit creates its child inside the job (`PROC_THREAD_ATTRIBUTE_JOB_LIST`) and the class applies (idle `0x40`, normal
`0x20`, above-normal `0x8000` as set). The exploration created a suspended child and called
`AssignProcessToJobObject`: the class read `0x4000` before assignment, right after it, and while running, for every
class and every flag combination.

### Hosted runner facts (verified)

* The runner is an **elevated administrator** (`runneradmin`): token elevated, integrity High (0x3000), UAC elevation
  type "default", Administrators enabled, `SeDebug`/`SeImpersonate`/`SeCreateGlobal`/`SeChangeNotify` enabled, the
  rest of an admin's privileges held but disabled.
* The process is **already inside a job** and runs at **BELOW_NORMAL**, which child processes inherit.
* The kit says "never run elevated", so CI runs it both ways.

### Running unelevated on an elevated runner

* `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE | LUA_TOKEN)` + Medium integrity (`S-1-16-8192`) gives
  `is_elevated 0`, Administrators not enabled, one privilege — a standard-user profile (verified). A Microsoft Q&A
  answer says `CreateRestrictedToken` alone does not de-elevate (integrity stays High); I always lowered the
  integrity label, so I did not measure that myself.
* It also has to set the token's **owner and default DACL to the user** (as a real UAC-filtered token does). Left as
  the elevated token's Administrators-only values, the unelevated process cannot open the child processes and jobs it
  creates itself (`AccessDenied` in `adopt`, six kit cases).
* `pwsh` cannot be run under this token on the hosted runner: every native command it starts fails (`Access is
  denied`, then PowerShell's "StandardOutputEncoding is only supported when standard output is redirected").
  File ACLs are not the cause (`crystal.exe` grants Users RX). Giving the child its own console
  (`CREATE_NO_WINDOW`) makes even a Crystal executable die with `STATUS_DLL_INIT_FAILED` (0xC0000142). So only the
  probe **executable** is run filtered (`PROCESS_PROBE_LAUNCHER`); the wrapper and the build stay elevated.
  Why pwsh fails was not isolated (inferred: console / desktop access for a restricted token on a non-interactive
  runner).

---

## macOS

### `kill(-pgid, sig)` returns `EPERM` once every process left in the group is a zombie (verified)

For signal 0, `SIGTERM` and `SIGKILL` alike; Linux keeps delivering to zombies (rc 0) and returns `ESRCH` only after
reaping. `kill(pid, sig)` on the zombie itself still succeeds on macOS.

| State | macOS 15 arm64 | Linux |
|---|---|---|
| group leader alive | 0 | 0 |
| leader exited, not reaped (only zombie) | **EPERM** | 0 |
| leader zombie + live member | 0 | 0 |
| leader zombie, last member gone | **EPERM** | 0 |
| two own children, both zombies | **EPERM** | 0 |
| reaped | ESRCH | ESRCH |

`SIGTERM`, then `SIGKILL` to a group the TERM kills: **EPERM in 300/300 trials at a 1 ms gap, 300/300 at 10 ms and
100/100 at 50 ms** (700/700, repeated in every run), and 12–20 % at a 0 ms gap (37/300 and 59/300 in two runs). The kit's `signal` raised on it and its `empty?`
called such a group non-empty, so escalation raised whenever the group died during the grace period; on Darwin that
`EPERM` now means "no live member", with a deterministic regression case.

**Same on every macOS tried** (macOS 14, 15, 26 arm64 and 15, 26 Intel, `explore-matrix`): `EPERM` in 700/700 trials
at a 1–50 ms gap in each, 6–26 % at 0 ms; 0 on all three Ubuntu runners.

### `EVFILT_PROC`/`NOTE_EXIT` registration on an already-exited child fails with `ESRCH` (verified)

200/200 zombie registrations failed with `ESRCH` (never "registered but silent"); 100/100 registrations before exit
delivered. The 16-child kit case lost two registrations that way when spawning outlasted the children's 90–162 ms
delays. Same 200/200 and 100/100 on all five macOS runners.

### `kevent` is never restarted after a signal, `SA_RESTART` or not (verified)

The one 8-child failure (8 successful registrations, 7 events) was a **harness bug**. XNU's `kevent_cleanup` turns
`ERESTART` into `EINTR` ("don't restart after signals", `bsd/kern/kern_event.c`), and Crystal's runtime handles
`SIGCHLD` (with `SA_RESTART`) for every child that exits. The kit's `kevent_wait` returned that `EINTR` as "no
event", and the case makes exactly eight single-event waits. `kqueue_zombie.c` emulates it on all five macOS runners
(run `41791776012`): with a Crystal-like handler 6–23 of 320 waits returned `EINTR` and 15–55 % of trials got fewer
than 8 events — with or without a second thread that could have taken the signal. The kernel itself lost nothing:
about 11 000 registrations per runner, with and without a concurrent reaper, at the kit's and at tight exit delays,
all delivered (run `41790549832`). `kevent_wait` now retries with the remaining time; in the next kit run the case
needed one retry (`eintr_retries: 1`, run `41793011070`) and passed.

---

## Crystal 1.21.1 facts the harness had wrong (all reproduced)

* `N.times.map { … }` is a **lazy iterator**: the block runs when consumed, once. It made "concurrent" thread groups run
  one at a time, timed waits run after the child had exited, and barrier tests race nothing.
* `Atomic` is a struct: `array[i].set(x)` (and `pointer[i].set(x)`) mutates a copy.
* A bare `Thread.new` thread has no execution context. `File.read/write/open`, `IO.pipe`, `Process.new/run` and fiber
  `sleep` raise `NilAssertionError: Thread#execution_context cannot be nil` there; `File.exists?`, `Dir.children`,
  `Thread.sleep`, `::Mutex` and `Atomic` work. `spawn` fibers and `Fiber::ExecutionContext::Isolated` work.
* Each `Isolated` context keeps its event-loop descriptors until the process exits (Linux +3 fds each, measured;
  macOS +8 for 8 contexts, so presumably 1 each); fibers keep none — do not count fds around them.
* `Process#wait` **closes the child's pipes** ("Waits for this process to complete and closes any pipes").
* `Process.new` closes the child's stdio by default; a grandchild must be given `output: Redirect::Inherit` to retain a
  pipe.
* Stdlib `Process.new` opens `/dev/null` three times before it spawns and has no `ensure` on that path: a failed spawn
  leaves them to the GC finalizer (descriptor counts return to baseline after `GC.collect`).

From `explore/posix/crystal_spawn.cr` on all eight POSIX runners (macOS and Linux unless stated):

* `Process.new`/`Process.run` have **no process-group option**. A parent `setpgid(child, child)` right after
  `Process.new` returned `EACCES` ("child has already exec'd") in 100 of 100 trials on every runner: by the time
  `Process.new` returns, the exec has happened, so a supervisor cannot put a stdlib-spawned child in its own group.
* A child gets the parent's **ignored** signals, and Crystal itself ignores `SIGPIPE`, so every child starts with
  `SIGPIPE` ignored (plus whatever the program ignored, here `SIGHUP`, `SIGINT`). The blocked mask is **not** passed
  on (unlike plain fork+exec and `posix_spawn`). Descriptors opened without `O_CLOEXEC` outside the stdlib leak into the
  child.
* A relative command path is resolved **after** `chdir:` takes effect: `Process.run("explore-out/build/sigstate",
  chdir: "/tmp")` raised `File::NotFoundError`. With a missing `chdir:` directory the error is also
  `File::NotFoundError`, and its message names the executable, not the directory.
* Failure classes: missing file, missing interpreter, `ENOTDIR` and a too-long path → `File::NotFoundError`; directory
  or no exec bit → `File::AccessDeniedError`; symlink loop and `E2BIG` → plain `IO::Error`. A script without a shebang
  and a garbage executable **raise `File::BadExecutableError` on macOS but spawn on Linux** (run by `/bin/sh`: exit 0
  and 127).
* `Process::Status#exit_reason` maps TERM → `SessionEnded`, KILL → `Aborted`, SEGV → `AccessViolation`.

## Windows process control beyond Job objects (`explore/windows/proc_explore.c`)

Measured on Windows Server 2025 (26100) and Server 2022 (20348) x64, elevated and with the filtered token, and on
Windows 11 arm64 (26200) elevated (`explore-matrix.yml`, runs `41783031447` and `41783972189`). Every result below was
the same in all five configurations unless a difference is stated.

### Console control events: the graceful stop for console programs, and easy to send into the void (verified)

* `CTRL_BREAK_EVENT` to a child started with `CREATE_NEW_PROCESS_GROUP`, sent with
  `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child_pid)`, reaches only that group, at once (handler ran at +0 ms).
  Without a handler, or with a handler that returns FALSE, the child dies with `0xC000013A`
  (`STATUS_CONTROL_C_EXIT`); a handler that returns TRUE keeps it alive.
* `CTRL_C_EVENT` to a process group **succeeds and delivers nothing** (`generate_ok=1`, no event, child alive).
  Microsoft documents this ("this signal cannot be limited to a specific process group"); the return value does not
  say so.
* A child with its own console (`CREATE_NEW_CONSOLE`, or `CREATE_NO_WINDOW`, which also gives it a console, just no
  window) can be reached by a helper that `FreeConsole` + `AttachConsole(child)` +
  `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)`: the handler ran 6–35 ms after the helper was started, and a child
  without a handler had exited 7–16 ms after it (kernel exit time).
  `CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP` still received `CTRL_C` this way, although `CreateProcess` documents
  that a new process group has CTRL+C disabled.
* A `DETACHED_PROCESS` child has no console: `AttachConsole` fails with error 6, so it cannot be sent any control
  event at all.
* A child that called `SetConsoleCtrlHandler(NULL, TRUE)` ignores `CTRL_C` (it stays alive).
* The filtered token changed nothing here (the launcher is simply one more process on the console).

### ConPTY (verified)

* Writing `0x03` into the pseudoconsole's input pipe raises `CTRL_C_EVENT` in the client (+0–1 ms); without a
  handler it exits `0xC000013A` within 1–2 ms; a client that ignores `CTRL_C` survives.
* Attach + `CTRL_BREAK` works for a ConPTY client like for any console.
* `ClosePseudoConsole` sends `CTRL_CLOSE_EVENT` (event 2) and the client ends `0xC000013A` even when its handler
  returns TRUE (close cannot be refused). The call returned in 0–3 ms because the output pipe was being drained.

### `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (verified)

* A child created with a stand-in parent reports that parent, inherits the stand-in's **job** and its **priority
  class** (IDLE `0x40` from the stand-in, not the creator's BELOW_NORMAL `0x4000`), and keeps both after the stand-in
  exits.
* Elevated (runner default, `SeDebugPrivilege` enabled), `OpenProcess(PROCESS_CREATE_PROCESS)` works on our own
  parent, `explorer.exe`, `winlogon.exe` and `svchost.exe`, and the child is created there. `services.exe` is
  refused (5) even elevated. With the filtered token every foreign process is refused (5).
* The child stayed in our session (2) also under a session-0 `svchost.exe`. In the first run the arm64 children did
  not report the foreign parent in the process snapshot; in the second they did, so that was not reproducible.

### Waiting (verified)

* `WaitForMultipleObjects` takes at most 64 handles; 65 fails with `ERROR_INVALID_PARAMETER` (87).
* Wait-any returns the **lowest index** among signaled handles (5 of 5, 9, 30).
* Wait-all on auto-reset events waits until all are signaled and then consumes all of them.
* Waiting for process handles wakes within 0.7–1.5 ms of the kernel exit time on x64 (2.8–4.6 ms on arm64), in
  exit-time order (the first arm64 run woke out of start order only because its children started at uneven times).
* `RegisterWaitForSingleObject` scales: 200 and 2000 registered waits all fired within 6–35 ms of being signaled.
* A job handle becomes signaled when its time limit terminates its processes, at the next enforcement pass.
  `JOB_OBJECT_POST_AT_END_OF_JOB` needs a completion port: without one the job was terminated exactly like
  `TERMINATE_AT_END_OF_JOB` (as documented). With a port, the pass posts one `END_OF_JOB_TIME` message (after the
  `NEW_PROCESS` one), the process keeps running and the job handle is never signaled.

### Crashes and the debugger (verified)

* An access violation exits `0xC0000005` in 5–13 ms, with or without `SEM_NOGPFAULTERRORBOX`; `WerFault.exe` was never
  seen. On hosted runners a crash does not hang the supervisor behind an error-reporting dialog.
* A debugger sees `80000003/first` (the initial breakpoint), then `C0000005/first`, `C0000005/second`, then the exit.
* Terminating a debugger kills its `DEBUG_ONLY_THIS_PROCESS` debuggee within 1–3 ms (exit `0xC0000354`,
  `STATUS_DEBUGGER_INACTIVE`): a "die with the supervisor" mechanism that needs no job.
  `DebugSetProcessKillOnExit(FALSE)` called after the debuggee exists makes the debuggee survive; called before
  (no debug object yet) it fails with error 6 and the debuggee still dies.

### Child-process policy, rate control, silos

* `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` makes the child's own `CreateProcess` fail with 367
  (`ERROR_CHILD_PROCESS_BLOCKED`), also with the override flag; `..._RESTRICTED_UNLESS_SECURE` lets it create.
* `JobObjectNetRateControlInformation` (bandwidth, DSCP tag) is accepted and read back, also with the filtered token
  (verified).
* **I/O rate control works, although Microsoft marks it unsupported** — the docs for
  `SetIoRateControlInformationJobObject`, `QueryIoRateControlInformationJobObject` and the structure all say
  "Windows 10, version 1607, and newer: ... not supported". Measured on every build, elevated and filtered (runs
  `41788061976`, `41790104512`, `41791776012`, `41793150011`; `proc_explore iorate`, 5 s windows, unlimited rates
  0.1–8.6 k ops/s for comparison):
  * `Set` follows the documented convention (nonzero on success; 0 and error 6 for a non-job handle). It accepts a
    nonzero `BaseIoSize` (documented as must be 0) and ignores it. `Query` always fails (error 24, or 5 with the
    filtered token), also for the C: volume's device name; the registry value `StorageBaseIOSize` does not exist.
  * `MaxIops = 20`: 4 KiB unbuffered overwrites in place run at exactly **20.0** writes/s (with or without
    write-through), 4 KiB unbuffered reads at 20.6–24.6/s; `MaxIops = 40` gives 39.8–40.0/s. Reads and writes count
    alike.
  * I/O is counted in **8 KiB units**: 64 KiB writes run at 2.4–2.6/s (20 / 8), whatever `BaseIoSize` says.
  * **Appending write-through writes cost two I/Os** (9.2–9.6/s) — the first run's "half rate"; appending without
    write-through costs one (19.6–19.8/s), so the second is the written-through file-size update (inferred).
    Buffered writes with `FlushFileBuffers` after each run at 6.6–8.6/s.
  * `MaxBandwidth` throttles accurately (1 MB/s: 14–15 × 64 KiB or about 243 × 4 KiB per second; 10 MB/s: about
    150 × 64 KiB per second) but **about once per second one write fails with `ERROR_INVALID_PARAMETER` (87)**, usually
    the first at about 1.0 s, with or without `MaxIops` as well. Only one 4 KiB run (Server 2022, elevated) had no failure. An
    IOPS-only limit never failed a write. A bandwidth-limited child therefore sees spurious write errors.
* Creating a silo through `NtSetInformationJobObject(JobObjectCreateSilo)` returned `STATUS_INVALID_PARAMETER`
  everywhere, and the extended limit `JOB_OBJECT_LIMIT_SILO_READY` was rejected (87). Not pursued.

---

## POSIX supervision primitives: macOS vs Linux (`explore/posix/`)

Measured on macOS 14, 15, 26 (arm64) and 15, 26 (Intel), and on Ubuntu 22.04 and 24.04 (x64) and 24.04 (arm64),
twice (runs `41783031447`, `41783972189`), as the unprivileged runner user. Within each OS family every version and
architecture behaved the same unless a difference is stated; the differences are between macOS and Linux.

### A stopped process and `SIGTERM` (verified)

| | macOS (all five) | Linux (all three) |
|---|---|---|
| `SIGTERM` to a stopped child, default action | **terminates it at once** | stays stopped; dies only after `SIGCONT` |
| `killpg(TERM)` to a stopped group of 3 | all 3 dead within 300 ms; the following `killpg(CONT)` fails (-1; the group is only zombies, cf. the EPERM finding) | all 3 still stopped; `killpg(CONT)` then lets TERM kill them |
| `SIGTERM` to a stopped child with a handler | handler runs only after `SIGCONT` | same |
| `SIGKILL` to a stopped child | kills it | same |

So a TERM-then-wait stop of a stopped child works on macOS and hangs until the grace period ends on Linux; a portable
supervisor sends `SIGCONT` after `SIGTERM`. The kit's `posix/process_group.cr` `terminate` sends only `SIGTERM`; its
macOS case `group_stopped_member_can_be_terminated` passes because of this macOS behaviour and would not on Linux
(the kit has no Linux lane, so nothing was changed). Crystal's `Process#terminate` inherits this: on Linux the stopped child
survived 400 ms of TERM and died after CONT; on macOS TERM alone ended it and the following `Process#signal(:cont)`
raised `RuntimeError: kill: No such process`.

### `SIGCHLD` (verified)

* macOS sends **no `SIGCHLD` when a child is continued**: STOP, CONT, TERM gave `CLD_STOPPED, CLD_KILLED` on macOS and
  `CLD_STOPPED, CLD_CONTINUED, CLD_KILLED` on Linux. `waitpid(WCONTINUED)` reports the continue on both.
* `SA_NOCLDSTOP` leaves only `CLD_KILLED` on both.
* `SIGCHLD` coalesces: 12 children exiting together produced 1–3 handler calls on macOS and 6–8 on Linux. A handler
  must reap in a `WNOHANG` loop (it found all 12 in one loop).
* `SIGCHLD` set to `SIG_IGN`, or `SA_NOCLDWAIT`, makes children vanish without a zombie on both: `waitpid` then
  fails with `ECHILD` and the exit status is lost.

### Orphaned process groups (verified, identical everywhere)

When the supervisor exits or is SIGKILLed, a stopped child in its group gets `SIGHUP` then `SIGCONT`. With the default
`SIGHUP` action that **kills** the child; with a handler or `SIG_IGN` the child runs on. A running child, a child
in its own (non-orphaned) group, and a supervisor that stays alive produce no signal. Pipe EOF from such a child
arrives before its reaper has collected it (`kill(pid, 0)` still succeeded for a moment on one Linux runner).

### Terminals (pty, verified)

| | macOS | Linux |
|---|---|---|
| master closed: session leader gets | `SIGHUP` | `SIGHUP` + `SIGCONT` |
| leader exits after hangup: foreground group gets | `SIGHUP` | `SIGHUP` + `SIGCONT` |
| leader exits: stopped background group gets | `SIGHUP` + `SIGCONT` | same |
| leader exits: running background group gets | nothing | same |

`SIGWINCH` on resize reaches only the foreground group; a background `read` stops with `SIGTTIN`; a background
`write` succeeds unless `TOSTOP` is set, then it stops with `SIGTTOU` — identical on both.

### Detecting that the supervisor died (verified)

A lifeline pipe (EOF), `getppid()` changing to 1, `kqueue EVFILT_PROC NOTE_EXIT` (macOS), `pidfd_open` + `poll`
(Linux) and `PR_SET_PDEATHSIG` (Linux) all fired within 0.1–0.3 ms (Linux) and 0.4–1.1 ms (macOS) of the supervisor
being SIGKILLed. Orphaned children and grandchildren keep running and are reparented to pid 1 (no subreaper on these
runners).

### Resource limits (verified)

* **`RLIMIT_CPU` is unreliable on macOS.** Soft 1 s / hard 3 s:

  | | macOS (all five) | Linux |
  |---|---|---|
  | user-time spin, default action | `SIGXCPU` at 1.00 s CPU | `SIGXCPU` (+core) at 1.00 s |
  | user-time spin, `SIGXCPU` ignored or handled | **never killed** (ran to the 8 s cut-off) | `SIGKILL` at 3.00 s |
  | syscall-heavy spin (about half system time) | `SIGXCPU` seconds late (6.6–6.8 s CPU) or **not at all** in 8 s | `SIGXCPU` at 1.00 s, `SIGKILL` at 3.00 s |

  The hard limit was never enforced on any macOS runner, also not with soft = hard = 1 s (`SIGXCPU` ignored: ran 5 s;
  Linux: `SIGKILL` at 1.000 s). The handler variant got exactly one `SIGXCPU`. A CPU budget on macOS has to be
  enforced by the supervisor (sample `proc_pid_rusage`, then kill).
* **Why (XNU source, confirmed by measurement):** `setrlimit(RLIMIT_CPU)` arms a per-task timer for the *soft*
  limit only (`bsd/kern/kern_resource.c`). `task_vtimer_check` sets `AST_BSD` on every trap, system call and
  interrupt (`osfmk/arm64/sleh.c`; `hndl_alltraps`, `hndl_unix_scall` and the interrupt path in
  `osfmk/x86_64/idt64.s`). `bsd_ast` (`bsd/kern/kern_sig.c`) then charges the CPU time since the previous check, as
  returned by `task_vtimer_update` (`osfmk/kern/task.c`): that converts the delta with `absolutetime_to_microtime`,
  keeps only the **whole microseconds** (and drops whole seconds), and always resets the saved value, so the
  remainder is lost. When the budget is used up it sends one `SIGXCPU` and switches the timer off; nothing looks at
  `rlim_max`. So every check discards up to 1 µs, and a process that enters the kernel more often than once per
  microsecond of CPU is barely charged. Measured with `getppid()` every N loop iterations (soft limit 1 s; run
  `41788061976`):

  | CPU time between syscalls | share charged, macOS (5 runners) | Linux (3 runners) |
  |---|---|---|
  | 0.23–0.6 µs | 0 % — no `SIGXCPU` in 8 s (macOS 15 Intel, at 0.86–0.97 µs: 18 %) | 100 % |
  | 1.1–1.6 µs | 79–93 % | 100 % |
  | 3.3–5.7 µs | 85–92 % | 100 % |
  | 29–54 µs | 98–99 % | 100 % |

  which is roughly ⌊interval⌋ / interval. A pure user-time spin is checked only at timer interrupts (milliseconds
  apart), loses almost nothing, and gets `SIGXCPU` on time.
* `RLIMIT_AS` and `RLIMIT_DATA` below the current usage: `setrlimit` fails with `EINVAL` on macOS (so nothing is
  limited; a 768 MiB allocation succeeds); Linux accepts both and the allocation fails with `ENOMEM`.
* `RLIMIT_NOFILE`: macOS defaults 10240/unlimited and accepts a soft limit of `RLIM_INFINITY`; Linux defaults
  65536/65536, rejects an infinite soft limit (`EINVAL`) and an unprivileged raise of the hard limit (`EPERM`).
* With the descriptor table full of **inheritable** descriptors, exec itself succeeds but the new program cannot start:
  macOS dyld aborts (`SIGABRT`), Linux's loader exits 127 (`libc.so.6: ... Error 24`). With `O_CLOEXEC` descriptors the
  child starts normally on both.
* `RLIMIT_NPROC` 1 for the runner user: `fork` fails `EAGAIN` everywhere; `posix_spawn` fails `EAGAIN`, except
  `EPERM` with Ubuntu 22.04's glibc 2.35. Running the case in containers with each release's glibc on both runners'
  kernels (seccomp unconfined) settles it: glibc 2.35 gives `EPERM` on kernel 6.8 and 7.0, glibc 2.39 gives `EAGAIN`
  on both (run `41788061976`). This is glibc bug 29109, "posix_spawn() always returns 1 (EPERM) on clone() failure"
  (the real errno was discarded), fixed in 2.36; Ubuntu 22.04's 2.35 does not carry the fix.
* `RLIMIT_FSIZE` with `SIGXFSZ` ignored: the write past the limit fails with `EFBIG` on both.
* Limits set before fork/exec or `posix_spawn` are inherited unchanged on both.

### Resource accounting (verified)

* `wait4` reports the child's CPU including the descendants it waited for; the CPU of an **orphaned** grandchild is
  credited to nobody the supervisor can see (`RUSAGE_CHILDREN` unchanged after it finished), on both.
* `ru_maxrss` is **bytes** on macOS and **KiB** on Linux (69 468 160 vs 68 328 for the same 64 MiB worker).
* After writing 16 MiB, macOS reports `ru_oublock` 0 while `proc_pid_rusage` reports 16 777 216 bytes written;
  Linux reports 32 768 blocks and `/proc/<pid>/io` the bytes.
* A zombie can still be measured: `proc_pid_rusage` works on it (CPU and disk I/O kept, footprint 0);
  `/proc/<pid>/stat` works but `/proc/<pid>/io` fails with `EACCES`. After reaping: `ESRCH` / `ENOENT`.

### Spawning (verified)

(Crystal's `Process.new` is covered in the Crystal section.)

* fork+exec and `posix_spawn` report the same errno for every failure tried, on both systems: `ENOENT` (missing
  file or interpreter), `EACCES` (directory, no exec bit, non-executable interpreter), `ENOEXEC` (no shebang, garbage
  bytes), `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`, `E2BIG` (environment over `ARG_MAX`).
* Differences: macOS lets you exec a file another process has open for writing (Linux: `ETXTBSY`); a single 200 000
  byte argument works on macOS (`ARG_MAX` 1 MiB) and fails `E2BIG` on Linux (per-string cap); an argv of three times
  `ARG_MAX` failed `EFAULT` on the runners (16 MiB stack limit) but `E2BIG` locally (8 MiB) — the Linux errno depends on
  the stack limit (inferred); a `posix_spawn_file_actions_addclose` of a descriptor that is not open fails the spawn
  with `EBADF` on macOS and is ignored by glibc.
* What a child inherits (fork+exec and `posix_spawn` alike, both systems): the blocked signal mask, ignored
  dispositions (caught signals reset to default), and every descriptor without `FD_CLOEXEC`.
  `POSIX_SPAWN_SETSIGMASK`/`SETSIGDEF`, `SETPGROUP` and `SETSID` do what they say on both. macOS also has
  `POSIX_SPAWN_CLOEXEC_DEFAULT` (only file-action descriptors survive) and `POSIX_SPAWN_START_SUSPENDED` (the child is
  reported stopped with signal 0 and runs after `SIGCONT`); glibc has neither.

---

## Still open

* the in-loop HIGH success in the exploration tool (above);
* why `pwsh` cannot launch native commands under the filtered token on the hosted runner;
* the Windows enforcement period (7.000 s on x64, 7.04–7.16 s on arm64, not a clock effect) is not documented
  anywhere I found, and why arm64's pass runs later is not known;
* why a job bandwidth limit makes about one write per second fail with `ERROR_INVALID_PARAMETER`.
