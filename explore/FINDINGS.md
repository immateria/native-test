# What the native runs showed

Measured on GitHub-hosted runners. The kit and `job_explore` ran on **Windows Server 2025 x64** (`windows-2025`,
Crystal 1.21.1 MSVC) and **macOS 15 arm64** (`macos-15`, Crystal 1.21.1 universal) (`native-probes.yml`). The C
exploration probes and `crystal_spawn` ran on Windows Server 2025 and 2022 x64 and Windows 11 arm64, macOS 14/15/26
arm64 and 15/26 Intel, and Ubuntu 22.04/24.04 x64 and 24.04 arm64 (`explore-matrix.yml`). Every number below comes
from a CI run on branch `native-probes-ci`; run ids are given so the artifacts can be re-read. The Linux-only probes and
the kit's Linux shards ran on Ubuntu 22.04/24.04 x64 and 24.04 arm64 in a delegated cgroup. "Verified" means
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
* **The "in-loop HIGH success" was a bug in my exploration tool** (explained; the earlier text called it
  unexplained). In `job_explore.cr` one local variable was assigned a `JOBOBJECT_BASIC_LIMIT_INFORMATION` in one branch
  and a `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` in the other, so Crystal typed it as a union, and `pointerof` on a
  local binds to the variable's full type (`semantic/main_visitor.cr`, `pointerof_var`). A Crystal union of two structs
  is stored as a 4-byte type id, padding, then the value at offset 8 (`codegen/unions.cr`), so `SetInformationJobObject`
  received everything shifted by 8 bytes and read `LimitFlags` from the zeroed `PerJobUserTimeLimit`: it installed no
  limit at all and "succeeded" for every class, HIGH included. **Reproduced in C on all three Windows builds**
  (`win_more priority`, run `41886046710`): the same HIGH request shifted by 8 bytes returns success and the job reads
  back `LimitFlags 0x0`, while the correct request fails with 1314 until the privilege is enabled and then installs
  `0x20` / `0x80`. The kit and its probe do not contain the pattern (every `pointerof` site was checked); the tool now
  uses two differently named locals. Lesson for Crystal FFI: never take `pointerof` of a variable that is assigned
  more than one type in its method.

### A job priority class and affinity apply at assignment and when set on a populated job (verified; corrects an earlier claim)

An earlier version of this file said the class applied only to a process created *into* the job. That came from the
buggy loop above, which never installed a limit, so it is withdrawn. Measured with C (`win_more priority`, run
`41886046710`, Server 2022, Server 2025 and Windows 11 arm64, elevated), for idle, below-normal, normal, above-normal and
high (high with the privilege enabled), each with an affinity limit of CPU 0:

| how the child joins | class and affinity |
|---|---|
| created inside the job (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), read before it resumes | the job's, from creation |
| created suspended, then `AssignProcessToJobObject` | inherited `0x4000` / `0xf` before; **the job's immediately after the call**, still suspended |
| running in a job without limits, then the limit is set on the job | **the job's immediately after `SetInformationJobObject`** |

The values stayed the same 100 ms and 1.1 s later. This matches the Windows Research Kernel, whose assignment path calls
`PspApplyJobLimitsToProcess` and whose setter walks the existing members (`PspApplyJobLimitsToProcessSet`). Unlike the CPU
time limits, these are not deferred to the 7-second pass. `JOB_OBJECT_LIMIT_SCHEDULING_CLASS` 0, 5 and 9 were accepted
and read back (9 with the privilege enabled); its effect on quantum length was not observed.

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

From `explore/windows/crystal_spawn_win.cr` on Windows Server 2025 and 2022 (runs `41798991357`, `41800538877`):

* **Every inheritable handle in the parent reaches every child**: `Process.new` calls `CreateProcessW` with
  `bInheritHandles = TRUE` and no handle list; an inheritable event created by the parent was valid and signaled in the
  child (a non-inheritable one was not; on Server 2022 its number happened to be some other valid handle there).
* **`Process#terminate` is `TerminateProcess(handle, 1)`**, `graceful: true` or not: the status reads `1`,
  `exit_reason Normal`, indistinguishable from a child that exited with 1. `Process#signal` raises
  `NotImplementedError`.
* Exit codes: `259` (`STILL_ACTIVE`) reads as a normal exit 259; `0xC0000005` and `0xC00000FD` → `AccessViolation`,
  `0xC000013A` → `Interrupted`; `0xC0000409` (fail-fast), `0xC0000094` (integer divide by zero), `0x40010004` and
  `0xE0000001` → `Unknown`. Any status with the top bits set has `exit_code` nil and `normal_exit?` false.
* Spawn errors: missing file → `File::NotFoundError`; directory → `File::AccessDeniedError`; `.bat`, `.cmd` (also with
  a trailing `. `) and a `.txt` → `File::BadExecutableError` (Crystal refuses batch files on purpose, "BatBadBut"); a
  garbage `.exe` → plain `IO::Error` with an **empty message** (`ERROR_EXE_MACHINE_TYPE_MISMATCH`, 216, is not mapped);
  a missing `chdir:` → `File::NotFoundError` naming the command ("The directory name is invalid").
* **Executable search includes the current directory before the system directories**: with a `whoami.exe` in the
  parent's current directory, `Process.run("whoami")` ran that copy. `chdir:` does not take part: the bare name and a
  relative path are both resolved in the parent's directory — the opposite of POSIX, where the relative path is
  resolved after `chdir`.
* Arguments with spaces, quotes, backslashes, empty strings, `%PATH%`, `^&|<>`, tabs and non-ASCII round-trip exactly.
* `env: {"PROBE_A" => "1", "probe_a" => "2"}` puts **both** into the child's environment block, although Windows
  environment names are case-insensitive; `clear_env: true` leaves only what was given.

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

## Linux: cgroup v2, subreaper, pidfd, namespaces (`explore/linux/`)

Measured on Ubuntu 22.04 (kernel 6.8) and 24.04 (kernel 7.0) x64 and 24.04 arm64 (runs `41797796450`,
`41798083044`). The CI step creates a cgroup with `sudo`, chowns it to the runner user, enables `cpu memory pids` in
it and moves the step's shell into `<it>/supervisor` — the shape of a subtree a service manager delegates. Everything
below then runs **unprivileged** inside that subtree, and was identical on all three runners unless stated.

### The kit's Linux shards

* Their own specs pass on all three runners (process-handle 22 examples, process-supervision 18). The specs only
  cover discovery and the process-group fallback; `explore/linux/kit_linux.cr` drives the rest on real cgroups.
* `CgroupV2` does what its comments say: `create` refuses a name with `/` and an undelegated parent
  (`Error::Unavailable`, from `EACCES`); `open` refuses the hierarchy root; `kill` reached a descendant that had moved
  to its own session (`killpg` would have missed it); `close` of a populated cgroup raises `Error::Busy` and of an empty
  owned one removes the directory; an opened (not owned) cgroup is never removed; `shutdown` skips straight to kill
  (`soft_termination?` false, `terminate` raises `Unsupported`).
* `ProcessHandle::Linux` (pidfd) behaves on live, exited, reaped and foreign processes: `alive?` false after exit,
  `kill`/`terminate` after the runtime reaped the child are silent no-ops (no stray signal to a recycled pid), `open`
  of a reaped pid raises `NoSuchProcess`, `open(1)` works, 8 concurrent `wait`s all see the exit.
* Observations for the kit (nothing changed): `wait_empty` polls every 10 ms (10.1–10.6 ms to notice), while
  `cgroup.events` notifies through `poll(POLLPRI)` within 0.1–0.3 ms; `attach` of a nonexistent pid surfaces a raw
  `IO::Error` (`ESRCH` is not a `File::Error`), outside the kit's error types; `Child#close` closes the process and the
  handle but not the group.

### cgroup v2 (verified)

* **`cgroup.kill` reaches everything in the cgroup**, including a daemonized descendant in another process group and
  session that `killpg` left running; `populated 0` 0.1–0.3 ms later, and `poll(POLLPRI)` on `cgroup.events`
  reported the change at the same moment.
* **Zombies do not count**: a child killed but not yet reaped (state `Z`) is already gone from `cgroup.procs`, the
  cgroup reads `populated 0`, and `rmdir` succeeds before the parent reaps.
* **`CLONE_INTO_CGROUP`** (`clone3` with a cgroup directory fd) works unprivileged in the delegated subtree: the child
  starts in the target cgroup, so there is no window in which it can fork outside it. (Crystal's `Process.new` cannot
  do this; the kit's `attach` after spawn has that window, as its own comment says.)
* **Freezer**: `cgroup.freeze 1` reached `frozen 1` within 0.1–1.2 ms; frozen tasks show state `S`, gain no CPU, and
  `waitpid(WUNTRACED)` reports nothing. `SIGKILL` and a default-action `SIGTERM` still kill a frozen task; a `SIGTERM`
  handler runs only after thaw (0.1–1.2 ms after); `SIGCONT` does not thaw. `cgroup.kill` on a frozen cgroup empties
  it in 10–11 ms.
* **`memory.max` 64 MiB** (swap max 0): the hog was OOM-killed (`SIGKILL`) after touching 63 MiB, 17–41 ms in;
  `memory.events` `oom 1 oom_kill 1`, `memory.peak` exactly 64 MiB; a bystander in the same cgroup survived. With
  `memory.oom.group 1` the bystander was killed too (`oom_group_kill 1`, `oom_kill 3` for two processes — inferred: the
  victim is counted twice).
* **`pids.max` 5** (the forker itself counts): 4 forks succeeded, the fifth failed `EAGAIN`; `pids.events max 1`.
* **`cpu.max` "20000 100000"**: a 2 s spin got 420 ms of CPU (21 throttling periods, 1.63–1.65 s throttled); without
  the limit 2000 ms.
* **Accounting**: an orphaned grandchild's 400 ms of CPU appears in the cgroup's `cpu.stat usage_usec` (400.4–400.7
  ms) and not in the supervisor's `RUSAGE_CHILDREN` (0.3–0.6 ms) — the gap `wait4` leaves (see Resource accounting).
* **The delegation boundary is the delegated subtree, not the leaf**: a child moved itself from its leaf into the
  supervisor's sibling cgroup (allowed: same owner, common ancestor writable), but not to the hierarchy root or the
  parent of the delegation (`EACCES`), and could not `mkdir` at the root (`EACCES`). A supervisor that runs children
  under its own uid cannot stop them from leaving their leaf.
* The "no internal processes" rule, observed: in a populated leaf, enabling `+pids` and `+cpu` succeeded and
  `+memory` then failed with `EOPNOTSUPP`. The hierarchy root has no `cgroup.kill` file at all.

### Without cgroups (verified)

* **`PR_SET_CHILD_SUBREAPER`**: an orphaned grandchild is reparented to the subreaper (not pid 1), `waitpid(-1)`
  collects its status, and its CPU then shows in the subreaper's `RUSAGE_CHILDREN` (300 ms). The flag is not inherited
  by forked children.
* **pidfd**: `pidfd_send_signal` to a zombie succeeds, after reaping fails `ESRCH`; `waitid(P_PIDFD)` reaps
  (`CLD_KILLED`, status 9) and a second call gives `ECHILD`; `pidfd_open` after reaping fails `ESRCH`; a
  `PIDFD_NONBLOCK` pidfd makes `waitid` without `WNOHANG` fail `EAGAIN` while the child lives. A grandchild's pidfd
  polls readable at its exit, but only its parent can `waitid` it (`ECHILD`). `clone3(CLONE_PIDFD)` returns a pidfd
  together with the child. After reaping, `poll` reports `POLLIN` on kernel 6.8 and `POLLIN|POLLHUP` on 7.0.
* **`PR_SET_PDEATHSIG`**: fires when the **thread** that forked the child exits, although the parent process lives
  on; armed after the parent already died it never fires (the child saw `getppid() == 1` — check it after `prctl`);
  it survives `exec` (an exec'd shell got its `SIGTERM` when the parent died).
* **PID namespace** (`unshare(CLONE_NEWUSER | CLONE_NEWPID)`, unprivileged): killing the namespace's init killed all
  members, including a `setsid` daemon (4 alive before, 0 after 300 ms). On Ubuntu 24.04
  (`kernel.apparmor_restrict_unprivileged_userns = 1`) the `unshare` still succeeds but writing `uid_map` fails
  `EPERM`; the PID-namespace kill-all works either way.
* **`signalfd`**: 12 simultaneous child exits gave **one** `SIGCHLD` record; one `waitpid(WNOHANG)` loop found all 12.
* **`oom_score_adj`**: runner processes start at 500; an unprivileged parent can raise its child's value to 1000 and
  lower it to 0, but not to a negative value (`-500`: `EACCES`).

---

## Pipes, stdio and PID reuse (`explore/posix/pipes.c`, `pid_reuse.c`, `proc_explore pipes|pidreuse`)

All eight POSIX runners and all five Windows configurations (runs `41798991357`, `41800538877`). Results were the
same within each OS family unless stated.

**A fact about the runners first: GitHub Actions steps on macOS and Linux start with `SIGPIPE` ignored**, inherited
from the runner process (verified: `pipes` reports `inherited_sigpipe_disposition: ignored` on all eight; `sigstate`'s
parent ignores only `SIGINT` and `SIGHUP`, yet its children list `SIGPIPE` too). Any test that relies on the default
`SIGPIPE` action must set it explicitly.

### Pipes and stdio (verified)

| | macOS | Linux | Windows (anonymous pipe) |
|---|---|---|---|
| capacity before the writer blocks | 64 KiB (any write size) | 64 KiB; `F_SETPIPE_SZ` up to `pipe-max-size` 1 MiB unprivileged, 64 MiB `EPERM` | the `nSize` asked for; `0` gives **4 KiB** |
| child writes 1 MiB while the supervisor waits for exit first | blocked (deadlock until read) | blocked, state `S` | blocked |
| supervisor closes its read end, default `SIGPIPE` | child killed by `SIGPIPE` | killed by `SIGPIPE` | `WriteFile` fails `ERROR_NO_DATA` (232) |
| same with `SIGPIPE` ignored (every Crystal child, every CI step) | `write` fails `EPIPE` | `EPIPE` | — |
| **the child also inherited the read end** | **blocks forever** (it is its own reader) | blocks forever | blocks forever (inheritable read handle) |
| supervisor closes the child's stdin | `read` returns 0 | returns 0 | `ReadFile` **fails** `ERROR_BROKEN_PIPE` (109), no 0-byte success |
| child started with descriptors 0–2 closed | its first `open` gets fd **0** and the next fd 1, so whatever it later writes to "stdout" lands in that file (inferred); writes to 1/2 before that fail `EBADF` | same | (a child given `NULL` std handles under `CREATE_NO_WINDOW` wrote successfully — inferred: to its new console) |
| `O_NONBLOCK` set on the supervisor's copy of the child's stdin | the child's blocking `read` fails `EAGAIN`: one open file description, one flag | same | — |
| EOF on a pipe whose write end a grandchild inherited | only when the grandchild exits (612 ms later) | same | — |

### PID reuse (verified)

* **macOS and Linux hand out pids sequentially** (200 of 200 consecutive children got pid + 1; on one macOS 26 run
  other activity made 33 steps of 2).
* **macOS reuses a pid after one wrap of its 99 999 limit**: the first pid came back after 98 400–99 000 forks, i.e.
  **40–86 s** of continuous spawning (1 100–2 500 forks/s), on four of five runners; the fifth (macOS 15 Intel) had
  wrapped when the 90 s budget ran out. A held, unreaped zombie's pid was never reissued.
* **Linux** (`pid_max` 4 194 304, 6 400–9 300 forks/s): a full cycle takes about 7.5–11 minutes of spawning — but
  inside an unprivileged user + PID namespace, writing `ns_last_pid` made the very next child get the pid just freed
  (Ubuntu 22.04). On 24.04 AppArmor's userns restriction blocks that (`uid_map`, mount and `ns_last_pid` all `EPERM`).
* **Windows reuses pids almost at once**: 600 spawn/wait/close cycles produced only 325–471 distinct pids, the first
  repeat after 104–304 children (4–10 s). **An open handle to an exited process keeps its pid out of circulation**
  (0 reissues in 600 children while held); after closing it the pid came back within 600 children once in five.
  So a supervisor that holds the process handle (as the kit does) cannot hit a recycled pid; one that keeps only the
  number can, within seconds.

## Signals and threads, crashes, process trees, scale (`explore/posix/signals_threads.c`, `crash_latency.c`, `tree_enum.c`, `scale.c`)

Eight POSIX runners (runs `41805839970`, `41807338781`, `41808488438`). Identical within an OS family unless stated.

### Signals and threads (verified)

* **A process-directed signal (`kill(pid)` from another process) goes to the main thread if it has the signal
  unblocked** (40 of 40 on all eight). If the main thread blocks it, **all 40 went to the first-created worker that
  had it unblocked**; with only thread 3 unblocked, to thread 3. `pthread_kill` reaches exactly its target.
* 40 sends while every thread blocked the signal left **one** pending instance (standard signals coalesce).
  Unblocking in the main thread delivers it on both systems. **Unblocking in a worker thread delivers it on Linux but
  not on macOS**: the already-pending signal stayed undelivered for a full second after the worker unblocked it; a
  *new* signal sent afterwards was delivered to that worker (and counted once). A macOS program that blocks a signal
  everywhere and later enables it on a worker only can lose the wake-up it was waiting for.
* **Why (explained from XNU, confirmed by measurement):** XNU keeps pending signals per thread (`uu_siglist`). For a
  process-directed signal, `get_signalthread()` looks for a thread that does not block it; when every thread blocks it,
  `get_signalact()` picks the first thread of the task and the signal is parked in **that thread's** pending set
  (`bsd/kern/kern_sig.c`, `osfmk/kern/bsd_kern.c`). `__pthread_sigmask(SIG_UNBLOCK)` only re-checks the calling
  thread, and `sigpending()` returns only the caller's set. Measured on all five macOS runners (run `41886046710`,
  `parked_signal_collected_by_worker_sigwait`): the main thread's `sigpending` shows the signal, a worker's does not.
  **But `sigwait()` scans every thread's set** (`__sigwait_nocancel` walks `p_uthlist`): a worker calling `sigwait`
  received the parked signal at once (0.0 ms, no second signal needed) and the main thread's pending bit was cleared.
  On Linux the signal sits in the process-wide set and both threads see it. So on macOS a dedicated signal thread must
  use `sigwait` (or kqueue `EVFILT_SIGNAL` / `EVFILT_PROC`), not unblock-and-wait-for-the-handler.
* **A blocking `read` is interrupted only if the thread that blocks in it takes the signal**: main unblocked, workers
  blocked: `EINTR` after 100 ms; main blocked and a worker unblocked: the handler ran in the worker and `read` kept
  waiting (returned the data 300 ms later). With `SA_RESTART` the read restarts. Identical on both.
* **A signal that is blocked and pending is cleared by `fork` but kept across `exec`**: the exec'd program inherited
  the blocked mask and the pending bit, and its new handler ran when it unblocked (both `kill(getpid())` and `raise`).
* **A signal sent to a forked child before it execs runs the parent's handler in the child** (the handler wrote the
  child's pid; observed on both). This is the reason a fork-based spawner blocks signals around the fork.

### A crashing process is held back by the crash handler on Linux, not on macOS (verified)

The child wrote a timestamp and then faulted; the table is the time until the pipe reached EOF / `waitpid` returned.

| | macOS (all five) | Ubuntu 22.04, 24.04, 24.04 arm |
|---|---|---|
| baselines: exit, `SIGKILL` | 0.1–0.5 ms | 0.0–0.2 ms |
| null dereference, `abort()`, trap (`RLIMIT_CORE` 0) | **0.1–0.7 ms** | **45–75 ms typical, up to 185 ms** |
| `kill(pid, SIGSEGV)` from outside | 0.3–0.6 ms | **48–77 ms** |
| `RLIMIT_CORE` raised to 256 MiB | same as above; no core file appeared, no `core` flag in the status | same delay; no core file in the cwd |
| `core_pattern` | files in `/cores/core.%P` (`kern.coredump=1`), none produced | **`|/usr/lib/systemd/systemd-coredump ...`** on every image |
| status | `signaled(SIGSEGV)` | `signaled(SIGSEGV,core)` — the core flag is set although `RLIMIT_CORE` was 0 |
| crash reports | `ReportCrash` wrote 4–5 `.ips` reports under `~/Library/Logs/DiagnosticReports` within 3 s, **asynchronously: it did not delay the exit** | none |

So on the Ubuntu runners a core-dumping signal keeps the process alive for tens of milliseconds while
`systemd-coredump` reads the dump, even with a core limit of zero; `SIGKILL` is not affected. Tests that assert on the
instant a crashed child disappears must allow ~200 ms. The `__builtin_trap` instruction raises `SIGTRAP` on arm64
(macOS, Linux) and `SIGILL` on x86.

**Why a core limit of 0 does not help, and what does** (run `41886046710`, all three Ubuntu runners, 3–5 trials each):

* The runners' `core_pattern` is `|/usr/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h %d`: the
  sixth argument, where upstream systemd passes `%c` (the crashing process's core limit), is the **literal 2^63**
  (Debian/Ubuntu packaging). For a piped pattern the kernel runs the helper whatever `RLIMIT_CORE` is (it uses
  `RLIM_INFINITY` for the pipe writer, `fs/coredump.c`), and the collector never learns that the limit was 0.
  `core_pipe_limit` is **16** on all three images (not 0), so the kernel also waits for the helper to close the pipe.
* **Every core-dumping signal pays it:** `SIGQUIT` (raised), `SIGFPE` (integer division by zero on x86; raised on
  arm64, where division by zero does not trap), `SIGBUS` (touching a mapping after `ftruncate`), `SIGXCPU`
  (`RLIMIT_CPU` 1 s), `SIGSYS`: 93–113 ms (22.04, 24.04 x64) and 57–62 ms (24.04 arm64), the same as `SIGSEGV`. A
  supervisor that stops children with `SIGQUIT` pays it on every stop.
* **Two per-child opt-outs skip the helper entirely:** soft `RLIMIT_CORE` of **exactly 1 byte** (the kernel's
  recursion guard for the helper itself; kernel 6.8 (22.04) logs "Process N(comm) has RLIMIT_CORE set to 1 / Aborting
  core" for every such crash — 8 pairs for 8 crashes — and current kernels log "coredump: N(comm): RLIMIT_CORE is set to
  1, aborting core" through `printk_ratelimited`), and `prctl(PR_SET_DUMPABLE, 0)` in the child: 0.1–1.5 ms, status without the
  core flag. The `RLIMIT_CORE=1` setting survives `exec`; **dumpability does not** — `linux_extras` set it to 0 before
  `execve` and the new program read back 1 (`fs/exec.c` resets it), so only a child that sets it itself can use it.
* **A large core takes long, and `SIGKILL` cuts it short:** with 384 MiB dirtied, the crash took 605–887 ms to reach
  `waitpid`; `SIGKILL` sent 20 ms after the fault ended it at 42–51 ms (status `SIGKILL`; `coredumpctl` kept a 4 KiB
  truncated core). The interrupt checks are `dump_interrupted()` / `fatal_signal_pending()` in `fs/coredump.c`.

### Finding the descendants of a process without groups or cgroups (verified, identical on all eight)

The probe builds `probe -> A -> {A1, X -> D}` where `X` exits at once (`D` is reparented to pid 1) and `D` calls
`setsid()`; every node carries an environment tag.

| method | finds A, A1 | finds D (orphaned, new session) | cost |
|---|---|---|---|
| walk the parent-pid table (`/proc/*/stat`, `sysctl KERN_PROC_ALL`) | yes | **no** | 0.4–1 ms |
| kernel child lists (`proc_listchildpids`, `/proc/<pid>/task/<tid>/children`) | yes | **no** | 0.03–0.07 ms |
| same process group (probe made group leader) | yes | no (it called `setsid`) | 0.2–1 ms |
| same session | yes (+ every other process of the runner's session: 7 on Linux, 206–228 on macOS) | no | 0.2–0.9 ms |
| **read every process's environment for a tag** (`/proc/<pid>/environ`, `sysctl KERN_PROCARGS2`) | yes | **yes** | Linux 1 ms; macOS 11 ms (arm64), 150 ms (Intel) for 400–500 processes |

Only the environment tag finds a daemonized orphan without a cgroup. It works only for programs that were `exec`ed
with the tag (a bare `fork` keeps the parent's original environment area) and only for processes of the same user
(`EACCES` for the other users' processes on Linux, 158–164 of ~170; on macOS `KERN_PROCARGS2` failed with `EINVAL` — never
`EPERM` — for 190–260 of the 410–510 listed processes). Start times are available for pid-reuse checks: microseconds on macOS (`pbi_start_tvsec/usec`), 10 ms ticks on
Linux (`/proc/<pid>/stat` field 22).

### Memory limits on macOS (verified on all five macOS runners)

(The first CI run of this probe measured nothing: the compiler removed `malloc` + `memset` of memory that was never read,
so the child never used the 256 MiB it reported. The pointers are now kept in a volatile array. Worth remembering for any
memory test.)

* **`RLIMIT_RSS` is not a resident-size limit on Darwin: it is an alias of `RLIMIT_AS`** (`bsd/sys/resource.h`:
  `#define RLIMIT_RSS RLIMIT_AS /* source compatibility alias */`). The earlier "cannot be set" was the address-space
  limit refusing a value below the current virtual size: `setrlimit` fails `EINVAL` for 64 MiB, and for half the virtual
  size. A process's virtual size is **~392–415 GiB on arm64** and ~33 GiB on Intel (shared cache and reservations), so
  `RLIMIT_AS` = current virtual size + 256 MiB **is accepted** and then refuses address space: within it a 128 MiB
  `malloc` worked, a 512 MiB `malloc` and a 512 MiB `PROT_NONE` reservation failed with `ENOMEM` (all five runners,
  user and root, run `41886046710`). It caps reservations, not footprint, and only relative to a virtual size the
  supervisor cannot know for an exec'd program.
* **The footprint is honest**: `proc_pid_rusage(RUSAGE_INFO_CURRENT).ri_phys_footprint` counted a 128 MiB `memset` of one
  repeated byte in full (128.3–128.9 MiB) and still did 1.5 s later — no compressor shortcut — and 257 MiB after a second
  128 MiB of random data; resident size agrees.
* **Polling works fine as a memory cap.** A supervisor polling every millisecond (0.007–0.019 ms per call, ~100 polls)
  saw a child cross 256 MiB (8 MiB steps every 3 ms) **0.6–4.7 ms after the step that crossed it**, killed it, and had it
  reaped 3.6–13 ms later; the child had reached 256 MiB, i.e. overshoot of one step.
* **The kernel's own limit needs root.** `memorystatus_control` (private, found with `dlsym`) as the runner user:
  `EPERM` for `SET_MEMLIMIT_PROPERTIES` and even for `GET_MEMLIMIT_PROPERTIES` on the process itself. **As root (the
  runners allow `sudo`) setting a fatal 64 MB limit on itself worked and the kernel killed the process with `SIGKILL`**
  after it had reported 56 MiB (the next 8 MiB step crossed the limit), 55–180 ms after the start. `SET_JETSAM_TASK_LIMIT`
  (command 6, flags = MB) fails `EINVAL` for root because the command does not exist in macOS kernels: it is compiled only
  `#if CONFIG_JETSAM` (`kern_memorystatus.c`), which `config/MASTER` describes as "used on embedded" and the macOS
  configurations do not enable, so it falls to the `default: error = EINVAL` case. `SET_MEMLIMIT_PROPERTIES` is the
  macOS route.
* **Correction: a supervisor that is not root *can* have the kernel enforce the limit**, by installing it at creation
  with the private `posix_spawnattr_setjetsam_ext(attr, flags, priority, active_MB, inactive_MB)` (looked up with
  `dlsym`; flags `0x04 | 0x08` = active- and inactive-fatal, priority -1 = default band). XNU's exec path applies the
  spawn attributes with `memorystatus_set_memlimits` and no privilege check (`kern_exec.c`), unlike the
  `memorystatus_control` system call. As the ordinary runner user on all five macOS runners (run `41886046710`) a child
  allocating 8 MiB steps was **killed with `SIGKILL` under a 64 MB and a 128 MB fatal limit**, while the control (no
  attribute) and a non-fatal 64 MB limit kept running to 512 MiB. The kill comes on the step that crosses the limit:
  the last step reported was 56 MiB (64 MB limit) and 120 MiB (128 MB limit), 120–150 ms and 220–400 ms after spawn,
  identical as the runner user and as root (run `41888597722`, macOS 14 and 26). As root, `GET_MEMLIMIT_PROPERTIES` on the child read
  back exactly the requested limits (64/128 MB, attribute 1 = fatal; non-fatal: attribute 0). It is private SPI (no
  public header, no stability promise) and works only for children created with `posix_spawn`, not `fork`.

### Process creation at scale (verified)

* **Spawn latency** (median, until the child exited and was reaped; trivial program): Linux 0.28–0.55 ms
  (fork+exec 0.36, `posix_spawn` 0.28; arm 0.43–0.55), macOS 1.0–4.2 ms (Intel runners slowest, 3.6–4.2 ms; `posix_spawn`
  15–40 % faster than fork+exec), **Windows `CreateProcess` 0.8 ms (2022) / 1.5 ms (2025) / 2.4 ms (arm64) to return, 6.9 / 10.4 / 13 ms until
  exit**. `JOB assign + resume` added nothing measurable.
* **A big parent matters only for `fork` on Linux**: with 512 MiB resident, fork+exec took 3.3–6.4 ms to return
  (7.8–15 ms in total) against 0.05 ms for a small parent; `vfork` and `posix_spawn` did not change (0.06–0.15 ms).
  On macOS and Windows a 512 MiB parent changed nothing.
* **First start of a new executable** costs about twice a repeat: macOS 1.4→3.2 ms (one macOS 26 run: 44 ms, then
  5.6, then 35 — erratic, probably Gatekeeper's assessment), Windows 19→9 ms (2022), 26→12.5 ms (2025), 38→20 ms (arm64); Linux none.
* **Concurrent children.** Linux forked 299 sleeping children in 14–23 ms (0.05–0.08 ms each) with no slowdown;
  macOS 505–550 in 180–390 ms (0.4–0.7 ms each; the second hundred was often slower than the first); Windows 400
  `CreateProcess`+job assignment in 0.7–1.1 s with no failure; `TerminateJobObject` had all 400 gone in 105–185 ms,
  `kill`+`waitpid` of 300–550 POSIX children in 6–60 ms.
* **`RLIMIT_NPROC` counts tasks, including unreaped zombies.** With the limit set to the current count plus 20,
  `fork` of children that exit at once started failing with `EAGAIN` after 21 children on Linux and macOS, and
  worked again after reaping one (21–26 children; the macOS 14 estimate of the baseline was a few off). Linux counts every thread of the user (the probe counted `/proc/*/task/*`: 47–54 for
  an idle runner). On macOS the kernel's per-user count matches the user's processes. (An earlier version said it was
  "about half of what `sysctl KERN_PROC_UID` lists". That was a bug in the probe: it took the size XNU reports for a
  NULL buffer, and `sysdoproc_callback` applies the uid filter only when a buffer is supplied, so the "listing" was every
  process on the machine plus `KERN_PROCSLOP` (5). Read into a real buffer, run `41886046710`: 215 / 244 / 293 / 226 /
  271 processes of the runner user against kernel counts of 209 / 238 / 286 / 221 / 262, found by seeing how many
  children fit under a known limit; the real-uid listing is identical.) Defaults: macOS `kern.maxproc` 2000 (arm64) /
  3132 (Intel), `maxprocperuid` 1333 / 2088; Linux soft = hard = 58 000–64 000.

---

## Windows: suspend, freeze, WM_CLOSE, emulation, scale (`proc_explore suspend|wmclose|emulation|scale`)

Runs `41807338781`, `41808488438`: windows-2022, windows-2025, windows-11-arm; elevated and unelevated gave identical
results unless stated.

### Suspending and freezing (verified)

* **`NtSuspendProcess` stops all CPU use at once and counts**: 312 ms of CPU in 300 ms running, 0 suspended; two
  suspends and one resume still 0; the second resume restores the full rate. An extra `NtResumeProcess` without a
  suspend returns success. `CREATE_SUSPENDED` is one suspend count (`SuspendThread` returned 1, the two `ResumeThread`
  calls returned 2 and 1).
* **`TerminateProcess` kills a suspended process at once** (1–2 ms, exit code as given).
* **A thread-by-thread suspend (Toolhelp snapshot, `SuspendThread`) lost no thread** in 8 trials against a process
  creating a thread every millisecond (about 100–220 threads), neither one pass nor repeated passes — a window exists
  but was never hit.
* **Job freeze works and is the better tool**: `SetInformationJobObject(job, 18 /* JobObjectFreezeInformation */,
  {Flags=1, Freeze=TRUE})` with a 16-byte struct succeeded on all three builds, elevated or not. Frozen: 0 ms CPU in 300
  ms (297–312 running). **A process assigned to the frozen job was frozen too** (0 ms). Unfreezing resumed both. **
  `TerminateJobObject` on a frozen job killed it in 2 ms.** The struct and class number are undocumented in the
  public headers (written from memory of the community `ntpsapi.h`; the call working is the evidence the layout is right).

### WM_CLOSE and `taskkill` (verified, hosted runners have an interactive desktop: session 2, `WinSta0\Default`)

* A GUI child that handles `WM_CLOSE` by destroying its window exited with its message-loop code **3–4 ms** after the
  `PostMessage`; one that ignores it was still running after 1.5 s (exit code 259).
* A GUI thread with one window of its own showed **two** top-level windows in `EnumWindows` (presumably the thread's
  default IME window as the second; not checked); filter by class, not by "the" window of the pid.
* **`SendMessageTimeout(WM_NULL, SMTO_ABORTIFHUNG, 1000)` to a thread that never pumps messages waited the full
  1000 ms (`ERROR_TIMEOUT` 1460) even after `IsHungAppWindow` had turned true (6 s)**, so `SMTO_ABORTIFHUNG` did not
  shorten it here.
* `taskkill /PID n` **without `/F`**: on a console program it fails (exit 1, "can only be terminated forcefully (with
  /F option)") and the process lives; on a GUI process it posts `WM_CLOSE` ("SUCCESS: Sent termination signal") and the
  child was gone in 60–110 ms.

### AppContainer children (verified on windows-2022, 2025, 11-arm; elevated and unelevated alike)

`CreateAppContainerProfile` worked for the runner (also unelevated); the child was started with
`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (no capabilities), suspended, assigned to a job (kill on close), resumed.
The container SID was given read/execute on the program directory and full access on a scratch directory with
`icacls` (it exited 5 for the program directory when unelevated, but the program started anyway — presumably the workspace
ACL already allowed it; not checked).

* **It starts, runs and exits normally; the job controls it.** Token: `TokenIsAppContainer` 1, integrity **Low**
  (`0x1000`), in the supervisor's job. Its exit code (0) and wait semantics are those of any child.
* **It cannot touch the supervisor**: `OpenProcess(supervisor)` for `PROCESS_QUERY_LIMITED_INFORMATION`,
  `SYNCHRONIZE` and `PROCESS_TERMINATE` all failed with access denied (5).
* **File system**: it wrote to the granted scratch directory and to its own `GetTempPath` (presumably a per-container
  directory; not checked), and was denied (5) in `C:\Users\Public` and `C:\Windows\Temp`.
* **Loopback networking is silently blocked**: `connect` to a listener on `127.0.0.1` neither succeeded nor was
  refused — **no answer within 3 s** (the packets are dropped; a blocking `connect` waits ~21 s, which is what made my
  first version of the probe look hung).
* **It can start grandchildren** (`ok`), which are in the job too, and **create a job object and assign itself to
  it** (nested job, `ok`).

### x64 and x86 children on Windows 11 arm64 (verified, one runner)

* An **x64 child reports `IsWow64Process2` process machine `0x0000` (not WOW64) with native machine `0xAA64`**,
  `PROCESSOR_ARCHITECTURE=AMD64`, `GetSystemInfo` architecture 9; an x86 child reports `0x014C`, `x86`, 0, 32-bit
  pointers; a native child 12 / `ARM64`.
* Under a job: CPU accounting of an emulated spinner matched the native one (484–516 ms in 500 ms); a 100 ms
  per-process CPU limit killed the x64 and x86 children with `0xC0000044` exactly as it killed the native one (after
  1.7 / 6.5 / 6.5 s, which is the phase of the periodic enforcement pass, not a difference between architectures); a
  200 MiB per-process memory limit let an 80 MiB allocation through and refused 300 MiB (`ERROR_COMMITMENT_LIMIT`) for all
  three. Nothing the kit relies on behaves differently for emulated children.

---

## A Mach exception handler holds a crashing thread (macOS, verified on all five runners)

`explore/macos/mach_exc.c`, run `41886046710`. The child sets its own task exception port for `EXC_BAD_ACCESS`
(`EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES`, message id 2405), runs a handler thread, writes a timestamp and dereferences
NULL. Medians after the fault:

| case | handler received | process reaped | status |
|---|---|---|---|
| no handler | — | 0.2–0.8 ms | `SIGSEGV` |
| handler replies `KERN_FAILURE` at once | 0.1–1.3 ms | 0.7–4.3 ms | `SIGSEGV` (the kernel falls back to the Unix signal) |
| handler holds 500 ms, then `KERN_FAILURE` | 0.1–0.5 ms | 502–563 ms | `SIGSEGV` |
| handler never replies, `SIGTERM` after 300 ms | 0.1–0.2 ms | 5 ms after the `SIGTERM` | **`SIGSEGV`**, not `SIGTERM` |
| handler never replies, `SIGKILL` after 300 ms | 0.1 ms | 0.2–0.6 ms after the `SIGKILL` | `SIGKILL` |

So whoever owns the exception port (a debugger, an in-process crash reporter such as a Crashpad/Breakpad-style handler)
decides how long a crashed child stays alive, and `waitpid` waits for it. A `SIGTERM` does end the wait, but the
child then completes the crash and is reported as `SIGSEGV`: a supervisor that sent `SIGTERM` must not conclude that
the child died of its signal. `SIGKILL` is immediate. (Without a handler the macOS figures match `crash_latency`:
`ReportCrash` does not hold the process.)

## Linux: dumpability, `WNOWAIT`, executing a script by descriptor (verified, all three Ubuntu runners)

`explore/linux/linux_extras.c`, runs `41886046710`, `41888597722`:

* `prctl(PR_SET_DUMPABLE, 0)` before `execve` is undone by the exec (the program read back 1); `RLIMIT_CORE` set before
  `exec` stays (1). A launcher can opt a child out of the crash handler only through `RLIMIT_CORE=1` (see above).
* **`waitid(..., WEXITED | WNOWAIT)` reserves nothing.** One thread observed the exited child (pid, status 37) with
  `WNOWAIT`, a second thread then reaped it with `waitpid`, and the observer's own collection got `ECHILD`. The same with
  a pidfd (`waitid(P_PIDFD, ...)`): a pidfd gives a stable identity, not ownership of the exit status. If a runtime
  (Crystal's) reaps children on its own, any other waiter can lose the status.
* **`fexecve` of a `#!` script fails with `ENOENT` when the descriptor is close-on-exec** (the interpreter is handed
  `/dev/fd/N`, which no longer exists after the exec); without `O_CLOEXEC` the script ran (exit 23); an ELF binary works
  with `O_CLOEXEC`. A spawner that executes by descriptor to pin the file must not set `O_CLOEXEC` on scripts.

## Windows: ExitProcess while a killed thread held what DLL detach needs (verified, all three builds)

`win_more exitproc` with `detach_dll.dll`, run `41886046710`, elevated. `ExitProcess` terminates every other thread
first and then runs each DLL's `DLL_PROCESS_DETACH`. A worker thread took a resource and slept; the main thread called
`ExitProcess(0)`; detach then waited for that resource.

| what detach waits for | result |
|---|---|
| nothing | exits in 0–1 ms, code 0 |
| a critical section the terminated thread held | **exits at once with code 0 — detach never finished** (the loader ends the process instead of blocking) |
| an SRW lock the terminated thread held | the same: exit at once, code 0, rest of detach skipped |
| an event the terminated thread would have set | **hangs**; still alive after 6 s; `TerminateProcess` ended it in 2 ms |
| a mutex the terminated thread held | the wait returns `WAIT_ABANDONED` (128) and detach completes |
| the terminated worker's thread handle | returns at once (the thread is already gone) |
| nothing, but detach sleeps 1.5 s | the exit takes 1.50 s |

So a "graceful" exit can hang forever, or can skip cleanup silently while reporting success (exit code 0 after an
abandoned critical section). A supervisor needs a deadline after asking a child to exit and must escalate to
`TerminateProcess` / `TerminateJobObject` (which do not run DLL detach). The exit code of a child that exited by itself
says nothing about whether its cleanup ran.

## Still open

* the in-loop HIGH success in the exploration tool (above);
* why `pwsh` cannot launch native commands under the filtered token on the hosted runner;
* the Windows enforcement period (7.000 s on x64, 7.04–7.16 s on arm64, not a clock effect) is not documented
  anywhere I found, and why arm64's pass runs later is not known;
* why a job bandwidth limit makes about one write per second fail with `ERROR_INVALID_PARAMETER`;
* why a signal that is pending process-wide is not delivered on macOS when a non-main thread unblocks it (only a new
  signal, or the main thread unblocking, delivers it);
* why the macOS kernel's `RLIMIT_NPROC` count is about half of what `KERN_PROC_UID` lists;
* `memorystatus_control(SET_JETSAM_TASK_LIMIT)` failing `EINVAL` for root (probably wrong arguments);
* the unmeasured parts of this round: the core-dumping signals other than `SEGV`/`ABRT`/trap on Linux; `SIGTERM`
  stopping a process stuck in a crash handler; WER timing on a *service* process; Windows services and session 0.
