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
* **`pwsh` works under this token** (corrects an earlier claim). The first attempts (run `41771599247`) failed every
  captured native command with `Access is denied`, then PowerShell's "StandardOutputEncoding is only supported when
  standard output is redirected" (its retry clears the redirection but keeps the encoding, which hides the first
  error), and a child given its own console or `CREATE_NO_WINDOW` died with `STATUS_DLL_INIT_FAILED` (0xC0000142).
  **Both happened before the owner/default-DACL fix above** (`10a8f97`, 23 minutes later), and neither was tried again
  until now. With the fixed token (`pwsh_native.ps1`, run `41888597722`, Server 2022 and 2025): all 11 launch shapes
  work — uncaptured and captured native commands, `whoami`, `Process.Start` with redirected stdout/stderr/stdin and
  without, `CreateNoWindow`, `Start-Process -NoNewWindow` (PowerShell 7.6.9 on .NET 10.0.14, Administrators role not
  active). In C (`win_more desktop`), under the same token: `CreatePipe` + a non-inheritable `DuplicateHandle` + a
  redirected `CreateProcess` work, and children start and exit normally with `CREATE_NEW_CONSOLE`, `CREATE_NO_WINDOW`
  and `DETACHED_PROCESS` (no 0xC0000142). The token: Medium integrity, Administrators and the local-account SID
  deny-only (`0x10`), owner = the user, default DACL `D:(A;;GA;;;LA)(A;;GA;;;SY)`, same logon SID as the elevated
  token. The window station `WinSta0` and desktop `Default` grant that logon SID full access, so every access right
  tried opened. The probe-only launcher (`PROCESS_PROBE_LAUNCHER`) is therefore no longer required; it was kept.

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
  seen. On hosted runners a crash does not hang the supervisor behind an error-reporting dialog. (Explained later: the
  step's processes already inherit `SEM_NOGPFAULTERRORBOX`, so "without" was never tested; with error mode 0, WER runs and
  a crash takes ~0.3 s — see "Windows services, session 0 and crash reporting".)
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
  * **What the error-87 writes are, and how to avoid them** (`proc_explore iobw`, runs `41886046710`, `41888597722`,
    all three builds, elevated and de-elevated; each write carries a unique header at an explicit offset, and the
    parent reads the file back outside the job): **the failed write did not happen** — `n` = 0 and the block on disk
    still held its previous content, 6 of 6 per run. **Retrying the same write at the same offset succeeded on the
    first retry**, 6 of 6, and the whole file verified. And **the failures depend on the limit's value**: 1,000,000
    bytes/s failed about once a second with 4 KiB and 64 KiB writes, while every limit that is a multiple of 4 KiB never
    failed — 1,003,520 (245 × 4 KiB, not a multiple of 8 KiB), 1,007,616, 1,015,808, 1,048,576, 10,485,760. So: set
    `MaxBandwidth` to a multiple of 4096, or treat 87 from a write as retryable. The code that returns it was not found
    (Microsoft names `IORate.sys` as the driver that holds rate-controlled I/O).
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
  do this; the kit's `attach` after spawn has that window, as its own comment says — see "Spawning into containment"
  for how often it leaks, and for the caveat that a cgroup written `cgroup.kill` kills every later `clone3` child.)
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

## Windows services, session 0 and crash reporting (verified on Server 2022, Server 2025, Windows 11 arm64)

`win_more services`, runs `41886046710`, `41888597722`, elevated (de-elevated, `OpenSCManager` with create rights is
denied, error 5). How the hosted runner itself runs: the Task Scheduler service (`svchost`, session 0) starts
`hosted-compute-agent` in session 2, which starts `Runner.Listener` → `Runner.Worker` → the step's shell. Session 2 is
the console session of the auto-logged-on `runneradmin` (`AutoAdminLogon 1`), with `explorer.exe` running. The runner's
own job has **no limit flags** (`0x0`, no breakaway). Registry: WER `DontShowUI 1`, `ForceQueue 1`, no global
`LocalDumps` (only Service Fabric's per-program keys), `WaitToKillServiceTimeout 5000`, **`ServicesPipeTimeout
120000`**.

The test service is an own-process service running this executable as LocalSystem. It reached `RUNNING` 14–25 ms after
`StartService`, in session 0 and in no job, and started a worker child.

| case | what happened |
|---|---|
| `SERVICE_CONTROL_STOP`, worker not in a job | `ControlService` returned in 0–1 ms, `STOPPED`, the service process exited 1–2 ms later — **the worker kept running**. The SCM does not touch a service's children. |
| the same, worker in the service's kill-on-close job | the worker was gone 3 ms after the service process |
| a STOP handler that never returns | `ControlService` **blocked for 240 s** and failed with `ERROR_SERVICE_REQUEST_TIMEOUT` (1053); the state stayed `RUNNING` all along; at 240 s the service process was gone (exit code 0) and the state `STOPPED`. Not the documented 30 s; on these runners `ServicesPipeTimeout` is 120 s (that 240 s = 2 × 120 s is a guess) |
| access violation in the service | `ControlService` returned `ERROR_BROKEN_PIPE` (109) when the process died, **161–942 ms after the crash** (WER, below); with the restart action (1000 ms delay) the new instance was ready 1.004–1.032 s after the old one exited, **while the old instance's worker was still running** |
| `ExitProcess(3)` without reporting `STOPPED` | treated as a failure: restarted after the delay |
| reports `STOPPED` with `ERROR_SERVICE_SPECIFIC_ERROR` | not restarted — unless `FailureActionsOnNonCrashFailures` is set, then restarted after the delay |
| a session-0 worker assigned to a job created by this session-2 process | **into an empty job: succeeded** (with `PROCESS_SET_QUOTA`; a first attempt without it gave error 5). **Into a job that already holds a session-2 process: `ERROR_ACCESS_DENIED` (5)** — the worker in no job before, so only the session rule refused it (runs `41891670151`, `41894086301`, all three builds). A job takes the session of its first process |

**Crash reporting, and why the runner's own crashes are fast.** A crashing *service* goes through WER: 161–942 ms
between the fault and the process exit, and with a per-program `LocalDumps` key a minidump (0.6–0.9 MiB) or a full
dump (26–49 MiB) appears. Children of the service behave the same — 161–323 ms, with dumps — and **in a job with
`JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` they exit at once (0 ms) with no dump**; a job without that flag changes
nothing (169–307 ms). But a child crashing in the runner's session 2 also exits at once (0 ms) and writes no dump even
with `LocalDumps` set, and the runner's job does *not* have that flag. **The cause is the inherited error mode**: the
step's processes run with `GetErrorMode()` = `0x8003` (`SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
SEM_NOOPENFILEERRORBOX`), which children inherit, while the test service had `0x8001`. With `SEM_NOGPFAULTERRORBOX` the
unhandled-exception path does not call WER at all. Measured in the runner's session (run `41894086301`, all three builds): a child
that crashed with the inherited `0x8003` — or with `SetErrorMode(SEM_NOGPFAULTERRORBOX)` alone — exited in 0 ms, no
`WerFault`, no dump; the same child after `SetErrorMode(0)` took **214–361 ms**, `WerFault` ran (in sessions 0 and 2)
and `LocalDumps` wrote a minidump. So "a crash does not wait for WER on the hosted runner" is a property of
the runner's error mode, not of Windows: a supervisor whose children run with error mode 0 (any service, any process
whose parent did not set the flag) waits ~0.2–0.9 s per crash, longer with full dumps. A supervisor can make crashes
immediate and dump-free for its children with `SetErrorMode(SEM_NOGPFAULTERRORBOX)` before creating them (inherited) or
with a job that has `DIE_ON_UNHANDLED_EXCEPTION`; it cannot count on a dump unless it clears both.

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

## Spawning into containment: cgroup attach race, `clone3`, `posix_spawn`, Crystal reaping, macOS descendants

(`explore/linux/spawn_cgroup.c`, `explore/posix/spawn_attrs.c`, `explore/posix/crystal_own_spawn.cr`,
`explore/macos/kqueue_track.c`; runs `41910905753`, `41912692793`, `41914457166`, all eleven Unix runners; the Linux
numbers were identical in kind on Ubuntu 22.04 (kernel 6.8), 24.04 (7.0) and 24.04 arm64 (7.0), the macOS ones on all five
macOS runners.) The kit spawns a Windows child into its Job before it runs; on POSIX it can only adopt a group or cgroup
afterwards. These runs measure what that costs and what the alternatives are.

### Attach after spawn leaks children under load; `clone3(CLONE_INTO_CGROUP)` and an `sh` trampoline did not (verified)

The child program forks 6 children as its first action (a shell starting background jobs does the same); 150 trials per
cell, counted by looking at each child's `/proc/<pid>/cgroup`. "Busy" = two CPU-spinning processes per CPU.

| how the child gets into the cgroup | idle: trials that lost children | busy: trials that lost children (children outside / 900) |
|---|---|---|
| `fork`+`exec`, parent writes the pid to `cgroup.procs` the moment `fork` returns | 1, 1, 1 of 150 | 2, 3, 4 (12, 18, 24) |
| `fork`+`exec`, parent waits for the exec to finish (CLOEXEC pipe closes — what `Process.new` does before it returns), then writes the pid | 1, 0, 2 | **67, 54, 109 of 150** (400, 324, 654) |
| `clone3(CLONE_INTO_CGROUP)` then `exec` | 0, 0, 0 | 0, 0, 0 |
| `sh -c 'echo $$ > cgroup.procs && exec "$@"' …` (dash) | 0, 0, 0 | 0, 0, 0 |
| the same through `bash` | 0, 0, 0 | 0, 0, 0 |

(columns are Ubuntu 22.04, 24.04, 24.04 arm64.) The one idle loss in the first row is always exactly one trial with all
six children outside, on every runner — it looks like the cold first spawn, not randomness (inferred). After the exec
notice the parent's write took a median 30–64 µs idle and 46–569 µs busy. So with the exec-wait that `Process.new` imposes,
attach-after-spawn lost children in a third to two thirds of trials once the CPUs were contended, and in almost none when
idle: a race that a test on an idle machine will not show.

* While the pid is not yet attached the cgroup reads `populated 0` (100 of 100 trials) and `populated 1` after the write
  (100 of 100): a `wait_empty`/`empty?` check in that gap says "drained" although a child exists.
  `clone3` showed `populated 1`, `pids.current 1` and the pid in `cgroup.procs` at the moment the call returned (100 of 100).
* The trampoline costs time to the program's first instruction: median +0.4–0.6 ms for dash, +0.9–1.5 ms for bash over
  0.4–0.65 ms; busy medians 0.96–2.56 ms (dash) and 1.57–4.46 ms (bash), p95 up to 10.5 and 14.4 ms.
* What the program sees through the trampoline: with dash (`/bin/sh` on Ubuntu) argv (14 awkward arguments: empty,
  leading/trailing space, `-n`, `--`, `$HOME`, backquotes, newline, backslash, `*`, UTF-8, quotes), environment, open
  descriptors, ignored and blocked signals, umask and cwd were **identical** to a direct exec. Through bash the only
  difference was that the `_` variable was missing.
* Failures through the trampoline lose the errno: a missing program, a non-executable file and a directory give exit
  127, 126, 126 (indistinguishable from a program that exits that way) with a message on stderr; an unwritable
  `cgroup.procs` gives exit 2 (dash) / 1 (bash). A direct `fork`+`exec` with a CLOEXEC pipe reports `ENOENT`/`EACCES`.

### `clone3(CLONE_INTO_CGROUP)` details (verified, all three Linux runners)

* Needs `struct clone_args` of at least 88 bytes (64 → `EINVAL`). Refusals: descriptor not open, `/dev/null`, or an
  ordinary directory → `EBADF`; cgroup removed after the descriptor was opened → `ENOENT`; the hierarchy root →
  `EACCES`; the delegated cgroup that has controllers in `subtree_control` → `EBUSY`. A directory opened read-only is enough.
* With `CLONE_PIDFD` in the same call the pidfd is valid, `pidfd_send_signal` and `waitid(P_PIDFD)` work at once
  (`CLD_KILLED`, 9), and a later `waitpid` gives `ECHILD`.
* Into a frozen cgroup: the call succeeds at once (0.08 ms on Ubuntu 24.04), the child does not run (state `S`, `frozen 1`,
  `waitpid(WNOHANG)` 0) and runs 0.18 ms after the thaw (same on all three). A `Process.new`-style spawn that waits for the exec would block
  until someone thaws the cgroup. At `pids.max 1` the second `clone3` fails `EAGAIN` and `pids.events` counts `max 1`.
* **A cgroup that has been written `cgroup.kill` kills every later `clone3(CLONE_INTO_CGROUP)` child at once** (SIGKILL,
  before it ran; also when the cgroup was empty when killed; also 500 ms later; also through a fresh descriptor).
  Not affected: a child forked and attached by writing its pid to `cgroup.procs`, a normal `fork` by a member (both
  lived), and a cgroup removed and recreated under the same name (lived). I have not read these kernel versions' source;
  the pattern fits a per-cgroup kill sequence number that the `CLONE_INTO_CGROUP` path does not account for, which is a
  guess. Consequence: after `kill`, a cgroup that is used with `clone3` is single-use.
* `fork` of the supervisor costs more as its memory grows; `posix_spawn` (glibc, `CLONE_VM|CLONE_VFORK`) does not:
  with a parent that dirtied 0 / 256 MiB / 1 GiB, the call took 0.04–0.06 / 1.8–3.1 / 6.4–10.9 ms for `fork`+`exec` and
  `clone3` without `CLONE_VM`, and 0.07–0.20 ms at every size for `posix_spawn`.

### `posix_spawn` attributes (verified, all eight POSIX runners; two result sets: macOS ×5, Linux ×3)

* `POSIX_SPAWN_SETPGROUP` (group 0): the child was **already in its own group when `posix_spawn` returned in 300 of 300
  trials**; `fork`+`exec` followed by the parent's `setpgid(child, child)` failed `EACCES` in 300 of 300 (the finding
  for `Process.new` again, now in C). `POSIX_SPAWN_SETSID` makes the child a session leader and group leader.
* `SETSIGDEF` (all signals) with `SETSIGMASK` (empty) removed the inherited ignored `SIGPIPE`/`SIGHUP` and the blocked
  `SIGUSR1`; without them all three were inherited. `addchdir_np` works. Closing descriptors: macOS
  `POSIX_SPAWN_CLOEXEC_DEFAULT` (+ `addinherit_np` for 0–2), glibc ≥ 2.34 `addclosefrom_np(3)`; both left only 0, 1, 2.
  The umask is inherited either way.
* Errors come back from the call itself on both OSes (missing program `ENOENT`, directory `EACCES`, missing `chdir`
  directory `ENOENT`, `dup2` from an unopened descriptor `EBADF`, `addopen` of a missing file `ENOENT`) with no pid
  written and nothing to reap. One difference: `addclose` of a descriptor that is not open is `EBADF` on macOS but
  succeeds on glibc 2.35/2.39 (the child ran and exited 0).
* **macOS `POSIX_SPAWN_START_SUSPENDED`** (all five runners): the child exists but has run nothing — `p_stat` is `SSTOP`,
  `waitpid(WUNTRACED)` reports "stopped" with signal 0, no output while suspended, already in its own group with
  `SETPGROUP`. `SIGCONT` starts it (exit 0 after about 3 ms). `SIGKILL` while suspended ends it (`SIGKILL`). **`SIGTERM`
  also ends it, without it ever running** (unlike a process stopped by `SIGSTOP`, which keeps `SIGTERM` pending).
  This is the macOS counterpart of `CREATE_SUSPENDED`.

### Crystal 1.21.1: a pid made by `posix_spawn` or `clone3` can be given to `Process` (verified, Linux and macOS, default and `-Dpreview_mt -Dexecution_context` builds)

* The stdlib's SIGCHLD handler reaps every child of the process (`waitpid(-1, WNOHANG)`) and keeps the status of pids it
  has no waiter for until `Crystal::System::Process.new(pid)` asks (`signal.cr`). `Process.new(Crystal::System::Process.new(pid))`
  is the public (`:nodoc`) constructor the kit's Windows spawn already uses. Measured: a child wrapped before or after it
  exited gives the right status (`exited(7)`, and `exited(9)` after the process was already gone and reaped), 100 of 100
  concurrent spawns from four fibers were correct, and no zombies were left (checked on Linux).
* **A shard-owned `waitpid` on such a pid steals the status**: after it, `Process#wait` never returned (1.5 s deadline);
  a `waitpid` after the runtime reaped gives `ECHILD`. Same in the multi-threaded build. Observe exit with a pidfd
  (`poll`) or `WNOWAIT`, never by reaping.
* Raw `clone3` from Crystal works: `LibC.syscall(435, …)` with all signals blocked around it and an `execve` of pre-built
  `argv`/`envp` in the child (no allocation, no runtime calls); the child saw `0::/…/crystal-clone3` in
  `/proc/self/cgroup`, stdio plumbing through a pipe worked, 100 of 100 spawns exit 0, status kept when the child was
  gone before wrapping.
* Child state: a `posix_spawn` child without attributes sees what `Process.run` gives (ignored `SIGHUP` and `SIGPIPE`,
  fds 0–2); with `SETPGROUP|SETSIGDEF|SETSIGMASK` it is in its own group with nothing ignored.
* **Spawn cost against the size of the Crystal heap** (a fresh process per size; median call time, 25 spawns):
  on Linux `Process.new` (fork) took 0.5–0.7 ms with an empty heap, 6.3–10.5 ms with 256 MiB and 12.2–22.3 ms with
  512 MiB; `posix_spawn` 0.14–0.31 / 0.16–0.40 / 0.30–0.43 ms; raw `clone3` (fork semantics) 0.16–0.26 / 2.4–4.8 /
  4.5–9.5 ms. On macOS the heap barely mattered: `Process.new` 0.6–1.8 ms (7.6–8.8 on macos-26-intel) and
  ≤ 5.0 ms at 512 MiB, `posix_spawn` 0.2–1.3 ms (2.0 on macos-26-intel).
* The macOS START_SUSPENDED path works through `Process`: wrapped while suspended, `SIGCONT` → output and `exited(0)`;
  `SIGKILL` while suspended → `Process#wait` returned `signaled(KILL)`.

### macOS has no tracking for descendants; an environment marker finds the ones that reparent (verified, five runners)

* `kqueue` `EVFILT_PROC` with `NOTE_TRACK` is refused at registration with `ENOTSUP`. `NOTE_FORK` works but is one
  coalesced event for 30 forks and does not say which children.
* `proc_listchildpids` from the supervisor or from the child, recursively, found all 30 children (and 31 in a two-level
  tree) while their parents were alive.
* A child that double-forks and calls `setsid` leaves a grandchild with `ppid` 1: neither enumeration from the
  supervisor nor from the former parent found it (0 found). Reading every same-user process's original environment with
  `sysctl(KERN_PROCARGS2)` and looking for a variable the supervisor put into the child's environment found it on all
  five runners (2 of about 220–340 readable processes carried the marker — the forker and the grandchild) in 3–17 ms
  (one 94.5 ms outlier). Not tested: a program that execs and replaces its environment.

## Where cgroups are usable: delegation, systemd, containers, Alpine (`explore/linux/cgroup_env.c`, `env_run.sh`)

Run `41920365122` on Ubuntu 22.04 (kernel 6.8, systemd 249), 24.04 (7.0, systemd 255) and 24.04 arm64; the outcome classes
were identical on all three except where noted. Each scenario ran `cgroup_env` (what is possible), `spawn_attrs`,
`spawn_cgroup` (20 trials per cell) and the kit's `kit_linux` inside it. Hosted runners only; Docker 28 and systemd were
already on the image. Earlier cgroup results in this file all used a subtree I delegated by hand with `sudo mkdir` +
`chown` — that was one stand-in for delegation, not a survey of how a supervisor actually finds itself; this is the survey.

| environment | create a cgroup | `clone3` | what the shard did |
|---|---|---|---|
| host, unprivileged, nothing delegated (the step's cgroup, `system.slice/hosted-compute-agent.service`, root-owned) | `EACCES` in its own cgroup, its parent and the root | works | `create` → `Error::Unavailable` (correct) |
| host, root | yes, anywhere | works | all 9 cases pass |
| systemd service, `User=`, no `Delegate=` | `EACCES` (unit cgroup root-owned) | works | `Unavailable` (correct) |
| systemd service, `Delegate=yes` | yes, in the unit's cgroup (owned by the service user; `cpuset cpu io memory pids` listed, `subtree_control` empty); not in `system.slice` | works | all 9 pass |
| … plus `DelegateSubgroup=supervisor` (systemd ≥ 254; on 22.04 systemd 249: `Unknown assignment`) | yes: the main process sits in `<unit>/supervisor`, which lists no controllers; the unit cgroup itself is empty and takes `+pids` | works | all 9 pass |
| systemd user manager (lingering user, `user@1001.service`) | yes, in the unit under `app.slice` (owned by the user; `memory pids` only); the root `EACCES` | works | all 9 pass |
| Docker, default, root or non-root | **no: `/sys/fs/cgroup` is a read-only mount** (`EROFS`, non-root `EACCES`) | **`ENOSYS`** (default seccomp profile; `pidfd_open` and `PR_SET_CHILD_SUBREAPER` still work) | see below |
| Docker, `seccomp=unconfined` | no (`EROFS`) | works | see below |
| Docker, `--privileged` (private cgroup namespace) | yes, as root; the container's own cgroup is the mount root (`/`) | works | 8 of 9 pass |
| Docker, `--privileged --cgroupns=host` | yes: own, parent and the host root | works | all 9 pass |
| Alpine (musl, busybox `sh`), default / privileged | same as Docker default / privileged | `ENOSYS` / works | (C probes only) |

* **Detection must be "try it", not "is cgroup2 mounted".** `CgroupV2.available?` was `true` in every row, including the
  read-only Docker mount where nothing can be created.
* **Two refusals escape `Error::Unavailable`**, so `ProcessSupervision.cgroup_v2(path, fallback_pgid:)`, which only
  rescues `Unavailable`, does not fall back there: (1) `CgroupV2.create` on the read-only mount raises
  `File::Error: Unable to create directory … Read-only file system`; (2) opening the process's own cgroup raises
  `ArgumentError: refusing to supervise the cgroup-v2 hierarchy root` in every container with a private cgroup namespace,
  because there the container's cgroup *is* the root of what it sees — also in the privileged one, where it is writable
  and `create` under it works and the other 8 kit cases pass. A cgroup v1 named hierarchy handed to the shard gives
  `ArgumentError: … outside every visible cgroup-v2 mount`. Unprivileged `EACCES` is classified correctly.
* The kit's three pidfd cases passed in every environment, including default Docker and rootless-style non-root.
* A default container has neither a usable cgroup nor `clone3`: it needs the process-group/subreaper/pidfd path, and a
  `clone3` caller must treat `ENOSYS` (not only `EPERM`) as "use the fork path".
* A `Delegate=yes` service that keeps its main process in the unit cgroup can add `pids` to `subtree_control` but I did
  not test `memory` (the shard sets no limits, so it did not matter here); `DelegateSubgroup=` is the clean way where
  systemd allows it.
* **The earlier spawn results held in every usable row** (20 trials per cell, 7 environments × 3 runners): attach after the
  exec lost children in 4–18 of 20 trials under CPU load and 0 when idle; `clone3 INTO_CGROUP` and the `sh`/`bash`
  trampolines 0 of 20 everywhere; a `clone3` into a cgroup that had been written `cgroup.kill` died at once in all of them.
  The same pattern also appeared on a fourth kernel (6.18, hybrid v1/unified host, as root; 7 of 20 busy trials).
* **musl and busybox:** `posix_spawn` behaved like glibc for process group, session, signal reset, `chdir` and every error
  code, **except that musl has no `posix_spawn_file_actions_addclosefrom_np`**, so an inherited descriptor above 2 stayed
  open in the child (glibc ≥ 2.34 and macOS can close them). Through busybox `sh` the trampoline changed one thing, `SHLVL`
  (incremented); through bash on Alpine nothing differed. Exit-code behaviour of the trampoline was the same as on dash.
* `posix_spawn` results were identical in all 33 glibc environment/runner combinations (host, root, systemd, Docker).

## The shard now spawns contained children on Linux and macOS (what was built, what building it found)

Built in `probes/workspace` (details in the shard README): `CgroupV2#spawn` (clone3 `CLONE_INTO_CGROUP | CLONE_PIDFD`, fork
fallback whose child enters the cgroup before exec), `ProcessGroup#spawn` and `.spawn_leader` (the same engine with `setpgid` on
Linux; `posix_spawn` started suspended on macOS), `ProcessHandle::Linux.adopt_child` and `ProcessHandle::Kqueue` (macOS exit
watch), `CgroupV2.usable?` / `.delegated_parent`, `ProcessSupervision.spawn` / `.strongest_mechanism`, `Error::Killed`, and the
refusal of process group 1. The loop used was `.github/workflows/shard-dev.yml`: formatter applied, specs built and run on a
chosen runner and, on Linux, inside the environments of the previous section.

Spec results (38 examples on Linux, 23 on macOS; runs `41925930006`, `41926354364`, `41926366594`, `41925944136`, `41926309194`,
`41926321192`, `41926333437`): **0 failures in every cell** — Ubuntu 22.04, 24.04 and 24.04 arm64, each as the plain runner
user, as root, in a systemd service with and without `Delegate=yes`, in the user manager, and in a default and a privileged
Docker container; macOS 14, 15, 26 (arm64) and 15 (Intel). Pending examples are the ones that need a cgroup this environment
does not give (4 plain and 4 in a service without `Delegate=`; 11 in a default container, where the spec binary is also PID 1)
or that only apply where none is available (1 where a cgroup can be made). `ProcessSupervision.spawn` chose `CgroupV2` exactly
where `delegated_parent` found one and `ProcessGroup` everywhere else, and its shutdown drained and released the group in each.
The burst test (30 spawns of a shell that forks three `sleep`s, `cgroup.kill`, then a scan of every `/proc/*/environ` for a
token) found no survivor in any delegated environment.

What building it found:

* **Process group 1 is a broadcast.** The specs ran as PID 1 of a container, whose process group is 1; `ProcessGroup.new(1)`
  then addressed `kill(-1, sig)`, which signals every process the caller may signal. It is refused now (the kit validates 0,
  -1 and `Int32::MAX + 1` only, so no kit case changed).
* **`ProcessHandle.open` rejects a process that has already exited** (it retries three times, then `NoSuchProcess`), which
  would make a command that finishes at once unsupervisable; hence `adopt_child`, fed by the pidfd that `clone3` returns
  with the process.
* **A fiber must not yield while holding a `Thread::Mutex`**: a second fiber on the same thread would block the thread and
  deadlock. The spawn is split: `create` (no call that can yield) runs under the group's mutex, `complete` (reads the
  exec-error pipe) runs outside it.
* **The earlier classification gaps are closed and checked where they occurred**: in a default Docker container
  `create` on the read-only mount is now `Error::Unavailable`; in a privileged container the namespace-root cgroup can be
  opened and spawned into.
* The specs read sources through paths baked in at compile time, so a binary run from another path (a container mount)
  fails five unrelated examples; the loop mounts the workspace at its own path.
* The kit pins its sources by hash, so `MANIFEST.sha256` was regenerated and the four new files added; the kit's case names
  and meaning are unchanged.

The kit's own native qualification, run against the modified source (runs `41926248879` and, after the stdio change, `41928529899`): macOS arm64 386 Crystal + 45 C/SDK
cases, Windows x64 elevated 459 and unelevated 459, all `qualification_validation=pass`, manifest checks before and after pass.

Standard stream redirection (`input:`/`output:`/`error:` with `Redirect::Inherit`/`Close`/`Pipe` or an `IO::FileDescriptor`;
`Child#input`/`#output`/`#error`) was added afterwards for Linux and macOS (runs `41928042954`, `41928059007` and the other
runners): 49 examples on Linux in all eight environments and 32 on macOS, 0 failures, including a megabyte through `cat`
in both directions without deadlock, the same pipes for a child inside a cgroup on both the `clone3` and the fork path, a
failed exec leaking no descriptor (30 attempts with three pipes each), and `Child#close` closing the pipes. Design points that
mattered: the child's end of each pipe must be blocking and the parent's non-blocking (O_NONBLOCK is per open file
description); the parent has to close the child's ends as soon as the process exists or EOF never arrives; every source
descriptor is first copied above 2 so that a `dup2` cannot overwrite a later source (a process with a closed stdin gets
descriptor 0 back from `pipe()`).

Windows Jobs got the same `input:`/`output:`/`error:` contract afterwards (`Job#spawn` and `ProcessSupervision.spawn`),
and `shard-dev.yml` gained Windows runners, so the Windows branch is now run natively instead of only compiled: runs
`41931785086` (windows-2022) and `41931789343` (windows-2025), 19 supervision examples and 7 handle examples, 0 failures,
0 pending in both. The new examples pipe through a child, keep stdout and stderr apart, hand a closed stream the null
device, read and write files, move a megabyte each way, leave the process handle count unchanged over 30 failed creations
with three pipes each, and see EOF on a pipe a grandchild still held once the Job is killed. The children are
`spec/support/stdio_child.cr` (the runners have no `cat`). The kit's qualification against this source (run
`41931774414`): Windows x64 elevated 459 and unelevated 459, macOS arm64 386 Crystal + 45 C/SDK, all
`qualification_validation=pass`, manifest checks before and after pass. Ubuntu 24.04 in all eight environments (run
`41931793815`): 0 failures. Design points: each stream is its own duplicate, so the `HANDLE_LIST` never holds a value
twice even when output and error name the same file; the child's pipe ends are synchronous and the parent's overlapped,
as in the stdlib; the parent's copies of the child's ends are closed after the Job mutex is released (closing an IO may
yield, and a fiber must not yield while holding a `Thread::Mutex`).

## Any IO for streams, `pidfd_spawn`, the descendant marker, kit r14 (what was built, what building it found)

Commit `af9533e`. shard-dev runs `41935986057` (ubuntu-24.04), `41935994918` (22.04), `41935998676` (24.04 arm64),
`41936002311` / `41936024178` / `41936012111` (macOS 15, 26, 15 Intel), `41936016495` / `41936020264` (Windows 2022, 2025);
kit run `41935986039`. **0 failures everywhere**: 60 supervision examples on Linux in each of the eight environments on each
of the three Ubuntu runners, and again with the engine forced to clone3 and to fork; 39 on macOS; 22 on Windows. Kit:
Windows elevated 468 and unelevated 468, macOS 397 Crystal + 45 C/SDK, all `qualification_validation=pass`, manifest checks
before and after pass; every one of the 20 new r14 cases passes.

* **Any IO for standard streams.** An `IO` that is not a file descriptor gets a pipe and a copy fiber (`StreamCopies`);
  `Child#wait` waits for the copies and raises a failed one (the status stays in `Child#status`). A child that exits
  without reading its input is not an error here (the stdlib's `Process#wait` raises the broken pipe). A megabyte each way
  through `IO::Memory` and a failed exec with IO objects leaking nothing were checked on all three systems.
* **`pidfd_spawn` (glibc 2.39) as the first Linux engine.** Median spawn at a 512 MiB touched heap: 0.27-0.45 ms against
  22.3-22.8 ms for fork (x64) and 16.3-17.2 ms (arm64). With `posix_spawnattr_setcgroup_np` it also enters a cgroup at
  creation (verified in the delegated environments). Ubuntu 22.04 (glibc 2.35) has neither and uses clone3, or fork in a
  default Docker container (seccomp `ENOSYS`); on 24.04 `pidfd_spawn` works in that same container.
* **glibc 2.39 leaks the pidfd of a child whose exec failed** (sourceware BZ 31695): the call returns the errno and leaves
  an `anon_inode:[pidfd]` open whose fdinfo reads `Pid: -1`, and does not say which descriptor it is. Reproduced in C (5 of
  5). The kernel gives the pidfd the lowest free number, so that number is taken before the call and closed after a failure
  if, and only if, it is then a pidfd of a gone process: 20 of 20 closed in every 24.04 environment, 0 needed on 22.04.
* **Descendant marker.** `PROCESS_SUPERVISION_GROUP=<token>` in every child spawned into a `ProcessGroup` (also with
  `clear_env`). A `setsid` descendant was found by the scan and ended by `shutdown` on Linux and macOS (scan 42.8 ms on the
  macOS 15 arm64 runner); without the marker the same descendant survived the group's shutdown, which is the weakness the
  marker addresses. Escapees are signalled through a handle opened first (pidfd, or `ProcessHandle::Kqueue.watch` on macOS)
  and only after the marker is read again.

Not built: a kit lane for Linux (the shard specs are its native evidence), and FreeBSD.

## First pass over every roadmap gap (what was built, what building it found)

Commits `f6ea4f9` (the pass), then `6d4fac4`, `de0f4a5`, `55046d0` and `aa4fd94` (fixes from its native runs). What was built is listed in `ROADMAP.md`
("Status after the first pass") and the shard README ("Spawn options, control and supervision"). Native results: Linux (`6d4fac4`, ubuntu-24.04 / 22.04 / 24.04 arm64) 83 supervision examples with 0 failures in each of
the eleven runs per runner (plain, clone3 and fork engines, systemd `Delegate=yes`, no delegation, user manager, root,
Docker default and privileged, plus the 200-cycle stress run), 22 process-handle examples; macOS (`de0f4a5`, 15, 15
Intel, 26) 55 supervision and 9 process-handle examples, 0 failures, stress passing; Windows (`aa4fd94`, Server 2022 and
2025) 27 supervision and 7 process-handle examples, 0 failures; the Windows control specs (process ids, suspend/resume, usage, snapshot, CTRL_BREAK stop, crash policy, extra handle, refused options) ran natively for the first time here, after the user32 link fix. Kit (`55046d0`): Windows elevated and unelevated and macOS Crystal + SDK lanes all
`qualification_validation=pass`, manifest checks before and after pass.

What building it found:

* **Execution contexts and `Thread::Mutex`.** With Crystal 1.21 execution contexts, a fiber that makes a blocking call can
  resume on another thread (the system monitor starts a new thread for the context while one is blocked). A
  `Thread::Mutex` held across Crystal I/O, `sleep` or anything else that can yield is then unlocked from a thread that
  does not own it, or the next locker waits forever. Found as a deadlock by a 200-cycle stress loop (gdb: the mutex owner
  was a transient `DEFAULT-0` thread that no longer existed). Rule adopted: under a lock, only raw syscalls (`LibC.open`,
  `read`, `write`, `kill`); `/proc` scans and interface-file reads happen outside it.
* **`IO::FileDescriptor.new(fd)` changes the descriptor's blocking mode.** Its setup makes pipes, sockets and terminals
  non-blocking and everything else blocking. On macOS `fcntl(F_SETFL, O_NONBLOCK)` on a kqueue fails with `ENOTTY`
  (macOS 15, 15 Intel, 26), so every event-driven `Kqueue#wait` raised; on Linux it cleared `O_NONBLOCK` on an inotify
  instance (an anonymous inode), so the loop that drains queued events blocked forever once a delegated cgroup emptied.
  Neither shows where cgroups are not delegated (the local host is hybrid v1, where those specs are pending). A descriptor
  the event loop only waits on is now wrapped with `IO::FileDescriptor.new(handle:)`, which leaves the mode alone.
* **A kqueue cannot be waited on through Crystal's macOS event loop.** The loop registers every descriptor for both
  `EVFILT_READ` and `EVFILT_WRITE` (edge-triggered, once per descriptor), and the kernel refuses `EVFILT_WRITE` on a
  kqueue descriptor: `kevent: Invalid argument` on macOS 15, 15 Intel and 26. `Kqueue#wait` polls the exit watch every
  5 ms again; an event-driven wait needs a kevent thread of its own or `EVFILT_PROC` in the runtime.
* **Crystal ignores `@[Link]` on a `private lib`.** A cross-compiled link line has no `user32.lib` for
  `@[Link("user32")] private lib ...` and has it once the lib is public (checked with a three-line program). kernel32,
  ntdll and libproc are linked by the standard library anyway, so only user32 showed it: the Windows supervision spec
  binary did not link, and the shard-dev gate passed because it judged only the result files that existed (it now
  requires them).
* **Winsock and `clear_env`.** Requiring Crystal's socket library makes the program call `WSAStartup` at start; in a
  process whose environment has no `SystemRoot` that fails and the program dies before `main`. The kit's
  `clear_env` cases (the probe is itself the child) all lost their child once the shard required `socket`. The shard
  now requires it on POSIX only.
* **IPC socket ends.** `UNIXSocket.pair` returns non-blocking ends; `O_NONBLOCK` belongs to the open file description, so
  the child's end must be set blocking before it is passed on, as for pipes.
* **A process group of zombies.** On Linux `kill(-pgid, 0)` succeeds while any member is a zombie (macOS answers
  `EPERM`), so a group whose last members exited but were not reaped looked alive. `empty?` reads `/proc/<pid>/stat`
  (state not `Z`/`X`, process group equal) when the probe succeeds.
* **`kill --` in dash.** `kill -KILL -- -<pgid>` is rejected by dash (Ubuntu's `/bin/sh`); `kill -KILL -<pgid>` works in
  dash, bash and macOS's sh. The lifeline watcher uses the latter.
* **`SystemdScope` and the migration rule.** `systemd-run --user --scope -p Delegate=yes` creates a scope owned by the
  user on the hosted Ubuntu runners, but a CI job runs in a system service, and moving a process between cgroups needs
  write access to `cgroup.procs` of the closest common ancestor (here the root): every spawn into the scope failed with
  `EACCES`. `acquire` now checks this and refuses with the reason. Only a supervisor inside the user's systemd tree, or
  root, can use it.
* **Crystal children do not crash on Windows the way other programs do.** The runtime installs a first vectored exception
  handler that prints an access violation or a stack overflow and exits with code 1, so such a child is reported as
  "exited 1", not as `STATUS_ACCESS_VIOLATION`, and `DIE_ON_UNHANDLED_EXCEPTION` never sees it. Other exceptions pass
  through: a non-continuable `STATUS_ILLEGAL_INSTRUCTION` ends the child at once in a Job with that limit and is
  classified as a crash.
* **Windows command-line limit.** `CreateProcessW` takes 32,767 UTF-16 units including the terminator; the shard checks
  before anything is created and raises the error `CreateProcessW` itself gives (`ERROR_FILENAME_EXCED_RANGE`, 206).

## Hard questions, measured (explore-hard.yml: Windows arguments and batch files, a Crystal service, Landlock and seccomp, launchd, FreeBSD)

The questions documentation does not settle, each answered by running it: `explore/windows/argv_fuzz.cr` +
`argdump.c`, `explore/windows/crystal_service.cr`, `explore/linux/sandbox.c`, `explore/macos/launchd_probe.sh`,
`explore/freebsd/fbsd_proc.c`. What it changed in the shards: macOS exit watches share one kqueue and one thread
(event-driven, no descriptor per handle; process-handle 0.10.0), and Windows has `Job#spawn_batch`.

### Windows: argument quoting (Server 2022 and 2025)

| Path | Cases | Mismatches |
|---|---|---|
| `Process.quote_windows` → `CommandLineToArgvW`, in process | 20 000 × 2 runners | 0 |
| → a child built with `cl.exe` (Universal CRT `wmain` argv) | 1 500 × 2 | 0 |
| → a Crystal child (`ARGV`) | 300 × 2 | 0 |

The random arguments mix spaces, tabs, `"`, runs of backslashes (also trailing), `^&|<>%!()`, `%PATH%`, empty
strings, non-BMP characters, U+00A0, U+3000 and (rarely) `\n \r \v \f`. Crystal's quoting is exact for every C-runtime
parser measured; nothing to fix. (The first run reported 1 500 mismatches: `argdump`'s stdout is in text mode and
added `\r`. A probe bug, worth knowing when a child's output is compared byte for byte.)

### Windows: batch files

`CreateProcessW` runs a `.bat`/`.cmd` through `cmd.exe`, whose parser does not follow the C runtime's, so quoting for
the C runtime lets an argument inject commands ("BatBadBut", CVE-2024-24576). Crystal's `Process.new` and the shard's
`Job#spawn` both refuse batch files by extension. Every spelling tried against both, with an injection payload
(`"&echo injected>inj.txt&rem `):

* `t.bat`, `T.BAT`, `t.bat.`, `t.bat `, `t.bat. . `, `t.cmd`, a long name: refused by the extension check (Crystal:
  `File::BadExecutableError`; the shard: `Error::Unsupported`);
* `t.bat::$DATA`, `t.cmd::$DATA`, an alternate stream `t2.bat:s`, `noext:s`: `CreateProcessW` itself answers
  `ERROR_BAD_EXE_FORMAT` (193): **a stream name does not make Windows start cmd.exe**; `plain.txt:evil.bat` is caught
  by the extension check;
* `t.bat\t`, `t.bat/`, `t.bat\`, `t` (with `t.bat` present), `tonly` with its directory first in `PATH`: not found
  (`CreateProcessW` appends only `.exe`; Crystal's lookup does not use `PATHEXT`);
* batch text in a file named `.exe`: error 216 (`ERROR_EXE_MACHINE_TYPE_MISMATCH`); Crystal raises an `IO::Error`
  with an empty message for it;
* 8.3 short names are disabled on the runners' `D:` volume (`GetShortPathNameW` returns the long name).

Nothing ran a batch file and nothing was injected. **Running a batch file safely**: the quoting Rust adopted
(`cmd.exe /e:ON /v:OFF /d /c ""script" args"`; an argument that is not plain is quoted, `"` doubled, backslashes
doubled only before a quote, `%` preceded by a `%%cd:~,` no-op so `%VAR%` never expands), sent through a wrapper
`.cmd` that passes `%*` to the UCRT child: **3 000 random argument lists, 0 mismatches, 0 injections** (an injection
payload in every tenth list). With `\n \r \v \f` mixed in, 251 of 1 500 lists differ, still 0 injections. Character
by character (alone, at the start, middle and end of an argument, quoted, between `%`): `\v`, `\f`, `\t`, ESC, U+0001
and DEL pass unchanged; **`\n` ends the command** (everything after it is lost) and **`\r` is dropped**, leaving the
`%%cd:~,` text visible. A line break cannot pass through cmd.exe at all. Built as `Job#spawn_batch` (it refuses
`\n`/`\r` and a script path with `"`, and names `cmd.exe` by its full path); its spec passes on both runners.

### Windows: a Crystal program as a service (Server 2022 and 2025, elevated)

The SCM calls `ServiceMain` on a thread it creates, and the control handler on the thread that called
`StartServiceCtrlDispatcherW`. The probe runs the dispatcher on a Crystal `Thread`, keeps `ServiceMain` to Win32 calls
(register the handler, report `RUNNING`, signal an event) and does the Crystal work on the main thread.

* It works: `RUNNING` 47–96 ms after `StartService`; `ServiceMain` ran on a thread that was neither the main nor the
  dispatcher thread; the handler ran on the dispatcher thread.
* Allocating Crystal objects inside `ServiceMain` (the foreign thread) did not crash in 4 starts, but that thread is
  not registered with the GC; a design must not depend on it.
* Standard streams: all three are not ttys, and `STDOUT.puts` raises `IO::Error: Closed stream` (Crystal maps the
  service's missing handles to closed streams). A service must log to a file or the event log.
* `Process.run` works from the service; a worker started with `ProcessSupervision.job` ran in session 0.
* `SERVICE_CONTROL_STOP`: `STOPPED` 17 ms after `ControlService`, the Job's shutdown took 0.1–0.2 ms, the worker was
  gone. `taskkill /F` of the service process: the worker was gone with it (the Job's kill-on-close), the SCM reported
  `STOPPED` within 86–100 ms.

### Linux: Landlock and seccomp in the child (22.04 kernel 6.8, 24.04 x64 and arm64 kernel 7.0; also as root and in Docker)

| | ubuntu-22.04 | ubuntu-24.04 / 24.04-arm |
|---|---|---|
| Landlock ABI | 4 | 8 |
| filesystem rules (read-only `/`, one writable directory, `/dev/null`) survive `exec` | yes | yes |
| TCP connect denied (ABI ≥ 4) | yes | yes |
| signal scoping (ABI ≥ 6): the sandboxed child cannot signal its supervisor, can signal its own children | n/a | yes |
| `landlock_restrict_self` without `no_new_privs`, unprivileged / root on host / root in Docker | `EPERM` / works / `EPERM` | same |
| seccomp filter without `no_new_privs`, unprivileged / root on host / root in Docker | `EACCES` / works / `EACCES` | same |
| `SECCOMP_RET_ERRNO` survives `exec` | yes | yes |
| `SECCOMP_RET_KILL_PROCESS` | `SIGSYS`, core dumped | same |
| user notification: the child sends its listener to the supervisor (`SCM_RIGHTS`), the supervisor reads the path from `/proc/<pid>/mem`, checks `NOTIF_ID_VALID` and answers `EROFS` | works, 2 µs from request to receipt; also in default Docker | works (2–191 µs) |

Consequences for the shard: a sandbox must be applied in the child between fork and exec (the fork / `clone3` engines;
`posix_spawn` and `pidfd_spawn` cannot), it needs `no_new_privs` unless the supervisor has `CAP_SYS_ADMIN`, and
Docker's root does not count. On glibc x86_64, `mkdir` uses `__NR_mkdir`, not `mkdirat`, so a filter must name both.
Landlock's signal scope (kernel 6.12+) is the first kernel mechanism here that stops a child from signalling its own
supervisor.

### macOS: launchd as the supervisor's own manager (macOS 15.8 and 26.6)

A job that writes its pid, starts a background `sleep` in its process group and a `setsid()` escapee, then loops
(`sleep 1`) with a TERM trap. Liveness by `ps` (not `kill -0`, which answers `EPERM` for root's processes and succeeds
for zombies, and made the first run's answers wrong).

| Case | main gone | background child (same group) | `setsid` escapee |
|---|---|---|---|
| `bootout`, `gui/501` and `system` | 0.77–0.97 s (the TERM trap runs after the current `sleep 1`) | with main | **still running after 8 s** |
| `bootout`, TERM ignored, `ExitTimeOut` 3 | 3.10–3.13 s (SIGKILL) | with main | still running |
| `bootout`, `AbandonProcessGroup` | 0.89–1.12 s | **still running** | still running |
| main SIGKILLed | 23–50 ms | with main | still running |
| main SIGKILLed, `KeepAlive` | new main after **10.10–10.20 s** (default throttle) | with the old main | still running |
| the same with `ThrottleInterval` 1 | new main after 1.06–1.11 s | with the old main | still running |

* Domains a CI user has: `gui/501` (a login session exists on the hosted runners) and `system` (through `sudo`);
  `launchctl bootstrap user/501` fails with `5: Input/output error`.
* `bootstrap` returns in 10–41 ms; the job runs 76–223 ms after it.
* launchd's guarantee is the job's process group: it ends the group when the job ends unless `AbandonProcessGroup`,
  and does nothing to a process that left the group. On macOS 26 each job is in its own resource and jetsam coalition
  (`launchctl procinfo`); launchd did not use the coalition to end the escapee. A supervisor run by launchd still needs
  its own escapee tracking (the environment marker), and should set `ExitTimeOut` above its own shutdown grace.

### FreeBSD: process descriptors and the reaper (14.3 and 15.0, amd64, in a VM, as root)

| Question | Answer (both releases) |
|---|---|
| `pdfork` + `pdkill(SIGTERM)` + `poll(POLLHUP)` | 0.06–0.10 ms; `pdgetpid` matches |
| does an exited `pdfork` child appear in `wait(-1)`, send `SIGCHLD`? | **no and no** (`ECHILD`, 0 signals); `waitpid(pid)` reaps it |
| `EVFILT_PROCDESC` / `NOTE_EXIT` on the descriptor | fires, `data` is the wait status (exit code 3 → 768) |
| closing the last descriptor | **kills the child** (gone after 5.2–5.5 ms); with `PD_DAEMON` it keeps running |
| `EVFILT_PROC` with `NOTE_TRACK` (removed from macOS) | a child's fork attaches the grandchild automatically: `NOTE_CHILD` (data = parent pid), `NOTE_FORK`, then `NOTE_EXIT` with the status for both |
| `procctl(PROC_REAP_ACQUIRE)` | works; orphans (also a `setsid` one) are reparented to the reaper, `PROC_REAP_STATUS`/`GETPIDS` list them |
| `PROC_REAP_KILL` (SIGKILL, all descendants) | `rk_killed` 2, both orphans dead 0.3–1.9 ms later, **the `setsid` escapee included** |
| `PROC_REAP_KILL` across a nested reaper | `rk_killed` 3: the nested reaper **and its own descendants** died within 1.5–4.9 ms |
| `PROC_PDEATHSIG_CTL` | works; the signal arrived 1.06–1.22 ms after the parent exited |
| `posix_spawn` | `addchdir_np`, `addfchdir_np`, `addclosefrom_np` exist; `POSIX_SPAWN_SETSID` does not |
| Crystal | 1.21.1 is packaged (`pkg install crystal`, LLVM 20); process-handle's spec builds and passes (7 platform-independent examples) |

FreeBSD has the strongest POSIX primitives measured anywhere in this repository: a process descriptor that cannot be
recycled and kills its child when closed (the Windows Job's kill-on-close, per process), plus a subreaper whose tree kill
reaches escapees and nested reapers in one call. A FreeBSD backend would be `pdfork` for identity plus
`PROC_REAP_ACQUIRE`/`PROC_REAP_KILL` for the group. Not built yet: **the Crystal 1.21.1 compiler crashes (`Trace/BPT
trap`, exit 133, no message) compiling process-supervision's spec on FreeBSD 15.0**; that must be reduced first.

### macOS: event-driven exit waits, built (process-handle 0.10.0)

Every `ProcessHandle::Kqueue` registers its `NOTE_EXIT` watch in one shared kqueue. One isolated execution context
blocks in `kevent` on a second kqueue in which the shared one is registered for `EVFILT_READ`, and drains the shared
kqueue under the watcher's mutex; every caller that reads the state drains under the same mutex first, so an exit the
kernel has posted is never invisible because the thread dequeued it and has not recorded it yet. A waiting fiber gets a
pipe and is woken with one byte (not end-of-file: a write end leaked into a concurrently spawned child would hold
end-of-file back). All handles of one pid share one entry, because kqueue keys a watch by (pid, filter). Native
results on macOS 15 and 26: 12 process-handle examples (three new: 53 watches add at most 2 descriptors and all 53
waiters wake on `SIGKILL`; a wait times out while the process runs and returns on exit; `alive?` is false as soon as the
process is reaped, 20 times in a row) and 55 supervision examples, 0 failures, stress run passing.

### Built from these measurements: a Windows service host and launchd jobs

`ProcessSupervision::Windows::Service` follows the probe's wiring, with an isolated execution context for the dispatcher
instead of a raw thread and a pipe (written with a plain `WriteFile` from the SCM's threads) instead of Win32 events, so
the waiting side is an ordinary fiber. Its spec builds `spec/support/service_child.cr`, installs it as a real service,
starts it, finds its Job worker parented to the service process, stops it (the worker is gone, the block returned),
and uninstalls it: 30 supervision examples, 0 failures, 0 pending on Server 2022 and 2025; outside the SCM, `run`
raises `Error::Unavailable` (`StartServiceCtrlDispatcherW` error 1063). `ProcessSupervision::Launchd` writes and loads a
job and reads `launchctl print`; its spec checks that launchd starts the job, that `XPC_SERVICE_NAME` is the label, that
`status` reports the running pid, and that `uninstall` ends the process and removes the property list. It passes on macOS 15 and 26 (57 supervision examples, 0 failures; the one pending is the stress spec, which runs
in its own step).

## Process semantics that were wrong in the shard (found, reproduced, fixed)

Each one has a spec that failed before the fix (shown by reverting the fix) and passes after; Linux runs on all three
Ubuntu runners in every environment (plain, root, systemd units, Docker), macOS 15 and 26.

* **The parent-death signal fired minutes after spawn.** `PR_SET_PDEATHSIG` is tied to the *thread* that created the
  child. Crystal 1.21 runs with execution contexts by default; an isolated context's thread goes back to a pool when
  its fiber ends, and the pool ends idle threads after `Fiber::ExecutionContext.thread_keepalive` (5 minutes). A child
  spawned with `parent_death_signal` from such a context (the shard's own bridge made one for every call from a raw
  thread) was SIGKILLed when that thread was retired. With a 50 ms keepalive the spec's child died at once. Spawns
  with a parent-death signal now run on one isolated context that never ends.
* **PID 1 of a new PID namespace ignored SIGTERM.** The kernel drops every signal the namespace's init has no handler
  for, so `sleep 30` started with `namespaces: Pid` survived `TERM` (the spec shows it still running after 3 s), and
  every orphan in the namespace became its zombie. The child now runs a minimal init as PID 1 (all signals blocked and
  taken with `sigwaitinfo`, forwarded to the program's process group, `waitpid(-1)` for orphans, exit with the
  program's code or 128 + signal); the program is PID 2. `pid_namespace_init = false` keeps the old behaviour.
* **A reused pid inherited a stray child's exit status.** Crystal's SIGCHLD handler reaps every child with
  `waitpid(-1)` and parks a status nobody waits for under its pid; `Crystal::System::Process.new` claims a parked
  status at once. A stray (an orphan adopted as a subreaper, a raw `fork`, a `Process` dropped without `wait`) whose
  pid the kernel reuses for a new child hands that child its status: with `ns_last_pid` forcing the reuse, a child
  that ran for a second "exited 7" after 2 ms, in plain `Process.new` and in the shard. The shard now drops a parked
  status before adopting a pid unless the new child itself has been reaped (`waitid(P_PID, WNOHANG | WNOWAIT)`
  answers ECHILD), checked under the handler's own mutex so a concurrent reap is never lost. Plain `Process.new` in
  the standard library still has this.
* **Children inherited descriptors without close-on-exec.** "Inherits stdio and nothing else" held only for
  descriptors with `O_CLOEXEC`; one the supervisor itself inherited, or a C library opened, reached every Linux child
  (the spec saw it on the `pidfd_spawn` path). `pidfd_spawn` now closes the gaps below the highest extra descriptor
  and everything above it (`posix_spawn_file_actions_addclosefrom_np`); the clone3/fork child marks everything from 3
  up close-on-exec (`close_range(CLOSE_RANGE_CLOEXEC)`, kernel 5.11+, an `fcntl` loop before) so the exec-error pipe
  still works, then clears the flag on the extra descriptors. macOS already used `POSIX_SPAWN_CLOEXEC_DEFAULT`.
* **`wait` hung on streams after the child had exited.** With a stream copied into an `IO`, `Child#wait` waited
  for every copy. An output pipe reaches end-of-file only when every process holding its write end closes it, so
  `sh -c 'sleep 3 & echo hi'` made `wait` take 3 s (the grandchild's life, not the child's); a copy into stdin from a
  source that never ends kept even `wait(5.seconds)` blocked (still blocked when the 30 s guard ended the program).
  Now the stdin copy is abandoned once the child has exited, `SpawnOptions#wait_delay` (Go's `Cmd.WaitDelay`) bounds
  the wait for output pipes after the exit and sets `Child#output_cut?`, and a finite `wait(timeout)` bounds the whole
  call (the collection goes on in a fiber; a later `wait` picks it up).
* **A process group number was signalled after it could belong to someone else.** `ProcessGroup#signal` sent
  `kill(-pgid)` forever. Once every member has exited, an unrelated process that leads a new group (`setsid`) can get
  the number: with `ns_last_pid` forcing it, `group.kill` killed a `setsid sleep 30`. While any member lives the kernel
  does not reuse a pgid, and a group that has emptied can never get a member again (joining needs a live member), so
  the group is tombstoned the first time it is seen empty (`ESRCH`) and nothing is sent to the number afterwards. Not
  covered: a group that empties and whose number is reused before the controller looks at it even once (a full pid
  wrap in between).
* **Windows: an exited process stays in the process snapshot while any handle to it is open**, so "the worker is gone"
  right after a service stop must wait for the last handle (the Windows Server 2025 run failed once on that).

## Still open

* the Windows enforcement period (7.000 s on x64, 7.04–7.16 s on arm64, not a clock effect): the 7-second job-time
  timer is in the Windows Research Kernel (`PSP_JOB_TIME_LIMITS_TIME = -7`, `psjob.c`) and a third-party disassembly of
  a later x64 kernel shows the balance-set manager counting it down; why arm64's pass runs later is not known;
* which code returns `ERROR_INVALID_PARAMETER` for a write when `MaxBandwidth` is not a multiple of 4 KiB;
* why a hung service STOP handler blocks `ControlService` for 240 s on these runners, and what ends the service process
  then (exit code 0);
* why a child cloned with `CLONE_INTO_CGROUP` into a cgroup that has had `cgroup.kill` written dies at once (kernel
  source for 6.8 and 7.0 not read);
* not testable on hosted runners: WSL, Kubernetes, rootless Docker/Podman, a cgroup-v1-only or hybrid-only host (the
  runners are unified; one local 6.18 hybrid host showed the same escape and kill behaviour), SELinux-enforcing hosts;
* macOS descendants: whether the environment marker survives a program that execs and clears or rewrites its environment,
  and whether `START_SUSPENDED` plus a marker is enough in practice; musl/Alpine `posix_spawn` and Docker/systemd cgroup
  delegation were not tested (everything above is the hosted runner images);
* why the Crystal 1.21.1 compiler crashes (SIGTRAP) on process-supervision's spec on FreeBSD; whether launchd's
  coalitions can be used to find escapees; an unprivileged FreeBSD run (the VM runs everything as root);
* not measured: a shared-process (`svchost`-style) service, preshutdown and system shutdown ordering; the macOS
  `posix_spawnattr_setjetsam_ext` limit for grandchildren and after `exec`; GitHub Actions' own cancellation timing.
