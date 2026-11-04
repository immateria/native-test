# What the native runs showed

Measured on GitHub-hosted runners: **Windows Server 2025 x64** (`windows-2025`, Crystal 1.21.1 MSVC) and
**macOS 15 arm64** (`macos-15`, Crystal 1.21.1 universal). Every number below comes from a CI run on branch
`native-probes-ci`; run ids are given so the artifacts can be re-read. "Verified" means observed directly;
"inferred" means it fits the data but was not isolated.

Final state: kit r13 qualifies on **macOS** (386 Crystal + 45 C/SDK cases), on **Windows as the runner provides it
(elevated)** (459 cases) and on **Windows with a filtered, unelevated token** (459 cases) — run `41776017433`, all
three validators pass.

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

### `EVFILT_PROC`/`NOTE_EXIT` registration on an already-exited child fails with `ESRCH` (verified)

200/200 zombie registrations failed with `ESRCH` (never "registered but silent"); 100/100 registrations before exit
delivered. The 16-child kit case lost two registrations that way when spawning outlasted the children's 90–162 ms
delays. One 8-child failure (8 successful registrations, 7 events) is **unexplained**.

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

## Still open

* the in-loop HIGH success in the exploration tool (above);
* the single macOS 8-child kqueue failure (8 registrations, 7 events);
* why `pwsh` cannot launch native commands under the filtered token on the hosted runner;
* the Windows 7.000 s period was measured on `windows-2025` only; it is not documented anywhere I found.
