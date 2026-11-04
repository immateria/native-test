# Revision 13 — harness defects found by the first native run

Revision 13 changes **only the probe harness**. The 889 case identities, `COVERAGE.md`, the result
validator and both shards are unchanged. The first native execution of r10 on GitHub-hosted runners
(Windows Server 2025 x64, macOS 15 arm64, Crystal 1.21.1) produced 28 failures and a C/SDK build
failure. Triage showed 17 of the 28 were harness bugs, 4 more share their mechanism, and 7 are open
OS-behaviour questions (those are explored by `explore/`, not changed here).

Everything below was reproduced on Crystal 1.21.1 before it was changed.

## Crystal semantics the harness got wrong

| Defect | Where | Effect |
|---|---|---|
| `N.times.map { … }` is a **lazy iterator**; the block runs when it is consumed, and it is consumed once. | 9 sites (8 Windows, 1 macOS) | `wait_many_timeouts_then_completion`: the 8 timed waits ran *after* the child had exited, so all returned true. Six `threads = N.times.map { Thread.new … }` sites created and joined threads **one at a time**; in `wait_close_barrier_native_threads`, `wait_kill_barrier_native_threads` and `job_close_vs_accounting_parallel_only_success_or_closed` the close/kill therefore ran before any waiter existed, so those cases passed without ever racing the action under test. Now eager (`Array(T).new(n) { … }`), and the barrier results are part of the assertion. |
| `Array(Atomic(Int32))` slots: `Atomic` is a struct, `slots[i].set(x)` mutates a copy. | `r6_thread_wait_fanout_*` (windows) | The case could not pass on any OS. Replaced by `ProbeSlots` (Thread::Mutex-guarded). Worker exceptions are now recorded with a backtrace frame instead of being counted as `-2`. |
| A bare `Thread.new` thread has **no execution context**. `File.read/write/open`, `IO.pipe`, `Process.new/run` and fiber `sleep` raise `NilAssertionError: Thread#execution_context cannot be nil` there; `File.exists?`, `Dir.children`, `Thread.sleep`, `::Mutex` and `Atomic` do not. | 4 Windows cross-job cases, 6 macOS cases | Harness I/O inside those workers moved to `ProbeThread` (a dedicated thread owning a `Fiber::ExecutionContext::Isolated`). Cases whose point is "this library call works from a native thread" keep bare `Thread.new` and now report the first failure frame. |
| `Process#wait` **closes the child's pipes** (documented: "Waits for this process to complete and closes any pipes"). | `r9_direct_child_exit_precedes_inherited_pipe_eof`, `r9_kqueue_exit_precedes_inherited_pipe_eof` | The reader lost its fd as soon as the case reaped the child, so "exit is independent of EOF" could not be observed. The reader now uses a `dup` of the read end taken before the wait. |
| Stdlib `Process.new` opens `/dev/null` three times before it spawns and has no `ensure` on that path. A failed spawn leaves those `File`s to the GC finalizer. | 4 macOS fd-count cases | These cases measure **stdlib** `Process.new`, not the kit. Descriptor counts now settle the GC (`gc_settle`) before the assertion and additionally report `after_no_gc` / `lingering_until_gc`. |

## C / SDK lane

`macos_abi_probe.c` declared `all_count` / `all_errno` twice in `main` (an `int` libproc block and a
`size_t` sysctl block ~220 lines later); `-Werror` made the file unbuildable, so none of the 45 SDK
checks ran. The first (libproc) pair is renamed `pid_list_count` / `pid_list_errno`.

## Second pass: what the first native run of r13 showed

The r13 harness fixes cleared 20 of the 28 failures (Windows 15 -> 5, macOS 13 -> 3) and made the C/SDK lane build (all 45 checks pass and
r12's validator accepts the lane). Native exploration (`explore/`) then explained most of what remained:

* **Windows evaluates job CPU-time limits and notification limits in a periodic system-wide pass every
  7.000 s**, not when a limit is crossed. Measured directly (`explore` cpu-period, elevated and unelevated
  identical): successive kills of a job-time-limited spinner were 7004.6 / 6998.6 / 7000.7 / 6998.9 /
  6998.5 ms apart, the first kill landing at an arbitrary phase; two jobs started 2.5 s apart were killed at
  the *same* instant (one global pass, not a per-job timer). Earlier evidence: ten trials per setting alternated killed / not killed
  regardless of the configured limit (50, 150 or 300 ms), killed trials all died ~3.48 s into a 3.5 s spin
  because each firing ends the running trial and phase-locks the next, and the write/read notification
  messages arrived 0.6-4.7 s after the I/O, with two read messages 6.995 s apart. The kit's 4 s spin / 7 s
  wait and its 5 s notification wait therefore passed or failed by where the tick landed. Spin/wait windows
  now cover two periods (`cpu-spin` clamp raised to 20 s, wait 18 s; notification wait 12 s).
* **macOS returns `EPERM` from `kill(-pgid, sig)` once every process in the group is a zombie** (signal 0,
  TERM and KILL alike; Linux keeps delivering to zombies). A KILL sent >= 1 ms after TERM to a TERM-killed
  group was `EPERM` in 100% of 700 trials, 12% at 0 ms. `posix/process_group.cr` raised on it and reported
  such a group as non-empty, so TERM -> grace -> KILL escalation raised whenever the group died during the
  grace period. On Darwin that `EPERM` now means "no live member" (`signal` returns, `empty?` is true).
  New deterministic case: `r13_group_signal_zombie_only_group_is_not_fatal` (COVERAGE now lists 890).
* `r9_*_exit_precedes_inherited_pipe_eof`: the helper's grandchild was started with `Process.new`'s default
  `output: Redirect::Close`, so it never held the pipe and EOF arrived at the direct child's exit. It now
  inherits stdout.
* `r9_concurrent_failed_spawn_fd_reuse_stress`: `ProbeThread` contexts keep their event-loop descriptors
  until exit (reproduced: +24 fds for 8 contexts on Linux, 0 for 8 fibers), so this case uses `ProbeFiber`.

* `kqueue_many_children_one_queue_all_exit_events` failed once in six native runs: 8 successful registrations
  but 7 exit events. **Unexplained.** A registration made after the child has exited fails with `ESRCH`
  (`explore/macos/kqueue_zombie.c`: 200 of 200 trials; 100 of 100 live registrations delivered), which would have
  shown as a failed registration, not a missing event. The case now registers each child right after spawning it
  (removing that ESRCH path on slow runners) and records `event_rcs` and `missing_pids` so a recurrence says more.
* **A HIGH job priority class is rejected with 1314 by an elevated token that merely holds
  `SeIncreaseBasePriorityPrivilege` disabled.** Measured in fresh processes (no earlier calls): the kit executable
  and `job_explore` both get 1314 for all three request shapes (basic, extended, extended + KILL_ON_JOB_CLOSE), with
  no thread token. This matches Microsoft's "the calling process must enable" the privilege (and a Stack Overflow
  report that fixed the same 1314 by enabling it). An earlier `job_explore` run appeared to succeed because something it did
  first changed the process state. It is **not** `SetPriorityClass(self, X)` for any of the six classes, REALTIME
  included (measured: the HIGH request stays 1314 and the privilege stays disabled throughout); `priority_flip`
  rows now replay the remaining candidates (creating a job with a lower class, a suspended child, assigning it,
  resuming, terminating). `r6_priority_applied_high` enables the privilege when the token holds it, verifies the
  state by reading the token, restores it afterwards, and expects success; a token that does not hold it (the
  unelevated run) is expected to get 1314. Its details record `privilege_before`/`privilege_during`.
* The fault-injection helpers (`job_checked_close_failure_surfaces` and siblings) close a handle behind the library's
  back so its own `CloseHandle` fails; Windows reuses handle values at once, so another thread can take the number
  first and the library's close then succeeds (`unexpected_success`, seen once in ten runs, only in the unelevated
  run). `run_fault_helper` now retries up to five times and records `attempts`.
* `handle_allowlist_blocks_unrelated_inheritable_event` passed elevated and failed unelevated with
  `wrongly_inherited: true`, but only because the check treated "some valid handle has this number in the child" as
  inheritance, and a filtered-token child owns different handles. The event is now created signaled and the child
  reports whether that handle is a signaled waitable object (`number_collision_only` records the benign case).
* `r6_kqueue_many_children_16` had 14 of 16 successful registrations: the same spawn-all-then-register race as the
  8-child case (late registration fails with `ESRCH`, measured); it now registers each child right after spawning.
* `job_user_time_limit_enforced_and_event` (the one remaining short-window enforcement assertion) also spins and
  waits two periods.

## Not changed on purpose

* `r6_priority_applied_high` (`SetInformationJobObject` fails with 1314 in the kit but the identical request
  succeeds from `explore`; the exploration also shows a job priority class is *not* applied to a process
  assigned after creation, whereas the kit's create-into-job path applies it) is still asserted as before
  pending the caller-class experiment in `explore`.
* The Windows run was elevated (`runneradmin`). The kit says never to run elevated; CI now also runs
  the kit with a filtered, unelevated token (`explore/windows/job_explore.cr launch-unelevated`: Medium
  integrity, Administrators deny-only, only SeChangeNotify). `pwsh` cannot be run under that token on a
  non-interactive runner: every native command it starts fails (`Access is denied`, then PowerShell's
  `StandardOutputEncoding is only supported when standard output is redirected`), `crystal.exe`'s ACL is open
  so it is not a file permission problem, and giving the child a fresh console (`CREATE_NO_WINDOW`) makes even
  a Crystal binary die with `STATUS_DLL_INIT_FAILED`. So only the probe *executable* runs filtered: the
  wrapper (and the Crystal build) stay elevated, and the new optional `PROCESS_PROBE_LAUNCHER` environment
  variable in `run-windows.ps1` starts the probe through `job_explore.exe launch-unelevated`. Unset, the
  wrapper behaves exactly as before.

## Evidence boundary

First pass (the harness fixes + C rename) ran natively. The second-pass changes above are type-checked
for `x86_64-windows-msvc` and `aarch64-apple-darwin` (and the shard's 18 Linux specs pass) but had not run
natively when this was written.
