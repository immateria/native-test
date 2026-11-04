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

* `job_user_time_limit_enforced_and_event` (the one remaining short-window enforcement assertion) also spins and
  waits two periods.

## Not changed on purpose

* `r6_priority_applied_high` (`SetInformationJobObject` fails with 1314 in the kit but the identical request
  succeeds from `explore`; the exploration also shows a job priority class is *not* applied to a process
  assigned after creation, whereas the kit's create-into-job path applies it) is still asserted as before
  pending the caller-class experiment in `explore`.
* The Windows run was elevated (`runneradmin`). The kit says never to run elevated; CI now also runs
  the kit with a filtered, unelevated token (`explore/windows/job_explore.cr launch-unelevated`: Medium
  integrity, Administrators deny-only, only SeChangeNotify). Under it the kit wrapper fails at its first
  `crystal` invocation with `Access is denied`; `C:\crystal\crystal.exe` already grants Users RX and
  Authenticated Users Modify with no mandatory label, so this is **not** a file ACL problem. Cause under
  investigation (`explore/windows/unelevated-diag.ps1`).

## Evidence boundary

First pass (the harness fixes + C rename) ran natively. The second-pass changes above are type-checked
for `x86_64-windows-msvc` and `aarch64-apple-darwin` (and the shard's 18 Linux specs pass) but had not run
natively when this was written.
