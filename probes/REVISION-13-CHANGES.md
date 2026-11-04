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

## Not changed on purpose

* `r6_priority_applied_high`, the CPU-time enforcement cases, `r9_notification_limit_write_*` and the
  macOS `r6_group_shutdown_grace_*` `EPERM` cases are still asserted as before. They are open
  questions about Windows/macOS behaviour; `explore/` measures them directly.
* The Windows run was elevated (`runneradmin`). The kit says never to run elevated; CI now also runs
  the kit with a filtered, unelevated token (see `.github/workflows/native-probes.yml`).

## Evidence boundary

Type-checked for `x86_64-windows-msvc` and `aarch64-apple-darwin` on Linux; **not** executed natively
at the time of writing. The C change cannot be compiled without the macOS SDK.
