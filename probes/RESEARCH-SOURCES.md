# Research sources underlying exhaustive revisions 4–10

Revision 4 was designed from a behavior inventory first, then implemented as tests. Revisions 5–7 preserve that inventory and add closure probes derived from native failures rather than restarting the research surface. Primary OS documentation/source was treated as the contract authority; mature runtime/library implementations supplied adversarial test ideas and lifecycle patterns. These references are design inputs, not runtime evidence for the current shards.

## Windows primary behavior sources

- Microsoft Job Objects: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
  - job lifetime, child inheritance, breakaway, limits, completion-port notification semantics.
- Microsoft Nested Jobs: https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs
  - hierarchy formation, inherited limits, breakaway interactions, notification propagation, nested termination.
- AssignProcessToJobObject: https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
  - access requirements, active-process-limit failure, nested assignment restrictions, terminating-job behavior.
- CreateJobObject: https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw
  - last-handle lifetime and kill-on-close behavior.
- Job completion ports: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port
  - NEW/EXIT/ABNORMAL/ACTIVE_ZERO and limit messages, PID-reuse warning, non-guaranteed ordinary notifications.
- Job basic/extended limits: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
  - working set, process/job time, active-process count, affinity, priority and scheduling semantics.
- SetInformationJobObject / QueryInformationJobObject:
  - https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
  - https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject
- CreateProcess / STARTUPINFOEX / process-thread attributes:
  - https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
  - https://learn.microsoft.com/en-us/windows/win32/procthread/attribute-list
  - used for HANDLE_LIST, JOB_LIST, suspended creation, environment block and std-handle behavior.
- Thread-pool registered waits:
  - https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerwaitforsingleobject
  - https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-unregisterwaitex
  - callback/unregister/quiescence and completion-event behavior.
- Raymond Chen, waiting for a Job to become empty: https://devblogs.microsoft.com/oldnewthing/20130405-00/?p=4743
  - confirms a Job handle itself is not a general "all processes exited" wait primitive; ACTIVE_PROCESS_ZERO is the relevant completion-port event.

## Windows implementation/test cross-checks

- hcsshim: https://github.com/microsoft/hcsshim
  - Job lifecycle, IOCP event readers, nested cleanup, process lists, accounting and resource controls.
- .NET runtime: https://github.com/dotnet/runtime
  - process creation/waiting, kill-on-parent-exit Job usage, inherited handles and suspended start.
- watchexec/process-wrap: https://github.com/watchexec/process-wrap
  - Job ownership, completion-port waiting, forced suspension and assignment/resume ordering.
- libuv: https://github.com/libuv/libuv
  - Windows process HANDLE lifetime, spawn/exit integration and cleanup.
- Swift Subprocess: https://github.com/swiftlang/swift-subprocess
  - current cross-platform spawn/teardown semantics and Windows Job behavior.

## macOS / Darwin primary behavior sources

- XNU `event.h`: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/event.h
  - EVFILT_PROC flags: NOTE_EXIT/FORK/EXEC/SIGNAL/EXITSTATUS/EXIT_DETAIL, deprecated NOTE_REAP/TRACK family and kqueue control flags.
- XNU `kqueue(2)` manual source: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/kqueue.2
  - EV_ADD/DELETE/ENABLE/DISABLE/ONESHOT/CLEAR/RECEIPT and filter semantics.
- XNU `proc_info.h`: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
  - `proc_bsdinfo`, process states, process-group and generation/start fields.
- XNU libproc wrappers:
  - https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h
  - https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c
  - `proc_pidinfo`, `proc_listpgrppids`, `proc_listchildpids`, return/error conventions.

## macOS implementation/test cross-checks

- Swift Subprocess: https://github.com/swiftlang/swift-subprocess
  - kqueue child monitoring, POSIX process groups/sessions, spawn environment/cwd/FD hygiene and teardown.
- psutil: https://github.com/giampaolo/psutil
  - Darwin libproc observation, start-time handling and process-state normalization.
- libuv: https://github.com/libuv/libuv
  - EVFILT_PROC child-exit integration and POSIX spawn lifecycle.
- CPython subprocess tests: https://github.com/python/cpython/blob/main/Lib/test/test_subprocess.py
  - argv/env/cwd failures, FD inheritance, waits/timeouts and cleanup edge cases.
- Go `os/exec`: https://github.com/golang/go/tree/master/src/os/exec
  - process-state/wait/cancel/rollback test ideas.

## Research process

The requested GitHub, Exa and Parallel Search connectors were used on 2026-11-03 to search the OS contract surface and mature implementations from multiple angles. The cumulative current coverage is represented by `COVERAGE.md` and `R10-BEHAVIOR-MATRIX.md`; historical revision-specific decisions are retained in the workspace review material where applicable. Gaps are listed explicitly instead of being silently treated as covered.


## Revision 6/7 matrix derivation

Revision 6 and its revision-7 closure pass do not introduce a new dependency or substitute secondary documentation for OS contracts. It reuses the primary Win32/Job Object and XNU/libproc/kqueue sources above and applies mature subprocess test-suite patterns to systematically enumerate boundary values, repeated lifecycle operations, fan-out sizes, registration timing, exit/signal values, argument/environment pathologies, containment cardinality and resource-policy ranges. Cases are split into literal named receipts so failures are attributable to a specific input/state rather than hidden inside one aggregate loop.


## Revision-9 supplied source tranche

Pinned snapshots supplied for this pass: CPython `7e3290d94427cdbfe0483f0a99d589b784d77c1a`; Wine `7692c6213e2c1c2f9cea92cc29ea13afc582865f`; ReactOS `5608ce5a1a0d90ded61d7bd42257825e8c6ec409`; OpenJDK `d7d71e64983bc36dc5b60cfe6ee1f9b5bc3509b5`; Go `a17a0eb2480aeeb9c2930543fcc6c0bf87100f4e`; Rust `708c94ef093ecc42fb8851e17d8383d999727abc`; Apple Libc `71bbe350ab79eef58113991d817ccc6165061a64`; Swift Corelibs Foundation `08a9cd98b7eaf4821c70e87e2173ff18a2359b1f`; Microsoft BuildXL `bb47829d070db954ea03c1bac9f524c5c175fe41`; System Informer `509c135002b5d93bd2ddef9dd6fcecf4ab0c7268`; Fs.Processes `43dbf5fc2cd21c463bbc02dfb7654e124085c3b7`; win_safesubprocess `24be26f05f78e3869fdec986ad4b478e1a7573ec`; JobExplorer `15702eef6a8c3d588d51138b923cc433b9352b64`.

The accepted revision-9 lessons are retained in `R10-BEHAVIOR-MATRIX.md`. These repositories are evidence, never runtime dependencies.


## Revision-10 hardening derivation

Revision 10 adds no new external dependency or research tranche. Its production changes come from direct source/runtime investigation of the checkpoint-0007 APIs: exception-precedence fault injection for block-scoped ownership and a Linux cross-user pidfd signalling reproduction. The new native Windows case exists to qualify the same cleanup invariant on the HANDLE backend. The full-manifest launcher gate is an evidence-integrity change, not a platform-semantics claim.
