# Revision 12 — PID-range and qualification-integrity hardening

Revision 12 advances the bundled production workspace to **checkpoint 0009 / working** while preserving all **889** Windows/macOS behavioral case identities from revision 11.

## Production fix: Linux native PID range

The Linux pidfd path accepted `Int64` PIDs but converted them directly to signed native `pid_t` with `to_i32`. `ProcessHandle.open(Int64::MAX)` therefore leaked Crystal's `OverflowError`. `observe`/`lookup` also treated out-of-range values differently from the other POSIX backends.

Checkpoint 0009 validates the Linux native PID range before pidfd conversion and before `/proc` observation/identity lookup. `open`, `observe`, and `lookup` now reject values above `Int32::MAX` with `ArgumentError("pid exceeds native pid range")`. A runtime regression covers all three public entrypoints. `process-handle` advances to **0.8.0**; `process-supervision` remains **0.7.0**.

## Probe fix: macOS C/SDK summary admission

Revision 11's result validator required the macOS C/SDK lane to have no `summary` record, but `macos_abi_probe.c` has always emitted a final summary. As a result, a completely passing native C/SDK run would still be rejected with `unexpected SDK summary`.

Revision 12 makes the validator enforce the C lane's real contract instead: exactly one final summary, matching `cases` and `failures`, with a status consistent with the body records. The regression suite now uses the real C-lane shape and covers a missing SDK summary and contradictory SDK counters.

## Evidence binding: post-run manifest verification

Both launchers already verify the packaged manifest before compilation. Revision 12 rechecks the manifest hash and every covered file after native execution and result validation. A covered file or the manifest itself changing during the run prevents qualification while preserving the diagnostic handback. This closes the preflight-to-build/run mutation window for accidental edits or synchronization races.

The Windows implementation remains PowerShell 5.1-native and adds no Python dependency. The macOS implementation continues to use the system `shasum` path already required by the preflight.

## Harness maintenance

`test-validator.py` no longer uses the deprecated `SourceFileLoader.load_module()` API; it loads the validator through `importlib.util` instead.

## Evidence boundary

Revision 12 is still **native Windows/macOS runtime pending**. Linux runtime specs and hosted cross-target compilation do not qualify Windows Job/registered-wait behavior or native macOS libproc/kqueue behavior. The 889-case inventory is unchanged; only the checkpoint/revision metadata and admission rules change.
