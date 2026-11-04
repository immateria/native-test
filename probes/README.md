# Crystal Process Development — exhaustive native probes (revision 10)

This is the native qualification kit for exact **checkpoint 0008 / working** source under `workspace/`. Revision 10 preserves the complete revision-9 matrix and closes two production defects found during an adversarial source/runtime pass, while hardening the handoff so native receipts cannot silently run against edited or stale kit bytes.

It contains **459 Windows Crystal cases**, **385 macOS Crystal cases**, and **45 independent macOS C/SDK behavioral checks**: **889 behavioral checks total**.

See `COVERAGE.md` for every literal case name, `R10-BEHAVIOR-MATRIX.md` for the behavior matrix, and `REVISION-10-CHANGES.md` for the production and harness changes in this pass.

## Production source in this kit

- `process-handle` 0.7.0
- `process-supervision` 0.7.0
- checkpoint 0008 source SHA-256 `0cc24ea5284d5e2efe6a2b533755f4ab9556812ed9551079649bc3418df341b7`
- deterministic checkpoint archive SHA-256 `28e292cc13f1109448e7f51d481efd0477cfc24a0e7cd18d895a95121ed6cc7c`
- 48 source files / 168,893 bytes

Checkpoint 0008 adds first-error-wins cleanup to the public block-scoped `ProcessHandle.open` API and fixes Linux pidfd access-denied diagnostics so the low-level error retains the actual target PID instead of a hard-coded PID 1. Revision 10 adds a native Windows fault-injection case for the block-scoped cleanup rule.

## Handoff integrity

Both native launchers now verify every file listed in `MANIFEST.sha256` before compiling anything. They also reject redirected build directories and recreate `.build` from scratch for each run. The exact admitted manifest is copied into the handback output.

A changed or missing kit file therefore fails before native qualification begins instead of producing a receipt against unknown source bytes.

## Windows

Run non-elevated:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-windows.ps1
```

Return `windows-probe-handback.zip` unchanged even if the command exits non-zero.

## macOS

Run without `sudo`:

```sh
./run-macos.sh
```

Return `macos-probe-handback.zip` unchanged even if compilation, a Crystal case, the C/SDK lane, manifest admission, or the watchdog fails.

## Requirements

- Native probe lane: Crystal 1.21.1 or newer.
- macOS: Xcode Command Line Tools (`clang`) plus Python 3 for the watchdog.
- No third-party shards; exact checkpoint-0008 source is bundled.
- Whole-run watchdog: **1800 seconds**.
- Partial/failing handbacks are diagnostic evidence and should still be returned.

Revision 10 is **native runtime pending**. Linux-hosted specs and Windows/macOS cross-target compilation are verification evidence, not native Windows/macOS qualification.
