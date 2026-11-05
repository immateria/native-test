# Crystal Process Development — exhaustive native probes (revision 12)

This is the native qualification kit for exact **checkpoint 0009 / working** source under `workspace/`. Revision 12 preserves all **889** revision-11 behavioral case identities and hardens both the Linux production API and native handback admission.

It contains **468 Windows Crystal cases**, **397 macOS Crystal cases**, and **45 independent macOS C/SDK behavioral checks**: **910 behavioral checks total** (revision 14; see below).

See `COVERAGE.md` for every literal case name, `R12-BEHAVIOR-MATRIX.md` for the active behavior matrix, and `REVISION-12-CHANGES.md` for this pass.

## Production source in this kit

- `process-handle` **0.8.0**
- `process-supervision` **0.7.0**
- checkpoint 0009 source SHA-256 `2eca11ff1b63d0a0671679f1cb1e54583bac2eb344e05ac5555dd0a1b2b402a5`
- deterministic checkpoint archive SHA-256 `37f380ac3785317655932377d30ed7d97e6831742e50b2c8e9f69f59d9c971ac`
- **48 source files / 170,026 bytes**

Checkpoint 0009 adds explicit Linux signed-native-PID range validation before pidfd conversion and `/proc` observation/identity lookup. Values above `Int32::MAX` now fail with a stable `ArgumentError` rather than leaking `OverflowError` or being interpreted as a nonexistent PID.

Checkpoint 0008's first-error-wins block-scoped `ProcessHandle.open` cleanup and corrected Linux pidfd access-denied diagnostics remain intact.

## Source changed after checkpoint 0009

The workspace below no longer matches the checkpoint hashes quoted above: the spawn work added `posix/spawn.cr`,
`posix/darwin_spawn.cr`, `linux/raw_spawn.cr` (process-supervision) and `darwin/kqueue_handle.cr`, `Linux.adopt_child`
(process-handle), `ProcessGroup#spawn`/`spawn_leader`, `CgroupV2#spawn`/`usable?`/`delegated_parent`,
`ProcessSupervision.spawn`/`strongest_mechanism`, and refuses process group 1. `MANIFEST.sha256` pins the current files; every
kit case keeps its name and meaning. The measurements behind the changes are in `explore/FINDINGS.md`.

Later: standard-stream options on every spawn (`input:`/`output:`/`error:`, including any `IO` via `stream_copies.cr`),
`pidfd_spawn` as the first Linux engine, the process-group descendant marker (`posix/marker_scan.cr`,
`ProcessGroup#escapees`, `ProcessHandle::Kqueue.watch`). Revision 14 adds **9 Windows and 11 macOS cases** (`r14_*`) for
`ProcessSupervision.spawn`, the stream options and the marker: **468 Windows Crystal, 397 macOS Crystal, 45 C/SDK** (910).
Existing cases keep their names and meaning.

## Handoff integrity

Both native launchers verify every file listed in `MANIFEST.sha256` before compilation, reject redirected build/output paths, and recreate `.build` from scratch. Revision 12 additionally re-verifies the manifest hash and every covered file after execution so changes during a native run cannot silently qualify.

Native JSONL admission is independent of the probe's exit code. Every expected case from `COVERAGE.md` must occur exactly once and pass; unexpected non-informational cases, duplicates, skips, failures, malformed records, missing/non-final summaries, or contradictory summary counters fail qualification. The macOS C/SDK lane now validates its actual final-summary format rather than rejecting it.

Diagnostic handbacks are packaged even when qualification fails.

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

Return `macos-probe-handback.zip` unchanged even if compilation, a Crystal case, the C/SDK lane, manifest admission/revalidation, coverage validation, or the watchdog fails.

## Requirements

- Native probe lane: Crystal **1.21.1 or newer**.
- macOS: Xcode Command Line Tools (`clang`) plus Python 3 for the watchdog/result validator.
- No third-party shards; exact checkpoint-0009 source is bundled.
- Whole-run watchdog: **1800 seconds**.
- Partial/failing handbacks are diagnostic evidence and should still be returned.

Revision 12 is **native runtime pending**. Linux-hosted specs and Windows/macOS cross-target compilation are verification evidence, not native Windows/macOS qualification.
