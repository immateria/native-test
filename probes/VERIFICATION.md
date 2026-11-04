# Verification receipt — revision 12

Production source is **checkpoint 0009 / working**.

- `process-handle` **0.8.0**
- `process-supervision` **0.7.0**
- source tree SHA-256 `2eca11ff1b63d0a0671679f1cb1e54583bac2eb344e05ac5555dd0a1b2b402a5`
- deterministic checkpoint archive SHA-256 `37f380ac3785317655932377d30ed7d97e6831742e50b2c8e9f69f59d9c971ac`
- **48 source files / 170,026 bytes**

## Root-cause reproductions

Two defects were reproduced before implementation.

1. `ProcessHandle.open(Int64::MAX)` on Linux raised `OverflowError: Arithmetic overflow` from the unchecked `Int64 -> Int32` pidfd conversion. The same native-range contract was not consistently enforced by Linux `observe`/`lookup`.
2. A synthetic result file matching the actual `macos_abi_probe.c` output shape (one passing SDK case followed by its final summary) was rejected by revision 11 with `unexpected SDK summary`.

## Production-source verification

Linux x86-64:

- Crystal **1.21.0**: `process-handle` **22/22**, `process-supervision` **18/18**, public consumer probes pass.
- Crystal **1.21.1 / LLVM 23.1.2**: `process-handle` **22/22**, `process-supervision` **18/18**, public consumer probes pass.
- Crystal 1.21.1 with `-D evloop=io_uring`: `process-handle` **22/22**.
- `crystal tool format --check src spec` passes through each shard's source-owned `scripts/verify.sh` lane.
- The Linux PID-range regression covers `open`, `observe`, and `lookup`; all now return the documented `ArgumentError` for `Int64::MAX` rather than leaking arithmetic overflow or treating the value as a process observation.

## Native-probe compile gates

All four deep no-codegen cross-target compiles pass with Crystal 1.21.1 / LLVM 23.1.2:

| Target | Named Crystal cases | Authoring-host gate |
|---|---:|---|
| `x86_64-pc-windows-msvc` | 459 | deep `--no-codegen --cross-compile` |
| `aarch64-pc-windows-msvc` | 459 | deep `--no-codegen --cross-compile` |
| `x86_64-apple-darwin` | 385 | deep `--no-codegen --cross-compile` |
| `aarch64-apple-darwin` | 385 | deep `--no-codegen --cross-compile` |

A source/coverage audit derives literal `test(...)` names from both Crystal probes and unique `record(...)` names from the C probe. It matches `COVERAGE.md` exactly: **459 Windows + 385 macOS + 45 SDK/C = 889**, with zero missing or extra names.

## Revision-12 result-integrity lane

- `python3 -B test-validator.py`: **12/12** admission regressions pass.
- The tests include the actual SDK/C final-summary shape, missing SDK summary, contradictory SDK counters, missing/duplicate/unexpected cases, skips/failures, wrong checkpoint metadata and Crystal summary manipulation.
- `python3 -m py_compile validate-results.py test-validator.py` passes.
- `sh -n run-macos.sh` passes.
- `test-validator.py` uses `importlib.util` rather than deprecated `SourceFileLoader.load_module()`.

The macOS wrapper's manifest path was exercised on Linux only as an integrity-path test, not as macOS qualification:

- untampered kit: preflight `manifest_check=pass`, expected Linux-vs-Darwin compilation failure, and `post_manifest_check=pass`;
- controlled mid-run mutation after preflight: preflight passes and postflight reports `post_manifest_check=fail` with the changed covered file identified.

PowerShell is unavailable on this authoring host. `run-windows.ps1` contains equivalent post-run manifest/hash validation, but its PowerShell syntax/runtime and native Windows behavior still require the native Windows run.

## Evidence boundary

Revision 12 contains **459 Windows Crystal + 385 macOS Crystal + 45 independent macOS C/SDK = 889 checks**. Native Windows and macOS execution of these exact revision-12 bytes is still pending. Cross-target compilation is compiler/type/ABI-surface evidence only and does not qualify native Job Object, registered-wait, libproc, kqueue, or wrapper runtime behavior.
