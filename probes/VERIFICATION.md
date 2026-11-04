# Verification receipt — revision 10

Production source is **checkpoint 0008 / working**.

- `process-handle` 0.7.0
- `process-supervision` 0.7.0
- source tree SHA-256 `0cc24ea5284d5e2efe6a2b533755f4ab9556812ed9551079649bc3418df341b7`
- deterministic checkpoint archive SHA-256 `28e292cc13f1109448e7f51d481efd0477cfc24a0e7cd18d895a95121ed6cc7c`
- 48 source files / 168,893 bytes

## Authoring-host source verification

Linux x86-64:

- Crystal **1.21.1** / LLVM **23.1.2**: `process-handle` **21/21**, `process-supervision` **18/18**.
- Crystal **1.21.0** / LLVM **20.1.8**: `process-handle` **21/21**, `process-supervision` **18/18**.
- Crystal 1.21.1 formatting check passes for the changed shard source/spec and both Crystal native probes.
- A native Linux cross-user reproduction confirms pidfd `EPERM` now reports the real target PID without the former nested `process 1` diagnostic.

## Revision-10 probe compile gates

All four deep no-codegen cross-target compiles pass with Crystal 1.21.1 / LLVM 23.1.2:

| Target | Named Crystal cases | Authoring-host gate |
|---|---:|---|
| `x86_64-pc-windows-msvc` | 459 | deep `--no-codegen --cross-compile` |
| `aarch64-pc-windows-msvc` | 459 | deep `--no-codegen --cross-compile` |
| `x86_64-apple-darwin` | 385 | deep `--no-codegen --cross-compile` |
| `aarch64-apple-darwin` | 385 | deep `--no-codegen --cross-compile` |

The independent macOS SDK program still contains 45 behavioral cases. `macos_zombie_holder.c` remains separately built with warnings-as-errors and hash-bound into qualification.

`run-macos.sh` is packaged mode `0755` and passes POSIX shell syntax validation on the authoring host. Its manifest-admission path was exercised in a disposable copy: an untampered kit recorded `manifest_check=pass` and copied `kit-manifest.sha256` before reaching the expected Linux-vs-Darwin compile rejection; after modifying one manifest-covered file, the wrapper exited 3 with `manifest_check=fail` before compilation. This is wrapper-integrity evidence, not native macOS qualification.

PowerShell is not installed on this Linux host, so `run-windows.ps1` cannot be executed here; its native Windows wrapper behavior remains part of the pending Windows run.

## Evidence boundary

Revision 10 contains **459 Windows Crystal + 385 macOS Crystal + 45 independent macOS C/SDK = 889 checks**. Native Windows and macOS execution of these exact revision-10 bytes is still pending. Cross-target compilation is compiler/type/ABI-surface evidence only and does not qualify native Job Object, registered-wait, libproc, kqueue, or wrapper runtime behavior.
