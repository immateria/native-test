# Revision 10 changes

Revision 10 is a focused hardening pass over checkpoint 0007 / probe revision 9. It does not broaden the public process-tree API. It fixes two production defects and strengthens the evidentiary boundary of the native probe handoff.

## 1. Block-scoped `ProcessHandle.open` now preserves the primary exception

The public block form previously used a plain `ensure handle.close`. If the caller raised and owner close also failed, the close exception replaced the caller's original exception.

A Linux reproduction deliberately invalidated the owned pidfd inside the block, then raised `"primary block failure"`. Before the fix, the observed exception was `ProcessHandle::Error::Native` from `close(pidfd)`. The root cause was cleanup precedence in the public wrapper, not a platform backend.

Checkpoint 0008 records the active exception before cleanup. When a primary exception exists, cleanup is best-effort/no-throw; when the block succeeds, a close failure still surfaces normally. Two native Linux specs cover both sides. A new Windows fault-helper case, `r10_block_scoped_open_preserves_primary_error`, exercises the same contract against a deliberately invalidated process HANDLE.

## 2. Linux pidfd access-denied diagnostics retain the real PID

`ProcessHandle::Linux::Native.send_signal` raised `AccessDenied` with a hard-coded PID `1`. The outer handle layer then wrapped that error with the actual target PID, producing diagnostics such as:

```text
process 1925: process 1: Operation not permitted
```

The native helper now receives the retained handle PID explicitly and constructs `AccessDenied` with that value. The redundant outer rewrap is removed. A root-owned child / unprivileged caller reproduction now reports only the actual target PID, for example:

```text
process 2336: Operation not permitted
```

A source-contract regression prevents reintroduction of the hard-coded PID or omission of the PID argument from the helper call.

## 3. Native handbacks are bound to the full kit manifest

Revision 9 recorded hashes for the top-level probe sources but did not verify the bundled workspace before compiling. A locally edited shard could therefore generate a native handback without an admission failure.

Revision 10 makes `MANIFEST.sha256` a pre-build gate on both native launchers. Every listed file must exist and match its packaged SHA-256. The manifest admitted by the launcher is copied into the result directory before handback packaging.

The launchers also reject redirected `.build` paths and remove/recreate an ordinary build directory before compilation, eliminating stale executable reuse across repeated runs.

The macOS launcher is also packaged executable (`0755`). Revision 9 carried mode `0644` while instructing users to invoke `./run-macos.sh`, which made a fresh Unix extraction fail before any probe logic ran.

## Compatibility and qualification status

`process-handle` is now 0.7.0; `process-supervision` remains 0.7.0. The public API shape is unchanged. The source still passes its Linux host suites on Crystal 1.21.0 and 1.21.1. Revision-10 Windows/macOS native runtime remains pending and must not be inferred from cross-target compilation.
