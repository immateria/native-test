# Native qualification status — revision 10

Revision 10 is **native runtime pending**. Its matrix is **459 Windows Crystal + 385 macOS Crystal + 45 independent macOS C/SDK = 889 checks**.

Revision 7 supplied a complete macOS diagnostic run; revision 8 corrected the zombie fixture but was superseded before a new native handback. No valid revision-7/8/9 Windows process handback exists, and revision 9 itself did not receive a complete native closure receipt before this source hardening pass.

Checkpoint 0008 changes two production behaviors:

1. block-scoped `ProcessHandle.open` preserves a caller exception when owner cleanup also fails;
2. Linux pidfd signal access-denied errors retain the actual target PID through the low-level diagnostic.

The first change has a new Windows native fault-injection case, `r10_block_scoped_open_preserves_primary_error`, so fresh Windows execution against the exact revision-10 bytes is mandatory before promoting that lane.

The macOS production backend behavior is unchanged by checkpoint 0008, but revision 10 changes probe metadata and the native handoff admission path. Fresh macOS execution is therefore also required to qualify the complete revision-10 kit and its manifest-preflight wrapper.

Linux-hosted specs and Windows/macOS cross-target compiles are recorded in `VERIFICATION.md`; neither substitutes for native execution.
