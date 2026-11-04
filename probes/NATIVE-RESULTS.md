# Native qualification status — revision 12

Revision 12 is **native runtime pending**. Its matrix remains **459 Windows Crystal + 385 macOS Crystal + 45 independent macOS C/SDK = 889 checks**.

Revision 7 supplied a complete macOS diagnostic run; later revisions corrected and broadened the native suite before a new complete handback. There is no native revision-12 Windows or macOS receipt yet.

Checkpoint 0009 retains the checkpoint-0008 cleanup/diagnostic fixes and adds one Linux-only production correction: public Linux `open`, `observe`, and `lookup` reject PIDs outside signed native `pid_t` range before conversion or `/proc` lookup.

The Windows/macOS production backend behavior is otherwise unchanged, but revision 12 changes checkpoint metadata and the native handoff admission path. Fresh execution of these exact bytes is therefore required for both native lanes.

Revision 12 also repairs the revision-11 C/SDK result validator: the independent C probe emits a final summary and the validator now checks that summary instead of rejecting it. Both wrappers additionally revalidate the admitted manifest after execution.

Linux-hosted specs and Windows/macOS cross-target compiles are recorded in `VERIFICATION.md`; neither substitutes for native execution.
