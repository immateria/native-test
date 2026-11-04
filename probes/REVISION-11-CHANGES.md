# Revision 11 — native result integrity

The production source and 889 behavioral case identities are identical to revision 10. Checkpoint 0008 remains the source authority.

**Root cause.** The previous wrappers validated input source bytes but treated the probe executable's zero exit code as sufficient evidence. The executable's own summary counts only cases it executed; it has no independent inventory to detect missing cases. An accidental early return or omitted `test(...)` call could therefore create a green but incomplete native handback.

**Changes.**

- Add a dependency-free Python 3 validator for Windows, macOS and macOS C/SDK JSONL results. The checker derives literal expected names from `COVERAGE.md` and enforces all names exactly once, recognized schema/platform/checkpoint, no unexpected non-informational cases, no failed/skipped cases, and coherent final Crystal summaries.
- Add independent PowerShell 5.1-native Windows result admission with the same behavioral closure conditions; no new Windows runtime dependency.
- Integrate the checks with both run wrappers. A validation failure sets a nonzero exit and saves its diagnostics into the ordinary handback archive.
- Add ten deterministic regression tests for the validator, including summary manipulation, missing cases, duplicates, skips and wrong source checkpoint.

**Limitations.** Native PowerShell execution and Windows/macOS process behavior remain pending. The Python validator is independently tested on Linux; the PowerShell implementation still needs native syntax/runtime validation. The coverage ledger and manifest are packaged together; a deliberately malicious party who can replace both could forge them, so this is accidental-integrity validation, not a signed attestation.
