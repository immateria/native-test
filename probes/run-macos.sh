#!/bin/sh
# Run on a native Mac with Crystal 1.21.1+ and the Xcode Command Line Tools.
# The watchdog uses Python 3; no sudo or third-party Crystal shards required.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT" || exit 1
RUN="$ROOT/macos-probe-output"
BUILD="$ROOT/.build"
MANIFEST="$ROOT/MANIFEST.sha256"
# Refuse redirected output/build paths; never mix stale artifacts with a new run.
if [ -L "$RUN" ]; then
  echo "refusing symlinked result directory: $RUN" >&2
  exit 2
fi
if [ -d "$RUN" ]; then rm -rf -- "$RUN"; fi
mkdir -p "$RUN/child-artifacts"
{
  echo "probe=macos-0008-r10"
  echo "probe_revision=10"
  echo "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "os=$(uname -s)"
  echo "arch=$(uname -m)"
  echo "macos_version=$(sw_vers -productVersion 2>/dev/null || echo unavailable)"
  echo "darwin_version=$(uname -r)"
  echo "hw_ncpu=$(sysctl -n hw.ncpu 2>/dev/null || echo unavailable)"
  echo "hw_model=$(sysctl -n hw.model 2>/dev/null || echo unavailable)"
  echo "cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unavailable)"
  echo "crystal_compiler=$(command -v crystal || echo not-found)"
  crystal --version 2>&1 || :
  echo "source_sha256:"
  shasum -a 256 macos_process_probe.cr macos_abi_probe.c macos_zombie_holder.c 2>/dev/null || :
} > "$RUN/environment.txt"

package_handback() {
  if command -v zip >/dev/null 2>&1; then
    rm -f "$ROOT/macos-probe-handback.zip"
    (cd "$ROOT" && zip -qr macos-probe-handback.zip macos-probe-output)
    echo "Handback: $ROOT/macos-probe-handback.zip"
  else
    echo "zip unavailable: upload $RUN instead"
  fi
}
trap 'package_handback' EXIT

if [ ! -f "$MANIFEST" ]; then
  echo "missing kit manifest: $MANIFEST" > "$RUN/manifest-check.log"
  echo "manifest_check=fail" >> "$RUN/environment.txt"
  exit 3
fi
MANIFEST_SHA=$(shasum -a 256 "$MANIFEST" | awk '{print $1}')
echo "manifest_sha256=$MANIFEST_SHA" >> "$RUN/environment.txt"
if shasum -a 256 -c "$MANIFEST" > "$RUN/manifest-check.log" 2>&1; then
  echo "manifest_check=pass" >> "$RUN/environment.txt"
  cp "$MANIFEST" "$RUN/kit-manifest.sha256"
else
  echo "manifest_check=fail" >> "$RUN/environment.txt"
  exit 3
fi

if [ -L "$BUILD" ]; then
  echo "refusing symlinked build directory: $BUILD" >&2
  exit 3
fi
if [ -e "$BUILD" ] && [ ! -d "$BUILD" ]; then
  echo "refusing non-directory build path: $BUILD" >&2
  exit 3
fi
if [ -d "$BUILD" ]; then rm -rf -- "$BUILD"; fi
mkdir -p "$BUILD"

if ! command -v crystal >/dev/null 2>&1; then
  echo "Crystal compiler not on PATH" > "$RUN/build.log"
  exit 2
fi
ORIGINAL_PATH=$(crystal env CRYSTAL_PATH) || exit 2
CRYSTAL_PATH="$ROOT/workspace/process-supervision/src:$ROOT/workspace/process-handle/src:$ORIGINAL_PATH"
export CRYSTAL_PATH
crystal build --no-color "$ROOT/macos_process_probe.cr" -o "$BUILD/macos_process_probe" > "$RUN/build.log" 2>&1
BUILD_RC=$?
echo "crystal_build_exit=$BUILD_RC" >> "$RUN/environment.txt"
RUN_RC=$BUILD_RC
ZOMBIE_BUILD_RC=127
if command -v clang >/dev/null 2>&1; then
  clang -std=c11 -Wall -Wextra -Werror "$ROOT/macos_zombie_holder.c" -o "$BUILD/macos_zombie_holder" > "$RUN/zombie-helper-build.log" 2>&1
  ZOMBIE_BUILD_RC=$?
else
  echo "clang unavailable" > "$RUN/zombie-helper-build.log"
fi
echo "c_zombie_helper_build_exit=$ZOMBIE_BUILD_RC" >> "$RUN/environment.txt"
if [ "$ZOMBIE_BUILD_RC" -ne 0 ]; then RUN_RC=1; fi
if [ "$BUILD_RC" -eq 0 ] && [ "$ZOMBIE_BUILD_RC" -eq 0 ]; then
  if command -v python3 >/dev/null 2>&1; then
    PROCESS_PROBE_WORKDIR="$RUN/child-artifacts"
    PROCESS_ZOMBIE_HELPER="$BUILD/macos_zombie_holder"
    export PROCESS_PROBE_WORKDIR PROCESS_ZOMBIE_HELPER
    python3 - "$BUILD/macos_process_probe" "$RUN" <<'PY'
import pathlib, subprocess, sys
exe, dest = sys.argv[1:]
p = pathlib.Path(dest)
with (p / "results.jsonl").open("wb") as out, (p / "stderr.log").open("wb") as err:
    try:
        completed = subprocess.run([exe], stdout=out, stderr=err, timeout=1800)
        code = completed.returncode
        state = "exited"
    except subprocess.TimeoutExpired:
        state, code = "timeout-1800s", 124
    except OSError as exc:
        state, code = "spawn-error:" + str(exc), 125
(p / "run-status.txt").write_text(f"run_state={state}\nexit_code={code}\n", encoding="utf-8")
sys.exit(0 if code == 0 else 1)
PY
    RUN_RC=$?
  else
    RUN_RC=125
    echo "python3 unavailable; run the binary directly with a manual timeout" > "$RUN/run-status.txt"
    echo "missing-python3" > "$RUN/stderr.log"
  fi
fi
if command -v clang >/dev/null 2>&1; then
  clang -std=c11 -Wall -Wextra -Werror "$ROOT/macos_abi_probe.c" -o "$BUILD/macos_abi_probe" > "$RUN/abi-build.log" 2>&1
  ABI_BUILD_RC=$?
  if [ "$ABI_BUILD_RC" -ne 0 ]; then RUN_RC=1; fi
  echo "c_abi_build_exit=$ABI_BUILD_RC" >> "$RUN/environment.txt"
  if [ "$ABI_BUILD_RC" -eq 0 ]; then
    "$BUILD/macos_abi_probe" > "$RUN/abi-results.jsonl" 2> "$RUN/abi-stderr.log"
    ABI_RUN_RC=$?
    echo "c_abi_run_exit=$ABI_RUN_RC" >> "$RUN/environment.txt"
    if [ "$ABI_RUN_RC" -ne 0 ]; then RUN_RC=1; fi
  fi
else
  echo "clang unavailable" > "$RUN/abi-build.log"
fi
exit "$RUN_RC"
