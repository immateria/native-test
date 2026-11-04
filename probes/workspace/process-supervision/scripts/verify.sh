#!/bin/sh
set -eu

CRYSTAL=${CRYSTAL:-crystal}
HANDLE_SRC=${HANDLE_SRC:-../process-handle/src}
DEFAULT_CRYSTAL_PATH=$($CRYSTAL env CRYSTAL_PATH)
SOURCE_PATH="$(pwd)/src:$HANDLE_SRC:$DEFAULT_CRYSTAL_PATH"
PROBE=$(mktemp "${TMPDIR:-/tmp}/process-supervision-consumer.XXXXXX.cr")
trap 'rm -f "$PROBE"' EXIT HUP INT TERM

"$CRYSTAL" tool format --check src spec
CRYSTAL_PATH="$SOURCE_PATH" "$CRYSTAL" spec --no-color
printf '%s\n' 'require "process-supervision"' 'puts ProcessSupervision::VERSION' > "$PROBE"
CRYSTAL_PATH="$SOURCE_PATH" "$CRYSTAL" run --no-color "$PROBE"
