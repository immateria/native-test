#!/bin/sh
# Build and run every POSIX exploration probe, writing one JSON-lines file per probe.
# usage: run.sh <output dir>      (macOS and Linux; never fails the job - results are data, not assertions)
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: run.sh <output dir>}
mkdir -p "$out" "$out/build"
os=$(uname -s)
arch=$(uname -m)
tag="posix-$os-$arch"
libs=""
[ "$os" = Linux ] && libs="-lutil"

for p in orphan_pgrp supervisor_death rusage rlimit stopcont_chld sigstate spawn_errors pty pipes pid_reuse signals_threads scale crash_latency tree_enum; do
  l=""
  [ "$p" = pty ] && l="$libs"
  [ "$p" = signals_threads ] && l="-pthread"
  if cc -O1 -Wall -Wextra -o "$out/build/$p" "$here/$p.c" $l > "$out/$tag-$p.build.txt" 2>&1; then
    "$out/build/$p" > "$out/$tag-$p.jsonl" 2> "$out/$tag-$p.err"
    rc=$?
    echo "$p: exit=$rc lines=$(wc -l < "$out/$tag-$p.jsonl" | tr -d ' ')"
  else
    echo "$p: BUILD FAILED (see $tag-$p.build.txt)"
    tail -n 20 "$out/$tag-$p.build.txt"
  fi
done

if command -v crystal > /dev/null 2>&1 && [ -x "$out/build/sigstate" ]; then
  if crystal build --no-color "$here/crystal_spawn.cr" -o "$out/build/crystal_spawn" > "$out/$tag-crystal_spawn.build.txt" 2>&1; then
    "$out/build/crystal_spawn" "$out/build/sigstate" > "$out/$tag-crystal_spawn.jsonl" 2> "$out/$tag-crystal_spawn.err"
    echo "crystal_spawn: exit=$? lines=$(wc -l < "$out/$tag-crystal_spawn.jsonl" | tr -d ' ')"
  else
    echo "crystal_spawn: BUILD FAILED"
    tail -n 20 "$out/$tag-crystal_spawn.build.txt"
  fi
fi
exit 0
