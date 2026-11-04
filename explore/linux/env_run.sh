#!/bin/sh
# Runs the environment probes inside whatever environment this shell is in (host, root, a systemd unit, a container).
#   env_run.sh <scenario name> [directory holding the built probes]      OUT=<output directory> to move the output
# cgroup_env says what is possible and picks a directory in which a cgroup can be created and a child cloned into; the
# probes that need a usable cgroup (spawn_cgroup, kit_linux) run there. When there is none, kit_linux is pointed at the
# process's own (refusing) cgroup so the shard's classification of the refusal is recorded.
NAME=$1
BIN=${2:-explore-out/build}
OUT=${OUT:-explore-out}
P="$OUT/env-$NAME"
T=""
command -v timeout > /dev/null 2>&1 && T="timeout 240"
mkdir -p "$OUT"
rm -f "$P.dir" "$P.own"
$T "$BIN/cgroup_env" --emit-dir "$P.dir" --emit-own "$P.own" > "$P-cgroup_env.jsonl" 2> "$P-cgroup_env.err"
D=$(cat "$P.dir" 2> /dev/null)
OWN=$(cat "$P.own" 2> /dev/null)
if [ -x "$BIN/spawn_attrs" ]; then $T "$BIN/spawn_attrs" > "$P-spawn_attrs.jsonl" 2> "$P-spawn_attrs.err"; fi
if [ -n "$D" ] && [ -x "$BIN/spawn_cgroup" ]; then
  SPAWN_CGROUP_TRIALS=20 $T "$BIN/spawn_cgroup" "$D" > "$P-spawn_cgroup.jsonl" 2> "$P-spawn_cgroup.err"
fi
K=${D:-$OWN}
[ -z "$K" ] && K=/sys/fs/cgroup
if [ -x "$BIN/kit_linux" ]; then $T "$BIN/kit_linux" "$K" > "$P-kit_linux.jsonl" 2> "$P-kit_linux.err"; fi
echo "env_run $NAME: uid=$(id -u) usable='$D' own='$OWN' kit_linux_dir='$K'"
exit 0
