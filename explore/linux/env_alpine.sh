#!/bin/sh
# Inside an Alpine (musl, busybox) container: build the C probes against musl and run them with env_run.sh.
#   env_alpine.sh <scenario name>
NAME=$1
OUT=${OUT:-explore-out}
mkdir -p "$OUT" "$OUT/build-musl"
apk add --no-cache build-base linux-headers bash > "$OUT/env-$NAME-apk.txt" 2>&1
for p in linux/cgroup_env posix/spawn_attrs linux/spawn_cgroup; do
  b=$(basename "$p")
  cc -O1 -Wall -Wextra -o "$OUT/build-musl/$b" "explore/$p.c" > "$OUT/env-$NAME-build-$b.txt" 2>&1
done
{ echo "musl: $(ldd --version 2>&1 | head -1)"; echo "sh -> $(readlink -f /bin/sh)"; busybox 2>&1 | head -1; } > "$OUT/env-$NAME-userland.txt"
exec sh explore/linux/env_run.sh "$NAME" "$OUT/build-musl"
