#!/bin/sh
# Spike kernel build: base config + pocket fragment → spike/bin/vmlinux.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
ver=6.18.56
src=$HOME/.cache/pocket-dev/kernel/linux-$ver.tar.xz
build=$here/build
mkdir -p "$build"
[ -d "$build/linux-$ver" ] || tar -C "$build" -xf "$src"
cd "$build/linux-$ver"
cp "$here/base-x86_64.config" .config
./scripts/kconfig/merge_config.sh -m .config "$here/pocket.config" >/dev/null
make olddefconfig >/dev/null
export KBUILD_BUILD_TIMESTAMP='2026-01-01 00:00:00 UTC' KBUILD_BUILD_USER=pocket KBUILD_BUILD_HOST=pocket
make -j"$(nproc)" vmlinux >/dev/null
cp vmlinux "$here/../bin/vmlinux"
for o in $(grep -E '^(# )?CONFIG_' "$here/pocket.config" | sed -E 's/^# (CONFIG_[A-Z0-9_]+) is not set/\1=n/' ); do
  k=${o%%=*}; v=${o#*=}
  got=$(grep -E "^$k=|^# $k is not set" .config | sed -E "s/^# $k is not set/n/; s/^$k=//")
  [ "${got:-n}" = "$v" ] || echo "WARN $k want $v got ${got:-unset}"
done
