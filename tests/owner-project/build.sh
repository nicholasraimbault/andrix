#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Full serial rebuild of this fixture; not a general-purpose build/package manager.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p build
work=$(mktemp -d build/.work.XXXXXX)
trap 'rm -rf "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for unit in parse summary; do
    c++ @flags.rsp -MMD -MF "$work/$unit.d" \
        -c "src/$unit.cpp" -o "$work/$unit.o"
done
ar rcs "$work/libstats.a" "$work/parse.o" "$work/summary.o"
ranlib "$work/libstats.a"
c++ @flags.rsp src/main.cpp "$work/libstats.a" -o "$work/stats"
# Keep the last working executable if compilation, linking or this check fails.
result=$("$work/stats" 2 4 6)
case "$result" in
    'v1 count=3 mean=4 rms=4.32049'|'v2 count=3 mean=4 rms=4.32049') ;;
    *) echo "unexpected smoke result: $result" >&2; exit 1 ;;
esac
mv "$work/stats" build/stats
printf '%s\n' "BUILD_OK $result"
