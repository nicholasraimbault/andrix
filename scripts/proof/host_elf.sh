#!/usr/bin/env bash
# Host-side Andrix ELF gate. Fail closed.
set -euo pipefail

elf=${1:-}

if [[ -z "$elf" || ! -f "$elf" ]]; then
  echo "FAIL: no ELF at '${elf:-<missing>}'" >&2
  exit 1
fi

if ! command -v readelf >/dev/null; then
  echo "FAIL: readelf not found" >&2
  exit 1
fi

machine=$(readelf -hW "$elf" | awk -F: '/Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }')
if [[ "$machine" != "AArch64" ]]; then
  echo "FAIL: ELF machine is '${machine:-empty}', want AArch64" >&2
  exit 1
fi

interp=$(readelf -lW "$elf" | awk '/Requesting program interpreter/ { gsub(/[\[\]]/, "", $NF); print $NF }')
if [[ -z "$interp" ]]; then
  interp=$(readelf -p .interp "$elf" 2>/dev/null | awk '/linker/ { print $NF; exit }')
fi

if [[ "$interp" != "/system/bin/linker64" ]]; then
  echo "FAIL: INTERP is '${interp:-empty}', want /system/bin/linker64" >&2
  exit 1
fi

needed=$(readelf -d "$elf" | awk '/NEEDED/ { gsub(/[\[\]]/, "", $NF); print $NF }')
echo "$needed" | grep -qx 'libc.so' || {
  echo "FAIL: NEEDED missing libc.so (Bionic). Got:" >&2
  echo "$needed" >&2
  exit 1
}
if echo "$needed" | grep -Eq 'libc\.so\.6|ld-linux|ld-musl'; then
  echo "FAIL: foreign libc in NEEDED:" >&2
  echo "$needed" >&2
  exit 1
fi
if echo "$interp" | grep -Eq 'ld-linux|ld-musl'; then
  echo "FAIL: foreign INTERP $interp" >&2
  exit 1
fi

# readelf -lW keeps Offset…Align on one line; Align is last field.
min_align=
while read -r align; do
  val=$((align))
  if [[ -z "$min_align" || "$val" -lt "$min_align" ]]; then
    min_align=$val
  fi
done < <(readelf -lW "$elf" | awk '/^  LOAD/ { print $NF }')
if [[ -z "$min_align" || "$min_align" -lt 16384 ]]; then
  echo "FAIL: LOAD Align ${min_align:-missing} < 0x4000" >&2
  exit 1
fi

digest=$(sha256sum "$elf" | awk '{ print $1 }')
echo "PASS: $elf MACHINE=$machine INTERP=$interp Bionic libc.so LOAD Align ok SHA256=$digest"
