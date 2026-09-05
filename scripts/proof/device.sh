#!/usr/bin/env bash
# Operator runs this against a booted Andrix image. Fail closed on provenance.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
expected_apex=${ANDRIX_EXPECTED_APEX:-}
expected_elf=${ANDRIX_EXPECTED_PROOF_ELF:-}
expected_fingerprint=${ANDRIX_EXPECTED_FINGERPRINT:-}

if [[ ! -f "$expected_apex" ]]; then
  echo "FAIL: set ANDRIX_EXPECTED_APEX to the APEX from the built image" >&2
  exit 1
fi
if [[ ! -f "$expected_elf" ]]; then
  echo "FAIL: set ANDRIX_EXPECTED_PROOF_ELF to bin/andrix-hello extracted from that APEX" >&2
  exit 1
fi
if [[ -z "$expected_fingerprint" ]]; then
  echo "FAIL: set ANDRIX_EXPECTED_FINGERPRINT to the built image fingerprint" >&2
  exit 1
fi
for command in adb sha256sum; do
  if ! command -v "$command" >/dev/null; then
    echo "FAIL: $command not found" >&2
    exit 1
  fi
done

"$root/scripts/proof/host_elf.sh" "$expected_elf"
expected_apex_sha=$(sha256sum "$expected_apex" | awk '{ print $1 }')
expected_elf_sha=$(sha256sum "$expected_elf" | awk '{ print $1 }')

if ! adb get-state >/dev/null 2>&1; then
  echo "FAIL: exactly one authorized adb device is required" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

actual_fingerprint=$(adb shell getprop ro.build.fingerprint | tr -d '\r')
if [[ "$actual_fingerprint" != "$expected_fingerprint" ]]; then
  echo "FAIL: device fingerprint does not match the built image" >&2
  echo "expected: $expected_fingerprint" >&2
  echo "actual:   $actual_fingerprint" >&2
  exit 1
fi

actual_abilist=$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')
actual_abilist64=$(adb shell getprop ro.product.cpu.abilist64 | tr -d '\r')
actual_abilist32=$(adb shell getprop ro.product.cpu.abilist32 | tr -d '\r')
if [[ "$actual_abilist" != "arm64-v8a" || "$actual_abilist64" != "arm64-v8a" || -n "$actual_abilist32" ]]; then
  echo "FAIL: booted product is not ARM64-only" >&2
  echo "ro.product.cpu.abilist='$actual_abilist'" >&2
  echo "ro.product.cpu.abilist64='$actual_abilist64'" >&2
  echo "ro.product.cpu.abilist32='$actual_abilist32'" >&2
  exit 1
fi

if ! adb pull /apex/apex-info-list.xml "$tmp/apex-info-list.xml" >/dev/null 2>&1; then
  echo "FAIL: cannot pull /apex/apex-info-list.xml" >&2
  exit 1
fi
apex_entry=$(grep 'moduleName="dev.andrix.usr"' "$tmp/apex-info-list.xml" || true)
if [[ -z "$apex_entry" || "$apex_entry" != *'isActive="true"'* || "$apex_entry" != *'isFactory="true"'* ]]; then
  echo "FAIL: dev.andrix.usr is not an active factory APEX" >&2
  echo "${apex_entry:-<no apex-info entry>}" >&2
  exit 1
fi
preinstalled_path=$(sed -n 's/.*preinstalledModulePath="\([^"]*\)".*/\1/p' <<<"$apex_entry")
if [[ -z "$preinstalled_path" ]]; then
  echo "FAIL: dev.andrix.usr has no preinstalledModulePath" >&2
  exit 1
fi
if ! adb pull "$preinstalled_path" "$tmp/device.apex" >/dev/null 2>&1; then
  echo "FAIL: cannot pull factory APEX at $preinstalled_path" >&2
  exit 1
fi
device_apex_sha=$(sha256sum "$tmp/device.apex" | awk '{ print $1 }')
if [[ "$device_apex_sha" != "$expected_apex_sha" ]]; then
  echo "FAIL: factory APEX differs from the built artifact" >&2
  exit 1
fi

for remote in /usr/bin/andrix-hello /apex/dev.andrix.usr/bin/andrix-hello; do
  localf="$tmp/$(tr / _ <<<"$remote")"
  if ! adb pull "$remote" "$localf" >/dev/null 2>&1; then
    echo "FAIL: cannot pull $remote" >&2
    exit 1
  fi
  "$root/scripts/proof/host_elf.sh" "$localf"
  actual_sha=$(sha256sum "$localf" | awk '{ print $1 }')
  if [[ "$actual_sha" != "$expected_elf_sha" ]]; then
    echo "FAIL: $remote differs from bin/andrix-hello in the built APEX" >&2
    exit 1
  fi
done

usr_stat=$(adb shell toybox stat -c '%d:%i' /usr/bin/andrix-hello | tr -d '\r')
apex_stat=$(adb shell toybox stat -c '%d:%i' /apex/dev.andrix.usr/bin/andrix-hello | tr -d '\r')
if [[ -z "$usr_stat" || "$usr_stat" != "$apex_stat" ]]; then
  echo "FAIL: /usr and canonical APEX paths are not the same mounted file" >&2
  exit 1
fi

mountinfo=$(adb shell cat /proc/self/mountinfo | tr -d '\r')
usr_mount=$(awk '$5 == "/usr" { print; exit }' <<<"$mountinfo")
if [[ -z "$usr_mount" ]]; then
  echo "FAIL: /usr is not a mountpoint" >&2
  exit 1
fi
mount_options=$(awk '{ print $6 }' <<<"$usr_mount")
if [[ ",$mount_options," != *,ro,* ]]; then
  echo "FAIL: /usr mount is not read-only: $usr_mount" >&2
  exit 1
fi

usr_output=$(adb shell /usr/bin/andrix-hello | tr -d '\r')
apex_output=$(adb shell /apex/dev.andrix.usr/bin/andrix-hello | tr -d '\r')
if [[ "$usr_output" != "andrix" || "$apex_output" != "andrix" ]]; then
  echo "FAIL: exact andrix-hello output mismatch: usr='$usr_output' apex='$apex_output'" >&2
  exit 1
fi

etc_target=$(adb shell readlink /etc | tr -d '\r')
if [[ "$etc_target" != "/system/etc" ]]; then
  echo "FAIL: /etc is not Android's /system/etc symlink: '$etc_target'" >&2
  exit 1
fi
if adb shell 'test -e /etc/debian_version -o -e /etc/os-release'; then
  echo "FAIL: /etc contains a foreign distro identity" >&2
  exit 1
fi

enforcing=$(adb shell getenforce | tr -d '\r')
if [[ "$enforcing" != "Enforcing" ]]; then
  echo "FAIL: SELinux is '$enforcing', want Enforcing" >&2
  exit 1
fi
page_size=$(adb shell getconf PAGESIZE 2>/dev/null | tr -d '\r')
if [[ ! "$page_size" =~ ^[0-9]+$ ]]; then
  echo "FAIL: could not record kernel page size" >&2
  exit 1
fi
avc=$(adb logcat -b all -d 2>/dev/null | grep -E 'avc:.*(andrix|/usr|dev\.andrix\.usr)' || true)
if [[ -n "$avc" ]]; then
  echo "FAIL: relevant SELinux denials found" >&2
  echo "$avc" >&2
  exit 1
fi

echo "PASS: fingerprint=$actual_fingerprint"
echo "PASS: product ABI list is exactly arm64-v8a with no 32-bit ABI"
echo "PASS: APEX=$preinstalled_path SHA256=$device_apex_sha active factory"
echo "PASS: andrix-hello SHA256=$expected_elf_sha same mounted inode=$usr_stat exact output=andrix"
echo "PASS: /usr is a read-only mount; /etc is Android; SELinux enforcing"
echo "INFO: kernel page size=$page_size"
