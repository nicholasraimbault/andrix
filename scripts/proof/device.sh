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
for command in adb cmp python3 sha256sum; do
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

rkp_host=$(adb shell getprop remote_provisioning.hostname | tr -d '\r')
rkp_only=$(adb shell getprop remote_provisioning.tee.rkp_only | tr -d '\r')
if [[ -n "$rkp_host" || "$rkp_only" != "false" ]]; then
  echo "FAIL: Cuttlefish remote provisioning is not configured for local keys only" >&2
  exit 1
fi

if ! adb pull /apex/apex-info-list.xml "$tmp/apex-info-list.xml" >/dev/null 2>&1; then
  echo "FAIL: cannot pull /apex/apex-info-list.xml" >&2
  exit 1
fi
preinstalled_path=$(python3 - "$tmp/apex-info-list.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

try:
    root = ET.parse(sys.argv[1]).getroot()
except (OSError, ET.ParseError) as exc:
    sys.exit(f"FAIL: cannot parse apex-info-list.xml: {exc}")
if root.tag != "apex-info-list":
    sys.exit("FAIL: unexpected apex-info-list.xml root")
active = [row for row in root.findall("apex-info")
          if row.get("moduleName") == "dev.andrix.usr"
          and row.get("isActive") == "true"]
if len(active) != 1:
    sys.exit(f"FAIL: expected exactly one active dev.andrix.usr APEX entry, found {len(active)}")
row = active[0]
if row.get("isFactory") != "true":
    sys.exit("FAIL: dev.andrix.usr is not an active factory APEX")
path = row.get("preinstalledModulePath", "")
if not path.strip():
    sys.exit("FAIL: active dev.andrix.usr has no preinstalledModulePath")
# Do not let command substitution silently trim a path containing newlines.
if "\n" in path or "\r" in path:
    sys.exit("FAIL: invalid preinstalledModulePath")
print(path)
PY
)
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
  # Read these fixed payload paths in the shell context: adbd's sync service
  # (adb pull) need not be allowed to read andrix_exec files. Keep bytes raw.
  # exec-out need not forward cat's exit status. Append a failure marker so
  # even a complete payload followed by a read failure fails the hash check.
  if ! adb exec-out "cat $remote || { printf '\\nFAIL: payload read failed\\n'; exit 1; }" >"$localf"; then
    echo "FAIL: cannot read $remote via adb exec-out" >&2
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

printf 'andrix\n' >"$tmp/expected-output"
for remote in /usr/bin/andrix-hello /apex/dev.andrix.usr/bin/andrix-hello; do
  output="$tmp/${remote//\//_}.stdout"
  # exec-out need not forward the remote exit status. Append a failure marker
  # on nonzero exit so even otherwise-correct stdout cannot pass the comparison.
  if ! adb exec-out "$remote || { printf '\\nFAIL: andrix-hello exited nonzero\\n'; exit 1; }" >"$output"; then
    echo "FAIL: adb exec-out failed for $remote" >&2
    exit 1
  fi
  if ! cmp -s "$tmp/expected-output" "$output"; then
    echo "FAIL: exact andrix-hello output mismatch for $remote (want bytes andrix\\n)" >&2
    exit 1
  fi
done

etc_target=$(adb shell readlink /etc | tr -d '\r')
if [[ "$etc_target" != "/system/etc" ]]; then
  echo "FAIL: /etc is not Android's /system/etc symlink: '$etc_target'" >&2
  exit 1
fi
# An explicit response distinguishes absence from an adb/probe failure.
if ! etc_identity=$(adb shell 'if test -e /etc/debian_version; then echo debian; elif test -e /etc/os-release; then echo os-release; else echo absent; fi' | tr -d '\r'); then
  echo "FAIL: cannot inspect /etc distro identity" >&2
  exit 1
fi
case "$etc_identity" in
  debian)
    echo "FAIL: /etc contains a foreign distro identity (debian_version)" >&2
    exit 1
    ;;
  os-release)
    if ! adb pull /etc/os-release "$tmp/os-release" >/dev/null 2>&1; then
      echo "FAIL: cannot pull /etc/os-release" >&2
      exit 1
    fi
    # Parse only ID; never source device-controlled shell text on the host.
    python3 - "$tmp/os-release" <<'PY'
import shlex
import sys

ids = []
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        for line in source:
            key, separator, value = line.strip().partition("=")
            if key == "ID":
                tokens = shlex.split(value, comments=True)
                if not separator or len(tokens) != 1:
                    raise ValueError("invalid ID assignment")
                ids.append(tokens[0])
except (OSError, UnicodeError, ValueError) as exc:
    sys.exit(f"FAIL: cannot parse /etc/os-release: {exc}")
if ids != ["android"]:
    sys.exit("FAIL: /etc/os-release must contain exactly one ID=android")
PY
    ;;
  absent) ;;
  *)
    echo "FAIL: unexpected /etc identity probe response: '$etc_identity'" >&2
    exit 1
    ;;
esac

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
if ! adb logcat -b all -d >"$tmp/logcat"; then
  echo "FAIL: cannot retrieve device logs" >&2
  exit 1
fi
if grep -E 'avc:.*(andrix|/usr|dev\.andrix\.usr)' "$tmp/logcat" >"$tmp/avc"; then
  echo "FAIL: relevant SELinux denials found" >&2
  cat "$tmp/avc" >&2
  exit 1
elif [[ "$?" -ne 1 ]]; then
  echo "FAIL: cannot search device logs for relevant SELinux denials" >&2
  exit 1
fi

echo "PASS: fingerprint=$actual_fingerprint"
echo "PASS: product ABI list is exactly arm64-v8a with no 32-bit ABI"
echo "PASS: remote provisioning has no server and is not required for local keys"
echo "PASS: APEX=$preinstalled_path SHA256=$device_apex_sha active factory"
echo "PASS: andrix-hello SHA256=$expected_elf_sha same mounted inode=$usr_stat exact output=andrix"
echo "PASS: /usr is a read-only mount; /etc is Android; SELinux enforcing"
echo "INFO: kernel page size=$page_size"
