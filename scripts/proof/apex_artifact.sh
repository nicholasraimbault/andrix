#!/usr/bin/env bash
# Verify a built APEX and extract the exact andrix-hello device oracle.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
apex=${1:-}
artifact_out=${ANDRIX_ARTIFACT_OUT:-"$root/out/apex-artifact"}
payload_key=${ANDRIX_APEX_PAYLOAD_KEY:-"$root/keys/dev.andrix.usr.pem"}
public_key=${ANDRIX_APEX_PUBLIC_KEY:-"$root/keys/dev.andrix.usr.avbpubkey"}
container_cert=${ANDRIX_APEX_CONTAINER_CERT:-"$root/keys/dev.andrix.usr.x509.pem"}

if [[ ! -f "$apex" ]]; then
  echo "FAIL: usage: $0 /path/to/dev.andrix.usr.apex" >&2
  exit 1
fi
if [[ ! -f "$payload_key" || ! -f "$public_key" || ! -f "$container_cert" ]]; then
  echo "FAIL: Andrix signing material not found under keys/" >&2
  exit 1
fi
if [[ -e "$artifact_out" ]]; then
  echo "FAIL: refusing to overwrite $artifact_out" >&2
  exit 1
fi

host_out=${ANDROID_HOST_OUT:-}
deapexer_bin=${DEAPEXER:-${host_out:+$host_out/bin/deapexer}}
avbtool_bin=${AVBTOOL:-${host_out:+$host_out/bin/avbtool}}
apksigner_bin=${APKSIGNER:-${host_out:+$host_out/bin/apksigner}}
for pair in \
  "deapexer:$deapexer_bin" \
  "avbtool:$avbtool_bin" \
  "apksigner:$apksigner_bin"; do
  name=${pair%%:*}
  path=${pair#*:}
  if [[ -z "$path" || ! -x "$path" ]]; then
    echo "FAIL: $name not found; lunch the Android tree or set its uppercase path variable" >&2
    exit 1
  fi
done
for command in cmp openssl realpath sha256sum unzip; do
  if ! command -v "$command" >/dev/null; then
    echo "FAIL: $command not found" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$artifact_out")"
work=$(mktemp -d "$(dirname "$artifact_out")/.apex-artifact.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

if ! apksigner_output=$("$apksigner_bin" verify --verbose --print-certs "$apex" 2>&1); then
  echo "$apksigner_output" >&2
  exit 1
fi
echo "$apksigner_output"
actual_cert_sha=$(awk -F': ' '/Signer #1 certificate SHA-256 digest:/ { print $2; exit }' <<<"$apksigner_output" | tr '[:upper:]' '[:lower:]')
expected_cert_sha=$(openssl x509 -in "$container_cert" -outform DER | sha256sum | awk '{ print $1 }')
if [[ -z "$actual_cert_sha" || "$actual_cert_sha" != "$expected_cert_sha" ]]; then
  echo "FAIL: APEX container certificate differs from the Andrix certificate" >&2
  exit 1
fi
unzip -p "$apex" apex_payload.img >"$work/apex_payload.img"
unzip -p "$apex" apex_pubkey >"$work/apex_pubkey"
if ! cmp -s "$work/apex_pubkey" "$public_key"; then
  echo "FAIL: embedded apex_pubkey differs from the Andrix public key" >&2
  exit 1
fi
"$avbtool_bin" verify_image \
  --image "$work/apex_payload.img" \
  --key "$payload_key"
"$deapexer_bin" extract "$apex" "$work/payload"
"$root/scripts/proof/host_elf.sh" "$work/payload/bin/andrix-hello"

apex_path=$(realpath "$apex")
apex_sha=$(sha256sum "$apex" | awk '{ print $1 }')
andrix_hello_sha=$(sha256sum "$work/payload/bin/andrix-hello" | awk '{ print $1 }')
mv "$work" "$artifact_out"
trap - EXIT

echo "PASS: verified both APEX signatures and extracted Bionic andrix-hello"
echo "APEX=$apex_path"
echo "APEX_SHA256=$apex_sha"
echo "ANDRIX_HELLO=$artifact_out/payload/bin/andrix-hello"
echo "ANDRIX_HELLO_SHA256=$andrix_hello_sha"
