#!/usr/bin/env bash
# Lab keys for dev.andrix.usr. Run on the build machine. Does not commit.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/keys"
mkdir -p "$dir"

if ! command -v openssl >/dev/null; then
  echo "FAIL: openssl required" >&2
  exit 1
fi

avbtool_bin=${AVBTOOL:-}
if [[ -z "$avbtool_bin" ]]; then
  avbtool_bin=$(command -v avbtool || true)
fi
if [[ -z "$avbtool_bin" || ! -x "$avbtool_bin" ]]; then
  echo "FAIL: avbtool required; set AVBTOOL to its absolute executable path" >&2
  exit 1
fi

outputs=(
  dev.andrix.usr.pem
  dev.andrix.usr.avbpubkey
  dev.andrix.usr.x509.pem
  dev.andrix.usr.pk8
)
for output in "${outputs[@]}"; do
  if [[ -e "$dir/$output" ]]; then
    echo "FAIL: refusing to overwrite $dir/$output" >&2
    exit 1
  fi
done

work=$(mktemp -d "$dir/.keygen.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

openssl genrsa -out "$work/dev.andrix.usr.pem" 4096
"$avbtool_bin" extract_public_key \
  --key "$work/dev.andrix.usr.pem" \
  --output "$work/dev.andrix.usr.avbpubkey"

# APK container cert (test/lab). Distinct from the AVB payload key.
openssl req -new -x509 -newkey rsa:4096 \
  -keyout "$work/dev.andrix.usr.container.pem" \
  -out "$work/dev.andrix.usr.x509.pem" \
  -days 10000 \
  -nodes \
  -subj "/CN=Andrix dev.andrix.usr/"
openssl pkcs8 -topk8 -outform DER \
  -in "$work/dev.andrix.usr.container.pem" \
  -out "$work/dev.andrix.usr.pk8" \
  -nocrypt

install -m 0600 "$work/dev.andrix.usr.pem" "$dir/dev.andrix.usr.pem"
install -m 0600 "$work/dev.andrix.usr.pk8" "$dir/dev.andrix.usr.pk8"
install -m 0644 "$work/dev.andrix.usr.avbpubkey" "$dir/dev.andrix.usr.avbpubkey"
install -m 0644 "$work/dev.andrix.usr.x509.pem" "$dir/dev.andrix.usr.x509.pem"

# android_app_certificate expects certificate: "dev.andrix.usr" beside this Android.bp.
echo "wrote $dir (gitignored private material)"
