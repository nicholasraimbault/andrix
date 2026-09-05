#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify/stage five public CT files without network access or trust changes."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

FILES = ("log_list.pub", "v2/log_list.json", "v2/log_list.sig",
         "v3/log_list.ctfb", "v3/log_list.sig")
MAX_FILE = 1024 * 1024
MAX_AGE_MS = 70 * 24 * 60 * 60 * 1000  # Pinned Conscrypt PolicyImpl.


def read_public(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError("Expected a regular public input file")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if not data or len(data) > MAX_FILE or b"PRIVATE KEY" in data:
        raise ValueError("Invalid public input size/type")
    return data


def decode(data):
    return base64.b64decode(b"".join(data.split()), validate=True)


def verify(source, allowed_keys, now_ms=None):
    source = source.resolve()
    files = {}
    for name in FILES:
        path = source / name
        if not path.resolve().is_relative_to(source):
            raise ValueError("Input escapes source directory")
        files[name] = read_public(path)
    allowed = read_public(allowed_keys)
    blocks = re.findall(rb"-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----", allowed, re.S)
    if not blocks:
        raise ValueError("No allowed public keys found")
    der = decode(files["log_list.pub"])
    if der not in {decode(block) for block in blocks}:
        raise ValueError("Signing key is not in the supplied Android allowlist")
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="andrix-ct-public-") as tmp:
        tmp = Path(tmp)
        key = tmp / "public.pem"
        key.write_bytes(pem)
        for version, extension in (("v2", "json"), ("v3", "ctfb")):
            content, signature = tmp / "content", tmp / "signature"
            content.write_bytes(files[f"{version}/log_list.{extension}"])
            signature.write_bytes(decode(files[f"{version}/log_list.sig"]))
            result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key),
                                     "-signature", str(signature), str(content)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                raise ValueError("CT " + version + " signature verification failed")
    metadata = json.loads(files["v2/log_list.json"])
    timestamp = metadata["log_list_timestamp"]
    if type(timestamp) is not int:
        raise ValueError("Invalid CT timestamp")
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if timestamp > now_ms or now_ms - timestamp > MAX_AGE_MS:
        raise ValueError("CT data is future-dated or older than the pinned 70-day policy")
    manifest = {"schema": 1, "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "allowed_keys_sha256": hashlib.sha256(allowed).hexdigest(),
                "log_list_timestamp_ms": timestamp, "valid_until_ms": timestamp + MAX_AGE_MS,
                "version": metadata["version"], "verified_at_ms": now_ms,
                "upstream": "https://www.gstatic.com/android/certificate_transparency/",
                "network_access_during_verification": False}
    return files, manifest


def stage(source, allowed_keys, output):
    files, manifest = verify(source, allowed_keys)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--allowed-keys", required=True, type=Path,
                        help="ct_public_keys.pem extracted from the exact target resource APK")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(stage(args.source_dir, args.allowed_keys, args.output_dir), indent=2))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("CT staging failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
