#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify/stage five public CT files without network access or trust changes."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import time

FILES = ("log_list.pub", "v2/log_list.json", "v2/log_list.sig",
         "v3/log_list.ctfb", "v3/log_list.sig")
MAX_FILE = 1024 * 1024
MAX_AGE_MS = 70 * 24 * 60 * 60 * 1000  # Pinned Conscrypt PolicyImpl.
MAX_INT64 = (1 << 63) - 1
MAX_VERSION = (1 << 31) - 1  # Conscrypt v2 parseInt / v3 Math.toIntExact.


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


def read_v3_metadata(data):
    """Read only the r1 ct_log_store.fbs root's three int64 metadata fields.

    This is not a FlatBuffer/log-entry verifier. The caller must first verify
    the original signature and key allowlist; see stage_ct_data.md.
    """
    def require(condition):
        if not condition:
            raise ValueError("Invalid CT v3 FlatBuffer metadata bounds/layout")

    def unpack(kind, position):
        size = struct.calcsize(kind)
        require(0 <= position <= len(data) - size)
        return struct.unpack_from(kind, data, position)[0]

    require(8 <= len(data) <= MAX_FILE)
    if data[4:8] != b"CTFB":
        raise ValueError("Invalid CT v3 FlatBuffer identifier (expected CTFB)")
    table = unpack("<I", 0)  # Non-size-prefixed FlatBuffer root uoffset.
    require(table >= 8 and table % 4 == 0)
    # Vtables may be shared and located after a table: this offset is signed.
    vtable = table - unpack("<i", table)
    require(vtable >= 8 and vtable % 2 == 0)
    vtable_size = unpack("<H", vtable)
    object_size = unpack("<H", vtable + 2)
    require(vtable_size >= 4 and vtable_size % 2 == 0
            and vtable + vtable_size <= len(data))
    require(object_size >= 4 and table + object_size <= len(data))
    require(vtable + vtable_size <= table or table + object_size <= vtable)
    values, positions = [], set()
    # Schema slots 0, 1, 2: version_major, version_minor, timestamp. All default
    # to zero when absent (short vtable or zero field offset), as in FlatBuffers.
    for slot in range(3):
        entry = 4 + 2 * slot
        offset = unpack("<H", vtable + entry) if entry < vtable_size else 0
        if offset == 0:
            values.append(0)
            continue
        position = table + offset
        require(4 <= offset and offset + 8 <= object_size
                and position % 8 == 0 and position not in positions)
        positions.add(position)
        values.append(unpack("<q", position))
    return tuple(values)


def format_metadata(name, version, timestamp, now_ms):
    # Keep v2's original string, but require a usable major.minor version in
    # the consumer's signed-int32 range. v3 stores these as int64 on the wire.
    # A default minor of zero is valid.
    parts = (re.fullmatch(r"([0-9]{1,19})\.([0-9]{1,19})", version)
             if isinstance(version, str) else None)
    if (parts is None or not 0 < int(parts[1]) <= MAX_VERSION
            or not 0 <= int(parts[2]) <= MAX_VERSION):
        raise ValueError("Invalid CT " + name + " version")
    if type(timestamp) is not int or not 0 < timestamp <= MAX_INT64:
        raise ValueError("Invalid CT " + name + " timestamp")
    if timestamp > now_ms or now_ms - timestamp > MAX_AGE_MS:
        raise ValueError("CT " + name + " data is future-dated or older than the pinned 70-day policy")
    return {"version": version, "log_list_timestamp_ms": timestamp,
            "valid_until_ms": timestamp + MAX_AGE_MS}


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
    # Inspect metadata only after BOTH original signatures have passed.
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    metadata = json.loads(files["v2/log_list.json"])
    if not isinstance(metadata, dict):
        raise ValueError("Invalid CT v2 metadata")
    v2 = format_metadata("v2", metadata.get("version"), metadata.get("log_list_timestamp"), now_ms)
    major, minor, timestamp = read_v3_metadata(files["v3/log_list.ctfb"])
    v3 = format_metadata("v3", f"{major}.{minor}", timestamp, now_ms)
    manifest = {"schema": 1, "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "allowed_keys_sha256": hashlib.sha256(allowed).hexdigest(),
                # Legacy version/timestamp are v2 aliases, NOT shared metadata.
                "log_list_timestamp_ms": v2["log_list_timestamp_ms"],
                "version": v2["version"], "formats": {"v2": v2, "v3": v3},
                "valid_until_ms": min(v2["valid_until_ms"], v3["valid_until_ms"]),
                "verified_at_ms": now_ms,
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
