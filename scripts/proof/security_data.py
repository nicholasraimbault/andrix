#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage bounded public security snapshots offline; metadata is NOT a signature."""
import argparse
from contextlib import contextmanager
from datetime import date, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time


MAX_FILE_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 16384
MAX_ENTRIES = 10000
MAX_AGE_SECONDS = 86400  # Both publisher responses observed with max-age=86400.
GSI_PATH = "/security/gsi-keyblacklist.json"
ATTESTATION_PATH = "/security/attestation-status.json"
CATALOG_PATH = "/system-images/catalog.json"
# Neither client request targets nor operator manifests can select disk paths.
FILES = {GSI_PATH: "gsi-keyblacklist.json", ATTESTATION_PATH: "attestation-status.json",
         CATALOG_PATH: "catalog.json"}
SOURCE_URLS = {
    GSI_PATH: "https://dl.google.com/developers/android/gsi/gsi-keyblacklist.json",
    ATTESTATION_PATH: "https://android.googleapis.com/attestation/status",
    CATALOG_PATH: "https://probe.andrix.org/system-images/catalog.json",
}
SOURCE_KINDS = {GSI_PATH: "operator-reported-public-snapshot-over-tls",
                ATTESTATION_PATH: "operator-reported-public-snapshot-over-tls",
                CATALOG_PATH: "owner-supplied-empty-experimental-catalog"}
STATUSES = {"REVOKED", "SUSPENDED"}
REASONS = {"UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"}
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
SERIAL = re.compile(r"[1-9a-f][0-9a-f]{0,39}")  # Positive, canonical lower-case X.509 hex.
PRIVATE_TEXT = re.compile(r"PRIVATE\s+KEY", re.I)
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@contextmanager
def _directory_fd(path):
    """Linux host paths: reject symlinks in every component, including parents."""
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ValueError("Parent traversal is unsupported")
    fd = os.open(path.anchor, DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def read_public(path, limit=MAX_FILE_BYTES):
    """Read bounded regular, nonsymlink FILEs, never stdin, devices or FIFOs."""
    path = Path(path)
    if str(path) == "-" or path.name in ("", ".."):
        raise ValueError("Expected an explicit public FILE")
    with _directory_fd(path.parent) as parent:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Invalid public input type or size")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
                raise ValueError("Invalid public input type or size")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
        finally:
            os.close(fd)
    if not 0 < len(data) <= limit or PRIVATE_TEXT.search(data.decode("utf-8", errors="replace")):
        raise ValueError("Invalid public input size or private-key text")
    return data


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _noninteger(unused):
    raise ValueError("Noninteger JSON number or nonfinite constant")


def _integer(text):
    # Only small manifest schema/size integers are needed. Bound conversion even
    # on Python versions without a built-in integer string length limit.
    if len(text) > 10:
        raise ValueError("Oversized JSON integer")
    return int(text)


def strict_json(data):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_integer,
                           parse_constant=_noninteger, parse_float=_noninteger)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 8:
                raise ValueError("JSON nesting exceeds fixture limit")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for pair in item.items() for child in pair)
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
            elif isinstance(item, str):
                item.encode("utf-8")  # Reject escaped unpaired surrogates too.
                if PRIVATE_TEXT.search(item):
                    raise ValueError("Private-key text is not public snapshot data")
        return value
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid UTF-8 or excessive JSON nesting") from error


def validate_payload(path, raw):
    if not 0 < len(raw) <= MAX_FILE_BYTES:
        raise ValueError("Invalid public data size")
    value = strict_json(raw)
    if path == GSI_PATH:
        # r1 KeyRevocationList accepts {} or an entries array. Preserve published
        # revocations too; never replace a newly nonempty list with an empty one.
        if not isinstance(value, dict) or set(value) - {"entries"}:
            raise ValueError("Unsupported GSI root schema")
        entries = value.get("entries", [])
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise ValueError("Invalid GSI entries")
        seen = set()
        for entry in entries:
            if (not isinstance(entry, dict) or not {"public_key", "status"} <= set(entry)
                    or set(entry) - {"public_key", "status", "reason"}):
                raise ValueError("Unsupported GSI revocation entry")
            key = entry["public_key"]
            if (not isinstance(key, str) or not re.fullmatch(r"[0-9a-fA-F]{1,8192}", key)
                    or key.lower() in seen or entry["status"] != "REVOKED"):
                raise ValueError("Invalid/duplicate GSI public key or unsupported status")
            seen.add(key.lower())
            if "reason" in entry and (not isinstance(entry["reason"], str)
                                      or len(entry["reason"]) > 2048):
                raise ValueError("Invalid GSI revocation reason")
    elif path == CATALOG_PATH:
        if value != {"include": [], "images": []}:
            raise ValueError("Only the explicitly acknowledged empty experimental catalog is supported")
    elif path == ATTESTATION_PATH:
        if not isinstance(value, dict) or set(value) != {"entries"}:
            raise ValueError("Unsupported attestation root schema")
        entries = value["entries"]
        if not isinstance(entries, dict) or not 0 < len(entries) <= MAX_ENTRIES:
            raise ValueError("Expected bounded nonempty attestation entries")
        for serial, entry in entries.items():
            if not SERIAL.fullmatch(serial):
                raise ValueError("Invalid attestation serial")
            if (not isinstance(entry, dict) or not {"status", "reason"} <= set(entry)
                    or set(entry) - {"status", "reason", "comment", "expires"}):
                raise ValueError("Unsupported attestation entry schema")
            if (not isinstance(entry["status"], str) or entry["status"] not in STATUSES
                    or not isinstance(entry["reason"], str) or entry["reason"] not in REASONS):
                raise ValueError("Invalid attestation status or reason enum")
            if "comment" in entry and (not isinstance(entry["comment"], str)
                                       or len(entry["comment"]) > 2048):
                raise ValueError("Invalid attestation comment")
            if "expires" in entry:
                expiry = entry["expires"]
                if not isinstance(expiry, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", expiry):
                    raise ValueError("Invalid attestation entry expiry date")
                date.fromisoformat(expiry)
                # This is publisher record data, NOT the snapshot freshness time.
                # Never remove entries or turn expiry into a positive verdict.
    else:
        raise ValueError("Unsupported public data path")


def _timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError("Use explicit UTC timestamps with seconds and Z suffix")
    result = datetime.fromisoformat(value[:-1] + "+00:00").timestamp()
    if result < 0:
        raise ValueError("Timestamp predates Unix epoch")
    return result


def _now():
    value = time.time()
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Invalid host clock")
    return value


def _window(record, now):
    fetched, expires = _timestamp(record["fetched_at"]), _timestamp(record["expires_at"])
    if not 0 < expires - fetched <= MAX_AGE_SECONDS or not fetched <= now < expires:
        raise ValueError("Snapshot is future-dated, expired or exceeds the 24-hour bound")
    return fetched, expires


def _records(document, manifest=False):
    keys = {"schema", "files"}
    if manifest:
        keys |= {"source_observed_tls_acknowledged", "empty_catalog_acknowledged",
                 "cryptographic_provenance_verified"}
    if (not isinstance(document, dict) or set(document) != keys
            or type(document["schema"]) is not int or document["schema"] != 1
            or not isinstance(document["files"], dict) or set(document["files"]) != set(FILES)):
        raise ValueError("Unexpected security metadata schema or paths")
    if manifest and (document["source_observed_tls_acknowledged"] is not True
                     or document["empty_catalog_acknowledged"] is not True
                     or document["cryptographic_provenance_verified"] is not False):
        raise ValueError("Missing acknowledgments or false cryptographic provenance claim")
    record_keys = {"source_url", "fetched_at", "expires_at"}
    if manifest:
        record_keys |= {"sha256", "size", "provenance"}
    now = _now()
    for path, record in document["files"].items():
        if not isinstance(record, dict) or set(record) != record_keys:
            raise ValueError("Unexpected security file metadata")
        if record["source_url"] != SOURCE_URLS[path]:
            raise ValueError("Unexpected source URL")
        _window(record, now)
        if manifest and (not isinstance(record["sha256"], str)
                         or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                         or type(record["size"]) is not int or not 0 < record["size"] <= MAX_FILE_BYTES
                         or record["provenance"] != SOURCE_KINDS[path]):
            raise ValueError("Invalid manifest digest, size or provenance classification")
    return document["files"]


def stage(gsi, attestation, catalog, provenance, output, *,
          ack_source_observed_tls=False, ack_empty_catalog=False):
    """Validate all explicit inputs before creating a NEW bundle; no fetch/signing."""
    if ack_source_observed_tls is not True or ack_empty_catalog is not True:
        raise ValueError("Explicit TLS-source and empty experimental catalog acknowledgments required")
    inputs = {GSI_PATH: gsi, ATTESTATION_PATH: attestation, CATALOG_PATH: catalog}
    raw = {path: read_public(filename) for path, filename in inputs.items()}
    for path, data in raw.items():
        validate_payload(path, data)
    records = _records(strict_json(read_public(provenance, MAX_METADATA_BYTES)))
    manifest = {"schema": 1, "source_observed_tls_acknowledged": True,
                "empty_catalog_acknowledged": True, "cryptographic_provenance_verified": False,
                "files": {path: {**records[path], "sha256": hashlib.sha256(data).hexdigest(),
                                 "size": len(data), "provenance": SOURCE_KINDS[path]}
                          for path, data in raw.items()}}
    output = Path(output)
    # Create only under an existing nonsymlink parent. Never overwrite a bundle.
    with _directory_fd(output.parent) as parent:
        if output.name in ("", ".."):
            raise ValueError("Expected a new bundle directory")
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        fd = os.open(output.name, DIR_FLAGS, dir_fd=parent)
        try:
            contents = {FILES[path]: data for path, data in raw.items()}
            # Manifest last: incomplete/failed staging cannot be loaded as a bundle.
            contents["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
            for name, data in contents.items():
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                with os.fdopen(target, "wb") as stream:
                    stream.write(data)
        finally:
            os.close(fd)
    return manifest


class SecurityAssets:
    """Loaded bytes, exact paths and per-response expiry; never re-read disk paths."""
    paths = tuple(path.encode("ascii") for path in FILES)

    def __init__(self, raw, records):
        now, monotonic = _now(), time.monotonic()
        self._data = {}
        self._unavailable = set()
        for path, data in raw.items():
            fetched, expires = _window(records[path], now)
            self._data[path.encode("ascii")] = (data, fetched, expires, monotonic + expires - now)

    def payload(self, path):
        data, fetched, expires, deadline = self._data[path]
        # Monotonic bound prevents wall-clock rollback from extending service.
        # Once observed invalid, a path remains unavailable until explicit restart.
        try:
            now = _now()
            valid = fetched <= now < expires and time.monotonic() < deadline
        except ValueError:
            valid = False
        if not valid or path in self._unavailable:
            self._unavailable.add(path)
            raise ValueError("Security snapshot unavailable; explicit fresh staging/restart required")
        return data


def load_assets(directory):
    records = _records(strict_json(read_public(Path(directory) / "manifest.json", MAX_METADATA_BYTES)),
                       manifest=True)
    raw = {}
    for path, name in FILES.items():
        data = read_public(Path(directory) / name)
        if len(data) != records[path]["size"] or hashlib.sha256(data).hexdigest() != records[path]["sha256"]:
            raise ValueError("Security data digest or size mismatch")
        validate_payload(path, data)
        raw[path] = data
    return SecurityAssets(raw, records)  # Recheck all windows after reading/validating.


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "security_data: invalid arguments; use --help (inputs take FILE paths)\n")


def main(argv=None):
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--gsi-keyblacklist", required=True, type=Path, metavar="FILE")
    parser.add_argument("--attestation-status", required=True, type=Path, metavar="FILE")
    parser.add_argument("--catalog", required=True, type=Path, metavar="FILE")
    parser.add_argument("--provenance", required=True, type=Path, metavar="FILE",
                        help="Explicit source URLs, fetched_at and expires_at per path; see security_data.md")
    parser.add_argument("--output-dir", required=True, type=Path, metavar="NEW_DIRECTORY")
    parser.add_argument("--ack-source-observed-tls", required=True, action="store_true",
                        help="Operator observed public source HTTPS fetches; NOT detached signature verification")
    parser.add_argument("--ack-empty-catalog", required=True, action="store_true",
                        help="Owner supplied an empty catalog for the unreleased Andrix GSI experiment")
    args = parser.parse_args(argv)
    try:
        stage(args.gsi_keyblacklist, args.attestation_status, args.catalog, args.provenance,
              args.output_dir, ack_source_observed_tls=args.ack_source_observed_tls,
              ack_empty_catalog=args.ack_empty_catalog)
    except (OSError, ValueError):
        # Never echo input contents, paths or operator argument text.
        print("security_data: staging refused; check public inputs, schema and freshness", file=sys.stderr)
        return 1
    print("Staged public snapshots and explicit empty catalog; provenance is operator-reported, not signed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
