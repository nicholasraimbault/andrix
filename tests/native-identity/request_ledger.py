#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private fixture operation ownership. No device authority and no automatic retry as new work."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

PACKAGES = {'dev.andrix.proof.uidstore', 'dev.andrix.proof.uidstorepeer'}


def _hash(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _root(value):
    root = Path(value)
    if not root.is_absolute() or root.is_symlink() or root.resolve() != root or not root.is_dir():
        raise ValueError('private canonical ledger directory required')
    return root


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    _sync(path.parent)
    return hashlib.sha256(data).hexdigest()


def prepare(root, operation, setup, package, uid, serial, signer, provenance, expected_key=None):
    """Provenance hashes must identify independent PMS, UserManager and apksigner captures."""
    root = _root(root)
    if (operation not in ('initialize', 'observe', 'absent') or package not in PACKAGES
            or type(uid) is not int or not 10000 <= uid <= 19999
            or type(serial) is not int or serial < 0 or not _hash(signer)
            or type(setup) is not str or not re.fullmatch(r'[a-z0-9_]{1,48}', setup)
            or type(provenance) is not dict or set(provenance) != {'pms', 'user', 'apk'}
            or not all(_hash(value) for value in provenance.values())
            or (operation == 'observe' and not _hash(expected_key))
            or (operation != 'observe' and expected_key is not None)):
        raise ValueError('fixture request or independent provenance missing')
    nonce = secrets.token_hex(16)
    directory = root / nonce
    directory.mkdir(mode=0o700) # A collision or old result is never overwritten.
    request = {'version': 1, 'operation': operation, 'nonce': nonce, 'setup': setup,
               'package': package, 'uid': uid, 'user_serial': serial, 'apk_signer': signer,
               'provenance': dict(provenance), 'expected_key': expected_key}
    _write_new(directory / 'request.json', request)
    _sync(root)
    return request


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate request key')
        value[key] = item
    return value


def _read(root, nonce):
    root = _root(root)
    if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('ledger nonce')
    directory = root / nonce
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('owned request missing')
    file = directory / 'request.json'
    if file.is_symlink() or not file.is_file() or file.stat().st_size > 4096:
        raise ValueError('request record')
    data = file.read_bytes()
    request = json.loads(data, object_pairs_hook=_unique)
    if (type(request) is not dict or request.get('nonce') != nonce
            or type(request.get('version')) is not int or request['version'] != 1):
        raise ValueError('request identity mismatch')
    return directory, request, hashlib.sha256(data).hexdigest()


def claim(root, nonce):
    """Write before sending the command. A lost reply keeps this nonce issued forever."""
    directory, request, digest = _read(root, nonce)
    if (directory / 'outcome.json').exists():
        raise ValueError('completed request cannot be issued again')
    _write_new(directory / 'issued.json', {'request_sha256': digest})
    return request


def complete(root, nonce, outcome, capture_sha256):
    """Call after independent assessment. Unknown stays unknown, never replayed as initialize."""
    if outcome not in ('observed-success', 'observed-refusal', 'unknown') or not _hash(capture_sha256):
        raise ValueError('fixture outcome')
    directory, _, digest = _read(root, nonce)
    issued = directory / 'issued.json'
    if issued.is_symlink() or not issued.is_file() or issued.stat().st_size > 4096:
        raise ValueError('request was not issued')
    if json.loads(issued.read_bytes(), object_pairs_hook=_unique).get('request_sha256') != digest:
        raise ValueError('issued request changed')
    _write_new(directory / 'outcome.json', {'request_sha256': digest, 'outcome': outcome,
                                          'capture_sha256': capture_sha256})
