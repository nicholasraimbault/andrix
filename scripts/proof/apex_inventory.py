# SPDX-License-Identifier: Apache-2.0
"""Bounded public APEX/rotation observations, not signer ownership or runtime trust."""
import base64
import re
import stat
from dataclasses import dataclass
try:
    from .signing_identity import MAX_DOCUMENT, MAX_PUBLIC_BLOB, SHA256, public_identity, strict_json
except ImportError:
    from signing_identity import MAX_DOCUMENT, MAX_PUBLIC_BLOB, SHA256, public_identity, strict_json


@dataclass(frozen=True)
class ImageEntry:
    name: str
    inode: int
    mode: int
    uid: int
    gid: int
    size: int | None
    kind: str


@dataclass(frozen=True)
class ImageDirectory:
    inode: int
    parent_inode: int
    entries: tuple[ImageEntry, ...]
    unused_slots: int


def debugfs_directory(code, stdout, stderr):
    """Parse the observed pinned debugfs `ls -l -p` form. A zero exit is not enough.

    No path is opened here. Unsupported names fail rather than becoming tool command
    syntax. Callers must not follow payload symlinks into the host filesystem.
    """
    if (code != 0 or not isinstance(stdout, str) or not isinstance(stderr, str)
            or len(stdout) > MAX_DOCUMENT or len(stderr) > 4096):
        raise ValueError('Directory observation unavailable')
    if stderr and not re.fullmatch(r'debugfs [0-9][A-Za-z0-9.() +_-]*\n?', stderr):
        raise ValueError('Directory tool error, including zero exit errors')
    entries = []
    special = {}
    names = set()
    unused = 0
    for line in stdout.splitlines():
        if not line:
            continue
        parts = line.split('/')
        if len(parts) != 8 or parts[0] or parts[-1]:
            raise ValueError('Unrecognized debugfs directory record')
        inode, mode, uid, gid, name, size = parts[1:7]
        if not re.fullmatch(r'[0-9]+', inode) or not re.fullmatch(r'[0-7]{5,6}', mode):
            raise ValueError('Invalid inode or mode')
        if not re.fullmatch(r'[0-9]+', uid) or not re.fullmatch(r'[0-9]+', gid):
            raise ValueError('Invalid image owner observation')
        inode, mode, uid, gid = int(inode), int(mode, 8), int(uid), int(gid)
        if not name and inode == 0:
            unused += 1
            continue
        if (inode <= 0 or len(name) > 255 or not re.fullmatch(r'[A-Za-z0-9_.@+,:=-]+', name)
                or name in names):
            raise ValueError('Unsupported or duplicate image entry name')
        names.add(name)
        if size and not re.fullmatch(r'[0-9]+', size):
            raise ValueError('Invalid image entry size')
        size = int(size) if size else None
        kind = ('directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode)
                else 'symlink' if stat.S_ISLNK(mode) else 'special')
        if kind == 'file' and size is None:
            raise ValueError('Missing regular file length')
        row = ImageEntry(name, inode, mode, uid, gid, size, kind)
        if name in ['.', '..']:
            if kind != 'directory':
                raise ValueError('Directory identity has wrong type')
            special[name] = row
        else:
            entries.append(row)
        if len(entries) > 100000:
            raise ValueError('Directory entry bound')
    if set(special) != {'.', '..'}:
        raise ValueError('No complete directory identity observation')
    return ImageDirectory(special['.'].inode, special['..'].inode, tuple(entries), unused)


def lineage_observation(code, output, sdk):
    """Check the exact public probe schema, retaining each scheme's separate lineage.

    Capabilities are artifact declarations. Successful verification at one SDK does
    not establish the installed history, all SDK selections or possession of a key.
    """
    if code != 0 or type(sdk) is not int or not 0 < sdk <= 1000:
        raise ValueError('Lineage observation failed')
    value = strict_json(output)
    fields = {'version', 'sdk', 'artifact_verified', 'schemes_verified', 'current_signers',
              'combined_lineage', 'v3_signers', 'v31_signers', 'v32_signer', 'scope',
              'installed_history_or_key_ownership_proved'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['version']) is not int
            or value['version'] != 1 or type(value['sdk']) is not int or value['sdk'] != sdk
            or value['artifact_verified'] is not True
            or value['installed_history_or_key_ownership_proved'] is not False
            or value['scope'] != 'lineages exposed by successful verification at this SDK'):
        raise ValueError('Unsupported lineage observation schema')
    schemes = value['schemes_verified']
    if (not isinstance(schemes, dict) or set(schemes) != {'v1', 'v2', 'v3', 'v31', 'v32'}
            or any(type(flag) is not bool for flag in schemes.values()) or not any(schemes.values())):
        raise ValueError('Invalid signing scheme observation')

    def identity(row):
        if not isinstance(row, dict) or set(row) != {'certificate_sha256', 'spki_sha256', 'certificate_der', 'spki_der'}:
            raise ValueError('Unsupported lineage public identity')
        result = {}
        for name, encoding in [('certificate', 'x509-der'), ('spki', 'spki-der')]:
            text, digest = row[name + '_der'], row[name + '_sha256']
            if (not isinstance(text, str) or len(text) > 4 * MAX_PUBLIC_BLOB // 3 + 4
                    or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
                raise ValueError('Public identity encoding bound')
            blob = base64.b64decode(text, validate=True)
            if base64.b64encode(blob).decode() != text:
                raise ValueError('Noncanonical public identity encoding')
            result[name] = public_identity(encoding, blob)
            if result[name]['sha256'] != digest:
                raise ValueError('Public identity digest mismatch')
        return result

    def bounded(rows, nonempty=False):
        if not isinstance(rows, list) or len(rows) > 64 or (nonempty and not rows):
            raise ValueError('Signer or lineage count bound')
        return rows

    def lineage(rows):
        if rows is None:
            return None
        result = []
        seen = set()
        for row in bounded(rows, True):
            if not isinstance(row, dict) or set(row) != {'identity', 'capabilities'}:
                raise ValueError('Unsupported lineage node')
            public = identity(row['identity'])
            digest = public['certificate']['sha256']
            if digest in seen:
                raise ValueError('Repeated certificate within lineage')
            seen.add(digest)
            caps = row['capabilities']
            if (not isinstance(caps, dict) or set(caps) != {'installed_data', 'shared_uid', 'permission', 'rollback', 'auth'}
                    or any(type(flag) is not bool for flag in caps.values())):
                raise ValueError('Unsupported lineage capabilities')
            result.append({'identity': public, 'capabilities': dict(caps)})
        return result

    def signer(row):
        if row is None:
            return None
        if (not isinstance(row, dict) or set(row) != {'min_sdk', 'max_sdk', 'targets_dev_release', 'contains_errors', 'lineage'}
                or any(type(row[key]) is not int or not -1 <= row[key] <= 2147483647
                       for key in ['min_sdk', 'max_sdk'])
                or type(row['targets_dev_release']) is not bool or type(row['contains_errors']) is not bool):
            raise ValueError('Unsupported scheme signer observation')
        if not row['contains_errors'] and not 0 <= row['min_sdk'] <= row['max_sdk']:
            raise ValueError('Inconsistent verified signer SDK range')
        return {**row, 'lineage': lineage(row['lineage'])}

    current = [identity(row) for row in bounded(value['current_signers'], True)]
    if len({row['certificate']['sha256'] for row in current}) != len(current):
        raise ValueError('Repeated current signer')
    hybrid = value['v32_signer']
    if hybrid is not None:
        if not isinstance(hybrid, dict) or set(hybrid) != {'classical', 'pqc'}:
            raise ValueError('Unsupported hybrid signer observation')
        hybrid = {name: signer(row) for name, row in hybrid.items()}
    return {**value, 'current_signers': current, 'combined_lineage': lineage(value['combined_lineage']),
            'v3_signers': [signer(row) for row in bounded(value['v3_signers'])],
            'v31_signers': [signer(row) for row in bounded(value['v31_signers'])], 'v32_signer': hybrid}
