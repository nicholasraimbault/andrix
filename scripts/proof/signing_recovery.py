# SPDX-License-Identifier: Apache-2.0
"""Finite host recovery vehicle, not a privileged signer or installation API.

age owns encryption and authentication. OpenSSL and the pinned avbtool own key
parsing and public representation derivation. An independently trusted manifest
commitment is mandatory: public key encryption does not authenticate a sender.
No recovered material is returned before complete decryption and all checks.

Python objects are not a secure heap and no physical erasure claim is made.
These bounds are parser limits for the proof, not permanent product key quotas.
"""
import base64
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

try:
    from .signing_identity import public_identity, strict_json
except ImportError:
    from signing_identity import public_identity, strict_json

MAX_BUNDLE = 8 * 1024 * 1024
MAX_DOCUMENT = 4 * 1024 * 1024
MAX_KEY = 65536
MAX_KEYS = 128
MAX_USES = 1024
TOKEN = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}')
HEX = re.compile(r'[0-9a-f]{64}')
PURPOSE_ENCODING = {'apk': 'x509-der', 'apex-container': 'x509-der',
                    'apex-payload': 'avb-public-key', 'avb': 'avb-public-key',
                    'ota-package': 'x509-der', 'ota-payload': 'spki-der'}
BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


class RecoveryError(ValueError):
    """A deliberately nonsecret error suitable for a caller to record."""


def _fail(condition, message):
    if not condition:
        raise RecoveryError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(document):
    try:
        data = json.dumps(document, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError):
        raise RecoveryError('Invalid document') from None
    _fail(len(data) <= MAX_DOCUMENT, 'Document too large')
    return data


def _decode(text):
    _fail(isinstance(text, str) and len(text) <= 4 * MAX_KEY // 3 + 4,
          'Invalid key encoding size')
    try:
        blob = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        raise RecoveryError('Invalid key encoding') from None
    _fail(0 < len(blob) <= MAX_KEY and base64.b64encode(blob).decode() == text,
          'Noncanonical key encoding')
    return blob


def _encode(blob):
    _fail(isinstance(blob, bytes) and 0 < len(blob) <= MAX_KEY, 'Key size')
    return base64.b64encode(blob).decode('ascii')


def _fields(value, fields):
    _fail(isinstance(value, dict) and set(value) == set(fields), 'Unexpected fields')


def _token(value):
    _fail(isinstance(value, str) and TOKEN.fullmatch(value) is not None, 'Invalid name')


def _public_blobs(key):
    _fields(key, ['slot', 'spki', 'certificates', 'avb_public_key'])
    _token(key['slot'])
    spki = _decode(key['spki'])
    certs = key['certificates']
    _fail(isinstance(certs, list) and len(certs) <= 16, 'Certificate count')
    certs = [_decode(item) for item in certs]
    _fail(len(certs) == len(set(certs)), 'Repeated certificate')
    blobs = [('spki-der', spki)] + [('x509-der', item) for item in certs]
    if key['avb_public_key'] is not None:
        blob = _decode(key['avb_public_key'])
        try:
            public_identity('avb-public-key', blob)
        except ValueError:
            raise RecoveryError('Invalid AVB public encoding') from None
        blobs.append(('avb-public-key', blob))
    return blobs


def validate_manifest(manifest):
    """Shape and binding validation only. Cryptographic derivation is separate."""
    canonical(manifest)
    _fields(manifest, ['version', 'installation', 'generation', 'keys', 'uses'])
    _fail(type(manifest['version']) is int and manifest['version'] == 1,
          'Unsupported manifest version')
    try:
        installation = str(uuid.UUID(manifest['installation']))
    except (ValueError, TypeError, AttributeError):
        raise RecoveryError('Invalid installation identity') from None
    _fail(installation == manifest['installation'], 'Noncanonical installation identity')
    _fail(type(manifest['generation']) is int and 0 < manifest['generation'] < 1 << 63,
          'Invalid generation')
    keys, uses = manifest['keys'], manifest['uses']
    _fail(isinstance(keys, list) and 0 < len(keys) <= MAX_KEYS, 'Key count')
    _fail(isinstance(uses, list) and 0 < len(uses) <= MAX_USES, 'Use count')
    slots, spkis = {}, set()
    for key in keys:
        blobs = _public_blobs(key)
        _fail(key['slot'] not in slots, 'Repeated key slot')
        spki = digest(blobs[0][1])
        _fail(spki not in spkis, 'Repeated private key identity under different slots')
        spkis.add(spki)
        slots[key['slot']] = {(encoding, digest(blob)) for encoding, blob in blobs}
    names, used = set(), set()
    for use in uses:
        _fields(use, ['purpose', 'component', 'slot', 'identity'])
        _fail(isinstance(use['purpose'], str) and use['purpose'] in PURPOSE_ENCODING,
              'Unknown signing purpose')
        _token(use['component']); _token(use['slot'])
        _fields(use['identity'], ['encoding', 'sha256'])
        _fail(use['identity']['encoding'] == PURPOSE_ENCODING[use['purpose']],
              'Wrong identity encoding for purpose')
        value = use['identity']['sha256']
        _fail(isinstance(value, str) and HEX.fullmatch(value) is not None,
              'Invalid identity digest')
        _fail(use['slot'] in slots and (use['identity']['encoding'], value) in slots[use['slot']],
              'Use does not bind to the declared key representation')
        name = (use['purpose'], use['component'])
        _fail(name not in names, 'Repeated signing use')
        names.add(name); used.add(use['slot'])
    _fail(used == set(slots), 'Unbound key slot')
    return digest(canonical(manifest))


@dataclass(frozen=True)
class Tools:
    age: Path
    openssl: Path
    avbtool: Path

    def __post_init__(self):
        for path in (self.age, self.openssl, self.avbtool):
            _fail(isinstance(path, Path) and path.is_absolute() and path.is_file(),
                  'Tools must be explicit absolute files')

    def _run(self, argv, data=b'', pass_fds=()):
        env = {'PATH': str(self.openssl.parent) + ':/usr/bin:/bin',
               'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'HOME': '/nonexistent',
               'OPENSSL_CONF': '/dev/null', 'GOTELEMETRY': 'off'}
        try:
            result = subprocess.run([str(x) for x in argv], input=data,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=60, close_fds=True, pass_fds=pass_fds, env=env)
        except (OSError, subprocess.TimeoutExpired):
            raise RecoveryError('Cryptographic tool unavailable or timed out') from None
        # stderr and partial stdout are deliberately not included in errors.
        _fail(result.returncode == 0, 'Cryptographic operation refused')
        _fail(len(result.stdout) <= MAX_BUNDLE, 'Cryptographic output too large')
        return result.stdout

    def private_spki(self, pkcs8):
        _fail(isinstance(pkcs8, bytes) and 0 < len(pkcs8) <= MAX_KEY, 'Private key size')
        self._run([self.openssl, 'pkey', '-inform', 'DER', '-passin', 'pass:',
                   '-check', '-noout'], pkcs8)
        normalized = self._run([self.openssl, 'pkcs8', '-topk8', '-nocrypt',
                                '-inform', 'DER', '-outform', 'DER', '-passin', 'pass:'], pkcs8)
        _fail(normalized == pkcs8, 'Expected canonical unencrypted PKCS8 input')
        return self._run([self.openssl, 'pkey', '-inform', 'DER', '-passin', 'pass:',
                          '-pubout', '-outform', 'DER'], pkcs8)

    def public_spki(self, spki):
        normalized = self._run([self.openssl, 'pkey', '-pubin', '-inform', 'DER',
                                '-outform', 'DER'], spki)
        _fail(normalized == spki, 'Expected canonical public key encoding')
        return normalized

    def certificate_spki(self, certificate):
        normalized = self._run([self.openssl, 'x509', '-inform', 'DER',
                                '-outform', 'DER'], certificate)
        _fail(normalized == certificate, 'Expected canonical certificate encoding')
        pem = self._run([self.openssl, 'x509', '-inform', 'DER', '-pubkey', '-noout'], certificate)
        return self._run([self.openssl, 'pkey', '-pubin', '-outform', 'DER'], pem)

    def avb_public_key(self, spki):
        pem = self._run([self.openssl, 'pkey', '-pubin', '-inform', 'DER'], spki)
        # Only PUBLIC key material goes into these temporary files. avbtool's
        # openssl subprocess cannot use our parent's private memfd descriptors.
        with tempfile.TemporaryDirectory(prefix='andrix-public-avb-') as folder:
            root = Path(folder); (root / 'public.pem').write_bytes(pem)
            self._run([sys.executable, '-B', self.avbtool, 'extract_public_key',
                       '--key', root / 'public.pem', '--output', root / 'public.avb'])
            data = (root / 'public.avb').read_bytes()
        public_identity('avb-public-key', data)
        return data


def key_description(slot, private_key, tools, certificates=(), avb=False):
    _token(slot)
    spki = tools.private_spki(private_key)
    for certificate in certificates:
        _fail(tools.certificate_spki(certificate) == spki, 'Certificate key disagreement')
    return {'slot': slot, 'spki': _encode(spki),
            'certificates': [_encode(value) for value in certificates],
            'avb_public_key': _encode(tools.avb_public_key(spki)) if avb else None}


def _validate_material(manifest, private_keys, tools):
    validate_manifest(manifest)
    _fail(isinstance(private_keys, dict) and set(private_keys) == {k['slot'] for k in manifest['keys']},
          'Incomplete or extra private material')
    for key in manifest['keys']:
        spki = _decode(key['spki'])
        _fail(tools.public_spki(spki) == tools.private_spki(private_keys[key['slot']]),
              'Private key does not match expected public identity')
        for certificate in key['certificates']:
            _fail(tools.certificate_spki(_decode(certificate)) == spki,
                  'Certificate does not bind to this key')
        if key['avb_public_key'] is not None:
            _fail(tools.avb_public_key(spki) == _decode(key['avb_public_key']),
                  'AVB representation does not bind to this key')


def _native_recipient(recipient):
    _fail(isinstance(recipient, str) and (
        re.fullmatch(r'age1[' + BECH32 + r']{58}', recipient) is not None or
        re.fullmatch(r'age1pq1[' + BECH32 + r']{1952}', recipient) is not None),
        'Only native age recipients are supported by this vehicle')


def _native_identity(identity):
    _fail(isinstance(identity, bytes) and 0 < len(identity) <= 4096, 'Recovery identity size')
    try:
        lines = [line for line in identity.decode('ascii').splitlines()
                 if line and not line.startswith('#')]
    except UnicodeError:
        raise RecoveryError('Recovery identity encoding') from None
    _fail(len(lines) == 1 and re.fullmatch(
        r'AGE-SECRET-KEY-(?:PQ-)?1[' + BECH32.upper() + r']{58}', lines[0]) is not None,
        'Only one native recovery identity is permitted')
    return (lines[0] + '\n').encode('ascii')


def _identity_fd(identity):
    fd = os.memfd_create('andrix-recovery-identity', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        data = _native_identity(identity)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            _fail(count > 0, 'Recovery identity transfer failed')
            view = view[count:]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def encrypt_bundle(manifest, private_keys, recipient, tools):
    _native_recipient(recipient)
    _validate_material(manifest, private_keys, tools)
    payload = canonical({'version': 1, 'manifest': manifest,
                         'private_keys': {slot: _encode(key) for slot, key in private_keys.items()}})
    encrypted = tools._run([tools.age, '--encrypt', '--recipient', recipient, '--output', '-'], payload)
    _fail(0 < len(encrypted) <= MAX_BUNDLE, 'Encrypted bundle size')
    return encrypted, validate_manifest(manifest)


@dataclass(frozen=True)
class Recovered:
    manifest: dict
    private_keys: dict = field(repr=False)


def decrypt_bundle(encrypted, identity, expected_manifest_sha256, tools):
    """The expected commitment must come from an independently trusted record.

    Taking this value from the untrusted backup or its sibling file would not
    establish which installation identity or signing roles the owner expected.
    """
    _fail(isinstance(encrypted, bytes) and 0 < len(encrypted) <= MAX_BUNDLE,
          'Encrypted bundle size')
    _fail(isinstance(expected_manifest_sha256, str)
          and HEX.fullmatch(expected_manifest_sha256) is not None,
          'An expected public identity commitment is required')
    fd = _identity_fd(identity)
    try:
        plaintext = tools._run([tools.age, '--decrypt', '--identity', '/proc/self/fd/' + str(fd),
                                '--output', '-'], encrypted, pass_fds=(fd,))
    finally:
        os.close(fd)
    # age may emit complete early chunks before discovering a bad final chunk.
    # _run must succeed before parsing or exposing any of those bytes.
    try:
        data = strict_json(plaintext)
    except (ValueError, TypeError):
        raise RecoveryError('Invalid recovered document') from None
    _fields(data, ['version', 'manifest', 'private_keys'])
    _fail(type(data['version']) is int and data['version'] == 1, 'Unsupported bundle version')
    actual = validate_manifest(data['manifest'])
    _fail(actual == expected_manifest_sha256, 'Unexpected installation identity or role set')
    _fail(isinstance(data['private_keys'], dict) and len(data['private_keys']) <= MAX_KEYS,
          'Invalid private material table')
    private_keys = {slot: _decode(value) for slot, value in data['private_keys'].items()}
    _validate_material(data['manifest'], private_keys, tools)
    return Recovered(data['manifest'], private_keys)
