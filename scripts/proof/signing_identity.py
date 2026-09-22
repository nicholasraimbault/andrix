# SPDX-License-Identifier: Apache-2.0
"""Public identity observations, not key ownership or deployment authorization.

Certificate, SubjectPublicKeyInfo and AVB encodings have different identifiers.
A matching public key does not make differently encoded certificates identical.
All limits here are input parser bounds, not product account or key quotas.
"""
import base64
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET

SHA256 = re.compile(r'[0-9a-f]{64}')
PUBLIC_ENCODINGS = frozenset({'x509-der', 'spki-der', 'avb-public-key'})
MAX_DOCUMENT = 4 * 1024 * 1024
MAX_PUBLIC_BLOB = 65536


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('Duplicate JSON field')
        out[key] = value
    return out


def strict_json(data):
    if not isinstance(data, bytes) or len(data) > MAX_DOCUMENT:
        raise ValueError('JSON input size/type')
    def invalid(_):
        raise ValueError('Nonfinite JSON number')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_object,
                          parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid or excessive JSON encoding') from error


def public_identity(encoding, blob):
    if encoding not in PUBLIC_ENCODINGS or not isinstance(blob, bytes):
        raise ValueError('Unknown public identity encoding')
    if not 0 < len(blob) <= MAX_PUBLIC_BLOB:
        raise ValueError('Public identity size')
    # Structural validation is separate from certificate or signature verification.
    if encoding == 'avb-public-key':
        if len(blob) < 8:
            raise ValueError('Truncated AVB key')
        bits, _ = struct.unpack('!II', blob[:8])
        if bits not in (2048, 4096, 8192) or len(blob) != 8 + 2 * (bits // 8):
            raise ValueError('Unexpected AVB key encoding')
    return {'encoding': encoding, 'sha256': sha256(blob)}


def apk_signers(code, output, sdk):
    """Read the exact probe schema, without converting verification to authority."""
    if code != 0 or type(sdk) is not int or not 0 < sdk <= 1000:
        raise ValueError('APK observation did not succeed')
    data = strict_json(output)
    if (not isinstance(data, dict) or set(data) != {
            'version', 'sdk', 'artifact_signature_verified', 'signers',
            'signer_authorized', 'rotation_lineage_enumerated'}
            or type(data['version']) is not int or data['version'] != 1
            or type(data['sdk']) is not int or data['sdk'] != sdk
            or data['artifact_signature_verified'] is not True
            or data['signer_authorized'] is not False
            or data['rotation_lineage_enumerated'] is not False):
        raise ValueError('Unsupported APK observation schema')
    if not isinstance(data['signers'], list) or not 0 < len(data['signers']) <= 32:
        raise ValueError('Signer count')
    rows = []
    seen = set()
    for signer in data['signers']:
        if not isinstance(signer, dict) or set(signer) != {
                'certificate_der_sha256', 'spki_der_sha256',
                'certificate_der_base64', 'spki_der_base64'}:
            raise ValueError('Unsupported signer record')
        row = {}
        for name, encoding in [('certificate', 'x509-der'), ('spki', 'spki-der')]:
            text = signer[name + '_der_base64']
            digest = signer[name + '_der_sha256']
            if (not isinstance(text, str) or len(text) > 4 * MAX_PUBLIC_BLOB // 3 + 4
                    or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
                raise ValueError('Public blob/digest type or size')
            blob = base64.b64decode(text, validate=True)
            if base64.b64encode(blob).decode() != text:
                raise ValueError('Noncanonical public blob encoding')
            row[name] = public_identity(encoding, blob)
            if row[name]['sha256'] != digest:
                raise ValueError('Public identity digest disagreement')
        identity = row['certificate']['sha256']
        if identity in seen:
            raise ValueError('Duplicate signer certificate')
        seen.add(identity)
        rows.append(row)
    return rows


def manifest_identity(code, output):
    """Observe package and shared UID from pinned aapt2 xmltree output only.

    These are declarations, not actual credentials or granted permissions.
    Only direct manifest attributes are read, not a matching nested attribute.
    """
    if code != 0 or not isinstance(output, str) or len(output) > MAX_DOCUMENT:
        raise ValueError('Manifest observation unavailable')
    lines = output.splitlines()
    roots = [(i, re.fullmatch(r'( *)E: manifest(?: \(line=[0-9]+\))?', line))
             for i, line in enumerate(lines)]
    roots = [(i, match[1]) for i, match in roots if match]
    if len(roots) != 1:
        raise ValueError('No unique manifest root')
    start, indent = roots[0]
    prefix = indent + '  '
    attrs = []
    for line in lines[start + 1:]:
        if line.lstrip().startswith('E:') or (line and not line.startswith(prefix)):
            break
        if line.startswith(prefix + 'A:'):
            attrs.append(line[len(indent):])
    def field(name, required):
        matches = []
        for line in attrs:
            if re.match(r'  A: ' + re.escape(name) + r'(?:\(|=)', line):
                value = re.fullmatch(r'  A: ' + re.escape(name)
                                    + r'(?:\(0x[0-9a-f]+\))?="([A-Za-z0-9_.]+)"'
                                    + r'(?: \(Raw: "\1"\))?', line)
                if not value:
                    raise ValueError('Unexpected manifest attribute encoding')
                matches.append(value[1])
        if len(matches) > 1 or (required and not matches):
            raise ValueError('Missing or repeated manifest identity')
        return matches[0] if matches else None
    return {'package': field('package', True),
            'shared_user_id_declaration': field(
                'http://schemas.android.com/apk/res/android:sharedUserId', False)}


def mac_signers(data):
    """Observe certificate-to-seinfo selectors, not effective process labels."""
    if (not isinstance(data, bytes) or len(data) > MAX_DOCUMENT
            or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper()):
        raise ValueError('Unsupported policy XML')
    root = ET.fromstring(data)
    if root.tag != 'policy' or root.attrib:
        raise ValueError('Unexpected policy root')
    rows = []
    for signer in root:
        if signer.tag != 'signer' or set(signer.attrib) != {'signature'}:
            raise ValueError('Unsupported policy selector')
        text = signer.get('signature')
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,65536}', text):
            raise ValueError('Expected public certificate in policy')
        identity = public_identity('x509-der', bytes.fromhex(text))
        for selector in signer:
            if selector.tag == 'seinfo' and set(selector.attrib) == {'value'} and len(selector) == 0:
                rows.append({'certificate': identity, 'package': None,
                             'seinfo': selector.get('value')})
            elif selector.tag == 'package' and set(selector.attrib) == {'name'}:
                if len(selector) != 1 or selector[0].tag != 'seinfo' or set(selector[0].attrib) != {'value'} or len(selector[0]):
                    raise ValueError('Unsupported package policy selector')
                rows.append({'certificate': identity, 'package': selector.get('name'),
                             'seinfo': selector[0].get('value')})
            else:
                raise ValueError('Unsupported policy selector child')
    return rows
