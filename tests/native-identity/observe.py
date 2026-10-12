#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict decoding of this fixture's result. Missing instrumentation is UNKNOWN, not refusal proof."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

PREFIX = 'INSTRUMENTATION_RESULT: uid_recovery_result='
PACKAGES = {'dev.andrix.proof.uidstore', 'dev.andrix.proof.uidstorepeer'}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate result key')
        result[key] = value
    return result


BASE_FIELDS = {'version', 'operation', 'nonce', 'setup', 'package', 'apk_signer_sha256',
               'uid', 'user_serial', 'pid', 'elapsed_ms', 'user_unlocked',
               'key_existed_before', 'ce_existed_before', 'de_existed_before', 'stage', 'passed'}
KEY_FIELDS = {'ce_matches', 'de_matches', 'ce_sha256', 'de_sha256', 'key_matches',
              'key_sha256', 'public_key_der_b64', 'signature_b64', 'signature_verified'}
BEFORE = ('key_existed_before', 'ce_existed_before', 'de_existed_before')


def _reply(text, expected_code):
    if len(text) > 65536:
        raise ValueError('instrumentation output bounds')
    rows = [line[len(PREFIX):] for line in text.splitlines() if line.startswith(PREFIX)]
    codes = re.findall(r'^INSTRUMENTATION_CODE: (-?[0-9]+)$', text, re.M)
    if len(rows) != 1 or codes != [str(expected_code)]:
        raise ValueError('instrumentation outcome not established')
    return json.loads(rows[0], object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def _scope(value, operation, nonce, setup, package, uid, serial, signer):
    if (type(value) is not dict or type(value.get('version')) is not int or value['version'] != 1
            or package not in PACKAGES or type(uid) is not int or not 10000 <= uid <= 19999
            or value.get('operation') != operation or value.get('nonce') != nonce
            or value.get('setup') != setup or value.get('package') != package
            or type(signer) is not str or not re.fullmatch(r'[0-9a-f]{64}', signer)
            or value.get('apk_signer_sha256') != signer
            or type(serial) is not int or serial < 0 or type(value.get('user_serial')) is not int
            or value['user_serial'] != serial or type(value.get('uid')) is not int or value['uid'] != uid
            or type(value.get('pid')) is not int or value['pid'] <= 0
            or type(value.get('elapsed_ms')) is not int or value['elapsed_ms'] < 0
            or value.get('user_unlocked') is not True):
        raise ValueError('fixture identity mismatch')
    for name in ('nonce', 'setup'):
        if not re.fullmatch(r'[a-z0-9_]{1,48}', value[name]):
            raise ValueError('fixture token')
    for name in BEFORE:
        if type(value.get(name)) is not bool:
            raise ValueError('missing before state')


def _retained(value, package, uid, setup, original_key=None):
    for name in ('ce_matches', 'de_matches', 'signature_verified'):
        if value.get(name) is not True:
            raise ValueError('retained state did not match')
    expected = ('Andrix dummy UID recovery canary\n' + package + '\n' + str(uid)
                + '\n' + setup + '\n').encode()
    expected_hash = hashlib.sha256(expected).hexdigest()
    if value.get('ce_sha256') != expected_hash or value.get('de_sha256') != expected_hash:
        raise ValueError('canary digest mismatch')
    public = base64.b64decode(value.get('public_key_der_b64', ''), validate=True)
    signature = base64.b64decode(value.get('signature_b64', ''), validate=True)
    if not 32 <= len(public) <= 512 or not 8 <= len(signature) <= 256:
        raise ValueError('public signature bounds')
    key_hash = hashlib.sha256(public).hexdigest()
    if value.get('key_sha256') != key_hash or (original_key is not None and original_key != key_hash):
        raise ValueError('old public key identity was not retained')
    return key_hash


def parse(text, operation, nonce, setup, package, uid, expected_serial, expected_signer, expected_key=None):
    """Decode a success. Runtime controllers use assess(), which also verifies the signature."""
    value = _reply(text, -1)
    _scope(value, operation, nonce, setup, package, uid, expected_serial, expected_signer)
    fields = BASE_FIELDS | (KEY_FIELDS if operation != 'absent' else set())
    if set(value) != fields or value.get('passed') is not True or value.get('stage') != 'complete':
        raise ValueError('fixture outcome mismatch')
    if operation in ('initialize', 'absent') and any(value[name] for name in BEFORE):
        raise ValueError('initial or independent UID state was not empty')
    if operation == 'absent':
        return value
    if operation not in ('initialize', 'observe') or value.get('key_matches') is not True:
        raise ValueError('operation or key mismatch')
    if operation == 'observe':
        if not all(value[name] for name in BEFORE) or type(expected_key) is not str:
            raise ValueError('observation lacks its original key anchor or before state')
        if not re.fullmatch(r'[0-9a-f]{64}', expected_key):
            raise ValueError('original key anchor')
    _retained(value, package, uid, setup, expected_key if operation == 'observe' else None)
    return value


def assess(text, operation, nonce, setup, package, uid, expected_serial, expected_signer,
           expected_key=None, openssl='openssl'):
    value = parse(text, operation, nonce, setup, package, uid, expected_serial, expected_signer, expected_key)
    if operation != 'absent':
        verify_signature(value, nonce, openssl)
    return value


def parse_refusal(text, control, nonce, setup, package, uid, expected_serial, expected_signer,
                  original_key=None, wrong_key=None, openssl='openssl'):
    """Recognize only an exact admitted negative control, not a transport/admission failure."""
    choices = {'observe-missing': ('observe', 'observe_existing', False),
               'initialize-existing': ('initialize', 'initialize_precondition', True),
               'observe-wrong-anchor': ('observe', 'complete', True)}
    if control not in choices:
        raise ValueError('negative control')
    operation, stage, before = choices[control]
    value = _reply(text, 0)
    _scope(value, operation, nonce, setup, package, uid, expected_serial, expected_signer)
    if value.get('passed') is not False or value.get('stage') != stage or any(
            value[name] is not before for name in BEFORE):
        raise ValueError('negative control state mismatch')
    if control == 'observe-wrong-anchor':
        if (set(value) != BASE_FIELDS | KEY_FIELDS or value.get('key_matches') is not False
                or type(original_key) is not str or not re.fullmatch(r'[0-9a-f]{64}', original_key)
                or type(wrong_key) is not str or not re.fullmatch(r'[0-9a-f]{64}', wrong_key)
                or original_key == wrong_key):
            raise ValueError('negative key anchors')
        _retained(value, package, uid, setup, original_key)
        verify_signature(value, nonce, openssl)
    elif (set(value) != BASE_FIELDS | {'error_class'}
          or value['error_class'] != 'java.lang.IllegalStateException'):
        raise ValueError('negative control was not the expected refusal')
    return value


SCALARS = ('live_settings', 'authority', 'counter_known', 'cached_header', 'cached_enumeration_complete',
           'creation_ready', 'allocator_search_start', 'unidentified_code')
STATUSES = ('MISSING', 'VALID', 'DAMAGED', 'CONFLICT', 'UNSUPPORTED')
SCHEMAS = {'andrix-native-identities-v1': 1, 'andrix-native-identities-v2': 2, 'andrix-native-identities-v3': 3}
DEFERRED_MAX = 100000
COUNT = re.compile(r'0|[1-9][0-9]{0,5}')
BASE64 = re.compile(r'[A-Za-z0-9+/]+={0,2}')
SLOT_VERSIONS = ('1', '2', 'not-reported')
SLOT_STATES = ('ELIGIBLE', 'RETIRING', 'RETIRED', 'TOMBSTONE', 'not-reported')


def parse_reservations(text, schema=None):
    """Privileged cached PMS diagnostics, not a live execution/storage lease.

    The header selects the schema. Version 1 is read exactly as before and names no deferred
    package, so it never establishes a deferred set. Schema 2, the B1 dump, adds the complete
    deferred names; schema 3, which only the lifecycle format's store renders, adds one slot row per
    hold. A caller that relies on the deferred names passes the schema it requires. Either
    unavailable form raises, never an empty result."""
    if len(text) > 8 * 1024 * 1024:
        raise ValueError('reservation dump bounds')
    # The new schemas name themselves on their first LF delimited line, exactly. Any other line
    # break, such as a vertical tab or a Unicode separator, is not a line of theirs. Only a text
    # whose own historical splitting yields the version 1 header is read as version 1.
    first = text.split('\n', 1)[0]
    if first in ('andrix-native-identities-v2', 'andrix-native-identities-v3'):
        version = SCHEMAS[first]
    else:
        lines = text.splitlines()
        version = 1 if lines and lines[0] == 'andrix-native-identities-v1' else None
    if version is None:
        raise ValueError('reservation observer unavailable')
    if schema is not None and version != schema:
        raise ValueError('reservation dump schema %d where %d is required' % (version, schema))
    if version == 1:
        return _parse_reservations_v1(text)
    return _parse_reservations_v2(text, version)


def _boolean_scalars(fields):
    return all(fields[k] in ('true', 'false') for k in
               ('counter_known', 'cached_enumeration_complete', 'creation_ready', 'unidentified_code'))


def _hold(line, holds):
    row = line[len('hold='):].split('\t')
    if len(row) != 5 or not re.fullmatch(r'1[0-9]{4}', row[0]):
        raise ValueError('hold record')
    app_id = int(row[0])
    if (row[1] not in STATUSES or row[2] not in ('true', 'false')
            or row[3] not in ('empty', 'package', 'shared', 'other')):
        raise ValueError('invalid hold')
    if holds and app_id <= max(holds):
        raise ValueError('holds out of order or repeated')
    package = _base64_text(row[4], allow_empty=True)
    if (len(package.encode('utf-8')) > 255 or (row[3] == 'empty' and package)
            or (row[3] in ('package', 'shared') and not package)):
        raise ValueError('mapping name bounds')
    holds[app_id] = {'cached_slot': row[1], 'memory_pin': row[2] == 'true', 'mapping_kind': row[3], 'mapping': package}


def _base64_text(token, allow_empty=False):
    """The UTF-8 text of one canonical padded standard Base64 token."""
    if token == '' and allow_empty:
        return ''
    if not BASE64.fullmatch(token) or len(token) % 4:
        raise ValueError('not canonical Base64')
    data = base64.b64decode(token, validate=True)
    if base64.b64encode(data).decode('ascii') != token:
        raise ValueError('not canonical Base64')
    return data.decode('utf-8', errors='strict')


def _parse_reservations_v2(text, version):
    # Every rendered byte is printable ASCII, a tab between record columns, or the LF ending a line.
    if not text.endswith('\n') or any(not (' ' <= c <= '~' or c in '\t\n') for c in text):
        raise ValueError('reservation dump line form')
    lines = text[:-1].split('\n')
    if lines[0] != ('andrix-native-identities-v%d' % version):
        raise ValueError('reservation dump header')
    if lines[1:] == ['live_settings=false']:
        raise ValueError('reservation observer unavailable: no live settings')
    if lines[1:] == ['observer_available=false']:
        raise ValueError('reservation observer unavailable')
    keys = list(SCALARS) + ['deferred_count'] + (['slot_count'] if version == 3 else [])
    if len(lines) < 1 + len(keys):
        raise ValueError('reservation fields')
    fields = {}
    for key, line in zip(keys, lines[1:]):
        name, sep, value = line.partition('=')
        if name != key or not sep:
            raise ValueError('reservation fields')
        fields[key] = value
    if (fields['live_settings'] != 'true' or fields['authority'] != 'not-reported'
            or fields['cached_header'] not in STATUSES or not _boolean_scalars(fields)
            or not re.fullmatch(r'[0-9]{1,10}', fields['allocator_search_start'])
            or int(fields['allocator_search_start']) > 2147483647):
        raise ValueError('reservation state not established')
    counts = {}
    for key in keys[len(SCALARS):]:
        if not COUNT.fullmatch(fields[key]) or int(fields[key]) > DEFERRED_MAX:
            raise ValueError('reservation count')
        counts[key] = int(fields.pop(key))
    rest = lines[1 + len(keys):]
    holds, slots, names = {}, {}, []
    at = 0
    while at < len(rest) and rest[at].startswith('hold='):
        _hold(rest[at], holds)
        at += 1
    if version == 3:
        if counts['slot_count'] != len(holds):
            raise ValueError('slot count')
        for app_id in holds:
            if at >= len(rest) or not rest[at].startswith('slot='):
                raise ValueError('slot rows')
            row = rest[at][len('slot='):].split('\t')
            if (len(row) != 4 or row[0] != str(app_id) or row[1] not in SLOT_VERSIONS or row[2] not in SLOT_STATES
                    or row[3] not in ('true', 'false', 'not-reported')
                    or (('not-reported' in row[1:]) and row[1:] != ['not-reported'] * 3)
                    or (row[2] == 'TOMBSTONE' and row[3] != 'false')
                    # Positive state comes only from a selected VALID body.
                    or (holds[app_id]['cached_slot'] != 'VALID' and row[1:] != ['not-reported'] * 3)):
                raise ValueError('slot row')
            slots[app_id] = {'version': row[1], 'lifecycle': row[2], 'suspended': row[3]}
            at += 1
    while at < len(rest) and rest[at].startswith('deferred='):
        name = _base64_text(rest[at][len('deferred='):])
        units = name.encode('utf-16-be')
        if not name or len(units) // 2 > 255 or len(name.encode('utf-8')) > 1020:
            raise ValueError('deferred name bounds')
        if names and units <= names[-1].encode('utf-16-be'):
            raise ValueError('deferred names out of Java String order or repeated')
        names.append(name)
        at += 1
    if at != len(rest) or len(names) != counts['deferred_count']:
        raise ValueError('reservation records')
    value = {'fields': fields, 'holds': holds, 'schema_version': version, 'deferred_names': names}
    if version == 3:
        value['slots'] = slots
    return value


def _parse_reservations_v1(text):
    """Privileged cached PMS diagnostics, not a live execution/storage lease."""
    if len(text) > 8 * 1024 * 1024:
        raise ValueError('reservation dump bounds')
    lines = text.splitlines()
    if not lines or lines[0] != 'andrix-native-identities-v1':
        raise ValueError('reservation observer unavailable')
    fields, holds = {}, {}
    statuses = {'MISSING', 'VALID', 'DAMAGED', 'CONFLICT', 'UNSUPPORTED'}
    for line in lines[1:]:
        if line.startswith('hold='):
            row = line[5:].split('\t')
            if len(row) != 5 or not re.fullmatch(r'1[0-9]{4}', row[0]):
                raise ValueError('hold record')
            app_id = int(row[0])
            if (app_id in holds or row[1] not in statuses or row[2] not in ('true', 'false')
                    or row[3] not in ('empty', 'package', 'shared', 'other')):
                raise ValueError('duplicate or invalid hold')
            package = base64.b64decode(row[4], validate=True).decode('utf-8', errors='strict')
            if (len(package.encode('utf-8')) > 255 or (row[3] == 'empty' and package)
                    or (row[3] in ('package', 'shared') and not package)):
                raise ValueError('mapping name bounds')
            holds[app_id] = {'cached_slot': row[1], 'memory_pin': row[2] == 'true', 'mapping_kind': row[3], 'mapping': package}
        else:
            key, sep, value = line.partition('=')
            if not sep or key in fields:
                raise ValueError('reservation fields')
            fields[key] = value
    if (set(fields) != {'live_settings', 'authority', 'counter_known', 'cached_header',
                        'cached_enumeration_complete', 'creation_ready', 'allocator_search_start',
                        'unidentified_code'} or fields['live_settings'] != 'true'
            or fields['authority'] != 'not-reported' or fields['cached_header'] not in statuses
            or any(fields[k] not in ('true', 'false') for k in
                   ['counter_known', 'cached_enumeration_complete', 'creation_ready', 'unidentified_code'])
            or not re.fullmatch(r'[0-9]{1,10}', fields['allocator_search_start'])
            or int(fields['allocator_search_start']) > 2147483647):
        raise ValueError('reservation state not established')
    return {'fields': fields, 'holds': holds}


def verify_signature(value, expected_nonce, openssl='openssl'):
    """Independent public verification only. Never opens or exports a private key."""
    if value.get('nonce') != expected_nonce:
        raise ValueError('signature challenge scope mismatch')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'public.der').write_bytes(base64.b64decode(value['public_key_der_b64'], validate=True))
        (root / 'signature.der').write_bytes(base64.b64decode(value['signature_b64'], validate=True))
        (root / 'challenge').write_bytes(('Andrix UID recovery challenge/' + expected_nonce).encode())
        converted = subprocess.run([openssl, 'pkey', '-pubin', '-inform', 'DER', '-in',
                                    str(root / 'public.der'), '-out', str(root / 'public.pem')],
                                   capture_output=True, timeout=15)
        if converted.returncode:
            raise ValueError('invalid public key')
        verified = subprocess.run([openssl, 'dgst', '-sha256', '-verify', str(root / 'public.pem'),
                                   '-signature', str(root / 'signature.der'), str(root / 'challenge')],
                                  capture_output=True, timeout=15)
        if verified.returncode or verified.stdout.strip() != b'Verified OK':
            raise ValueError('independent signature verification failed')
    return True
