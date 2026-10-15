#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""B2 fixture contracts and independently verified, challenge bound replies. No guest I/O."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

PACKAGE = 'dev.andrix.proof.principalclosed'
SIGNER = '874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3'
SERVICE = PACKAGE + '.B2StateJobService'
CHANNEL = 'andrix.b2.state'
SETUP_MAIN = 'dev.andrix.proof.b2setup.NotificationSetup'
SETUP_JAR = '/data/local/tmp/andrix-b2-notification-setup.jar'
NOTIFICATION_SETUP = 'channel-bubbles-copy-v1'
JOB_ID = 21802
LATENCY = 2592000000
TRIAL_LIMIT = 604800000
BEFORE = ('key0_existed_before', 'key1_existed_before', 'ce_existed_before',
          'de_existed_before', 'intent_existed_before')
PAYLOAD_FIELDS = (
    'version', 'operation', 'nonce', 'setup', 'contract_sha256', 'phase',
    'guest_binding_sha256', 'package', 'uid', 'user_serial', 'apk_signer_sha256',
    'pid', 'elapsed_ms', 'user_unlocked', *BEFORE, 'key0_sha256',
    'key1_sha256', 'ce_sha256', 'de_sha256', 'intent_sha256', 'post_notifications_granted',
    'job_id', 'job_namespace', 'job_service', 'job_persisted', 'job_periodic',
    'job_min_latency_ms', 'job_max_delay_ms', 'job_setup', 'job_contract_sha256',
    'stage', 'passed')
BINARY_FIELDS = {f'key{i}_{suffix}' for i in range(2)
                 for suffix in ('spki_b64', 'signature_b64')}
BOOL_FIELDS = {*BEFORE, 'user_unlocked', 'post_notifications_granted', 'job_persisted',
               'job_periodic', 'passed'}
INT_FIELDS = {'version', 'uid', 'user_serial', 'pid', 'elapsed_ms', 'job_id',
              'job_min_latency_ms', 'job_max_delay_ms'}
HEX_FIELDS = {'contract_sha256', 'guest_binding_sha256', 'apk_signer_sha256',
              'key0_sha256', 'key1_sha256', 'ce_sha256', 'de_sha256', 'intent_sha256',
              'job_contract_sha256'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex_value(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def strict_json(data):
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'nonfinite JSON'))


def make_contract(uid, serial, setup, ce_token, de_token):
    require(type(uid) is int and 10000 <= uid <= 19999, 'user zero application UID')
    require(type(serial) is int and 0 <= serial < 1 << 63, 'user serial')
    require(all(hex_value(x, 32) for x in (setup, ce_token, de_token))
            and ce_token != de_token, 'independent dummy tokens')

    def canary(storage, token):
        return (f'andrix-b2-canary-v1\nstorage={storage}\npackage={PACKAGE}\nuid={uid}\n'
                f'user_serial={serial}\nsetup={setup}\ntoken={token}\n').encode('ascii')

    ce, de = canary('CE', ce_token), canary('DE', de_token)
    contract = (f'andrix-b2-contract-v1\npackage={PACKAGE}\nuid={uid}\nuser_serial={serial}\n'
                f'apk_signer_sha256={SIGNER}\nsetup={setup}\nkey0_alias=andrix_b2_state_ec0\n'
                f'key1_alias=andrix_b2_state_ec1\nce_sha256={sha(ce)}\nde_sha256={sha(de)}\n'
                'permission=android.permission.POST_NOTIFICATIONS\npermission_flags=48\n'
                'package_appop=android:vibrate:1\nuid_appop=android:vibrate:default\n'
                'notification_setup=channel-bubbles-copy-v1\n'
                f'channel=andrix.b2.state:2:1:256\nchannel_audio=5:4:0\njob=21802:{PACKAGE}/{SERVICE}'
                ':null:2592000000\ntrial_limit_ms=604800000\n').encode('ascii')
    digest = sha(contract)
    intent = (f'andrix-b2-setup-v1\npackage={PACKAGE}\nuid={uid}\nuser_serial={serial}\n'
              f'setup={setup}\ncontract_sha256={digest}\nce_sha256={sha(ce)}\n'
              f'de_sha256={sha(de)}\n').encode('ascii')
    return {'uid': uid, 'serial': serial, 'setup': setup, 'ce_token': ce_token,
            'de_token': de_token, 'contract_sha256': digest, 'ce_sha256': sha(ce),
            'de_sha256': sha(de), 'intent_sha256': sha(intent), 'ce_bytes': ce,
            'de_bytes': de, 'intent_bytes': intent, 'contract_bytes': contract}


def validate_contract(contract):
    require(type(contract) is dict, 'contract type')
    expected = make_contract(*(contract.get(k) for k in
                              ('uid', 'serial', 'setup', 'ce_token', 'de_token')))
    require(contract == expected, 'contract changed or unexpected fields')


def payload(value):
    return ('andrix-b2-state-v1\n' + ''.join(
        name + '=' + (str(value[name]).lower() if type(value[name]) is bool else str(value[name]))
        + '\n' for name in PAYLOAD_FIELDS)).encode('ascii')


def _binary(value, name):
    text = value[name]
    require(type(text) is str and len(text) <= 1024, 'base64 bounds')
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError('base64 encoding') from error
    require(base64.b64encode(data).decode() == text, 'noncanonical base64')
    return data


def _ecdsa_der(data):
    # P-256 signatures: one definite short sequence, two canonical positive INTEGERs.
    require(8 <= len(data) <= 72 and data[0] == 0x30 and data[1] == len(data) - 2,
            'ECDSA DER sequence')
    pos = 2
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    for _ in range(2):
        require(pos + 2 <= len(data) and data[pos] == 2, 'ECDSA INTEGER')
        size = data[pos + 1]
        number = data[pos + 2:pos + 2 + size]
        require(1 <= size <= 33 and len(number) == size and number[0] < 128
                and not (size > 1 and number[0] == 0 and number[1] < 128)
                and 0 < int.from_bytes(number, 'big') < order, 'ECDSA scalar')
        pos += size + 2
    require(pos == len(data), 'ECDSA trailing data')


def assess_reply(stdout, stderr, exit_code, contract, operation, nonce, phase, guest_binding,
                 expected_keys=None, openssl='openssl'):
    """Success only. Raises on unavailable/failed observations, never invents an empty fact set.

    expected_keys are the TWO original independently verified setup digests, never reply defaults.
    OpenSSL verifies both signatures; no caller option can disable signature verification.
    """
    validate_contract(contract)
    require(stderr == '' and type(exit_code) is int and exit_code == 0, 'instrument transport')
    require(type(stdout) is str and len(stdout) <= 32768 and stdout.endswith('\n'), 'reply bounds')
    lines = stdout.split('\n')
    prefix = 'INSTRUMENTATION_RESULT: b2_state_result='
    require(len(lines) == 3 and lines[0].startswith(prefix)
            and lines[1] == 'INSTRUMENTATION_CODE: -1' and lines[2] == '', 'reply envelope')
    value = strict_json(lines[0][len(prefix):])
    require(type(value) is dict and set(value) == set(PAYLOAD_FIELDS) | BINARY_FIELDS,
            'reply fields')
    require(operation in ('initialize', 'observe') and hex_value(nonce, 32)
            and type(phase) is str and re.fullmatch('[a-z][a-z0-9_]{0,47}', phase)
            and hex_value(guest_binding), 'challenge binding')
    for name in BOOL_FIELDS:
        require(type(value[name]) is bool, 'boolean type: ' + name)
    for name in INT_FIELDS:
        require(type(value[name]) is int and 0 <= value[name] < 1 << 63, 'integer type: ' + name)
    for name in HEX_FIELDS:
        require(hex_value(value[name]), 'digest type: ' + name)
    fixed = {'version': 1, 'operation': operation, 'nonce': nonce, 'setup': contract['setup'],
             'contract_sha256': contract['contract_sha256'], 'phase': phase,
             'guest_binding_sha256': guest_binding, 'package': PACKAGE, 'uid': contract['uid'],
             'user_serial': contract['serial'], 'apk_signer_sha256': SIGNER,
             'user_unlocked': True, 'ce_sha256': contract['ce_sha256'],
             'de_sha256': contract['de_sha256'], 'intent_sha256': contract['intent_sha256'],
             'post_notifications_granted': operation == 'observe', 'job_id': JOB_ID,
             'job_namespace': 'null', 'job_service': SERVICE, 'job_persisted': True,
             'job_periodic': False, 'job_max_delay_ms': 0, 'job_setup': contract['setup'],
             'job_contract_sha256': contract['contract_sha256'], 'stage': 'complete', 'passed': True}
    require(all(value[k] == v for k, v in fixed.items()), 'identity or retained state mismatch')
    require(value['pid'] > 0 and 0 < value['job_min_latency_ms'] <= LATENCY + 60000,
            'process or delayed job bounds')
    require(all(value[k] is (operation == 'observe') for k in BEFORE), 'before state')
    if operation == 'observe':
        require(type(expected_keys) in (tuple, list) and len(expected_keys) == 2
                and all(hex_value(k) for k in expected_keys) and expected_keys[0] != expected_keys[1],
                'two original key anchors required')
    else:
        require(expected_keys is None, 'initialize must not borrow key anchors')
    require(value['key0_sha256'] != value['key1_sha256'], 'distinct keys')
    signed = payload(value)
    with tempfile.TemporaryDirectory(prefix='b2-verify-') as directory:
        root = Path(directory)
        (root / 'payload').write_bytes(signed)
        for i in range(2):
            public = _binary(value, f'key{i}_spki_b64')
            signature = _binary(value, f'key{i}_signature_b64')
            # Exact id-ecPublicKey / prime256v1 SubjectPublicKeyInfo with uncompressed point.
            require(len(public) == 91 and public[:27] == bytes.fromhex(
                '3059301306072a8648ce3d020106082a8648ce3d03010703420004'), 'P-256 SPKI')
            require(sha(public) == value[f'key{i}_sha256']
                    and (operation != 'observe' or sha(public) == expected_keys[i]),
                    'original key identity')
            _ecdsa_der(signature)
            (root / 'key.pem').write_text('-----BEGIN PUBLIC KEY-----\n'
                                         + base64.b64encode(public).decode()
                                         + '\n-----END PUBLIC KEY-----\n', encoding='ascii')
            (root / 'signature').write_bytes(signature)
            result = subprocess.run([openssl, 'dgst', '-sha256', '-verify', str(root / 'key.pem'),
                                     '-signature', str(root / 'signature'), str(root / 'payload')],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'TMPDIR': str(root)})
            require(result.returncode == 0 and result.stdout == b'Verified OK\n'
                    and result.stderr == b'', 'independent ECDSA verification')
    return value


def instrumentation_argv(contract, operation, nonce, phase, guest_binding, expected_keys=None):
    """Return argv for a separately authorized vehicle. Never executes it."""
    validate_contract(contract)
    require(operation in ('initialize', 'observe') and hex_value(nonce, 32)
            and type(phase) is str and re.fullmatch('[a-z][a-z0-9_]{0,47}', phase)
            and hex_value(guest_binding), 'request binding')
    values = {'operation': operation, 'nonce': nonce, 'setup': contract['setup'],
              'contract_sha256': contract['contract_sha256'], 'phase': phase,
              'guest_binding_sha256': guest_binding, 'expected_uid': str(contract['uid']),
              'expected_serial': str(contract['serial']), 'ce_token': contract['ce_token'],
              'de_token': contract['de_token']}
    if operation == 'observe':
        require(type(expected_keys) in (tuple, list) and len(expected_keys) == 2
                and all(hex_value(k) for k in expected_keys) and expected_keys[0] != expected_keys[1],
                'original key anchors')
        values.update(expected_key0=expected_keys[0], expected_key1=expected_keys[1])
    else:
        require(expected_keys is None, 'initialize key anchors')
    argv = ['am', 'instrument', '-w', '-r', '--user', '0', '--no-test-api-access',
            '--always-check-signature']
    for name, value in values.items():
        argv += ['-e', name, value]
    return argv + [PACKAGE + '/.B2StateInstrumentation']


def notification_preference(stage):
    """Only the retained state qualifies preservation; created is setup precondition only."""
    require(type(stage) is str and stage in ('created', 'retained'), 'channel preference stage')
    return (1, 256) if stage == 'retained' else (-1, 0)


def notification_setup_argv(contract, nonce):
    """Setup only as shell, never root or the target UID. No command is executed here."""
    validate_contract(contract)
    require(hex_value(nonce, 32), 'owned setup nonce')
    return ['env', 'CLASSPATH=' + SETUP_JAR, 'app_process', '/system/bin', SETUP_MAIN,
            str(contract['uid']), nonce, contract['setup'], contract['contract_sha256']]


def setup_commands(contract, nonce):
    return [
        ['pm', 'grant', '--user', '0', PACKAGE, 'android.permission.POST_NOTIFICATIONS'],
        ['pm', 'set-permission-flags', '--user', '0', PACKAGE,
         'android.permission.POST_NOTIFICATIONS', 'user-set'],
        ['cmd', 'appops', 'set', '--user', '0', PACKAGE, 'VIBRATE', 'ignore'],
        notification_setup_argv(contract, nonce)]
