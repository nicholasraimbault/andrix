# SPDX-License-Identifier: Apache-2.0
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PATH = Path(__file__).with_name('observe.py')
spec = importlib.util.spec_from_file_location('identity_observe', PATH)
observe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observe)
PACKAGE = 'dev.andrix.proof.uidstore'
UID = 10123
SIGNER = 'c' * 64


def result(operation='observe'):
    value = {'version': 1, 'operation': operation, 'nonce': 'observe_1', 'setup': 'setup_1',
             'package': PACKAGE, 'apk_signer_sha256': SIGNER, 'user_serial': 7, 'uid': UID, 'pid': 123, 'elapsed_ms': 456, 'user_unlocked': True,
             'key_existed_before': operation == 'observe',
             'ce_existed_before': operation == 'observe', 'de_existed_before': operation == 'observe',
             'stage': 'complete', 'passed': True}
    if operation != 'absent':
        public = b'controlled public-key parser input, not a private key'
        canary = f'Andrix dummy UID recovery canary\n{PACKAGE}\n{UID}\nsetup_1\n'.encode()
        value.update({'ce_matches': True, 'de_matches': True, 'key_matches': True,
                      'signature_verified': True, 'ce_sha256': hashlib.sha256(canary).hexdigest(),
                      'de_sha256': hashlib.sha256(canary).hexdigest(),
                      'key_sha256': hashlib.sha256(public).hexdigest(),
                      'public_key_der_b64': base64.b64encode(public).decode(),
                      'signature_b64': base64.b64encode(b'dummy signature parser bytes').decode()})
    return value


def wire(value, code=-1):
    return observe.PREFIX + json.dumps(value) + '\nINSTRUMENTATION_CODE: ' + str(code) + '\n'


def parse(value, text=None):
    return observe.parse(text or wire(value), value['operation'], 'observe_1', 'setup_1', PACKAGE,
                         UID, 7, SIGNER, result().get('key_sha256'))


class ObservationTests(unittest.TestCase):
    def test_exact_identity_and_modes(self):
        for mode in ('initialize', 'observe', 'absent'):
            value = result(mode)
            self.assertEqual(parse(value), value)

    def test_absence_or_failed_transport_is_not_quarantine_proof(self):
        for text in ('', 'INSTRUMENTATION_FAILED: package unavailable\n', 'Error: device offline\n',
                     wire(result()).replace('CODE: -1', 'CODE: 0'), wire(result()) * 2):
            with self.assertRaises(ValueError):
                observe.parse(text, 'observe', 'observe_1', 'setup_1', PACKAGE, UID, 7, SIGNER,
                              result()['key_sha256'])

    def test_wrong_scope_or_fabricated_success_refused(self):
        for name, changed in [('nonce', 'other'), ('setup', 'other'), ('package', PACKAGE + 'peer'),
                              ('apk_signer_sha256', 'd' * 64), ('user_serial', 8), ('user_serial', True), ('uid', UID + 1), ('uid', True), ('pid', 0), ('passed', 1),
                              ('stage', 'key_generation'), ('user_unlocked', False),
                              ('key_matches', False), ('ce_matches', False), ('de_matches', False),
                              ('signature_verified', False), ('key_existed_before', False),
                              ('key_sha256', '0' * 64), ('ce_sha256', '0' * 64),
                              ('signature_b64', '!bad'), ('extra_data', 'not authorized')]:
            value = result(); value[name] = changed
            with self.subTest(name=name, value=changed), self.assertRaises(ValueError):
                parse(value)
        for mode in ('initialize', 'absent'):
            value = result(mode); value['key_existed_before'] = True
            with self.assertRaises(ValueError): parse(value)

    def test_duplicates_and_missing_fields_refused(self):
        text = wire(result()).replace('"passed": true', '"passed": true, "passed": true')
        with self.assertRaises(ValueError): parse(result(), text)
        for name in result():
            value = result(); del value[name]
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError)):
                # Expected operation is fixed by the controller, not missing reply data.
                observe.parse(wire(value), 'observe', 'observe_1', 'setup_1', PACKAGE, UID, 7, SIGNER,
                              result()['key_sha256'])

    def test_self_consistent_replacement_key_cannot_replace_anchor(self):
        value = result()
        new_public = b'a different internally consistent public key fixture'
        value['public_key_der_b64'] = base64.b64encode(new_public).decode()
        value['key_sha256'] = hashlib.sha256(new_public).hexdigest()
        value['key_matches'] = True
        with self.assertRaises(ValueError): parse(value)
        with self.assertRaises(ValueError):
            observe.parse(wire(result()), 'observe', 'observe_1', 'setup_1', PACKAGE,
                          UID, 7, SIGNER, None)

    def test_expected_refusals_are_distinct_from_transport_loss(self):
        for control, operation, stage, before in [
                ('observe-missing', 'observe', 'observe_existing', False),
                ('initialize-existing', 'initialize', 'initialize_precondition', True)]:
            value = result(operation)
            for name in observe.KEY_FIELDS: value.pop(name, None)
            value.update({'stage': stage, 'passed': False, 'error_class': 'java.lang.IllegalStateException'})
            for name in observe.BEFORE: value[name] = before
            self.assertEqual(observe.parse_refusal(wire(value, 0), control, 'observe_1', 'setup_1',
                                                  PACKAGE, UID, 7, SIGNER), value)
            for text in ('', wire(value), wire(value, 0) * 2,
                         wire(value, 0).replace(stage, 'key_generation'),
                         wire(value, 0).replace('java.lang.IllegalStateException', 'java.io.IOException')):
                with self.assertRaises(ValueError):
                    observe.parse_refusal(text, control, 'observe_1', 'setup_1', PACKAGE, UID, 7, SIGNER)

    def test_cached_reservation_dump_is_explicit_not_live_authority(self):
        text = ('andrix-native-identities-v1\nlive_settings=true\nauthority=not-reported\n'
                'counter_known=true\ncached_header=VALID\ncached_enumeration_complete=true\n'
                'creation_ready=true\nallocator_search_start=10000\nunidentified_code=false\n'
                'hold=10123\tVALID\ttrue\tpackage\t' + base64.b64encode(PACKAGE.encode()).decode() + '\n')
        value = observe.parse_reservations(text)
        self.assertEqual(value['holds'][10123]['mapping'], PACKAGE)
        for bad in ('', 'Permission Denial\n', text + text.splitlines()[-1] + '\n',
                    text.replace('authority=not-reported', 'authority=true'),
                    text.replace('allocator_search_start=10000', 'allocator_search_start=-1'),
                    text.replace('hold=10123', 'hold=20000'), text + 'unknown=1\n',
                    text.replace('\tpackage\t', '\tinvalid\t'),
                    text.replace('\tpackage\t', '\tempty\t')):
            with self.assertRaises(ValueError): observe.parse_reservations(bad)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for independent public verification')
    def test_real_signature_and_changed_challenge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-out', str(root / 'fixture-key.pem')],
                           check=True, capture_output=True, timeout=15)
            subprocess.run(['openssl', 'pkey', '-in', str(root / 'fixture-key.pem'), '-pubout',
                            '-outform', 'DER', '-out', str(root / 'public.der')],
                           check=True, capture_output=True, timeout=15)
            challenge = root / 'challenge'
            challenge.write_bytes(b'Andrix UID recovery challenge/observe_1')
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(root / 'fixture-key.pem'),
                            '-out', str(root / 'signature.der'), str(challenge)],
                           check=True, capture_output=True, timeout=15)
            value = result()
            value['public_key_der_b64'] = base64.b64encode((root / 'public.der').read_bytes()).decode()
            value['signature_b64'] = base64.b64encode((root / 'signature.der').read_bytes()).decode()
            value['key_sha256'] = hashlib.sha256((root / 'public.der').read_bytes()).hexdigest()
            original = value['key_sha256']
            self.assertTrue(observe.verify_signature(value, 'observe_1'))
            self.assertEqual(observe.assess(wire(value), 'observe', 'observe_1', 'setup_1', PACKAGE,
                                           UID, 7, SIGNER, original), value)
            changed = copy.deepcopy(value); changed['nonce'] = 'changed'
            with self.assertRaises(ValueError): observe.verify_signature(changed, 'observe_1')
            with self.assertRaises(ValueError): observe.verify_signature(changed, 'changed')
            changed = copy.deepcopy(value); changed['signature_b64'] = base64.b64encode(b'x' * 70).decode()
            with self.assertRaises(ValueError):
                observe.assess(wire(changed), 'observe', 'observe_1', 'setup_1', PACKAGE,
                               UID, 7, SIGNER, original)
            refused = copy.deepcopy(value); refused.update({'passed': False, 'key_matches': False})
            self.assertEqual(observe.parse_refusal(wire(refused, 0), 'observe-wrong-anchor',
                                                  'observe_1', 'setup_1', PACKAGE, UID, 7, SIGNER,
                                                  original, '0' * 64), refused)


if __name__ == '__main__':
    unittest.main()
