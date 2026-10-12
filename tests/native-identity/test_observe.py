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

    def test_schema_two_names_every_deferred_package_and_schema_three_its_slots(self):
        b64 = lambda name: base64.b64encode(name.encode()).decode()
        scalars = ('live_settings=true\nauthority=not-reported\ncounter_known=true\ncached_header=VALID\n'
                   'cached_enumeration_complete=true\ncreation_ready=true\nallocator_search_start=10000\n'
                   'unidentified_code=false\n')
        names = sorted(['dev.b', 'Z', 'café', 'line\nbreak', 'smile\U0001F600'], key=lambda n: n.encode('utf-16-be'))
        hold = 'hold=10123\tVALID\ttrue\tpackage\t' + b64(PACKAGE) + '\n'
        two = ('andrix-native-identities-v2\n' + scalars + 'deferred_count=%d\n' % len(names) + hold
               + ''.join('deferred=' + b64(name) + '\n' for name in names))
        value = observe.parse_reservations(two, schema=2)
        self.assertEqual((value['schema_version'], value['deferred_names']), (2, names))
        self.assertEqual(set(value['fields']), set(observe.SCALARS))
        self.assertEqual(value['holds'][10123]['mapping'], PACKAGE)
        empty = 'andrix-native-identities-v2\n' + scalars + 'deferred_count=0\n'
        self.assertEqual(observe.parse_reservations(empty)['deferred_names'], [])
        three = ('andrix-native-identities-v3\n' + scalars + 'deferred_count=0\nslot_count=2\n'
                 + hold + 'hold=10124\tDAMAGED\tfalse\tempty\t\n'
                 + 'slot=10123\t2\tELIGIBLE\ttrue\nslot=10124\tnot-reported\tnot-reported\tnot-reported\n')
        value = observe.parse_reservations(three, schema=3)
        self.assertEqual(value['slots'][10123], {'version': '2', 'lifecycle': 'ELIGIBLE', 'suspended': 'true'})
        # A version 1 dump is read exactly as before and never stands for a deferred set.
        one = ('andrix-native-identities-v1\n' + scalars + hold)
        self.assertEqual(set(observe.parse_reservations(one)), {'fields', 'holds'})
        for bad, required in ((one, 2), (three, 2), (two, 3)):
            with self.assertRaises(ValueError):
                observe.parse_reservations(bad, schema=required)
        refused = [
            one.replace(hold, 'deferred_count=0\n' + hold),                      # a new field under version 1
            'andrix-native-identities-v2\nlive_settings=false\n',               # not live
            'andrix-native-identities-v3\nobserver_available=false\n',          # unavailable
            'andrix-native-identities-v2\nlive_settings=false\nhold=x\n',      # a record after an arm
            two.replace('deferred_count=%d' % len(names), 'deferred_count=%d' % (len(names) - 1)),
            two.replace('deferred_count=%d' % len(names), 'deferred_count=05'),
            two.replace('deferred=' + b64(names[0]) + '\n', ''),                # a missing name
            two + 'deferred=' + b64(names[-1]) + '\n',                            # a repeated name, count aside
            two.replace('deferred=' + b64(names[1]), 'deferred=' + b64(names[1]).rstrip('=')),
            two.replace('deferred=' + b64(names[0]), 'deferred=ZGV2LmI_'),        # the URL safe alphabet
            two.replace('deferred=' + b64(names[0]), 'deferred=' + b64(names[0]) + '===='),  # extra padding
            two.replace('deferred=' + b64(names[0]), 'deferred=' + base64.b64encode(b'\xff').decode()),
            two.replace('deferred=' + b64(names[0]), 'deferred='),
            two.replace('deferred=' + b64(names[0]), 'deferred=' + b64('x' * 256)),
            two[:-1],                                                               # no last line end
            two.replace('\n', '\r\n'),
            two.replace('counter_known=true\ncached_header=VALID', 'cached_header=VALID\ncounter_known=true'),
            two.replace(hold, hold + 'unknown=1\n'),
            two + 'hold=10200\tVALID\ttrue\tpackage\t' + b64('dev.c') + '\n',
            two.replace(hold, 'hold=10124\tVALID\ttrue\tpackage\t' + b64('dev.c') + '\n' + hold),
            three.replace('slot_count=2', 'slot_count=1'),
            three.replace('slot=10124\tnot-reported\tnot-reported\tnot-reported', 'slot=10124\t2\tnot-reported\tfalse'),
            three.replace('slot=10123\t2\tELIGIBLE\ttrue', 'slot=10123\t2\tTOMBSTONE\ttrue'),
            three.replace('slot=10123\t2', 'slot=10124\t2'),
        ]
        # A first line that only another line break ends, followed by an unavailable record, is not
        # a header; nor is any byte outside printable ASCII, tab and LF.
        live = 'andrix-native-identities-v2\n' + scalars + 'deferred_count=0\n'
        for separator in ('\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029', '\r'):
            refused.append(live.replace('andrix-native-identities-v2\n',
                                        'andrix-native-identities-v2' + separator + 'observer_available=false\n', 1))
            refused.append(live.replace('creation_ready=true', 'creation_ready=true' + separator))
        refused.append(live.replace('andrix-native-identities-v2', 'andrix-native-identities-v2 ', 1))
        # Schema 3 reports positive lifecycle state only for a VALID hold.
        refused.append(three.replace('slot=10124\tnot-reported\tnot-reported\tnot-reported', 'slot=10124\t2\tELIGIBLE\ttrue'))
        for bad in refused:
            with self.subTest(bad=bad[-60:]), self.assertRaises(ValueError):
                observe.parse_reservations(bad)
        self.assertEqual(observe.parse_reservations(live)['deferred_names'], [])
        # The order of the names is Java String order, by UTF-16 code units, not code points.
        swapped = sorted(['\uFFFD', '\U0001F600'], key=lambda n: n.encode('utf-16-be'))
        self.assertEqual(swapped, ['\U0001F600', '\uFFFD'])
        java = ('andrix-native-identities-v2\n' + scalars + 'deferred_count=2\n'
                + ''.join('deferred=' + b64(name) + '\n' for name in swapped))
        self.assertEqual(observe.parse_reservations(java)['deferred_names'], swapped)
        reversed_ = ('andrix-native-identities-v2\n' + scalars + 'deferred_count=2\n'
                     + ''.join('deferred=' + b64(name) + '\n' for name in reversed(swapped)))
        with self.assertRaises(ValueError):
            observe.parse_reservations(reversed_)

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
