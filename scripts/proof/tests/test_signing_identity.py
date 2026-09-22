# SPDX-License-Identifier: Apache-2.0
"""Supplied public observations only, not signature or certificate verification."""
import base64
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signing_identity as si


class SigningIdentityTests(unittest.TestCase):
    def report(self):
        signer = {}
        for name, blob in [('certificate', b'certificate fixture'), ('spki', b'public key fixture')]:
            signer[name + '_der_base64'] = base64.b64encode(blob).decode()
            signer[name + '_der_sha256'] = si.sha256(blob)
        return {'version': 1, 'sdk': 37, 'artifact_signature_verified': True,
                'signers': [signer], 'signer_authorized': False,
                'rotation_lineage_enumerated': False}

    def test_probe_observation_retains_distinct_identity_encodings(self):
        rows = si.apk_signers(0, json.dumps(self.report()).encode(), 37)
        self.assertEqual(rows[0]['certificate']['encoding'], 'x509-der')
        self.assertEqual(rows[0]['spki']['encoding'], 'spki-der')
        self.assertNotEqual(rows[0]['certificate']['sha256'], rows[0]['spki']['sha256'])

    def test_refuse_claimed_authority_lineage_or_wrong_platform(self):
        for field, value in [('version', True), ('sdk', 38), ('signer_authorized', True),
                             ('rotation_lineage_enumerated', True),
                             ('artifact_signature_verified', False), ('new_field', 0)]:
            report = self.report(); report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                si.apk_signers(0, json.dumps(report).encode(), 37)
        with self.assertRaises(ValueError):
            si.apk_signers(1, json.dumps(self.report()).encode(), 37)

    def test_refuse_missing_repeated_malformed_or_inconsistent_signers(self):
        for change in ['empty', 'repeat', 'digest', 'base64', 'unknown']:
            report = self.report()
            if change == 'empty': report['signers'] = []
            if change == 'repeat': report['signers'] *= 2
            if change == 'digest': report['signers'][0]['certificate_der_sha256'] = '0' * 64
            if change == 'base64': report['signers'][0]['spki_der_base64'] = '!'
            if change == 'unknown': report['signers'][0]['private_key'] = 'not permitted'
            with self.subTest(change=change), self.assertRaises(ValueError):
                si.apk_signers(0, json.dumps(report).encode(), 37)

    def test_strict_json_rejects_duplicates_nonfinite_encoding_and_size(self):
        for text in [b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'[' * 1200,
                     b' ' * (si.MAX_DOCUMENT + 1)]:
            with self.assertRaises(ValueError): si.strict_json(text)

    def test_avb_encoding_is_bounded_and_not_a_certificate_identity(self):
        blob = struct.pack('!II', 4096, 0) + b'x' * 1024
        self.assertEqual(si.public_identity('avb-public-key', blob)['sha256'], si.sha256(blob))
        for value in [b'', blob[:-1], blob + b'x', struct.pack('!II', 0, 0)]:
            with self.assertRaises(ValueError): si.public_identity('avb-public-key', value)
        with self.assertRaises(ValueError): si.public_identity('private-key', blob)

    def manifest(self):
        return ('N: android=http://schemas.android.com/apk/res/android (line=19)\n'
                '  E: manifest (line=19)\n'
                '    A: http://schemas.android.com/apk/res/android:sharedUserId(0x0101000b)="android.uid.systemui" (Raw: "android.uid.systemui")\n'
                '    A: package="com.android.systemui" (Raw: "com.android.systemui")\n'
                '      E: application (line=20)\n'
                '        A: package="not.the.root" (Raw: "not.the.root")\n')

    def test_manifest_direct_attributes_not_nested_or_runtime_credentials(self):
        value = si.manifest_identity(0, self.manifest())
        self.assertEqual(value, {'package': 'com.android.systemui',
                                'shared_user_id_declaration': 'android.uid.systemui'})
        without_uid = '\n'.join(x for x in self.manifest().splitlines() if 'sharedUserId' not in x)
        self.assertIsNone(si.manifest_identity(0, without_uid)['shared_user_id_declaration'])
        for text in [self.manifest() + self.manifest(), self.manifest().replace('package="com.android.systemui"', 'package="unexpected/path"'), '']:
            with self.assertRaises(ValueError): si.manifest_identity(0, text)
        with self.assertRaises(ValueError): si.manifest_identity(1, self.manifest())

    def test_policy_observes_direct_and_package_specific_selectors(self):
        data = (b'<policy><signer signature="010203"><seinfo value="platform"/>'
                b'<package name="dev.andrix.terminal"><seinfo value="andrix_terminal"/>'
                b'</package></signer></policy>')
        rows = si.mac_signers(data)
        self.assertEqual([r['package'] for r in rows], [None, 'dev.andrix.terminal'])
        self.assertEqual(rows[0]['certificate'], si.public_identity('x509-der', b'\x01\x02\x03'))
        self.assertEqual(si.mac_signers(b'<policy/>'), [])

    def test_policy_refuses_entities_and_unsupported_selectors(self):
        for data in [b'<!DOCTYPE policy><policy/>', b'<!ENTITY x "y"><policy/>',
                     b'<policy><default/></policy>', b'<policy><signer signature="abc"/></policy>',
                     b'<policy><signer signature="00"><package name="x"/></signer></policy>']:
            with self.assertRaises(ValueError): si.mac_signers(data)


if __name__ == '__main__': unittest.main()
