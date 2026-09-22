# SPDX-License-Identifier: Apache-2.0
"""Manifest binding/model checks. Real encryption and key checks run separately."""
import base64
import copy
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signing_recovery as sr


class SigningRecoveryTests(unittest.TestCase):
    def manifest(self):
        cert = b'certificate fixture'
        return {'version': 1, 'installation': '69ea1c46-f5fa-4bd7-a3ab-d15c20d0493e',
                'generation': 1,
                'keys': [{'slot': 'platform', 'spki': base64.b64encode(b'spki fixture').decode(),
                          'certificates': [base64.b64encode(cert).decode()], 'avb_public_key': None}],
                'uses': [{'purpose': 'apk', 'component': 'platform', 'slot': 'platform',
                          'identity': {'encoding': 'x509-der', 'sha256': sr.digest(cert)}}]}

    def test_commitment_binds_public_identities_roles_and_installation(self):
        original = self.manifest(); value = sr.validate_manifest(original)
        for field, replacement in [('generation', 2), ('installation', '69ea1c46-f5fa-4bd7-a3ab-d15c20d0493f')]:
            modified = copy.deepcopy(original); modified[field] = replacement
            self.assertNotEqual(value, sr.validate_manifest(modified))
        modified = copy.deepcopy(original); modified['uses'][0]['purpose'] = 'ota-package'
        self.assertNotEqual(value, sr.validate_manifest(modified))
        self.assertEqual(value, sr.validate_manifest(dict(reversed(list(original.items())))))

    def test_wrong_role_encoding_or_foreign_reference_is_refused(self):
        for field, value in [('purpose', 'root-shell'), ('purpose', 'avb'), ('slot', 'another'),
                             ('component', '../../platform')]:
            manifest = self.manifest(); manifest['uses'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(sr.RecoveryError):
                sr.validate_manifest(manifest)
        manifest = self.manifest(); manifest['uses'][0]['identity']['sha256'] = '0' * 64
        with self.assertRaises(sr.RecoveryError): sr.validate_manifest(manifest)

    def test_duplicates_unused_keys_and_unknown_fields_are_refused(self):
        for change in ['key', 'use', 'alias', 'unbound', 'field']:
            manifest = self.manifest()
            if change == 'key': manifest['keys'] *= 2
            if change == 'use': manifest['uses'] *= 2
            if change in ['alias', 'unbound']:
                key = copy.deepcopy(manifest['keys'][0]); key['slot'] = 'extra'
                if change == 'unbound': key['spki'] = base64.b64encode(b'other').decode()
                manifest['keys'].append(key)
            if change == 'field': manifest['private_keys'] = {}
            with self.subTest(change=change), self.assertRaises(sr.RecoveryError):
                sr.validate_manifest(manifest)

    def test_types_versions_and_parser_bounds_are_refused(self):
        for field, value in [('version', True), ('version', 2), ('generation', True),
                             ('generation', 0), ('generation', 1 << 63), ('keys', []),
                             ('uses', []), ('installation', 'not-a-uuid')]:
            manifest = self.manifest(); manifest[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(sr.RecoveryError):
                sr.validate_manifest(manifest)
        manifest = self.manifest(); manifest['keys'][0]['spki'] = 'A' * (sr.MAX_DOCUMENT + 1)
        with self.assertRaises(sr.RecoveryError): sr.validate_manifest(manifest)

    def test_certificate_and_avb_encodings_are_not_interchangeable(self):
        manifest = self.manifest(); key = manifest['keys'][0]
        blob = struct.pack('!II', 4096, 0) + b'x' * 1024
        key['avb_public_key'] = base64.b64encode(blob).decode()
        manifest['uses'].append({'purpose': 'apex-payload', 'component': 'usr', 'slot': 'platform',
                                 'identity': {'encoding': 'avb-public-key', 'sha256': sr.digest(blob)}})
        sr.validate_manifest(manifest)
        manifest['uses'][1]['identity']['encoding'] = 'x509-der'
        with self.assertRaises(sr.RecoveryError): sr.validate_manifest(manifest)

    def test_native_credentials_only_no_plugins_or_ambiguous_identity_files(self):
        sr._native_recipient('age1' + 'q' * 58)
        sr._native_recipient('age1pq1' + 'q' * 1952)
        secret = b'AGE-SECRET-KEY-1' + b'Q' * 58
        self.assertEqual(sr._native_identity(b'# comment\n' + secret + b'\n'), secret + b'\n')
        for value in [b'AGE-PLUGIN-TEST-1ABC', secret + b'\n' + secret, b'\xff', b'']:
            with self.assertRaises(sr.RecoveryError): sr._native_identity(value)
        for value in ['ssh-ed25519 AAA', 'age1plugin1' + 'q' * 58, 'age1' + 'q' * 57]:
            with self.assertRaises(sr.RecoveryError): sr._native_recipient(value)

    def test_expected_commitment_required_before_decryption(self):
        class Never:
            def _run(self, *args, **kwargs): raise AssertionError('must not run')
        for digest in [None, '', '0' * 63, 'A' * 64]:
            with self.assertRaises(sr.RecoveryError):
                sr.decrypt_bundle(b'ciphertext', b'identity', digest, Never())

    def test_failed_complete_decryption_does_not_parse_partial_plaintext(self):
        class Failed:
            age = Path('/not-executed')
            def _run(self, *args, **kwargs): raise sr.RecoveryError('Cryptographic operation refused')
        secret = b'AGE-SECRET-KEY-1' + b'Q' * 58
        with patch.object(sr, 'strict_json', side_effect=AssertionError('must not parse')):
            with self.assertRaises(sr.RecoveryError): sr.decrypt_bundle(b'ciphertext', secret, '0' * 64, Failed())

    def test_successful_decrypt_is_not_sufficient_for_recovery(self):
        class Supplied:
            age = Path('/not-executed')
            def __init__(self, body): self.body = body
            def _run(self, *args, **kwargs): return self.body
        secret = b'AGE-SECRET-KEY-1' + b'Q' * 58
        manifest = self.manifest(); expected = sr.validate_manifest(manifest)
        swapped = copy.deepcopy(manifest); swapped['uses'][0]['purpose'] = 'ota-package'
        data = {'version': 1, 'manifest': swapped, 'private_keys': {'platform': 'eA=='}}
        with self.assertRaisesRegex(sr.RecoveryError, 'Unexpected installation'):
            sr.decrypt_bundle(b'ciphertext', secret, expected, Supplied(sr.canonical(data)))
        data['manifest'] = manifest; data['private_keys'] = {}
        with self.assertRaisesRegex(sr.RecoveryError, 'Incomplete'):
            sr.decrypt_bundle(b'ciphertext', secret, expected, Supplied(sr.canonical(data)))

    def test_private_material_is_not_in_result_representation(self):
        result = sr.Recovered(self.manifest(), {'platform': b'NEVER_PRINT_THIS_SECRET'})
        self.assertNotIn('NEVER_PRINT_THIS_SECRET', repr(result))


if __name__ == '__main__': unittest.main()
