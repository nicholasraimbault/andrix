# SPDX-License-Identifier: Apache-2.0
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from apex_inventory import debugfs_directory, lineage_observation


class ApexInventoryTests(unittest.TestCase):
    def directory(self):
        return ('/33/040755/0/2000/.//\n/2/040755/1000/1000/..//\n'
                '/34/040755/0/2000/PermissionController@CP2A.260605.016//\n'
                '/35/100644/1000/1000/Test.apk/128/\n'
                '/36/120777/1000/1000/alias.apk/8/\n')

    def test_observed_directory_shape_preserves_types_and_image_owners(self):
        row = debugfs_directory(0, self.directory(), 'debugfs 1.47.0 (5-Feb-2023)\n')
        self.assertEqual((row.inode, row.parent_inode), (33, 2))
        self.assertEqual([entry.kind for entry in row.entries], ['directory', 'file', 'symlink'])
        self.assertEqual(row.entries[1].size, 128)
        self.assertEqual(row.entries[1].uid, 1000)
        self.assertIsNone(row.entries[0].size)

    def test_zero_exit_error_missing_identity_and_duplicate_are_not_empty(self):
        for code, text, error in [(1, self.directory(), ''),
                                  (0, self.directory(), 'debugfs: File not found by ext2_lookup\n'),
                                  (0, '', ''), (0, self.directory().replace('/33/040755/0/2000/.//\n', ''), ''),
                                  (0, self.directory() + '/40/100644/0/0/Test.apk/1/\n', '')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                debugfs_directory(code, text, error)

    def test_unsupported_command_names_or_bad_modes_fail_closed(self):
        for changed in [self.directory().replace('Test.apk', 'a b.apk'),
                        self.directory().replace('Test.apk', 'bad"name.apk'),
                        self.directory().replace('Test.apk', '<2>'),
                        self.directory().replace('/128/', '/-1/'),
                        self.directory().replace('100644', '100888'),
                        self.directory().replace('/128/', '//')]:
            with self.subTest(text=changed), self.assertRaises(ValueError):
                debugfs_directory(0, changed, '')

    def identity(self, certificate=b'public certificate', spki=b'public key'):
        return {'certificate_sha256': hashlib.sha256(certificate).hexdigest(),
                'spki_sha256': hashlib.sha256(spki).hexdigest(),
                'certificate_der': base64.b64encode(certificate).decode(),
                'spki_der': base64.b64encode(spki).decode()}

    def observation(self):
        node = {'identity': self.identity(), 'capabilities': {'installed_data': True,
                'shared_uid': False, 'permission': True, 'rollback': False, 'auth': True}}
        signer = {'min_sdk': 28, 'max_sdk': 2147483647, 'targets_dev_release': False,
                  'contains_errors': False, 'lineage': [node]}
        return {'version': 1, 'sdk': 37, 'artifact_verified': True,
                'schemes_verified': {'v1': False, 'v2': False, 'v3': True, 'v31': False, 'v32': False},
                'current_signers': [self.identity()], 'combined_lineage': [node],
                'v3_signers': [signer], 'v31_signers': [], 'v32_signer': None,
                'scope': 'lineages exposed by successful verification at this SDK',
                'installed_history_or_key_ownership_proved': False}

    def read(self, value, code=0):
        return lineage_observation(code, json.dumps(value).encode(), 37)

    def test_lineage_keeps_certificate_spki_capabilities_and_scope_distinct(self):
        value = self.observation()
        # The same public key under a different certificate remains a different identity.
        value['combined_lineage'].append({'identity': self.identity(b'new certificate'),
                                          'capabilities': value['combined_lineage'][0]['capabilities'].copy()})
        row = self.read(value)
        first, second = row['combined_lineage']
        self.assertNotEqual(first['identity']['certificate'], second['identity']['certificate'])
        self.assertEqual(first['identity']['spki'], second['identity']['spki'])
        self.assertFalse(row['installed_history_or_key_ownership_proved'])
        self.assertTrue(first['capabilities']['permission'])

    def test_failed_wrong_sdk_and_claimed_ownership_are_refused(self):
        for field, bad in [('sdk', 36), ('version', True), ('artifact_verified', False),
                           ('installed_history_or_key_ownership_proved', True)]:
            value = self.observation(); value[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError): self.read(value)
        with self.assertRaises(ValueError): self.read(self.observation(), 1)

    def test_duplicate_identity_tampered_digest_and_nonboolean_caps_are_refused(self):
        for mutate in [lambda v: v['current_signers'].append(v['current_signers'][0]),
                       lambda v: v['combined_lineage'].append(v['combined_lineage'][0]),
                       lambda v: v['current_signers'][0].update(certificate_sha256='0'*64),
                       lambda v: v['combined_lineage'][0]['capabilities'].update(auth=1),
                       lambda v: v['v3_signers'][0].update(min_sdk=2147483647, max_sdk=28)]:
            value = self.observation(); mutate(value)
            with self.assertRaises(ValueError): self.read(value)

    def test_per_scheme_lineages_and_missing_lineages_are_retained(self):
        value = self.observation(); value['combined_lineage'] = None
        other = copy.deepcopy(value['v3_signers'][0]); other['lineage'][0]['capabilities']['rollback'] = True
        value['v31_signers'] = [other]; value['v32_signer'] = {'classical': other, 'pqc': None}
        row = self.read(value)
        self.assertIsNone(row['combined_lineage'])
        self.assertFalse(row['v3_signers'][0]['lineage'][0]['capabilities']['rollback'])
        self.assertTrue(row['v31_signers'][0]['lineage'][0]['capabilities']['rollback'])
        self.assertIsNone(row['v32_signer']['pqc'])


if __name__ == '__main__': unittest.main()
