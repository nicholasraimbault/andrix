# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('request_ledger', Path(__file__).with_name('request_ledger.py'))
ledger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger)
PROVENANCE = {'pms': '1' * 64, 'user': '2' * 64, 'apk': '3' * 64}


class LedgerTests(unittest.TestCase):
    def prepare(self, root, operation='initialize', key=None):
        return ledger.prepare(root, operation, 'fixture_setup', 'dev.andrix.proof.uidstore',
                              10123, 7, 'a' * 64, PROVENANCE, key)

    def test_owned_once_and_unknown_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = self.prepare(root)
            other = self.prepare(root, 'observe', 'b' * 64)
            self.assertNotEqual(first['nonce'], other['nonce'])
            self.assertEqual(len(first['nonce']), 32)
            self.assertEqual(ledger.claim(root, first['nonce']), first)
            with self.assertRaises(FileExistsError): ledger.claim(root, first['nonce'])
            ledger.complete(root, first['nonce'], 'unknown', 'c' * 64)
            with self.assertRaises(ValueError): ledger.claim(root, first['nonce'])
            with self.assertRaises(FileExistsError):
                ledger.complete(root, first['nonce'], 'observed-success', 'd' * 64)
            saved = json.loads((root / first['nonce'] / 'outcome.json').read_text())
            self.assertEqual(saved['outcome'], 'unknown')

    def test_no_outcome_without_issue_or_changed_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); request = self.prepare(root)
            with self.assertRaises(ValueError):
                ledger.complete(root, request['nonce'], 'observed-success', 'c' * 64)
            ledger.claim(root, request['nonce'])
            path = root / request['nonce'] / 'request.json'
            changed = json.loads(path.read_text()); changed['uid'] = 10124
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                ledger.complete(root, request['nonce'], 'observed-success', 'c' * 64)

    def test_collision_and_missing_provenance_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(ledger.secrets, 'token_hex', return_value='a' * 32):
                self.prepare(root)
                with self.assertRaises(FileExistsError): self.prepare(root)
            with self.assertRaises(ValueError): self.prepare(root, 'observe', None)
            with self.assertRaises(ValueError):
                ledger.prepare(root, 'initialize', 's', 'dev.andrix.proof.uidstore', 10123,
                               7, 'a' * 64, {'pms': 'a' * 64})
            with self.assertRaises(ValueError): ledger.claim(root, '../outside')


if __name__ == '__main__':
    unittest.main()
