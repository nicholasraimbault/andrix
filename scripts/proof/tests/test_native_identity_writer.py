# SPDX-License-Identifier: Apache-2.0
"""Exact lab source selection. No Android writer qualification from these checks."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_identity_writer as writer


class NativeIdentityWriterTests(unittest.TestCase):
    def test_exact_bounded_profile(self):
        profile = writer.profile()
        self.assertTrue(profile['lab_only'])
        self.assertFalse(profile['native_execution_enabled'])
        self.assertIn('getRemainingArgs().toArray(new String[0])', writer.PATCH.read_text())
        with self.assertRaises(ValueError):
            writer.targets(b'wrong source', profile)
        production = (ROOT / 'owner/platform/Android.bp').read_text()
        self.assertNotIn('NativePrincipalWriterFixture', production)
        self.assertNotIn('native-identity/writer', production)

    def test_normal_admission_rejects_any_fixture_adaptation(self):
        writer.require_admission({'state': 'UPSTREAM'})
        for state in ('ADAPTED', 'PARTIAL'):
            with self.assertRaises(ValueError): writer.require_admission({'state': state})
            with self.assertRaises(ValueError): writer.require_admission({'state': state}, 1)
            writer.require_admission({'state': state}, True)
        fence = (ROOT / 'scripts/proof/android_lifecycle.py').read_text()
        self.assertIn('def inspect(root, *, lab_writer_fixture=False):', fence)
        self.assertIn('native_identity_writer.require_admission(native_writer, lab_writer_fixture)', fence)

    def test_profile_and_patch_scope_changes_refuse(self):
        original = json.loads(writer.PROFILE.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            for value in (dict(original, version=True), dict(original, head='0' * 40),
                          dict(original, lab_only=False), dict(original, native_execution_enabled=True),
                          dict(original, patch_sha256='0' * 64)):
                path.write_text(json.dumps(value))
                with mock.patch.object(writer, 'PROFILE', path), self.assertRaises(ValueError): writer.profile()
            patch = Path(directory) / 'wrong.patch'
            patch.write_text(writer.PATCH.read_text().replace('a/' + writer.FILE, 'a/../outside.java'))
            path.write_text(json.dumps(dict(original, patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest())))
            with mock.patch.object(writer, 'PROFILE', path), mock.patch.object(writer, 'PATCH', patch), self.assertRaises(ValueError):
                writer.profile()


if __name__ == '__main__':
    unittest.main()
