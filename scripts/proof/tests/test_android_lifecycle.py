# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import android_lifecycle as lifecycle


class AndroidLifecycleTests(unittest.TestCase):
    def test_pinned_profile_and_exact_framework_method_fixture(self):
        profile = lifecycle.profile()
        self.assertEqual(profile['head'], lifecycle.HEAD)
        self.assertEqual(len(profile['files']), 2)
        methods = lifecycle.EXTRACTED.read_text()
        for name in ['private void connectVold()', 'private void restoreCeUnlockedUsers(IVold vold)',
                     'public void lockCeStorage(int userId)', 'private void resetIfBootedAndConnected()',
                     'private void restoreSystemUnlockedUsers(']:
            self.assertEqual(methods.count(name), 1)
        self.assertIn('Copyright (C) 2007 The Android Open Source Project', methods)
        self.assertIn('mVold.asBinder() != binder', methods)
        self.assertLess(methods.index('mCeAccess.connected(binder)'), methods.index('mVold = candidate'))
        self.assertIn('mCeAccess.beginRevocation(userId', methods)
        self.assertIn('mCeUnlockedUsers.appendAll(userIds)', methods)
        self.assertNotIn('mCeUnlockedUsers.clear', methods)
        with self.assertRaises(ValueError):
            lifecycle.targets({name: b'wrong source' for name in lifecycle.FILES}, profile)

    def test_profile_rejects_drift_and_other_patch_paths(self):
        data = json.loads(lifecycle.PROFILE.read_text())
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / 'profile.json'
            for invalid in [json.dumps(dict(data, head='0' * 40)),
                            json.dumps(dict(data, version=True)),
                            json.dumps(dict(data, version=float('nan'))),
                            json.dumps(data).replace('"version": 1', '"version": 1, "version": 1', 1)]:
                profile.write_text(invalid)
                with mock.patch.object(lifecycle, 'PROFILE', profile), self.assertRaises(ValueError):
                    lifecycle.profile()
            patch = Path(directory) / 'wrong.patch'
            contents = lifecycle.PATCH.read_text().replace('a/' + lifecycle.FILES[0], 'a/../outside.java')
            patch.write_text(contents)
            profile.write_text(json.dumps(dict(data, patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest())))
            with mock.patch.object(lifecycle, 'PROFILE', profile), mock.patch.object(lifecycle, 'PATCH', patch):
                with self.assertRaises(ValueError):
                    lifecycle.profile()

    def test_rejects_both_evidence_seal_forms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(lifecycle.sealed_ancestor(root / 'new/receipt.json'))
            (root / 'SHA256SUMS').write_text('existing receipt manifest\n')
            self.assertTrue(lifecycle.sealed_ancestor(root / 'new/receipt.json'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'SEALED').write_text('closed\n')
            self.assertTrue(lifecycle.sealed_ancestor(root / 'new/receipt.json'))

    def test_opt_in_authority_and_existing_cleanup(self):
        product = (ROOT / 'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertIn('ifeq ($(ANDRIX_OWNER_LIFECYCLE),true)', product)
        self.assertIn('ANDRIX_OWNER_LIFECYCLE requires ANDRIX_OWNER_SESSION=true', product)
        self.assertIn('PRODUCT_SYSTEM_SERVER_JARS_EXTRA += system_ext:andrix-owner-lifecycle', product)
        self.assertNotIn('PRODUCT_BROKEN_SUBOPTIMAL_ORDER_OF_SYSTEM_SERVER_JARS :=', product)
        policy = (ROOT / 'owner/platform/sepolicy/owner_lifecycle.te').read_text()
        self.assertIn('binder_call(andrixd, system_server)', policy)
        self.assertIn('andrix_owner andrix_terminal untrusted_app_all isolated_app_all', policy)
        properties = (ROOT / 'owner/platform/sepolicy/property_contexts').read_text()
        self.assertEqual([line.split()[0] for line in properties.splitlines() if not line.startswith('#')],
                         ['ctl.start$andrixd', 'ctl.stop$andrixd', 'ctl.restart$andrixd'])
        service = (ROOT / 'owner/platform/java/dev/andrix/server/OwnerLifecycleService.java').read_text()
        self.assertIn('Binder.getCallingUid() != OWNER_UID', service)
        self.assertIn('registerCeStorageAccessListener', service)
        self.assertIn('onUserStopping(TargetUser user)', service)
        self.assertNotIn('lockCeStorage(', service)
        self.assertNotIn('MANAGE_USERS', service)
        self.assertNotIn('STORAGE_INTERNAL', service)
        native = (ROOT / 'owner/native/platform_lifecycle.cpp').read_text()
        self.assertIn('AIBinder_DeathRecipient_setOnUnlinked', native)
        self.assertIn('instance_ != state.instance || generation_ != state.generation', native)
        self.assertIn('gate_.begin_query', native)
        self.assertIn('gate_.report', native)
        daemon = (ROOT / 'owner/native/andrixd.cpp').read_text()
        start = daemon.index('  void controller_died(uint64_t registration) {')
        body = daemon[start:daemon.index('  void revoke_locked()', start)]
        self.assertIn('controller_generation_ != registration', body)
        self.assertIn('if (!kept_) stopping_ = true;', body)
        negative = (ROOT / 'tests/owner-negative/probe.cpp').read_text()
        self.assertIn('AServiceManager_checkService("andrix.owner.lifecycle")', negative)
        self.assertIn('lifecycle_service_found', negative)


if __name__ == '__main__':
    unittest.main()
