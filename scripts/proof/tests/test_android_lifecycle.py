# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import android_lifecycle as lifecycle
import native_identity_writer as writer
import native_principal_pins as pins
import package_verity as verity


def state(root):
    # Every entry below root, links not followed: mode, size, inode, mtime, ctime and bytes.
    return {path.relative_to(root).as_posix(): (
        path.lstat().st_mode, path.lstat().st_size, path.lstat().st_ino, path.lstat().st_mtime_ns,
        path.lstat().st_ctime_ns,
        path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        for path in [root, *root.rglob('*')]}


@contextlib.contextmanager
def previous(path, root=None):
    # The earlier tracked check: both diffs against the project's own index.
    flags = lifecycle.source.filter_overrides(path)
    yield lambda *args: lifecycle.source.run(path, *flags, *args)[1]


class FrameworkFence:
    """A frameworks/base Git project with the two pinned files, beside synthetic companions that
    report themselves upstream. Only the fence's own Git view is real."""
    TARGET = {**{name: b'adapted ' + name.encode() + b'\n' for name in lifecycle.FILES},
              lifecycle.ADDED: b'added helper\n'}

    def build(self, root):
        project = root / lifecycle.PROJECT
        for name in (*lifecycle.FILES, 'core/java/Other.java'):
            (project / name).parent.mkdir(parents=True, exist_ok=True)
            (project / name).write_bytes(b'upstream ' + name.encode() + b'\n')
        (project / lifecycle.ADDED).parent.mkdir(parents=True, exist_ok=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update({'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'})
        def git(where, *args):
            return subprocess.check_output(['git', '-C', str(where), '-c', 'user.name=Fixture',
                                            '-c', 'user.email=fixture@example.invalid', *args],
                                           env=env, stderr=subprocess.STDOUT).strip()
        git(project, 'init'); git(project, 'add', '.')
        git(project, 'commit', '-m', 'synthetic input')
        return git, git(project, 'rev-parse', 'HEAD').decode()

    def mocks(self, head, targets=None):
        stack = contextlib.ExitStack()
        upstream = {'state': 'UPSTREAM', 'file': verity.FILE}
        native = {'state': 'UPSTREAM',
                  'files': {name: 'UPSTREAM' for name in (*pins.FILES, *pins.ADDED)}}
        shell = {'state': 'UPSTREAM', 'files': {writer.FILE: 'UPSTREAM', writer.ADDED: 'UPSTREAM'}}
        for owner, attribute, arguments in [
                (lifecycle, 'HEAD', {'new': head}), (lifecycle, 'profile', {'return_value': {}}),
                (lifecycle, 'targets',
                 {'side_effect': targets or (lambda original, value: dict(self.TARGET))}),
                (verity, 'inspect_file', {'return_value': (b'', b'', upstream)}),
                (pins, 'inspect_files', {'return_value': ({}, {}, native)}),
                (writer, 'inspect_files', {'return_value': ({}, {}, shell)})]:
            stack.enter_context(mock.patch.object(owner, attribute, **arguments))
        return stack


def outcome(root):
    try:
        return lifecycle.inspect(root)[3]['state']
    except ValueError as error:
        return str(error)


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



class CopiedFrameworkTests(FrameworkFence, unittest.TestCase):
    def test_a_copied_tree_is_read_through_a_private_index(self):
        # A copy's index matches none of its files, and the earlier check rewrote it there. Each
        # verdict on a copy is the earlier check's, on a twin copy, and the copy is unchanged.
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            git, head = self.build(work / 'original')
            time.sleep(1.1)  # Git compares whole seconds of ctime: copies start a second later.
            def adapt(project):
                for name, data in self.TARGET.items(): (project / name).write_bytes(data)
            def other(project): (project / 'core/java/Other.java').write_bytes(b'changed\n')
            def stage(project):
                name = lifecycle.FILES[0]
                (project / name).write_bytes(b'staged\n'); git(project, 'add', name)
                (project / name).write_bytes(b'upstream ' + name.encode() + b'\n')
            with self.mocks(head):
                for name, change, expected in [('upstream', None, 'UPSTREAM'),
                                               ('adapted', adapt, 'ADAPTED'),
                                               ('other', other, 'other staged/tracked/untracked'),
                                               ('staged', stage, 'other staged/tracked/untracked')]:
                    with self.subTest(name):
                        copy = work / name
                        shutil.copytree(work / 'original', copy, symlinks=True)
                        if change: change(copy / lifecycle.PROJECT)
                        twin = shutil.copytree(copy, work / (name + '-twin'), symlinks=True)
                        before = state(copy)
                        found = outcome(copy)
                        self.assertEqual(state(copy), before)
                        self.assertIn(expected, found)
                        with mock.patch.object(lifecycle.source, 'refreshed_index', previous):
                            self.assertEqual(outcome(twin), found)

    def test_a_temporary_directory_inside_the_source_tree_is_refused_before_scratch_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            _, head = self.build(work / 'root')
            inside, outside = work / 'root/tmp', work / 'outside'
            inside.mkdir(); outside.mkdir()
            time.sleep(0.05)  # File times are coarse: a later write must show.
            before = state(work / 'root')
            def scratch(original, value): raise AssertionError('scratch patching began')
            for directory in (inside, outside):
                with self.subTest(directory=directory.name), \
                        self.mocks(head, None if directory == outside else scratch), \
                        mock.patch.object(tempfile, 'tempdir', None), \
                        mock.patch.dict(os.environ, {'TMPDIR': str(directory)}):
                    if directory == inside:
                        with self.assertRaisesRegex(lifecycle.source.SourceError,
                                                    'temporary directory must be outside'):
                            lifecycle.inspect(work / 'root')
                    else:
                        self.assertEqual(lifecycle.inspect(work / 'root')[3]['state'], 'UPSTREAM')
                    self.assertEqual(state(work / 'root'), before)
                    self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
