# SPDX-License-Identifier: Apache-2.0
"""Ordered Package Installer companions: package verity, then payload sync.

Host checks only. Synthetic cases replace the two exact derivations with fixed bytes, so the
ordered state machine runs through the real framework fence logic with a simulated Git
view. Real patches, and the real pinned bytes when ANDRIX_SOURCE_ROOT is set, check the
derivation itself. Nothing here builds or runs Android.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
import io
import itertools
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import android_lifecycle as lifecycle
import grapheneos_source as source
import native_identity_writer as writer
import native_principal_pins as pins
import package_installer_payload_sync as payload
import package_verity as verity

HOST = ROOT / 'tests/installer-durability'
SYNTHETIC = {'UPSTREAM': b'pinned upstream Package Installer\n',
             'VERITY': b'exact package verity candidate\n',
             'COMBINED': b'exact package verity candidate with payload sync\n'}
FENCE = 'other staged/tracked/untracked framework changes'


def host_module():
    if str(HOST) not in sys.path:
        sys.path.insert(0, str(HOST))
    import pis_reverse_write_sync
    return pis_reverse_write_sync


def pinned_bytes():
    """Upstream, package verity and combined bytes derived from a pinned checkout."""
    current = (Path(os.environ['ANDRIX_SOURCE_ROOT']).resolve(strict=True)
               / verity.PROJECT / verity.FILE).read_bytes()
    value, host = payload.profile(), host_module()
    if verity.sha(current) == value['candidate_sha256']:
        current = host.patched(current, payload.PATCH, reverse=True)
    if verity.sha(current) == value['base_sha256']:
        current = host.patched(current, verity.PATCH, reverse=True)
    verity_target, combined = payload.derive(current)
    return {'UPSTREAM': current, 'VERITY': verity_target, 'COMBINED': combined}


class FakeCheckout:
    """Real files in a framework project; only the Git view is simulated."""

    def __init__(self, directory, data):
        self.root = Path(directory).resolve()
        self.project = self.root / verity.PROJECT
        self.data = data
        self.head = verity.HEAD
        self.tracked = {verity.FILE: data['UPSTREAM'], **{name: b'old' for name in lifecycle.FILES}}
        self.staged, self.untracked, self.also_modified = [], [], []
        for name, content in self.tracked.items():
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (self.project / lifecycle.ADDED).parent.mkdir(parents=True, exist_ok=True)
        self.path = self.project / verity.FILE

    def write(self, state):
        self.path.write_bytes(self.data.get(state, state))

    def state(self):
        current = self.path.read_bytes()
        return next((name for name, data in self.data.items() if data == current), current)

    def run(self, where, *args, allowed=(0,)):
        if args[0] == 'rev-parse':
            return 0, self.head.encode()
        if args[0] == 'show':
            return 0, self.tracked[args[1].split(':', 1)[1]]
        if args[0] == 'diff' and '--cached' in args:
            return 0, '\n'.join(self.staged).encode()
        if args[0] == 'diff':
            changed = [name for name, content in self.tracked.items()
                       if (self.project / name).read_bytes() != content]
            return 0, '\n'.join(changed + self.also_modified).encode()
        if args[0] == 'ls-files':
            return 0, '\n'.join(self.untracked).encode()
        raise AssertionError(args)

    def fake_verity(self, original, value):
        if original != self.data['UPSTREAM']:
            raise ValueError('pinned Package Installer bytes differ')
        return self.data['VERITY']

    def fake_combined(self, verity_target, value=None):
        if verity_target != self.data['VERITY']:
            raise ValueError('payload sync requires the exact package verity candidate')
        return self.data['COMBINED']

    def mocks(self, synthetic):
        stack = ExitStack()
        pin_state = {'state': 'UPSTREAM',
                     'files': {name: 'UPSTREAM' for name in (*pins.FILES, *pins.ADDED)}}
        writer_state = {'state': 'UPSTREAM', 'files': {writer.FILE: 'UPSTREAM', writer.ADDED: 'UPSTREAM'}}
        lifecycle_targets = {name: b'new' for name in (*lifecycle.FILES, lifecycle.ADDED)}
        for owner, attribute, arguments in [
                (source, 'run', {'side_effect': self.run}),
                (source, 'filter_overrides', {'return_value': []}),
                (lifecycle, 'profile', {'return_value': {}}),
                (lifecycle, 'targets', {'return_value': lifecycle_targets}),
                (pins, 'inspect_files', {'return_value': ({}, {}, pin_state)}),
                (writer, 'inspect_files', {'return_value': ({}, {}, writer_state)})]:
            stack.enter_context(mock.patch.object(owner, attribute, **arguments))
        if synthetic:
            stack.enter_context(mock.patch.object(verity, 'candidate', side_effect=self.fake_verity))
            stack.enter_context(mock.patch.object(payload, 'combined', side_effect=self.fake_combined))
        return stack


class PayloadSyncProfileTests(unittest.TestCase):
    def test_canonical_patch_is_the_host_tested_patch(self):
        value = payload.profile()
        base = verity.profile()
        self.assertEqual(payload.PATCH.read_bytes(), payload.HOST_PATCH.read_bytes())
        self.assertEqual((value['upstream_sha256'], value['base_sha256']),
                         (base['upstream_sha256'], base['candidate_sha256']))
        self.assertEqual(value['requires_sha256'], verity.sha(verity.PROFILE.read_bytes()))
        host = json.loads(payload.HOST_PROFILE.read_text())
        for key in ('candidate_sha256', 'patch_sha256', 'base_sha256', 'upstream_sha256'):
            self.assertEqual(host[key], value[key])
        lines = payload.PATCH.read_text().splitlines()
        self.assertEqual(lines[:2], ['--- a/' + verity.FILE, '+++ b/' + verity.FILE])
        self.assertEqual([line for line in lines[2:] if line.startswith('-')], [])
        code = [line[1:].strip() for line in lines[2:]
                if line.startswith('+') and not line[1:].strip().startswith('//')]
        self.assertEqual(code, ['Os.fsync(targetPfd.getFileDescriptor());'])

    def test_profile_refuses_drift(self):
        original = json.loads(payload.PROFILE.read_text())
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            profile = directory / 'profile.json'
            reduced = {key: value for key, value in original.items() if key != 'scope'}
            for data in [dict(original, version=True), dict(original, head='0' * 40),
                         dict(original, file='../outside.java'), dict(original, extra=True), reduced,
                         dict(original, requires='patches/grapheneos-2026081300/other.json'),
                         dict(original, requires_sha256='0' * 64),
                         dict(original, base_sha256=original['upstream_sha256']),
                         dict(original, upstream_sha256=original['base_sha256']),
                         dict(original, patch_sha256='0' * 64),
                         dict(original, host_profile_sha256='0' * 64),
                         dict(original, host_fragment_sha256=original['host_base_fragment_sha256'])]:
                profile.write_text(json.dumps(data))
                with mock.patch.object(payload, 'PROFILE', profile), self.assertRaises(ValueError):
                    payload.profile()
            profile.write_text(payload.PROFILE.read_text().replace(
                '"version": 1', '"version": 1, "version": 1', 1))
            with mock.patch.object(payload, 'PROFILE', profile), self.assertRaises(ValueError):
                payload.profile()
            # Changed canonical patch bytes no longer match the host tested copy, even with
            # their own hash recorded.
            patch = directory / 'changed.patch'
            patch.write_bytes(payload.PATCH.read_bytes().replace(b'fsync(targetPfd', b'fsync(incomingFd'))
            profile.write_text(json.dumps(dict(original, patch_sha256=verity.sha(patch.read_bytes()))))
            with (mock.patch.object(payload, 'PROFILE', profile), mock.patch.object(payload, 'PATCH', patch),
                  self.assertRaisesRegex(ValueError, 'host tested candidate')):
                payload.profile()
            escape = directory / 'escape.patch'
            escape.write_text(payload.PATCH.read_text().replace('a/' + verity.FILE, 'a/../outside.java'))
            profile.write_text(json.dumps(dict(original, patch_sha256=verity.sha(escape.read_bytes()))))
            with (mock.patch.object(payload, 'PROFILE', profile), mock.patch.object(payload, 'PATCH', escape),
                  self.assertRaisesRegex(ValueError, 'patch target')):
                payload.profile()
            fixture = directory / 'fragment.inc'
            fixture.write_bytes(payload.HOST_FRAGMENT.read_bytes() + b'\n')
            profile.write_text(json.dumps(dict(original, host_fragment_sha256=verity.sha(fixture.read_bytes()))))
            with (mock.patch.object(payload, 'PROFILE', profile),
                  mock.patch.object(payload, 'HOST_FRAGMENT', fixture),
                  self.assertRaisesRegex(ValueError, 'host tested candidate')):
                payload.profile()
        real = payload.strict_json

        def other_host_record(path):
            value = real(path)
            return dict(value, candidate_sha256='0' * 64) if path == payload.HOST_PROFILE else value
        with (mock.patch.object(payload, 'strict_json', side_effect=other_host_record),
              self.assertRaisesRegex(ValueError, 'host tested candidate')):
            payload.profile()

    def test_real_patches_compose_in_order_on_exact_fixtures(self):
        upstream = verity.UPSTREAM_METHOD.read_bytes() + payload.HOST_BASE_FRAGMENT.read_bytes()
        with_verity = payload.patched(upstream, verity.PATCH)
        self.assertEqual(with_verity, verity.EXTRACTED.read_bytes() + payload.HOST_BASE_FRAGMENT.read_bytes())
        combined = payload.patched(with_verity)
        self.assertEqual(combined, verity.EXTRACTED.read_bytes() + payload.HOST_FRAGMENT.read_bytes())
        with self.assertRaises(ValueError):
            payload.patched(combined)
        # The patch text also fits without package verity; the order is the adapters' contract.
        self.assertNotIn(payload.patched(upstream), (upstream, with_verity, combined))
        for fixture in (payload.HOST_BASE_FRAGMENT, payload.HOST_FRAGMENT):
            first, second = payload.tested_regions(fixture)
            self.assertTrue(first.startswith(payload.REGIONS[0].encode()))
            self.assertTrue(second.startswith(payload.REGIONS[1].encode()))
            self.assertTrue(fixture.read_bytes().endswith(first + second))


class OrderedCompanionChecks:
    synthetic = True

    def setUp(self):
        data = SYNTHETIC if self.synthetic else pinned_bytes()
        self.sync_only = b'payload sync without package verity\n' if self.synthetic else payload.patched(data['UPSTREAM'])
        checkout = tempfile.TemporaryDirectory()
        self.addCleanup(checkout.cleanup)
        evidence = tempfile.TemporaryDirectory()
        self.addCleanup(evidence.cleanup)
        self.checkout = FakeCheckout(checkout.name, data)
        self.evidence = Path(evidence.name).resolve()
        self.counter = itertools.count()
        stack = self.checkout.mocks(self.synthetic)
        self.addCleanup(stack.close)
        self.replace = stack.enter_context(mock.patch.object(lifecycle, 'replace', wraps=lifecycle.replace))

    def main(self, module, *args):
        argv = [module.__file__, '--source-root', str(self.checkout.root), *args]
        with mock.patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            module.main()

    def fresh(self):
        return self.evidence / str(next(self.counter)) / 'evidence.json'

    def cli(self, module, action, *extra):
        evidence = self.fresh()
        self.main(module, '--action', action, '--evidence', str(evidence), *extra)
        return json.loads(evidence.read_text())

    def refuse(self, module, action, message, *extra):
        evidence = self.fresh()
        with self.assertRaisesRegex(ValueError, message):
            self.main(module, '--action', action, '--evidence', str(evidence), *extra)
        self.assertFalse(evidence.exists())

    def test_three_known_states_and_unknown_bytes(self):
        c = self.checkout
        hashes = verity.sha(verity.PROFILE.read_bytes()), verity.sha(payload.PROFILE.read_bytes())
        for state, verity_state, payload_state in [('UPSTREAM', 'UPSTREAM', 'UPSTREAM'),
                                                   ('VERITY', 'ADAPTED', 'UPSTREAM'),
                                                   ('COMBINED', 'ADAPTED', 'ADAPTED')]:
            c.write(state)
            original, target, result = verity.inspect_file(c.project)
            self.assertEqual((result['state'], result['payload_sync_companion']),
                             (verity_state, {'state': payload_state, 'profile_sha256': hashes[1]}))
            self.assertEqual(original, c.data['UPSTREAM'])
            # Package verity keeps the composition as its apply target once it exists.
            self.assertEqual(target, c.data['COMBINED' if state == 'COMBINED' else 'VERITY'])
            self.assertEqual({key: result[key] for key in ('project', 'head', 'file', 'profile_sha256',
                                                          'signature_checks_bypassed', 'runtime_proved')},
                             {'project': verity.PROJECT, 'head': verity.HEAD, 'file': verity.FILE,
                              'profile_sha256': verity.sha(verity.PROFILE.read_bytes()),
                              'signature_checks_bypassed': False, 'runtime_proved': False})
            verity_target, combined, own = payload.inspect_file(c.project)
            self.assertEqual((own['state'], own['profile_sha256'], own['package_verity_state'],
                              own['package_verity_profile_sha256']),
                             (payload_state, hashes[1], verity_state, hashes[0]))
            self.assertEqual((verity_target, combined), (c.data['VERITY'], c.data['COMBINED']))
            fence = lifecycle.inspect(c.root)[3]['package_verity_companion']
            self.assertEqual((fence['state'], fence['profile_sha256'], fence['payload_sync_companion']),
                             (verity_state, hashes[0], {'state': payload_state, 'profile_sha256': hashes[1]}))
            self.assertEqual(payload.inspect(c.root)[3]['package_verity_companion'], fence)
        for unknown in (b'unknown bytes\n', self.sync_only, c.data['COMBINED'] + b'\n'):
            c.write(unknown)
            for inspector in (verity.inspect_file, payload.inspect_file):
                with self.assertRaises(ValueError):
                    inspector(c.project)
            with self.assertRaises(ValueError):
                lifecycle.inspect(c.root)

    def test_require_adapted_names_each_component(self):
        c = self.checkout
        hashes = verity.sha(verity.PROFILE.read_bytes()), verity.sha(payload.PROFILE.read_bytes())
        # Package verity's flag means its correction is present, alone or in the exact
        # combination. Only the payload sync flag requires the combination.
        for state, verity_present, payload_present in (('UPSTREAM', False, False),
                                                       ('VERITY', True, False),
                                                       ('COMBINED', True, True)):
            c.write(state)
            if verity_present:
                result = self.cli(verity, 'check', '--require-adapted')
                self.assertEqual((result['profile_sha256'], result['payload_sync_companion']['profile_sha256'],
                                  result['payload_sync_state_after']),
                                 (hashes[0], hashes[1], 'ADAPTED' if payload_present else 'UPSTREAM'))
            else:
                self.refuse(verity, 'check', 'complete package adaptation required', '--require-adapted')
            if payload_present:
                result = self.cli(payload, 'check', '--require-adapted')
                self.assertEqual((result['profile_sha256'], result['package_verity_profile_sha256'],
                                  result['package_verity_companion']['profile_sha256']),
                                 (hashes[1], hashes[0], hashes[0]))
            else:
                self.refuse(payload, 'check', 'payload sync required for build', '--require-adapted')
        for unknown in (b'unknown bytes\n', self.sync_only):
            c.write(unknown)
            for module in (verity, payload):
                self.refuse(module, 'check', 'unrecognized', '--require-adapted')
        self.assertEqual(self.replace.call_count, 0)

    def test_verity_recognition_is_lazy(self):
        c = self.checkout
        with mock.patch.object(payload, 'combined', wraps=payload.combined) as spy:
            for state, calls in (('UPSTREAM', 0), ('VERITY', 0), ('COMBINED', 1)):
                spy.reset_mock()
                c.write(state)
                verity.inspect_file(c.project)
                self.assertEqual(spy.call_count, calls, state)

    def test_wrong_revision_and_paths_are_refused(self):
        c = self.checkout
        c.write('COMBINED')
        c.head = '0' * 40
        for inspector in (verity.inspect_file, payload.inspect_file):
            with self.assertRaises(ValueError):
                inspector(c.project)
        self.refuse(payload, 'check', 'revision')
        c.head = verity.HEAD
        link = c.root / 'linked-project'
        link.symlink_to(c.project, target_is_directory=True)
        for inspector in (verity.inspect_file, payload.inspect_file):
            with self.assertRaises(ValueError):
                inspector(link)
        moved = c.path.with_name('Moved.java')
        c.path.rename(moved)
        c.path.symlink_to(moved)
        for inspector in (verity.inspect_file, payload.inspect_file):
            with self.assertRaises(ValueError):
                inspector(c.project)
        self.assertEqual(self.replace.call_count, 0)

    def test_apply_order_idempotence_and_verity_keeps_the_companion(self):
        c = self.checkout
        self.refuse(payload, 'apply', 'apply the package verity adaptation first')
        self.assertEqual((c.state(), self.replace.call_count), ('UPSTREAM', 0))
        result = self.cli(payload, 'check')
        self.assertEqual((result['state'], result['package_verity_state']), ('UPSTREAM', 'UPSTREAM'))
        self.cli(verity, 'apply')
        self.assertEqual((c.state(), self.replace.call_count), ('VERITY', 1))
        result = self.cli(payload, 'apply')
        self.assertEqual((c.state(), self.replace.call_count), ('COMBINED', 2))
        self.assertEqual((result['state'], result['package_verity_state'], result['state_after'],
                          result['package_verity_state_after'], result['action']),
                         ('UPSTREAM', 'ADAPTED', 'ADAPTED', 'ADAPTED', 'apply'))
        self.assertEqual(result['CE_companion_state'], 'UPSTREAM')
        result = self.cli(payload, 'apply')
        self.assertEqual((result['state'], result['state_after']), ('ADAPTED', 'ADAPTED'))
        result = self.cli(verity, 'apply')
        self.assertEqual((result['state'], result['state_after']), ('ADAPTED', 'ADAPTED'))
        self.assertEqual((result['payload_sync_companion']['state'], result['payload_sync_state_after']),
                         ('ADAPTED', 'ADAPTED'))
        self.assertEqual((c.state(), self.replace.call_count), ('COMBINED', 2))
        self.cli(payload, 'check', '--require-adapted')
        self.cli(verity, 'check', '--require-adapted')

    def test_revert_order_and_idempotence(self):
        c = self.checkout
        c.write('COMBINED')
        self.refuse(verity, 'revert', 'revert the package installer payload sync companion first')
        self.assertEqual((c.state(), self.replace.call_count), ('COMBINED', 0))
        self.refuse(payload, 'revert', 'cannot require adapted state', '--require-adapted')
        result = self.cli(payload, 'revert')
        self.assertEqual((c.state(), self.replace.call_count), ('VERITY', 1))
        self.assertEqual((result['state'], result['state_after'], result['package_verity_state_after']),
                         ('ADAPTED', 'UPSTREAM', 'ADAPTED'))
        self.cli(payload, 'revert')
        self.assertEqual((c.state(), self.replace.call_count), ('VERITY', 1))
        self.refuse(payload, 'check', 'payload sync required for build', '--require-adapted')
        result = self.cli(verity, 'revert')
        self.assertEqual((c.state(), self.replace.call_count), ('UPSTREAM', 2))
        self.assertEqual((result['state_after'], result['payload_sync_state_after']), ('UPSTREAM', 'UPSTREAM'))
        # Reverting the companion on upstream bytes must not reapply package verity.
        self.cli(payload, 'revert')
        self.assertEqual((c.state(), self.replace.call_count), ('UPSTREAM', 2))
        self.refuse(payload, 'apply', 'apply the package verity adaptation first')

    def test_other_framework_changes_are_still_refused(self):
        c = self.checkout
        c.write('COMBINED')
        self.cli(payload, 'check')
        for field, value in (('also_modified', 'services/core/java/com/android/server/Unrelated.java'),
                             ('untracked', 'services/core/java/com/android/server/Extra.java'),
                             ('staged', verity.FILE)):
            getattr(c, field).append(value)
            for module in (payload, verity):
                self.refuse(module, 'check', FENCE)
                self.refuse(module, 'apply', FENCE)
            getattr(c, field).remove(value)
        (c.project / lifecycle.FILES[0]).write_bytes(b'changed')
        for module in (payload, verity):
            self.refuse(module, 'check', 'unrecognized framework modification')
        self.assertEqual((c.state(), self.replace.call_count), ('COMBINED', 0))

    def test_evidence_and_arguments_keep_the_same_guards(self):
        c = self.checkout
        c.write('VERITY')
        existing = self.evidence / 'existing.json'
        existing.write_text('{}\n')
        sealed = self.evidence / 'sealed'
        sealed.mkdir()
        (sealed / 'SEALED').write_text('closed\n')
        outside = ROOT / 'never-written-payload-sync-evidence.json'
        for evidence in (existing, c.root / 'inside.json', outside, sealed / 'new.json'):
            with self.assertRaisesRegex(ValueError, 'fresh unsealed evidence'):
                self.main(payload, '--action', 'apply', '--evidence', str(evidence))
        self.assertFalse(outside.exists())
        with self.assertRaises(SystemExit):
            self.main(payload, '--action', 'apply', '--lab-test-only', '--evidence', str(self.fresh()))
        self.assertEqual((c.state(), self.replace.call_count), ('VERITY', 0))


class SyntheticOrderedCompanionTests(OrderedCompanionChecks, unittest.TestCase):
    synthetic = True


@unittest.skipUnless(os.environ.get('ANDRIX_SOURCE_ROOT'), 'set ANDRIX_SOURCE_ROOT to a pinned framework checkout')
class PinnedOrderedCompanionTests(OrderedCompanionChecks, unittest.TestCase):
    synthetic = False

    def test_exact_derivation_from_pinned_upstream(self):
        data = self.checkout.data
        value = payload.profile()
        self.assertEqual([verity.sha(data[name]) for name in ('UPSTREAM', 'VERITY', 'COMBINED')],
                         [value['upstream_sha256'], value['base_sha256'], value['candidate_sha256']])
        host = host_module()
        self.assertEqual(host.pis_fragment(data['VERITY']), payload.HOST_BASE_FRAGMENT.read_bytes())
        self.assertEqual(host.pis_fragment(data['COMBINED']), payload.HOST_FRAGMENT.read_bytes())
        self.assertEqual(verity.extracted_method(data['COMBINED']), verity.EXTRACTED.read_bytes())
        for wrong in (data['UPSTREAM'], data['COMBINED'], self.sync_only):
            with self.assertRaises(ValueError):
                payload.combined(wrong)


if __name__ == '__main__':
    unittest.main()
