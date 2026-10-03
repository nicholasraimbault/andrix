# SPDX-License-Identifier: Apache-2.0
"""Exact lab source selection and its complete stack lab admission. No Android writer
qualification from these checks.

Synthetic cases replace the exact CE, package, native and writer derivations with fixed bytes, so
the real fence and every real companion tool run over a simulated Git view. With
ANDRIX_PINNED_FRAMEWORK naming the pinned canonical framework copies, the real native and writer
derivations run too. Host checks only; nothing here builds, boots or activates Android."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
import hashlib
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
import android_lifecycle as lifecycle  # noqa: E402
import grapheneos_source as source  # noqa: E402
import native_creation_binding as b1  # noqa: E402
import native_identity_writer as writer  # noqa: E402
import native_principal_pins as pins  # noqa: E402
import package_installer_payload_sync as payload  # noqa: E402
import package_verity as verity  # noqa: E402

PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')
PACKAGE = {'UPSTREAM': b'pinned upstream Package Installer\n', 'VERITY': b'exact package verity candidate\n',
           'COMBINED': b'exact package verity candidate with payload sync\n'}
LAB = '--lab-test-only'
FENCE = 'other staged/tracked/untracked framework changes'


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
        complete = {'ce_state': 'ADAPTED', 'native_state': 'ADAPTED',
                    'package': {'state': 'ADAPTED', 'payload_sync_companion': {'state': 'ADAPTED'}}}
        writer.require_admission({'state': 'UPSTREAM'})
        # Without lab admission the companions do not matter, and only the upstream fixture passes.
        writer.require_admission({'state': 'UPSTREAM'}, False, ce_state='UPSTREAM', package={},
                                 native_state='UPSTREAM')
        for state in ('ADAPTED', 'PARTIAL'):
            with self.assertRaises(ValueError): writer.require_admission({'state': state})
            with self.assertRaises(ValueError): writer.require_admission({'state': state}, 1)
            with self.assertRaises(ValueError): writer.require_admission({'state': state}, 1, **complete)
        # Lab admission takes either exact fixture state over the complete stack, never a partial one.
        for state in ('UPSTREAM', 'ADAPTED'):
            writer.require_admission({'state': state}, True, **complete)
            with self.assertRaisesRegex(ValueError, 'lab admission requires the native principal companion'):
                writer.require_admission({'state': state}, True)
        with self.assertRaisesRegex(ValueError, 'lab admission requires the writer fixture exactly upstream or '
                                                'adapted, not partial'):
            writer.require_admission({'state': 'PARTIAL'}, True, **complete)
        for name, value in (('ce_state', 'PARTIAL'), ('native_state', 'UPSTREAM'),
                            ('package', {'state': 'ADAPTED', 'payload_sync_companion': {'state': 'UPSTREAM'}})):
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, 'lab admission requires'):
                writer.require_admission({'state': 'ADAPTED'}, True, **dict(complete, **{name: value}))
        fence = (ROOT / 'scripts/proof/android_lifecycle.py').read_text()
        self.assertIn('def inspect(root, *, lab_writer_fixture=False):', fence)
        self.assertEqual(fence.count('native_identity_writer.require_admission(native_writer, lab_writer_fixture, '
                                     'ce_state=state,\n'
                                     '                                             package=package, '
                                     "native_state=native_pins['state'])"), 1)
        self.assertEqual(fence.count('require_admission('), 1)

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

    def test_lab_admission_decisions(self):
        complete = {'state': 'ADAPTED', 'payload_sync_companion': {'state': 'ADAPTED'}}
        self.assertEqual(writer.lab_problems('check', 'UPSTREAM', 'ADAPTED', complete, 'ADAPTED'), [])
        self.assertEqual(writer.lab_problems('check', 'ADAPTED', 'ADAPTED', complete, 'ADAPTED'), [])
        self.assertEqual(writer.lab_problems('apply', 'UPSTREAM', 'ADAPTED', complete, 'ADAPTED'), [])
        self.assertEqual(writer.lab_problems('revert', 'ADAPTED', 'ADAPTED', complete, 'ADAPTED'), [])
        for action, state in (('apply', 'ADAPTED'), ('revert', 'UPSTREAM'), ('check', 'PARTIAL'),
                              ('apply', 'PARTIAL'), ('revert', 'PARTIAL')):
            with self.subTest(action=action, state=state):
                self.assertEqual(writer.lab_problems(action, state, 'ADAPTED', complete, 'ADAPTED'),
                                 ['the writer fixture exactly %s, not %s'
                                  % (' or '.join(item.lower() for item in writer.LAB_STATES[action]), state.lower())])
        parts = {'the native principal companion exactly adapted': ('ADAPTED', complete, 'PARTIAL'),
                 'the owner lifecycle CE companion exactly adapted': ('UPSTREAM', complete, 'ADAPTED'),
                 'package verity with its payload sync companion exactly adapted':
                     ('ADAPTED', {'state': 'ADAPTED', 'payload_sync_companion': {'state': 'UPSTREAM'}}, 'ADAPTED')}
        for part, (ce, package, native) in parts.items():
            for action, state in (('check', 'UPSTREAM'), ('apply', 'UPSTREAM'), ('revert', 'ADAPTED')):
                with self.subTest(part=part, action=action):
                    self.assertEqual(writer.lab_problems(action, state, ce, package, native), [part])
        # A package report without its payload sync companion, or with it but no package verity, refuses.
        for package in ({'state': 'ADAPTED'}, {'state': 'UPSTREAM', 'payload_sync_companion': {'state': 'ADAPTED'}},
                        None):
            self.assertEqual(writer.lab_problems('check', 'UPSTREAM', 'ADAPTED', package, 'ADAPTED'),
                             ['package verity with its payload sync companion exactly adapted'])
        self.assertEqual(len(writer.lab_problems('apply', 'PARTIAL', 'PARTIAL', {}, 'UPSTREAM')), 4)


class Checkout:
    """Real files in a framework project. The Git view, and the CE and package derivations, are
    simulated. The native and writer derivations are synthetic, or real over the pinned copies."""

    def __init__(self, directory, real):
        self.root = Path(directory).resolve()
        self.project = self.root / writer.PROJECT
        self.head = writer.HEAD
        self.staged, self.also_modified = [], []
        pinned = Path(PINNED) if real else None
        native = ({name: (pinned / name).read_bytes() for name in pins.FILES} if real
                  else {name: b'native upstream ' + name.encode() + b'\n' for name in pins.FILES})
        shell = (pinned / writer.FILE).read_bytes() if real else b'shell upstream\n'
        self.tracked = {**{name: b'ce upstream ' + name.encode() for name in lifecycle.FILES},
                        verity.FILE: PACKAGE['UPSTREAM'], writer.FILE: shell, **native}
        for name, content in self.tracked.items():
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (self.project / lifecycle.ADDED).parent.mkdir(parents=True, exist_ok=True)
        self.ce_target = {**{name: b'ce adapted ' + name.encode() for name in lifecycle.FILES},
                          lifecycle.ADDED: b'ce helper\n'}
        if real:
            self.native_target = pins.targets(native, pins.profile())
            self.writer_target = writer.targets(shell, writer.profile())
        else:
            self.native_target = {**{name: b'native adapted ' + name.encode() + b'\n' for name in pins.FILES},
                                  **{name: b'native helper ' + name.encode() + b'\n' for name in pins.ADDED}}
            self.writer_target = {writer.FILE: b'shell adapted\n', writer.ADDED: b'writer helper\n'}

    # The simulated Git view of the framework project.
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
            others = sorted(p.relative_to(self.project).as_posix() for p in self.project.rglob('*')
                            if p.is_file() and p.relative_to(self.project).as_posix() not in self.tracked)
            return 0, '\n'.join(others).encode()
        raise AssertionError(args)

    def fake_native(self, original, value):
        # As targets() does, only the ten pinned file rows are inputs.
        if {name: original[name] for name in pins.FILES} != {name: self.tracked[name] for name in pins.FILES}:
            raise ValueError('wrong pinned input')
        return dict(self.native_target)

    def fake_verity(self, original, value):
        if original != PACKAGE['UPSTREAM']:
            raise ValueError('pinned Package Installer bytes differ')
        return PACKAGE['VERITY']

    def fake_combined(self, verity_target, value=None):
        if verity_target != PACKAGE['VERITY']:
            raise ValueError('payload sync requires the exact package verity candidate')
        return PACKAGE['COMBINED']

    def writer_files(self, project):
        original = {writer.FILE: self.tracked[writer.FILE], writer.ADDED: None}
        states = {}
        for name in (writer.FILE, writer.ADDED):
            path = project / name
            current = path.read_bytes() if path.exists() else None
            if current == original[name]:
                states[name] = 'UPSTREAM'
            elif current == self.writer_target[name]:
                states[name] = 'ADAPTED'
            else:
                raise ValueError('unrecognized writer fixture modification: ' + name)
        kinds = set(states.values())
        return original, dict(self.writer_target), {
            'state': next(iter(kinds)) if len(kinds) == 1 else 'PARTIAL', 'files': states,
            'profile_sha256': hashlib.sha256(writer.PROFILE.read_bytes()).hexdigest(), 'lab_only': True,
            'native_execution_enabled': False, 'runtime_qualified': False}

    def put(self, name, data):
        path = self.project / name
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(data)

    def set_ce(self, adapted):
        for name in lifecycle.FILES:
            self.put(name, self.ce_target[name] if adapted else self.tracked[name])
        self.put(lifecycle.ADDED, self.ce_target[lifecycle.ADDED] if adapted else None)

    def set_package(self, state):
        self.put(verity.FILE, PACKAGE.get(state, state))

    def set_native(self, adapted):
        for name in (*pins.FILES, *pins.ADDED):
            self.put(name, self.native_target[name] if adapted else self.tracked.get(name))

    def set_writer(self, adapted):
        for name in (writer.FILE, writer.ADDED):
            self.put(name, self.writer_target[name] if adapted else self.tracked.get(name))

    def lab_ready(self):
        """The complete normal stack with the writer fixture upstream."""
        self.set_ce(True)
        self.set_package('COMBINED')
        self.set_native(True)
        self.set_writer(False)

    def writer_bytes(self):
        return tuple((self.project / name).read_bytes() if (self.project / name).exists() else None
                     for name in (writer.FILE, writer.ADDED))


class WriterComposition:
    real = False

    def setUp(self):
        checkout = tempfile.TemporaryDirectory()
        self.addCleanup(checkout.cleanup)
        evidence = tempfile.TemporaryDirectory()
        self.addCleanup(evidence.cleanup)
        self.checkout = c = Checkout(checkout.name, self.real)
        self.evidence = Path(evidence.name).resolve()
        self.counter = itertools.count()
        stack = ExitStack()
        self.addCleanup(stack.close)
        for owner, attribute, arguments in [
                (source, 'run', {'side_effect': c.run}),
                (source, 'filter_overrides', {'return_value': []}),
                (lifecycle, 'profile', {'return_value': {}}),
                (lifecycle, 'targets', {'side_effect': lambda original, value: dict(c.ce_target)}),
                (verity, 'candidate', {'side_effect': c.fake_verity}),
                (payload, 'combined', {'side_effect': c.fake_combined})]:
            stack.enter_context(mock.patch.object(owner, attribute, **arguments))
        if not self.real:
            stack.enter_context(mock.patch.object(pins, 'targets', side_effect=c.fake_native))
            stack.enter_context(mock.patch.object(writer, 'inspect_files', side_effect=c.writer_files))
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

    def breakers(self):
        """Each way the lab stack can lack a companion, with the part admission then names."""
        c = self.checkout
        return {'CE upstream': (lambda: c.set_ce(False), 'the owner lifecycle CE companion'),
                'CE partial': (lambda: c.put(lifecycle.ADDED, None), 'the owner lifecycle CE companion'),
                'verity only': (lambda: c.set_package('VERITY'), 'package verity with its payload sync companion'),
                'package upstream': (lambda: c.set_package('UPSTREAM'),
                                     'package verity with its payload sync companion'),
                'native upstream': (lambda: c.set_native(False), 'the native principal companion'),
                'native partial': (lambda: c.put(pins.FILES[0], c.tracked[pins.FILES[0]]),
                                   'the native principal companion'),
                'native helper missing': (lambda: c.put(next(iter(pins.ADDED)), None),
                                          'the native principal companion')}

    def partials(self):
        """The two partial writer states: the route without its helper, and the helper alone."""
        c = self.checkout
        return {'route only': lambda: c.put(writer.ADDED, None),
                'helper only': lambda: c.put(writer.FILE, c.tracked[writer.FILE])}

    def test_the_shared_fence_admits_the_lab_writer_only_over_the_complete_stack(self):
        c = self.checkout
        for adapted in (False, True):
            with self.subTest(adapted=adapted):
                c.lab_ready()
                c.set_writer(adapted)
                fence = lifecycle.inspect(c.root, lab_writer_fixture=True)[3]
                self.assertEqual((fence['state'], fence['package_verity_companion']['state'],
                                  fence['package_verity_companion']['payload_sync_companion']['state'],
                                  fence['native_principal_pins_companion']['state'],
                                  fence['native_identity_writer_companion']['state']),
                                 ('ADAPTED', 'ADAPTED', 'ADAPTED', 'ADAPTED', 'ADAPTED' if adapted else 'UPSTREAM'))
        for name, partial in self.partials().items():
            with self.subTest(partial=name):
                c.lab_ready()
                c.set_writer(True)
                partial()
                with self.assertRaisesRegex(ValueError, 'lab admission requires the writer fixture exactly '
                                                        'upstream or adapted, not partial'):
                    lifecycle.inspect(c.root, lab_writer_fixture=True)
                with self.assertRaisesRegex(ValueError, 'requires explicit lab admission'):
                    lifecycle.inspect(c.root)
        for name, (breaker, part) in self.breakers().items():
            for adapted in (False, True):
                with self.subTest(name=name, adapted=adapted):
                    c.lab_ready()
                    c.set_writer(adapted)
                    breaker()
                    with self.assertRaisesRegex(ValueError, 'lab admission requires .*' + part):
                        lifecycle.inspect(c.root, lab_writer_fixture=True)
        self.assertEqual(self.replace.call_count, 0)

    def test_the_normal_fence_is_unchanged(self):
        c = self.checkout
        # An upstream writer passes normal admission whatever state the companions are in.
        for name, (breaker, _) in self.breakers().items():
            with self.subTest(name=name):
                c.lab_ready()
                breaker()
                self.assertEqual(lifecycle.inspect(c.root)[3]['native_identity_writer_companion']['state'],
                                 'UPSTREAM')
        c.set_ce(False)
        c.set_package('UPSTREAM')
        c.set_native(False)
        self.assertEqual(lifecycle.inspect(c.root)[3]['state'], 'UPSTREAM')
        # Any other writer state refuses it, also over the complete stack.
        c.lab_ready()
        c.set_writer(True)
        with self.assertRaisesRegex(ValueError, 'test-only native writer route requires explicit lab admission'):
            lifecycle.inspect(c.root)
        for flag in (False, 1, 'yes', None):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'requires explicit lab admission'):
                lifecycle.inspect(c.root, lab_writer_fixture=flag)
        self.assertEqual(self.replace.call_count, 0)

    def test_lab_admission_requires_the_complete_stack_for_every_action(self):
        c = self.checkout
        for name, (breaker, part) in self.breakers().items():
            for action, adapted in (('check', False), ('check', True), ('apply', False), ('revert', True)):
                with self.subTest(name=name, action=action, adapted=adapted):
                    c.lab_ready()
                    c.set_writer(adapted)
                    breaker()
                    before = c.writer_bytes()
                    self.refuse(writer, action, 'lab admission requires .*' + part, LAB)
                    self.assertEqual((c.writer_bytes(), self.replace.call_count), (before, 0))
        # No option forces an action over an incomplete stack; its repair is a reviewed manual one.
        c.lab_ready()
        c.set_ce(False)
        for option in ('--force', '--allow-partial'):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                self.main(writer, '--action', 'apply', LAB, option, '--evidence', str(self.fresh()))
        self.assertEqual(self.replace.call_count, 0)

    def test_apply_needs_the_exact_upstream_writer_and_a_repeat_refuses(self):
        c = self.checkout
        c.lab_ready()
        self.assertEqual(self.cli(writer, 'check', LAB)['state'], 'UPSTREAM')
        result = self.cli(writer, 'apply', LAB, '--require-adapted')
        self.assertEqual((result['state'], result['state_after'], result['action']), ('UPSTREAM', 'ADAPTED', 'apply'))
        self.assertEqual((c.writer_bytes(), self.replace.call_count),
                         ((c.writer_target[writer.FILE], c.writer_target[writer.ADDED]), 2))
        # A repeated apply is no longer a no operation: it refuses before any write.
        self.refuse(writer, 'apply', 'the writer fixture exactly upstream, not adapted', LAB)
        self.assertEqual(self.replace.call_count, 2)
        self.assertEqual(self.cli(writer, 'check', LAB, '--require-adapted')['state'], 'ADAPTED')

    def test_revert_needs_the_exact_adapted_writer_and_a_repeat_refuses(self):
        c = self.checkout
        c.lab_ready()
        c.set_writer(True)
        self.refuse(writer, 'revert', 'cannot require adapted state during revert', LAB, '--require-adapted')
        result = self.cli(writer, 'revert', LAB)
        self.assertEqual((result['state'], result['state_after']), ('ADAPTED', 'UPSTREAM'))
        self.assertEqual((c.writer_bytes(), self.replace.call_count), ((c.tracked[writer.FILE], None), 2))
        self.refuse(writer, 'revert', 'the writer fixture exactly adapted, not upstream', LAB)
        self.assertEqual(self.replace.call_count, 2)
        self.refuse(writer, 'check', 'complete writer fixture required', LAB, '--require-adapted')

    def test_check_takes_either_exact_state_and_a_partial_writer_refuses_everything(self):
        c = self.checkout
        for partial in ((writer.FILE, None), (writer.ADDED, 'helper only')):
            with self.subTest(partial=partial[1] or 'route only'):
                c.lab_ready()
                c.set_writer(True)
                if partial[1] is None:
                    c.put(writer.ADDED, None)
                else:
                    c.put(writer.FILE, c.tracked[writer.FILE])
                before = c.writer_bytes()
                for action in ('check', 'apply', 'revert'):
                    self.refuse(writer, action, 'the writer fixture exactly .*, not partial', LAB)
                self.refuse(writer, 'check', 'requires explicit lab admission')
                for module in (pins, payload, verity, lifecycle):
                    self.refuse(module, 'check', 'requires explicit lab admission')
                self.assertEqual((c.writer_bytes(), self.replace.call_count), (before, 0))

    def test_normal_admission_needs_lab_scope_and_refuses_an_adapted_writer(self):
        c = self.checkout
        c.lab_ready()
        for action in ('apply', 'revert'):
            with self.assertRaisesRegex(ValueError, 'explicit lab test scope required'):
                self.main(writer, '--action', action, '--evidence', str(self.fresh()))
        with self.assertRaisesRegex(ValueError, 'explicit lab test scope required'):
            self.main(writer, '--action', 'check', '--require-adapted', '--evidence', str(self.fresh()))
        self.assertEqual(self.cli(writer, 'check')['state'], 'UPSTREAM')
        c.set_writer(True)
        self.refuse(writer, 'check', 'requires explicit lab admission')
        # While the writer is adapted, every normal companion tool refuses, so no companion can be
        # reverted beneath it.
        for module in (pins, payload, verity, lifecycle):
            self.refuse(module, 'revert', 'requires explicit lab admission')
        self.assertEqual(self.replace.call_count, 0)

    def test_ordered_apply_and_revert_through_the_actual_tools(self):
        c = self.checkout
        self.refuse(writer, 'apply', 'lab admission requires the native principal companion', LAB)
        self.cli(lifecycle, 'apply')
        self.cli(verity, 'apply')
        self.cli(payload, 'apply')
        self.refuse(writer, 'apply', 'lab admission requires the native principal companion exactly adapted', LAB)
        self.cli(pins, 'apply', '--require-adapted')
        result = self.cli(writer, 'apply', LAB, '--require-adapted')
        self.assertEqual(result['state_after'], 'ADAPTED')
        self.refuse(pins, 'check', 'requires explicit lab admission', '--require-adapted')
        self.cli(writer, 'revert', LAB)
        self.cli(pins, 'revert')
        self.cli(payload, 'revert')
        self.assertEqual(self.cli(writer, 'check')['state'], 'UPSTREAM')
        self.refuse(writer, 'check', 'lab admission requires the native principal companion', LAB)
        self.assertEqual((c.writer_bytes(), (c.project / pins.SETTINGS).read_bytes()),
                         ((c.tracked[writer.FILE], None), c.tracked[pins.SETTINGS]))

    def test_other_framework_changes_are_still_refused_under_lab_admission(self):
        c = self.checkout
        c.lab_ready()
        self.cli(writer, 'check', LAB)
        for field, value in (('also_modified', 'services/core/java/com/android/server/Unrelated.java'),
                             ('staged', writer.FILE)):
            getattr(c, field).append(value)
            for action in ('check', 'apply'):
                self.refuse(writer, action, FENCE, LAB)
            getattr(c, field).remove(value)
        c.put('services/core/java/com/android/server/pm/Extra.java', b'untracked\n')
        self.refuse(writer, 'apply', FENCE, LAB)
        c.put('services/core/java/com/android/server/pm/Extra.java', None)
        c.head = '0' * 40
        with self.assertRaises(ValueError):
            self.main(writer, '--action', 'check', LAB, '--evidence', str(self.fresh()))
        c.head = writer.HEAD
        self.assertEqual(self.replace.call_count, 0)


class SyntheticWriterCompositionTests(WriterComposition, unittest.TestCase):
    real = False


class PinnedWriterComposition(WriterComposition):
    """The same composition with the real native and writer derivations over the pinned copies.
    It is a test case only when ANDRIX_PINNED_FRAMEWORK names them, as the lab history runner's
    pure suites always do. The B1 runner's regressions, which refuse any skipped case, then run
    only the synthetic composition."""
    real = True

    def test_old_adapted_settings_are_refused(self):
        """The tree precondition: a checkout that holds the adapted Settings of the earlier profile,
        with its version 1 boot literal, is unknown bytes to every tool. It needs a revert with
        the old tools or a reviewed manual repair."""
        c = self.checkout
        c.lab_ready()
        current = c.native_target[pins.SETTINGS]
        old = current.replace((b1.CONSTRUCTION + b1.PRODUCTION).encode(), (b1.CONSTRUCTION + b1.RETIRED).encode(), 1)
        self.assertEqual((sum(a != b for a, b in zip(old, current)), len(old)), (1, len(current)))
        self.assertEqual(b1.r0_forward(old.decode()).encode(), current)
        c.put(pins.SETTINGS, old)
        with self.assertRaisesRegex(ValueError, 'unrecognized native principal modification'):
            pins.inspect_files(c.project)
        for module, extra in ((writer, (LAB,)), (writer, ()), (pins, ()), (lifecycle, ())):
            self.refuse(module, 'check', 'unrecognized native principal modification', *extra)
        self.refuse(pins, 'revert', 'unrecognized native principal modification')
        self.assertEqual(((c.project / pins.SETTINGS).read_bytes(), self.replace.call_count), (old, 0))

    def test_pinned_outputs_are_the_profile_candidates(self):
        value = pins.profile()
        self.assertEqual({row['path']: hashlib.sha256(self.checkout.native_target[row['path']]).hexdigest()
                          for row in value['files']},
                         {row['path']: row['candidate_sha256'] for row in value['files']})
        self.assertEqual(hashlib.sha256(self.checkout.writer_target[writer.FILE]).hexdigest(),
                         writer.profile()['file']['candidate_sha256'])


if PINNED:
    class PinnedWriterCompositionTests(PinnedWriterComposition, unittest.TestCase):
        pass


if __name__ == '__main__':
    unittest.main()
