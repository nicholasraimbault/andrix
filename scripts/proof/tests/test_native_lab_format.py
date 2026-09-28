# SPDX-License-Identifier: Apache-2.0
"""The optional lab native store format: its exact profile and single token, the third Settings
state in the shared framework fence, ordered apply and revert, and the unmodified production
format guard.

Synthetic cases replace the exact CE, package, native and lab derivations with fixed bytes, so
the real fence and every real companion tool run over a simulated Git view. With
ANDRIX_PINNED_FRAMEWORK naming the pinned canonical framework copies, the real native and lab
derivations run too. Host checks only; nothing here builds, boots or activates Android.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
import hashlib
import io
import itertools
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import android_lifecycle as lifecycle  # noqa: E402
import grapheneos_source as source  # noqa: E402
import native_creation_binding as b1  # noqa: E402
import native_identity_writer as writer  # noqa: E402
import native_lab_format as lab  # noqa: E402
import native_principal_pins as pins  # noqa: E402
import package_installer_payload_sync as payload  # noqa: E402
import package_verity as verity  # noqa: E402

PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')
SETTINGS = lab.FILE
REAL_CANDIDATE = lab.candidate
# The build source allowlist, checked for completeness against tracked build definitions. Untracked output, evidence,
# download and node trees are never inputs, whatever they contain.
BUILD_SCOPE = ('Android.bp', 'AndroidProducts.mk', 'andrix.mk', 'apex', 'board', 'experiments', 'init', 'keys',
               'overlays', 'owner', 'products', 'sepolicy', 'supervision', 'tests', 'third_party', 'toolchain',
               'scripts/proof/tests/fixtures')
PRUNED = {'out', 'node_modules', 'downloads'}
# The named new candidate files of this lab preparation.
LAB_FILES = ('scripts/proof/native_lab_format.py', 'scripts/proof/native_lab_history.py',
             'scripts/proof/native_lab_history_predictions.json', 'tests/native-identity/lab_history_observe.py',
             'tests/native-identity/lab-history/LabHistoryStore.java',
             'tests/native-identity/lab-history/LabHistoryStoreTest.java',
             'tests/native-identity/lab-history/NativeWriterLabRehearsal.java',
             'tests/native-identity/lab-history/README.md',
             'tests/native-identity/lab-history/native-store-format-v2.json',
             'tests/native-identity/lab-history/native-store-format-v2.patch')
LAB_TOKENS = ('lab-history', 'native-store-format-v2', 'LabHistoryStore', 'NativeWriterLabRehearsal',
              'NativePrincipalWriterFixture', 'native_lab_format', 'lab_history_observe')
PACKAGE = {'UPSTREAM': b'pinned upstream Package Installer\n', 'VERITY': b'exact package verity candidate\n',
           'COMBINED': b'exact package verity candidate with payload sync\n'}
FENCE = 'other staged/tracked/untracked framework changes'
LAB_FLAG = '--lab-history-format'
# The existing writer route and observer, byte identical at this base.
UNCHANGED = {
    'tests/native-identity/writer/NativePrincipalWriterFixture.java':
        '7628d42b1535aac7ea971eb1161fd22e403518f889fe619ad6170d5d5fde8a21',
    'patches/grapheneos-2026081300/native-identity-writer.json':
        '1591b623b8b276d0835da91c4e7358c1b13ae10cfd80b8a5bcf4b8622fb119e3',
    'patches/grapheneos-2026081300/native-identity-writer.patch':
        '2ede775d3e67610457b294870854310d38d97ff873bec2f70fe08646253a328b',
    'scripts/proof/native_identity_writer.py': '332256d84c59a673a7f13b4da56e04d7f9351cdd022ae4e3948b9c851f29eb77',
    'tests/native-identity/writer_observe.py': 'd9663ba6a880f970c8914a035989e3159cc0ab7ce10e54904ab073cc4f2115e1'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def scratch(test):
    directory = Path(tempfile.mkdtemp()).resolve()
    test.addCleanup(shutil.rmtree, directory)
    return directory


def build_definitions(root):
    """Build and product definitions inside the explicit source allowlist, never outside it."""
    found = []
    for name in BUILD_SCOPE:
        path = root / name
        if path.is_symlink():
            continue
        if path.is_file():
            found.append(path)
        elif path.is_dir():
            for current, directories, files in os.walk(path):
                directories[:] = sorted(item for item in directories
                                        if item not in PRUNED and not item.startswith('.'))
                found.extend(Path(current) / item for item in sorted(files) if item.endswith(('.mk', '.bp'))
                             and not (Path(current) / item).is_symlink())
    return found


def glob_matches(pattern, path):
    regex, index = '', 0
    while index < len(pattern):
        if pattern.startswith('**/', index):
            regex, index = regex + '(?:[^/]+/)*', index + 3
        elif pattern.startswith('**', index):
            regex, index = regex + '.*', index + 2
        elif pattern[index] == '*':
            regex, index = regex + '[^/]*', index + 1
        else:
            regex, index = regex + re.escape(pattern[index]), index + 1
    return re.fullmatch(regex, path) is not None


def lab_selections(root, definitions):
    """Definitions that name the lab, or whose source globs reach one of its named files."""
    found = []
    for path in definitions:
        text = path.read_text(errors='replace')
        base = path.parent.relative_to(root).as_posix()
        inside = [name if base == '.' else name[len(base) + 1:] for name in LAB_FILES
                  if base == '.' or name.startswith(base + '/')]
        if (any(token in text for token in LAB_TOKENS)
                or any(glob_matches(pattern, name) for pattern in re.findall(r'"([^"]*\*[^"]*)"', text)
                       for name in inside)):
            found.append(path)
    return found


def boot_text(token=lab.PRODUCTION, path=b'"native-principals"', method=lab.METHOD):
    """A minimal Settings with the exact boot construction, for pure token checks."""
    return (b'final class Settings {\n' + b'    // filler\n' * 5 + method
            + b'        if (mNativeIdentityPersistence != null) throw new IllegalStateException("twice");\n'
            + lab.CONSTRUCTION.replace(b'"native-principals"', path) + token + b'\n' + lab.BOOT_END
            + b'        return null;\n    }\n}\n')


class Checkout:
    """Real files in a framework project. The Git view, and the CE, package and writer
    derivations, are simulated. The native and lab derivations are synthetic or real."""

    def __init__(self, directory, real):
        self.root = Path(directory).resolve()
        self.project = self.root / lab.PROJECT
        self.head = lab.HEAD
        self.staged, self.also_modified = [], []
        native = ({name: (Path(PINNED) / name).read_bytes() for name in pins.FILES} if real
                  else {name: b'native upstream ' + name.encode() + b'\n' for name in pins.FILES})
        self.tracked = {**{name: b'ce upstream ' + name.encode() for name in lifecycle.FILES},
                        verity.FILE: PACKAGE['UPSTREAM'], writer.FILE: b'shell upstream\n', **native}
        for name, content in self.tracked.items():
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (self.project / lifecycle.ADDED).parent.mkdir(parents=True, exist_ok=True)
        self.ce_target = {**{name: b'ce adapted ' + name.encode() for name in lifecycle.FILES},
                          lifecycle.ADDED: b'ce helper\n'}
        self.writer_target = {writer.FILE: b'shell adapted\n', writer.ADDED: b'writer helper\n'}
        if real:
            self.native_target = pins.targets(native, pins.profile())
            self.lab_settings = lab.candidate(self.native_target[SETTINGS])
        else:
            self.native_target = {**{name: b'native adapted ' + name.encode() + b'\n' for name in pins.FILES},
                                  **{name: b'native helper ' + name.encode() + b'\n' for name in pins.ADDED}}
            self.lab_settings = b'native lab Settings\n'

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

    def fake_lab(self, adapted, value=None):
        if adapted != self.native_target[SETTINGS]:
            raise ValueError('lab format requires the exact adapted B2 Settings')
        return self.lab_settings

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
            'profile_sha256': sha(writer.PROFILE.read_bytes()), 'lab_only': True,
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

    def normal(self):
        self.set_ce(True)
        self.set_package('COMBINED')
        self.set_native(True)
        self.set_writer(False)

    def lab_ready(self):
        self.normal()
        self.set_writer(True)

    def settings(self):
        return (self.project / SETTINGS).read_bytes()


class LabComposition:
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
                (writer, 'inspect_files', {'side_effect': c.writer_files}),
                (verity, 'candidate', {'side_effect': c.fake_verity}),
                (payload, 'combined', {'side_effect': c.fake_combined})]:
            stack.enter_context(mock.patch.object(owner, attribute, **arguments))
        if not self.real:
            stack.enter_context(mock.patch.object(pins, 'targets', side_effect=c.fake_native))
            stack.enter_context(mock.patch.object(lab, 'candidate', side_effect=c.fake_lab))
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

    def test_normal_admission_detects_and_refuses_the_exact_lab_state(self):
        c = self.checkout
        c.lab_ready()
        c.put(SETTINGS, c.lab_settings)
        for call in (lambda: lifecycle.inspect(c.root), lambda: lifecycle.inspect(c.root, lab_writer_fixture=True)):
            with self.assertRaisesRegex(ValueError, 'explicit lab history admission'):
                call()
        for module, extra in ((lifecycle, ()), (verity, ()), (payload, ()), (pins, ()), (writer, ('--lab-test-only',))):
            self.refuse(module, 'check', 'explicit lab history admission', *extra)
        fence = lifecycle.inspect_lab_native_format(c.root)[3]
        native = fence['native_principal_pins_companion']
        self.assertEqual((fence['lab_native_format'], native['state'], native['files'][SETTINGS]),
                         (lab.STATE, lab.STATE, lab.STATE))
        self.assertEqual({state for name, state in native['files'].items() if name != SETTINGS}, {'ADAPTED'})
        result = self.cli(lab, 'check', LAB_FLAG, '--require-lab')
        self.assertEqual((result['state'], result['settings_state'], result['format'], result['production_format'],
                          result['lab_only'], result['native_execution_enabled'], result['runtime_qualified']),
                         (lab.STATE, lab.STATE, 'V2', 'V1', True, False, False))
        self.assertEqual(result['companions']['native-principal-pins'], lab.STATE)
        self.assertEqual(self.replace.call_count, 0)

    def test_lab_flag_without_the_adapted_writer_refuses(self):
        c = self.checkout
        c.normal()
        c.put(SETTINGS, c.lab_settings)
        with self.assertRaisesRegex(ValueError, 'exact adapted writer fixture'):
            lifecycle.inspect_lab_native_format(c.root)
        self.refuse(lab, 'check', 'exact adapted writer fixture', LAB_FLAG)
        self.refuse(lab, 'revert', 'exact adapted writer fixture', LAB_FLAG)
        c.put(writer.FILE, c.writer_target[writer.FILE])  # PARTIAL: route without its helper
        self.refuse(lab, 'check', 'exact adapted writer fixture', LAB_FLAG)
        c.set_writer(False)
        c.put(SETTINGS, c.native_target[SETTINGS])
        self.refuse(lab, 'apply', 'exact adapted writer fixture', LAB_FLAG)
        self.assertEqual((c.settings(), self.replace.call_count), (c.native_target[SETTINGS], 0))

    def test_every_admission_of_the_lab_state_requires_the_complete_stack(self):
        c = self.checkout
        parts = {'CE upstream': (lambda: c.set_ce(False), 'the owner lifecycle CE companion'),
                 'CE partial': (lambda: c.put(lifecycle.ADDED, None), 'the owner lifecycle CE companion'),
                 'verity only': (lambda: c.set_package('VERITY'), 'package verity with its payload sync companion'),
                 'package upstream': (lambda: c.set_package('UPSTREAM'),
                                      'package verity with its payload sync companion'),
                 'writer partial': (lambda: c.put(writer.ADDED, None), 'the exact adapted writer fixture'),
                 'writer upstream': (lambda: c.set_writer(False), 'the exact adapted writer fixture'),
                 'native partial': (lambda: c.put(pins.FILES[0], c.tracked[pins.FILES[0]]),
                                    'the complete native principal companion'),
                 'native helper missing': (lambda: c.put(next(iter(pins.ADDED)), None),
                                           'the complete native principal companion')}
        for name, (breaker, part) in parts.items():
            with self.subTest(name=name):
                c.lab_ready()
                c.put(SETTINGS, c.lab_settings)
                breaker()
                with self.assertRaisesRegex(ValueError, 'complete lab stack: .*' + part):
                    lifecycle.inspect_lab_native_format(c.root)
                for call in (lambda: lifecycle.inspect(c.root), lambda: lifecycle.inspect(c.root, lab_writer_fixture=True)):
                    with self.assertRaisesRegex(ValueError, 'explicit lab history admission'):
                        call()
                for action, extra in (('check', ()), ('check', ('--require-lab',)), ('revert', ()), ('apply', ())):
                    self.refuse(lab, action, 'complete lab stack: .*' + part, LAB_FLAG, *extra)
                self.assertEqual((c.settings(), self.replace.call_count), (c.lab_settings, 0))
        # No option forces a revert over a partial stack; its repair is a reviewed manual one.
        c.lab_ready()
        c.put(SETTINGS, c.lab_settings)
        c.set_ce(False)
        for option in ('--force', '--allow-partial'):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                self.main(lab, '--action', 'revert', LAB_FLAG, option, '--evidence', str(self.fresh()))
        self.assertEqual((c.settings(), self.replace.call_count), (c.lab_settings, 0))

    def test_known_normal_states_never_load_the_lab_files(self):
        c = self.checkout
        absent = scratch(self) / 'lab-history'
        loaded = mock.Mock(side_effect=AssertionError('lab files loaded for known bytes'))
        with mock.patch.object(lab, 'DIRECTORY', absent), mock.patch.object(lab, 'PROFILE', absent / lab.PROFILE.name), \
                mock.patch.object(lab, 'PATCH', absent / lab.PATCH.name), mock.patch.object(lab, 'candidate', loaded), \
                mock.patch.object(lab, 'profile', loaded):
            for arrange, flag in ((lambda: None, False), (c.normal, False), (c.lab_ready, True)):
                arrange()
                self.assertEqual(lifecycle.inspect(c.root, lab_writer_fixture=flag)[3]['lab_native_format'], lab.ABSENT)
            c.normal()
            self.cli(pins, 'check', '--require-adapted')
            self.cli(payload, 'check', '--require-adapted')
        self.assertEqual(loaded.call_count, 0)

    def test_unknown_settings_fail_closed_when_the_lab_format_is_unavailable(self):
        c = self.checkout
        c.lab_ready()
        c.put(SETTINGS, b'unknown Settings bytes\n')
        timeout = types.SimpleNamespace(run=mock.Mock(side_effect=subprocess.TimeoutExpired(['/usr/bin/patch'], 30)),
                                        SubprocessError=subprocess.SubprocessError)
        for name, (attribute, value) in {'missing profile': ('PROFILE', lab.DIRECTORY / 'absent-profile.json'),
                                         'missing patch': ('PATCH', lab.DIRECTORY / 'absent.patch'),
                                         'patch timeout': ('subprocess', timeout)}.items():
            with self.subTest(name=name), mock.patch.object(lab, 'candidate', REAL_CANDIDATE), \
                    mock.patch.object(lab, attribute, value):
                for call in (lambda: lifecycle.inspect(c.root, lab_writer_fixture=True),
                             lambda: lifecycle.inspect_lab_native_format(c.root)):
                    with self.assertRaisesRegex(ValueError, 'unrecognized native principal modification: '
                                                            '.*lab format unavailable'):
                        call()
                self.refuse(lab, 'check', 'lab format unavailable', LAB_FLAG)
        with mock.patch.dict(sys.modules, {'native_lab_format': None}), \
                self.assertRaisesRegex(ValueError, 'lab format unavailable: (ImportError|ModuleNotFoundError)'):
            lifecycle.inspect(c.root, lab_writer_fixture=True)
        self.assertEqual(self.replace.call_count, 0)

    def test_unknown_settings_always_refuse(self):
        c = self.checkout
        c.lab_ready()
        for unknown in (c.lab_settings + b'\n', c.lab_settings[:-1], lab.PATCH.read_bytes(), b''):
            c.put(SETTINGS, unknown)
            for call in (lambda: lifecycle.inspect(c.root, lab_writer_fixture=True),
                         lambda: lifecycle.inspect_lab_native_format(c.root)):
                with self.assertRaisesRegex(ValueError, 'unrecognized native principal modification'):
                    call()
        self.assertEqual(self.replace.call_count, 0)

    def test_apply_requires_the_same_complete_stack(self):
        c = self.checkout
        for breaker, message in ((lambda: c.set_ce(False), 'the owner lifecycle CE companion'),
                                 (lambda: c.put(lifecycle.ADDED, None), 'the owner lifecycle CE companion'),
                                 (lambda: c.set_package('VERITY'), 'package verity with its payload sync companion'),
                                 (lambda: c.set_package('UPSTREAM'), 'package verity with its payload sync companion'),
                                 (lambda: c.set_native(False), 'the complete native principal companion'),
                                 (lambda: c.put(pins.FILES[0], c.tracked[pins.FILES[0]]),
                                  'the complete native principal companion'),
                                 (lambda: c.set_writer(False), 'the exact adapted writer fixture'),
                                 (lambda: c.put(writer.ADDED, None), 'the exact adapted writer fixture')):
            c.lab_ready()
            breaker()
            before = c.settings()
            self.refuse(lab, 'apply', 'apply the complete lab stack first: .*' + message, LAB_FLAG)
            self.assertEqual(c.settings(), before)
            # A check over the absent format still reports, and never requires the lab state.
            self.assertEqual(self.cli(lab, 'check', LAB_FLAG)['state'], lab.ABSENT)
            self.refuse(lab, 'check', 'the admitted lab native store format is required', LAB_FLAG, '--require-lab')
        self.assertEqual(self.replace.call_count, 0)
        c.lab_ready()
        result = self.cli(lab, 'apply', LAB_FLAG, '--require-lab')
        self.assertEqual((result['state'], result['state_after'], result['action']), (lab.ABSENT, lab.STATE, 'apply'))
        self.assertEqual((c.settings(), self.replace.call_count), (c.lab_settings, 1))
        result = self.cli(lab, 'apply', LAB_FLAG)
        self.assertEqual((result['state'], result['state_after'], self.replace.call_count), (lab.STATE, lab.STATE, 1))

    def test_ordered_apply_through_the_actual_tools(self):
        self.refuse(lab, 'apply', 'apply the complete lab stack first', LAB_FLAG)
        self.cli(lifecycle, 'apply')
        self.cli(verity, 'apply')
        self.cli(payload, 'apply')
        self.refuse(writer, 'apply', 'actual native principal manager adaptation required first', '--lab-test-only')
        self.refuse(lab, 'apply', 'complete native principal companion', LAB_FLAG)
        self.cli(pins, 'apply', '--require-adapted')
        self.refuse(lab, 'apply', 'exact adapted writer fixture', LAB_FLAG)
        self.cli(writer, 'apply', '--lab-test-only', '--require-adapted')
        result = self.cli(lab, 'apply', LAB_FLAG, '--require-lab')
        self.assertEqual(result['companions_after'], {
            'owner-lifecycle': 'ADAPTED', 'package-verity': 'ADAPTED', 'package-installer-payload-sync': 'ADAPTED',
            'native-principal-pins': lab.STATE, 'native-identity-writer': 'ADAPTED'})
        self.assertEqual(result['order'], {'apply': lab.APPLY_ORDER, 'revert': lab.REVERT_ORDER})
        self.assertEqual(self.checkout.settings(), self.checkout.lab_settings)
        # Normal build admission never takes the lab state for ADAPTED.
        self.refuse(pins, 'check', 'explicit lab history admission', '--require-adapted')

    def test_revert_reverses_the_format_first(self):
        c = self.checkout
        c.lab_ready()
        c.put(SETTINGS, c.lab_settings)
        self.refuse(writer, 'revert', 'explicit lab history admission', '--lab-test-only')
        self.refuse(pins, 'revert', 'explicit lab history admission')
        self.refuse(payload, 'revert', 'explicit lab history admission')
        self.refuse(verity, 'revert', 'explicit lab history admission')
        self.refuse(lab, 'revert', 'cannot require the lab format during revert', LAB_FLAG, '--require-lab')
        self.assertEqual((c.settings(), self.replace.call_count), (c.lab_settings, 0))
        result = self.cli(lab, 'revert', LAB_FLAG)
        self.assertEqual((result['state'], result['state_after']), (lab.STATE, lab.ABSENT))
        self.assertEqual((c.settings(), self.replace.call_count), (c.native_target[SETTINGS], 1))
        self.cli(lab, 'revert', LAB_FLAG)
        self.assertEqual(self.replace.call_count, 1)
        self.refuse(lab, 'check', 'the admitted lab native store format is required', LAB_FLAG, '--require-lab')
        self.cli(writer, 'revert', '--lab-test-only')
        self.cli(pins, 'revert')
        self.cli(payload, 'revert')
        self.assertEqual(c.settings(), c.tracked[SETTINGS])
        # Reverting the format again over the reverted native companion changes nothing.
        result = self.cli(lab, 'revert', LAB_FLAG)
        self.assertEqual((result['state'], result['settings_state'], c.settings()),
                         (lab.ABSENT, 'UPSTREAM', c.tracked[SETTINGS]))
        self.refuse(lab, 'apply', 'complete native principal companion', LAB_FLAG)

    def test_evidence_and_arguments_keep_the_same_guards(self):
        c = self.checkout
        c.lab_ready()
        existing = self.evidence / 'existing.json'
        existing.write_text('{}\n')
        sealed = self.evidence / 'sealed'
        sealed.mkdir()
        (sealed / 'SEALED').write_text('closed\n')
        outside = ROOT / 'never-written-lab-format-evidence.json'
        for evidence in (existing, c.root / 'inside.json', outside, sealed / 'new.json', c.root):
            with self.assertRaisesRegex(ValueError, 'fresh unsealed evidence'):
                self.main(lab, '--action', 'apply', LAB_FLAG, '--evidence', str(evidence))
        self.assertFalse(outside.exists())
        for action in ('check', 'apply', 'revert'):
            with self.assertRaisesRegex(ValueError, 'explicit lab history scope'):
                self.main(lab, '--action', action, '--evidence', str(self.fresh()))
        with self.assertRaises(SystemExit):
            self.main(lab, '--action', 'apply', '--lab-test-only', '--evidence', str(self.fresh()))
        self.assertEqual((c.settings(), self.replace.call_count), (c.native_target[SETTINGS], 0))

    def test_other_framework_changes_are_still_refused_under_lab_admission(self):
        c = self.checkout
        c.lab_ready()
        c.put(SETTINGS, c.lab_settings)
        self.cli(lab, 'check', LAB_FLAG)
        for field, value in (('also_modified', 'services/core/java/com/android/server/Unrelated.java'),
                             ('staged', SETTINGS)):
            getattr(c, field).append(value)
            self.refuse(lab, 'check', FENCE, LAB_FLAG)
            self.refuse(lab, 'revert', FENCE, LAB_FLAG)
            getattr(c, field).remove(value)
        # A copy of the lab patch, profile or bytes inside the checkout is an untracked file, never authority.
        for name, data in (('services/core/java/com/android/server/pm/native-store-format-v2.patch', lab.PATCH.read_bytes()),
                           ('services/core/java/com/android/server/pm/native-store-format-v2.json', lab.PROFILE.read_bytes()),
                           ('services/core/java/com/android/server/pm/Settings.java.lab', c.lab_settings)):
            c.put(name, data)
            self.refuse(lab, 'check', FENCE, LAB_FLAG)
            c.put(name, None)
        c.put(lifecycle.FILES[0], b'changed')
        self.refuse(lab, 'check', 'unrecognized framework modification', LAB_FLAG)
        c.set_ce(True)
        c.set_package(b'unknown Package Installer bytes\n')
        self.refuse(lab, 'check', 'unrecognized Package Installer modification', LAB_FLAG)
        c.set_package('COMBINED')
        c.head = '0' * 40
        with self.assertRaises(ValueError):
            self.main(lab, '--action', 'check', LAB_FLAG, '--evidence', str(self.fresh()))
        c.head = lab.HEAD
        self.cli(lab, 'check', LAB_FLAG, '--require-lab')
        self.assertEqual(self.replace.call_count, 0)


class SyntheticLabCompositionTests(LabComposition, unittest.TestCase):
    real = False


@unittest.skipUnless(PINNED, 'ANDRIX_PINNED_FRAMEWORK not set')
class PinnedLabCompositionTests(LabComposition, unittest.TestCase):
    real = True

    def test_pinned_candidate_changes_only_settings_by_one_token(self):
        value = pins.profile()
        original = {row['path']: (Path(PINNED) / row['path']).read_bytes() for row in value['files']}
        self.assertEqual({name: sha(data) for name, data in original.items()},
                         {row['path']: row['upstream_sha256'] for row in value['files']})
        output = pins.targets(original, value)
        lab_bytes = lab.candidate(output[SETTINGS])
        self.assertEqual(sha(lab_bytes), lab.profile()['file']['output_sha256'])
        for row in value['files']:
            if row['path'] != SETTINGS:
                self.assertEqual(sha(output[row['path']]), row['candidate_sha256'], row['path'])
        self.assertEqual(sum(a != b for a, b in zip(output[SETTINGS], lab_bytes)), 1)
        self.assertEqual(lab.one_token(output[SETTINGS], lab_bytes), output[SETTINGS].index(lab.PRODUCTION) + 28)
        for wrong in (original[SETTINGS], lab_bytes):
            with self.assertRaises(ValueError):
                lab.patched(wrong)
            with self.assertRaises(ValueError):
                lab.candidate(wrong)


class LabFormatSourceTests(unittest.TestCase):
    def test_exact_profile_pins_and_metadata(self):
        value = lab.profile()
        native = {row['path']: row for row in pins.profile()['files']}[SETTINGS]
        self.assertEqual((value['lab_only'], value['native_execution_enabled'], value['format'],
                          value['production_format'], value['state']), (True, False, 'V2', 'V1', lab.STATE))
        self.assertEqual((value['file']['upstream_sha256'], value['file']['input_sha256']),
                         (native['upstream_sha256'], native['candidate_sha256']))
        self.assertEqual(value['file']['input_sha256'], 'd18ffbd11b4382046ab7df33dec2913ca527bb31e5acfe32b38da2a1d2b17ba6')
        self.assertEqual(value['file']['output_sha256'], '301cb589989220fb017fa9ab58fd2a36775dc68ec49362e73e15770a84408455')
        self.assertEqual(value['patch_sha256'], sha(lab.PATCH.read_bytes()))
        self.assertEqual(value['requires']['writer_profile_sha256'], sha(writer.PROFILE.read_bytes()))
        self.assertEqual(lab.PATCH.relative_to(ROOT).parts[:2], ('tests', 'native-identity'))
        self.assertNotIn(ROOT / 'patches', lab.PATCH.parents)

    def test_profile_drift_refused(self):
        original = json.loads(lab.PROFILE.read_text())
        directory = scratch(self)
        path = directory / 'profile.json'
        file = original['file']
        variants = [dict(original, version=True), dict(original, head='0' * 40), dict(original, lab_only=False),
                    dict(original, native_execution_enabled=True), dict(original, native_execution_enabled=0),
                    dict(original, format='V1'), dict(original, format='V3'), dict(original, production_format='V2'),
                    dict(original, state='ADAPTED'), dict(original, patch_sha256='0' * 64), dict(original, extra=1),
                    {key: item for key, item in original.items() if key != 'scope'},
                    dict(original, file=dict(file, path='services/core/java/com/android/server/pm/Other.java')),
                    dict(original, file=dict(file, method='applyNativeIdentityStoreLPw')),
                    dict(original, file=dict(file, input_sha256=file['upstream_sha256'])),
                    dict(original, file=dict(file, upstream_sha256='0' * 64)),
                    dict(original, file=dict(file, output_sha256=file['input_sha256'])),
                    dict(original, file=dict(file, output_sha256=file['output_sha256'].upper())),
                    dict(original, requires=dict(original['requires'], writer_profile_sha256='0' * 64)),
                    dict(original, requires=dict(original['requires'], writer_helper_sha256='0' * 64)),
                    dict(original, requires=dict(original['requires'], native_profile='patches/other.json')),
                    dict(original, subject=dict(original['subject'], signer_sha256='0' * 64)),
                    dict(original, subject=dict(original['subject'], version_code=2)),
                    dict(original, subject=dict(original['subject'], version_code=True)),
                    dict(original, subject=dict(original['subject'], user_id=10)),
                    dict(original, subject=dict(original['subject'], package='dev.andrix.proof.principal')),
                    dict(original, order={'apply': lab.APPLY_ORDER[::-1], 'revert': lab.REVERT_ORDER}),
                    dict(original, order={'apply': lab.APPLY_ORDER, 'revert': lab.REVERT_ORDER[1:]})]
        # Only the separately tested location rule is bypassed, so each refusal is its own rule.
        path.write_text(json.dumps(original))
        with mock.patch.object(lab, 'PROFILE', path), mock.patch.object(lab, 'require_location', lambda: None):
            self.assertEqual(lab.profile(), original)
        for value in variants:
            path.write_text(json.dumps(value))
            with self.subTest(value=value), mock.patch.object(lab, 'PROFILE', path), \
                    mock.patch.object(lab, 'require_location', lambda: None), self.assertRaises(ValueError):
                lab.profile()
        for text in (lab.PROFILE.read_text().replace('"version": 1', '"version": 1, "version": 1', 1),
                     lab.PROFILE.read_text().replace('"version": 1', '"version": NaN', 1)):
            path.write_text(text)
            with mock.patch.object(lab, 'PROFILE', path), mock.patch.object(lab, 'require_location', lambda: None), \
                    self.assertRaises(ValueError):
                lab.profile()

    def test_store_only_correction_keeps_the_format_admissible(self):
        real = pins.profile()
        self.assertNotIn('native_profile_sha256', lab.profile()['requires'])
        store = pins.PREFIX + 'NativeIdentityStore.java'
        corrected = json.loads(json.dumps(real))
        corrected['patch_sha256'] = '1' * 64
        for row in corrected['added']:
            if row['path'] == store:
                row['sha256'] = '0' * 64
        with mock.patch.object(pins, 'profile', lambda: corrected):
            self.assertEqual(lab.profile()['file']['input_sha256'],
                             'd18ffbd11b4382046ab7df33dec2913ca527bb31e5acfe32b38da2a1d2b17ba6')
        for field, value in (('candidate_sha256', '2' * 64), ('upstream_sha256', '3' * 64)):
            changed = json.loads(json.dumps(corrected))
            for row in changed['files']:
                if row['path'] == SETTINGS:
                    row[field] = value
            with self.subTest(field=field), mock.patch.object(pins, 'profile', lambda changed=changed: changed), \
                    self.assertRaisesRegex(ValueError, 'lab format profile drift'):
                lab.profile()
        # The current normal profile is still validated with every source hash it requires.
        with mock.patch.object(pins, 'profile', side_effect=ValueError('native principal helper drift')), \
                self.assertRaisesRegex(ValueError, 'native principal helper drift'):
            lab.profile()

    def test_inputs_must_stay_outside_the_production_patches(self):
        lab.require_location()
        inside = ROOT / 'patches/grapheneos-2026081300'
        for attribute in ('PROFILE', 'PATCH'):
            moved = {attribute: inside / getattr(lab, attribute).name}
            other = 'PATCH' if attribute == 'PROFILE' else 'PROFILE'
            moved[other] = inside / getattr(lab, other).name
            with mock.patch.object(lab, 'DIRECTORY', inside), mock.patch.object(lab, 'PROFILE', moved['PROFILE']), \
                    mock.patch.object(lab, 'PATCH', moved['PATCH']), \
                    self.assertRaisesRegex(ValueError, 'outside the production patches'):
                lab.profile()
        with mock.patch.object(lab, 'PATCH', ROOT / 'tests/native-identity/native-store-format-v2.patch'), \
                self.assertRaisesRegex(ValueError, 'outside the production patches'):
            lab.profile()
        directory = scratch(self)
        link = directory / lab.PROFILE.name
        link.symlink_to(lab.PROFILE)
        with mock.patch.object(lab, 'PROFILE', link), mock.patch.object(lab, 'DIRECTORY', directory), \
                self.assertRaisesRegex(ValueError, 'outside the production patches'):
            lab.profile()

    def test_writer_helper_cert_and_version_mismatches_refuse(self):
        directory = scratch(self)
        text = writer.HELPER.read_text()
        subject = lab.profile()['subject']
        self.assertEqual(lab.subject_constants(text), subject)
        real_writer, real_relative = writer.profile(), lab.relative
        changes = {'cert': (subject['signer_sha256'], '0' * 64),
                   'version': ('chosen.versionCode != 1', 'chosen.versionCode != 2'),
                   'user': ('chosen.userId != 0', 'chosen.userId != 10'),
                   'subject': ('"dev.andrix.proof.principalclosed"', '"dev.andrix.proof.principal"')}
        for name, (old, new) in changes.items():
            changed = text.replace(old, new)
            self.assertNotEqual(changed, text, name)
            self.assertNotEqual(lab.subject_constants(changed), subject, name)
            helper = directory / (name + '.java')
            helper.write_text(changed)
            # A self consistent writer profile for the changed helper, as a careless update would leave.
            writer_path = directory / (name + '-writer.json')
            writer_path.write_text(json.dumps(dict(real_writer, added=dict(real_writer['added'],
                                                                             sha256=sha(helper.read_bytes())))))
            names = {helper: real_relative(writer.HELPER), writer_path: real_relative(writer.PROFILE)}
            repinned = json.loads(lab.PROFILE.read_text())
            repinned['requires'].update(writer_profile_sha256=sha(writer_path.read_bytes()),
                                        writer_helper_sha256=sha(helper.read_bytes()))
            repinned_path = directory / (name + '-lab.json')
            repinned_path.write_text(json.dumps(repinned))
            # The pinned writer hashes refuse first; with them repinned the subject still refuses.
            for profile, message in ((lab.PROFILE, 'requires the exact writer fixture'),
                                     (repinned_path, 'subject differs from the writer fixture')):
                with self.subTest(name=name, message=message), \
                        mock.patch.object(lab, 'require_location', lambda: None), \
                        mock.patch.object(lab, 'PROFILE', profile), \
                        mock.patch.object(lab, 'relative', lambda path, names=names: names.get(path) or real_relative(path)), \
                        mock.patch.object(writer, 'HELPER', helper), mock.patch.object(writer, 'PROFILE', writer_path), \
                        mock.patch.object(writer, 'profile', lambda path=writer_path: json.loads(path.read_text())), \
                        self.assertRaisesRegex(ValueError, message):
                    lab.profile()
        for broken in (text.replace('Set.of(FIXTURE_SIGNER)', 'Set.of()'), text + '\n' + text):
            with self.assertRaises(ValueError):
                lab.subject_constants(broken)
        # The writer companion's own profile must name the same helper bytes.
        drifted = dict(real_writer, added=dict(real_writer['added'], sha256='0' * 64))
        with mock.patch.object(writer, 'profile', lambda: drifted), \
                self.assertRaisesRegex(ValueError, 'requires the exact writer fixture'):
            lab.profile()

    def test_patch_must_be_one_exact_token(self):
        text = lab.PATCH.read_text()
        self.assertEqual(lab.patch_change(text), ('-                NativeIdentityStore.Format.V1);',
                                                  '+                NativeIdentityStore.Format.V2);'))
        hunk = text[text.index('@@'):]
        variants = {
            'second hunk': text + hunk.replace('@@ -611,7 +611,7 @@', '@@ -711,7 +711,7 @@'),
            'third token': text.replace('Format.V2);', 'Format.V3);'),
            'reversed': text.replace('-                NativeIdentityStore.Format.V1);', '-X').replace(
                '+                NativeIdentityStore.Format.V2);', '-                NativeIdentityStore.Format.V1);').replace(
                '-X', '+                NativeIdentityStore.Format.V2);'),
            'value selector': text.replace('+                NativeIdentityStore.Format.V2);',
                                           '+                NativeIdentityStore.Format.valueOf("V2"));'),
            'property selector': text.replace('+                NativeIdentityStore.Format.V2);',
                                              '+                NativeIdentityStore.Format.valueOf(android.os.SystemProperties'
                                              '.get("persist.andrix.native_format", "V1")));'),
            'boolean selector': text.replace('+                NativeIdentityStore.Format.V2);',
                                             '+                true ? NativeIdentityStore.Format.V2 : NativeIdentityStore.Format.V1);'),
            'store path': text.replace(' "native-principals"),', ' "native-principals-lab"),'),
            'another removed line': text.replace('\n         mNativeIdentityStore = new', '\n-        mNativeIdentityStore = new', 1),
            'crlf': text.replace('\n', '\r\n'),
            'escaping path': text.replace('a/' + SETTINGS, 'a/../outside.java'),
            'other file': text.replace(SETTINGS, SETTINGS.replace('Settings', 'PackageManagerService')),
            'unterminated': text[:-1],
            'extra added line': text.replace('+                NativeIdentityStore.Format.V2);',
                                             '+                NativeIdentityStore.Format.V2);\n+        // selected')}
        for name, variant in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                lab.patch_change(variant)

    def test_one_token_equivalence_and_selector_mutants(self):
        before, after = boot_text(), boot_text(lab.LAB)
        self.assertEqual(lab.one_token(before, after), before.index(lab.PRODUCTION) + 28)
        mutants = {
            'second byte before': (before, after.replace(b'filler', b'fillex', 1)),
            'second byte after': (before, after.replace(b'return null;', b'return nulk;')),
            'third format': (before, boot_text(b'NativeIdentityStore.Format.V3);')),
            'store path': (before, boot_text(lab.LAB, path=b'"native-principalz"')),
            'boolean selector': (before, boot_text(b'true ? NativeIdentityStore.Format.V2 : NativeIdentityStore.Format.V1);')),
            'value selector': (before, boot_text(b'NativeIdentityStore.Format.valueOf(SystemProperties.get("f", "V1")));')),
            'values selector': (before, boot_text(b'NativeIdentityStore.Format.values()[1]);')),
            'reversed': (after, before),
            'unchanged': (before, before),
            'other method': (boot_text(method=b'    NativeIdentityStore.Loaded readOtherStore() {\n'),
                             boot_text(lab.LAB, method=b'    NativeIdentityStore.Loaded readOtherStore() {\n')),
            'second construction': (before + before, after + before),
            'after the boot construction': (lab.METHOD + lab.BOOT_END + lab.CONSTRUCTION + lab.PRODUCTION + b'\n',
                                            lab.METHOD + lab.BOOT_END + lab.CONSTRUCTION + lab.LAB + b'\n'),
            'text': (before.decode(), after.decode()),
        }
        for name, (old, new) in mutants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                lab.one_token(old, new)

    def test_patch_applies_only_to_its_exact_context(self):
        body = lab.PATCH.read_text().split('\n')[3:-1]
        old = '\n'.join(line[1:] for line in body if line[:1] in (' ', '-')) + '\n'
        filler = ''.join('    // line %d\n' % index for index in range(620))
        before = (filler + lab.METHOD.decode() + old + '    }\n').encode()
        after = lab.patched(before)
        self.assertEqual(after, before.replace(lab.PRODUCTION, lab.LAB))
        lab.one_token(before, after)
        for wrong in (after, before.replace(b'"native-principals"', b'"native-principalz"'), b''):
            with self.assertRaises(ValueError):
                lab.patched(wrong)
        with self.assertRaisesRegex(ValueError, 'exact adapted B2 Settings'):
            lab.candidate(before)

    def test_lab_patch_copied_under_patches_trips_the_unmodified_production_guard(self):
        self.assertEqual(b1.format_violations(b1.production_texts()), [])
        root = scratch(self)
        shutil.copytree(ROOT / b1.FRAMEWORK_DIR, root / b1.FRAMEWORK_DIR)
        shutil.copytree(ROOT / 'patches', root / 'patches')
        fixture = 'tests/native-identity/writer/NativePrincipalWriterFixture.java'
        (root / fixture).parent.mkdir(parents=True)
        shutil.copy2(ROOT / fixture, root / fixture)
        with mock.patch.object(b1, 'ROOT', root):
            self.assertEqual(b1.format_violations(b1.production_texts()), [])
            for target in ('patches/grapheneos-2026081300/native-store-format-v2.patch', 'patches/lab/any-name.patch'):
                copy = root / target
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(lab.PATCH, copy)
                problems = b1.format_violations(b1.production_texts())
                self.assertTrue(any('Format.V2' in problem for problem in problems), problems)
                copy.unlink()
            self.assertEqual(b1.format_violations(b1.production_texts()), [])

    def test_admission_decisions(self):
        complete = {'state': 'ADAPTED', 'payload_sync_companion': {'state': 'ADAPTED'}}
        verity_only = {'state': 'ADAPTED', 'payload_sync_companion': {'state': 'UPSTREAM'}}
        package_upstream = {'state': 'UPSTREAM', 'payload_sync_companion': {'state': 'UPSTREAM'}}
        adapted = {'state': 'ADAPTED', 'files': {SETTINGS: 'ADAPTED'}}
        labbed = {'state': lab.STATE, 'files': {SETTINGS: lab.STATE}}
        partial = {'state': 'PARTIAL', 'files': {SETTINGS: lab.STATE}}
        ready, missing, half = {'state': 'ADAPTED'}, {'state': 'UPSTREAM'}, {'state': 'PARTIAL'}
        # Without the lab state the decision returns before any companion detail is read, as the
        # older package verity fence mock expects: its report has no payload sync entry.
        bare = {'state': 'ADAPTED', 'file': verity.FILE}
        for ce, package, writer_state, flag in (('UPSTREAM', bare, missing, False), ('PARTIAL', {}, half, True),
                                                ('ADAPTED', complete, ready, True)):
            self.assertEqual(lab.require_admission(ce, package, adapted, writer_state, flag), lab.ABSENT)
        self.assertEqual(lab.require_admission('ADAPTED', complete, labbed, ready, True), lab.STATE)
        for ce, package, native, writer_state, flag, message in (
                ('ADAPTED', complete, labbed, ready, False, 'explicit lab history admission'),
                ('ADAPTED', complete, labbed, ready, 1, 'explicit lab history admission'),
                ('ADAPTED', complete, labbed, ready, 'yes', 'explicit lab history admission'),
                ('UPSTREAM', bare, partial, missing, False, 'explicit lab history admission'),
                ('UPSTREAM', complete, labbed, ready, True, 'the owner lifecycle CE companion'),
                ('PARTIAL', complete, labbed, ready, True, 'the owner lifecycle CE companion'),
                ('ADAPTED', verity_only, labbed, ready, True, 'package verity with its payload sync companion'),
                ('ADAPTED', package_upstream, labbed, ready, True, 'package verity with its payload sync companion'),
                # An inconsistent report, payload sync without package verity, refuses too.
                ('ADAPTED', {'state': 'UPSTREAM', 'payload_sync_companion': {'state': 'ADAPTED'}}, labbed, ready, True,
                 'package verity with its payload sync companion'),
                ('ADAPTED', complete, partial, ready, True, 'the complete native principal companion'),
                ('ADAPTED', complete, labbed, missing, True, 'the exact adapted writer fixture'),
                ('ADAPTED', complete, labbed, half, True, 'the exact adapted writer fixture')):
            with self.subTest(ce=ce, native=native['state'], writer=writer_state, flag=flag), \
                    self.assertRaisesRegex(ValueError, message):
                lab.require_admission(ce, package, native, writer_state, flag)
        with self.assertRaisesRegex(ValueError, 'the complete native principal companion, the exact adapted writer '
                                                'fixture, the owner lifecycle CE companion, package verity'):
            lab.require_admission('PARTIAL', package_upstream, partial, missing, True)
        self.assertEqual(lab.stack_problems('ADAPTED', complete, lab.STATE, 'ADAPTED'), [])

    def test_lab_derivation_failures_refuse_consistently(self):
        target = {SETTINGS: b'adapted'}
        for error in (ValueError('drift'), KeyError('file'), TypeError('shape'), FileNotFoundError('profile'),
                      subprocess.TimeoutExpired(['/usr/bin/patch'], 30),
                      subprocess.CalledProcessError(1, ['/usr/bin/patch'])):
            with self.subTest(error=type(error).__name__), mock.patch.object(lab, 'candidate', side_effect=error), \
                    self.assertRaisesRegex(ValueError, 'unrecognized native principal modification: .*Settings.java '
                                                       r'\(lab format unavailable: ' + type(error).__name__):
                pins.lab_format_state(SETTINGS, b'unknown', target)
        with mock.patch.dict(sys.modules, {'native_lab_format': None}), \
                self.assertRaisesRegex(ValueError, 'lab format unavailable: (ImportError|ModuleNotFoundError)'):
            pins.lab_format_state(SETTINGS, b'unknown', target)
        with mock.patch.object(lab, 'candidate', side_effect=AssertionError('loaded')):
            self.assertIsNone(pins.lab_format_state(pins.FILES[0], b'unknown', target))
            self.assertIsNone(pins.lab_format_state(SETTINGS, None, target))
        for error in (subprocess.TimeoutExpired(['/usr/bin/patch'], 30), FileNotFoundError('/usr/bin/patch')):
            fake = types.SimpleNamespace(run=mock.Mock(side_effect=error), SubprocessError=subprocess.SubprocessError)
            with self.subTest(error=type(error).__name__), mock.patch.object(lab, 'subprocess', fake), \
                    self.assertRaisesRegex(ValueError, 'exact lab format patch unavailable: ' + type(error).__name__):
                lab.patched(b'any Settings bytes')

    def test_build_scope_reads_no_untracked_output_download_or_evidence_tree(self):
        root = scratch(self)
        for name in ('Android.bp', 'owner/Android.bp', 'products/phone.mk', 'tests/native-identity/Android.bp'):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text('clean\n')
        for decoy in ('out/native-history-lab/Android.bp', 'out/evidence/product.mk', 'node_modules/a/Android.bp',
                      'downloads/b.mk', 'private/c.bp', 'owner/out/d.mk', 'tests/node_modules/e.bp'):
            path = root / decoy
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('native-store-format-v2 LabHistoryStore lab-history\n')
        with mock.patch.object(pathlib.Path, 'read_text', autospec=True, side_effect=pathlib.Path.read_text) as read:
            scanned = build_definitions(root)
            self.assertEqual(lab_selections(root, scanned), [])
        self.assertEqual(sorted(path.relative_to(root).as_posix() for path in scanned),
                         ['Android.bp', 'owner/Android.bp', 'products/phone.mk', 'tests/native-identity/Android.bp'])
        self.assertFalse(any('out' in Path(call.args[0]).parts or 'node_modules' in Path(call.args[0]).parts
                             for call in read.call_args_list))
        # A scoped definition that names or globs the lab files is found.
        (root / 'owner/Android.bp').write_text('srcs: ["tests/native-identity/lab-history/LabHistoryStore.java"]\n')
        (root / 'tests/native-identity/Android.bp').write_text('srcs: ["**/*.java"]\n')
        self.assertEqual(len(lab_selections(root, build_definitions(root))), 2)

    def test_build_scope_covers_every_tracked_build_definition(self):
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', '*.bp', '*.mk'],
                                 capture_output=True, check=True, timeout=30).stdout
        paths = {name.decode('utf-8') for name in tracked.split(b'\0') if name}
        covered = {path.relative_to(ROOT).as_posix() for path in build_definitions(ROOT)}
        self.assertTrue(paths)
        self.assertEqual(paths - covered, set(), 'new build source needs an explicit audit scope')

    def test_native_execution_factory_stays_off_and_nothing_selects_the_lab(self):
        self.assertIs(lab.profile()['native_execution_enabled'], False)
        self.assertIs(writer.profile()['native_execution_enabled'], False)
        self.assertIn('owner account designation/factory not connected', pins.profile()['activation_fences'])
        for name in LAB_FILES:
            self.assertTrue((ROOT / name).is_file(), name)
        scanned = build_definitions(ROOT)
        self.assertIn(ROOT / 'tests/native-identity/Android.bp', scanned)
        self.assertEqual(lab_selections(ROOT, scanned), [])
        framework = ''.join(path.read_text() for path in sorted((ROOT / b1.FRAMEWORK_DIR).glob('*.java')))
        self.assertNotIn('native_lab_format', framework)
        self.assertNotIn('LAB_FORMAT_V2', framework)

    def test_existing_writer_checks_and_fence_lines_are_unchanged(self):
        for name, digest in UNCHANGED.items():
            self.assertEqual(sha((ROOT / name).read_bytes()), digest, name)
        fence = (ROOT / 'scripts/proof/android_lifecycle.py').read_text()
        self.assertIn('def inspect(root, *, lab_writer_fixture=False):', fence)
        self.assertIn('native_identity_writer.require_admission(native_writer, lab_writer_fixture)', fence)
        # The outermost lab layer is diagnosed first, so a normal refusal names what to reverse first.
        decision = 'native_lab_format.require_admission(state, package, native_pins, native_writer,'
        self.assertEqual(fence.count('native_lab_format.require_admission('), 1)
        self.assertLess(fence.index(decision),
                        fence.index('native_identity_writer.require_admission(native_writer, lab_writer_fixture)'))
        self.assertLess(fence.index("    state = next(iter(set(states.values())))"), fence.index(decision))
        # The lab inspector calls the shared fence, never its own tool or itself.
        source_text = Path(lab.__file__).read_text()
        self.assertEqual(source_text.count('android_lifecycle.inspect_lab_native_format(root)'), 1)
        self.assertNotIn('android_lifecycle.inspect(', source_text)
        self.assertNotIn('native_lab_format.main', fence + (ROOT / 'scripts/proof/native_principal_pins.py').read_text())


if __name__ == '__main__':
    unittest.main()
