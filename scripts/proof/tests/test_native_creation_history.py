# SPDX-License-Identifier: Apache-2.0
"""B2 historical identities and restored creation rebinding: pure source guards, harness
generation, the 0018a1d parity rules and the runner's refusals and evidence retention. The guarded
JVM matrix is only in the runner, which is NOT RUN without the required resource bounds and a
short enough work path. These tests start no compiler or JVM. Not Android runtime proof."""
from pathlib import Path
import ast
import contextlib
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_history as runner  # noqa: E402

# The pinned canonical framework copies, which the lab history runner's pure suites always name.
PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')
HISTORY = 'scripts/proof/native_creation_history.py'


def synthetic_settings(fragments=None, side=None):
    """A minimal candidate that holds every B2 fragment and harness text at its adapted position:
    the current fragments, or those given, such as the archived ones. A side names the candidate in
    its hold refresh, which every harness copies, so each side's harness is its own."""
    if fragments is None:
        fragments = {name: path.read_text() for name, (_, path) in runner.integration.FRAGMENTS.items()}
    refresh = '    void refreshNativePrincipalAppIdsLPw() {\n' + ('        // candidate %s\n' % side if side else '')
    # The lifecycle texts of a current candidate: the boot facts and the retired boot queries after
    # the boot method, which records the boot facts last, and the release finish after observation.
    lifecycle = 'boot-facts' in fragments
    boot = '        recordNativeBootFactsLPw(loaded);\n' if lifecycle else ''
    queries = fragments['boot-facts'] + '\n' + fragments['retired-boot'] + '\n' if lifecycle else ''
    release = ('    void finishNativeIdentityReleaseLPw(NativePrincipalPins.Record record,'
               ' NativeIdentityStore.Loaded loaded) {\n        observeNativeIdentityStoreLPw(loaded);\n    }\n\n'
               if lifecycle else '')
    return ('final class Settings {\n'
            '    private final java.util.Map<Long, NativeIdentityStore.History> mNativeRememberedBindings =\n'
            '            new java.util.HashMap<>();\n\n'
            '    void applyNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'
            + fragments['restore-history'] + fragments['restore-capacity']
            + '        mNativePrincipalPins = restored;\n'
            '        observeNativeIdentityStoreLPw(loaded);\n'
            '        seedNativeRecoveryLPw();\n' + boot + '    }\n\n' + queries
            + fragments['scan'] + '\n    boolean nativePrincipalCreationReadyLPr() {\n        return true;\n    }\n\n'
            '    NativeIdentityRecords.Slot nativePrincipalBindingLPr(NativePrincipalPins.Record record) {\n'
            '        if (!mNativeIdentityLoaded.bindingUsable(record.appId)) return null;\n'
            '        return mNativeIdentityLoaded.slots.get(record.appId).value;\n    }\n\n'
            + fragments['stored-history']
            + '\n    String nativeIdentityLineageLPr() {\n        return mNativeIdentityLoaded.header.value.lineage;\n'
            '    }\n\n'
            '    boolean isNativePrincipalAppIdLPr(int appId) {\n'
            '        return mNativeStoreAppIds.contains(appId) || nativePrincipalPinsLPr().isAppIdPinned(appId);\n'
            '    }\n\n' + fragments['identity'] + '\n' + fragments['path-safety']
            + '\n    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'
            '        mNativeIdentityLoaded = loaded;\n'
            '        mNativeStoreAppIds.addAll(loaded.occupiedAppIds);\n'
            '        rememberNativeHistoriesLPw(loaded);\n'
            '        refreshNativePrincipalAppIdsLPw();\n    }\n\n'
            + release + refresh +
            '        java.util.Set<Integer> held = new java.util.TreeSet<>(mNativeStoreAppIds);\n'
            '        held.addAll(nativePrincipalPinsLPr().reservedAppIds());\n'
            '        mAppIds.setNativePrincipalAppIds(held);\n'
            '        mNativeRecoveryView = mNativeRecoveryView.withHolds(held);\n'
            '        onChanged();\n    }\n\n'
            + fragments['recovery-seeding']
            + '\n    @Watched(manual = true)\n    private final PccIdSettingMap mPccIds;\n}\n')


def scratch(test):
    """A fresh directory below the caller's TMPDIR, removed after the test."""
    directory = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, directory)
    return directory


def suite_result(stdout, returncode):
    """A finished suite record as the B1 runner's execute and outcome report it."""
    run = {'returncode': returncode, 'stdout': stdout, 'stderr': '',
           'passed': re.findall(r'^PASS (.+)$', stdout, re.M),
           'failed': sorted(set(re.findall(r'^FAIL (.+?): ', stdout, re.M)))}
    return runner.b1.outcome({'build': {'returncode': 0, 'inputs': {}}, 'run': run}, ('a', 'b'))


def parity_line(fmt, name, kind, key, payload):
    return '\t'.join((fmt, name, kind, key, payload))


class CreationHistorySourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_surface_is_the_b2_surface(self):
        self.assertEqual(runner.surface_violations(), [])

    def test_mutants_anchor_once_and_predictions_are_consistent(self):
        sources = runner.mutant_sources()
        self.assertEqual(set(sources), set(runner.MUTANTS))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        names = set(runner.FOCUSED_NAMES) | set(runner.FAULT_NAMES) | {runner.PROBE_CHECK}
        self.assertEqual(set(predictions['b2_mutants_caught_at_least']), set(runner.MUTANTS))
        for name, expected in predictions['b2_mutants_caught_at_least'].items():
            self.assertTrue(expected and set(expected) <= names, name)
            if runner.PROBE_CHECK in expected:
                self.assertIn('probe', runner.MUTANTS[name][2], name)
            if set(expected) & set(runner.FAULT_NAMES):
                self.assertIn('faults', runner.MUTANTS[name][2], name)
        for name, (path, text, _) in sources.items():
            self.assertNotEqual(text, (runner.ROOT / path).read_text(), name)
        self.assertEqual((len(runner.FOCUSED_NAMES), len(runner.FAULT_NAMES), len(runner.LAYOUT_NAMES)),
                         (87, 40, 45))
        self.assertEqual(len(runner.MUTANTS), 40)

    def test_every_focused_and_fault_case_is_named_in_its_source(self):
        focused = (runner.ROOT / runner.PLATFORM / 'NativeCreationHistoryTest.java').read_text()
        for name in runner.FOCUSED_NAMES:
            prefix, _, rest = name.partition(' / ')
            self.assertTrue('"%s"' % name in focused or ('"%s / "' % prefix in focused and rest in focused),
                            name)
        faults = (runner.ROOT / runner.PLATFORM / 'NativeCreationHistoryFaultTest.java').read_text()
        for kind in runner.FAULT_KINDS:
            self.assertIn('"%s / "' % kind, faults)

    def test_harness_takes_each_side_text_and_fills_every_placeholder(self):
        settings = synthetic_settings()
        self.assertEqual(runner.b2_text_checks(settings), [])
        for side in ('b2', runner.BASE):
            source = runner.harness_source(settings, side)
            self.assertIsNone(re.search(r'@[A-Z_]+@', source))
            self.assertIn('NativeIdentityPersistence.scanOwner(', source)
            self.assertIn('private void seedNativeRecoveryLPw() {', source)
            self.assertIn(runner.BODY_INPUTS[side].read_text(), source)
        mutated = runner.mutant_sources()['seeding-body-only'][1]
        self.assertIn(mutated, runner.harness_source(settings, 'b2', mutated))
        with self.assertRaises(ValueError):
            runner.settings_texts(settings.replace('    private void seedNativeRecoveryLPw() {\n', ''))

    def test_harness_runs_the_candidate_boot_observation_and_refresh(self):
        settings = synthetic_settings()
        texts = runner.settings_texts(settings)
        source = runner.harness_source(settings, 'b2')
        for tag in ('APPLY', 'OBSERVE', 'REFRESH', 'STORED', 'REMEMBERED_FIELD'):
            self.assertEqual(source.count(texts[tag]), 1, tag)
        self.assertIn('        rememberNativeHistoriesLPw(loaded);\n', texts['OBSERVE'])
        self.assertIn('mNativeRecoveryView = mNativeRecoveryView.withHolds(held);', texts['REFRESH'])
        self.assertIn('        applyNativeIdentityStoreLPw(loaded);\n', source)
        # No hand copied hold computation remains in the template.
        self.assertNotIn('reservedAppIds', runner.TEMPLATE.read_text())
        body_only = settings.replace('        rememberNativeHistoriesLPw(loaded);\n',
                                     '        if (loaded.bindingUsable(0)) return;\n', 1)
        self.assertEqual(runner.b2_text_checks(body_only),
                         ['candidate observation does not remember through the history view'])
        with self.assertRaises(ValueError):
            runner.settings_texts(settings.replace('    void refreshNativePrincipalAppIdsLPw() {\n', ''))

    def test_cut_requires_single_ordered_anchors(self):
        self.assertEqual(runner.cut('a[b]c', '[', ']'), '[b')
        self.assertEqual(runner.cut('a[b]c', '[', ']', False), 'b')
        for text in ('a[b]c]', 'a[[b]c', 'a]b[c'):
            with self.assertRaises(ValueError):
                runner.cut(text, '[', ']')

    def test_parity_rules(self):
        relation = 'relation\treservation\treservation-published\nrelation\treservation-published\tsame\n'
        old = relation + '\n'.join((
            parity_line('V2', 'reservation', 'restore', '-', 'records= counter=1'),
            parity_line('V2', 'reservation', 'body', '-', 'records='),
            parity_line('V2', 'reservation-published', 'restore', '-', 'records=1/R counter=1'),
            parity_line('V2', 'reservation-published', 'body', '-', 'records=1/R'),
            parity_line('V1', 'reservation', 'restore', '-', 'records= counter=none'),
            parity_line('V1', 'reservation', 'body', '-', 'records='),
            parity_line('V1', 'reservation-published', 'restore', '-', 'records= counter=none'),
            parity_line('V1', 'reservation-published', 'body', '-', 'records='))) + '\n'
        good = old.replace(parity_line('V2', 'reservation', 'restore', '-', 'records= counter=1'),
                           parity_line('V2', 'reservation', 'restore', '-', 'records=1/R counter=1'))
        problems, differing = runner.archived_compare_parity(old, good)
        self.assertEqual((problems, differing), ([], ['reservation']))
        # A body only line never takes the published twin.
        bad_body = good.replace(parity_line('V2', 'reservation', 'body', '-', 'records='),
                                parity_line('V2', 'reservation', 'body', '-', 'records=1/R'))
        self.assertTrue(runner.archived_compare_parity(old, bad_body)[0])
        # A version 1 run always equals 0018a1d on the same bytes.
        bad_v1 = good.replace(parity_line('V1', 'reservation', 'restore', '-', 'records= counter=none'),
                              parity_line('V1', 'reservation', 'restore', '-', 'records=1/R counter=none'))
        self.assertTrue(runner.archived_compare_parity(old, bad_v1)[0])
        # Unchanged twinned output is compared with the twin and fails.
        problems, differing = runner.archived_compare_parity(old, old)
        self.assertTrue(problems)
        self.assertEqual(differing, [])
        thrown = good.replace('records=1/R counter=1\n', 'threw=IllegalArgumentException\n', 1)
        self.assertTrue(any('threw' in problem for problem in runner.archived_compare_parity(old, thrown)[0]))
        for parse in (runner.parse_parity, runner.archived_parse_parity):
            with self.assertRaises(ValueError):
                parse(old + parity_line('V1', 'reservation', 'body', '-', 'records=') + '\n')
        # The living parity lists every outcome of the current sources that differs from the archived
        # side, and only what the predictions state may differ.
        self.assertEqual(runner.parity_differences(good, good), [])
        self.assertEqual(runner.parity_differences(good, old), ['V2/reservation/restore/-'])
        unrelated = good.replace('relation\treservation-published\tsame\n', '')
        self.assertEqual(runner.parity_differences(good, unrelated), ['relation/reservation-published'])
        extra = good + parity_line('V2', 'extra', 'body', '-', 'records=') + '\n'
        self.assertEqual(runner.parity_differences(good, extra), ['V2/extra/body/-'])
        self.assertEqual(runner.parity_differences(extra, good), ['V2/extra/body/-'])
        self.assertEqual(runner.predicted_parity(good, good, []), ([], [], []))
        self.assertEqual(runner.predicted_parity(good, old, []),
                         (['V2/reservation/restore/-'], ['V2/reservation/restore/-'], []))
        self.assertEqual(runner.predicted_parity(good, old, ['V2/reservation/restore/-']),
                         (['V2/reservation/restore/-'], [], []))
        self.assertEqual(runner.predicted_parity(good, good, ['V2/extra/body/-']), ([], [], ['V2/extra/body/-']))
        predicted = json.loads(runner.PREDICTIONS.read_text())['living_parity']
        # The seeding deferral of a mapped retiring history: only the archived body-retiring layout
        # holds one, which under Format.V1 reads no body beside its version 2 header.
        self.assertEqual(predicted['predicted_differences'], sorted(
            '%s/%s/seed/10002/same/%s' % (fmt, layout, owner)
            for fmt, layout in (('V2', 'body-retiring'), ('V1', 'body-retiring~cleared'),
                                ('V2', 'body-retiring~cleared'))
            for owner in ('none', 'matching', 'unowned-name', 'incomplete')))

    def test_living_parity_runs_the_current_sources_with_the_pinned_driver(self):
        settings = synthetic_settings(side='b2')
        files = runner.living_parity_files(settings)
        self.assertEqual(files['tests/NativeHistoryParity.java'],
                         runner.b1.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_PARITY))
        # While the living parity compiles the pinned driver, the working-tree driver, which the living
        # label rows name, keeps those bytes: an edit of it is refused, not silently left unrun.
        self.assertEqual(runner.PARITY_DRIVER.read_bytes(), files['tests/NativeHistoryParity.java'])
        drifted = scratch(self) / 'NativeHistoryParity.java'
        drifted.write_bytes(runner.PARITY_DRIVER.read_bytes().replace(b'\n}', b'\n    // edited\n}', 1))
        self.assertNotEqual(drifted.read_bytes(), runner.PARITY_DRIVER.read_bytes())
        with mock.patch.object(runner, 'PARITY_DRIVER', drifted):
            self.assertIn('parity driver differs from the pinned 24bfb6a driver that the living parity compiles',
                          runner.source_checks())
            self.assertEqual(runner.living_parity_files(settings)['tests/NativeHistoryParity.java'],
                             files['tests/NativeHistoryParity.java'])
        rows = [row for row in runner.b1.HARNESS_LABELS if row[1] == HISTORY and 'NativeHistoryParity' in row[2]
                and row[0] in runner.b1.LIVING_RUN_LABELS]
        self.assertEqual([row[0] for row in rows], ['production', 'legacy'])
        for row in rows:
            self.assertIn('pinned driver', row[3])
        self.assertEqual(files['tests/NativeHistoryHarness.java'], runner.harness_source(settings, 'b2').encode())
        self.assertEqual(files['framework/NativeIdentityStore.java'], (runner.ROOT / runner.STORE).read_bytes())
        self.assertEqual(files['tests/NativeHeaderTestSupport.java'],
                         (runner.ROOT / runner.PLATFORM / 'NativeHeaderTestSupport.java').read_bytes())

    def test_fresh_outside_refuses_repository_and_existing_paths(self):
        with self.assertRaises(ValueError):
            runner.fresh_outside(runner.ROOT / 'scratch-output', 'work directory')
        with self.assertRaises(ValueError):
            runner.fresh_outside(runner.ROOT, 'work directory')

    def test_shared_support_is_0018a1d_with_exactly_the_r0_facade_routing(self):
        # Archived: the 24bfb6a support against 0018a1d's, both pinned Git objects.
        self.assertEqual(runner.archived_support_problems(), [])
        self.assertEqual(set(runner.SUPPORT_R0_SHA256), set(runner.SUPPORT_0018))
        relative = 'NativeHeaderTestSupport.java'
        path = runner.PLATFORM + relative
        current = runner.b1.pinned_bytes(runner.ARCHIVE, path)
        real = runner.b1.git_bytes
        code = '24bfb6a test support differs from 0018a1d beyond the R0 facade routing: ' + relative
        pinned = 'archived test support pin differs from its reviewed R0 bytes: ' + relative

        def problems(changed, reviewed=True):
            """The problems when the 24bfb6a object held other bytes: pinned and, when reviewed,
            also recorded as the R0 bytes."""
            digest = runner.sha(changed)
            archived = (runner.b1.REVISIONS[runner.ARCHIVE], path)

            def objects(revision, name):
                return changed if (revision, name) == archived else real(revision, name)
            with mock.patch.object(runner.b1, 'git_bytes', side_effect=objects), \
                    mock.patch.dict(runner.b1.ARCHIVE_SHA256, {path: digest}), \
                    mock.patch.dict(runner.SUPPORT_R0_SHA256, {relative: digest} if reviewed else {}):
                return runner.archived_support_problems()
        # Code beyond the reviewed routing is refused; a comment is not code.
        for changed in (current.replace(b'NativeHeaderApi.pm(root, false)', b'new PackageManagerService(root, false)'),
                        current.replace(b'static final long SERIAL = 7;', b'static final long SERIAL = 8;')):
            self.assertNotEqual(changed, current)
            self.assertEqual(problems(changed), [code])
        commented = current.replace(b'Shared host fixtures', b'The shared host fixtures', 1)
        self.assertNotEqual(commented, current)
        self.assertEqual(problems(commented), [])
        # The reviewed R0 bytes are the archive's pin, so other pinned bytes are refused.
        self.assertEqual(problems(commented, reviewed=False), [pinned])
        with mock.patch.dict(runner.ARCHIVED_SUPPORT_R0, {relative: ()}):
            self.assertEqual(runner.archived_support_problems(), [code])
        # An object that is not the pinned one never reaches the comparison.
        with mock.patch.object(runner.b1, 'git_bytes', side_effect=lambda revision, name: real(revision, name) + b' '):
            with self.assertRaisesRegex(ValueError, 'archived input drift'):
                runner.archived_support_problems()
        # The working tree's support constrains nothing archived: its living byte pin is retired.
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('working tree read')):
            self.assertEqual(runner.archived_support_problems(), [])

    def test_readers_and_labels(self):
        self.assertEqual(runner.label_problems(), [])
        self.assertEqual(runner.READERS, (('b2-v1', None, 'b1'),))
        self.assertEqual(runner.LEGACY_ROLLBACK, (('b2-v1', None),))
        self.assertIn((runner.ROLLBACK, runner.ROLLBACK, 'b1'), runner.ARCHIVED_READERS)
        self.assertIn(('24bf-v1', runner.ARCHIVE, 'b1'), runner.ARCHIVED_READERS)
        self.assertEqual(runner.ARCHIVED_ROLLBACK_READERS,
                         (('24bf-v1', runner.ARCHIVE), (runner.ROLLBACK, runner.ROLLBACK)))
        self.assertEqual(runner.b1.REVISIONS[runner.ROLLBACK], '78456b352267dba916778b90d7c926c4e67ef888')
        for target, _ in runner.ARCHIVED_ROLLBACK_READERS:
            self.assertEqual(runner.READER_LABELS[target], 'rollback-reader')
        self.assertEqual(runner.READER_LABELS['b2-v1'], 'legacy')
        self.assertEqual({runner.READER_LABELS[runner.BASE], runner.READER_LABELS['c926']}, {'archived-baseline'})
        self.assertEqual([prefix for _, prefix in runner.ROLLBACK_CHECKS], ['rollback reader', 'rollback seeding'])
        for main, prefix in runner.ROLLBACK_CHECKS:
            source = (runner.ROOT / runner.PLATFORM / (main + '.java')).read_text()
            self.assertIn('public final class %s ' % main, source)
            # Each printed case name of the check is one the runner expects.
            for name in ('"%s / "' % prefix, '"%s control / "' % prefix, '"%s / version 2 copy layouts"' % prefix):
                self.assertEqual(source.count(name), 1, (main, name))
        # Every step a guarded run records carries labels of its kind: the probe, parity and archived
        # readers are archived, every other step living.
        self.assertEqual(set(runner.STEP_LABELS), set(runner.PHASES) - {'candidates', 'b1 runner'})
        self.assertEqual(runner.ARCHIVED_STEP_NAMES, ('probe', 'parity', 'archived readers'))
        for step, labels in runner.STEP_LABELS.items():
            allowed = (runner.b1.ARCHIVED_RUN_LABELS if step in runner.ARCHIVED_STEP_NAMES
                       else runner.b1.LIVING_RUN_LABELS)
            self.assertTrue(labels and set(labels) <= set(allowed), step)
        # The current sources' Format.V1 reads are legacy; the archived 24bfb6a parity side's are the
        # rollback reader model's, like the 24bf-v1 reader.
        self.assertEqual(runner.STEP_LABELS['b2 focused'], ('production', 'legacy'))
        self.assertEqual(runner.STEP_LABELS['living parity'], ('production', 'legacy'))
        self.assertEqual(runner.STEP_LABELS['readers'], ('production', 'legacy'))
        self.assertEqual(runner.STEP_LABELS['parity'], ('archived-baseline', 'rollback-reader'))
        self.assertEqual(runner.STEP_LABELS['probe'], ('archived-baseline',))
        history = {}
        for label, harness, classes, _ in runner.b1.HARNESS_LABELS:
            if harness == HISTORY:
                for name in classes:
                    history.setdefault(name, set()).add(label)
        self.assertEqual(history['NativeCreationHistoryTest'], {'production', 'legacy'})
        # Every label but new-format, which only the lifecycle record runner's Format.V3 cases carry.
        self.assertEqual(history['NativeHistoryParity'], set(runner.b1.RUN_LABELS) - {'new-format'})
        # The label rules: each break is refused.
        for change in ({'READER_LABELS': dict(runner.READER_LABELS, **{'b2-v1': 'rollback-reader'})},
                       {'READER_LABELS': {k: v for k, v in runner.READER_LABELS.items() if k != '24bf-v1'}},
                       {'ARCHIVED_READERS': (('24bf-v1', None, 'b1'),) + runner.ARCHIVED_READERS[1:]},
                       {'READERS': (('b2-v1', runner.BASE, 'b1'),)},
                       {'ARCHIVED_ROLLBACK_READERS': (('24bf-v1', runner.ROLLBACK),
                                                      (runner.ROLLBACK, runner.ROLLBACK))},
                       {'ARCHIVED_ROLLBACK_READERS': runner.ARCHIVED_ROLLBACK_READERS + (('b2-v1', None),)},
                       {'LEGACY_ROLLBACK': ((runner.ROLLBACK, runner.ROLLBACK),)},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'b2 focused': ('production', 'rollback-reader')})},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'living parity': ('rollback-reader',)})},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, parity=('archived-baseline', 'production'))},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, unknown=('production',))},
                       {'ARCHIVED_STEP_NAMES': runner.ARCHIVED_STEP_NAMES + ('absent',)}):
            with self.subTest(change=sorted(change)), mock.patch.multiple(runner, **change):
                self.assertTrue(runner.label_problems())

    def test_living_readers_and_rollback_checks_are_predicted(self):
        predictions = json.loads(runner.PREDICTIONS.read_text())
        predicted = predictions['p0_archive']
        self.assertIn('PREDICTED', predicted['status'])
        self.assertEqual(predicted['living_readers'],
                         {target: len(runner.LAYOUT_NAMES) for target, _, _ in runner.READERS})
        cases = len(runner.LAYOUT_NAMES) + len(runner.ROLLBACK_CONTROLS) + 1
        self.assertEqual(predicted['living_rollback'],
                         {target: {main: cases for main, _ in runner.ROLLBACK_CHECKS}
                          for target, _ in runner.LEGACY_ROLLBACK})
        self.assertEqual(predicted['relabelled'],
                         {target: runner.READER_LABELS[target] for target, _, _ in runner.READERS})
        # Every history layout starts from version 2 copies, and both controls are emitted layouts.
        self.assertEqual(runner.ROLLBACK_COPY_LAYOUTS, len(runner.LAYOUT_NAMES))
        self.assertTrue(set(runner.ROLLBACK_CONTROLS) <= set(runner.LAYOUT_NAMES))
        self.assertEqual(len(runner.b1.rollback_names('rollback reader', runner.LAYOUT_NAMES,
                                                      runner.ROLLBACK_CONTROLS)), cases)
        # The renamed check of R0 is a living name.
        for old, new in predictions['r0_rollback_reader']['renamed_check'].items():
            self.assertNotIn(old, runner.FOCUSED_NAMES)
            self.assertIn(new, runner.FOCUSED_NAMES)

    def test_living_probe_keeps_the_reviewed_bytes(self):
        self.assertEqual(runner.sha(runner.PROBE.read_bytes()), runner.PROBE_SHA256)
        drifted = scratch(self) / 'BodyOriginRetirementProbe.java'
        drifted.write_bytes(runner.PROBE.read_bytes() + b'\n')
        with mock.patch.object(runner, 'PROBE', drifted):
            self.assertIn('BODY origin probe differs from the reviewed probe', runner.source_checks())
            # The archived probe sides compile the pinned object whatever the working tree holds.
            self.assertEqual(runner.archived_probe_files(runner.BASE)['tests/BodyOriginRetirementProbe.java'],
                             runner.b1.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_PROBE))

    def test_rollback_candidate_differs_only_by_the_boot_literal(self):
        # Archived: the 78456b3 candidate against the 24bfb6a candidate, cut with the pinned fragments.
        settings = synthetic_settings(runner.archived_fragments())
        boot = runner.b1.ARCHIVED_CONSTRUCTION + runner.b1.ARCHIVED_PRODUCTION + ');'
        current = settings.replace('final class Settings {\n', 'final class Settings {\n' + boot + '\n', 1)
        old = current.replace(boot, runner.b1.ARCHIVED_CONSTRUCTION + runner.b1.ARCHIVED_RETIRED + ');')
        built = {runner.ARCHIVE: current, runner.ROLLBACK: old, 'rollback_changed': [runner.b1.ARCHIVED_SETTINGS]}
        self.assertEqual(runner.archived_rollback_candidate_problems(built), [])
        self.assertTrue(runner.archived_rollback_candidate_problems(
            dict(built, rollback_changed=[runner.b1.ARCHIVED_SETTINGS, 'x'])))
        self.assertTrue(runner.archived_rollback_candidate_problems(dict(built, **{runner.ROLLBACK: current})))
        seeding = '    private void seedNativeRecoveryLPw() {\n'
        moved = old.replace(seeding, seeding + '\n', 1)
        self.assertTrue(runner.archived_rollback_candidate_problems(dict(built, **{runner.ROLLBACK: moved})))
        # The current candidate plays no part, and neither do the living boot literals and Settings path.
        self.assertEqual(runner.archived_rollback_candidate_problems(dict(built, b2='anything')), [])
        with mock.patch.multiple(runner.b1, CONSTRUCTION='x', PRODUCTION='y', RETIRED='z'), \
                mock.patch.object(runner, 'SETTINGS', 'elsewhere/Settings.java'):
            self.assertEqual(runner.archived_rollback_candidate_problems(built), [])

    def test_baselines_are_pinned_git_objects(self):
        self.assertEqual(runner.b1.REVISIONS[runner.ARCHIVE], '24bfb6ad3c5c9630faca141a93d3531851e280b8')
        # Each patch and Settings pin is the Git object and its own profile's candidate.
        for key, patch, settings in ((runner.BASE, runner.PATCH_0018_SHA256, runner.SETTINGS_0018_SHA256),
                                     (runner.ROLLBACK, runner.PATCH_7845_SHA256, runner.SETTINGS_7845_SHA256),
                                     (runner.ARCHIVE, runner.PATCH_24BF_SHA256, runner.SETTINGS_24BF_SHA256)):
            revision = runner.b1.REVISIONS[key]
            profile = json.loads(runner.b1.git_bytes(revision, runner.b1.ARCHIVED_PROFILE))
            self.assertEqual(runner.sha(runner.b1.git_bytes(revision, runner.b1.ARCHIVED_PATCH)), patch, key)
            self.assertEqual(profile['patch_sha256'], patch, key)
            self.assertEqual([row['candidate_sha256'] for row in profile['files']
                              if row['path'] == runner.b1.ARCHIVED_SETTINGS], [settings], key)
            self.assertEqual(runner.b1.manifest(key)[runner.b1.ARCHIVED_PATCH], patch, key)
        # The probe and R0 support pins are the archive's pins of their 24bfb6a objects.
        archive = runner.b1.manifest(runner.ARCHIVE)
        self.assertEqual(archive[runner.ARCHIVED_PROBE], runner.PROBE_SHA256)
        for relative, digest in runner.SUPPORT_R0_SHA256.items():
            self.assertEqual(archive[runner.b1.ARCHIVED_PLATFORM + relative], digest, relative)
        for relative, digest in runner.SUPPORT_0018.items():
            self.assertEqual(runner.b1.manifest(runner.BASE)[runner.b1.ARCHIVED_PLATFORM + relative], digest,
                             relative)
        self.assertEqual(runner.b1.REVISIONS[runner.BASE], runner.REVISION_0018)
        self.assertEqual(set(runner.BASELINE_0018), set(runner.b1.ARCHIVED_FRAMEWORK) | {'Settings'})
        patch = runner.b1.git_bytes(runner.REVISION_0018, runner.b1.ARCHIVED_PATCH)
        self.assertEqual(runner.sha(patch), runner.PATCH_0018_SHA256)
        for name, digest in runner.BASELINE_0018.items():
            path = (runner.b1.ARCHIVED_FACADE if name == 'Settings'
                    else runner.b1.ARCHIVED_FRAMEWORK_DIR + name + '.java')
            self.assertEqual(runner.sha(runner.b1.git_bytes(runner.REVISION_0018, path)), digest, name)


def historical_constants(revision, path, names, namespace=None):
    """Module level constants of a runner as its Git object at one revision states them: each named
    assignment, evaluated in file order with the given namespace and the names before it, and no
    builtins but tuple and sorted."""
    values = {}
    for node in ast.parse(runner.b1.git_bytes(revision, path).decode()).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in names):
            code = compile(ast.Expression(node.value), path, 'eval')
            scope = {'__builtins__': {'tuple': tuple, 'sorted': sorted}, **(namespace or {}), **values}
            values[node.targets[0].id] = eval(code, scope)  # noqa: S307
    return values


def pin_data(value):
    """Whether a value is pinned revision data: a revision key, a full revision, a SHA-256 digest, or
    a mapping of such data."""
    if isinstance(value, str):
        return re.fullmatch(r'[0-9a-z]{4}|[0-9a-f]{40}|[0-9a-f]{64}', value) is not None
    if isinstance(value, dict):
        return all(isinstance(key, str) and pin_data(item) for key, item in value.items())
    return False


def historical_function(path, name):
    """The source of one top level function as a runner's 24bfb6a Git object states it."""
    text = runner.b1.git_bytes(runner.b1.REVISIONS[runner.ARCHIVE], path).decode()
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    raise AssertionError('no function %s in %s' % (name, path))


def normalized_function(source, renames=None):
    """One function's syntax tree as text, without decorators and docstring and with names mapped:
    two functions that differ only in layout, comments, docstrings and the mapped names compare
    equal."""
    node = ast.parse(textwrap.dedent(source)).body[0]
    node.decorator_list = []
    if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
        node.body = node.body[1:]
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            child.id = (renames or {}).get(child.id, child.id)
        elif isinstance(child, ast.Attribute):
            child.attr = (renames or {}).get(child.attr, child.attr)
        elif isinstance(child, ast.FunctionDef):
            child.name = (renames or {}).get(child.name, child.name)
    return ast.dump(node)


def frozen_matches(test, frozen, original, renames=None, replacements=(), path=HISTORY, module=runner):
    """Assert that one frozen function of a runner, this one unless another module is given, is its
    24bfb6a original, but for the mapped names and the marked replacements applied to the original."""
    source = historical_function(path, original)
    for old, new in replacements:
        test.assertEqual(source.count(old), 1, (frozen, old))
        source = source.replace(old, new)
    mapping = {frozen: original, **(renames or {})}
    test.assertEqual(normalized_function(inspect.getsource(getattr(module, frozen)), mapping),
                     normalized_function(source), frozen)


def fake_tools(layouts, parity='relation\tlayout\tsame\nV2\tlayout\tbody\t-\trecords=\n'):
    """A stand in for the compiler and JVM, with Git itself: javac succeeds, a layout emitter writes
    the given layouts, each of version 2 copies, a parity driver writes the given outcomes, and every
    JVM prints one passing check. Their effects are the same whichever code starts them."""
    real = subprocess.run

    def run(args, **kwargs):
        if args[0] not in ('javac', 'java'):
            return real(args, **kwargs)
        if args[0] == 'java':
            index = next(index for index, arg in enumerate(args) if arg.startswith('com.android.server.pm.'))
            main, rest = args[index].rsplit('.', 1)[1], args[index + 1:]
            if main.endswith('Layouts'):
                for name in layouts:
                    (Path(rest[0]) / name).mkdir(parents=True)
                    (Path(rest[0]) / name / 'kind').write_text('copy\n')
            elif main == 'NativeHistoryParity':
                Path(rest[1]).write_text(parity)
        return subprocess.CompletedProcess(args, 0, 'PASS a\n', '')
    return run


def living_code_broken(test, module, names):
    """Patch every named living function of a module to fail the test when it runs."""
    for name in names:
        patcher = mock.patch.object(module, name, side_effect=AssertionError('living %s ran' % name))
        patcher.start()
        test.addCleanup(patcher.stop)


# The living functions of the B1 runner that the archived legs of every runner must not call.
B1_LIVING = ('build', 'execute', 'suite', 'outcome', 'with_seams', 'product_sources', 'store_sources',
             'test_sources', 'b0_suite', 'b1_suite', 'r0_forward', 'copy_layouts', 'rollback_names',
             'replace_once', 'strip_java_comments', 'tool_environment')
# And this runner's.
HISTORY_LIVING = ('settings_texts', 'b2_text_checks', 'harness_source', 'history_stubs', 'worktree_tests',
                  'b2_product', 'b2_suite', 'living_parity_files', 'run_parity', 'probe_outcome', 'probe_red',
                  'red_names', 'parse_parity', 'parity_differences', 'predicted_parity', 'cut', 'method',
                  'candidates', 'candidate_problems', 'mutant_sources')


def living_constants_changed(test, work):
    """Change every living constant and fragment of the B1 runner and this one that a later package
    may change, for the rest of the test."""
    body = work / 'changed.inc'
    body.write_text('changed\n')
    for patcher in (mock.patch.multiple(runner.b1, PRODUCTION='x', RETIRED='y', CONSTRUCTION='z', FRAMEWORK=(),
                                        PLATFORM='x/', FRAMEWORK_DIR='x/', LAYOUT_NAMES=(), ROLLBACK_CONTROLS=(),
                                        ROLLBACK_COPY_LAYOUTS=0, PREDICTIONS=work / 'absent.json', STEPS=()),
                    mock.patch.multiple(runner, TEMPLATE=body, HISTORY_STUBS=work, PROBE=body, LAYOUT_NAMES=(),
                                        ROLLBACK_COPY_LAYOUTS=0, ROLLBACK_CONTROLS=(), ROLLBACK_CHECKS=(),
                                        PREDICTIONS=work / 'absent.json', SETTINGS='x', PLATFORM='x/',
                                        FRAMEWORK_DIR='x/'),
                    mock.patch.dict(runner.BODY_INPUTS, {side: body for side in runner.BODY_INPUTS}),
                    mock.patch.dict(runner.integration.FRAGMENTS, {name: (row[0], body) for name, row
                                                                   in runner.integration.FRAGMENTS.items()})):
        patcher.start()
        test.addCleanup(patcher.stop)


def synthetic_built():
    """Archived candidate Settings texts that hold the pinned 24bfb6a fragments, one for each
    archived revision, as the archived candidates return them. Each names its revision in the text
    every harness copies, so a leg that takes another side's candidate shows."""
    fragments = runner.archived_fragments()
    return {revision: synthetic_settings(fragments, revision)
            for revision in (runner.ARCHIVE, runner.BASE, runner.ROLLBACK)}


class ArchivedHistoryTests(unittest.TestCase):
    """The archived history legs: pinned inputs only, assembled with the working tree closed, archive
    code alone, its copies of 24bfb6a code and expectations frozen at 24bfb6a."""

    def test_archived_harness_is_filled_from_pinned_inputs_only(self):
        settings = synthetic_settings(runner.archived_fragments())
        for side, body in runner.ARCHIVED_BODY_INPUTS.items():
            source = runner.archived_harness_source(settings, side)
            self.assertIsNone(re.search(r'@[A-Z_]+@', source))
            self.assertIn(runner.b1.pinned_bytes(runner.ARCHIVE, body).decode(), source)
            # The working tree's template, fragments and body inputs play no part.
            with mock.patch.object(Path, 'read_text', side_effect=AssertionError('working tree read')):
                self.assertEqual(runner.archived_harness_source(settings, side), source)
        self.assertEqual(runner.archived_text_checks(settings), [])

    def test_archived_assembly_reads_no_worktree_file(self):
        built = synthetic_built()
        legs = runner.archived_inputs(built)
        self.assertEqual(set(legs), {'probe 0018', 'probe 24bf', 'parity 0018', 'parity 24bf', 'emitter',
                                     *('reader ' + target for target, _, _ in runner.ARCHIVED_READERS),
                                     *('rollback ' + target for target, _ in runner.ARCHIVED_ROLLBACK_READERS)})
        pinned = {digest for revision in runner.b1.REVISIONS for digest in runner.b1.manifest(revision).values()}
        generated = {'tests/NativeHistoryHarness.java', 'framework/NativeIdentityStore.java',
                     'fixtures/ResilientAtomicFile.java'}
        for leg, files in sorted(legs.items()):
            for name, data in sorted(files.items()):
                with self.subTest(leg=leg, name=name):
                    if runner.sha(data) not in pinned:
                        self.assertIn(name, generated)
        # Each harness is the archived harness of its own side's candidate: 0018a1d's for its parity
        # side, 78456b3's for its rollback check, and 24bfb6a's elsewhere.
        sides = {'probe 24bf': (runner.ARCHIVE, 'b2'), 'parity 0018': (runner.BASE, runner.BASE),
                 'parity 24bf': (runner.ARCHIVE, 'b2'), 'emitter': (runner.ARCHIVE, 'b2'),
                 'rollback 24bf-v1': (runner.ARCHIVE, 'b2'), 'rollback 7845': (runner.ROLLBACK, 'b2')}
        for leg, files in sorted(legs.items()):
            with self.subTest(leg=leg):
                if leg not in sides:
                    self.assertNotIn('tests/NativeHistoryHarness.java', files)
                    continue
                revision, side = sides[leg]
                harness = files['tests/NativeHistoryHarness.java']
                self.assertEqual(harness, runner.archived_harness_source(built[revision], side).encode())
                self.assertEqual([marker for marker in built if ('// candidate %s\n' % marker).encode() in harness],
                                 [revision])
        for leg in ('probe 0018', 'probe 24bf'):
            self.assertEqual(legs[leg]['tests/BodyOriginRetirementProbe.java'],
                             runner.b1.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_PROBE))
        for leg in ('parity 0018', 'parity 24bf'):
            self.assertEqual(legs[leg]['tests/NativeHistoryParity.java'],
                             runner.b1.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_PARITY))
        # A leak in an archived assembly raises: here the loader reads the working tree instead.
        with mock.patch.object(runner.b1, 'pinned_bytes', lambda revision, path: (ROOT / path).read_bytes()):
            with self.assertRaises(runner.b1.WorktreeRead):
                runner.archived_inputs(built)
        # So do the archived checks over Git objects.
        for check in (runner.archived_support_problems, runner.archived_fragments):
            with mock.patch.object(runner.b1, 'pinned_bytes', lambda revision, path: (ROOT / path).read_bytes()):
                with self.assertRaises(runner.b1.WorktreeRead):
                    check()

    def test_archived_phases_call_no_living_code(self):
        built = synthetic_built()

        def archived_run(work):
            steps, problems = {}, []
            with mock.patch.object(runner.subprocess, 'run', fake_tools(layouts)):
                for phase in (runner.archived_probe_phase, runner.archived_parity_phase, runner.archived_readers_phase):
                    phase(work, built, steps, problems, mock.Mock())
            return json.loads(json.dumps([steps, problems], default=str).replace(str(work), 'WORK'))
        layouts = runner.ARCHIVED_LAYOUT_NAMES
        work = scratch(self)
        expected = archived_run(work / 'first')
        self.assertTrue({'probe', 'parity', 'archived readers'} <= set(expected[0]))
        self.assertTrue({'rollback 24bf-v1', 'rollback 7845', *(target for target, _, _ in runner.ARCHIVED_READERS)}
                        <= set(expected[0]['archived readers']))
        # The archived phases run without any living function or constant and record the same.
        living_code_broken(self, runner.b1, B1_LIVING)
        living_code_broken(self, runner, HISTORY_LIVING)
        living_constants_changed(self, work)
        self.assertEqual(archived_run(work / 'second'), expected)

    def test_archived_legs_ignore_every_living_edit(self):
        built = synthetic_built()
        before = runner.archived_inputs(built)
        work = scratch(self)
        template, body, probe = work / 'template', work / 'body', work / 'probe'
        template.write_text('@BODY_INPUTS@\n')
        body.write_text('changed\n')
        probe.write_bytes(b'changed')
        # A later package may change the living cutting, fragments, harness inputs, R0 literal and
        # predictions: the archived inputs and expectations stay the 24bfb6a ones.
        with mock.patch.object(runner, 'settings_texts', side_effect=AssertionError('living cutting')), \
                mock.patch.object(runner, 'harness_source', side_effect=AssertionError('living harness')), \
                mock.patch.object(runner, 'TEMPLATE', template), \
                mock.patch.dict(runner.BODY_INPUTS, {'b2': body, runner.BASE: body}), \
                mock.patch.object(runner, 'PROBE', probe), \
                mock.patch.object(runner, 'PREDICTIONS', work / 'absent.json'), \
                mock.patch.dict(runner.integration.FRAGMENTS, {name: (row[0], body) for name, row
                                                               in runner.integration.FRAGMENTS.items()}), \
                mock.patch.multiple(runner.b1, CONSTRUCTION='x', PRODUCTION='y', RETIRED='z',
                                    PREDICTIONS=work / 'absent.json'):
            self.assertEqual(runner.archived_inputs(built), before)
            self.assertEqual(runner.archive_problems(), [])
            self.assertEqual(runner.archived_support_problems(), [])

    def test_pinned_copies_are_read_before_the_tree_closes(self):
        rows = runner.archived_profile_rows()
        root = scratch(self).resolve()
        pinned = root / 'pinned'
        for row in rows:
            copy = pinned / row['path']
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(b'not the upstream copy\n')
        outside = scratch(self)
        # Here the closed tree is this scratch root, which holds the copies as a repository may.
        with mock.patch.object(runner.b1, 'CLOSED_ROOT', root):
            with runner.b1.worktree_closed():
                with self.assertRaises(runner.b1.WorktreeRead):
                    (pinned / rows[0]['path']).read_bytes()
            # The archived candidates read every copy before the tree closes, against the pinned
            # profile's upstream hash: a wrong copy is refused as wrong, not as a working tree read.
            with self.assertRaisesRegex(ValueError, 'wrong pinned input: ' + re.escape(rows[0]['path'])):
                runner.archived_candidates(pinned, outside / 'candidates')
            # Their patches apply in scratch outside the repository only.
            with self.assertRaisesRegex(ValueError, 'scratch outside the repository'):
                runner.archived_candidates(pinned, root / 'scratch')
        self.assertEqual(list(outside.iterdir()), [])
        with self.assertRaisesRegex(ValueError, 'pinned framework copy missing'):
            runner.archived_candidates(scratch(self), outside / 'candidates')
        with self.assertRaisesRegex(ValueError, 'scratch outside the repository'):
            runner.archived_candidates(pinned, ROOT / 'scratch')

    def test_frozen_expectations_are_the_24bfb6a_constants(self):
        revision = runner.b1.REVISIONS[runner.ARCHIVE]
        history = historical_constants(revision, HISTORY, (
            'STEPS', 'LAYOUT_NAMES', 'ROLLBACK_COPY_LAYOUTS', 'ROLLBACK_CONTROLS', 'TWINNED', 'PROBE_SHA256',
            'SUPPORT_0018', 'SUPPORT_R0', 'SUPPORT_R0_SHA256', 'PATCH_7845_SHA256', 'SETTINGS_7845_SHA256',
            'REVISION_0018', 'BASELINE_0018', 'PATCH_0018_SHA256', 'SETTINGS_0018_SHA256', 'APPLY_START',
            'BINDING_START', 'ROLLBACK_CHECKS', 'REMEMBERED_FIELD'), {'re': re})
        self.assertEqual(runner.b1.ARCHIVED_STEPS, history['STEPS'])
        self.assertEqual(runner.ARCHIVED_LAYOUT_NAMES, history['LAYOUT_NAMES'])
        self.assertEqual((runner.ARCHIVED_COPY_LAYOUTS, runner.ARCHIVED_ROLLBACK_CONTROLS),
                         (history['ROLLBACK_COPY_LAYOUTS'], history['ROLLBACK_CONTROLS']))
        self.assertEqual((runner.PROBE_SHA256, runner.SUPPORT_R0_SHA256),
                         (history['PROBE_SHA256'], history['SUPPORT_R0_SHA256']))
        self.assertEqual((runner.SUPPORT_0018, runner.ARCHIVED_SUPPORT_R0),
                         (history['SUPPORT_0018'], history['SUPPORT_R0']))
        self.assertEqual((runner.PATCH_7845_SHA256, runner.SETTINGS_7845_SHA256),
                         (history['PATCH_7845_SHA256'], history['SETTINGS_7845_SHA256']))
        self.assertEqual((runner.REVISION_0018, runner.BASELINE_0018, runner.PATCH_0018_SHA256,
                          runner.SETTINGS_0018_SHA256),
                         (history['REVISION_0018'], history['BASELINE_0018'], history['PATCH_0018_SHA256'],
                          history['SETTINGS_0018_SHA256']))
        self.assertEqual((runner.ARCHIVED_APPLY_START, runner.ARCHIVED_BINDING_START,
                          runner.ARCHIVED_ROLLBACK_CHECKS),
                         (history['APPLY_START'], history['BINDING_START'], history['ROLLBACK_CHECKS']))
        self.assertEqual(runner.ARCHIVED_REMEMBERED_FIELD.pattern, history['REMEMBERED_FIELD'].pattern)
        # The pinned 24bfb6a predictions hold the twinned layouts.
        pinned = runner.b1.archived_predictions('history')
        self.assertEqual(tuple(pinned['parity_twinned_layouts']), history['TWINNED'])
        # The living P0 record repeats the counts the archived expectations hold.
        predicted = json.loads(runner.PREDICTIONS.read_text())['p0_archive']
        self.assertIn('PREDICTED', predicted['status'])
        self.assertEqual(predicted['revision'], revision)
        self.assertEqual(predicted['archived_readers'],
                         {target: len(runner.ARCHIVED_LAYOUT_NAMES) for target, _, _ in runner.ARCHIVED_READERS})
        cases = len(runner.ARCHIVED_LAYOUT_NAMES) + len(runner.ARCHIVED_ROLLBACK_CONTROLS) + 1
        self.assertEqual(predicted['archived_rollback'],
                         {target: {main: cases for main, _ in runner.ARCHIVED_ROLLBACK_CHECKS}
                          for target, _ in runner.ARCHIVED_ROLLBACK_READERS})
        self.assertEqual((predicted['archived_layouts'], predicted['archived_copy_layouts'],
                          tuple(predicted['archived_rollback_controls'])),
                         (len(runner.ARCHIVED_LAYOUT_NAMES), runner.ARCHIVED_COPY_LAYOUTS,
                          runner.ARCHIVED_ROLLBACK_CONTROLS))
        self.assertEqual(predicted['parity'],
                         {'mismatches': 0, 'twinned_layouts': len(pinned['parity_twinned_layouts'])})
        self.assertEqual(predicted['candidates']['changed_24bf_against_0018'], [runner.b1.ARCHIVED_SETTINGS])
        self.assertEqual(predicted['candidates']['rollback_changed_7845_against_24bf'],
                         [runner.b1.ARCHIVED_SETTINGS])
        self.assertEqual(runner.archive_problems(), [])
        # A frozen list or pin that the pinned predictions and manifest no longer state is refused.
        expectations = ['archived history expectations differ from the pinned predictions']
        for change in ({'ARCHIVED_LAYOUT_NAMES': runner.ARCHIVED_LAYOUT_NAMES[1:]},
                       {'ARCHIVED_COPY_LAYOUTS': 44}, {'ARCHIVED_ROLLBACK_CONTROLS': ('history-rebound',)},
                       {'ARCHIVED_HARNESS_SHA256': dict(runner.ARCHIVED_HARNESS_SHA256, b2=None)}):
            with self.subTest(change=sorted(change)), mock.patch.multiple(runner, **change):
                self.assertEqual(runner.archive_problems(), expectations)
        with mock.patch.object(runner, 'PROBE_SHA256', '0' * 64):
            self.assertEqual(runner.archive_problems(),
                             ['archived pin differs from the manifest: ' + runner.ARCHIVED_PROBE])

    def test_frozen_code_is_the_24bfb6a_code(self):
        fragments = '{name: path.read_text() for name, (_, path) in integration.FRAGMENTS.items()}'
        cutting = {'archived_method': 'method', 'archived_cut': 'cut', 'ARCHIVED_APPLY_START': 'APPLY_START',
                   'ARCHIVED_BINDING_START': 'BINDING_START', 'ARCHIVED_REMEMBERED_FIELD': 'REMEMBERED_FIELD'}
        for frozen, original in (('archived_cut', 'cut'), ('archived_method', 'method'),
                                 ('archived_parse_parity', 'parse_parity'),
                                 ('archived_probe_outcome', 'probe_outcome'), ('archived_red_names', 'red_names')):
            frozen_matches(self, frozen, original)
        frozen_matches(self, 'archived_settings_texts', 'settings_texts', cutting,
                       ((fragments, 'archived_fragments()'),))
        frozen_matches(self, 'archived_text_checks', 'b2_text_checks', {'archived_settings_texts': 'settings_texts'},
                       ((fragments, 'archived_fragments()'),))
        frozen_matches(self, 'archived_harness_source', 'harness_source',
                       {'archived_settings_texts': 'settings_texts'}, (
                           ('BODY_INPUTS[side].read_text()',
                            'b1.pinned_bytes(ARCHIVE, ARCHIVED_BODY_INPUTS[side]).decode()'),
                           ('TEMPLATE.read_text()', 'b1.pinned_bytes(ARCHIVE, ARCHIVED_TEMPLATE).decode()')))
        frozen_matches(self, 'archived_compare_parity', 'compare_parity', {'archived_parse_parity': 'parse_parity'})
        frozen_matches(self, 'archived_normalized', 'normalized',
                       {'archived_strip_java_comments': 'strip_java_comments'})
        frozen_matches(self, 'archived_revision_outputs', 'revision_outputs', replacements=(
            ('revision, digest, original, scratch', 'revision, original, scratch'),
            ("b1.git_bytes(b1.REVISIONS[revision] if revision in b1.REVISIONS else revision, PATCH_PATH)\n"
             "    if sha(patch) != digest:\n        raise ValueError('%s patch drift' % revision)\n",
             'b1.pinned_bytes(revision, b1.ARCHIVED_PATCH)\n')))
        frozen_matches(self, 'archived_rollback_candidate_problems', 'rollback_candidate_problems', {
            'ARCHIVED_CONSTRUCTION': 'CONSTRUCTION', 'ARCHIVED_RETIRED': 'RETIRED',
            'ARCHIVED_PRODUCTION': 'PRODUCTION', 'archived_settings_texts': 'settings_texts'}, (
            ("built['b2']", 'built[ARCHIVE]'), ('[SETTINGS]', '[b1.ARCHIVED_SETTINGS]'),
            ("'78456b3 outputs differ beyond", "'78456b3 outputs differ from 24bfb6a beyond"),
            ('the current Settings', 'the 24bfb6a Settings'), ('and current harness', 'and 24bfb6a harness')))
        # The parity run is the second half of the 24bfb6a parity side, whose sources the archived
        # assemblies now give it.
        assembly = ("def parity(work, settings, side):\n"
                    "    if side == BASE:\n"
                    "        files = {**b1.product_sources(BASE), **support_0018(), **history_stubs()}\n"
                    "    else:\n"
                    "        files = {**b2_product(settings), **worktree_tests(['NativeHeaderTestSupport',"
                    " 'NativeBindingTestSupport'])}\n"
                    "    files['tests/NativeHistoryHarness.java'] = harness_source(settings, side).encode()\n"
                    "    files['tests/NativeHistoryParity.java'] = (ROOT / PLATFORM / 'NativeHistoryParity.java')"
                    ".read_bytes()\n")
        frozen_matches(self, 'archived_run_parity', 'parity',
                       {'archived_build': 'build', 'archived_execute': 'execute'},
                       ((assembly, 'def parity(work, files):\n'),))
        # A changed copy no longer matches.
        with self.assertRaises(AssertionError):
            frozen_matches(self, 'archived_red_names', 'probe_outcome')

    def test_archive_uses_no_living_name(self):
        self.assertEqual(runner.boundary_problems(), [])
        text = Path(runner.__file__).read_text()
        foreign = {'b1': runner.b1.archive_names(Path(runner.b1.__file__).read_text(), runner.b1.ARCHIVE_SHARED),
                   'integration': None}
        for name, old, new, problem in (
                ('living constant', 'source = b1.pinned_bytes(ARCHIVE, ARCHIVED_TEMPLATE).decode()',
                 'source = TEMPLATE.read_text()', 'archive function archived_harness_source uses living TEMPLATE'),
                ('living function', 'relations, old = archived_parse_parity(baseline_text)',
                 'relations, old = parse_parity(baseline_text)',
                 'archive function archived_compare_parity uses living parse_parity'),
                ('living B1 function', "    built = b1.archived_build(work, files)\n    record = {'build': built}",
                 "    built = b1.build(work, files)\n    record = {'build': built}",
                 'archive function archived_run_parity uses b1.build'),
                ('living module', 'for name, path in b1.ARCHIVED_FRAGMENTS.items()}',
                 'for name, (_, path) in integration.FRAGMENTS.items()}',
                 'archive function archived_fragments uses integration.FRAGMENTS'),
                # Module level archive data, built from living names, also of a foreign archive.
                ('archive data', "ARCHIVED_TEMPLATE = b1.ARCHIVED_PLATFORM + 'NativeHistoryHarness.java.in'",
                 "ARCHIVED_TEMPLATE = b1.PLATFORM + 'NativeHistoryHarness.java.in'",
                 'archive data ARCHIVED_TEMPLATE uses b1.PLATFORM'),
                ('foreign archive data', 'b1.BASELINE_INPUTS_SHA256[ROLLBACK] = {b1.ARCHIVED_PATCH: PATCH_7845_SHA256}',
                 'b1.BASELINE_INPUTS_SHA256[ROLLBACK] = {PATCH_PATH: PATCH_7845_SHA256}',
                 'archive data b1.BASELINE_INPUTS_SHA256[ROLLBACK] uses living PATCH_PATH')):
            with self.subTest(name=name):
                self.assertEqual(text.count(old), 1, name)
                mutated = text.replace(old, new, 1)
                self.assertEqual(runner.b1.archive_boundary(mutated, runner.ARCHIVE_SHARED, foreign), [problem])

    def test_archive_shares_only_its_pins(self):
        # Every name the archive uses without the archived prefix is pinned revision data, the hash or
        # the archive's own check; nothing that looks living is archive code or data.
        for name in sorted(set(runner.ARCHIVE_SHARED) - {'sha', 'archive_problems'}):
            self.assertTrue(pin_data(getattr(runner, name)), name)
        for name in ('ARCHIVED_ROLLBACK_READERS', 'ARCHIVED_SUPPORT_R0', 'ARCHIVED_PROBE'):
            self.assertFalse(pin_data(getattr(runner, name)), name)


if PINNED:
    class PinnedArchivedHistoryTests(unittest.TestCase):
        """The archived candidates and harnesses over the real pinned canonical copies. A test case
        only when ANDRIX_PINNED_FRAMEWORK names them, as the lab history runner's pure suites always
        do; elsewhere the runner's own --pinned-framework source checks run the same checks."""

        def test_archived_candidates_harnesses_and_assembly(self):
            built = runner.candidates(Path(PINNED), scratch(self))
            self.assertEqual(runner.candidate_problems(built), [])
            self.assertEqual((built['changed'], built['rollback_changed']),
                             ([runner.b1.ARCHIVED_SETTINGS], [runner.b1.ARCHIVED_SETTINGS]))
            self.assertEqual(runner.archived_harness_problems(built), [])
            legs = runner.archived_inputs(built)
            for leg, side in (('parity 0018', runner.BASE), ('emitter', 'b2'), ('rollback 7845', 'b2')):
                self.assertEqual(runner.sha(legs[leg]['tests/NativeHistoryHarness.java']),
                                 runner.ARCHIVED_HARNESS_SHA256[side], leg)

        def test_pinned_copies_inside_the_repository_build_the_same_candidates(self):
            # Here the closed tree is a scratch root that holds the real copies, as a repository may.
            root = scratch(self).resolve()
            for row in runner.archived_profile_rows():
                copy = root / 'pinned' / row['path']
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(PINNED) / row['path'], copy)
            with mock.patch.object(runner.b1, 'CLOSED_ROOT', root):
                inside = runner.archived_candidates(root / 'pinned', scratch(self) / 'candidates')
            self.assertEqual(inside, runner.archived_candidates(Path(PINNED), scratch(self) / 'candidates'))
            self.assertEqual(runner.archived_candidate_problems(inside), [])


class RunnerRefusalAndEvidenceTests(unittest.TestCase):
    def test_presence_tail_comes_from_the_actual_nested_sources(self):
        tail = runner.presence_tail()
        self.assertEqual(tail, '/tmpXXXXXXXX/presence-V1/c999/store/slots/10123/record.bin-seed')
        drifted = scratch(self) / 'NativeIdentityPresenceTest.java'
        drifted.write_text(runner.PRESENCE_TEST.read_text().replace('length() >= 100', 'length() >= 108'))
        with mock.patch.object(runner, 'PRESENCE_TEST', drifted):
            with self.assertRaises(ValueError):
                runner.presence_tail()
            self.assertIn('budget unknown', runner.work_path_problem(Path('/srv/b2w')))

    def test_work_path_budget_counts_characters_and_utf8_bytes(self):
        self.assertIsNone(runner.work_path_problem(Path('/srv/b2w')))
        self.assertIsNone(runner.work_path_problem(Path('/' + 'a' * 31)))
        self.assertIn('at most 32 ASCII characters', runner.work_path_problem(Path('/' + 'a' * 32)))
        # Twenty two byte characters: 88 characters but 108 bytes for the kernel.
        self.assertIsNone(runner.work_path_problem(Path('/' + 'e' * 20)))
        self.assertIn('108 bytes', runner.work_path_problem(Path('/' + '\u00e9' * 20)))

    def test_long_work_path_is_not_run_before_any_effect(self):
        base = scratch(self)
        work, evidence = base / ('w' * 40), base / 'evidence.json'
        started = mock.Mock(side_effect=AssertionError('started'))
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner.b1, 'resource_guard', started), \
                mock.patch.object(runner.shutil, 'which', started), \
                mock.patch.object(runner.subprocess, 'run', started), \
                mock.patch.object(runner.b1, 'build', started), \
                mock.patch.object(runner, 'qualify', started), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        report = json.loads(output.getvalue())
        self.assertEqual((code, report['status']), (2, 'NOT_RUN'))
        self.assertIn('work path too long', report['reason'])
        self.assertEqual(list(base.iterdir()), [])
        started.assert_not_called()

    def test_short_work_path_is_accepted_and_the_next_guard_decides(self):
        base = scratch(self)
        work = base / 'w'
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None) as budget, \
                mock.patch.object(runner.b1, 'resource_guard', return_value='required bounds absent'), \
                mock.patch.object(runner, 'qualify', side_effect=AssertionError('started')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(base / 'evidence.json'), '--work', str(work),
                                '--pinned-framework', str(base)])
        self.assertEqual((code, json.loads(output.getvalue())['reason']), (2, 'required bounds absent'))
        budget.assert_called_once_with(work.resolve())
        self.assertEqual(list(base.iterdir()), [])

    def test_timeout_after_a_recorded_step_keeps_the_record_and_its_streams(self):
        base = scratch(self)
        work, evidence = base / 'w', base / 'evidence.json'
        seen = {}

        def interrupted(directory, pinned, progress):
            progress.begin('candidates')
            progress.report['steps']['candidates'] = {'changed': [runner.SETTINGS]}
            progress.done('candidates')
            progress.begin('b2 focused')
            seen['checkpoint'] = json.loads((work / 'progress.json').read_text())
            raise subprocess.TimeoutExpired(['java', 'NativeCreationHistoryTest'], 900,
                                            output=b'PASS a\n\xff', stderr=b'stuck\n')
        previous = tempfile.tempdir
        self.addCleanup(setattr, tempfile, 'tempdir', previous)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'qualify', side_effect=interrupted), \
                mock.patch.object(runner, 'regressions', side_effect=AssertionError('retried')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        self.assertEqual(code, 1)
        # The durable checkpoint before the failure: RUNNING, only the finished phase.
        checkpoint = seen['checkpoint']
        self.assertEqual((checkpoint['status'], checkpoint['completed_phases'], checkpoint['phase']),
                         ('RUNNING', ['candidates'], 'b2 focused'))
        self.assertEqual(checkpoint['steps'], {'candidates': {'changed': [runner.SETTINGS]}})
        report = json.loads(evidence.read_text())
        self.assertEqual(report, json.loads((work / 'progress.json').read_text()))
        self.assertEqual(report['status'], 'NOT_COMPLETE')
        self.assertEqual(report['steps'], {'candidates': {'changed': [runner.SETTINGS]}})
        self.assertEqual(report['completed_phases'], ['candidates'])
        self.assertEqual(report['phase'], 'b2 focused')
        self.assertEqual(report['not_completed_phases'], list(runner.PHASES[1:]))
        self.assertEqual(report['exception'], {
            'type': 'TimeoutExpired', 'message': str(subprocess.TimeoutExpired(
                ['java', 'NativeCreationHistoryTest'], 900)),
            'command': ['java', 'NativeCreationHistoryTest'], 'timeout': 900,
            'stdout': 'PASS a\n\ufffd', 'stderr': 'stuck\n'})
        self.assertIn('qualification did not complete', report['problems'])
        self.assertEqual(json.loads(output.getvalue())['status'], 'NOT_COMPLETE')

    def test_progress_checkpoints_are_never_pass_until_the_end(self):
        base = scratch(self)
        report = {'problems': []}
        progress = runner.Progress(report, base / 'progress.json')
        self.assertEqual(json.loads((base / 'progress.json').read_text())['status'], 'RUNNING')
        progress.begin('candidates')
        with self.assertRaises(ValueError):
            progress.done('parity')
        progress.done('candidates')
        written = json.loads((base / 'progress.json').read_text())
        self.assertEqual((written['status'], written['completed_phases'], written['phase']),
                         ('RUNNING', ['candidates'], None))
        self.assertEqual(sorted(path.name for path in base.iterdir()), ['progress.json'])

    def test_mutant_results_count_only_complete_runs_with_their_exit_status(self):
        names = ('a', 'b')
        self.assertEqual(runner.red_names(suite_result('PASS a\nFAIL b: x\n', 1), names), {'b'})
        self.assertEqual(runner.red_names(suite_result('PASS a\nPASS b\n', 0), names), set())
        for stdout, returncode in (('FAIL a: x\n', 1),                    # stopped before b
                                   ('PASS a\nFAIL b: x\n', 137),          # killed after both
                                   ('PASS a\nFAIL b: x\n', 0),            # failures, exit 0
                                   ('FAIL a: x\nFAIL a: y\nPASS b\n', 1),  # a repeated
                                   ('PASS a\nPASS b\nPASS c\n', 0),       # an unknown case
                                   ('PASS a\nPASS b\n', 1)):              # exit 1, no failure
            self.assertIsNone(runner.red_names(suite_result(stdout, returncode), names), stdout)
        self.assertIsNone(runner.red_names({'error': 'compile failure', 'build': {}}, names))
        red = {'returncode': 1, 'stderr': 'Exception in thread "main" java.lang.AssertionError\n'}
        self.assertTrue(runner.probe_red(red))
        for other in (dict(red, returncode=137), dict(red, stderr='java.lang.IllegalStateException'),
                      {'error': 'compile failure'}):
            self.assertFalse(runner.probe_red(other))

    def test_exception_record_decodes_timeout_streams(self):
        record = runner.exception_record(subprocess.TimeoutExpired('java', 5, output=None, stderr=b'\xfe'))
        self.assertEqual((record['command'], record['stdout'], record['stderr']), ('java', '', '\ufffd'))
        self.assertEqual(runner.exception_record(ValueError('drift')), {'type': 'ValueError', 'message': 'drift'})


if __name__ == '__main__':
    unittest.main()
