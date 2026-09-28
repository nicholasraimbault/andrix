# SPDX-License-Identifier: Apache-2.0
"""B2 historical identities and restored creation rebinding: pure source guards, harness
generation, the 0018a1d parity rules and the runner's refusals and evidence retention. The guarded
JVM matrix is only in the runner, which is NOT RUN without the required resource bounds and a
short enough work path. These tests start no compiler or JVM. Not Android runtime proof."""
from pathlib import Path
import contextlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_history as runner  # noqa: E402


def synthetic_settings():
    """A minimal candidate that holds every B2 fragment and harness text at its adapted position."""
    fragments = {name: path.read_text() for name, (_, path) in runner.integration.FRAGMENTS.items()}
    return ('final class Settings {\n'
            '    private final java.util.Map<Long, NativeIdentityStore.History> mNativeRememberedBindings =\n'
            '            new java.util.HashMap<>();\n\n'
            '    void applyNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'
            + fragments['restore-history'] + fragments['restore-capacity']
            + '        mNativePrincipalPins = restored;\n'
            '        observeNativeIdentityStoreLPw(loaded);\n'
            '        seedNativeRecoveryLPw();\n    }\n\n'
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
            '    void refreshNativePrincipalAppIdsLPw() {\n'
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
        self.assertEqual(len(runner.TWINNED), 7)

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
        problems, differing = runner.compare_parity(old, good)
        self.assertEqual((problems, differing), ([], ['reservation']))
        # A body only line never takes the published twin.
        bad_body = good.replace(parity_line('V2', 'reservation', 'body', '-', 'records='),
                                parity_line('V2', 'reservation', 'body', '-', 'records=1/R'))
        self.assertTrue(runner.compare_parity(old, bad_body)[0])
        # A version 1 run always equals 0018a1d on the same bytes.
        bad_v1 = good.replace(parity_line('V1', 'reservation', 'restore', '-', 'records= counter=none'),
                              parity_line('V1', 'reservation', 'restore', '-', 'records=1/R counter=none'))
        self.assertTrue(runner.compare_parity(old, bad_v1)[0])
        # Unchanged twinned output is compared with the twin and fails.
        problems, differing = runner.compare_parity(old, old)
        self.assertTrue(problems)
        self.assertEqual(differing, [])
        thrown = good.replace('records=1/R counter=1\n', 'threw=IllegalArgumentException\n', 1)
        self.assertTrue(any('threw' in problem for problem in runner.compare_parity(old, thrown)[0]))
        with self.assertRaises(ValueError):
            runner.parse_parity(old + parity_line('V1', 'reservation', 'body', '-', 'records=') + '\n')

    def test_fresh_outside_refuses_repository_and_existing_paths(self):
        with self.assertRaises(ValueError):
            runner.fresh_outside(runner.ROOT / 'scratch-output', 'work directory')
        with self.assertRaises(ValueError):
            runner.fresh_outside(runner.ROOT, 'work directory')

    def test_baselines_are_pinned_git_objects(self):
        self.assertEqual(runner.b1.REVISIONS[runner.BASE], runner.REVISION_0018)
        self.assertEqual(set(runner.BASELINE_0018), set(runner.b1.FRAMEWORK) | {'Settings'})
        patch = runner.b1.git_bytes(runner.REVISION_0018, runner.PATCH_PATH)
        self.assertEqual(runner.sha(patch), runner.PATCH_0018_SHA256)
        for name, digest in runner.BASELINE_0018.items():
            path = ('owner/tests/platform/native_principal_stubs/com/android/server/pm/Settings.java'
                    if name == 'Settings' else runner.FRAMEWORK_DIR + name + '.java')
            self.assertEqual(runner.sha(runner.b1.git_bytes(runner.REVISION_0018, path)), digest, name)


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
