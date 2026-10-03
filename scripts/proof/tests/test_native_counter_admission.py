# SPDX-License-Identifier: Apache-2.0
"""Native counter admission: pure source guards, the exact correction surface, the comparison
rules across 0018a1d, 89491b9 and the corrected sources, probe classification and the runner's
refusals and evidence retention. The guarded JVM matrix is only in the runner, which is NOT RUN
without the required resource bounds and a short enough work path. These tests start no compiler
or JVM. Not Android runtime proof."""
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
import native_counter_admission as runner  # noqa: E402


def scratch(test):
    """A fresh directory below the caller's TMPDIR, removed after the test."""
    directory = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, directory)
    return directory


def balanced(text):
    """Whether braces and parentheses of Java code, comments and literals aside, nest. A sanity
    check of generated mutant text only, never a compilation."""
    code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', runner.b1.strip_java_comments(text))
    depth = {'{': 0, '(': 0}
    for c in code:
        if c in '{(':
            depth[c] += 1
        elif c in '})':
            depth['{' if c == '}' else '('] -= 1
            if min(depth.values()) < 0:
                return False
    return depth == {'{': 0, '(': 0}


def observed(label, fmt, facts, ready, restorable):
    return 'OBSERVE\t%s\t%s\t%s\tready=%s\trestorable=%s' % (
        label, fmt, facts, str(ready).lower(), str(restorable).lower())


class CounterAdmissionSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_mutants_anchor_once_and_predictions_are_consistent(self):
        sources = runner.mutant_sources()
        self.assertEqual(set(sources), set(runner.MUTANTS))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        names = set(runner.FOCUSED_NAMES)
        self.assertEqual((len(runner.FOCUSED_NAMES), len(names), predictions['focused_cases']), (35, 35, 35))
        self.assertEqual(len(runner.MUTANTS), 15)
        self.assertEqual(set(predictions['mutants_caught_at_least']), set(runner.MUTANTS))
        for name, expected in predictions['mutants_caught_at_least'].items():
            self.assertTrue(expected and set(expected) <= names, name)
        failures = predictions['baselines']['0018']['focused_failures']
        self.assertEqual(failures, predictions['baselines']['8949']['focused_failures'])
        self.assertEqual(len(failures), 25)
        self.assertTrue(set(failures) <= names)
        # Dropping the rule leaves the 89491b9 store rule, so it fails what 89491b9 fails.
        self.assertEqual(set(predictions['mutants_caught_at_least']['rule-dropped']), set(failures))
        self.assertEqual(predictions['fix']['focused_failures'], [])
        for name, (path, text) in sources.items():
            self.assertNotEqual(text, (ROOT / path).read_text(), name)
            self.assertTrue(balanced(text), name)
        self.assertTrue(balanced((ROOT / runner.STORE).read_text()))

    def test_every_case_and_observation_label_is_in_the_suite_source(self):
        source = (ROOT / runner.PLATFORM / (runner.TEST + '.java')).read_text()
        self.assertTrue(balanced(source))
        for name in runner.FOCUSED_NAMES:
            self.assertEqual(source.count('"%s"' % name), 1, name)
        predictions = json.loads(runner.PREDICTIONS.read_text())
        blocked, unchanged = set(predictions['blocked_observations']), set(predictions['unchanged_observations'])
        self.assertFalse(blocked & unchanged)
        labels = set(re.findall(r'"([a-z0-9]+(?:-[a-z0-9]+)+)"', source)) - {'counter-admission'}
        self.assertEqual(labels, blocked | unchanged)
        # The runner's own probe and helper lists match the predictions.
        self.assertEqual(set(predictions['probes']), set(runner.PROBES))

    def test_store_differs_from_89491_only_by_the_rule(self):
        base = runner.b1.git_bytes(runner.REVISION_8949, runner.STORE).decode()
        current = (ROOT / runner.STORE).read_text()
        self.assertEqual(runner.store_problems(current, base), [])
        # Comments are free; code is not.
        self.assertEqual(runner.store_problems(current.replace(
            '    // Whether this decoded slot copy names', '    // Whether the decoded slot copy names'), base), [])
        for old, new in (('if (user.id > counter) return true;', 'if (user.id >= counter) return true;'),
                         ('blocked = header.status != Status.VALID;', 'blocked = header.status == Status.MISSING;'),
                         ('occupied.add(appId);', 'occupied.add(appId + 0);')):
            self.assertTrue(current.count(old) >= 1, old)
            self.assertTrue(runner.store_problems(current.replace(old, new, 1), base), old)
        self.assertTrue(runner.store_problems(base, base))

    def test_the_later_r0_change_is_allowed_exactly(self):
        old_profile = json.loads(runner.b1.git_bytes(runner.REVISION_8949, runner.PROFILE_PATH))
        profile = json.loads((ROOT / runner.PROFILE_PATH).read_text())
        self.assertEqual(runner.r0_problems(old_profile, profile), [])
        settings = [row['path'] for row in profile['files']].index(runner.SETTINGS)
        other = json.loads(json.dumps(profile))
        other['files'][0]['candidate_sha256'] = '0' * 64
        self.assertTrue(runner.r0_problems(old_profile, other))
        upstream = json.loads(json.dumps(profile))
        upstream['files'][settings]['upstream_sha256'] = '0' * 64
        self.assertTrue(runner.r0_problems(old_profile, upstream))
        stale = json.loads(json.dumps(profile))
        stale['patch_sha256'] = old_profile['patch_sha256']
        self.assertTrue(runner.r0_problems(old_profile, stale))
        facade = (ROOT / runner.FACADE).read_bytes()
        self.assertEqual(runner.sha(facade), runner.FACADE_R0_SHA256)
        real = Path.read_bytes

        def facade_problems(changed):
            with mock.patch.object(Path, 'read_bytes', autospec=True,
                                   side_effect=lambda path, *a, **k: changed if path == ROOT / runner.FACADE
                                   else real(path, *a, **k)):
                return runner.r0_problems(old_profile, profile)
        code = 'Settings facade differs from 89491b9 beyond the R0 default'
        pinned = 'Settings facade differs from its reviewed R0 bytes'
        for changed in (facade.replace(b'        storeHolds.remove(record.appId);\n', b''),
                        facade.replace(b'initialize, NativeIdentityStore.Format.V2); }',
                                       b'initialize, NativeIdentityStore.Format.V1); }')):
            self.assertNotEqual(changed, facade)
            self.assertEqual(facade_problems(changed), [code, pinned])
        # A comment change keeps the code comparison and trips only the exact byte pin.
        commented = facade.replace(b'// Host PMS facade', b'// The host PMS facade')
        self.assertNotEqual(commented, facade)
        self.assertEqual(facade_problems(commented), [pinned])

    def test_b1_suite_changed_only_its_readiness_check(self):
        base = runner.b1.git_bytes(runner.REVISION_8949, runner.B1_TEST).decode()
        current = (ROOT / runner.B1_TEST).read_text()
        self.assertEqual(runner.b1_test_problems(current, base), [])
        weakened = current.replace('unchanged(problems, root, "publication",',
                                   'check(problems, true, "publication",', 1)
        self.assertNotEqual(weakened, current)
        self.assertTrue(runner.b1_test_problems(weakened, base))
        self.assertTrue(runner.b1_test_problems(base, base))

    def test_baselines_and_probes_are_pinned(self):
        self.assertEqual(runner.b1.REVISIONS[runner.BASE_8949], runner.REVISION_8949)
        self.assertEqual(set(runner.BASELINE_8949), set(runner.b1.FRAMEWORK) | {'Settings'})
        for name, digest in runner.BASELINE_8949.items():
            path = runner.FACADE if name == 'Settings' else runner.FRAMEWORK_DIR + name + '.java'
            self.assertEqual(runner.sha(runner.b1.git_bytes(runner.REVISION_8949, path)), digest, name)
        for name, digest in runner.PROBES.items():
            self.assertEqual(runner.sha((ROOT / runner.PLATFORM / (name + '.java')).read_bytes()), digest)
        with self.assertRaises(ValueError):
            runner.suite_files(runner.BASE_0018, '', [], {runner.STORE: 'mutant'})


class ComparisonTests(unittest.TestCase):
    def sides(self, fix_ready=False, baseline_ready=True, facts=('f', 'f', 'f')):
        lines = {}
        for side, fact, ready in zip(runner.SIDES, facts, (baseline_ready, baseline_ready, fix_ready)):
            lines[side] = '\n'.join((observed('blocked', 'V1', fact, ready, ready),
                                     observed('same', 'V1', 'g', True, True), 'PASS a'))
        return {side: runner.observations(text) for side, text in lines.items()}

    def test_blocked_layouts_differ_only_in_readiness(self):
        self.assertEqual(runner.compare_observations(self.sides(), {'blocked'}), [])
        # The corrected sources were still ready.
        self.assertTrue(runner.compare_observations(self.sides(fix_ready=True), {'blocked'}))
        # A baseline was not ready, so the layout proves nothing about the correction.
        self.assertTrue(runner.compare_observations(self.sides(baseline_ready=False), {'blocked'}))
        # An unpredicted readiness difference.
        self.assertTrue(runner.compare_observations(self.sides(), set()))
        # Any other fact differs.
        self.assertTrue(runner.compare_observations(self.sides(facts=('f', 'f', 'x')), {'blocked'}))
        # A predicted layout that no side observed.
        self.assertTrue(runner.compare_observations(self.sides(), {'blocked', 'absent'}))

    def test_missing_or_malformed_observations(self):
        sides = self.sides()
        del sides[runner.BASE_0018][('same', 'V1')]
        self.assertTrue(runner.compare_observations(sides, {'blocked'}))
        for text in ('OBSERVE\tx\tV1\tf\tready=yes\trestorable=true',
                     'OBSERVE\tx\tV1\tf\tready=true',
                     observed('x', 'V1', 'f', True, True) + '\n' + observed('x', 'V1', 'f', True, True)):
            with self.assertRaises(ValueError):
                runner.observations(text)

    def test_probe_facts_and_verdicts(self):
        expected = json.loads(runner.PREDICTIONS.read_text())['probes']['UnsupportedCounterProbe']
        baseline = expected['baseline']
        stdout = '\n'.join(baseline['lines']).replace('holds=[10000, 10001]', 'holds=[10001, 10000]') + '\n'
        red = {'returncode': 1, 'stdout': stdout,
               'stderr': 'Exception in thread "main" ' + baseline['exception'] + '\n\tat x\n'}
        facts = runner.probe_facts(red)
        self.assertEqual(facts['lines'], baseline['lines'])
        self.assertEqual(runner.probe_verdict(facts, baseline), 'RED')
        refused = {'returncode': 1, 'stdout': expected['fix']['lines'][0] + '\n',
                   'stderr': 'Exception in thread "main" ' + expected['fix']['exception'] + '\n'}
        self.assertEqual(runner.probe_verdict(runner.probe_facts(refused), expected['fix']), 'REFUSED')
        # A refusal is never read as the baseline's red, a crash is neither, and a probe that
        # issued nothing but printed other facts is unexpected.
        self.assertEqual(runner.probe_verdict(runner.probe_facts(refused), baseline), 'UNEXPECTED')
        self.assertEqual(runner.probe_verdict(runner.probe_facts(dict(red, returncode=137)), baseline),
                         'UNEXPECTED')
        self.assertEqual(runner.probe_verdict(runner.probe_facts(dict(red, stdout=stdout.replace(
            'ID=2', 'ID=3'))), baseline), 'UNEXPECTED')
        self.assertIsNone(runner.probe_facts({'returncode': 0, 'stdout': '', 'stderr': ''})['exception'])


class RunnerRefusalAndEvidenceTests(unittest.TestCase):
    def test_work_path_budget_includes_the_nested_b2_runner(self):
        self.assertIsNone(runner.work_path_problem(Path('/srv/b3w')))
        self.assertIsNone(runner.work_path_problem(Path('/' + 'a' * 28)))
        problem = runner.work_path_problem(Path('/' + 'a' * 29))
        self.assertIn('work path too long', problem)
        self.assertIn('at most 29 ASCII characters', problem)

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

    def test_missing_jdk_is_not_run(self):
        base = scratch(self)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value=None), \
                mock.patch.object(runner, 'qualify', side_effect=AssertionError('started')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(base / 'evidence.json'), '--work', str(base / 'w'),
                                '--pinned-framework', str(base)])
        self.assertEqual((code, json.loads(output.getvalue())['reason']), (2, 'no JDK on PATH'))
        self.assertEqual(list(base.iterdir()), [])

    def test_timeout_after_a_recorded_step_keeps_the_record_and_its_streams(self):
        base = scratch(self)
        work, evidence = base / 'w', base / 'evidence.json'
        seen = {}

        def interrupted(directory, pinned, progress):
            progress.begin('candidates')
            progress.report['steps']['candidates'] = {'changed_against_0018': [runner.SETTINGS]}
            progress.done('candidates')
            progress.begin('focused')
            seen['checkpoint'] = json.loads((work / 'progress.json').read_text())
            raise subprocess.TimeoutExpired(['java', runner.TEST], 900, output=b'PASS a\n\xff',
                                            stderr=b'stuck\n')
        previous = tempfile.tempdir
        self.addCleanup(setattr, tempfile, 'tempdir', previous)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'qualify', side_effect=interrupted), \
                mock.patch.object(runner, 'b2_regression', side_effect=AssertionError('retried')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        self.assertEqual(code, 1)
        checkpoint = seen['checkpoint']
        self.assertEqual((checkpoint['status'], checkpoint['completed_phases'], checkpoint['phase']),
                         ('RUNNING', ['candidates'], 'focused'))
        report = json.loads(evidence.read_text())
        self.assertEqual(report, json.loads((work / 'progress.json').read_text()))
        self.assertEqual(report['status'], 'NOT_COMPLETE')
        self.assertEqual(report['completed_phases'], ['candidates'])
        self.assertEqual(report['not_completed_phases'], list(runner.PHASES[1:]))
        self.assertEqual(report['exception']['stdout'], 'PASS a\n\ufffd')
        self.assertEqual(report['exception']['stderr'], 'stuck\n')
        self.assertIn('qualification did not complete', report['problems'])

    def test_a_failed_b2_regression_fails_the_run(self):
        base = scratch(self)
        work, evidence = base / 'w', base / 'evidence.json'

        def finished(directory, pinned, progress):
            for phase in runner.PHASES[:-1]:
                progress.begin(phase)
                progress.done(phase)
        previous = tempfile.tempdir
        self.addCleanup(setattr, tempfile, 'tempdir', previous)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'qualify', side_effect=finished), \
                mock.patch.object(runner, 'b2_regression',
                                  return_value={'returncode': 1, 'status': 'FAIL'}), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        report = json.loads(evidence.read_text())
        self.assertEqual((code, report['status']), (1, 'FAIL'))
        self.assertEqual(report['completed_phases'], list(runner.PHASES))
        self.assertIn('B2 runner regression', report['problems'])

    def test_source_only_mode_is_pure(self):
        output = io.StringIO()
        with mock.patch.object(runner, 'qualify', side_effect=AssertionError('started')), \
                mock.patch.object(runner.b1, 'build', side_effect=AssertionError('compiled')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--source-checks-only'])
        self.assertEqual((code, json.loads(output.getvalue())['status']), (0, 'SOURCE_ONLY'))


if __name__ == '__main__':
    unittest.main()
