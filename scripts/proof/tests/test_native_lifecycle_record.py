# SPDX-License-Identifier: Apache-2.0
"""The native account lifecycle record runner: pure source guards and the independent encoder here,
and the guarded JVM run, which is NOT RUN without the required resource bounds, a JDK and the pinned
framework copies. Not Android runtime proof."""
from pathlib import Path
import ast
import inspect
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_lifecycle_record as runner  # noqa: E402
import native_lab_history as lab  # noqa: E402

PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')


def scratch(test):
    directory = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, directory)
    return directory


class LifecycleRecordSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_the_independent_encoder_states_the_plan_sizes(self):
        self.assertEqual(runner.sizes(), runner.PLAN_SIZES)
        self.assertEqual(runner.PLAN_SIZES['fixed'] + 64 * runner.PLAN_SIZES['user'], runner.PLAN_SIZES['largest'])
        self.assertLess(runner.PLAN_SIZES['largest'], 65536)
        self.assertEqual(len(runner.goldens()['MAXIMUM']), 60941)
        with mock.patch.object(runner, 'PLAN_SIZES', dict(runner.PLAN_SIZES, user=930)):
            self.assertIn('size arithmetic', ' '.join(runner.oracle_problems()))

    def test_java_goldens_are_the_independent_encoder_bytes(self):
        pins = runner.java_goldens((ROOT / runner.PLATFORM / (runner.CODEC_TEST + '.java')).read_text())
        gold = runner.goldens()
        self.assertEqual(tuple(pins), runner.GOLDEN_NAMES)
        for name, data in gold.items():
            self.assertEqual(pins[name], (len(data), runner.sha(data)), name)
            # Every golden is a framed version 2 slot record.
            self.assertEqual((data[:4], data[4:6], data[6:8]), (b'AXID', b'\x02\x00', b'\x02\x00'), name)
        predictions = json.loads(runner.PREDICTIONS.read_text())['goldens']
        self.assertEqual({name: (row['bytes'], row['sha256']) for name, row in predictions.items()}, pins)
        # A pin that differs from the encoder is reported.
        source = (ROOT / runner.PLATFORM / (runner.CODEC_TEST + '.java')).read_text()
        root = scratch(self)
        (root / runner.PLATFORM).mkdir(parents=True)
        (root / runner.PLATFORM / (runner.CODEC_TEST + '.java')).write_text(
            source.replace(pins['TICKET'][1], '0' * 64))
        with mock.patch.object(runner, 'ROOT', root):
            self.assertIn('Java golden TICKET differs from the independent encoder', runner.oracle_problems())

    def test_the_encoder_is_independent_of_the_codec(self):
        # The encoder is written here from the plan's layout; no part of it reads the Java codec.
        for function in (runner.record, runner.text, runner.block, runner.slot_v2, runner.goldens, runner.sizes):
            source = inspect.getsource(function)
            self.assertNotIn('NativeIdentityRecords', source, function.__name__)
            self.assertNotIn('read_', source, function.__name__)
        # Its frame agrees with the lab runner's own independent frame of the documented layout.
        for body in (b'', b'\x01\x02', bytes(range(200))):
            self.assertEqual(runner.record(2, 2, body), lab._record(2, 2, body))
        # The suspended golden, field by field.
        suspended = runner.goldens()['SUSPENDED']
        self.assertEqual(len(suspended), 176)
        body = suspended[12:-32]
        self.assertEqual(body[:16].hex(), runner.LINEAGE)
        self.assertEqual(body[16:28].hex(), '8b270000' + '0200000000000000')
        self.assertEqual(body[28:33], b'\x03\x00a.b')
        self.assertEqual(body[67:89].hex(), '0100' + '0300000000000000' + '00000000' + '0500000000000000')
        self.assertEqual(body[89:91], b'\x01\x01')
        self.assertEqual(len(body[91:]), 41)

    def test_case_names_and_counts(self):
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        self.assertEqual(predictions['cases'], {'codec': 47, 'reads': 60, 'goldens': 9, 'mutants': 94, 'store': 33,
                                                'transactions': 29, 'faults': 48})
        self.assertEqual((len(runner.CODEC_NAMES), len(runner.READ_NAMES), len(runner.STORE_NAMES),
                          len(runner.TRANSACTION_NAMES), len(runner.FAULT_NAMES)), (47, 60, 33, 29, 48))
        self.assertEqual(predictions['store_by_label'], {'new-format': 31, 'legacy': 1, 'production': 1})
        self.assertEqual(predictions['transactions_by_label'], {'new-format': 25, 'legacy': 2, 'production': 2})
        self.assertEqual(predictions['reads_by_label'], {'legacy': 20, 'production': 20, 'new-format': 20})
        for format_name in ('V1', 'V2', 'V3'):
            self.assertEqual(len(runner.read_names(format_name)), 20)
        # A failed case prints 'FAIL <name>: <problems>', read up to the first colon and space.
        for name in runner.CODEC_NAMES + runner.READ_NAMES:
            self.assertNotIn(': ', name)
        with mock.patch.object(runner, 'CODEC_NAMES', runner.CODEC_NAMES + ('bad: name',)):
            self.assertIn('a case name of NativeLifecycleCodecTest holds the failure separator', runner.source_checks())
        # Every read case runs under each format's own label.
        self.assertEqual(runner.FORMAT_LABELS, {'V1': 'legacy', 'V2': 'production', 'V3': 'new-format'})
        source = (ROOT / runner.PLATFORM / (runner.READ_TEST + '.java')).read_text()
        self.assertIn('private static final Format[] FORMATS = {Format.V1, Format.V2, Format.V3};', source)

    def test_mutants_anchor_once_change_their_text_and_are_predicted(self):
        texts = runner.mutant_texts()
        self.assertEqual(set(texts), set(runner.MUTANTS))
        for name, (changed, harness, suites) in texts.items():
            with self.subTest(mutant=name):
                self.assertTrue(changed or harness)
                for path, text in changed.items():
                    self.assertNotEqual(text, (ROOT / path).read_text())
                self.assertTrue(set(suites) <= {'codec', 'reads', 'store', 'transactions', 'faults'})
        predictions = json.loads(runner.PREDICTIONS.read_text())['mutants_caught_at_least']
        self.assertEqual(set(predictions), set(runner.MUTANTS))
        # A drifted anchor is refused.
        drifted = dict(runner.MUTANTS)
        drifted['absent'] = (((runner.RECORDS, 'no such text\n', ''),), ('codec',))
        with mock.patch.object(runner, 'MUTANTS', drifted):
            with self.assertRaises(ValueError):
                runner.mutant_texts()

    def test_labels_name_only_living_runs(self):
        self.assertEqual(runner.label_problems(), [])
        self.assertIn('new-format', runner.b1.LIVING_RUN_LABELS)
        rows = [row for row in runner.b1.HARNESS_LABELS if row[0] == 'new-format']
        # The read test's row and the store, transaction and fault tests' row, all of this runner.
        self.assertEqual([row[1] for row in rows], ['scripts/proof/native_lifecycle_record.py'] * 2)
        for label in (('production', 'archived-baseline'), ('rollback-reader',)):
            for step in ('reads', 'store', 'transactions', 'faults'):
                with mock.patch.dict(runner.STEP_LABELS, {step: label}):
                    self.assertTrue(runner.label_problems())
        # A new-format row of another harness is refused.
        with mock.patch.object(runner.b1, 'HARNESS_LABELS', runner.b1.HARNESS_LABELS + (
                ('new-format', 'scripts/proof/native_creation_binding.py', ('NativeCreationBindingTest',), 'x'),)):
            self.assertIn('the new-format label names another harness', runner.label_problems())

    def test_golden_and_result_checks(self):
        gold = scratch(self)
        for name, data in runner.goldens().items():
            (gold / (name + '.bin')).write_bytes(data)
        self.assertEqual(runner.golden_problems(gold), [])
        (gold / 'TICKET.bin').write_bytes(runner.goldens()['TICKET'][:-1] + b'\x00')
        self.assertEqual(runner.golden_problems(gold), ['golden TICKET differs from the independent encoder'])
        (gold / 'EXTRA.bin').write_bytes(b'')
        self.assertIn('written goldens', runner.golden_problems(gold)[0])
        complete = {'complete': True, 'failed': ['x'], 'returncode': 1}
        self.assertEqual(runner.red_names(complete, ('x', 'y')), {'x'})
        self.assertIsNone(runner.red_names(dict(complete, returncode=0), ('x', 'y')))
        self.assertIsNone(runner.red_names(dict(complete, complete=False), ('x', 'y')))
        self.assertIsNone(runner.red_names({'error': 'compile failure'}, ('x',)))

    def test_production_never_constructs_the_lifecycle_format(self):
        # The B1 guard's v3 rule, over the production texts this runner relies on.
        texts = runner.b1.production_texts()
        self.assertEqual(runner.b1.format_violations(texts), [])
        self.assertEqual(runner.b1.boot_literal(texts), runner.b1.PRODUCTION)
        for name, text in texts.items():
            self.assertNotRegex(runner.b1.strip_java_comments(text), r'\bFormat\s*\.\s*V3\b', name)


class LifecycleTransitionSourceTests(unittest.TestCase):
    def test_lifecycle_cases_are_named_once_and_labelled_by_format(self):
        self.assertEqual(runner.lifecycle_name_problems(), [])
        self.assertEqual(runner.PHASES, ('candidate', 'codec', 'reads', 'store', 'transactions', 'faults', 'mutants'))
        self.assertEqual({runner.case_label(name) for name in runner.FAULT_NAMES}, {'new-format'})
        for names in (runner.STORE_NAMES, runner.TRANSACTION_NAMES):
            self.assertEqual({runner.case_label(name) for name in names}, {'legacy', 'production', 'new-format'})
        # A case missing from its source, or a fault kind swept twice, is reported.
        with mock.patch.object(runner, 'STORE_NAMES', runner.STORE_NAMES + ('V3 / absent',)):
            self.assertIn('NativeLifecycleStoreTest case not named once in its source: V3 / absent',
                          runner.lifecycle_name_problems())
        with mock.patch.object(runner, 'FAULT_KINDS', runner.FAULT_KINDS + ('absent',)):
            self.assertIn('fault kind not swept once: absent', runner.lifecycle_name_problems())
        with mock.patch.object(runner, 'STORE_NAMES', runner.STORE_NAMES[:-1]):
            self.assertIn('predicted counts differ from the case lists', runner.source_checks())

    def test_fault_sweeps_reuse_the_existing_seams(self):
        # The eight steps are the B0 write fault seams', injected only into the fault sweep's copies.
        self.assertEqual(runner.FAULT_STEPS, tuple(runner.b1.STEPS))
        with mock.patch.object(runner, 'FAULT_STEPS', runner.FAULT_STEPS[:-1]):
            self.assertIn('the fault steps are not the eight steps of the existing write fault seams',
                          runner.lifecycle_name_problems())
        faults = runner.lifecycle_files(runner.FAULT_TEST)
        store = runner.lifecycle_files(runner.STORE_TEST)
        self.assertIn('NativeHeaderWriteFaults.at(', faults['framework/NativeIdentityStore.java'].decode())
        self.assertIn('NativeHeaderWriteFaults.at(', faults['fixtures/ResilientAtomicFile.java'].decode())
        self.assertIn('tests/NativeHeaderWriteFaults.java', faults)
        self.assertNotIn('NativeHeaderWriteFaults', store['framework/NativeIdentityStore.java'].decode())
        self.assertNotIn('tests/NativeHeaderWriteFaults.java', store)
        for files, test in ((faults, runner.FAULT_TEST), (store, runner.STORE_TEST)):
            self.assertIn('tests/%s.java' % test, files)
            self.assertIn('tests/NativeLifecycleTestSupport.java', files)
        # Production sources carry no seam.
        for path in (ROOT / runner.FRAMEWORK_DIR).glob('*.java'):
            self.assertNotIn('NativeHeaderWriteFaults', path.read_text(), path.name)

    def test_lifecycle_labels_and_mutant_suites(self):
        labelled = {}
        for label, harness, classes, _ in runner.b1.HARNESS_LABELS:
            if harness == 'scripts/proof/native_lifecycle_record.py':
                for name in classes:
                    labelled.setdefault(name, set()).add(label)
        every = {'production', 'legacy', 'new-format'}
        self.assertEqual(labelled, {runner.CODEC_TEST: {'production'}, runner.READ_TEST: every,
                                    runner.STORE_TEST: every, runner.TRANSACTION_TEST: every,
                                    runner.FAULT_TEST: {'new-format'}})
        self.assertEqual(runner.STEP_LABELS['faults'], ('new-format',))
        # A defect names cases of the suites it runs, and every suite runs some defect.
        used = {suite for _, suites in runner.MUTANTS.values() for suite in suites}
        self.assertEqual(used, set(runner.SUITE_NAMES))
        p2a = json.loads(runner.PREDICTIONS.read_text())['p2a']['new_mutants']
        self.assertEqual(len(p2a), 59)
        self.assertTrue(set(p2a) <= set(runner.MUTANTS))
        with mock.patch.dict(runner.MUTANTS, {'scope-bit-0-written': (runner.MUTANTS['scope-bit-0-written'][0],
                                                                      ('codec',))}):
            self.assertIn('mutant prediction inconsistent: scope-bit-0-written', runner.source_checks())


class LifecycleRecordRefusalTests(unittest.TestCase):
    def test_a_run_without_bounds_is_not_run_before_any_effect(self):
        base = scratch(self)
        work, evidence = base / 'work', base / 'evidence.json'
        started = mock.Mock(side_effect=AssertionError('started'))
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner.b1, 'resource_guard', return_value='required bounds absent'), \
                mock.patch.object(runner.b1, 'build', started), mock.patch.object(runner.b1, 'execute', started), \
                redirect_stdout(output):
            status = runner.main(['--evidence', str(evidence), '--work', str(work),
                                  '--pinned-framework', str(base)])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())['status'], 'NOT_RUN')
        self.assertFalse(work.exists() or evidence.exists())

    def test_paths_inside_the_repository_are_refused(self):
        with self.assertRaises(ValueError):
            runner.fresh_outside(ROOT / 'out-of-place', 'work directory')
        with self.assertRaises(ValueError):
            runner.fresh_outside(Path(__file__), 'evidence path')

    def test_runner_nests_no_other_runner(self):
        tree = ast.parse(Path(runner.__file__).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                 and node.attr in ('qualify', 'main', 'regressions', 'archived_qualify')]
        self.assertEqual([ast.unparse(node) for node in calls if ast.unparse(node).startswith(('b1.', 'b2.'))], [])


class LifecycleRecordJvmTests(unittest.TestCase):
    def test_guarded_codec_reads_and_mutants(self):
        reason = runner.b1.resource_guard()
        if reason:
            self.skipTest('NOT RUN: resource guard: ' + reason)
        if not (shutil.which('javac') and shutil.which('java')):
            self.skipTest('NOT RUN: no JDK on PATH')
        if not PINNED:
            self.skipTest('NOT RUN: ANDRIX_PINNED_FRAMEWORK does not name the pinned framework copies')
        work = scratch(self)
        report = {'steps': {}, 'problems': [], 'completed_phases': []}
        runner.qualify(work / 'run', Path(PINNED), report)
        self.assertEqual(report['problems'], [], json.dumps(report['steps'], indent=2)[-20000:])
        self.assertEqual(report['completed_phases'], list(runner.PHASES))


if __name__ == '__main__':
    unittest.main()
