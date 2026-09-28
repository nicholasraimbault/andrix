# SPDX-License-Identifier: Apache-2.0
"""Complete creation bindings and exact byte admission: pure source guards here, and the guarded
JVM matrix, which is NOT RUN without the required resource bounds. Not Android runtime proof."""
from pathlib import Path
import json
import resource
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_binding as runner  # noqa: E402


class CreationBindingSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_production_format_is_one_literal_v1_construction(self):
        texts = runner.production_texts()
        self.assertEqual(runner.format_violations(texts), [])
        for name, mutated in runner.guard_mutants().items():
            self.assertTrue(runner.format_violations(mutated), name)
        store = (ROOT / runner.STORE).read_text()
        # The enum's own constants and comments are not construction sites.
        self.assertIn('V2(2, 2);', store)
        self.assertIn('Format.V2 is for host tests', store)

    def test_comment_stripping_keeps_literals(self):
        text = 'String a = "// not a comment /* either */"; // gone\nchar c = \'"\'; /* gone\n */ int b;'
        stripped = runner.strip_java_comments(text)
        self.assertIn('"// not a comment /* either */"', stripped)
        self.assertNotIn('gone', stripped)
        self.assertIn("'\"'", stripped)
        self.assertIn('int b;', stripped)

    def test_mutants_anchor_once_and_predictions_are_consistent(self):
        sources = runner.mutant_sources()
        self.assertEqual(set(sources), set(runner.MUTANTS))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        self.assertEqual(set(predictions['b1_mutants_caught_at_least']), set(runner.MUTANTS))
        names = set(runner.FOCUSED_NAMES) | set(runner.FAULT_NAMES)
        for name, expected in predictions['b1_mutants_caught_at_least'].items():
            self.assertTrue(expected and set(expected) <= names, name)
        d104 = predictions['b0_adapted_suite']['d104e15']
        self.assertEqual((len(d104['focused_failures']), len(d104['fault_failures'])), (41, 18))
        self.assertEqual(set(d104['focused_failures']) | set(d104['focused_controls']),
                         set(runner.b0.FOCUSED_NAMES))
        self.assertEqual(set(d104['fault_failures']) | set(d104['fault_controls']),
                         set(runner.b0.FAULT_NAMES))
        self.assertEqual((len(runner.FOCUSED_NAMES), len(runner.FAULT_NAMES), len(runner.LAYOUT_NAMES)),
                         (80, 53, 47))

    def test_compile_failure_keeps_diagnostics_and_is_not_red(self):
        build = {'returncode': 1, 'stdout': '', 'stderr': 'missing symbol', 'inputs': {}}
        result = runner.outcome({'compile_failure': True, 'build': build}, ('case',))
        self.assertEqual(result, {'error': 'compile failure', 'build': build})
        self.assertNotIn('failed', result)

    def test_outcome_requires_complete_unique_names_and_keeps_raw_run(self):
        build = {'returncode': 0, 'inputs': {}}
        run = {'returncode': 1, 'passed': ['case'], 'failed': [],
               'stdout': 'PASS case\n', 'stderr': 'open descriptors'}
        result = runner.outcome({'build': build, 'run': run}, ('case',))
        self.assertEqual(result['returncode'], 1)
        self.assertIs(result['run'], run)
        self.assertTrue(result['complete'])
        run['passed'] = ['case', 'case']
        self.assertFalse(runner.outcome({'build': build, 'run': run}, ('case',))['complete'])

    def test_presence_socket_budget_keeps_the_real_store_path(self):
        with tempfile.TemporaryDirectory(prefix='b1p-', dir='/tmp') as state:
            path = Path(state) / 'presence-V2/c79/store/slots/10123/record.bin-seed'
            self.assertLess(len(str(path)), 100)

    def test_admission_facade_is_the_production_fragment(self):
        fragment = runner.integration.FRAGMENTS['admission'][1].read_bytes()
        facade = (ROOT / runner.PLATFORM /
                  'native_principal_stubs/com/android/server/pm/Settings.java').read_bytes()
        self.assertEqual(facade.count(fragment), 1)

    def test_resource_guard_requires_every_bound(self):
        def tree(values):
            directory = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, directory)
            leaf = directory / 'user.slice' / 'run.scope'
            leaf.mkdir(parents=True)
            for name, value in values.items():
                (leaf / name).write_text(value + '\n')
            membership = directory / 'membership'
            membership.write_text('0::/user.slice/run.scope\n')
            return directory, membership
        exact = {'memory.max': str(2 * runner.GIB), 'memory.swap.max': '0', 'cpu.max': '200000 100000',
                 'pids.max': '256'}
        with mock.patch.object(resource, 'getrlimit', return_value=(0, 0)):
            root, membership = tree(exact)
            self.assertIsNone(runner.resource_guard(root, membership))
            for name, weaker in (('memory.max', str(3 * runner.GIB)), ('memory.swap.max', 'max'),
                                 ('cpu.max', '300000 100000'), ('pids.max', '257')):
                root, membership = tree(dict(exact, **{name: weaker}))
                self.assertIsNotNone(runner.resource_guard(root, membership), name)
            for name in exact:
                root, membership = tree({k: v for k, v in exact.items() if k != name})
                self.assertIsNotNone(runner.resource_guard(root, membership), name)
        with mock.patch.object(resource, 'getrlimit', return_value=(0, 1)):
            root, membership = tree(exact)
            self.assertIn('core dumps', runner.resource_guard(root, membership))


class CreationBindingJvmTests(unittest.TestCase):
    def test_guarded_jvm_matrix(self):
        reason = runner.resource_guard()
        if reason:
            self.skipTest('NOT RUN: resource guard: ' + reason)
        if not (shutil.which('javac') and shutil.which('java')):
            self.skipTest('NOT RUN: no JDK on PATH')
        with tempfile.TemporaryDirectory() as directory:
            evidence = runner.qualify(Path(directory))
        self.assertEqual(evidence['problems'], [], json.dumps(evidence['steps'], indent=2)[-20000:])


if __name__ == '__main__':
    unittest.main()
