# SPDX-License-Identifier: Apache-2.0
"""The D1 deployment record and D2 artifact store runner: pure source guards and the independent
encoder here, and the guarded JVM run, which is NOT RUN without the required resource bounds and a JDK. Not Android
runtime proof."""
from pathlib import Path
import ast
import inspect
import io
import json
import shutil
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import component_transaction_records as runner  # noqa: E402


def scratch(test):
    directory = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, directory)
    return directory


class ComponentTransactionSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_java_goldens_are_the_independent_encoder_bytes(self):
        pins = runner.java_goldens(runner.source_text('codec'))
        gold = runner.goldens()
        self.assertEqual(tuple(pins), runner.GOLDEN_NAMES)
        for name, data in gold.items():
            self.assertEqual(pins[name], (len(data), runner.sha(data)), name)
            # Every golden is a framed record of its kind at version 1.
            kind = {'PLAN': 1, 'AUTH': 2, 'TICKET': 3, 'OBS': 4, 'SELECTION': 5}[name.split('_')[0]]
            self.assertEqual(data[:4], b'AXDR', name)
            self.assertEqual(struct.unpack('<HHI', data[4:12]), (kind, 1, len(data)), name)
        predictions = json.loads(runner.PREDICTIONS.read_text())['goldens']
        self.assertEqual({name: (row['bytes'], row['sha256']) for name, row in predictions.items()}, pins)
        # A pin that differs from the encoder is reported.
        root = scratch(self)
        (root / runner.TEST_DIR).mkdir(parents=True)
        (root / runner.TEST_DIR / 'DeploymentRecordsTest.java').write_text(
            runner.source_text('codec').replace(pins['TICKET_WINDOW'][1], '0' * 64))
        shutil.copy(ROOT / runner.TEST_DIR / 'ArtifactStoreTest.java', root / runner.TEST_DIR / 'ArtifactStoreTest.java')
        shutil.copytree(ROOT / 'owner/deployment', root / 'owner/deployment')
        with mock.patch.object(runner, 'ROOT', root), \
                mock.patch.object(runner, 'README', root / 'owner/deployment/README.md'):
            self.assertIn('Java golden TICKET_WINDOW differs from the independent encoder', runner.oracle_problems())

    def test_artifact_goldens_are_the_independent_encoder_bytes(self):
        pins = runner.java_goldens(runner.source_text('artifacts'))
        gold = runner.artifact_goldens()
        self.assertEqual(tuple(pins), runner.ARTIFACT_GOLDEN_NAMES)
        for name, data in gold.items():
            self.assertEqual(pins[name], (len(data), runner.sha(data)), name)
            kind = {'MANIFEST': 6, 'PUBLICATION': 7, 'TRANSACTION': 8}[name.split('_')[0]]
            self.assertEqual(data[:4], b'AXDR', name)
            self.assertEqual(struct.unpack('<HHI', data[4:12]), (kind, 1, len(data)), name)
        # The pair names both manifests by their digests, the variant first, each with its own
        # signing transaction.
        pair = gold['PUBLICATION_PAIR']
        transaction = bytes.fromhex(runner.ident(0x5e))
        self.assertIn(bytes.fromhex(runner.sha(gold['MANIFEST_VARIANT'])) + b'\x01' + transaction
                      + bytes.fromhex(runner.sha(gold['MANIFEST_RESTORATION'])) + b'\x02' + transaction, pair)
        predictions = json.loads(runner.PREDICTIONS.read_text())['artifact_goldens']
        self.assertEqual({name: (row['bytes'], row['sha256']) for name, row in predictions.items()}, pins)

    def test_the_encoder_is_independent_of_the_codec(self):
        # The encoder is written here from the README's layout; no part of it reads the Java codec.
        for function in (runner.record, runner.text, runner.ref, runner.plan, runner.authorization, runner.ticket,
                         runner.observation, runner.selection, runner.goldens, runner.manifest, runner.publication,
                         runner.artifact_manifest, runner.artifact_goldens, runner.transaction):
            source = inspect.getsource(function)
            self.assertNotIn('DeploymentRecords', source, function.__name__)
            self.assertNotIn('ArtifactRecords', source, function.__name__)
            self.assertNotIn('read_', source, function.__name__)
        # The authorization golden, field by field from the README's table.
        data = runner.goldens()['AUTH_SIGN']
        body = data[12:-32]
        self.assertEqual(body[:16].hex(), runner.INSTALLATION)
        self.assertEqual(body[16:32].hex(), '%032x' % 0x201)
        self.assertEqual(body[32:54], b'\x14\x00com.android.systemui')
        self.assertEqual(body[54:70].hex(), '%032x' % 0x101)
        self.assertEqual(struct.unpack('<BBBiq', body[70:85]), (1, 3, 1, 0, 0))
        self.assertEqual(body[85:101].hex(), '%032x' % 0x9a)
        self.assertEqual(body[101], runner.SCOPES['ONE_COMPONENT'])
        self.assertEqual(struct.unpack('<q', body[118:126])[0], runner.TIME + 10)
        self.assertEqual(len(body), 126)
        # The frame's checksum covers every preceding byte.
        self.assertEqual(data[-32:], runner.hashlib.sha256(data[:-32]).digest())
        # A text field refuses what the README calls not text.
        with self.assertRaises(ValueError):
            runner.text('a\nb')

    def test_case_names_and_counts(self):
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        self.assertEqual(predictions['cases'], {'codec': 52, 'machine': 70, 'store': 14, 'transactions': 44,
                                                'artifacts': 21, 'signing': 10, 'goldens': 23, 'artifact_goldens': 6,
                                                'mutants': 94})
        self.assertEqual({suite: len(names) for suite, names in runner.NAMES.items()},
                         {'codec': 52, 'machine': 70, 'store': 14, 'transactions': 44, 'artifacts': 21, 'signing': 10})
        self.assertEqual(predictions['guarded_run']['cases_passed'], 211)
        for names in runner.NAMES.values():
            for name in names:
                self.assertNotIn(': ', name)
        with mock.patch.dict(runner.NAMES, {'store': runner.STORE_NAMES + ('bad: name',)}):
            self.assertIn('a case name of store holds the failure separator', runner.name_problems())
        with mock.patch.dict(runner.NAMES, {'store': runner.STORE_NAMES + ('store / not in the source',)}):
            self.assertTrue(any('not named once' in p for p in runner.name_problems()))

    def test_mutants_anchor_once_change_their_text_and_are_predicted(self):
        texts = runner.mutant_texts()
        self.assertEqual(set(texts), set(runner.MUTANTS))
        for name, (changed, suites) in texts.items():
            with self.subTest(mutant=name):
                self.assertTrue(changed)
                for path, text in changed.items():
                    self.assertNotEqual(text, (ROOT / path).read_text())
                    self.assertTrue(path.startswith(runner.MAIN_DIR))
                self.assertTrue(suites and set(suites) <= set(runner.SUITES))
        predictions = json.loads(runner.PREDICTIONS.read_text())['mutants_caught_at_least']
        self.assertEqual(set(predictions), set(runner.MUTANTS))
        drifted = dict(runner.MUTANTS)
        drifted['absent'] = (((runner.RECORDS, 'no such text\n', ''),), ('codec',))
        with mock.patch.object(runner, 'MUTANTS', drifted):
            with self.assertRaises(ValueError):
                runner.mutant_texts()

    def test_every_required_defect_has_a_mutant(self):
        self.assertEqual(len(runner.REQUIRED_DEFECTS), 26)
        for defect, names in runner.REQUIRED_DEFECTS.items():
            for name in names:
                self.assertIn(name, runner.MUTANTS, defect)
        with mock.patch.dict(runner.REQUIRED_DEFECTS, {'a replay': ('missing',)}):
            self.assertIn('no mutant for a replay',
                          runner.prediction_problems(runner.strict(runner.PREDICTIONS.read_text())))

    def test_golden_and_result_checks(self):
        gold = scratch(self)
        for name, data in runner.goldens().items():
            (gold / (name + '.bin')).write_bytes(data)
        self.assertEqual(runner.golden_problems(gold), [])
        (gold / 'OBS_BOOT.bin').write_bytes(runner.goldens()['OBS_BOOT'][:-1] + b'\x00')
        self.assertEqual(runner.golden_problems(gold), ['golden OBS_BOOT differs from the independent encoder'])
        (gold / 'EXTRA.bin').write_bytes(b'')
        self.assertIn('written goldens', runner.golden_problems(gold)[0])
        complete = {'complete': True, 'failed': ['x'], 'returncode': 1}
        self.assertEqual(runner.red_names(complete, ('x', 'y')), {'x'})
        self.assertIsNone(runner.red_names(dict(complete, returncode=0), ('x', 'y')))
        self.assertIsNone(runner.red_names(dict(complete, complete=False), ('x', 'y')))
        run = {'returncode': 1, 'passed': ['a'], 'failed': ['b']}
        self.assertEqual(runner.outcome(run, ('a', 'b'))['complete'], True)
        self.assertEqual(runner.outcome(run, ('a', 'b', 'c'))['complete'], False)
        self.assertEqual(runner.failed_checks('PASS a\nFAIL b / c: d: e\n'), ['b / c'])

    def test_placement_and_store_guards(self):
        self.assertEqual(runner.placement_problems(), [])
        store = (ROOT / runner.STORE).read_text()
        unsynced = store.replace('this(root, installation, step -> { }, true);',
                                 'this(root, installation, step -> { }, false);')
        with mock.patch.object(Path, 'read_text', lambda self, *a, **k: unsynced if self.name == 'DeploymentStore.java'
                               else Path.read_bytes(self).decode()):
            self.assertIn('the public store constructor does not sync', runner.placement_problems())


class ComponentTransactionRefusalTests(unittest.TestCase):
    def test_a_run_without_bounds_is_not_run_before_any_effect(self):
        base = scratch(self)
        work, evidence = base / 'work', base / 'evidence.json'
        started = mock.Mock(side_effect=AssertionError('started'))
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'resource_guard', return_value='required bounds absent'), \
                mock.patch.object(runner, 'build', started), mock.patch.object(runner, 'execute', started), \
                redirect_stdout(output):
            status = runner.main(['--evidence', str(evidence), '--work', str(work)])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())['status'], 'NOT_RUN')
        self.assertFalse(work.exists() or evidence.exists())

    def test_paths_inside_the_repository_are_refused(self):
        with self.assertRaises(ValueError):
            runner.fresh_outside(ROOT / 'out-of-place', 'work directory')
        with self.assertRaises(ValueError):
            runner.fresh_outside(Path(__file__), 'evidence path')

    def test_resource_guard_reads_the_cgroup_limits(self):
        root = scratch(self)
        leaf = root / 'user.slice' / 'scope'
        leaf.mkdir(parents=True)
        membership = root / 'membership'
        membership.write_text('0::/user.slice/scope\n')
        for name, value in (('memory.max', str(2 << 30)), ('memory.swap.max', '0'), ('pids.max', '256'),
                            ('cpu.max', '200000 100000')):
            (leaf / name).write_text(value + '\n')
        with mock.patch.object(runner.resource, 'getrlimit', return_value=(0, 0)):
            self.assertIsNone(runner.resource_guard(root, membership))
            (leaf / 'memory.swap.max').write_text('max\n')
            self.assertIn('required bounds absent', runner.resource_guard(root, membership))
        with mock.patch.object(runner.resource, 'getrlimit', return_value=(0, 1)):
            self.assertIn('core dumps', runner.resource_guard(root, membership))

    def test_runner_imports_no_native_lifecycle_runner(self):
        tree = ast.parse(Path(runner.__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertFalse({name for name in imported if name and name.startswith('native_')}, imported)
        self.assertNotIn('test_native', Path(runner.__file__).read_text())


    def test_every_jvm_caps_its_memory_and_compiler_threads(self):
        calls = []

        def capture(command, **kwargs):
            calls.append(command)
            return mock.Mock(returncode=0, stdout='', stderr='')
        work = scratch(self)
        with mock.patch.object(runner.subprocess, 'run', capture):
            runner.build(work / 'b', {})
            runner.execute(work, 'Main', [])
        javac, java = calls
        self.assertEqual(javac[:2], ['javac', '-J-Xmx384m'])
        self.assertEqual(java[:2], ['java', '-Xmx256m'])
        for option in ('-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1',
                       '-XX:MaxMetaspaceSize=128m', '-XX:ReservedCodeCacheSize=48m'):
            self.assertIn('-J' + option, javac)
            self.assertIn(option, java)


class ComponentTransactionJvmTests(unittest.TestCase):
    def test_guarded_codec_machine_store_transactions_and_mutants(self):
        reason = runner.resource_guard()
        if reason:
            self.skipTest('NOT RUN: resource guard: ' + reason)
        if not (shutil.which('javac') and shutil.which('java')):
            self.skipTest('NOT RUN: no JDK on PATH')
        work = scratch(self)
        report = {'steps': {}, 'problems': [], 'completed_phases': []}
        runner.qualify(work / 'run', report)
        self.assertEqual(report['problems'], [], json.dumps(report['steps'], indent=2, default=str)[-20000:])
        self.assertEqual(report['completed_phases'], list(runner.PHASES))


if __name__ == '__main__':
    unittest.main()
