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


def predictions_rules():
    return json.loads(runner.PREDICTIONS.read_text())['p4_final']['source_rule_mutants']


def manager_code(texts):
    return runner.b1.strip_java_comments(texts[runner.MANAGER])


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
        self.assertEqual(predictions['cases'], {'codec': 47, 'reads': 60, 'goldens': 9, 'mutants': 183, 'store': 49,
                                                'transactions': 57, 'faults': 136, 'settings': 12, 'manager': 19,
                                                'layouts': 289})
        self.assertEqual((len(runner.CODEC_NAMES), len(runner.READ_NAMES), len(runner.STORE_NAMES),
                          len(runner.TRANSACTION_NAMES), len(runner.FAULT_NAMES), len(runner.SETTINGS_NAMES),
                          len(runner.MANAGER_NAMES)), (47, 60, 49, 57, 136, 12, 19))
        self.assertEqual(predictions['manager_by_label'], {'legacy': 1, 'production': 1, 'new-format': 17})
        self.assertEqual(predictions['store_by_label'], {'new-format': 47, 'legacy': 1, 'production': 1})
        self.assertEqual(predictions['transactions_by_label'], {'new-format': 53, 'legacy': 2, 'production': 2})
        # P2b's fault kinds: the two disposition transactions and Restore, with and without an intact copy.
        self.assertEqual(runner.FAULT_KINDS[6:10], ('beginDisposition', 'confirmDisposition', 'restore',
                                                    'restore without an intact copy'))
        # P2c's: each strict write of the release engine, from LIVE and from CREATING.
        self.assertEqual(runner.FAULT_KINDS[10:], ('release tombstone', 'release tombstone confirmation',
                                                   'release RELEASING', 'release RELEASING confirmation',
                                                   'release omission', 'release completion confirmation',
                                                   'release completion'))
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

    def test_release_stays_unreachable(self):
        texts = runner.b1.production_texts()
        others = runner.other_java_texts(texts)
        self.assertEqual(runner.unreachable_violations(texts, others), [])
        # The engine's own tests construct the capability, and nothing else does.
        for name in runner.CAPABILITY_TESTS:
            self.assertIn(name, others)
        support = others[runner.PLATFORM + runner.SUPPORT + '.java']
        self.assertEqual(support.count('new NativeIdentityPersistence.ReleaseCapability('), 1)
        # Both release bodies are found, and a declaration is no call.
        code = runner.b1.strip_java_comments(texts[runner.PERSISTENCE])
        self.assertEqual(len(runner.body_spans(code, runner.RELEASE_BODIES)), 2)
        mutants = runner.unreachable_mutants()
        self.assertEqual(sum(rules == {'capability'} for _, rules in mutants.values()), 4)
        self.assertEqual(sum(rules == {'release'} for _, rules in mutants.values()), len(runner.RELEASE_ENTRY_POINTS))
        self.assertEqual(sum(rules == {'primitives'} for _, rules in mutants.values()), 4)
        self.assertEqual(sum(rules == {'boot-facts'} for _, rules in mutants.values()), 3)
        self.assertEqual(sum(rules == {'lifecycle'} for _, rules in mutants.values()), 6)
        for name, ((production, other), rules) in mutants.items():
            self.assertEqual(runner.unreachable_rules(production, other), rules, name)
        # A release body that is not found refuses every call in it.
        moved = dict(texts)
        moved[runner.PERSISTENCE] = moved[runner.PERSISTENCE].replace(runner.RELEASE_BODIES[0], '    boolean free(', 1)
        self.assertIn('release', runner.unreachable_rules(moved, others))
        self.assertEqual(predictions_rules(), {'capability': 4, 'release': 12, 'primitives': 4, 'boot-facts': 3,
                                               'lifecycle': 6})
        # The manager's gated release is the one body that calls the engine, Settings' release finish and
        # the pins' finishRelease, and every other lifecycle operation calls only its own transaction.
        self.assertEqual({entry for entry, _, _ in runner.RELEASE_ALLOWANCES},
                         {'release', 'finishNativeIdentityReleaseLPw', 'finishRelease'})
        self.assertEqual(len(runner.body_spans(manager_code(texts), (runner.RELEASE_BODY,))), 1)
        self.assertEqual(len(runner.body_spans(manager_code(texts),
                                               tuple(body for _, _, body in runner.LIFECYCLE_ALLOWANCES))), 6)
        # An assert statement is no declaration: its call is refused like any other.
        asserted = dict(texts)
        asserted[runner.MANAGER] = asserted[runner.MANAGER].replace(
            '    private static void requireRetiring(Handle handle) {\n',
            '    private static void requireRetiring(Handle handle) {\n        assert lift(null, null);\n', 1)
        self.assertIn('lifecycle', runner.unreachable_rules(asserted, others))
        # The old release path keeps exactly its P6 allowances, each a body that exists today.
        self.assertEqual({entry for entry, _, _ in runner.P6_RELEASE_ALLOWANCES},
                         {'finishRetirement', 'finishNativeIdentityReleaseLPw', 'finishRetire'})
        manager = runner.b1.strip_java_comments(texts[runner.MANAGER])
        self.assertEqual(len(runner.body_spans(manager, (runner.OLD_RELEASE_BODY,))), 1)
        # Only Settings' boot facts fragment, carried verbatim by the facade, builds boot facts.
        fragment = runner.integration.FRAGMENTS[runner.BOOT_FACTS_FRAGMENT][1].read_text()
        self.assertEqual(fragment.count('NativeIdentityPersistence.bootFacts(loaded)'), 1)
        self.assertEqual(others[runner.FACADE].count(fragment), 1)
        for name in runner.BOOT_FACTS_TESTS:
            self.assertIn('bootFacts(', others[name])

    def test_mutants_anchor_once_change_their_text_and_are_predicted(self):
        texts = runner.mutant_texts()
        self.assertEqual(set(texts), set(runner.MUTANTS))
        for name, (changed, harness, suites) in texts.items():
            with self.subTest(mutant=name):
                self.assertTrue(changed or harness)
                for path, text in changed.items():
                    self.assertNotEqual(text, (ROOT / path).read_text())
                self.assertTrue(set(suites) <= {'codec', 'reads', 'store', 'transactions', 'faults', 'settings',
                                                'manager'})
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
        # The read test's row, the store, transaction and fault tests' row, the Settings test's row, the
        # manager test's row and the layout emitter's row, all of this runner.
        self.assertEqual([row[1] for row in rows], ['scripts/proof/native_lifecycle_record.py'] * 5)
        # The pinned step carries only the archived rollback reader label, and no living one.
        self.assertEqual(runner.STEP_LABELS['pinned'], ('rollback-reader',))
        with mock.patch.dict(runner.STEP_LABELS, {'pinned': ('new-format',)}):
            self.assertTrue(runner.label_problems())
        with mock.patch.dict(runner.STEP_LABELS, {'layouts': ('rollback-reader',)}):
            self.assertTrue(runner.label_problems())
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
        self.assertEqual(runner.PHASES, ('candidate', 'codec', 'reads', 'store', 'transactions', 'faults',
                                         'settings', 'manager', 'pinned', 'layouts', 'mutants'))
        self.assertEqual({runner.case_label(name) for name in runner.MANAGER_NAMES},
                         {'legacy', 'production', 'new-format'})
        self.assertEqual({runner.FORMAT_LABELS[name.split(' / ', 1)[0]] for name in runner.SETTINGS_NAMES},
                         {'production', 'new-format'})
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
        # The manager suite's store copy, and only it, checks the PMS facade's lock at every load.
        manager = runner.lifecycle_files(runner.MANAGER_TEST)
        self.assertIn(runner.LOCK_SEAM, manager['framework/NativeIdentityStore.java'].decode())
        self.assertNotIn('Thread.holdsLock', store['framework/NativeIdentityStore.java'].decode())
        self.assertNotIn('Thread.holdsLock', faults['framework/NativeIdentityStore.java'].decode())
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
                                    runner.FAULT_TEST: {'new-format'},
                                    runner.SETTINGS_TEST: {'production', 'new-format'},
                                    runner.MANAGER_TEST: every, runner.LAYOUTS: {'new-format'}})
        # Every Settings fragment mutant changes the facade and the harness alike.
        for name, (edits, suites) in runner.MUTANTS.items():
            if any(target.startswith(runner.FRAGMENT) for target, _, _ in edits):
                changed, harness, _ = runner.mutant_texts()[name]
                self.assertIn(runner.FACADE, changed, name)
                self.assertTrue(harness, name)
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


class LifecycleLayoutTests(unittest.TestCase):
    """The layout emitter's names, the independent decoder, the coverage check with its controls, and
    the pinned rollback inputs with their manifest test."""

    def test_layout_names_groups_and_predictions(self):
        self.assertEqual(runner.layout_name_problems(), [])
        predicted = json.loads(runner.PREDICTIONS.read_text())['p5_checkpoint_1']
        self.assertEqual(predicted['layouts']['by_group'], runner.layout_groups())
        self.assertEqual((len(runner.LAYOUT_NAMES), len(runner.LAYOUT_FACTS), len(runner.LAYOUT_STEP_FAMILIES)),
                         (289, 38, 31))
        self.assertEqual(predicted['phases'], list(runner.PHASES))
        # Every transaction of the fault sweeps and every manager operation is a step family.
        self.assertEqual(len(runner.STEP_LAYOUTS), 8 * len(runner.FAULT_KINDS))
        self.assertEqual(len(runner.MANAGER_LAYOUTS), 8 * len(runner.MANAGER_OPERATIONS))
        with mock.patch.object(runner, 'MANAGER_OPERATIONS', runner.MANAGER_OPERATIONS + ('restore',)):
            self.assertIn('manager operation not swept once by the emitter: restore', runner.layout_name_problems())
        with mock.patch.object(runner, 'STATE_LAYOUTS', runner.STATE_LAYOUTS + ('state-unwritten',)):
            self.assertIn('layout not named once in the emitter: state-unwritten', runner.layout_name_problems())

    def test_the_decoder_reads_the_independent_goldens(self):
        gold = runner.goldens()
        for name, data in gold.items():
            slot = runner.decode_slot(data)
            self.assertIsNotNone(slot, name)
            self.assertEqual((slot['version'], slot['size']), (2, len(data)), name)
        self.assertEqual(runner.decode_slot(gold['MAXIMUM'])['size'], runner.PLAN_SIZES['largest'])
        self.assertEqual(len(runner.decode_slot(gold['MAXIMUM'])['users']), 64)
        ticket = runner.decode_slot(gold['TICKET'])
        self.assertEqual((ticket['users'], ticket['ticket'][0]), ([], 17))
        legacy = runner.decode_slot(gold['LEGACY_SUSPENDED'])['users'][0]
        self.assertEqual((legacy['state'], legacy['retirement']['class'], legacy['retirement']['inventory']),
                         ('RETIRING', 'LEGACY_MARKER', 0))
        held = runner.decode_slot(gold['HOLDS'])['users'][0]['entries']
        self.assertEqual([(entry['class'], entry['scope'], entry['note']) for entry in held],
                         [('ACCOUNT_USER', 0, True), ('ADMIN_GRANT', 0, False), ('ADMIN_GRANT', 1, False),
                          ('RECOVERY_HOLD', 3, True)])
        # Damage, another record type and a later version give no reading.
        damaged = bytearray(gold['SUSPENDED'])
        damaged[20] ^= 1
        self.assertIsNone(runner.decode_slot(bytes(damaged)))
        self.assertIsNone(runner.decode_header(gold['SUSPENDED']))
        later = bytearray(gold['SUSPENDED'][:-32])
        later[6:8] = (3).to_bytes(2, 'little')
        self.assertIsNone(runner.decode_slot(bytes(later) + runner.hashlib.sha256(bytes(later)).digest()))
        # A version 1 header with a RELEASING entry, framed by the independent encoder's framing.
        body = bytes.fromhex(runner.LINEAGE) + runner.struct.pack('<qH', 1, 1)
        body += runner.struct.pack('<iBq', 10200, 3, 0) + runner.text('')
        header = runner.decode_header(runner.record(1, 1, body))
        self.assertEqual(header, {'version': 1, 'entries': [
            {'app_id': 10200, 'phase': 'RELEASING', 'package': '', 'bound': False}]})

    def layout(self, kind, holds, slots, header=None):
        directory = scratch(self) / 'layout'
        (directory / 'store' / 'slots').mkdir(parents=True)
        for app_id, data in slots.items():
            (directory / 'store' / 'slots' / str(app_id)).mkdir()
            (directory / 'store' / 'slots' / str(app_id) / 'record.bin').write_bytes(data)
        if header:
            (directory / 'store' / 'store.bin').write_bytes(header)
        (directory / 'kind').write_text(kind + '\n')
        (directory / 'holds').write_text(''.join('%d\n' % hold for hold in holds))
        (directory / 'packages').write_text('a.b 10123\n')
        return directory

    def test_layout_files_must_agree_with_their_bytes(self):
        data = runner.goldens()['SUSPENDED']
        good = runner.read_layout(self.layout('slot 0', [10123], {10123: data}))
        self.assertEqual(runner.layout_problems(good), [])
        self.assertIn('state ELIGIBLE suspended', runner.layout_facts(good))
        wrong = runner.read_layout(self.layout('version1 0', [10123], {10123: data}))
        self.assertIn('kind version1 with an intact version 2 slot', runner.layout_problems(wrong)[0])
        unheld = runner.read_layout(self.layout('slot 0', [], {10123: data}))
        self.assertIn('holds', runner.layout_problems(unheld)[0])
        stated = runner.read_layout(self.layout('slot 2', [10123], {10123: data}))
        self.assertIn('header version 2', runner.layout_problems(stated)[0])
        # A package is mapped only at a held app ID: one at another app ID is no store named package.
        elsewhere = self.layout('slot 0', [10123], {10123: data})
        (elsewhere / 'packages').write_text('a.b 10123\nc.d 10200\n')
        self.assertIn("packages mapped at an app ID that is not held: ['c.d']",
                      runner.layout_problems(runner.read_layout(elsewhere))[0])
        with self.assertRaises(ValueError):
            runner.read_layout(self.layout('copy 1', [10123], {10123: data}))

    def test_coverage_fails_when_a_fact_layout_or_step_is_missing(self):
        facts = {name: set() for name in runner.LAYOUT_NAMES}
        for index, fact in enumerate(runner.LAYOUT_FACTS):
            facts[runner.LAYOUT_NAMES[index]].add(fact)
        self.assertEqual(runner.coverage_problems(facts), [])
        self.assertEqual(runner.coverage_controls(facts), [])
        without = {name: value for name, value in facts.items() if name != 'step-lift-main-synced'}
        problems = runner.coverage_problems(without)
        self.assertIn("missing layouts: ['step-lift-main-synced']", problems)
        self.assertIn("writer steps missing: step-lift at ['main-synced']", problems)
        manager = {name: value for name, value in facts.items() if not name.startswith('manager-releaseuid-omission-')}
        self.assertIn("writer steps missing: manager-releaseuid-omission at %s" % list(runner.FAULT_STEPS),
                      runner.coverage_problems(manager))
        holder = runner.LAYOUT_NAMES[runner.LAYOUT_FACTS.index('companion lost')]
        lost = dict(facts, **{holder: set()})
        self.assertIn('fact missing: companion lost', runner.coverage_problems(lost))
        self.assertIn('unexpected layouts: [\'extra\']', runner.coverage_problems(dict(facts, extra=set())))
        # A control that cannot discriminate is reported: a fact that no reduction removes.
        with mock.patch.object(runner, 'coverage_problems', lambda layouts: []):
            self.assertEqual(len(runner.coverage_controls(facts)), len(runner.LAYOUT_FACTS) + len(facts))

    def test_pinned_rollback_inputs_refuse_living_reads(self):
        # The assembly runs with the working tree closed: a living read raises.
        with mock.patch.object(runner.b1, 'archived_product_sources',
                               lambda revision: {'x': (ROOT / runner.RECORDS).read_bytes()}):
            with self.assertRaises(runner.b1.WorktreeRead):
                runner.rollback_model_files('24bf', '')
        with self.assertRaises(ValueError):
            runner.rollback_model_files('0018', '')
        # The manifest test: exactly the pinned paths, the product from the model's revision.
        reads = {revision: sorted(runner.rollback_model_paths(revision)) for revision, _ in runner.ROLLBACK_MODELS}
        self.assertEqual(runner.rollback_manifest_problems(reads), [])
        self.assertEqual({source for source, _ in reads['7845']}, {'7845', '24bf'})
        self.assertIn(('7845', runner.b1.ARCHIVED_FACADE), reads['7845'])
        self.assertNotIn(('24bf', runner.b1.ARCHIVED_FACADE), reads['7845'])
        extra = dict(reads, **{'7845': reads['7845'] + [('7845', 'owner/tests/platform/NativeLifecycleLayouts.java')]})
        self.assertIn('7845 read an unpinned input: 7845 owner/tests/platform/NativeLifecycleLayouts.java',
                      runner.rollback_manifest_problems(extra))
        missing = dict(reads, **{'24bf': reads['24bf'][1:]})
        self.assertEqual(len(runner.rollback_manifest_problems(missing)), 1)
        self.assertEqual(dict(runner.ROLLBACK_MODELS), {'24bf': 'V2', '7845': 'V1'})

    def test_pinned_rollback_inputs_from_git_objects(self):
        if not PINNED:
            self.skipTest('NOT RUN: ANDRIX_PINNED_FRAMEWORK does not name the pinned framework copies')
        files, reads = runner.rollback_inputs(Path(PINNED), scratch(self) / 'candidates')
        self.assertEqual(runner.rollback_manifest_problems(reads), [])
        predicted = json.loads(runner.PREDICTIONS.read_text())['p5_checkpoint_1']['pinned']
        self.assertEqual(sorted(name for name in set(files['24bf']) | set(files['7845'])
                                if files['24bf'].get(name) != files['7845'].get(name)), predicted['differing_files'])
        self.assertEqual({revision: len(value) for revision, value in files.items()},
                         {revision: predicted['files_per_model'] for revision in files})


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
