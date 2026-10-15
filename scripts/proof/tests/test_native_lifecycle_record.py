# SPDX-License-Identifier: Apache-2.0
"""The native account lifecycle record runner: pure source guards and the independent encoder here,
and the guarded JVM run, which is NOT RUN without the required resource bounds, a JDK and the pinned
framework copies. Not Android runtime proof."""
from collections import Counter
from pathlib import Path
import ast
import base64
import contextlib
import inspect
import io
import json
import os
import re
import shutil
import sys
import tempfile
import textwrap
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
        self.assertEqual(predictions['cases'], {'codec': 47, 'reads': 60, 'dump': 20, 'goldens': 9, 'mutants': 206,
                                                'store': 50, 'transactions': 57, 'faults': 136, 'settings': 12,
                                                'manager': 32, 'layouts': 205})
        self.assertEqual(len(runner.DUMP_NAMES), 20)
        self.assertEqual({name.split(' / ', 1)[0] for name in runner.DUMP_NAMES}, set(runner.DUMP_LABELS))
        self.assertTrue(set(runner.DUMP_CASE_LABELS) <= set(runner.DUMP_NAMES))
        self.assertEqual({label for name in runner.DUMP_NAMES for label in runner.dump_labels(name)},
                         set(runner.STEP_LABELS['dump']))
        self.assertEqual((len(runner.CODEC_NAMES), len(runner.READ_NAMES), len(runner.STORE_NAMES),
                          len(runner.TRANSACTION_NAMES), len(runner.FAULT_NAMES), len(runner.SETTINGS_NAMES),
                          len(runner.MANAGER_NAMES)), (47, 60, 50, 57, 136, 12, 32))
        self.assertEqual(predictions['manager_by_label'], {'legacy': 1, 'previous': 1, 'production': 30})
        self.assertEqual(predictions['store_by_label'], {'production': 48, 'legacy': 1, 'previous': 1})
        self.assertEqual(predictions['transactions_by_label'], {'production': 55, 'legacy': 1, 'previous': 1})
        # P2b's fault kinds: the two disposition transactions and Restore, with and without an intact copy.
        self.assertEqual(runner.FAULT_KINDS[6:10], ('beginDisposition', 'confirmDisposition', 'restore',
                                                    'restore without an intact copy'))
        # P2c's: each strict write of the release engine, from LIVE and from CREATING.
        self.assertEqual(runner.FAULT_KINDS[10:], ('release tombstone', 'release tombstone confirmation',
                                                   'release RELEASING', 'release RELEASING confirmation',
                                                   'release omission', 'release completion confirmation',
                                                   'release completion'))
        self.assertEqual(predictions['reads_by_label'], {'legacy': 20, 'previous': 20, 'production': 20})
        for format_name in ('V1', 'V2', 'V3'):
            self.assertEqual(len(runner.read_names(format_name)), 20)
        # A failed case prints 'FAIL <name>: <problems>', read up to the first colon and space.
        for name in runner.CODEC_NAMES + runner.READ_NAMES:
            self.assertNotIn(': ', name)
        with mock.patch.object(runner, 'CODEC_NAMES', runner.CODEC_NAMES + ('bad: name',)):
            self.assertIn('a case name of NativeLifecycleCodecTest holds the failure separator', runner.source_checks())
        # Every read case runs under each format's own label: Format.V3, which the boot read
        # constructs, is production, and the earlier formats are previous and legacy.
        self.assertEqual(runner.FORMAT_LABELS, {'V1': 'legacy', 'V2': 'previous', 'V3': 'production'})
        b2 = predictions['b2_checkpoint_2']
        self.assertEqual(runner.FORMAT_LABELS, b2['format_labels'])
        # Checkpoint 2b adds the floor step and its own label to the step labels, and nothing else;
        # checkpoint 3a adds the guests step, under the production label.
        floor, guests = predictions['b2_checkpoint_2b'], predictions['b2_checkpoint_3a']
        self.assertEqual({step: list(labels) for step, labels in runner.STEP_LABELS.items()}, guests['step_labels'])
        self.assertEqual({step: labels for step, labels in guests['step_labels'].items() if step != 'guests'},
                         floor['step_labels'])
        self.assertEqual(guests['step_labels']['guests'], ['production'])
        self.assertEqual({step: labels for step, labels in floor['step_labels'].items() if step != 'floor'},
                         b2['step_labels'])
        self.assertEqual(floor['step_labels']['floor'], [floor['run_label']])
        self.assertEqual([(row['before'], row['after']) for row in b2['renamed_cases']],
                         [('V2 / the production format gives no lifecycle fact',
                           'V2 / the previous format gives no lifecycle fact')])
        self.assertIn(b2['renamed_cases'][0]['after'], runner.SETTINGS_NAMES)
        self.assertNotIn(b2['renamed_cases'][0]['before'], runner.SETTINGS_NAMES)
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
        self.assertEqual(len(runner.body_spans(code, runner.RELEASE_BODIES)), 1)
        mutants = runner.unreachable_mutants()
        self.assertEqual(sum(rules == {'capability'} for _, rules in mutants.values()), 12)
        self.assertEqual(sum(rules == {'release'} for _, rules in mutants.values()), len(runner.RELEASE_ENTRY_POINTS) + 25)
        self.assertEqual(sum(rules == {'primitives'} for _, rules in mutants.values()), 6)
        self.assertEqual(sum(rules == {'boot-facts'} for _, rules in mutants.values()), 4)
        self.assertEqual(sum(rules == {'lifecycle'} for _, rules in mutants.values()), 7)
        # Quoted names and the lifecycle state RETIRED trip nothing.
        self.assertEqual([name for name, (_, rules) in mutants.items() if not rules],
                         ['quoted-and-lifecycle-retired-text-allowed', 'quoted-writer-call-with-a-false-drop-flag',
                          'annotations-named-after-covered-methods-allowed'])
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
        # A longer non ASCII name is refused as code outside ASCII, never read as a covered call.
        peer = dict(texts)
        peer[runner.MANAGER] = peer[runner.MANAGER].replace(
            '    NativePrincipalManager(PackageManagerService pm) {\n',
            '    NativePrincipalManager(PackageManagerService pm) {\n        Object r = new Peer()::finishRelease\u20ac;\n', 1)
        found = runner.unreachable_violations(peer, others)
        self.assertTrue(any('outside printable ASCII' in p for p in found), found)
        self.assertFalse(any('finishRelease outside' in p for p in found), found)
        # An assert statement is no declaration: its call is refused like any other.
        asserted = dict(texts)
        asserted[runner.MANAGER] = asserted[runner.MANAGER].replace(
            '    private static void requireRetiring(Handle handle) {\n',
            '    private static void requireRetiring(Handle handle) {\n        assert lift(null, null);\n', 1)
        self.assertIn('lifecycle', runner.unreachable_rules(asserted, others))
        # The obsolete release path has no source allowance.
        self.assertEqual(runner.P6_RELEASE_ALLOWANCES, ())
        manager = runner.b1.strip_java_comments(texts[runner.MANAGER])
        self.assertNotIn('finishRetirementAfterQuiescence', manager)
        self.assertEqual(len(runner.body_spans(manager, (runner.RELEASE_BODY,))), 1)
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
                self.assertTrue(set(suites) <= {'codec', 'reads', 'dump', 'store', 'transactions', 'faults',
                                                'settings', 'manager'})
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
        # The B1 label of the lifecycle format's runs is retired: they are production now, and the
        # runs of Format.V2 on the current sources are previous.
        self.assertEqual(runner.b1.LIVING_RUN_LABELS, ('production', 'legacy', 'previous'))
        self.assertNotIn('new-format', runner.b1.RUN_LABELS)
        self.assertFalse([row for row in runner.b1.HARNESS_LABELS if row[0] == 'new-format'])
        rows = [row for row in runner.b1.HARNESS_LABELS if row[0] == 'production']
        # The codec's row and the Format.V3 rows of this runner: the read test's, the diagnostic
        # test's, the store, transaction and fault tests', the Settings test's, the manager test's,
        # the reader check's, the layout emitter's, and since checkpoint 3a the guest inputs': the
        # guest generator and the guest check.
        lifecycle = 'scripts/proof/native_lifecycle_record.py'
        self.assertEqual(len([row for row in rows if row[1] == lifecycle]), 9)
        self.assertIn(('production', lifecycle, (runner.GUEST_CHECK, runner.GUEST_GENERATOR_CLASS)),
                      [row[:3] for row in rows])
        # Elsewhere, the named V3 runs: the presence V3 step and the moved V3 cases of the binding
        # runner, its production twins and production default check, the header footprint module's
        # V3 cases, the store module's entry points, the production twins and parity of the history
        # runner, the counter suite's production twins, the lab store fixture's Format.V3 reads and
        # the lab rehearsal; and code that constructs no store.
        others = [row for row in rows if row[1] != lifecycle]
        v3 = [row for row in others if set(row[2]) <= set(runner.LIFECYCLE_FORMAT_HARNESSES.get(row[1], ()))]
        storeless = [row for row in others if set(row[2]) <= set(runner.STORELESS_HARNESSES.get(row[1], ()))]
        self.assertEqual([(row[1], row[2]) for row in v3], [
            ('scripts/proof/native_creation_binding.py', ('NativeIdentityPresenceTest',)),
            ('scripts/proof/native_creation_binding.py',
             ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest', 'NativeCreationBindingFaultTest')),
            ('scripts/proof/native_creation_binding.py', ('NativeCreationBindingTest',)),
            ('scripts/proof/native_creation_binding.py', ('NativeProductionDefaultTest',)),
            ('scripts/proof/tests/test_native_header_footprint.py',
             ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest')),
            ('scripts/proof/tests/test_native_identity_store.py',
             ('NativeIdentityFutureFormatTest', 'NativeIdentityVersionGateTest')),
            ('scripts/proof/native_creation_history.py',
             ('NativeCreationHistoryTest', 'NativeCreationHistoryFaultTest', 'NativeHistoryParity')),
            ('scripts/proof/native_counter_admission.py', ('NativeCounterAdmissionTest',)),
            ('scripts/proof/native_lab_history.py', ('LabHistoryStoreTest',))])
        self.assertEqual([row[1] for row in storeless], [
            'scripts/proof/tests/test_native_identity_store.py',
            'scripts/proof/tests/test_native_identity_persistence.py',
            'scripts/proof/tests/test_native_principal_pins.py', 'scripts/proof/tests/test_native_recovery_boot.py'])
        # The lab row holds the rehearsal, a Format.V3 run, and the generator, which constructs no
        # store.
        lab = [row for row in others if row not in v3 + storeless]
        self.assertEqual([(row[1], row[2]) for row in lab],
                         [('scripts/proof/native_lab_history.py', ('NativeWriterLabRehearsal', 'LabHistoryStore'))])
        # No harness is both a known V3 run and code that constructs no store.
        for harness, classes in runner.LIFECYCLE_FORMAT_HARNESSES.items():
            self.assertFalse(set(classes) & set(runner.STORELESS_HARNESSES.get(harness, ())), harness)
        # The rollback check is the one living source under an archived label.
        self.assertEqual(runner.b1.LIVING_ROLLBACK_CHECKS, (runner.ROLLBACK_CHECK,))
        self.assertEqual([row[0] for row in runner.b1.HARNESS_LABELS if runner.ROLLBACK_CHECK in row[2]],
                         ['rollback-reader'])
        with mock.patch.object(runner.b1, 'LIVING_ROLLBACK_CHECKS', ()):
            self.assertIn('labelled host class not found once: rollback-reader NativeLifecycleRollbackCheck',
                          runner.b1.label_problems())
        # The pinned step carries only the archived rollback reader label, and no living one.
        self.assertEqual(runner.STEP_LABELS['pinned'], ('rollback-reader',))
        with mock.patch.dict(runner.STEP_LABELS, {'pinned': ('production',)}):
            self.assertTrue(runner.label_problems())
        with mock.patch.dict(runner.STEP_LABELS, {'layouts': ('rollback-reader',)}):
            self.assertTrue(runner.label_problems())
        # The floor step carries only the floor model's label, which no other step carries, and
        # which names one row: the floor's own reader check here.
        self.assertEqual(runner.STEP_LABELS['floor'], ('floor-model',))
        self.assertEqual(runner.b1.FLOOR_RUN_LABELS, ('floor-model',))
        for change in ({'floor': ('previous',)}, {'floor': ('rollback-reader',)}, {'readers': ('floor-model',)},
                       {'rollback': ('floor-model',)}):
            with self.subTest(change=change), mock.patch.dict(runner.STEP_LABELS, change):
                self.assertTrue(runner.label_problems())
        floor_rows = [row for row in runner.b1.HARNESS_LABELS if row[0] == 'floor-model']
        self.assertEqual([row[1:3] for row in floor_rows], [(lifecycle, (runner.FLOOR_READER,)),
                                                            (lifecycle, (runner.GUEST_CHECK,))])
        # The guest check is the floor's one working-tree class, and the binding runner names it so.
        self.assertEqual(runner.b1.LIVING_FLOOR_CHECKS, (runner.GUEST_CHECK,))
        for change in ({'HARNESS_LABELS': runner.b1.HARNESS_LABELS + (
                ('floor-model', 'scripts/proof/native_creation_binding.py', ('NativeHeaderTestSupport',), 'x'),)},
                       {'LIVING_FLOOR_CHECKS': ()},
                       {'HARNESS_LABELS': tuple(row for row in runner.b1.HARNESS_LABELS
                                                if row[:3] != ('floor-model', lifecycle, (runner.GUEST_CHECK,)))}):
            with self.subTest(change=sorted(change)), mock.patch.multiple(runner.b1, **change):
                self.assertIn('the floor label does not name the floor model\'s reader check and the guest check'
                              ' alone', runner.label_problems())
        for label in (('production', 'archived-baseline'), ('rollback-reader',)):
            for step in ('reads', 'store', 'transactions', 'faults'):
                with mock.patch.dict(runner.STEP_LABELS, {step: label}):
                    self.assertTrue(runner.label_problems())
        # A production row of another harness, such as a suite that runs only the earlier formats,
        # is refused, and so is the retired label.
        for row in (('production', 'scripts/proof/native_creation_binding.py', ('NativeCreationBindingLayouts',), 'x'),
                    ('production', 'scripts/proof/native_creation_history.py', ('NativeRollbackSeedingCheck',), 'x'),
                    ('production', 'scripts/proof/native_counter_admission.py', ('NativeHistoryParity',), 'x'),
                    ('production', 'tests/native-identity/test_writer.py', ('NativePrincipalWriterFixtureTest',), 'x')):
            with self.subTest(row=row[1:3]), mock.patch.object(runner.b1, 'HARNESS_LABELS',
                                                                runner.b1.HARNESS_LABELS + (row,)):
                self.assertIn('the production label names another harness', runner.label_problems())
        with mock.patch.object(runner.b1, 'HARNESS_LABELS', runner.b1.HARNESS_LABELS + (
                ('new-format', 'scripts/proof/native_creation_binding.py', ('NativeIdentityPresenceTest',), 'x'),)):
            self.assertIn('harness label row new-format scripts/proof/native_creation_binding.py',
                          runner.b1.label_problems())

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

    def test_production_constructs_the_lifecycle_format_exactly_at_the_boot_site(self):
        # The binding runner's production format rule, over the production texts this runner relies
        # on: the one anchored boot construction passes Format.V3, and no production text names a
        # format anywhere else.
        texts = runner.b1.production_texts()
        self.assertEqual(runner.b1.format_violations(texts), [])
        self.assertEqual(runner.b1.boot_literal(texts), runner.b1.PRODUCTION)
        self.assertEqual(runner.b1.PRODUCTION, 'NativeIdentityStore.Format.V3')
        named = {name: re.findall(r'\bFormat\s*\.\s*V[0-9]+\b', runner.b1.strip_java_comments(text))
                 for name, text in texts.items()}
        settings = runner.b1.SETTINGS_SECTION
        self.assertEqual({name: found for name, found in named.items() if found}, {settings: ['Format.V3']})
        boot = runner.b1.CONSTRUCTION + runner.b1.PRODUCTION + ');\n' + runner.b1.BOOT_END
        self.assertEqual(texts[settings].count(boot), 1)
        # The lifecycle format's runs carry the production label, and the earlier formats' runs
        # their own.
        self.assertEqual(runner.FORMAT_LABELS['V3'], 'production')
        self.assertNotIn('production', (runner.FORMAT_LABELS['V1'], runner.FORMAT_LABELS['V2']))
        # The floor's boot literal, or a second construction, breaks the rule.
        regressed = runner.b1.guard_mutants()['regression-to-v2'][0]
        self.assertEqual(sorted(runner.b1.format_rules(regressed)), ['format', 'v2'])
        self.assertEqual(runner.b1.format_rules(runner.b1.guard_mutants()['second-construction'][0]), {'sites'})


class LifecycleTransitionSourceTests(unittest.TestCase):
    def test_the_case_map_names_each_old_flow_and_real_lifecycle_cases(self):
        self.assertEqual(runner.case_map_problems(), [])
        predicted = json.loads(runner.PREDICTIONS.read_text())['p6_checkpoint_1e']['case_map']
        self.assertEqual((predicted['mapped'], predicted['removed'], predicted['to_move']),
                         (len(runner.CASE_MAP), len(runner.CASE_MAP_REMOVED), len(runner.CASE_MAP_TO_MOVE)))
        # A removed old flow's literal is gone from its suite, and the lifecycle layouts replace it.
        suite, name, literal, layouts = runner.CASE_MAP_REMOVED[0]
        with mock.patch.object(runner, 'CASE_MAP_REMOVED', ((suite, name, '"fresh-upgrade-"', layouts),)):
            self.assertIn('removed old flow still in its suite: %s %s' % (suite, name), runner.case_map_problems())
        with mock.patch.object(runner, 'CASE_MAP_REMOVED', ((suite, name, literal, ('no-such-layout',)),)):
            self.assertIn('removed old flow without its lifecycle layouts: %s' % name, runner.case_map_problems())
        # Every target is a case of the lifecycle format, chosen by its format whatever its label,
        # an emitted layout, or a V3 case of a living suite of the binding runner, named with its
        # suite.
        for _, _, _, targets in runner.CASE_MAP:
            for target in targets:
                suite, _, name = target.partition(': ')
                self.assertTrue(target in runner.LAYOUT_NAMES or runner.case_format(target) == 'V3'
                                or (suite in ('b0 focused', 'b0 faults', 'binding faults') and name.startswith('V3 '))
                                or (suite in runner.ARM_SUITES and name in runner.ARM_SUITES[suite][1])
                                or target in runner.V3_STEPS,
                                target)
        targets_now = runner.case_map_targets()
        self.assertIn('b0 focused: V3 removeReleasingSlot refused', targets_now)
        self.assertNotIn('b0 focused: removeReleasingSlot refused', targets_now)
        suite, name, literal, targets = runner.CASE_MAP[0]
        with mock.patch.object(runner, 'CASE_MAP', runner.CASE_MAP + ((suite, name, literal, targets),)):
            self.assertIn('old flow named twice in the case map: %s %s' % (suite, name), runner.case_map_problems())
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, '"no such case"', targets),)):
            self.assertIn('old flow not in its suite: %s %s' % (suite, name), runner.case_map_problems())
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal, ('V3 / no such case',)),)):
            self.assertIn('case map target is no lifecycle format case: %s -> V3 / no such case' % name,
                          runner.case_map_problems())
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal, ()),)):
            self.assertIn('case map entry without a lifecycle case: %s' % name, runner.case_map_problems())
        # Exact shapes, lifecycle format targets only, codec goldens only beside another target, and
        # literals that name the flow.
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal),)):
            self.assertIn('case map entry of the wrong shape: %r' % ((suite, name),), runner.case_map_problems())
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal, targets[0]),)):
            self.assertIn('case map entry without a lifecycle case: %s' % name, runner.case_map_problems())
        earlier = 'V1 / every lifecycle transaction refuses before any effect'
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal, targets + (earlier,)),)):
            self.assertIn('case map target is no lifecycle format case: %s -> %s' % (name, earlier),
                          runner.case_map_problems())
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal, ('golden / retiring',)),)):
            self.assertIn('case map entry with codec goldens alone: %s' % name, runner.case_map_problems())
        codec = 'one encoding / every version 1 value is refused in version 2'
        with mock.patch.object(runner, 'CASE_MAP', ((suite, name, literal, targets + (codec,)),)):
            self.assertIn('case map target is no lifecycle format case: %s -> %s' % (name, codec),
                          runner.case_map_problems())
        # The targets do not follow the label: under the retired B1 labels the same cases are
        # chosen.
        with mock.patch.dict(runner.FORMAT_LABELS, {'V1': 'legacy', 'V2': 'production', 'V3': 'new-format'}), \
                mock.patch.dict(runner.b1.STEP_LABELS, {'presence v3': ('new-format',)}):
            self.assertEqual(runner.case_map_targets(), targets_now)
        # The previous format's read cases are refusal targets, and the production format's are not.
        self.assertIn('reads: V2 / a suspended version 2 slot', runner.refusal_targets())
        self.assertNotIn('reads: V3 / a suspended version 2 slot', runner.refusal_targets())
        self.assertIsNotNone(runner.case_map_literal_problem(name, 'run('))
        self.assertIsNotNone(runner.case_map_literal_problem(name, '"another case"'))
        self.assertIsNone(runner.case_map_literal_problem('x / y', '"x / "'))
        self.assertIsNone(runner.case_map_literal_problem('x', 'void x('))
        # A call names its flow complete, or cut after a quoted first argument that the name holds.
        self.assertIsNone(runner.case_map_literal_problem('V1 release marker refused', 'priorOrdering("release marker"'))
        self.assertIsNone(runner.case_map_literal_problem('x', 'store.removeReleasingSlot(releasing, A)'))
        self.assertIsNone(runner.case_map_literal_problem('x', 'refused(root, () -> store.removeReleasingSlot(r, A))'))
        self.assertIsNotNone(runner.case_map_literal_problem('x', 'priorOrdering("release marker"'))
        self.assertIsNotNone(runner.case_map_literal_problem('main: the retirement', 'check(problems, manager'))
        self.assertIsNotNone(runner.case_map_literal_problem('x', 'store.removeReleasingSlot(releasing, A'))
        self.assertIsNotNone(runner.case_map_literal_problem('x', 'store.removeReleasingSlot(a) && b(c)'))
        self.assertIsNotNone(runner.case_map_literal_problem('x', 'check(problems, store.load().creationReady())'))

    def test_each_old_flow_has_its_refusal_and_none_waits(self):
        self.assertEqual(runner.refusal_problems(), [])
        predicted = json.loads(runner.PREDICTIONS.read_text())['p6_checkpoint_1e']['refusals']
        self.assertEqual((predicted['with_refusal'], predicted['to_write'], predicted['one_format']),
                         (len(runner.CASE_MAP_REFUSALS), len(runner.REFUSALS_TO_WRITE), len(runner.ONE_FORMAT_REFUSALS)))
        self.assertEqual(runner.REFUSALS_TO_WRITE, ())
        # A one format refusal names a mapped flow and its reason.
        with mock.patch.dict(runner.ONE_FORMAT_REFUSALS, {('NativeCreationHistoryTest', 'no such flow'): 'reason'}):
            self.assertIn('a one format refusal names no mapped flow or gives no reason', runner.refusal_problems())
        # The manager suite's main names each refusal by the arguments of its shared check.
        self.assertIn('manager main: persistedRoot, manager, first', runner.refusal_targets())
        # The store level refusals run under each earlier format.
        for format_name in ('V1', 'V2'):
            self.assertIn('version gate %s: formatRefusals' % format_name, runner.refusal_targets())
            self.assertIn('presence %s: retiring flag refused on its healthy layout' % format_name,
                          runner.refusal_targets())
        flow = next(iter(runner.CASE_MAP_REFUSALS))
        with mock.patch.dict(runner.CASE_MAP_REFUSALS, {flow: ('binding focused: V2 / no such case',)}):
            self.assertIn('refusal is no case that runs: %s -> binding focused: V2 / no such case' % flow[1],
                          runner.refusal_problems())
        with mock.patch.dict(runner.CASE_MAP_REFUSALS, {flow: ()}):
            self.assertIn('old flow without a refusal case: %s %s' % flow, runner.refusal_problems())
        # A refusal runs in its own suite, and the presence and version gate flows under both formats.
        with mock.patch.dict(runner.CASE_MAP_REFUSALS,
                             {flow: ('counter: manager / a healthy body retires beside a blocked store',)}):
            self.assertTrue(any(p.startswith('refusal outside its own suite: ') for p in runner.refusal_problems()))
        gate = next(key for key in runner.CASE_MAP_REFUSALS if key[0] == 'NativeIdentityVersionGateTest')
        with mock.patch.dict(runner.CASE_MAP_REFUSALS, {gate: ('version gate V1: formatRefusals',)}):
            self.assertIn('refusal not under both earlier formats: %s %s' % gate, runner.refusal_problems())
        # No flow may wait for its refusal, and every flow of the map has one.
        with mock.patch.object(runner, 'REFUSALS_TO_WRITE', (flow,)):
            self.assertTrue(any(p.startswith('old flows still waiting for their refusal')
                                for p in runner.refusal_problems()))
        refusals = dict(runner.CASE_MAP_REFUSALS)
        del refusals[flow]
        with mock.patch.object(runner, 'CASE_MAP_REFUSALS', refusals):
            self.assertTrue(any(p.startswith('old flows without a refusal') for p in runner.refusal_problems()))

    def test_lifecycle_cases_are_named_once_and_labelled_by_format(self):
        self.assertEqual(runner.lifecycle_name_problems(), [])
        # The floor model's phase follows the readers, and the guest inputs' the layouts.
        self.assertEqual(runner.PHASES, ('candidate', 'codec', 'reads', 'dump', 'store', 'transactions', 'faults',
                                         'settings', 'manager', 'pinned', 'layouts', 'guests', 'rollback', 'readers',
                                         'floor', 'mutants'))
        self.assertEqual({runner.case_label(name) for name in runner.MANAGER_NAMES},
                         {'legacy', 'previous', 'production'})
        self.assertEqual({runner.FORMAT_LABELS[name.split(' / ', 1)[0]] for name in runner.SETTINGS_NAMES},
                         {'previous', 'production'})
        self.assertEqual({runner.case_label(name) for name in runner.FAULT_NAMES}, {'production'})
        self.assertEqual({runner.case_format(name) for name in runner.FAULT_NAMES}, {'V3'})
        for names in (runner.STORE_NAMES, runner.TRANSACTION_NAMES):
            self.assertEqual({runner.case_label(name) for name in names}, {'legacy', 'previous', 'production'})
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
        every = {'production', 'legacy', 'previous'}
        self.assertEqual(labelled, {runner.CODEC_TEST: {'production'}, runner.READ_TEST: every,
                                    runner.DUMP_TEST: every,
                                    runner.STORE_TEST: every, runner.TRANSACTION_TEST: every,
                                    runner.FAULT_TEST: {'production'},
                                    runner.SETTINGS_TEST: {'previous', 'production'},
                                    runner.MANAGER_TEST: every, runner.LAYOUTS: {'production'},
                                    runner.ROLLBACK_CHECK: {'rollback-reader'},
                                    runner.READER_CHECK: {'previous', 'production', 'floor-model'},
                                    runner.GUEST_CHECK: {'production', 'floor-model'},
                                    runner.GUEST_GENERATOR_CLASS: {'production'}})
        # Every Settings fragment mutant changes the facade and the harness alike.
        for name, (edits, suites) in runner.MUTANTS.items():
            if any(target.startswith(runner.FRAGMENT) for target, _, _ in edits):
                changed, harness, _ = runner.mutant_texts()[name]
                self.assertIn(runner.FACADE, changed, name)
                self.assertTrue(harness, name)
        self.assertEqual(runner.STEP_LABELS['faults'], ('production',))
        # A defect names cases of the suites it runs, and every suite runs some defect.
        used = {suite for _, suites in runner.MUTANTS.values() for suite in suites}
        self.assertEqual(used, set(runner.SUITE_NAMES))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        p2a = predictions['p2a']['new_mutants']
        self.assertEqual(len(p2a), 59)
        # The refusal of the version 1 writes under every format made two P2a mutants equivalent.
        removed = set(predictions['p6_checkpoint_1d']['removed_mutants'])
        self.assertTrue(set(p2a) - removed <= set(runner.MUTANTS))
        self.assertFalse(removed & set(runner.MUTANTS))
        self.assertTrue(set(predictions['p6_checkpoint_1d']['new_mutants']) <= set(runner.MUTANTS))
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
        predicted = json.loads(runner.PREDICTIONS.read_text())['p5_checkpoint_2']
        self.assertEqual(predicted['layouts']['by_group'], runner.layout_groups())
        self.assertEqual((len(runner.LAYOUT_NAMES), len(runner.LAYOUT_FACTS), len(runner.LAYOUT_STEP_FAMILIES)),
                         (205, 42, 20))
        for name in ('state-releasing-without-directory-header-2', 'state-releasing-without-directory-beside-reservation'):
            self.assertIn(name, runner.STATE_LAYOUTS)
        self.assertIn('RELEASING without a directory under header 2', runner.LAYOUT_FACTS)
        # The manager's writes are the persistence transactions': no manager layout is emitted.
        self.assertFalse([name for name in runner.LAYOUT_NAMES if name.startswith('manager-')])
        # Checkpoint 2b's phases are P5's with the floor phase after the readers, and checkpoint
        # 3a's are 2b's with the guests phase after the layouts.
        phases = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2b']['phases']
        current = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_3a']['phases']
        self.assertEqual(current, list(runner.PHASES))
        self.assertEqual([phase for phase in current if phase != 'guests'], phases)
        self.assertEqual(current.index('guests'), current.index('layouts') + 1)
        self.assertEqual([phase for phase in phases if phase != 'floor'], predicted['phases'])
        self.assertEqual(phases.index('floor'), phases.index('readers') + 1)
        # Every transaction of the fault sweeps is a step family.
        self.assertEqual(len(runner.STEP_LAYOUTS), 8 * len(runner.FAULT_KINDS))
        with mock.patch.object(runner, 'FAULT_KINDS', runner.FAULT_KINDS + ('unswept',)):
            self.assertIn('transaction not swept once by the emitter: unswept', runner.layout_name_problems())
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
        # Obligation states and retirement classes, each as the independent encoder wrote it.
        retired = runner.decode_slot(gold['RETIRED'])['users'][0]['retirement']
        self.assertEqual((retired['class'], retired['inventory']), ('ADMIN_GRANT', 1))
        self.assertEqual([state for _, state in retired['obligations']],
                         ['DISCHARGED'] * 9 + ['DISPOSING'] * 3 + ['ORPHANED_WITH_USER', 'DISCHARGED'] + ['OUTSTANDING'] * 2)
        retiring = runner.decode_slot(gold['RETIRING'])['users'][0]['retirement']
        self.assertEqual((retiring['class'], [state for _, state in retiring['obligations']]),
                         ('ACCOUNT_USER', ['DISCHARGED'] * 3 + ['OUTSTANDING'] * 13))
        self.assertEqual(runner.decode_slot(gold['MAXIMUM'])['users'][0]['retirement']['class'], 'USER_REMOVAL')
        continued = runner.decode_slot(gold['LEGACY_CONTINUED'])['users'][0]['retirement']
        self.assertEqual((continued['class'], continued['inventory'], len(continued['obligations'])),
                         ('LEGACY_MARKER', 1, 16))
        self.assertEqual([kind for kind, _ in retired['obligations']], list(runner.KINDS))
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
        family = {name: value for name, value in facts.items() if not name.startswith('step-release-omission-')}
        self.assertIn("writer steps missing: step-release-omission at %s" % list(runner.FAULT_STEPS),
                      runner.coverage_problems(family))
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
        # The assembly is sealed too: a Git object read past the loader through a raw subprocess, and
        # a path read outside the repository, both raise, so nothing escapes the manifest test.
        outside = scratch(self) / 'outside'
        outside.write_bytes(b'x')
        link = scratch(self) / 'link'
        link.symlink_to(outside)
        probes = {'raw git show': lambda revision: {'x': runner.b1.subprocess.run(
                      ['git', '-C', str(ROOT), 'show', 'HEAD:' + runner.RECORDS], capture_output=True).stdout},
                  'read outside': lambda revision: {'x': outside.read_bytes()},
                  'list outside': lambda revision: {'x': bytes(len(os.listdir(outside.parent)))},
                  'stat outside': lambda revision: {'x': bytes(os.stat(outside).st_size)},
                  'exists outside': lambda revision: {'x': bytes(int(outside.exists()))},
                  'access outside': lambda revision: {'x': bytes(int(os.access(outside, os.R_OK)))},
                  'readlink outside': lambda revision: {'x': os.fsencode(os.readlink(link))}}
        for name, probe in probes.items():
            with self.subTest(probe=name), mock.patch.object(runner.b1, 'archived_product_sources', probe):
                with self.assertRaises(runner.b1.WorktreeRead):
                    runner.rollback_model_files('24bf', '')
        # Outside a sealed assembly the same reads are allowed, and the Git reader stays allowed inside.
        self.assertEqual(outside.read_bytes(), b'x')
        self.assertTrue(os.access(outside, os.R_OK) and os.readlink(link) == str(outside))
        self.assertTrue(runner.b1.sealed(lambda: runner.b1.git_paths(runner.b1.REVISIONS['24bf'], runner.RECORDS))())
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
        # A Git object read past the pinned loader is reported.
        bypass = dict(reads, **{'7845 git': [(runner.b1.REVISIONS['7845'], 'owner/tests/platform/Other.java')]})
        self.assertIn("7845 read Git objects outside the pinned loader", runner.rollback_manifest_problems(bypass)[0])
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


class LifecycleModelTests(unittest.TestCase):
    """The classes the rollback and reader checks take for each layout, their controls and the
    registration guard."""

    def layout(self, kind, header, slots, packages):
        return {'name': 'x', 'kind': kind, 'header': header, 'holds': sorted(slots), 'packages': packages,
                'headers': [], 'slots': slots}

    def body(self, app_id, package, principal, retiring=False):
        return runner.decode_slot(runner.record(2, 1, bytes.fromhex(runner.LINEAGE) + runner.struct.pack('<iq', app_id, 1)
                                                + runner.text(package) + runner.struct.pack('<H', 0)
                                                + runner.struct.pack('<H', 1)
                                                + runner.struct.pack('<qiqB', principal, 0, 5, 1 if retiring else 0)))

    def test_classes_follow_the_bytes_and_the_header(self):
        newer = runner.decode_slot(runner.goldens()['SUSPENDED'])  # app 10123, a.b, principal 3
        layout = self.layout('slot', 1, {10123: [newer]}, {'a.b': 10123})
        self.assertEqual([runner.rollback_class(layout, model) for model in ('24bf', '7845')], ['footprint'] * 2)
        layout['header'] = 2
        self.assertEqual([runner.rollback_class(layout, model) for model in ('24bf', '7845')], ['footprint', 'withdrawn'])
        self.assertEqual((runner.reader_class(layout), runner.version_two_ids(layout)), ('footprint', [10123]))
        layout['header'] = 1
        # The family name in the kind file decides nothing: the bytes do.
        self.assertEqual(runner.rollback_class(dict(layout, kind='reservation'), '24bf'), 'footprint')
        self.assertEqual(runner.rollback_class(dict(layout, packages={'a.b': 'lost'}), '24bf'), 'lost')
        bound = [{'version': 2, 'entries': [{'app_id': 10300, 'phase': 'CREATING', 'package': 'r', 'bound': True}]}]
        self.assertEqual(runner.rollback_class(dict(layout, headers=bound), '24bf'), 'reservation')
        same_package = dict(layout, slots={10123: [newer], 10211: [self.body(10211, 'a.b', 4)]})
        self.assertEqual((runner.rollback_class(same_package, '24bf'), runner.sibling_of(same_package)),
                         ('sibling', ('sibling', 10211, 4)))
        same_principal = dict(layout, slots={10123: [newer], 10211: [self.body(10211, 's.t', 3)]})
        self.assertEqual(runner.sibling_of(same_principal), ('sibling-principal', 10211, 3))
        readable = dict(layout, kind='version1', slots={10123: [self.body(10123, 'a.b', 3)],
                                                       10211: [self.body(10211, 'a.b', 4)]})
        self.assertEqual(runner.rollback_class(readable, '24bf'), 'conflict')
        positive = self.layout('version1', 1, {10123: [self.body(10123, 'a.b', 3)]}, {'a.b': 10123})
        self.assertEqual(runner.rollback_class(positive, '24bf'), 'admitted')
        self.assertEqual(runner.rollback_class(dict(positive, slots={10123: [self.body(10123, 'a.b', 3, True)]}), '24bf'),
                         'retiring')
        self.assertEqual(runner.rollback_class(dict(positive, slots={}, packages={}), '24bf'), 'nothing')
        tombstone = runner.decode_slot(runner.record(2, 1, bytes.fromhex(runner.LINEAGE)
                                                     + runner.struct.pack('<iq', 10123, 4) + runner.text('a.b')
                                                     + runner.struct.pack('<HH', 0, 0)))
        self.assertEqual(runner.rollback_class(dict(positive, slots={10123: [tombstone]}), '24bf'), 'tombstone')
        self.assertEqual(runner.rollback_class(dict(positive, slots={}), '24bf'), 'admitted')

    def test_the_fact_controls_can_fail(self):
        self.assertEqual(runner.fact_control_problems(), [])
        rotated = {code: runner.DUTY_NAMES[code % 4 + 1] for code in runner.DUTY_NAMES}
        with mock.patch.dict(runner.DUTY_NAMES, rotated):
            self.assertTrue(runner.fact_control_problems())
        swapped_classes = {**runner.CLASS_NAMES, 1: 'ADMIN_GRANT', 2: 'ACCOUNT_USER'}
        with mock.patch.dict(runner.CLASS_NAMES, swapped_classes):
            self.assertTrue(runner.fact_control_problems())

    def test_expectations_swaps_and_outcomes(self):
        layouts = {'b': {'kind': 'slot', 'header': 1, 'headers': [], 'packages': {},
                         'slots': {10200: [{'version': 2, 'users': [], 'package': 'a.b'}]}},
                   'a': {'kind': 'version1', 'header': 1, 'headers': [], 'slots': {}, 'packages': {}}}
        lines = runner.expectation_lines(layouts, runner.reader_class)
        self.assertEqual(lines, 'a nothing - -\nb footprint 10200 -\n')
        self.assertEqual(runner.class_counts(lines), {'nothing': 1, 'footprint': 1})
        self.assertEqual(runner.counts_argument({'b': 2, 'a': 1}), 'a=1,b=2')
        self.assertEqual(runner.swapped(lines, {'b': 'admitted'}), 'a nothing - -\nb admitted 10200 -\n')
        names = ['x / a', 'x / b']
        passing = {'passed': names, 'failed': [], 'returncode': 0, 'stdout': 'unqualified'}
        self.assertIsNone(runner.check_outcome(passing, names))
        self.assertIsNotNone(runner.check_outcome(passing, names, ['x / b']))
        failing = {'passed': ['x / a'], 'failed': ['x / b'], 'returncode': 1, 'stdout': ''}
        self.assertIsNone(runner.check_outcome(failing, names, ['x / b']))
        self.assertIsNotNone(runner.check_outcome(failing, names))
        self.assertIsNotNone(runner.check_outcome(dict(failing, passed=[]), names, ['x / b']))

    def test_predictions_cover_every_layout_and_name_real_controls(self):
        predictions = json.loads(runner.PREDICTIONS.read_text())
        predicted, swaps = predictions['p5_checkpoint_2'], runner.swap_controls(predictions)
        self.assertEqual(runner.model_prediction_problems(predicted, swaps), [])
        # The swap controls are rotated: each model gives every class once, to a layout of another class.
        for revision, _ in runner.ROLLBACK_MODELS:
            self.assertEqual(sorted(swaps[revision].values()), sorted(runner.ROLLBACK_CLASSES))
            self.assertEqual(predictions['p6_checkpoint_1b']['rollback'][revision]['swap_control_fails'],
                             len(swaps[revision]))
            # The sibling classes go to conflict layouts, whose lines carry real sibling coordinates.
            self.assertEqual({name for name, klass in swaps[revision].items() if klass.startswith('sibling')},
                             {'companion-sibling-package-version1', 'companion-sibling-principal-version1'})
        repeated = json.loads(json.dumps(swaps))
        repeated['7845']['state-lifted'] = 'footprint'
        self.assertIn('rollback swap control of 7845 does not give each class once',
                      runner.model_prediction_problems(predicted, repeated))
        for revision, _ in runner.ROLLBACK_MODELS:
            self.assertEqual(sum(predicted['rollback'][revision]['classes'].values()), len(runner.LAYOUT_NAMES))
            self.assertEqual(len(predicted['rollback'][revision]['format_control']), 47)
        self.assertEqual(predicted['rollback']['7845']['classes']['withdrawn'], 47)
        self.assertEqual((predicted['readers']['valid_under_v3'], predicted['readers']['outside_user_0_under_v3']),
                         (157, 2))
        self.assertEqual(predicted['rollback']['24bf']['classes']['sibling-principal'], 1)
        self.assertEqual(predicted['rollback']['24bf']['classes']['conflict'], 2)
        broken, unknown = json.loads(json.dumps(predicted)), json.loads(json.dumps(swaps))
        unknown['24bf']['no-such-layout'] = 'admitted'
        self.assertIn('rollback swap control no-such-layout admitted', runner.model_prediction_problems(broken, unknown))
        broken['readers']['classes']['nothing'] += 1
        self.assertIn('predicted reader classes do not cover the layouts',
                      runner.model_prediction_problems(broken, swaps))

    def test_the_registration_guard_is_the_first_fresh_check(self):
        self.assertEqual(runner.registration_guard_problems(), [])
        with mock.patch.object(runner, 'REGISTRATION_GUARD', runner.REGISTRATION_GUARD.replace('isNative', 'isOther')):
            self.assertTrue(runner.registration_guard_problems())

    def test_the_checks_name_their_formats_and_api(self):
        rollback = (ROOT / runner.PLATFORM / (runner.ROLLBACK_CHECK + '.java')).read_text()
        reader = (ROOT / runner.PLATFORM / (runner.READER_CHECK + '.java')).read_text()
        # The rollback check names no lifecycle record API that the old products lack.
        code = runner.b1.strip_java_comments(rollback)
        for pattern in (r'\bLifecycle\b', r'\bSuspension\b', r'Format\s*\.\s*V3\b', r'\bBootFacts\b',
                        r'\blifecycleFormat\b', r'\.history\('):
            self.assertNotRegex(code, pattern)
        self.assertIn('Format.V3', reader)
        # The format is passed to boot explicitly; nothing builds through the adapter, reopen or livePm,
        # whose 24bfb6a copies construct Format.V1.
        for pattern in (r'\bNativeHeaderApi\b', r'\breopen\s*\(', r'\blivePm', r'\breopenOf\s*\('):
            self.assertNotRegex(code, pattern)
        self.assertRegex(code, r'\bboot\(root, format, mapped\)')
        self.assertRegex(code, r'new NativeIdentityStore\(root\.toFile\(\), format\)')
        self.assertEqual(runner.STEP_LABELS['rollback'], ('rollback-reader',))
        self.assertEqual(runner.STEP_LABELS['readers'], ('previous', 'production'))
        self.assertIn('rollback', runner.PINNED_STEPS)
        self.assertEqual(runner.FLOOR_STEPS, ('floor',))
        self.assertNotIn('floor', runner.PINNED_STEPS)
        # The current sources' reader no longer calls itself B1's: B1's own reader is the floor's.
        self.assertNotIn("B1's reader", reader)
        self.assertIn('read by the current sources under Format.', reader)
        self.assertNotIn("B1's reader", inspect.getdoc(runner.readers_phase))
        floor = runner.b1.floor_bytes(runner.b1.FLOOR_PLATFORM + runner.FLOOR_READER + '.java').decode()
        self.assertIn("lifecycle layouts read by B1's reader under Format.", floor)


FLOOR_HISTORY = 'scripts/proof/native_creation_history.py'


def floor_history_function(name):
    """The source of one top level function of the history runner as its Git object at the floor
    revision states it."""
    text = runner.b1.git_bytes(runner.b1.FLOOR, FLOOR_HISTORY).decode()
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    raise AssertionError('no function %s at the floor revision' % name)


def floor_history_constants(names):
    """Module level constants of the history runner as its Git object at the floor revision states
    them, evaluated with no builtins and the regular expression module alone."""
    values = {}
    for node in ast.parse(runner.b1.git_bytes(runner.b1.FLOOR, FLOOR_HISTORY).decode()).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in names):
            code = compile(ast.Expression(node.value), FLOOR_HISTORY, 'eval')
            values[node.targets[0].id] = eval(code, {'__builtins__': {}, 're': re})  # noqa: S307
    return values


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


class LifecycleFloorTests(unittest.TestCase):
    """The floor model of B1's image: its own manifest and loader, the frozen cutter, the sealed
    assembly and its read record, the format and wrong model refusals, the hook of the B2 guest
    inputs, the footprint of the emitted layouts and the predictions. Each refusal has its
    control."""

    def test_the_floor_manifest_is_its_own(self):
        pins = runner.b1.FLOOR_SHA256
        self.assertEqual(runner.b1.floor_problems(), [])
        # The patch and profile, six helpers, two fixtures, the facade and stubs, the file and XML
        # stubs, eighteen fragments, and the harness template, body inputs, supports and reader
        # check.
        self.assertEqual([len(group) for _, group in runner.b1.FLOOR_PIN_GROUPS], [2, 6, 2, 21, 18, 18, 6])
        self.assertEqual(len(pins), 73)
        # Not the 24bfb6a surroundings: inputs at one path differ, and some of B1's are not there.
        archive = runner.b1.manifest(runner.b1.ARCHIVE)
        differing = sorted(path for path in pins if path in archive and archive[path] != pins[path])
        self.assertEqual(len(differing), 15)
        for path in (runner.FLOOR_TEMPLATE, runner.b1.FLOOR_PLATFORM + 'native_recovery_fragments/identity.java.inc',
                     runner.b1.FLOOR_PLATFORM + 'native_principal_stubs/android/os/UserHandle.java'):
            self.assertIn(path, differing)
        self.assertEqual(len([path for path in pins if path not in archive]), 10)
        self.assertIn(runner.b1.FLOOR_PLATFORM + runner.FLOOR_READER + '.java', pins)
        self.assertNotIn(runner.b1.FLOOR_PLATFORM + 'native_principal_xml_stubs/android/util/Xml.java', pins)
        # Git objects alone: the working tree is never read.
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('working tree read')), \
                mock.patch.object(Path, 'read_text', side_effect=AssertionError('working tree read')):
            self.assertEqual(runner.sha(runner.b1.floor_bytes(runner.FLOOR_TEMPLATE)), pins[runner.FLOOR_TEMPLATE])
        # B1's profile names the floor's patch and pins each helper, fixture and fragment as the
        # manifest does.
        self.assertEqual(runner.floor_profile_problems(runner.floor_profile()), [])
        self.assertEqual(sorted(runner.floor_fragments()), sorted(runner.integration.FRAGMENTS))

    def test_the_floor_loader_refuses_a_missing_pin_drift_and_a_wrong_patch(self):
        directory = runner.b1.FLOOR_PLATFORM + 'native_principal_stubs/'
        stub = directory + 'android/os/UserHandle.java'
        # Controls: the pinned tree and object load.
        self.assertIn(stub, runner.b1.floor_paths(directory))
        self.assertEqual(runner.sha(runner.b1.floor_bytes(stub)), runner.b1.FLOOR_SHA256[stub])
        # A missing pin refuses the input and the stub tree it belongs to.
        without = {path: digest for path, digest in runner.b1.FLOOR_SHA256.items() if path != stub}
        with mock.patch.object(runner.b1, 'FLOOR_SHA256', without):
            with self.assertRaisesRegex(ValueError, 'unpinned floor input'):
                runner.b1.floor_bytes(stub)
            with self.assertRaisesRegex(ValueError, 'floor tree drift'):
                runner.b1.floor_paths(directory)
            self.assertTrue(runner.b1.floor_problems())
        # An altered stub is drift.
        original = runner.b1.git_bytes

        def altered(revision, path):
            return original(revision, path) + (b'// altered\n' if path == stub else b'')
        with mock.patch.object(runner.b1, 'git_bytes', altered):
            with self.assertRaisesRegex(ValueError, 'floor input drift'):
                runner.b1.floor_bytes(stub)
            self.assertEqual(runner.b1.floor_problems(), ['floor pins: floor input drift: ' + stub])
        # A wrong patch, B2's own, is drift; pinned in its place, B1's profile refuses it.
        current = runner.integration.PATCH.read_bytes()

        def wrong(revision, path):
            return current if path == runner.b1.NATIVE_PATCH else original(revision, path)
        with mock.patch.object(runner.b1, 'git_bytes', wrong):
            with self.assertRaisesRegex(ValueError, 'floor input drift'):
                runner.b1.floor_bytes(runner.b1.NATIVE_PATCH)
            with mock.patch.dict(runner.b1.FLOOR_SHA256, {runner.b1.NATIVE_PATCH: runner.sha(current)}):
                self.assertIn('the floor profile names another patch',
                              runner.floor_profile_problems(runner.floor_profile()))
                self.assertIn('the floor patch does not construct', ' '.join(runner.b1.floor_problems()))

    def test_the_floor_runs_the_format_of_b1s_boot_read_only(self):
        boot = runner.b1.METHOD + runner.b1.CONSTRUCTION + runner.b1.PREVIOUS + ');\n' + runner.b1.BOOT_END + '    }\n'
        self.assertEqual(runner.floor_format_problems(boot), [])
        forward = runner.b1.b2_forward(boot)
        self.assertEqual(len(runner.floor_format_problems(forward)), 1)
        self.assertEqual(len(runner.floor_format_problems(forward, 'V3')), 1)
        self.assertEqual(len(runner.floor_format_problems(boot, 'V3')), 2)
        self.assertEqual(len(runner.floor_format_problems('class Settings {}')), 1)
        with mock.patch.object(runner, 'FLOOR_FORMAT', 'V3'):
            self.assertEqual(len(runner.floor_format_problems(boot)), 2)
        self.assertEqual(runner.FLOOR_FORMAT, 'V2')
        # The floor patch's own boot read constructs the previous format.
        sections = dict(runner.b1.patch_sections(runner.b1.floor_bytes(runner.b1.NATIVE_PATCH).decode()))
        self.assertEqual(runner.b1.boot_literal({runner.b1.SETTINGS_SECTION: sections[runner.integration.SETTINGS]}),
                         runner.b1.PREVIOUS)

    def test_the_frozen_cutter_is_b1s(self):
        anchors = {'FLOOR_' + name: name for name in (
            'APPLY_START', 'BOOT_FACTS_START', 'QUERIES_START', 'RELEASE_FINISH_START', 'BINDING_START',
            'DIAGNOSTIC_START', 'DIAGNOSTIC_NAME_START', 'REMEMBERED_FIELD')}
        values = floor_history_constants(set(anchors.values()))
        self.assertEqual(set(values), set(anchors.values()))
        for frozen, original in anchors.items():
            value = getattr(runner, frozen)
            self.assertEqual(getattr(value, 'pattern', value), getattr(values[original], 'pattern', values[original]))
        cutters = {'_floor_cut': 'cut', '_floor_method': 'method', '_floor_methods_through': 'methods_through',
                   'floor_settings_texts': 'settings_texts', 'floor_text_checks': 'b2_text_checks',
                   'floor_harness_source': 'harness_source'}
        fragments = ('fragments = {name: path.read_text() for name, (_, path) in integration.FRAGMENTS.items()}',
                     'fragments = floor_fragments()')
        harness = (('def harness_source(settings, side, seeding=None):', 'def harness_source(settings):'),
                   ("    if seeding is not None:\n        texts['SEEDING'] = seeding\n", ''),
                   ('BODY_INPUTS[side].read_text()', 'b1.floor_bytes(FLOOR_BODY_INPUTS).decode()'),
                   ('source = TEMPLATE.read_text()', 'source = b1.floor_bytes(FLOOR_TEMPLATE).decode()'),
                   ('    return source', "    if sha(source.encode()) != FLOOR_HARNESS_SHA256:\n"
                                       "        raise ValueError('floor harness drift: %s' % sha(source.encode()))\n"
                                       "    return source"))
        replacements = {'settings_texts': (fragments,), 'b2_text_checks': (fragments,), 'harness_source': harness}
        for frozen, original in cutters.items():
            with self.subTest(frozen=frozen):
                source = floor_history_function(original)
                for old, new in replacements.get(original, ()):
                    self.assertEqual(source.count(old), 1, old)
                    source = source.replace(old, new)
                frozen_source = inspect.getsource(getattr(runner, frozen))
                self.assertEqual(normalized_function(frozen_source, {**cutters, **anchors}),
                                 normalized_function(source))
        # A drifted copy is no longer B1's cutter.
        drifted = inspect.getsource(runner._floor_cut).replace('keep_start=True', 'keep_start=False')
        self.assertNotEqual(normalized_function(drifted, cutters), normalized_function(floor_history_function('cut')))

    def test_the_sealed_floor_assembly_reads_pinned_objects_alone(self):
        def stand_in(settings):
            return 'final class NativeHistoryHarness {}'
        # Control: with a stand-in harness the assembly is B1's product, supports and reader check.
        with mock.patch.object(runner, 'floor_harness_source', stand_in):
            files = runner.floor_model_files('')
        self.assertEqual(len(files), 51)
        self.assertEqual(files['tests/%s.java' % runner.FLOOR_READER],
                         runner.b1.floor_bytes(runner.b1.FLOOR_PLATFORM + runner.FLOOR_READER + '.java'))
        self.assertEqual(files['stubs/android/util/Log.java'], runner.b1.floor_bytes(
            runner.b1.FLOOR_PLATFORM + 'native_principal_xml_stubs/android/util/Log.java'))
        self.assertFalse([name for name in files if name.startswith('history-stubs/')])
        # A planted living read raises, as do a raw Git read and any read or examination outside.
        outside = scratch(self) / 'outside'
        outside.write_bytes(b'x')
        probes = {'living read': lambda settings: (ROOT / runner.FACADE).read_text(),
                  'living fragment': lambda settings: runner.integration.FRAGMENTS['identity'][1].read_text(),
                  'raw git show': lambda settings: runner.b1.subprocess.run(
                      ['git', '-C', str(ROOT), 'show', '%s:%s' % (runner.b1.FLOOR, runner.FLOOR_TEMPLATE)],
                      capture_output=True).stdout.decode(),
                  'read outside': lambda settings: outside.read_text(),
                  'stat outside': lambda settings: str(os.stat(outside).st_size)}
        for name, probe in probes.items():
            with self.subTest(probe=name), mock.patch.object(runner, 'floor_harness_source', probe):
                with self.assertRaises(runner.b1.WorktreeRead):
                    runner.floor_model_files('')

    @staticmethod
    def floor_stand_ins():
        """A candidate and harness standing in for B1's, reading their inputs through the loader."""
        def candidate(pinned, scratch):
            runner.b1.floor_bytes(runner.b1.NATIVE_PATCH)
            return '', {}

        def harness(settings):
            runner.floor_fragments()
            runner.b1.floor_bytes(runner.FLOOR_TEMPLATE)
            runner.b1.floor_bytes(runner.FLOOR_BODY_INPUTS)
            return 'final class NativeHistoryHarness {}'
        return candidate, harness

    def test_the_call_record_is_exactly_the_floor_manifest(self):
        floor, store = runner.b1.FLOOR, runner.b1.STORE
        trees = [(floor, runner.b1.FLOOR_PLATFORM + name + '/') for name in runner.b1.FLOOR_STUB_DIRECTORIES]
        calls = [(floor, path) for path in runner.b1.FLOOR_SHA256] + [(floor, store)]
        reads = {'floor': calls, 'git': list(calls), 'trees': trees, 'listed': list(trees), 'outside': []}
        self.assertEqual(runner.floor_manifest_problems(reads), [])
        for change, expected in (
                ({'floor': calls + [(floor, 'owner/tests/platform/NativeLifecycleLayouts.java')]},
                 'the floor read unpinned inputs'),
                ({'floor': calls + [(runner.b1.REVISIONS['24bf'], runner.FLOOR_TEMPLATE)]},
                 'the floor read unpinned inputs'),
                ({'floor': calls[1:]}, 'the floor manifest pins inputs the floor did not read'),
                ({'git': calls + [(floor, 'AGENTS.md')]}, 'the floor read Git objects outside its loader'),
                # A second Git read of a path the loader read twice: the multisets differ.
                ({'git': calls + [(floor, store)]}, "outside its loader: [('%s', '%s')]" % (floor, store)),
                ({'git': calls[:-1]}, "without a Git read: [('%s', '%s')]" % (floor, store)),
                ({'outside': [('show', floor, store)]}, 'the floor read Git objects outside its loader'),
                ({'listed': trees + trees[:1]}, 'the floor listed'),
                ({'listed': trees + [(floor, runner.b1.FLOOR_PLATFORM)]}, 'the floor listed'),
                ({'trees': trees[:1], 'listed': trees[:1]}, 'the floor listed')):
            with self.subTest(change=sorted(change), expected=expected):
                self.assertIn(expected, ' '.join(runner.floor_manifest_problems(dict(reads, **change))))

    def test_every_git_read_passes_through_the_floor_loader(self):
        candidate, harness = self.floor_stand_ins()
        floor, store, product = runner.b1.FLOOR, runner.b1.STORE, runner.floor_product_sources
        loaders = (runner.b1.floor_bytes, runner.b1.floor_paths, runner.b1.git_bytes, runner.b1.git_paths)
        # Control: the normal assembly, the candidate and harness standing in. Every pinned input is
        # read, and each Git read is the active loader call's own, one for one.
        with mock.patch.object(runner, 'floor_candidate', candidate), \
                mock.patch.object(runner, 'floor_harness_source', harness):
            reads = runner.floor_inputs(Path('unused'), Path('unused'))[3]
        self.assertEqual(runner.floor_manifest_problems(reads), [])
        self.assertEqual((len(set(reads['floor'])), reads['outside']), (73, []))
        self.assertEqual(Counter(reads['git']), Counter(reads['floor']))
        self.assertEqual(Counter(reads['listed']), Counter(reads['trees']))
        # A Git call past the loader raises: of a new path, of a path the loader already read, at
        # another revision, a tree listing, and the store helper read again and changed.
        cases = {'new path': lambda files: runner.b1.git_bytes(floor, 'AGENTS.md') and files,
                 'already read path': lambda files: runner.b1.git_bytes(floor, store) and files,
                 'other revision': lambda files: runner.b1.git_bytes(runner.b1.REVISIONS['24bf'], store) and files,
                 'tree listing': lambda files: runner.b1.git_paths(floor, runner.b1.FLOOR_PLATFORM) and files,
                 'changed store helper': lambda files: dict(files, **{
                     'framework/NativeIdentityStore.java': runner.b1.git_bytes(floor, store) + b'// changed\n'})}
        for name, edit in cases.items():
            with self.subTest(case=name), mock.patch.object(runner, 'floor_candidate', candidate), \
                    mock.patch.object(runner, 'floor_harness_source', harness), \
                    mock.patch.object(runner, 'floor_product_sources', lambda edit=edit: edit(product())):
                with self.assertRaisesRegex(runner.FloorBypass, 'past its loader'):
                    runner.floor_inputs(Path('unused'), Path('unused'))
        # Each refusal leaves the loaders restored and no floor state behind.
        self.assertEqual((runner.b1.floor_bytes, runner.b1.floor_paths, runner.b1.git_bytes, runner.b1.git_paths),
                         loaders)
        self.assertEqual((runner._FLOOR_ACTIVE, runner._FLOOR_LOADER, runner._FLOOR_REBUILD), ([], [], []))

    def rebuild_layout(self):
        """A rebuild scratch directory as b1's floor rebuild lays it out before its patch start: the
        scratch copy of B1's patch, from the floor loader, and a tree of framework copies. Without
        the pinned copies these are stand-ins, and the rebuild is bound to their digests."""
        base = scratch(self)
        pinned, directory = base / 'pinned', base / 'rebuild'
        names = ('services/a/A.java', 'services/b/B.java')
        for name in names:
            for root in (pinned, directory / 'tree'):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(name.encode())
        (directory / 'floor.patch').write_bytes(runner.b1.floor_bytes(runner.b1.NATIVE_PATCH))
        value = {'files': [{'path': name, 'upstream_sha256': runner.sha(name.encode())} for name in names]}
        return pinned, directory, runner.floor_rebuild(pinned, directory, value)

    def rebuilding(self, spec, *starts, before=None, window=True):
        """A candidate standing in for B1's that opens the rebuild's window for spec, makes the edit
        before, starts each of starts as (argv, cwd, env), and reads the patch through the
        loader."""
        candidate = self.floor_stand_ins()[0]

        def stand_in(pinned, scratch):
            with runner.floor_rebuilding(spec) if window else contextlib.nullcontext():
                if before:
                    before()
                for argv, cwd, env in starts:
                    runner.subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=30)
            return candidate(pinned, scratch)
        return stand_in

    def test_the_rebuild_admits_only_its_own_patch_command(self):
        harness = self.floor_stand_ins()[1]
        outside = scratch(self) / 'floor.patch'
        outside.write_bytes(runner.b1.floor_bytes(runner.b1.NATIVE_PATCH))
        living = ROOT / runner.b1.NATIVE_PATCH
        # Control: the rebuild's own command, as b1 starts it, once, with its inputs as laid out.
        pinned, directory, spec = self.rebuild_layout()
        self.assertEqual(spec['argv'], [runner.FLOOR_PATCH_TOOL, *runner.FLOOR_PATCH_OPTIONS, '-i',
                                        str(directory / 'floor.patch')])
        self.assertEqual(spec['cwd'], str(directory / 'tree'))
        with mock.patch.object(runner, 'floor_candidate', self.rebuilding(spec, (spec['argv'], spec['cwd'], None))), \
                mock.patch.object(runner, 'floor_harness_source', harness):
            reads = runner.floor_inputs(Path('unused'), Path('unused'))[3]
        self.assertEqual((runner.floor_manifest_problems(reads), spec['started']), ([], 1))

        def replaced(path, by):
            path.unlink()
            by(path)
        # Each case: the starts it makes, as (argv, cwd, env), from a fresh layout's pinned copies,
        # rebuild directory and command, the edit made to that layout before the floor's assembly
        # opens, and why its start is refused. A link made inside the assembly is refused as it is
        # made; one laid out before it reaches the start's own checks.
        own = lambda pinned, directory, spec: (spec['argv'], spec['cwd'], None)  # noqa: E731
        command, copy = 'not the rebuild\'s own patch command', 'the patch input is not the scratch copy'
        cases = {
            'the living patch as input': (
                lambda p, d, s: (([*s['argv'][:-1], str(living)], s['cwd'], None),), None, command),
            'B1\'s patch bytes outside the scratch as input': (
                lambda p, d, s: (([*s['argv'][:-1], str(outside)], s['cwd'], None),), None, command),
            'the scratch copy changed': (None, lambda p, d: (d / 'floor.patch').write_bytes(b'changed'), copy),
            'the scratch copy a link to B1\'s bytes': (
                None, lambda p, d: replaced(d / 'floor.patch', lambda path: path.symlink_to(outside)), copy),
            'the scratch copy hard linked': (None, lambda p, d: os.link(d / 'floor.patch', d / 'second'), copy),
            'a link in the tree': (
                None, lambda p, d: replaced(d / 'tree/services/a/A.java',
                                            lambda path: path.symlink_to(p / 'services/a/A.java')),
                'the scratch tree holds a link or special file'),
            'a tree copy changed': (None, lambda p, d: (d / 'tree/services/a/A.java').write_bytes(b'changed'),
                                    'a scratch tree copy is not its pinned upstream bytes'),
            'another file in the tree': (None, lambda p, d: (d / 'tree/services/C.java').write_bytes(b''),
                                         'the scratch tree holds other files'),
            'another working directory': (lambda p, d, s: ((s['argv'], str(d), None),), None, command),
            'another argument': (
                lambda p, d, s: (([s['argv'][0], '--dry-run', *s['argv'][1:]], s['cwd'], None),), None, command),
            'an environment of its own': (lambda p, d, s: ((s['argv'], s['cwd'], dict(os.environ)),), None, command),
            'a second start': (lambda p, d, s: (own(p, d, s), own(p, d, s)), None, 'a second rebuild start'),
            'the patch tool asked its version': (
                lambda p, d, s: (([runner.FLOOR_PATCH_TOOL, '--version'], s['cwd'], None),), None, command),
            'another program': (lambda p, d, s: (([sys.executable, '-c', 'pass'], s['cwd'], None),), None, command),
            'a raw Git process': (lambda p, d, s: ((['git', '-C', str(ROOT), 'show', '%s:%s' % (
                runner.b1.FLOOR, runner.b1.STORE)], None, None),), None, command),
            'the start outside the rebuild': (None, None, 'outside a loader call and the rebuild')}
        for name, (starts, before, why) in cases.items():
            pinned, directory, spec = self.rebuild_layout()
            made = starts(pinned, directory, spec) if starts else (own(pinned, directory, spec),)
            if before:
                before(pinned, directory)
            stand_in = self.rebuilding(spec, *made, window=name != 'the start outside the rebuild')
            with self.subTest(case=name), mock.patch.object(runner, 'floor_candidate', stand_in), \
                    mock.patch.object(runner, 'floor_harness_source', harness):
                with self.assertRaisesRegex(runner.FloorBypass, 'started a process past its loader and rebuild: .*'
                                            + re.escape(why)):
                    runner.floor_inputs(Path('unused'), Path('unused'))
        self.assertEqual((runner._FLOOR_ACTIVE, runner._FLOOR_LOADER, runner._FLOOR_REBUILD, runner._FLOOR_EXEC),
                         ([], [], [], []))
        # Outside the floor's assembly the same starts are no concern of its guard.
        self.assertEqual(runner.subprocess.run([sys.executable, '-c', 'pass']).returncode, 0)

    def test_the_rebuild_reads_only_its_checked_inputs(self):
        harness = self.floor_stand_ins()[1]
        elsewhere = scratch(self) / 'elsewhere'
        elsewhere.write_bytes(b'x')
        # Control: in the rebuild, reading a pinned copy and below the scratch, then its own start.
        pinned, directory, spec = self.rebuild_layout()

        def reads_admitted():
            (pinned / 'services/a/A.java').read_bytes()
            (directory / 'tree/services/a/A.java').read_bytes()
            sorted(directory.rglob('*'))
        stand_in = self.rebuilding(spec, (spec['argv'], spec['cwd'], None), before=reads_admitted)
        with mock.patch.object(runner, 'floor_candidate', stand_in), \
                mock.patch.object(runner, 'floor_harness_source', harness):
            runner.floor_inputs(Path('unused'), Path('unused'))
        def below_a_descriptor():
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.close(os.open('floor.patch', os.O_RDONLY, dir_fd=descriptor))
            finally:
                os.close(descriptor)
        # Any other path read raises: a working tree file, a file elsewhere, a pinned copy's
        # directory listed, a path relative to a directory descriptor, or a scratch file read
        # outside the rebuild's window.
        for name, read, window in (('a working tree file', lambda: (ROOT / 'AGENTS.md').read_bytes(), True),
                                   ('a file elsewhere', lambda: elsewhere.read_bytes(), True),
                                   ('the pinned directory listed', lambda: os.listdir(pinned), True),
                                   ('a path relative to a descriptor', below_a_descriptor, True),
                                   ('the scratch outside the window', lambda: (directory / 'floor.patch').read_bytes(),
                                    False)):
            pinned, directory, spec = self.rebuild_layout()
            stand_in = self.rebuilding(spec, before=read, window=window)
            with self.subTest(case=name), mock.patch.object(runner, 'floor_candidate', stand_in), \
                    mock.patch.object(runner, 'floor_harness_source', harness):
                with self.assertRaisesRegex(runner.FloorBypass, 'read a path past its loader and rebuild'):
                    runner.floor_inputs(Path('unused'), Path('unused'))
        # No input comes from the network: a socket, or a request, raises in the rebuild too. The
        # modules load first, outside the floor's assembly.
        import socket
        import urllib.request
        for name, reach in (('a socket', lambda: socket.socket().close()),
                            ('a request', lambda: urllib.request.urlopen('http://127.0.0.1:9/', timeout=1))):
            pinned, directory, spec = self.rebuild_layout()
            with self.subTest(case=name), \
                    mock.patch.object(runner, 'floor_candidate', self.rebuilding(spec, before=reach)), \
                    mock.patch.object(runner, 'floor_harness_source', harness):
                with self.assertRaisesRegex(runner.FloorBypass, 'reached the network'):
                    runner.floor_inputs(Path('unused'), Path('unused'))
        self.assertEqual((runner._FLOOR_ACTIVE, runner._FLOOR_LOADER, runner._FLOOR_REBUILD), ([], [], []))

    def test_git_starts_are_the_readers_own_commands(self):
        candidate, harness = self.floor_stand_ins()
        real = runner.subprocess.run

        def rewritten(change):
            def run(argv, *args, **kwargs):
                if argv and argv[0] == 'git':
                    argv, kwargs = change(list(argv), dict(kwargs))
                return real(argv, *args, **kwargs)
            return run
        # Inside a loader call, after its Python call was attributed, the Git start itself must be
        # the reader's own command and environment for that call, once.
        other = str(scratch(self))
        cases = {'another Git command': lambda argv, kwargs: (argv[:3] + ['cat-file', '-p'] + argv[4:], kwargs),
                 'another repository': lambda argv, kwargs: (argv[:2] + [other] + argv[3:], kwargs),
                 'another environment': lambda argv, kwargs: (
                     argv, dict(kwargs, env=dict(kwargs['env'], GIT_DIR=other))),
                 'a working directory': lambda argv, kwargs: (argv, dict(kwargs, cwd=str(ROOT)))}
        for name, change in cases.items():
            with self.subTest(case=name), mock.patch.object(runner, 'floor_candidate', candidate), \
                    mock.patch.object(runner, 'floor_harness_source', harness), \
                    mock.patch.object(runner.subprocess, 'run', rewritten(change)):
                with self.assertRaisesRegex(runner.FloorBypass, 'not the Git reader\'s own command for show %s'
                                            % re.escape(runner.b1.NATIVE_PATCH)):
                    runner.floor_inputs(Path('unused'), Path('unused'))

        def twice(argv, *args, **kwargs):
            if argv and argv[0] == 'git':
                real(argv, *args, **kwargs)
            return real(argv, *args, **kwargs)
        with mock.patch.object(runner, 'floor_candidate', candidate), \
                mock.patch.object(runner, 'floor_harness_source', harness), \
                mock.patch.object(runner.subprocess, 'run', twice):
            with self.assertRaisesRegex(runner.FloorBypass, 'a second Git start in one loader call'):
                runner.floor_inputs(Path('unused'), Path('unused'))
        # The reader's own commands, the control, pass: one start per loader call.
        with mock.patch.object(runner, 'floor_candidate', candidate), \
                mock.patch.object(runner, 'floor_harness_source', harness):
            reads = runner.floor_inputs(Path('unused'), Path('unused'))[3]
        self.assertEqual(runner.floor_manifest_problems(reads), [])
        self.assertEqual(runner.floor_git_command('show', 'x')[0],
                         ['git', '-C', str(ROOT), 'show', '%s:x' % runner.b1.FLOOR])
        self.assertEqual(runner.floor_git_command('list', 'y/')[0],
                         ['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', runner.b1.FLOOR, 'y/'])

    def repository_copy(self):
        """A scratch repository standing in for this one, so that no test writes into the real
        working tree: its Git directory borrows the repository's objects, the only thing the floor
        reads from a repository, and its root holds a working tree file with B1's patch bytes,
        which no floor input names. Returns its root, that file, and a patch of b1's ROOT and
        CLOSED_ROOT under which the floor's checks run against that root."""
        copy = scratch(self) / 'repository'
        objects = runner.subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--git-path', 'objects'],
                                        capture_output=True, text=True, check=True).stdout.strip()
        runner.subprocess.run(['git', 'init', '--quiet', str(copy)], capture_output=True, check=True)
        (copy / '.git/objects/info/alternates').write_text('%s\n' % (ROOT / objects))
        living = copy / 'planted-living-floor.patch'
        living.write_bytes(runner.b1.floor_bytes(runner.b1.NATIVE_PATCH))
        return copy, living, mock.patch.multiple(runner.b1, ROOT=copy, CLOSED_ROOT=copy)

    @staticmethod
    def brought_in(living):
        """Edits that bring a file into a rebuild's scratch directory and read it there: a hard
        link to it, the file renamed into it and back, and a symbolic link to it, each with the
        audit event that makes the name."""
        def linked(directory):
            os.link(living, directory / 'staging')
            return (directory / 'staging').read_bytes()

        def renamed(directory):
            os.rename(living, directory / 'moved')
            try:
                return (directory / 'moved').read_bytes()
            finally:
                os.rename(directory / 'moved', living)

        def symlinked(directory):
            os.symlink(living, directory / 'pointer')
            return (directory / 'pointer').read_bytes()
        return (('hard linked into the scratch', linked, 'os.link'), ('renamed into the scratch', renamed, 'os.rename'),
                ('a symbolic link to it in the scratch', symlinked, 'os.symlink'))

    def test_nothing_is_linked_or_renamed_while_the_inputs_are_assembled(self):
        candidate, harness = self.floor_stand_ins()
        # The floor's checks run against a scratch repository whose working tree holds B1's bytes.
        copy, living, against_copy = self.repository_copy()
        held = living.read_bytes()
        with against_copy:
            # Control: the honest rebuild, its own start, passes.
            pinned, directory, spec = self.rebuild_layout()
            stand_in = self.rebuilding(spec, (spec['argv'], spec['cwd'], None))
            with mock.patch.object(runner, 'floor_candidate', stand_in), \
                    mock.patch.object(runner, 'floor_harness_source', harness):
                reads = runner.floor_inputs(Path('unused'), Path('unused'))[3]
            self.assertEqual((runner.floor_manifest_problems(reads), spec['started']), ([], 1))
            # A working tree file holding B1's bytes, hard linked or renamed into the rebuild's
            # scratch and read there before the rebuild's own start, or a symbolic link to it made
            # there, is refused as the name is made: nothing is read, and the file stays put.
            for name, edit, event in self.brought_in(living):
                pinned, directory, spec = self.rebuild_layout()
                before = (lambda edit=edit, directory=directory: edit(directory))
                stand_in = self.rebuilding(spec, (spec['argv'], spec['cwd'], None), before=before)
                with self.subTest(case=name), mock.patch.object(runner, 'floor_candidate', stand_in), \
                        mock.patch.object(runner, 'floor_harness_source', harness):
                    with self.assertRaisesRegex(runner.FloorBypass, 'made a link or renamed a path while its '
                                                'inputs are assembled: ' + re.escape(event)):
                        runner.floor_inputs(Path('unused'), Path('unused'))
                    self.assertEqual((living.read_bytes(), spec['started']), (held, 0))
                    self.assertEqual(sorted(path.name for path in directory.iterdir()), ['floor.patch', 'tree'])
        # The same holds while the inputs are assembled outside the rebuild: a rename in the sealed
        # assembly is refused too.
        elsewhere = scratch(self)
        (elsewhere / 'a').write_bytes(b'x')

        def renaming(settings):
            os.rename(elsewhere / 'a', elsewhere / 'b')
            return harness(settings)
        with mock.patch.object(runner, 'floor_candidate', candidate), \
                mock.patch.object(runner, 'floor_harness_source', renaming):
            with self.assertRaisesRegex(runner.FloorBypass, 'made a link or renamed a path .*: os.rename'):
                runner.floor_inputs(Path('unused'), Path('unused'))
        self.assertEqual(sorted(path.name for path in elsewhere.iterdir()), ['a'])
        self.assertEqual((runner._FLOOR_ACTIVE, runner._FLOOR_LOADER, runner._FLOOR_REBUILD, runner._FLOOR_EXEC),
                         ([], [], [], []))
        # Outside the floor's assembly the same names are no concern of its guard.
        os.link(elsewhere / 'a', elsewhere / 'c')
        self.assertEqual((elsewhere / 'c').read_bytes(), b'x')

    def test_an_exec_is_admitted_only_as_its_starts_very_next_event(self):
        harness = self.floor_stand_ins()[1]
        argv, env = runner.floor_git_command('show', runner.b1.NATIVE_PATCH)
        base, here = scratch(self), os.getcwd()
        empty = base / 'empty'
        empty.mkdir()
        other = {'PATH': os.environ['PATH'], 'GIT_DIR': str(base / 'no-such-repository')}
        # The child opens its own output, which is no path this process opens.
        quiet = [(os.POSIX_SPAWN_OPEN, descriptor, os.devnull, os.O_WRONLY, 0) for descriptor in (1, 2)]

        def spawned(environment, directory=None):
            """A raw posix_spawnp of Git with the reader's own argv for B1's patch."""
            if directory:
                os.chdir(directory)
            try:
                os.waitpid(os.posix_spawnp('git', argv, environment, file_actions=quiet), 0)
            finally:
                os.chdir(here)

        def later(environment, directory=None, between=None):
            """In the rebuild, the floor loader's admitted Git start for B1's patch, then between,
            then that raw spawn from directory."""
            def edit(scratch_directory, spec):
                runner.b1.floor_bytes(runner.b1.NATIVE_PATCH)
                if between:
                    between(scratch_directory)
                spawned(environment, directory)
            return edit

        def raised(environment=None, directory=None):
            """The rebuild's own start and an exec of it, raised by hand as subprocess raises them
            for a start it runs with posix_spawn: the start, then at once the exec, from directory,
            the start's own working directory unless named. No start of the floor raises an exec
            today."""
            def edit(scratch_directory, spec):
                os.chdir(directory or spec['cwd'])
                try:
                    sys.audit('subprocess.Popen', runner.FLOOR_PATCH_TOOL, spec['argv'], spec['cwd'], None)
                    sys.audit('os.posix_spawn', runner.FLOOR_PATCH_TOOL, spec['argv'], environment)
                finally:
                    os.chdir(here)
            return edit
        # Controls: the honest rebuild with its own start, and that start with its own exec as the
        # very next event, in its environment and working directory.
        for name, starts, edit in (('the honest rebuild', 1, None), ('its own exec as the next event', 0, raised())):
            pinned, directory, spec = self.rebuild_layout()
            before = edit and (lambda edit=edit, directory=directory, spec=spec: edit(directory, spec))
            stand_in = self.rebuilding(spec, *[(spec['argv'], spec['cwd'], None)] * starts, before=before)
            with self.subTest(control=name), mock.patch.object(runner, 'floor_candidate', stand_in), \
                    mock.patch.object(runner, 'floor_harness_source', harness):
                reads = runner.floor_inputs(Path('unused'), Path('unused'))[3]
                self.assertEqual((runner.floor_manifest_problems(reads), spec['started']), ([], 1))
        # A later raw spawn with the argv of the reader's start just admitted, from another
        # environment and directory, or with its own environment and directory after another event,
        # and the rebuild's exec as the next event but with another environment or directory: each
        # is refused, and starts nothing.
        cases = {'a later spawn, another environment and directory': later(other, empty),
                 'a later spawn, the same command after another event': later(
                     env, between=lambda scratch_directory: (scratch_directory / 'floor.patch').read_bytes()),
                 'the next exec with another environment': raised(other),
                 'the next exec from another directory': raised(directory=empty)}
        for name, edit in cases.items():
            pinned, directory, spec = self.rebuild_layout()
            before = (lambda edit=edit, directory=directory, spec=spec: edit(directory, spec))
            stand_in = self.rebuilding(spec, before=before)
            with self.subTest(case=name), mock.patch.object(runner, 'floor_candidate', stand_in), \
                    mock.patch.object(runner, 'floor_harness_source', harness):
                with self.assertRaisesRegex(runner.FloorBypass, 'started a process past its loader and rebuild: '
                                            '.*not the exec of the start just admitted'):
                    runner.floor_inputs(Path('unused'), Path('unused'))
        self.assertEqual(os.getcwd(), here)
        self.assertEqual((runner._FLOOR_ACTIVE, runner._FLOOR_LOADER, runner._FLOOR_REBUILD, runner._FLOOR_EXEC),
                         ([], [], [], []))

    def test_the_floor_compiles_exactly_the_bytes_its_loader_checked(self):
        sources = runner.floor_compile_sources()
        self.assertEqual(len(sources), 50)
        self.assertEqual(sources['stubs/android/util/Log.java'],
                         runner.b1.FLOOR_PLATFORM + 'native_principal_xml_stubs/android/util/Log.java')
        digests = {name: runner.b1.FLOOR_SHA256[path] for name, path in sources.items()}
        digests['tests/NativeHistoryHarness.java'] = runner.FLOOR_HARNESS_SHA256
        self.assertEqual(runner.floor_compile_problems(digests), [])
        for change, expected in (({'framework/NativeIdentityStore.java': runner.sha(b'changed')},
                                  'framework/NativeIdentityStore.java'),
                                 ({'tests/NativeHistoryHarness.java': '0' * 64}, 'tests/NativeHistoryHarness.java'),
                                 ({'tests/Extra.java': '0' * 64}, 'tests/Extra.java')):
            with self.subTest(expected=expected):
                self.assertIn(expected, ' '.join(runner.floor_compile_problems(dict(digests, **change))))
        without = {name: digest for name, digest in digests.items() if name != 'fixtures/AppIdSettingMap.java'}
        self.assertIn('fixtures/AppIdSettingMap.java', ' '.join(runner.floor_compile_problems(without)))
        # The stand-in assembly compiles the pinned bytes; only its stand-in harness differs.
        candidate, harness = self.floor_stand_ins()
        product = runner.floor_product_sources
        with mock.patch.object(runner, 'floor_candidate', candidate), \
                mock.patch.object(runner, 'floor_harness_source', harness):
            files = runner.floor_inputs(Path('unused'), Path('unused'))[2]
        self.assertEqual(runner.floor_compile_problems({name: runner.sha(data) for name, data in files.items()}),
                         ['the floor compile set differs from its pinned inputs: '
                          "['tests/NativeHistoryHarness.java']"])
        # Bytes changed after the loader checked them, with no read past it, are refused here.

        def changed():
            files = product()
            files['framework/NativeIdentityStore.java'] = runner.b1.floor_bytes(runner.b1.STORE) + b'// changed\n'
            return files
        with mock.patch.object(runner, 'floor_candidate', candidate), \
                mock.patch.object(runner, 'floor_harness_source', harness), \
                mock.patch.object(runner, 'floor_product_sources', changed):
            files, reads = runner.floor_inputs(Path('unused'), Path('unused'))[2:]
        self.assertEqual(runner.floor_manifest_problems(reads), [])
        self.assertIn('framework/NativeIdentityStore.java',
                      ' '.join(runner.floor_compile_problems({name: runner.sha(data) for name, data in files.items()})))
        # The floor phase compiles exactly the pinned bytes only, and checks what the compiler got.
        source = inspect.getsource(runner.floor_phase)
        self.assertIn("floor_compile_problems({name: sha(data) for name, data in files.items()})", source)
        self.assertIn("floor_compile_problems(built['inputs'])", source)

    def test_wrong_models_differ_from_the_floor_compile_set(self):
        self.assertEqual(runner.compile_differences({'a': b'1', 'b': b'2'}, {'a': b'1', 'b': b'2'}), [])
        self.assertEqual(runner.compile_differences({'a': b'1', 'b': b'2'}, {'a': b'1', 'b': b'3', 'c': b''}),
                         ['b', 'c'])
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2b']['floor']
        # The current sources' reader differs from the floor in the store helper's comments, the
        # facade's default and the reader check's comments and closing line, nothing else.
        self.assertEqual(predicted['differing_from_previous'], ['framework/NativeIdentityStore.java',
                                                              'stubs/com/android/server/pm/Settings.java',
                                                              'tests/NativeLifecycleReaderCheck.java'])
        # B2's own change moves the store helper's comments and the facade's default.
        self.assertNotEqual(runner.b1.floor_bytes(runner.b1.STORE), (ROOT / runner.STORE).read_bytes())
        self.assertNotEqual(runner.b1.floor_bytes(runner.FACADE), (ROOT / runner.FACADE).read_bytes())
        # The 24bfb6a model's pinned half differs in its product, stubs, supports, harness, checks.
        self.assertEqual(predicted['differing_from_24bf'], 17)

    def test_the_guest_input_hook_fails_closed(self):
        # Every guest input has its floor and production reads, each a prediction of every check.
        self.assertEqual(len(runner.GUEST_INPUTS), 35)
        self.assertEqual(runner.guest_input_problems(), [])
        reads = runner.guest_section()['reads']
        found = runner.guest_input_problems(runner.GUEST_INPUTS + ('suspended-by-user',))
        self.assertEqual(len(found), 1)
        for check in runner.GUEST_INPUT_CHECKS:
            self.assertIn(check, found[0])
        self.assertIn("['suspended-by-user']", found[0])
        with mock.patch.object(runner, 'GUEST_INPUTS', runner.GUEST_INPUTS + ('suspended-by-user',)):
            self.assertEqual(runner.guest_input_problems(), found)
        # A reader or a check missing from one input's predictions is no read either, and a
        # prediction of an input that does not exist is refused.
        for change in (lambda value: value['v2-grant'].pop('floor'),
                       lambda value: value['v2-grant']['production'].pop('boot facts'),
                       lambda value: value['v2-grant']['floor'].update(extra=[])):
            broken = json.loads(json.dumps(reads))
            change(broken)
            self.assertIn("B2 guest inputs without reads: ['v2-grant']",
                          runner.guest_input_problems(predicted=broken)[0])
        broken = dict(reads, **{'unknown-input': reads['v2-grant']})
        self.assertEqual(runner.guest_input_problems(predicted=broken),
                         ["reads of guest inputs that do not exist: ['unknown-input']"])
        self.assertIn('guest_input_problems()', inspect.getsource(runner.source_checks))
        self.assertIn('guest_input_problems(', inspect.getsource(runner.floor_phase))
        self.assertIn('guest_floor(', inspect.getsource(runner.floor_phase))
        # Checkpoint 2b's record of the hook, before any input: the same checks.
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2b']['guest_inputs']
        self.assertEqual((predicted['inputs'], tuple(predicted['checks'])), (0, runner.GUEST_INPUT_CHECKS))

    def test_the_layout_footprint_sees_bytes_and_files_not_times(self):
        emitted = scratch(self) / 'emitted'
        (emitted / 'a' / 'store').mkdir(parents=True)
        record = emitted / 'a' / 'store' / 'record.bin'
        record.write_bytes(b'x')
        before = runner.layout_footprint(emitted)
        self.assertEqual(sorted(before), ['a', 'a/store', 'a/store/record.bin'])
        # Aged, as each check ages the store it reads: unchanged.
        os.utime(record, (0, 86400))
        state = {}
        self.assertEqual(runner.footprint_problems(emitted, before, 'floor', state), [])
        self.assertEqual(state, {'unchanged after floor': True})
        # Changed bytes, a replaced file and an added file are each a change.
        record.write_bytes(b'y')
        self.assertEqual(runner.footprint_problems(emitted, before, 'floor', state),
                         ['the emitted layouts changed during the floor step'])
        self.assertEqual(state, {'unchanged after floor': False})
        record.write_bytes(b'x')
        self.assertEqual(runner.layout_footprint(emitted), before)
        replacement = emitted / 'a' / 'store' / 'replacement'
        replacement.write_bytes(b'x')
        os.replace(replacement, record)
        self.assertNotEqual(runner.layout_footprint(emitted), before)
        (emitted / 'a' / 'extra').write_bytes(b'')
        self.assertEqual(len(runner.layout_footprint(emitted)), 4)
        self.assertEqual(runner.layout_footprint(emitted / 'absent'), {})

    def test_the_floor_predictions_are_consistent(self):
        predictions = json.loads(runner.PREDICTIONS.read_text())
        predicted, current = predictions['b2_checkpoint_2b'], predictions['b2_checkpoint_3a']
        floor = predicted['floor']
        self.assertEqual(runner.floor_prediction_problems(predicted, current), [])
        # Without the current checkpoint, the floor's own record names the phases before the guests
        # step.
        self.assertEqual(runner.floor_prediction_problems(predicted),
                         ['the predicted phases or step labels differ from the runner'])
        readers = predictions['p5_checkpoint_2']['readers']
        self.assertEqual((floor['classes'], floor['outside_user_0']),
                         (readers['classes'], readers['outside_user_0_under_v3']))
        versioned = sum(count for klass, count in floor['classes'].items() if klass in runner.VERSION_TWO_CLASSES)
        self.assertEqual(versioned, 165)
        self.assertEqual(floor['failed'], {'run': 0, 'swap control': len(floor['swap_control']),
                                           'production expectations': versioned, 'wrong model': versioned})
        self.assertEqual(floor['swap_control_fails'], len(floor['swap_control']))
        self.assertEqual(set(floor['cases'].values()), {len(runner.LAYOUT_NAMES) + 1})
        self.assertEqual((floor['settings_sha256'], floor['harness_sha256'], floor['reads'], floor['git_reads']),
                         (runner.b1.FLOOR_SETTINGS_SHA256, runner.FLOOR_HARNESS_SHA256, len(runner.b1.FLOOR_SHA256),
                          len(runner.b1.FLOOR_SHA256)))
        # Each Git object read and tree listing is a floor loader call's own, one for one.
        self.assertEqual(floor['calls'], {'floor': 95, 'git': 95, 'trees': 2, 'listed': 2})
        self.assertEqual(floor['listed'], [runner.b1.FLOOR_PLATFORM + name + '/'
                                           for name in runner.b1.FLOOR_STUB_DIRECTORIES])
        self.assertEqual(predicted['run_label'], runner.b1.FLOOR_RUN_LABELS[0])
        # Each break of the predictions is refused.
        for path, value, expected in (
                (('floor', 'swap_control', 'state-disposing'), 'footprint', 'does not give each reader class once'),
                (('floor', 'swap_control', 'no-such-layout'), 'admitted', 'floor swap control no-such-layout'),
                (('floor', 'format'), 'V3', 'another format'),
                (('floor', 'reads'), 72, 'input count'),
                (('floor', 'calls', 'git'), 96, 'Git calls other than the floor loader'),
                (('floor', 'calls', 'listed'), 3, 'Git calls other than the floor loader'),
                (('floor', 'classes', 'nothing'), 13, 'do not cover the layouts'),
                (('phases',), list(runner.PHASES[:-1]), 'phases or step labels'),
                (('phases',), list(runner.PHASES), 'phases or step labels')):
            broken = json.loads(json.dumps(predicted))
            target = broken
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertIn(expected, ' '.join(runner.floor_prediction_problems(broken, current)))
        for value in (list(runner.PHASES[:-1]), [phase for phase in runner.PHASES if phase != 'guests']):
            with self.subTest(current=value):
                self.assertIn('the predicted phases or step labels differ from the runner',
                              runner.floor_prediction_problems(predicted, dict(current, phases=value)))

    def test_the_floor_from_its_git_objects(self):
        if not PINNED:
            self.skipTest('NOT RUN: ANDRIX_PINNED_FRAMEWORK does not name the pinned framework copies')
        pinned = Path(PINNED)
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2b']['floor']
        settings, outputs, files, reads = runner.floor_inputs(pinned, scratch(self) / 'candidate')
        self.assertEqual(runner.floor_manifest_problems(reads), [])
        self.assertEqual((runner.sha(settings.encode()), len(files), len(set(reads['floor']))),
                         (predicted['settings_sha256'], predicted['files'], predicted['reads']))
        self.assertEqual(runner.sha(files['tests/NativeHistoryHarness.java']), predicted['harness_sha256'])
        self.assertEqual(runner.floor_text_checks(settings), [])
        self.assertEqual(outputs, {row['path']: row['candidate_sha256'] for row in runner.floor_profile()['files']})
        self.assertEqual(runner.compile_differences(files, runner.reader_files(runner.candidate(pinned))),
                         predicted['differing_from_previous'])
        # Every call of the real assembly is the loader's, and it compiles exactly the pinned bytes.
        self.assertEqual({key: len(reads[key]) for key in ('floor', 'git', 'trees', 'listed')}, predicted['calls'])
        self.assertEqual(reads['outside'], [])
        self.assertEqual(runner.floor_compile_problems({name: runner.sha(data) for name, data in files.items()}), [])
        # On the real assembly, the store helper read again past the loader and changed is refused
        # at that read, and the same change through the loader by the compile check.
        product = runner.floor_product_sources

        def past_the_loader():
            return dict(product(), **{'framework/NativeIdentityStore.java':
                                      runner.b1.git_bytes(runner.b1.FLOOR, runner.b1.STORE) + b'// changed\n'})

        def through_the_loader():
            return dict(product(), **{'framework/NativeIdentityStore.java':
                                      runner.b1.floor_bytes(runner.b1.STORE) + b'// changed\n'})
        with mock.patch.object(runner, 'floor_product_sources', past_the_loader):
            with self.assertRaisesRegex(runner.FloorBypass, 'past its loader: show %s %s' % (runner.b1.FLOOR,
                                                                                           runner.b1.STORE)):
                runner.floor_inputs(pinned, scratch(self) / 'past-the-loader')
        with mock.patch.object(runner, 'floor_product_sources', through_the_loader):
            changed, reads = runner.floor_inputs(pinned, scratch(self) / 'through-the-loader')[2:]
        self.assertEqual(runner.floor_manifest_problems(reads), [])
        # The real rebuild's patch start, redirected, is refused as it starts, while the normal
        # pinned rebuild above is its control: its input the living patch in the working tree, or
        # B1's patch bytes outside the scratch, another working directory, or another argument.
        outside = scratch(self) / 'floor.patch'
        outside.write_bytes(runner.b1.floor_bytes(runner.b1.NATIVE_PATCH))
        real = runner.subprocess.run

        def redirected(change):
            def run(argv, *args, **kwargs):
                if argv and argv[0] == runner.FLOOR_PATCH_TOOL:
                    argv, kwargs = change(list(argv), dict(kwargs))
                return real(argv, *args, **kwargs)
            return run
        for name, change in (
                ('the living patch as input',
                 lambda argv, kwargs: (argv[:-1] + [str(ROOT / runner.b1.NATIVE_PATCH)], kwargs)),
                ('B1\'s patch bytes outside the scratch', lambda argv, kwargs: (argv[:-1] + [str(outside)], kwargs)),
                ('another working directory', lambda argv, kwargs: (argv, dict(kwargs, cwd=str(outside.parent)))),
                ('another argument', lambda argv, kwargs: (argv[:1] + ['--dry-run'] + argv[1:], kwargs))):
            with self.subTest(case=name), mock.patch.object(runner.subprocess, 'run', redirected(change)):
                with self.assertRaisesRegex(runner.FloorBypass, 'not the rebuild\'s own patch command'):
                    runner.floor_inputs(pinned, scratch(self) / 'redirected')
        self.assertEqual(runner.floor_compile_problems({name: runner.sha(data) for name, data in changed.items()}),
                         ['the floor compile set differs from its pinned inputs: '
                          "['framework/NativeIdentityStore.java']"])
        # On the real rebuild too, the normal pinned rebuild above its control: a later raw spawn of
        # Git with the argv of the reader's last start, for B1's profile, from another environment
        # and directory, is refused.
        rebuild, empty = runner.b1.floor_patch_outputs, scratch(self)
        other = {'PATH': os.environ['PATH'], 'GIT_DIR': str(empty / 'no-such-repository')}
        profile_argv = runner.floor_git_command('show', runner.b1.NATIVE_PROFILE)[0]

        def spawned(directory):
            here = os.getcwd()
            os.chdir(empty)
            try:
                os.waitpid(os.posix_spawnp('git', profile_argv, other, file_actions=[
                    (os.POSIX_SPAWN_OPEN, descriptor, os.devnull, os.O_WRONLY, 0) for descriptor in (1, 2)]), 0)
            finally:
                os.chdir(here)

        def edited(edit):
            """b1's own rebuild step, after an edit made inside it."""
            def patch_outputs(pinned_copies, value, directory):
                edit(directory)
                return rebuild(pinned_copies, value, directory)
            return mock.patch.object(runner.b1, 'floor_patch_outputs', patch_outputs)
        with self.subTest(case='a later raw spawn from another environment and directory'), edited(spawned):
            with self.assertRaisesRegex(runner.FloorBypass, 'not the exec of the start just admitted'):
                runner.floor_inputs(pinned, scratch(self) / 'spawned')
        # Against a scratch repository whose working tree holds B1's patch bytes, the real rebuild
        # passes, and that file, brought into the rebuild's scratch and read there, is refused as
        # its name is made.
        copy, living, against_copy = self.repository_copy()
        with against_copy:
            reads = runner.floor_inputs(pinned, scratch(self) / 'in-the-copy')[3]
            self.assertEqual((runner.floor_manifest_problems(reads), reads['outside']), ([], []))
            self.assertEqual({key: len(reads[key]) for key in ('floor', 'git', 'trees', 'listed')}, predicted['calls'])
            for name, edit, event in self.brought_in(living):
                with self.subTest(case=name), edited(edit):
                    with self.assertRaisesRegex(runner.FloorBypass, 'made a link or renamed a path while its '
                                                'inputs are assembled: ' + re.escape(event)):
                        runner.floor_inputs(pinned, scratch(self) / 'brought-in')
        self.assertEqual(living.read_bytes(), runner.b1.floor_bytes(runner.b1.NATIVE_PATCH))
        # A wrong patch fails the ten candidate checks, another format the boot read check, and a
        # harness that is not the pinned one is refused.
        current, original = runner.integration.PATCH.read_bytes(), runner.b1.git_bytes

        def wrong(revision, path):
            return current if path == runner.b1.NATIVE_PATCH else original(revision, path)
        with mock.patch.object(runner.b1, 'git_bytes', wrong), \
                mock.patch.dict(runner.b1.FLOOR_SHA256, {runner.b1.NATIVE_PATCH: runner.sha(current)}):
            with self.assertRaisesRegex(ValueError, 'floor candidate drift: ' + runner.integration.SETTINGS):
                runner.floor_candidate(pinned, scratch(self) / 'wrong-patch')
        with mock.patch.object(runner, 'FLOOR_FORMAT', 'V3'):
            with self.assertRaisesRegex(ValueError, 'floor candidate: the floor candidate constructs'):
                runner.floor_candidate(pinned, scratch(self) / 'wrong-format')
        # The rebuild needs fresh scratch outside the repository, and refuses the working tree.
        for place in (ROOT / 'floor-scratch', scratch(self)):
            with self.subTest(place=place), self.assertRaisesRegex(ValueError, 'floor scratch is not fresh'):
                runner.floor_candidate(pinned, place)
        self.assertFalse((ROOT / 'floor-scratch').exists())
        with mock.patch.object(runner, 'FLOOR_HARNESS_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'floor harness drift'):
                runner.floor_model_files(settings)


def rendered(rows):
    """A raw diagnostic with these predicted rows, written here from the documented schema alone:
    the scalars in their order with an allocator search start, the counts, holds, slot rows and
    names."""
    fields = dict(item.split('=') for item in rows['fields'])
    encode = lambda name: base64.b64encode(name.encode()).decode()
    lines = ['andrix-native-identities-v%d' % rows['schema'], 'live_settings=true', 'authority=not-reported',
             'counter_known=' + fields['counter_known'], 'cached_header=' + fields['cached_header'],
             'cached_enumeration_complete=' + fields['cached_enumeration_complete'],
             'creation_ready=' + fields['creation_ready'], 'allocator_search_start=10150',
             'unidentified_code=' + fields['unidentified_code'], 'deferred_count=%d' % len(rows['deferred'])]
    if rows['schema'] == 3:
        lines.append('slot_count=%d' % len(rows['holds']))
    for hold in rows['holds']:
        app, status, pinned, kind, name = hold.split(' ')
        lines.append('hold=%s\t%s\t%s\t%s\t%s' % (app, status, str(pinned == 'pinned').lower(), kind,
                                                  '' if name == '-' else encode(name)))
    for slot in rows.get('slots', []):
        lines.append('slot=' + '\t'.join(slot.split(' ')))
    lines += ['deferred=' + encode(name) for name in rows['deferred']]
    return '\n'.join(lines) + '\n'


def guest_line(name, reading):
    """The line a guest check prints for this reading."""
    value = {'lifecycle': reading['lifecycle'], 'pins': reading['pin phase'], 'deferred': reading['deferred set'],
             'scan': reading['scan outcome'], 'boot_facts': reading['boot facts'],
             'dump': rendered(reading['schema 3 rows'])}
    return 'GUEST %s %s' % (name, json.dumps(value, separators=(',', ':')))


class LifecycleGuestInputTests(unittest.TestCase):
    """The B2 guest inputs: their modes and coverage, both readers' exact predictions with their
    swap and cross controls, the comparison of readings with predictions, the independent prefix
    decoder and the largest record's arithmetic. The JVM reads run in the guarded run's guests and
    floor steps."""

    def test_the_inputs_are_every_generator_mode_with_the_lost_mapping(self):
        observe = runner.lab.observer()
        self.assertEqual(runner.GUEST_MODES, observe.LIFECYCLE_MODES)
        self.assertEqual(len(runner.GUEST_MODES), 33)
        self.assertEqual(runner.GUEST_INPUTS, ('empty-v1',) + runner.GUEST_MODES + ('v2-slot-mapping-lost',))
        self.assertEqual(runner.GUEST_INPUT_MODES['v2-slot-mapping-lost'], ('v2-slot', 'lost'))
        self.assertEqual({mapping for name, (mode, mapping) in runner.GUEST_INPUT_MODES.items()
                          if name != 'v2-slot-mapping-lost'}, {'mapped'})
        self.assertEqual(runner.GUEST_SUBJECT, observe.SUBJECT)
        self.assertEqual(dict(runner.GUEST_NAMES)['maximum'], runner.lab.MAXIMUM)
        self.assertEqual(len(runner.lab.MAXIMUM), 255)
        # The subject's certificate is the generator's signer, and the store holds the subject's app
        # ID in every layout but the empty store, so the boot enumerates its data owner there.
        self.assertEqual(runner.sha(runner.guest_certificate()), observe.FIXTURE_SIGNER)
        lineage, app_id, other_app_id, serial = runner.lab.GUEST_VALUES
        for mode in runner.GUEST_MODES:
            files = runner.lab.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
            self.assertIn(app_id, runner.guest_holds(files), mode)
            self.assertEqual(other_app_id in runner.guest_holds(files), mode in observe.COMPANION_MODES, mode)
        empty = dict.fromkeys(observe.HEADERS, runner.lab.goldens()['EMPTY'])
        self.assertEqual(runner.guest_holds(empty), set())
        self.assertEqual(sorted(runner.guest_files({'a': b''})), ['a', 'tests/%s.java' % runner.GUEST_CHECK])

    def test_every_plan_layout_is_covered(self):
        self.assertEqual(runner.guest_coverage_problems(), [])
        rows = [row for source, row, _ in runner.GUEST_COVERAGE if source == 'plan']
        self.assertEqual(len(rows), 14)
        reduced = tuple((source, row, tuple(name for name in names if name != 'lift-v1'))
                        for source, row, names in runner.GUEST_COVERAGE)
        with mock.patch.object(runner, 'GUEST_COVERAGE', reduced):
            self.assertIn("guest coverage differs from the inputs: ['lift-v1']", runner.guest_coverage_problems())
        with mock.patch.object(runner, 'GUEST_COVERAGE', runner.GUEST_COVERAGE + (
                ('plan', 'a layout the plan never names', ('v2-slot',)),)):
            self.assertIn('guest coverage row not in its source: a layout the plan never names',
                          runner.guest_coverage_problems())

    def test_the_predictions_and_their_controls_are_consistent(self):
        section = runner.guest_section()
        self.assertEqual(runner.guest_prediction_problems(section), [])
        reads = section['reads']
        # The readers differ beyond the schema on 26 inputs and read the other 9 alike.
        alike = [name for name in runner.GUEST_INPUTS if name not in section['cross_control_fails']]
        self.assertEqual(alike, ['empty-v1', 'retiring-v1', 'eligible-v1', 'releasing-without-directory',
                                 'v3-prefix-valid', 'v3-prefix-broken', 'reservation', 'reservation-wrong-serial',
                                 'lift-v1'])
        self.assertEqual(len(section['cross_control_fails']), 26)
        for reader in runner.GUEST_READERS:
            self.assertEqual(sorted(section['swap_control'][reader]), sorted(runner.GUEST_INPUTS))
            self.assertEqual({reads[name][reader]['schema 3 rows']['schema'] for name in runner.GUEST_INPUTS},
                             {runner.GUEST_SCHEMAS[reader]})
        # B1 reads every intact version 2 frame of the subject alike, whatever its lifecycle.
        floor = {json.dumps(reads[name]['floor'], sort_keys=True) for name in (
            'v2-slot', 'v2-grant', 'v2-scope-1', 'v2-recovery-hold', 'v2-recovery-scope-2', 'v2-recovery-scope-3',
            'v2-noted', 'v2-retiring', 'v2-retired', 'v2-disposing', 'v2-legacy-suspended')}
        self.assertEqual(len(floor), 1)
        # Each break is refused.
        for change, expected in (
                (lambda value: value['swap_control']['floor'].update({'v2-grant': 'v2-slot'}),
                 'the floor guest swap control keeps the own prediction of [\'v2-grant\']'),
                (lambda value: value['cross_control_fails'].pop(), 'cross control failures'),
                (lambda value: value['values'].update(user_serial=0), 'other values'),
                (lambda value: value['reads']['v2-slot']['floor']['schema 3 rows'].update(schema=3),
                 'the floor guest predictions name schemas [2, 3]'),
                (lambda value: value['inputs'].pop('lift-v1'), 'the predicted guest inputs differ'),
                (lambda value: value['readers']['floor'].update(format='V3'), 'other formats, schemas or labels')):
            broken = json.loads(json.dumps(section))
            change(broken)
            with self.subTest(expected=expected):
                self.assertIn(expected, ' '.join(runner.guest_prediction_problems(broken)))

    def test_readings_are_compared_exactly_with_their_predictions(self):
        reads = runner.guest_section()['reads']
        for reader, schema in runner.GUEST_SCHEMAS.items():
            stdout = '\n'.join(['PASS x'] + [guest_line(name, reads[name][reader]) for name in runner.GUEST_INPUTS])
            readings = runner.guest_readings(stdout, schema)
            self.assertEqual(runner.guest_mismatches(readings, reads, reader), [])
            # Another reader's predictions fail beyond the schema exactly where predicted.
            other = 'floor' if reader == 'production' else 'production'
            self.assertEqual(runner.mismatched_inputs(runner.guest_mismatches(
                readings, runner.guest_other(reads, reader, other), reader, runner.schema_free)),
                sorted(runner.guest_section()['cross_control_fails']))
            # A swap fails each swapped input.
            swaps = runner.guest_section()['swap_control'][reader]
            self.assertEqual(runner.mismatched_inputs(runner.guest_mismatches(
                readings, runner.guest_swapped(reads, reader, swaps), reader)), sorted(swaps))
            # One changed fact fails its input and check alone; a missing reading is named.
            for check, change in (('lifecycle', lambda value: value.update(header='VALID v1 last=2')),
                                  ('pin phase', lambda value: value.append('10149 9 x PENDING')),
                                  ('deferred set', lambda value: value.append('dev.andrix.extra')),
                                  ('scan outcome', lambda value: value.update({'other unmapped': 'protected'})),
                                  ('boot facts', lambda value: value.append('releasing 10148')),
                                  ('schema 3 rows', lambda value: value['deferred'].append('dev.andrix.extra'))):
                changed = json.loads(json.dumps(readings))
                change(changed['lift-v1'][check])
                self.assertEqual(runner.guest_mismatches(changed, reads, reader), [('lift-v1', check)])
            missing = {name: value for name, value in readings.items() if name != 'reservation'}
            self.assertEqual(runner.guest_mismatches(missing, reads, reader), [('reservation', 'no reading')])
        # A diagnostic of the other schema, a repeated reading or unknown facts are refused.
        line = guest_line('lift-v1', reads['lift-v1']['production'])
        repeated = line.replace('"boot_facts":[]', '"boot_facts":[],"boot_facts":[]')
        for stdout, schema in ((line, 2), (line + '\n' + line, 3), (line.replace('"pins"', '"pin"'), 3),
                               (repeated, 3), (guest_line('lift-v1', reads['lift-v1']['floor']), 3)):
            with self.subTest(stdout=stdout[:60], schema=schema), self.assertRaises(ValueError):
                runner.guest_readings(stdout, schema)

    def test_the_independent_prefix_decoder(self):
        lineage, app_id, other_app_id, serial = runner.lab.GUEST_VALUES
        files = {mode: runner.lab.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
                 for mode in ('v3-prefix-valid', 'v3-prefix-broken', 'v2-slot')}
        record = 'slots/%d/record.bin' % app_id
        self.assertEqual(runner.decode_prefix(files['v3-prefix-valid'][record]),
                         {'version': 3, 'app_id': app_id, 'package': runner.GUEST_SUBJECT, 'principals': [1]})
        self.assertIsNone(runner.decode_slot(files['v3-prefix-valid'][record]))
        self.assertIsNone(runner.decode_prefix(files['v3-prefix-broken'][record]))
        self.assertIsNone(runner.decode_prefix(files['v2-slot'][record]))
        # Each frozen bound and rule refuses: the app ID, the generation, the package, the signers
        # and the identities.
        head, tail = bytes.fromhex(lineage), b'later'
        sign = '0f' * 32

        def frame(app=app_id, generation=2, package='dev.andrix.a', signers=(sign,), identities=((1, 0, 7),)):
            body = head + runner.struct.pack('<iq', app, generation) + runner.text(package)
            body += runner.struct.pack('<H', len(signers)) + b''.join(bytes.fromhex(item) for item in signers)
            body += runner.struct.pack('<H', len(identities))
            body += b''.join(runner.struct.pack('<qiq', *item) for item in identities)
            return runner.record(runner.TYPE_SLOT, 3, body + tail)
        self.assertIsNotNone(runner.decode_prefix(frame()))
        for change in ({'app': 9999}, {'generation': 0}, {'package': 'nodots'}, {'package': 'a.' + 'b' * 254},
                       {'signers': ()}, {'signers': ('1f' * 32, sign)}, {'identities': ((0, 0, 7),)},
                       {'identities': ((1, 5, 7), (2, 5, 7))}, {'identities': ((1, 0, 7), (1, 5, 7))},
                       {'identities': ((1, -1, 7),)}, {'identities': ((1, 21475, 7),)}):
            with self.subTest(change=change):
                self.assertIsNone(runner.decode_prefix(frame(**change)))
        self.assertIsNone(runner.decode_prefix(frame()[:-1] + b'\x00'))

    def test_the_largest_record_is_the_plans_arithmetic(self):
        lineage, app_id, other_app_id, serial = runner.lab.GUEST_VALUES
        largest = runner.lab.lifecycle_goldens('maximum-beside-eligible', lineage, app_id, other_app_id,
                                               serial)['slots/%d/record.bin' % other_app_id]
        self.assertEqual(len(largest), 60941)
        self.assertEqual(runner.maximum_problems(largest), [])
        self.assertEqual(runner.maximum_problems(runner.goldens()['MAXIMUM']), [])
        for broken in (largest[:-1], runner.lab.lifecycle_goldens('v2-noted')['slots/10148/record.bin']):
            self.assertTrue(runner.maximum_problems(broken))
        # The same arithmetic at a future guest's values: the record's size never depends on them.
        future = runner.lab.lifecycle_goldens('maximum-beside-eligible', *runner.lab.GUEST_FUTURE_VALUES)
        self.assertEqual(runner.maximum_problems(future['slots/%d/record.bin' % runner.lab.GUEST_FUTURE_VALUES[2]]), [])

    def test_the_floors_guest_compile_set_is_its_pinned_set_and_the_check(self):
        if not PINNED:
            self.skipTest('NOT RUN: ANDRIX_PINNED_FRAMEWORK does not name the pinned framework copies')
        pinned = Path(PINNED)
        files = runner.floor_inputs(pinned, scratch(self) / 'candidate')[2]
        production = runner.guest_files(runner.reader_files(runner.candidate(pinned)))
        floor = runner.guest_files(files)
        compile_set = runner.guest_section()['compile']
        self.assertEqual((len(floor), len(production)), (compile_set['files'],) * 2)
        self.assertEqual(runner.compile_differences(floor, production), compile_set['differing_from_production'])
        living = runner.guest_files({})
        self.assertEqual(runner.floor_compile_problems({name: runner.sha(data) for name, data in floor.items()
                                                        if name not in living}), [])


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
