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
import re
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
        self.assertEqual({step: list(labels) for step, labels in runner.STEP_LABELS.items()}, b2['step_labels'])
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
        # the reader check's and the layout emitter's.
        lifecycle = 'scripts/proof/native_lifecycle_record.py'
        self.assertEqual(len([row for row in rows if row[1] == lifecycle]), 8)
        # Elsewhere, the named V3 runs: the presence V3 step and the moved V3 cases of the binding
        # runner, the header footprint module's V3 cases, the store module's entry points and the
        # lab rehearsal; and code that constructs no store.
        others = [row for row in rows if row[1] != lifecycle]
        v3 = [row for row in others if set(row[2]) <= set(runner.LIFECYCLE_FORMAT_HARNESSES.get(row[1], ()))]
        storeless = [row for row in others if set(row[2]) <= set(runner.STORELESS_HARNESSES.get(row[1], ()))]
        self.assertEqual([row[1] for row in v3], [
            'scripts/proof/native_creation_binding.py', 'scripts/proof/native_creation_binding.py',
            'scripts/proof/tests/test_native_header_footprint.py', 'scripts/proof/tests/test_native_identity_store.py'])
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
        for label in (('production', 'archived-baseline'), ('rollback-reader',)):
            for step in ('reads', 'store', 'transactions', 'faults'):
                with mock.patch.dict(runner.STEP_LABELS, {step: label}):
                    self.assertTrue(runner.label_problems())
        # A production row of another harness, such as a suite that runs only the earlier formats,
        # is refused, and so is the retired label.
        for row in (('production', 'scripts/proof/native_creation_binding.py', ('NativeCreationBindingTest',), 'x'),
                    ('production', 'scripts/proof/native_lab_history.py', ('LabHistoryStoreTest',), 'x'),
                    ('production', 'scripts/proof/native_counter_admission.py', ('NativeCounterAdmissionTest',), 'x')):
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
        self.assertEqual(runner.PHASES, ('candidate', 'codec', 'reads', 'dump', 'store', 'transactions', 'faults',
                                         'settings', 'manager', 'pinned', 'layouts', 'rollback', 'readers', 'mutants'))
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
                                    runner.READER_CHECK: {'previous', 'production'}})
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
        self.assertEqual(predicted['phases'], list(runner.PHASES))
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
