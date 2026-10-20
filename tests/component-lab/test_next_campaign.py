# SPDX-License-Identifier: Apache-2.0
"""The next campaign's host checks that need no JVM: the matrix of next_cells.py and its counts,
the version 3 admission the driver writes, the broker's helper push and helper check, the strict
selection and authorization readers, and the next driver's own rules on fakes of the broker's
ledger: its explicit boot phases, its boot accounting, its scheduled loss control, its synced
records and immutable baseline cache, its publication pin and its comparison of a cell. The
driver's end to end histories are test_next_driver.py's. Host evidence only."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import unittest.mock

import capture_ledger
import health_compose
import labtest
import lab_actions
import lab_broker
import lab_driver
import lab_evidence
import lab_losses
import lab_records
import next_cells
import process_health
from scripts.proof import component_transaction_records as encoder

PLANS = {'COHORT': '0a' * 16, 'A': '0d' * 16, 'R': '0f' * 16}
PREDICATES = {'FULL': 'd1' * 32, 'LIMITED': 'd2' * 32, 'REFUSED': 'd3' * 32}
HELPERS = {name: {'sha256': pin, 'bytes': 4096} for name, pin in (
    ('ui-state', health_compose.UI_STATE_HELPER_SHA256), ('process-health', process_health.HELPER_SHA256))}
PAYLOADS = {'N2': [{'role': 'base.apk', 'sha256': 'b2' * 32, 'bytes': 100},
                   {'role': 'base.apk.idsig', 'sha256': 'b3' * 32, 'bytes': 10}],
            'N3': [{'role': 'base.apk', 'sha256': 'b4' * 32, 'bytes': 100}]}
BOOT = 'b0' * 16


def admission(**changes):
    value = dict(installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR, trust=labtest.TRUST,
                 manifest='aa' * 32, config='bb' * 32, serial='127.0.0.1:6520', target_scope='ESTABLISHED_EMPTY',
                 device_dir=labtest.DEVICE_DIR,
                 fences={'stop_file': '/lab/STOP', 'lease_file': None, 'lease_token': None,
                         'deadline_monotonic_ns': None, 'host_boot_id': None},
                 limits=dict(labtest.LIMITS), store='/lab/store', plans=PLANS, runtime='e2' * 16, helpers=HELPERS,
                 predicates=PREDICATES, payloads=PAYLOADS)
    value.update(changes)
    return lab_driver.next_admission(**value)


class CellsTests(unittest.TestCase):
    def test_the_campaign_is_well_formed_in_the_profile_phase_order(self):
        self.assertTrue(next_cells.check_sequence())
        phases = [lab_actions.PHASES.index(c['phase']) for c in next_cells.SEQUENCE]
        self.assertEqual(phases, sorted(phases))
        self.assertEqual([c['attempt'] for c in next_cells.cells(kind='managed') if c['plan'] == 'A'], [1, 2, 3, 4, 5, 6])

    def test_the_nominal_counts_are_the_contracts(self):
        n = next_cells.nominal()
        # Thirteen fault cells before N1, six confirmations, ten services, thirteen identities.
        original = [f for c in next_cells.SEQUENCE if c['phase'] == 'CELLS' for f in c.get('faults', [])]
        self.assertEqual(len(original), 13)
        self.assertEqual((n['confirmations'], n['activations'], n['services'], n['identities']), (6, 4, 10, 13))
        self.assertEqual((n['entries']['CREATE'], n['launched']['CREATE']), (6, 5))
        self.assertEqual(n['member_writes'], 11)
        self.assertEqual((n['entries']['ABANDON'], n['launched']['ABANDON']), (4, 3))
        self.assertEqual(n['launched']['COMMIT'] + n['direct']['COMMIT'], 4)
        self.assertEqual((n['entries']['COMMIT'], n['entries']['REBOOT'], n['entries']['SIGN'], n['entries']['PUBLISH']),
                         (3, 3, 2, 3))
        self.assertEqual((n['boots'], n['repair_boots']), ([0, 1, 1, 1, 3, 1], [1]))
        self.assertEqual(sum(1 for _, kind, _ in next_cells.BOOTS if kind in next_cells.SERVICE_KINDS), 10)

    def test_malformed_cells_are_refused(self):
        changes = {
            'a confirmation outside the waits a later boot resolves': lambda c: c['confirmations'].append('READY'),
            'a confirmation count other than the waits named': lambda c: c['prediction'].update(confirmations=0),
            'fewer boots than its own confirmations': lambda c: c['prediction'].update(boots=0),
            'a fault named twice': lambda c: c['faults'].append(dict(c['faults'][0])),
            'an unknown crossing': lambda c: c['faults'][0].update(crossing='LAUNCH'),
            'a loss at no milestone': lambda c: c['faults'].append(next_cells.loss('x-round', 'round', 'SETTLED')),
            'a read loss of health outside the window': lambda c: c['faults'].append(
                next_cells.loss('x-read', 'read', 'READY', reader='health')),
            'a NOTICE fault that needs no notice': lambda c: c['faults'].append(
                next_cells.fault('x-notice', 'cross', 'NOTICE', 1, 'loss-before')),
            'a milestone outside the enum': lambda c: c['prediction']['milestones'].append('SETTLED'),
            'an end that is not terminal': lambda c: c['prediction'].update(end='READY'),
            'a native count that is not a count': lambda c: c['prediction']['calls'].update(CREATE='1'),
            'a missing prediction key': lambda c: c['prediction'].pop('boots'),
            'an unknown plan role': lambda c: c.update(plan='B'),
        }
        base = next_cells.by_cell('m0-b0')
        for label, change in changes.items():
            cell = copy.deepcopy(base)
            change(cell)
            with self.subTest(change=label), self.assertRaises(ValueError):
                next_cells.check_cell(cell)
        direct = copy.deepcopy(next_cells.by_cell('n2'))
        direct['prediction']['cause'] = next_cells.CAUSES['N3']
        with self.assertRaises(ValueError):
            next_cells.check_cell(direct)

    def test_a_campaign_out_of_order_or_reusing_a_fault_is_refused(self):
        cells = list(next_cells.SEQUENCE)
        swapped = cells[:2] + [cells[3], cells[2]] + cells[4:]
        reused = copy.deepcopy(cells)
        reused[3]['faults'][0]['cell'] = reused[2]['faults'][0]['cell']
        phased = cells[:7] + [cells[8], cells[7]] + cells[9:]
        for label, sequence in (('attempts out of order', swapped), ('a fault reused', reused),
                                ('phases out of order', phased)):
            with self.subTest(label), self.assertRaises(ValueError):
                next_cells.check_sequence(tuple(sequence))

    def test_the_schedule_is_canonical_and_only_what_the_world_can_reach(self):
        nominal = next_cells.schedule_bytes(labtest.INSTALLATION, PLANS)
        faults = lab_losses.parse(nominal, labtest.INSTALLATION, lab_actions.PROFILE)
        self.assertEqual(len(faults), sum(len(c.get('faults', [])) for c in next_cells.SEQUENCE))
        self.assertEqual({f['plan'] for f in faults}, {PLANS['A'], PLANS['R']})
        quiet = {'notice': False, 'f0': 'FULL'}
        silent = next_cells.declaration(notice=False)
        kept = [f['cell'] for f in lab_losses.parse(next_cells.schedule_bytes(labtest.INSTALLATION, PLANS, silent),
                                                    labtest.INSTALLATION, lab_actions.PROFILE)]
        self.assertNotIn('a-notice', kept)
        self.assertNotIn('r-notice', kept)
        self.assertEqual(next_cells.uncaptured(next_cells.by_cell('a'), quiet), ['a-notice'])
        self.assertEqual(next_cells.qualified(next_cells.by_cell('a'), quiet)['ledger'],
                         ['CREATE', 'WRITE', 'COMMIT', 'REBOOT', 'REBOOT'])
        refused = {'notice': True, 'f0': 'REFUSED'}
        self.assertIsNone(next_cells.qualified(next_cells.by_cell('a'), refused))
        self.assertIsNone(next_cells.qualified(next_cells.by_cell('r'), refused))
        self.assertEqual(next_cells.faults(next_cells.by_cell('a'), refused), [])
        self.assertEqual(next_cells.qualified(next_cells.by_cell('m0-b0'), refused)['boots'], 3)
        record = next_cells.record_bytes(PLANS, silent)
        self.assertEqual(lab_evidence.parse(record)['plans'], PLANS)
        self.assertNotEqual(record, next_cells.record_bytes(dict(PLANS, R='0e' * 16), silent))

    def test_the_cells_record_freezes_every_declared_branch(self):
        for limited in (False, True):
            with self.subTest(limited=limited):
                declared = next_cells.declaration(notice=True, limited=limited)
                record = lab_evidence.parse(next_cells.record_bytes(PLANS, declared))
                self.assertEqual((record['schema'], record['notice']), ('andrix-next-cells-v2', True))
                self.assertEqual(sorted(record['branches']), sorted(declared['branches']))
                for branch, entries in record['branches'].items():
                    by = {e['cell']: e for e in entries}
                    runs = branch != 'REFUSED'
                    self.assertEqual([by[c]['runs'] for c in ('m0-b0', 'f0', 'a', 'r', 'final')],
                                     [True, True, runs, runs, runs])
                    self.assertEqual(by['a']['prediction'] is None, not runs)
                    self.assertEqual(by['a']['not_captured'] == [f['cell'] for f in next_cells.by_cell('a')['faults']],
                                     not runs)
                if limited:
                    self.assertEqual(record['branches']['LIMITED'], record['branches']['FULL'])
        # The schedule arms every fault a declared branch reaches, the same with LIMITED or without.
        one = next_cells.schedule_bytes(labtest.INSTALLATION, PLANS, next_cells.declaration(True, False))
        self.assertEqual(one, next_cells.schedule_bytes(labtest.INSTALLATION, PLANS, next_cells.declaration(True, True)))
        armed = [f['cell'] for f in lab_losses.parse(one, labtest.INSTALLATION, lab_actions.PROFILE)]
        self.assertTrue({'a-commit', 'r-commit', 'h1-sign'} <= set(armed))
        # Before F0 decides nothing after it is predicted, and asking is an error, never a guess.
        before = next_cells.undecided(next_cells.DECLARED)
        self.assertTrue(next_cells.reached(next_cells.by_cell('m0-b0'), before))
        for name in ('a', 'r', 'final'):
            with self.subTest(undecided=name), self.assertRaises(ValueError):
                next_cells.reached(next_cells.by_cell(name), before)
        with self.assertRaises(ValueError):
            next_cells.health(before, True)
        for bad in ({'notice': True, 'branches': ['LIMITED', 'REFUSED']}, {'notice': True, 'branches': ['FULL']},
                    {'notice': 1, 'branches': ['FULL', 'REFUSED']}, {'notice': True}):
            with self.subTest(declaration=bad), self.assertRaises(ValueError):
                next_cells.check_declaration(bad)

    def test_milestones_match_conditional_and_repeated_ones_only_where_predicted(self):
        a = next_cells.by_cell('a')['prediction']['milestones']
        seen = ['READY', 'READY', 'BOOT_OBSERVED', 'APPLIED_PROVISIONAL', 'APPLIED', 'HEALTH_WINDOW_ENTRY']
        self.assertTrue(next_cells.milestones_match(a, seen + ['HEALTH_WINDOW_PROGRESS'] * 6 + ['TERMINAL']))
        unseen = [m for m in seen if m != 'APPLIED_PROVISIONAL']
        self.assertTrue(next_cells.milestones_match(a, unseen + ['HEALTH_WINDOW_PROGRESS', 'TERMINAL']))
        for label, found in (('no progress', seen + ['TERMINAL']), ('one READY', seen[1:] + ['TERMINAL']),
                             ('twice provisional', seen[:4] + ['APPLIED_PROVISIONAL'] + seen[4:] + ['TERMINAL']),
                             ('out of order', seen[:2] + ['APPLIED', 'BOOT_OBSERVED'] + seen[4:] + ['TERMINAL']),
                             ('an extra close', seen + ['HEALTH_WINDOW_PROGRESS', 'TERMINAL', 'TERMINAL'])):
            with self.subTest(label):
                self.assertFalse(next_cells.milestones_match(a, found))

    def test_health_is_healthy_only_for_full_probes_under_a_full_f0(self):
        self.assertEqual(next_cells.health({'notice': True, 'f0': 'FULL'}, True), 'HEALTHY')
        for world, full in (({'notice': True, 'f0': 'FULL'}, False), ({'notice': True, 'f0': 'LIMITED'}, True),
                            ({'notice': False, 'f0': 'LIMITED'}, False)):
            with self.subTest(world=world, full=full):
                self.assertEqual(next_cells.health(world, full), 'INCONCLUSIVE')
        with self.assertRaises(ValueError):
            next_cells.health({'notice': True, 'f0': 'PARTIAL'}, True)

    def test_action_ids_are_fixed_distinct_and_nonzero(self):
        names = [n for n, _, _ in next_cells.confirmation_cells()]
        self.assertEqual(names, ['h2-c0-confirm', 'c1-w0-b1-confirm', 'c2-w1-b2-confirm', 'm0-b0-confirm-1',
                                 'm0-b0-confirm-2', 'm0-b0-confirm-3'])
        ids = [next_cells.action_id('confirm', n) for n in names] + [next_cells.action_id('helper', n)
                                                                       for n in next_cells.HELPERS]
        self.assertEqual(len(set(ids)), len(ids))
        self.assertTrue(all(lab_actions.HEX16.fullmatch(i) and i != '00' * 16 for i in ids))
        self.assertEqual(ids[0], next_cells.action_id('confirm', 'h2-c0-confirm'))


class AdmissionTests(unittest.TestCase):
    def test_the_written_admission_is_a_version_3_admission_of_the_campaign(self):
        value = admission()
        self.assertEqual(lab_broker.check_admission(value), value)
        self.assertEqual(value['branches']['positive'], {'plan': PLANS['A'], 'attempt': 6})
        self.assertIsNone(value['branches']['LIMITED'])
        self.assertEqual(value['boot_policy'], dict(lab_driver.BOOT_POLICY, activation_services=4,
                                                    confirmation_services=6, observed_boots=13))
        limits = value['effect_limits']
        self.assertEqual(limits['crossings'], {'CREATE': 5, 'WRITE': 4, 'COMMIT': 2, 'ABANDON': 3, 'REBOOT': 2,
                                               'NOTICE': next_cells.NOTICE_BUDGET})
        self.assertEqual((limits['direct'], limits['admin'], limits['control']), (9, 0, 6))
        self.assertEqual(limits['phases']['CELLS'], 6)
        self.assertEqual(value['cells_sha256'], hashlib.sha256(next_cells.record_bytes(PLANS)).hexdigest())
        self.assertEqual(value['fault_schedule_sha256'],
                         hashlib.sha256(next_cells.schedule_bytes(labtest.INSTALLATION, PLANS)).hexdigest())
        self.assertTrue(admission(limited=True)['branches']['LIMITED'])

    def test_the_specs_run_in_the_campaign_order_only(self):
        specs = admission()['lab_actions']
        by_type = {}
        for s in specs:
            by_type.setdefault(s['type'], []).append(s)
        confirms = by_type['PLAIN_KERNEL_CONFIRM']
        self.assertEqual([s['cell'] for s in confirms], [n for n, _, _ in next_cells.confirmation_cells()])
        self.assertEqual([s['predecessor'] for s in confirms], [None] + [s['id'] for s in confirms[:-1]])
        self.assertTrue(all(s['max_uses'] == 1 and s['phase'] == 'CELLS' for s in confirms))
        stages = by_type['DIRECT_STAGE']
        activations = by_type['NEGATIVE_ACTIVATION']
        self.assertEqual(stages[0]['predecessor'], confirms[-1]['id'])
        self.assertEqual(stages[1]['predecessor'], activations[0]['id'])
        self.assertEqual([s['inputs'] for s in stages], [PAYLOADS['N2'], PAYLOADS['N3']])
        self.assertEqual([s['parameters']['helper'] for s in by_type['HELPER_PUSH']], list(next_cells.HELPERS))
        self.assertEqual(sorted(s['phase'] for s in by_type['HEALTH_PREPARATION']), ['A', 'R'])
        self.assertNotIn('FRAMEWORK_RESTART', by_type)
        refused = admission()['branches']['REFUSED']['actions']
        self.assertFalse({s['id'] for s in by_type['HEALTH_PREPARATION']} & set(refused))
        # Only the direct controls the campaign names are admitted, whatever payloads are given.
        quiet = tuple(c for c in next_cells.SEQUENCE if c['kind'] != 'direct')
        self.assertNotIn('DIRECT_STAGE', [s['type'] for s in admission(sequence=quiet)['lab_actions']])
        self.assertEqual(admission(sequence=quiet)['effect_limits']['direct'], 0)

    def test_n1_and_the_notice_captures_are_admitted_only_as_the_campaign_names_them(self):
        n1 = [{'role': 'base.apk', 'sha256': 'b1' * 32, 'bytes': 100}]
        value = admission(payloads=dict(PAYLOADS, N1=n1))
        by_type = {}
        for s in value['lab_actions']:
            by_type.setdefault(s['type'], []).append(s)
        [install] = by_type['DIRECT_NONSTAGED']
        confirms, stages = by_type['PLAIN_KERNEL_CONFIRM'], by_type['DIRECT_STAGE']
        self.assertEqual((install['phase'], install['parameters']['role'], install['inputs'], install['max_uses']),
                         ('N1', 'N1', n1, 1))
        self.assertEqual((install['predecessor'], stages[0]['predecessor']), (confirms[-1]['id'], install['id']))
        self.assertIn(install['id'], value['branches']['REFUSED']['actions'])
        # N1's one install is a direct effect of its own phase; notices owed add each window phase's
        # captures to the fixture caps.
        limits = value['effect_limits']
        self.assertEqual((limits['direct'], limits['phases']['N1']), (10, 1))
        captures = by_type['NOTICE_VISIBILITY']
        self.assertEqual([(s['phase'], s['max_uses'], s['user_selector']) for s in captures],
                         [('A', next_cells.NOTICE_BUDGET, {'kind': 'NOTICE_RECIPIENT'}),
                          ('R', next_cells.NOTICE_BUDGET, {'kind': 'NOTICE_RECIPIENT'})])
        self.assertEqual((limits['fixture'], limits['phases']['A'], limits['phases']['R']),
                         (2 + 2 * lab_driver.PROBES + 2 * next_cells.NOTICE_BUDGET,
                          lab_driver.PROBES + next_cells.NOTICE_BUDGET, lab_driver.PROBES + next_cells.NOTICE_BUDGET))
        # Without notices owed, no capture; without N1's payload, no N1 and the old caps.
        quiet = admission(notice=False)
        self.assertNotIn('NOTICE_VISIBILITY', [s['type'] for s in quiet['lab_actions']])
        self.assertEqual((quiet['effect_limits']['fixture'], quiet['effect_limits']['phases']['A']),
                         (2 + 2 * lab_driver.PROBES, lab_driver.PROBES))
        plain = admission()
        self.assertNotIn('DIRECT_NONSTAGED', [s['type'] for s in plain['lab_actions']])
        self.assertEqual((plain['effect_limits']['direct'], plain['effect_limits']['phases']['N1']), (9, 0))
        # The nominal counts name N1's one install apart from every session command.
        n = next_cells.nominal()
        self.assertEqual((n['direct']['INSTALL'], n['launched']['INSTALL'], n['direct']['CREATE']), (1, 0, 2))
        self.assertEqual(next_cells.by_cell('n1')['prediction']['calls'], next_cells.calls(install=1))

    def test_an_admission_of_no_known_form_is_never_written(self):
        with self.assertRaisesRegex(lab_driver.DriverError, 'predicate for each F0 branch'):
            admission(predicates={'FULL': 'd1' * 32, 'REFUSED': 'd3' * 32})
        other = {'ui-state': {'sha256': 'ee' * 32, 'bytes': 10}, 'process-health': HELPERS['process-health']}
        with self.assertRaisesRegex(lab_broker.BrokerError, "pins other bytes than its reader's"):
            admission(helpers=other)
        with self.assertRaisesRegex(lab_driver.DriverError, 'every helper'):
            lab_driver.fixtures_record({'ui-state': HELPERS['ui-state']})
        doubled = next_cells.SEQUENCE + (dict(copy.deepcopy(next_cells.by_cell('a')), cell='a-again', attempt=7),)
        with self.assertRaises((lab_driver.DriverError, ValueError)):
            admission(sequence=doubled)

    def test_the_wait_policy_is_its_own_admitted_budget(self):
        self.assertEqual(lab_driver.WAIT_POLICY, {'ordinary_wait_ms': 600_000})
        self.assertEqual(admission()['wait_policy'], lab_driver.WAIT_POLICY)
        self.assertEqual(admission(wait_policy={'ordinary_wait_ms': 90_000})['wait_policy'], {'ordinary_wait_ms': 90_000})
        good = admission()
        for label, value in (('no wait policy', None), ('an extra key', {'ordinary_wait_ms': 600_000, 'plan': 1}),
                             ('under a second', {'ordinary_wait_ms': 999}),
                             ('past an action bound', {'ordinary_wait_ms': lab_actions.MAX_TIMEOUT_MS + 1}),
                             ('not a count', {'ordinary_wait_ms': '600000'}),
                             ('a truth value', {'ordinary_wait_ms': True})):
            with self.subTest(label), self.assertRaises(lab_broker.BrokerError):
                bad = dict(good)
                if value is None:
                    del bad['wait_policy']
                else:
                    bad['wait_policy'] = value
                lab_broker.check_admission(bad)
        # A read deadline belongs to a version 3 round and is a host monotonic instant; nothing is
        # spawned for a refused one.
        plain = labtest.Harness()
        self.addCleanup(plain.close)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'version 3'):
            plain.broker.run_generation(['/nonexistent/never-run'], deadline_ns=10 ** 12)
        next_profile = labtest.Harness(next_profile=True)
        self.addCleanup(next_profile.close)
        for deadline in (0, -1, True, 1.5):
            with self.subTest(deadline=deadline), self.assertRaisesRegex(lab_broker.BrokerError, 'read deadline'):
                next_profile.broker.run_generation(['/nonexistent/never-run'], deadline_ns=deadline)
        self.assertEqual([e for e in next_profile.broker.ledger.entries if e.kind == 'generation'], [])


class F0Tests(unittest.TestCase):
    """F0 as a gate among the declared branches, on the real broker's decision."""

    def harness(self, limited):
        declared = admission(limited=limited, payloads=None)
        h = labtest.Harness(next_profile=True, specs=declared['lab_actions'], branches=declared['branches'],
                            cells_sha256=declared['cells_sha256'])
        self.addCleanup(h.close)
        return h

    def driver(self, h, limited):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return lab_driver.NextDriver(temp.name, 'java', 'classes', PLANS, broker=h.broker, sync=False,
                                     declaration=next_cells.declaration(notice=True, limited=limited))

    def decide(self, actual, limited=True):
        h = self.harness(limited)
        d = self.driver(h, limited)
        return h, d, d.decide_f0(labtest.f0_record(actual), 'select one declared F0 branch')

    def test_f0_selects_the_decided_branch_among_the_declared_ones(self):
        for actual in ('FULL', 'LIMITED', 'REFUSED'):
            with self.subTest(actual=actual):
                h, d, decision = self.decide(actual)
                qualified = actual != 'REFUSED'
                self.assertEqual((decision['branch'], h.broker.f0['branch'], h.broker.f0['qualified']),
                                 (actual, actual, qualified))
                self.assertEqual(d.world, {'notice': True, 'f0': actual})
                self.assertEqual(d.results['f0'], {'status': 'DECIDED', 'branch': actual, 'qualified': qualified,
                                                   'outcome': next_cells.by_cell('f0')['prediction'][actual]})
                self.assertEqual([next_cells.reached(next_cells.by_cell(c), d.world) for c in ('a', 'r', 'final')],
                                 [qualified] * 3)
                self.assertEqual(next_cells.health(d.world, True), 'HEALTHY' if actual == 'FULL' else 'INCONCLUSIVE')
        # Without LIMITED in the admission, a capability record of LIMITED decides nothing at all.
        with self.assertRaisesRegex(lab_broker.BrokerError, 'does not admit'):
            self.decide('LIMITED', limited=False)
        # The driver's declaration is the admission's, or its entry stops before anything runs.
        h = self.harness(limited=True)
        self.driver(h, limited=True).bound_declaration()
        with self.assertRaisesRegex(lab_driver.DriverError, "does not bind this campaign's declaration"):
            self.driver(h, limited=False).bound_declaration()


class HelperPushTests(unittest.TestCase):
    """The broker's HELPER_PUSH and helper check on the simulated guest."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.jar = b'J' * 1024 + b'a stand in UI state helper jar'
        self.digest = hashlib.sha256(self.jar).hexdigest()
        self.path = Path(self.temp.name) / 'helper.jar'
        self.path.write_bytes(self.jar)
        patch = unittest.mock.patch.object(health_compose, 'UI_STATE_HELPER_SHA256', self.digest)
        patch.start()
        self.addCleanup(patch.stop)

    def spec(self, ident='5a' * 16, helper='ui-state', digest=None, uses=1):
        return labtest.action_spec(ident, 'HELPER_PUSH', phase='ENTRY', cell='entry-helper', max_uses=uses,
                                   parameters={'helper': helper},
                                   inputs=[{'role': 'helper', 'sha256': digest or self.digest, 'bytes': len(self.jar)}])

    def harness(self, uses=1, **changes):
        h = labtest.Harness(next_profile=True, specs=labtest.default_specs() + [self.spec(uses=uses)], **changes)
        self.addCleanup(h.close)
        h.sim.ui_helper = False
        return h

    def test_a_push_settles_only_on_its_byte_readback(self):
        h = self.harness()
        self.assertEqual(h.broker.helper_check('ui-state', 'before the push')['ok'], False)
        end = h.broker.run_action('5a' * 16, 'the helper before its reads', host=str(self.path))
        self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']), ('OK', True, 1))
        self.assertEqual(h.sim.files[health_compose.UI_STATE_HELPER], self.jar)
        readback = h.broker.ledger.entries[end['outcome']['readback'] - 1].content
        self.assertEqual(readback['intent']['command'], 'sha256sum ' + health_compose.UI_STATE_HELPER)
        found = h.broker.helper_check('ui-state', 'after the push')
        self.assertEqual((found['ok'], found['sha256'], found['pinned']), (True, self.digest, self.digest))
        self.assertEqual(h.broker.ledger.entries[found['capture'] - 1].content['intent']['purpose'], 'helper-check')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'admitted uses of the action are spent'):
            h.broker.run_action('5a' * 16, 'again', host=str(self.path))

    def test_a_push_its_transport_refuses_launches_nothing(self):
        # The transport's last question before the helper's sync service request refuses it once
        # a deadline has passed while connecting: the run's, whose stop is latched and ends the
        # action STOPPED, or the action's own bound, which refuses the action. Either way the push
        # is not launched, the helper never reaches the guest, and the END counts the push as an
        # effect not launched. The twin connects within both and pushes the helper. The run's
        # deadline comes before the action's bound of 600 s in the first case and after it in the
        # second, so each refusal is that deadline's alone.
        for case in ('the run deadline', 'the action bound', 'neither'):
            with self.subTest(case):
                D = labtest.Clock().mono + (300 if case == 'the run deadline' else 3600) * 10 ** 9
                h = self.harness(fences={'stop_file': '/nonexistent/STOP', 'lease_file': None, 'lease_token': None,
                                         'deadline_monotonic_ns': D, 'host_boot_id': labtest.HOST_BOOT})

                def connect(command):
                    if command != 'push ' + health_compose.UI_STATE_HELPER or case == 'neither':
                        return
                    [begin] = [e.content for e in h.entries('lab-action') if e.content['record'] == 'BEGIN']
                    passed = D if case == 'the run deadline' else begin['deadline_monotonic_ns']
                    h.clock.wall += passed - h.clock.mono
                    h.clock.mono = passed
                h.sim.hooks.append(connect)
                if case == 'the run deadline':
                    with self.assertRaises(lab_broker.Stopped):
                        h.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
                    end = [e.content for e in h.entries('lab-action') if e.content['record'] == 'END'][-1]
                else:
                    end = h.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
                if case == 'neither':
                    self.assertEqual((end['status'], end['counts']['effects_launched']), ('OK', 1))
                    self.assertEqual(h.sim.files[health_compose.UI_STATE_HELPER], self.jar)
                    continue
                [push] = [e.content for e in h.entries('capture')
                          if e.content['intent']['operation'] == 'lab-action-push']
                self.assertEqual((push['result']['launch'], push['result']['transport']),
                                 ('not-launched', 'launch-deadline'))
                self.assertNotIn(health_compose.UI_STATE_HELPER, h.sim.files)
                self.assertEqual((end['counts']['effects_launched'], end['counts']['effects_not_launched']), (0, 1))
                stops = [e.content['reason'] for e in h.entries('stop')]
                if case == 'the run deadline':
                    self.assertEqual((end['status'], end['uncertainty'], stops),
                                     ('STOPPED', lab_broker.RUN_AT_SERVICE, [lab_broker.RUN_AT_SERVICE]))
                else:
                    self.assertEqual((end['status'], stops), ('REFUSED', []))

    def test_other_host_bytes_launch_nothing(self):
        other = Path(self.temp.name) / 'other.jar'
        other.write_bytes(self.jar + b'!')
        link = Path(self.temp.name) / 'link.jar'
        link.symlink_to(self.path)
        for host in (other, link, Path(self.temp.name) / 'absent.jar'):
            with self.subTest(host=host.name):
                h2 = self.harness(uses=1)
                end = h2.broker.run_action('5a' * 16, 'the helper', host=str(host))
                self.assertEqual((end['status'], end['counts']['effects_launched'], end['counts']['effects_uncertain']),
                                 ('REFUSED', 0, 0))
                self.assertEqual([c for c in h2.sim.calls if c[0] == 'push'], [])

    def test_a_readback_of_other_bytes_is_unexpected_and_never_repeated(self):
        h = self.harness(uses=2)

        def tamper(command):
            if command == 'push ' + health_compose.UI_STATE_HELPER:
                h.sim.hooks.append(lambda c: setattr(h.sim, 'ui_helper', 'ee' * 32))
        h.sim.hooks.append(tamper)
        end = h.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
        self.assertEqual((end['status'], end['settled']), ('UNEXPECTED', False))
        found = h.broker.helper_check('ui-state', 'after the push')
        self.assertEqual((found['ok'], found['sha256']), (False, 'ee' * 32))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            h.broker.run_action('5a' * 16, 'again', host=str(self.path))
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'push']), 1)

    def test_a_push_whose_readback_is_lost_stays_uncertain(self):
        h = self.harness(uses=2)
        h.sim.scripts['sha256sum ' + health_compose.UI_STATE_HELPER] = ['before']
        end = h.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
        self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']), ('UNKNOWN', False, 1))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            h.broker.run_action('5a' * 16, 'again', host=str(self.path))

    def test_the_admission_refuses_a_pin_other_than_the_readers(self):
        with tempfile.TemporaryDirectory() as directory:
            value = labtest.admission3(directory, specs=labtest.default_specs() + [self.spec(digest='ee' * 32)])
            with self.assertRaisesRegex(lab_broker.BrokerError, "pins other bytes than its reader's"):
                lab_broker.check_admission(value)
            other = labtest.admission3(directory, specs=labtest.default_specs() + [self.spec(helper='other')])
            with self.assertRaises(lab_broker.BrokerError):
                lab_broker.check_admission(other)

    def test_pushes_count_against_the_fixture_and_entry_caps(self):
        other = b'Q' * 1024 + b'a stand in process history helper jar'
        path = Path(self.temp.name) / 'other-helper.jar'
        path.write_bytes(other)
        patch = unittest.mock.patch.object(process_health, 'HELPER_SHA256', hashlib.sha256(other).hexdigest())
        patch.start()
        self.addCleanup(patch.stop)
        second = labtest.action_spec('5b' * 16, 'HELPER_PUSH', phase='ENTRY', cell='entry-other-helper', max_uses=1,
                                     parameters={'helper': 'process-health'},
                                     inputs=[{'role': 'helper', 'sha256': hashlib.sha256(other).hexdigest(),
                                              'bytes': len(other)}])
        one = labtest.Harness(next_profile=True, specs=labtest.default_specs() + [self.spec(), second],
                              effect_limits=dict(labtest.effect_limits(), fixture=1))
        self.addCleanup(one.close)
        self.assertEqual(one.broker.run_action('5a' * 16, 'the first helper', host=str(self.path))['status'], 'OK')
        end = one.broker.run_action('5b' * 16, 'the second helper', host=str(path))
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertEqual(len([c for c in one.sim.calls if c[0] == 'push']), 1)
        limits = dict(labtest.effect_limits(), fixture=0)
        h = self.harness(effect_limits=limits)
        end = h.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertIn('fixture effects are spent', end['uncertainty'])
        phases = dict(labtest.effect_limits(), phases=dict(labtest.effect_limits()['phases'], ENTRY=0))
        h2 = self.harness(effect_limits=phases)
        end = h2.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertEqual([c for c in h.sim.calls + h2.sim.calls if c[0] == 'push'], [])

    def test_no_push_while_a_boot_transition_is_unsettled_and_no_check_beside_a_generation(self):
        h = self.harness()
        with unittest.mock.patch.object(h.broker, '_unsettled_transition', lambda current=None: 'a transition is open'):
            with self.assertRaisesRegex(lab_broker.BrokerError, 'a transition is open'):
                h.broker.run_action('5a' * 16, 'the helper', host=str(self.path))
        self.assertEqual([c for c in h.sim.calls if c[0] == 'push'], [])
        h.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'beside a generation'):
            h.broker.helper_check('ui-state', 'during a generation')
        h.end()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no helper of that name'):
            h.broker.helper_check('another', 'an unknown helper')
        plain = labtest.Harness()
        self.addCleanup(plain.close)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'version 3'):
            plain.broker.helper_check('ui-state', 'version 1')


class ControllerReadTests(unittest.TestCase):
    def test_a_controller_reads_whole_inventories_only_under_its_admission(self):
        h = labtest.Harness(next_profile=True)
        self.addCleanup(h.close)
        groups = h.broker.controller_read(['clock', 'global-sessions', 'inventory', 'clock'], 'the final reads')
        self.assertEqual([g.status for g in groups], ['facts'] * 4)
        self.assertTrue(groups[1].reading['whole'] and groups[2].reading['whole'])
        recorded = [h.broker.ledger.entries[g.number - 1].content for g in groups]
        self.assertEqual([(c['reader'], c['emitted'], c['purpose']) for c in recorded],
                         [(name, False, 'controller: the final reads')
                          for name in ('clock', 'global-sessions', 'inventory', 'clock')])
        plain = labtest.Harness()
        self.addCleanup(plain.close)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'version 3'):
            plain.broker.controller_read(['global-sessions'], 'a version 1 read')
        for reader, name, why in (({'inventory': True}, 'global-sessions', 'no global session inventory'),
                                  ({'global_sessions': True}, 'inventory', 'no user inventory')):
            with self.subTest(name):
                other = labtest.Harness(next_profile=True, reader=reader)
                self.addCleanup(other.close)
                with self.assertRaisesRegex(lab_broker.BrokerError, why):
                    other.broker.controller_read(['clock', name], 'an unadmitted read')
                self.assertEqual([e for e in other.broker.ledger.entries if e.kind == 'group'
                                  and e.content.get('reader') == name], [])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'known groups'):
            h.broker.controller_read(['receipts'], 'not a controller read')


def selection_record(**changes):
    value = {'installation': labtest.INSTALLATION, 'component': 'com.android.systemui', 'revision': 1, 'choice': 'PLAN',
             'plan': PLANS['A'], 'responsibility': 'REBUILD_WINDOW', 'rebuildWindow': 1209600000,
             'realization': 'CURRENT', 'checkedBoot': BOOT, 'repair': '00' * 16, 'temporary': '00' * 16,
             'changedAt': encoder.TIME}
    value.update(changes)
    return encoder.selection(value)


def authorization_record(**changes):
    value = {'installation': labtest.INSTALLATION, 'authorization': '2a' * 16, 'component': 'com.android.systemui',
             'plan': PLANS['R'], 'effect': 'STAGE', 'inputs': 0, 'actor': 'LAB_OPERATOR', 'user': -10000,
             'serial': -1, 'grant': '00' * 16, 'scope': 'NONE', 'interaction': '2b' * 16, 'grantedAt': encoder.TIME}
    value.update(changes)
    return encoder.authorization(value)


class ReaderTests(unittest.TestCase):
    def test_the_selection_and_authorization_readers_read_the_encoders_records(self):
        s = lab_records.decode_selection(selection_record())
        self.assertEqual((s['choice'], s['plan'], s['revision'], s['realization'], s['checkedBoot']),
                         ('PLAN', PLANS['A'], 1, 'CURRENT', BOOT))
        a = lab_records.decode_authorization(authorization_record())
        self.assertEqual((a['effect'], a['inputs'], a['actor'], a['plan']), ('STAGE', 0, 'LAB_OPERATOR', PLANS['R']))
        self.assertEqual(lab_records.decode_authorization(authorization_record(effect='SIGN', inputs=3))['inputs'], 3)

    def test_changed_records_are_refused(self):
        good = selection_record()
        cut = good[:-33] + good[-32:]
        flipped = good[:20] + bytes([good[20] ^ 1]) + good[21:]
        for label, data in (('a factory choice naming a plan', selection_record(choice='FACTORY')),
                            ('a plan choice naming none', selection_record(plan='00' * 16)),
                            ('a cut record', cut), ('a changed byte', flipped),
                            ('a ticket record', encoder.ticket(dict(encoder.base_ticket(1, PLANS['A']))))):
            with self.subTest(label), self.assertRaises(lab_records.RecordError):
                lab_records.decode_selection(data)
        for label, data in (('a SIGN of no inputs', authorization_record(effect='SIGN', inputs=0)),
                            ('a STAGE with inputs', authorization_record(inputs=1)),
                            ('inputs outside both roles', authorization_record(effect='SIGN', inputs=4))):
            with self.subTest(label), self.assertRaises(lab_records.RecordError):
                lab_records.decode_authorization(data)
        trailing = authorization_record()
        body = trailing[:-32] + b'\0'
        body = body[:8] + struct.pack('<I', len(body) + 32) + body[12:]
        with self.assertRaises(lab_records.RecordError):
            lab_records.decode_authorization(body + hashlib.sha256(body).digest())


class FakeLedger:
    def __init__(self):
        self.entries = []

    @property
    def last(self):
        return self.entries[-1] if self.entries else None

    def add(self, kind, content, state='complete'):
        self.entries.append(capture_ledger.Entry(len(self.entries) + 1, kind, state, dict(content), None))
        return len(self.entries)


class FakeBroker:
    """The parts of a broker the next driver's own rules read: its ledger, transitions, cells,
    admission, pins and helper checks."""

    def __init__(self, cells=(), observed=13):
        self.ledger = FakeLedger()
        self.transitions = {}
        self.specs = {}
        self.cells = [dict(c) for c in cells]
        self.admission = {'boot_policy': {'observed_boots': observed}, 'component': 'com.android.systemui',
                          'config': '3c' * 32}
        self.pins = []
        self.helper_reads = {}

    def clock(self, boot, transition=None, wall=0):
        number = self.ledger.add('group', {'reader': 'clock', 'status': 'facts', 'transition': transition,
                                           'reading': {'boot': boot, 'instance': 4001, 'elapsed': 1000, 'wall': wall}})
        # As the broker does: a clock reading of a new boot settles an open managed activation.
        for ident, t in sorted(self.transitions.items()):
            if t['begin']['transition_kind'] == 'MANAGED_ACTIVATION' and t['end'] is None \
                    and boot != t['begin']['old']['boot']:
                t['end'] = {'record': 'END', 'transition': ident, 'status': 'OK', 'new_boots': [boot],
                            'polls': [{'groups': [number], 'boot': boot, 'missing': None}], 'settled_poll': 1}
                self.ledger.add('boot-transition', t['end'])
        return number

    def transition(self, ident, kind, cell):
        begin = {'record': 'BEGIN', 'transition': ident, 'transition_kind': kind, 'cell': cell}
        self.ledger.add('boot-transition', begin)
        self.transitions[ident] = {'begin': begin, 'progress': [], 'end': None}

    def reboot(self, launched=True):
        number = self.ledger.add('crossing', {'crossing': 'REBOOT', 'ticket': '36' * 16})
        # As the broker does: the crossing's MANAGED_ACTIVATION transition around its service.
        clocks = [e.content['reading']['boot'] for e in self.ledger.entries if e.kind == 'group']
        ident = 'managed-%d' % number
        begin = {'record': 'BEGIN', 'transition': ident, 'transition_kind': 'MANAGED_ACTIVATION', 'cell': None,
                 'old': {'boot': clocks[-1] if clocks else None}, 'subject': {'crossing': number}}
        self.ledger.add('boot-transition', begin)
        capture = self.ledger.add('capture', {'intent': {'operation': 'reboot', 'crossing': number, 'transition': ident,
                                                         'command': lab_broker.REBOOT_LABEL},
                                              'result': {'launch': 'launched' if launched else 'not-launched'}})
        progress = {'record': 'PROGRESS', 'transition': ident, 'capture': capture,
                    'launch': 'launched' if launched else 'not-launched'}
        self.ledger.add('boot-transition', progress)
        self.transitions[ident] = {'begin': begin, 'progress': [progress], 'end': None}
        if not launched:
            self.transitions[ident]['end'] = {'record': 'END', 'transition': ident, 'status': 'REFUSED',
                                              'new_boots': [], 'polls': [], 'settled_poll': None}
            self.ledger.add('boot-transition', self.transitions[ident]['end'])

    def pin_artifacts(self, plan, members, publication=None):
        self.pins.append((plan, members, publication))

    def helper_check(self, name, purpose):
        ok = self.helper_reads.get(name, True)
        return {'capture': 1, 'helper': name, 'sha256': None, 'pinned': 'aa' * 32, 'ok': ok}


def boot(n):
    return ('%02x' % (0xb0 + n)) * 16


class DriverRuleTests(unittest.TestCase):
    def driver(self, broker, sync=False, sequence=next_cells.SEQUENCE):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return lab_driver.NextDriver(temp.name, 'java', 'classes', PLANS, broker=broker, sync=sync, sequence=sequence)

    def test_every_coordinator_jvm_names_its_output_destinations(self):
        # The JVM's own output and its unified logging go to standard error, which the broker keeps,
        # never a frame pipe: the lab driver's and the next driver's JVMs both name them, before
        # their class path, as the lab's own bridge suite does.
        self.assertEqual(lab_broker.JVM_OUTPUT, ('-XX:+DisplayVMOutputToStderr', '-Xlog:disable',
                                                 '-Xlog:all=warning:stderr:uptime,level,tags'))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        drivers = {'the lab driver': lab_driver.LabDriver(temp.name, 'java', 'classes', 'host.config', '5e' * 32),
                   'the next driver': self.driver(FakeBroker())}
        for name, d in drivers.items():
            with self.subTest(name):
                argv = d._argv('check')
                before = argv[:argv.index('-cp')]
                self.assertEqual([o for o in before if o in lab_broker.JVM_OUTPUT], list(lab_broker.JVM_OUTPUT))
        import test_lab_bridge
        self.assertEqual(test_lab_bridge.JVM[-3:], lab_broker.JVM_OUTPUT)

    def test_boot_phases_follow_the_ledger_and_name_their_transitions(self):
        b = FakeBroker()
        d = self.driver(b)
        # The wall times run backwards: the ledger's order alone decides.
        b.clock(boot(0), wall=9000)
        b.transition('t1', 'CONFIRMATION', 'h2-c0-confirm')
        b.clock(boot(0), transition='t1', wall=8000)
        b.clock(boot(1), transition='t1', wall=7000)
        b.transition('t2', 'NEGATIVE_ACTIVATION', 'n2-negative-activation')
        b.clock(boot(2), transition='t2', wall=6000)
        b.clock(boot(3), transition='t2', wall=5000)
        b.reboot()
        b.clock(boot(4), wall=4000)
        d.observe_boots()
        self.assertEqual([(x['boot'], x['kind'], x['cell']) for x in d.boots],
                         [(boot(0), 'INITIAL', 'entry'), (boot(1), 'CONFIRMATION', 'h2-c0-confirm'),
                          (boot(2), 'NEGATIVE_ACTIVATION', 'n2-negative-activation'),
                          (boot(3), 'NATIVE_RECOVERY', 'n2-negative-activation'), (boot(4), 'MANAGED_ACTIVATION', None)])
        self.assertEqual(len(list((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())), 5)

    def test_a_boot_no_transition_or_launched_reboot_made_stops_the_driver(self):
        for label, make in (('no cause', lambda b: None), ('a reboot never launched', lambda b: b.reboot(False)),
                            ('a second boot of a confirmation',
                             lambda b: (b.transition('t1', 'CONFIRMATION', 'c'), b.clock(boot(5), transition='t1')))):
            with self.subTest(label):
                b = FakeBroker()
                d = self.driver(b)
                b.clock(boot(0))
                d.observe_boots()
                make(b)
                b.clock(boot(1), transition='t1' if label.startswith('a second') else None)
                with self.assertRaisesRegex(lab_driver.DriverError, 'unexpected'):
                    d.observe_boots()
        b = FakeBroker(observed=2)
        d = self.driver(b)
        b.clock(boot(0))
        b.reboot()
        b.clock(boot(1))
        b.reboot()
        b.clock(boot(2))
        with self.assertRaisesRegex(lab_driver.DriverError, 'observed boots pass'):
            d.observe_boots()

    def test_a_managed_boot_is_the_one_its_transition_settled_on_that_reading(self):
        # The honest control: the managed transition the broker settled on the new boot's first
        # reading names the boot.
        b = FakeBroker()
        d = self.driver(b)
        b.clock(boot(0))
        b.reboot()
        b.clock(boot(1))
        d.observe_boots()
        [ident] = list(b.transitions)
        self.assertEqual([(x['kind'], x['transition']) for x in d.boots], [('INITIAL', None),
                                                                          ('MANAGED_ACTIVATION', ident)])

        def unknown(t, number):
            t['end'] = {'record': 'END', 'status': 'UNKNOWN', 'new_boots': [], 'polls': [], 'settled_poll': None}
        changes = {
            'a transition asked again in the same boot': ('before', unknown),
            'a settlement on another reading': ('after', lambda t, n: t['end']['polls'][-1].update(groups=[n - 1])),
            'a settlement of another boot': ('after', lambda t, n: t['end'].update(new_boots=[boot(9)])),
            'a service its progress shows not launched': ('after', lambda t, n: t['progress'][0].update(
                launch='not-launched')),
        }
        for name, (when, change) in changes.items():
            with self.subTest(name):
                b = FakeBroker()
                d = self.driver(b)
                b.clock(boot(0))
                d.observe_boots()
                b.reboot()
                [t] = b.transitions.values()
                if when == 'before':
                    change(t, None)
                number = b.clock(boot(1))
                if when == 'after':
                    change(t, number)
                with self.assertRaisesRegex(lab_driver.DriverError, 'boot 1 is unexpected'):
                    d.observe_boots()

    def test_a_managed_boot_needs_a_capture_of_its_own_service_that_may_have_launched(self):
        # Each history's transition settled OK on the new boot's first reading: only its own
        # service's capture decides. A capture a lost broker interrupted may have launched, with
        # no PROGRESS; a BEGIN with no capture, another transition's capture, or a refused one
        # sent nothing of it.
        def service(b):
            return next(e for e in b.ledger.entries if e.kind == 'capture')

        def interrupted(b, t):
            capture = service(b)
            capture.state, capture.content = 'interrupted', {'intent': capture.content['intent']}
            t['progress'] = []

        def missing(b, t):
            b.ledger.entries[service(b).number - 1] = capture_ledger.Entry(
                service(b).number, 'group', 'complete', {'reader': 'checkpoint', 'status': 'facts'}, None)
            t['progress'] = []
        histories = {
            'a launched service': (None, 'MANAGED_ACTIVATION'),
            'a capture a lost broker interrupted, no PROGRESS': (interrupted, 'MANAGED_ACTIVATION'),
            'a BEGIN with no capture of its service': (missing, None),
            'a capture of another transition': (lambda b, t: service(b).content['intent'].update(
                transition='managed-other'), None),
            'a capture of another crossing': (lambda b, t: service(b).content['intent'].update(crossing=99), None),
            'a capture refused before its launch': (lambda b, t: service(b).content['result'].update(
                launch='not-launched'), None),
        }
        for name, (change, kind) in histories.items():
            with self.subTest(name):
                b = FakeBroker()
                d = self.driver(b)
                b.clock(boot(0))
                d.observe_boots()
                b.reboot()
                [(ident, t)] = b.transitions.items()
                if change is not None:
                    change(b, t)
                b.clock(boot(1))
                self.assertEqual(t['end']['status'], 'OK')
                if kind is None:
                    with self.assertRaisesRegex(lab_driver.DriverError, 'boot 1 is unexpected'):
                        d.observe_boots()
                    self.assertEqual((d.boots[-1]['kind'], d.boots[-1]['transition']), ('UNEXPECTED', None))
                else:
                    d.observe_boots()
                    self.assertEqual((d.boots[-1]['kind'], d.boots[-1]['transition']), (kind, ident))

    def test_a_round_that_issued_notices_captures_each_recipients_display_once(self):
        b = FakeBroker()
        action = next_cells.action_id('visibility', 'A')
        b.specs = {action: {}}
        order = []

        @contextlib.contextmanager
        def forward(user):
            order.append(('forward', user))
            yield
            order.append(('back', user))

        def run_action(action_id, reason, **request):
            order.append(('capture', action_id, request))
            return {'status': 'OK', 'outcome': {'qualified': request['serial'] == 5, 'why_not': None, 'group': 9}}
        b.run_action = run_action
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        d = lab_driver.NextDriver(temp.name, 'java', 'classes', PLANS, broker=b, sync=False,
                                  foreground=lambda driver, issue, r: forward(r['user']))
        ticket = '36' * 16
        two = [{'user': 10, 'serial': 5, 'type': lab_actions.SECONDARY_TYPE},
               {'user': 11, 'serial': 6, 'type': lab_actions.SECONDARY_TYPE}]
        b.ledger.add('notice-issue', {'number': 1, 'ticket': ticket, 'index': 3, 'required': two})
        mark = len(b.ledger.entries)
        b.ledger.add('notice-issue', {'number': 2, 'ticket': ticket, 'index': 4, 'required': two})
        b.ledger.add('notice-issue', {'number': 3, 'ticket': '37' * 16, 'index': 2, 'required': two[:1]})
        d.notice_visibility(next_cells.by_cell('a'), ticket, mark)
        self.assertEqual(order, [('forward', 10), ('capture', action, {'ticket': ticket, 'index': 4, 'serial': 5}),
                                 ('back', 10), ('forward', 11),
                                 ('capture', action, {'ticket': ticket, 'index': 4, 'serial': 6}), ('back', 11)])
        records = [json.loads(p.read_text()) for p in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())]
        self.assertEqual([(r['label'], r['facts']['serial'], r['facts']['qualified']) for r in records],
                         [('notice-visibility', 5, True), ('notice-visibility', 6, False)])
        # No issue since the mark captures nothing; an issue with no capture admitted stops.
        order.clear()
        d.notice_visibility(next_cells.by_cell('a'), ticket, len(b.ledger.entries))
        self.assertEqual(order, [])
        b.specs = {}
        with self.assertRaisesRegex(lab_driver.DriverError, 'no visibility capture is admitted'):
            d.notice_visibility(next_cells.by_cell('a'), ticket, mark)

    def test_drive_captures_a_rounds_notices_before_the_next_round(self):
        b = FakeBroker()
        b.specs = {next_cells.action_id('visibility', 'A'): {}}
        events = []

        def run_action(action_id, reason, **request):
            events.append(('capture', request['index'], request['serial']))
            return {'status': 'OK', 'outcome': {'qualified': True, 'why_not': None, 'group': 1}}
        b.run_action = run_action
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        d = lab_driver.NextDriver(temp.name, 'java', 'classes', PLANS, broker=b, sync=False)
        ticket = '36' * 16
        # The ticket's state before the first round and after each: the first round issues a notice.
        states = [('PUBLISHED', 'a1'), ('PUBLISHED', 'a2'), ('CLOSED_APPLIED', 'a3')]
        rounds = []

        def advance(kind, which):
            rounds.append(kind)
            events.append(('round', len(rounds)))
            if len(rounds) == 1:
                b.ledger.add('notice-issue', {'number': len(b.ledger.entries) + 1, 'ticket': ticket, 'index': 2,
                                              'required': [{'user': 10, 'serial': 5,
                                                            'type': lab_actions.SECONDARY_TYPE}]})
            return {'generation': len(rounds), 'status': 'COMPLETE'}
        d.advance = advance
        d.ticket_state = lambda which: {'ticket': ticket, 'state': states[len(rounds)][0], 'ledger': [],
                                        'boot': BOOT, 'bootCount': 0, 'sha256': states[len(rounds)][1]}
        end = d.drive({'confirmations': [], 'phase': 'A', 'name': 'A'}, ticket, PLANS['A'], generations=5)
        self.assertEqual(end['state'], 'CLOSED_APPLIED')
        self.assertEqual(events, [('round', 1), ('capture', 2, 5), ('round', 2)])

    def test_the_boot_accounting_moves_by_one_with_an_observed_boot_only(self):
        b = FakeBroker()
        d = self.driver(b)
        b.clock(boot(0))
        b.clock(boot(1))
        d.boots = [{'ordinal': 0, 'boot': boot(0)}, {'ordinal': 1, 'boot': boot(1)}]
        d.selection = lambda: {'sha256': 'cc' * 32}
        before = {'ticket': '35' * 16, 'boot': boot(0), 'bootCount': 0, 'sha256': '01' * 32}
        d.account_boot(before, dict(before, boot=boot(1), bootCount=1, sha256='02' * 32))
        records = [json.loads(p.read_text()) for p in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())]
        self.assertEqual(records[-1]['facts']['new_count'], 1)
        for label, after in (('two at once', dict(before, boot=boot(1), bootCount=2)),
                             ('a count that falls', dict(before, bootCount=-1)),
                             ('a count without a new boot', dict(before, bootCount=1)),
                             ('a boot the ledger never showed', dict(before, boot=boot(9), bootCount=1))):
            with self.subTest(label), self.assertRaises(lab_driver.DriverError):
                d.account_boot(before, after)

    def test_the_loss_control_takes_only_scheduled_halts_one_a_halted_generation(self):
        cells = [{'cell': 'x-before'}, {'cell': 'x-drop'}, {'cell': 'x-round'}, {'cell': 'x-read'}]

        def run(entries, status):
            b = FakeBroker(cells)
            d = self.driver(b)
            for kind, content in entries:
                b.ledger.add(kind, content)
            d.control_losses({'generation': 3, 'status': status}, 0)
            return d
        d = run([('fault', {'cell': 'x-before', 'decision': 'halt-before-effect'})], 'DELIBERATE_HALT')
        self.assertEqual(d.acted['x-before']['generation'], 3)
        self.assertIn('x-drop', run([('escrow', {'cell': 'x-drop'})], 'COMPLETE').acted)
        refused = {
            'a halt with no fault': ([], 'DELIBERATE_HALT'),
            'a halt with two faults': ([('fault', {'cell': 'x-round', 'decision': 'halt'}),
                                        ('fault', {'cell': 'x-read', 'decision': 'halt'})], 'DELIBERATE_HALT'),
            'a halting fault in a complete generation': ([('fault', {'cell': 'x-round', 'decision': 'halt'})],
                                                         'COMPLETE'),
            'a loss left not acted': ([('fault', {'cell': 'x-read', 'decision': 'not-acted'})], 'COMPLETE'),
            'a fault outside the schedule': ([('fault', {'cell': 'y-other', 'decision': 'halt'})], 'DELIBERATE_HALT'),
            'a fault acting twice': ([('fault', {'cell': 'x-round', 'decision': 'halt'}),
                                      ('escrow', {'cell': 'x-round'})], 'DELIBERATE_HALT'),
        }
        for label, (entries, status) in refused.items():
            with self.subTest(label), self.assertRaises(lab_driver.DriverError):
                run(entries, status)

    def test_a_cell_owes_every_reachable_fault_but_one_a_guest_need_not_show(self):
        cell = next_cells.by_cell('a')
        world = {'notice': False, 'f0': 'FULL'}
        b = FakeBroker()
        d = self.driver(b)
        d.world = world
        prediction = next_cells.qualified(cell, world)
        state = {'state': 'CLOSED_APPLIED', 'cause': 'NONE', 'ledger': [(c,) for c in prediction['ledger']],
                 'bootCount': 1, 'health': [(0, 0, 'INCONCLUSIVE')], 'sha256': '01' * 32}
        d.selection = lambda: {'choice': 'PLAN', 'plan': PLANS['A'], 'revision': 1, 'sha256': '02' * 32}
        d.plan_record = lambda plan: {'selectionRevision': 0}
        for name in ('CREATE', 'WRITE', 'COMMIT', 'REBOOT'):
            number = b.ledger.add('crossing', {'crossing': name, 'ticket': '36' * 16})
            commands = {'CREATE': ['pm install-create x'], 'WRITE': ['pm install-write a', 'pm install-write b'],
                        'COMMIT': ['pm install-commit c'], 'REBOOT': [lab_broker.REBOOT_LABEL]}[name]
            for command in commands:
                b.ledger.add('capture', {'intent': {'crossing': number, 'command': command},
                                         'result': {'launch': 'launched'}})
        for milestone in prediction['milestones']:
            if milestone != 'APPLIED_PROVISIONAL':
                b.ledger.add('checkpoint', {'ticket': '36' * 16, 'milestone': milestone})
        acted = [f['cell'] for f in next_cells.faults(cell, world) if f['cell'] != 'a-provisional-round']
        d.acted = {name: {'cell': 'a'} for name in acted}
        result = d.compare(cell, '36' * 16, PLANS['A'], state, 0)
        self.assertEqual((result['status'], result['not_captured']), ('PASSED', ['a-provisional-round', 'a-notice']))
        del d.acted['a-ready-round']
        with self.assertRaisesRegex(lab_driver.DriverError, 'differs from its prediction'):
            d.compare(cell, '36' * 16, PLANS['A'], state, 0)
        d.acted['a-ready-round'] = {'cell': 'a'}
        with self.assertRaisesRegex(lab_driver.DriverError, 'differs from its prediction'):
            d.compare(cell, '36' * 16, PLANS['A'], dict(state, health=[(0, 0, 'HEALTHY')]), 0)

    def compare_a(self, reached, acted):
        # A's comparison on the fake ledger: every count, crossing and milestone of its prediction,
        # APPLIED_PROVISIONAL recorded when reached, and its scheduled loss acted when asked.
        cell = next_cells.by_cell('a')
        world = {'notice': False, 'f0': 'FULL'}
        b = FakeBroker()
        d = self.driver(b)
        d.world = world
        prediction = next_cells.qualified(cell, world)
        state = {'state': 'CLOSED_APPLIED', 'cause': 'NONE', 'ledger': [(c,) for c in prediction['ledger']],
                 'bootCount': 1, 'health': [(0, 0, 'INCONCLUSIVE')], 'sha256': '01' * 32}
        d.selection = lambda: {'choice': 'PLAN', 'plan': PLANS['A'], 'revision': 1, 'sha256': '02' * 32}
        d.plan_record = lambda plan: {'selectionRevision': 0}
        commands = {'CREATE': ['pm install-create x'], 'WRITE': ['pm install-write a', 'pm install-write b'],
                    'COMMIT': ['pm install-commit c'], 'REBOOT': [lab_broker.REBOOT_LABEL]}
        for name, lines in commands.items():
            number = b.ledger.add('crossing', {'crossing': name, 'ticket': '36' * 16})
            for line in lines:
                b.ledger.add('capture', {'intent': {'crossing': number, 'command': line},
                                         'result': {'launch': 'launched'}})
        for milestone in prediction['milestones']:
            if reached or milestone != 'APPLIED_PROVISIONAL':
                b.ledger.add('checkpoint', {'ticket': '36' * 16, 'milestone': milestone})
        d.acted = {f['cell']: {'cell': 'a'} for f in next_cells.faults(cell, world)
                   if acted or f['cell'] != 'a-provisional-round'}
        return d.compare(cell, '36' * 16, PLANS['A'], state, 0)

    def test_a_reached_conditional_milestone_owes_its_loss(self):
        self.assertEqual(self.compare_a(reached=False, acted=False)['not_captured'], ['a-provisional-round', 'a-notice'])
        self.assertEqual(self.compare_a(reached=True, acted=True)['not_captured'], ['a-notice'])
        with self.assertRaisesRegex(lab_driver.DriverError, 'differs from its prediction.*"faults"'):
            self.compare_a(reached=True, acted=False)

    def test_the_final_join_owns_the_campaigns_live_sessions_only(self):
        component = 'com.android.systemui'

        def row(ident, referrer, section='ACTIVE', package=component, **flags):
            value = {'section': section, 'id': ident, 'package': package, 'referrer': referrer, 'staged': True,
                     'multi_package': False, 'parent': -1, 'children': [], 'sealed': True, 'committed': True,
                     'ready': False, 'applied': False, 'failed': False, 'destroyed': False, 'created': 1000 + ident,
                     'installer': 2000, 'cause': None}
            value.update(flags)
            return value
        references = {'nonces': ['a1' * 16, 'a2' * 16], 'sessions': [(7, 1007, 2000)], 'controls': ['c2' * 16]}
        history = [row(1, 'andrix-ticket:' + 'a1' * 16, 'FINALIZED', applied=True),
                   row(2, 'andrix-lab-control:' + 'c2' * 16, 'FINALIZED', failed=True, cause='SIGNATURE'),
                   row(3, 'andrix-ticket:' + 'a2' * 16, applied=True),
                   row(4, 'adb:other', package='org.example.app', sealed=False, committed=False)]
        reading = {'whole': True, 'sessions': history}
        self.assertIsNone(lab_actions.check_global(reading))
        self.assertEqual(lab_driver.final_join(reading, component, references), ([], [], [history[3]]))
        cases = {
            'a live session under a ticket nonce': (row(5, 'andrix-ticket:' + 'a2' * 16, committed=False), [5], []),
            'a live session under a control referrer': (row(6, 'andrix-lab-control:' + 'c2' * 16), [6], []),
            "a ticket's recorded session without its referrer": (row(7, None), [7], []),
            'a session of the campaign in an unknown state': (row(8, 'andrix-ticket:' + 'a1' * 16, applied=None),
                                                              [8], []),
            'a live session of the component under another referrer': (row(9, 'adb:other'), [], [9]),
            'a live session of no known package': (row(10, None, package=None), [], [10]),
            "another package's live session under the campaign's form": (
                row(11, 'andrix-ticket:' + 'ee' * 16, package='org.example.app'), [], [11]),
        }
        for label, (extra, owned, uncertain) in cases.items():
            with self.subTest(label):
                found = {'whole': True, 'sessions': history + [extra]}
                self.assertIsNone(lab_actions.check_global(found))
                self.assertEqual(lab_driver.final_join(found, component, references), (owned, uncertain, [history[3]]))

    def test_other_packages_live_sessions_are_reported_whole_and_classified(self):
        component = 'com.android.systemui'
        base = {'section': 'ACTIVE', 'package': 'org.example.app', 'referrer': 'adb:installer', 'staged': False,
                'multi_package': False, 'parent': -1, 'children': [], 'sealed': False, 'committed': False,
                'ready': False, 'applied': False, 'failed': False, 'destroyed': False, 'created': 5000,
                'installer': 10123, 'cause': None}
        states = [('OPEN', {}), ('SEALED', {'sealed': True}), ('COMMITTED', {'sealed': True, 'committed': True}),
                  ('READY', {'sealed': True, 'committed': True, 'ready': True}), ('UNKNOWN', {'committed': None}),
                  ('UNKNOWN', {'applied': None})]
        rows = [dict(base, id=20 + n, **flags) for n, (_, flags) in enumerate(states)]
        terminal = [dict(base, id=40, section='FINALIZED', applied=True),
                    dict(base, id=41, failed=True), dict(base, id=42, referrer=None, destroyed=True)]
        reading = {'whole': True, 'sessions': rows + terminal}
        self.assertIsNone(lab_actions.check_global(reading))
        owned, uncertain, others = lab_driver.final_join(reading, component, {'nonces': [], 'sessions': [],
                                                                              'controls': []})
        self.assertEqual((owned, uncertain), ([], []))
        # Each live one whole, as the inventory read it; no terminal one; each classified.
        self.assertEqual(others, rows)
        self.assertEqual([lab_driver.session_classification(r) for r in others], [name for name, _ in states])
        others[0]['id'] = 99
        self.assertEqual(rows[0]['id'], 20)

    def test_the_driver_records_are_synced_before_anything_relies_on_them(self):
        for sync in (True, False):
            with self.subTest(sync=sync), tempfile.TemporaryDirectory() as root, \
                    tempfile.TemporaryDirectory() as other:
                b = FakeBroker()
                d = lab_driver.NextDriver(root, 'java', 'classes', PLANS, broker=b, sync=sync)
                store = Path(root) / 'store'
                (store / 'tickets').mkdir(parents=True)
                (store / 'tickets' / 'one.rec').write_bytes(b'a ticket record')
                d.store = store
                with labtest.SyncTrace(root) as trace:
                    d.checkpoint('first', step=1)
                    d.snapshot('step')
                    trace.mark('after')
                image = trace.image('after', Path(other) / 'image')
                checkpoints = list((image / lab_driver.RUN_CHECKPOINTS).glob('*.json'))
                snapshot = image / 'store-snapshots' / '0001-step'
                if sync:
                    self.assertEqual(lab_evidence.parse(checkpoints[0].read_bytes())['facts'], {'step': 1})
                    self.assertEqual((snapshot / 'tickets' / 'one.rec').read_bytes(), b'a ticket record')
                    manifest = json.loads((snapshot / 'manifest.json').read_text())
                    self.assertEqual(manifest, {'tickets/one.rec': hashlib.sha256(b'a ticket record').hexdigest()})
                    order = [e for e in trace.events if e[0] in ('create', 'fsync-file')]
                    self.assertEqual(order[-2:], [('create', str(Path(root) / 'store-snapshots' / '0001-step'
                                                              / 'manifest.json')),
                                                  ('fsync-file', str(Path(root) / 'store-snapshots' / '0001-step'
                                                                     / 'manifest.json'))])
                else:
                    self.assertFalse(checkpoints and checkpoints[0].read_bytes())

    def test_baseline_cache_entries_are_written_once_and_never_inherited(self):
        b = FakeBroker()
        d = self.driver(b)
        group = {'status': 'facts', 'compound': 'compound/aa', 'brackets': {'boot': boot(1), 'instance': 4001},
                 'user': 0, 'serial': 0, 'complete': True}
        d._cache('health', 7, group)
        d._cache('health', 8, dict(group, complete=False))
        d._cache('health', 9, dict(group, status='unavailable'))
        d._cache('health', 10, dict(group, brackets={'boot': boot(1), 'instance': 4101}))
        self.assertEqual([e['group'] for e in d.whole_baselines(boot(1), 4001, 0, 0)], [7])
        self.assertEqual([e['group'] for e in d.whole_baselines(boot(1), 4101, 0, 0)], [10])
        self.assertEqual(d.whole_baselines(boot(2), 4001, 0, 0), [])
        first = sorted((d.dir / lab_driver.BASELINES).iterdir())[0]
        with self.assertRaises(FileExistsError):
            lab_driver._write_synced(first, b'{}\n', False)
        self.assertEqual(lab_evidence.parse(first.read_bytes())['group'], 7)

    def test_a_publication_is_pinned_with_its_record_digest_only(self):
        b = FakeBroker()
        d = self.driver(b)
        lines = 'base.apk %s 10\nbase.apk.idsig %s 5\npublication %s\n' % ('a1' * 32, 'a2' * 32, 'a3' * 32)
        d.export = lambda plan, out: lines
        d.checkpoint = lambda *args, **kwargs: None
        members = d.stage_publication(PLANS['A'])
        self.assertEqual(b.pins, [(PLANS['A'], members, 'a3' * 32)])
        self.assertEqual(d.stage_publication(PLANS['A']), members)
        self.assertEqual(len(b.pins), 1)
        for label, text in (('no publication line', lines.rsplit('publication', 1)[0]),
                            ('a member named twice', lines.replace('base.apk.idsig', 'base.apk')),
                            ('a size that is not one', lines.replace(' 5\n', ' five\n')),
                            ('two publication lines', lines + 'publication %s\n' % ('a4' * 32))):
            with self.subTest(label):
                other = self.driver(FakeBroker())
                other.export = lambda plan, out, text=text: text
                other.checkpoint = lambda *args, **kwargs: None
                with self.assertRaises(lab_driver.DriverError):
                    other.stage_publication(PLANS['A'])
                self.assertEqual(other.broker.pins, [])
        unpublished = self.driver(FakeBroker())
        unpublished.export = lambda plan, out: None
        self.assertIsNone(unpublished.stage_publication(PLANS['A']))

    def test_the_window_pace_stays_within_its_gap_and_its_admitted_probes(self):
        for pace in (0, -1, lab_driver.WINDOW_GAP_S, 30):
            with self.subTest(pace=pace), self.assertRaisesRegex(lab_driver.DriverError, 'window pace'):
                lab_driver.NextDriver('/lab/driver', 'java', 'classes', PLANS, window_pace_s=pace)
        slept = []
        with unittest.mock.patch.object(lab_driver.time, 'sleep', slept.append):
            d = lab_driver.NextDriver('/lab/driver', 'java', 'classes', PLANS, pace_s=20.0, window_pace_s=180.0)
            d.wait({'state': 'HEALTH_WINDOW'})
            d.wait({'state': 'REBOOT_INTENT'})
        self.assertEqual(slept, [180.0, 20.0])

    def test_one_wait_spans_its_intents_flag_changes_and_ends_at_its_deadline(self):
        clock = labtest.Clock()
        b = FakeBroker()
        b.admission['wait_policy'] = {'ordinary_wait_ms': 100_000}
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        d = lab_driver.NextDriver(temp.name, 'java', 'classes', PLANS, broker=b, sync=False, pace_s=40.0,
                                  monotonic=clock.monotonic_ns)
        ledger = [('CREATE',), ('WRITE',), ('COMMIT',)]
        # The ticket's bytes before the first round and after each: unchanged, then its unresolved
        # flag set and later cleared, always one intent: COMMIT_INTENT, one ledger, one boot.
        digests = ['aa', 'aa', 'bb', 'bb', 'cc'] + ['cc'] * 20
        state = {'ticket': '36' * 16, 'state': 'COMMIT_INTENT', 'ledger': ledger, 'boot': BOOT, 'bootCount': 1,
                 'sha256': 'aa'}
        rounds = []

        def advance(kind, ticket):
            rounds.append(kind)
            n = len(rounds)
            b.ledger.add('group', {'reader': 'clock', 'status': 'facts', 'generation': n,
                                   'reading': {'boot': BOOT, 'instance': 4001, 'elapsed': 30_000 + 1000 * n, 'wall': 0}})
            return {'generation': n, 'status': 'COMPLETE'}
        d.advance = advance
        d.ticket_state = lambda ticket: dict(state, sha256=digests[len(rounds)])
        d.later_boot_resolves = lambda generation: False
        steps = []

        def between(driver, now):
            steps.append(driver.pause_s(now))
            clock.sleep(steps[-1])
        d.between_hook = between
        with self.assertRaisesRegex(lab_driver.DriverError, 'within its admitted budget of 100000 ms'):
            d.drive({'confirmations': []}, '36' * 16, PLANS['A'], generations=20)
        records = [json.loads(p.read_text()) for p in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())]
        ends = [r['facts'] for r in records if r['label'] == 'ordinary-wait']
        self.assertEqual([e['outcome'] for e in ends], ['unresolved'])
        self.assertEqual([s['unchanged'] for s in ends[0]['samples']], [True, False, True, False, True])
        self.assertEqual([s['guest']['elapsed'] for s in ends[0]['samples']], [31_000, 32_000, 33_000, 34_000, 35_000])
        self.assertEqual((steps, len(rounds)), ([40.0, 40.0, 20.0], 5))
        self.assertEqual(ends[0]['ended_ns'], ends[0]['deadline_ns'])

    def test_a_pause_is_cut_to_what_is_left_of_an_open_wait(self):
        clock = labtest.Clock()
        slept = []
        with unittest.mock.patch.object(lab_driver.time, 'sleep', slept.append):
            d = lab_driver.NextDriver('/lab/driver', 'java', 'classes', PLANS, pace_s=20.0, window_pace_s=120.0,
                                      monotonic=clock.monotonic_ns)
            d.wait({'state': 'COMMIT_INTENT'})
            self.assertIsNone(d.remaining_wait_s())
            d.waiting = {'deadline_ns': clock.monotonic_ns() + 7_500_000_000}
            d.wait({'state': 'COMMIT_INTENT'})
            d.wait({'state': 'HEALTH_WINDOW'})
            clock.sleep(30)
            d.wait({'state': 'COMMIT_INTENT'})
        self.assertEqual(slept, [20.0, 7.5, 7.5, 0.0])

    def test_a_new_boot_needs_both_helpers_read_back(self):
        b = FakeBroker()
        d = self.driver(b)
        d.new_boot_gates('a new boot')
        b.helper_reads['process-health'] = False
        with self.assertRaisesRegex(lab_driver.DriverError, 'process-health helper'):
            d.new_boot_gates('a new boot')


if __name__ == '__main__':
    unittest.main()
