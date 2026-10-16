# SPDX-License-Identifier: Apache-2.0
"""The next campaign profile's read and round losses, round boundaries, durable barrier, plain
kernel confirmations, direct negative controls and F0 commit fence, on a simulated guest with the
stored records of the independent encoder. Each contrary form must be refused for its own reason
while its honest original passes. Host evidence only: the simulated guest's forms are test fakes,
not Android forms."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import labtest
from labtest import GRANT, PLAN, TICKET, Harness
import capture_ledger
import lab_actions
import lab_broker
import lab_evidence
import lab_losses
import lab_protocol as proto
import sim_android

STATUS = proto.STATUSES
CODE = proto.MILESTONES
# Each milestone's round: the ticket's state when the round began and when it ended. The repair
# milestones are of a plan that repairs another without signing.
ROUNDS = {'READY': ('COMMIT_INTENT', 'READY'), 'BOOT_OBSERVED': ('REBOOT_INTENT', 'BOOT_OBSERVED'),
          'APPLIED_PROVISIONAL': ('BOOT_OBSERVED', 'APPLIED_PROVISIONAL'),
          'APPLIED': ('APPLIED_PROVISIONAL', 'APPLIED'), 'HEALTH_WINDOW_ENTRY': ('APPLIED', 'HEALTH_WINDOW'),
          'HEALTH_WINDOW_PROGRESS': ('HEALTH_WINDOW', 'HEALTH_WINDOW'), 'TERMINAL': ('HEALTH_WINDOW', 'CLOSED_APPLIED'),
          'REPAIR_SIGNING_SKIPPED': ('SIGNING', 'SIGNED'), 'REPAIR_PUBLICATION_BOUND': ('SIGNED', 'PUBLISHED')}
# Each read milestone's state: the one a read at it observes.
READS = {'READY': 'READY', 'BOOT_OBSERVED': 'BOOT_OBSERVED', 'APPLIED_PROVISIONAL': 'APPLIED_PROVISIONAL',
         'APPLIED': 'APPLIED', 'HEALTH_WINDOW_PROGRESS': 'HEALTH_WINDOW', 'TERMINAL': 'CLOSED_FAILED',
         'REPAIR_SIGNING_SKIPPED': 'SIGNED', 'REPAIR_PUBLICATION_BOUND': 'PUBLISHED'}
REPAIR = {'repairs': '0f' * 16, 'signing': 0}


@contextlib.contextmanager
def failing_sync(root, directory=lab_broker.RECORDS):
    """The first sync of one of the broker's directories fails, as C1a's latch test injects it:
    after a kept file's rename, before its name is durable."""
    sync, failures = lab_broker._sync_directory, []

    def failing(path):
        if Path(path) == Path(root) / directory and not failures:
            failures.append(path)
            raise OSError('the directory sync failed')
        return sync(path)
    lab_broker._sync_directory = failing
    try:
        yield failures
    finally:
        lab_broker._sync_directory = sync


@contextlib.contextmanager
def failing_keep(broker, digests):
    """Keeping the bytes of one of the given digests fails with the error a failed sync gives."""
    keep, failures = broker._keep, []

    def failing(digest, data, where=lab_broker.RECORDS):
        if digest in digests:
            failures.append(digest)
            raise OSError('the file sync failed')
        return keep(digest, data, where)
    broker._keep = failing
    try:
        yield failures
    finally:
        del broker._keep


def loss(cell, on, milestone, ordinal=0, occurrence=1, attempt=1, plan=PLAN):
    return {'cell': cell, 'on': on, 'plan': plan, 'attempt': attempt, 'operation': lab_losses.OPERATIONS[on],
            'milestone': milestone, 'ordinal': ordinal, 'occurrence': occurrence, 'mode': 'halt'}


class LossBase(unittest.TestCase):
    def harness(self, cells=(), **options):
        options.setdefault('notice', sim_android.SimNotice())
        options.setdefault('health', sim_android.SimHealth())
        h = Harness(next_profile=True, cells=cells, **options)
        self.addCleanup(h.close)
        return h

    def put(self, h, state, plan=None, attempt=1, ticket=TICKET, **changes):
        """The store holds the ticket in a state, its plan, the selection and the grant."""
        if state == 'HEALTH_WINDOW':
            changes.setdefault('windowBoot', h.sim.boot)
            changes.setdefault('windowStart', 30_000)
        root = Path(h.admission['store'])
        for directory, name, data in (
                ('tickets', ticket, labtest.ticket_record(h.sim, state, ticket=ticket, attempt=attempt, **changes)),
                ('plans', PLAN, labtest.plan_record(**(plan or {}))),
                ('selections', sim_android.PACKAGE, b'selection record'), ('authorizations', GRANT, b'grant record')):
            (root / directory).mkdir(parents=True, exist_ok=True)
            (root / directory / (name + '.rec')).write_bytes(data)

    def open_round(self, h):
        if h.broker.open_generation is None:
            h.begin()
            self.assertEqual(h.hello()['status'], STATUS['OK'])
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])

    def boundary(self, h, before, after, milestone, plan=None, attempt=1, **changes):
        """One round from one stored state to another: its clock, its observation in the first
        state, the coordinator's write of the second, then its ROUND_DONE naming the milestone."""
        self.put(h, before, plan, attempt, **changes)
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code(before))['status'], STATUS['OK'])
        self.put(h, after, plan, attempt, **changes)
        return h.round_done(attempt=attempt, milestone=CODE[milestone] if milestone else 0)

    def entry(self, h, number):
        return h.broker.ledger.entries[number - 1]

    def waiting(self, h, state='SESSION_INTENT', **changes):
        """The ticket waits in `state`, its round's boundary recorded, between generations."""
        self.put(h, state, **changes)
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code(state))['status'], STATUS['OK'])
        self.assertEqual(h.round_done()['status'], STATUS['OK'])
        h.end(0)

    def confirm(self, h, action=labtest.CONFIRM_ACTION):
        return h.broker.run_action(action, 'a later boot confirms the wait', ticket=TICKET)

    def transitions(self, h):
        return [e.content for e in h.entries('boot-transition')]

    def checkpoints(self, h):
        return [e.content for e in h.entries('checkpoint')]


class MilestoneTests(unittest.TestCase):
    # The same table as the Java codec test's: before, after, signed, repair, the milestone.
    BOUNDARIES = [(None, 'READY', False, False, 'READY'), ('COMMIT_INTENT', 'READY', False, False, 'READY'),
                  ('READY', 'READY', False, False, None), ('REBOOT_INTENT', 'READY', False, False, 'READY'),
                  ('REBOOT_INTENT', 'BOOT_OBSERVED', False, False, 'BOOT_OBSERVED'),
                  ('BOOT_OBSERVED', 'APPLIED_PROVISIONAL', False, False, 'APPLIED_PROVISIONAL'),
                  ('APPLIED_PROVISIONAL', 'APPLIED', False, False, 'APPLIED'),
                  ('APPLIED', 'HEALTH_WINDOW', False, False, 'HEALTH_WINDOW_ENTRY'),
                  ('HEALTH_WINDOW', 'HEALTH_WINDOW', False, False, 'HEALTH_WINDOW_PROGRESS'),
                  ('HEALTH_WINDOW', 'CLOSED_APPLIED', False, False, 'TERMINAL'),
                  ('NO_SESSION', 'CLOSED_FAILED', False, False, 'TERMINAL'),
                  ('CLOSED_FAILED', 'CLOSED_FAILED', False, False, None),
                  ('SIGNING', 'SIGNED', False, True, 'REPAIR_SIGNING_SKIPPED'),
                  ('SIGNING', 'SIGNED', True, True, None), ('SIGNING', 'SIGNED', False, False, None),
                  ('SIGNED', 'PUBLISHED', False, True, 'REPAIR_PUBLICATION_BOUND'),
                  ('SIGNED', 'PUBLISHED', True, False, None), ('PUBLISHED', 'SESSION_INTENT', False, False, None),
                  ('WRITTEN', 'COMMIT_INTENT', False, False, None), (None, 'HEALTH_WINDOW', False, False,
                                                                    'HEALTH_WINDOW_ENTRY')]
    READ_STATES = [('READY', False, False, 'READY'), ('HEALTH_WINDOW', False, False, 'HEALTH_WINDOW_PROGRESS'),
                   ('CLOSED_APPLIED', False, False, 'TERMINAL'), ('VOID', False, False, 'TERMINAL'),
                   ('SIGNED', False, True, 'REPAIR_SIGNING_SKIPPED'), ('SIGNED', True, True, None),
                   ('PUBLISHED', False, True, 'REPAIR_PUBLICATION_BOUND'), ('PUBLISHED', False, False, None),
                   ('COMMIT_INTENT', False, False, None), ('APPLIED', False, False, 'APPLIED')]

    def test_the_milestone_enum_is_fixed_and_its_rule_one_table(self):
        self.assertEqual(sorted(proto.MILESTONES.values()), list(range(1, 10)))
        self.assertEqual(proto.MILESTONES, {'READY': 1, 'BOOT_OBSERVED': 2, 'APPLIED_PROVISIONAL': 3, 'APPLIED': 4,
                                            'HEALTH_WINDOW_ENTRY': 5, 'HEALTH_WINDOW_PROGRESS': 6, 'TERMINAL': 7,
                                            'REPAIR_SIGNING_SKIPPED': 8, 'REPAIR_PUBLICATION_BOUND': 9})
        for before, after, signed, repair, expected in self.BOUNDARIES:
            self.assertEqual(proto.boundary_milestone(before, after, signed, repair), expected, (before, after))
        for state, signed, repair, expected in self.READ_STATES:
            self.assertEqual(proto.read_milestone(state, signed, repair), expected, state)
        # No read is at the window's entry.
        self.assertNotIn('HEALTH_WINDOW_ENTRY', {proto.read_milestone(s, False, False) for s in proto.ENTERED +
                                                 ('HEALTH_WINDOW',) + proto.TERMINAL_STATES})


class RoundBoundaryTests(LossBase):
    def test_a_boundary_is_checkpointed_from_the_stored_bytes(self):
        h = self.harness()
        reply = self.boundary(h, 'COMMIT_INTENT', 'READY', 'READY')
        self.assertEqual(reply['status'], STATUS['OK'])
        c = self.entry(h, reply['record']).content
        self.assertEqual((c['ordinal'], c['milestone'], c['milestone_code'], c['state'], c['occurrence']),
                         (1, 'READY', 1, 'READY', 1))
        store = Path(h.admission['store'])
        for name, path in (('ticket', store / 'tickets' / (TICKET + '.rec')),
                           ('selection', store / 'selections' / (sim_android.PACKAGE + '.rec')),
                           ('plan', store / 'plans' / (PLAN + '.rec'))):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(c[name + '_sha256'], digest)
            self.assertEqual((h.root / 'records' / digest).read_bytes(), path.read_bytes())
        self.assertEqual((c['round_start']['state'], c['round_start']['source']), ('COMMIT_INTENT', 'observe'))
        self.assertTrue((h.root / 'records' / c['round_start']['sha256']).exists())
        # The next round's boundary is the ticket's second, and the bridge is told so.
        reply = self.boundary(h, 'READY', 'READY', None)
        self.assertEqual((reply['status'], self.entry(h, reply['record']).content['ordinal']), (STATUS['OK'], 2))
        self.assertEqual(h.broker.checkpoint_counts(), '%s:2' % TICKET)
        h.end(0)
        h.reopen()
        self.assertEqual((len(h.broker.checkpoints[TICKET]), h.broker.checkpoint_counts()), (2, '%s:2' % TICKET))

    def test_a_round_without_an_observation_starts_from_its_last_boundary(self):
        h = self.harness()
        self.assertEqual(self.boundary(h, 'COMMIT_INTENT', 'COMMIT_INTENT', None)['status'], STATUS['OK'])
        # The clock is unavailable: the round reads nothing, and still reaches READY.
        h.sim.scripts['sim:clock'] = ['before']
        self.put(h, 'READY')
        self.assertEqual(h.clock_read()['status'], STATUS['UNAVAILABLE'])
        reply = h.round_done(milestone=CODE['READY'])
        c = self.entry(h, reply['record']).content
        self.assertEqual((reply['status'], c['milestone'], c['round_start']['source']), (STATUS['OK'], 'READY',
                                                                                         'checkpoint'))

    def test_every_milestone_is_verified_from_the_stored_bytes(self):
        for milestone, (before, after) in ROUNDS.items():
            with self.subTest(milestone):
                h = self.harness()
                plan = REPAIR if milestone.startswith('REPAIR') else None
                ledger = [] if milestone == 'REPAIR_SIGNING_SKIPPED' else None
                wrong = (CODE[milestone] % 9) + 1
                self.put(h, before, plan, ledger=ledger)
                self.open_round(h)
                h.observe(state=labtest.state_code(before))
                self.put(h, after, plan, ledger=ledger)
                refused = h.round_done(milestone=wrong)
                self.assertEqual(refused['status'], STATUS['REFUSED'])
                self.assertIn('reached %s' % milestone, refused['reason'])
                self.assertEqual(self.checkpoints(h), [])
                self.assertEqual(self.boundary(h, before, after, milestone, plan, ledger=ledger)['status'],
                                 STATUS['OK'])
                self.assertEqual(self.checkpoints(h)[-1]['milestone'], milestone)
        # A round that reached none carries 0, and a claim of one is refused.
        h = self.harness()
        self.assertEqual(self.boundary(h, 'WRITTEN', 'COMMIT_INTENT', None)['status'], STATUS['OK'])
        reply = self.boundary(h, 'COMMIT_INTENT', 'COMMIT_INTENT', 'READY')
        self.assertEqual(reply['status'], STATUS['REFUSED'])

    def test_contrary_boundaries_are_refused_and_record_nothing(self):
        def stale_selection(h):
            (Path(h.admission['store']) / 'selections' / (sim_android.PACKAGE + '.rec')).write_bytes(b'moved')
        cases = {
            'a second ROUND_DONE for one round': ({}, 'second'),
            'another ticket than its round named': ({'ticket': '05' * 16, 'ticket_digest': '11' * 32}, None),
            'another plan than the store holds': ({'plan': '02' * 16}, None),
            'another attempt than the store holds': ({'attempt': 2}, None),
            'a stale ticket digest': ({'ticket_digest': '11' * 32}, None),
            'a stale selection digest': ({'selection_digest': hashlib.sha256(b'selection record').hexdigest()},
                                         stale_selection),
            'a stale ordinal': ({'checkpoint_ordinal': 1}, None),
            'a skipped ordinal': ({'checkpoint_ordinal': 3}, None),
        }
        for name, (changes, world) in cases.items():
            with self.subTest(name):
                h = self.harness()
                self.assertEqual(self.boundary(h, 'COMMIT_INTENT', 'COMMIT_INTENT', None)['status'], STATUS['OK'])
                recorded = len(h.broker.ledger.entries)
                if world == 'second':
                    reply = h.round_done()
                else:
                    self.open_round(h)
                    h.observe(state=labtest.state_code('COMMIT_INTENT'))
                    if callable(world):
                        world(h)
                    reply = h.round_done(**changes)
                self.assertEqual((reply['status'], reply['record']), (STATUS['REFUSED'], 0), name)
                self.assertEqual([e.kind for e in h.broker.ledger.entries[recorded:]
                                  if e.kind in ('checkpoint', 'fault')], [])
                self.assertEqual(len(h.broker.checkpoints[TICKET]), 1)
        # A round whose requests name two tickets has no one boundary.
        h = self.harness()
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        h.observe(state=labtest.state_code('COMMIT_INTENT'))
        h.cross('CREATE', 2, ticket='05' * 16, ticket_digest='11' * 32, plan_digest='22' * 32)
        self.assertEqual(h.round_done()['status'], STATUS['REFUSED'])

    def test_a_stop_answers_stopped_with_no_record(self):
        h = self.harness()
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        h.observe(state=labtest.state_code('COMMIT_INTENT'))
        Path(h.admission['fences']['stop_file']).write_text('stop\n')
        reply = h.round_done()
        self.assertEqual((reply['status'], reply['record']), (STATUS['STOPPED'], 0))
        self.assertEqual(self.checkpoints(h), [])

    def test_the_broker_tells_each_generation_its_checkpoint_counts(self):
        h = self.harness()
        self.boundary(h, 'COMMIT_INTENT', 'READY', 'READY')
        self.boundary(h, 'READY', 'READY', None)
        h.end(0)
        told = h.directory / 'told'
        script = ('import os, sys; open(%r, "w").write(os.environ.get(%r, "absent"))'
                  % (str(told), lab_broker.CHECKPOINT_ENV))
        h.broker.run_generation([sys.executable, '-c', script])
        self.assertEqual(told.read_text(), '%s:2' % TICKET)
        v1 = Harness()
        self.addCleanup(v1.close)
        v1.broker.run_generation([sys.executable, '-c', script])
        self.assertEqual(told.read_text(), 'absent')


class RoundLossTests(LossBase):
    def test_a_round_loss_at_each_milestone_halts_after_its_durable_checkpoint(self):
        for milestone, (before, after) in ROUNDS.items():
            with self.subTest(milestone):
                h = self.harness([loss('round-loss', 'round', milestone)])
                plan = REPAIR if milestone.startswith('REPAIR') else None
                ledger = [] if milestone == 'REPAIR_SIGNING_SKIPPED' else None
                # An earlier boundary at no milestone passes.
                self.assertEqual(self.boundary(h, 'PLANNED', 'AUTHORIZED', None, plan)['status'], STATUS['OK'])
                reply = self.boundary(h, before, after, milestone, plan, ledger=ledger)
                self.assertEqual(reply['status'], STATUS['HALT'])
                fault = self.entry(h, reply['record'])
                checkpoint = self.entry(h, fault.content['evidence'])
                self.assertEqual((fault.kind, fault.content['decision'], fault.content['milestone']),
                                 ('fault', 'halt', milestone))
                self.assertEqual((checkpoint.kind, checkpoint.content['loss_cell'], checkpoint.content['milestone']),
                                 ('checkpoint', 'round-loss', milestone))
                self.assertLess(checkpoint.number, fault.number)
                self.assertTrue(h.state['halt_ordered'])
                self.assertEqual(h.call('CLOCK')['status'], STATUS['REFUSED'])

    def test_a_round_loss_acts_at_its_occurrence_only_and_once(self):
        h = self.harness([loss('third-progress', 'round', 'HEALTH_WINDOW_PROGRESS', occurrence=3)])
        for round_ in range(1, 4):
            reply = self.boundary(h, 'HEALTH_WINDOW', 'HEALTH_WINDOW', 'HEALTH_WINDOW_PROGRESS')
            self.assertEqual(reply['status'], STATUS['HALT'] if round_ == 3 else STATUS['OK'], round_)
        h.end(99)
        h.reopen()
        reply = self.boundary(h, 'HEALTH_WINDOW', 'HEALTH_WINDOW', 'HEALTH_WINDOW_PROGRESS')
        self.assertEqual(reply['status'], STATUS['OK'])
        self.assertEqual(self.entry(h, reply['record']).content['occurrence'], 4)
        self.assertEqual(len([e for e in h.entries('fault') if e.content['cell'] == 'third-progress']), 1)

    def test_a_round_loss_of_another_attempt_or_plan_does_not_act(self):
        h = self.harness([loss('other-attempt', 'round', 'READY', attempt=2),
                          loss('other-plan', 'round', 'READY', plan='02' * 16)])
        self.assertEqual(self.boundary(h, 'COMMIT_INTENT', 'READY', 'READY')['status'], STATUS['OK'])
        self.assertEqual(h.entries('fault'), [])



class ReadLossTests(LossBase):
    def observed(self, h, request_groups=None):
        """The group records of the last observation, in order."""
        last = h.entries('group')[-1].content['request']
        return [e for e in h.entries('group') if e.content.get('request') == last]

    def halt(self, h, state):
        reply = h.observe(state=labtest.state_code(state))
        self.assertEqual((reply['status'], reply['envelopes']), (STATUS['HALT'], []))
        fault = self.entry(h, reply['control_record'])
        self.assertEqual((fault.kind, fault.content['decision'], fault.content['operation']), ('fault', 'halt', 'OBSERVE'))
        self.assertIn(fault.content['cell'], h.broker.consumed)
        self.assertTrue(h.state['halt_ordered'])
        return reply, fault

    def test_a_read_loss_at_each_milestone_halts_after_its_selected_child(self):
        for milestone, state in READS.items():
            with self.subTest(milestone):
                h = self.harness([loss('read-loss', 'read', milestone, ordinal=1)])
                plan = REPAIR if milestone.startswith('REPAIR') else None
                self.put(h, state, plan, ledger=[] if state == 'SIGNED' else None)
                self.open_round(h)
                reply, fault = self.halt(h, state)
                groups = [self.entry(h, n) for n in fault.content['groups']]
                child = self.entry(h, fault.content['evidence'])
                self.assertEqual([g.content['reader'] for g in groups], ['boot', 'checkpoint'])
                self.assertEqual((child.number, child.content['read']['loss_cell'], child.content['status']),
                                 (groups[-1].number, 'read-loss', 'facts'))
                # The child's captures completed whole before the decision; nothing after it ran.
                for number in child.content['captures']:
                    self.assertEqual(self.entry(h, number).state, 'complete')
                    self.assertLess(number, fault.number)
                self.assertEqual([e for e in h.entries('capture') if e.number > child.number
                                  and e.content['intent'].get('request') == child.content['request']], [])

    def two_prepared_users(self, cells):
        """The system user prepared by its action, and a second running user whose typed
        preparation is seeded as the review's probe seeds it: an exact copy of the real one,
        assigned to that user with a fresh operation and challenge. No action creates or
        prepares a secondary user yet."""
        h = self.harness(cells)
        self.put(h, 'HEALTH_WINDOW', windowStart=h.sim.uptime)
        h.sim.tick(1000)
        self.assertEqual(h.broker.run_action(labtest.PREPARATION_ACTION, 'prepare the system user')['status'], 'OK')
        first = next(iter(h.broker.preparations))
        second = copy.deepcopy(h.broker.preparations[first])
        second['begin']['operation'] = '81' * 16
        second['begin']['challenge'] = '82' * 16
        second['begin']['resolved_user'].update(id=10, serial=100, type=lab_actions.SECONDARY_TYPE)
        h.broker.preparations[second['begin']['operation']] = second
        h.sim.prepared[10] = {'criteria': [2, 3, 5], 'challenge': second['begin']['challenge']}
        h.sim.users.append((10, 100, 'RUNNING_UNLOCKED'))
        h.sim.tick(1000)
        self.open_round(h)
        return h, first, second['begin']['operation']

    def test_a_health_loss_stops_at_its_selected_child_beside_a_second_prepared_user(self):
        # The honest control: without a loss both users' compositions are read and both
        # preparations are used.
        h, first, second = self.two_prepared_users([])
        reply = h.observe(state=labtest.state_code('HEALTH_WINDOW'))
        self.assertEqual(reply['status'], STATUS['OK'])
        self.assertEqual([g.content['user'] for g in h.entries('group') if g.content.get('reader') == 'health'],
                         [0, 10])
        self.assertTrue({first, second} <= h.broker.used_preparations)
        # The review's case: the loss selects the first completed composition, user 0's. The
        # decision follows that child at once: user 10 is never read and its preparation stays
        # unused.
        h, first, second = self.two_prepared_users([loss('first-health-loss', 'read', 'HEALTH_WINDOW_PROGRESS',
                                                         ordinal=lab_losses.HEALTH)])
        reply, fault = self.halt(h, 'HEALTH_WINDOW')
        child = self.entry(h, fault.content['evidence'])
        self.assertEqual((child.content['reader'], child.content['user']), ('health', 0))
        self.assertEqual(fault.number, child.number + 1)
        self.assertEqual([g.content['user'] for g in h.entries('group') if g.content.get('reader') == 'health'], [0])
        self.assertNotIn('sim:health 10', [c[0] for c in h.sim.calls])
        self.assertIn(first, h.broker.used_preparations)
        self.assertNotIn(second, h.broker.used_preparations)

    def test_each_reader_of_the_observation_can_be_selected(self):
        names = lab_losses.READERS
        for ordinal in range(len(names) - 1):
            with self.subTest(names[ordinal]):
                h = self.harness([loss('reader-loss', 'read', 'READY', ordinal=ordinal)])
                self.put(h, 'READY')
                self.open_round(h)
                reply, fault = self.halt(h, 'READY')
                readers = [self.entry(h, n).content['reader'] for n in fault.content['groups']]
                self.assertEqual(readers, list(names[:ordinal + 1]))
                self.assertEqual(self.entry(h, fault.content['evidence']).content['reader'], names[ordinal])
        # Health is read only in the window after a preparation: its first composition is the child.
        h = self.harness([loss('health-loss', 'read', 'HEALTH_WINDOW_PROGRESS', ordinal=lab_losses.HEALTH)])
        self.put(h, 'HEALTH_WINDOW', windowStart=h.sim.uptime)
        h.sim.tick(1000)
        self.assertEqual(h.broker.run_action(labtest.PREPARATION_ACTION, 'prepare a probe')['status'], 'OK')
        h.sim.tick(1000)
        self.open_round(h)
        reply, fault = self.halt(h, 'HEALTH_WINDOW')
        child = self.entry(h, fault.content['evidence']).content
        self.assertEqual((child['reader'], child['user'], child['read']['ordinal']), ('health', 0, lab_losses.HEALTH))

    def test_a_read_loss_counts_completed_runs_of_its_reader(self):
        h = self.harness([loss('second-active', 'read', 'READY', ordinal=3, occurrence=2)])
        self.put(h, 'READY')
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('READY'))['status'], STATUS['OK'])
        reply, fault = self.halt(h, 'READY')
        self.assertEqual((fault.content['occurrence'], self.entry(h, fault.content['evidence']).content['read']
                          ['occurrence']), (2, 2))

    def test_a_boot_change_before_the_selected_reader_keeps_the_loss_due(self):
        h = self.harness([loss('sessions-loss', 'read', 'READY', ordinal=4)])
        self.put(h, 'READY')
        self.open_round(h)
        h.sim.hooks.append(lambda command: command == 'sim:factory' and not h.sim.hooks.clear() and h.sim.reboot())
        reply = h.observe(state=labtest.state_code('READY'))
        self.assertEqual((reply['status'], h.entries('fault')), (STATUS['OK'], []))
        self.assertEqual(self.entry(h, h.entries('group')[-1].number).content['reason'], 'the boot changed')
        self.put(h, 'READY')
        h.end(0)
        self.open_round(h)
        reply, fault = self.halt(h, 'READY')
        self.assertEqual(self.entry(h, fault.content['evidence']).content['reader'], 'sessions')

    def test_a_stop_at_the_selected_reader_records_the_loss_not_acted(self):
        h = self.harness([loss('stopped-loss', 'read', 'READY', ordinal=2)])
        self.put(h, 'READY')
        self.open_round(h)
        stop = Path(h.admission['fences']['stop_file'])
        h.sim.hooks.append(lambda command: command == 'sim:checkpoint' and stop.write_text('stop\n'))
        reply = h.observe(state=labtest.state_code('READY'))
        self.assertEqual(reply['status'], STATUS['STOPPED'])
        decision = h.entries('fault')[-1].content
        self.assertEqual((decision['cell'], decision['decision']), ('stopped-loss', 'not-acted'))
        self.assertEqual(self.entry(h, decision['evidence']).content['status'], 'stopped')

    def test_a_broker_lost_after_the_selected_child_leaves_the_loss_not_acted(self):
        h = self.harness([loss('lost-loss', 'read', 'READY', ordinal=1)])
        self.put(h, 'READY')
        self.open_round(h)
        record = h.broker.ledger.record

        def lost(kind, value):
            if kind == 'fault':
                raise KeyboardInterrupt('the broker is lost before the decision')
            return record(kind, value)
        h.broker.ledger.record = lost
        with self.assertRaises(KeyboardInterrupt):
            h.observe(state=labtest.state_code('READY'))
        h.broker.close()
        h.open()
        decision = h.entries('fault')[-1].content
        self.assertEqual((decision['cell'], decision['decision']), ('lost-loss', 'not-acted'))
        self.assertEqual(self.entry(h, decision['evidence']).content['reader'], 'checkpoint')
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('READY'))['status'], STATUS['OK'])

    def test_a_read_loss_is_never_skipped_when_the_store_cannot_be_read(self):
        h = self.harness([loss('due-loss', 'read', 'READY', ordinal=1)])
        self.put(h, 'READY')
        (Path(h.admission['store']) / 'tickets' / (TICKET + '.rec')).write_bytes(b'not a ticket')
        self.open_round(h)
        reply = h.observe(state=labtest.state_code('READY'))
        self.assertEqual(reply['status'], STATUS['REFUSED'])
        self.assertIn('read address cannot be derived', reply['reason'])
        self.assertNotIn('due-loss', h.broker.consumed)
        # A state the store does not hold is no address either.
        self.put(h, 'READY')
        self.assertEqual(h.observe(state=labtest.state_code('APPLIED'))['status'], STATUS['REFUSED'])


class ScheduleTests(LossBase):
    def test_the_schedule_is_bound_by_its_digest_and_admitted_once(self):
        faults = [loss('read-loss', 'read', 'READY', ordinal=1), loss('round-loss', 'round', 'TERMINAL'),
                  {'cell': 'lose-create', 'on': 'cross', 'mode': 'loss-before', 'plan': PLAN, 'attempt': 2,
                   'crossing': 'CREATE', 'occurrence': 1}]
        h = self.harness(faults)
        record = h.entries('faults')[-1].content
        digest = hashlib.sha256(labtest.schedule(faults)).hexdigest()
        self.assertEqual((record['schedule_sha256'], [c['cell'] for c in record['cells']]),
                         (digest, ['read-loss', 'round-loss', 'lose-create']))
        self.assertEqual((h.root / 'records' / digest).read_bytes(), labtest.schedule(faults))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'admitted once'):
            h.broker.admit_schedule(labtest.schedule(faults))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'only from its bound schedule'):
            h.broker.admit_faults([faults[2]])
        bound = self.harness(fault_schedule_sha256=digest)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'not the one the admission binds'):
            bound.broker.admit_schedule(labtest.schedule(faults[:2]))
        bound.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'between generations'):
            bound.broker.admit_schedule(labtest.schedule(faults))
        bound.end(0)
        bound.broker.admit_schedule(labtest.schedule(faults))
        self.assertEqual(len(bound.broker.cells), 3)

    def test_malformed_foreign_and_wrongly_timed_faults_are_refused_before_any_effect(self):
        good = loss('a-loss', 'read', 'READY', ordinal=1)
        cases = {
            'an unknown key': [dict(good, extra=1)],
            'another operation': [dict(good, operation='ROUND_DONE')],
            'a round loss naming a reader': [dict(loss('r', 'round', 'READY'), ordinal=1)],
            'a read at the window entry': [loss('r', 'read', 'HEALTH_WINDOW_ENTRY')],
            'health read outside the window': [loss('r', 'read', 'READY', ordinal=lab_losses.HEALTH)],
            'a reader beyond the observation': [loss('r', 'read', 'READY', ordinal=8)],
            'a milestone of no known name': [loss('r', 'round', 'COMMIT_INTENT')],
            'no occurrence': [loss('r', 'round', 'READY', occurrence=0)],
            'a mode other than halt': [dict(good, mode='drop-reply')],
            'a cell name in upper case': [dict(good, cell='A-LOSS')],
            'a cell named twice': [good, dict(loss('a-loss', 'round', 'READY'))],
            'one address twice': [good, dict(good, cell='b-loss')],
            'a crossing of no known name': [{'cell': 'c', 'on': 'cross', 'mode': 'loss-before', 'plan': PLAN,
                                             'attempt': 1, 'crossing': 'SIGN', 'occurrence': 1}],
        }
        for name, faults in cases.items():
            with self.subTest(name), self.assertRaises(lab_broker.BrokerError):
                self.harness(faults)
        for name, value in (('another installation', labtest.schedule([good], installation='99' * 16)),
                            ('another schema', lab_evidence.canonical({'schema': 'x', 'profile': lab_actions.PROFILE,
                                                                       'installation': labtest.INSTALLATION,
                                                                       'faults': []})),
                            ('bytes of no canonical form', labtest.schedule([good]).replace(b',', b', '))):
            with self.subTest(name):
                h = self.harness(fault_schedule_sha256=hashlib.sha256(value).hexdigest())
                with self.assertRaises(lab_broker.BrokerError):
                    h.broker.admit_schedule(value)
                self.assertEqual(h.entries('faults'), [])
        # A receipt read without an admitted receipt reader.
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no receipt reader'):
            self.harness([loss('r', 'read', 'READY', ordinal=lab_losses.RECEIPTS)],
                         reader={'inventory': True, 'health': True, 'global_sessions': True})
        # A plan of another component in the store.
        faults = [good]
        h = self.harness(fault_schedule_sha256=hashlib.sha256(labtest.schedule(faults)).hexdigest())
        self.put(h, 'READY', plan={'component': 'com.android.settings'})
        with self.assertRaisesRegex(lab_broker.BrokerError, 'another installation or component'):
            h.broker.admit_schedule(labtest.schedule(faults))

    def test_a_fault_whose_address_has_passed_is_refused(self):
        for name, fault in (('a round loss', loss('late', 'round', 'READY')),
                            ('a read loss', loss('late', 'read', 'READY', ordinal=1)),
                            ('a crossing loss', {'cell': 'late', 'on': 'cross', 'mode': 'loss-before', 'plan': PLAN,
                                                 'attempt': 1, 'crossing': 'CREATE', 'occurrence': 1})):
            with self.subTest(name):
                data = labtest.schedule([fault])
                h = self.harness(fault_schedule_sha256=hashlib.sha256(data).hexdigest())
                self.boundary(h, 'COMMIT_INTENT', 'READY', 'READY')
                self.open_round(h)
                h.observe(state=labtest.state_code('READY'))
                h.cross('CREATE', 2, ticket_digest=hashlib.sha256((Path(h.admission['store']) / 'tickets' / (
                    TICKET + '.rec')).read_bytes()).hexdigest(), plan_digest=hashlib.sha256(labtest.plan_record())
                    .hexdigest())
                h.end(0)
                with self.assertRaisesRegex(lab_broker.BrokerError, 'already passed'):
                    h.broker.admit_schedule(data)
                self.assertEqual(h.broker.cells, [])


class BarrierTests(LossBase):
    def traced(self, cells):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        trace = labtest.SyncTrace(directory / 'broker')
        h = Harness(directory=directory, next_profile=True, sync=True, fsync=trace.fsync, cells=cells,
                    notice=sim_android.SimNotice(), health=sim_android.SimHealth())
        self.addCleanup(h.close)
        return h, trace

    def order(self, trace, path):
        """The event indexes of one record's barrier: its entry made, the entry's name synced in
        the ledger, the file created, written, synced, and its name synced in the entry."""
        entry = str(Path(path).parent)
        events = trace.events

        def index(kind, target):
            return next(i for i, e in enumerate(events) if e[0] == kind and e[-1] == target)
        return [index('mkdir', entry), next(i for i, e in enumerate(events) if e[0] == 'fsync-dir'
                                            and e[1] == str(Path(entry).parent) and i > index('mkdir', entry)),
                index('create', path), index('write', path), index('fsync-file', path),
                next(i for i, e in enumerate(events) if e[0] == 'fsync-dir' and e[1] == entry
                     and i > index('fsync-file', path))]

    def assert_durable_halt(self, h, trace, record, depends, cell):
        """Every record the halt depends on reached its barrier, in order, before the HALT, and a
        loss right after the HALT finds them; a loss before the decision's sync does not."""
        halt = trace.at('HALT')
        decision = str(h.root / 'ledger' / ('%06d-fault' % record) / 'record.json')
        steps = self.order(trace, decision)
        self.assertEqual(steps, sorted(steps))
        self.assertLess(steps[-1], halt)
        for path in depends:
            before = self.order(trace, path)
            self.assertEqual(before, sorted(before))
            self.assertLess(before[-1], steps[0])
        h.broker.close()
        image = trace.image('HALT', h.directory / 'image')
        reopened = h.open_at(image)
        try:
            c = reopened.ledger.entries[record - 1].content
            self.assertEqual((c['cell'], c['decision']), (cell, 'halt'))
            self.assertIn(cell, reopened.consumed)
            for path in depends:
                self.assertEqual(reopened.ledger.entries[int(Path(path).parent.name[:6]) - 1].state, 'complete')
        finally:
            reopened.close()
        trace.events.insert(steps[3] + 1, ('mark', 'EARLY'))
        early = h.open_at(trace.image('EARLY', h.directory / 'early'))
        try:
            self.assertNotEqual(early.ledger.entries[record - 1].state, 'complete')
            self.assertEqual(early.ledger.entries[-3].content['decision'], 'not-acted')
        finally:
            early.close()

    def test_a_round_loss_halts_only_after_its_checkpoint_and_decision_are_durable(self):
        h, trace = self.traced([loss('round-loss', 'round', 'READY')])
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        h.observe(state=labtest.state_code('COMMIT_INTENT'))
        self.put(h, 'READY')
        with trace:
            reply = h.round_done(milestone=CODE['READY'])
            trace.mark('HALT')
        self.assertEqual(reply['status'], STATUS['HALT'])
        checkpoint = self.entry(h, self.entry(h, reply['record']).content['evidence'])
        kept = [str(h.root / 'records' / checkpoint.content[name]) for name in ('ticket_sha256', 'selection_sha256',
                                                                              'plan_sha256')]
        # The retained bytes are durable before the checkpoint names them.
        point = str(checkpoint.path / 'record.json')
        for path in kept:
            renamed = [i for i, e in enumerate(trace.events) if e[0] == 'rename' and e[2] == path]
            synced = [i for i, e in enumerate(trace.events) if e[0] == 'fsync-dir' and e[1] == str(Path(path).parent)]
            if renamed:
                self.assertTrue(any(renamed[0] < i < self.order(trace, point)[2] for i in synced))
        self.assert_durable_halt(h, trace, reply['record'], [point], 'round-loss')

    def test_a_read_loss_halts_only_after_its_child_and_decision_are_durable(self):
        h, trace = self.traced([loss('read-loss', 'read', 'READY', ordinal=1)])
        self.put(h, 'READY')
        self.open_round(h)
        with trace:
            reply = h.observe(state=labtest.state_code('READY'))
            trace.mark('HALT')
        self.assertEqual(reply['status'], STATUS['HALT'])
        child = self.entry(h, self.entry(h, reply['control_record']).content['evidence'])
        captures = [str(self.entry(h, n).path / 'result.json') for n in child.content['captures']]
        self.assert_durable_halt(h, trace, reply['control_record'], captures + [str(child.path / 'record.json')],
                                 'read-loss')


class ReopenAfterLossTests(LossBase):
    def test_a_reopened_broker_after_a_read_or_round_loss_never_repeats_it(self):
        h = self.harness([loss('read-loss', 'read', 'READY', ordinal=0), loss('round-loss', 'round', 'READY')])
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        h.observe(state=labtest.state_code('COMMIT_INTENT'))
        self.put(h, 'READY')
        self.assertEqual(h.round_done(milestone=CODE['READY'])['status'], STATUS['HALT'])
        h.end(99)
        h.reopen()
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('READY'))['status'], STATUS['HALT'])
        h.end(99)
        h.reopen()
        self.assertEqual(h.broker.consumed, {'read-loss', 'round-loss'})
        self.assertEqual((h.broker.read_counts[(TICKET, 'READY', 0)], len(h.broker.checkpoints[TICKET])), (1, 1))
        reply = self.boundary(h, 'READY', 'READY', None)
        self.assertEqual((reply['status'], self.entry(h, reply['record']).content['ordinal']), (STATUS['OK'], 2))
        self.assertEqual([e.content['decision'] for e in h.entries('fault')], ['halt', 'halt'])

    def test_a_broker_lost_between_a_checkpoint_and_its_decision_records_the_loss_not_acted(self):
        h = self.harness([loss('round-loss', 'round', 'READY')])
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        h.observe(state=labtest.state_code('COMMIT_INTENT'))
        self.put(h, 'READY')
        record = h.broker.ledger.record

        def lost(kind, value):
            if kind == 'fault':
                raise KeyboardInterrupt('the broker is lost after the checkpoint')
            return record(kind, value)
        h.broker.ledger.record = lost
        with self.assertRaises(KeyboardInterrupt):
            h.round_done(milestone=CODE['READY'])
        h.broker.close()
        h.open()
        decision = h.entries('fault')[-1].content
        self.assertEqual((decision['decision'], self.entry(h, decision['evidence']).kind), ('not-acted', 'checkpoint'))
        self.assertEqual(h.entries('generation-end')[-1].content['status'], 'LOST')



class ConfirmationTests(LossBase):
    def test_an_honest_confirmation_reboots_once_and_settles_on_the_new_boot(self):
        h = self.harness()
        self.waiting(h)
        stored = (Path(h.admission['store']) / 'tickets' / (TICKET + '.rec')).read_bytes()
        old = h.sim.boot
        end = self.confirm(h)
        self.assertEqual((end['status'], end['settled'], end['outcome']['new_boot']), ('OK', True, h.sim.boot))
        self.assertNotEqual(h.sim.boot, old)
        begin, progress, done = self.transitions(h)
        self.assertEqual((begin['record'], begin['transition_kind'], begin['old']['boot'], begin['ordinal']),
                         ('BEGIN', 'CONFIRMATION', old, 1))
        self.assertEqual((begin['subject']['ticket'], begin['subject']['state'],
                          begin['subject']['predecessor_checkpoint']),
                         (TICKET, 'SESSION_INTENT', h.entries('checkpoint')[-1].number))
        self.assertEqual(begin['caps'], {'activation_services': 4, 'confirmation_services': 6, 'reboot_services': 10,
                                         'observed_boots': 13})
        self.assertEqual((progress['acknowledgement'], done['status'], done['new_boots']), ('accepted', 'OK', [h.sim.boot]))
        preflight = self.entry(h, begin['preflight']).content
        manifest = lab_evidence.parse((h.root / preflight['compound']['path']).read_bytes())
        self.assertEqual((preflight['reader'], preflight['status'], manifest['schema']),
                         ('confirmation-preflight', 'facts', 'andrix-confirmation-preflight-v1'))
        self.assertEqual(sorted(manifest['children']), ['active', 'boot', 'checkpoint', 'clock', 'factory',
                                                        'global-sessions', 'sessions'])
        # Its BEGIN is durable before the reboot's intent, and its effect is the reboot service.
        reboot = self.entry(h, progress['capture'])
        self.assertLess(h.entries('boot-transition')[0].number, reboot.number)
        self.assertEqual((reboot.content['intent']['command'], reboot.content['intent']['transition_kind']),
                         (lab_broker.REBOOT_LABEL, 'CONFIRMATION'))
        # No managed crossing, no store write: the ticket's own records decide later.
        self.assertEqual((h.entries('crossing'), (Path(h.admission['store']) / 'tickets' / (TICKET + '.rec'))
                          .read_bytes()), ([], stored))
        renewed = end['outcome']['renewed']
        self.assertEqual(sorted(renewed), ['active', 'factory', 'global-sessions', 'sessions', 'users'])
        self.assertTrue(all(r['status'] == 'facts' for r in renewed.values()))

    def test_an_uncommitted_session_is_no_bar_and_survives_the_boot(self):
        h = self.harness()
        session = sim_android.Session(77, sim_android.WALL_BASE + 5, labtest.NONCE)
        h.sim.sessions[77] = session
        self.waiting(h, 'COMMIT_INTENT')
        self.assertEqual(self.confirm(h)['status'], 'OK')
        self.assertEqual(session.state, 'OPEN')

    def test_no_reboot_beside_an_armed_unknown_or_foreign_session(self):
        def row(**changes):
            value = {'section': 'ACTIVE', 'id': 91, 'package': sim_android.PACKAGE, 'referrer': None, 'staged': True,
                     'multi_package': False, 'parent': -1, 'children': [], 'sealed': False, 'committed': False,
                     'ready': False, 'applied': False, 'failed': False, 'destroyed': False, 'created': 5,
                     'installer': 2000, 'cause': None}
            value.update(changes)
            return value
        cases = {'a ready session': ({'ready': True, 'committed': True, 'sealed': True}, 'committed, ready'),
                 'a verifying session': ({'committed': True, 'sealed': True}, 'committed, ready'),
                 'unknown commitment': ({'committed': None}, 'committed, ready or of unknown'),
                 'unknown end': ({'failed': None}, 'unknown'),
                 'a session of another package': ({'package': 'com.example.other'}, 'another package'),
                 'a family': ({'multi_package': True}, 'family'),
                 'a child of a parent': ({'parent': 90}, 'family'),
                 'an incomplete inventory': (None, 'not whole'),
                 'a SystemUI session the global inventory does not show': ('listing', 'disagree')}
        for name, (change, reason) in cases.items():
            with self.subTest(name):
                h = self.harness()
                self.waiting(h)
                if change is None:
                    h.sim.global_whole = False
                elif change == 'listing':
                    h.sim.sessions[78] = sim_android.Session(78, sim_android.WALL_BASE, labtest.NONCE)
                    h.sim.global_sessions = lambda: {'whole': True, 'sessions': []}
                else:
                    h.sim.foreign_sessions.append(row(**change))
                end = self.confirm(h)
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']), ('REFUSED', True, 0))
                self.assertIn(reason, end['uncertainty'])
                self.assertEqual(([c for c in h.sim.calls if c[0] == 'reboot'], self.transitions(h)), ([], []))
                preflight = [g.content for g in h.entries('group') if g.content['reader'] == 'confirmation-preflight']
                self.assertEqual((preflight[-1]['status'], preflight[-1]['reason']), ('refused', end['uncertainty']))
        # A terminal session of any package is no bar.
        h = self.harness()
        self.waiting(h)
        h.sim.foreign_sessions.append(row(package='com.example.other', section='HISTORICAL', committed=True,
                                          failed=True))
        self.assertEqual(self.confirm(h)['status'], 'OK')

    def test_a_confirmation_needs_its_ticket_waiting_as_its_boundary_recorded(self):
        cases = {'a ticket in no wait': ('READY', {}, None, 'not in a wait'),
                 'no recorded boundary': ('SESSION_INTENT', {}, 'no boundary', 'last recorded boundary'),
                 'a ticket changed since its boundary': ('SESSION_INTENT', {}, 'changed', 'last recorded boundary'),
                 'the boot limit': ('SESSION_INTENT', {'bootCount': 3}, None, 'boot limit'),
                 'the boot limit alert': ('SESSION_INTENT', {'flags': ('BOOT_LIMIT',)}, None, 'boot limit'),
                 'a pending checkpoint': ('SESSION_INTENT', {}, 'pending', 'COMMITTED')}
        for name, (state, changes, world, reason) in cases.items():
            with self.subTest(name):
                h = self.harness()
                if world == 'no boundary':
                    self.put(h, state, **changes)
                else:
                    self.waiting(h, state, **changes)
                if world == 'changed':
                    self.put(h, state, flags=('UNRESOLVED',))
                elif world == 'pending':
                    h.sim.checkpoint = 'PENDING'
                end = self.confirm(h)
                self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0), name)
                self.assertIn(reason, end['uncertainty'])
                self.assertEqual([c for c in h.sim.calls if c[0] == 'reboot'], [])

    def test_the_confirmation_and_observed_boot_allowances_are_kept(self):
        specs = labtest.default_specs() + [labtest.action_spec('0d' * 16, 'PLAIN_KERNEL_CONFIRM', phase='CELLS',
                                                               cell='b1-confirm')]
        h = self.harness(specs=specs, boot_policy=dict(labtest.BOOT_POLICY, confirmation_services=1))
        self.waiting(h)
        self.assertEqual(self.confirm(h)['status'], 'OK')
        h.reopen()
        end = self.confirm(h, '0d' * 16)
        self.assertEqual((end['status'], end['uncertainty']), ('REFUSED', 'the admitted 1 confirmation services are spent'))
        h = self.harness(boot_policy=dict(labtest.BOOT_POLICY, observed_boots=1))
        self.waiting(h)
        end = self.confirm(h)
        self.assertEqual(end['status'], 'REFUSED')
        self.assertIn('observed boots', end['uncertainty'])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'reboot'], [])

    def test_honest_prefixes_of_an_interrupted_confirmation(self):
        stop = lambda h: Path(h.admission['fences']['stop_file']).write_text('stop\n')  # noqa: E731
        # A stop before the BEGIN records nothing; one after the preflight, before the
        # transition, ends the action STOPPED with no transition; one after the durable BEGIN
        # sends no reboot; one during the send leaves the reboot with no poll.
        h = self.harness()
        self.waiting(h)
        stop(h)
        recorded = len(h.broker.ledger.entries)
        with self.assertRaises(lab_broker.Stopped):
            self.confirm(h)
        self.assertEqual([e.kind for e in h.broker.ledger.entries[recorded:]], ['stop'])
        h = self.harness()
        self.waiting(h)
        h.sim.hooks.append(lambda command: command == 'sim:global-sessions' and stop(h))
        with self.assertRaises(lab_broker.Stopped):
            self.confirm(h)
        self.assertEqual((self.transitions(h), [c for c in h.sim.calls if c[0] == 'reboot']), ([], []))
        self.assertEqual(h.entries('lab-action')[-1].content['status'], 'STOPPED')
        h = self.harness()
        self.waiting(h)
        record = h.broker.ledger.record

        def after_begin(kind, value):
            number = record(kind, value)
            if kind == 'boot-transition' and value['record'] == 'BEGIN':
                stop(h)
            return number
        h.broker.ledger.record = after_begin
        with self.assertRaises(lab_broker.Stopped):
            self.confirm(h)
        self.assertEqual([t['record'] for t in self.transitions(h)], ['BEGIN', 'END'])
        self.assertEqual((self.transitions(h)[-1]['status'], [c for c in h.sim.calls if c[0] == 'reboot']),
                         ('STOPPED', []))
        h = self.harness()
        self.waiting(h)
        h.sim.hooks.append(lambda command: command == lab_broker.REBOOT_LABEL and stop(h))
        with self.assertRaises(lab_broker.Stopped):
            self.confirm(h)
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'reboot']), 1)
        done = self.transitions(h)[-1]
        self.assertEqual((done['status'], done['new_boots'], len(done['polls'])), ('STOPPED', [], 1))
        self.assertTrue(done['polls'][0]['missing'].startswith('stopped'))
        self.assertEqual(self.entry(h, done['polls'][0]['groups'][0]).content['status'], 'stopped')

    def test_unavailable_polls_an_unfinished_boot_and_a_pending_checkpoint_are_waits(self):
        h = self.harness()
        self.waiting(h)
        state = {'polls': 0}

        def booting(command):
            if command == 'sim:clock' and h.sim.boots > 1:
                state['polls'] += 1
                h.sim.boot_completed = state['polls'] > 3
                h.sim.checkpoint = 'COMMITTED' if state['polls'] > 4 else 'PENDING'
        h.sim.hooks.append(booting)
        h.sim.scripts['adb service reboot:'] = []
        h.sim.next_instance = 17
        old_instance = h.sim.instance
        disconnected = ['before', 'before']
        h.sim.scripts['sim:clock'] = []
        h.sim.hooks.append(lambda command: command == lab_broker.REBOOT_LABEL and h.sim.scripts['sim:clock'].extend(
            disconnected))
        end = self.confirm(h)
        self.assertEqual(end['status'], 'OK')
        polls = self.transitions(h)[-1]['polls']
        reasons = [p['missing'] for p in polls]
        self.assertTrue(reasons[0].startswith('the clock is unavailable'))
        self.assertIn('the new boot is not read completed', reasons)
        self.assertIn('the checkpoint is pending or unknown: a read only wait', reasons)
        self.assertIsNone(reasons[-1])
        # A lower framework tick on the new boot is honest.
        self.assertLess(end['outcome']['instance'], old_instance)

    def test_no_new_boot_within_the_bound_or_a_second_boot_holds_every_crossing(self):
        h = self.harness(boot_policy=dict(labtest.BOOT_POLICY, settle_ms=20_000))
        self.waiting(h)
        h.sim.reboot = lambda: None
        end = self.confirm(h)
        self.assertEqual((end['status'], end['settled']), ('UNKNOWN', False))
        self.assertEqual(self.transitions(h)[-1]['status'], 'UNKNOWN')
        self.assertTrue(all(p['missing'] == 'the same boot: no new boot is observed yet'
                            for p in self.transitions(h)[-1]['polls']))
        self.open_round(h)
        store = Path(h.admission['store'])
        reply = h.cross('CREATE', 2, ticket_digest=hashlib.sha256((store / 'tickets' / (TICKET + '.rec')).read_bytes())
                        .hexdigest(), plan_digest=hashlib.sha256(labtest.plan_record()).hexdigest())
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('unsettled', reply['reason'])
        h = self.harness()
        self.waiting(h)
        state = {'polls': 0}

        def twice(command):
            if command == 'sim:clock' and h.sim.boots > 1:
                state['polls'] += 1
                if state['polls'] == 2:
                    h.sim.new_boot()
        h.sim.checkpoint = 'COMMITTED'
        h.sim.hooks.append(twice)
        h.sim.boot_completed = True
        real = h.sim.new_boot

        def slow_settle():
            real()
            h.sim.checkpoint = 'PENDING' if state['polls'] < 2 else 'COMMITTED'
        h.sim.new_boot = slow_settle
        end = self.confirm(h)
        self.assertEqual((end['status'], end['settled']), ('UNEXPECTED', False))
        self.assertEqual(len(self.transitions(h)[-1]['new_boots']), 2)

    def test_a_broker_lost_in_the_reboot_never_sends_it_again(self):
        h = self.harness()
        self.waiting(h)

        def lost(command):
            if command == lab_broker.REBOOT_LABEL:
                raise KeyboardInterrupt('the broker is lost while the reboot is sent')
        h.sim.hooks.append(lost)
        with self.assertRaises(KeyboardInterrupt):
            self.confirm(h)
        h.sim.hooks.clear()
        h.broker.close()
        h.open()
        quarantine = h.entries('quarantine')[-1].content
        self.assertEqual((quarantine['launched'], quarantine['intent']['command']), ('unknown', lab_broker.REBOOT_LABEL))
        self.assertEqual((self.transitions(h)[-1]['status'], h.entries('lab-action')[-1].content['status']),
                         ('LOST', 'LOST'))
        self.assertTrue(h.clock.slept)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            self.confirm(h)
        self.assertEqual([c for c in h.sim.calls if c[0] == 'reboot'], [])

    def test_the_withdrawn_framework_restart_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as directory:
            specs = labtest.default_specs()
            specs[0] = dict(specs[0], type='FRAMEWORK_RESTART', phase='F0',
                            preconditions=['WHOLE_LISTING', 'NO_COMMITTED_SESSION'])
            with self.assertRaisesRegex(lab_broker.BrokerError, 'withdrawn from this profile'):
                lab_broker.check_admission(labtest.admission3(directory, specs=specs))
            for wrong in ({'phase': 'A'}, {'parameters': {'ticket': TICKET}}):
                specs = labtest.default_specs()
                specs[0] = dict(specs[0], **wrong)
                with self.assertRaises(lab_broker.BrokerError):
                    lab_broker.check_admission(labtest.admission3(directory, specs=specs))


class FenceTests(LossBase):
    DIGESTS = None

    def crossing(self, h, name, index, attempt=1, ticket=TICKET, **changes):
        """A managed crossing naming the stored records, the ticket's written first if missing."""
        store = Path(h.admission['store'])
        if not (store / 'tickets' / (ticket + '.rec')).exists():
            self.put(h, 'WRITTEN', ticket=ticket, attempt=attempt)
        digests = {'ticket_digest': hashlib.sha256((store / 'tickets' / (ticket + '.rec')).read_bytes()).hexdigest(),
                   'plan_digest': hashlib.sha256((store / 'plans' / (PLAN + '.rec')).read_bytes()).hexdigest()}
        return h.cross(name, index, attempt=attempt, ticket=ticket, **dict(digests, **changes))

    def commits(self, h):
        return [c for c in h.sim.calls if c[0] == 'COMMIT']

    def test_a_managed_commit_launches_nothing_before_a_qualified_f0_whatever_its_fault(self):
        m0 = {'cell': 'm0-commit', 'on': 'cross', 'mode': 'loss-before', 'plan': PLAN, 'attempt': 1,
              'crossing': 'COMMIT', 'occurrence': 1}
        h = self.harness([m0])
        self.put(h, 'WRITTEN')
        self.open_round(h)
        self.assertEqual(self.crossing(h, 'CREATE', 2)['status'], STATUS['OK'])
        # The fault present: its admitted halt launches nothing.
        reply = self.crossing(h, 'COMMIT', 3)
        self.assertEqual(reply['status'], STATUS['HALT'])
        h.end(99)
        # The fault consumed: the fence refuses, nothing launched, no native reply invented.
        self.open_round(h)
        reply = self.crossing(h, 'COMMIT', 3, ticket='06' * 16)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('no managed COMMIT launches before F0 qualifies', reply['reason'])
        outcome = h.entries('outcome')[-1].content
        self.assertEqual((outcome['status'], outcome['reply'], outcome['captures']), ('NO_REPLY', None, []))
        # The fault absent.
        h2 = self.harness()
        self.put(h2, 'WRITTEN')
        self.open_round(h2)
        self.crossing(h2, 'CREATE', 2)
        self.assertEqual(self.crossing(h2, 'COMMIT', 3)['status'], STATUS['NO_REPLY'])
        self.assertEqual((self.commits(h), self.commits(h2)), ([], []))
        # A qualified F0 lifts the fence for a managed COMMIT.
        h2.end(0)
        h2.broker.record_f0(labtest.f0_record('FULL'), 'F0 qualified')
        self.open_round(h2)
        self.assertEqual(self.crossing(h2, 'COMMIT', 4, ticket='07' * 16)['status'], STATUS['OK'])
        self.assertEqual(len(self.commits(h2)), 1)

    def test_a_refused_f0_leaves_the_positive_attempt_uncreated_and_unarmed(self):
        h = self.harness()
        positive = labtest.POSITIVE_ATTEMPT
        with self.assertRaisesRegex(lab_broker.BrokerError, 'uncreated and unarmed'):
            h.broker.gate_positive(PLAN, positive, 'before F0')
        h.broker.record_f0(labtest.f0_record('REFUSED'), 'F0 refused')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'uncreated and unarmed'):
            h.broker.gate_positive(PLAN, positive, 'after a refused F0')
        gates = [e.content for e in h.entries('qualification') if e.content['record'] == 'GATE']
        self.assertEqual([g['allowed'] for g in gates], [False, False])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'not the positive attempt'):
            h.broker.gate_positive(PLAN, 5, 'another attempt')
        # Should it exist anyway, nothing serves it.
        self.put(h, 'PUBLISHED', attempt=positive)
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('PUBLISHED'))['status'], STATUS['REFUSED'])
        h.end(2)
        self.open_round(h)
        reply = self.crossing(h, 'CREATE', 2, attempt=positive)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('uncreated and unarmed', reply['reason'])
        reply = h.call('HOST', phase=1, crossing=1, ticket=TICKET, plan=PLAN, attempt=positive, index=0,
                       occurrence=1, reference='9b' * 16, outcome=0, reply=proto.ZERO_DIGEST)
        self.assertEqual(reply['status'], STATUS['REFUSED'])
        self.assertEqual([c for c in h.sim.calls if c[0] in ('CREATE', 'COMMIT', 'reboot')], [])

    def test_f0_is_decided_once_and_only_as_admitted(self):
        h = self.harness()
        for record, reason in ((labtest.f0_record('LIMITED'), 'does not admit'),
                               (labtest.f0_record('FULL', installation='99' * 16), 'another schema'),
                               (labtest.f0_record('FULL').replace(b'}', b' }'), 'canonical'),
                               (lab_evidence.canonical({'schema': 'x', 'profile': lab_actions.PROFILE,
                                                        'installation': labtest.INSTALLATION, 'branch': 'FULL'}),
                                'another schema')):
            with self.assertRaisesRegex(lab_broker.BrokerError, reason):
                h.broker.record_f0(record, 'a decision')
        h.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'between generations'):
            h.broker.record_f0(labtest.f0_record('FULL'), 'during a generation')
        h.end(0)
        decision = h.broker.record_f0(labtest.f0_record('FULL'), 'F0 qualified')
        self.assertEqual((decision['branch'], decision['qualified'], decision['predicate_sha256']),
                         ('FULL', True, 'd1' * 32))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'decided once'):
            h.broker.record_f0(labtest.f0_record('REFUSED'), 'again')
        h.reopen()
        self.assertTrue(h.broker._f0_qualified())
        limited = self.harness(branches=dict(labtest.admission3('/x')['branches'],
                                             LIMITED={'predicate_sha256': 'd3' * 32, 'actions': []}))
        self.assertTrue(limited.broker.record_f0(labtest.f0_record('LIMITED'), 'limited')['qualified'])

    def direct(self, roles=('N2', 'N3')):
        h = self.harness(specs=labtest.default_specs() + labtest.direct_specs(roles))
        h.pin_payloads(roles)
        return h

    def step(self, h, role, kind):
        return h.broker.run_action(labtest.DIRECT_IDS[(role, kind)], '%s %s' % (role, kind))

    def test_an_honest_n2_n3_direct_sequence_commits_before_f0_and_a_managed_commit_does_not(self):
        h = self.direct()
        for role in ('N2', 'N3'):
            control = labtest.N2_CONTROL if role == 'N2' else labtest.N3_CONTROL
            self.assertEqual(self.step(h, role, 'DIRECT_STAGE')['status'], 'OK')
            h.broker.consent(control, 'the lab may arm and activate %s' % role)
            self.assertEqual(self.step(h, role, 'DIRECT_COMMIT')['status'], 'OK')
            # The same moment, a managed COMMIT launches nothing.
            self.put(h, 'WRITTEN')
            self.open_round(h)
            reply = self.crossing(h, 'COMMIT', 3, ticket={'N2': '07', 'N3': '08'}[role] * 16)
            self.assertEqual(reply['status'], STATUS['NO_REPLY'])
            self.assertIn('no managed COMMIT launches before F0 qualifies', reply['reason'])
            h.end(0)
            end = self.step(h, role, 'NEGATIVE_ACTIVATION')
            self.assertEqual((end['status'], end['settled']), ('OK', True))
            transition = h.broker.transitions[end['outcome']['transition']]
            self.assertEqual((transition['begin']['transition_kind'], transition['begin']['subject']['consent']),
                             ('NEGATIVE_ACTIVATION', h.broker.consents[control]['number']))
            self.assertEqual(end['outcome']['active'], 'FACTORY_COPY')
        failed = sorted((s.cause, 'base.apk.idsig' in s.members) for s in h.sim.sessions.values())
        self.assertEqual(failed, [('FS_VERITY', False), ('SIGNATURE', True)])
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'COMMIT']), 2)
        self.assertEqual([c[1] for c in h.sim.calls if c[0] == 'CREATE'], [labtest.N2_CONTROL, labtest.N3_CONTROL])
        self.assertEqual(h.sim.active[0], 'FACTORY_COPY')
        h.broker.record_f0(labtest.f0_record('FULL'), 'F0 after N3')
        self.open_round(h)
        self.assertEqual(self.crossing(h, 'CREATE', 2, ticket='09' * 16)['status'], STATUS['OK'])
        self.assertEqual(self.crossing(h, 'COMMIT', 3, ticket='09' * 16)['status'], STATUS['OK'])
        self.assertEqual(len(self.commits(h)), 3)

    def test_the_direct_exception_has_its_own_gates_and_order(self):
        h = self.direct()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'predecessor'):
            self.step(h, 'N2', 'DIRECT_COMMIT')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'predecessor'):
            self.step(h, 'N3', 'DIRECT_STAGE')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'not an admitted direct'):
            h.broker.consent('99' * 16, 'no such control')
        self.step(h, 'N2', 'DIRECT_STAGE')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no consent'):
            self.step(h, 'N2', 'DIRECT_COMMIT')
        h.broker.consent(labtest.N2_CONTROL, 'arm N2')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'once'):
            h.broker.consent(labtest.N2_CONTROL, 'again')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'predecessor'):
            self.step(h, 'N2', 'NEGATIVE_ACTIVATION')
        # Before F0 only: a decided F0 refuses every later direct step.
        self.assertEqual(self.step(h, 'N2', 'DIRECT_COMMIT')['status'], 'OK')
        h.broker.f0 = {'record': 'DECISION', 'qualified': False}
        with self.assertRaisesRegex(lab_broker.BrokerError, 'only before F0'):
            self.step(h, 'N2', 'NEGATIVE_ACTIVATION')
        h.broker.f0 = None
        # A payload of other bytes is never pinned; the admission refuses one of the wrong role.
        bare = self.harness(specs=labtest.default_specs() + labtest.direct_specs(('N2',)))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'admitted digest'):
            bare.broker.pin_payload(labtest.N2_CONTROL, {m: {'host': '/x', 'sha256': '00' * 32, 'bytes': 1}
                                                         for m in ('base.apk', 'base.apk.idsig')})
        with tempfile.TemporaryDirectory() as directory:
            for name, specs in (('N3 with a sidecar', labtest.direct_specs(('N2',)) + [
                    dict(s, parameters=dict(s['parameters'], role='N3', control=labtest.N3_CONTROL), phase='N3')
                    for s in labtest.direct_specs(('N2',))]),
                                ('N3 without N2', labtest.direct_specs(('N3',))),
                                ('a commit used twice', [dict(s, max_uses=2) for s in labtest.direct_specs(('N2',))])):
                with self.subTest(name), self.assertRaises(lab_broker.BrokerError):
                    lab_broker.check_admission(labtest.admission3(directory, specs=labtest.default_specs() + specs))

    def test_a_direct_commit_arms_nothing_on_an_incomplete_inventory(self):
        # The review's case beside its control: the admitted N2 stage, its pinned payload and
        # consent, then a global inventory that says it is whole or that it is not.
        for whole in (True, False):
            with self.subTest(whole=whole):
                h = self.direct(('N2',))
                self.assertEqual(self.step(h, 'N2', 'DIRECT_STAGE')['status'], 'OK')
                h.broker.consent(labtest.N2_CONTROL, 'consent to N2')
                h.sim.global_whole = whole
                end = self.step(h, 'N2', 'DIRECT_COMMIT')
                if whole:
                    self.assertEqual((end['status'], len(self.commits(h))), ('OK', 1))
                    continue
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']),
                                 ('REFUSED', True, 0))
                self.assertIn('not whole', end['uncertainty'])
                self.assertEqual(self.commits(h), [])

    def test_a_reopened_fence_restores_f0_only_from_its_kept_capability_record(self):
        """The fence's qualification comes back on reopening only when the kept capability record
        still makes the decision the ledger records."""
        def history(branch='FULL'):
            h = self.harness()
            decision = h.broker.record_f0(labtest.f0_record(branch), 'retain the capability record')
            h.broker.close()
            return h, h.root / 'records' / decision['capabilities_sha256']

        # The intact control reopens qualified and launches its one managed COMMIT.
        h, _ = history()
        h.open()
        self.assertTrue(h.broker._f0_qualified())
        self.open_round(h)
        self.assertEqual(self.crossing(h, 'CREATE', 2)['status'], STATUS['OK'])
        self.assertEqual(self.crossing(h, 'COMMIT', 3)['status'], STATUS['OK'])
        self.assertEqual(len(self.commits(h)), 1)
        # The review's case, the kept record changed, then the record gone, and a REFUSED
        # record whose decision the ledger was changed to call FULL: each refuses the reopening.
        cases = {
            'changed': ('FULL', lambda h, kept: kept.write_bytes(b'not the retained F0 record')),
            'gone': ('FULL', lambda h, kept: kept.unlink()),
            'a decision its record does not make': ('REFUSED', lambda h, kept: ChangedCopyTests.rewrite(
                h.root, 'qualification', lambda c: c.update(branch='FULL', qualified=True,
                                                             predicate_sha256='d1' * 32))),
        }
        for name, (branch, change) in cases.items():
            with self.subTest(name):
                h, kept = history(branch)
                change(h, kept)
                with self.assertRaisesRegex(lab_broker.BrokerError, 'F0 decision'):
                    h.open()
                self.assertEqual(self.commits(h), [])

    def test_direct_steps_launch_nothing_past_their_effect_caps(self):
        """A direct step's guest commands are action effects: the admitted cap of their class and
        of their phase, counted from the ledger, refuses a step past it with nothing launched."""
        phases = dict(labtest.effect_limits()['phases'], N2=0)
        for name, limits in (('class', dict(labtest.effect_limits(), direct=0)),
                             ('phase', dict(labtest.effect_limits(), phases=phases))):
            with self.subTest(name):
                h = self.harness(specs=labtest.default_specs() + labtest.direct_specs(('N2',)), effect_limits=limits)
                h.pin_payloads(('N2',))
                end = self.step(h, 'N2', 'DIRECT_STAGE')
                self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
                self.assertIn('spent', end['uncertainty'])
                self.assertEqual(self.commits(h) + [c for c in h.sim.calls if c[0] == 'CREATE'], [])

    def test_a_managed_session_relabeled_as_direct_gets_no_exception(self):
        h = self.direct(('N2',))
        self.step(h, 'N2', 'DIRECT_STAGE')
        h.broker.consent(labtest.N2_CONTROL, 'arm N2')
        session = next(s for s in h.sim.sessions.values() if s.control == labtest.N2_CONTROL)
        session.control, session.nonce = None, labtest.NONCE
        end = self.step(h, 'N2', 'DIRECT_COMMIT')
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertIn('no single live session of the control', end['uncertainty'])
        self.assertEqual(self.commits(h), [])

    def test_an_activation_that_does_not_reject_is_unexpected_and_holds_everything(self):
        h = self.direct(('N2',))
        h.sim.wrong_signer.clear()
        self.step(h, 'N2', 'DIRECT_STAGE')
        h.broker.consent(labtest.N2_CONTROL, 'arm N2')
        self.step(h, 'N2', 'DIRECT_COMMIT')
        end = self.step(h, 'N2', 'NEGATIVE_ACTIVATION')
        self.assertEqual((end['status'], end['settled']), ('UNEXPECTED', True))
        self.assertIn('no safe recovery', end['uncertainty'])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'before F0'):
            h.broker.record_f0(labtest.f0_record('FULL'), 'F0')
        self.put(h, 'WRITTEN')
        self.open_round(h)
        self.assertIn('unsettled or unexpected', self.crossing(h, 'CREATE', 2)['reason'])

    def test_no_activation_beside_another_armed_session(self):
        h = self.direct(('N2',))
        self.step(h, 'N2', 'DIRECT_STAGE')
        h.broker.consent(labtest.N2_CONTROL, 'arm N2')
        self.step(h, 'N2', 'DIRECT_COMMIT')
        h.sim.sessions[5] = sim_android.Session(5, sim_android.WALL_BASE, labtest.NONCE, state='READY')
        end = self.step(h, 'N2', 'NEGATIVE_ACTIVATION')
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertIn('another live session', end['uncertainty'])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'reboot'], [])


class WriterLatchTests(LossBase):
    """A failed write or sync of the evidence this change keeps latches the writer's stop, as the
    compound writer's does: nothing it would have recorded is recorded, and no later command or
    effect starts, after a reopening too. Each case stands beside its honest control."""

    def stopped(self, h):
        self.assertIn('the evidence writer failed', h.broker.stopped)
        self.assertEqual(len(h.entries('stop')), 1)

    def test_a_failed_keep_at_a_boundary_stops_and_records_no_checkpoint_or_loss(self):
        # The honest control: the same boundary keeps its bytes, checkpoints and halts by its loss.
        h = self.harness([loss('round-loss', 'round', 'READY')])
        reply = self.boundary(h, 'COMMIT_INTENT', 'READY', 'READY')
        self.assertEqual(reply['status'], STATUS['HALT'])
        checkpoint = self.checkpoints(h)[-1]
        self.assertEqual(checkpoint['round_start']['source'], 'observe')
        for digest in (checkpoint['round_start']['sha256'], checkpoint['ticket_sha256']):
            self.assertEqual(hashlib.sha256((h.root / 'records' / digest).read_bytes()).hexdigest(), digest)
        self.assertIsNone(h.broker.stopped)
        # The first sync of the records directory fails while the boundary keeps its bytes.
        h = self.harness([loss('round-loss', 'round', 'READY')])
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('COMMIT_INTENT'))['status'], STATUS['OK'])
        self.put(h, 'READY')
        calls = len(h.sim.calls)
        with failing_sync(h.root) as failures:
            reply = h.round_done(milestone=CODE['READY'])
        self.assertTrue(failures)
        self.assertEqual((reply['status'], reply['record']), (STATUS['STOPPED'], 0))
        self.assertIn('the evidence writer failed', reply['reason'])
        self.stopped(h)
        self.assertEqual((self.checkpoints(h), h.entries('fault')), ([], []))
        self.assertNotIn('round-loss', h.broker.consumed)
        # Nothing follows: not in this generation, not in the next, not after a reopening.
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual(h.end(125)['status'], 'STOPPED')
        for reopened in (False, True):
            if reopened:
                h.reopen()
            h.begin()
            self.assertEqual(h.hello()['status'], STATUS['STOPPED'])
            h.end(125)
        self.assertEqual(h.sim.calls[calls:], [])
        self.assertEqual((self.checkpoints(h), h.entries('fault')), ([], []))

    def test_a_failed_keep_of_a_confirmations_issuing_records_stops_before_any_reboot(self):
        # The honest control: the confirmation keeps its issuing records and reboots once.
        h = self.harness()
        self.waiting(h)
        self.assertEqual(self.confirm(h)['status'], 'OK')
        self.assertIsNone(h.broker.stopped)
        h = self.harness()
        self.waiting(h)
        ticket = hashlib.sha256((Path(h.admission['store']) / 'tickets' / (TICKET + '.rec')).read_bytes()).hexdigest()
        with failing_keep(h.broker, {ticket}) as failures:
            with self.assertRaisesRegex(lab_broker.Stopped, 'the evidence writer failed'):
                self.confirm(h)
        self.assertEqual(failures, [ticket])
        self.stopped(h)
        end = [e.content for e in h.entries('lab-action') if e.content['record'] == 'END'][-1]
        self.assertEqual((end['status'], end['settled']), ('STOPPED', False))
        self.assertEqual((self.transitions(h), [c for c in h.sim.calls if c[0] == 'reboot']), ([], []))
        h.reopen()
        with self.assertRaisesRegex(lab_broker.Stopped, 'the evidence writer failed'):
            h.broker.run_action(labtest.PREPARATION_ACTION, 'an effect after the failed keep')
        self.assertEqual([c for c in h.sim.calls if c[0] in ('reboot', 'prepare')], [])

    def test_a_failed_keep_of_f0_or_the_schedule_stops_and_records_neither(self):
        # The honest controls: F0 and the schedule are each kept and recorded.
        record = labtest.f0_record('FULL')
        h = self.harness()
        self.assertTrue(h.broker.record_f0(record, 'F0 qualified')['qualified'])
        data = labtest.schedule([loss('round-loss', 'round', 'READY')])
        bound = hashlib.sha256(data).hexdigest()
        h = self.harness(fault_schedule_sha256=bound)
        h.broker.admit_schedule(data)
        self.assertEqual([c['cell'] for c in h.broker.cells], ['round-loss'])
        # F0's capability record cannot be kept: no decision, and the fence stays.
        h = self.harness()
        with failing_keep(h.broker, {hashlib.sha256(record).hexdigest()}):
            with self.assertRaisesRegex(lab_broker.Stopped, 'the evidence writer failed'):
                h.broker.record_f0(record, 'F0 qualified')
        self.stopped(h)
        self.assertEqual((h.broker.f0, h.entries('qualification')), (None, []))
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['STOPPED'])
        h.end(125)
        # The schedule cannot be kept: no fault is admitted.
        h = self.harness(fault_schedule_sha256=bound)
        with failing_keep(h.broker, {bound}):
            with self.assertRaisesRegex(lab_broker.Stopped, 'the evidence writer failed'):
                h.broker.admit_schedule(data)
        self.stopped(h)
        self.assertEqual((h.broker.cells, h.entries('faults')), ([], []))
        h.reopen()
        self.assertEqual((h.broker.schedule, h.broker.cells), (None, []))
        self.assertIn('the evidence writer failed', h.broker.stopped)


class PointTests(LossBase):
    """At the coordinator's selection-written point, between its selection and ticket writes, an
    admitted halt first keeps the store as the point left it: the old ticket and the new
    selection, which the fault record names. Versions 1 and 2 keep their record's form."""
    POINT = {'cell': 'between', 'on': 'point', 'mode': 'halt', 'plan': PLAN, 'attempt': 1,
             'point': 'selection-written'}
    KEYS = {'cell', 'on', 'decision', 'ticket', 'plan', 'point', 'request', 'generation'}

    def point(self, h, ticket=TICKET):
        return h.call('POINT', point='selection-written', ticket=ticket, plan=PLAN, attempt=1)

    def stored(self, h, directory, name):
        return (Path(h.admission['store']) / directory / (name + '.rec'))

    @staticmethod
    def kept(h):
        return set(os.listdir(h.root / 'records')) if (h.root / 'records').exists() else set()

    def test_a_point_keeps_the_old_ticket_and_the_new_selection_before_its_halt(self):
        h = self.harness([dict(self.POINT)])
        self.put(h, 'PUBLISHED')
        self.stored(h, 'selections', sim_android.PACKAGE).write_bytes(b'selection record, revision 1')
        old = self.stored(h, 'tickets', TICKET).read_bytes()
        new = self.stored(h, 'selections', sim_android.PACKAGE).read_bytes()
        self.open_round(h)
        reply = self.point(h)
        self.assertEqual(reply['status'], STATUS['HALT'])
        fault = self.entry(h, reply['record']).content
        self.assertEqual(set(fault), self.KEYS | {'ticket_sha256', 'selection_sha256', 'number', 'kind'})
        self.assertEqual((fault['ticket_sha256'], fault['selection_sha256']),
                         (hashlib.sha256(old).hexdigest(), hashlib.sha256(new).hexdigest()))
        # The ticket the next generation writes changes nothing kept.
        self.put(h, 'SESSION_INTENT')
        for digest, data in ((fault['ticket_sha256'], old), (fault['selection_sha256'], new)):
            self.assertEqual((h.root / 'records' / digest).read_bytes(), data)
        h.end(99)
        h.reopen()
        self.assertIn('between', h.broker.consumed)
        h.begin()
        h.hello()
        self.assertEqual(self.point(h)['status'], STATUS['OK'])
        h.end(0)
        # A kept copy that is gone refuses the reopening.
        h.broker.close()
        (h.root / 'records' / fault['selection_sha256']).unlink()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not keep'):
            h.open()

    def test_a_point_that_cannot_keep_its_records_does_not_halt(self):
        # The honest control: no admitted cell, so the point is OK and keeps nothing.
        h = self.harness()
        self.put(h, 'PUBLISHED')
        self.open_round(h)
        kept = self.kept(h)
        self.assertEqual(self.point(h)['status'], STATUS['OK'])
        self.assertEqual(self.kept(h), kept)
        # Records it cannot read whole, or a stored ticket of another attempt: refused, with
        # nothing kept or consumed.
        for name, change in (('no selection', lambda h: self.stored(h, 'selections', sim_android.PACKAGE).unlink()),
                             ('another attempt', lambda h: self.put(h, 'PUBLISHED', attempt=2))):
            with self.subTest(name):
                h = self.harness([dict(self.POINT)])
                self.put(h, 'PUBLISHED')
                change(h)
                self.open_round(h)
                reply = self.point(h)
                self.assertEqual((reply['status'], reply['record']), (STATUS['REFUSED'], 0))
                self.assertIn('the point does not halt', reply['reason'])
                self.assertEqual((h.entries('fault'), sorted(h.broker.consumed)), ([], []))
        # A failed sync of the kept bytes latches the writer: no halt, no fault, nothing follows.
        h = self.harness([dict(self.POINT)])
        self.put(h, 'PUBLISHED')
        self.open_round(h)
        calls = len(h.sim.calls)
        with failing_sync(h.root) as failures:
            reply = self.point(h)
        self.assertTrue(failures)
        self.assertEqual((reply['status'], reply['record']), (STATUS['REFUSED'], 0))
        self.assertIn('the evidence writer failed', reply['reason'])
        self.assertIn('the evidence writer failed', h.broker.stopped)
        self.assertEqual((h.entries('fault'), sorted(h.broker.consumed)), ([], []))
        self.assertEqual(self.point(h)['status'], STATUS['REFUSED'])
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual(h.sim.calls[calls:], [])

    def test_versions_1_and_2_keep_their_point_record(self):
        cell = dict(self.POINT)
        for version, changes in ((1, {}), (2, {'version': 2, 'lab_actions': {'framework-restart': 1},
                                               'launches': ['CREATE', 'WRITE', 'ABANDON'],
                                               'store': '/nonexistent-store'})):
            with self.subTest(version=version):
                h = Harness(cells=[cell], **changes)
                self.addCleanup(h.close)
                h.begin()
                h.hello()
                reply = self.point(h)
                self.assertEqual(reply['status'], STATUS['HALT'])
                fault = h.broker.ledger.entries[reply['record'] - 1].content
                self.assertEqual(set(fault) - {'number', 'kind'}, self.KEYS)
                self.assertEqual(self.kept(h), set())


class ChangedCopyTests(LossBase):
    def history(self):
        """One broker with every new record: losses, a checkpoint, a confirmation, both direct
        controls, consents and F0."""
        faults = [loss('round-loss', 'round', 'READY'), loss('read-loss', 'read', 'READY', ordinal=0)]
        h = self.harness(faults, specs=labtest.default_specs() + labtest.direct_specs())
        self.put(h, 'COMMIT_INTENT')
        self.open_round(h)
        h.observe(state=labtest.state_code('COMMIT_INTENT'))
        self.put(h, 'READY')
        self.assertEqual(h.round_done(milestone=CODE['READY'])['status'], STATUS['HALT'])
        h.end(99)
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('READY'))['status'], STATUS['HALT'])
        h.end(99)
        self.waiting(h, 'COMMIT_INTENT')
        self.assertEqual(self.confirm(h)['status'], 'OK')
        h.pin_payloads()
        for role, control in (('N2', labtest.N2_CONTROL), ('N3', labtest.N3_CONTROL)):
            h.broker.run_action(labtest.DIRECT_IDS[(role, 'DIRECT_STAGE')], 'stage')
            h.broker.consent(control, 'arm')
            h.broker.run_action(labtest.DIRECT_IDS[(role, 'DIRECT_COMMIT')], 'commit')
            self.assertEqual(h.broker.run_action(labtest.DIRECT_IDS[(role, 'NEGATIVE_ACTIVATION')], 'activate')
                             ['status'], 'OK')
        h.broker.record_f0(labtest.f0_record('FULL'), 'F0')
        h.broker.close()
        return h

    def copy(self, h):
        target = Path(tempfile.mkdtemp()) / 'broker'
        self.addCleanup(shutil.rmtree, target.parent, True)
        shutil.copytree(h.root, target)
        return target

    @staticmethod
    def kept(root):
        """The ticket bytes the last checkpoint kept."""
        last = sorted(p for p in (root / 'ledger').iterdir() if p.name.endswith('-checkpoint'))[-1]
        return json.loads((last / 'record.json').read_text())['ticket_sha256']

    @staticmethod
    def rewrite(root, kind, change, which=-1):
        entries = sorted(p for p in (root / 'ledger').iterdir() if p.name.endswith('-' + kind))
        path = entries[which] / 'record.json'
        value = json.loads(path.read_text())
        change(value)
        path.write_bytes(capture_ledger.encode_json(value))

    @staticmethod
    def append(root, kind, which=-1, change=None):
        entries = sorted(p for p in (root / 'ledger').iterdir() if p.is_dir())
        source = sorted(p for p in entries if p.name.endswith('-' + kind))[which]
        value = json.loads((source / 'record.json').read_text())
        value['number'] = len(entries) + 1
        if change:
            change(value)
        target = root / 'ledger' / ('%06d-%s' % (value['number'], kind))
        target.mkdir()
        (target / 'record.json').write_bytes(capture_ledger.encode_json(value))

    def test_a_changed_schedule_summary_never_moves_an_admitted_fault(self):
        # The review's case beside its control: a checkpoint read loss admitted at occurrence 2.
        # Intact, the first read is OK and the second halts.
        h = self.harness([loss('second-checkpoint-read', 'read', 'READY', ordinal=1, occurrence=2)])
        h.reopen()
        self.assertEqual(h.broker.cells[0]['occurrence'], 2)
        self.put(h, 'READY')
        self.open_round(h)
        self.assertEqual(h.observe(state=labtest.state_code('READY'))['status'], STATUS['OK'])
        self.assertEqual(h.observe(state=labtest.state_code('READY'))['status'], STATUS['HALT'])
        # Only the ledger's summary changed: the occurrence moved to 1, or the summary named no
        # schedule. Each refuses the reopening, so no read halts at an unadmitted address.
        for name, change in (('a moved occurrence', lambda c: c['cells'][0].update(occurrence=1)),
                             ('no schedule named', lambda c: c.pop('schedule_sha256'))):
            with self.subTest(name):
                h = self.harness([loss('second-checkpoint-read', 'read', 'READY', ordinal=1, occurrence=2)])
                h.broker.close()
                self.rewrite(h.root, 'faults', change)
                with self.assertRaisesRegex(lab_broker.BrokerError, 'schedule'):
                    h.open()

    def test_changed_copies_of_each_new_record_refuse_the_reopening(self):
        h = self.history()
        honest = h.open_at(self.copy(h))
        honest.close()

        def keep_key(name, value):
            return lambda c: c.__setitem__(name, value)
        cases = {
            'a checkpoint out of its sequence': (lambda r: self.rewrite(r, 'checkpoint', keep_key('ordinal', 5)),
                                                 'out of its ticket'),
            'a checkpoint naming other bytes': (lambda r: self.rewrite(r, 'checkpoint',
                                                                       keep_key('ticket_sha256', 'ab' * 32)),
                                                'did not keep'),
            'a checkpoint whose kept bytes are gone': (lambda r: (r / 'records' / self.kept(r)).unlink(),
                                                       'did not keep'),
            'a checkpoint of no known milestone': (lambda r: self.rewrite(r, 'checkpoint',
                                                                          keep_key('milestone', 'LATER')),
                                                   'no known milestone'),
            'a checkpoint with another key': (lambda r: self.rewrite(r, 'checkpoint', keep_key('extra', 1)),
                                              'no known form'),
            'a loss consumed twice': (lambda r: self.append(r, 'fault'), 'consumed twice'),
            'a loss decided without its evidence': (lambda r: self.rewrite(r, 'fault', keep_key('evidence', 1)),
                                                    'named it due'),
            'a loss of no admitted cell': (lambda r: self.rewrite(r, 'fault', keep_key('cell', 'other')),
                                           'no admitted cell'),
            'a transition ended twice': (lambda r: self.append(r, 'boot-transition'), 'after its END'),
            'a transition of no known kind': (lambda r: self.rewrite(r, 'boot-transition',
                                                                     keep_key('transition_kind', 'RESTART'), 0),
                                              'no known kind'),
            'an END of no BEGIN': (lambda r: self.rewrite(r, 'boot-transition', keep_key('transition', 'ee' * 16)),
                                   'without its BEGIN'),
            'a consent given twice': (lambda r: self.append(r, 'consent'), 'given twice'),
            'a direct step of no admitted control': (lambda r: self.rewrite(r, 'direct-control',
                                                                            keep_key('control', 'ee' * 16)),
                                                     'no admitted control'),
            'a second F0 decision': (lambda r: self.append(r, 'qualification'), 'second or unknown F0'),
            'a schedule the admission does not bind': (lambda r: self.rewrite(r, 'faults',
                                                                              keep_key('schedule_sha256', 'ab' * 32),
                                                                              0), 'does not bind'),
        }
        for name, (mutate, reason) in cases.items():
            with self.subTest(name):
                root = self.copy(h)
                mutate(root)
                with self.assertRaisesRegex(lab_broker.BrokerError, reason):
                    h.open_at(root).close()


if __name__ == '__main__':
    unittest.main()
