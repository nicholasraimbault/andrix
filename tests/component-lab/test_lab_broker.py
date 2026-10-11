# SPDX-License-Identifier: Apache-2.0
"""The broker on a simulated guest: generations, fences, groups, typed crossings, fault cells,
escrow, replay refusal and reopening. Host evidence only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
import unittest.mock

import labtest
from labtest import GRANT, NONCE, PLAN, TICKET, Harness, read_observation
import lab_broker
import lab_protocol as proto
import lab_readers
import sim_android
import source_manifest

STATUS = proto.STATUSES


def cell(name, on='cross', mode='drop-reply', **key):
    value = {'cell': name, 'on': on, 'mode': mode, 'plan': PLAN, 'attempt': 1}
    value.update(key)
    return value


class Base(unittest.TestCase):
    def harness(self, **options):
        h = Harness(**options)
        self.addCleanup(h.close)
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['OK'])
        return h

    def created(self, h):
        """A session created through the broker, as the ticket binds it."""
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['OK'])
        return h.bound()

    def mutations(self, h):
        return [c for c in h.sim.calls if c[0] in ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'reboot')]


class GenerationTests(Base):
    def test_hello_binds_the_admitted_configuration(self):
        h = Harness()
        self.addCleanup(h.close)
        for change in ({'installation': '99' * 16}, {'coordinator': 'c1' * 16}, {'config': '3d' * 32},
                       {'trust': '7b' * 32}, {'component': 'com.android.settings'}):
            h.begin()
            reply = h.hello(**change)
            self.assertEqual(reply['status'], STATUS['REFUSED'], change)
            self.assertIsNotNone(h.state['violation'])
            h.end(1)
        h.begin()
        reply = h.hello()
        self.assertEqual((reply['status'], reply['generation'], reply['target']), (STATUS['OK'], 6, 1))

    def test_requests_before_hello_and_of_another_manifest_are_refused(self):
        h = Harness()
        self.addCleanup(h.close)
        h.begin()
        self.assertEqual(h.clock_read()['status'], STATUS['REFUSED'])
        h.end(1)
        h.begin()
        self.assertEqual(h.call('HELLO', manifest='ab' * 32, installation=labtest.INSTALLATION,
                                coordinator=labtest.COORDINATOR, config=labtest.CONFIG,
                                component=sim_android.PACKAGE, trust=labtest.TRUST, route=1)['status'],
                         STATUS['REFUSED'])
        self.assertEqual(h.entries('capture'), [])

    def test_a_target_scope_that_is_not_established_launches_nothing(self):
        h = self.harness(target_scope='UNKNOWN')
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertEqual(self.mutations(h), [])
        self.assertIn('target scope', reply['reason'])

    def test_one_writer_holds_the_ledger(self):
        h = Harness()
        self.addCleanup(h.close)
        with self.assertRaises(lab_broker.BrokerError):
            lab_broker.Broker.open(h.root, labtest.REPO, sim_android.SimTransport(h.sim),
                                   sim_android.SimReader(labtest.INSTALLATION))

    def test_other_source_bytes_refuse_the_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / 'tree'
            for name in labtest.LAB_FILES:
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(labtest.REPO / name, tree / name)
            h = Harness()
            self.addCleanup(h.close)
            h.broker.close()
            same = lab_broker.Broker.open(h.root, tree, sim_android.SimTransport(h.sim),
                                          sim_android.SimReader(labtest.INSTALLATION), sync=False)
            self.assertEqual(same.admission['manifest'], h.manifest)
            same.close()
            with open(tree / labtest.LAB_FILES[0], 'a') as handle:
                handle.write('# changed\n')
            with self.assertRaises(lab_broker.BrokerError):
                lab_broker.Broker.open(h.root, tree, sim_android.SimTransport(h.sim),
                                       sim_android.SimReader(labtest.INSTALLATION), sync=False)
            h.open()

    def test_generation_ends_are_classified(self):
        h = self.harness(cells=[cell('p', on='point', mode='halt', point='selection-written')])
        self.assertEqual(h.call('POINT', point='selection-written', ticket=TICKET, plan=PLAN, attempt=1)['status'],
                         STATUS['HALT'])
        self.assertEqual(h.end(99)['status'], 'DELIBERATE_HALT')
        h.begin()
        h.hello()
        self.assertEqual(h.end(99)['status'], 'FAILED')
        h.begin()
        h.hello()
        self.assertEqual(h.end(0)['status'], 'COMPLETE')
        h.begin()
        h.hello()
        self.assertEqual(h.broker.end_served(h.state, None, 9)['status'], 'KILLED')

    def test_a_request_after_a_halt_order_is_refused(self):
        h = self.harness(cells=[cell('p', on='point', mode='halt', point='selection-written')])
        h.call('POINT', point='selection-written', ticket=TICKET, plan=PLAN, attempt=1)
        self.assertEqual(h.clock_read()['status'], STATUS['REFUSED'])
        self.assertEqual(h.entries('capture'), [])


class IntentTests(Base):
    def test_every_command_finds_its_intent_in_the_ledger_first(self):
        h = self.harness()
        launched = []

        def check(command):
            last = labtest.lab_broker.ledgers.scan(h.root / 'ledger')[-1]
            intent = last.content['intent']
            recorded = 'push ' + intent['path'] if intent['operation'] == 'push' else intent['command']
            self.assertEqual((last.kind, last.state, recorded), ('capture', 'interrupted', command))
            launched.append(command)
        h.sim.hooks.append(check)
        h.clock_read()
        h.observe()
        self.created(h)
        h.cross('WRITE', 3)
        h.cross('COMMIT', 4)
        h.cross('REBOOT', 5, entry_instance=-1)
        # 1 clock, 6 observation groups, CREATE 3, COMMIT 3, REBOOT 2, and WRITE 12: the preflight's 2,
        # 4 to stage both members, and before each member the gate's clock and session readback and
        # its write.
        self.assertEqual(len(launched), 27)
        self.assertEqual(launched[-1], 'adb service reboot:')
        self.assertIn('pm install-commit --staged-ready-timeout 60000 %d' % h.bound()[1], launched)


class FeatureTests(Base):
    def test_a_device_without_shell_protocol_v2_stops_everything(self):
        h = self.harness()
        h.sim.features = ('cmd', 'stat_v2')
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual(h.cross('CREATE', 2)['status'], STATUS['STOPPED'])
        self.assertEqual([c for c in h.sim.calls if c[0] != 'features'], [])
        self.assertEqual(h.entries('stop')[0].content['reason'], 'the device does not offer shell protocol v2')

    def test_unreadable_features_launch_nothing_and_are_asked_again(self):
        h = self.harness()
        h.sim.features = None
        self.assertEqual(h.clock_read()['status'], STATUS['UNAVAILABLE'])
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('nothing launched', reply['reason'])
        self.assertEqual([c[0] for c in h.sim.calls], ['features', 'features'])
        h.sim.features = ('shell_v2',)
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])
        self.assertEqual([c[0] for c in h.sim.calls], ['features', 'features', 'features'])
        self.assertEqual(h.entries('stop'), [])


class FenceTests(Base):
    def test_the_stop_fence_comes_before_every_read_and_latches(self):
        h = self.harness()
        stop = Path(h.admission['fences']['stop_file'])

        def appear(command):
            if command == 'sim:checkpoint':
                stop.write_text('stop\n')
        h.sim.hooks.append(appear)
        reply = h.observe()
        self.assertEqual(reply['status'], STATUS['STOPPED'])
        commands = [e.content['intent']['command'] for e in h.entries('capture')]
        self.assertEqual(commands, ['host-serial:127.0.0.1:6520:features', 'sim:boot', 'sim:checkpoint'])
        self.assertEqual(len(h.entries('stop')), 1)
        stop.unlink()
        captured = len(h.entries('capture'))
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual(h.cross('CREATE', 2)['status'], STATUS['STOPPED'])
        self.assertEqual(len(h.entries('capture')), captured)
        self.assertEqual(self.mutations(h), [])
        h.end(125)
        h.reopen()
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['STOPPED'])
        self.assertEqual(len(h.entries('capture')), captured)

    def test_the_lease_and_the_deadline_are_fences(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = Path(directory) / 'lease'
            lease.write_text('runtime-7\n')
            fences = {'stop_file': str(Path(directory) / 'STOP'), 'lease_file': str(lease),
                      'lease_token': 'runtime-7', 'deadline_wall_ns': 1_791_504_000_000_000_000 + 10 ** 12}
            h = self.harness(fences=fences)
            self.assertEqual(h.clock_read()['status'], STATUS['OK'])
            lease.write_text('runtime-8\n')
            self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
            self.assertEqual(h.entries('stop')[0].content['reason'], 'the lease is not held')
            lease.write_text('runtime-7\n')
            self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        h = self.harness(fences={'stop_file': '/nonexistent/STOP', 'lease_file': None, 'lease_token': None,
                                 'deadline_wall_ns': 1_791_504_000_000_000_000 + 5})
        h.clock.wall += 10
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual(h.entries('stop')[0].content['reason'], 'the runtime deadline passed')


class FenceDuringFeaturesTests(Base):
    def test_a_fence_that_trips_during_the_feature_query_stops_the_next_command(self):
        for kind in ('stop', 'lease', 'deadline'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                lease = Path(directory) / 'lease'
                lease.write_text('runtime-7\n')
                stop = Path(directory) / 'STOP'
                fences = {'stop_file': str(stop), 'lease_file': str(lease), 'lease_token': 'runtime-7',
                          'deadline_wall_ns': labtest.Clock().wall + 10 ** 12}
                h = self.harness(fences=fences)
                features = h.broker.transport.features

                def trip(timeout, h=h, kind=kind, lease=lease, stop=stop):
                    value = features(timeout)
                    if kind == 'stop':
                        stop.write_text('stop\n')
                    elif kind == 'lease':
                        lease.write_text('runtime-8\n')
                    else:
                        h.clock.wall += 10 ** 13
                    return value
                h.broker.transport.features = trip
                self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
                commands = [e.content['intent']['command'] for e in h.entries('capture')]
                self.assertEqual(commands, ['host-serial:127.0.0.1:6520:features'])
                self.assertEqual(len(h.entries('stop')), 1)
                self.assertEqual(h.cross('CREATE', 2)['status'], STATUS['STOPPED'])
                self.assertEqual(len(h.entries('capture')), 1)
                self.assertEqual(self.mutations(h), [])


class GroupTests(Base):
    def test_a_clock_is_one_recorded_group_on_the_observation_scale(self):
        h = self.harness()
        reply = h.clock_read()
        self.assertEqual((reply['status'], reply['boot'], reply['instance'], reply['elapsed']),
                         (STATUS['OK'], h.sim.boot, h.sim.instance, h.sim.uptime))
        group = h.broker.ledger.entries[reply['group'] - 1]
        self.assertEqual(group.kind, 'group')
        captures = [h.broker.ledger.entries[n - 1] for n in group.content['captures']]
        self.assertEqual([c.content['intent']['command'] for c in captures], ['sim:clock'])
        raw = lab_readers.raw_digest([(c.content['intent']['command'], c.content['result']['exit'],
                                       c.content['stdout'], c.content['stderr']) for c in captures])
        self.assertEqual(group.content['raw'], raw)

    def test_an_incomplete_read_is_unavailable_never_a_status(self):
        h = self.harness()
        h.sim.scripts['sim:clock'] = ['before']
        reply = h.clock_read()
        self.assertEqual(reply['status'], STATUS['UNAVAILABLE'])
        capture = h.entries('capture')[-1].content['result']
        self.assertEqual((capture['completion'], capture['exit'], capture['transport']),
                         ('eof-before-exit', None, 'closed'))

    def test_a_lost_read_never_reads_as_no_framework(self):
        class PidofReader(sim_android.SimReader):
            """A clock that reads no framework from pidof's quiet failure, as the observer does."""

            def clock(self):
                value = self._read('sim:clock')
                code, out, err = self._run('pidof system_server')
                instance = -1 if (code, out, err) == (1, '', '') else value['instance']
                return value['boot'], instance, value['elapsed'], 1
        h = self.harness()
        h.broker.reader = PidofReader(labtest.INSTALLATION)
        h.sim.framework = False
        self.assertEqual(h.clock_read()['instance'], -1)
        h.sim.framework = True
        h.sim.scripts['pidof system_server'] = ['before']
        reply = h.clock_read()
        self.assertEqual(reply['status'], STATUS['UNAVAILABLE'])
        self.assertIn('did not complete', reply['reason'])

    def test_observations_name_their_group_and_raw_digest(self):
        h = self.harness()
        reply = h.observe(scope='COMPONENT')
        self.assertEqual(reply['status'], STATUS['OK'])
        kinds = [read_observation(frame)['kind'] for _, frame in reply['frames']]
        self.assertEqual(kinds, [1, 2, 3, 4])
        for group, frame in reply['frames']:
            entry = h.broker.ledger.entries[group - 1]
            fact = read_observation(frame)
            self.assertEqual(fact['raw'], entry.content['raw'])
            self.assertIn(fact['observation'], [o['id'] for o in entry.content['observations']])
            self.assertEqual(hashlib.sha256(frame).hexdigest(),
                             [o['sha256'] for o in entry.content['observations'] if o['id'] == fact['observation']][0])
        reply = h.observe()
        self.assertEqual([read_observation(f)['kind'] for _, f in reply['frames']], [1, 2, 3, 4, 5, 8])

    def test_facts_of_another_boot_are_refused(self):
        h = self.harness()
        reply = h.observe(boot='ab' * 16)
        self.assertEqual((reply['status'], reply['frames']), (STATUS['OK'], []))
        groups = h.entries('group')
        self.assertEqual(groups[-1].content['reason'], 'the boot changed')
        self.assertEqual(len(groups), 1)

    def test_the_uptime_scale_never_goes_back(self):
        h = self.harness()
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])
        h.sim.uptime -= 5000
        reply = h.clock_read()
        self.assertEqual(reply['status'], STATUS['UNAVAILABLE'])
        self.assertIn('went back', reply['reason'])

    def test_a_removed_user_is_reported_once_from_the_ledger(self):
        h = self.harness()
        h.sim.users = [(0, 0, 'RUNNING_UNLOCKED'), (10, 11, 'RUNNING_LOCKED')]
        h.observe()
        h.sim.users = [(0, 0, 'RUNNING_UNLOCKED')]
        h.end(0)
        h.reopen()
        h.begin()
        h.hello()
        frames = [read_observation(f) for _, f in h.observe()['frames']]
        removed = [f for f in frames if f['kind'] == 8 and f['user'] == 10]
        self.assertEqual([(f['serial'], f['classification']) for f in removed], [(11, 4)])
        frames = [read_observation(f) for _, f in h.observe()['frames']]
        self.assertEqual([f for f in frames if f['kind'] == 8 and f['user'] == 10], [])


class CrossingTests(Base):
    def test_create_replies_with_the_reference_joined_in_its_framework_instance(self):
        h = self.harness()
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['OK'])
        fact = read_observation(reply['frame'])
        session = [s for s in h.sim.sessions.values() if s.nonce == NONCE][0]
        self.assertEqual((fact['kind'], fact['classification'], fact['ticket'], fact['index'], fact['crossing']),
                         (7, 1, TICKET, 2, 3))
        self.assertEqual(fact['reference'], (31, session.identity, session.created,
                                             '/data/app-staging/session_%d' % session.identity, 2000, NONCE))
        self.assertEqual((fact['boot'], fact['instance'], fact['route']), (h.sim.boot, h.sim.instance, 1))
        mutations = [e.content['intent']['command'] for e in h.entries('capture')
                     if e.content['intent']['operation'] == 'mutation']
        self.assertEqual(mutations, ['pm install-create --user 0 -r --pkg com.android.systemui --staged '
                                     '--referrer andrix-ticket:' + NONCE])

    def test_create_without_a_join_carries_the_id_alone(self):
        h = self.harness()
        h.sim.scripts['sim:sessions'] = ['before']
        fact = read_observation(h.cross('CREATE', 2)['frame'])
        self.assertEqual(fact['reference'][:2], (1, h.bound()[1]))
        self.assertEqual(fact['reference'][2:], (0, '', 0, proto.ZERO_ID))

    def test_an_entry_is_crossed_once(self):
        h = self.harness()
        self.assertEqual(h.cross('CREATE', 2)['status'], STATUS['OK'])
        captured = len(h.entries('capture'))
        self.assertEqual(h.cross('CREATE', 2)['status'], STATUS['REFUSED'])
        self.assertEqual(len(h.entries('capture')), captured)
        self.assertEqual([c[0] for c in self.mutations(h)], ['CREATE'])

    def test_an_incomplete_reply_is_no_reply_and_unknown_effect(self):
        h = self.harness()
        h.sim.scripts['pm install-create'] = ['after']
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('effect is unknown', reply['reason'])
        self.assertEqual([c[0] for c in self.mutations(h)], ['CREATE'])

    def test_preflight_refuses_a_changed_boot_or_framework(self):
        h = self.harness()
        entry_instance = h.sim.instance
        h.sim.framework_restart()
        reply = h.cross('CREATE', 2, entry_instance=entry_instance)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('framework instance changed', reply['reason'])
        old_boot = h.sim.boot
        h.sim.new_boot()
        reply = h.cross('REBOOT', 5, entry_boot=old_boot, entry_instance=-1)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('boot changed', reply['reason'])
        self.assertEqual(self.mutations(h), [])

    def test_write_stages_and_writes_each_member_in_its_own_capture(self):
        h = self.harness()
        self.created(h)
        reply = h.cross('WRITE', 3)
        self.assertEqual(reply['status'], STATUS['OK'])
        self.assertEqual(read_observation(reply['frame'])['classification'], 1)
        crossing = [e.number for e in h.entries('crossing')][-1]
        captures = [e for e in h.entries('capture') if e.content['intent'].get('crossing') == crossing]
        operations = [(e.content['intent']['operation'], e.content['intent'].get('member')) for e in captures]
        self.assertEqual([o for o in operations if o[0] in ('push', 'mutation')],
                         [('push', 'base.apk'), ('push', 'base.apk.idsig'), ('mutation', 'base.apk'),
                          ('mutation', 'base.apk.idsig')])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'WRITE'],
                         [('WRITE', h.bound()[1], 'base.apk'), ('WRITE', h.bound()[1], 'base.apk.idsig')])

    def test_write_refuses_an_unpinned_bundle_and_a_staged_member_that_differs(self):
        h = self.harness()
        self.created(h)
        self.assertEqual(h.cross('WRITE', 3, bundle_apk='ee' * 32)['status'], STATUS['NO_REPLY'])
        h2 = self.harness()
        self.created(h2)

        def corrupt(command):
            if command.startswith('sha256sum') and command.endswith('base.apk'):
                path = command.split(' ', 1)[1]
                h2.sim.files[path] = b'other bytes'
        h2.sim.hooks.append(corrupt)
        reply = h2.cross('WRITE', 3)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('does not read back exactly', reply['reason'])
        self.assertEqual([c for c in h2.sim.calls if c[0] == 'WRITE'], [])

    def test_session_crossings_confirm_the_exact_reference_first(self):
        h = self.harness()
        native = self.created(h)
        reused = (native[0], native[1], native[2] + 1, native[3], native[4], '77' * 16)
        for crossing, index in (('WRITE', 3), ('COMMIT', 4), ('ABANDON', 5)):
            reply = h.cross(crossing, index, native=reused)
            self.assertEqual(reply['status'], STATUS['NO_REPLY'], crossing)
            self.assertIn('another session', reply['reason'])
        self.assertEqual([c[0] for c in self.mutations(h)], ['CREATE'])

    def test_commit_forms(self):
        cases = (
            (sim_android.result('x', 0, b'Success. Reboot device to apply staged session\n'), 3),
            (sim_android.result('x', 0, b'Success\n'), 4),
            (sim_android.result('x', 1, b"Failure [timed out after 60000 ms]. Ending this command now but session is still "
                                        b"being staged asynchronously. Use 'pm list staged-sessions' to check the session "
                                        b"status later.\n"), 5),
            (sim_android.result('x', 0, b'Success. Reboot device to apply staged session\n', b'warning\n'), 6),
            (sim_android.result('x', 1, b''), 6),
        )
        for scripted, code in cases:
            h = self.harness()
            self.created(h)
            h.cross('WRITE', 3)
            h.sim.scripts['pm install-commit'] = [lambda command, r=scripted: r]
            reply = h.cross('COMMIT', 4)
            self.assertEqual(read_observation(reply['frame'])['classification'], code)
        h = self.harness()
        self.created(h)
        h.cross('WRITE', 3)
        h.sim.scripts['pm install-commit'] = ['timeout']
        self.assertEqual(h.cross('COMMIT', 4)['status'], STATUS['NO_REPLY'])

    def test_abandon_waits_when_the_session_cannot_be_targeted(self):
        h = self.harness()
        native = self.created(h)
        h.sim.sessions[native[1]].state = 'ABANDONED'
        reply = h.cross('ABANDON', 3)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertEqual([c[0] for c in self.mutations(h)], ['CREATE'])

    def test_a_reboot_has_its_own_acknowledgement_and_no_reply(self):
        h = self.harness()
        boot = h.sim.boot
        reply = h.cross('REBOOT', 5, entry_instance=-1)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertNotEqual(h.sim.boot, boot)
        capture = h.entries('capture')[-1].content
        self.assertEqual((capture['intent']['operation'], capture['result']['acknowledgement']), ('reboot', 'accepted'))
        self.assertNotIn('exit', capture['result'])

    def test_notice_needs_an_admitted_route(self):
        h = self.harness()
        reply = h.cross('NOTICE', 1, entry_instance=-1, native=proto.NO_REFERENCE)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('no notice route', reply['reason'])


class Notice:
    """A notice route stand in: one fixed command and its own exact form."""

    def allowed(self, command):
        return command == 'sim:notice'

    def notice(self, run, ticket, index, plan):
        result = run('sim:notice')
        if not result.completed:
            raise lab_readers.Unavailable('the notice did not complete')
        return 'SUCCESS' if result.exit == 0 and result.stdout == b'notice shown\n' else 'UNRECOGNIZED'


class GateTests(Base):
    def wall(self, h):
        return sim_android.WALL_BASE + h.sim.uptime

    def written(self, h, ticket):
        """A session created and written for one ticket, ready to commit."""
        reply = h.cross('CREATE', 2, ticket=ticket)
        self.assertEqual(reply['status'], STATUS['OK'])
        self.assertEqual(h.cross('WRITE', 3, ticket=ticket)['status'], STATUS['OK'])

    def test_an_activation_grant_is_judged_again_at_launch(self):
        h = self.harness()
        cases = (('expired', lambda w: (w - 10_000, 5_000), 'NO_REPLY'),
                 ('given later', lambda w: (w + 60_000, 10 ** 9), 'NO_REPLY'),
                 ('valid', lambda w: (w - 1_000, 10 ** 9), 'OK'))
        for at, (name, grant, expected) in enumerate(cases):
            with self.subTest(case=name):
                h.sim.sessions.clear()
                ticket = '%02x' % (0x40 + at) * 16
                self.written(h, ticket)
                commits = len([c for c in h.sim.calls if c[0] == 'COMMIT'])
                granted, window = grant(self.wall(h))
                reply = h.cross('COMMIT', 4, ticket=ticket, granted_at=granted, window=window)
                self.assertEqual(reply['status'], STATUS[expected], reply['reason'])
                launched = len([c for c in h.sim.calls if c[0] == 'COMMIT']) - commits
                self.assertEqual(launched, 1 if expected == 'OK' else 0)
                if expected != 'OK':
                    self.assertIn('activation grant', reply['reason'])

    def test_a_grant_that_expires_during_the_preflight_launches_nothing(self):
        h = self.harness()
        self.written(h, TICKET)
        granted = self.wall(h) - 4_000

        def later(command):
            if command == 'sim:clock':
                h.sim.tick(2_000)
        h.sim.hooks.append(later)
        # Valid when the request was built, expired at the preflight's own clock reading.
        reply = h.cross('COMMIT', 4, granted_at=granted, window=5_000)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('activation grant', reply['reason'])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'COMMIT'], [])
        for crossing, index in (('REBOOT', 5),):
            reply = h.cross(crossing, index, entry_instance=-1, granted_at=granted, window=5_000)
            self.assertEqual(reply['status'], STATUS['NO_REPLY'])
            self.assertEqual([c for c in h.sim.calls if c[0] == 'reboot'], [])

    def test_the_launch_deadline_follows_the_reconcilers_rule(self):
        deadline = lab_broker.activation_deadline
        # Expired before its grant time, and from its grant time plus its window on.
        self.assertIsNone(deadline(999, 0, 1_000, 5_000))
        self.assertIsNone(deadline(6_000, 0, 1_000, 5_000))
        self.assertIsNone(deadline(7_000, 0, 1_000, 5_000))
        # Valid at its grant time, until the host clock has advanced by what the window has left.
        self.assertEqual(deadline(1_000, 0, 1_000, 5_000), 5_000 * 1_000_000)
        self.assertEqual(deadline(5_999, 7, 1_000, 5_000), 7 + 1_000_000)

    def test_a_grant_that_expires_during_the_confirmation_launches_nothing(self):
        # The clock is read after the exact session confirmation, as the last read before the
        # launch: a confirmation that outlasts the grant's window launches nothing.
        h = self.harness()
        self.written(h, TICKET)
        granted = self.wall(h) - 4_000
        slow = []

        def confirming(command):
            if command == 'sim:sessions' and h.broker.open_crossings and not slow:
                slow.append(command)
                h.sim.tick(2_000)
        h.sim.hooks.append(confirming)
        reply = h.cross('COMMIT', 4, granted_at=granted, window=5_000)
        self.assertEqual(slow, ['sim:sessions'])
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('activation grant is not valid', reply['reason'])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'COMMIT'], [])

    def test_a_launch_is_refused_once_its_grant_may_have_expired_in_transit(self):
        # One second of the window is left at the guest's clock reading. The host clock then moves
        # two seconds, while the clock read is in flight, while the launch's intent is synced or while
        # the transport connects and selects the device: the guest may be past the window at the
        # launch, so nothing is sent.
        for where in ('clock read', 'launch intent', 'connection setup'):
            for crossing, index in (('COMMIT', 4), ('REBOOT', 5)):
                with self.subTest(where=where, crossing=crossing):
                    h = self.harness()
                    if crossing == 'COMMIT':
                        self.written(h, TICKET)
                    granted = self.wall(h) - 4_000
                    moved = []

                    def in_flight(command, h=h, moved=moved):
                        if command == 'sim:clock' and h.broker.open_crossings and not moved:
                            moved.append(command)
                            h.clock.mono += 2_000_000_000
                    begin = h.broker.ledger.begin_capture

                    def in_setup(command, h=h, moved=moved):
                        if command.startswith(('pm install-commit', 'adb service reboot:')) and not moved:
                            moved.append(command)
                            h.clock.mono += 2_000_000_000

                    def slow_intent(intent, h=h, moved=moved, begin=begin):
                        entry = begin(intent)
                        if intent['operation'] in ('mutation', 'reboot') and h.broker.open_crossings and not moved:
                            moved.append(intent['operation'])
                            h.clock.mono += 2_000_000_000
                        return entry
                    if where == 'clock read':
                        h.sim.hooks.append(in_flight)
                    elif where == 'launch intent':
                        h.broker.ledger.begin_capture = slow_intent
                    else:
                        h.sim.hooks.append(in_setup)
                    launched = len(self.mutations(h))
                    extra = {} if crossing == 'COMMIT' else {'entry_instance': -1}
                    reply = h.cross(crossing, index, granted_at=granted, window=5_000, **extra)
                    self.assertEqual(len(moved), 1)
                    self.assertEqual(reply['status'], STATUS['NO_REPLY'])
                    self.assertIn('activation grant may have expired before the', reply['reason'])
                    self.assertEqual(len(self.mutations(h)), launched)
                    capture = h.entries('capture')[-1].content
                    self.assertEqual(capture['intent']['operation'], 'mutation' if crossing == 'COMMIT' else 'reboot')
                    self.assertEqual((capture['result']['launch'], capture['result']['transport']),
                                     ('not-launched', 'launch-deadline' if where == 'connection setup' else 'not-sent'))
                    # The same grant with its whole window left launches.
                    if crossing == 'REBOOT':
                        h.broker.ledger.begin_capture = begin
                        h.sim.hooks.clear()
                        moved.append('done')
                        reply = h.cross(crossing, index + 1, granted_at=self.wall(h) - 1_000, window=10 ** 9, **extra)
                        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
                        self.assertIn('new boot ID', reply['reason'])
                        self.assertEqual(len(self.mutations(h)), launched + 1)

    def test_the_native_target_scope_is_read_again_at_every_crossing(self):
        scope = {'value': 'ESTABLISHED_EMPTY'}

        def target():
            if scope['value'] == 'unreadable':
                raise OSError('the target record cannot be read')
            return scope['value']
        h = self.harness(target=target)
        native = self.created(h)
        for at, value in enumerate(('HELD', 'UNKNOWN', 'unreadable', 'NOT A SCOPE')):
            with self.subTest(scope=value):
                scope['value'] = value
                calls = len(self.mutations(h))
                reply = h.cross('WRITE', 3, ticket='%02x' % (0x60 + at) * 16, native=native)
                self.assertEqual(reply['status'], STATUS['NO_REPLY'])
                self.assertIn('target scope', reply['reason'])
                self.assertEqual(len(self.mutations(h)), calls)
        # The exact own session can still be abandoned whatever the scope reads.
        scope['value'] = 'unreadable'
        reply = h.cross('ABANDON', 3, native=native)
        self.assertEqual(reply['status'], STATUS['OK'])
        self.assertEqual(self.mutations(h)[-1][0], 'ABANDON')
        # HELLO reports what the target reads now, and an unreadable target as UNKNOWN.
        h.end(0)
        h.begin()
        self.assertEqual(h.hello()['target'], proto.TARGETS['UNKNOWN'])

    def test_changed_sources_stop_before_any_crossing(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            for name in labtest.LAB_FILES:
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(labtest.REPO / name, source / name)
            h = self.harness(source_root=source)
            self.assertEqual(h.clock_read()['status'], STATUS['OK'])
            with open(source / labtest.LAB_FILES[0], 'a') as handle:
                handle.write('# changed\n')
            reply = h.cross('CREATE', 2)
            self.assertEqual(reply['status'], STATUS['STOPPED'])
            self.assertIn('sources', h.entries('stop')[0].content['reason'])
            self.assertEqual(self.mutations(h), [])

    def test_write_is_revalidated_after_staging_and_before_each_member(self):
        h = self.harness()
        native = self.created(h)
        session = native[1]

        fired = []

        def reboot_during_push(command):
            if command.startswith('push ') and not fired:
                fired.append(command)
                h.sim.new_boot()
                # The new boot reuses the session ID for another session.
                h.sim.sessions[session] = sim_android.Session(session, 4321, '88' * 16, instance=h.sim.instance)
        h.sim.hooks.append(reboot_during_push)
        reply = h.cross('WRITE', 3, native=native)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('revalidation', reply['reason'])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'WRITE'], [])
        self.assertEqual(h.sim.sessions[session].members, {})

    def test_a_change_between_the_members_never_writes_the_second(self):
        for change in ('framework', 'boot', 'session'):
            with self.subTest(change=change):
                h = self.harness()
                native = self.created(h)
                wrote = []

                def between(command, h=h, change=change, native=native):
                    # The change comes with the first guest command after the first member, which is
                    # the first read of the second member's gate.
                    if command.startswith('pm install-write') and 'base.apk ' in command + ' ' and not wrote:
                        wrote.append(command)
                    elif wrote and len(wrote) == 1:
                        wrote.append('changed')
                        if change == 'framework':
                            h.sim.framework_restart()
                        elif change == 'boot':
                            h.sim.new_boot()
                        else:
                            h.sim.sessions[native[1]].state = 'ABANDONED'
                h.sim.hooks.append(between)
                reply = h.cross('WRITE', 3, native=native)
                self.assertEqual(reply['status'], STATUS['NO_REPLY'])
                self.assertIn('the first member was written', reply['reason'])
                self.assertEqual([c[2] for c in h.sim.calls if c[0] == 'WRITE'], ['base.apk'])


class NoticeTests(Base):
    def test_an_admitted_route_runs_only_its_own_commands(self):
        h = self.harness(notice=Notice())
        h.sim.scripts['sim:notice'] = [lambda command: sim_android.result(command, 0, b'notice shown\n')]
        reply = h.cross('NOTICE', 1, entry_instance=-1, native=proto.NO_REFERENCE)
        fact = read_observation(reply['frame'])
        self.assertEqual((fact['classification'], fact['crossing'], fact['index'], fact['instance']),
                         (1, 8, 1, h.sim.instance))
        self.assertEqual(h.entries('capture')[-1].content['intent']['operation'], 'notice')
        h.broker.notice.allowed = lambda command: False
        reply = h.cross('NOTICE', 2, occurrence=2, entry_instance=-1, native=proto.NO_REFERENCE)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('allowlist', reply['reason'])


class FaultTests(Base):
    def test_a_dropped_reply_runs_once_and_is_escrowed_never_given(self):
        h = self.harness(cells=[cell('drop-create', crossing='CREATE', occurrence=1)])
        reply = h.cross('CREATE', 2)
        self.assertEqual((reply['status'], reply['frame']), (STATUS['WITHHELD'], b''))
        self.assertEqual([c[0] for c in self.mutations(h)], ['CREATE'])
        escrow = h.entries('escrow')[0].content
        frame = bytes.fromhex(escrow['frame'])
        self.assertEqual(read_observation(frame)['classification'], 1)
        self.assertEqual(escrow['frame_sha256'], hashlib.sha256(frame).hexdigest())
        outcome = h.entries('outcome')[-1].content
        self.assertEqual((outcome['status'], outcome['cell']), ('WITHHELD', 'drop-create'))
        # The cell is consumed: the same key never acts again, after reopening too.
        h.end(0)
        h.reopen()
        self.assertIn('drop-create', h.broker.consumed)
        self.assertIsNone(h.broker._match('cross', plan=PLAN, attempt=1, crossing='CREATE', occurrence=1))

    def test_a_loss_before_the_effect_launches_nothing_and_is_consumed_before_the_halt(self):
        h = self.harness(cells=[cell('lose-create', mode='loss-before', crossing='CREATE', occurrence=1)])
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['HALT'])
        self.assertEqual(self.mutations(h), [])
        kinds = [e.kind for e in h.broker.ledger.entries]
        self.assertEqual(kinds[-3:], ['crossing', 'fault', 'outcome'])
        self.assertEqual(h.entries('fault')[0].content['launched'], False)
        self.assertNotIn('capture', kinds[kinds.index('crossing'):])
        self.assertEqual(h.end(99)['status'], 'DELIBERATE_HALT')

    def test_a_loss_after_the_effect_records_it_and_withholds_the_reply(self):
        h = self.harness(cells=[cell('lose-commit', mode='loss-after', crossing='COMMIT', occurrence=1)])
        self.created(h)
        h.cross('WRITE', 3)
        reply = h.cross('COMMIT', 4)
        self.assertEqual((reply['status'], reply['frame']), (STATUS['HALT'], b''))
        self.assertEqual([c[0] for c in self.mutations(h)][-1], 'COMMIT')
        fault = h.entries('fault')[0].content
        self.assertEqual(fault['decision'], 'halt-after-effect')
        self.assertIsNotNone(fault['withheld_sha256'])

    def test_a_loss_between_the_write_members_never_writes_the_second(self):
        h = self.harness(cells=[cell('half', mode='loss-between-members', crossing='WRITE', occurrence=1)])
        self.created(h)
        reply = h.cross('WRITE', 3)
        self.assertEqual(reply['status'], STATUS['HALT'])
        self.assertEqual([c[2] for c in h.sim.calls if c[0] == 'WRITE'], ['base.apk'])
        h.end(99)
        h.reopen()
        h.begin()
        h.hello()
        self.assertEqual(h.cross('WRITE', 3)['status'], STATUS['REFUSED'])
        self.assertEqual([c[2] for c in h.sim.calls if c[0] == 'WRITE'], ['base.apk'])

    def test_a_point_cell_halts_once(self):
        h = self.harness(cells=[cell('between', on='point', mode='halt', point='selection-written')])
        first = h.call('POINT', point='selection-written', ticket=TICKET, plan=PLAN, attempt=1)
        self.assertEqual(first['status'], STATUS['HALT'])
        fault = h.broker.ledger.entries[first['record'] - 1]
        self.assertEqual((fault.kind, fault.content['cell']), ('fault', 'between'))
        h.end(99)
        h.reopen()
        h.begin()
        h.hello()
        self.assertEqual(h.call('POINT', point='selection-written', ticket=TICKET, plan=PLAN, attempt=1)['status'],
                         STATUS['OK'])

    def test_host_calls_begin_and_end_once_and_take_their_cells(self):
        cells = [cell('sign-before', on='host', mode='loss-before', crossing='SIGN', occurrence=1),
                 cell('publish-drop', on='host', mode='drop-reply', crossing='PUBLISH', occurrence=1),
                 cell('publish-after', on='host', mode='loss-after', crossing='PUBLISH', occurrence=2)]
        h = self.harness(cells=cells)

        def host(phase, crossing, index, occurrence, outcome=0, reply=proto.ZERO_DIGEST):
            return h.call('HOST', phase=phase, crossing=proto.HOST_CROSSINGS[crossing], ticket=TICKET, plan=PLAN,
                          attempt=1, index=index, occurrence=occurrence, reference='9b' * 16, outcome=outcome,
                          reply=reply)
        self.assertEqual(host(1, 'SIGN', 0, 1)['status'], STATUS['HALT'])
        summary = h.end(99)
        self.assertEqual(summary['status'], 'DELIBERATE_HALT')
        ended = [e.content for e in h.entries('host') if e.content['phase'] == 'END']
        self.assertEqual(ended[0]['outcome'], 'PROCESS_ENDED')
        h.begin()
        h.hello()
        self.assertEqual(host(1, 'SIGN', 0, 1)['status'], STATUS['REFUSED'])
        self.assertEqual(host(1, 'PUBLISH', 1, 1)['status'], STATUS['OK'])
        self.assertEqual(host(1, 'PUBLISH', 1, 1)['status'], STATUS['REFUSED'])
        self.assertEqual(host(2, 'PUBLISH', 1, 1, 1, 'ab' * 32)['status'], STATUS['WITHHELD'])
        self.assertEqual(host(2, 'PUBLISH', 1, 1, 1, 'ab' * 32)['status'], STATUS['REFUSED'])
        self.assertEqual(host(1, 'PUBLISH', 2, 2)['status'], STATUS['OK'])
        self.assertEqual(host(2, 'PUBLISH', 2, 2, 2)['status'], STATUS['HALT'])
        self.assertEqual(h.entries('escrow')[0].content['reply_sha256'], 'ab' * 32)

    def test_admission_refuses_malformed_or_repeated_cells(self):
        h = self.harness(cells=[cell('one', crossing='CREATE', occurrence=1)])
        for bad in ([cell('one', crossing='CREATE', occurrence=1)],
                    [cell('two', mode='loss-between-members', crossing='COMMIT', occurrence=1)],
                    [cell('three', crossing='SIGN', occurrence=1)],
                    [cell('four', on='point', mode='halt', point='other')],
                    [dict(cell('five', crossing='CREATE', occurrence=1), extra=1)]):
            with self.assertRaises(lab_broker.BrokerError):
                h.broker.admit_faults(bad)


class ReopenTests(Base):
    def test_an_interrupted_capture_is_quarantined_drained_and_never_repeated(self):
        h = self.harness()
        boot = h.sim.boot

        def lose(command):
            if command.startswith('pm install-create'):
                raise KeyboardInterrupt('the broker is lost here')
        h.sim.hooks.append(lose)
        with self.assertRaises(KeyboardInterrupt):
            h.cross('CREATE', 2)
        h.sim.hooks.clear()
        # The broker process is lost inside the call: the capture holds its intent and nothing more.
        interrupted = h.broker.ledger.last
        self.assertEqual((interrupted.kind, interrupted.state), ('capture', 'interrupted'))
        self.assertEqual(sorted(os.listdir(interrupted.path)), ['intent.json'])
        h.broker.close()
        h.clock.slept.clear()
        h.open()
        quarantine = h.entries('quarantine')[0].content
        self.assertEqual((quarantine['entry'], quarantine['state'], quarantine['launched']),
                         (interrupted.number, 'interrupted', 'unknown'))
        lost = [e.content for e in h.entries('outcome') if e.content['status'] == 'LOST']
        self.assertEqual(len(lost), 1)
        self.assertTrue(h.clock.slept and h.clock.slept[0] > 0)
        self.assertEqual(h.entries('generation-end')[-1].content['status'], 'LOST')
        h.begin()
        h.hello()
        self.assertEqual(h.cross('CREATE', 2, entry_boot=boot)['status'], STATUS['REFUSED'])
        self.assertEqual(self.mutations(h), [])

    def test_a_drain_survives_a_crash_after_its_quarantine(self):
        h = self.harness()

        def lose(command):
            if command.startswith('pm install-create'):
                raise KeyboardInterrupt('the broker is lost here')
        h.sim.hooks.append(lose)
        with self.assertRaises(KeyboardInterrupt):
            h.cross('CREATE', 2)
        h.sim.hooks.clear()
        intent = h.broker.ledger.last.content['intent']
        deadline = intent['started_wall_ns'] + int((intent['timeout_s'] + labtest.LIMITS['drain_grace_s']) * 1e9)
        h.broker.close()

        def lost_in_the_wait(seconds):
            raise KeyboardInterrupt('the reopening broker is lost during its drain')
        h.clock.sleep = lost_in_the_wait
        with self.assertRaises(KeyboardInterrupt):
            h.open()
        del h.clock.sleep
        # The broker that failed to open left its quarantine record behind.
        self.assertEqual([e.kind for e in lab_broker.ledgers.scan(h.root / 'ledger')].count('quarantine'), 1)
        # The next reopening still owes the whole wait, although the capture is quarantined.
        h.clock.slept.clear()
        start = h.clock.wall
        h.open()
        self.assertEqual(len(h.clock.slept), 1)
        self.assertEqual(start + int(h.clock.slept[0] * 1e9), deadline)
        self.assertEqual(h.entries('open')[-1].content['drained_until_wall_ns'], deadline)
        # Once the bound has passed, a reopening waits no more.
        h.broker.close()
        h.clock.slept.clear()
        h.open()
        self.assertEqual(h.clock.slept, [])

    def test_a_lost_generation_process_is_ended_before_another_is_served(self):
        processes = labtest.Processes(alive=True)
        h = Harness(processes=processes)
        self.addCleanup(h.close)
        h.begin(pid=4242, start_ticks=99)
        h.hello()
        h.broker.close()
        h.open()
        self.assertEqual(processes.killed, [4242])
        end = h.entries('generation-end')[-1].content
        self.assertEqual((end['status'], end['killed']), ('LOST', True))
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['OK'])

    def test_an_incomplete_record_is_quarantined_and_earlier_damage_refuses(self):
        h = Harness()
        self.addCleanup(h.close)
        h.broker.close()
        ledger = h.root / 'ledger'
        number = len(os.listdir(ledger))
        os.mkdir(ledger / ('%06d-fault' % number))
        h.open()
        quarantine = h.entries('quarantine')[-1].content
        self.assertEqual((quarantine['entry'], quarantine['launched']), (number, False))
        gap = ledger / ('%06d-report' % (len(h.broker.ledger.entries) + 2))
        h.broker.close()
        os.mkdir(gap)
        with self.assertRaises(lab_broker.BrokerError):
            h.open()
        os.rmdir(gap)
        (ledger / ('%06d-fault' % number) / 'record.json').write_text('{}')
        with self.assertRaises(lab_broker.BrokerError):
            h.open()
        (ledger / ('%06d-fault' % number) / 'record.json').unlink()
        h.open()


class TransferTests(Base):
    def serve(self, h, request_bytes, reply_pipe_full=False):
        to_broker_r, to_broker_w = os.pipe()
        to_jvm_r, to_jvm_w = os.pipe()
        if reply_pipe_full:
            os.set_blocking(to_jvm_w, False)
            try:
                while True:
                    os.write(to_jvm_w, b'\0' * 65536)
            except BlockingIOError:
                pass
            os.set_blocking(to_jvm_w, True)
        rfile, wfile = os.fdopen(to_broker_r, 'rb', buffering=0), os.fdopen(to_jvm_w, 'wb', buffering=0)
        result = {}
        thread = threading.Thread(target=lambda: result.update(state=h.broker.serve(rfile, wfile)))
        os.write(to_broker_w, request_bytes)
        thread.start()
        thread.join(10)
        alive = thread.is_alive()
        for fd in (to_broker_w, to_jvm_r):
            os.close(fd)
        thread.join(10)
        for stream in (rfile, wfile):
            try:
                stream.close()
            except OSError:
                pass
        return alive, result.get('state')

    def hello_frame(self, h):
        return proto.encode(proto.message('HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION,
                                          coordinator=labtest.COORDINATOR, config=labtest.CONFIG,
                                          component=sim_android.PACKAGE, trust=labtest.TRUST, route=1))

    def test_a_partial_request_cannot_outlast_its_bound(self):
        frame = None
        for cut in (1, 11, 12, 40):
            with self.subTest(cut=cut):
                h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.3))
                self.addCleanup(h.close)
                frame = frame or self.hello_frame(h)
                alive, state = self.serve(h, frame[:cut])
                self.assertFalse(alive, 'the broker still waited for the rest of the frame')
                self.assertIn('transfer', state['violation'])
                self.assertEqual(h.broker.end_served(state, None, 9)['status'], 'KILLED')

    def test_a_reply_that_cannot_be_delivered_cannot_outlast_its_bound(self):
        h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.3))
        self.addCleanup(h.close)
        alive, state = self.serve(h, self.hello_frame(h), reply_pipe_full=True)
        self.assertFalse(alive, 'the broker still waited to deliver its reply')
        self.assertIn('reply transfer', state['violation'])


class StreamAndReapTests(Base):
    def test_a_buffered_generation_stream_is_refused_before_any_read(self):
        # A buffer can hold a frame that select cannot see, so a buffered stream is never served.
        h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.3))
        self.addCleanup(h.close)
        to_broker_r, to_broker_w = os.pipe()
        to_jvm_r, to_jvm_w = os.pipe()
        os.write(to_broker_w, proto.encode(proto.message(
            'HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR,
            config=labtest.CONFIG, component=sim_android.PACKAGE, trust=labtest.TRUST, route=1)))
        os.close(to_broker_w)
        with os.fdopen(to_broker_r, 'rb') as rfile, os.fdopen(to_jvm_w, 'wb', buffering=0) as wfile:
            self.assertTrue(rfile.peek(1))  # The whole frame now waits in the buffer.
            with self.assertRaises(lab_broker.BrokerError):
                h.broker.serve(rfile, wfile)
        self.assertEqual(os.read(to_jvm_r, 65536), b'')
        os.close(to_jvm_r)
        self.assertEqual(h.entries('capture'), [])

    def test_a_generation_whose_kill_does_not_take_stays_open(self):
        h = Harness()
        self.addCleanup(h.close)
        stubborn = []

        class Stubborn:
            """A generation process that sends nothing, ends its stream and never exits."""

            def __init__(self, argv, **options):
                to_broker_r, to_broker_w = os.pipe()
                self.reader, to_jvm_w = os.pipe()
                os.close(to_broker_w)
                self.stdout = os.fdopen(to_broker_r, 'rb', buffering=0)
                self.stdin = os.fdopen(to_jvm_w, 'wb', buffering=0)
                self.pid, self.waits, self.kills = 2 ** 22 + 1, [], 0
                stubborn.append(self)

            def wait(self, timeout=None):
                self.waits.append(timeout)
                raise lab_broker.subprocess.TimeoutExpired('stubborn', timeout)

            def kill(self):
                self.kills += 1
        with unittest.mock.patch.object(lab_broker.subprocess, 'Popen', Stubborn):
            with self.assertRaises(lab_broker.BrokerError):
                h.broker.run_generation(['stubborn'])
        os.close(stubborn[0].reader)
        grace = h.broker.limits['exit_grace_s']
        self.assertEqual((stubborn[0].waits, stubborn[0].kills), ([grace, grace], 1))
        # The generation stays open in the ledger: no end is recorded and no other is served.
        self.assertIsNotNone(h.broker.open_generation)
        self.assertEqual((len(h.entries('generation')), h.entries('generation-end')), (1, []))
        with self.assertRaises(lab_broker.BrokerError):
            h.broker.begin_generation()


class ServeTests(Base):
    def test_a_generation_lost_during_a_crossing_is_drained_then_ended(self):
        h = Harness()
        self.addCleanup(h.close)
        to_broker_r, to_broker_w = os.pipe()
        to_jvm_r, to_jvm_w = os.pipe()
        rfile, wfile = os.fdopen(to_broker_r, 'rb', buffering=0), os.fdopen(to_jvm_w, 'wb', buffering=0)
        result = {}
        thread = threading.Thread(target=lambda: result.update(state=h.broker.serve(rfile, wfile)))
        thread.start()
        jvm_out, jvm_in = os.fdopen(to_broker_w, 'wb'), os.fdopen(to_jvm_r, 'rb')
        hello = proto.message('HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION,
                              coordinator=labtest.COORDINATOR, config=labtest.CONFIG, component=sim_android.PACKAGE,
                              trust=labtest.TRUST, route=1)
        jvm_out.write(proto.encode(hello))
        jvm_out.flush()
        self.assertEqual(proto.decode(proto.read_frame(jvm_in))['status'], STATUS['OK'])
        reached = threading.Event()

        def slow(command):
            if command.startswith('pm install-create'):
                jvm_in.close()  # The generation dies while the command runs.
                reached.set()
        h.sim.hooks.append(slow)
        cross = proto.message('CROSS', '%032x' % 2, h.manifest, ticket=TICKET, ticket_digest='11' * 32, plan=PLAN,
                              plan_digest='22' * 32, attempt=1, component=sim_android.PACKAGE, index=2, crossing=3,
                              occurrence=1, entry_boot=h.sim.boot, entry_instance=h.sim.instance, entry_elapsed=1,
                              grant=GRANT, reference=NONCE, native=(proto.NONCE, 0, 0, '', 0, NONCE),
                              bundle_apk=proto.ZERO_DIGEST, actor=2, granted=0, window=0)
        jvm_out.write(proto.encode(cross))
        jvm_out.flush()
        jvm_out.close()
        thread.join(30)
        self.assertTrue(reached.is_set())
        state = result['state']
        self.assertEqual(state['violation'], 'the generation was lost before its reply')
        self.assertEqual([c[0] for c in h.sim.calls if c[0] == 'CREATE'], ['CREATE'])
        outcome = h.entries('outcome')[-1].content
        self.assertEqual(outcome['status'], 'OK')
        self.assertEqual(h.broker.end_served(state, None, 9)['status'], 'KILLED')
        for stream in (rfile, wfile):
            try:
                stream.close()
            except OSError:
                pass


if __name__ == '__main__':
    unittest.main()
