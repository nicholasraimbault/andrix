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

import capture_ledger
import labtest
from labtest import GRANT, NONCE, PLAN, TICKET, Harness, read_observation
import lab_broker
import lab_protocol as proto
import lab_readers
import lab_target
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
        # The unreadable query is the group's own capture.
        query = h.entries('capture')[-1]
        self.assertEqual(query.content['intent']['operation'], 'features')
        self.assertEqual(h.entries('group')[-1].content['captures'], [query.number])
        reply = h.cross('CREATE', 2)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('nothing launched', reply['reason'])
        self.assertEqual([c[0] for c in h.sim.calls], ['features', 'features'])
        h.sim.features = ('shell_v2',)
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])
        self.assertEqual([c[0] for c in h.sim.calls], ['features', 'features', 'features'])
        self.assertEqual(h.entries('stop'), [])


class BrokerDirectoryTests(unittest.TestCase):
    """The broker directory's own name is made durable when it is made and at every opening."""

    def traced(self, fail=None):
        """os.fsync, recording the path each synced descriptor names, raising EIO for `fail`."""
        real, synced = os.fsync, []

        def fsync(fd):
            target = os.readlink('/proc/self/fd/%d' % fd)
            synced.append(target)
            if fail is not None and target == str(fail):
                raise OSError(5, 'injected')
            return real(fd)
        return synced, unittest.mock.patch.object(lab_broker.os, 'fsync', side_effect=fsync)

    def directory(self):
        path = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, path, True)
        return path

    def test_the_brokers_name_is_synced_when_made_and_at_every_opening(self):
        directory = self.directory()
        synced, patch = self.traced()
        with patch:
            lab_broker.Broker.initialize(directory / 'made', labtest.admission(directory), labtest.manifest_bytes())
        self.assertIn(str(directory), synced)
        h = Harness(directory=directory)
        self.addCleanup(h.close)
        synced, patch = self.traced()
        with patch:
            h.reopen()
        self.assertIn(str(directory), synced)
        self.assertIn(str(h.root), synced)

    def test_a_failed_sync_of_the_brokers_name_refuses_the_opening_until_it_completes(self):
        directory = self.directory()
        h = Harness(directory=directory)
        self.addCleanup(h.close)
        h.broker.close()
        opened = len([e for e in capture_ledger.scan(h.root / 'ledger') if e.kind == 'open'])
        _, patch = self.traced(fail=directory)
        with patch, self.assertRaisesRegex(lab_broker.BrokerError, 'cannot be made durable'):
            h.open()
        self.assertEqual(len([e for e in capture_ledger.scan(h.root / 'ledger') if e.kind == 'open']), opened)
        h.open()
        self.assertEqual(len([e for e in capture_ledger.scan(h.root / 'ledger') if e.kind == 'open']), opened + 1)

    def test_a_failed_ledger_entry_sync_refuses_the_opening_until_it_completes(self):
        directory = self.directory()
        h = Harness(directory=directory, sync=True)
        self.addCleanup(h.close)
        h.broker.close()
        entry = sorted(p for p in (h.root / 'ledger').iterdir() if p.is_dir())[-1]
        opened = len([e for e in capture_ledger.scan(h.root / 'ledger') if e.kind == 'open'])
        real = capture_ledger.Ledger._sync_dir

        def failing(ledger, path):
            if Path(path) == entry:
                raise OSError(5, 'injected')
            return real(ledger, path)
        with unittest.mock.patch.object(capture_ledger.Ledger, '_sync_dir', failing):
            for _ in range(2):
                with self.assertRaisesRegex(lab_broker.BrokerError, 'the ledger cannot be made durable'):
                    h.open()
        self.assertEqual(len([e for e in capture_ledger.scan(h.root / 'ledger') if e.kind == 'open']), opened)
        h.open()
        self.assertEqual(len([e for e in capture_ledger.scan(h.root / 'ledger') if e.kind == 'open']), opened + 1)

    def test_a_failed_ledger_file_sync_refuses_the_opening_until_it_completes(self):
        directory = self.directory()
        h = Harness(directory=directory, sync=True)
        self.addCleanup(h.close)
        h.broker.close()
        entry = sorted(p for p in (h.root / 'ledger').iterdir() if p.is_dir())[-1]
        real = capture_ledger.Ledger._sync_file

        def failing(ledger, path):
            if Path(path) == entry / 'record.json':
                raise OSError(5, 'injected')
            return real(ledger, path)
        with unittest.mock.patch.object(capture_ledger.Ledger, '_sync_file', failing):
            for _ in range(2):
                with self.assertRaisesRegex(lab_broker.BrokerError, 'the ledger cannot be made durable'):
                    h.open()
        h.open()
        self.assertEqual(h.broker.ledger.last.kind, 'open')

    def test_a_failed_sync_when_the_broker_is_made_leaves_nothing_to_open(self):
        directory = self.directory()
        _, patch = self.traced(fail=directory)
        with patch, self.assertRaises(OSError):
            lab_broker.Broker.initialize(directory / 'made', labtest.admission(directory), labtest.manifest_bytes())
        self.assertEqual(os.listdir(directory / 'made'), [])


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


def guest_admission(store='/nonexistent-store', limit=10, launches=('CREATE', 'WRITE', 'ABANDON')):
    """A version 2 admission as a guest's: the restart action with its limit, a launch set and the
    deployment store whose records crossings name."""
    return {'version': 2, 'lab_actions': {'framework-restart': limit}, 'launches': list(launches), 'store': str(store)}


class LabActionTests(Base):
    RESTART = guest_admission(launches=proto.DEVICE_CROSSINGS)

    def test_the_admission_names_its_lab_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            lab_broker.check_admission(labtest.admission(directory, **self.RESTART))
            lab_broker.check_admission(labtest.admission(directory, **dict(self.RESTART, lab_actions={}, launches=[])))
            bad = [{'version': 2}, dict(self.RESTART, lab_actions=['framework-restart']),
                   dict(self.RESTART, lab_actions={'reboot': 1}), dict(self.RESTART, lab_actions={'framework-restart': 0}),
                   dict(self.RESTART, lab_actions={'framework-restart': 101}),
                   dict(self.RESTART, lab_actions={'framework-restart': True}), dict(self.RESTART, launches=['LAUNCH']),
                   dict(self.RESTART, launches=['CREATE', 'CREATE']), dict(self.RESTART, launches='CREATE'),
                   dict(self.RESTART, store='relative/store'), dict(self.RESTART, store=None),
                   dict(self.RESTART, version=1), dict(self.RESTART, version=3)]
            for changes in bad:
                with self.subTest(changes=changes), self.assertRaises(lab_broker.BrokerError):
                    lab_broker.check_admission(labtest.admission(directory, **changes))

    def test_a_framework_restart_is_refused_unless_the_admission_names_it(self):
        h = Harness()
        self.addCleanup(h.close)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'not an admitted lab action'):
            h.broker.framework_restart('a later framework instance')
        self.assertEqual((h.entries('lab-action'), h.entries('capture')), ([], []))

    def test_a_framework_restart_runs_only_between_generations_and_is_recorded(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        instance, boot = h.sim.instance, h.sim.boot
        h.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'between generations'):
            h.broker.framework_restart('a later framework instance')
        h.end(0)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'reason'):
            h.broker.framework_restart(' ')
        summary = h.broker.framework_restart('a later framework instance for the gone proof')
        self.assertEqual((summary['launch'], summary['completion'], summary['exit']), ('launched', 'exited', 0))
        self.assertEqual((h.sim.boot, h.sim.instance > instance), (boot, True))
        self.assertEqual([c for c in h.sim.calls if c[0] == 'am restart'], [('am restart', boot)])
        actions = [e.content for e in h.entries('lab-action')]
        self.assertEqual([(a['action'], a['phase']) for a in actions], [('framework-restart', 'BEGIN'), ('framework-restart', 'END')])
        self.assertEqual(actions[1]['begin'], actions[0]['number'])
        captures = [e for e in h.entries('capture') if e.content['intent']['command'] == 'am restart']
        self.assertEqual([(c.content['intent']['operation'], c.content['intent']['lab_action']) for c in captures],
                         [('lab-action', actions[0]['number'])])
        self.assertEqual(actions[1]['capture'], captures[0].number)

    def test_a_framework_restart_is_refused_beside_a_committed_session(self):
        for state in ('READY', 'VERIFYING', 'LIVE_NOT_READY'):
            with self.subTest(state):
                h = Harness(**self.RESTART)
                self.addCleanup(h.close)
                h.sim.sessions[7001] = sim_android.Session(7001, 4321, '88' * 16, state=state, instance=h.sim.instance)
                with self.assertRaisesRegex(lab_broker.BrokerError, 'committed'):
                    h.broker.framework_restart('a later framework instance')
                self.assertEqual([c for c in h.sim.calls if c[0] == 'am restart'], [])
                actions = [e.content for e in h.entries('lab-action')]
                self.assertEqual([(a['phase'], a.get('refused')) for a in actions],
                                 [('BEGIN', None), ('END', 'a session of the component is committed or of unknown commitment')])
                groups = [e.content for e in h.entries('group') if e.content.get('purpose') == 'lab-action-precondition']
                self.assertEqual([(g['reader'], g['status'], g['emitted']) for g in groups],
                                 [('clock', 'facts', False), ('sessions', 'facts', False)])
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        h.sim.sessions[7002] = sim_android.Session(7002, 4321, '88' * 16, state='SEALED', instance=h.sim.instance)
        self.assertEqual(h.broker.framework_restart('a sealed session cannot activate')['exit'], 0)

    def test_a_framework_restart_needs_a_whole_listing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        h.sim.scripts['sim:sessions'] = ['before']
        with self.assertRaisesRegex(lab_broker.BrokerError, 'session listing is unavailable'):
            h.broker.framework_restart('a later framework instance')
        self.assertEqual([c for c in h.sim.calls if c[0] == 'am restart'], [])
        h.sim.framework = False
        with self.assertRaisesRegex(lab_broker.BrokerError, 'refused'):
            h.broker.framework_restart('a later framework instance')
        self.assertEqual([c for c in h.sim.calls if c[0] == 'am restart'], [])

    def restart_that_goes_down(self, h, back_after=None, new_boot=False):
        """`am restart` takes the framework down; it comes back after `back_after` clock reads, as a
        later instance of the same boot, or never; or the guest boots again at the first poll."""
        reads = {'clock': 0, 'down': False}

        def restart(command):
            h.sim.calls.append(('am restart', h.sim.boot))
            h.sim.framework, reads['down'] = False, True
            return sim_android.result(command, 0)

        def poll(command):
            if command != 'sim:clock' or not reads['down']:
                return
            reads['clock'] += 1
            if new_boot:
                h.sim.reboot()
                reads['down'] = False
            elif back_after is not None and reads['clock'] == back_after:
                h.sim.framework = True
                h.sim.framework_restart()
                reads['down'] = False
        h.sim.scripts['am restart'] = [restart]
        h.sim.hooks.append(poll)

    def settle_groups(self, h):
        return [e.content['reader'] for e in h.entries('group') if e.content.get('purpose') == 'lab-action-settle']

    def test_the_restart_waits_for_a_later_instance_with_a_whole_listing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        instance = h.sim.instance
        self.restart_that_goes_down(h, back_after=3)
        summary = h.broker.framework_restart('a later framework instance')
        self.assertEqual(summary['polls'], 3)
        self.assertEqual((summary['before']['instance'], summary['settled']['instance'] > instance), (instance, True))
        self.assertEqual(self.settle_groups(h), ['clock', 'clock', 'clock', 'sessions'])
        end = h.entries('lab-action')[-1].content
        self.assertEqual((end['phase'], end.get('refused'), end['settled']), ('END', None, summary['settled']))
        self.assertEqual(h.clock.slept.count(lab_broker.RESTART_POLL_S), 2)

    def test_a_restart_that_never_settles_is_refused_after_its_record(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        self.restart_that_goes_down(h)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            h.broker.framework_restart('a later framework instance that does not come')
        end = h.entries('lab-action')[-1].content
        self.assertEqual((end['phase'], end['settled']), ('END', None))
        self.assertIn('within', end['refused'])
        self.assertEqual(end['polls'], lab_broker.RESTART_SETTLE_S // lab_broker.RESTART_POLL_S)
        self.assertEqual(end['settle']['deadline_monotonic_ns'] - end['settle']['started_monotonic_ns'],
                         lab_broker.RESTART_SETTLE_S * 1_000_000_000)
        self.assertNotIn('sessions', self.settle_groups(h))

    def test_a_later_instance_settles_only_with_a_whole_listing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        sessions, restarted = h.broker.reader.sessions, {'polls': 0}

        def listing():
            # In the later instance, the first listing reads but is not whole, and the second does
            # not complete; only the third is a whole listing.
            facts = sessions()
            if restarted['polls']:
                restarted['polls'] += 1
                if restarted['polls'] == 2:
                    for fact in facts:
                        if fact['kind'] == 'LISTING':
                            fact['classification'] = 'INCOMPLETE'
                elif restarted['polls'] == 3:
                    raise lab_readers.Unavailable('the listing did not complete')
            return facts

        def restart(command):
            h.sim.calls.append(('am restart', h.sim.boot))
            h.sim.framework_restart()
            restarted['polls'] = 1
            return sim_android.result(command, 0)
        h.broker.reader.sessions = listing
        h.sim.scripts['am restart'] = [restart]
        summary = h.broker.framework_restart('a later framework instance')
        self.assertEqual(summary['polls'], 3)
        self.assertEqual(self.settle_groups(h), ['clock', 'sessions'] * 3)

    def slow_commands(self, h, seconds, incomplete_listings=0):
        """After `am restart` every guest command takes `seconds` of host time, the framework is back at
        once, and the first `incomplete_listings` listings in the later instance are not whole. Records
        each command's timeout."""
        state = {'restarted': False, 'listings': 0, 'timeouts': []}
        sessions = h.broker.reader.sessions

        def listing():
            facts = sessions()
            if state['restarted']:
                state['listings'] += 1
                if state['listings'] <= incomplete_listings:
                    for fact in facts:
                        if fact['kind'] == 'LISTING':
                            fact['classification'] = 'INCOMPLETE'
            return facts

        def restart(command):
            h.sim.calls.append(('am restart', h.sim.boot))
            h.sim.framework_restart()
            state['restarted'] = True
            return sim_android.result(command, 0)
        shell = h.broker.transport.shell

        def timed(command, timeout, stdout_max, stderr_max, **extra):
            # The command launches now and takes `seconds`: the time passes after the launch.
            result = shell(command, timeout, stdout_max, stderr_max, **extra)
            if state['restarted'] and command in ('sim:clock', 'sim:sessions'):
                state['timeouts'].append((command, timeout))
                h.clock.mono += seconds * 1_000_000_000
            return result
        h.broker.reader.sessions = listing
        h.broker.transport.shell = timed
        h.sim.scripts['am restart'] = [restart]
        return state

    def test_a_slow_successful_poll_that_ends_after_the_bound_settles_nothing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        # Each command takes 29 s, within its 30 s limit; the fifth poll's listing is the first whole
        # one, and it ends 310 s after the bound began.
        state = self.slow_commands(h, 29, incomplete_listings=4)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'ended after the 300 s bound'):
            h.broker.framework_restart('a later framework instance')
        end = h.entries('lab-action')[-1].content
        self.assertEqual((end['settled'], end['polls']), (None, 5))
        # The last command's timeout was cut to the time the bound had left.
        self.assertEqual(state['timeouts'][-1], ('sim:sessions', 19))

    def test_the_bound_passing_between_a_polls_groups_starts_no_listing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        self.slow_commands(h, 301)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            h.broker.framework_restart('a later framework instance')
        polls = h.entries('lab-action')[-1].content['settle']['polls']
        self.assertEqual([(p['clock'] is not None, p['sessions']) for p in polls], [(True, None)])

    # ------------------------------------------------ a bound reaches each command's launch

    def bounded_clock(self, h, seconds_left):
        return h.broker._group('clock', h.broker.reader.clock, {'request': None, 'generation': None, 'purpose': 'test'},
                               None, emitted=False, deadline_ns=h.clock.mono + int(seconds_left * 1_000_000_000))

    def test_a_fraction_of_a_second_left_starts_no_command(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        before = len(h.entries('capture'))
        group = self.bounded_clock(h, 0.5)
        self.assertEqual((group.status, len(h.entries('capture'))), ('unavailable', before))

    def test_expiry_while_the_intent_is_synced_launches_nothing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        h.broker.controller_read(['clock'], 'warm up')  # the feature query comes first
        begin = h.broker.ledger.begin_capture

        def slow(intent):
            entry = begin(intent)
            h.clock.mono += 2_000_000_000
            return entry
        h.broker.ledger.begin_capture = slow
        group = self.bounded_clock(h, 1.5)
        result = h.entries('capture')[-1].content['result']
        self.assertEqual((group.status, result['launch'], result['transport']), ('unavailable', 'not-launched', 'not-sent'))
        self.assertEqual(h.entries('group')[-1].content['captures'], [h.entries('capture')[-1].number])

    def test_a_fresh_brokers_feature_query_keeps_the_bound(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        begin = h.broker.ledger.begin_capture

        def slow(intent):
            entry = begin(intent)
            if intent['operation'] == 'features':
                h.clock.mono += 2_000_000_000
            return entry
        h.broker.ledger.begin_capture = slow
        group = self.bounded_clock(h, 1.5)
        last = h.entries('capture')[-1]
        self.assertEqual((last.content['intent']['operation'], last.content['result']['transport']), ('features', 'not-sent'))
        self.assertEqual((group.status, h.sim.calls), ('unavailable', []))
        self.assertEqual(h.entries('group')[-1].content['captures'], [last.number])

    def test_a_fresh_brokers_feature_query_is_given_only_what_the_bound_has_left(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        begin, features, seen = h.broker.ledger.begin_capture, h.broker.transport.features, []

        def slow(intent):
            entry = begin(intent)
            h.clock.mono += 700_000_000
            return entry

        def recorded(timeout, **extra):
            seen.append(timeout)
            return features(timeout, **extra)
        h.broker.ledger.begin_capture, h.broker.transport.features = slow, recorded
        self.assertEqual(self.bounded_clock(h, 10).status, 'facts')
        self.assertTrue(seen and abs(seen[0] - 9.3) < 1e-6, seen)

    def test_a_fresh_brokers_feature_query_is_refused_by_the_transport_once_the_bound_passes(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        features = h.broker.transport.features

        def late(timeout, **extra):
            # The handoff to the transport takes longer than the bound has left.
            h.clock.mono += 2_000_000_000
            return features(timeout, **extra)
        h.broker.transport.features = late
        group = self.bounded_clock(h, 1.5)
        last = h.entries('capture')[-1]
        self.assertEqual(last.content['intent']['operation'], 'features')
        self.assertEqual(last.content['result']['status'], 'launch-deadline')
        self.assertEqual((group.status, h.sim.calls), ('unavailable', []))
        self.assertEqual(h.entries('group')[-1].content['captures'], [last.number])

    def test_expiry_during_device_selection_launches_nothing(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        h.broker.controller_read(['clock'], 'warm up')
        h.sim.hooks.append(lambda command: command == 'sim:clock' and setattr(h.clock, 'mono', h.clock.mono + 2_000_000_000))
        group = self.bounded_clock(h, 1.5)
        result = h.entries('capture')[-1].content['result']
        self.assertEqual((group.status, result['launch'], result['transport']), ('unavailable', 'not-launched', 'launch-deadline'))

    def test_the_transport_is_given_only_what_the_bound_has_left(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        h.broker.controller_read(['clock'], 'warm up')
        begin, shell, seen = h.broker.ledger.begin_capture, h.broker.transport.shell, []

        def slow(intent):
            entry = begin(intent)
            h.clock.mono += 700_000_000
            return entry

        def recorded(command, timeout, stdout_max, stderr_max, **extra):
            seen.append(timeout)
            return shell(command, timeout, stdout_max, stderr_max, **extra)
        h.broker.ledger.begin_capture, h.broker.transport.shell = slow, recorded
        self.assertEqual(self.bounded_clock(h, 10).status, 'facts')
        self.assertTrue(seen and abs(seen[-1] - 9.3) < 1e-6, seen)

    def test_a_poll_of_another_boot_refuses_the_restart(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        self.restart_that_goes_down(h, new_boot=True)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            h.broker.framework_restart('a later framework instance')
        self.assertEqual(h.entries('lab-action')[-1].content['refused'], 'a poll read another boot')

    def test_the_restart_limit_is_enforced_before_the_command(self):
        h = Harness(**guest_admission(limit=1))
        self.addCleanup(h.close)
        h.broker.framework_restart('the first restart')
        with self.assertRaisesRegex(lab_broker.BrokerError, 'limit of 1'):
            h.broker.framework_restart('a second restart')
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'am restart']), 1)
        self.assertEqual(h.entries('lab-action')[-1].content['refused'], 'the admitted limit of 1 framework restarts is reached')

    def test_an_incomplete_listing_never_admits_a_restart(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        sessions = h.broker.reader.sessions

        def incomplete():
            facts = sessions()
            for fact in facts:
                if fact['kind'] == 'LISTING':
                    fact['classification'] = 'INCOMPLETE'
            return facts
        h.broker.reader.sessions = incomplete
        with self.assertRaisesRegex(lab_broker.BrokerError, 'not whole'):
            h.broker.framework_restart('a later framework instance')
        self.assertEqual([c for c in h.sim.calls if c[0] == 'am restart'], [])

    def test_a_stopped_broker_runs_no_lab_action(self):
        h = Harness(**self.RESTART)
        self.addCleanup(h.close)
        Path(h.admission['fences']['stop_file']).write_text('stop\n')
        with self.assertRaises(lab_broker.Stopped):
            h.broker.framework_restart('a later framework instance')
        self.assertEqual(([c for c in h.sim.calls if c[0] == 'am restart'], h.entries('lab-action')), ([], []))


class GuestAdmissionTests(Base):
    """A version 2 admission's launch fence and the records each crossing names."""

    def store(self, h, ticket=b'ticket record', plan=b'plan record'):
        root = h.directory / 'store'
        for directory, name, data in (('tickets', TICKET, ticket), ('plans', PLAN, plan),
                                      ('selections', sim_android.PACKAGE, b'selection record'),
                                      ('authorizations', labtest.GRANT, b'grant record')):
            (root / directory).mkdir(parents=True, exist_ok=True)
            (root / directory / (name + '.rec')).write_bytes(data)
        return root

    def harness_with_store(self, launches=('CREATE', 'WRITE', 'ABANDON'), cells=()):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        store = Path(directory) / 'store'
        h = Harness(directory=directory, **guest_admission(store=store, launches=launches))
        self.addCleanup(h.close)
        self.store(h)
        if cells:
            h.broker.admit_faults(list(cells))
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['OK'])
        digests = {'ticket_digest': hashlib.sha256(b'ticket record').hexdigest(),
                   'plan_digest': hashlib.sha256(b'plan record').hexdigest()}
        return h, digests

    def test_the_records_a_crossing_names_are_kept_by_digest(self):
        h, digests = self.harness_with_store()
        self.assertEqual(h.cross('CREATE', 2, **digests)['status'], STATUS['OK'])
        crossing = h.entries('crossing')[-1].content
        # CREATE carries its STAGE grant, so the grant is kept too.
        kept = {name: hashlib.sha256(data).hexdigest() for name, data in
                (('ticket', b'ticket record'), ('plan', b'plan record'), ('selection', b'selection record'),
                 ('grant', b'grant record'))}
        self.assertEqual(crossing['records'], kept)
        for digest, data in ((kept['ticket'], b'ticket record'), (kept['plan'], b'plan record')):
            self.assertEqual((h.root / 'records' / digest).read_bytes(), data)

    def test_a_crossing_whose_stored_records_differ_launches_nothing(self):
        h, digests = self.harness_with_store(cells=[cell('drop', crossing='CREATE', occurrence=1)])
        reply = h.cross('CREATE', 2, **dict(digests, ticket_digest='33' * 32))
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('not the record the crossing names', reply['reason'])
        self.assertEqual(self.mutations(h), [])
        # No cell was consumed by the refused crossing.
        self.assertEqual(h.broker.consumed, set())
        (h.directory / 'store' / 'plans' / (PLAN + '.rec')).unlink()
        reply = h.cross('CREATE', 3, **digests)
        self.assertIn('cannot be read whole', reply['reason'])
        self.assertEqual(self.mutations(h), [])

    def test_the_admitted_launch_set_is_a_fence_whatever_the_faults(self):
        h, digests = self.harness_with_store()
        native = self.created_with(h, digests)
        for crossing, index in (('COMMIT', 4), ('REBOOT', 5)):
            with self.subTest(crossing=crossing):
                calls = len(self.mutations(h))
                extra = {} if crossing == 'REBOOT' else {'native': native}
                reply = h.cross(crossing, index, **dict(digests, **extra))
                self.assertEqual(reply['status'], STATUS['NO_REPLY'])
                self.assertIn('not admitted to launch', reply['reason'])
                self.assertEqual(len(self.mutations(h)), calls)

    def test_a_loss_before_cell_still_halts_a_crossing_outside_the_launch_set(self):
        h, digests = self.harness_with_store(cells=[cell('m0', mode='loss-before', crossing='COMMIT', occurrence=1)])
        native = self.created_with(h, digests)
        reply = h.cross('COMMIT', 4, native=native, **digests)
        self.assertEqual(reply['status'], STATUS['HALT'])
        self.assertEqual(h.entries('fault')[-1].content['cell'], 'm0')

    def test_cells_that_need_a_launch_outside_the_set_are_refused_at_admission(self):
        h, _ = self.harness_with_store()
        for mode in ('loss-after', 'drop-reply'):
            with self.subTest(mode=mode), self.assertRaisesRegex(lab_broker.BrokerError, 'may not launch'):
                h.broker.admit_faults([cell('c-' + mode, mode=mode, crossing='COMMIT', occurrence=1)])

    def test_a_short_write_is_completed_before_the_record_is_kept(self):
        h, digests = self.harness_with_store()
        real = os.write
        short = {'done': False}

        def write(fd, data):
            # The first write of a retained record's temporary file writes only half.
            if not short['done'] and '/records/.' in os.readlink('/proc/self/fd/%d' % fd):
                short['done'] = True
                return real(fd, bytes(data)[:len(data) // 2])
            return real(fd, data)
        with unittest.mock.patch.object(lab_broker.os, 'write', side_effect=write):
            reply = h.cross('CREATE', 2, **digests)
        self.assertTrue(short['done'])
        self.assertEqual(reply['status'], STATUS['OK'])
        for digest in h.entries('crossing')[-1].content['records'].values():
            self.assertEqual(hashlib.sha256((h.root / 'records' / digest).read_bytes()).hexdigest(), digest)

    def test_a_record_that_cannot_be_kept_whole_launches_nothing(self):
        h, digests = self.harness_with_store(cells=[cell('drop', crossing='CREATE', occurrence=1)])
        real = os.write

        def write(fd, data):
            if '/records/.' in os.readlink('/proc/self/fd/%d' % fd):
                return 0
            return real(fd, data)
        with unittest.mock.patch.object(lab_broker.os, 'write', side_effect=write):
            reply = h.cross('CREATE', 2, **digests)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('cannot be retained', reply['reason'])
        self.assertEqual((self.mutations(h), h.broker.consumed), ([], set()))
        # Nothing is left under any record's name.
        self.assertEqual([p.name for p in (h.root / 'records').iterdir() if not p.name.startswith('.')], [])

    def test_retained_record_names_are_made_durable(self):
        h, digests = self.harness_with_store()
        real, synced = os.fsync, []

        def fsync(fd):
            target = os.readlink('/proc/self/fd/%d' % fd)
            if target in (str(h.root), str(h.root / 'records')):
                synced.append(target)
            return real(fd)
        with unittest.mock.patch.object(lab_broker.os, 'fsync', side_effect=fsync):
            self.assertEqual(h.cross('CREATE', 2, **digests)['status'], STATUS['OK'])
            first = list(synced)
            self.assertIn(str(h.root), first)
            self.assertIn(str(h.root / 'records'), first)
            # The same records named again: the directory is synced again, never skipped.
            synced.clear()
            self.assertEqual(h.cross('WRITE', 3, native=h.bound(), **digests)['status'], STATUS['OK'])
            self.assertIn(str(h.root / 'records'), synced)

    def test_a_failed_directory_sync_launches_nothing_and_is_completed_later(self):
        h, digests = self.harness_with_store()
        real = os.fsync

        def failing(fd):
            if os.readlink('/proc/self/fd/%d' % fd) == str(h.root / 'records'):
                raise OSError(5, 'injected')
            return real(fd)
        with unittest.mock.patch.object(lab_broker.os, 'fsync', side_effect=failing):
            reply = h.cross('CREATE', 2, **digests)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('cannot be retained', reply['reason'])
        self.assertEqual(self.mutations(h), [])
        synced = []

        def counting(fd):
            if os.readlink('/proc/self/fd/%d' % fd) == str(h.root / 'records'):
                synced.append(fd)
            return real(fd)
        with unittest.mock.patch.object(lab_broker.os, 'fsync', side_effect=counting):
            self.assertEqual(h.cross('CREATE', 3, **digests)['status'], STATUS['OK'])
        self.assertTrue(synced)

    def created_with(self, h, digests):
        reply = h.cross('CREATE', 2, **digests)
        self.assertEqual(reply['status'], STATUS['OK'])
        return h.bound()


class ControllerTests(Base):
    """Reads and diagnostics the controller asks between generations."""

    def test_controller_reads_are_recorded_groups_between_generations(self):
        h = Harness()
        self.addCleanup(h.close)
        groups = h.broker.controller_read(['clock', 'sessions', 'checkpoint'], 'baseline listing')
        self.assertEqual([g.status for g in groups], ['facts', 'facts', 'facts'])
        listing = [f for f in groups[1].facts if f['kind'] == 'LISTING']
        self.assertEqual([f['classification'] for f in listing], ['NONE_FOR_PACKAGE'])
        recorded = [e.content for e in h.entries('group') if e.content['purpose'] == 'controller: baseline listing']
        self.assertEqual([(g['reader'], g['emitted']) for g in recorded],
                         [('clock', False), ('sessions', False), ('checkpoint', False)])
        for names, purpose in ((['reboot'], 'x'), ([], 'x'), (['clock'], ' '), (['target'], 'x')):
            with self.subTest(names=names, purpose=purpose), self.assertRaises(lab_broker.BrokerError):
                h.broker.controller_read(names, purpose)
        h.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'between generations'):
            h.broker.controller_read(['clock'], 'during a generation')

    def test_a_diagnostic_is_a_fixed_fenced_capture(self):
        h = Harness()
        self.addCleanup(h.close)
        number, result = h.broker.diagnostic('logcat')
        capture = next(e for e in h.entries('capture') if e.number == number).content
        self.assertEqual((capture['intent']['operation'], capture['intent']['command']), ('diagnostic', 'logcat -b all -d'))
        self.assertEqual(result.exit, 0)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no known name'):
            h.broker.diagnostic('bugreport')
        Path(h.admission['fences']['stop_file']).write_text('stop\n')
        with self.assertRaises(lab_broker.Stopped):
            h.broker.diagnostic('logcat')
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'logcat']), 1)


class TargetReadTests(Base):
    """The native target scope read from the guest as the broker's own recorded group."""

    def target_groups(self, h):
        return [e.content for e in h.entries('group') if e.content['reader'] == 'target']

    def test_the_fresh_form_is_read_and_recorded_at_hello_and_at_every_crossing_gate(self):
        h = self.harness(target_read=True)
        groups = self.target_groups(h)
        self.assertEqual([(g['purpose'], g['status'], g['emitted'], g['reading']) for g in groups],
                         [('target', 'facts', False, {'scope': 'ESTABLISHED_EMPTY'})])
        commands = [e.content['intent']['command'] for e in h.entries('capture') if e.number in groups[0]['captures']]
        self.assertEqual(commands, [lab_target.COMMAND])
        self.assertTrue(h.entries('open')[0].content['target_read'])
        native = self.created(h)
        self.assertEqual(h.cross('WRITE', 3, native=native)['status'], STATUS['OK'])
        # HELLO, CREATE's gate, and WRITE's gate before its push and again before each member.
        self.assertEqual(len(self.target_groups(h)), 5)
        # Every launched mutation follows a target read made since the mutation before it; the
        # WRITE's two staging pushes share the gate read before them.
        read_since, mutations = False, 0
        for entry in h.broker.ledger.entries:
            if entry.kind == 'group' and entry.content['reader'] == 'target':
                read_since = entry.content['reading'] == {'scope': 'ESTABLISHED_EMPTY'}
            elif entry.kind == 'capture' and entry.content['intent']['operation'] in ('mutation', 'push'):
                self.assertTrue(read_since, entry.content['intent'].get('command'))
                if entry.content['intent']['operation'] == 'mutation':
                    read_since, mutations = False, mutations + 1
        self.assertEqual(mutations, 3)

    def test_any_other_reply_reads_unknown_and_launches_nothing(self):
        fresh = lab_target.FRESH_FORM.encode()
        replies = {
            'another value': (0, fresh.replace(b'counter_known=false', b'counter_known=true'), b''),
            'a hold': (0, fresh + b'hold=10147\tPINNED\ttrue\tpackage\tdev.andrix.proof\n', b''),
            'another schema': (0, fresh.replace(b'-v1\n', b'-v2\n'), b''),
            'error output': (0, fresh, b'warning\n'),
            'a nonzero exit': (1, fresh, b''),
            'a missing line end': (0, fresh[:-1], b''),
        }
        for label, reply in replies.items():
            with self.subTest(reply=label):
                h = Harness(target_read=True)
                self.addCleanup(h.close)
                h.begin()
                self.assertEqual(h.hello()['status'], STATUS['OK'])
                h.sim.native_dump = reply
                calls = len(self.mutations(h))
                outcome = h.cross('CREATE', 2)
                self.assertEqual(outcome['status'], STATUS['NO_REPLY'])
                self.assertIn('not established empty', outcome['reason'])
                self.assertEqual(len(self.mutations(h)), calls)
                self.assertEqual(self.target_groups(h)[-1]['reading'], {'scope': 'UNKNOWN'})

    def test_hello_reports_unknown_for_another_form_and_never_held(self):
        h = Harness(target_read=True)
        self.addCleanup(h.close)
        h.sim.native_dump = (0, lab_target.FRESH_FORM.encode() + b'hold=10147\tPINNED\ttrue\tpackage\tx\n', b'')
        h.begin()
        reply = h.hello()
        self.assertEqual((reply['status'], reply['target']), (STATUS['OK'], proto.TARGETS['UNKNOWN']))

    def test_an_unavailable_read_is_unknown(self):
        h = Harness(target_read=True)
        self.addCleanup(h.close)
        h.sim.scripts[lab_target.COMMAND] = ['before']
        h.begin()
        reply = h.hello()
        self.assertEqual((reply['status'], reply['target']), (STATUS['OK'], proto.TARGETS['UNKNOWN']))
        self.assertEqual(self.target_groups(h)[0]['status'], 'unavailable')

    def test_the_admission_still_bounds_the_read(self):
        for admitted in ('HELD', 'UNKNOWN'):
            with self.subTest(admitted=admitted):
                h = Harness(target_read=True, target_scope=admitted)
                self.addCleanup(h.close)
                h.begin()
                self.assertEqual(h.hello()['target'], proto.TARGETS[admitted])

    def test_a_target_read_needs_the_readers_target_and_no_host_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'broker'
            admission = labtest.admission(directory)
            lab_broker.Broker.initialize(root, admission, labtest.manifest_bytes())
            sim = sim_android.SimAndroid()
            for reader, target in ((sim_android.SimReader(labtest.INSTALLATION), None),
                                   (sim_android.SimReader(labtest.INSTALLATION, target=True), lambda: 'ESTABLISHED_EMPTY')):
                with self.assertRaisesRegex(lab_broker.BrokerError, 'target read'):
                    lab_broker.Broker.open(root, labtest.REPO, sim_android.SimTransport(sim), reader,
                                           target=target, target_read=True)

    def test_the_fresh_form_is_the_sealed_capture(self):
        self.assertEqual(hashlib.sha256(lab_target.FRESH_FORM.encode()).hexdigest(), lab_target.FRESH_FORM_SHA256)
        self.assertEqual(len(lab_target.FRESH_FORM.encode()), 220)


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

    def test_host_records_carry_the_brokers_times(self):
        h = self.harness()

        def host(phase, crossing, index, occurrence, outcome=0, reply=proto.ZERO_DIGEST):
            return h.call('HOST', phase=phase, crossing=proto.HOST_CROSSINGS[crossing], ticket=TICKET, plan=PLAN,
                          attempt=1, index=index, occurrence=occurrence, reference='9b' * 16, outcome=outcome,
                          reply=reply)
        h.clock.wall, h.clock.mono = h.clock.wall + 7_000_000_000, h.clock.mono + 7_000_000_000
        begun = (h.clock.wall, h.clock.mono)
        self.assertEqual(host(1, 'PUBLISH', 1, 1)['status'], STATUS['OK'])
        h.clock.wall, h.clock.mono = h.clock.wall + 2_000_000_000, h.clock.mono + 2_000_000_000
        self.assertEqual(host(2, 'PUBLISH', 1, 1, 1, 'ab' * 32)['status'], STATUS['OK'])
        self.assertEqual(host(1, 'SIGN', 0, 1)['status'], STATUS['OK'])
        h.clock.wall, h.clock.mono = h.clock.wall + 1_000_000_000, h.clock.mono + 1_000_000_000
        h.end(0)
        records = [e.content for e in h.entries('host')]
        self.assertEqual([(r['phase'], r.get('outcome'), r['wall_ns'], r['monotonic_ns']) for r in records],
                         [('BEGIN', None) + begun, ('END', 'REPLY', begun[0] + 2_000_000_000, begun[1] + 2_000_000_000),
                          ('BEGIN', None, begun[0] + 2_000_000_000, begun[1] + 2_000_000_000),
                          ('END', 'PROCESS_ENDED', begun[0] + 3_000_000_000, begun[1] + 3_000_000_000)])

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
