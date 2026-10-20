# SPDX-License-Identifier: Apache-2.0
"""The broker on a simulated guest: generations, fences, groups, typed crossings, fault cells,
escrow, replay refusal and reopening. Host evidence only."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time
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

    def test_no_host_call_begins_after_a_stop_of_any_cause(self):
        # A host call is forward work like any guest command. After a stop of any cause, latched by
        # a fence, by the run's deadline at a launch gate or by the controller, its BEGIN is
        # refused with the stop's reason and recorded as refused, and no host call begins. So it is
        # when the stop file appears just before the BEGIN, whose own fence then latches the stop.
        # A reopening reads the refusal as neither a BEGIN nor an END. The twin, with no stop,
        # begins its host call.
        for cause in ('the stop file, latched by a read', 'the run deadline at a launch gate', 'the controller',
                      'the stop file, at the BEGIN', 'no stop'):
            with self.subTest(cause):
                directory = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
                self.addCleanup(shutil.rmtree, directory)
                D = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=dict(runtime_fences(D), stop_file=str(directory / 'STOP')))
                if cause == 'the stop file, latched by a read':
                    (directory / 'STOP').write_text('stop\n')
                    self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
                elif cause == 'the run deadline at a launch gate':
                    elapse(h, D - 10 ** 9 - h.clock.mono)
                    h.sim.hooks.append(lambda command: elapse(h, 2 * 10 ** 9))
                    self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
                    h.sim.hooks.clear()
                elif cause == 'the controller':
                    h.broker.stop('the controller stops the run')
                elif cause == 'the stop file, at the BEGIN':
                    (directory / 'STOP').write_text('stop\n')
                fields = dict(crossing=proto.HOST_CROSSINGS['PUBLISH'], ticket=TICKET, plan=PLAN, attempt=1, index=1,
                              occurrence=1, reference='9b' * 16, reply=proto.ZERO_DIGEST)
                reply = h.call('HOST', phase=1, outcome=0, **fields)
                records = [(e.number, e.content['phase'], e.content.get('reason')) for e in h.entries('host')]
                if cause == 'no stop':
                    self.assertEqual((reply['status'], [r[1] for r in records]), (STATUS['OK'], ['BEGIN']))
                    continue
                reason = {'the run deadline at a launch gate': lab_broker.RUN_AT_SERVICE,
                          'the controller': 'the controller stops the run'}.get(cause, 'the stop file exists')
                self.assertEqual((h.broker.stopped, reply['status'], reply['reason']),
                                 (reason, STATUS['REFUSED'], reason))
                self.assertEqual(records, [(reply['record'], 'REFUSED', reason)])
                self.assertEqual(h.broker.host_begun, {})
                if cause == 'the stop file, at the BEGIN':
                    # The BEGIN's own fence latched the stop, with the reading it judged.
                    [stop] = h.entries('stop')
                    self.assertEqual((stop.number, stop.content['reason'], stop.content['monotonic_ns']),
                                     (reply['record'] - 1, reason, h.clock.mono))
                end = h.call('HOST', phase=2, outcome=2, **fields)
                self.assertEqual((end['status'], end['reason']),
                                 (STATUS['REFUSED'], 'a host call ends once, after it began'))
                h.reopen()
                self.assertEqual((h.broker.host_begun, h.broker.host_ended), ({}, set()))

    def test_the_lease_and_the_deadline_are_fences(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = Path(directory) / 'lease'
            lease.write_text('runtime-7\n')
            fences = {'stop_file': str(Path(directory) / 'STOP'), 'lease_file': str(lease),
                      'lease_token': 'runtime-7', 'deadline_monotonic_ns': labtest.Clock().mono + 10 ** 12,
                      'host_boot_id': labtest.HOST_BOOT}
            h = self.harness(fences=fences)
            self.assertEqual(h.clock_read()['status'], STATUS['OK'])
            lease.write_text('runtime-8\n')
            self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
            self.assertEqual(h.entries('stop')[0].content['reason'], 'the lease is not held')
            lease.write_text('runtime-7\n')
            self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        h = self.harness(fences={'stop_file': '/nonexistent/STOP', 'lease_file': None, 'lease_token': None,
                                 'deadline_monotonic_ns': labtest.Clock().mono + 5, 'host_boot_id': labtest.HOST_BOOT})
        h.clock.mono += 10
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual(h.entries('stop')[0].content['reason'], 'the runtime deadline passed')


# Another host boot's ID, for a harness moved to it.
OTHER_HOST_BOOT = '9e4f1b06-2c7a-4d58-8b13-f6a0c2d9e471'


def runtime_fences(deadline, boot=labtest.HOST_BOOT):
    return {'stop_file': '/nonexistent/STOP', 'lease_file': None, 'lease_token': None,
            'deadline_monotonic_ns': deadline, 'host_boot_id': boot}


def elapse(h, ns):
    """`ns` nanoseconds pass on both of the harness's host clocks."""
    h.clock.mono += ns
    h.clock.wall += ns


class MonotonicFenceTests(Base):
    def started(self, h):
        return [e.content['intent']['started_monotonic_ns'] for e in h.entries('capture')]

    def test_the_runtime_deadline_counts_on_the_host_monotonic_clock_whatever_the_wall_clock_does(self):
        # One second before the deadline or one after it on the host's monotonic clock, the wall
        # clock unchanged, stepped an hour ahead or an hour back. Before the deadline every read is
        # served, and after it none is: no step of the wall clock moves the deadline, and no command
        # starts at or after it.
        for relative in (-1, 1):
            for step in (0, 3600, -3600):
                with self.subTest(relative=relative, step=step):
                    deadline = labtest.Clock().mono + 600 * 10 ** 9
                    h = self.harness(fences=runtime_fences(deadline))
                    elapse(h, deadline + relative * 10 ** 9 - h.clock.mono)
                    h.clock.wall += step * 10 ** 9
                    status = h.clock_read()['status']
                    stops = [e.content['reason'] for e in h.entries('stop')]
                    late = [start for start in self.started(h) if start >= deadline]
                    self.assertEqual(late, [])
                    if relative < 0:
                        self.assertEqual((status, stops), (STATUS['OK'], []))
                    else:
                        self.assertEqual((status, stops), (STATUS['STOPPED'], ['the runtime deadline passed']))

    def test_a_broker_reopened_in_the_same_host_boot_keeps_its_runtime_deadline(self):
        # Reopened in the same host boot, a broker counts toward the same instant on the same clock:
        # it serves before the deadline, after a wall step back too, and once the deadline has
        # passed it stops, then and after every later reopening.
        deadline = labtest.Clock().mono + 600 * 10 ** 9
        h = self.harness(fences=runtime_fences(deadline))
        h.end(0)
        elapse(h, 300 * 10 ** 9)
        h.clock.wall -= 3600 * 10 ** 9
        h.reopen()
        h.begin()
        self.assertEqual((h.hello()['status'], h.clock_read()['status']), (STATUS['OK'], STATUS['OK']))
        elapse(h, 300 * 10 ** 9)
        self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
        self.assertEqual([e.content['reason'] for e in h.entries('stop')], ['the runtime deadline passed'])
        h.end(125)
        captured = len(h.entries('capture'))
        h.reopen()
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['STOPPED'])
        self.assertEqual(len(h.entries('capture')), captured)
        self.assertEqual([e.content['host_boot_id'] for e in h.entries('open')], [labtest.HOST_BOOT] * 3)

    def test_a_broker_opened_in_another_host_boot_counts_its_runtime_deadline_as_passed(self):
        # The host booted again: its monotonic clock began anew, here long before the deadline, and
        # its boot ID changed. The reopened broker counts the deadline as passed, with its own
        # reason, and launches nothing; so does one that cannot read its host's boot ID. The twin,
        # reopened in the same host boot at the same reading of that clock, serves.
        for case in ('another boot', 'a boot that cannot be read', 'the same boot'):
            with self.subTest(case):
                deadline = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=runtime_fences(deadline))
                self.assertEqual(h.clock_read()['status'], STATUS['OK'])
                h.end(0)
                h.broker.close()
                h.clock.mono = labtest.Clock().mono
                h.host_boot = {'another boot': OTHER_HOST_BOOT, 'a boot that cannot be read': None}.get(case,
                                                                                                    labtest.HOST_BOOT)
                h.open()
                captured = len(h.entries('capture'))
                h.begin()
                h.hello()
                status = h.clock_read()['status']
                stops = [e.content['reason'] for e in h.entries('stop')]
                if case == 'the same boot':
                    self.assertEqual((status, stops), (STATUS['OK'], []))
                    continue
                reason = lab_broker.UNREAD_BOOT if case == 'a boot that cannot be read' else lab_broker.OTHER_BOOT
                self.assertEqual((status, stops, len(h.entries('capture'))), (STATUS['STOPPED'], [reason], captured))
                self.assertEqual(h.entries('open')[-1].content['host_boot_id'], h.host_boot)

    def test_the_runtime_deadline_has_passed_at_its_own_instant(self):
        # One nanosecond before the deadline a read is served; at the deadline it is not.
        for offset in (-1, 0):
            with self.subTest(offset=offset):
                deadline = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=runtime_fences(deadline))
                elapse(h, deadline + offset - h.clock.mono)
                status = h.clock_read()['status']
                self.assertEqual(status, STATUS['OK'] if offset < 0 else STATUS['STOPPED'])
                self.assertEqual([start for start in self.started(h) if start >= deadline], [])

    def test_a_command_is_admitted_at_the_reading_its_fence_judged(self):
        # The deadline passes right after the feature query's fence judged it, before its intent is
        # written. That command is admitted, and its intent names the very reading its fence
        # judged, before the deadline, so the record agrees with the fence and with a closure that
        # judges the record by the same clock. Its launch gate, once the intent is durable, then
        # finds the deadline passed: it is not launched, and the stop is latched with the gate's
        # reading. The twin passes no deadline.
        for passes in (True, False):
            with self.subTest(passes=passes):
                deadline = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=runtime_fences(deadline))
                check, judged = h.broker.fences.check, []

                def fence():
                    reason, now = check()
                    judged.append(now)
                    if passes and reason is None and len(judged) == 1:
                        elapse(h, deadline - h.clock.mono)
                    return reason, now
                h.broker.fences.check = fence
                status = h.clock_read()['status']
                self.assertEqual(self.started(h)[:1], judged[:1])
                if not passes:
                    self.assertEqual((status, len(self.started(h))), (STATUS['OK'], 2))
                    continue
                result = h.entries('capture')[0].content['result']
                self.assertEqual((status, result['launch'], result['error'], result['launch_monotonic_ns']),
                                 (STATUS['STOPPED'], 'not-launched', lab_broker.RUN_AT_LAUNCH, None))
                self.assertEqual([(e.content['reason'], e.content['monotonic_ns']) for e in h.entries('stop')],
                                 [(lab_broker.RUN_AT_LAUNCH, deadline)])
                self.assertEqual([start for start in self.started(h) if start >= deadline], [])
                self.assertEqual(len(self.started(h)), 1)

    def test_a_command_whose_run_deadline_passes_after_its_fence_is_not_launched(self):
        # The fence admits a read one nanosecond before the run's deadline D, and writing its
        # intent stalls for 2 s of both host clocks: once the intent is durable the deadline has
        # passed, so nothing is sent, with the run's own reason, which latches the stop at the
        # gate's reading, and the record keeps the fence's reading as its start. The twins: no
        # stall, which launches at D - 1 ns; and a launch deadline at D, refused as before, with the
        # run's reason when D is also the run's deadline and with its own when the run's deadline
        # is later.
        for case in ('a stall writing its intent', 'no stall', 'a launch deadline at D',
                     'a launch deadline at D, the run deadline later'):
            with self.subTest(case):
                base = labtest.Clock().mono
                D = base + 600 * 10 ** 9
                run = D + 100 * 10 ** 9 if case.endswith('later') else D
                h = self.harness(fences=runtime_fences(run))
                self.assertEqual(h.clock_read()['status'], STATUS['OK'])
                launched, begin = [], h.broker.ledger.begin_capture
                h.sim.hooks.append(lambda command: launched.append((command, h.clock.mono)))

                def slow(intent):
                    entry = begin(intent)
                    if case != 'no stall':
                        elapse(h, 2 * 10 ** 9)
                    return entry
                h.broker.ledger.begin_capture = slow
                elapse(h, D - 1 - h.clock.mono)
                bound = D if case.startswith('a launch deadline') else None
                raised = None
                try:
                    h.broker._shell('read', 'sim:clock', {'request': None, 'generation': None, 'purpose': 'probe'},
                                    30, 65536, 65536, not_after_ns=bound, bound_ns=bound)
                except (lab_broker._NotLaunched, lab_broker.Stopped) as error:
                    raised = (type(error).__name__, str(error))
                capture = h.entries('capture')[-1].content
                stops = [(e.content['reason'], e.content['monotonic_ns']) for e in h.entries('stop')]
                self.assertEqual(capture['intent']['started_monotonic_ns'], D - 1)
                if case == 'no stall':
                    self.assertEqual((raised, capture['result']['launch'], launched, stops),
                                     (None, 'launched', [('sim:clock', D - 1)], []))
                    self.assertEqual(capture['result']['launch_monotonic_ns'], D - 1)
                    continue
                if case.endswith('later'):
                    reason = 'the activation grant may have expired before the launch, or its bound passed'
                    self.assertEqual((raised, launched, stops), (('_NotLaunched', reason), [], []))
                else:
                    reason = lab_broker.RUN_AT_LAUNCH
                    self.assertEqual((raised, launched, stops),
                                     (('Stopped', reason), [], [(reason, D + 2 * 10 ** 9 - 1)]))
                result = capture['result']
                self.assertEqual((result['launch'], result['transport'], result['error']),
                                 ('not-launched', 'not-sent', reason))
                # It keeps the reading its launch gate refused it at, and no launch.
                self.assertEqual((result['ended_monotonic_ns'], result['launch_monotonic_ns']),
                                 (D + 2 * 10 ** 9 - 1, None))

    def test_a_crossing_whose_run_deadline_passes_before_its_second_member_is_stopped(self):
        # The run's deadline passes while the second member's write records its intent, after the
        # first member was written: that write is not launched, and the stop it latches ends the
        # crossing STOPPED, its captures named, never as a crossing that launched nothing. The
        # twin's deadline lies ahead, and both members are written.
        for passes in (True, False):
            with self.subTest(passes=passes):
                D = labtest.Clock().mono + 3600 * 10 ** 9
                h = self.harness(fences=runtime_fences(D))
                native = self.created(h)
                begin, writes = h.broker.ledger.begin_capture, []

                def slow(intent):
                    entry = begin(intent)
                    if (intent.get('command') or '').startswith('pm install-write'):
                        writes.append(intent['command'])
                        if passes and len(writes) == 2:
                            elapse(h, D - h.clock.mono)
                    return entry
                h.broker.ledger.begin_capture = slow
                reply = h.cross('WRITE', 3, native=native)
                written = [c[2] for c in h.sim.calls if c[0] == 'WRITE']
                if not passes:
                    self.assertEqual((reply['status'], written), (STATUS['OK'], ['base.apk', 'base.apk.idsig']))
                    continue
                self.assertEqual((reply['status'], reply['reason'], written),
                                 (STATUS['STOPPED'], lab_broker.RUN_AT_LAUNCH, ['base.apk']))
                # The outcome names the first member's write, which launched; the second's capture,
                # the crossing's own, ends not launched.
                outcome = h.entries('outcome')[-1].content
                first, second = [e for e in h.entries('capture')
                                 if (e.content['intent'].get('command') or '').startswith('pm install-write')]
                self.assertEqual((outcome['status'], outcome['reason']), ('STOPPED', lab_broker.RUN_AT_LAUNCH))
                self.assertIn(first.number, outcome['captures'])
                self.assertEqual((second.content['intent']['crossing'], second.content['result']['launch'],
                                  second.content['result']['error']),
                                 (outcome['crossing'], 'not-launched', lab_broker.RUN_AT_LAUNCH))

    def test_a_command_whose_run_deadline_passes_at_its_transport_is_not_launched(self):
        # The run's deadline passes while the transport connects and selects the device, after the
        # launch gate: its last question before the service request refuses a read and a push alike,
        # and keeps the reading it judged, which the stop latched with the run's reason keeps too.
        # The twins connect within the deadline and launch, keeping their launch's reading.
        for kind in ('read', 'push'):
            for passes in (True, False):
                with self.subTest(kind=kind, passes=passes):
                    D = labtest.Clock().mono + 600 * 10 ** 9
                    h = self.harness(fences=runtime_fences(D))
                    self.assertEqual(h.clock_read()['status'], STATUS['OK'])
                    elapse(h, D - 10 ** 9 - h.clock.mono)
                    connect = (2000 if passes else 500) * 10 ** 6
                    h.sim.hooks.append(lambda command: elapse(h, connect))
                    context = {'request': None, 'generation': None, 'purpose': 'probe'}
                    path = labtest.DEVICE_DIR + '/probe'
                    raised = None
                    try:
                        if kind == 'read':
                            h.broker._shell('read', 'sim:clock', context, 30, 65536, 65536)
                        else:
                            h.broker._capture('push', None, dict(context, path=path),
                                              lambda may_send: h.broker.transport.push(b'probe', path, 0o644, 0, 30,
                                                                                       may_send=may_send), 30)
                    except (lab_broker._NotLaunched, lab_broker.Stopped) as error:
                        raised = (type(error).__name__, str(error))
                    result = h.entries('capture')[-1].content['result']
                    stops = [(e.content['reason'], e.content['monotonic_ns']) for e in h.entries('stop')]
                    self.assertEqual(result['launch_monotonic_ns'], D - 10 ** 9 + connect)
                    if not passes:
                        self.assertEqual((raised, result['launch'], stops), (None, 'launched', []))
                        continue
                    self.assertEqual((raised, result['launch'], result['transport']),
                                     (('Stopped', lab_broker.RUN_AT_SERVICE), 'not-launched', 'launch-deadline'))
                    self.assertGreaterEqual(result['launch_monotonic_ns'], D)
                    self.assertEqual(stops, [(lab_broker.RUN_AT_SERVICE, result['launch_monotonic_ns'])])
                    if kind == 'push':
                        self.assertNotIn(path, h.sim.files)

    def test_a_crossing_push_whose_run_deadline_passes_at_its_transport_is_not_launched(self):
        # The run's deadline passes while the transport connects for the WRITE crossing's first
        # member push: its last question refuses the push, nothing reaches the guest, and the stop
        # latched with the run's reason ends the crossing STOPPED, before any member is written.
        # The twin's deadline lies ahead, and both members are pushed and written.
        for passes in (True, False):
            with self.subTest(passes=passes):
                D = labtest.Clock().mono + 3600 * 10 ** 9
                h = self.harness(fences=runtime_fences(D))
                native = self.created(h)
                pushes = []

                def connect(command):
                    if command.startswith('push '):
                        pushes.append(command)
                        if passes and len(pushes) == 1:
                            elapse(h, D - h.clock.mono)
                h.sim.hooks.append(connect)
                reply = h.cross('WRITE', 3, native=native)
                pushed = [c[1] for c in h.sim.calls if c[0] == 'push']
                written = [c[2] for c in h.sim.calls if c[0] == 'WRITE']
                if not passes:
                    self.assertEqual((reply['status'], len(pushed), written),
                                     (STATUS['OK'], 2, ['base.apk', 'base.apk.idsig']))
                    continue
                self.assertEqual((reply['status'], reply['reason'], pushed, written),
                                 (STATUS['STOPPED'], lab_broker.RUN_AT_SERVICE, [], []))
                [push] = [e for e in h.entries('capture') if e.content['intent']['operation'] == 'push']
                result = push.content['result']
                self.assertEqual((result['launch'], result['transport'], result['launch_monotonic_ns']),
                                 ('not-launched', 'launch-deadline', D))
                [stop] = h.entries('stop')
                self.assertEqual((stop.number, stop.content['reason'], stop.content['monotonic_ns']),
                                 (push.number + 1, lab_broker.RUN_AT_SERVICE, D))

    def test_a_feature_query_whose_run_deadline_passes_at_its_transport_stops_the_broker(self):
        # A fresh broker's feature query is its first command. The run's deadline passes while the
        # transport connects for it: its last question refuses the query, and the stop latched with
        # the run's reason, at the reading that question judged, answers the request STOPPED. The
        # twin connects within the deadline, and the read is served.
        for passes in (True, False):
            with self.subTest(passes=passes):
                D = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=runtime_fences(D))
                elapse(h, D - 10 ** 9 - h.clock.mono)
                features = h.broker.transport.features

                def connect(timeout, may_send=None):
                    elapse(h, (2000 if passes else 500) * 10 ** 6)
                    return features(timeout, may_send=may_send)
                h.broker.transport.features = connect
                status = h.clock_read()['status']
                [query] = [e for e in h.entries('capture') if e.content['intent']['operation'] == 'features']
                result = query.content['result']
                if not passes:
                    self.assertEqual((status, result['status'], h.entries('stop')), (STATUS['OK'], 'ok', []))
                    continue
                self.assertEqual((status, result['status'], result['launch_monotonic_ns']),
                                 (STATUS['STOPPED'], 'launch-deadline', D + 10 ** 9))
                [stop] = h.entries('stop')
                self.assertEqual((stop.number, stop.content['reason'], stop.content['monotonic_ns']),
                                 (query.number + 1, lab_broker.RUN_AT_SERVICE, D + 10 ** 9))
                self.assertEqual(len(h.entries('capture')), 1)

    def test_each_command_keeps_its_actual_launch_beside_its_fences_reading(self):
        # A command's record keeps the fence's reading as its start and the reading at the
        # transport's last question as its launch: here the connection takes 1 s, so the launch is
        # 1 s after the start, both before the run's deadline. The twin connects at once, and its
        # launch is its start.
        for connect_s in (1, 0):
            with self.subTest(connect_s=connect_s):
                D = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=runtime_fences(D))
                self.assertEqual(h.clock_read()['status'], STATUS['OK'])
                h.sim.hooks.append(lambda command: elapse(h, connect_s * 10 ** 9))
                self.assertEqual(h.clock_read()['status'], STATUS['OK'])
                capture = h.entries('capture')[-1].content
                start = capture['intent']['started_monotonic_ns']
                self.assertEqual(capture['result']['launch_monotonic_ns'], start + connect_s * 10 ** 9)
                self.assertLess(capture['result']['launch_monotonic_ns'], D)

    def test_a_tripped_fence_keeps_the_reading_it_judged(self):
        # The run's deadline, five nanoseconds past, and the stop file: each trips the fence of the
        # next command, and the stop records the monotonic reading that fence judged.
        for trip in ('the runtime deadline', 'the stop file'):
            with self.subTest(trip):
                directory = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
                self.addCleanup(shutil.rmtree, directory)
                D = labtest.Clock().mono + 600 * 10 ** 9
                h = self.harness(fences=dict(runtime_fences(D), stop_file=str(directory / 'STOP')))
                if trip == 'the stop file':
                    (directory / 'STOP').write_text('stop\n')
                    elapse(h, 7)
                else:
                    elapse(h, D + 5 - h.clock.mono)
                judged = h.clock.mono
                self.assertEqual(h.clock_read()['status'], STATUS['STOPPED'])
                [stop] = h.entries('stop')
                self.assertEqual(stop.content['monotonic_ns'], judged)

    def test_a_lost_generation_of_another_host_boot_is_never_signalled(self):
        # A broker is lost while it serves a generation; the reopening ends that generation. In
        # another host boot its process ID and start ticks name nothing of this boot: nothing is
        # asked or signalled, and the generation is recorded lost in another boot. In the same boot,
        # the twin, its process is ended as before.
        for case in ('another boot', 'the same boot'):
            with self.subTest(case):
                processes, asked = labtest.Processes(alive=True), []
                alive = processes.alive
                processes.alive = lambda pid, start: asked.append(pid) or alive(pid, start)
                h = Harness(processes=processes)
                self.addCleanup(h.close)
                h.begin(pid=4242, start_ticks=99)
                h.hello()
                h.broker.close()
                if case == 'another boot':
                    h.host_boot, h.clock.mono = OTHER_HOST_BOOT, labtest.Clock().mono // 2
                h.open()
                end = h.entries('generation-end')[-1].content
                if case == 'another boot':
                    self.assertEqual((processes.killed, asked), ([], []))
                    self.assertEqual((end['status'], end['killed'], end['violation'], end['host_boot']),
                                     ('LOST', False, lab_broker.LOST_OTHER_BOOT, 'another'))
                    continue
                self.assertEqual(processes.killed, [4242])
                self.assertEqual((end['status'], end['killed'], end['violation'], end['host_boot']),
                                 ('LOST', True, 'the broker was lost', 'this'))

    def test_a_lost_generation_of_an_unknown_host_boot_is_recorded_as_unknown(self):
        # When the lost generation's opening, or this one, could not read its host's boot ID, the
        # broker cannot tell the two boots apart. It ends a process that still runs as in this
        # boot, and its record says that the boot is unknown, never what a loss in this boot says;
        # so it does when the process had already ended. The twin, a loss in this boot, keeps the
        # plain record. Every one of them has the same keys.
        keys = set()
        for case, first, second, alive in (('this boot unread', labtest.HOST_BOOT, None, True),
                                           ("the generation's boot unread", None, labtest.HOST_BOOT, True),
                                           ('both unread', None, None, True),
                                           ('this boot unread, the process gone', labtest.HOST_BOOT, None, False),
                                           ('this boot', labtest.HOST_BOOT, labtest.HOST_BOOT, True)):
            with self.subTest(case):
                processes = labtest.Processes(alive=alive)
                h = Harness(processes=processes)
                self.addCleanup(h.close)
                h.broker.close()
                h.host_boot = first
                h.open()
                h.begin(pid=4242, start_ticks=99)
                h.hello()
                h.broker.close()
                h.host_boot = second
                h.open()
                end = h.entries('generation-end')[-1].content
                keys.add(tuple(sorted(end)))
                known = (('this', 'the broker was lost') if case == 'this boot'
                         else ('unknown', lab_broker.LOST_UNKNOWN_BOOT))
                self.assertEqual((end['status'], end['host_boot'], end['violation']), ('LOST',) + known)
                self.assertEqual((processes.killed, end['killed']), ([4242], True) if alive else ([], False))
        self.assertEqual(len(keys), 1)

    def test_a_reopening_does_not_wait_again_a_bound_it_waited_in_this_host_boot(self):
        # A broker is lost inside the native CREATE, so its effect is unknown, and the host boots
        # again. The first reopening in the new boot waits the command's whole bound. A second
        # reopening in that same boot does not wait it again; the twin, a reopening in yet another
        # boot, whose clock has not waited it, does. When the first reopening is itself lost during
        # its wait, it recorded no opening, and the next one in that boot waits the whole bound.
        for case in ('the same new boot', 'yet another boot', 'a reopening lost during its wait'):
            with self.subTest(case):
                h = self.harness()

                def lose(command):
                    if command.startswith('pm install-create'):
                        raise KeyboardInterrupt('the broker is lost here')
                h.sim.hooks.append(lose)
                with self.assertRaises(KeyboardInterrupt):
                    h.cross('CREATE', 2)
                h.sim.hooks.clear()
                intent = h.broker.ledger.last.content['intent']
                bound = int((intent['timeout_s'] + labtest.LIMITS['drain_grace_s']) * 1e9)
                h.broker.close()
                h.host_boot, h.clock.mono = OTHER_HOST_BOOT, labtest.Clock().mono // 2
                h.clock.slept.clear()
                if case == 'a reopening lost during its wait':
                    def lost_in_the_wait(seconds):
                        elapse(h, int(seconds * 1e9) // 2)
                        raise KeyboardInterrupt('the reopening broker is lost during its wait')
                    h.clock.sleep = lost_in_the_wait
                    with self.assertRaises(KeyboardInterrupt):
                        h.open()
                    del h.clock.sleep
                    self.assertEqual([e.content['host_boot_id'] for e in h.entries('open')], [labtest.HOST_BOOT])
                else:
                    h.open()
                    self.assertLess(abs(sum(h.clock.slept) * 1e9 - bound), 1000)
                    h.broker.close()
                if case == 'yet another boot':
                    h.host_boot, h.clock.mono = '3c8d9a14-5e2f-4b61-a7d0-9f1e6b2c4d58', labtest.Clock().mono // 3
                h.clock.slept.clear()
                before = h.clock.mono
                h.open()
                opened = h.entries('open')[-1].content
                if case == 'the same new boot':
                    self.assertEqual(h.clock.slept, [])
                    self.assertLessEqual(opened['drained_until_monotonic_ns'], before)
                    continue
                self.assertLess(abs(sum(h.clock.slept) * 1e9 - bound), 1000)
                self.assertEqual(opened['drained_until_monotonic_ns'], before + bound)

    def test_the_reopening_waits_on_the_host_monotonic_clock_whatever_the_wall_clock_does(self):
        # A broker is lost inside the native CREATE, so its effect is unknown, and 10 s later it is
        # reopened. The wait is that command's bound, counted on the host's monotonic clock from its
        # start: with the wall clock unchanged, an hour ahead or an hour back, the same. In another
        # host boot the clock it started on is gone, and the reopening waits the whole bound.
        for case, step in (('unchanged', 0), ('the wall clock an hour ahead', 3600),
                           ('the wall clock an hour back', -3600), ('another boot', 0)):
            with self.subTest(case):
                h = self.harness()

                def lose(command):
                    if command.startswith('pm install-create'):
                        raise KeyboardInterrupt('the broker is lost here')
                h.sim.hooks.append(lose)
                with self.assertRaises(KeyboardInterrupt):
                    h.cross('CREATE', 2)
                h.sim.hooks.clear()
                intent = h.broker.ledger.last.content['intent']
                bound = int((intent['timeout_s'] + labtest.LIMITS['drain_grace_s']) * 1e9)
                h.broker.close()
                elapse(h, 10 * 10 ** 9)
                h.clock.wall += step * 10 ** 9
                if case == 'another boot':
                    h.host_boot, h.clock.mono = OTHER_HOST_BOOT, labtest.Clock().mono // 2
                before = h.clock.mono
                h.clock.slept.clear()
                h.open()
                drain = before + bound if case == 'another boot' else intent['started_monotonic_ns'] + bound
                opened = h.entries('open')[-1].content
                self.assertEqual((opened['drained_until_monotonic_ns'], opened['host_boot_id']), (drain, h.host_boot))
                self.assertLess(abs(sum(h.clock.slept) * 1e9 - (drain - before)), 1000)
                self.assertEqual(len(h.clock.slept), 1)

    def test_the_admission_names_its_runtime_deadline_with_its_host_boot_or_neither(self):
        # The old wall deadline is refused, and so are a deadline without its host boot, a boot
        # without its deadline, a boot ID of no known form, and a deadline that is no positive
        # instant. A deadline with its boot, and neither, are admitted.
        directory = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, directory)
        good = runtime_fences(10 ** 12)
        bad = [dict(good, deadline_wall_ns=10 ** 12), {k: v for k, v in good.items() if k != 'host_boot_id'},
               dict(good, host_boot_id=None), dict(good, deadline_monotonic_ns=None),
               dict(good, host_boot_id=labtest.HOST_BOOT.upper()), dict(good, host_boot_id='boot'),
               dict(good, deadline_monotonic_ns=0), dict(good, deadline_monotonic_ns=True),
               dict(good, deadline_monotonic_ns=1.5)]
        for fences in bad:
            with self.subTest(fences=fences), self.assertRaises(lab_broker.BrokerError):
                lab_broker.check_admission(labtest.admission(directory, fences=fences))
        for fences in (good, runtime_fences(None, None)):
            lab_broker.check_admission(labtest.admission(directory, fences=fences))


class FenceDuringFeaturesTests(Base):
    def test_a_fence_that_trips_during_the_feature_query_stops_the_next_command(self):
        for kind in ('stop', 'lease', 'deadline'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                lease = Path(directory) / 'lease'
                lease.write_text('runtime-7\n')
                stop = Path(directory) / 'STOP'
                fences = {'stop_file': str(stop), 'lease_file': str(lease), 'lease_token': 'runtime-7',
                          'deadline_monotonic_ns': labtest.Clock().mono + 10 ** 12, 'host_boot_id': labtest.HOST_BOOT}
                h = self.harness(fences=fences)
                features = h.broker.transport.features

                def trip(timeout, h=h, kind=kind, lease=lease, stop=stop, **extra):
                    value = features(timeout, **extra)
                    if kind == 'stop':
                        stop.write_text('stop\n')
                    elif kind == 'lease':
                        lease.write_text('runtime-8\n')
                    else:
                        h.clock.mono += 10 ** 13
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
        deadline = intent['started_monotonic_ns'] + int((intent['timeout_s'] + labtest.LIMITS['drain_grace_s']) * 1e9)
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
        start = h.clock.mono
        h.open()
        self.assertEqual(len(h.clock.slept), 1)
        self.assertEqual(start + int(h.clock.slept[0] * 1e9), deadline)
        self.assertEqual(h.entries('open')[-1].content['drained_until_monotonic_ns'], deadline)
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
            """A generation process that sends nothing and never exits. It holds none of the pipes
            the broker made for it, so its frame and output streams end at once."""

            def __init__(self, argv, **options):
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
        grace = h.broker.limits['exit_grace_s']
        self.assertEqual((stubborn[0].waits, stubborn[0].kills), ([grace, grace], 1))
        # The generation stays open in the ledger: no end is recorded and no other is served.
        self.assertIsNotNone(h.broker.open_generation)
        self.assertEqual((len(h.entries('generation')), h.entries('generation-end')), (1, []))
        with self.assertRaises(lab_broker.BrokerError):
            h.broker.begin_generation()


# A generation that writes its argument's bytes to the request pipe its environment names, then
# reads one whole reply when it has a request file. Its standard streams get a VM style warning.
FAKE = '''
import os, struct, sys
replies, requests = (int(n) for n in os.environ[%r].split(','))
warning = b'[0.000s][warning][gc] -XX:+PrintGC is deprecated. Will use -Xlog:gc instead.\\n'
os.write(1, warning)
os.write(2, warning)
os.write(requests, open(sys.argv[1], 'rb').read())
if sys.argv[2:] == ['reply']:
    head = os.read(replies, 12)
    left = struct.unpack('<I', head[8:12])[0] - len(head)
    while left > 0:
        left -= len(os.read(replies, left))
''' % lab_broker.FRAMES_ENV


class FrameChannelTests(Base):
    def generation(self, h, data, reply=False):
        request = h.directory / 'request'
        request.write_bytes(data)
        summary = h.broker.run_generation([sys.executable, '-c', FAKE, str(request)] + (['reply'] if reply else []))
        kept = (h.root / lab_broker.JVM / ('%06d.stderr' % summary['generation'])).read_bytes()
        return summary, kept

    def test_output_on_the_standard_streams_never_reaches_a_frame(self):
        h = Harness()
        self.addCleanup(h.close)
        hello = proto.encode(proto.message(
            'HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR,
            config=labtest.CONFIG, component=sim_android.PACKAGE, trust=labtest.TRUST, route=1))
        summary, kept = self.generation(h, hello, reply=True)
        self.assertEqual((summary['status'], summary['served'], summary['violation']), ('COMPLETE', 1, None))
        self.assertNotIn('unreadable', summary)
        # Both standard streams are the kept output file, and only the frame pipes carry frames.
        warning = b'[0.000s][warning][gc] -XX:+PrintGC is deprecated. Will use -Xlog:gc instead.\n'
        self.assertEqual(kept, warning * 2)
        self.assertEqual((summary['stderr_bytes'], summary['stderr_sha256']),
                         (len(kept), hashlib.sha256(kept).hexdigest()))

    def test_a_truly_unreadable_frame_is_refused_and_its_first_bytes_are_kept(self):
        h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=2))
        self.addCleanup(h.close)
        warning = b'[0.000s][warning][os,thread] Failed to start thread "Unknown thread" - pthread_create failed\n'
        frame = proto.encode(proto.message(
            'HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR,
            config=labtest.CONFIG, component=sim_android.PACKAGE, trust=labtest.TRUST, route=1))
        cases = {
            'a warning on the frame pipe': (warning, 'not a lab bridge frame', warning, False),
            'more bytes than the bound': (b'x' * 2000, 'not a lab bridge frame', b'x' * lab_broker.UNREADABLE_HEAD,
                                          True),
            'a frame cut short': (frame[:40], 'the stream ended inside a frame', frame[:40], False),
            'a warning before a whole frame': (warning + frame, 'not a lab bridge frame', warning + frame, False),
        }
        for name, (data, reason, head, more) in cases.items():
            with self.subTest(name):
                summary, kept = self.generation(h, data)
                self.assertEqual((summary['status'], summary['served'], summary['violation']),
                                 ('FAILED', 0, 'unreadable request: %s' % reason))
                self.assertEqual(summary['unreadable'], {'head': head.hex(), 'bytes': len(head), 'more': more})
                self.assertIn(b'[warning][gc]', kept)
                self.assertEqual(h.entries('generation-end')[-1].content['unreadable'], summary['unreadable'])


# A framed coordinator: it writes `before` bytes of output, sends the HELLO of its request file
# and reads its reply, then writes `after` bytes, and may first start a child that inherits its
# standard streams, as a library's helper would, its process ID written to `pid`.
OUTPUT_FAKE = '''
import os, struct, subprocess, sys, time
replies, requests = (int(n) for n in os.environ[%r].split(','))
args = dict(a.split('=', 1) for a in sys.argv[2:])
pattern = bytes(range(256)) * 4096

def output(size):
    while size > 0:
        size -= os.write(1, pattern[:min(size, len(pattern))])

if 'child' in args:
    child = subprocess.Popen([sys.executable, '-B', '-c', args['script'], args['child'], args['release']])
    open(args['pid'], 'w').write(str(child.pid))
    # The child runs, in its group or out of it, before any request; an early one has ended.
    end = time.monotonic() + 10
    while not os.path.exists(args['release'] + '.ready') and time.monotonic() < end:
        time.sleep(0.01)
    if args['child'] == 'early':
        child.wait()
output(int(args.get('before', 0)))
os.write(requests, open(sys.argv[1], 'rb').read())
head = b''
while len(head) < 12:
    more = os.read(replies, 12 - len(head))
    if not more:
        sys.exit(1)
    head += more
left = struct.unpack('<I', head[8:12])[0] - 12
while left > 0:
    left -= len(os.read(replies, left))
output(int(args.get('after', 0)))
''' % lab_broker.FRAMES_ENV
# The child: once running, and an escaped one out of its process group, it says so, waits for
# its release file, at most 10 s, then writes once to each inherited stream. An early child
# writes at once.
CHILD = '''
import os, pathlib, sys, time
mode, release = sys.argv[1], pathlib.Path(sys.argv[2])
if mode == 'escaped':
    os.setsid()
pathlib.Path(sys.argv[2] + '.ready').write_text('ready')
end = time.monotonic() + 10
while mode != 'early' and not release.exists() and time.monotonic() < end:
    time.sleep(0.01)
try:
    os.write(1, b'child standard output\\n')
    os.write(2, b'child standard error\\n')
except OSError:
    pass
'''


def written(size):
    """The first `size` bytes the framed coordinator writes."""
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def gone(pid, bound_s=3.0):
    """Whether a process has ended, a zombie included, within a bound."""
    end = time.monotonic() + bound_s
    while time.monotonic() < end:
        found = lab_broker.proc_start_ticks(pid)
        if found is None or found[0] == 'Z':
            return True
        time.sleep(0.02)
    return False


def retire(pid):
    """Ends a test's own child, if it still runs."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class GenerationOutputTests(Base):
    def generation(self, h, **options):
        request = h.directory / 'request'
        request.write_bytes(proto.encode(proto.message(
            'HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR,
            config=labtest.CONFIG, component=sim_android.PACKAGE, trust=labtest.TRUST, route=1)))
        argv = [sys.executable, '-B', '-c', OUTPUT_FAKE, str(request)] + ['%s=%s' % kv for kv in options.items()]
        summary = h.broker.run_generation(argv)
        kept = (h.root / lab_broker.JVM / ('%06d.stderr' % summary['generation'])).read_bytes()
        self.assertEqual((summary['stderr_bytes'], summary['stderr_sha256']),
                         (len(kept), hashlib.sha256(kept).hexdigest()))
        return summary, kept

    def stopped_after(self, h, reason):
        """The broker latched a stop for the generation's output, so no forward work follows."""
        self.assertEqual(([e.content['reason'] for e in h.entries('stop')], h.broker.stopped), ([reason], reason))
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['STOPPED'])

    def test_an_output_within_its_allowance_is_kept_whole_and_one_past_it_stops_forward_work(self):
        # A 1 MiB and an 8 MiB output, with the allowance's own edges.
        allowance = lab_broker.OUTPUT_ALLOWANCE
        self.assertEqual(allowance, 4 << 20)
        for size in (1 << 20, allowance, allowance + 1, 8 << 20):
            with self.subTest(size=size):
                h = Harness()
                self.addCleanup(h.close)
                summary, kept = self.generation(h, after=size)
                if size <= allowance:
                    self.assertEqual((summary['status'], summary['served'], summary['violation']),
                                     ('COMPLETE', 1, None))
                    self.assertNotIn('output', summary)
                    self.assertEqual(kept, written(size))
                    self.assertEqual((h.entries('stop'), h.broker.stopped), ([], None))
                    continue
                reason = "the generation's output passed its allowance of %d bytes" % allowance
                self.assertEqual((summary['status'], summary['served'], summary['violation']), ('FAILED', 1, reason))
                self.assertEqual(summary['output'], {'reason': reason, 'allowance': allowance, 'kept': allowance,
                                                     'dropped': size - allowance, 'unfinished_writer': False,
                                                     'error': None})
                # Nothing is truncated silently: the first bytes are kept, and the record says so.
                self.assertEqual(kept, written(allowance))
                self.stopped_after(h, 'generation 1: ' + reason)

    def test_output_past_its_allowance_before_a_request_leaves_it_unserved(self):
        h = Harness()
        self.addCleanup(h.close)
        summary, kept = self.generation(h, before=8 << 20)
        reason = "the generation's output passed its allowance of %d bytes" % lab_broker.OUTPUT_ALLOWANCE
        self.assertEqual((summary['status'], summary['served'], summary['violation']), ('FAILED', 0, reason))
        self.assertEqual((kept, summary['output']['dropped']), (written(lab_broker.OUTPUT_ALLOWANCE), 4 << 20))
        self.stopped_after(h, 'generation 1: ' + reason)
        # The serve loop's own gate latched the stop when it found the problem, before the end.
        self.assertLess(h.entries('stop')[0].number, h.entries('generation-end')[0].number)

    def test_a_child_that_inherits_the_output_is_retired_at_the_generations_end(self):
        # A library style child of the coordinator, still holding the inherited streams at the
        # coordinator's end, never changes the kept output once it is recorded. Its honest twin
        # wrote before the end, and its lines are kept and recorded.
        lines = b'child standard output\nchild standard error\n'
        for mode, expected in (('held', b''), ('early', lines)):
            with self.subTest(mode):
                h = Harness()
                self.addCleanup(h.close)
                release, pid = h.directory / 'release', h.directory / 'child-pid'
                summary, kept = self.generation(h, child=mode, script=CHILD, release=release, pid=pid)
                self.assertEqual((summary['status'], summary['served'], summary['violation']), ('COMPLETE', 1, None))
                self.assertNotIn('output', summary)
                self.assertEqual(kept, expected)
                child = int(pid.read_text())
                self.assertTrue(gone(child))
                release.write_text('release\n')
                time.sleep(0.2)
                self.assertEqual((h.root / lab_broker.JVM / '000001.stderr').read_bytes(), expected)

    def test_a_writer_that_left_the_group_is_an_unfinished_writer_and_stops_forward_work(self):
        h = Harness()
        self.addCleanup(h.close)
        release, pid = h.directory / 'release', h.directory / 'child-pid'
        started = time.monotonic()
        summary, kept = self.generation(h, child='escaped', script=CHILD, release=release, pid=pid)
        child = int(pid.read_text())
        self.addCleanup(retire, child)
        self.assertGreaterEqual(time.monotonic() - started, lab_broker.OUTPUT_DRAIN_S)
        reason = "a writer still held the generation's output 5 s after its end"
        self.assertEqual((summary['status'], summary['served'], summary['violation']), ('FAILED', 1, reason))
        self.assertEqual(summary['output'], {'reason': reason, 'allowance': lab_broker.OUTPUT_ALLOWANCE, 'kept': 0,
                                             'dropped': 0, 'unfinished_writer': True, 'error': None})
        self.stopped_after(h, 'generation 1: ' + reason)
        # The escaped writer's later output never reaches the kept output: it ends at its record.
        release.write_text('release\n')
        self.assertTrue(gone(child))
        self.assertEqual((h.root / lab_broker.JVM / '000001.stderr').read_bytes(), kept)


# A framed coordinator that sends each frame of its request file and reads each reply, keeping
# the replies beside that file, while a second thread writes `size` bytes of output once its
# trigger file appears, or closes both standard streams if the trigger reads `close`; once every
# frame was answered without the trigger, it writes nothing.
FLOOD_FAKE = '''
import os, pathlib, struct, sys, threading, time
replies, requests = (int(n) for n in os.environ[%r].split(','))
frames, trigger, size = pathlib.Path(sys.argv[1]).read_bytes(), pathlib.Path(sys.argv[2]), int(sys.argv[3])
answered, kept = threading.Event(), open(sys.argv[1] + '.replies', 'wb')

def flood():
    while not trigger.exists() and not answered.wait(0.005):
        pass
    if trigger.exists() and trigger.read_text() == 'close':
        os.close(1)
        os.close(2)
        return
    left = size if trigger.exists() else 0
    while left > 0:
        left -= os.write(1, b'x' * min(left, 65536))
thread = threading.Thread(target=flood)
thread.start()
at = 0
while at < len(frames):
    length = struct.unpack('<I', frames[at + 8:at + 12])[0]
    os.write(requests, frames[at:at + length])
    at += length
    head = b''
    while len(head) < 12:
        more = os.read(replies, 12 - len(head))
        if not more:
            break
        head += more
    if len(head) < 12:
        break
    left, body = struct.unpack('<I', head[8:12])[0] - 12, b''
    while left > 0:
        more = os.read(replies, left)
        if not more:
            break
        body, left = body + more, left - len(more)
    kept.write(head + body)
kept.close()
answered.set()
thread.join(10)
''' % lab_broker.FRAMES_ENV


# A coordinator that closes both standard streams at once, then sends each frame of its request
# file and reads each reply: its output ends while it is still being served.
CLOSED_FAKE = '''
import os, struct, sys, time
replies, requests = (int(n) for n in os.environ[%r].split(','))
os.close(1)
os.close(2)
time.sleep(0.05)
frames, at = open(sys.argv[1], 'rb').read(), 0
while at < len(frames):
    length = struct.unpack('<I', frames[at + 8:at + 12])[0]
    os.write(requests, frames[at:at + length])
    at += length
    head = b''
    while len(head) < 12:
        more = os.read(replies, 12 - len(head))
        if not more:
            sys.exit(1)
        head += more
    left = struct.unpack('<I', head[8:12])[0] - 12
    while left > 0:
        more = os.read(replies, left)
        if not more:
            sys.exit(1)
        left -= len(more)
''' % lab_broker.FRAMES_ENV


class Ending:
    """A collector's thread as a gate sees it while that thread reports and ends. The first time
    the broker's own thread asks whether it is alive before it reported, at a gate that `where`
    accepts, the thread first runs to its end: the switch that lets a gate's two reads straddle
    its report."""

    def __init__(self, collector, thread, where):
        self.collector, self.thread, self.where = collector, thread, where

    def is_alive(self):
        if (threading.current_thread() is threading.main_thread() and not self.collector.reported
                and self.where()):
            self.thread.join(5)
        return self.thread.is_alive()

    def join(self, timeout=None):
        return self.thread.join(timeout)


def ending(switched, where=lambda: True):
    """A collector whose sync takes 0.5 s, so the generation is still served while it ends; when
    `switched`, a gate that asks while it ends gets the switch of `Ending`."""
    class Collector(lab_broker._OutputCollector):
        def _run(self):
            sync = self._sync

            def slow(fd):
                time.sleep(0.5)
                sync(fd)
            self._sync = slow
            super()._run()

        def _start(self):
            super()._start()
            if switched:
                self._thread = Ending(self, self._thread, where)
    return Collector


def asked_at(name):
    """Whether the broker asks from inside its method `name`."""
    frame = sys._getframe(2)
    while frame is not None and frame.f_code.co_name != name:
        frame = frame.f_back
    return frame is not None


class OutputFenceTests(Base):
    def common(self, h):
        return {'installation': labtest.INSTALLATION, 'coordinator': labtest.COORDINATOR, 'config': labtest.CONFIG,
                'component': sim_android.PACKAGE, 'trust': labtest.TRUST, 'route': 1}

    def create(self, h, request=3):
        return proto.message('CROSS', '%032x' % request, h.manifest, ticket=TICKET, ticket_digest='11' * 32, plan=PLAN,
                             plan_digest='22' * 32, attempt=1, component=sim_android.PACKAGE, index=0,
                             crossing=proto.CROSSINGS['CREATE'][0], occurrence=1, entry_boot=h.sim.boot,
                             entry_instance=h.sim.instance, entry_elapsed=1000, grant=GRANT, reference=NONCE,
                             native=(proto.NONCE, 0, 0, '', 0, NONCE), bundle_apk=proto.ZERO_DIGEST, actor=2,
                             granted=0, window=0)

    def generation(self, h, messages, flood, size=lab_broker.OUTPUT_ALLOWANCE + 1):
        """A generation of the framed messages. `flood(h, trigger, seen)`, when given, installs what
        sends its output past the allowance at the chosen moment, keeping in `seen` what the
        collector had counted by then; `size` is what the trigger makes it write."""
        frames, trigger = h.directory / 'frames', h.directory / 'trigger'
        frames.write_bytes(b''.join(proto.encode(m) for m in messages))
        seen = []
        if flood is not None:
            flood(h, trigger, seen)
        argv = [sys.executable, '-B', '-c', FLOOD_FAKE, str(frames), str(trigger), str(size)]
        return h.broker.run_generation(argv), seen

    @staticmethod
    def replies(h):
        data, found = (h.directory / 'frames.replies').read_bytes(), []
        while data:
            length = int.from_bytes(data[8:12], 'little')
            found.append(proto.decode(data[:length], h.broker.protocol))
            data = data[length:]
        return found

    @staticmethod
    def overflow(h, trigger):
        """Triggers the output past the allowance and waits until the collector has counted it."""
        trigger.write_text('overflow now\n')
        end = time.monotonic() + 10
        while h.broker._collector.dropped == 0 and time.monotonic() < end:
            time.sleep(0.005)
        return h.broker._collector.dropped

    def stopped_before_any_launch(self, h, summary, launched):
        """Nothing was launched, the generation is not COMPLETE, and the overflow's stop was latched
        before its end. Returns the stop's entry."""
        self.assertEqual(launched, [])
        reason = "the generation's output passed its allowance of %d bytes" % lab_broker.OUTPUT_ALLOWANCE
        self.assertNotEqual(summary['status'], 'COMPLETE')
        self.assertEqual((summary['output']['reason'], summary['output']['dropped']), (reason, 1))
        stop = h.entries('stop')
        self.assertEqual([e.content['reason'] for e in stop], ['generation 1: ' + reason])
        self.assertLess(stop[0].number, h.entries('generation-end')[-1].number)
        return stop[0]

    def test_a_known_overflow_launches_no_later_command_of_the_request_it_arose_in(self):
        # Output passes the allowance during CREATE's preflight clock read, and the collector has
        # counted it before that read ends: no later command of the request is admitted, by the
        # fence before each intent, and the native CREATE never launches. Its twin launches it.
        for flooded in (True, False):
            with self.subTest(flooded=flooded):
                h = Harness()
                self.addCleanup(h.close)
                known = []

                def flood(h, trigger, seen):
                    def hook(command):
                        if command == 'sim:clock' and h.broker.open_crossings and not trigger.exists():
                            seen.append(self.overflow(h, trigger))
                            known.append(len(h.broker.ledger.entries))
                    h.sim.hooks.append(hook)
                clock = proto.message('CLOCK', '%032x' % 2, h.manifest)
                summary, seen = self.generation(
                    h, [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)), clock, self.create(h)],
                    flood if flooded else None)
                launched = [c for c in h.sim.calls if c[0] == 'CREATE']
                reply = self.replies(h)[-1]
                if not flooded:
                    self.assertEqual((summary['status'], len(launched), reply['status']), ('COMPLETE', 1, STATUS['OK']))
                    continue
                self.assertEqual(seen, [1])
                stop = self.stopped_before_any_launch(h, summary, launched)
                # The read whose output overflowed ends; nothing is begun after it.
                self.assertEqual([e.number for e in h.entries('capture') if e.number > known[0]], [])
                self.assertEqual((reply['type'], reply['status'], reply['reason']),
                                 ('CROSS_REPLY', STATUS['STOPPED'], stop.content['reason']))

    def test_a_problem_known_after_a_commands_intent_sends_nothing(self):
        # The output passes the allowance once the native CREATE's intent is durable: the launch
        # gate after the intent ends it not launched, then latches and raises the stop.
        for flooded in (True, False):
            with self.subTest(flooded=flooded):
                h = Harness()
                self.addCleanup(h.close)
                begin = h.broker.ledger.begin_capture

                def flood(h, trigger, seen):
                    def intent(value):
                        entry = begin(value)
                        if value['command'].startswith('pm install-create') and flooded:
                            seen.append(self.overflow(h, trigger))
                        return entry
                    h.broker.ledger.begin_capture = intent
                summary, seen = self.generation(
                    h, [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)), self.create(h, 2)], flood)
                launched = [c for c in h.sim.calls if c[0] == 'CREATE']
                [create] = [e for e in h.entries('capture')
                            if e.content['intent']['command'].startswith('pm install-create')]
                reply = self.replies(h)[-1]
                if not flooded:
                    self.assertEqual((summary['status'], len(launched), create.content['result']['launch'],
                                      reply['status']), ('COMPLETE', 1, 'launched', STATUS['OK']))
                    continue
                self.assertEqual(seen, [1])
                stop = self.stopped_before_any_launch(h, summary, launched)
                self.assertEqual((create.content['result']['launch'], create.content['result']['error']),
                                 ('not-launched', summary['output']['reason']))
                self.assertEqual([e.number for e in h.entries('capture') if e.number > create.number], [])
                self.assertGreater(stop.number, create.number)
                self.assertEqual((reply['type'], reply['status'], reply['reason']),
                                 ('CROSS_REPLY', STATUS['STOPPED'], stop.content['reason']))

    def test_a_problem_known_before_a_host_call_begins_no_host_effect(self):
        for flooded in (True, False):
            with self.subTest(flooded=flooded):
                h = Harness()
                self.addCleanup(h.close)
                positive = h.broker._positive_problem

                def flood(h, trigger, seen):
                    def problem(plan, attempt):
                        seen.append(self.overflow(h, trigger))
                        return positive(plan, attempt)
                    h.broker._positive_problem = problem
                host = proto.message('HOST', '%032x' % 2, h.manifest, phase=1, crossing=proto.HOST_CROSSINGS['SIGN'],
                                     ticket=TICKET, plan=PLAN, attempt=1, index=0, occurrence=1, reference='9b' * 16,
                                     outcome=0, reply=proto.ZERO_DIGEST)
                summary, seen = self.generation(
                    h, [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)), host],
                    flood if flooded else None)
                begun = [e.number for e in h.entries('host') if e.content['phase'] == 'BEGIN']
                reply = self.replies(h)[-1]
                if not flooded:
                    self.assertEqual((summary['status'], len(begun), reply['status']), ('COMPLETE', 1, STATUS['OK']))
                    continue
                self.assertEqual(seen, [1])
                stop = self.stopped_before_any_launch(h, summary, begun)
                # A host reply has no STOPPED: the call is refused with the stop's reason, so the
                # bridge never runs it, and the generation ends after that reply. The refusal is
                # recorded, and the reply names its record.
                self.assertEqual((reply['type'], reply['status'], reply['reason'], summary['served']),
                                 ('HOST_REPLY', STATUS['REFUSED'], stop.content['reason'], 2))
                self.assertEqual([(e.number, e.content['phase'], e.content['reason']) for e in h.entries('host')],
                                 [(reply['record'], 'REFUSED', stop.content['reason'])])

    def test_output_during_a_call_lets_that_call_finish_and_starts_nothing_after_it(self):
        # Output passes the allowance while one command is already inside its transport call: a
        # preflight read, or the native CREATE itself. That call may finish, and is recorded as it
        # ran; then no later command, no crossing effect launch and no host call starts, though the
        # generation asks for a host call next. The twin runs the crossing and its host call.
        for case in ('a preflight read', 'the effect launch', 'no overflow'):
            with self.subTest(case):
                h = Harness()
                self.addCleanup(h.close)
                inside = {'a preflight read': 'sim:clock', 'the effect launch': 'pm install-create'}.get(case)
                current = []

                def flood(h, trigger, seen):
                    def hook(command):
                        if command.startswith(inside) and h.broker.open_crossings and not trigger.exists():
                            seen.append(self.overflow(h, trigger))
                            current.append(len(h.broker.ledger.entries))
                    h.sim.hooks.append(hook)
                host = proto.message('HOST', '%032x' % 3, h.manifest, phase=1, crossing=proto.HOST_CROSSINGS['SIGN'],
                                     ticket=TICKET, plan=PLAN, attempt=1, index=0, occurrence=1, reference='9b' * 16,
                                     outcome=0, reply=proto.ZERO_DIGEST)
                summary, seen = self.generation(
                    h, [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)), self.create(h, 2), host],
                    flood if inside else None)
                launched = [c for c in h.sim.calls if c[0] == 'CREATE']
                hosts = [e.content['phase'] for e in h.entries('host')]
                replies = [(r['type'], r['status']) for r in self.replies(h)]
                if inside is None:
                    self.assertEqual((summary['status'], len(launched), hosts, replies),
                                     ('COMPLETE', 1, ['BEGIN', 'END'], [('HELLO_REPLY', STATUS['OK']),
                                      ('CROSS_REPLY', STATUS['OK']), ('HOST_REPLY', STATUS['OK'])]))
                    continue
                self.assertEqual(seen, [1])
                # The call that was inside its transport call finished, and is recorded as it ran.
                [call] = [e for e in h.entries('capture') if e.number == current[0]]
                self.assertTrue(call.content['intent']['command'].startswith(inside))
                self.assertEqual((call.content['result']['launch'], call.content['result']['completion'],
                                  call.content['result']['exit']), ('launched', 'exited', 0))
                self.assertEqual(len(launched), 1 if case == 'the effect launch' else 0)
                # Then nothing starts: no command, no effect launch and no host call.
                self.assertEqual([e.number for e in h.entries('capture') if e.number > call.number], [])
                [stop] = h.entries('stop')
                self.assertGreater(stop.number, call.number)
                self.assertEqual((hosts, summary['served'], replies),
                                 ([], 2, [('HELLO_REPLY', STATUS['OK']), ('CROSS_REPLY', STATUS['STOPPED'])]))
                self.assertNotEqual(summary['status'], 'COMPLETE')

    def test_a_gate_asking_while_the_collector_reports_and_ends_finds_no_problem(self):
        # The generation closes its standard streams, then sends HELLO and CLOCK, so its output ends
        # while it is served; its collector's sync takes 0.5 s. At the first gate that asks while
        # the collector ends, the switch lets the collector report and end between whatever two
        # reads the gate makes. The collector did report: no gate may find a problem, no stop is
        # latched, and the generation completes with its empty output final, as its twin does.
        for switched in (True, False):
            with self.subTest(switched=switched):
                h = Harness()
                self.addCleanup(h.close)
                frames, made, collector = h.directory / 'frames', [], ending(switched)
                frames.write_bytes(proto.encode(proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)))
                                   + proto.encode(proto.message('CLOCK', '%032x' % 2, h.manifest)))

                def make(*args):
                    made.append(collector(*args))
                    return made[-1]
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', make):
                    summary = h.broker.run_generation([sys.executable, '-B', '-c', CLOSED_FAKE, str(frames)])
                self.assertEqual((made[0].reported, made[0].final, [e.content['reason'] for e in h.entries('stop')]),
                                 (True, True, []))
                self.assertEqual((summary['status'], summary['served'], summary['violation'], summary['stderr_bytes'],
                                  summary['stderr_sha256']), ('COMPLETE', 2, None, 0, hashlib.sha256(b'').hexdigest()))
                self.assertNotIn('output', summary)

    def test_a_launch_gate_asking_while_the_collector_reports_and_ends_launches_as_its_twin(self):
        # The generation closes its standard streams during CREATE's preflight clock read, and
        # the collector has seen their end of file before that read returns; its sync takes 0.5 s.
        # The native CREATE's launch gate, once its intent is durable, gets the switch. The
        # collector reported, so the CREATE launches once, its capture ends, the crossing and the
        # generation complete, and the ledger is whole, as in the twin.
        for switched in (True, False):
            with self.subTest(switched=switched):
                h = Harness()
                self.addCleanup(h.close)
                made = []

                def gate():
                    last = h.broker.ledger.entries[-1]
                    return asked_at('_record_command') and last.kind == 'capture' and last.state == 'interrupted'
                collector = ending(switched, gate)

                def make(*args):
                    made.append(collector(*args))
                    return made[-1]

                def close(h, trigger, seen):
                    def hook(command):
                        if command == 'sim:clock' and h.broker.open_crossings and not trigger.exists():
                            staged = trigger.with_name('trigger.staged')
                            staged.write_text('close')
                            staged.replace(trigger)
                            end = time.monotonic() + 10
                            while not made[0].ended and time.monotonic() < end:
                                time.sleep(0.005)
                            seen.append(made[0].ended)
                    h.sim.hooks.append(hook)
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', make):
                    summary, seen = self.generation(
                        h, [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)), self.create(h, 2)],
                        close, size=0)
                self.assertEqual((seen, made[0].reported, [e.content['reason'] for e in h.entries('stop')]),
                                 ([True], True, []))
                self.assertEqual([e.number for e in h.broker.ledger.entries if not e.complete], [])
                [create] = [e for e in h.entries('capture')
                            if e.content['intent']['command'].startswith('pm install-create')]
                self.assertEqual((create.content['result']['launch'], len([c for c in h.sim.calls if c[0] == 'CREATE']),
                                  [e.content['status'] for e in h.entries('outcome')]), ('launched', 1, ['OK']))
                self.assertEqual((summary['status'], summary['served'], summary['stderr_bytes']), ('COMPLETE', 2, 0))

    def test_a_collector_seen_while_it_ends_is_never_taken_for_one_that_did_not_report(self):
        # The actual collector on a real pipe and file: its writer end is closed, so its thread
        # reads end of file, closes and reports, while this thread asks for its problem in a loop,
        # as a gate would, until the thread has ended. For 2 s of such ends no answer may name a
        # problem: the output is whole, and its collector reports.
        directory = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, directory)
        deadline, ends, named = time.monotonic() + 2.0, 0, []
        while time.monotonic() < deadline:
            ours, theirs = os.pipe()
            os.write(theirs, b'x' * 100)
            collector = lab_broker._OutputCollector(ours, directory / ('%06d' % ends), lab_broker.OUTPUT_ALLOWANCE,
                                                    lambda fd: None)
            os.close(theirs)
            while collector._thread.is_alive():
                found = collector.problem()
                if found is not None:
                    named.append((ends, found['reason']))
            collector._thread.join()
            self.assertEqual((collector.reported, collector.problem()), (True, None))
            ends += 1
        self.assertGreater(ends, 10)
        self.assertEqual(named[:3], [])

    def test_each_gate_asks_the_output_once_and_acts_on_that_answer(self):
        # Every answer the collector gives is numbered. The output passes the allowance just
        # before a gate asks: at the native CREATE's launch gate once its intent is durable, at the
        # fence before a command's intent, at the serve loop before a request, or at a host call's
        # BEGIN. Each launch gate asks once, and the stop the gate latches, and the refused
        # capture's error, name the answer that gate was given. The twin asks with no overflow.
        for case in ('the launch gate', 'the fence', 'the serve loop', 'a host BEGIN', 'no overflow'):
            with self.subTest(case):
                h = Harness()
                self.addCleanup(h.close)
                answers = []

                class Numbered(lab_broker._OutputCollector):
                    def problem(self):
                        found = super().problem()
                        caller = sys._getframe(1)
                        gate = caller.f_back.f_code.co_name if caller.f_code.co_name == '_output_stop' else \
                            caller.f_code.co_name
                        entry = caller.f_locals.get('entry') if gate == '_record_command' else None
                        answers.append((gate, entry and entry.number))
                        if found is not None:
                            found = dict(found, reason='%s (answer %d)' % (found['reason'], len(answers)))
                        return found
                hello = proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h))
                begin, positive = h.broker.ledger.begin_capture, h.broker._positive_problem

                def flood(h, trigger, seen):
                    if case == 'the launch gate':
                        def intent(value):
                            entry = begin(value)
                            if value['command'].startswith('pm install-create'):
                                seen.append(self.overflow(h, trigger))
                            return entry
                        h.broker.ledger.begin_capture = intent
                    elif case == 'the fence':
                        def hook(command):
                            if command == 'sim:clock' and h.broker.open_crossings and not trigger.exists():
                                seen.append(self.overflow(h, trigger))
                        h.sim.hooks.append(hook)
                    elif case == 'a host BEGIN':
                        def problem(plan, attempt):
                            seen.append(self.overflow(h, trigger))
                            return positive(plan, attempt)
                        h.broker._positive_problem = problem
                host = proto.message('HOST', '%032x' % 3, h.manifest, phase=1, crossing=proto.HOST_CROSSINGS['SIGN'],
                                     ticket=TICKET, plan=PLAN, attempt=1, index=0, occurrence=1, reference='9b' * 16,
                                     outcome=0, reply=proto.ZERO_DIGEST)
                messages = [hello, host] if case == 'a host BEGIN' else [hello, self.create(h, 2)]
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', Numbered):
                    if case == 'the serve loop':
                        summary, kept = GenerationOutputTests.generation(self, h, before=8 << 20)
                    else:
                        summary, seen = self.generation(h, messages, None if case == 'no overflow' else flood)
                launch = [entry for gate, entry in answers if gate == '_record_command']
                self.assertEqual(len(launch), len(set(launch)))
                stops = [e.content['reason'] for e in h.entries('stop')]
                if case == 'no overflow':
                    self.assertEqual((stops, summary['status']), ([], 'COMPLETE'))
                    continue
                [stop] = stops
                number = int(stop.rsplit('(answer ', 1)[1].rstrip(')'))
                gate = {'the launch gate': '_record_command', 'the fence': '_fence', 'the serve loop': 'serve',
                        'a host BEGIN': '_host'}[case]
                self.assertEqual(answers[number - 1][0], gate)
                if case == 'the launch gate':
                    [create] = [e for e in h.entries('capture')
                                if e.content['intent']['command'].startswith('pm install-create')]
                    self.assertEqual((answers[number - 1][1], 'generation 1: ' + create.content['result']['error']),
                                     (create.number, stop))

    def test_a_problem_once_named_stays_named_and_the_end_agrees_with_the_stop(self):
        # A view of the collector that names a problem once, at the first ask after the first
        # CLOCK's read, and none after it. The gate that asked latches the stop, and the collector
        # goes on naming that problem, so the generation's end records it too: never COMPLETE, and
        # never a stop that its own end contradicts. The twin's view names none, and it completes.
        reason = 'a modeled problem, named once'
        for named in (True, False):
            with self.subTest(named=named):
                h = Harness()
                self.addCleanup(h.close)
                view = {'armed': False, 'named': False}

                def arm(command):
                    if command == 'sim:clock' and named and not h.broker.open_crossings:
                        view['armed'] = True
                h.sim.hooks.append(arm)
                made = []

                class Once(lab_broker._OutputCollector):
                    def _problem(self):
                        found = super()._problem()
                        if found is None and view['armed'] and not view['named'] and asked_at('_output_stop'):
                            view['named'] = True
                            return {'reason': reason, 'allowance': self.allowance, 'kept': self.kept,
                                    'dropped': self.dropped, 'unfinished_writer': False, 'error': None}
                        return found

                def make(*args):
                    made.append(Once(*args))
                    return made[-1]
                clock = [proto.message('CLOCK', '%032x' % n, h.manifest) for n in (2, 3)]
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', make):
                    summary, seen = self.generation(
                        h, [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h))] + clock, None)
                if not named:
                    self.assertEqual((summary['status'], summary['served'], h.entries('stop')), ('COMPLETE', 3, []))
                    continue
                self.assertEqual(([e.content['reason'] for e in h.entries('stop')], view['named']),
                                 (['generation 1: ' + reason], True))
                self.assertNotEqual(summary['status'], 'COMPLETE')
                self.assertEqual((summary['output']['reason'], made[0].problem()['reason']), (reason, reason))

    def test_a_generation_lost_with_its_broker_never_has_its_output_claimed(self):
        # The generation writes 1000 bytes, then its broker is lost inside a CLOCK read and later
        # closed; the reopening ends the generation as lost. Whatever its file holds, its record
        # claims no size or digest, and says that its output's fate is unknown. The twin is served
        # to its end, and its output is recorded and final.
        for lost in (True, False):
            with self.subTest(lost=lost):
                h = Harness()
                self.addCleanup(h.close)
                made, real = [], lab_broker.subprocess.Popen

                def popen(argv, **options):
                    made.append(real(argv, **options))
                    return made[-1]

                def flood(h, trigger, seen):
                    def hook(command):
                        if command == 'sim:clock' and not h.broker.open_crossings and not trigger.exists():
                            trigger.write_text('write now\n')
                            end = time.monotonic() + 10
                            while h.broker._collector.kept < 1000 and time.monotonic() < end:
                                time.sleep(0.005)
                            seen.append(h.broker._collector.kept)
                            if lost:
                                raise KeyboardInterrupt('the broker is lost here')
                    h.sim.hooks.append(hook)
                messages = [proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h)),
                            proto.message('CLOCK', '%032x' % 2, h.manifest)]
                path = h.root / lab_broker.JVM / '000001.stderr'
                with unittest.mock.patch.object(lab_broker.subprocess, 'Popen', popen):
                    if not lost:
                        summary, seen = self.generation(h, messages, flood, size=1000)
                        self.assertEqual((seen, summary['status'], summary['stderr_bytes'], summary['stderr_sha256']),
                                         ([1000], 'COMPLETE', 1000, hashlib.sha256(path.read_bytes()).hexdigest()))
                        continue
                    with self.assertRaises(KeyboardInterrupt):
                        self.generation(h, messages, flood, size=1000)
                h.sim.hooks.clear()
                h.broker.close()
                made[0].wait(10)
                h.open()
                end = h.entries('generation-end')[-1].content
                self.assertEqual((len(path.read_bytes()), end['status'], end['stderr_bytes'], end['stderr_sha256']),
                                 (1000, 'LOST', None, None))
                self.assertEqual((end['output']['reason'], end['output']['kept']), (lab_broker.LOST_OUTPUT, None))

    def test_retirement_signals_the_group_while_its_leader_is_unreaped(self):
        # Each signal names an identity the generation still owns: its exited leader is still a
        # zombie when its group is signalled. A leader that outlives its grace is killed first, by
        # its own process ID, still unreaped. A process the broker cannot see without reaping is
        # reaped as before, and no group is signalled.
        real = os.killpg
        for name, linger in (('an exited leader', 0), ('a leader killed after its grace', 30)):
            with self.subTest(name):
                h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.25, exit_grace_s=0.5))
                self.addCleanup(h.close)
                states = []

                def killpg(pgid, signum):
                    found = lab_broker.proc_start_ticks(pgid)
                    states.append((found and found[0], signum))
                    return real(pgid, signum)
                script = 'import time; time.sleep(%d)' % linger
                with unittest.mock.patch.object(lab_broker.os, 'killpg', killpg):
                    summary = h.broker.run_generation([sys.executable, '-B', '-c', script])
                self.assertEqual(states, [('Z', signal.SIGKILL)])
                self.assertEqual(summary['killed'], bool(linger))
        h = Harness()
        self.addCleanup(h.close)
        calls = []

        class Unseen:
            def __init__(self, argv, **options):
                self.pid = 2 ** 22 + 2

            def wait(self, timeout=None):
                return 0
        with unittest.mock.patch.object(lab_broker.subprocess, 'Popen', Unseen), \
                unittest.mock.patch.object(lab_broker.os, 'killpg', lambda *a: calls.append(a)):
            summary = h.broker.run_generation(['unseen'])
        self.assertEqual((calls, summary['killed']), ([], False))

    def test_an_unreaped_leader_whose_kill_does_not_take_stays_open_within_its_bound(self):
        # The waits for an unreaped leader are bounded as a reaped one's are: a kill that does not
        # take, here one never delivered, leaves the generation open after its grace, unrecorded.
        h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.25, exit_grace_s=0.5))
        self.addCleanup(h.close)
        made, kills, real = [], [], lab_broker.subprocess.Popen

        def popen(argv, **options):
            made.append(real(argv, **options))
            return made[-1]
        started = time.monotonic()
        with unittest.mock.patch.object(lab_broker.subprocess, 'Popen', popen), \
                unittest.mock.patch.object(lab_broker.os, 'kill', lambda pid, signum: kills.append((pid, signum))), \
                self.assertRaises(lab_broker.BrokerError):
            h.broker.run_generation([sys.executable, '-B', '-c', 'import time; time.sleep(5)'])
        elapsed = time.monotonic() - started
        made[0].kill()
        made[0].wait()
        self.assertEqual(kills, [(made[0].pid, signal.SIGKILL)])
        self.assertLess(elapsed, 3.0)
        self.assertIsNotNone(h.broker.open_generation)
        self.assertEqual(h.entries('generation-end'), [])

    def test_a_short_write_then_an_error_keeps_exactly_the_acknowledged_prefix(self):
        # A write that acknowledges 123 bytes, then ENOSPC: the record keeps exactly those bytes'
        # size and digest, beside the error. Its twin's writer keeps all 1000 bytes.
        for mode in ('partial then error', 'normal'):
            with self.subTest(mode):
                h = Harness()
                self.addCleanup(h.close)

                class Short:
                    def __init__(self, file):
                        self.file, self.first = file, True

                    def __getattr__(self, name):
                        return getattr(self.file, name)

                    def write(self, data):
                        if mode == 'normal':
                            return self.file.write(data)
                        if self.first:
                            self.first = False
                            return self.file.write(data[:123])
                        raise OSError(errno.ENOSPC, 'no space left for the kept output')

                class Collector(lab_broker._OutputCollector):
                    def _run(self):
                        self._file = Short(self._file)
                        super()._run()
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', Collector):
                    summary, kept = GenerationOutputTests.generation(self, h, after=1000)
                if mode == 'normal':
                    self.assertEqual((summary['status'], kept), ('COMPLETE', written(1000)))
                    continue
                self.assertEqual((summary['status'], kept), ('FAILED', written(123)))
                self.assertEqual((summary['output']['kept'], summary['output']['error']),
                                 (123, 'OSError: [Errno 28] no space left for the kept output'))
                self.assertEqual(h.entries('stop')[-1].content['reason'],
                                 'generation 1: ' + summary['output']['reason'])

    def test_a_collector_stalled_in_a_write_leaves_its_output_unfinal_within_a_bound(self):
        # The collector's first write is held, for 8 s or, in the twin, 1 s; the producer writes
        # before HELLO and fills the pipe, and short bounds end and reap it. Every wait of the end
        # is bounded: the stalled collector's output is recorded as not final, with no size or
        # digest, and the stop latched. The twin's write returns within the bound, and its kept
        # output is final and recorded.
        for hold in (8.0, 1.0):
            with self.subTest(hold=hold):
                h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.25, exit_grace_s=0.25))
                self.addCleanup(h.close)
                release, holding = threading.Event(), threading.Event()
                self.addCleanup(release.set)
                threads = []

                class Held:
                    def __init__(self, file):
                        self.file, self.first = file, True

                    def __getattr__(self, name):
                        return getattr(self.file, name)

                    def write(self, data):
                        if self.first:
                            self.first = False
                            holding.set()
                            release.wait(hold)
                        return self.file.write(data)

                class Collector(lab_broker._OutputCollector):
                    def _run(self):
                        threads.append(self._thread)
                        self._file = Held(self._file)
                        super()._run()
                started = time.monotonic()
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', Collector):
                    request = h.directory / 'request'
                    request.write_bytes(proto.encode(proto.message('HELLO', '%032x' % 1, h.manifest, **self.common(h))))
                    summary = h.broker.run_generation([sys.executable, '-B', '-c', OUTPUT_FAKE, str(request),
                                                       'before=%d' % (1 << 20)])
                elapsed = time.monotonic() - started
                path = h.root / lab_broker.JVM / '000001.stderr'
                if hold < lab_broker.OUTPUT_DRAIN_S:
                    kept = path.read_bytes()
                    self.assertEqual((summary['stderr_bytes'], summary['stderr_sha256']),
                                     (len(kept), hashlib.sha256(kept).hexdigest()))
                    continue
                self.assertLess(elapsed, lab_broker.OUTPUT_DRAIN_S + lab_broker.OUTPUT_STOP_S + 1.5)
                reason = "the output's collector did not stop within 1 s: the kept output is not final"
                self.assertEqual((summary['status'] == 'COMPLETE', summary['stderr_bytes'], summary['stderr_sha256']),
                                 (False, None, None))
                self.assertEqual((summary['output']['reason'], summary['output']['unfinished_writer']), (reason, True))
                self.assertEqual(h.entries('stop')[-1].content['reason'], 'generation 1: ' + reason)
                # The broker's close awaits a collector it still holds within the same bound: one
                # stalled in its write is left so. Each held write's later end closes its file.
                holding.clear()
                ours, theirs = os.pipe()
                self.addCleanup(os.close, theirs)
                held = Collector(ours, h.directory / 'held.stderr', lab_broker.OUTPUT_ALLOWANCE, os.fsync)
                os.write(theirs, b'held output\n')
                self.assertTrue(holding.wait(5))
                h.broker._collector = held
                closing = time.monotonic()
                h.broker.close()
                self.assertLess(time.monotonic() - closing, lab_broker.OUTPUT_STOP_S + 1.0)
                self.assertEqual((held.stalled, held.problem()['unfinished_writer']), (True, True))
                release.set()
                for thread in threads:
                    thread.join(5)
                    self.assertFalse(thread.is_alive())

    def test_a_refused_spawn_leaves_no_pipe_open(self):
        def pipes():
            found = set()
            for name in os.listdir('/proc/self/fd'):
                try:
                    if os.readlink('/proc/self/fd/' + name).startswith('pipe:'):
                        found.add(name)
                except OSError:
                    pass
            return found
        h = Harness()
        self.addCleanup(h.close)
        before = pipes()

        def refuse(argv, **options):
            raise OSError(errno.EAGAIN, 'modeled spawn refusal')
        with unittest.mock.patch.object(lab_broker.subprocess, 'Popen', refuse), self.assertRaises(OSError):
            h.broker.run_generation(['refused'])
        self.assertEqual(pipes(), before)
        h.broker.close()
        self.assertEqual(pipes(), before)


# Each failure that `failing` models, and the reason its generation's record gives.
FAILURES = {
    'read': "the output pipe could not be read: OSError: [Errno 5] modeled pipe read failure",
    'write': 'the kept output could not be written: OSError: [Errno 28] modeled full disk',
    'sync': 'the kept output could not be synced: OSError: [Errno 5] modeled output sync failure',
    'sync, otherwise': 'the kept output could not be synced: RuntimeError: modeled sync defect',
    'close': 'the kept output could not be closed: OSError: [Errno 5] modeled final close failure',
    'pipe': 'the output pipe could not be closed: OSError: [Errno 5] modeled pipe close failure',
    'thread': "the output's collector failed: RuntimeError: modeled collector defect",
}


def failing(mode):
    """A collector whose stage fails as `mode` models, without disturbing the host: a read, the
    first write, the sync, the file's close or the pipe's close, each failing with an I/O error, a
    sync that fails otherwise, or an exception no stage expects, raised by the first write. Each
    close closes for real first, then fails, as close(2) may report a delayed I/O error. Any other
    mode fails nowhere."""
    class File:
        def __init__(self, file):
            self.file = file

        def __getattr__(self, name):
            return getattr(self.file, name)

        def write(self, data):
            if mode == 'write':
                raise OSError(errno.ENOSPC, 'modeled full disk')
            if mode == 'thread':
                raise RuntimeError('modeled collector defect')
            return self.file.write(data)

        def close(self):
            self.file.close()
            if mode == 'close':
                raise OSError(errno.EIO, 'modeled final close failure')

    def sync(fd):
        if mode == 'sync':
            raise OSError(errno.EIO, 'modeled output sync failure')
        raise RuntimeError('modeled sync defect')

    class Collector(lab_broker._OutputCollector):
        def _run(self):
            self._file = File(self._file)
            if mode.startswith('sync'):
                self._sync = sync
            super()._run()

        def _read(self):
            if mode == 'read':
                raise OSError(errno.EIO, 'modeled pipe read failure')
            return super()._read()

        def _close_pipe(self):
            super()._close_pipe()
            if mode == 'pipe':
                raise OSError(errno.EIO, 'modeled pipe close failure')
    return Collector


def held(path):
    """This process's descriptors of pipes and of `path`."""
    found = {}
    for name in os.listdir('/proc/self/fd'):
        try:
            target = os.readlink('/proc/self/fd/' + name)
        except OSError:
            continue
        if target.startswith('pipe:') or target == str(path):
            found[name] = target
    return found


class CollectorFailureTests(Base):
    def generation(self, h, collector, **options):
        """A generation that sends HELLO, reads its reply and writes `options`' output, its output
        collected by `collector`. Returns its summary and the bytes its kept file holds."""
        request = h.directory / 'request'
        request.write_bytes(proto.encode(proto.message(
            'HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR,
            config=labtest.CONFIG, component=sim_android.PACKAGE, trust=labtest.TRUST, route=1)))
        argv = [sys.executable, '-B', '-c', OUTPUT_FAKE, str(request)] + ['%s=%s' % kv for kv in options.items()]
        with unittest.mock.patch.object(lab_broker, '_OutputCollector', collector):
            summary = h.broker.run_generation(argv)
        return summary, (h.root / lab_broker.JVM / '000001.stderr').read_bytes()

    def failed_and_stopped(self, h, summary, kept, reason):
        """The generation is not COMPLETE, its record names the failure and claims exactly the
        bytes its file holds, and the stop is latched, so the next generation is told STOPPED."""
        self.assertNotEqual(summary['status'], 'COMPLETE')
        self.assertEqual(summary['output']['reason'], reason)
        self.assertEqual((summary['stderr_bytes'], summary['stderr_sha256']),
                         (len(kept), hashlib.sha256(kept).hexdigest()))
        GenerationOutputTests.stopped_after(self, h, 'generation 1: ' + reason)

    def test_a_close_that_fails_after_closing_is_recorded_and_stops_forward_work(self):
        # The file's close closes it, then fails with EIO. The failure is the output's problem:
        # never COMPLETE, and the stop is latched. Its twins: a normal writer, COMPLETE, and a
        # failing sync, recorded and stopped as before.
        for mode in ('close', 'normal', 'sync'):
            with self.subTest(mode):
                h = Harness()
                self.addCleanup(h.close)
                summary, kept = self.generation(h, failing(mode), after=1000)
                self.assertEqual(kept, written(1000))
                if mode == 'normal':
                    self.assertEqual((summary['status'], summary['stderr_bytes'], h.broker.stopped),
                                     ('COMPLETE', 1000, None))
                    self.assertNotIn('output', summary)
                    continue
                self.failed_and_stopped(h, summary, kept, FAILURES[mode])
                self.assertEqual(summary['output']['error'], FAILURES[mode].split(': ', 1)[1])

    def test_a_failure_at_any_stage_of_the_collector_is_recorded_and_stops_forward_work(self):
        # A read, the first write, the sync, either close, or the collector's thread itself fails:
        # each is recorded with its stage and stops forward work, and the record claims exactly
        # what the file holds. The honest twin's collector keeps all 1000 bytes, COMPLETE.
        for mode in ('normal',) + tuple(FAILURES):
            with self.subTest(mode):
                h = Harness()
                self.addCleanup(h.close)
                summary, kept = self.generation(h, failing(mode), after=1000)
                if mode == 'normal':
                    self.assertEqual((summary['status'], kept, h.broker.stopped), ('COMPLETE', written(1000), None))
                    continue
                self.failed_and_stopped(h, summary, kept, FAILURES[mode])
                self.assertEqual(kept, written(1000) if mode in ('sync', 'sync, otherwise', 'close', 'pipe') else b'')

    def test_a_collector_that_ends_without_its_own_report_leaves_an_output_that_is_not_final(self):
        # Its thread collects and closes, then ends without its report that it ended: quietly, or
        # dying of an exception. The output is not final, so no size or digest is claimed, and the
        # stop is latched. The twin reports.
        for mode in ('ends quietly', 'dies before its report', 'reports'):
            with self.subTest(mode):
                h = Harness()
                self.addCleanup(h.close)
                died = []

                class Collector(lab_broker._OutputCollector):
                    def _run(self):
                        if mode != 'ends quietly':
                            return super()._run()
                        self._collect()
                        self._close()

                    def _report(self):
                        if mode == 'dies before its report':
                            raise RuntimeError('modeled death before its report')
                        super()._report()
                with unittest.mock.patch.object(threading, 'excepthook', lambda args: died.append(args.exc_type)):
                    summary, kept = self.generation(h, Collector, after=1000)
                self.assertEqual((kept, died),
                                 (written(1000), [RuntimeError] if mode == 'dies before its report' else []))
                if mode == 'reports':
                    self.assertEqual((summary['status'], summary['stderr_bytes'], h.broker.stopped),
                                     ('COMPLETE', 1000, None))
                    continue
                reason = "the output's collector ended without reporting its end: the kept output is not final"
                self.assertNotEqual(summary['status'], 'COMPLETE')
                self.assertEqual((summary['stderr_bytes'], summary['stderr_sha256']), (None, None))
                self.assertEqual((summary['output']['reason'], summary['output']['unfinished_writer']), (reason, True))
                GenerationOutputTests.stopped_after(self, h, 'generation 1: ' + reason)

    def test_a_collector_failure_beside_a_refused_spawn_or_an_unreaped_leader_still_stops_forward_work(self):
        # No generation record ends either: the spawn is refused, or the leader's kill never takes.
        # A failure of the collector, its file's close here, is still recorded as the stop. Each
        # twin's collector does not fail, and the broker does not stop, as before.
        for case, mode in (('refused spawn', 'close'), ('refused spawn', 'normal'), ('unreaped leader', 'close'),
                           ('unreaped leader', 'normal')):
            with self.subTest(case=case, mode=mode):
                h = Harness(limits=dict(labtest.LIMITS, generation_idle_s=0.25, exit_grace_s=0.5))
                self.addCleanup(h.close)
                made, real = [], lab_broker.subprocess.Popen

                def popen(argv, **options):
                    if case == 'refused spawn':
                        raise OSError(errno.EAGAIN, 'modeled spawn refusal')
                    made.append(real(argv, **options))
                    return made[-1]
                expected = OSError if case == 'refused spawn' else lab_broker.BrokerError
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', failing(mode)), \
                        unittest.mock.patch.object(lab_broker.subprocess, 'Popen', popen), \
                        unittest.mock.patch.object(lab_broker.os, 'kill', lambda pid, signum: None), \
                        self.assertRaises(expected):
                    h.broker.run_generation([sys.executable, '-B', '-c', 'import time; time.sleep(5)'])
                for process in made:
                    process.kill()
                    process.wait()
                self.assertEqual(h.entries('generation-end'), [])
                if mode == 'normal':
                    self.assertEqual((h.entries('stop'), h.broker.stopped), ([], None))
                    continue
                reason = 'generation 1: ' + FAILURES['close']
                if case == 'refused spawn':
                    GenerationOutputTests.stopped_after(self, h, reason)
                    continue
                # The leader's generation stays open, as before, so nothing is served until a
                # reopening ends it; the stop is latched all the same, and outlives that reopening.
                self.assertEqual(([e.content['reason'] for e in h.entries('stop')], h.broker.stopped),
                                 ([reason], reason))
                self.assertIsNotNone(h.broker.open_generation)
                h.reopen()
                self.assertEqual((h.broker.stopped, h.broker.open_generation), (reason, None))
                GenerationOutputTests.stopped_after(self, h, reason)

    def test_output_after_a_failed_write_is_still_counted_and_its_overflow_recorded(self):
        # The first write fails, then the generation writes 5 MiB in all: what is read and not kept
        # is counted as dropped, so the overflow is recorded, beside the write's failure. Its twins:
        # a normal writer of 5 MiB, whose overflow is recorded as before, and a failed write with
        # 1000 bytes only, which is no overflow.
        allowance = lab_broker.OUTPUT_ALLOWANCE
        overflow = "the generation's output passed its allowance of %d bytes" % allowance
        for mode, size in (('write', 5 << 20), ('normal', 5 << 20), ('write', 1000)):
            with self.subTest(mode=mode, size=size):
                h = Harness()
                self.addCleanup(h.close)
                summary, kept = self.generation(h, failing(mode), after=size)
                output = summary['output']
                if mode == 'normal':
                    self.assertEqual((output['reason'], output['kept'], output['dropped'], output['error']),
                                     (overflow, allowance, size - allowance, None))
                    self.failed_and_stopped(h, summary, kept, overflow)
                    continue
                self.assertEqual((output['kept'], output['dropped'], output['error'], kept),
                                 (0, size, FAILURES['write'].split(': ', 1)[1], b''))
                self.failed_and_stopped(h, summary, kept, overflow if size > allowance else FAILURES['write'])

    def test_a_kept_output_that_cannot_be_opened_or_collected_starts_no_generation(self):
        # Its file exists already, cannot be made for want of space, or the collector's thread
        # cannot start: no generation starts, nothing it opened stays open, and the stop is latched
        # with the reason. A broker stopped already keeps its stop, and the failure is named beside
        # it. The twin opens it and completes.
        for mode in ('exists', 'no space', 'no thread', 'exists, stopped already', 'normal'):
            with self.subTest(mode):
                h = Harness()
                self.addCleanup(h.close)
                path, ran = h.root / lab_broker.JVM / '000001.stderr', h.directory / 'ran'
                if mode.startswith('exists'):
                    path.write_bytes(b'')
                if mode.endswith('stopped already'):
                    h.broker.stop('an earlier stop')

                class Collector(lab_broker._OutputCollector):
                    def _open(self, path):
                        if mode == 'no space':
                            raise OSError(errno.ENOSPC, 'modeled full disk')
                        return super()._open(path)

                    def _start(self):
                        if mode == 'no thread':
                            raise RuntimeError("can't start new thread")
                        super()._start()
                if mode == 'normal':
                    summary, kept = self.generation(h, Collector, after=1000)
                    self.assertEqual((summary['status'], kept, h.broker.stopped), ('COMPLETE', written(1000), None))
                    continue
                before = held(path)
                with unittest.mock.patch.object(lab_broker, '_OutputCollector', Collector), \
                        self.assertRaises(lab_broker.Stopped) as raised:
                    h.broker.run_generation([sys.executable, '-B', '-c', 'open(%r, "w").write("ran")' % str(ran)])
                error = {'exists': "FileExistsError: [Errno 17] File exists: '%s'" % path,
                         'no space': 'OSError: [Errno 28] modeled full disk',
                         'no thread': "RuntimeError: can't start new thread"}[mode.split(',')[0]]
                reason = "generation 1: the kept output's collector could not start: " + error
                self.assertEqual((h.entries('generation'), ran.exists(), held(path)), ([], False, before))
                if mode.endswith('stopped already'):
                    self.assertEqual(str(raised.exception), 'an earlier stop; then ' + reason)
                    GenerationOutputTests.stopped_after(self, h, 'an earlier stop')
                    continue
                self.assertEqual(str(raised.exception), reason)
                GenerationOutputTests.stopped_after(self, h, reason)


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
