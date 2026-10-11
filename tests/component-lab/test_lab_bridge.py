# SPDX-License-Identifier: Apache-2.0
"""End to end: the accepted Java coordinator, through the Java bridge, against the real broker on a
simulated guest. Each coordinator generation is a JVM process that the broker starts and reaps.

The suite needs a JDK and the compiled lab classes, named by ANDRIX_LAB_JAVA and ANDRIX_LAB_CLASSES,
which the lab runner provides inside its resource guard. Without them every case is skipped. The
host is the scripted host of the Java tests, not apksig. Host evidence only: no guest, no Android."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import labtest
from labtest import PLAN, REPO, TICKET
import lab_broker
import sim_android

JAVA = os.environ.get('ANDRIX_LAB_JAVA')
CLASSES = os.environ.get('ANDRIX_LAB_CLASSES')
MAIN = 'dev.andrix.lab.component.LabBridgeTestMain'
JVM = ('-Xmx256m', '-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1', '-XX:MaxMetaspaceSize=128m',
       '-XX:ReservedCodeCacheSize=48m', '-ea')
RESTORATION_APK = 'a2' * 32
TERMINAL = ('CLOSED_APPLIED', 'CLOSED_FAILED', 'CANCELLED', 'VOID', 'DIVERGED', 'SUPERSEDED')
TICKET_TWO = '05' * 16
DAY = 24 * 3600 * 1000


def cell(name, on='cross', mode='drop-reply', attempt=1, **key):
    value = {'cell': name, 'on': on, 'mode': mode, 'plan': PLAN, 'attempt': attempt}
    value.update(key)
    return value


class World:
    """A store made by the Java fixtures, a broker over a simulated guest, and the generations."""

    def __init__(self, cells=(), window=120_000, activate=None, target=None, notice=None, receipts=False):
        self._temp = tempfile.TemporaryDirectory()
        self.dir = Path(self._temp.name)
        self.store = self.dir / 'store'
        self.sim = sim_android.SimAndroid()
        self.target, self.notice, self.receipts = target, notice, receipts
        manifest = labtest.manifest_bytes()
        setup = ['setup', str(self.dir), str(self.store), hashlib.sha256(manifest).hexdigest(), PLAN, TICKET, str(window)]
        if activate is not None:
            setup.append(str(activate))
        config = self.java(*setup).strip()
        self.config = self.dir / 'bridge.config'
        self.admission = labtest.admission(self.dir, config=config)
        lab_broker.Broker.initialize(self.dir / 'broker', self.admission, manifest)
        self.open()
        self.apk, self.idsig = b'A' * 4096 + b'variant', b'S' * 512 + b'sidecar'
        self.bundle_apk = hashlib.sha256(self.apk).hexdigest()
        members = {}
        for member, data in (('base.apk', self.apk), ('base.apk.idsig', self.idsig)):
            path = self.dir / member
            path.write_bytes(data)
            members[member] = {'host': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        self.broker.pin_artifacts(PLAN, members)
        self.sim.apks[self.bundle_apk] = 40
        if cells:
            self.broker.admit_faults(list(cells))
        self.generations = []

    def open(self):
        self.broker = lab_broker.Broker.open(self.dir / 'broker', REPO, sim_android.SimTransport(self.sim),
                                             sim_android.SimReader(labtest.INSTALLATION, receipts=self.receipts),
                                             notice=self.notice, sync=False, target=self.target)

    def reopen(self):
        """A new broker on the same directory, as after the loss of the old one."""
        self.broker.close()
        self.open()

    def close(self):
        self.broker.close()
        self._temp.cleanup()

    def java(self, *args):
        done = subprocess.run([JAVA, *JVM, '-Djava.io.tmpdir=%s' % self.dir, '-cp', CLASSES, MAIN, *args],
                              capture_output=True, text=True, timeout=120)
        if done.returncode != 0:
            raise AssertionError('java %s failed: %s' % (args[0], done.stderr[-2000:]))
        return done.stdout

    def generation(self, *args):
        argv = [JAVA, *JVM, '-Djava.io.tmpdir=%s' % self.dir, '-Dandrix.lab.hostDir=%s' % (self.dir / 'host'),
                '-Dandrix.lab.bundleApk=%s' % self.bundle_apk, '-Dandrix.lab.restorationApk=%s' % RESTORATION_APK,
                '-cp', CLASSES, MAIN, str(self.config), *args]
        summary = self.broker.run_generation(argv)
        self.generations.append(summary)
        return summary

    def inspect(self, ticket=TICKET):
        line = self.java('inspect', str(self.store), ticket).strip()
        return dict(part.split('=', 1) for part in line.split(' '))

    def until(self, done, ticket=TICKET, generations=12, tick=40_000):
        state = None
        for _ in range(generations):
            self.generation('settle', ticket, '40')
            state = self.inspect(ticket)
            if done(state):
                return state
            self.sim.tick(tick)
        raise AssertionError('the ticket did not get there: %s' % state)

    def entries(self, kind):
        return [e for e in self.broker.ledger.entries if e.kind == kind]

    def calls(self, kind):
        return [c for c in self.sim.calls if c[0] == kind]

    def stored(self, observation):
        return (self.store / 'observations' / (observation + '.rec')).exists()

    def outcomes(self, crossing):
        """Each ledger outcome of a crossing name, with its crossing record."""
        records = {e.number: e.content for e in self.entries('crossing')}
        return [(records[o.content['crossing']], o.content) for o in self.entries('outcome')
                if records.get(o.content['crossing'], {}).get('crossing') == crossing]


@unittest.skipUnless(JAVA and CLASSES, 'needs ANDRIX_LAB_JAVA and ANDRIX_LAB_CLASSES')
class BridgeEndToEnd(unittest.TestCase):
    def world(self, cells=(), **options):
        world = World(cells, **options)
        self.addCleanup(world.close)
        return world

    def assert_applied(self, w, state):
        self.assertEqual(state['state'], 'CLOSED_APPLIED')
        self.assertEqual((state['choice'], state['plan'], state['revision'], state['realization']),
                         ('PLAN', PLAN, '1', 'CURRENT'))
        self.assertEqual(state['health'], '0/0/INCONCLUSIVE,')
        self.assertEqual(state['boots'], '1')
        self.assertEqual(w.sim.active, ('DATA_COPY', w.bundle_apk, 40))
        self.assertEqual((len(w.calls('CREATE')), len(w.calls('WRITE')), len(w.calls('COMMIT')),
                          len(w.calls('reboot'))), (1, 2, 1, 1))

    def test_a_ticket_closes_applied_from_observation_alone(self):
        w = self.world()
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)
        self.assertEqual(state['ledger'], 'SIGN,PUBLISH,CREATE,WRITE,COMMIT,REBOOT')
        self.assertEqual({g['status'] for g in w.generations}, {'COMPLETE'})
        # COMMIT and REBOOT carry their ACTIVATE grant's time and the plan's window to the broker's gate.
        # A reboot has no shell reply: a new boot ID resolves it.
        for crossing, granted, status in (('CREATE', 0, 'OK'), ('WRITE', 0, 'OK'), ('COMMIT', sim_android.WALL_BASE, 'OK'),
                                          ('REBOOT', sim_android.WALL_BASE, 'NO_REPLY')):
            record, outcome = w.outcomes(crossing)[0]
            window = DAY if granted else 0
            self.assertEqual((record['granted'], record['window'], outcome['status']), (granted, window, status), crossing)
        reports = [e.content for e in w.entries('report')]
        self.assertEqual(reports[-1]['state'], 23)

    def test_a_dropped_create_reply_binds_the_session_by_its_nonce(self):
        w = self.world([cell('drop-create', crossing='CREATE', occurrence=1)])
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)
        escrow = w.entries('escrow')
        self.assertEqual(len(escrow), 1)
        withheld = labtest.read_observation(bytes.fromhex(escrow[0].content['frame']))
        self.assertEqual(withheld['classification'], 1)
        self.assertFalse(w.stored(withheld['observation']))

    def test_a_dropped_commit_reply_is_resolved_by_the_ready_session(self):
        w = self.world([cell('drop-commit', crossing='COMMIT', occurrence=1)])
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)
        withheld = labtest.read_observation(bytes.fromhex(w.entries('escrow')[0].content['frame']))
        self.assertEqual(withheld['classification'], 3)
        self.assertFalse(w.stored(withheld['observation']))

    def test_a_loss_before_write_and_a_dropped_abandon_reply(self):
        w = self.world([cell('lose-write', mode='loss-before', crossing='WRITE', occurrence=1),
                        cell('drop-abandon', crossing='ABANDON', occurrence=1)])
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.generations[-1]['status'], 'DELIBERATE_HALT')
        self.assertEqual(w.inspect()['state'], 'SESSION_BOUND')
        self.assertEqual((w.calls('WRITE'), w.calls('push')), ([], []))
        w.generation('settle', TICKET, '40')
        state = w.inspect()
        self.assertEqual((state['state'], state['flags']), ('ABANDON_INTENT', '1'))
        self.assertEqual(len(w.calls('ABANDON')), 1)
        w.sim.framework_restart()
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assertEqual((state['state'], state['ledger']), ('CLOSED_FAILED', 'SIGN,PUBLISH,CREATE,WRITE,ABANDON'))
        self.assertEqual(len(w.calls('ABANDON')), 1)
        self.assertEqual(state['choice'], 'FACTORY')

    def test_a_loss_before_create_ends_in_no_session(self):
        w = self.world([cell('lose-create', mode='loss-before', crossing='CREATE', occurrence=1)])
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.generations[-1]['status'], 'DELIBERATE_HALT')
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.inspect()['state'], 'SESSION_INTENT')
        w.sim.framework_restart()
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assertEqual((state['state'], state['ledger']), ('CLOSED_FAILED', 'SIGN,PUBLISH,CREATE'))
        self.assertEqual(w.calls('CREATE'), [])
        fault = w.entries('fault')[0].content
        self.assertEqual((fault['decision'], fault['launched']), ('halt-before-effect', False))

    def test_a_loss_after_commit_resumes_by_observation(self):
        w = self.world([cell('lose-commit', mode='loss-after', crossing='COMMIT', occurrence=1)])
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.generations[-1]['status'], 'DELIBERATE_HALT')
        self.assertEqual(w.inspect()['state'], 'COMMIT_INTENT')
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)
        self.assertIsNotNone(w.entries('fault')[0].content['withheld_sha256'])

    def test_a_loss_between_the_selection_and_ticket_writes_moves_the_choice_once(self):
        w = self.world([cell('between', on='point', mode='halt', point='selection-written')])
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.generations[-1]['status'], 'DELIBERATE_HALT')
        state = w.inspect()
        self.assertEqual((state['state'], state['choice'], state['revision']), ('APPLIED_PROVISIONAL', 'PLAN', '1'))
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)

    def test_a_stop_fences_every_later_generation(self):
        w = self.world()
        w.generation('settle', TICKET, '40')
        Path(w.admission['fences']['stop_file']).write_text('stop\n')
        captured = len(w.entries('capture'))
        w.generation('settle', TICKET, '40')
        w.generation('check')
        self.assertEqual([g['status'] for g in w.generations[1:]], ['STOPPED', 'STOPPED'])
        self.assertEqual(len(w.entries('capture')), captured)
        self.assertEqual(len(w.entries('stop')), 1)

    def test_host_losses_resolve_by_reading_never_by_signing_again(self):
        w = self.world([cell('lose-sign', on='host', mode='loss-before', crossing='SIGN', occurrence=1),
                        cell('drop-publish', on='host', attempt=2, crossing='PUBLISH', occurrence=1)])
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.generations[-1]['status'], 'DELIBERATE_HALT')
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assertEqual((state['state'], state['ledger']), ('CLOSED_FAILED', 'SIGN'))
        self.assertFalse(list((w.dir / 'host').glob('sign-*')))
        w.java('ticket', str(w.store), PLAN, TICKET_TWO, '2b' * 16)
        state = w.until(lambda s: s['state'] in TERMINAL, ticket=TICKET_TWO)
        self.assertEqual((state['state'], state['ledger']), ('CLOSED_APPLIED', 'SIGN,PUBLISH,CREATE,WRITE,COMMIT,REBOOT'))
        self.assertEqual(len(list((w.dir / 'host').glob('publish-*'))), 1)
        self.assertEqual(w.entries('escrow')[0].content['cell'], 'drop-publish')


    # ---------------------------------------------------------------- the command gate and its races

    def abandoned_then_closed(self, w):
        """Runs a ticket to its abandon, then to its end. An abandoned session is proved gone only by
        a complete listing in a later framework instance than the abandon, so the framework restarts
        once the abandon is issued."""
        state = w.until(lambda s: s['state'] in TERMINAL or s['state'] == 'ABANDON_INTENT')
        if state['state'] == 'ABANDON_INTENT':
            self.assertEqual(len(w.calls('ABANDON')), 1)
            w.sim.framework_restart()
            state = w.until(lambda s: s['state'] in TERMINAL)
        self.assertEqual(state['state'], 'CLOSED_FAILED')
        self.assertEqual(state['choice'], 'FACTORY')
        return state

    def test_a_grant_that_expires_during_the_round_never_commits(self):
        w = self.world(activate=200_000)
        fired = []
        commit = lab_broker.proto.CROSSINGS['COMMIT'][0]

        def expire(command):
            # The COMMIT's own preflight reads the clock after the round's clock, which the reconciler
            # judged the grant by. The guest's time moves past the window in between.
            if command == 'sim:clock' and not fired and any(
                    m['crossing'] == commit for m in w.broker.open_crossings.values()):
                fired.append(command)
                w.sim.tick(200_000)
        w.sim.hooks.append(expire)
        w.until(lambda s: s['state'] == 'COMMIT_INTENT')
        # A session still open after a lost commit may be verifying. Only a later framework instance
        # in which it is live and not ready shows that the commit did nothing, and then it is abandoned.
        w.sim.framework_restart()
        state = self.abandoned_then_closed(w)
        self.assertTrue(fired)
        self.assertEqual(w.calls('COMMIT'), [])
        self.assertEqual(w.calls('reboot'), [])
        record, outcome = w.outcomes('COMMIT')[0]
        self.assertEqual(outcome['status'], 'NO_REPLY')
        self.assertIn('activation grant', outcome['reason'])
        self.assertNotEqual(state['state'], 'CLOSED_APPLIED')
        self.assertEqual(w.sim.active[0], 'FACTORY_COPY')

    def test_a_grant_that_expires_during_the_confirmation_never_commits(self):
        w = self.world(activate=200_000)
        fired = []
        commit = lab_broker.proto.CROSSINGS['COMMIT'][0]

        def slow_confirmation(command):
            # The COMMIT's exact session confirmation outlasts the window. The broker reads the clock
            # after it, as the last read before the launch.
            if command == 'sim:sessions' and not fired and any(
                    m['crossing'] == commit for m in w.broker.open_crossings.values()):
                fired.append(command)
                w.sim.tick(200_000)
        w.sim.hooks.append(slow_confirmation)
        w.until(lambda s: s['state'] == 'COMMIT_INTENT')
        w.sim.framework_restart()
        state = self.abandoned_then_closed(w)
        self.assertTrue(fired)
        self.assertEqual(w.calls('COMMIT'), [])
        self.assertEqual(w.calls('reboot'), [])
        record, outcome = w.outcomes('COMMIT')[0]
        self.assertEqual(outcome['status'], 'NO_REPLY')
        self.assertIn('activation grant is not valid', outcome['reason'])
        self.assertNotEqual(state['state'], 'CLOSED_APPLIED')
        self.assertEqual(w.sim.active[0], 'FACTORY_COPY')

    def test_a_change_between_the_write_members_is_never_continued(self):
        w = self.world()
        wrote = []

        def between(command):
            if command.startswith('pm install-write') and not wrote:
                wrote.append(command)
            elif command == 'sim:clock' and len(wrote) == 1:
                wrote.append('restart')
                w.sim.framework_restart()
        w.sim.hooks.append(between)
        state = self.abandoned_then_closed(w)
        self.assertEqual([c[2] for c in w.calls('WRITE')], ['base.apk'])
        record, outcome = w.outcomes('WRITE')[0]
        self.assertEqual(outcome['status'], 'NO_REPLY')
        self.assertIn('the first member was written', outcome['reason'])
        self.assertEqual(w.calls('COMMIT'), [])
        self.assertNotEqual(state['state'], 'CLOSED_APPLIED')

    def test_an_unknown_target_refuses_to_round_and_launches_nothing(self):
        w = self.world(target=lambda: 'UNKNOWN')
        w.generation('settle', TICKET, '40')
        self.assertEqual(w.generations[-1]['status'], 'FAILED')
        self.assertEqual([c for c in w.sim.calls if c[0] in ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'reboot')], [])
        self.assertEqual(w.inspect()['state'], 'PLANNED')

    def test_a_target_held_during_a_generation_stops_every_later_crossing(self):
        scope = {'value': 'ESTABLISHED_EMPTY'}

        def target():
            return scope['value']
        w = self.world(target=target)

        def held(command):
            if command.startswith('pm install-create'):
                scope['value'] = 'HELD'
        w.sim.hooks.append(held)
        w.generation('settle', TICKET, '40')
        self.assertEqual(len(w.calls('CREATE')), 1)
        self.assertEqual(w.calls('WRITE'), [])
        refused = [o for _, o in w.outcomes('WRITE')]
        self.assertTrue(refused and all(o['status'] == 'NO_REPLY' and 'target scope' in o['reason'] for o in refused))
        # Later generations learn the held target at HELLO. The own exact session may be abandoned.
        for _ in range(4):
            w.generation('settle', TICKET, '40')
            w.sim.tick(40_000)
        self.assertEqual(w.calls('WRITE'), [])
        self.assertEqual(w.calls('COMMIT'), [])
        self.assertEqual(w.calls('reboot'), [])
        self.assertTrue(all(c[1] == w.sim.next_session for c in w.calls('ABANDON')))

    def test_no_native_call_is_replayed_across_a_broker_reopening(self):
        w = self.world([cell('drop-create', crossing='CREATE', occurrence=1)])
        w.generation('settle', TICKET, '40')
        w.reopen()
        w.sim.tick(40_000)
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)
        self.assertEqual(len(w.calls('CREATE')), 1)
        self.assertEqual(len(w.entries('open')), 2)
        withheld = labtest.read_observation(bytes.fromhex(w.entries('escrow')[0].content['frame']))
        self.assertFalse(w.stored(withheld['observation']))

    def test_noisy_and_truncated_reads_give_no_fact_and_the_ticket_waits(self):
        w = self.world()
        w.sim.scripts['sim:sessions'] = ['before', lambda command: sim_android.result(command, 0, b'garbage\n')]
        state = w.until(lambda s: s['state'] in TERMINAL)
        self.assert_applied(w, state)
        statuses = [e.content['status'] for e in w.entries('group') if e.content['reader'] == 'sessions']
        self.assertIn('unavailable', statuses)
        self.assertIn('unclassified', statuses)

    def test_a_framework_restart_after_the_round_clock_gives_no_stale_crossing(self):
        w = self.world()
        stale, native = [], []
        write = lab_broker.proto.CROSSINGS['WRITE'][0]

        def restart(command):
            crossing = next(iter(w.broker.open_crossings.values()), None)
            # The first WRITE was decided on its round's clock. The framework restarts as the
            # crossing's gate begins, so its entry instance is stale before any of its reads.
            if command == 'sim:sessions' and crossing is not None and crossing['crossing'] == write and not stale:
                stale.append(crossing['entry_instance'])
                w.sim.framework_restart()
            if command.startswith('pm install-'):
                native.append((command.split()[1], crossing['entry_instance'], w.sim.instance))
        w.sim.hooks.append(restart)
        # The coordinator abandons the session it can no longer write, and proves the abandon in a later
        # framework instance.
        state = self.abandoned_then_closed(w)
        self.assertEqual(len(stale), 1)
        refused = [o for r, o in w.outcomes('WRITE') if r['entry_instance'] == stale[0]]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]['status'], 'NO_REPLY')
        self.assertIn('nothing launched', refused[0]['reason'])
        self.assertIn('session', refused[0]['reason'])
        # No native call ran in a framework instance other than its crossing's entry instance, and
        # none of the stale WRITE.
        self.assertTrue(native)
        self.assertEqual([call for call in native if call[1] != call[2]], [])
        self.assertNotIn(stale[0], [entry for kind, entry, _ in native if kind == 'install-write'])
        self.assertEqual([kind for kind, _, _ in native], ['install-create', 'install-abandon'])
        self.assertEqual(state['ledger'], 'SIGN,PUBLISH,CREATE,WRITE,ABANDON')

    def test_a_notice_without_receipts_never_permits_a_reboot(self):
        w = self.world(activate=300_000, notice=sim_android.SimNotice())
        w.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        # Past the notice delay and past the ACTIVATE window: the ticket may wait, never apply.
        for _ in range(10):
            w.generation('settle', TICKET, '40')
            w.sim.tick(40_000)
        state = w.inspect()
        notices = w.calls('NOTICE')
        self.assertTrue(notices, 'the other running user was owed a notice')
        # Each route SUCCESS is a reply, never a receipt: no user's delivery is satisfied by it.
        self.assertTrue(all(o['status'] == 'OK' for _, o in w.outcomes('NOTICE')))
        self.assertLessEqual(len(notices), 4)  # The plan's request limit of 3, plus one.
        self.assertEqual((w.calls('CREATE'), w.calls('COMMIT'), w.calls('reboot')), ([], [], []))
        self.assertNotIn(state['state'], ('CLOSED_APPLIED', 'APPLIED_PROVISIONAL'))
        self.assertEqual(w.sim.active[0], 'FACTORY_COPY')

    def drive(self, w, generations=18):
        """Settles the ticket to its end. When a generation changes nothing, the framework restarts,
        because only a listing in a later framework instance proves what a lost crossing did."""
        last = None
        for _ in range(generations):
            w.generation('settle', TICKET, '40')
            state = w.inspect()
            if state['state'] in TERMINAL:
                return state
            progress = (state['state'], state['ledger'])
            if progress == last:
                w.sim.framework_restart()
            last = progress
            w.sim.tick(40_000)
        raise AssertionError('the ticket did not end: %s' % state)

    def test_every_loss_and_dropped_reply_resolves_by_observation_without_a_repeat(self):
        companions = {'ABANDON': [cell('force-abandon', mode='loss-before', crossing='WRITE', occurrence=1)]}
        for crossing in ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'REBOOT'):
            for mode in ('loss-before', 'loss-after', 'drop-reply'):
                with self.subTest(crossing=crossing, mode=mode):
                    w = World([cell('matrix', mode=mode, crossing=crossing, occurrence=1)]
                              + companions.get(crossing, []))
                    try:
                        state = self.drive(w)
                        self.assertIn(state['state'], ('CLOSED_APPLIED', 'CLOSED_FAILED'))
                        # Every native mutation ran at most once for its ledger entry.
                        self.assertLessEqual(len(w.calls('CREATE')), 1)
                        self.assertLessEqual(len(w.calls('WRITE')), 2)
                        self.assertLessEqual(len(w.calls('COMMIT')), 1)
                        self.assertLessEqual(len(w.calls('ABANDON')), 1)
                        self.assertLessEqual(len(w.calls('reboot')), 1)
                        if state['state'] == 'CLOSED_APPLIED':
                            self.assert_applied(w, state)
                        else:
                            self.assertEqual(w.sim.active[0], 'FACTORY_COPY')
                        # The cell acted once, and nothing it withheld reached the store.
                        acted = [e for e in w.entries('fault') + w.entries('escrow') if e.content['cell'] == 'matrix']
                        self.assertEqual(len(acted), 1)
                        for escrow in w.entries('escrow'):
                            if escrow.content.get('frame'):
                                withheld = labtest.read_observation(bytes.fromhex(escrow.content['frame']))
                                self.assertFalse(w.stored(withheld['observation']))
                    finally:
                        w.close()

    def test_receipts_count_only_for_the_running_user_and_the_ticket_they_name(self):
        def world(serial):
            w = self.world(activate=900_000, notice=sim_android.SimNotice(), receipts=True)
            w.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
            notice = lab_broker.proto.CROSSINGS['NOTICE'][0]

            def receipt(command):
                if command == sim_android.NOTICE_COMMAND:
                    index = [m['index'] for m in w.broker.open_crossings.values() if m['crossing'] == notice][0]
                    w.sim.receipts.append({'user': 10, 'serial': serial, 'ticket': TICKET, 'index': index,
                                           'route': 'FULL_SCREEN'})
            w.sim.hooks.append(receipt)
            for _ in range(8):
                w.generation('settle', TICKET, '40')
                w.sim.tick(40_000)
            return w
        # A receipt of the running user's own serial satisfies the notice: the ticket goes on to stage.
        control = world(5)
        self.assertTrue(control.calls('NOTICE'))
        self.assertEqual(len(control.calls('CREATE')), 1)
        # A receipt of another serial is no delivery: nothing is staged and nothing reboots.
        other = world(6)
        self.assertTrue(other.calls('NOTICE'))
        self.assertLessEqual(len(other.calls('NOTICE')), 4)
        self.assertEqual((other.calls('CREATE'), other.calls('reboot')), ([], []))
        # A receipt naming another ticket ends the generation: the bridge never takes it.
        stray = self.world(activate=900_000, notice=sim_android.SimNotice(), receipts=True)
        stray.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        stray.sim.receipts.append({'user': 10, 'serial': 5, 'ticket': TICKET_TWO, 'index': 2, 'route': 'FULL_SCREEN'})
        stray.generation('settle', TICKET, '40')
        self.assertEqual(stray.generations[-1]['status'], 'FAILED')
        self.assertEqual(stray.calls('CREATE'), [])


if __name__ == '__main__':
    unittest.main()
