# SPDX-License-Identifier: Apache-2.0
"""End to end: the next campaign's driver over the accepted Java coordinator, the Java bridge and
the real broker on a simulated guest, with honest multi boot histories.

The driver's Java entry here is the host test entry, LabBridgeTestMain, with the scripted host of
the Java tests in place of apksig: the same command forms as the lab driver entry for the steps this
suite drives, the store's records through the deployment package's public API, and the repair
records through the same LabRepair code. The scripted host stands in for signing and the artifact
store; the lab driver suite runs the real host signer. The simulated guest boots as a kernel does:
a plain confirmation gives a new boot ID with a reset elapsed scale and keeps an uncommitted
session, a negative payload is rejected with a native recovery boot, a ready managed session
applies at its reboot.

The suite needs a JDK and the compiled lab classes, named by ANDRIX_LAB_JAVA and ANDRIX_LAB_CLASSES,
which the lab runner provides inside its resource guard; without them its cases are skipped. Host
evidence only: no guest, no Android."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import unittest.mock

import health_baseline
import health_compose
import health_witness
import labtest
import lab_broker
import lab_crossings
import lab_driver
import lab_evidence
import lab_records
import next_cells
import process_health
import sim_android
import sim_users

JAVA = os.environ.get('ANDRIX_LAB_JAVA')
CLASSES = os.environ.get('ANDRIX_LAB_CLASSES')
MAIN = 'dev.andrix.lab.component.LabBridgeTestMain'
PLANS = {'COHORT': '0a' * 16, 'A': '0d' * 16, 'R': '0f' * 16}
RUNTIME = 'e2' * 16
PREDICATES = {'FULL': 'd1' * 32, 'LIMITED': 'd2' * 32, 'REFUSED': 'd3' * 32}
# The scripted world's stand ins for the two helper jars: their digests become the readers' pins.
HELPER_BYTES = {'ui-state': b'U' * 2048 + b'a fixed read only UI state helper jar',
                'process-health': b'P' * 2048 + b'a fixed read only process history helper jar'}
VARIANT = (b'A' * 4096 + b'variant', b'S' * 512 + b'sidecar')
RESTORATION = (b'R' * 4096 + b'restoration', b'T' * 512 + b'restoration sidecar')
# Without a running full secondary user no activation owes a notice: this suite's declaration. The
# notice cells need F0's user setup, a later part. F0's branch is the guest's measurement, never
# the declaration's: a World is given the branch its F0 capability record names.
# Each cell's ticket.
TICKETS = {'cohort': '0b' * 16, 'h1': '31' * 16, 'h2-c0': '32' * 16, 'c1-w0-b1': '33' * 16, 'c2-w1-b2': '34' * 16,
           'm0-b0': '35' * 16, 'a': '36' * 16, 'r': '37' * 16}
DAY = 24 * 3600 * 1000


class ScriptedNextDriver(lab_driver.NextDriver):
    """The next driver with the scripted host's publication in place of the artifact store's export:
    a plan reads published once a PUBLISH of one of its tickets completed on the scripted host, and
    binds the scripted host's APKs, a repair plan the restoration as its variant."""

    def __init__(self, files, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.files = files

    def export(self, plan, out):
        published = any((self.files.host / ('publish-' + entry[5])).exists()
                        for t in self.tickets(plan) for entry in self.ticket_state(t['ticket'])['ledger']
                        if entry[0] == 'PUBLISH')
        if not published:
            return None
        record = self.plan_record(plan)
        members = RESTORATION if record['repairs'] != '00' * 16 else VARIANT
        lines = []
        for name, data in zip(lab_driver.MEMBERS, members):
            (out / name).write_bytes(data)
            lines.append('%s %s %d' % (name, hashlib.sha256(data).hexdigest(), len(data)))
        lines.append('publication %s' % hashlib.sha256(('publication ' + plan).encode('ascii')).hexdigest())
        return '\n'.join(lines) + '\n'


class World:
    """The next driver over a broker on a simulated guest with its full user forms, its health and
    process history readers, its global session inventory and the scripted host. The helpers are
    absent until the driver pushes them. The driver and the broker share one host clock that tests
    move by hand; it moves only through an ordinary read wait, so every other history keeps the
    host times it had. `wait_ms` is the admission's own ordinary wait budget, when not the frozen
    one."""

    def __init__(self, sequence=next_cells.SEQUENCE, notice=False, limited=False, f0='FULL', between=None,
                 verification=None, sync=False, wait_ms=None, n1=False):
        self._temp = tempfile.TemporaryDirectory()
        self.dir = Path(self._temp.name)
        self.store = self.dir / 'store'
        self.host = self.dir / 'host'
        self.sim = sim_android.SimAndroid()
        self.sim.enable_user_forms()
        self.sim.ui_helper = self.sim.process_helper = False
        self.declaration = next_cells.declaration(notice, limited)
        self.f0 = f0
        self.sequence = sequence
        self._patches = [unittest.mock.patch.object(health_compose, 'UI_STATE_HELPER_SHA256',
                                                    hashlib.sha256(HELPER_BYTES['ui-state']).hexdigest()),
                         unittest.mock.patch.object(process_health, 'HELPER_SHA256',
                                                    hashlib.sha256(HELPER_BYTES['process-health']).hexdigest())]
        for patch in self._patches:
            patch.start()
        self.helpers = {}
        for name, data in HELPER_BYTES.items():
            path = self.dir / ('%s.jar' % name)
            path.write_bytes(data)
            self.helpers[name] = path
        self.bundle_apk = hashlib.sha256(VARIANT[0]).hexdigest()
        self.restoration_apk = hashlib.sha256(RESTORATION[0]).hexdigest()
        self.sim.apks[self.bundle_apk] = 40
        self.sim.apks[self.restoration_apk] = 41
        self.payloads = {}
        roles = (('N1', labtest.N1_PAYLOAD),) if n1 else ()
        for role, payload in roles + (('N2', labtest.N2_PAYLOAD), ('N3', labtest.N3_PAYLOAD)):
            members = {}
            for member, data in payload:
                path = self.dir / ('%s-%s' % (role, member))
                path.write_bytes(data)
                members[member] = {'host': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            self.payloads[role] = members
        self.sim.wrong_signer.add(hashlib.sha256(labtest.N2_PAYLOAD[0][1]).hexdigest())
        self.verification = verification or {}
        self.driver = ScriptedNextDriver(self, self.dir, JAVA, CLASSES, PLANS, main=MAIN,
                                         properties=['-Dandrix.lab.hostDir=%s' % self.host,
                                                     '-Dandrix.lab.bundleApk=%s' % self.bundle_apk,
                                                     '-Dandrix.lab.restorationApk=%s' % self.restoration_apk,
                                                     '-Dandrix.lab.repair=%s %s' % (PLANS['R'], PLANS['A'])],
                                         clock=lambda: sim_android.WALL_BASE + self.sim.uptime,
                                         declaration=self.declaration, sequence=sequence,
                                         between=between or self.between, prepare=self.prepare, sync=sync,
                                         monotonic=lambda: self.clock.monotonic_ns(), foreground=self.foreground)
        manifest = labtest.manifest_bytes()
        config = self.driver.init(self.store, hashlib.sha256(manifest).hexdigest(), labtest.INSTALLATION,
                                  labtest.COORDINATOR, labtest.TRUST)
        pins = {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                for name, data in HELPER_BYTES.items()}
        payload_pins = {role: [{'role': m, 'sha256': v['sha256'], 'bytes': v['bytes']} for m, v in members.items()]
                        for role, members in self.payloads.items()}
        self.admission = lab_driver.next_admission(
            installation=labtest.INSTALLATION, coordinator=labtest.COORDINATOR, trust=labtest.TRUST,
            manifest=hashlib.sha256(manifest).hexdigest(), config=config, serial='127.0.0.1:6520',
            target_scope='ESTABLISHED_EMPTY', device_dir=labtest.DEVICE_DIR,
            fences={'stop_file': str(self.dir / 'STOP'), 'lease_file': None, 'lease_token': None,
                    'deadline_monotonic_ns': None, 'host_boot_id': None},
            limits=dict(labtest.LIMITS), store=self.store, plans=PLANS, runtime=RUNTIME, helpers=pins,
            predicates=PREDICATES, payloads=payload_pins, notice=notice, limited=limited, sequence=sequence,
            wait_policy=None if wait_ms is None else {'ordinary_wait_ms': wait_ms})
        self.schedule = next_cells.schedule_bytes(labtest.INSTALLATION, PLANS, self.declaration, sequence)
        lab_broker.Broker.initialize(self.dir / 'broker', self.admission, manifest)
        self.clock = labtest.Clock()
        # The broker's durability barriers are its own suites' to check; here they cost only time.
        self.fsync = None if sync else (lambda fd: None)
        self.open()
        self.thresholds = []
        # Each host step an ordinary read wait took, in milliseconds, in order.
        self.steps = []

    def open(self):
        reader = health_witness.WitnessReader()
        options = {'receipts': True, 'inventory': True, 'health': True, 'witness': True, 'global_sessions': True,
                   'users': True, 'composer': health_compose.Composer({}, witness=reader),
                   'baseline': health_baseline.BaselineReader(reader)}
        self.driver.broker = lab_broker.Broker.open(
            self.dir / 'broker', labtest.REPO, sim_android.SimTransport(self.sim),
            sim_android.SimReader(labtest.INSTALLATION, **options), notice=sim_android.SimNotice(), sync=False,
            health=sim_android.SimHealth(), wall=self.clock.wall_ns, monotonic=self.clock.monotonic_ns,
            sleep=self.clock.sleep, fsync=self.fsync)
        return self.driver.broker

    def close(self):
        self.driver.broker.close()
        for patch in reversed(self._patches):
            patch.stop()
        self._temp.cleanup()

    def completed_at(self):
        """The elapsed time of the current boot's first completed BOOT fact a round read."""
        for entry in self.driver.broker.ledger.entries:
            c = entry.content
            if entry.kind == 'group' and c.get('reader') == 'boot' and c.get('purpose') == 'observe' \
                    and c.get('status') == 'facts':
                found = [o for o in c['observations'] if o['boot'] == self.sim.boot and o['classification'] == 'COMPLETED']
                if found:
                    return found[0]['elapsed']
        return None

    def between(self, driver, state):
        """Lets simulated time pass after a round that changed nothing: two minutes in a window, a
        minute while a reboot request waits, and in M0's first verification wait exactly to the
        thresholds the cell names, one millisecond short and then exactly."""
        if state['state'] == 'BOOT_OBSERVED' and driver.cell == 'm0-b0' and len(self.thresholds) < 2 \
                and [e[0] for e in state['ledger']].count('ABANDON') == 0:
            completed = self.completed_at()
            target = completed + self.verification.get(len(self.thresholds), (599_999, 600_000)[len(self.thresholds)])
            self.thresholds.append({'completed': completed, 'at': target, 'abandons': 0})
            self.sim.tick(target - self.sim.uptime)
            return
        step = 120_000 if state['state'] == 'HEALTH_WINDOW' else 60_000 if state['state'] == 'REBOOT_INTENT' else 40_000
        self.pass_time(driver, step)

    def pass_time(self, driver, step, guest=True):
        """Moves the guest's clock by `step` milliseconds, unless `guest` is false. In an open
        ordinary wait the step is cut to what is left of it, as the driver cuts its own pause, and
        the host's clock moves by the same step."""
        remaining = driver.remaining_wait_s()
        if remaining is not None:
            step = min(step, int(remaining * 1000))
            self.clock.sleep(step / 1000)
            self.steps.append(step)
        if guest:
            self.sim.tick(step)

    def prepare(self, driver, ticket, plan, users):
        phase = 'R' if plan == PLANS['R'] else 'A'
        end = driver.broker.run_action(next_cells.action_id('prepare', phase), 'prepare a probe of the window')
        assert end['status'] == 'OK', end

    @contextlib.contextmanager
    def foreground(self, driver, issue, recipient):
        """The recipient's display in the foreground for its capture, and the user before it after:
        a world event standing in for the user setup's switch, a later part."""
        forms = self.sim.forms
        before = forms.current
        forms.current = recipient['user']
        forms.sync()
        try:
            yield
        finally:
            forms.current = before
            forms.sync()

    def start_secondary(self):
        """A running full secondary user, created once and started again in a later boot: world
        events standing in for F0's user setup and its start in each new boot, a later part. Returns
        its ID and serial."""
        forms = self.sim.forms
        created = [u for u in forms.users.values() if u.type == sim_users.SECONDARY_TYPE]
        if not created:
            forms.create('pm create-user AndrixLab', sim_users.SECONDARY_TYPE, 'AndrixLab')
            created = [u for u in forms.users.values() if u.type == sim_users.SECONDARY_TYPE]
        user = created[0]
        if not forms.running(user.id):
            forms.start('am start-user %d' % user.id, user.id)
        return user.id, user.serial

    def run(self):
        return self.driver.run_campaign(TICKETS, self.schedule, self.helpers, self.payloads,
                                        labtest.f0_record(self.f0))

    def entries(self, kind):
        return [e for e in self.driver.broker.ledger.entries if e.kind == kind]

    def calls(self, kind):
        return [c for c in self.sim.calls if c[0] == kind]


def sequence_of(*names, change=None):
    """A shorter campaign of the named cells in their order, each managed cell renumbered as its
    plan's next attempt. A cell that becomes A's first attempt signs and publishes itself, so its
    prediction gains SIGN and PUBLISH and it takes the plan's own grants. A's positive cell follows
    when none is named: the admission gates it, and these histories stop before it."""
    out, attempts = [], {}
    if not any(next_cells.by_cell(n)['phase'] == 'A' for n in names):
        names = names + ('a',)
    for name in names:
        c = copy.deepcopy(next_cells.by_cell(name))
        if c['kind'] == 'managed':
            attempt = attempts.get(c['plan'], 0) + 1
            p = c['prediction']
            if attempt == 1 and c['plan'] == 'A' and 'SIGN' not in p['ledger']:
                c['prediction'] = dict(p, ledger=['SIGN', 'PUBLISH'] + p['ledger'], signs=1, publishes=1)
                if c['without_notice'] is not None:
                    c['without_notice'] = {'ledger': ['SIGN', 'PUBLISH'] + c['without_notice']['ledger']}
            c['attempt'], c['grants'] = attempt, [] if attempt == 1 else c['grants']
            attempts[c['plan']] = attempt
        if change is not None:
            change(c)
        out.append(c)
    return tuple(out)


def store_record(world, kind, name):
    return (world.store / kind / (name + '.rec')).read_bytes()


def quiet(cell):
    """A managed cell without its faults: a short history that reaches its end plainly."""
    if cell['kind'] == 'managed':
        cell['faults'] = []


def only_commit(cell):
    """A's cell with only its dropped COMMIT reply, as the review's commit wait has it."""
    if cell['cell'] == 'a':
        cell['faults'] = [f for f in cell['faults'] if f['cell'] == 'a-commit']


@unittest.skipUnless(JAVA and CLASSES, 'needs ANDRIX_LAB_JAVA and ANDRIX_LAB_CLASSES')
class CampaignTests(unittest.TestCase):
    def world(self, **options):
        world = World(**options)
        self.addCleanup(world.close)
        return world

    def applied_history(self, w, repair=True):
        # The entry, a FULL F0, A to its end through rounds alone, and R to its end when asked.
        d = w.driver
        d.entry(w.schedule, w.helpers)
        d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
        d.cell = 'a'
        d.check()
        d.broker.gate_positive(PLANS['A'], 1, 'the positive attempt')
        d.plan(PLANS['A'], TICKETS['a'], 4)
        a = d.drive(w.sequence[1], TICKETS['a'], PLANS['A'])
        r = d.run_repair(w.sequence[2], TICKETS['r']) if repair else None
        return d, a, r

    def verifying(self, w, rounds, lost=0):
        # Each native COMMIT leaves its exact session verifying, with `lost` session reads lost
        # right after it, until its ticket has waited `rounds` times in COMMIT_INTENT: then it is
        # ready.
        waits = []

        def pending_commit(command):
            w.sim._run(command)
            w.sim.sessions[int(command.split()[-1])].state = 'VERIFYING'
            w.sim.scripts.setdefault('sim:sessions', []).extend(['before'] * lost)
            return sim_android.result(command, 0, lab_crossings.ACCEPTED)
        w.sim.scripts['pm install-commit '] = [pending_commit, pending_commit]

        def between(driver, state):
            if state['state'] == 'COMMIT_INTENT':
                waits.append(state['ticket'])
                if waits.count(state['ticket']) >= rounds:
                    for session in w.sim.sessions.values():
                        if session.state == 'VERIFYING':
                            session.state = 'READY'
            w.between(driver, state)
        w.driver.between_hook = between
        return waits

    def confirmations(self, w):
        return [e for e in w.entries('lab-action') if e.content.get('type') == 'PLAIN_KERNEL_CONFIRM']

    def test_the_whole_matrix_runs_in_order_to_its_predicted_ends(self):
        w = self.world()
        results = w.run()
        d = w.driver
        self.assertEqual({k: v['status'] for k, v in results.items()},
                         dict({c['cell']: 'PASSED' for c in next_cells.SEQUENCE}, n1='NOT_CAPTURED', f0='DECIDED'))
        self.assertEqual((results['f0']['branch'], d.world), ('FULL', {'notice': False, 'f0': 'FULL'}))
        # The boot phases, in ledger order: the initial boot, six plain confirmations, the two
        # negative activations (this guest's native recovery boots again at once, so no poll sees
        # the rejecting boot) and the A and R activations. No framework restart, ever.
        self.assertEqual([b['kind'] for b in d.boots], ['INITIAL'] + ['CONFIRMATION'] * 6
                         + ['NEGATIVE_ACTIVATION'] * 2 + ['MANAGED_ACTIVATION'] * 2)
        self.assertEqual([b['cell'] for b in d.boots[1:7]], [n for n, _, _ in next_cells.confirmation_cells()])
        self.assertEqual([b['cell'] for b in d.boots[9:]], ['a', 'r'])
        self.assertEqual([c for c in w.sim.calls if c[0] == 'am restart'], [])
        self.assertEqual([results[c]['boots'] for c in ('h1', 'h2-c0', 'c1-w0-b1', 'c2-w1-b2', 'm0-b0', 'a', 'r')],
                         [0, 1, 1, 1, 3, 1, 1])
        services = [e.content['intent'] for e in w.entries('capture')
                    if (e.content.get('intent') or {}).get('command') == lab_broker.REBOOT_LABEL
                    and lab_broker.Broker._may_have_launched(e)]
        self.assertEqual(len(services), 10)
        self.assertEqual(sorted(i.get('transition_kind', 'MANAGED') for i in services),
                         sorted(['CONFIRMATION'] * 6 + ['NEGATIVE_ACTIVATION'] * 2 + ['MANAGED'] * 2))
        # M0's first verification wait: a round one millisecond short of it abandons nothing, and
        # the first ABANDON entry is the round exactly at it, in the first confirmation's boot.
        m0 = d.ticket_state(TICKETS['m0-b0'])
        abandons = [e for e in m0['ledger'] if e[0] == 'ABANDON']
        self.assertEqual(len(abandons), 2)
        [short, exact] = w.thresholds
        self.assertEqual((abandons[0][1], abandons[0][3]), (d.boots[4]['boot'], exact['at']))
        self.assertEqual(exact['at'] - exact['completed'], 600_000)
        self.assertEqual(short['at'] - short['completed'], 599_999)
        clocks = [g.content['reading'] for g in w.entries('group') if g.content.get('reader') == 'clock'
                  and g.content.get('purpose') == 'clock' and g.content.get('status') == 'facts']
        self.assertIn((d.boots[4]['boot'], short['at']), [(r['boot'], r['elapsed']) for r in clocks])
        # Every scheduled fault acted once, in its own cell.
        self.assertEqual(sorted(d.acted), sorted(c['cell'] for c in d.broker.cells))
        self.assertTrue(all(d.acted[f['cell']]['cell'] == cell['cell'] for cell in next_cells.SEQUENCE
                            for f in next_cells.faults(cell, d.world)))
        # The final reads: one whole group of the checked boot, R's exact copy active, and the whole
        # global inventory holds the campaign's terminal history and no live session of its own.
        final = results['final']
        self.assertEqual((final['active'], final['cohort'], final['live_owned']), ('R', 'ORIGINAL', 0))
        readers = [d.broker.ledger.entries[n - 1].content['reader'] for n in final['groups']]
        self.assertEqual(readers, list(lab_driver.FINAL_READS))
        listing = d.broker.ledger.entries[final['groups'][5] - 1].content['reading']
        self.assertTrue(listing['whole'])
        self.assertTrue(any(r['referrer'] == 'andrix-ticket:' + d.ticket_state(TICKETS['a'])['reference'][5]
                            and r['applied'] for r in listing['sessions']))
        # The entry: both helpers pushed with their readback, the identity baseline with the factory
        # copy active, and both helpers read back in every later boot before anything relied on it.
        pushes = [e.content for e in w.entries('lab-action') if e.content.get('record') == 'END'
                  and e.content['type'] == 'HELPER_PUSH']
        self.assertEqual([(p['status'], p['settled']) for p in pushes], [('OK', True)] * 2)
        self.assertEqual((d.cache[0]['kind'], d.cache[0]['status']), ('identity', 'facts'))
        checks = [e.number for e in w.entries('capture') if (e.content.get('intent') or {}).get('purpose') == 'helper-check']
        firsts = [b['first_entry'] for b in d.boots] + [len(d.broker.ledger.entries) + 1]
        for at, b in enumerate(d.boots):
            self.assertGreaterEqual(len([n for n in checks if firsts[at] < n < firsts[at + 1]]), 2, b)
        # The APPLIED boundary: at least two whole baselines of the system user before the round
        # that opened each window.
        checkpoints = {e.number: e.content for e in w.entries('checkpoint')}
        for cell in ('a', 'r'):
            boundary = [json.loads(p.read_text()) for p in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())
                        if p.name.endswith('-applied-boundary.json')]
            entry = [n for n, c in checkpoints.items() if c['ticket'] == TICKETS[cell]
                     and c['milestone'] == 'HEALTH_WINDOW_ENTRY']
            mine = [b for b in boundary if b['facts']['ticket'] == TICKETS[cell]]
            self.assertEqual(len(entry), 1)
            self.assertTrue(mine)
            groups = mine[-1]['facts']['baselines']['0/0']
            self.assertGreaterEqual(len(groups), 2)
            self.assertTrue(all(g < entry[0] for g in groups))
        # R: the repair of A from A's current baseline in the newest checked boot, signing nothing.
        r = lab_records.decode_plan(store_record(w, 'plans', PLANS['R']))
        a = lab_records.decode_plan(store_record(w, 'plans', PLANS['A']))
        self.assertEqual((r['repairs'], r['signing'], r['selectionRevision'], r['restorationInput']),
                         (PLANS['A'], 0, 1, '00' * 32))
        self.assertEqual((r['bundleInput'], r['bundleVersion'], r['signer']),
                         (a['restorationInput'], a['restorationVersion'], a['signer']))
        self.assertEqual((r['baseApk'], r['baseVersion'], r['baseUid'], r['baseContext']),
                         (w.bundle_apk, 40, sim_android.UID, sim_android.CONTEXT))
        self.assertEqual((r['fingerprint'], r['factoryApk']), (a['fingerprint'], a['factoryApk']))
        self.assertEqual(d.current['boot'], d.boots[9]['boot'])
        self.assertEqual(sorted(g['effect'] for g in d.grants(PLANS['R'])), ['ACTIVATE', 'STAGE'])
        repair = d.ticket_state(TICKETS['r'])
        self.assertNotIn('SIGN', [e[0] for e in repair['ledger']])
        self.assertEqual(results['r']['signs'], 0)
        self.assertEqual(d.staged[PLANS['R']]['base.apk']['sha256'], w.restoration_apk)
        self.assertEqual(w.sim.active, ('DATA_COPY', w.restoration_apk, 41))
        selection = d.selection()
        self.assertEqual((selection['choice'], selection['plan'], selection['revision'], selection['realization']),
                         ('PLAN', PLANS['R'], 2, 'CURRENT'))
        # A's selection move halted between its two writes and moved the choice once.
        point = [e.content for e in w.entries('fault') if e.content.get('on') == 'point']
        self.assertEqual([(p['cell'], p['ticket']) for p in point], [('a-selection', TICKETS['a'])])
        # The store was snapshotted after every generation, each snapshot whole with its manifest.
        snapshots = sorted((d.dir / 'store-snapshots').iterdir())
        self.assertEqual(len(snapshots), d.snapshots)
        self.assertTrue(all((s / 'manifest.json').exists() for s in snapshots))
        for path in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir()):
            self.assertEqual(lab_evidence.parse(path.read_bytes())['schema'], lab_driver.CURRENT_SCHEMA)

    def test_the_nominal_matrix_with_n1_and_owed_notices_runs_to_its_predicted_ends(self):
        # The nominal world: N1's payload admitted, and a running full secondary user from F0 on,
        # created at F0 and started again before R, world events standing in for the user setup.
        w = self.world(notice=True, n1=True)
        d = w.driver
        users = []
        decide, repair = d.decide_f0, d.run_repair

        def decide_f0(capabilities, reason):
            users.append(w.start_secondary())
            return decide(capabilities, reason)

        def run_repair(cell, ticket):
            users.append(w.start_secondary())
            return repair(cell, ticket)
        d.decide_f0, d.run_repair = decide_f0, run_repair
        results = w.run()
        self.assertEqual({k: v['status'] for k, v in results.items()},
                         dict({c['cell']: 'PASSED' for c in next_cells.SEQUENCE}, f0='DECIDED'))
        self.assertEqual(d.world, {'notice': True, 'f0': 'FULL'})
        self.assertEqual(results['n1']['calls'], next_cells.calls(install=1))
        # Every notice fault acted, each issue's recipient was captured and qualified, and the
        # ledgers hold the cells' notices before their creates.
        self.assertEqual(sorted(d.acted), sorted(c['cell'] for c in d.broker.cells))
        self.assertTrue({'a-notice', 'r-notice'} <= set(d.acted))
        user, serial = users[0]
        captures = [c['facts'] for c in self.checkpoints(d, 'notice-visibility')]
        self.assertEqual([(c['ticket'], c['user'], c['serial'], c['qualified']) for c in captures],
                         [(TICKETS['a'], user, serial, True), (TICKETS['r'], user, serial, True)])
        for cell in ('a', 'r'):
            self.assertEqual(results[cell]['ledger'], next_cells.by_cell(cell)['prediction']['ledger'])
        self.assertEqual([b['kind'] for b in d.boots], ['INITIAL'] + ['CONFIRMATION'] * 6
                         + ['NEGATIVE_ACTIVATION'] * 2 + ['MANAGED_ACTIVATION'] * 2)
        self.assertTrue(all(b['transition'] for b in d.boots[1:]))
        self.assertEqual((results['final']['active'], results['final']['live_owned']), ('R', 0))

    def test_n1_is_captured_with_its_payload_and_its_refusal_comes_before_n2(self):
        # The honest control: without N1's payload no N1 is admitted, and it stays NOT_CAPTURED.
        names = ('n1', 'n2', 'n3', 'f0')
        bare = self.world(sequence=sequence_of(*names), f0='REFUSED')
        results = bare.run()
        self.assertEqual({k: v['status'] for k, v in results.items()},
                         {'n1': 'NOT_CAPTURED', 'n2': 'PASSED', 'n3': 'PASSED', 'f0': 'DECIDED', 'a': 'NOT_CAPTURED'})
        self.assertEqual(bare.calls('INSTALL'), [])
        # With its payload N1 runs first: one install, refused as a persistent app's, no boot.
        w = self.world(sequence=sequence_of(*names), f0='REFUSED', n1=True)
        results = w.run()
        self.assertEqual({k: v['status'] for k, v in results.items()},
                         {'n1': 'PASSED', 'n2': 'PASSED', 'n3': 'PASSED', 'f0': 'DECIDED', 'a': 'NOT_CAPTURED'})
        self.assertEqual((results['n1']['calls'], results['n1']['new_boots'], results['n1']['cause']),
                         (next_cells.calls(install=1), [], next_cells.CAUSES['N1']))
        self.assertEqual(results['n1']['session']['referrer'],
                         'andrix-lab-control:' + next_cells.action_id('control', 'N1'))
        self.assertEqual([c[0] for c in w.sim.calls if c[0] in ('INSTALL', 'CREATE')],
                         ['INSTALL', 'CREATE', 'CREATE'])
        self.assertEqual([b['kind'] for b in w.driver.boots], ['INITIAL'] + ['NEGATIVE_ACTIVATION'] * 2)
        installs = [e for e in w.entries('lab-action') if e.content.get('type') == 'DIRECT_NONSTAGED']
        stages = [e for e in w.entries('lab-action') if e.content.get('type') == 'DIRECT_STAGE']
        self.assertEqual([e.content['record'] for e in installs], ['BEGIN', 'END'])
        self.assertLess(installs[-1].number, stages[0].number)
        # A guest without the persistent guard installs it: N1 stops the campaign before N2.
        w = self.world(sequence=sequence_of(*names), f0='REFUSED', n1=True)
        w.sim.persistent = False
        with self.assertRaisesRegex(lab_driver.DriverError, 'N1 ended UNEXPECTED'):
            w.run()
        self.assertEqual([c[0] for c in w.sim.calls if c[0] in ('INSTALL', 'CREATE', 'reboot')], ['INSTALL'])
        self.assertNotIn('f0', w.driver.results)

    def test_notices_owed_to_a_running_secondary_user_are_captured_and_received(self):
        w = self.world(sequence=sequence_of('f0', 'a', 'r'), notice=True)
        d = w.driver
        d.entry(w.schedule, w.helpers)
        user, serial = w.start_secondary()
        d.decide_f0(labtest.f0_record('FULL'), 'F0 with a running secondary user')
        a = d.run_managed(w.sequence[1], TICKETS['a'])
        # A's activation boot stopped the secondary user; the setup starts it again before R.
        self.assertFalse(w.sim.forms.running(user))
        w.start_secondary()
        r = d.run_repair(w.sequence[2], TICKETS['r'])
        for result in (a, r):
            self.assertEqual((result['status'], result['end']), ('PASSED', 'CLOSED_APPLIED'))
        self.assertEqual([e[0] for e in d.ticket_state(TICKETS['a'])['ledger']].count('NOTICE'), 2)
        self.assertTrue({'a-notice', 'r-notice'} <= set(d.acted))
        issues = {e.content['ticket']: e.content for e in w.entries('notice-issue')}
        self.assertEqual(sorted(issues), sorted([TICKETS['a'], TICKETS['r']]))
        self.assertTrue(all(i['required'] == [{'user': user, 'serial': serial, 'type': sim_users.SECONDARY_TYPE}]
                            for i in issues.values()))
        # Each issue's recipient was captured once, in the foreground, and qualified.
        captures = [c['facts'] for c in self.checkpoints(d, 'notice-visibility')]
        self.assertEqual([(c['ticket'], c['serial'], c['qualified']) for c in captures],
                         [(TICKETS['a'], serial, True), (TICKETS['r'], serial, True)])
        # Each ticket's receipt read was given exactly its recipient, and its receipt is the
        # visibility's completion; under late commit the create came no sooner than the notice
        # delay after it, and the ledger's order is the cell's: the notices before the create.
        reads = [g.content for g in w.entries('group') if g.content.get('reader') == 'receipts']
        for cell, number in (('a', 0), ('r', 1)):
            ticket = TICKETS[cell]
            mine = [g for g in reads if g['ticket'] == ticket and issues[ticket]['number'] < g['number']]
            self.assertTrue(mine and all(g['recipients'] == [[user, serial]] for g in mine))
            emitted = [row for g in mine for row in g['rows'] if row['judgment'] == 'EMITTED']
            visible = w.driver.broker.ledger.entries[captures[number]['group'] - 1].content
            self.assertEqual({row['proof']['proven_elapsed'] for row in emitted},
                             {visible['brackets']['end']['elapsed']})
            create = [e for e in d.ticket_state(ticket)['ledger'] if e[0] == 'CREATE'][0]
            self.assertGreaterEqual(create[3] - visible['brackets']['end']['elapsed'], 120_000)
            names = [e[0] for e in d.ticket_state(ticket)['ledger']]
            self.assertLess(max(i for i, n in enumerate(names) if n == 'NOTICE'), names.index('CREATE'))
        # R's notice was lost after its delivered effect: no presentation again, one entry.
        presents = [c for c in w.sim.calls if c[0] == 'present']
        self.assertEqual(len(presents), 2)
        self.assertEqual([e[0] for e in d.ticket_state(TICKETS['r'])['ledger']].count('NOTICE'), 1)

    def test_a_wait_the_cell_does_not_predict_stops_the_driver(self):
        for label, waits in (('no confirmation', []), ('one for another wait', ['ABANDON_INTENT'])):
            def unpredicted(c, waits=waits):
                if c['cell'] == 'h2-c0':
                    c['confirmations'] = list(waits)
                    c['prediction']['confirmations'] = len(waits)
            with self.subTest(label):
                w = self.world(sequence=sequence_of('h2-c0', change=unpredicted))
                w.driver.entry(w.schedule, w.helpers)
                with self.assertRaisesRegex(lab_driver.DriverError, 'an unpredicted wait in SESSION_INTENT'):
                    w.driver.run_managed(w.sequence[0], TICKETS['h2-c0'])
                self.assertEqual(w.calls('reboot'), [])
                self.assertEqual([e for e in w.entries('lab-action') if e.content.get('type') == 'PLAIN_KERNEL_CONFIRM'],
                                 [])

    def test_a_confirmation_whose_renewed_reads_are_not_whole_stops_the_driver(self):
        w = self.world(sequence=sequence_of('h2-c0'))
        w.driver.entry(w.schedule, w.helpers)
        reboot = w.sim.reboot

        def lost_users():
            reboot()
            w.sim.scripts['sim:users'] = ['before']
        w.sim.reboot = lost_users
        with self.assertRaisesRegex(lab_driver.DriverError, 'did not renew every read'):
            w.driver.run_managed(w.sequence[0], TICKETS['h2-c0'])
        transition = [t for t in w.driver.broker.transitions.values() if t['begin']['transition_kind'] == 'CONFIRMATION']
        self.assertEqual([t['end']['status'] for t in transition], ['OK'])
        self.assertFalse([e for e in w.entries('generation') if e.number > transition[0]['end']['number']])

    def test_the_window_opens_only_after_two_whole_baselines_of_each_user(self):
        def plain(c):
            if c['cell'] == 'a':
                c['faults'] = []
        w = self.world(sequence=sequence_of('f0', 'a', change=plain))
        d = w.driver
        d.entry(w.schedule, w.helpers)
        d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
        d.cell = 'a'
        d.check()
        d.broker.gate_positive(PLANS['A'], 1, 'the positive attempt')
        d.plan(PLANS['A'], TICKETS['a'], 4)
        state = d.drive(w.sequence[1], TICKETS['a'], PLANS['A'])
        self.assertEqual(state['state'], 'CLOSED_APPLIED')
        [boundary] = [json.loads(p.read_text()) for p in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())
                      if p.name.endswith('-applied-boundary.json')]
        groups = boundary['facts']['baselines']['0/0']
        self.assertEqual(len(groups), 2)
        [entry] = [e.number for e in w.entries('checkpoint') if e.content['milestone'] == 'HEALTH_WINDOW_ENTRY']
        self.assertTrue(all(g < entry for g in groups))
        whole = d.whole_baselines(boundary['facts']['boot'], boundary['facts']['instance'], 0, 0)
        self.assertEqual([e['group'] for e in whole], groups)
        self.assertTrue(all(e['complete'] for e in whole))

    def test_an_unexpected_boot_stops_the_driver(self):
        w = self.world(sequence=sequence_of('h1'))
        w.driver.entry(w.schedule, w.helpers)
        w.sim.reboot()
        with self.assertRaisesRegex(lab_driver.DriverError, 'boot 1 is unexpected'):
            w.driver.check()
        self.assertEqual([b['kind'] for b in w.driver.boots], ['INITIAL', 'UNEXPECTED'])

    def test_a_managed_reboot_lost_before_its_service_never_explains_a_later_boot(self):
        # The real coordinator stores REBOOT_INTENT with its REBOOT entry, and the broker is lost
        # right after the managed BEGIN, before any service intent. The reopening reaps the lost
        # generation, and the model's kernel then boots on its own: that boot is unexpected, while
        # the coordinator's observation of it and the ticket's count stay recorded. The twin is
        # lost inside the service's capture, which may have launched: the boot is then managed.
        no_service = 'a new boot that no reboot service of this transition may have launched'
        for cut in ('after BEGIN', 'inside the service'):
            with self.subTest(cut):
                w = self.world(sequence=sequence_of('f0', 'a', change=quiet))
                d = w.driver
                d.entry(w.schedule, w.helpers)
                d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
                d.cell = 'a'
                d.check()
                d.broker.gate_positive(PLANS['A'], 1, 'the positive attempt')
                d.plan(PLANS['A'], TICKETS['a'], 4)
                record, children, popen = d.broker.ledger.record, [], subprocess.Popen

                def child(*args, **kwargs):
                    process = popen(*args, **kwargs)
                    children.append(process)
                    return process

                def lose(kind, value):
                    number = record(kind, value)
                    if kind == 'boot-transition' and value['record'] == 'BEGIN' \
                            and value['transition_kind'] == 'MANAGED_ACTIVATION':
                        raise KeyboardInterrupt('the broker is lost after its durable BEGIN')
                    return number

                def lost(command):
                    if command == lab_broker.REBOOT_LABEL:
                        raise KeyboardInterrupt('the broker is lost while the reboot is sent')
                if cut == 'after BEGIN':
                    d.broker.ledger.record = lose
                else:
                    w.sim.hooks.append(lost)
                with unittest.mock.patch.object(subprocess, 'Popen', child), self.assertRaises(KeyboardInterrupt):
                    d.drive(w.sequence[1], TICKETS['a'], PLANS['A'], generations=40)
                before = d.ticket_state(TICKETS['a'])
                self.assertEqual((before['state'], [e[0] for e in before['ledger']][-1]), ('REBOOT_INTENT', 'REBOOT'))
                w.sim.hooks.clear()
                d.broker.close()
                w.open()
                for process in children:
                    process.wait(timeout=10)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
                w.sim.reboot()
                if cut == 'after BEGIN':
                    with self.assertRaisesRegex(lab_driver.DriverError, 'is unexpected'):
                        d.advance('round', TICKETS['a'])
                else:
                    d.advance('round', TICKETS['a'])
                [transition] = [t for t in d.broker.transitions.values()
                                if t['begin']['transition_kind'] == 'MANAGED_ACTIVATION']
                services = [e for e in w.entries('capture')
                            if (e.content.get('intent') or {}).get('command') == lab_broker.REBOOT_LABEL]
                after = d.ticket_state(TICKETS['a'])
                end = transition['end']
                self.assertEqual(([e.state for e in services], len(w.calls('reboot')), transition['progress']),
                                 ([] if cut == 'after BEGIN' else ['interrupted'], 0, []))
                self.assertEqual((end['status'], end['new_boots'], end['reason']),
                                 ('UNEXPECTED', [w.sim.boot], no_service) if cut == 'after BEGIN'
                                 else ('OK', [w.sim.boot], None))
                self.assertEqual((d.boots[-1]['boot'], d.boots[-1]['kind']),
                                 (w.sim.boot, 'UNEXPECTED' if cut == 'after BEGIN' else 'MANAGED_ACTIVATION'))
                self.assertEqual((d.generations[-1]['status'], after['state'], after['bootCount']),
                                 ('COMPLETE', 'BOOT_OBSERVED', 1))

    def test_a_helper_that_reads_back_other_bytes_after_a_boot_stops_the_driver(self):
        w = self.world(sequence=sequence_of('h2-c0'))
        w.driver.entry(w.schedule, w.helpers)
        reboot = w.sim.reboot

        def changed():
            reboot()
            w.sim.ui_helper = 'ee' * 32
        w.sim.reboot = changed
        with self.assertRaisesRegex(lab_driver.DriverError, 'ui-state helper reads back'):
            w.driver.run_managed(w.sequence[0], TICKETS['h2-c0'])
        transition = [t for t in w.driver.broker.transitions.values() if t['begin']['transition_kind'] == 'CONFIRMATION']
        self.assertEqual([t['end']['status'] for t in transition], ['OK'])
        self.assertEqual(w.driver.boots[-1]['kind'], 'CONFIRMATION')
        # No generation began after the confirmation's new boot failed its helper gate.
        self.assertFalse([e for e in w.entries('generation') if e.number > transition[0]['end']['number']])

    def test_without_two_whole_baselines_the_window_never_opens(self):
        def plain(c):
            if c['cell'] == 'a':
                c['faults'] = []
        w = self.world(sequence=sequence_of('f0', 'a', change=plain))
        d = w.driver
        d.entry(w.schedule, w.helpers)
        d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
        boundary = d.applied_boundary

        def lost(ticket, plan):
            w.sim.forms.processes.pop(0, None)
            return boundary(ticket, plan)
        d.applied_boundary = lost
        with self.assertRaisesRegex(lab_driver.DriverError, 'user 0 has 0 whole health baselines'):
            d.run_managed(w.sequence[1], TICKETS['a'])
        self.assertEqual(d.ticket_state(TICKETS['a'])['state'], 'APPLIED')
        # The identity was read at the entry and again before the positive attempt's gate.
        identities = [e for e in d.cache if e['kind'] == 'identity']
        gate = [e.number for e in w.entries('qualification') if e.content.get('record') == 'GATE']
        self.assertEqual([e['status'] for e in identities], ['facts', 'facts'])
        self.assertLess(identities[1]['group'], gate[0])
        taken = [e for e in d.cache if e['kind'] == 'health']
        self.assertEqual(len(taken), lab_driver.BASELINE_ATTEMPTS)
        self.assertFalse(any(e['complete'] for e in taken))
        self.assertEqual([e for e in w.entries('checkpoint') if e.content['milestone'] == 'HEALTH_WINDOW_ENTRY'], [])

    def test_the_repair_never_starts_while_a_is_open(self):
        w = self.world(sequence=sequence_of('f0', 'a', 'r'))
        d = w.driver
        d.entry(w.schedule, w.helpers)
        d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
        d.check()
        d.broker.gate_positive(PLANS['A'], 1, 'the positive attempt')
        d.plan(PLANS['A'], TICKETS['a'], 4)
        with self.assertRaisesRegex(lab_driver.DriverError, 'R needs A closed applied'):
            d.run_repair(w.sequence[2], TICKETS['r'])
        d.check()
        with self.assertRaisesRegex(lab_driver.DriverError, 'repair-plan failed'):
            d.run('repair-plan', str(d.config), PLANS['R'], PLANS['A'], d.t0, str(d.clock()))
        self.assertFalse((w.store / 'plans' / (PLANS['R'] + '.rec')).exists())

    def test_a_positive_attempt_before_f0_is_never_created(self):
        w = self.world(sequence=sequence_of('f0', 'a'))
        d = w.driver
        d.entry(w.schedule, w.helpers)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'F0'):
            d.run_managed(w.sequence[1], TICKETS['a'])
        self.assertFalse((w.store / 'plans' / (PLANS['A'] + '.rec')).exists())
        gates = [e.content for e in w.entries('qualification') if e.content.get('record') == 'GATE']
        self.assertEqual([(g['plan'], g['attempt'], g['allowed']) for g in gates], [(PLANS['A'], 1, False)])

    def test_the_verification_wait_abandons_only_from_its_threshold(self):
        w = self.world(sequence=sequence_of('m0-b0'), verification={0: 599_999, 1: 600_001})
        w.driver.entry(w.schedule, w.helpers)
        result = w.driver.run_managed(w.sequence[0], TICKETS['m0-b0'])
        self.assertEqual((result['status'], result['boots'], result['confirmations']), ('PASSED', 3, 3))
        abandons = [e for e in w.driver.ticket_state(TICKETS['m0-b0'])['ledger'] if e[0] == 'ABANDON']
        [short, late] = w.thresholds
        self.assertEqual((late['at'] - late['completed'], abandons[0][3]), (600_001, late['at']))
        self.assertEqual(short['at'] - short['completed'], 599_999)

    def test_a_scheduled_fault_that_never_acts_stops_the_driver(self):
        def unreached(c):
            if c['cell'] == 'h1':
                c['faults'].append(next_cells.fault('h1-unreached', 'cross', 'CREATE', 1, 'drop-reply'))
        w = self.world(sequence=sequence_of('h1', change=unreached))
        w.driver.entry(w.schedule, w.helpers)
        with self.assertRaisesRegex(lab_driver.DriverError, 'differs from its prediction.*h1-unreached'):
            w.driver.run_managed(w.sequence[0], TICKETS['h1'])
        self.assertNotIn('h1-unreached', w.driver.acted)

    def test_the_final_reads_join_every_live_session_against_the_campaign(self):
        w = self.world(sequence=sequence_of('f0', 'a', 'r', 'final', change=quiet))
        d, a, r = self.applied_history(w)
        self.assertEqual((a['state'], r['end']), ('CLOSED_APPLIED', 'CLOSED_APPLIED'))
        found = d.final()
        self.assertEqual((found['active'], found['cohort'], found['live_owned']), ('R', 'ORIGINAL', 0))
        groups = d.results['final']['groups']
        readers = [d.broker.ledger.entries[n - 1].content['reader'] for n in groups]
        self.assertEqual(readers, list(lab_driver.FINAL_READS))
        listing = d.broker.ledger.entries[groups[5] - 1].content['reading']
        nonces = [d.ticket_state(TICKETS[c])['reference'][5] for c in ('a', 'r')]
        self.assertEqual(sorted(row['referrer'] for row in listing['sessions'] if row['applied']),
                         sorted('andrix-ticket:' + n for n in nonces))
        # The review's case: a live session under R's own nonce beside that terminal history.
        identity = max(w.sim.sessions) + 100
        w.sim.sessions[identity] = sim_android.Session(identity, w.sim.wall(), nonces[1], state='OPEN',
                                                       instance=w.sim.instance)
        with self.assertRaisesRegex(lab_driver.DriverError, 'the final reads differ.*"live_owned": 1'):
            d.final()
        self.assertEqual(json.loads(sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())[-1].read_text())['label'],
                         'cell-differs')
        # Once that session is terminal it is history, which may stay.
        w.sim.sessions[identity].state = 'ABANDONED'
        self.assertEqual(d.final()['live_owned'], 0)
        # A live session of the component whose owner the join cannot tell leaves Final UNKNOWN.
        w.sim.foreign_sessions.append(dict(listing['sessions'][0], section='ACTIVE', id=identity + 1, referrer=None,
                                           sealed=False, committed=False, applied=False))
        with self.assertRaisesRegex(lab_driver.DriverError, 'UNKNOWN.*owner the join cannot tell'):
            d.final()
        self.assertEqual(d.results['final']['status'], 'UNKNOWN')
        w.sim.foreign_sessions.clear()
        # So does a global session inventory that is not whole.
        w.sim.global_whole = False
        with self.assertRaisesRegex(lab_driver.DriverError, 'UNKNOWN.*not whole'):
            d.final()
        w.sim.global_whole = True
        # R's exact identity: its bytes at another versionCode are not R's copy.
        kind, apk, version = w.sim.active
        w.sim.active = (kind, apk, version + 1)
        with self.assertRaisesRegex(lab_driver.DriverError, 'the final reads differ.*"active": \\{'):
            d.final()
        w.sim.active = (kind, apk, version)
        self.assertEqual(d.final()['active'], 'R')

    def test_final_reports_other_packages_live_sessions_without_failing(self):
        w = self.world(sequence=sequence_of('f0', 'a', 'r', 'final', change=quiet))
        d, a, r = self.applied_history(w)
        self.assertEqual((a['state'], r['end']), ('CLOSED_APPLIED', 'CLOSED_APPLIED'))
        found = d.final()
        self.assertEqual((found['live_owned'], d.results['final']['other_live']), (0, []))
        group = d.results['final']['other_live_group']
        listing = d.broker.ledger.entries[group - 1].content
        self.assertEqual(listing['reader'], 'global-sessions')
        # Live sessions of another package: one ready, one in an unknown state, both reported whole
        # and classified, beside the campaign's terminal history. Final still passes.
        ready = dict(listing['reading']['sessions'][0], section='ACTIVE', id=9001, package='org.example.app',
                     referrer='adb:installer', sealed=True, committed=True, ready=True, applied=False, failed=False,
                     destroyed=False, created=1_791_504_000_000, installer=10123, cause=None)
        unknown = dict(ready, id=9002, referrer=None, committed=None, ready=None)
        w.sim.foreign_sessions.extend([ready, unknown])
        found = d.final()
        self.assertEqual((found['live_owned'], d.results['final']['status']), (0, 'PASSED'))
        report = d.results['final']['other_live']
        self.assertEqual(report, [{'classification': 'READY', 'session': ready},
                                  {'classification': 'UNKNOWN', 'session': unknown}])
        self.assertEqual(self.checkpoints(d, 'final')[-1]['facts']['other_live'], report)
        group = d.results['final']['other_live_group']
        self.assertEqual([r['id'] for r in d.broker.ledger.entries[group - 1].content['reading']['sessions']][-2:],
                         [9001, 9002])
        # Ownership is unchanged: the same live session of the component is one whose owner the
        # join cannot tell, and Final is UNKNOWN.
        w.sim.foreign_sessions[:] = [dict(ready, package='com.android.systemui')]
        with self.assertRaisesRegex(lab_driver.DriverError, 'UNKNOWN.*owner the join cannot tell'):
            d.final()

    def test_a_commit_still_verifying_is_read_again_without_a_confirmation(self):
        for label, rounds in (('ready at once', 0), ('still verifying', 2)):
            with self.subTest(label):
                w = self.world(sequence=sequence_of('f0', 'a', change=only_commit))
                waits = self.verifying(w, rounds) if rounds else []
                d, a, _ = self.applied_history(w, repair=False)
                self.assertEqual(a['state'], 'CLOSED_APPLIED')
                self.assertEqual(len(w.calls('COMMIT')), 1)
                self.assertEqual(waits, [TICKETS['a']] * rounds)
                self.assertEqual(self.confirmations(w), [])
                self.assertEqual(w.calls('reboot'), [('reboot', w.driver.boots[0]['boot'])])
                self.assertIn('a-commit', d.acted)
                # The wait is recorded resolved within its budget, every round's samples kept.
                ends = [c['facts'] for c in self.checkpoints(d, 'ordinary-wait')]
                if rounds:
                    self.assertEqual([(e['outcome'], e['state'], e['end_state'], len(e['samples'])) for e in ends],
                                     [('resolved', 'COMMIT_INTENT', 'READY', rounds + 1)])
                    self.assertTrue(all(s['guest'] is not None for s in ends[0]['samples']))
                else:
                    self.assertEqual(ends, [])

    def checkpoints(self, d, label):
        return [json.loads(p.read_text()) for p in sorted((d.dir / lab_driver.RUN_CHECKPOINTS).iterdir())
                if json.loads(p.read_text())['label'] == label]

    def test_an_ordinary_wait_stops_at_its_own_budget_on_the_host_clock(self):
        for label, guest in (('the guest clock moving', True), ('the guest clock still', False)):
            with self.subTest(label):
                w = self.world(sequence=sequence_of('f0', 'a', change=only_commit), wait_ms=100_000)
                waits = self.verifying(w, rounds=1000)
                if not guest:
                    def still(driver, state):
                        if state['state'] != 'COMMIT_INTENT':
                            return w.between(driver, state)
                        waits.append(state['ticket'])
                        w.pass_time(driver, 40_000, guest=False)
                    w.driver.between_hook = still
                d = w.driver
                d.entry(w.schedule, w.helpers)
                d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
                d.cell = 'a'
                d.check()
                d.broker.gate_positive(PLANS['A'], 1, 'the positive attempt')
                d.plan(PLANS['A'], TICKETS['a'], 4)
                with self.assertRaisesRegex(lab_driver.DriverError, 'the COMMIT_INTENT wait did not resolve within '
                                            'its admitted budget of 100000 ms; the ticket stays unresolved'):
                    d.drive(w.sequence[1], TICKETS['a'], PLANS['A'], generations=40)
                # The budget is the admission's, not the plan's verification wait, which stays.
                self.assertEqual((d.broker.admission['wait_policy'], d.plan_record(PLANS['A'])['verificationWait']),
                                 ({'ordinary_wait_ms': 100_000}, 600_000))
                [opened] = [c['facts'] for c in self.checkpoints(d, 'ordinary-wait-open')]
                [end] = [c['facts'] for c in self.checkpoints(d, 'ordinary-wait')]
                self.assertEqual((end['outcome'], end['state'], end['budget_ms']), ('unresolved', 'COMMIT_INTENT', 100_000))
                self.assertEqual((opened['since_ns'], opened['deadline_ns']), (end['since_ns'], end['deadline_ns']))
                self.assertEqual(end['deadline_ns'] - end['since_ns'], 100_000 * 1_000_000)
                # Each pause is cut to what is left, and the wait ends exactly at its host deadline.
                self.assertEqual(w.steps, [40_000, 40_000, 20_000])
                self.assertEqual(end['ended_ns'], end['deadline_ns'])
                # The guest's own clock is kept beside the host's for every waiting round.
                samples = end['samples']
                self.assertEqual([s['host_ns'] - end['since_ns'] for s in samples], [0, 40_000_000_000, 80_000_000_000])
                elapsed = [s['guest']['elapsed'] for s in samples]
                self.assertEqual(elapsed, [elapsed[0] + 40_000 * i for i in range(3)] if guest else [elapsed[0]] * 3)
                # Every read of a waiting round was cut to the deadline, and none began past it.
                waiting = {s['generation'] for s in samples[1:]}
                generations = [e.content for e in w.entries('generation') if e.content['generation'] in waiting]
                self.assertEqual([g.get('read_deadline_ns') for g in generations], [end['deadline_ns']] * 2)
                reads = [e.content['intent'] for e in w.entries('capture')
                         if e.content['intent'].get('generation') in waiting and e.content['intent']['operation'] == 'read']
                self.assertTrue(reads)
                for intent in reads:
                    self.assertEqual(intent['not_after_monotonic_ns'], end['deadline_ns'])
                    self.assertLessEqual(intent['timeout_s'] * 1e9, end['deadline_ns'] - intent['started_monotonic_ns'])
                self.assertTrue(all(e.content['intent']['started_monotonic_ns'] < end['deadline_ns']
                                    for e in w.entries('capture')))
                # Unresolved: the ticket as it was; one COMMIT, no reboot or confirmation, no cause.
                ticket = d.ticket_state(TICKETS['a'])
                self.assertEqual((ticket['state'], ticket['cause']), ('COMMIT_INTENT', 'NONE'))
                self.assertEqual((len(w.calls('COMMIT')), w.calls('reboot'), self.confirmations(w)), (1, [], []))
                self.assertEqual(len(waits), 3)

    def test_delayed_validation_and_lost_reads_in_a_and_r_are_read_again(self):
        w = self.world(sequence=sequence_of('f0', 'a', 'r'))
        waits = self.verifying(w, rounds=4, lost=2)
        d = w.driver
        d.entry(w.schedule, w.helpers)
        d.decide_f0(labtest.f0_record('FULL'), 'F0 for the positive attempt')
        a = d.run_managed(w.sequence[1], TICKETS['a'])
        r = d.run_repair(w.sequence[2], TICKETS['r'])
        for result in (a, r):
            self.assertEqual((result['status'], result['end'], result['confirmations']), ('PASSED', 'CLOSED_APPLIED', 0))
        self.assertEqual((waits.count(TICKETS['a']), waits.count(TICKETS['r'])), (4, 4))
        self.assertEqual((len(w.calls('COMMIT')), self.confirmations(w)), (2, []))
        lost = [e.content for e in w.entries('group') if e.content.get('reader') == 'sessions'
                and e.content.get('status') != 'facts']
        self.assertEqual(len(lost), 4)
        # One ordinary wait of each commit's intent: two rounds whose session read was lost, then
        # two that read the session still verifying, resolved by the round that read it ready.
        ends = [c['facts'] for c in self.checkpoints(d, 'ordinary-wait')]
        self.assertEqual([(e['ticket'], e['outcome'], e['state'], e['end_state']) for e in ends],
                         [(TICKETS[c], 'resolved', 'COMMIT_INTENT', 'READY') for c in ('a', 'r')])
        for end in ends:
            self.assertEqual([s['unchanged'] for s in end['samples']], [True, True, True, True, False])
            read = []
            for sample in end['samples'][:4]:
                [group] = [g for g in d._groups(sample['generation']) if g['reader'] == 'sessions']
                read.append(group['status'] if group['status'] != 'facts' else
                            'VERIFYING' in [o['classification'] for o in group['observations']])
            self.assertEqual(read, ['unavailable', 'unavailable', True, True])

    def test_one_declaration_runs_whichever_branch_f0_decides(self):
        w = self.world(sequence=sequence_of('f0', 'a'), limited=True, f0='LIMITED')
        results = w.run()
        self.assertEqual((results['f0']['status'], results['f0']['branch'], results['f0']['qualified']),
                         ('DECIDED', 'LIMITED', True))
        self.assertEqual((results['a']['status'], results['a']['end']), ('PASSED', 'CLOSED_APPLIED'))
        self.assertEqual({h[2] for h in w.driver.ticket_state(TICKETS['a'])['health']}, {'INCONCLUSIVE'})
        refused = self.world(sequence=sequence_of('f0', 'a', 'r', 'final'), limited=True, f0='REFUSED')
        results = refused.run()
        self.assertEqual({k: v['status'] for k, v in results.items()},
                         {'f0': 'DECIDED', 'a': 'NOT_CAPTURED', 'r': 'NOT_CAPTURED', 'final': 'NOT_CAPTURED'})
        self.assertEqual((results['f0']['branch'], results['f0']['qualified']), ('REFUSED', False))
        self.assertFalse((refused.store / 'plans' / (PLANS['A'] + '.rec')).exists())
        self.assertEqual([e for e in refused.entries('qualification') if e.content.get('record') == 'GATE'], [])


if __name__ == '__main__':
    unittest.main()
