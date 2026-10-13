# SPDX-License-Identifier: Apache-2.0
"""End to end with the real host: the lab driver's setup from the guest's own baseline, the accepted
coordinator through the bridge, the real host signer over apksig, the artifact store and the bundle
builder, against the real broker on a simulated guest.

It needs a JDK, the driver's classes compiled with the pinned apksigner jar, the public development
platform key and the two built SystemUI signing inputs, named by ANDRIX_LAB_JAVA,
ANDRIX_LAB_DRIVER_CLASSPATH, ANDRIX_LAB_PLATFORM_KEYS (a directory with platform.pk8 and
platform.x509.pem) and ANDRIX_LAB_SIGNING_INPUTS (a directory with built-A.apk and built-R.apk).
Without them the end to end cases are skipped; the cell sequence's form checks run without them.
Host evidence only: a simulated guest, not Android."""
import base64
import hashlib
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

import cells
import labtest
import lab_broker
import lab_driver
import sim_android

JAVA = os.environ.get('ANDRIX_LAB_JAVA')
CLASSPATH = os.environ.get('ANDRIX_LAB_DRIVER_CLASSPATH')
KEYS = os.environ.get('ANDRIX_LAB_PLATFORM_KEYS')
INPUTS = os.environ.get('ANDRIX_LAB_SIGNING_INPUTS')
PLAN, TICKET = '0d' * 16, '0e' * 16
OTHER_PLAN, OTHER_TICKET = '0a' * 16, '0b' * 16
TERMINAL = ('CLOSED_APPLIED', 'CLOSED_FAILED', 'CANCELLED', 'VOID', 'DIVERGED', 'SUPERSEDED')


def der(data, offset):
    """(tag, header length, content length) of the DER element at offset."""
    tag, first = data[offset], data[offset + 1]
    if first < 0x80:
        return tag, 2, first
    count = first & 0x7f
    return tag, 2 + count, int.from_bytes(data[offset + 2:offset + 2 + count], 'big')


def children(data, offset):
    """The offsets of a constructed element's children."""
    _, header, length = der(data, offset)
    position, end, found = offset + header, offset + header + length, []
    while position < end:
        found.append(position)
        _, h, n = der(data, position)
        position += h + n
    return found


def role_of(pem):
    """The certificate's own identity, computed here independently of the Java side: the SHA-256 of
    its DER encoding and of its SubjectPublicKeyInfo."""
    body = b''.join(line for line in pem.splitlines() if line and not line.startswith(b'-----'))
    cert = base64.b64decode(body)
    tbs = children(cert, 0)[0]
    fields = children(cert, tbs)
    if der(cert, fields[0])[0] == 0xa0:  # The explicit version.
        fields = fields[1:]
    spki = fields[5]
    _, header, length = der(cert, spki)
    return hashlib.sha256(cert).hexdigest(), hashlib.sha256(cert[spki:spki + header + length]).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class World:
    """A lab driver over a broker on a simulated guest, with the real host."""

    def __init__(self, cells=(), sdk=(37, 65535), plans=(PLAN,), lab_actions=False):
        self._temp = tempfile.TemporaryDirectory()
        self.dir = Path(self._temp.name)
        self.store = self.dir / 'store'
        self.sim = sim_android.SimAndroid()
        keys, inputs = Path(KEYS), Path(INPUTS)
        certificate, key = role_of((keys / 'platform.x509.pem').read_bytes())
        lines = ['andrix-lab-host 1', 'signer %s' % (self.dir / 'signer'), 'artifacts %s' % (self.dir / 'artifacts'),
                 'work %s' % (self.dir / 'work'), 'key %s %s' % (keys / 'platform.pk8', sha(keys / 'platform.pk8')),
                 'certificate %s %s' % (keys / 'platform.x509.pem', sha(keys / 'platform.x509.pem')),
                 'role %s %s' % (certificate, key), 'sdk %d %d' % sdk,
                 'variant %s %s' % (inputs / 'built-A.apk', sha(inputs / 'built-A.apk')),
                 'restoration %s %s' % (inputs / 'built-R.apk', sha(inputs / 'built-R.apk'))]
        host = self.dir / 'host.config'
        host.write_text('\n'.join(lines + ['plans %s' % ','.join(plans)]) + '\n')
        # A second configuration admitting one more plan, for the approval case.
        self.wider = self.dir / 'host-wider.config'
        self.wider.write_text('\n'.join(lines + ['plans %s' % ','.join(plans + (OTHER_PLAN,))]) + '\n')
        self.driver = lab_driver.LabDriver(self.dir, JAVA, CLASSPATH, host, sha(host),
                                           clock=lambda: sim_android.WALL_BASE + self.sim.uptime)
        manifest = labtest.manifest_bytes()
        config = self.driver.init(self.store, hashlib.sha256(manifest).hexdigest(), labtest.INSTALLATION,
                                  labtest.COORDINATOR, labtest.TRUST)
        # A guest's admission: the restart action with its limit, the launch set the loss cells need
        # (no COMMIT, no reboot) and this store, whose records each crossing names. Its settle wait
        # sleeps on a host test clock, not in real time.
        changes, timing = {}, {}
        if lab_actions:
            changes = {'version': 2, 'lab_actions': {'framework-restart': 10}, 'launches': ['CREATE', 'WRITE', 'ABANDON'],
                       'store': str(self.store)}
            clock = labtest.Clock()
            timing = {'monotonic': clock.monotonic_ns, 'sleep': clock.sleep}
        lab_broker.Broker.initialize(self.dir / 'broker', labtest.admission(self.dir, config=config, **changes), manifest)
        self.driver.broker = lab_broker.Broker.open(self.dir / 'broker', labtest.REPO, sim_android.SimTransport(self.sim),
                                                    sim_android.SimReader(labtest.INSTALLATION), sync=False, **timing)
        if cells:
            self.driver.broker.admit_faults(list(cells))

    def close(self):
        self.driver.broker.close()
        self._temp.cleanup()

    def staged(self, members):
        # The simulated guest installs an APK it knows by digest; the real one reads the APK itself.
        self.sim.apks[members['base.apk']['sha256']] = 38

    def calls(self, kind):
        return [c for c in self.sim.calls if c[0] == kind]


class CellSequenceTests(unittest.TestCase):
    """The cell sequence's data, without the JDK."""

    def test_the_sequence_is_well_formed(self):
        self.assertTrue(cells.check_sequence())
        self.assertEqual([spec['attempt'] for spec in cells.SEQUENCE], list(range(1, len(cells.SEQUENCE) + 1)))

    def test_malformed_attempts_are_refused(self):
        base = cells.SEQUENCE[1]
        changes = {
            'a missing key': lambda s: s.pop('restarts'),
            'an unknown crossing': lambda s: s['faults'][0].update(crossing='LAUNCH'),
            'a fault named twice': lambda s: s['faults'].append(dict(s['faults'][0])),
            'a restart outside the waits a later instance resolves': lambda s: s['restarts'].append('READY'),
            'a native call missing from the prediction': lambda s: s['calls'].pop('reboot'),
            'an unknown grant': lambda s: s.update(grants=['STAGE']),
            'an unknown fault mode': lambda s: s['faults'][0].update(mode='loss-during'),
            'a host occurrence beyond two': lambda s: s['faults'][0].update(occurrence=3),
            'a host fault on a device crossing': lambda s: s['faults'][0].update(crossing='CREATE'),
            'a loss between members outside WRITE': lambda s: s['faults'][3].update(mode='loss-between-members'),
            'an end that is not terminal': lambda s: s.update(end='READY'),
            'a native count that is not a count': lambda s: s['calls'].update(CREATE='1'),
        }
        for label, change in changes.items():
            spec = copy.deepcopy(base)
            change(spec)
            with self.subTest(change=label), self.assertRaises(ValueError):
                cells.check_spec(spec)
        first = copy.deepcopy(cells.SEQUENCE[0])
        first['grants'] = ['SIGN']
        with self.assertRaises(ValueError):
            cells.check_spec(first)

    def test_the_sequence_refuses_reordered_or_reused_cells(self):
        with self.assertRaises(ValueError):
            cells.check_sequence((cells.SEQUENCE[1], cells.SEQUENCE[0]))
        reused = copy.deepcopy(cells.SEQUENCE[:2])
        reused[1]['faults'][0]['cell'] = reused[0]['faults'][0]['cell']
        with self.assertRaises(ValueError):
            cells.check_sequence(reused)


class Entry:
    def __init__(self, kind, content):
        self.kind, self.content = kind, content


class RestartDecisionTests(unittest.TestCase):
    """Which unchanged waits the driver asks a restart for, from one generation's recorded reads."""

    def decide(self, checkpoint='COMMITTED', listing='SESSIONS_FOR_PACKAGE', session='SEALED', instance=4001,
               unavailable=()):
        def group(reader, observations, reading=None):
            status = 'unavailable' if reader in unavailable else 'facts'
            return Entry('group', {'generation': 7, 'reader': reader, 'status': status, 'reading': reading,
                                   'observations': observations if status == 'facts' else []})
        entries = [group('clock', [], {'boot': 'b1' * 16, 'instance': 4001}),
                   group('checkpoint', [{'kind': 'CHECKPOINT', 'classification': checkpoint, 'instance': -1}]),
                   group('sessions', [{'kind': 'LISTING', 'classification': listing, 'instance': instance}]
                         + ([{'kind': 'SESSION', 'classification': session, 'instance': instance}] if session else []))]
        driver = lab_driver.LabDriver.__new__(lab_driver.LabDriver)
        driver.broker = type('Broker', (), {'ledger': type('Ledger', (), {'entries': entries})()})()
        return driver.restart_resolves(7)

    def test_a_loss_wait_beside_an_uncommitted_session_is_one_a_later_instance_resolves(self):
        for session in ('OPEN', 'SEALED', 'ABANDONED', None):
            with self.subTest(session=session):
                self.assertTrue(self.decide(session=session, listing='NONE_FOR_PACKAGE' if session is None else 'SESSIONS_FOR_PACKAGE'))

    def test_a_committed_session_or_unknown_commitment_is_another_wait(self):
        for session in ('VERIFYING', 'READY', 'LIVE_NOT_READY'):
            with self.subTest(session=session):
                self.assertFalse(self.decide(session=session))

    def test_a_pending_checkpoint_is_another_wait(self):
        self.assertFalse(self.decide(checkpoint='PENDING'))

    def test_unavailable_or_partial_reads_ask_no_restart(self):
        for case in ({'unavailable': ('clock',)}, {'unavailable': ('checkpoint',)}, {'unavailable': ('sessions',)},
                     {'listing': 'INCOMPLETE'}, {'instance': 3901}):
            with self.subTest(case=case):
                self.assertFalse(self.decide(**case))


@unittest.skipUnless(JAVA and CLASSPATH and KEYS and INPUTS, 'needs the JDK, the driver classpath, the keys and inputs')
class DriverEndToEnd(unittest.TestCase):
    def world(self, cells=(), **options):
        world = World(cells, **options)
        self.addCleanup(world.close)
        return world

    def test_a_plan_is_refused_before_the_baseline_check(self):
        w = self.world()
        with self.assertRaisesRegex(lab_driver.DriverError, 'right after a complete baseline check'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_the_plan_is_the_guests_own_baseline_and_the_inputs_own_facts(self):
        w = self.world()
        w.driver.check()
        made = w.driver.plan(PLAN, TICKET, 4)
        self.assertEqual((made['fingerprint'], made['base'], made['version'], made['uid'], made['context']),
                         (sim_android.FINGERPRINT, sim_android.FACTORY_APK, str(sim_android.FACTORY_VERSION),
                          str(sim_android.UID), sim_android.CONTEXT))
        self.assertTrue(made['variant'].endswith('/38') and made['restoration'].endswith('/39'))
        with self.assertRaisesRegex(lab_driver.DriverError, 'already exists'):
            w.driver.plan(PLAN, '0f' * 16, 4)

    def test_a_configured_sdk_range_other_than_the_inputs_declared_range_is_refused(self):
        # The bridge makes the host when a generation opens, so even the check refuses to run.
        w = self.world(sdk=(37, 37))
        summary = w.driver.generation('check')
        self.assertEqual(summary['status'], 'FAILED')
        stderr = (w.dir / 'broker' / 'jvm' / ('%06d.stderr' % summary['generation'])).read_text()
        self.assertIn('is not an input\'s declared range 37-65535', stderr)
        with self.assertRaisesRegex(lab_driver.DriverError, 'right after a complete baseline check'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_a_host_configuration_other_than_its_admitted_digest_refuses_every_generation(self):
        w = self.world()
        w.driver.host = (w.driver.host[0], '0' * 64)
        summary = w.driver.generation('check')
        self.assertEqual(summary['status'], 'FAILED')
        stderr = (w.dir / 'broker' / 'jvm' / ('%06d.stderr' % summary['generation'])).read_text()
        self.assertIn('the host configuration differs from its admitted digest', stderr)

    def test_a_plan_is_refused_when_a_data_copy_is_active_at_the_baseline(self):
        w = self.world()
        w.sim.active = ('DATA_COPY', 'aa' * 32, 40)
        w.driver.check()
        with self.assertRaisesRegex(lab_driver.DriverError, 'not found current at revision 0|a data copy is active'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_a_plan_the_host_configuration_does_not_name_is_refused(self):
        w = self.world()
        w.driver.check()
        with self.assertRaisesRegex(lab_driver.DriverError, 'does not admit this plan'):
            w.driver.plan('0c' * 16, TICKET, 4)

    def test_a_ticket_closes_applied_with_the_real_signer_and_publication(self):
        w = self.world()
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        # The plan's health window is the design's 15 minutes: two simulated minutes pass per generation.
        state = w.driver.drive(TICKET, PLAN, lambda s: s['state'] in TERMINAL, generations=20,
                               between=lambda s: w.sim.tick(120_000), staged=w.staged)
        self.assertEqual(state['state'], 'CLOSED_APPLIED')
        self.assertEqual(state['ledger'], 'SIGN,PUBLISH,CREATE,WRITE,COMMIT,REBOOT')
        self.assertEqual((state['choice'], state['plan'], state['revision'], state['realization']),
                         ('PLAN', PLAN, '1', 'CURRENT'))
        members = w.driver.staged[PLAN]
        self.assertEqual(w.sim.active, ('DATA_COPY', members['base.apk']['sha256'], 38))
        self.assertEqual((len(w.calls('CREATE')), len(w.calls('WRITE')), len(w.calls('COMMIT')), len(w.calls('reboot'))),
                         (1, 2, 1, 1))
        self.assertEqual({g['status'] for g in w.driver.generations}, {'COMPLETE'})
        # The pushed variant is the signer's own retained output of one transaction, signed without v1. Its
        # bytes may equal the input's: the built input already carries this key's deterministic v2 and v3
        # signatures, so signing again without v1 can reproduce them; its v4 sidecar is new either way.
        transactions = list((w.dir / 'signer' / 'outputs').iterdir())
        self.assertEqual(len(transactions), 1)
        retained = transactions[0] / 'variant'
        self.assertEqual((sha(retained / 'base.apk'), sha(retained / 'base.apk.idsig')),
                         (members['base.apk']['sha256'], members['base.apk.idsig']['sha256']))
        self.assertTrue((transactions[0] / 'restoration' / 'base.apk').exists())
        with zipfile.ZipFile(members['base.apk']['host']) as z:
            self.assertFalse([n for n in z.namelist() if n.startswith('META-INF/') and n.endswith(('.SF', '.RSA', '.DSA', '.EC'))])

    def test_a_host_configuration_the_bridge_configuration_does_not_bind_is_refused(self):
        # Both the host configuration and its matching digest replaced: the admitted bridge
        # configuration names the original digest, so planning and every generation refuse.
        w = self.world()
        w.driver.check()
        w.driver.host = (str(w.wider), sha(w.wider))
        with self.assertRaisesRegex(lab_driver.DriverError, 'not the one the bridge configuration binds'):
            w.driver.plan(OTHER_PLAN, OTHER_TICKET, 4)
        summary = w.driver.generation('check')
        self.assertEqual(summary['status'], 'FAILED')
        stderr = (w.dir / 'broker' / 'jvm' / ('%06d.stderr' % summary['generation'])).read_text()
        self.assertIn('not the one the bridge configuration binds', stderr)

    def test_a_store_with_facts_of_another_boot_gives_no_plan_whatever_the_wall_times(self):
        # Boot 1 checked late in its uptime, then boot 2, with other factory bytes, checked earlier on
        # the wall clock. The selection records boot 2 as checked and T0 is boot 2, but the store also
        # holds boot 1's facts, and nothing orders boots, so no plan is made from it.
        w = self.world()
        w.sim.tick(600_000)
        w.driver.check()
        w.sim.new_boot()
        w.sim.factory = ('ed' * 32, 37)
        w.sim.active = ('FACTORY_COPY', w.sim.factory[0], 37)
        w.driver.check()
        self.assertEqual(w.driver.t0, w.driver.selection()['checked'])
        with self.assertRaisesRegex(lab_driver.DriverError, 'facts of another boot'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_a_plan_binds_only_a_complete_check_that_is_the_last_generation(self):
        w = self.world()
        w.driver.check()
        good = w.driver.host
        w.driver.host = (good[0], '0' * 64)
        with self.assertRaisesRegex(lab_driver.DriverError, 'the baseline check ended FAILED'):
            w.driver.check()
        w.driver.host = good
        with self.assertRaisesRegex(lab_driver.DriverError, 'right after a complete baseline check'):
            w.driver.plan(PLAN, TICKET, 4)
        w.driver.check()
        self.assertEqual(w.driver.plan(PLAN, TICKET, 4)['boot'], w.sim.boot)

    def test_a_check_that_read_nothing_establishes_no_t0(self):
        # A complete check in boot 1, then boot 2 with other factory bytes and its clock read lost: the
        # coordinator keeps the stored selection and the generation still completes, but its own reads
        # establish no boot, so there is no T0 and no plan from boot 1's facts.
        w = self.world()
        w.driver.check()
        w.sim.new_boot()
        w.sim.factory = ('ed' * 32, 37)
        w.sim.active = ('FACTORY_COPY', w.sim.factory[0], 37)
        w.sim.scripts['sim:clock'] = ['before']
        with self.assertRaisesRegex(lab_driver.DriverError, 'did not read one current boot'):
            w.driver.check()
        self.assertEqual(w.driver.generations[-1]['status'], 'COMPLETE')
        self.assertIsNone(w.driver.t0)
        with self.assertRaisesRegex(lab_driver.DriverError, 'right after a complete baseline check'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_an_empty_baseline_read_establishes_no_t0(self):
        # After a complete check, each of the four baseline reads in turn returns no fact although
        # its capture ran (the checkpoint meanwhile PENDING): the generation completes, but the read
        # carried nothing, so no T0, and the plan cannot bind the earlier facts. An ordinary repeated
        # check then establishes T0 again.
        w = self.world()
        w.driver.check()
        w.sim.tick(1000)
        w.sim.checkpoint = 'PENDING'
        reader = w.driver.broker.reader
        for name in ('boot', 'checkpoint', 'factory', 'active'):
            real = getattr(reader, name)

            def empty(real=real):
                real()
                return []
            setattr(reader, name, empty)
            with self.assertRaisesRegex(lab_driver.DriverError, 'did not read one current boot'):
                w.driver.check()
            self.assertEqual(w.driver.generations[-1]['status'], 'COMPLETE')
            setattr(reader, name, real)
            with self.assertRaisesRegex(lab_driver.DriverError, 'right after a complete baseline check'):
                w.driver.plan(PLAN, TICKET, 4)
        w.sim.checkpoint = 'COMMITTED'
        w.driver.check()
        with self.assertRaisesRegex(lab_driver.DriverError, 'pending checkpoint'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_an_ordinary_repeated_check_establishes_t0(self):
        # The repeated check reads the same facts, which the store keeps once: T0 rests on the
        # ledger's record of this generation's reads, not on newly stored observations.
        w = self.world()
        w.driver.check()
        observations = w.store / 'observations'
        before = sorted(p.name for p in observations.iterdir())
        w.sim.tick(1000)
        w.driver.check()
        self.assertEqual(sorted(p.name for p in observations.iterdir()), before)
        self.assertEqual(w.driver.plan(PLAN, TICKET, 4)['boot'], w.sim.boot)

    def test_a_bridge_configuration_the_admission_does_not_bind_is_refused_before_any_record(self):
        # The bridge configuration and the host configuration it names replaced together: the admitted
        # digest comes from the broker's admission, so planning refuses before writing anything.
        w = self.world()
        w.driver.check()
        original, good = w.driver.config, w.driver.host
        text = original.read_text().replace('host %s' % good[1], 'host %s' % sha(w.wider))
        other = w.dir / 'bridge-other.config'
        other.write_text(text)
        w.driver.config, w.driver.host = other, (str(w.wider), sha(w.wider))
        with self.assertRaisesRegex(lab_driver.DriverError, 'not the one the admission binds'):
            w.driver.plan(OTHER_PLAN, OTHER_TICKET, 4)
        w.driver.config, w.driver.host = original, good
        with self.assertRaisesRegex(lab_driver.DriverError, 'cannot be read'):
            w.driver.inspect(OTHER_TICKET)

    def test_a_data_copy_with_the_factory_bytes_is_refused_at_the_baseline(self):
        # A data copy equal in bytes to the factory copy keeps the cohort check current, so only the
        # baseline's own data copy check refuses it.
        w = self.world()
        w.driver.check()
        w.sim.active = ('DATA_COPY', w.sim.factory[0], w.sim.factory[1])
        w.driver.check()
        with self.assertRaisesRegex(lab_driver.DriverError, 'a data copy is active at the baseline'):
            w.driver.plan(PLAN, TICKET, 4)

    def test_a_failed_publication_export_stops_before_any_session(self):
        w = self.world()
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        real = w.driver.run

        def failing(*args, **kwargs):
            if args[0] == 'published':
                raise lab_driver.DriverError('published failed: an injected export failure')
            return real(*args, **kwargs)
        w.driver.run = failing
        with self.assertRaisesRegex(lab_driver.DriverError, 'injected export failure'):
            w.driver.drive(TICKET, PLAN, lambda s: s['state'] in TERMINAL, between=lambda s: w.sim.tick(40_000))
        state = w.driver.inspect(TICKET)
        self.assertEqual(state['ledger'], 'SIGN,PUBLISH')
        self.assertEqual((w.driver.broker.pinned, w.calls('CREATE'), w.calls('WRITE')), ({}, [], []))

    def test_a_publication_lost_before_its_effect_waits_then_stages_the_republication(self):
        cell = {'cell': 'lose-publish', 'on': 'host', 'mode': 'loss-before', 'plan': PLAN, 'attempt': 1, 'crossing': 'PUBLISH',
                'occurrence': 1}
        w = self.world([cell])
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        state = w.driver.drive(TICKET, PLAN, lambda s: 'CREATE' in s['ledger'].split(','), between=lambda s: w.sim.tick(40_000),
                               staged=w.staged)
        self.assertIn(PLAN, w.driver.staged)
        self.assertEqual(state['ledger'].split(',').count('PUBLISH'), 2)
        self.assertEqual([g['status'] for g in w.driver.generations].count('DELIBERATE_HALT'), 1)
        self.assertGreaterEqual(len(list((w.dir / 'published' / PLAN).iterdir())), 2)

    def test_a_failed_generation_stops_the_driver(self):
        # A generation given a host digest that is not its configuration's fails at once; the driver
        # stops there rather than polling on.
        w = self.world()
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        w.driver.host = (w.driver.host[0], '0' * 64)
        with self.assertRaisesRegex(lab_driver.DriverError, 'ended FAILED'):
            w.driver.drive(TICKET, PLAN, lambda s: s['state'] in TERMINAL, generations=3, between=lambda s: w.sim.tick(40_000))
        self.assertEqual(len(w.driver.generations), 2)

    def test_the_loss_cells_run_in_order_to_their_predicted_ends(self):
        # The design's cohort refusal first, then its loss cells as one sequence of attempts on plan
        # A, each compared with its prediction from the store and the broker's ledger; the factory
        # choice stays current throughout.
        w = self.world(lab_actions=True, plans=(PLAN, OTHER_PLAN))
        w.driver.check()
        w.driver.run_cohort_refusal(OTHER_PLAN, OTHER_TICKET)
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        tickets = [TICKET] + [('%02x' % (0x30 + i)) * 16 for i in range(1, len(cells.SEQUENCE))]
        for spec, ticket in zip(cells.SEQUENCE, tickets):
            with self.subTest(attempt=spec['name']):
                w.driver.run_attempt(spec, PLAN, ticket, between=lambda s: w.sim.tick(40_000), staged=w.staged)
        selection = w.driver.selection()
        self.assertEqual((selection['choice'], selection['revision'], selection['realization']), ('FACTORY', '0', 'CURRENT'))
        self.assertEqual(w.sim.active[0], 'FACTORY_COPY')
        # Every crossing kept the exact ticket, plan and selection records it named, by digest.
        crossings = [e.content for e in w.driver.broker.ledger.entries if e.kind == 'crossing']
        self.assertTrue(crossings)
        for crossing in crossings:
            records = crossing['records']
            self.assertEqual((records['ticket'], records['plan']), (crossing['ticket_digest'], crossing['plan_digest']))
            for digest in records.values():
                data = (w.dir / 'broker' / 'records' / digest).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        self.assertEqual([c for c in w.sim.calls if c[0] in ('COMMIT', 'reboot')], [])

    def test_an_attempt_begins_only_after_the_previous_ticket_is_terminal(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        # The plan's first ticket is PLANNED: no second attempt yet, and attempt 1 is only that ticket.
        with self.assertRaisesRegex(lab_driver.DriverError, 'previous ticket is terminal'):
            w.driver.run_attempt(cells.SEQUENCE[1], PLAN, '31' * 16, staged=w.staged)
        with self.assertRaisesRegex(lab_driver.DriverError, "attempt 1 is the plan's first ticket"):
            w.driver.run_attempt(cells.SEQUENCE[0], PLAN, '31' * 16, staged=w.staged)
        # Nothing was admitted for the refused attempts, and the store holds only the first ticket.
        self.assertEqual([e for e in w.driver.broker.ledger.entries if e.kind == 'faults'], [])
        self.assertEqual(w.driver.tickets(PLAN), [{'ticket': TICKET, 'attempt': 1, 'state': 'PLANNED'}])
        # A moved first ticket is no longer attempt 1's to take.
        w.driver.advance('round', TICKET)
        self.assertNotEqual(w.driver.tickets(PLAN)[0]['state'], 'PLANNED')
        with self.assertRaisesRegex(lab_driver.DriverError, "attempt 1 is the plan's first ticket"):
            w.driver.run_attempt(cells.SEQUENCE[0], PLAN, TICKET, staged=w.staged)

    def test_a_framework_restart_that_does_not_take_stops_the_driver(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        # The command succeeds, but the framework does not restart: no poll shows a later instance,
        # the broker refuses the action after its record, and no generation follows.
        w.sim.scripts['am restart'] = [lambda command: sim_android.result(command, 0)]
        generations = len(w.driver.generations)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            w.driver.restart_framework('a later framework instance that does not come')
        self.assertIsNone(w.driver.t0)
        self.assertEqual(len(w.driver.generations), generations)

    def test_a_restart_without_a_renewed_checkpoint_read_stops_the_driver(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.restart_framework('a later framework instance')
        # The next generation reads the later instance, but its checkpoint read does not complete.
        w.sim.scripts['sim:checkpoint'] = ['before']
        with self.assertRaisesRegex(lab_driver.DriverError, 'checkpoint again'):
            w.driver.check()
        self.assertIsNone(w.driver.t0)

    def test_a_generation_of_another_boot_after_a_settled_restart_stops_the_driver(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.restart_framework('a later framework instance')
        # The restart settled, but the guest boots again before the next generation reads.
        w.sim.reboot()
        with self.assertRaisesRegex(lab_driver.DriverError, 'later instance of the same boot'):
            w.driver.check()

    def test_a_ticket_round_after_a_restart_must_read_the_checkpoint_again(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        w.driver.restart_framework('a later framework instance')
        w.sim.scripts['sim:checkpoint'] = ['before']
        with self.assertRaisesRegex(lab_driver.DriverError, 'checkpoint again'):
            w.driver.advance('round', TICKET)

    def test_the_store_is_kept_after_every_step(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        snapshots = sorted(p.name for p in (w.dir / 'store-snapshots').iterdir())
        self.assertEqual([name.split('-', 1)[1] for name in snapshots], ['init', 'generation-1', 'plan'])
        manifest = json.loads((w.dir / 'store-snapshots' / snapshots[-1] / 'manifest.json').read_text())
        self.assertIn('tickets/%s.rec' % TICKET, manifest)
        ticket = (w.store / 'tickets' / ('%s.rec' % TICKET)).read_bytes()
        self.assertEqual(manifest['tickets/%s.rec' % TICKET], hashlib.sha256(ticket).hexdigest())

    def test_a_fault_that_never_acts_stops_the_driver(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        extra = copy.deepcopy(cells.SEQUENCE[0])
        # H1 never creates a session, so a CREATE cell admitted with it never acts.
        extra['faults'].append(cells.fault('h1-unreached', 'cross', 'CREATE', 1, 'drop-reply'))
        with self.assertRaisesRegex(lab_driver.DriverError, 'differs from its prediction'):
            w.driver.run_attempt(extra, PLAN, TICKET, between=lambda s: w.sim.tick(40_000), staged=w.staged)

    def test_a_prediction_the_records_do_not_meet_stops_the_driver(self):
        w = self.world(lab_actions=True)
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        wrong = copy.deepcopy(cells.SEQUENCE[0])
        wrong['signs'] = 1
        with self.assertRaisesRegex(lab_driver.DriverError, 'differs from its prediction'):
            w.driver.run_attempt(wrong, PLAN, TICKET, between=lambda s: w.sim.tick(40_000), staged=w.staged)

    def test_a_lost_sign_reply_is_resolved_by_reading_never_by_signing_again(self):
        cell = {'cell': 'drop-sign', 'on': 'host', 'mode': 'drop-reply', 'plan': PLAN, 'attempt': 1, 'crossing': 'SIGN',
                'occurrence': 1}
        w = self.world([cell])
        w.driver.check()
        w.driver.plan(PLAN, TICKET, 4)
        state = w.driver.drive(TICKET, PLAN, lambda s: 'PUBLISH' in s['ledger'].split(','), between=lambda s: w.sim.tick(40_000),
                               staged=w.staged)
        self.assertEqual(state['ledger'].split(',').count('SIGN'), 1)
        records = list((w.dir / 'signer' / 'transactions').iterdir())
        self.assertEqual(len(records), 1)


if __name__ == '__main__':
    unittest.main()
