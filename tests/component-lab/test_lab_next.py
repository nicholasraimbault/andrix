# SPDX-License-Identifier: Apache-2.0
"""The broker's next campaign profile on a simulated guest: the version 3 admission and protocol
version 2, notice receipts past the clock guard, full health compositions and typed lab actions.
Each changed copy must fail for its own reason while its honest original passes. Host evidence
only: the simulated guest's forms are test fakes, not Android forms."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import capture_ledger
import labtest
from labtest import GRANT, PLAN, TICKET, Harness, read_observation
import lab_actions
import lab_broker
import lab_evidence
import lab_protocol as proto
import lab_records
import sim_android
from scripts.proof import component_transaction_records as encoder

STATUS = proto.STATUSES
RECEIPT, HEALTH, SIMPLE = proto.MODES['RECEIPT_EVENT'], proto.MODES['COMPOSED_HEALTH'], proto.MODES['SIMPLE_CURRENT']
DIGESTS = {'ticket_digest': hashlib.sha256(b'ticket record').hexdigest(),
           'plan_digest': hashlib.sha256(b'plan record').hexdigest()}


class NextBase(unittest.TestCase):
    def harness(self, generation=True, **options):
        options.setdefault('notice', sim_android.SimNotice())
        options.setdefault('health', sim_android.SimHealth())
        h = Harness(next_profile=True, **options)
        self.addCleanup(h.close)
        self.store(h)
        if generation:
            self.generation(h)
        return h

    def store(self, h, ticket=b'ticket record', plan=b'plan record'):
        root = Path(h.admission['store'])
        for directory, name, data in (('tickets', TICKET, ticket), ('plans', PLAN, plan),
                                      ('selections', sim_android.PACKAGE, b'selection record'),
                                      ('authorizations', GRANT, b'grant record')):
            (root / directory).mkdir(parents=True, exist_ok=True)
            (root / directory / (name + '.rec')).write_bytes(data)

    def generation(self, h):
        self.between(h)
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['OK'])
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])

    def between(self, h):
        """Ends the open generation, so that an action or a baseline may run."""
        if h.broker.open_generation is not None:
            h.end(0)

    def notice(self, h, index=2, **changes):
        return h.cross('NOTICE', index, entry_instance=-1, native=proto.NO_REFERENCE, entry_elapsed=h.sim.uptime,
                       **dict(DIGESTS, **changes))

    def visible(self, h, index=2, user=10, serial=5):
        """The recipient's display shows the notice, and a typed visibility action captures it."""
        self.between(h)
        h.sim.current_user = user
        return h.broker.run_action(labtest.VISIBILITY_ACTION, 'capture the notice', ticket=TICKET, index=index,
                                   serial=serial)

    def envelopes(self, reply, mode):
        return [e for e in reply['envelopes'] if e['mode'] == mode]

    def groups(self, h, reader):
        return [e.content for e in h.entries('group') if e.content.get('reader') == reader]

    def actions(self, h, record=None):
        return [e.content for e in h.entries('lab-action') if record is None or e.content.get('record') == record]


class CodecTests(unittest.TestCase):
    def test_side_records_have_one_canonical_form(self):
        value = {'schema': 'andrix-receipt-read-v1', 'rows': [{'b': 2, 'a': None}], 'ok': True, 'n': -(1 << 63)}
        data = lab_evidence.canonical(value)
        self.assertEqual(data, b'{"n":-9223372036854775808,"ok":true,"rows":[{"a":null,"b":2}],'
                               b'"schema":"andrix-receipt-read-v1"}\n')
        self.assertEqual(lab_evidence.parse(data), value)
        self.assertEqual(lab_evidence.digest(value), hashlib.sha256(data).hexdigest())
        bad = {'a duplicate key': b'{"a":1,"a":1}\n', 'a float': b'{"a":1.5}\n', 'NaN': b'{"a":NaN}\n',
               'an infinity': b'{"a":Infinity}\n', 'spacing': b'{"a": 1}\n', 'key order': b'{"b":1,"a":1}\n',
               'no terminal newline': b'{"a":1}', 'not ASCII': '{"a":"\u00e9"}\n'.encode('utf-8'),
               'an escaped control': b'{"a":"\\n"}\n', 'not an object': b'[1]\n',
               'a big integer': b'{"a":9223372036854775808}\n'}
        for name, data in bad.items():
            with self.subTest(name), self.assertRaises(lab_evidence.SideError):
                lab_evidence.parse(data)
        for value in ({'a': 1.5}, {'a': b'x'}, {1: 'a'}, {'a': 'x' * 4097}, {'a': [[[[[[[[[1]]]]]]]]]}):
            with self.subTest(value=str(value)[:30]), self.assertRaises(lab_evidence.SideError):
                lab_evidence.canonical(value)

    def test_stored_plans_and_tickets_are_read_strictly(self):
        goldens = encoder.goldens()
        plan = lab_records.decode_plan(goldens['PLAN_LATE_ONE'])
        self.assertEqual((plan['plan'], plan['criteria'], plan['healthWindow']), (encoder.ident(0x101), 127, 600_000))
        ticket = lab_records.decode_ticket(goldens['TICKET_WINDOW'])
        self.assertEqual((ticket['state'], ticket['windowBoot'], ticket['windowStart']),
                         ('HEALTH_WINDOW', encoder.ident(0xb0073), 90_000))
        self.assertEqual([e[0] for e in lab_records.decode_ticket(goldens['TICKET_MAXIMUM'])['ledger']][:3],
                         ['SIGN', 'SIGN', 'PUBLISH'])
        data = goldens['TICKET_WINDOW']

        def resealed(body):
            raw = bytearray(data[:12] + body)
            raw[8:12] = (len(raw) + 32).to_bytes(4, 'little')
            return bytes(raw) + hashlib.sha256(bytes(raw)).digest()
        bad = {'a changed byte': data[:40] + bytes([data[40] ^ 1]) + data[41:], 'trailing bytes': resealed(data[12:-32] + b'\0'),
               'cut short': resealed(data[12:-33]), 'another type': goldens['PLAN_LATE_ONE'], 'empty': b''}
        for name, record in bad.items():
            with self.subTest(name), self.assertRaises(lab_records.RecordError):
                lab_records.decode_ticket(record)
        with self.assertRaises(lab_records.RecordError):
            lab_records.decode_plan(goldens['TICKET_WINDOW'])


class AdmissionTests(NextBase):
    def test_a_version_3_admission_is_exact_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            good = labtest.admission3(directory)
            lab_broker.check_admission(good)
            specs = good['lab_actions']

            def spec(at, **changes):
                return [dict(s, **changes) if i == at else s for i, s in enumerate(specs)]
            restart, visibility, preparation = specs
            bad = {
                'a missing key': {k: v for k, v in good.items() if k != 'boot_policy'},
                'an extra key': dict(good, extra=1),
                'another profile': dict(good, profile='d5-next-vehicle-2'),
                'a zero bound manifest': dict(good, cells_sha256='00' * 32),
                "version 2's action map": dict(good, lab_actions={'framework-restart': 1}),
                'no action': dict(good, lab_actions=[]),
                'a spec with an extra key': dict(good, lab_actions=spec(0, extra=1)),
                'an unregistered type': dict(good, lab_actions=spec(0, type='SHELL')),
                'installation authority': dict(good, lab_actions=spec(0, authority='ACTIVATE')),
                "another type's authority": dict(good, lab_actions=spec(0, authority='LAB_USER_ADMIN')),
                'a selector the type does not admit': dict(good, lab_actions=spec(0, user_selector={'kind': 'NOTICE_RECIPIENT'})),
                'a selector naming a user': dict(good, lab_actions=spec(0, user_selector={'kind': 'SYSTEM_USER', 'user': 10})),
                'a created user without a create action': dict(good, lab_actions=spec(2, user_selector={
                    'kind': 'CREATED_BY', 'action': restart['id']})),
                'an unprepared criterion': dict(good, lab_actions=spec(2, parameters={'criteria': [1], 'max_probe_ms': 1})),
                'unsorted criteria': dict(good, lab_actions=spec(2, parameters={'criteria': [5, 2], 'max_probe_ms': 1})),
                'no probe width': dict(good, lab_actions=spec(2, parameters={'criteria': [2], 'max_probe_ms': 0})),
                'a shell text parameter': dict(good, lab_actions=spec(0, parameters={'command': 'reboot'})),
                'a pinned input': dict(good, lab_actions=spec(0, inputs=[{'role': 'apk', 'sha256': 'ab' * 32}])),
                'other preconditions': dict(good, lab_actions=spec(0, preconditions=[])),
                'an unknown predecessor': dict(good, lab_actions=spec(0, predecessor='9a' * 16)),
                'a successor not naming its predecessor': dict(good, lab_actions=spec(0, successors=[visibility['id']])),
                'a predecessor not listing its successor': dict(good, lab_actions=spec(1, predecessor=restart['id'])),
                'no use': dict(good, lab_actions=spec(0, max_uses=0)),
                'too many uses': dict(good, lab_actions=spec(0, max_uses=101)),
                'no timeout': dict(good, lab_actions=spec(0, timeout_ms=0)),
                'a boolean bound': dict(good, lab_actions=spec(0, stdout_max=True)),
                'another runtime': dict(good, lab_actions=spec(1, runtime='e2' * 16)),
                'another installation': dict(good, lab_actions=spec(0, installation='99' * 16)),
                'an unknown phase': dict(good, lab_actions=spec(0, phase='G1A')),
                'an action twice': dict(good, lab_actions=[restart, restart]),
                'an uncapped crossing': dict(good, effect_limits=dict(good['effect_limits'], crossings={'CREATE': 1})),
                'a negative cap': dict(good, effect_limits=dict(good['effect_limits'], admin=-1)),
                'an uncapped phase': dict(good, effect_limits=dict(good['effect_limits'], phases={'A': 1})),
                'a boot that does not halt': dict(good, boot_policy=dict(good['boot_policy'], unexpected_boot='CONTINUE')),
                'no observed boot': dict(good, boot_policy=dict(good['boot_policy'], observed_boots=0)),
                'no FULL branch': dict(good, branches={'LIMITED': None, 'REFUSED': good['branches']['REFUSED']}),
                'a branch of no admitted action': dict(good, branches=dict(good['branches'], FULL={
                    'predicate_sha256': 'd1' * 32, 'actions': ['9a' * 16]})),
                'a branch without its predicate': dict(good, branches=dict(good['branches'], REFUSED={
                    'predicate_sha256': '00' * 32, 'actions': []})),
                'version 2 with the new keys': dict(good, version=2),
                'version 1 with the new keys': dict(good, version=1),
            }
            for name, value in bad.items():
                with self.subTest(name), self.assertRaises(lab_broker.BrokerError):
                    lab_broker.check_admission(value)
            # A predecessor and its successor name each other.
            lab_broker.check_admission(dict(good, lab_actions=[dict(restart, successors=[visibility['id']]),
                                                               dict(visibility, predecessor=restart['id']),
                                                               preparation]))

    def test_version_2s_action_map_is_never_reinterpreted(self):
        h = self.harness(generation=False)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'not an admitted lab action'):
            h.broker.framework_restart('the version 2 restart')
        self.assertEqual(h.sim.calls, [])
        v2 = Harness()
        self.addCleanup(v2.close)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'version 3'):
            v2.broker.run_action(labtest.RESTART_ACTION, 'a typed action under version 1')

    def test_a_version_3_pin_names_its_publication_and_only_it(self):
        h = self.harness(generation=False, pins=False)
        apk = h.directory / 'apk'
        apk.write_bytes(b'A' * 64)
        members = {m: {'host': str(apk), 'sha256': hashlib.sha256(b'A' * 64).hexdigest(), 'bytes': 64}
                   for m in ('base.apk', 'base.apk.idsig')}
        for publication in (None, '00' * 32, 'XY' * 32):
            with self.assertRaises(lab_broker.BrokerError):
                h.broker.pin_artifacts(PLAN, members, publication)
        h.broker.pin_artifacts(PLAN, members, '9f' * 32)
        with self.assertRaises(lab_broker.BrokerError):
            h.broker.pin_artifacts(PLAN, members, '9e' * 32)
        self.assertEqual(h.entries('artifacts')[-1].content['publication'], '9f' * 32)
        v1 = Harness(pins=False)
        self.addCleanup(v1.close)
        with self.assertRaises(lab_broker.BrokerError):
            v1.broker.pin_artifacts(PLAN, members, '9f' * 32)


class ProtocolVersionTests(NextBase):
    def frame(self, h, version):
        return proto.encode(proto.message('HELLO', '%032x' % 1, h.manifest, installation=labtest.INSTALLATION,
                                          coordinator=labtest.COORDINATOR, config=labtest.CONFIG,
                                          component=sim_android.PACKAGE, trust=labtest.TRUST, route=1), version)

    def test_a_broker_speaks_exactly_its_admissions_protocol(self):
        for next_profile, version, accepted in ((True, 2, True), (True, 1, False), (False, 1, True), (False, 2, False)):
            with self.subTest(next_profile=next_profile, version=version):
                h = Harness(next_profile=next_profile)
                self.addCleanup(h.close)
                out = io.BytesIO()
                state = h.broker.serve(io.BytesIO(self.frame(h, version)), out)
                self.assertEqual(state['hello'], accepted)
                if accepted:
                    self.assertEqual(proto.decode(out.getvalue(), version)['status'], STATUS['OK'])
                else:
                    self.assertIn('malformed request', state['violation'])
                    self.assertEqual(out.getvalue(), b'')

    def test_simple_envelopes_carry_the_current_reads_unchanged(self):
        h = self.harness()
        reply = h.observe()
        self.assertEqual((reply['status'], reply['control_record']), (STATUS['OK'], 0))
        simple = self.envelopes(reply, SIMPLE)
        self.assertEqual([read_observation(e['observation'])['kind'] for e in simple], [1, 2, 3, 4, 5, 8])
        for e in simple:
            fact = read_observation(e['observation'])
            group = h.broker.ledger.entries[e['group'] - 1].content
            self.assertEqual((e['evidence'], e['block']), (fact['raw'], {}))
            self.assertEqual(group['raw'], fact['raw'])
            self.assertIn(hashlib.sha256(e['observation']).hexdigest(), [o['sha256'] for o in group['observations']])
        reply = h.observe(scope='COMPONENT')
        self.assertEqual([read_observation(e['observation'])['kind'] for e in reply['envelopes']], [1, 2, 3, 4])

    def test_an_observation_above_its_bounds_is_refused_never_cut(self):
        for profile in (False, True):
            with self.subTest(next_profile=profile):
                h = Harness(next_profile=profile)
                self.addCleanup(h.close)
                h.begin()
                h.hello()
                h.sim.users += [(n, n + 1, 'NOT_RUNNING') for n in range(10, 270)]
                reply = h.observe()
                if profile:
                    self.assertEqual(reply['status'], STATUS['REFUSED'])
                    self.assertIn('none is cut', reply['reason'])
                else:
                    # Version 1, kept for its admitted vehicle, still cuts to its bound.
                    self.assertEqual(len(reply['frames']), proto.MAX_FRAMES)


class ReceiptTests(NextBase):
    def delivered(self, h):
        """A notice issued and presented to user 10, and its visibility captured 200 ms later."""
        h.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        self.assertEqual(self.notice(h)['status'], STATUS['OK'])
        h.sim.tick(200)
        end = self.visible(h)
        self.assertTrue(end['outcome']['qualified'], end)
        return self.groups(h, 'notice-visibility')[-1]

    def test_a_delivery_read_after_a_later_clock_keeps_its_event_time(self):
        # Version 1 cannot carry it: the event is older than the round's clock.
        old = Harness(notice=sim_android.SimNotice(), reader={'receipts': True})
        self.addCleanup(old.close)
        old.begin()
        old.hello()
        old.sim.receipts.append({'user': 10, 'serial': 5, 'ticket': TICKET, 'index': 2, 'route': 'FULL_SCREEN'})
        old.sim.tick(500)
        old.clock_read()
        reply = old.observe()
        self.assertNotIn(12, [read_observation(f)['kind'] for _, f in reply['frames']])
        self.assertEqual(old.entries('group')[-1].content['reason'], 'the uptime or framework instance went back')
        # Version 2 carries it with its proven event time, the visibility's completion.
        h = self.harness()
        visible = self.delivered(h)
        h.sim.tick(40_000)
        self.generation(h)
        reply = h.observe()
        receipts = self.envelopes(reply, RECEIPT)
        self.assertEqual(len(receipts), 1)
        e = receipts[0]
        fact = read_observation(e['observation'])
        proven = visible['brackets']['end']['elapsed']
        self.assertEqual((fact['kind'], fact['classification'], fact['user'], fact['serial']), (12, 2, 10, 5))
        self.assertEqual((fact['elapsed'], e['block']['proven_elapsed'], e['block']['delivery_end']), (proven,) * 3)
        self.assertEqual(e['block']['read_end_elapsed'], h.sim.uptime)
        self.assertLess(fact['elapsed'], e['block']['read_begin_elapsed'])
        group = self.groups(h, 'receipts')[-1]
        manifest = (h.root / group['compound']['path']).read_bytes()
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), group['compound']['sha256'])
        self.assertEqual((e['evidence'], fact['raw']), (group['compound']['sha256'],) * 2)
        self.assertEqual(lab_evidence.parse(manifest)['schema'], 'andrix-receipt-read-v1')
        self.assertEqual(e['block']['delivery_group'], visible['compound']['sha256'])
        issue = h.entries('notice-issue')[-1].content
        self.assertEqual((e['block']['event'], e['block']['issue_ticket_digest']),
                         (issue['challenge'], DIGESTS['ticket_digest']))

    def test_the_read_bracket_moves_the_clock_scale_and_the_event_never_does(self):
        h = self.harness()
        self.delivered(h)
        h.sim.tick(40_000)
        self.generation(h)
        h.observe()
        group = self.groups(h, 'receipts')[-1]
        self.assertEqual(h.broker.scale[h.sim.boot]['elapsed'], group['brackets']['end']['elapsed'])
        # An ordinary current fact still never goes back, and neither does any reopened scale.
        reading = self.groups(h, 'checkpoint')[-1]
        h.sim.uptime = reading['observations'][0]['elapsed'] - 1
        self.assertEqual(h.clock_read()['status'], STATUS['UNAVAILABLE'])
        h.end(0)
        h.reopen()
        self.assertEqual(h.broker.scale[h.sim.boot]['elapsed'], group['brackets']['end']['elapsed'])

    def test_a_reread_in_a_later_framework_keeps_the_first_proven_time(self):
        h = self.harness()
        visible = self.delivered(h)
        h.sim.tick(1000)
        self.generation(h)
        first = read_observation(self.envelopes(h.observe(), RECEIPT)[0]['observation'])
        h.end(0)
        h.reopen()
        h.sim.framework_restart()
        h.sim.tick(5000)
        self.generation(h)
        e = self.envelopes(h.observe(), RECEIPT)[0]
        again = read_observation(e['observation'])
        self.assertEqual(again['elapsed'], first['elapsed'])
        self.assertEqual(again['elapsed'], visible['brackets']['end']['elapsed'])
        self.assertEqual((again['instance'], e['block']['delivery_instance']), (h.sim.instance, first['instance']))
        self.assertNotEqual(again['observation'], first['observation'])

    def test_a_row_without_a_qualified_visibility_proves_nothing_until_one_completes(self):
        h = self.harness()
        h.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        self.notice(h)
        self.assertEqual([r['user'] for r in h.sim.rows], [10])
        h.sim.tick(1000)
        self.generation(h)
        self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
        self.assertEqual([r['judgment'] for r in self.groups(h, 'receipts')[-1]['rows']], ['NO_VISIBILITY'])
        # The display shows the system user, so the capture does not qualify, and still nothing.
        self.between(h)
        unseen = h.broker.run_action(labtest.VISIBILITY_ACTION, 'capture', ticket=TICKET, index=2, serial=5)
        self.assertEqual((unseen['status'], unseen['outcome']['qualified']), ('OK', False))
        self.assertIn('current user', unseen['outcome']['why_not'])
        self.generation(h)
        self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
        # A later qualified capture proves delivery at its own completion, never at the row's.
        h.sim.tick(3000)
        visible = self.visible(h)
        self.generation(h)
        fact = read_observation(self.envelopes(h.observe(), RECEIPT)[0]['observation'])
        group = self.groups(h, 'notice-visibility')[-1]
        self.assertEqual(fact['elapsed'], group['brackets']['end']['elapsed'])
        self.assertGreater(fact['elapsed'], h.sim.rows[0]['candidate_elapsed'] + 3000)
        self.assertTrue(visible['outcome']['qualified'])

    def test_the_first_proof_is_never_moved_by_a_later_visibility(self):
        h = self.harness()
        first = self.delivered(h)
        h.sim.tick(9000)
        self.visible(h)
        self.generation(h)
        fact = read_observation(self.envelopes(h.observe(), RECEIPT)[0]['observation'])
        self.assertEqual(fact['elapsed'], first['brackets']['end']['elapsed'])
        self.assertEqual(len([g for g in self.groups(h, 'notice-visibility') if g['qualified']]), 2)

    def test_contrary_rows_refuse_the_whole_read(self):
        changes = {
            'another text': {'text_sha256': 'ab' * 32}, 'another event': {'event': 'cd' * 16},
            'another boot token': {'boot': 'ef' * 16}, 'another plan': {'plan': '02' * 16},
            'another installation': {'installation': 'ee' * 16}, 'a notice never issued': {'index': 9},
            'a user the notice was not owed to': {'user': 0, 'serial': 0},
            'a row of no known form': {'uid': 'app'}, 'a row naming a control action too': {'control': 'ab' * 16},
        }
        for name, change in changes.items():
            with self.subTest(name):
                h = self.harness()
                self.delivered(h)
                h.sim.rows[0].update(change)
                self.generation(h)
                reply = h.observe()
                self.assertEqual(self.envelopes(reply, RECEIPT), [])
                group = self.groups(h, 'receipts')[-1]
                self.assertEqual((group['status'], group['emitted'], group['observations']), ('refused', False, []))
                manifest = lab_evidence.parse((h.root / group['compound']['path']).read_bytes())
                self.assertEqual(manifest['status'], 'refused')
        # A row that changes after its first read, and one notice's row twice in a read.
        for name in ('changed bytes', 'a second row'):
            with self.subTest(name):
                h = self.harness()
                self.delivered(h)
                self.generation(h)
                self.assertEqual(len(self.envelopes(h.observe(), RECEIPT)), 1)
                if name == 'changed bytes':
                    h.sim.rows[0]['candidate_elapsed'] += 1
                else:
                    h.sim.rows.append(dict(h.sim.rows[0]))
                self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
                self.assertEqual(self.groups(h, 'receipts')[-1]['status'], 'refused')

    def test_rows_of_another_ticket_purpose_or_boot_are_kept_and_give_nothing(self):
        h = self.harness()
        self.delivered(h)
        row = h.sim.rows[0]
        h.sim.rows += [dict(row, ticket='05' * 16),
                       dict(row, purpose='QUALIFICATION', plan=None, ticket=None, index=None, control='ab' * 16)]
        self.generation(h)
        self.assertEqual(len(self.envelopes(h.observe(), RECEIPT)), 1)
        self.assertEqual([r['judgment'] for r in self.groups(h, 'receipts')[-1]['rows']],
                         ['EMITTED', 'OTHER_TICKET', 'QUALIFICATION'])
        # Another boot inherits nothing from this boot's notice.
        h.end(0)
        h.sim.reboot()
        self.generation(h)
        reply = h.observe()
        self.assertEqual(self.envelopes(reply, RECEIPT), [])
        self.assertEqual(self.groups(h, 'receipts')[-1]['rows'][0]['judgment'], 'OTHER_BOOT')

    def test_a_notice_issue_binds_records_recipients_challenge_and_text_before_any_launch(self):
        h = self.harness()
        h.sim.users.append((10, 5, 'RUNNING_LOCKED'))
        self.assertEqual(self.notice(h)['status'], STATUS['OK'])
        issue = h.entries('notice-issue')[-1]
        presents = [e for e in h.entries('capture') if e.content['intent']['operation'] == 'notice']
        self.assertTrue(presents and all(e.number > issue.number for e in presents))
        self.assertEqual(presents[0].content['intent']['issue'], issue.number)
        c = issue.content
        self.assertEqual(c['required'], [{'user': 10, 'serial': 5, 'type': sim_android.SECONDARY_TYPE}])
        self.assertEqual((c['ticket_sha256'], c['grant_sha256'], c['actor']),
                         (DIGESTS['ticket_digest'], hashlib.sha256(b'grant record').hexdigest(), 'LAB_OPERATOR'))
        self.assertEqual(c['text_sha256'], hashlib.sha256(c['text'].encode()).hexdigest())
        self.assertIn(c['challenge'], c['text'])
        self.assertEqual(h.broker.ledger.entries[c['inventory'] - 1].content['reader'], 'inventory')
        self.notice(h, index=3, occurrence=2)
        self.assertNotEqual(h.entries('notice-issue')[-1].content['challenge'], c['challenge'])
        # Each contrary form launches nothing.
        cases = {'a grant holder': ({'actor': 1}, None), 'an inventory that is not whole': ({}, 'whole'),
                 'a running profile': ({}, 'profile'), 'nobody owed it': ({}, 'alone'),
                 'a user being removed': ({}, 'removing')}
        for name, (changes, world) in cases.items():
            with self.subTest(name):
                h = self.harness()
                h.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
                if world == 'whole':
                    h.sim.inventory_whole = False
                elif world == 'profile':
                    h.sim.user_types[10] = 'android.os.usertype.profile.MANAGED'
                elif world == 'alone':
                    h.sim.users.pop()
                elif world == 'removing':
                    h.sim.user_marks[10] = {'removing': True}
                reply = self.notice(h, **changes)
                self.assertEqual(reply['status'], STATUS['NO_REPLY'], name)
                self.assertIn('nothing launched', reply['reason'])
                self.assertEqual((h.entries('notice-issue'), h.sim.rows), ([], []))
                self.assertNotIn('present', [c[0] for c in h.sim.calls])

    def test_a_reply_lost_after_delivery_is_recovered_by_a_fresh_read(self):
        h = self.harness(cells=[{'cell': 'lose-notice', 'on': 'cross', 'mode': 'loss-after', 'plan': PLAN,
                                 'attempt': 1, 'crossing': 'NOTICE', 'occurrence': 1}])
        h.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        self.assertEqual(self.notice(h)['status'], STATUS['HALT'])
        withheld = h.entries('fault')[-1].content['withheld_sha256']
        h.end(99)
        h.sim.tick(100)
        self.visible(h)
        self.generation(h)
        e = self.envelopes(h.observe(), RECEIPT)[0]
        self.assertNotEqual(hashlib.sha256(e['observation']).hexdigest(), withheld)
        self.assertEqual(read_observation(e['observation'])['elapsed'],
                         self.groups(h, 'notice-visibility')[-1]['brackets']['end']['elapsed'])

    def test_a_manifest_without_its_group_is_an_honest_prefix(self):
        h = self.harness()
        self.delivered(h)
        self.generation(h)
        record = h.broker.ledger.record

        def lost(kind, value):
            if kind == 'group' and value.get('reader') == 'receipts':
                raise KeyboardInterrupt('the broker is lost after the manifest')
            return record(kind, value)
        h.broker.ledger.record = lost
        with self.assertRaises(KeyboardInterrupt):
            h.observe()
        kept = sorted((h.root / 'compound').iterdir())
        h.broker.close()
        h.open()
        self.assertEqual(h.broker.proofs, {})
        self.assertTrue(any(lab_evidence.parse(p.read_bytes())['schema'] == 'andrix-receipt-read-v1' for p in kept))
        self.generation(h)
        self.assertEqual(len(self.envelopes(h.observe(), RECEIPT)), 1)

    def test_a_changed_manifest_or_summary_refuses_the_reopening(self):
        # The honest control: an intact history reopens, and a fresh read proves the first time.
        h = self.harness()
        visibility = self.delivered(h)
        self.generation(h)
        self.assertEqual(len(self.envelopes(h.observe(), RECEIPT)), 1)
        self.between(h)
        h.reopen()
        self.generation(h)
        e = self.envelopes(h.observe(), RECEIPT)[0]
        self.assertEqual(e['block']['delivery_group'], visibility['compound']['sha256'])
        self.assertEqual(read_observation(e['observation'])['elapsed'], visibility['brackets']['end']['elapsed'])
        # The kept visibility manifest gains one space, or is removed, or stays while its group's
        # summary moves the proven time: each refuses the reopening.
        for change in ('one space more', 'removed', 'another proven time'):
            with self.subTest(change):
                h = self.harness()
                visibility = self.delivered(h)
                self.generation(h)
                self.assertEqual(len(self.envelopes(h.observe(), RECEIPT)), 1)
                self.between(h)
                path = h.root / visibility['compound']['path']
                if change == 'one space more':
                    path.write_bytes(path.read_bytes() + b' ')
                elif change == 'removed':
                    path.unlink()
                else:
                    record = h.root / 'ledger' / ('%06d-group' % visibility['number']) / 'record.json'
                    content = json.loads(record.read_bytes())
                    content['brackets']['end']['elapsed'] -= 100
                    record.write_bytes(capture_ledger.encode_json(content))
                with self.assertRaisesRegex(lab_broker.BrokerError, 'compound manifest of group %d is damaged'
                                            % visibility['number']):
                    h.reopen()

    def test_a_refused_read_keeps_the_first_bytes_of_its_rows(self):
        for changed in (False, True):
            with self.subTest(changed=changed):
                h = self.harness()
                visibility = self.delivered(h)
                row = dict(h.sim.rows[0])
                first_bytes = hashlib.sha256(lab_evidence.canonical(row)).hexdigest()
                # Another row names a notice never issued, so the whole read is refused.
                h.sim.rows.append(dict(row, index=9))
                self.generation(h)
                self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
                first = self.groups(h, 'receipts')[-1]
                self.assertEqual((first['status'], first['reason']),
                                 ('refused', 'a row of this ticket names a notice that was never issued'))
                self.assertEqual([r['sha256'] for r in first['rows']][:1], [first_bytes])
                h.sim.rows.pop()
                if changed:
                    h.sim.rows[0]['candidate_elapsed'] += 1
                self.between(h)
                h.reopen()
                self.generation(h)
                receipts = self.envelopes(h.observe(), RECEIPT)
                second = self.groups(h, 'receipts')[-1]
                if changed:
                    self.assertEqual(receipts, [])
                    self.assertEqual((second['status'], second['reason']),
                                     ('refused', 'a row changed after it was first read'))
                    continue
                # The honest control: the unchanged row proves its first delivery.
                self.assertEqual((second['status'], receipts[0]['block']['row']), ('facts', first_bytes))
                self.assertEqual(read_observation(receipts[0]['observation'])['elapsed'],
                                 visibility['brackets']['end']['elapsed'])
        # A whole read whose end clock is lost keeps its rows' first bytes too.
        h = self.harness()
        self.delivered(h)
        self.generation(h)
        h.sim.hooks.append(lambda command: command == 'sim:rows' and h.sim.scripts.update({'sim:clock': ['before']}))
        self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
        h.sim.hooks.clear()
        lost = self.groups(h, 'receipts')[-1]
        self.assertEqual((lost['status'], [r['judgment'] for r in lost['rows']]), ('unavailable', ['UNBRACKETED']))
        h.sim.rows[0]['candidate_elapsed'] += 1
        self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
        self.assertEqual(self.groups(h, 'receipts')[-1]['reason'], 'a row changed after it was first read')
        # So does a read whose manifest has no side record form, after a reopening too.
        h = self.harness()
        self.delivered(h)
        self.generation(h)
        rows = h.broker.reader.receipt_rows
        h.broker.reader.receipt_rows = lambda ticket: [dict(rows(ticket)[0], uid=1 << 64, row=b'an app UID out of bounds')]
        self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
        h.broker.reader.receipt_rows = rows
        unkept = self.groups(h, 'receipts')[-1]
        self.assertEqual((unkept['status'], unkept['compound'], unkept['rows'][0]['judgment']),
                         ('unavailable', None, 'EMITTED'))
        for reopened in (False, True):
            if reopened:
                self.between(h)
                h.reopen()
                self.generation(h)
            self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
            self.assertEqual(self.groups(h, 'receipts')[-1]['reason'], 'a row changed after it was first read')

    def test_a_contrary_first_row_never_hides_a_later_rows_first_bytes(self):
        firsts = {'a notice never issued': ({'index': 9}, 'a row of this ticket names a notice that was never issued'),
                  'a row of no known form': ({'uid': 'app'}, 'a provider row of no known form')}
        for name, (change, reason) in firsts.items():
            for changed in (False, True):
                with self.subTest(name, changed=changed):
                    h = self.harness()
                    visibility = self.delivered(h)
                    row = dict(h.sim.rows[0])
                    first_bytes = hashlib.sha256(lab_evidence.canonical(row)).hexdigest()
                    # The contrary row comes first and the delivered row after it.
                    h.sim.rows.insert(0, dict(row, **change))
                    self.generation(h)
                    self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
                    first = self.groups(h, 'receipts')[-1]
                    self.assertEqual(first['status'], 'refused')
                    self.assertTrue(first['reason'].startswith(reason), first['reason'])
                    h.sim.rows.pop(0)
                    if changed:
                        h.sim.rows[0]['candidate_elapsed'] += 1
                    self.between(h)
                    h.reopen()
                    self.generation(h)
                    receipts = self.envelopes(h.observe(), RECEIPT)
                    second = self.groups(h, 'receipts')[-1]
                    if changed:
                        self.assertEqual(receipts, [])
                        self.assertEqual((second['status'], second['reason']),
                                         ('refused', 'a row changed after it was first read'))
                    else:
                        # The honest control: the unchanged row proves its first delivery.
                        self.assertEqual((second['status'], receipts[0]['block']['row']), ('facts', first_bytes))
                        self.assertEqual(read_observation(receipts[0]['observation'])['elapsed'],
                                         visibility['brackets']['end']['elapsed'])
                    # The refused read kept the delivered row's first bytes, past its contrary row.
                    self.assertEqual([r['sha256'] for r in first['rows'] if r['key']], [first_bytes])

    def test_an_erased_emission_refuses_the_reopening_and_the_scale_never_falls(self):
        for erased in (False, True):
            with self.subTest(erased=erased):
                h = self.harness()
                self.delivered(h)
                self.generation(h)
                # The provider read ends a second after every other fact of the round.
                h.sim.hooks.append(lambda command: command == 'sim:rows' and h.sim.tick(1000))
                self.assertEqual(len(self.envelopes(h.observe(), RECEIPT)), 1)
                h.sim.hooks.clear()
                group = self.groups(h, 'receipts')[-1]
                end = group['brackets']['end']['elapsed']
                others = [item['elapsed'] for g in (e.content for e in h.entries('group'))
                          if g['emitted'] and g['number'] != group['number']
                          for item in g['observations'] + [g.get('reading') or {'elapsed': 0}]]
                self.assertLess(max(others), end - 500)
                self.assertEqual(h.broker.scale[h.sim.boot]['elapsed'], end)
                self.between(h)
                if erased:
                    # Only the group's emission summary is erased; its manifest and captures stay.
                    record = h.root / 'ledger' / ('%06d-group' % group['number']) / 'record.json'
                    content = json.loads(record.read_bytes())
                    content.update(emitted=False, observations=[])
                    record.write_bytes(capture_ledger.encode_json(content))
                    with self.assertRaisesRegex(lab_broker.BrokerError, 'compound manifest of group %d is damaged'
                                                % group['number']):
                        h.reopen()
                    continue
                # The honest control: the reopened scale keeps the read's end, and a clock half a
                # second before it is refused as going back.
                h.reopen()
                self.assertEqual(h.broker.scale[h.sim.boot]['elapsed'], end)
                h.begin()
                self.assertEqual(h.hello()['status'], STATUS['OK'])
                h.sim.uptime = end - 500
                self.assertEqual(h.clock_read()['status'], STATUS['UNAVAILABLE'])

    def test_a_compound_group_without_its_manifest_reference_refuses_the_reopening(self):
        unkept = ('a manifest that could not be kept', 'that record claiming facts')
        for case in ('intact', 'null reference', 'removed reference') + unkept:
            with self.subTest(case):
                h = self.harness()
                self.delivered(h)
                self.generation(h)
                start = h.sim.uptime
                if case in unkept:
                    rows = h.broker.reader.receipt_rows
                    h.broker.reader.receipt_rows = lambda ticket: [dict(rows(ticket)[0], uid=1 << 64,
                                                                        row=b'an app UID out of bounds')]
                # The provider read ends a second after every other fact of the round.
                h.sim.hooks.append(lambda command: command == 'sim:rows' and h.sim.tick(1000))
                receipts = self.envelopes(h.observe(), RECEIPT)
                h.sim.hooks.clear()
                group = self.groups(h, 'receipts')[-1]
                end = group['brackets']['end']['elapsed']
                scale = h.broker.scale[h.sim.boot]['elapsed']
                self.between(h)
                if case == 'intact':
                    # The honest control: the scale keeps the read's end, and an ordinary clock half
                    # a second before it is refused as going back.
                    self.assertEqual((len(receipts), scale), (1, end))
                    h.reopen()
                    self.assertEqual(h.broker.scale[h.sim.boot]['elapsed'], end)
                    h.begin()
                    self.assertEqual(h.hello()['status'], STATUS['OK'])
                    h.sim.uptime = start + 500
                    self.assertEqual(h.clock_read()['status'], STATUS['UNAVAILABLE'])
                    continue
                if case == unkept[0]:
                    # The writer's own record of a manifest it could not keep reopens. It moved no
                    # scale, and its rows' first bytes still hold.
                    self.assertEqual((receipts, group['status'], group['compound']), ([], 'unavailable', None))
                    self.assertLess(scale, end)
                    h.reopen()
                    self.assertEqual(h.broker.scale[h.sim.boot]['elapsed'], scale)
                    self.generation(h)
                    self.assertEqual(self.envelopes(h.observe(), RECEIPT), [])
                    self.assertEqual(self.groups(h, 'receipts')[-1]['reason'], 'a row changed after it was first read')
                    continue
                # Only the record changes; the manifest file, if any, and the captures stay.
                record = h.root / 'ledger' / ('%06d-group' % group['number']) / 'record.json'
                content = json.loads(record.read_bytes())
                if case == 'null reference':
                    content['compound'] = None
                elif case == 'removed reference':
                    del content['compound']
                else:
                    content.update(status='facts', reason=None, emitted=True)
                record.write_bytes(capture_ledger.encode_json(content))
                with self.assertRaisesRegex(lab_broker.BrokerError, 'group %d has the form of a compound group'
                                            % group['number']):
                    h.reopen()


class HealthTests(NextBase):
    def health_store(self, h, start, window_ms=600_000, state='HEALTH_WINDOW', criteria=127, boot=None):
        plan = dict(encoder.base_plan(1), plan=PLAN, healthWindow=window_ms, criteria=criteria)
        window = state == 'HEALTH_WINDOW'
        ticket = dict(encoder.base_ticket(1, PLAN), ticket=TICKET, state=state, boot=h.sim.boot,
                      windowBoot=(boot or h.sim.boot) if window else proto.ZERO_ID, windowStart=start if window else 0)
        self.store(h, encoder.ticket(ticket), encoder.plan(plan))

    def window(self, h, preparations=1, baseline=True, window_ms=600_000, action=labtest.PREPARATION_ACTION):
        """A baseline, then the window opening a second later, then prepared probes a second
        apart, then a generation a second later. Returns the window's start."""
        self.between(h)
        if baseline:
            h.broker.health_baseline(TICKET, PLAN, 0, 0, 'before the window opens')
        h.sim.tick(1000)
        start = h.sim.uptime
        self.health_store(h, start, window_ms)
        for _ in range(preparations):
            h.sim.tick(1000)
            self.assertEqual(h.broker.run_action(action, 'prepare a probe')['status'], 'OK')
        h.sim.tick(1000)
        self.generation(h)
        return start

    def probe(self, h):
        reply = h.observe(state=lab_broker.HEALTH_WINDOW_STATE)
        return self.envelopes(reply, HEALTH)

    def classification(self, envelope):
        return {v: k for k, v in proto.HEALTH_CLASSIFICATIONS.items()}[read_observation(envelope['observation'])['classification']]

    def test_a_prepared_full_probe_in_its_window_is_one_held_composition(self):
        h = self.harness()
        start = self.window(h)
        probes = self.probe(h)
        self.assertEqual(len(probes), 1)
        e, b = probes[0], probes[0]['block']
        fact = read_observation(e['observation'])
        group = self.groups(h, 'health')[-1]
        prep = self.actions(h, 'END')[-1]
        baseline = self.groups(h, 'health-baseline')[-1]
        self.assertEqual((fact['kind'], fact['user'], fact['serial'], self.classification(e)), (9, 0, 0, 'HELD'))
        self.assertEqual([row[1] for row in b['rows']], [1] * 7)
        self.assertEqual((b['window_boot'], b['window_start'], b['criteria']), (h.sim.boot, start, 127))
        self.assertEqual(b['probe_begin'], prep['outcome']['interval']['begin'])
        self.assertEqual((b['probe_end'], b['read_end_elapsed'], fact['elapsed']), (h.sim.uptime,) * 3)
        self.assertEqual((b['publication'], b['active_apk']), ('9f' * 32, hashlib.sha256(h.apk).hexdigest()))
        self.assertEqual(b['baseline'], baseline['compound']['sha256'])
        self.assertEqual((e['evidence'], fact['raw']), (group['compound']['sha256'],) * 2)
        manifest = lab_evidence.parse((h.root / group['compound']['path']).read_bytes())
        self.assertEqual((manifest['schema'], manifest['status']), ('andrix-health-composition-v1', 'facts'))
        self.assertEqual(b['preparation_root'], lab_evidence.digest({'preparations': manifest['projection']['offered']}))
        self.assertEqual([row[2] for row in b['rows']], [lab_evidence.digest(r) for r in manifest['projection']['rows']])
        self.assertEqual(group['preparations'], [prep['operation']])

    def test_partial_and_missing_forms_are_kept_and_never_held(self):
        narrow = labtest.default_specs()
        narrow[2] = dict(narrow[2], parameters={'criteria': [2, 3], 'max_probe_ms': 120_000})
        stale = labtest.default_specs()
        stale[2] = dict(stale[2], parameters={'criteria': [2, 3, 5], 'max_probe_ms': 500})
        cases = {'no baseline': ({}, {'baseline': False}, None, (1,)),
                 'no witness reader': ({'reader': {'inventory': True, 'receipts': True, 'health': True}}, {}, None, (1,)),
                 'a criterion left unprepared': ({'specs': narrow}, {}, None, (5,)),
                 'a preparation older than its probe width': ({'specs': stale}, {}, None, (2, 3, 5)),
                 'a preparation the guest does not show': ({}, {}, 'other challenge', (2, 3, 5)),
                 'a criterion the guest could not judge': ({}, {}, 'unknown unlock', (3,)),
                 'a read that did not complete': ({}, {}, 'lost read', None),
                 'a composition of six rows': ({}, {}, 'six rows', None)}
        for name, (options, window, guest, unknown) in cases.items():
            with self.subTest(name):
                h = self.harness(**options)
                self.window(h, **window)
                if guest == 'other challenge':
                    h.sim.prepared[0]['challenge'] = 'ab' * 16
                elif guest == 'lost read':
                    h.sim.scripts['sim:health'] = ['before']
                elif guest == 'six rows':
                    h.sim.health_statuses[0] = ['HELD'] * 6
                elif guest == 'unknown unlock':
                    h.sim.health_statuses[0] = ['HELD'] * 3 + ['UNKNOWN'] + ['HELD'] * 3
                probes = self.probe(h)
                group = self.groups(h, 'health')[-1]
                if unknown is None:
                    self.assertEqual(probes, [])
                    self.assertIn(group['status'], ('unavailable', 'unclassified'))
                    self.assertTrue(group['captures'])
                    self.assertFalse(group['emitted'])
                    continue
                self.assertEqual(self.classification(probes[0]), 'INCONCLUSIVE')
                rows = probes[0]['block']['rows']
                self.assertEqual([bit for bit, status, _ in rows if status == 3], list(unknown))

    def test_bad_rows_and_a_witnessed_crash_follow_the_rows(self):
        cases = {'a bad active copy': ({4: 'BAD'}, None, 'DEGRADED'),
                 'a witnessed crash': ({1: 'BAD'}, {'decision': 'QUALIFIED_CURRENT_ERROR'}, 'CRASH'),
                 'a crash without a witness': ({1: 'BAD'}, None, 'INCONCLUSIVE'),
                 'a pending witness': ({1: 'BAD'}, {'decision': 'PENDING'}, 'INCONCLUSIVE')}
        for name, (bad, witness, expected) in cases.items():
            with self.subTest(name):
                h = self.harness()
                self.window(h)
                h.sim.health_statuses[0] = [bad.get(bit, 'HELD') for bit in range(7)]
                h.sim.witness[0] = witness
                probes = self.probe(h)
                self.assertEqual(self.classification(probes[0]), expected)
        h = self.harness(reader={'inventory': True, 'receipts': True, 'health': True})
        self.window(h)
        h.sim.health_statuses[0] = ['HELD', 'BAD'] + ['HELD'] * 5
        h.sim.witness[0] = {'decision': 'QUALIFIED_CURRENT_ERROR'}
        self.assertEqual(self.classification(self.probe(h)[0]), 'INCONCLUSIVE')

    def test_no_preparation_no_probe_and_one_preparation_one_probe(self):
        h = self.harness()
        self.window(h, preparations=0)
        self.assertEqual(self.probe(h), [])
        self.assertEqual(self.groups(h, 'health'), [])
        self.assertNotIn('sim:health 0', [e.content['intent']['command'] for e in h.entries('capture')])
        h = self.harness()
        self.window(h)
        self.assertEqual(len(self.probe(h)), 1)
        self.assertEqual(self.probe(h), [])
        h.end(0)
        h.reopen()
        self.generation(h)
        self.assertEqual(self.probe(h), [])

    def test_a_probe_that_ends_after_its_window_is_kept_and_emits_nothing(self):
        h = self.harness()
        self.window(h, window_ms=1500)
        self.assertEqual(self.probe(h), [])
        group = self.groups(h, 'health')[-1]
        self.assertEqual((group['status'], group['emitted']), ('facts', False))
        self.assertIn('after its window', group['reason'])
        self.assertEqual(len(group['preparations']), 1)

    def test_only_a_baseline_completed_before_the_window_in_this_framework_is_relied_on(self):
        h = self.harness()
        self.between(h)
        h.sim.tick(1000)
        self.health_store(h, h.sim.uptime)
        h.sim.tick(500)
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'after the window opened')
        h.sim.tick(1000)
        h.broker.run_action(labtest.PREPARATION_ACTION, 'prepare')
        self.generation(h)
        rows = self.probe(h)[0]['block']['rows']
        self.assertEqual(rows[1][1], 3)
        h = self.harness()
        self.between(h)
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'before the window')
        h.sim.framework_restart()
        h.sim.tick(1000)
        self.health_store(h, h.sim.uptime)
        h.sim.tick(1000)
        h.broker.run_action(labtest.PREPARATION_ACTION, 'prepare')
        self.generation(h)
        self.assertEqual(self.probe(h)[0]['block']['rows'][1][1], 3)
        # An unavailable baseline read never replaces the last good one.
        h = self.harness()
        self.between(h)
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'the good one')
        h.sim.scripts['sim:baseline'] = ['before']
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'a lost one')
        self.assertEqual([g['status'] for g in self.groups(h, 'health-baseline')], ['facts', 'unavailable'])
        h.sim.tick(1000)
        self.health_store(h, h.sim.uptime)
        h.sim.tick(1000)
        h.broker.run_action(labtest.PREPARATION_ACTION, 'prepare')
        self.generation(h)
        self.assertEqual(self.classification(self.probe(h)[0]), 'HELD')

    def test_health_needs_its_window_from_the_store_and_a_ticket(self):
        for name in ('not in a window', 'fewer criteria', 'another boot'):
            with self.subTest(name):
                h = self.harness()
                start = self.window(h)
                if name == 'not in a window':
                    self.health_store(h, start, state='APPLIED')
                elif name == 'fewer criteria':
                    self.health_store(h, start, criteria=63)
                else:
                    self.health_store(h, start, boot='ab' * 16)
                self.assertEqual(self.probe(h), [])
                group = self.groups(h, 'health')[-1]
                self.assertEqual((group['status'], group['captures']), ('refused', []))
        h = self.harness()
        self.window(h)
        self.assertEqual(self.envelopes(h.observe(state=16), HEALTH), [])
        self.assertEqual(h.observe(scope='COMPONENT')['status'], STATUS['OK'])
        self.assertEqual(self.groups(h, 'health'), [])
        self.assertEqual(len(self.probe(h)), 1)

    def test_held_needs_current_reads_and_no_witness_doubt(self):
        # The honest control: seven HELD rows, each naming the read it judged, and no witness.
        h = self.harness()
        self.window(h)
        self.assertEqual(self.classification(self.probe(h)[0]), 'HELD')
        group = self.groups(h, 'health')[-1]
        manifest = lab_evidence.parse((h.root / group['compound']['path']).read_bytes())
        self.assertTrue(group['captures'])
        self.assertTrue(all(row['children'] for row in manifest['projection']['rows']))
        # A composer that claims seven HELD rows without a single current read.
        h = self.harness()
        self.window(h)

        def without_reads(context):
            prep, base = context['preparations'][0]['operation'], context['baseline']['digest']
            return {'user': context['user'], 'serial': context['serial'], 'witness': None,
                    'rows': [{'bit': bit, 'status': 'HELD', 'reason': '', 'commands': [],
                              'preparation': prep if bit in (2, 3, 5) else None,
                              'baseline': base if bit == 1 else None} for bit in range(7)]}
        h.broker.reader.health_composition = without_reads
        probe = self.probe(h)[0]
        group = self.groups(h, 'health')[-1]
        manifest = lab_evidence.parse((h.root / group['compound']['path']).read_bytes())
        self.assertEqual((self.classification(probe), [row[1] for row in probe['block']['rows']]),
                         ('INCONCLUSIVE', [3] * 7))
        self.assertEqual(group['captures'], [])
        self.assertEqual([len(row['children']) for row in manifest['projection']['rows']], [0] * 7)
        self.assertEqual({row['reason'] for row in manifest['projection']['rows']}, {'no current read of this criterion'})
        # A pending or inconclusive witness leaves doubt, and a qualified one contradicts a HELD
        # row: no crash or ANR is UNKNOWN, and the probe is never HELD.
        for decision in ('PENDING', 'INCONCLUSIVE', 'QUALIFIED_CURRENT_ERROR'):
            with self.subTest(decision):
                h = self.harness()
                self.window(h)
                h.sim.witness[0] = {'decision': decision}
                probe = self.probe(h)[0]
                self.assertEqual(self.classification(probe), 'INCONCLUSIVE')
                self.assertEqual([row[1] for row in probe['block']['rows']], [1, 3, 1, 1, 1, 1, 1])

    def test_a_probe_uses_up_its_preparations_whatever_its_rows_give(self):
        h = self.harness()
        self.window(h)
        prepared = self.actions(h, 'END')[-1]['operation']
        h.sim.health_statuses[0] = ['HELD' if bit not in (2, 3, 5) else 'UNKNOWN' for bit in range(7)]
        self.assertEqual(self.classification(self.probe(h)[0]), 'INCONCLUSIVE')
        self.assertEqual(self.groups(h, 'health')[-1]['preparations'], [prepared])
        # Its preparation never serves a later probe, though the guest now shows every row HELD.
        h.sim.tick(1000)
        h.sim.health_statuses[0] = ['HELD'] * 7
        self.assertEqual(self.probe(h), [])
        self.assertEqual(len(self.groups(h, 'health')), 1)
        # The honest control: a new preparation serves the next probe, and only it.
        self.between(h)
        h.sim.tick(1000)
        end = h.broker.run_action(labtest.PREPARATION_ACTION, 'prepare the next probe')
        h.sim.tick(1000)
        self.generation(h)
        self.assertEqual(self.classification(self.probe(h)[0]), 'HELD')
        self.assertEqual(self.groups(h, 'health')[-1]['preparations'], [end['operation']])
        # A probe whose read is lost uses up its preparation as well.
        h = self.harness()
        self.window(h)
        h.sim.scripts['sim:health'] = ['before']
        self.assertEqual(self.probe(h), [])
        self.assertEqual(self.groups(h, 'health')[-1]['status'], 'unavailable')
        self.assertEqual(self.probe(h), [])
        self.assertEqual(len(self.groups(h, 'health')), 1)

    def test_a_preparation_from_an_earlier_framework_supports_no_row(self):
        for restarted in (False, True):
            for statuses, expected in ((['HELD'] * 7, 'HELD'), (['HELD', 'HELD', 'BAD'] + ['HELD'] * 4, 'DEGRADED')):
                with self.subTest(restarted=restarted, expected=expected):
                    h = self.harness()
                    self.window(h)
                    self.between(h)
                    prepared = self.actions(h, 'END')[-1]['outcome']['interval']['instance']
                    if restarted:
                        h.sim.framework_restart()
                    h.sim.tick(1000)
                    h.sim.health_statuses[0] = statuses
                    self.generation(h)
                    probe = self.probe(h)[0]
                    if not restarted:
                        # The honest control: in the preparation's framework, the rows stand.
                        self.assertEqual(self.classification(probe), expected)
                        continue
                    # The baseline and every prepared row, the BAD UI marker included, are lost
                    # with the framework instance.
                    self.assertNotEqual(probe['block']['read_instance'], prepared)
                    self.assertEqual([row[1] for row in probe['block']['rows']], [1, 3, 3, 3, 1, 3, 1])
                    self.assertEqual(self.classification(probe), 'INCONCLUSIVE')

    def test_a_failed_manifest_sync_latches_the_writer_and_no_effect_follows(self):
        # The honest control: every manifest is kept, the probe is HELD and the next use runs.
        h = self.harness()
        self.window(h)
        self.assertEqual(self.classification(self.probe(h)[0]), 'HELD')
        self.between(h)
        self.assertEqual(h.broker.run_action(labtest.PREPARATION_ACTION, 'the next probe')['status'], 'OK')
        self.assertIsNone(h.broker.stopped)
        # The first sync of the compound directory after a manifest's rename fails. The broker's
        # stop is latched first, the group keeps its reason, nothing more is read, and no effect
        # launches, after a reopening too.
        h = self.harness()
        self.window(h)
        sync, failures = lab_broker._sync_directory, []

        def failing(path):
            if Path(path) in (h.root / lab_broker.COMPOUND, h.root / lab_broker.RECORDS) and not failures:
                failures.append(path)
                raise OSError('the directory sync failed')
            return sync(path)
        lab_broker._sync_directory = failing
        try:
            reply = h.observe(state=lab_broker.HEALTH_WINDOW_STATE)
        finally:
            lab_broker._sync_directory = sync
        self.assertEqual((reply['status'], reply['envelopes']), (STATUS['STOPPED'], []))
        failed = [e for e in h.entries('group') if 'directory sync failed' in str(e.content['reason'])]
        self.assertEqual([(e.content['reader'], e.content['status'], e.content['compound'], e.content['emitted'])
                          for e in failed], [('receipts', 'unavailable', None, False)])
        self.assertIn('the evidence writer failed', h.broker.stopped)
        self.assertEqual([e.number + 1 for e in h.entries('stop')], [failed[0].number])
        self.between(h)
        before = len(h.sim.calls)
        for reopened in (False, True):
            if reopened:
                h.reopen()
            with self.assertRaisesRegex(lab_broker.Stopped, 'the evidence writer failed'):
                h.broker.run_action(labtest.PREPARATION_ACTION, 'an effect after the failed sync')
        self.assertEqual(h.sim.calls[before:], [])
        self.assertEqual([e.number for e in h.entries('capture') if e.number > failed[0].number], [])
        # A failed sync of an action's kept spec latches the same way, before its BEGIN.
        h = self.harness()
        self.between(h)
        failures.clear()
        lab_broker._sync_directory = failing
        try:
            with self.assertRaisesRegex(lab_broker.Stopped, 'the evidence writer failed'):
                h.broker.run_action(labtest.PREPARATION_ACTION, 'a use whose spec cannot be kept')
        finally:
            lab_broker._sync_directory = sync
        self.assertEqual((failures, self.actions(h)), ([h.root / lab_broker.RECORDS], []))
        self.assertNotIn('prepare', [c[0] for c in h.sim.calls])

    def test_a_probe_whose_manifest_cannot_be_encoded_still_uses_up_its_preparation(self):
        # A pending witness with metadata that its composition holds, but that nests deeper than a
        # manifest may. The honest control's metadata is shallow, so its manifest is kept.
        # A row reason above a side record's bound is a row of no known form.
        deep = {'decision': 'PENDING', 'detail': {'a': {'b': {'c': {'d': {'e': 1}}}}}}
        shallow = {'decision': 'PENDING', 'detail': {'a': 1}}
        cases = (('kept', shallow, False), ('unencodable', deep, False), ('unencodable', deep, True),
                 ('unclassified', None, False))
        for name, witness, reopened in cases:
            with self.subTest(name, reopened=reopened):
                h = self.harness()
                self.window(h)
                prepared = self.actions(h, 'END')[-1]['operation']
                h.sim.witness[0] = witness
                compose = h.broker.reader.health_composition
                if name == 'unclassified':
                    def unbounded(context):
                        value = compose(context)
                        value['rows'][4].update(status='UNKNOWN', reason='x' * (lab_evidence.MAX_STRING + 1))
                        return value
                    h.broker.reader.health_composition = unbounded
                first = self.probe(h)
                group = self.groups(h, 'health')[-1]
                self.assertEqual(group['preparations'], [prepared])
                if name == 'unencodable':
                    self.assertEqual((first, group['status'], group['compound']), ([], 'unavailable', None))
                    self.assertIn('nested too deep', group['reason'])
                elif name == 'unclassified':
                    self.assertEqual((first, group['status'], group['reason']),
                                     ([], 'unclassified', 'criterion row 4 of no known form'))
                else:
                    self.assertEqual((self.classification(first[0]), group['status']), ('INCONCLUSIVE', 'facts'))
                # Without a new preparation, the guest now shows every row HELD and no witness.
                h.sim.witness[0] = None
                h.broker.reader.health_composition = compose
                h.sim.tick(1000)
                if reopened:
                    self.between(h)
                    h.reopen()
                    self.generation(h)
                self.assertEqual(self.probe(h), [])
                self.assertEqual(len(self.groups(h, 'health')), 1)

    def test_a_probe_kept_after_its_window_reopens_kept_and_never_emitted(self):
        for claimed in (False, True):
            with self.subTest(claimed=claimed):
                h = self.harness()
                self.window(h, window_ms=1500)
                # The probe ends a second after every other fact of the round, and after its window.
                h.sim.hooks.append(lambda command: command.startswith('sim:health') and h.sim.tick(1000))
                self.assertEqual(self.probe(h), [])
                h.sim.hooks.clear()
                group = self.groups(h, 'health')[-1]
                manifest = lab_evidence.parse((h.root / group['compound']['path']).read_bytes())
                self.assertEqual((group['status'], group['emitted'], group['observations']), ('facts', False, []))
                self.assertEqual(len(manifest['emits']), 1)
                end = group['brackets']['end']['elapsed']
                self.assertLess(h.broker.scale[h.sim.boot]['elapsed'], end)
                self.between(h)
                if not claimed:
                    # The honest control: the kept fact reopens as kept and moves no scale, and its
                    # manifest says it is kept.
                    h.reopen()
                    self.assertLess(h.broker.scale[h.sim.boot]['elapsed'], end)
                    self.assertIs(manifest.get('emitted'), False)
                    continue
                # A group record that claims the kept fact as emitted, frame digest and all, is
                # refused: only the manifest decides the emission.
                emits = manifest['emits'][0]
                record = h.root / 'ledger' / ('%06d-group' % group['number']) / 'record.json'
                content = json.loads(record.read_bytes())
                content.update(emitted=True, observations=[
                    lab_broker._emitted(emits['mode'], emits['fact'], group['compound']['sha256'])[1]])
                record.write_bytes(capture_ledger.encode_json(content))
                with self.assertRaisesRegex(lab_broker.BrokerError, 'compound manifest of group %d is damaged'
                                            % group['number']):
                    h.reopen()


class ActionTests(NextBase):
    def restart(self, h, action=labtest.RESTART_ACTION):
        self.between(h)
        return h.broker.run_action(action, 'a later framework instance')

    def test_a_typed_action_pins_its_spec_authority_and_user_before_any_effect(self):
        h = self.harness()
        end = self.restart(h)
        begin = self.actions(h, 'BEGIN')[-1]
        inventory = h.broker.ledger.entries[begin['resolved_user']['inventory_group'] - 1]
        captures = [e for e in h.entries('capture') if e.content['intent'].get('lab_action') == begin['number']]
        self.assertTrue(inventory.number < begin['number'] < captures[0].number < end['number'])
        self.assertEqual(inventory.content['purpose'], 'lab-action-resolve')
        self.assertEqual(set(begin) - {'number', 'kind'}, {
            'record', 'action_id', 'type', 'operation', 'spec_sha256', 'authority', 'resolved_user', 'input_digests',
            'predecessor_checkpoint', 'phase', 'cell', 'use', 'reason', 'request', 'parameters',
            'deadline_monotonic_ns', 'wall_ns', 'monotonic_ns'})
        spec = h.broker.specs[labtest.RESTART_ACTION]
        kept = (h.root / 'records' / begin['spec_sha256']).read_bytes()
        self.assertEqual(kept, lab_actions.spec_bytes(spec))
        self.assertEqual((begin['authority'], begin['phase'], begin['cell']), ('LAB_CONTROL', 'F0', 'f0-control'))
        self.assertEqual(begin['resolved_user'], {'id': 0, 'serial': 0, 'type': sim_android.SYSTEM_TYPE,
                                                  'inventory_group': inventory.number})
        effects = [c for c in captures if c.content['intent']['operation'] == 'lab-action-effect']
        self.assertEqual([(c.content['intent']['command'], c.content['intent']['effect_class']) for c in effects],
                         [('am restart', 'control')])
        self.assertEqual((end['status'], end['settled'], end['captures']), ('OK', True, [c.number for c in captures]))
        self.assertEqual(end['counts']['effects_launched'], 1)
        self.assertEqual([c for c in h.sim.calls if c[0] == 'am restart'], [('am restart', h.sim.boot)])

    def test_requests_outside_the_admission_are_refused_before_anything_is_recorded(self):
        h = self.harness()
        self.between(h)
        before = len(h.broker.ledger.entries)
        refusals = {
            'an action never admitted': lambda: h.broker.run_action('9a' * 16, 'reason'),
            'no reason': lambda: h.broker.run_action(labtest.RESTART_ACTION, ' '),
            'caller text in a request': lambda: h.broker.run_action(labtest.RESTART_ACTION, 'r', command='reboot'),
            'a visibility without its entry': lambda: h.broker.run_action(labtest.VISIBILITY_ACTION, 'r',
                                                                          ticket=TICKET, serial=5),
            'a visibility of a notice never issued': lambda: h.broker.run_action(labtest.VISIBILITY_ACTION, 'r',
                                                                                 ticket=TICKET, index=2, serial=5),
        }
        for name, call in refusals.items():
            with self.subTest(name), self.assertRaises(lab_broker.BrokerError):
                call()
        h.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'beside a generation'):
            h.broker.run_action(labtest.RESTART_ACTION, 'during a generation')
        h.end(0)
        self.assertEqual([e.kind for e in h.broker.ledger.entries[before:]], ['generation', 'generation-end'])
        bare = self.harness(health=None)
        self.between(bare)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no health adapter'):
            bare.broker.run_action(labtest.PREPARATION_ACTION, 'prepare')

    def test_uses_and_effect_limits_are_counted_from_the_ledger_and_survive_reopening(self):
        specs = labtest.default_specs()
        specs[0] = dict(specs[0], max_uses=1)
        h = self.harness(specs=specs)
        self.assertEqual(self.restart(h)['status'], 'OK')
        for reopened in (False, True):
            if reopened:
                h.reopen()
            with self.assertRaisesRegex(lab_broker.BrokerError, 'uses of the action are spent'):
                self.restart(h)
        specs = labtest.default_specs() + [labtest.action_spec('0d' * 16, 'FRAMEWORK_RESTART')]
        for limits in (dict(labtest.effect_limits(), control=1), dict(labtest.effect_limits(), phases=dict(
                labtest.effect_limits()['phases'], F0=1))):
            with self.subTest(limits['control']):
                h = self.harness(specs=specs, effect_limits=limits)
                self.assertEqual(self.restart(h)['status'], 'OK')
                h.reopen()
                end = self.restart(h, '0d' * 16)
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']), ('REFUSED', True, 0))
                self.assertIn('spent', end['uncertainty'])
                self.assertEqual(len([c for c in h.sim.calls if c[0] == 'am restart']), 1)

    def test_an_interrupted_action_is_closed_lost_and_never_repeated(self):
        h = self.harness()
        self.between(h)

        def lose(command):
            if command == 'am restart':
                raise KeyboardInterrupt('the broker is lost during the action')
        h.sim.hooks.append(lose)
        with self.assertRaises(KeyboardInterrupt):
            h.broker.run_action(labtest.RESTART_ACTION, 'a restart that is lost')
        h.sim.hooks.clear()
        h.broker.close()
        h.open()
        end = self.actions(h, 'END')[-1]
        self.assertEqual((end['status'], end['settled'], end['counts']['effects_uncertain']), ('LOST', False, 1))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
            self.restart(h)
        # An idempotent capture and read may follow its own uncertain use.
        h.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        self.generation(h)
        self.notice(h)
        self.between(h)
        h.sim.hooks.append(lambda command: command.startswith('sim:read-visibility') and (_ for _ in ()).throw(
            KeyboardInterrupt('lost again')))
        with self.assertRaises(KeyboardInterrupt):
            h.broker.run_action(labtest.VISIBILITY_ACTION, 'capture', ticket=TICKET, index=2, serial=5)
        h.sim.hooks.clear()
        h.broker.close()
        h.open()
        self.assertEqual(self.actions(h, 'END')[-1]['status'], 'LOST')
        self.assertTrue(self.visible(h)['outcome']['qualified'])

    def test_a_stop_ends_an_action_and_no_command_follows(self):
        h = self.harness()
        self.between(h)
        stop = Path(h.admission['fences']['stop_file'])
        h.sim.hooks.append(lambda command: command == 'am restart' and stop.write_text('stop\n'))
        with self.assertRaises(lab_broker.Stopped):
            h.broker.run_action(labtest.RESTART_ACTION, 'a restart that is stopped')
        end = self.actions(h, 'END')[-1]
        self.assertEqual((end['status'], end['settled']), ('STOPPED', False))
        commands = [e.content['intent']['command'] for e in h.entries('capture')]
        self.assertEqual(commands[-1], 'am restart')
        with self.assertRaises(lab_broker.Stopped):
            h.broker.run_action(labtest.VISIBILITY_ACTION, 'r', ticket=TICKET, index=2, serial=5)
        self.assertEqual([e.content['intent']['command'] for e in h.entries('capture')], commands)

    def test_a_user_is_resolved_from_a_whole_inventory_and_never_guessed(self):
        cases = {'a serial the notice was not owed to': (6, None), 'a recipient being removed': (5, 'removing'),
                 'an inventory that is not whole': (5, 'whole'), 'a recipient of another type': (5, 'type'),
                 'another user with the serial': (5, 'other')}
        for name, (serial, change) in cases.items():
            with self.subTest(name):
                h = self.harness()
                h.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
                self.notice(h)
                self.between(h)
                if change == 'removing':
                    h.sim.user_marks[10] = {'removing': True}
                elif change == 'whole':
                    h.sim.inventory_whole = False
                elif change == 'type':
                    h.sim.user_types[10] = 'android.os.usertype.profile.MANAGED'
                elif change == 'other':
                    h.sim.users[-1] = (11, 5, 'RUNNING_UNLOCKED')
                with self.assertRaisesRegex(lab_broker.BrokerError, 'resolves no user'):
                    h.broker.run_action(labtest.VISIBILITY_ACTION, 'r', ticket=TICKET, index=2, serial=serial)
                refused = self.actions(h)[-1]
                self.assertEqual(refused['record'], 'REFUSED')
                self.assertEqual(self.actions(h, 'BEGIN'), [])
        h = self.harness()
        h.sim.user_marks[0] = {'partial': True}
        with self.assertRaisesRegex(lab_broker.BrokerError, 'resolves no user'):
            self.restart(h)
        self.assertNotIn('am restart', [c[0] for c in h.sim.calls])

    def test_a_successor_runs_only_after_its_predecessor_settled(self):
        specs = labtest.default_specs()
        specs[0] = dict(specs[0], successors=[labtest.PREPARATION_ACTION])
        specs[2] = dict(specs[2], predecessor=labtest.RESTART_ACTION)
        h = self.harness(specs=specs)
        self.between(h)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'predecessor'):
            h.broker.run_action(labtest.PREPARATION_ACTION, 'too early')
        end = self.restart(h)
        h.broker.run_action(labtest.PREPARATION_ACTION, 'after the restart')
        self.assertEqual(self.actions(h, 'BEGIN')[-1]['predecessor_checkpoint'], end['number'])

    def test_crossing_effect_limits_launch_nothing_past_their_caps(self):
        limits = labtest.effect_limits()
        limits['crossings'] = dict(limits['crossings'], CREATE=1)
        h = self.harness(effect_limits=limits)
        self.assertEqual(h.cross('CREATE', 2, **DIGESTS)['status'], STATUS['OK'])
        reply = h.cross('CREATE', 3, **DIGESTS)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('limit of 1 CREATE crossings', reply['reason'])
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'CREATE']), 1)
        h = self.harness(boot_policy={'activation_services': 0, 'observed_boots': 8, 'poll_interval_ms': 5000,
                                      'settle_ms': 600_000, 'unexpected_boot': 'HALT'})
        reply = h.cross('REBOOT', 5, entry_instance=-1, **DIGESTS)
        self.assertEqual(reply['status'], STATUS['NO_REPLY'])
        self.assertIn('activation services', reply['reason'])
        self.assertEqual([c for c in h.sim.calls if c[0] == 'reboot'], [])

    def test_an_effect_is_never_launched_past_its_actions_deadline(self):
        specs = labtest.default_specs()
        specs[0] = dict(specs[0], timeout_ms=1500)
        h = self.harness(specs=specs)
        self.between(h)
        h.sim.hooks.append(lambda command: command == 'sim:clock' and setattr(h.clock, 'mono', h.clock.mono + 2 * 10 ** 9))
        end = h.broker.run_action(labtest.RESTART_ACTION, 'a slow restart')
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertNotIn('am restart', [c[0] for c in h.sim.calls])

    def test_a_preparation_without_a_qualified_settlement_is_never_repeated(self):
        # The honest control: a settled use, then after a reopening a second one.
        h = self.harness()
        self.between(h)
        first = h.broker.run_action(labtest.PREPARATION_ACTION, 'a settled preparation')
        self.assertEqual((first['status'], first['settled'], first['outcome']['classification']),
                         ('OK', True, 'PREPARED'))
        h.reopen()
        self.assertEqual(h.broker.run_action(labtest.PREPARATION_ACTION, 'the next probe')['status'], 'OK')
        self.assertEqual(len([c for c in h.sim.calls if c[0] == 'prepare']), 2)
        # The effect ran, then the response was whole but of no recognized form, or the end clock
        # was lost: the use stays uncertain and is never run again, after a reopening too.
        for name in ('an unrecognized form', 'an unavailable postread'):
            with self.subTest(name):
                h = self.harness()
                self.between(h)
                if name == 'an unrecognized form':
                    def unrecognized(command):
                        h.sim._run(command)
                        return sim_android.result(command, 0, b'an unfamiliar result form\n')
                    h.sim.scripts['sim:prepare'] = [unrecognized]
                else:
                    h.sim.hooks.append(lambda command: command.startswith('sim:prepare') and h.sim.scripts.update(
                        {'sim:clock': ['before']}))
                end = h.broker.run_action(labtest.PREPARATION_ACTION, 'a preparation that does not settle')
                h.sim.hooks.clear()
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']),
                                 ('UNKNOWN', False, 1))
                if name == 'an unrecognized form':
                    self.assertEqual(end['outcome']['classification'], 'UNRECOGNIZED')
                else:
                    self.assertIsNone(end['outcome']['interval'])
                self.assertTrue(end['uncertainty'])
                for reopened in (False, True):
                    if reopened:
                        h.reopen()
                    with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
                        h.broker.run_action(labtest.PREPARATION_ACTION, 'a repeat')
                self.assertEqual(len([c for c in h.sim.calls if c[0] == 'prepare']), 1)
                self.assertEqual(h.broker.preparations, {})


if __name__ == '__main__':
    unittest.main()
