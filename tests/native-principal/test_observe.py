# SPDX-License-Identifier: Apache-2.0
import copy
import json
import unittest
from observe import active_notification, bound_context, completed, events

PKG = 'dev.andrix.proof.principal'


def fixture(uid=10001):
    base = dict(schema=1, uid=uid, pid=456, target_package=PKG, nonce='fixture', action='post', elapsed_realtime_ms=1)
    entry = dict(base, phase='entry', selinux_context='u:r:runas_app:s0:c1,c257')
    entry['kernel_fields'] = {'Uid': ' '.join([str(uid)] * 4), 'Gid': ' '.join([str(uid)] * 4),
                             'CapInh': '0', 'CapPrm': '0', 'CapEff': '0', 'CapAmb': '0'}
    return [entry, dict(base, phase='context', context_package=PKG, context_uid=uid,
                        attribution_uid=uid, attribution_package=PKG),
            dict(base, phase='complete', active_at_last_observation=True)]


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128); value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    if isinstance(value, str): value = value.encode()
    if isinstance(value, bytes): return varint(number * 8 + 2) + varint(len(value)) + value
    return varint(number * 8) + varint(value)


def record(uid=10001, user=0, pkg=PKG, nonce='fixture', state=1, extra=b''):
    return field(1, field(1, f'{user}|{pkg}|7301|{nonce}|{uid}')
                 + field(2, state) + field(11, pkg) + field(12, pkg) + extra)


TAIL = b''.join(field(n, field(1, 'marker')) for n in [2, 3, 6, 7, 8])


class ObservationTests(unittest.TestCase):
    def test_independent_identity_and_completion(self):
        for uid in [10001, 1010001]:
            rows = events('\n'.join(json.dumps(r) for r in fixture(uid)))
            self.assertTrue(completed(rows, uid, PKG, 'fixture', 'post')[1]['active_at_last_observation'])
        for uid in [0, 2000, -89999, 1001000]:
            with self.assertRaises(ValueError): completed(fixture(uid), uid, PKG, 'fixture', 'post')

    def test_mixed_and_incomplete_outputs_refused(self):
        for key, value in [('uid', 10002), ('nonce', 'other'), ('pid', 457), ('target_package', 'android'),
                           ('elapsed_realtime_ms', -1)]:
            rows = fixture(); rows[1][key] = value
            with self.assertRaises(ValueError): completed(rows, 10001, PKG, 'fixture', 'post')
        for change in ['tuple', 'capability', 'domain', 'duplicate', 'missing', 'failure']:
            rows = fixture()
            if change == 'tuple': rows[0]['kernel_fields']['Uid'] = '10001 10001 0 10001'
            if change == 'capability': rows[0]['kernel_fields']['CapEff'] = '1'
            if change == 'domain': rows[0]['selinux_context'] = 'u:r:shell:s0'
            if change == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            if change == 'missing': rows.pop(0)
            if change == 'failure': rows.append(dict(schema=1, status='refused_or_failed'))
            with self.assertRaises(ValueError): completed(rows, 10001, PKG, 'fixture', 'post')
        for text in ['', 'x' * 131073, '{"schema":true}', '{"schema":2}', 'ignored\n{"schema":1}']:
            with self.assertRaises(ValueError): events(text)

    def test_native_refusal_requires_correct_caller_binding(self):
        peer = PKG + 'peer'
        rows = fixture(10002)
        rows[1].update(context_package=peer, attribution_package=peer)
        rows[-1].update(phase='post', status='refused_or_failed')
        self.assertEqual(bound_context(rows, 10002, PKG, 'fixture', 'post', peer)['context_package'], peer)
        for index, key, value in [(1, 'context_uid', 10001), (1, 'context_package', PKG),
                (1, 'attribution_uid', 10001), (1, 'attribution_package', 'android'),
                (2, 'uid', 0), (2, 'pid', 1), (2, 'target_package', 'android'),
                (2, 'action', 'cancel'), (2, 'elapsed_realtime_ms', -1), (2, 'nonce', 'other')]:
            bad = copy.deepcopy(rows); bad[index][key] = value
            with self.assertRaises(ValueError): bound_context(bad, 10002, PKG, 'fixture', 'post', peer)
        for bad in [rows + [rows[-1]], rows[:2] + [fixture(10002)[2], rows[-1]]]:
            with self.assertRaises(ValueError): bound_context(bad, 10002, PKG, 'fixture', 'post', peer)
        bad = copy.deepcopy(rows); bad[1]['status'] = 'refused_or_failed'
        with self.assertRaises(ValueError): bound_context(bad, 10002, PKG, 'fixture', 'post', peer)
        bad = fixture(); bad[-1]['status'] = 'report_failed'
        with self.assertRaises(ValueError): completed(bad, 10001, PKG, 'fixture', 'post')
        old = fixture(); old[1]['attribution_package'] = 'android'
        with self.assertRaises(ValueError): completed(old, 10001, PKG, 'fixture', 'post')
        wrong_order = fixture(); wrong_order[0], wrong_order[1] = wrong_order[1], wrong_order[0]
        with self.assertRaises(ValueError): completed(wrong_order, 10001, PKG, 'fixture', 'post')
        for invalid in [None, '', 3]:
            with self.assertRaises(ValueError): bound_context(rows, 10002, invalid, 'fixture', 'post', peer)

    def test_only_posted_structured_records_count(self):
        self.assertTrue(active_notification(record() + TAIL, 10001, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(TAIL, 10001, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(record(state=0) + record(state=2) + TAIL, 10001, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(record(nonce='different') + TAIL, 10001, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(record(pkg='other.package', extra=field(9,
            '\n  Notification List:\n    key=0|' + PKG + '|7301|fixture|10001:\u2028')) + TAIL,
            10001, 0, PKG, 'fixture'))
        for bad in [record(uid=10002) + TAIL, record(user=1) + TAIL, record() * 2 + TAIL]:
            with self.assertRaises(ValueError): active_notification(bad, 10001, 0, PKG, 'fixture')

    def test_malformed_or_partial_service_data_is_not_absence(self):
        for bad in [b'', b'\x80', b'\x80' * 11, b'\x00', b'\x0b', b'\x0a\xff', b'\x0a\x05x',
                    record(), record() + TAIL[:-1], TAIL + field(8, b'x'), TAIL + record(),
                    record(extra=field(1, 'duplicate')) + TAIL, field(1, field(11, PKG)) + TAIL,
                    record(state=3) + TAIL, 'Current Notification Manager state:\n']:
            with self.assertRaises(ValueError): active_notification(bad, 10001, 0, PKG, 'fixture')
        with self.assertRaises(ValueError): active_notification(record() + TAIL, 10001, 1, PKG, 'fixture')


if __name__ == '__main__':
    unittest.main()
