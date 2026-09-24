# SPDX-License-Identifier: Apache-2.0
import copy
import json
import unittest
from observe import active_notification, completed, events

PKG = 'dev.andrix.proof.principal'


def fixture(uid=10001):
    base = dict(schema=1, uid=uid, pid=456, target_package=PKG, nonce='fixture', action='post', elapsed_realtime_ms=1)
    entry = dict(base, phase='entry', selinux_context='u:r:runas_app:s0:c1,c257')
    entry['kernel_fields'] = {'Uid': ' '.join([str(uid)] * 4), 'Gid': ' '.join([str(uid)] * 4),
                             'CapInh': '0', 'CapPrm': '0', 'CapEff': '0', 'CapAmb': '0'}
    return [entry, dict(base, phase='context', context_package=PKG),
            dict(base, phase='complete', active_at_last_observation=True)]


class ObservationTests(unittest.TestCase):
    def test_independent_identity_and_completion(self):
        for uid in [10001, 1010001]:
            rows = events('\n'.join(json.dumps(r) for r in fixture(uid)))
            self.assertTrue(completed(rows, uid, PKG, 'fixture', 'post')[1]['active_at_last_observation'])
        for uid in [0, 2000, -89999, 1001000]:
            with self.assertRaises(ValueError):
                completed(fixture(uid), uid, PKG, 'fixture', 'post')

    def test_mixed_and_incomplete_outputs_refused(self):
        for key, value in [('uid', 10002), ('nonce', 'other'), ('pid', 457), ('target_package', 'android'),
                           ('elapsed_realtime_ms', -1)]:
            rows = fixture(); rows[1][key] = value
            with self.assertRaises(ValueError):
                completed(rows, 10001, PKG, 'fixture', 'post')
        for change in ['tuple', 'capability', 'domain', 'duplicate', 'missing', 'failure']:
            rows = fixture()
            if change == 'tuple': rows[0]['kernel_fields']['Uid'] = '10001 10001 0 10001'
            if change == 'capability': rows[0]['kernel_fields']['CapEff'] = '1'
            if change == 'domain': rows[0]['selinux_context'] = 'u:r:shell:s0'
            if change == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            if change == 'missing': rows.pop(0)
            if change == 'failure': rows.append(dict(schema=1, status='refused_or_failed'))
            with self.assertRaises(ValueError):
                completed(rows, 10001, PKG, 'fixture', 'post')
        for text in ['', 'x' * 131073, '{"schema":true}', '{"schema":2}']:
            with self.assertRaises(ValueError): events(text)

    def test_only_active_exact_service_record_counts(self):
        header = 'Current Notification Manager state:\n'
        record = f'    NotificationRecord(0x123: pkg={PKG} user=UserHandle{{0}} id=7301 tag=fixture importance=3 key=0|{PKG}|7301|fixture|10001: Notification())\n'
        yes = header + '  Notification List:\n' + record + '  \n'
        self.assertTrue(active_notification(yes, 10001, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(yes, 10002, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(yes, 10001, 0, PKG, 'different'))
        self.assertFalse(active_notification(header + '  Enqueued Notification List:\n' + record, 10001, 0, PKG, 'fixture'))
        self.assertFalse(active_notification(header + '  History:\n' + record, 10001, 0, PKG, 'fixture'))
        for bad in ['service unavailable', yes + '  Notification List:\n', header + '  Notification List:\n' + record * 2]:
            with self.assertRaises(ValueError): active_notification(bad, 10001, 0, PKG, 'fixture')
        with self.assertRaises(ValueError): active_notification(yes, 10001, 1, PKG, 'fixture')


if __name__ == '__main__':
    unittest.main()
