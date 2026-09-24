# SPDX-License-Identifier: Apache-2.0
import copy
import json
import unittest
from location_observe import ATTRIBUTION, PROVIDER, registration_state, stream, appop_mode, device_state

PKG = 'dev.andrix.proof.principal'
UID = 10146
HASH = '0123ABCD'


def rows():
    base = dict(schema=1, action='watch', nonce='fixture', uid=UID, pid=777, provider=PROVIDER, callback_count=0)
    values = [dict(base, phase='entry', kernel_fields={
        'Uid': ' '.join([str(UID)] * 4), 'Gid': ' '.join([str(UID)] * 4),
        'CapInh': '0', 'CapPrm': '0', 'CapEff': '0', 'CapAmb': '0'}, selinux_context='u:r:runas_app:s0:c146,c256'),
        dict(base, phase='context', context_package=PKG, context_uid=UID, attribution_uid=UID,
             attribution_package=PKG, attribution_tag=ATTRIBUTION, coarse_granted=True,
             fine_granted=True, background_granted=True),
        dict(base, phase='provider', fixed_provider_present=True),
        dict(base, phase='registered', request_returned_not_delivery=True, listener_diagnostic_hash=HASH),
        dict(base, phase='callback', callback_count=1, mock=True, marker_time_ms=1234567,
             location_elapsed_realtime_ns=1000000000),
        dict(base, phase='heartbeat', callback_count=1, coarse_granted=True,
             fine_granted=False, background_granted=True),
        dict(base, phase='cleanup', callback_count=1, registered=True, remove_updates_returned=True, executor_retired=True),
        dict(base, phase='complete', callback_count=1)]
    return number(values)


def number(values):
    for index, row in enumerate(values):
        row['sequence'] = index + 1; row['elapsed_realtime_ms'] = index + 1000
    return values


def encode(values):
    return ''.join(json.dumps(row) + '\n' for row in values).encode()


def dump(line):
    return ('Provider:\n  ' + PROVIDER + ' provider [mock]:\n    service: false\n'
            + ('    listeners:\n' + line + '\n' if line else '')
            + '    last location=null\n    enabled=true\n    last mock location=null\nEvent Log:\n')


def listener(flags='', inactive=False, uid=UID, pkg=PKG, identity=HASH):
    return (f'      {uid}/{pkg}[{ATTRIBUTION}]/{identity}' + (' {' + flags + '}' if flags else '')
            + ' Request[@1000ms HIGH_ACCURACY]' + (' (inactive)' if inactive else ''))


class LocationObserverTests(unittest.TestCase):
    def test_valid_stream_and_partial_writes(self):
        data = encode(rows())
        parsed = stream(data, 'fixture', UID, PKG, complete=True)
        self.assertEqual(parsed[-1]['callback_count'], 1)
        partial = encode(rows()[:4]) + b'{"unfinished"'
        self.assertEqual(len(stream(partial, 'fixture', UID, PKG)), 4)
        with self.assertRaises(ValueError): stream(partial, 'fixture', UID, PKG, complete=True)
        self.assertEqual(stream(b'', 'fixture', UID, PKG), [])
        with self.assertRaises(ValueError): stream(b'', 'fixture', UID, PKG, complete=True)

    def test_identity_sequence_permission_and_privacy_failures(self):
        for index, key, value in [(0, 'uid', 0), (1, 'pid', 778), (1, 'attribution_package', 'android'),
                (1, 'context_uid', 1000), (3, 'nonce', 'other'), (3, 'sequence', True),
                (4, 'mock', False), (4, 'latitude', 1.0), (4, 'marker_time_ms', '1234'),
                (4, 'callback_count', 5), (5, 'fine_granted', 0), (6, 'executor_retired', False),
                (2, 'fixed_provider_present', False), (5, 'action', 'info')]:
            values = rows(); values[index][key] = value
            with self.assertRaises(ValueError): stream(encode(values), 'fixture', UID, PKG, complete=True)
        values = rows(); values[0]['kernel_fields']['Gid'] = '0 0 0 0'
        with self.assertRaises(ValueError): stream(encode(values), 'fixture', UID, PKG, complete=True)
        for uid in [-89854, 1001000, 2000]:
            with self.assertRaises(ValueError): stream(encode(rows()), 'fixture', uid, PKG)

    def test_terminal_failures_are_not_completion(self):
        values = rows()[:3]
        values += [dict(values[2], phase='cleanup', registered=False, remove_updates_returned=False, executor_retired=True),
                   dict(values[2], phase='request', status='refused_or_failed', error_class='java.lang.SecurityException')]
        self.assertEqual(stream(encode(number(values)), 'fixture', UID, PKG, complete=True)[-1]['phase'], 'request')
        for bad in [rows()[:-1], number(rows() + [rows()[-1]]), number(rows()[:3] + [rows()[1]] + rows()[3:])]:
            with self.assertRaises(ValueError): stream(encode(bad), 'fixture', UID, PKG, complete=True)
        values = rows(); values[-1]['status'] = 'refused_or_failed'
        with self.assertRaises(ValueError): stream(encode(values), 'fixture', UID, PKG, complete=True)

    def test_registration_state_and_history_separation(self):
        state = registration_state(dump(listener()), UID, PKG, HASH)
        self.assertTrue(state['active'] and state['permitted']); self.assertFalse(state['background'])
        state = registration_state(dump(listener('bg, na', True)), UID, PKG, HASH)
        self.assertTrue(state['background']); self.assertFalse(state['active'] or state['permitted'])
        state = registration_state(dump(listener('bg')), UID, PKG, HASH)
        self.assertTrue(state['active'] and state['permitted'] and state['background'])
        self.assertIsNone(registration_state(dump('') + listener() + '\n', UID, PKG, HASH))
        self.assertIsNone(registration_state(dump(listener(pkg=PKG+'peer', uid=10147)), UID, PKG, HASH))

    def test_appop_configuration_has_uid_precedence(self):
        self.assertEqual(appop_mode('Uid mode: FINE_LOCATION: foreground\nFINE_LOCATION: allow; time=1s ago\n', 'FINE_LOCATION'), 'foreground')
        self.assertEqual(appop_mode('No operations.\nDefault mode: deny\n', 'MOCK_LOCATION'), 'deny')
        self.assertEqual(appop_mode('COARSE_LOCATION: allow (running)\n', 'COARSE_LOCATION'), 'allow')
        for bad in ['', 'No operations.', 'Uid mode: FINE_LOCATION: allow\nUid mode: FINE_LOCATION: ignore\n', 'FINE_LOCATION: unknown\n']:
            with self.assertRaises(ValueError): appop_mode(bad, 'FINE_LOCATION')

    def test_device_conditions_come_from_controller_diagnostics(self):
        power = ('POWER MANAGER (dumpsys power)\n\nPower Manager State:\n  mWakefulness=Awake\n  mWakefulnessChanging=false\n'
                 'Battery saver state machine:\n  Enabled=false\n    full=false\n    adaptive=false\n')
        window = ('WINDOW MANAGER POLICY STATE (dumpsys window policy)\n    KeyguardServiceDelegate\n'
                  '      showing=false\n      inputRestricted=false\n      systemReady=true\n'
                  '      bootCompleted=true\n      screenState=SCREEN_STATE_ON\n'
                  '      interactiveState=INTERACTIVE_STATE_AWAKE\n')
        state = device_state(power, window)
        self.assertTrue(state['interactive'] and state['keyguard_ready'] and state['keyguard_awake'])
        self.assertFalse(state['power_save'] or state['keyguard_showing'])
        self.assertTrue(device_state(power.replace('full=false', 'full=true'), window)['power_save'])
        self.assertTrue(device_state(power, window.replace('showing=false', 'showing=true'))['keyguard_showing'])
        for bad in ['', power.replace('Enabled=false', 'Enabled=unknown'), power + '  mWakefulness=Awake\n']:
            with self.assertRaises(ValueError): device_state(bad, window)
        for bad in ['', window + '    KeyguardServiceDelegate\n', window.replace('systemReady=true\n', '')]:
            with self.assertRaises(ValueError): device_state(power, bad)

    def test_provider_dump_ambiguity_is_not_absence(self):
        for text in [dump(listener(uid=1000)), dump(listener(identity='FFFFFFFF')),
                dump(listener() + '\n' + listener()), dump(listener()).replace('Event Log:', 'partial'),
                dump(listener()).replace(' [mock]', ''), dump(listener()).replace('last location=', 'unknown='),
                dump(listener()).replace('Request[', 'Unknown['), 'Location Manager State:\n']:
            with self.assertRaises(ValueError): registration_state(text, UID, PKG, HASH)


if __name__ == '__main__':
    unittest.main()
