# SPDX-License-Identifier: Apache-2.0
"""Supplied reply/UI observations only, not user authentication evidence."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from signing_custody import credential_target, provider_observation, recordable_ui_request, raw_input_command


class CustodyObservationTests(unittest.TestCase):
    def test_exact_provider_results_and_refusals(self):
        result = provider_observation(0, 'Result: Bundle[{result={"id":"a.1","signature_base64":null}}]\n')
        self.assertEqual(result.result, {'id': 'a.1', 'signature_base64': None})
        self.assertIsNone(result.error_class)
        error = provider_observation(0, 'Result: Bundle[{error_class=java.lang.IllegalStateException}]\n')
        self.assertEqual(error.error_class, 'java.lang.IllegalStateException')
        self.assertIsNone(error.result)

    def test_unknown_truncated_duplicate_and_failed_reply_are_not_acknowledgements(self):
        for code, text in [(1, 'Result: Bundle[{result={}}]'), (0, 'Result: null'),
                           (0, 'Result: Bundle[{result={"id":1,"id":2}}]'),
                           (0, 'Result: Bundle[{result={}}] extra'),
                           (0, 'Result: Bundle[{error_class=bad input}]')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                provider_observation(code, text)

    def test_sensitive_or_unknown_ui_inputs_are_refused_before_recording(self):
        for data in [b'{"action":"text","text":"PRIVATE_PIN"}',
                     b'{"action":"pin-keypad","pin":"PRIVATE_PIN"}',
                     b'{"action":"custody-pin","context":"setup","label":"setup","pin":"PRIVATE_PIN"}',
                     b'{"action":"console","label":{"private_key":"PRIVATE_KEY"}}',
                     b'{"action":"PRIVATE_KEY"}', b'{"action":"console","label":"PRIVATE_KEY"}',
                     b'{"action":"wait","seconds":false}', b'{"action":"custody-pin"}',
                     b'PRIVATE_KEY not JSON']:
            record, allowed = recordable_ui_request(data)
            self.assertFalse(allowed)
            self.assertNotIn('PRIVATE_', str(record))
        record, allowed = recordable_ui_request(
            b'{"action":"custody-pin","context":"authenticate","label":"credential-ready"}')
        self.assertTrue(allowed)
        self.assertEqual(record['context'], 'authenticate')
        record, allowed = recordable_ui_request(b'{"action":"swipe","x1":350,"y1":1200,"x2":350,"y2":400}')
        self.assertTrue(allowed)

    def test_raw_input_transport_preserves_remote_lifetime_and_exit_status(self):
        import shlex
        remote = ['content', 'write', '--user', '0', '--uri',
                  'content://dev.andrix.proof.signingcustody/import']
        args = raw_input_command('/opt/host/bin/adb', '127.0.0.1:6520', remote)
        self.assertEqual(args[:7], ['/opt/host/bin/adb', '-s', '127.0.0.1:6520',
                                    'shell', '-T', '-e', 'none'])
        self.assertEqual(shlex.split(args[7]), remote)
        self.assertNotIn('exec-in', args)
        self.assertNotIn('-x', args)

    def test_raw_input_transport_does_not_adopt_arbitrary_endpoints_or_bad_arguments(self):
        for adb, serial, remote in [('adb', '127.0.0.1:6520', ['cat']),
                                    ('/adb', 'other-host:5555', ['cat']),
                                    ('/adb', '127.0.0.1:6520', []),
                                    ('/adb', '127.0.0.1:6520', ['bad\nargument']),
                                    ('/adb', '127.0.0.1:6520', ['bad\x00argument'])]:
            with self.assertRaises(ValueError): raw_input_command(adb, serial, remote)

    def window(self, nodes, focused='true', active='true', display='0'):
        return ('<displays><display id="' + display + '"><window focused="' + focused
                + '" active="' + active + '"><hierarchy>' + nodes
                + '</hierarchy></window></display></displays>')

    def field(self, package='com.android.settings', name='com.android.settings:id/password_entry',
              focused='true', password='true', enabled='true'):
        return ('<node package="' + package + '" resource-id="' + name + '" focused="'
                + focused + '" password="' + password + '" enabled="' + enabled + '"/>')

    def test_credential_field_requires_unique_actual_active_focused_window(self):
        field = self.field()
        self.assertEqual(credential_target(self.window(field), 'setup'), 'settings-credential-field')
        for xml in [self.window(field, focused='false'), self.window(field, active='false'),
                    self.window(field, display='1'), self.window(field + field),
                    self.window(self.field(focused='false')), self.window(self.field(password='false')),
                    self.window(self.field(package='untrusted.app')), '<hierarchy>' + field + '</hierarchy>']:
            with self.subTest(xml=xml), self.assertRaises(ValueError): credential_target(xml, 'setup')

    def test_authenticator_views_are_not_arbitrary_password_fields(self):
        for name in ['com.android.systemui:id/lockPassword', 'lockPassword']:
            field = self.field(package='com.android.systemui', name=name)
            self.assertEqual(credential_target(self.window(field), 'authenticate'), 'systemui-credential-field')
        nodes = ''.join(self.field(package='com.android.systemui',
                                  name='com.android.systemui:id/' + name)
                        for name in ['pinEntry'] + ['key' + str(i) for i in range(10)])
        self.assertEqual(credential_target(self.window(nodes), 'authenticate'), 'systemui-pin-keypad')
        with self.assertRaises(ValueError): credential_target(self.window(nodes + nodes), 'authenticate')
        with self.assertRaises(ValueError): credential_target(self.window(self.field()), 'authenticate')

    def test_nested_or_background_window_and_entities_are_refused(self):
        field = self.field()
        xml = ('<displays><display id="0"><window focused="true" active="true">'
               '<window focused="false" active="false"><hierarchy>' + field
               + '</hierarchy></window><hierarchy><node package="other"/></hierarchy>'
               '</window></display></displays>')
        with self.assertRaises(ValueError): credential_target(xml, 'setup')
        with self.assertRaises(ValueError): credential_target('<!DOCTYPE displays>' + self.window(field), 'setup')
        with self.assertRaises(ValueError): credential_target(self.window(field), 'anything')


if __name__ == '__main__': unittest.main()
