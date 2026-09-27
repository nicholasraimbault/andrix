# SPDX-License-Identifier: Apache-2.0
import unittest
from consent_observe import permission_state, ui_target

P = 'dev.andrix.proof.principal'
ROW = '      android.permission.POST_NOTIFICATIONS: granted=true, flags=[RUNTIME_GRANTED|USER_SET]'
TEXT = 'App ID: 10148\n  User: 0\n    Permissions:\n' + ROW + '\n    App ops:\n    Package: ' + P + '\n      version=15\n      App ops:\n'
XML = '<hierarchy><node package="com.android.permissioncontroller" resource-id="com.android.permissioncontroller:id/permission_allow_button" text="Allow" enabled="true" clickable="true" bounds="[20,40][200,100]"/></hierarchy>'


class ConsentObservationTests(unittest.TestCase):
    def state(self, text, **kwargs):
        return permission_state(text, package=P, uid=10148, user_id=0, **kwargs)

    def test_platform_flags_and_declared_section(self):
        self.assertEqual(self.state(TEXT), {'stored': True, 'granted': True, 'flags': ['RUNTIME_GRANTED', 'USER_SET']})
        self.assertEqual(self.state(TEXT.replace(ROW + '\n', '')), {'stored': False, 'granted': False, 'flags': []})
        denied = TEXT.replace('granted=true', 'granted=false').replace('RUNTIME_GRANTED|USER_SET', 'USER_SET|USER_FIXED')
        self.assertEqual(self.state(denied)['flags'], ['USER_FIXED', 'USER_SET'])
        self.assertFalse(self.state(denied)['granted'])

    def test_default_device_not_another_device_or_user(self):
        altered = TEXT.replace('    App ops:', '    Permissions (Device other):\n' + ROW.replace('true', 'false') + '\n    App ops:', 1)
        self.assertTrue(self.state(altered)['granted'])
        other = TEXT + '  User: 10\n    Permissions:\n' + ROW.replace('true', 'false') + '\n    App ops:\n    Package: ' + P + '\n'
        self.assertTrue(self.state(other)['granted'])
        self.assertFalse(permission_state(other, package=P, uid=1010148, user_id=10)['granted'])

    def test_incomplete_wrong_and_duplicate_refuse(self):
        for bad in ['', 'Unknown package '+P+'.', TEXT.replace('10148', '10149'), TEXT.replace(P, 'dev.other'),
                    TEXT.replace('  User: 0', '  User: 1'), TEXT+TEXT, TEXT+'  User: 0\n',
                    TEXT.replace('    Permissions:', '    App ops:'), TEXT.replace(ROW, ROW+'\n'+ROW),
                    TEXT.replace('[RUNTIME_GRANTED|USER_SET]', '[USER_SET|USER_SET]'),
                    TEXT.replace('    App ops:', '    Permissions:', 1), TEXT.split('    Package:')[0]]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.state(bad)
        for uid, user in [(True, 0), (10148, False), (10148, 1), (1000, 0), (-1, 0)]:
            with self.assertRaises(ValueError):permission_state(TEXT, package=P, uid=uid, user_id=user)

    def test_ui_target_exact_and_bounded(self):
        wanted = {'package': 'com.android.permissioncontroller', 'resource_id': 'com.android.permissioncontroller:id/permission_allow_button'}
        self.assertEqual(ui_target(XML, **wanted), {'x': 110, 'y': 70})
        self.assertEqual(ui_target(XML, package='com.android.permissioncontroller', text='Allow'), {'x': 110, 'y': 70})
        for bad in [XML.replace('enabled="true"','enabled="false"'), XML.replace('clickable="true"','clickable="false"'),
                    XML.replace('[200,100]', '[721,100]'), XML.replace('[20,40]', '[200,40]'),
                    XML.replace('package="com.android.permissioncontroller"', 'package="dev.other"'),
                    XML.replace('</hierarchy>', XML[11:-12]+'</hierarchy>'), '<!DOCTYPE hierarchy>'+XML]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):ui_target(bad, **wanted)
        with self.assertRaises(ValueError):ui_target(XML, text='Allow', **wanted)


if __name__ == '__main__':unittest.main()
