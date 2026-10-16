# SPDX-License-Identifier: Apache-2.0
"""The full user setup package on the host: the source derived user forms and their contrary
copies, the typed inventory and limits, the setup actions through the broker on a simulated guest,
the discovery of genuine main SystemUI processes, and changed copies of every new record. Each
contrary form or changed copy must fail for its own reason while its honest original passes.

Host evidence only. The forms are derived from the pinned Android source with illustrative values,
and the guest is simulated: no test here shows a user created, started, switched or set up on a
device, any foreground drawing, or any SystemUI process."""
import hashlib
import json
from pathlib import Path
import shutil
import unittest
import unittest.mock

import capture_ledger
import full_users
import lab_actions
import lab_broker
import lab_protocol as proto
import lab_readers
import labtest
from labtest import GRANT, PLAN, TICKET, Harness
import sim_android
import sim_users
import test_lab_loss

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'full-users'
FORMS = json.loads((FIXTURES / 'forms.json').read_text())
STATUS = proto.STATUSES
SECONDARY = full_users.SECONDARY_TYPE
CREATED = {'kind': 'CREATED_BY', 'action': labtest.CREATE_ACTION}
DIGESTS = {'ticket_digest': hashlib.sha256(b'ticket record').hexdigest(),
           'plan_digest': hashlib.sha256(b'plan record').hexdigest()}


def text(name):
    return (FIXTURES / (name + '.out')).read_bytes().decode('utf-8', 'surrogateescape')


def reply(name, stdout=None):
    """A fixture's whole reply: its exit status, standard output and standard error."""
    form = FORMS[name]
    return form['exit'], text(name) if stdout is None else stdout, form['stderr']


def dump(name='dump-background', stdout=None):
    return full_users.parse_dump(*reply(name, stdout))


class FormTests(unittest.TestCase):
    """The source derived forms and the contrary copies derived from them."""

    def refused(self, call, *args):
        with self.assertRaises(full_users.FormError):
            call(*args)

    def test_every_source_derived_form_parses(self):
        self.assertEqual(set(FORMS), {p.stem for p in FIXTURES.glob('*.out')})
        for name, form in FORMS.items():
            self.assertEqual(form['origin'], 'source', name)
        fresh, created, background, foreground = (dump(n) for n in ('dump-system-only', 'dump-created',
                                                                    'dump-background', 'dump-foreground'))
        self.assertEqual([(u['id'], u['serial'], u['type'], u['state']) for u in fresh['users']],
                         [(0, 0, full_users.SYSTEM_TYPE, 'RUNNING_UNLOCKED')])
        self.assertEqual([(u['id'], u['serial'], u['state'], u['flags']) for u in created['users'][1:]],
                         [(13, 41, '-1', 0x400)])
        self.assertEqual([(u['id'], u['serial'], u['state'], u['flags'], u['restrictions'])
                          for u in background['users'][1:]],
                         [(13, 41, 'RUNNING_UNLOCKED', 0x410, ['no_outgoing_calls', 'no_sms'])])
        self.assertEqual((background['current_user'], background['visible']), (0, [0]))
        self.assertEqual((foreground['current_user'], foreground['mediator_current_user'], foreground['visible']),
                         (13, 13, [13]))
        self.assertEqual((background['supports_switchable'], background['max_switchable'], background['built_in_max'],
                          background['limit_reached']), (True, 4, 32, False))
        self.assertEqual(background['types'][SECONDARY], {'enabled': True, 'max_allowed': 3})
        self.assertIs(background['types'][SECONDARY]['enabled'], True)
        self.assertEqual(full_users.parse_list(*reply('list-created')),
                         [{'id': 0, 'flags': 0x4c13, 'running': True}, {'id': 13, 'flags': 0x400, 'running': False}])
        self.assertEqual((full_users.parse_supports(*reply('supports-true')), full_users.parse_max_users(
            *reply('max-users')), full_users.parse_max_of_type(*reply('max-of-type')),
            full_users.parse_max_running(*reply('max-running'))), (True, 4, 3, 3))
        self.assertEqual((full_users.parse_current(*reply('current-user')), full_users.parse_visible(
            *reply('visible-true')), full_users.parse_setup(*reply('setup-null')),
            full_users.parse_setup(*reply('setup-complete'))), (13, True, 'null', '1'))
        self.assertEqual(full_users.parse_package_uid(*reply('uid-list-13'), full_users.SYSTEMUI, 13), 1310112)
        self.assertTrue(full_users.data_path(labtest.FIXTURE_PACKAGE).fullmatch(
            full_users.parse_package_path(*reply('path-fixture'), labtest.FIXTURE_PACKAGE)))
        self.assertEqual(full_users.parse_pidof(*reply('pidof-two')), [1839, 4734])
        self.assertEqual(full_users.parse_pidof(*reply('pidof-none')), [])
        self.assertEqual(full_users.parse_cmdline(*reply('cmdline-4734')), full_users.SYSTEMUI)
        self.assertEqual(full_users.parse_status(*reply('status-4734'), 4734),
                         {'name': 'ndroid.systemui', 'uids': [1310112] * 4})
        self.assertEqual(full_users.parse_stat(*reply('stat-4734'), 4734),
                         {'comm': 'ndroid.systemui', 'start_ticks': 53000})
        self.assertEqual(full_users.parse_context(*reply('context-4734')), 'u:r:platform_app:s0:c525,c768')
        # The simulated guest prints exactly these forms for the same users, so the broker suites
        # read what these parser checks read.
        sim = sim_android.SimAndroid()
        forms = sim.enable_user_forms()
        forms.next_user, forms.next_serial = 13, 41
        self.assertEqual(forms.dump(), text('dump-system-only'))
        sim._run('pm create-user --user-type %s AndrixLab' % SECONDARY)
        self.assertEqual((forms.dump(), forms.listing()), (text('dump-created'), text('list-created')))
        sim._run('am start-user -w 13')
        self.assertEqual((forms.dump(), forms.listing()), (text('dump-background'), text('list-background')))
        sim._run('am switch-user -w 13')
        self.assertEqual(forms.dump(), text('dump-foreground'))

    def test_user_type_enablement_is_the_printed_boolean(self):
        # UserTypeDetails.mEnabled is a boolean printed as true or false (UserTypeDetails.java:55,
        # 414); only its builder holds the configured integer (:458, :651-654). The system only
        # dump with its five lines in each printed form parses to that meaning, which reaches the
        # limits and the creation gate. The integer forms no dump prints are refused.
        whole, line = text('dump-system-only'), '        mEnabled: true\n'
        self.assertEqual(whole.count(line), 5)
        fresh = inventory_of('system-only')
        for form, meaning in (('true', True), ('false', False)):
            with self.subTest(form=form):
                parsed = dump('dump-system-only', whole.replace(line, '        mEnabled: %s\n' % form))
                self.assertEqual([t['enabled'] for t in parsed['types'].values()], [meaning] * 5)
                self.assertIs(parsed['types'][SECONDARY]['enabled'], meaning)
                value = full_users.limits(parsed, True, 4, 3, 3)
                self.assertIs(value['type_enabled'], meaning)
                problem = full_users.creation_problem(fresh, value)
                if meaning:
                    self.assertIsNone(problem)
                else:
                    self.assertIn('not enabled', problem)
        for form in ('1', '0', '-1', 'True', 'FALSE', 'yes', '', ' true', 'true '):
            with self.subTest(form=form):
                self.refused(full_users.parse_dump, 0, whole.replace(line, '        mEnabled: %s\n' % form), '')
        # Only the full secondary type disabled: its own flag decides the gate.
        at = whole.index(line, whole.index('    %s: \n' % SECONDARY))
        parsed = dump('dump-system-only', whole[:at] + '        mEnabled: false\n' + whole[at + len(line):])
        self.assertEqual([n for n, t in parsed['types'].items() if t['enabled'] is not True], [SECONDARY])
        self.assertIn('not enabled', full_users.creation_problem(fresh, full_users.limits(parsed, True, 4, 3, 3)))
        # A limits reading carries the boolean, never a number that only compares equal to it.
        self.assertIsNone(full_users.check_limits(limits_of()))
        for number in (1, 0):
            with self.subTest(number=number):
                self.assertEqual(full_users.check_limits(limits_of(type_enabled=number)),
                                 'a user limit flag is a boolean')
                self.assertIn('not enabled', full_users.creation_problem(fresh, limits_of(type_enabled=number)))

    def test_a_dump_cut_anywhere_is_refused(self):
        whole = text('dump-background')
        lines = whole[:-1].split('\n')
        for at in range(len(lines)):
            with self.subTest(cut=at):
                self.refused(full_users.parse_dump, 0, '\n'.join(lines[:at]) + ('\n' if at else ''), '')
        self.refused(full_users.parse_dump, 0, whole[:-1], '')
        self.refused(full_users.parse_dump, 0, whole[:len(whole) // 2], '')
        self.assertEqual(len(dump(stdout=whole)['users']), 2)
        for code, err in ((1, ''), (0, 'Can\'t find service: user\n'), (255, '')):
            with self.subTest(code=code, err=err):
                self.refused(full_users.parse_dump, code, whole, err)

    def test_duplicate_users_serials_and_sections_are_refused(self):
        whole = text('dump-background')
        start = whole.index('  UserInfo{13:')
        end = whole.index('\n\nDevice properties:')
        block = whole[start:end + 1]
        cases = {
            'a user listed twice': whole[:end + 1] + block + whole[end + 1:],
            # Otherwise consistent: listed among the started users and the cached IDs too.
            'another user with the same serial': (whole[:end + 1] + block.replace('UserInfo{13:', 'UserInfo{14:')
                                                  + whole[end + 1:]).replace(
                '13=RUNNING_UNLOCKED]', '13=RUNNING_UNLOCKED, 14=RUNNING_UNLOCKED]').replace('[0, 13]', '[0, 13, 14]'),
            'the whole dump twice': whole + whole,
            'a second started users line': whole.replace('  Cached user IDs: [0, 13]\n',
                                                         '  Started users state: [0=RUNNING_UNLOCKED, 13=RUNNING_UNLOCKED]'
                                                         '\n  Cached user IDs: [0, 13]\n'),
            'a started user twice': whole.replace('13=RUNNING_UNLOCKED]', '13=RUNNING_UNLOCKED, 13=RUNNING_UNLOCKED]'),
            'a user type twice': whole.replace('User types (5 types):', 'User types (6 types):').replace(
                '\n\nAllowlisted packages', '\n' + whole[whole.index('    android.os.usertype.full.SYSTEM: '):
                                                         whole.index('    android.os.usertype.full.SECONDARY: ')]
                + '\nAllowlisted packages'),
            'a restriction twice': whole.replace('      no_sms\n    Device policy', '      no_sms\n      no_sms\n'
                                                 '    Device policy'),
            'users out of their order': whole[:whole.index('  UserInfo{0:')] + block
            + whole[whole.index('  UserInfo{0:'):start] + whole[end + 1:],
        }
        for name, copy in cases.items():
            with self.subTest(name):
                self.refused(full_users.parse_dump, 0, copy, '')

    def test_disagreeing_dumps_are_refused(self):
        whole = text('dump-background')
        cases = {
            'a started state that is not the user state': ('13=RUNNING_UNLOCKED]', '13=RUNNING_LOCKED]'),
            'a running user missing from the started users': (', 13=RUNNING_UNLOCKED]', ']'),
            'cached user IDs without a listed user': ('  Cached user IDs: [0, 13]', '  Cached user IDs: [0]'),
            'two current users': ('  Current user id: 0', '  Current user id: 13'),
            'a visible user that is not listed': ('  Visible users: [0]', '  Visible users: [0, 21]'),
            'effective restrictions that are not base and policy ones': (
                '    Effective restrictions:\n      no_outgoing_calls\n      no_sms\n',
                '    Effective restrictions:\n      no_outgoing_calls\n'),
            'a user of a type the dump does not list': ('    Type: android.os.usertype.full.SECONDARY',
                                                        '    Type: android.os.usertype.full.DEMO'),
            'flags that disagree with the user line': ('    Flags: 1040 (FULL|INITIALIZED)', '    Flags: 1024 (FULL)'),
            'flag names that are not the value': ('    Flags: 1040 (FULL|INITIALIZED)', '    Flags: 1040 (FULL|GUEST)'),
            'a primary user without the primary flag': ('{13:AndrixLab:410} serialNo=41 isPrimary=false',
                                                        '{13:AndrixLab:410} serialNo=41 isPrimary=true'),
            'a type detail of another type': ('        mName: android.os.usertype.full.GUEST',
                                              '        mName: android.os.usertype.full.SYSTEM'),
            'a built-in maximum equal to the effective one': ('Max switchable users: 4 (built-in value: 32)',
                                                             'Max switchable users: 4 (built-in value: 4)'),
            'a state of no known name': ('    State: RUNNING_UNLOCKED\n    Created: +2h', '    State: 9\n    Created: +2h'),
            'a line the dump never prints': ('  User version: 11\n', '  User version: 11\n  Users frozen: true\n'),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name):
                self.assertEqual(whole.count(old), 1, name)
                self.refused(full_users.parse_dump, 0, whole.replace(old, new), '')
        # A user list that disagrees with the dump read around it.
        good = dump()
        self.assertIsNone(full_users.check_list(good, full_users.parse_list(*reply('list-background'))))
        for name, rows in {'a list without the created user': 'list-system-only',
                           'a list that says it does not run': 'list-created'}.items():
            with self.subTest(name):
                self.assertIsNotNone(full_users.check_list(good, full_users.parse_list(*reply(rows))))
                with self.assertRaises(full_users.FormError):
                    full_users.inventory(good, full_users.parse_list(*reply(rows)))
        listing = text('list-background')
        for name, copy in {'other flags': listing.replace(':410}', ':10}'), 'a user twice': listing + listing[7:],
                           'no header': listing[7:], 'a row of no known form': listing.replace('\tUserInfo{13', ' UserInfo{13')}.items():
            with self.subTest(name):
                try:
                    rows = full_users.parse_list(0, copy, '')
                except full_users.FormError:
                    continue
                self.assertIsNotNone(full_users.check_list(good, rows), name)

    def test_flags_restrictions_and_states_follow_the_source(self):
        whole = text('dump-background')
        # DebugUtils names flags in whatever order reflection gives, and shows unknown bits last.
        for names in ('INITIALIZED|FULL', 'FULL|INITIALIZED'):
            self.assertEqual(dump(stdout=whole.replace('(FULL|INITIALIZED)', '(%s)' % names))['users'][1]['flags'],
                             0x410)
        unknown = whole.replace('{13:AndrixLab:410}', '{13:AndrixLab:10410}').replace(
            '    Flags: 1040 (FULL|INITIALIZED)', '    Flags: 66576 (FULL|INITIALIZED|10000)')
        self.assertEqual(dump(stdout=unknown)['users'][1]['flags'], 0x10410)
        self.refused(full_users.parse_dump, 0, unknown.replace('|10000)', ')'), '')
        # A restriction key may hold digits; a cached null is derived from the base and policy
        # lists.
        digits = whole.replace('      no_outgoing_calls\n      no_sms\n    Device policy',
                               '      no_cellular_2g\n      no_outgoing_calls\n      no_sms\n    Device policy').replace(
            '    Effective restrictions:\n      no_outgoing_calls\n      no_sms\n',
            '    Effective restrictions:\n      null\n')
        parsed = dump(stdout=digits)
        self.assertEqual(parsed['users'][1]['restrictions'], ['no_cellular_2g', 'no_outgoing_calls', 'no_sms'])
        self.assertIsNone(lab_actions.check_inventory(full_users.inventory(
            parsed, full_users.parse_list(*reply('list-background')))))
        policy = whole.replace('  Device policy global restrictions:\n    null\n',
                               '  Device policy global restrictions:\n    no_add_user\n')
        self.refused(full_users.parse_dump, 0, policy, '')
        self.assertIn('no_add_user', dump(stdout=policy.replace(
            '    Effective restrictions:\n      no_outgoing_calls\n      no_sms\n',
            '    Effective restrictions:\n      null\n'))['users'][1]['restrictions'])
        # Every state projects onto the inventory's coarse states; a removing or guest-to-remove
        # user is being removed.
        for state, coarse in full_users.COARSE.items():
            copy = whole.replace('    State: RUNNING_UNLOCKED\n    Created: +2h', '    State: %s\n    Created: +2h' % state)
            if state == '-1':
                copy = copy.replace(', 13=RUNNING_UNLOCKED]', ']')
            else:
                copy = copy.replace('13=RUNNING_UNLOCKED]', '13=%s]' % state)
            rows = [dict(r, running=r['id'] != 13 or state in full_users.RUNNING_STATES)
                    for r in full_users.parse_list(*reply('list-background'))]
            with self.subTest(state):
                self.assertEqual(full_users.inventory(dump(stdout=copy), rows)['users'][1]['state'], coarse)
        marked = whole.replace('serialNo=41 isPrimary=false', 'serialNo=41 isPrimary=false <guestToRemove>')
        self.assertTrue(full_users.inventory(dump(stdout=marked), full_users.parse_list(
            *reply('list-background')))['users'][1]['removing'])
        self.refused(full_users.inventory, dump(stdout=whole.replace('Current user: 0', 'Current user: N/A')),
                     full_users.parse_list(*reply('list-background')))

    def test_the_small_forms_and_their_contrary_copies(self):
        parsers = {'supports-true': full_users.parse_supports, 'max-users': full_users.parse_max_users,
                   'max-of-type': full_users.parse_max_of_type, 'max-running': full_users.parse_max_running,
                   'current-user': full_users.parse_current, 'visible-true': full_users.parse_visible,
                   'setup-complete': full_users.parse_setup}
        for name, parse in parsers.items():
            code, out, err = reply(name)
            for label, copy in {'a second line': (code, out + out, err), 'no newline': (code, out[:-1], err),
                                'an error': (code, out, 'Error: something\n'), 'another status': (1, out, err),
                                'other text': (code, 'Error: ' + out, err)}.items():
                with self.subTest(name=name, copy=label):
                    self.refused(parse, *copy)
        self.refused(full_users.parse_max_of_type, *reply('max-of-type', text('max-of-type').replace(
            'full.SECONDARY', 'full.GUEST')))
        self.assertEqual(full_users.parse_max_of_type(*reply('max-of-type', text('max-of-type').replace(
            'full.SECONDARY', 'full.GUEST')), 'android.os.usertype.full.GUEST'), 3)
        self.refused(full_users.parse_package_uid, 0, 'package:com.android.systemui uid:10112\n', '',
                     full_users.SYSTEMUI, 13)
        self.refused(full_users.parse_package_uid, 0, text('uid-list-13') * 2, '', full_users.SYSTEMUI, 13)
        self.assertIsNone(full_users.parse_package_uid(0, '', '', full_users.SYSTEMUI, 13))
        self.assertIsNone(full_users.parse_package_path(1, '', '', labtest.FIXTURE_PACKAGE))
        self.refused(full_users.parse_package_path, 0, text('path-fixture') + text('path-fixture'), '',
                     labtest.FIXTURE_PACKAGE)
        self.refused(full_users.parse_package_path, 0, 'package:/data/local/tmp/x/base.apk\n', '',
                     labtest.FIXTURE_PACKAGE)
        # The reader admits only its own reads: no effect, and no read an action makes for itself.
        self.assertTrue(full_users.read_allowed('pm list packages --user 13 -U com.android.systemui'))
        for command in ('am get-current-user', 'cmd user is-user-visible 13', 'pm path --user 13 dev.andrix.lab.notice',
                        'pm list packages --user 13 -U dev.andrix.lab.notice', 'am start-user -w 13',
                        'pm create-user --user-type %s AndrixLab' % SECONDARY, 'cat /proc/4734/environ'):
            self.assertFalse(full_users.read_allowed(command), command)

    def test_effect_replies_classify_only_their_exact_forms(self):
        self.assertEqual(full_users.classify_create(*reply('create-success')), ('CREATED', 13))
        self.assertEqual(full_users.classify_create(*reply('create-refused-maximum'))[1]['code'], 6)
        self.assertEqual(full_users.classify_create(*reply('create-refused-restriction'))[1]['code'], 10)
        for copy in ((0, 'Success: created user id 13\n', 'Error: x\n'), (1, 'Success: created user id 13\n', ''),
                     (0, 'Success: created user id 013\n', ''), (0, 'Success: created user id 21475\n', ''),
                     (255, '', 'java.lang.SecurityException: no\n')):
            self.assertEqual(full_users.classify_create(*copy), ('UNRECOGNIZED', None), copy)
        # Exit status 0 with the failure on standard error is a failure, never a start.
        self.assertEqual(full_users.classify_start(*reply('start-success')), 'STARTED')
        self.assertEqual(full_users.classify_start(*reply('start-failed')), 'FAILED')
        for copy in ((0, 'Success: user started\n', 'Error: could not start user\n'), (1, 'Success: user started\n', ''),
                     (0, 'Success: user started on display 2\n', '')):
            self.assertEqual(full_users.classify_start(*copy), 'UNRECOGNIZED', copy)
        self.assertEqual(full_users.classify_switch(*reply('switch-success'), 13), 'SWITCHED')
        self.assertEqual(full_users.classify_switch(*reply('switch-failed'), 13), 'FAILED')
        self.assertEqual(full_users.classify_switch(*reply('switch-failed'), 14), 'UNRECOGNIZED')
        self.assertEqual(full_users.classify_switch(*reply('switch-not-switchable'), 13), 'REFUSED')
        self.assertEqual(full_users.classify_switch(0, '', 'Error: Thread interrupted unexpectedly.\n', 13), 'UNRECOGNIZED')
        self.assertEqual(full_users.classify_input(*reply('setup-step')), 'INJECTED')
        self.assertEqual(full_users.classify_install_existing(*reply('install-existing'), labtest.FIXTURE_PACKAGE, 13),
                         'REPORTED')
        self.assertEqual(full_users.classify_install_existing(*reply('install-existing'), labtest.FIXTURE_PACKAGE, 14),
                         'UNRECOGNIZED')
        self.assertEqual(full_users.classify_enable(*reply('enable'), labtest.FIXTURE_PACKAGE), 'enabled')
        self.assertEqual(full_users.classify_enable(0, 'Package other.pkg new state: enabled\n', '',
                                                    labtest.FIXTURE_PACKAGE), 'UNRECOGNIZED')


def inventory_of(name='background'):
    # The user list does not show the current user, so the foreground dump shares the background
    # list.
    rows = 'list-' + ('background' if name == 'foreground' else name)
    return full_users.inventory(dump('dump-' + name), full_users.parse_list(*reply(rows)))


def limits_of(name='system-only', **changes):
    value = full_users.limits(dump('dump-' + name), True, 4, 3, 3)
    value.update(changes)
    return value


class InventoryTests(unittest.TestCase):
    """The typed inventory, the user limits and the gates they decide."""

    def test_creation_needs_support_no_restriction_and_room(self):
        fresh = inventory_of('system-only')
        self.assertIsNone(full_users.creation_problem(fresh, limits_of()))
        cases = {'unsupported': ({'supports_multiple': False}, 'not supported'),
                 'restricted': ({'creator_restrictions': ['no_add_user']}, 'no_add_user'),
                 'the switchable limit reached': ({'limit_reached': True}, 'maximum'),
                 'the type allowance reached': ({'type_allowed': 0}, 'maximum'),
                 'no switchable room': ({'max_switchable': 1}, 'maximum'),
                 'the type disabled': ({'type_enabled': False}, 'not enabled')}
        for name, (changes, why) in cases.items():
            with self.subTest(name):
                self.assertIn(why, full_users.creation_problem(fresh, limits_of(**changes)))
        self.assertIn('other than the system user', full_users.creation_problem(inventory_of('created'), limits_of()))
        self.assertIn('not whole', full_users.creation_problem(dict(fresh, whole=False), limits_of()))
        with self.assertRaises(full_users.FormError):
            full_users.limits(dump('dump-system-only'), False, 4, 3, 3)
        with self.assertRaises(full_users.FormError):
            full_users.limits(dump('dump-system-only'), True, 5, 3, 3)

    def test_invalid_user_types_are_refused(self):
        whole = text('dump-background')
        with self.assertRaises(full_users.FormError):
            full_users.parse_dump(0, whole.replace('    Type: android.os.usertype.full.SECONDARY',
                                                   '    Type: android.os.usertype.Full.SECONDARY'), '')
        created = {'user': 13, 'before_users': [0], 'serials_before': [0]}
        for user_type in ('android.os.usertype.profile.MANAGED', 'android.os.usertype.profile.PRIVATE',
                          'android.os.usertype.profile.CLONE', 'android.os.usertype.full.GUEST'):
            with self.subTest(user_type):
                reading = inventory_of()
                reading['users'][1]['type'] = user_type
                self.assertIn('another type', full_users.identify(created, reading)[1])
        for parameters in ({'user_type': 'android.os.usertype.profile.MANAGED', 'name': 'AndrixLab'},
                           {'user_type': 'android.os.usertype.full.GUEST', 'name': 'AndrixLab'},
                           {'user_type': SECONDARY, 'name': 'Andrix Lab'}, {'user_type': SECONDARY, 'name': 'x;id'}):
            with self.subTest(parameters), self.assertRaises(lab_actions.AdmissionError):
                lab_actions.check_specs([labtest.action_spec(labtest.CREATE_ACTION, 'USER_CREATE', max_uses=1,
                                                             parameters=parameters)], labtest.INSTALLATION)

    def test_id_and_serial_reuse_identify_no_user(self):
        reading = inventory_of('created')
        honest = {'user': 13, 'before_users': [0], 'serials_before': [0]}
        self.assertEqual(full_users.identify(honest, reading)[0]['serial'], 41)
        self.assertIn('already a user', full_users.identify(dict(honest, before_users=[0, 13]), reading)[1])
        self.assertIn('serial seen before', full_users.identify(dict(honest, serials_before=[0, 41]), reading)[1])
        self.assertIn('does not list', full_users.identify(dict(honest, user=14), reading)[1])
        self.assertIn('not whole', full_users.identify(honest, dict(reading, whole=False))[1])
        # An ephemeral user would be stopped once it left the foreground.
        reading['users'][1]['flags'] |= full_users.FLAGS['EPHEMERAL']
        self.assertIn('ephemeral', full_users.identify(honest, reading)[1])

    def test_removal_only_from_a_whole_later_inventory(self):
        previous = [(0, 0), (13, 41)]
        self.assertEqual(full_users.removed(previous, inventory_of()), [])
        self.assertEqual(full_users.removed(previous, inventory_of('system-only')), [(13, 41)])
        self.assertIsNone(full_users.removed(previous, dict(inventory_of('system-only'), whole=False)))
        self.assertIsNone(full_users.removed(previous, None))
        marked = inventory_of()
        marked['users'][1]['removing'] = True
        self.assertEqual(full_users.removed(previous, marked), [])
        identified = {'user': 13, 'serial': 41, 'type': SECONDARY}
        self.assertIn('removed', lab_actions.resolve_created(inventory_of('system-only'), identified)[1])
        self.assertIn('not whole', lab_actions.resolve_created(dict(inventory_of('system-only'), whole=False),
                                                               identified)[1])
        reused = inventory_of()
        reused['users'][1]['serial'] = 57
        self.assertIn('another user', lab_actions.resolve_created(reused, identified)[1])

    def test_background_stopped_screen_locked_and_ce_withdrawn(self):
        self.assertEqual(full_users.condition(inventory_of('background'), 13),
                         {'condition': 'BACKGROUND', 'ce_unlocked': True})
        self.assertEqual(full_users.condition(inventory_of('foreground'), 13),
                         {'condition': 'FOREGROUND', 'ce_unlocked': True})
        self.assertEqual(full_users.condition(inventory_of('created'), 13), {'condition': 'STOPPED', 'ce_unlocked': False})
        # A locked screen over an unlocked user changes nothing the dump shows: it reads as
        # RUNNING_UNLOCKED. Only CE storage locked again reads locked.
        withdrawn = text('dump-foreground').replace('    State: RUNNING_UNLOCKED\n    Created: +2h',
                                                     '    State: RUNNING_LOCKED\n    Created: +2h').replace(
            '13=RUNNING_UNLOCKED]', '13=RUNNING_LOCKED]')
        rows = full_users.parse_list(*reply('list-background'))
        reading = full_users.inventory(full_users.parse_dump(0, withdrawn, ''), rows)
        self.assertEqual(full_users.condition(reading, 13), {'condition': 'FOREGROUND', 'ce_unlocked': False})
        for state in ('BOOTING', 'RUNNING_UNLOCKING'):
            copy = withdrawn.replace('State: RUNNING_LOCKED', 'State: ' + state).replace('13=RUNNING_LOCKED]',
                                                                                       '13=%s]' % state)
            self.assertFalse(full_users.condition(full_users.inventory(full_users.parse_dump(0, copy, ''), rows),
                                                  13)['ce_unlocked'])
        self.assertIsNone(full_users.condition(dict(reading, whole=False), 13))
        self.assertIsNone(full_users.condition(reading, 14))

    def test_a_start_never_passes_the_running_limit(self):
        target = {'id': 13, 'serial': 41, 'type': SECONDARY}
        created = inventory_of('created')
        self.assertIsNone(full_users.start_problem(created, limits_of('created'), target))
        self.assertIn('running limit', full_users.start_problem(created, limits_of('created', max_running=1), target))
        self.assertIn('runs already', full_users.start_problem(inventory_of(), limits_of('background'), target))
        self.assertIn('as its create action identified',
                      full_users.start_problem(created, limits_of('created'), dict(target, serial=42)))
        before, after = inventory_of('background'), inventory_of('created')
        self.assertEqual(full_users.still_running(before, after), [(13, 41)])
        self.assertEqual(full_users.still_running(after, before), [])


def process_reads(sim):
    """The process reads of a simulated guest with users 0 and 13 running."""
    forms = sim.enable_user_forms()
    forms.next_user, forms.next_serial = 13, 41
    sim._run('pm create-user --user-type %s AndrixLab' % SECONDARY)
    sim._run('am start-user -w 13')
    return forms


class ProcessTests(unittest.TestCase):
    """The discovery of genuine main SystemUI processes, joined by actual UID and serial."""

    def read(self, sim, reading=None):
        def run(command):
            r = sim.shell(command, 30, 1 << 22, 1 << 16)
            if r.completion != 'exited':
                raise lab_readers.Unavailable('the transport lost the reply')
            return r.exit, r.stdout.decode('utf-8', 'surrogateescape'), r.stderr.decode('utf-8', 'surrogateescape')
        reader = full_users.UserReader(run)
        return reader.processes(reading or reader.inventory())

    def test_each_user_gets_its_genuine_main_process_by_actual_uid(self):
        sim = sim_android.SimAndroid()
        forms = process_reads(sim)
        honest = self.read(sim)
        by_user = {u['user']: u for u in honest['users']}
        self.assertEqual((honest['app_id'], honest['absent']), (sim_users.APP_ID, False))
        self.assertEqual((by_user[0]['serial'], by_user[0]['uid'], by_user[0]['process']['pid']), (0, 10112, 1839))
        self.assertEqual((by_user[13]['serial'], by_user[13]['uid'], by_user[13]['process']['uids']),
                         (41, 1310112, [1310112] * 4))
        self.assertEqual(by_user[13]['process']['context'], 'u:r:platform_app:s0:c525,c768')
        # pidof's order decides nothing.
        forms.pid_order = lambda pids: list(reversed(pids))
        self.assertEqual(self.read(sim), honest)
        # A user whose process is gone has none, and the other keeps its own.
        forms.processes.pop(13)
        self.assertIsNone({u['user']: u for u in self.read(sim)['users']}[13]['process'])

    def test_a_reused_pid_or_a_changed_process_set_is_unavailable(self):
        sim = sim_android.SimAndroid()
        forms = process_reads(sim)
        pid = forms.processes[13][0]
        seen = []

        def reuse(command):
            # The process ends and its PID is reused after its first stat read.
            if command == 'cat /proc/%d/stat' % pid:
                seen.append(command)
                if len(seen) == 1:
                    sim.hooks.append(lambda c: forms.processes[13].__setitem__(1, forms.processes[13][1] + 9))
        sim.hooks.append(reuse)
        with self.assertRaisesRegex(lab_readers.Unavailable, 'changed during the read'):
            self.read(sim)
        sim.hooks.clear()
        count = []

        def grow(command):
            if command == full_users.PIDOF:
                count.append(command)
                if len(count) == 2:
                    forms.extra_processes.append({'user': 0, 'pid': 9999, 'start_ticks': 1, 'name': full_users.SYSTEMUI,
                                                  'uid': 10112})
        sim.hooks.append(grow)
        with self.assertRaisesRegex(lab_readers.Unavailable, 'changed during the read'):
            self.read(sim)

    def test_a_pid_reused_after_its_status_read_is_unavailable(self):
        # The earlier reuse: user 0's process ends after its status was read, and its PID goes at
        # once to another main SystemUI process of user 13, beside that user's own. The PID set
        # stays the same and every later stat agrees. Only the start identity read before the
        # identity fields differs from the one read after the group. The control replaces nothing.
        for reused in (False, True):
            with self.subTest(reused=reused):
                sim = sim_android.SimAndroid()
                forms = process_reads(sim)
                pid, ticks = forms.processes[0]
                own = forms.processes[13][0]

                def replace(command):
                    if 0 in forms.processes:
                        del forms.processes[0]
                        forms.extra_processes.append({'user': 13, 'pid': pid, 'start_ticks': ticks + 100,
                                                      'name': full_users.SYSTEMUI, 'uid': 1310112})

                def after_status(command):
                    # A hook added now runs from the next command on.
                    if reused and command == full_users.proc_command(pid, 'status'):
                        sim.hooks.append(replace)
                sim.hooks.append(after_status)
                if not reused:
                    by_user = {u['user']: u['process'] for u in self.read(sim)['users']}
                    self.assertEqual((by_user[0]['pid'], by_user[0]['uid'], by_user[13]['pid'], by_user[13]['uid']),
                                     (pid, 10112, own, 1310112))
                    continue
                with self.assertRaisesRegex(lab_readers.Unavailable, 'process %d changed during the read' % pid):
                    self.read(sim)
                self.assertNotIn(0, forms.processes)
                # Read from its first start identity on, the replacement is user 13's whole: a
                # second main process for that user, which has no known form, and never user 0's.
                with self.assertRaisesRegex(full_users.FormError, 'two main SystemUI processes for user 13'):
                    self.read(sim)

    def test_only_the_exact_name_task_name_and_context_qualify(self):
        cases = {'the screenshot process': {'name': 'com.android.systemui:screenshot'},
                 'another package': {'name': 'com.android.systemuix'},
                 'UIDs that disagree': {'uids': [1310112, 1310112, 0, 1310112]},
                 'a UID of no listed user': {'uid': 2510112},
                 'a second main process for user 13': {},
                 'a context of no known form': {'context': 'u:r:platform_app:s0:c525,c768 '}}
        for name, extra in cases.items():
            with self.subTest(name):
                sim = sim_android.SimAndroid()
                forms = process_reads(sim)
                process = dict({'user': 13, 'pid': 7001, 'start_ticks': 61000, 'name': full_users.SYSTEMUI,
                                'uid': 1310112}, **extra)
                if name in ('another package', 'the screenshot process', 'UIDs that disagree', 'a UID of no listed user',
                            'a context of no known form'):
                    forms.processes.pop(13)
                forms.extra_processes.append(process)
                with self.assertRaises(full_users.FormError):
                    self.read(sim)
        # An exact context of another domain is kept as read, never judged by a guessed rule.
        sim = sim_android.SimAndroid()
        forms = process_reads(sim)
        forms.processes.pop(13)
        forms.extra_processes.append({'user': 13, 'pid': 7001, 'start_ticks': 61000, 'name': full_users.SYSTEMUI,
                                      'uid': 1310112, 'context': 'u:r:systemui_app:s0:c13,c768'})
        users = {u['user']: u for u in self.read(sim)['users']}
        self.assertEqual(users[13]['process']['context'], 'u:r:systemui_app:s0:c13,c768')

    def test_quiet_absence_is_not_a_denied_proc_or_a_lost_reply(self):
        sim = sim_android.SimAndroid()
        forms = process_reads(sim)
        saved = dict(forms.processes)
        forms.processes.clear()
        quiet = self.read(sim)
        self.assertTrue(quiet['absent'])
        self.assertEqual([u['process'] for u in quiet['users']], [None, None])
        # The quiet failure must repeat in the same read.
        calls = []

        def repeat(command):
            if command == full_users.PIDOF:
                calls.append(command)
                if len(calls) == 2:
                    forms.processes.update(saved)
        sim.hooks.append(repeat)
        with self.assertRaisesRegex(lab_readers.Unavailable, 'did not repeat'):
            self.read(sim)
        sim.hooks.clear()
        forms.processes.update(saved)
        forms.proc_denied.add(saved[13][0])
        with self.assertRaisesRegex(lab_readers.Unavailable, 'refused or the process ended'):
            self.read(sim)
        forms.proc_denied.clear()
        sim.scripts['pidof com.android.systemui'] = ['timeout']
        with self.assertRaisesRegex(lab_readers.Unavailable, 'lost the reply'):
            self.read(sim)
        sim.scripts.clear()
        forms.replies[full_users.PIDOF] = [(1, b'', b'pidof: Permission denied\n')]
        with self.assertRaisesRegex(lab_readers.Unavailable, 'other than quietly'):
            self.read(sim)


class UserBase(unittest.TestCase):
    """A broker over a simulated guest that answers the full user forms."""

    def harness(self, specs=None, next_user=13, next_serial=41, fixture=True, **options):
        sim = sim_android.SimAndroid()
        forms = sim.enable_user_forms()
        forms.next_user, forms.next_serial = next_user, next_serial
        if fixture:
            forms.add_fixture(labtest.FIXTURE_PACKAGE, labtest.FIXTURE_APK)
        options.setdefault('notice', sim_android.SimNotice())
        options.setdefault('health', sim_android.SimHealth())
        h = Harness(next_profile=True, sim=sim, specs=labtest.user_specs() if specs is None else specs,
                    reader={'users': True, 'receipts': True, 'health': True, 'witness': True, 'global_sessions': True},
                    **options)
        h.forms = forms
        self.addCleanup(h.close)
        return h

    def act(self, h, action, reason='a user setup step'):
        return h.broker.run_action(action, reason)

    def setup_user(self, h, upto=labtest.FIXTURE_ACTION):
        ends = []
        for action in (labtest.CREATE_ACTION, labtest.START_ACTION, labtest.SWITCH_ACTION, labtest.SETUP_ACTION,
                       labtest.FIXTURE_ACTION):
            ends.append(self.act(h, action))
            self.assertEqual((ends[-1]['status'], ends[-1]['settled']), ('OK', True), ends[-1])
            if action == upto:
                break
        return ends

    def records(self, h, kind='user-setup'):
        return [e.content for e in h.broker.ledger.entries if e.kind == kind and e.complete]

    def effects(self, h):
        return [e.content['intent']['command'] for e in h.broker.ledger.entries if e.kind == 'capture'
                and e.content['intent'].get('operation') == 'lab-action-effect']


class ActionTests(UserBase):
    """The user setup actions through the broker."""

    def test_the_full_setup_pins_authority_and_intent_before_each_effect(self):
        h = self.harness()
        ends = self.setup_user(h)
        create = ends[0]
        self.assertEqual((create['outcome']['user'], create['outcome']['serial'], create['outcome']['type']),
                         (13, 41, SECONDARY))
        begins = [e for e in h.broker.ledger.entries if e.kind == 'lab-action' and e.content['record'] == 'BEGIN']
        self.assertEqual([b.content['type'] for b in begins], ['USER_CREATE', 'USER_START', 'USER_SWITCH', 'USER_SETUP',
                                                              'USER_FIXTURE'])
        for b in begins:
            c = b.content
            self.assertEqual(c['authority'], 'LAB_USER_ADMIN')
            captures = [e for e in h.broker.ledger.entries if e.kind == 'capture'
                        and e.content['intent'].get('lab_action') == b.number]
            effects = [e for e in captures if e.content['intent']['operation'] == 'lab-action-effect']
            self.assertTrue(effects and all(e.number > b.number for e in effects), c['type'])
            expected = {'id': 0, 'serial': 0} if c['type'] == 'USER_CREATE' else {'id': 13, 'serial': 41}
            self.assertEqual({k: c['resolved_user'][k] for k in ('id', 'serial')}, expected)
        self.assertEqual(self.effects(h), [
            'pm create-user --user-type %s AndrixLab' % SECONDARY, 'am start-user -w 13', 'am switch-user -w 13',
            'input keyevent KEYCODE_ENTER', 'pm install-existing --user 13 dev.andrix.lab.notice',
            'pm enable --user 13 dev.andrix.lab.notice'])
        # No user action's own forms admit a stop, a removal or a settings write.
        user = {'id': 13, 'serial': 41, 'type': SECONDARY}
        for spec in h.broker.specs.values():
            if spec['type'] in lab_actions.USER_TYPES:
                for command in ('am stop-user -w 13', 'am stop-user 13', 'pm remove-user 13',
                                'settings put --user 13 secure user_setup_complete 1', 'am switch-user -w 0'):
                    self.assertFalse(h.broker._own_command(spec, command, user), (spec['type'], command))
        # The returned ID is recorded right after the create's capture, before any later read, and
        # the user is identified from a whole listing after it.
        created, identified = self.records(h)
        capture = h.broker.ledger.entries[created['capture'] - 1]
        self.assertEqual(capture.content['intent']['command'], 'pm create-user --user-type %s AndrixLab' % SECONDARY)
        self.assertEqual(created['number'], created['capture'] + 1)
        self.assertEqual((created['user'], created['before_users'], created['serials_before']), (13, [0], [0]))
        group = h.broker.ledger.entries[identified['inventory_group'] - 1].content
        self.assertEqual((group['reader'], group['status'], identified['serial'], identified['type']),
                         ('inventory', 'facts', 41, SECONDARY))
        self.assertGreater(identified['inventory_group'], created['number'])
        # Never user 10 or serial 10: another guest gives other numbers, and the actions follow
        # them.
        h = self.harness(next_user=21, next_serial=88)
        ends = self.setup_user(h)
        self.assertEqual((ends[0]['outcome']['user'], ends[0]['outcome']['serial']), (21, 88))
        self.assertIn('am switch-user -w 21', self.effects(h))
        self.assertEqual(ends[-1]['outcome']['uid'], 2110150)

    def test_unsupported_restricted_and_maximum_refusals_launch_nothing(self):
        cases = {'unsupported': lambda f: setattr(f, 'supports', False),
                 'restricted': lambda f: f.users[0].base.append('no_add_user'),
                 'the switchable maximum reached': lambda f: setattr(f, 'max_switchable', 1),
                 'the type allowance reached': lambda f: setattr(f, 'type_max', 0),
                 'the type disabled': lambda f: setattr(f, 'type_enabled', False),
                 'another user present': lambda f: f.users.__setitem__(11, sim_users.SimUser(
                     11, 9, 'android.os.usertype.profile.MANAGED', 0x1030, '-1'))}
        for name, change in cases.items():
            with self.subTest(name):
                h = self.harness()
                change(h.forms)
                h.forms.sync()
                end = self.act(h, labtest.CREATE_ACTION)
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']), ('REFUSED', True, 0))
                self.assertEqual((self.effects(h), self.records(h)), ([], []))
        # The guest itself refuses when the gate's reads were right but its own check differs: the
        # refusal settles only when a whole inventory shows no new user.
        h = self.harness()
        h.forms.replies['pm create-user'] = [(1, b'', FORMS['create-refused-maximum']['stderr'].encode())]
        end = self.act(h, labtest.CREATE_ACTION)
        self.assertEqual((end['status'], end['settled'], end['outcome']['detail']['code'], end['outcome']['new_users']),
                         ('FAILED', True, 6, []))
        self.assertEqual(self.records(h), [])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'uses of the action are spent'):
            self.act(h, labtest.CREATE_ACTION)

    def test_a_reused_id_or_serial_is_never_identified(self):
        # The reply names the system user's ID: recorded as the reply said, never identified.
        h = self.harness()
        h.forms.replies['pm create-user'] = [(0, b'Success: created user id 0\n', b'')]
        end = self.act(h, labtest.CREATE_ACTION)
        self.assertEqual((end['status'], end['settled']), ('UNEXPECTED', True))
        self.assertIn('already a user before the create', end['uncertainty'])
        self.assertEqual([(r['record'], r['user']) for r in self.records(h)], [('CREATED', 0)])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'already a user before the create'):
            self.act(h, labtest.START_ACTION)
        # A new user whose serial an earlier inventory showed for a user since gone.
        h = self.harness(next_serial=5)
        h.forms.users[9] = sim_users.SimUser(9, 5, SECONDARY, 0x400, '-1')
        h.forms.sync()
        self.assertEqual(h.broker.systemui_processes('every serial is kept')[0].status, 'facts')
        del h.forms.users[9]
        h.forms.sync()
        end = self.act(h, labtest.CREATE_ACTION)
        self.assertEqual((end['status'], end['settled']), ('UNEXPECTED', True))
        self.assertIn('serial seen before', end['uncertainty'])
        self.assertEqual(self.records(h)[0]['serials_before'], [0, 5])
        self.assertEqual([r['record'] for r in self.records(h)], ['CREATED'])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'serial seen before'):
            self.act(h, labtest.START_ACTION)

    def cut_after(self, h, command):
        """Cuts the next whole user dump after a command short, as a lost reply would leave it."""
        seen, original = [], h.forms.run

        def run(text):
            reply = original(text)
            if text == command:
                seen.append(text)
            elif seen and text == full_users.DUMP and seen != ['cut']:
                seen[:] = ['cut']
                return sim_users.result(text, 0, reply.stdout[:2000])
            return reply
        h.forms.run = run
        return original

    def test_a_failed_whole_read_after_the_create_gives_no_removal(self):
        h = self.harness()
        original = self.cut_after(h, 'pm create-user --user-type %s AndrixLab' % SECONDARY)
        end = self.act(h, labtest.CREATE_ACTION)
        self.assertEqual((end['status'], end['settled'], end['outcome']['detail']), ('UNKNOWN', False, 13))
        self.assertIn('nothing is known absent', end['uncertainty'])
        self.assertEqual([r['record'] for r in self.records(h)], ['CREATED'])
        group = h.broker.ledger.entries[end['postread_groups'][0] - 1].content
        self.assertEqual((group['reader'], group['status']), ('inventory', 'unclassified'))
        # A later whole inventory identifies the user the reply named; the create never runs again.
        h.forms.run = original
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual(end['status'], 'OK')
        self.assertEqual([r['record'] for r in self.records(h)], ['CREATED', 'IDENTIFIED'])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'spent|did not settle'):
            self.act(h, labtest.CREATE_ACTION)
        # A read that is not whole removes nothing: the user still resolves once a whole one shows
        # it.
        h.forms.run = lambda text: sim_users.result(text, 0, original(text).stdout[:2000]) \
            if text == full_users.DUMP else original(text)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'resolves no user: the user inventory is unavailable'):
            self.act(h, labtest.SWITCH_ACTION)
        h.forms.run = original
        self.assertEqual(self.act(h, labtest.SWITCH_ACTION)['status'], 'OK')
        # Only a whole later inventory that no longer lists the user shows it removed.
        self.act(h, labtest.HOME_ACTION)
        del h.forms.users[13]
        h.forms.processes.pop(13, None)
        h.forms.sync()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no longer lists the created user'):
            self.act(h, labtest.SETUP_ACTION)

    def test_start_success_against_stderr_failure(self):
        h = self.harness()
        self.act(h, labtest.CREATE_ACTION)
        h.forms.replies['am start-user'] = [(0, b'', b'Error: could not start user\n')]
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual((end['status'], end['settled'], end['outcome']['reply'], end['counts']['effects_launched']),
                         ('FAILED', True, 'FAILED', 1))
        self.assertEqual(end['outcome']['condition'], {'condition': 'STOPPED', 'ce_unlocked': False})
        # A success reply with the user still stopped, polled whole, is not a start.
        h.forms.replies['am start-user'] = [(0, b'Success: user started\n', b'')]
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual((end['status'], end['settled']), ('UNEXPECTED', True))
        self.assertIn('does not run', end['uncertainty'])
        self.assertEqual(len([p for p in end['postread_groups']]), lab_broker.USER_POLLS)
        # Stderr failure while the user runs anyway is contrary too.
        h = self.harness()
        self.act(h, labtest.CREATE_ACTION)
        h.forms.replies['am start-user'] = [lambda c: (h.forms.start(c, 13), sim_users.result(
            c, 0, b'', b'Error: could not start user\n'))[1]]
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual(end['status'], 'UNEXPECTED')

    def test_a_start_that_would_stop_a_running_user_is_refused_and_one_that_did_is_unexpected(self):
        h = self.harness()
        self.act(h, labtest.CREATE_ACTION)
        h.forms.max_running = 1
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertIn('running limit', end['uncertainty'])
        # A guest that stops another running user beside the start is caught by the whole read
        # after it.
        h = self.harness()
        self.act(h, labtest.CREATE_ACTION)
        h.forms.users[11] = sim_users.SimUser(11, 9, SECONDARY, 0x410, 'RUNNING_UNLOCKED', logged_in=True)
        h.forms.sync()

        def start_and_stop(command):
            reply = h.forms.start(command, 13)
            h.forms.users[11].state = '-1'
            h.forms.sync()
            return reply
        h.forms.replies['am start-user'] = [start_and_stop]
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual((end['status'], end['settled'], end['outcome']['stopped']), ('UNEXPECTED', True, [[11, 9]]))

    def test_an_incomplete_switch_or_a_wrong_current_user_is_never_ok(self):
        for name, scripted, status in (
                ('a done reply with no switch', (0, b'', b''), 'UNEXPECTED'),
                ('a failed switch', (1, b'Error: Failed to switch to user 13\n', b''), 'FAILED'),
                ('not switchable', (255, b'', b'Error: UserSwitchabilityResult=2\n'), 'FAILED'),
                ('an interrupted wait', (0, b'', b'Error: Thread interrupted unexpectedly.\n'), 'UNKNOWN')):
            with self.subTest(name):
                h = self.harness()
                self.setup_user(h, upto=labtest.START_ACTION)
                h.forms.replies['am switch-user'] = [scripted]
                end = self.act(h, labtest.SWITCH_ACTION)
                self.assertEqual(end['status'], status, end)
                self.assertEqual(end['settled'], status != 'UNKNOWN')
                if status == 'UNEXPECTED':
                    self.assertIn('user 0 is current', end['uncertainty'])
                    self.assertEqual((end['outcome']['foreground'], end['outcome']['visible']), (0, False))
                if status == 'UNKNOWN':
                    with self.assertRaisesRegex(lab_broker.BrokerError, 'did not settle'):
                        self.act(h, labtest.SWITCH_ACTION)
        # Current but not visible: each is confirmed by its own read.
        h = self.harness()
        self.setup_user(h, upto=labtest.START_ACTION)
        h.forms.replies['cmd user is-user-visible'] = [(0, b'false\n', b'')] * lab_broker.USER_POLLS
        end = self.act(h, labtest.SWITCH_ACTION)
        self.assertEqual((end['status'], end['outcome']['foreground'], end['outcome']['visible']),
                         ('UNEXPECTED', 13, False))
        self.assertIn('not visible', end['uncertainty'])
        # A switch never starts a user, and never leaves a user that may not run in the background.
        h = self.harness()
        self.act(h, labtest.CREATE_ACTION)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'does not run'):
            self.act(h, labtest.SWITCH_ACTION)
        h = self.harness()
        self.setup_user(h, upto=labtest.SWITCH_ACTION)
        h.forms.users[13].base.append('no_run_in_background')
        h.forms.sync()
        end = self.act(h, labtest.HOME_ACTION)
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        self.assertIn('may not run in the background', end['uncertainty'])
        h.forms.users[13].base.remove('no_run_in_background')
        h.forms.sync()
        self.assertEqual(self.act(h, labtest.HOME_ACTION)['status'], 'OK')

    def test_setup_settles_only_on_the_setup_android_records(self):
        h = self.harness()
        self.setup_user(h, upto=labtest.SWITCH_ACTION)
        h.forms.wizard[13] = [{'key': 'KEYCODE_ENTER'}, {'tap': [540, 1800]}]
        end = self.act(h, labtest.SETUP_ACTION)
        self.assertEqual((end['status'], end['settled'], end['outcome']['setup']), ('UNEXPECTED', True, 'null'))
        self.assertNotIn('settings put', ' '.join(self.effects(h)))
        specs = labtest.user_specs(steps=[{'key': 'KEYCODE_ENTER'}, {'tap': [540, 1800]}])
        h = self.harness(specs=specs)
        self.setup_user(h, upto=labtest.SWITCH_ACTION)
        h.forms.wizard[13] = [{'key': 'KEYCODE_ENTER'}, {'tap': [540, 1800]}]
        end = self.act(h, labtest.SETUP_ACTION)
        self.assertEqual((end['status'], end['outcome']['setup'], end['outcome']['initialized']), ('OK', '1', True))
        # An image that completes setup on its own runs no step.
        h = self.harness(specs=labtest.user_specs(steps=[]))
        self.act(h, labtest.CREATE_ACTION)
        h.forms.wizard[13] = []
        self.act(h, labtest.START_ACTION)
        self.act(h, labtest.SWITCH_ACTION)
        end = self.act(h, labtest.SETUP_ACTION)
        self.assertEqual((end['status'], end['outcome'].get('already_complete'), end['counts']['effects_launched']),
                         ('OK', True, 0))
        # Background, stopped and CE locked users are refused, and so is a dump that cannot say.
        for name in ('background', 'stopped', 'CE withdrawn'):
            with self.subTest(name):
                h = self.harness()
                self.setup_user(h, upto=labtest.START_ACTION if name == 'background' else labtest.CREATE_ACTION)
                if name == 'CE withdrawn':
                    self.act(h, labtest.START_ACTION)
                    self.act(h, labtest.SWITCH_ACTION)
                    h.forms.users[13].state = 'RUNNING_LOCKED'
                    h.forms.sync()
                if name == 'stopped':
                    with self.assertRaisesRegex(lab_broker.BrokerError, 'does not run'):
                        self.act(h, labtest.SETUP_ACTION)
                    continue
                end = self.act(h, labtest.SETUP_ACTION)
                self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))

    def test_a_fixture_needs_its_pinned_bytes_and_settles_on_readback(self):
        h = self.harness(fixture=False)
        self.setup_user(h, upto=labtest.SETUP_ACTION)
        end = self.act(h, labtest.FIXTURE_ACTION)
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        h = self.harness(fixture=False)
        h.forms.add_fixture(labtest.FIXTURE_PACKAGE, labtest.FIXTURE_APK + b' changed')
        self.setup_user(h, upto=labtest.SETUP_ACTION)
        end = self.act(h, labtest.FIXTURE_ACTION)
        self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        # The install reply says installed, but the readback does not show it.
        h = self.harness()
        self.setup_user(h, upto=labtest.SETUP_ACTION)
        h.forms.replies['pm install-existing'] = [(0, b'Package dev.andrix.lab.notice installed for user: 13\n', b'')]
        end = self.act(h, labtest.FIXTURE_ACTION)
        self.assertEqual((end['status'], end['settled'], end['outcome']['uid']), ('UNEXPECTED', True, None))
        h = self.harness()
        self.setup_user(h, upto=labtest.SETUP_ACTION)
        h.forms.replies['pm enable'] = [(0, b'Package dev.andrix.lab.notice new state: disabled-user\n', b'')]
        end = self.act(h, labtest.FIXTURE_ACTION)
        self.assertEqual((end['status'], end['outcome']['enabled']), ('UNEXPECTED', 'disabled-user'))


class NoticeTests(UserBase):
    """A user that starts running after a notice is owed one."""

    def store(self, h):
        root = Path(h.admission['store'])
        for directory, name, data in (('tickets', TICKET, b'ticket record'), ('plans', PLAN, b'plan record'),
                                      ('selections', sim_android.PACKAGE, b'selection record'),
                                      ('authorizations', GRANT, b'grant record')):
            (root / directory).mkdir(parents=True, exist_ok=True)
            (root / directory / (name + '.rec')).write_bytes(data)

    def notice(self, h, index):
        h.begin()
        self.assertEqual(h.hello()['status'], STATUS['OK'])
        self.assertEqual(h.clock_read()['status'], STATUS['OK'])
        reply = h.cross('NOTICE', index, entry_instance=-1, native=proto.NO_REFERENCE, entry_elapsed=h.sim.uptime,
                        occurrence=index - 1, **DIGESTS)
        h.end(0)
        return reply

    def test_a_new_running_user_after_a_notice_is_owed_a_notice(self):
        h = self.harness()
        self.store(h)
        self.setup_user(h, upto=labtest.START_ACTION)
        self.assertEqual(self.notice(h, 2)['status'], STATUS['OK'])
        first = [e.content for e in h.broker.ledger.entries if e.kind == 'notice-issue'][-1]
        self.assertEqual(first['required'], [{'user': 13, 'serial': 41, 'type': SECONDARY}])
        # Another full user starts running after the notice: the issue never covers it, and the next
        # one is owed to both.
        h.forms.users[17] = sim_users.SimUser(17, 52, SECONDARY, 0x410, 'RUNNING_UNLOCKED', logged_in=True)
        h.forms.new_process(17)
        h.forms.sync()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'resolves no user'):
            h.broker.run_action(labtest.VISIBILITY_ACTION, 'capture', ticket=TICKET, index=2, serial=52)
        self.assertEqual(self.notice(h, 3)['status'], STATUS['OK'])
        second = [e.content for e in h.broker.ledger.entries if e.kind == 'notice-issue'][-1]
        self.assertEqual([(r['user'], r['serial']) for r in second['required']], [(13, 41), (17, 52)])


class RecordTests(UserBase):
    """Interrupted prefixes, reopening, and changed copies of each new record."""

    def copy_and_open(self, h, change):
        """A copy of the broker directory with one change, opened over the same guest."""
        target = h.directory / ('changed-%d' % len(list(h.directory.glob('changed-*'))))
        shutil.copytree(h.root, target)
        change(target)
        return h.open_at(target)

    def edit(self, number, change):
        def apply(root):
            entry = next(p for p in (root / 'ledger').iterdir() if p.name.startswith('%06d-' % number))
            record = json.loads((entry / 'record.json').read_text())
            change(record)
            (entry / 'record.json').write_bytes(capture_ledger.encode_json(record))
        return apply

    def test_an_interrupted_create_is_closed_lost_and_never_repeated(self):
        # Lost before the reply's ID was recorded: the create's raw reply is kept, but no created
        # user is ever resolved from it.
        h = self.harness()
        with unittest.mock.patch.object(lab_broker.Broker, '_write_setup', side_effect=KeyboardInterrupt('lost')):
            with self.assertRaises(KeyboardInterrupt):
                self.act(h, labtest.CREATE_ACTION)
        h.reopen()
        end = [e.content for e in h.broker.ledger.entries if e.kind == 'lab-action'][-1]
        self.assertEqual((end['record'], end['status'], end['settled'], end['counts']['effects_uncertain']
                          + end['counts']['effects_launched']), ('END', 'LOST', False, 1))
        self.assertEqual(self.records(h), [])
        with self.assertRaisesRegex(lab_broker.BrokerError, 'recorded no returned user ID'):
            self.act(h, labtest.START_ACTION)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'spent'):
            self.act(h, labtest.CREATE_ACTION)
        # Lost after CREATED and before the identifying read: a later whole inventory identifies it.
        h = self.harness()
        count = []
        h.sim.hooks.append(lambda c: c == 'pm create-user --user-type %s AndrixLab' % SECONDARY and count.append(c))
        h.sim.hooks.append(lambda c: count and c == full_users.DUMP and (_ for _ in ()).throw(
            KeyboardInterrupt('lost after the reply')))
        with self.assertRaises(KeyboardInterrupt):
            self.act(h, labtest.CREATE_ACTION)
        h.sim.hooks.clear()
        h.reopen()
        self.assertEqual([r['record'] for r in self.records(h)], ['CREATED'])
        self.assertEqual(self.act(h, labtest.START_ACTION)['status'], 'OK')
        self.assertEqual([r['record'] for r in self.records(h)], ['CREATED', 'IDENTIFIED'])
        # A stop before the effect launches nothing.
        h = self.harness()
        stop = Path(h.admission['fences']['stop_file'])
        h.sim.hooks.append(lambda c: c == full_users.MAX_RUNNING and stop.write_text('stop\n'))
        with self.assertRaises(lab_broker.Stopped):
            self.act(h, labtest.CREATE_ACTION)
        self.assertEqual(self.effects(h), [])

    def test_serials_and_created_users_survive_reopening(self):
        h = self.harness()
        self.setup_user(h, upto=labtest.START_ACTION)
        before = (dict(h.broker.serials_seen), json.dumps(h.broker.created, sort_keys=True))
        h.reopen()
        self.assertEqual((dict(h.broker.serials_seen), json.dumps(h.broker.created, sort_keys=True)), before)
        self.assertEqual(h.broker.serials_seen, {0: 0, 41: 13})
        self.assertEqual(self.act(h, labtest.SWITCH_ACTION)['status'], 'OK')
        # After a kernel boot the user is stopped again; a later use of the start starts it.
        h.sim.reboot()
        end = self.act(h, labtest.START_ACTION)
        self.assertEqual((end['status'], end['outcome']['condition']['condition']), ('OK', 'BACKGROUND'))

    def test_changed_copies_of_each_new_record_refuse_the_reopening(self):
        h = self.harness()
        self.setup_user(h)
        h.broker.systemui_processes('one discovery')
        created, identified = self.records(h)
        groups = {e.content['reader']: e.number for e in h.broker.ledger.entries if e.kind == 'group'}
        self.copy_and_open(h, lambda root: None).close()
        cases = {
            'CREATED names another user': (self.edit(created['number'], lambda r: r.update(user=14)),
                                           'does not name that user ID'),
            'CREATED forgets a serial': (self.edit(created['number'], lambda r: r.update(serials_before=[])),
                                         'every serial'),
            'CREATED names another capture': (self.edit(created['number'], lambda r: r.update(
                capture=created['capture'] - 1)), 'capture'),
            'IDENTIFIED names another serial': (self.edit(identified['number'], lambda r: r.update(serial=42)),
                                                'not the one its inventory lists'),
            'IDENTIFIED without its CREATED': (self.edit(identified['number'], lambda r: r.update(created=1)),
                                               'without its CREATED'),
            'a typed inventory reading changed': (self.edit(groups['inventory'], lambda r: r['reading']['users'][-1].update(
                serial=99)), 'not what its captures give'),
            'the user limits changed': (self.edit(groups['user-limits'], lambda r: r['reading'].update(max_running=9)),
                                        'not what its captures give'),
            'the type enablement negated': (self.edit(groups['user-limits'], lambda r: r['reading'].update(
                type_enabled=False)), 'not what its captures give'),
            'the type enablement as a number': (self.edit(groups['user-limits'], lambda r: r['reading'].update(
                type_enabled=1)), 'not what its captures give'),
            'a process reading changed': (self.edit(groups['systemui-processes'], lambda r: r['reading']['users'][0].update(
                serial=3)), 'not what its captures give'),
        }
        for name, (change, why) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(lab_broker.BrokerError, why):
                self.copy_and_open(h, change)
        # A changed raw capture refuses the ledger itself.
        group = h.broker.ledger.entries[groups['inventory'] - 1].content

        def change_stream(root):
            entry = next(p for p in (root / 'ledger').iterdir() if p.name.startswith('%06d-' % group['captures'][0]))
            (entry / 'stdout').write_bytes((entry / 'stdout').read_bytes().replace(b'serialNo=41', b'serialNo=42'))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'damaged'):
            self.copy_and_open(h, change_stream)

    def test_the_process_discovery_through_the_broker(self):
        h = self.harness()
        self.setup_user(h, upto=labtest.START_ACTION)
        inventory, processes = h.broker.systemui_processes('genuine main processes')
        self.assertEqual((inventory.status, processes.status), ('facts', 'facts'))
        self.assertGreater(processes.number, inventory.number)
        group = h.broker.ledger.entries[processes.number - 1].content
        self.assertEqual((group['inventory_group'], group['emitted'], group['observations']),
                         (inventory.number, False, []))
        # Denied /proc and a lost reply are unavailable, never absence; the quiet failure is
        # absence.
        h.forms.proc_denied.add(h.forms.processes[13][0])
        self.assertEqual(h.broker.systemui_processes('denied')[1].status, 'unavailable')
        h.forms.proc_denied.clear()
        h.sim.scripts['pidof com.android.systemui'] = ['timeout']
        self.assertEqual(h.broker.systemui_processes('lost')[1].status, 'unavailable')
        h.forms.processes.clear()
        quiet = h.broker.systemui_processes('quiet')[1]
        self.assertEqual((quiet.status, quiet.reading['absent']), ('facts', True))
        h.begin()
        with self.assertRaisesRegex(lab_broker.BrokerError, 'beside a generation'):
            h.broker.systemui_processes('during a generation')
        h.end(0)

    def test_a_pid_reused_during_the_identity_reads_through_the_broker(self):
        # User 0's process 1839 ends and another main SystemUI process of user 13, UID 1310112,
        # takes its PID, beside that user's own: once after 1839's status was read, and once at
        # its first stat read, now the first read of it at all. The PID set stays the same and
        # every later stat agrees. Neither is ever joined to user 0, before or after reopening.
        # The control replaces nothing.
        expected = {'stable': ('facts', None), 'after its status': ('unavailable', 'process 1839 changed'),
                    'at its first stat': ('unclassified', 'two main SystemUI processes for user 13')}
        for case, (status, why) in expected.items():
            with self.subTest(case):
                h = self.harness()
                self.setup_user(h, upto=labtest.START_ACTION)
                pid, ticks = h.forms.processes[0]
                own, old, done = h.forms.processes[13][0], h.forms.run, []

                def replace():
                    done.append(pid)
                    del h.forms.processes[0]
                    h.forms.extra_processes.append({'user': 13, 'pid': pid, 'start_ticks': ticks + 100,
                                                    'name': full_users.SYSTEMUI, 'uid': 1310112})

                def run(command, case=case):
                    if case == 'at its first stat' and command == full_users.proc_command(pid, 'stat') and not done:
                        replace()
                    reply = old(command)
                    if case == 'after its status' and command == full_users.proc_command(pid, 'status') and not done:
                        replace()
                    return reply
                h.forms.run = run
                inventory, processes = h.broker.systemui_processes(case)
                self.assertEqual((pid, inventory.status, processes.status), (1839, 'facts', status))
                self.assertEqual(done, [] if case == 'stable' else [pid])
                if why is not None:
                    self.assertIn(why, processes.reason)
                else:
                    by_user = {u['user']: u['process'] for u in processes.reading['users']}
                    self.assertEqual((by_user[0]['pid'], by_user[0]['uid'], by_user[13]['pid'], by_user[13]['uid']),
                                     (pid, 10112, own, 1310112))
                h.reopen()
                group = h.broker.ledger.entries[processes.number - 1].content
                self.assertEqual((group['reader'], group['status']), ('systemui-processes', status))
                self.assertEqual(group['reading'], processes.reading)


class TransitionTests(UserBase, test_lab_loss.LossBase):
    """User effects follow only settled boot transitions, as managed crossings do: an uncertain
    reboot may still take effect, and no inventory read settles it."""

    def confirmed(self, h, unknown):
        """A plain kernel confirmation through its broker path: settled OK, or, with no new boot
        before its bound, UNKNOWN and unsettled."""
        self.waiting(h)
        if unknown:
            h.sim.reboot = lambda: None
        end = self.confirm(h)
        self.assertEqual((end['status'], end['settled']), ('UNKNOWN', False) if unknown else ('OK', True))
        return end

    def refused(self, h, action):
        """The action is refused before anything is recorded or sent, and spends no use."""
        sent, count, uses = [], len(h.broker.ledger.entries), list(h.broker.action_begins.get(action, []))
        hook = sent.append
        h.sim.hooks.append(hook)
        try:
            with self.assertRaisesRegex(lab_broker.BrokerError, 'boot transition .* unsettled or unexpected'):
                self.act(h, action)
        finally:
            h.sim.hooks.remove(hook)
        self.assertEqual((sent, len(h.broker.ledger.entries), h.broker.action_begins.get(action, [])),
                         ([], count, uses))

    def test_creation_waits_for_an_earlier_boot_transition_to_settle(self):
        # The confirmation ends UNKNOWN and unsettled: the creation is refused, and again after
        # reopening, and no pm create-user is sent. The control's confirmation settles, and the
        # same creation then sends one and identifies the user.
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                h = self.harness(boot_policy=dict(labtest.BOOT_POLICY, settle_ms=20_000))
                self.confirmed(h, unknown)
                # The confirmation's own reboot request is its only effect so far.
                self.assertEqual(self.effects(h), ['adb service reboot:'])
                if unknown:
                    self.refused(h, labtest.CREATE_ACTION)
                    h.reopen()
                    self.assertIn('nothing continues', h.broker._unsettled_transition())
                    self.refused(h, labtest.CREATE_ACTION)
                    self.assertEqual((self.effects(h), self.records(h)), (['adb service reboot:'], []))
                    continue
                h.reopen()
                self.assertIsNone(h.broker._unsettled_transition())
                end = self.act(h, labtest.CREATE_ACTION)
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched']), ('OK', True, 1))
                self.assertEqual(self.effects(h)[1:], ['pm create-user --user-type %s AndrixLab' % SECONDARY])
                self.assertEqual([r['record'] for r in self.records(h)], ['CREATED', 'IDENTIFIED'])

    def test_every_user_effect_waits_for_an_earlier_boot_transition_to_settle(self):
        # The user is created and started before the confirmation. After an unsettled one no
        # start, switch, setup step, fixture or switch home follows, before or after reopening.
        # After a settled one, whose kernel boot stopped the user, each follows in turn after the
        # reopening.
        later = (labtest.START_ACTION, labtest.SWITCH_ACTION, labtest.SETUP_ACTION, labtest.FIXTURE_ACTION,
                 labtest.HOME_ACTION)
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                h = self.harness(boot_policy=dict(labtest.BOOT_POLICY, settle_ms=20_000))
                self.setup_user(h, upto=labtest.START_ACTION)
                self.confirmed(h, unknown)
                before = self.effects(h)
                self.assertEqual(before[-3:], ['pm create-user --user-type %s AndrixLab' % SECONDARY,
                                               'am start-user -w 13', 'adb service reboot:'])
                if unknown:
                    for action in later:
                        self.refused(h, action)
                h.reopen()
                for action in later:
                    if unknown:
                        self.refused(h, action)
                    else:
                        end = self.act(h, action)
                        self.assertEqual((end['status'], end['settled']), ('OK', True), action)
                after = self.effects(h)[len(before):]
                self.assertEqual(after, [] if unknown else [
                    'am start-user -w 13', 'am switch-user -w 13', 'input keyevent KEYCODE_ENTER',
                    'pm install-existing --user 13 %s' % labtest.FIXTURE_PACKAGE,
                    'pm enable --user 13 %s' % labtest.FIXTURE_PACKAGE, 'am switch-user -w 0'])


class AdmissionTests(unittest.TestCase):
    """The user setup specs are exact."""

    def test_user_action_specs_are_exact(self):
        good = labtest.user_specs()
        self.assertEqual(len(lab_actions.check_specs(good, labtest.INSTALLATION)), len(good))
        by_type = {s['type']: at for at, s in enumerate(good) if s['type'] in lab_actions.USER_TYPES}

        def changed(kind, **changes):
            specs = [dict(s) for s in good]
            specs[by_type[kind]] = dict(specs[by_type[kind]], **changes)
            return specs
        cases = {
            'a create used twice': changed('USER_CREATE', max_uses=2),
            'a second create': good + [labtest.action_spec('2a' * 16, 'USER_CREATE', max_uses=1, parameters={
                'user_type': SECONDARY, 'name': 'Other'})],
            'a created user selected by a start': changed('USER_SWITCH', user_selector={
                'kind': 'CREATED_BY', 'action': labtest.START_ACTION}),
            'a start of the system user': changed('USER_START', user_selector={'kind': 'SYSTEM_USER'}),
            'a user action under LAB_CONTROL': changed('USER_START', authority='LAB_CONTROL'),
            'a fixture without its pinned bytes': changed('USER_FIXTURE', inputs=[]),
            'the component as a fixture': changed('USER_FIXTURE', parameters={'package': 'com.android.systemui'}),
            'typed text as a setup step': changed('USER_SETUP', parameters={'steps': [{'text': '1234'}],
                                                                            'settle_ms': 5000}),
            'a key outside the admitted ones': changed('USER_SETUP', parameters={'steps': [{'key': 'KEYCODE_HOME'}],
                                                                                 'settle_ms': 5000}),
            'a create outside F0': changed('USER_CREATE', phase='A'),
            'a create of a profile': changed('USER_CREATE', parameters={
                'user_type': 'android.os.usertype.profile.MANAGED', 'name': 'AndrixLab'}),
        }
        for name, specs in cases.items():
            with self.subTest(name), self.assertRaises(lab_actions.AdmissionError):
                lab_actions.check_specs(specs, labtest.INSTALLATION)
        # The PIN and the CE sentinel complete the sequence; the health package defines them, so the
        # user types are the whole sequence. Their own specs are checked in test_health.py.
        self.assertEqual(lab_actions.USER_SEQUENCE, lab_actions.USER_TYPES)
        self.assertEqual(lab_actions.USER_TYPES[-2:], ('USER_PIN', 'CE_SENTINEL'))


if __name__ == '__main__':
    unittest.main()
