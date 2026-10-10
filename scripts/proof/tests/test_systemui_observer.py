# SPDX-License-Identifier: Apache-2.0
"""The read only shell observer: fixtures to Observation records, its allowlist and its brackets."""
import ast
import hashlib
import json
from pathlib import Path
import struct
import unittest

from scripts.proof import component_transaction_records as encoder
from scripts.proof import systemui_observer as o
from scripts.proof import systemui_sessions as s

FIXTURES = Path(__file__).parent / 'fixtures' / 'systemui_readbacks'
FORMS = json.loads((FIXTURES / 'forms.json').read_text())
SOURCE = Path(o.__file__)
INSTALLATION = '00112233445566778899aabbccddeeff'
NONCE = '5e1f0c9a7d3b4e2f8a6c1d0b9e7f3a25'
BOOT = '1f0d016e80904303a3ff9eb193eb403d'


def reply(name):
    entry = FORMS[name]
    return entry['exit'], (FIXTURES / (name + '.out')).read_text(), entry['stderr']


def device(**changes):
    """One consistent guest state, from captured forms where they exist. The captured listings
    were read with --only-parent. Without children the plain listing prints the same bytes."""
    replies = {
        o.BOOT_ID: 'boot-id', o.UPTIME: 'uptime', o.FRAMEWORK_PID: 'framework-pid', 'cat /proc/957/stat': 'framework-stat',
        o.FINGERPRINT: 'fingerprint', o.BOOT_COMPLETED: 'boot-completed', o.SUPPORTS_CHECKPOINT: 'vdc-supports-checkpoint',
        o.NEEDS_CHECKPOINT: 'vdc-needs-checkpoint-none', o.FACTORY_DIGEST: 'digest-factory',
        o.FACTORY_VERSION: 'factory-version-list', o.ACTIVE_PATH: 'path-factory', o.ACTIVE_VERSION: 'version-uid-list',
        o.SYSTEMUI_PID: 'systemui-pid', 'cat /proc/1839/attr/current': 'systemui-context',
        'cat /proc/1839/status': 'systemui-status-1839', 'cat /proc/4721/status': 'systemui-status-4721',
        'cat /proc/4721/attr/current': 'systemui-context-4721', o.USERS: 'users-two',
        "sha256sum '%s'" % reply('path-data')[1][len('package:'):-1]: 'digest-data',
        o.LISTING: 'listing-failed-signer', o.INSTALLS: 'installs-finalized-failed'}
    replies = {command: reply(name) for command, name in replies.items()}
    replies.update(changes)
    return replies


class Shell:
    """A fake shell. A reply that is a list answers each call with its next item."""

    def __init__(self, replies):
        self.replies, self.commands = replies, []

    def __call__(self, command):
        self.commands.append(command)
        value = self.replies[command]
        if isinstance(value, list):
            return value.pop(0) if len(value) > 1 else value[0]
        return value


def observer(replies):
    shell = Shell(replies)
    counter = iter(range(1, 1000))
    return o.ShellObserver(shell, INSTALLATION, new_id=lambda: '%032x' % next(counter), wall=lambda: 7), shell


def decode_frame(data):
    magic, kind, version, length = struct.unpack_from('<IHHI', data)
    assert (magic, kind, version, length) == (0x52445841, 4, 1, len(data))
    assert hashlib.sha256(data[:-32]).digest() == data[-32:]
    return data


def listing_text(rows):
    writer = s.IndentingWriter()
    for row in rows:
        writer.println(row)
    return writer.text()


def fixture_facts():
    """Every fact the fixture guest gives, by name: each kind and classification the forms reach."""
    facts = {}
    observe, _ = observer(device())
    facts['boot-completed'] = observe.boot()
    facts['checkpoint-committed'] = observe.checkpoint()
    facts['factory-present'] = observe.factory()
    facts['active-factory'] = observe.active()
    facts['boot-booting'] = observer(device(**{o.BOOT_COMPLETED: reply('boot-not-completed')}))[0].boot()
    pending = device(**{o.NEEDS_CHECKPOINT: reply('vdc-needs-checkpoint-pending')})
    facts['checkpoint-pending'] = observer(pending)[0].checkpoint()
    facts['active-data'] = observer(device(**{o.ACTIVE_PATH: reply('path-data')}))[0].active()
    pairs = {'failed': ('listing-failed-signer', 'installs-finalized-failed'),
             'refused': ('listing-pair-mismatched', 'installs-finalized-historical'),
             'none': ('listing-pair-nonstaged', 'installs-historical-refused')}
    for label, (listing, dump) in pairs.items():
        for n, fact in enumerate(observer(device(**{o.LISTING: reply(listing), o.INSTALLS: reply(dump)}))[0].sessions()):
            facts['sessions-%s-%d' % (label, n)] = fact
    ready = device(**{o.LISTING: (1, listing_text([READY_ROW]), ''), o.INSTALLS: reply('installs-active-referrer')})
    for n, fact in enumerate(observer(ready)[0].sessions()):
        facts['sessions-nonce-%d' % n] = fact
    two = device(**{o.SYSTEMUI_PID: reply('systemui-pids-two')})
    for n, fact in enumerate(observer(two)[0].users()):
        facts['users-%d' % n] = fact
    _, baseline = observer(two)[0].health(DOMAIN, FACTORY_APK)
    for n, fact in enumerate(observer(two)[0].health(DOMAIN, FACTORY_APK, baseline)[0]):
        facts['health-%d' % n] = fact
    for label, listing, dump in (('abandoned', (1, '', ''), 'installs-destroyed-ready'),
                                 ('removed', (1, '', ''), 'installs-historical-outcomes'),
                                 ('foreign', reply('listing-failed-signer'), 'installs-foreign-records')):
        scenario = device(**{o.LISTING: listing, o.INSTALLS: reply(dump)})
        for n, fact in enumerate(observer(scenario)[0].sessions()):
            facts['sessions-%s-%d' % (label, n)] = fact
    return facts


DOMAIN = 'platform_app'
FACTORY_APK = s.file_digest(*reply('digest-factory')[:2], s.FACTORY_PATH)
DATA_APK = reply('digest-data')[1][:64]


def listed(state_ten='RUNNING_UNLOCKED', marker=''):
    """The source derived user listing with user 10's state and markers changed."""
    text = reply('users-two')[1]
    second = text.index('  UserInfo{10:')
    head, tail = text[:second], text[second:]
    tail = tail.replace('    State: RUNNING_UNLOCKED\n', '    State: %s\n' % state_ten, 1)
    tail = tail.replace('isPrimary=false', 'isPrimary=false' + marker, 1)
    # The started users list the same states, without a user that has none.
    started = '' if state_ten == '-1' else ', 10=' + state_ten
    tail = tail.replace(', 10=RUNNING_UNLOCKED]', started + ']', 1)
    return 0, head + tail, ''


READY_ROW = ('sessionId = 1378782103; appPackageName = com.android.systemui; isStaged = true; isReady = true; '
             'isApplied = false; isFailed = false; errorMsg = ;')


class DeviceFactTests(unittest.TestCase):
    def test_boot(self):
        observe, shell = observer(device())
        fact = observe.boot()
        self.assertEqual((fact['kind'], fact['classification'], fact['component']), ('BOOT', 'COMPLETED', ''))
        self.assertEqual((fact['user'], fact['serial'], fact['route'], fact['instance']), (-10000, -1, 'SHELL', -1))
        self.assertEqual(fact['boot'], BOOT)
        self.assertEqual(fact['elapsed'], 5432170)
        self.assertEqual(fact['facts'], {'fingerprint': s.build_fingerprint(*reply('fingerprint')[:2])})
        self.assertEqual(shell.commands, [o.BOOT_ID, o.UPTIME, o.FINGERPRINT, o.BOOT_COMPLETED, o.BOOT_ID])
        captures = [o.Capture(c, *shell.replies[c]) for c in shell.commands]
        self.assertEqual(fact['raw'], o.raw_digest(captures))
        decode_frame(o.encode(fact))
        booting, _ = observer(device(**{o.BOOT_COMPLETED: reply('boot-not-completed')}))
        self.assertEqual(booting.boot()['classification'], 'BOOTING')

    def test_checkpoint(self):
        self.assertEqual(observer(device())[0].checkpoint()['classification'], 'COMMITTED')
        pending = device(**{o.NEEDS_CHECKPOINT: reply('vdc-needs-checkpoint-pending')})
        fact = observer(pending)[0].checkpoint()
        self.assertEqual((fact['kind'], fact['classification'], fact['component'], fact['facts']),
                         ('CHECKPOINT', 'PENDING', '', {}))
        decode_frame(o.encode(fact))
        for changes in ({o.NEEDS_CHECKPOINT: reply('vdc-needs-checkpoint-failed')},
                        {o.SUPPORTS_CHECKPOINT: (0, '', '')}, {o.NEEDS_CHECKPOINT: (2, '', '')}):
            with self.subTest(changes=changes), self.assertRaises(o.Unclassified):
                observer(device(**changes))[0].checkpoint()

    def test_factory_and_active(self):
        observe, _ = observer(device())
        factory = observe.factory()
        self.assertEqual((factory['kind'], factory['classification']), ('FACTORY', 'PRESENT'))
        self.assertEqual(factory['facts'], {'apk': s.file_digest(*reply('digest-factory')[:2], s.FACTORY_PATH),
                                            'version': 37})
        active = observe.active()
        self.assertEqual((active['kind'], active['classification']), ('ACTIVE', 'FACTORY_COPY'))
        self.assertEqual(active['facts'], {'apk': factory['facts']['apk'], 'version': 37, 'uid': 10112,
                                           'context': 'u:r:platform_app:s0:c512,c768'})
        data, _ = observer(device(**{o.ACTIVE_PATH: reply('path-data')}))
        fact = data.active()
        self.assertEqual(fact['classification'], 'DATA_COPY')
        self.assertEqual(fact['facts']['apk'], reply('digest-data')[1][:64])
        for value in (factory, active, fact):
            decode_frame(o.encode(value))

    def test_cohort_from_fixtures(self):
        observe, _ = observer(device())
        cohort = o.observed_cohort(observe.boot(), observe.factory())
        planned = s.Cohort(s.build_fingerprint(*reply('fingerprint')[:2]),
                           s.file_digest(*reply('digest-factory')[:2], s.FACTORY_PATH))
        self.assertTrue(s.cohort_matches(planned, cohort))
        other = s.Cohort(planned.fingerprint.replace('CP2A.260605.016', 'CP2A.260705.001'), planned.factory_digest)
        self.assertFalse(s.cohort_matches(other, cohort))
        boot = observe.boot()
        moved = dict(observe.factory(), boot='1' * 32)
        with self.assertRaises(ValueError):
            o.observed_cohort(boot, moved)


class SessionFactTests(unittest.TestCase):
    def facts(self, listing, dump):
        observe, _ = observer(device(**{o.LISTING: listing, o.INSTALLS: dump}))
        return observe.sessions()

    def test_captured_pairs(self):
        expected = {
            ('listing-failed-signer', 'installs-finalized-failed'): [('FAILED', 2014338406)],
            ('listing-failed-verity', 'installs-finalized-two'): [('FAILED', 2014338406), ('FAILED', 1978352588)],
            ('listing-pair-mismatched', 'installs-finalized-historical'): [
                ('FAILED', 181393819), ('FAILED', 1590532299), ('REFUSED', 636061908)],
            ('listing-pair-nonstaged', 'installs-historical-refused'): []}
        for (listing, dump), sessions in expected.items():
            facts = self.facts(reply(listing), reply(dump))
            self.assertEqual(facts[0]['kind'], 'LISTING')
            self.assertEqual(facts[0]['facts']['count'], sum(c != 'REFUSED' for c, _ in sessions))
            self.assertEqual(facts[0]['classification'], 'SESSIONS_FOR_PACKAGE' if facts[0]['facts']['count']
                             else 'NONE_FOR_PACKAGE')
            self.assertEqual([(f['classification'], f['facts']['reference'][1]) for f in facts[1:]], sessions)
            for fact in facts:
                self.assertEqual((fact['instance'], fact['boot'], fact['user']), (14229, BOOT, -10000))
                decode_frame(o.encode(fact))

    def test_reference_fields(self):
        facts = self.facts(reply('listing-failed-signer'), reply('installs-finalized-failed'))
        presence, session, created, stage, installer, nonce = facts[1]['facts']['reference']
        self.assertEqual(presence, o.SESSION | o.CREATED | o.STAGE_DIR | o.INSTALLER)
        self.assertEqual((session, stage, installer, nonce),
                         (2014338406, '/data/app-staging/session_2014338406', 2000, encoder.ZERO_ID))
        self.assertGreater(created, 0)

    def test_nonce_from_the_referrer(self):
        facts = self.facts((1, listing_text([READY_ROW]), ''), reply('installs-active-referrer'))
        session = facts[1]
        self.assertEqual(session['classification'], 'READY')
        presence, identity, _, _, _, nonce = session['facts']['reference']
        self.assertEqual((presence & o.NONCE, identity, nonce), (o.NONCE, 1378782103, NONCE))
        decode_frame(o.encode(session))

    def test_another_tickets_referrer_is_not_this_ticket(self):
        dump = reply('installs-active-referrer')[1].replace(NONCE, '2' * 32)
        facts = self.facts((1, listing_text([READY_ROW]), ''), (0, dump, ''))
        self.assertEqual(facts[1]['facts']['reference'][5], '2' * 32)
        self.assertEqual(s.sessions_by_nonce(s.installs_dump(0, dump), NONCE), ())
        foreign = reply('installs-active-referrer')[1].replace('andrix-ticket:' + NONCE, 'https://example.org/x' + 'x' * 25)
        facts = self.facts((1, listing_text([READY_ROW]), ''), (0, foreign, ''))
        self.assertEqual(facts[1]['facts']['reference'][0] & o.NONCE, 0)

    def test_disagreement_gives_no_fact(self):
        failed_row = READY_ROW.replace('isReady = true', 'isReady = false').replace('isFailed = false', 'isFailed = true')
        for listing, dump in (
                ((1, listing_text([failed_row]), ''), reply('installs-active-referrer')),
                ((1, '', ''), reply('installs-active-referrer')),
                (reply('listing-ready'), reply('installs-active-referrer')),
                (reply('listing-failed-signer'), reply('installs-historical-refused'))):
            with self.subTest(listing=listing[1][:40]), self.assertRaises(o.Unclassified):
                self.facts(listing, dump)


class RemovalTests(unittest.TestCase):
    """Abandoned, destroyed and removed sessions, from source derived forms that await a guest."""

    def facts(self, listing, dump):
        observe, _ = observer(device(**{o.LISTING: listing, o.INSTALLS: dump}))
        return observe.sessions()

    def test_a_destroyed_session_reads_abandoned(self):
        facts = self.facts((1, '', ''), reply('installs-destroyed-ready'))
        self.assertEqual([(f['kind'], f['classification']) for f in facts],
                         [('LISTING', 'NONE_FOR_PACKAGE'), ('SESSION', 'ABANDONED')])
        self.assertEqual(facts[1]['facts']['reference'][1], 1378782103)

    def test_a_destroyed_session_still_listed_gives_no_fact(self):
        with self.assertRaises(o.Unclassified):
            self.facts((1, listing_text([READY_ROW]), ''), reply('installs-destroyed-ready'))

    def test_a_removed_session_still_listed_gives_no_fact(self):
        # The listed session is live under the same ID, so only the removed record contradicts it.
        failed = reply('installs-finalized-failed')[1]
        lines = failed[failed.index('Finalized install sessions:'):failed.index('Historical install sessions:')]
        body = [line for line in lines.split('\n') if line.startswith('    ')]
        _, values, keys = s._session('Finalized', 2014338406, s._logical('\n'.join(body) + '\n', '    '))
        writer = s.IndentingWriter()
        writer.println('Finalized install sessions:')
        writer.increase()
        s._render_session(writer, 'Finalized', 636061908, values, keys)
        writer.println()
        writer.println()
        writer.decrease()
        removed = reply('installs-historical-outcomes')[1]
        dump = 'Active install sessions:\n  \n' + writer.text() + removed[removed.index('Historical install sessions:'):]
        row = READY_ROW.replace('1378782103', '636061908').replace('isReady = true', 'isReady = false').replace(
            'isFailed = false', 'isFailed = true')
        with self.assertRaises(o.Unclassified):
            self.facts((1, listing_text([row]), ''), (0, dump, ''))
        live = dump.replace('  Session 636061908:', '  Session 636061907:', 1)
        self.assertEqual(self.facts((1, listing_text([row]), ''), (0, live, ''))[1]['classification'], 'FAILED')

    def test_a_committed_removed_session_needs_its_terminal_flag(self):
        facts = self.facts((1, '', ''), reply('installs-historical-outcomes'))
        outcomes = {f['facts']['reference'][1]: f['classification'] for f in facts[1:]}
        self.assertEqual((outcomes[636061911], outcomes[636061912]), ('APPLIED', 'FAILED'))
        with self.assertRaises(o.Unclassified):
            self.facts((1, '', ''), reply('installs-historical-unknown'))

    def test_an_abandon_needs_its_message(self):
        facts = self.facts((1, '', ''), reply('installs-historical-outcomes'))
        outcomes = {f['facts']['reference'][1]: f['classification'] for f in facts[1:]}
        self.assertEqual((outcomes[636061908], outcomes[636061910]), ('ABANDONED', 'REFUSED'))

    def test_a_listed_session_missing_from_the_dump_gives_no_fact(self):
        extra = READY_ROW.replace('1378782103', '1378782104')
        with self.assertRaises(o.Unclassified):
            self.facts((1, listing_text([READY_ROW, extra]), ''), reply('installs-active-referrer'))
        self.assertEqual(len(self.facts((1, listing_text([READY_ROW]), ''), reply('installs-active-referrer'))), 2)

    def test_the_join_needs_a_complete_listing(self):
        dump = s.installs_dump(*reply('installs-active-referrer')[:2])
        text = listing_text([READY_ROW])
        self.assertEqual(len(o.join(s.staged_listing(1, text, False), dump)), 1)
        with self.assertRaises(ValueError):
            o.join(s.staged_listing(1, text, True), dump)

    def test_a_staged_session_of_no_known_package_gives_no_fact(self):
        row = READY_ROW.replace('1378782103', '1378782199').replace('com.android.systemui', 'null').replace(
            'isReady = true', 'isReady = false')
        with self.assertRaises(o.Unclassified):
            self.facts((1, listing_text([row]), ''), reply('installs-unknown-package'))

    def test_records_of_other_packages_block_nothing(self):
        facts = self.facts(reply('listing-failed-signer'), reply('installs-foreign-records'))
        self.assertEqual([(f['kind'], f['classification']) for f in facts],
                         [('LISTING', 'SESSIONS_FOR_PACKAGE'), ('SESSION', 'FAILED')])


class ClockTests(unittest.TestCase):
    def test_the_clock_reads_the_observation_scale(self):
        observe, shell = observer(device())
        self.assertEqual(observe.clock(), (BOOT, 14229, 5432170, 7))
        self.assertEqual(observe.sessions()[0]['instance'], 14229)
        stat = reply('framework-stat')
        later = (0, stat[1].replace(' 14229 ', ' 99999 '), '')
        restarted, _ = observer(device(**{'cat /proc/957/stat': later}))
        self.assertGreater(restarted.clock()[1], observe.clock()[1])
        none, _ = observer(device(**{o.FRAMEWORK_PID: (1, '', '')}))
        self.assertEqual(none.clock()[1], -1)
        with self.assertRaises(o.Unclassified):
            observer(device(**{'cat /proc/957/stat': [stat, later]}))[0].clock()
        with self.assertRaises(o.Unclassified):
            observer(device(**{o.FRAMEWORK_PID: (0, '957 958\n', '')}))[0].clock()


class RefusalTests(unittest.TestCase):
    READERS = ('boot', 'checkpoint', 'factory', 'active', 'sessions')

    def test_unknown_output_gives_no_fact(self):
        unknown = {o.FINGERPRINT: (0, 'garbage\n', ''), o.BOOT_COMPLETED: (0, 'yes\n', ''),
                   o.NEEDS_CHECKPOINT: (0, 'x', ''), o.FACTORY_DIGEST: (0, 'x\n', ''),
                   o.FACTORY_VERSION: (0, 'package:com.android.systemui\n', ''), o.ACTIVE_PATH: (0, 'package:/tmp/x\n', ''),
                   o.ACTIVE_VERSION: (0, '', ''), o.SYSTEMUI_PID: (0, '1839\n1840\n', ''),
                   o.LISTING: (1, reply('listing-failed-signer')[1][:-2], ''),
                   o.INSTALLS: (0, reply('installs-finalized-failed')[1][:-1], ''),
                   o.UPTIME: (0, '5432.1 1.0\n', ''), o.BOOT_ID: (0, BOOT + '\n', '')}
        for command, value in unknown.items():
            for reader in self.READERS:
                observe, shell = observer(device(**{command: value}))
                try:
                    result = getattr(observe, reader)()
                except o.Unclassified:
                    continue
                self.assertNotIn(command, shell.commands, (command, reader, result))

    def test_a_boot_between_the_reads_gives_no_fact(self):
        later = (0, '2b1e0f9c-5d4a-4c3b-9a8f-7e6d5c4b3a29\n', '')
        for reader in self.READERS:
            with self.subTest(reader=reader), self.assertRaises(o.Unclassified):
                observe, _ = observer(device(**{o.BOOT_ID: [reply('boot-id'), later]}))
                getattr(observe, reader)()

    def test_a_framework_restart_between_the_reads_gives_no_fact(self):
        stat = reply('framework-stat')
        restarted = (0, stat[1].replace(' 14229 ', ' 99999 '), '')
        self.assertNotEqual(restarted, stat)
        with self.assertRaises(o.Unclassified):
            observer(device(**{'cat /proc/957/stat': [stat, restarted]}))[0].sessions()
        moved = device(**{o.FRAMEWORK_PID: [reply('framework-pid'), (0, '958\n', '')],
                          'cat /proc/958/stat': (0, stat[1].replace('957 (', '958 (', 1), '')})
        with self.assertRaises(o.Unclassified):
            observer(moved)[0].sessions()

    def test_active_package_change_gives_no_fact(self):
        with self.assertRaises(o.Unclassified):
            observer(device(**{o.ACTIVE_PATH: [reply('path-factory'), reply('path-data')]}))[0].active()


WRITES = (
    'pm install-create --user 0 -r --pkg com.android.systemui --staged', 'pm install-write 1 base.apk /x',
    'pm install-commit 1', 'pm install-abandon 1', 'pm uninstall com.android.systemui', 'reboot',
    'setprop sys.powerctl reboot', 'vdc checkpoint commitChanges', 'vdc checkpoint startCheckpoint 2',
    'vdc checkpoint abortChanges x 0', 'vdc checkpoint markBootAttempt', 'settings put global x 1',
    'rm -rf /data/app-staging', 'cmd package compile -f com.android.systemui', 'am force-stop com.android.systemui',
    'sha256sum /system_ext/priv-app/SystemUI/SystemUI.apk; reboot', 'cat /proc/1/stat > /data/x',
    "sha256sum '/data/app/~~EqvwNErLUKwVeZB_S0CLiA==/com.android.systemui-ilHNckf09AGTZ3jNQm-LEQ==/base.apk'; reboot",
    'pm list staged-sessions && reboot', 'dumpsys -t 25 package installs | sh', 'cat /proc/$(pidof x)/stat',
    'pm list staged-sessions\nreboot', 'getprop ro.build.fingerprint `reboot`')
WRITE_TOKENS = {'install', 'uninstall', 'abandon', 'commit', 'reboot', 'setprop', 'settings', 'put', 'rm', 'mv',
                'write', 'start', 'stop', 'kill', 'clear', 'grant', 'revoke', 'commitChanges', 'abortChanges',
                'startCheckpoint', 'markBootAttempt', 'restoreCheckpoint', 'restoreCheckpointPart',
                'prepareCheckpoint', 'resetCheckpoint', 'compile', 'am', 'cmd', 'sh', 'su', 'dd', 'touch', 'mkdir'}
READ_VERBS = ('cat /proc/', 'pidof ', 'pm list ', 'pm path ', 'dumpsys ', 'getprop ', 'sha256sum ',
              'vdc checkpoint supportsCheckpoint', 'vdc checkpoint needsCheckpoint')


class UserAndHealthTests(unittest.TestCase):
    def two(self, **changes):
        return device(**{o.SYSTEMUI_PID: reply('systemui-pids-two'), **changes})

    def test_users_by_serial(self):
        observe, shell = observer(device())
        facts = observe.users()
        self.assertEqual([(f['kind'], f['classification'], f['user'], f['serial'], f['component']) for f in facts],
                         [('USER', 'RUNNING_UNLOCKED', 0, 0, ''), ('USER', 'RUNNING_UNLOCKED', 10, 12, '')])
        self.assertEqual(shell.commands, [o.BOOT_ID, o.UPTIME, o.FRAMEWORK_PID, 'cat /proc/957/stat', o.USERS,
                                          o.FRAMEWORK_PID, 'cat /proc/957/stat', o.BOOT_ID])
        for fact in facts:
            decode_frame(o.encode(fact))
        gone = observer(device())[0].users(previous=[(0, 0), (11, 14)])
        self.assertEqual([(f['classification'], f['user'], f['serial']) for f in gone][2:], [('REMOVED', 11, 14)])
        for state, classification in (('RUNNING_LOCKED', 'RUNNING_LOCKED'), ('RUNNING_UNLOCKING', 'RUNNING_LOCKED'),
                                      ('BOOTING', 'RUNNING_LOCKED'), ('STOPPING', 'NOT_RUNNING'),
                                      ('SHUTDOWN', 'NOT_RUNNING'), ('-1', 'NOT_RUNNING')):
            with self.subTest(state=state):
                fact = observer(device(**{o.USERS: listed(state)}))[0].users()[1]
                self.assertEqual(fact['classification'], classification)
        removing = observer(device(**{o.USERS: listed(marker=' <removing> ')}))[0].users()[1]
        self.assertEqual(removing['classification'], 'REMOVED')

    def test_a_partial_listing_gives_no_user_at_all(self):
        text = reply('users-two')[1]
        for cut in (text[:text.index('\nDevice properties:')], text.replace('    State: RUNNING_UNLOCKED\n', '', 1),
                    text.replace('serialNo=12 ', 'serialNo=0 '),
                    text.replace('    State: RUNNING_UNLOCKED', '    State: ?', 1),
                    listed('RUNNING')[1]):
            with self.subTest(text=cut[-40:]), self.assertRaises(o.Unclassified):
                observer(device(**{o.USERS: (0, cut, '')}))[0].users()
        with self.assertRaises(o.Unclassified):
            observer(device(**{o.USERS: (255, '', 'Can\'t find service: user\n')}))[0].users()

    def test_one_systemui_process_for_each_user(self):
        observe, shell = observer(self.two())
        active = observe.active()
        self.assertEqual(active['facts']['context'], 'u:r:platform_app:s0:c512,c768')
        self.assertIn('cat /proc/4721/status', shell.commands)
        self.assertIn('cat /proc/4721/attr/current', shell.commands)
        # The system user's process must carry the package's UID, and each user runs one process.
        for changes in ({o.SYSTEMUI_PID: (0, '4721\n', '')}, {'cat /proc/4721/status': reply('systemui-status-1839')},
                        {'cat /proc/1839/status': (0, reply('systemui-status-1839')[1].replace('10112', '10113'), '')}):
            with self.subTest(changes=list(changes)), self.assertRaises(o.Unclassified):
                observer(self.two(**changes))[0].active()
        double = self.two(**{'cat /proc/4721/status': (0, reply('systemui-status-4721')[1].replace('1010112', '10112')
                                                       .replace('Pid:\t10112', 'Pid:\t4721'), '')})
        with self.assertRaises(o.Unclassified):
            observer(double)[0].active()

    def probe(self, changes=None, baseline=None, domain=DOMAIN, apk=FACTORY_APK):
        """One health probe on the two user guest: [(user, classification, criteria)] and the baseline."""
        facts, following = observer(self.two(**(changes or {})))[0].health(domain, apk, baseline)
        return [(f['user'], f['classification'], f['facts']['count']) for f in facts], following

    def baseline(self):
        return self.probe()[1]

    def test_health_for_each_user(self):
        instance = observer(self.two())[0].clock()[1]
        first, baseline = self.probe()
        self.assertEqual(baseline, {(BOOT, instance, 0, 0): 1839, (BOOT, instance, 10, 12): 4721})
        facts, _ = observer(self.two())[0].health(DOMAIN, FACTORY_APK, baseline)
        self.assertEqual([(f['kind'], f['classification'], f['user'], f['serial'], f['component'], f['facts'])
                          for f in facts],
                         [('HEALTH', 'HELD', 0, 0, o.PACKAGE, {'count': 0x13}),
                          ('HEALTH', 'HELD', 10, 12, o.PACKAGE, {'count': 0x13})])
        for fact in facts:
            decode_frame(o.encode(fact))
        # The system user's SystemUI is persistent: its process ending is a crash.
        restarted = {(BOOT, instance, 0, 0): 1700, (BOOT, instance, 10, 12): 4721}
        self.assertEqual(self.probe(baseline=restarted)[0], [(0, 'CRASH', 0x13), (10, 'HELD', 0x13)])
        # A baseline of another boot or framework instance is no evidence: it starts a new one.
        for other in ((BOOT[::-1], instance), (BOOT, instance + 1)):
            stale = {other + (0, 0): 1700, other + (10, 12): 4700}
            facts, following = self.probe(baseline=stale)
            self.assertEqual((facts, following), ([], baseline))
        self.assertEqual(self.probe(domain='system_app')[0], [(0, 'DEGRADED', 0x11), (10, 'DEGRADED', 0x11)])
        self.assertEqual(self.probe(apk=DATA_APK)[0], [(0, 'DEGRADED', 0x11), (10, 'DEGRADED', 0x11)])
        status = reply('systemui-status-4721')[1].replace('1010112', '1010113')
        other_app = {'cat /proc/4721/status': (0, status, '')}
        self.assertEqual(self.probe(other_app, baseline)[0], [(0, 'HELD', 0x13), (10, 'DEGRADED', 0x13)])
        # No SystemUI process at all, read quietly twice, is observed: a miss for every user.
        none = {o.SYSTEMUI_PID: (1, '', '')}
        self.assertEqual(self.probe(none)[0], [(0, 'DEGRADED', 0x11), (10, 'INCONCLUSIVE', 0x11)])
        self.assertEqual(self.probe(none, baseline)[0], [(0, 'CRASH', 0x13), (10, 'INCONCLUSIVE', 0x13)])
        with self.assertRaises(o.Unclassified):
            observer(self.two(**none))[0].active()
        # Only running, unlocked users that Android is not removing get a probe.
        for state, marker in (('RUNNING_LOCKED', ''), ('RUNNING_UNLOCKING', ''), ('RUNNING_UNLOCKED', ' <removing> ')):
            with self.subTest(state=state, marker=marker):
                facts, _ = self.probe({o.USERS: listed(state, marker)}, baseline)
                self.assertEqual([user for user, _, _ in facts], [0])

    def test_an_unavailable_process_read_is_never_a_crash(self):
        baseline = self.baseline()
        quiet = (1, '', '')
        for value in ((1, '', '/proc: Permission denied\n'), (1, '', 'error: device offline\n'),
                      [quiet, (0, '1839 4721\n', '')], [quiet, (1, '', 'error: device offline\n')],
                      [quiet, (0, '1839\n', '')]):
            with self.subTest(value=value), self.assertRaises(o.Unclassified):
                observer(self.two(**{o.SYSTEMUI_PID: value}))[0].health(DOMAIN, FACTORY_APK, baseline)
        observe, shell = observer(self.two(**{o.SYSTEMUI_PID: quiet}))
        facts, _ = observe.health(DOMAIN, FACTORY_APK, baseline)
        self.assertEqual([(f['user'], f['classification']) for f in facts], [(0, 'CRASH'), (10, 'INCONCLUSIVE')])
        self.assertEqual(shell.commands.count(o.SYSTEMUI_PID), 2)

    def test_a_probe_without_a_baseline_holds_nothing(self):
        # A HELD fact without the crash criterion would read as partial criteria for the whole window,
        # so the first probe only sets the baseline. A miss it sees is still reported.
        facts, baseline = self.probe()
        self.assertEqual((facts, sorted(user for _, _, user, _ in baseline)), ([], [0, 10]))
        self.assertEqual(self.probe(baseline=baseline)[0], [(0, 'HELD', 0x13), (10, 'HELD', 0x13)])
        self.assertEqual(self.probe(domain='system_app')[0], [(0, 'DEGRADED', 0x11), (10, 'DEGRADED', 0x11)])
        self.assertEqual(self.probe({o.SYSTEMUI_PID: reply('systemui-pid')})[0], [(10, 'INCONCLUSIVE', 0x11)])

    def test_another_users_systemui_ending_is_inconclusive(self):
        # ProcessList marks SystemUI persistent only for the system user, so another user's SystemUI
        # may be ended to free memory. Its ending or absence cannot show a crash.
        instance = observer(self.two())[0].clock()[1]
        baseline = self.baseline()
        moved = {(BOOT, instance, 0, 0): 1839, (BOOT, instance, 10, 12): 4700}
        self.assertEqual(self.probe(baseline=moved)[0], [(0, 'HELD', 0x13), (10, 'INCONCLUSIVE', 0x13)])
        only_system = {o.SYSTEMUI_PID: reply('systemui-pid')}
        self.assertEqual(self.probe(only_system, baseline)[0], [(0, 'HELD', 0x13), (10, 'INCONCLUSIVE', 0x13)])
        only_ten = {o.SYSTEMUI_PID: (0, '4721\n', '')}
        self.assertEqual(self.probe(only_ten)[0], [(0, 'DEGRADED', 0x11)])
        self.assertEqual(self.probe(only_ten, baseline)[0], [(0, 'CRASH', 0x13), (10, 'HELD', 0x13)])


class AllowlistTests(unittest.TestCase):
    def test_every_command_the_observer_ran_is_allowed(self):
        commands = set()
        for changes in ({}, {o.ACTIVE_PATH: reply('path-data')}):
            observe, shell = observer(device(**changes))
            for reader in RefusalTests.READERS:
                getattr(observe, reader)()
            commands |= set(shell.commands)
        self.assertTrue(all(o.allowed(c) for c in commands))
        self.assertGreaterEqual(len(commands), len(o.ALLOWED))

    def test_write_commands_are_refused_before_the_shell(self):
        for command in WRITES:
            with self.subTest(command=command):
                self.assertFalse(o.allowed(command))
                observe, shell = observer({})
                with self.assertRaises(o.Unclassified):
                    observe.read(command)
                self.assertEqual(shell.commands, [])

    def test_source_rule(self):
        """Every allowed form is a read, and the shell is reached only through the allowlist."""
        tree = ast.parse(SOURCE.read_text())
        strings = {n.targets[0].id for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                   and isinstance(n.value, (ast.Constant, ast.BinOp))}
        assigned = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'ALLOWED' for t in n.targets)]
        self.assertEqual(len(assigned), 1)
        self.assertIsInstance(assigned[0].value, ast.Tuple)
        for element in assigned[0].value.elts:
            self.assertTrue(isinstance(element, ast.Constant) or (isinstance(element, ast.Name) and element.id in strings),
                            ast.unparse(element))
        literals = list(o.ALLOWED)
        self.assertEqual(len(literals), len(assigned[0].value.elts))
        patterns = [p.pattern for p in o.ALLOWED_PATTERNS]
        for form in literals + patterns:
            with self.subTest(form=form):
                self.assertTrue(form.startswith(READ_VERBS), form)
                tokens = set(form.split(' '))
                self.assertFalse(tokens & WRITE_TOKENS or any(t.startswith(('install-', '--install')) for t in tokens), form)
        for literal in literals:
            self.assertFalse(any(char in literal for char in ";&|><`$\n'\"\\(){}*?"), literal)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and node.func.attr == '_run']
        self.assertEqual(len(calls), 1)
        read = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'read')
        self.assertIn(calls[0], list(ast.walk(read)))
        # Every use of _run is the constructor's assignment or that one call: never bound to another
        # name, passed on, or called anywhere else.
        init = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        uses = [node for node in ast.walk(tree) if (isinstance(node, ast.Attribute) and node.attr == '_run')
                or (isinstance(node, ast.Name) and node.id == '_run')]
        stores = [node for node in uses if isinstance(node.ctx, ast.Store)]
        self.assertEqual(len(stores), 1)
        self.assertEqual(ast.unparse(stores[0]), 'self._run')
        self.assertIn(stores[0], list(ast.walk(init)))
        others = [node for node in uses if node is not stores[0] and node is not calls[0].func]
        self.assertEqual(others, [], [ast.unparse(node) for node in others])
        # The constructor's run parameter appears exactly once, as the value assigned to self._run:
        # never stored a second time, wrapped in a lambda or passed on.
        loads = [node for node in ast.walk(init) if isinstance(node, ast.Name) and node.id == 'run']
        self.assertEqual(len(loads), 1, [ast.unparse(node) for node in loads])
        assignment = next(n for n in ast.walk(init) if isinstance(n, ast.Assign) and stores[0] in n.targets)
        self.assertIs(assignment.value, loads[0])
        guard = read.body[0]
        self.assertIsInstance(guard, ast.If)
        self.assertEqual(ast.unparse(guard.test), 'not allowed(command)')
        self.assertIsInstance(guard.body[0], ast.Raise)
        # Every import at any depth, of the observer and of its parser module, as what it imports and
        # the name it binds: exactly these.
        parser = ast.parse(Path(s.__file__).read_text())
        self.assertEqual(imports(tree), sorted([('dataclasses.dataclass', 'dataclass'), ('hashlib', 'hashlib'),
                                                ('re', 're'), ('secrets', 'secrets'), ('time', 'time'),
                                                ('scripts.proof.component_transaction_records', 'encoder'),
                                                ('scripts.proof.systemui_sessions', 'readback')]))
        self.assertEqual(imports(parser), [('dataclasses.dataclass', 'dataclass'), ('re', 're')])
        # Nothing reaches a process through another module: each imported module's name appears only
        # where one of the attributes listed here is used, never as a value of its own, and nothing
        # looks names up dynamically.
        parsers = {n.name for n in parser.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        reach = {'hashlib': {'sha256'}, 're': {'compile'}, 'secrets': {'token_hex'}, 'time': {'time_ns'},
                 'encoder': {'observation', 'NO_USER', 'NO_SERIAL', 'ZERO_ID'},
                 'readback': parsers | {'PACKAGE', 'FACTORY_PATH', 'DATA_PATH', 'Cohort'}}
        values = attribute_values(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in reach:
                self.assertIn(node.attr, reach[node.value.id], ast.unparse(node))
            if isinstance(node, ast.Name) and node.id in reach:
                self.assertIn(id(node), values, 'a module as a value: ' + node.id)
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id, {'getattr', '__import__', 'eval', 'exec', 'globals', 'vars', 'open',
                                           'compile', '__builtins__', 'importlib', 'sys'}, ast.unparse(node))
            if isinstance(node, ast.Attribute):
                self.assertFalse(node.attr.startswith('__') or node.attr in {'subprocess', 'system', 'popen', 'Popen',
                                                                           'spawn', 'fork', 'execv'},
                                 ast.unparse(node))
        # The parser module's re is likewise only ever the value of an attribute.
        parser_values = attribute_values(parser)
        for node in ast.walk(parser):
            if isinstance(node, ast.Name) and node.id == 're':
                self.assertIn(id(node), parser_values, 'a module as a value in the parser: re')


def imports(tree):
    """Every import of a module at any depth, as (what it imports, the name it binds), sorted."""
    found = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            found += [(alias.name, alias.asname or alias.name) for alias in n.names]
        elif isinstance(n, ast.ImportFrom):
            found += [('.' * n.level + (n.module or '') + '.' + alias.name, alias.asname or alias.name)
                      for alias in n.names]
    return sorted(found)


def attribute_values(tree):
    """The IDs of the Name nodes that are the value of an attribute."""
    return {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}


class EncodingTests(unittest.TestCase):
    def test_each_kind_encodes_through_the_independent_encoder(self):
        observe, _ = observer(device(**{o.ACTIVE_PATH: reply('path-data')}))
        kinds = {}
        for fact in [observe.boot(), observe.checkpoint(), observe.factory(), observe.active()] + observe.sessions():
            data = decode_frame(o.encode(fact))
            self.assertEqual(data, encoder.observation(fact))
            kinds[fact['kind']] = data
        for fact in observe.users() + observe.health(DOMAIN, FACTORY_APK)[0]:
            data = decode_frame(o.encode(fact))
            self.assertEqual(data, encoder.observation(fact))
            kinds[fact['kind']] = data
        self.assertEqual(sorted(kinds), ['ACTIVE', 'BOOT', 'CHECKPOINT', 'FACTORY', 'HEALTH', 'LISTING', 'SESSION',
                                         'USER'])


if __name__ == '__main__':
    unittest.main()
