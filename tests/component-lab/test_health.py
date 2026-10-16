# SPDX-License-Identifier: Apache-2.0
"""The health package of the next campaign profile: the side metadata codec, the health and
identity baselines, the composer with its readers of bits 0, 2 and 3, the UI state helper's form,
and the typed actions USER_PIN and CE_SENTINEL, on a simulated guest. Each changed copy must fail
for its own reason while its honest original passes. Host evidence only: the simulated guest's
forms are source derived or test fakes, not Android forms."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest

import full_users
import health_baseline
import health_compose
import health_records
import lab_actions
import lab_broker
import lab_evidence
import lab_protocol as proto
import lab_readers
import labtest
from labtest import PLAN, TICKET, Harness, read_observation
import shell_transport
import sim_android
import sim_users
from scripts.proof import component_transaction_records as encoder

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
# The repository's own sources, also from a copy of this directory whose `scripts` links to them.
SOURCES = (REPO / 'scripts').resolve().parent
HEALTH = proto.MODES['COMPOSED_HEALTH']
USER, SERIAL = 13, 41
# The plan's pinned variant, as the harness pins it, which the composer expects to draw WS-A.
APK = hashlib.sha256(b'A' * 4096 + b'variant').hexdigest()
CREATED = {'kind': 'CREATED_BY', 'action': labtest.CREATE_ACTION}
PREPARE_CREATED = '2f' * 16
CAPS = health_compose.UI_STATE_CAPABILITIES
HEADER = health_compose.UI_STATE_HEADER
CLASSES = {v: k for k, v in proto.HEALTH_CLASSIFICATIONS.items()}
SETUP = (labtest.CREATE_ACTION, labtest.START_ACTION, labtest.SWITCH_ACTION, labtest.SETUP_ACTION,
         labtest.FIXTURE_ACTION)


def specs():
    """The health package's specs, and a preparation of the created user's bits 2 and 3."""
    return labtest.health_specs() + [labtest.action_spec(
        PREPARE_CREATED, 'HEALTH_PREPARATION', phase='A', cell='a-window-created', user_selector=CREATED,
        parameters={'criteria': [2, 3, 5], 'max_probe_ms': 120_000})]


def ui_reply(user=USER, missing=None, code=None, end=True, status=None, header=HEADER, caps=CAPS, stderr='',
             **values):
    """One whole UI state helper reply, in the form tests/ui-state-read prints."""
    answers = {'interactive': True, 'keyguard_locked': False, 'keyguard_secure': True, 'device_locked': False,
               'device_secure': True, 'ce_unlocked': True}
    answers.update(values)
    missing = missing or {}
    lines = [header, 'user=%d' % user, 'capabilities=' + ','.join(caps)]
    for name in CAPS:
        lines.append('%s=%s' % (name, 'unavailable:' + missing[name] if name in missing
                                else 'true' if answers[name] else 'false'))
    lines.append('status=' + (status or ('unavailable' if missing else 'complete')))
    if end:
        lines.append('end=' + HEADER)
    return ((5 if missing else 0) if code is None else code), '\n'.join(lines) + '\n', stderr


def condition(user=USER, current=USER, state=None, **values):
    """One capture or unlock condition as a preparation records it."""
    answers = {'interactive': True, 'keyguard_locked': False, 'keyguard_secure': True, 'device_locked': False,
               'device_secure': True, 'ce_unlocked': True}
    answers.update(values)
    missing = {k: 'java.lang.SecurityException' for k, v in answers.items() if v is None}
    value = {'current_user': current, 'ui_state': {'user': user, 'values': answers, 'unavailable': missing,
                                                   'complete': not missing}}
    if state is not None:
        value['state'] = state
    return value


def locked(**values):
    return condition(state='RUNNING_LOCKED', **dict({'keyguard_locked': True, 'device_locked': True,
                                                    'ce_unlocked': False}, **values))


def unlocked(**values):
    return condition(state='RUNNING_UNLOCKED', **values)


class HeldHook:
    """A later part's reader as a test fake: it judges one read the composer admits and holds.
    It stands in for the witness, active bytes, native work and recovery readers, never for
    evidence of them."""

    def __init__(self, bit):
        self.bit = bit

    def allowed(self, command):
        return command == health_compose.SHELL_IDENTITY

    def read(self, calls, context):
        at = calls.count
        calls.run(health_compose.SHELL_IDENTITY)
        baseline = context['baseline']['digest'] if self.bit == 1 and context['baseline'] else None
        # Native work is a prepared criterion: its row names the fresh preparation it relies on.
        offers = [p['operation'] for p in context.get('preparations', ()) if self.bit in p['criteria']]
        prepared = offers[-1] if offers and self.bit == health_compose.NATIVE_WORK else None
        value = health_compose.row(self.bit, 'HELD', '', [at], preparation=prepared, baseline=baseline)
        return (value, None) if self.bit == health_compose.NO_CRASH_OR_ANR else value


class WitnessParts:
    """The witness reader's baseline parts as a test fake, so a baseline can be complete."""

    def allowed(self, command):
        return False

    def baseline(self, run, context):
        part = {'status': 'OK', 'schema': 'andrix-test-witness-v1', 'reading': {'rows': []}}
        return part, dict(part)


class ConstantTests(unittest.TestCase):
    def test_the_declared_starting_values_are_the_drivers(self):
        # The composer keeps the design's starting values exactly as the driver declares them,
        # and the criteria and window parts as the deployment records and the judge define them.
        driver = (HERE / 'driver/dev/andrix/lab/component/LabDriverMain.java').read_text()
        constants = dict(re.findall(r'(HEALTH_WINDOW|NOTICE_DELAY|REBOOT_TIME|ACTIVATE_WINDOW|VERIFICATION_WAIT) = '
                                    r'([0-9_ *]+)L', driver))
        # Each declared value is a product of integer literals, such as 15 * 60_000L.
        value = {name: math.prod(int(factor.replace('_', '')) for factor in text.split('*'))
                 for name, text in constants.items()}
        self.assertEqual(value, {'HEALTH_WINDOW': health_compose.HEALTH_WINDOW_MS,
                                 'NOTICE_DELAY': health_compose.NOTICE_DELAY_MS,
                                 'REBOOT_TIME': health_compose.REBOOT_TIMEOUT_MS,
                                 'ACTIVATE_WINDOW': health_compose.ACTIVATE_WINDOW_MS,
                                 'VERIFICATION_WAIT': health_compose.VERIFICATION_WAIT_MS})
        self.assertIn('static final int REQUEST_LIMIT = %d;' % health_compose.REQUEST_LIMIT, driver)
        self.assertIn('.notice(NOTICE_DELAY, NOTICE_DELAY)', driver)
        deployment = SOURCES / 'owner/deployment/java/dev/andrix/server/deployment'
        reconciler = (deployment / 'Reconciler.java').read_text()
        self.assertIn('static final int WINDOW_PARTS = %d;' % health_compose.WINDOW_PARTS, reconciler)
        self.assertEqual(health_compose.MAX_GAP_MS, 225_000)
        records = (deployment / 'DeploymentRecords.java').read_text()
        self.assertIn('UID_AND_CONTEXT(0), NO_CRASH_OR_ANR(1), UI_MARKER(2), UNLOCK_AND_CE(3), BYTES_UNCHANGED(4),', records)
        self.assertIn('NATIVE_WORK(5), RECOVERY_ROUTE(6);', records)
        self.assertIn('public static final int ALL = 0x7f;', records)
        self.assertEqual((health_compose.CRITERIA_ALL, proto.CRITERIA_ALL), (127, 127))

    def test_every_composition_declares_all_seven_criteria_and_readers_emit_no_fact(self):
        composer = health_compose.Composer({APK: 'WS-A'})
        calls = []

        def run(command):
            calls.append(command)
            raise lab_readers.Unavailable('no guest')
        found = composer.compose(run, {'user': USER, 'serial': SERIAL})
        self.assertEqual(set(found), {'user', 'serial', 'rows', 'witness'})
        self.assertEqual([r['bit'] for r in found['rows']], list(range(7)))
        self.assertEqual({r['status'] for r in found['rows']}, {'UNKNOWN'})
        self.assertIsNone(found['witness'])
        for bit in (1, 4, 5, 6):
            self.assertEqual(found['rows'][bit]['reason'], health_compose.HOOKS[bit])
        # A criterion reader gives one row, never a HEALTH fact of its own.
        for value in found['rows']:
            self.assertEqual(set(value), set(health_compose.ROW_KEYS))
        self.assertEqual(proto.health_classification(proto.ROW_STATUSES[r['status']] for r in found['rows']),
                         proto.HEALTH_CLASSIFICATIONS['INCONCLUSIVE'])


class UiStateFormTests(unittest.TestCase):
    def test_a_whole_reply_parses_and_an_unavailable_answer_is_never_false(self):
        reading = health_compose.parse_ui_state(*ui_reply(), USER)
        self.assertEqual(reading['values'], {'interactive': True, 'keyguard_locked': False, 'keyguard_secure': True,
                                             'device_locked': False, 'device_secure': True, 'ce_unlocked': True})
        self.assertTrue(reading['complete'])
        for name in CAPS:
            with self.subTest(name):
                reading = health_compose.parse_ui_state(*ui_reply(missing={name: 'java.lang.SecurityException'}),
                                                        USER)
                self.assertIsNone(reading['values'][name])
                self.assertIsNot(reading['values'][name], False)
                self.assertEqual(reading['unavailable'], {name: 'java.lang.SecurityException'})
                self.assertFalse(reading['complete'])
                self.assertIsNone(health_records.ui_state_problem(reading, USER))
        reading = health_compose.parse_ui_state(*ui_reply(missing={'device_locked': 'service-absent',
                                                                   'ce_unlocked': 'android.os.RemoteException'}), USER)
        self.assertEqual(reading['unavailable'], {'device_locked': 'service-absent',
                                                  'ce_unlocked': 'android.os.RemoteException'})

    def test_a_contrary_reply_has_no_known_form(self):
        cases = {'another user': ui_reply(user=0), 'another version': ui_reply(header='andrix-ui-state-read-v2'),
                 'another build': ui_reply(caps=CAPS[:-1]), 'no end marker': ui_reply(end=False),
                 'a status that does not follow': ui_reply(status='complete', missing={'ce_unlocked': 'x.Y'}),
                 'an exit that does not follow': ui_reply(code=5),
                 'standard error': ui_reply(stderr='WARNING: linker\n'),
                 'an unavailable reason of no known form': ui_reply(missing={'ce_unlocked': 'not a class'}),
                 'an argument refusal': (2, '%s\nerror=arguments\nend=%s\n' % (HEADER, HEADER), ''),
                 'another end marker': (0, ui_reply()[1].replace('end=' + HEADER, 'end=andrix-other'), '')}
        for name, reply in cases.items():
            with self.subTest(name), self.assertRaises(lab_readers.Unclassified):
                health_compose.parse_ui_state(*reply, USER)
        code, stdout, stderr = ui_reply()
        for at in range(len(stdout)):
            with self.assertRaises(lab_readers.Unclassified, msg='cut at %d' % at):
                health_compose.parse_ui_state(code, stdout[:at], stderr, USER)
        changed = stdout.replace('interactive=true', 'interactive=TRUE')
        with self.assertRaises(lab_readers.Unclassified):
            health_compose.parse_ui_state(code, changed, stderr, USER)
        swapped = stdout.replace('interactive=true\nkeyguard_locked=false', 'keyguard_locked=false\ninteractive=true')
        with self.assertRaises(lab_readers.Unclassified):
            health_compose.parse_ui_state(code, swapped, stderr, USER)

    def test_the_helper_runs_only_between_reads_of_the_shell_user_and_its_pinned_bytes(self):
        sim = sim_android.SimAndroid()
        sim.enable_user_forms()

        def run_on(guest):
            seen = []

            def run(command):
                seen.append(command)
                done = guest.shell(command, 30, 1 << 20, 1 << 16)
                return sim_android.streams(done)
            return run, seen
        run, seen = run_on(sim)
        reading = health_compose.read_ui_state(run, 0)
        self.assertTrue(reading['complete'])
        self.assertEqual(seen, ['id', health_compose.HELPER_DIGEST, health_compose.ui_state_command(0), 'id',
                                health_compose.HELPER_DIGEST])
        for name in ('another digest', 'no helper', 'another shell user'):
            with self.subTest(name):
                other = sim_android.SimAndroid()
                other.enable_user_forms()
                if name == 'another digest':
                    other.ui_helper = 'ab' * 32
                elif name == 'no helper':
                    other.ui_helper = False
                else:
                    other.scripts['id'] = [lambda c: sim_android.result(c, 0, b'uid=0(root) gid=0(root) groups=0(root) '
                                                                              b'context=u:r:su:s0\n')]
                run, seen = run_on(other)
                with self.assertRaises((lab_readers.Unclassified, ValueError)):
                    health_compose.read_ui_state(run, 0)
                self.assertNotIn(health_compose.ui_state_command(0), seen)
        # Changed after the helper ran: refused, though the helper's own reply was whole.
        sim = sim_android.SimAndroid()
        sim.enable_user_forms()
        sim.hooks.append(lambda c: setattr(sim, 'ui_helper', 'cd' * 32) if 'UiStateRead' in c else None)
        run, seen = run_on(sim)
        with self.assertRaises(lab_readers.Unclassified):
            health_compose.read_ui_state(run, 0)

    def test_only_one_bounded_invocation_is_admitted(self):
        self.assertTrue(health_compose.read_allowed(health_compose.ui_state_command(21473)))
        for command in ('CLASSPATH=%s app_process /system/bin UiStateRead 21474' % health_compose.UI_STATE_HELPER,
                        'CLASSPATH=%s app_process /system/bin UiStateRead 010' % health_compose.UI_STATE_HELPER,
                        'CLASSPATH=%s app_process /system/bin UiStateRead -1' % health_compose.UI_STATE_HELPER,
                        'CLASSPATH=%s app_process /system/bin UiStateRead 0 1' % health_compose.UI_STATE_HELPER,
                        'CLASSPATH=%s app_process /system/bin CheckpointRead' % health_compose.UI_STATE_HELPER,
                        'CLASSPATH=/data/local/tmp/other.jar app_process /system/bin UiStateRead 0',
                        'cat /data/local/tmp/andrix-d5/health/hierarchy-../x.xml', 'cat /data/local/tmp/window_dump.xml',
                        'sha256sum /data/local/tmp/andrix-d5/other.jar', 'locksettings set-pin 123456'):
            with self.subTest(command):
                self.assertFalse(health_compose.read_allowed(command))
        for bad in (-1, 21474, True, '0'):
            with self.assertRaises(ValueError):
                health_compose.ui_state_command(bad)


def capture_part(path, **changes):
    value = {'path': path, 'acknowledged': True, 'before': condition(), 'after': condition()}
    value.update(changes)
    return value


class MarkerTests(unittest.TestCase):
    """Bit 2's reader over fresh hierarchies of the simulated guest's form."""

    def setUp(self):
        self.sim = sim_android.SimAndroid()

    def dump(self, change=None, marker=False, notice=False):
        self.sim.marker_apks = {self.sim.active[1]} if marker else set()
        self.sim.hierarchy_change = change
        self.sim.shown = {0: {'challenge': 'ab' * 16, 'ticket': TICKET, 'index': 2}} if notice else {}
        return health_compose.parse_hierarchy(0, self.sim.hierarchy(), '')

    def judge(self, root, expectation, capture=None):
        capture = capture_part(health_compose.hierarchy_path('ee' * 16)) if capture is None else capture
        return health_compose.ui_marker_row(capture, root, USER, expectation, sim_android.NOTICE_PACKAGE, [4], 'ee' * 16)

    def test_the_clock_node_shows_the_expected_marker_or_the_original_time(self):
        self.assertEqual(self.judge(self.dump(marker=True), 'WS-A')['status'], 'HELD')
        self.assertEqual(self.judge(self.dump(marker=True), 'WS-A')['preparation'], 'ee' * 16)
        self.assertEqual(self.judge(self.dump(), 'ORIGINAL')['status'], 'HELD')
        self.assertEqual(self.judge(self.dump(), 'WS-A')['status'], 'BAD')
        self.assertEqual(self.judge(self.dump(marker=True), 'ORIGINAL')['status'], 'BAD')
        self.assertEqual(self.judge(self.dump(), None)['status'], 'UNKNOWN')
        for clock in (('10:42', '10:42 PM'), ('22:05', '22:05'), ('9:05', '9:05\u202fAM'), ('10:42:07', '10:42:07 PM')):
            self.sim.clock = clock
            self.assertEqual(self.judge(self.dump(), 'ORIGINAL')['status'], 'HELD', clock)
            self.assertEqual(self.judge(self.dump(marker=True), 'WS-A')['status'], 'HELD', clock)

    def test_a_marker_elsewhere_or_a_contrary_clock_does_not_qualify(self):
        def elsewhere(xml):
            return xml.replace('package="com.android.launcher3" content-desc=""',
                               'package="com.android.launcher3" content-desc="10:42 WS-A"')
        # A substring in another window never stands for the clock's own marker.
        self.assertEqual(self.judge(self.dump(elsewhere), 'WS-A')['status'], 'BAD')
        self.assertEqual(self.judge(self.dump(elsewhere), 'ORIGINAL')['status'], 'BAD')

        def text_only(xml):
            return xml.replace('content-desc="10:42 PM WS-A"', 'content-desc="10:42 PM"')
        self.assertEqual(self.judge(self.dump(text_only, marker=True), 'WS-A')['status'], 'BAD')

        def bad(xml):
            return xml.replace('text="10:42"', 'text="WS-B BAD"')
        self.assertEqual(self.judge(self.dump(bad), 'ORIGINAL')['status'], 'BAD')
        self.assertEqual(self.judge(self.dump(bad), 'WS-A')['status'], 'BAD')

        def unknown(xml):
            return xml.replace('text="10:42"', 'text="22h42"')
        self.assertEqual(self.judge(self.dump(unknown), 'ORIGINAL')['status'], 'UNKNOWN')

    def test_the_clock_must_be_one_visible_node_of_a_status_bar_window_with_no_notice_in_view(self):
        def two(xml):
            clock = re.search(r'<node index="0" text="10:42[^"]*".*?</node>', xml)[0]
            return xml.replace(clock, clock + clock)

        def other_window(xml):
            return xml.replace('type="TYPE_SYSTEM"', 'type="TYPE_APPLICATION"')

        def hidden(xml):
            return xml.replace('bounds="[42,0][150,63]"', 'bounds="[42,0][42,63]"')

        def other_display(xml):
            return xml.replace('<display id="0">', '<display id="2">')
        for name, change in (('two clocks', two), ('another window type', other_window), ('no visible bounds', hidden),
                             ('no default display', other_display)):
            with self.subTest(name):
                found = self.judge(self.dump(change, marker=True), 'WS-A')
                self.assertEqual((found['status'], found['preparation']), ('UNKNOWN', None))
        found = self.judge(self.dump(marker=True, notice=True), 'WS-A')
        self.assertEqual((found['status'], found['reason']), ('UNKNOWN', 'the notice fixture is in view'))

    def test_the_capture_conditions_must_hold_before_and_after_and_an_unavailable_answer_never_does(self):
        path = health_compose.hierarchy_path('ee' * 16)
        cases = {'not acknowledged': capture_part(path, acknowledged=False),
                 'another user in the foreground': capture_part(path, before=condition(current=0)),
                 'asleep': capture_part(path, after=condition(interactive=False)),
                 'keyguard showing': capture_part(path, before=condition(keyguard_locked=True)),
                 'device locked': capture_part(path, after=condition(device_locked=True)),
                 'no secure credential': capture_part(path, before=condition(device_secure=False)),
                 'awake unavailable': capture_part(path, before=condition(interactive=None)),
                 'lock unavailable': capture_part(path, after=condition(device_locked=None))}
        root = self.dump(marker=True)
        self.assertEqual(self.judge(root, 'WS-A', capture_part(path))['status'], 'HELD')
        for name, capture in cases.items():
            with self.subTest(name):
                self.assertEqual(self.judge(root, 'WS-A', capture)['status'], 'UNKNOWN')

    def test_a_hierarchy_of_no_known_form_or_not_read_whole_gives_nothing(self):
        xml = self.sim.hierarchy()
        for name, reply in {'a document type': (0, '<!DOCTYPE x>' + xml, ''), 'an entity': (0, xml.replace(
                '<displays>', '<!ENTITY a "b"><displays>'), ''), 'another root': (0, '<hierarchy rotation="0"/>', ''),
                'not XML': (0, xml[:-20], '')}.items():
            with self.subTest(name), self.assertRaises(lab_readers.Unclassified):
                health_compose.parse_hierarchy(*reply)
        for name, reply in {'missing': (1, '', 'cat: x: No such file or directory\n'), 'empty': (0, '', ''),
                            'above its bound': (0, 'x' * (health_compose.MAX_HIERARCHY + 1), '')}.items():
            with self.subTest(name), self.assertRaises(lab_readers.Unavailable):
                health_compose.parse_hierarchy(*reply)
        self.assertEqual(health_compose.ui_marker_row(capture_part(health_compose.hierarchy_path('ee' * 16)), None, USER,
                                                      'WS-A', None, [], 'ee' * 16)['status'], 'UNKNOWN')


class UnlockTests(unittest.TestCase):
    """Bit 3's reader."""

    def judge(self, unlock=None, now=None, state='RUNNING_UNLOCKED', read=None, origin=None, default=True):
        unlock = {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': unlocked()} if unlock is None and default \
            else unlock
        now = condition()['ui_state'] if now is None else now
        inventory = {'whole': True, 'current_user': USER, 'users': [
            {'id': USER, 'serial': SERIAL, 'type': lab_actions.SECONDARY_TYPE, 'state': state, 'flags': 0x10,
             'restrictions': [], 'parent': -10000, 'removing': False, 'partial': False, 'precreated': False}]}
        nonce = 'ab' * 16
        read = {'status': 'PRESENT', 'nonce': nonce} if read is None else read
        origin = {'nonce': nonce, 'record': 9} if origin is None else origin
        return health_compose.unlock_row(unlock, now, inventory, USER, SERIAL, read, origin or None, [1, 2], 'ee' * 16)

    def test_a_credential_unlock_from_a_genuine_lock_returns_ce_authority_and_its_nonce(self):
        found = self.judge()
        self.assertEqual((found['status'], found['preparation'], found['commands']), ('HELD', 'ee' * 16, [1, 2]))
        # A screen relock without CE withdrawal still demonstrates the credential unlock.
        relock = {'route': 'CREDENTIAL_UI', 'before': condition(state='RUNNING_UNLOCKED', keyguard_locked=True,
                                                                device_locked=True), 'after': unlocked()}
        self.assertEqual(self.judge(relock)['status'], 'HELD')

    def test_an_insecure_dismissal_or_no_genuine_lock_is_never_a_credential_unlock(self):
        cases = {'no secure credential': {'before': locked(device_secure=False, keyguard_secure=False)},
                 'keyguard not showing': {'before': locked(keyguard_locked=False)},
                 'device not locked': {'before': locked(device_locked=False)},
                 'another user in the foreground': {'before': locked(current=0)},
                 'a secure answer unavailable': {'before': locked(device_secure=None)},
                 'the lock answer unavailable': {'before': locked(device_locked=None)}}
        for name, change in cases.items():
            with self.subTest(name):
                unlock = dict({'route': 'CREDENTIAL_UI', 'before': locked(), 'after': unlocked()}, **change)
                found = self.judge(unlock)
                self.assertEqual(found['status'], 'UNKNOWN')
                self.assertIsNone(found['preparation'])
        self.assertEqual(self.judge(None, default=False)['status'], 'UNKNOWN')

    def test_an_unlock_that_leaves_the_user_or_ce_storage_locked_is_bad(self):
        stayed = {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': locked()}
        self.assertEqual(self.judge(stayed)['status'], 'BAD')
        still = {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': unlocked(keyguard_locked=True, device_locked=True)}
        self.assertEqual(self.judge(still)['status'], 'BAD')
        ce = {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': condition(state='RUNNING_LOCKED', ce_unlocked=False)}
        found = self.judge(ce)
        self.assertEqual((found['status'], found['preparation']), ('BAD', 'ee' * 16))
        # The framework and the listing disagreeing is doubt, and an unavailable answer too.
        split = {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': condition(state='RUNNING_LOCKED')}
        self.assertEqual(self.judge(split)['status'], 'UNKNOWN')
        missing = {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': unlocked(ce_unlocked=None)}
        self.assertEqual(self.judge(missing)['status'], 'UNKNOWN')

    def test_the_current_ce_state_and_the_nonce_decide_and_an_exception_is_never_false(self):
        self.assertEqual(self.judge(now=condition(ce_unlocked=None)['ui_state'])['status'], 'UNKNOWN')
        self.assertEqual(self.judge(now=condition(ce_unlocked=False)['ui_state'])['status'], 'UNKNOWN')
        self.assertEqual(self.judge(state='RUNNING_LOCKED')['status'], 'UNKNOWN')
        self.assertEqual(self.judge(now=condition(device_secure=False)['ui_state'])['status'], 'UNKNOWN')
        self.assertEqual(self.judge(read={'status': 'PRESENT', 'nonce': 'cd' * 16})['status'], 'BAD')
        self.assertEqual(self.judge(read={'status': 'ABSENT'})['status'], 'BAD')
        self.assertEqual(self.judge(origin=False)['status'], 'UNKNOWN')
        found = health_compose.unlock_row({'route': 'CREDENTIAL_UI', 'before': locked(), 'after': unlocked()},
                                          condition()['ui_state'], None, USER, SERIAL, None, {'nonce': 'ab' * 16},
                                          [], 'ee' * 16)
        self.assertEqual(found['status'], 'UNKNOWN')


def processes(context='u:r:platform_app:s0:c525,c768', app=10112, process=True, user=USER, serial=SERIAL):
    uid = user * 100000 + app
    joined = {'pid': 4734, 'start_ticks': 9120, 'uid': uid, 'uids': [uid] * 4, 'name': full_users.SYSTEMUI,
              'comm': full_users.COMM, 'context': context} if process else None
    return {'package': full_users.SYSTEMUI, 'app_id': app, 'absent': not process, 'users': [
        {'user': user, 'serial': serial, 'state': 'RUNNING_UNLOCKED', 'uid': uid, 'process': joined}]}


def identity(context='u:r:platform_app:s0:c525,c768', app=10112, user=USER, serial=SERIAL):
    return {'user': user, 'serial': serial, 'uid': user * 100000 + app, 'app_id': app, 'context': context,
            'name': full_users.SYSTEMUI, 'comm': full_users.COMM}


class IdentityTests(unittest.TestCase):
    """Bit 0's reader."""

    INVENTORY = {'whole': True, 'current_user': 0, 'users': [
        {'id': USER, 'serial': SERIAL, 'type': lab_actions.SECONDARY_TYPE, 'state': 'RUNNING_UNLOCKED', 'flags': 0x10,
         'restrictions': [], 'parent': -10000, 'removing': False, 'partial': False, 'precreated': False}]}

    def judge(self, found=None, expected=None, plan_base=None, inventory=None, user=USER):
        return health_compose.identity_row(self.INVENTORY if inventory is None else inventory,
                                           processes() if found is None else found, user, SERIAL,
                                           identity() if expected is None else expected, plan_base, [3, 4])

    def test_the_genuine_process_against_its_serials_factory_identity(self):
        self.assertEqual(self.judge()['status'], 'HELD')
        self.assertEqual(self.judge(found=processes(context='u:r:platform_app:s0:c526,c768'))['status'], 'BAD')
        self.assertEqual(self.judge(found=processes(context='u:r:untrusted_app:s0:c525,c768'))['status'], 'BAD')
        self.assertEqual(self.judge(found=processes(app=10113))['status'], 'BAD')

    def test_doubt_is_unknown_and_process_loss_alone_is_no_failure(self):
        self.assertEqual(self.judge(found=processes(process=False))['status'], 'UNKNOWN')
        self.assertEqual(health_compose.identity_row(self.INVENTORY, None, USER, SERIAL, identity(), None, [])['status'],
                         'UNKNOWN')
        self.assertEqual(health_compose.identity_row(self.INVENTORY, processes(), USER, SERIAL, None, None,
                                                     [])['status'], 'UNKNOWN')
        self.assertEqual(self.judge(expected=identity(user=14))['status'], 'UNKNOWN')
        self.assertEqual(self.judge(inventory=dict(self.INVENTORY, whole=False))['status'], 'UNKNOWN')
        stopped = copy.deepcopy(self.INVENTORY)
        stopped['users'][0]['state'] = 'NOT_RUNNING'
        self.assertEqual(self.judge(inventory=stopped)['status'], 'UNKNOWN')
        other = copy.deepcopy(self.INVENTORY)
        other['users'][0]['serial'] = 42
        self.assertEqual(self.judge(inventory=other)['status'], 'UNKNOWN')

    def test_the_system_user_is_also_held_to_the_plans_base(self):
        system = {'whole': True, 'current_user': 0, 'users': [dict(self.INVENTORY['users'][0], id=0, serial=0,
                                                                   type=lab_actions.SYSTEM_TYPE)]}
        found = processes(context=sim_users.CONTEXT, user=0, serial=0)
        expected = identity(context=sim_users.CONTEXT, user=0, serial=0)
        base = {'uid': 10112, 'context': sim_users.CONTEXT}
        self.assertEqual(health_compose.identity_row(system, found, 0, 0, expected, base, [1])['status'], 'HELD')
        for changed in ({'uid': 10057, 'context': sim_users.CONTEXT}, {'uid': 10112, 'context': 'u:r:su:s0'}):
            with self.subTest(changed):
                row = health_compose.identity_row(system, found, 0, 0, expected, changed, [1])
                self.assertEqual(row['status'], 'UNKNOWN')
                self.assertIn('disagree', row['reason'])



class HealthBase(unittest.TestCase):
    """A broker over a simulated guest that answers the full user forms and the health package's
    forms, with the real composer and baseline reader, a UI preparation that returns its result,
    the work fixture's fakes and a private store."""

    def harness(self, markers=None, hooks=False, health=None, work=True, private=True, specs_=None, admitted=None,
                **options):
        sim = sim_android.SimAndroid()
        forms = sim.enable_user_forms()
        forms.next_user, forms.next_serial = USER, SERIAL
        forms.add_fixture(labtest.FIXTURE_PACKAGE, labtest.FIXTURE_APK)
        held = {bit: HeldHook(bit) for bit in (1, 4, 5, 6)} if hooks else {}
        composer = health_compose.Composer({APK: 'WS-A'} if markers is None else markers,
                                           notice_package=sim_android.NOTICE_PACKAGE,
                                           ce_reader=sim_android.SimCeReader(), witness=held.get(1),
                                           bytes_reader=held.get(4), work=held.get(5), recovery=held.get(6))
        # Whether the reader admits a witness reader: by default exactly when hooks stand for one.
        witness = hooks if admitted is None else admitted
        reader = {'users': True, 'receipts': True, 'health': True, 'witness': witness, 'global_sessions': True,
                  'composer': composer, 'baseline': health_baseline.BaselineReader(WitnessParts() if hooks else None)}
        h = Harness(next_profile=True, sim=sim, specs=specs() if specs_ is None else specs_, reader=reader,
                    notice=sim_android.SimNotice(), health=health or sim_android.SimUiPreparation(),
                    work=sim_android.SimWork() if work else None, private=private, **options)
        h.forms = forms
        self.addCleanup(h.close)
        return h

    def between(self, h):
        if h.broker.open_generation is not None:
            h.end(0)

    def act(self, h, action, reason='a health setup step', ok=True):
        self.between(h)
        end = h.broker.run_action(action, reason)
        if ok:
            self.assertEqual((end['status'], end['settled']), ('OK', True), end)
        return end

    def setup(self, h, pin=True, sentinel=True):
        for action in SETUP:
            self.act(h, action)
        if pin:
            self.act(h, labtest.PIN_ACTION)
        if sentinel:
            self.act(h, labtest.SENTINEL_ACTION)

    def variant(self, h):
        h.sim.active = ('DATA_COPY', APK, 40)
        h.sim.marker_apks = {APK}

    def store(self, h, start, window_ms=600_000, boot=None, state='HEALTH_WINDOW'):
        plan = dict(encoder.base_plan(1), plan=PLAN, healthWindow=window_ms, criteria=127, baseUid=sim_users.APP_ID,
                    baseContext=sim_users.CONTEXT)
        window = state == 'HEALTH_WINDOW'
        ticket = dict(encoder.base_ticket(1, PLAN), ticket=TICKET, state=state, boot=h.sim.boot,
                      windowBoot=(boot or h.sim.boot) if window else proto.ZERO_ID, windowStart=start if window else 0)
        root = Path(h.admission['store'])
        for directory, name, data in (('tickets', TICKET, encoder.ticket(ticket)), ('plans', PLAN, encoder.plan(plan)),
                                      ('selections', sim_android.PACKAGE, b'selection record'),
                                      ('authorizations', labtest.GRANT, b'grant record')):
            (root / directory).mkdir(parents=True, exist_ok=True)
            (root / directory / (name + '.rec')).write_bytes(data)

    def ready(self, h, users=((USER, SERIAL),), baseline=True):
        """The created user set up with its PIN and sentinel, the factory identities, the variant
        active, each user's baseline, then the window opening a second later. Its start."""
        self.setup(h)
        h.broker.identity_baseline('the factory identities')
        self.variant(h)
        if baseline:
            for user, serial in users:
                h.broker.health_baseline(TICKET, PLAN, user, serial, 'before the window opens')
        h.sim.tick(1000)
        start = h.sim.uptime
        self.store(h, start)
        return start

    def prepare(self, h, action=PREPARE_CREATED, ok=True):
        h.sim.tick(1000)
        return self.act(h, action, 'prepare a probe', ok)

    def probe(self, h):
        self.between(h)
        h.sim.tick(1000)
        h.begin()
        self.assertEqual(h.hello()['status'], proto.STATUSES['OK'])
        self.assertEqual(h.clock_read()['status'], proto.STATUSES['OK'])
        reply = h.observe(state=lab_broker.HEALTH_WINDOW_STATE)
        self.assertEqual(reply['status'], proto.STATUSES['OK'], reply)
        return [e for e in reply['envelopes'] if e['mode'] == HEALTH]

    def groups(self, h, reader):
        return [e.content for e in h.broker.ledger.entries if e.kind == 'group' and e.content.get('reader') == reader]

    def composition(self, h, user=USER):
        group = [g for g in self.groups(h, 'health') if g.get('user') == user][-1]
        manifest = lab_evidence.parse((h.root / group['compound']['path']).read_bytes()) if group['compound'] else None
        return group, manifest

    def statuses(self, h, user=USER):
        return [row['status'] for row in self.composition(h, user)[1]['projection']['rows']]

    def classification(self, envelope):
        return CLASSES[read_observation(envelope['observation'])['classification']]

    def ledger_bytes(self, h):
        """Every byte the broker's directory holds: the ledger, its records and its compound
        manifests."""
        out = b''
        for path in sorted(h.root.rglob('*')):
            if path.is_file():
                out += path.read_bytes()
        return out


class ComposerTests(HealthBase):
    """The composer through the broker, judged with the broker's own rules."""

    def test_an_honest_probe_holds_bits_0_2_and_3_and_leaves_the_hooks_unknown(self):
        h = self.harness()
        start = self.ready(h)
        prep = self.prepare(h)
        probes = self.probe(h)
        self.assertEqual(len(probes), 1)
        self.assertEqual(self.statuses(h), ['HELD', 'UNKNOWN', 'HELD', 'HELD', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN'])
        self.assertEqual(self.classification(probes[0]), 'INCONCLUSIVE')
        block = probes[0]['block']
        self.assertEqual((block['criteria'], block['window_start']), (127, start))
        group, manifest = self.composition(h)
        rows = manifest['projection']['rows']
        self.assertEqual((rows[2]['preparation'], rows[3]['preparation']), (prep['operation'], prep['operation']))
        self.assertEqual(group['preparations'], [prep['operation']])
        result = prep['outcome']['result']
        self.assertEqual([o['result_sha256'] for o in manifest['projection']['offered']],
                         [lab_evidence.digest({'result': result})])
        self.assertTrue(all(r['children'] for r in rows if r['status'] == 'HELD'))
        # The fresh hierarchy is read by the composer, at the preparation's own path.
        reads = [h.broker.ledger.entries[n - 1].content['intent']['command'] for n in group['captures']]
        self.assertIn('cat ' + health_compose.hierarchy_path(prep['operation']), reads)
        self.assertEqual(reads.count(health_compose.ui_state_command(USER)), 1)

    def test_one_full_health_per_completed_probe_held_only_when_every_criterion_holds(self):
        h = self.harness(hooks=True)
        self.ready(h, users=((0, 0), (USER, SERIAL)))
        self.act(h, labtest.HOME_ACTION)
        self.act(h, labtest.HOME_PIN_ACTION)
        self.act(h, labtest.HOME_SENTINEL_ACTION)
        self.prepare(h, labtest.PREPARATION_ACTION)
        self.act(h, labtest.SWITCH_ACTION)
        self.prepare(h)
        probes = self.probe(h)
        self.assertEqual(sorted((read_observation(e['observation'])['user'], self.classification(e)) for e in probes),
                         [(0, 'HELD'), (USER, 'HELD')])
        for e in probes:
            fact = read_observation(e['observation'])
            self.assertEqual((fact['kind'], e['block']['criteria']), (9, 127))
            self.assertEqual([row[1] for row in e['block']['rows']], [1] * 7)
        # A second observation without fresh preparations composes nothing: no fact without a probe.
        self.assertEqual(self.probe(h), [])

    def test_a_partial_hold_is_doubt_and_never_held(self):
        cases = {'no CE sentinel origin': {'sentinel': False}, 'no identity baseline': {'identity': False},
                 'no witness hook': {'hooks': False}, 'a capture without the user unlocked': {'unlock': False},
                 'a complete baseline and a witness hook, no admitted witness reader': {'admitted': False}}
        for name, change in cases.items():
            with self.subTest(name):
                h = self.harness(hooks=change.get('hooks', True), admitted=change.get('admitted'),
                                 health=None if change.get('unlock', True) else sim_android.SimUiPreparation(
                                     changes=lambda r: dict(r, criteria={'2': dict(r['criteria']['2'], before=dict(
                                         r['criteria']['2']['before'], current_user=0))})))
                self.setup(h, sentinel=change.get('sentinel', True))
                if change.get('identity', True):
                    h.broker.identity_baseline('the factory identities')
                self.variant(h)
                h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'before the window')
                h.sim.tick(1000)
                self.store(h, h.sim.uptime)
                self.prepare(h)
                probes = self.probe(h)
                self.assertEqual(len(probes), 1)
                self.assertEqual(self.classification(probes[0]), 'INCONCLUSIVE')
                self.assertIn('UNKNOWN', self.statuses(h))
                self.assertNotIn('BAD', self.statuses(h))
                if 'admitted' in change:
                    row = self.composition(h)[1]['projection']['rows'][1]
                    self.assertEqual((row['status'], row['reason'][:21]), ('UNKNOWN', 'no witness reader is '))

    def test_an_unavailable_read_is_unknown_never_false_and_an_unadmitted_command_has_no_form(self):
        h = self.harness()
        self.ready(h)
        self.prepare(h)
        h.sim.ui_unavailable = {'ce_unlocked': 'java.lang.SecurityException'}
        self.probe(h)
        self.assertEqual(self.statuses(h)[3], 'UNKNOWN')
        self.assertEqual(self.statuses(h)[0], 'HELD')
        # A helper reply cut short: the read is unavailable and bit 3 unknown, never false.
        h = self.harness()
        self.ready(h)
        self.prepare(h)
        h.sim.scripts[health_compose.ui_state_command(USER)] = ['after']
        self.probe(h)
        group, manifest = self.composition(h)
        self.assertEqual(group['status'], 'facts')
        self.assertEqual(self.statuses(h)[3], 'UNKNOWN')
        # A composer that asks for a command its reader does not admit has no form: no fact.
        h = self.harness()
        self.ready(h)
        self.prepare(h)
        h.broker.reader.composer.ce_reader = type('Stray', (), {'allowed': staticmethod(lambda c: False),
                                                                'read': staticmethod(lambda calls, c: calls.run(
                                                                    'sim:sentinel-read 13'))})()
        self.assertEqual(self.probe(h), [])
        group, _ = self.composition(h)
        self.assertEqual(group['status'], 'unclassified')
        # The same in the middle of a composition: had the unadmitted command been taken as an
        # unavailable read, with no capture of its own, every later row would name the capture after
        # its own, still within the probe's captures. The composition has no form instead.
        h = self.harness(hooks=True)
        self.ready(h)
        self.prepare(h)

        class Stray:
            def allowed(self, command):
                return False

            def read(self, calls, context):
                calls.run('sim:stray')

        class Unnamed(HeldHook):
            def read(self, calls, context):
                calls.run(health_compose.SHELL_IDENTITY)
                return health_compose.row(self.bit, 'UNKNOWN', 'read and not judged')
        h.broker.reader.composer.hooks.update({4: Stray(), 6: Unnamed(6)})
        self.assertEqual(self.probe(h), [])
        group, _ = self.composition(h)
        self.assertEqual(group['status'], 'unclassified')

    def test_a_preparation_result_of_no_known_form_or_of_another_user_settles_nothing(self):
        def other_user(result):
            return dict(result, user=0)

        def other_path(result):
            return dict(result, criteria=dict(result['criteria'], **{'2': dict(
                result['criteria']['2'], path=health_compose.hierarchy_path('ab' * 16))}))

        def other_criterion(result):
            return dict(result, criteria=dict(result['criteria'], **{'4': {'schema': 'andrix-bytes-v1'}}))
        for name, change in (('another user', other_user), ('another path', other_path),
                             ('a criterion it did not serve', other_criterion)):
            with self.subTest(name):
                h = self.harness(health=sim_android.SimUiPreparation(changes=change))
                self.ready(h)
                end = self.prepare(h, ok=False)
                self.assertEqual((end['status'], end['outcome']['classification'], end['outcome']['result']),
                                 ('UNKNOWN', 'UNRECOGNIZED', None))
                self.assertEqual(self.probe(h), [])


class BaselineTests(HealthBase):
    """Which health baseline a probe relies on, through the broker and in health_baseline."""

    def bit1(self, h):
        return self.composition(h)[1]['projection']['rows'][1]

    def test_the_last_whole_complete_baseline_before_the_window_is_relied_on(self):
        h = self.harness(hooks=True)
        self.ready(h)
        self.prepare(h)
        self.probe(h)
        row = self.bit1(h)
        self.assertEqual(row['status'], 'HELD')
        self.assertEqual(row['baseline'], self.groups(h, 'health-baseline')[-1]['compound']['sha256'])
        # Without the witness reader a baseline is never complete, and bit 1 never holds.
        h = self.harness()
        self.ready(h)
        self.assertEqual([g['complete'] for g in self.groups(h, 'health-baseline')], [False])
        facts = self.groups(h, 'health-baseline')[-1]['projection']['facts']
        self.assertEqual((facts['history'], facts['current_errors']), ({'status': 'NOT_ADMITTED'},) * 2)
        self.assertEqual(facts['process']['uid'], USER * 100000 + sim_users.APP_ID)

    def test_unavailable_output_never_resets_the_last_whole_baseline(self):
        h = self.harness(hooks=True)
        self.setup(h)
        h.broker.identity_baseline('the factory identities')
        self.variant(h)
        h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'the good one')
        h.sim.scripts[full_users.PIDOF] = ['before']
        h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'a lost one')
        h.forms.proc_denied.add(h.forms.processes[USER][0])
        h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'a refused one')
        h.forms.proc_denied.clear()
        good = health_baseline.BaselineReader(WitnessParts()).read
        h.broker.reader.baseline_reader.read = lambda run, context: dict(good(run, context), facts=dict(
            good(run, context)['facts'], uid=1))
        h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'one of no known form')
        self.assertEqual([g['status'] for g in self.groups(h, 'health-baseline')],
                         ['facts', 'unavailable', 'unavailable', 'unclassified'])
        self.assertIsNotNone(self.groups(h, 'health-baseline')[-1]['brackets'])
        h.sim.tick(1000)
        self.store(h, h.sim.uptime)
        self.prepare(h)
        self.probe(h)
        self.assertEqual(self.bit1(h)['baseline'], self.groups(h, 'health-baseline')[0]['compound']['sha256'])

    def test_a_stale_reused_late_or_later_framework_baseline_is_never_relied_on(self):
        cases = ('after the window opened', 'a later framework', 'another boot', 'another serial',
                 'the process gone since')
        for name in cases:
            with self.subTest(name):
                h = self.harness(hooks=True)
                self.setup(h)
                h.broker.identity_baseline('the factory identities')
                self.variant(h)
                if name != 'after the window opened':
                    if name == 'another serial':
                        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'the system user')
                    else:
                        h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'before')
                if name == 'a later framework':
                    h.sim.framework_restart()
                if name == 'the process gone since':
                    h.forms.processes.pop(USER)
                    h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'no process now')
                    h.forms.new_process(USER)
                h.sim.tick(1000)
                self.store(h, h.sim.uptime)
                if name == 'after the window opened':
                    h.sim.tick(500)
                    h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'late')
                if name == 'another boot':
                    baselines = h.broker.baselines.pop((h.sim.boot, USER, SERIAL))
                    h.broker.baselines[('ab' * 16, USER, SERIAL)] = baselines
                self.prepare(h)
                self.probe(h)
                row = self.bit1(h)
                self.assertEqual(row['status'], 'UNKNOWN')
                self.assertIn('no valid baseline relied on', row['reason'])

    def test_a_newly_unlocked_users_baseline_is_taken_before_its_first_full_probe(self):
        listings = [(1000, {(0, 0): 'RUNNING_UNLOCKED', (USER, SERIAL): 'NOT_RUNNING'}),
                    (5000, {(0, 0): 'RUNNING_UNLOCKED', (USER, SERIAL): 'RUNNING_LOCKED'}),
                    (7000, {(0, 0): 'RUNNING_UNLOCKED', (USER, SERIAL): 'RUNNING_UNLOCKED'})]
        window = {'boot': 'aa' * 16, 'start': 3000, 'end': 603000}

        def baseline(begin, end, complete=True, instance=4001):
            facts = {'schema': health_records.BASELINE_FACTS, 'user': USER, 'serial': SERIAL,
                     'state': 'RUNNING_UNLOCKED', 'app_id': 10112, 'uid': 1310112,
                     'process': processes()['users'][0]['process'], 'absent': False,
                     'history': WitnessParts().baseline(None, None)[0], 'current_errors': WitnessParts().baseline(
                         None, None)[1], 'complete': complete}
            if not complete:
                facts['history'] = facts['current_errors'] = {'status': 'NOT_ADMITTED'}
            return {'status': 'facts', 'projection': {'user': USER, 'serial': SERIAL, 'facts': facts},
                    'brackets': {'instance': instance, 'begin': {'elapsed': begin}, 'end': {'elapsed': end}}}
        self.assertEqual(health_baseline.span_start(listings, window, USER, SERIAL), 5000)
        self.assertEqual(health_baseline.span_start(listings, window, 0, 0), 3000)
        before = baseline(1500, 1600)
        late = baseline(6000, 6100)
        chosen, rule = health_baseline.select([before, late], listings, [8000], window, USER, SERIAL, 4001)
        self.assertEqual((chosen, rule), (late, health_baseline.NEWLY_UNLOCKED))
        # A baseline from before the span, or after the user's first probe, relies on nothing.
        self.assertIsNone(health_baseline.select([before], listings, [8000], window, USER, SERIAL, 4001)[0])
        self.assertIsNone(health_baseline.select([before, late], listings, [5500], window, USER, SERIAL, 4001)[0])
        self.assertIsNone(health_baseline.select([before, baseline(4000, 4100)], listings, [8000], window, USER,
                                                 SERIAL, 4001)[0])
        self.assertIsNone(health_baseline.select([late], listings, [8000], window, USER, SERIAL, 4101)[0])
        self.assertIsNone(health_baseline.select([baseline(6000, 6100, complete=False)], listings, [8000], window,
                                                 USER, SERIAL, 4001)[0])
        # The system user, unlocked before the window, relies only on a baseline before it.
        system = baseline(1500, 1600)
        system['projection'] = dict(system['projection'], user=0, serial=0, facts=dict(
            system['projection']['facts'], user=0, serial=0, uid=10112, process=processes(user=0, serial=0)['users'][0]
            ['process']))
        self.assertEqual(health_baseline.select([system], listings, [8000], window, 0, 0, 4001)[1],
                         health_baseline.BEFORE_WINDOW)

    def test_a_newly_unlocked_users_baseline_through_the_broker(self):
        h = self.harness(hooks=True)
        self.setup(h)
        h.broker.identity_baseline('the factory identities')
        self.variant(h)
        h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'before the window, then lost to a lock')
        h.sim.tick(1000)
        start = h.sim.uptime
        self.store(h, start)
        # After the window opened, a whole listing shows the user with CE storage locked; it is
        # unlocked later, and its baseline taken then, before its first probe.
        h.forms.users[USER].state = 'RUNNING_LOCKED'
        h.forms.sync()
        h.sim.tick(1000)
        h.begin()
        h.hello()
        h.clock_read()
        h.observe(state=lab_broker.HEALTH_WINDOW_STATE)
        self.between(h)
        h.forms.users[USER].state = 'RUNNING_UNLOCKED'
        h.forms.sync()
        h.sim.tick(1000)
        late = h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, 'newly unlocked')
        self.prepare(h)
        self.probe(h)
        row = self.bit1(h)
        self.assertEqual(row['status'], 'HELD')
        kept = [e.content for e in h.broker.ledger.entries if e.number == late][0]
        self.assertEqual(row['baseline'], kept['compound']['sha256'])

    def test_baseline_facts_of_no_known_form_are_unclassified(self):
        h = self.harness()
        self.setup(h)
        good = health_baseline.BaselineReader().read
        for name, change in (('complete without a witness', lambda f: dict(f, complete=True)),
                             ('another uid', lambda f: dict(f, uid=f['uid'] + 1)),
                             ('a process although none ran', lambda f: dict(f, absent=True)),
                             ('another serial', lambda f: dict(f, serial=99))):
            with self.subTest(name):
                h.broker.reader.baseline_reader.read = lambda run, context, change=change: dict(
                    good(run, context), facts=change(good(run, context)['facts']))
                number = h.broker.health_baseline(TICKET, PLAN, USER, SERIAL, name)
                group = [e.content for e in h.broker.ledger.entries if e.number == number][0]
                self.assertEqual(group['status'], 'unclassified', name)



class IdentityBaselineTests(HealthBase):
    """Each serial's expected identity: read while the factory copy is active, never redefined."""

    def entry(self, h, number):
        return h.broker.ledger.entries[number - 1].content

    def context_reply(self, h, user, context):
        pid = h.forms.processes[user][0]
        h.forms.replies['cat /proc/%d/attr/current' % pid] = [(0, context.encode() + b'\x00', b'')]

    def test_the_first_qualified_identity_of_a_serial_stands(self):
        h = self.harness()
        self.setup(h, pin=False, sentinel=False)
        first = self.entry(h, h.broker.identity_baseline('the factory identities'))
        self.assertEqual((first['status'], first['projection']['qualified'], first['conflicts']), ('facts', True, []))
        self.assertEqual(sorted(i['serial'] for i in first['projection']['identities']), [0, SERIAL])
        expected = h.broker.identities[SERIAL]['identity']
        self.assertEqual((expected['uid'], expected['app_id'], expected['context']),
                         (USER * 100000 + sim_users.APP_ID, sim_users.APP_ID, 'u:r:platform_app:s0:c525,c768'))
        # With the variant active the read is not qualified, and changes nothing.
        self.variant(h)
        later = self.entry(h, h.broker.identity_baseline('with the variant active'))
        self.assertEqual((later['status'], later['projection']['qualified'], later['projection']['why_not']),
                         ('facts', False, 'the factory copy is not active'))
        # A data copy of the factory's own bytes is not the factory copy either.
        h.sim.active = ('DATA_COPY', sim_android.FACTORY_APK, sim_android.FACTORY_VERSION)
        copied = self.entry(h, h.broker.identity_baseline('a data copy of the factory bytes'))
        self.assertEqual(copied['projection']['why_not'], 'the factory copy is not active')
        # A later qualified read that differs is a conflict, never a new expectation.
        h.sim.active = ('FACTORY_COPY', sim_android.FACTORY_APK, sim_android.FACTORY_VERSION)
        h.sim.marker_apks = set()
        self.context_reply(h, USER, 'u:r:platform_app:s0:c600,c768')
        contrary = self.entry(h, h.broker.identity_baseline('a contrary identity'))
        self.assertEqual((contrary['projection']['qualified'], contrary['conflicts']), (True, [SERIAL]))
        self.assertEqual(h.broker.identities[SERIAL]['identity'], expected)
        self.assertEqual(h.broker.identity_conflicts, {SERIAL: [contrary['number']]})
        h.reopen()
        self.assertEqual((h.broker.identities[SERIAL]['identity'], h.broker.identity_conflicts),
                         (expected, {SERIAL: [contrary['number']]}))

    def test_an_identity_baseline_its_reader_cannot_read_again_gives_no_expectation(self):
        # A reader that cannot read the children's captures again leaves the group unclassified,
        # with no projection and no expectation, and so does every reopening with such a reader.
        # A reopening whose reader can read them again finds the group not what its children give.
        import unittest.mock
        original = sim_android.SimReader.rederive

        def unread(reader, name, captures, inventory=None):
            return NotImplemented if name == 'active' else original(reader, name, captures, inventory)
        h = self.harness()
        self.setup(h, pin=False, sentinel=False)
        with unittest.mock.patch.object(sim_android.SimReader, 'rederive', unread):
            group = self.entry(h, h.broker.identity_baseline('the factory identities'))
            self.assertEqual((group['status'], group['reason'], group['projection'], group['conflicts']),
                             ('unclassified', lab_broker.UNREAD, None, []))
            self.assertEqual(h.broker.identities, {})
            h.reopen()
            self.assertEqual(h.broker.identities, {})
        with self.assertRaisesRegex(lab_broker.BrokerError, "not what its children's captures give"):
            h.reopen()

    def test_the_system_users_process_must_be_the_one_the_active_read_names(self):
        h = self.harness()
        self.setup(h, pin=False, sentinel=False)
        self.context_reply(h, 0, 'u:r:platform_app:s0:c513,c768')
        group = self.entry(h, h.broker.identity_baseline('a contrary system user'))
        self.assertEqual((group['projection']['qualified'], h.broker.identities),
                         (False, {}))
        self.assertIn('active read', group['projection']['why_not'])

    def test_a_probe_compares_its_users_process_with_its_serials_identity(self):
        h = self.harness()
        self.ready(h)
        self.prepare(h)
        self.context_reply(h, USER, 'u:r:platform_app:s0:c600,c768')
        probes = self.probe(h)
        self.assertEqual(self.statuses(h)[0], 'BAD')
        self.assertEqual(self.classification(probes[0]), 'DEGRADED')
        # Only the identity baseline of the serial's own user counts: the system user's never does.
        h = self.harness()
        self.ready(h)
        h.broker.identities.pop(SERIAL)
        self.prepare(h)
        self.probe(h)
        self.assertEqual(self.statuses(h)[0], 'UNKNOWN')


class PinTests(HealthBase):
    """USER_PIN: a disposable lab PIN through locksettings and private standard input."""

    def pin_of(self, h, serial=SERIAL):
        found = h.broker.private_pin(serial)
        return None if found is None else found[0]

    def setup_records(self, h, prefix='PIN_'):
        return [e.content for e in h.broker.ledger.entries if e.kind == 'user-setup' and e.complete
                and e.content['record'].startswith(prefix)]

    def captures(self, h, begin):
        return [e for e in h.broker.ledger.entries if e.kind == 'capture'
                and (e.content.get('intent') or {}).get('lab_action') == begin]

    def assert_private(self, h, pin):
        """The PIN is in the private store and in no byte of the broker's directory, neither as it
        is nor as the hexadecimal digits of its bytes, the form a capture's residual takes."""
        self.assertIsNotNone(pin)
        data = self.ledger_bytes(h)
        self.assertNotIn(pin.encode(), data)
        self.assertNotIn(pin.encode().hex().encode(), data)
        record = Path(h.private) / h.broker.pins[SERIAL]['PIN_INTENT']['private']
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertIn(pin.encode(), record.read_bytes())

    def test_the_pin_is_set_through_private_input_and_never_enters_the_ledger(self):
        h = self.harness()
        self.setup(h, pin=False, sentinel=False)
        end = self.act(h, labtest.PIN_ACTION)
        pin = self.pin_of(h)
        self.assertEqual(h.sim.pins, {USER: pin})
        self.assertTrue(re.fullmatch(r'[0-9]{6}', pin))
        self.assert_private(h, pin)
        intent, done = self.setup_records(h)
        self.assertEqual((intent['record'], done['record'], done['intent']), ('PIN_INTENT', 'PIN_SET', intent['number']))
        effects = [e for e in self.captures(h, end['begin']) if e.content['intent']['operation'] == 'lab-action-effect']
        self.assertEqual(len(effects), 1)
        effect = effects[0]
        self.assertEqual((effect.content['intent']['command'], effect.content['intent']['private_input']),
                         ('sh', True))
        self.assertEqual(effect.content['result']['service'], 'shell,v2,raw:sh')
        # Intent before effect: the private record and PIN_INTENT precede the effect's capture.
        self.assertLess(intent['number'], effect.number)
        self.assertLess(intent['readback'], intent['number'])
        self.assertLess(effect.number, done['readback'])
        self.assertEqual((end['outcome']['reply'], end['outcome']['device_secure']), ('SET', True))
        self.assertEqual(('private', 'sh'), [c for c in h.sim.calls if c[0] == 'private'][0])
        # A second PIN for the serial is refused before anything is sent: never replaced.
        for first in ('OK', 'FAILED'):
            h2 = self.harness(specs_=[dict(s, max_uses=2) if s['id'] == labtest.PIN_ACTION else s for s in specs()])
            self.setup(h2, pin=False, sentinel=False)
            if first == 'FAILED':
                h2.sim.private_scripts = [lambda c: sim_android.result(c, 255)]
            self.assertEqual(self.act(h2, labtest.PIN_ACTION, ok=False)['status'], first)
            again = self.act(h2, labtest.PIN_ACTION, ok=False)
            self.assertEqual((again['status'], again['counts']['effects_launched']), ('REFUSED', 0), first)
            self.assertIn('never replaced', again['uncertainty'])

    def test_the_pin_is_refused_without_its_preconditions_and_launches_nothing(self):
        cases = ('a secure credential already', 'CE storage locked', 'the UI state unavailable', 'no private store',
                 'the helper bytes changed')
        for name in cases:
            with self.subTest(name):
                h = self.harness(private=name != 'no private store')
                self.setup(h, pin=False, sentinel=False)
                if name == 'a secure credential already':
                    h.sim.pins[USER] = '999999'
                elif name == 'CE storage locked':
                    h.forms.users[USER].state = 'RUNNING_LOCKED'
                    h.forms.sync()
                elif name == 'the UI state unavailable':
                    h.sim.ui_unavailable = {'device_secure': 'android.os.DeadObjectException'}
                elif name == 'the helper bytes changed':
                    h.sim.ui_helper = 'ab' * 32
                end = self.act(h, labtest.PIN_ACTION, ok=False)
                self.assertEqual((end['status'], end['settled'], end['counts']['effects_launched'],
                                  end['counts']['effects_uncertain']), ('REFUSED', True, 0, 0))
                self.assertEqual(self.setup_records(h), [])
                self.assertNotIn(('private', 'sh'), h.sim.calls)

    def test_an_interrupted_pin_leaves_an_honest_prefix_and_is_never_repeated(self):
        def lost_at(method, record=None):
            original = getattr(lab_broker.Broker, method)

            def fake(broker, *args, **kwargs):
                if record is None or (args and args[0] == record):
                    raise KeyboardInterrupt('lost at ' + method)
                return original(broker, *args, **kwargs)
            return unittest.mock.patch.object(lab_broker.Broker, method, fake)
        import unittest.mock
        for name in ('before the private record', 'before the intent', 'in the effect', 'after the effect'):
            with self.subTest(name):
                h = self.harness()
                self.setup(h, pin=False, sentinel=False)
                if name == 'before the private record':
                    patch = lost_at('_keep_private')
                elif name == 'before the intent':
                    patch = lost_at('_write_health_setup', 'PIN_INTENT')
                elif name == 'in the effect':
                    patch = unittest.mock.patch.object(h.sim, 'hooks', [lambda c: c == 'sh' and (_ for _ in ()).throw(
                        KeyboardInterrupt('lost in the effect'))])
                else:
                    patch = lost_at('_write_health_setup', 'PIN_SET')
                with patch, self.assertRaises(KeyboardInterrupt):
                    h.broker.run_action(labtest.PIN_ACTION, 'set the PIN')
                h.reopen()
                end = [e.content for e in h.broker.ledger.entries if e.kind == 'lab-action'][-1]
                self.assertEqual((end['record'], end['status'], end['settled']), ('END', 'LOST', False))
                records = [r['record'] for r in self.setup_records(h)]
                launched = end['counts']['effects_launched'] + end['counts']['effects_uncertain']
                expected = {'before the private record': ([], 0), 'before the intent': ([], 0),
                            'in the effect': (['PIN_INTENT'], 1), 'after the effect': (['PIN_INTENT'], 1)}[name]
                self.assertEqual((records, launched), expected)
                if records:
                    # The PIN that may now be set stays in the private store, for the credential
                    # unlock.
                    self.assert_private(h, self.pin_of(h))
                with self.assertRaisesRegex(lab_broker.BrokerError, 'spent|did not settle'):
                    h.broker.run_action(labtest.PIN_ACTION, 'again')
                self.assertEqual(len([c for c in h.sim.calls if c[0] == 'private']), 1 if name == 'after the effect'
                                 else 0)

    def test_an_uncertain_or_refused_effect_settles_only_on_its_readback(self):
        for name in ('reply lost after the effect', 'readback unavailable', 'refused', 'output with the pin',
                     'success without a credential'):
            with self.subTest(name):
                h = self.harness()
                self.setup(h, pin=False, sentinel=False)
                if name == 'success without a credential':
                    h.sim.private_scripts = [lambda c: sim_android.result(c, 0)]
                if name == 'reply lost after the effect':
                    h.sim.private_scripts = ['after']
                elif name == 'readback unavailable':
                    def unavailable(command):
                        if command == 'sh':
                            h.sim.ui_unavailable['device_secure'] = 'java.lang.SecurityException'
                    h.sim.hooks.append(unavailable)
                elif name == 'refused':
                    h.sim.private_scripts = [lambda c: sim_android.result(c, 255)]
                else:
                    h.sim.private_echo = True
                end = self.act(h, labtest.PIN_ACTION, ok=False)
                status = {'reply lost after the effect': ('UNKNOWN', False), 'readback unavailable': ('UNKNOWN', False),
                          'refused': ('FAILED', True), 'output with the pin': ('UNKNOWN', False),
                          'success without a credential': ('UNEXPECTED', True)}[name]
                self.assertEqual((end['status'], end['settled']), status, end)
                self.assertEqual([r['record'] for r in self.setup_records(h)], ['PIN_INTENT'])
                pin = self.pin_of(h)
                self.assert_private(h, pin)
                if name == 'output with the pin':
                    effect = [e for e in self.captures(h, end['begin'])
                              if e.content['intent']['operation'] == 'lab-action-effect'][0]
                    self.assertEqual((effect.content['result']['withheld'], effect.content['result']['stdout_bytes']),
                                     (True, 0))
                    kept = Path(h.private) / (h.broker.pins[SERIAL]['PIN_INTENT']['private'] + '-withheld')
                    withheld = lab_evidence.parse(kept.read_bytes())
                    self.assertIn(pin.encode(), bytes.fromhex(withheld['stdout_hex']))


    def test_a_malformed_oversized_or_cut_private_reply_never_puts_the_pin_in_the_ledger(self):
        # The PIN effect's reply through the real shell client over a scripted socket. The
        # review's case is an oversized stdout packet whose first payload holds the PIN, which the
        # decoder keeps as residual. Beside it: a malformed reply with the PIN in a packet of no
        # known ID or after the exit, a reply cut inside a stderr packet with part of the PIN, the
        # normal echo of a whole reply, and an honest silent success. Any output withholds every
        # field that holds it, while the outcome and the effect counts stay as they were.
        def stream(kind, pin, bound):
            echo = b"Pin set to '" + pin + b"'\n"
            exit0 = bytes([shell_transport.ID_EXIT]) + struct.pack('<I', 1) + b'\x00'
            if kind == 'oversized':
                return bytes([shell_transport.ID_STDOUT]) + struct.pack('<I', bound + 1) + echo
            if kind == 'unknown packet':
                return bytes([7]) + struct.pack('<I', len(echo)) + echo
            if kind == 'after its exit':
                return exit0 + bytes([shell_transport.ID_STDOUT]) + struct.pack('<I', len(echo)) + echo
            if kind == 'cut':
                return bytes([shell_transport.ID_STDERR]) + struct.pack('<I', len(echo)) + echo[:len(echo) - 4]
            if kind == 'echo':
                return bytes([shell_transport.ID_STDOUT]) + struct.pack('<I', len(echo)) + echo + exit0
            return exit0
        # (completion, status, settled, the field that keeps the output privately)
        cases = {'oversized': ('overflow', 'UNKNOWN', False, 'residual'),
                 'unknown packet': ('malformed', 'UNKNOWN', False, 'residual'),
                 'after its exit': ('malformed', 'UNKNOWN', False, 'residual'),
                 'cut': ('eof-before-exit', 'UNKNOWN', False, 'stderr'),
                 'echo': ('exited', 'UNKNOWN', False, 'stdout'),
                 'silent success': ('exited', 'OK', True, None)}
        for kind, (completion, status, settled, field) in cases.items():
            with self.subTest(kind):
                h = self.harness()
                self.setup(h, pin=False, sentinel=False)
                spec = h.broker.specs[labtest.PIN_ACTION]
                sent = []

                def reply(command):
                    pin = self.pin_of(h)
                    # The guest's credential is set, as the model's own effect sets it.
                    h.sim.pins[USER] = pin
                    sock = ReplySocket(stream(kind, pin.encode(), spec['stdout_max']))
                    sent.append(sock)
                    return shell_transport.AdbClient('127.0.0.1:6520', lambda timeout: sock).shell(
                        command, 5, spec['stdout_max'], spec['stderr_max'],
                        private=(lab_broker.PIN_INPUT % (USER, pin)).encode())
                h.sim.private_scripts = [reply]
                end = self.act(h, labtest.PIN_ACTION, ok=False)
                pin = self.pin_of(h)
                self.assertEqual((end['status'], end['settled']), (status, settled), end)
                self.assertEqual((end['counts']['effects_launched'], end['counts']['effects_uncertain'],
                                  end['counts']['effects_not_launched']), (1, 0, 0))
                script = (lab_broker.PIN_INPUT % (USER, pin)).encode()
                self.assertIn(struct.pack('<BI', shell_transport.ID_STDIN, len(script)) + script
                              + struct.pack('<BI', shell_transport.ID_CLOSE_STDIN, 0), sent[0].sent)
                self.assert_private(h, pin)
                effect = [e for e in self.captures(h, end['begin'])
                          if e.content['intent']['operation'] == 'lab-action-effect'][0]
                result = effect.content['result']
                self.assertEqual(result['completion'], completion)
                self.assertEqual((result['stdout_bytes'], result['stderr_bytes'], result['residual_hex'],
                                  result['residual_bytes']), (0, 0, '', 0))
                kept = Path(h.private) / (h.broker.pins[SERIAL]['PIN_INTENT']['private'] + '-withheld')
                records = [r['record'] for r in self.setup_records(h)]
                if field is None:
                    self.assertNotIn('withheld', result)
                    self.assertFalse(kept.exists())
                    self.assertEqual(records, ['PIN_INTENT', 'PIN_SET'])
                    continue
                self.assertEqual(records, ['PIN_INTENT'])
                self.assertEqual((result['withheld'], result['withheld_kept']), (True, True))
                self.assertEqual(result['error'], None if completion == 'exited' else lab_broker.WITHHELD)
                withheld = lab_evidence.parse(kept.read_bytes())
                self.assertEqual(result['withheld_bytes'], {name: withheld[name + '_bytes']
                                                            for name in ('stdout', 'stderr', 'residual')})
                # The PIN, or for the cut reply the part of it that arrived, is kept privately only.
                self.assertIn(pin.encode() if kind != 'cut' else pin.encode()[:4], bytes.fromhex(withheld[field + '_hex']))


class ReplySocket:
    """A client socket for one shell service: the adb server's device selection and service
    replies, then a scripted shell protocol stream. It keeps what the client sends."""

    def __init__(self, stream):
        self.data = bytearray(b'OKAY' + struct.pack('<Q', 7) + b'OKAY' + stream)
        self.sent = []

    def settimeout(self, value):
        pass

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, count):
        out = bytes(self.data[:count])
        del self.data[:count]
        return out

    def close(self):
        pass


class SentinelTests(HealthBase):
    """CE_SENTINEL: the fixture's CE nonce, the origin bit 3 reads back."""

    def records(self, h):
        return [e.content for e in h.broker.ledger.entries if e.kind == 'user-setup' and e.complete
                and e.content['record'].startswith('SENTINEL_')]

    def test_the_nonce_is_recorded_before_the_write_and_settles_on_its_readback(self):
        h = self.harness()
        self.setup(h, sentinel=False)
        end = self.act(h, labtest.SENTINEL_ACTION)
        intent, done = self.records(h)
        self.assertEqual(h.sim.ce_sentinels, {USER: intent['nonce']})
        self.assertEqual((done['nonce'], done['intent']), (intent['nonce'], intent['number']))
        writes = [e for e in h.broker.ledger.entries if e.kind == 'capture'
                  and (e.content.get('intent') or {}).get('lab_action') == end['begin']
                  and e.content['intent']['operation'] == 'lab-action-effect']
        self.assertEqual([w.content['intent']['command'] for w in writes],
                         ['sim:sentinel-write %d %s' % (USER, intent['nonce'])])
        self.assertLess(intent['number'], writes[0].number)
        self.assertLess(writes[0].number, done['readback'])
        self.assertEqual(h.broker._ce_origin(SERIAL), {'nonce': intent['nonce'], 'record': done['number']})

    def test_the_sentinel_is_refused_without_ce_storage_unlocked_or_its_fixture_adapter(self):
        for name in ('CE storage locked', 'the framework CE state unavailable', 'a second sentinel'):
            with self.subTest(name):
                h = self.harness(specs_=[dict(s, max_uses=2) if s['id'] == labtest.SENTINEL_ACTION else s
                                         for s in specs()])
                self.setup(h, sentinel=name == 'a second sentinel')
                if name == 'CE storage locked':
                    h.forms.users[USER].state = 'RUNNING_LOCKED'
                    h.forms.sync()
                elif name == 'the framework CE state unavailable':
                    h.sim.ui_unavailable = {'ce_unlocked': 'java.lang.SecurityException'}
                end = self.act(h, labtest.SENTINEL_ACTION, ok=False)
                self.assertEqual((end['status'], end['counts']['effects_launched']), ('REFUSED', 0))
        h = self.harness(work=False)
        self.setup(h, sentinel=False)
        with self.assertRaisesRegex(lab_broker.BrokerError, 'no work adapter'):
            h.broker.run_action(labtest.SENTINEL_ACTION, 'no fixture adapter')

    def test_an_uncertain_or_contrary_sentinel_never_becomes_an_origin(self):
        for name in ('write reply lost', 'readback unavailable', 'readback of another nonce', 'refused and absent'):
            with self.subTest(name):
                h = self.harness()
                self.setup(h, sentinel=False)
                if name == 'write reply lost':
                    h.sim.scripts['sim:sentinel-write'] = ['after']
                elif name == 'readback unavailable':
                    h.sim.scripts['sim:sentinel-read'] = ['before']
                elif name == 'readback of another nonce':
                    h.sim.scripts['sim:sentinel-read'] = [lambda c: sim_android.result(c, 0, b'nonce=%s\n' % (b'cd' * 16))]
                else:
                    h.sim.scripts['sim:sentinel-write'] = [lambda c: sim_android.result(c, 1, b'', b'locked\n')]
                end = self.act(h, labtest.SENTINEL_ACTION, ok=False)
                expected = {'write reply lost': ('UNKNOWN', False), 'readback unavailable': ('UNKNOWN', False),
                            'readback of another nonce': ('UNEXPECTED', True), 'refused and absent': ('FAILED', True)}
                self.assertEqual((end['status'], end['settled']), expected[name])
                self.assertEqual([r['record'] for r in self.records(h)], ['SENTINEL_INTENT'])
                self.assertIsNone(h.broker._ce_origin(SERIAL))
                if not end['settled']:
                    with self.assertRaisesRegex(lab_broker.BrokerError, 'spent|did not settle'):
                        h.broker.run_action(labtest.SENTINEL_ACTION, 'again')

    def test_an_interrupted_sentinel_is_closed_lost_and_never_repeated(self):
        import unittest.mock
        for name in ('before the intent', 'in the write'):
            with self.subTest(name):
                h = self.harness()
                self.setup(h, sentinel=False)
                if name == 'before the intent':
                    original = lab_broker.Broker._write_health_setup

                    def fake(broker, record, **fields):
                        if record == 'SENTINEL_INTENT':
                            raise KeyboardInterrupt('lost')
                        return original(broker, record, **fields)
                    patch = unittest.mock.patch.object(lab_broker.Broker, '_write_health_setup', fake)
                else:
                    patch = unittest.mock.patch.object(h.sim, 'hooks', [lambda c: c.startswith('sim:sentinel-write') and (
                        _ for _ in ()).throw(KeyboardInterrupt('lost'))])
                with patch, self.assertRaises(KeyboardInterrupt):
                    h.broker.run_action(labtest.SENTINEL_ACTION, 'keep the nonce')
                h.reopen()
                end = [e.content for e in h.broker.ledger.entries if e.kind == 'lab-action'][-1]
                self.assertEqual((end['status'], end['settled']), ('LOST', False))
                self.assertEqual([r['record'] for r in self.records(h)],
                                 [] if name == 'before the intent' else ['SENTINEL_INTENT'])
                self.assertEqual(end['counts']['effects_launched'] + end['counts']['effects_uncertain'],
                                 0 if name == 'before the intent' else 1)
                self.assertEqual(h.sim.ce_sentinels, {})
                with self.assertRaisesRegex(lab_broker.BrokerError, 'spent|did not settle'):
                    h.broker.run_action(labtest.SENTINEL_ACTION, 'again')


class TransitionTests(HealthBase):
    """USER_PIN and CE_SENTINEL wait for every boot transition to settle, as the full user setup's
    actions do."""

    def test_the_pin_and_the_sentinel_wait_for_an_earlier_boot_transition_to_settle(self):
        import test_lab_loss
        loss = test_lab_loss.LossBase()
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                h = self.harness(boot_policy=dict(labtest.BOOT_POLICY, settle_ms=20_000))
                self.setup(h, pin=False, sentinel=False)
                loss.waiting(h)
                if unknown:
                    h.sim.reboot = lambda: None
                confirmed = loss.confirm(h)
                self.assertEqual((confirmed['status'], confirmed['settled']), ('UNKNOWN', False) if unknown
                                 else ('OK', True))
                for action in (labtest.PIN_ACTION, labtest.SENTINEL_ACTION):
                    if unknown:
                        for reason in ('after the confirmation', 'after the reopening'):
                            if reason == 'after the reopening':
                                h.reopen()
                            count = len(h.broker.ledger.entries)
                            with self.assertRaisesRegex(lab_broker.BrokerError,
                                                        'boot transition .* unsettled or unexpected'):
                                h.broker.run_action(action, reason)
                            self.assertEqual(len(h.broker.ledger.entries), count)
                if unknown:
                    self.assertEqual((h.sim.pins, h.sim.ce_sentinels), ({}, {}))
                    continue
                # The settled confirmation's boot stopped the user: started and unlocked again, both
                # run.
                self.act(h, labtest.START_ACTION)
                self.act(h, labtest.SWITCH_ACTION)
                self.act(h, labtest.PIN_ACTION)
                self.act(h, labtest.SENTINEL_ACTION)


class ReopeningTests(HealthBase):
    """A reopening checks every new record against the evidence it names: a changed copy refuses
    it."""

    def copy_and_open(self, h, change):
        target = h.directory / ('changed-%d' % len(list(h.directory.glob('changed-*'))))
        shutil.copytree(h.root, target)
        change(target)
        return h.open_at(target)

    def edit(self, number, change):
        def apply(root):
            entry = next(p for p in (root / 'ledger').iterdir() if p.name.startswith('%06d-' % number))
            record = json.loads((entry / 'record.json').read_text())
            change(record)
            (entry / 'record.json').write_bytes(json.dumps(record, indent=1, sort_keys=True).encode() + b'\n')
        return apply

    def rewrite_capture(self, number, stdout):
        def apply(root):
            entry = next(p for p in (root / 'ledger').iterdir() if p.name.startswith('%06d-' % number))
            (entry / 'stdout').write_bytes(stdout)
            result = json.loads((entry / 'result.json').read_text())
            result.update(stdout_sha256=hashlib.sha256(stdout).hexdigest(), stdout_bytes=len(stdout))
            (entry / 'result.json').write_bytes(json.dumps(result, indent=1, sort_keys=True).encode() + b'\n')
        return apply

    def reconflict(self, group, conflicts):
        """A changed copy that names other conflicts in the group and in a manifest rewritten to
        match them, under its new digest: only the identity rule itself can refuse it."""
        def apply(root):
            manifest = lab_evidence.parse((root / group['compound']['path']).read_bytes())
            manifest['extra']['conflicts'] = conflicts
            data = lab_evidence.canonical(manifest)
            digest = hashlib.sha256(data).hexdigest()
            (root / 'compound' / digest).write_bytes(data)
            self.edit(group['number'], lambda r: r.update(conflicts=conflicts, compound={
                'path': 'compound/' + digest, 'sha256': digest, 'bytes': len(data)}))(root)
        return apply

    def test_honest_records_reopen_and_rebuild_the_same_state(self):
        h = self.harness()
        self.ready(h)
        before = (dict(h.broker.pins), dict(h.broker.sentinels), dict(h.broker.identities), h.broker.private_pin(SERIAL))
        h.reopen()
        self.assertEqual((h.broker.pins, h.broker.sentinels, h.broker.identities, h.broker.private_pin(SERIAL)), before)
        other = self.copy_and_open(h, lambda root: None)
        self.assertEqual(other.sentinels, h.broker.sentinels)
        other.close()

    def test_changed_copies_of_each_new_record_refuse_the_reopening(self):
        h = self.harness()
        self.ready(h)
        records = {r['record']: r for r in (e.content for e in h.broker.ledger.entries if e.kind == 'user-setup')}
        pin_intent, pin_set = records['PIN_INTENT'], records['PIN_SET']
        sentinel_intent, sentinel_set = records['SENTINEL_INTENT'], records['SENTINEL_SET']
        identity = [g for g in self.groups(h, 'identity-baseline')][-1]
        secure = health_compose.parse_ui_state(0, ui_reply()[1], '', USER)
        self.assertTrue(secure['values']['device_secure'])
        insecure = ui_reply(device_secure=False, keyguard_secure=False)[1].encode()
        changes = {
            'a PIN intent of another serial': (self.edit(pin_intent['number'], lambda r: r.update(serial=42)),
                                               'no use of an admitted USER_PIN of its user'),
            'a PIN intent naming its PIN, not a fresh name': (self.edit(pin_intent['number'], lambda r: r.update(
                private='123456')), 'by a fresh name, never by the PIN'),
            'a PIN intent whose readback read a credential': (self.rewrite_capture(
                pin_intent['readback'], ui_reply()[1].encode()), 'does not read device_secure False'),
            'a PIN set whose readback reads no credential': (self.rewrite_capture(pin_set['readback'], insecure),
                                                             'does not read device_secure True'),
            'a PIN set naming another capture as its effect': (self.edit(pin_set['number'], lambda r: r.update(
                capture=pin_intent['readback'])), 'its effect is not its own private PIN command'),
            'a PIN set without its intent': (self.edit(pin_set['number'], lambda r: r.update(
                intent=pin_set['number'] - 1)), 'a settlement without its intent'),
            'a sentinel set of another nonce': (self.edit(sentinel_set['number'], lambda r: r.update(
                nonce='cd' * 16)), 'another nonce than its intent'),
            'a sentinel readback of another nonce': (self.rewrite_capture(
                sentinel_set['readback'], b'nonce=%s\n' % (b'cd' * 16)), 'its readback shows another nonce'),
            'a sentinel intent of a zero nonce': (self.edit(sentinel_intent['number'], lambda r: r.update(
                nonce='00' * 16)), 'names its nonzero nonce'),
            'an identity baseline naming other conflicts, its manifest too': (self.reconflict(identity, [SERIAL]),
                                                                               'other conflicts than its projection'),
        }
        for name, (change, reason) in changes.items():
            with self.subTest(name), self.assertRaisesRegex(lab_broker.BrokerError, reason):
                self.copy_and_open(h, change).close()

    def test_a_changed_baseline_or_composition_manifest_refuses_the_reopening(self):
        h = self.harness()
        self.ready(h)
        self.prepare(h)
        self.probe(h)
        self.between(h)
        for reader in ('health-baseline', 'health', 'identity-baseline'):
            group = self.groups(h, reader)[-1]

            def change(root, group=group):
                path = root / group['compound']['path']
                path.write_bytes(path.read_bytes().replace(b'"status":"facts"', b'"status":"facts" '))
            with self.subTest(reader), self.assertRaises(lab_broker.BrokerError):
                self.copy_and_open(h, change).close()

    def rewrite_identity(self, group, projection=None, children=None):
        """A consistent rewrite of an identity baseline: its projection changed in the group and in
        both of its copies in the manifest, or its children in both, the manifest kept again under
        its new digest. No child group, capture or reply changes."""
        def apply(root):
            manifest = lab_evidence.parse((root / group['compound']['path']).read_bytes())
            fields = {}
            if projection is not None:
                fields['projection'] = copy.deepcopy(manifest['extra']['projection'])
                projection(fields['projection'])
                manifest['extra']['projection'] = fields['projection']
                manifest['projection']['projection'] = copy.deepcopy(fields['projection'])
            if children is not None:
                fields['children'] = dict(manifest['children'], **children)
                manifest['children'] = fields['children']
            data = lab_evidence.canonical(manifest)
            digest = hashlib.sha256(data).hexdigest()
            (root / 'compound' / digest).write_bytes(data)
            self.edit(group['number'], lambda r: r.update(fields, compound={
                'path': 'compound/' + digest, 'sha256': digest, 'bytes': len(data)}))(root)
        return apply

    def test_a_consistently_rewritten_identity_projection_refuses_the_reopening(self):
        # The review's case: a history with one identity baseline, one serial's identity changed
        # in the projection, in the group and in both of its copies in the manifest, kept under
        # its new digest, with every child group, capture and reply unchanged. Beside it, its
        # honest control: the intact copy reopens to the same expectations, against which the
        # criterion reader finds the current process in the changed context BAD. In a history
        # with a second identity baseline, a child of the first named by the second refuses too.
        h = self.harness()
        self.setup(h, pin=False, sentinel=False)
        number = h.broker.identity_baseline('the factory identities')
        group = h.broker.ledger.entries[number - 1].content
        expected = copy.deepcopy(h.broker.identities)
        identity = expected[SERIAL]['identity']
        intact = self.copy_and_open(h, lambda root: None)
        self.assertEqual((intact.identities, intact.identity_conflicts), (expected, {}))
        intact.close()
        changed = re.sub(r':c[0-9]+,', ':c600,', identity['context'])
        self.assertNotEqual(changed, identity['context'])
        inventory = h.broker.ledger.entries[group['children']['inventory'] - 1].content['reading']
        current = copy.deepcopy(h.broker.ledger.entries[group['children']['processes'] - 1].content['reading'])
        for user in current['users']:
            if user['serial'] == SERIAL:
                user['process']['context'] = changed
        row = health_compose.identity_row(inventory, current, USER, SERIAL, identity, None, [0])
        self.assertEqual(row['status'], 'BAD')

        def reidentify(**fields):
            def change(projection):
                for found in projection['identities']:
                    if found['serial'] == SERIAL:
                        found.update(fields)
                self.assertIsNone(health_records.identity_projection_problem(projection))
            return change
        for name, change in (('another context', reidentify(context=changed)),
                             ('another UID and app ID', reidentify(uid=identity['uid'] + 1,
                                                                   app_id=identity['app_id'] + 1))):
            with self.subTest(name), self.assertRaisesRegex(lab_broker.BrokerError,
                                                            "not what its children's captures give"):
                self.copy_and_open(h, self.rewrite_identity(group, projection=change)).close()
        later = h.broker.ledger.entries[h.broker.identity_baseline('the factory identities again') - 1].content
        self.assertEqual(h.broker.identities, expected)
        with self.subTest('the processes of another read'), self.assertRaisesRegex(
                lab_broker.BrokerError, 'a child that is not its own processes read'):
            self.copy_and_open(h, self.rewrite_identity(later, children={
                'processes': group['children']['processes']})).close()


class CodecTests(unittest.TestCase):
    """The side metadata codec: each form exact, and a changed copy refused for its own reason."""

    def test_baseline_facts(self):
        process = processes()['users'][0]['process']
        good = {'schema': health_records.BASELINE_FACTS, 'user': USER, 'serial': SERIAL, 'state': 'RUNNING_UNLOCKED',
                'app_id': 10112, 'uid': 1310112, 'process': process, 'absent': False,
                'history': {'status': 'NOT_ADMITTED'}, 'current_errors': {'status': 'NOT_ADMITTED'}, 'complete': False}
        self.assertIsNone(health_records.baseline_facts_problem(good, USER, SERIAL))
        part = WitnessParts().baseline(None, None)[0]
        self.assertIsNone(health_records.baseline_facts_problem(dict(good, history=part, current_errors=part,
                                                                     complete=True), USER, SERIAL))
        changed = {'complete without witness parts': dict(good, complete=True),
                   'another user': dict(good, user=14), 'a UID of another app ID': dict(good, uid=1310113),
                   'a process of another UID': dict(good, process=dict(process, uid=1310113, uids=[1310113] * 4)),
                   'a process named otherwise': dict(good, process=dict(process, name='com.android.systemui:screenshot')),
                   'a process although none ran': dict(good, absent=True),
                   'a witness part of no form': dict(good, history={'status': 'OK'}),
                   'another schema': dict(good, schema='andrix-health-baseline-facts-v2'),
                   'an extra key': dict(good, extra=1), 'a stopped user complete': dict(
                       good, state='NOT_RUNNING', history=part, current_errors=part, complete=True)}
        for name, value in changed.items():
            with self.subTest(name):
                self.assertIsNotNone(health_records.baseline_facts_problem(value, USER, SERIAL))

    def test_identity_baselines(self):
        good = {'qualified': True, 'why_not': None, 'active': {'apk': 'f0' * 32, 'factory_apk': 'f0' * 32, 'uid': 10112,
                                                                'context': sim_users.CONTEXT},
                'identities': [identity(context=sim_users.CONTEXT, user=0, serial=0), identity()]}
        self.assertIsNone(health_records.identity_projection_problem(good))
        changed = {'a serial twice': dict(good, identities=[identity(), identity()]),
                   'a UID of another user': dict(good, identities=[dict(identity(), uid=10112)]),
                   'qualified with a reason': dict(good, why_not='x'),
                   'qualified without its active copy': dict(good, active=None),
                   'not qualified without a reason': dict(good, qualified=False),
                   'another process name': dict(good, identities=[dict(identity(), name='com.android.systemui:x')])}
        for name, value in changed.items():
            with self.subTest(name):
                self.assertIsNotNone(health_records.identity_projection_problem(value))

    def test_preparation_results(self):
        operation = 'ee' * 16
        good = {'schema': health_records.PREPARATION_RESULT, 'user': USER, 'serial': SERIAL, 'criteria': {
            '2': capture_part(health_compose.hierarchy_path(operation)),
            '3': {'route': 'CREDENTIAL_UI', 'before': locked(), 'after': unlocked()}}}
        self.assertIsNone(health_records.preparation_problem(good, USER, SERIAL, [2, 3], operation))
        changed = {'another operation': (good, [2, 3], 'ab' * 16), 'a criterion not served': (good, [2], operation),
                   'another user': (dict(good, user=0), [2, 3], operation),
                   'an unknown route': (dict(good, criteria=dict(good['criteria'], **{'3': dict(
                       good['criteria']['3'], route='LOCKSETTINGS_VERIFY')})), [2, 3], operation),
                   'a UI state of another user': (dict(good, criteria=dict(good['criteria'], **{'2': capture_part(
                       health_compose.hierarchy_path(operation), before=condition(user=0))})), [2, 3], operation),
                   'an unlock condition without its state': (dict(good, criteria=dict(good['criteria'], **{'3': {
                       'route': 'CREDENTIAL_UI', 'before': condition(), 'after': unlocked()}})), [2, 3], operation),
                   'no criterion at all': (dict(good, criteria={}), [2, 3], operation)}
        for name, (value, criteria, op) in changed.items():
            with self.subTest(name):
                self.assertIsNotNone(health_records.preparation_problem(value, USER, SERIAL, criteria, op))

    def test_setup_records(self):
        good = {'record': 'PIN_INTENT', 'action_id': '2b' * 16, 'begin': 3, 'user': USER, 'serial': SERIAL,
                'digits': 6, 'private': 'pin-' + 'ab' * 16, 'readback': 2, 'wall_ns': 1}
        self.assertIsNone(health_records.setup_problem(good))
        for name, value in {'a PIN of five digits': dict(good, digits=5), 'the PIN as its name': dict(good,
                            private='123456'), 'an extra key': dict(good, pin='123456'),
                            'no readback': {k: v for k, v in good.items() if k != 'readback'},
                            'an unknown record': dict(good, record='PIN_GUESSED')}.items():
            with self.subTest(name):
                self.assertIsNotNone(health_records.setup_problem(value))
        sentinel = {'record': 'SENTINEL_INTENT', 'action_id': '2c' * 16, 'begin': 3, 'user': USER, 'serial': SERIAL,
                    'package': labtest.WORK_PACKAGE, 'nonce': 'ab' * 16, 'readback': 2, 'wall_ns': 1}
        self.assertIsNone(health_records.setup_problem(sentinel))
        for name, value in {'the component as its fixture': dict(sentinel, package='com.android.systemui'),
                            'a zero nonce': dict(sentinel, nonce='00' * 16)}.items():
            with self.subTest(name):
                self.assertIsNotNone(health_records.setup_problem(value))


class AdmissionTests(unittest.TestCase):
    def test_pin_and_sentinel_specs_are_exact(self):
        good = specs()
        self.assertEqual(len(lab_actions.check_specs(good, labtest.INSTALLATION)), len(good))
        index = {s['id']: at for at, s in enumerate(good)}

        def changed(ident, **changes):
            out = [dict(s) for s in good]
            out[index[ident]] = dict(out[index[ident]], **changes)
            return out
        cases = {'a PIN of five digits': changed(labtest.PIN_ACTION, parameters={'digits': 5}),
                 'a PIN of seventeen digits': changed(labtest.PIN_ACTION, parameters={'digits': 17}),
                 'a PIN given by the admission': changed(labtest.PIN_ACTION, parameters={'digits': 6, 'pin': '123456'}),
                 'a PIN under LAB_CONTROL': changed(labtest.PIN_ACTION, authority='LAB_CONTROL'),
                 'a PIN outside F0': changed(labtest.PIN_ACTION, phase='A'),
                 'a PIN for a notice recipient': changed(labtest.PIN_ACTION, user_selector={'kind': 'NOTICE_RECIPIENT'}),
                 'a PIN without its private store precondition': changed(labtest.PIN_ACTION, preconditions=[
                     'WHOLE_USER_INVENTORY']),
                 'the component as the sentinel fixture': changed(labtest.SENTINEL_ACTION, parameters={
                     'package': 'com.android.systemui'}),
                 'a sentinel under LAB_CONTROL': changed(labtest.SENTINEL_ACTION, authority='LAB_CONTROL')}
        for name, value in cases.items():
            with self.subTest(name), self.assertRaises(lab_actions.AdmissionError):
                lab_actions.check_specs(value, labtest.INSTALLATION)
        self.assertEqual(lab_actions.TYPES['USER_PIN']['authority'], 'LAB_USER_ADMIN')
        self.assertIn('USER_PIN', lab_actions.USER_TYPES)
        self.assertIn('CE_SENTINEL', lab_actions.USER_TYPES)


class PrivateInputTests(unittest.TestCase):
    """The PIN's private input never runs a partial command when it is cut short: the host's POSIX
    shell runs each prefix of the exact input with a stand in `locksettings` that records each
    run. A cut inside the function body is a syntax error, a cut before its call runs nothing, and
    only an input whose last token arrived runs, the whole command once. The guest's shell is mksh;
    this shows the input's form under a POSIX shell, not mksh's own behavior."""

    def test_no_prefix_of_the_private_input_runs_a_partial_command(self):
        script = (lab_broker.PIN_INPUT % (USER, '482915')).encode()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = base / 'locksettings'
            fake.write_text('#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n' % (base / 'ran'))
            fake.chmod(0o700)
            environment = {'PATH': '%s:/usr/bin:/bin' % base, 'LC_ALL': 'C'}
            for at in range(len(script) + 1):
                done = subprocess.run(['/bin/sh'], input=script[:at], env=environment, capture_output=True,
                                      timeout=20)
                ran = (base / 'ran').read_text() if (base / 'ran').exists() else ''
                (base / 'ran').unlink(missing_ok=True)
                if at < len(script) - 1:
                    self.assertEqual(ran, '', 'a prefix of %d bytes ran the command' % at)
                else:
                    self.assertEqual((done.returncode, ran), (0, 'set-pin --user %d 482915\n' % USER), at)
                    self.assertEqual((done.stdout, done.stderr), (b'', b''))


if __name__ == '__main__':
    unittest.main()
