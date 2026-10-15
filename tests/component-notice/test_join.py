# SPDX-License-Identifier: Apache-2.0
"""The notice route and receipt reader joined with the lab broker's historical receipt path, on a
simulated guest that answers the fixture's real command forms.

These cases need the broker's next campaign profile: a version 3 admission, its notice issue, the
NOTICE_VISIBILITY action and the RECEIPT_EVENT read. Without that profile in tests/component-lab
every case is skipped with that reason, which qualifies nothing. The end to end cases further need
ANDRIX_LAB_JAVA and ANDRIX_LAB_CLASSES, a JDK and the lab's compiled bridge, as the lab's own end
to end suite does, and run the accepted Java coordinator and reconciler over the real broker.

The guest model is a test fake shaped by the pinned sources' forms: the helper's reply, the
`content query` rows, `dumpsys power`, `dumpsys window displays`, `am get-current-user` and the
uiautomator dump. Its app decides as the fixture does before anything is shown, refusing a request
whose key holds a conflicting or corrupt row, and reports that decision in the helper's result. It
writes a row once per key, with its own user and serial, after focus and a committed frame while
visible, never rewriting a first row. Each start ends the fixture's earlier activity of that user,
as the helper's task flags do. Host evidence only: nothing here is an Android form or Android
behavior."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
LAB = HERE.parent / 'component-lab'
for _path in (str(HERE), str(LAB)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import notice_reader as reader  # noqa: E402
import notice_route as route  # noqa: E402

try:
    import lab_actions  # noqa: E402
    import lab_broker  # noqa: E402
    import labtest  # noqa: E402
    import sim_android  # noqa: E402
    import test_lab_next  # noqa: E402
    PROFILE = hasattr(lab_broker, 'ADMISSION_3') and hasattr(lab_broker.Broker, 'run_action')
except ImportError:
    PROFILE = False

SKIP = "needs the lab broker's next campaign profile (version 3 admission) in tests/component-lab"
JAR = b'dex\n039\0 the helper jar the guest holds'
APP_ID = 10123
HELPER = re.compile(r'CLASSPATH=%s app_process /system/bin %s (.*)' % (re.escape(route.JAR), re.escape(route.HELPER)))
DUMP = re.compile(r'uiautomator dump (%s)' % (re.escape(route.DEVICE_DIR) + r'/hierarchy-[0-9a-f]{32}\.xml'))
CAT = re.compile(r'cat (%s)' % (re.escape(route.DEVICE_DIR) + r'/hierarchy-[0-9a-f]{32}\.xml'))
NODE = ('<node index="%d" text="%s" resource-id="%s" class="android.widget.TextView" package="%s" content-desc="" '
        'checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" '
        'scrollable="false" long-clickable="false" password="false" selected="false" bounds="%s" drawing-order="1" '
        'hint="">%s</node>')

if PROFILE:
    class NoticeGuest(sim_android.SimAndroid):
        """The simulated guest with the fixture installed in every user, its helper jar pushed, a
        display and the shell commands the route and reader use."""

        def __init__(self, seed=1):
            super().__init__(seed)
            self.files[route.JAR] = JAR
            self.stores = {}
            self.shown = {}
            self.recorded = set()
            self.share_identity = True
            self.focus_and_commit = True
            self.keyguard_covers = False
            self.drop_dump_file = False
            self.challenge_bounds = '[63,300][1017,400]'
            self.unreadable = set()
            self.process_start = {}
            self.decisions = []

        def new_boot(self):
            """A kernel boot ends every activity; the app's device encrypted rows stay."""
            super().new_boot()
            self.shown = {}

        def _settle(self):
            """The app gets focus and a committed frame once its notice is on the current user's
            awake, uncovered display, and writes that notice's row once."""
            user = self.current_user
            notice = self.shown.get(user)
            if (notice is None or not self.awake or self.keyguard_covers or not self.focus_and_commit
                    or notice['key'] in self.recorded):
                return
            self.recorded.add(notice['key'])
            fields = dict(notice['fields'], uid=user * 100000 + APP_ID, user=user, serial=self.serial(user),
                          process_pid=3000 + user, process_start_elapsed=self.process_start.setdefault(user, 1000),
                          resumed_elapsed=self.uptime - 3, focus_elapsed=self.uptime - 2,
                          candidate_rule=reader.CANDIDATE_RULE, candidate_elapsed=self.uptime)
            store = self.stores.setdefault(user, {})
            key = reader.row_key(fields)
            if key in store:
                return  # A repeat or a conflict: the first row stays.
            store[key] = reader.encode_row(fields)

        def _run(self, command):
            self.uptime += 7  # Each command takes a little of the guest's time.
            self._settle()
            reply = self._notice_command(command)
            self._settle()
            return reply

        def _notice_command(self, command):
            match = HELPER.fullmatch(command)
            if match:
                return self._present(command, match[1].split(' '))
            match = reader.QUERY_FORM.fullmatch(command)
            if match:
                return self._query(command, int(match[1]))
            if command == route.CURRENT_USER:
                return sim_android.result(command, 0, b'%d\n' % self.current_user)
            if command == route.POWER:
                state = 'Awake' if self.awake else 'Asleep'
                return sim_android.result(command, 0, ('POWER MANAGER (dumpsys power)\n\nPower Manager State:\n'
                                                       '  mWakefulness=%s\n' % state).encode())
            if command == route.WINDOWS:
                return sim_android.result(command, 0, self._windows().encode())
            match = DUMP.fullmatch(command)
            if match:
                if not self.awake:
                    return sim_android.result(command, 0, b'',
                                              b'ERROR: null root node returned by UiTestAutomationBridge.\n')
                if not self.drop_dump_file:
                    self.files[match[1]] = self._hierarchy()
                return sim_android.result(command, 0, ('UI hierchary dumped to: %s\n' % match[1]).encode())
            match = CAT.fullmatch(command)
            if match:
                if match[1] not in self.files:
                    return sim_android.result(command, 1, b'',
                                              ('cat: %s: No such file or directory\n' % match[1]).encode())
                return sim_android.result(command, 0, self.files[match[1]])
            return super()._run(command)

        def _present(self, command, args):
            """The helper's one start and the fixture activity's decision, which the helper's
            result carries."""
            self.calls.append(('present', int(args[1])))
            user, serial, purpose = int(args[1]), int(args[2]), args[3]
            text = bytes.fromhex(args[13]).decode('ascii')
            if len(args) != 14 or hashlib.sha256(text.encode()).hexdigest() != args[12]:
                return sim_android.result(command, 2, b'andrix-notice-present-v2\nerror=arguments\n')
            self.shown.pop(user, None)  # The new task replaces the fixture's earlier activity.
            notice = purpose == 'TICKET_NOTICE'
            fields = {'purpose': purpose, 'installation': args[4], 'component': args[5],
                      'plan': args[6] if notice else None, 'ticket': args[7] if notice else None,
                      'index': int(args[8]) if notice else None, 'control': None if notice else args[9],
                      'boot': args[10], 'event': args[11], 'text_sha256': args[12]}
            decision = self._decide(user, serial, fields)
            if decision == 'presented':
                key = '/'.join(str(fields[k]) for k in ('purpose', 'boot', 'ticket', 'index', 'control')) + '/%d' % user
                self.shown[user] = {'challenge': args[11], 'fields': fields, 'key': key}
            self.decisions.append(decision)
            reply = ('andrix-notice-present-v2\nresult=0\ntimeout=false\nwho=%s\ntotal_time=%d\nlaunch_state=%d\n'
                     'activity=%s\nreporter=%d\n' % (route.ACTIVITY_SHORT, 180 if decision == 'presented' else -1,
                                                       2 if decision == 'presented' else 0, decision,
                                                       user * 100000 + APP_ID))
            return sim_android.result(command, 0 if decision == 'presented' else 9, reply.encode())

        def _decide(self, user, serial, fields):
            """The fixture activity's decision before anything is shown."""
            if not self.share_identity:
                return 'refused:launcher'
            running = [u for u, _, state in self.users if u == user and state.startswith('RUNNING')]
            if not running:
                return 'refused:user'
            if self.serial(user) != serial:
                return 'refused:serial'
            uid = user * 100000 + APP_ID
            key = reader.row_key(dict(fields, user=user, serial=serial))
            existing = self.stores.get(user, {}).get(key)
            if existing is None:
                return 'presented'
            first = reader.parse_quietly(existing)
            if first is None or reader.row_key(first) != key:
                return 'refused:corrupt'
            same = all(first[k] == v for k, v in fields.items()) and (first['uid'], first['serial']) == (uid, serial)
            return 'presented' if same else 'refused:conflict'

        def _query(self, command, user):
            if user not in [u for u, _, state in self.users if state.startswith('RUNNING')]:
                return sim_android.result(command, 0, b'',
                                          b'Error while accessing provider:dev.andrix.lab.notice.receipts\n')
            serial, uid = self.serial(user), user * 100000 + APP_ID
            if user in self.unreadable:
                status, entries = 'UNREADABLE', []
            elif user not in self.stores:
                status, entries = 'ABSENT', []
            else:
                status, entries = 'OK', []
                for name, data in sorted(self.stores[user].items()):
                    fields = reader.parse_quietly(data)
                    if reader.temporary_name(name):
                        entries.append(('partial', name, data, None))
                    elif fields is None:
                        entries.append(('corrupt', name, data, 'unparseable'))
                    elif reader.row_key(fields) != name:
                        entries.append(('corrupt', name, data, 'key'))
                    elif (fields['uid'], fields['user'], fields['serial']) != (uid, user, serial):
                        entries.append(('corrupt', name, data, 'identity'))
                    else:
                        entries.append(('row', name, data, None))
            lines = reader.listing_lines(user, serial, uid, status, entries)
            return sim_android.result(command, 0, reader.query_output(lines).encode())

        def _windows(self):
            user = self.current_user
            ours = self.awake and not self.keyguard_covers and user in self.shown
            window = ('Window{1a2b3c u%d %s}' % (user, route.ACTIVITY_LONG) if ours
                      else 'Window{4d5e6f u0 NotificationShade}' if self.keyguard_covers else 'null')
            app = 'ActivityRecord{123456 u%d %s t42}' % (user, route.ACTIVITY_SHORT) if ours else 'null'
            return ('WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n  Display: mDisplayId=0\n'
                    '    init=1080x2400 420dpi\n  mCurrentFocus=%s\n  mFocusedApp=%s\n' % (window, app))

        def _hierarchy(self):
            user = self.current_user
            if self.keyguard_covers:
                package, inner = 'com.android.systemui', ''
            elif user in self.shown:
                package = route.PACKAGE
                inner = NODE % (1, self.shown[user]['challenge'], route.CHALLENGE_ID, route.PACKAGE,
                                self.challenge_bounds, '')
            else:
                package, inner = 'com.android.launcher3', ''
            root = NODE % (0, '', '', package, '[0,0][1080,2400]', inner)
            return ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">%s</hierarchy>"
                    % root).encode()

    class JoinReader(sim_android.SimReader):
        """The simulated guest's readers, with the fixture's provider rows read by the strict
        receipt reader for the recipients of the ticket's issued notices."""

        def __init__(self, installation, recipients, **options):
            super().__init__(installation, **options)
            self.notices = reader.NoticeReader(recipients)

        def allowed(self, command):
            return super().allowed(command) or self.notices.allowed(command)

        def bind(self, run):
            super().bind(run)
            self.notices.bind(run)

        def receipt_rows(self, ticket):
            return self.notices.receipt_rows(ticket)

    def recipients(broker, ticket):
        """The recipients of every notice the broker issued for a ticket: what the join needs from
        the broker's issue records."""
        return sorted({(r['user'], r['serial']) for (t, _), issue in broker.issues.items() if t == ticket
                       for r in issue['required']})

    class JoinHarness(labtest.Harness):
        def open(self):
            self.broker = lab_broker.Broker.open(
                self.root, self.source_root, sim_android.SimTransport(self.sim),
                JoinReader(labtest.INSTALLATION, lambda ticket: recipients(self.broker, ticket),
                           target=self.target_read, **self.reader_options),
                notice=self.notice, wall=self.clock.wall_ns, monotonic=self.clock.monotonic_ns, sleep=self.clock.sleep,
                ids=lambda n: os.urandom(n), processes=self.processes, sync=self.sync, target=self.target,
                target_read=self.target_read, health=self.health)
            return self.broker

    Base = test_lab_next.NextBase
    STATUS = test_lab_next.STATUS
    RECEIPT = test_lab_next.RECEIPT
    read_observation = labtest.read_observation
    TICKET = labtest.TICKET
else:
    Base = unittest.TestCase


@unittest.skipUnless(PROFILE, SKIP)
class JoinTests(Base):
    def harness(self, generation=True, **options):
        options.setdefault('health', sim_android.SimHealth())
        h = JoinHarness(next_profile=True, sim=NoticeGuest(),
                        notice=route.NoticeRoute(jar_sha256=hashlib.sha256(JAR).hexdigest()), **options)
        self.addCleanup(h.close)
        self.store(h)
        if generation:
            self.generation(h)
        return h

    def issued(self, h, user=10, serial=5, index=2):
        if (user, serial, 'RUNNING_UNLOCKED') not in h.sim.users:
            h.sim.users.append((user, serial, 'RUNNING_UNLOCKED'))
        self.assertEqual(self.notice(h, index=index)['status'], STATUS['OK'])
        return h.entries('notice-issue')[-1].content

    def delivered(self, h):
        issue = self.issued(h)
        h.sim.tick(200)
        end = self.visible(h)
        self.assertTrue(end['outcome']['qualified'], end)
        return issue, self.groups(h, 'notice-visibility')[-1]

    def read(self, h):
        self.generation(h)
        reply = h.observe()
        return self.envelopes(reply, RECEIPT), self.groups(h, 'receipts')[-1]

    def test_a_presented_and_visible_notice_gives_one_receipt_at_its_proven_delivery(self):
        h = self.harness()
        issue, visible = self.delivered(h)
        presents = [e.content['intent']['command'] for e in h.entries('capture')
                    if e.content['intent']['operation'] == 'notice']
        self.assertEqual([c.split(' ')[0] for c in presents], ['sha256sum', 'CLASSPATH=' + route.JAR, 'sha256sum'])
        self.assertIn(' '.join(route.helper_arguments(issue, issue['required'][0])), presents[1])
        h.sim.tick(40_000)
        receipts, group = self.read(h)
        self.assertEqual(len(receipts), 1)
        fact = read_observation(receipts[0]['observation'])
        row = h.sim.stores[10][next(iter(h.sim.stores[10]))]
        self.assertEqual((fact['user'], fact['serial'], fact['classification']), (10, 5, 2))
        self.assertEqual(fact['elapsed'], visible['brackets']['end']['elapsed'])
        self.assertEqual(receipts[0]['block']['row'], hashlib.sha256(row).hexdigest())
        self.assertEqual([r['judgment'] for r in group['rows']], ['EMITTED'])
        self.assertEqual(reader.parse_row(row)['event'], issue['challenge'])

    def test_a_row_without_its_visibility_group_proves_nothing(self):
        h = self.harness()
        h.sim.current_user = 10
        self.issued(h)
        self.assertTrue(h.sim.stores[10], 'the app wrote its row while visible')
        h.sim.tick(1000)
        receipts, group = self.read(h)
        self.assertEqual((receipts, [r['judgment'] for r in group['rows']]), ([], ['NO_VISIBILITY']))

    def test_no_identity_sharing_and_no_focus_or_frame_give_no_row_and_no_receipt(self):
        for name in ('identity', 'focus'):
            with self.subTest(name):
                h = self.harness()
                if name == 'identity':
                    h.sim.share_identity = False
                else:
                    h.sim.focus_and_commit = False
                self.issued(h)
                h.sim.tick(200)
                end = self.visible(h)
                self.assertEqual(end['outcome']['qualified'], name == 'focus', end)
                receipts, group = self.read(h)
                self.assertEqual((receipts, group['rows'], h.sim.stores), ([], [], {}))

    def test_screen_off_locked_occlusion_and_an_offscreen_challenge_never_qualify(self):
        for name in ('screen off', 'locked occlusion', 'offscreen'):
            with self.subTest(name):
                h = self.harness()
                self.issued(h)
                h.sim.tick(200)
                if name == 'screen off':
                    h.sim.awake = False
                elif name == 'locked occlusion':
                    h.sim.keyguard_covers = True
                else:
                    h.sim.challenge_bounds = '[63,2390][1017,2500]'
                end = self.visible(h)
                self.assertFalse(end['outcome']['qualified'], end)
                receipts, _ = self.read(h)
                self.assertEqual(receipts, [])

    def test_a_stale_or_missing_hierarchy_never_qualifies(self):
        h = self.harness()
        self.issued(h)
        h.sim.drop_dump_file = True
        h.sim.tick(200)
        end = self.visible(h)
        self.assertEqual((end['status'], end['outcome']['qualified']), ('UNAVAILABLE', False), end)
        self.assertIn('no hierarchy file after a reported dump', end['uncertainty'])
        # A hierarchy that shows an earlier notice's challenge is not this notice's delivery.
        old = self.harness()
        self.issued(old, index=2)
        old.sim.tick(200)
        self.visible(old, index=2)
        self.issued(old, index=3)
        old.sim.shown[10]['challenge'] = old.entries('notice-issue')[0].content['challenge']
        stale = self.visible(old, index=3)
        self.assertIn("the visible challenge is not the notice's", stale['outcome']['why_not'])

    def test_the_event_is_the_visibility_completion_never_the_read_or_candidate_time(self):
        h = self.harness()
        _, visible = self.delivered(h)
        candidate = reader.parse_row(next(iter(h.sim.stores[10].values())))['candidate_elapsed']
        h.sim.tick(60_000)
        receipts, group = self.read(h)
        fact = read_observation(receipts[0]['observation'])
        block = receipts[0]['block']
        self.assertEqual(fact['elapsed'], visible['brackets']['end']['elapsed'])
        self.assertNotEqual(fact['elapsed'], candidate)
        self.assertLess(fact['elapsed'], block['read_begin_elapsed'])
        self.assertEqual(block['read_end_elapsed'], group['brackets']['end']['elapsed'])

    def test_an_elapsed_step_or_a_framework_change_in_one_group_qualifies_nothing(self):
        for name in ('step back in the visibility', 'framework in the visibility', 'framework in the read'):
            with self.subTest(name):
                h = self.harness()
                self.issued(h)
                h.sim.tick(200)

                def hook(command, name=name, sim=h.sim):
                    if name == 'step back in the visibility' and command.startswith('uiautomator dump'):
                        sim.uptime -= 5_000
                    if name == 'framework in the visibility' and command.startswith('uiautomator dump'):
                        sim.framework_restart()
                    if name == 'framework in the read' and reader.QUERY_FORM.fullmatch(command):
                        sim.framework_restart()
                if name == 'framework in the read':
                    self.visible(h)
                    h.sim.hooks.append(hook)
                    receipts, group = self.read(h)
                    self.assertEqual((receipts, group['status']), ([], 'unavailable'))
                    self.assertEqual([r['judgment'] for r in group['rows']], ['UNBRACKETED'])
                    h.sim.hooks.remove(hook)
                    h.end(0)
                    receipts, _ = self.read(h)
                    self.assertEqual(len(receipts), 1, 'a later whole read in one framework still proves it')
                else:
                    h.sim.hooks.append(hook)
                    end = self.visible(h)
                    h.sim.hooks.remove(hook)
                    self.assertFalse(end['outcome']['qualified'], end)
                    self.assertIn('bracket', end['outcome']['why_not'])
                    h.sim.tick(10_000)  # Past the broker's high water mark of this boot again.
                    receipts, _ = self.read(h)
                    self.assertEqual(receipts, [])

    def test_the_original_time_survives_a_lost_generation_and_a_later_framework(self):
        h = self.harness()
        _, visible = self.delivered(h)
        h.sim.tick(1000)
        receipts, _ = self.read(h)
        first = read_observation(receipts[0]['observation'])
        h.end(137)  # The coordinator's JVM is lost after the read: nothing of it reached the store.
        h.sim.tick(30_000)
        receipts, _ = self.read(h)
        again = read_observation(receipts[0]['observation'])
        self.assertEqual(again['elapsed'], first['elapsed'])
        self.assertNotEqual(again['observation'], first['observation'])
        h.end(0)
        h.reopen()
        h.sim.framework_restart()
        h.sim.tick(5_000)
        receipts, _ = self.read(h)
        later = read_observation(receipts[0]['observation'])
        self.assertEqual((later['elapsed'], later['instance'], receipts[0]['block']['delivery_instance']),
                         (visible['brackets']['end']['elapsed'], h.sim.instance, first['instance']))

    def test_a_prior_boot_another_serial_or_index_and_a_changed_row_prove_nothing(self):
        h = self.harness()
        self.delivered(h)
        h.end(0)
        h.sim.reboot()
        receipts, group = self.read(h)
        self.assertEqual((receipts, [r['judgment'] for r in group['rows']]), ([], ['OTHER_BOOT']))
        cases = {'another serial': {'serial': 6}, 'another index': {'index': 9}}
        for name, change in cases.items():
            with self.subTest(name):
                h = self.harness()
                self.delivered(h)
                store = h.sim.stores[10]
                (key, data), = store.items()
                fields = dict(reader.parse_row(data), **change)
                store[reader.row_key(fields)] = reader.encode_row(fields)
                receipts, group = self.read(h)
                self.assertEqual((receipts, group['status']), ([], 'refused'))
        changed = self.harness()
        self.delivered(changed)
        receipts, _ = self.read(changed)
        self.assertEqual(len(receipts), 1)
        store = changed.sim.stores[10]
        (key, data), = store.items()
        store[key] = reader.encode_row(dict(reader.parse_row(data),
                                            candidate_elapsed=reader.parse_row(data)['candidate_elapsed'] + 1))
        receipts, group = self.read(changed)
        self.assertEqual((receipts, group['reason']), ([], 'a row changed after it was first read'))

    def test_a_redisplay_keeps_the_first_row_and_its_proven_time(self):
        h = self.harness()
        issue, visible = self.delivered(h)
        first = dict(h.sim.stores[10])
        h.sim.tick(5_000)
        self.between(h)
        outcome = h.broker.notice.present(lambda command: h.sim.shell(command, 10, 1 << 20, 1 << 16), issue)
        self.assertEqual(outcome, 'SUCCESS')
        self.assertEqual(h.sim.stores[10], first)
        receipts, _ = self.read(h)
        self.assertEqual(read_observation(receipts[0]['observation'])['elapsed'],
                         visible['brackets']['end']['elapsed'])

    def test_a_conflicting_presentation_is_refused_shows_nothing_and_writes_nothing(self):
        h = self.harness()
        issue, visible = self.delivered(h)
        store = h.sim.stores[10]
        (key, data), = store.items()
        first = reader.parse_row(data)
        # A row already under the key that the next notice, entry 3, will have: another challenge.
        stale = dict(first, index=3, event='9d' * 16)
        store[reader.row_key(stale)] = reader.encode_row(stale)
        before = dict(store)
        self.generation(h)
        self.assertEqual(self.notice(h, index=3)['status'], STATUS['OK'])
        outcome = h.entries('outcome')[-1].content
        self.assertEqual(outcome['reply']['classification'], 'REFUSED')
        self.assertEqual(h.sim.decisions[-1], 'refused:conflict')
        self.assertEqual((h.sim.stores[10], h.sim.shown), (before, {}))
        issue3 = h.entries('notice-issue')[-1].content
        self.assertNotEqual(issue3['challenge'], stale['event'])
        unseen = self.visible(h, index=3)
        self.assertFalse(unseen['outcome']['qualified'])
        # The row under entry 3's key contradicts entry 3's issue, so the broker refuses the whole
        # read wherever that row stands: the conflict is never hidden, and nothing is proven.
        receipts, group = self.read(h)
        self.assertEqual((receipts, group['status']), ([], 'refused'))
        self.assertEqual(group['reason'], "a row whose event or text is not its notice's")
        # Beside it, the honest repeat of entry 2 is shown again and keeps the first row.
        self.between(h)
        honest = h.broker.notice.present(lambda command: h.sim.shell(command, 10, 1 << 20, 1 << 16), issue)
        self.assertEqual((honest, h.sim.decisions[-1], h.sim.stores[10]), ('SUCCESS', 'presented', before))
        self.assertEqual(h.sim.shown[10]['challenge'], issue['challenge'])
        self.assertTrue(visible['qualified'])

    def test_an_unreadable_store_or_a_refused_provider_read_is_never_empty(self):
        for name in ('unreadable', 'stopped'):
            with self.subTest(name):
                h = self.harness()
                self.delivered(h)
                if name == 'unreadable':
                    h.sim.unreadable.add(10)
                else:
                    h.sim.users = [u for u in h.sim.users if u[0] != 10] + [(10, 5, 'NOT_RUNNING')]
                receipts, group = self.read(h)
                self.assertEqual((receipts, group['status'], group['emitted']), ([], 'unavailable', False))

    def test_per_family_allowlists_admit_no_foreign_command(self):
        h = self.harness()
        self.issued(h)
        route_ = h.broker.notice
        self.assertFalse(route_.allowed(route.CURRENT_USER) or route_.allowed(route.DIGEST_COMMAND))
        self.assertFalse(h.broker.reader.allowed('content insert --uri %s --user 10' % reader.ROWS_URI))
        self.assertFalse(h.broker.reader.allowed(route.DIGEST_COMMAND))


JAVA = os.environ.get('ANDRIX_LAB_JAVA')
CLASSES = os.environ.get('ANDRIX_LAB_CLASSES')
MAIN = 'dev.andrix.lab.component.LabBridgeTestMain'
JVM = ('-Xmx256m', '-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1', '-XX:MaxMetaspaceSize=128m',
       '-XX:ReservedCodeCacheSize=48m', '-ea')


@unittest.skipUnless(PROFILE and JAVA and CLASSES, SKIP + ', ANDRIX_LAB_JAVA and ANDRIX_LAB_CLASSES')
class EndToEndTests(unittest.TestCase):
    """The accepted Java coordinator and reconciler, through the lab's Java bridge, against the
    real broker joined with the notice route and reader, as the lab's own end to end suite runs."""

    def world(self, activate=900_000):
        temporary = tempfile.TemporaryDirectory(prefix='notice-e2e-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.dir, self.store = root, root / 'store'
        self.sim = NoticeGuest()
        manifest = labtest.manifest_bytes()
        config = self.java('setup3', str(root), str(self.store), hashlib.sha256(manifest).hexdigest(), labtest.PLAN,
                           TICKET, '120000', str(activate)).strip()
        self.config = root / 'bridge.config'
        admission = labtest.admission3(root, store=self.store, config=config)
        lab_broker.Broker.initialize(root / 'broker', admission, manifest)
        self.broker = lab_broker.Broker.open(
            root / 'broker', labtest.REPO, sim_android.SimTransport(self.sim),
            JoinReader(labtest.INSTALLATION, lambda ticket: recipients(self.broker, ticket), receipts=True,
                       inventory=True, health=True, witness=True),
            notice=route.NoticeRoute(jar_sha256=hashlib.sha256(JAR).hexdigest()), sync=False,
            health=sim_android.SimHealth())
        self.addCleanup(self.broker.close)
        apk, idsig = b'A' * 4096 + b'variant', b'S' * 512 + b'sidecar'
        self.bundle = hashlib.sha256(apk).hexdigest()
        members = {}
        for member, data in (('base.apk', apk), ('base.apk.idsig', idsig)):
            (root / member).write_bytes(data)
            members[member] = {'host': str(root / member), 'sha256': hashlib.sha256(data).hexdigest(),
                               'bytes': len(data)}
        self.broker.pin_artifacts(labtest.PLAN, members,
                                  hashlib.sha256(('publication ' + labtest.PLAN).encode()).hexdigest())
        self.sim.apks[self.bundle] = 40

    def java(self, *args):
        done = subprocess.run([JAVA, *JVM, '-Djava.io.tmpdir=%s' % self.dir, '-cp', CLASSES, MAIN, *args],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        return done.stdout

    def generation(self):
        argv = [JAVA, *JVM, '-Djava.io.tmpdir=%s' % self.dir, '-Dandrix.lab.hostDir=%s' % (self.dir / 'host'),
                '-Dandrix.lab.bundleApk=%s' % self.bundle, '-Dandrix.lab.restorationApk=%s' % ('a2' * 32), '-cp',
                CLASSES, MAIN, str(self.config), 'settle', TICKET, '40']
        return self.broker.run_generation(argv)

    def inspect(self):
        line = self.java('inspect', str(self.store), TICKET).strip()
        return dict(part.split('=', 1) for part in line.split(' '))

    def stored_receipts(self):
        facts = [read_observation(p.read_bytes()) for p in sorted((self.store / 'observations').glob('*.rec'))]
        return [f for f in facts if f['kind'] == 12]

    def outcomes(self, crossing):
        records = {e.number: e.content for e in self.broker.ledger.entries if e.kind == 'crossing'}
        return [records[e.content['crossing']] for e in self.broker.ledger.entries if e.kind == 'outcome'
                and records.get(e.content['crossing'], {}).get('crossing') == crossing]

    def test_the_reconciler_counts_the_delay_from_the_fixtures_proven_delivery(self):
        self.world()
        self.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        self.assertEqual(self.generation()['status'], 'COMPLETE')
        issue = [e.content for e in self.broker.ledger.entries if e.kind == 'notice-issue'][-1]
        self.sim.tick(1000)
        self.sim.current_user = 10
        end = self.broker.run_action(labtest.VISIBILITY_ACTION, 'capture the notice', ticket=TICKET,
                                     index=issue['index'], serial=5)
        self.assertTrue(end['outcome']['qualified'], end)
        proven = [e.content for e in self.broker.ledger.entries if e.kind == 'group'
                  and e.content.get('reader') == 'notice-visibility'][-1]['brackets']['end']['elapsed']
        for _ in range(8):
            self.sim.tick(40_000)
            self.assertEqual(self.generation()['status'], 'COMPLETE')
            if [c for c in self.sim.calls if c[0] == 'CREATE']:
                break
        create = self.outcomes('CREATE')[0]
        self.assertGreaterEqual(create['entry_elapsed'] - proven, 120_000)
        self.assertLess(create['entry_elapsed'] - proven, 160_000)
        stored = self.stored_receipts()
        self.assertTrue(stored)
        self.assertEqual({(f['user'], f['serial'], f['elapsed']) for f in stored}, {(10, 5, proven)})

    def test_without_a_qualified_visibility_the_notice_budget_ends_and_nothing_is_staged(self):
        self.world()
        self.sim.users.append((10, 5, 'RUNNING_UNLOCKED'))
        for _ in range(10):
            self.assertEqual(self.generation()['status'], 'COMPLETE')
            self.sim.tick(130_000)
        presents = [c for c in self.sim.calls if c[0] == 'present']
        state = self.inspect()
        self.assertEqual((len(presents), self.sim.stores, self.stored_receipts()), (4, {}, []))
        self.assertEqual(state['ledger'].split(',').count('NOTICE'), 4, state)
        self.assertNotIn('CREATE', state['ledger'].split(','))
        self.assertEqual([c for c in self.sim.calls if c[0] in ('CREATE', 'reboot')], [])


if __name__ == '__main__':
    unittest.main()
