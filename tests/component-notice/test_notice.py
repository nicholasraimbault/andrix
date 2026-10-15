# SPDX-License-Identifier: Apache-2.0
"""Host tests of the notice route and the receipt reader: strict row and listing framing, the
provider read's refusals, the store binding of rows, the helper's command and reply forms, and the
visibility projection from source derived guest forms. Each changed copy must fail for its own
reason while its honest original passes. Host evidence only: no guest form here is calibrated."""
import hashlib
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import notice_reader as reader  # noqa: E402
import notice_route as route  # noqa: E402
import lab_readers  # noqa: E402

GOLDENS = HERE / 'goldens'
INSTALLATION = '00112233445566778899aabbccddeeff'
COMPONENT = 'com.android.systemui'
PLAN, TICKET = '01' * 16, '04' * 16
BOOT = '3b8f0e2d9c4a6b1f7e5d2c0a8b6f4e13'
EVENT = '8c0e3f7a91b24d6e5a17c3f9d2e4b608'
TEXT = ('Andrix will restart this device to change %s. The device owner approved it. Notice %s, ticket %s, entry 2.'
        % (COMPONENT, EVENT, TICKET))
UID = 10 * 100000 + 10123
JAR_SHA = 'ab' * 32


class Result:
    """A whole shell result as the transport gives it."""

    def __init__(self, exit=0, stdout=b'', stderr=b'', completed=True, overflow=None):
        self.exit, self.stdout, self.stderr = exit, stdout, stderr
        self.completed, self.overflow = completed, overflow


def golden(name):
    return (GOLDENS / name).read_bytes()


def row_fields(**changes):
    fields = reader.parse_row(golden('row-ticket_notice.row'))
    fields.update(changes)
    return fields


def issue(**changes):
    value = {'purpose': 'TICKET_NOTICE', 'installation': INSTALLATION, 'component': COMPONENT, 'plan': PLAN,
             'ticket': TICKET, 'index': 2, 'boot': BOOT, 'challenge': EVENT, 'text': TEXT,
             'text_sha256': hashlib.sha256(TEXT.encode()).hexdigest(),
             'required': [{'user': 10, 'serial': 5, 'type': 'android.os.usertype.full.SECONDARY'}]}
    value.update(changes)
    return value


class RowTests(unittest.TestCase):
    def test_the_goldens_are_rows_and_the_codec_is_their_exact_inverse(self):
        for name in ('ticket_notice', 'qualification'):
            data = golden('row-%s.row' % name)
            fields = reader.parse_row(data)
            self.assertEqual(reader.encode_row(fields), data)
            self.assertEqual(reader.row_key(fields) + '\n', golden('row-%s.name' % name).decode())
            self.assertTrue(reader.key_name(reader.row_key(fields)))
            self.assertEqual((fields['uid'], fields['user'], fields['serial']), (UID, 10, 5))
        q = reader.parse_row(golden('row-qualification.row'))
        self.assertEqual((q['plan'], q['ticket'], q['index'], q['control']),
                         (None, None, None, 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'))

    def test_every_change_outside_the_canonical_form_is_refused(self):
        good = golden('row-ticket_notice.row').decode()
        changes = {
            'magic': good.replace('receipt-v1', 'receipt-v2'), 'cut': good[:-1], 'carriage return':
            good.replace('\nuid=', '\r\nuid='), 'extra line': good + 'extra=1\n', 'blank line': good + '\n',
            'reordered': good.replace('uid=1010123\nuser=10\n', 'user=10\nuid=1010123\n'),
            'leading zero': good.replace('\nserial=5\n', '\nserial=05\n'),
            'uppercase': good.replace(BOOT, BOOT.upper()),
            'uid of another user': good.replace('uid=1010123', 'uid=1110123'),
            'system uid': good.replace('uid=1010123', 'uid=1001000'),
            'candidate before focus': good.replace('candidate_elapsed=2500', 'candidate_elapsed=2099'),
            'another rule': good.replace('focus-then-frame-commit', 'draw'),
            'a notice naming a control': good.replace('\ncontrol=-\n', '\ncontrol=' + 'cd' * 16 + '\n'),
            'index at the bound': good.replace('\nindex=2\n', '\nindex=140\n'),
            'zero installation': good.replace(INSTALLATION, '0' * 32),
        }
        for name, text in changes.items():
            with self.subTest(name):
                self.assertNotEqual(text, good)
                with self.assertRaises(reader.RowError):
                    reader.parse_row(text.encode('latin-1'))
        for data in (b'', bytes(reader.MAX_ROW + 1), good.encode().replace(b'systemui', b'system\xfcui')):
            with self.assertRaises(reader.RowError):
                reader.parse_row(data)

    def test_key_and_temporary_names(self):
        key = golden('row-ticket_notice.name').decode().strip()
        self.assertTrue(reader.key_name(key))
        self.assertTrue(reader.temporary_name('.' + key + '.00000000000000aa.tmp'))
        for bad in (key + '.tmp', key.replace('.2.10.', '.140.10.'), key.replace('TICKET_NOTICE', 'NOTICE'),
                    'x' + key, key.replace('.10.5.row', '.10.05.row')):
            self.assertFalse(reader.key_name(bad), bad)
        for bad in (key, '.' + key + '.0000000000000000.tmp', '.' + key + '.00aa.tmp', key + '.00000000000000aa.tmp'):
            self.assertFalse(reader.temporary_name(bad), bad)


class ListingTests(unittest.TestCase):
    def query(self, lines):
        return reader.query_output(lines)

    def test_the_goldens_parse_and_the_twin_writes_them_byte_for_byte(self):
        for name, status in (('ok', 'OK'), ('absent', 'ABSENT'), ('unreadable', 'UNREADABLE')):
            lines = golden('listing-%s.txt' % name).decode().splitlines()
            parsed = reader.parse_listing(reader.parse_query(0, self.query(lines), ''))
            self.assertEqual(parsed['status'], status)
            entries = [(e['kind'], e['name'], e['data'], e['reason']) for e in parsed['entries']]
            self.assertEqual(reader.listing_lines(parsed['user'], parsed['serial'], parsed['uid'], status, entries),
                             lines)

    def test_an_unreadable_or_overflowing_store_is_never_empty(self):
        for status in ('UNREADABLE', 'OVERFLOW'):
            out = self.query(reader.listing_lines(10, 5, UID, status, []))
            with self.assertRaises(lab_readers.Unavailable):
                reader.store_read(0, out, '', 10, 5)
        absent = reader.store_read(0, self.query(reader.listing_lines(10, 5, UID, 'ABSENT', [])), '', 10, 5)
        self.assertEqual(absent['rows'], [])

    def test_provider_replies_of_another_form_are_refused(self):
        lines = golden('listing-ok.txt').decode().splitlines()
        good = self.query(lines)
        self.assertTrue(reader.store_read(0, good, '', 10, 5)['rows'])
        unclassified = {
            'no result': 'No result found.\n', 'cut': good[:-1], 'renumbered': good.replace('Row: 1 ', 'Row: 2 ', 1),
            'extra line': good + 'Row: %d line=x\n' % len(lines), 'no end': self.query(lines[:-1]),
            'counts': self.query(lines[:-1] + [lines[-1].replace('rows=1', 'rows=2')]),
            'digest': self.query(lines[:-1] + [lines[-1][:-1] + ('0' if lines[-1][-1] != '0' else '1')]),
            'reordered': self.query([lines[0], lines[2], lines[1]] + lines[3:]),
            'a dropped entry': self.query([lines[0]] + lines[2:]),
            'size': self.query([lines[0], lines[1].replace(' 40 ', ' 41 ', 1)] + lines[2:]),
        }
        for name, out in unclassified.items():
            with self.subTest(name):
                with self.assertRaises(lab_readers.Unclassified):
                    reader.store_read(0, out, '', 10, 5)
        with self.assertRaises(lab_readers.Unclassified) as empty:
            reader.parse_query(0, 'No result found.\n', '')
        self.assertIn('never an empty store', str(empty.exception))
        with self.assertRaises(lab_readers.Unavailable):
            reader.store_read(0, '', 'Error while accessing provider:dev.andrix.lab.notice.receipts\n', 10, 5)
        with self.assertRaises(lab_readers.Unclassified):
            reader.store_read(1, good, '', 10, 5)
        for user, serial in ((11, 5), (10, 6)):
            with self.assertRaises(lab_readers.Unclassified):
                reader.store_read(0, good, '', user, serial)
        other_uid = self.query(reader.listing_lines(10, 5, 10 * 100000 + 1000, 'OK', []))
        with self.assertRaises(lab_readers.Unclassified):
            reader.store_read(0, other_uid, '', 10, 5)

    def test_rows_keep_their_bytes_and_the_store_binding_decides_their_form(self):
        data = golden('row-ticket_notice.row')
        fields = reader.parse_row(data)
        key = reader.row_key(fields)
        partial = ('partial', '.' + key + '.00000000000000aa.tmp', data[:40], None)
        out = self.query(reader.listing_lines(10, 5, UID, 'OK', [partial, ('row', key, data, None)]))
        rows = reader.store_read(0, out, '', 10, 5)['rows']
        self.assertEqual(len(rows), 1, 'a partial write is never a row')
        self.assertEqual(set(rows[0]), set(reader.ROW_KEYS))
        self.assertEqual(rows[0]['row'], data)
        self.assertEqual((rows[0]['user'], rows[0]['serial'], rows[0]['candidate_elapsed']), (10, 5, 2500))
        # Another user's row in this user's store keeps its bytes but names no identity.
        other = dict(fields, uid=11 * 100000 + 10123, user=11, serial=7)
        other_data = reader.encode_row(other)
        out = self.query(reader.listing_lines(10, 5, UID, 'OK', [('row', reader.row_key(other), other_data, None)]))
        row = reader.store_read(0, out, '', 10, 5)['rows'][0]
        self.assertEqual((row['row'], row['uid'], row['user'], row['serial']), (other_data, None, None, None))
        # A corrupt entry keeps its bytes, or names none, and has no known form.
        out = self.query(reader.listing_lines(10, 5, UID, 'OK', [('corrupt', key, b'damaged', 'unparseable')]))
        row = reader.store_read(0, out, '', 10, 5)['rows'][0]
        self.assertEqual(row, dict({k: None for k in reader.ROW_KEYS}, row=b'damaged'))
        out = self.query(reader.listing_lines(10, 5, UID, 'OK', [('corrupt', key, None, 'not-regular')]))
        self.assertEqual(reader.store_read(0, out, '', 10, 5)['rows'][0]['row'], None)
        # A temporary that is no regular file is listed as corrupt by its own name, never a row.
        odd = ('corrupt', '.' + key + '.00000000000000ab.tmp', None, 'not-regular')
        out = self.query(reader.listing_lines(10, 5, UID, 'OK', [odd]))
        self.assertEqual(reader.store_read(0, out, '', 10, 5)['rows'], [dict({k: None for k in reader.ROW_KEYS})])
        for bad in (('row', '.' + key + '.00000000000000ab.tmp', data, None),
                    ('partial', key, data[:40], None),
                    ('corrupt', '.' + key + '.00000000000000ab.tmp', b'damaged', 'unparseable')):
            out = self.query(reader.listing_lines(10, 5, UID, 'OK', [bad]))
            with self.assertRaises(lab_readers.Unclassified):
                reader.store_read(0, out, '', 10, 5)


class ReaderTests(unittest.TestCase):
    def test_a_read_covers_each_recipient_store_whole_or_raises(self):
        data = golden('row-ticket_notice.row')
        key = reader.row_key(reader.parse_row(data))
        stores = {10: reader.listing_lines(10, 5, UID, 'OK', [('row', key, data, None)]),
                  11: reader.listing_lines(11, 7, 11 * 100000 + 10123, 'ABSENT', [])}
        commands = []

        def run(command):
            commands.append(command)
            user = int(command.rsplit(' ', 1)[1])
            return 0, reader.query_output(stores[user]), ''
        notice = reader.NoticeReader(lambda ticket: [(11, 7), (10, 5)])
        self.assertTrue(all(notice.allowed(reader.QUERY % u) for u in (0, 10, 21473)))
        for bad in ('content query --uri %s --user 010' % reader.ROWS_URI, 'content query --uri x --user 10',
                    reader.QUERY % 10 + ' --where x', 'content insert --uri %s --user 10' % reader.ROWS_URI):
            self.assertFalse(notice.allowed(bad), bad)
        with self.assertRaises(lab_readers.Unavailable):
            notice.receipt_rows(TICKET)
        notice.bind(run)
        rows = notice.receipt_rows(TICKET)
        self.assertEqual(commands, [reader.QUERY % 10, reader.QUERY % 11])
        self.assertEqual([r['row'] for r in rows], [data])
        self.assertEqual([r['status'] for r in notice.last_reads], ['OK', 'ABSENT'])
        stores[11] = reader.listing_lines(11, 7, 11 * 100000 + 10123, 'UNREADABLE', [])
        with self.assertRaises(lab_readers.Unavailable):
            notice.receipt_rows(TICKET)
        two = reader.NoticeReader(lambda ticket: [(10, 5), (10, 6)])
        two.bind(run)
        with self.assertRaises(lab_readers.Unclassified):
            two.receipt_rows(TICKET)


class PresentTests(unittest.TestCase):
    def helper_reply(self, code=0, result=0, who=route.ACTIVITY_SHORT, timeout='false', activity='presented',
                     reporter=UID, header=route.HELPER_HEADER):
        body = ('result=%d\ntimeout=%s\nwho=%s\ntotal_time=321\nlaunch_state=1\nactivity=%s\nreporter=%d\n'
                % (result, timeout, who, activity, reporter))
        return Result(code, (header + '\n' + body).encode())

    def refused(self, why='conflict'):
        """The helper's result when the recipient's activity refused the request."""
        return self.helper_reply(code=9, activity='refused:' + why, who=route.ACTIVITY_SHORT)

    def test_the_helper_arguments_are_the_issue_and_recipient_exactly(self):
        args = route.helper_arguments(issue(), {'user': 10, 'serial': 5})
        self.assertEqual(args, golden('request-ticket_notice.args').decode().split('\n')[:-1])
        command = route.helper_command(args)
        self.assertEqual(command, 'CLASSPATH=/data/local/tmp/andrix-notice/andrix-notice-present.jar app_process '
                         '/system/bin dev.andrix.lab.notice.NoticePresent ' + ' '.join(args))
        q = issue(purpose='QUALIFICATION', plan=None, ticket=None, index=None,
                  control='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
                  text='Andrix notice screen check %s.' % EVENT,
                  text_sha256=hashlib.sha256(('Andrix notice screen check %s.' % EVENT).encode()).hexdigest())
        self.assertEqual(route.helper_arguments(q, {'user': 10, 'serial': 5}),
                         golden('request-qualification.args').decode().split('\n')[:-1])
        bad = {'purpose': {'purpose': 'NOTICE'}, 'zero boot': {'boot': '0' * 32},
               'text digest': {'text_sha256': 'ab' * 32},
               'index': {'index': 140}, 'text': {'text': TEXT + '\n'}, 'component': {'component': 'systemui'},
               'challenge': {'challenge': EVENT.upper()}}
        for name, change in bad.items():
            with self.subTest(name):
                with self.assertRaises(lab_readers.Unclassified):
                    route.helper_arguments(issue(**change), {'user': 10, 'serial': 5})
        with self.assertRaises(lab_readers.Unclassified):
            route.helper_arguments(issue(), {'user': 10, 'serial': -1})

    def test_helper_replies_are_success_refusal_or_unrecognized(self):
        self.assertEqual(route.classify_helper(self.helper_reply(), 10), 'SUCCESS')
        cases = {
            'REFUSED': [Result(3, b'andrix-notice-present-v2\nerror=identity\n'),
                        Result(2, b'andrix-notice-present-v2\nerror=arguments\n'),
                        Result(5, b'andrix-notice-present-v2\nerror=signature\n'),
                        Result(6, b'andrix-notice-present-v2\nerror=start:java.lang.SecurityException\n'),
                        self.helper_reply(code=7, result=-94, who='null', activity='unreported', reporter=-1),
                        *(self.refused(why) for why in route.ACTIVITY_REFUSALS)],
            'UNRECOGNIZED': [self.helper_reply(timeout='true'), self.helper_reply(who='other/.Activity'),
                             self.helper_reply(code=7, result=2, activity='unreported', reporter=-1),
                             self.helper_reply(code=7, result=100, activity='unreported', reporter=-1),
                             self.helper_reply(code=7, result=-94, who='null'),
                             self.helper_reply(code=10, activity='unreported', reporter=-1),
                             self.helper_reply(code=0, activity='refused:conflict'),
                             self.helper_reply(code=9, activity='presented'),
                             self.helper_reply(code=9, activity='refused:other'),
                             self.helper_reply(reporter=11 * 100000 + 10123),
                             self.helper_reply(reporter=10 * 100000 + 1000),
                             self.helper_reply(code=9, activity='refused:conflict', reporter=-1),
                             self.helper_reply(header='andrix-notice-present-v1'),
                             Result(6, b'andrix-notice-present-v2\nerror=start:android.os.DeadObjectException\n'),
                             Result(8, b'andrix-notice-present-v2\nerror=result:java.lang.NoSuchFieldException\n'),
                             Result(0, self.helper_reply().stdout, b'warning\n'), Result(0, b'\n'),
                             Result(3, b'andrix-notice-present-v2\nerror=arguments\n')],
        }
        for expected, results in cases.items():
            for result in results:
                with self.subTest(expected=expected, stdout=result.stdout):
                    self.assertEqual(route.classify_helper(result, 10), expected)
        self.assertEqual(route.classify_helper(self.helper_reply(), 11), 'UNRECOGNIZED',
                         "another user's app reported for this recipient")
        with self.assertRaises(lab_readers.Unavailable):
            route.classify_helper(Result(completed=False), 10)

    def present(self, replies, digests=(JAR_SHA, JAR_SHA), required=None):
        notice = route.NoticeRoute(jar_sha256=JAR_SHA)
        ran = []
        digests = list(digests)

        def run(command):
            self.assertTrue(notice.allowed(command), command)
            ran.append(command)
            if command == route.DIGEST_COMMAND:
                return Result(0, ('%s  %s\n' % (digests.pop(0), route.JAR)).encode())
            return replies.pop(0)
        value = issue(required=required or [{'user': 10, 'serial': 5, 'type': 't'}])
        outcome = notice.present(run, value)
        self.assertFalse(notice.allowed(ran[0]), 'nothing is admitted outside a call')
        return outcome, ran

    def test_present_checks_the_jar_runs_the_helper_per_recipient_and_checks_again(self):
        two = [{'user': 10, 'serial': 5, 'type': 't'}, {'user': 11, 'serial': 7, 'type': 't'}]
        eleven = self.helper_reply(reporter=11 * 100000 + 10123)
        outcome, ran = self.present([self.helper_reply(), eleven], required=two)
        self.assertEqual(outcome, 'SUCCESS')
        self.assertEqual([c.split(' ')[0] for c in ran], ['sha256sum', route.helper_command([]).split(' ')[0],
                                                          route.helper_command([]).split(' ')[0], 'sha256sum'])
        self.assertIn(' 1 10 5 TICKET_NOTICE ', ran[1])
        self.assertIn(' 1 11 7 TICKET_NOTICE ', ran[2])
        refused = Result(3, b'andrix-notice-present-v2\nerror=identity\n')
        self.assertEqual(self.present([refused, refused], required=two)[0], 'REFUSED')
        self.assertEqual(self.present([self.helper_reply(), refused], required=two)[0], 'UNRECOGNIZED')
        self.assertEqual(self.present([self.helper_reply(), self.helper_reply()], required=two)[0], 'UNRECOGNIZED',
                         "user 10's app reported for user 11")

    def test_a_conflicting_presentation_is_refused_beside_the_honest_repeat(self):
        # The honest repeat is presented again; a request whose key holds another row is refused by
        # the activity before anything is shown, and the helper's result says so.
        self.assertEqual(self.present([self.helper_reply()])[0], 'SUCCESS')
        outcome, ran = self.present([self.refused('conflict')])
        self.assertEqual((outcome, len(ran)), ('REFUSED', 3))
        self.assertEqual(self.present([self.refused('corrupt')])[0], 'REFUSED')
        self.assertEqual(self.present([self.helper_reply(code=10, activity='unreported', reporter=-1)])[0],
                         'UNRECOGNIZED')
        outcome, ran = self.present([], digests=('cd' * 32,))
        self.assertEqual((outcome, len(ran)), ('REFUSED', 1))
        self.assertEqual(self.present([self.helper_reply()], digests=(JAR_SHA, 'cd' * 32))[0], 'UNRECOGNIZED')

    def test_a_route_admits_only_the_commands_of_its_current_call(self):
        notice = route.NoticeRoute(jar_sha256=JAR_SHA, nonce=lambda: 'ef' * 16)
        seen = {}

        def effect(command):
            seen.setdefault('effect', []).append(notice.allowed(command))
            seen['present'] = notice.allowed(route.DIGEST_COMMAND)
            return Result(0, ('UI hierchary dumped to: %s\n' % (route.HIERARCHY % ('ef' * 16))).encode())

        def read(command):
            seen.setdefault('read', []).append(notice.allowed(command))
            raise lab_readers.Unavailable('stop here')
        with self.assertRaises(lab_readers.Unavailable):
            notice.visibility(effect, read, issue(), {'id': 10, 'serial': 5, 'type': 't'})
        self.assertEqual(seen['read'], [True])
        self.assertFalse(notice.allowed(route.CURRENT_USER))
        self.assertFalse(notice.allowed(route.DIGEST_COMMAND))
        with self.assertRaises(lab_readers.Unclassified):
            notice.notice(None, TICKET, 2, PLAN)


def power(state='Awake'):
    return Result(0, ('POWER MANAGER (dumpsys power)\n\nPower Manager State:\n  mDirty=0x0\n  mWakefulness=%s\n'
                      '  mWakefulnessChanging=false\nmWakefulness=1\n' % state).encode())


def window(focus='ours', user=10):
    windows = {'ours': 'Window{1a2b3c u%d %s}' % (user, route.ACTIVITY_LONG),
               'shade': 'Window{4d5e6f u0 NotificationShade}', 'none': 'null',
               'exiting': 'Window{1a2b3c u%d %s EXITING}' % (user, route.ACTIVITY_LONG)}
    apps = {'ours': 'ActivityRecord{123456 u%d %s t42}' % (user, route.ACTIVITY_SHORT), 'shade': 'null',
            'none': 'null', 'exiting': 'ActivityRecord{123456 u%d %s t42 f}}' % (user, route.ACTIVITY_SHORT)}
    text = ('WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n  Display: mDisplayId=0\n'
            '    init=1080x2400 420dpi\n  mCurrentFocus=%s\n  mFocusedApp=%s\n  Display: mDisplayId=2\n'
            '  mCurrentFocus=null\n  mFocusedApp=null\n' % (windows[focus], apps[focus]))
    return Result(0, text.encode())


NODE = ('<node index="%d" text="%s" resource-id="%s" class="android.widget.TextView" package="%s" content-desc="" '
        'checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" '
        'scrollable="false" long-clickable="false" password="false" selected="false" bounds="%s" drawing-order="1" '
        'hint="">%s</node>')


def hierarchy(challenge=EVENT, package=route.PACKAGE, bounds='[63,300][1017,400]', root_bounds='[0,0][1080,2400]',
              twice=False):
    inner = NODE % (1, challenge, route.CHALLENGE_ID, route.PACKAGE, bounds, '')
    if twice:
        inner += NODE % (2, challenge, route.CHALLENGE_ID, route.PACKAGE, bounds, '')
    root = NODE % (0, '', '', package, root_bounds, inner)
    return ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">%s</hierarchy>"
            % root).encode()


class VisibilityTests(unittest.TestCase):
    def capture(self, states=None, after=None, xml=None, dump=None, cat=None):
        """One capture against scripted replies: (projection or exception, commands run)."""
        path = route.HIERARCHY % ('ef' * 16)
        states = states or {}
        after = after or states
        replies = {'before': {route.CURRENT_USER: Result(0, b'%d\n' % states.get('user', 10)),
                              route.POWER: power(states.get('power', 'Awake')),
                              route.WINDOWS: window(states.get('focus', 'ours'))},
                   'after': {route.CURRENT_USER: Result(0, b'%d\n' % after.get('user', 10)),
                             route.POWER: power(after.get('power', 'Awake')),
                             route.WINDOWS: window(after.get('focus', 'ours'))}}
        phase = ['before']
        ran = []

        def effect(command):
            ran.append(command)
            phase[0] = 'after'
            return dump or Result(0, ('UI hierchary dumped to: %s\n' % path).encode())

        def read(command):
            ran.append(command)
            if command == 'cat ' + path:
                return cat or Result(0, xml if xml is not None else hierarchy())
            return replies[phase[0]][command]
        notice = route.NoticeRoute(jar_sha256=JAR_SHA, nonce=lambda: 'ef' * 16)
        try:
            return notice.visibility(effect, read, issue(), {'id': 10, 'serial': 5, 'type': 't'}), ran
        except (lab_readers.Unavailable, lab_readers.Unclassified) as error:
            return error, ran

    def test_an_honest_capture_is_visible_focused_awake_and_shows_the_challenge(self):
        projection, ran = self.capture()
        self.assertEqual(projection, {'user': 10, 'serial': 5, 'current_user': 10, 'awake': True, 'focused': True,
                                      'challenge': EVENT, 'visible': True})
        path = route.HIERARCHY % ('ef' * 16)
        self.assertEqual(ran, [route.CURRENT_USER, route.POWER, route.WINDOWS, 'uiautomator dump ' + path,
                               'cat ' + path, route.CURRENT_USER, route.POWER, route.WINDOWS])

    def test_no_focus_screen_off_and_locked_occlusion_never_qualify(self):
        no_focus, _ = self.capture({'focus': 'none'})
        self.assertFalse(no_focus['focused'])
        exiting, _ = self.capture({'focus': 'exiting'})
        self.assertFalse(exiting['focused'])
        lost_after, _ = self.capture({}, {'focus': 'shade'})
        self.assertFalse(lost_after['focused'])
        asleep, _ = self.capture({'power': 'Asleep'})
        self.assertFalse(asleep['awake'])
        dozing, _ = self.capture({}, {'power': 'Dozing'})
        self.assertFalse(dozing['awake'])
        keyguard, _ = self.capture({'focus': 'shade'}, xml=hierarchy(challenge='', package='com.android.systemui'))
        self.assertEqual((keyguard['focused'], keyguard['visible'], keyguard['challenge']), (False, False, '00' * 16))
        covered, _ = self.capture({'focus': 'shade'}, xml=hierarchy(package='com.android.systemui'))
        self.assertFalse(covered['visible'], 'the challenge under another active window is not visible')
        switched, _ = self.capture({}, {'user': 0})
        self.assertEqual(switched['current_user'], -1)

    def test_an_offscreen_or_ambiguous_challenge_is_not_visible(self):
        for name, xml in {'beyond the window': hierarchy(bounds='[63,2390][1017,2500]'),
                          'empty': hierarchy(bounds='[63,300][63,300]'),
                          'left of the window': hierarchy(bounds='[-20,300][1017,400]'),
                          'twice': hierarchy(twice=True)}.items():
            with self.subTest(name):
                projection, _ = self.capture(xml=xml)
                self.assertFalse(projection['visible'])
        old, _ = self.capture(xml=hierarchy(challenge='9d' * 16))
        self.assertEqual((old['challenge'], old['visible']), ('9d' * 16, True))

    def test_a_stale_missing_or_refused_hierarchy_is_unavailable_or_unclassified(self):
        path = route.HIERARCHY % ('ef' * 16)
        missing, _ = self.capture(cat=Result(1, b'', ('cat: %s: No such file or directory\n' % path).encode()))
        self.assertIsInstance(missing, lab_readers.Unavailable)
        refused, _ = self.capture(dump=Result(0, b'', b'ERROR: null root node returned by UiTestAutomationBridge.\n'))
        self.assertIsInstance(refused, lab_readers.Unavailable)
        other, _ = self.capture(dump=Result(0, b'UI hierchary dumped to: /sdcard/window_dump.xml\n'))
        self.assertIsInstance(other, lab_readers.Unclassified)
        for name, xml in {'doctype': b'<!DOCTYPE x>' + hierarchy(), 'not xml': b'<hierarchy',
                          'unknown attribute': hierarchy().replace(b'hint=""', b'hint="" extra="1"', 1),
                          'unknown element': hierarchy().replace(b'</hierarchy>', b'<window/></hierarchy>'),
                          'no rotation': hierarchy().replace(b' rotation="0"', b''),
                          'bounds': hierarchy(bounds='[63,300]')}.items():
            with self.subTest(name):
                projection, _ = self.capture(xml=xml)
                self.assertIsInstance(projection, lab_readers.Unclassified)

    def test_reads_of_no_known_form_are_unclassified(self):
        bad_window = Result(0, b'WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n  Display: mDisplayId=0\n'
                               b'  mCurrentFocus=Window{zz}\n  mFocusedApp=null\n')
        with self.assertRaises(lab_readers.Unclassified):
            route.focus(bad_window, 10)
        with self.assertRaises(lab_readers.Unclassified):
            route.focus(Result(0, b'WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n'), 10)
        with self.assertRaises(lab_readers.Unclassified):
            route.awake(Result(0, b'POWER MANAGER (dumpsys power)\n\n  mWakefulness=Awake\n  mWakefulness=Awake\n'))
        with self.assertRaises(lab_readers.Unclassified):
            route.current_user(Result(0, b'10\n', b'warning\n'))
        with self.assertRaises(lab_readers.Unavailable):
            route.current_user(Result(completed=False))


if __name__ == '__main__':
    unittest.main()
