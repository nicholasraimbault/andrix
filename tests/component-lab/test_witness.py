# SPDX-License-Identifier: Apache-2.0
"""The process history reader of criterion bit 1: the process health helper's strict reply parser,
the identity and time join of its rows with the genuine main SystemUI process, and the bit 1 reader
through the broker on a simulated guest. Each contrary case beside its honest control. Host
evidence only: the replies are the helper's form as tests/process-health-read prints it on the host
JVM, not Android replies, and the positive paths are qualified by these fixtures alone."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import unittest

import full_users
import health_baseline
import health_compose
import health_records
import health_witness
import lab_broker
import lab_evidence
import lab_protocol as proto
import lab_readers
import labtest
from labtest import PLAN, TICKET, Harness
import process_health
import sim_android
import sim_users
import test_health

BOOT = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'
INSTANCE = 4001
WALL = sim_android.WALL_BASE
UID0 = sim_users.APP_ID
CONTEXT = sim_users.CONTEXT
PROCESS = [1839, 9120, UID0, CONTEXT]
FIELDS = process_health.ROW_FIELDS
CLASSES = {v: k for k, v in proto.HEALTH_CLASSIFICATIONS.items()}
# The health window the broker passes, as its stored ticket gives it: opened after the fixture's two
# baselines, at 1000 and 3000, and before its earliest probe, open long after its latest one.
WINDOW = {'boot': BOOT.replace('-', ''), 'start': 3500, 'end': 10_003_500}


def exit_row(**changes):
    value = {'timestamp': WALL + 50_000, 'pid': PROCESS[0], 'real_uid': UID0, 'package_uid': UID0,
             'defining_uid': UID0, 'user': 0, 'process': process_health.PACKAGE, 'reason': 4, 'subreason': 0,
             'status': 0}
    value.update(changes)
    return value


def report(**changes):
    value = {'condition': 1, 'pid': PROCESS[0], 'uid': UID0, 'process': process_health.PACKAGE, 'tag': None,
             'short': 'java.lang.IllegalStateException: test', 'long': 'a test crash', 'stack': 'at test'}
    value.update(changes)
    return value


def reply(elapsed, rows=(), entries=(), wall_step=0, user=0, history=None, current=None):
    """One reply of the helper at one elapsed time, in the form the helper prints: [its exit
    status, standard output, standard error]."""
    samples = [[elapsed + i, WALL + elapsed + i + wall_step] for i in range(4)]
    code, text = sim_android.process_health_reply(user, history or ('OK', list(rows)), current or ('OK', list(entries)),
                                                  samples)
    return [code, text, '']


def reading(elapsed, rows=(), entries=(), wall_step=0, user=0, **parts):
    """One parsed reply of the helper at one elapsed time."""
    return process_health.parse_reply(*reply(elapsed, rows, entries, wall_step, user, **parts), user)


def observation(elapsed, before=PROCESS, after=PROCESS, rows=(), entries=(), wall_step=0, boot=BOOT,
                instance=INSTANCE, uid=UID0, user=0, serial=0, **parts):
    """One read as the reader observes it, with the raw reply its capture recorded."""
    raw = reply(elapsed, rows, entries, wall_step, user, **parts)
    return {'boot': boot, 'instance': instance, 'user': user, 'serial': serial, 'uid': uid, 'before': before,
            'after': after, 'reading': process_health.parse_reply(*raw, user), 'reply': raw}


def baseline(number, elapsed, rows=(), entries=(), process=PROCESS, boot=BOOT, instance=INSTANCE, user=0, serial=0,
             wall_step=0):
    """One whole baseline group as the broker passes it: its digest, projection and bracket. With
    no process, a whole read while the process was absent: its facts are incomplete."""
    uid = user * full_users.PER_USER_RANGE + UID0 if process is None else process[2]
    history, current = health_witness.baseline_parts(
        {'boot': boot, 'instance': instance, 'user': user, 'uid': uid, 'after': process,
         'reading': reading(elapsed, rows, entries, wall_step, user)}, serial)
    facts = {'schema': health_records.BASELINE_FACTS, 'user': user, 'serial': serial, 'state': 'RUNNING_UNLOCKED',
             'app_id': UID0, 'uid': uid, 'process': None if process is None else {
                 'pid': process[0], 'start_ticks': process[1], 'uid': uid, 'uids': [uid] * 4,
                 'name': full_users.SYSTEMUI, 'comm': full_users.COMM, 'context': process[3]},
             'absent': process is None, 'history': history, 'current_errors': current, 'complete': process is not None}
    assert health_records.baseline_facts_problem(facts, user, serial) is None
    return {'digest': '%064x' % number, 'projection': {'user': user, 'serial': serial, 'facts': facts},
            'brackets': {'boot': boot.replace('-', ''), 'instance': instance, 'begin': {'elapsed': elapsed - 5},
                         'end': {'elapsed': elapsed + 10}}}


def context(baselines, trail=(), user=0, serial=0, window=WINDOW):
    relied = baselines[-1] if baselines else None
    return {'user': user, 'serial': serial, 'baselines': list(baselines), 'trail': list(trail),
            'baseline': None if relied is None else {'digest': relied['digest'], 'projection': relied['projection']},
            'window': window}


def two(rows=(), entries=(), **options):
    return [baseline(1, 1000, rows, entries, **options), baseline(2, 3000, rows, entries, **options)]


def trail_entry(status, decision, begin, end, instance=INSTANCE, helper=None, user=0):
    """An earlier composition as the broker passes it: its bracket, bit 1 as accepted, its
    decision, and the replies its own captures recorded for the helper. By default that is the
    reply its decision's read gave, or for a held probe a whole read at its bracket's begin."""
    if helper is None:
        observed = None if decision is None else decision['observed']
        if observed is not None:
            rows = [dict(zip(FIELDS, r[:6] + [process_health.decode_text(r[6])] + r[7:])) for r in decision['new_rows']]
            entries = [{'condition': e[0], 'pid': e[1], 'uid': e[2], 'process': process_health.decode_text(e[3]),
                        'tag': process_health.decode_text(e[4]), 'short': process_health.decode_text(e[6]),
                        'long': process_health.decode_text(e[8]), 'stack': process_health.decode_text(e[10])}
                       for e in decision['errors']]
            helper = [list(sim_android.process_health_reply(decision['user'], ('OK', rows), ('OK', entries),
                                                             observed['samples'])) + ['']]
        elif status == 'HELD':
            helper = [list(sim_android.process_health_reply(user, ('OK', []), ('OK', []),
                                                             [[begin, WALL + begin]] * 4)) + ['']]
        else:
            helper = []
    return {'group': begin, 'status': status, 'decision': decision, 'helper': helper,
            'brackets': {'instance': instance, 'begin': {'elapsed': begin}, 'end': {'elapsed': end}}}


class Fresh:
    """A later part's independent evidence that an exit row belongs to the current boot, as a host
    fixture: it says yes, and records what it was asked."""

    def __init__(self):
        self.asked = []

    def fresh(self, row, birth, loss, context):
        self.asked.append(row)
        return {'witness': 'host-fixture'}


class Later(Fresh):
    """The host fixture, which gives its evidence only once a test gives it: before, none exists."""

    def __init__(self):
        super().__init__()
        self.given = False

    def fresh(self, row, birth, loss, context):
        self.asked.append(row)
        return {'witness': 'host-fixture'} if self.given else None


def judge(now, ctx, failure=None, **options):
    return health_witness.judge(now, failure, ctx, **options)


def redigest(text):
    """A changed reply with its end marker made to agree again, so only its own form decides."""
    body = text[:text.rindex('end=')]
    return body + 'end=%s lines=%d sha256=%s\n' % (process_health.HEADER, body.count('\n'),
                                                  hashlib.sha256(body.encode()).hexdigest())


class ParserTests(unittest.TestCase):
    """The helper's reply parsed strictly: whole, complete empty, or no evidence."""

    def text(self, rows=(), entries=(), history=None, current=None, user=0):
        return sim_android.process_health_reply(user, history or ('OK', list(rows)), current or ('OK', list(entries)),
                                                [[1000, WALL + 1000]] * 4)

    def test_a_complete_empty_reply_is_not_filtered_denied_or_malformed_output(self):
        code, text = self.text()
        reading = process_health.parse_reply(code, text, '', 0)
        self.assertTrue(reading['complete'])
        self.assertEqual((reading['history']['rows'], reading['current']['entries'], reading['current']['returned']),
                         ([], [], 'null'))
        # Denied, and every other failed read: a part that is not whole, never zero rows.
        for part, reason in (('history', 'java.lang.SecurityException'), ('current', 'android.os.RemoteException'),
                             ('history', 'overflow')):
            with self.subTest(part=part, reason=reason):
                failed = {part: ('ERROR', reason)}
                code, text = self.text(**failed)
                denied = process_health.parse_reply(code, text, '', 0)
                self.assertEqual(code, 5)
                self.assertFalse(denied['complete'])
                self.assertEqual((denied[part]['status'], denied[part]['reason']), ('ERROR', reason))
                self.assertEqual(denied[part]['rows' if part == 'history' else 'entries'], [])
                status, _, decision = judge(dict(observation(5000), reading=denied), context(two()))
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                self.assertIn('never zero rows', decision['exclusions'][0])
        code, text = self.text(current=('UNAVAILABLE', 'service-absent'))
        self.assertFalse(process_health.parse_reply(code, text, '', 0)['complete'])
        # Filtered: a row taken out, with or without its count and end marker made to agree.
        code, text = self.text(rows=[exit_row(), exit_row(pid=4000)])
        lines = text.split('\n')
        cut = [line for line in lines if not line.startswith('history row=1 ')]
        recounted = [line.replace('count=2', 'count=1') for line in cut]
        relined = recounted[:-2] + [recounted[-2].replace('lines=%d' % (len(lines) - 2), 'lines=%d' % (len(lines) - 3)),
                                    '']
        for name, changed in (('a row taken out', cut), ('its count made to agree', recounted),
                              ('its end marker counted again', relined)):
            with self.subTest(name), self.assertRaises(lab_readers.Unavailable):
                process_health.parse_reply(code, '\n'.join(changed), '', 0)
        # Malformed, with an end marker that agrees: no known form, never a reading.
        malformed = {'another version': text.replace(process_health.HEADER + '\n', 'andrix-process-health-read-v2\n', 1),
                     'another package': text.replace('package=com.android.systemui', 'package=com.android.shell'),
                     'a number with a leading zero': text.replace('pid=4000', 'pid=04000'),
                     'a status of no known form': text.replace('status=OK count=2', 'status=MAYBE count=2'),
                     'rows out of order': text.replace('history row=1 ', 'history row=0 '),
                     'a sample out of its place': text.replace('history sample=after', 'history sample=before'),
                     'an error line': text.replace('status=complete\n', 'error=clock\n')}
        for name, changed in malformed.items():
            with self.subTest(name), self.assertRaises(process_health.FormError):
                process_health.parse_reply(code, redigest(changed), '', 0)
        for name, args in (('standard error', (code, text, 'warning\n')), ('another exit status', (5, text, '')),
                           ('another user', (code, text, '')), ('a carriage return', (code, text.replace('\n', '\r\n'), ''))):
            with self.subTest(name), self.assertRaises((process_health.FormError, lab_readers.Unavailable)):
                process_health.parse_reply(*args, 13 if name == 'another user' else 0)

    def test_a_missing_end_marker_or_an_impossible_count_is_unavailable_evidence(self):
        code, text = self.text(rows=[exit_row()], entries=[report()])
        self.assertTrue(process_health.parse_reply(code, text, '', 0)['complete'])
        for at in range(len(text)):
            with self.subTest(cut=at), self.assertRaises((lab_readers.Unavailable, process_health.FormError)):
                process_health.parse_reply(code, text[:at], '', 0)
        lines = text.split('\n')
        without = '\n'.join(lines[:-2]) + '\n'
        with self.assertRaisesRegex(lab_readers.Unavailable, 'end marker'):
            process_health.parse_reply(code, without, '', 0)
        # A count above the helper's bound is impossible, however the end marker reads.
        changed = text.replace('history status=OK count=1', 'history status=OK count=%d' % (process_health.MAX_ROWS + 1))
        with self.assertRaisesRegex(lab_readers.Unavailable, 'impossible count'):
            process_health.parse_reply(code, redigest(changed), '', 0)
        # A count the rows do not have, under an end marker that agrees, is no reading either.
        changed = text.replace('history status=OK count=1', 'history status=OK count=2')
        with self.assertRaises(process_health.FormError):
            process_health.parse_reply(code, redigest(changed), '', 0)
        # An end marker that counts other lines, or digests other bytes, is no reading.
        for wrong in (text.replace(' lines=', ' lines=1', 1), text[:-65] + '0' * 64 + '\n'):
            with self.assertRaisesRegex(lab_readers.Unavailable, 'end marker'):
                process_health.parse_reply(code, wrong, '', 0)

    def test_times_are_numeric_milliseconds_and_no_time_zone_changes_a_decision(self):
        code, text = self.text(rows=[exit_row()])
        stamp = 'timestamp=%d' % (WALL + 50_000)
        for name, form in (('ISO with a zone', 'timestamp=2026-10-15T21:22:33.123Z'),
                           ('a dump date', 'timestamp=2026-10-15%2021:22:33.123'),
                           ('seconds with a fraction', 'timestamp=1791504050.000'), ('a sign', 'timestamp=+1791504050000')):
            with self.subTest(name), self.assertRaises(process_health.FormError):
                process_health.parse_reply(code, redigest(text.replace(stamp, form)), '', 0)
        # The same replies give the same readings and decisions in every host time zone.
        old = os.environ.get('TZ')

        def restore():
            if old is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = old
            time.tzset()
        self.addCleanup(restore)
        found = []
        for zone in ('UTC', 'Pacific/Kiritimati', 'America/St_Johns', 'Asia/Kathmandu'):
            os.environ['TZ'] = zone
            time.tzset()
            now = observation(9000, after=None, rows=[exit_row(timestamp=WALL + 8000)])
            found.append((process_health.parse_reply(code, text, '', 0), judge(now, context(two()), freshness=Fresh())))
        self.assertEqual([f == found[0] for f in found], [True] * 4)

    def test_an_empty_list_or_a_string_of_another_encoding_has_no_known_form(self):
        code, text = self.text(rows=[exit_row(process='com.android.systemui:x y')])
        self.assertEqual(process_health.parse_reply(code, text, '', 0)['history']['rows'][0][6],
                         'com.android.systemui:x%20y')
        for token in ('%41ndroid', 'x%2dy', 'x%FFy', 'x%2', '%C3', 'x y'):
            with self.subTest(token), self.assertRaises(process_health.FormError):
                process_health.decode_text(token)
        for value in ('com.android.systemui', '', None, 'a-b c\nd', '\u00e9\U0001F600'):
            self.assertEqual(process_health.decode_text(process_health.encode_text(value)), value)
        code, text = self.text()
        with self.assertRaisesRegex(process_health.FormError, 'never returns'):
            process_health.parse_reply(code, redigest(text.replace('count=0 returned=null', 'count=0 returned=list')),
                                       '', 0)
        code, text = self.text(entries=[report()])
        with self.assertRaises(process_health.FormError):
            process_health.parse_reply(code, redigest(text.replace('count=1 returned=list', 'count=1 returned=null')),
                                       '', 0)


class JoinTests(unittest.TestCase):
    """The identity and time join, a pure function of one read and its context."""

    def test_the_honest_continuous_process_holds_and_a_wall_step_alone_changes_nothing(self):
        ctx = context(two(rows=[exit_row(timestamp=WALL - 90_000, pid=1700)]))
        self.assertEqual(judge(observation(9000, rows=[exit_row(timestamp=WALL - 90_000, pid=1700)]), ctx),
                         ('HELD', '', None))
        self.assertEqual(judge(observation(9000, rows=[exit_row(timestamp=WALL - 90_000, pid=1700)],
                                           wall_step=3_600_000), ctx), ('HELD', '', None))
        # An exit row evicted from the bounded history since the baselines is no change either.
        self.assertEqual(judge(observation(9000), ctx)[0], 'HELD')

    def test_a_current_report_while_the_process_still_runs_is_a_qualified_failure(self):
        # An earlier read inside the window, a probe held at 6000, found the process without it.
        for condition in (1, 2):
            with self.subTest(condition=condition):
                status, reason, decision = judge(observation(9000, entries=[report(condition=condition)]),
                                                 context(two(), [trail_entry('HELD', None, 6000, 6100)]))
                self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_CURRENT_ERROR'))
                self.assertEqual(decision['qualified'][:3], [condition, PROCESS[0], UID0])
                self.assertEqual(decision['birth']['start_ticks'], PROCESS[1])
                self.assertIsNone(health_witness.decision_problem(decision))
                # A qualified report is a witnessed failure, never a partial hold.
                for others in ('HELD', 'UNKNOWN'):
                    statuses = [others] * 7
                    statuses[1] = status
                    self.assertEqual(CLASSES[proto.health_classification(proto.ROW_STATUSES[s] for s in statuses)],
                                     'CRASH')
        # A report of a process that does not live before and after the call joins nothing, even
        # after the clean read inside the window that would show it new: each for its own reason.
        for before, after, why in ((PROCESS, None, 'joins no process living before and after the call'),
                                   (None, PROCESS, 'the identity was seen again after it was gone'),
                                   ([1839, 9300, UID0, CONTEXT], PROCESS, 'the identity was seen again after it was gone')):
            with self.subTest(before=before, after=after):
                status, reason, decision = judge(observation(9000, before=before, after=after, entries=[report()]),
                                                 context(two(), [trail_entry('HELD', None, 6000, 6100)]))
                self.assertEqual((status, decision['qualified']), ('UNKNOWN', None))
                self.assertIn(why, reason)

    def test_a_report_already_present_in_the_baseline_is_no_new_failure(self):
        status, _, decision = judge(observation(9000, entries=[report()]), context(two(entries=[report()])))
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('already present in a baseline', decision['exclusions'][0])
        # Its honest control: the same report new since the baselines, absent from an earlier read
        # inside the window, qualifies.
        self.assertEqual(judge(observation(9000, entries=[report()]),
                               context(two(), [trail_entry('HELD', None, 6000, 6100)]))[0], 'BAD')
        # A process in an error state in a baseline that is gone later is no newly induced failure.
        gone = observation(9000, after=None, before=None, rows=[exit_row(timestamp=WALL + 8000)])
        status, _, decision = judge(gone, context(two(entries=[report()])), freshness=Fresh())
        self.assertEqual(status, 'UNKNOWN')
        self.assertIn('no newly induced failure', ' '.join(decision['exclusions']))

    def test_a_late_old_history_row_never_counts(self):
        late = exit_row(timestamp=WALL + 500)
        status, _, decision = judge(observation(9000, rows=[late]), context(two()))
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('a late row or a reused PID', decision['exclusions'][0])
        fresh = Fresh()
        status, _, decision = judge(observation(9000, before=None, after=None, rows=[late]), context(two()),
                                    freshness=fresh)
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'PENDING'))
        self.assertIn('a late exit row from before the identity was last seen living', decision['exclusions'])
        self.assertEqual(fresh.asked, [])
        # Its honest control: the same row placed after the last living read, with the fixture.
        status, _, decision = judge(observation(9000, before=None, after=None, rows=[exit_row(timestamp=WALL + 8000)]),
                                    context(two()), freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))

    def test_an_updated_reason_or_time_is_never_new(self):
        old = exit_row(timestamp=WALL - 600_000, reason=0)
        for name, update in (('reason', dict(old, reason=4)), ('time', dict(old, timestamp=WALL + 8000)),
                             ('both', dict(old, reason=6, timestamp=WALL + 8000))):
            for before, after in ((PROCESS, PROCESS), (None, None)):
                with self.subTest(name, living=before is not None):
                    status, _, decision = judge(observation(9000, before=before, after=after, rows=[update]),
                                                context(two(rows=[old])), freshness=Fresh())
                    self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                    self.assertIn('never a new exit', ' '.join(decision['exclusions']))

    def test_a_wall_clock_offset_change_places_no_row(self):
        row = exit_row(timestamp=WALL + 8000 + 60_000)
        status, _, decision = judge(observation(9000, before=None, after=None, rows=[row], wall_step=60_000),
                                    context(two()), freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('a wall clock offset change', decision['exclusions'][0])
        # Within the declared tolerance, the same row is placed.
        row = exit_row(timestamp=WALL + 8000 + 500)
        status, _, decision = judge(observation(9000, before=None, after=None, rows=[row], wall_step=500),
                                    context(two()), freshness=Fresh())
        self.assertEqual(decision['decision'], 'QUALIFIED_LIFECYCLE_JOIN')

    def test_a_boot_or_framework_change_continues_no_identity(self):
        # The report would be new: an earlier read inside the window, of the read's own framework,
        # found the process without it.
        other = 'f1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'
        for name, now, instance in (('another boot', observation(9000, boot=other, entries=[report()]), INSTANCE),
                                    ('another framework',
                                     observation(9000, instance=INSTANCE + 100, entries=[report()]), INSTANCE + 100)):
            with self.subTest(name):
                status, _, decision = judge(
                    now, context(two(), [trail_entry('HELD', None, 6000, 6100, instance=instance)]), freshness=Fresh())
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        status, _, decision = judge(None, context(two()), failure='unavailable: the device rebooted during the read')
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))

    def test_a_reused_pid_and_start_time_is_not_the_identity(self):
        # Across a boot the same PID and start ticks are another process: no continuity, no claim.
        other = 'f1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'
        for entries in ((), (report(),)):
            status, _, _ = judge(observation(9000, boot=other, entries=entries), context(two()))
            self.assertEqual(status, 'UNKNOWN')
        # In one boot a PID reused with other start ticks is gone, not the identity.
        reused = [PROCESS[0], 9500, UID0, CONTEXT]
        status, _, decision = judge(observation(9000, before=reused, after=reused), context(two()))
        self.assertEqual((status, decision['decision'], decision['observed']['state']), ('UNKNOWN', 'PENDING', 'GONE'))
        # A report of another app's process that took the PID joins nothing of the user's SystemUI.
        stranger = report(uid=10150, process='dev.andrix.lab.notice')
        status, _, decision = judge(observation(9000, before=None, after=None, entries=[stranger]), context(two()))
        self.assertEqual((status, decision['errors']), ('UNKNOWN', []))
        # An exit row of the reused PID's earlier record changed in place is an update, never new.
        old = exit_row(timestamp=WALL - 600_000, reason=10)
        status, _, decision = judge(observation(9000, before=reused, after=reused,
                                                rows=[dict(old, reason=4, timestamp=WALL + 8000)]),
                                    context(two(rows=[old])), freshness=Fresh())
        self.assertEqual(decision['decision'], 'INCONCLUSIVE')

    def test_a_wrong_user_uid_or_process_never_joins(self):
        gone = dict(before=None, after=None)
        for name, row in (('another user', exit_row(user=10, real_uid=1000000 + UID0, package_uid=1000000 + UID0,
                                                     defining_uid=1000000 + UID0)),
                          ('another real UID', exit_row(real_uid=99000 + 1)),
                          ('another defining UID', exit_row(defining_uid=1010)),
                          ('another process', exit_row(process='com.android.systemui:screenshot')),
                          ('a longer name', exit_row(process='com.android.systemuix')),
                          ('another PID', exit_row(pid=1840))):
            with self.subTest(name):
                fresh = Fresh()
                status, _, decision = judge(observation(9000, rows=[exit_row(timestamp=WALL + 8000, **{
                    k: v for k, v in row.items() if k != 'timestamp'})], **gone), context(two()), freshness=fresh)
                self.assertEqual((status, fresh.asked), ('UNKNOWN', []))
                self.assertIn('an exit row of another identity', ' '.join(decision['exclusions']))
        for name, entry in (('another process', report(process='com.android.systemui:screenshot')),
                            ('another PID', report(pid=1840))):
            with self.subTest(name):
                status, _, decision = judge(observation(9000, entries=[entry]), context(two()))
                self.assertEqual(status, 'UNKNOWN')
                self.assertIn('joins no process', decision['exclusions'][0])
        # Another user's SystemUI in error is not this user's: the honest process still holds.
        self.assertEqual(judge(observation(9000, entries=[report(uid=1000000 + UID0)]), context(two()))[0], 'HELD')

    def test_the_low_memory_signal_and_user_stop_reasons_are_never_a_crash(self):
        for reason in (3, 2, 11, 16, 1, 0, 10):
            with self.subTest(reason=process_health.REASONS[reason]):
                fresh = Fresh()
                status, _, decision = judge(observation(9000, before=None, after=None,
                                                        rows=[exit_row(timestamp=WALL + 8000, reason=reason)]),
                                            context(two()), freshness=fresh)
                self.assertEqual((status, decision['decision'], fresh.asked), ('UNKNOWN', 'INCONCLUSIVE', []))
                self.assertIn('not a crash or ANR', ' '.join(decision['exclusions']))
        for reason in health_witness.QUALIFIED_REASONS:
            with self.subTest(reason=process_health.REASONS[reason]):
                status, _, decision = judge(observation(9000, before=None, after=None,
                                                        rows=[exit_row(timestamp=WALL + 8000, reason=reason)]),
                                            context(two()), freshness=Fresh())
                self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))

    def test_duplicate_candidates_are_ambiguous(self):
        rows = [exit_row(timestamp=WALL + 8000, reason=6), exit_row(timestamp=WALL + 8100, reason=4)]
        status, _, decision = judge(observation(9000, before=None, after=None, rows=rows), context(two()),
                                    freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('duplicate candidates', decision['exclusions'][0])
        status, _, decision = judge(observation(9000, entries=[report(), report(condition=2)]), context(two()))
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('duplicate candidates', decision['exclusions'][0])

    def test_no_publication_stays_pending_through_the_declared_bound_then_inconclusive(self):
        bound = health_witness.PENDING_BOUND_MS
        ctx = context(two())
        first = judge(observation(9000, before=None, after=None), ctx)
        self.assertEqual((first[0], first[2]['decision']), ('UNKNOWN', 'PENDING'))
        self.assertIn('no qualified exit row of the gone identity was published', first[2]['exclusions'])
        self.assertEqual(first[2]['loss'], {'after': 3003, 'by': 9000})
        self.assertEqual(first[2]['pending_until'], 9000 + bound)
        # A later probe counts the bound from the read that first saw the loss.
        trail = [trail_entry('HELD', None, 6000, 6100), trail_entry('UNKNOWN', first[2], 8990, 9100)]
        later = judge(observation(8996 + bound, before=None, after=None), context(two(), trail))
        self.assertEqual((later[2]['decision'], later[2]['loss']), ('PENDING', {'after': 6000, 'by': 9000}))
        after = judge(observation(9001 + bound, before=None, after=None), context(two(), trail))
        self.assertEqual((after[0], after[2]['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        # A loss during the read counts its bound from the read's last sample; a later probe that
        # saw the identity living again is no loss at all.
        went = judge(observation(9000, before=PROCESS, after=None), ctx)
        self.assertEqual((went[2]['decision'], went[2]['loss']['by'], went[2]['pending_until']),
                         ('PENDING', None, 9003 + bound))
        again = judge(observation(9500, before=None, after=None),
                      context(two(), [trail_entry('UNKNOWN', first[2], 8990, 9100), trail_entry('HELD', None, 9200, 9300)]))
        self.assertIn('seen again', again[1])
        # A row from before a probe that saw the identity living is late, whatever its reason.
        held = [trail_entry('HELD', None, 7000, 7100)]
        status, _, decision = judge(observation(9000, before=None, after=None, rows=[exit_row(timestamp=WALL + 6500)]),
                                    context(two(), held), freshness=Fresh())
        self.assertEqual(decision['decision'], 'PENDING')
        self.assertIn('a late exit row from before the identity was last seen living', decision['exclusions'])

    def test_a_lifecycle_join_needs_independent_evidence_of_this_boot(self):
        row = exit_row(timestamp=WALL + 8000)
        status, reason, first = judge(observation(9000, before=None, after=None, rows=[row]), context(two()))
        self.assertEqual((status, first['decision']), ('UNKNOWN', 'PENDING'))
        self.assertIn('no independent evidence', reason)
        status, _, decision = judge(observation(9001 + health_witness.PENDING_BOUND_MS, before=None, after=None,
                                                rows=[row]), context(two(), [trail_entry('UNKNOWN', first, 8990, 9100)]))
        self.assertEqual(decision['decision'], 'INCONCLUSIVE')
        # The positive path, qualified by a host fixture only.
        status, _, decision = judge(observation(9000, before=None, after=None, rows=[row]), context(two()),
                                    freshness=Fresh())
        self.assertEqual((status, decision['decision'], decision['freshness']),
                         ('BAD', 'QUALIFIED_LIFECYCLE_JOIN', {'witness': 'host-fixture'}))
        self.assertEqual(decision['qualified'][1], PROCESS[0])
        # The decision is a side record at the depth a BAD row's witness has in a manifest.
        lab_evidence.canonical({'projection': {'rows': [{'witness': decision}]}})

    def test_repeated_whole_baselines_before_the_window_are_required(self):
        one = [baseline(2, 3000)]
        for name, ctx in (('one baseline', context(one)),
                          ('no baseline relied on', dict(context(two()), baseline=None)),
                          ('the relied one not the last', dict(context(two()), baseline=context(two()[:1])['baseline'])),
                          ('one of another framework', context([baseline(1, 1000, instance=INSTANCE - 1),
                                                                 baseline(2, 3000)]))):
            with self.subTest(name):
                status, _, decision = judge(observation(9000, entries=[report()]), ctx)
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        other = two()
        other[0]['projection']['facts']['history'] = dict(other[0]['projection']['facts']['history'],
                                                          schema='andrix-test-witness-v1')
        self.assertEqual(judge(observation(9000), context(other))[0], 'UNKNOWN')
        # The old sets are every repeated baseline's: a row only the first one read is old.
        ctx = context([baseline(1, 1000, rows=[exit_row(timestamp=WALL - 5000, pid=1700)]), baseline(2, 3000)])
        self.assertEqual(judge(observation(9000, rows=[exit_row(timestamp=WALL - 5000, pid=1700)]), ctx)[0], 'HELD')

    def test_a_secondary_users_current_list_coverage_must_be_qualified(self):
        uid = 13 * 100000 + UID0
        process = [4734, 50_100, uid, 'u:r:platform_app:s0:c525,c768']
        ctx = context([baseline(1, 1000, process=process, user=13, serial=41),
                       baseline(2, 3000, process=process, user=13, serial=41)], user=13, serial=41)
        now = observation(9000, before=process, after=process, uid=uid, user=13, serial=41)
        status, _, decision = judge(now, ctx)
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('INTERACT_ACROSS_USERS_FULL', decision['exclusions'][0])
        self.assertEqual(judge(now, ctx, cross_user=True), ('HELD', '', None))
        # A report present needs no coverage, but its absence at an earlier read does: it is new
        # only once the shell's INTERACT_ACROSS_USERS_FULL is qualified, and an earlier read inside
        # the window found the process living without it.
        now = observation(9000, before=process, after=process, uid=uid, user=13, serial=41,
                          entries=[report(pid=4734, uid=uid)])
        ctx = dict(ctx, trail=[trail_entry('HELD', None, 6000, 6100, user=13)])
        self.assertEqual(judge(now, ctx)[2]['decision'], 'INCONCLUSIVE')
        self.assertEqual(judge(now, ctx, cross_user=True)[2]['decision'], 'QUALIFIED_CURRENT_ERROR')

    def test_missing_or_partial_evidence_is_inconclusive_and_never_a_failure(self):
        for failure in ('unavailable: a reply without its end marker', 'of no known form: FormError: x'):
            status, reason, decision = judge(None, context(two()), failure=failure)
            self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        for part in ('history', 'current'):
            failed = observation(9000, entries=[report()], **{part: ('ERROR', 'java.lang.SecurityException')})
            status, _, decision = judge(failed, context(two()), freshness=Fresh())
            self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        status, _, decision = judge(observation(9000, before=None, after=PROCESS), context(two()))
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        status, _, decision = judge(observation(9000, uid=UID0 + 1), context(two()))
        self.assertEqual(decision['decision'], 'INCONCLUSIVE')


    def test_a_baseline_report_no_longer_listed_while_its_process_lives_is_no_hold(self):
        # The review's case: repeated whole baselines hold a report of the identified process; the
        # current list no longer shows it while the same birth identity lives on, as after a
        # waited ANR dialog. A baseline error prevents a hold and proves no new failure.
        for condition in (1, 2):
            with self.subTest(condition=condition):
                ctx = context(two(entries=[report(condition=condition)]))
                status, reason, decision = judge(observation(9000), ctx)
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                self.assertIn('in a baseline', reason)
                self.assertEqual(decision['qualified'], None)
        # A report of another SystemUI process of the user in a baseline prevents a hold as well.
        other = report(pid=1900, process='com.android.systemui:screenshot')
        self.assertEqual(judge(observation(9000), context(two(entries=[other])))[0], 'UNKNOWN')
        # Its honest control: the same read against baselines without the report holds.
        self.assertEqual(judge(observation(9000), context(two())), ('HELD', '', None))

    def test_an_update_of_a_row_first_read_in_the_window_is_never_new(self):
        # The review's case: no exit row in the baselines; a living probe reads a late row of the
        # identity with reason UNKNOWN; a later probe finds the identity gone and the same record
        # with reason CRASH and a later time. It is an update of a row already read, never new.
        old = exit_row(timestamp=WALL + 500, reason=0)
        first = judge(observation(9000, rows=[old]), context(two()))
        self.assertEqual((first[2]['decision'], first[2]['observed']['state']), ('INCONCLUSIVE', 'ALIVE'))
        updated = dict(old, timestamp=WALL + 11_000, reason=4)
        gone = observation(13_000, before=None, after=None, rows=[updated])
        status, reason, decision = judge(gone, context(two(), [trail_entry('UNKNOWN', first[2], 8990, 9100)]),
                                         freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('never a new exit', reason)
        # Its honest control: after a probe that held, with no earlier read of that record, the same
        # row is placed after the identity was last seen living and qualifies with the fixture.
        held = context(two(), [trail_entry('HELD', None, 9000, 9100)])
        self.assertEqual(judge(gone, held, freshness=Fresh())[2]['decision'], 'QUALIFIED_LIFECYCLE_JOIN')
        # The review's other orders, each beside the same later read with no earlier one.
        for name, first_row, later_row in (
                ('a reason updated after a first gone read', exit_row(timestamp=WALL + 8000, reason=0),
                 exit_row(timestamp=WALL + 8000, reason=4)),
                ('an old time and reason updated', exit_row(timestamp=WALL + 500, reason=0),
                 exit_row(timestamp=WALL + 8000, reason=4))):
            with self.subTest(name):
                first = judge(observation(9000, before=None, after=None, rows=[first_row]), context(two()))
                later = observation(12_000, before=None, after=None, rows=[later_row])
                status, _, decision = judge(later, context(two(), [trail_entry('UNKNOWN', first[2], 8990, 9100)]),
                                            freshness=Fresh())
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                self.assertIn('never a new exit', ' '.join(decision['exclusions']))
                self.assertEqual(judge(later, context(two()), freshness=Fresh())[0], 'BAD')

    def test_an_exit_row_after_the_identity_was_already_gone_is_not_its_exit(self):
        # The review's case: a probe finds the identity gone with nothing published; a later probe
        # reads a row of its PID, UIDs and name placed 7000 ms after that first gone read. A later
        # occupant of the PID may share every field, so it is not the gone identity's exit.
        first = judge(observation(9000, before=None, after=None), context(two()))
        ctx = context(two(), [trail_entry('UNKNOWN', first[2], 8990, 9100)])
        late = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + 16_000)])
        status, reason, decision = judge(late, ctx, freshness=Fresh())
        self.assertEqual((status, decision['decision'], decision['loss']['by']), ('UNKNOWN', 'INCONCLUSIVE', 9000))
        self.assertIn('after the identity was already gone', reason)
        # Its honest control: a row placed inside the loss interval qualifies with the fixture.
        inside = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + 8000)])
        status, _, decision = judge(inside, ctx, freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))

    def test_a_wall_clock_step_an_earlier_held_probe_read_is_kept(self):
        # The review's case: a living probe reads the wall clock 60 s ahead of the baselines and
        # holds, with no decision; at elapsed 80000 the identity is gone, the clock is back, and a
        # row has wall time WALL + 68000. The held probe's own recorded reply keeps the step.
        held = observation(9000, wall_step=60_000)
        self.assertEqual(judge(held, context(two())), ('HELD', '', None))
        gone = observation(80_000, before=None, after=None, rows=[exit_row(timestamp=WALL + 68_000)])
        ctx = context(two(), [trail_entry('HELD', None, 8990, 9100, helper=[held['reply']])])
        status, reason, decision = judge(gone, ctx, freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('a wall clock offset change', reason)
        # A held probe whose recorded reply cannot be read again keeps no clock, so places no row.
        for helper in ([], [[None, '', '']], [held['reply'], held['reply']]):
            ctx = context(two(), [trail_entry('HELD', None, 8990, 9100, helper=helper)])
            status, reason, decision = judge(gone, ctx, freshness=Fresh())
            self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
            self.assertIn('cannot be read again', reason)
        # Its honest control: the same held probe without a step, and the row qualifies.
        steady = observation(9000)
        ctx = context(two(), [trail_entry('HELD', None, 8990, 9100, helper=[steady['reply']])])
        status, _, decision = judge(gone, ctx, freshness=Fresh())
        self.assertEqual((status, decision['decision'], decision['loss']['after']),
                         ('BAD', 'QUALIFIED_LIFECYCLE_JOIN', 9003))

    def test_an_older_incomplete_baseline_never_vetoes_two_later_whole_ones(self):
        # The review's case: a baseline read whole while the process was absent, then two whole
        # baselines of it; a new current report of the living process, absent from an earlier read
        # inside the window, qualifies, and the honest process holds. The older one keeps its rows
        # and reports in the old sets.
        older = baseline(0, 500, process=None, entries=[report(pid=1700)])
        ctx = context([older] + two(), [trail_entry('HELD', None, 6000, 6100)])
        status, _, decision = judge(observation(9000, entries=[report()]), ctx)
        self.assertEqual((status, decision['decision'], len(decision['old']['baselines']), decision['old']['errors']),
                         ('BAD', 'QUALIFIED_CURRENT_ERROR', 3, 1))
        self.assertEqual(judge(observation(9000), context([baseline(0, 500, process=None)] + two())),
                         ('HELD', '', None))
        # Its honest controls: the last baseline without its process relies on nothing, and an
        # incomplete one never counts as a repeat.
        for name, baselines, why in (('the last incomplete', two() + [baseline(3, 5000, process=None)],
                                      "the relied baseline is not this reader's whole reading"),
                                     ('one whole after it', [baseline(0, 500, process=None), baseline(2, 3000)],
                                      'not repeated')):
            with self.subTest(name):
                status, reason, decision = judge(observation(9000, entries=[report()]), context(baselines))
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                self.assertIn(why, reason)

    def test_an_update_read_again_is_still_never_new(self):
        # The review's case: a living probe reads a late UNKNOWN row of the identity; the next probe
        # finds it gone and the same record a CRASH at a later time, an update; the probe after that
        # reads the updated row unchanged. A record an earlier read showed with other contents stays
        # an update however often its new contents are read again, and no evidence is asked for it.
        old = exit_row(timestamp=WALL + 500, reason=0)
        alive = observation(9000, rows=[old])
        first = judge(alive, context(two()))
        self.assertEqual((first[2]['decision'], first[2]['observed']['state']), ('INCONCLUSIVE', 'ALIVE'))
        updated = dict(old, timestamp=WALL + 11_000, reason=4)
        trail = [trail_entry('UNKNOWN', first[2], 8990, 9100, helper=[alive['reply']])]
        for elapsed in (13_000, 15_000, 17_000):
            with self.subTest(elapsed=elapsed):
                now = observation(elapsed, before=None, after=None, rows=[updated])
                fresh = Fresh()
                status, reason, decision = judge(now, context(two(), trail), freshness=fresh)
                self.assertEqual((status, decision['decision'], fresh.asked), ('UNKNOWN', 'INCONCLUSIVE', []))
                self.assertIn('never a new exit', reason)
                trail.append(trail_entry(status, decision, elapsed - 10, elapsed + 100, helper=[now['reply']]))
        # Its honest control: a row no earlier read showed otherwise stays a candidate when it is
        # read again unchanged. Read first without independent evidence, the loss is pending; read
        # again with the fixture's, it qualifies.
        held = trail_entry('HELD', None, 8990, 9100)
        pending = observation(13_000, before=None, after=None, rows=[updated])
        second = judge(pending, context(two(), [held]))
        self.assertEqual(second[2]['decision'], 'PENDING')
        trail = [held, trail_entry('UNKNOWN', second[2], 12_990, 13_100, helper=[pending['reply']])]
        status, _, decision = judge(observation(15_000, before=None, after=None, rows=[updated]),
                                    context(two(), trail), freshness=Fresh())
        self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))

    def test_a_wall_clock_step_an_earlier_partial_read_saw_is_kept(self):
        # The review's case: a probe finds the process before and after the helper and reads the
        # history whole and empty, but its current error list fails, so it judges nothing and names
        # no birth identity; its samples read the wall clock 60 s ahead of the baselines. At elapsed
        # 80000 the identity is gone, the clock is back, and a row has wall time WALL + 68000. The
        # clock is the boot's, not one identity's: the step that read saw is kept.
        error = ('ERROR', 'android.os.RemoteException')
        gone = observation(80_000, before=None, after=None, rows=[exit_row(timestamp=WALL + 68_000)])
        for name, step, parts, expected in (
                ("the review's case", 60_000, {'current': error}, 'INCONCLUSIVE'),
                ('a failed history part', 60_000, {'history': ('ERROR', 'java.lang.SecurityException')},
                 'INCONCLUSIVE'),
                ('its honest control: the same error on a steady clock', 0, {'current': error},
                 'QUALIFIED_LIFECYCLE_JOIN')):
            with self.subTest(name):
                partial = observation(9000, wall_step=step, **parts)
                first = judge(partial, context(two()))
                self.assertEqual((first[2]['decision'], first[2]['birth']), ('INCONCLUSIVE', None))
                ctx = context(two(), [trail_entry('UNKNOWN', first[2], 8990, 9100, helper=[partial['reply']])])
                status, reason, decision = judge(gone, ctx, freshness=Fresh())
                self.assertEqual(decision['decision'], expected)
                if step:
                    self.assertIn('a wall clock offset change', reason)
        # A read whose bit 1 the broker lowered, with no decision, keeps its recorded clock too.
        stepped = observation(9000, wall_step=60_000)
        ctx = context(two(), [trail_entry('UNKNOWN', None, 8990, 9100, helper=[stepped['reply']])])
        status, reason, _ = judge(gone, ctx, freshness=Fresh())
        self.assertEqual(status, 'UNKNOWN')
        self.assertIn('a wall clock offset change', reason)

    def test_a_partial_reads_whole_discovery_bounds_the_loss(self):
        # A probe whose current error list fails judges nothing, but its discovery before and after
        # the helper is whole. One that found the identity gone bounds its loss above, so a row
        # placed after that read is not its exit; one that found it living bounds the loss below,
        # so a row from before that read is late. Each beside a row inside the loss interval, which
        # qualifies with the fixture.
        error = ('ERROR', 'android.os.RemoteException')

        def after(partial, begin):
            first = judge(partial, context(two()))
            self.assertEqual((first[2]['decision'], first[2]['birth']), ('INCONCLUSIVE', None))
            return trail_entry('UNKNOWN', first[2], begin, begin + 110, helper=[partial['reply']])
        gone_then = after(observation(9000, before=None, after=None, current=error), 8990)
        living_then = after(observation(9000, current=error), 8990)
        for name, entry, at, expected, why in (
                ('found gone, a row after it', gone_then, 16_000, 'INCONCLUSIVE',
                 'after the identity was already gone'),
                ('found gone, a row before it', gone_then, 8000, 'QUALIFIED_LIFECYCLE_JOIN', None),
                ('found living, a row before it', living_then, 5000, 'PENDING',
                 'a late exit row from before the identity was last seen living'),
                ('found living, a row after it', living_then, 12_000, 'QUALIFIED_LIFECYCLE_JOIN', None)):
            with self.subTest(name):
                now = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + at)])
                status, _, decision = judge(now, context(two(), [entry]), freshness=Fresh())
                self.assertEqual(decision['decision'], expected)
                if why is not None:
                    self.assertIn(why, ' '.join(decision['exclusions']))
        # A partial read before the relied baseline that found another SystemUI process says nothing
        # of this identity's loss: the baselines had not yet read it living.
        earlier = [1500, 4000, UID0, CONTEXT]
        entry = after(observation(400, before=earlier, after=earlier, current=error), 390)
        now = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + 8000)])
        status, _, decision = judge(now, context(two(), [entry]), freshness=Fresh())
        self.assertEqual((status, decision['decision'], decision['loss']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN',
                                                                            {'after': 3003, 'by': 20_000}))
        # A decision whose observation does not name its discovery is of no known form.
        broken = copy.deepcopy(gone_then)
        del broken['decision']['observed']['before']
        status, reason, _ = judge(now, context(two(), [broken]), freshness=Fresh())
        self.assertEqual(status, 'UNKNOWN')
        self.assertIn("an earlier probe's witness decision of no known form", reason)

    def test_an_earlier_read_that_found_the_identity_only_after_the_call_never_joins(self):
        # The review's case: a read at 9000 finds no process before the helper's call and the birth
        # identity after it, its current list failing or whole, and judges INCONCLUSIVE. At 20000
        # the identity is gone and a CRASH row is placed at 5000 or 8000, before that living
        # observation, or at 12000, after it. The living observation bounds the loss, and the
        # identity contradiction never supplies a join, so the fixture is never asked.
        error = ('ERROR', 'android.os.RemoteException')

        def earlier(before, partial, elapsed=9000, ctx=None):
            ob = observation(elapsed, before=before, after=PROCESS, **({'current': error} if partial else {}))
            status, _, decision = judge(ob, ctx or context(two()))
            return trail_entry(status, decision, elapsed - 10, elapsed + 100, helper=[ob['reply']])

        def later(entry, at):
            now = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + at)])
            fresh = Fresh()
            return judge(now, context(two(), [entry]), freshness=fresh), fresh.asked
        for partial in (True, False):
            entry = earlier(None, partial)
            for at in (5000, 8000, 12_000):
                with self.subTest(partial=partial, row=at):
                    (status, reason, decision), asked = later(entry, at)
                    self.assertEqual((status, decision['decision'], decision['loss']['after'], asked),
                                     ('UNKNOWN', 'INCONCLUSIVE', 9003, []))
                    self.assertIn('found the identity only after the call', reason)
        # Its honest control: the same reads finding the identity before the call too. Rows before
        # that living observation are late, and one after it qualifies with the fixture.
        for partial in (True, False):
            entry = earlier(PROCESS, partial)
            for at, expected in ((5000, 'PENDING'), (8000, 'PENDING'), (12_000, 'QUALIFIED_LIFECYCLE_JOIN')):
                with self.subTest('control', partial=partial, row=at):
                    (status, _, decision), _ = later(entry, at)
                    self.assertEqual((decision['decision'], decision['loss']['after']), (expected, 9003))
        # A read before the relied baseline, judged against none, that found the identity only
        # after the call may be its birth: no contradiction, and the row at 8000 qualifies.
        for partial in (True, False):
            with self.subTest('before the relied baseline', partial=partial):
                (status, _, decision), _ = later(earlier(None, partial, elapsed=400, ctx=context([])), 8000)
                self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))

    def test_every_discovery_state_of_an_earlier_read_bounds_the_loss(self):
        # Each state an earlier read's discovery can give, partial or whole, its discoveries placed
        # at the helper's first and last samples, 9000 and 9003. Found before and after the call,
        # the identity lived at 9003; before only, it lived at 9000 and was gone by 9003; neither
        # time, it was gone by 9000; after only, it lived at 9003, and the contradiction never
        # joins. A later read at 20000 finds it gone, with one CRASH row.
        error = ('ERROR', 'android.os.RemoteException')

        def entry(before, after, partial, elapsed=9000):
            ob = observation(elapsed, before=before, after=after, **({'current': error} if partial else {}))
            status, _, decision = judge(ob, context(two()))
            return trail_entry(status, decision, elapsed - 10, elapsed + 100, helper=[ob['reply']])

        def now(at):
            return observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + at)])
        states = (('ALIVE', PROCESS, PROCESS, {'after': 9003, 'by': 20_000},
                   ('PENDING', 'PENDING', 'QUALIFIED_LIFECYCLE_JOIN')),
                  ('WENT', PROCESS, None, {'after': 9000, 'by': 9003},
                   ('PENDING', 'QUALIFIED_LIFECYCLE_JOIN', 'INCONCLUSIVE')),
                  ('GONE', None, None, {'after': 3003, 'by': 9000},
                   ('QUALIFIED_LIFECYCLE_JOIN', 'INCONCLUSIVE', 'INCONCLUSIVE')),
                  ('UNKNOWN', None, PROCESS, {'after': 9003, 'by': 20_000},
                   ('INCONCLUSIVE', 'INCONCLUSIVE', 'INCONCLUSIVE')))
        for name, before, after, loss, expected in states:
            for partial in (True, False):
                trail = [entry(before, after, partial)]
                for at, decided in zip((5000, 10_001, 12_000), expected):
                    with self.subTest(name, partial=partial, row=at):
                        status, _, decision = judge(now(at), context(two(), trail), freshness=Fresh())
                        self.assertEqual((decision['decision'], decision['loss']), (decided, loss))
        # After a read that found it gone, a read that finds it living, before the call or after
        # it, refuses the join; one that finds it gone again keeps the first loss.
        for name, before, after, _, _ in states:
            with self.subTest('after a gone read', state=name):
                trail = [entry(None, None, True), entry(before, after, True, elapsed=12_000)]
                status, reason, decision = judge(now(8000), context(two(), trail), freshness=Fresh())
                if name == 'GONE':
                    self.assertEqual((status, decision['loss']['by']), ('BAD', 9000))
                else:
                    self.assertEqual(status, 'UNKNOWN')
                    self.assertIn('the identity was seen again after it was gone', reason)
        # A baseline that misses the identity between baselines that find it is the same
        # contradiction. Its honest control: one before them all, which may precede the birth.
        for name, bases, expected in (
                ('missed between', [baseline(1, 1000), baseline(2, 2000, process=None), baseline(3, 3000)],
                 'INCONCLUSIVE'),
                ('another process between', [baseline(1, 1000), baseline(2, 2000, process=[1700, 4000, UID0, CONTEXT]),
                                             baseline(3, 3000)], 'INCONCLUSIVE'),
                ('missed before them', [baseline(0, 500, process=None), baseline(1, 1000), baseline(3, 3000)],
                 'QUALIFIED_LIFECYCLE_JOIN')):
            with self.subTest(name):
                status, reason, decision = judge(now(8000), context(bases), freshness=Fresh())
                self.assertEqual(decision['decision'], expected)
                if expected == 'INCONCLUSIVE':
                    self.assertIn('a baseline did not find the identity between baselines that did', reason)
                self.assertEqual(judge(observation(9000), context(bases)), ('HELD', '', None))

    def test_this_reads_discovery_before_the_call_bounds_the_loss(self):
        # A read that finds the identity before the call and not after it saw it living at its
        # first sample. After a held probe at 8990, a CRASH row placed at 15000 is from before this
        # read found it living at 20000: late, never a join. Its honest control: the same row when
        # this read finds it neither time, which qualifies with the fixture.
        held = context(two(), [trail_entry('HELD', None, 8990, 9100)])
        row = [exit_row(timestamp=WALL + 15_000)]
        status, _, decision = judge(observation(20_000, before=PROCESS, after=None, rows=row), held,
                                    freshness=Fresh())
        self.assertEqual((status, decision['decision'], decision['loss']),
                         ('UNKNOWN', 'PENDING', {'after': 20_000, 'by': None}))
        self.assertIn('a late exit row from before the identity was last seen living', decision['exclusions'])
        status, _, decision = judge(observation(20_000, before=None, after=None, rows=row), held,
                                    freshness=Fresh())
        self.assertEqual((status, decision['decision'], decision['loss']),
                         ('BAD', 'QUALIFIED_LIFECYCLE_JOIN', {'after': 8990, 'by': 20_000}))
        # Found before the call after an earlier read found it gone: no loss can be placed.
        gone = observation(9000, before=None, after=None)
        trail = [trail_entry('UNKNOWN', judge(gone, context(two()))[2], 8990, 9100, helper=[gone['reply']])]
        status, reason, _ = judge(observation(20_000, before=PROCESS, after=None, rows=row), context(two(), trail),
                                  freshness=Fresh())
        self.assertEqual(status, 'UNKNOWN')
        self.assertIn('the identity was seen again after it was gone', reason)

    def test_a_late_row_from_before_the_window_is_never_a_new_window_crash(self):
        # The review's case: whole baselines at 1000 and 3000, the window opening at 10000, and a
        # read at 20000 finding the identity gone with a CRASH row placed at 8000, after the last
        # baseline but before the window. A late publication does not make it the window's: it is
        # a prewindow exit, never a newly induced failure, so the fixture is never asked. Its
        # honest control: the same row placed at 12000, inside the window, qualifies.
        window = dict(WINDOW, start=10_000, end=1_000_000)

        def gone(at, win=window):
            fresh = Fresh()
            now = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + at)])
            return judge(now, context(two(), window=win), freshness=fresh), fresh.asked
        (status, reason, decision), asked = gone(8000)
        self.assertEqual((status, decision['decision'], asked), ('UNKNOWN', 'INCONCLUSIVE', []))
        self.assertIn('a prewindow exit, not a newly induced failure', reason)
        (status, _, decision), _ = gone(12_000)
        self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))
        # Within the clock tolerance of either bound, a row is not placed inside the window.
        for at, win, expected in ((10_500, window, 'INCONCLUSIVE'), (11_001, window, 'QUALIFIED_LIFECYCLE_JOIN'),
                                  (14_500, dict(window, end=15_000), 'INCONCLUSIVE'),
                                  (13_999, dict(window, end=15_000), 'QUALIFIED_LIFECYCLE_JOIN')):
            with self.subTest(row=at, end=win['end']):
                self.assertEqual(gone(at, win)[0][2]['decision'], expected)
        # The prewindow row keeps a living read from holding, as any row new since the baselines
        # does, and never makes it a failure.
        for pid in (PROCESS[0], 1700):
            with self.subTest('living', pid=pid):
                now = observation(20_000, rows=[exit_row(timestamp=WALL + 8000, pid=pid)])
                status, _, decision = judge(now, context(two(), window=window), freshness=Fresh())
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))

    def test_a_window_that_places_no_row_or_a_loss_before_it_qualifies_nothing(self):
        # A window that is not this boot's whole window places no exit row: missing, of no known
        # form, or of another boot than the baselines. A loss already seen before the window opened
        # was no failure of it, so it is settled, never pending. Each beside the default window,
        # where the same reads qualify or stay pending.
        now = observation(20_000, before=None, after=None, rows=[exit_row(timestamp=WALL + 8000)])
        for name, win in (('missing', None), ('of no known form', dict(WINDOW, start=20_000, end=10_000)),
                          ('of another boot', dict(WINDOW, boot='ff' * 16))):
            with self.subTest(name):
                status, reason, decision = judge(now, context(two(), window=win), freshness=Fresh())
                self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                self.assertIn('no exit row can be placed in it', reason)
        self.assertEqual(judge(now, context(two()), freshness=Fresh())[2]['decision'], 'QUALIFIED_LIFECYCLE_JOIN')
        # An earlier read found the identity gone at 9000, and the window opened at 12000.
        gone = observation(9000, before=None, after=None)
        trail = [trail_entry('UNKNOWN', judge(gone, context(two()))[2], 8990, 9100, helper=[gone['reply']])]
        later = observation(20_000, before=None, after=None)
        status, reason, decision = judge(later, context(two(), trail, window=dict(WINDOW, start=12_000)))
        self.assertEqual((status, decision['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('a prewindow loss, not a newly induced failure', reason)
        self.assertEqual(judge(later, context(two(), trail))[2]['decision'], 'PENDING')

    def test_a_current_report_first_seen_at_the_windows_first_read_is_inconclusive(self):
        # The decision's case: a current CRASHED or NOT_RESPONDING report carries no time, and the
        # window's first read is the first to see it, so it may have begun between the last
        # baseline and the window's start. It is not shown to be new: INCONCLUSIVE, which refuses
        # the hold, never a crash. So is a report whose earlier reads cannot show it absent inside
        # the window. Its honest control: a probe held at 6000, inside the window, which qualifies.
        error = ('ERROR', 'android.os.RemoteException')

        def entry(ob):
            status, _, decision = judge(ob, context(two()))
            return trail_entry(status, decision, 5990, 6100, helper=[ob['reply']])
        held = trail_entry('HELD', None, 6000, 6100)
        for condition in (1, 2):
            now = observation(9000, entries=[report(condition=condition)])
            for name, ctx in (
                    ('the first read', context(two())),
                    ('a held read before the window opened', context(two(), [trail_entry('HELD', None, 3200, 3300)])),
                    ('an earlier read whose current list failed', context(two(), [entry(observation(6000, current=error))])),
                    ('an earlier read that already listed it',
                     context(two(), [entry(observation(6000, entries=[report(condition=condition)]))])),
                    ('an earlier read that found the process before the call only',
                     context(two(), [entry(observation(6000, before=PROCESS, after=None))])),
                    ('no window to place an earlier read in', context(two(), [held], window=None))):
                with self.subTest(name, condition=condition):
                    status, reason, decision = judge(now, ctx)
                    self.assertEqual((status, decision['decision'], decision['qualified']),
                                     ('UNKNOWN', 'INCONCLUSIVE', None))
                    self.assertTrue(reason.startswith('a current report'), reason)
            with self.subTest('its honest control', condition=condition):
                status, _, decision = judge(now, context(two(), [held]))
                self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_CURRENT_ERROR'))

    def test_an_earlier_read_whose_history_was_denied_never_shows_a_report_absent(self):
        # The review's case: at 6000 the same process lives before and after the helper, its
        # history is denied with a SecurityException and its current list is whole and empty.
        # Without DUMP the service silently leaves out every UID but the shell's, so that empty list
        # may hide a report: it shows none absent. At 9000 the list holds an ANR of the same
        # process, which stays INCONCLUSIVE, as after a history that failed otherwise. Its honest
        # control: a whole covered clean read, a held probe, then the same ANR, which qualifies.
        anr = report(condition=2, short='ANR', long='old ANR', stack=None)
        now = observation(9000, entries=[anr])
        for name, history in (('denied', ('ERROR', 'java.lang.SecurityException')),
                              ('failed otherwise', ('ERROR', 'android.os.RemoteException'))):
            with self.subTest(name):
                earlier = observation(6000, history=history)
                first = judge(earlier, context(two()))
                self.assertEqual((first[2]['decision'], first[2]['observed']['before']), ('INCONCLUSIVE', PROCESS))
                trail = [trail_entry(first[0], first[2], 5990, 6100, helper=[earlier['reply']])]
                status, reason, decision = judge(now, context(two(), trail))
                self.assertEqual((status, decision['decision'], decision['qualified']),
                                 ('UNKNOWN', 'INCONCLUSIVE', None))
                self.assertIn('not shown to begin in the window', reason)
        status, _, decision = judge(now, context(two(), [trail_entry('HELD', None, 6000, 6100)]))
        self.assertEqual((status, decision['decision']), ('BAD', 'QUALIFIED_CURRENT_ERROR'))

    def test_a_current_report_first_absent_then_present_in_the_window_qualifies(self):
        # The decision's positive: an earlier read inside the window found the same living birth
        # identity without the report, so the report began in the window: a newly induced failure.
        # That read may be a held probe, or a decision whose discovery found the process before and
        # after its call with a whole reply, whose history part shows the list covered it. A report
        # cleared and present again is new again after the read that found it gone.
        def entry(ob, begin):
            status, _, decision = judge(ob, context(two()))
            return trail_entry(status, decision, begin - 10, begin + 100, helper=[ob['reply']])
        unheld = entry(observation(6000, rows=[exit_row(timestamp=WALL - 90_000, pid=1700)]), 6000)
        cleared = [entry(observation(5000, entries=[report()]), 5000), trail_entry('HELD', None, 7000, 7100)]
        for name, trail in (('a held probe', [trail_entry('HELD', None, 6000, 6100)]),
                            ('a whole read that did not hold, for a new row of another process', [unheld]),
                            ('a report cleared, then present again', cleared)):
            for condition in (1, 2):
                with self.subTest(name, condition=condition):
                    status, reason, decision = judge(observation(9000, entries=[report(condition=condition)]),
                                                     context(two(), trail))
                    self.assertEqual((status, decision['decision'], decision['qualified'][0]),
                                     ('BAD', 'QUALIFIED_CURRENT_ERROR', condition))
                    self.assertIn('absent from an earlier read of it in the window', reason)


class WitnessBase(test_health.HealthBase):
    """A broker over the simulated guest with the real composer, whose bit 1 reader and baseline
    witness are this reader, for the system user."""

    def harness(self, cross_user=False, freshness=None, **options):
        sim = sim_android.SimAndroid()
        sim.enable_user_forms()
        witness = health_witness.WitnessReader(cross_user=cross_user, freshness=freshness)
        composer = health_compose.Composer({test_health.APK: 'WS-A'}, notice_package=sim_android.NOTICE_PACKAGE,
                                           ce_reader=sim_android.SimCeReader(), witness=witness)
        reader = {'users': True, 'receipts': True, 'health': True, 'witness': True, 'global_sessions': True,
                  'composer': composer, 'baseline': health_baseline.BaselineReader(witness)}
        h = Harness(next_profile=True, sim=sim, specs=test_health.specs(), reader=reader, notice=sim_android.SimNotice(),
                    health=sim_android.SimUiPreparation(), work=sim_android.SimWork(), private=True, **options)
        h.forms = sim.forms
        self.addCleanup(h.close)
        return h

    def window(self, h, baselines=2):
        """The system user's baselines, a second apart, then the window opening: its start."""
        self.variant(h)
        for i in range(baselines):
            h.broker.health_baseline(TICKET, PLAN, 0, 0, 'baseline %d before the window opens' % i)
            h.sim.tick(1000)
        start = h.sim.uptime
        self.store(h, start)
        return start

    def probe_system(self, h):
        self.prepare(h, labtest.PREPARATION_ACTION)
        envelopes = self.probe(h)
        group, manifest = self.composition(h, 0)
        return envelopes, group, manifest

    def bit1(self, manifest):
        return manifest['projection']['rows'][1], manifest['projection']['candidate']['witness']


class ReaderTests(WitnessBase):
    """Bit 1's reader through the broker: the composer's hook and the baseline reader's."""

    def test_an_honest_probe_holds_bit_1_on_repeated_whole_baselines(self):
        h = self.harness()
        self.window(h)
        baselines = self.groups(h, 'health-baseline')
        self.assertEqual([(g['status'], g['complete']) for g in baselines], [('facts', True)] * 2)
        facts = baselines[-1]['projection']['facts']
        self.assertEqual({facts[k]['schema'] for k in ('history', 'current_errors')}, {process_health.SCHEMA})
        self.assertEqual(facts['history']['reading']['process'][:2], h.forms.processes[0])
        envelopes, group, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], row['baseline'], witness), ('HELD', baselines[-1]['compound']['sha256'], None))
        self.assertTrue(row['children'])
        commands = [h.broker.ledger.entries[n - 1].content['intent']['command'] for n in group['captures']]
        for command in (health_witness.BOOT_ID, health_witness.FRAMEWORK_PID, process_health.command(0),
                        process_health.HELPER_DIGEST):
            self.assertIn(command, commands)
        self.assertEqual(group['witness'], {'status': 'HELD', 'decision': None})
        self.assertEqual(h.broker.witness_trail[(h.sim.boot, 0, 0)][0]['status'], 'HELD')
        # The baseline before the window is the one relied on, once, by the HEALTH it emits.
        self.assertEqual(len(envelopes), 1)

    def test_a_current_report_is_a_crash_and_missing_evidence_is_inconclusive(self):
        # A first probe inside the window holds; the report appears after it.
        h = self.harness()
        self.window(h)
        self.assertEqual(self.bit1(self.probe_system(h)[2])[0]['status'], 'HELD')
        h.sim.error_states.append(report(pid=h.forms.processes[0][0]))
        envelopes, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision']), ('BAD', 'QUALIFIED_CURRENT_ERROR'))
        self.assertEqual(row['witness']['decision'], 'QUALIFIED_CURRENT_ERROR')
        self.assertEqual(self.classification(envelopes[0]), 'CRASH')
        for name, change in (('no helper', lambda sim: setattr(sim, 'process_helper', False)),
                             ('another helper', lambda sim: setattr(sim, 'process_helper', 'ab' * 32)),
                             ('a denied history', lambda sim: sim.process_failures.update(
                                 history=('ERROR', 'java.lang.SecurityException'))),
                             ('a reply cut short', lambda sim: sim.scripts.update(
                                 {process_health.command(0): [lambda c: sim_android.result(c, 0, b'andrix-process')]}))):
            with self.subTest(name):
                h = self.harness()
                self.window(h)
                self.probe_system(h)
                h.sim.error_states.append(report(pid=h.forms.processes[0][0]))
                change(h.sim)
                envelopes, group, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((group['status'], row['status'], witness['decision']),
                                 ('facts', 'UNKNOWN', 'INCONCLUSIVE'))
                self.assertEqual(self.classification(envelopes[0]), 'INCONCLUSIVE')

    def test_a_lost_process_stays_pending_then_inconclusive_across_probes(self):
        h = self.harness()
        self.window(h)
        _, first, manifest = self.probe_system(h)
        self.assertEqual(self.bit1(manifest)[0]['status'], 'HELD')
        h.sim.systemui_exit(0, published=False)
        _, second, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision'], witness['observed']['state']),
                         ('UNKNOWN', 'PENDING', 'GONE'))
        # The interval in which it went: after the probe that saw it living, by this one.
        self.assertGreaterEqual(witness['loss']['after'], first['brackets']['begin']['elapsed'])
        self.assertLessEqual(witness['loss']['by'], second['brackets']['end']['elapsed'])
        # A crash row published late, with no independent evidence of this boot, stays pending.
        h.sim.exit_rows.append(exit_row(timestamp=h.sim.wall(), pid=witness['birth']['pid']))
        _, _, manifest = self.probe_system(h)
        row, later = self.bit1(manifest)
        self.assertEqual((row['status'], later['decision'], later['loss']['by']), ('UNKNOWN', 'PENDING',
                                                                                   witness['loss']['by']))
        h.sim.tick(health_witness.PENDING_BOUND_MS)
        envelopes, _, manifest = self.probe_system(h)
        row, last = self.bit1(manifest)
        self.assertEqual((row['status'], last['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertEqual(self.classification(envelopes[0]), 'INCONCLUSIVE')
        trail = h.broker.witness_trail[(h.sim.boot, 0, 0)]
        self.assertEqual([t['status'] for t in trail], ['HELD', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN'])

    def test_a_baseline_needs_the_helpers_whole_read_and_repeats_are_taken_before_the_window(self):
        h = self.harness()
        self.variant(h)
        h.sim.process_helper = False
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'no helper')
        h.sim.process_helper = True
        h.sim.process_failures['current'] = ('ERROR', 'android.os.RemoteException')
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'a remote failure')
        h.sim.process_failures.clear()
        good = h.broker.health_baseline(TICKET, PLAN, 0, 0, 'the one whole baseline')
        self.assertEqual([g['status'] for g in self.groups(h, 'health-baseline')],
                         ['unclassified', 'unavailable', 'facts'])
        h.sim.tick(1000)
        self.store(h, h.sim.uptime)
        _, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('not repeated', witness['exclusions'][0])
        self.assertEqual(witness['old'], None)
        self.assertEqual(h.broker.ledger.entries[good - 1].content['complete'], True)
        # A whole baseline taken after the window opened is no repeat: it relies on nothing.
        self.between(h)
        h.broker.health_baseline(TICKET, PLAN, 0, 0, 'a whole baseline after the window opened')
        _, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('not repeated', witness['exclusions'][0])

    def test_a_reopening_rebuilds_the_trail_and_refuses_a_changed_copy(self):
        h = self.harness()
        self.window(h)
        self.probe_system(h)
        h.sim.systemui_exit(0, published=False)
        _, group, _ = self.probe_system(h)
        self.between(h)
        trail = copy.deepcopy(h.broker.witness_trail)
        h.reopen()
        self.assertEqual(h.broker.witness_trail, trail)
        reopening = test_health.ReopeningTests.copy_and_open
        intact = reopening(self, h, lambda root: None)
        self.assertEqual(intact.witness_trail, trail)
        intact.close()

        def held(root):
            manifest = lab_evidence.parse((root / group['compound']['path']).read_bytes())
            manifest['extra']['witness'] = {'status': 'HELD', 'decision': None}
            data = lab_evidence.canonical(manifest)
            digest = hashlib.sha256(data).hexdigest()
            (root / 'compound' / digest).write_bytes(data)
            entry = next(p for p in (root / 'ledger').iterdir() if p.name.startswith('%06d-' % group['number']))
            record = json.loads((entry / 'record.json').read_text())
            record.update(witness=manifest['extra']['witness'], compound={'path': 'compound/' + digest,
                                                                           'sha256': digest, 'bytes': len(data)})
            (entry / 'record.json').write_bytes(json.dumps(record, indent=1, sort_keys=True).encode() + b'\n')
        with self.assertRaisesRegex(lab_broker.BrokerError, "its copy of bit 1's witness is not its projection's"):
            reopening(self, h, held).close()


    def test_a_baseline_report_cleared_while_its_process_lives_is_no_hold_through_the_broker(self):
        # The review's case through the broker: both baselines hold an ANR report of the process,
        # which is cleared, as a waited ANR dialog clears it, while the same process lives on.
        h = self.harness()
        h.sim.error_states.append(report(pid=h.forms.processes[0][0], condition=2))
        self.window(h)
        self.assertEqual(len(self.groups(h, 'health-baseline')[-1]['projection']['facts']['current_errors']
                             ['reading']['entries']), 1)
        h.sim.error_states.clear()
        envelopes, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertIn('in a baseline', witness['exclusions'][0])
        self.assertEqual(self.classification(envelopes[0]), 'INCONCLUSIVE')
        # Its honest control: the same probe after baselines without the report holds.
        h = self.harness()
        self.window(h)
        _, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness), ('HELD', None))

    def test_a_wall_clock_step_a_held_probe_read_is_kept_through_the_broker(self):
        # The review's case through the broker: a probe holds while the wall clock reads 60 s ahead;
        # the clock comes back, the process exits with a published crash row, and the next probe has
        # the host fixture's independent evidence. The held probe's own recorded reply keeps the
        # step, so no row is placed. Its honest control is the same without the step.
        for step, expected in ((60_000, ('UNKNOWN', 'INCONCLUSIVE')), (0, ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))):
            with self.subTest(step=step):
                h = self.harness(freshness=Fresh())
                self.window(h)
                h.sim.wall_step = step
                _, _, manifest = self.probe_system(h)
                self.assertEqual(self.bit1(manifest)[0]['status'], 'HELD')
                h.sim.wall_step = 0
                h.sim.tick(2000)
                h.sim.systemui_exit(0)
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((row['status'], witness['decision']), expected)
                if step:
                    self.assertIn('a wall clock offset change', witness['exclusions'][0])
                else:
                    self.assertEqual(self.classification(envelopes[0]), 'CRASH')

    def test_an_older_baseline_without_its_process_never_vetoes_two_whole_ones(self):
        # The review's case through the broker: a baseline read whole while the process was absent,
        # then two whole baselines of it, then a new current CRASHED report of the living process,
        # which appears after a first probe inside the window.
        def run(order):
            h = self.harness()
            self.variant(h)
            process = list(h.forms.processes[0])
            for present in order:
                if present:
                    h.forms.processes[0] = list(process)
                else:
                    h.forms.processes.pop(0, None)
                h.broker.health_baseline(TICKET, PLAN, 0, 0, 'a baseline, its process %s' % (
                    'present' if present else 'absent'))
                h.sim.tick(1000)
            h.forms.processes[0] = list(process)
            self.assertEqual([(g['status'], g['complete']) for g in self.groups(h, 'health-baseline')],
                             [('facts', present) for present in order])
            self.store(h, h.sim.uptime)
            self.probe_system(h)
            h.sim.error_states.append(report(pid=process[0]))
            return self.bit1(self.probe_system(h)[2])
        row, witness = run((False, True, True))
        self.assertEqual((row['status'], witness['decision']), ('BAD', 'QUALIFIED_CURRENT_ERROR'))
        # Its honest control: whole, whole, then one without the process last, which the baseline
        # selection relies on none of, so the same report is no evidence.
        row, witness = run((True, True, False))
        self.assertEqual((row['status'], witness['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        self.assertEqual(witness['exclusions'], ['no valid baseline relied on'])

    def test_an_update_read_again_is_still_never_new_through_the_broker(self):
        # The review's case through the broker: a living probe reads a late UNKNOWN row of the
        # process's PID; the process exits and Android updates that record to a CRASH at the exit
        # time; the next probe excludes the update, and so does each probe after it that reads the
        # updated row unchanged, with the host fixture's evidence at hand.
        h = self.harness(freshness=Fresh())
        self.window(h)
        old = exit_row(timestamp=WALL + 500, reason=0, pid=h.forms.processes[0][0])
        h.sim.exit_rows.append(old)
        _, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['observed']['state']), ('UNKNOWN', 'ALIVE'))
        h.sim.tick(2000)
        h.sim.systemui_exit(0, published=False)
        old.update(timestamp=h.sim.wall(), reason=4)
        for poll in range(3):
            with self.subTest(poll=poll):
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((row['status'], witness['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                self.assertIn('never a new exit', witness['exclusions'][0])
                self.assertEqual(self.classification(envelopes[0]), 'INCONCLUSIVE')
        # Its honest control: with no earlier read of that record, the crash row read first without
        # independent evidence leaves the loss pending, and read again unchanged once the fixture
        # gives its evidence, it qualifies.
        later = Later()
        h = self.harness(freshness=later)
        self.window(h)
        _, _, manifest = self.probe_system(h)
        self.assertEqual(self.bit1(manifest)[0]['status'], 'HELD')
        h.sim.tick(2000)
        h.sim.systemui_exit(0)
        _, _, manifest = self.probe_system(h)
        self.assertEqual(self.bit1(manifest)[1]['decision'], 'PENDING')
        later.given = True
        envelopes, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision']), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))
        self.assertEqual(self.classification(envelopes[0]), 'CRASH')

    def test_a_wall_clock_step_a_partial_read_saw_is_kept_through_the_broker(self):
        # The review's case through the broker: a probe's current error list fails while the wall
        # clock reads 60 s ahead, so it judges nothing; the clock comes back, the process exits with
        # a published crash row, and the next probe has the host fixture's evidence. The partial
        # probe's own recorded reply keeps the step, so no row is placed. Its honest control is the
        # same partial probe, with the same error, on a steady clock.
        for step, expected in ((60_000, ('UNKNOWN', 'INCONCLUSIVE')), (0, ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))):
            with self.subTest(step=step):
                h = self.harness(freshness=Fresh())
                self.window(h)
                h.sim.wall_step = step
                h.sim.process_failures['current'] = ('ERROR', 'android.os.RemoteException')
                _, _, manifest = self.probe_system(h)
                row, first = self.bit1(manifest)
                self.assertEqual((row['status'], first['decision'], first['birth']), ('UNKNOWN', 'INCONCLUSIVE', None))
                h.sim.wall_step = 0
                h.sim.process_failures.clear()
                h.sim.tick(2000)
                h.sim.systemui_exit(0)
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((row['status'], witness['decision']), expected)
                if step:
                    self.assertIn('a wall clock offset change', witness['exclusions'][0])
                else:
                    self.assertEqual(self.classification(envelopes[0]), 'CRASH')

    def test_a_partial_reads_whole_discovery_bounds_the_loss_through_the_broker(self):
        # Through the broker: the process exits unpublished, and a probe whose current error list
        # fails finds it gone, judging nothing. A crash row of its PID placed after that probe is
        # not its exit, even with the host fixture's evidence; its honest control, the same record
        # placed at the exit before that probe, qualifies.
        for placed_later, expected in ((True, ('UNKNOWN', 'INCONCLUSIVE')),
                                       (False, ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))):
            with self.subTest(placed_later=placed_later):
                h = self.harness(freshness=Fresh())
                self.window(h)
                h.sim.tick(2000)
                record = h.sim.systemui_exit(0, published=False)
                h.sim.process_failures['current'] = ('ERROR', 'android.os.RemoteException')
                _, _, manifest = self.probe_system(h)
                row, first = self.bit1(manifest)
                self.assertEqual((row['status'], first['birth']), ('UNKNOWN', None))
                h.sim.process_failures.clear()
                h.sim.tick(7000)
                h.sim.exit_rows.append(dict(record, timestamp=h.sim.wall()) if placed_later else record)
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((row['status'], witness['decision']), expected)
                if placed_later:
                    self.assertIn('after the identity was already gone', witness['exclusions'][0])
                else:
                    self.assertEqual(self.classification(envelopes[0]), 'CRASH')

    def test_an_earlier_read_that_found_the_identity_only_after_the_call_never_joins_through_the_broker(self):
        # The review's case through the broker: a probe's discovery misses the process before the
        # helper's call and finds the same birth identity after it, its current list failing or
        # whole. The process then exits unpublished, and a later probe reads a CRASH row placed
        # 2000 ms before the earlier probe's last sample, with the host fixture's evidence. Its
        # honest control finds the process before the call too: the same row is late, and a row
        # placed 2000 ms after that sample qualifies.
        def run(partial, found_before, shift):
            h = self.harness(freshness=Fresh())
            self.window(h)
            h.sim.tick(2000)
            original = list(h.forms.processes[0])
            if not found_before:
                h.forms.processes.pop(0)

                def identify_after(command):
                    h.forms.processes[0] = list(original)
                    return h.sim._process_health(command)
                h.sim.scripts[process_health.command(0)] = [identify_after]
            if partial:
                h.sim.process_failures['current'] = ('ERROR', 'android.os.RemoteException')
            self.probe_system(h)
            reply = h.broker._trail(h.sim.boot, 0, 0)[-1]['helper'][0]
            last = process_health.parse_reply(*reply, 0)['current']['samples'][1][0]
            h.sim.process_failures.clear()
            h.sim.tick(4000)
            h.sim.systemui_exit(0, published=False)
            h.sim.exit_rows.append(exit_row(timestamp=WALL + last + shift, pid=original[0]))
            envelopes, _, manifest = self.probe_system(h)
            row, witness = self.bit1(manifest)
            return row['status'], witness['decision'], witness['exclusions'], self.classification(envelopes[0])
        for partial in (True, False):
            with self.subTest(partial=partial):
                status, decision, exclusions, classification = run(partial, False, -2000)
                self.assertEqual((status, decision, classification), ('UNKNOWN', 'INCONCLUSIVE', 'INCONCLUSIVE'))
                self.assertIn('found the identity only after the call', exclusions[0])
                status, decision, exclusions, classification = run(partial, True, -2000)
                self.assertEqual((status, decision, classification), ('UNKNOWN', 'PENDING', 'INCONCLUSIVE'))
                self.assertIn('a late exit row from before the identity was last seen living', exclusions)
        status, decision, _, classification = run(False, True, 2000)
        self.assertEqual((status, decision, classification), ('BAD', 'QUALIFIED_LIFECYCLE_JOIN', 'CRASH'))
        status, decision, exclusions, classification = run(False, False, 2000)
        self.assertEqual((status, decision, classification), ('UNKNOWN', 'INCONCLUSIVE', 'INCONCLUSIVE'))
        self.assertIn('found the identity only after the call', exclusions[0])

    def test_a_read_that_finds_the_process_only_before_the_call_bounds_the_loss_through_the_broker(self):
        # Through the broker: after a held probe, the process exits during a later probe's helper
        # call, so that probe finds it before the call only. A CRASH row placed 5 s before that
        # probe is from before it was found living: late, even with the host fixture's evidence.
        # Its honest control: the process exits at that row's time, before the probe, which
        # qualifies.
        for during, expected in ((True, ('UNKNOWN', 'PENDING')), (False, ('BAD', 'QUALIFIED_LIFECYCLE_JOIN'))):
            with self.subTest(during_the_call=during):
                h = self.harness(freshness=Fresh())
                self.window(h)
                _, _, manifest = self.probe_system(h)
                self.assertEqual(self.bit1(manifest)[0]['status'], 'HELD')
                h.sim.tick(5000)
                if during:
                    record = exit_row(timestamp=h.sim.wall(), pid=h.forms.processes[0][0])

                    def exit_during(command, h=h):
                        h.sim.systemui_exit(0, published=False)
                        return h.sim._process_health(command)
                    h.sim.scripts[process_health.command(0)] = [exit_during]
                else:
                    record = h.sim.systemui_exit(0, published=False)
                h.sim.tick(5000)
                h.sim.exit_rows.append(record)
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((row['status'], witness['decision']), expected)
                if during:
                    self.assertEqual(witness['observed']['state'], 'WENT')
                    self.assertIn('a late exit row from before the identity was last seen living',
                                  witness['exclusions'])
                else:
                    self.assertEqual(self.classification(envelopes[0]), 'CRASH')

    def test_a_late_row_from_before_the_window_is_never_a_new_window_crash_through_the_broker(self):
        # The review's case through the broker: two whole baselines, then the process exits 2 s
        # later with its record unpublished, and the window opens 5 s after the exit. The record is
        # published unchanged once the window is open, and a probe reads it with the host fixture's
        # evidence: a prewindow exit, never a crash of the window. Its honest control opens the
        # window before the same exit, which qualifies.
        for before_window, expected in ((True, ('UNKNOWN', 'INCONCLUSIVE', 'INCONCLUSIVE')),
                                        (False, ('BAD', 'QUALIFIED_LIFECYCLE_JOIN', 'CRASH'))):
            with self.subTest(before_window=before_window):
                h = self.harness(freshness=Fresh())
                self.variant(h)
                for i in range(2):
                    h.broker.health_baseline(TICKET, PLAN, 0, 0, 'whole baseline %d' % i)
                    h.sim.tick(1000)
                if not before_window:
                    self.store(h, h.sim.uptime)
                h.sim.tick(2000)
                record = h.sim.systemui_exit(0, published=False)
                h.sim.tick(5000)
                if before_window:
                    self.store(h, h.sim.uptime)
                h.sim.exit_rows.append(record)
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual(record['timestamp'] - WALL < manifest['projection']['window']['start'],
                                 before_window)
                self.assertEqual((row['status'], witness['decision'], self.classification(envelopes[0])), expected)
                if before_window:
                    self.assertIn('a prewindow exit, not a newly induced failure', witness['exclusions'][0])

    def test_a_current_report_first_seen_at_the_windows_first_read_is_inconclusive_through_the_broker(self):
        # The decision's case through the broker: the report is already listed at the window's first
        # probe. It refuses the hold but is no crash, and the probe after it, which sees it again,
        # has no read of the window without it either.
        for condition in (1, 2):
            with self.subTest(condition=condition):
                h = self.harness()
                self.window(h)
                h.sim.error_states.append(report(pid=h.forms.processes[0][0], condition=condition))
                for probe in range(2):
                    envelopes, _, manifest = self.probe_system(h)
                    row, witness = self.bit1(manifest)
                    self.assertEqual((row['status'], witness['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
                    self.assertIn('not shown to begin in the window', witness['exclusions'][0])
                    self.assertEqual(self.classification(envelopes[0]), 'INCONCLUSIVE')

    def test_an_earlier_read_whose_history_was_denied_never_shows_a_report_absent_through_the_broker(self):
        # The review's case through the broker: an ANR of the process appears 2 s before the window
        # opens and never clears. The window's first probe gets a reply whose history is denied and
        # whose current list, filtered to the shell's own UID, is whole and empty: INCONCLUSIVE. The
        # second probe's whole reply lists the same ANR, still never shown absent in the window:
        # INCONCLUSIVE, never CRASH. Its honest control: a whole covered clean read, then a new ANR.
        h = self.harness()
        self.variant(h)
        for i in range(2):
            h.broker.health_baseline(TICKET, PLAN, 0, 0, 'whole baseline %d' % i)
            h.sim.tick(1000)
        h.sim.tick(2000)
        anr = report(pid=h.forms.processes[0][0], condition=2, short='ANR', long='old ANR', stack=None)
        h.sim.error_states.append(anr)
        h.sim.tick(2000)
        self.store(h, h.sim.uptime)

        def denied_and_filtered(command):
            code, text = sim_android.process_health_reply(0, ('ERROR', 'java.lang.SecurityException'), ('OK', []),
                                                          [[h.sim.uptime, h.sim.wall()]] * 4)
            return sim_android.result(command, code, text.encode())
        h.sim.scripts[process_health.command(0)] = [denied_and_filtered]
        _, _, manifest = self.probe_system(h)
        row, first = self.bit1(manifest)
        self.assertEqual((row['status'], first['decision']), ('UNKNOWN', 'INCONCLUSIVE'))
        envelopes, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual(h.sim.error_states, [anr])
        self.assertEqual((row['status'], witness['decision'], self.classification(envelopes[0])),
                         ('UNKNOWN', 'INCONCLUSIVE', 'INCONCLUSIVE'))
        self.assertIn('not shown to begin in the window', witness['exclusions'][0])
        h = self.harness()
        self.window(h)
        self.assertEqual(self.bit1(self.probe_system(h)[2])[0]['status'], 'HELD')
        h.sim.error_states.append(report(pid=h.forms.processes[0][0], condition=2))
        envelopes, _, manifest = self.probe_system(h)
        row, witness = self.bit1(manifest)
        self.assertEqual((row['status'], witness['decision'], self.classification(envelopes[0])),
                         ('BAD', 'QUALIFIED_CURRENT_ERROR', 'CRASH'))

    def test_a_current_report_first_absent_then_present_in_the_window_qualifies_through_the_broker(self):
        # The decision's positive through the broker: the window's first probe holds, finding the
        # process living without a report; the report appears after it, and the next probe finds
        # it: a newly induced failure, CRASH.
        for condition in (1, 2):
            with self.subTest(condition=condition):
                h = self.harness()
                self.window(h)
                _, _, manifest = self.probe_system(h)
                self.assertEqual(self.bit1(manifest)[0]['status'], 'HELD')
                h.sim.error_states.append(report(pid=h.forms.processes[0][0], condition=condition))
                envelopes, _, manifest = self.probe_system(h)
                row, witness = self.bit1(manifest)
                self.assertEqual((row['status'], witness['decision'], witness['qualified'][0]),
                                 ('BAD', 'QUALIFIED_CURRENT_ERROR', condition))
                self.assertEqual(self.classification(envelopes[0]), 'CRASH')

if __name__ == '__main__':
    unittest.main()
