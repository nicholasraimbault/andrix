# SPDX-License-Identifier: Apache-2.0
"""The next profile's real readers behind ObserverAdapter: the whole global session inventory of
global_sessions.py over the public observer's captured and source derived forms, and the notice
fixture's receipt rows read for exactly the recipients the broker passes. Each changed form must
give no reading, or the class it names, for its own reason while its honest original passes. Host
evidence only: the forms are lab guest captures and source derived fixtures, not a guest of the
next profile."""
import dataclasses
import json
import unittest

import labtest  # noqa: F401  (path setup)
import global_sessions
import lab_actions
import lab_broker
import lab_driver
import lab_readers
from scripts.proof import systemui_observer as observer
from scripts.proof import systemui_sessions as readback
from scripts.proof.tests import test_systemui_observer as captured

COMPONENT = 'com.android.systemui'
# One D3 guest's bracket reads, all captured in one boot and one framework instance.
BRACKET = {observer.BOOT_ID: captured.reply('boot-id-3e3ad786'),
           observer.FRAMEWORK_PID: captured.reply('framework-pid-937'),
           'cat /proc/937/stat': captured.reply('framework-stat-937')}


def shell(listing, dump, **changes):
    """A fake shell of the bracket reads and one listing and dump, each by its fixture name or a
    reply; a list answers each call with its next item."""
    replies = dict(BRACKET, **{observer.LISTING: captured.reply(listing) if isinstance(listing, str) else listing,
                               observer.INSTALLS: captured.reply(dump) if isinstance(dump, str) else dump})
    replies.update(changes)
    return captured.Shell(replies)


def recorded(run):
    """A run function that keeps every capture as a group records it."""
    captures = []

    def call(command):
        reply = run(command)
        captures.append((command,) + tuple(reply))
        return reply
    return call, captures


def rows(reading):
    return [(r['section'], r['id'], r['package'], r['staged'], r['failed'], r['cause']) for r in reading['sessions']]


def listed(identity, package, ready=False, failed=False, error=''):
    """One staged listing row in the pinned shell's form."""
    return ('sessionId = %d; appPackageName = %s; isStaged = true; isReady = %s; isApplied = false; '
            'isFailed = %s; errorMsg = %s;' % (identity, package, str(ready).lower(), str(failed).lower(), error))


def listing(*rows):
    """A whole staged listing of (row, child) pairs through the writer's model, a child indented
    below its multiple package parent, as the shell prints it."""
    writer = readback.IndentingWriter()
    for row, child in rows:
        writer.indent = '  ' if child else ''
        writer.println(row)
    return 1, writer.text(), ''


# The captured signer failure's row, and the foreign family of installs-foreign-records: its
# parent of no known package and two children of other packages.
SIGNER = listed(2014338406, COMPONENT, failed=True, error=readback.staged_listing(
    *captured.reply('listing-failed-signer')[:2], False).sessions[0].error)
FAMILY = ((listed(1700000001, 'null'), False), (listed(1700000002, 'com.example.one'), True),
          (listed(1700000003, 'com.example.two'), True))


class GlobalInventoryTests(unittest.TestCase):
    def test_captured_listings_and_dumps_give_a_whole_inventory_of_every_session(self):
        cases = {
            ('listing-pair-nonstaged', 'installs-historical-refused'):
                [('HISTORICAL', 1082186470, COMPONENT, False, True, 'PERSISTENT')],
            ('listing-failed-signer', 'installs-finalized-failed'):
                [('FINALIZED', 2014338406, COMPONENT, True, True, 'SIGNATURE')],
            ('listing-failed-verity', 'installs-finalized-two'):
                [('FINALIZED', 1978352588, COMPONENT, True, True, 'FS_VERITY'),
                 ('FINALIZED', 2014338406, COMPONENT, True, True, 'SIGNATURE')],
            ('listing-pair-mismatched', 'installs-finalized-historical'):
                [('FINALIZED', 181393819, COMPONENT, True, True, 'SIGNATURE'),
                 ('FINALIZED', 1590532299, COMPONENT, True, True, 'FS_VERITY'),
                 ('HISTORICAL', 636061908, COMPONENT, True, False, None)],
        }
        for (listing, dump), expected in cases.items():
            with self.subTest(dump):
                fake = shell(listing, dump)
                reading = global_sessions.read(fake)
                self.assertEqual(lab_actions.check_global(reading), None)
                self.assertEqual((reading['whole'], rows(reading)), (True, expected))
                # The reads are the observer's own, all in its allowlist, in their bracket's order.
                self.assertEqual(fake.commands, [observer.BOOT_ID, observer.FRAMEWORK_PID, 'cat /proc/937/stat',
                                                 observer.LISTING, observer.INSTALLS, observer.FRAMEWORK_PID,
                                                 'cat /proc/937/stat', observer.BOOT_ID])
                self.assertTrue(all(observer.allowed(c) and global_sessions.allowed(c) for c in fake.commands))
        # Every field of one exact record, as the dump printed it.
        [row] = global_sessions.read(shell('listing-pair-nonstaged', 'installs-historical-refused'))['sessions']
        self.assertEqual(row, {'section': 'HISTORICAL', 'id': 1082186470, 'package': COMPONENT, 'referrer': None,
                               'staged': False, 'multi_package': False, 'parent': -1, 'children': [], 'sealed': True,
                               'committed': True, 'ready': False, 'applied': False, 'failed': True,
                               'destroyed': True, 'created': 1790064919539, 'installer': 2000, 'cause': 'PERSISTENT'})
        # A ready session in the active section with a ticket's referrer, as a source derived form.
        listing = (1, captured.listing_text([captured.READY_ROW]), '')
        reading = global_sessions.read(shell(listing, 'installs-active-referrer'))
        live = lab_actions.live_rows(reading)
        self.assertEqual([(r['id'], r['ready'], r['committed'], r['referrer']) for r in live],
                         [(1378782103, True, True, 'andrix-ticket:' + captured.NONCE)])
        self.assertIn('committed, ready', lab_actions.confirmation_safety(reading, COMPONENT))

    def test_records_of_other_packages_are_listed_with_every_unknown_field(self):
        reading = global_sessions.read(shell('listing-failed-signer', 'installs-foreign-records'))
        self.assertEqual(lab_actions.check_global(reading), None)
        foreign = [r for r in reading['sessions'] if r['package'] != COMPONENT]
        self.assertEqual([(r['section'], r['id'], r['package']) for r in foreign],
                         [('ACTIVE', 1700000000, 'com.example.other'), ('ACTIVE', 1700000001, None),
                          ('ACTIVE', 1700000002, 'com.example.one'), ('ACTIVE', 1700000003, 'com.example.two'),
                          ('HISTORICAL', 1700000011, None), ('HISTORICAL', 1700000012, 'com.example.one')])
        unknown = ('referrer', 'staged', 'multi_package', 'parent', 'children', 'sealed', 'committed', 'ready',
                   'applied', 'failed', 'destroyed', 'created', 'installer', 'cause')
        self.assertTrue(all(r[k] is None for r in foreign for k in unknown))
        # An unknown never counts as safe: no reboot beside them, and Final cannot tell their owner
        # where no package is known, while a terminal foreign record blocks nothing.
        self.assertIn('unknown', lab_actions.confirmation_safety(reading, COMPONENT))
        owned, uncertain, others = lab_driver.final_join(reading, COMPONENT, {'nonces': [], 'sessions': [],
                                                                               'controls': []})
        self.assertEqual((owned, uncertain), ([], [1700000001]))
        self.assertEqual([r['id'] for r in others], [1700000000, 1700000002, 1700000003])
        self.assertTrue(all(lab_driver.session_classification(r) == 'UNKNOWN' for r in others))

    def test_a_read_that_disagrees_or_crosses_a_restart_gives_no_reading(self):
        later = (0, captured.reply('framework-stat-937')[1].replace(' 10829 ', ' 10830 '), '')
        # The captured failed session listed as not failed, rendered through the writer's model.
        unfailed = (1, captured.listing_text(['sessionId = 2014338406; appPackageName = com.android.systemui; '
                                              'isStaged = true; isReady = false; isApplied = false; isFailed = false; '
                                              'errorMsg = ;']), '')
        cases = {
            'a listed session missing from the dump': (shell('listing-ready', 'installs-active-ready'),
                                                        lab_readers.Unclassified, 'not in the dump'),
            'a dumped staged session not listed': (shell('listing-empty', 'installs-active-ready'),
                                                   lab_readers.Unclassified, 'not listed'),
            'an end the listing and the dump disagree on': (shell(unfailed, 'installs-finalized-failed'),
                                                             lab_readers.Unclassified, 'disagree'),
            'a boot change during the read': (shell('listing-failed-signer', 'installs-finalized-failed', **{
                observer.BOOT_ID: [captured.reply('boot-id-3e3ad786'), captured.reply('boot-id')]}),
                lab_readers.Unclassified, 'restarted'),
            'a framework restart during the read': (shell('listing-failed-signer', 'installs-finalized-failed', **{
                'cat /proc/937/stat': [captured.reply('framework-stat-937'), later]}), lab_readers.Unclassified,
                'restarted'),
            'a dump cut short': (shell('listing-failed-signer',
                                       (0, captured.reply('installs-finalized-failed')[1][:900], '')),
                                 lab_readers.Unclassified, 'sections missing'),
            'a listing on standard error': (shell((1, '', 'Error: something\n'), 'installs-finalized-failed'),
                                            lab_readers.Unclassified, 'standard error'),
            'no framework': (shell('listing-empty', 'installs-historical-refused', **{
                observer.FRAMEWORK_PID: (1, '', '')}), lab_readers.Unavailable, 'no framework'),
        }
        for name, (fake, error, reason) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(error, reason):
                global_sessions.read(fake)

        def lost(command):
            raise lab_readers.Unavailable('capture 9 did not complete: eof-before-exit')
        with self.assertRaisesRegex(lab_readers.Unavailable, 'did not complete'):
            global_sessions.read(lost)

    def test_a_package_the_listing_and_the_dump_contradict_gives_no_reading(self):
        # The two contradictions, each beside its honest twin: the listing's package for
        # an exactly parsed record, and for a record the dump left as another package's. The
        # listing prints SessionInfo's package, which falls back to the parameters' the dump
        # prints, so a package the dump knows is the listed one; one only the listing knows stays
        # unknown in the inventory.
        ready = captured.READY_ROW
        other = listed(1700000000, COMPONENT, ready=True)
        honest = {
            'the ready session as both print it': (listing((ready, False)), 'installs-active-referrer',
                                                   1378782103, COMPONENT),
            'a package only the listing knows': (listing((listed(1378782199, COMPONENT), False)),
                                                 'installs-unknown-package', 1378782199, None),
            'the other package listed for its record': (
                listing((other.replace(COMPONENT, 'com.example.other'), False), (SIGNER, False)),
                'installs-foreign-records', 1700000000, 'com.example.other'),
            'the foreign family as the dump has it': (listing(*FAMILY, (SIGNER, False)), 'installs-foreign-records',
                                                      1700000003, 'com.example.two'),
        }
        for name, (parts, dump, identity, package) in honest.items():
            with self.subTest(name):
                reading = global_sessions.read(shell(parts, dump))
                self.assertEqual(lab_actions.check_global(reading), None)
                self.assertEqual([r['package'] for r in reading['sessions'] if r['id'] == identity], [package])
                # No row is dropped: every record the dump holds, historical ones too, is listed.
                dumped = readback.installs_dump(*captured.reply(dump)[:2])
                self.assertEqual(len(reading['sessions']), len(dumped.sessions) + len(dumped.skipped))
        contrary = {
            'another package listed for an exact record': (listing((ready.replace(
                'appPackageName = com.android.systemui', 'appPackageName = com.example.other'), False)),
                'installs-active-referrer', 1378782103),
            'no package listed for an exact record': (listing((ready.replace(
                'appPackageName = com.android.systemui', 'appPackageName = null'), False)),
                'installs-active-referrer', 1378782103),
            "SystemUI listed for another package's record": (listing((other, False), (SIGNER, False)),
                                                             'installs-foreign-records', 1700000000),
            "a child listed as its sibling's package": (listing(FAMILY[0], FAMILY[1], (FAMILY[1][0].replace(
                '1700000002', '1700000003'), True), (SIGNER, False)), 'installs-foreign-records', 1700000003),
        }
        for name, (parts, dump, identity) in contrary.items():
            with self.subTest(name), self.assertRaisesRegex(
                    lab_readers.Unclassified, 'name other packages for session %d$' % identity):
                global_sessions.read(shell(parts, dump))

    def test_the_families_flags_and_errors_both_parts_print_agree_or_give_no_reading(self):
        # The dump keeps the parameters' staged flag, the family and the error message too. A
        # record the dump left as certainly another package's is never listed as SystemUI's, and
        # an exactly parsed record is a single session, listed at the top level with no row below.
        signer_dump = captured.reply('installs-finalized-failed')
        nonstaged = captured.reply('installs-active-referrer')[1].replace('isStaged=true', 'isStaged=false', 1)
        nonstaged = (0, nonstaged.replace('params.isStaged=true', 'params.isStaged=false', 1), '')
        honest = {
            'the family parent listed as another package': (
                listing((listed(1700000001, 'com.example.three'), False), *FAMILY[1:], (SIGNER, False)),
                'installs-foreign-records', 1700000001, None),
            'the signer row at the top level after the family': (listing(*FAMILY, (SIGNER, False)),
                                                                  'installs-foreign-records', 2014338406, True),
            'a nonstaged live session, unlisted': ((1, '', ''), nonstaged, 1378782103, False),
            'the error message as both print it': ('listing-failed-signer', signer_dump, 2014338406, True),
        }
        for name, (parts, dump, identity, value) in honest.items():
            with self.subTest(name):
                reading = global_sessions.read(shell(parts, dump))
                self.assertEqual(lab_actions.check_global(reading), None)
                [found] = [r for r in reading['sessions'] if r['id'] == identity]
                self.assertEqual(found['package'] if identity == 1700000001 else found['staged'], value)
        error = SIGNER.replace('ignoring!', 'ignored!')
        contrary = {
            'the family parent listed as SystemUI': (
                listing((listed(1700000001, COMPONENT), False), *FAMILY[1:], (SIGNER, False)),
                'installs-foreign-records', 'session 1700000001 of com.android.systemui is a record of another'),
            'an exact record listed as a child': (listing(*FAMILY[:2], (SIGNER, True)), 'installs-foreign-records',
                                                  'family of session 2014338406$'),
            'an exact record with a row below it': (listing((captured.READY_ROW, False),
                                                            ('sessionId = 1700000009; not found', True)),
                                                    'installs-active-referrer', 'family of session 1378782103$'),
            'an exact record the dump holds as not staged': (listing((captured.READY_ROW, False)), nonstaged,
                                                             'disagree on session 1378782103$'),
            'another error message': (listing((error, False)), signer_dump, 'disagree on session 2014338406$'),
        }
        for name, (parts, dump, reason) in contrary.items():
            with self.subTest(name), self.assertRaisesRegex(lab_readers.Unclassified, reason):
                global_sessions.read(shell(parts, dump))

    def test_a_cause_is_classified_only_by_its_exact_source_form_joined_to_its_session(self):
        def parsed(dump):
            return {s.identity: s for s in readback.installs_dump(*captured.reply(dump)[:2]).sessions}
        signer = parsed('installs-finalized-failed')[2014338406]
        verity = parsed('installs-finalized-two')[1978352588]
        nonstaged = parsed('installs-historical-refused')[1082186470]
        self.assertEqual([global_sessions.cause(s) for s in (signer, verity, nonstaged)],
                         ['SIGNATURE', 'FS_VERITY', 'PERSISTENT'])
        changes = {
            'a revert of another session': (signer, {'error_message': signer.error_message.replace(
                'Marking 2014338406', 'Marking 2014338407')}),
            'a revert without its reason': (signer, {'error_message': signer.error_message.split(' Reason for')[0]}),
            'another error code': (signer, {'error_code': -7}),
            'the signature of another package': (signer, {'package': 'com.example.other'}),
            'an upgrade key branch': (signer, {'error_message': signer.error_message.replace(
                'Existing package com.android.systemui signatures do not match newer version; ignoring!',
                'New package has a different signature: com.android.systemui')}),
            'the missing verity of another stage': (verity, {'stage_dir': '/data/app-staging/session_1'}),
            'a nonstaged refusal of another status': (nonstaged, {'final_status': -7}),
            'a nonstaged refusal of another sentence': (nonstaged, {'final_message': 'Package is not updateable.'}),
            'a staged session with the persistent sentence': (nonstaged, {'staged': True}),
            'a failure of no known package': (signer, {'package': None}),
        }
        for name, (session, change) in changes.items():
            with self.subTest(name):
                self.assertEqual(global_sessions.cause(dataclasses.replace(session, **change)), 'OTHER')
        self.assertIsNone(global_sessions.cause(dataclasses.replace(signer, failed=False)))

    def test_the_adapter_admits_the_reader_and_reads_its_recorded_captures_again(self):
        adapter = lab_readers.ObserverAdapter(observer, captured.INSTALLATION, COMPONENT, global_sessions=True)
        self.assertTrue(adapter.global_admitted)
        run, captures = recorded(shell('listing-failed-verity', 'installs-finalized-two'))
        adapter.bind(run)
        reading = adapter.global_sessions()
        self.assertEqual(rows(reading), [('FINALIZED', 1978352588, COMPONENT, True, True, 'FS_VERITY'),
                                         ('FINALIZED', 2014338406, COMPONENT, True, True, 'SIGNATURE')])
        self.assertTrue(all(adapter.allowed(c[0]) for c in captures))
        self.assertEqual(adapter.rederive('global-sessions', captures), reading)
        # A reading its captures do not give, captures of other reads, or one that did not
        # complete, are refused.
        changed = captures[:-1] + [captures[-1][:2] + captured.reply('boot-id')[1:]]
        for name, value, error in (('a changed reply', changed, lab_readers.Unclassified),
                                   ('one capture more', captures + [captures[-1]], lab_readers.Unclassified),
                                   ('reads out of order', [captures[1], captures[0]] + captures[2:],
                                    lab_readers.Unclassified),
                                   ('a capture that did not complete', [(captures[0][0], None) + captures[0][2:]]
                                    + captures[1:], lab_readers.Unavailable)):
            with self.subTest(name), self.assertRaises(error):
                adapter.rederive('global-sessions', value)
        # Without the flag the adapter admits no global inventory, as before.
        plain = lab_readers.ObserverAdapter(observer, captured.INSTALLATION, COMPONENT)
        self.assertFalse(plain.global_admitted)
        self.assertIs(plain.rederive('global-sessions', captures), NotImplemented)
        plain.bind(run)
        with self.assertRaises(lab_readers.Unavailable):
            plain.global_sessions()
        # Its reads are the observer's own, which any adapter's allowlist holds: only the reading
        # is admitted by the flag.
        self.assertTrue(all(plain.allowed(c[0]) for c in captures))

    def test_the_broker_records_the_inventory_and_refuses_a_changed_copy_on_reopening(self):
        h = labtest.Harness(next_profile=True)
        self.addCleanup(h.close)
        h.sim.foreign_sessions.append(global_sessions.unknown('Active', 1700000000, 'com.example.other'))
        groups = h.broker.controller_read(['clock', 'global-sessions'], 'the whole global inventory')
        group = h.broker.ledger.entries[groups[1].number - 1]
        self.assertEqual((group.content['status'], group.content['reading']), ('facts', h.sim.global_sessions()))
        # The honest record reopens; one whose reading hides the live foreign session is refused.
        h.reopen()
        h.broker.close()
        record = group.path / 'record.json'
        content = json.loads(record.read_text())
        content['reading'] = {'whole': True, 'sessions': []}
        record.write_bytes(lab_broker.ledgers.encode_json(content))
        with self.assertRaisesRegex(lab_broker.BrokerError, 'typed reading of group %d is not what its captures give'
                                    % group.number):
            h.open()


class ReceiptRecipientTests(unittest.TestCase):
    QUERY = 'content query --uri content://dev.andrix.lab.notice.receipts/rows --user %d'

    class Stores:
        """A receipt reader factory of the notice fixture's form: made with its recipients
        function, it reads each recipient's store through the bound run function."""

        made = []

        def __init__(self, recipients):
            self.recipients, self.run = recipients, None
            ReceiptRecipientTests.Stores.made.append(self)

        def allowed(self, command):
            return any(command == ReceiptRecipientTests.QUERY % user for user in range(0, 100))

        def bind(self, run):
            self.run = run

        def receipt_rows(self, ticket):
            out = []
            for user, serial in self.recipients(ticket):
                code, stdout, _ = self.run(ReceiptRecipientTests.QUERY % user)
                out.append({'user': user, 'serial': serial, 'reply': stdout})
            return out

    def test_the_adapter_reads_exactly_the_recipients_the_broker_passes(self):
        self.Stores.made = []
        adapter = lab_readers.ObserverAdapter(observer, captured.INSTALLATION, COMPONENT, receipts=self.Stores)
        self.assertTrue(adapter.receipts_admitted)
        self.assertTrue(adapter.allowed(self.QUERY % 10))
        ran = []
        adapter.bind(lambda command: (ran.append(command), (0, 'rows of %s\n' % command[-2:], ''))[1])
        found = adapter.receipt_rows(labtest.TICKET, [(10, 5), (11, 6)])
        self.assertEqual(ran, [self.QUERY % 10, self.QUERY % 11])
        self.assertEqual([(r['user'], r['serial']) for r in found], [(10, 5), (11, 6)])
        # The reader made for a read gives no recipients for another ticket, and none at all once
        # its read has ended: it holds nothing between reads.
        reader = self.Stores.made[-1]
        self.assertEqual((reader.recipients('05' * 16), reader.run), ([], None))
        ran.clear()
        self.assertEqual(adapter.receipt_rows(labtest.TICKET, []), [])
        self.assertEqual(ran, [])
        # Without a receipt reader nothing is admitted or read.
        plain = lab_readers.ObserverAdapter(observer, captured.INSTALLATION, COMPONENT)
        self.assertFalse(plain.receipts_admitted)
        self.assertFalse(plain.allowed(self.QUERY % 10))
        with self.assertRaises(lab_readers.Unavailable):
            plain.receipt_rows(labtest.TICKET, [(10, 5)])


if __name__ == '__main__':
    unittest.main()
