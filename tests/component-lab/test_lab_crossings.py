# SPDX-License-Identifier: Apache-2.0
"""The typed crossing commands, their reply forms, and the reader adapter's contract. Host
evidence only; the forms come from the D3 guest captures and the session parsers."""
import types
import unittest

import labtest  # noqa: F401  (path setup)
import lab_crossings as lc
import lab_readers
import sim_android
from scripts.proof import systemui_observer
from scripts.proof import systemui_sessions

NONCE = '5e1f0c9a7d3b4e2f8a6c1d0b9e7f3a25'
PATH = '/data/local/tmp/andrix-d5/0101/base.apk'


def done(stdout, code=0, stderr=b''):
    return sim_android.result('x', code, stdout, stderr)


class CommandTests(unittest.TestCase):
    def test_commands_are_built_from_typed_fields_only(self):
        self.assertEqual(lc.create_command('com.android.systemui', NONCE),
                         'pm install-create --user 0 -r --pkg com.android.systemui --staged --referrer '
                         'andrix-ticket:' + NONCE)
        self.assertEqual(lc.write_command(7, 'base.apk.idsig', PATH + '.idsig'),
                         'pm install-write 7 base.apk.idsig ' + PATH + '.idsig')
        self.assertEqual(lc.commit_command(7), 'pm install-commit --staged-ready-timeout 60000 7')
        self.assertEqual(lc.abandon_command(2147483647), 'pm install-abandon 2147483647')
        self.assertEqual(lc.digest_command(PATH), 'sha256sum ' + PATH)
        refused = (lambda: lc.create_command('com.android.systemui; id', NONCE),
                   lambda: lc.create_command('com.android.systemui', '0' * 32),
                   lambda: lc.create_command('com.android.systemui', NONCE.upper()),
                   lambda: lc.write_command(7, 'other.apk', PATH),
                   lambda: lc.write_command(0, 'base.apk', PATH),
                   lambda: lc.write_command(True, 'base.apk', PATH),
                   lambda: lc.commit_command(2147483648),
                   lambda: lc.abandon_command(-1),
                   lambda: lc.digest_command('/data/local/tmp/x;reboot'),
                   lambda: lc.digest_command('/data/local/tmp/andrix-d5/../../system/x'),
                   lambda: lc.digest_command('/sdcard/base.apk'),
                   lambda: lc.digest_command("/data/local/tmp/a/'b'"))
        for call in refused:
            with self.assertRaises(ValueError):
                call()

    def test_the_referrer_is_the_session_parsers_scheme(self):
        self.assertEqual(lc.NONCE_SCHEME, systemui_sessions.NONCE_SCHEME)
        referrer = lc.create_command('com.android.systemui', NONCE).rsplit(' ', 1)[1]
        self.assertEqual(systemui_sessions.referrer_nonce(referrer), NONCE)


class FormTests(unittest.TestCase):
    def test_create(self):
        self.assertEqual(lc.classify_create(done(b'Success: created install session [1189842383]\n')),
                         ('SUCCESS', 1189842383))
        for result in (done(b'Success: created install session [1189842383]\n', 0, b'warning\n'),
                       done(b'Success: created install session [0]\n'),
                       done(b'Success: created install session [2147483648]\n'),
                       done(b'Success: created install session [12]'), done(b'', 1),
                       done(b'Success: created install session [12]\n', 1)):
            self.assertEqual(lc.classify_create(result), ('UNRECOGNIZED', None))
        for completion in ('eof-before-exit', 'timeout', 'malformed', 'overflow', 'not-started'):
            result = sim_android.result('x', 0, b'Success: created install session [5]\n', completion=completion)
            self.assertEqual(lc.classify_create(result), (None, None), completion)

    def test_write_needs_the_members_size(self):
        self.assertEqual(lc.classify_write(done(b'Success: streamed 4103 bytes\n'), 4103), 'SUCCESS')
        self.assertEqual(lc.classify_write(done(b'Success: streamed 4102 bytes\n'), 4103), 'UNRECOGNIZED')
        self.assertEqual(lc.classify_write(done(b'Error: something\n', 1), 4103), 'UNRECOGNIZED')
        self.assertIsNone(lc.classify_write(sim_android.result('x', completion='timeout'), 4103))

    def test_commit_and_abandon(self):
        self.assertEqual(lc.classify_commit(done(lc.READY)), 'READY')
        self.assertEqual(lc.classify_commit(done(b'Success\n')), 'ACCEPTED')
        self.assertEqual(lc.classify_commit(done(b'Failure [INSTALL_FAILED_VERIFICATION_FAILURE]\n', 1)),
                         'UNRECOGNIZED')
        self.assertIsNone(lc.classify_commit(sim_android.result('x', completion='eof-before-exit')))
        self.assertEqual(lc.classify_abandon(done(b'Success\n')), 'SUCCESS')
        self.assertEqual(lc.classify_abandon(done(b'Success\n', 1)), 'UNRECOGNIZED')
        self.assertIsNone(lc.classify_abandon(sim_android.result('x', completion='timeout')))

    def test_a_digest_read_names_its_path(self):
        good = ('ab' * 32 + '  ' + PATH + '\n').encode()
        self.assertEqual(lc.classify_digest(done(good), PATH), 'ab' * 32)
        self.assertIsNone(lc.classify_digest(done(good), PATH + '.idsig'))
        self.assertIsNone(lc.classify_digest(done(good, 0, b'x'), PATH))
        self.assertIsNone(lc.classify_digest(sim_android.result('x', 0, good, completion='timeout'), PATH))


class StubObserver:
    """A stand in for the observer module, exercising only the adapter's contract."""

    class Unclassified(Exception):
        pass

    readings = {}

    @staticmethod
    def allowed(command):
        return command in ('pidof system_server', 'cat /proc/sys/kernel/random/boot_id')

    class ShellObserver:
        def __init__(self, run, installation, component, new_id=None, wall=None):
            self.run = run

        def clock(self):
            self.run('cat /proc/sys/kernel/random/boot_id')
            first = self.run('pidof system_server')
            second = self.run('pidof system_server')
            if first[0] == 0:
                return 'aa' * 16, 4021, 5, 6
            if StubObserver.readings.get('raise'):
                raise StubObserver.Unclassified('no form')
            return 'aa' * 16, -1, 5, 6

        def boot(self):
            raise StubObserver.Unclassified('Boot ID of no known form')


class AdapterTests(unittest.TestCase):
    def adapter(self, replies, checkpoint=None):
        adapter = lab_readers.ObserverAdapter(StubObserver, '00' * 15 + '01', 'com.android.systemui',
                                              checkpoint=checkpoint)
        adapter.bind(lambda command: replies[command])
        return adapter

    def test_no_framework_only_from_a_confirmed_quiet_failure(self):
        boot = (0, '1f0d016e-8090-4303-a3ff-9eb193eb403d\n', '')
        adapter = self.adapter({'cat /proc/sys/kernel/random/boot_id': boot, 'pidof system_server': (1, '', '')})
        self.assertEqual(adapter.clock()[1], -1)
        adapter = self.adapter({'cat /proc/sys/kernel/random/boot_id': boot,
                                'pidof system_server': (1, '', 'pidof: permission denied\n')})
        with self.assertRaises(lab_readers.Unclassified):
            adapter.clock()
        adapter = self.adapter({'cat /proc/sys/kernel/random/boot_id': boot, 'pidof system_server': (0, '937\n', '')})
        self.assertEqual(adapter.clock()[1], 4021)

    def test_unknown_forms_and_unavailable_reads_give_no_fact(self):
        adapter = self.adapter({})
        with self.assertRaises(lab_readers.Unclassified):
            adapter.boot()
        with self.assertRaises(lab_readers.Unavailable):
            adapter.checkpoint()
        adapter.bind(None)
        with self.assertRaises(lab_readers.Unavailable):
            adapter.clock()
        self.assertTrue(adapter.allowed('pidof system_server'))
        self.assertFalse(adapter.allowed('reboot'))
        self.assertFalse(adapter.receipts_admitted)

    def test_an_injected_checkpoint_reader_and_its_allowlist(self):
        fact = {'kind': 'CHECKPOINT'}
        adapter = lab_readers.ObserverAdapter(StubObserver, '00' * 15 + '01', 'com.android.systemui',
                                              checkpoint=lambda observer: fact,
                                              checkpoint_allowed=lambda c: c == 'sm supports-checkpoint')
        self.assertEqual(adapter.checkpoint(), [fact])
        self.assertTrue(adapter.allowed('sm supports-checkpoint'))

    def test_the_public_checkpoint_reader_is_injected_through_its_documented_api(self):
        # The base's public observer reads the checkpoint through the fixed StorageManager helper.
        # Its own captured guest replies drive it here, through the adapter, unchanged.
        from scripts.proof.tests import test_systemui_observer as captured
        shell = captured.Shell(captured.guest())
        adapter = lab_readers.ObserverAdapter(systemui_observer, captured.INSTALLATION, 'com.android.systemui',
                                              checkpoint=systemui_observer.ShellObserver.checkpoint)
        adapter.bind(shell)
        facts = adapter.checkpoint()
        self.assertEqual([(f['kind'], f['classification'], f['component'], f['instance']) for f in facts],
                         [('CHECKPOINT', 'COMMITTED', '', 10829)])
        self.assertIn(systemui_observer.CHECKPOINT_READ, shell.commands)
        self.assertTrue(all(adapter.allowed(command) for command in shell.commands))
        # A helper of other bytes gives no fact.
        other = captured.guest(**{systemui_observer.HELPER_DIGEST: (0, '00' * 32 + '  '
                                                                    + systemui_observer.CHECKPOINT_HELPER + '\n', '')})
        adapter.bind(captured.Shell(other))
        with self.assertRaises(lab_readers.Unclassified):
            adapter.checkpoint()

    def test_the_factory_and_active_facts_are_read_again_from_their_captures(self):
        # A reopening's check of an identity baseline: the public observer reads a group's recorded
        # replies again, in order, to the same facts but for their observation IDs and wall times.
        # A reply of another form gives another fact; captures of other reads, one that did not
        # complete or one left over refuse. Driven by the base's own captured guest replies.
        from scripts.proof.tests import test_systemui_observer as captured
        shell = captured.Shell(captured.device())
        adapter = lab_readers.ObserverAdapter(systemui_observer, captured.INSTALLATION, 'com.android.systemui')
        recorded = []

        def run(command):
            reply = shell(command)
            recorded.append((command,) + tuple(reply))
            return reply

        def same(fact):
            return {k: v for k, v in fact.items() if k not in ('observation', 'wall')}
        for name in ('factory', 'active'):
            recorded.clear()
            adapter.bind(run)
            fact = getattr(adapter, name)()[0]
            captures = list(recorded)
            self.assertEqual([same(f) for f in adapter.rederive(name, captures)], [same(fact)])
            with self.assertRaises(lab_readers.Unclassified):
                adapter.rederive(name, captures + [captures[-1]])
            with self.assertRaises(lab_readers.Unclassified):
                adapter.rederive(name, [captures[1], captures[0]] + captures[2:])
            with self.assertRaises(lab_readers.Unavailable):
                adapter.rederive(name, [(captures[0][0], None) + captures[0][2:]] + captures[1:])
        context = [c for c in captures if c[0] == 'cat /proc/1839/attr/current']
        self.assertEqual(len(context), 1)
        other = [(c, code, out.replace('c512,', 'c600,') if c == context[0][0] else out, err)
                 for c, code, out, err in captures]
        self.assertEqual(adapter.rederive('active', other)[0]['facts']['context'],
                         fact['facts']['context'].replace('c512,', 'c600,'))
        self.assertIs(adapter.rederive('clock', captures), NotImplemented)

    def test_the_raw_digest_is_the_observers(self):
        captures = [('cat /proc/uptime', 0, b'812.34 1610.22\n', b''),
                    ('pidof com.android.systemui', 1, b'', b''),
                    ('dumpsys user', 0, b'\xff\xfe raw bytes\n', b'warning \x80\n')]
        theirs = systemui_observer.raw_digest([systemui_observer.Capture(c, code, out.decode('utf-8', 'surrogateescape'),
                                                                         err.decode('utf-8', 'surrogateescape'))
                                               for c, code, out, err in captures])
        self.assertEqual(lab_readers.raw_digest(captures), theirs)


if __name__ == '__main__':
    unittest.main()
