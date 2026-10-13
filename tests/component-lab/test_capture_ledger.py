# SPDX-License-Identifier: Apache-2.0
"""The broker's numbered ledger: exclusive creation, the sync order of a capture, verified
reopening, incomplete entries and quarantine. Host filesystem evidence, not power loss."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import labtest  # noqa: F401  (path setup)
import capture_ledger as cl


class Spy:
    """Records the path of every synced descriptor, in order, then syncs it for real."""

    def __init__(self):
        self.events = []

    def __call__(self, fd):
        self.events.append(os.readlink('/proc/self/fd/%d' % fd))
        os.fsync(fd)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'ledger'

    def ledger(self, sync=False, fsync=os.fsync):
        return cl.Ledger.create(self.root, sync=sync, fsync=fsync)

    def test_a_new_ledger_needs_an_empty_directory(self):
        self.ledger()
        self.assertEqual((self.root / 'LEDGER').read_bytes(), cl.MARKER)
        with self.assertRaises(cl.LedgerDamaged):
            cl.Ledger.create(self.root)

    def test_entries_are_numbered_and_repeat_their_name(self):
        ledger = self.ledger()
        self.assertEqual([ledger.record('open', {'x': 1}), ledger.record('stop', {'reason': 'r'})], [1, 2])
        content = json.loads((self.root / '000002-stop' / 'record.json').read_text())
        self.assertEqual((content['number'], content['kind'], content['reason']), (2, 'stop', 'r'))
        os.mkdir(self.root / '000003-fault')
        with self.assertRaises(cl.LedgerDamaged):
            ledger.record('fault', {})

    def test_the_intent_is_synced_before_the_command_and_the_result_last(self):
        spy = Spy()
        ledger = self.ledger(sync=True, fsync=spy)
        spy.events.clear()
        entry = ledger.begin_capture({'operation': 'mutation', 'command': 'pm install-abandon 7'})
        launched_after = list(spy.events)
        ledger.finish_capture(entry, b'Success\n', b'', {'exit': 0})
        folder = str(entry.path)
        self.assertEqual(launched_after, [str(self.root), folder + '/intent.json', folder])
        self.assertEqual(spy.events[len(launched_after):], [folder + '/stdout', folder + '/stderr',
                                                            folder + '/result.json', folder])
        result = json.loads((entry.path / 'result.json').read_text())
        self.assertEqual((result['stdout_bytes'], result['stderr_bytes'], result['exit']), (8, 0, 0))
        with self.assertRaises(ValueError):
            ledger.finish_capture(entry, b'again', b'', {'exit': 0})
        with self.assertRaises(FileExistsError):
            ledger._write_new(entry.path / 'stdout', b'other')
        self.assertEqual((entry.path / 'stdout').read_bytes(), b'Success\n')

    def test_reopening_reads_back_every_entry(self):
        ledger = self.ledger()
        ledger.record('open', {})
        entry = ledger.begin_capture({'command': 'id'})
        ledger.finish_capture(entry, b'uid=2000(shell)\n', b'', {'exit': 0})
        reopened = cl.Ledger.open(self.root)
        self.assertEqual([(e.number, e.kind, e.state) for e in reopened.entries],
                         [(1, 'open', 'complete'), (2, 'capture', 'complete')])
        self.assertEqual(reopened.entries[1].content['stdout'], b'uid=2000(shell)\n')

    def test_reopening_syncs_every_file_and_directory_again(self):
        ledger = self.ledger(sync=True)
        ledger.record('open', {'pid': 1})
        capture = ledger.begin_capture({'command': 'id'})
        ledger.finish_capture(capture, b'out', b'', {'exit': 0})
        spy = Spy()
        reopened = cl.Ledger.open(self.root, sync=True, fsync=spy)
        want = [str(self.root / 'LEDGER')]
        for entry in reopened.entries:
            want += [str(entry.path / name) for name in sorted(os.listdir(entry.path))] + [str(entry.path)]
        self.assertEqual(spy.events, want + [str(self.root)])

    def test_a_failed_file_sync_refuses_reopening_until_it_completes(self):
        ledger = self.ledger(sync=True)
        record = self.root / '000001-open' / 'record.json'

        def failing(fd):
            if os.readlink('/proc/self/fd/%d' % fd) == str(record):
                raise OSError(5, 'injected')
            os.fsync(fd)
        ledger._fsync = failing
        with self.assertRaises(OSError):
            ledger.record('open', {'pid': 1})
        # The record reads whole, but its own barrier never completed: every opening refuses until it does.
        self.assertEqual(cl.scan(self.root)[-1].state, 'complete')
        for _ in range(2):
            with self.assertRaises(OSError):
                cl.Ledger.open(self.root, sync=True, fsync=failing)
        spy = Spy()
        self.assertEqual(cl.Ledger.open(self.root, sync=True, fsync=spy).last.state, 'complete')
        self.assertIn(str(record), spy.events)

    def test_a_failed_write_latches_the_ledger_in_its_process(self):
        ledger = self.ledger(sync=True)

        def failing(fd):
            raise OSError(5, 'injected')
        ledger._fsync = failing
        with self.assertRaises(OSError):
            ledger.record('open', {'pid': 1})
        ledger._fsync = os.fsync
        # Nothing more is written in this process, whatever the storage does next.
        for write in (lambda: ledger.record('open', {'pid': 2}), lambda: ledger.begin_capture({'command': 'id'})):
            with self.assertRaisesRegex(cl.LedgerDamaged, 'an earlier write or sync failed'):
                write()
        self.assertEqual(len(cl.scan(self.root)), 1)

    def test_a_failed_final_directory_sync_refuses_reopening_until_it_completes(self):
        ledger = self.ledger(sync=True)
        ledger.record('open', {'pid': 1})
        entry = self.root / '000002-capture'

        def failing(fd):
            if os.readlink('/proc/self/fd/%d' % fd) == str(entry):
                raise OSError(5, 'injected')
            os.fsync(fd)
        # The capture's own intent sync succeeds; only its last directory sync after the result fails.
        writer = cl.Ledger.open(self.root, sync=True)
        capture = writer.begin_capture({'command': 'id'})
        writer._fsync = failing
        with self.assertRaises(OSError):
            writer.finish_capture(capture, b'out', b'', {'exit': 0})
        # The entry reads whole, but its barrier never completed: every opening refuses until it does.
        self.assertEqual(cl.scan(self.root)[-1].state, 'complete')
        for _ in range(2):
            with self.assertRaises(OSError):
                cl.Ledger.open(self.root, sync=True, fsync=failing)
        spy = Spy()
        self.assertEqual(cl.Ledger.open(self.root, sync=True, fsync=spy).last.state, 'complete')
        self.assertIn(str(entry), spy.events)

    def test_damage_refuses_reopening(self):
        def fresh():
            if self.root.exists():
                for path in sorted(self.root.rglob('*'), reverse=True):
                    path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
                self.root.rmdir()
            ledger = self.ledger()
            ledger.record('open', {})
            entry = ledger.begin_capture({'command': 'id'})
            ledger.finish_capture(entry, b'out', b'err', {'exit': 0})
            ledger.record('report', {})
            return ledger
        damages = {
            'stream bytes': lambda: (self.root / '000002-capture' / 'stdout').write_bytes(b'OUT'),
            'unknown name': lambda: (self.root / 'stray').write_text('x'),
            'unknown kind': lambda: os.mkdir(self.root / '000004-shell'),
            'gap': lambda: os.mkdir(self.root / '000005-report'),
            'link entry': lambda: os.symlink('000001-open', self.root / '000004-open'),
            'extra file': lambda: (self.root / '000001-open' / 'extra').write_text('x'),
            'lost stream': lambda: (self.root / '000002-capture' / 'stderr').unlink(),
            'wrong number': lambda: (self.root / '000003-report' / 'record.json').write_text(
                json.dumps({'number': 9, 'kind': 'report'})),
            'marker': lambda: (self.root / 'LEDGER').write_bytes(b'other\n'),
        }
        for name, damage in damages.items():
            fresh()
            damage()
            with self.assertRaises(cl.LedgerDamaged, msg=name):
                cl.Ledger.open(self.root)

    def test_incomplete_last_entries_have_known_states(self):
        cases = {
            'empty capture': ([], 'intent-incomplete'),
            'partial intent': ([('intent.json', b'{"number": 2, "ki')], 'intent-incomplete'),
            'intent only': ([('intent.json', None)], 'interrupted'),
            'intent and stdout': ([('intent.json', None), ('stdout', b'x')], 'interrupted'),
            'partial result': ([('intent.json', None), ('stdout', b''), ('stderr', b''), ('result.json', b'{"num')],
                               'interrupted'),
        }
        for name, (files, state) in cases.items():
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'ledger'
                ledger = cl.Ledger.create(root, sync=False)
                ledger.record('open', {})
                folder = root / '000002-capture'
                os.mkdir(folder)
                for file, data in files:
                    if data is None:
                        data = cl.encode_json({'number': 2, 'kind': 'capture', 'command': 'id'})
                    (folder / file).write_bytes(data)
                reopened = cl.Ledger.open(root, sync=False)
                self.assertEqual(reopened.last.state, state, name)
                self.assertEqual([e.number for e in reopened.unquarantined()], [2])
                with self.assertRaises(cl.LedgerDamaged):
                    reopened.record('open', {})
                number = reopened.record('quarantine', {'entry': 2})
                self.assertEqual(number, 3)
                again = cl.Ledger.open(root, sync=False)
                self.assertEqual(again.unquarantined(), [])
                again.record('open', {})

    def test_a_quarantine_cut_short_is_completed_by_the_next_reopening(self):
        ledger = self.ledger()
        ledger.record('open', {})
        os.mkdir(self.root / '000002-capture')  # The entry a lost broker left.
        os.mkdir(self.root / '000003-quarantine')  # Its reopening was lost while naming it.
        reopened = cl.Ledger.open(self.root)
        self.assertEqual([e.number for e in reopened.unquarantined()], [2, 3])
        reopened.record('quarantine', {'entry': 2})
        reopened.record('quarantine', {'entry': 3})
        cl.Ledger.open(self.root).record('open', {})

    def test_an_incomplete_entry_before_other_entries_is_damage(self):
        ledger = self.ledger()
        ledger.record('open', {})
        os.mkdir(self.root / '000002-fault')
        os.mkdir(self.root / '000003-report')
        (self.root / '000003-report' / 'record.json').write_bytes(cl.encode_json({'number': 3, 'kind': 'report'}))
        with self.assertRaises(cl.LedgerDamaged):
            cl.Ledger.open(self.root)

    def test_a_quarantine_names_an_incomplete_entry(self):
        ledger = self.ledger()
        ledger.record('open', {})
        ledger.record('quarantine', {'entry': 1})
        with self.assertRaises(cl.LedgerDamaged):
            cl.Ledger.open(self.root)

    def test_the_ledger_is_bounded(self):
        ledger = self.ledger()
        with mock.patch.object(cl, 'MAX_ENTRIES', 2):
            ledger.record('open', {})
            ledger.record('open', {})
            with self.assertRaises(cl.LedgerDamaged):
                ledger.record('open', {})


if __name__ == '__main__':
    unittest.main()
