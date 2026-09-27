# SPDX-License-Identifier: Apache-2.0
"""Host qualification of the bounded descriptor fixture, not crash durability."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class FdCopyTests(unittest.TestCase):
    def test_descriptor_modes_exclusive_namespace_and_faults(self):
        self.assertTrue(shutil.which('cc'), 'C compiler required')
        self.assertNotEqual(os.geteuid(), 0, 'DAC controls require an unprivileged host user')
        with tempfile.TemporaryDirectory(prefix='fdcopy-') as directory:
            root = Path(directory)
            base = root / 'files'
            base.mkdir()
            binary = root / 'fd-copy'
            compile_result = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                                             '-DFD_COPY_HOST_TEST', '-DFD_COPY_FAULT_TEST',
                                             '-DFD_COPY_TEST_BASE="' + str(base) + '"',
                                             str(HERE / 'fd_copy_probe.c'), '-o', str(binary)],
                                            capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)
            data = bytes((i * 31 + 17) % 256 for i in range(37068))
            digest = hashlib.sha256(data).hexdigest()

            def invoke(action, nonce, ok=True, fail=None):
                env = dict(os.environ)
                if fail is not None:env['FD_COPY_FAIL_SYNC'] = str(fail)
                result = subprocess.run([str(binary), action, nonce], env=env,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                complete = [row for row in rows if row.get('complete') is True]
                if ok:self.assertEqual(complete, [{'complete': True, 'operation': action, 'nonce': nonce, 'physical_power_loss_proved': False}])
                else:self.assertFalse(complete)
                return rows

            def input_file(nonce):
                path = base / ('andrix-writeback-input-' + nonce + '.apk')
                path.write_bytes(data)
                return path

            nonce = '1' * 32
            input_file(nonce)
            rows = invoke('prepare', nonce)
            events = [(row.get('stage'), row.get('group')) for row in rows if 'event' in row]
            self.assertEqual([group for stage, group in events if stage == 'create-start'], ['durable', 'namespace', 'unsynced'])
            self.assertEqual([group for stage, group in events if stage == 'writing-fd-synced'], ['durable'])
            self.assertEqual([group for stage, group in events if stage == 'parent-directory-synced'], ['durable', 'namespace'])
            self.assertLess(events.index(('writing-fd-synced', 'durable')), events.index(('writing-fd-closed', 'durable')))
            self.assertLess(events.index(('parent-directory-synced', 'durable')), events.index(('create-start', 'namespace')))
            self.assertLess(events.index(('parent-directory-synced', 'namespace')), events.index(('create-start', 'unsynced')))
            self.assertFalse(any('synced' in stage for stage, _ in events[events.index(('create-start', 'unsynced')):]))
            destination = base / ('andrix-writeback-' + nonce)
            before = {str(p.relative_to(destination)): (p.stat().st_ino, p.read_bytes()) for p in destination.rglob('*.apk')}
            rows = invoke('observe', nonce, fail=1)  # Observe must never call fsync.
            copies = [row for row in rows if 'hex' in row]
            self.assertEqual(len(copies), 3)
            self.assertTrue(all(hashlib.sha256(bytes.fromhex(row['hex'])).hexdigest() == digest for row in copies))
            invoke('prepare', nonce, ok=False)
            self.assertEqual(before, {str(p.relative_to(destination)): (p.stat().st_ino, p.read_bytes()) for p in destination.rglob('*.apk')})

            for point in range(1, 7):
                value = f'{point + 10:032x}'
                input_file(value)
                invoke('prepare', value, ok=False, fail=point)
                self.assertTrue((base / ('andrix-writeback-' + value)).is_dir())
                invoke('prepare', value, ok=False)
            for bad in ['a' * 31, 'A' * 32, '../' + '0' * 29, 'g' * 32]:invoke('prepare', bad, ok=False)
            invoke('erase', nonce, ok=False)
            missing = invoke('observe', 'e' * 32)
            self.assertEqual(missing[0]['state'], 'absent')

            value = '2' * 32
            source = input_file(value)
            source.unlink(); source.symlink_to(base / ('andrix-writeback-input-' + nonce + '.apk'))
            invoke('prepare', value, ok=False)
            self.assertFalse((base / ('andrix-writeback-' + value)).exists())
            value = '3' * 32
            source = input_file(value)
            os.link(source, base / 'input-alias')
            invoke('prepare', value, ok=False)
            self.assertFalse((base / ('andrix-writeback-' + value)).exists())
            payload = destination / 'durable/payload.apk'
            payload.chmod(0o200)
            try:invoke('observe', nonce, ok=False)
            finally:payload.chmod(0o600)
            payload.unlink(); payload.symlink_to(base / ('andrix-writeback-input-' + nonce + '.apk'))
            invoke('observe', nonce, ok=False)


if __name__ == '__main__':unittest.main()
