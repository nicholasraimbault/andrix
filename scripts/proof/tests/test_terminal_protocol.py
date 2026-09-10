# SPDX-License-Identifier: Apache-2.0
"""Real native/Java protocol cores; not an Android transport integration verdict."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class TerminalProtocolTests(unittest.TestCase):
    def test_native_journal_java_cursor_and_cross_language_frames(self):
        tools = {name: shutil.which(name) for name in ['g++', 'javac', 'java']}
        for name, path in tools.items():
            self.assertIsNotNone(path, name + ' required (use the pinned JDK on PATH)')
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            native = work/'protocol-test'
            compiled = subprocess.run([
                tools['g++'], '-std=c++20', '-Wall', '-Wextra', '-Werror', '-O2',
                '-I'+str(ROOT/'owner/native'),
                str(ROOT/'owner/native/terminal_protocol.cpp'),
                str(ROOT/'owner/tests/terminal_protocol_test.cpp'), '-o', str(native),
            ], text=True, capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(native)], text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('real host sockets', result.stdout)
            fixture = subprocess.run([str(native), '--fixture'], capture_output=True, timeout=10)
            self.assertEqual(fixture.returncode, 0, fixture.stderr)
            self.assertEqual(fixture.stdout[:4], b'ATX1')
            path = work/'native-frame.bin'
            path.write_bytes(fixture.stdout)
            compiled = subprocess.run([
                tools['javac'], '-d', str(work),
                str(ROOT/'owner/terminal/protocol/OutputProtocol.java'),
                str(ROOT/'owner/tests/OutputProtocolTest.java'),
            ], text=True, capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([tools['java'], '-ea', '-cp', str(work),
                                     'OutputProtocolTest', str(path)],
                                    text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('C++ wire fixture', result.stdout)
            self.assertIn('not yet integrated', result.stdout)


if __name__ == '__main__':
    unittest.main()
