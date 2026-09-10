# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import terminal_libraries as libraries


class TerminalLibraryPinsTests(unittest.TestCase):
    def test_pinned_library_only_inputs(self):
        result = libraries.verify()
        self.assertEqual(result['unmodified_files'], 42)
        self.assertEqual(result['commit'], libraries.COMMIT)
        self.assertFalse((libraries.LIBRARIES/'terminal-emulator/src/main/jni').exists())
        bp = (libraries.LIBRARIES/'Android.bp').read_text()
        self.assertIn('name: "AndrixTerminalLibraries"', bp)
        self.assertIn('":andrix_terminal_adapter_sources"', bp)
        self.assertNotIn('jni_libs', bp)

    def test_changed_blob_and_self_rewritten_manifest_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'libraries'
            shutil.copytree(libraries.LIBRARIES, root)
            target = root/'terminal-emulator/src/main/java/com/termux/terminal/KeyHandler.java'
            target.write_bytes(target.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'Changed terminal library'):
                libraries.verify(root)
            manifest = json.loads((root/'SOURCE.json').read_text())
            row = next(x for x in manifest['files'] if x['path'] == target.relative_to(root).as_posix())
            data = target.read_bytes()
            row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                       sha1=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest())
            (root/'SOURCE.json').write_text(json.dumps(manifest, indent=2)+'\n')
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                libraries.verify(root)

    def test_extra_source_symlink_and_license_change_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'libraries'
            shutil.copytree(libraries.LIBRARIES, root)
            extra = root/'unexpected.java';extra.write_text('class Unexpected {}')
            with self.assertRaisesRegex(ValueError, 'Unexpected terminal library'):
                libraries.verify(root)
            extra.unlink()
            target = root/'terminal-emulator/src/main/java/com/termux/terminal/KeyHandler.java'
            saved = Path(tmp)/'saved.java';target.rename(saved);target.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, 'Source symlink'):
                libraries.verify(root)
            target.unlink();saved.rename(target)
            license = root/'LICENSE';saved_license = Path(tmp)/'LICENSE'
            license.rename(saved_license);license.symlink_to(saved_license)
            with self.assertRaisesRegex(ValueError, 'Source symlink'):
                libraries.verify(root)
            license.unlink();saved_license.rename(license)
            (root/'UPSTREAM-LICENSE.md').write_text('replaced')
            with self.assertRaisesRegex(ValueError, 'License statement changed'):
                libraries.verify(root)


if __name__ == '__main__':
    unittest.main()
