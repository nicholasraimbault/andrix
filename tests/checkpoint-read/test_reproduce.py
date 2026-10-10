# SPDX-License-Identifier: Apache-2.0
"""Host checks for the checkpoint helper's source, its pins and its reproducible build.

The pin, source and refusal checks always run. The real rebuild runs only when
ANDRIX_CHECKPOINT_READ_JDK names the pinned JDK 25 home and ANDRIX_CHECKPOINT_READ_R8 the pinned
r8 jar. It writes into a fresh directory under ANDRIX_CHECKPOINT_READ_WORK, or the system's
temporary directory, never into the repository.
"""
from pathlib import Path
import hashlib
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
import reproduce  # noqa: E402
from scripts.proof import systemui_observer as observer  # noqa: E402
from scripts.proof import systemui_sessions as readback  # noqa: E402

SOURCE = HERE / 'CheckpointRead.java'


def java_code(text):
    """Java source without comments."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


class PinTests(unittest.TestCase):
    def test_the_pins_name_the_committed_source(self):
        pins = reproduce.pins()
        data = SOURCE.read_bytes()
        self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                         (pins['source']['bytes'], pins['source']['sha256']))
        self.assertEqual(set(pins), {'schema', 'source', 'jdk', 'javac', 'class', 'r8', 'd8', 'jar'})
        self.assertEqual(pins['javac'], ['--release', '17', '-Xlint:all', '-Werror'])
        self.assertEqual(pins['d8'], ['--release', '--min-api', '30'])

    def test_the_observer_admits_exactly_the_pinned_jar(self):
        pins = reproduce.pins()
        self.assertEqual(observer.CHECKPOINT_HELPER_SHA256, pins['jar']['sha256'])
        self.assertEqual(Path(observer.CHECKPOINT_HELPER).name, pins['jar']['name'])
        self.assertEqual(observer.CHECKPOINT_READ,
                         'CLASSPATH=%s app_process /system/bin CheckpointRead' % observer.CHECKPOINT_HELPER)
        self.assertEqual(observer.HELPER_DIGEST, 'sha256sum ' + observer.CHECKPOINT_HELPER)

    def test_the_source_asks_only_the_two_queries(self):
        code = java_code(SOURCE.read_text())
        self.assertEqual(re.findall(r'call\(iface, storage, "(\w+)"\)', code), ['supportsCheckpoint', 'needsCheckpoint'])
        self.assertEqual(re.findall(r'getService", String\.class\)\.invoke\(null, "(\w+)"\)', code), ['mount'])
        for name in ('startCheckpoint', 'commitChanges', 'abortChanges', 'prepareCheckpoint', 'restoreCheckpoint',
                     'markBootAttempt', 'resetCheckpoint', 'getRuntime', 'exec(', 'ProcessBuilder', 'transact', 'File'):
            self.assertNotIn(name, code)
        self.assertEqual(re.findall(r'HEADER = "([^"]*)"', code), [readback.CHECKPOINT_READ_HEADER])
        # The protocol the parser reads: the error lines and the status of each.
        self.assertEqual(re.findall(r'"error=([a-z-]+)[:"]', code), ['arguments', 'service-absent'])
        self.assertEqual(re.findall(r'System\.exit\((\d)\)', code), ['2', '3', '4'])
        self.assertIn('fail("lookup", e)', code)
        self.assertIn('? 0 : 5) : 5);', code)


class RefusalTests(unittest.TestCase):
    """Nothing starts until the work directory and every input are the pinned ones."""

    def refused(self, **arguments):
        with mock.patch.object(reproduce.subprocess, 'run', side_effect=AssertionError('a tool started')):
            with self.assertRaises(reproduce.Refused):
                reproduce.reproduce(**arguments)

    def test_a_work_directory_in_the_repository_or_not_new_is_refused(self):
        self.refused(jdk='/nonexistent', r8='/nonexistent', work=ROOT / 'tests' / 'checkpoint-read' / 'out')
        self.refused(jdk='/nonexistent', r8='/nonexistent', work=ROOT)
        with tempfile.TemporaryDirectory() as existing:
            self.refused(jdk='/nonexistent', r8='/nonexistent', work=existing)

    def test_inputs_that_are_not_the_pinned_ones_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            jdk = base / 'jdk'
            (jdk / 'bin').mkdir(parents=True)
            (jdk / 'release').write_text('JAVA_VERSION="25"\n')
            r8 = base / 'r8.jar'
            r8.write_bytes(b'not r8')
            self.refused(jdk=jdk, r8=r8, work=base / 'work')
            self.refused(jdk=base / 'missing', r8=r8, work=base / 'work')
            link = base / 'link'
            link.symlink_to(jdk / 'release')
            with self.assertRaises(reproduce.Refused):
                reproduce.pinned_file(link, 18, hashlib.sha256(b'JAVA_VERSION="25"\n').hexdigest(), 'a link')
            self.assertFalse((base / 'work').exists())

    def test_a_changed_source_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / 'CheckpointRead.java'
            changed.write_bytes(SOURCE.read_bytes().replace(b'needsCheckpoint', b'startCheckpoint'))
            pins = reproduce.pins()
            with self.assertRaises(reproduce.Refused):
                reproduce.pinned_file(changed, pins['source']['bytes'], pins['source']['sha256'], 'the helper source')


@unittest.skipUnless(os.environ.get('ANDRIX_CHECKPOINT_READ_JDK') and os.environ.get('ANDRIX_CHECKPOINT_READ_R8'),
                     'the pinned JDK and r8 jar are not given')
class RebuildTests(unittest.TestCase):
    def test_the_source_rebuilds_to_the_pinned_jar(self):
        parent = os.environ.get('ANDRIX_CHECKPOINT_READ_WORK') or None
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory) / 'work'
            record = reproduce.reproduce(os.environ['ANDRIX_CHECKPOINT_READ_JDK'],
                                         os.environ['ANDRIX_CHECKPOINT_READ_R8'], work)
            pins = reproduce.pins()
            self.assertEqual(record['status'], 'PASS', record.get('problem'))
            self.assertEqual(record['jar'], {'bytes': pins['jar']['bytes'], 'sha256': pins['jar']['sha256']})
            data = (work / pins['jar']['name']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), observer.CHECKPOINT_HELPER_SHA256)


if __name__ == '__main__':
    unittest.main()
