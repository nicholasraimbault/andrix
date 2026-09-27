# SPDX-License-Identifier: Apache-2.0
"""Host checks for the Package Installer reverse write fsync candidate.

Source and provenance checks always run. Pinned source checks need ANDRIX_SOURCE_ROOT.
JVM checks run only inside the required resource bounds. They execute the exact extracted
fragment on a host JVM; they are not Android compilation or runtime evidence.
"""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pis_reverse_write_sync as rws  # noqa: E402

PASS = 'PIS_REVERSE_WRITE_SYNC_HOST_PASS_NO_ANDROID_CLAIM'
FSYNC = '                    Os.fsync(targetPfd.getFileDescriptor());\n'
FINALLY = '                } finally {\n'
AFTER_INCOMING = '                    IoUtils.closeQuietly(incomingFd);\n'
MISPLACED = 'FAIL fsync did not use the descriptor that received the copy'
UNCHECKED = 'FAIL fsync failure did not fail the write'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise AssertionError('variant anchor is not unique')
    return text.replace(old, new, 1)


def indented(*lines):
    return ''.join(' ' * 20 + line + '\n' for line in lines)


# Each wrong placement must fail the harness with the named check. The one accepted
# alternative is a checked java.io.FileDescriptor.sync() on the same writing descriptor.
VARIANTS = {
    'swallowed_error': (lambda t: replace_once(t, FSYNC, indented(
        'try {', '    Os.fsync(targetPfd.getFileDescriptor());',
        '} catch (ErrnoException ignored) {', '}')), UNCHECKED),
    'fileutils_sync_ignored_bool': (lambda t: replace_once(t, FSYNC, indented(
        'FileUtils.sync(new FileOutputStream(targetPfd.getFileDescriptor()));')), UNCHECKED),
    'reopened_read_descriptor': (lambda t: replace_once(t, FSYNC, indented(
        'Os.fsync(Os.open(target.getAbsolutePath(), O_RDONLY, 0));')), MISPLACED),
    'stage_directory': (lambda t: replace_once(t, FSYNC, indented(
        'Os.fsync(Os.open(stageDir.getAbsolutePath(), O_RDONLY, 0));')), MISPLACED),
    'incoming_descriptor': (lambda t: replace_once(t, FSYNC, indented(
        'Os.fsync(incomingFd.getFileDescriptor());')), MISPLACED),
    'under_session_lock': (lambda t: replace_once(t, FSYNC, indented(
        'synchronized (mLock) {', '    Os.fsync(targetPfd.getFileDescriptor());', '}')),
        'FAIL Os.fsync ran while holding a session lock'),
    'first_in_finally': (lambda t: replace_once(replace_once(t, FSYNC, ''), FINALLY,
                                                FINALLY + FSYNC),
                         'FAIL event order after fsync failure'),
    'after_close': (lambda t: replace_once(replace_once(t, FSYNC, ''), AFTER_INCOMING,
                                           AFTER_INCOMING + FSYNC),
                    'FAIL positive reverse write threw'),
    'checked_descriptor_sync': (lambda t: replace_once(t, FSYNC, indented(
        'targetPfd.getFileDescriptor().sync();')), None),
}


def added_lines():
    lines = rws.PATCH.read_text().splitlines()[2:]
    return [line[1:] for line in lines if line.startswith('+')]


class PisReverseWriteSourceTests(unittest.TestCase):
    def test_profile_binds_candidate_to_accepted_verity_base(self):
        value = rws.profile()
        base = rws.verity.profile()
        self.assertEqual(value['base_sha256'], base['candidate_sha256'])
        self.assertEqual(value['upstream_sha256'], base['upstream_sha256'])
        self.assertEqual((value['status'], value['integrated']), ('candidate', False))
        self.assertEqual(value['base_profile_sha256'], rws.sha(rws.verity.PROFILE.read_bytes()))

    def test_patch_adds_one_checked_fsync_and_removes_nothing(self):
        lines = rws.PATCH.read_text().splitlines()
        self.assertEqual(lines[:2], ['--- a/' + rws.FILE, '+++ b/' + rws.FILE])
        self.assertEqual(sum(line.startswith('@@') for line in lines), 1)
        self.assertEqual([line for line in lines[2:] if line.startswith('-')], [])
        code = [line.strip() for line in added_lines() if not line.strip().startswith('//')]
        self.assertEqual(code, ['Os.fsync(targetPfd.getFileDescriptor());'])
        self.assertTrue(all(len(line) <= 100 for line in added_lines()))
        text = '\n'.join(added_lines())
        for forbidden in ('FileUtils.sync', 'O_RDONLY', 'stageDir', 'catch', 'synchronized',
                          'incomingFd', 'Os.open', 'fdatasync', 'finally'):
            self.assertNotIn(forbidden, text)

    def test_fragments_differ_only_by_the_inserted_lines(self):
        base = rws.BASE_FRAGMENT.read_text()
        candidate = rws.CANDIDATE_FRAGMENT.read_text()
        block = ''.join(line + '\n' for line in added_lines())
        self.assertEqual(candidate.count(block), 1)
        self.assertEqual(candidate.replace(block, '', 1), base)
        self.assertNotIn('fsync', base)
        for fixture in (rws.BASE_FRAGMENT, rws.CANDIDATE_FRAGMENT, rws.SYNC_FRAGMENT):
            text = fixture.read_text()
            self.assertIn('The Android Open Source Project', text)
            self.assertIn(rws.ATTRIBUTION, text)

    def test_patch_helper_applies_each_direction_only_where_it_fits(self):
        base = rws.BASE_FRAGMENT.read_bytes()
        candidate = rws.CANDIDATE_FRAGMENT.read_bytes()
        self.assertEqual(rws.patched(base, rws.PATCH), candidate)
        self.assertEqual(rws.patched(candidate, rws.PATCH, reverse=True), base)
        # Batch mode would otherwise flip either request into the opposite direction.
        with self.assertRaises(ValueError):
            rws.patched(base, rws.PATCH, reverse=True)
        with self.assertRaises(ValueError):
            rws.patched(candidate, rws.PATCH)

    def test_candidate_orders_copy_fsync_close_and_release(self):
        text = rws.CANDIDATE_FRAGMENT.read_text()
        method = text[text.index('    private ParcelFileDescriptor doWriteInternal('):
                      text.index('    /**\n     * If anybody is reading')]
        order = ['synchronized (mLock) {', 'mBridges.add(bridge);',
                 'FileUtils.copy(incomingFd.getFileDescriptor(), targetPfd.getFileDescriptor(),',
                 FSYNC, FINALLY + '                    IoUtils.closeQuietly(targetPfd);\n',
                 AFTER_INCOMING, 'synchronized (mLock) {', 'mFds.remove(fd);',
                 'bridge.forceClose();', 'mBridges.remove(bridge);', 'return null;']
        position = 0
        for token in order:
            position = method.index(token, position) + len(token)
        for token in (FSYNC, FINALLY + '                    IoUtils.closeQuietly(targetPfd);\n',
                      AFTER_INCOMING, 'Os.fsync('):
            self.assertEqual(method.count(token), 1)
        # Same depth as the copy call, directly after it, so outside every lock block.
        before = method[:method.index(FSYNC)].splitlines()
        self.assertEqual([line for line in before if not line.strip().startswith('//')][-1],
                         '                            });')
        copy = next(line for line in method.splitlines() if 'FileUtils.copy(' in line)
        self.assertEqual(len(copy) - len(copy.lstrip()), len(FSYNC) - len(FSYNC.lstrip()))

    def test_profile_refuses_drift_and_unrecognized_bytes(self):
        original = json.loads(rws.PROFILE.read_text())
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / 'profile.json'
            for data in [dict(original, integrated=True), dict(original, status='applied'),
                         dict(original, version=True), dict(original, head='0' * 40),
                         dict(original, base_sha256=original['upstream_sha256']),
                         dict(original, file='../outside.java'), dict(original, extra=1)]:
                profile.write_text(json.dumps(data))
                with mock.patch.object(rws, 'PROFILE', profile), self.assertRaises(ValueError):
                    rws.profile()
            profile.write_text(rws.PROFILE.read_text().replace(
                '"version": 1', '"version": 1, "version": 1', 1))
            with mock.patch.object(rws, 'PROFILE', profile), self.assertRaises(ValueError):
                rws.profile()
            fixture = Path(directory) / 'fragment.inc'
            fixture.write_bytes(rws.CANDIDATE_FRAGMENT.read_bytes() + b'\n')
            with mock.patch.object(rws, 'CANDIDATE_FRAGMENT', fixture), self.assertRaises(ValueError):
                rws.profile()
            patch = Path(directory) / 'patch'
            patch.write_text(rws.PATCH.read_text().replace('a/' + rws.FILE, 'a/../outside.java'))
            profile.write_text(json.dumps(dict(original, patch_sha256=rws.sha(patch.read_bytes()))))
            with (mock.patch.object(rws, 'PROFILE', profile), mock.patch.object(rws, 'PATCH', patch),
                  self.assertRaises(ValueError)):
                rws.profile()
        with self.assertRaises(ValueError):
            rws.inspect_bytes(b'not the pinned source', b'not FileUtils')

    def test_harness_offers_only_the_real_sync_routes(self):
        template = rws.HARNESS.read_text()
        section = template[template.index('    static final class Os {'):
                           template.index('    static final class FileUtils {')]
        self.assertEqual(sorted(re.findall(r'static \w+ (\w+)\(', section)),
                         ['chmod', 'fsync', 'link', 'lseek', 'open', 'unlink'])
        self.assertNotIn('assert ', template)
        self.assertIn('desiredAssertionStatus()', template)
        self.assertIn(PASS, template)
        rendered = rws.render(rws.CANDIDATE_FRAGMENT.read_bytes(), rws.SYNC_FRAGMENT.read_bytes())
        self.assertIn(rws.CANDIDATE_FRAGMENT.read_text(), rendered)
        self.assertIn(rws.SYNC_FRAGMENT.read_text(), rendered)
        self.assertNotIn('@FRAGMENT@', rendered)
        with self.assertRaises(ValueError):
            rws.render(b'@FRAGMENT@', rws.SYNC_FRAGMENT.read_bytes())
        candidate = rws.CANDIDATE_FRAGMENT.read_text()
        for name, (make, _) in VARIANTS.items():
            with self.subTest(name):
                self.assertNotEqual(make(candidate), candidate)


class PisResourceGuardTests(unittest.TestCase):
    @mock.patch.object(rws.resource, 'getrlimit', return_value=(0, 0))
    def test_guard_requires_every_bound(self, core_limit):
        good = {'memory.max': str(2 << 30), 'memory.swap.max': '0',
                'cpu.max': '200000 100000', 'pids.max': '256'}
        unlimited = {'memory.max': 'max', 'memory.swap.max': 'max',
                     'cpu.max': 'max 100000', 'pids.max': 'max'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'cgroup'
            parent = root / 'user.slice'
            leaf = parent / 'check.scope'
            leaf.mkdir(parents=True)
            membership = Path(directory) / 'membership'
            membership.write_text('0::/user.slice/check.scope\n')
            for name, value in good.items():
                (leaf / name).write_text(value + '\n')
            self.assertIsNone(rws.resource_guard(root, membership))
            for limits in [(0, -1), (1, 1), (-1, -1), (0, 1024)]:
                core_limit.return_value = limits
                self.assertIn('core dumps', rws.resource_guard(root, membership))
            core_limit.return_value = (0, 0)
            for name, weaker in [('memory.max', str(4 << 30)), ('memory.max', 'max'),
                                 ('memory.swap.max', 'max'), ('memory.swap.max', '1'),
                                 ('cpu.max', 'max 100000'), ('cpu.max', '300000 100000'),
                                 ('pids.max', '257'), ('pids.max', 'max')]:
                (leaf / name).write_text(weaker + '\n')
                self.assertIsNotNone(rws.resource_guard(root, membership), name + ' ' + weaker)
                (leaf / name).write_text(good[name] + '\n')
            (leaf / 'pids.max').unlink()
            self.assertIsNotNone(rws.resource_guard(root, membership))
            for name, value in good.items():
                (leaf / name).write_text(unlimited[name] + '\n')
                (parent / name).write_text(value + '\n')
            self.assertIsNone(rws.resource_guard(root, membership))
            (parent / 'cpu.max').write_text('garbage\n')
            self.assertIsNotNone(rws.resource_guard(root, membership))
            (parent / 'cpu.max').write_text(good['cpu.max'] + '\n')
            for text in ['0::/../escape\n', '', '0::/a\n0::/b\n', '1:name=systemd:/x\n']:
                membership.write_text(text)
                self.assertIsNotNone(rws.resource_guard(root, membership), text)
            self.assertIsNotNone(rws.resource_guard(root, Path(directory) / 'missing'))

    def test_guard_only_reports_on_this_host(self):
        result = rws.resource_guard()
        self.assertTrue(result is None or isinstance(result, str))


@unittest.skipUnless(os.environ.get('ANDRIX_SOURCE_ROOT'),
                     'set ANDRIX_SOURCE_ROOT to the pinned Android checkout')
class PisReverseWritePinnedSourceTests(unittest.TestCase):
    def setUp(self):
        project = Path(os.environ['ANDRIX_SOURCE_ROOT']).resolve(strict=True) / rws.PROJECT
        self.pis = (project / rws.FILE).read_bytes()
        self.fileutils = (project / rws.FILEUTILS).read_bytes()
        self.value = rws.profile()

    def test_pinned_source_rebuilds_upstream_and_candidate(self):
        result = rws.inspect_bytes(self.pis, self.fileutils)
        self.assertIn(result['state'], ('BASE', 'CANDIDATE'))
        self.assertTrue(result['fs_verity_correction_preserved'])
        self.assertFalse(result['integrated'] or result['runtime_proved'])
        base = self.pis if result['state'] == 'BASE' else rws.patched(self.pis, rws.PATCH, reverse=True)
        candidate = rws.candidate(base, self.value)
        self.assertEqual(rws.inspect_bytes(candidate, self.fileutils)['state'], 'CANDIDATE')
        self.assertEqual(rws.verity.extracted_method(candidate), rws.verity.EXTRACTED.read_bytes())
        self.assertEqual(rws.pis_fragment(rws.upstream(base, self.value)), rws.BASE_FRAGMENT.read_bytes())

    def test_other_bytes_are_refused(self):
        base = self.pis if rws.sha(self.pis) == self.value['base_sha256'] else rws.patched(
            self.pis, rws.PATCH, reverse=True)
        candidate = rws.candidate(base, self.value)
        upstream = rws.upstream(base, self.value)
        for data in [candidate.replace(b'Os.fsync(targetPfd', b'Os.fsync(incomingFd', 1),
                     base + b'\n', candidate[:-1], upstream, rws.patched(upstream, rws.PATCH)]:
            with self.assertRaises(ValueError):
                rws.inspect_bytes(data, self.fileutils)
        with self.assertRaises(ValueError):
            rws.inspect_bytes(base, self.fileutils + b'\n')


class PisReverseWriteHarnessJvmTests(unittest.TestCase):
    """Guarded JVM checks. No JDK process starts unless the resource guard passes."""

    @classmethod
    def setUpClass(cls):
        cls.javac = os.environ.get('JAVAC') or shutil.which('javac')
        cls.java = os.environ.get('JAVA') or shutil.which('java')
        reason = None if cls.javac and cls.java else 'JDK required (JAVAC and JAVA, or PATH)'
        if reason is None:
            guard = rws.resource_guard()
            reason = None if guard is None else 'resource guard: ' + guard
        if reason is not None:
            if os.environ.get('ANDRIX_REQUIRE_JVM_CHECKS') == '1':
                raise AssertionError('JVM checks required but not run: ' + reason)
            raise unittest.SkipTest(reason)

    def build(self, work, label, fragment):
        directory = work / label
        directory.mkdir()
        source = directory / 'PisReverseWriteHarness.java'
        source.write_text(rws.render(fragment, rws.SYNC_FRAGMENT.read_bytes()))
        result = subprocess.run([self.javac, '-J-Xmx256m', '--release', '17', '-Xlint:all',
                                 '-Werror', '-d', str(directory / 'classes'), str(source)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, label + ' javac\n' + result.stdout + result.stderr)
        return directory

    def run_harness(self, directory, name, *flags):
        return subprocess.run([self.java, '-Xmx256m', '-XX:ActiveProcessorCount=2',
                               '-Djava.io.tmpdir=' + str(directory), *flags,
                               '-cp', str(directory / 'classes'), 'PisReverseWriteHarness',
                               str(directory / name)], capture_output=True, text=True, timeout=120)

    def test_candidate_passes_both_hold_branches(self):
        with tempfile.TemporaryDirectory() as work:
            directory = self.build(Path(work), 'candidate', rws.CANDIDATE_FRAGMENT.read_bytes())
            result = self.run_harness(directory, 'enabled', '-ea')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(PASS, result.stdout)
            for branch in ('bridge', 'revocable'):
                self.assertIn('hold branch ' + branch + ': positive, fsync failure', result.stdout)

    def test_assertions_disabled_run_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            directory = self.build(Path(work), 'candidate', rws.CANDIDATE_FRAGMENT.read_bytes())
            for name, flags in [('default', ()), ('disabled', ('-da',))]:
                result = self.run_harness(directory, name, *flags)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('-ea required', result.stderr)
                self.assertNotIn(PASS, result.stdout)
                self.assertFalse((directory / name).exists())

    def test_pinned_fragment_is_red(self):
        with tempfile.TemporaryDirectory() as work:
            directory = self.build(Path(work), 'pinned', rws.BASE_FRAGMENT.read_bytes())
            result = self.run_harness(directory, 'enabled', '-ea')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('FAIL reverse write returned without exactly one fsync of its writing'
                          ' descriptor: 0', result.stderr)
            self.assertNotIn(PASS, result.stdout)

    def test_wrong_sync_placements_are_red(self):
        candidate = rws.CANDIDATE_FRAGMENT.read_text()
        with tempfile.TemporaryDirectory() as work:
            for name, (make, expected) in VARIANTS.items():
                with self.subTest(name):
                    directory = self.build(Path(work), name, make(candidate).encode())
                    result = self.run_harness(directory, 'enabled', '-ea')
                    output = result.stdout + result.stderr
                    if expected is None:
                        self.assertEqual(result.returncode, 0, output)
                        self.assertIn(PASS, result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0, output)
                        self.assertIn(expected, result.stderr, output)
                        self.assertNotIn(PASS, result.stdout)


if __name__ == '__main__':
    unittest.main()
