# SPDX-License-Identifier: Apache-2.0
"""The fixture's Java host suites, compiled and run with the pinned JDK, and their controls.

ANDRIX_NOTICE_JDK names the pinned JDK 25 bin directory; without it every case is skipped, which
qualifies nothing. Each suite compiles with javac --release 17 -Xlint:all -Werror in a scratch
directory and runs in a bounded JVM:

- the plain Java suite: request and row framing, the activity's identity and callback decisions,
  the store's order, repeats, conflicts, failures, crash prefixes and process restarts, the listing
  and the provider policy, and goldens that must equal the committed ones byte for byte, with a
  control built from a changed copy of the disk model that takes an existing directory as durable;
- the model suite: the actual helper, provider, writer holder and disk classes against explicit
  host stubs of the Android classes they use, with two controls built from changed copies: a
  helper without identity sharing, and a Binder interface of another shape;
- the reconciler suite: receipts against the accepted deployment Reconciler, with changed copies
  of the reconciler's delay, first receipt and budget rules that must each fail their case.

Host evidence only: the stubs and changed copies live in scratch, never in a build."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import notice_route as route  # noqa: E402

JDK = os.environ.get('ANDRIX_NOTICE_JDK')
DEPLOYMENT = ROOT / 'owner/deployment/java/dev/andrix/server/deployment'
SOURCES = HERE / 'src/dev/andrix/lab/notice'
PURE = ('Forms', 'NoticeRequest', 'ReceiptRow', 'Disk', 'ReceiptStore', 'Delivery', 'ProviderPolicy')
MODELLED = PURE + ('ReceiptProvider', 'AndroidDisk', 'Writer')
JAVAC = ('--release', '17', '-Xlint:all', '-Werror', '-proc:none', '-implicit:none', '-encoding', 'US-ASCII')
JVM = ('-Xmx256m', '-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1', '-XX:MaxMetaspaceSize=128m',
       '-XX:ReservedCodeCacheSize=48m', '-ea')
HOST_CASES = 20
MODEL_CASES = 14
RECONCILER_CASES = 7
RESTART_CASES = ("store / after a process restart, a new row is accepted once the directory's name is durable",
                 "store / after a process restart, a repeat is accepted once the row's name is durable",
                 'store / after every restart prefix, an accepted row survives a later loss')


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))


def results(stdout):
    return re.findall(r'^PASS (.+)$', stdout, re.M), re.findall(r'^FAIL (.+?): ', stdout, re.M)


@unittest.skipUnless(JDK, 'needs ANDRIX_NOTICE_JDK, the pinned JDK 25 bin directory')
class JavaSuites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jdk = Path(JDK)
        tools = json.loads((HERE / 'tools.json').read_text())
        for tool in ('javac', 'java'):
            digest = hashlib.sha256((cls.jdk / tool).read_bytes()).hexdigest()
            if digest != tools['prebuilts/jdk/jdk25/linux-x86/bin/' + tool]:
                raise ValueError('the Java suites need the pinned JDK')
        cls.temporary = tempfile.TemporaryDirectory(prefix='notice-java-')
        cls.root = Path(cls.temporary.name)
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(cls.root), 'TMPDIR': str(cls.root), 'LANG': 'C.UTF-8'}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def javac(self, name, sources):
        out = self.root / name
        out.mkdir()
        done = subprocess.run([str(self.jdk / 'javac'), '-J-Xmx384m', '-J-XX:+UseSerialGC', *JAVAC, '-d', str(out),
                               *map(str, sources)], capture_output=True, text=True, timeout=170, env=self.env,
                              preexec_fn=_limits)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return out

    def java(self, classes, main, *args):
        done = subprocess.run([str(self.jdk / 'java'), *JVM, '-Djava.io.tmpdir=' + str(self.root), '-cp',
                               str(classes), main, *map(str, args)], capture_output=True, text=True, timeout=170,
                              env=self.env, preexec_fn=_limits)
        return done.returncode, done.stdout + done.stderr

    # ------------------------------------------------------------------ the plain Java suite

    def test_the_plain_java_suite_passes_and_writes_the_committed_goldens(self):
        classes = self.javac('host', [*(SOURCES / (n + '.java') for n in PURE),
                                      *sorted((HERE / 'javatests').rglob('*.java'))])
        goldens = self.root / 'goldens'
        vectors = self.root / 'vectors.txt'
        vectors.write_text(self.vectors(), encoding='ascii')
        code, out = self.java(classes, 'dev.andrix.lab.notice.NoticeHostTests', goldens, vectors)
        passed, failed = results(out)
        self.assertEqual((code, failed), (0, []), out)
        self.assertEqual(len(passed), HOST_CASES + 2, out)
        # Java writes every golden but the pinned aapt2 manifest dump, which the producer recorded.
        committed = sorted(p.name for p in (HERE / 'goldens').iterdir() if p.name != 'compiled-manifest.txt')
        self.assertEqual(sorted(p.name for p in goldens.iterdir()), committed)
        for name in committed:
            self.assertEqual((goldens / name).read_bytes(), (HERE / 'goldens' / name).read_bytes(), name)

    def test_a_disk_that_skips_an_existing_directorys_parent_sync_loses_the_restarted_row(self):
        """Control: a disk model that takes an existing directory as durable, without syncing its
        parent, loses the row a restarted process accepted at the next loss, so only the restart
        cases fail. The actual model syncs the parent, and the plain suite passes."""
        source = (HERE / 'javatests/dev/andrix/lab/notice/MemoryDisk.java').read_text()
        rule = '    public void ensureDirectory() throws IOException {\n'
        self.assertEqual(source.count(rule), 1)
        changed = self.root / 'unsynced-parent' / 'MemoryDisk.java'
        changed.parent.mkdir()
        changed.write_text(source.replace(rule, rule + '        if (directory) return;\n'))
        tests = [p for p in sorted((HERE / 'javatests').rglob('*.java')) if p.name != 'MemoryDisk.java']
        classes = self.javac('host-unsynced-parent', [*(SOURCES / (n + '.java') for n in PURE), *tests, changed])
        code, out = self.java(classes, 'dev.andrix.lab.notice.NoticeHostTests')
        failed = results(out)[1]
        self.assertEqual(code, 1, out)
        self.assertIn(RESTART_CASES[0], failed, out)
        self.assertTrue(set(failed) <= set(RESTART_CASES), out)
        line = next(x for x in out.splitlines() if x.startswith('FAIL ' + RESTART_CASES[0] + ': '))
        self.assertIn('the row survives the later loss', line)

    def vectors(self):
        """The Python route's helper arguments for a spread of issues, which Java must accept and
        give back exactly, and hand changed copies, which Java must refuse."""
        text = ''.join(chr(c) for c in range(0x20, 0x7f)) * 10
        base = {'purpose': 'TICKET_NOTICE', 'installation': '00112233445566778899aabbccddeeff',
                'component': 'com.android.systemui', 'plan': '01' * 16, 'ticket': '04' * 16, 'index': 0,
                'boot': '3b' * 16, 'challenge': '8c' * 16, 'text': 'x', 'text_sha256': hashlib.sha256(b'x').hexdigest()}
        issues = [base, dict(base, index=59, component='a_1.B2.c3_d', text=text[:1024],
                             text_sha256=hashlib.sha256(text[:1024].encode()).hexdigest()),
                  dict(base, purpose='QUALIFICATION', plan=None, ticket=None, index=None, control='c0' * 16)]
        lines = []
        for value in issues:
            for user, serial in ((0, 0), (10, 5), (21473, 2 ** 31 - 1)):
                lines.append('accept\t' + ' '.join(route.helper_arguments(value, {'user': user, 'serial': serial})))
        good = route.helper_arguments(base, {'user': 10, 'serial': 5})
        for at, value in ((1, '21474'), (2, '2147483648'), (8, '140'), (12, 'ab' * 32), (13, 'X'), (0, '2')):
            lines.append('refuse\t' + ' '.join(good[:at] + [value] + good[at + 1:]))
        lines.append('refuse\t' + ' '.join(good[:13]))
        return '\n'.join(lines) + '\n'

    # ------------------------------------------------------------------ the model suite

    def model(self, name, stubs=None, helper=None):
        stubs = stubs or HERE / 'javatests-model'
        sources = [*sorted(p for p in stubs.rglob('*.java') if 'dev/andrix' not in p.as_posix()),
                   HERE / 'javatests-model/dev/andrix/lab/notice/ModelTests.java',
                   *(HERE / 'javatests/dev/andrix/lab/notice' / (n + '.java') for n in ('Cases', 'NoticeHostTests',
                                                                                         'MemoryDisk')),
                   *(SOURCES / (n + '.java') for n in MODELLED),
                   helper or HERE / 'present-src/dev/andrix/lab/notice/NoticePresent.java']
        return self.javac(name, sources)

    def test_the_model_suite_runs_the_actual_helper_provider_and_disk_against_stubs(self):
        classes = self.model('model')
        code, out = self.java(classes, 'dev.andrix.lab.notice.ModelTests', 'all', self.root / 'model-run')
        passed, failed = results(out)
        self.assertEqual((code, failed, len(passed)), (0, [], MODEL_CASES), out)

    def test_a_helper_without_identity_sharing_is_refused_by_the_activity(self):
        source = (HERE / 'present-src/dev/andrix/lab/notice/NoticePresent.java').read_text()
        call = '        options.setShareIdentityEnabled(true);\n'
        self.assertEqual(source.count(call), 1)
        mutant = self.root / 'no-identity' / 'NoticePresent.java'
        mutant.parent.mkdir()
        mutant.write_text(source.replace(call, ''))
        classes = self.model('model-no-identity', helper=mutant)
        code, out = self.java(classes, 'dev.andrix.lab.notice.ModelTests', 'no-identity', self.root / 'no-identity-run')
        self.assertEqual((code, len(results(out)[0])), (0, 1), out)
        # Control: the actual helper shares identity, so the same expectation fails.
        actual = self.model('model-identity-control')
        code, out = self.java(actual, 'dev.andrix.lab.notice.ModelTests', 'no-identity', self.root / 'control-run')
        self.assertEqual((code, len(results(out)[1])), (1, 1), out)

    def test_a_binder_interface_of_another_shape_is_refused_before_any_call(self):
        feature = 'String callingPackage, String callingFeatureId,\n            Intent intent,'
        for name, old, new in (('feature', feature, 'String callingPackage,\n            Intent intent,'),
                               ('return', 'WaitResult startActivityAndWait(', 'int startActivityAndWait(')):
            with self.subTest(name):
                stubs = self.root / ('stubs-' + name)
                for path in (HERE / 'javatests-model/android').rglob('*.java'):
                    target = stubs / path.relative_to(HERE / 'javatests-model')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(path.read_text())
                interface = stubs / 'android/app/IActivityTaskManager.java'
                text = interface.read_text()
                self.assertEqual(text.count(old), 1)
                interface.write_text(text.replace(old, new))
                classes = self.model('model-' + name, stubs=stubs)
                code, out = self.java(classes, 'dev.andrix.lab.notice.ModelTests', 'signature', self.root / name)
                self.assertEqual((code, len(results(out)[0])), (0, 1), out)
        control = self.model('model-signature-control')
        code, out = self.java(control, 'dev.andrix.lab.notice.ModelTests', 'signature', self.root / 'signature-control')
        self.assertEqual(code, 1, out)

    # ------------------------------------------------------------------ the reconciler suite

    def reconciler(self, name, change=None):
        sources = sorted(DEPLOYMENT.glob('*.java'))
        if change is not None:
            copy = self.root / (name + '-src')
            copy.mkdir()
            for path in sources:
                text = path.read_text()
                if path.name == 'Reconciler.java':
                    self.assertEqual(text.count(change[0]), 1, change[0])
                    text = text.replace(change[0], change[1])
                (copy / path.name).write_text(text)
            sources = sorted(copy.glob('*.java'))
        test = HERE / 'javatests-reconciler/dev/andrix/lab/notice/join/ReceiptReconcilerTests.java'
        classes = self.javac(name, [*sources, test])
        return self.java(classes, 'dev.andrix.lab.notice.join.ReceiptReconcilerTests')

    def test_receipts_against_the_accepted_reconciler(self):
        code, out = self.reconciler('reconciler')
        passed, failed = results(out)
        self.assertEqual((code, failed, len(passed)), (0, [], RECONCILER_CASES), out)

    def test_changed_reconciler_rules_fail_their_own_cases(self):
        changes = {
            'the delay boundary': ('return c.now.elapsed - last >= noticeDelay(c, delivered);',
                                   'return c.now.elapsed - last > noticeDelay(c, delivered);',
                                   'delay / the reboot waits the declared delay from the proven delivery'),
            'the first receipt': ('if (first == null || r.elapsed < first.elapsed) first = r;',
                                  'if (first == null || r.elapsed > first.elapsed) first = r;',
                                  "delay / the last required user's first receipt starts the delay"),
            'the notice budget': ('if (inBoot >= p.requestLimit + 1 || t.count(',
                                  'if (inBoot >= p.requestLimit + 2 || t.count(',
                                  'budget / without receipts, request limit plus one notices in a boot'),
        }
        for name, (old, new, case) in changes.items():
            with self.subTest(name):
                code, out = self.reconciler('changed-' + name.replace(' ', '-'), (old, new))
                failed = results(out)[1]
                self.assertEqual(code, 1, out)
                self.assertTrue(any(f.startswith(case) for f in failed), out)


if __name__ == '__main__':
    unittest.main()
