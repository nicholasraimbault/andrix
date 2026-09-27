# SPDX-License-Identifier: Apache-2.0
"""Native header copy compatibility, unselected additions and protected reservation writes on
the JVM with host facades and host injected write failures. Not Android crash or power loss proof."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration

FRAMEWORK = ('NativePrincipalPins', 'NativePrincipalManager', 'NativeIdentityRecords',
             'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery')
STORE = ROOT / 'owner/platform/framework/NativeIdentityStore.java'
FACADE = ROOT / 'owner/tests/platform/native_principal_stubs/com/android/server/pm/Settings.java'
FOCUSED = 'NativeIdentityHeaderFootprintTest'
FAULTS = 'NativeHeaderWriteFaultTest'
STEPS = ('seed-synced', 'backup-renamed', 'backup-published', 'write-started', 'main-synced',
         'reserve-synced', 'backup-unlink', 'backup-unlinked')
# Every isolated check, in run order. The corrected sources pass exactly these.
FOCUSED_NAMES = (
    "store repro / admission refuses reuse of B's creation ID",
    'store repro / reservation refused before any effect',
    'store repro / direct header write refused', 'store repro / selected header rewrite refused',
    'initializeNew refused', 'ensureFreshSlot refused', 'resumeCreatingDirectory refused',
    'publishCreatingSlot refused', 'confirmReleasedSlot cannot release an addition',
    'removeReleasingSlot refused',
    'CREATING to LIVE waits for reconciliation', 'LIVE to RELEASING waits for reconciliation',
    'unrelated final omission waits for reconciliation', 'owned retirement header steps refused',
    'exact original B retry', 'original plan with C id2', 'unpublished RETIRING B restated',
    'interrupted CREATING to LIVE is compatible', 'interrupted LIVE to RELEASING is compatible',
    'interrupted omission is compatible',
    'single intact main beside a torn reserve counts', 'single intact reserve beside a torn main counts',
    'disagreeing copies of one addition refuse', 'additions sharing a creation ID refuse',
    'B not substituted by another app ID', 'B not substituted by another creation ID',
    'B not substituted by another package',
    'addition of another lineage not reinterpreted', 'copy of another lineage refuses writes',
    'selected backup of another lineage refuses writes',
    'manager repro / reopened PMS issues nothing',
    'same manager / original B retry', 'same manager / C id2, C committed first',
    'same manager / C id2, B committed first', 'same manager / unpublished RETIRING B with C id2',
    'same manager / C issued first, both restated', 'same manager / B release waits for C',
    'reopened registry keeps holds and LIVE bindings',
    'predecessor of a protected reservation is compatible', 'dropped CREATING entry is no predecessor',
    'lower counter without a newer reservation refuses', 'higher counter only copy refuses header writes',
    'counter advances only with a pure reservation', 'mixed phase change and reservation write refuses',
    'mixed forward phase and addition copy needs its reservation first',
    'incompatible copy / LIVE addition', 'incompatible copy / addition at or below the counter',
    'incompatible copy / backward phase', 'incompatible copy / changed CREATING tuple',
    'incompatible copy / dropped LIVE entry', 'incompatible copy / skipped phase',
    'new entry in the observed range must be a known addition',
    'restatement must cover every copy counter')
FAULT_NAMES = (
    'owned retry keeps B through a failure after startWrite',
    *('legacy owned retry / ' + step for step in STEPS),
    *('new reservation / ' + step for step in STEPS),
    'prior ordering / publication', 'prior ordering / release marker', 'prior ordering / omission',
    'prior ordering / confirmation', 'chained protected reservations',
    'legacy B with C id2 / C first', 'legacy B with C id2 / B first', 'unpublished RETIRING B',
    'interrupted publication then protected reservation',
    'foreign preferred backup is refused unchanged')
# Host only fault seam: anchor, position, indentation, step and record file expression. It is
# inserted into copies of the store and strict writer sources; production sources never call it.
STORE_SEAMS = (
    ('        Node preferred = node(backup(main));\n', 'before', 8, 'backup-guard', 'main'),
    ('            out.getFD().sync();\n        }\n', 'after', 8, 'seed-synced', 'main'),
    ('                StandardCopyOption.REPLACE_EXISTING);\n', 'after', 8, 'backup-renamed', 'main'),
    ('        syncDirectory(main.getParentFile());\n', 'after', 8, 'backup-published', 'main'),
    ('            FileOutputStream out = atomic.startWrite();\n', 'after', 12, 'write-started', 'main'))
WRITER_SEAMS = (
    ('            finalizeStrict(mMainOutStream);\n', 'after', 12, 'main-synced', 'mFile'),
    ('            finalizeStrict(mReserveOutStream);\n', 'after', 12, 'reserve-synced', 'mFile'),
    ('            if (mTemporaryBackup.exists() && !mTemporaryBackup.delete()) {\n', 'before', 12,
     'backup-unlink', 'mFile'),
    ('            FileDescriptor directory = Os.open(mFile.getParent(),\n', 'before', 12,
     'backup-unlinked', 'mFile'))
PROTECT = 'addsOnly(read.value, next), true);'
WRITER_FENCE = '\n                || !keepsHeaderCopies(read, next)) {'
CONFIRM_FENCE = '\n                || !keepsHeaderCopies(read, expected)) return false;'
GUESS = ('            long guessed = 0;\n'
         '            for (NativeIdentityRecords.Header copy : loaded.header.decodedCopies) {\n'
         '                guessed = Math.max(guessed, copy.lastId);\n'
         '            }\n'
         '            restored.restore(new NativePrincipalPins.Snapshot(guessed, records, retiring));\n')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('header footprint source seam drift: ' + old)
    return text.replace(old, new, 1)


def inject(text, seams):
    for anchor, position, indent, step, expression in seams:
        call = ' ' * indent + 'NativeHeaderWriteFaults.at("%s", %s);\n' % (step, expression)
        text = replace_once(text, anchor, call + anchor if position == 'before' else anchor + call)
    return text


def mutants():
    """Deliberate defects: store and facade text, the tests to run and checks that must fail."""
    store = STORE.read_text()
    facade = FACADE.read_text()
    return {
        'prior-protection-for-additions': (
            replace_once(store, PROTECT, 'false, true);'), facade, (FAULTS,),
            {'owned retry keeps B through a failure after startWrite', 'legacy owned retry / write-started',
             'new reservation / backup-published', 'chained protected reservations'}),
        'target-for-every-header-write': (
            replace_once(store, PROTECT, '!read.value.equals(next), true);'), facade, (FAULTS,),
            {'prior ordering / publication', 'prior ordering / release marker', 'prior ordering / omission'}),
        'lost-conservation-fence': (
            replace_once(replace_once(store, WRITER_FENCE, ') {'), CONFIRM_FENCE, ') return false;'),
            facade, (FOCUSED,),
            {'store repro / direct header write refused', 'store repro / selected header rewrite refused',
             'initializeNew refused', 'CREATING to LIVE waits for reconciliation',
             'unrelated final omission waits for reconciliation'}),
        'confirmation-unfenced': (
            replace_once(store, CONFIRM_FENCE, ') return false;'), facade, (FOCUSED,),
            {'initializeNew refused', 'ensureFreshSlot refused', 'resumeCreatingDirectory refused',
             'publishCreatingSlot refused', 'confirmReleasedSlot cannot release an addition',
             'removeReleasingSlot refused'}),
        'missing-predecessor-acceptance': (
            replace_once(store, ': copy.lastId < selected.lastId ? behind : true;',
                         ': copy.lastId < selected.lastId ? false : true;'), facade, (FOCUSED, FAULTS),
            {'predecessor of a protected reservation is compatible', 'new reservation / backup-published',
             'chained protected reservations'}),
        'permissive-predecessor': (
            replace_once(store, 'if (kept.phase == SlotPhase.CREATING && kept.creationId > copy.lastId) behind = true;',
                         'if (kept.phase == SlotPhase.CREATING) behind = true;'), facade, (FOCUSED,),
            {'dropped CREATING entry is no predecessor'}),
        'counter-only-advance': (
            replace_once(replace_once(store, 'return copy.lastId > selected.lastId ? ahead',
                                      'return copy.lastId > selected.lastId ? true'),
                         '\n                || (next.lastId != selected.lastId && !addsOnly(selected, next))', ''),
            facade, (FOCUSED,),
            {'counter advances only with a pure reservation', 'higher counter only copy refuses header writes',
             'mixed phase change and reservation write refuses'}),
        'foreign-backup-accepted': (
            replace_once(store, 'if (current == null || !(java.util.Arrays.equals(kept, current)\n'
                                '                    || (prior != null && java.util.Arrays.equals(prior, current)))) {',
                         'if (current == null) {'), facade, (FAULTS,),
            {'foreign preferred backup is refused unchanged'}),
        'boot-counter-beside-footprints': (
            replace_once(store, 'return creationReady() && !unselectedFootprint;', 'return creationReady();'),
            facade, (FOCUSED,),
            {'manager repro / reopened PMS issues nothing', 'reopened registry keeps holds and LIVE bindings',
             'single intact main beside a torn reserve counts', 'incompatible copy / backward phase'}),
        'boot-counter-guessed': (
            store, replace_once(facade, '            restored.restoreBindingsWithoutCounter(records, retiring);\n',
                                GUESS), (FOCUSED,),
            {'manager repro / reopened PMS issues nothing', 'reopened registry keeps holds and LIVE bindings',
             'single intact main beside a torn reserve counts'}),
        'compare-app-id-only': (
            replace_once(replace_once(store, 'if (!addition.equals(headerEntry(next, addition.appId))) return false;',
                                      'if (headerEntry(next, addition.appId) == null) return false;'),
                         '&& !entry.equals(additions.get(entry.appId))) return false;',
                         '&& !additions.containsKey(entry.appId)) return false;'), facade, (FOCUSED,),
            {'B not substituted by another creation ID', 'B not substituted by another package'}),
        'ignore-one-surviving-copy': (
            replace_once(store, 'for (Header copy : read.decodedCopies) {\n'
                                '            if (!compatible(selected, copy)) return false;',
                         'for (Header copy : read.decodedCopies.subList(1, read.decodedCopies.size())) {\n'
                         '            if (!compatible(selected, copy)) return false;'), facade, (FOCUSED,),
            {'single intact main beside a torn reserve counts', 'single intact reserve beside a torn main counts',
             'disagreeing copies of one addition refuse', 'additions sharing a creation ID refuse'}),
        'phase-difference-as-addition': (
            replace_once(store, 'if (headerEntry(selected, entry.appId) != null) continue;\n'
                                '                HeaderEntry known',
                         'if (entry.equals(headerEntry(selected, entry.appId))) continue;\n'
                         '                HeaderEntry known'), facade, (FOCUSED,),
            {'interrupted CREATING to LIVE is compatible', 'interrupted LIVE to RELEASING is compatible'}),
    }


def build(work, test, store_text, facade_text, framework=None):
    """The framework sources, guarded fixtures and host facades with one store text. A fault
    build injects the seam into copies of the store and the strict writer fixture."""
    framework = framework or {name: (ROOT / 'owner/platform/framework' / (name + '.java')).read_text()
                              for name in FRAMEWORK}
    faults = test == FAULTS
    work.mkdir(parents=True)
    source = work / 'src'
    source.mkdir()
    files = []
    for name in ('AppIdSettingMap', 'ResilientAtomicFile'):
        text = integration.FIXTURES[integration.PREFIX + name + '.java'].read_text()
        if faults and name == 'ResilientAtomicFile':
            text = inject(text, WRITER_SEAMS)
        (source / (name + '.java')).write_text(text)
        files.append(source / (name + '.java'))
    for name in FRAMEWORK:
        text = store_text if name == 'NativeIdentityStore' else framework[name]
        if faults and name == 'NativeIdentityStore':
            text = inject(text, STORE_SEAMS)
        (source / (name + '.java')).write_text(text)
        files.append(source / (name + '.java'))
    (source / 'Settings.java').write_text(facade_text)
    files.append(source / 'Settings.java')
    stubs = {}
    for directory in ('native_principal_stubs', 'native_principal_xml_stubs'):
        base = ROOT / 'owner/tests/platform' / directory
        for path in sorted(base.rglob('*.java')):
            relative = path.relative_to(base).as_posix()
            if path.name != 'Xml.java' and relative != 'com/android/server/pm/Settings.java':
                if relative in stubs and relative != 'android/util/Log.java':
                    raise ValueError('unreviewed host facade overlap: ' + relative)
                stubs[relative] = path
    files += list(stubs.values())
    tests = ['NativeHeaderTestSupport', test] + (['NativeHeaderWriteFaults'] if faults else [])
    files += [ROOT / 'owner/tests/platform' / (name + '.java') for name in tests]
    classes = work / 'classes'
    classes.mkdir()
    return subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                           '-d', str(classes), *map(str, files)], capture_output=True, text=True, timeout=180)


def execute(work, test, assertions=True):
    state = work / 'state'
    state.mkdir(exist_ok=True)
    return subprocess.run(['java', '-Xmx256m', *(['-ea'] if assertions else []),
                           '-Djava.io.tmpdir=' + str(state), '-cp', str(work / 'classes'),
                           'com.android.server.pm.' + test, str(state)],
                          capture_output=True, text=True, timeout=300)


def failed_checks(stdout):
    return set(re.findall(r'^FAIL (.+?): ', stdout, re.M))


def passed_checks(stdout):
    return re.findall(r'^PASS (.+)$', stdout, re.M)


class NativeHeaderFootprintTests(unittest.TestCase):
    def test_seams_and_boot_agreement(self):
        integration.profile()
        mutations = mutants()
        self.assertEqual(len(mutations), 13)
        for mode, (_, _, tests, expected) in mutations.items():
            names = set(FOCUSED_NAMES if FOCUSED in tests else ()) | set(FAULT_NAMES if FAULTS in tests else ())
            self.assertTrue(expected and expected <= names, mode)
        self.assertEqual((len(set(FOCUSED_NAMES)), len(set(FAULT_NAMES))), (53, 27))
        seen, overlaps = set(), set()
        for directory in ('native_principal_stubs', 'native_principal_xml_stubs'):
            base = ROOT / 'owner/tests/platform' / directory
            for path in base.rglob('*.java'):
                relative = path.relative_to(base).as_posix()
                if relative in seen:
                    overlaps.add(relative)
                seen.add(relative)
        self.assertEqual(overlaps, {'android/util/Log.java'})
        inject(STORE.read_text(), STORE_SEAMS)
        inject(integration.FIXTURES[integration.PREFIX + 'ResilientAtomicFile.java'].read_text(), WRITER_SEAMS)
        for path in [*(ROOT / 'owner/platform/framework').glob('*.java'),
                     integration.FIXTURES[integration.PREFIX + 'ResilientAtomicFile.java']]:
            self.assertNotIn('NativeHeaderWriteFaults', path.read_text(), path.name)
        fragment = integration.FRAGMENTS['restore-capacity'][1].read_bytes()
        self.assertIn(b'} else if (loaded.counterRestorable()) {', fragment)
        # The host facade runs the exact adapted boot fragment, not a parallel rule.
        self.assertEqual(FACADE.read_bytes().count(fragment), 1)
        self.assertIn('+        } else if (loaded.counterRestorable()) {', integration.PATCH.read_text())

    def test_matrix_faults_and_mutants_on_jvm(self):
        self.assertTrue(shutil.which('javac') and shutil.which('java'),
                        'header footprint qualification requires a JDK on PATH')
        integration.profile()
        store, facade = STORE.read_text(), FACADE.read_text()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for test, names in ((FOCUSED, FOCUSED_NAMES), (FAULTS, FAULT_NAMES)):
                work = base / ('controlled-' + test)
                built = build(work, test, store, facade)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                result = execute(work, test)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(passed_checks(result.stdout), list(names))
                self.assertIn('%d passed, 0 failed' % len(names), result.stdout)
                self.assertIn('unqualified', result.stdout)
                refused = execute(work, test, assertions=False)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('-ea', refused.stderr)
            for mode, (store_text, facade_text, tests, expected) in mutants().items():
                failed = set()
                for test in tests:
                    work = base / mode / test
                    built = build(work, test, store_text, facade_text)
                    self.assertEqual(built.returncode, 0, mode + '\n' + built.stdout + built.stderr)
                    result = execute(work, test)
                    failed |= failed_checks(result.stdout)
                    if expected & failed_checks(result.stdout):
                        self.assertNotEqual(result.returncode, 0, mode)
                self.assertTrue(expected <= failed, mode + ' missed ' + str(sorted(expected - failed)))


if __name__ == '__main__':
    unittest.main()
