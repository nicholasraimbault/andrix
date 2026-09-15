# SPDX-License-Identifier: Apache-2.0
"""Lab-only source/host-facade checks. Never Android key or caller-identity proof."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
FAULTS = ROOT / 'owner/platform/faults'
TESTS = ROOT / 'owner/tests/platform'


class LifecycleFaultTests(unittest.TestCase):
    def test_gate_and_actual_selected_adapters_under_host_facades(self):
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac)
        self.assertIsNotNone(java)
        facades = sorted((TESTS / 'fault-facades').rglob('*.java'))
        for variant, names in [
                ('enabled', ['LifecycleFaultGateTest', 'LifecycleFaultBinderTest']),
                ('disabled', ['LifecycleNormalBinderTest'])]:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                sources = facades + sorted((FAULTS / variant).rglob('*.java'))
                sources += [TESTS / (name + '.java') for name in names]
                compiled = subprocess.run([javac, '-J-Xmx128m', '--release', '17',
                    '-Xlint:all', '-Werror', '-d', directory, *map(str, sources)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                for name in names:
                    ran = subprocess.run([java, '-Xmx64m', '-ea', '-cp', directory,
                        'dev.andrix.server.' + name], capture_output=True, text=True, timeout=30)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                if variant == 'disabled':
                    binder = Path(directory) / 'dev/andrix/server/OwnerLifecycleBinder.class'
                    data = binder.read_bytes()
                    for forbidden in [b'lock-ce-user0', b'delay-next-snapshot',
                                      b'lockCeStorage', b'LifecycleFaultGate', b'onShellCommand']:
                        self.assertNotIn(forbidden, data)

    def test_real_make_selection_is_explicit_and_debug_product_only(self):
        product = ROOT / 'products/andrix_gos_cf_arm64_only_phone.mk'
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / 'Makefile'
            makefile.write_text('soong_config_set_bool = $(eval CFG_$(2) := $(3))\n'
                'include ' + str(product) + '\nall:\n\t@printf "%s\\n" "$(CFG_owner_fault_tests)"\n')
            base = {'TARGET_PRODUCT': 'andrix_gos_cf_arm64_only_phone',
                'TARGET_BUILD_VARIANT': 'userdebug', 'ANDRIX_OWNER_SESSION': 'true',
                'ANDRIX_OWNER_LIFECYCLE': 'true', 'ANDRIX_OWNER_COMPILER': 'true',
                'ANDRIX_OWNER_KEEP': 'true', 'ANDRIX_OWNER_FAULT_TESTS': 'true'}
            for changes, success, selected in [
                    ({}, True, 'true'), ({'TARGET_BUILD_VARIANT': 'eng'}, True, 'true'),
                    ({'ANDRIX_OWNER_FAULT_TESTS': ''}, True, 'false'),
                    ({'ANDRIX_OWNER_FAULT_TESTS': 'false'}, True, 'false'),
                    ({'TARGET_BUILD_VARIANT': 'user'}, False, None),
                    ({'TARGET_BUILD_VARIANT': ''}, False, None),
                    ({'TARGET_PRODUCT': 'other_product'}, False, None),
                    ({'ANDRIX_OWNER_KEEP': ''}, False, None),
                    ({'ANDRIX_OWNER_LIFECYCLE': ''}, False, None)]:
                args = dict(base, **changes)
                ran = subprocess.run(['make', '--no-print-directory', '-f', str(makefile),
                    *[key + '=' + value for key, value in args.items()]],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(ran.returncode == 0, success, ran.stdout + ran.stderr)
                if success:
                    self.assertEqual(ran.stdout.strip(), selected)

    def test_production_auth_precedes_capture_and_lab_reply_hook(self):
        source = (ROOT / 'owner/platform/java/dev/andrix/server/OwnerLifecycleService.java').read_text()
        method = source[source.index('@Override public PlatformState snapshot()'):source.index('@Override public long keepWork(')]
        self.assertLess(method.index('enforceCoordinator();'), method.index('captureState();'))
        self.assertLess(method.index('captureState();'), method.index('beforeReply(result);'))
        self.assertNotIn('lockCeStorage(', source)
        self.assertNotIn('STORAGE_INTERNAL', source)
        bp = (ROOT / 'owner/platform/Android.bp').read_text()
        self.assertIn('bool_variables: ["owner_fault_tests"]', bp)
        self.assertIn('srcs: ["faults/enabled/**/*.java"]', bp)
        self.assertIn('srcs: ["faults/disabled/**/*.java"]', bp)
        normal = (FAULTS / 'disabled/dev/andrix/server/OwnerLifecycleBinder.java').read_text()
        for forbidden in ['lockCeStorage(', 'onShellCommand(', 'LifecycleFaultGate', 'ShellCommand']:
            self.assertNotIn(forbidden, normal)
        lab = (FAULTS / 'enabled/dev/andrix/server/OwnerLifecycleBinder.java').read_text()
        self.assertIn('Binder.getCallingUid() != android.os.Process.SHELL_UID', lab)
        self.assertIn('!Build.IS_DEBUGGABLE', lab)
        self.assertIn('getNextArg() != null', lab)
        self.assertIn('storage.lockCeStorage(OWNER_USER)', lab)
        self.assertIn('Binder.restoreCallingIdentity(identity)', lab)
        self.assertNotIn('SystemProperties', lab)
        self.assertNotIn('state.fail(', lab)
        # No AIDL fault methods, service-manager or broad permission policy added.
        for p in (ROOT / 'owner/platform/aidl').rglob('*.aidl'):
            self.assertNotIn('lock-ce-user0', p.read_text())
            self.assertNotIn('delay-next-snapshot', p.read_text())


if __name__ == '__main__':
    unittest.main()
