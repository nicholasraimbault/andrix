# SPDX-License-Identifier: Apache-2.0
"""Real portable owner-core compilation/execution, not Android service proof."""
from pathlib import Path
import configparser
import shutil
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class OwnerSessionTests(unittest.TestCase):
    def test_opt_in_product_and_board_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            upstream = work/'device/google/cuttlefish/vsoc_arm64_only/BoardConfig.mk'
            upstream.parent.mkdir(parents=True)
            upstream.write_text('TARGET_FS_CONFIG_GEN := upstream-marker\n')
            makefile = work/'Makefile'
            makefile.write_text('include '+str(ROOT/'board/andrix_cf_arm64_only/BoardConfig.mk')+
                                '\nall:\n\t@echo $(TARGET_FS_CONFIG_GEN)\n'
                                '\t@echo $(SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS)\n'
                                '\t@echo $(BOARD_SEPOLICY_M4DEFS)\n')
            for product in ['andrix_gos_cf_arm64_only_phone', 'andrix_cf_arm64_only_phone', 'other']:
                for opt in ['', 'false', 'true']:
                    result = subprocess.run(['make', '--no-print-directory', '-f', str(makefile),
                                             'TARGET_PRODUCT='+product, 'ANDRIX_OWNER_SESSION='+opt],
                                            cwd=work, text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = product == 'andrix_gos_cf_arm64_only_phone' and opt == 'true'
                    self.assertIn('upstream-marker', result.stdout)
                    self.assertEqual('vendor/andrix/owner/config.fs' in result.stdout, expected)
                    self.assertEqual('vendor/andrix/owner/sepolicy' in result.stdout, expected)
                    self.assertEqual('andrix_owner_session=true' in result.stdout, expected)
            makefile.write_text('include '+str(ROOT/'products/andrix_gos_cf_arm64_only_phone.mk')+
                                '\nall:\n\t@echo $(PRODUCT_PACKAGES)\n')
            for opt in ['', 'false', 'true']:
                result = subprocess.run(['make', '--no-print-directory', '-f', str(makefile),
                                         'TARGET_PRODUCT=andrix_gos_cf_arm64_only_phone',
                                         'ANDRIX_OWNER_SESSION='+opt], cwd=work,
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.split(),
                    ['andrixd', 'andrix-session-runner', 'AndrixTerminal'] if opt == 'true' else [])

    def test_explicit_identity_and_scoped_signer_mapping(self):
        cfg = configparser.ConfigParser()
        cfg.read(ROOT/'owner/config.fs')
        self.assertEqual(cfg.sections(), ['AID_SYSTEM_EXT_ANDRIX'])
        self.assertEqual(cfg.getint('AID_SYSTEM_EXT_ANDRIX', 'value'), 7500)
        policy = ET.parse(ROOT/'owner/sepolicy/mac_permissions.xml').getroot()
        signers = policy.findall('signer')
        self.assertEqual(len(signers), 1)
        self.assertEqual(signers[0].attrib, {'signature': '@ANDRIX_OWNER_CONSOLE'})
        self.assertIsNone(signers[0].find('seinfo'))  # no blanket same-cert domain
        packages = signers[0].findall('package')
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].get('name'), 'dev.andrix.terminal')
        self.assertEqual(packages[0].find('seinfo').get('value'), 'andrix_terminal')
        frontend_policy = (ROOT/'owner/sepolicy/andrix_terminal.te').read_text()
        self.assertIn('allow andrix_terminal app_api_service:service_manager find;', frontend_policy)
        self.assertNotIn('system_api_service:service_manager find', frontend_policy)
        seapp = (ROOT/'owner/sepolicy/seapp_contexts').read_text()
        self.assertIn('isPrivApp=true name=dev.andrix.terminal ', seapp)
        self.assertNotIn('*', seapp)
        manifest = ET.parse(ROOT/'owner/terminal/AndroidManifest.xml').getroot()
        self.assertIsNone(manifest.find('uses-permission'))
        self.assertNotIn('{http://schemas.android.com/apk/res/android}sharedUserId', manifest.attrib)

    def test_init_has_fixed_bounds_and_no_root_or_de_home(self):
        text = (ROOT/'owner/andrixd.rc').read_text()
        self.assertIn('on property:sys.user.0.ce_available=true', text)
        self.assertIn('mkdir /data/misc_ce/0/andrix 0700 system_ext_andrix system_ext_andrix', text)
        self.assertNotIn('mkdir /data/misc_ce/0 ', text)
        self.assertNotIn('/data/misc_de', text)
        self.assertNotIn('user root', text)
        self.assertNotIn('group system', text.replace('group system_ext_andrix', 'group owner'))
        self.assertIn('capabilities\n', text)
        self.assertIn('oom_score_adjust 700', text)
        self.assertIn('rlimit nproc 32 32', text)
        self.assertIn('rlimit nofile 128 128', text)
        self.assertIn('memory.max 268435456', text)
        self.assertIn('memory.swap.max 0', text)
        self.assertNotIn('ro.config.per_app_memcg', text)
        daemon = (ROOT/'owner/native/andrixd.cpp').read_text()
        self.assertLess(daemon.index('check_resource_bounds()'), daemon.index('AServiceManager_addService'))
        self.assertIn('AIBinder_setRequestingSid(binder.get(), true)', daemon)
        self.assertIn('authorized_console(AIBinder_getCallingUid(), sid)', daemon)
        self.assertNotIn('kill(-1', daemon)
        policy = (ROOT/'owner/sepolicy/andrix_owner.te').read_text()
        self.assertIn('allow andrix_owner cgroup_v2:dir { search getattr };', policy)
        self.assertIn('neverallow andrix_owner { cgroup cgroup_v2 }:file { write append };', policy)

    def test_negative_is_optional_same_signer_not_same_identity(self):
        manifest = ET.parse(ROOT/'tests/owner-negative/AndroidManifest.xml').getroot()
        self.assertEqual(manifest.get('package'), 'dev.andrix.proof.ownernegative')
        self.assertIsNone(manifest.find('uses-permission'))
        self.assertNotIn('{http://schemas.android.com/apk/res/android}sharedUserId', manifest.attrib)
        bp = (ROOT/'tests/owner-negative/Android.bp').read_text()
        self.assertIn('certificate: ":dev.andrix.usr.certificate"', bp)
        self.assertIn('installable: false', bp)
        self.assertNotIn('AndrixOwnerNegative', (ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text())
        source = (ROOT/'tests/owner-negative/src/dev/andrix/proof/ownernegative/OwnerNegative.java').read_text()
        self.assertIn('NEGATIVES_OBSERVED_REQUIRE_POSITIVE_CONTROL', source)
        self.assertNotIn('adoptShellPermissionIdentity', source)

    def test_actual_pump_methods_with_host_pty_and_revocable_streams(self):
        source = (ROOT/'owner/native/andrixd.cpp').read_text()
        death_start = source.index('  void controller_died() {')
        start = source.index('  void revoke_locked() {')
        death = source[death_start:start]
        revoke = source[start:source.index('  bool start_shell_locked(', start)]
        start = source.index('  void transfer_locked() {')
        pump = source[start:source.index('  std::mutex mutex_;', start)]
        self.assertEqual(revoke.count('void revoke_locked'), 1)
        self.assertEqual(pump.count('void transfer_locked'), 1)
        harness = (ROOT/'owner/tests/transport_harness.cpp.in').read_text()
        self.assertEqual(harness.count('// PRODUCTION_METHODS'), 1)
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            cpp = work/'pump.cpp'
            cpp.write_text(harness.replace('// PRODUCTION_METHODS', death + revoke + pump))
            binary = work/'pump'
            compiled = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                                       '-O2', '-I'+str(ROOT/'owner/native'),
                                       str(ROOT/'owner/native/session_core.cpp'),
                                       str(ROOT/'owner/native/terminal_protocol.cpp'), str(cpp), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Android unqualified', ran.stdout)

    def test_worker_filter_real_host_syscalls_and_exec_inheritance(self):
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'filter-test'
            compiled = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                                       '-O2', '-I'+str(ROOT/'owner/native'),
                                       str(ROOT/'owner/native/worker_filter.cpp'),
                                       str(ROOT/'owner/tests/worker_filter_test.cpp'), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Android unqualified', ran.stdout)
        policy = (ROOT/'owner/sepolicy/andrix_owner.te').read_text()
        bridge = (ROOT/'scripts/proof/owner_policy.py').read_text()
        self.assertNotIn('app_domain(andrix_owner)', bridge + policy)
        self.assertNotIn('untrusted_app_domain(andrix_owner)', bridge + policy)
        self.assertIn('data_file_type -andrix_home_file', bridge)
        self.assertNotIn('type andrix_owner, domain', policy)
        runner = (ROOT/'owner/native/runner.cpp').read_text()
        self.assertLess(runner.index('install_worker_filter()'), runner.index('execve('))
        self.assertNotIn('install_worker_filter', (ROOT/'owner/native/andrixd.cpp').read_text())

    def test_ce_key_authority_and_controller_lifetime_are_not_faked(self):
        guards = (ROOT/'owner/native/guards.cpp').read_text()
        self.assertIn('FS_IOC_GET_ENCRYPTION_POLICY_EX', guards)
        self.assertNotIn('FS_IOC_GET_ENCRYPTION_KEY_STATUS', guards)
        daemon = (ROOT/'owner/native/andrixd.cpp').read_text()
        self.assertIn('AIBinder_linkToDeath(lifetime.get(), death_, this)', daemon)
        self.assertIn('controller_pid_ == AIBinder_getCallingPid()', daemon)
        self.assertIn('void controller_died()', daemon)
        activity = (ROOT/'owner/terminal/src/dev/andrix/terminal/ConsoleActivity.java').read_text()
        controller = (ROOT/'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        self.assertIn('static final Binder PROCESS_LIFETIME = new Binder()', controller)
        self.assertLess(controller.index('registerController(PROCESS_LIFETIME)'), controller.index('service.attach('))
        self.assertIn('uiEpoch != requestEpoch', controller)
        self.assertIn('cursor.accept(frame, session::applyOutput)', controller)
        self.assertIn('acknowledgeOutput(current.generation, ack[0])', controller)
        self.assertIn('new ArrayBlockingQueue<>(1)', controller)
        self.assertNotIn('InputStreamReader', controller.replace('// fragment independently or retain an InputStreamReader across sockets.', ''))
        self.assertNotIn('getIntent().get', activity + controller)
        self.assertNotIn('shutdownNow()', activity)

    def test_terminal_ui_focus_and_accessibility_keep_foreground_guards(self):
        activity = (ROOT/'owner/terminal/src/dev/andrix/terminal/ConsoleActivity.java').read_text()
        controller = (ROOT/'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        self.assertIn('if (inputAllowed && !previouslyEnabled) terminal.requestFocus()', activity)
        self.assertIn('showInputMethodPicker()', activity)
        self.assertIn('InputMethodManager.SHOW_IMPLICIT', activity)
        self.assertNotIn('SHOW_FORCED', activity)
        self.assertNotIn('Settings.Secure.put', activity)
        self.assertIn('controller.canReadScreen(ConsoleActivity.this)', activity)
        self.assertIn('return listener == target && eligible()', controller)
        self.assertIn('TerminalViewportText.capture', activity)
        self.assertIn('event.getText().clear()', activity)
        self.assertIn('cancelAccessibilityUpdate()', activity)
        self.assertNotIn('announceForAccessibility', activity)
        self.assertIn('v4_signature: false', (ROOT/'owner/Android.bp').read_text())

    def test_bounded_non_input_attachment_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            compiled = subprocess.run(['javac', '-d', tmp,
                str(ROOT/'owner/terminal/protocol/AttachTrace.java'),
                str(ROOT/'owner/tests/AttachTraceTest.java')], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run(['java', '-ea', '-cp', tmp, 'AttachTraceTest'],
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('no Android timing claim', ran.stdout)
        controller = (ROOT/'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        self.assertIn('if (!Build.IS_DEBUGGABLE) return;', controller)
        self.assertIn('SystemClock::elapsedRealtime', controller)
        self.assertIn('"attachment is no longer active".equals(message)', controller)
        self.assertNotIn('Log.i("AndrixAttach", error', controller)

    def test_actual_attach_failure_callback_ignores_stale_ui(self):
        controller = (ROOT/'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        start = controller.index('    private void failAttach(')
        method = controller[start:controller.index('    private void finishAttach(', start)]
        harness = (ROOT/'owner/tests/AttachFailureTest.java.in').read_text()
        self.assertEqual(harness.count('// PRODUCTION_FAILURE_CALLBACK'), 1)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source = work/'AttachFailureTest.java'
            source.write_text(harness.replace('// PRODUCTION_FAILURE_CALLBACK', method))
            compiled = subprocess.run(['javac', '-d', str(work), str(source)],
                                      text=True, capture_output=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run(['java', '-ea', '-cp', str(work), 'AttachFailureTest'],
                                 text=True, capture_output=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Android unqualified', ran.stdout)
        attach = controller[controller.index('    void attach()'):start]
        self.assertLess(attach.index('disconnect(connection)'), attach.index('show("Attaching'))
        self.assertLess(attach.index('show("Attaching'), attach.index('control.execute('))
        self.assertIn('main.post(() -> failAttach(requestEpoch, target, error.getMessage()))', attach)

    def test_native_core_and_host_guard_negatives(self):
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler, 'a host C++ compiler is required')
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'session-core-test'
            result = subprocess.run([
                compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror', '-O2',
                '-I'+str(ROOT/'owner/native'),
                str(ROOT/'owner/native/session_core.cpp'),
                str(ROOT/'owner/native/guards.cpp'),
                str(ROOT/'owner/tests/session_core_test.cpp'), '-o', str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Android runtime unqualified', result.stdout)
