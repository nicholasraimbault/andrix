# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class KeepTests(unittest.TestCase):
    def test_platform_state_orchestration_and_notice_deadline(self):
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac)
        self.assertIsNotNone(java)
        main = ROOT / 'owner/platform/java/dev/andrix/server'
        tests = ROOT / 'owner/tests/platform'
        with tempfile.TemporaryDirectory() as directory:
            sources = [main / (name + '.java') for name in
                       ['OwnerLifecycleState', 'KeepWorkState', 'KeepWork', 'KeepNoticeWait']]
            sources += [tests / (name + '.java') for name in
                        ['KeepWorkStateTest', 'KeepWorkTest', 'KeepNoticeWaitTest']]
            compiled = subprocess.run([javac, '--release', '17', '-Xlint:all', '-Werror',
                '-d', directory, *map(str, sources)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for name in ['KeepWorkStateTest', 'KeepWorkTest', 'KeepNoticeWaitTest']:
                ran = subprocess.run([java, '-ea', '-cp', directory, 'dev.andrix.server.' + name],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                self.assertIn('Android unqualified', ran.stdout)

    def test_actual_controller_registration_cookie_ownership(self):
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler)
        source = (ROOT / 'owner/native/andrixd.cpp').read_text()
        constructor = source[source.index('  OwnerSession() :'):source.index('  bool start_lifecycle()')]
        registration = source[source.index('  ScopedAStatus registerController('):source.index('  ScopedAStatus attach(')]
        death = source[source.index('  void clear_controller_locked() {'):source.index('  void revoke_locked() {')]
        harness = (ROOT / 'owner/tests/controller_lifetime_test.cpp.in').read_text()
        for marker, body in [('CONSTRUCTOR', constructor), ('REGISTRATION', registration), ('DEATH_METHODS', death)]:
            self.assertEqual(harness.count('// ' + marker), 1)
            harness = harness.replace('// ' + marker, body)
        with tempfile.TemporaryDirectory() as directory:
            cpp = Path(directory) / 'cookies.cpp'
            cpp.write_text(harness)
            binary = Path(directory) / 'cookies'
            # Sanitizer compilation can exceed a minute under a shared CPU quota.
            # This budget does not change the test's runtime or lifecycle deadlines.
            compiled = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                '-I' + str(ROOT / 'owner/native'), str(ROOT / 'owner/native/session_core.cpp'),
                str(cpp), '-o', str(binary)], capture_output=True, text=True, timeout=180)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('onUnlinked lifetime', ran.stdout)

    def test_notification_channel_owner_control_contract(self):
        source = (ROOT / 'owner/platform/java/dev/andrix/server/KeepNotifications.java').read_text()
        self.assertLess(source.index('channel.setBlockable(true)'),
                        source.index('manager.createNotificationChannel(channel)'))
        self.assertIn('NotificationManager.IMPORTANCE_LOW', source)
        self.assertIn('Notification.VISIBILITY_PUBLIC', source)
        self.assertIn('.setAuthenticationRequired(false)', source)
        self.assertIn('if (!allowed()) keep.notificationRevoked();', source)
        self.assertNotIn('setLockscreenVisibility', source)
        # Source contract only. The Android channel/UI/broadcast path requires the
        # separately recorded active-block, denied-new-Keep and re-enable controls.

    def test_creation_plain_preservation_and_new_presentation_contract(self):
        native = (ROOT / 'owner/native/andrixd.cpp').read_text()
        start = native[native.index('  ScopedAStatus startKept('):native.index('  ScopedAStatus stopKeptWork()')]
        self.assertIn('#ifndef ANDRIX_OWNER_KEEP', start)
        self.assertIn('home_ >= 0 || terminal_.has_process()', start)
        self.assertLess(start.index('guard.unlock()'), start.index('platform_.retain('))
        self.assertLess(start.index('platform_.retain('), start.index('guard.lock()'))
        self.assertIn('controller_generation_ != controller_generation', start)
        self.assertLess(native.index('++session_id_'), native.index('output_.clear_for_new_presentation()'))
        self.assertIn('!fresh_presentation &&', native)
        self.assertIn('master_.reset();', native)
        # The compatibility command deliberately selects both axes. Presentation
        # retirement/launch must not infer its role from a Keep permission bit.
        self.assertIn('terminal_.select_role(TerminalProcessRole::PresentationClient)', start)
        revoke = native[native.index('  void revoke_locked() {'):native.index('  void revoke_stream_locked() {')]
        launch = native[native.index('  bool start_terminal_locked('):native.index('  void transfer_locked() {')]
        self.assertNotIn('kept_', revoke + launch)
        self.assertIn('terminal_.replaceable()', revoke)
        self.assertIn('terminal_.ever_started()', launch)
        aidl = (ROOT / 'owner/aidl/dev/andrix/session/IOwnerSession.aidl').read_text()
        self.assertLess(aidl.index('String status();'), aidl.index('Attachment startKept'))
        stop = (ROOT / 'owner/platform/java/dev/andrix/server/KeepWork.java').read_text()
        self.assertIn('record.lifetime.stop(record.workId, record.registration)', stop)
        self.assertNotIn('SystemProperties', stop)
        product = (ROOT / 'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertIn('ANDRIX_OWNER_KEEP requires ANDRIX_OWNER_LIFECYCLE=true', product)
        self.assertIn('ANDRIX_OWNER_KEEP requires the pinned ANDRIX_OWNER_COMPILER=true', product)
        self.assertIn('KEEP = false', (ROOT / 'owner/terminal/features/keep-disabled/ConsoleFeatures.java').read_text())
        self.assertIn('ENABLED = false', (ROOT / 'owner/platform/config/disabled/dev/andrix/server/KeepBuild.java').read_text())


if __name__ == '__main__':
    unittest.main()
