# SPDX-License-Identifier: Apache-2.0
"""Host-only source/input checks, NOT an SDK compile, Binder test or runtime proof."""
from pathlib import Path
import hashlib
import importlib.util
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'src/dev/andrix/proof/webviewqualification'
SPEC = importlib.util.spec_from_file_location('prepare_contract', ROOT / 'prepare_contract.py')
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)
ANDROID = '{http://schemas.android.com/apk/res/android}'

# Synthetic parser inputs, deliberately NOT represented as the upstream AIDL.
NOTICE = ('// Copyright 2026 The Chromium Authors\n'
          '// Use of this source code is governed by a BSD-style license that can be\n'
          '// found in the LICENSE file.\n')


def aidl(body):
    return (NOTICE + 'package example.contract;\ninterface ISafeModeService {\n'
            + body + '\n}\n').encode()


class ImportTests(unittest.TestCase):
    def test_pinned_upstream_contract_and_adapter(self):
        path = ROOT/'aidl/org/chromium/android_webview/common/services/ISafeModeService.aidl'
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         '881975244f5e77d7f3184484b78cd2f4c5cbe2931e69887c2172e16c68c66abc')
        relative, generated = PREPARE.adapter(data)
        self.assertEqual(ROOT/relative, path)
        self.assertEqual((JAVA/'SafeModeContract.java').read_bytes(), generated)

    def test_typed_adapter_follows_exact_spelling_and_aidl_handles_order(self):
        methods = ['void setSafeMode(in List<String> actions);', 'long getStartExample();']
        for order in (methods, list(reversed(methods))):
            source = aidl('\n'.join(order))
            path, java = PREPARE.adapter(source)
            self.assertEqual(str(path), 'aidl/example/contract/ISafeModeService.aidl')
            self.assertIn(b'return service.getStartExample();', java)
            self.assertIn(b'service.setSafeMode(actions);', java)
            self.assertNotIn(b'transact(', java)
            self.assertNotIn(b'reflect', java)

    def test_array_contract_is_typed_not_a_different_wire_contract(self):
        _, java = PREPARE.adapter(aidl('long getTimestampExample();\n'
                                      'void setSafeMode(in String[] actions);'))
        self.assertIn(b'service.setSafeMode(actions.toArray(new String[0]));', java)

    def test_import_preserves_all_bytes_and_refuses_replacement(self):
        source = aidl('long getStartExample(); void setSafeMode(in List<String> actions);')
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            path = PREPARE.prepare(source, root)
            self.assertEqual((root / path).read_bytes(), source)
            PREPARE.prepare(source, root)  # Idempotent, not an implicit upstream advancement.
            with self.assertRaises(ValueError):
                PREPARE.prepare(source + b'// changed\n', root)
            self.assertEqual((root / path).read_bytes(), source)

    def test_unexpected_shape_or_missing_notice_fails_closed(self):
        for body in (
            'int getStartExample(); void setSafeMode(in List<String> actions);',
            'long getStartExample(); oneway void setSafeMode(in List<String> actions);',
            'long getStartExample(); void setSafeMode(in List<String> actions); void other();',
            'long getStartExample(); void setSafeMode(out List<String> actions);',
            'long getStartExample(); void setSafeMode(in int[] actions);',
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                PREPARE.adapter(aidl(body))
        with self.assertRaises(ValueError):
            PREPARE.adapter(aidl('long getStartExample(); void setSafeMode(in List<String> a);')
                            .replace(NOTICE.encode(), b''))


class SourceBoundaryTests(unittest.TestCase):
    def test_manifest_authorities_and_no_permissions(self):
        root = ET.parse(ROOT / 'AndroidManifest.xml').getroot()
        self.assertEqual(root.get('package'), 'dev.andrix.proof.webviewqualification')
        self.assertNotIn(ANDROID + 'sharedUserId', root.attrib)
        self.assertFalse([node for node in root if node.tag.startswith('uses-permission')])
        app = root.find('application')
        self.assertEqual(app.get(ANDROID + 'testOnly'), 'true')
        self.assertEqual(app.find('activity').get(ANDROID + 'exported'), 'false')
        entries = {entry.get(ANDROID + 'name'): entry.get(ANDROID + 'targetPackage')
                   for entry in root.findall('instrumentation')}
        self.assertEqual(entries, {
            '.SelfInstrumentation': 'dev.andrix.proof.webviewqualification',
            '.ProviderInstrumentation': 'dev.andrix.experiment.webview',
        })
        self.assertEqual({node.get(ANDROID + 'name') for node in root.findall('queries/package')},
                         {'dev.andrix.experiment.webview', 'dev.andrix.experiment.webviewconfig'})

    def test_public_sdk_and_no_escalation_or_direct_state_writes(self):
        bp = (ROOT / 'Android.bp').read_text()
        self.assertIn('sdk_version: "current"', bp)
        for prop in ('min_sdk_version', 'target_sdk_version'):
            self.assertIn(f'{prop}: "37"', bp)
        self.assertIn('certificate: ":dev.andrix.usr.certificate"', bp)
        source = '\n'.join(path.read_text() for path in JAVA.glob('*.java'))
        for forbidden in ('runOnMainSync(', 'startActivitySync(', 'UiAutomation',
                          'adoptShellPermissionIdentity', 'getUiAutomation(', 'ProcessBuilder',
                          'Runtime.getRuntime(', 'getSharedPreferences(', 'openFileOutput(',
                          'setComponentEnabledSetting(', 'cancelAll(', 'scheduleJob(',
                          'createPackageContext(', 'loadUrl(', 'loadData', '.invoke(',
                          'getDeclaredMethod(', 'grantRuntimePermission('):
            self.assertNotIn(forbidden, source)
        self.assertIn('TIMEOUT_SECONDS = 180', source)
        self.assertIn('future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)', source)
        self.assertIn('Activity.RESULT_CANCELED : Activity.RESULT_OK', source)

    def test_fixed_pin_and_job_guard_shapes(self):
        pins = (JAVA / 'Pins.java').read_text()
        self.assertIn('1a2dcd3b0af00bbb4c52ba215245dfc7c86011b8a4b2318d445d5db2ad7cf755', pins)
        self.assertIn('6c292164d3710a4fd44b91d90fd3a2c894fe4c6945dd41f52493ffb19389b5b3', pins)
        self.assertIn('Build.VERSION.SDK_INT == 37', pins)
        self.assertIn('Process.myUid() == expectedUid', pins)
        jobs = (JAVA / 'Jobs.java').read_text()
        self.assertIn('static final int ID = 83;', jobs)
        self.assertIn('.setMinimumLatency(ONE_DAY_MS)', jobs)
        self.assertIn('.setPersisted(true)', jobs)
        self.assertIn('.setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)', jobs)
        cancellation = jobs[jobs.index('void cancelMarkedIfPresent'):jobs.index('void rollback()')]
        self.assertLess(cancellation.index('requireOwned(pending)'), cancellation.index('scheduler.cancel(ID)'))

    def test_guard_precedes_modes_and_denial_catches_only_the_setter(self):
        runner = (JAVA / 'QualificationInstrumentation.java').read_text()
        self.assertLess(runner.index('s.step("guard"'), runner.index('operations.open()'))
        self.assertLess(runner.index('s.step("guard"'), runner.index('startActivity('))
        connection = (JAVA / 'SafeModeConnection.java').read_text()
        denial = connection[connection.index('void requireSetterDenied()'):connection.index('void close()')]
        protected = denial[denial.index('try {') + len('try {'):denial.index('} catch (SecurityException')]
        self.assertEqual(protected.split('//')[0].strip(), 'contract.setActions(actions);')
        operations = (JAVA / 'ModeOperations.java').read_text()
        negative = operations[operations.index('private void differentUid()'):operations.index('void cleanup()')]
        self.assertLess(negative.index('safe.read("different_uid_control")'),
                        negative.index('safe.requireSetterDenied()'))
        self.assertNotIn('new Jobs', negative)

    def test_reflection_is_read_only_and_narrow(self):
        config = (JAVA / 'ConfigCheck.java').read_text()
        for cls in ('WV.xr', 'WV.op1', 'WV.mp1'):
            self.assertIn(f'ownClass(loader, "{cls}")', config)
        for forbidden in ('.set(null', '.setByte(', '.setLong(', '.invoke(', 'newInstance('):
            self.assertNotIn(forbidden, config)
        self.assertIn('pm.hasSigningCertificate(Pins.CONFIG, expectedPin,', config)
        self.assertIn('futureField.get(null) == null && parsedField.get(null) == null', config)
        self.assertIn('version >= 0 && version == s.args.configVersion', config)


if __name__ == '__main__':
    unittest.main()
