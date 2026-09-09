# SPDX-License-Identifier: Apache-2.0
"""Source-only permission regressions; no Android/prompt, network, keys or ADB."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

PROBE = Path(__file__).resolve().parents[1]
JAVA = PROBE / 'src/dev/andrix/proof/webview'
ACTIVITY = (JAVA / 'ProbeActivity.java').read_text()
RUNNER = (JAVA / 'WebViewProbeInstrumentation.java').read_text()
SESSION = (JAVA / 'ProbeSession.java').read_text()
PROFILE = (JAVA / 'ProbePlatformProfile.java').read_text()


def section(source, start, end):
    first = source.index(start)
    return source[first:source.index(end, first + len(start))]


def compact(source):
    return re.sub(r'\s+', '', source)


REQUEST = section(ACTIVITY, 'private void requestLocalNetworkPermission()',
                  'public void onRequestPermissionsResult(')
CALLBACK = section(ACTIVITY, 'public void onRequestPermissionsResult(',
                   'private void recordFinalPermission()')
FINAL = section(ACTIVITY, 'private void recordFinalPermission()', 'private void recordProvider(')


class PermissionContractTests(unittest.TestCase):
    def assertOrdered(self, source, *tokens):
        cursor = 0
        for token in tokens:
            self.assertIn(token, source[cursor:])
            cursor = source.index(token, cursor) + len(token)

    def test_manifest_has_exactly_two_unrestricted_public_permissions(self):
        root = ET.parse(PROBE / 'AndroidManifest.xml').getroot()
        nodes = [node for node in root if node.tag.startswith('uses-permission')]
        name = '{http://schemas.android.com/apk/res/android}name'
        self.assertCountEqual([node.attrib[name] for node in nodes],
                              ['android.permission.INTERNET',
                               'android.permission.ACCESS_LOCAL_NETWORK'])
        for node in nodes:
            self.assertEqual(node.tag, 'uses-permission')
            self.assertEqual(set(node.attrib), {name})

    def test_runner_permission_set_is_exact_and_order_independent(self):
        runner = compact(RUNNER)
        self.assertIn('arguments.getString("platform_profile",ProbePlatformProfile.AOSP)', runner)
        self.assertOrdered(runner,
                           'platform.validate(Build.FINGERPRINT,Build.PRODUCT,Build.VERSION.SDK_INT,info.requestedPermissions);',
                           'activeSession=session;', 'session.post("local_network_permission",')
        self.assertIn('permissions!=null&&permissions.length==expected.length', compact(PROFILE))
        self.assertIn('Arrays.equals(expected,observed)', compact(PROFILE))
        self.assertIn('String[]observed=permissions.clone();', compact(PROFILE))
        self.assertIn('"implicit_sensor_grant_measured", false', RUNNER)
        self.assertNotIn('requestedPermissions[', RUNNER)

    def test_permission_is_first_stage_and_only_callback_initializes_webview(self):
        creation = section(ACTIVITY, 'protected void onCreate(', 'private boolean active()')
        self.assertIn('private static final String PERMISSION = "local_network_permission";', ACTIVITY)
        self.assertIn('private String phase = PERMISSION;', ACTIVITY)
        self.assertIn('guarded(this::requestLocalNetworkPermission);', creation)
        self.assertNotIn('initialize', creation)
        self.assertEqual(ACTIVITY.count('initialize();'), 1)
        self.assertIn('initialize();', CALLBACK)
        self.assertIn('session.post("local_network_permission",', RUNNER)
        stages = re.search(r'for \(String stage : new String\[\] \{([^}]+)\}', RUNNER).group(1)
        self.assertEqual(re.findall(r'"([a-z_]+)"', stages),
                         ['local_network_permission', 'initialization', 'safe_browsing',
                          'javascript_fetch', 'wrong_host_tls'])
        initialization = section(ACTIVITY, 'private void initialize()', 'private void pollJavaScript()')
        self.assertOrdered(compact(initialization),
                           'require("initialization".equals(phase)&&permissionRequested',
                           'checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK)',
                           '==PackageManager.PERMISSION_GRANTED',
                           'recordProvider("before_initialization");', 'newWebView(this)')

    def test_request_uses_only_normal_activity_api_after_initial_denial(self):
        self.assertOrdered(compact(REQUEST),
                           'initialPermissionState=checkSelfPermission('
                           'Manifest.permission.ACCESS_LOCAL_NETWORK);',
                           '"point","initial"',
                           'require(initialPermissionState==PackageManager.PERMISSION_DENIED,',
                           'permissionRequested=true;', '"point","request"',
                           'requestPermissions(newString[]{Manifest.permission.ACCESS_LOCAL_NETWORK},'
                           'LOCAL_NETWORK_REQUEST);')
        self.assertEqual(ACTIVITY.count('requestPermissions('), 1)
        self.assertIn('"initial_state", initialPermissionState, "requested", false', REQUEST)
        self.assertIn('"initial_state", initialPermissionState, "requested", true', REQUEST)

    def test_callback_requires_exact_explicit_grant_before_completion(self):
        self.assertOrdered(compact(CALLBACK),
                           'finalState=checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK);',
                           'booleanexpected=active()&&PERMISSION.equals(phase)'
                           '&&permissionRequested&&!permissionCallbackReceived;',
                           'permissionCallbackReceived=true;', '"point","callback"',
                           'require(expected,', 'require(requestCode==LOCAL_NETWORK_REQUEST,',
                           'require(permissions!=null&&permissions.length==1'
                           '&&Manifest.permission.ACCESS_LOCAL_NETWORK.equals(permissions[0]),',
                           'require(grantResults!=null&&grantResults.length==1'
                           '&&grantResults[0]==PackageManager.PERMISSION_GRANTED,',
                           'require(finalState==PackageManager.PERMISSION_GRANTED,',
                           'session.complete(PERMISSION);', 'phase="initialization";',
                           'if(active()){initialize();}')
        self.assertIn('catch (Throwable error)', CALLBACK)
        self.assertIn('session.fail(phase, error);', CALLBACK)
        self.assertIn('permissions == null ? null : new JSONArray(permissions)', CALLBACK)
        self.assertIn('grantResults == null ? null : new JSONArray(grantResults)', CALLBACK)

    def test_evidence_and_cleanup_keep_permission_wait_bounded(self):
        for source in (CALLBACK, FINAL):
            for field in ('initial_state', 'final_state', 'requested', 'callback_received'):
                self.assertIn('"' + field + '"', source)
        self.assertIn('"point", "final"', FINAL)
        self.assertIn('checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK)', FINAL)
        self.assertIn('require(session.failed.get()||(permissionRequested&&permissionCallbackReceived'
                      '&&finalState==PackageManager.PERMISSION_GRANTED),', compact(FINAL))
        destruction = ACTIVITY[ACTIVITY.index('protected void onDestroy()'):]
        self.assertOrdered(destruction, 'releaseWebView();', 'cleanupCall(this::recordFinalPermission);',
                           'session.record("cleanup",', 'session.cleaned.countDown();')
        self.assertIn('STAGE_TIMEOUT_SECONDS = 180;', SESSION)
        self.assertIn('stages.poll(STAGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)', SESSION)
        self.assertIn('session.post("cleanup", session::close);', RUNNER)
        self.assertIn('session.cleaned.await(ProbeSession.STAGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)', RUNNER)

    def test_no_permission_or_network_shortcut_in_java(self):
        sources = '\n'.join(path.read_text() for path in JAVA.glob('*.java'))
        for forbidden in ('UiAutomation', 'adoptShellPermissionIdentity', 'grantRuntimePermission',
                          'executeShellCommand', 'pm grant', 'ProcessBuilder', 'disable-features',
                          'setAllowFileAccess(true)', 'handler.proceed('):
            self.assertNotIn(forbidden, sources)


if __name__ == '__main__':
    unittest.main()
