# SPDX-License-Identifier: Apache-2.0
"""The guest allocator probe's sources: a manifest only ordinary package, built apart from the
observers. Its built APK, signer and hash are sealed by the image step, not here."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

HERE = Path(__file__).parent
ANDROID = '{http://schemas.android.com/apk/res/android}'
MODULE = 'AndrixNativeIdentityAllocationProbe'


class AllocationProbeTests(unittest.TestCase):
    def test_the_manifest_declares_nothing_but_its_package(self):
        root = ET.parse(HERE / 'allocator' / 'AndroidManifest.xml').getroot()
        self.assertEqual(root.get('package'), 'dev.andrix.proof.uidallocation')
        self.assertEqual({key: value for key, value in root.attrib.items() if key != 'package'},
                         {ANDROID + 'versionCode': '1', ANDROID + 'versionName': '1'})
        self.assertEqual([child.tag for child in root], ['uses-sdk', 'application'])
        sdk = root.find('uses-sdk')
        self.assertEqual(sdk.attrib, {ANDROID + 'minSdkVersion': '37', ANDROID + 'targetSdkVersion': '37'})
        application = root.find('application')
        self.assertEqual(list(application), [])
        self.assertEqual({key.replace(ANDROID, ''): value for key, value in application.attrib.items()},
                         {'label': 'Andrix allocator probe', 'hasCode': 'false', 'debuggable': 'false',
                          'allowBackup': 'false', 'testOnly': 'true'})

    def test_its_module_has_no_sources_and_is_built_apart(self):
        text = (HERE / 'Android.bp').read_text()
        modules = re.findall(r'^(\w+) \{\n(.*?)^\}', text, re.M | re.S)
        found = [(kind, body) for kind, body in modules if 'name: "%s"' % MODULE in body]
        self.assertEqual(len(found), 1)
        kind, body = found[0]
        self.assertEqual(kind, 'android_test_helper_app')
        for line in ('manifest: "allocator/AndroidManifest.xml",', 'sdk_version: "current",',
                     'min_sdk_version: "37",', 'target_sdk_version: "37",', 'certificate: "testkey",',
                     'optimize: { enabled: false },', 'dex_preopt: { enabled: false },'):
            self.assertIn(line, body)
        for absent in ('srcs', 'defaults', 'static_libs', 'libs:', 'instrumentation', 'privileged', 'platform'):
            self.assertNotIn(absent, body)
        # No other module names its manifest.
        self.assertEqual(text.count('allocator/AndroidManifest.xml'), 1)


if __name__ == '__main__':
    unittest.main()
