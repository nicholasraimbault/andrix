# SPDX-License-Identifier: Apache-2.0
"""Pinned app-input regressions, not Android execution or a privacy verdict."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
PATCHES = ROOT/'patches/android-17.0.0_r1'
ANDROID = '{http://schemas.android.com/apk/res/android}'


class AppEndpointInputsTests(unittest.TestCase):
    def test_wallpaper_removes_only_google_link_filter_not_picker_or_verifier(self):
        series = json.loads((PATCHES/'series.json').read_text())
        project = next(p for p in series['projects'] if p['path']=='packages/apps/WallpaperPicker2')
        row = project['files'][0]
        before = (Path(__file__).parent/'fixtures/aosp17-wallpaper-manifest.xml').read_bytes()
        self.assertEqual(hashlib.sha256(before).hexdigest(), row['base_sha256'])
        name = project['path']+'/'+row['path']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/name
            path.parent.mkdir(parents=True)
            path.write_bytes(before)
            subprocess.run(['git','apply','--check','--whitespace=error','--include='+name,
                            str(PATCHES/series['patch'])],cwd=directory,check=True,capture_output=True)
            subprocess.run(['git','apply','--whitespace=error','--include='+name,
                            str(PATCHES/series['patch'])],cwd=directory,check=True,capture_output=True)
            after = path.read_bytes()
        self.assertEqual(hashlib.sha256(after).hexdigest(), row['patched_sha256'])
        old, new = ET.fromstring(before), ET.fromstring(after)
        removed = 0
        for component in old.find('application'):
            for intent in list(component.findall('intent-filter')):
                if any(data.get(ANDROID+'host')=='g.co' for data in intent.findall('data')):
                    self.assertEqual(intent.get(ANDROID+'autoVerify'), 'true')
                    component.remove(intent)
                    removed += 1
        self.assertEqual(removed, 1)
        # Ignore XML text indentation, not structure/attributes of any component.
        def tree(node):
            return node.tag, node.attrib, [tree(child) for child in node]
        self.assertEqual(tree(old), tree(new))

    def test_other_app_changes_are_only_endpoint_or_existing_geo_helper_selection(self):
        text = (PATCHES/'network-endpoints.patch').read_text()
        expected = {
            'packages/apps/Settings/src/com/android/settings/development/DSULoader.java': (
                '"https://dl.google.com/developers/android/gsi/gsi-src.json";',
                '"https://probe.andrix.org/system-images/catalog.json";'),
            'external/android-key-attestation/server/src/main/java/com/google/android/attestation/CertificateRevocationStatus.java': (
                'private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";',
                'private static final String STATUS_URL = "https://probe.andrix.org/security/attestation-status.json";'),
            'packages/apps/Contacts/src/com/android/contacts/util/StructuredPostalUtils.java': (
                'return Uri.parse("https://maps.google.com/maps?daddr=" + Uri.encode(postalAddress));',
                'return getPostalAddressUri(postalAddress);'),
        }
        for name, (before, after) in expected.items():
            with self.subTest(name=name):
                prefix = 'diff --git a/'+name+' b/'+name+'\n'
                self.assertEqual(text.count(prefix), 1)
                section = text.split(prefix, 1)[1].split('\ndiff --git ',1)[0]
                removed = [line[1:].strip() for line in section.splitlines()
                           if line.startswith('-') and not line.startswith('---') and line[1:].strip()]
                added = [line[1:].strip() for line in section.splitlines()
                         if line.startswith('+') and not line.startswith('+++') and line[1:].strip()]
                self.assertEqual(removed, [before])
                self.assertEqual(added, [after])


if __name__ == '__main__':
    unittest.main()
