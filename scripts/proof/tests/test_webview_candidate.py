# SPDX-License-Identifier: Apache-2.0
"""Host-only candidate input checks; no APK/device/provider qualification."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
EXPERIMENT = ROOT / 'experiments/webview'
OVERLAY = ROOT / 'overlays/cuttlefish/AndrixCuttlefishWebViewOverlay'
MODULES = {'AndrixExperimentalWebView', 'AndrixExperimentalTrichromeLibrary',
           'AndrixExperimentalWebViewConfig', 'AndrixCuttlefishWebViewOverlay'}


class WebViewCandidateInputsTests(unittest.TestCase):
    def test_provider_resource_binds_the_experimental_certificate(self):
        candidate = json.loads((EXPERIMENT/'candidate.json').read_text())
        root = ET.parse(OVERLAY/'res/xml/config_webview_packages.xml').getroot()
        self.assertEqual(root.tag, 'webviewproviders')
        self.assertEqual(len(root), 1)
        provider = root[0]
        self.assertEqual(provider.tag, 'webviewprovider')
        self.assertEqual(provider.attrib, {
            'description': 'Andrix experimental WebView',
            'packageName': 'dev.andrix.experiment.webview', 'availableByDefault': 'true'})
        self.assertEqual([p.tag for p in provider], ['signature'])
        der = base64.b64decode(provider[0].text, validate=True)
        self.assertEqual(hashlib.sha256(der).hexdigest(), candidate['signer_der_sha256'])
        self.assertEqual({p['name'] for p in candidate['apks']},
                         {'TrichromeWebView64.apk', 'TrichromeLibrary64.apk', 'VanadiumConfig.apk'})
        for item in candidate['apks']:
            self.assertRegex(item['sha256'], r'^[0-9a-f]{64}$')
            self.assertGreater(item['size'], 0)

    def test_exact_opt_in_controls_product_membership(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory)/'check.mk'
            file.write_text('define inherit-product\nendef\n'
                            'define soong_config_set\n$(eval CONF := $(3))\nendef\n'
                            'include '+str(ROOT/'products/andrix_cf_arm64_only_phone.mk')+'\n'
                            '$(info PACKAGES=$(strip $(PRODUCT_PACKAGES)))\n'
                            '$(info CONF=$(CONF))\n.PHONY: check\ncheck:\n\t@:\n')
            for value in ['', 'false', 'true', 'TRUE', '1']:
                with self.subTest(value=value):
                    output = subprocess.check_output(['make', '--no-print-directory', '-f', str(file),
                        'ANDRIX_WEBVIEW_EXPERIMENT='+value, 'check'], text=True)
                    rows = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
                    self.assertEqual(MODULES.intersection(rows['PACKAGES'].split()),
                                     MODULES if value == 'true' else set())
                    self.assertEqual(rows['CONF'], 'true' if value == 'true' else '')

    def test_imports_preserve_signatures_and_keep_preprocessed_checks(self):
        bp = (EXPERIMENT/'Android.bp').read_text()
        for name in MODULES - {'AndrixCuttlefishWebViewOverlay'}:
            self.assertIn('name: "'+name+'"', bp)
        self.assertEqual(len(re.findall(r'\bpresigned:\s*true', bp)), 3)
        self.assertEqual(len(re.findall(r'\bpreprocessed:\s*true', bp)), 3)
        self.assertEqual(len(re.findall(r'^    enabled:\s*false', bp, re.MULTILINE)), 3)
        self.assertNotRegex(bp, r'\bskip_preprocessed_apk_checks:\s*true')
        self.assertIn('libwebviewchromium_loader', bp)
        self.assertIn('libwebviewchromium_plat_support', bp)
        self.assertIn('SPDX-license-identifier-GPL-2.0-only', bp)

    def test_only_no_dex_imports_skip_dex_precompilation(self):
        bp = (EXPERIMENT/'Android.bp').read_text()
        modules = re.findall(r'andrix_webview_app_import\s*\{(.*?)^\}', bp, re.S | re.M)
        self.assertEqual(len(modules), 3)
        for module in modules:
            name = re.search(r'\bname:\s*"([^"]+)"', module).group(1)
            disabled = bool(re.search(r'dex_preopt:\s*\{\s*enabled:\s*false', module))
            self.assertEqual(disabled, name in {
                'AndrixExperimentalTrichromeLibrary', 'AndrixExperimentalWebViewConfig'})
            self.assertNotRegex(module, r'skip_preprocessed_apk_checks:\s*true')

    def test_source_policy_manifest_matches_its_patch(self):
        manifest = json.loads((EXPERIMENT/'policy-inputs.json').read_text())
        self.assertEqual(manifest['chromium_tag'], '152.0.7977.84')
        self.assertEqual(hashlib.sha256((EXPERIMENT/manifest['patch']).read_bytes()).hexdigest(),
                         manifest['patch_sha256'])
        self.assertEqual(len({r['path'] for r in manifest['files']}), len(manifest['files']))
        for item in manifest['files']:
            self.assertRegex(item['before_sha256'], r'^[0-9a-f]{64}$')
            self.assertRegex(item['after_sha256'], r'^[0-9a-f]{64}$')
            self.assertNotEqual(item['before_sha256'], item['after_sha256'])


if __name__ == '__main__':
    unittest.main()
