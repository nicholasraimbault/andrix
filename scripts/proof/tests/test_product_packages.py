# SPDX-License-Identifier: Apache-2.0
"""Evaluate the pinned AOSP product leaf, not a full Android build or boot."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PATCH_DIR = ROOT / 'patches/android-17.0.0_r1'
FIXTURE = Path(__file__).resolve().parent / 'fixtures/aosp17-handheld-product.mk'
LEAF = 'build/make/target/product/handheld_product.mk'


class ProductPackageTests(unittest.TestCase):
    def test_exact_base_and_product_scoped_omission(self):
        series = json.loads((PATCH_DIR/'series.json').read_text())
        project = next(p for p in series['projects'] if p['path'] == 'build/make')
        entry = next(f for f in project['files'] if f['path'] == 'target/product/handheld_product.mk')
        original = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), entry['base_sha256'])
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            leaf = tmp / LEAF
            leaf.parent.mkdir(parents=True)
            leaf.write_bytes(original)
            subprocess.run(['git','apply','--check','--whitespace=error','--include='+LEAF,
                            str(PATCH_DIR/series['patch'])], cwd=tmp, check=True, capture_output=True)
            subprocess.run(['git','apply','--whitespace=error','--include='+LEAF,
                            str(PATCH_DIR/series['patch'])], cwd=tmp, check=True, capture_output=True)
            self.assertEqual(hashlib.sha256(leaf.read_bytes()).hexdigest(), entry['patched_sha256'])
            before = tmp/'original.mk'
            before.write_bytes(original)

            def evaluate(path, product):
                makefile = tmp/'check.mk'
                makefile.write_text('define inherit-product\nendef\n'
                                    'include '+str(path)+'\n'
                                    '$(info PACKAGES=$(strip $(PRODUCT_PACKAGES)))\n'
                                    '$(info DEBUG=$(strip $(PRODUCT_PACKAGES_DEBUG)))\n'
                                    '.PHONY: check\ncheck:\n\t@:\n')
                output = subprocess.check_output(['make','--no-print-directory','-f',str(makefile),
                                                   'TARGET_PRODUCT='+product,'check'], cwd=tmp, text=True)
                return dict(line.split('=',1) for line in output.splitlines() if '=' in line)

            for product in ('andrix_cf_arm64_only_phone','aosp_cf_arm64_only_phone','andrix_caiman',''):
                with self.subTest(product=product):
                    old = evaluate(before, product)
                    new = evaluate(leaf, product)
                    old_packages, new_packages = old['PACKAGES'].split(), new['PACKAGES'].split()
                    self.assertIn('QuickSearchBox', old_packages)
                    self.assertEqual(old['DEBUG'], new['DEBUG'])
                    if product == 'andrix_cf_arm64_only_phone':
                        self.assertNotIn('QuickSearchBox', new_packages)
                        self.assertEqual([p for p in old_packages if p != 'QuickSearchBox'], new_packages)
                    else:
                        self.assertCountEqual(old_packages, new_packages)

    def test_stock_webview_omission_requires_exact_product_and_explicit_opt_in(self):
        series = json.loads((PATCH_DIR/'series.json').read_text())
        project = next(p for p in series['projects'] if p['path'] == 'build/make')
        entry = next(f for f in project['files'] if f['path'] == 'target/product/media_product.mk')
        original = (FIXTURE.parent/'aosp17-media-product.mk').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), entry['base_sha256'])
        leaf_name = 'build/make/target/product/media_product.mk'
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            leaf = tmp/leaf_name
            leaf.parent.mkdir(parents=True)
            leaf.write_bytes(original)
            subprocess.run(['git', 'apply', '--check', '--whitespace=error',
                            '--include='+leaf_name, str(PATCH_DIR/series['patch'])],
                           cwd=tmp, check=True, capture_output=True)
            subprocess.run(['git', 'apply', '--whitespace=error',
                            '--include='+leaf_name, str(PATCH_DIR/series['patch'])],
                           cwd=tmp, check=True, capture_output=True)
            self.assertEqual(hashlib.sha256(leaf.read_bytes()).hexdigest(), entry['patched_sha256'])
            makefile = tmp/'check.mk'
            makefile.write_text('define inherit-product\nendef\ninclude '+str(leaf)+'\n'
                                '$(info PACKAGES=$(strip $(PRODUCT_PACKAGES)))\n'
                                '.PHONY: check\ncheck:\n\t@:\n')
            for product in ('andrix_cf_arm64_only_phone', 'aosp_cf_arm64_only_phone',
                            'andrix_caiman', ''):
                for enabled in ('', 'false', 'true', 'TRUE', '1'):
                    with self.subTest(product=product, enabled=enabled):
                        output = subprocess.check_output(['make', '--no-print-directory',
                            '-f', str(makefile), 'TARGET_PRODUCT='+product,
                            'ANDRIX_WEBVIEW_EXPERIMENT='+enabled, 'check'], cwd=tmp, text=True)
                        packages = next(line.split('=', 1)[1].split() for line in output.splitlines()
                                        if line.startswith('PACKAGES='))
                        self.assertEqual('webview' not in packages,
                                         product == 'andrix_cf_arm64_only_phone' and enabled == 'true')
                        self.assertIn('preinstalled-packages-media-product.xml', packages)


if __name__ == '__main__':
    unittest.main()
