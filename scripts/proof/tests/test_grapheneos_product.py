# SPDX-License-Identifier: Apache-2.0
"""Source contracts for the minimal migration product, not Android build proof."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PRODUCT = ROOT/'products/andrix_gos_cf_arm64_only_phone.mk'


class GrapheneosProductTests(unittest.TestCase):
    def test_separate_product_and_release_choice(self):
        registration=(ROOT/'AndroidProducts.mk').read_text()
        self.assertIn('andrix_gos_cf_arm64_only_phone.mk',registration)
        self.assertIn('andrix_gos_cf_arm64_only_phone-cur-userdebug',registration)
        self.assertIn('andrix_cf_arm64_only_phone-cp2a-userdebug',registration)
        text=PRODUCT.read_text()
        self.assertIn('PRODUCT_DEVICE := andrix_cf_arm64_only',text)
        inherited=re.findall(r'\$\(call inherit-product, ([^)]+)\)',text)
        self.assertEqual(inherited,['device/google/cuttlefish/vsoc_arm64_only/phone/aosp_cf.mk',
                                    'vendor/andrix/andrix.mk'])
        self.assertNotIn('PRODUCT_PACKAGES',text)
        self.assertNotIn('ANDRIX_WEBVIEW_EXPERIMENT',text)
        self.assertNotIn('AndrixCuttlefish',text)

    def test_official_build_rejection_is_scoped(self):
        # Real GNU make expansion with an empty inherit-product fixture. This
        # checks the guard, not Android inheritance or compilation.
        with tempfile.TemporaryDirectory() as tmp:
            makefile=Path(tmp)/'Makefile'
            makefile.write_text('include '+str(PRODUCT)+'\nall:\n\t@printf "%s\\n" "$(PRODUCT_NAME)"\n')
            for product,official,expected in [
                    ('andrix_gos_cf_arm64_only_phone','true',False),
                    ('andrix_gos_cf_arm64_only_phone','false',True),
                    ('andrix_gos_cf_arm64_only_phone','',True),
                    ('unrelated_product','true',True)]:
                result=subprocess.run(['make','--no-print-directory','-f',str(makefile),
                                       'TARGET_PRODUCT='+product,'OFFICIAL_BUILD='+official],
                                      capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode==0,expected,result.stderr)
                if not expected:self.assertIn('requires OFFICIAL_BUILD unset or false',result.stderr)
