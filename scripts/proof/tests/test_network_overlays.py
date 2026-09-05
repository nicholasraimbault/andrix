# SPDX-License-Identifier: Apache-2.0
"""Host-only checks of checked-in RRO inputs; no build, device, network or keys.

Run: python3 -B -m unittest discover -s scripts/proof/tests -p test_network_overlays.py
These are not Soong/idmap validation or evidence of effective runtime URLs.
"""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[3]
OVERLAY_ROOT = ROOT / "overlays/cuttlefish"
PRODUCT = ROOT / "products/andrix_cf_arm64_only_phone.mk"
ANDROID = "{http://schemas.android.com/apk/res/android}"
HTTP = "http://probe.andrix.org/generate_204"
HTTPS = "https://probe.andrix.org/generate_204"
OVERLAYS = {
    "AndrixCuttlefishFrameworkOverlay": {
        "package": "dev.andrix.cuttlefish.framework.overlay",
        "targetPackage": "android",
        "resources": {
            ("string-array", "config_ntpServers"): ("ntp://probe.andrix.org",),
        },
    },
    "AndrixCuttlefishNetworkStackOverlay": {
        "package": "dev.andrix.cuttlefish.networkstack.overlay",
        "targetPackage": "com.android.networkstack",
        "targetName": "NetworkStackConfig",
        "resources": {
            ("string", "config_captive_portal_http_url"): HTTP,
            ("string", "config_captive_portal_https_url"): HTTPS,
            ("string-array", "config_captive_portal_http_urls"): (HTTP,),
            ("string-array", "config_captive_portal_https_urls"): (HTTPS,),
            ("string-array", "config_captive_portal_fallback_urls"): (HTTP,),
        },
    },
    "AndrixCuttlefishConnectivityOverlay": {
        "package": "dev.andrix.cuttlefish.connectivity.overlay",
        "targetPackage": "com.android.connectivity.resources",
        "targetName": "ServiceConnectivityResourcesConfig",
        "resources": {
            ("string", "config_networkCaptivePortalServerUrl"): HTTP,
        },
    },
}


class NetworkOverlayInputsTests(unittest.TestCase):
    def test_only_cuttlefish_product_includes_modules(self):
        makefiles = sorted([*ROOT.glob("*.mk"), *(ROOT / "products").rglob("*.mk")])
        sources = {
            path: re.sub(r"#[^\n]*", "", path.read_text(encoding="utf-8"))
            for path in makefiles
        }
        logical_lines = sources[PRODUCT].replace("\\\n", " ")
        packages = " ".join(re.findall(
            r"(?m)^\s*PRODUCT_PACKAGES\s*\+=\s*(.*)$", logical_lines
        )).split()
        for name in OVERLAYS:
            with self.subTest(module=name):
                self.assertEqual(packages.count(name), 1)
                self.assertEqual(
                    [path for path, text in sources.items() if name in text],
                    [PRODUCT],
                )

    def test_minimal_product_rros_use_public_sdk_and_repository_license(self):
        for name in OVERLAYS:
            with self.subTest(module=name):
                bp = (OVERLAY_ROOT / name / "Android.bp").read_text(encoding="utf-8")
                bp = re.sub(r"//[^\n]*", "", bp)
                self.assertEqual(len(re.findall(r"\bruntime_resource_overlay\s*\{", bp)), 1)
                self.assertRegex(bp, rf'\bname:\s*"{name}"')
                self.assertRegex(bp, r'\bsdk_version:\s*"current"')
                self.assertRegex(bp, r"\bproduct_specific:\s*true")
                self.assertRegex(bp, r'default_applicable_licenses:\s*\[\s*"vendor_andrix_license"\s*,?\s*\]')
                # No custom signer, platform API access or extra install policy.
                self.assertCountEqual(re.findall(r"^\s*(\w+):", bp, re.MULTILINE),
                                      ["default_applicable_licenses", "name",
                                       "sdk_version", "product_specific"])

    def test_static_manifest_targets_and_priority(self):
        for name, expected in OVERLAYS.items():
            with self.subTest(module=name):
                manifest = ET.parse(OVERLAY_ROOT / name / "AndroidManifest.xml").getroot()
                self.assertEqual(manifest.tag, "manifest")
                self.assertEqual(manifest.get("package"), expected["package"])
                self.assertCountEqual([child.tag for child in manifest], ["overlay", "application"])
                overlay_attributes = {
                    ANDROID + "targetPackage": expected["targetPackage"],
                    ANDROID + "isStatic": "true",
                    ANDROID + "priority": "999",
                }
                if "targetName" in expected:
                    overlay_attributes[ANDROID + "targetName"] = expected["targetName"]
                self.assertEqual(manifest.find("overlay").attrib, overlay_attributes)
                self.assertEqual(manifest.find("application").attrib, {ANDROID + "hasCode": "false"})

    def test_exact_nonempty_config_hooks_without_qualified_or_default_resources(self):
        for name, expected in OVERLAYS.items():
            with self.subTest(module=name):
                res = OVERLAY_ROOT / name / "res"
                self.assertEqual(sorted(path.relative_to(res).as_posix()
                                        for path in res.rglob("*") if path.is_file()),
                                 ["values/config.xml"])
                resources = ET.parse(res / "values/config.xml").getroot()
                self.assertEqual(resources.tag, "resources")
                actual = {}
                for resource in resources:
                    self.assertIn(resource.tag, ("string", "string-array"))
                    key = (resource.tag, resource.get("name"))
                    self.assertNotIn(key, actual)
                    self.assertEqual(resource.attrib, {"name": key[1], "translatable": "false"})
                    if resource.tag == "string":
                        self.assertEqual(len(resource), 0)
                        actual[key] = (resource.text or "").strip()
                    else:
                        self.assertGreater(len(resource), 0)
                        for item in resource:
                            self.assertEqual(item.tag, "item")
                            self.assertEqual(item.attrib, {})
                            self.assertEqual(len(item), 0)
                        actual[key] = tuple((item.text or "").strip() for item in resource)
                self.assertEqual(actual, expected["resources"])


if __name__ == "__main__":
    unittest.main()
