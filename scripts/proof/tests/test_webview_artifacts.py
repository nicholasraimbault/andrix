#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""HOST-ONLY synthetic fixtures/mocked tools, NOT observations of future APKs.

Run: python3 -B -m unittest discover -s scripts/proof/tests -p test_webview_artifacts.py
No private keys, signing, builds, installation, devices, network or real subprocesses.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("webview_artifacts", HERE / "webview_artifacts.py")
w = importlib.util.module_from_spec(SPEC)
with mock.patch.object(sys, "path", [str(HERE), *sys.path]):
    SPEC.loader.exec_module(w)

PACKAGES = {"webview": "dev.example.webview", "library": "dev.example.trichromelibrary", "config": "dev.example.config"}
NAMESPACE = "dev.example.shared"
LIBRARY = "libfixturemonochrome.so"
NATIVE = "lib/arm64-v8a/" + LIBRARY
MARKER = "lib/arm64-v8a/libplaceholder.so"
ANDROID = "http://schemas.android.com/apk/res/android"


def tlv(tag, value):
    size = len(value)
    count = (size.bit_length() + 7) // 8
    length = bytes([size]) if size < 128 else bytes([0x80 | count]) + size.to_bytes(count, "big")
    return bytes([tag]) + length + value


def public_certificate_fixture():
    # Structurally valid X.509 with fixed dummy public bits and a dummy signature.
    # No signing or key generation. Trust-store loading parses, NOT verifies, it.
    algorithm = tlv(0x30, tlv(0x06, b"\x2b\x65\x70"))  # Ed25519 OID
    name = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b"\x55\x04\x03") + tlv(0x0c, b"HOST-ONLY FIXTURE"))))
    validity = tlv(0x30, tlv(0x17, b"240101000000Z") + tlv(0x17, b"350101000000Z"))
    public = tlv(0x30, algorithm + tlv(0x03, b"\0" + b"\x42" * 32))
    tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01") + algorithm + name + validity + name + public)
    der = tlv(0x30, tbs + algorithm + tlv(0x03, b"\0" + b"\x55" * 64))
    return der, b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


DER, PEM = public_certificate_fixture()
DIGEST = hashlib.sha256(DER).hexdigest()
SIGNATURE = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
Signer #1 certificate DN: CN=HOST-ONLY FIXTURE
Signer #1 certificate SHA-256 digest: """ + DIGEST + """
Signer #1 certificate SHA-1 digest: """ + "a" * 40 + """
Signer #1 certificate MD5 digest: """ + "b" * 32 + """
Signer #1 key algorithm: Ed25519
Signer #1 key size (bits): 256
Signer #1 public key SHA-256 digest: """ + "c" * 64 + "\n"

METADATA = f'''        E: meta-data (line=7)
          A: {ANDROID}:name(0x01010003)="com.android.webview.WebViewLibrary" (Raw: "com.android.webview.WebViewLibrary")
          A: {ANDROID}:value(0x01010024)="{LIBRARY}" (Raw: "{LIBRARY}")
'''
USES = f'''        E: uses-static-library (line=8)
          A: {ANDROID}:name(0x01010003)="{NAMESPACE}" (Raw: "{NAMESPACE}")
          A: {ANDROID}:version(0x01010519)=123
          A: {ANDROID}:certDigest(0x01010548)="{DIGEST}" (Raw: "{DIGEST}")
'''
STATIC = f'''        E: static-library (line=8)
          A: {ANDROID}:name(0x01010003)="{NAMESPACE}" (Raw: "{NAMESPACE}")
          A: {ANDROID}:version(0x01010519)=123
'''


def xmltree(role):
    return f'''N: android={ANDROID} (line=1)
  E: manifest (line=1)
    A: {ANDROID}:versionCode(0x0101021b)=123
    A: {ANDROID}:versionName(0x0101021c)="fixture" (Raw: "fixture")
    A: {ANDROID}:compileSdkVersion(0x01010572)=37
    A: {ANDROID}:compileSdkVersionCodename(0x01010573)="17" (Raw: "17")
    A: package="{PACKAGES[role]}" (Raw: "{PACKAGES[role]}")
      E: uses-sdk (line=3)
        A: {ANDROID}:minSdkVersion(0x0101020c)=34
        A: {ANDROID}:targetSdkVersion(0x01010270)=36
      E: application (line=5)
        A: {ANDROID}:hasCode(0x0101000c)=true
''' + {"webview": METADATA + USES, "library": STATIC, "config": ""}[role]


def badging(role):
    return f"package: name='{PACKAGES[role]}' versionCode='123' versionName='fixture' compileSdkVersion='37' compileSdkVersionCodename='17'\n" \
           "minSdkVersion:'34'\ntargetSdkVersion:'36'\napplication: label='Host fixture' icon=''\n" \
           + ("native-code: 'arm64-v8a'\n" if role != "config" else "")


def elf_header():
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 3, 183, 1)
    return bytes(header)


def archive_bytes(entries=None):
    # Deliberately NOT a usable APK: binary-XML header only; aapt2 is mocked.
    entries = [("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8)),
               (NATIVE, elf_header())] if entries is None else entries
    data = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(data, "w") as archive:
        warnings.simplefilter("ignore", UserWarning)  # Intentional duplicate fixture.
        for name, content in entries:
            archive.writestr(name, content)
    return data.getvalue()


def apk_records():
    return {role: {"metadata": w.check_metadata(badging(role), xmltree(role), PACKAGES[role], role),
                   "signer_certificate_sha256": DIGEST,
                   "archive": {"native_libraries": [{"path": NATIVE}] if role != "config" else []}}
            for role in w.ROLES}


class HostOnly(unittest.TestCase):
    def setUp(self):
        blocker = mock.patch.object(subprocess, "run", side_effect=AssertionError("NO REAL SUBPROCESSES"))
        self.blocked = blocker.start()
        self.addCleanup(blocker.stop)


class CertificateAndSignerTests(HostOnly):
    def test_public_pem_hash_is_certificate_der_not_pem_or_public_key(self):
        info = w.certificate_info(PEM)
        self.assertEqual(info["certificate_sha256"], DIGEST)
        self.assertEqual(info["pem_sha256"], hashlib.sha256(PEM).hexdigest())
        self.assertNotEqual(info["pem_sha256"], DIGEST)
        self.assertEqual(w.certificate_info(PEM.replace(b"\n", b"\r\n"))["certificate_sha256"], DIGEST)

    def test_pem_rejects_chains_keys_junk_malformed_base64_and_non_x509(self):
        for pem in (b"", PEM + PEM, b"comment\n" + PEM, PEM + b"junk",
                    PEM.replace(b"CERTIFICATE", b"PRIVATE KEY"),
                    PEM.replace(b"CERTIFICATE", b"PUBLIC KEY"),
                    PEM.replace(base64.encodebytes(DER), b"!!!!\n"),
                    PEM.replace(base64.encodebytes(DER), base64.encodebytes(DER + b"junk")),
                    PEM.replace(base64.encodebytes(DER), base64.encodebytes(b"\x30\x02\x05\x00")),
                    PEM + b" " * 65536):
            with self.subTest(pem=pem[:60]), self.assertRaises(w.Failure):
                w.certificate_info(pem)

    def test_legacy_and_aosp17_single_signer(self):
        for output in (SIGNATURE, SIGNATURE.replace("Signer #1 ", "V3.0 Signer: "),
                       SIGNATURE.replace(DIGEST, DIGEST.upper()).replace("\n", "\r\n")):
            self.assertEqual(w.signer_digest(output, DIGEST), DIGEST)

    def test_wrong_missing_malformed_or_ambiguous_signer_fails_closed(self):
        cert_row = "Signer #1 certificate SHA-256 digest: " + DIGEST + "\n"
        for output in ("", SIGNATURE.replace(DIGEST, "d" * 64),
                       SIGNATURE.replace("Verifies\n", ""), SIGNATURE.replace("true", "false"),
                       SIGNATURE.replace("Number of signers: 1\n", ""),
                       SIGNATURE.replace("Number of signers: 1", "Number of signers: 2"),
                       SIGNATURE + "Number of signers: 1\n", SIGNATURE + cert_row,
                       SIGNATURE.replace("Signer #1 ", "Signer #2 "),
                       SIGNATURE.replace(DIGEST, DIGEST[:-1]), SIGNATURE.replace(DIGEST, ":".join(["aa"] * 32)),
                       SIGNATURE.replace(cert_row, "").replace("c" * 64, DIGEST),
                       SIGNATURE + cert_row.replace("Signer #1 ", "V3.0 Signer: "),
                       SIGNATURE + cert_row.replace("Signer #1 ", "Source Stamp Signer "),
                       SIGNATURE + cert_row.replace("SHA-256", "SHA256"),
                       SIGNATURE.replace("SourceStamp: false", "SourceStamp: true"),
                       SIGNATURE + "WARNING: unsupported signature\n"):
            with self.subTest(output=output[-160:]), self.assertRaises(w.Failure):
                w.signer_digest(output, DIGEST)


class MetadataTests(HostOnly):
    def check(self, badge=None, xml=None, role="webview"):
        return w.check_metadata(badging(role) if badge is None else badge,
                                xmltree(role) if xml is None else xml, PACKAGES[role], role)

    def test_both_aapt2_formats_and_versions_are_recorded(self):
        for role in w.ROLES:
            for legacy in (False, True):
                xml = xmltree(role)
                badge = badging(role)
                if legacy:
                    xml = xml.replace(ANDROID + ":", "android:")
                    for number in (123, 37, 34, 36):
                        xml = xml.replace("=" + str(number) + "\n", "=(type 0x10)" + hex(number) + "\n")
                    badge = badge.replace("minSdkVersion:", "sdkVersion:")
                with self.subTest(role=role, legacy=legacy):
                    info = self.check(badge, xml, role)
                    self.assertEqual(info["package"], PACKAGES[role])
                    self.assertEqual((info["version_code"], info["version_name"], info["min_sdk"], info["target_sdk"]),
                                     (123, "fixture", 34, 36))
                    self.assertEqual(info["compileSdkVersion"], 37)

    def test_existing_public_p5_aapt2_fixture_format_only(self):
        # Actual r1 TOOL FORMAT from the pre-existing P5 fixture, not a WebView APK.
        fixtures = Path(__file__).resolve().parent / "fixtures"
        info = w.parse_badging((fixtures / "p5-aapt2-r1-badging.txt").read_text())
        nodes = w.parse_xmltree((fixtures / "p5-aapt2-r1-manifest.txt").read_text())
        self.assertEqual(w.string(nodes[0], "package"), info["package"])
        sdk = w.one_child(nodes, nodes[0], "uses-sdk")
        self.assertEqual(w.integer(sdk, "android:minSdkVersion"), info["min_sdk"])
        self.assertEqual(w.integer(sdk, "android:targetSdkVersion"), info["target_sdk"])

    def test_missing_optional_version_name_and_compile_sdk_are_explicit(self):
        badge = badging("config").replace("versionName='fixture'", "versionName=''")
        xml = xmltree("config").replace(f'    A: {ANDROID}:versionName(0x0101021c)="fixture" (Raw: "fixture")\n', "")
        self.assertIsNone(self.check(badge, xml, "config")["version_name"])
        for field, literal in (("compileSdkVersion", "37"), ("compileSdkVersionCodename", "17")):
            badge = badge.replace(f" {field}='{literal}'", "")
            xml = "\n".join(line for line in xml.splitlines() if ":" + field + "(" not in line) + "\n"
        self.assertIsNone(self.check(badge, xml, "config")["compileSdkVersion"])

    def test_package_and_sdk_badging_are_required_and_unambiguous(self):
        good = badging("webview")
        for badge in ("", good.replace("package:", "broken:"), good + good.splitlines()[0] + "\n",
                      good.replace("name='dev.example.webview'", "name=dev.example.webview"),
                      good.replace("name='dev.example.webview'", "name='wrong.package'"),
                      good.replace("name='dev.example.webview' ", ""),
                      good.replace("versionCode='123' ", ""), good.replace("versionName='fixture' ", ""),
                      good.replace("versionCode='123'", "versionCode='abc'"),
                      good.replace("versionCode='123'", "versionCode='123' versionCode='123'"),
                      good.replace("versionCode='123'", "versionCode='124'"),
                      good.replace("minSdkVersion:'34'\n", ""), good.replace("targetSdkVersion:'36'\n", ""),
                      good + "sdkVersion:'34'\n", good + "minSdkVersion:'34'\n", good + "targetSdkVersion:'36'\n",
                      good.replace("minSdkVersion:'34'", "minSdkVersion:34"),
                      good.replace("targetSdkVersion:'36'", "targetSdkVersion:'preview'"),
                      good.replace("versionName='fixture'", "versionName='fixture' split='config.arm64_v8a'")):
            with self.subTest(badge=badge[:180]), self.assertRaises(w.Failure):
                self.check(badge=badge)

    def test_binary_manifest_identity_structure_and_attribute_ids(self):
        good = xmltree("webview")
        package_line = f'    A: package="{PACKAGES["webview"]}" (Raw: "{PACKAGES["webview"]}")\n'
        for xml in ("", "<manifest package='dev.example.webview'/>", good + "garbage\n",
                    good.replace(package_line, ""), good.replace(package_line, package_line * 2),
                    good.replace(PACKAGES["webview"], "wrong.package"),
                    good.replace("versionCode(0x0101021b)=123", "versionCode(0x0101021b)=124"),
                    good.replace("versionCode(0x0101021b)", "versionCode(0x0101021c)"),
                    good.replace("minSdkVersion(0x0101020c)=34", "minSdkVersion(0x0101020c)=33"),
                    good.replace("E: uses-sdk", "E: not-uses-sdk"),
                    good.replace("E: application", "E: service"),
                    good + "      E: application (line=30)\n", good + "        E: manifest (line=30)\n",
                    good.replace(package_line, package_line.replace('="dev.example.webview" (Raw: "dev.example.webview")', '=@0x7f010000')),
                    good.replace('"fixture" (Raw: "fixture")', '"fixture" (Raw: "different")'),
                    good.replace(ANDROID + ":", "http://wrong.example/android:"),
                    good.replace(ANDROID + ":", "android:").replace("android=" + ANDROID, "android=http://wrong.example")):
            with self.subTest(xml=xml[:140]), self.assertRaises(w.Failure):
                self.check(xml=xml)

    def test_sdk_bounds_and_optional_maximum_are_consistent(self):
        badge = badging("webview") + "maxSdkVersion:'40'\n"
        xml = xmltree("webview").replace("      E: application", f"        A: {ANDROID}:maxSdkVersion(0x01010271)=40\n      E: application")
        self.assertEqual(self.check(badge, xml)["max_sdk"], 40)
        for bad, tree in ((badge + "maxSdkVersion:'40'\n", xml), (badging("webview"), xml),
                          (badge, xml.replace("maxSdkVersion(0x01010271)=40", "maxSdkVersion(0x01010271)=41")),
                          (badge.replace("'40'", "'30'"), xml.replace("maxSdkVersion(0x01010271)=40", "maxSdkVersion(0x01010271)=30")),
                          (badging("webview").replace("'36'", "'33'"), xmltree("webview").replace("targetSdkVersion(0x01010270)=36", "targetSdkVersion(0x01010270)=33")),
                          (badging("webview").replace("compileSdkVersion='37'", "compileSdkVersion='36'"), xmltree("webview"))):
            with self.subTest(badging=bad), self.assertRaises(w.Failure):
                self.check(bad, tree)

    def test_webview_metadata_must_be_unique_literal_and_on_application(self):
        good = xmltree("webview")
        misplaced = "        E: service (line=6)\n" + "\n".join("  " + line for line in METADATA.splitlines()) + "\n"
        for xml in (good.replace(METADATA, ""), good + METADATA, good.replace(METADATA, misplaced),
                    good.replace("com.android.webview.WebViewLibrary", "other.metadata"),
                    good.replace(":value(0x01010024)", ":resource(0x01010025)"),
                    good.replace(f'"{LIBRARY}" (Raw: "{LIBRARY}")', "@0x7f010000"),
                    good.replace(LIBRARY, "../" + LIBRARY),
                    good.replace("value(0x01010024)", "value(0x01010025)")):
            with self.subTest(xml=xml[-500:]), self.assertRaises(w.Failure):
                self.check(xml=xml)

    def test_static_declarations_and_pin_are_required_literal_and_single(self):
        good = xmltree("webview")
        for xml in (good.replace(USES, ""), good + USES,
                    good.replace(":version(0x01010519)=123", ":version(0x01010519)=@0x7f010000"),
                    good.replace(f'          A: {ANDROID}:version(0x01010519)=123\n', ""),
                    "\n".join(line for line in good.splitlines() if ":certDigest(" not in line),
                    good.replace(DIGEST, ""), good.replace(DIGEST, DIGEST[:-1]),
                    good.replace(DIGEST, DIGEST + "," + DIGEST),
                    good.replace("certDigest(0x01010548)", "certDigest(0x01010003)"),
                    good + '          E: additional-certificate (line=9)\n',
                    good + STATIC):
            with self.subTest(xml=xml[-300:]), self.assertRaises(w.Failure):
                self.check(xml=xml)
        colon = ":".join(DIGEST[index:index + 2].upper() for index in range(0, 64, 2))
        self.assertEqual(self.check(xml=good.replace(DIGEST, colon))["uses-static-library"]["certificate_sha256"], DIGEST)
        for xml in (xmltree("library").replace(STATIC, ""), xmltree("library") + STATIC,
                    xmltree("library").replace("E: static-library", "E: uses-static-library")):
            with self.subTest(xml=xml[-300:]), self.assertRaises(w.Failure):
                self.check(xml=xml, role="library")
        with self.assertRaises(w.Failure):
            self.check(xml=xmltree("config") + STATIC, role="config")

    def test_badging_rejects_arm32_mixed_unknown_or_duplicate_abis(self):
        for line in ("native-code: 'armeabi-v7a'", "native-code: 'arm64-v8a' 'armeabi-v7a'",
                     "native-code: 'x86_64'", "native-code: 'arm64-v8a' 'arm64-v8a'", "native-code:"):
            with self.subTest(line=line), self.assertRaises(w.Failure):
                self.check(badge=badging("webview").replace("native-code: 'arm64-v8a'", line))
        with self.assertRaises(w.Failure):
            self.check(badge=badging("webview") + "native-code: 'arm64-v8a'\n")

    def test_static_library_namespace_version_and_signer_relationship(self):
        self.assertEqual(w.check_relationships(apk_records(), DIGEST)["namespace"], NAMESPACE)
        for role, key, value in (("webview", "name", "other.namespace"), ("webview", "version", 124),
                                 ("library", "version", 124), ("webview", "certificate_sha256", "d" * 64)):
            with self.subTest(role=role, key=key), self.assertRaises(w.Failure):
                records = apk_records()
                tag = "uses-static-library" if role == "webview" else "static-library"
                records[role]["metadata"][tag][key] = value
                w.check_relationships(records, DIGEST)
        records = apk_records()
        records["library"]["signer_certificate_sha256"] = "d" * 64
        with self.assertRaises(w.Failure):
            w.check_relationships(records, DIGEST)

    def test_native_library_must_exist_in_library_not_just_webview(self):
        for libraries in ([], [{"path": "lib/arm64-v8a/libwrong.so"}]):
            records = apk_records()
            records["library"]["archive"]["native_libraries"] = libraries
            with self.subTest(libraries=libraries), self.assertRaises(w.Failure):
                w.check_relationships(records, DIGEST)

    def test_relationship_never_counts_an_abi_marker_as_native_payload(self):
        # Library-role archive checks already forbid this. Independently ensure
        # relationship checks cannot use an ABI marker, even when named by metadata.
        records = apk_records()
        records["webview"]["metadata"]["webview_library"] = "libplaceholder.so"
        records["library"]["archive"]["abi_markers"] = [{"path": MARKER}]
        records["library"]["archive"]["native_abis"] = ["arm64-v8a"]
        with self.assertRaisesRegex(w.Failure, "WebViewLibrary native payload missing"):
            w.check_relationships(records, DIGEST)


class ArchiveTests(HostOnly):
    def check(self, entries=None, **kwargs):
        return w.check_archive(io.BytesIO(archive_bytes(entries)), **kwargs)

    def test_header_and_manifest_hashes_are_recorded(self):
        info = self.check()
        self.assertEqual(info["native_abis"], ["arm64-v8a"])
        self.assertEqual(info["abi_markers"], [])
        self.assertEqual(info["native_libraries"][0]["sha256"], hashlib.sha256(elf_header()).hexdigest())
        self.assertEqual(self.check([("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))])["native_abis"], [])
        self.check([("lib/", b""), ("lib/arm64-v8a/", b""),
                    ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8)), (NATIVE, elf_header())])

    def test_empty_webview_placeholder_is_an_abi_marker_not_a_native_library(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        for libraries in ([], [(NATIVE, elf_header())]):
            with self.subTest(with_payload=bool(libraries)):
                info = self.check([manifest, (MARKER, b""), *libraries], role="webview")
                self.assertEqual(info["abi_markers"], [{"path": MARKER, "size_bytes": 0,
                                                      "sha256": hashlib.sha256(b"").hexdigest()}])
                self.assertEqual(info["native_libraries"], [
                    {"path": path, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                    for path, content in libraries])
                self.assertEqual(info["native_abis"], ["arm64-v8a"])

    def test_placeholder_requires_explicit_webview_role(self):
        entries = [("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8)), (MARKER, b"")]
        for options in ({}, {"role": None}, {"role": "library"}, {"role": "config"},
                        {"role": "WEBVIEW"}, {"role": "unknown"}):
            with self.subTest(options=options), self.assertRaises(w.Failure):
                self.check(entries, **options)

    def test_placeholder_must_be_empty_even_if_it_contains_a_valid_elf_header(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        for role in (None, *w.ROLES):
            for content in (b"\0", b"not ELF", elf_header()):
                with self.subTest(role=role, content=content), self.assertRaisesRegex(w.Failure, "ABI marker"):
                    self.check([manifest, (MARKER, content)], role=role)

    def test_placeholder_requires_exact_path_abi_and_regular_file(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        for path in ("libplaceholder.so", "assets/libplaceholder.so", "lib/libplaceholder.so",
                     "lib/arm64-v8a/nested/libplaceholder.so", "lib/armeabi-v7a/libplaceholder.so",
                     "lib/x86_64/libplaceholder.so", "lib/arm64_v8a/libplaceholder.so",
                     "lib/arm64-v8a/libPlaceholder.so", "lib/arm64-v8a/./libplaceholder.so",
                     MARKER + "/"):
            with self.subTest(path=path), self.assertRaises(w.Failure):
                self.check([manifest, (path, b"")], role="webview")

    def test_marker_does_not_exempt_other_native_payloads_from_elf_checks(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        invalid = [b"", b"not ELF", elf_header()[:32]]
        # ELF32, big-endian, ET_EXEC and x86_64 remain invalid under WebView permission.
        for offset, value in ((4, 1), (5, 2), (16, 2), (18, 62)):
            header = bytearray(elf_header())
            header[offset] = value
            invalid.append(bytes(header))
        for content in invalid:
            with self.subTest(content=content), self.assertRaisesRegex(w.Failure, "not ELF64"):
                self.check([manifest, (MARKER, b""), (NATIVE, content)], role="webview")

    def test_marker_does_not_bypass_manifest_or_zip_checks(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        marker = (MARKER, b"")
        symlink = zipfile.ZipInfo(MARKER)
        symlink.create_system = 3
        symlink.external_attr = 0o120777 << 16
        for entries in ([marker], [("AndroidManifest.xml", b"<manifest/>"), marker],
                        [manifest, marker, marker], [manifest, (symlink, b"")]):
            with self.subTest(entries=entries), self.assertRaises(w.Failure):
                self.check(entries, role="webview")

    def test_missing_text_truncated_manifest_duplicate_or_unsafe_paths(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        for entries in ([], [(NATIVE, elf_header())], [("AndroidManifest.xml", b"<manifest/>")],
                        [("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 99))], [manifest, manifest],
                        [manifest, (NATIVE, elf_header()), (NATIVE, elf_header())],
                        [manifest, ("../outside", b"x")], [manifest, ("/absolute", b"x")],
                        [manifest, ("assets//duplicate", b"x")], [manifest, ("assets\\escape", b"x")]):
            with self.subTest(entries=[name for name, _ in entries]), self.assertRaises(w.Failure):
                self.check(entries)
        symlink = zipfile.ZipInfo("assets/link")
        symlink.create_system = 3
        symlink.external_attr = 0o120777 << 16
        with self.assertRaises(w.Failure):
            self.check([manifest, (symlink, b"target")])

    def test_executable_elf_is_not_a_loadable_shared_library(self):
        header = bytearray(elf_header())
        struct.pack_into("<H", header, 16, 2)  # ET_EXEC, not ET_DYN
        with self.assertRaises(w.Failure):
            self.check([("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8)),
                        (NATIVE, bytes(header))])

    def test_corrupted_zip_contents_are_not_accepted(self):
        data = bytearray(archive_bytes())
        data[data.index(elf_header()) + 32] ^= 1  # Outside the checked architecture fields; CRC still fails.
        with self.assertRaises(zipfile.BadZipFile):
            w.check_archive(io.BytesIO(data))

    def test_arm32_mixed_and_renamed_non_arm64_native_payloads(self):
        manifest = ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
        arm32 = bytearray(elf_header())
        arm32[4] = 1
        struct.pack_into("<H", arm32, 18, 40)
        x86 = bytearray(elf_header())
        struct.pack_into("<H", x86, 18, 62)
        for extra in ([(NATIVE.replace("arm64-v8a", "armeabi-v7a"), bytes(arm32))],
                      [(NATIVE.replace("arm64-v8a", "armeabi-v7a"), bytes(arm32)), (NATIVE, elf_header())],
                      [("lib/armeabi-v7a/", b"")], [(NATIVE, bytes(arm32))], [(NATIVE, bytes(x86))],
                      [(NATIVE, b"not ELF")], [("assets/hidden.so", elf_header())],
                      [("assets/disguised.bin", bytes(arm32))]):
            with self.subTest(paths=[name for name, _ in extra]), self.assertRaises(w.Failure):
                self.check([manifest, *extra])


class RunnerTests(HostOnly):
    def make_runner(self):
        temporary = tempfile.TemporaryDirectory(prefix="andrix-webview-HOST-ONLY-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        args = argparse.Namespace(evidence=root / "evidence", expected_cert=root / "public-fixture.pem")
        args.expected_cert.write_bytes(PEM)
        args.evidence.mkdir()
        for role in w.ROLES:
            path = root / (role + "-input.apk")
            entries = [("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))]
            if role == "webview":
                entries.append((MARKER, b""))
            elif role == "library":
                entries.append((NATIVE, elf_header()))
            path.write_bytes(archive_bytes(entries))
            setattr(args, role + "_apk", path)
            setattr(args, role + "_package", PACKAGES[role])
        for tool in ("aapt2", "apksigner"):
            path = root / ("FAKE_" + tool)
            path.write_text("HOST-ONLY mock placeholder, NEVER EXECUTE\n")
            path.chmod(0o700)
            setattr(args, tool, path)
        return w.Runner(args)

    def tools(self, runner, outputs=None, fail=None, after=None, stderr=None):
        outputs = {} if outputs is None else outputs
        stderr = {} if stderr is None else stderr

        def run(argv, **kwargs):
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")
            self.assertIn(Path(argv[0]), (runner.args.aapt2, runner.args.apksigner))
            if argv[1:] == ["version"]:
                key, output = ("tool", "version"), "SYNTHETIC TOOL VERSION ONLY\n"
            elif argv[1:5] == ["verify", "--verbose", "--print-certs", "--Werr"]:
                self.assertEqual(len(argv), 6)
                key = (Path(argv[5]).stem, "verify")
                output = SIGNATURE
            elif argv[1:3] == ["dump", "badging"]:
                self.assertEqual(len(argv), 4)
                key = (Path(argv[3]).stem, "badging")
                output = badging(key[0])
            elif argv[1:3] == ["dump", "xmltree"]:
                self.assertEqual(argv[4:], ["--file", "AndroidManifest.xml"])
                key = (Path(argv[3]).stem, "xmltree")
                output = xmltree(key[0])
            else:
                raise AssertionError("unexpected host command: " + repr(argv))
            output = outputs.get(key, output)
            kwargs["stdout"].write(output.encode() if isinstance(output, str) else output)
            kwargs["stderr"].write(stderr.get(key, b"SYNTHETIC FAILURE\n" if key == fail else b""))
            if after:
                after(key)
            return subprocess.CompletedProcess(argv, 7 if key == fail else 0)
        return run

    def run_fake(self, runner, **kwargs):
        with mock.patch.object(subprocess, "run", side_effect=self.tools(runner, **kwargs)) as calls:
            runner.run()
        return calls

    def test_success_records_commands_snapshots_hashes_and_explicit_limits(self):
        runner = self.make_runner()
        original = {role: getattr(runner.args, role + "_apk").read_bytes() for role in w.ROLES}
        calls = self.run_fake(runner)
        self.assertEqual(calls.call_count, 11)  # two versions; verify, badging and xmltree for EACH APK
        self.assertEqual(runner.summary["verdict"], "PASS")
        self.assertEqual(runner.summary["config_info_trust"], "UNVERIFIED")
        self.assertFalse(runner.summary["runtime_verified"])
        self.assertIn("Config APK container signature does NOT prove", " ".join(runner.summary["unverified"]))
        self.assertEqual(len(list(runner.evidence.glob("*.command.json"))), 11)
        for role in w.ROLES:
            self.assertEqual(getattr(runner.args, role + "_apk").read_bytes(), original[role])
            self.assertEqual((runner.evidence / (role + ".apk")).read_bytes(), original[role])
            record = runner.summary["apks"][role]
            self.assertEqual(record["sha256"], hashlib.sha256(original[role]).hexdigest())
            self.assertEqual(record["signer_certificate_sha256"], DIGEST)
            self.assertEqual(record["metadata"]["package"], PACKAGES[role])
            self.assertEqual(record["archive"]["abi_markers"],
                             [{"path": MARKER, "size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}]
                             if role == "webview" else [])
            self.assertEqual([entry["path"] for entry in record["archive"]["native_libraries"]],
                             [NATIVE] if role == "library" else [])
            self.assertEqual(record["archive"]["native_abis"], ["arm64-v8a"] if role != "config" else [])
        for path in runner.evidence.glob("*.command.json"):
            record = json.loads(path.read_text())
            self.assertEqual(record["returncode"], 0)
            self.assertTrue(Path(str(path).replace(".command.json", ".stdout")).is_file())
            self.assertTrue(Path(str(path).replace(".command.json", ".stderr")).is_file())
        self.assertEqual(json.loads((runner.evidence / "summary.json").read_text()), runner.summary)

    def test_runner_forbids_marker_in_library_and_config(self):
        for role in ("library", "config"):
            runner = self.make_runner()
            entries = [("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8)), (MARKER, b"")]
            if role == "library":
                entries.append((NATIVE, elf_header()))
            getattr(runner.args, role + "_apk").write_bytes(archive_bytes(entries))
            with self.subTest(role=role), self.assertRaisesRegex(w.Failure, "ABI marker"):
                self.run_fake(runner)
            self.assertEqual(runner.summary["verdict"], "FAIL")

    def test_webview_marker_does_not_replace_library_payload(self):
        for filename, has_payload in ((LIBRARY, False), ("libplaceholder.so", True), ("libplaceholder.so", False)):
            runner = self.make_runner()
            outputs = {("webview", "xmltree"): xmltree("webview").replace(LIBRARY, filename)}
            if not has_payload:
                runner.args.library_apk.write_bytes(archive_bytes([
                    ("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))]))
                outputs[("library", "badging")] = badging("library").replace("native-code: 'arm64-v8a'\n", "")
            with self.subTest(filename=filename, has_payload=has_payload):
                with self.assertRaisesRegex(w.Failure, "WebViewLibrary native payload missing"):
                    self.run_fake(runner, outputs=outputs)
                self.assertEqual(runner.summary["verdict"], "FAIL")

    def test_each_apk_must_have_the_expected_signer(self):
        for role in w.ROLES:
            runner = self.make_runner()
            with self.subTest(role=role), self.assertRaisesRegex(w.Failure, "signer differs"):
                self.run_fake(runner, outputs={(role, "verify"): SIGNATURE.replace(DIGEST, "d" * 64)})
            self.assertEqual(runner.summary["verdict"], "FAIL")

    def test_actual_parsed_pin_namespace_and_version_mismatches_fail(self):
        for role, xml, message in (("webview", xmltree("webview").replace(DIGEST, "d" * 64), "certificate pin/signer mismatch"),
                                   ("library", xmltree("library").replace(NAMESPACE, "other.namespace"), "namespace mismatch"),
                                   ("library", xmltree("library").replace(":version(0x01010519)=123", ":version(0x01010519)=124"), "version mismatch")):
            runner = self.make_runner()
            with self.subTest(role=role, message=message), self.assertRaisesRegex(w.Failure, message):
                self.run_fake(runner, outputs={(role, "xmltree"): xml})
            self.assertEqual(runner.summary["verdict"], "FAIL")

    def test_tools_nonzero_even_with_valid_stdout_never_pass(self):
        for role in w.ROLES:
            for action in ("verify", "badging", "xmltree"):
                runner = self.make_runner()
                with self.subTest(role=role, action=action), self.assertRaisesRegex(w.Failure, "command .* failed"):
                    self.run_fake(runner, fail=(role, action))
                records = [json.loads(path.read_text()) for path in runner.evidence.glob("*.command.json")]
                self.assertEqual(sum(item["returncode"] == 7 for item in records), 1)
                self.assertEqual(json.loads((runner.evidence / "summary.json").read_text())["verdict"], "FAIL")

    def test_aapt2_version_stderr_is_narrowly_accepted(self):
        runner = self.make_runner()
        version = b"Android Asset Packaging Tool (aapt) 2.20-eng.202609\n"
        pattern = r"Android Asset Packaging Tool \(aapt\) [0-9A-Za-z.+_-]+"
        def invoke(argv, **kwargs):
            kwargs["stderr"].write(version)
            return subprocess.CompletedProcess(argv, 0)
        with mock.patch.object(subprocess, "run", side_effect=invoke):
            self.assertEqual(runner.command([runner.args.aapt2, "version"],
                                           version_stderr_pattern=pattern), version.decode())
        for invalid in (version + b"WARNING: unexpected\n", b"unrecognized version\n"):
            def fail_version(argv, **kwargs):
                kwargs["stderr"].write(invalid)
                return subprocess.CompletedProcess(argv, 0)
            with mock.patch.object(subprocess, "run", side_effect=fail_version), self.assertRaises(w.Failure):
                runner.command([runner.args.aapt2, "version"], version_stderr_pattern=pattern)

    def test_zero_exit_with_unexpected_stderr_is_not_a_pass(self):
        runner = self.make_runner()
        extra = b"Signer #2 certificate SHA-256 digest: " + b"d" * 64 + b"\n"
        with self.assertRaisesRegex(w.Failure, "unexpected stderr"):
            self.run_fake(runner, stderr={("webview", "verify"): extra})
        self.assertEqual(runner.summary["verdict"], "FAIL")
        self.assertIn(extra, [path.read_bytes() for path in runner.evidence.glob("*.stderr")])

    def test_timeout_missing_tool_interrupt_and_invalid_utf8_preserve_failure(self):
        for error in (subprocess.TimeoutExpired("FAKE", 120), FileNotFoundError("FAKE"), KeyboardInterrupt()):
            runner = self.make_runner()
            with self.subTest(error=type(error)), mock.patch.object(subprocess, "run", side_effect=error), self.assertRaises(w.Failure):
                runner.run()
            command = json.loads((runner.evidence / "001.command.json").read_text())
            self.assertIn(type(error).__name__, command["exception"])
            self.assertEqual(runner.summary["verdict"], "FAIL")
        runner = self.make_runner()
        with self.assertRaises(w.Failure):
            self.run_fake(runner, outputs={("webview", "badging"): b"\xff"})
        self.assertIn(b"\xff", b"".join(path.read_bytes() for path in runner.evidence.glob("*.stdout")))

    def test_badging_and_archive_abi_must_agree(self):
        runner = self.make_runner()
        with self.assertRaisesRegex(w.Failure, "ABI badging/archive mismatch"):
            self.run_fake(runner, outputs={("webview", "badging"): badging("webview").replace("native-code: 'arm64-v8a'\n", "")})
        runner = self.make_runner()
        with self.assertRaisesRegex(w.Failure, "ABI badging/archive mismatch"):
            self.run_fake(runner, outputs={("config", "badging"): badging("config") + "native-code: 'arm64-v8a'\n"})

    def test_input_and_snapshot_changes_never_pass(self):
        for snapshot in (False, True):
            runner = self.make_runner()
            path = runner.evidence / "webview.apk" if snapshot else runner.args.webview_apk

            def change(key):
                if key == ("config", "xmltree"):
                    with path.open("ab") as stream:
                        stream.write(b"changed")

            with self.subTest(snapshot=snapshot), self.assertRaisesRegex(w.Failure, "changed during verification"):
                self.run_fake(runner, after=change)

    def test_noncertificate_input_is_never_copied_or_sent_to_tools(self):
        runner = self.make_runner()
        runner.args.expected_cert.write_bytes(PEM.replace(b"CERTIFICATE", b"PRIVATE KEY"))
        with self.assertRaisesRegex(w.Failure, "public CERTIFICATE PEM"):
            runner.run()
        self.blocked.assert_not_called()
        self.assertFalse((runner.evidence / "expected-certificate.pem").exists())
        self.assertEqual(json.loads((runner.evidence / "summary.json").read_text())["verdict"], "FAIL")

    def test_cli_guards_run_before_any_tool_and_never_overwrite_evidence(self):
        runner = self.make_runner()
        argv = []
        for name in ("webview_apk", "library_apk", "config_apk", "webview_package", "library_package", "config_package",
                     "expected_cert", "aapt2", "apksigner", "evidence"):
            argv.extend(["--" + name.replace("_", "-"), str(getattr(runner.args, name))])
        marker = runner.evidence / "existing"
        marker.write_text("KEEP")
        for option, value in (("--evidence", str(runner.evidence)),
                              ("--evidence", str(HERE / "MUST-NOT-CREATE-EVIDENCE")),
                              ("--webview-package", "not a package"),
                              ("--webview-package", PACKAGES["library"]),
                              ("--library-apk", str(runner.args.webview_apk)),
                              ("--apksigner", str(runner.evidence / "MISSING"))):
            modified = argv.copy()
            modified[modified.index(option) + 1] = value
            with self.subTest(option=option, value=value), mock.patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(w.main(modified), 1)
            self.blocked.assert_not_called()
        self.assertEqual(marker.read_text(), "KEEP")


if __name__ == "__main__":
    unittest.main()
