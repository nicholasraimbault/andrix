#!/usr/bin/env python3
"""HOST-ONLY synthetic parser/lifecycle tests: no device, network, build or keys.

Run: python3 -B -m unittest discover -s scripts/proof/tests -p test_ordinary_app.py
These tests cannot supply P5 runtime evidence. All subprocess execution is blocked.
"""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "ordinary_app.py"
SPEC = importlib.util.spec_from_file_location("ordinary_app", SCRIPT)
p5 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p5)

UID = 10001
FINGERPRINT = "host-unit-fixture/NOT-A-BOOTED-IMAGE"
SOURCE_DIR = "/data/app/~~fixture/dev.andrix.proof.p5-fixture/base.apk"
SHELL_SHA = "a" * 64
BADGING = """package: name='dev.andrix.proof.p5' versionCode='1' versionName='1'
sdkVersion:'37'
targetSdkVersion:'37'
native-code: 'arm64-v8a'
"""
XMLTREE = """N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="dev.andrix.proof.p5" (Raw: "dev.andrix.proof.p5")
    E: uses-sdk (line=6)
      A: android:minSdkVersion(0x0101020c)=(type 0x10)0x25
      A: android:targetSdkVersion(0x01010270)=(type 0x10)0x25
    E: application (line=7)
      A: android:testOnly(0x01010272)=(type 0x12)0xffffffff
    E: instrumentation (line=8)
      A: android:name(0x01010003)="dev.andrix.proof.p5.P5Instrumentation" (Raw: "dev.andrix.proof.p5.P5Instrumentation")
      A: android:targetPackage(0x01010021)="dev.andrix.proof.p5" (Raw: "dev.andrix.proof.p5")
"""


def elf_fixture(interpreter=b"/system/bin/linker64\0"):
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 3, 183)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<I", data, 64, 3 if interpreter else 1)
    struct.pack_into("<Q", data, 72, 128)
    struct.pack_into("<Q", data, 96, len(interpreter))
    data[128:128 + len(interpreter)] = interpreter
    return bytes(data)


def report_fixture(shell_sha=SHELL_SHA):
    native = dict.fromkeys(p5.NATIVE_FIELDS, "")
    native.update(status="complete", error_errno="0", cleanup_errno="0", uid=str(UID),
                  euid=str(UID), gid=str(UID), egid=str(UID), copy_uid=str(UID),
                  selinux="u:r:untrusted_app:s0:c1,c256,c512,c768", cap_eff="0000000000000000",
                  mappings="1000-2000 r-xp 0000 00:01 1 /apex/com.android.runtime/bin/linker64\n"
                           "3000-4000 r-xp 0000 00:01 2 /apex/com.android.runtime/lib64/bionic/libc.so\n",
                  page_size="4096", source_path="/system/bin/sh", source_mode="0755", source_uid="0",
                  source_dev_inode="1:2", source_size="256", copy_size="256", copy_mode="0700",
                  copy_dir_mode="0700", copy_mount_noexec="0",
                  copy_path="/data/user/0/" + p5.PACKAGE + "/files/p5.abc123/sh",
                  byte_identity_before="identical", byte_identity_after="identical",
                  control_outcome="exited", control_stage="waitpid", control_errno="0",
                  control_exit="0", control_signal="0", control_reaped="1",
                  copy_outcome="exec_errno", copy_stage="execve", copy_errno="13", copy_exit="127",
                  copy_signal="0", copy_reaped="1")
    return dict(schema=1, package=p5.PACKAGE, instrumentation_package=p5.PACKAGE,
                uid=UID, package_uid=UID, app_flags=256, shared_user_id=None, permissions=[],
                source_dir=SOURCE_DIR, files_dir="/data/user/0/" + p5.PACKAGE + "/files",
                min_sdk=37, target_sdk=37, sdk=37, fingerprint=FINGERPRINT, abis=["arm64-v8a"],
                is_64_bit=True, system_sh_sha256_before=shell_sha, system_sh_sha256_after=shell_sha,
                native=native)


def raw_fixture(report):
    return "INSTRUMENTATION_RESULT: p5=" + json.dumps(report) + "\nINSTRUMENTATION_CODE: -1\n"


class HostOnly(unittest.TestCase):
    def setUp(self):
        block = mock.patch.object(subprocess, "run", side_effect=AssertionError("NO SUBPROCESSES IN UNIT TESTS"))
        block.start()
        self.addCleanup(block.stop)


class ParserTests(HostOnly):
    def validate(self, report):
        p5.validate_report(report, FINGERPRINT, UID, SOURCE_DIR, SHELL_SHA, 4096)

    def test_valid_synthetic_observations(self):
        report = p5.parse_instrumentation(raw_fixture(report_fixture()).replace("\n", "\r\n"))
        self.validate(report)

    def test_instrumentation_is_unambiguous(self):
        good = raw_fixture(report_fixture())
        for raw in ("", good.replace("CODE: -1", "CODE: 0"), good + good,
                    good + "INSTRUMENTATION_FAILED: process crashed\n",
                    good.replace('"schema": 1', '"schema": 1, "schema": 1'),
                    good.replace('"schema": 1', '"schema": NaN'),
                    "INSTRUMENTATION_RESULT: p5_error=java.lang.UnsatisfiedLinkError\nINSTRUMENTATION_CODE: 0\n"):
            with self.subTest(raw=raw[:80]), self.assertRaises(p5.Failure):
                p5.parse_instrumentation(raw)

    def test_identity_and_provenance_fail_closed(self):
        mutations = {"schema": True, "uid": 2000, "package_uid": 10002, "app_flags": 257,
                     "shared_user_id": "android.uid.system", "permissions": ["android.permission.INTERNET"],
                     "source_dir": "/system/app/proof.apk", "fingerprint": "wrong", "min_sdk": 36,
                     "target_sdk": 36, "sdk": 36, "abis": ["arm64-v8a", "armeabi-v7a"],
                     "is_64_bit": False, "system_sh_sha256_before": "b" * 64,
                     "system_sh_sha256_after": "b" * 64, "files_dir": "/data/local/tmp"}
        for key, value in mutations.items():
            with self.subTest(key=key), self.assertRaises(p5.Failure):
                report = report_fixture()
                report[key] = value
                self.validate(report)

    def test_setup_loader_other_errno_and_unexpected_execution_never_pass(self):
        mutations = {"status": "error", "error_stage": "copy_and_chmod", "cleanup_errno": "13",
                     "euid": "0", "selinux": "u:r:shell:s0", "cap_eff": "0000000000000001",
                     "page_size": "16384", "source_mode": "0644", "copy_mode": "0600",
                     "copy_dir_mode": "0777", "copy_mount_noexec": "1", "copy_size": "255",
                     "byte_identity_before": "different", "byte_identity_after": "different",
                     "control_outcome": "exec_errno", "control_exit": "127", "control_reaped": "0",
                     "copy_outcome": "exited", "copy_stage": "child_stdio", "copy_errno": "2",
                     "copy_exit": "0", "copy_signal": "31", "copy_reaped": "0"}
        for key, value in mutations.items():
            with self.subTest(key=key), self.assertRaises(p5.Failure):
                report = report_fixture()
                report["native"][key] = value
                self.validate(report)
        for error in ("0", "1", "8", "26"):  # success, EPERM, ENOEXEC, ETXTBSY != EACCES
            with self.subTest(errno=error), self.assertRaises(p5.Failure):
                report = report_fixture()
                report["native"]["copy_errno"] = error
                self.validate(report)
        for outcome in ("setup_error", "timeout", "wait_error", "protocol_error", "signaled"):
            with self.subTest(outcome=outcome), self.assertRaises(p5.Failure):
                report = report_fixture()
                report["native"]["copy_outcome"] = outcome
                self.validate(report)

    def test_native_fields_cannot_be_missing_or_extended(self):
        for key in p5.NATIVE_FIELDS:
            with self.subTest(key=key), self.assertRaises(p5.Failure):
                report = report_fixture()
                del report["native"][key]
                self.validate(report)
        report = report_fixture()
        report["native"]["extra"] = "1"
        with self.assertRaises(p5.Failure):
            self.validate(report)

    def test_invalid_mls_categories(self):
        for context in ("u:r:untrusted_app:s0:c1,c1024", "u:r:untrusted_app:s0:c1,c1"):
            with self.subTest(context=context), self.assertRaises(p5.Failure):
                report = report_fixture()
                report["native"]["selinux"] = context
                self.validate(report)

    def test_explicit_serial_and_fingerprint_required_before_commands(self):
        argv = [str(SCRIPT), "--apk", "NONEXISTENT.apk", "--system-sh", "NONEXISTENT.elf",
                "--evidence", "MUST-NOT-BE-CREATED"]
        for environment in ({}, {"ANDROID_SERIAL": "HOST-ONLY"},
                            {"ANDRIX_EXPECTED_FINGERPRINT": FINGERPRINT}):
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(p5.main(), 1)

    def test_every_adb_command_selects_serial(self):
        args = argparse.Namespace(evidence=Path("HOST-ONLY-NOT-CREATED"), adb="FAKE_ADB")
        runner = p5.Runner(args, "EXPLICIT-HOST-ONLY-SERIAL", FINGERPRINT)
        runner.command = mock.Mock(return_value="device\n")
        runner.adb("get-state")
        runner.command.assert_called_once_with(["FAKE_ADB", "-s", "EXPLICIT-HOST-ONLY-SERIAL", "get-state"], 30)

    def test_foreign_or_missing_executable_mappings(self):
        good = report_fixture()["native"]["mappings"]
        for bad in ("", good.replace("r-xp", "r--p"), good.replace("/lib64/bionic/libc.so", "/lib64/libc.so"),
                    good.replace("/apex/com.android.runtime/bin/linker64", "/data/local/tmp/linker64")):
            with self.subTest(maps=bad), self.assertRaises(p5.Failure):
                p5.check_mappings(bad)

    def test_apk_metadata(self):
        p5.check_apk_metadata(BADGING, XMLTREE)
        for badging, xml in ((BADGING.replace("'37'", "'36'"), XMLTREE),
                             (BADGING.replace("'arm64-v8a'", "'x86_64'"), XMLTREE),
                             (BADGING + "uses-permission: name='android.permission.INTERNET'\n", XMLTREE),
                             (BADGING.replace("name='dev.andrix.proof.p5'", "name='other.package'"), XMLTREE),
                             (BADGING, XMLTREE + '    E: uses-permission (line=9)\n'),
                             (BADGING, XMLTREE + '    A: android:sharedUserId(0x0101000b)="android.uid.system"\n'),
                             (BADGING, XMLTREE.replace("0xffffffff", "0x0"))):
            with self.subTest(badging=badging, xml=xml), self.assertRaises(p5.Failure):
                p5.check_apk_metadata(badging, xml)

    def test_pinned_aapt2_metadata_format(self):
        # Text captured from the real r1-built APK/pinned aapt2, not a boot test.
        fixtures = Path(__file__).resolve().parent / "fixtures"
        badging = (fixtures / "p5-aapt2-r1-badging.txt").read_text()
        manifest = (fixtures / "p5-aapt2-r1-manifest.txt").read_text()
        p5.check_apk_metadata(badging, manifest)
        for bad, xml in (
                (badging.replace("minSdkVersion:'37'", "minSdkVersion:'36'"), manifest),
                (badging.replace("minSdkVersion:'37'\n", ""), manifest),
                (badging + "sdkVersion:'37'\n", manifest),
                (badging + "minSdkVersion:'37'\n", manifest),
                (badging + "targetSdkVersion:'37'\n", manifest),
                (badging, manifest.replace("testOnly(0x01010272)=true", "testOnly(0x01010272)=false")),
                (badging, manifest + " A: http://schemas.android.com/apk/res/android:testOnly(0x01010272)=true\n"),
                (badging, manifest + ' A: http://schemas.android.com/apk/res/android:sharedUserId(0x0101000b)="android.uid.system"\n'),
                (badging, manifest + ' A: http://schemas.android.com/apk/res/android:permission(0x01010006)="android.permission.INTERNET"\n'),
        ):
            with self.subTest(badging=bad, manifest=xml), self.assertRaises(p5.Failure):
                p5.check_apk_metadata(bad, xml)

    def test_minimum_sdk_metadata_is_unambiguous(self):
        for badging in (BADGING + "sdkVersion:'37'\n", BADGING + "minSdkVersion:'37'\n",
                        BADGING.replace("sdkVersion:'37'\n", "")):
            with self.subTest(badging=badging), self.assertRaises(p5.Failure):
                p5.check_apk_metadata(badging, XMLTREE)

    def test_apk_archive_has_only_one_arm64_jni_payload(self):
        expected = "lib/arm64-v8a/libandrix_p5_probe.so"
        for libraries, valid in (([expected], True), ([], False),
                                 ([expected.replace("arm64-v8a", "x86_64")], False),
                                 ([expected, "lib/arm64-v8a/libc++_shared.so"], False)):
            with self.subTest(libraries=libraries):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    for library in libraries:
                        archive.writestr(library, elf_fixture(b""))
                buffer.seek(0)
                if valid:
                    p5.check_apk_archive(buffer)
                else:
                    with self.assertRaises(p5.Failure):
                        p5.check_apk_archive(buffer)

    def test_elf_interpreter_and_architecture(self):
        p5.elf_arm64(elf_fixture(), executable=True)
        p5.elf_arm64(elf_fixture(b""), executable=False)
        bad_arch = bytearray(elf_fixture())
        struct.pack_into("<H", bad_arch, 18, 62)
        for data in (b"not an ELF", bad_arch, elf_fixture(b"/lib/ld-linux-aarch64.so.1\0"), elf_fixture(b"")):
            with self.subTest(data=data[:20]), self.assertRaises(p5.Failure):
                p5.elf_arm64(data, executable=True)

    def test_user_and_package_parsers(self):
        self.assertEqual(p5.users_from_output("Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Other:10}\n"), [0, 10])
        self.assertEqual(p5.packages_from_output(""), [])
        self.assertEqual(p5.packages_from_output("package:" + p5.PACKAGE), [p5.PACKAGE])
        for raw in ("", "Users:\n", "Users:\nError: permission denied", "Users:\nUserInfo{0:Owner:c13}\nUserInfo{0:Duplicate:0}"):
            with self.subTest(raw=raw), self.assertRaises(p5.Failure):
                p5.users_from_output(raw)
        with self.assertRaises(p5.Failure):
            p5.packages_from_output("Error: unavailable")


class FakeRunner(p5.Runner):
    """Finite in-process fake protocol, with no fallback to real commands."""
    existing = False
    uncertain_install = False
    missing_install_identity = False
    changed_boot = False
    changed_apk = False
    bad_report = False
    instrumented = False
    present = False

    def command(self, arguments, timeout=30):
        self.calls.append(tuple(str(arg) for arg in arguments))
        if arguments[0:3] == ["FAKE_AAPT2", "dump", "badging"]:
            return BADGING
        if arguments[0:3] == ["FAKE_AAPT2", "dump", "xmltree"]:
            return XMLTREE
        raise AssertionError("unexpected host command: " + repr(arguments))

    def adb(self, *arguments, timeout=30):
        self.calls.append(arguments)
        if arguments == ("get-state",):
            return "device\n"
        if arguments[0] == "install":
            self.present = True
            if self.uncertain_install:
                raise subprocess.TimeoutExpired("FAKE_ADB install", timeout)
            return "Performing Streamed Install\nSuccess\n"
        if arguments == ("uninstall", p5.PACKAGE):
            self.present = False
            return "Success\n"
        assert arguments[0] == "shell", arguments
        command = shlex.split(arguments[1])
        if command[0] == "getprop":
            return {"ro.build.fingerprint": FINGERPRINT, "sys.boot_completed": "1", "ro.build.version.sdk": "37",
                    "ro.product.cpu.abilist": "arm64-v8a", "ro.product.cpu.abilist64": "arm64-v8a",
                    "ro.product.cpu.abilist32": ""}[command[1]]
        if command == ["getenforce"]:
            return "Enforcing"
        if command == ["id", "-u"]:
            return "2000"
        if command == ["id", "-Z"]:
            return "u:r:shell:s0"
        if command == ["uname", "-m"]:
            return "aarch64"
        if command == ["am", "get-current-user"]:
            return "0"
        if command == ["getconf", "PAGESIZE"]:
            return "4096"
        if command == ["cat", "/proc/sys/kernel/random/boot_id"]:
            return ("1" if self.changed_boot and self.instrumented else "0") + "0000000-0000-0000-0000-000000000000"
        if command[:2] == ["toybox", "sha256sum"]:
            if command[2] == "/system/bin/sh":
                digest = self.summary["system_sh_sha256"]
            else:
                assert command[2] == SOURCE_DIR, command
                digest = "c" * 64 if self.changed_apk and self.instrumented else self.summary["apk_sha256"]
            return digest + "  " + command[2]
        if command == ["pm", "list", "users"]:
            return "Users:\nUserInfo{0:Owner:c13} running\nUserInfo{10:Other:10}\n"
        if command[:4] == ["pm", "list", "packages", "-u"]:
            return "package:" + p5.PACKAGE if self.present or (self.existing and command[5] == "10") else ""
        if command == ["pm", "path", "--user", "0", p5.PACKAGE]:
            assert self.present
            if self.missing_install_identity:
                return ""
            return "package:" + SOURCE_DIR
        if command == ["pm", "list", "packages", "-U", "--user", "0", p5.PACKAGE]:
            assert self.present
            return "package:" + p5.PACKAGE + " uid:" + str(UID)
        if command == ["am", "instrument", "-w", "-r", "--user", "0", p5.INSTRUMENTATION]:
            self.instrumented = True
            report = report_fixture(self.summary["system_sh_sha256"])
            if self.bad_report:
                report["native"]["copy_errno"] = "8"
            return raw_fixture(report)
        raise AssertionError("unexpected device command: " + repr(command))


class LifecycleTests(HostOnly):
    def make_runner(self, **settings):
        temporary = tempfile.TemporaryDirectory(prefix="andrix-p5-HOST-ONLY-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        apk = root / "fixture.apk"
        apk.write_bytes(b"HOST UNIT FIXTURE ONLY, not an APK")
        shell = root / "fixture.elf"
        shell.write_bytes(elf_fixture())
        evidence = root / "evidence"
        evidence.mkdir()
        args = argparse.Namespace(apk=apk, system_sh=shell, evidence=evidence, adb="FAKE_ADB", aapt2="FAKE_AAPT2")
        runner = FakeRunner(args, "HOST-ONLY-NOT-A-SERIAL", FINGERPRINT)
        runner.calls = []
        for key, value in settings.items():
            setattr(runner, key, value)
        return runner

    def run_fake(self, runner):
        with mock.patch.object(p5, "check_apk_archive"):
            runner.run()

    def test_acknowledged_install_without_grants_and_cleanup(self):
        runner = self.make_runner()
        self.run_fake(runner)
        self.assertEqual(runner.summary["verdict"], "PASS")
        installs = [call for call in runner.calls if call[0] == "install"]
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0][:-1], ("install", "-t", "--user", "0"))
        self.assertEqual(runner.calls.count(("uninstall", p5.PACKAGE)), 1)
        self.assertFalse(runner.present)

    def test_preexisting_other_user_package_is_never_installed_or_removed(self):
        runner = self.make_runner(existing=True)
        with self.assertRaises(p5.Failure):
            self.run_fake(runner)
        self.assertFalse(any(call[0] in ("install", "uninstall") for call in runner.calls))

    def test_unknown_install_ownership_never_triggers_uninstall(self):
        runner = self.make_runner(uncertain_install=True)
        with self.assertRaises(p5.Failure):
            self.run_fake(runner)
        self.assertTrue(runner.present)  # Explicit uncertainty, for operator reconciliation.
        self.assertTrue(runner.summary["install_attempted"])
        self.assertFalse(runner.summary["install_confirmed"])
        self.assertNotIn(("uninstall", p5.PACKAGE), runner.calls)

    def test_unestablished_installed_identity_blocks_cleanup(self):
        runner = self.make_runner(missing_install_identity=True)
        with self.assertRaises(p5.Failure):
            self.run_fake(runner)
        self.assertTrue(runner.summary["install_confirmed"])
        self.assertIsNone(runner.identity)
        self.assertTrue(runner.present)
        self.assertNotIn(("uninstall", p5.PACKAGE), runner.calls)
        self.assertIn("no blind uninstall", runner.summary["failure"])

    def test_bad_proof_is_failure_but_own_install_is_removed(self):
        runner = self.make_runner(bad_report=True)
        with self.assertRaises(p5.Failure):
            self.run_fake(runner)
        self.assertEqual(runner.summary["verdict"], "FAIL")
        self.assertTrue(runner.summary["uninstall_confirmed"])
        self.assertFalse(runner.present)

    def test_changed_boot_or_apk_blocks_cleanup_and_pass(self):
        for setting in ("changed_boot", "changed_apk"):
            with self.subTest(setting=setting):
                runner = self.make_runner(**{setting: True})
                with self.assertRaises(p5.Failure):
                    self.run_fake(runner)
                self.assertNotIn(("uninstall", p5.PACKAGE), runner.calls)
                self.assertEqual(runner.summary["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
