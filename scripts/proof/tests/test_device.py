#!/usr/bin/env python3
"""Deterministic HOST UNIT FIXTURES ONLY for device.sh parser/command flow.

Run: python3 scripts/proof/tests/test_device.py

Uses temporary labelled dummy files and fake adb/readelf, never a device,
network, target build, real ELF/APEX or signing material. Passing these tests
is NOT milestone, artifact, ABI, SELinux or runtime evidence. bash -n is included.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
DEVICE = HERE.parent / "device.sh"
HOST_ELF = HERE.parent / "host_elf.sh"
USR = "/usr/bin/andrix-hello"
APEX = "/apex/dev.andrix.usr/bin/andrix-hello"
FACTORY = "/system_ext/apex/dev.andrix.usr.apex"


def apex_row(active="true", factory="true", path=FACTORY):
    path_attribute = f' preinstalledModulePath="{path}"' if path is not None else ""
    return (f'<apex-info moduleName="dev.andrix.usr" isActive="{active}" '
            f'isFactory="{factory}"{path_attribute}/>')


def apex_xml(*rows):
    return '<?xml version="1.0"?>\n<apex-info-list>\n' + "\n".join(rows) + "\n</apex-info-list>\n"


class DeviceCommandFlowUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ("bash", "awk", "cat", "cmp", "dirname", "grep", "mktemp", "python3", "rm", "sha256sum", "tr")
        missing = [tool for tool in required if shutil.which(tool) is None]
        if missing:
            raise RuntimeError("Missing host test prerequisites: " + ", ".join(missing))
        cls.bash = shutil.which("bash")

    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="andrix-device-unit-fixture-")
        self.addCleanup(work.cleanup)
        self.work = Path(work.name).resolve()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.scratch = self.work / "scratch"
        self.scratch.mkdir()
        self.apex = self.work / "oracle.apex.fixture"
        self.elf = self.work / "oracle.elf.fixture"
        self.apex.write_bytes(b"HOST UNIT FIXTURE ONLY: not an APEX\n")
        # Exercise binary-safe retrieval, not merely line-oriented text output.
        self.elf.write_bytes(b"HOST UNIT FIXTURE ONLY: not an ELF\n\x00\x01\x7f\x80\xff\r\n\n")
        source = (HERE / "fake_tools.py").read_text(encoding="utf-8").split("\n", 1)[1]
        for name in ("adb", "readelf", "unit-fixture-cat", "unit-fixture-hello"):
            tool = self.bin / name
            tool.write_text(f"#!{sys.executable}\n" + source, encoding="utf-8")
            tool.chmod(0o700)
        # Do not inherit ADB settings, shell startup files/functions or a custom
        # PATH. Both tool names resolve to the temporary fakes, with no fallback.
        self.env = {
            "PATH": os.pathsep.join((str(self.bin), str(Path(sys.executable).parent), os.defpath)),
            "HOME": str(self.work),
            "LC_ALL": "C",
            "TMPDIR": str(self.scratch),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ANDRIX_DEVICE_UNIT_FIXTURE": str(self.work),
            "ANDRIX_EXPECTED_APEX": str(self.apex),
            "ANDRIX_EXPECTED_PROOF_ELF": str(self.elf),
            "ANDRIX_EXPECTED_FINGERPRINT": "host-unit-fixture/not-a-runtime-fingerprint",
        }

    def run_case(self, **overrides):
        case = {
            "host_bash": self.bash,
            "apex_xml": apex_xml(
                '<apex-info moduleName="com.android.runtime" isActive="true" isFactory="true"/>',
                apex_row(),
            ),
        }
        case.update(overrides)
        (self.work / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (self.work / "calls.jsonl").write_text("", encoding="utf-8")
        result = subprocess.run(
            [self.bash, str(DEVICE)], cwd=self.work, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        self.calls = [json.loads(line) for line in
                      (self.work / "calls.jsonl").read_text(encoding="utf-8").splitlines()]
        self.adb_calls = [call[1:] for call in self.calls if call[0] == "adb"]
        self.assertNotIn("HOST UNIT FIXTURE ERROR", result.stderr, self.diagnostic(result))
        self.assertEqual(list(self.scratch.iterdir()), [], "device.sh must clean temporary captures")
        return result

    @staticmethod
    def diagnostic(result):
        return f"HOST UNIT FIXTURE output only (status {result.returncode}):\n{result.stdout}\n{result.stderr}"

    def assert_pass(self, result):
        self.assertEqual(result.returncode, 0, self.diagnostic(result))
        self.assertIn("PASS: fingerprint=host-unit-fixture/", result.stdout)
        self.assertIn(["logcat", "-b", "all", "-d"], self.adb_calls)

    def assert_failure(self, result, message):
        self.assertNotEqual(result.returncode, 0, self.diagnostic(result))
        self.assertIn(message, result.stderr, self.diagnostic(result))
        self.assertNotIn("PASS: fingerprint=", result.stdout)

    def test_bash_syntax(self):
        for script in (DEVICE, HOST_ELF):
            with self.subTest(script=script.name):
                result = subprocess.run([self.bash, "-n", str(script)], env=self.env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_successful_command_flow(self):
        self.assert_pass(self.run_case())
        pulls = [call[1] for call in self.adb_calls if call[0] == "pull"]
        self.assertEqual(pulls, ["/apex/apex-info-list.xml", FACTORY])
        executions = [call[1] for call in self.adb_calls if call[0] == "exec-out"]
        self.assertEqual(len(executions), 4)
        for prefix, command in zip((f"cat {USR}", f"cat {APEX}", USR, APEX), executions):
            self.assertTrue(command == prefix or command.startswith(prefix + " "), command)
        self.assertEqual([call[1] for call in self.calls if call[0] == "unit-fixture-cat"], [USR, APEX])
        self.assertEqual([call[1] for call in self.calls if call[0] == "unit-fixture-hello"], [USR, APEX])
        self.assertEqual(sum(call[:2] == ["readelf", "-hW"] for call in self.calls), 3)

    def test_apex_metadata_and_container_pull_failures_stop_before_payload_reads(self):
        for remote in ("/apex/apex-info-list.xml", FACTORY):
            with self.subTest(remote=remote):
                result = self.run_case(pull_failures=[remote])
                self.assert_failure(result, "cannot pull")
                self.assertIn(remote, result.stderr)
                self.assertFalse(any(call[0] == "exec-out" for call in self.adb_calls))

    def test_payload_read_nonzero_adb_status_even_with_exact_bytes(self):
        payload = self.elf.read_bytes()
        for remote in (USR, APEX):
            for output in (b"", payload[:len(payload) // 2], payload):
                with self.subTest(remote=remote, output=output):
                    result = self.run_case(payload_reads={remote: {
                        "stdout_hex": output.hex(), "adb_status": 9,
                    }})
                    self.assert_failure(result, f"cannot read {remote} via adb exec-out")
                    self.assertFalse(any(call[0] == "unit-fixture-hello" for call in self.calls))

    def test_payload_read_nonzero_remote_status_even_with_exact_bytes_and_adb_success(self):
        payload = self.elf.read_bytes()
        for remote in (USR, APEX):
            for output in (b"", payload[:len(payload) // 2], payload):
                with self.subTest(remote=remote, output=output):
                    # The fake runs the real shell guard, but discards its status.
                    # Complete bytes + failed cat must not become a passing hash.
                    result = self.run_case(payload_reads={remote: {
                        "stdout_hex": output.hex(), "exit_status": 7, "adb_status": 0,
                    }})
                    self.assert_failure(result, f"{remote} differs from bin/andrix-hello")
                    self.assertIn(["unit-fixture-cat", remote], self.calls)
                    self.assertFalse(any(call[0] == "unit-fixture-hello" for call in self.calls))

    def test_payload_reads_require_exact_bytes_for_each_path(self):
        payload = self.elf.read_bytes()
        outputs = (
            b"", payload[:len(payload) // 2],                  # Empty/partial read.
            bytes([payload[0] ^ 1]) + payload[1:],             # Wrong, same size.
            payload + b"\x00",                                # Extra bytes.
            payload.replace(b"\r\n", b"\n"), payload.rstrip(b"\n"),
            payload.replace(b"\x00", b""),                     # Lossy text handling.
        )
        for remote in (USR, APEX):
            for output in outputs:
                with self.subTest(remote=remote, output=output):
                    result = self.run_case(payload_reads={remote: {"stdout_hex": output.hex()}})
                    self.assert_failure(result, f"{remote} differs from bin/andrix-hello")
                    self.assertFalse(any(call[0] == "unit-fixture-hello" for call in self.calls))

    def test_remote_provisioning_must_be_locally_disabled(self):
        for properties in (
                {"remote_provisioning.hostname": "preprod-remoteprovisioning.googleapis.com"},
                {"remote_provisioning.hostname": "unapproved.example"},
                {"remote_provisioning.tee.rkp_only": "true"},
                {"remote_provisioning.tee.rkp_only": ""}):
            with self.subTest(properties=properties):
                self.assert_failure(self.run_case(properties=properties),
                                    "not configured for local keys only")
                self.assertFalse(any(call[0] in ("pull", "exec-out") for call in self.adb_calls))

    def test_active_updated_plus_inactive_factory_does_not_cross_match(self):
        # The old grep concatenated these rows: active=true came from the
        # updated row, factory=true and the only preinstalled path from the
        # inactive row. It could then pull the expected factory and falsely pass.
        xml = apex_xml(apex_row(factory="false", path=None), apex_row(active="false"))
        self.assert_failure(self.run_case(apex_xml=xml), "not an active factory APEX")
        self.assertEqual([call[1] for call in self.adb_calls if call[0] == "pull"],
                         ["/apex/apex-info-list.xml"])

    def test_rejects_malformed_or_ambiguous_xml(self):
        cases = (
            ("truncated", "<apex-info-list>\n" + apex_row(), "cannot parse apex-info-list.xml"),
            ("garbage", "not XML", "cannot parse apex-info-list.xml"),
            ("wrong root", "<wrong>" + apex_row() + "</wrong>", "unexpected apex-info-list.xml root"),
            ("duplicate factory", apex_xml(apex_row(), apex_row()), "exactly one active"),
            ("two active kinds", apex_xml(apex_row(), apex_row(factory="false")), "exactly one active"),
            ("missing module", apex_xml(), "exactly one active"),
            ("inactive only", apex_xml(apex_row(active="false")), "exactly one active"),
        )
        for name, xml, message in cases:
            with self.subTest(case=name):
                self.assert_failure(self.run_case(apex_xml=xml), message)
                self.assertEqual([call[1] for call in self.adb_calls if call[0] == "pull"],
                                 ["/apex/apex-info-list.xml"])

    def test_active_path_is_required_and_not_trimmed(self):
        for path in (None, "", "   ", FACTORY + "&#10;", FACTORY + "&#13;"):
            with self.subTest(path=path):
                self.assert_failure(self.run_case(apex_xml=apex_xml(apex_row(path=path))),
                                    "preinstalledModulePath")

    def test_multiline_single_quoted_xml_and_same_row_path(self):
        active = ("<apex-info\n moduleName='dev.andrix.usr'\n isActive='true'\n"
                  f" isFactory='true'\n preinstalledModulePath='{FACTORY}'/>")
        inactive = apex_row(active="false", path="/must-not-pull-inactive.apex")
        for rows in ((inactive, active), (active, inactive)):
            with self.subTest(rows=rows):
                self.assert_pass(self.run_case(apex_xml=apex_xml(*rows)))
                self.assertIn(FACTORY, [call[1] for call in self.adb_calls if call[0] == "pull"])

    def test_output_is_byte_exact_for_each_path(self):
        for remote in (USR, APEX):
            for output in (b"andrix\n\n", b"andrix\r\n", b"andrix\n\r", b"andrix", b"andrix\x00\n", b""):
                with self.subTest(remote=remote, output=output):
                    result = self.run_case(hello={remote: {"stdout_hex": output.hex()}})
                    self.assert_failure(result, f"exact andrix-hello output mismatch for {remote}")

    def test_nonzero_executable_status_even_with_exact_stdout_and_adb_success(self):
        for remote in (USR, APEX):
            with self.subTest(remote=remote):
                result = self.run_case(hello={remote: {"exit_status": 7}})
                self.assert_failure(result, f"exact andrix-hello output mismatch for {remote}")
                self.assertIn(["unit-fixture-hello", remote], self.calls)

    def test_nonzero_adb_status_even_with_exact_stdout(self):
        for remote in (USR, APEX):
            with self.subTest(remote=remote):
                result = self.run_case(hello={remote: {"adb_status": 9}})
                self.assert_failure(result, f"adb exec-out failed for {remote}")

    def test_logcat_failure_is_not_no_denials(self):
        for log in ("", "avc: denied { execute } path=/usr/bin/andrix-hello\n"):
            with self.subTest(log=log):
                result = self.run_case(logcat_status=1, logcat=log)
                self.assert_failure(result, "cannot retrieve device logs")
                self.assertNotIn("relevant SELinux denials found", result.stderr)

    def test_relevant_avc_fails_and_unrelated_log_does_not(self):
        for detail in ("comm=andrix-hello", "path=/usr/bin/tool", "name=dev.andrix.usr"):
            with self.subTest(detail=detail):
                line = f"avc: denied {{ execute }} {detail}\n"
                result = self.run_case(logcat=line)
                self.assert_failure(result, "relevant SELinux denials found")
                self.assertIn(line, result.stderr)
        self.assert_pass(self.run_case(logcat="avc: denied { read } name=unrelated\nandrix informational\n"))

    def test_android_os_release_is_accepted(self):
        for identity in ("ID=android\n", 'NAME="Android"\nID="android"\n', "# fixture\nID='android'\n"):
            with self.subTest(identity=identity):
                self.assert_pass(self.run_case(os_release=identity))
                self.assertIn("/etc/os-release", [call[1] for call in self.adb_calls if call[0] == "pull"])

    def test_foreign_missing_duplicate_and_malformed_os_release_id_fail(self):
        for identity in ("ID=debian\n", "ID=ubuntu\nID_LIKE=android\n", "ID=Android\n",
                         "NAME=Android\n", "", "ID=android\nID=debian\n", "ID=android\nID=android\n",
                         'ID="android\n', "ID=android extra\n"):
            with self.subTest(identity=identity):
                self.assert_failure(self.run_case(os_release=identity), "/etc/os-release")

    def test_os_release_is_not_sourced(self):
        marker = self.work / "must-not-be-created"
        identity = f'ID="$(touch {marker})"\n'
        self.assert_failure(self.run_case(os_release=identity), "/etc/os-release")
        self.assertFalse(marker.exists(), "device os-release must never execute host commands")
        self.assert_pass(self.run_case(os_release=f"ID=android\nUNUSED=$(touch {marker})\n"))
        self.assertFalse(marker.exists(), "unrelated os-release fields must not execute either")

    def test_identity_inspection_fails_closed(self):
        cases = (
            ({"debian_version": True, "os_release": "ID=android\n"}, "foreign distro identity"),
            ({"identity_probe_status": 1}, "cannot inspect /etc distro identity"),
            ({"identity_probe_response": ""}, "unexpected /etc identity probe response"),
            ({"os_release": "ID=android\n", "pull_failures": ["/etc/os-release"]}, "cannot pull /etc/os-release"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides):
                self.assert_failure(self.run_case(**overrides), message)

    def test_existing_provenance_abi_mount_hash_and_selinux_gates_remain(self):
        cases = (
            ({"properties": {"ro.build.fingerprint": "wrong"}}, "fingerprint does not match"),
            ({"properties": {"ro.product.cpu.abilist": "arm64-v8a,armeabi-v7a"}}, "not ARM64-only"),
            ({"properties": {"ro.product.cpu.abilist64": ""}}, "not ARM64-only"),
            ({"properties": {"ro.product.cpu.abilist32": "armeabi-v7a"}}, "not ARM64-only"),
            ({"bad_apex_hash": True}, "factory APEX differs"),
            ({"bad_elf_hash": USR}, "differs from bin/andrix-hello"),
            ({"bad_elf_hash": APEX}, "differs from bin/andrix-hello"),
            ({"stats": {APEX: "42:5678"}}, "not the same mounted file"),
            ({"mountinfo": "100 99 7:1 / /usr rw - ext4 /dev/fixture rw"}, "not read-only"),
            ({"mountinfo": ""}, "not a mountpoint"),
            ({"etc_target": "/foreign/etc"}, "not Android's /system/etc symlink"),
            ({"enforcing": "Permissive"}, "want Enforcing"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides):
                self.assert_failure(self.run_case(**overrides), message)


if __name__ == "__main__":
    print("HOST UNIT FIXTURES ONLY — no milestone/artifact/runtime evidence", file=sys.stderr)
    unittest.main(verbosity=2)
