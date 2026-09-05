#!/usr/bin/env python3
"""Host-only mocks: no real procfs, devices, ioctls, hardware or network.

Run: python3 -B -m unittest discover -s scripts/proof/tests -p test_host_preflight.py
"""
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("host_preflight", Path(__file__).resolve().parents[1] / "host_preflight.py")
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)
ELF = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x03\x00\xb7\x00"


class PreflightTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        p = stack.enter_context
        self.system = p(mock.patch.object(host.platform, "system", return_value="Linux"))
        p(mock.patch.object(host.platform, "release", return_value="fixture-kernel"))
        self.machine = p(mock.patch.object(host.platform, "machine", return_value="aarch64"))
        self.pointer = p(mock.patch.object(host.struct, "calcsize", return_value=8))
        p(mock.patch.object(host.sys, "byteorder", "little"))
        self.page = p(mock.patch.object(host.os, "sysconf", return_value=16384, create=True))
        self.cpu = p(mock.patch.object(host.os, "cpu_count", return_value=8))
        self.affinity = p(mock.patch.object(host.os, "sched_getaffinity", return_value={3, 1}, create=True))
        self.files = {"/proc/meminfo": "MemTotal: 1024 kB\nMemAvailable: 512 kB\n",
                      "/proc/self/status": "Name:\tpython3\nCapEff:\t0000000000001000\n"}
        p(mock.patch.object(host.Path, "read_text", autospec=True, side_effect=lambda path: self.files[str(path)]))
        self.elf = p(mock.patch.object(host.Path, "open", mock.mock_open(read_data=ELF)))
        self.resolve = p(mock.patch.object(host.Path, "resolve", autospec=True, return_value=Path("/work")))
        self.is_dir = p(mock.patch.object(host.Path, "is_dir", return_value=True))
        self.disk = p(mock.patch.object(host.shutil, "disk_usage", return_value=SimpleNamespace(free=123)))
        self.open = p(mock.patch.object(host.os, "open", side_effect=AssertionError("unexpected device open")))
        self.close = p(mock.patch.object(host.os, "close", side_effect=AssertionError("unexpected close")))
        p(mock.patch.object(host.os, "O_CLOEXEC", 0x80000, create=True))
        self.ioctl = mock.Mock(side_effect=AssertionError("unexpected ioctl"))
        p(mock.patch.dict(sys.modules, {"fcntl": SimpleNamespace(ioctl=self.ioctl)}))

    def allow_probes(self):
        for target in (self.open, self.close, self.ioctl):
            target.reset_mock()
        self.open.side_effect = [10, 20, 30]
        self.close.side_effect = None
        self.ioctl.side_effect = [12, 11]

    def test_default_json_is_not_run_with_all_observations(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(host.main(["--work-dir", "/chosen"]), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertFalse(report["runtime_qualified"])
        self.assertEqual({p["status"] for p in report["probes"].values()}, {"NOT_RUN"})
        facts = report["host"]
        for key, value in {"system": "Linux", "kernel_release": "fixture-kernel", "architecture": "aarch64",
                           "python_pointer_bits": 64, "python_byteorder": "little", "process_elf_machine": 183,
                           "page_size_bytes": 16384, "cpu_count": 8, "cpu_affinity": [1, 3],
                           "memory_kib": {"MemTotal": 1024, "MemAvailable": 512},
                           "work_directory": {"path": "/work", "free_bytes": 123}}.items():
            self.assertEqual(facts[key], value)
        self.assertTrue(facts["network_capability"]["cap_net_admin_effective"])
        self.assertEqual(facts["network_capability"]["cap_eff_hex"], "0000000000001000")
        self.assertEqual(report["observation_errors"], [])
        self.assertGreaterEqual(len(report["still_unproved"]), 4)
        self.resolve.assert_called_once_with(Path("/chosen"), strict=True)
        self.open.assert_not_called()
        self.ioctl.assert_not_called()

    def test_opt_in_does_only_empty_vm_and_open_close(self):
        self.allow_probes()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(host.main(["--probe-kvm"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "LIMITED_PROBES_PASSED")
        self.assertFalse(report["runtime_qualified"])
        self.assertEqual(report["probes"]["/dev/kvm"], {"status": "PASS", "api_version": 12, "empty_vm_created": True})
        self.assertEqual(self.open.call_args_list, [mock.call(path, host.os.O_RDWR | host.os.O_CLOEXEC)
                                                  for path in host.DEVICES])
        self.assertEqual(self.ioctl.call_args_list, [mock.call(10, 0xAE00, 0), mock.call(10, 0xAE01, 0)])
        self.assertEqual(self.close.call_args_list, [mock.call(fd) for fd in (11, 10, 20, 30)])

    def test_wrong_os_arch_width_or_endian_never_opens_devices(self):
        for system, machine, width, endian in (("Darwin", "arm64", 8, "little"),
                                              ("Windows", "arm64", 8, "little"),
                                              ("Linux", "x86_64", 8, "little"),
                                              ("Linux", "armv7l", 4, "little"),
                                              ("Linux", "aarch64", 4, "little"),
                                              ("Linux", "aarch64", 8, "big")):
            with self.subTest(system=system, machine=machine, width=width, endian=endian):
                self.system.return_value, self.machine.return_value = system, machine
                self.pointer.return_value = width
                with mock.patch.object(host.sys, "byteorder", endian):
                    report = host.build_report(probe_kvm=True)
                self.assertEqual(report["status"], "FAIL")
                self.assertFalse(report["native_linux_arm64_check"])
                self.assertEqual({p["status"] for p in report["probes"].values()}, {"NOT_RUN"})
                self.open.assert_not_called()
                self.ioctl.assert_not_called()

    def test_process_elf_must_also_be_arm64(self):
        for data in (b"", ELF[:-1], ELF[:-2] + b"\x3e\0", ELF[:4] + b"\x01" + ELF[5:]):
            with self.subTest(data=data):
                self.elf.return_value.read.return_value = data
                self.assertEqual(host.build_report(probe_kvm=True)["status"], "FAIL")
                self.open.assert_not_called()

    def test_no_resource_thresholds_or_capability_authority_claim(self):
        self.files["/proc/meminfo"] = "MemTotal: 1 kB\nMemAvailable: 0 kB\n"
        self.files["/proc/self/status"] = "CapEff: 0000000000000000\n"
        self.disk.return_value.free, self.cpu.return_value, self.affinity.return_value = 0, 1, {0}
        for page_size in (4096, 16384, 65536):
            with self.subTest(page_size=page_size):
                self.page.return_value = page_size
                self.allow_probes()
                report = host.build_report(probe_kvm=True)
                self.assertEqual(report["status"], "LIMITED_PROBES_PASSED")
                self.assertFalse(report["host"]["network_capability"]["cap_net_admin_effective"])
                self.assertFalse(report["runtime_qualified"])

    def test_missing_or_malformed_observations_block_probes(self):
        for path, text in (("/proc/meminfo", "MemTotal: 1 kB\n"),
                           ("/proc/meminfo", "MemTotal: 1 MB\nMemAvailable: 0 kB\n"),
                           ("/proc/self/status", "Name: python\n"),
                           ("/proc/self/status", "CapEff: not-hex\n")):
            with self.subTest(path=path, text=text), mock.patch.dict(self.files, {path: text}):
                report = host.build_report(probe_kvm=True)
                self.assertEqual(report["status"], "FAIL")
                self.assertTrue(report["observation_errors"])
                self.open.assert_not_called()
        self.is_dir.return_value = False
        self.assertEqual(host.build_report(probe_kvm=True)["status"], "FAIL")
        self.resolve.side_effect = RuntimeError("fixture symlink loop")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(host.main(["--probe-kvm"]), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "FAIL")
        self.open.assert_not_called()

    def test_device_open_errors_fail_closed(self):
        for index, path in enumerate(host.DEVICES):
            with self.subTest(path=path):
                self.allow_probes()
                opens = [10, 20, 30]
                opens[index] = PermissionError(13, "fixture denied")
                self.open.side_effect = opens
                report = host.build_report(probe_kvm=True)
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(report["probes"][path]["status"], "FAIL")
                self.assertIn("fixture denied", report["probes"][path]["error"])

    def test_api_and_create_errors_close_kvm_without_vcpu(self):
        for replies in ([OSError(5, "API error")], [11], [13], [12, OSError(5, "create error")], [12, -1]):
            with self.subTest(replies=replies):
                self.allow_probes()
                self.ioctl.side_effect = replies
                report = host.build_report(probe_kvm=True)
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(report["probes"]["/dev/kvm"]["status"], "FAIL")
                self.assertEqual(self.close.call_args_list, [mock.call(fd) for fd in (10, 20, 30)])
                self.assertEqual(self.ioctl.call_count, len(replies))

    def test_each_close_failure_fails_but_other_descriptors_are_closed(self):
        for bad_fd, path in ((11, "/dev/kvm"), (10, "/dev/kvm"), (20, "/dev/vhost-vsock"), (30, "/dev/net/tun")):
            with self.subTest(fd=bad_fd):
                self.allow_probes()
                def close(fd):
                    if fd == bad_fd:
                        raise OSError(5, "close error")
                self.close.side_effect = close
                report = host.build_report(probe_kvm=True)
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(report["probes"][path]["status"], "FAIL")
                self.assertEqual(self.close.call_args_list, [mock.call(fd) for fd in (11, 10, 20, 30)])

    def test_zero_is_a_valid_vm_descriptor(self):
        self.allow_probes()
        self.ioctl.side_effect = [12, 0]
        self.assertEqual(host.build_report(probe_kvm=True)["status"], "LIMITED_PROBES_PASSED")
        self.close.assert_any_call(0)


if __name__ == "__main__":
    unittest.main()
