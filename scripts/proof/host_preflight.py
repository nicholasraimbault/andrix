#!/usr/bin/env python3
"""Local host observations and opt-in empty-VM/device probes; never boot readiness."""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys

KVM_GET_API_VERSION = 0xAE00  # Linux _IO(KVMIO, 0x00)
KVM_CREATE_VM = 0xAE01       # Linux _IO(KVMIO, 0x01), type 0: default ARM IPA size
DEVICES = ("/dev/kvm", "/dev/vhost-vsock", "/dev/net/tun")
STILL_UNPROVED = [
    "Complete matching host-package/loader/library compatibility, including host page size.",
    "Real KVM vCPU execution, interrupts/GIC, VMM backends and working vsock/TAP.",
    "Networking/capture authority (namespaces, policy, provider), configuration and controlled external egress.",
    "Android gates: P3 provenance/static no-Google review; capture before first boot; "
    "P4 APEX, /usr, Bionic, enforcing policy and no-Google runtime; P5 ordinary-app boundary; P6 review.",
    "Native bare-metal/provider identity: local OS/ELF checks are not hardware attestation.",
]


def process_elf_machine():
    # Inspect the running executable, not a PATH command or the Cuttlefish package.
    with Path("/proc/self/exe").open("rb") as source:
        header = source.read(20)
    if len(header) != 20 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("running process is not ELF64 little-endian v1")
    return struct.unpack_from("<H", header, 18)[0]


def proc_fields(path):
    return dict(line.split(":", 1) for line in Path(path).read_text().splitlines() if ":" in line)


def memory_kib():
    fields = proc_fields("/proc/meminfo")
    result = {}
    for name in ("MemTotal", "MemAvailable"):
        parts = fields[name].split()
        if len(parts) != 2 or not parts[0].isdigit() or parts[1] != "kB":
            raise ValueError("invalid /proc/meminfo " + name)
        result[name] = int(parts[0])  # Linux procfs kB means KiB.
    return result


def network_capability():
    value = proc_fields("/proc/self/status")["CapEff"].strip()
    if not re.fullmatch(r"[0-9a-fA-F]{16}", value):
        raise ValueError("invalid CapEff")
    return {"cap_eff_hex": value, "cap_net_admin_effective": bool(int(value, 16) & (1 << 12)),
            "scope": "Current process only; namespace/policy/external authority unproved."}


def work_space(directory):
    path = Path(directory).resolve(strict=True)
    if not path.is_dir():
        raise ValueError("work directory must already exist and be a directory")
    return {"path": str(path), "free_bytes": shutil.disk_usage(path).free}


def probe_device(path):
    result = {"status": "FAIL"}
    try:
        with ExitStack() as cleanup:
            fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
            cleanup.callback(os.close, fd)
            if path == "/dev/kvm":
                import fcntl  # Never needed on unsupported OSes or without opt-in.
                api = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
                result["api_version"] = api
                if api != 12:
                    raise ValueError("KVM API must be 12")
                vm = fcntl.ioctl(fd, KVM_CREATE_VM, 0)
                if vm < 0:
                    raise ValueError("KVM_CREATE_VM returned an invalid fd")
                cleanup.callback(os.close, vm)
                result["empty_vm_created"] = True
                # No vCPU, memory, IRQ setup, KVM_RUN or network ioctls.
        result["status"] = "PASS"  # Includes successful close of all descriptors.
    except (OSError, ValueError, ImportError) as error:
        result["error"] = str(error)
    return result


def build_report(directory=".", probe_kvm=False):
    errors = []

    def observe(label, read):
        try:
            return read()
        except (OSError, ValueError, KeyError, AttributeError, RuntimeError) as error:
            errors.append(label + ": " + str(error))
            return None

    host = {"system": platform.system(), "kernel_release": platform.release(),
            "architecture": platform.machine(), "python_pointer_bits": struct.calcsize("P") * 8,
            "python_byteorder": sys.byteorder}
    linux = host["system"] == "Linux"
    host["process_elf_machine"] = observe("process ELF", process_elf_machine) if linux else None
    native = (linux and host["architecture"].lower() in ("aarch64", "arm64")
              and host["python_pointer_bits"] == 64 and host["python_byteorder"] == "little"
              and host["process_elf_machine"] == 183)  # EM_AARCH64
    if not native:
        errors.append("Requires native Linux ARM64 with a 64-bit little-endian Python process.")
    host["page_size_bytes"] = observe("page size", lambda: os.sysconf("SC_PAGE_SIZE"))
    host["cpu_count"] = observe("CPU count", os.cpu_count)
    if host["cpu_count"] is None:
        errors.append("CPU count unavailable")
    host["cpu_affinity"] = observe("CPU affinity", lambda: sorted(os.sched_getaffinity(0)))
    host["memory_kib"] = observe("memory", memory_kib) if linux else None
    host["network_capability"] = observe("CapEff", network_capability) if linux else None
    host["work_directory"] = observe("work directory", lambda: work_space(directory))

    reason = "not requested" if not probe_kvm else "host observations/OS/architecture guard failed"
    probes = {path: {"status": "NOT_RUN", "reason": reason} for path in DEVICES}
    # All observations and the OS/architecture guard precede EVERY device open.
    if probe_kvm and native and not errors:
        probes = {path: probe_device(path) for path in DEVICES}
    failed = bool(errors) or any(item["status"] == "FAIL" for item in probes.values())
    status = "FAIL" if failed else ("LIMITED_PROBES_PASSED" if probe_kvm else "NOT_RUN")
    return {"schema": 1, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "Local observations, KVM API/empty VM and device open/close only",
            "status": status, "runtime_qualified": False, "probe_kvm_requested": probe_kvm,
            "native_linux_arm64_check": native, "host": host, "observation_errors": errors,
            "probes": probes, "still_unproved": STILL_UNPROVED}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", default=".", help="Existing directory to measure; never written.")
    parser.add_argument("--probe-kvm", action="store_true",
                        help="Open KVM, check API 12, create/close an EMPTY VM; "
                             "also open/close vhost-vsock and tun. No vCPU or network ioctls.")
    args = parser.parse_args(argv)
    report = build_report(args.work_dir, args.probe_kvm)
    print(json.dumps(report, indent=2, sort_keys=True))
    return {"LIMITED_PROBES_PASSED": 0, "FAIL": 1, "NOT_RUN": 2}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
