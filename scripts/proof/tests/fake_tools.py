#!/usr/bin/env python3
"""HOST UNIT FIXTURES ONLY: fake adb/readelf/cat/hello, not device or artifact evidence.

The test runner copies this into its temporary bin directory under each tool
name. Unknown commands fail; nothing delegates to real adb or real readelf.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

USR = "/usr/bin/andrix-hello"
APEX = "/apex/dev.andrix.usr/bin/andrix-hello"
FACTORY = "/system_ext/apex/dev.andrix.usr.apex"
IDENTITY_PROBE = (
    "if test -e /etc/debian_version; then echo debian; "
    "elif test -e /etc/os-release; then echo os-release; else echo absent; fi"
)


def fail(message):
    sys.exit(f"HOST UNIT FIXTURE ERROR: {message}")


def confined_file(root, path):
    path = Path(path).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"refusing a path outside the temporary fixture: {path}")
    return path


def fake_adb(root, case, args):
    if args == ["get-state"]:
        print("device")  # Fabricated parser/command-flow response, not discovery.
        return 0
    if args[:1] == ["pull"] and len(args) == 3:
        remote, local = args[1:]
        local = confined_file(root, local)
        if remote in case.get("pull_failures", []):
            return 1
        if remote == "/apex/apex-info-list.xml":
            local.write_text(case["apex_xml"], encoding="utf-8")
        elif remote == FACTORY:
            shutil.copyfile(root / "oracle.apex.fixture", local)
            if case.get("bad_apex_hash"):
                local.write_bytes(b"HOST UNIT FIXTURE: mismatched dummy APEX\n")
        elif remote == "/etc/os-release" and case.get("os_release") is not None:
            local.write_text(case["os_release"], encoding="utf-8")
        else:
            fail(f"unexpected pull: {args!r}")
        return 0
    if args[:2] == ["shell", "getprop"] and len(args) == 3:
        properties = {
            "ro.build.fingerprint": "host-unit-fixture/not-a-runtime-fingerprint",
            "ro.product.cpu.abilist": "arm64-v8a",
            "ro.product.cpu.abilist64": "arm64-v8a",
            "ro.product.cpu.abilist32": "",
            "remote_provisioning.hostname": "",
            "remote_provisioning.tee.rkp_only": "false",
        }
        properties.update(case.get("properties", {}))
        if args[2] not in properties:
            fail(f"unexpected property: {args!r}")
        print(properties[args[2]])
        return 0
    if args[:5] == ["shell", "toybox", "stat", "-c", "%d:%i"] and len(args) == 6:
        if args[5] not in (USR, APEX):
            fail(f"unexpected stat: {args!r}")
        print(case.get("stats", {}).get(args[5], "42:1234"))
        return 0
    if args == ["shell", "cat", "/proc/self/mountinfo"]:
        print(case.get("mountinfo", "100 99 7:1 / /usr ro,relatime - ext4 /dev/fixture ro"))
        return 0
    if args[:1] == ["exec-out"] and len(args) == 2:
        command = args[1]
        for remote in (USR, APEX):
            if command == f"cat {remote}" or command.startswith(f"cat {remote} "):
                prefix = f"cat {remote}"
                tool = "unit-fixture-cat"
                response = case.get("payload_reads", {}).get(remote, {})
                break
            if command == remote or command.startswith(remote + " "):
                prefix = remote
                tool = "unit-fixture-hello"
                response = case.get("hello", {}).get(remote, {})
                break
        else:
            fail(f"unexpected exec-out: {args!r}")
        # Execute only the host fixture in place of cat/the absolute device path.
        # Deliberately discard the shell's status, like exec-out without shell-v2
        # exit reporting. This tests the production script's remote failure guards,
        # rather than pretending adb always forwards the read/executable exit code.
        replacement = shlex.quote(str(root / "bin" / tool))
        command = replacement + " " + shlex.quote(remote) + command[len(prefix):]
        subprocess.run([case["host_bash"], "-c", command], check=False)
        return response.get("adb_status", 0)
    if args == ["shell", "readlink", "/etc"]:
        print(case.get("etc_target", "/system/etc"))
        return 0
    if args == ["shell", IDENTITY_PROBE]:
        if case.get("identity_probe_status", 0):
            return case["identity_probe_status"]
        identity = "debian" if case.get("debian_version") else (
            "os-release" if case.get("os_release") is not None else "absent"
        )
        print(case.get("identity_probe_response", identity))
        return 0
    if args == ["shell", "getenforce"]:
        print(case.get("enforcing", "Enforcing"))
        return 0
    if args == ["shell", "getconf", "PAGESIZE"]:
        print("16384")
        return 0
    if args == ["logcat", "-b", "all", "-d"]:
        sys.stdout.write(case.get("logcat", ""))
        return case.get("logcat_status", 0)
    fail(f"unexpected adb command: {args!r}")


def fake_readelf(root, args):
    if len(args) != 2 or not confined_file(root, args[-1]).is_file():
        fail(f"unexpected readelf input: {args!r}")
    # These strings only let the command-flow test reach the device checks.
    # The input is a labelled dummy file, emphatically NOT an ELF or ABI oracle.
    if args[0] == "-hW":
        print("  Machine:                           AArch64")
    elif args[0] == "-lW":
        print("      [Requesting program interpreter: /system/bin/linker64]")
        print("  LOAD 0x000000 0x000000 0x000000 0x001000 0x001000 R E 0x4000")
    elif args[0] == "-d":
        print(" 0x0000000000000001 (NEEDED) Shared library: [libc.so]")
    else:
        fail(f"unexpected readelf command: {args!r}")
    return 0


def main():
    root = Path(os.environ["ANDRIX_DEVICE_UNIT_FIXTURE"]).resolve()
    case = json.loads((root / "case.json").read_text(encoding="utf-8"))
    tool = Path(sys.argv[0]).name
    args = sys.argv[1:]
    with (root / "calls.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps([tool, *args]) + "\n")
    if tool == "adb":
        return fake_adb(root, case, args)
    if tool == "readelf":
        return fake_readelf(root, args)
    if tool == "unit-fixture-cat" and args in ([USR], [APEX]):
        payload_read = case.get("payload_reads", {}).get(args[0], {})
        payload = (root / "oracle.elf.fixture").read_bytes()
        if case.get("bad_elf_hash") == args[0]:
            payload = b"HOST UNIT FIXTURE: mismatched dummy ELF\n"
        sys.stdout.buffer.write(bytes.fromhex(payload_read.get("stdout_hex", payload.hex())))
        return payload_read.get("exit_status", 0)
    if tool == "unit-fixture-hello" and args in ([USR], [APEX]):
        hello = case.get("hello", {}).get(args[0], {})
        sys.stdout.buffer.write(bytes.fromhex(hello.get("stdout_hex", b"andrix\n".hex())))
        return hello.get("exit_status", 0)
    fail(f"unexpected fixture tool: {tool!r} {args!r}")


if __name__ == "__main__":
    sys.exit(main())
