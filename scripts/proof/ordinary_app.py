#!/usr/bin/env python3
"""Opt-in P5 only. No device is contacted on import or by the unit tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import zipfile

PACKAGE = "dev.andrix.proof.p5"
INSTRUMENTATION = PACKAGE + "/" + PACKAGE + ".P5Instrumentation"
PLATFORM_PROFILES = ("aosp17", "grapheneos-2026081300")
GOS_PRODUCT = "andrix_gos_cf_arm64_only_phone"
GOS_IMPLICIT_PERMISSION = "android.permission.OTHER_SENSORS"
NATIVE_FIELDS = set("""
status error_stage error_errno cleanup_errno uid euid gid egid selinux cap_eff mappings page_size
source_path source_mode source_uid source_size source_dev_inode copy_path copy_dir_mode copy_mode
copy_uid copy_size copy_mount_noexec byte_identity_before byte_identity_after
control_outcome control_stage control_errno control_exit control_signal control_reaped
copy_outcome copy_stage copy_errno copy_exit copy_signal copy_reaped
""".split())


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def validate_platform_profile(profile, fingerprint):
    require(profile in PLATFORM_PROFILES, "unknown platform profile")
    gos_prefix = "Andrix/" + GOS_PRODUCT + "/andrix_cf_arm64_only:17/"
    if profile == "grapheneos-2026081300":
        require(re.fullmatch(re.escape(gos_prefix)
                             + r"[^/\r\n]+/andrix\.gos\.2026081300\.[0-9a-f]{7,40}:userdebug/test-keys",
                             fingerprint) is not None,
                "GrapheneOS profile requires the exact pinned ARM64 proof image family")
    else:
        require(not fingerprint.startswith(gos_prefix),
                "GrapheneOS proof image requires an explicit platform profile")


def expected_pm_permissions(profile):
    require(profile in PLATFORM_PROFILES, "unknown platform profile")
    return [GOS_IMPLICIT_PERMISSION] if profile == "grapheneos-2026081300" else []


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def elf_arm64(data, executable):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "not ELF64 little-endian v1")
    kind, machine = struct.unpack_from("<HH", data, 16)
    require(kind == 3 and machine == 183, "not ARM64 ET_DYN (PIE/shared library)")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and 0 < count < 1024 and offset >= 64
            and offset + size * count <= len(data), "bad ELF program headers")
    interpreters = []
    for index in range(count):
        header = offset + index * size
        if struct.unpack_from("<I", data, header)[0] == 3:  # PT_INTERP
            start = struct.unpack_from("<Q", data, header + 8)[0]
            length = struct.unpack_from("<Q", data, header + 32)[0]
            require(start + length <= len(data), "bad ELF interpreter bounds")
            interpreters.append(data[start:start + length])
    require(interpreters == ([b"/system/bin/linker64\0"] if executable else []), "unexpected ELF interpreter")


def check_apk_archive(apk):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate APK ZIP entries")
        libraries = [name for name in names if name.startswith("lib/") and not name.endswith("/")]
        require(libraries == ["lib/arm64-v8a/libandrix_p5_probe.so"], "APK must contain only the ARM64 proof JNI library")
        elf_arm64(archive.read(libraries[0]), executable=False)


def check_apk_metadata(badging, xmltree):
    lines = badging.splitlines()
    packages = [line for line in lines if line.startswith("package:")]
    require(len(packages) == 1 and shlex.split(packages[0])[1] == "name=" + PACKAGE, "wrong APK package")
    # r1 aapt2 calls this minSdkVersion; older tools called it sdkVersion.
    # Accept either spelling, but never missing, duplicate or conflicting rows.
    minimum = [line for line in lines if line.startswith(("sdkVersion:", "minSdkVersion:"))]
    require(len(minimum) == 1 and minimum[0] in ("sdkVersion:'37'", "minSdkVersion:'37'"),
            "APK minimum SDK must be exactly 37")
    require([line for line in lines if line.startswith("targetSdkVersion:")]
            == ["targetSdkVersion:'37'"], "APK target SDK must be exactly 37")
    abis = [shlex.split(line) for line in lines if line.startswith("native-code:")]
    require(abis == [["native-code:", "arm64-v8a"]], "APK ABI must be only arm64-v8a")
    require(not any(line.startswith("uses-permission") for line in lines), "APK requests permissions")
    # Reject extra components/permission declarations and shared identity. The
    # supplied APK's source/signing provenance still needs the operator's review.
    # New aapt2 prints the namespace URI on attribute names. Normalize only
    # that anchored prefix, not attribute values or arbitrary namespaces.
    xmltree = re.sub(r"(?m)^(\s*A: )http://schemas\.android\.com/apk/res/android:",
                     r"\1android:", xmltree)
    elements = re.findall(r"^\s*E: ([^\s(]+)", xmltree, re.MULTILINE)
    require(sorted(elements) == ["application", "instrumentation", "manifest", "uses-sdk"], "unexpected manifest elements")
    require(not re.search(r"A: android:(?:sharedUser\w*|permission)\b", xmltree), "shared UID/permission in manifest")
    for attribute, value in (("targetPackage", PACKAGE), ("name", PACKAGE + ".P5Instrumentation")):
        matches = re.findall(r"A: android:" + attribute + r'(?:\(0x[0-9a-f]+\))?="([^"]*)"', xmltree)
        require(matches == [value], "incorrect self-instrumentation " + attribute)
    test_only = re.findall(r"^\s*A: android:testOnly\(0x[0-9a-f]+\)=(.*)$", xmltree, re.MULTILINE)
    require(test_only in (["true"], ["(type 0x12)0xffffffff"]), "APK is not unambiguously testOnly")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise Failure("non-finite JSON: " + value)


def parse_instrumentation(raw):
    lines = raw.replace("\r\n", "\n").splitlines()
    lines = [line for line in lines if line]
    require(len(lines) == 2 and lines[0].startswith("INSTRUMENTATION_RESULT: p5=")
            and lines[1] == "INSTRUMENTATION_CODE: -1", "missing, failed, or ambiguous instrumentation completion")
    try:
        result = json.loads(lines[0].split("p5=", 1)[1], object_pairs_hook=unique_object,
                            parse_constant=reject_constant)
    except ValueError as error:
        raise Failure("invalid instrumentation JSON: " + str(error)) from error
    require(isinstance(result, dict), "instrumentation result is not an object")
    return result


def users_from_output(raw):
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    require(lines and lines[0] == "Users:", "cannot enumerate users")
    ids = []
    for line in lines[1:]:
        match = re.fullmatch(r"UserInfo\{([0-9]+):[^\r\n]*:[0-9a-fA-F]+\}(?: running)?", line)
        require(match is not None, "unrecognized user listing")
        ids.append(int(match[1]))
    require(0 in ids and len(ids) == len(set(ids)), "invalid user IDs")
    return sorted(ids)


def packages_from_output(raw):
    lines = raw.splitlines()
    require(all(re.fullmatch(r"package:[A-Za-z0-9_.]+", line) for line in lines), "unrecognized package listing")
    return [line.removeprefix("package:") for line in lines]


def check_mappings(raw):
    found = set()
    require(isinstance(raw, str) and raw, "no native mappings")
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        require(len(fields) == 6 and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", fields[0])
                and re.fullmatch(r"[r-][w-][x-][ps]", fields[1]), "invalid mapping row")
        path = fields[5]
        if re.fullmatch(r"/apex/com\.android\.runtime(?:@[0-9]+)?/lib64/bionic/libc\.so", path):
            component = "bionic"
        elif path == "/system/bin/linker64" or re.fullmatch(r"/apex/com\.android\.runtime(?:@[0-9]+)?/bin/linker64", path):
            component = "linker"
        else:
            raise Failure("unexpected libc/linker mapping: " + path)
        if fields[1] == "r-xp":
            found.add(component)
    require(found == {"linker", "bionic"}, "missing executable Android linker/Bionic mapping")


def validate_report(report, fingerprint, uid, source_dir, shell_sha, page_size, platform_profile="aosp17"):
    require(type(report.get("schema")) is int and report["schema"] == 1, "unknown report schema")
    for key in ("package", "instrumentation_package"):
        require(report.get(key) == PACKAGE, "incorrect " + key)
    require(10000 <= uid <= 19999, "Package Manager UID is not ordinary user-0 app UID")
    for key in ("uid", "package_uid"):
        require(type(report.get(key)) is int and report[key] == uid, "Java/PM UID mismatch")
    flags = report.get("app_flags")
    require(type(flags) is int and flags & (1 | 128) == 0 and flags & 256 != 0, "system/updated-system or non-test app")
    require("shared_user_id" in report and report["shared_user_id"] is None, "shared UID")
    validate_platform_profile(platform_profile, fingerprint)
    require(report.get("permissions") == expected_pm_permissions(platform_profile),
            "unexpected PackageManager permission list for platform profile")
    require(report.get("source_dir") == source_dir and source_dir.startswith("/data/app/"), "not the installed data APK")
    require(report.get("fingerprint") == fingerprint, "app fingerprint mismatch")
    for key in ("sdk", "min_sdk", "target_sdk"):
        require(type(report.get(key)) is int and report[key] == 37, "incorrect " + key)
    require(report.get("abis") == ["arm64-v8a"] and report.get("is_64_bit") is True, "app is not ARM64-only")
    for key in ("system_sh_sha256_before", "system_sh_sha256_after"):
        require(report.get(key) == shell_sha, "app's /system/bin/sh differs from exact P3 artifact")
    files = report.get("files_dir")
    require(files in ("/data/user/0/" + PACKAGE + "/files", "/data/data/" + PACKAGE + "/files"), "unexpected app-private directory")
    native = report.get("native")
    require(isinstance(native, dict) and set(native) == NATIVE_FIELDS
            and all(type(value) is str for value in native.values()), "missing/unknown/non-string JNI fields")
    require(native["status"] == "complete" and native["error_stage"] == ""
            and native["error_errno"] == "0" and native["cleanup_errno"] == "0", "native setup/probe/cleanup failure")
    for key in ("uid", "euid", "gid", "egid", "copy_uid"):
        require(native[key] == str(uid), "JNI identity/ownership mismatch: " + key)
    require(re.fullmatch(r"u:r:untrusted_app:s0:c[0-9]+(?:,c[0-9]+)+", native["selinux"]), "not the ordinary untrusted_app domain")
    categories = [int(value[1:]) for value in native["selinux"].rsplit(":", 1)[1].split(",")]
    require(categories == sorted(set(categories)) and max(categories) <= 1023, "invalid MLS categories")
    require(re.fullmatch(r"[0-9a-fA-F]{16}", native["cap_eff"]) and int(native["cap_eff"], 16) == 0, "nonzero/invalid effective capabilities")
    check_mappings(native["mappings"])
    require(native["page_size"] == str(page_size), "JNI/kernel page-size mismatch")
    require(native["source_path"] == "/system/bin/sh" and native["source_mode"] == "0755"
            and native["source_uid"] == "0" and re.fullmatch(r"[0-9]+:[0-9]+", native["source_dev_inode"]), "source path/mode/owner invalid")
    require(re.fullmatch(r"[1-9][0-9]*", native["source_size"]) and native["copy_size"] == native["source_size"], "source/copy size mismatch")
    require(re.fullmatch(re.escape(files) + r"/p5\.[A-Za-z0-9]{6}/sh", native["copy_path"]), "copy outside private temporary directory")
    require(native["copy_dir_mode"] == "0700" and native["copy_mode"] == "0700"
            and native["copy_mount_noexec"] == "0", "copy DAC/noexec confound")
    require(native["byte_identity_before"] == native["byte_identity_after"] == "identical", "copy byte comparison failed")
    for prefix, outcome, stage, error, exit_code in (
            ("control", "exited", "waitpid", "0", "0"),
            ("copy", "exec_errno", "execve", "13", "127")):
        for suffix, expected in (("outcome", outcome), ("stage", stage), ("errno", error),
                                 ("exit", exit_code), ("signal", "0"), ("reaped", "1")):
            require(native[prefix + "_" + suffix] == expected, "invalid " + prefix + " execution: " + suffix)


class Runner:
    def __init__(self, args, serial, fingerprint):
        self.args, self.serial, self.fingerprint = args, serial, fingerprint
        self.platform_profile = getattr(args, "platform_profile", "aosp17")
        validate_platform_profile(self.platform_profile, fingerprint)
        self.evidence = args.evidence.resolve()
        self.sequence = 0
        self.installed = False
        self.identity = None
        self.baseline = None
        self.summary = {"verdict": "FAIL", "serial": serial, "expected_fingerprint": fingerprint,
                        "platform_profile": self.platform_profile,
                        "expected_pm_permissions": expected_pm_permissions(self.platform_profile),
                        "install_attempted": False, "install_confirmed": False,
                        "proof_validated": False, "uninstall_confirmed": False}

    def command(self, arguments, timeout=30):
        self.sequence += 1
        stem = self.evidence / f"{self.sequence:03d}"
        record = {"argv": [str(arg) for arg in arguments], "timeout_seconds": timeout}
        with open(str(stem) + ".stdout", "wb") as stdout, open(str(stem) + ".stderr", "wb") as stderr:
            try:
                completed = subprocess.run(record["argv"], stdin=subprocess.DEVNULL, stdout=stdout,
                                           stderr=stderr, timeout=timeout, check=False)
                record["returncode"] = completed.returncode
            except BaseException as error:
                record["exception"] = type(error).__name__ + ": " + str(error)
                raise
            finally:
                Path(str(stem) + ".command.json").write_text(json.dumps(record, indent=2) + "\n")
        require(completed.returncode == 0, f"command {self.sequence:03d} failed; see raw evidence")
        return Path(str(stem) + ".stdout").read_text(encoding="utf-8")

    def adb(self, *arguments, timeout=30):
        return self.command([self.args.adb, "-s", self.serial, *arguments], timeout)

    def shell(self, *arguments):
        # adb shell concatenates its arguments; quote once, never interpolate raw output.
        return self.adb("shell", shlex.join(arguments)).replace("\r\n", "\n").rstrip("\n")

    def remote_hash(self, path):
        output = self.shell("toybox", "sha256sum", path)
        fields = output.split()
        require(len(fields) == 2 and fields[1] == path and re.fullmatch(r"[0-9a-f]{64}", fields[0]), "bad device SHA-256 response")
        return fields[0]

    def state(self):
        require(self.adb("get-state").strip() == "device", "selected device is not online")
        observed = {}
        properties = {"ro.build.fingerprint": self.fingerprint, "sys.boot_completed": "1",
                      "ro.build.version.sdk": "37", "ro.product.cpu.abilist": "arm64-v8a",
                      "ro.product.cpu.abilist64": "arm64-v8a", "ro.product.cpu.abilist32": ""}
        if self.platform_profile == "grapheneos-2026081300":
            properties["ro.product.name"] = GOS_PRODUCT
        for key, expected in properties.items():
            observed[key] = self.shell("getprop", key)
            require(observed[key] == expected, "target mismatch: " + key)
        for key, command, expected in (("selinux", ("getenforce",), "Enforcing"),
                                       ("shell_uid", ("id", "-u"), "2000"),
                                       ("shell_context", ("id", "-Z"), "u:r:shell:s0"),
                                       ("machine", ("uname", "-m"), "aarch64"),
                                       ("user", ("am", "get-current-user"), "0")):
            observed[key] = self.shell(*command)
            require(observed[key] == expected, "target mismatch: " + key)
        observed["boot_id"] = self.shell("cat", "/proc/sys/kernel/random/boot_id")
        require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", observed["boot_id"]), "invalid boot ID")
        page = self.shell("getconf", "PAGESIZE")
        require(page in ("4096", "16384", "65536"), "invalid ARM64 kernel page size")
        observed["page_size"] = int(page)
        observed["system_sh_sha256"] = self.remote_hash("/system/bin/sh")
        require(observed["system_sh_sha256"] == self.summary["system_sh_sha256"], "device shell differs from exact P3 artifact")
        if self.baseline is not None:
            require(observed == self.baseline, "target rebooted or changed during proof")
        return observed

    def absent(self):
        users = users_from_output(self.shell("pm", "list", "users"))
        for user in users:
            packages = packages_from_output(self.shell("pm", "list", "packages", "-u", "--user", str(user), PACKAGE))
            require(PACKAGE not in packages, "refusing pre-existing proof package (including retained data), user " + str(user))

    def installed_identity(self):
        paths = self.shell("pm", "path", "--user", "0", PACKAGE).splitlines()
        require(len(paths) == 1 and paths[0].startswith("package:"), "missing/split installed APK")
        path = paths[0].removeprefix("package:")
        require(re.fullmatch(r"/data/app/[A-Za-z0-9_./=+~\-]+/base\.apk", path)
                and ".." not in path.split("/"), "unexpected installed APK path")
        output = self.shell("pm", "list", "packages", "-U", "--user", "0", PACKAGE)
        match = re.fullmatch(r"package:" + re.escape(PACKAGE) + r" uid:([0-9]+)", output)
        require(match is not None and 10000 <= int(match[1]) <= 19999, "cannot establish ordinary installed UID")
        require(self.remote_hash(path) == self.summary["apk_sha256"], "installed APK differs from supplied APK")
        identity = (int(match[1]), path)
        if self.identity is not None:
            require(identity == self.identity, "installed package identity changed; refusing cleanup")
        return identity

    def run(self):
        failure = None
        try:
            apk = self.evidence / "proof.apk"
            shutil.copyfile(self.args.apk, apk)
            self.summary["apk_input"] = str(self.args.apk.resolve())
            self.summary["apk_sha256"] = sha256(apk)
            self.summary["system_sh_input"] = str(self.args.system_sh.resolve())
            shell = self.args.system_sh.read_bytes()
            elf_arm64(shell, executable=True)
            self.summary["system_sh_sha256"] = hashlib.sha256(shell).hexdigest()
            check_apk_archive(apk)
            check_apk_metadata(self.command([self.args.aapt2, "dump", "badging", apk]),
                               self.command([self.args.aapt2, "dump", "xmltree", apk, "--file", "AndroidManifest.xml"]))
            self.summary["apk_manifest_declares_permissions"] = False
            self.baseline = self.state()
            self.summary["target"] = self.baseline
            self.absent()
            self.summary["install_attempted"] = True
            output = self.adb("install", "-t", "--user", "0", str(apk), timeout=120)
            require(output.splitlines() and output.splitlines()[-1] == "Success"
                    and "Failure" not in output, "installation not acknowledged; ownership uncertain, no blind uninstall")
            self.installed = True
            self.summary["install_confirmed"] = True
            self.identity = self.installed_identity()
            self.summary["installed_uid"], self.summary["installed_path"] = self.identity
            self.state()
            raw = self.adb("shell", shlex.join(("am", "instrument", "-w", "-r", "--user", "0", INSTRUMENTATION)), timeout=60)
            report = parse_instrumentation(raw)
            (self.evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            self.state()
            self.summary["observed_pm_permissions"] = report.get("permissions")
            self.summary["runtime_permission_grants_measured"] = False
            validate_report(report, self.fingerprint, *self.identity,
                            self.summary["system_sh_sha256"], self.baseline["page_size"],
                            self.platform_profile)
            self.summary["proof_validated"] = True
        except (Exception, KeyboardInterrupt) as error:
            failure = type(error).__name__ + ": " + str(error)
        finally:
            if self.installed:
                try:
                    # Only this acknowledged install, still on the same boot with
                    # the exact same APK/UID/path. No -k, no data-directory deletion.
                    require(self.identity is not None,
                            "installed UID/path was never established; no blind uninstall")
                    self.state()
                    self.installed_identity()
                    require(self.adb("uninstall", PACKAGE, timeout=60).strip() == "Success", "uninstall not acknowledged")
                    self.summary["uninstall_confirmed"] = True
                    self.absent()
                    self.state()
                except (Exception, KeyboardInterrupt) as error:
                    failure = (failure + "; " if failure else "") + "cleanup: " + type(error).__name__ + ": " + str(error)
            if failure is None and not (self.summary["proof_validated"] and self.summary["uninstall_confirmed"]):
                failure = "proof/cleanup incomplete"
            self.summary["verdict"] = "FAIL" if failure else "PASS"
            self.summary["failure"] = failure
            (self.evidence / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")
        if failure:
            raise Failure(failure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path, help="exact explicitly built AndrixP5OrdinaryApp.apk")
    parser.add_argument("--system-sh", required=True, type=Path, help="system/bin/sh executable from the exact P3 image (follow its mksh symlink)")
    parser.add_argument("--evidence", required=True, type=Path, help="NEW directory outside this checkout; never overwritten/deleted")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--aapt2", default="aapt2", help="aapt2 from the pinned build/SDK")
    parser.add_argument("--platform-profile", choices=PLATFORM_PROFILES, default="aosp17",
                        help="explicit source-aware PM metadata contract; never changes APK permissions")
    args = parser.parse_args()
    try:
        serial = os.environ.get("ANDROID_SERIAL", "")
        fingerprint = os.environ.get("ANDRIX_EXPECTED_FINGERPRINT", "")
        for name, value in (("ANDROID_SERIAL", serial), ("ANDRIX_EXPECTED_FINGERPRINT", fingerprint)):
            require(value and value == value.strip() and not any(char in value for char in "\r\n\0"), "explicit single-line " + name + " required")
        validate_platform_profile(args.platform_profile, fingerprint)
        require(args.apk.is_file() and args.apk.suffix == ".apk", "exact APK file required")
        require(args.system_sh.is_file(), "exact P3 system/bin/sh artifact required")
        root = Path(__file__).resolve().parents[2]
        evidence = args.evidence.resolve()
        require(evidence != root and root not in evidence.parents, "evidence must be outside this checkout")
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        runner = Runner(args, serial, fingerprint)
        runner.run()
        print("PASS: ordinary ARM64/Bionic app; valid system sh control; identical private copy execve EACCES; package removed")
        print("Evidence: " + str(evidence))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        print("Inspect evidence, including install/cleanup uncertainty; no runtime proof on failure.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
