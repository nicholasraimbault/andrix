#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit, bounded host JVM test of the current production query and controller."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = ROOT / "owner/tests/native-accounts-host"
FACADES = (
    "android/content/Context.java",
    "android/content/pm/ApplicationInfo.java",
    "android/content/pm/PackageInfo.java",
    "android/content/pm/PackageManager.java",
    "android/content/pm/SigningInfo.java",
    "android/content/pm/UserInfo.java",
    "android/os/Binder.java",
    "android/os/Handler.java",
    "android/os/IBinder.java",
    "android/os/Looper.java",
    "android/os/Process.java",
    "android/os/ServiceManager.java",
    "android/os/UserHandle.java",
    "android/widget/TextView.java",
    "com/android/server/LocalServices.java",
    "com/android/server/pm/NativePrincipalManager.java",
    "com/android/server/pm/UserManagerInternal.java",
    "dev/andrix/lifecycle/INativeAccountQuery.java",
    "dev/andrix/lifecycle/NativeAccountRow.java",
    "dev/andrix/lifecycle/NativeAccountSnapshot.java",
)
TESTS = ("dev/andrix/server/EndpointHostTest.java",
         "dev/andrix/terminal/ControllerHostTest.java")
PRODUCTION = (
    "owner/platform/java/dev/andrix/server/OwnerNativeAccountQuery.java",
    "owner/terminal/src/dev/andrix/terminal/NativeAccountController.java",
)
AIDL = (
    "owner/platform/aidl/dev/andrix/lifecycle/INativeAccountQuery.aidl",
    "owner/platform/aidl/dev/andrix/lifecycle/NativeAccountRow.aidl",
    "owner/platform/aidl/dev/andrix/lifecycle/NativeAccountSnapshot.aidl",
)


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_file(path):
    require(path.is_absolute() and path.is_file() and not path.is_symlink()
            and path.resolve(strict=True) == path, f"not a canonical regular file: {path}")


def source_inputs():
    require(HERE.resolve(strict=True) == HERE and ROOT.resolve(strict=True) == ROOT,
            "source root is not canonical")
    paths = [HERE / "facades" / rel for rel in FACADES]
    paths += [ROOT / rel for rel in PRODUCTION]
    paths += [HERE / "tests" / rel for rel in TESTS]
    for path in [*paths, *(ROOT / rel for rel in AIDL), HERE / "run.py"]:
        canonical_file(path)
    require(set((HERE / "facades").rglob("*.java")) == set(paths[:20]),
            "facade inventory changed; declare any new input")
    require(set((HERE / "tests").rglob("*.java")) == set(paths[-2:]),
            "test inventory changed; declare any new input")
    return paths


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "jdk", "javac-sha256", "java-sha256"):
        p.add_argument("--" + name, required=True)
    return p.parse_args(argv)


def owned_output(output):
    parent = output.parent
    require(parent.is_absolute() and parent.is_dir()
            and parent.resolve(strict=True) == parent, "output parent must be canonical")
    require(output.is_absolute() and output.resolve(strict=False) == output
            and not output.exists() and not output.is_symlink(),
            "output must be a fresh absolute directory")
    require(parent != ROOT and parent not in ROOT.parents and ROOT not in parent.parents,
            "output and checkout must be disjoint")


def write_new(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def signal_child(proc, action):
    # The JDK shares our externally supervised group. Never signal the group
    # from inside it. Its external owner handles group wide stop and retirement.
    if proc.poll() is None:
        try:
            proc.send_signal(action)
        except ProcessLookupError:
            pass


def inputs_unchanged(manifest):
    return all(sha(ROOT / row["path"]) == row["sha256"] for row in
               [*manifest["inputs"], *manifest["aidl_shape_reference_only"]])


def run_stage(name, command, out, env, manifest, global_start):
    receipts = out / "receipts"
    require(time.monotonic() - global_start < 100, "whole run deadline before " + name)
    require(inputs_unchanged(manifest), "source changed before " + name)
    write_new(receipts / (name + ".intent.json"), {
        "argv": command, "cwd": str(out), "stage": name,
        "input_manifest_sha256": sha(out / "INPUTS.json"),
        "stdin_path": str(out / "empty-stdin"), "stdin_access": "O_RDONLY",
        "term_after_seconds": 100, "kill_after_seconds": 101,
        "retire_by_seconds": 103, "environment": env,
    })
    stdout = receipts / (name + ".stdout")
    stderr = receipts / (name + ".stderr")
    with stdout.open("xb") as so, stderr.open("xb") as se:
        # Unlike subprocess.DEVNULL (which Python can open O_RDWR), this is an
        # owned, empty regular file opened read only. The child sees immediate EOF.
        fd = os.open(out / "empty-stdin", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            proc = subprocess.Popen(command, cwd=out, env=env, stdin=fd,
                                    stdout=so, stderr=se, close_fds=True,
                                    start_new_session=False)
        finally:
            os.close(fd)
        group = os.getpgrp()  # Same owned group as this runner and its supervisor.
        try:
            write_new(receipts / (name + ".process.json"), {
                "pid": proc.pid, "pgid": group, "parent_pid": os.getpid(),
                "new_session": False, "same_supervised_group": True,
            })
        except BaseException:
            signal_child(proc, signal.SIGKILL)
            proc.wait(timeout=2)
            raise
        start = time.monotonic()
        start_term = None
        term_sent = kill_sent = False
        failure = None
        try:
            while True:
                elapsed = time.monotonic() - global_start
                if proc.poll() is not None:
                    break
                if elapsed >= 100 and failure is None:
                    failure = "100 second whole run deadline"
                if failure is not None and not term_sent:
                    signal_child(proc, signal.SIGTERM)
                    term_sent = True
                    start_term = elapsed
                if term_sent and not kill_sent and elapsed >= min(101, start_term + 1):
                    signal_child(proc, signal.SIGKILL)
                    kill_sent = True
                if elapsed >= 103 or term_sent and elapsed >= min(103, start_term + 3):
                    failure = failure or "JDK child did not exit by 103 seconds"
                    break
                time.sleep(0.05)
            rc = proc.wait(timeout=1)  # Direct wait for our known child only.
        except BaseException:
            signal_child(proc, signal.SIGKILL)
            proc.wait(timeout=2)
            raise
    receipt = {"pid": proc.pid, "pgid": group, "direct_wait": True,
               "returncode": rc, "shared_supervised_group": True,
               "term_sent": term_sent, "kill_sent": kill_sent,
               "elapsed_seconds": time.monotonic() - start,
               "whole_run_seconds": time.monotonic() - global_start,
               "inputs_unchanged": inputs_unchanged(manifest),
               "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr),
               "failure": failure}
    write_new(receipts / (name + ".wait.json"), receipt)
    require(rc == 0 and not failure and receipt["inputs_unchanged"],
            f"{name} failed; see {receipts}")
    return receipt


def main(argv=None):
    args = parse_args(argv)
    require(not sys.flags.optimize and sys.dont_write_bytecode,
            "run with python3 -B, not optimized Python")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(os.getpid() == os.getpgrp(),
            "run as leader of a dedicated externally supervised process group")
    out, jdk = Path(args.output), Path(args.jdk)
    owned_output(out)
    require(jdk.is_absolute() and jdk.resolve(strict=True) == jdk, "JDK not canonical")
    source = source_inputs()
    for tool in ("javac", "java"):
        path = jdk / "bin" / tool
        canonical_file(path)
        require(re.fullmatch("[0-9a-f]{64}", getattr(args, tool + "_sha256")) is not None
                and sha(path) == getattr(args, tool + "_sha256"), "JDK " + tool + " SHA mismatch")
    inputs = [{"path": str(path.relative_to(ROOT)), "sha256": sha(path),
               "bytes": path.stat().st_size} for path in source]
    shapes = [{"path": rel, "sha256": sha(ROOT / rel)} for rel in AIDL]
    manifest = {"inputs": inputs, "aidl_shape_reference_only": shapes,
                "runner_sha256": sha(HERE / "run.py"),
                "jdk_sha256": {tool: getattr(args, tool + "_sha256")
                               for tool in ("javac", "java")}}
    # No writes above this line. Local storage admission belongs to the caller.
    global_start = time.monotonic()
    out.mkdir(mode=0o700)
    for directory in ("classes", "home", "tmp", "empty-sourcepath", "receipts"):
        (out / directory).mkdir(mode=0o700)
    # Create without opening a generic device or accepting an inherited stdin.
    fd = os.open(out / "empty-stdin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    os.close(fd)
    write_new(out / "INPUTS.json", manifest)
    env = {"HOME": str(out / "home"), "TMPDIR": str(out / "tmp"),
           "TMP": str(out / "tmp"), "TEMP": str(out / "tmp"),
           "XDG_CACHE_HOME": str(out / "home"), "XDG_CONFIG_HOME": str(out / "home"),
           "XDG_DATA_HOME": str(out / "home"), "PATH": "/nonexistent",
           "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    vm = ["-Xmx256m", "-Djava.io.tmpdir=" + str(out / "tmp"),
          "-Duser.home=" + str(out / "home"), "-XX:-UsePerfData",
          "-XX:+DisableAttachMechanism",
          "-XX:ErrorFile=" + str(out / "tmp/hs-err-%p.log")]
    compile_cmd = [str(jdk / "bin/javac"), *("-J" + flag for flag in vm),
                   "--release", "17", "-Xlint:all", "-Werror", "-proc:none",
                   "-sourcepath", str(out / "empty-sourcepath"),
                   "-classpath", str(out / "empty-sourcepath"),
                   "-d", str(out / "classes"), *(str(path) for path in source)]
    result = {"verdict": "HOLD", "android_qualified": False,
              "host_pass": False, "completed_stages": []}
    try:
        run_stage("compile", compile_cmd, out, env, manifest, global_start)
        result["completed_stages"].append("compile")
        classes = sorted((out / "classes").rglob("*.class"))
        require(classes and all(path.is_file() and not path.is_symlink() for path in classes),
                "no owned class output")
        write_new(out / "CLASSES.json", [{"path": str(p.relative_to(out)),
                                         "sha256": sha(p)} for p in classes])
        for stage, entry, count in (("endpoint", "dev.andrix.server.EndpointHostTest", 46),
                                    ("controller", "dev.andrix.terminal.ControllerHostTest", 21)):
            cmd = [str(jdk / "bin/java"), *vm, "-ea", "-cp", str(out / "classes"), entry]
            run_stage(stage, cmd, out, env, manifest, global_start)
            result["completed_stages"].append(stage)
            output = (out / "receipts" / (stage + ".stdout")).read_text()
            require(len(re.findall(r"^PASS " + stage + r" ", output, re.M)) >= count
                    and f"{stage.upper()} HOST PASS {count} CASES" in output,
                    "expected case count missing: " + stage)
            if stage == "controller":
                require("OWNED_WORKER_RETIRED pool=0 active=0 pending=0" in output,
                        "test worker retirement missing")
        result.update(verdict="PASS (bounded host facade only); HOLD (Android and merge)",
                      host_pass=True, endpoint_cases=46, controller_cases=21,
                      class_count=len(classes))
    except BaseException as exc:
        result["failure"] = repr(exc)
    finally:
        result["postflight_inputs_unchanged"] = inputs_unchanged(manifest)
        if not result["postflight_inputs_unchanged"]:
            result["verdict"] = "HOLD"
            result["host_pass"] = False
        write_new(out / "RESULT.json", result)
    print(json.dumps({"output": str(out), **result}, sort_keys=True))
    return 0 if result["host_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
