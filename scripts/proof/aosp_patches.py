#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check/apply the pinned, narrowly scoped Andrix AOSP product adaptation.

Default is read-only. --apply changes only the declared source files, not Git
HEADs/indexes, and requires a fresh evidence directory outside source trees.
This does not qualify an image, authorize a boot, or establish network proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SERIES = ROOT / "patches/android-17.0.0_r1/series.json"


class PatchError(Exception):
    pass


def run(cwd, *args, data=None):
    result = subprocess.run(["git", "-C", str(cwd), *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise PatchError(result.stderr.decode(errors="replace").strip() or "git operation failed")
    return result.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(p in (".", "..", ".git") for p in path.parts):
        raise PatchError("Unsafe relative source path")
    return Path(*path.parts)


def inspect(aosp, series_file=SERIES):
    series = json.loads(series_file.read_text())
    if series.get("schema") != 1 or series.get("aosp_tag") != "android-17.0.0_r1":
        raise PatchError("Unsupported patch series")
    manifest = run(aosp / ".repo/manifests", "rev-parse", "HEAD").decode().strip()
    if manifest != series["manifest_commit"]:
        raise PatchError("AOSP manifest revision differs from the pinned baseline")
    patch_path = series_file.parent / relative(series["patch"])
    patch = patch_path.read_bytes()
    if digest(patch) != series["patch_sha256"]:
        raise PatchError("Patch digest mismatch")
    files, projects, states = {}, [], set()
    for project in series["projects"]:
        base = aosp / relative(project["path"])
        if base.is_symlink() or not base.resolve().is_relative_to(aosp.resolve()):
            raise PatchError("Project path is not contained in AOSP_ROOT")
        head = run(base, "rev-parse", "HEAD").decode().strip()
        if head != project["base_commit"]:
            raise PatchError("Project revision mismatch: " + project["path"])
        if run(base, "diff", "--cached", "--name-only") or run(base, "ls-files", "--others", "--exclude-standard"):
            raise PatchError("Staged or untracked changes in " + project["path"])
        expected_modified = set()
        for entry in project["files"]:
            name = relative(entry["path"])
            path = base / name
            if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
                raise PatchError("Source path is not a contained regular file")
            actual = digest(path.read_bytes())
            if actual == entry["base_sha256"]:
                state = "base"
            elif actual == entry["patched_sha256"]:
                state = "applied"
                expected_modified.add(name.as_posix())
            else:
                raise PatchError("Unexpected source bytes: " + str(path.relative_to(aosp)))
            states.add(state)
            full_name = path.relative_to(aosp).as_posix()
            if full_name in files:
                raise PatchError("Duplicate source entry")
            files[full_name] = {"state": state, "sha256": actual,
                                "expected_patched_sha256": entry["patched_sha256"]}
        modified = set(run(base, "diff", "--name-only", "HEAD", "--").decode().splitlines())
        if modified != expected_modified or run(base, "diff", "--summary", "HEAD", "--"):
            raise PatchError("Unrelated source or file-mode changes in " + project["path"])
        projects.append({"path": project["path"], "head": head})
    if len(states) != 1:
        raise PatchError("Partial patch state; preserve and diagnose rather than force applying")
    declared = set(files)
    headers = re.findall(rb"^diff --git a/(\S+) b/(\S+)$", patch, re.M)
    if not headers or len(headers) != len(declared) or any(a != b for a, b in headers):
        raise PatchError("Unexpected patch headers")
    if {a.decode() for a, _ in headers} != declared:
        raise PatchError("Patch changes files outside the declared set")
    state = states.pop()
    if state == "base":
        run(aosp, "apply", "--check", "--whitespace=error", str(patch_path.resolve()))
    else:
        run(aosp, "apply", "--reverse", "--check", "--whitespace=error", str(patch_path.resolve()))
    report = {"aosp_tag": series["aosp_tag"], "manifest_commit": manifest,
              "patch_sha256": series["patch_sha256"], "state": state,
              "projects": projects, "files": files, "runtime_proof": False}
    return report, patch_path


def apply(aosp, evidence, series_file=SERIES):
    before, patch = inspect(aosp, series_file)
    evidence = evidence.resolve()
    if evidence.is_relative_to(ROOT) or evidence.is_relative_to(aosp.resolve()):
        raise PatchError("Evidence must be outside the source trees")
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    (evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")
    (evidence / "command.json").write_text(json.dumps(sys.argv) + "\n")
    try:
        if before["state"] == "base":
            # One git-apply transaction covers the whole declared patch. There
            # is no --reject/--3way/fuzz/force or modification of project HEADs.
            run(aosp, "apply", "--whitespace=error", str(patch.resolve()))
        after, _ = inspect(aosp, series_file)
        if after["state"] != "applied":
            raise PatchError("Post-application source verification failed")
        (evidence / "after.json").write_text(json.dumps(after, indent=2) + "\n")
        for project in after["projects"]:
            filename = project["path"].replace("/", "_") + ".diff"
            (evidence / filename).write_bytes(run(aosp / project["path"], "diff", "--binary", "HEAD", "--"))
        return after
    except Exception:
        # Do not reset/restore over unexpected concurrent edits. Preserve the
        # source and failed state for diagnosis; the next check will reject it.
        (evidence / "FAILED").write_text("Application/post-check failed; inspect source state before retrying.\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aosp-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true", help="apply only after exact base checks")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    if args.apply and args.evidence_dir is None:
        parser.error("--apply requires --evidence-dir")
    os.umask(0o077)
    try:
        if args.apply:
            report = apply(args.aosp_root.resolve(), args.evidence_dir)
        else:
            report, _ = inspect(args.aosp_root.resolve())
        print(json.dumps(report, indent=2))
    except (PatchError, OSError, ValueError, KeyError, TypeError) as exc:
        print("AOSP patch check failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
