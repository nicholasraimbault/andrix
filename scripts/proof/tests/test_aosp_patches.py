# SPDX-License-Identifier: Apache-2.0
"""Temporary-Git, host-only patch guard tests; no AOSP, network or device use."""
import contextlib
import difflib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "aosp_patches.py"
sys.path.insert(0, str(MODULE.parent))  # its private index module, git_index
spec = importlib.util.spec_from_file_location("aosp_patches", MODULE)
patches = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patches)


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], stderr=subprocess.PIPE).decode().strip()


def state(root):
    # Every entry below root, links not followed: mode, size, inode, mtime, ctime and bytes.
    return {path.relative_to(root).as_posix(): (
        path.lstat().st_mode, path.lstat().st_size, path.lstat().st_ino, path.lstat().st_mtime_ns,
        path.lstat().st_ctime_ns,
        path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        for path in [root, *root.rglob("*")]}


@contextlib.contextmanager
def previous(base, aosp):
    # The earlier procedure: every diff against the project's own index.
    yield lambda *args: patches.run(base, *args)


def repository(path, contents):
    path.mkdir(parents=True)
    git(path, "init", "-b", "master")
    # Identity belongs solely to synthetic test objects, never project commits.
    git(path, "config", "user.name", "Synthetic patch fixture")
    git(path, "config", "user.email", "fixture@example.test")
    git(path, "config", "commit.gpgsign", "false")
    for name, data in contents.items():
        (path / name).write_text(data)
    git(path, "add", ".")
    git(path, "commit", "-m", "Synthetic base")
    return git(path, "rev-parse", "HEAD")


class PatchGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.aosp = self.root / "aosp"
        manifest = repository(self.aosp / ".repo/manifests", {"default.xml": "fixture\n"})
        self.project = self.aosp / "project"
        head = repository(self.project, {"source.txt": "before\n", "other.txt": "untouched\n"})
        self.patch_dir = self.root / "patches"
        self.patch_dir.mkdir()
        text = ("diff --git a/project/source.txt b/project/source.txt\n" +
                "".join(difflib.unified_diff(["before\n"], ["after\n"],
                    fromfile="a/project/source.txt", tofile="b/project/source.txt")))
        (self.patch_dir / "change.patch").write_text(text)
        self.series = self.patch_dir / "series.json"
        self.data = {"schema": 1, "aosp_tag": "android-17.0.0_r1",
                     "manifest_commit": manifest, "patch": "change.patch",
                     "patch_sha256": patches.digest(text.encode()), "projects": [{
                         "path": "project", "base_commit": head, "files": [{
                             "path": "source.txt", "base_sha256": patches.digest(b"before\n"),
                             "patched_sha256": patches.digest(b"after\n")}]}]}
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        self.series.write_text(json.dumps(self.data))

    def test_default_check_is_read_only(self):
        report, _ = patches.inspect(self.aosp, self.series)
        self.assertEqual(report["state"], "base")
        self.assertFalse(report["runtime_proof"])
        self.assertEqual((self.project / "source.txt").read_text(), "before\n")
        self.assertEqual(git(self.project, "status", "--porcelain"), "")

    def test_apply_verified_idempotent_and_heads_indexes_unchanged(self):
        before = git(self.project, "rev-parse", "HEAD")
        report = patches.apply(self.aosp, self.root / "first", self.series)
        self.assertEqual(report["state"], "applied")
        self.assertEqual(git(self.project, "rev-parse", "HEAD"), before)
        self.assertEqual(git(self.project, "diff", "--cached", "--name-only"), "")
        self.assertEqual((self.project / "source.txt").read_text(), "after\n")
        self.assertEqual((self.project / "other.txt").read_text(), "untouched\n")
        self.assertTrue((self.root / "first/after.json").exists())
        self.assertEqual(patches.apply(self.aosp, self.root / "second", self.series)["state"], "applied")
        with self.assertRaises(FileExistsError):
            patches.apply(self.aosp, self.root / "first", self.series)

    def test_wrong_revision_or_patch_hash_fails_before_writes(self):
        for key in ("manifest_commit", "patch_sha256"):
            saved = self.data[key]
            self.data[key] = "0" * len(saved)
            self.save()
            with self.assertRaises(patches.PatchError):
                patches.inspect(self.aosp, self.series)
            self.data[key] = saved
        self.save()
        self.data["projects"][0]["base_commit"] = "0" * 40
        self.save()
        with self.assertRaises(patches.PatchError):
            patches.inspect(self.aosp, self.series)
        self.assertEqual((self.project / "source.txt").read_text(), "before\n")

    def test_unexpected_source_and_unrelated_changes_fail(self):
        for name, contents in (("source.txt", "unexpected\n"), ("other.txt", "changed\n"), ("extra.txt", "new\n")):
            path = self.project / name
            original = path.read_text() if path.exists() else None
            path.write_text(contents)
            with self.assertRaises(patches.PatchError):
                patches.inspect(self.aosp, self.series)
            if original is None:
                path.unlink()
            else:
                path.write_text(original)

    def test_staged_changes_and_mode_changes_fail(self):
        path = self.project / "source.txt"
        path.write_text("after\n")
        git(self.project, "add", "source.txt")
        with self.assertRaises(patches.PatchError):
            patches.inspect(self.aosp, self.series)
        git(self.project, "reset", "--", "source.txt")
        path.write_text("before\n")
        path.chmod(0o755)
        with self.assertRaises(patches.PatchError):
            patches.inspect(self.aosp, self.series)

    def test_partial_and_symlink_source_fail(self):
        (self.project / "source.txt").write_text("after\n")
        self.data["projects"][0]["files"].append({"path": "other.txt",
            "base_sha256": patches.digest(b"untouched\n"), "patched_sha256": patches.digest(b"other after\n")})
        self.save()
        with self.assertRaises(patches.PatchError):
            patches.inspect(self.aosp, self.series)
        path = self.project / "source.txt"
        path.unlink()
        target = self.root / "outside"
        target.write_text("before\n")
        path.symlink_to(target)
        with self.assertRaises(patches.PatchError):
            patches.inspect(self.aosp, self.series)

    def test_evidence_must_be_outside_sources(self):
        with self.assertRaises(patches.PatchError):
            patches.apply(self.aosp, self.aosp / "evidence", self.series)
        self.assertEqual((self.project / "source.txt").read_text(), "before\n")

    def test_patch_file_set_and_traversal_are_rejected(self):
        self.data["projects"][0]["files"][0]["path"] = "../outside"
        self.save()
        with self.assertRaises(patches.PatchError):
            patches.inspect(self.aosp, self.series)

    def copies(self, *names):
        time.sleep(1.1)  # Git compares whole seconds of ctime: copies start a second later.
        return [shutil.copytree(self.aosp, self.root / name, symlinks=True) for name in names]

    def test_a_copied_tree_is_checked_and_applied_through_a_private_index(self):
        # A copy's index matches none of its files, and the earlier diffs rewrote it there. The
        # check and the application decide and record what the earlier procedure did, on a twin
        # copy, while the copy's Git directories stay byte identical.
        copy, twin = self.copies("copy", "twin")
        before = state(copy)
        report, _ = patches.inspect(copy, self.series)
        self.assertEqual(report["state"], "base")
        self.assertEqual(state(copy), before)
        with mock.patch.object(patches, "refreshed", previous):
            self.assertEqual(patches.inspect(twin, self.series)[0], report)
        before = {name: state(copy / name / ".git") for name in ("project", ".repo/manifests")}
        applied = patches.apply(copy, self.root / "copy-evidence", self.series)
        self.assertEqual({name: state(copy / name / ".git") for name in before}, before)
        self.assertEqual((copy / "project/source.txt").read_text(), "after\n")
        with mock.patch.object(patches, "refreshed", previous):
            self.assertEqual(patches.apply(twin, self.root / "twin-evidence", self.series), applied)
        self.assertEqual((self.root / "copy-evidence/project.diff").read_bytes(),
                         (self.root / "twin-evidence/project.diff").read_bytes())

    def test_index_writes_stay_in_the_private_copy(self):
        # A split index setting would write a shared index file into the Git directory, and an
        # index write runs post-index-change. Neither happens for the private copy.
        copy, = self.copies("copy")
        # Files an hour older than the index: Git writes a whole index when an entry is racily
        # clean, so only older entries take the split index path.
        for name in ("source.txt", "other.txt"):
            os.utime(copy / "project" / name, (time.time() - 3600,) * 2)
        marker = self.root / "hook-ran"
        hook = copy / "project/.git/hooks/post-index-change"
        hook.write_text("#!/bin/sh\necho ran > '%s'\n" % marker)
        hook.chmod(0o755)
        git(copy / "project", "config", "core.splitIndex", "true")
        twin = shutil.copytree(copy, self.root / "twin", symlinks=True)
        before = state(copy)
        self.assertEqual(patches.inspect(copy, self.series)[0]["state"], "base")
        self.assertEqual(state(copy), before)
        self.assertFalse(marker.exists())
        # The control: the earlier procedure on a twin copy with the same settings runs the hook
        # and leaves a shared index file, so this fixture shows either write.
        with mock.patch.object(patches, "refreshed", previous):
            self.assertEqual(patches.inspect(twin, self.series)[0]["state"], "base")
        self.assertTrue(marker.exists())
        self.assertTrue(list((twin / "project/.git").glob("sharedindex.*")))

    def test_a_temporary_directory_inside_the_tree_is_refused_before_any_write(self):
        inside, outside = self.aosp / "tmp", self.root / "outside"
        inside.mkdir()
        outside.mkdir()
        time.sleep(0.05)  # File times are coarse: a later write must show.
        before = state(self.aosp)
        for directory in (inside, outside):
            with self.subTest(directory=directory.name), \
                    mock.patch.object(tempfile, "tempdir", None), \
                    mock.patch.dict(os.environ, {"TMPDIR": str(directory)}):
                if directory == inside:
                    with self.assertRaisesRegex(patches.PatchError,
                                                "temporary directory must be outside"):
                        patches.inspect(self.aosp, self.series)
                else:
                    self.assertEqual(patches.inspect(self.aosp, self.series)[0]["state"], "base")
                self.assertEqual(state(self.aosp), before)
                self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
