# SPDX-License-Identifier: Apache-2.0
"""Guard mechanics with explicit synthetic pins; real source/build checks separate."""
from pathlib import Path
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import owner_policy as policy


def state(root):
    # Every entry below root, links not followed: mode, size, inode, mtime, ctime and bytes.
    return {path.relative_to(root).as_posix(): (
        path.lstat().st_mode, path.lstat().st_size, path.lstat().st_ino, path.lstat().st_mtime_ns,
        path.lstat().st_ctime_ns,
        path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        for path in [root, *root.rglob('*')]}


@contextlib.contextmanager
def previous(path, root=None):
    # The earlier tracked check: both diffs against the project's own index.
    flags = policy.source.filter_overrides(path)
    yield lambda *args: policy.source.run(path, *flags, *args)[1]


def outcome(root):
    try:
        return policy.inspect(root)[3]['state']
    except ValueError as error:
        return str(error)


class OwnerPolicyTests(unittest.TestCase):
    def fixture(self):
        return (policy.PREFIX + '\n' + policy.ORIGINAL_EXEC_PREFIX + '} file_type:file execute;\n'
                + policy.ORIGINAL_DATA_PREFIX + '} data_file_type:file execute;\n'
                + ''.join('allow ' + policy.CGROUP_SUBJECT + ' ' + kind + ':' + cls + ' write;\n'
                          for kind in ['cgroup', 'cgroup_v2'] for cls in ['dir','file'])).encode()

    def test_real_pin_and_patch_record(self):
        root = Path(__file__).resolve().parents[3]
        info = json.loads((root/'patches/grapheneos-2026081300/owner-session-policy.json').read_text())
        self.assertEqual(info['head'], policy.HEAD)
        self.assertEqual(info['upstream_sha256'], policy.BEFORE)
        self.assertEqual(info['patch_sha256'], policy.sha(
            (root/'patches/grapheneos-2026081300/owner-session-policy.patch').read_bytes()))
        with self.assertRaisesRegex(ValueError, 'pinned upstream'):
            policy.patched(self.fixture())

    def test_flag_off_preserves_rules_and_flag_on_is_exactly_scoped(self):
        original = self.fixture()
        with patch.object(policy, 'BEFORE', policy.sha(original)):
            adapted = policy.patched(original)
        def expand(data, enabled):
            args = ['m4'] + (['-Dandrix_owner_session=true'] if enabled else [])
            run = subprocess.run(args, input=data, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            return '\n'.join(' '.join(line.split()) for line in run.stdout.decode().splitlines()
                              if line.strip() and not line.lstrip().startswith('#'))
        self.assertEqual(expand(original, False), expand(adapted, False))
        on = expand(adapted, True)
        self.assertIn('type andrixd, domain, coredomain;', on)
        self.assertIn('type andrix_owner, domain, coredomain;', on)
        self.assertIn('-andrix_owner', on)
        self.assertIn('neverallow { domain -andrixd } andrix_owner:process transition', on)
        self.assertIn('neverallow domain andrix_owner:process dyntransition', on)
        self.assertIn('neverallow andrix_owner { data_file_type -andrix_home_file }', on)
        self.assertNotIn('app_domain(andrix_owner)', on)
        self.assertNotIn('-untrusted_app', on)

    def test_ambiguous_context_rejected(self):
        original = self.fixture() + policy.ORIGINAL_DATA_PREFIX.encode()
        with patch.object(policy, 'BEFORE', policy.sha(original)):
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                policy.patched(original)

    def test_real_git_worktree_state_guards_with_synthetic_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root/policy.PROJECT
            target = project/policy.FILE
            target.parent.mkdir(parents=True)
            original = self.fixture()
            target.write_bytes(original)
            env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
            env.update({'GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_NOSYSTEM':'1'})
            def git(*args):
                return subprocess.check_output(['git','-C',str(project),'-c','user.name=Fixture',
                    '-c','user.email=fixture@example.invalid',*args],env=env,stderr=subprocess.STDOUT).strip()
            git('init');git('add','.');git('commit','-m','synthetic input')
            head = git('rev-parse','HEAD').decode()
            with patch.object(policy,'HEAD',head), patch.object(policy,'BEFORE',policy.sha(original)):
                self.assertEqual(policy.inspect(root)[3]['state'],'UPSTREAM')
                adapted = policy.patched(original)
                target.write_bytes(adapted)
                self.assertEqual(policy.inspect(root)[3]['state'],'ANDRIX_PRIVATE_BRIDGE')
                target.write_bytes(adapted+b'\n')
                with self.assertRaisesRegex(ValueError,'unexpected policy'):policy.inspect(root)
                target.write_bytes(adapted);git('add','.')
                with self.assertRaisesRegex(ValueError,'staged'):policy.inspect(root)
                git('reset','--',policy.FILE);target.unlink()
                with self.assertRaises((ValueError,FileNotFoundError)):policy.inspect(root)
                other=root/'outside';other.write_bytes(original);target.symlink_to(other)
                with self.assertRaisesRegex(ValueError,'containment'):policy.inspect(root)
            target.unlink();target.write_bytes(original)
            with patch.object(policy,'BEFORE',policy.sha(original)):
                with self.assertRaisesRegex(ValueError,'wrong pinned'):policy.inspect(root)

    def synthetic_tree(self, root):
        project = root/policy.PROJECT
        (project/policy.FILE).parent.mkdir(parents=True)
        (project/policy.FILE).write_bytes(self.fixture())
        (project/'private/other.te').write_bytes(b'# another tracked file\n')
        env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update({'GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_NOSYSTEM':'1'})
        def git(where, *args):
            return subprocess.check_output(['git','-C',str(where),'-c','user.name=Fixture',
                '-c','user.email=fixture@example.invalid',*args],env=env,
                stderr=subprocess.STDOUT).strip()
        git(project,'init');git(project,'add','.');git(project,'commit','-m','synthetic input')
        return git, git(project,'rev-parse','HEAD').decode()

    def test_a_copied_tree_is_read_through_a_private_index(self):
        # A copy's index matches none of its files, and the earlier check rewrote it there. Each
        # verdict on a copy is the earlier check's, on a twin copy, and the copy is unchanged.
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            git, head = self.synthetic_tree(work/'original')
            time.sleep(1.1)  # Git compares whole seconds of ctime: copies start a second later.
            original = self.fixture()
            with patch.object(policy,'HEAD',head), \
                    patch.object(policy,'BEFORE',policy.sha(original)):
                adapted = policy.patched(original)
                def adapt(project): (project/policy.FILE).write_bytes(adapted)
                def stage(project):
                    adapt(project); git(project,'add',policy.FILE)
                def other(project): (project/'private/other.te').write_bytes(b'# changed\n')
                for name, change, expected in [('upstream', None, 'UPSTREAM'),
                                               ('adapted', adapt, 'ANDRIX_PRIVATE_BRIDGE'),
                                               ('staged', stage, 'unexpected staged'),
                                               ('other', other,
                                                'unexpected staged or other tracked')]:
                    with self.subTest(name):
                        copy = work/name
                        shutil.copytree(work/'original', copy, symlinks=True)
                        if change: change(copy/policy.PROJECT)
                        twin = shutil.copytree(copy, work/(name+'-twin'), symlinks=True)
                        before = state(copy)
                        found = outcome(copy)
                        self.assertEqual(state(copy), before)
                        self.assertIn(expected, found)
                        with patch.object(policy.source, 'refreshed_index', previous):
                            self.assertEqual(outcome(twin), found)

    def test_a_temporary_directory_inside_the_source_tree_is_refused_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            _, head = self.synthetic_tree(work/'root')
            inside, outside = work/'root/tmp', work/'outside'
            inside.mkdir(); outside.mkdir()
            time.sleep(0.05)  # File times are coarse: a later write must show.
            before = state(work/'root')
            with patch.object(policy,'HEAD',head), \
                    patch.object(policy,'BEFORE',policy.sha(self.fixture())):
                for directory in (inside, outside):
                    with self.subTest(directory=directory.name), \
                            patch.object(tempfile,'tempdir',None), \
                            patch.dict(os.environ,{'TMPDIR':str(directory)}):
                        if directory == inside:
                            with self.assertRaisesRegex(policy.source.SourceError,
                                                        'temporary directory must be outside'):
                                policy.inspect(work/'root')
                        else:
                            self.assertEqual(policy.inspect(work/'root')[3]['state'], 'UPSTREAM')
                        self.assertEqual(state(work/'root'), before)
                        self.assertEqual(list(outside.iterdir()), [])
