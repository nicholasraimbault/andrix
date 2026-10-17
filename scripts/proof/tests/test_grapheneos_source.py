# SPDX-License-Identifier: Apache-2.0
"""Source-verifier regressions with explicit mocked Git results, not a source sync."""
import contextlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import sys
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

FILE = Path(__file__).resolve().parents[1] / 'grapheneos_source.py'
sys.path.insert(0, str(FILE.parent))  # its base identity module, grapheneos_base
spec = importlib.util.spec_from_file_location('grapheneos_source', FILE)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'source'; self.root.mkdir()
        self.manifest_repo = self.root/'.repo/manifests'; self.manifest_repo.mkdir(parents=True)
        (self.root/'.repo/manifests.git').mkdir(); (self.root/'.repo/repo').mkdir()
        self.manifest = b'<manifest><default remote="aosp" revision="refs/tags/android-17.0.0_r1"/><project name="one" path="p/one" revision="1111111111111111111111111111111111111111"/><project name="two" path="p/two" revision="2222222222222222222222222222222222222222" remote="grapheneos"/></manifest>'
        (self.manifest_repo/'default.xml').write_bytes(self.manifest)
        (self.root/'.repo/manifest.xml').write_text('<manifest><include name="default.xml"/></manifest>')
        for name in ['one','two']:
            p=self.root/'p'/name;p.mkdir(parents=True);(p/'.git').write_text('mock git marker')
        self.signers=Path(self.tmp.name)/'signers';self.signers.write_text('mock public trust input')
        self.overrides={};self.calls=[]
        for key,value in [('MANIFEST_SHA256',g.digest(self.manifest)),('SIGNERS_SHA256',g.digest(self.signers.read_bytes())),('PROJECT_COUNT',2)]:
            patch=mock.patch.object(g,key,value);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(g,'run',side_effect=self.git);patch.start();self.addCleanup(patch.stop)

    def git(self,cwd,*args,allowed=(0,),index=None):
        name=str(Path(cwd).relative_to(self.root));self.calls.append((name,args))
        if args[:1] in [('update-index',),('diff',)]:
            # Worktree and staged comparisons read a private index copy outside the tree.
            self.assertFalse(Path(index).resolve().is_relative_to(self.root))
        key=(name,args)
        if key in self.overrides:
            value=self.overrides[key]
            if isinstance(value,Exception):raise value
            return value
        if args==('rev-parse','--path-format=absolute','--git-dir','--git-common-dir',
                  '--git-path','index'):
            return 0,('%s/.git\n%s/.git\n%s/.no-index\n'%(cwd,cwd,cwd)).encode()
        if args[:1]==('update-index',):return 0,b''
        if args==('rev-parse','HEAD'):
            heads={'.repo/manifests':g.MANIFEST_COMMIT,'.repo/repo':g.REPO_COMMIT,'p/one':'1'*40,'p/two':'2'*40}
            return 0,(heads[name]+'\n').encode()
        if args==('rev-parse','--show-toplevel'):return 0,(str(cwd)+'\n').encode()
        if args[:1]==('rev-parse',):
            return 0,((g.MANIFEST_COMMIT if args[-1].endswith('^{commit}') else g.TAG_OBJECT)+'\n').encode()
        if 'verify-tag' in args:return 0,b''
        if args[:1]==('diff',):return 0,b''
        if args==('config','--null','--name-only','--get-regexp',r'^filter\.'):return 1,b''
        if args[:2]==('config','--get'):return 1,b''
        raise AssertionError((name,args))

    def inspect(self):return g.inspect(self.root,self.signers)

    def test_success_scope_and_signature_invocation(self):
        result=self.inspect();self.assertEqual(result['verdict'],'PASS_PINNED_SOURCE_HEADS')
        self.assertEqual(result['verified_projects'],2);self.assertTrue(result['tag_signature_verified'])
        self.assertFalse(result['build_proved']);self.assertFalse(result['prebuilt_materialization_verified'])
        self.assertTrue(any('verify-tag' in args for _,args in self.calls))
        self.assertFalse(any(set(args)&{'fetch','sync','reset','apply','checkout'} for _,args in self.calls))

    def test_missing_project_is_failure_not_excluded(self):
        (self.root/'p/two/.git').unlink();result=self.inspect()
        self.assertEqual(result['verdict'],'FAIL');self.assertEqual(result['verified_projects'],1)
        self.assertEqual(result['selection']['excluded_projects'],[])

    def test_wrong_project_head(self):
        self.overrides[('p/one',('rev-parse','HEAD'))]=(0,b'3'*40+b'\n')
        self.assertEqual(self.inspect()['verdict'],'FAIL')

    def test_tracked_or_staged_dirty(self):
        for args in [('diff','--no-ext-diff','--no-textconv','--name-only','HEAD','--'),
                     ('diff','--no-ext-diff','--no-textconv','--cached','--name-only','--')]:
            self.overrides={('p/one',args):(0,b'changed.java\n')}
            self.assertEqual(self.inspect()['verdict'],'FAIL')

    def test_wrong_git_worktree(self):
        self.overrides[('p/one',('rev-parse','--show-toplevel'))]=(0,b'/somewhere/else\n')
        self.assertEqual(self.inspect()['verdict'],'FAIL')

    def test_noncontained_project(self):
        p=self.root/'p/one';(p/'.git').unlink();p.rmdir();p.symlink_to(Path(self.tmp.name))
        self.assertEqual(self.inspect()['verdict'],'FAIL')

    def test_manifest_bytes_and_trust_bytes(self):
        (self.manifest_repo/'default.xml').write_bytes(self.manifest+b' ')
        with self.assertRaises(g.SourceError):self.inspect()
        (self.manifest_repo/'default.xml').write_bytes(self.manifest);self.signers.write_text('different key')
        with self.assertRaises(g.SourceError):self.inspect()

    def test_wrong_manifest_tag_tool_or_signature(self):
        cases=[('.repo/manifests',('rev-parse','HEAD')),
               ('.repo/manifests',('rev-parse','refs/tags/'+g.TAG)),
               ('.repo/manifests',('rev-parse','refs/tags/'+g.TAG+'^{commit}')),
               ('.repo/repo',('rev-parse','HEAD'))]
        for key in cases:
            self.overrides={key:(0,b'0'*40+b'\n')}
            with self.assertRaises(g.SourceError):self.inspect()
        # The pins are spelled out here, so a change to them fails this case.
        args=('-c','gpg.ssh.program=/usr/bin/ssh-keygen','-c','gpg.program=/usr/bin/false',
              '-c','gpg.openpgp.program=/usr/bin/false','-c','gpg.x509.program=/usr/bin/false',
              '-c','gpg.minTrustLevel=fully','-c','gpg.ssh.revocationFile=/dev/null',
              '-c','gpg.ssh.allowedSignersFile='+str(self.signers),'verify-tag',g.TAG)
        self.overrides={('.repo/manifests',args):g.SourceError('signature rejected')}
        with self.assertRaises(g.SourceError):self.inspect()

    def test_active_manifest_overrides_and_groups(self):
        for body in ['<manifest><include name="other.xml"/></manifest>',
                     '<manifest><include name="default.xml"/><project name="extra"/></manifest>']:
            (self.root/'.repo/manifest.xml').write_text(body)
            with self.assertRaises(g.SourceError):self.inspect()
        (self.root/'.repo/manifest.xml').write_text('<manifest><include name="default.xml"/></manifest>')
        self.overrides={('.repo/manifests.git',('config','--get','manifest.groups')):(0,b'all\n')}
        with self.assertRaises(g.SourceError):self.inspect()
        self.overrides={};local=self.root/'.repo/local_manifests';local.mkdir();(local/'extra.xml').write_text('<manifest/>')
        with self.assertRaises(g.SourceError):self.inspect()

    def test_parser_pins_paths_counts_and_no_exclusions(self):
        self.assertEqual(len(g.parse_projects(self.manifest)),2)
        for changed in [self.manifest.replace(b'path="p/one"',b'path="../escape"'),
                        self.manifest.replace(b'path="p/one"',b'path="p/two"'),
                        self.manifest.replace(b'revision="'+b'1'*40+b'"',b'revision="main"'),
                        self.manifest.replace(b'name="one"',b'name="one" groups="notdefault"'),
                        self.manifest.replace(b'android-17.0.0_r1',b'android-17.0.0_r2'),
                        self.manifest.replace(b'</manifest>',b'<include name="other.xml"/></manifest>')]:
            with self.assertRaises(g.SourceError):g.parse_projects(changed)
        with mock.patch.object(g,'PROJECT_COUNT',3):
            with self.assertRaises(g.SourceError):g.parse_projects(self.manifest)

    def test_relative_path_rejection(self):
        for value in ['',None,'/absolute','../parent','a/../b','a//b','a/./b','x/.git/data',' padded']:
            with self.assertRaises(g.SourceError):g.relative(value)

    def test_cli_no_overwrite_and_failure_evidence(self):
        evidence=Path(self.tmp.name)/'result';args=['--source-root',str(self.root),'--allowed-signers',str(self.signers),'--evidence-dir',str(evidence)]
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(g.main(args),0)
        first=(evidence/'result.json').read_bytes()
        rows=[json.loads(line) for line in (evidence/'projects.jsonl').read_text().splitlines()]
        self.assertEqual({row['path'] for row in rows},{'p/one','p/two'})
        self.assertTrue(all(row['verdict']=='PASS' for row in rows))
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(g.main(args),1)
        self.assertEqual((evidence/'result.json').read_bytes(),first)
        bad=Path(self.tmp.name)/'bad';self.signers.write_text('bad')
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(g.main(args[:-1]+[str(bad)]),1)
        self.assertIn('FAIL',(bad/'result.json').read_text())
        inside=self.root/'forbidden-output'
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(g.main(args[:-1]+[str(inside)]),1)
        self.assertFalse(inside.exists())


class GitExecutionTests(unittest.TestCase):
    def test_git_is_read_only_and_bounded(self):
        with mock.patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'yes',b'')) as runner:
            self.assertEqual(g.run(Path('/tmp/source'),'rev-parse','HEAD'),(0,b'yes'))
            args,kwargs=runner.call_args;self.assertEqual(args[0][:2],['git','--no-optional-locks'])
            self.assertEqual(kwargs['timeout'],120);self.assertIs(kwargs['stdin'],subprocess.DEVNULL)
            self.assertIn('--no-lazy-fetch',args[0]);self.assertIn('--no-replace-objects',args[0])
            self.assertIn('core.fsmonitor=false',args[0])
            self.assertIn('core.hooksPath='+os.devnull,args[0])
            self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'],'')
            self.assertEqual(kwargs['env']['GIT_CONFIG_GLOBAL'],os.devnull)

    def test_only_a_private_index_is_named_and_kept_whole(self):
        done=subprocess.CompletedProcess([],0,b'',b'')
        with mock.patch.object(subprocess,'run',return_value=done) as runner, \
                mock.patch.dict(os.environ,{'GIT_INDEX_FILE':'/tree/.git/index'}):
            g.run(Path('/tmp/source'),'update-index','--refresh',index=Path('/private/index'))
            args,kwargs=runner.call_args
            self.assertEqual(kwargs['env']['GIT_INDEX_FILE'],'/private/index')
            self.assertEqual(args[0][-4:],['-c','core.splitIndex=false','update-index','--refresh'])
            self.assertEqual(kwargs['timeout'],120)
            g.run(Path('/tmp/source'),'rev-parse','HEAD')
            args,kwargs=runner.call_args
            self.assertNotIn('GIT_INDEX_FILE',kwargs['env'])
            self.assertNotIn('core.splitIndex=false',args[0])

    def test_inherited_git_environment_is_not_authority(self):
        with mock.patch.dict(os.environ,{'GIT_DIR':'elsewhere','GIT_CONFIG_COUNT':'1',
                                        'GIT_CONFIG_PARAMETERS':'injected','GIT_TRACE':'write-here',
                                        'GIT_ALLOW_PROTOCOL':'ext','GIT_SSH_COMMAND':'callback'}):
            env=g.git_environment()
            for name in ['GIT_DIR','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS','GIT_TRACE','GIT_SSH_COMMAND']:
                self.assertNotIn(name,env)
            self.assertEqual(env['GIT_ALLOW_PROTOCOL'],'')
            self.assertEqual(env['GIT_NO_LAZY_FETCH'],'1')
            self.assertEqual(env['GIT_CONFIG_NOSYSTEM'],'1')


class RealGitReadOnlyTests(unittest.TestCase):
    """Only temporary local Git repositories; no Internet or active source edits."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.work=Path(self.tmp.name);self.repo=self.work/'repo';self.repo.mkdir()
        self.fixture_git('init','-q')
        self.fixture_git('config','user.name','nicholasraimbault')
        self.fixture_git('config','user.email','11843674+nicholasraimbault@users.noreply.github.com')
        (self.repo/'file.dat').write_bytes(b'committed\n')
        (self.repo/'.gitattributes').write_text('file.dat filter=sentinel diff=sentinel\n')
        self.fixture_git('add','.')
        self.fixture_git('commit','-qm','Local read-only verifier fixture')

    def fixture_git(self,*args):
        return subprocess.run(['git','-C',str(self.repo),*args],env=g.git_environment(),
                              check=True,capture_output=True,timeout=20).stdout

    def snapshot(self):
        # Content snapshots exclude access times, which reads may legitimately
        # update. No Git command or clean filter is used to compute these hashes.
        return {p.relative_to(self.repo).as_posix():g.digest(p.read_bytes())
                for p in self.repo.rglob('*') if p.is_file() and not p.is_symlink()}

    def sentinel(self,name):
        marker=self.work/(name+'.ran');script=self.work/(name+'.py')
        script.write_text('from pathlib import Path\nimport sys\n'
                          'Path(sys.argv[1]).write_text("executed")\n'
                          'sys.stdin.buffer.read()\n'
                          'sys.stdout.buffer.write(b"committed\\n")\n')
        return ' '.join(shlex.quote(str(x)) for x in [sys.executable,script,marker]),marker

    def test_clean_filter_cannot_hide_changes_or_write(self):
        command,marker=self.sentinel('clean')
        self.fixture_git('config','filter.sentinel.clean',command)
        (self.repo/'file.dat').write_bytes(b'changed contents\n')
        before=self.snapshot()
        with self.assertRaises(g.SourceError):g.check_tracked_clean(self.repo)
        self.assertFalse(marker.exists());self.assertEqual(self.snapshot(),before)

    def test_process_filter_fsmonitor_and_diff_commands_do_not_run(self):
        markers=[]
        for key in ['filter.sentinel.process','filter.sentinel.smudge',
                    'diff.sentinel.command','diff.sentinel.textconv','core.fsmonitor']:
            command,marker=self.sentinel(key.replace('.','-'));markers.append(marker)
            self.fixture_git('config',key,command)
        self.fixture_git('config','filter.sentinel.required','true')
        before=self.snapshot()
        g.check_tracked_clean(self.repo)
        self.assertTrue(all(not x.exists() for x in markers))
        self.assertEqual(self.snapshot(),before)
        (self.repo/'file.dat').write_bytes(b'changed contents\n');before=self.snapshot()
        with self.assertRaises(g.SourceError):g.check_tracked_clean(self.repo)
        self.assertTrue(all(not x.exists() for x in markers))
        self.assertEqual(self.snapshot(),before)

    def test_unsafe_filter_override_key_fails_before_execution(self):
        command,marker=self.sentinel('unsafe-name')
        self.fixture_git('config','filter.unsafe=name.clean',command)
        before=self.snapshot()
        with self.assertRaisesRegex(g.SourceError,'Unsupported Git filter configuration key'):
            g.check_tracked_clean(self.repo)
        self.assertFalse(marker.exists());self.assertEqual(self.snapshot(),before)

    def test_global_filter_and_git_injection_are_ignored(self):
        command,marker=self.sentinel('global-filter')
        config=self.work/'global.gitconfig'
        subprocess.run(['git','config','--file',str(config),'filter.sentinel.clean',command],
                       check=True,capture_output=True,timeout=10)
        (self.repo/'file.dat').write_bytes(b'changed contents\n');before=self.snapshot()
        with mock.patch.dict(os.environ,{'GIT_CONFIG_GLOBAL':str(config),
                                        'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'filter.sentinel.clean',
                                        'GIT_CONFIG_VALUE_0':command}):
            with self.assertRaises(g.SourceError):g.check_tracked_clean(self.repo)
        self.assertFalse(marker.exists());self.assertEqual(self.snapshot(),before)

    def test_pointer_is_not_materialization_and_expansion_fails_closed(self):
        # No external LFS program is installed or invoked by this test.
        pointer=(b'version https://git-lfs.github.com/spec/v1\n'
                 b'oid sha256:'+b'0'*64+b'\nsize 42\n')
        (self.repo/'file.dat').write_bytes(pointer)
        self.fixture_git('add','file.dat');self.fixture_git('commit','-qm','Pointer fixture')
        command,marker=self.sentinel('lfs-filter')
        self.fixture_git('config','filter.sentinel.process',command)
        self.fixture_git('config','filter.sentinel.required','true')
        g.check_tracked_clean(self.repo)
        (self.repo/'file.dat').write_bytes(b'materialized content is not validated here\n')
        with self.assertRaises(g.SourceError):g.check_tracked_clean(self.repo)
        self.assertFalse(marker.exists())

    def test_missing_promisor_object_cannot_fetch_even_from_local_remote(self):
        remote=self.work/'remote.git'
        subprocess.run(['git','clone','-q','--bare',str(self.repo),str(remote)],
                       env={**g.git_environment(),'GIT_ALLOW_PROTOCOL':'file'},
                       check=True,capture_output=True,timeout=20)
        oid=self.fixture_git('rev-parse','HEAD:file.dat').decode().strip()
        blob=self.repo/'.git/objects'/oid[:2]/oid[2:];self.assertTrue(blob.exists())
        self.fixture_git('config','core.repositoryformatversion','1')
        self.fixture_git('config','extensions.partialClone','origin')
        self.fixture_git('config','remote.origin.url',str(remote))
        self.fixture_git('config','remote.origin.promisor','true')
        self.fixture_git('config','remote.origin.partialCloneFilter','blob:none')
        blob.unlink();before=self.snapshot()
        with self.assertRaises(g.SourceError):g.run(self.repo,'cat-file','-p',oid)
        self.assertEqual(self.snapshot(),before)
        self.assertFalse(blob.exists());self.assertFalse((self.repo/'.git/FETCH_HEAD').exists())
        # Positive control: the same fixture really can satisfy a lazy fetch.
        # This deliberate local-file transfer is outside the verifier call.
        control=subprocess.run(['git','-C',str(self.repo),'cat-file','-p',oid],
                               env={**g.git_environment(),'GIT_NO_LAZY_FETCH':'0',
                                    'GIT_ALLOW_PROTOCOL':'file'},capture_output=True,timeout=20)
        self.assertEqual(control.returncode,0,control.stderr)
        self.assertEqual(control.stdout,b'committed\n')
        self.assertNotEqual(self.snapshot(),before)

    def test_replace_refs_do_not_change_observed_objects(self):
        original=self.fixture_git('rev-parse','HEAD:file.dat').decode().strip()
        replacement=subprocess.run(['git','-C',str(self.repo),'hash-object','-w','--stdin'],
                                   input=b'replacement\n',env=g.git_environment(),check=True,
                                   capture_output=True,timeout=20).stdout.decode().strip()
        self.fixture_git('replace',original,replacement)
        self.assertEqual(g.run(self.repo,'cat-file','-p',original)[1],b'committed\n')


def fixture_git(repo,*args,input=None):
    return subprocess.run(['git','-C',str(repo),*args],env=g.git_environment(),input=input,
                          check=True,capture_output=True,timeout=20).stdout


def tree_state(root):
    # The root and every entry below it, links not followed: type and mode, size, inode, link
    # count, owner, modification and change times, and each file's or link's bytes. Access
    # times are left out, since reads may update them. No Git command computes this.
    state={}
    for path in [root,*root.rglob('*')]:
        status=path.lstat()
        data=(g.digest(path.read_bytes()) if stat.S_ISREG(status.st_mode)
              else os.readlink(path) if stat.S_ISLNK(status.st_mode) else None)
        state[path.relative_to(root).as_posix()]=(
            status.st_mode,status.st_size,status.st_ino,status.st_nlink,status.st_uid,
            status.st_gid,status.st_mtime_ns,status.st_ctime_ns,data)
    return state


def previous_check(path):
    # The check before the private index: both diffs against the project's own index.
    overrides=g.filter_overrides(path)
    return not any(g.run(path,*overrides,*args)[1] for args in [
        ('diff','--no-ext-diff','--no-textconv','--name-only','HEAD','--'),
        ('diff','--no-ext-diff','--no-textconv','--cached','--name-only','--')])


class CopiedIndexTests(unittest.TestCase):
    """Projects copied as a source tree is copied: each file has a new inode and a later ctime,
    so the copied index's stat data matches none of them and every check compares content.
    Where the previous check reaches a verdict, it decides the same. It runs on a twin copy,
    since it can rewrite the index it reads."""
    FILES={'a.txt':b'alpha\n','b.txt':b'bravo\n','d/c.txt':b'charlie\n'}

    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup)
        cls.original=Path(cls.tmp.name)/'original';cls.original.mkdir()
        fixture_git(cls.original,'init','-q')
        fixture_git(cls.original,'config','user.name','fixture')
        fixture_git(cls.original,'config','user.email','fixture@example.invalid')
        # Whole seconds an hour ago: no entry is racily clean against the index written now.
        cls.mtime=int(time.time())-3600
        for name,data in cls.FILES.items():
            path=cls.original/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
            os.utime(path,(cls.mtime,cls.mtime))
        (cls.original/'link').symlink_to('a.txt')
        os.utime(cls.original/'link',(cls.mtime,cls.mtime),follow_symlinks=False)
        fixture_git(cls.original,'add','.')
        fixture_git(cls.original,'commit','-qm','Copied index fixture')
        cls.head=fixture_git(cls.original,'rev-parse','HEAD').decode().strip()
        time.sleep(1.1)  # This Git compares whole seconds of ctime: copies start a second later.

    def setUp(self):
        self.work=Path(tempfile.mkdtemp(dir=self.tmp.name))
        # The check's private directories go here, so each test sees that none remain.
        self.private=self.work/'private';self.private.mkdir()
        patch=mock.patch.object(tempfile,'tempdir',str(self.private));patch.start()
        self.addCleanup(patch.stop)

    def copy(self,source,target):
        shutil.copytree(source,target,symlinks=True)
        return target

    def stale(self,name='project'):
        project=self.copy(self.original,self.work/name)
        for entry in [*self.FILES,'link']:
            copied,original=(project/entry).lstat(),(self.original/entry).lstat()
            self.assertNotEqual(copied.st_ino,original.st_ino)
            self.assertNotEqual(int(copied.st_ctime),int(original.st_ctime))
        return project

    def assertUnchanged(self,root,before):
        after=tree_state(root)
        self.assertEqual(sorted(key for key in before.keys()|after.keys()
                                if before.get(key)!=after.get(key)),[])
        self.assertEqual(list(self.private.iterdir()),[])

    def verdict(self,project):
        twin=self.copy(project,Path(tempfile.mkdtemp(dir=self.work))/'twin')
        before=tree_state(project)
        try:
            g.check_tracked_clean(project);found='PASS'
        except g.SourceError as error:
            found=str(error)
        self.assertUnchanged(project,before)
        self.assertEqual(previous_check(twin),found=='PASS')
        return found

    def test_clean_copy_passes_and_its_git_files_stay_byte_identical(self):
        self.assertEqual(self.verdict(self.stale()),'PASS')

    def test_modified_file_fails(self):
        project=self.stale();(project/'a.txt').write_bytes(b'alpha, changed\n')
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_staged_change_fails(self):
        project=self.stale();(project/'b.txt').write_bytes(b'bravo, staged\n')
        fixture_git(project,'add','b.txt');(project/'b.txt').write_bytes(self.FILES['b.txt'])
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_deleted_file_fails(self):
        project=self.stale();(project/'d/c.txt').unlink()
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_same_size_and_mtime_with_other_content_fails(self):
        project=self.stale();path=project/'a.txt';status=path.stat()
        path.write_bytes(b'ALPHA\n');os.utime(path,ns=(status.st_atime_ns,status.st_mtime_ns))
        self.assertEqual((path.stat().st_size,path.stat().st_mtime_ns),
                         (status.st_size,status.st_mtime_ns))
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_assume_unchanged_and_skip_worktree_entries_are_honored_as_before(self):
        # Neither check examines the worktree file of such an entry, so a change there is not
        # reported, now as before. The entry itself is still compared with HEAD.
        for flag in ['--assume-unchanged','--skip-worktree']:
            with self.subTest(flag=flag,change='worktree'):
                project=self.stale('worktree'+flag)
                fixture_git(project,'update-index',flag,'a.txt')
                (project/'a.txt').write_bytes(b'alpha, not examined\n')
                self.assertEqual(self.verdict(project),'PASS')
            with self.subTest(flag=flag,change='staged'):
                project=self.stale('staged'+flag)
                (project/'a.txt').write_bytes(b'alpha, staged\n');fixture_git(project,'add','a.txt')
                fixture_git(project,'update-index',flag,'a.txt')
                (project/'a.txt').write_bytes(self.FILES['a.txt'])
                self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_unmerged_entry_and_missing_index_fail_as_before(self):
        project=self.stale('unmerged')
        oid=fixture_git(project,'rev-parse','HEAD:a.txt').decode().strip()
        fixture_git(project,'update-index','--index-info',input=(
            '0 %s\ta.txt\n100644 %s 1\ta.txt\n100644 %s 2\ta.txt\n'%('0'*40,oid,oid)).encode())
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')
        project=self.stale('without-index');(project/'.git/index').unlink()
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_racily_clean_entry_keeps_its_content_check(self):
        # With core.checkStat=minimal only size and mtime count, so a changed file's stat data
        # can match its entry without a race. Git checks the content of each entry whose mtime
        # is not older than the index file's, so the copy must keep that file's mtime.
        project=self.stale();fixture_git(project,'config','core.checkStat','minimal')
        path=project/'a.txt';path.write_bytes(b'ALPHA\n');os.utime(path,(self.mtime,self.mtime))
        os.utime(project/'.git/index',(self.mtime,self.mtime))
        self.assertRegex(self.verdict(project),'^Tracked or staged changes')

    def test_index_writes_stay_in_the_private_copy(self):
        # Settings that would take an index write into the Git directory: a split index writes
        # a shared index file there, and each index write runs post-index-change.
        project=self.stale();marker=self.work/'hook-ran'
        hooks=self.work/'hooks';hooks.mkdir()
        for directory in [hooks,project/'.git/hooks']:
            hook=directory/'post-index-change'
            hook.write_text('#!/bin/sh\necho ran > %s\n'%shlex.quote(str(marker)));hook.chmod(0o755)
        fixture_git(project,'config','core.splitIndex','true')
        fixture_git(project,'config','core.hooksPath',str(hooks))
        self.assertEqual(self.verdict(project),'PASS')
        self.assertFalse(marker.exists())

    def test_clean_copy_passes_with_auto_refresh_disabled(self):
        # With diff.autoRefreshIndex=false git diff lists every entry whose stat data differs,
        # so the previous check reported each file of a clean copy. That is the one verdict
        # that differs: the refreshed copy holds no such entry, and a changed file still fails.
        for name,change in [('clean',None),('changed',b'alpha, changed\n')]:
            with self.subTest(name):
                project=self.stale(name)
                fixture_git(project,'config','diff.autoRefreshIndex','false')
                if change:(project/'a.txt').write_bytes(change)
                before=tree_state(project)
                try:
                    g.check_tracked_clean(project);found='PASS'
                except g.SourceError as error:
                    found=str(error)
                self.assertUnchanged(project,before)
                self.assertRegex(found,'^PASS$' if change is None else '^Tracked or staged changes')

    def test_missing_blob_is_not_needed_for_a_clean_copy(self):
        # The refresh hashes each regular file and compares it with its entry, so its blob is
        # not read and nothing is fetched. The previous check read the blobs of a stale copy
        # and failed here.
        project=self.stale()
        oid=fixture_git(project,'rev-parse','HEAD:b.txt').decode().strip()
        (project/'.git/objects'/oid[:2]/oid[2:]).unlink()
        before=tree_state(project)
        g.check_tracked_clean(project)
        self.assertUnchanged(project,before)

    def test_repo_layout_tree_stays_byte_identical(self):
        tree=self.work/'tree'
        for name in ['clean','changed']:
            project=self.copy(self.original,tree/'p'/name)
            # As Repo lays out a tree: the worktree's .git and the Git directory's objects
            # are relative links into .repo.
            gitdir=tree/'.repo/projects/p'/(name+'.git')
            gitdir.parent.mkdir(parents=True,exist_ok=True);(project/'.git').rename(gitdir)
            (project/'.git').symlink_to(os.path.relpath(gitdir,project))
            objects=tree/'.repo/project-objects'/(name+'.git')/'objects'
            objects.parent.mkdir(parents=True);(gitdir/'objects').rename(objects)
            (gitdir/'objects').symlink_to(os.path.relpath(objects,gitdir))
        (tree/'p/changed/b.txt').write_bytes(b'bravo, changed\n')
        before=tree_state(tree)
        rows=[g.check_project(tree,{'path':'p/'+name,'revision':self.head})
              for name in ['clean','changed']]
        self.assertEqual([row['verdict'] for row in rows],['PASS','FAIL'])
        self.assertRegex(rows[1]['failure'],'^Tracked or staged changes')
        self.assertUnchanged(tree,before)

    def test_temporary_directory_inside_a_source_tree_is_refused(self):
        tree=self.work/'tree';project=self.copy(self.original,tree/'p')
        for inside,root in [(project/'tmp',None),(project/'.git/tmp',None),(tree/'tmp',tree)]:
            with self.subTest(inside=inside.relative_to(tree).as_posix()):
                inside.mkdir();before=tree_state(tree)
                with mock.patch.object(tempfile,'tempdir',str(inside)), \
                        self.assertRaisesRegex(g.SourceError,'temporary directory must be outside'):
                    g.check_tracked_clean(project,root)
                self.assertUnchanged(tree,before)
