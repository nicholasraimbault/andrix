# SPDX-License-Identifier: Apache-2.0
"""Source-verifier regressions with explicit mocked Git results, not a source sync."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

FILE = Path(__file__).resolve().parents[1] / 'grapheneos_source.py'
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

    def git(self,cwd,*args,allowed=(0,)):
        name=str(Path(cwd).relative_to(self.root));self.calls.append((name,args))
        key=(name,args)
        if key in self.overrides:
            value=self.overrides[key]
            if isinstance(value,Exception):raise value
            return value
        if args==('rev-parse','HEAD'):
            heads={'.repo/manifests':g.MANIFEST_COMMIT,'.repo/repo':g.REPO_COMMIT,'p/one':'1'*40,'p/two':'2'*40}
            return 0,(heads[name]+'\n').encode()
        if args==('rev-parse','--show-toplevel'):return 0,(str(cwd)+'\n').encode()
        if args[:1]==('rev-parse',):
            return 0,((g.MANIFEST_COMMIT if args[-1].endswith('^{commit}') else g.TAG_OBJECT)+'\n').encode()
        if 'verify-tag' in args:return 0,b''
        if args[:1]==('diff',):return 0,b''
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
        for args in [('diff','--name-only','HEAD','--'),('diff','--cached','--name-only','--')]:
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
        args=('-c','gpg.ssh.program=/usr/bin/ssh-keygen','-c','gpg.ssh.allowedSignersFile='+str(self.signers),'verify-tag',g.TAG)
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
