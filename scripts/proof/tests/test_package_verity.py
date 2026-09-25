# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'scripts/proof'))
import package_verity as verity
import android_lifecycle as lifecycle


class PackageVerityTests(unittest.TestCase):
    def test_exact_local_patch_and_method(self):
        profile = verity.profile()
        self.assertEqual(profile['head'], lifecycle.HEAD)
        patch = verity.PATCH.read_text()
        self.assertEqual(patch.count('+++ b/'+verity.FILE), 1)
        self.assertIn('if (!VerityUtils.hasFsverity(file.getPath()))', patch)
        method = verity.EXTRACTED.read_text()
        self.assertIn('Copyright (C) 2014 The Android Open Source Project', method)
        self.assertIn('VerityUtils.setUpFsverity(file.getPath());', method)
        self.assertIn('fsVerityEnabledApksSizeBytes += file.length();', method)
        self.assertIn('catch (IOException e)', method)
        self.assertNotIn('hasFsverity', verity.UPSTREAM_METHOD.read_text())
        with self.assertRaises(ValueError):
            verity.candidate(b'wrong upstream bytes', profile)

    def test_profile_refuses_drift_duplicate_and_path_escape(self):
        original = json.loads(verity.PROFILE.read_text())
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)/'profile.json'
            variants = [dict(original, head='0'*40), dict(original, version=True),
                        dict(original, file='../outside.java')]
            for data in variants:
                profile.write_text(json.dumps(data))
                with mock.patch.object(verity, 'PROFILE', profile), self.assertRaises(ValueError):
                    verity.profile()
            profile.write_text(verity.PROFILE.read_text().replace('"version": 1', '"version": 1, "version": 1', 1))
            with mock.patch.object(verity, 'PROFILE', profile), self.assertRaises(ValueError):
                verity.profile()
            patch = Path(directory)/'patch'
            patch.write_text(verity.PATCH.read_text().replace('a/'+verity.FILE, 'a/../outside.java'))
            profile.write_text(json.dumps(dict(original, patch_sha256=verity.sha(patch.read_bytes()))))
            with mock.patch.object(verity, 'PROFILE', profile), mock.patch.object(verity, 'PATCH', patch), self.assertRaises(ValueError):
                verity.profile()

    def test_inspector_only_accepts_original_or_exact_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            file = project/verity.FILE
            file.parent.mkdir(parents=True)
            def run(root, *args):
                return 0, (verity.HEAD.encode() if args[0]=='rev-parse' else b'original')
            with mock.patch.object(verity.source, 'run', side_effect=run), mock.patch.object(verity, 'profile', return_value={}), mock.patch.object(verity, 'candidate', return_value=b'candidate'):
                for data, state in [(b'original','UPSTREAM'),(b'candidate','ADAPTED')]:
                    file.write_bytes(data)
                    with mock.patch.object(verity, 'PROFILE', file):
                        self.assertEqual(verity.inspect_file(project)[2]['state'],state)
                file.write_bytes(b'unrecognized')
                with self.assertRaises(ValueError):verity.inspect_file(project)
                file.unlink();file.symlink_to(project/'elsewhere')
                with self.assertRaises(ValueError):verity.inspect_file(project)

    def test_combined_framework_fence_keeps_other_changes_forbidden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();project=root/lifecycle.PROJECT;project.mkdir(parents=True)
            original = {name:b'old' for name in lifecycle.FILES}
            target = {name:b'new' for name in [*lifecycle.FILES,lifecycle.ADDED]}
            for name in target:
                p=project/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(target[name])
            modified=[*lifecycle.FILES,verity.FILE];staged=[];others=[lifecycle.ADDED]
            def run(where,*args):
                if args[0]=='rev-parse':return 0,lifecycle.HEAD.encode()
                if args[0]=='show':return 0,b'old'
                if args[0]=='diff':return 0,'\n'.join(staged if '--cached' in args else modified).encode()
                if args[0]=='ls-files':return 0,'\n'.join(others).encode()
                raise AssertionError(args)
            known={'state':'ADAPTED','file':verity.FILE}
            import native_principal_pins as native
            native_state={'state':'UPSTREAM','files':{name:'UPSTREAM' for name in (*native.FILES,*native.ADDED)}}
            with mock.patch.object(lifecycle, 'profile', return_value={}), mock.patch.object(lifecycle, 'targets', return_value=target), mock.patch.object(lifecycle.source, 'filter_overrides', return_value=[]), mock.patch.object(lifecycle.source, 'run', side_effect=run), mock.patch.object(verity,'inspect_file',return_value=(b'old',b'new',known)), mock.patch.object(native,'inspect_files',return_value=({}, {}, native_state)):
                self.assertEqual(lifecycle.inspect(root)[3]['state'],'ADAPTED')
                modified.append('unrelated.java')
                with self.assertRaises(ValueError):lifecycle.inspect(root)
                modified.pop();others.append('unexpected.java')
                with self.assertRaises(ValueError):lifecycle.inspect(root)
                others.pop();staged.append(verity.FILE)
                with self.assertRaises(ValueError):lifecycle.inspect(root)

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_exact_method_red_and_fixed_models(self):
        template = (ROOT/'tests/staged-apk-verity/VeritySetupHarness.java.in').read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label,method,success in [('upstream',verity.UPSTREAM_METHOD,False),('fixed',verity.EXTRACTED,True)]:
                dest=root/label;dest.mkdir();java=dest/'VeritySetupHarness.java';java.write_text(template.replace('@METHOD@',method.read_text()))
                subprocess.run(['javac','-d',str(dest),str(java)],check=True,capture_output=True,timeout=30)
                args=['java','-Xmx128m','-cp',str(dest),'VeritySetupHarness',str(dest/'files')]
                if not success:args.append('restored')
                result=subprocess.run(args,capture_output=True,text=True,timeout=30)
                if success:
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertIn('JAVA_METHOD_MODEL_PASS_NO_KERNEL_OR_SIGNATURE_CLAIM',result.stdout)
                else:
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('EEXIST',result.stderr)


if __name__ == '__main__':
    unittest.main()
