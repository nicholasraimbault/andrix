# SPDX-License-Identifier: Apache-2.0
"""Four file private policy bridge, guarded Git inspection, and review record."""
from pathlib import Path
import contextlib
import difflib
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
import grapheneos_carry as carry
import grapheneos_candidate as candidate


def snapshot(root):
    return {path.relative_to(root).as_posix(): (
        path.lstat().st_mode, path.lstat().st_size, path.lstat().st_ino, path.lstat().st_mtime_ns,
        path.lstat().st_ctime_ns,
        path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        for path in [root, *root.rglob('*')]}


@contextlib.contextmanager
def previous(path, root=None):
    flags = policy.source.filter_overrides(path)
    yield lambda *args: policy.source.run(path, *flags, *args)[1]


class OwnerPolicyTests(unittest.TestCase):
    def fixture(self):
        domain = (policy.PREFIX + '\n' + policy.ORIGINAL_EXEC_PREFIX + '} file_type:file execute;\n'
                  + policy.ORIGINAL_DATA_PREFIX + '} data_file_type:file execute;\n'
                  + ''.join('allow ' + policy.CGROUP_SUBJECT + ' ' + kind + ':' + cls + ' write;\n'
                            for kind in ('cgroup', 'cgroup_v2') for cls in ('dir', 'file')))
        return {policy.FILES[0]: domain.encode(), **{
            path: ('# ' + path + '\n' + policy.FIND[path.removeprefix('private/').removesuffix('.te')]
                   + '  -existing_service\n}:service_manager find;\n').encode()
            for path in policy.FILES[1:]}}

    def synthetic_tree(self, root):
        project = root/policy.PROJECT
        project.mkdir(parents=True)
        original = self.fixture()
        for path, data in original.items():
            file = project/path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        (project/'private/other.te').write_bytes(b'# another tracked file\n')
        env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update({'GIT_CONFIG_GLOBAL':os.devnull, 'GIT_CONFIG_NOSYSTEM':'1'})
        def git(where, *args):
            return subprocess.check_output(['git', '-C', str(where), '-c', 'user.name=Fixture',
                '-c', 'user.email=fixture@example.invalid', *args], env=env,
                stderr=subprocess.STDOUT).strip()
        git(project, 'init'); git(project, 'add', '.'); git(project, 'commit', '-m', 'synthetic input')
        return project, original, git, git(project, 'rev-parse', 'HEAD').decode()

    def test_pinned_review_and_real_four_upstream_images(self):
        root = Path(__file__).resolve().parents[3]
        info = json.loads((root/'patches/grapheneos-2026081300/owner-session-policy.json').read_text())
        review = root/'patches/grapheneos-2026081300/owner-session-policy.patch'
        self.assertEqual(info['head'], policy.HEAD)
        self.assertEqual(info['patch_sha256'], policy.sha(review.read_bytes()))
        self.assertEqual([row['path'] for row in policy.profile_files(info)], list(policy.FILES))
        self.assertFalse(info['public_policy_api_changed'])
        self.assertFalse(info['existing_domain_grants_changed'])
        self.assertEqual(len(carry.load_patch_set(info['base_release'])[-1]['files']), 4)
        with self.assertRaisesRegex(ValueError, 'pinned upstream'):
            policy.patched(self.fixture())
        # Optional exact read-only upstream source is supplied for this assignment, not a
        # dependency of regular host tests or a mutable Android source checkout.
        if not os.environ.get('ANDRIX_POLICY_UPSTREAM'):
            return
        base = Path(os.environ['ANDRIX_POLICY_UPSTREAM'])
        original = {name: (base/name).read_bytes() for name in policy.FILES}
        adapted = policy.patched(original)
        self.assertEqual(info['files'], [dict(path=name, upstream_sha256=policy.sha(original[name]),
                                             candidate_sha256=policy.sha(adapted[name]))
                                          for name in policy.FILES])
        expected = ''.join(''.join(difflib.unified_diff(
            original[name].decode().splitlines(True), adapted[name].decode().splitlines(True),
            fromfile='a/'+name, tofile='b/'+name, n=0)) for name in policy.FILES)
        self.assertEqual(review.read_text(), expected)
        old_domain = adapted[policy.FILES[0]].replace(
            b'type andrix_native_accounts_service, service_manager_type, system_server_service;\n', b'')
        old_domain = old_domain.replace(
            b'# no vendor/public policy API; all preexisting service grants remain. The opt-in\n'
            b'# product supplies andrix_owner_session=true and the matching system_ext implementation.',
            b'# no vendor/public policy API and no existing domain changes. The opt-in product\n'
            b'# supplies andrix_owner_session=true and the matching system_ext implementation.')
        self.assertEqual(policy.sha(old_domain),
            '60625d252272b49656f9c101e0f8eefcb7c07b0c892f970c850b42eb5403db2b')
        for path in policy.FILES:
            with self.subTest(path=path):
                def run(data):
                    output = subprocess.run(['m4'], input=data, capture_output=True,
                                            timeout=10, check=True).stdout.decode()
                    return [' '.join(line.split()) for line in output.splitlines()
                            if line.strip() and not line.lstrip().startswith('#')]
                self.assertEqual(run(original[path]), run(adapted[path]))
        for path in policy.FILES[1:]:
            name = path.removeprefix('private/').removesuffix('.te')
            self.assertEqual(adapted[path].replace(
                policy.FIND[name].encode() +
                b"  ifelse(andrix_owner_session, `true', `-andrix_native_accounts_service')\n",
                policy.FIND[name].encode()), original[path])
        with tempfile.TemporaryDirectory() as work:
            self.assertEqual(carry.apply_patch(review, original, work)[2], adapted)
            spec = carry.load_patch_set(info['base_release'])[-1]
            row, base_out, target_out = carry.carry_patch(spec, original, original, work)
            self.assertEqual(base_out, adapted)
            self.assertEqual(target_out, adapted)
            self.assertEqual([file['review_record'] for file in row['files']], ['agrees'] * 4)
            self.assertEqual([file['class'] for file in row['files']], ['identical'] * 4)
            wrong = dict(spec, files=[dict(file) for file in spec['files']])
            wrong['files'][1]['candidate'] = '0' * 64
            with self.assertRaisesRegex(carry.CarryError, 'positive control failed'):
                carry.carry_patch(wrong, original, original, work)

    def test_flag_off_semantics_and_on_only_concrete_service_exclusions(self):
        originals = self.fixture()
        with patch.object(policy, 'BEFORE', {p:policy.sha(d) for p,d in originals.items()}):
            adapted = policy.patched(originals)
        def expand(data, enabled):
            cmd = ['m4'] + (['-Dandrix_owner_session=true'] if enabled else [])
            run = subprocess.run(cmd, input=data, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            return [' '.join(line.split()) for line in run.stdout.decode().splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
        for path in policy.FILES:
            with self.subTest(path=path):
                self.assertEqual(expand(originals[path], False), expand(adapted[path], False))
        domain = '\n'.join(expand(adapted[policy.FILES[0]], True))
        self.assertEqual(domain.count('type andrix_native_accounts_service, service_manager_type, system_server_service;'), 1)
        for text in ('neverallow andrix_owner { data_file_type -andrix_home_file }',
                     'neverallow { domain -andrix_owner } andrix_home_file',
                     'neverallow { domain -andrixd } andrix_owner:process transition',
                     'neverallow domain andrix_owner:process dyntransition'):
            self.assertIn(text, domain)
        self.assertNotIn('app_domain(andrix_owner)', domain)
        for path in policy.FILES[1:]:
            on = ' '.join(expand(adapted[path], True))
            before = ' '.join(expand(originals[path], True))
            self.assertEqual(on.replace(' -andrix_native_accounts_service', ''), before)
            self.assertEqual(on.count('-andrix_native_accounts_service'), 1)
            self.assertIn('service_manager_type -andrix_native_accounts_service -existing_service', on)
        # The service type is present even if a separate lifecycle gate is disabled. This
        # intentional empty type has no new access grants when the owner session is enabled.
        self.assertNotIn('andrix_native_accounts_service', '\n'.join(expand(adapted[policy.FILES[0]], False)))

    def test_ambiguous_and_incomplete_anchors_are_refused(self):
        original = self.fixture()
        for path in policy.FILES:
            altered = dict(original)
            altered[path] += policy.anchors(path)[0].encode()
            with self.subTest(path=path), patch.object(policy, 'BEFORE', {p:policy.sha(d) for p,d in altered.items()}):
                with self.assertRaisesRegex(ValueError, 'ambiguous'):
                    policy.patched(altered)
        for path in policy.FILES:
            altered = dict(original)
            del altered[path]
            with self.assertRaisesRegex(ValueError, 'four private'):
                policy.bridge(altered)

    def test_profile_rejects_legacy_incomplete_or_unknown_files(self):
        root = Path(__file__).resolve().parents[3]
        record = json.loads((root/'patches/grapheneos-2026081300/owner-session-policy.json').read_text())
        for altered in (dict(record, files=record['files'][:1]),
                        dict(record, file=policy.FILES[0], files=None),
                        dict(record, files=list(reversed(record['files']))),
                        dict(record, files=[dict(record['files'][0], candidate_sha256='Z'*64),
                                            *record['files'][1:]])):
            with self.assertRaisesRegex(ValueError, 'four pinned files'):
                policy.profile_files(altered)

    def test_candidate_agreement_checks_each_file_not_just_domain(self):
        record = {'files': [dict(path=path, upstream_sha256='a'*64,
                                 candidate_sha256='b'*64) for path in policy.FILES]}
        reading = [dict(path=path, upstream_sha256='a'*64, bridge_sha256='b'*64)
                   for path in policy.FILES]
        def check(files, value=record):
            return candidate.policy_agreement([
                {'check':'patch set','result':'PASS','policy':value},
                {'check':'owner_policy','result':'PASS','files':files}])
        self.assertEqual(check(reading)['result'], 'PASS')
        for path in policy.FILES:
            with self.subTest(path=path):
                tampered = [dict(row) for row in reading]
                tampered[policy.FILES.index(path)]['bridge_sha256'] = 'c'*64
                self.assertEqual(check(tampered)['result'], 'FAIL')
                self.assertIn(path, check(tampered)['failure'])
        self.assertEqual(check(reading[:1])['result'], 'FAIL')
        self.assertEqual(check(reading, {'files':record['files'][:1]})['result'], 'FAIL')

    def test_all_four_git_states_and_rejections(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project, original, git, head = self.synthetic_tree(root/'source')
            pins = {path:policy.sha(data) for path,data in original.items()}
            with patch.object(policy, 'HEAD', head), patch.object(policy, 'BEFORE', pins):
                def inspect(): return policy.inspect(root/'source')[3]['state']
                target = policy.patched(original)
                self.assertEqual(inspect(), 'UPSTREAM')
                for path in policy.FILES:
                    (project/path).write_bytes(target[path])
                self.assertEqual(inspect(), 'ANDRIX_PRIVATE_BRIDGE')
                (project/policy.FILES[1]).write_bytes(original[policy.FILES[1]])
                with self.assertRaisesRegex(ValueError, 'mixed'):
                    inspect()
                (project/policy.FILES[1]).write_bytes(target[policy.FILES[1]] + b'\n')
                with self.assertRaisesRegex(ValueError, 'mixed'):
                    inspect()
                (project/policy.FILES[1]).write_bytes(target[policy.FILES[1]])
                git(project,'add', policy.FILES[2])
                with self.assertRaisesRegex(ValueError, 'staged'): inspect()
                git(project,'reset', '--', policy.FILES[2])
                other=project/'private/other.te';other.write_bytes(b'# modified\n')
                with self.assertRaisesRegex(ValueError, 'other tracked'): inspect()
                other.write_bytes(b'# another tracked file\n')
                for path in policy.FILES:
                    file=project/path
                    file.unlink()
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        inspect()
                    file.symlink_to(other)
                    with self.assertRaisesRegex(ValueError, 'containment'): inspect()
                    file.unlink(); file.write_bytes(target[path])
                with patch.object(policy, 'HEAD', '0'*40):
                    with self.assertRaisesRegex(ValueError, 'wrong pinned'): inspect()

    def test_private_index_and_temporary_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp)
            project, original, git, head=self.synthetic_tree(work/'original')
            time.sleep(1.1)
            with patch.object(policy,'HEAD',head), patch.object(policy,'BEFORE',
                        {p:policy.sha(d) for p,d in original.items()}):
                bridge=policy.patched(original)
                for kind in ('upstream','adapted','staged','other'):
                    with self.subTest(kind=kind):
                        copy=shutil.copytree(work/'original',work/kind,symlinks=True)
                        copy_project=copy/policy.PROJECT
                        if kind in ('adapted','staged'):
                            for path in policy.FILES:
                                (copy_project/path).write_bytes(bridge[path])
                        if kind=='staged': git(copy_project,'add',*policy.FILES)
                        if kind=='other': (copy_project/'private/other.te').write_bytes(b'# changed\n')
                        twin=shutil.copytree(copy,work/(kind+'-twin'),symlinks=True)
                        before=snapshot(copy)
                        def outcome(root):
                            try: return policy.inspect(root)[3]['state']
                            except ValueError as e: return str(e)
                        found=outcome(copy)
                        self.assertEqual(snapshot(copy),before)
                        with patch.object(policy.source,'refreshed_index',previous):
                            self.assertEqual(outcome(twin),found)
                inside=work/'original/tmp';outside=work/'outside'
                inside.mkdir();outside.mkdir()
                before=snapshot(work/'original')
                for folder in (inside,outside):
                    with patch.object(tempfile,'tempdir',None), patch.dict(os.environ,{'TMPDIR':str(folder)}):
                        if folder==inside:
                            with self.assertRaisesRegex(policy.source.SourceError,'temporary directory must be outside'):
                                policy.inspect(work/'original')
                        else:
                            self.assertEqual(policy.inspect(work/'original')[3]['state'],'UPSTREAM')
                        self.assertEqual(snapshot(work/'original'), before)
                self.assertEqual(list(outside.iterdir()), [])

    def test_cli_applies_and_reverts_only_complete_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp); root=work/'source'
            project, original, git, head=self.synthetic_tree(root)
            pins={path:policy.sha(data) for path,data in original.items()}
            def run(action, suffix=''):
                evidence=work/(action+suffix+'.json')
                with patch.object(sys,'argv',['owner_policy','--source-root',str(root),
                                               '--action',action,'--evidence',str(evidence)]):
                    policy.main()
                return json.loads(evidence.read_text())
            with patch.object(policy,'HEAD',head),patch.object(policy,'BEFORE',pins):
                self.assertEqual(run('apply')['state_after'],'ANDRIX_PRIVATE_BRIDGE')
                self.assertEqual(run('revert')['state_after'],'UPSTREAM')
                (project/policy.FILES[0]).write_bytes(policy.patched(original)[policy.FILES[0]])
                with self.assertRaisesRegex(ValueError,'mixed'):
                    run('apply', '-mixed')
                self.assertEqual({path:(project/path).read_bytes() for path in policy.FILES[1:]},
                                 {path:original[path] for path in policy.FILES[1:]})


if __name__ == '__main__':
    unittest.main()
