# SPDX-License-Identifier: Apache-2.0
"""Carry check regressions. Offline: recorded public fixtures and local Git repositories only."""
import base64
import contextlib
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import grapheneos_carry as carry
import grapheneos_source as source

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'grapheneos_carry'
# A pinned GrapheneOS source root is a local operator path, never part of the repository.
GRAPHENEOS_ROOT = os.environ.get('ANDRIX_GRAPHENEOS_ROOT')
GIT_ENV = dict(source.git_environment(), GIT_ALLOW_PROTOCOL='file',
               GIT_AUTHOR_NAME='Carry fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
               GIT_COMMITTER_NAME='Carry fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
               GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='core.fsync', GIT_CONFIG_VALUE_0='none')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_network(*args, **kwargs):
    raise AssertionError('network access in an offline test')


class Offline(unittest.TestCase):
    """Every test refuses Python network access; Git may only use local file URLs."""

    def setUp(self):
        guard = mock.patch('urllib.request.urlopen', side_effect=no_network)
        guard.start()
        self.addCleanup(guard.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)

    def git(self, budget=carry.SCRATCH_BUDGET):
        scratch = self.work / ('scratch-%d' % len(list(self.work.glob('scratch-*'))))
        scratch.mkdir()
        return carry.Git(scratch, protocols=('file',), budget=budget)


def run(cwd, *args, data=None, env=None):
    return subprocess.run(['git', *args], cwd=cwd, env=env or GIT_ENV, input=data, check=True,
                          capture_output=True, timeout=60).stdout.decode().strip()


class Repo:
    """A local fixture repository served over file URLs with filters and wants by ID enabled."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True)
        run(self.path, 'init', '-q', '-b', 'main')
        for key, value in (('uploadpack.allowFilter', 'true'), ('uploadpack.allowAnySHA1InWant', 'true'),
                           ('commit.gpgSign', 'false'), ('tag.gpgSign', 'false')):
            run(self.path, 'config', key, value)
        self.url = 'file://' + str(self.path)

    def commit(self, files, message, date='2026-01-12T00:00:00Z'):
        for name, data in files.items():
            target = self.path / name
            if data is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data if isinstance(data, bytes) else data.encode())
        run(self.path, 'add', '-A')
        env = dict(GIT_ENV, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        run(self.path, 'commit', '-q', '--allow-empty', '-m', message, env=env)
        return run(self.path, 'rev-parse', 'HEAD')

    def tag(self, name, target='HEAD', key=None):
        args = ['tag', '-a', '-m', name, name, target]
        if key is not None:
            args = ['-c', 'gpg.format=ssh', '-c', 'user.signingKey=' + str(key), 'tag', '-s', '-m', name, name, target]
        run(self.path, *args)
        return run(self.path, 'rev-parse', 'refs/tags/' + name)


def ssh_key(directory, principal='fixture@example.invalid'):
    key = Path(directory) / 'key'
    for old in (key, Path(str(key) + '.pub')):
        old.unlink(missing_ok=True)
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'carry fixture', '-f', str(key)],
                   check=True, capture_output=True, timeout=30)
    signers = Path(directory) / 'allowed_signers'
    signers.write_text(principal + ' ' + ' '.join((Path(str(key) + '.pub')).read_text().split()[:2]) + '\n')
    return key, signers


JAVA = '''package demo;

public final class Foo {
    private int count;

    public int first() {
        int value = count;
        value += 1;
        return value;
    }

    public int second(int input) {
        int value = input;
        value *= 2;
        value -= 1;
        value += 4;
        value /= 3;
        value %= 7;
        value ^= 5;
        value |= 8;
        value &= 255;
        value <<= 1;
        return value;
    }

    public int third() {
        return count * 3;
    }
}
'''


def unified(path, before, after):
    lines = difflib.unified_diff(before.splitlines(True), after.splitlines(True), 'a/' + path, 'b/' + path, n=3)
    return ''.join(line.replace('--- a/%s\t' % path, '--- a/%s' % path) for line in lines).encode()


def demo_spec(work, base, candidate, path='services/Foo.java', check=None, added=()):
    patch = work / 'demo.patch'
    patch.write_bytes(unified(path, base, candidate))
    profile = work / 'demo.json'
    profile.write_text('{"demo": true}\n')
    checks = check or (lambda outputs, originals: [
        {'name': 'tested region', 'path': path,
         'result': 'pass' if outputs[path].count(b'value *= 20;') == 1 else 'fail'}])
    return {'name': 'demo', 'project': 'frameworks/base', 'head': None, 'profile': profile, 'patch': patch,
            'files': [{'path': path, 'upstream': sha(base.encode()), 'candidate': sha(candidate.encode())}],
            'added': list(added), 'checks': checks, 'after': None, 'lab_only': False, 'method': 'patch'}


CANDIDATE = JAVA.replace('        value *= 2;\n', '        value *= 20;\n')


class ClassificationTests(Offline):
    """Every class from a small exact patch, and the negative controls."""

    def carry_one(self, target, spec=None):
        spec = spec or demo_spec(self.work, JAVA, CANDIDATE)
        work = self.work / 'apply'
        work.mkdir(exist_ok=True)
        path = spec['files'][0]['path']
        row, base_out, out = carry.carry_patch(spec, {path: JAVA.encode()},
                                               {path: None if target is None else target.encode()}, work)
        return row, row['files'][0], out

    def test_identical(self):
        row, entry, out = self.carry_one(JAVA)
        self.assertEqual((row['class'], entry['class']), ('identical', 'identical'))
        self.assertEqual(entry['candidate_sha256'], sha(CANDIDATE.encode()))
        self.assertTrue(row['applies'])

    def test_moved(self):
        row, entry, out = self.carry_one(JAVA.replace('package demo;\n', 'package demo;\n\nimport a.B;\nimport a.C;\n'))
        self.assertEqual(entry['class'], 'moved')
        self.assertEqual(entry['offsets'], [[1, 3]])
        self.assertNotEqual(entry['candidate_sha256'], entry['pinned_candidate_sha256'])

    def test_changed_clean(self):
        row, entry, out = self.carry_one(JAVA.replace('return count * 3;', 'return count * 3 + 1;'))
        self.assertEqual(entry['class'], 'changed clean')
        self.assertEqual(entry['offsets'], [])
        self.assertNotIn('overlaps', entry)

    def test_overlap_in_the_same_member(self):
        row, entry, out = self.carry_one(JAVA.replace('        value <<= 1;\n', '        value <<= 2;\n'))
        self.assertEqual(entry['class'], 'overlap')
        self.assertEqual(entry['overlaps'][0]['reason'], 'same member')
        self.assertIn('second(int input)', entry['overlaps'][0]['member'])
        self.assertIsNotNone(entry['candidate_sha256'])

    def test_overlap_adjacent_to_a_hunk(self):
        row, entry, out = self.carry_one(JAVA.replace('    public int first() {\n', '    // note\n    public int first() {\n')
                                         .replace('        value /= 3;\n', '        value /= 3;\n'))
        self.assertIn(entry['class'], ('moved', 'changed clean'))
        changed = JAVA.replace('        return value;\n    }\n\n    public int second',
                               '        return value + 0;\n    }\n\n    public int second')
        row, entry, out = self.carry_one(changed)
        self.assertEqual(entry['class'], 'overlap')
        self.assertEqual(entry['overlaps'][0]['reason'], 'adjacent')

    def test_overlap_when_a_tool_check_fails(self):
        spec = demo_spec(self.work, JAVA, CANDIDATE, check=lambda outputs, originals: [
            {'name': 'fixture', 'path': 'services/Foo.java',
             'result': 'pass' if b'third()' in outputs['services/Foo.java'] else 'fail'}])
        row, entry, out = self.carry_one(JAVA.replace('third()', 'thirdRenamed()'), spec)
        self.assertEqual(entry['class'], 'overlap')
        self.assertEqual(row['checks'][0]['result'], 'fail')

    def test_conflict_is_reported_not_hidden(self):
        """Negative control: a changed context line conflicts at fuzz 0 and nothing hides it."""
        spec = demo_spec(self.work, JAVA, CANDIDATE)
        before = spec['patch'].read_bytes()
        calls = []
        real = subprocess.run

        def spy(command, *args, **kwargs):
            if command and command[0] == '/usr/bin/patch':
                calls.append(list(command))
            return real(command, *args, **kwargs)

        with mock.patch.object(carry.subprocess, 'run', side_effect=spy):
            row, entry, out = self.carry_one(JAVA.replace('        value -= 1;\n', '        value -= 9;\n'), spec)
        self.assertEqual((row['class'], entry['class']), ('conflict', 'conflict'))
        self.assertEqual(entry['failed_hunks'], [1])
        self.assertIsNone(entry['candidate_sha256'])
        self.assertIsNone(out)
        self.assertFalse(row['applies'])
        self.assertTrue(row['checks'][0]['result'].startswith('not run'))
        self.assertEqual(spec['patch'].read_bytes(), before)
        self.assertEqual(len(calls), 2)  # positive control at base, then the target; no retry
        for command in calls:
            self.assertEqual(command[:6], list(carry.PATCH_COMMAND))
            self.assertEqual([arg for arg in command if arg.startswith('--fuzz')], ['--fuzz=0'])
            self.assertFalse({'-f', '--force', '-N', '-r', '--reject-file', '-F1', '-F2', '-F3'} & set(command))

    def test_already_applied_upstream_conflicts(self):
        row, entry, out = self.carry_one(CANDIDATE)
        self.assertEqual(entry['class'], 'conflict')
        self.assertIn('note', entry)

    def test_missing_target(self):
        row, entry, out = self.carry_one(None)
        self.assertEqual((row['class'], entry['class']), ('missing', 'missing'))
        self.assertIsNone(entry['target_sha256'])
        self.assertIsNone(out)

    def test_positive_control_refuses_a_wrong_base(self):
        spec = demo_spec(self.work, JAVA, CANDIDATE)
        spec['files'][0]['upstream'] = '0' * 64
        with self.assertRaisesRegex(carry.CarryError, 'positive control'):
            self.carry_one(JAVA, spec)

    def test_worst_class_order(self):
        self.assertEqual(carry.worst(['identical', 'moved', 'changed clean']), 'moved')
        self.assertEqual(carry.worst(['overlap', 'conflict', 'moved']), 'conflict')
        self.assertEqual(carry.worst(['missing', 'conflict']), 'missing')

    def test_java_members_are_approximate_but_bounded(self):
        text = ('class A {\n  @Override\n  public void run() {\n    if (x) {\n      y();\n    }\n  }\n'
                '  abstract int size(int a);\n  static {\n    z();\n  }\n'
                '  Runnable r = () -> {\n    w();\n  };\n  String s = "{";\n  char c = \'}\';\n'
                '  /* { */\n  outer: for (;;) {\n  }\n}\n')
        spans = carry.java_members(text)
        self.assertIn((2, 7, 'public void run()'), spans)  # the annotation line starts the member
        self.assertIn((9, 11, 'static'), spans)
        self.assertEqual(len(spans), 2)
        self.assertIn('abstract int size(int a)', {s for _, _, s in carry.java_members(text, declarations=True)})


class PatchSetTests(Offline):
    def test_real_patch_set_is_validated_by_its_own_tools(self):
        specs = carry.load_patch_set(source.TAG)
        self.assertEqual([s['name'] for s in specs], [
            'native-principal-pins', 'owner-lifecycle', 'package-verity', 'package-installer-payload-sync',
            'native-identity-writer', 'owner-session-policy'])
        self.assertEqual({s['project'] for s in specs}, {'frameworks/base', 'system/sepolicy'})
        self.assertEqual(sum(len(s['files']) for s in specs), 16)
        self.assertEqual(sum(len(s['added']) for s in specs), 8)
        self.assertEqual([s['name'] for s in specs if s['lab_only']], ['native-identity-writer'])
        self.assertEqual(specs[3]['after'], 'package-verity')
        self.assertEqual(specs[5]['method'], 'policy bridge')
        with self.assertRaisesRegex(carry.CarryError, 'no patch set'):
            carry.load_patch_set('2026100600')

    def test_policy_bridge_mirrors_owner_policy(self):
        import owner_policy as policy
        text = ('# header\n' + policy.PREFIX + 'x\n' + policy.ORIGINAL_EXEC_PREFIX + '}\n'
                + policy.ORIGINAL_DATA_PREFIX + '}\n'
                + ''.join('allow ' + policy.CGROUP_SUBJECT + ' cgroup%s;\n' % n for n in range(4))).encode()
        result, counts = carry.policy_bridge(text)
        with mock.patch.object(policy, 'BEFORE', sha(text)):
            self.assertEqual(result, policy.patched(text))
        self.assertEqual(counts, (1, 1, 1, 4))
        self.assertEqual(carry.policy_bridge(text.replace(policy.PREFIX.encode(), b''))[0], None)
        self.assertEqual(carry.policy_anchor_lines(text)[0], 2)

    def test_surface_covers_every_framework_service_stub(self):
        surface = carry.load_surface()
        declared = {row['path'] for row in surface['paths'] if row['project'] == 'frameworks/base'}
        declared |= {row['path'] for spec in carry.load_patch_set(source.TAG) for row in spec['files']}
        stubs = sorted(p for p in (ROOT / 'owner/tests/platform').glob('*_stubs/com/android/server/**/*.java'))
        self.assertTrue(stubs)
        for stub in stubs:
            name = stub.as_posix().split('_stubs/', 1)[1]
            self.assertTrue({'services/core/java/' + name, 'core/java/' + name} & declared, name)
        projects = {row['project'] for row in surface['projects']}
        self.assertTrue({row['project'] for row in surface['paths'] + surface['runtime']} <= projects)

    def test_runtime_surface_cites_repository_evidence(self):
        surface = carry.load_surface()
        self.assertTrue({'services/core/java/com/android/server/pm/PackageInstallerService.java',
                         'services/core/java/com/android/server/pm/StagingManager.java',
                         'services/core/java/com/android/server/pm/PackageSessionVerifier.java',
                         'keystore/java/android/security/keystore2', 'keystore2', 'apexd'}
                        <= {row['path'] for row in surface['runtime']})
        for row in surface['runtime']:
            cited, _, line = row['evidence'].rpartition(':')
            self.assertIn(row['cites'], (ROOT / cited).read_text().split('\n')[int(line) - 1])
        self.assertIn('keystore/java/android/security/keystore2', carry.ledger_paths([], surface)[2])
        bad = json.loads(carry.SURFACE.read_text())
        for change in ({'evidence': 'plans/2026-09-22-staged-apk-verity.md:1'},
                       {'evidence': 'plans/absent.md:1'}, {'cites': 'NotThere'}, {'evidence': 'no line number'},
                       {'evidence': '../outside.md:1'}, {'evidence': 'plans/current.md:0'}):
            bad['runtime'][0] = dict(json.loads(carry.SURFACE.read_text())['runtime'][0], **change)
            path = self.work / 'surface.json'
            path.write_text(json.dumps(bad))
            with self.assertRaisesRegex(carry.CarryError, 'evidence does not cite'):
                carry.load_surface(path)
        bad['runtime'][0] = dict(json.loads(carry.SURFACE.read_text())['runtime'][0], project='unwatched/project')
        path.write_text(json.dumps(bad))
        with self.assertRaisesRegex(carry.CarryError, 'not watched'):
            carry.load_surface(path)


def release_files(level, alias='cp9a'):
    return {'release_config_map.textproto': 'aliases: {\n  name: "aosp_current"\n  target: "%s"\n}\n' % alias,
            'release_configs/cur.textproto': 'name: "cur"\ninherits: "aosp_current"\n',
            'release_configs/%s.textproto' % alias: 'name: "%s"\ninherits: "cp8a"\n' % alias,
            'release_configs/cp8a.textproto': 'name: "cp8a"\n',
            'flag_values/cp8a/RELEASE_PLATFORM_SECURITY_PATCH.textproto':
                'name: "RELEASE_PLATFORM_SECURITY_PATCH"\nvalue: {\n  string_value: "2025-12-05"\n}\n',
            'flag_values/%s/RELEASE_PLATFORM_SECURITY_PATCH.textproto' % alias:
                'name: "RELEASE_PLATFORM_SECURITY_PATCH"\nvalue: {\n  string_value: "%s"\n}\n' % level}


class ReleaseConfigTests(Offline):
    def level(self, files):
        repo = Repo(self.work / ('rel-%d' % len(list(self.work.glob('rel-*')))))
        commit = repo.commit(files, 'release config')
        store = self.git().store(repo.url)
        return carry.patch_level(store, commit, 'cur', 'userdebug')

    def test_alias_and_inheritance(self):
        level = self.level(release_files('2026-01-05'))
        self.assertEqual(level['value'], '2026-01-05')
        self.assertEqual(level['path'], 'flag_values/cp9a/RELEASE_PLATFORM_SECURITY_PATCH.textproto')
        self.assertEqual(level['resolution'], ['cur inherits aosp_current', 'aosp_current aliases cp9a', 'cp9a sets it'])

    def test_competing_definitions_fail(self):
        files = release_files('2026-01-05')
        files['flag_values/userdebug/RELEASE_PLATFORM_SECURITY_PATCH.textproto'] = \
            'value: {\n  string_value: "2026-03-05"\n}\n'
        with self.assertRaisesRegex(carry.CarryError, 'build variant'):
            self.level(files)
        files = release_files('2026-01-05')
        del files['flag_values/cp9a/RELEASE_PLATFORM_SECURITY_PATCH.textproto']
        files['release_configs/cp9a.textproto'] = 'name: "cp9a"\ninherits: "cp8a"\ninherits: "cp7a"\n'
        files['release_configs/cp7a.textproto'] = 'name: "cp7a"\n'
        files['flag_values/cp7a/RELEASE_PLATFORM_SECURITY_PATCH.textproto'] = 'value: {\n  string_value: "2025-11-05"\n}\n'
        with self.assertRaisesRegex(carry.CarryError, 'ambiguous'):
            self.level(files)


MANIFEST = '''<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <remote name="aosp" fetch="{aosp}"/>
  <remote name="gos" fetch="{gos}" revision="refs/tags/{tag}"/>
  <default remote="aosp" revision="refs/tags/android-17.0.0_r1" sync-j="4"/>
  <superproject name="platform/superproject" remote="aosp"/>
  <project name="fb" path="frameworks/base" remote="gos" revision="{fb}" groups="pdk"/>
  <project name="rel" path="build/release" remote="gos" revision="{rel}"/>
  <project name="kp" path="kernel/prebuilts/6.12/arm64" remote="gos" revision="{kp}" clone-depth="1">
    <linkfile src="a" dest="b"/>
  </project>
</manifest>
'''


class ManifestTests(Offline):
    def manifest(self, **values):
        fields = dict(aosp='file:///aosp', gos='file:///gos/', tag='2026010100', fb='1' * 40, rel='2' * 40, kp='3' * 40)
        fields.update(values)
        return MANIFEST.format(**fields).encode()

    def test_table_is_independent_of_formatting(self):
        data = self.manifest()
        parsed = carry.parse_manifest(data)
        self.assertEqual(sorted(parsed['projects']), ['build/release', 'frameworks/base', 'kernel/prebuilts/6.12/arm64'])
        self.assertEqual(parsed['projects']['kernel/prebuilts/6.12/arm64']['files'], [['linkfile', 'a', 'b']])
        reformatted = data.replace(b'  <project', b'<project').replace(b' groups="pdk"', b'  groups="pdk"')
        self.assertNotEqual(sha(reformatted), sha(data))
        self.assertEqual(carry.project_rows(carry.parse_manifest(reformatted)), carry.project_rows(parsed))
        self.assertEqual(carry.project_url(parsed, 'frameworks/base'), 'file:///gos/fb')

    def test_refused_structure(self):
        for changed in [self.manifest().replace(b'</manifest>', b'<include name="x.xml"/></manifest>'),
                        self.manifest().replace(b'</manifest>', b'<remove-project name="fb"/></manifest>'),
                        self.manifest(fb='main'), self.manifest(rel='1' * 40).replace(b'path="build/release"',
                                                                                     b'path="frameworks/base"'),
                        self.manifest().replace(b'path="build/release"', b'path="../escape"'),
                        self.manifest().replace(b'remote="gos" revision="' + b'2' * 40, b'remote="nowhere" revision="'
                                                + b'2' * 40), b'<manifest><project', b'<other/>']:
            with self.assertRaises(carry.CarryError):
                carry.parse_manifest(changed)

    def test_diff(self):
        base = carry.parse_manifest(self.manifest())
        target = carry.parse_manifest(self.manifest(fb='4' * 40).replace(b'name="rel"', b'name="rel2"').replace(
            b'  <project name="kp"', b'  <project name="new" path="new/p" remote="gos" revision="' + b'5' * 40 + b'"/>\n'
            b'  <project name="kp"'))
        diff = carry.manifest_diff(base, target)
        self.assertEqual(diff['counts'], {'base': 3, 'target': 4})
        self.assertEqual([row['path'] for row in diff['changed']], ['build/release', 'frameworks/base'])
        self.assertEqual(diff['changed'][0]['name'], ['rel', 'rel2'])
        self.assertEqual(diff['renamed'], 1)
        self.assertEqual([row['path'] for row in diff['added']], ['new/p'])
        self.assertEqual(diff['removed'], [])


class RecordedPublicTagTests(Offline):
    """Real GrapheneOS tag objects and the real allowed signers file, verified offline."""

    def verify(self, raw):
        repo = self.work / 'tags'
        if not repo.exists():
            run(self.work, 'init', '-q', '--bare', str(repo))
        oid = run(repo, 'hash-object', '-t', 'tag', '-w', '--stdin', '--literally', data=raw)
        process = subprocess.run(['git', '-c', 'gpg.ssh.program=/usr/bin/ssh-keygen', '-c',
                                  'gpg.ssh.allowedSignersFile=' + str(FIXTURES / 'allowed_signers'),
                                  'verify-tag', oid], cwd=repo, env=GIT_ENV, capture_output=True, timeout=30)
        return oid, process

    def test_recorded_tags_match_records_and_verify(self):
        self.assertEqual(sha((FIXTURES / 'allowed_signers').read_bytes()), source.SIGNERS_SHA256)
        for release in ('2026081300', '2026100600'):
            raw = (FIXTURES / ('tag-%s.raw' % release)).read_bytes()
            record = carry.load_record(ROOT / 'upstream/bases' / (release + '.json'))
            oid, process = self.verify(raw)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn(b'Good "git" signature for contact@grapheneos.org', process.stderr)
            self.assertEqual(oid, record['manifest']['tag_object'])
            fields = carry.parse_tag(raw)
            self.assertEqual((fields['tag'], fields['object'], fields['type']),
                             (release, record['manifest']['commit'], 'commit'))

    def test_tampered_tag_fails(self):
        raw = (FIXTURES / 'tag-2026100600.raw').read_bytes()
        for tampered in (raw.replace(b'tag 2026100600', b'tag 2026100700'),
                         raw.replace(b'object 26f7e8a7', b'object 26f7e8a8'),
                         raw.replace(b'1791386355', b'1791386356')):
            oid, process = self.verify(tampered)
            self.assertNotEqual(process.returncode, 0)


def fragment(message, change_id=None, extra=''):
    body = message + '\n\n' + extra
    if change_id:
        body += '\nChange-Id: ' + change_id + '\n'
    return body


class TrailerTests(Offline):
    def message(self, name):
        # Commit messages only: the recorded fixtures keep no author or committer identities.
        return (FIXTURES / ('commit-%s.message' % name)).read_text()

    def test_recorded_grapheneos_trailers(self):
        found = carry.trailers(self.message('93784e07a8b8'))
        self.assertEqual(found['change_id'], 'I4fab1579d22c4a1dcf2d75d4f4aab0a352df1bd9')
        self.assertEqual(found['cves'], ['CVE-2026-58865'])
        self.assertEqual(found['cve_info'], ['CVE-2026-58865 | Severity: Critical | Type: DoS'])
        self.assertEqual(found['cherry_picked_from'], ['cbb0d81bf0866a8249eca7c7ec53f7c179f8b171'])
        found = carry.trailers(self.message('38400ae03366'))
        self.assertEqual(found['subject'], 'CVE-2025-22442: set profile user restrictions earlier')
        self.assertEqual(found['cves'], ['CVE-2025-22442'])
        self.assertEqual(len(found['cherrypick_from']), 2)
        self.assertTrue(all(url.startswith(carry.CHERRYPICK_PREFIX) for url in found['cherrypick_from']))
        self.assertEqual(found['merged_in'], ['I9019c05f61455feb1ce03d0dd8818a6f13c7af97'])
        found = carry.trailers(self.message('9551f679c4f3'))
        self.assertTrue(found['cve_fix_flag'])
        self.assertEqual(found['cves'], [])
        found = carry.trailers(self.message('bb21412e83bc'))
        self.assertIsNone(found['change_id'])
        self.assertEqual(found['subject'], 'fix integer overflow in ZipFileRO.cpp')
        found = carry.trailers(self.message('84183aff99be'))
        self.assertEqual(found['cves'], ['CVE-2026-55265'])
        self.assertEqual(found['change_id'], 'I46f37df0bd5aa6d75d5043d34b5e831b64b53f57')

    def test_last_change_id_wins(self):
        found = carry.trailers('subject\n\nChange-Id: I' + '1' * 40 + '\n\nmore\n\nChange-Id: I' + '2' * 40 + '\n')
        self.assertEqual(found['change_id'], 'I' + '2' * 40)


class LedgerParsingTests(Offline):
    def test_recorded_bulletin_rows(self):
        rows = carry.bulletin_fixes((FIXTURES / 'asb-2026-09-01.excerpt.html').read_bytes(), '2026-09-01')
        self.assertEqual([r['cve'] for r in rows], ['CVE-2026-28666', 'CVE-2026-55273', 'CVE-2026-49932',
                                                    'CVE-2025-48564', 'CVE-2025-48566'])
        self.assertEqual(rows[0]['commits'], ['8800ef252b9f59834c1e1707bfa47a5de65aae10'])
        self.assertEqual((rows[0]['type'], rows[0]['severity'], rows[0]['component']), ('EoP', 'Critical', 'Framework'))
        self.assertEqual(rows[3]['commits'], rows[4]['commits'])
        other = carry.bulletin_fixes((FIXTURES / 'asb-2026-09-01.excerpt.html').read_bytes(), '2026-09-01',
                                     aosp_project='platform/art')
        self.assertEqual([r['cve'] for r in other], ['CVE-2026-28664'])
        self.assertEqual(carry.bulletin_fixes((FIXTURES / 'asb-2026-09-01.excerpt.html').read_bytes(), '2026-09-01',
                                              version='12'), [])

    def test_recorded_gitiles_log(self):
        log = carry.gitiles_json((FIXTURES / 'gitiles-security-log.excerpt.json').read_bytes())
        commits = {c['commit'][:12]: c for c in log['log']}
        self.assertEqual(len(commits['48fe68e00b94']['parents']), 2)
        self.assertEqual(carry.trailers(commits['79dd06a8c17c']['message'])['change_id'],
                         'I9019c05f61455feb1ce03d0dd8818a6f13c7af97')
        paths = {d['new_path'] for d in commits['79dd06a8c17c']['tree_diff']}
        self.assertIn('services/core/java/com/android/server/pm/PackageManagerShellCommand.java', paths)
        with self.assertRaises(carry.CarryError):
            carry.gitiles_json(b'{"log": []}')

    def test_recorded_preview_lists(self):
        lists = carry.preview_lists((FIXTURES / 'releases.excerpt.html').read_bytes(), ['2026081300', '2026100600'])
        self.assertEqual(lists['2026100600']['preview'], '2026100601')
        self.assertEqual(lists['2026100600']['cves']['Critical'][:2], ['CVE-2026-58814', 'CVE-2026-58820'])
        self.assertEqual(lists['2026081300']['cves']['Unclassified'], ['CVE-2026-55260', 'CVE-2026-58883'])
        self.assertNotIn('Pixels', lists['2026100600']['cves'])
        self.assertEqual(carry.preview_lists((FIXTURES / 'releases.excerpt.html').read_bytes(), ['2026090500']), {})

    def test_security_branch_name(self):
        self.assertEqual(carry.security_branch('refs/tags/android-17.0.0_r1'), 'android17-security-release')
        with self.assertRaises(carry.CarryError):
            carry.security_branch('refs/heads/main')


class FakeHttp(carry.Http):
    def __init__(self, documents):
        super().__init__()
        self.documents = documents

    def get(self, url, allow_missing=False):
        if url not in self.documents:
            if allow_missing:
                return None
            raise carry.NotRun('HTTP 404 from ' + url)
        data = self.documents[url]
        self.retrieved.append({'url': url, 'sha256': sha(data), 'bytes': len(data)})
        return data


def gitiles(value):
    return b")]}'\n" + json.dumps(value).encode()


def commit_json(repo, oid):
    message = run(repo.path, 'show', '-s', '--format=%B', oid) + '\n'
    parents = run(repo.path, 'show', '-s', '--format=%P', oid).split()
    paths = run(repo.path, 'show', '--format=', '--name-only', oid).split()
    return {'commit': oid, 'parents': parents, 'message': message,
            'tree_diff': [{'type': 'modify', 'old_path': p, 'new_path': p} for p in paths]}


def lines(*items):
    return ''.join(item + '\n' for item in items)


THING = lines('one', 'two', 'three', 'thing', 'five', 'six', 'seven')
OLD = lines('L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8')
REV = lines('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8')
TOAST_BEFORE = lines('t1', 't2', 't3', 't4', 't5', 't6')
TOAST_AFTER = lines('t1', 't2', 't3', 'if (token is not empty) refuse', 't4', 't5', 't6')


def own_diff(repo, oid):
    return base64.b64encode(subprocess.run(['git', 'show', '--format=', '--no-color', oid], cwd=repo.path, env=GIT_ENV,
                                           check=True, capture_output=True).stdout)


class LedgerBuildTests(Offline):
    """Every status method, from local stand ins of each source, including content checks."""

    def test_build_ledger(self):
        aosp = Repo(self.work / 'remote/aosp')
        r0 = aosp.commit({'services/Foo.java': JAVA, 'other/Thing.java': THING, 'services/Old.java': OLD,
                          'services/Rev.java': REV, 'services/Toast.java': TOAST_BEFORE}, 'Earlier', '2026-01-05T00:00:00Z')
        # The AOSP base already contains the toast change, made by some other commit.
        r1 = aosp.commit({'services/Toast.java': TOAST_AFTER}, 'Merge release', '2026-01-10T00:00:00Z')
        aosp.tag('android-17.0.0_r1')
        run(aosp.path, 'checkout', '-q', '-b', 'older', r0)
        fix_t = aosp.commit({'services/Toast.java': TOAST_AFTER}, fragment('Block toast windows', 'I' + '9' * 40),
                            '2026-01-08T00:00:00Z')
        run(aosp.path, 'checkout', '-q', '-b', 'android17-security-release', r1)
        fix_a = aosp.commit({'services/Foo.java': JAVA.replace('count * 3', 'count * 4')},
                            fragment('Fix A', 'I' + 'a' * 40), '2026-01-20T00:00:00Z')
        fix_b = aosp.commit({'other/Thing.java': THING.replace('thing', 'thing 2')}, fragment('Fix B', 'I' + 'b' * 40),
                            '2026-01-21T00:00:00Z')
        fix_u = aosp.commit({'services/Old.java': OLD.replace('L4', 'L4 fixed')}, fragment('Fix U', 'I' + 'f' * 40),
                            '2026-01-22T00:00:00Z')
        fix_v = aosp.commit({'services/Rev.java': REV.replace('R4', 'R4 fixed')}, fragment('Fix V', 'I' + '7' * 40),
                            '2026-01-23T00:00:00Z')
        run(aosp.path, 'checkout', '-q', '-b', 'elsewhere', r1)
        fix_d = aosp.commit({'other/Thing.java': THING.replace('thing', 'thing 3')}, fragment('Fix D', 'I' + 'd' * 40),
                            '2026-01-24T00:00:00Z')
        run(aosp.path, 'checkout', '-q', 'android17-security-release')
        gos = Repo(self.work / 'remote/gos-fb')
        run(gos.path, 'fetch', '-q', aosp.url, 'main')
        run(gos.path, 'reset', '-q', '--hard', r1)
        own = gos.commit({'services/ui/Panel.java': lines('panel')}, 'Fix D', '2026-02-01T00:00:00Z')
        base_rev = gos.commit({'services/Old.java': OLD.replace('L5', 'L5 gos')}, 'GrapheneOS change', '2026-02-02T00:00:00Z')
        exact = gos.commit({'services/Foo.java': JAVA.replace('count * 3', 'count * 4')},
                           fragment('Fix A', 'I' + 'a' * 40, 'Cherrypick-From: https://example.invalid/q/commit:1\n'),
                           '2026-02-10T00:00:00Z')
        picked_v = gos.commit({'services/Rev.java': REV.replace('R4', 'R4 fixed')}, fragment('Fix V', 'I' + '7' * 40),
                              '2026-02-11T00:00:00Z')
        related = gos.commit({'other/Thing.java': THING.replace('thing', 'thing 2b')},
                             fragment('Fix B again', 'I' + 'c' * 40, 'Merged-In: I' + 'b' * 40 + '\n'),
                             '2026-02-12T00:00:00Z')
        gos.commit({'services/Rev.java': REV}, fragment('Revert "Fix V"', 'I' + '8' * 40), '2026-02-13T00:00:00Z')
        trailer = gos.commit({'services/ui/Panel.java': lines('panel 2')},
                             fragment('Harden panel', 'I' + 'e' * 40, 'CVE-Info: CVE-2026-0002 | Severity: High | Type: EoP\n'),
                             '2026-02-14T00:00:00Z')
        records = [{'release': '2026020100', 'aosp_default_revision': 'refs/tags/android-17.0.0_r1',
                    'security_patch_level': {'value': '2026-01-05'},
                    'patched_projects': {'frameworks/base': {'url': gos.url, 'revision': base_rev}}},
                   {'release': '2026030100', 'aosp_default_revision': 'refs/tags/android-17.0.0_r1',
                    'security_patch_level': {'value': '2026-02-05'},
                    'patched_projects': {'frameworks/base': {'url': gos.url, 'revision': trailer}}}]
        link = 'https://android.googlesource.com/platform/frameworks/base/+/'
        row = '<tr><td>%s</td><td><a href="%s%s">A-1</a></td><td>EoP</td><td>High</td><td>%s</td></tr>'
        bulletin = ('<h2>2026-02-01 security patch level vulnerability details</h2><h3>Framework</h3><table><tbody>'
                    '<tr><th>CVE</th><th>References</th><th>Type</th><th>Severity</th><th>Updated AOSP versions</th></tr>'
                    + row % ('CVE-2026-0001', link, fix_a, '16, 17') + row % ('CVE-2026-0003', link, fix_d, '17')
                    + row % ('CVE-2026-0004', link, fix_b, '15') + row % ('CVE-2026-0005', link, fix_t, '17')
                    + '</tbody></table>').encode()
        releases = ('<article id=2026020100><p>All of the Android 17 security patches from the current February 2026 '
                    'Android Security Bulletins are included in the 2026020101 security preview release. List of '
                    'additional fixed CVEs:</p><ul><li>High: CVE-2026-0002, CVE-2026-0009</li></ul></article>'
                    '<article id=2026030100><p>Changes</p><ul><li>Pixels: firmware</li></ul></article>').encode()
        log_url = '%s/+log/%s..refs/heads/android17-security-release?format=JSON&n=1000&name-status=1' % (aosp.url, r1)
        documents = {
            carry.BULLETINS + 'asb-overview': b'<a href="/docs/security/bulletin/2025/2025-12-01">old</a>'
                                              b'<a href="/docs/security/bulletin/2026/2026-02-01">new</a>',
            carry.BULLETINS + '2026/2026-02-01': bulletin,
            log_url: gitiles({'log': [commit_json(aosp, o) for o in (fix_v, fix_u, fix_b, fix_a)]}),
            carry.RELEASES: releases}
        for oid in (fix_d, fix_t):
            documents['%s/+/%s?format=JSON' % (aosp.url, oid)] = gitiles(commit_json(aosp, oid))
        for oid in (fix_a, fix_b, fix_u, fix_v, fix_d, fix_t):
            documents['%s/+/%s^!/?format=TEXT' % (aosp.url, oid)] = own_diff(aosp, oid)
        specs = [{'project': 'frameworks/base', 'files': [{'path': 'services/Foo.java'}], 'added': ['services/Added.java']}]
        surface = {'paths': [{'project': 'frameworks/base', 'path': 'services/ui'}], 'runtime': [
            {'project': 'frameworks/base', 'path': 'services/Rev.java'}]}
        backports = [{'release': '2026030100', 'change_id': 'I' + 'd' * 40,
                      'patch': 'patches/grapheneos-2026081300/package-verity.patch'}]
        work = self.work / 'content'
        work.mkdir()
        ledger = carry.build_ledger(self.git(), FakeHttp(documents), records, specs, surface, backports, work,
                                    aosp_url=aosp.url)
        fixes = {row['change_id'][:2]: row for row in ledger['fixes']}
        base, target = '2026020100', '2026030100'
        state = lambda key: {release: (v['status'], v['method'], v['content'])
                             for release, v in fixes[key]['status'].items()}
        # Forward clean at the base, confirmed by content where the Change-Id arrives.
        self.assertEqual(state('Ia'), {base: ('absent', 'content', 'absent'), target: ('present', 'change_id', 'present')})
        self.assertEqual(fixes['Ia']['sources'], ['bulletin', 'security_branch', 'grapheneos'])
        self.assertEqual((fixes['Ia']['andrix_targets'], fixes['Ia']['grapheneos']), (['services/Foo.java'], [exact[:12]]))
        self.assertEqual(fixes['Ia']['content_from'], 'aosp ' + fix_a[:12])
        # Already in the AOSP base: no GrapheneOS commit carries it, the content check finds it.
        self.assertEqual(state('I9'), {base: ('present', 'content', 'present'), target: ('present', 'content', 'present')})
        self.assertEqual(fixes['I9']['sources'], ['bulletin'])
        # Neither direction applies: unresolved, never guessed.
        self.assertEqual(state('If'), {base: ('unresolved', 'content', 'unresolved'),
                                       target: ('unresolved', 'content', 'unresolved')})
        self.assertEqual(fixes['If']['status'][base]['content_files'], {'services/Old.java': 'neither'})
        # Backported through Merged-In, and by a declared Andrix backport.
        self.assertEqual(state('Ib')[target], ('backported', 'merged_in', 'unresolved'))
        self.assertEqual(fixes['Ib']['status'][target]['via'], [related[:12]])
        self.assertNotIn('cves', fixes['Ib'])  # version 15 only in the bulletin
        self.assertEqual(state('Id'), {base: ('absent', 'content', 'absent'), target: ('backported', 'backport', 'unresolved')})
        self.assertEqual(fixes['Id']['status'][target]['patch'], 'patches/grapheneos-2026081300/package-verity.patch')
        self.assertEqual(fixes['Id']['same_subject'], {base: [own[:12]]})
        # A GrapheneOS only fix: its own diff is rebuilt from single objects.
        self.assertEqual(state('Ie'), {base: ('absent', 'content', 'absent'), target: ('present', 'change_id', 'present')})
        self.assertEqual((fixes['Ie']['sources'], fixes['Ie']['content_from']), (['grapheneos'], 'grapheneos ' + trailer[:12]))
        self.assertEqual(fixes['Ie']['andrix_surface'], ['services/ui'])
        self.assertEqual(fixes['Ie']['cves'][0], {'id': 'CVE-2026-0002', 'source': 'grapheneos-trailer',
                                                  'type': 'EoP', 'severity': 'High'})
        # Carried by Change-Id, then reverted: the methods disagree, and the ledger says so.
        self.assertEqual(state('I7'), {base: ('absent', 'content', 'absent'), target: ('present', 'change_id', 'absent')})
        self.assertEqual(fixes['I7']['grapheneos'], [picked_v[:12]])
        self.assertEqual(fixes['I7']['andrix_surface'], ['services/Rev.java'])
        check = ledger['content_check']
        self.assertEqual([(d['change_id'][:2], d['release'], d['note']) for d in check['disagreements']],
                         [('I7', target, 'the content check finds the change absent')])
        self.assertEqual(sorted((u['change_id'][:2], u['release']) for u in check['unconfirmed']),
                         [('Ib', target), ('Id', target)])
        self.assertEqual(check['results'], {base: {'present': 1, 'absent': 5, 'unresolved': 1},
                                            target: {'present': 3, 'absent': 1, 'unresolved': 3}})
        self.assertEqual(check['diffs'], {'aosp': 6, 'grapheneos': 1})
        self.assertNotIn('Ic', fixes)
        self.assertEqual([p['preview_release'] for p in ledger['preview']], ['2026020101', None])
        self.assertEqual(ledger['preview'][0]['cves'], {'High': ['CVE-2026-0002', 'CVE-2026-0009']})
        self.assertFalse(ledger['preview'][0]['public_source'])
        self.assertEqual([b['grapheneos_commits_since_aosp_base'] for b in ledger['bases']], [2, 7])
        summary = carry.ledger_summary(ledger, base, target)
        self.assertEqual((summary['absent_at_base'], summary['present_at_base'], summary['unresolved_at_base'],
                          summary['bulletin_linked'], summary['in_patch_targets'], summary['present_at_target'],
                          summary['content_disagreements'], summary['content_unconfirmed']), (5, 1, 1, 2, 1, 3, 1, 2))
        self.assertIn(carry.BULLETINS + '2026/2026-02-01', [s['url'] for s in ledger['sources']])
        self.assertNotIn(carry.BULLETINS + '2025/2025-12-01', [s['url'] for s in ledger['sources']])


def hunk_sides(data):
    """{path: (old bytes, new bytes)} built from the hunk sides of a recorded diff, in order."""
    files = {}
    for section in carry.split_diff(data):
        old, new, body = [], [], False
        for line in section['text'].split(b'\n'):
            if line.startswith(b'@@ '):
                body = True
            elif body and line.startswith(b' '):
                old.append(line[1:])
                new.append(line[1:])
            elif body and line.startswith(b'-'):
                old.append(line[1:])
            elif body and line.startswith(b'+'):
                new.append(line[1:])
        files[section['path']] = (b'\n'.join(old) + b'\n', b'\n'.join(new) + b'\n')
    return files


class ContentCheckTests(Offline):
    """Recorded AOSP diffs tried at fuzz 0, dry run only, against files built from their own hunks."""

    def recorded(self, name):
        return base64.b64decode((FIXTURES / ('gitiles-%s.diff.b64' % name)).read_bytes())

    def check(self, data, files):
        work = self.work / 'content'
        work.mkdir(exist_ok=True)
        return carry.content_state(carry.split_diff(data), files, work)

    def test_fix_already_in_the_base_is_present(self):
        data = self.recorded('a00072f03623')  # the toast window fix, already in android-17.0.0_r1
        sections = carry.split_diff(data)
        self.assertEqual([s['path'] for s in sections], [
            'services/core/java/com/android/server/wm/WindowManagerService.java',
            'services/tests/wmtests/src/com/android/server/wm/WindowManagerServiceTests.java'])
        self.assertIn(b'addToastWindowRequiresToken && !token.isEmpty()', data)
        after = {path: new for path, (old, new) in hunk_sides(data).items()}
        state, files, skipped = self.check(data, after)
        self.assertEqual((state, set(files.values()), skipped), ('present', {'present'}, {}))

    def test_forward_applicable_fix_is_absent(self):
        data = self.recorded('03988cf95e56')  # openProxyFileDescriptor caller check, September 2026
        before = {path: old for path, (old, new) in hunk_sides(data).items()}
        self.assertEqual(sorted(before), ['services/core/java/com/android/server/StorageManagerService.java',
                                          'services/core/java/com/android/server/storage/AppFuseBridge.java'])
        state, files, _ = self.check(data, before)
        self.assertEqual((state, set(files.values())), ('absent', {'absent'}))

    def test_mixed_or_changed_files_are_unresolved(self):
        data = self.recorded('a00072f03623')
        sides = hunk_sides(data)
        wms, tests = sorted(sides)
        state, files, _ = self.check(data, {wms: sides[wms][1], tests: sides[tests][0]})
        self.assertEqual((state, files[wms], files[tests]), ('unresolved', 'present', 'absent'))
        changed = sides[wms][1].replace(b'// Make sure this happens before', b'// Make sure this happens after', 1)
        self.assertNotEqual(changed, sides[wms][1])
        state, files, _ = self.check(data, {wms: changed, tests: sides[tests][1]})
        self.assertEqual((state, files[wms]), ('unresolved', 'neither'))
        state, files, _ = self.check(data, {tests: sides[tests][1]})
        self.assertEqual((state, files[wms]), ('unresolved', 'neither'))  # the file is missing at this base
        # Both directions apply when a file holds both sides: ambiguous, so unresolved.
        old, new = sides[wms]
        state, files, _ = self.check(data, {wms: old + new, tests: sides[tests][1]})
        self.assertEqual((state, files[wms]), ('unresolved', 'both'))

    def test_dry_run_only_never_writes_or_fuzzes(self):
        data = self.recorded('03988cf95e56')
        before = {path: old for path, (old, new) in hunk_sides(data).items()}
        calls, real = [], subprocess.run

        def tree(cwd):
            return {p.relative_to(cwd).as_posix(): p.read_bytes() for p in cwd.rglob('*') if p.is_file()}

        def spy(command, *args, **kwargs):
            if command and command[0] == '/usr/bin/patch':
                calls.append(list(command))
                snapshot = tree(Path(kwargs['cwd']))
                self.assertTrue(snapshot)
                result = real(command, *args, **kwargs)
                self.assertEqual(tree(Path(kwargs['cwd'])), snapshot)  # a dry run writes nothing
                return result
            return real(command, *args, **kwargs)

        with mock.patch.object(carry.subprocess, 'run', side_effect=spy):
            self.check(data, before)
        self.assertEqual(len(calls), 4)
        for command in calls:
            self.assertEqual(command[:7], [*carry.PATCH_COMMAND, '--dry-run'])
            self.assertEqual([a for a in command if a.startswith('--fuzz')], ['--fuzz=0'])
        self.assertEqual(sum('-R' in command for command in calls), 2)

    def test_split_diff_marks_what_patch_cannot_check(self):
        data = (b'diff --git a/res/icon.png b/res/icon.png\nindex 1..2 100644\nBinary files a/res/icon.png and '
                b'b/res/icon.png differ\n'
                b'diff --git a/old.txt b/new.txt\nsimilarity index 90%\nrename from old.txt\nrename to new.txt\n'
                b'--- a/old.txt\n+++ b/new.txt\n@@ -1 +1 @@\n-a\n+b\n'
                b'diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n'
                b'diff --git a/added.txt b/added.txt\nnew file mode 100644\nindex 0000000..1\n--- /dev/null\n'
                b'+++ b/added.txt\n@@ -0,0 +1 @@\n+x\n'
                b'diff --git a/../escape b/../escape\n--- a/../escape\n+++ b/../escape\n@@ -1 +1 @@\n-a\n+b\n')
        sections = carry.split_diff(data)
        self.assertEqual([(s['path'], s['skip']) for s in sections], [
            ('res/icon.png', 'binary'), ('new.txt', 'rename or copy'), ('run.sh', 'no text hunks'), ('added.txt', None),
            ('../escape', 'unsafe path')])
        self.assertEqual(sections[3]['paths'], ['added.txt'])
        state, files, skipped = self.check(data, {})
        self.assertEqual((state, files, len(skipped)), ('absent', {'added.txt': 'absent'}, 4))
        state, files, _ = self.check(data, {'added.txt': b'x\n'})
        self.assertEqual((state, files), ('present', {'added.txt': 'present'}))
        self.assertEqual(self.check(sections[0]['text'], {})[0], 'unresolved')  # nothing checkable

    def test_decision_order_and_disagreements(self):
        none = {'change_id': set(), 'content': 'unresolved', 'later': set(), 'backport': None, 'merged_in': set(),
                'cve': set()}
        cases = [({'change_id': {'x'}, 'content': 'absent'}, ('present', 'change_id'), 'the content check finds the change absent'),
                 ({'content': 'present', 'later': {'y'}}, ('present', 'content'), 'its Change-Id lands only in a later base'),
                 ({'content': 'present'}, ('present', 'content'), None),
                 ({'backport': 'patches/x.patch', 'merged_in': {'z'}}, ('backported', 'backport'), None),
                 ({'backport': 'patches/x.patch', 'content': 'absent'}, ('backported', 'backport'), None),
                 ({'merged_in': {'z'}, 'cve': {'w'}}, ('backported', 'merged_in'), None),
                 ({'cve': {'w'}, 'content': 'absent'}, ('backported', 'cve'), 'the content check finds the change absent'),
                 ({'content': 'absent', 'later': {'y'}}, ('absent', 'content'), None),
                 ({'later': {'y'}}, ('absent', 'change_id'), None),
                 ({}, ('unresolved', 'content'), None)]
        for change, expected, note in cases:
            evidence = dict(none, **change)
            self.assertEqual(carry.decide(evidence), expected, change)
            self.assertEqual(carry.disagreement(*expected, evidence), note, change)

    def test_grapheneos_commit_diff_from_single_objects(self):
        repo = Repo(self.work / 'remote/gos')
        parent = repo.commit({'a/Keep.java': lines('k1', 'k2'), 'a/Change.java': OLD, 'gone.txt': lines('bye'),
                              'logo.bin': b'\x00\x01'}, 'parent')
        commit = repo.commit({'a/Change.java': OLD.replace('L4', 'L4 fixed'), 'gone.txt': None,
                              'b/New.java': lines('new'), 'logo.bin': b'\x00\x02'}, 'commit')
        store = self.git().store(repo.url)
        work = self.work / 'diff'
        work.mkdir()
        data = carry.commit_diff(store, store.commits([commit])[commit], work)
        sections = {s['path']: s for s in carry.split_diff(data)}
        self.assertEqual(sorted(sections), ['a/Change.java', 'b/New.java', 'gone.txt', 'logo.bin'])
        self.assertEqual(sections['logo.bin']['skip'], 'binary')
        at = lambda oid: {p: e[1] if e else None for p, e in store.files(oid, sorted(sections)).items()}
        self.assertEqual(self.check(data, at(commit))[0], 'present')
        self.assertEqual(self.check(data, at(parent))[0], 'absent')


class CarryCheckTests(Offline):
    """The whole check on a signed local release: tags, manifests, objects, history, seal."""

    BASE, TARGET = '2026010100', '2026020200'

    def build(self, target_java, key=None):
        remote = self.work / 'remote'
        self.key, self.signers = ssh_key(self.work)
        key = key or self.key
        fb = Repo(remote / 'fb')
        self.fb_base = fb.commit({'services/Foo.java': JAVA, 'services/Surface.java': 'class Surface {\n'
                                  '    abstract void old();\n}\n', 'services/Other.java': 'class Other {}\n'}, 'base')
        fb.tag(self.BASE)
        fb.commit({'services/Foo.java': target_java},
                  fragment('Fix the counter', 'I' + 'f' * 40, 'CVE-Info: CVE-2026-0007 | Severity: High | Type: EoP\n'
                           'Cherrypick-From: https://googleplex-android-review.googlesource.com/q/commit:' + '9' * 40 + '\n'))
        self.fb_target = fb.commit({'services/Surface.java': 'class Surface {\n    abstract void old();\n'
                                    '    abstract int added(int a);\n}\n'}, fragment('Surface API', 'I' + '1' * 40))
        fb.tag(self.TARGET)
        rel = Repo(remote / 'rel')
        rel_base = rel.commit(release_files('2026-01-05'), 'release base')
        rel_target = rel.commit(release_files('2026-02-05'), 'release target')
        kp = Repo(remote / 'kp')
        kp_rev = kp.commit({'Image': 'kernel\n'}, 'kernel')
        manifest = Repo(remote / 'platform_manifest')
        for tag, fb_rev, rel_rev in ((self.BASE, self.fb_base, rel_base), (self.TARGET, self.fb_target, rel_target)):
            manifest.commit({'default.xml': MANIFEST.format(aosp='file://' + str(remote / 'aosp'), gos='file://%s/' % remote,
                                                            tag=tag, fb=fb_rev, rel=rel_rev, kp=kp_rev)}, tag)
            manifest.tag(tag, key=key)
        self.manifest_url = manifest.url
        patch_spec = demo_spec(self.work, JAVA, CANDIDATE, added=['services/Added.java'])
        patch_spec['head'] = self.fb_base
        self.specs = [patch_spec]
        self.surface = {'schema': carry.SCHEMA['surface'],
                        'projects': [{'project': 'frameworks/base', 'reason': 'x'}, {'project': 'build/release', 'reason': 'y'}],
                        'paths': [{'project': 'frameworks/base', 'path': 'services/Surface.java', 'reason': 'stub'}],
                        'runtime': [{'project': 'frameworks/base', 'path': 'services/Other.java', 'reason': 'trial',
                                     'evidence': 'x.md:1', 'cites': 'Other'}]}

    def records(self):
        with mock.patch.object(source, 'SIGNERS_SHA256', sha(self.signers.read_bytes())):
            base, _, _ = carry.derive_record(self.git(), self.BASE, self.signers, ['frameworks/base'], self.manifest_url)
            target, _, _ = carry.derive_record(self.git(), self.TARGET, self.signers, ['frameworks/base'], self.manifest_url)
        return base, target

    def check(self, base, target, ledger_rows=()):
        out = self.work / 'records'
        out.mkdir(exist_ok=True)
        base_path, target_path, ledger_path = out / 'base.json', out / 'target.json', out / 'ledger.json'
        for path in (base_path, target_path, ledger_path):
            path.unlink(missing_ok=True)
        carry.write_new(base_path, base)
        carry.write_new(target_path, target)
        ledger = {'schema': carry.SCHEMA['ledger'], 'project': 'frameworks/base',
                  'bases': [{'release': r['release'], 'record_sha256': sha(carry.dump(r))} for r in (base, target)],
                  'fixes': list(ledger_rows), 'preview': []}
        carry.write_new(ledger_path, ledger)
        work = self.work / 'check-apply'
        work.mkdir(exist_ok=True)
        with mock.patch.object(source, 'SIGNERS_SHA256', sha(self.signers.read_bytes())):
            return carry.run_check(self.git(), FakeHttp({}), base_path, self.TARGET, self.signers, ledger_path, work,
                                   target_path, self.manifest_url, self.specs, self.surface)

    def test_records_from_signed_local_releases(self):
        self.build(JAVA)
        base, target = self.records()
        carry.validate_record(dict(base, manifest=dict(base['manifest'], allowed_signers_sha256=source.SIGNERS_SHA256)))
        self.assertEqual(base['release'], self.BASE)
        self.assertEqual(base['manifest']['signer'], 'fixture@example.invalid')
        self.assertEqual(base['projects']['count'], 3)
        self.assertEqual(base['security_patch_level']['value'], '2026-01-05')
        self.assertEqual(target['security_patch_level']['value'], '2026-02-05')
        self.assertEqual(list(base['kernel_prebuilts']), ['kernel/prebuilts/6.12/arm64'])
        self.assertEqual(base['patched_projects']['frameworks/base']['revision'], self.fb_base)

    def test_moved_target_carries_and_seals(self):
        moved = JAVA.replace('package demo;\n', 'package demo;\n\nimport a.B;\n')
        self.build(moved)
        base, target = self.records()
        fix = {'change_id': 'I' + 'f' * 40, 'sources': ['bulletin', 'security_branch', 'grapheneos'],
               'andrix_targets': ['services/Foo.java'],
               'status': {self.BASE: {'status': 'absent', 'method': 'content', 'content': 'absent'},
                          self.TARGET: {'status': 'present', 'method': 'change_id', 'content': 'present'}}}
        report = self.check(base, target, [fix])
        self.assertEqual(report['verdict'], 'CARRIED')
        demo = report['patches'][0]
        self.assertEqual(demo['files'][0]['class'], 'moved')
        self.assertEqual(demo['added'], [{'path': 'services/Added.java', 'upstream': 'absent'}])
        self.assertEqual(demo['files'][0]['upstream_commits'][0]['cves'], ['CVE-2026-0007'])
        history = report['history']['frameworks/base']
        self.assertEqual((history['complete'], history['count'], history['with_cve'], history['with_cherrypick']),
                         (True, 2, 1, 1))
        self.assertEqual(history['commits'][1]['cherrypick_from'], ['9' * 40])
        surface = {row['path']: row for row in report['surface']}
        self.assertEqual(surface['services/Surface.java']['class'], 'changed')
        self.assertEqual(surface['services/Surface.java']['api_added'], ['abstract int added(int a)'])
        self.assertEqual((surface['services/Other.java']['class'], surface['services/Other.java']['list']),
                         ('identical', 'runtime'))
        self.assertEqual(surface['services/Surface.java']['list'], 'paths')
        self.assertEqual(report['status'], 'base %s (patch level 2026-01-05); latest %s (2026-02-05); 1 known '
                         'frameworks/base security fixes absent (1 bulletin linked, 1 fixed in latest), 1 in Andrix '
                         'patch targets; all patches apply at fuzz 0, 1 targets with line offsets'
                         % (self.BASE, self.TARGET))
        self.assertEqual(report['seal'], carry.seal(report))
        path = self.work / 'report.json'
        carry.write_new(path, report)
        with mock.patch.object(carry, 'ROOT', self.work):
            report['base']['record'] = 'records/base.json'
            report['ledger']['path'] = 'records/ledger.json'
            report['seal'] = carry.seal(report)
            resealed = self.work / 'resealed.json'
            carry.write_new(resealed, report)
            _, drift = carry.verify_report(resealed)
            self.assertEqual([d for d in drift if 'record' in d or 'ledger' in d], [])
            tampered = json.loads(resealed.read_text())
            tampered['verdict'] = 'CONFLICT'
            resealed.write_text(json.dumps(tampered))
            with self.assertRaisesRegex(carry.CarryError, 'seal'):
                carry.verify_report(resealed)
        with self.assertRaisesRegex(carry.CarryError, 'overwrite'):
            carry.write_new(path, report)

    def test_conflict_and_missing_targets_are_published(self):
        self.build(JAVA.replace('        value -= 1;\n', '        value -= 5;\n'))
        report = self.check(*self.records())
        self.assertEqual((report['verdict'], report['patches'][0]['class']), ('CONFLICT', 'conflict'))
        self.assertIn('1 conflicting and 0 missing patch targets', report['status'])
        shutil.rmtree(self.work / 'remote')
        os.remove(self.signers)
        self.build(None)
        report = self.check(*self.records())
        self.assertEqual(report['patches'][0]['files'][0]['class'], 'missing')
        self.assertEqual(report['verdict'], 'CONFLICT')

    def test_added_path_existing_upstream_conflicts(self):
        self.build(JAVA)
        fb = self.work / 'remote/fb'
        run(fb, 'tag', '-d', self.TARGET)
        (fb / 'services/Added.java').write_text('class Added {}\n')
        run(fb, 'add', '-A')
        run(fb, 'commit', '-q', '-m', 'upstream adds the same path')
        self.specs[0]['head'] = self.fb_base
        new_target = run(fb, 'rev-parse', 'HEAD')
        run(fb, 'tag', '-a', '-m', self.TARGET, self.TARGET)
        manifest = self.work / 'remote/platform_manifest'
        text = (manifest / 'default.xml').read_text().replace(self.fb_target, new_target)
        (manifest / 'default.xml').write_text(text)
        run(manifest, 'commit', '-q', '-am', 'retarget')
        run(manifest, 'tag', '-d', self.TARGET)
        run(manifest, '-c', 'gpg.format=ssh', '-c', 'user.signingKey=' + str(self.key), 'tag', '-s', '-m', self.TARGET,
            self.TARGET)
        report = self.check(*self.records())
        self.assertEqual(report['patches'][0]['added'], [{'path': 'services/Added.java', 'upstream': 'exists'}])
        self.assertEqual(report['verdict'], 'CONFLICT')

    def test_tampered_tag_or_manifest_is_refused(self):
        self.build(JAVA)
        base, target = self.records()
        # The check re-derives both records from their signed releases and refuses any difference.
        with self.assertRaisesRegex(carry.CarryError, 'does not match its signed release'):
            self.check(dict(base, manifest=dict(base['manifest'], sha256='0' * 64)), target)
        with self.assertRaisesRegex(carry.CarryError, 'does not match its signed release'):
            self.check(dict(base, projects=dict(base['projects'], table_sha256='0' * 64)), target)
        with self.assertRaisesRegex(carry.CarryError, 'target record does not match'):
            self.check(base, dict(target, release=target['release'], aosp_default_revision='refs/tags/android-17.0.0_r2'))
        # A tag signed by a key outside the allowed signers file.
        other = self.work / 'other'
        other.mkdir()
        other_key, _ = ssh_key(other, 'intruder@example.invalid')
        manifest = self.work / 'remote/platform_manifest'
        run(manifest, 'tag', '-d', self.TARGET)
        run(manifest, '-c', 'gpg.format=ssh', '-c', 'user.signingKey=' + str(other_key), 'tag', '-s', '-m',
            self.TARGET, self.TARGET)
        with mock.patch.object(source, 'SIGNERS_SHA256', sha(self.signers.read_bytes())):
            with self.assertRaisesRegex(carry.CarryError, 'signature rejected'):
                carry.verify_release(self.git(), self.TARGET, self.signers, self.manifest_url)
        # A validly signed tag object for another release, published under this release's name.
        run(manifest, 'tag', '-d', self.TARGET)
        run(manifest, 'tag', self.TARGET, 'refs/tags/' + self.BASE)  # lightweight alias of the base tag object
        with mock.patch.object(source, 'SIGNERS_SHA256', sha(self.signers.read_bytes())):
            with self.assertRaisesRegex(carry.CarryError, 'does not name this release'):
                carry.verify_release(self.git(), self.TARGET, self.signers, self.manifest_url)
            run(manifest, 'tag', '-f', self.TARGET, 'HEAD')
            with self.assertRaisesRegex(carry.CarryError, 'not annotated'):
                carry.verify_release(self.git(), self.TARGET, self.signers, self.manifest_url)
        with self.assertRaisesRegex(carry.CarryError, 'allowed signers'):
            carry.verify_release(self.git(), self.TARGET, self.signers, self.manifest_url)


class SourceFailureTests(Offline):
    """Unavailable or limited sources end in NOT_RUN, never in a guess."""

    def test_http_failures(self):
        http = carry.Http(interval=0)
        for error, expected in ((urllib.error.HTTPError('u', 429, 'Too Many Requests', {}, None), 'rate limited'),
                                (urllib.error.HTTPError('u', 403, 'Forbidden', {}, None), 'rate limited'),
                                (urllib.error.HTTPError('u', 500, 'Server Error', {}, None), 'HTTP 500'),
                                (urllib.error.URLError('down'), 'network unavailable')):
            with mock.patch('urllib.request.urlopen', side_effect=error):
                with self.assertRaisesRegex(carry.NotRun, expected):
                    http.get('https://grapheneos.org/releases')
        with mock.patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError('u', 404, 'Missing', {}, None)):
            self.assertIsNone(http.get('https://grapheneos.org/missing', allow_missing=True))
        for url in ('http://grapheneos.org/releases', 'https://example.com/x', 'file:///etc/passwd'):
            with self.assertRaises(carry.CarryError):
                http.get(url)

    def test_http_redirect_and_size_limits(self):
        class Response(io.BytesIO):
            def __init__(self, data, final):
                super().__init__(data)
                self.final = final

            def geturl(self):
                return self.final

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        http = carry.Http(limit=10, interval=0)
        with mock.patch('urllib.request.urlopen', return_value=Response(b'x' * 11, 'https://grapheneos.org/releases')):
            with self.assertRaisesRegex(carry.NotRun, 'size limit'):
                http.get('https://grapheneos.org/releases')
        with mock.patch('urllib.request.urlopen', return_value=Response(b'ok', 'https://example.com/elsewhere')):
            with self.assertRaisesRegex(carry.CarryError, 'redirected'):
                http.get('https://grapheneos.org/releases')
        with mock.patch('urllib.request.urlopen', return_value=Response(b'ok', 'https://grapheneos.org/releases')):
            self.assertEqual(http.get('https://grapheneos.org/releases'), b'ok')
        self.assertEqual(http.retrieved[-1]['sha256'], sha(b'ok'))

    def test_http_requests_to_one_host_are_paced(self):
        http = carry.Http(interval=0.2)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = 'https://grapheneos.org/releases'
        response.read.return_value = b'ok'
        slept = []
        with mock.patch('urllib.request.urlopen', return_value=response), \
                mock.patch.object(carry.time, 'sleep', side_effect=slept.append):
            http.get('https://grapheneos.org/releases')
            http.get('https://grapheneos.org/releases')
            http.get('https://source.android.com/docs/security/bulletin/asb-overview')
        self.assertEqual(len(slept), 1)
        self.assertTrue(0 < slept[0] <= 0.2)

    def test_git_failures(self):
        git = self.git()
        failed = subprocess.CompletedProcess([], 128, b'', b'fatal: unable to access: The requested URL returned '
                                                            b'error: 429')
        with mock.patch.object(carry.subprocess, 'run', return_value=failed):
            with self.assertRaisesRegex(carry.NotRun, 'rate limited'):
                git.run(None, ['ls-remote', 'https://github.com/GrapheneOS/platform_manifest'], network=True)
            with self.assertRaisesRegex(carry.CarryError, 'Git failed'):
                git.run(None, ['rev-parse', 'HEAD'])
        with self.assertRaisesRegex(carry.NotRun, 'Git fetch failed'):
            git.ls_remote('file://' + str(self.work / 'absent'), ['refs/tags/x'])
        for url in ('https://example.com/repo', 'http://github.com/x', 'ssh://github.com/x',
                    'https://user@github.com/x', 'https://github.com:8443/x'):
            with self.assertRaises(carry.CarryError):
                carry.Git(self.work, protocols=('https',)).check_url(url)

    def test_scratch_budget_and_missing_objects(self):
        repo = Repo(self.work / 'remote/r')
        commit = repo.commit({'big.bin': os.urandom(200000)}, 'big')
        git = self.git(budget=1000)
        with self.assertRaisesRegex(carry.NotRun, 'budget'):
            git.store(repo.url).commits([commit])
        git = self.git()
        store = git.store(repo.url)
        with self.assertRaisesRegex(carry.NotRun, '.'):
            store.ensure(['0' * 40])

    def test_cli_not_run_and_fail_exit_codes(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.object(carry, 'derive_record', side_effect=carry.NotRun('rate limited by github.com')):
                self.assertEqual(carry.main(['record', '--tag', '2026100600', '--allowed-signers',
                                             str(FIXTURES / 'allowed_signers'), '--scratch', str(self.work / 's1'),
                                             '--out', str(self.work / 'r.json')]), 3)
        self.assertIn('NOT_RUN: rate limited', err.getvalue())
        self.assertFalse((self.work / 'r.json').exists())
        self.assertTrue((self.work / 's1').exists() is False)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(carry.main(['record', '--tag', '2026100600', '--allowed-signers',
                                         str(FIXTURES / 'allowed_signers'), '--scratch', str(ROOT / 'scratch'),
                                         '--out', str(self.work / 'r.json')]), 1)
        self.assertIn('outside the repository', err.getvalue())
        kept = self.work / 'kept'
        kept.mkdir()
        (kept / 'x').write_text('x')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(carry.main(['record', '--tag', '2026100600', '--allowed-signers',
                                         str(FIXTURES / 'allowed_signers'), '--scratch', str(kept),
                                         '--out', str(self.work / 'r.json')]), 1)
        self.assertTrue((kept / 'x').exists())


class RecordFormatTests(Offline):
    def test_render_round_trip_and_rows(self):
        value = {'schema': 'x', 'fixes': [{'change_id': 'I1', 'status': {'a': 'absent'}}] * 2, 'small': [1, 2],
                 'nested': {'deep': {'list': list(range(40))}}}
        text = carry.dump(value).decode()
        self.assertEqual(json.loads(text), value)
        self.assertIn('\n    {"change_id": "I1", "status": {"a": "absent"}},\n', text)
        self.assertIn('"small": [1, 2]', text)

    def test_write_new_refuses_and_replaces_only_on_request(self):
        path = self.work / 'r.json'
        digest = carry.write_new(path, {'a': 1})
        self.assertEqual(digest, sha(path.read_bytes()))
        with self.assertRaises(carry.CarryError):
            carry.write_new(path, {'a': 2})
        carry.write_new(path, {'a': 2}, replace=True)
        self.assertEqual(json.loads(path.read_text()), {'a': 2})
        self.assertEqual([p.name for p in self.work.iterdir()], ['r.json'])

    def test_strict_json(self):
        path = self.work / 'dup.json'
        path.write_text('{"a": 1, "a": 2}')
        with self.assertRaisesRegex(carry.CarryError, 'duplicate'):
            carry.load_json(path)
        path.write_text('{"a": NaN}')
        with self.assertRaises(carry.CarryError):
            carry.load_json(path)


class CommittedRecordTests(Offline):
    """The committed records agree with the pinned verifier, the tools and each other."""

    def test_pinned_base_record(self):
        record = carry.load_record(ROOT / 'upstream/bases/2026081300.json')
        self.assertEqual(record['manifest']['tag_object'], source.TAG_OBJECT)
        self.assertEqual(record['manifest']['commit'], source.MANIFEST_COMMIT)
        self.assertEqual(record['manifest']['sha256'], source.MANIFEST_SHA256)
        self.assertEqual(record['projects']['count'], source.PROJECT_COUNT)
        self.assertEqual(record['manifest']['allowed_signers_sha256'], source.SIGNERS_SHA256)
        heads = {spec['project']: spec['head'] for spec in carry.load_patch_set(source.TAG)}
        self.assertEqual({p: v['revision'] for p, v in record['patched_projects'].items()}, heads)

    @unittest.skipUnless(GRAPHENEOS_ROOT, 'set ANDRIX_GRAPHENEOS_ROOT to the pinned GrapheneOS source root')
    def test_pinned_manifest_bytes(self):
        data = (Path(GRAPHENEOS_ROOT) / '.repo/manifests/default.xml').read_bytes()
        record = carry.load_record(ROOT / 'upstream/bases/2026081300.json')
        self.assertEqual(sha(data), record['manifest']['sha256'])
        rows = carry.project_rows(carry.parse_manifest(data))
        self.assertEqual(sha(carry.canonical(rows)), record['projects']['table_sha256'])
        projection = [{key: row[key] for key in ('path', 'revision', 'remote', 'groups')} for row in rows]
        self.assertEqual(source.parse_projects(data), projection)

    def test_sealed_report_ledger_and_status(self):
        path = ROOT / 'upstream/reports/2026081300-2026100600.json'
        report, drift = carry.verify_report(path)
        self.assertEqual(drift, [])
        ledger = carry.validate_ledger(carry.load_json(ROOT / report['ledger']['path']))
        records = [carry.load_record(ROOT / 'upstream/bases' / (r + '.json')) for r in ('2026081300', '2026100600')]
        self.assertEqual({b['release']: b['record_sha256'] for b in ledger['bases']},
                         {r['release']: sha(carry.dump(r)) for r in records})
        self.assertEqual(report['target']['record_sha256'], sha(carry.dump(records[1])))
        summary = carry.ledger_summary(ledger, '2026081300', '2026100600')
        summary['in_lab_only_targets'] = report['ledger']['in_lab_only_targets']
        self.assertEqual(carry.status_line(records[0], records[1], report['patches'], summary), report['status'])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(carry.main(['status', str(path)]), 0)
        self.assertEqual(out.getvalue().strip(), report['status'])
        for row in (ROOT / 'upstream/bases').glob('*.json'):
            self.assertEqual(row.read_bytes(), carry.dump(carry.load_json(row)))


if __name__ == '__main__':
    unittest.main()
