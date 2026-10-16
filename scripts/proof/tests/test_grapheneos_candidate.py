# SPDX-License-Identifier: Apache-2.0
"""The candidate base check: the scratch checkout that selects the candidate, the checks it runs
there, the exact patch set, policy record and host tested record it requires and its refusals,
beside the production guard of the selected base. A fixture repository stands in for this one. No
Android tree is used: the source verifier and the patch tools run against an empty tree and report
their refusals."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import grapheneos_base as base  # noqa: E402
import grapheneos_candidate as candidate  # noqa: E402

PINNED, SECOND = '2026081300', '2026100600'
PINNED_PATCHES, SECOND_PATCHES = 'patches/grapheneos-2026081300', 'patches/grapheneos-2026100600'
SECOND_RECORD = 'upstream/bases/2026100600.json'
NATIVE = SECOND_PATCHES + '/native-principal-pins.patch'
POLICY = SECOND_PATCHES + '/owner-session-policy.json'
# The payload companion's host tested record of each base, keyed by the base.
PINNED_HOST = 'tests/installer-durability/pis-reverse-write-sync.candidate.json'
SECOND_HOST = ('tests/installer-durability/grapheneos-2026100600/'
               'pis-reverse-write-sync.candidate.json')
# The production boot read of the native patch, as an added line.
BOOT = '+                NativeIdentityStore.Format.V3);\n'
SETTINGS = 'services/core/java/com/android/server/pm/Settings.java'
# The record's own host tool, run in a checkout: it validates the record it reads and names it.
HOST_TOOL = ('import sys; sys.path.insert(0, "tests/installer-durability"); '
             'import pis_reverse_write_sync as host; host.profile(); '
             'print(host.PROFILE.relative_to(host.ROOT).as_posix())')
# A non Java patch that no profile records.
UNRECORDED = '--- a/extra.te\n+++ b/extra.te\n@@ -0,0 +1 @@\n+allow domain self:process *;\n'
# How the patch set check ends each refusal: the policy record fields that differ, the inventory
# of the patch directory and the host tested record fields that differ.
FIELDS = 'does not name the selected base and its review patch: '
INVENTORY = 'missing %s, unexpected %s, not regular files %s'
HOST_FIELDS = 'the host tested record %s does not name the selected base: ' % SECOND_HOST
# The fixture's Git: no system or global configuration, a fixed author.
GIT = {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_AUTHOR_NAME': 'fixture', 'GIT_AUTHOR_EMAIL': 'fixture@invalid',
       'GIT_COMMITTER_NAME': 'fixture', 'GIT_COMMITTER_EMAIL': 'fixture@invalid'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT)
    return subprocess.run(['git', '-C', str(root), *args], env=environment, capture_output=True,
                          check=True, timeout=120).stdout


def python_environment():
    return {key: value for key, value in os.environ.items()
            if key not in candidate.DROPPED_ENVIRONMENT}


def rewrite(path, **changes):
    value = json.loads(path.read_text())
    value.update(changes)
    path.write_text(json.dumps(value, indent=2) + '\n')


def fixture_repository(directory):
    """A Git repository standing in for this one: the working tree's files a commit would hold,
    with an honest candidate patch directory beside the production one. Returns its root."""
    root = directory / 'repository'
    listing = git(ROOT, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
    for name in os.fsdecode(listing).split('\0'):
        if name and (ROOT / name).is_file() and not (ROOT / name).is_symlink():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, root / name)
    honest_candidate(root)
    git(root, 'init', '--quiet')
    commit(root, 'an honest candidate')
    return root


def honest_candidate(root):
    """A copy of the selected base's patch directory, pointed at the 2026100600 base: every profile
    names that base's revision of its project and the policy record names that base. The payload
    companion's own host tested record, keyed by that base, is a copy of the selected base's that
    names that base's revision and package verity profile. No file of the selected base changes.
    They replace any candidate directory and record of that base that the copy holds."""
    record = json.loads((root / SECOND_RECORD).read_text())
    revisions = {project: row['revision'] for project, row in record['patched_projects'].items()}
    for directory in (root / SECOND_PATCHES, (root / SECOND_HOST).parent):
        shutil.rmtree(directory, ignore_errors=True)
    shutil.copytree(root / PINNED_PATCHES, root / SECOND_PATCHES)
    for profile in sorted((root / SECOND_PATCHES).glob('*.json')):
        rewrite(profile, head=revisions[json.loads(profile.read_text())['project']])
    rewrite(root / POLICY, base_release=SECOND)
    verity = root / SECOND_PATCHES / 'package-verity.json'
    (root / SECOND_HOST).parent.mkdir()
    shutil.copyfile(root / PINNED_HOST, root / SECOND_HOST)
    rewrite(root / SECOND_HOST, head=revisions['frameworks/base'],
            base_profile=SECOND_PATCHES + '/package-verity.json',
            base_profile_sha256=sha(verity.read_bytes()))
    rewrite(root / SECOND_PATCHES / 'package-installer-payload-sync.json',
            requires=SECOND_PATCHES + '/package-verity.json',
            requires_sha256=sha(verity.read_bytes()), host_profile=SECOND_HOST,
            host_profile_sha256=sha((root / SECOND_HOST).read_bytes()))


def commit(root, message):
    git(root, 'add', '--all')
    git(root, 'commit', '--quiet', '--message', message)
    return git(root, 'rev-parse', 'HEAD').decode().strip()


def edit(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise AssertionError('fixture anchor not found once in ' + path.name)
    path.write_text(text.replace(old, new))


class CandidateCheckTests(unittest.TestCase):
    """One fixture repository. Its main line holds an honest candidate, then a native patch whose
    boot read passes the retired format, then a truncated patch hunk beside it. Side revisions of
    the honest candidate hold one patch set defect each, and one a link."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name).resolve()
        cls.root = root = fixture_repository(cls.directory)
        cls.honest = git(root, 'rev-parse', 'HEAD').decode().strip()
        policy, candidates = root / POLICY, root / SECOND_PATCHES

        def side(name, change):
            git(root, 'checkout', '--quiet', '--detach', cls.honest)
            change()
            return commit(root, name)
        cls.defects = {
            'a policy record of the old base and digest': side(
                'a policy record of the old base and digest',
                lambda: rewrite(policy, base_release=PINNED, patch_sha256='0' * 64)),
            'no policy artifacts': side(
                'no policy artifacts',
                lambda: [(candidates / name).unlink() for name in
                         ('owner-session-policy.json', 'owner-session-policy.patch')]),
            'an unrecorded patch': side(
                'an unrecorded patch',
                lambda: (candidates / 'unrecorded.patch').write_text(UNRECORDED))}
        cls.linked = side('a link', lambda: (root / 'a-link').symlink_to('README.md'))
        git(root, 'checkout', '--quiet', '--detach', cls.honest)
        edit(root / NATIVE, BOOT, BOOT.replace('V3', 'V1'))
        cls.retired = commit(root, 'a candidate boot read of the retired format')
        lifecycle = candidates / 'owner-lifecycle.patch'
        lifecycle.write_bytes(lifecycle.read_bytes().rsplit(b'\n', 4)[0] + b'\n')
        cls.truncated = commit(root, 'a truncated candidate hunk')
        cls.tree = cls.directory / 'tree'
        cls.tree.mkdir()
        cls.signers = cls.directory / 'allowed_signers'
        cls.signers.write_text('not the approved trust input\n')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check(self, revision, name):
        """The fixture's own copy of the tool on one revision: its process and its report."""
        scratch = self.directory / name.replace(' ', '-')
        process = subprocess.run(
            [sys.executable, '-B', str(self.root / 'scripts/proof/grapheneos_candidate.py'),
             'check', '--release', SECOND, '--source-root', str(self.tree), '--allowed-signers',
             str(self.signers), '--scratch', str(scratch), '--revision', revision],
            env=python_environment(), capture_output=True, text=True, timeout=900)
        return process, json.loads((scratch / 'report.json').read_text()), scratch

    def test_a_candidate_is_checked_in_a_scratch_checkout_that_selects_it(self):
        selection = (self.root / base.SELECTION).read_bytes()
        process, report, scratch = self.check(self.honest, 'honest')
        self.assertEqual(process.returncode, 1, process.stderr)
        printed = json.loads(process.stdout)
        self.assertEqual((printed['verdict'], printed['checks']['format guard'],
                          printed['checks']['patch set']), ('FAIL', 'PASS', 'PASS'))
        record = sha((self.root / SECOND_RECORD).read_bytes())
        self.assertEqual(
            (report['release'], report['revision'], report['record'], report['record_sha256']),
            (SECOND, self.honest, SECOND_RECORD, record))
        self.assertEqual((report['repository_selects'], report['verdict']), (PINNED, 'FAIL'))
        # The checkout selects the candidate by its record digest, and is otherwise its revision.
        tree = scratch / 'checkout'
        self.assertEqual(json.loads((tree / base.SELECTION).read_text()),
                         {'schema': base.SCHEMA, 'release': SECOND, 'record': SECOND_RECORD,
                          'record_sha256': record})
        self.assertEqual(sha((tree / base.SELECTION).read_bytes()), report['selection_sha256'])
        selected = base.load(root=tree)
        self.assertEqual((selected.release, selected.patches), (SECOND, tree / SECOND_PATCHES))
        listed = git(self.root, 'ls-tree', '-r', '-z', '--name-only', self.honest)
        files = [path.relative_to(tree).as_posix() for path in tree.rglob('*') if path.is_file()]
        self.assertEqual(sorted(files), sorted(filter(None, os.fsdecode(listed).split('\0'))))
        self.assertEqual((tree / NATIVE).read_bytes(),
                         git(self.root, 'show', '%s:%s' % (self.honest, NATIVE)))
        # Each check ran the checkout's own copy of its tool: the guard and the patch set check
        # read the candidate, and the source verifier and every patch tool read the given tree.
        rows = report['checks']
        self.assertEqual([row['check'] for row in rows],
                         ['format guard', 'patch set', 'source verifier', *candidate.PATCH_TOOLS,
                          'policy record'])
        for row in rows[:-1]:
            self.assertEqual(Path(row['command'][2]).parent, tree / 'scripts/proof', row['check'])
        guard, patches = rows[0], rows[1]
        self.assertEqual(
            (guard['result'], guard['base'], guard['production_patches'], guard['format_guard']),
            ('PASS', SECOND, SECOND_PATCHES, 'PASS'))
        policy = json.loads((tree / POLICY).read_text())
        self.assertEqual((patches['result'], patches['base'], patches['patch_set']),
                         ('PASS', SECOND, 'PASS'))
        self.assertEqual(sorted(patches['patches']), sorted(candidate.PATCH_NAMES))
        self.assertEqual(patches['policy'], {key: policy[key] for key in (
            'upstream_sha256', 'adapted_sha256', 'patch_sha256')})
        # It read the candidate's own host tested record. The selected base's record beside it is
        # this repository's, byte for byte.
        self.assertEqual(patches['host_record'],
                         {'path': SECOND_HOST, 'sha256': sha((tree / SECOND_HOST).read_bytes())})
        self.assertEqual((tree / PINNED_HOST).read_bytes(), (ROOT / PINNED_HOST).read_bytes())
        self.assertEqual(rows[2]['result'], 'FAIL')
        self.assertIn('Allowed-signers bytes differ from the approved trust input',
                      rows[2]['failure'])
        for row in rows[3:-1]:
            self.assertEqual(row['result'], 'FAIL', row['check'])
            self.assertIn(str(self.tree), row['failure'], row['check'])
        # The policy record is compared with the policy tool's reading only when both pass.
        self.assertEqual((rows[-1]['result'], rows[-1]['failure']),
                         ('NOT_RUN', 'needs a passing patch set and policy tool check'))
        for name in ('format-guard.out', 'patch-set.out', 'source-verifier.err',
                     'native-principal-pins.err'):
            self.assertTrue((scratch / 'evidence' / name).is_file(), name)
        # The fixture still selects the pinned base, with the same bytes, and its tree is clean.
        self.assertEqual((self.root / base.SELECTION).read_bytes(), selection)
        self.assertEqual(json.loads(selection)['release'], PINNED)
        self.assertEqual(git(self.root, 'status', '--porcelain'), b'')

    def test_a_candidate_patch_set_is_refused_unless_exact(self):
        refusals = {
            'a policy record of the old base and digest': FIELDS + 'base_release, patch_sha256',
            'no policy artifacts': INVENTORY % (
                ['owner-session-policy.json', 'owner-session-policy.patch'], [], []),
            'an unrecorded patch': INVENTORY % ([], ['unrecorded.patch'], [])}
        for name, revision in self.defects.items():
            with self.subTest(case=name):
                process, report, _ = self.check(revision, name)
                self.assertEqual((process.returncode, report['verdict']), (1, 'FAIL'))
                rows = {row['check']: row for row in report['checks']}
                self.assertEqual(rows['format guard']['result'], 'PASS')
                self.assertEqual(rows['patch set']['result'], 'FAIL')
                self.assertEqual(len(rows['patch set']['patch_set']), 1)
                self.assertTrue(rows['patch set']['patch_set'][0].endswith(refusals[name]),
                                rows['patch set']['patch_set'])
                self.assertEqual(rows['policy record']['result'], 'NOT_RUN')

    def test_a_candidate_with_a_malformed_patch_is_refused(self):
        process, report, _ = self.check(self.retired, 'retired')
        self.assertEqual((process.returncode, report['verdict']), (1, 'FAIL'))
        guard, patches = report['checks'][0], report['checks'][1]
        self.assertEqual((guard['check'], guard['result'], guard['base']),
                         ('format guard', 'FAIL', SECOND))
        section = '%s:%s' % (NATIVE, SETTINGS)
        self.assertIn('v1: %s names the retired format: Format.V1' % section, guard['format_guard'])
        self.assertIn('format: the boot construction passes NativeIdentityStore.Format.V1, not '
                      'NativeIdentityStore.Format.V3', guard['format_guard'])
        # Its profile no longer names the patch's digest, so the tool's own profile check refuses.
        self.assertEqual((patches['check'], patches['result'], patches['patch_set']),
                         ('patch set', 'FAIL', ['ValueError: native principal profile drift']))
        process, report, _ = self.check(self.truncated, 'truncated')
        self.assertEqual((process.returncode, report['verdict']), (1, 'FAIL'))
        guard = report['checks'][0]
        self.assertEqual((guard['result'], guard['format_guard']),
                         ('FAIL', ['production texts: truncated patch hunk']))

    def test_the_patch_set_check_reads_the_selected_base_exactly(self):
        # A checkout of the honest revision selecting the candidate; each change below is made in
        # that scratch checkout alone and undone, and its own copy of the tool checks it.
        scratch = self.directory / 'patch-set'
        scratch.mkdir()
        with mock.patch.object(candidate, 'ROOT', self.root):
            tree = candidate.checkout(scratch, self.honest)[0]
            candidate.select(tree, SECOND)
        directory, policy = tree / SECOND_PATCHES, tree / POLICY

        def patch_set():
            process = subprocess.run(
                [sys.executable, '-B', str(tree / 'scripts/proof/grapheneos_candidate.py'),
                 'patch-set'], cwd=tree, env=python_environment(), capture_output=True, text=True,
                timeout=300)
            report = json.loads(process.stdout)
            return process.returncode, report['patch_set'], report

        code, result, report = patch_set()
        self.assertEqual((code, result, report['base'], report['patches_directory']),
                         (0, 'PASS', SECOND, SECOND_PATCHES))
        self.assertEqual(report['patches'], list(candidate.PATCH_NAMES))
        self.assertEqual(report['host_record']['path'], SECOND_HOST)
        # The checkout's copy of the record's own host tool reads and accepts the same record.
        process = subprocess.run([sys.executable, '-B', '-c', HOST_TOOL], cwd=tree,
                                 env=python_environment(), capture_output=True, text=True,
                                 timeout=300)
        self.assertEqual((process.returncode, process.stdout), (0, SECOND_HOST + '\n'),
                         process.stderr)
        record = json.loads(policy.read_text())
        old = (tree / PINNED_PATCHES / 'native-principal-pins.json').read_text()
        host, pinned_host = tree / SECOND_HOST, tree / PINNED_HOST
        own = json.loads(host.read_text())
        payload = directory / 'package-installer-payload-sync.json'

        def named_host(path, data):
            # The candidate's payload profile names another record by its path and digest.
            value = dict(json.loads(payload.read_text()), host_profile=path,
                         host_profile_sha256=sha(data))
            payload.write_text(json.dumps(value, indent=2) + '\n')

        def changed(path, text):
            def change():
                path.write_text(text)
            return change

        def removed(*names):
            def change():
                for name in names:
                    (directory / name).unlink()
            return change

        def linked():
            target = tree / 'owner-lifecycle.json'
            (directory / 'owner-lifecycle.json').rename(target)
            (directory / 'owner-lifecycle.json').symlink_to(target)

        def field(**changes):
            return changed(policy, json.dumps(dict(record, **changes), indent=2) + '\n')

        def host_field(**changes):
            return changed(host, json.dumps(dict(own, **changes), indent=2) + '\n')

        def linked_host():
            host.rename(tree / 'host.json')
            host.symlink_to(tree / 'host.json')

        def shared_host():
            # The selected base's record rewritten to follow the candidate instead of its own.
            pinned_host.write_bytes(host.read_bytes())
            host.unlink()
            named_host(PINNED_HOST, pinned_host.read_bytes())
        no_record = 'the selected base has no host tested record ' + SECOND_HOST
        cases = (
            ('without a README', removed('README.md'), None),
            ('the old base', field(base_release=PINNED), FIELDS + 'base_release'),
            ('the old revision', field(head=json.loads(old)['head']), FIELDS + 'head'),
            ('another file', field(file='private/file.te'), FIELDS + 'file'),
            ('another upstream digest', field(upstream_sha256='1' * 64),
             FIELDS + 'upstream_sha256'),
            ('another review patch', field(patch='native-principal-pins.patch'), FIELDS + 'patch'),
            ('a zero patch digest', field(patch_sha256='0' * 64), FIELDS + 'patch_sha256'),
            ('a malformed adapted digest', field(adapted_sha256='HEAD'), FIELDS + 'adapted_sha256'),
            ('a record that is no object', changed(policy, '[]\n'),
             'the owner session policy record is not a JSON object'),
            ('a duplicate key', changed(policy, policy.read_text().replace(
                '"base_release": "2026100600",',
                '"base_release": "2026100600", "base_release": "2026081300",')),
             'the carry tool refuses the patch set: duplicate JSON key: base_release'),
            ('no policy record', removed('owner-session-policy.json'),
             INVENTORY % (['owner-session-policy.json'], [], [])),
            ('no review patch', removed('owner-session-policy.patch'),
             INVENTORY % (['owner-session-policy.patch'], [], [])),
            ('an unrecorded patch', changed(directory / 'unrecorded.patch', '+x\n'),
             INVENTORY % ([], ['unrecorded.patch'], [])),
            ('a nested directory', lambda: (directory / 'nested').mkdir(),
             INVENTORY % ([], ['nested'], ['nested'])),
            ('a linked profile', linked, INVENTORY % ([], [], ['owner-lifecycle.json'])),
            ('a profile of the old base', changed(directory / 'native-principal-pins.json', old),
             'ValueError: native principal profile drift'),
            ('no host tested record', host.unlink, no_record),
            ('a linked host tested record', linked_host, no_record),
            ("the selected base's host tested record", changed(host, pinned_host.read_text()),
             HOST_FIELDS + 'base_profile, base_profile_sha256, head'),
            ('a host tested record of the old revision', host_field(head=json.loads(old)['head']),
             HOST_FIELDS + 'head'),
            ('a host tested record of the old verity profile',
             host_field(base_profile=PINNED_PATCHES + '/package-verity.json'),
             HOST_FIELDS + 'base_profile'),
            ('a host tested record that is no object', changed(host, '[]\n'),
             'the host tested record %s is not a JSON object' % SECOND_HOST),
            ('a host tested record with a duplicate key',
             changed(host, host.read_text().replace('"head":', '"head": "x", "head":', 1)),
             'the host tested record %s: duplicate JSON key: head' % SECOND_HOST),
            ("a payload profile naming the selected base's record",
             lambda: named_host(PINNED_HOST, pinned_host.read_bytes()),
             'ValueError: payload sync profile drift'),
            ("the selected base's record shared", shared_host, no_record))
        saved = {path: path.read_bytes() for path in (*directory.iterdir(), host, pinned_host)}
        for name, change, refusal in cases:
            with self.subTest(case=name):
                change()
                code, result, _ = patch_set()
                if refusal is None:
                    self.assertEqual((code, result), (0, 'PASS'))
                else:
                    self.assertEqual(code, 1)
                    self.assertEqual(len(result), 1)
                    self.assertTrue(result[0].endswith(refusal), result)
                for path in (*directory.iterdir(), host):
                    if path.is_dir() and not path.is_symlink():
                        path.rmdir()
                    elif path not in saved or path.is_symlink():
                        path.unlink()
                for path, data in saved.items():
                    path.write_bytes(data)
                (tree / 'owner-lifecycle.json').unlink(missing_ok=True)
                (tree / 'host.json').unlink(missing_ok=True)
        self.assertEqual(patch_set()[:2], (0, 'PASS'))

    def test_the_policy_record_must_agree_with_the_policy_tools_reading(self):
        named = {'upstream_sha256': 'a' * 64, 'adapted_sha256': 'b' * 64, 'patch_sha256': 'c' * 64}

        def rows(patch_set='PASS', tool='PASS', bridge='b' * 64):
            return [{'check': 'patch set', 'result': patch_set, 'policy': named},
                    {'check': 'owner_policy', 'result': tool, 'upstream_sha256': 'a' * 64,
                     'bridge_sha256': bridge}]
        self.assertEqual(candidate.policy_agreement(rows())['result'], 'PASS')
        found = candidate.policy_agreement(rows(bridge='d' * 64))
        self.assertEqual((found['result'], found['failure']),
                         ('FAIL', 'the policy record names other digests than the tree gives: '
                                  'adapted_sha256'))
        for failed in (rows(patch_set='FAIL'), rows(tool='FAIL'), rows(tool='NOT_RUN')):
            self.assertEqual(candidate.policy_agreement(failed)['result'], 'NOT_RUN')

    def test_the_repository_patch_set_is_exact(self):
        found = candidate.patch_set()
        record = json.loads((ROOT / PINNED_PATCHES / 'owner-session-policy.json').read_text())
        self.assertEqual(found['patches'], list(candidate.PATCH_NAMES))
        self.assertEqual(found['policy'], {key: record[key] for key in (
            'upstream_sha256', 'adapted_sha256', 'patch_sha256')})
        self.assertEqual(found['host_record'], {'path': PINNED_HOST,
                                                'sha256': sha((ROOT / PINNED_HOST).read_bytes())})
        self.assertEqual(candidate.patch_set_report()[1], 0)

    def test_the_production_guard_of_the_selected_base_ignores_the_candidate(self):
        # The fixture's working tree holds the truncated candidate, which no production read parses.
        self.assertEqual(git(self.root, 'rev-parse', 'HEAD').decode().strip(), self.truncated)
        process = subprocess.run(
            [sys.executable, '-B', str(self.root / 'scripts/proof/native_creation_binding.py'),
             '--format-guard-only'], env=python_environment(), capture_output=True, text=True,
            timeout=600)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual((report['base'], report['production_patches']), (PINNED, PINNED_PATCHES))
        self.assertEqual((report['format_guard'], report['status']), ('PASS', 'SOURCE_ONLY'))
        # The selected base's patch set passes with its own host tested record, which the
        # candidate's beside it left as it was.
        process = subprocess.run(
            [sys.executable, '-B', str(self.root / 'scripts/proof/grapheneos_candidate.py'),
             'patch-set'], env=python_environment(), capture_output=True, text=True, timeout=300)
        self.assertEqual(process.returncode, 0, process.stdout)
        report = json.loads(process.stdout)
        self.assertEqual((report['base'], report['patch_set'], report['host_record']),
                         (PINNED, 'PASS', {'path': PINNED_HOST,
                                           'sha256': sha((ROOT / PINNED_HOST).read_bytes())}))

    def test_the_checkout_is_exactly_its_revision(self):
        scratch = self.directory / 'exact'
        scratch.mkdir()
        original = tarfile.TarFile.extractall
        changes = (('extra', 'planted.txt', 'not exactly the revision'),
                   ('changed', 'README.md', 'differs from the revision: README.md'))
        with mock.patch.object(candidate, 'ROOT', self.root):
            self.assertEqual(candidate.checkout(scratch, self.honest),
                             (scratch / 'checkout', self.honest))
            # A selection written there has the repository's own form, byte for byte.
            self.assertEqual(candidate.select(scratch / 'checkout', PINNED).release, PINNED)
            self.assertEqual((scratch / 'checkout' / base.SELECTION).read_bytes(),
                             (ROOT / base.SELECTION).read_bytes())
            self.assertEqual(candidate.select(scratch / 'checkout', SECOND).release, SECOND)
            with self.assertRaisesRegex(candidate.CandidateError, 'a link or a submodule: a-link'):
                candidate.checkout(self.directory / 'linked', self.linked)
            for name, written, pattern in changes:
                def extract(archive, path, *args, written=written, **kwargs):
                    original(archive, path, *args, **kwargs)
                    (Path(path) / written).write_text('x')
                (self.directory / name).mkdir()
                with self.subTest(case=name), \
                        mock.patch.object(tarfile.TarFile, 'extractall', extract), \
                        self.assertRaisesRegex(candidate.CandidateError, pattern):
                    candidate.checkout(self.directory / name, self.honest)

    def test_the_scratch_is_new_and_outside_the_source_tree(self):
        busy = self.directory / 'busy'
        busy.mkdir()
        (busy / 'kept').write_text('x')
        tree = self.tree.resolve()
        for path, pattern in ((busy, 'new or empty'), (tree / 'scratch', 'outside the source tree'),
                              (tree.parent, 'outside the source tree')):
            with self.subTest(path=path), self.assertRaisesRegex(candidate.CandidateError, pattern):
                candidate.scratch_dir(path, tree)
        self.assertEqual(sorted(path.name for path in busy.iterdir()), ['kept'])
        self.assertFalse((tree / 'scratch').exists())

    def test_the_tool_refuses_the_working_tree(self):
        before = (ROOT / base.SELECTION).read_bytes()
        refusal = "the scratch must be outside the repository's working tree"
        for scratch in (ROOT, ROOT / 'scripts', ROOT / 'candidate-scratch', ROOT.parent):
            arguments = ['check', '--release', SECOND, '--source-root', str(self.tree),
                         '--allowed-signers', str(self.signers), '--scratch', str(scratch)]
            errors = io.StringIO()
            with self.subTest(scratch=scratch), contextlib.redirect_stderr(errors), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(candidate.main(arguments), 1)
                self.assertIn(refusal, errors.getvalue())
        self.assertFalse((ROOT / 'candidate-scratch').exists())
        # Its selection is written only in a scratch checkout: never in this working tree, nor in
        # another Git checkout.
        for tree in (ROOT, self.root):
            with self.subTest(tree=tree), \
                    self.assertRaisesRegex(candidate.CandidateError, 'never in the'):
                candidate.select(tree, SECOND)
        self.assertEqual((ROOT / base.SELECTION).read_bytes(), before)
        self.assertEqual(base.load().release, PINNED)


if __name__ == '__main__':
    unittest.main()
