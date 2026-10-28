# SPDX-License-Identifier: Apache-2.0
"""The candidate patch set exporter. Its parts are checked on this repository's records and on
synthetic Git projects and source. Then an honest export, beside a negative control of each kind
(a wrong base, missing objects, host drift, a policy disagreement and an old artifact changed),
runs in a fixture repository whose records, profiles and sealed report name fixture Git projects.
So does each fault late in an export, beside its honest twin: a full evidence filesystem, an
ordinary termination signal, another entry in the candidate directories, a created path replaced
by another file, another directory or a link to the selected base's patches, a created file
removed and made again, a parent replaced while writing, a record failure after the final
record's rename, with or without the failure record's second name, and a kill just after it. The
selection and every old artifact must keep their bytes in every case.

The honest export needs the public upstream files of the patch targets at both bases. Name local
copies with ANDRIX_CARRY_FILES (2026081300=DIR:2026100600=DIR, each DIR holding <project>/<path>
files of that release). Without it the fixture repository cases skip. FileUtils.java is
synthetic unless a DIR holds it. No network is used."""
import copy
import difflib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
sys.path.insert(0, str(ROOT / 'tests/installer-durability'))
import grapheneos_base as base  # noqa: E402
import grapheneos_candidate as candidate  # noqa: E402
import grapheneos_carry as carry  # noqa: E402
import grapheneos_export as export  # noqa: E402
import grapheneos_source as source  # noqa: E402
import owner_policy as policy  # noqa: E402
import pis_reverse_write_sync as host  # noqa: E402

PINNED, SECOND = '2026081300', '2026100600'
REPORT = 'upstream/reports/2026081300-2026100600.json'
SECOND_RECORD = 'upstream/bases/2026100600.json'
PINNED_PATCHES, SECOND_PATCHES = 'patches/grapheneos-2026081300', 'patches/grapheneos-2026100600'
PINNED_HOST = 'tests/installer-durability/pis-reverse-write-sync.candidate.json'
SECOND_HOSTS = 'tests/installer-durability/grapheneos-2026100600'
SECOND_HOST = SECOND_HOSTS + '/pis-reverse-write-sync.candidate.json'
FRAMEWORK, SEPOLICY = 'frameworks/base', 'system/sepolicy'
PREFIX = 'services/core/java/com/android/server/'
PIS = PREFIX + 'pm/PackageInstallerSession.java'
CHANGED = {'services/core/java/com/android/server/pm/InstallPackageHelper.java': 'moved',
           'services/core/java/com/android/server/StorageManagerService.java': 'moved',
           'services/core/java/com/android/server/pm/PackageManagerShellCommand.java':
               'changed clean'}
# The candidate's files in the order an export writes them.
WRITTEN = [SECOND_PATCHES + '/' + name for name in (
    'native-principal-pins.patch', 'native-principal-pins.json', 'owner-lifecycle.patch',
    'owner-lifecycle.json', 'package-verity.patch', 'package-verity.json',
    'native-identity-writer.patch', 'native-identity-writer.json')] + [SECOND_HOST] + [
    SECOND_PATCHES + '/' + name for name in (
        'package-installer-payload-sync.patch', 'package-installer-payload-sync.json',
        'owner-session-policy.patch', 'owner-session-policy.json', 'README.md')]
# Local copies of the public upstream files, by release.
FILES = dict(item.split('=', 1) for item in os.environ.get('ANDRIX_CARRY_FILES', '').split(':')
             if '=' in item)
NEEDS_FILES = 'set ANDRIX_CARRY_FILES to local copies of the upstream patch target files'
PRINCIPAL = 'fixture@example.invalid'
# The fixture's Git: no system or global configuration, a fixed author.
GIT = {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_AUTHOR_NAME': 'fixture', 'GIT_AUTHOR_EMAIL': PRINCIPAL,
       'GIT_COMMITTER_NAME': 'fixture', 'GIT_COMMITTER_EMAIL': PRINCIPAL,
       'GIT_ALLOW_PROTOCOL': 'file'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT)
    return subprocess.run(['git', '-C', str(root), *args], env=environment, capture_output=True,
                          check=True, timeout=120).stdout


def text(root, *args):
    return git(root, *args).decode().strip()


def python_environment():
    return {key: value for key, value in os.environ.items()
            if key not in candidate.DROPPED_ENVIRONMENT}


def rewrite(path, **changes):
    value = json.loads(path.read_text())
    value.update(changes)
    path.write_text(json.dumps(value, indent=2) + '\n')


def ssh_key(directory):
    key = directory / 'key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'export fixture', '-f',
                    str(key)], check=True, capture_output=True, timeout=30)
    signers = directory / 'allowed_signers'
    signers.write_text(PRINCIPAL + ' ' + ' '.join(
        (directory / 'key.pub').read_text().split()[:2]) + '\n')
    return key, signers


def commits(path, trees):
    """A Git project with one commit for each tree of files in turn, each the child of the one
    before, its worktree at the last. Returns the commits."""
    path.mkdir(parents=True)
    git(path, 'init', '--quiet')
    git(path, 'config', 'uploadpack.allowFilter', 'true')
    found = []
    for files in trees:
        for name in filter(None, git(path, 'ls-files', '-z').decode().split('\0')):
            (path / name).unlink()
        for name, data in files.items():
            (path / name).parent.mkdir(parents=True, exist_ok=True)
            (path / name).write_bytes(data)
        git(path, 'add', '--all')
        git(path, 'commit', '--quiet', '--allow-empty', '--message', 'fixture %d' % len(found))
        found.append(text(path, 'rev-parse', 'HEAD'))
    return found


def signed_manifest(path, key, release, data=b'<manifest/>\n'):
    """A manifest repository whose commit holds default.xml under a tag signed with key."""
    commit = commits(path, [{'default.xml': data}])[0]
    git(path, '-c', 'gpg.format=ssh', '-c', 'user.signingKey=' + str(key), 'tag', '-s', '-m',
        release, release)
    return {'commit': commit, 'tag_object': text(path, 'rev-parse', 'refs/tags/' + release),
            'blob': text(path, 'rev-parse', 'HEAD:default.xml'), 'sha256': sha(data)}


def synthetic_fileutils():
    """FileUtils.java source whose host tested sync fragment is the fixture's."""
    header, region = host.SYNC_FRAGMENT.read_text().split(host.ATTRIBUTION, 1)
    return (header + 'package android.os;\n\npublic final class FileUtils {\n' + region
            + host.SYNC_REGIONS[0][1] + '        return false;\n    }\n}\n').encode()


def synthetic_pis(fragment):
    """Package Installer source whose host tested fragment is the given fixture's."""
    header, regions = fragment.read_text().split(host.ATTRIBUTION, 1)
    second = regions.index(host.PIS_REGIONS[1][0])
    return (header + 'package com.android.server.pm;\n\npublic class PackageInstallerSession {\n'
            + regions[:second] + host.PIS_REGIONS[0][1] + '        return null;\n    }\n\n'
            + regions[second:] + host.PIS_REGIONS[1][1] + '    }\n}\n').encode()


def sealed_rows():
    """The sealed report's patch rows without the upstream commits an offline carry omits."""
    rows = copy.deepcopy(carry.load_json(ROOT / REPORT)['patches'])
    for row in rows:
        for entry in row['files']:
            entry.pop('upstream_commits', None)
    return rows


def verification(directory, record, **changes):
    """A passing result.json of the candidate's source verification, as grapheneos_source.py
    writes it for a scratch checkout selecting the candidate, with any field changed."""
    directory.mkdir()
    rows = [{'path': project, 'revision': row['revision'], 'remote': 'grapheneos', 'groups': '',
             'head': row['revision'], 'verdict': 'PASS'}
            for project, row in sorted(record['patched_projects'].items())]
    rows += [{'path': 'fixture/project-%04d' % number, 'revision': '0' * 40, 'remote': 'aosp',
              'groups': '', 'head': '0' * 40, 'verdict': 'PASS'}
             for number in range(record['projects']['count'] - len(rows))]
    count = record['projects']['count']
    value = {'schema': 1, 'verdict': 'PASS_PINNED_SOURCE_HEADS', 'release': record['release'],
             'manifest_commit': record['manifest']['commit'],
             'manifest_tag': record['manifest']['tag_object'],
             'manifest_sha256': record['manifest']['sha256'], 'tag_signature_verified': True,
             'repo_commit': source.REPO_COMMIT, 'declared_projects': count,
             'verified_projects': count, 'projects': rows, 'build_proved': False}
    value.update(changes)
    (directory / 'result.json').write_text(json.dumps(value, indent=2) + '\n')
    return directory


def evidence_record(scratch):
    """An export's evidence record as a reader takes it: export.json, or export.fail.json if
    export.json is absent. None if neither exists."""
    for name in (export.RECORD, export.FALLBACK):
        path = Path(scratch) / 'evidence' / name
        if path.is_file():
            return json.loads(path.read_text())
    return None


def snapshot(root):
    """Every entry of a fixture repository's old artifact directories, by path."""
    found = {}
    for top in export.OLD_ARTIFACTS:
        for path in sorted((root / top).rglob('*')):
            name = path.relative_to(root).as_posix()
            if not (name.startswith(SECOND_PATCHES) or name.startswith(SECOND_HOSTS)):
                found[name] = sha(path.read_bytes()) if path.is_file() else 'directory'
    return found


class ReportAndRecordTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name in ('upstream', 'patches'):
            shutil.copytree(ROOT / name, self.root / name)
        for module in (export, carry):
            patcher = mock.patch.object(module, 'ROOT', self.root)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.report = self.root / REPORT
        self.value = carry.load_json(self.report)
        self.selected = base.load(root=self.root)

    def resealed(self, **changes):
        value = copy.deepcopy(self.value)
        for key, item in changes.items():
            parent = value
            *path, last = key.split('.')
            for part in path:
                parent = parent[part]
            if item is None:
                del parent[last]
            else:
                parent[last] = item
        value['seal'] = carry.seal(value)
        self.report.write_bytes(carry.dump(value))

    def test_the_selected_base_report_must_be_sealed_carried_and_unchanged(self):
        report, first, second = export.sealed(self.report, self.selected)
        self.assertEqual((report['verdict'], first['release'], second['release']),
                         ('CARRIED', PINNED, SECOND))
        self.assertEqual(second['patched_projects'][FRAMEWORK]['revision'],
                         '84183aff99be5e156dc0446a6fa2d4a7150f4bc3')
        self.assertEqual(second['patched_projects'][SEPOLICY]['revision'],
                         '5e359dcf9ae863a593e9055a85e1657c87c4cb18')
        lifecycle = self.root / PINNED_PATCHES / 'owner-lifecycle.patch'
        original = self.report.read_bytes()
        cases = (
            ('a broken seal', lambda: self.report.write_bytes(carry.dump(dict(
                self.value, status='changed'))), carry.CarryError, 'seal does not verify'),
            ('an old patch changed', lambda: lifecycle.write_bytes(lifecycle.read_bytes() + b'\n'),
             export.ExportError, 'drift: patch %s/owner-lifecycle.patch' % PINNED_PATCHES),
            ('a review verdict', lambda: self.resealed(verdict='REVIEW'), export.ExportError,
             'is REVIEW, not CARRIED'),
            ('a public source not run', lambda: self.resealed(not_run=['x']), export.ExportError,
             'has checks not run: x'),
            ('another carry tool', lambda: self.resealed(**{'generated.tool_sha256': '0' * 64}),
             export.ExportError, 'not the one that sealed the report'),
            ('no target record', lambda: self.resealed(**{'target.record': None}),
             export.ExportError, 'names no record of another release'))
        saved = lifecycle.read_bytes()
        for name, change, error, pattern in cases:
            with self.subTest(case=name):
                change()
                try:
                    with self.assertRaisesRegex(error, pattern):
                        export.sealed(self.report, self.selected)
                finally:
                    self.report.write_bytes(original)
                    lifecycle.write_bytes(saved)
        # A report naming another digest of the base record has drift.
        value = copy.deepcopy(self.value)
        value['base']['record_sha256'] = '1' * 64
        value['seal'] = carry.seal(value)
        self.report.write_bytes(carry.dump(value))
        with self.assertRaisesRegex(export.ExportError, 'drift: base record changed'):
            export.sealed(self.report, self.selected)
        self.report.write_bytes(original)
        # A report outside upstream/reports, and a selection of another base, are refused.
        outside = self.root / 'report.json'
        outside.write_bytes(original)
        with self.assertRaisesRegex(export.ExportError, 'not a sealed report in upstream/reports'):
            export.sealed(outside, self.selected)
        selection = self.root / 'selection.json'
        selection.write_text(json.dumps({
            'schema': base.SCHEMA, 'release': SECOND, 'record': SECOND_RECORD,
            'record_sha256': sha((self.root / SECOND_RECORD).read_bytes())}) + '\n')
        other = base.load(selection=selection, root=self.root)
        with self.assertRaisesRegex(export.ExportError,
                                    'is of base 2026081300, not of the selected base 2026100600'):
            export.sealed(self.report, other)

    def test_the_source_verification_must_pass_for_the_target(self):
        record = carry.load_record(self.root / SECOND_RECORD)
        honest = verification(self.root / 'honest', record)
        found = export.verified_source(honest, record)
        self.assertEqual((found['declared_projects'], found['repo_commit']),
                         (1057, source.REPO_COMMIT))
        revision = record['patched_projects'][FRAMEWORK]['revision']
        rows = json.loads((honest / 'result.json').read_text())['projects']
        cases = (
            ('a failed verification', {'verdict': 'FAIL'}, 'verdict'),
            ('the base release', {'release': PINNED}, 'release'),
            ('another manifest', {'manifest_commit': '0' * 40}, 'manifest_commit'),
            ('another tag', {'manifest_tag': '0' * 40}, 'manifest_tag'),
            ('another manifest digest', {'manifest_sha256': '0' * 64}, 'manifest_sha256'),
            ('no signature', {'tag_signature_verified': 1}, 'tag_signature_verified'),
            ('a project fewer', {'verified_projects': 1056}, 'verified_projects'),
            ('a truncated ledger', {'projects': rows[:-1]}, 'projects'),
            ('the framework at the base', {'projects': [
                dict(row, revision='1' * 40, head='1' * 40) if row['path'] == FRAMEWORK else row
                for row in rows]}, 'project frameworks/base'),
            ('a failed framework', {'projects': [
                dict(row, verdict='FAIL') if row['path'] == FRAMEWORK else row for row in rows]},
             'project frameworks/base'))
        for number, (name, changes, field) in enumerate(cases):
            with self.subTest(case=name), self.assertRaisesRegex(
                    export.ExportError, 'does not pass for 2026100600: .*' + field):
                export.verified_source(verification(self.root / str(number), record, **changes),
                                       record)
        self.assertEqual(rows[0]['revision'], revision)
        with self.assertRaisesRegex(export.ExportError, 'missing or not a regular file'):
            export.verified_source(self.root / 'absent', record)


class SourceTreeTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.key, self.signers = ssh_key(self.directory)
        patcher = mock.patch.object(source, 'SIGNERS_SHA256', sha(self.signers.read_bytes()))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tree(self, name, release=SECOND):
        """A source tree: a signed manifest and two projects with a base and a target commit."""
        root = self.directory / name
        revisions = {project: commits(root / project, [{'file.txt': b'base\n'},
                                                       {'file.txt': b'target\n'}])
                     for project in (FRAMEWORK, SEPOLICY)}
        manifest = signed_manifest(root / '.repo/manifests', self.key, release)
        record = carry.load_json(ROOT / SECOND_RECORD)
        record['manifest'].update(manifest, allowed_signers_sha256=source.SIGNERS_SHA256)
        for project, (_, target) in revisions.items():
            record['patched_projects'][project]['revision'] = target
        return root, record, revisions

    def test_the_source_tree_is_authenticated_against_the_target_record(self):
        root, record, revisions = self.tree('tree')
        self.assertEqual(export.authenticate(root, record, self.signers), root)
        framework = root / FRAMEWORK
        manifests = root / '.repo/manifests'
        (self.directory / 'other').mkdir()
        other_key, _ = ssh_key(self.directory / 'other')

        def changed(path, data):
            def change():
                saved = path.read_bytes()
                path.write_bytes(data)
                return lambda: path.write_bytes(saved)
            return change

        def head(project, revision):
            def change():
                git(root / project, 'checkout', '--quiet', '--detach', revision)
                return lambda: git(root / project, 'checkout', '--quiet', '--detach',
                                   revisions[project][1])
            return change

        def retag(*options):
            def change():
                saved = text(manifests, 'rev-parse', 'refs/tags/' + SECOND)
                git(manifests, 'tag', '--delete', SECOND)
                git(manifests, *options, 'tag', '-m', SECOND, *(['-s'] if options else []),
                    SECOND)
                record['manifest']['tag_object'] = text(manifests, 'rev-parse',
                                                        'refs/tags/' + SECOND)

                def restore():
                    git(manifests, 'tag', '--delete', SECOND)
                    git(manifests, 'update-ref', 'refs/tags/' + SECOND, saved)
                    record['manifest']['tag_object'] = saved
                return restore
            return change

        def linked():
            moved = self.directory / 'moved-sepolicy'
            (root / SEPOLICY).rename(moved)
            (root / SEPOLICY).symlink_to(moved)

            def restore():
                (root / SEPOLICY).unlink()
                moved.rename(root / SEPOLICY)
            return restore
        cases = (
            ('other manifest bytes', changed(manifests / 'default.xml', b'<manifest></manifest>\n'),
             'not the signed manifest of 2026100600'),
            ('the framework at the base revision', head(FRAMEWORK, revisions[FRAMEWORK][0]),
             'frameworks/base of the source tree is not at the 2026100600 revision'),
            ('a tracked change', changed(framework / 'file.txt', b'changed\n'),
             'frameworks/base of the source tree is not verified: Tracked or staged changes'),
            ('an unsigned tag', retag(), 'the manifest tag 2026100600 does not verify'),
            ('a tag of another key', retag('-c', 'gpg.format=ssh', '-c',
                                           'user.signingKey=' + str(other_key)),
             'the manifest tag 2026100600 does not verify'),
            ('a linked project', linked, 'system/sepolicy is missing from'))
        before = {project: text(root / project, 'status', '--porcelain')
                  for project in (FRAMEWORK, SEPOLICY, '.repo/manifests')}
        for name, change, pattern in cases:
            with self.subTest(case=name):
                restore = change()
                try:
                    with self.assertRaisesRegex(export.ExportError, pattern):
                        export.authenticate(root, record, self.signers)
                finally:
                    restore()
        self.assertEqual(export.authenticate(root, record, self.signers), root)
        wrong = copy.deepcopy(record)
        wrong['manifest']['tag_object'] = '0' * 40
        with self.assertRaisesRegex(export.ExportError, 'refs/tags/2026100600 is not the record'):
            export.authenticate(root, wrong, self.signers)
        with self.assertRaisesRegex(carry.CarryError, 'allowed signers bytes differ'):
            export.authenticate(root, record, self.directory / 'key.pub')
        # Every check read the tree only.
        self.assertEqual({project: text(root / project, 'status', '--porcelain')
                          for project in (FRAMEWORK, SEPOLICY, '.repo/manifests')}, before)

    def test_the_temporary_directory_must_be_outside_the_whole_source_tree(self):
        # The guide refuses a temporary directory inside the source root, not only inside a
        # project or its Git directories. Git's tag check writes its temporary files there too.
        root, record, _ = self.tree('tree')
        inside, outside = root / 'tmp', self.directory / 'tmp'
        inside.mkdir()
        outside.mkdir()
        time.sleep(0.05)  # File times are coarse: a later write must show.

        def state():
            return {path.relative_to(root).as_posix(): (
                path.lstat().st_mode, path.lstat().st_size, path.lstat().st_ino,
                path.lstat().st_mtime_ns, path.lstat().st_ctime_ns,
                path.read_bytes() if path.is_file() and not path.is_symlink() else None)
                for path in [root, *root.rglob('*')]}
        before = state()
        for directory in (inside, outside):
            with self.subTest(directory=directory.relative_to(self.directory).as_posix()), \
                    mock.patch.object(tempfile, 'tempdir', None), \
                    mock.patch.dict(os.environ, {'TMPDIR': str(directory)}):
                if directory == inside:
                    with self.assertRaisesRegex(export.ExportError,
                                                'temporary directory must be outside source'):
                        export.authenticate(root, record, self.signers)
                else:
                    self.assertEqual(export.authenticate(root, record, self.signers), root)
                self.assertEqual(state(), before)
                self.assertEqual(list(outside.iterdir()), [])

    def test_objects_are_read_from_local_git_objects_only(self):
        project = self.directory / 'project'
        first, second = commits(project, [
            {'kept.txt': b'kept\n', 'changed.txt': b'base\n', 'dir/inner.txt': b'inner\n'},
            {'kept.txt': b'kept\n', 'changed.txt': b'target\n', 'dir/inner.txt': b'inner\n',
             'added.txt': b'added\n'}])
        (project / 'link').symlink_to('kept.txt')
        git(project, 'add', 'link')
        git(project, 'commit', '--quiet', '--message', 'a link')
        third = text(project, 'rev-parse', 'HEAD')
        found = export.blobs(project, first, ['kept.txt', 'changed.txt', 'added.txt',
                                              'dir/inner.txt'], 'the fixture')
        self.assertEqual(found['changed.txt'][1], b'base\n')
        self.assertEqual(found['dir/inner.txt'][1], b'inner\n')
        self.assertIsNone(found['added.txt'])
        self.assertEqual(found['kept.txt'][0], text(project, 'rev-parse', first + ':kept.txt'))
        self.assertEqual(export.blobs(project, second, ['added.txt'], 'x')['added.txt'][1],
                         b'added\n')
        for paths, revision, pattern in ((['dir'], second, 'dir at .* is not a regular file'),
                                         (['link'], third, 'link at .* is not a regular file'),
                                         (['kept.txt'], '0' * 40,
                                          'is not in the Git objects of the fixture')):
            with self.subTest(paths=paths), self.assertRaisesRegex(export.ExportError, pattern):
                export.blobs(project, revision, paths, 'the fixture')
        # A partial clone lacks the base blobs. They are refused as missing, and the promisor
        # remote that holds them is never asked.
        clone = self.directory / 'clone'
        git(self.directory, 'clone', '--quiet', '--filter=blob:none', '--no-checkout',
            'file://' + str(project), str(clone))
        blob = text(project, 'rev-parse', first + ':changed.txt')
        with self.assertRaisesRegex(export.ExportError, 'changed.txt at .* is missing from the '
                                                        'Git objects of the clone, and nothing'):
            export.blobs(clone, first, ['changed.txt'], 'the clone')
        process = subprocess.run(['git', '-C', str(clone), 'cat-file', '-e', blob],
                                 env=dict(source.git_environment()), capture_output=True,
                                 timeout=60)
        self.assertNotEqual(process.returncode, 0)


class CarryAndRecordTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.specs = carry.load_patch_set(PINNED)
        self.report = carry.load_json(ROOT / REPORT)
        self.target = carry.load_record(ROOT / SECOND_RECORD)

    def test_carried_rows_must_equal_the_sealed_report(self):
        rows = sealed_rows()
        export.compare(rows, self.report)

        def report_with(change):
            value = copy.deepcopy(self.report)
            change(value['patches'])
            return value

        def candidate_digest(patches):
            patches[1]['files'][1]['candidate_sha256'] = '0' * 64
        with self.assertRaisesRegex(export.ExportError, 'owner-lifecycle carries otherwise than '
                                    'the sealed report: files .*StorageManagerService.java'):
            export.compare(rows, report_with(candidate_digest))

        def overlap(patches):
            patches[0]['files'][4]['class'] = 'overlap'

        def failing(patches):
            patches[2]['checks'][0]['result'] = 'fail'

        def stale(patches):
            patches[5]['files'][0]['review_record'] = 'stale'
        for name, change, pattern in (
                ('an overlap', overlap, 'native-principal-pins is not carried, so it needs a new '
                                        'reviewed patch: overlap$'),
                ('a failing check', failing, 'package-verity is not carried, so it needs a new '
                                             'reviewed patch: check upstream method$'),
                ('a stale review', stale, 'policy disagreement: the review patch of '
                                          'owner-session-policy')):
            with self.subTest(case=name):
                value = report_with(change)
                same = copy.deepcopy(value['patches'])
                for row in same:
                    for entry in row['files']:
                        entry.pop('upstream_commits', None)
                with self.assertRaisesRegex(export.ExportError, pattern):
                    export.compare(same, value)

    def test_framework_profiles_change_only_the_revision_and_target_digests(self):
        rows = {row['name']: row for row in sealed_rows()}
        revision = self.target['patched_projects'][FRAMEWORK]['revision']
        for spec in self.specs:
            if spec['name'] not in export.FRAMEWORK:
                continue
            with self.subTest(patch=spec['name']):
                old = carry.load_json(spec['profile'])
                new = export.carried_profile(spec, rows[spec['name']], revision)
                self.assertEqual(list(new), list(old))
                self.assertEqual(new['head'], revision)
                restored = copy.deepcopy(new)
                restored['head'] = old['head']
                for entry in rows[spec['name']]['files']:
                    pair = export.digest_pair(new, entry['path'])
                    self.assertEqual((pair['upstream_sha256'], pair['candidate_sha256']),
                                     (entry['target_sha256'], entry['candidate_sha256']))
                    back = export.digest_pair(restored, entry['path'])
                    back['upstream_sha256'] = entry['base_sha256']
                    back['candidate_sha256'] = entry['pinned_candidate_sha256']
                # Nothing but the revision and the target digests changed.
                self.assertEqual(restored, old)
                wrong = copy.deepcopy(rows[spec['name']])
                wrong['files'][0]['base_sha256'] = '0' * 64
                with self.assertRaisesRegex(export.ExportError, 'disagrees with its report row'):
                    export.carried_profile(spec, wrong, revision)
        with self.assertRaisesRegex(export.ExportError, 'a shared source differs'):
            export.shared({'added': [{'source': 'owner/platform/framework/NativePrincipalPins.java',
                                      'sha256': '0' * 64}]})
        found = {row['path']: row['candidate_sha256'] for row in rows['native-principal-pins'][
            'files']}
        self.assertEqual(found[PREFIX + 'pm/InstallPackageHelper.java'],
                         'e83bfedf360bc115a69e524b06ebf127f53357db350c26400a5005b702426e0d')

    def test_the_host_tested_record_follows_the_tested_source(self):
        fileutils = synthetic_fileutils()
        upstream = synthetic_pis(host.BASE_FRAGMENT)
        combined = synthetic_pis(host.CANDIDATE_FRAGMENT)
        old = dict(carry.load_json(ROOT / PINNED_HOST), fileutils_sha256=sha(fileutils))

        def run(old=old, upstream=upstream, combined=combined, target_fileutils=fileutils):
            files = {('base', FRAMEWORK): {host.FILEUTILS: ('b', fileutils)},
                     ('target', FRAMEWORK): {PIS: ('t', upstream),
                                             host.FILEUTILS: ('f', target_fileutils)}}
            outputs = {'package-verity': (None, {PIS: b'verity\n'}),
                       export.PAYLOAD: (None, {PIS: combined})}
            return export.host_record(old, files, outputs, '1' * 40,
                                      SECOND_PATCHES + '/package-verity.json', '2' * 64)
        value = run()
        self.assertEqual(list(value), list(old))
        changed = {key for key in old if value[key] != old[key]}
        self.assertEqual(changed, {'head', 'base_profile', 'base_profile_sha256',
                                   'upstream_sha256', 'base_sha256', 'candidate_sha256'})
        self.assertEqual((value['head'], value['base_profile'], value['base_profile_sha256'],
                          value['upstream_sha256'], value['base_sha256'],
                          value['candidate_sha256'], value['fileutils_sha256']),
                         ('1' * 40, SECOND_PATCHES + '/package-verity.json', '2' * 64,
                          sha(upstream), sha(b'verity\n'), sha(combined), sha(fileutils)))
        start = host.SYNC_REGIONS[0][0]
        cases = (
            ('the FileUtils sync range', dict(target_fileutils=fileutils.replace(
                b'fsync', b'fdatasync', 1)), 'core/java/android/os/FileUtils.java'),
            ('a second FileUtils sync range', dict(target_fileutils=fileutils + start.encode()),
             'core/java/android/os/FileUtils.java'),
            ('the upstream Package Installer range', dict(upstream=upstream.replace(
                b'ParcelFileDescriptor fd) {', b'ParcelFileDescriptor pfd) {', 1)),
             'upstream ' + PIS),
            ('the combined Package Installer range', dict(combined=combined[:-40]),
             'combined ' + PIS),
            ('another base FileUtils', dict(old=dict(old, fileutils_sha256='0' * 64)),
             'the base core/java/android/os/FileUtils.java'),
            ('an integrated record', dict(old=dict(old, integrated=True)), 'record form'),
            ('another host patch', dict(old=dict(old, patch_sha256='0' * 64)), 'patch_sha256'))
        for name, changes, pattern in cases:
            with self.subTest(case=name), self.assertRaisesRegex(
                    export.ExportError, 'host drift: the tested source no longer holds in .*'
                    + pattern):
                run(**changes)

    def test_the_policy_record_needs_the_pinned_upstream_and_an_agreeing_review(self):
        domain = ('# header\n' + policy.PREFIX + 'x\n' + policy.ORIGINAL_EXEC_PREFIX + '}\n'
                  + policy.ORIGINAL_DATA_PREFIX + '}\n' + ''.join(
                      'allow ' + policy.CGROUP_SUBJECT + ' cgroup%d;\n' % number
                      for number in range(4))).encode()
        upstream = {policy.FILES[0]: domain, **{
            path: (policy.FIND[path.removeprefix('private/').removesuffix('.te')] +
                   '}:service_manager find;\n').encode() for path in policy.FILES[1:]}}
        bridge, _ = carry.policy_bridge(upstream)
        review = self.directory / 'owner-session-policy.patch'

        def write_review(after):
            review.write_text(''.join(''.join(difflib.unified_diff(
                upstream[path].decode().splitlines(True), after[path].decode().splitlines(True),
                'a/' + path, 'b/' + path, n=0)) for path in policy.FILES))
        write_review(bridge)
        record = self.directory / 'owner-session-policy.json'
        old = carry.load_json(ROOT / PINNED_PATCHES / 'owner-session-policy.json')
        old['files'] = [dict(path=path, upstream_sha256=sha(upstream[path]),
                             candidate_sha256=sha(bridge[path])) for path in policy.FILES]
        record.write_text(json.dumps(dict(old, patch_sha256=sha(review.read_bytes())), indent=2)
                          + '\n')
        spec = {'name': export.POLICY, 'patch': review, 'profile': record}
        files = {('target', SEPOLICY): {path: ('b', upstream[path]) for path in policy.FILES}}
        outputs = {export.POLICY: (None, bridge)}

        def run():
            return export.policy_record(spec, files, outputs, SECOND, '3' * 40, self.directory)
        with mock.patch.object(policy, 'BEFORE', {path: sha(data) for path, data in upstream.items()}):
            value = run()
            self.assertEqual(list(value), list(old))
            self.assertEqual({key for key in old if value[key] != old[key]},
                             {'base_release', 'head', 'patch_sha256'})
            self.assertEqual((value['base_release'], value['head'], value['files'], value['patch']),
                             (SECOND, '3' * 40, [dict(path=path, upstream_sha256=sha(upstream[path]),
                                                      candidate_sha256=sha(bridge[path]))
                                                  for path in policy.FILES], review.name))
            other = dict(old, files=[dict(row) for row in old['files']],
                         patch_sha256=sha(review.read_bytes()))
            other['files'][1]['candidate_sha256'] = '0' * 64
            record.write_text(json.dumps(other, indent=2) + '\n')
            with self.assertRaisesRegex(export.ExportError, 'record names other bridge bytes'):
                run()
            record.write_text(json.dumps(dict(old, patch_sha256=sha(review.read_bytes())),
                                         indent=2) + '\n')
            write_review(dict(bridge, **{policy.FILES[0]: bridge[policy.FILES[0]].replace(
                b'cgroup0', b'cgroupX')}))
            record.write_text(json.dumps(dict(old, patch_sha256=sha(review.read_bytes())),
                                         indent=2) + '\n')
            with self.assertRaisesRegex(export.ExportError, 'policy disagreement: the review '
                                                            'patch does not reproduce the bridge'):
                run()
            write_review(bridge)
            record.write_text(json.dumps(dict(old, patch_sha256=sha(review.read_bytes()),
                                              public_policy_api_changed=True), indent=2) + '\n')
            with self.assertRaisesRegex(export.ExportError, 'no longer names its review patch'):
                run()
        with self.assertRaisesRegex(export.ExportError, 'policy disagreement: one of the four files '
                                                        'at 2026100600 is not the upstream'):
            run()

    def test_the_readme_states_provenance_scope_and_limits(self):
        data = export.readme(self.specs, sealed_rows(), self.report, self.target, SECOND_HOST)
        readme = data.decode()
        lines = readme.splitlines()
        self.assertEqual(lines[0], '# GrapheneOS 2026100600 candidate patches')
        self.assertTrue(readme.isascii())
        self.assertEqual([line for line in lines if len(line) > 100], [])
        for phrase in ('`upstream/selected-base.json` still selects 2026081300',
                       '- report: `%s`, verdict `CARRIED`' % REPORT,
                       '- seal: `%s`' % self.report['seal']['sha256'],
                       '- `frameworks/base`: `84183aff99be5e156dc0446a6fa2d4a7150f4bc3`',
                       '- `system/sepolicy`: `5e359dcf9ae863a593e9055a85e1657c87c4cb18`',
                       'Every patch here is the 2026081300 patch byte for byte',
                       'Of the 15 upstream files the patches change, 12 are identical',
                       '`%s`.' % SECOND_HOST, 'checked lab test source only',
                       'A normal image does not\napply it', 'Source only.'):
            self.assertIn(phrase, readme)
        for path, kind in CHANGED.items():
            self.assertIn('- `%s`: %s' % (path, 'moved, at line offsets' if kind == 'moved'
                                           else kind), lines)
        self.assertNotIn('targets 2026081300', readme)


class OwnershipPartsTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        patcher = mock.patch.object(export, 'ROOT', self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def new_files(self):
        """A NewFiles whose held objects are released after the test."""
        new = export.NewFiles()
        self.addCleanup(new.close)
        return new

    def created(self, directory, data=b'owned payload\n'):
        new = self.new_files()
        new.directory(directory)
        new.write(directory + '/a.patch', data)
        return new

    def test_the_rollback_removes_only_what_it_created_and_still_finds_there(self):
        # The honest twin: everything this export created is removed.
        self.assertEqual(self.created('honest').remove(), (['honest/a.patch', 'honest'], {}))
        self.assertFalse((self.root / 'honest').exists())
        another, holds = ('another object than the one this export created',
                          'it holds entries this export did not create')
        # A created file replaced by another with the same, fewer or no bytes is kept.
        for name, replacement in (('equal', b'owned payload\n'), ('prefix', b'owned'),
                                  ('empty', b'')):
            with self.subTest(replacement=name):
                new = self.created(name)
                path = self.root / name / 'a.patch'
                path.rename(self.root / (name + '.original'))
                path.write_bytes(replacement)
                self.assertEqual(new.remove(), ([], {name + '/a.patch': another, name: holds}))
                self.assertEqual(path.read_bytes(), replacement)
                self.assertEqual((self.root / (name + '.original')).read_bytes(),
                                 b'owned payload\n')
        # A created directory replaced by another empty directory is kept.
        new = self.new_files()
        new.directory('directory')
        (self.root / 'directory').rename(self.root / 'directory.original')
        (self.root / 'directory').mkdir()
        self.assertEqual(new.remove(), ([], {'directory': another}))
        self.assertTrue((self.root / 'directory').is_dir())
        self.assertTrue((self.root / 'directory.original').is_dir())
        # A created directory replaced by a link to a directory holding a file with the very same
        # name and bytes: nothing is followed, and both are kept.
        selected = self.root / 'selected'
        selected.mkdir()
        (selected / 'a.patch').write_bytes(b'owned payload\n')
        new = self.created('linked')
        (self.root / 'linked').rename(self.root / 'linked.original')
        (self.root / 'linked').symlink_to(selected, target_is_directory=True)
        removed, left = new.remove()
        self.assertEqual((removed, sorted(left)), ([], ['linked', 'linked/a.patch']))
        self.assertTrue(left['linked/a.patch'].startswith('not reached: linked: '), left)
        self.assertEqual(left['linked'], another)
        self.assertEqual((selected / 'a.patch').read_bytes(), b'owned payload\n')
        self.assertEqual((self.root / 'linked.original/a.patch').read_bytes(),
                         b'owned payload\n')

    def test_new_paths_are_never_created_through_a_link_or_a_replaced_directory(self):
        selected = self.root / 'selected'
        selected.mkdir()
        (self.root / 'patches').symlink_to(selected, target_is_directory=True)
        with self.assertRaisesRegex(export.Moved, 'patches: '):
            self.new_files().directory('patches/grapheneos-x')
        self.assertEqual(list(selected.iterdir()), [])
        (self.root / 'patches').unlink()
        (self.root / 'patches').mkdir()
        new = self.new_files()
        new.directory('patches/grapheneos-x')
        (self.root / 'patches/grapheneos-x').rename(self.root / 'aside')
        (self.root / 'patches/grapheneos-x').mkdir()
        with self.assertRaisesRegex(export.Moved, 'patches/grapheneos-x is another directory'):
            new.write('patches/grapheneos-x/a.patch', b'a\n')
        self.assertEqual(list((self.root / 'patches/grapheneos-x').iterdir()), [])
        self.assertEqual(list((self.root / 'aside').iterdir()), [])

    def test_an_object_removed_and_made_again_is_never_taken_for_the_created_one(self):
        # The honest twin: a created file and directory, unchanged, are removed.
        self.assertEqual(self.created('honest').remove(), (['honest/a.patch', 'honest'], {}))
        another, holds = ('another object than the one this export created',
                          'it holds entries this export did not create')
        # A created file removed, then made again with its very bytes, as often as a filesystem
        # might take to hand out its freed inode again. The created file is held open, so its
        # inode is never free: the new file is another object, which the inventory finds foreign
        # and the rollback keeps.
        new = self.created('file')
        path = self.root / 'file/a.patch'
        created = export.identity(path.stat())
        for attempt in range(512):
            path.unlink()
            path.write_bytes(b'owned payload\n')
            self.assertNotEqual(export.identity(path.stat()), created, attempt)
        found, *problems = export.candidate_inventory([('file/a.patch', b'owned payload\n')],
                                                      ['file'], new)
        self.assertEqual(problems, [[], [], [], ['file/a.patch']])
        self.assertEqual(new.remove(), ([], {'file/a.patch': another, 'file': holds}))
        self.assertEqual(path.read_bytes(), b'owned payload\n')
        # A created directory removed and made again, the same way.
        new = self.new_files()
        new.directory('directory')
        path = self.root / 'directory'
        created = export.identity(path.stat())
        for attempt in range(512):
            path.rmdir()
            path.mkdir()
            self.assertNotEqual(export.identity(path.stat()), created, attempt)
        self.assertEqual(new.remove(), ([], {'directory': another}))
        self.assertTrue(path.is_dir())


class WritingTests(unittest.TestCase):

    def test_new_files_are_created_only_where_nothing_existed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            (root / 'patches').mkdir()
            # An existing directory that sorts after the new one: the new one is made first.
            (root / 'tests' / 'grapheneos-x').mkdir(parents=True)
            kept = root / 'tests' / 'grapheneos-x' / 'kept.json'
            kept.write_text('kept\n')
            staged = [('patches/grapheneos-x/a.patch', b'a\n'),
                      ('patches/grapheneos-x/a.json', b'{}\n'),
                      ('tests/grapheneos-x/kept.json', b'new\n')]
            patcher = mock.patch.object(export, 'ROOT', root)
            patcher.start()
            self.addCleanup(patcher.stop)
            new = export.NewFiles()
            self.addCleanup(new.close)
            with self.assertRaises(FileExistsError):
                export.write_candidate(staged, new)
            self.assertEqual(new.remove(), (['patches/grapheneos-x'], {}))
            self.assertFalse((root / 'patches' / 'grapheneos-x').exists())
            self.assertEqual(kept.read_text(), 'kept\n')
            new = export.NewFiles()
            self.addCleanup(new.close)
            export.write_candidate(staged[:2], new)
            self.assertEqual((root / 'patches/grapheneos-x/a.json').read_bytes(), b'{}\n')
            self.assertEqual((root / 'patches/grapheneos-x/a.patch').stat().st_mode & 0o777,
                             0o644)
            link = root / 'patches/grapheneos-x/link.json'
            link.symlink_to(kept)
            with self.assertRaises(FileExistsError):
                new.write('patches/grapheneos-x/link.json', b'x\n')
            self.assertEqual(kept.read_text(), 'kept\n')
            link.unlink()
            # The rollback removes its own file holding part of its bytes, as an interrupted write
            # leaves it. It keeps its own file someone else rewrote in place and an entry someone
            # else added, and so the directory too.
            (root / 'patches/grapheneos-x/a.patch').write_bytes(b'')
            (root / 'patches/grapheneos-x/a.json').write_bytes(b'{"foreign": true}\n')
            (root / 'patches/grapheneos-x/extra.txt').write_text('extra\n')
            self.assertEqual(new.remove(), (['patches/grapheneos-x/a.patch'], {
                'patches/grapheneos-x/a.json': 'changed since this export wrote it',
                'patches/grapheneos-x': 'it holds entries this export did not create'}))
            self.assertEqual(sorted(path.relative_to(root).as_posix() for path in root.rglob('*')),
                             ['patches', 'patches/grapheneos-x', 'patches/grapheneos-x/a.json',
                              'patches/grapheneos-x/extra.txt', 'tests', 'tests/grapheneos-x',
                              'tests/grapheneos-x/kept.json'])

    def test_the_scratch_must_be_new_and_outside_both_trees(self):
        before = snapshot(ROOT)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name).resolve()
            tree = directory / 'tree'
            tree.mkdir()
            busy = directory / 'busy'
            busy.mkdir()
            (busy / 'kept').write_text('x')
            for scratch, pattern in ((ROOT / 'export-scratch', "outside the repository's"),
                                     (tree / 'scratch', 'outside the source tree'),
                                     (busy, 'new or empty')):
                with self.subTest(scratch=scratch), self.assertRaisesRegex(
                        candidate.CandidateError, pattern):
                    export.export(ROOT / REPORT, tree, directory, directory / 'signers', scratch)
            with self.assertRaisesRegex(export.ExportError, 'outside the base source tree'):
                export.export(ROOT / REPORT, tree, directory, directory / 'signers',
                              directory / 'scratch', base_source_root=directory)
            self.assertEqual(sorted(path.name for path in busy.iterdir()), ['kept'])
        self.assertFalse((ROOT / 'export-scratch').exists())
        self.assertEqual(snapshot(ROOT), before)

    def test_validate_needs_every_upstream_input(self):
        with tempfile.TemporaryDirectory() as name:
            report, status = export.validate_report(Path(name))
        self.assertEqual((status, report['base'], report['status']), (1, PINNED, 'FAIL'))
        self.assertIn('upstream input frameworks/base/', report['validate'][0])


def oserror(number):
    """An OSError as a system call raises it."""
    return OSError(number, os.strerror(number))


class Faults:
    """The failures of one case of publishing the final record and putting its failure record
    back, injected into the exporter's os module, its directory sync and Path.read_bytes. A call
    either fails before it does anything or, as POSIX allows for EIO, takes effect and then
    reports an error. Once the first fault happened, later faults of a persistent case follow
    it."""
    # The cases whose renames over export.json all fail once the first fault happened.
    STUCK = ('directory sync, no rename after', 'directory sync, neither rename nor unlink after',
             'second name gone, no rename after', 'second name replaced, no rename after',
             'final rename takes effect, then EIO, no rename after',
             'final rename takes effect, then ENOENT, no rename after')
    # The cases whose first fault is the directory sync just after the final record's rename.
    SYNC = ('directory sync once', 'directory sync, no rename after',
            'directory sync, neither rename nor unlink after', 'second name gone',
            'second name gone, no rename after', 'second name replaced, no rename after',
            'directory sync twice', 'rename back takes effect, then EIO',
            'withdrawal takes effect, then EIO')

    def __init__(self, case, directory):
        self.case, self.directory, self.failed = case, directory, False
        self.module = types.ModuleType('os')
        self.module.__dict__.update(os.__dict__)
        self.module.fsync, self.module.replace = self.fsync, self.replace
        self.module.unlink, self.module.link = self.unlink, self.link

    def published(self):
        path = self.directory / export.RECORD
        with open(path, 'rb') as handle:
            return b'EXPORTED' in handle.read()

    def fsync(self, descriptor):
        path = os.readlink('/proc/self/fd/%d' % descriptor)
        if self.case == 'final fsync' and '/.export-' in path and not self.failed:
            with open(path, 'rb') as handle:
                if b'EXPORTED' in handle.read():
                    self.failed = True
                    raise oserror(errno.ENOSPC)
        return os.fsync(descriptor)

    def link(self, source, destination, *args, **kwargs):
        os.link(source, destination, *args, **kwargs)
        if self.case == 'second name links, then EIO' and not self.failed:
            self.failed = True
            raise oserror(errno.EIO)

    def replace(self, source, destination):
        if Path(destination).name == export.RECORD:
            back = Path(source).name == export.FALLBACK
            if not back and not self.failed and b'EXPORTED' in Path(source).read_bytes():
                if self.case == 'final rename':
                    self.failed = True
                    raise oserror(errno.ENOSPC)
                if self.case.startswith('final rename takes effect'):
                    os.replace(source, destination)
                    self.failed = True
                    raise oserror(errno.ENOENT if 'ENOENT' in self.case else errno.EIO)
            if back and self.failed and self.case == 'rename back takes effect, then EIO':
                os.replace(source, destination)
                raise oserror(errno.EIO)
            if back and self.failed and self.case == 'withdrawal takes effect, then EIO':
                raise oserror(errno.EIO)
            if self.case in self.STUCK and self.failed:
                raise oserror(errno.ENOSPC)
        return os.replace(source, destination)

    def unlink(self, path, *args, **kwargs):
        if self.failed and Path(path).name == export.RECORD:
            if self.case == 'directory sync, neither rename nor unlink after':
                raise oserror(errno.EIO)
            if self.case == 'withdrawal takes effect, then EIO':
                os.unlink(path, *args, **kwargs)
                raise oserror(errno.EIO)
        return os.unlink(path, *args, **kwargs)

    def sync(self, path):
        if self.case == 'directory sync twice' and self.failed:
            raise oserror(errno.ENOSPC)
        if self.case in self.SYNC and not self.failed and self.published():
            self.failed = True
            fallback = self.directory / export.FALLBACK
            if self.case.startswith('second name'):
                # Another process removed the failure record's second name, or put another file
                # in its place.
                os.unlink(fallback)
            if self.case.startswith('second name replaced'):
                fallback.write_text('{"status": "EXPORTED", "phase": "done"}\n')
            raise oserror(errno.ENOSPC)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def read(self, path):
        with open(path, 'rb') as handle:
            data = handle.read()
        if (self.case == 'readback once' and not self.failed and path.name == export.RECORD
                and b'EXPORTED' in data):
            self.failed = True
            raise oserror(errno.EIO)
        return data


def failing_fsync(prefix):
    """An os module whose fsync fails as a full filesystem does, for files whose path starts with
    prefix."""
    module = types.ModuleType('os')
    module.__dict__.update(os.__dict__)

    def fsync(descriptor):
        if os.readlink('/proc/self/fd/%d' % descriptor).startswith(prefix):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return os.fsync(descriptor)
    module.fsync = fsync
    return module


class FinishingPartsTests(unittest.TestCase):

    def setUp(self):
        # A termination signal that escaped the code under test is counted, not fatal.
        self.escaped = []
        for number in export.TERMINATION:
            previous = signal.signal(number, lambda number, frame: self.escaped.append(number))
            self.addCleanup(signal.signal, number, previous)

    def test_a_record_is_replaced_whole_or_not_at_all(self):
        with tempfile.TemporaryDirectory() as name:
            evidence = export.Evidence(Path(name).resolve())
            record = evidence.directory / export.RECORD
            first = evidence.save({'status': 'FAIL', 'phase': 'checks'})
            self.assertEqual(record.read_bytes(), first)
            full = failing_fsync(str(evidence.directory / '.export-'))
            with mock.patch.object(export, 'os', full), self.assertRaises(OSError) as caught:
                evidence.save({'status': 'FAIL', 'phase': 'writing'})
            self.assertEqual(caught.exception.errno, errno.ENOSPC)
            # The previous record stays whole, and no temporary file is left beside it.
            self.assertEqual(record.read_bytes(), first)
            self.assertEqual([path.name for path in evidence.directory.iterdir()], [export.RECORD])
            self.assertEqual(evidence.describe(), '%s says FAIL in the checks phase' % record)

    def test_some_record_is_on_disk_whatever_fails_while_the_final_record_is_published(self):
        writing, final = {'status': 'FAIL', 'phase': 'writing'}, {'status': 'EXPORTED',
                                                                   'phase': 'done'}
        # (case, the failure of publish, whether its publication began, whether the failure record
        # is then durably back so that the rollback may run, the files on disk once the failure
        # path has run, and what the first of them says)
        record, fallback = export.RECORD, export.FALLBACK
        cases = (('none', None, True, None, [record], 'EXPORTED'),
                 ('final fsync', errno.ENOSPC, False, None, [record], 'FAIL'),
                 # The final rename failing before or after it took effect, or the second name's
                 # link after it took effect: the disk decides, not the error.
                 ('final rename', errno.ENOSPC, True, True, [record, fallback], 'FAIL'),
                 ('final rename takes effect, then EIO', errno.EIO, True, True, [record],
                  'FAIL'),
                 ('final rename takes effect, then EIO, no rename after', errno.EIO, True, True,
                  [fallback], 'FAIL'),
                 ('final rename takes effect, then ENOENT, no rename after', errno.ENOENT, True,
                  True, [fallback], 'FAIL'),
                 ('second name links, then EIO', errno.EIO, True, True, [record, fallback],
                  'FAIL'),
                 ('directory sync once', errno.ENOSPC, True, True, [record], 'FAIL'),
                 ('readback once', errno.EIO, True, True, [record], 'FAIL'),
                 ('directory sync, no rename after', errno.ENOSPC, True, True, [fallback],
                  'FAIL'),
                 ('directory sync, neither rename nor unlink after', errno.ENOSPC, True, False,
                  [record, fallback], 'EXPORTED'),
                 # A step putting the failure record back takes effect, then reports an error.
                 ('rename back takes effect, then EIO', errno.ENOSPC, True, True, [record],
                  'FAIL'),
                 ('withdrawal takes effect, then EIO', errno.ENOSPC, True, True, [fallback],
                  'FAIL'),
                 # Unless the second name still holds the very failure record, nothing is
                 # renamed or withdrawn, whatever else fails: the final record stays true.
                 ('second name gone', errno.ENOSPC, True, False, [record], 'EXPORTED'),
                 ('second name gone, no rename after', errno.ENOSPC, True, False, [record],
                  'EXPORTED'),
                 ('second name replaced, no rename after', errno.ENOSPC, True, False,
                  [record, fallback], 'EXPORTED'),
                 # The failure record renamed back, but its directory not synced: no rollback.
                 ('directory sync twice', errno.ENOSPC, True, False, [record], 'FAIL'))
        for case, failure, published, undone, files, status in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as name:
                evidence = export.Evidence(Path(name).resolve())
                self.addCleanup(evidence.close)
                evidence.save(writing)
                faults = Faults(case, evidence.directory)
                with mock.patch.object(export, 'os', faults.module), \
                        mock.patch.object(export, 'sync_directory', faults.sync), \
                        mock.patch.object(Path, 'read_bytes', lambda path: faults.read(path)):
                    try:
                        evidence.publish(final)
                        raised = None
                    except OSError as error:
                        raised = error.errno
                    self.assertEqual((raised, evidence.published), (failure, published))
                    if raised is None:
                        self.assertIsNone(evidence.forget())
                    elif evidence.published:
                        self.assertEqual(evidence.restore(), undone)
                found = sorted(path.name for path in evidence.directory.iterdir())
                self.assertEqual(found, sorted(files))
                self.assertEqual(json.loads((evidence.directory / files[0]).read_text())['status'],
                                 status)
                described = evidence.describe()
                if files == [export.FALLBACK]:
                    self.assertEqual(described, '%s is absent; %s says FAIL in the writing phase'
                                     % (evidence.directory / export.RECORD,
                                        evidence.directory / export.FALLBACK))
                else:
                    self.assertTrue(described.startswith('%s says %s' % (
                        evidence.directory / export.RECORD, status)), described)

    def test_the_inventory_counts_every_entry_of_the_new_directories(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            (root / 'hosts').mkdir()
            staged = [('new/a.json', b'{}\n'), ('new/b.patch', b'b\n'),
                      ('hosts/new/c.json', b'c\n')]
            directories = ['new', 'hosts/new']
            patcher = mock.patch.object(export, 'ROOT', root)
            patcher.start()
            self.addCleanup(patcher.stop)
            new = export.NewFiles()
            self.addCleanup(new.close)
            export.write_candidate(staged, new)
            found, *problems = export.candidate_inventory(staged, directories, new)
            self.assertEqual((sorted(found), problems),
                             (sorted(path for path, _ in staged), [[], [], [], []]))
            # Entries Git ignores count as much as any other, and a file with the right bytes
            # that this export did not create is foreign.
            (root / 'new/__pycache__').mkdir()
            (root / 'new/__pycache__/stray.pyc').write_bytes(b'x')
            (root / 'new/link.json').symlink_to('a.json')
            os.mkfifo(root / 'new/pipe')
            (root / 'new/b.patch').write_bytes(b'other\n')
            (root / 'new/a.json').rename(root / 'a.json.original')
            (root / 'new/a.json').write_bytes(b'{}\n')
            (root / 'hosts/new/c.json').unlink()
            found, unexpected, missing, differing, foreign = export.candidate_inventory(
                staged, directories, new)
            self.assertEqual(unexpected, ['new/__pycache__', 'new/__pycache__/stray.pyc',
                                          'new/link.json', 'new/pipe'])
            self.assertEqual((missing, differing, foreign),
                             (['hosts/new/c.json'], ['new/b.patch'], ['new/a.json']))
            self.assertEqual((found['new/link.json'], found['new/__pycache__'], found['new/pipe']),
                             ('link to a.json', 'directory', 'other'))
            # A new directory replaced by a link is not followed.
            (root / 'hosts/new').rmdir()
            (root / 'hosts/new').symlink_to(root / 'new', target_is_directory=True)
            found, unexpected, *_ = export.candidate_inventory(staged, directories, new)
            self.assertTrue(found['hosts/new'].startswith('not reached: hosts/new'))
            self.assertIn('hosts/new', unexpected)
            self.assertNotIn('hosts/new/a.json', found)

    def test_termination_signals_wait_until_the_export_lets_them_through(self):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        with export.terminable():
            os.kill(os.getpid(), signal.SIGHUP)
            # Blocked: the signal waits, and nothing is raised here.
            self.assertIn(signal.SIGHUP, signal.sigpending())
            with self.assertRaises(export.Terminated) as caught:
                with export.interruptible():
                    time.sleep(1)
            self.assertEqual((caught.exception.number, str(caught.exception)),
                             (signal.SIGHUP, 'terminated by SIGHUP'))
            os.kill(os.getpid(), signal.SIGTERM)
        # A signal still pending at the end is discarded, and the handlers and mask return.
        self.assertEqual(signal.sigpending() & set(export.TERMINATION), set())
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        self.assertEqual(self.escaped, [])
        os.kill(os.getpid(), signal.SIGTERM)
        self.assertEqual(self.escaped, [signal.SIGTERM])

    def test_the_handler_blocks_further_signals_before_it_raises(self):
        mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, export.TERMINATION)
        self.addCleanup(signal.pthread_sigmask, signal.SIG_SETMASK, mask)
        with self.assertRaises(export.Terminated):
            export.terminate(signal.SIGTERM, None)
        self.assertLessEqual(set(export.TERMINATION),
                             signal.pthread_sigmask(signal.SIG_BLOCK, ()))

    def test_a_signal_ignored_on_entry_stays_ignored(self):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        with export.terminable():
            self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
            self.assertIs(signal.getsignal(signal.SIGTERM), export.terminate)
            os.kill(os.getpid(), signal.SIGHUP)
            with export.interruptible():
                pass
        self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)


class MainTests(unittest.TestCase):

    def test_every_failure_ends_stderr_with_its_evidence_line(self):
        line = 'evidence: /scratch/evidence/export.json says FAIL in the writing phase'
        arguments = ['export', '--report', 'report.json', '--source-root', 'tree',
                     '--source-evidence', 'verification', '--allowed-signers', 'signers',
                     '--scratch', 'scratch']
        moved = 'patches is another directory than the one this export found or created'
        # A refusal of a parent replaced while writing, an unexpected error and a termination
        # signal: each ends with its failure and then exactly which record is on disk.
        for error, code, failure in (
                (export.Moved(moved), 1, 'FAIL: ' + moved),
                (RuntimeError('an unexpected error'), 1,
                 'FAIL: RuntimeError: an unexpected error'),
                (export.Terminated(signal.SIGTERM), 128 + signal.SIGTERM,
                 'FAIL: terminated by SIGTERM.')):
            error.evidence = line[len('evidence: '):]
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(export, 'export', side_effect=error), \
                    mock.patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(export.main(arguments), code)
            self.assertEqual(stderr.getvalue().splitlines()[-2:], [failure, line])
            # Only an unexpected error shows its traceback, before those lines.
            self.assertEqual('Traceback' in stderr.getvalue(), code == 1 and
                             isinstance(error, RuntimeError))


@unittest.skipUnless(PINNED in FILES and SECOND in FILES, NEEDS_FILES)
class FixtureCase(unittest.TestCase):
    """A fixture repository standing in for this one, with a source tree of the candidate whose
    two projects hold a base and a target commit of the public upstream files, a signed manifest
    and the candidate's source verification. The repository's base records, selection, profiles,
    host tested record and sealed report name the fixture's commits, manifest and allowed signers;
    the files the carry reads keep their public bytes and the sealed report its patch rows."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = directory = Path(cls.tmp.name).resolve()
        cls.key, cls.signers = ssh_key(directory)
        cls.fileutils = {}
        upstream = {release: cls.upstream(release) for release in (PINNED, SECOND)}
        cls.tree = directory / 'source'
        cls.revisions = {project: commits(cls.tree / project, [upstream[PINNED][project],
                                                                upstream[SECOND][project]])
                         for project in (FRAMEWORK, SEPOLICY)}
        # The added helper's directory, which the patch tools' containment checks resolve.
        (cls.tree / FRAMEWORK / 'services/core/java/com/android/server/storage').mkdir()
        cls.manifest = signed_manifest(cls.tree / '.repo/manifests', cls.key, SECOND)
        cls.root = cls.repository(directory / 'repository')
        cls.main = text(cls.root, 'rev-parse', 'HEAD')
        cls.record = carry.load_json(cls.root / SECOND_RECORD)
        cls.evidence = verification(directory / 'source-evidence', cls.record)
        cls.inputs = {}
        for release in (PINNED, SECOND):
            for project, files in upstream[release].items():
                for path, data in files.items():
                    target = directory / 'inputs' / release / project / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            cls.inputs[release] = directory / 'inputs' / release

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def upstream(cls, release):
        """The public files a fixture project holds at a release: every patch target and
        FileUtils.java."""
        root = Path(FILES[release])
        found = {FRAMEWORK: {}, SEPOLICY: {}}
        for spec in carry.load_patch_set(PINNED):
            for row in spec['files']:
                found[spec['project']][row['path']] = (
                    root / spec['project'] / row['path']).read_bytes()
        copied = root / FRAMEWORK / host.FILEUTILS
        found[FRAMEWORK][host.FILEUTILS] = cls.fileutils[release] = (
            copied.read_bytes() if copied.is_file() else synthetic_fileutils())
        return found

    @classmethod
    def repository(cls, root):
        """The fixture repository: this repository's files, with the records naming the fixture."""
        listing = git(ROOT, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
        for name in os.fsdecode(listing).split('\0'):
            if name and (ROOT / name).is_file() and not (ROOT / name).is_symlink():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, root / name)
        for path in (root / SECOND_PATCHES, root / SECOND_HOSTS):
            shutil.rmtree(path, ignore_errors=True)
        digest = sha(cls.signers.read_bytes())
        verifier = root / 'scripts/proof/grapheneos_source.py'
        verifier.write_text(verifier.read_text().replace(source.SIGNERS_SHA256, digest, 1))
        records = {}
        for release, side in ((PINNED, 0), (SECOND, 1)):
            path = root / ('upstream/bases/%s.json' % release)
            value = carry.load_json(path)
            value['manifest']['allowed_signers_sha256'] = digest
            for project, revisions in cls.revisions.items():
                value['patched_projects'][project]['revision'] = revisions[side]
            if release == SECOND:
                value['manifest'].update(cls.manifest, signer=PRINCIPAL)
            path.write_bytes(carry.dump(value))
            records[release] = path
        rewrite(root / base.SELECTION, record_sha256=sha(records[PINNED].read_bytes()))
        old = root / PINNED_PATCHES
        for profile in sorted(old.glob('*.json')):
            project = json.loads(profile.read_text())['project']
            rewrite(profile, head=cls.revisions[project][0])
        verity = sha((old / 'package-verity.json').read_bytes())
        rewrite(root / PINNED_HOST, head=cls.revisions[FRAMEWORK][0], base_profile_sha256=verity,
                fileutils_sha256=sha(cls.fileutils[PINNED]))
        rewrite(old / 'package-installer-payload-sync.json', requires_sha256=verity,
                host_profile_sha256=sha((root / PINNED_HOST).read_bytes()))
        report = carry.load_json(root / REPORT)
        report['base']['record_sha256'] = sha(records[PINNED].read_bytes())
        report['target'].update(record_sha256=sha(records[SECOND].read_bytes()),
                                tag_object=cls.manifest['tag_object'],
                                manifest_commit=cls.manifest['commit'],
                                manifest_sha256=cls.manifest['sha256'])
        for row in report['patches']:
            row['profile_sha256'] = sha((root / row['profile']).read_bytes())
        for row in report['surface']:
            if row['path'] == host.FILEUTILS:
                row['base_object'], row['target_object'] = (
                    text(cls.tree / FRAMEWORK, 'rev-parse', '%s:%s' % (revision, host.FILEUTILS))
                    for revision in cls.revisions[FRAMEWORK])
        report['seal'] = carry.seal(report)
        (root / REPORT).write_bytes(carry.dump(report))
        git(root, 'init', '--quiet')
        git(root, 'add', '--all')
        # Files this repository tracks although its ignore rules match them.
        tracked = root.parent / 'tracked'
        tracked.write_bytes(git(ROOT, 'ls-files', '-z', '--cached', '--ignored',
                                '--exclude-standard'))
        if tracked.read_bytes():
            git(root, 'add', '--force', '--pathspec-from-file=' + str(tracked),
                '--pathspec-file-nul')
        git(root, 'commit', '--quiet', '--message', 'the fixture repository')
        return root

    def side(self, name, change):
        """A revision of the fixture repository beside its main one, holding one change."""
        git(self.root, 'checkout', '--quiet', '--detach', self.main)
        change()
        git(self.root, 'add', '--all')
        git(self.root, 'commit', '--quiet', '--message', name)
        return text(self.root, 'rev-parse', 'HEAD')

    def resealed(self, change):
        def edit():
            report = carry.load_json(self.root / REPORT)
            change(report)
            report['seal'] = carry.seal(report)
            (self.root / REPORT).write_bytes(carry.dump(report))
        return edit

    def tree_copy(self, name, change=None):
        """A copy of the candidate's source tree with one change."""
        tree = self.directory / name
        if not tree.exists():
            shutil.copytree(self.tree, tree, symlinks=True)
            if change is not None:
                change(tree)
        return tree

    def command(self, name, revision=None, tree=None, evidence=None, options=(), driver=()):
        """The command of the fixture repository's own exporter at a revision, or of the driver
        given with its arguments, with the fixture checked out there: (command, scratch)."""
        git(self.root, 'checkout', '--quiet', '--detach', revision or self.main)
        scratch = self.directory / ('export-' + name.replace(' ', '-').replace('/', '-'))
        arguments = ['export', '--report', str(self.root / REPORT), '--source-root',
                     str(tree or self.tree), '--source-evidence', str(evidence or self.evidence),
                     '--allowed-signers', str(self.signers), '--scratch', str(scratch), *options]
        tool = self.root / 'scripts/proof/grapheneos_export.py'
        command = [sys.executable, '-B', str(tool), *arguments] if not driver else \
            [sys.executable, '-B', '-c', driver[0], str(tool.parent), *driver[1:], *arguments]
        return command, scratch

    def kept(self):
        """The fixture's old artifacts and selection, to compare after a run."""
        return snapshot(self.root), (self.root / base.SELECTION).read_bytes()

    def run_export(self, name, **options):
        """Run the command: its process, its evidence record and whether the fixture's selection
        and old artifacts kept their bytes."""
        command, scratch = self.command(name, **options)
        before = self.kept()
        process = subprocess.run(command, cwd=self.root, env=python_environment(),
                                 capture_output=True, text=True, timeout=900)
        return process, evidence_record(scratch), self.kept() == before

    def refused(self, name, pattern, **options):
        process, record, kept = self.run_export(name, **options)
        self.assertEqual(process.returncode, 1, process.stdout)
        self.assertIn(pattern, process.stderr)
        self.assertEqual((record['status'], record.get('left')), ('FAIL', None))
        self.assertIn(pattern, record['failure'])
        self.assertTrue(kept, name)
        self.assertEqual(git(self.root, 'status', '--porcelain'), b'')
        self.assertFalse((self.root / SECOND_PATCHES).exists())
        self.assertFalse((self.root / SECOND_HOSTS).exists())
        return record

    def clear_candidate(self):
        for path in (self.root / SECOND_PATCHES, self.root / SECOND_HOSTS):
            if path.is_symlink():
                path.unlink()
            else:
                shutil.rmtree(path, ignore_errors=True)

    def remove_candidate(self):
        self.clear_candidate()
        self.assertEqual(git(self.root, 'status', '--porcelain'), b'')


class HonestExportTests(FixtureCase):

    def test_an_honest_export_writes_the_candidate_from_the_sealed_report(self):
        self.addCleanup(self.remove_candidate)
        old = {path.name: path.read_bytes() for path in (self.root / PINNED_PATCHES).iterdir()}
        process, record, kept = self.run_export('honest')
        self.assertEqual(process.returncode, 0, process.stderr)
        printed = json.loads(process.stdout.split('\nevidence: ')[0])
        self.assertEqual((printed['status'], printed['base'], printed['release']),
                         ('EXPORTED', PINNED, SECOND))
        self.assertEqual([row['path'] for row in printed['written']], WRITTEN)
        self.assertTrue(kept)
        # Exactly the candidate's files are new. Nothing else in the fixture changed.
        listed = git(self.root, 'status', '--porcelain', '--untracked-files=all').decode()
        self.assertEqual(sorted(listed.splitlines()), sorted('?? ' + name for name in WRITTEN))
        for row in printed['written']:
            self.assertEqual(sha((self.root / row['path']).read_bytes()), row['sha256'])
        candidates = self.root / SECOND_PATCHES
        for name in ('native-principal-pins.patch', 'owner-lifecycle.patch',
                     'package-verity.patch', 'package-installer-payload-sync.patch',
                     'native-identity-writer.patch', 'owner-session-policy.patch'):
            self.assertEqual((candidates / name).read_bytes(), old[name], name)
        # Each profile names the candidate's revision and the digests the real sealed report
        # carried from the public files, and otherwise equals the selected base's.
        real = {row['name']: row for row in sealed_rows()}
        framework, sepolicy = self.revisions[FRAMEWORK][1], self.revisions[SEPOLICY][1]
        for name in export.FRAMEWORK:
            new = json.loads((candidates / (name + '.json')).read_text())
            previous = json.loads(old[name + '.json'])
            self.assertEqual(new['head'], framework)
            for entry in real[name]['files']:
                pair = export.digest_pair(new, entry['path'])
                self.assertEqual((pair['upstream_sha256'], pair['candidate_sha256']),
                                 (entry['target_sha256'], entry['candidate_sha256']))
                export.digest_pair(new, entry['path']).update(
                    upstream_sha256=entry['base_sha256'],
                    candidate_sha256=entry['pinned_candidate_sha256'])
            self.assertEqual(dict(new, head=previous['head']), previous, name)
        verity = (candidates / 'package-verity.json').read_bytes()
        hosted = json.loads((self.root / SECOND_HOST).read_text())
        pinned_host = json.loads((self.root / PINNED_HOST).read_text())
        self.assertEqual(
            {key: hosted[key] for key in hosted if hosted[key] != pinned_host[key]},
            {'head': framework, 'base_profile': SECOND_PATCHES + '/package-verity.json',
             'base_profile_sha256': sha(verity)})
        self.assertEqual((hosted['status'], hosted['integrated'], hosted['fileutils_sha256']),
                         ('candidate', False, sha(self.fileutils[SECOND])))
        payload = json.loads((candidates / 'package-installer-payload-sync.json').read_text())
        previous = json.loads(old['package-installer-payload-sync.json'])
        self.assertEqual(
            {key: payload[key] for key in payload if payload[key] != previous[key]},
            {'head': framework, 'requires': SECOND_PATCHES + '/package-verity.json',
             'requires_sha256': sha(verity), 'host_profile': SECOND_HOST,
             'host_profile_sha256': sha((self.root / SECOND_HOST).read_bytes())})
        self.assertEqual((payload['upstream_sha256'], payload['base_sha256'],
                          payload['candidate_sha256']),
                         (real['package-verity']['files'][0]['target_sha256'],
                          real['package-verity']['files'][0]['candidate_sha256'],
                          real[export.PAYLOAD]['files'][0]['candidate_sha256']))
        policy_record = json.loads((candidates / 'owner-session-policy.json').read_text())
        previous = json.loads(old['owner-session-policy.json'])
        self.assertEqual(
            {key: policy_record[key] for key in policy_record
             if policy_record[key] != previous[key]},
            {'base_release': SECOND, 'head': sepolicy})
        self.assertEqual(policy_record['files'], [
            dict(path=path, upstream_sha256=policy.BEFORE[path],
                 candidate_sha256=entry['candidate_sha256'])
            for path, entry in zip(policy.FILES, real[export.POLICY]['files'])])
        readme = (candidates / 'README.md').read_text()
        self.assertIn('- `frameworks/base`: `%s`' % framework, readme)
        self.assertIn('Of the 18 upstream files the patches change, 15 are identical', readme)
        # The evidence keeps the carried rows, the inputs by object and the scratch checkout's
        # results; the fixture's sealed report holds the same rows.
        self.assertEqual(record['status'], 'EXPORTED')
        rows = carry.load_json(self.root / REPORT)['patches']
        for row in rows:
            for entry in row['files']:
                entry.pop('upstream_commits', None)
        self.assertEqual(record['rows'], rows)
        checks = record['export_check'].get('checks', {})
        self.assertEqual(sorted(checks), ['format guard', 'patch set', 'validate'])
        self.assertEqual(checks['format guard']['format_guard'], 'PASS')
        self.assertEqual(checks['patch set']['host_record'],
                         {'path': SECOND_HOST,
                          'sha256': sha((self.root / SECOND_HOST).read_bytes())})
        sides = {(row['release'], row.get('upstream', 'present')) for row in record['inputs']}
        self.assertEqual(sides, {(PINNED, 'present'), (PINNED, 'absent'), (SECOND, 'present'),
                                 (SECOND, 'absent')})
        self.assertEqual(sum(1 for row in record['inputs'] if row.get('upstream') == 'absent'), 16)
        # The candidate gate, run on a commit of the export, passes every check but the source
        # verifier, which needs a real Repo tree.
        git(self.root, 'add', '--all')
        git(self.root, 'commit', '--quiet', '--message', 'the exported candidate')
        revision = text(self.root, 'rev-parse', 'HEAD')
        self.addCleanup(git, self.root, 'checkout', '--quiet', '--detach', self.main)
        process = subprocess.run(
            [sys.executable, '-B', str(self.root / 'scripts/proof/grapheneos_candidate.py'),
             'check', '--release', SECOND, '--source-root', str(self.tree), '--allowed-signers',
             str(self.signers), '--scratch', str(self.directory / 'gate'), '--revision',
             revision], cwd=self.root, env=python_environment(), capture_output=True, text=True,
            timeout=900)
        gate = json.loads((self.directory / 'gate/report.json').read_text())
        results = {row['check']: row['result'] for row in gate['checks']}
        self.assertEqual(process.returncode, 1)
        self.assertEqual(results, dict({name: 'PASS' for name in results},
                                       **{'source verifier': 'FAIL'}))
        self.assertEqual(len(results), 10)
        tools = {row['check']: row for row in gate['checks']}
        self.assertEqual({tools[name]['state'] for name in candidate.PATCH_TOOLS}, {'UPSTREAM'})
        git(self.root, 'checkout', '--quiet', '--detach', self.main)

    def test_missing_base_objects_are_refused_then_read_from_a_reviewed_base_tree(self):
        def partial(tree):
            shutil.rmtree(tree / FRAMEWORK)
            git(tree, 'clone', '--quiet', '--filter=blob:none',
                'file://' + str(self.tree / FRAMEWORK), str(tree / FRAMEWORK))
        tree = self.tree_copy('partial', partial)
        blob = text(self.tree / FRAMEWORK, 'rev-parse', '%s:%s' % (
            self.revisions[FRAMEWORK][0], 'services/core/java/com/android/server/pm/'
                                          'InstallPackageHelper.java'))
        self.refused('missing base objects', 'is missing from the Git objects of frameworks/base '
                     'of %s, and nothing is fetched' % tree, tree=tree)
        process = subprocess.run(['git', '-C', str(tree / FRAMEWORK), 'cat-file', '-e', blob],
                                 env=dict(source.git_environment()), capture_output=True,
                                 timeout=60)
        self.assertNotEqual(process.returncode, 0, 'a missing object was fetched')
        self.addCleanup(self.remove_candidate)
        process, record, kept = self.run_export('reviewed base tree', tree=tree,
                                                options=('--base-source-root', str(self.tree)))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(kept)
        self.assertEqual(record['base_source_root'], str(self.tree))
        self.assertEqual({row['path'] for row in record['written']}, set(WRITTEN))

    def test_validate_reads_the_selected_base(self):
        git(self.root, 'checkout', '--quiet', '--detach', self.main)
        tool = self.root / 'scripts/proof/grapheneos_export.py'
        for release, code in ((PINNED, 0), (SECOND, 1)):
            with self.subTest(release=release):
                process = subprocess.run([sys.executable, '-B', str(tool), 'validate', '--inputs',
                                          str(self.inputs[release])], cwd=self.root,
                                         env=python_environment(), capture_output=True,
                                         text=True, timeout=300)
                report = json.loads(process.stdout)
                self.assertEqual((process.returncode, report['base']), (code, PINNED))
                if code:
                    self.assertIn('wrong pinned input', report['validate'][0])
                    continue
                self.assertEqual(report['host_record'], {
                    'path': PINNED_HOST, 'sha256': sha((self.root / PINNED_HOST).read_bytes()),
                    'states': ['BASE', 'CANDIDATE'],
                    'fileutils_sha256': sha(self.fileutils[PINNED])})
                rows = {row['name']: row for row in sealed_rows()}
                for name, found in report['patches'].items():
                    self.assertEqual(found['files'], {
                        entry['path']: [entry['base_sha256'], entry['pinned_candidate_sha256']]
                        for entry in rows[name]['files']}, name)
        self.assertEqual(git(self.root, 'status', '--porcelain'), b'')


# Runs the fixture's exporter with one step wrapped so that it changes an old artifact.
DRIVER = '''import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import grapheneos_export as export
step, path, data = sys.argv[2], Path(sys.argv[3]), sys.argv[4].encode()
original = getattr(export, step)
def wrapped(*args, **kwargs):
    result = original(*args, **kwargs)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((path.read_bytes() if path.exists() else b'') + data)
    return result
setattr(export, step, wrapped)
sys.exit(export.main(sys.argv[5:]))
'''


class RefusedExportTests(FixtureCase):

    def test_a_wrong_base_is_refused(self):
        tree = self.tree_copy('old-base', lambda tree: git(
            tree / FRAMEWORK, 'checkout', '--quiet', '--detach', self.revisions[FRAMEWORK][0]))
        self.refused('a source tree at the base', 'frameworks/base of the source tree is not at '
                     'the 2026100600 revision', tree=tree)
        old = carry.load_json(self.root / ('upstream/bases/%s.json' % PINNED))
        evidence = verification(self.directory / 'base-evidence', old)
        self.refused('the base verification', 'does not pass for 2026100600: release, '
                     'manifest_commit, manifest_tag, manifest_sha256', evidence=evidence)
        selects = self.side('a producer selecting the candidate', lambda: rewrite(
            self.root / base.SELECTION, release=SECOND, record=SECOND_RECORD,
            record_sha256=sha((self.root / SECOND_RECORD).read_bytes())))
        self.refused('a producer selecting the candidate', 'the report is of base 2026081300, not '
                     'of the selected base 2026100600', revision=selects)

    def test_missing_target_objects_are_refused(self):
        path = 'services/core/java/com/android/server/pm/InstallPackageHelper.java'
        blob = text(self.tree / FRAMEWORK, 'rev-parse', '%s:%s' % (self.revisions[FRAMEWORK][1],
                                                                   path))
        # With a current index, the tree's own cleanliness check reads no object.
        tree = self.tree_copy('loose', lambda tree: (
            git(tree / FRAMEWORK, 'update-index', '--refresh'),
            (tree / FRAMEWORK / '.git/objects' / blob[:2] / blob[2:]).unlink()))
        self.refused('a missing target object', '%s at %s is missing from the Git objects' % (
            path, self.revisions[FRAMEWORK][1]), tree=tree)

    def test_files_other_than_the_carried_ones_are_refused(self):
        def digest(index, entry, key):
            def change(report):
                report['patches'][index]['files'][entry][key] = '0' * 64
            return change
        for name, change, release, path in (
                ('another carried target', digest(0, 4, 'target_sha256'), SECOND,
                 'services/core/java/com/android/server/pm/InstallPackageHelper.java'),
                ('another carried base', digest(1, 0, 'base_sha256'), PINNED,
                 'services/core/java/com/android/server/StorageManagerInternal.java')):
            with self.subTest(case=name):
                self.refused(name, 'the %s file %s of frameworks/base is not the one the sealed '
                             'report carried' % (release, path),
                             revision=self.side(name, self.resealed(change)))

    def test_host_drift_is_refused(self):
        watched = self.side('another watched FileUtils.java', self.resealed(lambda report: [
            row.update(target_object='0' * 40) for row in report['surface']
            if row['path'] == host.FILEUTILS]))
        self.refused('another watched FileUtils.java', 'host drift: core/java/android/os/'
                     'FileUtils.java at 2026100600 is not the object the sealed report watched',
                     revision=watched)

        def fragment():
            path = self.root / 'tests/installer-durability/PisFileUtilsSync.pinned.java.inc'
            path.write_bytes(path.read_bytes().replace(b'fsync', b'fdatasync', 1))
        changed = self.side('a changed shared sync fragment', fragment)
        self.refused('a changed shared sync fragment', 'host drift: the tested source no longer '
                     'holds in fileutils_sync_fragment_sha256', revision=changed)

        def candidate_fragment():
            path = self.root / host.CANDIDATE_FRAGMENT.relative_to(ROOT)
            path.write_bytes(path.read_bytes() + b'\n')
        changed = self.side('a changed shared candidate fragment', candidate_fragment)
        self.refused('a changed shared candidate fragment', 'payload sync profile drift',
                     revision=changed)

    def test_a_policy_disagreement_is_refused(self):
        domain = policy.FILES[0]
        upstream = {path: (self.inputs[SECOND] / SEPOLICY / path).read_bytes()
                    for path in policy.FILES}
        variant = dict(upstream, **{domain: upstream[domain] + b'# a later upstream comment\n'})

        def change(tree):
            project = tree / SEPOLICY
            git(project, 'checkout', '--quiet', '--detach', self.revisions[SEPOLICY][0])
            (project / domain).write_bytes(variant[domain])
            git(project, 'commit', '--quiet', '--all', '--message', 'a later policy')
        tree = self.tree_copy('policy', change)
        revision = text(tree / SEPOLICY, 'rev-parse', 'HEAD')
        spec = [spec for spec in carry.load_patch_set(PINNED) if spec['name'] == export.POLICY][0]
        base_te = {path: (self.inputs[PINNED] / SEPOLICY / path).read_bytes()
                   for path in policy.FILES}
        work = self.directory / 'policy-work'
        work.mkdir()
        row, _, _ = carry.carry_patch(spec, base_te, variant, work)
        self.assertEqual((row['class'], row['files'][0]['review_record']),
                         ('changed clean', 'agrees'))

        def edit():
            path = self.root / SECOND_RECORD
            value = carry.load_json(path)
            value['patched_projects'][SEPOLICY]['revision'] = revision
            path.write_bytes(carry.dump(value))
            report = carry.load_json(self.root / REPORT)
            row['profile_sha256'] = report['patches'][5]['profile_sha256']
            report['patches'][5] = row
            report['target']['record_sha256'] = sha(path.read_bytes())
            report['seal'] = carry.seal(report)
            (self.root / REPORT).write_bytes(carry.dump(report))
        sealed = self.side('a carried later policy', edit)
        record = carry.load_json(self.root / SECOND_RECORD)
        evidence = verification(self.directory / 'policy-evidence', record)
        self.refused('a later upstream policy', 'policy disagreement: one of the four files at '
                     '2026100600 is not the upstream file that owner_policy.py pins',
                     revision=sealed, tree=tree, evidence=evidence)
        # With the sealed report unchanged, the later policy is not the file it carried.
        git(self.root, 'checkout', '--quiet', '--detach', self.main)
        self.refused('an uncarried later policy', 'system/sepolicy of the source tree is not at '
                     'the 2026100600 revision', tree=tree)

    def test_an_old_artifact_changed_is_refused(self):
        def append(name):
            def change():
                path = self.root / name
                path.write_bytes(path.read_bytes() + b'\n')
            return change
        for name, pattern in ((PINNED_PATCHES + '/owner-lifecycle.patch',
                               'the sealed report has drift: patch %s/owner-lifecycle.patch'
                               % PINNED_PATCHES),
                              (PINNED_HOST, 'payload sync profile drift')):
            with self.subTest(changed=name):
                self.refused('changed ' + name, pattern, revision=self.side(
                    'changed ' + name, append(name)))
        # A change while the export runs: before it writes, and after it wrote.
        git(self.root, 'checkout', '--quiet', '--detach', self.main)
        listed = git(self.root, 'status', '--porcelain', '--ignored')
        lifecycle = self.root / PINNED_PATCHES / 'owner-lifecycle.patch'
        for step, path, pattern in (
                ('check_export', lifecycle, 'an old artifact changed during the checks: '
                                            '%s/owner-lifecycle.patch' % PINNED_PATCHES),
                ('write_candidate', self.root / PINNED_PATCHES / '__pycache__/stray.pyc',
                 'an old artifact changed during the export: %s/__pycache__'
                 % PINNED_PATCHES),
                ('write_candidate', self.root / base.SELECTION,
                 'this checkout has other changes than the candidate files')):
            with self.subTest(step=step, path=path.name):
                self.clear_candidate()
                saved = path.read_bytes() if path.exists() else None
                process, record, _ = self.run_export(
                    'during %s %s' % (step, path.name),
                    driver=(DRIVER, step, str(path), 'changed\n'))
                try:
                    self.assertEqual(process.returncode, 1, process.stdout)
                    self.assertIn(pattern, process.stderr)
                    self.assertEqual((record['status'], record.get('left')), ('FAIL', None))
                    self.assertFalse((self.root / SECOND_PATCHES).exists())
                    self.assertFalse((self.root / SECOND_HOSTS).exists())
                finally:
                    if saved is None:
                        shutil.rmtree(path.parent, ignore_errors=True)
                    else:
                        path.write_bytes(saved)
                self.assertEqual(git(self.root, 'status', '--porcelain', '--ignored'), listed)

    def test_an_existing_candidate_or_a_changed_checkout_is_refused(self):
        existing = self.side('an existing candidate', lambda: (
            (self.root / SECOND_PATCHES).mkdir(), (self.root / SECOND_PATCHES / 'README.md')
            .write_text('an earlier candidate\n')))
        process, record, kept = self.run_export('an existing candidate', revision=existing)
        self.assertEqual(process.returncode, 1)
        self.assertIn('the candidate path already exists: ' + SECOND_PATCHES, process.stderr)
        self.assertTrue(kept)
        self.assertEqual((self.root / SECOND_PATCHES / 'README.md').read_text(),
                         'an earlier candidate\n')
        self.assertEqual(git(self.root, 'status', '--porcelain'), b'')
        git(self.root, 'checkout', '--quiet', '--detach', self.main)
        stray = self.root / 'stray.txt'
        stray.write_text('x\n')
        try:
            process, record, kept = self.run_export('a changed checkout')
            self.assertEqual(process.returncode, 1)
            self.assertIn('this checkout has changes', process.stderr)
            self.assertTrue(kept)
        finally:
            stray.unlink()
        self.assertFalse((self.root / SECOND_PATCHES).exists())


# Runs the fixture's exporter with one fault late in its run, or with none as the honest twin of
# every fault: a full evidence filesystem at the first or the final record (once, or from then on),
# a termination signal at a given point, another entry in the candidate directories, a created
# path replaced, or removed and made again, a parent replaced while writing, a record failure
# after the final record's rename (once, or with no record replaceable from then on), with or
# without the failure record's second name, or SIGKILL just after that rename.
FAULTS = '''import errno, json, os, shutil, signal, sys, time, types
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import grapheneos_export as export
fault, marker = sys.argv[2], Path(sys.argv[3])
target = export.ROOT / 'patches/grapheneos-2026100600'
state = {'failed': False}


def after(owner, name, action):
    original = getattr(owner, name)

    def wrapped(*args, **kwargs):
        result = original(*args, **kwargs)
        action(*args)
        return result
    setattr(owner, name, wrapped)


def once(action):
    done = []

    def run(*args):
        if not done:
            done.append(True)
            action(*args)
    return run


def send(number):
    return lambda *args: os.kill(os.getpid(), number)


def proxy(**functions):
    module = types.ModuleType('os')
    module.__dict__.update(os.__dict__)
    module.__dict__.update(functions)
    export.os = module


def full(descriptor):
    name = os.readlink('/proc/self/fd/%d' % descriptor)
    if '/evidence/.export-' in name:
        with open(name, 'rb') as handle:
            final = b'"status": "EXPORTED"' in handle.read()
        if final or (fault == 'evidence full' and full.failed):
            full.failed = True
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    return os.fsync(descriptor)
full.failed = False


def no_space(descriptor):
    """Every evidence record fails to sync, from the first on."""
    if '/evidence/.export-' in os.readlink('/proc/self/fd/%d' % descriptor):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    return os.fsync(descriptor)


def opened(path, flags, mode=0o777, **options):
    descriptor = os.open(path, flags, mode, **options)
    # The first file created exclusively through a directory descriptor: a candidate file.
    if not opened.sent and flags & os.O_CREAT and options.get('dir_fd') is not None:
        opened.sent = True
        os.kill(os.getpid(), signal.SIGTERM)
    return descriptor
opened.sent = False


def waiting(*args):
    marker.write_text('the first candidate file is written')
    deadline = time.monotonic() + 120
    while signal.SIGTERM not in signal.sigpending() and time.monotonic() < deadline:
        time.sleep(0.05)


def stray(*args):
    (target / '__pycache__').mkdir()
    (target / '__pycache__/stray.pyc').write_bytes(b'a stray compiled file')


def foreign(*args):
    (target / 'README.md').write_bytes(b'# a README someone else wrote')


def signalled(original):
    def remove(self):
        os.kill(os.getpid(), signal.SIGTERM)
        return original(self)
    return remove


def refused(change):
    """After writing: one change of the candidate's paths, then a refusal, so the rollback runs."""
    def run(*args):
        change()
        raise export.ExportError('induced refusal after namespace replacement')
    return run


def readme(replacement):
    """The created README moved aside and another file, a new inode, put in its place."""
    def change(*args):
        path = target / 'README.md'
        data = path.read_bytes()
        path.rename(marker.with_suffix('.original'))
        path.write_bytes(replacement(data))
    return change


def directory(link):
    """The created patch directory moved aside, and an empty directory or a link to the selected
    base's patch directory put in its place."""
    def change(*args):
        target.rename(marker.with_suffix('.original'))
        if link:
            target.symlink_to(export.ROOT / 'patches/grapheneos-2026081300',
                              target_is_directory=True)
        else:
            target.mkdir()
    return change


def exported(path):
    with open(path, 'rb') as handle:
        return b'"status": "EXPORTED"' in handle.read()


def synced(original, remove=False):
    """The directory sync right after the final record is renamed into place fails, once. With
    remove, the failure record's second name is removed with it."""
    def sync(path):
        record = Path(path) / export.RECORD
        if not state['failed'] and record.exists() and exported(record):
            state['failed'] = True
            if remove:
                (Path(path) / export.FALLBACK).unlink()
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return original(path)
    return sync


def reused(held):
    """The created README removed and made again with its very bytes, up to 512 times until the
    new file has the created inode, as a filesystem hands out a freed inode again. With held,
    another descriptor holds the original open meanwhile."""
    def change(*args):
        path = target / 'README.md'
        data = path.read_bytes()
        created = path.stat()
        if held:
            state['held'] = os.open(path, os.O_RDONLY)
        path.unlink()
        for attempt in range(512):
            path.write_bytes(data)
            again = path.stat()
            matched = (again.st_dev, again.st_ino) == (created.st_dev, created.st_ino)
            if matched or attempt == 511:
                break
            path.unlink()
        marker.write_text(json.dumps({'reused': matched, 'attempts': attempt + 1}) + '\\n')
    return change


def copied(*args):
    """The patches directory moved aside, and a copy of it, byte for byte, put in its place."""
    parent = export.ROOT / 'patches'
    parent.rename(marker.with_suffix('.saved-parent'))
    shutil.copytree(marker.with_suffix('.saved-parent'), parent)


def read_back(original):
    """Reading the final record back after it is renamed into place fails, once."""
    def read(path):
        data = original(path)
        if (path.name == export.RECORD and not state['failed']
                and b'"status": "EXPORTED"' in data):
            state['failed'] = True
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return data
    return read


def stuck(source, destination, *args, **kwargs):
    """Once the first fault happened, no record can be renamed into place any more."""
    if state['failed'] and Path(destination).name == export.RECORD:
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    return os.replace(source, destination, *args, **kwargs)


if fault in ('evidence full once', 'evidence full'):
    proxy(fsync=full)
elif fault == 'first record':
    proxy(fsync=no_space)
elif fault == 'SIGKILL after final rename':
    def killed(source, destination, *args, **kwargs):
        os.replace(source, destination, *args, **kwargs)
        if Path(destination).name == export.RECORD and exported(destination):
            os.kill(os.getpid(), signal.SIGKILL)
    proxy(replace=killed)
elif fault == 'SIGTERM through timeout':
    after(export.NewFiles, 'write', once(waiting))
elif fault in ('SIGHUP', 'SIGINT'):
    # Delivered as a terminal would, whatever the test runner ignores.
    number = getattr(signal, fault)
    signal.signal(number, signal.default_int_handler if fault == 'SIGINT' else signal.SIG_DFL)
    after(export.NewFiles, 'write', once(send(number)))
elif fault == 'SIGTERM after open':
    proxy(open=opened)
elif fault == 'SIGTERM during rollback':
    after(export.NewFiles, 'write', once(send(signal.SIGTERM)))
    export.NewFiles.remove = signalled(export.NewFiles.remove)
elif fault == 'stray ignored file':
    after(export, 'write_candidate', stray)
elif fault == 'foreign file bytes':
    after(export, 'write_candidate', foreign)
elif fault.startswith('owned README '):
    cut = {'equal': lambda data: data, 'prefix': lambda data: data[:10],
           'empty': lambda data: b''}[fault.split()[-1]]
    after(export, 'write_candidate', refused(readme(cut)))
elif fault == 'replacement directory':
    after(export, 'write_candidate', refused(directory(link=False)))
elif fault == 'link to old patches':
    after(export, 'write_candidate', refused(directory(link=True)))
elif fault == 'same bytes after writing':
    after(export, 'write_candidate', readme(lambda data: data))
elif fault.startswith('post publish sync '):
    export.sync_directory = synced(export.sync_directory)
    if fault.endswith('persistent'):
        proxy(replace=stuck)
elif fault.startswith('fallback gone '):
    export.sync_directory = synced(export.sync_directory, remove=True)
    if fault.endswith('persistent'):
        proxy(replace=stuck)
elif fault == 'reuse accepted':
    after(export, 'write_candidate', reused(held=False))
elif fault in ('reuse rollback', 'reuse held original'):
    after(export, 'write_candidate', refused(reused(held=fault.endswith('original'))))
elif fault == 'parent replaced during writing':
    after(export.NewFiles, 'directory', once(copied))
elif fault.startswith('final readback '):
    Path.read_bytes = read_back(Path.read_bytes)
    if fault.endswith('persistent'):
        proxy(replace=stuck)
elif fault != 'none':
    raise SystemExit('unknown fault ' + fault)
sys.exit(export.main(sys.argv[4:]))
'''


class FaultCase(FixtureCase):
    """The fixture's exporter run by FAULTS: with no fault as the honest twin of every case, then
    with each fault."""
    twin = None

    def fault(self, fault, code):
        """One run with a fault, its exit status code: (process, record, kept). Whatever an
        earlier case that failed left behind is cleared first, so it fails alone."""
        self.clear_candidate()
        marker = self.directory / ('marker-' + fault.replace(' ', '-'))
        process, record, kept = self.run_export('fault ' + fault,
                                                driver=(FAULTS, fault, str(marker)))
        self.assertEqual(process.returncode, code, process.stderr)
        self.assertIsNotNone(record, 'the export left no evidence record')
        return process, record, kept

    def honest_twin(self):
        """The same driver without a fault exports the candidate. It runs once per class."""
        cls = type(self)
        if cls.twin is None:
            process, record, kept = self.fault('none', 0)
            self.assertTrue(kept)
            self.assertEqual((record['status'], record['phase']), ('EXPORTED', 'done'))
            self.assertEqual(sorted(record['inventory']), sorted(WRITTEN))
            self.assertEqual([row['path'] for row in record['written']], WRITTEN)
            self.remove_candidate()
            cls.twin = record
        self.assertEqual(cls.twin['status'], 'EXPORTED')

    def rolled_back(self, record, kept, failure, phase='writing'):
        """A failure record, and no candidate path or other change left in the fixture."""
        self.assertTrue(kept)
        self.assertEqual((record['status'], record['phase']), ('FAIL', phase))
        self.assertIn(failure, record['failure'])
        self.assertNotIn('left', record)
        self.assertFalse((self.root / SECOND_PATCHES).exists())
        self.assertFalse((self.root / SECOND_HOSTS).exists())
        self.assertEqual(git(self.root, 'status', '--porcelain', '--untracked-files=all',
                             '--ignored'), b'')


class FinishingTests(FaultCase):

    def test_the_export_is_done_only_once_its_final_record_persists(self):
        self.honest_twin()
        process, record, kept = self.fault('evidence full once', 1)
        self.assertIn('No space left on device', process.stderr)
        self.rolled_back(record, kept, 'OSError: [Errno 28] No space left on device',
                         phase='finishing')
        self.assertEqual(sorted(record['removed']), sorted(WRITTEN + [SECOND_PATCHES,
                                                                      SECOND_HOSTS]))
        evidence = self.directory / 'export-fault-evidence-full-once/evidence'
        self.assertIn('evidence: %s says FAIL in the finishing phase' % (evidence / export.RECORD),
                      process.stderr)
        # With the evidence filesystem full from then on, the failure record of the writing
        # phase, written before the first candidate file, is the one left, and stderr says so.
        process, record, kept = self.fault('evidence full', 1)
        evidence = self.directory / 'export-fault-evidence-full/evidence'
        self.assertIn('note: the failure record of this run could not be written ([Errno 28] No '
                      'space left on device). The rollback removed 16 paths this export created, '
                      'and kept: nothing', process.stderr)
        self.assertIn('evidence: %s says FAIL in the writing phase' % (evidence / export.RECORD),
                      process.stderr)
        self.rolled_back(record, kept, export.UNFINISHED['writing'])
        self.assertEqual(record['failure'], export.UNFINISHED['writing'])
        self.assertNotIn('removed', record)
        self.assertEqual(sorted(path.name for path in evidence.iterdir()
                                if path.name.startswith(('.', 'export'))), [export.RECORD])

    def test_the_candidate_directories_must_hold_exactly_the_checked_files(self):
        self.honest_twin()
        readme = SECOND_PATCHES + '/README.md'
        holds = {SECOND_PATCHES: 'it holds entries this export did not create'}
        # (fault, the failure, its key in the record and the entries it names, the reasons the
        # rollback keeps paths for, and the files left in the patch directory)
        cases = (('stray ignored file', 'unexpected %s/__pycache__, %s/__pycache__/stray.pyc'
                  % (SECOND_PATCHES, SECOND_PATCHES), 'unexpected',
                  [SECOND_PATCHES + '/__pycache__', SECOND_PATCHES + '/__pycache__/stray.pyc'],
                  holds, {'__pycache__/stray.pyc': b'a stray compiled file'}),
                 ('foreign file bytes', 'differing ' + readme, 'differing', [readme],
                  dict({readme: 'changed since this export wrote it'}, **holds),
                  {'README.md': b'# a README someone else wrote'}),
                 # Another file with the very bytes this export wrote: a new inode, not its own.
                 ('same bytes after writing', 'foreign ' + readme, 'foreign', [readme],
                  dict({readme: 'another object than the one this export created'}, **holds),
                  None))
        written = {row['path']: row['sha256'] for row in self.twin['written']}
        for fault, failure, key, entries, reasons, others in cases:
            with self.subTest(fault=fault):
                process, record, kept = self.fault(fault, 1)
                self.assertTrue(kept)
                self.assertEqual((record['status'], record.get(key)), ('FAIL', entries))
                self.assertIn('the candidate directories hold other entries than the files this '
                              'export wrote: ' + failure, record['failure'])
                # The export removed only what it wrote. Another's entry is kept and reported,
                # with the directory holding it.
                self.assertEqual((record.get('left'), record.get('left_reasons')),
                                 (list(reasons), reasons))
                kept_files = {path.relative_to(self.root / SECOND_PATCHES).as_posix():
                              path.read_bytes()
                              for path in (self.root / SECOND_PATCHES).rglob('*')
                              if path.is_file()}
                if others is None:
                    aside = self.directory / ('marker-%s.original' % fault.replace(' ', '-'))
                    self.assertEqual(sha(aside.read_bytes()), written[readme])
                    others = {'README.md': aside.read_bytes()}
                self.assertEqual(kept_files, others)
                self.assertFalse((self.root / SECOND_HOSTS).exists())
                self.remove_candidate()


class OwnershipTests(FaultCase):

    def test_a_replaced_candidate_file_is_kept_whatever_its_bytes(self):
        self.honest_twin()
        readme = SECOND_PATCHES + '/README.md'
        written = {row['path']: row['sha256'] for row in self.twin['written']}
        # The created README moved aside and another file, a new inode, put in its place with
        # the same bytes, a prefix of them or none, then a refusal.
        for cut, length in (('equal', None), ('prefix', 10), ('empty', 0)):
            with self.subTest(replacement=cut):
                fault = 'owned README ' + cut
                process, record, kept = self.fault(fault, 1)
                self.assertTrue(kept)
                self.assertIn('FAIL: induced refusal after namespace replacement', process.stderr)
                self.assertEqual((record['status'], record['phase']), ('FAIL', 'writing'))
                # The replacement is kept and reported, with the directory holding it. Every
                # other path this export created is still its own and is removed.
                self.assertEqual(record['left_reasons'], {
                    readme: 'another object than the one this export created',
                    SECOND_PATCHES: 'it holds entries this export did not create'})
                self.assertEqual(record['left'], [readme, SECOND_PATCHES])
                self.assertEqual(record['removed'], [name for name in reversed(WRITTEN)
                                                     if name != readme] + [SECOND_HOSTS])
                original = (self.directory / ('marker-' + fault.replace(' ', '-') + '.original')
                            ).read_bytes()
                self.assertEqual(sha(original), written[readme])
                self.assertEqual((self.root / readme).read_bytes(), original[:length])
                self.assertEqual([path.name for path in (self.root / SECOND_PATCHES).iterdir()],
                                 ['README.md'])
                self.assertFalse((self.root / SECOND_HOSTS).exists())
                self.remove_candidate()

    def test_a_replaced_candidate_directory_is_neither_followed_nor_removed(self):
        self.honest_twin()
        inside = [name for name in reversed(WRITTEN) if name.startswith(SECOND_PATCHES + '/')]
        written = {row['path']: row['sha256'] for row in self.twin['written']}
        old = {path.name: path.read_bytes() for path in (self.root / PINNED_PATCHES).iterdir()}
        # The created patch directory moved aside and another empty directory, or a link to the
        # selected base's patch directory, whose patches have the very bytes this export wrote,
        # put in its place, then a refusal. The link is never followed.
        for fault, reason in (
                ('replacement directory', 'not reached: %s is another directory than the one '
                                          'this export found or created' % SECOND_PATCHES),
                ('link to old patches', 'not reached: %s: %s' % (SECOND_PATCHES,
                                                                 os.strerror(errno.ENOTDIR)))):
            with self.subTest(fault=fault):
                process, record, kept = self.fault(fault, 1)
                self.assertTrue(kept)
                self.assertEqual((record['status'], record['phase']), ('FAIL', 'writing'))
                self.assertEqual(record['left'], inside + [SECOND_PATCHES])
                self.assertEqual(record['left_reasons'], dict(
                    {name: reason for name in inside},
                    **{SECOND_PATCHES: 'another object than the one this export created'}))
                self.assertEqual(record['removed'], [SECOND_HOST, SECOND_HOSTS])
                # The selected base's patches keep every byte, and so does each file this export
                # wrote in the directory moved aside.
                self.assertEqual({path.name: path.read_bytes()
                                  for path in (self.root / PINNED_PATCHES).iterdir()}, old)
                aside = self.directory / ('marker-' + fault.replace(' ', '-') + '.original')
                self.assertEqual({SECOND_PATCHES + '/' + path.name: sha(path.read_bytes())
                                  for path in aside.iterdir()},
                                 {name: written[name] for name in inside})
                if fault == 'link to old patches':
                    self.assertEqual(os.readlink(self.root / SECOND_PATCHES),
                                     str(self.root / PINNED_PATCHES))
                else:
                    self.assertEqual(list((self.root / SECOND_PATCHES).iterdir()), [])
                self.assertFalse((self.root / SECOND_HOSTS).exists())
                self.remove_candidate()

    def test_a_candidate_file_removed_and_made_again_is_kept(self):
        self.honest_twin()
        readme = SECOND_PATCHES + '/README.md'
        written = {row['path']: row['sha256'] for row in self.twin['written']}
        reasons = {readme: 'another object than the one this export created',
                   SECOND_PATCHES: 'it holds entries this export did not create'}
        # The created README removed and made again with its very bytes, until a filesystem would
        # hand out its inode again: with no other fault, with a refusal after it, and with a
        # refusal while another descriptor holds the original open too. The export holds it open
        # itself, so the new README never has its inode: it is foreign, and it is kept.
        refusal = 'ExportError: induced refusal after namespace replacement'
        for fault, failure in (('reuse accepted', 'the candidate directories hold other entries '
                                                  'than the files this export wrote: foreign '
                                + readme),
                               ('reuse rollback', refusal), ('reuse held original', refusal)):
            with self.subTest(fault=fault):
                process, record, kept = self.fault(fault, 1)
                self.assertTrue(kept)
                self.assertEqual((record['status'], record['phase']), ('FAIL', 'writing'))
                self.assertIn(failure, record['failure'])
                self.assertEqual((record['left'], record['left_reasons']),
                                 (list(reasons), reasons))
                self.assertEqual(record['removed'], [name for name in reversed(WRITTEN)
                                                     if name != readme] + [SECOND_HOSTS])
                marker = self.directory / ('marker-' + fault.replace(' ', '-'))
                self.assertEqual(json.loads(marker.read_text()),
                                 {'reused': False, 'attempts': 512})
                self.assertEqual(sha((self.root / readme).read_bytes()), written[readme])
                self.assertEqual([path.name for path in (self.root / SECOND_PATCHES).iterdir()],
                                 ['README.md'])
                self.assertFalse((self.root / SECOND_HOSTS).exists())
                self.remove_candidate()

    def test_a_parent_replaced_while_writing_stops_the_export_with_its_evidence_line(self):
        self.honest_twin()
        fault = 'parent replaced during writing'
        saved = self.directory / ('marker-%s.saved-parent' % fault.replace(' ', '-'))

        def put_back():
            # The copy goes, and the original patches directory returns without the directory
            # the export created in it.
            if saved.is_dir():
                shutil.rmtree(self.root / 'patches')
                saved.rename(self.root / 'patches')
                self.clear_candidate()
        self.addCleanup(put_back)
        # The patches directory moved aside and a byte for byte copy put in its place, once the
        # export created its patch directory there: writing into it is refused, nothing is
        # followed or removed there, and stderr ends with the record on disk.
        process, record, kept = self.fault(fault, 1)
        self.assertTrue(kept)
        moved = 'patches is another directory than the one this export found or created'
        evidence = self.directory / ('export-fault-%s/evidence' % fault.replace(' ', '-'))
        self.assertNotIn('Traceback', process.stderr)
        self.assertEqual(process.stderr.splitlines()[-2:], [
            'FAIL: ' + moved,
            'evidence: %s says FAIL in the writing phase' % (evidence / export.RECORD)])
        self.assertEqual((record['status'], record['phase'], record['failure']),
                         ('FAIL', 'writing', 'Moved: ' + moved))
        self.assertEqual((record['removed'], record['left_reasons']),
                         ([SECOND_HOSTS], {SECOND_PATCHES: 'not reached: ' + moved}))
        self.assertEqual(list((self.root / SECOND_PATCHES).iterdir()), [])
        self.assertEqual(list((saved / 'grapheneos-2026100600').iterdir()), [])
        self.assertFalse((self.root / SECOND_HOSTS).exists())


class RecordTests(FaultCase):

    def evidence_directory(self, fault):
        return self.directory / ('export-fault-' + fault.replace(' ', '-')) / 'evidence'

    @staticmethod
    def records(evidence):
        """The record files and temporary records in an evidence directory, beside the logs."""
        return sorted(path.name for path in evidence.iterdir()
                      if path.name.startswith(('.', 'export')))

    def test_a_failure_after_the_final_rename_keeps_a_failure_record(self):
        self.honest_twin()
        # One failure after the final record is renamed into place: its directory sync, or
        # reading it back. The failure record returns, and this run's failure record follows it.
        for fault, failure in (('post publish sync once', '[Errno 28] No space left on device'),
                               ('final readback once', '[Errno 5] Input/output error')):
            with self.subTest(fault=fault):
                process, record, kept = self.fault(fault, 1)
                evidence = self.evidence_directory(fault)
                self.rolled_back(record, kept, 'OSError: ' + failure, phase='finishing')
                self.assertEqual(sorted(record['removed']),
                                 sorted(WRITTEN + [SECOND_PATCHES, SECOND_HOSTS]))
                self.assertEqual(self.records(evidence), [export.RECORD])
                self.assertIn('FAIL: ' + failure, process.stderr)
                self.assertIn('evidence: %s says FAIL in the finishing phase'
                              % (evidence / export.RECORD), process.stderr)
        # The same, with no record replaceable from then on: the final record is withdrawn, and
        # the failure record of the writing phase, kept under its second name, is the record.
        for fault, failure in (('post publish sync persistent',
                                '[Errno 28] No space left on device'),
                               ('final readback persistent', '[Errno 5] Input/output error')):
            with self.subTest(fault=fault):
                process, record, kept = self.fault(fault, 1)
                evidence = self.evidence_directory(fault)
                self.rolled_back(record, kept, export.UNFINISHED['writing'])
                self.assertEqual(record['failure'], export.UNFINISHED['writing'])
                self.assertEqual(self.records(evidence), [export.FALLBACK])
                self.assertIn('FAIL: ' + failure, process.stderr)
                self.assertIn('note: the failure record of this run could not be written ([Errno '
                              '28] No space left on device). The rollback removed 16 paths this '
                              'export created, and kept: nothing', process.stderr)
                self.assertIn('evidence: %s is absent; %s says FAIL in the writing phase'
                              % (evidence / export.RECORD, evidence / export.FALLBACK),
                              process.stderr)

    def test_a_kill_just_after_the_final_rename_leaves_an_honest_exported_record(self):
        self.honest_twin()
        self.addCleanup(self.remove_candidate)
        fault = 'SIGKILL after final rename'
        process, record, kept = self.fault(fault, -signal.SIGKILL)
        self.assertTrue(kept)
        # The record says EXPORTED, as the honest twin's does, and the candidate it names is on
        # disk whole and checked. The failure record's second name is left beside it.
        self.assertEqual((record['status'], record['phase']), ('EXPORTED', 'done'))
        self.assertEqual((record['written'], sorted(record['inventory'])),
                         (self.twin['written'], sorted(WRITTEN)))
        for row in record['written']:
            self.assertEqual(sha((self.root / row['path']).read_bytes()), row['sha256'])
        listed = git(self.root, 'status', '--porcelain', '--untracked-files=all').decode()
        self.assertEqual(sorted(listed.splitlines()), sorted('?? ' + name for name in WRITTEN))
        evidence = self.evidence_directory(fault)
        self.assertEqual(self.records(evidence), [export.FALLBACK, export.RECORD])
        fallback = json.loads((evidence / export.FALLBACK).read_text())
        self.assertEqual((fallback['status'], fallback['phase']), ('FAIL', 'writing'))

    def test_an_export_whose_first_record_fails_writes_nothing(self):
        self.honest_twin()
        self.clear_candidate()
        process, record, kept = self.run_export('fault first record', driver=(
            FAULTS, 'first record', str(self.directory / 'marker-first-record')))
        evidence = self.evidence_directory('first record')
        self.assertEqual((process.returncode, record), (1, None), process.stderr)
        self.assertTrue(kept)
        self.assertIn('FAIL: the first evidence record could not be written durably ([Errno 28] '
                      'No space left on device), so the export stopped before it wrote anything '
                      'in this checkout', process.stderr)
        self.assertIn('evidence: no evidence record exists in %s' % evidence, process.stderr)
        self.assertEqual(list(evidence.iterdir()), [])
        self.assertFalse((self.root / SECOND_PATCHES).exists())
        self.assertFalse((self.root / SECOND_HOSTS).exists())
        self.assertEqual(git(self.root, 'status', '--porcelain', '--untracked-files=all',
                             '--ignored'), b'')

    def test_a_lost_second_name_keeps_the_final_record_and_the_whole_candidate(self):
        self.honest_twin()
        self.addCleanup(self.clear_candidate)
        whole = ('kept whole, since no failure record could be made durable in place of the '
                 'final record')
        created = list(reversed([SECOND_PATCHES, SECOND_HOSTS] + WRITTEN))
        # The directory sync just after the final record's rename fails, and the failure record's
        # second name is gone with it: once, and with no record replaceable from then on. Nothing
        # is withdrawn or rolled back, and the candidate stays whole.
        for fault in ('fallback gone once', 'fallback gone persistent'):
            with self.subTest(fault=fault):
                process, record, kept = self.fault(fault, 1)
                evidence = self.evidence_directory(fault)
                self.assertTrue(kept)
                self.assertIn('note: no failure record could be made durable in place of the '
                              'final record, so the candidate was kept whole', process.stderr)
                self.assertEqual(self.records(evidence), [export.RECORD])
                for row in self.twin['written']:
                    self.assertEqual(sha((self.root / row['path']).read_bytes()), row['sha256'])
                listed = git(self.root, 'status', '--porcelain', '--untracked-files=all')
                self.assertEqual(sorted(listed.decode().splitlines()),
                                 sorted('?? ' + name for name in WRITTEN))
                last = process.stderr.splitlines()[-1]
                if fault.endswith('once'):
                    # This run's failure record names every path as kept whole.
                    self.assertEqual((record['status'], record['phase'], record['removed']),
                                     ('FAIL', 'finishing', []))
                    self.assertEqual((record['left'], set(record['left_reasons'].values())),
                                     (created, {whole}))
                    self.assertEqual(last, 'evidence: %s says FAIL in the finishing phase'
                                     % (evidence / export.RECORD))
                else:
                    # No record can be written: the final record stays, true of the candidate.
                    self.assertEqual((record['status'], record['phase']), ('EXPORTED', 'done'))
                    self.assertIn('note: the failure record of this run could not be written '
                                  '([Errno 28] No space left on device). The candidate was kept '
                                  'whole\n', process.stderr)
                    self.assertEqual(last, 'evidence: %s says EXPORTED in the done phase'
                                     % (evidence / export.RECORD))
                self.remove_candidate()


class TerminationTests(FaultCase):

    def test_an_ordinary_termination_signal_rolls_the_export_back(self):
        self.honest_twin()
        # As the documented command runs it, under timeout, which passes a SIGTERM it receives on
        # to its process group. The signal arrives once the first candidate file is written.
        marker = self.directory / 'marker-timeout'
        self.clear_candidate()
        command, scratch = self.command('fault SIGTERM through timeout', driver=(
            FAULTS, 'SIGTERM through timeout', str(marker)))
        before = self.kept()
        process = subprocess.Popen(['timeout', '-k', '30s', '600s', *command], cwd=self.root,
                                   env=python_environment(), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 600
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=300)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM, stderr)
        self.assertIn('FAIL: terminated by SIGTERM', stderr)
        self.assertTrue((scratch / 'evidence/export.json').is_file(), 'no evidence record')
        record = json.loads((scratch / 'evidence/export.json').read_text())
        self.rolled_back(record, self.kept() == before, 'Terminated: terminated by SIGTERM')
        self.assertEqual(record['removed'], [SECOND_PATCHES + '/native-principal-pins.patch',
                                             SECOND_HOSTS, SECOND_PATCHES])
        for fault in ('SIGHUP', 'SIGINT'):
            with self.subTest(fault=fault):
                number = getattr(signal, fault)
                process, record, kept = self.fault(fault, 128 + number)
                self.rolled_back(record, kept, 'Terminated: terminated by ' + fault)

    def test_new_paths_and_the_rollback_are_never_cut_by_a_signal(self):
        self.honest_twin()
        # A signal right after the first candidate file is opened, before it is registered: the
        # export still removes that file.
        process, record, kept = self.fault('SIGTERM after open', 128 + signal.SIGTERM)
        self.rolled_back(record, kept, 'Terminated: terminated by SIGTERM')
        self.assertIn(SECOND_PATCHES + '/native-principal-pins.patch', record['removed'])
        # A second signal while the export rolls back waits for the rollback to finish.
        process, record, kept = self.fault('SIGTERM during rollback', 128 + signal.SIGTERM)
        self.rolled_back(record, kept, 'Terminated: terminated by SIGTERM')
        self.assertEqual(record['removed'], [SECOND_PATCHES + '/native-principal-pins.patch',
                                             SECOND_HOSTS, SECOND_PATCHES])


if __name__ == '__main__':
    unittest.main()
