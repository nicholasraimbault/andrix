#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write a candidate GrapheneOS base's patch set from a sealed CARRIED carry report.

export carries the selected base's six exact patches to the release that the report targets,
offline, with the carry tool's own functions. It reads the pristine files of both releases as Git
objects of an authenticated local source tree, applies each patch in private scratch as the carry
check did and requires every result to equal the sealed report. It checks the candidate's records
with each patch tool in a scratch checkout that selects the candidate, then writes the candidate's
patch directory and payload host record to new paths of this checkout. Nothing it writes selects
the candidate. The selection and every old patch, host record and upstream record keep their
bytes. The export is done only once the complete inventory of the new paths is exactly the files
it created, and its evidence record is durably published. Until then a failure, or an ordinary
termination signal, removes what it created here and still holds open as its own, once a failure
record is durably in place, and keeps that record. It never applies or reverts a patch in a source
tree, fetches, syncs or builds.

validate checks the selected base's patch set against upstream files with each patch tool's own
derivation. A scratch checkout's own copy runs it for the candidate. See grapheneos_export.md.
"""
import argparse
import contextlib
import copy
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import subprocess
import sys
import tempfile
import traceback

# This tool imports the payload host tool from beside its fixtures, and it checks that the
# directories holding them keep every entry. It writes no byte code there, even without -B.
sys.dont_write_bytecode = True

import grapheneos_base  # noqa: E402
import grapheneos_candidate as candidate  # noqa: E402
import grapheneos_carry as carry  # noqa: E402
import grapheneos_source as source  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'andrix.upstream.candidate_export/1'
REPORTS = 'upstream/reports'
HOST_TESTS = 'tests/installer-durability'
# Every entry under these directories keeps its bytes through an export, except the candidate's
# own two new directories.
OLD_ARTIFACTS = ('patches', HOST_TESTS, 'upstream')
# The classes of a carried target file. Any other needs a new reviewed patch, not an export.
CARRIED = ('identical', 'changed clean', 'moved')
# The framework patches whose profiles carry only the revision and the target file digests, in the
# order they are written. Package verity's profile comes before the host tested record naming it.
FRAMEWORK = ('native-principal-pins', 'owner-lifecycle', 'package-verity',
             'native-identity-writer')
PAYLOAD, POLICY = 'package-installer-payload-sync', 'owner-session-policy'
# Seconds each check in the scratch checkout may take.
TIMEOUTS = {'format guard': candidate.TIMEOUTS['format guard'],
            'patch set': candidate.TIMEOUTS['patch set'], 'validate': 600}
# The evidence record, in the scratch's evidence directory, and the second name its failure
# record keeps while the final record is published. A reader takes RECORD, or FALLBACK if RECORD
# is absent.
RECORD, FALLBACK = 'export.json', 'export.fail.json'
# Directories are opened one component at a time, never through a link, and new files are created
# exclusively, never through a link either.
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# The ordinary termination signals: timeout's, a terminal's interrupt and a hangup.
TERMINATION = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
# What the evidence record says while the export runs, so a run that never finishes leaves a
# failure record behind.
UNFINISHED = {
    'checks': 'the export stopped before it wrote anything in the checkout',
    'writing': 'the export did not finish writing, checking and recording the candidate. The '
               'files listed in staged may remain, in part or whole, after SIGKILL or power loss '
               'and when no failure record could be made durable before a rollback. Otherwise it '
               'removed what it created and still held as its own, and kept anything else. The '
               'next export refuses until they are removed'}


class ExportError(Exception):
    """An input is refused or a result differs. Nothing past it is written."""


class Terminated(BaseException):
    """An ordinary termination signal, raised so that the export rolls back what it wrote."""

    def __init__(self, number):
        super().__init__('terminated by ' + signal.Signals(number).name)
        self.number = number


def terminate(number, frame):
    """The handler: block the ordinary termination signals, then raise. The rollback that follows
    runs with them blocked, so no second signal can cut it."""
    signal.pthread_sigmask(signal.SIG_BLOCK, TERMINATION)
    raise Terminated(number)


@contextlib.contextmanager
def terminable():
    """While the export runs, the ordinary termination signals are blocked, and they raise
    Terminated only where interruptible() lets them through. A signal ignored on entry, as under
    nohup, stays ignored. Afterwards a signal still pending is discarded, since the export has
    either finished or recorded its failure, and the handlers and mask return."""
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, TERMINATION)
    handlers = {number: signal.signal(number, terminate) for number in TERMINATION
                if signal.getsignal(number) is not signal.SIG_IGN}
    try:
        yield
    finally:
        while signal.sigtimedwait(TERMINATION, 0) is not None:
            pass
        for number, handler in handlers.items():
            signal.signal(number, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)


@contextlib.contextmanager
def interruptible():
    """The ordinary termination signals reach the handler while the block runs: during the
    checks and their subprocesses, and between the files the export writes. Elsewhere they wait,
    so creating and registering a new file, the final record and the rollback are never cut in
    two, and no subprocess starts with them blocked."""
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, TERMINATION)
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(cwd, *args):
    return source.run(cwd, *args)[1].decode().strip()


def relative(path):
    return Path(path).relative_to(ROOT).as_posix()


def regular(path, what):
    """The bytes of a regular file that is not a link."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ExportError('the %s is missing or not a regular file: %s' % (what, path))
    return path.read_bytes()


def render(value):
    """A record as the patch directories hold them: JSON indented by two spaces, then a newline."""
    return (json.dumps(value, indent=2) + '\n').encode()


def host_tool():
    """The payload companion's host tested record tool, which lives beside its fixtures."""
    directory = str(ROOT / HOST_TESTS)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import pis_reverse_write_sync
    return pis_reverse_write_sync


# ---------------------------------------------------------------- the sealed report and records

def sealed(path, base):
    """(report, base record, target record) of the selected base's sealed carry report. Its seal
    verifies and nothing it names has drifted, its verdict is CARRIED, the carry tool here is the
    one that wrote it, and it names both records by their digests."""
    path = Path(path).absolute()
    if (path.is_symlink() or not path.is_file()
            or path.resolve().parent != (ROOT / REPORTS).resolve()):
        raise ExportError('not a sealed report in %s of this checkout: %s' % (REPORTS, path))
    report, drift = carry.verify_report(path)
    if drift:
        raise ExportError('the sealed report has drift: ' + '; '.join(drift))
    if report.get('verdict') != 'CARRIED':
        raise ExportError('the sealed report is %s, not CARRIED' % report.get('verdict'))
    if report.get('not_run'):
        raise ExportError('the sealed report has checks not run: ' + '; '.join(report['not_run']))
    if report['generated']['tool_sha256'] != sha(Path(carry.__file__).read_bytes()):
        raise ExportError('the carry tool here is not the one that sealed the report')
    first, second = report['base'], report['target']
    if path.name != '%s-%s.json' % (first['release'], second['release']):
        raise ExportError('the report file does not name its base and target: ' + path.name)
    if (first['release'], first['record'], first['record_sha256']) != (
            base.release, base.record, base.record_sha256):
        raise ExportError('the report is of base %s, not of the selected base %s'
                          % (first['release'], base.release))
    if 'record' not in second or second['release'] == base.release:
        raise ExportError('the report names no record of another release')
    records = []
    for side in (first, second):
        record = carry.load_record(ROOT / side['record'])
        if record['release'] != side['release'] or sha(carry.dump(record)) != side['record_sha256']:
            raise ExportError('the record %s differs from the report' % side['record'])
        records.append(record)
    target, manifest = records[1], records[1]['manifest']
    if ((second['tag_object'], second['manifest_commit'], second['manifest_sha256'])
            != (manifest['tag_object'], manifest['commit'], manifest['sha256'])
            or set(target['patched_projects']) != set(records[0]['patched_projects'])):
        raise ExportError('the target record differs from the report')
    return report, records[0], target


def specifications(base, record, report):
    """The selected base's six exact patches from the carry tool's own loader, which validates
    every profile with its own tool, in the report's order, each at the base record's revision of
    its project."""
    specs = carry.load_patch_set(base.release)
    names = [spec['name'] for spec in specs]
    if names != list(candidate.PATCH_NAMES) or names != [row['name'] for row in report['patches']]:
        raise ExportError('the patch set and the report name other patches: %s' % names)
    for spec in specs:
        if (spec['head'] != record['patched_projects'][spec['project']]['revision']
                or spec['patch'] != base.patches / (spec['name'] + '.patch')
                or spec['profile'] != base.patches / (spec['name'] + '.json')):
            raise ExportError('the patch set disagrees with the base record: ' + spec['name'])
    return specs


# ---------------------------------------------------------------- the authenticated source tree

def verified_source(directory, record):
    """The target tree's complete source verification, which must come first: the result.json
    that grapheneos_source.py wrote when a scratch checkout selecting the target ran it. It passes
    for the target's signed manifest and every declared project, the patched projects at the
    record's revisions."""
    path = Path(directory) / 'result.json'
    data = regular(path, 'source verification result')
    result = carry.load_json(path)
    if not isinstance(result, dict):
        raise ExportError('the source verification result is not a JSON object: %s' % path)
    manifest, count = record['manifest'], record['projects']['count']
    wanted = {'verdict': 'PASS_PINNED_SOURCE_HEADS', 'release': record['release'],
              'manifest_commit': manifest['commit'], 'manifest_tag': manifest['tag_object'],
              'manifest_sha256': manifest['sha256']}
    differing = [key for key, value in wanted.items() if result.get(key) != value]
    if result.get('tag_signature_verified') is not True:
        differing.append('tag_signature_verified')
    for key in ('declared_projects', 'verified_projects'):
        if type(result.get(key)) is not int or result[key] != count:
            differing.append(key)
    projects = result.get('projects')
    rows = {row.get('path'): row for row in projects if isinstance(row, dict)} \
        if isinstance(projects, list) else {}
    if not isinstance(projects, list) or len(projects) != count or len(rows) != count:
        differing.append('projects')
    for project, row in sorted(record['patched_projects'].items()):
        found = rows.get(project, {})
        if (found.get('verdict'), found.get('revision'), found.get('head')) != (
                'PASS', row['revision'], row['revision']):
            differing.append('project ' + project)
    if differing:
        raise ExportError('the source verification %s does not pass for %s: %s'
                          % (path, record['release'], ', '.join(differing)))
    return {'result': str(path), 'sha256': sha(data), 'repo_commit': result.get('repo_commit'),
            'declared_projects': count, 'verified_projects': count}


def project_root(root, project):
    """A project of a source tree: its own Git worktree inside the tree, not a link."""
    path = root / source.relative(project)
    if path.is_symlink() or not path.resolve().is_relative_to(root) or not (path / '.git').exists():
        raise ExportError('%s is missing from %s or not contained in it' % (project, root))
    if Path(git(path, 'rev-parse', '--show-toplevel')).resolve() != path.resolve():
        raise ExportError('%s of %s is not its own Git worktree' % (project, root))
    return path.resolve()


def authenticate(root, record, signers):
    """The target's source tree, read only, as grapheneos_source.inspect checks its manifest and
    projects, with the target's record: the manifest bytes, commit, tag object and tag target are
    the record's, the tag signature verifies with the approved allowed signers, and each patched
    project is a Git worktree at the record's revision without tracked changes."""
    root = Path(root).resolve(strict=True)
    release, manifest = record['release'], record['manifest']
    repository = root / '.repo/manifests'
    try:
        if sha(regular(repository / manifest['path'], 'manifest')) != manifest['sha256']:
            raise ExportError('the source tree manifest is not the signed manifest of ' + release)
        for name, wanted in (('HEAD', manifest['commit']),
                             ('refs/tags/' + release, manifest['tag_object']),
                             ('refs/tags/%s^{commit}' % release, manifest['commit']),
                             ('HEAD:' + manifest['path'], manifest['blob'])):
            if git(repository, 'rev-parse', '--verify', '--end-of-options', name) != wanted:
                raise ExportError('the source tree manifest %s is not the record of %s'
                                  % (name, release))
        # Its temporary files, and those of the tag check below, stay outside the whole tree.
        source.check_tracked_clean(repository, root)
    except source.SourceError as error:
        raise ExportError('the source tree manifest is not verified: %s' % error) from error
    signers = carry.check_signers(signers)
    try:
        source.run(repository, *source.VERIFY_PINS,
                   '-c', 'gpg.ssh.allowedSignersFile=' + str(signers), 'verify-tag', release)
    except source.SourceError as error:
        raise ExportError('the manifest tag %s does not verify: %s' % (release, error)) from error
    for project, row in sorted(record['patched_projects'].items()):
        path = project_root(root, project)
        try:
            if git(path, 'rev-parse', 'HEAD') != row['revision']:
                raise ExportError('%s of the source tree is not at the %s revision %s'
                                  % (project, release, row['revision']))
            source.check_tracked_clean(path, root)
        except source.SourceError as error:
            raise ExportError('%s of the source tree is not verified: %s'
                              % (project, error)) from error
    return root


def blobs(project, revision, paths, where):
    """{path: (blob, bytes), or None if absent} at one commit, read from the project's own Git
    objects alone. The commit and every object must be there. Nothing is fetched."""
    try:
        if git(project, 'cat-file', '-t', revision) != 'commit':
            raise ExportError('%s is not a commit in %s' % (revision, where))
        algorithm = git(project, 'rev-parse', '--show-object-format')
    except source.SourceError as error:
        raise ExportError('the commit %s is not in the Git objects of %s, and nothing is fetched'
                          % (revision, where)) from error
    found = {}
    for path in paths:
        try:
            listing = source.run(project, '--literal-pathspecs', 'ls-tree', '--full-tree', '-z',
                                 revision, '--', path)[1]
            entries = [entry for entry in listing.split(b'\0') if entry]
            if not entries:
                found[path] = None
                continue
            meta, _, name = entries[0].partition(b'\t')
            mode, kind, blob = meta.decode().split()
            if (len(entries) != 1 or name.decode() != path or kind != 'blob'
                    or mode not in ('100644', '100755')):
                raise ExportError('%s at %s in %s is not a regular file' % (path, revision, where))
            data = source.run(project, 'show', revision + ':' + path)[1]
        except source.SourceError as error:
            raise ExportError('an object of %s at %s is missing from the Git objects of %s, and '
                              'nothing is fetched' % (path, revision, where)) from error
        if hashlib.new(algorithm, b'blob %d\0' % len(data) + data).hexdigest() != blob:
            raise ExportError('%s at %s in %s does not read as its blob' % (path, revision, where))
        found[path] = (blob, data)
    return found


def upstream_files(specs, report, records, roots):
    """Both releases' pristine files of every patch target and added path, and the FileUtils.java
    that the payload host tested record names, from each project's Git objects at the record's
    revision: {(side, project): {path: (blob, bytes) or None}}. Each is the file the sealed report
    carried: a target by its SHA-256 at both releases, an added path absent at both and
    FileUtils.java by the objects the report's surface watched."""
    import package_verity as verity
    host = host_tool()
    paths = {}
    for spec in specs:
        paths.setdefault(spec['project'], set()).update(row['path'] for row in spec['files'])
        paths[spec['project']].update(spec['added'])
    paths[verity.PROJECT].add(host.FILEUTILS)
    files = {}
    for side in ('base', 'target'):
        for project in sorted(paths):
            directory = project_root(roots[side], project)
            files[(side, project)] = blobs(
                directory, records[side]['patched_projects'][project]['revision'],
                sorted(paths[project]), '%s of %s' % (project, roots[side]))
    for spec, row in zip(specs, report['patches']):
        for path in spec['added']:
            for side in ('base', 'target'):
                if files[(side, spec['project'])][path] is not None:
                    raise ExportError('the added path %s exists upstream at %s'
                                      % (path, records[side]['release']))
        if spec['after'] is not None:
            continue  # an ordered companion starts from the outputs of the patch it follows
        for entry in row['files']:
            for side, key in (('base', 'base_sha256'), ('target', 'target_sha256')):
                found = files[(side, spec['project'])][entry['path']]
                if found is None or sha(found[1]) != entry[key]:
                    raise ExportError('the %s file %s of %s is not the one the sealed report '
                                      'carried' % (records[side]['release'], entry['path'],
                                                   spec['project']))
    watched = [row for row in report['surface']
               if row.get('project') == verity.PROJECT and row.get('path') == host.FILEUTILS]
    if len(watched) != 1:
        raise ExportError('the sealed report does not watch ' + host.FILEUTILS)
    for side, key in (('base', 'base_object'), ('target', 'target_object')):
        found = files[(side, verity.PROJECT)][host.FILEUTILS]
        if found is None or found[0] != watched[0][key]:
            raise ExportError('host drift: %s at %s is not the object the sealed report watched'
                              % (host.FILEUTILS, records[side]['release']))
    return files


# ---------------------------------------------------------------- carrying the exact patches

def carry_rows(specs, files, workdir):
    """Each exact patch through grapheneos_carry.carry_patch, as its run_check carries it: the
    positive control on the base, then the target, an ordered companion from the outputs of the
    patch it follows, and every added path absent upstream. (rows, {name: (base, target)})."""
    rows, outputs = [], {}
    for spec in specs:
        project = spec['project']
        base_in = {row['path']: files[('base', project)][row['path']][1] for row in spec['files']}
        target_in = {row['path']: files[('target', project)][row['path']][1]
                     for row in spec['files']}
        if spec['after']:
            prior_base, prior_target = outputs[spec['after']]
            if prior_target is None:
                raise ExportError('%s requires %s, which does not apply'
                                  % (spec['name'], spec['after']))
            base_in = {path: prior_base[path] for path in base_in}
            target_in = {path: prior_target[path] for path in target_in}
        row, base_out, target_out = carry.carry_patch(spec, base_in, target_in, workdir)
        outputs[spec['name']] = (base_out, target_out)
        for path in spec['added']:
            present = files[('target', project)][path] is not None
            row.setdefault('added', []).append({'path': path,
                                                'upstream': 'exists' if present else 'absent'})
            if present:
                row['class'] = 'conflict'
        rows.append(row)
    return rows, outputs


def compare(rows, report):
    """Every carried row equals the sealed report's, without its upstream commits, which come
    from history this offline tool does not read: the same patch and profile bytes, classes, line
    offsets, checks, added paths and candidate digests. Every patch applies at fuzz 0, every
    target is identical, changed clean or moved, every check passes, and the policy review patch
    agrees with the bridge at both releases."""
    for row, sealed_row in zip(rows, report['patches']):
        wanted = copy.deepcopy(sealed_row)
        for entry in wanted['files']:
            entry.pop('upstream_commits', None)
        if row != wanted:
            differing = sorted(key for key in set(row) | set(wanted)
                               if row.get(key) != wanted.get(key))
            files = [entry['path'] for entry, other in zip(row['files'], wanted['files'])
                     if entry != other]
            raise ExportError('%s carries otherwise than the sealed report: %s%s'
                              % (row['name'], ', '.join(differing),
                                 (' (' + ', '.join(files) + ')') if files else ''))
        classes = {entry['class'] for entry in row['files']} | {row['class']}
        reasons = sorted(classes - set(CARRIED)) + [
            'check ' + check['name'] for check in row['checks'] if check['result'] != 'pass']
        if not row['applies']:
            reasons.append('does not apply')
        reasons += ['%s exists upstream' % item['path'] for item in row.get('added', [])
                    if item['upstream'] != 'absent']
        if reasons:
            raise ExportError('%s is not carried, so it needs a new reviewed patch: %s'
                              % (row['name'], ', '.join(reasons)))
        for entry in row['files']:
            if 'review_record' in entry and (entry['review_record'],
                                             entry['review_record_at_base']) != ('agrees',
                                                                                 'agrees'):
                raise ExportError('policy disagreement: the review patch of %s does not agree '
                                  'with its bridge' % row['name'])


# ---------------------------------------------------------------- the candidate's records

def digest_pair(value, path):
    """The object in a framework profile that holds one target file's upstream and candidate
    digests."""
    if isinstance(value.get('files'), list):
        found = [row for row in value['files'] if row.get('path') == path]
    elif isinstance(value.get('file'), dict):
        found = [value['file']] if value['file'].get('path') == path else []
    else:
        found = [value] if value.get('file') == path else []
    if len(found) != 1:
        raise ExportError('the profile names no digests of ' + path)
    return found[0]


def shared(value):
    """Every producer file a record names by its source path still has the digest it names."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if 'source' in item and 'sha256' in item:
                path = ROOT / source.relative(item['source'])
                if sha(regular(path, 'shared source')) != item['sha256']:
                    raise ExportError('a shared source differs from its record: ' + item['source'])
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def carried_profile(spec, row, revision):
    """The target's profile of one framework patch: the selected base's profile with the target's
    revision of its project and each target file's actual upstream and candidate digests. Its
    patch, helpers, fixtures and fragments stay the selected base's, by the digests it names."""
    value = carry.load_json(spec['profile'])
    if value['patch_sha256'] != sha(spec['patch'].read_bytes()):
        raise ExportError('the profile of %s names another patch' % spec['name'])
    value['head'] = revision
    for entry in row['files']:
        pair = digest_pair(value, entry['path'])
        if (pair['upstream_sha256'], pair['candidate_sha256']) != (
                entry['base_sha256'], entry['pinned_candidate_sha256']):
            raise ExportError('the profile of %s disagrees with its report row: %s'
                              % (spec['name'], entry['path']))
        pair['upstream_sha256'] = entry['target_sha256']
        pair['candidate_sha256'] = entry['candidate_sha256']
    shared(value)
    return value


def host_record(old, files, outputs, revision, verity_path, verity_digest):
    """The target's own payload host tested record: the selected base's record naming the target's
    revision, the target's package verity profile by path and digest, and the target's actual
    upstream, package verity and combined Package Installer digests and FileUtils.java digest. The
    host patch and fragments it names stay shared, so the tested source ranges must hold in the
    target's bytes as they did in the base's."""
    import package_verity as verity
    host = host_tool()
    pis = files[('target', verity.PROJECT)][verity.FILE][1]
    verity_out = outputs['package-verity'][1][verity.FILE]
    combined = outputs[PAYLOAD][1][verity.FILE]
    base_fileutils = files[('base', verity.PROJECT)][host.FILEUTILS][1]
    fileutils = files[('target', verity.PROJECT)][host.FILEUTILS][1]
    shared_digests = {'patch_sha256': host.PATCH, 'base_fragment_sha256': host.BASE_FRAGMENT,
                      'candidate_fragment_sha256': host.CANDIDATE_FRAGMENT,
                      'fileutils_sync_fragment_sha256': host.SYNC_FRAGMENT}
    problems = [key for key, path in shared_digests.items()
                if old.get(key) != sha(path.read_bytes())]
    if (set(old) != host.KEYS or old['status'] != 'candidate' or old['integrated'] is not False
            or old['file'] != verity.FILE or old['fileutils_file'] != host.FILEUTILS):
        problems.append('record form')
    if sha(base_fileutils) != old['fileutils_sha256']:
        problems.append('the base %s' % host.FILEUTILS)
    for name, data, fragment, extract in (
            (host.FILEUTILS, fileutils, host.SYNC_FRAGMENT, host.sync_fragment),
            ('upstream ' + verity.FILE, pis, host.BASE_FRAGMENT, host.pis_fragment),
            ('combined ' + verity.FILE, combined, host.CANDIDATE_FRAGMENT, host.pis_fragment)):
        try:
            if extract(data) != fragment.read_bytes():
                problems.append(name)
        except (ValueError, UnicodeDecodeError):
            problems.append(name)
    if problems:
        raise ExportError('host drift: the tested source no longer holds in %s'
                          % ', '.join(problems))
    value = copy.deepcopy(old)
    value.update(head=revision, base_profile=verity_path, base_profile_sha256=verity_digest,
                 upstream_sha256=sha(pis), base_sha256=sha(verity_out),
                 candidate_sha256=sha(combined), fileutils_sha256=sha(fileutils))
    return value


def payload_profile(spec, files, outputs, revision, verity_path, verity_digest, host_path,
                    host_digest):
    """The target's payload sync profile: the selected base's, naming the target's revision, its
    package verity profile and its own host tested record by path and digest, and the target's
    upstream, package verity and combined digests. Its patch stays the shared host tested patch."""
    import package_installer_payload_sync as payload
    value = carry.load_json(spec['profile'])
    patch = spec['patch'].read_bytes()
    if (set(value) != payload.KEYS or value['patch_sha256'] != sha(patch)
            or payload.HOST_PATCH.read_bytes() != patch
            or value['host_patch'] != relative(payload.HOST_PATCH)
            or value['host_base_fragment_sha256'] != sha(payload.HOST_BASE_FRAGMENT.read_bytes())
            or value['host_fragment_sha256'] != sha(payload.HOST_FRAGMENT.read_bytes())):
        raise ExportError('host drift: the payload sync profile no longer names its shared host '
                          'patch and fragments')
    pis = files[('target', payload.PROJECT)][payload.FILE][1]
    value.update(head=revision, requires=verity_path, requires_sha256=verity_digest,
                 upstream_sha256=sha(pis),
                 base_sha256=sha(outputs['package-verity'][1][payload.FILE]),
                 candidate_sha256=sha(outputs[PAYLOAD][1][payload.FILE]), host_profile=host_path,
                 host_profile_sha256=host_digest)
    return value


def policy_record(spec, files, outputs, release, revision, workdir):
    """The target's owner session policy record: the selected base's, naming the target release,
    its system/sepolicy revision and the four actual upstream and bridge digests. All four files
    must be those owner_policy.py pins, and the review patch beside them must reproduce the bridge
    that grapheneos_carry.policy_bridge and owner_policy.patched both derive."""
    import owner_policy as policy
    originals = {path: files[('target', policy.PROJECT)][path][1] for path in policy.FILES}
    bridges = outputs[POLICY][1]
    if any(sha(originals[path]) != policy.BEFORE[path] for path in policy.FILES):
        raise ExportError('policy disagreement: one of the four files at %s is not the upstream '
                          'file that owner_policy.py pins. The bridge needs a reviewed change of '
                          'that tool, not a new digest' % release)
    mirror, _ = carry.policy_bridge(originals)
    _, _, reviewed = carry.apply_patch(spec['patch'], originals, workdir)
    if mirror != bridges or policy.patched(originals) != bridges or reviewed != bridges:
        raise ExportError('policy disagreement: the review patch does not reproduce the bridge '
                          'at ' + release)
    value = carry.load_json(spec['profile'])
    try:
        policy.profile_files(value)
    except ValueError as error:
        raise ExportError('policy disagreement: the policy record no longer names four files') from error
    pinned_rows = [dict(path=path, upstream_sha256=sha(originals[path]),
                        candidate_sha256=sha(bridges[path])) for path in policy.FILES]
    if value['files'] != pinned_rows:
        raise ExportError('policy disagreement: the policy record names other bridge bytes')
    if (value['project'] != policy.PROJECT or value['patch'] != spec['patch'].name
            or value['patch_sha256'] != sha(spec['patch'].read_bytes())
            or value['public_policy_api_changed'] is not False
            or value['existing_domain_grants_changed'] is not False):
        raise ExportError('policy disagreement: the policy record no longer names its review '
                          'patch and scope')
    value.update(base_release=release, head=revision, files=pinned_rows)
    return value


README = '''# GrapheneOS {target} candidate patches

These are Andrix's six patches, carried from the selected base, {base}, to GrapheneOS
{target}. They are a candidate. `upstream/selected-base.json` still selects {base}, and no
production tool reads this directory until a reviewed change selects {target}.

## Provenance

`scripts/proof/grapheneos_export.py` wrote this directory from a sealed carry report:

- report: `{report}`, verdict `CARRIED`
- seal: `{seal}`
{revisions}

Every patch here is the {base} patch byte for byte. Each was applied at fuzz 0 with the carry
tool's own functions to the pristine files of both releases, read as Git objects of a local source
tree authenticated against the signed {target} manifest, and every result equals the sealed
report. The profiles name the revisions above and the actual upstream and candidate digests.

Of the {count} upstream files the patches change, {identical} are identical at {target}.{changed}

The payload sync companion's host tested record is this base's own:
`{host}`.
Its patch and source fragments are shared with {base}.

## Lab only

`native-identity-writer.*` is carried as checked lab test source only. A normal image does not
apply it, and its lab admission rules are unchanged.

## Owner policy bridge

`owner-session-policy.*` is the same digest guarded private bridge, recorded for the {target}
revision of `system/sepolicy` above. Its four upstream private policy files are those that
`scripts/proof/owner_policy.py` pins, byte for byte, and the zero context review patch reproduces
the bridge there. It adds no public policy API and changes no existing domain's grants.

## Qualification

Source only. The candidate's source gate is `scripts/proof/grapheneos_candidate.py check` in a
scratch checkout that selects {target}. No build, boot, runtime or security result follows from
this directory, and no Android result of {base} carries over to it.
'''


def readme(specs, rows, report, target, host_path):
    """The candidate's README: carried provenance, the exact base, the lab only writer and the
    source only qualification."""
    worst = {}
    for spec, row in zip(specs, rows):
        if spec['after'] is not None:
            continue  # its file is the output of the patch it follows, not an upstream file
        for entry in row['files']:
            key = (spec['project'], entry['path'])
            worst[key] = carry.worst([worst.get(key, 'identical'), entry['class']])
    changed = [(path, kind) for (_, path), kind in worst.items() if kind != 'identical']
    lines = ''.join('\n- `%s`: %s' % (path, 'moved, at line offsets' if kind == 'moved' else kind)
                    for path, kind in changed)
    if changed:
        lines = '\nThese changed upstream, and the patches still apply at fuzz 0:\n' + lines
    revisions = '\n'.join('- `%s`: `%s`' % (project, row['revision'])
                          for project, row in sorted(target['patched_projects'].items()))
    text = README.format(target=target['release'], base=report['base']['release'],
                         report='%s/%s-%s.json' % (REPORTS, report['base']['release'],
                                                   target['release']),
                         seal=report['seal']['sha256'], revisions=revisions, count=len(worst),
                         identical=sum(1 for kind in worst.values() if kind == 'identical'),
                         changed=lines, host=host_path)
    return text.encode()


def stage(specs, rows, outputs, files, report, target, workdir):
    """The candidate's files in their dependency order: [(path, bytes)]. First the framework
    patches and their profiles, package verity's among them, then the host tested record that
    names package verity's profile, the payload sync patch and the profile that names that record,
    the policy review patch and record, and the README."""
    import package_installer_payload_sync as payload
    import package_verity as verity
    release = target['release']
    directory = 'patches/grapheneos-' + release
    host_path = payload.host_record(release)
    if PurePosixPath(host_path).parent.as_posix() != '%s/grapheneos-%s' % (HOST_TESTS, release):
        raise ExportError('the host tested record of %s is not keyed by its release' % release)
    revisions = {project: row['revision'] for project, row in target['patched_projects'].items()}
    found = {spec['name']: (spec, row) for spec, row in zip(specs, rows)}
    staged, profiles = [], {}
    for name in FRAMEWORK:
        spec, row = found[name]
        value = carried_profile(spec, row, revisions[spec['project']])
        if name == 'package-verity' and (
                value['method_fixture_sha256'] != sha(verity.EXTRACTED.read_bytes())
                or value['upstream_method_sha256'] != sha(verity.UPSTREAM_METHOD.read_bytes())):
            raise ExportError('a package verity method fixture differs from its profile')
        profiles[name] = render(value)
        staged += [(directory + '/' + spec['patch'].name, spec['patch'].read_bytes()),
                   (directory + '/' + spec['profile'].name, profiles[name])]
    verity_path = directory + '/package-verity.json'
    verity_digest = sha(profiles['package-verity'])
    record = render(host_record(carry.load_json(payload.HOST_PROFILE), files, outputs,
                                revisions[verity.PROJECT], verity_path, verity_digest))
    staged.append((host_path, record))
    spec, _ = found[PAYLOAD]
    value = payload_profile(spec, files, outputs, revisions[payload.PROJECT], verity_path,
                            verity_digest, host_path, sha(record))
    staged += [(directory + '/' + spec['patch'].name, spec['patch'].read_bytes()),
               (directory + '/' + spec['profile'].name, render(value))]
    spec, _ = found[POLICY]
    value = policy_record(spec, files, outputs, release, revisions[spec['project']], workdir)
    staged += [(directory + '/' + spec['patch'].name, spec['patch'].read_bytes()),
               (directory + '/' + spec['profile'].name, render(value))]
    staged.append((directory + '/README.md', readme(specs, rows, report, target, host_path)))
    names = [name for name, _ in staged]
    expected = {directory + '/' + stem + suffix for stem in candidate.PATCH_NAMES
                for suffix in ('.json', '.patch')} | {directory + '/README.md', host_path}
    if len(names) != len(set(names)) or set(names) != expected:
        raise ExportError('the candidate is not exactly its patch directory and host record')
    return staged


# ---------------------------------------------------------------- checks in a scratch checkout

def run_tool(name, command, tree, evidence):
    """One check by the scratch checkout's own copy of its tool, with its output kept in evidence:
    its JSON report, which it must print with exit status 0."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in candidate.DROPPED_ENVIRONMENT}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    try:
        process = subprocess.run(command, cwd=tree, env=environment, stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=TIMEOUTS[name])
    except subprocess.TimeoutExpired as error:
        raise ExportError('the %s check gave no result within %d seconds'
                          % (name, TIMEOUTS[name])) from error
    stem = name.replace(' ', '-')
    (evidence / (stem + '.out')).write_bytes(process.stdout)
    (evidence / (stem + '.err')).write_bytes(process.stderr)
    try:
        value = json.loads(process.stdout)
    except ValueError:
        value = None
    if process.returncode == 0 and isinstance(value, dict):
        return value
    reason = next((value[key] for key in ('format_guard', 'patch_set', 'validate')
                   if isinstance(value, dict) and value.get(key) not in (None, 'PASS')), None)
    if reason is None:
        lines = [line for line in process.stderr.decode(errors='replace').splitlines()
                 if line.strip()]
        reason = lines[-1] if lines else 'exit status %d' % process.returncode
    elif isinstance(reason, list):
        reason = '; '.join(str(item) for item in reason)
    raise ExportError('the %s check refuses the candidate: %s' % (name, reason))


def check_export(scratch, staged, rows, target, inputs, revision):
    """The candidate checked by its own tools in a scratch checkout of this checkout's revision
    that holds the staged files and selects the candidate: the production format guard, the exact
    patch set check and validate, each run by the checkout's own copy. Their results must name
    exactly the staged records and the carried digests."""
    import package_installer_payload_sync as payload
    release = target['release']
    directory = scratch / 'export'
    directory.mkdir(mode=0o700)
    tree, commit = candidate.checkout(directory, revision)
    if commit != revision:
        raise ExportError('the scratch checkout is not of the revision %s' % revision)
    for name, data in staged:
        path = tree / name
        if path.exists() or path.is_symlink():
            raise ExportError('the scratch checkout of this revision already holds ' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if candidate.select(tree, release).release != release:
        raise ExportError('the scratch checkout does not select ' + release)
    evidence = scratch / 'evidence'
    python = [sys.executable, '-B']
    tools = tree / candidate.TOOLS
    results = {name: run_tool(name, command, tree, evidence) for name, command in (
        ('format guard', python + [str(tools / 'native_creation_binding.py'),
                                   '--format-guard-only']),
        ('patch set', python + [str(tools / 'grapheneos_candidate.py'), 'patch-set']),
        ('validate', python + [str(tools / 'grapheneos_export.py'), 'validate', '--inputs',
                               str(inputs)]))}
    written = dict(staged)
    directory_name = 'patches/grapheneos-' + release
    host_path = payload.host_record(release)
    guard, patch_set, validated = (results[key] for key in ('format guard', 'patch set',
                                                            'validate'))
    policy = json.loads(written[directory_name + '/' + POLICY + '.json'])
    problems = []
    if (guard.get('base'), guard.get('production_patches'), guard.get('format_guard')) != (
            release, directory_name, 'PASS'):
        problems.append('format guard')
    if ((patch_set.get('base'), patch_set.get('patch_set'), patch_set.get('patches'))
            != (release, 'PASS', list(candidate.PATCH_NAMES))
            or patch_set.get('policy') != {key: policy[key] for key in (
                'files', 'patch_sha256')}
            or patch_set.get('host_record') != {'path': host_path,
                                                'sha256': sha(written[host_path])}):
        problems.append('patch set')
    derived = validated.get('patches', {})
    for row in rows:
        found = derived.get(row['name'], {})
        if (found.get('profile_sha256') != sha(written[directory_name + '/' + row['name']
                                                       + '.json'])
                or found.get('files') != {entry['path']: [entry['target_sha256'],
                                                          entry['candidate_sha256']]
                                          for entry in row['files']}):
            problems.append('validate ' + row['name'])
    if (validated.get('base'), validated.get('validate')) != (release, 'PASS') or validated.get(
            'host_record') != {'path': host_path, 'sha256': sha(written[host_path]),
                               'states': ['BASE', 'CANDIDATE'],
                               'fileutils_sha256': json.loads(written[host_path])[
                                   'fileutils_sha256']}:
        problems.append('validate host tested record')
    if problems:
        raise ExportError('the scratch checkout reads other records than the staged ones: '
                          + ', '.join(problems))
    return {'checkout': str(tree), 'revision': commit,
            'selection_sha256': sha((tree / grapheneos_base.SELECTION).read_bytes()),
            'checks': {name: {key: value for key, value in result.items()
                              if key in ('base', 'production_patches', 'format_guard',
                                         'patches', 'patch_set', 'validate', 'host_record',
                                         'policy')}
                       for name, result in results.items()}}


# ---------------------------------------------------------------- writing new paths only

def snapshot(excluded):
    """Every entry under the old artifact directories but the excluded ones, by its path: a file's
    SHA-256, a link's target or the kind of any other entry."""
    found = {}
    for top in OLD_ARTIFACTS:
        for path in sorted((ROOT / top).rglob('*')):
            name = relative(path)
            if any(name == item or name.startswith(item + '/') for item in excluded):
                continue
            if path.is_symlink():
                found[name] = 'link to ' + os.readlink(path)
            elif path.is_file():
                found[name] = sha(path.read_bytes())
            else:
                found[name] = 'directory' if path.is_dir() else 'other'
    return found


def unchanged(before, after, when):
    differing = sorted(name for name in set(before) | set(after)
                       if before.get(name) != after.get(name))
    if differing:
        raise ExportError('an old artifact changed %s: %s' % (when, ', '.join(differing[:8])))


def status():
    """This checkout's changes as Git reports them, untracked files one by one: [(code, path)]."""
    out = source.run(ROOT, 'status', '--porcelain=v1', '-z', '--untracked-files=all')[1]
    return [(entry[:2], entry[3:]) for entry in out.decode().split('\0') if entry]


class Moved(Exception):
    """A directory on the way is a link, is gone, or is another object than the one this export
    reached or created there."""


def split(path):
    """(parent, name) of a path relative to the checkout's root, the root being ''."""
    path = PurePosixPath(path)
    return ('' if path.parent == PurePosixPath('.') else path.parent.as_posix()), path.name


def identity(info):
    return info.st_dev, info.st_ino


def same_object(held, info):
    """Whether info, the stat of an object some path names, is of the object held open whose
    fstat is held: the same device, inode and type, while the held object is still linked. An
    object held open keeps its inode, so no object made meanwhile can have its identity."""
    return (held.st_nlink > 0 and identity(held) == identity(info)
            and stat.S_IFMT(held.st_mode) == stat.S_IFMT(info.st_mode))


def read_regular(descriptor, name):
    """(stat, bytes) of the regular file name in an open directory, opened without following a
    link or blocking on a pipe, or None if it is not a regular file."""
    with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=descriptor), 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return None
        return info, handle.read()


class NewFiles:
    """The directories and files this export creates in the checkout. Each is held open from the
    moment it is created, and so is every directory on the way from the moment this export first
    reaches it, until the export is done or its rollback complete. An object held open keeps its
    inode, so an object made later, even once the held one was removed, never has its identity.
    Every directory on the way is opened from the checkout's root one component at a time, never
    through a link, and must still be the object held for it. The export uses this with the
    termination signals blocked, so no signal falls between creating a path and holding it."""

    def __init__(self):
        self.held = {}
        self.created = []

    def hold(self, path, descriptor):
        """Hold the object open at descriptor as the one at path, until close()."""
        self.held[path] = descriptor

    def holds(self, path, info):
        """Whether info is of the object held for path (see same_object)."""
        held = self.held.get(path)
        return held is not None and same_object(os.fstat(held), info)

    def close(self):
        """Release every held object, once the export is done or its rollback complete."""
        while self.held:
            os.close(self.held.popitem()[1])

    def reach(self, path):
        """A descriptor of the directory at path below the root. Raises Moved when a component is
        a link, is gone, or is not the object held for it. A directory reached for the first time
        is held from then on."""
        parts = PurePosixPath(path).parts if path else ()
        try:
            descriptor = os.open(ROOT, DIRECTORY_FLAGS)
        except OSError as error:
            raise Moved('the checkout root: ' + error.strerror) from error
        try:
            self.verify('', descriptor)
            for index, part in enumerate(parts):
                name = '/'.join(parts[:index + 1])
                try:
                    child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as error:
                    raise Moved('%s: %s' % (name, error.strerror)) from error
                os.close(descriptor)
                descriptor = child
                self.verify(name, descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def verify(self, name, descriptor):
        if name not in self.held:
            self.hold(name, os.dup(descriptor))
        elif not self.holds(name, os.fstat(descriptor)):
            raise Moved('%s is another directory than the one this export found or created'
                        % (name or 'the checkout root'))

    def directory(self, path):
        """Create the directory at path, where nothing may exist, and hold it. No system call
        creates a directory as an open descriptor, so a directory moved in under the new name
        before it is opened here would be taken for this export's own. The rollback still
        removes such a directory only once it is empty."""
        parent, name = split(path)
        descriptor = self.reach(parent)
        try:
            os.mkdir(name, 0o755, dir_fd=descriptor)
            self.created.append((path, 'directory', None))
            self.hold(path, os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor))
        finally:
            os.close(descriptor)

    def write(self, path, data):
        """Create the file at path exclusively and hold it, then write and sync it."""
        parent, name = split(path)
        descriptor = self.reach(parent)
        try:
            created = os.open(name, FILE_FLAGS, 0o644, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        try:
            self.created.append((path, 'file', data))
            self.hold(path, os.dup(created))
            view = memoryview(data)
            while view:
                view = view[os.write(created, view):]
            os.fchmod(created, 0o644)
            os.fsync(created)
        finally:
            os.close(created)

    def sync(self):
        """Sync each directory this export created, and the directory holding it."""
        for path, kind, _ in self.created:
            if kind == 'directory':
                for directory in (path, split(path)[0]):
                    descriptor = self.reach(directory)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)

    def remove(self):
        """The rollback: remove what this export created, newest first, each through its parent
        directory reached from the root without following a link. An object goes only while it is
        the very object held for its path, a file only while it holds no more than the bytes it
        was to hold (fewer after an interrupted write), and a directory only once it is empty.
        Anything else is kept, with the reason. Every held object is released at the end. Returns
        (removed, left), left mapping each kept path to its reason."""
        removed, left = [], {}
        try:
            for path, kind, data in reversed(self.created):
                parent, name = split(path)
                try:
                    descriptor = self.reach(parent)
                except (Moved, OSError) as error:
                    left[path] = 'not reached: %s' % error
                    continue
                try:
                    reason = self.remove_one(descriptor, path, name, kind, data)
                finally:
                    os.close(descriptor)
                if reason is None:
                    removed.append(path)
                else:
                    left[path] = reason
        finally:
            self.created = []
            self.close()
        return removed, left

    def keep(self, reason):
        """Keep everything this export created, each path for reason, and release every held
        object. Returns the kept paths, newest first, with the reason."""
        left = {path: reason for path, _, _ in reversed(self.created)}
        self.created = []
        self.close()
        return left

    def remove_one(self, descriptor, path, name, kind, data):
        """Remove one created object from its open parent: None once removed, else the reason it is
        kept. A replacement racing the moment between this check and the removal is not
        excluded, since no system call removes a name only while it names a given inode."""
        if path not in self.held:
            return 'its identity could not be read when this export created it'
        try:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return 'not found where this export created it'
        except OSError as error:
            return error.strerror
        try:
            if not self.holds(path, info):
                return 'another object than the one this export created'
            if kind == 'directory':
                os.rmdir(name, dir_fd=descriptor)
                return None
            found = read_regular(descriptor, name)
            if found is None or not self.holds(path, found[0]):
                return 'another object than the one this export created'
            if not data.startswith(found[1]):
                return 'changed since this export wrote it'
            os.unlink(name, dir_fd=descriptor)
            return None
        except OSError as error:
            if error.errno == errno.ENOTEMPTY:
                return 'it holds entries this export did not create'
            return error.strerror


def listing(descriptor, prefix, found, objects):
    """Every entry below an open directory, without following a link: a regular file's SHA-256,
    a link's target, or the kind of anything else, by path. objects keeps each regular file's
    stat, by path."""
    with os.scandir(descriptor) as entries:
        children = sorted(entry.name for entry in entries)
    for child in children:
        name = prefix + '/' + child
        info = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            found[name] = 'link to ' + os.readlink(child, dir_fd=descriptor)
        elif stat.S_ISDIR(info.st_mode):
            found[name] = 'directory'
            inner = os.open(child, DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                listing(inner, name, found, objects)
            finally:
                os.close(inner)
        elif stat.S_ISREG(info.st_mode):
            regular = read_regular(descriptor, child)
            if regular is None:
                found[name] = 'other'
            else:
                objects[name] = regular[0]
                found[name] = sha(regular[1])
        else:
            found[name] = 'other'


def candidate_inventory(staged, directories, new):
    """The complete inventory of the candidate's new directories, reached from the root without
    following a link, every entry counted whether Git ignores it or not: (found, unexpected,
    missing, differing, foreign). found holds a file's SHA-256, a link's target or the kind of
    any other entry, by path. Only the staged files belong there, each a regular file with its
    staged bytes that is the very file this export created and holds there."""
    expected = {name: sha(data) for name, data in staged}
    found, objects = {}, {}
    for directory in directories:
        try:
            descriptor = new.reach(directory)
        except Moved as error:
            found[directory] = 'not reached: %s' % error
            continue
        try:
            listing(descriptor, directory, found, objects)
        finally:
            os.close(descriptor)
    found = dict(sorted(found.items()))
    unexpected = sorted(set(found) - set(expected))
    missing = sorted(set(expected) - set(found))
    both = set(found) & set(expected)
    differing = sorted(name for name in both if found[name] != expected[name])
    foreign = sorted(name for name in both
                     if name not in objects or not new.holds(name, objects[name]))
    return found, unexpected, missing, differing, foreign


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Evidence:
    """The export's evidence record in its own directory, written whole and durably. Until the
    export is done it is a failure record. Some complete record is on disk at every moment once
    the first is written, and no record is removed before another is durably in its place. A
    call that reports an error may still have taken effect, as POSIX allows for a rename that
    fails with EIO and as a network filesystem may do for a request it repeated, so after an
    error from a record's rename or removal the disk decides, never the error. While the final
    record is published, the failure record keeps a second name, export.fail.json, and is held
    open. From then on the final record may be on disk, whatever a call reported, so a failure
    puts the failure record durably back as the record, as the disk shows it, before any
    rollback. A reader takes export.json, or export.fail.json if export.json is absent. Each
    call is taken to be complete when it returns, as on a local filesystem."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.saved = None
        self.failure = None

    @property
    def published(self):
        """Whether the final record's publication began: from then on the final record may be on
        disk, whatever a call reported."""
        return self.failure is not None

    @staticmethod
    def encode(record):
        return (json.dumps(record, indent=2) + '\n').encode()

    def write(self, record):
        """The record written whole and synced to a temporary file beside the record: (bytes,
        temporary path)."""
        data = self.encode(record)
        descriptor, name = tempfile.mkstemp(prefix='.export-', dir=self.directory)
        try:
            with os.fdopen(descriptor, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(name)
            raise
        return data, name

    def save(self, record):
        """Replace the record whole: the temporary file renamed over it, then the directory
        synced. A reader finds the previous record or this one, never a part. An OSError means
        the record is not durably in place, though holds() may find it on disk."""
        data, name = self.write(record)
        try:
            os.replace(name, self.directory / RECORD)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(name)
            raise
        sync_directory(self.directory)
        self.saved = data
        return data

    def publish(self, record):
        """Publish the final record: the failure record on disk is held open and gains its second
        name, the final record is renamed over export.json, the directory is synced and the record
        read back. From the moment the failure record is held, the final record may be on disk,
        whatever a call reports, so any failure from then on goes through restore()."""
        data, name = self.write(record)
        try:
            self.failure = os.open(self.directory / RECORD,
                                   os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            os.link(self.directory / RECORD, self.directory / FALLBACK)
            if not self.holds_failure(FALLBACK):
                raise ExportError('the failure record changed while it gained its second name')
            sync_directory(self.directory)
            os.replace(name, self.directory / RECORD)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(name)
            raise
        sync_directory(self.directory)
        if (self.directory / RECORD).read_bytes() != data:
            raise ExportError('the final evidence record does not read back as written')
        return data

    def contents(self, name):
        """The bytes the record name holds now, read without following a link, or None."""
        try:
            descriptor = os.open(self.directory, DIRECTORY_FLAGS)
        except OSError:
            return None
        try:
            found = read_regular(descriptor, name)
        except OSError:
            return None
        finally:
            os.close(descriptor)
        return None if found is None else found[1]

    def holds(self, data):
        """Whether export.json holds exactly these bytes now."""
        return self.contents(RECORD) == data

    def present(self, name):
        """Whether anything is at the record name now. An error other than its absence counts as
        present, so that nothing is taken for withdrawn that might not be."""
        try:
            os.stat(self.directory / name, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return True

    def holds_failure(self, name):
        """Whether the record name holds the failure record this export saved and holds open: the
        very file, still linked, with the bytes saved."""
        if self.failure is None:
            return False
        try:
            info = os.stat(self.directory / name, follow_symlinks=False)
            held = os.fstat(self.failure)
            data = os.pread(self.failure, held.st_size + 1, 0)
        except OSError:
            return False
        return same_object(held, info) and data == self.saved

    def restore(self):
        """Once the final record's publication began, make its failure record durably the record
        again, whatever the calls so far did. If export.json holds it, nothing moves. Otherwise,
        while the second name still holds it, that name is renamed over export.json, or else
        export.json is withdrawn so that the second name is the record. Each step's outcome is
        read from the disk, never from its error. Then the directory is synced. Returns whether
        the failure record is now durably the record, so that the rollback may run."""
        if not self.holds_failure(RECORD):
            if not self.holds_failure(FALLBACK):
                return False
            with contextlib.suppress(OSError):
                os.replace(self.directory / FALLBACK, self.directory / RECORD)
            if not self.holds_failure(RECORD):
                if not self.holds_failure(FALLBACK):
                    return False
                with contextlib.suppress(OSError):
                    os.unlink(self.directory / RECORD)
                if self.present(RECORD) or not self.holds_failure(FALLBACK):
                    return False
        try:
            sync_directory(self.directory)
        except OSError:
            return False
        return True

    def forget(self):
        """Drop the failure record's second name once export.json holds a record that makes it
        needless. Returns the error if the name is still there."""
        try:
            os.unlink(self.directory / FALLBACK)
        except OSError as error:
            if self.present(FALLBACK):
                return error
        with contextlib.suppress(OSError):
            sync_directory(self.directory)
        return None

    def close(self):
        """Release the failure record held open, once the export is done or has failed."""
        if self.failure is not None:
            os.close(self.failure)
            self.failure = None

    def describe(self):
        """Exactly which record is on disk, for stderr."""
        found = []
        for name in (RECORD, FALLBACK):
            path = self.directory / name
            try:
                value = json.loads(path.read_bytes())
            except FileNotFoundError:
                found.append('%s is absent' % path)
                continue
            except (OSError, ValueError) as error:
                found.append('%s is unreadable (%s)' % (path, error))
                continue
            found.append('%s says %s in the %s phase' % (path, value.get('status'),
                                                         value.get('phase')))
        if found[1].endswith(' is absent'):
            return found[0] if not found[0].endswith(' is absent') else \
                'no evidence record exists in %s' % self.directory
        return '; '.join(found)


def write_candidate(staged, new):
    """The staged files at new paths of this checkout, in their order, each created exclusively in
    a directory this export creates, through directories reached from the root without following a
    link. It runs with the termination signals blocked, so each file is created, held and written
    whole. A signal is let through only between files."""
    directories = sorted({split(name)[0] for name, _ in staged})
    for directory in directories:
        new.directory(directory)
    for name, data in staged:
        new.write(name, data)
        with interruptible():
            pass
    new.sync()


# ---------------------------------------------------------------- the export

def tool_digests():
    """The SHA-256 of this tool and of every tool it runs or reads."""
    names = ['scripts/proof/' + name + '.py' for name in (
        'grapheneos_export', 'grapheneos_carry', 'grapheneos_candidate', 'grapheneos_source',
        'git_index', 'grapheneos_base', 'native_creation_binding', *candidate.PATCH_TOOLS)]
    names.append(HOST_TESTS + '/pis_reverse_write_sync.py')
    return {name: sha((ROOT / name).read_bytes()) for name in names}


def save_inputs(scratch, files, records):
    """The files read upstream, kept in scratch as the private generation inputs:
    inputs/<release>/<project>/<path>. Returns their provenance and the target's directory."""
    provenance = []
    for (side, project), found in sorted(files.items()):
        release = records[side]['release']
        for path, item in sorted(found.items()):
            row = {'release': release, 'project': project, 'path': path,
                   'revision': records[side]['patched_projects'][project]['revision']}
            if item is None:
                provenance.append(dict(row, upstream='absent'))
                continue
            target = scratch / 'inputs' / release / project / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(item[1])
            provenance.append(dict(row, blob=item[0], sha256=sha(item[1])))
    return provenance, scratch / 'inputs' / records['target']['release']


def export(report_path, source_root, source_evidence, allowed_signers, scratch,
           base_source_root=None):
    """The export, returning its evidence record, scratch/evidence/export.json. That record is
    written first, as a failure record kept current through the checks and the writing, and some
    complete record stays on disk from then on (see Evidence). The export is EXPORTED only once
    the complete inventory of its new paths is exactly the files it created, with their bytes,
    and its final record is published durably and read back. Until then any failure, and an
    ordinary termination signal, removes what the export created and still holds open as its own,
    with the signals blocked, once a failure record is durably in place, and records the failure.
    Anything else is kept and recorded. Once the scratch is accepted, an exception raised here
    carries, as its evidence attribute, exactly which record is on disk."""
    with terminable():
        return _export(report_path, source_root, source_evidence, allowed_signers, scratch,
                       base_source_root)


def _export(report_path, source_root, source_evidence, allowed_signers, scratch,
            base_source_root):
    report_path = Path(report_path).absolute()
    source_root = Path(source_root).resolve(strict=True)
    base_root = source_root if base_source_root is None else \
        Path(base_source_root).resolve(strict=True)
    if base_source_root is not None and not candidate.disjoint(
            Path(scratch).absolute().resolve(), base_root):
        raise ExportError('the scratch must be outside the base source tree: ' + str(scratch))
    scratch = candidate.scratch_dir(scratch, source_root)
    (scratch / 'evidence').mkdir(mode=0o700)
    evidence = Evidence(scratch / 'evidence')
    try:
        return transaction(evidence, report_path, source_root, base_root, source_evidence,
                           allowed_signers, scratch)
    except BaseException as error:
        # From here on every failure carries, for stderr, exactly which record is on disk.
        with contextlib.suppress(Exception):
            error.evidence = evidence.describe()
        raise
    finally:
        evidence.close()


def transaction(evidence, report_path, source_root, base_root, source_evidence, allowed_signers,
                scratch):
    """The export once its evidence directory exists: the first record, the checks, the writing
    and the finish, or else the failure path."""
    record = {'schema': SCHEMA, 'status': 'FAIL', 'phase': 'checks',
              'failure': UNFINISHED['checks'], 'started': now(), 'tools': tool_digests(),
              'source_root': str(source_root), 'base_source_root': str(base_root)}
    try:
        evidence.save(record)
    except OSError as error:
        raise ExportError('the first evidence record could not be written durably (%s), so the '
                          'export stopped before it wrote anything in this checkout'
                          % error) from error
    new, done = NewFiles(), False
    try:
        with interruptible():
            record['revision'] = git(ROOT, 'rev-parse', 'HEAD')
            if status():
                raise ExportError('this checkout has changes: an export starts from a clean '
                                  'revision')
            before = snapshot(())
            base = grapheneos_base.selected()
            report, base_record, target = sealed(report_path, base)
            records = {'base': base_record, 'target': target}
            release = target['release']
            excluded = ['patches/grapheneos-' + release,
                        '%s/grapheneos-%s' % (HOST_TESTS, release)]
            for name in excluded:
                if (ROOT / name).exists() or (ROOT / name).is_symlink():
                    raise ExportError('the candidate path already exists: %s. An export that '
                                      'was killed may have left it; its evidence record names '
                                      'what it was writing' % name)
            record.update(base=base.release, release=release, selection_sha256=sha(
                (ROOT / grapheneos_base.SELECTION).read_bytes()), report={
                    'path': relative(report_path.resolve()), 'seal': report['seal']['sha256']})
            specs = specifications(base, base_record, report)
            record['source_verification'] = verified_source(source_evidence, target)
            authenticate(source_root, target, allowed_signers)
            files = upstream_files(specs, report, records,
                                   {'base': base_root, 'target': source_root})
            record['inputs'], inputs = save_inputs(scratch, files, records)
            work = scratch / 'apply'
            work.mkdir(mode=0o700)
            rows, outputs = carry_rows(specs, files, work)
            record['rows'] = rows
            compare(rows, report)
            staged = stage(specs, rows, outputs, files, report, target, work)
            record['staged'] = [{'path': name, 'sha256': sha(data)} for name, data in staged]
            record['export_check'] = check_export(scratch, staged, rows, target, inputs,
                                                  record['revision'])
            unchanged(before, snapshot(excluded), 'during the checks')
            if status():
                raise ExportError('this checkout changed during the checks')
        record.update(phase='writing', failure=UNFINISHED['writing'])
        evidence.save(record)
        write_candidate(staged, new)
        with interruptible():
            if sorted(status()) != sorted(('??', name) for name, _ in staged):
                raise ExportError('this checkout has other changes than the candidate files')
            unchanged(before, snapshot(excluded), 'during the export')
            if grapheneos_base.load().release != base.release:
                raise ExportError('the selection changed during the export')
            found, *listed = candidate_inventory(staged, excluded, new)
            record['inventory'] = found
            problems = dict(zip(('unexpected', 'missing', 'differing', 'foreign'), listed))
            if any(problems.values()):
                record.update({key: value for key, value in problems.items() if value})
                raise ExportError('the candidate directories hold other entries than the files '
                                  'this export wrote: ' + '; '.join(
                                      '%s %s' % (key, ', '.join(value))
                                      for key, value in problems.items() if value))
        record['phase'] = 'finishing'
        final = dict(record, status='EXPORTED', phase='done', written=record['staged'],
                     finished=now())
        del final['failure']
        evidence.publish(final)
        done = True
        stays = evidence.forget()
        if stays is not None:
            print('note: %s, the failure record kept while the final record was published, could '
                  'not be removed (%s). The record is %s, which says EXPORTED.'
                  % (evidence.directory / FALLBACK, stays, evidence.directory / RECORD),
                  file=sys.stderr)
        return final
    except BaseException as error:
        record['failure'] = '%s: %s' % (type(error).__name__, error)
        raise
    finally:
        try:
            if not done:
                # The termination signals are blocked here: the handler blocked them before
                # raising, and every other path left an interruptible block or never entered one.
                fail(evidence, record, new)
        finally:
            new.close()


def fail(evidence, record, new):
    """The failure path, with the termination signals blocked. Once the final record's
    publication began, the final record may be on disk whatever a call reported, so the rollback
    runs only once restore() has made the failure record durably the record again, as the disk
    shows it, and no record claims EXPORTED while it runs. Otherwise the candidate is kept whole.
    Then this run's failure record, if it can be written, or else a note on stderr that says
    whether it is on disk anyway."""
    if evidence.published:
        undone = evidence.restore()
    else:
        undone = True
    if undone:
        record['removed'], left = new.remove()
    else:
        record['removed'] = []
        left = new.keep('kept whole, since no failure record could be made durable in place of '
                        'the final record')
        print('note: no failure record could be made durable in place of the final record, so '
              'the candidate was kept whole', file=sys.stderr)
    if left:
        record['left'], record['left_reasons'] = list(left), left
    record.update(status='FAIL', finished=now())
    try:
        evidence.save(record)
    except OSError as error:
        # Its rename may have taken effect before it failed: the disk decides what the note says.
        if evidence.holds(evidence.encode(record)):
            placed = 'is on disk, but may not be durable'
        else:
            placed = 'could not be written'
        if undone:
            remains = 'The rollback removed %d paths this export created, and kept: %s' % (
                len(record['removed']),
                '; '.join('%s (%s)' % item for item in left.items()) or 'nothing')
        else:
            remains = 'The candidate was kept whole'
        print('note: the failure record of this run %s (%s). %s' % (placed, error, remains),
              file=sys.stderr)
    else:
        evidence.forget()


# ---------------------------------------------------------------- validate

def validate(inputs):
    """The selected base's patch set against the upstream files under inputs, as
    <project>/<path>: each patch tool's own profile check and candidate derivation, the payload
    host tool's reading of both Package Installer states, and the policy record against the
    bridge and its review patch. Returns the digests each tool derived."""
    import android_lifecycle as lifecycle
    import native_identity_writer as writer
    import native_principal_pins as pins
    import owner_policy as policy
    import package_installer_payload_sync as payload
    import package_verity as verity
    host = host_tool()
    base = grapheneos_base.selected()
    inputs = Path(inputs).resolve(strict=True)

    def read(project, path):
        file = inputs / project / path
        if not file.resolve().is_relative_to(inputs):
            raise ExportError('an upstream input lies outside the inputs: %s/%s' % (project, path))
        return regular(file, 'upstream input %s/%s' % (project, path))

    def derived(profile, names, original, output, added=()):
        return {'profile_sha256': sha(profile.read_bytes()),
                'files': {name: [sha(original[name]), sha(output[name])] for name in names},
                'added': {name: sha(output[name]) for name in added}}
    patches = {}
    original = {name: read(pins.PROJECT, name) for name in pins.FILES}
    patches['native-principal-pins'] = derived(pins.PROFILE, pins.FILES, original,
                                               pins.targets(original, pins.profile()), pins.ADDED)
    original = {name: read(lifecycle.PROJECT, name) for name in lifecycle.FILES}
    patches['owner-lifecycle'] = derived(lifecycle.PROFILE, lifecycle.FILES, original,
                                         lifecycle.targets(original, lifecycle.profile()),
                                         [lifecycle.ADDED])
    pis = read(verity.PROJECT, verity.FILE)
    verity_out = verity.candidate(pis, verity.profile())
    patches['package-verity'] = derived(verity.PROFILE, [verity.FILE], {verity.FILE: pis},
                                        {verity.FILE: verity_out})
    verity_target, combined = payload.derive(pis, payload.profile())
    if verity_target != verity_out:
        raise ExportError('the payload sync tool derives another package verity candidate')
    patches[PAYLOAD] = derived(payload.PROFILE, [payload.FILE], {payload.FILE: verity_out},
                               {payload.FILE: combined})
    fileutils = read(verity.PROJECT, host.FILEUTILS)
    states = [host.inspect_bytes(data, fileutils)['state'] for data in (verity_out, combined)]
    original = {writer.FILE: read(writer.PROJECT, writer.FILE)}
    patches['native-identity-writer'] = derived(
        writer.PROFILE, [writer.FILE], original,
        writer.targets(original[writer.FILE], writer.profile()), [writer.ADDED])
    original = {path: read(policy.PROJECT, path) for path in policy.FILES}
    bridge = policy.patched(original)
    profile = base.patches / candidate.POLICY_RECORD
    record, review = carry.load_json(profile), base.patches / candidate.POLICY_PATCH
    with tempfile.TemporaryDirectory(prefix='andrix-export-') as work:
        _, _, reviewed = carry.apply_patch(review, original, work)
    wanted = {'base_release': base.release, 'project': policy.PROJECT, 'head': policy.HEAD,
              'files': [dict(path=path, upstream_sha256=sha(original[path]),
                             candidate_sha256=sha(bridge[path])) for path in policy.FILES],
              'patch': review.name, 'patch_sha256': sha(review.read_bytes())}
    differing = sorted(key for key, value in wanted.items() if record.get(key) != value)
    try:
        policy.profile_files(record)
    except ValueError:
        differing.append('four pinned files')
    if reviewed != bridge:
        differing.append('the review patch')
    if differing:
        raise ExportError('the policy record disagrees with the bridge: ' + ', '.join(differing))
    patches[POLICY] = derived(profile, policy.FILES, original, bridge)
    return {'patches': patches,
            'host_record': {'path': relative(host.PROFILE),
                            'sha256': sha(host.PROFILE.read_bytes()), 'states': states,
                            'fileutils_sha256': sha(fileutils)}}


def validate_report(inputs):
    """The validate command's report and exit status."""
    base = grapheneos_base.selected()
    report = {'base': base.release, 'patches_directory': relative(base.patches)}
    try:
        report.update(validate(inputs), validate='PASS', status='SOURCE_ONLY')
    except (ExportError, carry.CarryError, source.SourceError, OSError, ValueError, KeyError,
            TypeError) as error:
        report.update(validate=['%s: %s' % (type(error).__name__, error)], status='FAIL')
    return report, 0 if report['status'] == 'SOURCE_ONLY' else 1


def print_evidence(error):
    """The last line of a failure on stderr: exactly which record is on disk, once the scratch
    was accepted."""
    if getattr(error, 'evidence', None):
        print('evidence: ' + error.evidence, file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('export', help="write the report target's candidate patch set")
    run.add_argument('--report', required=True, type=Path,
                     help='the sealed carry report of the selected base, in upstream/reports')
    run.add_argument('--source-root', required=True, type=Path,
                     help="the target release's source tree, read only")
    run.add_argument('--source-evidence', required=True, type=Path,
                     help="the evidence directory of that tree's source verification, run by a "
                          'scratch checkout that selects the target')
    run.add_argument('--allowed-signers', required=True, type=Path,
                     help='the public file grapheneos_source.py pins by digest')
    run.add_argument('--scratch', required=True, type=Path,
                     help="NEW or empty directory outside this working tree and the source trees")
    run.add_argument('--base-source-root', type=Path,
                     help="a reviewed read only tree with the selected base's Git objects, when "
                          'the source tree lacks them')
    check = commands.add_parser('validate', help="check the selected base's patch set against "
                                                 'upstream files, with each patch tool')
    check.add_argument('--inputs', required=True, type=Path,
                       help='the upstream files, as <project>/<path>')
    args = parser.parse_args(argv)
    if args.command == 'validate':
        report, code = validate_report(args.inputs)
        print(json.dumps(report, indent=2))
        return code
    try:
        record = export(args.report, args.source_root, args.source_evidence,
                        args.allowed_signers, args.scratch, args.base_source_root)
    except Terminated as error:
        print('FAIL: %s.' % error, file=sys.stderr)
        print_evidence(error)
        return 128 + error.number
    except (ExportError, Moved, carry.CarryError, candidate.CandidateError, source.SourceError,
            grapheneos_base.BaseSelectionError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        print_evidence(error)
        return 1
    except Exception as error:
        # An unexpected error: its traceback, then the same last lines as any other failure.
        traceback.print_exc()
        print('FAIL: %s: %s' % (type(error).__name__, error), file=sys.stderr)
        print_evidence(error)
        return 1
    print(json.dumps({key: record[key] for key in (
        'status', 'base', 'release', 'revision', 'report', 'written')}, indent=2))
    print('evidence: ' + str(Path(args.scratch).resolve() / 'evidence/export.json'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
