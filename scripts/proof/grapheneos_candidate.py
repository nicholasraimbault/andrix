#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check a candidate GrapheneOS base in a scratch checkout that selects it.

check archives one revision of this repository into a new scratch directory outside its working
tree and checks every file against its blob ID. It writes there the checkout's own selection of
the candidate: its release, its record in upstream/bases and the SHA-256 of that record. In that
checkout it runs the production format guard and the exact patch set check over the candidate's
patch directory, and the source verifier and the patch tools' read only checks against the
candidate's source tree. It compares the policy record with the policy tool's reading of that
tree and reports each result. The repository's own selection is never written.

patch-set checks the selected base's exact patch set without a source tree. Run by a scratch
checkout's own copy, it checks the candidate's. No apply, revert, sync or build.
See grapheneos_candidate.md.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

import grapheneos_base
import grapheneos_source as source

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'andrix.upstream.candidate_check/1'
TOOLS = 'scripts/proof/'
# The patches of a base's patch directory, by name. Each lies there beside its profile, and the
# directory holds nothing else but a README.
PATCH_NAMES = ('native-principal-pins', 'owner-lifecycle', 'package-verity',
               'package-installer-payload-sync', 'native-identity-writer', 'owner-session-policy')
POLICY_RECORD = 'owner-session-policy.json'
POLICY_PATCH = 'owner-session-policy.patch'
HEX64 = re.compile(r'[0-9a-f]{64}')
# The patch tools, each run with its read only check action. The policy tool also reports the
# digests of the tree's four policy files and of the bridge it derives, which the policy record names.
PATCH_TOOLS = ('android_lifecycle', 'package_verity', 'package_installer_payload_sync',
               'native_principal_pins', 'native_identity_writer', 'owner_policy')
POLICY_TOOL = 'owner_policy'
# Seconds each check may take. The source verifier reads every project of the tree.
TIMEOUTS = {'format guard': 600, 'patch set': 300, 'source verifier': 3600, 'patch tool': 900,
            'policy tool': 900}
# The fields of each check's report that its result keeps.
SUMMARY = {'format guard': ('base', 'production_patches', 'format_guard'),
           'patch set': ('base', 'patch_set', 'patches', 'policy', 'host_record'),
           'source verifier': ('verdict', 'release', 'declared_projects', 'verified_projects'),
           'patch tool': ('state',), 'policy tool': ('state', 'files')}
# Variables that would let the repository's own modules shadow the checkout's.
DROPPED_ENVIRONMENT = ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONSAFEPATH')


class CandidateError(Exception):
    """An input is refused, or the checkout is not exactly its revision. No check runs past it."""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def disjoint(path, tree):
    """Whether neither path is the other or inside it."""
    return not (path == tree or path.is_relative_to(tree) or tree.is_relative_to(path))


# ---------------------------------------------------------------- the exact patch set

def host_record(base):
    """The selected base's own host tested record of the payload companion, by its path and
    digest. It is a regular file at the path keyed by the base, and a JSON object that names the
    base's frameworks/base revision and its package verity profile by path and digest. The payload
    tool's profile check then holds it to the payload profile."""
    import grapheneos_carry as carry
    import package_installer_payload_sync as payload
    import package_verity as verity
    path = payload.HOST_PROFILE
    name = path.relative_to(ROOT).as_posix()
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise CandidateError('the selected base has no host tested record ' + name)
    try:
        record = carry.load_json(path)
    except carry.CarryError as error:
        raise CandidateError('the host tested record %s: %s' % (name, error)) from error
    if not isinstance(record, dict):
        raise CandidateError('the host tested record %s is not a JSON object' % name)
    wanted = {'head': base.revision(verity.PROJECT),
              'base_profile': verity.PROFILE.relative_to(ROOT).as_posix(),
              'base_profile_sha256': sha(verity.PROFILE.read_bytes())}
    differing = sorted(key for key, value in wanted.items() if record.get(key) != value)
    if differing:
        raise CandidateError('the host tested record %s does not name the selected base: %s'
                             % (name, ', '.join(differing)))
    return {'path': name, 'sha256': sha(path.read_bytes())}


def patch_set():
    """The selected base's exact patch set, read without a source tree: the names of its patches,
    the digests its policy record names and its host tested record. Its directory holds exactly the
    six patches, each beside its profile, and at most a README, all regular files. The owner
    session policy record names the selected base, its system/sepolicy revision, four exact policy
    files, their pinned upstream and adapted digests, and the review patch beside it by its digest. The payload companion's host tested record is the base's own (host_record). The
    carry tool's own loader then checks that inventory, validates every other profile with its tool
    and checks the policy record again, so a patch set passes here only if the carry tool accepts
    it."""
    import grapheneos_carry as carry
    import owner_policy as policy
    base = grapheneos_base.selected()
    directory = base.patches
    name = directory.relative_to(ROOT).as_posix()
    if directory.is_symlink() or not directory.is_dir():
        raise CandidateError('the selected base has no patch directory ' + name)
    entries = {entry.name: entry for entry in directory.iterdir()}
    expected = {stem + suffix for stem in PATCH_NAMES for suffix in ('.json', '.patch')}
    missing = sorted(expected - set(entries))
    unexpected = sorted(set(entries) - expected - {'README.md'})
    irregular = sorted(key for key, entry in entries.items()
                       if entry.is_symlink() or not entry.is_file())
    if missing or unexpected or irregular:
        raise CandidateError('%s is not exactly the six patches beside their profiles: missing %s, '
                             'unexpected %s, not regular files %s'
                             % (name, missing, unexpected, irregular))
    try:
        record = carry.load_json(directory / POLICY_RECORD)
        if not isinstance(record, dict):
            raise CandidateError('the owner session policy record is not a JSON object')
        wanted = {'base_release': base.release, 'project': policy.PROJECT, 'head': policy.HEAD,
                  'patch': POLICY_PATCH, 'patch_sha256': sha((directory / POLICY_PATCH).read_bytes())}
        differing = sorted(key for key, value in wanted.items() if record.get(key) != value)
        try:
            policy.profile_files(record)
        except ValueError:
            differing.append('files')
        if differing:
            raise CandidateError('the owner session policy record does not name the selected base '
                                 'and its review patch: %s' % ', '.join(differing))
        host = host_record(base)
        specs = carry.load_patch_set(base.release)
    except carry.CarryError as error:
        raise CandidateError('the carry tool refuses the patch set: %s' % error) from error
    return {'patches': [spec['name'] for spec in specs],
            'policy': {'files': record['files'], 'patch_sha256': record['patch_sha256']},
            'host_record': host}


def patch_set_report():
    """The patch set check's report and exit status."""
    base = grapheneos_base.selected()
    report = {'base': base.release, 'patches_directory': base.patches.relative_to(ROOT).as_posix()}
    try:
        report.update(patch_set(), patch_set='PASS', status='SOURCE_ONLY')
    except (CandidateError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        report.update(patch_set=['%s: %s' % (type(error).__name__, error)], status='FAIL')
    return report, 0 if report['status'] == 'SOURCE_ONLY' else 1


# ---------------------------------------------------------------- the scratch checkout

def scratch_dir(path, source_root):
    """A new or empty scratch directory, disjoint from the repository's working tree and from the
    source tree."""
    path = Path(path).absolute()
    if not disjoint(path.resolve(), ROOT):
        raise CandidateError("the scratch must be outside the repository's working tree: "
                             + str(path))
    if not disjoint(path.resolve(), source_root):
        raise CandidateError('the scratch must be outside the source tree: ' + str(path))
    if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
        raise CandidateError('the scratch must be new or empty: ' + str(path))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path.resolve()


def checkout(scratch, revision):
    """An exact checkout of one revision of the repository, made from its Git objects in
    scratch/checkout. Returns (checkout, commit). Every file must have its blob ID, and the
    checkout holds no other file; a revision with a link or a submodule is refused."""
    commit = source.run(ROOT, 'rev-parse', '--verify', '--end-of-options',
                        revision + '^{commit}')[1].decode().strip()
    algorithm = source.run(ROOT, 'rev-parse', '--show-object-format')[1].decode().strip()
    listing = source.run(ROOT, 'ls-tree', '-r', '-z', '--full-tree', commit)[1]
    archive = source.run(ROOT, 'archive', '--format=tar', commit)[1]
    expected = {}
    for entry in filter(None, listing.split(b'\0')):
        meta, _, name = entry.partition(b'\t')
        mode, kind, blob = meta.split()
        if kind != b'blob' or mode not in (b'100644', b'100755'):
            raise CandidateError('the revision holds a link or a submodule: '
                                 + name.decode(errors='replace'))
        expected[name.decode()] = blob.decode()
    target = scratch / 'checkout'
    target.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        tar.extractall(target, filter='data')
    found = {path.relative_to(target).as_posix(): path for path in target.rglob('*')
             if path.is_symlink() or not path.is_dir()}
    if set(found) != set(expected) or any(path.is_symlink() for path in found.values()):
        raise CandidateError("the scratch checkout is not exactly the revision's tree")
    for name, path in sorted(found.items()):
        data = path.read_bytes()
        if hashlib.new(algorithm, b'blob %d\0' % len(data) + data).hexdigest() != expected[name]:
            raise CandidateError('the scratch checkout differs from the revision: ' + name)
    return target, commit


def select(tree, release):
    """Write the selection of release into a scratch checkout: the release, its record and the
    SHA-256 of the record's bytes. Refuses the repository's own working tree and every Git
    checkout, so the repository's selection is never written. Returns the base that the checkout
    now selects, as grapheneos_base reads it there."""
    tree = Path(tree).resolve()
    if not disjoint(tree, ROOT) or (tree / '.git').exists() or (tree / '.git').is_symlink():
        raise CandidateError("a candidate is selected only in a scratch checkout, never in the "
                             "repository's working tree or another Git checkout: " + str(tree))
    if not isinstance(release, str) or grapheneos_base.RELEASE.fullmatch(release) is None:
        raise CandidateError('not a release tag: %r' % (release,))
    record = 'upstream/bases/%s.json' % release
    if (tree / record).is_symlink() or not (tree / record).is_file():
        raise CandidateError('the checkout has no base record ' + record)
    patches = tree / 'patches' / ('grapheneos-' + release)
    if patches.is_symlink() or not patches.is_dir():
        raise CandidateError('the checkout has no patch directory patches/grapheneos-' + release)
    value = {'schema': grapheneos_base.SCHEMA, 'release': release, 'record': record,
             'record_sha256': sha((tree / record).read_bytes())}
    (tree / grapheneos_base.SELECTION).write_text(json.dumps(value, indent=2) + '\n')
    try:
        return grapheneos_base.load(root=tree)
    except grapheneos_base.BaseSelectionError as error:
        raise CandidateError('the checkout refuses its candidate selection: %s' % error) from error


# ---------------------------------------------------------------- the checks

def checks(tree, source_root, allowed_signers, evidence):
    """Each check as (name, kind, command), every one run by the checkout's own copy of its tool,
    so each reads the checkout's selection."""
    python = [sys.executable, '-B']
    result = [('format guard', 'format guard',
               python + [str(tree / TOOLS / 'native_creation_binding.py'), '--format-guard-only']),
              ('patch set', 'patch set',
               python + [str(tree / TOOLS / 'grapheneos_candidate.py'), 'patch-set']),
              ('source verifier', 'source verifier',
               python + [str(tree / TOOLS / 'grapheneos_source.py'), '--source-root',
                         str(source_root), '--allowed-signers', str(allowed_signers),
                         '--evidence-dir', str(evidence / 'source-verifier')])]
    for tool in PATCH_TOOLS:
        result.append((tool, 'policy tool' if tool == POLICY_TOOL else 'patch tool',
                       python + [str(tree / TOOLS / (tool + '.py')), '--source-root',
                                 str(source_root), '--action', 'check',
                                 '--evidence', str(evidence / (tool + '.json'))]))
    return result


def summary(kind, stdout, stderr, returncode):
    """The fields of a check's report that its result keeps, or its last line of error."""
    try:
        value = json.loads(stdout)
    except ValueError:
        value = None
    if isinstance(value, dict):
        return {key: value.get(key) for key in SUMMARY[kind]}
    lines = [line for line in stderr.decode(errors='replace').splitlines() if line.strip()]
    return {'failure': lines[-1] if lines else 'exit status %d' % returncode}


def run_check(name, kind, command, tree, evidence):
    """One check in the checkout: its result, with its output kept in evidence."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in DROPPED_ENVIRONMENT}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    stem = name.replace(' ', '-').replace('_', '-')
    row = {'check': name, 'command': command}
    try:
        process = subprocess.run(command, cwd=tree, env=environment, stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=TIMEOUTS[kind])
    except subprocess.TimeoutExpired:
        row.update(result='NOT_RUN', failure='no result within %d seconds' % TIMEOUTS[kind])
        return row
    (evidence / (stem + '.out')).write_bytes(process.stdout)
    (evidence / (stem + '.err')).write_bytes(process.stderr)
    row.update(result='PASS' if process.returncode == 0 else 'FAIL',
               returncode=process.returncode,
               **summary(kind, process.stdout, process.stderr, process.returncode))
    return row


def policy_agreement(rows):
    """The policy record against the policy tool's reading of the candidate's tree: the upstream
    and adapted digests it names are those of the tree's four policy files and the bridge the tool
    derives from them. Not run unless both the patch set and the policy tool pass."""
    found = {row['check']: row for row in rows}
    record, tool = found['patch set'], found[POLICY_TOOL]
    row = {'check': 'policy record'}
    if record['result'] != 'PASS' or tool['result'] != 'PASS':
        row.update(result='NOT_RUN', failure='needs a passing patch set and policy tool check')
        return row
    import owner_policy as policy
    named, read = record['policy'].get('files'), tool.get('files')
    if (not isinstance(named, list) or not isinstance(read, list)
            or len(named) != len(policy.FILES) or len(read) != len(policy.FILES)
            or any(not isinstance(item, dict) for item in named + read)):
        differing = ['four files']
    else:
        differing = [path for path, expected, observed in zip(policy.FILES, named, read)
                     if (expected.get('path') != path or observed.get('path') != path
                         or expected.get('upstream_sha256') != observed.get('upstream_sha256')
                         or expected.get('candidate_sha256') != observed.get('bridge_sha256'))]
    row.update(result='FAIL' if differing else 'PASS', files=read)
    if differing:
        row['failure'] = 'the policy record names other digests than the tree gives: ' + \
            ', '.join(differing)
    return row


def detail(row):
    """One check's result in a line: its result, and the state, verdict or failure behind it."""
    reason = next((row[key] for key in ('failure', 'format_guard', 'patch_set', 'verdict', 'state')
                   if row.get(key) not in (None, 'PASS')), None)
    return row['result'] if reason is None else '%s: %s' % (row['result'], reason)


def verify(release, source_root, allowed_signers, scratch, revision='HEAD'):
    """The candidate check: the report, written to scratch/report.json."""
    selection = ROOT / grapheneos_base.SELECTION
    before = selection.read_bytes()
    selected = grapheneos_base.load().release
    source_root = Path(source_root).resolve(strict=True)
    allowed_signers = Path(allowed_signers).resolve(strict=True)
    if not source_root.is_dir():
        raise CandidateError('the source tree is not a directory: ' + str(source_root))
    scratch = scratch_dir(scratch, source_root)
    tree, commit = checkout(scratch, revision)
    candidate = select(tree, release)
    evidence = scratch / 'evidence'
    evidence.mkdir(mode=0o700)
    rows = [run_check(name, kind, command, tree, evidence)
            for name, kind, command in checks(tree, source_root, allowed_signers, evidence)]
    rows.append(policy_agreement(rows))
    if selection.read_bytes() != before:
        raise CandidateError("the repository's selection changed during the check")
    passed = all(row['result'] == 'PASS' for row in rows)
    report = {'schema': SCHEMA, 'release': candidate.release, 'revision': commit,
              'record': candidate.record, 'record_sha256': candidate.record_sha256,
              'selection_sha256': sha((tree / grapheneos_base.SELECTION).read_bytes()),
              'repository_selects': selected, 'checkout': str(tree),
              'source_root': str(source_root), 'checks': rows,
              'verdict': 'PASS' if passed else 'FAIL', 'build_proved': False}
    (scratch / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check', help='check a candidate base in a scratch checkout')
    check.add_argument('--release', required=True, help='the candidate base, a ten digit tag')
    check.add_argument('--source-root', required=True, type=Path,
                       help="the candidate's GrapheneOS tree, read only")
    check.add_argument('--allowed-signers', required=True, type=Path,
                       help='the public file grapheneos_source.py pins by digest')
    check.add_argument('--scratch', required=True, type=Path,
                       help="NEW or empty directory outside the repository's working tree")
    check.add_argument('--revision', default='HEAD',
                       help='the repository revision to check out (default HEAD)')
    commands.add_parser('patch-set', help="the selected base's exact patch set, read only")
    args = parser.parse_args(argv)
    if args.command == 'patch-set':
        report, status = patch_set_report()
        print(json.dumps(report, indent=2))
        return status
    try:
        report = verify(args.release, args.source_root, args.allowed_signers, args.scratch,
                        args.revision)
    except (CandidateError, source.SourceError, grapheneos_base.BaseSelectionError, OSError,
            ValueError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({'release': report['release'], 'revision': report['revision'],
                      'repository_selects': report['repository_selects'],
                      'verdict': report['verdict'],
                      'checks': {row['check']: detail(row) for row in report['checks']},
                      'report': str(Path(args.scratch).resolve() / 'report.json')}, indent=2))
    return 0 if report['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
