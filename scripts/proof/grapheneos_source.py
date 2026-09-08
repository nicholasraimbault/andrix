#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only M1 checks for the pinned public GrapheneOS migration source.

No sync/fetch/reset/apply or build. PASS covers manifest authentication, intended
selection, project revisions and tracked cleanliness, not prebuilt materialization,
compiler results, runtime or device security. See grapheneos_source.md.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
TAG = '2026081300'
TAG_OBJECT = '5189230024ffe0048e0c351d5101c6b3f8b43eac'
MANIFEST_COMMIT = '84536744f0c06cccbcfa2110e9c937671ddc3278'
MANIFEST_SHA256 = 'c50f0096f538e604aa008e8ab4e3f1a3739f142c60c878a32f402c11eb406572'
SIGNERS_SHA256 = '344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0'
REPO_COMMIT = 'b85886fa9f5b4e2189cc5b2f40bd0a80459d4c77'
PROJECT_COUNT = 1108


class SourceError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(cwd, *args, allowed=(0,)):
    process = subprocess.run(['git', '--no-optional-locks', '-C', str(cwd), *args],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=120)
    if process.returncode not in allowed:
        raise SourceError('Git check failed: ' + process.stderr.decode(errors='replace').strip())
    return process.returncode, process.stdout


def relative(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise SourceError('Invalid relative path')
    p = PurePosixPath(value)
    if p.is_absolute() or value != p.as_posix() or any(x in ('.', '..', '.git') for x in p.parts):
        raise SourceError('Unsafe relative path')
    return Path(*p.parts)


def parse_projects(data):
    """This generation has no excluded host groups, includes or submanifests."""
    try:
        manifest = ET.fromstring(data)
    except ET.ParseError as error:
        raise SourceError('Malformed manifest XML') from error
    if manifest.tag != 'manifest' or manifest.find('include') is not None or manifest.find('submanifest') is not None:
        raise SourceError('Unexpected manifest structure')
    default = manifest.find('default')
    if default is None or default.get('revision') != 'refs/tags/android-17.0.0_r1':
        raise SourceError('Unexpected AOSP base')
    projects = []
    paths = set()
    for entry in manifest.findall('project'):
        name = relative(entry.get('path', entry.get('name'))).as_posix()
        revision = entry.get('revision', '')
        if name in paths or re.fullmatch(r'[0-9a-f]{40}', revision) is None:
            raise SourceError('Duplicate path or non-commit project revision')
        if 'notdefault' in entry.get('groups', '').split(','):
            raise SourceError('Unexpected excluded project in this exact generation')
        paths.add(name)
        projects.append({'path': name, 'revision': revision,
                         'remote': entry.get('remote', default.get('remote')),
                         'groups': entry.get('groups', '')})
    if len(projects) != PROJECT_COUNT:
        raise SourceError('Unexpected declared project count')
    return sorted(projects, key=lambda entry: entry['path'])


def check_tracked_clean(path):
    for args in [('diff', '--name-only', 'HEAD', '--'),
                 ('diff', '--cached', '--name-only', '--')]:
        if run(path, *args)[1]:
            raise SourceError('Tracked or staged changes in ' + str(path))


def check_selection(root):
    try:
        wrapper = ET.fromstring((root / '.repo/manifest.xml').read_bytes())
    except ET.ParseError as error:
        raise SourceError('Malformed active manifest wrapper') from error
    if (wrapper.tag != 'manifest' or wrapper.attrib or len(wrapper) != 1
            or wrapper[0].tag != 'include' or wrapper[0].attrib != {'name': 'default.xml'}):
        raise SourceError('Unexpected active manifest wrapper')
    local = root / '.repo/local_manifests'
    if local.exists() and any(local.iterdir()):
        raise SourceError('Local manifest overrides present before M1 completion')
    if (root / '.repo/local_manifest.xml').exists():
        raise SourceError('Legacy local manifest override present')
    # M0 selected the default Linux profile. This signed release already omits
    # Darwin-only projects, unlike the earlier direct-AOSP manifest.
    _, groups = run(root / '.repo/manifests.git', 'config', '--get', 'manifest.groups', allowed=(0, 1))
    if groups.strip():
        raise SourceError('Custom manifest groups are outside this M1 profile')
    _, platform = run(root / '.repo/manifests.git', 'config', '--get', 'manifest.platform', allowed=(0, 1))
    if platform.strip() not in (b'', b'auto', b'linux'):
        raise SourceError('Unexpected host platform selection')
    return {'groups': 'default Linux; no custom group override', 'excluded_projects': []}


def check_project(root, project):
    path = root / relative(project['path'])
    try:
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not (path / '.git').exists():
            raise SourceError('Missing or non-contained project')
        top = Path(run(path, 'rev-parse', '--show-toplevel')[1].decode().strip()).resolve()
        if top != path.resolve():
            raise SourceError('Git worktree is not the declared project directory')
        head = run(path, 'rev-parse', 'HEAD')[1].decode().strip()
        if head != project['revision']:
            raise SourceError('Project HEAD differs from manifest')
        check_tracked_clean(path)
        return {**project, 'head': head, 'verdict': 'PASS'}
    except (SourceError, OSError, subprocess.SubprocessError) as error:
        return {**project, 'verdict': 'FAIL', 'failure': str(error)}


def inspect(root, allowed_signers):
    root = root.resolve()
    allowed_signers = allowed_signers.resolve()
    if digest(allowed_signers.read_bytes()) != SIGNERS_SHA256:
        raise SourceError('Allowed-signers bytes differ from the approved trust input')
    manifest_repo = root / '.repo/manifests'
    manifest = (manifest_repo / 'default.xml').read_bytes()
    if digest(manifest) != MANIFEST_SHA256:
        raise SourceError('Manifest bytes differ from approved generation')
    if run(manifest_repo, 'rev-parse', 'HEAD')[1].decode().strip() != MANIFEST_COMMIT:
        raise SourceError('Manifest HEAD differs from approved generation')
    if run(manifest_repo, 'rev-parse', 'refs/tags/' + TAG)[1].decode().strip() != TAG_OBJECT:
        raise SourceError('Manifest tag object differs')
    if run(manifest_repo, 'rev-parse', 'refs/tags/' + TAG + '^{commit}')[1].decode().strip() != MANIFEST_COMMIT:
        raise SourceError('Manifest tag target differs')
    check_tracked_clean(manifest_repo)
    run(manifest_repo, '-c', 'gpg.ssh.program=/usr/bin/ssh-keygen',
        '-c', 'gpg.ssh.allowedSignersFile=' + str(allowed_signers), 'verify-tag', TAG)
    tool = root / '.repo/repo'
    if run(tool, 'rev-parse', 'HEAD')[1].decode().strip() != REPO_COMMIT:
        raise SourceError('Repo tool revision differs')
    check_tracked_clean(tool)
    selection = check_selection(root)
    projects = parse_projects(manifest)
    # Read-only checks, bounded to the same eight-job profile as source sync.
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda p: check_project(root, p), projects))
    passed = sum(p['verdict'] == 'PASS' for p in results)
    return {'schema': 1, 'verdict': 'PASS_PINNED_SOURCE_HEADS' if passed == len(projects) else 'FAIL',
            'release': TAG, 'manifest_commit': MANIFEST_COMMIT, 'manifest_tag': TAG_OBJECT,
            'manifest_sha256': MANIFEST_SHA256, 'tag_signature_verified': True,
            'trust_bootstrap': 'approved official-HTTPS allowed-signers input, not a phone identity audit',
            'repo_commit': REPO_COMMIT, 'selection': selection,
            'declared_projects': len(projects), 'verified_projects': passed, 'projects': results,
            'untracked_files_audited': False, 'prebuilt_materialization_verified': False,
            'build_proved': False, 'runtime_proved': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--allowed-signers', required=True, type=Path)
    parser.add_argument('--evidence-dir', required=True, type=Path,
                        help='NEW directory outside this checkout and the source root')
    args = parser.parse_args(argv)
    os.umask(0o077)
    evidence_created = False
    try:
        evidence = args.evidence_dir.resolve()
        if evidence.is_relative_to(ROOT) or evidence.is_relative_to(args.source_root.resolve()):
            raise SourceError('Evidence directory must be outside source trees')
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        evidence_created = True
        report = inspect(args.source_root, args.allowed_signers)
        (evidence / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({key: value for key, value in report.items() if key != 'projects'}, indent=2))
        return 0 if report['verdict'] == 'PASS_PINNED_SOURCE_HEADS' else 1
    except (SourceError, OSError, ValueError, subprocess.SubprocessError) as error:
        if evidence_created:
            try:
                (evidence / 'result.json').write_text(json.dumps(
                    {'schema': 1, 'verdict': 'FAIL', 'failure': str(error)}, indent=2) + '\n')
            except OSError:
                pass  # stderr still records failure if evidence storage itself failed.
        print('Source verification failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
