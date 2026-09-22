#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact pinned Package Installer adaptation, with the CE companion fenced too."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import tempfile

import grapheneos_source as source

ROOT = Path(__file__).resolve().parents[2]
PROJECT = 'frameworks/base'
HEAD = 'aab06a8bd44c4c2b58eeec780fde83baa9d43a40'
FILE = 'services/core/java/com/android/server/pm/PackageInstallerSession.java'
PROFILE = ROOT/'patches/grapheneos-2026081300/package-verity.json'
PATCH = ROOT/'patches/grapheneos-2026081300/package-verity.patch'
EXTRACTED = ROOT/'tests/staged-apk-verity/PackageInstallerMethod.java.inc'
UPSTREAM_METHOD = ROOT/'tests/staged-apk-verity/PackageInstallerMethod.upstream.java.inc'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate profile key')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('non-finite profile value')


def profile():
    result = json.loads(PROFILE.read_text(), object_pairs_hook=unique,
                        parse_constant=invalid_constant)
    if (type(result['version']) is not int or result['version'] != 1
            or result['project'] != PROJECT or result['head'] != HEAD
            or result['file'] != FILE or result['patch_sha256'] != sha(PATCH.read_bytes())
            or result['method_fixture_sha256'] != sha(EXTRACTED.read_bytes())
            or result['upstream_method_sha256'] != sha(UPSTREAM_METHOD.read_bytes())):
        raise ValueError('package verification profile drift')
    if re.findall(r'^(?:---|\+\+\+) (.+)$', PATCH.read_text(), re.M) != ['a/'+FILE, 'b/'+FILE]:
        raise ValueError('unexpected package verification patch target')
    return result


def extracted_method(data):
    text = data.decode()
    start = '    @GuardedBy("mLock")\n    private void enableFsVerityToAddedApksWithIdsig()'
    end = '    @GuardedBy("mLock")\n    private List<ApkLite> getAddedApkLitesLocked()'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('ambiguous method fixture boundaries')
    header = text.split('package com.android.server.pm;', 1)[0]
    return (header+'// Exact method fixture; checked by the pinned source adapter.\n'
            + text[text.index(start):text.index(end)]).encode()


def candidate(original, value):
    if (sha(original) != value['upstream_sha256']
            or extracted_method(original) != UPSTREAM_METHOD.read_bytes()):
        raise ValueError('pinned Package Installer bytes or upstream method differ')
    with tempfile.TemporaryDirectory(prefix='andrix-package-verity-') as directory:
        scratch = Path(directory)
        target = scratch/FILE
        target.parent.mkdir(parents=True)
        target.write_bytes(original)
        result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
            '--no-backup-if-mismatch', '-p1', '-i', str(PATCH)], cwd=scratch,
            capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('exact package patch failed: '+result.stderr.decode(errors='replace'))
        if ({p.relative_to(scratch).as_posix() for p in scratch.rglob('*') if p.is_file()}
                != {FILE} or any(p.is_symlink() for p in scratch.rglob('*'))):
            raise ValueError('unexpected package patch output')
        data = target.read_bytes()
    if sha(data) != value['candidate_sha256'] or extracted_method(data) != EXTRACTED.read_bytes():
        raise ValueError('package candidate or tested method differs')
    return data


def inspect_file(project):
    """Known companion for the complete framework fence, not a broad allowance."""
    if project.resolve(strict=True) != project:
        raise ValueError('framework project containment')
    if source.run(project, 'rev-parse', 'HEAD')[1].decode().strip() != HEAD:
        raise ValueError('wrong pinned framework revision')
    path = project/FILE
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError('package file containment')
    value = profile()
    original = source.run(project, 'show', 'HEAD:'+FILE)[1]
    target = candidate(original, value)
    current = path.read_bytes()
    if current == original:
        state = 'UPSTREAM'
    elif current == target:
        state = 'ADAPTED'
    else:
        raise ValueError('unrecognized Package Installer modification')
    return original, target, {'project': PROJECT, 'head': HEAD, 'file': FILE, 'state': state,
        'profile_sha256': sha(PROFILE.read_bytes()), 'signature_checks_bypassed': False,
        'runtime_proved': False}


def inspect(root):
    # Local import avoids a cycle: the lifecycle inspector calls inspect_file,
    # which checks only this exact companion. It then checks the complete tree.
    import android_lifecycle as lifecycle
    project, _, _, ce = lifecycle.inspect(root)
    original, target, result = inspect_file(project)
    result['CE_companion_state'] = ce['state']
    return project, original, target, result


def main():
    import android_lifecycle as lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--action', choices=('check', 'apply', 'revert'), default='check')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--require-adapted', action='store_true')
    args = parser.parse_args()
    if args.require_adapted and args.action == 'revert':
        raise ValueError('cannot require adapted state while reverting')
    root = args.source_root.resolve(strict=True)
    evidence = args.evidence.resolve()
    if (evidence.exists() or root in evidence.parents or ROOT in evidence.parents
            or lifecycle.sealed_ancestor(evidence)):
        raise ValueError('fresh unsealed evidence outside source and repository required')
    project, original, target, result = inspect(root)
    if args.action != 'check':
        wanted = target if args.action == 'apply' else original
        if (project/FILE).read_bytes() != wanted:
            lifecycle.replace(project/FILE, wanted)
    _, _, _, after = inspect(root)
    result.update(action=args.action, state_after=after['state'])
    if args.require_adapted and after['state'] != 'ADAPTED':
        raise ValueError('complete package adaptation required for build')
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
