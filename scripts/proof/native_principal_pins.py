#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact Package Manager native UID reservation adaptation, not a general patch tool."""
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
PREFIX = 'services/core/java/com/android/server/pm/'
FILES = tuple(PREFIX + name + '.java' for name in (
    'AppIdSettingMap', 'Settings', 'PackageManagerService', 'DeletePackageHelper',
    'InstallPackageHelper', 'ResilientAtomicFile', 'AppDataHelper', 'StorageEventHelper',
    'RemovePackageHelper', 'PackageManagerException'))
ADDED = {PREFIX + name + '.java': ROOT / 'owner/platform/framework' / (name + '.java')
         for name in ('NativePrincipalPins', 'NativePrincipalManager', 'NativeIdentityRecords',
                      'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery')}
FIXTURES = {PREFIX + name + '.java': ROOT / 'owner/tests/platform' / (name + '.java.inc')
            for name in ('AppIdSettingMap', 'ResilientAtomicFile')}
PROFILE = ROOT / 'patches/grapheneos-2026081300/native-principal-pins.json'
PATCH = ROOT / 'patches/grapheneos-2026081300/native-principal-pins.patch'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate profile key')
        result[key] = value
    return result


def profile():
    value = json.loads(PROFILE.read_text(), object_pairs_hook=unique,
                       parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v)))
    if (type(value['version']) is not int or value['version'] != 1
            or value['project'] != PROJECT or value['head'] != HEAD
            or [row['path'] for row in value['files']] != list(FILES)
            or [row['path'] for row in value['added']] != list(ADDED)
            or sha(PATCH.read_bytes()) != value['patch_sha256']):
        raise ValueError('native principal profile drift')
    for row in value['added']:
        helper = ADDED[row['path']]
        if row['source'] != helper.relative_to(ROOT).as_posix() or sha(helper.read_bytes()) != row['sha256']:
            raise ValueError('native principal helper drift')
    if re.findall(r'^(?:---|\+\+\+) (.+)$', PATCH.read_text(), re.M) != [
            prefix + name for name in FILES for prefix in ('a/', 'b/')]:
        raise ValueError('unexpected native principal patch targets')
    for row in value['fixtures']:
        if row['path'] not in FIXTURES or row['source'] != FIXTURES[row['path']].relative_to(ROOT).as_posix() or sha(FIXTURES[row['path']].read_bytes()) != row['sha256']:
            raise ValueError('native principal fixture drift')
    if [row['path'] for row in value['fixtures']] != list(FIXTURES):
        raise ValueError('native principal fixture set drift')
    return value


def targets(original, value):
    with tempfile.TemporaryDirectory(prefix='andrix-native-pins-') as directory:
        scratch = Path(directory)
        for row in value['files']:
            data = original[row['path']]
            if sha(data) != row['upstream_sha256']:
                raise ValueError('wrong pinned input: ' + row['path'])
            target = scratch / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
                                 '--no-backup-if-mismatch', '-p1', '-i', str(PATCH)],
                                cwd=scratch, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('exact native principal patch failed: ' + result.stderr.decode(errors='replace'))
        if ({p.relative_to(scratch).as_posix() for p in scratch.rglob('*') if p.is_file()} != set(FILES)
                or any(p.is_symlink() for p in scratch.rglob('*'))):
            raise ValueError('unexpected native principal patch output')
        output = {name: (scratch / name).read_bytes() for name in FILES}
        for row in value['files']:
            if sha(output[row['path']]) != row['candidate_sha256']:
                raise ValueError('native principal candidate drift: ' + row['path'])
    for name, fixture in FIXTURES.items():
        if output[name] != fixture.read_bytes():
            raise ValueError('host tested native principal source differs: ' + name)
    output.update({name: helper.read_bytes() for name, helper in ADDED.items()})
    return output


def inspect_files(project):
    """Exact companion for the shared framework fence, not a path exception."""
    if project.resolve(strict=True) != project or source.run(project, 'rev-parse', 'HEAD')[1].decode().strip() != HEAD:
        raise ValueError('wrong framework root/revision')
    value = profile()
    original = {name: source.run(project, 'show', 'HEAD:' + name)[1] for name in FILES}
    original.update({name: None for name in ADDED})
    target = targets(original, value)
    states = {}
    for name in (*FILES, *ADDED):
        path = project / name
        if path.is_symlink() or path.parent.resolve(strict=True) != path.parent:
            raise ValueError('native principal file containment')
        current = path.read_bytes() if path.exists() else None
        if current == original[name]:
            states[name] = 'UPSTREAM'
        elif current == target[name]:
            states[name] = 'ADAPTED'
        else:
            raise ValueError('unrecognized native principal modification: ' + name)
    kinds = set(states.values())
    return original, target, {'state': next(iter(kinds)) if len(kinds) == 1 else 'PARTIAL',
                              'files': states, 'profile_sha256': sha(PROFILE.read_bytes()),
                              'public_app_authority_added': False, 'runtime_qualified': False}


def inspect(root):
    import android_lifecycle
    project, _, _, companions = android_lifecycle.inspect(root)
    original, target, result = inspect_files(project)
    result['CE_companion_state'] = companions['state']
    result['package_verity_companion'] = companions['package_verity_companion']
    return project, original, target, result


def main():
    import android_lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--action', choices=('check', 'apply', 'revert'), default='check')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--require-adapted', action='store_true')
    args = parser.parse_args()
    if args.action == 'revert' and args.require_adapted:
        raise ValueError('cannot require adapted state while reverting')
    root = args.source_root.resolve(strict=True)
    evidence = args.evidence.resolve()
    if (evidence.exists() or root in evidence.parents or ROOT in evidence.parents
            or android_lifecycle.sealed_ancestor(evidence)):
        raise ValueError('fresh unsealed evidence outside source and repository required')
    project, original, target, result = inspect(root)
    if args.action != 'check':
        wanted = target if args.action == 'apply' else original
        for name in (*FILES, *ADDED):
            path = project / name
            current = path.read_bytes() if path.exists() else None
            if current != wanted[name]:
                android_lifecycle.replace(path, wanted[name])
    _, _, _, after = inspect(root)
    result.update(action=args.action, state_after=after['state'])
    if args.require_adapted and after['state'] != 'ADAPTED':
        raise ValueError('complete native principal adaptation required')
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
