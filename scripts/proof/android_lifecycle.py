#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Digest-guarded Android CE-observation integration; not a general patch tool."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile

import grapheneos_source as source

ROOT = Path(__file__).resolve().parents[2]
PROJECT = 'frameworks/base'
HEAD = 'aab06a8bd44c4c2b58eeec780fde83baa9d43a40'
PROFILE = ROOT / 'patches/grapheneos-2026081300/owner-lifecycle.json'
PATCH = ROOT / 'patches/grapheneos-2026081300/owner-lifecycle.patch'
FILES = (
    'services/core/java/com/android/server/StorageManagerInternal.java',
    'services/core/java/com/android/server/StorageManagerService.java',
)
ADDED = 'services/core/java/com/android/server/storage/CeStorageAccessTracker.java'
HELPER = ROOT / 'owner/platform/framework/CeStorageAccessTracker.java'
EXTRACTED = ROOT / 'owner/tests/platform/StorageManagerMethods.java.inc'


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
    value = json.loads(PROFILE.read_text(), object_pairs_hook=unique, parse_constant=invalid_constant)
    if (type(value['version']) is not int or value['version'] != 1 or value['project'] != PROJECT or value['head'] != HEAD
            or [row['path'] for row in value['files']] != list(FILES)
            or value['added']['path'] != ADDED
            or value['added']['source'] != HELPER.relative_to(ROOT).as_posix()
            or sha(PATCH.read_bytes()) != value['patch_sha256']
            or sha(HELPER.read_bytes()) != value['added']['sha256']):
        raise ValueError('lifecycle profile/producer drift')
    # Only two exact existing Java files; no renames, mode changes or arbitrary
    # paths. Application happens in private scratch first, never directly in AOSP.
    headers = re.findall(r'^(?:---|\+\+\+) (.+)$', PATCH.read_text(), re.M)
    wanted = [prefix + name for name in FILES for prefix in ('a/', 'b/')]
    if headers != wanted:
        raise ValueError('unexpected patch targets')
    return value


def targets(original, value):
    with tempfile.TemporaryDirectory(prefix='andrix-ce-source-') as temp:
        root = Path(temp)
        for row in value['files']:
            data = original[row['path']]
            if sha(data) != row['upstream_sha256']:
                raise ValueError('pinned upstream bytes differ: ' + row['path'])
            p = root / row['path']
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
            '--no-backup-if-mismatch', '-p1', '-i', str(PATCH)], cwd=root,
            capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('exact scratch patch failed: ' + result.stderr.decode(errors='replace'))
        present = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
        if present != set(FILES) or any(p.is_symlink() for p in root.rglob('*')):
            raise ValueError('unexpected scratch patch output')
        output = {name: (root / name).read_bytes() for name in FILES}
        for row in value['files']:
            if sha(output[row['path']]) != row['candidate_sha256']:
                raise ValueError('adapted-byte drift: ' + row['path'])
    if extracted_methods(output[FILES[1]]) != EXTRACTED.read_bytes():
        raise ValueError('host-tested framework methods differ from adapted source')
    output[ADDED] = HELPER.read_bytes()
    return output


def extracted_methods(data):
    text = data.decode('utf-8')
    result = text.split('package com.android.server;', 1)[0]
    result += ('// SPDX-License-Identifier: Apache-2.0\n'
               '// Exact candidate methods, verified by android_lifecycle.targets; not a parallel implementation.\n')
    for start, end in (
        ('    private void connectVold() {', '    private void servicesReady() {'),
        ('    private void restoreCeUnlockedUsers(IVold vold) {', '    private void onUserUnlocking(int userId) {'),
        ('    public void lockCeStorage(int userId) {', '    @Override\n    public boolean isCeStorageUnlocked('),
        ('    private void resetIfBootedAndConnected() {', '    private void restoreSystemUnlockedUsers('),
        ('    private void restoreSystemUnlockedUsers(', '    // If vold knows'),
        ('        public void unlockCeStorage(@UserIdInt int userId, byte[] secret) {',
         '        @Override\n        public void registerCloudProviderChangeListener('),
    ):
        if text.count(start) != 1 or text.count(end) != 1:
            raise ValueError('ambiguous extracted-method boundary')
        a = text.index(start)
        result += text[a:text.index(end, a)]
    return (result.rstrip() + '\n').encode('utf-8')


def inspect(root):
    root = root.resolve(strict=True)
    project = root / PROJECT
    if project.resolve(strict=True) != project:
        raise ValueError('project containment')
    if source.run(project, 'rev-parse', 'HEAD')[1].decode().strip() != HEAD:
        raise ValueError('wrong framework revision')
    value = profile()
    original = {name: source.run(project, 'show', 'HEAD:' + name)[1] for name in FILES}
    original[ADDED] = None
    target = targets(original, value)
    states = {}
    for name in (*FILES, ADDED):
        p = project / name
        if p.parent.resolve(strict=True) != p.parent or p.is_symlink():
            raise ValueError('file containment: ' + name)
        current = p.read_bytes() if p.exists() else None
        if current == original[name]:
            states[name] = 'UPSTREAM'
        elif current == target[name]:
            states[name] = 'ADAPTED'
        else:
            raise ValueError('unrecognized framework modification: ' + name)
    flags = source.filter_overrides(project)
    modified = source.run(project, *flags, 'diff', '--no-ext-diff', '--no-textconv',
                          '--name-only', 'HEAD', '--')[1].decode().splitlines()
    staged = source.run(project, *flags, 'diff', '--no-ext-diff', '--no-textconv',
                        '--cached', '--name-only', '--')[1].decode().splitlines()
    others = source.run(project, 'ls-files', '--others', '--exclude-standard')[1].decode().splitlines()
    expected_modified = sorted(name for name in FILES if states[name] == 'ADAPTED')
    expected_others = [ADDED] if states[ADDED] == 'ADAPTED' else []
    if staged or sorted(modified) != expected_modified or others != expected_others:
        raise ValueError('other staged/tracked/untracked framework changes')
    state = next(iter(set(states.values()))) if len(set(states.values())) == 1 else 'PARTIAL'
    return project, original, target, {'project': PROJECT, 'head': HEAD, 'state': state,
        'files': states, 'profile_sha256': sha(PROFILE.read_bytes()),
        'new_apk_authority': False, 'synchronous_cleanup_barrier': False, 'runtime_proved': False}


def replace(path, data):
    if data is None:
        path.unlink()  # Only the exact added helper, already byte-validated by inspect.
        return
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.andrix-ce-', delete=False) as out:
        temporary = Path(out.name)
        try:
            out.write(data); out.flush(); os.fsync(out.fileno()); os.fchmod(out.fileno(), mode)
        except BaseException:
            temporary.unlink(); raise
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--action', choices=('check', 'apply', 'revert'), default='check')
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--require-adapted', action='store_true', help='fail if build-ready adaptation is absent')
    args = parser.parse_args()
    if args.require_adapted and args.action == 'revert':
        raise ValueError('cannot require adapted state while reverting')
    root = args.source_root.resolve(strict=True)
    evidence = args.evidence.resolve()
    if (evidence.exists() or root in evidence.parents or ROOT in evidence.parents
            or any((parent / 'SEALED').exists() for parent in evidence.parents)):
        raise ValueError('fresh unsealed evidence outside source/repository required')
    project, original, target, result = inspect(root)
    if args.action != 'check':
        wanted = target if args.action == 'apply' else original
        for name in (*FILES, ADDED):
            path = project / name
            current = path.read_bytes() if path.exists() else None
            if current != wanted[name]:
                replace(path, wanted[name])
    _, _, _, after = inspect(root)
    result.update(action=args.action, state_after=after['state'])
    if args.require_adapted and after['state'] != 'ADAPTED':
        raise ValueError('complete adapted state required for build')
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
