#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact optional lab writer route. Normal framework admission refuses this adaptation."""
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
FILE = PREFIX + 'PackageManagerShellCommand.java'
ADDED = PREFIX + 'NativePrincipalWriterFixture.java'
HELPER = ROOT / 'tests/native-identity/writer/NativePrincipalWriterFixture.java'
PROFILE = ROOT / 'patches/grapheneos-2026081300/native-identity-writer.json'
PATCH = ROOT / 'patches/grapheneos-2026081300/native-identity-writer.patch'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate writer fixture profile key')
        result[name] = value
    return result


def profile():
    value = json.loads(PROFILE.read_text(), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite profile value')))
    if (type(value['version']) is not int or value['version'] != 1
            or value['project'] != PROJECT or value['head'] != HEAD
            or value['file']['path'] != FILE or value['added']['path'] != ADDED
            or value['added']['source'] != HELPER.relative_to(ROOT).as_posix()
            or value['native_execution_enabled'] is not False or value['lab_only'] is not True
            or value['patch_sha256'] != sha(PATCH.read_bytes())
            or value['added']['sha256'] != sha(HELPER.read_bytes())):
        raise ValueError('writer fixture profile drift')
    if re.findall(r'^(?:---|\+\+\+) (.+)$', PATCH.read_text(), re.M) != ['a/' + FILE, 'b/' + FILE]:
        raise ValueError('writer fixture patch scope')
    text = HELPER.read_text()
    allowed_imports = {'android.os.Binder', 'android.os.Build', 'android.os.Process',
                       'com.android.server.LocalServices', 'java.io.PrintWriter',
                       'java.security.SecureRandom', 'java.util.Set',
                       'org.json.JSONException', 'org.json.JSONObject'}
    if set(re.findall(r'^import ([^;]+);$', text, re.M)) != allowed_imports:
        raise ValueError('writer fixture import surface drift')
    if set(re.findall(r'\bmanager\.([A-Za-z]+)\(', text)) != {'select', 'find', 'prepare', 'commit', 'identity', 'phase'}:
        raise ValueError('writer fixture manager API surface drift')
    for forbidden in ('beginRetirement(', 'finishRetirementAfterQuiescence(', 'initializeNew(',
                      'NativeIdentityStore', 'NativeIdentityPersistence', 'reservePending(',
                      'Runtime.getRuntime()', 'ProcessBuilder', 'PackageManagerService',
                      'new NativePrincipalManager(', 'new NativePrincipalPins.', 'java.lang.reflect',
                      '.forName(', '.getDeclared', 'ClassLoader', 'MethodHandle', '.invoke(',
                      'Unsafe', 'System.load', 'setAccessible('):
        if forbidden in text:
            raise ValueError('writer fixture escaped its bounded API')
    return value


def targets(original, value):
    if sha(original) != value['file']['upstream_sha256']:
        raise ValueError('writer fixture pinned source differs')
    with tempfile.TemporaryDirectory(prefix='andrix-writer-fixture-') as directory:
        scratch = Path(directory)
        path = scratch / FILE
        path.parent.mkdir(parents=True)
        path.write_bytes(original)
        result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
                                 '--no-backup-if-mismatch', '-p1', '-i', str(PATCH)],
                                cwd=scratch, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('writer fixture exact patch failed')
        if ({p.relative_to(scratch).as_posix() for p in scratch.rglob('*') if p.is_file()} != {FILE}
                or any(p.is_symlink() for p in scratch.rglob('*'))):
            raise ValueError('writer fixture output scope')
        target = path.read_bytes()
    if sha(target) != value['file']['candidate_sha256']:
        raise ValueError('writer fixture candidate differs')
    return {FILE: target, ADDED: HELPER.read_bytes()}


def inspect_files(project):
    if project.resolve(strict=True) != project or source.run(project, 'rev-parse', 'HEAD')[1].decode().strip() != HEAD:
        raise ValueError('writer fixture framework identity')
    value = profile()
    original = {FILE: source.run(project, 'show', 'HEAD:' + FILE)[1], ADDED: None}
    target = targets(original[FILE], value)
    states = {}
    for name in (FILE, ADDED):
        path = project / name
        if path.is_symlink() or path.parent.resolve(strict=True) != path.parent:
            raise ValueError('writer fixture file containment')
        data = path.read_bytes() if path.exists() else None
        if data == original[name]:
            states[name] = 'UPSTREAM'
        elif data == target[name]:
            states[name] = 'ADAPTED'
        else:
            raise ValueError('unrecognized writer fixture modification: ' + name)
    kinds = set(states.values())
    return original, target, {'state': next(iter(kinds)) if len(kinds) == 1 else 'PARTIAL',
                             'files': states, 'profile_sha256': sha(PROFILE.read_bytes()),
                             'lab_only': True, 'native_execution_enabled': False, 'runtime_qualified': False}


def require_admission(result, lab_writer_fixture=False):
    if result['state'] != 'UPSTREAM' and lab_writer_fixture is not True:
        raise ValueError('test-only native writer route requires explicit lab admission')


def main():
    import android_lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--action', choices=('check', 'apply', 'revert'), default='check')
    parser.add_argument('--lab-test-only', action='store_true')
    parser.add_argument('--require-adapted', action='store_true')
    args = parser.parse_args()
    if (args.action != 'check' or args.require_adapted) and not args.lab_test_only:
        raise ValueError('explicit lab test scope required')
    if args.action == 'revert' and args.require_adapted:
        raise ValueError('cannot require adapted state during revert')
    root = args.source_root.resolve(strict=True)
    evidence = args.evidence.resolve()
    if (evidence.exists() or root in evidence.parents or ROOT in evidence.parents
            or android_lifecycle.sealed_ancestor(evidence)):
        raise ValueError('fresh unsealed evidence outside source/repository required')
    project, _, _, companions = android_lifecycle.inspect(root, lab_writer_fixture=args.lab_test_only)
    if args.action == 'apply' and companions['native_principal_pins_companion']['state'] != 'ADAPTED':
        raise ValueError('actual native principal manager adaptation required first')
    original, target, result = inspect_files(project)
    if args.action != 'check':
        wanted = target if args.action == 'apply' else original
        for name in (FILE, ADDED):
            path = project / name
            current = path.read_bytes() if path.exists() else None
            if current != wanted[name]:
                android_lifecycle.replace(path, wanted[name])
    _, _, _, after = android_lifecycle.inspect(root, lab_writer_fixture=args.lab_test_only)
    result.update(action=args.action, state_after=after['native_identity_writer_companion']['state'])
    if args.require_adapted and result['state_after'] != 'ADAPTED':
        raise ValueError('complete writer fixture required')
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
