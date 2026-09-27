#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact Package Installer payload sync companion, ordered after package verity.

The candidate is derived from the pinned upstream through the exact package verity
candidate, then this companion's exact patch. Apply requires package verity to be applied;
revert removes only this companion. The package verity inspector recognizes the combined
bytes, so the shared framework fence admits nothing broader than these exact bytes.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
import tempfile

import grapheneos_source as source
import package_verity as verity

ROOT = Path(__file__).resolve().parents[2]
PROJECT = verity.PROJECT
HEAD = verity.HEAD
FILE = verity.FILE
PROFILE = ROOT / 'patches/grapheneos-2026081300/package-installer-payload-sync.json'
PATCH = ROOT / 'patches/grapheneos-2026081300/package-installer-payload-sync.patch'
HOST_PROFILE = ROOT / 'tests/installer-durability/pis-reverse-write-sync.candidate.json'
HOST_PATCH = ROOT / 'tests/installer-durability/pis-reverse-write-sync.candidate.patch'
HOST_BASE_FRAGMENT = ROOT / 'tests/installer-durability/PisReverseWriteFragment.base.java.inc'
HOST_FRAGMENT = ROOT / 'tests/installer-durability/PisReverseWriteFragment.candidate.java.inc'
# First lines of the two exact source ranges held by each host fragment fixture.
REGIONS = ('    @Override\n    public void write(String name, long offsetBytes, long lengthBytes,\n',
           '    /**\n     * If anybody is reading or writing data of the session, throw an')
KEYS = {'version', 'project', 'head', 'file', 'requires', 'requires_sha256', 'upstream_sha256',
        'base_sha256', 'candidate_sha256', 'patch_sha256', 'host_profile', 'host_profile_sha256',
        'host_patch', 'host_base_fragment_sha256', 'host_fragment_sha256', 'scope'}
HOST_KEYS = ('head', 'file', 'upstream_sha256', 'base_sha256', 'candidate_sha256', 'patch_sha256')


def sha(data):
    return verity.sha(data)


def strict_json(path):
    return json.loads(path.read_text(), object_pairs_hook=verity.unique,
                      parse_constant=verity.invalid_constant)


def relative(path):
    return path.relative_to(ROOT).as_posix()


def profile():
    """Validated profile.

    The package verity profile is pinned here by its exact bytes rather than through
    package_verity.profile(), so the lazy recognition inside package_verity.inspect_file
    never calls back into package verity validation.
    """
    value = strict_json(PROFILE)
    required = strict_json(verity.PROFILE)
    host = strict_json(HOST_PROFILE)
    if (set(value) != KEYS or type(value['version']) is not int or value['version'] != 1
            or value['project'] != PROJECT or value['head'] != HEAD or value['file'] != FILE
            or value['requires'] != relative(verity.PROFILE)
            or value['requires_sha256'] != sha(verity.PROFILE.read_bytes())
            or value['upstream_sha256'] != required['upstream_sha256']
            or value['base_sha256'] != required['candidate_sha256']
            or sha(verity.EXTRACTED.read_bytes()) != required['method_fixture_sha256']
            or value['patch_sha256'] != sha(PATCH.read_bytes())
            or value['host_profile'] != relative(HOST_PROFILE)
            or value['host_profile_sha256'] != sha(HOST_PROFILE.read_bytes())
            or value['host_patch'] != relative(HOST_PATCH)
            or value['host_base_fragment_sha256'] != sha(HOST_BASE_FRAGMENT.read_bytes())
            or value['host_fragment_sha256'] != sha(HOST_FRAGMENT.read_bytes())):
        raise ValueError('payload sync profile drift')
    if re.findall(r'^(?:---|\+\+\+) (.+)$', PATCH.read_text(), re.M) != ['a/' + FILE, 'b/' + FILE]:
        raise ValueError('unexpected payload sync patch target')
    # The host tested candidate keeps its own record. Both copies of the patch must agree.
    if (HOST_PATCH.read_bytes() != PATCH.read_bytes()
            or any(host.get(key) != value[key] for key in HOST_KEYS)
            or host.get('base_profile_sha256') != value['requires_sha256']
            or host.get('base_fragment_sha256') != value['host_base_fragment_sha256']
            or host.get('candidate_fragment_sha256') != value['host_fragment_sha256']):
        raise ValueError('payload sync differs from its host tested candidate')
    return value


def patched(data, patch=None):
    """Apply one exact single file patch forward in private scratch, never in a checkout."""
    patch = PATCH if patch is None else patch
    with tempfile.TemporaryDirectory(prefix='andrix-payload-sync-') as directory:
        scratch = Path(directory)
        target = scratch / FILE
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
                                 '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                                cwd=scratch, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('exact payload sync patch failed: '
                             + result.stderr.decode(errors='replace'))
        if ({p.relative_to(scratch).as_posix() for p in scratch.rglob('*') if p.is_file()}
                != {FILE} or any(p.is_symlink() for p in scratch.rglob('*'))):
            raise ValueError('unexpected payload sync patch output')
        return target.read_bytes()


def tested_regions(fixture):
    """The two exact source ranges of a host fragment fixture, without its license header."""
    text = fixture.read_bytes().decode()
    if any(text.count(start) != 1 for start in REGIONS):
        raise ValueError('ambiguous host fragment fixture')
    first, second = (text.index(start) for start in REGIONS)
    if second <= first:
        raise ValueError('host fragment fixture order')
    return text[first:second].encode(), text[second:].encode()


def combined(verity_target, value=None):
    """Exact companion bytes from the exact package verity candidate. Reads no checkout."""
    value = profile() if value is None else value
    if sha(verity_target) != value['base_sha256']:
        raise ValueError('payload sync requires the exact package verity candidate')
    data = patched(verity_target)
    if sha(data) != value['candidate_sha256']:
        raise ValueError('payload sync candidate differs')
    if verity.extracted_method(data) != verity.EXTRACTED.read_bytes():
        raise ValueError('payload sync changed the package verity correction')
    for source_bytes, fixture in ((verity_target, HOST_BASE_FRAGMENT), (data, HOST_FRAGMENT)):
        if any(source_bytes.count(region) != 1 for region in tested_regions(fixture)):
            raise ValueError('host tested fragment differs from the actual source')
    return data


def derive(original, value=None):
    """Pinned upstream, then the exact package verity candidate, then this exact patch."""
    value = profile() if value is None else value
    verity_target = verity.candidate(original, verity.profile())
    return verity_target, combined(verity_target, value)


def inspect_file(project):
    """This companion's ordered state. Use inspect() for the whole framework fence."""
    if project.resolve(strict=True) != project:
        raise ValueError('framework project containment')
    if source.run(project, 'rev-parse', 'HEAD')[1].decode().strip() != HEAD:
        raise ValueError('wrong pinned framework revision')
    path = project / FILE
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError('package file containment')
    value = profile()
    original = source.run(project, 'show', 'HEAD:' + FILE)[1]
    verity_target, target = derive(original, value)
    current = path.read_bytes()
    if current == original:
        state, verity_state = 'UPSTREAM', 'UPSTREAM'
    elif current == verity_target:
        state, verity_state = 'UPSTREAM', 'ADAPTED'
    elif current == target:
        state, verity_state = 'ADAPTED', 'ADAPTED'
    else:
        raise ValueError('unrecognized Package Installer modification')
    # Each component is named with its state and profile hash. The package verity profile
    # hash was checked against its exact bytes by profile().
    return verity_target, target, {
        'project': PROJECT, 'head': HEAD, 'file': FILE, 'state': state,
        'profile_sha256': sha(PROFILE.read_bytes()), 'order': 'after package verity',
        'package_verity_state': verity_state,
        'package_verity_profile_sha256': value['requires_sha256'],
        'directory_or_install_durability_claimed': False, 'runtime_proved': False}


def inspect(root):
    """The whole framework fence first, then this companion's ordered state."""
    import android_lifecycle as lifecycle
    project, _, _, fence = lifecycle.inspect(root)
    verity_target, target, result = inspect_file(project)
    package = fence['package_verity_companion']
    if (package['state'] != result['package_verity_state']
            or package['profile_sha256'] != result['package_verity_profile_sha256']
            or package['payload_sync_companion'] != {'state': result['state'],
                                                     'profile_sha256': result['profile_sha256']}):
        raise ValueError('package installer companion views disagree')
    result['package_verity_companion'] = package
    result['CE_companion_state'] = fence['state']
    return project, verity_target, target, result


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
    project, verity_target, target, result = inspect(root)
    if args.action == 'apply':
        if result['package_verity_state'] != 'ADAPTED':
            raise ValueError('apply the package verity adaptation first')
        if result['state'] != 'ADAPTED':
            lifecycle.replace(project / FILE, target)
    elif args.action == 'revert' and result['state'] == 'ADAPTED':
        # Remove only this companion. The exact package verity candidate stays in place.
        lifecycle.replace(project / FILE, verity_target)
    _, _, _, after = inspect(root)
    result.update(action=args.action, state_after=after['state'],
                  package_verity_state_after=after['package_verity_state'])
    # Only the exact combined state has this companion applied.
    if args.require_adapted and after['state'] != 'ADAPTED':
        raise ValueError('package installer payload sync required for build')
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
