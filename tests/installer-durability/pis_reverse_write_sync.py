#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check only provenance guard for the Package Installer reverse write fsync candidate.

It recognizes the exact pinned Package Installer bytes that already carry the accepted
fs-verity correction, rebuilds the candidate in private scratch and compares the exact
fragments used by the host harness. It never applies or reverts Android source and it
is not part of the framework change fence.
"""
from pathlib import Path
import argparse
import json
import re
import resource
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import package_verity as verity  # noqa: E402  accepted companion, only read here

PROJECT = verity.PROJECT
HEAD = verity.HEAD
FILE = verity.FILE
FILEUTILS = 'core/java/android/os/FileUtils.java'
PROFILE = HERE / 'pis-reverse-write-sync.candidate.json'
PATCH = HERE / 'pis-reverse-write-sync.candidate.patch'
BASE_FRAGMENT = HERE / 'PisReverseWriteFragment.base.java.inc'
CANDIDATE_FRAGMENT = HERE / 'PisReverseWriteFragment.candidate.java.inc'
SYNC_FRAGMENT = HERE / 'PisFileUtilsSync.pinned.java.inc'
HARNESS = HERE / 'PisReverseWriteHarness.java.in'
ATTRIBUTION = '// Exact fragments; checked by tests/installer-durability/pis_reverse_write_sync.py.\n'
KEYS = {'version', 'status', 'integrated', 'project', 'head', 'file', 'base_profile',
        'base_profile_sha256', 'upstream_sha256', 'base_sha256', 'candidate_sha256',
        'patch_sha256', 'base_fragment_sha256', 'candidate_fragment_sha256',
        'fileutils_file', 'fileutils_sha256', 'fileutils_sync_fragment_sha256', 'scope'}

# From the public write() through doWriteInternal(), then the sealing check that the
# placeholder hold must keep failing until the copy has finished.
PIS_REGIONS = (
    ('    @Override\n    public void write(String name, long offsetBytes, long lengthBytes,\n'
     '            ParcelFileDescriptor fd) {\n',
     '    @Override\n    public ParcelFileDescriptor openRead(String name) {\n'),
    ('    /**\n     * If anybody is reading or writing data of the session, throw an'
     ' {@link SecurityException}.\n     */\n    @GuardedBy("mLock")\n'
     '    private void assertNoWriteFileTransfersOpenLocked() {\n',
     '    @Override\n    public void commit(@NonNull IntentSender statusReceiver,'
     ' boolean forTransfer) {\n'),
)
SYNC_REGIONS = (
    ('    /**\n     * Perform an fsync on the given FileOutputStream.',
     '    /**\n     * @deprecated use {@link #copy(File, File)} instead.\n     * @hide\n     */\n'
     '    @UnsupportedAppUsage\n    @Deprecated\n'
     '    public static boolean copyFile(File srcFile, File destFile) {\n'),
)
GIB = 1 << 30


def sha(data):
    return verity.sha(data)


def extract(data, regions, package):
    text = data.decode()
    if text.count(package) != 1:
        raise ValueError('ambiguous source header')
    result = text.split(package, 1)[0] + ATTRIBUTION
    for start, end in regions:
        if text.count(start) != 1 or text.count(end) != 1:
            raise ValueError('ambiguous fragment boundary')
        first, last = text.index(start), text.index(end)
        if last <= first:
            raise ValueError('fragment boundary order')
        result += text[first:last]
    return result.encode()


def pis_fragment(data):
    return extract(data, PIS_REGIONS, 'package com.android.server.pm;')


def sync_fragment(data):
    return extract(data, SYNC_REGIONS, 'package android.os;')


def profile():
    value = json.loads(PROFILE.read_text(), object_pairs_hook=verity.unique,
                       parse_constant=verity.invalid_constant)
    base = verity.profile()  # also checks the accepted companion's own fixtures
    if (set(value) != KEYS or type(value['version']) is not int or value['version'] != 1
            or value['status'] != 'candidate' or value['integrated'] is not False
            or value['project'] != PROJECT or value['head'] != HEAD or value['file'] != FILE
            or value['base_profile'] != verity.PROFILE.relative_to(ROOT).as_posix()
            or value['base_profile_sha256'] != sha(verity.PROFILE.read_bytes())
            or value['upstream_sha256'] != base['upstream_sha256']
            or value['base_sha256'] != base['candidate_sha256']
            or value['patch_sha256'] != sha(PATCH.read_bytes())
            or value['base_fragment_sha256'] != sha(BASE_FRAGMENT.read_bytes())
            or value['candidate_fragment_sha256'] != sha(CANDIDATE_FRAGMENT.read_bytes())
            or value['fileutils_file'] != FILEUTILS
            or value['fileutils_sync_fragment_sha256'] != sha(SYNC_FRAGMENT.read_bytes())):
        raise ValueError('reverse write candidate profile drift')
    if re.findall(r'^(?:---|\+\+\+) (.+)$', PATCH.read_text(), re.M) != ['a/' + FILE, 'b/' + FILE]:
        raise ValueError('unexpected reverse write patch target')
    return value


def patched(data, patch, *, reverse=False):
    """Apply one exact single file patch in private scratch, never in a checkout.

    --forward is always passed: in batch mode GNU patch otherwise treats a reverse request
    on unpatched bytes as a reversed patch and applies it forward.
    """
    with tempfile.TemporaryDirectory(prefix='andrix-pis-reverse-write-') as directory:
        scratch = Path(directory)
        target = scratch / FILE
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        result = subprocess.run(['/usr/bin/patch', '--batch', '--forward',
                                 *(['--reverse'] if reverse else []), '--fuzz=0',
                                 '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                                cwd=scratch, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('exact patch failed: ' + result.stderr.decode(errors='replace'))
        if ({p.relative_to(scratch).as_posix() for p in scratch.rglob('*') if p.is_file()}
                != {FILE} or any(p.is_symlink() for p in scratch.rglob('*'))):
            raise ValueError('unexpected patch output')
        return target.read_bytes()


def upstream(base, value):
    """The base must be exactly pinned upstream plus the accepted fs-verity patch."""
    data = patched(base, verity.PATCH, reverse=True)
    if (sha(data) != value['upstream_sha256']
            or verity.extracted_method(data) != verity.UPSTREAM_METHOD.read_bytes()):
        raise ValueError('base is not the accepted fs-verity candidate of pinned upstream')
    if pis_fragment(data) != BASE_FRAGMENT.read_bytes():
        raise ValueError('reverse write fragment differs from pinned upstream')
    return data


def candidate(base, value):
    if sha(base) != value['base_sha256'] or pis_fragment(base) != BASE_FRAGMENT.read_bytes():
        raise ValueError('pinned Package Installer bytes or reverse write fragment differ')
    data = patched(base, PATCH)
    if sha(data) != value['candidate_sha256'] or pis_fragment(data) != CANDIDATE_FRAGMENT.read_bytes():
        raise ValueError('reverse write candidate or tested fragment differs')
    if verity.extracted_method(data) != verity.EXTRACTED.read_bytes():
        raise ValueError('accepted fs-verity correction not preserved')
    return data


def inspect_bytes(pis, fileutils):
    value = profile()
    if sha(fileutils) != value['fileutils_sha256'] or sync_fragment(fileutils) != SYNC_FRAGMENT.read_bytes():
        raise ValueError('pinned FileUtils bytes or sync fragment differ')
    digest = sha(pis)
    if digest == value['base_sha256']:
        state, base = 'BASE', pis
    elif digest == value['candidate_sha256']:
        state, base = 'CANDIDATE', patched(pis, PATCH, reverse=True)
    else:
        raise ValueError('unrecognized Package Installer bytes')
    upstream(base, value)
    rebuilt = candidate(base, value)
    if state == 'CANDIDATE' and rebuilt != pis:
        raise ValueError('candidate reconstruction differs')
    return {'project': PROJECT, 'file': FILE, 'state': state,
            'base_sha256': value['base_sha256'], 'candidate_sha256': value['candidate_sha256'],
            'upstream_sha256': value['upstream_sha256'],
            'fs_verity_correction_preserved': True, 'git_head_checked': False,
            'integrated': False, 'android_compiled': False, 'runtime_proved': False}


def render(fragment, sync):
    """Host harness source with the exact fragments inserted verbatim."""
    template = HARNESS.read_text()
    fragment, sync = fragment.decode(), sync.decode()
    if (template.count('@FRAGMENT@') != 1 or template.count('@FILEUTILS_SYNC@') != 1
            or '@FRAGMENT@' in fragment + sync or '@FILEUTILS_SYNC@' in fragment + sync):
        raise ValueError('harness slots')
    return template.replace('@FRAGMENT@', fragment).replace('@FILEUTILS_SYNC@', sync)


def _limit(text):
    return None if text == 'max' else int(text)


def resource_guard(cgroup_root=Path('/sys/fs/cgroup'), membership=Path('/proc/self/cgroup')):
    """Require bounded memory, swap, CPU, tasks and disabled core dumps before a JVM.

    The cgroup limits may sit on this process's cgroup or an ancestor. Nothing is created
    or changed; a JVM check must be skipped or failed when a reason is returned.
    """
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        return 'core dumps must be disabled with both limits zero'
    try:
        lines = membership.read_text().splitlines()
    except OSError as error:
        return 'cgroup membership unreadable: %s' % error
    unified = [line[3:] for line in lines if line.startswith('0::')]
    if len(unified) != 1 or not unified[0].startswith('/') or '..' in unified[0].split('/'):
        return 'no single unified cgroup membership'
    leaf = cgroup_root / unified[0].lstrip('/')
    chain = [leaf, *leaf.parents]
    if cgroup_root not in chain:
        return 'cgroup path outside the mounted hierarchy'
    chain = chain[:chain.index(cgroup_root) + 1]
    found = {'memory.max': [], 'memory.swap.max': [], 'pids.max': [], 'cpu.max': []}
    try:
        for directory in chain:
            for name, values in found.items():
                path = directory / name
                if not path.exists():
                    continue
                text = path.read_text().strip()
                if name == 'cpu.max':
                    quota, period = text.split()
                    if quota != 'max':
                        values.append(int(quota) / int(period))
                elif _limit(text) is not None:
                    values.append(_limit(text))
    except (OSError, ValueError) as error:
        return 'cgroup limits unreadable: %s' % error
    effective = {name: min(values) if values else None for name, values in found.items()}
    if (effective['memory.max'] is None or effective['memory.max'] > 2 * GIB
            or effective['memory.swap.max'] != 0
            or effective['cpu.max'] is None or effective['cpu.max'] > 2
            or effective['pids.max'] is None or effective['pids.max'] > 256):
        return 'required bounds absent: %s' % json.dumps(effective, sort_keys=True)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True,
                        help='Android checkout root; only two files are read')
    args = parser.parse_args()
    project = args.source_root.resolve(strict=True) / PROJECT
    paths = [project / FILE, project / FILEUTILS]
    for path in paths:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError('source file containment')
    print(json.dumps(inspect_bytes(*(path.read_bytes() for path in paths)), indent=2))


if __name__ == '__main__':
    main()
