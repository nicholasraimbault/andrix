#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build/freeze signed-source GNU Make for ARM64/Bionic; never launch a guest."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import time

import compiler_package as package
import grapheneos_source

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT/'toolchain/make/profile.json'


def captured(path, digest):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular pinned input')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Pinned input digest changed: '+str(path))
    return data


def verify_sdk(sdk, digest):
    # Validate and parse the same captured manifest, then every frozen SDK byte.
    data = captured(sdk/'manifest.json', digest)
    manifest = package.parse(data)
    expected = {'manifest.json'}
    for row in manifest['files']:
        package.regular(sdk, row['path'], row['sha256'], row['size'])
        if row['path'] in expected:
            raise ValueError('Duplicate SDK path')
        expected.add(row['path'])
    actual = {p.relative_to(sdk).as_posix() for p in sdk.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != expected:
        raise ValueError('SDK file set differs')
    return manifest


def unpack(data, destination):
    """Reviewed GNU tarball: regular files/directories only, no links or escapes."""
    rows = []
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 2000 or sum(m.size for m in members) > 50 * 1024 * 1024:
            raise ValueError('Unexpected source archive bounds')
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts
                    or path.parts[0] != 'make-4.4.1' or str(path) != member.name.rstrip('/')
                    or str(path) in seen or not (member.isdir() or member.isfile())):
                raise ValueError('Unexpected source member: '+member.name)
            seen.add(str(path))
        destination.mkdir(parents=True, exist_ok=False)
        for member in members:
            target = destination/member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.extractfile(member).read()
            if len(content) != member.size:
                raise ValueError('Truncated source member')
            target.write_bytes(content)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
            os.utime(target, (member.mtime, member.mtime))
            rows.append({'path': member.name, 'size': len(content),
                         'sha256': hashlib.sha256(content).hexdigest()})
    return rows


def elf_facts(text):
    if (not re.search(r'Machine:\s+AArch64\s*$', text, re.M)
            or not re.search(r'Class:\s+ELF64\s*$', text, re.M)
            or '[Requesting program interpreter: /system/bin/linker64]' not in text
            or not re.search(r'Type:\s+DYN', text)):
        raise ValueError('Not an ARM64 dynamic Android executable')
    needed = re.findall(r'\(NEEDED\).*?\[([^]]+)\]', text)
    if set(needed) != {'libc.so', 'libdl.so'}:
        raise ValueError('Unexpected Make runtime dependencies')
    if re.search(r'\((?:RUNPATH|RPATH)\)', text):
        raise ValueError('Unexpected Make runtime path')
    loads = [line for line in text.splitlines() if line.lstrip().startswith('LOAD ')]
    if not loads or any(int(line.split()[-1], 16) < 16384 for line in loads):
        raise ValueError('Insufficient segment alignment')
    stack = [line for line in text.splitlines() if 'GNU_STACK' in line]
    if (len(stack) != 1 or ' E ' in stack[0] or 'RWE' in stack[0]
            or 'GNU_RELRO' not in text or 'BIND_NOW' not in text
            or not re.search(r'FLAGS_1.*PIE', text)):
        raise ValueError('Missing executable hardening')
    return {'needed': sorted(needed), 'interpreter': '/system/bin/linker64',
            'PIE_RELRO_NOW_NX_stack': True, 'load_alignment_minimum': 16384}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--downloads', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077)
    root, sdk = args.source_root.resolve(), args.sdk.resolve()
    build, output, evidence = [p.resolve() for p in (args.build_root, args.output, args.evidence)]
    if any(p.is_relative_to(ROOT) or p.is_relative_to(root) for p in (build, output, evidence)):
        raise ValueError('Build, evidence and binary outputs must be outside source trees')
    if any(p.exists() for p in (build, output, evidence)):
        raise ValueError('Use new output directories; preserve earlier attempts')
    if len({build, output, evidence}) != 3 or any(
            a != b and (a.is_relative_to(b) or b.is_relative_to(a))
            for a in (build, output, evidence) for b in (build, output, evidence)):
        raise ValueError('Build/evidence/output directories must be separate siblings')
    build.mkdir(parents=True); evidence.mkdir(parents=True)
    profile_data = PROFILE.read_bytes(); profile = package.parse(profile_data)
    profile_digest = hashlib.sha256(profile_data).hexdigest()
    result = {'verdict': 'FAIL', 'Android_execution_proved': False,
              'profile_sha256': profile_digest}
    started = time.monotonic()
    # No ambient compiler flags, make jobserver/eval flags or config.site injection.
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
           'HOME': str(build/'home'), 'TMPDIR': str(build/'tmp'),
           'CONFIG_SITE': '/dev/null', 'GIT_NO_LAZY_FETCH': '1'}
    for name in ['home', 'tmp', 'cross-bin']: (build/name).mkdir()

    def run(label, argv, cwd=build, timeout=300):
        began = time.monotonic()
        receipt = {'argv': list(map(str, argv)), 'timeout_seconds': timeout}
        try:
            with (evidence/(label+'.stdout')).open('wb') as out, (evidence/(label+'.stderr')).open('wb') as err:
                p = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, timeout=timeout)
            receipt['exit_code'] = p.returncode
        except Exception as error:
            receipt['failure'] = type(error).__name__+': '+str(error)
            raise
        finally:
            receipt['seconds'] = time.monotonic()-began
            (evidence/(label+'.json')).write_text(json.dumps(receipt, indent=2)+'\n')
        if p.returncode:
            raise RuntimeError(label+' failed; inspect retained evidence')
        return (evidence/(label+'.stdout')).read_text()

    try:
        producer = subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', 'rev-parse', 'HEAD'],
                                          cwd=ROOT, env=env, text=True).strip()
        for name in ['scripts/proof/native_make.py', 'toolchain/make/profile.json',
                     'toolchain/make/'+profile['patch']['file']]:
            committed = subprocess.run(['git', '--no-pager', '-c', 'core.hooksPath=/dev/null',
                'show', producer+':'+name], cwd=ROOT, env=env, capture_output=True)
            if committed.returncode or committed.stdout != (ROOT/name).read_bytes():
                raise ValueError('Commit the native Make recipe/profile before producing build artifacts')
        downloads = {}
        verification = evidence/'verification-inputs'; verification.mkdir()
        for name in ['archive', 'signature', 'keyring']:
            pin = profile[name]
            downloads[name] = captured(args.downloads/pin['file'], pin['sha256'])
            target = verification/pin['file']; target.write_bytes(downloads[name]); target.chmod(0o400)
        gpg_home = evidence/'gnupg'; gpg_home.mkdir(mode=0o700)
        status = run('signature', ['gpgv', '--homedir', gpg_home, '--keyring',
            verification/profile['keyring']['file'], '--status-fd=1',
            verification/profile['signature']['file'], verification/profile['archive']['file']])
        valid = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if (len(valid) != 1 or valid[0][2] != profile['signing_key']
                or valid[0][-1] != profile['primary_key']):
            raise ValueError('Unexpected GNU release signer')
        verify_sdk(sdk, profile['sdk_manifest_sha256'])
        for prefix in ['bootstrap', 'host_make']:
            checked = grapheneos_source.check_project(root, {
                'path': profile[prefix+'_project'], 'revision': profile[prefix+'_revision']})
            (evidence/(prefix+'-source.json')).write_text(json.dumps(checked, indent=2)+'\n')
            if checked['verdict'] != 'PASS': raise ValueError('Source project check failed')
        bootstrap = root/profile['bootstrap_project']/profile['bootstrap_directory']
        host_make = root/profile['host_make_project']/profile['host_make_file']
        captured(host_make, profile['host_make_sha256'])
        source_rows = unpack(downloads['archive'], build/'source')
        (evidence/'source-files.json').write_text(json.dumps(source_rows, indent=2)+'\n')
        source = build/'source/make-4.4.1'
        patch = profile['patch']; patch_file = verification/patch['file']
        patch_file.write_bytes(captured(PROFILE.parent/patch['file'], patch['sha256']))
        patch_file.chmod(0o400)
        captured(source/patch['source'], patch['before_sha256'])
        run('patch-check', ['patch', '--batch', '--dry-run', '-p1', '-i', patch_file], cwd=source)
        run('patch', ['patch', '--batch', '-p1', '-i', patch_file], cwd=source)
        captured(source/patch['source'], patch['after_sha256'])
        for row in source_rows:
            name = row['path'].removeprefix('make-4.4.1/')
            if name != patch['source']: captured(source/name, row['sha256'])
        captured(source/'COPYING', profile['copying_sha256'])

        # Configure must see a real target C++ compiler but save the device tool
        # name "c++", not a host absolute command, as its builtin CXX variable.
        cross = build/'cross-bin'
        cfg = ['-nostdinc++', shlex.join(['-isystem', str(sdk/'cxx/target')]),
               shlex.join(['-isystem', str(sdk/'cxx/include')]), '-nostdlib++',
               shlex.quote('$-Wl,--start-group,'+str(sdk/'cxx/lib/libc++_static.a')+','+
               str(sdk/'cxx/lib/libc++abi.a')+',--end-group'),
               '$-Wl,--exclude-libs,libc++_static.a:libc++abi.a:libunwind.a']
        (cross/'cxx.cfg').write_text('\n'.join(cfg)+'\n')
        command = [str(bootstrap/'bin/clang++'), '--target='+profile['target'],
                   '--sysroot='+str(sdk/'sysroot'), '--config='+str(cross/'cxx.cfg')]
        (cross/'c++').write_text('#!/bin/sh\nexec '+shlex.join(command)+' "$@"\n')
        (cross/'c++').chmod(0o700)
        env.update({'PATH': str(cross)+':/usr/bin:/bin', 'CXX': 'c++',
            'CC': shlex.join([str(bootstrap/'bin/clang'), '--target='+profile['target'],
                             '--sysroot='+str(sdk/'sysroot')]),
            'AR': str(bootstrap/'bin/llvm-ar'), 'RANLIB': str(bootstrap/'bin/llvm-ranlib'),
            'CFLAGS': ' '.join(profile['cflags']), 'LDFLAGS': ' '.join(profile['ldflags'])})
        (evidence/'build-environment.json').write_text(json.dumps(env, indent=2)+'\n')
        directory = build/'objects'; directory.mkdir()
        run('configure', [source/'configure', *profile['configure']], cwd=directory, timeout=600)
        config = (directory/'src/config.h').read_text()
        if '#define MAKE_CXX "c++"' not in config or '#define USE_POSIX_SPAWN 1' not in config:
            raise ValueError('Unexpected target compiler/default spawn configuration')
        shutil.copy2(directory/'src/config.h', evidence/'config.h')
        # Normal recursive target builds libgnu first. Never place this driver at
        # objects/build.sh: configure owns that pathname for its bootstrap helper.
        commands = run('build', [host_make, '-j8', 'V=1'], cwd=directory, timeout=1800)
        lines = [line for line in commands.splitlines() if line.startswith(str(bootstrap/'bin/clang'))]
        compilations = [line for line in lines if ' -c ' in line]
        if len(compilations) < 30: raise ValueError('Incomplete compiler-command evidence')
        for line in lines:
            if any(flag not in line for flag in profile['cflags']):
                raise ValueError('Missing native hardening flag in a compiler invocation')
            if '--target='+profile['target'] not in line or '--sysroot='+str(sdk/'sysroot') not in line:
                raise ValueError('Foreign compiler invocation')
        unstripped = evidence/'make.unstripped'; shutil.copy2(directory/'make', unstripped)
        output.mkdir(); (output/'bin').mkdir(); (output/'licenses').mkdir()
        run('strip', [bootstrap/'bin/llvm-strip', '--strip-unneeded', '-o', output/'bin/make', unstripped])
        run('elf-gate', ['bash', ROOT/'scripts/proof/host_elf.sh', output/'bin/make'])
        facts = elf_facts(run('readelf', ['readelf', '-hW', '-lW', '-dW', '-nW', output/'bin/make']))
        symbols = run('cfi-symbols', ['readelf', '-sW', unstripped])
        if '.cfi' not in symbols: raise ValueError('No CFI symbol corroboration')
        shutil.copy2(source/'COPYING', output/'licenses/COPYING')
        notice = ('GNU Make '+profile['version']+'; GPL-3.0-or-later\n'+
            'Corresponding upstream source: '+profile['archive']['url']+'\n'+
            'Archive SHA256: '+profile['archive']['sha256']+'\n'+
            'Andrix patch/build profile: toolchain/make and scripts/proof/native_make.py\n'+
            'Dynamic ARM64/Bionic API37; CC=cc, CXX=c++; serial by default.\n'+
            'Optional Guile/load/NLS disabled; existing owner limits apply.\n')
        (output/'licenses/SOURCE').write_text(notice)
        rows = []
        for p in sorted(output.rglob('*')):
            if p.is_file():
                p.chmod(0o755 if p.parent.name == 'bin' else 0o644)
                rows.append({'path': p.relative_to(output).as_posix(), 'size': p.stat().st_size,
                             'sha256': package.sha(p)})
        manifest = {'schema': 1, 'tool': 'GNU Make', 'version': profile['version'],
            'source_build': producer, 'profile_sha256': profile_digest,
            'source_archive_sha256': profile['archive']['sha256'], 'patch_sha256': patch['sha256'],
            'sdk_manifest_sha256': profile['sdk_manifest_sha256'], 'target': profile['target'],
            'bootstrap_version': profile['bootstrap_version'], 'unstripped_sha256': package.sha(unstripped),
            'compile_commands_checked': len(compilations), 'elf': facts, 'files': rows,
            'Android_execution_proved': False}
        (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        result.update({'verdict': 'PASS_NATIVE_MAKE_ARTIFACT_NOT_RUNTIME', 'manifest_sha256':
                       package.sha(output/'manifest.json'), 'compile_commands_checked': len(compilations)})
    except Exception as error:
        result['failure'] = type(error).__name__+': '+str(error)
    result['seconds'] = time.monotonic() - started
    (evidence/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0 if result['verdict'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
