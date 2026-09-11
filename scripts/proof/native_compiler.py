#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build matching host generators or a native AArch64/Bionic LLVM candidate. No guest launch."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

import compiler_sdk
import grapheneos_source

ROOT = Path(__file__).resolve().parents[2]


def verify_sdk(sdk, expected_digest):
    if compiler_sdk.sha(sdk/'manifest.json') != expected_digest:
        raise ValueError('SDK manifest differs from frozen receipt')
    manifest = json.loads((sdk/'manifest.json').read_text())
    if manifest['profile_sha256'] != compiler_sdk.sha(ROOT/'toolchain/native-compiler.json'):
        raise ValueError('SDK profile changed since it was frozen')
    names = set()
    for row in manifest['files']:
        relative = Path(row['path']); p = sdk/relative
        if relative.is_absolute() or '..' in relative.parts or row['path'] in names:
            raise ValueError('SDK path')
        if p.is_symlink() or not p.resolve().is_relative_to(sdk.resolve()):
            raise ValueError('SDK symlink')
        if p.stat().st_size != row['size'] or compiler_sdk.sha(p) != row['sha256']:
            raise ValueError('SDK bytes changed: '+row['path'])
        names.add(row['path'])
    actual = {p.relative_to(sdk).as_posix() for p in sdk.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != names | {'manifest.json'}: raise ValueError('Unexpected SDK files')
    return manifest


def common_flags():
    return ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
            '-DLLVM_TARGETS_TO_BUILD=AArch64',
            '-DLLVM_ENABLE_PROJECTS=clang;lld', '-DLLVM_INCLUDE_TESTS=OFF',
            '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_EXAMPLES=OFF',
            '-DLLVM_INCLUDE_DOCS=OFF', '-DLLVM_ENABLE_LIBXML2=OFF',
            '-DLLVM_ENABLE_LIBEDIT=OFF', '-DLLVM_ENABLE_ZSTD=OFF',
            '-DLLVM_ENABLE_CURL=OFF', '-DLLVM_ENABLE_HTTPLIB=OFF',
            '-DLLVM_ENABLE_PLUGINS=OFF', '-DLLVM_BUILD_LLVM_DYLIB=OFF',
            '-DLLVM_LINK_LLVM_DYLIB=OFF', '-DCLANG_LINK_CLANG_DYLIB=OFF',
            '-DLLVM_USE_LINKER=lld', '-DLLVM_PARALLEL_COMPILE_JOBS=8',
            '-DLLVM_PARALLEL_LINK_JOBS=1']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--sdk-manifest-sha256', required=True)
    p.add_argument('--build-root', type=Path, required=True)
    p.add_argument('--evidence-dir', type=Path, required=True)
    p.add_argument('--stage', choices=['host-tools', 'native-configure', 'native-build'], required=True)
    args = p.parse_args(); os.umask(0o077)
    root=args.source_root.resolve(); build=args.build_root.resolve(); evidence=args.evidence_dir.resolve()
    if build.is_relative_to(ROOT) or build.is_relative_to(root) or evidence.is_relative_to(ROOT) or evidence.is_relative_to(root):
        raise ValueError('Build/evidence outputs must be outside source trees')
    evidence.mkdir(parents=True,exist_ok=False); build.mkdir(parents=True,exist_ok=True)
    profile=json.loads((ROOT/'toolchain/native-compiler.json').read_text())
    result={'stage':args.stage,'verdict':'FAIL','native_runtime_proved':False,'on_device_compilation_proved':False}
    start=time.monotonic()
    try:
        verify_sdk(args.sdk.resolve(), args.sdk_manifest_sha256)
        for path,rev in [(profile['llvm_project'],profile['llvm_revision']),
                         (profile['bootstrap_project'],profile['bootstrap_revision'])]:
            checked=grapheneos_source.check_project(root,{'path':path,'revision':rev})
            if checked['verdict']!='PASS':raise ValueError(str(checked))
        src=root/profile['llvm_project']/'llvm'
        bootstrap=root/profile['bootstrap_project']/profile['bootstrap_directory']
        ninja=root/'prebuilts/build-tools/linux-x86/bin/ninja'
        cmake=Path('/usr/bin/cmake')
        env={key:value for key,value in os.environ.items() if key not in
             ['CC','CXX','CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS','LD_LIBRARY_PATH',
              'CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','LIBRARY_PATH','CMAKE_PREFIX_PATH']}
        env['USE_RBE']='false'
        def run(label,argv,timeout):
            began=time.monotonic()
            with (evidence/(label+'.stdout')).open('wb') as out,(evidence/(label+'.stderr')).open('wb') as err:
                q=subprocess.run(list(map(str,argv)),env=env,stdout=out,stderr=err,timeout=timeout)
            (evidence/(label+'.json')).write_text(json.dumps({'argv':list(map(str,argv)),
                'exit_code':q.returncode,'seconds':time.monotonic()-began},indent=2)+'\n')
            if q.returncode:raise RuntimeError(label+' failed; see retained output')
        if args.stage=='host-tools':
            directory=build/'host-tools'
            flags=common_flags()+['-DLLVM_ENABLE_ZLIB=OFF',
                '-DCMAKE_C_COMPILER='+str(bootstrap/'bin/clang'),
                '-DCMAKE_CXX_COMPILER='+str(bootstrap/'bin/clang++')]
            run('configure',[cmake,'-G','Ninja','-S',src,'-B',directory,
                 '-DCMAKE_MAKE_PROGRAM='+str(ninja),*flags],300)
            run('build',[ninja,'-C',directory,'-j8','llvm-tblgen','clang-tblgen'],7200)
            result['tools']={name:compiler_sdk.sha(directory/'bin'/name) for name in ['llvm-tblgen','clang-tblgen']}
        else:
            directory=build/'native'
            host=build/'host-tools/bin'
            for name in ['llvm-tblgen','clang-tblgen']:
                if not (host/name).is_file():raise ValueError('Build matching host generators first')
            if args.stage=='native-configure':
                flags=common_flags()+['-DLLVM_ENABLE_ZLIB=FORCE_ON','-DLLVM_ENABLE_LTO=Thin',
                    '-DCMAKE_TOOLCHAIN_FILE='+str(ROOT/'toolchain/AndroidBionic.cmake'),
                    '-DANDRIX_BOOTSTRAP='+str(bootstrap),'-DANDRIX_SDK='+str(args.sdk.resolve()),
                    '-DLLVM_TABLEGEN='+str(host/'llvm-tblgen'),'-DCLANG_TABLEGEN='+str(host/'clang-tblgen'),
                    '-DLLVM_NATIVE_TOOL_DIR='+str(host),
                    '-DLLVM_HOST_TRIPLE=aarch64-unknown-linux-android37',
                    '-DLLVM_DEFAULT_TARGET_TRIPLE=aarch64-unknown-linux-android37',
                    '-DCMAKE_INSTALL_PREFIX=/usr','-DCLANG_DEFAULT_CXX_STDLIB=libc++',
                    '-DCLANG_DEFAULT_LINKER=lld', '-DCLANG_DEFAULT_RTLIB=compiler-rt',
                    '-DCLANG_DEFAULT_UNWINDLIB=libunwind',
                    '-DDEFAULT_SYSROOT=../etc/andrix/sdk',
                    '-DCLANG_RESOURCE_DIR=../etc/andrix/clang/23']
                run('configure',[cmake,'-G','Ninja','-S',src,'-B',directory,
                     '-DCMAKE_MAKE_PROGRAM='+str(ninja),*flags],600)
            else:
                if not (directory/'CMakeCache.txt').is_file():raise ValueError('Configure native build first')
                run('build',[ninja,'-C',directory,'-j8',*profile['targets']],21600)
        result['verdict']='PASS_BUILD_STEP_ONLY'
    except Exception as error:
        result['failure']=type(error).__name__+': '+str(error)
    result['seconds']=time.monotonic()-start
    (evidence/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['verdict'].startswith('PASS_') else 1


if __name__=='__main__':raise SystemExit(main())
