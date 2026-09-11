#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze a declared AArch64/API37 compiler-build SDK. Not an on-device compiler proof."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time

import grapheneos_source as source

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT/'toolchain/native-compiler.json'


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def prepare(root, output):
    root = root.resolve(); output = output.resolve()
    if output.is_relative_to(root) or output.is_relative_to(ROOT):
        raise ValueError('SDK output must be outside source trees')
    profile = json.loads(PROFILE.read_text())
    for path, revision in [(profile['llvm_project'], profile['llvm_revision']),
                           (profile['bootstrap_project'], profile['bootstrap_revision']),
                           ('bionic', profile['bionic_revision'])]:
        result = source.check_project(root, {'path':path, 'revision':revision})
        if result['verdict'] != 'PASS':
            raise ValueError(str(result))
    sdk = root/'out/soong/ndk/sysroot'
    if not (root/'out/soong/ndk.timestamp').is_file():
        raise ValueError('Complete current-product m ndk output required')
    api = sdk/'usr/lib/aarch64-linux-android/37'
    required = ['crtbegin_dynamic.o', 'crtend_android.o', 'crtbegin_so.o', 'crtend_so.o',
                'libc.so', 'libm.so', 'libdl.so', 'libz.so']
    for name in required:
        if not (api/name).is_file(): raise ValueError('Incomplete SDK: '+name)
    bootstrap = root/profile['bootstrap_project']/profile['bootstrap_directory']
    cxx = bootstrap/'android_libc++/ndk/aarch64'
    cfg = (cxx/'include/c++/v1/__config_site').read_text()
    if '#define _LIBCPP_ABI_NAMESPACE __ndk1' not in cfg or '#define _LIBCPP_HARDENING_MODE_DEFAULT 2' not in cfg:
        raise ValueError('Unexpected Android NDK libc++ configuration')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    records = []

    def copy_file(path, target, input_root):
        if path.is_symlink() or not path.is_file():
            raise ValueError('SDK input is not a regular file: '+str(path))
        before = sha(path); st = path.stat(); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        if sha(target) != before or sha(path) != before:
            raise ValueError('Input changed during SDK copy')
        records.append({'path':target.relative_to(output).as_posix(), 'size':st.st_size,
                        'sha256':before, 'input':path.relative_to(input_root).as_posix()})

    def copy_tree(path, target, exclude=()):
        for item in sorted(path.rglob('*')):
            if item.relative_to(path).as_posix() in exclude: continue
            if item.is_symlink(): raise ValueError('SDK symlink needs explicit review: '+str(item))
            if item.is_file(): copy_file(item, target/item.relative_to(path), root)

    copy_tree(sdk/'usr/include', output/'sysroot/usr/include')
    copy_tree(api, output/'sysroot/usr/lib/aarch64-linux-android/37')
    # The first profile is dynamic PIE-only. Do not silently relocate the
    # current-only static CRT into /37 or advertise a complete static-link SDK.
    host_config = bootstrap/'include/c++/v1/__config_site'
    if not host_config.is_symlink() or os.readlink(host_config) != '../../x86_64-unknown-linux-gnu/c++/v1/__config_site':
        raise ValueError('Unexpected common libc++ configuration layout')
    # Explicitly omit the host configuration link; the Android target configuration
    # is copied separately and precedes common headers in the include search.
    copy_tree(bootstrap/'include/c++/v1', output/'cxx/include', exclude=('__config_site',))
    copy_tree(cxx/'include/c++/v1', output/'cxx/target')
    for name in ['libc++_shared.so', 'libc++_static.a', 'libc++abi.a']:
        copy_file(cxx/'lib'/name, output/'cxx/lib'/name, root)
    copy_file(bootstrap/'runtimes_ndk_cxx/aarch64/libunwind.a', output/'cxx/lib/libunwind.a', root)
    # Materialized ELF facts: these are target files, not host .so files or LFS pointers.
    for path in [output/'cxx/lib/libc++_shared.so', *[output/'sysroot/usr/lib/aarch64-linux-android/37'/n for n in required]]:
        p = subprocess.run(['readelf', '-hW', str(path)], text=True, capture_output=True, timeout=15)
        if p.returncode != 0 or 'AArch64' not in p.stdout:
            raise ValueError('Not an AArch64 ELF input: '+str(path))
    # Preserve license material alongside the profile, not just a directory name.
    for path in [root/'out/soong/ndk/NOTICE', bootstrap/'NOTICE', root/profile['llvm_project']/'LICENSE.TXT']:
        copy_file(path, output/'licenses'/str(len(records))/path.name, root)
    manifest = {'schema':1, 'profile':profile, 'profile_sha256':sha(PROFILE),
                'bootstrap_source_path':str(bootstrap), 'generated_sdk_scope':'API37 dynamic Bionic; explicit NDK C++ inputs',
                'static_Bionic_sdk_claimed':False, 'on_device_proved':False,
                'excluded_host_cxx_configuration':'include/c++/v1/__config_site (host symlink)',
                'files':records, 'created_ns':time.time_ns()}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); os.umask(0o077)
    try:
        m = prepare(args.source_root, args.output)
        print(json.dumps({'files':len(m['files']), 'sdk_scope':m['generated_sdk_scope'],
                          'on_device_proved':False}, indent=2))
        return 0
    except Exception as error:
        print(type(error).__name__+': '+str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
