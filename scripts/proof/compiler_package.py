#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify pinned compiler inputs; generate an opt-in APEX payload map and stage bytes."""
from pathlib import Path, PurePosixPath
import argparse
import collections
import hashlib
import json
import os
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
TOOLCHAIN = ROOT/'toolchain'


def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()


def unique(pairs):
    result={}
    for k,v in pairs:
        if k in result: raise ValueError('Duplicate JSON key')
        result[k]=v
    return result


def parse(data):
    return json.loads(data,object_pairs_hook=unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def load(path):
    return parse(path.read_bytes())


def pinned_manifest(root, pin):
    path=regular(root,pin['manifest'],pin['sha256'])
    data=path.read_bytes()
    # Parse the exact captured bytes whose digest was checked, not a second open
    # after validating a possibly replaced pathname.
    if hashlib.sha256(data).hexdigest()!=pin['sha256']:
        raise ValueError('Manifest changed while reading')
    return parse(data)


def relative(value):
    p=PurePosixPath(value)
    if not isinstance(value,str) or p.is_absolute() or '..' in p.parts or str(p)!=value or not p.parts:
        raise ValueError('Non-canonical payload path')
    if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+.-/' for c in value):
        raise ValueError('Unexpected payload path character')
    return p


def regular(root, path, digest, size=None):
    p=root/relative(path)
    if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root.resolve()):
        raise ValueError('Not a contained regular input: '+str(p))
    # Reject directory symlinks too, even if currently contained.
    q=p
    while q!=root:
        if q.is_symlink(): raise ValueError('Input path traverses a symlink')
        q=q.parent
    if size is not None and p.stat().st_size!=size: raise ValueError('Input size changed')
    if sha(p)!=digest: raise ValueError('Input digest changed: '+str(p))
    return p


def lldb_paths(manifest, pins, shared_stl_sha256):
    profile_data=(TOOLCHAIN/'lldb/profile.json').read_bytes()
    profile=parse(profile_data)
    if (manifest['tool']!='LLVM LLDB' or manifest['version']!=profile['version']
            or manifest['target']!=profile['target']
            or manifest['source_build']!=pins['lldb']['source_build']
            or manifest['profile_sha256']!=hashlib.sha256(profile_data).hexdigest()
            or manifest['source_revision']!=profile['source_revision']
            or manifest['bootstrap_revision']!=profile['bootstrap_revision']
            or manifest['sdk_manifest_sha256']!=pins['sdk']['sha256']
            or manifest['required_existing_shared_STL_sha256']!=shared_stl_sha256):
        raise ValueError('Unreviewed native LLDB artifact')
    paths={'bin/lldb':'bin/lldb', 'bin/lldb-server':'bin/lldb-server',
           'lib64/liblldb.so':'lib64/liblldb.so'}
    for name in ['LLVM-LICENSE.TXT','Clang-LICENSE.TXT','LLDB-LICENSE.TXT']:
        paths['licenses/'+name]='etc/andrix/lldb/'+name
    if {row['path'] for row in manifest['files']}!=set(paths) or len(manifest['files'])!=6:
        raise ValueError('Unexpected native LLDB payload')
    return paths


def inputs(input_root):
    input_root=input_root.resolve(); pins=load(TOOLCHAIN/'package-inputs.json')
    manifests={}
    for name in ['native','sdk','resources','make','lldb']:
        manifests[name]=pinned_manifest(input_root,pins[name])
    files={};sources={}
    def add(source,dest,digest,size):
        relative(dest)
        if dest in files:raise ValueError('Duplicate output '+dest)
        if source.is_symlink() or sha(source)!=digest or source.stat().st_size!=size:raise ValueError('Input changed')
        files[dest]={'path':dest,'sha256':digest,'size':size};sources[dest]=source
    for row in manifests['native']['records']:
        name=row['name'];dest={'clang':'bin/clang','lld':'bin/ld.lld','llvm-ar':'bin/llvm-ar'}[name]
        p=regular(input_root,'frozen-native-01/bin/'+name,row['stripped_sha256'],row['stripped_bytes'])
        add(p,dest,row['stripped_sha256'],row['stripped_bytes'])
    for row in manifests['sdk']['files']:
        path=row['path'];p=regular(input_root,'frozen-sdk-02/'+path,row['sha256'],row['size']);dest=None
        if path.startswith('sysroot/'):dest='etc/andrix/sdk/'+path.removeprefix('sysroot/')
        elif path.startswith('cxx/include/'):dest='etc/andrix/sdk/usr/include/c++/v1/'+path.removeprefix('cxx/include/')
        elif path.startswith('cxx/target/'):dest='etc/andrix/sdk/usr/include/aarch64-linux-android/c++/v1/'+path.removeprefix('cxx/target/')
        elif path=='cxx/lib/libc++_shared.so':dest='lib64/libc++_shared.so'
        elif path in ['cxx/lib/libc++_static.a','cxx/lib/libc++abi.a']:
            dest='etc/andrix/sdk/usr/lib/aarch64-linux-android/'+PurePosixPath(path).name
        elif path.startswith('licenses/'):
            dest={'out/soong/ndk/NOTICE':'etc/andrix/licenses/sdk-NOTICE',
                  'prebuilts/clang/host/linux-x86/clang-r584948b/NOTICE':'etc/andrix/licenses/bootstrap-NOTICE',
                  'external/opencl/llvm-project/LICENSE.TXT':'etc/andrix/licenses/llvm-LICENSE'}[row['input']]
        # Static C++ is separate from static Bionic. The profile still uses API37
        # dynamic executable CRTs and Android's system linker/libc.
        if dest:add(p,dest,row['sha256'],row['size'])
    for row in manifests['resources']['files']:
        p=regular(input_root,'frozen-resources/'+row['path'],row['sha256'],row['size'])
        add(p,'etc/andrix/clang/23/'+row['path'],row['sha256'],row['size'])
    make=manifests['make']
    if (make['tool']!='GNU Make' or make['version']!='4.4.1'
            or make['target']!='aarch64-linux-android37'
            or make['source_build']!=pins['make']['source_build']
            or make['profile_sha256']!=sha(TOOLCHAIN/'make/profile.json')):
        raise ValueError('Unreviewed native Make artifact')
    make_paths={'bin/make':'bin/make','licenses/COPYING':'etc/andrix/make/COPYING',
                'licenses/SOURCE':'etc/andrix/make/SOURCE'}
    if {row['path'] for row in make['files']}!=set(make_paths) or len(make['files'])!=3:
        raise ValueError('Unexpected native Make payload')
    for row in make['files']:
        p=regular(input_root,'frozen-make-01/'+row['path'],row['sha256'],row['size'])
        add(p,make_paths[row['path']],row['sha256'],row['size'])
    debugger=manifests['lldb']
    paths=lldb_paths(debugger,pins,files['lib64/libc++_shared.so']['sha256'])
    for row in debugger['files']:
        p=regular(input_root,'frozen-lldb-01/'+row['path'],row['sha256'],row['size'])
        add(p,paths[row['path']],row['sha256'],row['size'])
    for name in ['cxx.cfg','cxx-shared.cfg']:
        p=TOOLCHAIN/name;add(p,'etc/andrix/'+name,sha(p),p.stat().st_size)
    required=['bin/clang','bin/ld.lld','bin/llvm-ar','bin/make','bin/lldb','bin/lldb-server',
              'lib64/liblldb.so','etc/andrix/lldb/LLDB-LICENSE.TXT','etc/andrix/make/COPYING',
              'etc/andrix/make/SOURCE','lib64/libc++_shared.so',
              'etc/andrix/sdk/usr/lib/aarch64-linux-android/37/crtbegin_dynamic.o',
              'etc/andrix/sdk/usr/include/c++/v1/iostream',
              'etc/andrix/sdk/usr/lib/aarch64-linux-android/libc++_static.a',
              'etc/andrix/sdk/usr/lib/aarch64-linux-android/libc++abi.a',
              'etc/andrix/sdk/usr/include/aarch64-linux-android/c++/v1/__config_site',
              'etc/andrix/clang/23/lib/linux/libclang_rt.builtins-aarch64-android.a',
              'etc/andrix/clang/23/lib/linux/aarch64/libunwind.a']
    if any(p not in files for p in required):raise ValueError('Missing required package input')
    return sorted(files.values(),key=lambda r:r['path']),sources


def blueprint(rows):
    groups=collections.defaultdict(list)
    for row in rows:
        if row['path'].startswith('etc/'):
            groups[str(PurePosixPath(row['path']).parent)].append(row['path'])
    preamble='''// SPDX-License-Identifier: Apache-2.0
// Generated by scripts/proof/compiler_package.py from pinned input manifests.
// Data are grouped by directory: APEX prebuilt_etc does not preserve per-file dsts.
package { default_applicable_licenses: ["andrix_compiler_payload_license"] }
license {
    name: "andrix_compiler_payload_license",
    visibility: [":__subpackages__"],
    // Aggregated metadata for mixed upstream inputs, not a relicensing. Individual
    // headers and full notices, including LLVM exceptions, remain authoritative.
    license_kinds: ["SPDX-license-identifier-Apache-2.0", "SPDX-license-identifier-BSD",
        "SPDX-license-identifier-ISC", "SPDX-license-identifier-MIT",
        "SPDX-license-identifier-NCSA", "SPDX-license-identifier-PSF-2.0",
        "SPDX-license-identifier-Zlib", "legacy_notice", "legacy_unencumbered"],
    license_text: ["licenses/sdk-NOTICE", "licenses/bootstrap-NOTICE", "licenses/llvm-LICENSE"],
}
license {
    name: "andrix_native_make_license",
    visibility: [":__subpackages__"],
    license_kinds: ["SPDX-license-identifier-GPL-3.0-or-later"],
    license_text: ["licenses/make-COPYING"],
}
license {
    name: "andrix_native_lldb_license",
    visibility: [":__subpackages__"],
    license_kinds: ["SPDX-license-identifier-Apache-2.0", "SPDX-license-identifier-NCSA",
        "SPDX-license-identifier-BSD"],
    license_text: ["licenses/lldb-LLVM-LICENSE.TXT", "licenses/lldb-Clang-LICENSE.TXT",
        "licenses/lldb-LLDB-LICENSE.TXT"],
}
'''
    parts=[preamble]
    for suffix,base,props in [('binary','cc_prebuilt_binary',['enabled']),
                              ('library','cc_prebuilt_library_shared',['enabled']),
                              ('data','prebuilt_etc',['enabled']),
                              ('wrapper','cc_binary',['enabled']),
                              ('apex_defaults','apex_defaults',['binaries','native_shared_libs','prebuilts'])]:
        parts.append('soong_config_module_type {\n    name: "andrix_compiler_'+suffix+'",\n    module_type: '+json.dumps(base)+',\n    config_namespace: "andrix",\n    bool_variables: ["owner_compiler"],\n    properties: '+json.dumps(props)+',\n}\n')
    enabled='    enabled: false,\n    soong_config_variables: { owner_compiler: { enabled: true } },\n'
    for name,stem,aliases in [('clang','clang',[]),('lld','ld.lld',[]),('ar','llvm-ar',[])]:
        parts.append('andrix_compiler_binary {\n    name: "andrix_compiler_'+name+'",\n'+enabled+
            '    srcs: ["artifacts/root/bin/'+stem+'"],\n    stem: '+json.dumps(stem)+',\n    symlinks: '+json.dumps(aliases)+',\n'+
            '    compile_multilib: "64",\n    sdk_version: "37",\n    min_sdk_version: "37",\n    stl: "none",\n'+
            '    apex_available: ["dev.andrix.usr"],\n    shared_libs: ["andrix_compiler_libcxx", "libz"],\n'+
            '    system_shared_libs: ["libc", "libm", "libdl"],\n    strip: { none: true },\n}\n')
    parts.append('andrix_compiler_binary {\n    name: "andrix_compiler_make",\n'+enabled+'''
    licenses: ["andrix_native_make_license"],
    srcs: ["artifacts/root/bin/make"],
    stem: "make",
    compile_multilib: "64",
    sdk_version: "37",
    min_sdk_version: "37",
    stl: "none",
    apex_available: ["dev.andrix.usr"],
    system_shared_libs: ["libc", "libdl"],
    strip: { none: true },
}
''')
    parts.append('andrix_compiler_library {\n    name: "andrix_compiler_libcxx",\n'+enabled+'''
    srcs: ["artifacts/root/lib64/libc++_shared.so"],
    stem: "libc++_shared",
    compile_multilib: "64",
    sdk_version: "37",
    min_sdk_version: "37",
    stl: "none",
    apex_available: ["dev.andrix.usr"],
    system_shared_libs: ["libc", "libm", "libdl"],
    strip: { none: true },
}
''')
    for name,stem in [('lldb','lldb'),('lldb_server','lldb-server')]:
        libraries=['andrix_compiler_libcxx','libz']
        if name=='lldb':libraries.append('andrix_compiler_liblldb')
        parts.append('andrix_compiler_binary {\n    name: "andrix_compiler_'+name+'",\n'+enabled+
            '    licenses: ["andrix_native_lldb_license"],\n'+
            '    srcs: ["artifacts/root/bin/'+stem+'"],\n    stem: '+json.dumps(stem)+',\n'+
            '    compile_multilib: "64",\n    sdk_version: "37",\n    min_sdk_version: "37",\n    stl: "none",\n'+
            '    apex_available: ["dev.andrix.usr"],\n    shared_libs: '+json.dumps(libraries)+',\n'+
            '    system_shared_libs: ["libc", "libm", "libdl"],\n    strip: { none: true },\n}\n')
    parts.append('andrix_compiler_library {\n    name: "andrix_compiler_liblldb",\n'+enabled+'''
    licenses: ["andrix_native_lldb_license"],
    srcs: ["artifacts/root/lib64/liblldb.so"],
    stem: "liblldb",
    compile_multilib: "64",
    sdk_version: "37",
    min_sdk_version: "37",
    stl: "none",
    apex_available: ["dev.andrix.usr"],
    shared_libs: ["andrix_compiler_libcxx", "libz"],
    system_shared_libs: ["libc", "libm", "libdl"],
    strip: { none: true },
}
''')
    parts.append('andrix_compiler_wrapper {\n    name: "andrix_compiler_cxx",\n'+enabled+'''
    srcs: ["tool_driver.c"],
    stem: "clang++",
    symlinks: ["c++", "clang++-shared", "c++-shared", "cc", "ar", "ranlib", "llvm-ranlib"],
    cflags: ["-Wall", "-Wextra", "-Werror"],
    compile_multilib: "64",
    sdk_version: "37",
    min_sdk_version: "37",
    stl: "none",
    apex_available: ["dev.andrix.usr"],
}
''')
    modules=[]
    for directory,paths in sorted(groups.items()):
        name='andrix_compiler_data_'+hashlib.sha256(directory.encode()).hexdigest()[:16];modules.append(name)
        license_line='    licenses: ["andrix_native_make_license"],\n' if directory=='etc/andrix/make' else ''
        if directory=='etc/andrix/lldb':license_line='    licenses: ["andrix_native_lldb_license"],\n'
        parts.append('andrix_compiler_data {\n    name: '+json.dumps(name)+',\n'+enabled+license_line+
            '    relative_install_path: '+json.dumps(directory.removeprefix('etc/'))+',\n'+
            '    installable: false,\n    srcs: [\n'+''.join('        '+json.dumps('artifacts/root/'+p)+',\n' for p in paths)+'    ],\n}\n')
    parts.append('andrix_compiler_apex_defaults {\n    name: "andrix_compiler_apex_payload",\n    soong_config_variables: { owner_compiler: {\n'+
        '        binaries: ["andrix_compiler_clang", "andrix_compiler_lld", "andrix_compiler_ar", "andrix_compiler_cxx", "andrix_compiler_make", "andrix_compiler_lldb", "andrix_compiler_lldb_server"],\n'+
        '        native_shared_libs: ["andrix_compiler_libcxx", "andrix_compiler_liblldb"],\n        prebuilts: [\n'+
        ''.join('            '+json.dumps(n)+',\n' for n in modules)+'        ],\n    } },\n}\n')
    return '\n'.join(parts)


def stage(rows,sources,destination):
    if destination.exists():raise ValueError('Stage output already exists')
    destination.parent.mkdir(parents=True,exist_ok=True)
    tmp=Path(tempfile.mkdtemp(prefix='.compiler-stage-',dir=destination.parent))
    try:
        for row in rows:
            p=tmp/'root'/row['path'];p.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(sources[row['path']],p)
            if sha(p)!=row['sha256']:raise ValueError('Staged digest changed')
            p.chmod(0o755 if row['path'].startswith('bin/') else 0o644)
        (tmp/'payload.json').write_text(json.dumps({'schema':1,'files':rows},indent=2)+'\n')
        tmp.rename(destination)
    except Exception:
        # Retain failed staging inputs for inspection; do not expose a partial final path.
        raise


def verify_stage(rows,destination):
    if load(destination/'payload.json')!={'schema':1,'files':rows}:
        raise ValueError('Staged metadata differs')
    expected={'payload.json'} | {'root/'+r['path'] for r in rows}
    actual=set()
    for path in destination.rglob('*'):
        if path.is_symlink():raise ValueError('Staged symlink')
        if path.is_file():actual.add(path.relative_to(destination).as_posix())
    if actual!=expected:raise ValueError('Staged file set differs')
    for row in rows:regular(destination,'root/'+row['path'],row['sha256'],row['size'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--stage',type=Path);p.add_argument('--verify-stage',type=Path)
    p.add_argument('--generate',action='store_true');args=p.parse_args();os.umask(0o077)
    rows,sources=inputs(args.inputs)
    text=blueprint(rows)
    if args.generate:
        (TOOLCHAIN/'Android.bp').write_text(text)
        (TOOLCHAIN/'licenses').mkdir(exist_ok=True)
        for name in ['sdk-NOTICE','bootstrap-NOTICE','llvm-LICENSE']:
            shutil.copyfile(sources['etc/andrix/licenses/'+name],TOOLCHAIN/'licenses'/name)
        shutil.copyfile(sources['etc/andrix/make/COPYING'],TOOLCHAIN/'licenses/make-COPYING')
        for name in ['LLVM-LICENSE.TXT','Clang-LICENSE.TXT','LLDB-LICENSE.TXT']:
            shutil.copyfile(sources['etc/andrix/lldb/'+name],TOOLCHAIN/'licenses'/('lldb-'+name))
        (TOOLCHAIN/'payload.json').write_text(json.dumps({'schema':1,'files':rows},indent=2)+'\n')
    elif (TOOLCHAIN/'Android.bp').read_text()!=text or load(TOOLCHAIN/'payload.json')!={'schema':1,'files':rows}:
        raise ValueError('Generated public metadata differs; review before regenerating')
    if args.stage:stage(rows,sources,args.stage.resolve())
    if args.verify_stage:verify_stage(rows,args.verify_stage.resolve())
    print(json.dumps({'files':len(rows),'data_directories':len({str(PurePosixPath(r['path']).parent) for r in rows if r['path'].startswith('etc/')}),'staged':str(args.stage) if args.stage else None}))


if __name__=='__main__':main()
