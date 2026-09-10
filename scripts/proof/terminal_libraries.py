#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pinned terminal-library bytes and portable engine tests; not Android qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
LIBRARIES = ROOT / 'third_party/termux-terminal'
COMMIT = '3b66f8799635a4dba4a206563048ff0e6792c487'
TREE = '41ecedc1b870ccf8e471088e6cff77b926823ef9'
MANIFEST_SHA256 = '8686d35845da6a656fe36c1b53b5e169dceb14aff88f981624de7b55d5cf139f'
SDK_SHA256 = '4f3d35e16d20fda03abdc7f81b49ab50010742fb5effc51b821b4b9646697ead'
JUNIT_SHA256 = '59721f0805e223d84b90677887d9ff567dc534d7c502ca903c0c2b17f05c116a'
APACHE_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate manifest key')
        result[key] = value
    return result


def verify(root=LIBRARIES):
    if root.is_symlink() or any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Source symlink/escape')
    if digest(root/'SOURCE.json') != MANIFEST_SHA256:
        raise ValueError('Terminal source manifest changed; review the pin before updating it')
    manifest = json.loads((root/'SOURCE.json').read_text(), object_pairs_hook=unique)
    if manifest['schema'] != 1 or manifest['commit'] != COMMIT or manifest['tree'] != TREE:
        raise ValueError('Unreviewed terminal source pin')
    if manifest['local_changes'] != []:
        raise ValueError('Terminal library changes require an explicit review')
    names = set()
    for row in manifest['files']:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or row['path'] in names:
            raise ValueError('Non-contained or duplicate source path')
        names.add(row['path'])
        path = root/relative
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Source symlink/escape')
        data = path.read_bytes()
        blob = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if len(data) != row['size'] or blob != row['sha1'] or digest(path) != row['sha256']:
            raise ValueError('Changed terminal library: '+row['path'])
    metadata = {'SOURCE.json', 'README.md', 'LICENSE', 'UPSTREAM-LICENSE.md'}
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != names | metadata or len(names) != 42:
        raise ValueError('Unexpected terminal library inputs')
    if any(Path(name).name in ['TerminalSession.java', 'JNI.java'] or '/jni/' in name for name in names):
        raise ValueError('Termux process launcher is not an Andrix input')
    if (digest(root/'UPSTREAM-LICENSE.md') != manifest['upstream_license_sha256']
            or digest(root/'LICENSE') != APACHE_SHA256):
        raise ValueError('License statement changed')
    return {'commit': COMMIT, 'tree': TREE, 'unmodified_files': len(names)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--android-jar', type=Path, required=True)
    parser.add_argument('--junit-jar', type=Path, required=True)
    parser.add_argument('--jdk-bin', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    evidence = args.evidence_dir.resolve()
    if evidence.is_relative_to(ROOT):
        raise ValueError('Raw evidence must be outside the checkout')
    evidence.mkdir(parents=True, exist_ok=False)
    result = {'verdict': 'FAIL', 'Android_View_or_session_qualified': False,
              'host_adapters': 'logging, Base64, RGB extraction, annotations, inert session type'}
    started = time.monotonic()
    try:
        result['sources'] = verify()
        if digest(args.android_jar) != SDK_SHA256 or digest(args.junit_jar) != JUNIT_SHA256:
            raise ValueError('Use the inspected pinned SDK/JUnit inputs')
        core = LIBRARIES/'terminal-emulator/src/main/java/com/termux/terminal'
        tests = LIBRARIES/'terminal-emulator/src/test/java/com/termux/terminal'
        adapters = ROOT/'owner/tests/terminal-host'
        sources = list(core.glob('*.java')) + list(tests.glob('*.java')) + list(adapters.rglob('*.java'))
        sources.append(ROOT/'owner/terminal/protocol/OutputProtocol.java')
        classes = ['com.termux.terminal.'+p.stem for p in sorted(tests.glob('*Test.java'))]
        classes.append('com.termux.terminal.TerminalReplayTest')
        result['upstream_disabled_method_not_counted'] = 'OperatingSystemControlTest.disabledTestSetClipboard'
        with tempfile.TemporaryDirectory() as tmp:
            def run(name, argv):
                began = time.monotonic()
                p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
                (evidence/(name+'.stdout')).write_text(p.stdout)
                (evidence/(name+'.stderr')).write_text(p.stderr)
                (evidence/(name+'.json')).write_text(json.dumps({'argv':argv,'exit_code':p.returncode,
                    'seconds':time.monotonic()-began}, indent=2)+'\n')
                if p.returncode:
                    raise RuntimeError(name+' failed; see exact output')
                return p.stdout
            run('javac', [str(args.jdk_bin/'javac'), '-cp', str(args.android_jar)+':'+str(args.junit_jar),
                          '-d', tmp, *map(str, sources)])
            output = run('engine', [str(args.jdk_bin/'java'), '-ea', '-cp', tmp+':'+str(args.junit_jar),
                                    'TerminalEngineTests', *classes])
            result['tests'] = output.strip()
        verify()
        result['verdict'] = 'PASS_PORTABLE_TERMINAL_ENGINE_AND_REPLAY'
    except Exception as error:
        result['failure'] = type(error).__name__+': '+str(error)
    result['seconds'] = time.monotonic()-started
    (evidence/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0 if result['verdict'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
