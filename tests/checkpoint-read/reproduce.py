#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild the fixed checkpoint helper from its source on the host, bounded, and check its bytes.

  reproduce.py --jdk <JDK home> --r8 <r8.jar> --work <fresh directory outside the repository>

build.json pins every input and output: the source, the JDK by its release file, the compiler
options, the class file, the r8 jar and D8's version, D8's options and the jar. Every input is
checked before any tool starts, and each output must equal its pin. The tools write only into the
work directory, which must be new and outside the repository, so the jar is never committed.
build-record.json beside it keeps the digests and the tools' output.

Bounded: one JVM at a time, each with a capped heap, metaspace and code cache, the serial
collector and one compiler thread, a time limit, no core dumps and a file size limit, in an
environment without CLASSPATH or JVM option variables. Exit status 0 means that the jar's SHA-256
is the pinned one, 1 that a tool failed or an output differs, and 2 that an input or the work
directory was refused before any tool started. Host evidence only: it shows which bytes the source
gives, not what they do on a device.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import resource
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PINS = HERE / 'build.json'
JVM_LIMITS = ('-Xmx256m', '-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1',
              '-XX:MaxMetaspaceSize=128m', '-XX:ReservedCodeCacheSize=48m')
TIMEOUT = 300
FILE_LIMIT = 64 << 20
CLEARED = ('CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTIONS')
D8 = 'com.android.tools.r8.D8'


class Refused(Exception):
    """An input that is not the pinned one, or a work directory that is not fresh."""


def strict(text):
    def pairs(items):
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate key')
        return dict(items)
    return json.loads(text, object_pairs_hook=pairs)


def pins():
    return strict(PINS.read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pinned_file(path, size, digest, what):
    """The bytes of a regular file, not a link, of the pinned size and SHA-256."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Refused('%s is not a regular file' % what)
    data = path.read_bytes()
    if len(data) != size or sha(data) != digest:
        raise Refused('%s is not the pinned one' % what)
    return data


def fresh_outside(path):
    """The work directory, absolute: it must not exist yet and must lie outside the repository."""
    resolved = Path(path).resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise Refused('the work directory must lie outside the repository')
    if resolved.exists() or resolved.is_symlink():
        raise Refused('the work directory must be new')
    return resolved


def tool(path, what):
    path = Path(path)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise Refused('%s is not an executable file' % what)
    return path


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


def run(argv, cwd):
    """One tool, bounded, with its status and both streams."""
    environment = {name: value for name, value in os.environ.items() if name not in CLEARED}
    try:
        result = subprocess.run([str(a) for a in argv], cwd=cwd, env=environment, capture_output=True, text=True,
                                timeout=TIMEOUT, preexec_fn=_limits)
    except subprocess.TimeoutExpired:
        return {'argv': [str(a) for a in argv], 'returncode': None, 'stdout': '', 'stderr': 'timed out'}
    return {'argv': [str(a) for a in argv], 'returncode': result.returncode, 'stdout': result.stdout[-4000:],
            'stderr': result.stderr[-4000:]}


def reproduce(jdk, r8, work):
    """Check every input, run javac and D8 once each, and compare both outputs with their pins.
    Returns the build record. Raises Refused before any tool starts when an input is refused."""
    p = pins()
    work = fresh_outside(work)
    source = pinned_file(HERE / p['source']['name'], p['source']['bytes'], p['source']['sha256'], 'the helper source')
    jdk = Path(jdk).resolve()
    pinned_file(jdk / 'release', p['jdk']['release_bytes'], p['jdk']['release_sha256'], "the JDK's release file")
    javac, java = tool(jdk / 'bin' / 'javac', 'javac'), tool(jdk / 'bin' / 'java', 'java')
    r8 = Path(r8).resolve()
    pinned_file(r8, p['r8']['bytes'], p['r8']['sha256'], 'the r8 jar')
    record = {'schema': 'andrix-checkpoint-read-build-record-v1', 'pins_sha256': sha(PINS.read_bytes()),
              'status': 'FAIL', 'steps': {}}
    (work / 'src').mkdir(parents=True)
    (work / 'classes').mkdir()
    (work / 'src' / p['source']['name']).write_bytes(source)
    steps = record['steps']
    try:
        steps['d8-version'] = run([java, *JVM_LIMITS, '-cp', r8, D8, '--version'], work)
        if steps['d8-version']['returncode'] != 0 or steps['d8-version']['stdout'] != p['r8']['version'] + '\n':
            record['problem'] = "D8's version is not the pinned one"
            return record
        steps['javac'] = run([javac, *('-J' + option for option in JVM_LIMITS), *p['javac'], '-d', 'classes',
                              'src/' + p['source']['name']], work)
        classes = sorted(path.name for path in (work / 'classes').iterdir())
        if steps['javac']['returncode'] != 0 or classes != [p['class']['name']]:
            record['problem'] = 'javac failed or wrote other classes: %s' % classes
            return record
        compiled = (work / 'classes' / p['class']['name']).read_bytes()
        record['class'] = {'bytes': len(compiled), 'sha256': sha(compiled)}
        if record['class'] != {'bytes': p['class']['bytes'], 'sha256': p['class']['sha256']}:
            record['problem'] = 'the class file differs from its pin'
            return record
        steps['d8'] = run([java, *JVM_LIMITS, '-cp', r8, D8, *p['d8'], '--output', p['jar']['name'],
                           'classes/' + p['class']['name']], work)
        jar = work / p['jar']['name']
        if steps['d8']['returncode'] != 0 or jar.is_symlink() or not jar.is_file():
            record['problem'] = 'D8 failed'
            return record
        data = jar.read_bytes()
        record['jar'] = {'bytes': len(data), 'sha256': sha(data)}
        if record['jar'] != {'bytes': p['jar']['bytes'], 'sha256': p['jar']['sha256']}:
            record['problem'] = 'the jar differs from its pin'
            return record
        record['status'] = 'PASS'
        return record
    finally:
        (work / 'build-record.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--jdk', type=Path, required=True, help='the home of the pinned JDK 25')
    parser.add_argument('--r8', type=Path, required=True, help='the pinned r8 jar, which holds D8')
    parser.add_argument('--work', type=Path, required=True, help='a fresh directory outside the repository')
    args = parser.parse_args(argv)
    try:
        record = reproduce(args.jdk, args.r8, args.work)
    except Refused as error:
        print(json.dumps({'status': 'REFUSED', 'reason': str(error)}))
        return 2
    print(json.dumps({'status': record['status'], 'class': record.get('class'), 'jar': record.get('jar'),
                      'problem': record.get('problem')}, sort_keys=True))
    return 0 if record['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
