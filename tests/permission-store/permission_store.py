#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline reader for stored POST_NOTIFICATIONS flags in one Android permission store file.

It captures one regular file of at most 8 MiB without following a final symlink, verifies the
pinned Android sources named by permission-store.profile.json, compiles them with the reader in
private scratch and parses the complete document with the pinned BinaryXmlPullParser on a host
JVM. No JDK process starts unless the resource guard passes. The bounded JSON result carries the
input hash and length. It reports stored integers, not live permission state, grant authority or
history. It never writes to the input or to the Android checkout.
"""
from pathlib import Path
import argparse
import errno
import hashlib
import json
import os
import re
import resource
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PROFILE = HERE / 'permission-store.profile.json'
READER = HERE / 'PermissionStoreReader.java'
CHECKS = HERE / 'PermissionStoreChecks.java'
FACADES = ('facades/android/text/TextUtils.java', 'facades/android/util/Base64.java')

SCHEMA = 'andrix.permission-store.post-notifications.v1'
SOURCES_SCHEMA = 'andrix.permission-store.sources.v1'
READER_SCHEMA = 'andrix.permission-store.reader.v1'
PARSER = 'com.android.modules.utils.BinaryXmlPullParser'
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MIN_APP_ID = 10000
MAX_APP_ID = 19999
MAX_APP_IDS = 64
MAX_READER_OUTPUT = 64 * 1024
MAX_DETAIL = 4000
INT32 = (-(1 << 31), (1 << 31) - 1)
GIB = 1 << 30

UTILS = 'frameworks/libs/modules-utils/java/'
ACCESS = 'frameworks/base/services/permission/java/com/android/server/permission/access/'
COMPILE_SOURCES = (
    UTILS + 'com/android/modules/utils/BinaryXmlPullParser.java',
    UTILS + 'com/android/modules/utils/BinaryXmlSerializer.java',
    UTILS + 'com/android/modules/utils/FastDataInput.java',
    UTILS + 'com/android/modules/utils/FastDataOutput.java',
    UTILS + 'com/android/modules/utils/ModifiedUtf8.java',
    UTILS + 'com/android/modules/utils/TypedXmlPullParser.java',
    UTILS + 'com/android/modules/utils/TypedXmlSerializer.java',
    UTILS + 'android/annotation/NonNull.java',
    UTILS + 'android/annotation/Nullable.java',
    'libcore/xml/src/main/java/org/xmlpull/v1/XmlPullParser.java',
    'libcore/xml/src/main/java/org/xmlpull/v1/XmlPullParserException.java',
    'libcore/xml/src/main/java/org/xmlpull/v1/XmlSerializer.java',
)
# Read and pinned because the documentation relies on them; never compiled.
REFERENCE_SOURCES = (
    UTILS + 'com/android/modules/utils/Android.bp',
    UTILS + 'Android.bp',
    'frameworks/base/cmds/abx/src/com/android/commands/abx/Abx.java',
    UTILS + 'android/util/Xml.java',
    UTILS + 'com/android/internal/util/ArtBinaryXmlPullParser.java',
    UTILS + 'com/android/internal/util/ArtFastDataInput.java',
    UTILS + 'com/android/internal/util/ArtBinaryXmlSerializer.java',
    'libcore/xml/src/main/java/com/android/org/kxml2/io/KXmlSerializer.java',
)
# The permission service's own store writer and reader; read and pinned, never compiled.
STORE_SOURCES = (
    ACCESS + 'AccessCheckingService.kt',
    ACCESS + 'AccessPersistence.kt',
    ACCESS + 'AccessPolicy.kt',
    ACCESS + 'permission/AppIdPermissionPersistence.kt',
    ACCESS + 'permission/AppIdPermissionPolicy.kt',
    ACCESS + 'util/BinaryXmlSerializerExtensions.kt',
    ACCESS + 'util/BinaryXmlPullParserExtensions.kt',
    ACCESS + 'util/AtomicFileExtensions.kt',
    ACCESS + 'util/PermissionApex.kt',
)
SOURCE_GROUPS = (('compile', COMPILE_SOURCES), ('reference', REFERENCE_SOURCES),
                 ('store', STORE_SOURCES))
PROFILE_KEYS = frozenset({'version', 'status', 'source_release', 'git_revisions_checked',
                          'compile', 'reference', 'store', 'jdk', 'scope'})
ENTRY_KEYS = frozenset({'path', 'sha256', 'size'})
JDK_KEYS = frozenset({'path', 'release_sha256', 'java_version'})

READER_REFUSALS = frozenset({
    'header', 'missing_start_document', 'truncated', 'missing_end_document', 'parser_error',
    'attribute_bound', 'noncanonical_event', 'stray_attribute', 'event_accounting',
    'unexpected_token', 'invalid_name', 'invalid_value', 'duplicate_attribute', 'depth_bound',
    'wrong_root', 'multiple_roots', 'mismatched_end_tag', 'unclosed_elements', 'no_root',
    'trailing_bytes', 'post_end_probe', 'duplicate_section', 'missing_section',
    'unexpected_element', 'unexpected_attribute', 'attribute_encoding', 'duplicate_app_id',
    'duplicate_permission', 'noncanonical_string', 'duplicate_interned_string',
})
STATES = frozenset({'flags', 'permission_absent', 'app_id_absent'})
EXCEPTION_NAME = re.compile(r'[A-Za-z_$][A-Za-z0-9_$.]{0,199}')
EXIT_CODES = {'parsed': 0, 'verified': 0, 'refused': 1, 'not_run': 3}
# The JSON result could not be written. There is no result, whatever the document holds.
EXIT_UNDELIVERED = 4
SCOPE = {
    'record': 'one stored permission file, decoded offline',
    'live_permission_state': False,
    'grant_authority': False,
    'grant_or_revocation_history': False,
    'android_runtime_parser': False,
    'write_durability': False,
}

# Intake captures the final path component without following it and without opening it for
# reading, then reads the captured object through its /proc/self/fd magic link.
PATH_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
PROC_FD = '/proc/self/fd/'
JAVA_RELEASE = '17'
# Heap, processors, out of memory exit, no attach or performance data file. A fatal error
# creates no core dump from the JVM, reports to the captured stderr instead of a file and writes
# no compiler replay file.
JVM_BOUNDS = ('-Xmx512m', '-XX:ActiveProcessorCount=2', '-XX:+ExitOnOutOfMemoryError',
              '-XX:-UsePerfData', '-XX:+DisableAttachMechanism', '-XX:-CreateCoredumpOnCrash',
              '-XX:+ErrorFileToStderr', '-XX:-DumpReplayDataOnError')
# JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS are deliberately not inherited.
ENVIRONMENT = {'LC_ALL': 'C.UTF-8', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


class InputRefusal(Exception):
    """A file was not read: its code names the reason without quoting data."""

    def __init__(self, code, exception=None):
        super().__init__(code)
        self.code = code
        self.exception = exception


class NotRun(Exception):
    """The document was not evaluated because an environment precondition failed."""

    def __init__(self, reason, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class ProfileDrift(ValueError):
    """The profile itself is not the reviewed structure; the tool cannot continue."""


class BuildError(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _constant(name):
    raise ValueError('non-finite JSON number')


def strict_json(text):
    return json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)


def _relative(path):
    return (type(path) is str and bool(path) and not path.startswith('/') and '\\' not in path
            and all(part not in ('', '.', '..') for part in path.split('/')))


def _digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def tool_files(*, checks=False):
    """The exact tool bytes used for this run, read once and hashed into the provenance."""
    names = ['permission_store.py', PROFILE.name, READER.name, *FACADES]
    if checks:
        names.append(CHECKS.name)
    return {name: (HERE / name).read_bytes() for name in names}


def profile(data=None):
    """Load the pinned source profile. Any structural drift raises ProfileDrift."""
    try:
        value = strict_json((PROFILE.read_bytes() if data is None else data).decode('utf-8'))
    except ValueError:
        raise ProfileDrift('permission store profile is not strict JSON') from None
    if (type(value) is not dict or set(value) != PROFILE_KEYS
            or type(value['version']) is not int or value['version'] != 1
            or value['status'] != 'host_reader' or value['git_revisions_checked'] is not False
            or type(value['source_release']) is not str or not value['source_release']
            or type(value['scope']) is not str or not value['scope']):
        raise ProfileDrift('permission store profile drift')
    for group, expected in SOURCE_GROUPS:
        entries = value[group]
        if type(entries) is not list or len(entries) != len(expected):
            raise ProfileDrift('permission store profile drift: ' + group)
        for entry, path in zip(entries, expected):
            if (type(entry) is not dict or set(entry) != ENTRY_KEYS or entry['path'] != path
                    or not _relative(entry['path']) or not _digest(entry['sha256'])
                    or type(entry['size']) is not int
                    or not 0 < entry['size'] <= MAX_SOURCE_BYTES):
                raise ProfileDrift('permission store profile drift: ' + path)
    jdk = value['jdk']
    if (type(jdk) is not dict or set(jdk) != JDK_KEYS or not _relative(jdk['path'])
            or not _digest(jdk['release_sha256']) or type(jdk['java_version']) is not str
            or re.fullmatch(r'[0-9]+', jdk['java_version']) is None):
        raise ProfileDrift('permission store profile drift: jdk')
    return value


def _identity(status):
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns,
            status.st_ctime_ns)


def _open_failed(error):
    return InputRefusal('input_open_failed',
                        'OSError:' + errno.errorcode.get(error.errno, str(error.errno)))


def read_bounded(path, limit):
    """Read one regular file of at most limit bytes, or raise InputRefusal.

    The final path component is captured with O_PATH and O_NOFOLLOW, which neither follows a
    symlink nor opens the object for reading. A symlink, FIFO, directory, device, socket or
    oversize file is refused from that capture, before any readable open. The captured object is
    then opened for reading through its /proc/self/fd link, so replacing the path afterwards
    cannot substitute another file. Both descriptors must name the same object, and its size and
    times must not change from the capture to the end of reading. Parent directories resolve
    normally, including symlinks.
    """
    try:
        handle = os.open(path, PATH_FLAGS)
    except OSError as error:
        raise _open_failed(error) from None
    try:
        captured = os.fstat(handle)
        if stat.S_ISLNK(captured.st_mode):
            raise InputRefusal('input_symlink')
        if not stat.S_ISREG(captured.st_mode):
            raise InputRefusal('input_not_regular')
        if captured.st_size > limit:
            raise InputRefusal('input_too_large')
        # The kernel link names the captured object. O_NOFOLLOW would refuse the link itself.
        try:
            fd = os.open(PROC_FD + str(handle), READ_FLAGS)
        except OSError as error:
            raise _open_failed(error) from None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(captured):
                raise InputRefusal('input_changed')
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, min(1 << 20, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise InputRefusal('input_too_large')
            after = os.fstat(fd)
        finally:
            os.close(fd)
    finally:
        os.close(handle)
    data = b''.join(chunks)
    if len(data) != before.st_size or _identity(after) != _identity(before):
        raise InputRefusal('input_changed')
    return data


def read_input(path):
    return read_bounded(path, MAX_INPUT_BYTES)


def validate_app_ids(app_ids):
    values = list(app_ids)
    if (not 0 < len(values) <= MAX_APP_IDS or len(set(values)) != len(values)
            or any(type(value) is not int or not MIN_APP_ID <= value <= MAX_APP_ID
                   for value in values)):
        raise ValueError('1 to 64 distinct app ids from 10000 to 19999 are required')
    return values


def app_id_argument(text):
    if re.fullmatch(r'[1-9][0-9]{4}', text) is None or not MIN_APP_ID <= int(text) <= MAX_APP_ID:
        raise argparse.ArgumentTypeError('app ids are decimal numbers from 10000 to 19999')
    return int(text)


def verify_sources(source_root, value):
    """Return the exact pinned bytes keyed by profile path. Any drift raises NotRun."""
    try:
        root = Path(source_root).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise NotRun('source_root', type(error).__name__) from None
    if not root.is_dir():
        raise NotRun('source_root', 'not a directory')
    pinned = {}
    for group, _ in SOURCE_GROUPS:
        for entry in value[group]:
            path = root / entry['path']
            try:
                if path.resolve(strict=True) != path:
                    raise NotRun('source_drift', entry['path'] + ': symlink in path')
                data = read_bounded(path, MAX_SOURCE_BYTES)
            except InputRefusal as refusal:
                raise NotRun('source_drift', entry['path'] + ': ' + refusal.code) from None
            except (OSError, RuntimeError) as error:
                raise NotRun('source_drift',
                             entry['path'] + ': ' + type(error).__name__) from None
            if len(data) != entry['size'] or sha(data) != entry['sha256']:
                raise NotRun('source_drift', entry['path'] + ': bytes differ from the profile')
            pinned[entry['path']] = data
    return pinned


def jdk_tools(source_root, value, override=None):
    """Locate javac and java. The pinned JDK must match its release metadata in the profile.

    Only the release metadata identifies the JDK; its binaries are not hashed.
    """
    pinned = override is None
    try:
        if pinned:
            home = Path(source_root).resolve(strict=True) / value['jdk']['path']
        else:
            home = Path(override).resolve(strict=True)
        release = read_bounded(home / 'release', 64 * 1024)
    except (InputRefusal, OSError, RuntimeError):
        raise NotRun('jdk', 'release metadata unreadable') from None
    fields = {}
    for line in release.decode('utf-8', 'replace').splitlines():
        match = re.fullmatch(r'([A-Z_]+)="([^"]*)"', line)
        if match:
            fields[match[1]] = match[2]
    version = fields.get('JAVA_VERSION', '')
    runtime = fields.get('JAVA_RUNTIME_VERSION', '')
    matches = sha(release) == value['jdk']['release_sha256']
    if pinned and (not matches or version != value['jdk']['java_version']):
        raise NotRun('jdk', 'pinned JDK release metadata differs from the profile')
    major = re.fullmatch(r'([0-9]+)(?:\.[0-9]+)*', version)
    if major is None or int(major[1]) < 17:
        raise NotRun('jdk', 'JDK 17 or later required')
    tools = {}
    for name in ('javac', 'java'):
        path = home / 'bin' / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise NotRun('jdk', name + ' missing')
        tools[name] = path
    tools['record'] = {
        'pinned_path': pinned,
        'matches_profile': matches,
        'release_sha256': sha(release),
        'java_version': version,
        'runtime_version': runtime if re.fullmatch(r'[A-Za-z0-9+._-]{1,64}', runtime) else None,
        'binaries_hashed': False,
    }
    return tools


def _limit(text, name):
    if text == 'max':
        return None
    if re.fullmatch(r'[0-9]+', text) is None:
        raise ValueError(name)
    return int(text)


def resource_guard(cgroup_root=Path('/sys/fs/cgroup'), membership=Path('/proc/self/cgroup')):
    """Require bounded memory, swap, CPU, tasks and disabled core dumps before any JDK process.

    The cgroup limits may sit on this process's cgroup or an ancestor. Nothing is created or
    changed, and RLIMIT_AS is not accepted as a substitute. Returns None or the refusal reason.
    """
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        return 'core dumps must be disabled with both limits zero'
    try:
        lines = membership.read_text().splitlines()
    except OSError as error:
        return 'cgroup membership unreadable: ' + type(error).__name__
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
                    parts = text.split()
                    if len(parts) != 2:
                        raise ValueError(name)
                    quota, period = _limit(parts[0], name), _limit(parts[1], name)
                    if period is None or period <= 0:
                        raise ValueError(name)
                    if quota is not None:
                        values.append(quota / period)
                else:
                    limit = _limit(text, name)
                    if limit is not None:
                        values.append(limit)
    except (OSError, ValueError) as error:
        return 'cgroup limits unreadable: ' + type(error).__name__
    effective = {name: min(values) if values else None for name, values in found.items()}
    if (effective['memory.max'] is None or effective['memory.max'] > 2 * GIB
            or effective['memory.swap.max'] != 0
            or effective['cpu.max'] is None or effective['cpu.max'] > 2
            or effective['pids.max'] is None or effective['pids.max'] > 256):
        return 'required bounds absent: ' + json.dumps(effective, sort_keys=True)
    return None


def _run(command, *, work, timeout, stdin=None):
    return subprocess.run([str(part) for part in command], input=stdin, capture_output=True,
                          timeout=timeout, cwd=work, env=ENVIRONMENT, check=False)


def _private(work):
    # Unused while -XX:+ErrorFileToStderr holds; any report file stays in private scratch.
    return ('-XX:ErrorFile=' + str(Path(work) / 'hs_err_%p.log'),
            '-Djava.io.tmpdir=' + str(work))


def _output(completed):
    return (completed.stdout + completed.stderr).decode('utf-8', 'replace')


def build(pinned, work, tools, files):
    """Compile pinned sources, facades and reader into work/classes.

    The pinned sources compile unchanged without lint. Andrix sources compile with all lint
    warnings as errors. Bytes come from the verified sources and the hashed tool files.
    """
    work = Path(work)
    sources = work / 'src'
    classes = work / 'classes'
    first_pass = []
    for path in COMPILE_SOURCES:
        target = sources / 'pinned' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(pinned[path])
        first_pass.append(target)
    for path in FACADES:
        target = sources / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[path])
        first_pass.append(target)
    second_pass = []
    for name in (READER.name, CHECKS.name):
        if name in files:
            target = sources / 'reader' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(files[name])
            second_pass.append(target)
    classes.mkdir()
    javac = [tools['javac'], *('-J' + flag for flag in (*JVM_BOUNDS, *_private(work)))]
    common = ['--release', JAVA_RELEASE, '-encoding', 'UTF-8', '-proc:none', '-implicit:none']
    first = _run([*javac, *common, '-Xlint:none', '-d', classes, *first_pass],
                 work=work, timeout=300)
    if first.returncode != 0:
        raise BuildError('pinned sources and facades did not compile\n' + _output(first))
    second = _run([*javac, *common, '-Xlint:all', '-Werror', '-cp', classes, '-d', classes,
                   *second_pass], work=work, timeout=300)
    if second.returncode != 0:
        raise BuildError('reader did not compile\n' + _output(second))
    return classes


def run_reader(classes, work, tools, data, app_ids, *, assertions='-ea', timeout=120):
    """Run the compiled reader with the input on stdin. Its output is not yet validated."""
    command = [tools['java'], *JVM_BOUNDS, *_private(work), assertions, '-cp', classes,
               'PermissionStoreReader', *app_ids]
    return _run(command, work=work, timeout=timeout, stdin=data)


def reader_result(completed, data, app_ids):
    """Strictly validate the reader's JSON against the input and the request."""
    if len(completed.stdout) > MAX_READER_OUTPUT:
        raise ValueError('reader output too large')
    text = completed.stdout.decode('ascii')
    if not text.endswith('\n') or '\n' in text[:-1]:
        raise ValueError('reader output framing')
    value = strict_json(text)
    if type(value) is not dict or value.get('schema') != READER_SCHEMA:
        raise ValueError('reader schema')
    binding = value.get('input')
    if (type(binding) is not dict or set(binding) != {'length', 'sha256'}
            or type(binding['length']) is not int or binding['length'] != len(data)
            or binding['sha256'] != sha(data)):
        raise ValueError('reader input binding')
    if value.get('result') == 'parsed':
        if completed.returncode != 0 or set(value) != {'schema', 'result', 'input', 'document',
                                                       'app_ids'}:
            raise ValueError('parsed result shape')
        document = value['document']
        if (type(document) is not dict
                or set(document) != {'elements', 'app_id_entries', 'permission_entries'}
                or any(type(item) is not int or not 0 <= item <= MAX_INPUT_BYTES
                       for item in document.values())
                or document['elements'] < 2 + document['app_id_entries']
                + document['permission_entries']):
            raise ValueError('document summary')
        entries = value['app_ids']
        if type(entries) is not list or len(entries) != len(app_ids):
            raise ValueError('app id results')
        for entry, app_id in zip(entries, app_ids):
            if (type(entry) is not dict or set(entry) != {'app_id', 'state', 'flags'}
                    or type(entry['app_id']) is not int or entry['app_id'] != app_id
                    or type(entry['state']) is not str or entry['state'] not in STATES):
                raise ValueError('app id result')
            if entry['state'] == 'flags':
                if type(entry['flags']) is not int or not INT32[0] <= entry['flags'] <= INT32[1]:
                    raise ValueError('flags value')
            elif entry['flags'] is not None:
                raise ValueError('absent entry carries flags')
    elif value.get('result') == 'refused':
        if completed.returncode != 1 or set(value) != {'schema', 'result', 'input', 'refusal'}:
            raise ValueError('refused result shape')
        refusal = value['refusal']
        if (type(refusal) is not dict or set(refusal) != {'code', 'exception', 'offset', 'step'}
                or type(refusal['code']) is not str or refusal['code'] not in READER_REFUSALS
                or not (refusal['exception'] is None or (type(refusal['exception']) is str
                        and EXCEPTION_NAME.fullmatch(refusal['exception'])))
                or type(refusal['offset']) is not int or not 0 <= refusal['offset'] <= len(data)
                or type(refusal['step']) is not int or not 0 <= refusal['step'] <= len(data)):
            raise ValueError('refusal shape')
    else:
        raise ValueError('reader result kind')
    return value


def _provenance(files, value):
    return {
        'tool_sha256': {name: sha(data) for name, data in sorted(files.items())},
        'profile_sha256': sha(files[PROFILE.name]),
        'source_release': value['source_release'],
        'pinned_sources_verified': False,
        'git_revisions_checked': False,
        'parser': PARSER,
        'jdk': None,
    }


def _refusal(stage, code, exception=None, offset=None, step=None, exit_status=None):
    return {'stage': stage, 'code': code, 'exception': exception, 'offset': offset,
            'step': step, 'exit_status': exit_status}


def _not_run(error):
    return None if error is None else {
        'reason': error.reason,
        'detail': None if error.detail is None else str(error.detail)[-MAX_DETAIL:]}


def compose(result, app_ids, provenance, *, data=None, reader=None, refusal=None, not_run=None):
    """The decode envelope. Every decode result, including a tool error, has these keys."""
    parsed = result == 'parsed'
    return {
        'schema': SCHEMA,
        'result': result,
        'requested_app_ids': list(app_ids),
        'input': None if data is None else {'length': len(data), 'sha256': sha(data)},
        'document': reader['document'] if parsed else None,
        'app_ids': reader['app_ids'] if parsed else None,
        'refusal': refusal,
        'not_run': _not_run(not_run),
        'provenance': provenance,
        'scope': dict(SCOPE),
    }


def sources_result(result, provenance, not_run=None):
    """The check-sources envelope."""
    return {'schema': SOURCES_SCHEMA, 'result': result, 'not_run': _not_run(not_run),
            'provenance': provenance}


def tool_error(command, app_ids, error):
    """The envelope for an unexpected exception. Only the exception class is reported."""
    reason = NotRun('tool_error', type(error).__name__)
    if command == 'decode':
        return compose('not_run', app_ids, None, not_run=reason)
    return sources_result('not_run', None, reason)


def decode(source_root, input_path, app_ids, *, jdk=None):
    """Decode one stored permission file and return the complete result for JSON output."""
    app_ids = validate_app_ids(app_ids)
    files = tool_files()
    value = profile(files[PROFILE.name])
    provenance = _provenance(files, value)
    try:
        pinned = verify_sources(source_root, value)
    except NotRun as error:
        return compose('not_run', app_ids, provenance, not_run=error)
    provenance['pinned_sources_verified'] = True
    try:
        data = read_input(input_path)
    except InputRefusal as error:
        return compose('refused', app_ids, provenance,
                       refusal=_refusal('intake', error.code, error.exception))
    guard = resource_guard()
    if guard is not None:
        return compose('not_run', app_ids, provenance, data=data,
                       not_run=NotRun('resource_guard', guard))
    try:
        tools = jdk_tools(source_root, value, jdk)
    except NotRun as error:
        return compose('not_run', app_ids, provenance, data=data, not_run=error)
    provenance['jdk'] = tools['record']
    with tempfile.TemporaryDirectory(prefix='andrix-permission-store-') as directory:
        work = Path(directory)
        try:
            classes = build(pinned, work, tools, files)
        except BuildError as error:
            return compose('not_run', app_ids, provenance, data=data,
                           not_run=NotRun('build_failed', str(error)))
        except subprocess.TimeoutExpired:
            return compose('not_run', app_ids, provenance, data=data,
                           not_run=NotRun('build_failed', 'compiler timed out'))
        # From here the document has reached the parser. A reader crash, timeout or invalid
        # output is a refusal with no app id results, never not_run or absence.
        try:
            completed = run_reader(classes, work, tools, data, app_ids)
        except subprocess.TimeoutExpired:
            return compose('refused', app_ids, provenance, data=data,
                           refusal=_refusal('reader', 'reader_timeout'))
    if completed.returncode not in (0, 1):
        return compose('refused', app_ids, provenance, data=data,
                       refusal=_refusal('reader', 'reader_failure',
                                        exit_status=completed.returncode))
    try:
        reader = reader_result(completed, data, app_ids)
    except (ValueError, RecursionError):
        return compose('refused', app_ids, provenance, data=data,
                       refusal=_refusal('reader', 'reader_output_invalid',
                                        exit_status=completed.returncode))
    if reader['result'] == 'parsed':
        return compose('parsed', app_ids, provenance, data=data, reader=reader)
    detail = reader['refusal']
    return compose('refused', app_ids, provenance, data=data,
                   refusal=_refusal('reader', detail['code'], detail['exception'],
                                    detail['offset'], detail['step'], completed.returncode))


def check_sources(source_root):
    """Verify the pinned sources and JDK metadata without starting any process."""
    files = tool_files()
    value = profile(files[PROFILE.name])
    provenance = _provenance(files, value)
    try:
        verify_sources(source_root, value)
        provenance['pinned_sources_verified'] = True
        provenance['jdk'] = jdk_tools(source_root, value)['record']
    except NotRun as error:
        return sources_result('not_run', provenance, error)
    return sources_result('verified', provenance)


def _note(message):
    try:
        print('permission_store: ' + message, file=sys.stderr, flush=True)
    except Exception:
        pass


def _discard(stream):
    """Point a failed stream at /dev/null so that the flush at exit cannot fail again."""
    try:
        fd = stream.fileno()
        null = os.open(os.devnull, os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.dup2(null, fd)
        finally:
            os.close(null)
    except Exception:
        pass


def deliver(text, stream=None):
    """Write the complete JSON result. False means that no complete result was delivered."""
    stream = sys.stdout if stream is None else stream
    try:
        stream.write(text)
        stream.flush()
    except Exception as error:
        _discard(stream)
        _note('result not delivered: ' + type(error).__name__)
        return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest='command', required=True)
    decoding = commands.add_parser('decode', help='decode one stored permission file')
    decoding.add_argument('--source-root', required=True, type=Path,
                          help='pinned Android checkout; only profiled files are read')
    decoding.add_argument('--input', required=True, type=Path,
                          help='regular file of at most 8 MiB; a final symlink is refused')
    decoding.add_argument('--app-id', required=True, action='append', type=app_id_argument,
                          dest='app_ids', help='ordinary app id, 10000 to 19999; repeatable')
    decoding.add_argument('--jdk', type=Path, help='JDK home instead of the pinned prebuilt')
    checking = commands.add_parser('check-sources',
                                   help='verify pinned sources and JDK metadata only')
    checking.add_argument('--source-root', required=True, type=Path)
    args = parser.parse_args(argv)
    app_ids = args.app_ids if args.command == 'decode' else None
    if app_ids is not None and (len(app_ids) > MAX_APP_IDS or len(set(app_ids)) != len(app_ids)):
        parser.error('1 to 64 distinct --app-id values are required')
    try:
        if args.command == 'decode':
            output = decode(args.source_root, args.input, app_ids, jdk=args.jdk)
        else:
            output = check_sources(args.source_root)
        text = json.dumps(output, indent=2, sort_keys=True) + '\n'
    except Exception as error:
        # A traceback would exit 1, which means refused, and could quote data. The class alone
        # names the failure, in the envelope of the command that failed.
        output = tool_error(args.command, app_ids, error)
        text = json.dumps(output, indent=2, sort_keys=True) + '\n'
    if not deliver(text):
        return EXIT_UNDELIVERED
    return EXIT_CODES[output['result']]


if __name__ == '__main__':
    sys.exit(main())
