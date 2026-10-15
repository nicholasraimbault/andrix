#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The subject's Android owner stores from complete captured namespaces. Host side, no guest I/O.

A namespace capture holds one owner file family's raw command output: its directory before and
after, its listing before and after, each file's stat and digest before and after its pull, the
pulled bytes and, for binary XML, the booted image's own `abx2xml FILE -` output between those
bookends. Each owner's own role rule names the file its next read would use. The native store's
rule is never applied to another owner. Only a stable, bound and settled capture yields values.
The selected decoded record and the owner's dump must agree, and each setup stage pins every
expected value.

Unsettled means a write may be in progress or the capture moved, so a later bounded observation
round may settle. ValueError means the evidence is refused or unavailable. Neither is ever an
empty state. Nothing here writes, flushes, reads into a service or repairs a store.
"""
import re
from protocol import CHANNEL, JOB_ID, PACKAGE, SERVICE, require, sha, validate_contract
import observations as obs
import stored


class Unsettled(ValueError):
    """A transient observation: a write may be in progress or the capture moved."""


STAT_FORMAT = '%d|%i|%h|%b|%B|%u|%g|%a|%s|%x|%y|%z|%C|%F|%n'
TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9} \+0000')
TYPES = ('regular file', 'regular empty file', 'directory', 'symbolic link', 'fifo', 'socket',
         'character special file', 'block special file')
REGULAR = ('regular file', 'regular empty file')
# A file's identity: everything but access time, which a read may change.
IDENTITY = ('device', 'inode', 'links', 'uid', 'gid', 'mode', 'size', 'mtime', 'ctime',
            'context', 'type')
# A shared directory changes its times for unrelated siblings; a dedicated one keeps them.
SHARED_DIRECTORY = ('device', 'inode', 'uid', 'gid', 'mode', 'context', 'type')
DEDICATED_DIRECTORY = SHARED_DIRECTORY + ('mtime', 'ctime')
# The pinned binary XML serializer's magic. Its codec source is outside these roots; the
# repository's offline permission store reader pins it.
ABX_MAGIC = b'ABX\x00'
MAX_FILE = 16 * 1024 * 1024
MAX_ENTRIES = 4096
SYSTEM_LABEL = 'u:object_r:system_data_file:s0'

ATOMIC, ATOMIC_RESERVE, RESILIENT, JOBS, TREE = (
    'atomic-file', 'atomic-file-reserve-copy', 'resilient-atomic-file', 'job-directory', 'tree')
# Every owner family the settled read captures. 'patterns' are the listing's -name patterns and
# None lists the whole directory. 'decode' families yield selected records. 'pinned' metadata is
# what the owner's own writer sets. A dedicated directory belongs to its owner alone.
FAMILIES = {
    'packages': {'kind': RESILIENT, 'parent': '/data/system', 'main': 'packages.xml',
                 'backup': 'packages-backup.xml', 'reserve': 'packages.xml.reservecopy',
                 'patterns': ('packages.xml*', 'packages-backup.xml*'), 'decode': False,
                 'dedicated': False,
                 'pinned': {'uid': 1000, 'gid': 1000, 'mode': '660', 'context': SYSTEM_LABEL}},
    'restrictions': {'kind': RESILIENT, 'parent': '/data/system/users/0',
                     'main': 'package-restrictions.xml',
                     'backup': 'package-restrictions-backup.xml',
                     'reserve': 'package-restrictions.xml.reservecopy',
                     'patterns': ('package-restrictions.xml*',
                                  'package-restrictions-backup.xml*'),
                     'decode': False, 'dedicated': False,
                     'pinned': {'uid': 1000, 'gid': 1000, 'mode': '660'}},
    'access': {'kind': ATOMIC_RESERVE, 'main': 'access.abx',
               'parent': '/data/misc_de/0/apexdata/com.android.permission',
               'patterns': ('access.abx*',), 'decode': True, 'dedicated': False,
               'pinned': {}},
    'access-system': {'kind': ATOMIC_RESERVE, 'main': 'access.abx',
                      'parent': '/data/misc/apexdata/com.android.permission',
                      'patterns': ('access.abx*',), 'decode': False, 'dedicated': False,
                      'pinned': {}},
    'notification': {'kind': ATOMIC, 'parent': '/data/system', 'main': 'notification_policy.xml',
                     'patterns': ('notification_policy.xml*',), 'decode': True,
                     'dedicated': False, 'pinned': {}},
    'jobs': {'kind': JOBS, 'parent': '/data/system/job', 'patterns': None, 'decode': True,
             'dedicated': True, 'pinned': {}},
    'native': {'kind': TREE, 'parent': '/data/system/native-principals', 'patterns': None,
               'decode': False, 'dedicated': True, 'pinned': {}},
}
SUBJECT_FAMILIES = ('access', 'jobs', 'notification')
# Only these owners may be wholly absent at a stop boundary, and only where a phase says so: the
# native store for a missing store layout, and the notification policy before its first write.
# Package Manager and the Access store always need their finished main and reserve.
ABSENCE_ADMISSIBLE = ('native', 'notification')
PERMISSION = 'android.permission.POST_NOTIFICATIONS'
OP = 'android:vibrate'
# Internal Access flag bits, in bit order, and their dump names.
FLAG_NAMES = ('INSTALL_GRANTED', 'INSTALL_REVOKED', 'PROTECTION_GRANTED', 'ROLE',
              'RUNTIME_GRANTED', 'USER_SET', 'USER_FIXED', 'POLICY_FIXED', 'SYSTEM_FIXED',
              'PREGRANT', 'LEGACY_GRANTED', 'IMPLICIT_GRANTED', 'IMPLICIT',
              'USER_SENSITIVE_WHEN_GRANTED', 'USER_SENSITIVE_WHEN_REVOKED', 'INSTALLER_EXEMPT',
              'SYSTEM_EXEMPT', 'UPGRADE_EXEMPT', 'RESTRICTION_REVOKED', 'SOFT_RESTRICTED',
              'APP_OP_REVOKED', 'ONE_TIME', 'HIBERNATION', 'USER_SELECTED', 'PURPOSE_REVOKED',
              'TRUSTED_UI_SHOWN', 'TRUSTED_UI_CONSENTED')
BIT = {name: 1 << index for index, name in enumerate(FLAG_NAMES)}
MODE_NAMES = ('allow', 'ignore', 'deny', 'default', 'foreground')
MODE_IGNORED = 1
RESTORED_UID = '-1'


# Raw command captures.

def _capture(capture, argv):
    require(type(capture) is dict and set(capture) == {
        'argv', 'stdout', 'stderr', 'exit_code', 'complete'}, 'capture fields')
    require(capture['argv'] == argv and capture['complete'] is True
            and type(capture['exit_code']) is int, 'command, transport or completeness')
    return capture


def stat_row(capture, path):
    """One stat row of exactly this path in the fixed fifteen field form."""
    text = obs.capture_text(capture, ['stat', '-c', STAT_FORMAT, path])
    lines = text.split('\n')
    require(len(lines) == 2 and lines[1] == '', 'one stat row')
    fields = lines[0].split('|')
    require(len(fields) == 15 and fields[14] == path, 'stat row form or path')
    require(all(re.fullmatch(r'0|[1-9][0-9]{0,19}', x) for x in fields[:7] + [fields[8]])
            and re.fullmatch(r'[0-7]{3,4}', fields[7])
            and all(TIME.fullmatch(x) for x in fields[9:12])
            and re.fullmatch(r'u:object_r:[a-z0-9_]+:s0(?::c[0-9]+(?:\.c[0-9]+)?'
                             r'(?:,c[0-9]+(?:\.c[0-9]+)?)*)?', fields[12])
            and fields[13] in TYPES, 'stat row values')
    device, inode, links, blocks, unit, uid, gid = map(int, fields[:7])
    return {'device': device, 'inode': inode, 'links': links, 'blocks': blocks,
            'block_unit': unit, 'uid': uid, 'gid': gid, 'mode': fields[7].lstrip('0') or '0',
            'size': int(fields[8]), 'atime': fields[9], 'mtime': fields[10],
            'ctime': fields[11], 'context': fields[12], 'type': fields[13]}


def stat_or_absent(capture, path):
    """The same stat command, or its exact ENOENT. Any other failure is unavailable."""
    _capture(capture, ['stat', '-c', STAT_FORMAT, path])
    if capture['exit_code'] == 0:
        return stat_row(capture, path)
    stderr = capture['stderr']
    require(capture['exit_code'] == 1 and capture['stdout'] == '' and type(stderr) is str
            and stderr.endswith('\n') and len(stderr.splitlines()) == 1 and path in stderr
            and stderr.rstrip('\n').endswith('No such file or directory'),
            'absence is not ENOENT')
    return None


def digest(capture, path):
    text = obs.capture_text(capture, ['sha256sum', path])
    match = re.fullmatch(r'([0-9a-f]{64})  ' + re.escape(path) + r'\n', text)
    require(match is not None, 'digest line')
    return match[1]


def converted(capture, path):
    """The image's own converter output. Its codec is qualified on the guest, not here."""
    _capture(capture, ['abx2xml', path, '-'])
    require(capture['exit_code'] == 0 and capture['stderr'] in ('', b'')
            and type(capture['stdout']) is bytes and 0 < len(capture['stdout']) <= MAX_FILE,
            'converter exit, error output or bounds')
    return capture['stdout']


def _pulled(record, path):
    require(type(record) is dict and set(record) == {'path', 'bytes', 'complete'}
            and record['path'] == path and record['complete'] is True
            and type(record['bytes']) is bytes and len(record['bytes']) <= MAX_FILE,
            'pulled copy')
    return record['bytes']


def identity(row, keys=IDENTITY):
    return {key: row[key] for key in keys}


def listing_argvs(family):
    f = FAMILIES[family]
    if f['kind'] == TREE:
        return [['find', f['parent'], '-mindepth', '1']]
    base = ['find', f['parent'], '-mindepth', '1', '-maxdepth', '1']
    return [base] if f['patterns'] is None else [base + ['-name', p] for p in f['patterns']]


def file_argvs(path):
    """The frozen per file read grammar, in capture order. The vehicle owns the transport."""
    return {'stat_before': ['stat', '-c', STAT_FORMAT, path], 'sha256_before': ['sha256sum', path],
            'pull': ['pull', path], 'decode': ['abx2xml', path, '-'],
            'sha256_after': ['sha256sum', path], 'stat_after': ['stat', '-c', STAT_FORMAT, path]}


def _name(path, parent, tree):
    require(type(path) is str and path.startswith(parent + '/') and len(path) <= 4096,
            'listed path outside its owner directory')
    parts = path[len(parent) + 1:].split('/')
    require(all(part not in ('', '.', '..') and len(part) <= 255
                and re.fullmatch(r'[A-Za-z0-9._+=~@-]+', part) for part in parts)
            and (tree or len(parts) == 1), 'listed name form')
    return '/'.join(parts)


def _listing(captures, family):
    f = FAMILIES[family]
    argvs = listing_argvs(family)
    require(type(captures) is list and len(captures) == len(argvs), 'complete listing')
    names = []
    for capture, argv in zip(captures, argvs):
        names += [_name(line, f['parent'], f['kind'] == TREE)
                  for line in obs.capture_text(capture, argv).splitlines()]
    require(len(names) == len(set(names)) and len(names) <= MAX_ENTRIES,
            'duplicate listing or entry bounds')
    return set(names)


# Role rules, each exactly as its owner's source defines it.

JOB_NAME = re.compile(r'(jobs(?:_(0|[1-9][0-9]{0,9}))?\.xml)(\.new|\.bak)?')


def roles(family, names):
    """Each listed name's role under its owner's own rule. An unknown sibling is refused."""
    f = FAMILIES[family]
    if f['kind'] == TREE:
        return {name: 'entry' for name in names}
    if f['kind'] == JOBS:
        result = {}
        for name in names:
            match = JOB_NAME.fullmatch(name)
            require(match is not None and (match[2] is None or int(match[2]) < 1 << 31),
                    'unknown job directory entry')
            result[name] = {None: 'primary', '.new': 'new', '.bak': 'legacy-backup'}[match[3]]
        return result
    main = f['main']
    if f['kind'] == ATOMIC:
        known = {main: 'base', main + '.new': 'new', main + '.bak': 'legacy-backup'}
    elif f['kind'] == ATOMIC_RESERVE:
        reserve = main + '.reservecopy'
        known = {main: 'main', main + '.new': 'new', main + '.bak': 'legacy-backup',
                 reserve: 'reserve', reserve + '.new': 'reserve-new',
                 reserve + '.bak': 'reserve-legacy-backup'}
    else:
        known = {main: 'main', f['backup']: 'backup', f['reserve']: 'reserve'}
    require(all(name in known for name in names), 'unknown owner sibling')
    return {name: known[name] for name in names}


def layout(family, names, digests):
    """The next read and every transaction sibling, exactly as each owner's source defines them.

    AtomicFile writes .new and renames it over the base; a legacy .bak is renamed over the base
    before a read or write, and a .new beside a base is deleted. The Access store then copies the
    finished main into .reservecopy, and reads that copy only when parsing the main fails, never
    when the main is absent. ResilientAtomicFile keeps a temporary backup through each write and
    reads it first, then the main, then the reserve. JobStore reads exactly jobs.xml and
    jobs_UID.xml, each through AtomicFile, and never a .new or .bak whose base is absent.
    """
    f = FAMILIES[family]
    present = set(names)
    transactions = []
    if f['kind'] == TREE:
        return {'next_read': None, 'transactions': [], 'settled': True, 'absent': not present}
    if f['kind'] == JOBS:
        named = roles(family, present)
        primaries = sorted(name for name, role in named.items() if role == 'primary')
        for name, role in sorted(named.items()):
            if role != 'primary':
                transactions.append(role + (':' if name[:-4] in present else ':orphan:') + name)
        return {'next_read': {base: base + '.bak' if base + '.bak' in present else base
                              for base in primaries},
                'transactions': transactions, 'settled': not transactions,
                'absent': not primaries, 'primaries': primaries}
    main = f['main']
    if f['kind'] == ATOMIC:
        transactions = [role for suffix, role in (('.new', 'new'), ('.bak', 'legacy-backup'))
                        if main + suffix in present]
        return {'next_read': main + '.bak' if main + '.bak' in present
                else main if main in present else None,
                'transactions': transactions, 'settled': not transactions,
                'absent': not present}
    if f['kind'] == ATOMIC_RESERVE:
        reserve = main + '.reservecopy'
        transactions = [role for name, role in (
            (main + '.new', 'new'), (main + '.bak', 'legacy-backup'),
            (reserve + '.new', 'reserve-new'), (reserve + '.bak', 'reserve-legacy-backup'))
            if name in present]
        next_read = (main + '.bak' if main + '.bak' in present
                     else main if main in present else None)
    else:
        reserve = f['reserve']
        if f['backup'] in present:
            transactions.append('backup-present')
        next_read = (f['backup'] if f['backup'] in present else main if main in present
                     else reserve if reserve in present else None)
    if present and main not in present:
        transactions.append('main-missing')
    if main in present and reserve not in present:
        transactions.append('reserve-missing')
    if main in present and reserve in present and digests.get(main) != digests.get(reserve):
        transactions.append('reserve-lag')
    return {'next_read': next_read, 'transactions': transactions, 'settled': not transactions,
            'absent': not present, 'reserve': reserve}


# Namespace captures.

def _bookends(record, path):
    """An entry that vanished between its listing and its last stat is transient, not refused."""
    before = stat_or_absent(record['stat_before'], path)
    after = stat_or_absent(record['stat_after'], path)
    if before is None or after is None:
        raise Unsettled('entry vanished during capture: ' + path)
    return before, after


def _file(path, record):
    require(type(record) is dict and set(record) == set(file_argvs(path)), 'file capture fields')
    before, after = _bookends(record, path)
    require(before['type'] in REGULAR and before['links'] == 1,
            'link, alias or special entry: ' + path)
    require(before['size'] <= MAX_FILE, 'file bounds')
    if identity(before) != identity(after):
        raise Unsettled('file changed during capture: ' + path)
    first, last = digest(record['sha256_before'], path), digest(record['sha256_after'], path)
    if first != last:
        raise Unsettled('file content changed during capture: ' + path)
    data = _pulled(record['pull'], path)
    require(len(data) == before['size'] and sha(data) == first,
            'pulled bytes are not the stable captured file')
    return {'metadata': before, 'sha256': first, 'bytes': data, 'decode': record['decode']}


def _directory(path, record):
    require(type(record) is dict and set(record) == {'stat_before', 'stat_after'},
            'directory capture fields')
    before, after = _bookends(record, path)
    require(before['type'] == 'directory', 'link or special entry in a tree: ' + path)
    if identity(before, DEDICATED_DIRECTORY) != identity(after, DEDICATED_DIRECTORY):
        raise Unsettled('directory changed during capture: ' + path)
    return {'metadata': before}


def _root_keys(family):
    return DEDICATED_DIRECTORY if FAMILIES[family]['dedicated'] else SHARED_DIRECTORY


NAMESPACE_FIELDS = {'root', 'listing', 'files', 'directories', 'listing_after', 'root_after'}


def namespace(family, capture, absent_allowed=False):
    """One owner family's complete, stable namespace, its roles and its selected decoded files.

    Raises Unsettled while a transaction sibling exists or anything moved during the capture,
    and ValueError for refused, incomplete, aliased, linked, unknown or unbound evidence. The
    owner's required files must exist: the finished main and reserve of Package Manager and the
    Access store, the notification policy base, the job directory. absent_allowed is a phase's
    explicit exception for a native store or a notification policy that may not exist yet.
    """
    require(family in FAMILIES and type(absent_allowed) is bool
            and (not absent_allowed or family in ABSENCE_ADMISSIBLE),
            'owner family or an inadmissible absence')
    f = FAMILIES[family]
    require(type(capture) is dict and set(capture) == NAMESPACE_FIELDS, 'namespace capture fields')
    root = stat_or_absent(capture['root'], f['parent'])
    root_after = stat_or_absent(capture['root_after'], f['parent'])
    if root is None or root_after is None:
        require(absent_allowed and f['kind'] == TREE, 'owner directory absent')
        if root is not None or root_after is not None:
            raise Unsettled('owner directory appeared or vanished during capture')
        require(capture['listing'] == [] and capture['listing_after'] == []
                and capture['files'] == {} and capture['directories'] == {},
                'absent owner directory with entries')
        return {'family': family, 'kind': f['kind'], 'present': False, 'root': None,
                'files': {}, 'directories': {}, 'roles': {}, 'layout': layout(family, set(), {}),
                'decoded': {}}
    require(root['type'] == 'directory', 'owner directory type')
    if identity(root, _root_keys(family)) != identity(root_after, _root_keys(family)):
        raise Unsettled('owner directory changed during capture')
    names = _listing(capture['listing'], family)
    if _listing(capture['listing_after'], family) != names:
        raise Unsettled('namespace changed during capture')
    named = roles(family, names)
    paths = {f['parent'] + '/' + name: name for name in names}
    require(type(capture['files']) is dict and type(capture['directories']) is dict
            and set(capture['files']) | set(capture['directories']) == set(paths)
            and not set(capture['files']) & set(capture['directories']),
            'captured entries differ from the listing')
    require(f['kind'] == TREE or not capture['directories'], 'directory in a file family')
    files = {paths[path]: _file(path, record) for path, record in sorted(capture['files'].items())}
    directories = {paths[path]: _directory(path, record)
                   for path, record in sorted(capture['directories'].items())}
    for name in (*files, *directories):
        require('/' not in name or name.rsplit('/', 1)[0] in directories,
                'entry outside a listed directory')
    objects = [(x['metadata']['device'], x['metadata']['inode'])
               for x in (*files.values(), *directories.values())]
    require(len(objects) == len(set(objects)), 'aliased entries')
    for name, value in files.items():
        require(all(value['metadata'][key] == wanted for key, wanted in f['pinned'].items()),
                'owner file owner, mode or label: ' + name)
    shape = layout(family, set(files), {name: value['sha256'] for name, value in files.items()})
    if shape['transactions']:
        raise Unsettled(family + ' transaction: ' + ', '.join(shape['transactions']))
    # An empty family has no transaction, but lacks the persistence a stop boundary requires:
    # ResilientAtomicFile and the Access store would read nothing and start from defaults.
    require(not shape['absent'] or f['kind'] in (JOBS, TREE) or absent_allowed,
            'required owner files absent: ' + family)
    decoded = {}
    for name, value in files.items():
        if not f['decode']:
            require(value['decode'] is None, 'converter run on a file this read never decodes')
        elif value['bytes'].startswith(ABX_MAGIC):
            require(value['decode'] is not None, 'binary XML without its converter output')
            decoded[name] = converted(value['decode'], f['parent'] + '/' + name)
        else:
            require(value['decode'] is None, 'converter output for a text file')
            decoded[name] = value['bytes']
    if f['kind'] == ATOMIC_RESERVE and f['decode'] and not shape['absent']:
        # The reserve is a byte copy of the main, so one converter gives both one record.
        require(decoded[f['main']] == decoded[shape['reserve']], 'reserve decodes differently')
    return {'family': family, 'kind': f['kind'], 'present': True, 'root': root,
            'files': {name: {'metadata': value['metadata'], 'sha256': value['sha256'],
                             'role': named[name],
                             'binary_xml': value['bytes'].startswith(ABX_MAGIC),
                             'decoded_sha256': sha(decoded[name]) if name in decoded else None}
                      for name, value in files.items()},
            'directories': {name: {'metadata': value['metadata']}
                            for name, value in directories.items()},
            'roles': named, 'layout': shape, 'decoded': decoded}


def fingerprint(state):
    """Everything a round must keep: identities, digests and roles, never access times."""
    return {'present': state['present'],
            'root': None if state['root'] is None else identity(state['root'],
                                                                _root_keys(state['family'])),
            'files': {name: dict(identity(value['metadata']), sha256=value['sha256'],
                                 role=value['role']) for name, value in state['files'].items()},
            'directories': {name: identity(value['metadata'], DEDICATED_DIRECTORY)
                            for name, value in state['directories'].items()}}


def differences(first, second):
    """Named differences between two fingerprints of one family."""
    found = [key for key in ('present', 'root') if first[key] != second[key]]
    for kind in ('files', 'directories'):
        for name in sorted(set(first[kind]) | set(second[kind])):
            if first[kind].get(name) != second[kind].get(name):
                found.append(kind[:-1] + ':' + name)
    return found


def selected_records(state):
    """The decoded records the owner's next read selects, by role, never a transaction file."""
    f = FAMILIES[state['family']]
    require(f['decode'] and state['layout']['settled'], 'settled decoded owner family')
    if f['kind'] == JOBS:
        return {name: state['decoded'][name] for name in state['layout']['primaries']}
    selected = state['layout']['next_read']
    return {} if selected is None else {selected: state['decoded'][selected]}


# Selected values. Strict on the structure of the subject's own rows; the complete pinned
# contract stays with the existing strict readers, which the stage check also runs.

def _int(text, message, signed=False):
    pattern = (r'-?' if signed else '') + r'(?:0|[1-9][0-9]{0,18})'
    require(type(text) is str and re.fullmatch(pattern, text) is not None, message)
    return int(text)


def _at_most_one(nodes, message):
    require(len(nodes) <= 1, message)
    return nodes[0] if nodes else None


# The Access user state grammar, as its parsers accept it: each section's owner element, its key
# attribute and its rows, nested once more for device permissions. Android ignores any other
# element, and a repeated owner or row replaces the earlier one, so both are refused here.
NUMBER = r'0|[1-9][0-9]{0,9}'
TEXT = r'[^\x00-\x1f]{1,1024}'
ROWS = {'permission': {'name': TEXT, 'flags': NUMBER}, 'app-op': {'name': TEXT, 'mode': '[0-4]'},
        'app-function-access': {'targetUid': NUMBER, 'flags': NUMBER}}
ACCESS_SECTIONS = {
    'app-id-permissions': ('app-id', 'id', NUMBER, ('permission',)),
    'app-id-device-permissions': ('app-id', 'id', NUMBER, ('device', 'id', TEXT, 'permission')),
    'app-id-app-ops': ('app-id', 'id', NUMBER, ('app-op',)),
    'package-app-ops': ('package', 'name', TEXT, ('app-op',)),
    'app-id-app-function-accesses': ('app-id', 'id', NUMBER, ('app-function-access',)),
}
ACCESS_REQUIRED = ('package-versions', 'app-id-permissions', 'app-id-app-ops', 'package-app-ops')


def _element(node, tag, attrs, children=False):
    require(node.tag == tag and set(node.attrib) == set(attrs)
            and all(re.fullmatch(pattern, node.get(name)) for name, pattern in attrs.items())
            and (children or not len(node)), 'Access element, attribute or nesting: ' + node.tag)


def _rows(owner, tag, key):
    seen = set()
    for row in owner:
        _element(row, tag, ROWS[tag])
        require(row.get(key) not in seen, 'duplicate Access row')
        seen.add(row.get(key))


def access_grammar(root):
    """The complete Access document, refused at any stage unless every element is one Android's
    parsers read. The subject's values are then taken only from validated owners and rows."""
    require(root.tag == 'access' and not root.attrib, 'Access root')
    tags = [node.tag for node in root]
    require(all(tags.count(tag) == 1 for tag in ACCESS_REQUIRED) and len(tags) == len(set(tags))
            and set(tags) <= set(ACCESS_REQUIRED) | set(ACCESS_SECTIONS)
            | {'default-permission-grant', 'app-function-pregrant'}, 'Access sections')
    for section in root:
        if section.tag in ('default-permission-grant', 'app-function-pregrant'):
            _element(section, section.tag, {'fingerprint': TEXT})
            continue
        _element(section, section.tag, {}, children=True)
        if section.tag == 'package-versions':
            seen = set()
            for row in section:
                _element(row, 'package', {'name': TEXT, 'version': NUMBER})
                require(row.get('name') not in seen, 'duplicate stored package version')
                seen.add(row.get('name'))
            continue
        owner_tag, key, pattern, nested = ACCESS_SECTIONS[section.tag]
        owners = set()
        for owner in section:
            _element(owner, owner_tag, {key: pattern}, children=True)
            require(owner.get(key) not in owners, 'duplicate Access owner')
            owners.add(owner.get(key))
            if len(nested) == 1:
                _rows(owner, nested[0], next(iter(ROWS[nested[0]])))
                continue
            devices = set()
            for device in owner:
                _element(device, nested[0], {nested[1]: nested[2]}, children=True)
                require(device.get(nested[1]) not in devices, 'duplicate Access device')
                devices.add(device.get(nested[1]))
                _rows(device, nested[3], 'name')
    return {node.tag: node for node in root}


def access_values(data, uid):
    """The subject's permission flags, both scoped modes and its migration version, as stored."""
    require(type(uid) is int and 10000 <= uid <= 19999, 'application UID')
    section = access_grammar(stored.decoded_root(data, 'access'))
    version = _at_most_one([x for x in section['package-versions'] if x.get('name') == PACKAGE],
                           'duplicate stored package version')
    row = _at_most_one([x for x in section['app-id-permissions'] if x.get('id') == str(uid)],
                       'duplicate stored app ID permissions')
    permissions = {item.get('name'): int(item.get('flags'))
                   for item in (row if row is not None else [])}
    modes = {}
    for tag, key, target in (('app-id-app-ops', 'id', str(uid)),
                             ('package-app-ops', 'name', PACKAGE)):
        owner = _at_most_one([x for x in section[tag] if x.get(key) == target],
                             'duplicate stored app operation owner')
        modes[tag] = {item.get('name'): int(item.get('mode'))
                      for item in (owner if owner is not None else [])}
    return {'migration_version': None if version is None else int(version.get('version')),
            'permission_flags': permissions.get(PERMISSION), 'permissions': permissions,
            'uid_mode': modes['app-id-app-ops'].get(OP), 'uid_ops': modes['app-id-app-ops'],
            'package_mode': modes['package-app-ops'].get(OP),
            'package_ops': modes['package-app-ops']}


def notification_values(data):
    """Every stored preference row named for the subject, with its UID and channels."""
    root = stored.decoded_root(data, 'notification-policy')
    rankings = [x for x in root if x.tag == 'ranking']
    require(len(rankings) == 1 and len(root.findall('.//ranking')) == 1, 'one ranking section')
    own = [x for x in rankings[0] if x.tag == 'package' and x.get('name') == PACKAGE]
    require(len(root.findall('.//package[@name="' + PACKAGE + '"]')) == len(own),
            'misnested subject preference')
    packages = []
    for package in own:
        channels = {}
        for channel in package:
            if channel.tag == 'channel':
                require(channel.get('id') and channel.get('id') not in channels
                        and not len(channel), 'stored channel identity')
                channels[channel.get('id')] = dict(channel.attrib)
        packages.append({'uid': package.get('uid'), 'attrs': dict(package.attrib),
                         'channels': channels,
                         'other': sorted({x.tag for x in package} - {'channel'})})
    return {'packages': packages}


def job_values(files, uid):
    """Every stored job of the subject's UID or package across all selected primary files.

    JobStore keeps whichever duplicate identity it lists first and drops the other, so a
    duplicate across the legacy and split files, or a split file naming another UID, is refused.
    """
    require(type(files) is dict and len(files) <= MAX_ENTRIES, 'selected job files')
    found, identities = [], set()
    for name, data in sorted(files.items()):
        match = JOB_NAME.fullmatch(name)
        require(match is not None and match[3] is None, 'selected job file name')
        root = stored.decoded_root(data, 'job-info')
        for job in root:
            key = (job.get('uid'), job.get('namespace'), job.get('jobid'))
            require(job.tag == 'job' and None not in (key[0], key[2]) and key not in identities
                    and (match[2] is None or key[0] == match[2]),
                    'duplicate, misfiled or unidentified stored job')
            identities.add(key)
            if job.get('uid') != str(uid) and job.get('package') != PACKAGE:
                continue
            children = []
            for child in job:
                items = {}
                if child.tag == 'extras':
                    for item in child:
                        require(item.get('name') is not None and item.get('name') not in items,
                                'duplicate stored job extra')
                        items[item.get('name')] = (item.tag, item.text or '')
                children.append({'tag': child.tag, 'attrs': dict(child.attrib), 'items': items})
            found.append({'file': name, 'attrs': dict(job.attrib), 'children': children})
    return {'jobs': found}


def flags_names(value):
    """PermissionFlags.toString order: ascending bits, an unnamed bit in hexadecimal."""
    return [FLAG_NAMES[bit] if bit < len(FLAG_NAMES) else '0x%X' % (1 << bit)
            for bit in range(32) if value >> bit & 1]


def flags_value(names):
    require(type(names) is list and len(names) == len(set(names)), 'flag names')
    value = 0
    for name in names:
        if name in BIT:
            value |= BIT[name]
        else:
            match = re.fullmatch(r'0x([0-9A-Fa-f]{1,8})', name)
            require(match is not None, 'unknown flag name')
            value |= int(match[1], 16)
    require(flags_names(value) == [x if x in BIT else '0x%X' % int(x, 16) for x in names],
            'flag order or form')
    return value


def granted(flags):
    """PermissionFlags.isPermissionGranted for one internal flags integer."""
    if flags & BIT['PURPOSE_REVOKED']:
        return False
    if flags & BIT['INSTALL_GRANTED']:
        return True
    if flags & BIT['INSTALL_REVOKED']:
        return False
    if flags & (BIT['PROTECTION_GRANTED'] | BIT['LEGACY_GRANTED'] | BIT['IMPLICIT_GRANTED']):
        return True
    if flags & BIT['RESTRICTION_REVOKED']:
        return False
    return bool(flags & BIT['RUNTIME_GRANTED'])


def _mode(name):
    require(name is None or name in MODE_NAMES, 'app operation mode name')
    return None if name is None else MODE_NAMES.index(name)


def permission_dump_values(by_app_id, by_package, uid):
    """Both permission selectors must render one identical saved state for the subject."""
    first = obs.permissionmgr(by_app_id, uid, 'app-id')
    second = obs.permissionmgr(by_package, uid, 'package')
    require(first == second, 'permission selectors disagree')
    permissions = {}
    for name, row in first['permissions'].items():
        permissions[name] = flags_value(row['flags'])
        require(row['granted'] is granted(permissions[name]), 'rendered grant and flags disagree')
    return {'migration_version': first['version'],
            'permission_flags': permissions.get(PERMISSION), 'permissions': permissions,
            'uid_mode': _mode(first['uid_ops'].get(OP)),
            'package_mode': _mode(first['package_ops'].get(OP))}


APPOP_LINE = re.compile(r'(Uid mode: )?VIBRATE: (allow|ignore|deny|default|foreground)(.*)')
APPOP_SUFFIX = re.compile(r'(?:; time=[^;]+ ago)?(?:; rejectTime=[^;]+ ago)?'
                          r'(?: \(running\)|; duration=[^;]+)?')


def appops_values(package_capture, uid_capture, uid):
    """Package and UID VIBRATE modes from both appops queries, and any rendered access history."""
    require(type(uid) is int and 10000 <= uid <= 19999, 'application UID')
    values = {}
    for scope, capture, argv in (
            ('package', package_capture,
             ['cmd', 'appops', 'get', '--user', '0', PACKAGE, 'VIBRATE']),
            ('uid', uid_capture, ['cmd', 'appops', 'get', str(uid), 'VIBRATE'])):
        text = obs.capture_text(capture, argv)
        found = {'uid_mode': None, 'package_mode': None, 'history': False}
        if text != 'No operations.\nDefault mode: allow\n':
            lines = text.split('\n')
            require(lines[-1] == '' and 1 <= len(lines) - 1 <= 2, 'appops get form')
            for index, line in enumerate(lines[:-1]):
                match = APPOP_LINE.fullmatch(line)
                require(match is not None and APPOP_SUFFIX.fullmatch(match[3]) is not None,
                        'appops get row')
                key = 'uid_mode' if match[1] else 'package_mode'
                # UID operations print before package operations, each at most once.
                require(found[key] is None and (key == 'package_mode' or index == 0),
                        'duplicate or misordered appops row')
                found[key] = MODE_NAMES.index(match[2])
                found['history'] = found['history'] or bool(match[3])
        require(scope == 'package' or found['package_mode'] is None, 'UID query names a package')
        values[scope] = found
    require(values['package']['uid_mode'] == values['uid']['uid_mode'],
            'the two appops queries disagree on the UID mode')
    return {'package_mode': values['package']['package_mode'],
            'uid_mode': values['uid']['uid_mode'],
            'history': values['package']['history'] or values['uid']['history']}


def notification_dump_values(capture):
    """Every rendered preference row named for the subject, with its UID and complete channels."""
    text = obs.capture_text(capture, ['dumpsys', 'notification', '--noredact', '--package',
                                      PACKAGE])
    lines = text.splitlines()
    starts = [i for i, x in enumerate(lines) if x == 'PackagePreferences:']
    restored = [i for i, x in enumerate(lines) if x == 'Restored without uid:']
    ends = [i for i, x in enumerate(lines) if x == '  Notification listeners:']
    require(len(starts) == len(restored) == len(ends) == 1
            and 0 < starts[0] < restored[0] < ends[0]
            and lines[starts[0] - 1] == '    per-package config version: 4',
            'complete notification preferences section')
    packages, current = [], None
    for index in range(starts[0] + 1, ends[0]):
        line = lines[index]
        if not line or line == 'Restored without uid:':
            current = None
            continue
        app = re.fullmatch(r'      AppSettings: ([A-Za-z0-9_.]+) \((INVALID_UID|[0-9]+)\)(.*)',
                           line)
        if app:
            current = None
            if app[1] == PACKAGE:
                current = {'uid': app[2], 'restored': index > restored[0], 'extra': app[3],
                           'channels': {}, 'other': []}
                packages.append(current)
        elif current is not None:
            if line.startswith('        NotificationChannel{'):
                fields = obs.channel_fields(line[8:])
                require(fields['mId'] not in current['channels'], 'duplicate rendered channel')
                current['channels'][fields['mId']] = fields
            else:
                current['other'].append(line)
        elif PACKAGE in line or CHANNEL in line:
            raise ValueError('selected preference outside its package block')
    return {'packages': packages}


EXECUTION_FIELD = re.compile(r'(Num failures|Num system stops|Last successful run|'
                             r'Last failed run|Cumulative execution time)[:=]')


def job_dump_values(capture, uid):
    """Every registered job of the subject's UID or package, and every execution reference."""
    require(type(uid) is int and 10000 <= uid <= 19999, 'application UID')
    lines = obs.capture_text(capture, ['dumpsys', 'jobscheduler']).splitlines()
    fu = 'u0a' + str(uid - 10000)
    heads = [(i, int(m[1])) for i, line in enumerate(lines)
             if (m := re.fullmatch(r'Registered (0|[1-9][0-9]*) jobs:', line))]
    require(len(heads) == 1, 'registered jobs section')
    start, count = heads[0]
    end = next((i for i in range(start + 1, len(lines))
                if lines[i] and not lines[i].startswith(' ')), len(lines))
    require(end < len(lines) and all(lines.count(x) == 1 for x in (
        'Pending queue:', 'Active jobs:', 'Recently completed jobs:')),
        'complete unfiltered job dump')
    blocks, current = [], None
    for line in lines[start + 1:end]:
        if not line:
            continue
        if line.startswith('  JOB '):
            match = re.fullmatch(r'  JOB (?:#|([^ /:]+):)([^ /:]+)/(-?[0-9]+): ([0-9a-f]+) (\S+)',
                                 line)
            require(match is not None, 'registered job identity')
            current = {'namespace': match[1], 'calling': match[2], 'id': int(match[3]),
                       'component': match[5], 'lines': []}
            blocks.append(current)
        elif current is not None:
            current['lines'].append(line)
        else:
            require(count == 0 and line == '  None.', 'unexpected registered job content')
    require(len(blocks) == count, 'filtered or truncated registered jobs')
    own = []
    for block in blocks:
        if block['calling'] != fu and not block['component'].startswith(PACKAGE + '/'):
            continue
        facts = {key: block[key] for key in ('namespace', 'calling', 'id', 'component')}
        facts.update(source=None, earliest_ms=None, comp=None, persisted=False, extras=None,
                     executions=[])
        for raw in block['lines']:
            line = raw.strip()
            if line.startswith('Source: '):
                require(facts['source'] is None, 'duplicate job source')
                facts['source'] = line[len('Source: '):]
            elif line.startswith('Run time: '):
                match = re.fullmatch(r'Run time: earliest=([^,]+), latest=[^,]+, '
                                     r'original latest=.+', line)
                require(match is not None and facts['earliest_ms'] is None, 'job run time')
                facts['earliest_ms'] = None if match[1] == 'none' else obs.duration(match[1])
            elif line.startswith('Ready: '):
                match = re.fullmatch(r'Ready: (?:true|false) \(.* comp=(true|false)\)', line)
                require(match is not None and facts['comp'] is None, 'job ready line')
                facts['comp'] = match[1] == 'true'
            elif line == 'PERSISTED':
                facts['persisted'] = True
            elif line.startswith('Extras: '):
                require(facts['extras'] is None, 'duplicate job extras')
                facts['extras'] = line[len('Extras: '):]
            elif EXECUTION_FIELD.match(line):
                facts['executions'].append(line)
        own.append(facts)
    pending = lines.index('Pending queue:')
    histories = [i for i, x in enumerate(lines) if x == '  Job history:']
    require(len(histories) <= 1, 'job history section')
    tail = lines[pending:] + (lines[histories[0]:pending] if histories else [])
    pattern = r'(?<![A-Za-z0-9_])' + re.escape('#' + fu + '/' + str(JOB_ID)) + r'(?![0-9])'
    return {'jobs': own, 'execution_references': [x for x in tail if re.search(pattern, x)]}


def rtc_ms(capture):
    """The guest's UTC wall clock in whole seconds, as milliseconds."""
    text = obs.capture_text(capture, ['date', '+%s'])
    require(re.fullmatch(r'[1-9][0-9]{8,11}\n', text) is not None, 'wall clock form')
    return int(text) * 1000


# Comparable selected values, from disk and from the dumps.

# A rendered row without local preferences can exist for the notification permission alone, so
# the subject's UIDs compare only among rows holding channels.

def _disk_channel(values, uid):
    packages = [p for p in values['packages'] if p['uid'] != RESTORED_UID]
    own = [p for p in packages if p['uid'] == str(uid)]
    channel = own[0]['channels'].get(CHANNEL) if len(own) == 1 else None
    return {'channel_uids': sorted(p['uid'] or '' for p in packages if p['channels']),
            'restored': len(values['packages']) - len(packages),
            'channels': sorted(own[0]['channels']) if len(own) == 1 else [],
            'channel': None if channel is None else {
                'name': channel.get('name'),
                'importance': _int(channel.get('importance', '-1000'), 'importance', True),
                'allow_bubbles': _int(channel.get('allow_bubbles', '-1'), 'bubbles', True),
                'locked': _int(channel.get('locked', '0'), 'lock mask'),
                'deleted': channel.get('deleted', 'false') == 'true',
                'show_badge': channel.get('show_badge', 'false') == 'true'}}


def _dump_channel(values, uid):
    packages = [p for p in values['packages'] if not p['restored']]
    own = [p for p in packages if p['uid'] == str(uid)]
    channel = own[0]['channels'].get("'" + CHANNEL + "'") if len(own) == 1 else None
    return {'channel_uids': sorted(p['uid'] for p in packages if p['channels']),
            'restored': len(values['packages']) - len(packages),
            'channels': sorted(x[1:-1] for x in own[0]['channels']) if len(own) == 1 else [],
            'channel': None if channel is None else {
                'name': channel['mName'], 'importance': channel['mImportance'],
                'allow_bubbles': channel['mAllowBubbles'], 'locked': channel['mUserLockedFields'],
                'deleted': channel['mDeleted'], 'show_badge': channel['mShowBadge']}}


def _disk_jobs(values):
    jobs = []
    for job in values['jobs']:
        attrs = job['attrs']
        timing = [c for c in job['children'] if c['tag'] in ('one-off', 'periodic')]
        extras = [c['items'] for c in job['children'] if c['tag'] == 'extras']
        delay = timing[0]['attrs'].get('delay') if len(timing) == 1 else None
        jobs.append({'uid': attrs.get('uid'), 'namespace': attrs.get('namespace'),
                     'id': attrs.get('jobid'),
                     'component': (attrs.get('package') or '') + '/' + (attrs.get('class') or ''),
                     'timing': timing[0]['tag'] if len(timing) == 1 else None,
                     'deadline': timing[0]['attrs'].get('deadline') if len(timing) == 1 else None,
                     'due_ms': None if delay is None else _int(delay, 'stored delay'),
                     'extras': None if len(extras) != 1 else {
                         name: text for name, (tag, text) in extras[0].items() if tag == 'string'},
                     'typed_extras': None if len(extras) != 1 else sorted(
                         (name, tag) for name, (tag, _) in extras[0].items()),
                     'runs': [attrs.get(k, '0') for k in ('lastSuccessfulRunTime',
                                                          'lastFailedRunTime',
                                                          'cumulativeExecutionTime')],
                     'file': job['file']})
    return jobs


def _dump_jobs(values, uid, now_ms):
    jobs = []
    for job in values['jobs']:
        component = job['component']
        if component.startswith(PACKAGE + '/.'):
            component = PACKAGE + '/' + PACKAGE + component[len(PACKAGE) + 1:]
        jobs.append({'uid': str(uid) if job['calling'] == 'u0a' + str(uid - 10000)
                     else job['calling'], 'namespace': job['namespace'], 'id': str(job['id']),
                     'component': component, 'comp': job['comp'],
                     'persisted': job['persisted'], 'extras': job['extras'],
                     'executions': job['executions'],
                     'due_ms': None if job['earliest_ms'] is None else now_ms + job['earliest_ms']})
    return jobs


def owner_values(state, dumps, uid):
    """The subject's selected values from the settled disk records and from the owner dumps."""
    require(type(state) is dict and set(state) == set(SUBJECT_FAMILIES),
            'the three subject owner families')
    require(type(dumps) is dict and set(dumps) == {
        'permission_app_id', 'permission_package', 'appops_package', 'appops_uid',
        'notification', 'jobscheduler', 'rtc'}, 'subject owner dumps')
    records = {family: selected_records(state[family]) for family in SUBJECT_FAMILIES}
    require(len(records['access']) == 1, 'selected access record')
    policy = notification_values(next(iter(records['notification'].values()))) \
        if records['notification'] else {'packages': []}
    stored_jobs = job_values(records['jobs'], uid)
    rendered = notification_dump_values(dumps['notification'])
    registered = job_dump_values(dumps['jobscheduler'], uid)
    now = rtc_ms(dumps['rtc'])
    return {'disk': {'access': access_values(next(iter(records['access'].values())), uid),
                     'channel': _disk_channel(policy, uid), 'jobs': _disk_jobs(stored_jobs),
                     'policy': policy, 'stored_jobs': stored_jobs},
            'dump': {'access': permission_dump_values(dumps['permission_app_id'],
                                                      dumps['permission_package'], uid),
                     'appops': appops_values(dumps['appops_package'], dumps['appops_uid'], uid),
                     'channel': _dump_channel(rendered, uid),
                     'jobs': _dump_jobs(registered, uid, now),
                     'execution_references': registered['execution_references'],
                     'rendered': rendered},
            'rtc_ms': now}


JOB_IDENTITY = ('uid', 'namespace', 'id', 'component')


def disagreements(values, tolerance_ms=60000):
    """Where the settled disk record and the owner's dump name different selected values."""
    disk, dump = values['disk'], values['dump']
    found = ['access:' + key for key in ('permission_flags', 'permissions', 'migration_version',
                                         'uid_mode', 'package_mode')
             if disk['access'][key] != dump['access'][key]]
    found += ['appops:' + key for key in ('uid_mode', 'package_mode')
              if dump['appops'][key] != dump['access'][key]]
    found += ['notification:' + key for key in ('channel_uids', 'restored', 'channels', 'channel')
              if disk['channel'][key] != dump['channel'][key]]
    disk_jobs = sorted((tuple(str(j[k]) for k in JOB_IDENTITY), j['due_ms'])
                       for j in disk['jobs'])
    dump_jobs = sorted((tuple(str(j[k]) for k in JOB_IDENTITY), j['due_ms'])
                       for j in dump['jobs'])
    if [x[0] for x in disk_jobs] != [x[0] for x in dump_jobs]:
        found.append('jobs:identity')
    elif any((first is None) != (second is None)
             or (first is not None and abs(first - second) > tolerance_ms)
             for (_, first), (_, second) in zip(disk_jobs, dump_jobs)):
        found.append('jobs:due')
    return found


# Expected owner state. 'baseline' is the fresh install, 'initialized' follows the subject's
# own initialize, the next three follow each shell setup issue, and 'retained' is the final
# state every later phase must keep.
STAGES = ('baseline', 'initialized', 'granted', 'user-set', 'ignored', 'retained')
RUNTIME = BIT['RUNTIME_GRANTED']
USER_SET = BIT['USER_SET']
EXPECTED = {
    'baseline': {'flags': (None, 0), 'package_mode': None, 'channel': 'absent', 'job': False},
    'initialized': {'flags': (None, 0), 'package_mode': None, 'channel': 'created', 'job': True},
    'granted': {'flags': (RUNTIME,), 'package_mode': None, 'channel': 'created', 'job': True},
    'user-set': {'flags': (RUNTIME | USER_SET,), 'package_mode': None, 'channel': 'created',
                 'job': True},
    'ignored': {'flags': (RUNTIME | USER_SET,), 'package_mode': MODE_IGNORED,
                'channel': 'created', 'job': True},
    'retained': {'flags': (RUNTIME | USER_SET,), 'package_mode': MODE_IGNORED,
                 'channel': 'retained', 'job': True},
}
BASELINES = {'migration_version', 'admitted', 'original_due_ms', 'channel', 'stored_channel'}


def mismatches(values, stage, contract, baselines, tolerance_ms=60000):
    """Selected values that differ from the stage's pinned state, each named for its finding."""
    require(stage in STAGES and type(baselines) is dict and set(baselines) <= BASELINES
            and {'migration_version', 'admitted'} <= set(baselines), 'stage and baselines')
    validate_contract(contract)
    uid, want = contract['uid'], EXPECTED[stage]
    disk, dump = values['disk'], values['dump']
    found = []
    if disk['access']['permission_flags'] not in want['flags']:
        found.append('permission-flags')
    if disk['access']['migration_version'] != baselines['migration_version']:
        found.append('migration-version')
    if disk['access']['package_mode'] != want['package_mode']:
        found.append('package-mode')
    if disk['access']['uid_mode'] is not None or dump['appops']['uid_mode'] is not None:
        found.append('uid-override')
    if dump['appops']['history']:
        found.append('appops-history')
    channel = disk['channel']
    if channel['channel_uids'] not in ([], [str(uid)]) or channel['restored']:
        found.append('preference-moved-uid')
    if want['channel'] == 'absent':
        if channel['channels']:
            found.append('preference-preexisting')
    elif channel['channel'] is None:
        found.append('preference-lost')
    else:
        value = channel['channel']
        state = (value['allow_bubbles'], value['locked'])
        wanted = (1, 256) if want['channel'] == 'retained' else (-1, 0)
        if state != wanted:
            found.append('preference-reset' if state == (-1, 0) else 'preference-changed')
        if channel['channels'] != [CHANNEL] or (value['name'], value['importance'],
                                                value['deleted'], value['show_badge']) != (
                'Andrix B2 state', 2, False, True):
            found.append('preference-changed')
    jobs = disk['jobs']
    if not want['job']:
        if jobs:
            found.append('job-preexisting')
    elif not jobs:
        found.append('job-lost')
    else:
        markers = {'andrix.b2.setup': contract['setup'],
                   'andrix.b2.contract_sha256': contract['contract_sha256']}
        exact = [j for j in jobs if tuple(j[k] for k in JOB_IDENTITY) == (
            str(uid), None, str(JOB_ID), PACKAGE + '/' + SERVICE)
            and j['timing'] == 'one-off' and j['deadline'] is None and j['extras'] == markers
            and j['typed_extras'] == sorted((name, 'string') for name in markers)]
        due = baselines.get('original_due_ms')
        if len(jobs) != 1 or len(exact) != 1 or due is None or exact[0]['due_ms'] is None \
                or abs(exact[0]['due_ms'] - due) > tolerance_ms:
            found.append('job-replaced')
        elif any(j['comp'] is not baselines['admitted'] for j in dump['jobs']):
            found.append('job-component')
    if dump['execution_references'] or any(j['executions'] for j in dump['jobs']) or any(
            j['runs'] != ['0', '0', '0'] for j in jobs):
        found.append('job-executed')
    return sorted(set(found))


def strict_readers(state, dumps, stage, contract, baselines):
    """The existing strict readers at every stage they pin. Returns each refusal with its reason.

    'baselines' holds the pinned migration version, whether the package is admitted, the original
    UTC due time once the job exists, and, once established, the rendered 'channel' fields and
    the 'stored_channel' attributes of the retained preference.
    """
    require(stage in STAGES, 'setup stage')
    uid, want = contract['uid'], EXPECTED[stage]
    refused = []

    def run(name, call):
        try:
            call()
        except ValueError as error:
            refused.append(name + ': ' + str(error))

    access = next(iter(selected_records(state['access']).values()))
    # These readers pin permission and package mode together, at their two endpoints only.
    endpoint = {'baseline': False, 'initialized': False, 'ignored': True,
                'retained': True}.get(stage)
    if endpoint is not None:
        run('stored-access', lambda: stored.access(
            access, uid, baselines['migration_version'], endpoint))
        run('permission', lambda: obs.require_permission_state(
            obs.permissionmgr(dumps['permission_app_id'], uid),
            baselines['migration_version'], endpoint))
    run('appops-package', lambda: obs.appops(dumps['appops_package'], uid, True,
                                             want['package_mode'] == MODE_IGNORED))
    run('appops-uid', lambda: obs.appops(dumps['appops_uid'], uid, False))
    policy = selected_records(state['notification'])
    preference = want['channel']
    retained = preference == 'retained'
    if policy or preference != 'absent':
        run('stored-notification', lambda: stored.notification_policy(
            next(iter(policy.values())), uid,
            baselines.get('stored_channel') if retained else None, preference)
            if policy else require(False, 'no stored notification policy'))
    run('notification', lambda: obs.notification(
        dumps['notification'], uid, preference, baselines.get('channel') if retained else None))
    run('stored-jobs', lambda: stored.jobs(selected_records(state['jobs']), contract,
                                           baselines.get('original_due_ms'),
                                           initialized=want['job']))
    run('jobscheduler', lambda: obs.jobscheduler(dumps['jobscheduler'], contract,
                                                 baselines['admitted'], want['job']))
    return refused


def assess(captures, dumps, contract, stage, baselines, tolerance_ms=60000, absent_allowed=()):
    """The subject's three owner families and their dumps at one observation point.

    Returns 'settled' with any 'unsettled' reasons, and once settled the values, 'mismatches'
    against the stage and 'refused_readers'. 'matches' holds only when nothing differs. Refused
    or unavailable evidence raises ValueError; a moving or disagreeing store is never refused.
    absent_allowed names the subject families a phase explicitly expects may not exist.
    """
    validate_contract(contract)
    require(type(absent_allowed) in (tuple, list) and set(absent_allowed) <= {'notification'},
            'subject owner absence exceptions')
    require(type(captures) is dict and set(captures) == set(SUBJECT_FAMILIES),
            'subject owner captures')
    require(type(baselines) is dict and set(baselines) <= BASELINES
            and {'migration_version', 'admitted'} <= set(baselines)
            and type(baselines['admitted']) is bool, 'owner baselines')
    state, unsettled = {}, []
    for family in SUBJECT_FAMILIES:
        try:
            state[family] = namespace(family, captures[family], family in absent_allowed)
        except Unsettled as error:
            unsettled.append(str(error))
    if unsettled:
        return {'settled': False, 'unsettled': unsettled, 'state': state, 'values': None,
                'matches': False}
    values = owner_values(state, dumps, contract['uid'])
    disagree = disagreements(values, tolerance_ms)
    if disagree:
        return {'settled': False, 'unsettled': ['disk and dump disagree: ' + ', '.join(disagree)],
                'state': state, 'values': values, 'matches': False}
    found = mismatches(values, stage, contract, baselines, tolerance_ms)
    refused = strict_readers(state, dumps, stage, contract, baselines)
    return {'settled': True, 'unsettled': [], 'state': state, 'values': values,
            'mismatches': found, 'refused_readers': refused,
            'matches': not found and not refused}


# Rendered fields a designed phase changes without touching stored state, checked per phase:
# component usability ('comp', false while deferred and true once admitted), the extras display
# (parcelled until JobStore first writes the job, then a map) and the notification permission
# suffix of an AppSettings row (printed only for a scanned package).
PHASE_DEPENDENT_JOB = ('comp', 'extras', 'due_ms')


def comparable(result):
    """The selected values every later observation must keep. Due times compare separately,
    and the stored job compares by its identity, markers and run times, not its file name."""
    require(result['settled'], 'settled owner result')
    disk, dump = result['values']['disk'], result['values']['dump']
    rendered = {'packages': [{k: v for k, v in row.items() if k != 'extra'}
                             for row in dump['rendered']['packages']]}
    return {'access': disk['access'], 'channel': disk['channel'], 'policy': disk['policy'],
            'jobs': [{k: j[k] for k in j if k not in ('due_ms', 'file')} for j in disk['jobs']],
            'rendered': rendered,
            'registered': [{k: j[k] for k in j if k not in PHASE_DEPENDENT_JOB}
                           for j in dump['jobs']],
            'due_ms': sorted(j['due_ms'] for j in disk['jobs'] if j['due_ms'] is not None)}


def selected_changes(first, second, tolerance_ms=60000):
    """Named differences between two comparable results. JobStore recomputes a stored delay from
    the wall clock whenever it rewrites a job, so due times agree within the tolerance."""
    found = [key for key in ('access', 'channel', 'policy', 'jobs', 'rendered', 'registered')
             if first[key] != second[key]]
    if len(first['due_ms']) != len(second['due_ms']) or any(
            abs(a - b) > tolerance_ms for a, b in zip(first['due_ms'], second['due_ms'])):
        found.append('due_ms')
    return found
