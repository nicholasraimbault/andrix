# SPDX-License-Identifier: Apache-2.0
"""Synthetic owner namespaces and dumps in the frozen read grammar. These are not Android captures.

Binary files are a magic prefix and arbitrary bytes: no host ABX codec exists, so each carries the
decoded text its guest converter would have printed. Every builder returns fresh objects.
"""
import hashlib
import itertools
import fixtures as f
import owner_stores as own
from protocol import LATENCY, PACKAGE

UID = f.UID
TIME = '2026-10-15 12:00:00.000000000 +0000'
LATER = '2026-10-15 12:00:05.000000000 +0000'
# The wall clock at which the synthetic job, due at f.DUE, has 30 days less one second left.
RTC_SECONDS = (f.DUE - LATENCY + 1000) // 1000
_inodes = itertools.count(4000)


def capture(argv, stdout, code=0, stderr=''):
    return {'argv': argv, 'stdout': stdout, 'stderr': stderr, 'exit_code': code, 'complete': True}


def stat_line(path, kind='regular file', inode=None, size=0, mode='600', uid=1000, gid=1000,
              context=own.SYSTEM_LABEL, mtime=TIME, ctime=TIME, device=64775, links=1,
              atime=TIME):
    inode = next(_inodes) if inode is None else inode
    return (f'{device}|{inode}|{links}|8|512|{uid}|{gid}|{mode}|{size}|{atime}|{mtime}|{ctime}|'
            f'{context}|{kind}|{path}\n')


def stat(path, **meta):
    return capture(['stat', '-c', own.STAT_FORMAT, path], stat_line(path, **meta))


def absent(path):
    return capture(['stat', '-c', own.STAT_FORMAT, path], '', 1,
                   f"stat: '{path}': No such file or directory\n")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def binary(decoded):
    """Stand in binary XML: the pinned magic, then bytes no host decoder interprets."""
    return own.ABX_MAGIC + b'\x10' + hashlib.sha256(decoded).digest() + decoded[:8]


def file_record(path, raw, decoded=None, **meta):
    meta.setdefault('size', len(raw))
    meta.setdefault('inode', next(_inodes))
    line = stat(path, **meta)
    return {'stat_before': line, 'sha256_before': capture(['sha256sum', path],
                                                          f'{sha(raw)}  {path}\n'),
            'pull': {'path': path, 'bytes': raw, 'complete': True},
            'decode': None if decoded is None else capture(['abx2xml', path, '-'], decoded),
            'sha256_after': capture(['sha256sum', path], f'{sha(raw)}  {path}\n'),
            'stat_after': dict(line)}


def namespace(family, entries, directories=(), root=None, missing=False):
    """entries maps names to (raw bytes, decoded bytes or None, metadata keyword overrides)."""
    spec = own.FAMILIES[family]
    parent = spec['parent']
    if missing:
        return {'root': absent(parent), 'listing': [], 'files': {}, 'directories': {},
                'listing_after': [], 'root_after': absent(parent)}
    root = dict({'kind': 'directory', 'inode': 300, 'mode': '771'}, **(root or {}))
    paths = [parent + '/' + name for name in (*entries, *directories)]
    listing = []
    for argv in own.listing_argvs(family):
        if spec['patterns'] is None:
            chosen = paths
        else:
            prefix = argv[-1].rstrip('*')
            chosen = [p for p in paths if p.rsplit('/', 1)[1].startswith(prefix)]
        listing.append(capture(argv, ''.join(p + '\n' for p in chosen)))
    files = {}
    for name, (raw, decoded, meta) in entries.items():
        files[parent + '/' + name] = file_record(parent + '/' + name, raw, decoded, **(meta or {}))
    trees = {}
    for name in directories:
        line = stat(parent + '/' + name, kind='directory', mode='700')
        trees[parent + '/' + name] = {'stat_before': line, 'stat_after': dict(line)}
    return {'root': stat(parent, **root), 'listing': listing, 'files': files,
            'directories': trees, 'listing_after': [dict(x) for x in listing],
            'root_after': stat(parent, **root)}


# Decoded owner records, consistent with the rendered dumps below.

def access_xml(flags=48, package_mode=1, uid_mode=None, version=15, vibrate=1, uid=UID):
    perms = ''
    if flags is not None:
        perms += f'<permission name="android.permission.POST_NOTIFICATIONS" flags="{flags}"/>'
    if vibrate is not None:
        perms += f'<permission name="android.permission.VIBRATE" flags="{vibrate}"/>'
    uid_ops = ('' if uid_mode is None else
               f'<app-id id="{uid}"><app-op name="android:vibrate" mode="{uid_mode}"/></app-id>')
    package_ops = ('' if package_mode is None else
                   f'<package name="{PACKAGE}"><app-op name="android:vibrate" '
                   f'mode="{package_mode}"/></package>')
    return (f'<?xml version=\'1.0\' encoding=\'utf-8\' standalone=\'yes\' ?>\n<access>\n'
            f'  <package-versions><package name="{PACKAGE}" version="{version}"/>'
            f'<package name="com.example.other" version="15"/></package-versions>\n'
            f'  <app-id-permissions><app-id id="{uid}">{perms}</app-id>'
            '<app-id id="10050"><permission name="android.permission.INTERNET" flags="1"/>'
            '</app-id></app-id-permissions>\n'
            f'  <app-id-app-ops>{uid_ops}</app-id-app-ops>\n'
            f'  <package-app-ops>{package_ops}</package-app-ops>\n</access>\n').encode()


def notification_xml(preference='retained', uid=UID):
    if preference == 'absent':
        return f.notification_xml(False).replace(b'uid="10123"', f'uid="{uid}"'.encode())
    return f.notification_xml(True, preference).replace(b'uid="10123"', f'uid="{uid}"'.encode())


def job_xml(present=True, due=f.DUE, extras=None, timing='one-off', runs=(0, 0, 0)):
    if not present:
        return (b'<?xml version=\'1.0\' encoding=\'utf-8\' standalone=\'yes\' ?>\n'
                b'<job-info version="1"/>\n')
    data = f.job_xml().replace(f'delay="{f.DUE}"'.encode(), f'delay="{due}"'.encode())
    if timing != 'one-off':
        data = data.replace(b'<one-off ', b'<periodic period="900000" flex="900000" ')
    for name, value in zip(('lastSuccessfulRunTime', 'lastFailedRunTime',
                            'cumulativeExecutionTime'), runs):
        data = data.replace(f'{name}="0"'.encode(), f'{name}="{value}"'.encode())
    if extras is not None:
        start, end = data.index(b'<extras>'), data.index(b'</extras>') + len(b'</extras>')
        data = data[:start] + extras + data[end:]
    return data


# Rendered dumps.

def permission_text(flags=48, package_mode=1, uid_mode=None, version=15, vibrate=1, uid=UID):
    rows = []
    if flags is not None:
        rows.append(('android.permission.POST_NOTIFICATIONS', flags))
    if vibrate is not None:
        rows.append(('android.permission.VIBRATE', vibrate))
    text = f'App ID: {uid}\n  User: 0\n    Permissions:\n'
    for name, value in rows:
        text += (f'      {name}: granted={str(own.granted(value)).lower()}, flags=['
                 + '|'.join(own.flags_names(value)) + ']\n')
    text += '    App ops:\n'
    if uid_mode is not None:
        text += f'      android:vibrate: mode={own.MODE_NAMES[uid_mode]}\n'
    text += f'    Package: {PACKAGE}\n      version={version}\n      App ops:\n'
    if package_mode is not None:
        text += f'        android:vibrate: mode={own.MODE_NAMES[package_mode]}\n'
    return text


def appops_texts(package_mode=1, uid_mode=None):
    rows = []
    if uid_mode is not None:
        rows.append('Uid mode: VIBRATE: ' + own.MODE_NAMES[uid_mode])
    if package_mode is not None:
        rows.append('VIBRATE: ' + own.MODE_NAMES[package_mode])
    package = ''.join(r + '\n' for r in rows) or 'No operations.\nDefault mode: allow\n'
    uid = ('Uid mode: VIBRATE: ' + own.MODE_NAMES[uid_mode] + '\n' if uid_mode is not None
           else 'No operations.\nDefault mode: allow\n')
    return package, uid


def notification_text(preference='retained', uid=UID):
    if preference == 'absent':
        return f.notification_text(False)
    return f.notification_text(True, preference).replace(f'({f.UID})', f'({uid})')


def job_text(present=True, admitted=True, parcelled=True):
    if present:
        return f.job_text(admitted, parcelled)
    return ('JobScheduler:\nStarted users: [0]\nRegistered 0 jobs:\n  None.\n'
            '\nPending queue:\n  None\nActive jobs:\n  None\nRecently completed jobs:\n  None\n')


DUMP_ARGVS = {
    'permission_app_id': ['dumpsys', 'permissionmgr', '--app-id', str(UID)],
    'permission_package': ['dumpsys', 'permissionmgr', '--package', PACKAGE],
    'appops_package': ['cmd', 'appops', 'get', '--user', '0', PACKAGE, 'VIBRATE'],
    'appops_uid': ['cmd', 'appops', 'get', str(UID), 'VIBRATE'],
    'notification': ['dumpsys', 'notification', '--noredact', '--package', PACKAGE],
    'jobscheduler': ['dumpsys', 'jobscheduler'],
    'rtc': ['date', '+%s'],
}

# The owner state at each setup stage, as (flags, package mode, preference, job present).
STAGE_STATE = {
    'baseline': (0, None, 'absent', False), 'initialized': (0, None, 'created', True),
    'granted': (16, None, 'created', True), 'user-set': (48, None, 'created', True),
    'ignored': (48, 1, 'created', True), 'retained': (48, 1, 'retained', True),
}


def owner_captures(stage='retained', access=None, policy=None, jobs=None, extra_jobs=None,
                   legacy=False):
    flags, mode, preference, present = STAGE_STATE[stage]
    access = access_xml(flags, mode) if access is None else access
    policy = notification_xml(preference) if policy is None else policy
    jobs = job_xml(present) if jobs is None else jobs
    raw = binary(access)
    job_files = {('jobs.xml' if legacy else f'jobs_{UID}.xml'): (binary(jobs), jobs, None)}
    for name, data in (extra_jobs or {}).items():
        job_files[name] = (binary(data), data, None)
    return {'access': namespace('access', {'access.abx': (raw, access, None),
                                           'access.abx.reservecopy': (raw, access, None)}),
            'notification': namespace('notification', {
                'notification_policy.xml': (binary(policy), policy, None)}),
            'jobs': namespace('jobs', job_files)}


def owner_dumps(stage='retained', flags=..., package_mode=..., uid_mode=None, preference=...,
                job=..., rtc=RTC_SECONDS, admitted=True, permission=None, appops=None,
                notification=None, jobs=None):
    """Rendered owner dumps; an omitted state argument takes the stage's value."""
    s_flags, s_mode, s_preference, s_job = STAGE_STATE[stage]
    flags = s_flags if flags is ... else flags
    package_mode = s_mode if package_mode is ... else package_mode
    preference = s_preference if preference is ... else preference
    job = s_job if job is ... else job
    permission = permission_text(flags, package_mode, uid_mode) if permission is None \
        else permission
    package, uid = appops_texts(package_mode, uid_mode) if appops is None else appops
    texts = {'permission_app_id': permission, 'permission_package': permission,
             'appops_package': package, 'appops_uid': uid,
             'notification': notification_text(preference) if notification is None
             else notification,
             'jobscheduler': job_text(job, admitted) if jobs is None else jobs,
             'rtc': f'{rtc}\n'}
    return {key: capture(DUMP_ARGVS[key], value) for key, value in texts.items()}


def baselines(stage='retained', admitted=True, **extra):
    value = {'migration_version': 15, 'admitted': admitted}
    if STAGE_STATE[stage][3]:
        value['original_due_ms'] = f.DUE
    value.update(extra)
    return value


def packages_family(main=b'<packages/>', reserve=None, backup=None, **meta):
    meta = dict({'mode': '660', 'uid': 1000, 'gid': 1000}, **meta)
    entries = {'packages.xml': (binary(main), None, meta),
               'packages.xml.reservecopy': (binary(main if reserve is None else reserve), None,
                                            meta)}
    if backup is not None:
        entries['packages-backup.xml'] = (binary(backup), None, meta)
    return namespace('packages', entries)
