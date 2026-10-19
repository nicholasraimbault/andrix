#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict selected record observers for the pinned Android source. No guest commands run here.

All functions require a complete transport capture, including exact argv and exit status. These
are source derived grammars, not guest calibrated ones. Unrelated service sections are retained
in raw captures, not interpreted as selected state. No malformed selected row is skipped.
"""
import importlib.util
from pathlib import Path
import re
import stat
from protocol import (CHANNEL, JOB_ID, LATENCY, NOTIFICATION_SETUP, PACKAGE, SERVICE, SETUP_JAR,
                      TRIAL_LIMIT,
                      DumpUnavailable, assess_reply, dumpsys_argv, hex_value, instrumentation_argv,
                      notification_preference, notification_setup_argv, require, sha, strict_json,
                      validate_contract)

PERMISSION = 'android.permission.POST_NOTIFICATIONS'
OP = 'android:vibrate'
MODES = {'allow', 'ignore', 'deny', 'default', 'foreground'}


def capture_text(capture, argv, exit_code=0, stderr=''):
    require(type(capture) is dict and set(capture) == {
        'argv', 'stdout', 'stderr', 'exit_code', 'complete'}, 'capture fields')
    require(capture['argv'] == argv, 'command, transport or completeness')
    if argv[:1] == ['dumpsys']:
        # A dumpsys capture passes the one completeness gate before anything reads it: its transport
        # completed, dumpsys exited 0, no timeout line, its stderr empty and its last line ended.
        # Anything else is unavailable evidence with the gate's reason, never a shorter dump.
        require(exit_code == 0 and stderr == '', 'a dumpsys read expects exit 0 and no stderr')
        try:
            _complete_capture()(capture, ' '.join(argv[3:] if argv[1:2] == ['-t'] else argv[1:]) + ' dump')
        except ValueError as error:
            raise DumpUnavailable(str(error)) from error
    require(capture['complete'] is True
            and type(capture['exit_code']) is int and capture['exit_code'] == exit_code
            and capture['stderr'] == stderr, 'command, transport or completeness')
    text = capture['stdout']
    require(type(text) is str and len(text.encode('utf-8')) <= 16 * 1024 * 1024
            and all(ord(c) >= 32 or c in '\n\t' for c in text)
            and (not text or text.endswith('\n')), 'bounded LF terminated capture')
    return text


_GATE = []


def _complete_capture():
    """uid_observe.complete_capture, the observers' one completeness gate, loaded once."""
    if not _GATE:
        _GATE.append(_existing('uid_observe').complete_capture)
    return _GATE[0]


def _one(rows, message):
    require(len(rows) == 1, message)
    return rows[0]


def _put(mapping, key, value):
    require(key not in mapping, 'duplicate selected field or identity: ' + key)
    mapping[key] = value


PERMISSION_ROW = re.compile(r'([a-zA-Z][a-zA-Z0-9_.]*): granted=(true|false), '
                            r'flags=\[((?:[A-Z][A-Z0-9_]*|0x[0-9a-f]+)'
                            r'(?:\|(?:[A-Z][A-Z0-9_]*|0x[0-9a-f]+))*)?\]')


def permissionmgr(capture, uid, selector='app-id'):
    """The permission service's printer grammar (PermissionService.kt dumpAppIdState and dumpUserState; checkpoint 5 B
    version 21, Q25 c and the source check, section 2): after `App ID: <id>`, one block per saved user in print order, each with its
    `Permissions:`, zero or more `Permissions (Device <id>):` sections, its app ID's `App ops:` and one `Package:` block per
    package of the app ID with its migration version and package operations. Rows are in the service's map order, so the
    parser is order free within a section. `Unknown app ID` or `Unknown package` is unavailable evidence. Returns user 0's
    values under today's keys, every user named ('users') and user 0's device permission sections
    ('device_permissions'); the stage checks refuse another user or any device section."""
    require(type(uid) is int and 10000 <= uid <= 19999 and selector in ('app-id', 'package'),
            'permission selector')
    text = capture_text(capture, dumpsys_argv('permissionmgr', '--' + selector,
                                              str(uid) if selector == 'app-id' else PACKAGE))
    if text in (f'Unknown app ID {uid}.\n', f'Unknown package {PACKAGE}.\n'):
        raise DumpUnavailable('the permission service names no saved state for the subject: ' + text.strip())
    lines = text.splitlines()
    require(lines and lines[0] == f'App ID: {uid}', 'permission identity')
    users, order, user, section = {}, [], None, None
    for line in lines[1:]:
        match = re.fullmatch(r'  User: (0|[1-9][0-9]{0,9})', line)
        if match:
            number = int(match[1])
            require(number < 1 << 31 and number not in users, 'duplicate or out of range permission user')
            user = {'permissions': None, 'device_permissions': {}, 'uid_ops': None, 'packages': {}}
            users[number] = user
            order.append(number)
            section = None
            continue
        require(user is not None, 'permission user nesting')
        if line == '    Permissions:':
            require(user['permissions'] is None and user['uid_ops'] is None and not user['packages'],
                    'permission section order')
            user['permissions'] = {}
            section = ('rows', user['permissions'])
            continue
        match = re.fullmatch(r'    Permissions \(Device ([^\x00-\x1f]{1,1024})\):', line)
        if match:
            require(user['permissions'] is not None and user['uid_ops'] is None and not user['packages']
                    and match[1] not in user['device_permissions'], 'device permission section order or duplicate')
            user['device_permissions'][match[1]] = {}
            section = ('rows', user['device_permissions'][match[1]])
            continue
        if line == '    App ops:':
            require(user['permissions'] is not None and user['uid_ops'] is None and not user['packages'],
                    'app operation section order')
            user['uid_ops'] = {}
            section = ('ops', user['uid_ops'], '      ')
            continue
        match = re.fullmatch(r'    Package: ([A-Za-z][A-Za-z0-9_.]*)', line)
        if match:
            require(user['uid_ops'] is not None and match[1] not in user['packages'],
                    'package section order or duplicate')
            package = {'version': None, 'ops': None}
            user['packages'][match[1]] = package
            section = ('version', package)
            continue
        require(section is not None, 'unexpected permission structure')
        if section[0] == 'version':
            match = re.fullmatch(r'      version=(0|[1-9][0-9]{0,9}|null)', line)
            require(match is not None, 'permission migration version')
            section[1]['version'] = None if match[1] == 'null' else int(match[1])
            require(section[1]['version'] is None or section[1]['version'] < 1 << 31, 'migration version range')
            section = ('package_header', section[1])
        elif section[0] == 'package_header':
            require(line == '      App ops:', 'package operation section')
            section[1]['ops'] = {}
            section = ('ops', section[1]['ops'], '        ')
        elif section[0] == 'rows':
            match = PERMISSION_ROW.fullmatch(line[6:]) if line.startswith('      ') else None
            require(match is not None, 'permission row')
            flags = match[3].split('|') if match[3] else []
            require(len(flags) == len(set(flags)), 'duplicate permission flag')
            _put(section[1], match[1], {'granted': match[2] == 'true', 'flags': flags})
        else:
            match = re.fullmatch(section[2] + r'(android:[a-z0-9_]+): mode=([a-z]+)', line)
            require(match is not None and match[2] in MODES, 'app operation row or nesting')
            _put(section[1], match[1], match[2])
    require(users and all(u['permissions'] is not None and u['uid_ops'] is not None
                          and all(p['ops'] is not None for p in u['packages'].values()) for u in users.values()),
            'incomplete permission dump')
    require(0 in users and PACKAGE in users[0]['packages'], 'the subject\'s user 0 package block')
    zero, own = users[0], users[0]['packages'][PACKAGE]
    return {'app_id': uid, 'user': 0, 'package': PACKAGE, 'version': own['version'],
            'permissions': zero['permissions'], 'uid_ops': zero['uid_ops'], 'package_ops': own['ops'],
            'users': order, 'device_permissions': zero['device_permissions']}


def require_permission_state(facts, baseline_version, want):
    """The subject's saved permission state at one stage (checkpoint 5 B version 21, Q25 a): the stage's one expected
    row from owner_stores.EXPECTED, at every stage, never a literal of its own. The migration version as learned, no UID
    VIBRATE mode, the POST_NOTIFICATIONS row exactly the stage's flags as the service renders them, the package VIBRATE
    mode `ignore` where the stage names mode 1 and absent otherwise, one user and no device permission."""
    from owner_stores import flags_names, granted
    require(type(want) is dict and type(want.get('flags')) is int and want.get('package_mode') in (None, 1),
            'expected permission state')
    require(facts['version'] == baseline_version and OP not in facts['uid_ops'],
            'migration version or UID mode changed')
    require(facts['permissions'].get(PERMISSION) == {'granted': granted(want['flags']),
                                                     'flags': flags_names(want['flags'])},
            'permission state differs from the stage')
    require(facts['package_ops'].get(OP) == ('ignore' if want['package_mode'] == 1 else None)
            and (want['package_mode'] == 1 or OP not in facts['package_ops']), 'package mode differs from the stage')
    require(facts.get('users', [0]) == [0], 'permission state of another user')
    require(not facts.get('device_permissions'), 'device permission state')
    return facts


def appops(capture, uid, package=True, initialized=True):
    require(type(uid) is int and 10000 <= uid <= 19999, 'application UID')
    argv = ['cmd', 'appops', 'get', '--user', '0', PACKAGE, 'VIBRATE'] if package else [
        'cmd', 'appops', 'get', str(uid), 'VIBRATE']
    text = capture_text(capture, argv)
    if package and initialized:
        require(text == 'VIBRATE: ignore\n', 'package mode missing, overridden or has history')
        return {'scope': 'package', 'package': PACKAGE, 'uid': uid, 'op': OP, 'mode': 'ignore'}
    require(text == 'No operations.\nDefault mode: allow\n', 'nondefault mode or access history')
    return {'scope': 'package' if package else 'uid', 'uid': uid, 'op': OP, 'mode': 'default'}


CHANNEL_FIELDS = (
    'mId', 'mName', 'mDescription', 'mImportance', 'mBypassDnd', 'mLockscreenVisibility',
    'mSound', 'mLights', 'mLightColor', 'mVibrationPattern', 'mVibrationEffect',
    'mUserLockedFields', 'mUserVisibleTaskShown', 'mVibrationEnabled', 'mShowBadge',
    'mDeleted', 'mDeletedTimeMs', 'mGroup', 'mAudioAttributes', 'mBlockableSystem',
    'mAllowBubbles', 'mImportanceLockedDefaultApp', 'mOriginalImp', 'mParent',
    'mConversationId', 'mDemoted', 'mImportantConvo', 'mLastNotificationUpdateTimeMs',
    'isBundle', 'emoji')
CHANNEL_BOOLS = {'mBypassDnd', 'mLights', 'mUserVisibleTaskShown', 'mVibrationEnabled',
                 'mShowBadge', 'mDeleted', 'mBlockableSystem', 'mImportanceLockedDefaultApp',
                 'mDemoted', 'mImportantConvo', 'isBundle'}
CHANNEL_INTS = {'mImportance', 'mLockscreenVisibility', 'mLightColor', 'mDeletedTimeMs',
                'mAllowBubbles', 'mOriginalImp', 'mLastNotificationUpdateTimeMs'}


def channel_fields(line):
    """One complete channel row's typed fields, before any comparison with the contract."""
    require(line.startswith('NotificationChannel{') and line.endswith('}'), 'channel envelope')
    body = line[len('NotificationChannel{'):-1]
    parts = re.split(r', (?=[a-zA-Z][a-zA-Z0-9_]*=)', body)
    fields = {}
    for part in parts:
        key, sep, value = part.partition('=')
        require(sep and key in CHANNEL_FIELDS, 'unknown channel field')
        _put(fields, key, value)
    require(tuple(fields) == CHANNEL_FIELDS, 'channel order, missing or duplicate field')
    for key in CHANNEL_BOOLS:
        require(fields[key] in ('true', 'false'), 'channel boolean')
        fields[key] = fields[key] == 'true'
    for key in CHANNEL_INTS:
        require(re.fullmatch(r'-?(?:0|[1-9][0-9]{0,18})', fields[key]) is not None,
                'channel integer')
        fields[key] = int(fields[key])
    require(re.fullmatch('[0-9a-f]{1,8}', fields['mUserLockedFields']) is not None,
            'channel lock mask is hexadecimal')
    fields['mUserLockedFields'] = int(fields['mUserLockedFields'], 16)
    return fields


def channel_row(line):
    fields = channel_fields(line)
    required = {'mId': "'" + CHANNEL + "'", 'mName': 'Andrix B2 state', 'mDescription': '',
                'mImportance': 2, 'mSound': 'null', 'mVibrationPattern': 'null',
                'mVibrationEffect': 'null', 'mLights': False, 'mVibrationEnabled': False,
                'mShowBadge': True, 'mDeleted': False, 'mGroup': "'null'", 'mParent': 'null',
                'mConversationId': 'null', 'mDemoted': False, 'mImportantConvo': False,
                'mAudioAttributes': 'AudioAttributes: usage=USAGE_NOTIFICATION '
                'content=CONTENT_TYPE_SONIFICATION flags=0x800(FLAG_MUTE_HAPTIC)  tags= bundle=null',
                'mBypassDnd': False, 'mLockscreenVisibility': -1000, 'mLightColor': 0,
                'mUserVisibleTaskShown': False, 'mDeletedTimeMs': -1, 'mBlockableSystem': False,
                'mImportanceLockedDefaultApp': False, 'mOriginalImp': 2,
                'mLastNotificationUpdateTimeMs': 0, 'isBundle': False, 'emoji': 'null'}
    require(all(fields[k] == v for k, v in required.items()), 'channel contract')
    return fields


def notification_setup_file(capture, expected_sha256):
    """Pin the separately produced shell jar before and after setup. Not a state oracle."""
    return file_hashes(capture, {SETUP_JAR: expected_sha256})


def notification_setup(capture, contract, nonce):
    """Command acknowledgement only, never a preference or persistence oracle."""
    text = capture_text(capture, notification_setup_argv(contract, nonce))
    prefix = 'ANDRIX_B2_NOTIFICATION_SETUP: '
    lines = text.split('\n')
    require(len(lines) == 2 and lines[1] == '' and lines[0].startswith(prefix),
            'notification setup acknowledgement envelope')
    value = strict_json(lines[0][len(prefix):])
    expected = {'version': 1, 'operation': NOTIFICATION_SETUP, 'package': PACKAGE,
                'uid': contract['uid'], 'user': 0, 'channel': CHANNEL, 'process_uid': 2000,
                'nonce': nonce, 'setup': contract['setup'],
                'contract_sha256': contract['contract_sha256'], 'stage': 'update_returned',
                'setter_calls': 1, 'state_proven': False}
    require(type(value) is dict and value == expected and set(value) == set(expected)
            and all(type(value[k]) is int for k in
                    ('version', 'uid', 'user', 'process_uid', 'setter_calls'))
            and value['state_proven'] is False, 'notification setup acknowledgement scope')
    return value


def notification(capture, uid, stage='retained', baseline=None, app_settings=None):
    """The rendered preferences of the subject. Checkpoint 5 B version 21 (Q25 a): with APP_SETTINGS, the stage's
    AppSettings suffix (owner_stores.EXPECTED), the subject's row must carry exactly it; at the fresh baseline (STAGE
    'absent') the row may also be absent. Version 22 (the source check's B1): APP_SETTINGS '' is the bare saved row an unscanned
    package prints, which must then carry no suffix."""
    require(type(stage) is str and stage in ('absent', 'created', 'retained'),
            'notification observation stage')
    require(app_settings is None or app_settings == '' or (type(app_settings) is str and re.fullmatch(
        r' importance=[A-Z_]+ userSet=(?:true|false)', app_settings) is not None), 'expected AppSettings suffix')
    text = capture_text(capture, dumpsys_argv('notification', '--noredact', '--package', PACKAGE))
    lines = text.splitlines()
    start = _one([i for i, x in enumerate(lines) if x == 'PackagePreferences:'],
                 'notification preferences section')
    restored = _one([i for i, x in enumerate(lines) if x == 'Restored without uid:'],
                    'notification restore section')
    end = _one([i for i, x in enumerate(lines) if x == '  Notification listeners:'],
               'complete notification preferences boundary')
    require(0 < start < restored < end
            and lines[start - 1] == '    per-package config version: 4',
            'notification version or sections out of order')
    packages = []
    current = None
    target_channels = []
    suffixes = []
    for index in range(start + 1, end):
        line = lines[index]
        if not line or line == 'Restored without uid:':
            current = None
            continue
        app = re.fullmatch(r'      AppSettings: ([A-Za-z0-9_.]+) \((INVALID_UID|[0-9]+)\)(.*)', line)
        if app:
            require(not any(x[0] == app[1] and x[1] == app[2] for x in packages),
                    'duplicate notification package preference')
            packages.append((app[1], app[2], index >= restored))
            current = app[1]
            if current == PACKAGE:
                require(app[2] == str(uid) and index < restored, 'stranded notification UID')
                require(re.fullmatch(r'(?: importance=[A-Z_]+ userSet=(?:true|false))?', app[3])
                        is not None, 'nondefault package notification preferences')
                suffixes.append(app[3])
            continue
        if current == PACKAGE:
            require(line.startswith('        NotificationChannel{'), 'unexpected subject preference')
            target_channels.append(channel_row(line[8:]))
        elif PACKAGE in line or CHANNEL in line:
            raise ValueError('selected preference outside its package block')
    target_packages = [p for p in packages if p[0] == PACKAGE]
    require(len(target_packages) <= 1, 'duplicate subject preferences')
    if app_settings is not None:
        require(suffixes == [app_settings] or (not suffixes and stage == 'absent'),
                'subject notification preferences differ from the stage')
    if stage == 'absent':
        require(not target_channels, 'preexisting custom or deleted channel')
        return {'uid': uid, 'package': PACKAGE, 'channels': []}
    selected = _one(target_channels, 'one original channel required')
    bubbles, user_lock = notification_preference(stage)
    require(selected['mAllowBubbles'] == bubbles and selected['mUserLockedFields'] == user_lock,
            'bubble preference or user lock differs')
    if baseline is not None:
        require(selected == baseline, 'channel baseline fields changed')
    return {'uid': uid, 'package': PACKAGE, 'channel': selected}


def duration(text):
    match = re.fullmatch(r'([+-])(?:(0|[1-9][0-9]*)d)?(?:(0|[1-9][0-9]*)h)?'
                         r'(?:(0|[1-9][0-9]*)m)?(?:(0|[1-9][0-9]*)s)?(0|[1-9][0-9]*)ms', text)
    require(match is not None and len(text) <= 48, 'Android duration')
    values = [int(x) if x is not None else None for x in match.groups()[1:]]
    first = next(i for i, x in enumerate(values) if x is not None)
    require(all(x is not None for x in values[first:]), 'noncanonical duration units')
    for i, bound in ((1, 24), (2, 60), (3, 60), (4, 1000)):
        require(values[i] is None or i == first or values[i] < bound, 'duration range')
    total = sum((x or 0) * scale for x, scale in zip(values, (86400000, 3600000, 60000, 1000, 1)))
    require(total > 0 and total < 1 << 63, 'nonzero bounded duration')
    return total if match[1] == '+' else -total


SDK_ARGV = ['getprop', 'ro.build.version.sdk']


def sdk_level(capture):
    """The booted image's SDK level (checkpoint 5 B version 21, spec 2.5): `getprop ro.build.version.sdk`, one to three
    digits and a line feed, exit 0 and no error output. The setup reads it before its fresh read; the notification
    policy's last_bubbles_version_upgrade is this value (N/PreferencesHelper.java:714-718)."""
    text = capture_text(capture, SDK_ARGV)
    require(re.fullmatch(r'[1-9][0-9]{0,2}\n', text) is not None, 'SDK level form')
    return int(text)


def relative_time(text, unset=True):
    """TimeUtils.formatDuration relative to now (checkpoint 5 B version 21, the source check, sections 1 and 8): `--` where the stored
    time is 0 (None), `0` where it equals now (0), otherwise a signed duration. Version 22 (the source check's B2): UNSET False at a
    caller that prints only a nonzero stored time (the constraint history, Deferred since, Time since first force batch
    attempt), where `--` cannot print and is refused."""
    if text == '--':
        require(unset, 'a relative time its caller prints only when set')
        return None
    if text == '0':
        return 0
    return duration(text)


# The registered job header (JobStatus.toShortString with its namespace, UserHandle.formatUid and the job ID; Q25 c):
# one grammar for both jobscheduler readers.
JOB_CALLING = r'(?:-?(?:0|[1-9][0-9]{0,9})|u(?:0|[1-9][0-9]{0,9})(?:ai|a|i|s)(?:0|[1-9][0-9]{0,9}))'
JOB_REST = re.compile(r'(' + JOB_CALLING + r')/(-?(?:0|[1-9][0-9]{0,9})): ([0-9a-f]{1,8}) (.+)')
JOB_BODY = re.compile(r'    (' + JOB_CALLING + r') tag=')


def job_header(line, first_body_line):
    """One registered job's identity from `  JOB <#|namespace:><calling UID>/<signed ID>: <hash> <battery>`. The
    namespace may hold spaces, `/` and `:`, so every split is tried (`#`, then each `:` as the namespace's end) and kept
    where its remainder matches; exactly one kept split's calling UID must equal the first token of the block's first
    body line (`    <uid> tag=...`). The battery text is opaque. Anything else refuses the dump."""
    require(type(line) is str and line.startswith('  JOB ') and '\n' not in line, 'registered job identity')
    rest = line[len('  JOB '):]
    candidates = [(None, rest[1:])] if rest.startswith('#') else []
    candidates += [(rest[:i], rest[i + 1:]) for i, c in enumerate(rest) if c == ':' and 0 < i <= 1000]
    body = JOB_BODY.match(first_body_line) if type(first_body_line) is str else None
    kept = []
    for namespace, remainder in candidates:
        match = JOB_REST.fullmatch(remainder)
        if match and -1 << 31 <= int(match[2]) < 1 << 31 and body is not None and match[1] == body[1]:
            kept.append((namespace, match[1], int(match[2]), match[3], match[4]))
    require(len({k[:3] for k in kept}) == 1, 'registered job identity')
    namespace, calling, number, digest, battery = kept[0]
    return {'namespace': namespace, 'calling': calling, 'id': number, 'hash': digest, 'battery': battery}


def own_job(identity, lines, uid):
    """The shared own job rule: a block is the subject's if its calling UID is the subject's, or its Source line names
    the subject's UID or package, or its battery text names the package."""
    fu = 'u0a' + str(uid - 10000)
    if identity['calling'] == fu or PACKAGE in identity['battery']:
        return True
    for raw in lines:
        line = raw.strip()
        if line.startswith('Source: '):
            fields = dict(item.split('=', 1) for item in line[len('Source: '):].split(' ') if '=' in item)
            if fields.get('uid') == fu or fields.get('pkg') == PACKAGE:
                return True
    return False


CONSTRAINTS = {'CHARGING': 1, 'BATTERY_NOT_LOW': 2, 'STORAGE_NOT_LOW': 8,
               'TIMING_DELAY': 1 << 31, 'DEADLINE': 1 << 30, 'IDLE': 4,
               'CONNECTIVITY': 1 << 28, 'FLEXIBILITY': 1 << 21, 'CONTENT_TRIGGER': 1 << 26,
               'DEVICE_NOT_DOZING': 1 << 25, 'BACKGROUND_NOT_RESTRICTED': 1 << 22,
               'PREFETCH': 1 << 23, 'WITHIN_QUOTA': 1 << 24}


def _constraints(text):
    if text == '':
        return []
    match = re.fullmatch(r'((?:[A-Z_]+ )+)\[0x([0-9a-f]{1,8})\]', text)
    require(match is not None, 'constraint list form')
    names = match[1].split()
    require(len(names) == len(set(names)) and all(n in CONSTRAINTS for n in names)
            and names == [n for n in CONSTRAINTS if n in names]
            and sum(CONSTRAINTS[n] for n in names) == int(match[2], 16),
            'constraint names, order or mask')
    return names


def _extras(text, contract):
    if re.fullmatch(r'mParcelledData.dataSize=[1-9][0-9]{0,6}', text):
        return {'representation': 'parcelled', 'marker_observable': False, 'raw': text}
    require(text.startswith('{') and text.endswith('}'), 'persistable bundle form')
    values = {}
    for part in text[1:-1].split(', '):
        key, sep, value = part.partition('=')
        require(sep and key in ('andrix.b2.setup', 'andrix.b2.contract_sha256'), 'job extras field')
        _put(values, key, value)
    require(values == {'andrix.b2.setup': contract['setup'],
                       'andrix.b2.contract_sha256': contract['contract_sha256']}, 'job extras marker')
    return {'representation': 'map', 'marker_observable': True, 'values': values}


def _job_block(lines, uid, component, contract):
    """Parse the selected registered JobStatus only, preserving dynamic restriction fields."""
    fu = 'u0a' + str(uid - 10000)
    require(lines and lines[0] == f'    {fu} tag=*job*r/{PACKAGE}/.B2StateJobService', 'job tag')
    facts, info, implicit = {}, {}, {}
    section = 'top'
    history = []
    for raw in lines[1:]:
        require(raw.startswith('    '), 'job block indentation')
        line = raw[4:]
        if line == 'JobInfo:':
            require(section == 'top' and not info, 'duplicate JobInfo')
            section = 'info'; continue
        if section == 'info' and not line.startswith('  '):
            section = 'top'
        if line == 'Implicit constraints:':
            _put(facts, 'Implicit constraints', True)
            section = 'implicit'; continue
        if section in ('implicit', 'history') and not line.startswith('  '):
            section = 'top'
        if line == 'Constraint history:':
            require('Constraint history' not in facts, 'duplicate constraint history')
            facts['Constraint history'] = True; section = 'history'; continue
        if section == 'history':
            match = re.fullmatch(r'  ([^ ]+) =(?: (.*))?', line)
            require(match is not None and len(history) < 10, 'constraint history row')
            relative_time(match[1], unset=False)
            _constraints(match[2] or '')
            history.append(line[2:]); continue
        if section == 'info':
            require(line.startswith('  '), 'JobInfo indentation')
            line = line[2:]
            if line in ('PERSISTED', 'Has early constraint'):
                _put(info, line, True); continue
            if line.startswith('Has media backup exemption='):
                key, value = line.rstrip().split('=', 1)
            else:
                key, sep, value = line.partition(': ')
                require(sep != '', 'JobInfo field')
            require(key in {'Service', 'Priority', 'Requires', 'Has media backup exemption',
                            'Extras', 'Minimum latency', 'Backoff'}, 'unexpected JobInfo field')
            _put(info, key, value); continue
        if section == 'implicit':
            key, sep, value = line[2:].partition(': ')
            require(sep and key in {'readyNotDozing', 'readyNotRestrictedInBg',
                                   'readyDynamicSatisfied', 'readyComponentEnabled'}
                    and value in ('true', 'false'), 'implicit constraint')
            _put(implicit, key, value == 'true'); continue
        if line.startswith(('  Deferred since: ', '  Time since first force batch attempt: ')):
            require('Standby bucket' in facts, 'standby timing nesting')
            key, value = line[2:].split(': ', 1)
            relative_time(value, unset=False)
            _put(facts, key, value); continue
        key, sep, value = line.partition(':')
        if line in ('Uid: active', 'Doze whitelisted: true', 'Is exempted from app standby',
                    'User BG restricted'):
            _put(facts, line, True); continue
        require(sep and key in {'Source', 'Required constraints', 'Dynamic constraints',
                               'Satisfied constraints', 'Unsatisfied constraints',
                               'Num Required Flexible constraints', 'Num Dropped Flexible constraints',
                               'Tracking', 'Started with foreground flag', 'Standby bucket',
                               'Enqueue time', 'Run time', 'Restricted due to', 'Ready'}
                and not value.startswith('  '), 'unexpected job status field')
        _put(facts, key, value.lstrip(' '))
    require(info.get('Service') == component and info.get('PERSISTED') is True
            and info.get('Priority') == '300 [DEFAULT]'
            and info.get('Requires') == 'charging=false batteryNotLow=false deviceIdle=false'
            and info.get('Has media backup exemption') == 'false'
            and info.get('Has early constraint') is True
            and info.get('Backoff') == 'policy=1 initial=+30s0ms', 'one off JobInfo contract')
    require(set(info) == {'Service', 'PERSISTED', 'Priority', 'Requires', 'Has media backup exemption',
                          'Extras', 'Minimum latency', 'Backoff', 'Has early constraint'},
            'complete JobInfo')
    minimum = duration(info['Minimum latency'])
    require(0 < minimum <= LATENCY + 60000, 'minimum latency')
    extras = _extras(info['Extras'], contract)
    required = {'Source', 'Required constraints', 'Dynamic constraints', 'Satisfied constraints',
                'Unsatisfied constraints', 'Constraint history', 'Implicit constraints',
                'Started with foreground flag', 'Standby bucket', 'Enqueue time', 'Run time',
                'Restricted due to', 'Ready'}
    require(required <= set(facts) and {'readyNotDozing', 'readyNotRestrictedInBg',
                                       'readyComponentEnabled'} <= set(implicit), 'incomplete JobStatus')
    require(facts['Source'] == f'uid={fu} user=0 pkg={PACKAGE}'
            and facts['Started with foreground flag'] == 'false', 'job source')
    runtime = re.fullmatch(r'earliest=([^,]+), latest=none, original latest=none', facts['Run time'])
    require(runtime is not None and duration(runtime[1]) > 0, 'job became due or got a deadline')
    constraints = {key: _constraints(facts[key]) for key in (
        'Required constraints', 'Dynamic constraints', 'Satisfied constraints', 'Unsatisfied constraints')}
    require('TIMING_DELAY' in constraints['Required constraints']
            and 'TIMING_DELAY' in constraints['Unsatisfied constraints']
            and 'TIMING_DELAY' not in constraints['Satisfied constraints']
            and not set(constraints['Required constraints']) & {'DEADLINE', 'CONNECTIVITY',
                'CONTENT_TRIGGER', 'CHARGING', 'IDLE', 'BATTERY_NOT_LOW', 'STORAGE_NOT_LOW', 'PREFETCH'},
            'timing constraint lost or unexpected explicit constraint')
    tracking = facts.get('Tracking', '').split()
    tracking_order = ['BATTERY', 'CONNECTIVITY', 'CONTENT', 'IDLE', 'STORAGE', 'TIME', 'QUOTA']
    require(tracking and tracking == [x for x in tracking_order if x in tracking],
            'job tracking names, order or duplicate')
    require(facts['Standby bucket'] in {'ACTIVE', 'WORKING_SET', 'FREQUENT', 'RARE', 'NEVER',
                                       'RESTRICTED', 'EXEMPTED'}, 'standby bucket form')
    for key in ('Num Required Flexible constraints', 'Num Dropped Flexible constraints'):
        if key in facts:
            require(re.fullmatch(r'0|[1-9][0-9]{0,2}', facts[key]) is not None,
                    'flexible constraint count')
    enqueued = relative_time(facts['Enqueue time'])
    require(enqueued is None or enqueued <= 0, 'enqueue time is in the future')
    ready = re.fullmatch(r'false \(job=(true|false) user=(true|false) !restricted=(true|false) '
                         r'!pending=true !active=true !backingup=(true|false) comp=(true|false)\)',
                         facts['Ready'])
    require(ready is not None and ready[1] == 'false', 'active, pending or ready selected job')
    require((ready[5] == 'true') == implicit['readyComponentEnabled'], 'component status mismatch')
    return {'uid': uid, 'source_user': 0, 'package': PACKAGE, 'id': JOB_ID, 'namespace': None,
            'service': SERVICE, 'persisted': True, 'periodic': False, 'component': ready[5] == 'true',
            'remaining_ms': duration(runtime[1]), 'minimum_latency_ms': minimum, 'extras': extras,
            'dynamic': facts, 'implicit': implicit, 'constraint_history': history}


def jobscheduler(capture, contract, admitted, initialized=True):
    validate_contract(contract)
    text = capture_text(capture, dumpsys_argv('jobscheduler'))
    lines = text.splitlines()
    uid = contract['uid']; fu = 'u0a' + str(uid - 10000)
    start, count = _one([(i, int(m[1])) for i, line in enumerate(lines)
                         if (m := re.fullmatch(r'Registered (0|[1-9][0-9]*) jobs:', line))],
                        'registered jobs section')
    end = next((i for i in range(start + 1, len(lines))
                if lines[i] and not lines[i].startswith(' ')), len(lines))
    require(end < len(lines) and 'Pending queue:' in lines
            and 'Recently completed jobs:' in lines, 'complete unfiltered job dump')
    blocks = []; current = None
    for line in lines[start + 1:end]:
        if not line:
            continue
        if line.startswith('  JOB '):
            current = {'header': line, 'lines': []}
            blocks.append(current)
        elif current is not None:
            current['lines'].append(line)
        else:
            require(count == 0 and line == '  None.', 'unexpected registered job content')
    for block in blocks:
        block.update(job_header(block['header'], block['lines'][0] if block['lines'] else None))
    require(len(blocks) == count and len({(b['namespace'], b['calling'], b['id']) for b in blocks}) == count,
            'duplicate job identity or filtered/truncated registered count')
    own = [b for b in blocks if own_job(b, b['lines'], uid)]
    if not initialized:
        require(not own, 'preexisting job in some namespace')
        return {'uid': uid, 'jobs': []}
    block = _one(own, 'one original own job across all namespaces')
    require(block['namespace'] is None and block['calling'] == fu and block['id'] == JOB_ID
            and block['battery'] == PACKAGE + '/.B2StateJobService', 'job identity changed')
    result = _job_block(block['lines'], uid, block['battery'], contract)
    require(result['component'] is admitted, 'job component admission differs')
    # Controllers legitimately refer to waiting jobs. Only queue, execution and history
    # sections are negative oracles, not arbitrary later mentions of the registered identity.
    pending = _one([i for i, x in enumerate(lines) if x == 'Pending queue:'], 'pending section')
    active = _one([i for i, x in enumerate(lines) if x == 'Active jobs:'], 'active section')
    recent = _one([i for i, x in enumerate(lines) if x == 'Recently completed jobs:'],
                  'completion section')
    require(end <= pending < active < recent, 'job execution section order')
    histories = [i for i, x in enumerate(lines) if x == '  Job history:']
    require(len(histories) <= 1 and (not histories or end <= histories[0] < pending),
            'job history section')
    negative = '\n'.join(lines[pending:] + (lines[histories[0]:pending] if histories else []))
    require(re.search(r'(?<![A-Za-z0-9_])' + re.escape('#' + fu + '/' + str(JOB_ID))
                      + r'(?![0-9])', negative) is None, 'selected job execution or history')
    return result


def job_state(capture, uid, admitted, transport_error=None):
    argv = ['cmd', 'jobscheduler', 'get-job-state', '-u', '0', PACKAGE, str(JOB_ID)]
    if admitted:
        require(capture_text(capture, argv) == 'waiting\n', 'job not waiting')
        return {'lookup': 'waiting', 'retention_proven': False}
    require(type(transport_error) is int and transport_error != 0, 'record transport error encoding')
    text = capture_text(capture, argv, transport_error, f'Package not found: {PACKAGE} / user 0\n')
    require(text == f'unknown({PACKAGE})\n', 'deferred lookup form')
    return {'lookup': 'unknown-package', 'service_error': -1000,
            'transport_exit': transport_error, 'retention_proven': False}


def file_hashes(capture, expected):
    require(type(expected) is dict and expected and all(hex_value(x) for x in expected.values()),
            'committed hashes')
    text = capture_text(capture, ['sha256sum', *expected])
    actual = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (/[^\n]+)', line)
        require(match is not None, 'hash line')
        _put(actual, match[2], match[1])
    require(actual == expected, 'dummy files missing, duplicated or changed')
    return actual


def file_stats(capture, paths, uid, expected=None):
    text = capture_text(capture, ['stat', '-c', '%n|%f|%u|%g|%h|%s', *paths])
    facts = {}
    for line in text.splitlines():
        values = line.split('|')
        require(len(values) == 6 and values[0] in paths
                and re.fullmatch('[0-9a-f]{4,8}', values[1])
                and all(re.fullmatch(r'0|[1-9][0-9]*', x) for x in values[2:]), 'stat row')
        mode, owner, group, links, size = [int(values[1], 16), *map(int, values[2:])]
        require(stat.S_ISREG(mode) and owner == uid and group == uid and links == 1
                and 0 < size <= 4096, 'dummy file type, owner, link or size')
        _put(facts, values[0], {'mode': mode, 'uid': owner, 'gid': group, 'links': links, 'size': size})
    require(set(facts) == set(paths) and (expected is None or facts == expected), 'stat baseline changed')
    return facts


def file_labels(capture, paths, expected=None):
    text = capture_text(capture, ['ls', '-Zd', *paths])
    facts = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(u:object_r:app_data_file:s0(?::c[0-9]+(?:\.c[0-9]+)?'
                             r'(?:,c[0-9]+(?:\.c[0-9]+)?)*)?) +(/\S+)', line)
        require(match is not None and match[2] in paths, 'SELinux label row')
        _put(facts, match[2], match[1])
    require(set(facts) == set(paths) and (expected is None or facts == expected), 'label changed')
    return facts


def pm_surface(all_packages, admitted_packages, path_capture, details_capture, uid, code_path, admitted):
    expected = f'package:{PACKAGE} uid:{uid}\n'
    require(capture_text(all_packages, ['cmd', 'package', 'list', 'packages', '-U', '-u', PACKAGE])
            == expected, 'original retained PM mapping')
    require(capture_text(admitted_packages, ['cmd', 'package', 'list', 'packages', '-U', PACKAGE])
            == (expected if admitted else ''), 'PM admission list')
    require(capture_text(path_capture, ['pm', 'path', PACKAGE], 0 if admitted else 1)
            == ('package:' + code_path + '\n' if admitted else ''), 'PM path surface')
    text = capture_text(details_capture, dumpsys_argv('package', PACKAGE))
    lines = text.splitlines()
    header = _one([i for i, line in enumerate(lines)
                   if re.fullmatch(r'  Package \[' + re.escape(PACKAGE) + r'\] \([0-9a-f]+\):', line)],
                  'selected PM package block')
    require('Packages:' in lines[:header], 'PM package section')
    end = next((i for i in range(header + 1, len(lines))
                if lines[i] and not lines[i].startswith('    ')), len(lines))
    block = lines[header + 1:end]
    for key, wanted in [('appId', str(uid)), ('codePath', str(Path(code_path).parent))]:
        require(_one([x[4 + len(key) + 1:] for x in block if x.startswith('    ' + key + '=')],
                     'PM ' + key) == wanted, 'PM identity path')
    pkg = _one([x[8:] for x in block if x.startswith('    pkg=')], 'scanned PM package field')
    require((re.fullmatch(r'Package\{[0-9a-f]+ ' + re.escape(PACKAGE) + r'\}', pkg) is not None)
            if admitted else pkg == 'null', 'PM scanned object')
    version = _one([x.strip().split()[0] for x in block if x.startswith('    versionCode=')],
                   'PM version')
    user = _one([x for x in block if x.startswith('    User 0: ceDataInode=')], 'PM user zero')
    require(version == 'versionCode=1' and user.split().count('installed=true') == 1
            and len([x for x in user.split() if x.startswith('installed=')]) == 1, 'PM user install')
    return {'package': PACKAGE, 'uid': uid, 'code_path': code_path, 'admitted': admitted,
            'settings_retained': True, 'installed': True, 'version_code': 1}


def _existing(name):
    path = Path(__file__).resolve().parent.parent / (name + '.py')
    spec = importlib.util.spec_from_file_location('b2_existing_' + name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def package_maps(packages_capture, shared_capture):
    packages = capture_text(packages_capture, dumpsys_argv('package', 'packages'))
    shared = capture_text(shared_capture, dumpsys_argv('package', 'shared-users'))
    module = _existing('uid_observe')
    return {'packages': module.package_ids(packages), 'shared': module.shared_ids(shared)}


def native_dump(capture, schema):
    require(schema in (2, 3), 'explicit B1 or B2 schema')
    text = capture_text(capture, dumpsys_argv('package', '--andrix-native-identities'))
    return _existing('observe').parse_reservations(text, schema=schema)


def subject(capture, contract, operation, nonce, phase, guest_binding, expected_keys=None,
            openssl='openssl'):
    argv = instrumentation_argv(contract, operation, nonce, phase, guest_binding, expected_keys)
    text = capture_text(capture, argv)
    return assess_reply(text, capture['stderr'], capture['exit_code'], contract, operation, nonce,
                        phase, guest_binding, expected_keys, openssl)


def trial_clock(setup_rtc_ms, now_rtc_ms, original_due_ms, due_ms, tolerance_ms=60000):
    """Explicit bounded UTC admission, not equality of elapsed displays or disk bytes."""
    require(all(type(x) is int and 0 <= x < 1 << 63
                for x in (setup_rtc_ms, now_rtc_ms, original_due_ms, due_ms, tolerance_ms))
            and tolerance_ms <= 60000, 'RTC observations')
    require(0 <= now_rtc_ms - setup_rtc_ms <= TRIAL_LIMIT
            and abs(original_due_ms - (setup_rtc_ms + LATENCY)) <= tolerance_ms
            and abs(due_ms - original_due_ms) <= tolerance_ms
            and due_ms - now_rtc_ms > LATENCY - TRIAL_LIMIT - tolerance_ms,
            'expired trial, RTC shift or replaced timing')
    return {'age_ms': now_rtc_ms - setup_rtc_ms, 'due_ms': due_ms,
            'remaining_ms': due_ms - now_rtc_ms, 'tolerance_ms': tolerance_ms}
