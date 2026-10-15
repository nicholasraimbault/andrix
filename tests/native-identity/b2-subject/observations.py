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
                      assess_reply, hex_value, instrumentation_argv, notification_preference,
                      notification_setup_argv, require, sha, strict_json, validate_contract)

PERMISSION = 'android.permission.POST_NOTIFICATIONS'
OP = 'android:vibrate'
MODES = {'allow', 'ignore', 'deny', 'default', 'foreground'}


def capture_text(capture, argv, exit_code=0, stderr=''):
    require(type(capture) is dict and set(capture) == {
        'argv', 'stdout', 'stderr', 'exit_code', 'complete'}, 'capture fields')
    require(capture['argv'] == argv and capture['complete'] is True
            and type(capture['exit_code']) is int and capture['exit_code'] == exit_code
            and capture['stderr'] == stderr, 'command, transport or completeness')
    text = capture['stdout']
    require(type(text) is str and len(text.encode('utf-8')) <= 16 * 1024 * 1024
            and all(ord(c) >= 32 or c in '\n\t' for c in text)
            and (not text or text.endswith('\n')), 'bounded LF terminated capture')
    return text


def _one(rows, message):
    require(len(rows) == 1, message)
    return rows[0]


def _put(mapping, key, value):
    require(key not in mapping, 'duplicate selected field or identity: ' + key)
    mapping[key] = value


def permissionmgr(capture, uid, selector='app-id'):
    require(type(uid) is int and 10000 <= uid <= 19999 and selector in ('app-id', 'package'),
            'permission selector')
    text = capture_text(capture, ['dumpsys', 'permissionmgr', '--' + selector,
                                  str(uid) if selector == 'app-id' else PACKAGE])
    lines = text.splitlines()
    require(len(lines) >= 6 and lines[0] == f'App ID: {uid}' and lines[1] == '  User: 0'
            and lines[2] == '    Permissions:', 'permission identity and nesting')
    permissions, uid_ops, package_ops = {}, {}, {}
    section = 'permissions'
    version = None
    for line in lines[3:]:
        if section == 'permissions' and line == '    App ops:':
            section = 'uid_ops'
        elif section == 'uid_ops' and line == '    Package: ' + PACKAGE:
            section = 'version'
        elif section == 'version':
            match = re.fullmatch(r'      version=(0|[1-9][0-9]{0,9}|null)', line)
            require(match is not None, 'permission migration version')
            version = None if match[1] == 'null' else int(match[1])
            require(version is None or version < 1 << 31, 'migration version range')
            section = 'package_header'
        elif section == 'package_header' and line == '      App ops:':
            section = 'package_ops'
        elif section == 'permissions':
            match = re.fullmatch(r'      ([a-zA-Z][a-zA-Z0-9_.]*): granted=(true|false), '
                                 r'flags=\[((?:[A-Z][A-Z0-9_]*|0x[0-9a-f]+)'
                                 r'(?:\|(?:[A-Z][A-Z0-9_]*|0x[0-9a-f]+))*)?\]', line)
            require(match is not None, 'permission row')
            flags = match[3].split('|') if match[3] else []
            require(len(flags) == len(set(flags)), 'duplicate permission flag')
            _put(permissions, match[1], {'granted': match[2] == 'true', 'flags': flags})
        elif section in ('uid_ops', 'package_ops'):
            indent = '      ' if section == 'uid_ops' else '        '
            match = re.fullmatch(indent + r'(android:[a-z0-9_]+): mode=([a-z]+)', line)
            require(match is not None and match[2] in MODES, 'app operation row or nesting')
            _put(uid_ops if section == 'uid_ops' else package_ops, match[1], match[2])
        else:
            raise ValueError('unexpected permission structure')
    require(section == 'package_ops', 'incomplete permission dump')
    return {'app_id': uid, 'user': 0, 'package': PACKAGE, 'version': version,
            'permissions': permissions, 'uid_ops': uid_ops, 'package_ops': package_ops}


def require_permission_state(facts, baseline_version, initialized=True):
    require(facts['version'] == baseline_version and OP not in facts['uid_ops'],
            'migration version or UID mode changed')
    row = facts['permissions'].get(PERMISSION)
    if initialized:
        require(row == {'granted': True, 'flags': ['RUNTIME_GRANTED', 'USER_SET']}
                and facts['package_ops'].get(OP) == 'ignore', 'permission or package mode lost')
    else:
        require((row is None or row == {'granted': False, 'flags': []})
                and OP not in facts['package_ops'], 'dirty permission or operation baseline')
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


def notification(capture, uid, stage='retained', baseline=None):
    require(type(stage) is str and stage in ('absent', 'created', 'retained'),
            'notification observation stage')
    text = capture_text(capture, ['dumpsys', 'notification', '--noredact', '--package', PACKAGE])
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
            continue
        if current == PACKAGE:
            require(line.startswith('        NotificationChannel{'), 'unexpected subject preference')
            target_channels.append(channel_row(line[8:]))
        elif PACKAGE in line or CHANNEL in line:
            raise ValueError('selected preference outside its package block')
    target_packages = [p for p in packages if p[0] == PACKAGE]
    require(len(target_packages) <= 1, 'duplicate subject preferences')
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
            if match[1] != '0':
                duration(match[1])
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
            if value != '0':
                duration(value)
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
    require(facts['Enqueue time'] == '0' or duration(facts['Enqueue time']) < 0,
            'enqueue time is in the future')
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
    text = capture_text(capture, ['dumpsys', 'jobscheduler'])
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
            match = re.fullmatch(r'  JOB (#[^ /:]+|[^ /]+:[^ /:]+)/([0-9]+): '
                                 r'([0-9a-f]+) (\S+)', line)
            require(match is not None, 'registered job identity')
            current = {'identity': match[1], 'id': int(match[2]), 'component': match[4], 'lines': []}
            blocks.append(current)
        elif current is not None:
            current['lines'].append(line)
        else:
            require(count == 0 and line == '  None.', 'unexpected registered job content')
    require(len(blocks) == count and len({(b['identity'], b['id']) for b in blocks}) == count,
            'duplicate job identity or filtered/truncated registered count')
    own = [b for b in blocks if b['identity'] == '#' + fu or b['identity'].endswith(':' + fu)
           or b['component'].startswith(PACKAGE + '/')]
    if not initialized:
        require(not own, 'preexisting job in some namespace')
        return {'uid': uid, 'jobs': []}
    block = _one(own, 'one original own job across all namespaces')
    require(block['identity'] == '#' + fu and block['id'] == JOB_ID
            and block['component'] == PACKAGE + '/.B2StateJobService', 'job identity changed')
    result = _job_block(block['lines'], uid, block['component'], contract)
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
    text = capture_text(details_capture, ['dumpsys', 'package', PACKAGE])
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
    packages = capture_text(packages_capture, ['dumpsys', 'package', 'packages'])
    shared = capture_text(shared_capture, ['dumpsys', 'package', 'shared-users'])
    module = _existing('uid_observe')
    return {'packages': module.package_ids(packages), 'shared': module.shared_ids(shared)}


def native_dump(capture, schema):
    require(schema in (2, 3), 'explicit B1 or B2 schema')
    text = capture_text(capture, ['dumpsys', 'package', '--andrix-native-identities'])
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
