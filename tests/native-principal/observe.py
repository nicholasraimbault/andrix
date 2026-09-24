# SPDX-License-Identifier: Apache-2.0
"""Finite probe observations, not a product authorization interface."""
import json
import re


def events(stdout):
    if len(stdout) > 131072:
        raise ValueError('probe output bound')
    rows = []
    for line in stdout.splitlines():
        if not line.startswith('{'):
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or type(row.get('schema')) is not int or row.get('schema') != 1:
            raise ValueError('unknown probe schema')
        rows.append(row)
    if not rows or len(rows) > 320:
        raise ValueError('missing or excessive probe events')
    return rows


def completed(rows, uid, package, nonce, action):
    if any(row.get('status') == 'refused_or_failed' for row in rows):
        raise ValueError('probe did not complete')
    for phase in ['entry', 'context', 'complete']:
        if sum(row.get('phase') == phase for row in rows) != 1:
            raise ValueError('missing or duplicate phase')
    entry = next(row for row in rows if row['phase'] == 'entry')
    if type(uid) is not int or uid < 0 or not 10000 <= uid % 100000 <= 19999:
        raise ValueError('not an ordinary appId')
    pid = entry.get('pid')
    if type(pid) is not int or pid <= 1:
        raise ValueError('invalid diagnostic PID')
    elapsed = -1
    for row in rows:
        if (row.get('uid') != uid or row.get('pid') != pid or row.get('target_package') != package
                or row.get('nonce') != nonce or row.get('action') != action):
            raise ValueError('mixed command observations')
        now = row.get('elapsed_realtime_ms')
        if type(now) is not int or now < elapsed:
            raise ValueError('invalid observation time')
        elapsed = now
    kernel = entry['kernel_fields']
    for name in ['Uid', 'Gid']:
        if kernel.get(name, '').split() != [str(uid)] * 4:
            raise ValueError('kernel tuple mismatch')
    for name in ['CapInh', 'CapPrm', 'CapEff', 'CapAmb']:
        if not re.fullmatch('0{1,16}', kernel.get(name, '')):
            raise ValueError('unexpected capabilities')
    if not re.fullmatch(r'u:r:runas_app:s0(?::c[0-9]+(?:,c[0-9]+)*)?', entry.get('selinux_context', '')):
        raise ValueError('unexpected debug domain')
    context = next(row for row in rows if row['phase'] == 'context')
    if context.get('context_package') != package:
        raise ValueError('context package mismatch')
    if rows[-1].get('phase') != 'complete':
        raise ValueError('completion not final')
    return context, rows[-1]


def active_notification(dump, uid, user, package, nonce):
    """Only the pinned service's active Notification List, not history or enqueued work."""
    if type(uid) is not int or uid < 0 or type(user) is not int or user != uid // 100000:
        raise ValueError('user and UID mismatch')
    if not dump.startswith('Current Notification Manager state') or len(dump) > 4 * 1024 * 1024:
        raise ValueError('unrecognized or oversized service dump')
    lines = dump.splitlines()
    indices = [n for n, line in enumerate(lines) if line == '  Notification List:']
    if len(indices) > 1:
        raise ValueError('duplicate active notification list')
    if not indices:
        return False  # The inspected implementation omits this section when empty.
    key = f'{user}|{package}|7301|{nonce}|{uid}'
    found = 0
    for line in lines[indices[0] + 1:]:
        if not line.startswith('    '):
            break
        if line.startswith('    NotificationRecord(') and f' key={key}: ' in line:
            found += 1
    if found > 1:
        raise ValueError('duplicate exact active record')
    return found == 1
