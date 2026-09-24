# SPDX-License-Identifier: Apache-2.0
"""Finite probe observations, not a product authorization interface."""
import json
import re


def events(stdout):
    if len(stdout) > 131072:
        raise ValueError('probe output bound')
    rows = []
    for line in stdout.split('\n'):
        if not line.strip():
            continue
        if not line.startswith('{'):
            raise ValueError('non-JSON probe output')
        row = json.loads(line)
        if not isinstance(row, dict) or type(row.get('schema')) is not int or row.get('schema') != 1:
            raise ValueError('unknown probe schema')
        rows.append(row)
    if not rows or len(rows) > 320:
        raise ValueError('missing or excessive probe events')
    return rows


def bound_context(rows, uid, package, nonce, action, principal=None):
    """Validate the kernel and context prefix, including on a native service refusal."""
    principal = package if principal is None else principal
    if (not all(isinstance(value, str) and value for value in [package, nonce, action, principal])
            or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', nonce)
            or action not in ['info', 'post', 'cancel', 'observe']):
        raise ValueError('invalid expected command identity')
    failures = [n for n, row in enumerate(rows) if 'status' in row]
    if failures:
        if (failures != [len(rows) - 1] or rows[-1]['status'] != 'refused_or_failed'
                or any(row.get('phase') == 'complete' for row in rows)):
            raise ValueError('ambiguous or unsupported terminal status')
    if len(rows) < 2 or [row.get('phase') for row in rows[:2]] != ['entry', 'context']:
        raise ValueError('identity/context prefix is not first')
    for phase in ['entry', 'context']:
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
    if (context.get('context_package') != principal or context.get('context_uid') != uid
            or context.get('attribution_uid') != uid or context.get('attribution_package') != principal):
        raise ValueError('context/operation identity mismatch')
    return context


def completed(rows, uid, package, nonce, action):
    if any(row.get('status') == 'refused_or_failed' for row in rows):
        raise ValueError('probe did not complete')
    context = bound_context(rows, uid, package, nonce, action)
    if sum(row.get('phase') == 'complete' for row in rows) != 1 or rows[-1].get('phase') != 'complete':
        raise ValueError('missing, duplicate or nonfinal completion')
    return context, rows[-1]


def _varint(data, position):
    value = 0
    for index in range(10):
        if position >= len(data):
            raise ValueError('truncated protobuf varint')
        byte = data[position]; position += 1
        if index == 9 and byte > 1:
            raise ValueError('protobuf varint overflow')
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value, position
    raise ValueError('overlong protobuf varint')


def _fields(data):
    position = 0
    while position < len(data):
        tag, position = _varint(data, position)
        number, wire = tag >> 3, tag & 7
        if not number or number > 0x1fffffff:
            raise ValueError('invalid protobuf field')
        if wire == 0:
            value, position = _varint(data, position)
        elif wire in [1, 2, 5]:
            if wire == 2:
                size, position = _varint(data, position)
            else:
                size = 8 if wire == 1 else 4
            end = position + size
            if end > len(data):
                raise ValueError('truncated protobuf field')
            value = data[position:end]; position = end
        else:
            raise ValueError('unsupported protobuf wire type')
        yield number, wire, value


def active_notification(dump, uid, user, package, nonce):
    """Pinned NotificationServiceDumpProto, from an unfiltered successful --proto command.

    Requires the final ranking section and preceding singleton sections. Textual dumps,
    partial output and malformed records are not absence. Transport provenance and lack
    of command filters are verified by the controller, not authenticated by this parser.
    """
    if (type(uid) is not int or uid < 0 or type(user) is not int or user != uid // 100000
            or not isinstance(package, str) or not package or not isinstance(nonce, str)
            or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', nonce)):
        raise ValueError('invalid expected notification identity')
    if not isinstance(dump, bytes) or not dump or len(dump) > 4 * 1024 * 1024:
        raise ValueError('missing or oversized notification protobuf')
    expected_key = f'{user}|{package}|7301|{nonce}|{uid}'
    markers = set()
    found = 0
    for number, wire, value in _fields(dump):
        if number in [2, 3, 6, 7, 8]:
            if wire != 2 or number in markers:
                raise ValueError('invalid or duplicate service section')
            markers.add(number)
        if number != 1:
            continue
        if wire != 2 or markers:
            raise ValueError('invalid record type/order')
        fields = {}
        for field, kind, item in _fields(value):
            if field in fields:
                raise ValueError('duplicate notification record field')
            fields[field] = (kind, item)
        if fields.get(2, (0, 0))[0] != 0 or fields.get(2, (0, 0))[1] not in [0, 1, 2]:
            raise ValueError('unknown notification record state')
        if fields.get(1, (None,))[0] != 2 or fields.get(11, (None,))[0] != 2:
            raise ValueError('record missing key/package')
        key = fields[1][1].decode('utf-8', errors='strict')
        record_package = fields[11][1].decode('utf-8', errors='strict')
        if record_package != package:
            continue
        parts = key.split('|')
        if len(parts) < 5 or parts[1] != record_package:
            raise ValueError('malformed principal notification key')
        if parts[2:4] != ['7301', nonce]:
            continue
        if key != expected_key:
            raise ValueError('same target/nonce has unexpected UID or user')
        if fields.get(2, (0, 0))[1] == 1:  # POSTED, not ENQUEUED or SNOOZED.
            found += 1
    if markers != {2, 3, 6, 7, 8}:
        raise ValueError('incomplete notification service protobuf')
    if found > 1:
        raise ValueError('duplicate exact posted record')
    return found == 1
