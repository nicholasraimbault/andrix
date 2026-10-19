# SPDX-License-Identifier: Apache-2.0
"""The process history reader's helper contract and its strict reply parser, host side.

The fixed read only helper of tests/process-health-read, run as the shell user, makes two reads of
the activity manager for one user: SystemUI's exit history,
`getHistoricalProcessExitReasons("com.android.systemui", 0, 0, user)`, and the whole list of
processes in an error state, `getProcessesInErrorState()`. It samples the elapsed time since boot
and the wall clock right before and right after each call, and prints every row of each reply. This
module holds its device contract (the pinned jar, its path and its one invocation), the parser of
its exact reply, the exact form of a parsed reading, and the read bracketed by the shell user and
the helper's pinned bytes.

What a reply is:

- **Whole.** A reply ends with the end marker, which counts the lines before it and gives the
  SHA-256 of their bytes. A reply cut short, without that marker, or whose lines, count or digest do
  not agree is unavailable evidence, never a reply with fewer rows.
- **Complete empty.** `history status=OK count=0` is Android's whole answer that the user's SystemUI
  package has no exit record, and `current-errors status=OK count=0 returned=null` its whole answer
  that no process is in an error state: the service answers null then, never an empty list
  (core/java/android/app/ActivityManager.java:4015-4028; services/core/java/com/android/server/am/
  ActivityManagerService.java:10860-10910). An empty list returned is of no known form.
- **Not empty.** A denial, an exception, an absent service, a signature of another form or an
  overflow is `status=ERROR` or `status=UNAVAILABLE` with its reason. It is never zero rows: the
  part is unavailable.
- **Numeric times.** Every time is a decimal number of milliseconds: elapsed since boot, or the wall
  clock's milliseconds since the epoch. A formatted date, of any time zone, has no known form.

Which rows a complete reply can hide is the service's rule, not the reply's: the current list holds
another user's processes only for a caller with INTERACT_ACROSS_USERS_FULL, and the history of
another package UID needs DUMP (ActivityManagerService.java:10860-10879, 11184-11205). The reader
of criterion bit 1 (health_witness.py) decides what a complete reply covers. A host test of this
module shows the parser on the helper's forms; no Android reply here is qualified."""
import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import full_users  # noqa: E402
import lab_readers  # noqa: E402
from scripts.proof import systemui_sessions as readback  # noqa: E402

# The fixed read only helper of tests/process-health-read: its pinned jar, the one path the vehicle
# pushes it to, and its one invocation for a bounded user. The reader never pushes.
HELPER = '/data/local/tmp/andrix-d5/andrix-process-health-read.jar'
HELPER_SHA256 = 'b74f0aad224e14ac02eca814f741cc8018500a773ee200dab2dded96c469082e'
HEADER = 'andrix-process-health-read-v1'
# The schema of a baseline's history and current error parts that hold such a reading.
SCHEMA = HEADER
PACKAGE = full_users.SYSTEMUI
CAPABILITIES = ('history', 'current-errors')
# The helper's bounds: UserHandle.MAX_SECONDARY_USER_ID (core/java/android/os/UserHandle.java:
# 134-135), the most rows of one read, and the most UTF-16 units of a process name or of a
# diagnostic string kept.
MAX_USER = 21473
MAX_ROWS = 64
MAX_TEXT = 256
MAX_REPLY = 1 << 20
SHELL_IDENTITY = 'id'
SHELL_USER = (2000, 2000, 'u:r:shell:s0')
HELPER_DIGEST = 'sha256sum ' + HELPER
_INVOCATION = re.compile('CLASSPATH=' + re.escape(HELPER) + r' app_process /system/bin ProcessHealthRead '
                         r'(0|[1-9][0-9]{0,4})')
# ApplicationExitInfo's reasons (core/java/android/app/ApplicationExitInfo.java:67-185), and the
# conditions of a process in an error state (core/java/android/app/ActivityManager.java:3912-3914).
REASONS = {0: 'UNKNOWN', 1: 'EXIT_SELF', 2: 'SIGNALED', 3: 'LOW_MEMORY', 4: 'CRASH', 5: 'CRASH_NATIVE', 6: 'ANR',
           7: 'INITIALIZATION_FAILURE', 8: 'PERMISSION_CHANGE', 9: 'EXCESSIVE_RESOURCE_USAGE', 10: 'USER_REQUESTED',
           11: 'USER_STOPPED', 12: 'DEPENDENCY_DIED', 13: 'OTHER', 14: 'FREEZER', 15: 'PACKAGE_STATE_CHANGE',
           16: 'PACKAGE_UPDATED'}
CONDITIONS = {1: 'CRASHED', 2: 'NOT_RESPONDING'}
STATUSES = ('OK', 'ERROR', 'UNAVAILABLE')
# A row of the history, and an entry of the current list, as a reading holds them: fields in order.
ROW_FIELDS = ('timestamp', 'pid', 'real_uid', 'package_uid', 'defining_uid', 'user', 'process', 'reason',
              'subreason', 'status')
ENTRY_FIELDS = ('condition', 'pid', 'uid', 'process', 'tag', 'tag_length', 'short', 'short_length', 'long',
                'long_length', 'stack', 'stack_length')
READING_KEYS = ('user', 'complete', 'history', 'current', 'sha256')
PART_KEYS = ('status', 'reason', 'samples', 'rows')
CURRENT_KEYS = ('status', 'reason', 'samples', 'returned', 'entries')
_SAFE = re.compile(r'[A-Za-z0-9._:]')
TOKEN = re.compile(r'-|(?:[A-Za-z0-9._:]|%[0-9A-F]{2})*')
REASON = re.compile(r'service-absent|overflow|not-a-list|not-a-list-slice|not-an-exit-info|not-an-error-state|unknown'
                    r'|[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+')
_INT = r'-?(?:0|[1-9][0-9]{0,18})'
_END = re.compile(r'end=' + re.escape(HEADER) + r' lines=(0|[1-9][0-9]{0,5}) sha256=([0-9a-f]{64})')
INT32 = (-(1 << 31), (1 << 31) - 1)
INT64 = (-(1 << 63), (1 << 63) - 1)


class FormError(lab_readers.Unclassified):
    """A reply of no known form: no reading."""


def _user(user):
    if type(user) is not int or not 0 <= user <= MAX_USER:
        raise ValueError('a user ID from 0 to %d' % MAX_USER)
    return user


def command(user):
    """The helper's one invocation for one user, as the shell user."""
    return 'CLASSPATH=%s app_process /system/bin ProcessHealthRead %d' % (HELPER, _user(user))


def read_allowed(command):
    """Whether a command is one of this reader's own fixed forms: the shell user, the helper's
    digest and the helper for a bounded user."""
    if command in (SHELL_IDENTITY, HELPER_DIGEST):
        return True
    match = _INVOCATION.fullmatch(command)
    return bool(match) and int(match[1]) <= MAX_USER


def encode_text(text):
    """A string as the helper prints it: its UTF-8 bytes, a safe byte as itself and any other as
    %XX; None as '-'."""
    if text is None:
        return '-'
    return ''.join(chr(b) if _SAFE.fullmatch(chr(b)) else '%%%02X' % b for b in text.encode('utf-8'))


def decode_text(token):
    """The string one token holds, or None for '-'. Only the helper's exact encoding is a token: a
    safe byte escaped, a lowercase digit or bytes that are not UTF-8 have no known form."""
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise FormError('a string of no known form')
    if token == '-':
        return None
    data = bytearray()
    i = 0
    while i < len(token):
        if token[i] == '%':
            data.append(int(token[i + 1:i + 3], 16))
            i += 3
        else:
            data.append(ord(token[i]))
            i += 1
    try:
        text = bytes(data).decode('utf-8')
    except UnicodeDecodeError as error:
        raise FormError('a string that is not UTF-8') from error
    if encode_text(text) != token:
        raise FormError('a string not in the helper encoding')
    return text


def _number(text, bounds, low=None):
    if not re.fullmatch(_INT, text):
        raise FormError('a number of no known form')
    value = int(text)
    if not bounds[0] <= value <= bounds[1] or (low is not None and value < low):
        raise FormError('a number out of its bound')
    return value


def _fields(line, prefix, names):
    """The values of one line `<prefix> name=value ...` with exactly these names in order."""
    if not line.startswith(prefix + ' '):
        raise FormError('a line of no known form')
    parts = line[len(prefix) + 1:].split(' ')
    if len(parts) != len(names):
        raise FormError('a line of no known form')
    values = []
    for part, name in zip(parts, names):
        key, sep, value = part.partition('=')
        if key != name or not sep:
            raise FormError('a line of no known form')
        values.append(value)
    return values


def _sample(line, prefix, when):
    found = _fields(line, prefix, ('sample', 'elapsed', 'wall'))
    if found[0] != when:
        raise FormError('a sample out of its place')
    return [_number(found[1], INT64, 0), _number(found[2], INT64, 0)]


def _status(line, prefix, current):
    """(status, reason, count, returned) of one status line."""
    if line.startswith(prefix + ' status=OK '):
        if current:
            found = _fields(line, prefix, ('status', 'count', 'returned'))
            if found[2] not in ('null', 'list'):
                raise FormError('a current list returned in no known form')
        else:
            found = _fields(line, prefix, ('status', 'count')) + [None]
        count = found[1]
        if not re.fullmatch(r'0|[1-9][0-9]{0,5}', count):
            raise FormError('a count of no known form')
        if int(count) > MAX_ROWS:
            raise lab_readers.Unavailable('an impossible count: the helper prints at most %d rows' % MAX_ROWS)
        return 'OK', None, int(count), found[2]
    found = _fields(line, prefix, ('status', 'reason'))
    if found[0] not in ('ERROR', 'UNAVAILABLE') or not REASON.fullmatch(found[1]):
        raise FormError('a read status of no known form')
    if (found[0] == 'UNAVAILABLE') != (found[1] == 'service-absent'):
        raise FormError('a read status of no known form')
    return found[0], found[1], None, None


def _row(line, index):
    values = _fields(line, 'history', ('row', 'timestamp', 'pid', 'real-uid', 'package-uid', 'defining-uid', 'user',
                                       'process', 'reason', 'subreason', 'status'))
    if values[0] != str(index):
        raise FormError('a history row out of its order')
    process = values[7]
    decode_text(process)
    row = [_number(values[1], INT64), _number(values[2], INT32), _number(values[3], INT32), _number(values[4], INT32),
           _number(values[5], INT32), _number(values[6], INT32), process, _number(values[8], INT32),
           _number(values[9], INT32), _number(values[10], INT32)]
    name = decode_text(process)
    if name is not None and len(name.encode('utf-16-le')) // 2 > MAX_TEXT:
        raise FormError('a process name above its bound')
    return row


def _entry(line, index):
    values = _fields(line, 'current-errors', ('entry', 'condition', 'pid', 'uid', 'process', 'tag', 'tag-length',
                                              'short', 'short-length', 'long', 'long-length', 'stack', 'stack-length'))
    if values[0] != str(index):
        raise FormError('a current error out of its order')
    entry = [_number(values[1], INT32), _number(values[2], INT32), _number(values[3], INT32), values[4]]
    name = decode_text(values[4])
    if name is not None and len(name.encode('utf-16-le')) // 2 > MAX_TEXT:
        raise FormError('a process name above its bound')
    for token, length in zip(values[5:12:2], values[6:13:2]):
        text, whole = decode_text(token), _number(length, INT32, -1)
        units = None if text is None else len(text.encode('utf-16-le')) // 2
        # A diagnostic string is cut to its bound with its whole length, or kept whole.
        if (text is None) != (whole == -1) or (text is not None and units != min(whole, MAX_TEXT)
                                               and not (whole > MAX_TEXT and units == MAX_TEXT - 1)):
            raise FormError('a diagnostic string that is not its bounded form')
        entry += [token, whole]
    return entry


def parse_reply(code, stdout, stderr, user):
    """One whole reply of the helper for one user: {'user', 'complete', 'history', 'current',
    'sha256'}. Each part holds its status, its reason, its two samples [elapsed, wall] and its rows
    or entries, all of them; a part that is not OK holds none. A reply cut short, without its end
    marker, or whose end marker does not count and digest the lines before it, or whose count is
    impossible, is unavailable. Any other output, standard error or status has no known form."""
    if type(code) is not int or not isinstance(stdout, str) or not isinstance(stderr, str):
        raise FormError('a reply without its status and both streams')
    if len(stdout) > MAX_REPLY:
        raise lab_readers.Unavailable('a reply above its bound')
    if stderr != '' or '\r' in stdout or '\x00' in stdout or any(not ' ' <= c <= '~' for c in stdout.replace('\n', '')):
        raise FormError('a reply of no known form')
    if not stdout.endswith('\n'):
        raise lab_readers.Unavailable('a reply cut short')
    lines = stdout[:-1].split('\n')
    end = _END.fullmatch(lines[-1])
    if end is None:
        raise lab_readers.Unavailable('a reply without its end marker')
    body = stdout[:len(stdout) - len(lines[-1]) - 1]
    if int(end[1]) != len(lines) - 1 or hashlib.sha256(body.encode('ascii')).hexdigest() != end[2]:
        raise lab_readers.Unavailable('an end marker that does not count and digest the lines before it')
    head = [HEADER, 'user=%d' % _user(user), 'package=' + PACKAGE, 'capabilities=' + ','.join(CAPABILITIES)]
    if lines[:4] != head:
        raise FormError('a reply of another version, user, package or build')
    at = 4

    def take():
        nonlocal at
        if at >= len(lines) - 1:
            raise FormError('a whole reply without its parts')
        at += 1
        return lines[at - 1]
    parts = {}
    for name, prefix in (('history', 'history'), ('current', 'current-errors')):
        before = _sample(take(), prefix, 'before')
        status, reason, count, returned = _status(take(), prefix, name == 'current')
        items = []
        for index in range(count or 0):
            line = take()
            items.append(_row(line, index) if name == 'history' else _entry(line, index))
        after = _sample(take(), prefix, 'after')
        if name == 'current' and status == 'OK' and returned == 'list' and not items:
            # The service answers null for no current error, never an empty list.
            raise FormError('an empty current list, which the service never returns')
        value = {'status': status, 'reason': reason, 'samples': [before, after]}
        if name == 'history':
            value['rows'] = items
        else:
            value.update(returned=returned, entries=items)
        parts[name] = value
    complete = parts['history']['status'] == 'OK' and parts['current']['status'] == 'OK'
    if lines[at:-1] != ['status=' + ('complete' if complete else 'unavailable')] or code != (0 if complete else 5):
        raise FormError('a status that does not follow the reads')
    samples = parts['history']['samples'] + parts['current']['samples']
    if any(b[0] < a[0] for a, b in zip(samples, samples[1:])):
        raise FormError('elapsed samples that go back')
    reading = {'user': user, 'complete': complete, 'history': parts['history'], 'current': parts['current'],
               'sha256': end[2]}
    why = reading_problem(reading, user)
    if why is not None:
        raise FormError(why)
    return reading


def _int(value, bounds=INT64, low=None):
    return type(value) is int and bounds[0] <= value <= bounds[1] and (low is None or value >= low)


def _token(value):
    try:
        decode_text(value)
        return True
    except FormError:
        return False


def _samples_problem(samples):
    if (not isinstance(samples, list) or len(samples) != 2
            or any(not isinstance(s, list) or len(s) != 2 or not all(_int(v, INT64, 0) for v in s) for s in samples)
            or samples[1][0] < samples[0][0]):
        return 'a part names its two samples of elapsed and wall time'
    return None


def row_problem(row):
    """Why one history row is not of its exact form, or None."""
    if not isinstance(row, list) or len(row) != len(ROW_FIELDS):
        return 'a history row has exactly its fields'
    if not _int(row[0]) or not all(_int(v, INT32) for v in row[1:6] + row[7:]) or not _token(row[6]):
        return 'a history row of no known form'
    return None


def entry_problem(entry):
    """Why one current error entry is not of its exact form, or None."""
    if not isinstance(entry, list) or len(entry) != len(ENTRY_FIELDS):
        return 'a current error has exactly its fields'
    if not all(_int(v, INT32) for v in entry[:3]) or not _token(entry[3]):
        return 'a current error of no known form'
    for token, whole in zip(entry[4::2], entry[5::2]):
        if not _token(token) or not _int(whole, INT32, -1) or (token == '-') != (whole == -1):
            return 'a current error of no known form'
    return None


def reading_problem(reading, user=None):
    """Why a parsed reading is not of its exact form, or None: complete exactly when both parts are
    OK, a part that is not OK with its reason and no rows, every row and entry of its form."""
    if not isinstance(reading, dict) or set(reading) != set(READING_KEYS):
        return 'a reading has exactly its keys'
    if not _int(reading['user'], (0, MAX_USER)) or (user is not None and reading['user'] != user):
        return 'a reading of another user'
    if not isinstance(reading['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', reading['sha256']):
        return 'a reading names its reply digest'
    for name, keys, items, check in (('history', PART_KEYS, 'rows', row_problem),
                                     ('current', CURRENT_KEYS, 'entries', entry_problem)):
        part = reading[name]
        if not isinstance(part, dict) or set(part) != set(keys) or part['status'] not in STATUSES:
            return 'a reading part has exactly its keys'
        why = _samples_problem(part['samples'])
        if why is not None:
            return why
        if not isinstance(part[items], list) or len(part[items]) > MAX_ROWS:
            return 'a reading part lists its rows'
        if part['status'] == 'OK':
            if part['reason'] is not None:
                return 'a whole part names no reason'
            if name == 'current' and (part['returned'] not in ('null', 'list')
                                      or (part['returned'] == 'null') != (not part['entries'])):
                return 'a whole current list is null exactly when it is empty'
        elif (not isinstance(part['reason'], str) or not REASON.fullmatch(part['reason']) or part[items]
              or (name == 'current' and part['returned'] is not None)):
            return 'a part that is not whole names its reason and no rows'
        for item in part[items]:
            why = check(item)
            if why is not None:
                return why
    if reading['complete'] is not (reading['history']['status'] == 'OK' and reading['current']['status'] == 'OK'):
        return 'a reading is complete exactly when both parts are whole'
    return None


def read(run, user):
    """One reading of one user through the helper, bracketed by the shell user and the helper's
    pinned bytes, each read before and after it."""
    def admitted():
        try:
            identity = readback.shell_identity(*run(SHELL_IDENTITY))
        except ValueError as error:
            raise FormError('the shell identity of no known form') from error
        if identity != SHELL_USER:
            raise FormError('the commands do not run as the shell user')
        code, stdout, stderr = run(HELPER_DIGEST)
        try:
            digest = readback.file_digest(code, stdout, HELPER) if stderr == '' else None
        except ValueError:
            digest = None
        if digest != HELPER_SHA256:
            raise FormError('the process health helper is not the admitted bytes')
    admitted()
    reading = parse_reply(*run(command(user)), user)
    admitted()
    return reading
