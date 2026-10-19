# SPDX-License-Identifier: Apache-2.0
"""Host reader of the notice fixture's receipt provider: the strict row codec and the provider
listing parser. Host evidence only: the forms are the fixture's own and the pinned `content`
command's, from source, and need guest calibration.

A row, `andrix-notice-receipt-v1`, is the magic line and one `name=value` line for each field, in
a fixed order, in ASCII, each ending in a line feed. `encode_row` and `parse_row` are the twins of
ReceiptRow.java, and the Java host suite checks both against its goldens byte for byte.

The provider gives one whole listing per user as the `content query` command prints it: one
`Row: <n> line=<text>` line for each line of the listing. The listing's first line names the store,
the app's user, serial and UID and the store's status; then a line for each entry; then an end line
that counts the entries and digests every line before it. `parse_query` refuses every other form.
A provider that is unavailable, refused, unreadable or overflowing is never an empty store: only
ABSENT, no presentation ever wrote in this user, is a whole read with no rows.

`NoticeReader` reads every recipient user's provider for a ticket and gives the broker's row
projections (lab_broker.ROW_KEYS). It keeps every row's whole bytes: a row of no known form, or one
whose identity is not its store's, becomes a projection that the broker refuses as of no known form,
so the read is refused while every row's first bytes are still kept."""
import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
LAB = HERE.parent / 'component-lab'
if str(LAB) not in sys.path:
    sys.path.insert(0, str(LAB))

import lab_protocol  # noqa: E402
import lab_readers  # noqa: E402

MAGIC = 'andrix-notice-receipt-v1'
CANDIDATE_RULE = 'focus-then-frame-commit'
TICKET_NOTICE, QUALIFICATION = 'TICKET_NOTICE', 'QUALIFICATION'
NAMES = ('purpose', 'installation', 'component', 'plan', 'ticket', 'index', 'control', 'boot', 'text_sha256', 'event',
         'uid', 'user', 'serial', 'process_pid', 'process_start_elapsed', 'resumed_elapsed', 'focus_elapsed',
         'candidate_rule', 'candidate_elapsed')
MAX_ROW = 2048
# The public codec's ledger bound, through the lab protocol: a notice index is below it. The fixture
# app's own form takes up to 139 (Forms.MAX_LEDGER, in its pinned APK); the host route never asks
# for such an index, and this reader refuses a row or key that names one.
MAX_LEDGER = lab_protocol.MAX_LEDGER
PER_USER_RANGE = 100000
MAX_USER = (2 ** 31 - 1 - (PER_USER_RANGE - 1)) // PER_USER_RANGE
MAX_SERIAL = 2 ** 31 - 1
MAX_LONG = 2 ** 63 - 1
KEY_SUFFIX, TEMPORARY_SUFFIX = '.row', '.tmp'
STORE = 'andrix-notice-store-v1'
STATUSES = ('OK', 'ABSENT', 'UNREADABLE', 'OVERFLOW')
MAX_ENTRIES = 64
AUTHORITY = 'dev.andrix.lab.notice.receipts'
ROWS_URI = 'content://%s/rows' % AUTHORITY
QUERY = 'content query --uri ' + ROWS_URI + ' --user %d'
QUERY_FORM = re.compile(r'content query --uri ' + re.escape(ROWS_URI) + r' --user (0|[1-9][0-9]{0,4})')
# The broker's row projection keys, as lab_broker.ROW_KEYS names them.
ROW_KEYS = ('row', 'purpose', 'installation', 'component', 'plan', 'ticket', 'index', 'control', 'boot', 'text_sha256',
            'event', 'uid', 'user', 'serial', 'candidate_elapsed')
ID16 = re.compile(r'[0-9a-f]{32}')
ID32 = re.compile(r'[0-9a-f]{64}')
DECIMAL = re.compile(r'0|[1-9][0-9]{0,18}')
COMPONENT = re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')
NAME = re.compile(r'[A-Za-z0-9._]{1,200}')


class RowError(ValueError):
    """Bytes that are no row of the known form."""


def _id(value, size=16):
    return isinstance(value, str) and (ID16 if size == 16 else ID32).fullmatch(value) is not None \
        and value != '0' * (2 * size)


def _decimal(text, low, high):
    if not isinstance(text, str) or not DECIMAL.fullmatch(text):
        raise RowError('a decimal of no canonical form')
    value = int(text)
    if not low <= value <= high:
        raise RowError('a decimal out of bounds')
    return value


def check_row(fields):
    """Why a row's fields break the row's rules, or None. The same rules as ReceiptRow.java."""
    if not isinstance(fields, dict) or set(fields) != set(NAMES):
        return 'a row has exactly its fields'
    purpose = fields['purpose']
    notice = purpose == TICKET_NOTICE
    if not notice and purpose != QUALIFICATION:
        return 'a row of no known purpose'
    if not _id(fields['installation']) or not isinstance(fields['component'], str) \
            or len(fields['component']) > 255 or not COMPONENT.fullmatch(fields['component']):
        return 'a row names its installation and component'
    integers = ('index', 'uid', 'user', 'serial', 'process_pid', 'process_start_elapsed', 'resumed_elapsed',
                'focus_elapsed', 'candidate_elapsed')
    if any(fields[k] is not None and type(fields[k]) is not int for k in integers):
        return 'row numbers are integers'
    if notice != (fields['plan'] is not None) or notice != (fields['ticket'] is not None) \
            or notice != (fields['index'] is not None) or notice == (fields['control'] is not None):
        return 'a row names a notice or a control, not both'
    if notice and (not _id(fields['plan']) or not _id(fields['ticket']) or not 0 <= fields['index'] < MAX_LEDGER):
        return 'a notice row names its plan, ticket and index'
    if not notice and not _id(fields['control']):
        return 'a qualification row names its control'
    if not _id(fields['boot']) or not _id(fields['event']) or not _id(fields['text_sha256'], 32):
        return 'a row names its boot, event and text digest'
    uid, user = fields['uid'], fields['user']
    if uid is None or user is None or not 0 <= uid <= 2 ** 31 - 1 or not 10000 <= uid % PER_USER_RANGE <= 19999 \
            or uid // PER_USER_RANGE != user or not 0 <= user <= MAX_USER:
        return 'a row names an application UID of its user'
    if fields['serial'] is None or not 0 <= fields['serial'] <= MAX_SERIAL:
        return 'a row names its serial'
    if fields['process_pid'] is None or not 1 <= fields['process_pid'] <= 2 ** 31 - 1:
        return 'a row names its process'
    times = [fields[k] for k in ('process_start_elapsed', 'resumed_elapsed', 'focus_elapsed', 'candidate_elapsed')]
    if any(t is None or not 0 <= t <= MAX_LONG for t in times) or times != sorted(times):
        return 'row times are ordered: process start, resume, focus, candidate'
    if fields['candidate_rule'] != CANDIDATE_RULE:
        return 'a row of another candidate rule'
    return None


def encode_row(fields):
    """The exact bytes of a row's fields, or RowError."""
    problem = check_row(fields)
    if problem is not None:
        raise RowError(problem)
    lines = [MAGIC] + ['%s=%s' % (name, '-' if fields[name] is None else fields[name]) for name in NAMES]
    data = ('\n'.join(lines) + '\n').encode('ascii')
    if len(data) > MAX_ROW:
        raise RowError('a row above its bound')
    return data


def parse_row(data):
    """The fields of exactly these bytes, or RowError: any other form is no row."""
    if not isinstance(data, (bytes, bytearray)) or not 1 <= len(data) <= MAX_ROW:
        raise RowError('a row is 1 to %d bytes' % MAX_ROW)
    data = bytes(data)
    if any(b != 0x0a and not 0x20 <= b <= 0x7e for b in data) or not data.endswith(b'\n'):
        raise RowError('a row is printable ASCII lines')
    lines = data[:-1].decode('ascii').split('\n')
    if len(lines) != len(NAMES) + 1 or lines[0] != MAGIC:
        raise RowError('a row has the magic line and one line for each field')
    values = {}
    for name, line in zip(NAMES, lines[1:]):
        if not line.startswith(name + '='):
            raise RowError('row field %s out of place' % name)
        values[name] = line[len(name) + 1:]
    notice = values['purpose'] == TICKET_NOTICE
    fields = {}
    for name, text in values.items():
        if name in ('index', 'uid', 'user', 'serial', 'process_pid', 'process_start_elapsed', 'resumed_elapsed',
                    'focus_elapsed', 'candidate_elapsed'):
            fields[name] = None if text == '-' and name == 'index' and not notice else _decimal(text, 0, MAX_LONG)
        elif name in ('plan', 'ticket', 'control') and text == '-':
            fields[name] = None
        else:
            fields[name] = text
    problem = check_row(fields)
    if problem is not None:
        raise RowError(problem)
    if encode_row(fields) != data:
        raise RowError('a row not in its canonical form')
    return fields


def row_key(fields):
    """The immutable key of a row, which is also its file name."""
    if fields['purpose'] == TICKET_NOTICE:
        parts = (fields['purpose'], fields['installation'], fields['boot'], fields['ticket'], str(fields['index']),
                 str(fields['user']), str(fields['serial']))
    else:
        parts = (fields['purpose'], fields['installation'], fields['boot'], fields['control'], str(fields['user']),
                 str(fields['serial']))
    return '.'.join(parts) + KEY_SUFFIX


def key_name(name):
    """Whether a file name has the form of a key."""
    if not isinstance(name, str) or not name.endswith(KEY_SUFFIX) or len(name) > 200:
        return False
    parts = name[:-len(KEY_SUFFIX)].split('.')
    notice = len(parts) == 7 and parts[0] == TICKET_NOTICE
    if not notice and not (len(parts) == 6 and parts[0] == QUALIFICATION):
        return False
    if not all(_id(p) for p in parts[1:4]):
        return False
    bounds = ([MAX_LEDGER - 1] if notice else []) + [MAX_USER, MAX_SERIAL]
    for text, high in zip(parts[4:], bounds):
        if not DECIMAL.fullmatch(text) or int(text) > high:
            return False
    return True


def temporary_name(name):
    """Whether a file name has the form of a writer's temporary: a dot, a key, a nonce, '.tmp'."""
    if not isinstance(name, str) or not name.startswith('.') or not name.endswith(TEMPORARY_SUFFIX):
        return False
    body = name[1:-len(TEMPORARY_SUFFIX)]
    key, _, nonce = body.rpartition('.')
    return bool(re.fullmatch(r'[0-9a-f]{16}', nonce)) and nonce != '0' * 16 and key_name(key)


# ------------------------------------------------------------------ the provider listing


def listing_lines(user, serial, uid, status, entries):
    """The provider's listing lines for a store: the twin of ReceiptStore.list, for host fakes. Each
    entry is (kind, name, data or None, reason or None) in name order."""
    lines = ['%s user=%d serial=%d uid=%d status=%s' % (STORE, user, serial, uid, status)]
    counts = {'row': 0, 'corrupt': 0, 'partial': 0}
    for kind, name, data, reason in (entries if status == 'OK' else ()):
        if data is None:
            body = '- - -'
        else:
            body = '%d %s %s' % (len(data), hashlib.sha256(data).hexdigest(), data.hex() if data else '-')
        lines.append(' '.join(p for p in (kind, name, body, reason if kind == 'corrupt' else None) if p is not None))
        counts[kind] += 1
    digest = hashlib.sha256(''.join(line + '\n' for line in lines).encode('ascii')).hexdigest()
    lines.append('end rows=%d corrupt=%d partial=%d listing=%s' % (counts['row'], counts['corrupt'],
                                                                   counts['partial'], digest))
    return lines


def query_output(lines):
    """What the pinned `content query` command prints for a cursor of these listing lines."""
    return ''.join('Row: %d line=%s\n' % (number, line) for number, line in enumerate(lines))


HEADER = re.compile(r'%s user=(0|[1-9][0-9]*) serial=(0|[1-9][0-9]*) uid=(0|[1-9][0-9]*) status=([A-Z]+)'
                    % re.escape(STORE))
ENTRY = re.compile(r'(row|partial|corrupt) (\S+) (?:(0|[1-9][0-9]*) ([0-9a-f]{64}) (-|[0-9a-f]+)|- - -)'
                   r'(?: ([a-z-]+))?')
END = re.compile(r'end rows=(0|[1-9][0-9]*) corrupt=(0|[1-9][0-9]*) partial=(0|[1-9][0-9]*) '
                 r'listing=([0-9a-f]{64})')
CORRUPT_REASONS = ('unparseable', 'key', 'identity', 'not-regular', 'oversize', 'unknown-name')


def parse_listing(lines):
    """The whole listing of one provider read, strictly: {'user', 'serial', 'uid', 'status',
    'entries'}, each entry {'kind', 'name', 'data', 'reason'}. Raises lab_readers.Unclassified for
    any other form."""
    def refuse(why):
        raise lab_readers.Unclassified('a provider listing of no known form: %s' % why)
    if not isinstance(lines, list) or not 2 <= len(lines) <= MAX_ENTRIES + 2:
        refuse('a header, at most %d entries and an end' % MAX_ENTRIES)
    head = HEADER.fullmatch(lines[0])
    if head is None or head[4] not in STATUSES:
        refuse('its header')
    out = {'user': int(head[1]), 'serial': int(head[2]), 'uid': int(head[3]), 'status': head[4], 'entries': []}
    counts = {'row': 0, 'corrupt': 0, 'partial': 0}
    names = []
    for line in lines[1:-1]:
        m = ENTRY.fullmatch(line)
        if m is None:
            refuse('an entry line')
        kind, name, size, digest, data, reason = m.groups()
        if (kind == 'corrupt') != (reason is not None) or (reason is not None and reason not in CORRUPT_REASONS):
            refuse('an entry reason')
        if size is None:
            if kind != 'corrupt' or reason not in ('not-regular', 'oversize', 'unknown-name'):
                refuse('an entry without bytes')
            raw = None
        else:
            raw = b'' if data == '-' else bytes.fromhex(data)
            if (data == '-') != (int(size) == 0) or len(raw) != int(size) or len(raw) > MAX_ROW \
                    or hashlib.sha256(raw).hexdigest() != digest:
                refuse('an entry whose bytes are not its size and digest')
        # A row names its key and a partial write its temporary. A corrupt entry names a key, a
        # temporary that is no regular file or too large, or an unknown name by its bytes.
        if reason == 'unknown-name':
            if not re.fullmatch(r'unknown:(?:[0-9a-f]{2})+', name):
                refuse('an unknown name')
        elif kind == 'partial':
            if not temporary_name(name):
                refuse('a partial write that names no temporary')
        elif not key_name(name) and not (kind == 'corrupt' and temporary_name(name)
                                         and reason in ('not-regular', 'oversize')):
            refuse('an entry name of another form than its kind')
        if kind == 'row' and parse_quietly(raw) is None:
            refuse('a row entry whose bytes are no row')
        names.append(_original(name))
        counts[kind] += 1
        out['entries'].append({'kind': kind, 'name': name, 'data': raw, 'reason': reason})
    # The store sorts by each file's own name as Java orders strings, by UTF-16 code units.
    order = [name.encode('utf-16-be', 'surrogatepass') for name in names]
    if order != sorted(order) or len(set(names)) != len(names):
        refuse('entries out of name order or twice')
    if out['status'] != 'OK' and out['entries']:
        refuse('entries beside a status that has none')
    end = END.fullmatch(lines[-1])
    if end is None:
        refuse('its end line')
    digest = hashlib.sha256(''.join(line + '\n' for line in lines[:-1]).encode('ascii')).hexdigest()
    if (int(end[1]), int(end[2]), int(end[3])) != (counts['row'], counts['corrupt'], counts['partial']) \
            or end[4] != digest:
        refuse('its end does not count and digest the lines before it')
    return out


def _original(name):
    """A listed name as the store's file name: an unknown name is listed by its UTF-8 bytes."""
    if name.startswith('unknown:'):
        return bytes.fromhex(name[len('unknown:'):]).decode('utf-8', 'surrogateescape')
    return name


def parse_quietly(data):
    try:
        return parse_row(data)
    except RowError:
        return None


def parse_query(code, stdout, stderr):
    """The listing lines of one whole `content query` reply. Raises lab_readers.Unavailable when
    the command reported an error, and lab_readers.Unclassified for any other form, including
    'No result found.', which this provider never gives to the shell user."""
    if stderr:
        first = stderr.splitlines()[0] if stderr.splitlines() else ''
        raise lab_readers.Unavailable('the provider read failed: %s' % first[:200])
    if code != 0:
        raise lab_readers.Unclassified('the content command exited %r without an error line' % code)
    if stdout == 'No result found.\n':
        raise lab_readers.Unclassified('the provider gave no listing, which is never an empty store')
    if not stdout.endswith('\n'):
        raise lab_readers.Unclassified('a cut provider reply')
    lines = []
    for number, text in enumerate(stdout[:-1].split('\n')):
        prefix = 'Row: %d line=' % number
        if not text.startswith(prefix):
            raise lab_readers.Unclassified('a provider reply line of no known form')
        lines.append(text[len(prefix):])
    return lines


# ------------------------------------------------------------------ the broker's projections


def no_form(data):
    """A projection that the broker refuses as of no known form, keeping the row's bytes."""
    return dict({k: None for k in ROW_KEYS}, row=data)


def projection(fields, data):
    return dict({k: fields[k] for k in ROW_KEYS if k != 'row'}, row=data)


def store_read(code, stdout, stderr, user, serial):
    """One user's whole provider read: its listing and the broker projections of its rows. A store
    that is unreadable or overflowing raises lab_readers.Unavailable; a listing of another user,
    serial or app UID raises Unclassified. A corrupt entry, or a row whose fields are not its
    store's user and serial, is projected as of no known form with its bytes kept."""
    listing = parse_listing(parse_query(code, stdout, stderr))
    if (listing['user'], listing['serial']) != (user, serial):
        raise lab_readers.Unclassified('the provider listing is of user %d serial %d, not of user %d serial %d'
                                       % (listing['user'], listing['serial'], user, serial))
    uid = listing['uid']
    if uid // PER_USER_RANGE != user or not 10000 <= uid % PER_USER_RANGE <= 19999:
        raise lab_readers.Unclassified('the provider listing names no application UID of its user')
    if listing['status'] in ('UNREADABLE', 'OVERFLOW'):
        raise lab_readers.Unavailable('the receipt store is %s: never an empty store' % listing['status'].lower())
    rows = []
    for entry in listing['entries']:
        if entry['kind'] == 'partial':
            continue
        data = entry['data']
        if entry['kind'] == 'corrupt':
            rows.append(no_form(data))
            continue
        fields = parse_row(data)
        if (fields['uid'], fields['user'], fields['serial']) != (uid, user, serial) or row_key(fields) != entry['name']:
            rows.append(dict(projection(fields, data), uid=None, user=None, serial=None))
            continue
        rows.append(projection(fields, data))
    return {'listing': listing, 'rows': rows}


class NoticeReader:
    """The receipt reader of one installation. `recipients(ticket)` gives the (user, serial)
    pairs whose providers one whole read covers: the recipients of the ticket's issued notices.
    The broker binds its run function, which returns (exit, stdout, stderr) only for a whole
    capture and raises otherwise."""

    def __init__(self, recipients):
        self._recipients = recipients
        self._run = None
        # The whole listings of the latest read, for the composing adapter or closure to keep.
        self.last_reads = []

    def allowed(self, command):
        return QUERY_FORM.fullmatch(command) is not None

    def bind(self, run):
        self._run = run

    def receipt_rows(self, ticket):
        """Every row of every recipient's store, in user order; the broker judges them."""
        if self._run is None:
            raise lab_readers.Unavailable('no group is open')
        pairs = sorted(set(self._recipients(ticket)))
        if len({user for user, _ in pairs}) != len(pairs):
            raise lab_readers.Unclassified('one user with two serials among the recipients')
        rows, self.last_reads = [], []
        for user, serial in pairs:
            code, stdout, stderr = self._run(QUERY % user)
            read = store_read(code, stdout, stderr, user, serial)
            self.last_reads.append(read['listing'])
            rows.extend(read['rows'])
        return rows
