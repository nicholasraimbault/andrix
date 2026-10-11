# SPDX-License-Identifier: Apache-2.0
"""Version 1 of the lab bridge protocol: the typed frames between the Java bridge and the broker.

The bridge, inside one coordinator JVM, sends requests. The broker, which owns the guest commands,
the capture ledger and the fault schedule, answers each with exactly one reply. There is no shell
text in a request: each type has fixed typed fields, and the broker alone builds every guest
command from them. README.md in this directory states the layout normatively. The Java codec in
`java/dev/andrix/lab/component/LabProtocol.java` implements the same layout, and the goldens in
`tests/test_lab_protocol.py` bind the two.

Frame, little endian:

    u32  magic      0x424c5841, "AXLB" in file order
    u16  version    1
    u16  type       odd for a request, the request's type plus one for its reply
    u32  length     of the whole frame, checksum included
    id   request    16 bytes, nonzero, fresh for each request; a reply repeats it
    d32  manifest   32 bytes, the admitted source manifest digest, nonzero
         body       the type's fields, in order
    d32  checksum   SHA-256 of every preceding byte

Decoding checks the size, magic, version, type, length and checksum first, then every field's
bound, the absence of trailing bytes and every relation of the type. It never repairs input. Every
valid message has exactly one encoding."""
import hashlib
import re
import struct

MAGIC = 0x424c5841
VERSION = 1
HEADER = 60
CHECKSUM = 32
MIN_FRAME = HEADER + CHECKSUM
MAX_FRAME = 4 * 1024 * 1024
MAX_TEXT = 1024
MAX_STAGE_DIR = 255
MAX_RECORD = 65536
MAX_FRAMES = 256
MAX_LEDGER = 140
ZERO_ID = '00' * 16
ZERO_DIGEST = '00' * 32
NO_USER = -10000

TYPES = {'HELLO': 1, 'HELLO_REPLY': 2, 'CLOCK': 3, 'CLOCK_REPLY': 4, 'OBSERVE': 5, 'OBSERVE_REPLY': 6,
         'CROSS': 7, 'CROSS_REPLY': 8, 'POINT': 9, 'POINT_REPLY': 10, 'HOST': 11, 'HOST_REPLY': 12,
         'REPORT': 13, 'REPORT_REPLY': 14}
TYPE_NAMES = {code: name for name, code in TYPES.items()}
STATUSES = {'OK': 1, 'UNAVAILABLE': 2, 'STOPPED': 3, 'HALT': 4, 'WITHHELD': 5, 'NO_REPLY': 6, 'REFUSED': 7}
STATUS_NAMES = {code: name for name, code in STATUSES.items()}
# The deployment records' crossing codes and ledger bounds.
CROSSINGS = {'SIGN': (1, 2), 'PUBLISH': (2, 2), 'CREATE': (3, 1), 'WRITE': (4, 1), 'COMMIT': (5, 1),
             'ABANDON': (6, 16), 'REBOOT': (7, 16), 'NOTICE': (8, 17), 'HANDOVER': (9, 4)}
CROSSING_NAMES = {code: name for name, (code, _) in CROSSINGS.items()}
DEVICE_CROSSINGS = ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'REBOOT', 'NOTICE')
FRAMEWORK_CROSSINGS = ('CREATE', 'WRITE', 'COMMIT', 'ABANDON')
GRANTED = ('CREATE', 'COMMIT', 'REBOOT', 'NOTICE')
# The crossings under an ACTIVATE grant, whose validity the broker checks again at launch.
ACTIVATED = ('COMMIT', 'REBOOT', 'NOTICE')
HOST_CROSSINGS = {'SIGN': 1, 'PUBLISH': 2}
HOST_PHASES = {'BEGIN': 1, 'END': 2}
HOST_OUTCOMES = {'NONE': 0, 'REPLY': 1, 'NULL': 2, 'THREW': 3}
SCOPES = {'COMPONENT': 1, 'TICKET': 2}
TARGETS = {'ESTABLISHED_EMPTY': 1, 'HELD': 2, 'UNKNOWN': 3}
ACTORS = {'NONE': 0, 'GRANT_HOLDER': 1, 'LAB_OPERATOR': 2}
ROUTE_SHELL = 1
# The coordinator's only lab point, Coordinator.BETWEEN_WRITES.
POINTS = ('selection-written',)
STATE_COUNT = 28
# Reference presence bits, as the deployment records define them.
SESSION, CREATED, STAGE_DIR, INSTALLER, NONCE = 1, 2, 4, 8, 16
BOUND_REFERENCE = SESSION | CREATED | INSTALLER | NONCE
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')

# Each type's body fields, in order. Kinds: u8, u16, u32, i32, i64 integers, id 16 bytes, d32 32
# bytes, text, blob, ref (a reference block), frames (group and record pairs), codes (u8 list).
BODIES = {
    'HELLO': (('installation', 'id'), ('coordinator', 'id'), ('config', 'd32'), ('component', 'text'),
              ('trust', 'd32'), ('route', 'u8')),
    'HELLO_REPLY': (('status', 'u8'), ('generation', 'u32'), ('target', 'u8'), ('reason', 'text')),
    'CLOCK': (),
    'CLOCK_REPLY': (('status', 'u8'), ('boot', 'id'), ('instance', 'i64'), ('elapsed', 'i64'), ('wall', 'i64'),
                    ('group', 'u32'), ('reason', 'text')),
    'OBSERVE': (('scope', 'u8'), ('component', 'text'), ('boot', 'id'), ('ticket', 'id'), ('plan', 'id'),
                ('state', 'u8')),
    'OBSERVE_REPLY': (('status', 'u8'), ('frames', 'frames'), ('reason', 'text')),
    'CROSS': (('ticket', 'id'), ('ticket_digest', 'd32'), ('plan', 'id'), ('plan_digest', 'd32'),
              ('attempt', 'i32'), ('component', 'text'), ('index', 'u16'), ('crossing', 'u8'),
              ('occurrence', 'u16'), ('entry_boot', 'id'), ('entry_instance', 'i64'), ('entry_elapsed', 'i64'),
              ('grant', 'id'), ('reference', 'id'), ('native', 'ref'), ('bundle_apk', 'd32'), ('actor', 'u8'),
              ('granted', 'i64'), ('window', 'i64')),
    'CROSS_REPLY': (('status', 'u8'), ('record', 'u32'), ('frame', 'blob'), ('reason', 'text')),
    'POINT': (('point', 'text'), ('ticket', 'id'), ('plan', 'id'), ('attempt', 'i32')),
    'POINT_REPLY': (('status', 'u8'), ('record', 'u32'), ('reason', 'text')),
    'HOST': (('phase', 'u8'), ('crossing', 'u8'), ('ticket', 'id'), ('plan', 'id'), ('attempt', 'i32'),
             ('index', 'u16'), ('occurrence', 'u16'), ('reference', 'id'), ('outcome', 'u8'), ('reply', 'd32')),
    'HOST_REPLY': (('status', 'u8'), ('record', 'u32'), ('reason', 'text')),
    'REPORT': (('ticket', 'id'), ('state', 'u8'), ('flags', 'u8'), ('cause', 'u8'), ('ledger', 'codes'),
               ('note', 'text')),
    'REPORT_REPLY': (('status', 'u8'), ('record', 'u32'), ('reason', 'text')),
}
INTEGERS = {'u8': '<B', 'u16': '<H', 'u32': '<I', 'i32': '<i', 'i64': '<q'}


class ProtocolError(ValueError):
    """A frame or message that breaks a rule of the protocol. Nothing is repaired."""


def _fail(reason):
    raise ProtocolError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fresh_id(source):
    """A nonzero 16 byte ID as 32 hexadecimal digits from `source(16)`, such as os.urandom."""
    while True:
        value = source(16).hex()
        if value != ZERO_ID:
            return value


# ---------------------------------------------------------------- primitive checks

def _hex(value, width, name, zero_allowed=True):
    if not isinstance(value, str) or len(value) != 2 * width or not re.fullmatch(r'[0-9a-f]+', value):
        _fail('%s is not %d lowercase hexadecimal bytes' % (name, width))
    if not zero_allowed and value == '00' * width:
        _fail('%s is zero' % name)


def _text(value, name, limit=MAX_TEXT):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 0x20 or ord(c) > 0x7e for c in value):
        _fail('%s is not printable ASCII of at most %d bytes' % (name, limit))


def _int(value, kind, name):
    if not isinstance(value, int) or isinstance(value, bool):
        _fail('%s is not an integer' % name)
    bits = {'u8': (0, 0xff), 'u16': (0, 0xffff), 'u32': (0, 0xffffffff), 'i32': (-(1 << 31), (1 << 31) - 1),
            'i64': (-(1 << 63), (1 << 63) - 1)}[kind]
    if not bits[0] <= value <= bits[1]:
        _fail('%s is outside %s' % (name, kind))


def check_package(value, name='component'):
    _text(value, name, 255)
    if not PACKAGE.fullmatch(value):
        _fail('%s is not a package name' % name)


def check_reference(ref, name='native'):
    """A reference block as the deployment records define it: presence bits, then each field set
    exactly when its bit is."""
    if not isinstance(ref, tuple) or len(ref) != 6:
        _fail('%s is not a reference' % name)
    presence, session, created, stage, installer, nonce = ref
    _int(presence, 'u8', name + ' presence')
    if presence & ~31:
        _fail('%s has unknown presence bits' % name)
    _int(session, 'i32', name + ' session')
    _int(created, 'i64', name + ' created')
    _int(installer, 'i32', name + ' installer')
    _hex(nonce, 16, name + ' nonce')
    if (session > 0) != bool(presence & SESSION) or (not presence & SESSION and session != 0):
        _fail('%s session and its presence differ' % name)
    if presence & CREATED and created < 0 or not presence & CREATED and created != 0:
        _fail('%s createdMillis and its presence differ' % name)
    if presence & STAGE_DIR:
        _text(stage, name + ' stage directory', MAX_STAGE_DIR)
        if not stage:
            _fail('%s stage directory is empty' % name)
    elif stage != '':
        _fail('%s stage directory and its presence differ' % name)
    if presence & INSTALLER and installer < 0 or not presence & INSTALLER and installer != 0:
        _fail('%s installer and its presence differ' % name)
    if bool(presence & NONCE) == (nonce == ZERO_ID):
        _fail('%s nonce and its presence differ' % name)


NO_REFERENCE = (0, 0, 0, '', 0, ZERO_ID)


# ---------------------------------------------------------------- relations of each type

def _status(message, allowed):
    """The reply's status among those its type allows. REFUSED answers a request that breaks the
    protocol or the admission, in every reply type."""
    status = message['status']
    if status not in (STATUSES[name] for name in allowed + ('REFUSED',)):
        _fail('status %r is not allowed in %s' % (status, message['type']))
    ok = status == STATUSES['OK']
    if ok != (message['reason'] == ''):
        _fail('a reason exactly when the status is not OK')
    return STATUS_NAMES[status]


def _relations(m):
    kind = m['type']
    if kind == 'HELLO':
        for name in ('installation', 'coordinator'):
            _hex(m[name], 16, name, False)
        _hex(m['config'], 32, 'config', False)
        _hex(m['trust'], 32, 'trust', False)
        check_package(m['component'])
        if m['route'] != ROUTE_SHELL:
            _fail('the lab bridge has only the shell route')
    elif kind == 'HELLO_REPLY':
        status = _status(m, ('OK', 'STOPPED'))
        if (status == 'OK') != (m['generation'] >= 1):
            _fail('a generation exactly with OK')
        if status == 'OK' and m['target'] not in TARGETS.values() or status != 'OK' and m['target'] != 0:
            _fail('a target scope exactly with OK')
    elif kind == 'CLOCK_REPLY':
        status = _status(m, ('OK', 'UNAVAILABLE', 'STOPPED'))
        if status == 'OK':
            _hex(m['boot'], 16, 'boot', False)
            if m['instance'] < -1 or m['elapsed'] < 0 or m['group'] < 1:
                _fail('a clock reading outside its bounds')
        elif (m['boot'], m['instance'], m['elapsed'], m['wall']) != (ZERO_ID, 0, 0, 0):
            _fail('a reading without OK')
        if status in ('STOPPED', 'REFUSED') and m['group'] != 0:
            _fail('a stopped or refused clock read nothing')
    elif kind == 'OBSERVE':
        check_package(m['component'])
        _hex(m['boot'], 16, 'boot', False)
        if m['scope'] == SCOPES['COMPONENT']:
            if (m['ticket'], m['plan'], m['state']) != (ZERO_ID, ZERO_ID, 0):
                _fail('a component observation names no ticket')
        elif m['scope'] == SCOPES['TICKET']:
            _hex(m['ticket'], 16, 'ticket', False)
            _hex(m['plan'], 16, 'plan', False)
            if not 1 <= m['state'] <= STATE_COUNT:
                _fail('a ticket state outside 1..%d' % STATE_COUNT)
        else:
            _fail('an unknown observation scope')
    elif kind == 'OBSERVE_REPLY':
        status = _status(m, ('OK', 'STOPPED'))
        if status != 'OK' and m['frames']:
            _fail('frames only with OK')
        for group, frame in m['frames']:
            if group < 1 or not 1 <= len(frame) <= MAX_RECORD:
                _fail('a frame without its group or outside the record bound')
    elif kind == 'CROSS':
        _cross_relations(m)
    elif kind == 'CROSS_REPLY':
        status = _status(m, ('OK', 'NO_REPLY', 'WITHHELD', 'HALT', 'STOPPED'))
        if (status == 'OK') != bool(m['frame']):
            _fail('a reply frame exactly with OK')
        if len(m['frame']) > MAX_RECORD:
            _fail('a reply frame outside the record bound')
        if status in ('OK', 'NO_REPLY', 'WITHHELD', 'HALT') and m['record'] < 1:
            _fail('a crossing outcome names its record')
    elif kind == 'POINT':
        if m['point'] not in POINTS:
            _fail('an unknown lab point')
        _hex(m['ticket'], 16, 'ticket', False)
        _hex(m['plan'], 16, 'plan', False)
        if m['attempt'] < 1:
            _fail('an attempt below 1')
    elif kind == 'POINT_REPLY':
        status = _status(m, ('OK', 'HALT'))
        if (status == 'HALT') != (m['record'] >= 1):
            _fail('a fault record exactly with HALT')
    elif kind == 'HOST':
        if m['phase'] not in HOST_PHASES.values() or m['crossing'] not in HOST_CROSSINGS.values():
            _fail('an unknown host phase or crossing')
        _hex(m['ticket'], 16, 'ticket', False)
        _hex(m['plan'], 16, 'plan', False)
        _hex(m['reference'], 16, 'reference', False)
        if m['attempt'] < 1 or m['index'] >= MAX_LEDGER or not 1 <= m['occurrence'] <= 2:
            _fail('a host call outside its bounds')
        if m['phase'] == HOST_PHASES['BEGIN']:
            if m['outcome'] != 0 or m['reply'] != ZERO_DIGEST:
                _fail('a host call begins without an outcome')
        else:
            if m['outcome'] not in (1, 2, 3):
                _fail('an unknown host outcome')
            if (m['outcome'] == HOST_OUTCOMES['REPLY']) != (m['reply'] != ZERO_DIGEST):
                _fail('a reply digest exactly when the host replied')
    elif kind == 'HOST_REPLY':
        status = _status(m, ('OK', 'HALT', 'WITHHELD'))
        if status != 'REFUSED' and m['record'] < 1:
            _fail('a host outcome names its record')
    elif kind == 'REPORT':
        _hex(m['ticket'], 16, 'ticket', False)
        if not 1 <= m['state'] <= STATE_COUNT or m['flags'] & ~7 or m['cause'] > 6:
            _fail('a report outside the ticket codes')
        if any(code not in CROSSING_NAMES for code in m['ledger']):
            _fail('a report names an unknown crossing')
    elif kind == 'REPORT_REPLY':
        if _status(m, ('OK',)) == 'OK' and m['record'] < 1:
            _fail('a report names its record')


def _cross_relations(m):
    for name in ('ticket', 'plan', 'entry_boot'):
        _hex(m[name], 16, name, False)
    for name in ('ticket_digest', 'plan_digest'):
        _hex(m[name], 32, name, False)
    check_package(m['component'])
    if m['attempt'] < 1:
        _fail('an attempt below 1')
    name = CROSSING_NAMES.get(m['crossing'])
    if name not in DEVICE_CROSSINGS:
        _fail('not a device crossing')
    if m['index'] >= MAX_LEDGER or not 1 <= m['occurrence'] <= min(CROSSINGS[name][1], m['index'] + 1):
        _fail('an entry index or occurrence outside the ledger bounds')
    framework = name in FRAMEWORK_CROSSINGS
    if m['entry_instance'] < (0 if framework else -1) or m['entry_elapsed'] < 0:
        _fail('an entry instance or elapsed time outside its bounds')
    if (name in GRANTED) == (m['grant'] == ZERO_ID):
        _fail('a grant exactly for CREATE, COMMIT, REBOOT and NOTICE')
    if (m['actor'] != 0) != (m['grant'] != ZERO_ID) or m['actor'] not in ACTORS.values():
        _fail('an actor class exactly with a grant')
    if name in ACTIVATED:
        if m['granted'] < 1 or m['window'] < 1:
            _fail("an ACTIVATE crossing carries its grant's time and the plan's activation window")
    elif (m['granted'], m['window']) != (0, 0):
        _fail('a grant time and window exactly for COMMIT, REBOOT and NOTICE')
    if (name == 'CREATE') == (m['reference'] == ZERO_ID):
        _fail('an entry reference exactly for CREATE')
    check_reference(m['native'])
    presence = m['native'][0]
    if name == 'CREATE' and (presence != NONCE or m['native'][5] != m['reference']):
        _fail("CREATE carries exactly the ticket's nonce")
    if name in ('WRITE', 'COMMIT', 'ABANDON') and presence & BOUND_REFERENCE != BOUND_REFERENCE:
        _fail('a session crossing needs the session with its createdMillis, installer and nonce')
    if (name == 'WRITE') == (m['bundle_apk'] == ZERO_DIGEST):
        _fail("the bundle's APK digest exactly for WRITE")


# ---------------------------------------------------------------- encoding

def _encode_field(kind, value, name):
    if kind in INTEGERS:
        _int(value, kind, name)
        return struct.pack(INTEGERS[kind], value)
    if kind == 'id':
        _hex(value, 16, name)
        return bytes.fromhex(value)
    if kind == 'd32':
        _hex(value, 32, name)
        return bytes.fromhex(value)
    if kind == 'text':
        _text(value, name)
        return struct.pack('<H', len(value)) + value.encode('ascii')
    if kind == 'blob':
        if not isinstance(value, (bytes, bytearray)) or len(value) > MAX_RECORD:
            _fail('%s is not bytes within the record bound' % name)
        return struct.pack('<I', len(value)) + bytes(value)
    if kind == 'ref':
        check_reference(value, name)
        presence, session, created, stage, installer, nonce = value
        return (struct.pack('<Biq', presence, session, created) + struct.pack('<H', len(stage)) + stage.encode('ascii')
                + struct.pack('<i', installer) + bytes.fromhex(nonce))
    if kind == 'frames':
        if not isinstance(value, list) or len(value) > MAX_FRAMES:
            _fail('%s holds more than %d frames' % (name, MAX_FRAMES))
        out = struct.pack('<H', len(value))
        for group, frame in value:
            out += _encode_field('u32', group, name + ' group') + _encode_field('blob', frame, name + ' frame')
        return out
    if kind == 'codes':
        if not isinstance(value, list) or len(value) > MAX_LEDGER:
            _fail('%s holds more than %d codes' % (name, MAX_LEDGER))
        return struct.pack('<H', len(value)) + b''.join(_encode_field('u8', code, name) for code in value)
    raise AssertionError(kind)


def encode(message):
    """The one encoding of a valid message: a dict with 'type', 'request', 'manifest' and the
    type's body fields."""
    kind = message.get('type')
    if kind not in TYPES:
        _fail('an unknown message type')
    names = {'type', 'request', 'manifest'} | {name for name, _ in BODIES[kind]}
    if set(message) != names:
        _fail('the fields of %s are not exactly its layout' % kind)
    _hex(message['request'], 16, 'request', False)
    _hex(message['manifest'], 32, 'manifest', False)
    _relations(message)
    body = b''.join(_encode_field(field, message[name], name) for name, field in BODIES[kind])
    length = HEADER + len(body) + CHECKSUM
    if length > MAX_FRAME:
        _fail('a frame above the frame bound')
    head = struct.pack('<IHHI', MAGIC, VERSION, TYPES[kind], length) + bytes.fromhex(message['request'])
    head += bytes.fromhex(message['manifest'])
    data = head + body
    return data + hashlib.sha256(data).digest()


# ---------------------------------------------------------------- decoding

class _Reader:
    def __init__(self, data, end):
        self.data, self.at, self.end = data, HEADER, end

    def take(self, count, name):
        if count < 0 or self.at + count > self.end:
            _fail('%s runs past the body' % name)
        value = self.data[self.at:self.at + count]
        self.at += count
        return value

    def field(self, kind, name):
        if kind in INTEGERS:
            return struct.unpack(INTEGERS[kind], self.take(struct.calcsize(INTEGERS[kind]), name))[0]
        if kind == 'id':
            return self.take(16, name).hex()
        if kind == 'd32':
            return self.take(32, name).hex()
        if kind == 'text':
            raw = self.take(self.field('u16', name + ' length'), name)
            if len(raw) > MAX_TEXT or any(b < 0x20 or b > 0x7e for b in raw):
                _fail('%s is not printable ASCII within its bound' % name)
            return raw.decode('ascii')
        if kind == 'blob':
            size = self.field('u32', name + ' length')
            if size > MAX_RECORD:
                _fail('%s is above the record bound' % name)
            return self.take(size, name)
        if kind == 'ref':
            presence = self.field('u8', name)
            session = self.field('i32', name)
            created = self.field('i64', name)
            raw = self.take(self.field('u16', name), name)
            if len(raw) > MAX_STAGE_DIR or any(b < 0x20 or b > 0x7e for b in raw):
                _fail('%s stage directory is not printable ASCII within its bound' % name)
            installer = self.field('i32', name)
            nonce = self.field('id', name)
            value = (presence, session, created, raw.decode('ascii'), installer, nonce)
            check_reference(value, name)
            return value
        if kind == 'frames':
            count = self.field('u16', name)
            if count > MAX_FRAMES:
                _fail('%s holds more than %d frames' % (name, MAX_FRAMES))
            return [(self.field('u32', name), self.field('blob', name)) for _ in range(count)]
        if kind == 'codes':
            count = self.field('u16', name)
            if count > MAX_LEDGER:
                _fail('%s holds more than %d codes' % (name, MAX_LEDGER))
            return [self.field('u8', name) for _ in range(count)]
        raise AssertionError(kind)


def frame_length(header):
    """The whole frame's length from its first 12 bytes, checked against the frame bounds, so a
    reader never takes more than the bound from a stream."""
    if len(header) < 12:
        _fail('a header cut short')
    magic, version, kind, length = struct.unpack('<IHHI', bytes(header[:12]))
    if magic != MAGIC:
        _fail('not a lab bridge frame')
    if version != VERSION:
        _fail('protocol version %d is not 1' % version)
    if kind not in TYPE_NAMES:
        _fail('an unknown message type %d' % kind)
    if not MIN_FRAME <= length <= MAX_FRAME:
        _fail('a frame length outside its bounds')
    return length


def decode(data):
    """The message one exact frame holds."""
    data = bytes(data)
    if len(data) < MIN_FRAME:
        _fail('a frame below the minimum size')
    if frame_length(data) != len(data):
        _fail('the length field differs from the frame')
    if hashlib.sha256(data[:-CHECKSUM]).digest() != data[-CHECKSUM:]:
        _fail('the checksum differs')
    kind = TYPE_NAMES[struct.unpack('<H', data[6:8])[0]]
    message = {'type': kind, 'request': data[12:28].hex(), 'manifest': data[28:60].hex()}
    _hex(message['request'], 16, 'request', False)
    _hex(message['manifest'], 32, 'manifest', False)
    reader = _Reader(data, len(data) - CHECKSUM)
    for name, field in BODIES[kind]:
        message[name] = reader.field(field, name)
    if reader.at != reader.end:
        _fail('trailing bytes after the body')
    _relations(message)
    return message


def read_frame(stream):
    """One whole frame from a binary stream, or None at a clean end of stream before any byte.
    A stream that ends inside a frame is a protocol error."""
    header = _read_exact(stream, 12, allow_end=True)
    if header is None:
        return None
    length = frame_length(header)
    rest = _read_exact(stream, length - 12)
    return header + rest


def _read_exact(stream, count, allow_end=False):
    chunks, have = [], 0
    while have < count:
        chunk = stream.read(count - have)
        if not chunk:
            if allow_end and have == 0:
                return None
            _fail('the stream ended inside a frame')
        chunks.append(chunk)
        have += len(chunk)
    return b''.join(chunks)


def reply_type(request_type):
    """The reply type that answers a request type."""
    if TYPES.get(request_type, 0) % 2 != 1:
        _fail('not a request type')
    return TYPE_NAMES[TYPES[request_type] + 1]


def message(kind, request, manifest, **fields):
    """A message dict of one type with every body field given."""
    value = {'type': kind, 'request': request, 'manifest': manifest}
    value.update(fields)
    return value
