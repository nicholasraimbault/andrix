# SPDX-License-Identifier: Apache-2.0
"""Strict readers of the deployment records the lab must understand, version 1, in the layout of
owner/deployment/README.md and of the runner's independent encoder: a plan and a ticket for the
broker, and the selection and the authorizations the next campaign's driver paces by.

The broker reads plans and tickets from the admitted store only to judge where a compound fact may
be emitted, such as a ticket's health window and its plan's window length. The driver reads all
four between generations, to pace one round at a time and compare a cell's records with its
prediction; it decides no ticket. Each read checks the frame, the type, the version, the length,
the checksum, every field's bound and the absence of trailing bytes. The public Java codec stays
the validity oracle: the bridge decodes the same stored records and refuses a fact the broker
placed against another window. Nothing here writes a record."""
import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.proof import component_transaction_records as encoder  # noqa: E402

MAX_TEXT = 255
MAX_USERS = 64
CRITERIA_ALL = (1 << 7) - 1
INTEGERS = {'u8': '<B', 'u16': '<H', 'i32': '<i', 'i64': '<q'}


class RecordError(ValueError):
    """A record of no valid version 1 form."""


def _names(table):
    return {code: name for name, code in table.items()}


class _Input:
    def __init__(self, record, kind):
        record = bytes(record)
        if not 12 + 32 <= len(record) <= 65536:
            raise RecordError('a record outside its size bounds')
        magic, code, version, length = struct.unpack('<IHHI', record[:12])
        if magic != encoder.MAGIC or code != encoder.TYPES[kind] or version != 1 or length != len(record):
            raise RecordError('not a version 1 %s record' % kind)
        if hashlib.sha256(record[:-32]).digest() != record[-32:]:
            raise RecordError('a record whose checksum differs')
        self.data, self.at, self.end = record, 12, len(record) - 32

    def take(self, count):
        if self.at + count > self.end:
            raise RecordError('a record cut short')
        value = self.data[self.at:self.at + count]
        self.at += count
        return value

    def number(self, kind):
        return struct.unpack(INTEGERS[kind], self.take(struct.calcsize(INTEGERS[kind])))[0]

    def hex(self, width):
        return self.take(width).hex()

    def text(self, optional=False):
        raw = self.take(self.number('u16'))
        if len(raw) > MAX_TEXT or any(b < 0x20 or b > 0x7e for b in raw) or (not optional and not raw):
            raise RecordError('a text field of no valid form')
        return raw.decode('ascii')

    def code(self, table, kind='u8'):
        value = self.number(kind)
        names = _names(table)
        if value not in names:
            raise RecordError('an unknown code %d' % value)
        return names[value]

    def reference(self):
        return (self.number('u8'), self.number('i32'), self.number('i64'), self.text(optional=True),
                self.number('i32'), self.hex(16))

    def finish(self):
        if self.at != self.end:
            raise RecordError('trailing bytes in a record')


def decode_plan(record):
    """A plan record's fields, by the encoder's names."""
    i = _Input(record, 'plan')
    p = {'installation': i.hex(16), 'plan': i.hex(16), 'component': i.text(), 'class': i.code(encoder.CLASSES),
         'target': i.code(encoder.TARGETS), 'repairs': i.hex(16), 'bundleInput': i.hex(32),
         'bundleVersion': i.number('i64'), 'signer': i.hex(32), 'restorationInput': i.hex(32),
         'restorationVersion': i.number('i64'), 'signing': i.number('u8'), 'fingerprint': i.text(),
         'factoryApk': i.hex(32), 'factoryVersion': i.number('i64'), 'baseApk': i.hex(32),
         'baseVersion': i.number('i64'), 'baseUid': i.number('i32'), 'baseContext': i.text(),
         'users': i.number('u8'), 'data': i.number('u8'), 'selectionRevision': i.number('i64'),
         'trustPolicy': i.hex(32), 'commitMode': i.code(encoder.COMMIT_MODES), 'criteria': i.number('u16'),
         'healthWindow': i.number('i64'), 'healthResponse': i.code(encoder.HEALTH_RESPONSES),
         'restorationPlan': i.hex(16), 'recoveryRoute': i.code(encoder.RECOVERY_ROUTES),
         'noticeDelay': i.number('i64'), 'emergencyNoticeDelay': i.number('i64'), 'bootLimit': i.number('u16'),
         'rebootTimeLimit': i.number('i64'), 'requestLimit': i.number('u16'), 'activateWindow': i.number('i64'),
         'verificationWait': i.number('i64'), 'created': i.number('i64')}
    i.finish()
    if (p['users'], p['data']) != (1, 1):
        raise RecordError('a plan of an unknown user or data scope')
    if p['criteria'] == 0 or p['criteria'] & ~CRITERIA_ALL or p['healthWindow'] <= 0:
        raise RecordError('a plan of no valid health criteria or window')
    return p


def decode_selection(record):
    """A selection record's fields, by the encoder's names."""
    i = _Input(record, 'selection')
    s = {'installation': i.hex(16), 'component': i.text(), 'revision': i.number('i64'),
         'choice': i.code(encoder.CHOICES), 'plan': i.hex(16), 'responsibility': i.code(encoder.RESPONSIBILITIES),
         'rebuildWindow': i.number('i64'), 'realization': i.code(encoder.REALIZATIONS), 'checkedBoot': i.hex(16),
         'repair': i.hex(16), 'temporary': i.hex(16), 'changedAt': i.number('i64')}
    i.finish()
    if s['revision'] < 0 or (s['choice'] == 'PLAN') == (s['plan'] == '00' * 16):
        raise RecordError('a selection of no valid revision or choice')
    return s


def decode_authorization(record):
    """An authorization record's fields, by the encoder's names."""
    i = _Input(record, 'authorization')
    a = {'installation': i.hex(16), 'authorization': i.hex(16), 'component': i.text(), 'plan': i.hex(16),
         'effect': i.code(encoder.EFFECTS), 'inputs': i.number('u8'), 'actor': i.code(encoder.ACTORS),
         'user': i.number('i32'), 'serial': i.number('i64'), 'grant': i.hex(16), 'scope': i.code(encoder.SCOPES),
         'interaction': i.hex(16), 'grantedAt': i.number('i64')}
    i.finish()
    if a['inputs'] & ~3 or (a['effect'] == 'SIGN') != (a['inputs'] != 0):
        raise RecordError('an authorization whose inputs are not exactly a SIGN grant\'s')
    return a


def decode_ticket(record):
    """A ticket record's fields, by the encoder's names; flags as their number."""
    i = _Input(record, 'ticket')
    t = {'installation': i.hex(16), 'ticket': i.hex(16), 'component': i.text(), 'plan': i.hex(16),
         'attempt': i.number('i32'), 'coordinatorClass': i.code(encoder.COORDINATORS),
         'coordinator': i.hex(16)}
    state = i.number('u8')
    if not 1 <= state <= len(encoder.STATES):
        raise RecordError('an unknown ticket state %d' % state)
    t['state'] = encoder.STATES[state - 1]
    t['flags'] = i.number('u8')
    t['cause'] = i.code(encoder.CAUSES)
    t['bootCount'] = i.number('u16')
    t['boot'] = i.hex(16)
    t['reference'] = i.reference()
    t['windowBoot'] = i.hex(16)
    t['windowStart'] = i.number('i64')
    t['successor'] = i.hex(16)
    users = i.number('u16')
    if users > MAX_USERS:
        raise RecordError('more health outcomes than users')
    t['health'] = [(i.number('i32'), i.number('i64'), i.code(encoder.OUTCOMES)) for _ in range(users)]
    entries = i.number('u16')
    if entries > encoder.MAX_LEDGER:
        raise RecordError('a ledger above its bound')
    crossings = {code: name for name, (code, _) in encoder.CROSSINGS.items()}
    ledger = []
    for _ in range(entries):
        code = i.number('u8')
        if code not in crossings:
            raise RecordError('an unknown crossing %d' % code)
        ledger.append((crossings[code], i.hex(16), i.number('i64'), i.number('i64'), i.hex(16), i.hex(16),
                       i.number('i64')))
    t['ledger'] = ledger
    i.finish()
    if t['flags'] & ~7:
        raise RecordError('unknown ticket flags')
    window = t['state'] == 'HEALTH_WINDOW'
    if window == (t['windowBoot'] == '00' * 16) or (window and t['windowStart'] < 0) or (
            not window and t['windowStart'] != 0):
        raise RecordError('a window exactly in HEALTH_WINDOW')
    return t
