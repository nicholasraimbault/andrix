#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of the native account lifecycle record codec, its readers and its
first writers: the slot version 2 codec, the stable prefix reader of later slot versions and the
reads of every store format, as B1 package P1 of plans/2026-10-08-native-lifecycle-record.md
defines them, the store's named lifecycle transitions with the suspend, lift, markRetiring and
markRetired transactions of package P2a, the boot facts, the deletion or migration step, confirm
disposal and Restore of package P2b, and the gated release engine of package P2c with its
capability, its store primitives and its continuation from durable state, with their fault sweeps.

Pure source checks run first. An independent encoder, written here from the plan's layout alone,
gives every version 2 golden. Each must have the length and SHA-256 that the Java codec test pins,
and the plan's size arithmetic must hold for it. The mutant anchors, the predictions and the labels
must agree, and the production format guard of the binding runner must hold. Release stays
unreachable: no production text constructs the release capability or names it, only the release
engine's named tests construct it, and no production text calls or references a release entry point
outside the persistence's release bodies, each rule with its mutants. No compiler or JVM
starts unless an actual cgroup bounds this process to 2 GiB of memory, no swap, 2 CPUs and 256
tasks, with core dumps disabled, and a JDK is on PATH. Otherwise the run is NOT_RUN. A guarded run
rebuilds the candidate Settings from the pinned framework copies, runs the codec test and compares
every golden it writes with the independent encoder byte for byte, runs the read test under
Format.V1, V2 and V3 with the facade identity predicate and the candidate's seeding text, runs the
lifecycle store and transaction tests under every format and the fault sweeps of every lifecycle
transaction at each writer step under Format.V3, through the existing host write fault seams, runs
the Settings test, whose seeding, boot facts, retired boot and release body cases go through both
the facade and the history harness, and runs each deliberate defect against the suites predicted to
catch it, a Settings fragment defect in the facade and the harness alike. It does not nest another
runner.

Host JVM evidence only: not Android, crash, power loss, storage or activation evidence. Format.V3
is constructed only by host tests here; no production text constructs it."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration  # noqa: E402
import native_creation_binding as b1  # noqa: E402
import native_creation_history as b2  # noqa: E402

PREDICTIONS = ROOT / 'scripts/proof/native_lifecycle_record_predictions.json'
PLAN = ROOT / 'plans/2026-10-08-native-lifecycle-record.md'
PLATFORM = b1.PLATFORM
FRAMEWORK_DIR = b1.FRAMEWORK_DIR
RECORDS = FRAMEWORK_DIR + 'NativeIdentityRecords.java'
STORE = FRAMEWORK_DIR + 'NativeIdentityStore.java'
PERSISTENCE = FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
MANAGER = FRAMEWORK_DIR + 'NativePrincipalManager.java'
FACADE = b1.FACADE
CODEC_TEST = 'NativeLifecycleCodecTest'
READ_TEST = 'NativeLifecycleReadTest'
STORE_TEST = 'NativeLifecycleStoreTest'
TRANSACTION_TEST = 'NativeLifecycleTransactionTest'
FAULT_TEST = 'NativeLifecycleFaultTest'
# The Settings level rules over both host copies of the adapted Settings text, the facade and the
# history harness: seeding, the boot facts, the retired boot rule and the release body.
SETTINGS_TEST = 'NativeLifecycleSettingsTest'
MANAGER_TEST = 'NativeLifecycleManagerTest'
# The shared fixtures of the store, transaction and fault tests, and the host write fault seam.
SUPPORT = 'NativeLifecycleTestSupport'
FAULT_SEAM = 'NativeHeaderWriteFaults'
# The history harness text the read test runs: the candidate's exact Settings texts.
HARNESS = 'harness'
# A mutant target naming a Settings fragment: the defect is in the fragment text, so it is applied to
# the facade and to the harness, which both carry that text verbatim, and both copies run it.
FRAGMENT = 'fragment:'
PHASES = ('candidate', 'codec', 'reads', 'store', 'transactions', 'faults', 'settings', 'manager', 'mutants')
# Every step is living. The read, store and transaction tests run each store format under its own
# label: Format.V1 is legacy, Format.V2 production and Format.V3 the new format, which B1 builds and
# does not ship. The fault sweeps run Format.V3 only.
STEP_LABELS = {'codec': ('production',), 'reads': ('production', 'legacy', 'new-format'),
               'store': ('production', 'legacy', 'new-format'),
               'transactions': ('production', 'legacy', 'new-format'), 'faults': ('new-format',),
               'settings': ('production', 'new-format'), 'manager': ('production', 'legacy', 'new-format'),
               'mutants': ('production', 'legacy', 'new-format')}
FORMAT_LABELS = {'V1': 'legacy', 'V2': 'production', 'V3': 'new-format'}

# ---------------------------------------------------------------- the independent encoder
# Written from the plan's record section alone, never from the Java codec: field order, widths and
# codes as the plan's table states them. A test oracle only; it produces no store input.

MAGIC = 0x44495841
TYPE_SLOT = 2
STATES = {'ELIGIBLE': 1, 'RETIRING': 2, 'RETIRED': 3}
CLASSES = {'ACCOUNT_USER': 1, 'ADMIN_GRANT': 2, 'RECOVERY_HOLD': 3, 'USER_REMOVAL': 4, 'LEGACY_MARKER': 5}
KINDS = ('WORK', 'API_EFFECTS', 'DELEGATIONS', 'PUBLICATIONS', 'LEASE_OPERATIONS', 'MAINTENANCE', 'ERASERS',
         'RESTRICTED_SUBJECTS', 'PACKAGE_CHANGES', 'ANDROID_STATE', 'KEYSTORE', 'DATA_CE', 'DATA_DE',
         'DATA_EXTERNAL', 'HOME', 'MANAGED_OBJECTS')
DUTY_STATES = {'OUTSTANDING': 1, 'DISPOSING': 2, 'DISCHARGED': 3, 'ORPHANED_WITH_USER': 4}
ZERO = '00' * 16


def record(kind, version, body):
    """One framed record: magic, type, version, total length, body and the SHA-256 of all of it."""
    raw = bytearray(struct.pack('<IHHI', MAGIC, kind, version, 0) + body)
    raw[8:12] = struct.pack('<I', len(raw) + 32)
    return bytes(raw) + hashlib.sha256(bytes(raw)).digest()


def text(value):
    return struct.pack('<H', len(value)) + value.encode('ascii')


def block(lifecycle):
    """One user's lifecycle block: state, entries, then the retirement when there is one."""
    state, entries, retirement = lifecycle
    out = struct.pack('<BB', STATES[state], len(entries))
    for actor, scope, user, serial, grant, reason, time, note in entries:
        out += struct.pack('<BBiq', CLASSES[actor], scope, user, serial) + bytes.fromhex(grant)
        out += struct.pack('<Hq', reason, time) + (b'\x00' if note is None else b'\x01' + bytes.fromhex(note))
    if retirement is not None:
        actor, user, serial, grant, time, duties = retirement
        out += struct.pack('<Biq', CLASSES[actor], user, serial) + bytes.fromhex(grant) + struct.pack('<q', time)
        out += struct.pack('<BB', 1 if duties else 0, len(duties))
        for kind, state_name, reference, code, at in duties:
            out += struct.pack('<BB', KINDS.index(kind) + 1, DUTY_STATES[state_name]) + bytes.fromhex(reference)
            out += struct.pack('<Bq', code, at)
    return out


def slot_v2(lineage, app_id, generation, package, signers, users, ticket=None):
    """A version 2 slot: the stable prefix, the blocks in user order, and a tombstone's ticket."""
    body = bytes.fromhex(lineage) + struct.pack('<iq', app_id, generation) + text(package)
    body += struct.pack('<H', len(signers)) + b''.join(bytes.fromhex(signer) for signer in sorted(signers))
    body += struct.pack('<H', len(users))
    for identity, user, serial, _ in users:
        body += struct.pack('<qiq', identity, user, serial)
    for *_, lifecycle in users:
        body += block(lifecycle)
    if not users:
        last, user, serial, ticket_id = ticket
        body += struct.pack('<qiq', last, user, serial) + bytes.fromhex(ticket_id)
    return record(TYPE_SLOT, 2, body)


def entry_size(note):
    """The bytes of one suspension entry."""
    return len(block(('ELIGIBLE', [('ACCOUNT_USER', 0, 0, 0, ZERO, 1, 0, note)], None))) - 2


LINEAGE = '00112233445566778899aabbccddeeff'
LOW, HIGH = '0f' * 32, 'aa' * 32
LONGEST = 'a.' + 'b' * 253
TIME = 1_700_000_000_000


def all_kinds(each):
    return [each(index + 1, kind) for index, kind in enumerate(KINDS)]


def goldens():
    """Every version 2 golden of the codec test, by its name there."""
    def retiring_duty(code, kind):
        return ((kind, 'DISCHARGED', '%02x' % code * 16, code, TIME + code) if code <= 3
                else (kind, 'OUTSTANDING', ZERO, 0, 0))

    def retired_duty(code, kind):
        if code <= 9:
            return (kind, 'DISCHARGED', '%02x' % code * 16, code, TIME + code)
        state = {10: 'DISPOSING', 11: 'DISPOSING', 12: 'DISPOSING', 13: 'ORPHANED_WITH_USER', 14: 'DISCHARGED'}
        return (kind, state.get(code, 'OUTSTANDING'), '%02x' % code * 16 if code <= 14 else ZERO, 0, 0)

    def largest_user(index):
        user, serial = index * 340, index
        entries = [('ACCOUNT_USER', 0, user, serial, ZERO, 1, TIME, '%02x' % index * 32)]
        for grant in range(4):
            entries.append(('ADMIN_GRANT', 1 if grant == 0 else 0, 0, 1,
                            '%02x' % (16 * grant + 1) * 15 + '%02x' % index, 2 + grant, TIME + grant,
                            '%02x' % (255 - index) * 32))
        entries.append(('RECOVERY_HOLD', 2, 0, 1, ZERO, 7, -1, 'cd' * 32))
        duties = all_kinds(lambda code, kind: (kind, 'DISCHARGED' if code <= 9 else 'DISPOSING',
                                               '%02x' % code * 16, code, TIME + code))
        return (index + 1, user, serial, ('RETIRED', entries, ('USER_REMOVAL', 0, 1, ZERO, TIME, duties)))

    return {
        'SUSPENDED': slot_v2(LINEAGE, 10123, 2, 'a.b', [LOW], [
            (3, 0, 5, ('ELIGIBLE', [('ACCOUNT_USER', 0, 0, 5, ZERO, 1, TIME, None)], None))]),
        # Entries in the plan's order, class, then actor serial, then grant: the grant entry of
        # serial 2 precedes that of serial 3 though its grant reference is the larger.
        'HOLDS': slot_v2(LINEAGE, 10124, 3, 'dev.andrix.principal', [LOW, HIGH], [
            (7, 0, 9, ('ELIGIBLE', [
                ('ACCOUNT_USER', 0, 0, 9, ZERO, 2, 1, 'ab' * 32),
                ('ADMIN_GRANT', 0, 0, 2, '22' * 16, 999, 3, None),
                ('ADMIN_GRANT', 1, 0, 3, '11' * 16, 4, 2, None),
                ('RECOVERY_HOLD', 3, 0, 1, ZERO, 7, -1, 'cd' * 32)], None))]),
        'RETIRING': slot_v2(LINEAGE, 10125, 4, 'dev.andrix.retiring', [LOW], [
            (11, 0, 2, ('RETIRING', [], ('ACCOUNT_USER', 0, 2, ZERO, TIME + 100, all_kinds(retiring_duty))))]),
        'RETIRED': slot_v2(LINEAGE, 10126, 9, 'dev.andrix.retired', [HIGH], [
            (12, 0, 4, ('RETIRED', [('ACCOUNT_USER', 0, 0, 4, ZERO, 6, 6, None)],
                        ('ADMIN_GRANT', 0, 3, '33' * 16, 5, all_kinds(retired_duty))))]),
        'LEGACY_CONTINUED': slot_v2(LINEAGE, 10127, 5, 'dev.andrix.legacy', [LOW], [
            (13, 0, 1, ('RETIRING', [], ('LEGACY_MARKER', 0, 0, ZERO, 0,
                                         all_kinds(lambda code, kind: (kind, 'OUTSTANDING', ZERO, 0, 0)))))]),
        'LEGACY_SUSPENDED': slot_v2(LINEAGE, 10128, 6, 'dev.andrix.held', [LOW], [
            (14, 0, 1, ('RETIRING', [('RECOVERY_HOLD', 2, 0, 1, ZERO, 7, 8, None)],
                        ('LEGACY_MARKER', 0, 0, ZERO, 0, [])))]),
        'TWO_USERS': slot_v2(LINEAGE, 10129, 7, 'dev.andrix.shared', [LOW, HIGH], [
            (15, 0, 1, ('ELIGIBLE', [], None)),
            (16, 10, 2, ('ELIGIBLE', [('ADMIN_GRANT', 0, 0, 1, '44' * 16, 3, 9, None)], None))]),
        'TICKET': slot_v2(LINEAGE, 10130, 8, 'dev.andrix.released', [LOW], [], (17, 0, 3, '55' * 16)),
        'MAXIMUM': slot_v2('ffeeddccbbaa99887766554433221100', 19999, 2 ** 63 - 1, LONGEST,
                           ['%02x' % (255 - index) * 32 for index in range(32)],
                           [largest_user(index) for index in range(64)]),
    }


def sizes():
    """The plan's size arithmetic, from the independent encoder: the fixed slot part, an entry with
    and without its note, the retirement with every kind, one largest user and the largest slot."""
    largest = goldens()['MAXIMUM']
    retirement = len(block(('RETIRING', [], ('ACCOUNT_USER', 0, 0, ZERO, 0,
                                             all_kinds(lambda code, kind: (kind, 'OUTSTANDING', ZERO, 0, 0))))))
    user = 20 + 2 + 6 * entry_size('00' * 32) + retirement - 2
    fixed = len(largest) - 64 * user
    return {'fixed': fixed, 'entry': entry_size(None), 'noted_entry': entry_size('00' * 32),
            'retirement': retirement - 2, 'user': user, 'largest': len(largest)}


# The plan's own statements of those sizes.
PLAN_SIZES = {'fixed': 1357, 'entry': 41, 'noted_entry': 73, 'retirement': 471, 'user': 931, 'largest': 60941}
PLAN_SIZE_TEXT = ('The fixed slot part is at most 1,357 bytes. A suspension entry takes 41 bytes, or 73\n'
                  'with a note. One user takes at most 931 bytes: 20 for its identity, 2 for state and count, 438 for\n'
                  'six noted entries and 471 for the retirement block with 16 obligations. 64 users take at most\n'
                  '60,941 bytes')

# ---------------------------------------------------------------- predicted case names

GOLDEN_NAMES = ('SUSPENDED', 'HOLDS', 'RETIRING', 'RETIRED', 'LEGACY_CONTINUED', 'LEGACY_SUSPENDED', 'TWO_USERS',
                'TICKET', 'MAXIMUM')
CODEC_NAMES = (
    'golden / version 1 values built from lifecycles keep their version 1 bytes',
    *('golden / ' + name.lower().replace('_', ' ') for name in GOLDEN_NAMES),
    'golden / suspended layout written by hand',
    'version / each value has the version its lifecycle needs',
    'one encoding / every version 1 value is refused in version 2',
    'one encoding / confirming a legacy marker rewrites version 1 bytes',
    'size / the largest record takes 60,941 bytes', 'size / the measure equals every encoding',
    'decoder accepts / scope bit 0, unknown reasons, notes and any times',
    'decoder refuses / unknown lifecycle states', 'decoder refuses / more than six entries',
    'decoder refuses / suspension classes outside entries',
    'decoder refuses / unknown scope bits and bit 1 outside a recovery hold',
    'decoder refuses / grants that are zero exactly for ADMIN_GRANT broken',
    'decoder refuses / unknown note tags', 'decoder refuses / entries out of order or two from one actor',
    'decoder orders / entries by class, then actor serial, then grant',
    'decoder refuses / negative actor users and serials',
    'decoder refuses / a retirement in ELIGIBLE or missing from RETIRING and RETIRED',
    'decoder refuses / retirement classes outside retirements',
    'decoder refuses / a legacy marker with an actor, grant or time',
    "decoder refuses / inventories other than every kind once or a legacy marker's none",
    'decoder refuses / an unknown inventory outside RETIRING',
    'decoder refuses / obligations out of kind order or of unknown kinds and states',
    'decoder refuses / DISPOSING on a retirement kind or outside RETIRED',
    'decoder refuses / RETIRED with a retirement kind not DISCHARGED',
    'decoder refuses / ticket fields out of bounds',
    'decoder refuses / a tombstone without its ticket, a ticket beside users and trailing bytes',
    'values / the constructors enforce the same rules', 'ticket / bounds round trip',
    'mutation / resealed version 2 mutations are refused or canonical',
    'prefix / later versions give their package and principals', 'prefix / nothing after the prefix is read',
    'prefix / version 1 and 2 frames give no prefix', 'prefix / damaged frames give no prefix',
    'prefix / each frozen bound and rule refuses', 'prefix / the evidence carries no lifecycle',
    'reasons / a registry of specific codes without a catch-all',
    'surface / lifecycle values are closed and print no references')


def read_names(format_name):
    """The read test's cases under one store format, in run order."""
    names = ['a suspended version 2 slot', 'a retired version 2 slot',
             'a version 2 slot beside a sibling naming its package',
             'a version 2 slot beside a sibling naming its principal',
             'a version 2 slot beside a sibling naming neither',
             'a reservation elsewhere beside a version 2 slot',
             'the identity predicate and seeding name a package that only a version 2 slot holds',
             'a later frame with a valid prefix is negative evidence only',
             "the identity predicate and seeding read a later frame's valid prefix",
             'a later frame with a broken prefix gives no evidence',
             'healthy controls, every writer succeeds']
    for kind in ('valid', 'broken'):
        for position in ('main', 'reserve', 'backup', 'seed'):
            names.append('a later frame with a %s prefix in the %s, %s' % (
                kind, position, 'the seed gives nothing and every writer refuses' if position == 'seed'
                else 'nothing restored from the older copies and every writer refuses'))
    names.append('version 2 slot writes ' + ('succeed' if format_name == 'V3' else 'refuse before any effect'))
    return tuple('%s / %s' % (format_name, name) for name in names)


READ_NAMES = tuple(name for format_name in ('V1', 'V2', 'V3') for name in read_names(format_name))

# The lifecycle store test: the named transitions under Format.V3, then the refusals of the earlier
# formats. Every name is one literal in its source.
STORE_NAMES = (
    'V3 / suspend adds one entry in order and changes nothing else',
    'V3 / suspend refuses scope bit 0 before any effect',
    'V3 / suspend refuses a reason outside the registry before any effect',
    'V3 / suspend refuses a reason its actor class may not use before any effect',
    'V3 / suspend refuses an account user entry of another user or serial before any effect',
    'V3 / suspend refuses a recovery hold before any effect',
    'V3 / suspend refuses a second entry from one actor before any effect',
    'V3 / suspend refuses a seventh actor before any effect',
    "V3 / suspend allots four grant places and keeps the account user's place",
    'V3 / lift removes exactly its entry and the last one writes version 1',
    'V3 / lift refuses an entry the record does not hold exactly before any effect',
    'V3 / lift refuses a recovery hold before any effect',
    "V3 / suspend and lift keep a retiring or retired account's state and block",
    'V3 / retire writes RETIRING with its block and keeps every entry',
    'V3 / retire refuses blocks no writer writes before any effect',
    'V3 / retire never creates a legacy marker',
    'V3 / retire never moves an account back or changes its block',
    "V3 / a legacy marker's inventory continues once to every kind outstanding",
    'V3 / confirm retired discharges every retirement kind and keeps everything else',
    'V3 / confirm retired refuses an unknown inventory, an orphaned kind and incomplete receipts',
    'V3 / confirm retired binds a reference once and keeps a discharged kind',
    'V3 / confirm retired refuses an account that is not retiring before any effect',
    'V3 / the generic update refuses every lifecycle change',
    'V3 / the generic update never drops a user',
    "V3 / the generic update keeps every user's identity",
    'V3 / the generic update never writes a ticket',
    'V3 / the generic update still rewrites an unchanged lifecycle',
    'V3 / every transition needs the fresh durable value',
    'V3 / every transition refuses at the last generation before any effect',
    "V3 / every transition refuses beside a later slot version's footprint",
    'V3 / a header phase change completes a suspended body',
    # P2b: the deletion or migration step, confirm disposal and Restore.
    'V3 / the deletion step moves every disposition kind to DISPOSING at once and changes nothing else',
    'V3 / the deletion step refuses beside scope bit 0, an orphaned kind or a deletion that began before any effect',
    'V3 / the deletion step refuses an account that is not RETIRED before any effect',
    'V3 / confirm disposal discharges each DISPOSING kind it names and keeps everything else',
    'V3 / confirm disposal refuses outstanding and orphaned kinds and receipts no writer writes before any effect',
    'V3 / confirm disposal binds a reference once and keeps a discharged kind',
    'V3 / restore writes the intact copy of the highest generation with a recovery hold',
    'V3 / restore writes ELIGIBLE with scope bit 1 when no copy is intact',
    'V3 / restore refuses copies of another account, a tombstone, a tie at the highest generation and a full record'
    ' before any effect',
    'V3 / restore refuses a RELEASING or missing entry, a stale header, a footprint and a missing body before any'
    ' effect',
    'V3 / restore keeps a held recovery hold and confirms its own retry',
    # P2c: Restore beside a RELEASING header copy, and the release engine's primitives.
    'V3 / restore refuses beside a header copy that lists the account RELEASING',
    'V3 / the user drop writes the ticketed tombstone of a releasable account only',
    "V3 / RELEASING needs the release engine's ticketed tombstone",
    "V3 / a ticket's principal ID is sibling, claim and counter evidence",
    'V3 / the generic header write never turns an entry RELEASING or omits one',
    *('%s / every transition refuses before any effect' % format_name for format_name in ('V1', 'V2')))
# The lifecycle transaction test: the persistence transactions under Format.V3, then each earlier
# format's refusals and its version 1 marker and release.
TRANSACTION_NAMES = (
    'V3 / suspend writes the entries of the account user and of a grant',
    'V3 / a repeated suspension by the same actor confirms its entry unchanged',
    "V3 / a repeated suspension that differs holds the actor's entry unchanged",
    "V3 / a fifth grant is full beside the account user's place and applies once a grant is lifted",
    'V3 / a seventh actor is full beside six entries',
    'V3 / suspend refuses requests no writer writes before any effect',
    'V3 / only the actor that placed an entry lifts it',
    'V3 / lifting the last suspension writes version 1 again',
    'V3 / a lift once durable is confirmed again',
    "V3 / lift refuses a recovery hold and another user's account user entry as invalid requests",
    'V3 / markRetiring writes the block and keeps every suspension entry',
    'V3 / markRetiring confirms its own retirement and refuses any other',
    'V3 / markRetiring refuses blocks no writer writes before any effect',
    'V3 / a legacy marker continues once through markRetiring',
    'V3 / markRetiring never creates a legacy marker',
    'V3 / markRetired discharges the retirement kinds and confirms its retry',
    'V3 / markRetired refuses until every retirement kind can be discharged',
    'V3 / markRetired refuses receipts that are not one of each retirement kind before any effect',
    'V3 / a retired account keeps its entries and restores a RETIRING pin',
    'V3 / publish refuses a suspended binding before any effect',
    'V3 / publish refuses a retiring or retired binding before any effect',
    'V3 / the version 1 marker refuses before any effect',
    'V3 / the version 1 release refuses before any effect',
    'V3 / every lifecycle transaction needs only an intact binding',
    'V3 / a damaged, foreign or unbound record is never written',
    # P2b: the boot facts, disposition in a retired boot, and Restore.
    'V3 / the boot facts name RETIRED accounts, ticketed tombstones and RELEASING entries without a directory',
    'V3 / disposition waits for a boot that began with the account RETIRED',
    'V3 / beginDisposition moves every disposition kind to DISPOSING and confirms its retry',
    'V3 / beginDisposition refuses outside a retired boot, beside scope bit 0 and for an orphaned kind before any'
    ' effect',
    'V3 / confirmDisposition discharges per kind and confirms its retry',
    'V3 / confirmDisposition refuses outside a retired boot and before deletion began before any effect',
    'V3 / confirmDisposition refuses receipts that are not disposal receipts before any effect',
    'V3 / restore writes the last known state with a recovery hold',
    'V3 / restore writes ELIGIBLE with scope bit 1 when the state cannot be established',
    'V3 / a restored record never becomes active directly',
    'V3 / restore refuses requests no writer writes before any effect',
    'V3 / restore refuses another claim, lineage or counter and a missing body before any effect',
    # P2c: Restore's claims, the boot facts beside a header the format cannot read, and the gated
    # release engine.
    'V3 / the boot facts give no fact beside a newer header',
    'V3 / the boot facts give no fact beside an unreadable header copy',
    "V3 / restore refuses a sibling's reservation or tombstone of its package and a damaged header before any effect",
    'V3 / release clears the key namespace, then writes the ticketed tombstone, RELEASING and the omission',
    'V3 / release completes a CREATING entry to LIVE before the key namespace and the tombstone',
    'V3 / release refuses outside a retired boot before any effect',
    'V3 / release refuses beside a suspension entry or an open obligation before any effect',
    'V3 / release refuses tickets of another principal and unchecked users before any effect',
    "V3 / release refuses beside a foreign copy or another ticket's tombstone before any effect",
    'V3 / release refuses before any effect when the key namespace is not cleared',
    'V3 / an interrupted release continues only in a boot that began with its ticketed tombstone',
    'V3 / an interrupted release continues from RELEASING without a directory or with an emptied one',
    'V3 / continuation passes only the checked removal and omission',
    'V3 / continuation refuses a counter that does not cover the account before any effect',
    'V3 / continuation refuses a live binding of the package elsewhere before any effect',
    'V3 / an unticketed tombstone of the version 1 release stays held',
    *('%s / %s' % (format_name, case) for format_name in ('V1', 'V2')
      for case in ('every lifecycle transaction refuses before any effect',
                   'the version 1 marker and release still work')))
# The fault sweeps: each lifecycle transaction, failed at each writer step of the strict slot writer.
FAULT_STEPS = ('seed-synced', 'backup-renamed', 'backup-published', 'write-started', 'main-synced',
               'reserve-synced', 'backup-unlink', 'backup-unlinked')
FAULT_KINDS = ('suspend', 'repeated suspension', 'lift', 'markRetiring', 'legacy continuation', 'markRetired',
               'beginDisposition', 'confirmDisposition', 'restore', 'restore without an intact copy',
               'release tombstone', 'release tombstone confirmation', 'release RELEASING',
               'release RELEASING confirmation', 'release omission', 'release completion confirmation',
               'release completion')
FAULT_NAMES = tuple('%s / %s' % (kind, step) for kind in FAULT_KINDS for step in FAULT_STEPS)
SETTINGS_NAMES = (
    'V2 / a version 1 retiring body is deferred at seeding',
    'V3 / a retiring account is deferred at seeding',
    'V3 / a suspended account is deferred at seeding',
    'V3 / an eligible account stays recoverable',
    'V3 / a retired account is a retired boot and is deferred',
    'V3 / the boot facts defer an unmapped ticketed tombstone',
    'V3 / the boot facts are recorded once and survive later reads',
    'V2 / the production format gives no lifecycle fact',
    'V3 / disposition needs an instance that began with the account RETIRED',
    'V3 / release needs an instance that began with the account RETIRED',
    'V3 / a durable release keeps the app ID held until a new instance',
    'V3 / the release finish refuses without a durable omission')
# The manager's lifecycle operations: their format refusals, the suspension closure, each activation
# point's suspension refusal and retirement.
MANAGER_NAMES = (
    'V1 / every lifecycle operation refuses before any effect',
    'V2 / every lifecycle operation refuses before any effect',
    'V3 / suspension closes admission in memory and then writes its entry',
    'V3 / a lift is durable but nothing reopens in this instance',
    'V3 / a refused or uncertain suspension write keeps the closure',
    'V3 / suspension refuses an entry no writer writes before any effect',
    'V3 / preparation refuses a durably suspended account',
    'V3 / preparation refuses a handle closed in memory',
    'V3 / commit refuses a durably suspended account before any write',
    'V3 / commit refuses a handle closed in memory',
    'V3 / currentIdentity refuses a handle closed in memory',
    'V3 / the published binding check refuses a durably suspended account',
    'V3 / retirement moves the pin and then writes its block',
    'V3 / retirement refuses a block no writer writes before the pin change',
    'V3 / disposition and release need an instance that began with the account RETIRED',
    'V3 / the release body keeps the app ID held until a new instance',
    'V3 / a lost reply after the omission is acknowledged in the instance and freed at the next boot',
    'V3 / release refuses before any effect without its gate',
    'V3 / release refuses a suspension closed in memory before any effect')

# ---------------------------------------------------------------- deliberate defects

_IDENTITY_PREFIX = ('                // A later slot version\'s stable prefix names its package as negative evidence.\n'
                    '                for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes) {\n'
                    '                    if (prefix.packageName.equals(packageName)) return true;\n'
                    '                }\n')
_SEEDING_PREFIX = ('            for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes)'
                   ' names.add(prefix.packageName);\n')
# The publication transaction's own refusal of a binding outside the policy's Eligible state, and the
# shared slot confirmation's first line.
_PUBLISH_CHECK = ('                || slot.users.get(0).retiring\n'
                  '                || !slot.users.get(0).lifecycle.suspensions.isEmpty()) return false;\n')
_PUBLISH_RETIRING = '                || slot.users.get(0).retiring) return false;\n'
_CONFIRM_HEAD = '        if (expected.version > format.slotCeiling) return false;\n'
# Each defect: its edits, as target, exact old text and new text, and the suites that run it. A
# target is a source path, HARNESS: the history harness text filled from the candidate, whose
# identity and seeding are the fragments, so its anchors are checked in the fragment files, or
# FRAGMENT and a fragment name: the same edit in the facade and the harness, anchored once in the
# fragment. The predictions file lists the checks each must fail. A compile failure is a harness
# failure.
_SEEDING_LIFECYCLE = ('                        || history.retiring\n'
                      '                        || !history.suspensions.isEmpty()) {\n')
_BOOT_DEFERRAL = ('        for (String name : names) {\n'
                  '            PackageSetting pkg = getPackageLPr(name);\n'
                  '            mNativeRecoveryView = deferNativeName(mNativeRecoveryView, name, pkg == null ? null'
                  ' : pkg.getPath());\n'
                  '        }\n')
_OBSERVED = ('        mNativeIdentityLoaded = loaded;\n'
             '        // A failed/reduced read is not authority to forget a previous hold.\n')
_FORGET = '        mNativeRememberedBindings.remove(record.id);\n'
MUTANTS = {
    # Records: one encoding per value, the invariants and the prefix reader.
    'v2-admits-v1-values': (((RECORDS,
        '        if (slot.version != VERSION_2) throw invalid("version 1 value in a version 2 record");\n', ''),),
        ('codec',)),
    'legacy-marker-written-as-v2': (((RECORDS,
        '            return equals(ELIGIBLE_ONLY) || equals(LEGACY_RETIRING);\n',
        '            return equals(ELIGIBLE_ONLY);\n'),), ('codec',)),
    'unknown-inventory-anywhere': (((RECORDS,
        '                if (retirement.inventory == INVENTORY_UNKNOWN && state != LifecycleState.RETIRING) {\n',
        '                if (retirement.inventory == INVENTORY_UNKNOWN && state == null) {\n'),), ('codec',)),
    'retired-with-open-retirement-kind': (((RECORDS,
        '                    if (state == LifecycleState.RETIRED && !obligation.kind.disposition()\n',
        '                    if (state == null && !obligation.kind.disposition()\n'),), ('codec',)),
    'disposing-on-retirement-kind': (((RECORDS,
        '            if (state == ObligationState.DISPOSING && !kind.disposition()) {\n',
        '            if (state == ObligationState.DISPOSING && kind == null) {\n'),), ('codec',)),
    'disposing-outside-retired': (((RECORDS,
        '                    if (obligation.state == ObligationState.DISPOSING\n'
        '                            && state != LifecycleState.RETIRED) {\n',
        '                    if (obligation.state == ObligationState.DISPOSING && state == null) {\n'),), ('codec',)),
    'seventh-entry': (((RECORDS, '    static final int MAX_SUSPENSIONS = 6;\n',
                        '    static final int MAX_SUSPENSIONS = 7;\n'),), ('codec',)),
    'second-entry-per-actor': (((RECORDS,
        '                if (repeated) throw invalid("two suspension entries from one actor");\n', ''),), ('codec',)),
    # The grant reference compared before the actor serial. Dropping the serial instead is the same
    # defect: two entries of one class differ in their grants, so no case can tell the two apart.
    'order-grant-before-serial': (((RECORDS,
        '        if (order == 0) order = Long.compare(first.actorSerial, second.actorSerial);\n'
        '        return order != 0 ? order : first.grant.compareTo(second.grant);\n',
        '        if (order == 0) order = first.grant.compareTo(second.grant);\n'
        '        return order != 0 ? order : Long.compare(first.actorSerial, second.actorSerial);\n'),),
        ('codec',)),
    'scope-bit-1-anywhere': (((RECORDS,
        '            if ((scope & SCOPE_PRIOR_UNKNOWN) != 0 && actorClass != ActorClass.RECOVERY_HOLD) {\n',
        '            if ((scope & SCOPE_PRIOR_UNKNOWN) != 0 && actorClass == null) {\n'),), ('codec',)),
    'scope-bit-0-refused': (((RECORDS,
        '            if ((scope & ~(SCOPE_BLOCKS_DISPOSITION | SCOPE_PRIOR_UNKNOWN)) != 0) {\n',
        '            if ((scope & ~SCOPE_PRIOR_UNKNOWN) != 0) {\n'),), ('codec',)),
    'note-tag-lenient': (((RECORDS,
        '            if (note != NOTE_ABSENT && note != NOTE_PRESENT) throw invalid("unknown note tag");\n'
        '            String digest = note == NOTE_PRESENT ? hex(NOTE_BYTES) : null;\n',
        '            String digest = note != NOTE_ABSENT ? hex(NOTE_BYTES) : null;\n'),), ('codec',)),
    'legacy-marker-with-actor': (((RECORDS,
        '                    && (actorUserId != 0 || actorSerial != 0 || time != 0)) {\n',
        '                    && actorClass == null) {\n'),), ('codec',)),
    'inventory-byte-unchecked': (((RECORDS,
        '            if (count != (inventory == INVENTORY_KNOWN ? OBLIGATION_KINDS : 0)) {\n',
        '            if (count > OBLIGATION_KINDS) {\n'),), ('codec',)),
    'zero-ticket-id': (((RECORDS, '            if (ticketId.equals(NO_REFERENCE)) throw invalid("zero ticket ID");\n',
                         ''),), ('codec',)),
    'unknown-reason-refused': (((RECORDS,
        '            if (reason < 0 || reason > MAX_REASON) throw invalid("reason code outside its range");\n',
        '            if (SuspensionReason.registered(reason) == null) throw invalid("reason code outside its range");\n'),),
        ('codec',)),
    'reason-catch-all': (((RECORDS, '        RECOVERY_REVIEW(7, ActorClass.RECOVERY_HOLD);\n',
                           '        RECOVERY_REVIEW(7, ActorClass.RECOVERY_HOLD),\n        /** Any other reason. */\n'
                           '        OTHER(8, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT,'
                           ' ActorClass.RECOVERY_HOLD);\n'),), ('codec',)),
    # A grant holder may give the account user's own reason.
    'reason-actors-widened': (((RECORDS, '        USER_PAUSED(1, ActorClass.ACCOUNT_USER),\n',
                                '        USER_PAUSED(1, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT),\n'),),
                              ('codec',)),
    'prefix-reads-version-2': (((RECORDS,
        '            if (version <= VERSION_2) throw invalid("no stable prefix reading of this version");\n',
        '            if (version < VERSION_2) throw invalid("no stable prefix reading of this version");\n'),),
        ('codec',)),
    'prefix-needs-its-end': (((RECORDS,
        '        Prefix prefix = in.prefix();\n        List<Long> ids = new ArrayList<>(prefix.ids.length);\n',
        '        Prefix prefix = in.prefix();\n        in.finish();\n'
        '        List<Long> ids = new ArrayList<>(prefix.ids.length);\n'),), ('codec',)),
    'prefix-user-bound-raised': (((RECORDS, '    private static final int PREFIX_MAX_USERS = 64;\n',
                                   '    private static final int PREFIX_MAX_USERS = 65;\n'),), ('codec',)),
    'prefix-without-order': (((RECORDS,
        '                if (i > 0 && userIds[i] <= userIds[i - 1]) throw invalid("identities out of order");\n',
        ''),), ('codec',)),
    # Store: classification by the frame against the format's slot ceiling, the evidence, the writer
    # ceiling and the history facts.
    'slot-ceiling-fixed-at-1': (((STORE,
        '                : NativeIdentityRecords.intactSlotVersion(bytes) > format.slotCeiling;\n',
        '                : NativeIdentityRecords.intactSlotVersion(bytes) > 1;\n'),), ('reads',)),
    'slot-ceiling-fixed-at-2': (((STORE,
        '                : NativeIdentityRecords.intactSlotVersion(bytes) > format.slotCeiling;\n',
        '                : NativeIdentityRecords.intactSlotVersion(bytes) > 2;\n'),), ('reads',)),
    'broken-prefix-is-damage': (((STORE,
        '                if (unsupportedBytes(copy.bytes, header)) {\n',
        '                if (unsupportedBytes(copy.bytes, header) && (header || value != null\n'
        '                        || !stablePrefix(copy.bytes).isEmpty())) {\n'),), ('reads',)),
    'prefixes-not-read': (((STORE,
        '                    if (!header && value == null) prefixes.addAll(stablePrefix(copy.bytes));\n', ''),),
        ('reads',)),
    'prefix-evidence-dropped': (((STORE,
        '                    packages.putIfAbsent(prefix.packageName, entry.getKey());\n'
        '                    for (long id : prefix.principalIds) incarnations.putIfAbsent(id, entry.getKey());\n',
        ''),), ('reads',)),
    'version-2-copies-dropped': (((STORE,
        '            return readCopies(slotFile(appId), NativeIdentityRecords::decodeSlot, false);\n',
        '            return readCopies(slotFile(appId), bytes -> {\n'
        '                Slot decoded = NativeIdentityRecords.decodeSlot(bytes);\n'
        '                if (decoded.version > format.slotCeiling) throw new IllegalArgumentException("newer");\n'
        '                return decoded;\n'
        '            }, false);\n'),), ('reads',)),
    'publish-past-slot-ceiling': (((STORE, '        if (next.version > format.slotCeiling) return false;\n', ''),),
                                  ('reads',)),
    'update-past-slot-ceiling': (((STORE,
        '        if (expected.version > format.slotCeiling || next.version > format.slotCeiling) return false;\n',
        ''),), ('reads', 'store')),
    'history-drops-suspensions': (((STORE, '            this.suspensions = lifecycle.suspensions;\n',
                                    '            this.suspensions = List.of();\n'),), ('reads',)),
    'retired-restores-pending': (((STORE,
        '            this.retiring = lifecycle.state != NativeIdentityRecords.LifecycleState.ELIGIBLE;\n',
        '            this.retiring = lifecycle.state == NativeIdentityRecords.LifecycleState.RETIRING;\n'),),
        ('reads',)),
    # Persistence: only the Eligible state owns a scan.
    'scan-allows-suspended': (((PERSISTENCE,
        '                || currentSerial < 0 || history.appId != candidateAppId || !history.eligible()\n',
        '                || currentSerial < 0 || history.appId != candidateAppId || history.retiring\n'),),
        ('reads',)),
    # Settings: the identity predicate in the facade and the candidate, and the seeding names.
    'identity-ignores-prefixes': (((FRAGMENT + 'identity', _IDENTITY_PREFIX, ''),), ('reads',)),
    'seeding-ignores-prefixes': (((FRAGMENT + 'recovery-seeding', _SEEDING_PREFIX, ''),), ('reads',)),
    # Settings fragments, each run by the facade and the harness alike.
    'seeding-ignores-retired-accounts': (((FRAGMENT + 'recovery-seeding', _SEEDING_LIFECYCLE,
                                           '                        || !history.suspensions.isEmpty()) {\n'),),
                                         ('settings',)),
    'seeding-ignores-suspended-accounts': (((FRAGMENT + 'recovery-seeding', _SEEDING_LIFECYCLE,
                                             '                        || history.retiring) {\n'),), ('settings',)),
    'boot-facts-from-the-cached-view': (((FRAGMENT + 'retired-boot', '        return mNativeBootFacts;\n',
                                          '        return NativeIdentityPersistence.bootFacts(mNativeIdentityLoaded);\n'),),
                                        ('settings',)),
    'boot-facts-recorded-again-on-observe': (((FRAGMENT + 'observation', _OBSERVED, _OBSERVED
        + '        if (mNativeBootFacts != null) mNativeBootFacts = NativeIdentityPersistence.bootFacts(loaded);\n'),),
        ('settings',)),
    'boot-facts-lose-their-deferral': (((FRAGMENT + 'boot-facts', _BOOT_DEFERRAL, ''),), ('settings',)),
    'release-finish-drops-the-hold': (((FRAGMENT + 'release-finish', _FORGET,
                                        '        mNativeStoreAppIds.remove(record.appId);\n' + _FORGET),),
                                      ('settings',)),
    'release-finish-keeps-the-history': (((FRAGMENT + 'release-finish', _FORGET, ''),), ('settings',)),
    # P2a writer rules: the store's pure predicates, which the transactions apply as invalid requests.
    'scope-bit-0-written': (((STORE,
        '        if ((entry.scope & NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION) != 0) return false;\n', ''),),
        ('store', 'transactions')),
    'unregistered-reason-written': (((STORE,
        '        if (reason == null) return false;\n        if (!reason.actors.contains(entry.actorClass)) return false;\n',
        '        if (reason != null && !reason.actors.contains(entry.actorClass)) return false;\n'),),
        ('store', 'transactions')),
    'reason-class-unchecked': (((STORE, '        if (!reason.actors.contains(entry.actorClass)) return false;\n', ''),),
                               ('store', 'transactions')),
    'suspension-actor-unchecked': (((STORE,
        '        return entry.actorClass != ActorClass.ACCOUNT_USER\n'
        '                || (entry.actorUserId == userId && entry.actorSerial == userSerial);\n',
        '        return true;\n'),), ('store', 'transactions')),
    'recovery-hold-written': (((STORE,
        '        if (entry.actorClass != ActorClass.ACCOUNT_USER\n'
        '                && entry.actorClass != ActorClass.ADMIN_GRANT) return false;\n', ''),),
        ('store', 'transactions')),
    'retirement-actor-unchecked': (((STORE,
        '        if (retirement.actorClass == ActorClass.ACCOUNT_USER && (retirement.actorUserId != userId\n'
        '                || retirement.actorSerial != userSerial)) return false;\n', ''),), ('store', 'transactions')),
    'user-removal-written': (((STORE, '        if (retirement.actorClass == ActorClass.USER_REMOVAL) return false;\n', ''),),
                             ('store', 'transactions')),
    'written-inventory-accepted': (((STORE,
        '            if (!duty.equals(new Obligation(duty.kind, ObligationState.OUTSTANDING,\n'
        '                    NativeIdentityRecords.NO_REFERENCE, 0, 0))) return false;\n', ''),),
        ('store', 'transactions')),
    'unknown-inventory-requested': (((STORE, '        if (retirement.obligations.isEmpty()) return false;\n', ''),),
                                    ('transactions',)),
    'receipt-kinds-unchecked': (((STORE,
        '            if (receipt.kind != kind || receipt.state != ObligationState.DISCHARGED) return false;\n', ''),),
        ('store', 'transactions')),
    # The store applies each writer rule itself, and each transaction applies it to its request.
    'store-entry-unchecked': (((STORE,
        '        if (!writableSuspension(user.userId, user.userSerial, entry)) return null;\n', ''),), ('store',)),
    'store-block-unchecked': (((STORE,
        '        if (!writableRetirement(user.userId, user.userSerial, retirement)) return null;\n', ''),), ('store',)),
    'store-receipts-unchecked': (((STORE,
        '        if (!writableReceipts(receipts) || prior.state != LifecycleState.RETIRING) return null;\n',
        '        if (prior.state != LifecycleState.RETIRING) return null;\n'),), ('store',)),
    'suspension-request-unchecked': (((PERSISTENCE,
        '        if (!NativeIdentityStore.writableSuspension(record.userId, record.userSerial, entry)) {\n'
        '            throw new IllegalArgumentException("suspension entry outside the writer rules");\n'
        '        }\n', ''),), ('transactions',)),
    'retirement-request-unchecked': (((PERSISTENCE,
        '        if (!NativeIdentityStore.writableRetirement(record.userId, record.userSerial, retirement)) {\n'
        '            throw new IllegalArgumentException("retirement outside the writer rules");\n'
        '        }\n', ''),), ('transactions',)),
    'receipts-request-unchecked': (((PERSISTENCE,
        '        if (!NativeIdentityStore.writableReceipts(copy)) {\n'
        '            throw new IllegalArgumentException("not one receipt of each retirement kind");\n'
        '        }\n', ''),), ('transactions',)),
    # Entries: the six entry bound and its allotment, one entry per actor, and lifts of exactly the
    # placed entry.
    'seventh-entry-written': (((STORE,
        '        if (lifecycle.suspensions.size() >= NativeIdentityRecords.MAX_SUSPENSIONS) return false;\n', ''),),
        ('store', 'transactions')),
    'seventh-actor-refused-not-full': (((PERSISTENCE,
        '        if (!NativeIdentityStore.placeFree(lifecycle, entry.actorClass)) return SuspensionResult.FULL;\n',
        ''),), ('transactions',)),
    # Grant references take every place, so the account's user finds none beside them.
    'grants-take-every-place': (((STORE,
        '        return held < (actorClass == ActorClass.ADMIN_GRANT ? GRANT_PLACES : 1);\n',
        '        return held < (actorClass == ActorClass.ADMIN_GRANT ? NativeIdentityRecords.MAX_SUSPENSIONS : 1);\n'),),
        ('store', 'transactions')),
    # Every entry counts against every class's places, so the account's user loses its own.
    'user-place-taken-by-grants': (((STORE,
        '            if (entry.actorClass == actorClass) ++held;\n', '            ++held;\n'),),
        ('store', 'transactions')),
    'store-place-unchecked': (((STORE,
        '        if (!placeFree(prior, entry.actorClass)) return null;\n', ''),), ('store',)),
    'second-entry-per-actor-written': (((STORE,
        '        for (Suspension held : prior.suspensions) {\n            if (sameActor(held, entry)) return null;\n'
        '        }\n', ''),), ('store',)),
    # A grant's entries are one actor whatever its grant reference.
    'actor-ignores-grant': (((STORE,
        '        return first.actorClass == second.actorClass\n'
        '                && (first.actorClass != ActorClass.ADMIN_GRANT || first.grant.equals(second.grant));\n',
        '        return first.actorClass == second.actorClass;\n'),), ('store', 'transactions')),
    # A lift removes its actor's entry whatever the request names.
    'lift-any-entry-of-its-actor': (((PERSISTENCE,
        '                return held.equals(entry) && store.liftSuspension(slot, record.id, entry);\n',
        '                return store.liftSuspension(slot, record.id, held);\n'),), ('transactions',)),
    'store-lifts-by-class': (((STORE,
        '        if (!prior.suspensions.contains(entry)) return null;\n'
        '        List<Suspension> entries = new ArrayList<>(prior.suspensions);\n        entries.remove(entry);\n',
        '        List<Suspension> entries = new ArrayList<>(prior.suspensions);\n'
        '        if (!entries.removeIf(held -> held.actorClass == entry.actorClass)) return null;\n'),), ('store',)),
    'recovery-hold-lifted-by-store': (((STORE,
        '        if (entry.actorClass == ActorClass.RECOVERY_HOLD) return null;\n', ''),), ('store',)),
    # Suspend or lift move a retiring or retired account back to ELIGIBLE.
    'suspension-resets-state': (((STORE,
        '        entries.sort(NativeIdentityRecords::order);\n'
        '        return new Lifecycle(prior.state, entries, prior.retirement);\n',
        '        entries.sort(NativeIdentityRecords::order);\n'
        '        return new Lifecycle(LifecycleState.ELIGIBLE, entries, null);\n'),), ('store',)),
    'lift-resets-state': (((STORE,
        '        entries.remove(entry);\n        return new Lifecycle(prior.state, entries, prior.retirement);\n',
        '        entries.remove(entry);\n        return new Lifecycle(LifecycleState.ELIGIBLE, entries, null);\n'),),
        ('store',)),
    'recovery-hold-lift-path': (((PERSISTENCE,
        '        if (entry.actorClass == ActorClass.RECOVERY_HOLD) {\n'
        '            throw new IllegalArgumentException("a recovery hold has no lift path in this stage");\n'
        '        }\n', ''),), ('transactions',)),
    'lift-actor-unchecked': (((PERSISTENCE,
        '        if (entry.actorClass == ActorClass.ACCOUNT_USER && (entry.actorUserId != record.userId\n'
        '                || entry.actorSerial != record.userSerial)) {\n'
        '            throw new IllegalArgumentException("an account user entry of another user");\n'
        '        }\n', ''),), ('transactions',)),
    # Store transitions: the state only moves forward, entries change only through suspend and lift,
    # a written block is fixed except a legacy marker's inventory continuation, and no user leaves.
    'retire-from-any-state': (((STORE,
        '        } else if (prior.state != LifecycleState.ELIGIBLE) {\n'
        '            // The state only moves forward, and a written block never changes.\n'
        '            return null;\n        }\n', '        }\n'),), ('store', 'transactions')),
    'legacy-marker-created': (((STORE,
        '            if (prior.state != LifecycleState.RETIRING) return null;\n'
        '            if (!prior.retirement.obligations.isEmpty()) return null;\n',
        '            if (prior.retirement != null && !prior.retirement.obligations.isEmpty()) return null;\n'),),
        ('store', 'transactions')),
    'inventory-continued-again': (((STORE,
        '            if (!prior.retirement.obligations.isEmpty()) return null;\n', ''),), ('store',)),
    'retired-from-any-state': (((STORE,
        '        if (!writableReceipts(receipts) || prior.state != LifecycleState.RETIRING) return null;\n',
        '        if (!writableReceipts(receipts) || prior.state == LifecycleState.ELIGIBLE) return null;\n'),),
        ('store',)),
    'unknown-inventory-retired': (((STORE, '        if (held.obligations.isEmpty()) return null;\n', ''),),
                                  ('store', 'transactions')),
    'orphaned-kind-discharged': (((STORE,
        '            if (duty.state != ObligationState.OUTSTANDING) return null;\n', ''),), ('store', 'transactions')),
    'reference-bound-again': (((STORE,
        '            if (!duty.reference.equals(NativeIdentityRecords.NO_REFERENCE)\n'
        '                    && !duty.reference.equals(receipt.reference)) return null;\n', ''),),
        ('store', 'transactions')),
    'discharged-kind-changed': (((STORE,
        '                if (!duty.equals(receipt)) return null;\n                continue;\n',
        '                obligations.set(index, receipt);\n                continue;\n'),), ('store',)),
    'retired-drops-entries': (((STORE,
        '        return new Lifecycle(LifecycleState.RETIRED, prior.suspensions, new Retirement(\n',
        '        return new Lifecycle(LifecycleState.RETIRED, List.of(), new Retirement(\n'),),
        ('store', 'transactions')),
    # The new marker keeps every entry, unlike the version 1 marker's path under this format.
    'retiring-drops-entries': (((STORE,
        '        return new Lifecycle(LifecycleState.RETIRING, prior.suspensions, retirement);\n',
        '        return new Lifecycle(LifecycleState.RETIRING, List.of(), retirement);\n'),),
        ('store', 'transactions')),
    'retired-block-changed': (((STORE,
        '                held.actorClass, held.actorUserId, held.actorSerial, held.grant, held.time,\n',
        '                held.actorClass, held.actorUserId, held.actorSerial, held.grant, held.time + 1,\n'),),
        ('store', 'transactions')),
    # The generic update under Format.V3 keeps version 1's rule, which allows RETIRED back to
    # RETIRING, entries added or lifted, a changed block and a retired user dropped.
    'v3-update-keeps-version-1-rule': (((STORE,
        '        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION) {\n',
        '        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION || !transition) {\n'),), ('store',)),
    'v3-update-changes-lifecycles': (((STORE,
        '        return changed <= (transition ? 1 : 0);\n', '        return true;\n'),), ('store',)),
    'user-leaves-slot': (((STORE,
        '            if (current == null) return false;\n', '            if (current == null) continue;\n'),), ('store',)),
    # The generic update binds the principal to another incarnation of its user.
    'v3-update-ignores-serial': (((STORE,
        '            if (current.userId != prior.userId\n                    || current.userSerial != prior.userSerial) return false;\n',
        '            if (current.userId != prior.userId) return false;\n'),), ('store',)),
    # The generic update adds, changes or drops a tombstone's release ticket.
    'v3-update-changes-ticket': (((STORE,
        '        if (!Objects.equals(expected.ticket, next.ticket)) return false;\n', ''),), ('store',)),
    # A transition at the last generation overflows instead of refusing.
    'last-generation-overflows': (((STORE,
        '        if (next == null || expected.generation == Long.MAX_VALUE) return false;\n',
        '        if (next == null) return false;\n'),), ('store',)),
    # Refusals: the earlier formats, and the version 1 marker and release under the lifecycle format.
    'lifecycle-format-everywhere': (((PERSISTENCE,
        '        return store.format().slotCeiling >= VERSION_2;\n', '        return true;\n'),), ('transactions',)),
    'lift-under-earlier-formats': (((PERSISTENCE,
        '        if (!lifecycleFormat()) return false;\n        Slot slot = bound(store.load(), record);\n'
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        for (Suspension held : slot.users.get(0).lifecycle.suspensions) {\n',
        '        Slot slot = bound(store.load(), record);\n'
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        for (Suspension held : slot.users.get(0).lifecycle.suspensions) {\n'),), ('transactions',)),
    'version-1-marker-under-v3': (((PERSISTENCE,
        '        Set<String> signers = signers(expectedSigners);\n        if (lifecycleFormat()) return false;\n',
        '        Set<String> signers = signers(expectedSigners);\n'),), ('transactions',)),
    'version-1-release-under-v3': (((PERSISTENCE,
        '        if (record.userId != USER_SYSTEM) return false;\n        if (lifecycleFormat()) return false;\n',
        '        if (record.userId != USER_SYSTEM) return false;\n'),), ('transactions',)),
    # Publication refuses a suspended binding itself, before the header completes, and not in the
    # shared slot confirmation that retirement and header phase changes also use.
    'publication-admits-suspended': (((PERSISTENCE, _PUBLISH_CHECK, _PUBLISH_RETIRING),), ('transactions',)),
    'publication-check-in-confirmation': (((PERSISTENCE, _PUBLISH_CHECK, _PUBLISH_RETIRING),
        (STORE, _CONFIRM_HEAD, _CONFIRM_HEAD
         + '        for (UserEntry user : expected.users) if (!user.lifecycle.suspensions.isEmpty()) return false;\n')),
        ('store', 'transactions')),
    # Continuation: each retry of durable state confirms it, never refuses it or writes it twice.
    'repeated-suspension-not-confirmed': (((PERSISTENCE,
        '            if (!store.confirmExistingSlot(slot)) return SuspensionResult.REFUSED;\n',
        '            if (!store.addSuspension(slot, record.id, entry)) return SuspensionResult.REFUSED;\n'),),
        ('transactions', 'faults')),
    # A repeat that differs from the held entry reports it as this request's entry, or refuses it.
    'differing-repeat-reported-as-suspended': (((PERSISTENCE,
        '            return held.equals(entry) ? SuspensionResult.SUSPENDED : SuspensionResult.HELD_UNCHANGED;\n',
        '            return SuspensionResult.SUSPENDED;\n'),), ('transactions', 'faults')),
    'differing-repeat-refused': (((PERSISTENCE,
        '            return held.equals(entry) ? SuspensionResult.SUSPENDED : SuspensionResult.HELD_UNCHANGED;\n',
        '            return held.equals(entry) ? SuspensionResult.SUSPENDED : SuspensionResult.REFUSED;\n'),),
        ('transactions', 'faults')),
    'lift-retry-refused': (((PERSISTENCE,
        '            }\n        }\n        return store.confirmExistingSlot(slot);\n    }\n\n    /**\n     * The retire transaction',
        '            }\n        }\n        return false;\n    }\n\n    /**\n     * The retire transaction'),),
        ('transactions', 'faults')),
    'retiring-retry-refused': (((PERSISTENCE,
        '        if (lifecycle.state == LifecycleState.RETIRING && retirement.equals(lifecycle.retirement)) {\n'
        '            return store.confirmExistingSlot(slot);\n        }\n', ''),), ('transactions', 'faults')),
    'retired-retry-refused': (((PERSISTENCE,
        '        if (lifecycle.state == LifecycleState.RETIRED) {\n'
        '            return lifecycle.retirement.obligations.containsAll(copy)\n'
        '                    && store.confirmExistingSlot(slot);\n        }\n', ''),), ('transactions', 'faults')),
    # P2b boot facts: only an account RETIRED at the boot read, a selected ticketed tombstone and a
    # RELEASING entry whose slot reads as missing are facts.
    'boot-facts-name-retiring': (((PERSISTENCE,
        '                if (user.lifecycle.state == LifecycleState.RETIRED) {\n',
        '                if (user.lifecycle.state != LifecycleState.ELIGIBLE) {\n'),), ('transactions',)),
    'boot-facts-name-unticketed-tombstones': (((PERSISTENCE,
        '                    && read.value.ticket != null) {\n', '                    ) {\n'),), ('transactions',)),
    'boot-facts-releasing-beside-copies': (((PERSISTENCE,
        '                        && read.status == NativeIdentityStore.Status.MISSING) releasing.add(entry.appId);\n',
        '                        && read.status != NativeIdentityStore.Status.VALID) releasing.add(entry.appId);\n'),),
        ('transactions',)),
    # Disposition: a retired boot, every disposition kind at once, scope bit 0, and the obligation
    # transitions DISPOSING to DISCHARGED only, each reference bound once.
    'disposition-outside-retired-boot': (((PERSISTENCE,
        '        if (!lifecycleFormat() || !facts.retiredBoot(record)) return false;\n'
        '        Slot slot = bound(store.load(), record);\n'
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        Lifecycle lifecycle = slot.users.get(0).lifecycle;\n'
        '        if (lifecycle.state == LifecycleState.RETIRED && dispositionBegun(',
        '        if (!lifecycleFormat()) return false;\n'
        '        Slot slot = bound(store.load(), record);\n'
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        Lifecycle lifecycle = slot.users.get(0).lifecycle;\n'
        '        if (lifecycle.state == LifecycleState.RETIRED && dispositionBegun('),), ('transactions',)),
    'disposal-outside-retired-boot': (((PERSISTENCE,
        '        if (!lifecycleFormat() || !facts.retiredBoot(record)) return false;\n'
        '        Slot slot = bound(store.load(), record);\n'
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        Lifecycle lifecycle = slot.users.get(0).lifecycle;\n'
        '        if (lifecycle.state == LifecycleState.RETIRED\n',
        '        if (!lifecycleFormat()) return false;\n'
        '        Slot slot = bound(store.load(), record);\n'
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        Lifecycle lifecycle = slot.users.get(0).lifecycle;\n'
        '        if (lifecycle.state == LifecycleState.RETIRED\n'),), ('transactions',)),
    # One kind moves to DISPOSING alone.
    'disposition-kind-alone': (((STORE,
        '            if (!duty.kind.disposition()) continue;\n'
        '            // Every disposition kind at once, and only from OUTSTANDING.\n',
        '            if (duty.kind != ObligationKind.ANDROID_STATE) continue;\n'
        '            // Every disposition kind at once, and only from OUTSTANDING.\n'),), ('store', 'transactions', 'faults')),
    'disposition-beside-scope-bit-0': (((STORE, '        if (dispositionBlocked(prior)) return null;\n', ''),),
                                       ('store', 'transactions')),
    'disposition-over-orphaned': (((STORE,
        '            boolean outstanding = duty.state == ObligationState.OUTSTANDING;\n',
        '            boolean outstanding = duty.state != ObligationState.DISCHARGED;\n'),),
        ('store', 'transactions')),
    'disposition-from-any-state': (((STORE,
        '        if (prior.state != LifecycleState.RETIRED) return null;\n'
        '        // No writer sets scope bit 0 yet', '        // No writer sets scope bit 0 yet'),), ('store',)),
    'disposal-from-outstanding': (((STORE,
        '            if (duty.state != ObligationState.DISPOSING) return null;\n',
        '            if (duty.state == ObligationState.ORPHANED_WITH_USER) return null;\n'),), ('store', 'transactions')),
    'disposal-over-orphaned': (((STORE,
        '            if (duty.state != ObligationState.DISPOSING) return null;\n',
        '            if (duty.state == ObligationState.OUTSTANDING) return null;\n'),), ('store', 'transactions')),
    'disposal-reference-bound-again': (((STORE,
        '            if (bound && !duty.reference.equals(receipt.reference)) return null;\n', ''),), ('store',)),
    'disposal-discharged-kind-changed': (((STORE,
        '                if (duty.equals(receipt)) continue;\n                return null;\n',
        '                obligations.set(index, receipt);\n                continue;\n'),), ('store',)),
    'disposal-receipts-request-unchecked': (((PERSISTENCE,
        '        if (!NativeIdentityStore.writableDispositionReceipts(copy)) {\n'
        '            throw new IllegalArgumentException("not receipts of disposition kinds");\n'
        '        }\n', ''),), ('transactions',)),
    'store-disposal-receipts-unchecked': (((STORE,
        '        if (!writableDispositionReceipts(receipts) || prior.state != LifecycleState.RETIRED) {\n',
        '        if (prior.state != LifecycleState.RETIRED) {\n'),), ('store',)),
    'disposal-receipt-kinds-unchecked': (((STORE,
        '            if (!receipt.kind.disposition() || receipt.state != ObligationState.DISCHARGED\n',
        '            if (receipt.state != ObligationState.DISCHARGED\n'),), ('store', 'transactions')),
    'disposal-receipt-order-unchecked': (((STORE,
        '                    || receipt.kind.code <= last) return false;\n', '                    ) return false;\n'),),
        ('store', 'transactions')),
    'disposition-retry-refused': (((PERSISTENCE,
        '        if (lifecycle.state == LifecycleState.RETIRED && dispositionBegun(lifecycle.retirement)) {\n'
        '            return store.confirmExistingSlot(slot);\n        }\n', ''),), ('transactions', 'faults')),
    'disposal-retry-refused': (((PERSISTENCE,
        '                && lifecycle.retirement.obligations.containsAll(copy)) {\n'
        '            return store.confirmExistingSlot(slot);\n        }\n'
        '        return store.dischargeSlotDisposition(slot, record.id, copy);\n',
        '                && copy == null) {\n'
        '            return store.confirmExistingSlot(slot);\n        }\n'
        '        return store.dischargeSlotDisposition(slot, record.id, copy);\n'),), ('transactions', 'faults')),
    # Restore: the last known state is the intact copy of the highest generation, held, or ELIGIBLE
    # held with scope bit 1 when no copy is intact; never over another account, a tie or a releasing
    # entry, and its exact retry is a confirmation.
    'restored-without-hold': (((STORE,
        '        entries.add(hold);\n        entries.sort(NativeIdentityRecords::order);\n        UserEntry user =',
        '        entries.sort(NativeIdentityRecords::order);\n        UserEntry user ='),),
        ('store', 'transactions', 'faults')),
    'restore-from-lowest-generation': (((STORE,
        '            if (last == null || copy.generation > last.generation) last = copy;\n',
        '            if (last == null || copy.generation < last.generation) last = copy;\n'),),
        ('store', 'transactions', 'faults')),
    'restore-from-selected-copy': (((STORE,
        '        Slot next = restoration(read.decodedCopies, account, hold);\n',
        '        Slot next = restoration(read.status == Status.VALID ? List.of(read.value) : read.decodedCopies,\n'
        '                account, hold);\n'),), ('store',)),
    'unknown-state-without-scope-bit-1': (((STORE,
        '                    NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN, hold.actorUserId, hold.actorSerial,\n',
        '                    0, hold.actorUserId, hold.actorSerial,\n'),), ('store', 'transactions', 'faults')),
    'known-state-with-scope-bit-1': (((STORE,
        '        entries.add(hold);\n        entries.sort(NativeIdentityRecords::order);\n        UserEntry user =',
        '        entries.add(new Suspension(hold.actorClass, NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN,\n'
        '                hold.actorUserId, hold.actorSerial, hold.grant, hold.reason, hold.time, hold.noteDigest));\n'
        '        entries.sort(NativeIdentityRecords::order);\n        UserEntry user ='),),
        ('store', 'transactions', 'faults')),
    'restore-over-another-account': (((STORE, '            if (!sameAccount(copy, account)) return null;\n', ''),),
                                     ('store',)),
    'restore-chooses-in-a-tie': (((STORE,
        '            if (copy.generation == last.generation && !copy.equals(last)) return null;\n', ''),), ('store',)),
    'restore-past-allotment': (((STORE, '        if (!placeFree(prior, ActorClass.RECOVERY_HOLD)) return null;\n', ''),),
                               ('store',)),
    # Both refusals of RELEASING: in any decoded header copy, and the selected entry's own phase, which
    # the first already covers. The copy loop alone is restore-beside-a-releasing-copy.
    'restore-under-releasing': (((STORE,
        '        for (Header copy : loaded.header.decodedCopies) {\n'
        '            HeaderEntry listed = headerEntry(copy, account.appId);\n'
        '            if (listed != null && listed.phase == SlotPhase.RELEASING) return false;\n        }\n', ''),
        (STORE, '        if (index == null || index.phase == SlotPhase.RELEASING\n', '        if (index == null\n')),
        ('store', 'transactions')),
    'restore-above-counter': (((STORE, '                || account.users.get(0).id > expected.lastId) return false;\n',
                                '                ) return false;\n'),), ('store', 'transactions')),
    'restore-beside-a-claim': (((PERSISTENCE, '        if (claimedElsewhere(loaded, record)) return false;\n', ''),),
                               ('transactions',)),
    # P2c, Restore: the release's narrower claim check, which skips tombstones and matches a
    # reservation only by principal ID, and the selected header's phase alone.
    'restore-claim-as-release': (((PERSISTENCE, '        if (claimedElsewhere(loaded, record)) return false;\n',
                                   '        if (liveElsewhere(loaded, record)) return false;\n'),), ('transactions',)),
    'restore-beside-a-releasing-copy': (((STORE,
        '        for (Header copy : loaded.header.decodedCopies) {\n'
        '            HeaderEntry listed = headerEntry(copy, account.appId);\n'
        '            if (listed != null && listed.phase == SlotPhase.RELEASING) return false;\n        }\n', ''),),
        ('store',)),
    'disposal-signers-unchecked': (((PERSISTENCE,
        '        if (slot == null || !slot.signerSha256.equals(signers)) return false;\n'
        '        Lifecycle lifecycle = slot.users.get(0).lifecycle;\n'
        '        if (lifecycle.state == LifecycleState.RETIRED\n'
        '                && lifecycle.retirement.obligations.containsAll(copy)) {\n',
        '        if (slot == null) return false;\n'
        '        Lifecycle lifecycle = slot.users.get(0).lifecycle;\n'
        '        if (lifecycle.state == LifecycleState.RETIRED\n'
        '                && lifecycle.retirement.obligations.containsAll(copy)) {\n'),), ('transactions',)),
    # The boot facts beside a header copy above the format's ceiling or one that cannot be read: a
    # tombstone fact, or a RETIRED fact taken from a VALID slot without an eligible binding.
    'boot-facts-beside-newer-header': (((PERSISTENCE,
        '                    && loaded.header.status != NativeIdentityStore.Status.UNSUPPORTED\n', ''),),
        ('transactions',)),
    'boot-facts-beside-unreadable-header': (((PERSISTENCE,
        '                    && !loaded.header.unavailable && read.value.users.isEmpty()\n',
        '                    && read.value.users.isEmpty()\n'),), ('transactions',)),
    'boot-facts-retired-without-binding': (((PERSISTENCE,
        '            if (loaded.bindingUsable(appId) && read.value.users.size() == 1) {\n',
        '            if (read.status == NativeIdentityStore.Status.VALID && read.value.users.size() == 1) {\n'),),
        ('transactions',)),
    # P2c, the gated release engine: when it may start, its order, its continuation and its store rules.
    'release-outside-retired-boot': (((PERSISTENCE,
        '        if (!retiredBoot && !tombstoneBoot && !emptiedBoot) return false;\n', ''),
        (PERSISTENCE, '        if (!retiredBoot || !loaded.bindingUsable(appId) || !boundTo(slot, record)\n',
         '        if (!loaded.bindingUsable(appId) || !boundTo(slot, record)\n')), ('transactions',)),
    'release-beside-a-suspension': (((STORE,
        '        if (lifecycle.state != LifecycleState.RETIRED || !lifecycle.suspensions.isEmpty()\n',
        '        if (lifecycle.state != LifecycleState.RETIRED\n'),), ('store', 'transactions')),
    'release-with-an-open-obligation': (((STORE,
        '            if (duty.state != ObligationState.DISCHARGED) return false;\n',
        '            if (duty.state == ObligationState.OUTSTANDING) return false;\n'),), ('store', 'transactions')),
    # A step out of order: the tombstone before the key namespace, or the key namespace before a
    # CREATING entry completes.
    'release-tombstone-before-key-clear': (((PERSISTENCE,
        '        if (!capability.keys.clear(uid)) return false;\n'
        '        return store.dropReleasedUser(slot, record.id, ticket)\n'
        '                && store.markSlotReleasing(live, appId)\n',
        '        if (!store.dropReleasedUser(slot, record.id, ticket) || !capability.keys.clear(uid)) return false;\n'
        '        return store.markSlotReleasing(live, appId)\n'),), ('transactions',)),
    'release-keys-before-creating-completes': (((PERSISTENCE,
        '        if (entry.phase == SlotPhase.CREATING && !store.writeHeader(header, live)) return false;\n'
        '        if (!capability.keys.clear(uid)) return false;\n',
        '        if (!capability.keys.clear(uid)) return false;\n'
        '        if (entry.phase == SlotPhase.CREATING && !store.writeHeader(header, live)) return false;\n'),),
        ('transactions',)),
    'release-skips-key-clear': (((PERSISTENCE, '        if (!capability.keys.clear(uid)) return false;\n', ''),),
                                ('transactions',)),
    'release-before-creating-completes': (((PERSISTENCE,
        '        if (entry.phase == SlotPhase.CREATING && !store.writeHeader(header, live)) return false;\n', ''),),
        ('transactions',)),
    # Continuation from memory: the boot that wrote the tombstone continues it, without the next boot's
    # facts.
    'release-continues-from-memory': (((PERSISTENCE,
        '            if (!tombstoneBoot || entry.phase != SlotPhase.LIVE) return false;\n',
        '            if (entry.phase != SlotPhase.LIVE) return false;\n'),
        (PERSISTENCE, '            if (!tombstoneBoot && !emptiedBoot) return false;\n', '')), ('transactions', 'faults')),
    # Every remaining copy is this account's binding or its tombstone with this ticket.
    'release-copies-unchecked': (((PERSISTENCE,
        '        for (Slot copy : read.decodedCopies) {\n'
        '            if (!releaseCopy(copy, record, expectedLineage, signers, ticket)) return false;\n'
        '        }\n', ''),), ('transactions',)),
    # During a continuation the counter and the sibling check are the only guards.
    'continuation-above-counter': (((PERSISTENCE, '        if (header.lastId < record.id) return false;\n', ''),),
                                   ('transactions',)),
    'continuation-beside-a-live-binding': (((PERSISTENCE,
        '        if (liveElsewhere(loaded, record)) return false;\n', ''),), ('transactions',)),
    'continuation-ticket-unchecked': (((PERSISTENCE,
        '                && (copy.users.isEmpty() ? ticket.equals(copy.ticket)\n',
        '                && (copy.users.isEmpty() ? copy.ticket != null\n'),), ('transactions',)),
    # User 134217728 wraps to user 0's UID in int arithmetic.
    'ticket-uid-unchecked': (((PERSISTENCE,
        '        long uid = (long) ticket.userId * PER_USER_RANGE + appId;\n'
        '        return uid > Integer.MAX_VALUE ? -1 : (int) uid;\n',
        '        return ticket.userId * PER_USER_RANGE + appId;\n'),), ('transactions',)),
    'removal-of-unknown-files': (((STORE,
        '                if (!allowed.contains(file.getName()) || node(file) != Node.FILE) return false;\n',
        '                if (node(file) != Node.FILE) return false;\n'),), ('transactions',)),
    'releasing-without-ticket-under-v3': (((STORE,
        '                if (format.slotCeiling >= LIFECYCLE_SLOT_VERSION && slot.value.ticket == null) return false;\n',
        ''),), ('store',)),
    'generic-header-write-releases': (((STORE,
        '        if (format.slotCeiling >= LIFECYCLE_SLOT_VERSION && releases(expected, next)) return false;\n', ''),),
        ('store',)),
    # The generic update takes the release engine's drop.
    'generic-update-is-the-drop': (((STORE, '        return writeExistingSlot(expected, next, false, false);\n',
                                     '        return writeExistingSlot(expected, next, false, true);\n'),), ('store',)),
    # P2c, tickets: a ticket's principal ID as sibling evidence, in a valid tombstone and in an
    # unsupported record's decoded copy, as a reservation's claim, and for the counter bound.
    'ticket-not-sibling-evidence': (((STORE,
        '                    previous = incarnations.putIfAbsent(slot.ticket.lastId, entry.getKey());\n',
        '                    previous = null;\n'),), ('store',)),
    'unsupported-ticket-not-evidence': (((STORE,
        '                    if (copy.ticket != null) incarnations.putIfAbsent(copy.ticket.lastId, entry.getKey());\n',
        ''),), ('store',)),
    'ticket-not-claimed': (((STORE,
        '                if (claim.ticket != null && claim.ticket.lastId == creation.creationId) return true;\n', ''),),
        ('store',)),
    'ticket-above-counter-ignored': (((STORE,
        '        return copy.ticket != null && copy.ticket.lastId > counter;\n', '        return false;\n'),),
        ('store',)),
    'release-primitives-under-earlier-formats': (((STORE,
        '        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION || entry == null\n'
        '                || entry.phase != SlotPhase.LIVE) return false;\n',
        '        if (entry == null\n                || entry.phase != SlotPhase.LIVE) return false;\n'),
        (STORE, '        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION || entry == null\n'
                '                || entry.phase != SlotPhase.RELEASING) return false;\n',
         '        if (entry == null\n                || entry.phase != SlotPhase.RELEASING) return false;\n')), ('store',)),
    'recovery-hold-request-unchecked': (((PERSISTENCE,
        '        if (!NativeIdentityStore.writableRecoveryHold(hold)) {\n'
        '            throw new IllegalArgumentException("recovery hold outside the writer rules");\n'
        '        }\n', ''),), ('transactions',)),
    'store-recovery-hold-unchecked': (((STORE,
        '        if (!writableRecoveryHold(hold) || account.generation != 1 || account.users.size() != 1\n',
        '        if (account.generation != 1 || account.users.size() != 1\n'),), ('store',)),
    'recovery-hold-reason-unchecked': (((STORE,
        '        return reason != null && reason.actors.contains(ActorClass.RECOVERY_HOLD);\n', '        return true;\n'),),
        ('store', 'transactions')),
    'recovery-hold-scope-unchecked': (((STORE,
        '        if (hold.actorClass != ActorClass.RECOVERY_HOLD || hold.scope != 0) return false;\n',
        '        if (hold.actorClass != ActorClass.RECOVERY_HOLD) return false;\n'),), ('store', 'transactions')),
    'restore-keeps-the-backup-rule': (((STORE,
        '        if (preferred != Node.ABSENT && !(restore && preferred == Node.FILE)) {\n',
        '        if (preferred != Node.ABSENT) {\n'),),
        ('store', 'transactions', 'faults')),
    'restore-retry-not-confirmed': (((STORE,
        '                && recoveryHeld(read.value) && next.equals(advanced(read.value))) {\n',
        '                && recoveryHeld(read.value) && next == null) {\n'),), ('store', 'transactions', 'faults')),
    'restore-under-earlier-formats': (((PERSISTENCE,
        '        if (!lifecycleFormat() || record.userId != USER_SYSTEM) return false;\n',
        '        if (record.userId != USER_SYSTEM) return false;\n'),
        (STORE, '        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION) return false;\n'
                '        if (writeInspectionBlocked(account.appId)) return false;\n',
         '        if (writeInspectionBlocked(account.appId)) return false;\n'),
        (STORE, '        if (next == null || next.version > format.slotCeiling) return false;\n',
         '        if (next == null) return false;\n')), ('store', 'transactions')),
    # The manager: every lifecycle operation refuses under an earlier format before any effect, the
    # suspension closes admission in memory before its write and keeps it, and every activation point
    # refuses a suspended account.
    'manager-lifecycle-under-earlier-formats': (((MANAGER,
        '        if (!persistence.lifecycleFormat()) {\n'
        '            throw new IllegalStateException("Native lifecycle records need the lifecycle format");\n'
        '        }\n', ''),), ('manager',)),
    'manager-retirement-pin-before-the-format': (((MANAGER,
        '                if (retirement != null) {\n                    lifecycle(handle);\n',
        '                if (retirement != null) {\n'),
        (MANAGER, '                pins.beginRetire(handle.pin);\n',
         '                pins.beginRetire(handle.pin);\n                if (retirement != null) lifecycle(handle);\n')),
        ('manager',)),
    'manager-closure-after-the-write': (((MANAGER,
        '                close(handle);\n            }\n'
        '            NativeIdentityPersistence.SuspensionResult result =\n'
        '                    persistence.suspend(record, handle.storedSignerSha256, entry);\n',
        '            }\n'
        '            NativeIdentityPersistence.SuspensionResult result =\n'
        '                    persistence.suspend(record, handle.storedSignerSha256, entry);\n'
        '            if (result == NativeIdentityPersistence.SuspensionResult.SUSPENDED) {\n'
        '                synchronized (pm.mLock) { close(handle); }\n'
        '            }\n'),), ('manager',)),
    'manager-closure-without-deferral': (((MANAGER,
        '        pm.mSettings.deferNativePackage(record.packageName, setting == null ? null : setting.getPath());\n',
        ''),), ('manager',)),
    'manager-closure-unmarked': (((MANAGER, '        handle.suspended = true;\n', ''),), ('manager',)),
    'prepare-admits-suspended': (((MANAGER, '                    requireAdmissible(selection.prepared);\n', ''),
                                  (MANAGER, '                requireAdmissible(prepared);\n', '')), ('manager',)),
    'commit-admits-suspended': (((MANAGER,
        '                NativePrincipalPins pins = checked(handle);\n                requireAdmissible(handle);\n',
        '                NativePrincipalPins pins = checked(handle);\n'),), ('manager',)),
    'current-identity-admits-closed': (((MANAGER,
        '            requireOpen(handle);\n            if (handle.pin.phase() != NativePrincipalPins.Phase.ACTIVE) {\n',
        '            if (handle.pin.phase() != NativePrincipalPins.Phase.ACTIVE) {\n'),), ('manager',)),
    'published-binding-admits-suspended': (((MANAGER,
        '            if (user.id == handle.pin.record().id && !active(user.lifecycle)) {\n',
        '            if (user.id == handle.pin.record().id && user.retiring) {\n'),), ('manager',)),
    # The manager's release gate: the boot facts are this instance's, recorded once from its boot read,
    # and never the cached view; a suspension closed in memory refuses; and only an acknowledged
    # omission lets Settings' release finish, the pin's end and the refresh follow.
    'manager-release-ignores-the-closure': (((MANAGER,
        '                requireRetiring(handle);\n                requireOpen(handle);\n',
        '                requireRetiring(handle);\n'),), ('manager',)),
    'manager-release-boot-facts-from-the-cached-view': (((MANAGER,
        '                facts = pm.mSettings.nativeBootFactsLPr();\n                ticket = ticket(handle);\n',
        '                facts = NativeIdentityPersistence.bootFacts(pm.mSettings.mNativeIdentityLoaded);\n'
        '                ticket = ticket(handle);\n'),), ('manager',)),
    'manager-disposition-boot-facts-from-the-cached-view': (((MANAGER,
        '                facts = pm.mSettings.nativeBootFactsLPr();\n            }\n'
        '            boolean durable = persistence.beginDisposition(',
        '                facts = NativeIdentityPersistence.bootFacts(pm.mSettings.mNativeIdentityLoaded);\n            }\n'
        '            boolean durable = persistence.beginDisposition('),), ('manager',)),
    'manager-release-before-the-acknowledgement': (((MANAGER,
        '                if (!durable) return false;\n'
        '                pm.mSettings.finishNativeIdentityReleaseLPw(handle.pin.record(), observed);\n'
        '                pins.finishRelease(handle.pin);\n',
        '                pm.mSettings.finishNativeIdentityReleaseLPw(handle.pin.record(), observed);\n'
        '                pins.finishRelease(handle.pin);\n'),), ('manager',)),
    'manager-release-keeps-the-history': (((MANAGER,
        '                pm.mSettings.finishNativeIdentityReleaseLPw(handle.pin.record(), observed);\n'
        '                pins.finishRelease(handle.pin);\n',
        '                pins.finishRelease(handle.pin);\n'),), ('manager',)),
    'manager-release-keeps-the-pin': (((MANAGER, '                pins.finishRelease(handle.pin);\n', ''),),
                                      ('manager',)),
    # The manager's store reads run with no PMS state lock held: a load moved under it fails the
    # manager suite through the lock seam of its store copy.
    'manager-reads-under-the-pms-lock': (((MANAGER,
        '        NativeIdentityStore.Loaded observed = persistence.load();\n'
        '        synchronized (pm.mLock) {\n'
        '            pm.mSettings.observeNativeIdentityStoreLPw(observed);\n',
        '        synchronized (pm.mLock) {\n'
        '            NativeIdentityStore.Loaded observed = persistence.load();\n'
        '            pm.mSettings.observeNativeIdentityStoreLPw(observed);\n'),), ('manager',)),
    'manager-release-reads-under-the-pms-lock': (((MANAGER,
        '                    handle.storedSignerSha256, ticket, capability, facts);\n'
        '            NativeIdentityStore.Loaded observed = persistence.load();\n'
        '            synchronized (pm.mLock) {\n',
        '                    handle.storedSignerSha256, ticket, capability, facts);\n'
        '            synchronized (pm.mLock) {\n'
        '                NativeIdentityStore.Loaded observed = persistence.load();\n'),), ('manager',)),
}


# ---------------------------------------------------------------- release stays unreachable

# The release capability. Every class lives in one Java package, so access rules cannot stop its
# construction. No production text constructs it, references its constructor, takes its class
# literal or names it in a string. Among every other Java text only the release engine's named
# tests construct it, and the manager's lifecycle test, which drives the manager's gated release.
CAPABILITY_USES = (('construction', r'\bnew\s+(?:[\w$]+\s*\.\s*)*ReleaseCapability\s*\('),
                   ('constructor reference', r'\bReleaseCapability\s*::\s*new\b'),
                   ('class literal', r'\bReleaseCapability\s*\.\s*class\b'),
                   ('name string', r'"(?:[^"\\\n]|\\.)*ReleaseCapability(?:[^"\\\n]|\\.)*"'))
CAPABILITY_TESTS = tuple(PLATFORM + name + '.java' for name in (SUPPORT, TRANSACTION_TEST, FAULT_TEST, MANAGER_TEST))
# The release entry points: the persistence release and the store primitives that only release uses,
# which remove a releasing slot, confirm a released slot, write RELEASING, write the omission and drop
# a user. No production text calls or references one outside the release bodies of the persistence:
# the release engine, and the version 1 release finishRetirement until P6 retires it. Settings' release
# finish and the old release path join in P3: the manager's finishRetirementAfterQuiescence, the pins'
# finishRetire and the persistence's finishRetirement. The manager's releaseUid and the pins'
# finishRelease join in P4: only the manager's gated release calls the engine, Settings' release finish
# and the pins' finishRelease, and no production text calls releaseUid.
RELEASE_ENTRY_POINTS = ('release', 'removeReleasingSlot', 'confirmReleasedSlot', 'markSlotReleasing',
                        'omitReleasedSlot', 'dropReleasedUser', 'finishNativeIdentityReleaseLPw',
                        'finishRetirementAfterQuiescence', 'finishRetire', 'finishRetirement',
                        'releaseUid', 'finishRelease')
RELEASE_BODIES = ('    boolean release(NativePrincipalPins.Record record, String expectedLineage,',
                  '    boolean finishRetirement(NativePrincipalPins.Record record, String expectedLineage,')
# The store's own release powers behind the named primitives: writeAnyHeader, which makes RELEASING
# and omission writes, and the drop flag of the existing slot writer. Only the generic header write
# and the two named header writes call writeAnyHeader, and only dropReleasedUser passes the drop flag,
# the last argument of writeExistingSlot, as anything but the literal false.
ANY_HEADER_CALLERS = ('    boolean writeHeader(Header expected, Header next) {',
                      '    boolean markSlotReleasing(Header expected, int appId) {',
                      '    boolean omitReleasedSlot(Header expected, int appId) {')
DROP_CALLERS = ('    boolean dropReleasedUser(Slot expected, long id, ReleaseTicket ticket) {',)
# The boot facts are the evidence of a retired boot. Only Settings' boot facts fragment builds them,
# from the boot read, and the host facade carries that fragment verbatim. No other production text
# calls or references bootFacts, so no class can admit a boot from a fresh read. Among the other Java
# texts, only the facade through that fragment and the release engine's named tests do.
BOOT_FACTS_FRAGMENT = 'boot-facts'
BOOT_FACTS_TESTS = tuple(PLATFORM + name + '.java' for name in (SUPPORT, TRANSACTION_TEST, FAULT_TEST))
# The manager's other lifecycle operations have no production caller: their callers come in later
# steps, the account authority's retirement and suspension, the disposition owners and the recovery
# route. No production text calls or references them, or the persistence transactions of the same
# operations, outside the manager body of that operation. The old retirement's beginRetirement has no
# production caller either.
LIFECYCLE_ENTRY_POINTS = ('suspend', 'lift', 'beginRetirement', 'markRetiring', 'confirmRetired', 'markRetired',
                          'beginDisposition', 'confirmDisposition')
LIFECYCLE_ALLOWANCES = (
    ('suspend', MANAGER, '    NativeIdentityPersistence.SuspensionResult suspend(Handle handle,'),
    ('markRetiring', MANAGER, '    private boolean retire(Handle handle, NativeIdentityRecords.Retirement retirement) {'),
    ('lift', MANAGER, '    boolean lift(Handle handle, NativeIdentityRecords.Suspension entry) {'),
    ('markRetired', MANAGER,
     '    boolean confirmRetired(Handle handle, java.util.List<NativeIdentityRecords.Obligation> receipts) {'),
    ('beginDisposition', MANAGER, '    boolean beginDisposition(Handle handle) {'),
    ('confirmDisposition', MANAGER, '    boolean confirmDisposition(Handle handle,'))
UNREACHABLE_RULES = ('capability', 'release', 'primitives', 'boot-facts', 'lifecycle')
NON_NATIVE = FRAMEWORK_DIR + 'CeStorageAccessTracker.java'
# The old release path stays reachable until P6 retires it. Each allowance names an entry point, the
# production text and the one body there that may call it today. P6 removes every allowance.
OLD_RELEASE_BODY = '    public boolean finishRetirementAfterQuiescence(Handle handle) {'
P6_RELEASE_ALLOWANCES = (('finishRetirement', MANAGER, OLD_RELEASE_BODY),
                         ('finishNativeIdentityReleaseLPw', MANAGER, OLD_RELEASE_BODY),
                         ('finishRetire', MANAGER, OLD_RELEASE_BODY))
# The manager's gated release, which stays: the one body that calls the release engine, Settings'
# release finish and the pins' finishRelease, in the plan's order. Nothing in production calls it.
RELEASE_BODY = '    boolean releaseUid(Handle handle, NativeIdentityPersistence.ReleaseCapability capability) {'
RELEASE_ALLOWANCES = (('release', MANAGER, RELEASE_BODY),
                      ('finishNativeIdentityReleaseLPw', MANAGER, RELEASE_BODY),
                      ('finishRelease', MANAGER, RELEASE_BODY))


def other_java_texts(production):
    """Every Java text of the repository's own sources that is not a production text, by path."""
    texts = {}
    for top in ('owner', 'tests', 'scripts'):
        for path in sorted((ROOT / top).rglob('*.java')):
            name = path.relative_to(ROOT).as_posix()
            if name not in production:
                texts[name] = path.read_text()
    return texts


def body_spans(code, heads):
    """The offsets of each named method's body in comment free text, from its opening brace through
    the brace that closes it. A head that does not occur exactly once gives no span."""
    spans = []
    for head in heads:
        if code.count(head) != 1:
            continue
        start = code.index('{', code.index(head))
        depth, index = 0, start
        while index < len(code):
            depth += {'{': 1, '}': -1}.get(code[index], 0)
            index += 1
            if depth == 0:
                spans.append((start, index))
                break
    return spans


def unreachable_violations(texts, others):
    """Every violation of "Release stays unreachable", as 'rule: detail'.

    capability: a production text constructs the release capability, references its constructor,
    takes its class literal or names it in a string, or another Java text does so outside the
    release engine's named tests. release: a production text calls or references a release entry
    point outside the release bodies of the persistence. primitives: the store calls writeAnyHeader,
    or passes writeExistingSlot's drop flag, outside the bodies that may. A declaration is no call.
    Comments are not code."""
    problems = []
    for group, names in ((texts, None), (others, CAPABILITY_TESTS)):
        for name, raw in group.items():
            if names is not None and name in names:
                continue
            code = b1.strip_java_comments(raw)
            for what, pattern in CAPABILITY_USES:
                for found in re.finditer(pattern, code):
                    problems.append('capability: %s holds a %s of the release capability: %s'
                                    % (name, what, ' '.join(found.group(0).split())))
    for name, raw in texts.items():
        code = b1.strip_java_comments(raw)
        allowed = body_spans(code, RELEASE_BODIES) if name == PERSISTENCE else []
        if name == PERSISTENCE and len(allowed) != len(RELEASE_BODIES):
            problems.append('release: the release bodies of %s are not each found once' % name)
        for entry in RELEASE_ENTRY_POINTS:
            spans = list(allowed)
            for allowed_entry, holder, body in P6_RELEASE_ALLOWANCES + RELEASE_ALLOWANCES:
                if allowed_entry == entry and holder == name:
                    found_body = body_spans(code, (body,))
                    if not found_body:
                        problems.append('release: the allowed body of %s in %s is not found once' % (entry, name))
                    spans += found_body
            pattern = r'(?:\.\s*|::\s*|(?<![\w$.:]))%s\b(?=\s*\()|::\s*%s\b' % (entry, entry)
            for found in re.finditer(pattern, code):
                line = code[code.rfind('\n', 0, found.start()) + 1:found.start()]
                if re.fullmatch(r'\s*(?:(?:public|protected|private|static|final|synchronized)\s+)*'
                                r'(?:boolean|void)\s+', line):
                    continue  # Its declaration.
                if any(start <= found.start() < end for start, end in spans):
                    continue
                problems.append('release: %s calls or references %s outside the release bodies' % (name, entry))
    if STORE in texts:
        problems += primitive_violations(texts[STORE])
    problems += boot_facts_violations(texts, others)
    problems += lifecycle_violations(texts)
    return problems


def lifecycle_violations(texts):
    """'lifecycle: detail' for each call or method reference of a manager lifecycle operation, or of the
    persistence transaction it wraps, in a production text outside the manager body of that operation.
    A declaration is no call. Comments are not code."""
    problems = []
    declaration = (r'\s*(?!(?:return|throw|new|else|case|yield|assert|do)\b)'
                   r'(?:(?:public|protected|private|static|final|synchronized)\s+)*'
                   r'[\w$.]+(?:<[^;(){}]*>)?\s+')
    for name, raw in texts.items():
        code = b1.strip_java_comments(raw)
        for entry in LIFECYCLE_ENTRY_POINTS:
            spans = []
            for allowed_entry, holder, body in LIFECYCLE_ALLOWANCES:
                if allowed_entry == entry and holder == name:
                    found_body = body_spans(code, (body,))
                    if not found_body:
                        problems.append('lifecycle: the allowed body of %s in %s is not found once' % (entry, name))
                    spans += found_body
            pattern = r'(?:\.\s*|::\s*|(?<![\w$.:]))%s\b(?=\s*\()|::\s*%s\b' % (entry, entry)
            for found in re.finditer(pattern, code):
                line = code[code.rfind('\n', 0, found.start()) + 1:found.start()]
                if re.fullmatch(declaration, line):
                    continue  # Its declaration.
                if any(start <= found.start() < end for start, end in spans):
                    continue
                problems.append('lifecycle: %s calls or references %s outside its manager body' % (name, entry))
    return problems


def boot_facts_violations(texts, others):
    """'boot-facts: detail' for each call or method reference of bootFacts outside Settings' boot facts
    fragment: in a production text anywhere but that fragment in the Settings section, and in another
    Java text anywhere but that fragment in the host facade and the release engine's named tests. The
    Settings section and the facade each hold the fragment once. A declaration is no call. Comments
    are not code."""
    fragment = b1.strip_java_comments(integration.FRAGMENTS[BOOT_FACTS_FRAGMENT][1].read_text())
    problems = []
    for group, holders in ((texts, (b1.SETTINGS_SECTION,)), (others, (FACADE,))):
        for name in holders:
            if b1.strip_java_comments(group.get(name, '')).count(fragment) != 1:
                problems.append('boot-facts: %s does not hold the boot facts fragment once' % name)
        for name, raw in group.items():
            if group is others and name in BOOT_FACTS_TESTS:
                continue
            code = b1.strip_java_comments(raw)
            allowed = []
            if name in holders and code.count(fragment) == 1:
                start = code.index(fragment)
                allowed.append((start, start + len(fragment)))
            for found in re.finditer(r'(?:\.\s*|::\s*|(?<![\w$.:]))bootFacts\b(?=\s*\()|::\s*bootFacts\b', code):
                line = code[code.rfind('\n', 0, found.start()) + 1:found.start()]
                if name == PERSISTENCE and re.fullmatch(r'\s*static\s+BootFacts\s+', line):
                    continue  # Its declaration.
                if any(start <= found.start() < end for start, end in allowed):
                    continue
                problems.append('boot-facts: %s calls or references bootFacts outside the boot facts fragment' % name)
    return problems


def call_arguments(code, offset):
    """The top level arguments of the call whose opening parenthesis is at offset, stripped."""
    depth, start, arguments, index = 0, offset + 1, [], offset
    while index < len(code):
        char = code[index]
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
            if depth == 0:
                arguments.append(code[start:index].strip())
                return arguments
        elif char == ',' and depth == 1:
            arguments.append(code[start:index].strip())
            start = index + 1
        index += 1
    return arguments


def primitive_violations(store):
    """'primitives: detail' for each call of the store's own release powers outside the bodies that
    may make it: writeAnyHeader outside the generic and the two named header writes, and a drop flag
    other than the literal false outside dropReleasedUser. A method reference of either writer is
    refused anywhere in the store, because no body that may use them takes one."""
    code = b1.strip_java_comments(store)
    problems = []
    any_header, drop = body_spans(code, ANY_HEADER_CALLERS), body_spans(code, DROP_CALLERS)
    if len(any_header) != len(ANY_HEADER_CALLERS) or len(drop) != len(DROP_CALLERS):
        problems.append('primitives: the bodies that may use the release powers are not each found once')
    for found in re.finditer(r'(?<![\w$])writeAnyHeader\s*\(', code):
        line = code[code.rfind('\n', 0, found.start()) + 1:found.start()]
        if re.fullmatch(r'\s*private\s+boolean\s+', line):
            continue  # Its declaration.
        if not any(start <= found.start() < end for start, end in any_header):
            problems.append('primitives: writeAnyHeader is called outside the header writes that may')
    for found in re.finditer(r'(?<![\w$])writeExistingSlot\s*\(', code):
        line = code[code.rfind('\n', 0, found.start()) + 1:found.start()]
        if re.fullmatch(r'\s*private\s+boolean\s+', line):
            continue
        arguments = call_arguments(code, found.end() - 1)
        if (len(arguments) != 4 or arguments[3] != 'false') and not any(
                start <= found.start() < end for start, end in drop):
            problems.append('primitives: writeExistingSlot passes the drop flag outside dropReleasedUser')
    for found in re.finditer(r'::\s*(writeAnyHeader|writeExistingSlot)\b', code):
        problems.append('primitives: %s is referenced as a method' % found.group(1))
    return problems


def unreachable_rules(texts, others):
    return {problem.split(':', 1)[0] for problem in unreachable_violations(texts, others)}


def unreachable_mutants():
    """Release reachability defects, each with the exact set of rules it must trip: the capability in
    the Settings section, in a framework file outside the native sources and in a test that is not
    allowed, a call or reference of each release entry point, each of the store's own release powers
    used outside the bodies that may or referenced as a method, and boot facts built outside Settings'
    boot facts fragment: from a fresh read in the manager, again in the Settings section and in a
    test that is not allowed."""
    texts = b1.production_texts()
    others = other_java_texts(texts)
    settings = b1.SETTINGS_SECTION
    store_test = PLATFORM + STORE_TEST + '.java'

    def changed(*edits):
        production, other = dict(texts), dict(others)
        for name, old, new in edits:
            target = production if name in production else other
            target[name] = b1.replace_once(target[name], old, new) if old else target[name] + new
        return production, other

    tracker = 'public final class CeStorageAccessTracker {\n'
    manager = '    public boolean finishRetirementAfterQuiescence(Handle handle) {\n'
    restore = '        return store.restoreSlot(loaded.header.value, account, hold);\n'
    confirm = '    boolean confirmExistingSlot(Slot expected) {\n'
    publish = '        return store.confirmExistingSlot(slot);\n    }\n\n    /**\n     * Durably marks'
    store_main = '    public static void main(String[] args) throws Exception {\n'
    released = '        if (headerEntry(expected, appId) != null || !absent(slotDirectory(appId))\n'
    generic = '        return writeExistingSlot(expected, next, false, false);\n'
    return {
        'capability-in-settings': (changed((settings, None,
            '\n        NativeIdentityPersistence.ReleaseCapability capability =\n'
            '                new NativeIdentityPersistence.ReleaseCapability(uid -> true);\n')), {'capability'}),
        'capability-name-in-framework': (changed((NON_NATIVE, tracker, tracker
            + '    private static final String RELEASE = "NativeIdentityPersistence$ReleaseCapability";\n')),
            {'capability'}),
        'capability-in-another-test': (changed((store_test, store_main, store_main
            + '        java.util.function.Function<NativeIdentityPersistence.ReleaseCapability.KeyNamespace,\n'
            '                NativeIdentityPersistence.ReleaseCapability> made = NativeIdentityPersistence.ReleaseCapability::new;\n')),
            {'capability'}),
        'capability-class-in-manager': (changed((MANAGER, manager,
            '    private static final Class<?> RELEASE = NativeIdentityPersistence.ReleaseCapability.class;\n\n'
            + manager)), {'capability'}),
        'boot-facts-from-a-fresh-read-in-manager': (changed((MANAGER, manager,
            '    private static boolean freshBoot(NativeIdentityPersistence persistence) {\n'
            '        return NativeIdentityPersistence.bootFacts(persistence.load()).retired.isEmpty();\n    }\n\n'
            + manager)), {'boot-facts'}),
        'boot-facts-again-in-settings': (changed((settings, None,
            '\n        NativeIdentityPersistence.BootFacts again =\n'
            '                NativeIdentityPersistence.bootFacts(mNativeIdentityLoaded);\n')), {'boot-facts'}),
        'boot-facts-referenced-in-another-test': (changed((store_test, store_main, store_main
            + '        java.util.function.Function<NativeIdentityStore.Loaded, NativeIdentityPersistence.BootFacts> facts =\n'
            '                NativeIdentityPersistence::bootFacts;\n')), {'boot-facts'}),
        'release-called-from-manager': (changed((MANAGER, manager,
            '    boolean releaseNow(NativeIdentityPersistence persistence) {\n'
            '        return persistence.release(null, null, null, null, null, null);\n    }\n\n' + manager)),
            {'release'}),
        'removal-referenced-from-settings': (changed((settings, None,
            '\n        java.util.function.BiPredicate<NativeIdentityRecords.Header, Integer> remove =\n'
            '                mNativeIdentityStore::removeReleasingSlot;\n')), {'release'}),
        'released-slot-confirmed-from-restore': (changed((PERSISTENCE, restore,
            '        store.confirmReleasedSlot(loaded.header.value, record.appId);\n' + restore)), {'release'}),
        'releasing-written-from-publish': (changed((PERSISTENCE, publish,
            '        store.markSlotReleasing(loaded.header.value, record.appId);\n' + publish)), {'release'}),
        'omission-inside-the-store': (changed((STORE, confirm,
            confirm + '        omitReleasedSlot(null, expected.appId);\n')), {'release'}),
        'any-header-write-elsewhere': (changed((STORE, released,
            '        writeAnyHeader(expected, expected);\n' + released)), {'primitives'}),
        'drop-flag-in-the-generic-update': (changed((STORE, generic,
            '        return writeExistingSlot(expected, next, false, true);\n')), {'primitives'}),
        'any-header-write-referenced': (changed((STORE, confirm,
            '    private final java.util.function.BiPredicate<Header, Header> anyHeader = this::writeAnyHeader;\n\n'
            + confirm)), {'primitives'}),
        'slot-writer-referenced': (changed((STORE, confirm,
            '    private interface SlotWriter { boolean write(Slot expected, Slot next, boolean restore, boolean drop); }\n'
            '    private final SlotWriter slotWriter = this :: writeExistingSlot;\n\n' + confirm)), {'primitives'}),
        'release-finish-called-from-settings': (changed((settings, None,
            '\n        finishNativeIdentityReleaseLPw(record, loaded);\n')), {'release'}),
        'old-release-called-from-manager': (changed((MANAGER, manager,
            '    boolean retireNow(Handle handle) {\n        return finishRetirementAfterQuiescence(handle);\n    }\n\n'
            + manager)), {'release'}),
        'pins-release-referenced-from-manager': (changed((MANAGER, manager,
            '    private static final java.util.function.BiConsumer<NativePrincipalPins, NativePrincipalPins.Pin>\n'
            '            FINISH = NativePrincipalPins::finishRetire;\n\n' + manager)), {'release'}),
        'old-store-release-called-from-publish': (changed((PERSISTENCE, publish,
            '        finishRetirement(record, null, null);\n' + publish)), {'release'}),
        'drop-referenced-from-manager': (changed((MANAGER, manager,
            '    private static final Object DROP = (Object) (java.util.function.Predicate<NativeIdentityStore>)\n'
            '            store -> store.dropReleasedUser(null, 0, null);\n\n' + manager)), {'release'}),
        'manager-release-called-from-settings': (changed((settings, None,
            '\n        new NativePrincipalManager(null).releaseUid(null, null);\n')), {'release'}),
        'pins-release-in-the-old-finish': (changed((MANAGER, '                pins.finishRetire(handle.pin);\n',
            '                pins.finishRelease(handle.pin);\n')), {'release'}),
        'suspension-called-from-settings': (changed((settings, None,
            '\n        new NativePrincipalManager(null).suspend(null, null);\n')), {'lifecycle'}),
        'retirement-begun-from-the-old-finish': (changed((MANAGER, '                if (handle.retired) return true;\n',
            '                if (handle.retired) return beginRetirement(handle);\n')), {'lifecycle'}),
        'lift-called-from-publish': (changed((PERSISTENCE, publish,
            '        lift(record, expectedSigners, null);\n' + publish)), {'lifecycle'}),
        'retired-marked-from-manager': (changed((MANAGER, manager,
            '    private static final java.util.function.Function<NativeIdentityPersistence, Object> MARK =\n'
            '            persistence -> persistence.markRetired(null, null, null);\n\n' + manager)), {'lifecycle'}),
        'retiring-marked-from-settings': (changed((settings, None,
            '\n        mNativeIdentityPersistence.markRetiring(null, null, null);\n')), {'lifecycle'}),
        'suspension-asserted-in-the-old-finish': (changed((MANAGER, '                if (handle.retired) return true;\n',
            '                assert suspend(handle, null) != null;\n'
            '                if (handle.retired) return true;\n')), {'lifecycle'}),
    }


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(text_value):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    return json.loads(text_value, object_pairs_hook=unique)


# ---------------------------------------------------------------- pure source checks

def java_goldens(source):
    """The golden lengths and SHA-256 digests the Java codec test pins, by golden name."""
    lengths = dict(re.findall(r'private static final int GOLDEN_([A-Z0-9_]+)_BYTES = ([0-9]+);', source))
    digests = dict(re.findall(r'private static final String GOLDEN_([A-Z0-9_]+)_SHA256 = "([0-9a-f]{64})";', source))
    if set(lengths) != set(digests):
        raise ValueError('golden pins incomplete')
    return {name: (int(lengths[name]), digests[name]) for name in lengths}


def oracle_problems():
    """The Java goldens against the independent encoder, and the plan's size arithmetic."""
    problems = []
    pins = java_goldens((ROOT / PLATFORM / (CODEC_TEST + '.java')).read_text())
    gold = goldens()
    if set(pins) != set(gold) or tuple(gold) != GOLDEN_NAMES:
        problems.append('golden names differ: %s' % sorted(set(pins) ^ set(gold)))
    for name, data in gold.items():
        if pins.get(name) != (len(data), sha(data)):
            problems.append('Java golden %s differs from the independent encoder' % name)
    if sizes() != PLAN_SIZES:
        problems.append('size arithmetic %s differs from the plan %s' % (sizes(), PLAN_SIZES))
    if ' '.join(PLAN_SIZE_TEXT.split()) not in ' '.join(PLAN.read_text().split()):
        problems.append('the plan no longer states the sizes this runner checks')
    return problems


def mutant_texts():
    """The source texts each mutant changes, with its edits applied, and its harness edits. Each
    anchor must occur exactly once, a harness anchor in the identity or seeding fragment, and a
    fragment anchor in its fragment and in the facade, which carries the fragment verbatim."""
    fragments = {name: path.read_text() for name, (_, path) in integration.FRAGMENTS.items()}
    result = {}
    for name, (edits, suites) in MUTANTS.items():
        texts, harness = {}, []
        for target, old, new in edits:
            if target == HARNESS:
                if sum(text_value.count(old) for text_value in (fragments['identity'], fragments['recovery-seeding'])) != 1:
                    raise ValueError('harness mutant anchor drift: ' + name)
                harness.append((old, new))
                continue
            if target.startswith(FRAGMENT):
                fragment = fragments.get(target[len(FRAGMENT):], '')
                if fragment.count(old) != 1 or (ROOT / FACADE).read_text().count(fragment) != 1:
                    raise ValueError('fragment mutant anchor drift: ' + name)
                harness.append((old, new))
                texts[FACADE] = b1.replace_once(texts.get(FACADE, (ROOT / FACADE).read_text()), old, new)
                continue
            texts[target] = b1.replace_once(texts.get(target, (ROOT / target).read_text()), old, new)
        result[name] = (texts, tuple(harness), suites)
    return result


# The case names of each suite that runs deliberate defects.
SUITE_NAMES = {'codec': CODEC_NAMES, 'reads': READ_NAMES, 'store': STORE_NAMES, 'transactions': TRANSACTION_NAMES,
               'settings': SETTINGS_NAMES, 'manager': MANAGER_NAMES,
               'faults': FAULT_NAMES}
# The lifecycle suites of P2a, and the manager's, which runs over the Settings facade: each one's test
# class and case names.
LIFECYCLE_SUITES = {'store': (STORE_TEST, STORE_NAMES), 'transactions': (TRANSACTION_TEST, TRANSACTION_NAMES),
                    'faults': (FAULT_TEST, FAULT_NAMES), 'manager': (MANAGER_TEST, MANAGER_NAMES)}


def case_label(name):
    """The run label of one store, transaction or fault case: its format's, or new-format for a fault
    sweep, which runs Format.V3 only."""
    return FORMAT_LABELS.get(name.split(' / ', 1)[0], 'new-format')


def lifecycle_name_problems():
    """Each store and transaction case is named once in its source, as one literal or as the literal
    tail of its format's loop. Each fault kind is swept once, over the eight steps of the existing host
    write fault seams."""
    problems = []
    for test, names in ((STORE_TEST, STORE_NAMES), (TRANSACTION_TEST, TRANSACTION_NAMES)):
        source = (ROOT / PLATFORM / (test + '.java')).read_text()
        for name in names:
            prefix, rest = name.split(' / ', 1)
            literal = source.count('"%s"' % name) == 1 and prefix == 'V3'
            looped = prefix in ('V1', 'V2') and source.count('" / %s"' % rest) == 1
            if not (literal or looped):
                problems.append('%s case not named once in its source: %s' % (test, name))
    faults = (ROOT / PLATFORM / (FAULT_TEST + '.java')).read_text()
    for kind in FAULT_KINDS:
        if faults.count('sweep("%s", ' % kind) != 1:
            problems.append('fault kind not swept once: ' + kind)
    steps = ', '.join('"%s"' % step for step in FAULT_STEPS)
    if FAULT_STEPS != tuple(b1.STEPS) or ' '.join(steps.split()) not in ' '.join(faults.split()):
        problems.append('the fault steps are not the eight steps of the existing write fault seams')
    return problems


def label_problems():
    """Every step is living and carries living labels. This runner's harness rows name its tests,
    and the new-format label names only cases that are not production in B1."""
    problems = []
    for step, labels in STEP_LABELS.items():
        if step not in PHASES or not labels or not set(labels) <= set(b1.LIVING_RUN_LABELS):
            problems.append('step %s carries labels %s' % (step, labels))
    rows = [row for row in b1.HARNESS_LABELS if row[1] == 'scripts/proof/native_lifecycle_record.py']
    labelled = {}
    for label, _, classes, _ in rows:
        for name in classes:
            labelled.setdefault(name, set()).add(label)
    every = set(FORMAT_LABELS.values())
    if (labelled.get(CODEC_TEST) != {'production'} or labelled.get(READ_TEST) != every
            or labelled.get(STORE_TEST) != every or labelled.get(TRANSACTION_TEST) != every
            or labelled.get(FAULT_TEST) != {'new-format'}
            or labelled.get(SETTINGS_TEST) != {'production', 'new-format'}
            or labelled.get(MANAGER_TEST) != every or set(labelled) != {
                CODEC_TEST, READ_TEST, STORE_TEST, TRANSACTION_TEST, FAULT_TEST, SETTINGS_TEST, MANAGER_TEST}):
        problems.append('harness labels of this runner differ: %s' % labelled)
    if {row[0] for row in b1.HARNESS_LABELS if row[0] == 'new-format'} != {'new-format'} or any(
            row[1] != 'scripts/proof/native_lifecycle_record.py' for row in b1.HARNESS_LABELS if row[0] == 'new-format'):
        problems.append('the new-format label names another harness')
    return problems


def source_checks():
    problems = []
    try:
        integration.profile()
    except ValueError as error:
        problems.append('profile: %s' % error)
    problems += ['production format guard: ' + item for item in b1.format_violations(b1.production_texts())]
    try:
        problems += oracle_problems()
    except (OSError, ValueError) as error:
        problems.append('oracle: %s' % error)
    for test, names in ((CODEC_TEST, CODEC_NAMES), (READ_TEST, READ_NAMES), (STORE_TEST, STORE_NAMES),
                        (TRANSACTION_TEST, TRANSACTION_NAMES), (FAULT_TEST, FAULT_NAMES),
                        (SETTINGS_TEST, SETTINGS_NAMES), (MANAGER_TEST, MANAGER_NAMES)):
        if len(set(names)) != len(names):
            problems.append('duplicate case names of ' + test)
        # A failure prints 'FAIL <name>: <problems>', read up to the first colon and space.
        if any(': ' in name for name in names):
            problems.append('a case name of %s holds the failure separator' % test)
    codec = (ROOT / PLATFORM / (CODEC_TEST + '.java')).read_text()
    for name in CODEC_NAMES:
        if not name.startswith('golden / ') and codec.count('"%s"' % name) != 1:
            problems.append('codec case not named once in its source: ' + name)
    problems += lifecycle_name_problems()
    settings_source = (ROOT / PLATFORM / (SETTINGS_TEST + '.java')).read_text()
    for name in SETTINGS_NAMES:
        if settings_source.count('"%s"' % name) != 1 or name.split(' / ', 1)[0] not in ('V2', 'V3'):
            problems.append('settings case not named once in its source: ' + name)
    manager_source = (ROOT / PLATFORM / (MANAGER_TEST + '.java')).read_text()
    for name in MANAGER_NAMES:
        if manager_source.count('"%s"' % name) != 1 or name.split(' / ', 1)[0] not in FORMAT_LABELS:
            problems.append('manager case not named once in its source: ' + name)
    try:
        texts = b1.production_texts()
        problems += unreachable_violations(texts, other_java_texts(texts))
        for name, ((production, others), rules) in unreachable_mutants().items():
            tripped = unreachable_rules(production, others)
            if tripped != rules:
                problems.append('unreachable mutant %s tripped %s, not %s' % (name, sorted(tripped), sorted(rules)))
    except (OSError, ValueError) as error:
        problems.append('release reachability: %s' % error)
    try:
        mutant_texts()
    except ValueError as error:
        problems.append('mutant anchors: %s' % error)
    try:
        lifecycle_files(MANAGER_TEST)
    except ValueError as error:
        problems.append('the manager suite lock seam: %s' % error)
    predictions = strict(PREDICTIONS.read_text())
    if 'PREDICTED' not in predictions['status']:
        problems.append('predictions are not marked as predictions')
    expected = predictions['mutants_caught_at_least']
    if set(expected) != set(MUTANTS):
        problems.append('mutant predictions do not list every mutant')
    for name, checks in expected.items():
        suites = MUTANTS.get(name, ((), ()))[1]
        allowed = {check for suite in suites if suite in SUITE_NAMES for check in SUITE_NAMES[suite]}
        if not checks or not set(checks) <= allowed or not set(suites) <= set(SUITE_NAMES):
            problems.append('mutant prediction inconsistent: ' + name)
    counts = predictions['cases']
    if (counts['codec'], counts['reads'], counts['goldens'], counts['mutants'], counts['store'],
            counts['transactions'], counts['faults'], counts['settings'], counts['manager']) != (
            len(CODEC_NAMES), len(READ_NAMES), len(GOLDEN_NAMES), len(MUTANTS), len(STORE_NAMES),
            len(TRANSACTION_NAMES), len(FAULT_NAMES), len(SETTINGS_NAMES), len(MANAGER_NAMES)):
        problems.append('predicted counts differ from the case lists')
    by_label = {suite: {} for suite in ('store', 'transactions', 'manager')}
    for suite in by_label:
        for name in SUITE_NAMES[suite]:
            label = case_label(name)
            by_label[suite][label] = by_label[suite].get(label, 0) + 1
    if (predictions['store_by_label'], predictions['transactions_by_label'], predictions['manager_by_label']) != (
            by_label['store'], by_label['transactions'], by_label['manager']):
        problems.append('predicted counts by label differ from the case lists')
    problems += label_problems()
    return problems


# ---------------------------------------------------------------- JVM runs, guarded

def candidate(pinned):
    """The current candidate Settings, rebuilt from the pinned canonical copies by the current patch."""
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
    return integration.targets(original, value)[integration.SETTINGS].decode()


def codec_files(texts=None):
    files = {'framework/NativeIdentityRecords.java': (ROOT / RECORDS).read_bytes(),
             'tests/%s.java' % CODEC_TEST: (ROOT / PLATFORM / (CODEC_TEST + '.java')).read_bytes()}
    if texts and RECORDS in texts:
        files['framework/NativeIdentityRecords.java'] = texts[RECORDS].encode()
    return files


def read_files(settings, texts=None, harness=()):
    texts = texts or {}
    framework = {Path(path).stem: value for path, value in texts.items() if path.startswith(FRAMEWORK_DIR)}
    files = b1.product_sources(framework_override=framework)
    if FACADE in texts:
        files['stubs/com/android/server/pm/Settings.java'] = texts[FACADE].encode()
    files.update(b2.history_stubs())
    source = b2.harness_source(settings, 'b2')
    for old, new in harness:
        source = b1.replace_once(source, old, new)
    files['tests/NativeHistoryHarness.java'] = source.encode()
    files['tests/%s.java' % READ_TEST] = (ROOT / PLATFORM / (READ_TEST + '.java')).read_bytes()
    return files


def settings_files(settings, texts=None, harness=()):
    """The read files with the shared fixtures and the Settings test in place of the read test."""
    files = read_files(settings, texts, harness)
    del files['tests/%s.java' % READ_TEST]
    for name in (SUPPORT, SETTINGS_TEST):
        files['tests/%s.java' % name] = (ROOT / PLATFORM / (name + '.java')).read_bytes()
    return files


def run_suite(work, files, main, args, names):
    """One complete run: its build, its outcome by name and the case names it printed."""
    work.mkdir(parents=True)
    built = b1.build(work, files)
    record = {'build': built}
    if built['returncode']:
        record['compile_failure'] = True
        return b1.outcome(record, names), record
    record['run'] = b1.execute(work, main, args, timeout=1800)
    return b1.outcome(record, names), record


def red_names(result, names):
    """The failed names of a complete result, or None when it is not one."""
    if 'error' in result or not result['complete']:
        return None
    if result['returncode'] != (1 if result['failed'] else 0):
        return None
    return set(result['failed'])


def codec_suite(work, texts=None):
    gold = work / 'goldens'
    gold.mkdir(parents=True)
    return run_suite(work / 'build', codec_files(texts), CODEC_TEST, [str(gold)], CODEC_NAMES), gold


def read_suite(work, settings, texts=None, harness=()):
    return run_suite(work, read_files(settings, texts, harness), READ_TEST, [str(work / 'reads-state')],
                     READ_NAMES)


def settings_suite(work, settings, texts=None, harness=()):
    return run_suite(work, settings_files(settings, texts, harness), SETTINGS_TEST, [str(work / 'settings-state')],
                     SETTINGS_NAMES)


# The manager suite's lock proof. Its cases name the PMS facade's lock as the forbidden monitor of store
# I/O. The host Os facade checks that monitor only when it opens a descriptor, which the store does for
# its directory syncs. This seam, injected only into the store copy that the manager suite compiles,
# checks it at every store load as well, so a read under the PMS lock fails the case too.
LOCK_SEAM_ANCHOR = '    Loaded load() {\n'
LOCK_SEAM = ('    Loaded load() {\n'
             '        if (android.system.Os.forbiddenMonitor != null\n'
             '                && Thread.holdsLock(android.system.Os.forbiddenMonitor)) {\n'
             '            throw new AssertionError("PMS state lock held during a store load");\n'
             '        }\n')


def with_lock_seam(files):
    files = dict(files)
    store = files['framework/NativeIdentityStore.java'].decode()
    files['framework/NativeIdentityStore.java'] = b1.replace_once(store, LOCK_SEAM_ANCHOR, LOCK_SEAM).encode()
    return files


def lifecycle_files(test, texts=None):
    """The current product sources, with any framework text a defect changes, the shared fixtures and
    one lifecycle test. The fault sweeps take the existing host write fault seams, injected into
    copies of the store and strict writer sources, and the seam class. The manager suite takes the
    lock seam in its store copy."""
    framework = {Path(path).stem: value for path, value in (texts or {}).items() if path.startswith(FRAMEWORK_DIR)}
    files = b1.product_sources(framework_override=framework)
    if test == FAULT_TEST:
        files = b1.with_seams(files)
        files['tests/%s.java' % FAULT_SEAM] = (ROOT / PLATFORM / (FAULT_SEAM + '.java')).read_bytes()
    if test == MANAGER_TEST:
        files = with_lock_seam(files)
    for name in (SUPPORT, test):
        files['tests/%s.java' % name] = (ROOT / PLATFORM / (name + '.java')).read_bytes()
    return files


def lifecycle_suite(work, suite, texts=None):
    test, names = LIFECYCLE_SUITES[suite]
    return run_suite(work, lifecycle_files(test, texts), test, [str(work / 'lifecycle-state')], names)


def golden_problems(gold):
    """Each golden the codec test wrote against the independent encoder, byte for byte."""
    expected = goldens()
    written = sorted(path.name for path in gold.iterdir()) if gold.is_dir() else []
    problems = []
    if written != sorted(name + '.bin' for name in expected):
        problems.append('written goldens %s' % written)
    for name, data in expected.items():
        path = gold / (name + '.bin')
        if not path.is_file() or path.read_bytes() != data:
            problems.append('golden %s differs from the independent encoder' % name)
    return problems


def qualify(work, pinned, report):
    """Every guarded JVM step, in PHASES order, each recorded into the report as it finishes. The
    caller has passed every guard."""
    steps, problems = report['steps'], report['problems']
    predictions = strict(PREDICTIONS.read_text())
    report['java'] = subprocess.run(['java', '-version'], capture_output=True, text=True,
                                    timeout=60).stderr.strip()

    settings = candidate(pinned)
    steps['candidate'] = {'settings_sha256': sha(settings.encode())}
    report['completed_phases'].append('candidate')

    (result, record), gold = codec_suite(work / 'codec')
    steps['codec'] = result
    if red_names(result, CODEC_NAMES) != set() or 'unqualified' not in record.get('run', {}).get('stdout', ''):
        problems.append('codec suite')
    else:
        problems += golden_problems(gold)
        refused = b1.execute(work / 'codec' / 'build', CODEC_TEST, [str(work / 'codec' / 'no-assertions')],
                             assertions=False, timeout=120)
        if not refused['returncode'] or '-ea' not in refused['stderr']:
            problems.append('codec suite ran without assertions')
    report['completed_phases'].append('codec')

    result, record = read_suite(work / 'reads', settings)
    steps['reads'] = result
    steps['reads']['labels'] = {name.split(' / ', 1)[0]: FORMAT_LABELS[name.split(' / ', 1)[0]] for name in READ_NAMES}
    if red_names(result, READ_NAMES) != set() or 'unqualified' not in record.get('run', {}).get('stdout', ''):
        problems.append('read suite')
    else:
        refused = b1.execute(work / 'reads', READ_TEST, [str(work / 'reads' / 'no-assertions')],
                             assertions=False, timeout=120)
        if not refused['returncode'] or '-ea' not in refused['stderr']:
            problems.append('read suite ran without assertions')
    report['completed_phases'].append('reads')

    def lifecycle_phase(suite):
        test, names = LIFECYCLE_SUITES[suite]
        result, record = lifecycle_suite(work / suite, suite)
        steps[suite] = result
        steps[suite]['labels'] = {name.split(' / ', 1)[0]: case_label(name) for name in names}
        if red_names(result, names) != set() or 'unqualified' not in record.get('run', {}).get('stdout', ''):
            problems.append('%s suite' % suite)
        else:
            refused = b1.execute(work / suite, test, [str(work / suite / 'no-assertions')], assertions=False,
                                 timeout=120)
            if not refused['returncode'] or '-ea' not in refused['stderr']:
                problems.append('%s suite ran without assertions' % suite)
        report['completed_phases'].append(suite)

    for suite in ('store', 'transactions', 'faults'):
        lifecycle_phase(suite)

    result, record = settings_suite(work / 'settings', settings)
    steps['settings'] = result
    steps['settings']['labels'] = {name.split(' / ', 1)[0]: FORMAT_LABELS[name.split(' / ', 1)[0]]
                                   for name in SETTINGS_NAMES}
    if red_names(result, SETTINGS_NAMES) != set() or 'unqualified' not in record.get('run', {}).get('stdout', ''):
        problems.append('settings suite')
    else:
        refused = b1.execute(work / 'settings', SETTINGS_TEST, [str(work / 'settings' / 'no-assertions')],
                             assertions=False, timeout=120)
        if not refused['returncode'] or '-ea' not in refused['stderr']:
            problems.append('settings suite ran without assertions')
    report['completed_phases'].append('settings')

    lifecycle_phase('manager')

    steps['mutants'] = {}
    expectations = predictions['mutants_caught_at_least']
    for name, (texts, harness, suites) in mutant_texts().items():
        failed, record = set(), {}
        steps['mutants'][name] = record
        for suite in suites:
            directory = work / 'mutants' / name / suite
            if suite == 'codec':
                (result, _), _ = codec_suite(directory, texts)
            elif suite == 'reads':
                result, _ = read_suite(directory, settings, texts, harness)
            elif suite == 'settings':
                result, _ = settings_suite(directory, settings, texts, harness)
            else:
                result, _ = lifecycle_suite(directory, suite, texts)
            names = SUITE_NAMES[suite]
            record[suite] = result
            if 'error' in result:
                problems.append('mutant %s did not compile; not a red result' % name)
                continue
            red = red_names(result, names)
            if red is None:
                problems.append('mutant %s %s run is not a complete result' % (name, suite))
                continue
            failed |= red
        missed = sorted(set(expectations[name]) - failed)
        record['missed'] = missed
        if missed or not failed:
            problems.append('mutant %s not caught: %s' % (name, missed))
    report['completed_phases'].append('mutants')
    report['labels'] = {step: list(labels) for step, labels in STEP_LABELS.items()}


def fresh_outside(path, what):
    resolved = path.resolve()
    if resolved.exists() or ROOT in resolved.parents or resolved == ROOT:
        raise ValueError('fresh %s outside the repository required' % what)
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--work', type=Path, help='fresh scratch directory outside the repository')
    parser.add_argument('--pinned-framework', type=Path,
                        help='pinned canonical framework copies, each checked against the exact upstream'
                             ' hash its profile pins')
    parser.add_argument('--source-checks-only', action='store_true')
    args = parser.parse_args(argv)
    report = {'runtime_qualified': False, 'android_qualified': False, 'activation': False}
    problems = source_checks()
    report['source_checks'] = problems or 'PASS'
    if args.source_checks_only:
        report['status'] = 'FAIL' if problems else 'SOURCE_ONLY'
        report['problems'] = problems
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    if not (args.evidence and args.work and args.pinned_framework):
        parser.error('--evidence, --work and --pinned-framework are required for a guarded run')
    evidence = fresh_outside(args.evidence, 'evidence path')
    work = fresh_outside(args.work, 'work directory')
    pinned = args.pinned_framework.resolve(strict=True)
    # Pure refusals, in order. Nothing below is created or started until each one passes.
    reason = b1.resource_guard()
    if not reason and not (shutil.which('javac') and shutil.which('java')):
        reason = 'no JDK on PATH'
    if reason:
        report.update(status='NOT_RUN', reason=reason)
        print(json.dumps(report, indent=2))
        return 2
    work.mkdir(parents=True)
    (work / 'tmp').mkdir()
    tempfile.tempdir = str(work / 'tmp')
    report.update(problems=problems, steps={}, completed_phases=[])
    try:
        qualify(work, pinned, report)
        report['status'] = 'FAIL' if problems else 'PASS'
    except Exception as error:
        report['exception'] = b2.exception_record(error)
        problems.append('qualification did not complete')
        report['status'] = 'NOT_COMPLETE'
    report['not_completed_phases'] = [phase for phase in PHASES if phase not in report['completed_phases']]
    if report['not_completed_phases'] and report['status'] != 'NOT_COMPLETE':
        problems.append('phases did not complete: %s' % report['not_completed_phases'])
        report['status'] = 'NOT_COMPLETE'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
