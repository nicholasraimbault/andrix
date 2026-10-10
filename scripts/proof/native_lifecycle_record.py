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
the facade and the history harness, assembles the rollback models' inputs of 24bfb6a and 78456b3 from
pinned Git objects alone with the working tree closed, checks every read against the manifest and
compiles each, runs the layout emitter under Format.V3 and reads every layout it writes with an
independent decoder, which must show every lifecycle state, entry class, scope value, inventory,
obligation state, tombstone, RELEASING tail, companion and writer step, each control removing one of
them failing the check, and runs each deliberate defect against the suites predicted to catch it, a
Settings fragment defect in the facade and the harness alike. It does not nest another runner.

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
PHASES = ('candidate', 'codec', 'reads', 'store', 'transactions', 'faults', 'settings', 'manager', 'pinned',
          'layouts', 'rollback', 'readers', 'mutants')
# Every step but the pinned one is living. The read, store and transaction tests run each store format
# under its own label: Format.V1 is legacy, Format.V2 production and Format.V3 the new format, which B1
# builds and does not ship. The fault sweeps and the layout emitter run Format.V3 only. The pinned step
# assembles and compiles the rollback models' inputs from pinned Git objects only, under the rollback
# reader label.
STEP_LABELS = {'codec': ('production',), 'reads': ('production', 'legacy', 'new-format'),
               'store': ('production', 'legacy', 'new-format'),
               'transactions': ('production', 'legacy', 'new-format'), 'faults': ('new-format',),
               'settings': ('production', 'new-format'), 'manager': ('production', 'legacy', 'new-format'),
               'pinned': ('rollback-reader',), 'layouts': ('new-format',), 'rollback': ('rollback-reader',),
               'readers': ('production', 'new-format'), 'mutants': ('production', 'legacy', 'new-format')}
# The steps whose products are pinned Git objects only. They carry only archived labels. The rollback
# step compiles one working-tree check, written against the old API, with those pinned products.
PINNED_STEPS = ('pinned', 'rollback')
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
    'V3 / release refuses a suspension closed in memory before any effect',
    # P6: the positive halves of the existing formats' flows, moved to the lifecycle format.
    'V3 / publication, retirement, release and a later reservation keep header version 2',
    'V3 / a restored reservation refuses retirement before any effect until designated, then retires',
    'V3 / a retirement without a durable block restores PENDING after a restart',
    'V3 / a reservation whose package signer changed retires with its stored signers',
    'V3 / a cached body missing from the store returns false without a write',
    'V3 / a BODY origin republishes after its body was observed missing, then retires',
    'V3 / a lost BODY cannot be republished while the counter is blocked',
    'V3 / a BODY origin whose body is damaged, or missing under a LIVE entry, retires without a write',
    'V3 / a retiring account still consumes admission capacity',
    'V3 / a pending reservation and an unpublished retiring creation reserve together')

# ---------------------------------------------------------------- the case map of the old flows
# The flows of the existing formats that retire or release. Each old flow is named by its suite's
# source, its case name and a literal that its source holds once at least: its case name, its family
# prefix or its method. Its positive half moves to the lifecycle format under the new-format label:
# CASE_MAP names the lifecycle cases that carry it, each a case the guarded run requires to pass, or
# an emitted layout. CASE_MAP_TO_MOVE names the old flows whose lifecycle case is still to be written.
# The refusal side of every old flow joins when the store refuses the old writes.
_STEPS = ('seed-synced', 'backup-renamed', 'backup-published', 'write-started', 'main-synced', 'reserve-synced',
          'backup-unlink', 'backup-unlinked')
_RELEASE_SWEEPS = tuple('%s / %s' % (kind, step) for kind in (
    'release tombstone', 'release tombstone confirmation', 'release RELEASING', 'release RELEASING confirmation',
    'release omission', 'release completion confirmation', 'release completion') for step in _STEPS)
CASE_MAP = (
    # The binding suite.
    ('NativeCreationBindingTest', 'V1 / an owned flow writes the golden version 1 bytes, its retirement part',
     '"V1 / an owned flow writes the golden version 1 bytes"',
     ('golden / retiring', 'golden / retired', 'golden / ticket',
      'V3 / markRetiring writes the block and keeps every suspension entry',
      'V3 / release clears the key namespace, then writes the ticketed tombstone, RELEASING and the omission')),
    ('NativeCreationBindingTest', 'V2 / pending and unpublished RETIRING pins reserve together',
     '"V2 / pending and unpublished RETIRING pins reserve together"',
     ('V3 / a pending reservation and an unpublished retiring creation reserve together',)),
    ('NativeCreationBindingTest', 'V2 / publication, marker, release and a later reservation keep version 2, its'
     ' marker and release', '"V2 / publication, marker, release and a later reservation keep version 2"',
     ('V3 / publication, retirement, release and a later reservation keep header version 2',)),
    ('NativeCreationBindingTest', 'signer mutation / Q reserves P with its original signers, its retirement and'
     ' release', '"signer mutation / Q reserves P with its original signers"',
     ('V3 / a reservation whose package signer changed retires with its stored signers',
      'V3 / publication, retirement, release and a later reservation keep header version 2')),
    ('NativeCreationBindingTest', 'signer mutation / a durable P reservation does not strand Q, its retirement and'
     ' release', '"signer mutation / a durable P reservation does not strand Q"',
     ('V3 / a reservation whose package signer changed retires with its stored signers',
      'V3 / publication, retirement, release and a later reservation keep header version 2')),
    # The faulted write of this family is the reservation, which no format refusal touches; its
    # lifecycle half is the retirement of the unpublished RETIRING creation beside the pending one.
    ('NativeCreationBindingFaultTest', 'pending and RETIRING together / <step>, its retirement and release',
     '"pending and RETIRING together / "',
     ('V3 / a pending reservation and an unpublished retiring creation reserve together',
      'V3 / publication, retirement, release and a later reservation keep header version 2')),
    ('NativeCreationBindingFaultTest', 'version 2 prior ordering / release marker', 'priorOrdering("release marker"',
     tuple('release RELEASING / ' + step for step in _STEPS)),
    ('NativeCreationBindingFaultTest', 'version 2 prior ordering / omission', 'priorOrdering("omission"',
     tuple('release omission / ' + step for step in _STEPS)),
    ('NativeCreationBindingLayouts', 'pending-retiring-<step>', '"pending-retiring-"',
     tuple('moved-pending-retiring-' + step for step in _STEPS)),
    ('NativeCreationBindingLayouts', 'final-released', '"final-released"', ('moved-final-released',)),
    # The history suite.
    ('NativeCreationHistoryTest', 'retirement / a never rebound reservation refuses before any effect',
     '"retirement / a never rebound reservation refuses before any effect"',
     ('V3 / a restored reservation refuses retirement before any effect until designated, then retires',)),
    ('NativeCreationHistoryTest', 'retirement / an explicitly rebound reservation publishes and retires',
     '"retirement / an explicitly rebound reservation publishes and retires"',
     ('V3 / a restored reservation refuses retirement before any effect until designated, then retires',
      'V3 / the release body keeps the app ID held until a new instance')),
    ('NativeCreationHistoryTest', 'retirement / no durable marker restores PENDING after restart',
     '"retirement / no durable marker restores PENDING after restart"',
     ('V3 / a retirement without a durable block restores PENDING after a restart',)),
    ('NativeCreationHistoryTest', 'retirement / a cached body missing from the store returns false without a write',
     '"retirement / a cached body missing from the store returns false without a write"',
     ('V3 / a cached body missing from the store returns false without a write',)),
    ('NativeCreationHistoryTest', 'retirement / BODY origin republishes after its body was observed missing',
     '"retirement / BODY origin republishes after its body was observed missing"',
     ('V3 / a BODY origin republishes after its body was observed missing, then retires',
      'V3 / publication, retirement, release and a later reservation keep header version 2')),
    ('NativeCreationHistoryTest', 'retirement / a restored retiring body finishes',
     '"retirement / a restored retiring body finishes"',
     ('V3 / a retired account keeps its entries and restores a RETIRING pin',
      'V3 / disposition and release need an instance that began with the account RETIRED')),
    ('NativeCreationHistoryTest', 'holds / an exact release keeps its UID hold and keystore fence until a new'
     ' instance', '"holds / an exact release keeps its UID hold and keystore fence until a new instance"',
     ('V3 / a durable release keeps the app ID held until a new instance',
      'V3 / the release body keeps the app ID held until a new instance')),
    ('NativeCreationHistoryFaultTest', 'rebound retirement marker / <step>', '"rebound retirement marker / "',
     tuple('markRetiring / ' + step for step in _STEPS)),
    ('NativeCreationHistoryLayouts', 'history-retirement-marker-<step>',
     'interrupted("history-retirement-marker"', tuple('moved-retirement-block-' + step for step in _STEPS)),
    ('NativeCreationHistoryLayouts', 'history-retirement-publication-<step>',
     'interrupted("history-retirement-publication"', tuple('moved-retirement-publication-' + step for step in _STEPS)),
    # The counter suite.
    ('NativeCounterAdmissionTest', 'residual / another lineage above the counter strands a later release',
     '"residual / another lineage above the counter strands a later release"',
     ('V3 / continuation refuses a counter that does not cover the account before any effect',)),
    ('NativeCounterAdmissionTest', 'manager / a lost BODY cannot be republished while the counter is blocked',
     '"manager / a lost BODY cannot be republished while the counter is blocked"',
     ('V3 / a lost BODY cannot be republished while the counter is blocked',)),
    ('NativePreparationAdmissionTest', 'capacity: a retiring binding still consumes admission capacity',
     'void capacity(', ('V3 / a retiring account still consumes admission capacity',)),
    ('NativeCounterAdmissionTest', 'manager / a healthy body retires beside a blocked store',
     '"manager / a healthy body retires beside a blocked store"',
     ('V3 / every lifecycle transaction needs only an intact binding',)),
    # The manager and persistence suites, which name no cases: their flows by method or call.
    ('NativePrincipalManagerTest', 'main: retirement, quiescence and release of two handles, a restored one, a'
     ' marker and a partial store', 'manager.finishRetirementAfterQuiescence(first)',
     ('V3 / retirement moves the pin and then writes its block',
      'V3 / disposition and release need an instance that began with the account RETIRED',
      'V3 / the release body keeps the app ID held until a new instance',
      'V3 / a lost reply after the omission is acknowledged in the instance and freed at the next boot')),
    # The store test's version 1 primitives: under the lifecycle format the generic writers refuse
    # these steps, which only the release engine takes.
    ('NativeIdentityStoreTest', 'main: the retiring flag, user drop, RELEASING, removal, omission and released'
     ' confirmation', 'assert store.removeReleasingSlot(releasing, APP); // Exact filesystem continuation.',
     ('V3 / retire writes RETIRING with its block and keeps every entry',
      'V3 / the user drop writes the ticketed tombstone of a releasable account only',
      "V3 / RELEASING needs the release engine's ticketed tombstone",
      'V3 / continuation passes only the checked removal and omission',
      'V3 / release clears the key namespace, then writes the ticketed tombstone, RELEASING and the omission',
      'V3 / release completes a CREATING entry to LIVE before the key namespace and the tombstone',
      "V3 / a ticket's principal ID is sibling, claim and counter evidence")),
    # The living probe's five modes: missing, present, damaged, LIVE without a body, counter unknown.
    ('BodyOriginRetirementProbe', 'the living probe run, its five modes', 'Retirement marker is not durably confirmed',
     ('V3 / a BODY origin republishes after its body was observed missing, then retires',
      'V3 / retirement moves the pin and then writes its block',
      'V3 / a BODY origin whose body is damaged, or missing under a LIVE entry, retires without a write',
      'V3 / a lost BODY cannot be republished while the counter is blocked')),
    ('NativeIdentityPersistenceTest', 'retirementMonotonic', 'void retirementMonotonic(',
     ('V3 / markRetiring confirms its own retirement and refuses any other',
      'V3 / retire never moves an account back or changes its block')),
    ('NativeIdentityPersistenceTest', 'headerOnlyDamage', 'void headerOnlyDamage(',
     ('V3 / every lifecycle transaction needs only an intact binding',)),
    ('NativeIdentityPersistenceTest', 'creatingEntryCompletesBeforeOmission',
     'void creatingEntryCompletesBeforeOmission(',
     ('V3 / release completes a CREATING entry to LIVE before the key namespace and the tombstone',)),
    ('NativeIdentityPersistenceTest', 'releaseRefusals', 'void releaseRefusals(',
     ('V3 / release refuses outside a retired boot before any effect',
      'V3 / release refuses beside a suspension entry or an open obligation before any effect',
      'V3 / release refuses tickets of another principal and unchecked users before any effect',
      "V3 / release refuses beside a foreign copy or another ticket's tombstone before any effect",
      'V3 / continuation refuses a counter that does not cover the account before any effect',
      'V3 / continuation refuses a live binding of the package elsewhere before any effect')),
    ('NativeIdentityPersistenceTest', 'markWithUnknownOutcomes', 'void markWithUnknownOutcomes(',
     tuple('markRetiring / ' + step for step in _STEPS)),
    ('NativeIdentityPersistenceTest', 'releaseWithUnknownOutcomes', 'void releaseWithUnknownOutcomes(',
     _RELEASE_SWEEPS + ('V3 / an interrupted release continues from RELEASING without a directory or with an'
                        ' emptied one',)),
    ('NativeIdentityPersistenceTest', 'noSnapshotDerivedDeletion', 'void noSnapshotDerivedDeletion(',
     ('V3 / continuation passes only the checked removal and omission',)),
)
CASE_MAP_TO_MOVE = (
    ('NativeIdentityHeaderFootprintTest', 'confirmReleasedSlot cannot release an addition',
     '"confirmReleasedSlot cannot release an addition"'),
    ('NativeIdentityHeaderFootprintTest', 'removeReleasingSlot refused', '"removeReleasingSlot refused"'),
    ('NativeIdentityHeaderFootprintTest', 'owned retirement header steps refused',
     '"owned retirement header steps refused"'),
    ('NativeIdentityHeaderFootprintTest', 'interrupted omission is compatible', '"interrupted omission is compatible"'),
    ('NativeIdentityHeaderFootprintTest', 'same manager / unpublished RETIRING B with C id2',
     '"same manager / unpublished RETIRING B with C id2"'),
    ('NativeIdentityHeaderFootprintTest', 'same manager / B release waits for C',
     '"same manager / B release waits for C"'),
    ('NativeHeaderWriteFaultTest', 'unpublished RETIRING B', '"unpublished RETIRING B"'),
    ('NativeHeaderWriteFaultTest', 'prior ordering / release marker', 'priorOrdering("release marker"'),
    ('NativeHeaderWriteFaultTest', 'prior ordering / omission', 'priorOrdering("omission"'),
    ('NativeCreationHistoryFaultTest', 'rebound retirement publication / <step>',
     '"rebound retirement publication / "'),
    ('NativeIdentityFutureFormatTest', 'releasing, cases and ownedSeeds: the lifecycle writer rows', 'releasing('),
    ('NativeIdentityPresenceTest', 'releasing, matrixCases, unsearchable and the RELEASING and owned retirement'
     ' cases', 'releasing('),
)


def case_map_problems():
    """Every old flow is named once, by a literal its suite's source holds, either with lifecycle cases
    that exist in the suites the guarded run requires to pass or among the layouts, or among the flows
    still to move."""
    problems = []
    targets = set(LAYOUT_NAMES)
    for _, names in SUITE_NAMES.items():
        targets.update(names)
    seen = set()
    for suite, name, literal, *rest in CASE_MAP + CASE_MAP_TO_MOVE:
        if (suite, name) in seen:
            problems.append('old flow named twice in the case map: %s %s' % (suite, name))
        seen.add((suite, name))
        source = ROOT / PLATFORM / (suite + '.java')
        if not source.is_file() or literal not in source.read_text():
            problems.append('old flow not in its suite: %s %s' % (suite, name))
        for target in (rest[0] if rest else ()):
            if target not in targets:
                problems.append('case map target is no lifecycle case: %s -> %s' % (name, target))
        if rest and not rest[0]:
            problems.append('case map entry without a lifecycle case: %s' % name)
    return problems


# ---------------------------------------------------------------- the lifecycle layouts
# NativeLifecycleLayouts emits, under Format.V3 with the existing host write fault seams, the store
# layouts that the rollback models of 24bfb6a and 78456b3 and B1's own readers read. Its layout names
# are predicted here. Each layout's facts are read from its bytes by an independent decoder, written
# from the plan's layout alone, never from the Java codec, and the layouts together must show every
# fact below and every writer step, or the check names what is missing.
LAYOUTS = 'NativeLifecycleLayouts'
# The retirement families that the binding and history emitters wrote under the old retirement, now
# written by the lifecycle record's retirement: a pending reservation's retirement, which publishes its
# body first, a published account's retirement block, and a reservation interrupted beside a retiring
# account. Each is failed at every writer step. The account released through the lifecycle path
# replaces the old final release.
MOVED_FAMILIES = ('retirement-publication', 'retirement-block', 'pending-retiring')
STATE_LAYOUTS = (
    'state-suspended-user', 'state-suspended-grant', 'state-suspended-noted', 'state-six-entries',
    'state-recovery-prior-unknown', 'state-recovery-retired', 'state-retiring-user', 'state-retiring-grant',
    'state-legacy-continued', 'state-legacy-suspended', 'state-retired', 'state-retired-suspended',
    'state-disposing', 'state-disposal-confirmed', 'state-releasable', 'state-lifted', 'state-tombstone-ticketed',
    'state-releasing-tombstone', 'state-releasing-without-directory', 'state-releasing-without-directory-header-2',
    'state-releasing-without-directory-beside-reservation', 'state-released')
# Values no writer of this stage writes, through the codec: durable state of a later writer or an older image.
VALUE_LAYOUTS = (
    'value-scope-blocks-disposition', 'value-hold-both-scope-bits', 'value-user-removal-retiring',
    'value-orphaned-disposition', 'value-maximum', 'value-two-users', 'value-legacy-marker',
    'value-tombstone-without-ticket', 'value-releasing-tombstone-without-ticket')
COMPANION_LAYOUTS = tuple('companion-%s-%s' % (kind, state) for state in ('suspended', 'retiring', 'retired')
                          for kind in ('reservation', 'sibling-package', 'lost')) + (
    'companion-sibling-principal-suspended', 'companion-reservation-tombstone', 'companion-sibling-package-version1',
    'companion-sibling-principal-version1')


def dashed(text):
    return text.lower().replace(' ', '-')


STEP_LAYOUTS = tuple('step-%s-%s' % (dashed(kind), step) for kind in FAULT_KINDS for step in FAULT_STEPS)
MOVED_LAYOUTS = tuple('moved-%s-%s' % (family, step) for step in FAULT_STEPS for family in MOVED_FAMILIES) + (
    'moved-final-released',)
LAYOUT_NAMES = STATE_LAYOUTS + VALUE_LAYOUTS + STEP_LAYOUTS + MOVED_LAYOUTS + COMPANION_LAYOUTS
# The writer step families, each of which must be present at all eight steps.
LAYOUT_STEP_FAMILIES = (tuple('step-' + dashed(kind) for kind in FAULT_KINDS)
                        + tuple('moved-' + family for family in MOVED_FAMILIES))
# Every fact that the layouts must show, read from their bytes: each lifecycle state, entry class,
# scope value and noted entry, the entry bound, each retirement class, both inventories, each
# obligation state, two users and the maximum record, tombstones with and without a ticket, RELEASING
# beside each and without a directory, the version 1 values that older images read, a version 2 slot
# under each header version, and the three companions.
LAYOUT_FACTS = (
    'state ELIGIBLE suspended', 'state RETIRING', 'state RETIRED',
    'entry ACCOUNT_USER', 'entry ADMIN_GRANT', 'entry RECOVERY_HOLD',
    'scope 0', 'scope 1', 'scope 2', 'scope 3', 'noted entry', 'six entries',
    'retirement ACCOUNT_USER', 'retirement ADMIN_GRANT', 'retirement USER_REMOVAL', 'retirement LEGACY_MARKER',
    'inventory 0', 'inventory 1',
    'obligation OUTSTANDING', 'obligation DISPOSING', 'obligation DISCHARGED', 'obligation ORPHANED_WITH_USER',
    'RETIRED with DISPOSING', 'two users', 'maximum record',
    'ticketed tombstone', 'tombstone without a ticket',
    'RELEASING beside a ticketed tombstone', 'RELEASING beside a tombstone without a ticket',
    'RELEASING without a directory', 'RELEASING without a directory under header 2',
    'RELEASING without a directory beside a bound reservation under header 2',
    'version 1 siblings naming one package', 'version 1 siblings naming one principal',
    'version 1 legacy marker', 'version 1 eligible',
    'version 2 slot under header 1', 'version 2 slot under header 2',
    'companion reservation', 'companion sibling package', 'companion sibling principal', 'companion lost')
LAYOUT_KINDS = ('slot', 'version1', 'reservation', 'sibling', 'lost')
TYPE_HEADER = 1
PHASE_NAMES = {1: 'CREATING', 2: 'LIVE', 3: 'RELEASING'}
STATE_NAMES = {code: name for name, code in STATES.items()}
CLASS_NAMES = {code: name for name, code in CLASSES.items()}
DUTY_NAMES = {code: name for name, code in DUTY_STATES.items()}
MAX_RECORD = 65536
# The header copies a reader reads: the main, its reserve and the preferred backup. A staging seed is
# no copy. Every file of a slot directory, its staging seed included, counts for the slot kind.
HEADER_COPIES = ('store.bin', 'store.bin.reservecopy', 'store.bin-backup')


def decode_frame(data, kind):
    """The version and body of an intact frame of this record type, or None: magic, type, version and
    total length, the body, then the SHA-256 of everything before it."""
    if not 44 <= len(data) <= MAX_RECORD:
        return None
    magic, record_type, version, length = struct.unpack_from('<IHHI', data)
    if (magic, record_type, length) != (MAGIC, kind, len(data)) or hashlib.sha256(data[:-32]).digest() != data[-32:]:
        return None
    return version, data[12:-32]


class Cursor:
    """Little endian fields of one body, read in order; a short body raises struct.error or ValueError."""

    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, layout):
        values = struct.unpack_from(layout, self.data, self.at)
        self.at += struct.calcsize(layout)
        return values[0] if len(values) == 1 else values

    def raw(self, count):
        if self.at + count > len(self.data):
            raise ValueError('short body')
        self.at += count
        return self.data[self.at - count:self.at].hex()

    def text(self):
        return bytes.fromhex(self.raw(self.take('<H'))).decode('ascii')

    def done(self):
        if self.at != len(self.data):
            raise ValueError('trailing bytes')


def decode_slot(data):
    """An independent reading of an intact version 1 or 2 slot frame, from the plan's layout alone: its
    version, app ID, package, principals, each user's lifecycle and a tombstone's ticket, or None for any
    other input. It reads fields and does not judge the encoding rules, which the codec suites own."""
    frame = decode_frame(data, TYPE_SLOT)
    if frame is None or frame[0] not in (1, 2):
        return None
    version, body = frame
    cursor = Cursor(body)
    try:
        cursor.raw(16)
        app_id, _ = cursor.take('<iq')
        package = cursor.text()
        for _ in range(cursor.take('<H')):
            cursor.raw(32)
        count = cursor.take('<H')
        users = []
        if version == 1:
            for _ in range(count):
                principal, user, serial, flag = cursor.take('<qiqB')
                if flag not in (0, 1):
                    raise ValueError('flag')
                users.append({'principal': principal, 'user': user, 'serial': serial,
                              'state': 'RETIRING' if flag else 'ELIGIBLE', 'entries': [], 'legacy': bool(flag),
                              'retirement': {'class': 'LEGACY_MARKER', 'inventory': 0, 'obligations': []}
                              if flag else None})
            ticket = None
        else:
            identities = [cursor.take('<qiq') for _ in range(count)]
            for principal, user, serial in identities:
                state, entry_count = cursor.take('<BB')
                entries = []
                for _ in range(entry_count):
                    actor, scope, _, _ = cursor.take('<BBiq')
                    cursor.raw(16)
                    cursor.take('<Hq')
                    note = cursor.take('<B')
                    if note not in (0, 1):
                        raise ValueError('note')
                    if note:
                        cursor.raw(32)
                    entries.append({'class': CLASS_NAMES[actor], 'scope': scope, 'note': bool(note)})
                retirement = None
                if STATE_NAMES[state] != 'ELIGIBLE':
                    actor, _, _ = cursor.take('<Biq')
                    cursor.raw(16)
                    cursor.take('<q')
                    inventory, duty_count = cursor.take('<BB')
                    duties = []
                    for _ in range(duty_count):
                        kind, duty = cursor.take('<BB')
                        cursor.raw(16)
                        cursor.take('<Bq')
                        duties.append((KINDS[kind - 1], DUTY_NAMES[duty]))
                    retirement = {'class': CLASS_NAMES[actor], 'inventory': inventory, 'obligations': duties}
                users.append({'principal': principal, 'user': user, 'serial': serial, 'state': STATE_NAMES[state],
                              'entries': entries, 'legacy': False, 'retirement': retirement})
            ticket = None if count else cursor.take('<qiq') + (cursor.raw(16),)
        cursor.done()
    except (struct.error, ValueError, KeyError, IndexError, UnicodeDecodeError):
        return None
    return {'version': version, 'app_id': app_id, 'package': package, 'users': users, 'ticket': ticket,
            'size': len(data)}


def decode_header(data):
    """An independent reading of an intact version 1 or 2 header frame: its version and each entry's app
    ID, phase, creation package and whether a version 2 creation entry carries its binding, or None."""
    frame = decode_frame(data, TYPE_HEADER)
    if frame is None or frame[0] not in (1, 2):
        return None
    version, body = frame
    cursor = Cursor(body)
    try:
        cursor.raw(16)
        cursor.take('<q')
        entries = []
        for _ in range(cursor.take('<H')):
            app_id, phase, _ = cursor.take('<iBq')
            package = cursor.text()
            bound = False
            if version == 2 and phase == 1:
                flag = cursor.take('<B')
                if flag not in (0, 1):
                    raise ValueError('binding')
                if flag:
                    cursor.take('<iq')
                    for _ in range(cursor.take('<H')):
                        cursor.raw(32)
                    bound = True
            entries.append({'app_id': app_id, 'phase': PHASE_NAMES[phase], 'package': package, 'bound': bound})
        cursor.done()
    except (struct.error, ValueError, KeyError, UnicodeDecodeError):
        return None
    return {'version': version, 'entries': entries}


def read_layout(path):
    """One emitted layout: its three files and every intact header and slot copy of its store, read by
    the independent decoder. Raises ValueError for a malformed file."""
    words = (path / 'kind').read_text().split()
    if len(words) != 2 or words[0] not in LAYOUT_KINDS or words[1] not in ('0', '1', '2') or (
            (path / 'kind').read_text() != ' '.join(words) + '\n'):
        raise ValueError('%s: kind %r' % (path.name, (path / 'kind').read_text()))
    holds_text = (path / 'holds').read_text()
    holds = sorted(int(line) for line in holds_text.splitlines())
    if holds_text != ''.join('%d\n' % hold for hold in holds):
        raise ValueError('%s: holds' % path.name)
    packages = {}
    for line in (path / 'packages').read_text().splitlines():
        name, _, where = line.partition(' ')
        if not name or not (where == 'lost' or where.isdigit()) or name in packages:
            raise ValueError('%s: packages %r' % (path.name, line))
        packages[name] = where if where == 'lost' else int(where)
    store = path / 'store'
    headers = [header for header in (decode_header((store / name).read_bytes()) for name in HEADER_COPIES
                                     if (store / name).is_file()) if header]
    directories = {}
    slots_dir = store / 'slots'
    for directory in sorted(slots_dir.iterdir()) if slots_dir.is_dir() else ():
        directories[int(directory.name)] = [slot for slot in (decode_slot(file.read_bytes())
                                                              for file in sorted(directory.iterdir()) if file.is_file())
                                            if slot]
    return {'name': path.name, 'kind': words[0], 'header': int(words[1]), 'holds': holds, 'packages': packages,
            'headers': headers, 'slots': directories}


def layout_facts(layout):
    """The facts of LAYOUT_FACTS that one layout's bytes and files show."""
    facts = set()
    copies = [(app_id, slot) for app_id, slots in layout['slots'].items() for slot in slots]
    newer = [(app_id, slot) for app_id, slot in copies if slot['version'] == 2]
    for _, slot in copies:
        for user in slot['users']:
            if slot['version'] == 1:
                facts.add('version 1 legacy marker' if user['legacy'] else 'version 1 eligible')
                continue
            if user['state'] != 'ELIGIBLE' or user['entries']:
                facts.add('state ELIGIBLE suspended' if user['state'] == 'ELIGIBLE' else 'state ' + user['state'])
            for entry in user['entries']:
                facts.add('entry ' + entry['class'])
                facts.add('scope %d' % entry['scope'])
                if entry['note']:
                    facts.add('noted entry')
            if len(user['entries']) == 6:
                facts.add('six entries')
            retirement = user['retirement']
            if retirement:
                facts.add('retirement ' + retirement['class'])
                facts.add('inventory %d' % retirement['inventory'])
                for _, duty in retirement['obligations']:
                    facts.add('obligation ' + duty)
                    if duty == 'DISPOSING' and user['state'] == 'RETIRED':
                        facts.add('RETIRED with DISPOSING')
        if slot['version'] == 2 and len(slot['users']) >= 2:
            facts.add('two users')
        if slot['version'] == 2 and len(slot['users']) == 64 and slot['size'] == PLAN_SIZES['largest']:
            facts.add('maximum record')
        if not slot['users']:
            facts.add('ticketed tombstone' if slot['version'] == 2 else 'tombstone without a ticket')
    for header in layout['headers']:
        for entry in header['entries']:
            if entry['phase'] != 'RELEASING':
                continue
            if entry['app_id'] not in layout['slots']:
                facts.add('RELEASING without a directory')
                if layout['header'] == 2:
                    facts.add('RELEASING without a directory under header 2')
                    if any(other['phase'] == 'CREATING' and other['bound'] for other in header['entries']):
                        facts.add('RELEASING without a directory beside a bound reservation under header 2')
            for slot in layout['slots'][entry['app_id']] if entry['app_id'] in layout['slots'] else ():
                if not slot['users']:
                    facts.add('RELEASING beside a ticketed tombstone' if slot['version'] == 2
                              else 'RELEASING beside a tombstone without a ticket')
    if newer and layout['header'] in (1, 2):
        facts.add('version 2 slot under header %d' % layout['header'])
    newer_ids = {app_id for app_id, _ in newer}
    if layout['kind'] == 'reservation' and newer and any(
            entry['phase'] == 'CREATING' and entry['bound'] and entry['app_id'] not in newer_ids
            for header in layout['headers'] for entry in header['entries']):
        facts.add('companion reservation')
    if layout['kind'] == 'sibling':
        for app_id, slot in newer:
            principals = {user['principal'] for user in slot['users']}
            for other, sibling in copies:
                if other == app_id or sibling['version'] != 1:
                    continue
                if sibling['package'] == slot['package']:
                    facts.add('companion sibling package')
                if principals & {user['principal'] for user in sibling['users']} and sibling['package'] != slot['package']:
                    facts.add('companion sibling principal')
    if layout['kind'] == 'lost' and any(layout['packages'].get(slot['package']) == 'lost' for _, slot in newer):
        facts.add('companion lost')
    if not newer:
        older = [(app_id, slot) for app_id, slot in copies if slot['users']]
        for app_id, slot in older:
            for other, sibling in older:
                if other == app_id:
                    continue
                if sibling['package'] == slot['package']:
                    facts.add('version 1 siblings naming one package')
                if ({user['principal'] for user in slot['users']} & {user['principal'] for user in sibling['users']}
                        and sibling['package'] != slot['package']):
                    facts.add('version 1 siblings naming one principal')
    return facts


def layout_problems(layout):
    """How one layout's files disagree with its bytes: its kind is version1 exactly when no intact
    version 2 slot frame is present, a companion has one, its header version is the highest intact
    header copy's, its holds include every slot directory and every header entry, it maps packages
    only at held app IDs, and it maps every package that the bytes name at a held app ID."""
    problems = []
    newer = any(slot['version'] == 2 for slots in layout['slots'].values() for slot in slots)
    if newer == (layout['kind'] == 'version1'):
        problems.append('%s: kind %s with%s an intact version 2 slot' % (
            layout['name'], layout['kind'], '' if newer else 'out'))
    if layout['header'] != max([header['version'] for header in layout['headers']] or [0]):
        problems.append('%s: header version %d' % (layout['name'], layout['header']))
    named = set(layout['slots']) | {entry['app_id'] for header in layout['headers'] for entry in header['entries']}
    if not named <= set(layout['holds']):
        problems.append('%s: holds %s without %s' % (layout['name'], layout['holds'], sorted(named)))
    unheld = sorted(name for name, where in layout['packages'].items() if where != 'lost' and where not in layout['holds'])
    if unheld:
        problems.append('%s: packages mapped at an app ID that is not held: %s' % (layout['name'], unheld))
    named_packages = {slot['package'] for app_id, slots in layout['slots'].items() if app_id in layout['holds']
                      for slot in slots}
    named_packages |= {entry['package'] for header in layout['headers'] for entry in header['entries']
                       if entry['phase'] == 'CREATING' and entry['app_id'] in layout['holds']}
    if not named_packages <= set(layout['packages']):
        problems.append('%s: packages the bytes name are not mapped: %s' % (
            layout['name'], sorted(named_packages - set(layout['packages']))))
    return problems


# The fact controls: one witness slot encoded by the independent encoder, and the same with one field
# changed. The fact must hold for the witness and not for the changed copy, so a decoder or fact mapping
# that misreads a field fails the check. Each entry: the fact, the witness lifecycle and the changed one.
_ENTRY = ('ACCOUNT_USER', 0, 0, 5, ZERO, 1, 0, None)
_GRANT = ('ADMIN_GRANT', 0, 0, 5, '11' * 16, 2, 0, None)


def _witness_block(state='ELIGIBLE', entries=(_ENTRY,), actor='ACCOUNT_USER', inventory=True, duty='OUTSTANDING'):
    if state == 'ELIGIBLE':
        return (state, list(entries), None)
    duties = [(kind, duty if index >= 9 else ('DISCHARGED' if state == 'RETIRED' else duty), ZERO, 0, 0)
              for index, kind in enumerate(KINDS)] if inventory else []
    return (state, list(entries), (actor, 0, 5 if actor != 'LEGACY_MARKER' else 0,
                                   '33' * 16 if actor == 'ADMIN_GRANT' else ZERO, 0, duties))


FACT_CONTROLS = (
    ('state ELIGIBLE suspended', _witness_block(), _witness_block(state='RETIRING')),
    ('state RETIRING', _witness_block(state='RETIRING'), _witness_block(state='RETIRED', duty='DISCHARGED')),
    ('state RETIRED', _witness_block(state='RETIRED'), _witness_block(state='RETIRING')),
    ('entry ACCOUNT_USER', _witness_block(), _witness_block(entries=(_GRANT,))),
    ('entry ADMIN_GRANT', _witness_block(entries=(_GRANT,)), _witness_block()),
    ('entry RECOVERY_HOLD', _witness_block(entries=(('RECOVERY_HOLD', 0, 0, 5, ZERO, 7, 0, None),)),
     _witness_block()),
    ('scope 1', _witness_block(entries=(('ACCOUNT_USER', 1, 0, 5, ZERO, 1, 0, None),)), _witness_block()),
    ('scope 2', _witness_block(entries=(('RECOVERY_HOLD', 2, 0, 5, ZERO, 7, 0, None),)),
     _witness_block(entries=(('RECOVERY_HOLD', 0, 0, 5, ZERO, 7, 0, None),))),
    ('scope 3', _witness_block(entries=(('RECOVERY_HOLD', 3, 0, 5, ZERO, 7, 0, None),)),
     _witness_block(entries=(('RECOVERY_HOLD', 2, 0, 5, ZERO, 7, 0, None),))),
    ('noted entry', _witness_block(entries=(('ACCOUNT_USER', 0, 0, 5, ZERO, 1, 0, 'ab' * 32),)), _witness_block()),
    ('retirement ACCOUNT_USER', _witness_block(state='RETIRING'), _witness_block(state='RETIRING', actor='ADMIN_GRANT')),
    ('retirement ADMIN_GRANT', _witness_block(state='RETIRING', actor='ADMIN_GRANT'), _witness_block(state='RETIRING')),
    ('retirement USER_REMOVAL', _witness_block(state='RETIRING', actor='USER_REMOVAL'), _witness_block(state='RETIRING')),
    ('retirement LEGACY_MARKER', _witness_block(state='RETIRING', actor='LEGACY_MARKER', inventory=False),
     _witness_block(state='RETIRING', inventory=False)),
    ('inventory 0', _witness_block(state='RETIRING', actor='LEGACY_MARKER', inventory=False),
     _witness_block(state='RETIRING', actor='LEGACY_MARKER')),
    ('inventory 1', _witness_block(state='RETIRING'), _witness_block(state='RETIRING', inventory=False)),
    ('obligation OUTSTANDING', _witness_block(state='RETIRING'), _witness_block(state='RETIRING', duty='DISCHARGED')),
    ('obligation DISPOSING', _witness_block(state='RETIRED', duty='DISPOSING'), _witness_block(state='RETIRED')),
    ('obligation DISCHARGED', _witness_block(state='RETIRING', duty='DISCHARGED'), _witness_block(state='RETIRING')),
    ('obligation ORPHANED_WITH_USER', _witness_block(state='RETIRING', duty='ORPHANED_WITH_USER'),
     _witness_block(state='RETIRING')),
    ('RETIRED with DISPOSING', _witness_block(state='RETIRED', duty='DISPOSING'),
     _witness_block(state='RETIRED', duty='ORPHANED_WITH_USER')),
)


def fact_control_problems():
    """Each fact control: the witness, encoded by the independent encoder and read back through the
    independent decoder, shows its fact, and the copy with one field changed does not."""
    problems = []
    for fact, witness, changed in FACT_CONTROLS:
        shown = []
        for lifecycle in (witness, changed):
            data = slot_v2(LINEAGE, 10200, 2, 'a.b', [LOW], [(3, 0, 5, lifecycle)])
            slot = decode_slot(data)
            layout = {'name': 'control', 'kind': 'slot', 'header': 1, 'holds': [10200], 'packages': {'a.b': 10200},
                      'headers': [], 'slots': {10200: [slot] if slot else []}}
            shown.append(fact in layout_facts(layout))
        if shown != [True, False]:
            problems.append('fact control %s: witness %s, changed %s' % (fact, shown[0], shown[1]))
    return problems


def coverage_problems(layouts):
    """Whether the layouts, by name, are exactly the predicted ones and show every fact and every writer
    step: each missing fact, missing or unexpected name and step family is a problem."""
    problems = []
    names = set(layouts)
    missing = [name for name in LAYOUT_NAMES if name not in names]
    if missing:
        problems.append('missing layouts: %s' % missing)
    if names - set(LAYOUT_NAMES):
        problems.append('unexpected layouts: %s' % sorted(names - set(LAYOUT_NAMES)))
    for family in LAYOUT_STEP_FAMILIES:
        absent = [step for step in FAULT_STEPS if '%s-%s' % (family, step) not in names]
        if absent:
            problems.append('writer steps missing: %s at %s' % (family, absent))
    shown = set().union(*layouts.values()) if layouts else set()
    for fact in LAYOUT_FACTS:
        if fact not in shown:
            problems.append('fact missing: ' + fact)
    return problems


def coverage_controls(layouts):
    """The discrimination controls of the coverage check: without every layout that shows a fact, or
    without any one layout, the check names what is missing. Returns each control that it missed."""
    missed = []
    for fact in LAYOUT_FACTS:
        reduced = {name: facts for name, facts in layouts.items() if fact not in facts}
        if 'fact missing: ' + fact not in coverage_problems(reduced):
            missed.append('fact ' + fact)
    for name in layouts:
        reduced = {other: facts for other, facts in layouts.items() if other != name}
        if 'missing layouts: %s' % [name] not in coverage_problems(reduced):
            missed.append('layout ' + name)
    return missed


def layouts_check(directory):
    """The coverage check over an emitted directory: each layout's files against its bytes, the
    coverage of every fact and step, and the controls. Returns the problems and each layout's facts."""
    problems, facts = [], {}
    for path in sorted(directory.iterdir()):
        try:
            layout = read_layout(path)
        except (OSError, ValueError) as error:
            problems.append('layout %s: %s' % (path.name, error))
            continue
        problems += layout_problems(layout)
        facts[path.name] = layout_facts(layout)
    problems += coverage_problems(facts)
    problems += ['coverage control missed: ' + control for control in coverage_controls(facts)]
    problems += fact_control_problems()
    return problems, facts


def layout_groups():
    """How many layouts each group of the emitter writes, by the group argument it takes."""
    return {'states': len(STATE_LAYOUTS), 'values': len(VALUE_LAYOUTS), 'steps': len(STEP_LAYOUTS),
            'moved': len(MOVED_LAYOUTS), 'companions': len(COMPANION_LAYOUTS)}


def layout_name_problems():
    """The emitter names each state and value layout once, sweeps each transaction once over the eight
    steps of the existing write fault seams, and names each moved family and the companions as
    predicted."""
    problems = []
    source = (ROOT / PLATFORM / (LAYOUTS + '.java')).read_text()
    for name in STATE_LAYOUTS + VALUE_LAYOUTS + ('moved-final-released', 'companion-sibling-principal-suspended',
                                                 'companion-reservation-tombstone', 'companion-sibling-package-version1',
                                                 'companion-sibling-principal-version1'):
        if source.count('"%s"' % name) != 1:
            problems.append('layout not named once in the emitter: ' + name)
    for kind in FAULT_KINDS:
        if source.count('sweep("%s", ' % kind) != 1:
            problems.append('transaction not swept once by the emitter: ' + kind)
    if 'managerSweep(' in source:
        problems.append('the emitter sweeps manager operations, whose writes the persistence sweeps already make')
    for family in MOVED_FAMILIES:
        if source.count('"moved-%s-" + step' % family) != 1:
            problems.append('moved family not named once in the emitter: ' + family)
    for kind in ('reservation', 'sibling-package', 'lost'):
        if source.count('"companion-%s-" + account.getKey()' % kind) != 1:
            problems.append('companion not named once in the emitter: ' + kind)
    steps = ', '.join('"%s"' % step for step in FAULT_STEPS)
    if ' '.join(steps.split()) not in ' '.join(source.split()):
        problems.append('the emitter steps are not the eight steps of the existing write fault seams')
    if len(set(LAYOUT_NAMES)) != len(LAYOUT_NAMES) or any(
            not re.fullmatch(r'[a-z0-9]+(-[a-z0-9]+)*', name) for name in LAYOUT_NAMES):
        problems.append('layout names are not distinct directory names')
    if sum(layout_groups().values()) != len(LAYOUT_NAMES):
        problems.append('layout groups do not add up to the layout names')
    return problems

# ---------------------------------------------------------------- the rollback models' pinned inputs
# The rollback models of B1 compile a check written against the old API twice, each time against one
# old product read only from its pinned Git objects: 24bfb6a under Format.V2, its production format,
# and 78456b3 under Format.V1. The 24bfb6a history stubs, harness template, body inputs and test
# support with its B1 adapter compile against both products, whose APIs are equal: 78456b3 differs
# from 24bfb6a only by the boot literal, the store comments and the host facade default. Each model
# fills the harness template with the Settings texts of its own candidate, which the history runner's
# archive rebuilds from that revision's pinned patch. The pinned half of each compile set is assembled
# sealed: with the working tree closed, so any read of a living file raises, and with no path read
# outside the repository and no process started except by the Git reader, so the manifest test sees
# every input.
ROLLBACK_MODELS = (('24bf', 'V2'), ('7845', 'V1'))
ROLLBACK_SUPPORT = ('NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHistoryTestSupport')


@b1.sealed
def rollback_model_files(revision, settings):
    """The pinned half of one rollback model's compile set: the registered revision's product, the
    24bfb6a history stubs, the 24bfb6a harness template filled with this revision's candidate Settings
    texts, and the 24bfb6a test support with its B1 adapter."""
    if revision not in dict(ROLLBACK_MODELS):
        raise ValueError('not a rollback model: %s' % revision)
    return {**b1.archived_product_sources(revision), **b2.archived_history_stubs(),
            'tests/NativeHistoryHarness.java': b2.archived_harness_source(settings, 'b2').encode(),
            **b1.archived_test_sources(ROLLBACK_SUPPORT, adapter='b1')}


def rollback_model_paths(revision):
    """Every (revision, repository path) that one model's pinned half reads, each pinned by the manifest
    of the revision that supplies it: the product of the model's revision, and from 24bfb6a the history
    stubs, harness template, body inputs, the recovery fragments that the harness texts are checked
    against, and the test support with its B1 adapter."""
    product = {(revision, path) for path in b1.manifest(revision)
               if (b1.archived_product_path(path) or path.startswith(b1.ARCHIVED_FRAMEWORK_DIR)
                   or path == b1.ARCHIVED_FACADE) and not path.endswith('/Xml.java')}
    shared = [b2.ARCHIVED_TEMPLATE, b2.ARCHIVED_BODY_INPUTS['b2'], *b1.ARCHIVED_FRAGMENTS.values(),
              b1.ARCHIVED_PLATFORM + 'native_header_api/b1/NativeHeaderApi.java']
    shared += [path for path in b1.manifest(b1.ARCHIVE) if path.startswith(b2.ARCHIVED_HISTORY_STUBS)]
    shared += [b1.ARCHIVED_PLATFORM + name + '.java' for name in ROLLBACK_SUPPORT]
    return product | {(b1.ARCHIVE, path) for path in shared}


def rollback_manifest_problems(reads):
    """The manifest test of the pinned rollback inputs: every read of an assembly, as (revision, path),
    is a path the manifest of that revision pins, the product comes from the model's own revision and
    the shared inputs from 24bfb6a, and nothing else is read."""
    problems = []
    for revision, _ in ROLLBACK_MODELS:
        expected = rollback_model_paths(revision)
        actual = set(reads.get(revision, ()))
        pinned_git = {(b1.REVISIONS[source], path) for source, path in actual}
        bypass = sorted(set(reads.get(revision + ' git', ())) - pinned_git)
        if bypass:
            problems.append('%s read Git objects outside the pinned loader: %s' % (revision, bypass[:5]))
        for source, path in sorted(actual):
            if path not in b1.manifest(source):
                problems.append('%s read an unpinned input: %s %s' % (revision, source, path))
        if actual != expected:
            problems.append('%s read %s and missed %s' % (revision, sorted(actual - expected)[:5],
                                                           sorted(expected - actual)[:5]))
    return problems


# ---------------------------------------------------------------- the rollback and reader checks
# NativeLifecycleRollbackCheck is written against the old API only and compiled into each model's
# pinned set. NativeLifecycleReaderCheck uses the current sources and the candidate's harness. Both
# read every emitted layout with the class this runner states for it, from the independent reading of
# its bytes, and with the predicted count of each class.
ROLLBACK_CHECK = 'NativeLifecycleRollbackCheck'
READER_CHECK = 'NativeLifecycleReaderCheck'
ROLLBACK_CLASSES = ('footprint', 'reservation', 'sibling', 'sibling-principal', 'lost', 'withdrawn', 'admitted',
                    'retiring', 'tombstone', 'nothing', 'conflict')
# The classes of layouts with a version 2 slot. Every other class is a positive control or a control
# that both B1 and the old images read alike, version 1 bytes only.
VERSION_TWO_CLASSES = ('footprint', 'reservation', 'sibling', 'sibling-principal', 'lost')
READER_CLASSES = tuple(name for name in ROLLBACK_CLASSES if name != 'withdrawn')
# The supports of the reader check, from the working tree, and of the rollback check, pinned.
READER_SUPPORT = ('NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHistoryTestSupport')
# The registration guard: the first check of a fresh app ID registration in the adapted Settings, so a
# package that the identity predicate names cannot register afresh.
REGISTRATION_GUARD = ('     boolean registerAppIdLPw(PackageSetting p, boolean forceNew) throws PackageManagerException {\n'
                      '         final boolean createdNew;\n'
                      '         if (p.getAppId() == 0 || forceNew) {\n'
                      '+            if (isNativePrincipalPackageLPr(p.getPackageName())) {\n'
                      '+                throw PackageManagerException.ofInternalError("Native identity requires recovery",\n')


def registration_guard_problems():
    """The adapted Settings refuses a fresh registration of any package the identity predicate names,
    before it acquires an app ID: the host reader check asserts that predicate for a lost mapping."""
    patch = integration.PATCH.read_text()
    return [] if patch.count(REGISTRATION_GUARD) == 1 else ['the registration guard is not the first check of a fresh'
                                                            ' registration in the patch']


def version_two_ids(layout):
    """The app IDs whose slot directory holds an intact version 2 frame, a staging seed included."""
    return sorted(app_id for app_id, slots in layout['slots'].items() if any(slot['version'] == 2 for slot in slots))


def _users(slots):
    return [user for slot in slots for user in slot['users']]


def sibling_of(layout):
    """The class and expected principal of a valid version 1 slot that names the package or a principal of
    another slot in the layout, from the bytes: ('sibling' or 'sibling-principal', the sibling's app ID
    and its principal) beside a version 2 slot, ('conflict', its app ID, its principal) beside a readable
    version 1 account, or None."""
    newer = version_two_ids(layout)
    for app_id, slots in sorted(layout['slots'].items()):
        older = [slot for slot in slots if slot['version'] == 1 and slot['users']]
        if app_id in newer or not older:
            continue
        sibling = older[0]
        principals = {user['principal'] for user in sibling['users']}
        for other, others in sorted(layout['slots'].items()):
            if other == app_id:
                continue
            for copy in others:
                if not copy['users']:
                    continue
                same_package = copy['package'] == sibling['package']
                same_principal = bool(principals & {user['principal'] for user in copy['users']})
                if not (same_package or same_principal):
                    continue
                if other in newer and copy['version'] == 2:
                    return ('sibling' if same_package else 'sibling-principal', app_id,
                            sibling['users'][0]['principal'])
                if not newer and copy['version'] == 1:
                    return 'conflict', app_id, sibling['users'][0]['principal']
    return None


def rollback_class(layout, revision):
    """The class of one layout for one rollback model, from its decoded bytes and header version alone:
    78456b3 withdraws everything under a version 2 header; beside a version 2 slot, a valid sibling naming
    its package or principal, a bound reservation of another app ID, a lost mapping, or a footprint;
    without one, a conflict of two readable siblings, or a positive control that must equal B1's own
    reading: an eligible body or a reservation admitted, a legacy marker retiring, a tombstone without a
    ticket deferred, or nothing named."""
    if revision == '7845' and layout['header'] == 2:
        return 'withdrawn'
    sibling = sibling_of(layout)
    if version_two_ids(layout):
        if sibling:
            return sibling[0]
        newer = set(version_two_ids(layout))
        if any(entry['phase'] == 'CREATING' and entry['bound'] and entry['app_id'] not in newer
               for header in layout['headers'] for entry in header['entries']):
            return 'reservation'
        return 'lost' if 'lost' in layout['packages'].values() else 'footprint'
    if sibling:
        return 'conflict'
    if not layout['packages']:
        return 'nothing'
    users = _users(slot for slots in layout['slots'].values() for slot in slots)
    if any(user['legacy'] for user in users):
        return 'retiring'
    if users:
        return 'admitted'
    if any(layout['slots'].values()):
        return 'tombstone'
    # No slot copy at all: the mapped package is a bound reservation's.
    return 'admitted'


def reader_class(layout):
    """B1's class of one layout: the 24bfb6a model's, whose positive controls B1 must read alike."""
    return rollback_class(layout, '24bf')


def expectation_lines(layouts, classify):
    """One line per layout: its name, its class, its version 2 slot app IDs or "-", and for a sibling the
    principal that its admitted or conflicting record carries, or "-"."""
    lines = []
    for name, layout in sorted(layouts.items()):
        sibling = sibling_of(layout)
        lines.append('%s %s %s %s\n' % (name, classify(layout), ','.join(map(str, version_two_ids(layout))) or '-',
                                         '%d:%d' % sibling[1:] if sibling else '-'))
    return ''.join(lines)


def class_counts(lines):
    counts = {}
    for line in lines.splitlines():
        counts[line.split()[1]] = counts.get(line.split()[1], 0) + 1
    return counts


def counts_argument(counts):
    return ','.join('%s=%d' % item for item in sorted(counts.items()))


def swapped(lines, swaps):
    """The expectation lines with these layouts given another class: a control that must fail exactly
    there."""
    out = []
    for line in lines.splitlines():
        name, klass, ids, principal = line.split()
        out.append('%s %s %s %s\n' % (name, swaps.get(name, klass), ids, principal))
    return ''.join(out)


def swap_controls(predictions):
    """Each rollback model's swap control, rotated: every class's assertions applied once, to a layout
    of another class."""
    return {revision: predictions['p6_checkpoint_1']['rollback'][revision]['swap_control']
            for revision, _ in ROLLBACK_MODELS}


def model_prediction_problems(predicted, swaps):
    """The predicted classes of each model and of the reader cover every layout once, and every swap
    control names layouts that exist and gives each class exactly once, so the assertions of every
    class are shown to reject a layout of another class."""
    problems = []
    for revision, _ in ROLLBACK_MODELS:
        counts = predicted['rollback'][revision]['classes']
        if sum(counts.values()) != len(LAYOUT_NAMES) or not set(counts) <= set(ROLLBACK_CLASSES):
            problems.append('predicted rollback classes of %s do not cover the layouts' % revision)
        for name, klass in swaps[revision].items():
            if name not in LAYOUT_NAMES or klass not in ROLLBACK_CLASSES:
                problems.append('rollback swap control %s %s' % (name, klass))
        if sorted(swaps[revision].values()) != sorted(ROLLBACK_CLASSES):
            problems.append('rollback swap control of %s does not give each class once' % revision)
    counts = predicted['readers']['classes']
    if sum(counts.values()) != len(LAYOUT_NAMES) or not set(counts) <= set(READER_CLASSES):
        problems.append('predicted reader classes do not cover the layouts')
    return problems


def rollback_inputs(pinned, scratch):
    """Each rollback model's pinned half and the (revision, path) of every Git object it read. The
    candidate Settings of 24bfb6a and 78456b3 come from their pinned patches over the pinned framework
    copies, as the history runner's archive builds them."""
    built = b2.archived_candidates(pinned, scratch)
    settings = {'24bf': built[b2.ARCHIVE], '7845': built[b2.ROLLBACK]}
    files, reads = {}, {}
    original, original_git = b1.pinned_bytes, b1.git_bytes
    for revision, _ in ROLLBACK_MODELS:
        log = reads[revision] = []
        git = reads[revision + ' git'] = []

        def recorded(source, path, log=log):
            log.append((source, path))
            return original(source, path)

        # Every Git object read at all, so a read that bypasses the pinned loader shows too.
        def git_recorded(commit, path, git=git):
            git.append((commit, path))
            return original_git(commit, path)
        try:
            b1.pinned_bytes, b1.git_bytes = recorded, git_recorded
            files[revision] = rollback_model_files(revision, settings[revision])
        finally:
            b1.pinned_bytes, b1.git_bytes = original, original_git
    return files, reads

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
    """Every step but the pinned one is living and carries living labels, and the pinned step only
    archived ones. This runner's harness rows name its tests, and the new-format label names only cases
    that are not production in B1."""
    problems = []
    for step, labels in STEP_LABELS.items():
        allowed = b1.ARCHIVED_RUN_LABELS if step in PINNED_STEPS else b1.LIVING_RUN_LABELS
        if step not in PHASES or not labels or not set(labels) <= set(allowed):
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
            or labelled.get(MANAGER_TEST) != every or labelled.get(LAYOUTS) != {'new-format'}
            or labelled.get(ROLLBACK_CHECK) != {'rollback-reader'}
            or labelled.get(READER_CHECK) != {'production', 'new-format'} or set(labelled) != {
                CODEC_TEST, READ_TEST, STORE_TEST, TRANSACTION_TEST, FAULT_TEST, SETTINGS_TEST, MANAGER_TEST, LAYOUTS,
                ROLLBACK_CHECK, READER_CHECK}):
        problems.append('harness labels of this runner differ: %s' % labelled)
    if {row[0] for row in b1.HARNESS_LABELS if row[0] == 'new-format'} != {'new-format'} or any(
            row[1] != 'scripts/proof/native_lifecycle_record.py' for row in b1.HARNESS_LABELS if row[0] == 'new-format'):
        problems.append('the new-format label names another harness')
    if b1.LIVING_ROLLBACK_CHECKS != (ROLLBACK_CHECK,):
        problems.append('the living rollback check exception names %s' % (b1.LIVING_ROLLBACK_CHECKS,))
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
    problems += layout_name_problems()
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
            counts['transactions'], counts['faults'], counts['settings'], counts['manager'], counts['layouts']) != (
            len(CODEC_NAMES), len(READ_NAMES), len(GOLDEN_NAMES), len(MUTANTS), len(STORE_NAMES),
            len(TRANSACTION_NAMES), len(FAULT_NAMES), len(SETTINGS_NAMES), len(MANAGER_NAMES), len(LAYOUT_NAMES)):
        problems.append('predicted counts differ from the case lists')
    layouts = predictions['p5_checkpoint_2']['layouts']
    if (layouts['names'], layouts['facts'], layouts['step_families'], layouts['by_group']) != (
            len(LAYOUT_NAMES), len(LAYOUT_FACTS), len(LAYOUT_STEP_FAMILIES), layout_groups()):
        problems.append('predicted layouts differ from the layout lists')
    problems += model_prediction_problems(predictions['p5_checkpoint_2'], swap_controls(predictions))
    problems += registration_guard_problems()
    problems += case_map_problems()
    case_map = predictions['p6_checkpoint_1a']['case_map']
    if (case_map['mapped'], case_map['to_move']) != (len(CASE_MAP), len(CASE_MAP_TO_MOVE)):
        problems.append('predicted case map differs from the case map')
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


def layout_files():
    """The current product sources with the existing host write fault seams, the seam class, the shared
    fixtures and the layout emitter."""
    files = b1.with_seams(b1.product_sources())
    for name in (FAULT_SEAM, SUPPORT, LAYOUTS):
        files['tests/%s.java' % name] = (ROOT / PLATFORM / (name + '.java')).read_bytes()
    return files


def rollback_files(pinned_half):
    """One rollback model's compile set: its pinned half, assembled with the working tree closed, and the
    working-tree rollback check, the one living input, written against the old API only."""
    return {**pinned_half, 'tests/%s.java' % ROLLBACK_CHECK: (ROOT / PLATFORM / (ROLLBACK_CHECK + '.java')).read_bytes()}


def reader_files(settings):
    """The reader check's compile set: the current product, the history stubs, the candidate's harness
    and the current test supports with the B1 adapter."""
    files = b1.product_sources()
    files.update(b2.history_stubs())
    files['tests/NativeHistoryHarness.java'] = b2.harness_source(settings, 'b2').encode()
    files.update(b1.test_sources(list(READER_SUPPORT) + [READER_CHECK], adapter='b1'))
    return files


def check_outcome(run, names, failing=()):
    """Whether a finished check passed every named case but exactly the failing ones, and how."""
    passed, failed = set(run['passed']), set(run['failed'])
    if passed | failed != set(names) or len(run['passed']) + len(run['failed']) != len(names):
        return 'cases %d passed, %d failed, of %d named' % (len(passed), len(failed), len(names))
    if failed != set(failing):
        return 'failed %s, predicted %s' % (sorted(failed - set(failing))[:5], sorted(set(failing) - failed)[:5])
    if bool(run['returncode']) != bool(failing) or (not failing and 'unqualified' not in run['stdout']):
        return 'exit %s' % run['returncode']
    return None


def emitted_names(stdout):
    """The layout names the emitter printed, in order."""
    return [line[len('LAYOUT '):] for line in stdout.splitlines() if line.startswith('LAYOUT ')]


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


def pinned_phase(work, pinned, steps, problems, predicted=None):
    """The rollback models' pinned inputs: assembled from Git objects with the working tree closed, read
    only where the manifest pins, and compiled against each old product. The file and read counts and the
    differing files are recorded and compared with the predictions. Returns the pinned halves."""
    pinned_halves, reads = rollback_inputs(pinned, work / 'pinned-candidates')
    first, second = (pinned_halves[revision] for revision, _ in ROLLBACK_MODELS)
    steps['pinned'] = {'manifest': rollback_manifest_problems(reads), 'builds': {},
                       'files': {revision: len(pinned_halves[revision]) for revision, _ in ROLLBACK_MODELS},
                       'distinct_reads': {revision: len(set(reads[revision])) for revision, _ in ROLLBACK_MODELS},
                       'differing_files': sorted(name for name in set(first) | set(second)
                                                 if first.get(name) != second.get(name))}
    problems += ['pinned rollback inputs: ' + item for item in steps['pinned']['manifest']]
    if predicted is not None:
        record = steps['pinned']
        if (record['differing_files'] != predicted['differing_files']
                or set(record['files'].values()) != {predicted['files_per_model']}
                or set(record['distinct_reads'].values()) != {predicted['distinct_reads_per_model']}):
            problems.append('pinned inputs differ from the predictions: %s' % {
                key: record[key] for key in ('files', 'distinct_reads', 'differing_files')})
    for revision, _ in ROLLBACK_MODELS:
        built = b1.build(Path(tempfile.mkdtemp(dir=work, prefix='pinned-' + revision + '-')), pinned_halves[revision])
        steps['pinned']['builds'][revision] = {'returncode': built['returncode'], 'inputs': built['inputs'],
                                               'output': built['output'][-4000:]}
        if built['returncode']:
            problems.append('pinned rollback inputs of %s do not compile' % revision)

    return pinned_halves


def layout_evidence(emitted, steps, problems, predicted=None):
    """The kinds and the layouts without holds of the emitted set, recorded in the report and compared
    with the predictions."""
    kinds, without = {}, []
    for path in sorted(emitted.iterdir()):
        kind = ' '.join((path / 'kind').read_text().split())
        kinds[kind] = kinds.get(kind, 0) + 1
        if not (path / 'holds').read_text():
            without.append(path.name)
    steps['layouts']['kinds'], steps['layouts']['without_holds'] = kinds, without
    if predicted is not None and (kinds != predicted['kinds'] or without != predicted['without_holds']):
        problems.append('layout kinds or holds differ from the predictions: %s %s' % (kinds, without))


def layouts_phase(work, steps, problems, predicted=None):
    """The layout emitter under Format.V3 and the coverage check over every layout it writes."""
    layouts = work / 'layouts'
    (layouts / 'build').mkdir(parents=True)
    built = b1.build(layouts / 'build', layout_files())
    steps['layouts'] = {'build': {'returncode': built['returncode'], 'output': built['output'][-4000:]}}
    if built['returncode']:
        problems.append('layout emitter does not compile')
    else:
        run = b1.execute(layouts / 'build', LAYOUTS, [str(layouts / 'emitted'), str(layouts / 'state')],
                         timeout=3600)
        steps['layouts']['run'] = {'returncode': run['returncode'], 'stdout': run['stdout'][-4000:],
                                   'stderr': run['stderr'][-4000:]}
        names = emitted_names(run['stdout'])
        if (run['returncode'] or len(names) != len(set(names)) or sorted(names) != sorted(LAYOUT_NAMES)
                or 'unqualified' not in run['stdout']):
            problems.append('layout emitter run')
        else:
            refused = b1.execute(layouts / 'build', LAYOUTS, [str(layouts / 'no-assertions'), str(layouts / 'state')],
                                 assertions=False, timeout=120)
            if not refused['returncode'] or '-ea' not in refused['stderr']:
                problems.append('layout emitter ran without assertions')
            found, facts = layouts_check(layouts / 'emitted')
            layout_evidence(layouts / 'emitted', steps, problems, predicted)
            steps['layouts']['coverage'] = found
            steps['layouts']['facts'] = {name: sorted(value) for name, value in facts.items()}
            problems += ['layouts: ' + item for item in found]



def read_emitted(emitted, problems):
    """Every emitted layout, read by the independent decoder, or none when the set is incomplete."""
    read = {path.name: read_layout(path) for path in sorted(emitted.iterdir())} if emitted.is_dir() else {}
    if sorted(read) != sorted(LAYOUT_NAMES):
        problems.append('no complete layouts to read')
        return {}
    return read


def rollback_phase(work, predictions, pinned_halves, emitted, steps, problems):
    """The rollback models over the emitted layouts, each against the class this runner states for every
    layout from the independent reading, with their swap and format controls."""
    predicted = predictions['p5_checkpoint_2']
    read = read_emitted(emitted, problems)
    steps['rollback'] = {}
    for revision, format_name in ROLLBACK_MODELS if read else ():
        record = steps['rollback'][revision] = {}
        expected = predicted['rollback'][revision]
        swaps = swap_controls(predictions)[revision]
        lines = expectation_lines(read, lambda layout, revision=revision: rollback_class(layout, revision))
        record['classes'] = class_counts(lines)
        if record['classes'] != expected['classes']:
            problems.append('rollback classes of %s differ from the prediction: %s' % (revision, record['classes']))
        same = sorted(name for name, klass in swaps.items() if rollback_class(read[name], revision) == klass)
        if same:
            problems.append('rollback swap control of %s keeps the own class of %s' % (revision, same))
        base = work / 'rollback' / revision
        base.mkdir(parents=True)
        (base / 'expectations').write_text(lines)
        built = b1.build(base / 'build', rollback_files(pinned_halves[revision]))
        record['build'] = {'returncode': built['returncode'], 'output': built['output'][-4000:]}
        if built['returncode']:
            problems.append('rollback check of %s does not compile' % revision)
            continue
        names = ['lifecycle rollback / ' + name for name in LAYOUT_NAMES] + ['lifecycle rollback / layouts by class']
        controls = {'run': (format_name, lines, ()),
                    'swap control': (format_name, swapped(lines, swaps),
                                     ['lifecycle rollback / ' + name for name in swaps]),
                    'format control': (expected['format_control_format'], lines,
                                       ['lifecycle rollback / ' + name for name in expected['format_control']])}
        for leg, (format_used, text, failing) in controls.items():
            (base / (leg.replace(' ', '-') + '.expectations')).write_text(text)
            run = b1.execute(base / 'build', ROLLBACK_CHECK, [
                str(emitted), str(base / ('state-' + leg.replace(' ', '-'))), format_used,
                str(base / (leg.replace(' ', '-') + '.expectations')), counts_argument(class_counts(text))],
                timeout=1800)
            record[leg] = {'returncode': run['returncode'], 'failed': run['failed'], 'passed': len(run['passed']),
                           'stdout': run['stdout'][-3000:], 'stderr': run['stderr'][-3000:]}
            found = check_outcome(run, names, failing)
            if found:
                problems.append('rollback %s %s: %s' % (revision, leg, found))
        refused = b1.execute(base / 'build', ROLLBACK_CHECK, [str(emitted), str(base / 'no-assertions'), format_name,
                                                              str(base / 'expectations'), 'x=0'],
                             assertions=False, timeout=120)
        if not refused['returncode'] or '-ea' not in refused['stderr']:
            problems.append('rollback check of %s ran without assertions' % revision)



def readers_phase(work, predictions, settings, emitted, steps, problems):
    """B1's reader under Format.V2 and Format.V3 over the emitted layouts, with the cross-format controls."""
    predicted = predictions['p5_checkpoint_2']
    read = read_emitted(emitted, [])
    steps['readers'] = {}
    if read:
        record = steps['readers']
        expected = predicted['readers']
        lines = expectation_lines(read, reader_class)
        record['classes'] = class_counts(lines)
        if record['classes'] != expected['classes']:
            problems.append('reader classes differ from the prediction: %s' % record['classes'])
        base = work / 'readers'
        base.mkdir(parents=True)
        (base / 'expectations').write_text(lines)
        built = b1.build(base / 'build', reader_files(settings))
        record['build'] = {'returncode': built['returncode'], 'output': built['output'][-4000:]}
        if built['returncode']:
            problems.append('reader check does not compile')
        else:
            counts = class_counts(lines)
            with_valid = dict(counts, valid=expected['valid_under_v3'],
                              **{'outside-user-0': expected['outside_user_0_under_v3']})
            versioned = [name for name in LAYOUT_NAMES if reader_class(read[name]) in VERSION_TWO_CLASSES]
            legs = {'V2': ('V2', None, counts, 'lifecycle reader / ', ()),
                    'V3': ('V3', None, with_valid, 'lifecycle reader V3 / ', ()),
                    'V2 asserted under V3': ('V3', 'V2', counts, 'lifecycle reader / ', versioned),
                    'V3 asserted under V2': ('V2', 'V3', dict(counts, valid=0, **{
                        'outside-user-0': expected['outside_user_0_under_v3']}), 'lifecycle reader V3 / ', versioned)}
            for leg, (format_used, other, pairs, prefix, failing) in legs.items():
                run = b1.execute(base / 'build', READER_CHECK, [
                    str(emitted), str(base / ('state-' + leg.replace(' ', '-'))), format_used,
                    str(base / 'expectations'), counts_argument(pairs), *([other] if other else [])], timeout=1800)
                record[leg] = {'returncode': run['returncode'], 'failed': run['failed'], 'passed': len(run['passed']),
                               'stdout': run['stdout'][-3000:], 'stderr': run['stderr'][-3000:]}
                names = [prefix + name for name in LAYOUT_NAMES] + [prefix + 'layouts by class']
                found = check_outcome(run, names, [prefix + name for name in failing])
                if found:
                    problems.append('reader %s: %s' % (leg, found))
            refused = b1.execute(base / 'build', READER_CHECK, [str(emitted), str(base / 'no-assertions'), 'V2',
                                                                str(base / 'expectations'), 'x=0'],
                                 assertions=False, timeout=120)
            if not refused['returncode'] or '-ea' not in refused['stderr']:
                problems.append('reader check ran without assertions')



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

    pinned_halves = pinned_phase(work, pinned, steps, problems, predictions['p5_checkpoint_2']['pinned'])
    report['completed_phases'].append('pinned')
    layouts_phase(work, steps, problems, predictions['p5_checkpoint_2']['layouts'])
    report['completed_phases'].append('layouts')
    # Each layout's class comes from the independent reading of its bytes and every class count is
    # predicted, so no layout leaves its branch.
    rollback_phase(work, predictions, pinned_halves, work / 'layouts' / 'emitted', steps, problems)
    report['completed_phases'].append('rollback')
    readers_phase(work, predictions, settings, work / 'layouts' / 'emitted', steps, problems)
    report['completed_phases'].append('readers')

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
