#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of the native account lifecycle record codec and its readers: the
slot version 2 codec, the stable prefix reader of later slot versions and the reads of every store
format, as B1 package P1 of plans/2026-10-08-native-lifecycle-record.md defines them.

Pure source checks run first. An independent encoder, written here from the plan's layout alone,
gives every version 2 golden. Each must have the length and SHA-256 that the Java codec test pins,
and the plan's size arithmetic must hold for it. The mutant anchors, the predictions and the labels
must agree, and the production format guard of the binding runner must hold. No compiler or JVM
starts unless an actual cgroup bounds this process to 2 GiB of memory, no swap, 2 CPUs and 256
tasks, with core dumps disabled, and a JDK is on PATH. Otherwise the run is NOT_RUN. A guarded run
rebuilds the candidate Settings from the pinned framework copies, runs the codec test and compares
every golden it writes with the independent encoder byte for byte, runs the read test under
Format.V1, V2 and V3 with the facade identity predicate and the candidate's seeding text, and runs
each deliberate defect against the suites predicted to catch it. It does not nest another runner.

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
FACADE = b1.FACADE
CODEC_TEST = 'NativeLifecycleCodecTest'
READ_TEST = 'NativeLifecycleReadTest'
# The history harness text the read test runs: the candidate's exact Settings texts.
HARNESS = 'harness'
PHASES = ('candidate', 'codec', 'reads', 'mutants')
# Every step is living. The read test runs each store format under its own label: Format.V1 is
# legacy, Format.V2 production and Format.V3 the new format, which B1 builds and does not ship.
STEP_LABELS = {'codec': ('production',), 'reads': ('production', 'legacy', 'new-format'),
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

# ---------------------------------------------------------------- deliberate defects

_IDENTITY_PREFIX = ('                // A later slot version\'s stable prefix names its package as negative evidence.\n'
                    '                for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes) {\n'
                    '                    if (prefix.packageName.equals(packageName)) return true;\n'
                    '                }\n')
_SEEDING_PREFIX = ('            for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes)'
                   ' names.add(prefix.packageName);\n')
# Each defect: its edits, as target, exact old text and new text, and the suites that run it. A
# target is a source path, or HARNESS: the history harness text filled from the candidate, whose
# identity and seeding are the fragments, so its anchors are checked in the fragment files. The
# predictions file lists the checks each must fail. A compile failure is a harness failure.
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
        ''),), ('reads',)),
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
    'identity-ignores-prefixes': (((FACADE, _IDENTITY_PREFIX, ''), (HARNESS, _IDENTITY_PREFIX, '')), ('reads',)),
    'seeding-ignores-prefixes': (((HARNESS, _SEEDING_PREFIX, ''),), ('reads',)),
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
    anchor must occur exactly once, a harness anchor in the identity or seeding fragment."""
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
            texts[target] = b1.replace_once(texts.get(target, (ROOT / target).read_text()), old, new)
        result[name] = (texts, tuple(harness), suites)
    return result


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
    if labelled.get(CODEC_TEST) != {'production'} or labelled.get(READ_TEST) != set(FORMAT_LABELS.values()):
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
    for test, names in ((CODEC_TEST, CODEC_NAMES), (READ_TEST, READ_NAMES)):
        if len(set(names)) != len(names):
            problems.append('duplicate case names of ' + test)
        # A failure prints 'FAIL <name>: <problems>', read up to the first colon and space.
        if any(': ' in name for name in names):
            problems.append('a case name of %s holds the failure separator' % test)
    codec = (ROOT / PLATFORM / (CODEC_TEST + '.java')).read_text()
    for name in CODEC_NAMES:
        if not name.startswith('golden / ') and codec.count('"%s"' % name) != 1:
            problems.append('codec case not named once in its source: ' + name)
    try:
        mutant_texts()
    except ValueError as error:
        problems.append('mutant anchors: %s' % error)
    predictions = strict(PREDICTIONS.read_text())
    if 'PREDICTED' not in predictions['status']:
        problems.append('predictions are not marked as predictions')
    expected = predictions['mutants_caught_at_least']
    if set(expected) != set(MUTANTS):
        problems.append('mutant predictions do not list every mutant')
    for name, checks in expected.items():
        suites = MUTANTS.get(name, ((), ()))[1]
        allowed = set(CODEC_NAMES if 'codec' in suites else ()) | set(READ_NAMES if 'reads' in suites else ())
        if not checks or not set(checks) <= allowed:
            problems.append('mutant prediction inconsistent: ' + name)
    counts = predictions['cases']
    if (counts['codec'], counts['reads'], counts['goldens'], counts['mutants']) != (
            len(CODEC_NAMES), len(READ_NAMES), len(GOLDEN_NAMES), len(MUTANTS)):
        problems.append('predicted counts differ from the case lists')
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

    steps['mutants'] = {}
    expectations = predictions['mutants_caught_at_least']
    for name, (texts, harness, suites) in mutant_texts().items():
        failed, record = set(), {}
        steps['mutants'][name] = record
        for suite in suites:
            directory = work / 'mutants' / name / suite
            if suite == 'codec':
                (result, _), _ = codec_suite(directory, texts)
                names = CODEC_NAMES
            else:
                result, _ = read_suite(directory, settings, texts, harness)
                names = READ_NAMES
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
