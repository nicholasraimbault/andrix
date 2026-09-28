#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of B2: one shared historical native identity view and exact
restored creation rebinding. No compiler or JVM starts unless an actual cgroup bounds this
process to 2 GiB of memory, no swap, 2 CPUs and 256 tasks, with core dumps disabled, and the
resolved --work path is short enough for the deepest Unix socket a step binds below it. Otherwise
the run is NOT_RUN and creates and starts nothing. That socket budget needs a --work of at most
32 ASCII characters, such as /srv/b2w. A guarded run creates files only under that fresh --work
directory, including its checkpoint progress.json, and the fresh --evidence file. The unchanged
B1 runner it runs as a regression keeps its own behavior: its version 2 presence matrix binds its
sockets in a fresh /tmp/b1p-* directory, and everything else it writes is under --work. Unless
the JDK is configured otherwise, each JVM also keeps HotSpot's transient performance data file
in /tmp/hsperfdata_<user> while it runs. A run that stops early keeps every finished record and
its NOT_COMPLETE status; nothing is retried.
Source checks are pure Python. Not Android, crash, power loss, storage or activation evidence."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
sys.path.insert(0, str(ROOT / 'scripts/proof/tests'))
import native_creation_binding as b1  # noqa: E402
import native_principal_pins as integration  # noqa: E402

PLATFORM = b1.PLATFORM
FRAMEWORK_DIR = b1.FRAMEWORK_DIR
SETTINGS = integration.PREFIX + 'Settings.java'
PREDICTIONS = ROOT / 'scripts/proof/native_creation_history_predictions.json'
TEMPLATE = ROOT / PLATFORM / 'NativeHistoryHarness.java.in'
HISTORY_STUBS = ROOT / PLATFORM / 'native_history_stubs'
BODY_INPUTS = {'0018': ROOT / PLATFORM / 'native_history_api/baseline/body-inputs.java.inc',
               'b2': ROOT / PLATFORM / 'native_history_api/b2/body-inputs.java.inc'}
PROBE = ROOT / PLATFORM / 'BodyOriginRetirementProbe.java'
PRESENCE_TEST = ROOT / PLATFORM / 'NativeIdentityPresenceTest.java'
STORE_REGRESSION = ROOT / 'scripts/proof/tests/test_native_identity_store.py'
# NativeIdentityPresenceTest refuses to bind a socket whose path has this many characters or more.
# The kernel's own limit, 108 bytes with the terminator, is looser.
SOCKET_LIMIT = 100
# Every guarded phase in order. A run reports those it completed and those it did not.
PHASES = ('candidates', 'b2 focused', 'b2 faults', 'probe', 'parity', 'readers', 'mutants', 'b1 runner')
# The primary's reviewed read only probe, copied verbatim. Its 0018a1d result is BODY_ORIGIN_BASELINE.
PROBE_SHA256 = '34bfaf2c5cb8b62df05bd84e770e4d42b157cc8ad9119ab6a2ee5dbb43ff6e04'

BASE = '0018'
REVISION_0018 = '0018a1db6598f0bd08fbf7ed1eb71422805c4f65'
# The pinned 0018a1d product, host facade, test support and patch this runner compares with.
BASELINE_0018 = {
    'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
    'NativePrincipalManager': '5b50050a19ec61d0dcd94431e7f857c9556e4cb8b41a4b74b58576dd45c2cfb5',
    'NativeIdentityRecords': '412c2271a9efabf9937375bd42f2e49c5e3fb4d09935a9e98d6e5805736a3009',
    'NativeIdentityStore': 'd03c4b41dfdf88138d504675f21fda6eed0e175b7a9cc33a3cbd9b25b812e9e9',
    'NativeIdentityPersistence': '1202bb1bf938e613adf2b53cf28a61e6a8632a4ef40bd896cbc8f793e5bd4934',
    'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
    'Settings': '23b0dde8b399aa9165d5785e974527878eaed2f5b93bd3ba7bd85a0595f3aa8b'}
SUPPORT_0018 = {
    'NativeHeaderTestSupport.java': '73251ca4e30390017ab220746607deb176293ca117f3c32952b715c395fc16bf',
    'NativeBindingTestSupport.java': '2426ad2e672f28b762444727c9c34b9987fe5db4d7a1927a6c1d74b7ba8c199d',
    'native_header_api/b1/NativeHeaderApi.java':
        '674f66fb85586a68b0f9adb2f13facf30551ca47693f6ed3e1026ea8093bbc4b'}
PATCH_PATH = 'patches/grapheneos-2026081300/native-principal-pins.patch'
PATCH_0018_SHA256 = '072c964b4887ef7ff2e246cb1e8f0e633975b05d36e05b8e6daf6262e08a9209'
SETTINGS_0018_SHA256 = '17cfd8f7c9b436f83cccf749703ee2a584467fd59dedc1b7bc7709511275655c'
# 0018a1d becomes one more exact baseline of the B1 Git object loader, in memory only.
b1.REVISIONS[BASE] = REVISION_0018
b1.BASELINE_SHA256[BASE] = dict(BASELINE_0018)

STEPS = ('seed-synced', 'backup-renamed', 'backup-published', 'write-started', 'main-synced',
         'reserve-synced', 'backup-unlink', 'backup-unlinked')
FOCUSED_NAMES = (
    'history / an eligible body is BODY with its one user', 'history / a retiring body keeps its marker',
    'history / a body under its creation entry is BODY',
    'history / a complete creation without a body is a reservation',
    'history / an empty slot directory keeps the reservation',
    'history / a torn seed keeps the reservation and is no history', 'history / an intact seed is never history',
    'history / a damaged header keeps an eligible body', 'history / the production V1 format reads no reservation',
    'history / a protected V2 target beside V1 predecessors is a reservation',
    'history / bodies with a nonzero user give none and claim their principals',
    'history / tombstones give none and keep their holds',
    *('no fallback / ' + name for name in (
        'a binding mismatch', 'a directory record', 'a file entry', 'a future body', 'a link entry',
        'a tombstone', 'conflicting copies', 'damaged copies', 'an unavailable body')),
    *('gate / ' + name for name in (
        'a slot entry that is no app ID', 'an unindexed slot directory', 'an unsupported header seed',
        'an unsupported slot seed', 'an unavailable header copy', 'a LIVE copy of the creation',
        'a LIVE entry without a body', 'a RELEASING entry without a body', 'a copy of another lineage',
        'a copy with a counter only difference', 'a copy with another binding', 'a copy without the binding',
        'a version 1 entry', 'a version 2 entry without a binding', 'an unselected addition',
        "another user's binding", 'a compatible LIVE copy is withdrawn by corroboration alone',
        'incompatible copies are withdrawn by the copy rule alone')),
    *('uniqueness / ' + name for name in (
        'a body elsewhere naming this app ID', 'a conflicting copy', 'a damaged copy', 'a legacy creation entry',
        'a tombstone package', 'an unselected addition', 'an unsupported copy', 'the package of a valid body',
        'the principal of a valid body', 'valid bodies stay usable beside a withdrawn reservation',
        'two reservations of one package both withdraw', 'an unavailable copy withdraws through the store gate',
        'an unrelated sibling keeps the reservation')),
    'restoration / a store view needs no backstop', 'restoration / the backstop withdraws only merged reservations',
    'restoration / reservations restore PENDING under the selected counter',
    'restoration / an unknown counter restores R beside unselected X',
    'stored history / only the exact record is returned', 'stored history / only an exact core pin is remembered',
    *('rebind / ' + name for name in (
        'an explicit designation publishes the original ID', 'the next issuance advances the selected counter',
        'a new package reserves beside an unrebound reservation',
        'missing directory, empty directory and torn seed publish',
        'a mismatched intact seed refuses and keeps the reservation',
        'changed APK signers refuse without taking APK history',
        'a changed serial, UID, mapping or shared user refuses',
        'an unknown counter rebinds but neither commits nor issues',
        'a protected target confirms beside its predecessors',
        'a body first creation completes its lost LIVE entry')),
    'body only / no header only binding, current identity or ACTIVE exposure',
    *('retirement / ' + name for name in (
        'a never rebound reservation refuses before any effect',
        'a cached body missing from the store returns false without a write',
        'an explicitly rebound reservation publishes and retires',
        'BODY origin republishes after its body was observed missing',
        'no durable marker restores PENDING after restart', 'a restored retiring body finishes')),
    'scan / a mapped reservation is scanned with its recorded signers',
    'scan / signer, serial, retiring, mapping and shared negatives',
    'scan / a withdrawn reservation defers its package',
    'seeding / a mapped reservation stays recoverable',
    'seeding / an unmapped reservation keeps its hold and unidentified code',
    'seeding / shared and foreign mappings are deferred',
    'seeding / a matching data owner keeps a mapped reservation recoverable',
    'seeding / foreign, unreadable and unowned data owners are deferred',
    'seeding / an incomplete data owner enumeration keeps unidentified code',
    'seeding / a reservation seeds as its published body under every data owner',
    'holds / every hold and fence remains',
    'holds / an exact release lifts only its own UID hold and keystore fence')
FAULT_KINDS = ('exact header confirmation', 'first body write', 'LIVE completion',
               'rebound retirement publication', 'rebound retirement marker')
FAULT_NAMES = tuple('%s / %s' % (kind, step) for kind in FAULT_KINDS for step in STEPS)
PROBE_CHECK = 'probe / BODY origin baseline'
LAYOUT_NAMES = tuple(sorted(
    ['history-reserved', 'history-beside-body', 'history-unknown-counter', 'history-protected-target',
     'history-rebound']
    + ['history-%s-%s' % (kind, step) for kind in (
        'exact-confirmation', 'first-body', 'live-completion', 'retirement-publication',
        'retirement-marker') for step in STEPS]))
# Reservation layouts whose version 2 outcomes differ from 0018a1d on the same bytes and equal
# it on their published twins. Every other layout, and every version 1 run, equals 0018a1d.
TWINNED = ('reservation', 'reservation-empty-directory', 'reservation-torn-seed',
           'reservation-beside-body', 'protected-target', 'unknown-counter',
           'reservation-beside-multi-user-body')

STORE = FRAMEWORK_DIR + 'NativeIdentityStore.java'
PERSISTENCE = FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
MANAGER = FRAMEWORK_DIR + 'NativePrincipalManager.java'
FACADE = PLATFORM + 'native_principal_stubs/com/android/server/pm/Settings.java'
SEEDING = PLATFORM + 'native_recovery_fragments/recovery-seeding.java.inc'
_ALWAYS = '        if (!view.creationReady() || HeaderCopies.of(view.header) == null) {\n'
_GATE = '                    || read == null || read.status != Status.MISSING || read.unavailable\n'
_CLAIMS = '                    || !corroborated(view.header, creation) || claimed(view, creation)) continue;\n'
_HEADER_CLAIM = '                if (entry.appId != creation.appId && entry.phase == SlotPhase.CREATING\n'
_SLOT_CLAIMS = '            for (Slot claim : other.getValue().decodedCopies) {\n'
_ORIGIN = ('        return handle.selection != null\n'
           '                || handle.priorSource == NativeIdentityStore.Source.BODY;\n')
_SCAN_HEAD = '        if (history == null || candidateShared || mappingPackage == null || mappingShared\n'
# Deliberate B2 defects: source, exact replacements and the suites to run. The predictions file
# lists the checks each must fail. A compile failure is a harness failure, never a caught defect.
MUTANTS = {
    'no-reservation-history': (STORE, ((
        _ALWAYS, '        if (!view.creationReady() || HeaderCopies.of(view.header) == null || view != null) {\n'),),
        ('focused', 'faults')),
    'body-needs-creation-ready': (STORE, ((
        '            if (!view.bindingUsable(appId) || held.getValue().value.users.size() != 1) continue;\n',
        '            if (!view.bindingUsable(appId) || !view.creationReady()\n'
        '                    || held.getValue().value.users.size() != 1) continue;\n'),), ('focused',)),
    'retiring-history-dropped': (STORE, ((
        'user.userId, user.userSerial, body.signerSha256, user.retiring, Source.BODY));',
        'user.userId, user.userSerial, body.signerSha256, false, Source.BODY));'),), ('focused',)),
    'reservation-without-creation-ready': (STORE, ((
        _ALWAYS, '        if (view.header.status != Status.VALID || HeaderCopies.of(view.header) == null) {\n'),),
        ('focused',)),
    'reservation-without-copy-facts': (STORE, ((
        _ALWAYS, '        if (!view.creationReady()) {\n'),), ('focused',)),
    'reservation-any-user': (STORE, ((
        '                    || binding.userId != USER_SYSTEM || result.containsKey(creation.appId)\n',
        '                    || result.containsKey(creation.appId)\n'),), ('focused',)),
    'reservation-from-unselected-copy': (STORE, ((
        '        for (HeaderEntry creation : selected.entries) {\n',
        '        for (HeaderEntry creation : view.header.decodedCopies.get(0).entries) {\n'),), ('focused',)),
    'header-fallback-around-damage': (STORE, ((
        _GATE, '                    || read == null || read.status == Status.VALID || read.unavailable\n'),),
        ('focused',)),
    'tombstone-history': (STORE, ((
        _GATE, '                    || read == null || (read.status != Status.MISSING && !(read.value == null\n'
               '                    && !read.decodedCopies.isEmpty() && read.decodedCopies.get(0).users.isEmpty()))\n'
               '                    || read.unavailable\n'),), ('focused',)),
    'seed-history': (STORE, ((
        '                    if (record.unavailable || seed.found == Found.UNAVAILABLE) unavailable = true;\n',
        '                    if (record.unavailable || seed.found == Found.UNAVAILABLE) unavailable = true;\n'
        '                    if (record.status == Status.MISSING && seed.bytes != null) {\n'
        '                        try {\n'
        '                            Slot staged = NativeIdentityRecords.decodeSlot(seed.bytes);\n'
        '                            record = new ReadResult<>(Status.VALID, staged, List.of(staged));\n'
        '                        } catch (IllegalArgumentException torn) {\n'
        '                            record = new ReadResult<>(Status.MISSING, null, List.of());\n'
        '                        }\n'
        '                    }\n'),), ('focused',)),
    'uncorroborated-reservation': (STORE, ((
        _CLAIMS, '                    || claimed(view, creation)) continue;\n'),), ('focused',)),
    'no-uniqueness': (STORE, ((
        _CLAIMS, '                    || !corroborated(view.header, creation)) continue;\n'),), ('focused',)),
    'uniqueness-without-header-claims': (STORE, ((
        _HEADER_CLAIM, '                if (entry.appId != creation.appId && entry.phase == SlotPhase.CREATING'
                       ' && seen == null\n'),), ('focused',)),
    'uniqueness-one-sided': (STORE, ((
        _HEADER_CLAIM, '                if (entry.appId < creation.appId && entry.phase == SlotPhase.CREATING\n'),),
        ('focused',)),
    'uniqueness-without-slot-claims': (STORE, ((
        _SLOT_CLAIMS, '            for (Slot claim : List.<Slot>of()) {\n'),), ('focused',)),
    'uniqueness-valid-bodies-only': (STORE, ((
        _SLOT_CLAIMS, '            for (Slot claim : other.getValue().status == Status.VALID\n'
                      '                    ? other.getValue().decodedCopies : List.<Slot>of()) {\n'),), ('focused',)),
    'uniqueness-body-app-id': (STORE, ((
        '                if (claim.packageName.equals(creation.creationPackage)) return true;\n',
        '                if (claim.appId != creation.appId\n'
        '                        && claim.packageName.equals(creation.creationPackage)) return true;\n'),),
        ('focused',)),
    'uniqueness-package-only': (STORE, ((
        '                    if (user.id == creation.creationId) return true;\n',
        '                    if (user.id == creation.creationId && user.retiring) return true;\n'),), ('focused',)),
    'backstop-dropped': (PERSISTENCE, ((
        '            NativePrincipalPins.Record restored = restorable(entry.getKey(), entry.getValue(),\n'
        '                    histories);\n',
        '            NativePrincipalPins.Record restored = record(entry.getValue());\n'),), ('focused',)),
    'backstop-withdraws-everything': (PERSISTENCE, ((
        '        if (reservation.appId != key || reservation.retiring\n'
        '                || reservation.userId != USER_SYSTEM) return null;\n',
        '        if (reservation.appId == key) return null;\n'),), ('focused', 'faults')),
    'scan-ignores-mapping': (PERSISTENCE, (
        (_SCAN_HEAD, '        if (history == null || candidateShared || mappingShared\n'),
        ('                || !mappingPackage.equals(candidatePackage)) return null;\n',
         '                || (mappingPackage != null && !mappingPackage.equals(candidatePackage))) return null;\n')),
        ('focused',)),
    'scan-allows-shared-mapping': (PERSISTENCE, ((
        _SCAN_HEAD, '        if (history == null || candidateShared || mappingPackage == null\n'),), ('focused',)),
    'scan-ignores-serial': (PERSISTENCE, ((
        '                || history.userId != USER_SYSTEM || history.userSerial != currentSerial\n',
        '                || history.userId != USER_SYSTEM\n'),), ('focused',)),
    'scan-allows-retiring': (PERSISTENCE, ((
        '                || currentSerial < 0 || history.appId != candidateAppId || history.retiring\n',
        '                || currentSerial < 0 || history.appId != candidateAppId\n'),), ('focused',)),
    'selection-only-guard': (MANAGER, ((
        _ORIGIN, '        return handle.selection != null;\n'),), ('focused', 'probe')),
    'always-create-body': (MANAGER, ((
        _ORIGIN, '        return handle != null;\n'),), ('focused',)),
    'current-view-origin': (MANAGER, ((
        '        NativeIdentityStore.History prior = pm.mSettings.nativePrincipalStoredHistoryLPr(pin.record());\n',
        '        NativeIdentityStore.History prior =\n'
        '                pm.mSettings.mNativeIdentityLoaded.history(pin.record().appId);\n'),), ('focused',)),
    'current-view-guard': (MANAGER, ((
        '                mayCreateBody = mayCreateBody(handle);\n',
        '                mayCreateBody = handle.selection != null\n'
        '                        || pm.mSettings.nativePrincipalBindingLPr(handle.pin.record()) != null;\n'),),
        ('focused',)),
    'dropped-early-guard': (MANAGER, ((
        '                if (!mayCreateBody\n'
        '                        && pm.mSettings.nativePrincipalBindingLPr(handle.pin.record()) == null) {\n'
        '                    throw new IllegalStateException(\n'
        '                            "Restored native reservation needs its designation before retirement");\n'
        '                }\n', ''),), ('focused',)),
    'persist-ignores-origin': (MANAGER, ((
        '            if (!mayCreateBody || issued == null || !persistence.reservePending(issued)) return false;\n',
        '            if (issued == null || !persistence.reservePending(issued)) return false;\n'),), ('focused',)),
    'current-signers-only': (MANAGER, ((
        '        Handle created = new Handle(this, pin, prior.lineage, prior.signerSha256, prior.source);\n',
        '        Handle created = new Handle(this, pin, prior.lineage,\n'
        '                signerDigests(pm.mSettings.getPackageLPr(pin.record().packageName)), prior.source);\n'),),
        ('focused',)),
    'scan-current-signers': (FACADE, ((
        '        try { return history.signerSha256.equals(NativePrincipalManager.signerDigests(signer)); }\n',
        '        try { return NativePrincipalManager.signerDigests(signer) != null; }\n'),), ('focused',)),
    'published-binding-from-history': (FACADE, ((
        '        if (!mNativeIdentityLoaded.bindingUsable(record.appId)) return null;\n'
        '        NativeIdentityRecords.Slot slot = mNativeIdentityLoaded.slots.get(record.appId).value;\n'
        '        return matches(slot, record) ? slot : null;\n',
        '        NativeIdentityStore.History history = mNativeIdentityLoaded.history(record.appId);\n'
        '        if (history == null || !NativeIdentityPersistence.identifies(history, record)) return null;\n'
        '        return new NativeIdentityRecords.Slot(history.lineage, history.appId, history.packageName, 1,\n'
        '                history.signerSha256, java.util.List.of(new NativeIdentityRecords.UserEntry(history.id,\n'
        '                history.userId, history.userSerial, history.retiring)));\n'),), ('focused',)),
    'remember-without-exact-pin': (FACADE, ((
        '            if (pin != null && NativeIdentityPersistence.identifies(history, pin.record())) {\n',
        '            if (pin != null) {\n'),), ('focused',)),
    'stored-history-partial-match': (FACADE, ((
        '        return history != null && NativeIdentityPersistence.identifies(history, record) ? history : null;\n',
        '        return history;\n'),), ('focused',)),
    'seeding-body-only': (SEEDING, ((
        '                if (history == null || pkg.hasSharedUser()\n',
        '                if (history == null || history.source != NativeIdentityStore.Source.BODY\n'
        '                        || pkg.hasSharedUser()\n'),), ('focused',)),
    # The follow-up controls: data owner seeding branches, the refreshed recovery holds and the
    # booted facade's agreement with the adapted Settings text.
    'seeding-trusts-data-owners': (SEEDING, ((
        '            if (pkg == null || footprint.getValue() < 0\n'
        '                    || UserHandle.getUid(UserHandle.USER_SYSTEM, pkg.getAppId()) != footprint.getValue()) {\n',
        '            if (pkg == null) {\n'),), ('focused',)),
    'seeding-ignores-incomplete-enumeration': (SEEDING, ((
        '        if (!mNativeDeEnumerationComplete) mNativeRecoveryView = mNativeRecoveryView.withUnidentifiedCode();\n',
        ''),), ('focused',)),
    'recovery-holds-not-refreshed': (FACADE, ((
        "        // As the adapted framework's refresh does: the recovery view holds the same app IDs.\n"
        '        mNativeRecoveryView = mNativeRecoveryView.withHolds(union);\n', ''),), ('focused',)),
    'facade-restores-differently': (FACADE, ((
        '        } else if (loaded.counterRestorable()) {\n',
        '        } else if (loaded.counterRestorable() && records.isEmpty()) {\n'),), ('focused',)),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- pure source checks

def cut(text, start, end, keep_start=True):
    """The exact text from start, or just after it, to just before end. Each anchor occurs once."""
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('Settings history anchor drift: ' + start.strip()[:70])
    first, last = text.index(start), text.index(end)
    if last < first:
        raise ValueError('Settings history anchors out of order: ' + start.strip()[:70])
    return text[first if keep_start else first + len(start):last]


def method(text, start):
    """One four space indented method from its first line through its closing brace."""
    if text.count(start) != 1:
        raise ValueError('Settings method anchor drift: ' + start.strip()[:70])
    first = text.index(start)
    return text[first:text.index('\n    }\n', first) + len('\n    }\n')]


APPLY_START = '    void applyNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'
BINDING_START = '    NativeIdentityRecords.Slot nativePrincipalBindingLPr(NativePrincipalPins.Record record) {\n'
REMEMBERED_FIELD = re.compile(r'    private final java\.util\.Map<Long, [A-Za-z.]+> mNativeRememberedBindings =\n'
                              r'            new java\.util\.HashMap<>\(\);\n')


def settings_texts(settings):
    """Every history text the harness takes from one candidate Settings, by placeholder: its whole
    boot restoration method and restore inputs, the observation, remembered binding field and
    remembering it calls, the hold refresh, the app ID hold, scan rule and recovery seeding, all
    cut from it, and the shared identity and path safety fragments that it must contain exactly
    once. The restore capacity fragment must occur once, inside the restoration method."""
    fragments = {name: path.read_text() for name, (_, path) in integration.FRAGMENTS.items()}
    for name in ('restore-capacity', 'identity', 'path-safety'):
        if settings.count(fragments[name]) != 1:
            raise ValueError('shared fragment absent from a candidate Settings: ' + name)
    fields = REMEMBERED_FIELD.findall(settings)
    if len(fields) != 1:
        raise ValueError('remembered binding field anchor drift')
    apply = method(settings, APPLY_START)
    if fragments['restore-capacity'] not in apply:
        raise ValueError('restore capacity is not inside the restoration method')
    binding = method(settings, BINDING_START)
    stored = cut(settings, binding, '    String nativeIdentityLineageLPr() {\n', False)
    return {
        'REMEMBERED_FIELD': fields[0],
        'APPLY': apply,
        'OBSERVE': method(settings, '    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'),
        'REFRESH': method(settings, '    void refreshNativePrincipalAppIdsLPw() {\n'),
        'STORED': stored,
        'RESTORE_INPUTS': cut(settings, APPLY_START,
                              '        NativePrincipalPins restored = new NativePrincipalPins(64);\n', False),
        'APP_ID_HELD': method(settings, '    boolean isNativePrincipalAppIdLPr(int appId) {\n'),
        'IDENTITY': fragments['identity'],
        'PATH_SAFETY': fragments['path-safety'],
        'SCAN': cut(settings, '    boolean nativeScanSubjectAllowedLPr(PackageSetting candidate) {\n',
                    '\n    boolean nativePrincipalCreationReadyLPr() {\n'),
        'SEEDING': cut(settings, '    private void seedNativeRecoveryLPw() {\n',
                       '\n    @Watched(manual = true)\n    private final PccIdSettingMap mPccIds;\n'),
    }


def b2_text_checks(settings):
    """The B2 candidate's cut texts are exactly the registered B2 fragments."""
    texts = settings_texts(settings)
    fragments = {name: path.read_text() for name, (_, path) in integration.FRAGMENTS.items()}
    problems = []
    for tag, name in (('RESTORE_INPUTS', 'restore-history'), ('SCAN', 'scan'), ('SEEDING', 'recovery-seeding')):
        if texts[tag] != fragments[name]:
            problems.append('candidate %s differs from fragment %s' % (tag, name))
    if settings.count(fragments['stored-history']) != 1 or fragments['stored-history'] not in texts['STORED']:
        problems.append('candidate lacks the stored history fragment where the harness cuts it')
    if 'rememberNativeHistoriesLPw(loaded);' not in texts['OBSERVE'] or 'bindingUsable' in texts['OBSERVE']:
        problems.append('candidate observation does not remember through the history view')
    if 'NativeIdentityStore.History' not in texts['REMEMBERED_FIELD']:
        problems.append('candidate remembers something other than histories')
    return problems


def harness_source(settings, side, seeding=None):
    """NativeHistoryHarness for one side, filled with that side's exact Settings texts."""
    texts = settings_texts(settings)
    if seeding is not None:
        texts['SEEDING'] = seeding
    texts['BODY_INPUTS'] = BODY_INPUTS[side].read_text()
    source = TEMPLATE.read_text()
    for tag, text in texts.items():
        marker = '@%s@\n' % tag
        if source.count(marker) != 1:
            raise ValueError('harness placeholder drift: ' + tag)
        source = source.replace(marker, text)
    if re.search(r'@[A-Z_]+@', source):
        raise ValueError('unfilled harness placeholder')
    return source


def surface_violations():
    """The B2 production surface: one store history view, the shared Persistence helpers, the
    handle origin guard, body only published bindings and an adapted Settings that uses them."""
    problems = []
    read = lambda path: b1.strip_java_comments((ROOT / path).read_text())
    store, persistence, manager = read(STORE), read(PERSISTENCE), read(MANAGER)
    facade = (ROOT / FACADE).read_text()
    patch = b1.added_java((ROOT / PATCH_PATH).read_text())
    for pattern, what in ((r'\benum\s+Source\s*\{\s*BODY\s*,\s*RESERVATION\s*\}', 'Source enum'),
                          (r'\bstatic\s+final\s+class\s+History\b', 'History class'),
                          (r'histories\s*=\s*historiesOf\(this\);', 'histories computed once'),
                          (r'\bHistory\s+history\(int\s+appId\)', 'Loaded.history'),
                          (r'\bMap<Integer,\s*History>\s+histories\(\)', 'Loaded.histories')):
        if len(re.findall(pattern, store)) != 1:
            problems.append('store lacks one ' + what)
    if re.search(r'\bNativePrincipalPins\b|\bNativeIdentityPersistence\b', store):
        problems.append('store depends on the core or persistence')
    # BODY history stays exactly the bindingUsable slot's one user. A usable body with more users
    # is unreachable: the codec keeps user IDs strictly ascending, and load reads a slot with a
    # nonzero user as UNSUPPORTED, as 0018a1d does. No case can catch the guard's removal, so
    # these anchors keep all three.
    records = read(FRAMEWORK_DIR + 'NativeIdentityRecords.java')
    for text, needle, what in (
            (store, '            if (!view.bindingUsable(appId) || held.getValue().value.users.size() != 1)'
                    ' continue;\n', 'one user BODY guard'),
            (store, '                            if (user.userId != 0) {\n'
                    '                                record = new ReadResult<>(Status.UNSUPPORTED, null,'
                    ' record.decodedCopies);\n', 'user 0 limit at load'),
            (records, 'throw invalid("users not in strictly ascending user ID order");', 'ascending users'),
            (records, 'if (i > 0 && userId <= users.get(i - 1).userId) throw invalid("users out of order");',
             'ascending decoded users')):
        if text.count(needle) != 1:
            problems.append('a usable body with more than one user is no longer unreachable: ' + what)
    if re.search(r'private\s+History\s*\(', store) is None or re.search(r'\bnew\s+History\s*\(', persistence):
        problems.append('History is not built only by the store')
    for pattern, what in ((r'\bstatic\s+Restoration\s+restoration\s*\(\s*Map<Integer,\s*NativeIdentityStore\.History>',
                           'restoration helper'),
                          (r'\bstatic\s+NativeIdentityStore\.History\s+scanOwner\s*\(', 'scan rule'),
                          (r'\bstatic\s+boolean\s+identifies\s*\(', 'record identity'),
                          (r'\bstatic\s+NativePrincipalPins\.Record\s+record\s*\(\s*NativeIdentityStore\.History',
                           'history record')):
        if len(re.findall(pattern, persistence)) != 1:
            problems.append('persistence lacks one ' + what)
    if persistence.count('NativeIdentityRecords.encodedHeaderLength(') != 1:
        problems.append('projection byte measure changed')
    for needle, what in (('private final NativeIdentityStore.Source priorSource;', 'handle origin'),
                         ('handle.priorSource == NativeIdentityStore.Source.BODY', 'body origin rule'),
                         ('nativePrincipalStoredHistoryLPr(pin.record())', 'stored history handle'),
                         ('persistBinding(handle, persistence, issued, true)', 'commit may create'),
                         ('persistBinding(handle, persistence, issued, mayCreateBody)', 'retirement origin')):
        if manager.count(needle) != 1:
            problems.append('manager lacks one ' + what)
    if 'nativePrincipalStoredBindingLPr' in manager + patch + facade:
        problems.append('the former stored binding accessor remains')
    binding = cut(patch, 'NativeIdentityRecords.Slot nativePrincipalBindingLPr(NativePrincipalPins.Record record) {',
                  'private void rememberNativeHistoriesLPw(')
    if 'mNativeIdentityLoaded.bindingUsable(record.appId)' not in binding or 'history(' in binding:
        problems.append('published binding is not body only')
    if patch.count('bindingUsable(') != 1:
        problems.append('Settings still reads bindingUsable outside the published binding')
    if 'Handle created = new Handle(this, pin, prior.lineage, prior.signerSha256, prior.source);' not in manager:
        problems.append('restored handle is not built from the stored history')
    for name in ('admission', 'restore-capacity', 'restore-history', 'stored-history', 'identity', 'scan'):
        if facade.encode().count(integration.FRAGMENTS[name][1].read_bytes()) != 1:
            problems.append('host facade differs from fragment ' + name)
    return problems


def presence_tail():
    """The deepest socket path any guarded step binds below this runner's TMPDIR, from the actual
    nested sources. The unchanged B1 runner's regressions run test_native_identity_store.py under
    that TMPDIR. It passes a default TemporaryDirectory, 'tmp' and eight random characters, to
    NativeIdentityPresenceTest, which binds its special seed socket at
    presence-<format>/c<case>/store/slots/<A>/record.bin-seed. The case number is allowed three
    digits, more than the matrix uses. The B1 runner's own version 2 presence matrix binds in
    /tmp, not below this TMPDIR."""
    test, regression = PRESENCE_TEST.read_text(), STORE_REGRESSION.read_text()
    for text, anchor in (
            (test, '        if (path.toString().length() >= %d) {\n' % SOCKET_LIMIT),
            (test, 'Files.createDirectories(Path.of(args[0]).resolve("presence-" + format));'),
            (test, 'return Files.createDirectory(parent.resolve("c" + ++cases));'),
            (test, 'private static final int A = 10123, B = 10124, SPECIAL = 10125,'),
            (test, '            Path top = fresh();\n'
                   '            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(top.resolve("store"));\n'
                   '            socket(root.resolve("slots/" + A + "/record.bin-seed"));\n'),
            (test, '            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(fresh().resolve("store"));\n'
                   '            socket(root.resolve("slots/" + SPECIAL));\n'),
            (regression, '        with tempfile.TemporaryDirectory() as temporary:\n')):
        if text.count(anchor) != 1:
            raise ValueError('presence socket path anchor drift: ' + anchor.strip()[:70])
    if len(re.findall(r'\bsocket\(', test)) != 3:
        raise ValueError('presence socket fixtures changed')
    return '/%s%s/presence-V1/c999/store/slots/10123/record.bin-seed' % (tempfile.template, 'X' * 8)


def work_path_problem(work):
    """Why this resolved work directory leaves the deepest socket below <work>/tmp too long, or
    None. The presence guard counts Java characters, UTF-16 units; the kernel counts the path's
    bytes. Both must stay below SOCKET_LIMIT. Pure: nothing is created or started."""
    try:
        tail = presence_tail()
    except (OSError, ValueError) as error:
        return 'presence socket path budget unknown: %s' % error
    deepest = str(work / 'tmp') + tail
    characters = len(deepest.encode('utf-16-le', 'surrogatepass')) // 2
    size = len(os.fsencode(deepest))
    if characters < SOCKET_LIMIT and size < SOCKET_LIMIT:
        return None
    return ('work path too long: the deepest presence socket %s has %d characters and %d bytes, and'
            ' NativeIdentityPresenceTest refuses %d or more; use a fresh --work of at most %d ASCII'
            ' characters' % (deepest, characters, size, SOCKET_LIMIT,
                             SOCKET_LIMIT - 1 - len('/tmp') - len(tail)))


def mutant_sources():
    """Each B2 mutant applied to the current text of its target, anchored exactly once."""
    result = {}
    for name, (path, replacements, suites) in MUTANTS.items():
        text = (ROOT / path).read_text()
        for old, new in replacements:
            text = b1.replace_once(text, old, new)
        result[name] = (path, text, suites)
    return result


def source_checks():
    problems = []
    try:
        integration.profile()
    except ValueError as error:
        problems.append('profile: %s' % error)
    # Every B1 source check still holds, including its B0 and B1 mutant anchors.
    try:
        problems += ['b1: ' + problem for problem in b1.source_checks()]
    except ValueError as error:
        problems.append('b1 source checks: %s' % error)
    try:
        problems += surface_violations()
    except ValueError as error:
        problems.append('surface: %s' % error)
    if sha(PROBE.read_bytes()) != PROBE_SHA256:
        problems.append('BODY origin probe differs from the reviewed probe')
    for relative, digest in SUPPORT_0018.items():
        if sha((ROOT / PLATFORM / relative).read_bytes()) != digest:
            problems.append('shared test support drifted from 0018a1d: ' + relative)
    try:
        mutant_sources()
    except ValueError as error:
        problems.append('mutant anchors: %s' % error)
    predictions = json.loads(PREDICTIONS.read_text())
    names = set(FOCUSED_NAMES) | set(FAULT_NAMES) | {PROBE_CHECK}
    expected = predictions['b2_mutants_caught_at_least']
    if set(expected) != set(MUTANTS):
        problems.append('mutant predictions do not list every mutant')
    for name, checks in expected.items():
        if not checks or not set(checks) <= names:
            problems.append('mutant prediction inconsistent: ' + name)
    if (len(set(FOCUSED_NAMES)) != len(FOCUSED_NAMES) or len(set(FAULT_NAMES)) != len(FAULT_NAMES)
            or len(set(LAYOUT_NAMES)) != len(LAYOUT_NAMES)):
        problems.append('duplicate check names')
    if tuple(predictions['parity_twinned_layouts']) != TWINNED:
        problems.append('twinned layout prediction drift')
    try:
        presence_tail()
    except (OSError, ValueError) as error:
        problems.append('work path budget: %s' % error)
    return problems


def candidates(pinned, scratch):
    """B2 and 0018a1d candidate Settings built from the pinned canonical framework copies by
    their own patches, and which of the ten outputs B2 changed. Pure patch reproduction."""
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
    current = integration.targets(original, value)
    patch = b1.git_bytes(REVISION_0018, PATCH_PATH)
    if sha(patch) != PATCH_0018_SHA256:
        raise ValueError('0018a1d patch drift')
    tree = scratch / 'tree'
    for name, data in original.items():
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (scratch / 'patch').write_bytes(patch)
    applied = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                              '-p1', '-i', str(scratch / 'patch')], cwd=tree, capture_output=True, timeout=30)
    if applied.returncode:
        raise ValueError('0018a1d patch failed: ' + applied.stderr.decode(errors='replace'))
    baseline = {name: (tree / name).read_bytes() for name in original}
    if sha(baseline[SETTINGS]) != SETTINGS_0018_SHA256:
        raise ValueError('0018a1d Settings candidate drift')
    changed = sorted(name for name in original if baseline[name] != current[name])
    return {'b2': current[SETTINGS].decode(), BASE: baseline[SETTINGS].decode(), 'changed': changed,
            'outputs': {name: sha(current[name]) for name in sorted(original)}}


# ---------------------------------------------------------------- parity comparison

def parse_parity(text):
    relations, lines = {}, {}
    for line in text.splitlines():
        fields = line.split('\t')
        if fields[0] == 'relation' and len(fields) == 3:
            relations[fields[1]] = fields[2]
        elif len(fields) == 5:
            key = tuple(fields[:4])
            if key in lines:
                raise ValueError('duplicate parity line: ' + '/'.join(key))
            lines[key] = fields[4]
        else:
            raise ValueError('malformed parity line')
    return relations, lines


def compare_parity(baseline_text, b2_text):
    """Problems of the B2 parity output against 0018a1d's, and the twinned layouts whose version
    2 outcome differs on the same bytes."""
    relations, old = parse_parity(baseline_text)
    b2_relations, new = parse_parity(b2_text)
    problems, differing = [], set()
    if relations != b2_relations:
        problems.append('layout relations differ')
    if set(old) != set(new):
        problems.append('outcome keys differ')
    for key, payload in sorted(new.items()):
        fmt, name, kind, detail = key
        if 'threw' in payload:
            problems.append('B2 threw: ' + '/'.join(key))
        twin = relations.get(name, 'same')
        if kind == 'body':
            expected = old.get(key)
        elif fmt == 'V2' and twin != 'same':
            expected = old.get((fmt, twin, kind, detail))
            if old.get(key) != payload:
                differing.add(name)
        else:
            expected = old.get(key)
        if expected != payload:
            problems.append('%s: B2 %r, 0018a1d %r' % ('/'.join(key), payload, expected))
    return problems, sorted(differing)


# ---------------------------------------------------------------- JVM builds, guarded

def history_stubs():
    return {'history-stubs/' + path.relative_to(HISTORY_STUBS).as_posix(): path.read_bytes()
            for path in sorted(HISTORY_STUBS.rglob('*.java'))}


def support_0018():
    files = {}
    for relative, digest in SUPPORT_0018.items():
        data = b1.git_bytes(REVISION_0018, PLATFORM + relative)
        if sha(data) != digest:
            raise ValueError('0018a1d test support drift: ' + relative)
        files['tests/' + Path(relative).name] = data
    return files


def worktree_tests(names, adapter=True):
    files = b1.test_sources(names, adapter='b1' if adapter else None)
    return files


def b2_product(settings, override=None):
    """The current product, facade and fixtures with one mutant override, and the B2 harness."""
    override = override or {}
    framework = {Path(path).stem: text for path, text in override.items() if path.startswith(FRAMEWORK_DIR)}
    files = b1.product_sources(framework_override=framework)
    if FACADE in override:
        files['stubs/com/android/server/pm/Settings.java'] = override[FACADE].encode()
    files.update(history_stubs())
    files['tests/NativeHistoryHarness.java'] = harness_source(settings, 'b2', override.get(SEEDING)).encode()
    return files


def b2_suite(work, settings, kind, override=None):
    product = b2_product(settings, override)
    names = ['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHistoryTestSupport']
    if kind == 'faults':
        product = b1.with_seams(product)
        names += ['NativeHeaderWriteFaults', 'NativeCreationHistoryFaultTest']
        main = 'NativeCreationHistoryFaultTest'
    elif kind == 'probe':
        names = ['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'BodyOriginRetirementProbe']
        main = 'BodyOriginRetirementProbe'
    else:
        names += ['NativeCreationHistoryTest']
        main = 'NativeCreationHistoryTest'
    return b1.suite(work, {**product, **worktree_tests(names)}, main)


def probe_0018(work):
    files = {**b1.product_sources(BASE), **support_0018(), 'tests/BodyOriginRetirementProbe.java': PROBE.read_bytes()}
    return b1.suite(work, files, 'BodyOriginRetirementProbe')


def parity(work, settings, side):
    if side == BASE:
        files = {**b1.product_sources(BASE), **support_0018(), **history_stubs()}
    else:
        files = {**b2_product(settings), **worktree_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport'])}
    files['tests/NativeHistoryHarness.java'] = harness_source(settings, side).encode()
    files['tests/NativeHistoryParity.java'] = (ROOT / PLATFORM / 'NativeHistoryParity.java').read_bytes()
    work.mkdir(parents=True)
    built = b1.build(work, files)
    record = {'build': built}
    if built['returncode']:
        record['compile_failure'] = True
        return record, None
    output = work / 'outcomes.tsv'
    record['run'] = b1.execute(work, 'NativeHistoryParity', [str(work / 'state'), str(output)], timeout=1800)
    text = output.read_text() if output.is_file() else None
    if text is not None:
        record['outcomes'] = {'sha256': sha(text.encode()), 'lines': len(text.splitlines())}
    return record, text


def probe_outcome(record):
    if record.get('compile_failure'):
        return {'error': 'compile failure', 'build': record['build']}
    run = record['run']
    lines = [line for line in run['stdout'].splitlines() if line]
    return {'returncode': run['returncode'], 'lines': lines, 'stderr': run['stderr'],
            'passed': run['returncode'] == 0 and bool(lines) and lines[-1].startswith(
                'B1 BODY-origin retirement baseline passed'), 'build': record['build']}


def probe_red(result):
    """Whether one finished probe run failed on its own assertion: exit status 1 with an
    AssertionError, never a compile failure, crash or other exception."""
    return ('error' not in result and result['returncode'] == 1
            and 'java.lang.AssertionError' in result['stderr'])


def red_names(result, names):
    """The failed case names of one finished suite, or None when it is not a complete result: a
    compile failure, printed case names other than each of names exactly once, or an exit status
    other than 1 with failures and 0 without. A timeout never gets here; it stops the whole run
    with its streams."""
    if 'error' in result:
        return None
    stdout = result['run']['stdout']
    passed = re.findall(r'^PASS (.+)$', stdout, re.M)
    failed = re.findall(r'^FAIL (.+?): ', stdout, re.M)
    if sorted(passed + failed) != sorted(names):
        return None
    if result['returncode'] != (1 if failed else 0):
        return None
    return set(failed)


def stream_text(stream):
    """A captured stream as text: bytes decoded with replacement, None as empty."""
    return stream.decode(errors='replace') if isinstance(stream, bytes) else stream or ''


def exception_record(error):
    """The error that stopped a run, with a timed out command's own captured streams."""
    record = {'type': type(error).__name__, 'message': str(error)}
    if isinstance(error, subprocess.TimeoutExpired):
        command = error.cmd
        record.update(command=[str(part) for part in command] if isinstance(command, (list, tuple))
                      else str(command), timeout=error.timeout, stdout=stream_text(error.stdout),
                      stderr=stream_text(error.stderr))
    return record


class Progress:
    """The one report of a guarded run, shared by every phase before any starts, and written
    to <work>/progress.json with writing descriptor and directory sync at each phase boundary.
    This is a process interruption record, not a filesystem power loss qualification. Its status stays RUNNING until the
    run ends; a killed run leaves RUNNING with only the phases it completed. Nothing retries."""

    def __init__(self, report, path):
        self.report, self.path = report, path
        report.update(status='RUNNING', phase=None, completed_phases=[], steps={})
        report.setdefault('problems', [])
        self.write()

    def begin(self, phase):
        self.report['phase'] = phase
        self.write()

    def done(self, phase):
        if self.report['phase'] != phase:
            raise ValueError('phase %s ended while %s ran' % (phase, self.report['phase']))
        self.report['completed_phases'].append(phase)
        self.report['phase'] = None
        self.write()

    def write(self):
        staged = self.path.with_name(self.path.name + '.new')
        with open(staged, 'w') as stream:
            stream.write(json.dumps(self.report, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, self.path)
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def qualify(work, pinned, progress):
    """Every guarded JVM step, in PHASES order, each recorded into the shared report as it
    finishes. The caller has passed every guard. An exception stops the run where it is: what
    finished stays recorded, and nothing is retried."""
    report = progress.report
    steps, problems = report['steps'], report['problems']
    predictions = json.loads(PREDICTIONS.read_text())

    progress.begin('candidates')
    report['java'] = subprocess.run(['java', '-version'], capture_output=True, text=True,
                                    timeout=60).stderr.strip()
    (work / 'candidates').mkdir(parents=True)
    built = candidates(pinned, work / 'candidates')
    steps['candidates'] = {'changed': built['changed'], 'outputs': built['outputs']}
    if built['changed'] != [SETTINGS]:
        problems.append('B2 changed framework targets other than Settings: %s' % built['changed'])
    problems += b2_text_checks(built['b2'])
    settings = built['b2']
    progress.done('candidates')

    # The focused and fault matrices: each case exactly once, all passing, exit status 0.
    for kind, names in (('focused', FOCUSED_NAMES), ('faults', FAULT_NAMES)):
        progress.begin('b2 ' + kind)
        record = b2_suite(work / ('b2-' + kind), settings, kind)
        result = b1.outcome(record, names)
        steps['b2 ' + kind] = result
        if red_names(result, names) != set():
            problems.append('b2 %s matrix' % kind)
        elif 'unqualified' not in record['run']['stdout']:
            problems.append('b2 %s scope statement missing' % kind)
        else:
            main = 'NativeCreationHistoryFaultTest' if kind == 'faults' else 'NativeCreationHistoryTest'
            refused = b1.execute(work / ('b2-' + kind), main, [str(work / ('b2-' + kind) / 'state-da')],
                                 assertions=False, timeout=120)
            steps['b2 ' + kind]['without_assertions'] = refused
            if not refused['returncode'] or '-ea' not in refused['stderr']:
                problems.append('b2 %s ran without assertions' % kind)
        progress.done('b2 ' + kind)

    # The primary's BODY origin probe on 0018a1d and on B2: both pass with the same lines.
    progress.begin('probe')
    steps['probe'] = {BASE: probe_outcome(probe_0018(work / 'probe-0018'))}
    progress.write()
    steps['probe']['b2'] = probe_outcome(b2_suite(work / 'probe-b2', settings, 'probe'))
    old, new = steps['probe'][BASE], steps['probe']['b2']
    if 'error' in old or 'error' in new or not (old['passed'] and new['passed']) or old['lines'] != new['lines']:
        problems.append('BODY origin probe differs from 0018a1d')
    progress.done('probe')

    # Restoration, seeding and scan outcomes against 0018a1d's exact Settings text.
    progress.begin('parity')
    old_record, old_text = parity(work / 'parity-0018', built[BASE], BASE)
    steps['parity'] = {BASE: old_record}
    progress.write()
    new_record, new_text = parity(work / 'parity-b2', settings, 'b2')
    steps['parity']['b2'] = new_record
    if (old_text is None or new_text is None or old_record['run']['returncode']
            or new_record['run']['returncode']):
        problems.append('parity did not run')
    else:
        mismatches, differing = compare_parity(old_text, new_text)
        steps['parity']['mismatches'] = mismatches[:200]
        steps['parity']['mismatch_count'] = len(mismatches)
        steps['parity']['differing_twinned'] = differing
        if mismatches:
            problems.append('parity with 0018a1d: %d mismatches' % len(mismatches))
        if tuple(differing) != tuple(sorted(TWINNED)):
            problems.append('twinned layouts did not differ as predicted: %s' % differing)
    progress.done('parity')

    # Version 2 history layouts, read by version 1 readers of B2, 0018a1d and c9264e4.
    progress.begin('readers')
    emitter = work / 'layouts-emitter'
    emitter.mkdir(parents=True)
    files = {**b1.with_seams(b2_product(settings)),
             **worktree_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHistoryTestSupport',
                               'NativeHeaderWriteFaults', 'NativeCreationHistoryLayouts'])}
    built_emitter = b1.build(emitter, files)
    layouts = work / 'layouts'
    steps['readers'] = {'emitter_build': built_emitter}
    if built_emitter['returncode']:
        problems.append('history layout emitter did not compile')
    else:
        emitted = b1.execute(emitter, 'NativeCreationHistoryLayouts', [str(layouts), str(emitter / 'state')])
        names = sorted(p.name for p in layouts.iterdir()) if layouts.is_dir() else []
        steps['readers'].update(emitted=names, emitter_run=emitted)
        if emitted['returncode'] or tuple(names) != LAYOUT_NAMES:
            problems.append('history layout emitter')
        readers = (('b2-v1', None, 'b1'), (BASE, BASE, 'b1'), ('c926', 'c926', 'baseline'))
        for target, baseline, adapter in readers if tuple(names) == LAYOUT_NAMES else ():
            copy = work / ('layouts-' + target)
            shutil.copytree(layouts, copy, symlinks=True)
            reader = work / ('reader-' + target)
            reader.mkdir(parents=True)
            product = b1.product_sources(baseline)
            built_reader = b1.build(reader, {**product, **b1.test_sources(
                ['NativeHeaderTestSupport', 'NativeCreationBindingReaderCheck'], adapter=adapter)})
            if built_reader['returncode']:
                problems.append('reader %s did not compile' % target)
                steps['readers'][target] = {'build': built_reader}
                continue
            run = b1.execute(reader, 'NativeCreationBindingReaderCheck', [str(copy), str(reader / 'state')])
            steps['readers'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                        'passed': len(run['passed']), 'build': built_reader, 'run': run}
            if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                    ['version 1 reader / ' + name for name in LAYOUT_NAMES]):
                problems.append('reader ' + target)
            progress.write()
    progress.done('readers')

    # Deliberate B2 defects must compile and be caught by complete runs of their suites.
    progress.begin('mutants')
    steps['mutants'] = {}
    expectations = predictions['b2_mutants_caught_at_least']
    for name, (path, text, suites) in mutant_sources().items():
        override = {path: text}
        failed, record = set(), {}
        steps['mutants'][name] = record
        for kind in suites:
            directory = work / 'mutants' / name / kind
            if kind == 'probe':
                result = probe_outcome(b2_suite(directory, settings, 'probe', override))
                record[kind] = result
                if 'error' in result:
                    problems.append('mutant %s did not compile; not a red result' % name)
                elif probe_red(result):
                    failed.add(PROBE_CHECK)
                elif not result['passed']:
                    problems.append('mutant %s probe did not finish by its own assertion; not a red'
                                    ' result' % name)
                continue
            names = FOCUSED_NAMES if kind == 'focused' else FAULT_NAMES
            result = b1.outcome(b2_suite(directory, settings, kind, override), names)
            record[kind] = result
            if 'error' in result:
                problems.append('mutant %s did not compile; not a red result' % name)
                continue
            red = red_names(result, names)
            if red is None:
                problems.append('mutant %s %s run is not a complete result; its failures are not'
                                ' counted' % (name, kind))
                continue
            failed |= red
        missed = sorted(set(expectations[name]) - failed)
        record['missed'] = missed
        if missed or not failed:
            problems.append('mutant %s not caught: %s' % (name, missed))
        progress.write()
    progress.done('mutants')


def regressions(work):
    """The unchanged B1 runner, with its own guard, baselines, matrices, mutants and regressions.
    It writes under TMPDIR=<work>/tmp and its evidence into <work>, except its version 2 presence
    matrix, which binds its sockets in a fresh /tmp/b1p-* directory for the socket path budget.
    Its regressions bind the version 1 presence sockets below <work>/tmp, which the work path
    budget covers."""
    environment = dict(os.environ, TMPDIR=str(work / 'tmp'))
    evidence = work / 'b1-evidence.json'
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/proof/native_creation_binding.py'),
                             '--evidence', str(evidence)], capture_output=True, text=True,
                            timeout=4 * 3600, cwd=ROOT, env=environment)
    record = {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    if evidence.is_file():
        report = json.loads(evidence.read_text())
        record['status'] = report.get('status')
        record['problems'] = report.get('problems')
        record['evidence_sha256'] = sha(evidence.read_bytes())
    return record


def fresh_outside(path, what):
    resolved = path.resolve()
    if resolved.exists() or ROOT in resolved.parents or resolved == ROOT:
        raise ValueError('fresh %s outside the repository required' % what)
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--work', type=Path,
                        help='fresh scratch directory outside the repository; a guarded run needs'
                             ' it to resolve to at most 32 ASCII characters, such as /srv/b2w')
    parser.add_argument('--pinned-framework', type=Path, help='pinned canonical framework copies')
    parser.add_argument('--source-checks-only', action='store_true')
    args = parser.parse_args(argv)
    report = {'runtime_qualified': False, 'android_qualified': False, 'activation': False}
    problems = source_checks()
    report['source_checks'] = problems or 'PASS'
    if args.source_checks_only:
        if args.pinned_framework:
            if not args.work:
                parser.error('--work is required to rebuild candidates')
            work = fresh_outside(args.work, 'work directory')
            work.mkdir(parents=True)
            tempfile.tempdir = str(work)
            built = candidates(args.pinned_framework.resolve(strict=True), work)
            report['candidate'] = {'changed': built['changed'], 'outputs': built['outputs']}
            problems += b2_text_checks(built['b2'])
            if built['changed'] != [SETTINGS]:
                problems.append('B2 changed framework targets other than Settings')
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
    reason = work_path_problem(work) or b1.resource_guard()
    if not reason and not (shutil.which('javac') and shutil.which('java')):
        reason = 'no JDK on PATH'
    if reason:
        report.update(status='NOT_RUN', reason=reason)
        print(json.dumps(report, indent=2))
        return 2
    work.mkdir(parents=True)
    (work / 'tmp').mkdir()
    tempfile.tempdir = str(work / 'tmp')
    report['problems'] = problems
    progress = Progress(report, work / 'progress.json')
    try:
        qualify(work / 'b2', pinned, progress)
        progress.begin('b1 runner')
        report['b1_runner'] = regressions(work)
        if report['b1_runner']['returncode'] or report['b1_runner'].get('status') != 'PASS':
            problems.append('B1 runner regression')
        progress.done('b1 runner')
        report['status'] = 'FAIL' if problems else 'PASS'
    except Exception as error:
        report['exception'] = exception_record(error)
        problems.append('qualification did not complete')
        report['status'] = 'NOT_COMPLETE'
    report['not_completed_phases'] = [phase for phase in PHASES
                                      if phase not in report['completed_phases']]
    if report['not_completed_phases'] and report['status'] != 'NOT_COMPLETE':
        problems.append('phases did not complete: %s' % report['not_completed_phases'])
        report['status'] = 'NOT_COMPLETE'
    progress.write()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
