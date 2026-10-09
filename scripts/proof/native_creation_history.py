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
its NOT_COMPLETE status; nothing is retried. The comparisons with 0018a1d and 78456b3 are archived
at 24bfb6a: they read pinned Git objects and candidates built from pinned patches only. The probe
and the parity also run on the current sources as living legs: the probe by its own assertions,
and the parity against the archived 24bfb6a side, differing exactly where the predictions say.
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
# Host stubs that only the history harness needs. None remain: the package state stub moved to the
# shared host stubs when the facade began to run the exact seeding fragment.
HISTORY_STUBS = ROOT / PLATFORM / 'native_history_stubs'
BODY_INPUTS = {'0018': ROOT / PLATFORM / 'native_history_api/baseline/body-inputs.java.inc',
               'b2': ROOT / PLATFORM / 'native_history_api/b2/body-inputs.java.inc'}
PROBE = ROOT / PLATFORM / 'BodyOriginRetirementProbe.java'
# The living parity compiles the pinned 24bfb6a parity driver, so that it and the archived side run
# one driver. While it does, the working-tree driver keeps those bytes: a package that edits the
# driver moves the living parity to its edit and predicts each difference.
PARITY_DRIVER = ROOT / PLATFORM / 'NativeHistoryParity.java'
PRESENCE_TEST = ROOT / PLATFORM / 'NativeIdentityPresenceTest.java'
STORE_REGRESSION = ROOT / 'scripts/proof/tests/test_native_identity_store.py'
# NativeIdentityPresenceTest refuses to bind a socket whose path has this many characters or more.
# The kernel's own limit, 108 bytes with the terminator, is looser.
SOCKET_LIMIT = 100
# Every guarded phase in order. A run reports those it completed and those it did not.
PHASES = ('candidates', 'b2 focused', 'b2 faults', 'probe', 'living probe', 'parity', 'living parity', 'readers',
          'archived readers', 'mutants', 'b1 runner')
# The primary's reviewed read only probe, copied verbatim. Its 0018a1d result is BODY_ORIGIN_BASELINE.
# The living probe run keeps these bytes until its cases are ported, and the archived probe sides
# compile the pinned 24bfb6a object, which has them too.
PROBE_SHA256 = '34bfaf2c5cb8b62df05bd84e770e4d42b157cc8ad9119ab6a2ee5dbb43ff6e04'
ARCHIVED_PROBE = b1.ARCHIVED_PLATFORM + 'BodyOriginRetirementProbe.java'
ARCHIVED_PROBE_MAIN = 'BodyOriginRetirementProbe'
# The archive of the B1 runner: 24bfb6a, the source of the qualified version 2 normal image.
ARCHIVE = b1.ARCHIVE

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
# R0 of the version 2 normal store routes the shared support's host facades through the adapter,
# so the B1 adapter keeps them Format.V1 after the facade's default became the production V2.
# Comments aside, the 24bfb6a support is 0018a1d's with exactly these code replacements. Both are
# pinned Git objects: archived sides compile the 24bfb6a support and the 0018a1d probe and parity
# sides their own.
ARCHIVED_SUPPORT_R0 = {
    'NativeHeaderTestSupport.java': (
        ('PackageManagerService pm = new PackageManagerService(root, false);',
         'PackageManagerService pm = NativeHeaderApi.pm(root, false);'),
        ('PackageManagerService pm = new PackageManagerService(fresh(), true);',
         'PackageManagerService pm = NativeHeaderApi.pm(fresh(), true);')),
    'native_header_api/b1/NativeHeaderApi.java': ((
        'return new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1); }',
        'return new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1); }'
        ' static PackageManagerService pm(Path root, boolean initialize) {'
        ' return new PackageManagerService(root, initialize, NativeIdentityStore.Format.V1); }'),)}
# The exact R0 bytes of the shared support at 24bfb6a, beside the code comparison above. They are
# the archive's pins of these objects.
SUPPORT_R0_SHA256 = {
    'NativeHeaderTestSupport.java': '8632e5257eeb24f0c0d23fd8fdfd4ee363d30bc4890093b7421c24e43aa71560',
    'NativeBindingTestSupport.java': '2426ad2e672f28b762444727c9c34b9987fe5db4d7a1927a6c1d74b7ba8c199d',
    'native_header_api/b1/NativeHeaderApi.java':
        '781f7d345cdcdc4c7a28ae1cb89deb90f219093600d50906337aa7e4f24bda25'}
PATCH_PATH = 'patches/grapheneos-2026081300/native-principal-pins.patch'
PATCH_0018_SHA256 = '072c964b4887ef7ff2e246cb1e8f0e633975b05d36e05b8e6daf6262e08a9209'
SETTINGS_0018_SHA256 = '17cfd8f7c9b436f83cccf749703ee2a584467fd59dedc1b7bc7709511275655c'
# The 78456b3 rollback reader, the last version 1 normal image, registered by the B1 runner: its
# patch and adapted Settings, which construct Format.V1 at the boot read.
ROLLBACK = '7845'
PATCH_7845_SHA256 = '8e5a3ec75d0e9b0d9d6258c5e332f01c9258092145cbd3e32335aae8bf5f2d3d'
SETTINGS_7845_SHA256 = 'd18ffbd11b4382046ab7df33dec2913ca527bb31e5acfe32b38da2a1d2b17ba6'
# The archived 24bfb6a patch and adapted Settings, which construct Format.V2 at the boot read.
PATCH_24BF_SHA256 = 'eeaf34b2101c58f36d577ec020feb64f30bbdc6ddb982d7647e09ff223f5d4d5'
SETTINGS_24BF_SHA256 = '301cb589989220fb017fa9ab58fd2a36775dc68ec49362e73e15770a84408455'
# The version 1 reader of the layouts the current sources emit: target, baseline revision and
# adapter. b2-v1 is the current sources under Format.V1. Those sources stop modelling 78456b3 once
# B1 edits them, so this reader and its facade and seeding rollback checks are legacy guards of
# the existing format reader.
READERS = (('b2-v1', None, 'b1'),)
LEGACY_ROLLBACK = (('b2-v1', None),)
# The archived version 1 readers of the layouts the pinned 24bfb6a emitter writes, each over pinned
# Git objects only: the 24bf-v1 twin of the R0 rollback reader model, 0018a1d, c9264e4 and the
# pinned 78456b3 image.
ARCHIVED_READERS = (('24bf-v1', ARCHIVE, 'b1'), (BASE, BASE, 'b1'), ('c926', 'c926', 'baseline'),
                    (ROLLBACK, ROLLBACK, 'b1'))
# The rollback model's targets over the archived layouts: the 24bfb6a sources under Format.V1 and
# the pinned 78456b3 image.
ARCHIVED_ROLLBACK_READERS = (('24bf-v1', ARCHIVE), (ROLLBACK, ROLLBACK))
ROLLBACK_CHECKS = (('NativeRollbackReaderCheck', 'rollback reader'),
                   ('NativeRollbackSeedingCheck', 'rollback seeding'))
# Every emitted history layout holds a version 2 header copy: each starts from version 2 copies.
# The rollback checks assert this count. Their controls, the reservation and the rebound body, are
# read again under the production Format.V2.
ROLLBACK_COPY_LAYOUTS = 45
ROLLBACK_CONTROLS = ('history-rebound', 'history-reserved')
# The labels of this runner's guarded steps and readers, as the B1 runner's HARNESS_LABELS name them.
STEP_LABELS = {'b2 focused': ('production', 'legacy'), 'b2 faults': ('production',),
               'probe': ('archived-baseline',), 'living probe': ('production', 'legacy'),
               'parity': ('archived-baseline', 'rollback-reader'), 'living parity': ('production', 'legacy'),
               'readers': ('production', 'legacy'),
               'archived readers': ('archived-baseline', 'rollback-reader'),
               'mutants': ('production', 'legacy')}
# This runner's archived steps. Every other labelled step is living.
ARCHIVED_STEP_NAMES = ('probe', 'parity', 'archived readers')
READER_LABELS = {'b2-v1': 'legacy', '24bf-v1': 'rollback-reader', BASE: 'archived-baseline',
                 'c926': 'archived-baseline', ROLLBACK: 'rollback-reader'}
# 0018a1d becomes one more exact baseline of the B1 Git object loader, in memory only, with the
# test support and patch that archived comparisons read there, and 78456b3 with its patch.
b1.REVISIONS[BASE] = REVISION_0018
b1.BASELINE_SHA256[BASE] = dict(BASELINE_0018)
b1.BASELINE_INPUTS_SHA256[BASE] = {
    **{b1.ARCHIVED_PLATFORM + relative: digest for relative, digest in SUPPORT_0018.items()},
    b1.ARCHIVED_PATCH: PATCH_0018_SHA256}
b1.BASELINE_INPUTS_SHA256[ROLLBACK] = {b1.ARCHIVED_PATCH: PATCH_7845_SHA256}
# The archived history inputs at 24bfb6a: the harness template and body inputs by side, and the
# history stubs. The frozen expectations of the archived history layouts follow.
ARCHIVED_TEMPLATE = b1.ARCHIVED_PLATFORM + 'NativeHistoryHarness.java.in'
ARCHIVED_BODY_INPUTS = {BASE: b1.ARCHIVED_PLATFORM + 'native_history_api/baseline/body-inputs.java.inc',
                        'b2': b1.ARCHIVED_PLATFORM + 'native_history_api/b2/body-inputs.java.inc'}
ARCHIVED_HISTORY_STUBS = b1.ARCHIVED_PLATFORM + 'native_history_stubs/'
ARCHIVED_PARITY = b1.ARCHIVED_PLATFORM + 'NativeHistoryParity.java'
ARCHIVED_LAYOUT_NAMES = tuple(sorted(
    ['history-reserved', 'history-beside-body', 'history-unknown-counter', 'history-protected-target',
     'history-rebound']
    + ['history-%s-%s' % (kind, step) for kind in (
        'exact-confirmation', 'first-body', 'live-completion', 'retirement-publication',
        'retirement-marker') for step in b1.ARCHIVED_STEPS]))
ARCHIVED_COPY_LAYOUTS = 45
ARCHIVED_ROLLBACK_CONTROLS = ('history-rebound', 'history-reserved')
# The SHA-256 of each archived side's filled NativeHistoryHarness, by body input side: the harness
# the 24bfb6a qualification compiled for the 24bfb6a and 78456b3 candidates, and for 0018a1d's. It
# pins the cutting of the candidate texts too, so no later change of settings_texts reaches them.
ARCHIVED_HARNESS_SHA256 = {'b2': 'dcb0991f0a026d907ce25409a6b8b8168271e43aa0a0f14a6b22f13d0cbb1c1c',
                           BASE: '8a615d1fa4fad74ffbf04de0fc5833f8969c91482621f239d6744d8250cafd17'}

STEPS = ('seed-synced', 'backup-renamed', 'backup-published', 'write-started', 'main-synced',
         'reserve-synced', 'backup-unlink', 'backup-unlinked')
FOCUSED_NAMES = (
    'history / an eligible body is BODY with its one user', 'history / a retiring body keeps its marker',
    'history / a body under its creation entry is BODY',
    'history / a complete creation without a body is a reservation',
    'history / an empty slot directory keeps the reservation',
    'history / a torn seed keeps the reservation and is no history', 'history / an intact seed is never history',
    'history / a damaged header keeps an eligible body',
    'history / the version 1 rollback reader reads no reservation',
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
    'holds / an exact release keeps its UID hold and keystore fence until a new instance')
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
    # The body's lifecycle record dropped: a retiring body's history reads ELIGIBLE.
    'retiring-history-dropped': (STORE, ((
        'user.userId, user.userSerial, body.signerSha256, user.lifecycle, Source.BODY));',
        'user.userId, user.userSerial, body.signerSha256,\n'
        '                    NativeIdentityRecords.Lifecycle.version1(false), Source.BODY));'),), ('focused',)),
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
        '        if (reservation.appId != key || !reservation.eligible()\n'
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
    # The scan rule's lifecycle check dropped: a retiring history owns the scan.
    'scan-allows-retiring': (PERSISTENCE, ((
        '                || currentSerial < 0 || history.appId != candidateAppId || !history.eligible()\n',
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
BOOT_FACTS_START = '    private void recordNativeBootFactsLPw(NativeIdentityStore.Loaded loaded) {\n'
QUERIES_START = '    NativeIdentityPersistence.BootFacts nativeBootFactsLPr() {\n'
RELEASE_FINISH_START = ('    void finishNativeIdentityReleaseLPw(NativePrincipalPins.Record record,'
                        ' NativeIdentityStore.Loaded loaded) {\n')
# The adapted boot order the host facade's restore keeps: restore, observe, seed, then the boot
# facts.
BOOT_ORDER = ('NativeIdentityPersistence.restoration(loaded.histories());',
              'observeNativeIdentityStoreLPw(loaded);', 'seedNativeRecoveryLPw();',
              'recordNativeBootFactsLPw(loaded);')
BINDING_START = '    NativeIdentityRecords.Slot nativePrincipalBindingLPr(NativePrincipalPins.Record record) {\n'
REMEMBERED_FIELD = re.compile(r'    private final java\.util\.Map<Long, [A-Za-z.]+> mNativeRememberedBindings =\n'
                              r'            new java\.util\.HashMap<>\(\);\n')


def settings_texts(settings):
    """Every history text the harness takes from one candidate Settings, by placeholder: its whole
    boot restoration method and restore inputs, the observation, remembered binding field and
    remembering it calls, the hold refresh, the app ID hold, scan rule, recovery seeding, boot
    facts, retired boot queries and release finish, all cut from it, and the shared identity and
    path safety fragments that it must contain exactly once. The restore capacity fragment must
    occur once, inside the restoration method."""
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
        'BOOT_FACTS': method(settings, BOOT_FACTS_START),
        'RETIRED_BOOT': cut(settings, QUERIES_START,
                            '\n    boolean nativeScanSubjectAllowedLPr(PackageSetting candidate) {\n'),
        'RELEASE_FINISH': method(settings, RELEASE_FINISH_START),
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
    for tag, name in (('BOOT_FACTS', 'boot-facts'), ('RETIRED_BOOT', 'retired-boot'),
                      ('RELEASE_FINISH', 'release-finish'), ('OBSERVE', 'observation')):
        if settings.count(fragments[name]) != 1 or not fragments[name].endswith(texts[tag]):
            problems.append('candidate %s is not the end of fragment %s' % (tag, name))
    if texts['APPLY'].count('recordNativeBootFactsLPw(loaded);') != 1:
        problems.append('candidate boot restoration does not record the boot facts once')
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
    # The facade carries every Settings fragment verbatim, and restores in the adapted boot order.
    for name, (target, fragment) in integration.FRAGMENTS.items():
        if target == integration.SETTINGS and facade.encode().count(fragment.read_bytes()) != 1:
            problems.append('host facade differs from fragment ' + name)
    problems += boot_order_problems(patch + '\n', facade)
    return problems


def boot_order_problems(patch, facade):
    """The host facade's restore runs restore, observe, seed and the boot facts in the order of the
    adapted boot restoration method, each once."""
    problems = []
    for name, text, start in (('adapted boot restoration', patch, APPLY_START),
                              ('host facade restore', facade, '    void restoreAfterPackageSettings() {\n')):
        body = method(text, start)
        positions = [body.find(step) if body.count(step) == 1 else -1 for step in BOOT_ORDER]
        if -1 in positions or positions != sorted(positions):
            problems.append('%s does not restore, observe, seed and record the boot facts in order' % name)
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


def label_problems():
    """Every step and reader carries labels its kind allows: living steps and readers only living
    labels, and archived ones only archived labels. Living readers read the current sources and
    archived readers a registered revision; every reader is labelled once; the rollback models are
    archived rollback-reader targets over their readers' revisions, and the legacy rollback checks
    living legacy ones."""
    problems = []
    for step, labels in STEP_LABELS.items():
        allowed = b1.ARCHIVED_RUN_LABELS if step in ARCHIVED_STEP_NAMES else b1.LIVING_RUN_LABELS
        if not labels or not set(labels) <= set(allowed):
            problems.append('step %s carries labels %s' % (step, labels))
    if not set(ARCHIVED_STEP_NAMES) <= set(STEP_LABELS) or not set(STEP_LABELS) <= set(PHASES):
        problems.append('labelled steps differ from the phases')
    readers = READERS + ARCHIVED_READERS
    baselines = {target: baseline for target, baseline, _ in readers}
    if (set(READER_LABELS) != set(baselines) or len(readers) != len(READER_LABELS)
            or any(baseline is not None or READER_LABELS.get(target) not in b1.LIVING_RUN_LABELS
                   for target, baseline, _ in READERS)
            or any(baseline not in b1.REVISIONS or READER_LABELS.get(target) not in b1.ARCHIVED_RUN_LABELS
                   for target, baseline, _ in ARCHIVED_READERS)
            or any(baselines.get(target, False) != baseline
                   for target, baseline in ARCHIVED_ROLLBACK_READERS + LEGACY_ROLLBACK)
            or {target for target, _ in ARCHIVED_ROLLBACK_READERS} - {
                target for target, _, _ in ARCHIVED_READERS if READER_LABELS.get(target) == 'rollback-reader'}
            or {target for target, _ in LEGACY_ROLLBACK} - {
                target for target, _, _ in READERS if READER_LABELS.get(target) == 'legacy'}):
        problems.append('reader labels differ from the readers')
    return problems


def mutant_sources():
    """Each B2 mutant applied to the current text of its target, anchored exactly once."""
    result = {}
    for name, (path, replacements, suites) in MUTANTS.items():
        text = (ROOT / path).read_text()
        for old, new in replacements:
            text = b1.replace_once(text, old, new)
        result[name] = (path, text, suites)
    return result


# The other module level names of this runner that its archive uses: its pinned revisions and pins,
# the hash and the archive's own check. Every other name the archive uses begins with archived or
# ARCHIVED_.
ARCHIVE_SHARED = ('ARCHIVE', 'BASE', 'REVISION_0018', 'BASELINE_0018', 'ROLLBACK', 'SUPPORT_0018', 'SUPPORT_R0_SHA256',
                  'PATCH_0018_SHA256', 'SETTINGS_0018_SHA256', 'PATCH_7845_SHA256', 'SETTINGS_7845_SHA256',
                  'PATCH_24BF_SHA256', 'SETTINGS_24BF_SHA256', 'PROBE_SHA256', 'sha', 'archive_problems')


def boundary_problems():
    """This runner's archive uses only archive names, of its own and of the B1 archive."""
    b1_names = b1.archive_names(Path(b1.__file__).read_text(), b1.ARCHIVE_SHARED)
    return b1.archive_boundary(Path(__file__).read_text(), ARCHIVE_SHARED, {'b1': b1_names, 'integration': None})


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
    # The living probe run keeps the reviewed bytes until its cases are ported.
    if sha(PROBE.read_bytes()) != PROBE_SHA256:
        problems.append('BODY origin probe differs from the reviewed probe')
    # The living parity compiles the pinned 24bfb6a driver, so the working-tree driver keeps its bytes.
    if sha(PARITY_DRIVER.read_bytes()) != b1.ARCHIVE_SHA256[ARCHIVED_PARITY]:
        problems.append('parity driver differs from the pinned 24bfb6a driver that the living parity compiles')
    try:
        problems += archived_support_problems()
    except ValueError as error:
        problems.append('shared test support: %s' % error)
    problems += label_problems()
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
    predicted = predictions['living_parity']['predicted_differences']
    if not isinstance(predicted, list) or len(set(predicted)) != len(predicted):
        problems.append('living parity prediction is not a list of distinct outcome keys')
    try:
        problems += archive_problems()
    except ValueError as error:
        problems.append('archive: %s' % error)
    problems += boundary_problems()
    try:
        presence_tail()
    except (OSError, ValueError) as error:
        problems.append('work path budget: %s' % error)
    return problems


def candidates(pinned, scratch):
    """The current candidate Settings, built from the pinned canonical framework copies by the
    current patch, beside the archived 24bfb6a, 0018a1d and 78456b3 candidates of the archive. Pure
    patch reproduction."""
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
    current = integration.targets(original, value)
    built = archived_candidates(pinned, scratch)
    built.update(b2=current[SETTINGS].decode(), outputs={name: sha(current[name]) for name in sorted(original)})
    return built


def candidate_problems(built):
    """The current candidate's texts are the current fragments, and every archived candidate check
    holds."""
    return b2_text_checks(built['b2']) + archived_candidate_problems(built)


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


def parity_differences(archived_text, living_text):
    """Every difference of the current sources' parity outcomes from the archived 24bfb6a side's,
    sorted: 'relation/<layout>' for a twin relation and '<format>/<layout>/<kind>/<detail>' for an
    outcome line that one side lacks or prints otherwise. Pure."""
    relations, old = parse_parity(archived_text)
    current_relations, new = parse_parity(living_text)
    return sorted(['relation/' + name for name in set(relations) | set(current_relations)
                   if relations.get(name) != current_relations.get(name)]
                  + ['/'.join(key) for key in set(old) | set(new) if old.get(key) != new.get(key)])


def predicted_parity(archived_text, living_text, predicted):
    """The living parity's differences from the archived side, the differences the predictions do
    not state and the predicted differences that did not occur, each sorted. Pure."""
    differences = parity_differences(archived_text, living_text)
    return differences, sorted(set(differences) - set(predicted)), sorted(set(predicted) - set(differences))


# ---------------------------------------------------------------- JVM builds, guarded

def history_stubs():
    return {'history-stubs/' + path.relative_to(HISTORY_STUBS).as_posix(): path.read_bytes()
            for path in sorted(HISTORY_STUBS.rglob('*.java'))}


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
    if SEEDING in override:
        # A seeding defect is in the fragment text, which the facade carries verbatim too.
        facade = files['stubs/com/android/server/pm/Settings.java'].decode()
        files['stubs/com/android/server/pm/Settings.java'] = b1.replace_once(
            facade, (ROOT / SEEDING).read_text(), override[SEEDING]).encode()
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


def living_parity_files(settings):
    """The living parity: the current product, harness and support with the pinned 24bfb6a parity
    driver, whose fixed matrix holds the archived layouts. The source checks hold the working-tree
    driver to those bytes."""
    files = {**b2_product(settings), **worktree_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport'])}
    files['tests/NativeHistoryParity.java'] = b1.pinned_bytes(ARCHIVE, ARCHIVED_PARITY)
    return files


def run_parity(work, files):
    """One parity side's outcomes from its assembled sources."""
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


# ---------------------------------------------------------------- the 24bfb6a archive
# The archive of this runner: its candidates, checks, assemblies and phases. They read pinned Git
# objects only and run only archive code, the code in this section and in the B1 runner's archive.
# Part of it is copied from 24bfb6a, verbatim but for its names and, where marked, reading pinned
# objects, and tests compare each copy with its 24bfb6a Git object. None of it calls a living
# function of the three runners or reads a living constant.

# The Settings anchors of 24bfb6a, which the frozen cutting uses.
ARCHIVED_APPLY_START = '    void applyNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'
ARCHIVED_BINDING_START = ('    NativeIdentityRecords.Slot nativePrincipalBindingLPr('
                          'NativePrincipalPins.Record record) {\n')
ARCHIVED_REMEMBERED_FIELD = re.compile(
    r'    private final java\.util\.Map<Long, [A-Za-z.]+> mNativeRememberedBindings =\n'
    r'            new java\.util\.HashMap<>\(\);\n')
# The two facade and seeding rollback checks of 24bfb6a and the case prefixes they print.
ARCHIVED_ROLLBACK_CHECKS = (('NativeRollbackReaderCheck', 'rollback reader'),
                            ('NativeRollbackSeedingCheck', 'rollback seeding'))


@b1.archived
def archived_fragments():
    """The recovery fragments of 24bfb6a, by name, from their pinned Git objects."""
    return {name: b1.pinned_bytes(ARCHIVE, path).decode() for name, path in b1.ARCHIVED_FRAGMENTS.items()}


def archived_cut(text, start, end, keep_start=True):
    """The exact text from start, or just after it, to just before end. Each anchor occurs once."""
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('Settings history anchor drift: ' + start.strip()[:70])
    first, last = text.index(start), text.index(end)
    if last < first:
        raise ValueError('Settings history anchors out of order: ' + start.strip()[:70])
    return text[first if keep_start else first + len(start):last]


def archived_method(text, start):
    """One four space indented method from its first line through its closing brace."""
    if text.count(start) != 1:
        raise ValueError('Settings method anchor drift: ' + start.strip()[:70])
    first = text.index(start)
    return text[first:text.index('\n    }\n', first) + len('\n    }\n')]


def archived_settings_texts(settings):
    """Every history text the harness takes from one candidate Settings, by placeholder: its whole
    boot restoration method and restore inputs, the observation, remembered binding field and
    remembering it calls, the hold refresh, the app ID hold, scan rule and recovery seeding, all
    cut from it, and the shared identity and path safety fragments that it must contain exactly
    once. The restore capacity fragment must occur once, inside the restoration method."""
    fragments = archived_fragments()
    for name in ('restore-capacity', 'identity', 'path-safety'):
        if settings.count(fragments[name]) != 1:
            raise ValueError('shared fragment absent from a candidate Settings: ' + name)
    fields = ARCHIVED_REMEMBERED_FIELD.findall(settings)
    if len(fields) != 1:
        raise ValueError('remembered binding field anchor drift')
    apply = archived_method(settings, ARCHIVED_APPLY_START)
    if fragments['restore-capacity'] not in apply:
        raise ValueError('restore capacity is not inside the restoration method')
    binding = archived_method(settings, ARCHIVED_BINDING_START)
    stored = archived_cut(settings, binding, '    String nativeIdentityLineageLPr() {\n', False)
    return {
        'REMEMBERED_FIELD': fields[0],
        'APPLY': apply,
        'OBSERVE': archived_method(
            settings, '    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {\n'),
        'REFRESH': archived_method(settings, '    void refreshNativePrincipalAppIdsLPw() {\n'),
        'STORED': stored,
        'RESTORE_INPUTS': archived_cut(
            settings, ARCHIVED_APPLY_START, '        NativePrincipalPins restored = new NativePrincipalPins(64);\n',
            False),
        'APP_ID_HELD': archived_method(settings, '    boolean isNativePrincipalAppIdLPr(int appId) {\n'),
        'IDENTITY': fragments['identity'],
        'PATH_SAFETY': fragments['path-safety'],
        'SCAN': archived_cut(settings, '    boolean nativeScanSubjectAllowedLPr(PackageSetting candidate) {\n',
                             '\n    boolean nativePrincipalCreationReadyLPr() {\n'),
        'SEEDING': archived_cut(settings, '    private void seedNativeRecoveryLPw() {\n',
                                '\n    @Watched(manual = true)\n    private final PccIdSettingMap mPccIds;\n'),
    }


def archived_text_checks(settings):
    """The B2 candidate's cut texts are exactly the registered B2 fragments."""
    texts = archived_settings_texts(settings)
    fragments = archived_fragments()
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


@b1.archived
def archived_harness_source(settings, side, seeding=None):
    """NativeHistoryHarness for one side, filled with that side's exact Settings texts."""
    texts = archived_settings_texts(settings)
    if seeding is not None:
        texts['SEEDING'] = seeding
    texts['BODY_INPUTS'] = b1.pinned_bytes(ARCHIVE, ARCHIVED_BODY_INPUTS[side]).decode()
    source = b1.pinned_bytes(ARCHIVE, ARCHIVED_TEMPLATE).decode()
    for tag, text in texts.items():
        marker = '@%s@\n' % tag
        if source.count(marker) != 1:
            raise ValueError('harness placeholder drift: ' + tag)
        source = source.replace(marker, text)
    if re.search(r'@[A-Z_]+@', source):
        raise ValueError('unfilled harness placeholder')
    return source


def archived_parse_parity(text):
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


def archived_compare_parity(baseline_text, b2_text):
    """Problems of the B2 parity output against 0018a1d's, and the twinned layouts whose version
    2 outcome differs on the same bytes."""
    relations, old = archived_parse_parity(baseline_text)
    b2_relations, new = archived_parse_parity(b2_text)
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


def archived_probe_outcome(record):
    if record.get('compile_failure'):
        return {'error': 'compile failure', 'build': record['build']}
    run = record['run']
    lines = [line for line in run['stdout'].splitlines() if line]
    return {'returncode': run['returncode'], 'lines': lines, 'stderr': run['stderr'],
            'passed': run['returncode'] == 0 and bool(lines) and lines[-1].startswith(
                'B1 BODY-origin retirement baseline passed'), 'build': record['build']}


def archived_red_names(result, names):
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


def archived_normalized(text):
    """Java code with comments removed and every whitespace run one space."""
    return ' '.join(b1.archived_strip_java_comments(text).split())


@b1.archived
def archived_support_problems():
    """Whether the shared test support of 24bfb6a, comments aside, is 0018a1d's with exactly the R0
    facade routing, and whether the reviewed R0 bytes are the archive's pins of it. Archived: both
    sides are pinned Git objects, read with the working tree closed."""
    problems = []
    if set(SUPPORT_R0_SHA256) != set(SUPPORT_0018):
        problems.append('R0 support pins differ from the 0018a1d support set')
    pins = b1.manifest(ARCHIVE)
    for relative in SUPPORT_0018:
        path = b1.ARCHIVED_PLATFORM + relative
        if pins.get(path) != SUPPORT_R0_SHA256.get(relative):
            problems.append('archived test support pin differs from its reviewed R0 bytes: ' + relative)
            continue
        expected = archived_normalized(b1.pinned_bytes(BASE, path).decode())
        for old, new in ARCHIVED_SUPPORT_R0.get(relative, ()):
            expected = b1.archived_replace_once(expected, old, new)
        if archived_normalized(b1.pinned_bytes(ARCHIVE, path).decode()) != expected:
            problems.append('24bfb6a test support differs from 0018a1d beyond the R0 facade routing: '
                            + relative)
    return problems


def archived_revision_outputs(revision, original, scratch):
    """The ten outputs of one revision's exact native patch, a pinned Git object, over the pinned
    canonical copies, in private scratch. Pure patch reproduction."""
    patch = b1.pinned_bytes(revision, b1.ARCHIVED_PATCH)
    tree = scratch / 'tree'
    for name, data in original.items():
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (scratch / 'patch').write_bytes(patch)
    applied = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                              '-p1', '-i', str(scratch / 'patch')], cwd=tree, capture_output=True, timeout=30)
    if applied.returncode:
        raise ValueError('%s patch failed: %s' % (revision, applied.stderr.decode(errors='replace')))
    return {name: (tree / name).read_bytes() for name in original}


@b1.archived
def archived_profile_rows():
    """The ten file rows of the pinned 24bfb6a profile."""
    return json.loads(b1.pinned_bytes(ARCHIVE, b1.ARCHIVED_PROFILE))['files']


def archived_candidates(pinned, scratch):
    """The archived candidates: 24bfb6a, 0018a1d and 78456b3, each built by its own pinned patch
    over the canonical copies that the pinned 24bfb6a profile names. The copies are read before the
    working tree closes and must have that profile's exact upstream bytes, so they may lie anywhere,
    the repository included. The patches apply with the working tree closed, in scratch outside the
    repository. Returns the candidate Settings texts, which outputs 24bfb6a changed against 0018a1d
    and 78456b3 against 24bfb6a, and the 24bfb6a output hashes. Pure patch reproduction."""
    if not b1.outside_repository(scratch):
        raise ValueError('archived candidates need scratch outside the repository: %s' % scratch)
    rows = archived_profile_rows()
    original = {}
    for row in rows:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
        if sha(original[row['path']]) != row['upstream_sha256']:
            raise ValueError('wrong pinned input: ' + row['path'])
    return archived_patched_candidates(rows, original, scratch)


@b1.archived
def archived_patched_candidates(rows, original, scratch):
    """The archived candidates from the exact upstream copies, built with the working tree closed.
    Every 24bfb6a output is the pinned profile's candidate and every Settings its pin."""
    outputs = {revision: archived_revision_outputs(revision, original, scratch / revision)
               for revision in (ARCHIVE, BASE, ROLLBACK)}
    if any(sha(outputs[ARCHIVE][row['path']]) != row['candidate_sha256'] for row in rows):
        raise ValueError('24bfb6a outputs differ from the candidates of its pinned profile')
    for revision, digest in ((ARCHIVE, SETTINGS_24BF_SHA256), (BASE, SETTINGS_0018_SHA256),
                             (ROLLBACK, SETTINGS_7845_SHA256)):
        if sha(outputs[revision][b1.ARCHIVED_SETTINGS]) != digest:
            raise ValueError('%s Settings candidate drift' % revision)
    archive = outputs[ARCHIVE]
    return {**{revision: outputs[revision][b1.ARCHIVED_SETTINGS].decode() for revision in outputs},
            'changed': sorted(name for name in original if outputs[BASE][name] != archive[name]),
            'rollback_changed': sorted(name for name in original if outputs[ROLLBACK][name] != archive[name]),
            'archived_outputs': {name: sha(archive[name]) for name in sorted(original)}}


@b1.archived
def archived_rollback_candidate_problems(built):
    """The 78456b3 candidate differs from the archived 24bfb6a candidate only in the boot
    construction's format literal, so every text the harness takes from either is the same."""
    problems = []
    old, new = built[ROLLBACK], built[ARCHIVE]
    if built['rollback_changed'] != [b1.ARCHIVED_SETTINGS]:
        problems.append('78456b3 outputs differ from 24bfb6a beyond Settings: %s' % built['rollback_changed'])
    if (len(old) != len(new) or old.replace(b1.ARCHIVED_CONSTRUCTION + b1.ARCHIVED_RETIRED + ');',
                                            b1.ARCHIVED_CONSTRUCTION + b1.ARCHIVED_PRODUCTION + ');', 1) != new
            or sum(a != b for a, b in zip(old, new)) != 1):
        problems.append('78456b3 Settings differs from the 24bfb6a Settings beyond the boot literal')
    try:
        if archived_settings_texts(old) != archived_settings_texts(new):
            problems.append('78456b3 and 24bfb6a harness texts differ')
    except ValueError as error:
        problems.append('78456b3 harness texts: %s' % error)
    return problems


@b1.archived
def archived_harness_problems(built):
    """Every archived harness is the one the 24bfb6a qualification compiled: the 24bfb6a and
    78456b3 candidates fill the pinned template to one pinned harness, and 0018a1d's to its own."""
    problems = []
    for revision, side in ((ARCHIVE, 'b2'), (ROLLBACK, 'b2'), (BASE, BASE)):
        if sha(archived_harness_source(built[revision], side).encode()) != ARCHIVED_HARNESS_SHA256[side]:
            problems.append('archived %s harness differs from its pin' % revision)
    return problems


@b1.archived
def archived_candidate_problems(built):
    """The archived candidate checks: 24bfb6a changed only Settings against 0018a1d, its texts are its
    own pinned fragments, 78456b3 differs from it only by the boot literal, and every archived
    harness is the pinned one."""
    problems = []
    if built['changed'] != [b1.ARCHIVED_SETTINGS]:
        problems.append('24bfb6a changed framework targets other than Settings against 0018a1d: %s'
                        % built['changed'])
    problems += ['archived ' + problem for problem in archived_text_checks(built[ARCHIVE])]
    problems += archived_rollback_candidate_problems(built)
    problems += archived_harness_problems(built)
    return problems


@b1.archived
def archived_history_stubs():
    """The history stubs of 24bfb6a, from their pinned Git objects."""
    return {'history-stubs/' + path[len(ARCHIVED_HISTORY_STUBS):]: b1.pinned_bytes(ARCHIVE, path)
            for path in b1.pinned_paths(ARCHIVE, ARCHIVED_HISTORY_STUBS)}


@b1.archived
def archived_support_0018():
    """The test support and B1 adapter of 0018a1d, from their pinned Git objects."""
    return {'tests/' + Path(relative).name: b1.pinned_bytes(BASE, b1.ARCHIVED_PLATFORM + relative)
            for relative in SUPPORT_0018}


@b1.archived
def archived_product(settings):
    """The archived twin of b2_product: the pinned 24bfb6a product and history stubs with the
    archived harness of one candidate Settings."""
    files = b1.archived_product_sources(ARCHIVE)
    files.update(archived_history_stubs())
    files['tests/NativeHistoryHarness.java'] = archived_harness_source(settings, 'b2').encode()
    return files


@b1.archived
def archived_tests(names):
    """24bfb6a host test sources with its B1 adapter, from their pinned Git objects."""
    return b1.archived_test_sources(names, adapter='b1')


@b1.archived
def archived_probe_files(side, settings=None):
    """One archived side of the BODY origin probe, with the pinned probe: 0018a1d's product and
    test support, or the pinned 24bfb6a product, harness of its candidate Settings and support."""
    probe = {'tests/BodyOriginRetirementProbe.java': b1.pinned_bytes(ARCHIVE, ARCHIVED_PROBE)}
    if side == BASE:
        return {**b1.archived_product_sources(BASE), **archived_support_0018(), **probe}
    return {**archived_product(settings), **archived_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport']),
            **probe}


@b1.archived
def archived_parity_files(side, settings):
    """One archived side of the history parity, with the pinned parity driver: 0018a1d's product and
    test support with the pinned history stubs, or the pinned 24bfb6a product and support. Each
    side's harness is the archived harness of its own candidate Settings."""
    if side == BASE:
        files = {**b1.archived_product_sources(BASE), **archived_support_0018(), **archived_history_stubs()}
    else:
        files = {**archived_product(settings),
                 **archived_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport'])}
    files['tests/NativeHistoryHarness.java'] = archived_harness_source(
        settings, BASE if side == BASE else 'b2').encode()
    files['tests/NativeHistoryParity.java'] = b1.pinned_bytes(ARCHIVE, ARCHIVED_PARITY)
    return files


@b1.archived
def archived_emitter_files(settings):
    """The pinned 24bfb6a history layout emitter, with the archived seams and harness."""
    return {**b1.archived_with_seams(archived_product(settings)),
            **archived_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHistoryTestSupport',
                              'NativeHeaderWriteFaults', 'NativeCreationHistoryLayouts'])}


@b1.archived
def archived_rollback_files(baseline, settings):
    """One archived facade and seeding rollback check: a registered revision's product with the
    pinned history stubs, the archived harness of its own candidate Settings and the 24bfb6a checks."""
    return {**b1.archived_product_sources(baseline), **archived_history_stubs(),
            'tests/NativeHistoryHarness.java': archived_harness_source(settings, 'b2').encode(),
            **archived_tests(['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHistoryTestSupport',
                              *(main for main, _ in ARCHIVED_ROLLBACK_CHECKS)])}


def archived_rollback_settings(built):
    """The candidate Settings each archived rollback target fills its harness with."""
    return {'24bf-v1': built[ARCHIVE], ROLLBACK: built[ROLLBACK]}


@b1.archived
def archived_inputs(built):
    """Every archived input set of this runner, by leg, from the archived candidates' Settings
    texts, assembled with the working tree closed."""
    legs = {'probe ' + BASE: archived_probe_files(BASE),
            'probe ' + ARCHIVE: archived_probe_files(ARCHIVE, built[ARCHIVE]),
            'parity ' + BASE: archived_parity_files(BASE, built[BASE]),
            'parity ' + ARCHIVE: archived_parity_files(ARCHIVE, built[ARCHIVE]),
            'emitter': archived_emitter_files(built[ARCHIVE])}
    for target, baseline, adapter in ARCHIVED_READERS:
        legs['reader ' + target] = b1.archived_reader_files(baseline, adapter)
    for target, baseline in ARCHIVED_ROLLBACK_READERS:
        legs['rollback ' + target] = archived_rollback_files(baseline, archived_rollback_settings(built)[target])
    return legs


def archived_run_parity(work, files):
    """One archived parity side's outcomes from its assembled sources."""
    work.mkdir(parents=True)
    built = b1.archived_build(work, files)
    record = {'build': built}
    if built['returncode']:
        record['compile_failure'] = True
        return record, None
    output = work / 'outcomes.tsv'
    record['run'] = b1.archived_execute(work, 'NativeHistoryParity', [str(work / 'state'), str(output)], timeout=1800)
    text = output.read_text() if output.is_file() else None
    if text is not None:
        record['outcomes'] = {'sha256': sha(text.encode()), 'lines': len(text.splitlines())}
    return record, text


def archived_probe_phase(work, built, steps, problems, progress):
    """The primary's BODY origin probe on the pinned 0018a1d and 24bfb6a sides: both pass with the
    same lines."""
    steps['probe'] = {BASE: archived_probe_outcome(b1.archived_suite(
        work / 'probe-0018', archived_probe_files(BASE), ARCHIVED_PROBE_MAIN))}
    progress.write()
    steps['probe'][ARCHIVE] = archived_probe_outcome(b1.archived_suite(
        work / 'probe-24bf', archived_probe_files(ARCHIVE, built[ARCHIVE]), ARCHIVED_PROBE_MAIN))
    old, new = steps['probe'][BASE], steps['probe'][ARCHIVE]
    if 'error' in old or 'error' in new or not (old['passed'] and new['passed']) or old['lines'] != new['lines']:
        problems.append('BODY origin probe differs from 0018a1d')


def archived_parity_phase(work, built, steps, problems, progress):
    """Restoration, seeding and scan outcomes of the pinned 24bfb6a side against 0018a1d's exact
    Settings text, with the twinned layouts the pinned predictions state. Returns the 24bfb6a
    outcomes when that side ran."""
    twinned = tuple(b1.archived_predictions('history')['parity_twinned_layouts'])
    old_record, old_text = archived_run_parity(work / 'parity-0018', archived_parity_files(BASE, built[BASE]))
    steps['parity'] = {BASE: old_record}
    progress.write()
    new_record, new_text = archived_run_parity(work / 'parity-24bf', archived_parity_files(ARCHIVE, built[ARCHIVE]))
    steps['parity'][ARCHIVE] = new_record
    if (old_text is None or new_text is None or old_record['run']['returncode']
            or new_record['run']['returncode']):
        problems.append('parity did not run')
    else:
        mismatches, differing = archived_compare_parity(old_text, new_text)
        steps['parity']['mismatches'] = mismatches[:200]
        steps['parity']['mismatch_count'] = len(mismatches)
        steps['parity']['differing_twinned'] = differing
        if mismatches:
            problems.append('parity with 0018a1d: %d mismatches' % len(mismatches))
        if tuple(differing) != tuple(sorted(twinned)):
            problems.append('twinned layouts did not differ as predicted: %s' % differing)
    return new_text if new_text is not None and not new_record['run']['returncode'] else None


def archived_readers_phase(work, built, steps, problems, progress):
    """Version 2 history layouts from the pinned 24bfb6a production writer, read by the version 1
    rollback reader, its 24bf-v1 twin and the pinned 78456b3 image, and by archived 0018a1d and
    c9264e4. The rollback reader's facade and recovery seeding then read them again."""
    emitter = work / 'archived-layouts-emitter'
    emitter.mkdir(parents=True)
    built_emitter = b1.archived_build(emitter, archived_emitter_files(built[ARCHIVE]))
    layouts = work / 'archived-layouts'
    steps['archived readers'] = {'emitter_build': built_emitter}
    if built_emitter['returncode']:
        problems.append('archived history layout emitter did not compile')
        return
    emitted = b1.archived_execute(emitter, 'NativeCreationHistoryLayouts', [str(layouts), str(emitter / 'state')])
    names = sorted(p.name for p in layouts.iterdir()) if layouts.is_dir() else []
    steps['archived readers'].update(emitted=names, emitter_run=emitted)
    if emitted['returncode'] or tuple(names) != ARCHIVED_LAYOUT_NAMES:
        problems.append('archived history layout emitter')
    steps['archived readers']['copy_layouts'] = b1.archived_copy_layouts(layouts) if layouts.is_dir() else None
    if steps['archived readers']['copy_layouts'] != ARCHIVED_COPY_LAYOUTS:
        problems.append('archived version 2 copy history layouts %s, not the predicted %d'
                        % (steps['archived readers']['copy_layouts'], ARCHIVED_COPY_LAYOUTS))
    for target, baseline, adapter in ARCHIVED_READERS if tuple(names) == ARCHIVED_LAYOUT_NAMES else ():
        copy = work / ('archived-layouts-' + target)
        shutil.copytree(layouts, copy, symlinks=True)
        reader = work / ('archived-reader-' + target)
        reader.mkdir(parents=True)
        built_reader = b1.archived_build(reader, b1.archived_reader_files(baseline, adapter))
        if built_reader['returncode']:
            problems.append('archived reader %s did not compile' % target)
            steps['archived readers'][target] = {'build': built_reader}
            continue
        run = b1.archived_execute(reader, 'NativeCreationBindingReaderCheck', [str(copy), str(reader / 'state')])
        steps['archived readers'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                             'passed': len(run['passed']), 'build': built_reader, 'run': run}
        if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                ['version 1 reader / ' + name for name in ARCHIVED_LAYOUT_NAMES]):
            problems.append('archived reader ' + target)
        progress.write()
    settings = archived_rollback_settings(built)
    for target, baseline in ARCHIVED_ROLLBACK_READERS if tuple(names) == ARCHIVED_LAYOUT_NAMES else ():
        checker = work / ('archived-rollback-' + target)
        checker.mkdir(parents=True)
        built_checker = b1.archived_build(checker, archived_rollback_files(baseline, settings[target]))
        record = steps['archived readers']['rollback ' + target] = {'build': built_checker}
        if built_checker['returncode']:
            problems.append('archived rollback %s did not compile' % target)
            continue
        for main, prefix in ARCHIVED_ROLLBACK_CHECKS:
            copy = work / ('archived-layouts-%s-%s' % (main, target))
            shutil.copytree(layouts, copy, symlinks=True)
            run = b1.archived_execute(checker, main, [str(copy), str(checker / ('state-' + main)),
                                                      str(ARCHIVED_COPY_LAYOUTS), ','.join(ARCHIVED_ROLLBACK_CONTROLS)])
            record[main] = {'returncode': run['returncode'], 'failed': run['failed'],
                            'passed': len(run['passed']), 'run': run}
            if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                    b1.archived_rollback_names(prefix, ARCHIVED_LAYOUT_NAMES, ARCHIVED_ROLLBACK_CONTROLS)):
                problems.append('archived rollback %s %s' % (main, target))
        progress.write()


@b1.archived
def archive_problems():
    """The history runner's part of the archive: its named pins are the manifest's, and its frozen
    expectations are the ones the pinned 24bfb6a predictions state. The B1 source checks compare
    every manifest pin with its Git object."""
    problems = []
    pins = b1.manifest(ARCHIVE)
    named = {b1.ARCHIVED_PATCH: PATCH_24BF_SHA256, ARCHIVED_PROBE: PROBE_SHA256,
             **{b1.ARCHIVED_PLATFORM + relative: digest for relative, digest in SUPPORT_R0_SHA256.items()}}
    for path, digest in sorted(named.items()):
        if pins.get(path) != digest:
            problems.append('archived pin differs from the manifest: ' + path)
    predictions = b1.archived_predictions('history')
    reader = predictions['r0_rollback_reader']
    cases = len(ARCHIVED_LAYOUT_NAMES) + len(ARCHIVED_ROLLBACK_CONTROLS) + 1
    if (not b1.archived_distinct(ARCHIVED_LAYOUT_NAMES, 45)
            or reader['readers'] != {'b2-v1': 45, BASE: 45, 'c926': 45, ROLLBACK: 45}
            or {target for target, _, _ in ARCHIVED_READERS} != {'24bf-v1', BASE, 'c926', ROLLBACK}
            or reader['rollback_checks'] != {target: {main: cases for main, _ in ARCHIVED_ROLLBACK_CHECKS}
                                             for target in ('b2-v1', ROLLBACK)}
            or reader['copy_layouts'] != ARCHIVED_COPY_LAYOUTS or ARCHIVED_COPY_LAYOUTS != len(ARCHIVED_LAYOUT_NAMES)
            or tuple(reader['controls']) != ARCHIVED_ROLLBACK_CONTROLS
            or not set(ARCHIVED_ROLLBACK_CONTROLS) <= set(ARCHIVED_LAYOUT_NAMES)
            or len(predictions['parity_twinned_layouts']) != 7
            or None in ARCHIVED_HARNESS_SHA256.values()):
        problems.append('archived history expectations differ from the pinned predictions')
    return problems


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
    steps['candidates'] = {'changed': built['changed'], 'outputs': built['outputs'],
                           'rollback_changed': built['rollback_changed'],
                           'archived_outputs': built['archived_outputs']}
    problems += candidate_problems(built)
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

    # Archived: the primary's BODY origin probe on the pinned 0018a1d and 24bfb6a sides, which both
    # pass with the same lines.
    progress.begin('probe')
    archived_probe_phase(work, built, steps, problems, progress)
    progress.done('probe')

    # Living: the same probe on the current sources passes by its own assertions until its cases
    # are ported. It is compared with nothing.
    progress.begin('living probe')
    living = steps['living probe'] = probe_outcome(b2_suite(work / 'probe-b2', settings, 'probe'))
    if 'error' in living or not living['passed']:
        problems.append('BODY origin probe fails on the current sources')
    progress.done('living probe')

    # Archived: restoration, seeding and scan outcomes of the pinned 24bfb6a side against 0018a1d's
    # exact Settings text.
    progress.begin('parity')
    archived_outcomes = archived_parity_phase(work, built, steps, problems, progress)
    progress.done('parity')

    # Living: the current sources' restoration, seeding and scan outcomes over the archived layouts
    # of the pinned 24bfb6a parity driver, against the archived 24bfb6a side. They differ exactly
    # where the predictions file says, so any unpredicted boot effect of a later change shows.
    progress.begin('living parity')
    record, outcomes = run_parity(work / 'parity-living', living_parity_files(settings))
    steps['living parity'] = record
    predicted = predictions['living_parity']['predicted_differences']
    if archived_outcomes is None or outcomes is None or record['run']['returncode']:
        problems.append('living parity against 24bfb6a did not run')
    else:
        differences, unexpected, missing = predicted_parity(archived_outcomes, outcomes, predicted)
        record.update(difference_count=len(differences), differences=differences[:200],
                      unpredicted=unexpected[:200], missing=missing[:200])
        if unexpected or missing:
            problems.append('living parity against 24bfb6a: %d unpredicted and %d missing differences'
                            % (len(unexpected), len(missing)))
    progress.done('living parity')

    # Version 2 history layouts from the production writer on the current sources, read by the
    # legacy b2-v1 reader, the current sources under Format.V1, whose facade and recovery seeding
    # then read them again.
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
        steps['readers']['copy_layouts'] = b1.copy_layouts(layouts) if layouts.is_dir() else None
        if steps['readers']['copy_layouts'] != ROLLBACK_COPY_LAYOUTS:
            problems.append('version 2 copy history layouts %s, not the predicted %d'
                            % (steps['readers']['copy_layouts'], ROLLBACK_COPY_LAYOUTS))
        for target, baseline, adapter in READERS if tuple(names) == LAYOUT_NAMES else ():
            copy = work / ('layouts-' + target)
            shutil.copytree(layouts, copy, symlinks=True)
            reader = work / ('reader-' + target)
            reader.mkdir(parents=True)
            built_reader = b1.build(reader, {**b1.product_sources(), **b1.test_sources(
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
        for target, baseline in LEGACY_ROLLBACK if tuple(names) == LAYOUT_NAMES else ():
            checker = work / ('rollback-' + target)
            checker.mkdir(parents=True)
            files = {**b1.product_sources(), **history_stubs(),
                     'tests/NativeHistoryHarness.java': harness_source(settings, 'b2').encode(),
                     **b1.test_sources(['NativeHeaderTestSupport', 'NativeBindingTestSupport',
                                        'NativeHistoryTestSupport', *(main for main, _ in ROLLBACK_CHECKS)],
                                       adapter='b1')}
            built_checker = b1.build(checker, files)
            record = steps['readers']['rollback ' + target] = {'build': built_checker}
            if built_checker['returncode']:
                problems.append('rollback %s did not compile' % target)
                continue
            for main, prefix in ROLLBACK_CHECKS:
                copy = work / ('layouts-%s-%s' % (main, target))
                shutil.copytree(layouts, copy, symlinks=True)
                run = b1.execute(checker, main, [str(copy), str(checker / ('state-' + main)),
                                                 str(ROLLBACK_COPY_LAYOUTS), ','.join(ROLLBACK_CONTROLS)])
                record[main] = {'returncode': run['returncode'], 'failed': run['failed'],
                                'passed': len(run['passed']), 'run': run}
                if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                        b1.rollback_names(prefix, LAYOUT_NAMES, ROLLBACK_CONTROLS)):
                    problems.append('rollback %s %s' % (main, target))
            progress.write()
    progress.done('readers')

    # Archived: the R0 pipeline over pinned Git objects only.
    progress.begin('archived readers')
    archived_readers_phase(work, built, steps, problems, progress)
    progress.done('archived readers')

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
    report['labels'] = {step: list(STEP_LABELS[step]) for step in steps if step in STEP_LABELS}
    report['reader_labels'] = dict(READER_LABELS)
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
    parser.add_argument('--pinned-framework', type=Path,
                        help='pinned canonical framework copies, each checked against the exact upstream'
                             ' hash its profile pins; they may lie anywhere, the repository included')
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
            report['candidate'] = {'changed': built['changed'], 'outputs': built['outputs'],
                                   'rollback_changed': built['rollback_changed'],
                                   'archived_outputs': built['archived_outputs']}
            problems += candidate_problems(built)
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
