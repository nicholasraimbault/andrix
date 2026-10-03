#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of complete original creation bindings and exact encoded byte
admission. No compiler or JVM starts unless an actual cgroup bounds this process to 2 GiB of
memory, no swap, 2 CPUs and 256 tasks, with core dumps disabled. Otherwise the run is NOT_RUN.
Source checks are pure Python. Not Android, crash, power loss, storage or activation evidence."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
sys.path.insert(0, str(ROOT / 'scripts/proof/tests'))
import native_principal_pins as integration  # noqa: E402
import test_native_header_footprint as b0  # noqa: E402

GIB = 1 << 30
PLATFORM = 'owner/tests/platform/'
FRAMEWORK_DIR = 'owner/platform/framework/'
FRAMEWORK = ('NativePrincipalPins', 'NativePrincipalManager', 'NativeIdentityRecords',
             'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery')
STUB_DIRECTORIES = ('native_principal_stubs', 'native_principal_xml_stubs')
PREDICTIONS = ROOT / 'scripts/proof/native_creation_binding_predictions.json'
REVISIONS = {'c926': 'c9264e496777a81c2465ba3d1a0da91d3a4a8855',
             'd104': 'd104e15bae58a74dbba6e3c3325a93f216773667',
             '7845': '78456b352267dba916778b90d7c926c4e67ef888'}
# Exact baseline inputs taken from Git objects. c9264e4 and d104e15 are archived baselines.
# 78456b3 is the last version 1 normal image and the one supported rollback reader: its sources
# equal the version 2 normal sources except for the boot literal, the store comments and the host
# facade default, and the rollback model runs them under Format.V1.
BASELINE_SHA256 = {
    'c926': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '0488cf2e519bb09891dc8d0e87e606cc786895548bc0ec3609fc9613103b8c13',
        'NativeIdentityRecords': '36ef5e04b842b091e7af98de81b8ae67392729f333aeacb706a09c2b78580b16',
        'NativeIdentityStore': '92679c46989ab121ec274e9ddac340164aa55aba534c106aca23885bbc1cf991',
        'NativeIdentityPersistence': '4fd90c2546a9f99181a01b2ca074b63627b44c927ba6fd8e59c93c3ec3224665',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '1efa172c937b58c87db4d2f02e2601b3a4735d7ebf3a9435b4472de67d769869'},
    'd104': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '0488cf2e519bb09891dc8d0e87e606cc786895548bc0ec3609fc9613103b8c13',
        'NativeIdentityRecords': '36ef5e04b842b091e7af98de81b8ae67392729f333aeacb706a09c2b78580b16',
        'NativeIdentityStore': 'cb4d195f841491ec8a5e3a35888d2c06a7ab651673a22da8a68098ad51d4b721',
        'NativeIdentityPersistence': 'f20100402ca0284c009097c96d74213533d828d035ab1d83e1d4211c7ce919af',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '547078cd90a6b9b1cd2b6b872081ce3b8712a8bf49a6585b869e61cb9c656d69'},
    '7845': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '1fa50501728a66b676020c83fce44d5868686db37a6b5867498975ae4d57ceb4',
        'NativeIdentityRecords': '412c2271a9efabf9937375bd42f2e49c5e3fb4d09935a9e98d6e5805736a3009',
        'NativeIdentityStore': 'fa69ee859973504b9529c36d85551eda9c8cbe04ae285d89d5390603a6d45c23',
        'NativeIdentityPersistence': 'f2fd1a5e6d272f99bb06973700d885523c1dbff033731b4a02e969f8bfb29f54',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '2eaa6c9dae109f949fb23b553b92d8396d4d65c70b42caa83650821ba2b40669'},
}
# The version 1 readers of the emitted version 2 layouts: target, baseline revision and host
# adapter. b1-v1 is the current sources under Format.V1 and 7845 is the pinned 78456b3 image
# under Format.V1, both the rollback reader model. c926 is an archived baseline reader.
READERS = (('b1-v1', None, 'b1'), ('c926', 'c926', 'baseline'), ('7845', '7845', 'b1'))
# The targets that model the supported 78456b3 rollback reader.
ROLLBACK_READERS = ('b1-v1', '7845')
# The emitted layouts that hold a version 2 header copy, predicted from the writer protocol: all
# 47 but the four seed-synced steps whose prior header copies are version 1, where only the
# staging seed is version 2. The rollback checks assert this count, so no layout leaves the copy
# branch unnoticed. The controls are read again under the production Format.V2.
ROLLBACK_COPY_LAYOUTS = 43
ROLLBACK_CONTROLS = ('final-published', 'final-reserved')


def rollback_names(prefix, layouts, controls):
    """The case names one rollback check prints: each layout, each control and the copy count."""
    return sorted(['%s / %s' % (prefix, name) for name in layouts] + ['%s / version 2 copy layouts' % prefix]
                  + ['%s control / %s' % (prefix, name) for name in controls])


def copy_layouts(layouts):
    """How many emitted layouts record a version 2 header copy as their kind."""
    return sum((layout / 'kind').read_text() == 'copy\n' for layout in sorted(layouts.iterdir()))
# The archived header footprint suite, unchanged, as it ran in the B0 qualification.
ORIGINAL_B0_SHA256 = {
    'NativeHeaderTestSupport': 'fd6c83fd41958f4902e19143ac0fbd53b54e8483f00e9c701ed853ccb1ada91b',
    'NativeIdentityHeaderFootprintTest': 'bab48f444eb8680dfbe523889f196308fdc30bc43f2cd86b303b3e61299e85c7',
    'NativeHeaderWriteFaultTest': 'fa2efc9d24f1131fa814fe141fc1c60ac656c8aaeb6dd4adf249dcb464c04610',
    'NativeHeaderWriteFaults': '874a3ff09f4a261295173d4cd35931b58b3b536a80088d063a224973b3c5b1cd'}

STEPS = b0.STEPS
FOCUSED_NAMES = (
    'plan / rows only for records of a valid snapshot', 'plan / signer sets are valid, bounded and copied',
    'V1 / a new entry without an owned row refuses before effects', 'V1 / held entries and additions need no row',
    "manager / another manager's unreserved pin refuses before issuance",
    'manager / a late preparation failure keeps the original issuance',
    'V1 / an owned flow writes the golden version 1 bytes', 'V2 / an owned flow writes the golden version 2 bytes',
    'V2 / legacy B beside new C writes the golden bytes', 'encoded length / equals every actual encoding',
    'encoded length / refuses what it cannot measure', 'admission / exactly MAX_BYTES is admitted and written',
    'admission / one byte over MAX_BYTES refuses before issuance', 'V2 / a restatement alone keeps version 1',
    'V2 / legacy B with new C upgrades, C committed first', 'V2 / legacy B with new C upgrades, B committed first',
    'V2 / a restatement stays version 1, then new C upgrades',
    'V2 / pending and unpublished RETIRING pins reserve together',
    'V2 / a held binding refuses another owned signer row', 'V2 / a bound addition is restated exactly or refused',
    'low level / the version 1 format never writes version 2',
    'low level / a new entry under version 2 needs a complete binding',
    'low level / a restatement alone never upgrades', 'low level / relabels and downgrades refuse',
    'low level / a binding is never changed, dropped or filled',
    'low level / an unselected addition is restated exactly', 'low level / an upgrade needs a pure reservation',
    'cross version / a V2 target beside V1 predecessors restores only its counter',
    'cross version / a V1 selection beside a V2 copy is incompatible',
    'cross version / a V1 copy above the selected counter is incompatible',
    'cross version / a V1 copy at the selected counter is incompatible',
    'cross version / a V1 copy below a counter only advance is incompatible',
    'cross version / a V1 copy without the newer reservation is incompatible',
    'cross version / an interrupted V1 publication then a protected V2 reservation',
    'binding mismatch / disjoint signers', 'binding mismatch / serial', 'binding mismatch / signer subset',
    'binding mismatch / signer superset', 'binding mismatch / two users', 'binding mismatch / zero users',
    'binding mismatch / another user', 'binding mismatch / publication of another serial or signer set',
    'binding match / an active body is usable', 'binding match / a retiring body is usable',
    'binding / a published body stays usable beside a later reservation',
    *('binding conflict evidence / ' + name for name in (
        'package only collision', 'principal only collision', 'package and principal collision',
        'an unrelated sibling stays usable', 'a serial mismatch keeps package evidence',
        'a tombstone keeps package evidence', 'swapped app IDs keep package evidence',
        'unselected copies failing the binding beside a collision',
        'unselected copies failing the binding beside an unrelated sibling',
        'a matching binding keeps ordinary duplicates',
        'an ordinary conflict alone keeps N, a failed binding withdraws it',
        'version 1 reads bound collisions as c9264e4 does',
        'unselected slot copy keeps package evidence',
        'unselected slot copy keeps principal evidence',
        'matching binding ignores unselected package body',
        'matching binding ignores unselected principal body')),
    'restored R / unrelated N reserves beside it without a row',
    "restored R / a changed APK signer refuses only R's own rebind",
    'restored R / a mismatched body is a conflict that keeps its header',
    'signer mutation / Q reserves P with its original signers',
    'signer mutation / a durable P reservation does not strand Q',
    *('V2 gate / header version %d in %s' % (version, position) for version in (3, 65535)
      for position in ('store.bin', 'store.bin.reservecopy', 'store.bin-backup', 'store.bin-seed')),
    'V2 gate / malformed and damaged version 2 frames are damage',
    'V2 gate / version 2 slot frames are footprints under V1',
    'V2 gate / version 2 slot frames are footprints under V2',
    'V2 gate / initialization writes an empty version 1 header',
    'V2 / publication, marker, release and a later reservation keep version 2',
    'V1 reader / version 2 layouts stay read only with every hold')
FAULT_NAMES = (
    *('fresh upgrade / ' + step for step in STEPS),
    *('legacy B with bound C / C first / ' + step for step in STEPS),
    *('legacy B with bound C / B first / ' + step for step in STEPS),
    *('version 1 restatement under version 2 / ' + step for step in STEPS),
    *('restatement then upgrade / ' + step for step in STEPS),
    *('pending and RETIRING together / ' + step for step in STEPS),
    'version 2 prior ordering / publication', 'version 2 prior ordering / release marker',
    'version 2 prior ordering / omission', 'version 2 prior ordering / confirmation',
    'interrupted V1 publication then protected upgrade')
LAYOUT_NAMES = tuple(sorted(
    [prefix + step for prefix in ('fresh-upgrade-', 'legacy-b-bound-c-', 'pending-retiring-',
                                  'restated-then-upgraded-', 'v2-publication-') for step in STEPS]
    + ['final-reserved', 'final-published', 'final-legacy-null', 'final-released']
    + ['bound-collision-' + kind for kind in ('package', 'principal', 'both')]))

# Every host run carries one label. production: Format.V2, as the normal image's one boot read
# constructs it, or code that constructs no store. rollback-reader: Format.V1 reading version 2
# state, the model of the supported 78456b3 rollback reader. archived-baseline: pinned Git objects
# of an earlier revision, compared and never shipped again. legacy: Format.V1 writes or Format.V1
# end to end, which model no shipped reader since the normal image became version 2; they stay
# as regressions of the version 1 paths, and none is retired.
RUN_LABELS = ('production', 'rollback-reader', 'archived-baseline', 'legacy')
# Which harnesses run under each label: label, runner, the host classes it runs and which runs.
# A harness that runs cases under more than one format is listed once per label.
HARNESS_LABELS = (
    ('production', 'scripts/proof/tests/test_native_identity_store.py', ('NativeIdentityRecordsTest',),
     'the record codec, which constructs no store'),
    ('legacy', 'scripts/proof/tests/test_native_identity_store.py',
     ('NativeIdentityStoreTest', 'NativeIdentityPresenceTest'),
     'Format.V1 stores, including the default version 1 presence matrix'),
    ('rollback-reader', 'scripts/proof/tests/test_native_identity_store.py',
     ('NativeIdentityVersionGateTest', 'NativeIdentityFutureFormatTest'),
     'Format.V1 over intact version 2 and later frames'),
    ('production', 'scripts/proof/tests/test_native_identity_persistence.py', ('NativePrincipalRecoveryTest',),
     'the recovery view, which constructs no store'),
    ('legacy', 'scripts/proof/tests/test_native_identity_persistence.py', ('NativeIdentityPersistenceTest',),
     'Format.V1 transactions'),
    ('production', 'scripts/proof/native_creation_binding.py', ('NativeIdentityPresenceTest',),
     'the presence and unavailable matrix under Format.V2'),
    ('production', 'scripts/proof/tests/test_native_principal_pins.py',
     ('NativePrincipalPinsTest', 'NativePrincipalAllocatorTest'), 'the core and allocator, with no store'),
    ('legacy', 'scripts/proof/tests/test_native_principal_pins.py',
     ('NativePrincipalManagerTest', 'NativePreparationAdmissionTest', 'NativePrincipalPersistenceTest'),
     'explicit Format.V1 facades, and the XML pin codec that no image ships'),
    ('rollback-reader', 'scripts/proof/tests/test_native_principal_pins.py', ('NativePrincipalManagerTest',),
     'its last case: a version 2 header copy read as a footprint by the Format.V1 facade'),
    ('legacy', 'scripts/proof/tests/test_native_preparation_faults.py',
     ('NativePreparationFaultTest', 'NativePreparationAdmissionTest'), 'explicit Format.V1 facades'),
    ('production', 'scripts/proof/tests/test_native_recovery_boot.py', ('NativeRecoveryBootTest',),
     'the exact adapted boot fragments over constructed views, with no store'),
    ('legacy', 'scripts/proof/tests/test_native_header_footprint.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest'),
     'the B0 suite through the B1 adapter: Format.V1 stores and facades'),
    ('archived-baseline', 'scripts/proof/native_creation_binding.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest', 'NativeCreationBindingReaderCheck'),
     'b0 c926 and d104, archived and adapted, and the c926 reader of the version 2 layouts'),
    ('legacy', 'scripts/proof/native_creation_binding.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest', 'NativeCreationBindingTest'),
     'b0 b1-v1 on the current sources, and the V1 writer cases of b1 focused and its mutants'),
    ('production', 'scripts/proof/native_creation_binding.py',
     ('NativeCreationBindingTest', 'NativeCreationBindingFaultTest', 'NativeCreationBindingLayouts',
      'NativeRollbackReaderCheck'),
     'the V2 cases of b1 focused, the b1 fault matrix, the layout emitter, the B1 mutants and the'
     ' version 2 controls of the facade rollback checks'),
    ('rollback-reader', 'scripts/proof/native_creation_binding.py',
     ('NativeCreationBindingTest', 'NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck'),
     'the V1 reader cases of b1 focused, the b1-v1 and 7845 readers and their facade rollback checks'),
    ('production', 'scripts/proof/native_creation_history.py',
     ('NativeCreationHistoryTest', 'NativeCreationHistoryFaultTest', 'BodyOriginRetirementProbe',
      'NativeHistoryParity', 'NativeCreationHistoryLayouts', 'NativeRollbackReaderCheck',
      'NativeRollbackSeedingCheck'),
     'the V2 cases and runs of b2 focused, b2 faults, the B2 probe and parity, the emitter, the B2 mutants'
     ' and the version 2 controls of the rollback checks'),
    ('legacy', 'scripts/proof/native_creation_history.py', ('NativeCreationHistoryTest', 'BodyOriginRetirementProbe'),
     'their Format.V1 cases over version 1 stores'),
    ('rollback-reader', 'scripts/proof/native_creation_history.py',
     ('NativeCreationHistoryTest', 'NativeHistoryParity', 'NativeCreationBindingReaderCheck',
      'NativeRollbackReaderCheck', 'NativeRollbackSeedingCheck'),
     'the Format.V1 reads of version 2 layouts, the b2-v1 and 7845 readers and their facade and seeding'
     ' rollback checks'),
    ('archived-baseline', 'scripts/proof/native_creation_history.py',
     ('BodyOriginRetirementProbe', 'NativeHistoryParity', 'NativeCreationBindingReaderCheck'),
     'the 0018a1d probe and parity side, and the 0018 and c926 readers'),
    ('production', 'scripts/proof/native_counter_admission.py', ('NativeCounterAdmissionTest', 'NativeHistoryParity'),
     'the V2 cases of the focused suite and its mutants, and the V2 runs of the corrected parity side'),
    ('legacy', 'scripts/proof/native_counter_admission.py',
     ('NativeCounterAdmissionTest', 'UnsupportedCounterProbe', 'StaleSlotCounterProbe'),
     'the Format.V1 cases over version 1 stores, and the Format.V1 probes on the corrected sources'),
    ('rollback-reader', 'scripts/proof/native_counter_admission.py', ('NativeHistoryParity',),
     'the Format.V1 runs of the corrected parity side over version 2 layouts'),
    ('archived-baseline', 'scripts/proof/native_counter_admission.py',
     ('NativeCounterAdmissionTest', 'UnsupportedCounterProbe', 'StaleSlotCounterProbe', 'NativeHistoryParity'),
     'the 0018a1d and 89491b9 baselines, their probes and the 89491b9 parity side'),
    ('legacy', 'tests/native-identity/test_writer.py',
     ('NativePrincipalWriterFixtureTest', 'NativePrincipalWriterFixtureFaultTest',
      'NativePrincipalWriterFixtureTranscript'), 'the writer fixture tests on explicit Format.V1 facades'),
    ('production', 'scripts/proof/native_lab_history.py',
     ('NativeWriterLabRehearsal', 'LabHistoryStoreTest', 'LabHistoryStore'),
     'the lab rehearsal under Format.V2, and the codec controls, generator and predictor'),
)
# The labels of this runner's steps, by step or by the step's first two words, and of its readers.
STEP_LABELS = {'store classes': ('production', 'archived-baseline'),
               'b0 c926': ('archived-baseline',), 'b0 d104': ('archived-baseline',), 'b0 b1-v1': ('legacy',),
               'b1 focused': ('production', 'legacy', 'rollback-reader'), 'b1 faults': ('production',),
               'presence v2': ('production',),
               'readers': ('production', 'rollback-reader', 'archived-baseline'),
               'rollback': ('rollback-reader', 'production'),
               'mutants': ('production', 'legacy', 'rollback-reader')}
READER_LABELS = {'b1-v1': 'rollback-reader', 'c926': 'archived-baseline', '7845': 'rollback-reader'}


def step_labels(step):
    """The labels of one of this runner's steps."""
    return STEP_LABELS[step] if step in STEP_LABELS else STEP_LABELS[step.rsplit(' ', 1)[0]]


def harness_class(name):
    """The one host source of a labelled host class, under the platform tests or the native
    identity tests, or None."""
    found = [path for path in (ROOT / PLATFORM / (name + '.java'), ROOT / PLATFORM / (name + '.java.in'))
             if path.is_file()]
    found += sorted((ROOT / 'tests/native-identity').rglob(name + '.java'))
    return found[0] if len(found) == 1 else None


def label_problems():
    """The labels name only known runners and host classes, use every label, and label every step
    and reader of this runner."""
    problems = []
    for label, runner, classes, runs in HARNESS_LABELS:
        if label not in RUN_LABELS or not (ROOT / runner).is_file() or not classes or not runs:
            problems.append('harness label row %s %s' % (label, runner))
        for name in classes:
            if harness_class(name) is None:
                problems.append('labelled host class not found once: ' + name)
    if {row[0] for row in HARNESS_LABELS} != set(RUN_LABELS):
        problems.append('a run label names no harness')
    for labels in list(STEP_LABELS.values()) + [(label,) for label in READER_LABELS.values()]:
        if not labels or not set(labels) <= set(RUN_LABELS):
            problems.append('unknown step label %s' % (labels,))
    if set(READER_LABELS) != {target for target, _, _ in READERS} or not set(ROLLBACK_READERS) <= {
            target for target, label in READER_LABELS.items() if label == 'rollback-reader'}:
        problems.append('reader labels differ from the readers')
    return problems

STORE = FRAMEWORK_DIR + 'NativeIdentityStore.java'
PERSISTENCE = FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
MANAGER = FRAMEWORK_DIR + 'NativePrincipalManager.java'
# Deliberate B1 defects: source, exact replacements and the suites to run. The predictions file
# lists the checks each must fail.
MUTANTS = {
    'no-version-relaxation': (STORE, ((
        '        if (copy.version != selected.version && (copy.version != HEADER_V1\n'
        '                || selected.version != HEADER_V2 || copy.lastId >= selected.lastId)) return false;\n',
        '        if (copy.version != selected.version) return false;\n'),), ('focused', 'faults')),
    'permissive-v1-successor': (STORE, ((
        '                || selected.version != HEADER_V2 || copy.lastId >= selected.lastId)) return false;',
        '                || selected.version != HEADER_V2)) return false;'),), ('focused',)),
    'filling-legacy-b': (PERSISTENCE, ((
        '                entries.put(record.appId, known);\n',
        '                entries.put(record.appId, row == null || format.reservationVersion == VERSION_1\n'
        '                        ? known : new HeaderEntry(known.appId, SlotPhase.CREATING,\n'
        '                        known.creationId, known.creationPackage,\n'
        '                        new CreationBinding(record.userId, record.userSerial, row)));\n'),),
        ('focused', 'faults')),
    'upgrading-only-restatement': (PERSISTENCE, ((
        '        int version = bound ? format.reservationVersion : current.version;\n',
        '        int version = format.reservationVersion;\n'),), ('focused', 'faults')),
    'low-level-restatement-upgrade': (STORE, ((
        '        return next.version == selected.version || newlyBound;\n',
        '        return true;\n'),), ('focused',)),
    'wrong-version-measure': (PERSISTENCE, ((
        '                version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES) return null;',
        '                current.version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES)'
        ' return null;'),), ('focused', 'faults')),
    'no-byte-measure': (PERSISTENCE, ((
        '        if (list.size() > NativeIdentityRecords.MAX_SLOTS || NativeIdentityRecords.encodedHeaderLength(\n'
        '                version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES) return null;\n',
        '        if (list.size() > NativeIdentityRecords.MAX_SLOTS) return null;\n'),), ('focused',)),
    'current-packagesetting-signers': (MANAGER, ((
        '                rows.put(record.id, issuance.selection.currentSignerSha256);\n',
        '                rows.put(record.id, signerDigests(issuance.selection.setting));\n'),), ('focused',)),
    'omit-retiring': (MANAGER, ((
        '            } else if (pin.issuance() instanceof Issuance issuance && issuance.owner == this) {\n',
        '            } else if (pin.phase() != NativePrincipalPins.Phase.RETIRING\n'
        '                    && pin.issuance() instanceof Issuance issuance && issuance.owner == this) {\n'),),
        ('focused', 'faults')),
    'withphase-downgrade': (PERSISTENCE, ((
        '            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);\n'
        '        }\n        return sameVersion(header, entries);\n',
        '            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);\n'
        '        }\n        return new Header(header.lineage, header.lastId, entries);\n'),), ('focused', 'faults')),
    'new-incomplete-under-v2': (PERSISTENCE, ((
        '            CreationBinding binding = format.reservationVersion == VERSION_1 ? null\n'
        '                    : new CreationBinding(record.userId, record.userSerial, row);\n',
        '            CreationBinding binding = null;\n'),), ('focused', 'faults')),
    'low-level-incomplete-new': (STORE, ((
        '            if (format.reservationVersion > HEADER_V1 && (next.version != format.reservationVersion\n'
        '                    || entry.creationBinding == null)) return false;\n',
        ''),), ('focused',)),
    'rows-required-for-held': (PERSISTENCE, ((
        '                if (held.phase == SlotPhase.CREATING && !reservedFor(held, record, row)) return null;\n',
        '                if (row == null || (held.phase == SlotPhase.CREATING\n'
        '                        && !reservedFor(held, record, row))) return null;\n'),), ('focused',)),
    # The header footprint suite's app ID only defect. On these sources the projection reuses the
    # exact durable addition first, so that suite no longer reaches it; a direct writer case does.
    'compare-addition-app-id-only': (STORE, (
        ('            if (!addition.equals(headerEntry(next, addition.appId))) return false;',
         '            if (headerEntry(next, addition.appId) == null) return false;'),
        ('                    || entry.equals(copies.additions.get(entry.appId))) continue;',
         '                    || copies.additions.containsKey(entry.appId)) continue;')), ('focused',)),
    'binding-unchecked-on-load': (STORE, ((
        '                    if (index.phase == SlotPhase.CREATING && !bindingHolds(index, slot)) {\n'
        '                        bindingMismatch = true;\n'
        '                    }\n',
        ''),), ('focused',)),
    # A record whose complete creation binding fails stops being negative sibling evidence, so
    # the binding check makes a conflicting sibling usable again.
    'binding-conflict-first-copy-only': (STORE, ((
        '                for (Slot copy : entry.getValue().decodedCopies) {\n',
        '                for (Slot copy : entry.getValue().decodedCopies.subList(0,\n'
        '                        Math.min(1, entry.getValue().decodedCopies.size()))) {\n'),), ('focused',)),
    'binding-conflict-last-copy-only': (STORE, ((
        '                for (Slot copy : entry.getValue().decodedCopies) {\n',
        '                for (Slot copy : entry.getValue().decodedCopies.subList(\n'
        '                        Math.max(0, entry.getValue().decodedCopies.size() - 1),\n'
        '                        entry.getValue().decodedCopies.size())) {\n'),), ('focused',)),
    # Anchored to the one evidence predicate of the counter admission correction, which also
    # bounds creation. The defect is the same: a failed binding is no evidence.
    'binding-conflict-evidence-dropped': (STORE, ((
        '                        || entry.getValue().unavailable\n'
        '                        || bindingConflicts.contains(entry.getKey());',
        '                        || entry.getValue().unavailable;'),), ('focused',)),
    # Every CONFLICT record becomes evidence, so an ordinary unbound conflict alone withdraws a
    # sibling that version 1 keeps usable.
    'binding-conflict-evidence-every-conflict': (STORE, ((
        '                        || bindingConflicts.contains(entry.getKey());',
        '                        || entry.getValue().status == Status.CONFLICT;'),), ('focused',)),
    # The binding is checked only in the selected header copy, not in every decoded copy.
    'binding-checked-in-selected-header-only': (STORE, ((
        '                    if (index.phase == SlotPhase.CREATING && !bindingHolds(index, slot)) {\n',
        '                    if (copy == header.value && index.phase == SlotPhase.CREATING\n'
        '                            && !bindingHolds(index, slot)) {\n'),), ('focused',)),
    # A failed binding is evidence only when no ordinary conflict applies: the superseded rule.
    'binding-evidence-only-as-sole-cause': (STORE, ((
        '                if (bindingMismatch) bindingConflicts.add(entry.getKey());',
        '                if (bindingMismatch && !conflict) bindingConflicts.add(entry.getKey());'),),
        ('focused',)),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('creation binding source seam drift: ' + old[:80])
    return text.replace(old, new, 1)


def _limit(text):
    return None if text == 'max' else int(text)


def resource_guard(cgroup_root=Path('/sys/fs/cgroup'), membership=Path('/proc/self/cgroup')):
    """Require bounded memory, no swap, 2 CPUs, 256 tasks and disabled core dumps, from this
    process's cgroup or an ancestor. Nothing is created or changed. Returns None or a reason."""
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        return 'core dumps must be disabled with both limits zero'
    try:
        lines = membership.read_text().splitlines()
    except OSError as error:
        return 'cgroup membership unreadable: %s' % error
    unified = [line[3:] for line in lines if line.startswith('0::')]
    if len(unified) != 1 or not unified[0].startswith('/') or '..' in unified[0].split('/'):
        return 'no single unified cgroup membership'
    leaf = cgroup_root / unified[0].lstrip('/')
    chain = [leaf, *leaf.parents]
    if cgroup_root not in chain:
        return 'cgroup path outside the mounted hierarchy'
    chain = chain[:chain.index(cgroup_root) + 1]
    found = {'memory.max': [], 'memory.swap.max': [], 'pids.max': [], 'cpu.max': []}
    try:
        for directory in chain:
            for name, values in found.items():
                path = directory / name
                if not path.exists():
                    continue
                text = path.read_text().strip()
                if name == 'cpu.max':
                    quota, period = text.split()
                    if quota != 'max':
                        values.append(int(quota) / int(period))
                elif _limit(text) is not None:
                    values.append(_limit(text))
    except (OSError, ValueError) as error:
        return 'cgroup limits unreadable: %s' % error
    effective = {name: min(values) if values else None for name, values in found.items()}
    if (effective['memory.max'] is None or effective['memory.max'] > 2 * GIB
            or effective['memory.swap.max'] != 0
            or effective['cpu.max'] is None or effective['cpu.max'] > 2
            or effective['pids.max'] is None or effective['pids.max'] > 256):
        return 'required bounds absent: %s' % json.dumps(effective, sort_keys=True)
    return None


# ---------------------------------------------------------------- pure source checks

def strip_java_comments(text):
    """Java text with comments blanked, string and character literals kept."""
    result, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = n if end < 0 else end
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = n - 2 if end < 0 else end
            result.append(' ' * (end + 2 - i))
            i = end + 2
        elif c in '"\'':
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == '\\' else 1
            result.append(text[i:j + 1])
            i = j + 1
        else:
            result.append(c)
            i += 1
    return ''.join(result)


def added_java(patch_text):
    """Added lines of the patch's Java file sections only."""
    lines, java = [], False
    for line in patch_text.splitlines():
        if line.startswith('+++ '):
            java = line.split()[1].endswith('.java')
        elif java and line.startswith('+'):
            lines.append(line[1:])
    return '\n'.join(lines)


# ---------------------------------------------------------------- the production format guard

NATIVE_PATCH = 'patches/grapheneos-2026081300/native-principal-pins.patch'
WRITER_PATCH = 'patches/grapheneos-2026081300/native-identity-writer.patch'
WRITER_FIXTURE = 'tests/native-identity/writer/NativePrincipalWriterFixture.java'
# The native helpers the native patch adds to the framework, by production text name.
NATIVE_HELPERS = tuple(path.relative_to(ROOT).as_posix() for path in integration.ADDED.values())
SETTINGS_SECTION = NATIVE_PATCH + ':' + integration.SETTINGS
FACADE = PLATFORM + 'native_principal_stubs/com/android/server/pm/Settings.java'
# The one boot construction of the adapted Settings, ported from the retired lab format tool:
# its method, the construction up to its format argument and the persistence that follows it.
METHOD = '    NativeIdentityStore.Loaded readNativeIdentityStoreForBoot() {\n'
CONSTRUCTION = ('        mNativeIdentityStore = new NativeIdentityStore(\n'
                '                new File(Environment.getDataSystemDirectory(), "native-principals"),\n'
                '                ')
BOOT_END = '        mNativeIdentityPersistence = new NativeIdentityPersistence(mNativeIdentityStore);\n'
# The format the boot construction passes, and the format of the earlier normal images.
PRODUCTION = 'NativeIdentityStore.Format.V2'
RETIRED = 'NativeIdentityStore.Format.V1'
# The store's whole Format enum, comments aside: two closed versions fixed at construction.
FORMAT_ENUM = ('enum Format { V1(1, 1), V2(2, 2); final int headerCeiling; final int reservationVersion;'
               ' Format(int headerCeiling, int reservationVersion) { this.headerCeiling = headerCeiling;'
               ' this.reservationVersion = reservationVersion; } }')
# Value, property, settings, reflection and enum selection. This set is refused in every
# production text. The retired lab tool's wider set, with EnumSet, method and variable handles,
# Unsafe, and field and declaring class lookups, is refused in the native sources.
SELECTORS = (r'\bFormat\s*\.\s*valueOf\b', r'\bFormat\s*\.\s*values\s*\(', r'\bEnum\s*\.\s*valueOf\b',
             r'\bFormat\s*\.\s*class\b', r'getEnumConstants')
NATIVE_SELECTORS = SELECTORS + (r'SystemProperties', r'\bSettings\.Global\b', r'java\.lang\.reflect',
                                r'\.forName\(', r'\.getDeclared', r'setAccessible\(', r'\bEnumSet\b',
                                r'\bMethodHandle', r'\bVarHandle', r'\bUnsafe\b', r'\bgetField',
                                r'\bgetDeclaringClass\b')
# A store construction: direct, by simple or qualified name, or a constructor reference.
CONSTRUCTIONS = (r'\bnew\s+(?:[\w$]+\s*\.\s*)*NativeIdentityStore\s*\(', r'\bNativeIdentityStore\s*::\s*new\b')
# A Java unicode escape. Java decodes it before comments and literals, so it could hide code from
# the comment stripper and every pattern here. No production text carries one.
UNICODE_ESCAPE = r'\\+u+[0-9A-Fa-f]{4}'
# The guard's rules, by the name each violation starts with.
FORMAT_RULES = ('sites', 'format', 'v1', 'mention', 'selector', 'enum', 'escape')
HUNK = re.compile(r'@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@')


def patch_sections(text):
    """The added lines of each file section of a unified diff, in order, as (target, text). A
    section starts at its header pair. Hunk counts decide which lines are hunk content, so a
    content line that looks like a header stays in its own section. A malformed hunk refuses."""
    sections, lines, index = [], text.split('\n'), 0
    if lines and lines[-1] == '':
        lines.pop()  # The final newline ends the last line; it starts no empty one.
    while index < len(lines):
        line = lines[index]
        if line.startswith('--- ') and index + 1 < len(lines) and lines[index + 1].startswith('+++ '):
            target = lines[index + 1][4:].split('\t')[0]
            sections.append((target[2:] if target.startswith('b/') else target, []))
            index += 2
            continue
        hunk = HUNK.match(line)
        index += 1
        if hunk is None:
            continue
        if not sections:
            raise ValueError('patch hunk before any file header')
        old, new = (1 if count is None else int(count) for count in hunk.groups())
        added = sections[-1][1]
        while old > 0 or new > 0:
            if index >= len(lines):
                raise ValueError('truncated patch hunk')
            body = lines[index]
            index += 1
            if body.startswith('\\'):
                continue
            if body.startswith('+'):
                added.append(body[1:])
                new -= 1
            elif body.startswith('-'):
                old -= 1
            elif body.startswith(' ') or body == '':
                old -= 1
                new -= 1
            else:
                raise ValueError('malformed patch hunk line')
            if old < 0 or new < 0:
                raise ValueError('patch hunk count mismatch')
    return [(target, '\n'.join(added)) for target, added in sections]


def production_texts():
    """Every production Java text by name: the framework sources, each Java file section of every
    patch by its added lines, named '<patch>:<file>', and the lab writer fixture. A patch is read
    per file section, never as one merged text."""
    texts = {path.relative_to(ROOT).as_posix(): path.read_text()
             for path in sorted((ROOT / FRAMEWORK_DIR).glob('*.java'))}
    for patch in sorted((ROOT / 'patches').rglob('*.patch')):
        name = patch.relative_to(ROOT).as_posix()
        for target, added in patch_sections(patch.read_text()):
            key = '%s:%s' % (name, target)
            if key in texts:
                raise ValueError('patch with two sections for one file: ' + key)
            if target.endswith('.java'):
                texts[key] = added
    texts[WRITER_FIXTURE] = (ROOT / WRITER_FIXTURE).read_text()
    return texts


def native_source(name):
    """Whether a production text is native: a native helper, a section of the native patch, or the
    lab writer route, its fixture and its patch section."""
    return (name in NATIVE_HELPERS or name.startswith(NATIVE_PATCH + ':') or name == WRITER_FIXTURE
            or name.startswith(WRITER_PATCH + ':'))


def boot_site(text):
    """The offset of the format argument of the one anchored boot construction in a comment free
    Settings section, or None. The method, the construction and the persistence after it each
    occur once, in that order, inside that one method."""
    if text is None:
        return None
    start, site = text.find(METHOD), text.find(CONSTRUCTION)
    end = text.find(BOOT_END, max(start, 0))
    if (text.count(METHOD) != 1 or text.count(CONSTRUCTION) != 1 or text.count(BOOT_END) != 1
            or not 0 <= start < site < end or '\n    }\n' in text[start:end]):
        return None
    return site + len(CONSTRUCTION)


def boot_argument(text, offset):
    """The format argument from offset up to the parenthesis that closes the construction."""
    depth, index = 1, offset
    while depth and index < len(text):
        depth += {'(': 1, ')': -1}.get(text[index], 0)
        index += 1
    return re.sub(r'\s+', ' ', text[offset:index - 1]).strip()


def enum_definition(text):
    """The store's Format enum from its keyword through its closing brace, whitespace collapsed,
    or None when there is not exactly one."""
    found = list(re.finditer(r'\benum\s+Format\s*\{', text))
    if len(found) != 1:
        return None
    depth, index = 0, found[0].end() - 1
    while index < len(text):
        depth += {'{': 1, '}': -1}.get(text[index], 0)
        index += 1
        if depth == 0:
            return ' '.join(text[found[0].start():index].split())
    return None


def format_violations(texts):
    """Every production format violation, as 'rule: detail'.

    sites: exactly one store construction and one Format.V2 in all production texts, both the
    anchored boot construction in readNativeIdentityStoreForBoot of the native patch's Settings
    section. A qualified construction or a constructor reference is a construction too. format:
    that construction passes exactly Format.V2. v1: no production text names Format.V1 or imports
    the enum's constants by wildcard. mention: only the native helpers and the native patch name
    NativeIdentityStore. selector: no value, property, settings, reflection or enum selection,
    with the wider set in the native sources. enum: the store's Format enum is exactly its two
    closed versions. escape: no production text carries a Java unicode escape, which could hide
    code from every other rule. Comments are not code."""
    problems = []
    code = {name: strip_java_comments(raw) for name, raw in texts.items()}
    boot = boot_site(code.get(SETTINGS_SECTION))
    if boot is None:
        problems.append('sites: no anchored boot construction in readNativeIdentityStoreForBoot of '
                        + SETTINGS_SECTION)
        construction = literal = None
    else:
        construction = boot - len(CONSTRUCTION) + CONSTRUCTION.index('new ')
        literal = boot + PRODUCTION.index('Format')
    for name, text in code.items():
        here = name == SETTINGS_SECTION
        for pattern in CONSTRUCTIONS:
            for found in re.finditer(pattern, text):
                if not (here and found.start() == construction):
                    problems.append('sites: %s constructs a store outside the boot read: %s'
                                    % (name, ' '.join(found.group(0).split())))
        for found in re.finditer(r'\bFormat\s*\.\s*V2\b', text):
            if not (here and found.start() == literal):
                problems.append('sites: %s names Format.V2 outside the boot construction' % name)
        for pattern in (r'\bFormat\s*\.\s*V1\b', r'\bimport\s+static\s+[\w.]*\bFormat\s*\.\s*\*'):
            for found in re.finditer(pattern, text):
                problems.append('v1: %s names the retired format: %s' % (name, found.group(0)))
        if (re.search(r'\bNativeIdentityStore\b', text) and name not in NATIVE_HELPERS
                and not name.startswith(NATIVE_PATCH + ':')):
            problems.append('mention: %s names NativeIdentityStore outside the native helpers and patch'
                            % name)
        for pattern in NATIVE_SELECTORS if native_source(name) else SELECTORS:
            for found in re.finditer(pattern, text):
                problems.append('selector: %s selects by %s' % (name, found.group(0)))
        # Escapes are refused in the raw text of every production text, comments included, since
        # Java decodes them first.
        for found in re.finditer(UNICODE_ESCAPE, texts[name]):
            problems.append('escape: %s carries the unicode escape %s' % (name, found.group(0)))
    if boot is not None and not code[SETTINGS_SECTION].startswith(PRODUCTION + ');', boot):
        problems.append('format: the boot construction passes %s, not %s'
                        % (boot_argument(code[SETTINGS_SECTION], boot), PRODUCTION))
    store = code.get(STORE)
    definition = None if store is None else enum_definition(store)
    if definition != FORMAT_ENUM:
        problems.append('enum: the store Format enum is not exactly V1(1, 1) and V2(2, 2): %s' % definition)
    return problems


def format_rules(texts):
    """The guard rules these production texts trip."""
    return {problem.split(':', 1)[0] for problem in format_violations(texts)}


def boot_literal(texts=None):
    """The format argument of the anchored boot construction in the native patch, or None."""
    texts = production_texts() if texts is None else texts
    code = strip_java_comments(texts.get(SETTINGS_SECTION, ''))
    boot = boot_site(code)
    return None if boot is None else boot_argument(code, boot)


def facade_default(text=None):
    """The format the host Settings facade constructs when a test passes none, or None. Both
    constructors without a format must reach the one default."""
    text = (ROOT / FACADE).read_text() if text is None else text
    found = re.findall(r'^    Settings\(Path existing, boolean initialize\) '
                       r'\{ this\(existing, initialize, ([A-Za-z0-9_.]+)\); \}$', text, re.M)
    if len(found) != 1 or text.count('\n    Settings() { this(null, true); }\n') != 1:
        return None
    return found[0]


def r0_forward(text):
    """The text with the earlier images' boot literal Format.V1 replaced by Format.V2: the whole R0
    change of the native patch and of the adapted Settings, and the code change of the host
    facade's default. None unless exactly one earlier literal and no production literal occur.
    Historical comparisons use it to allow exactly that change and nothing else."""
    old, new = RETIRED + ');', PRODUCTION + ');'
    if text.count(old) != 1 or text.count(new):
        return None
    return text.replace(old, new, 1)


def facade_violations(texts=None, facade=None):
    """The host facade's default format is the literal of the patch's boot construction."""
    literal, default = boot_literal(texts), facade_default(facade)
    if literal is None or default != literal:
        return ['host Settings facade default %s differs from the boot construction literal %s'
                % (default, literal)]
    return []


def surface_violations():
    """The B1 production surface: no Snapshot overload beside plans, one fixed format, and the
    encoder's own byte measure. The format guard pins the Format enum itself."""
    problems = []
    store = strip_java_comments((ROOT / STORE).read_text())
    persistence = strip_java_comments((ROOT / PERSISTENCE).read_text())
    records = strip_java_comments((ROOT / FRAMEWORK_DIR / 'NativeIdentityRecords.java').read_text())
    manager = strip_java_comments((ROOT / MANAGER).read_text())
    if re.search(r'reservePending\s*\(\s*NativePrincipalPins\s*\.\s*Snapshot', persistence):
        problems.append('reservePending keeps a Snapshot overload')
    if re.search(r'projectReservation\s*\([^)]*Snapshot', persistence):
        problems.append('projectReservation keeps a Snapshot overload')
    if len(re.findall(r'\bboolean\s+reservePending\s*\(', persistence)) != 1:
        problems.append('reservePending is not one plan method')
    if len(re.findall(r'\bHeader\s+projectReservation\s*\(', persistence)) != 1:
        problems.append('projectReservation is not one method')
    if len(re.findall(r'NativeIdentityStore\s*\(\s*File\s+root\s*,\s*Format\s+format\s*\)', store)) != 1 \
            or re.search(r'NativeIdentityStore\s*\(\s*File\s+root\s*\)', store):
        problems.append('store is not constructed only with an explicit format')
    if len(re.findall(r'private final Format format;', store)) != 1 \
            or len(re.findall(r'\bformat\s*=\s*Objects\.requireNonNull\(format', store)) != 1:
        problems.append('store format is not one final field assigned at construction')
    if 'headerBody(version, lineage, lastId, copy).length()' not in records:
        problems.append('encodedHeaderLength is not the encoder measure')
    if persistence.count('NativeIdentityRecords.encodedHeaderLength(') != 1:
        problems.append('projection does not measure exactly once')
    if 'currentSignerSha256' not in manager or 'ownedPlan(' not in manager:
        problems.append('manager plan provenance missing')
    return problems


def mutant_sources():
    """Each B1 mutant applied to the current source text, anchored exactly once."""
    result = {}
    for name, (path, replacements, suites) in MUTANTS.items():
        text = (ROOT / path).read_text()
        for old, new in replacements:
            text = replace_once(text, old, new)
        result[name] = (path, text, suites)
    return result


def one_token_patch(old, new):
    """A one token Settings patch, as the retired lab format was, from one boot format literal to
    another."""
    first, second, indent = CONSTRUCTION.split('\n')
    return ('--- a/%s\n+++ b/%s\n@@ -611,7 +611,7 @@\n' % (integration.SETTINGS, integration.SETTINGS)
            + '         if (mNativeIdentityPersistence != null) throw new IllegalStateException('
              '"Native store loaded twice");\n'
            + ' %s\n %s\n-%s%s);\n+%s%s);\n %s' % (first, second, indent, old, indent, new, BOOT_END)
            + '         NativeIdentityStore.Loaded loaded = mNativeIdentityPersistence.load();\n'
            + '         // This is negative preservation evidence, never signer/owner identity.\n')


# Where each guard mutant's one token version 1 patch lands under patches/.
ONE_TOKEN_PATHS = {'one-token-v1-patch-beside-native': 'patches/grapheneos-2026081300/native-store-format-v1.patch',
                   'one-token-v1-patch-other-directory': 'patches/lab/any-name.patch'}
# Code the guard mutants insert before the persistence constructor, or pass at the boot site.
HOST_CONSTRUCTION = ('    static NativeIdentityPersistence host(java.io.File root) {\n'
                     '        return new NativeIdentityPersistence(new NativeIdentityStore(root,\n'
                     '                NativeIdentityStore.Format.V2));\n    }\n\n')
REFLECTIVE_WRITE = ('    static void copyFormat(NativeIdentityStore store, NativeIdentityStore from)\n'
                    '            throws ReflectiveOperationException {\n'
                    '        java.lang.reflect.Field field = NativeIdentityStore.class.getDeclaredField("format");\n'
                    '        field.setAccessible(true);\n'
                    '        field.set(store, field.get(from));\n    }\n\n')
COMPLEMENT = ('    static NativeIdentityStore.Format otherFormat(NativeIdentityStore store) {\n'
              '        return java.util.EnumSet.complementOf(java.util.EnumSet.of(store.format()))\n'
              '                .iterator().next();\n    }\n\n')
SELECTED = ('NativeIdentityStore.Format.valueOf(android.os.SystemProperties.get('
            '"persist.andrix.native_format", "V2")));\n')
QUALIFIED = ('    static NativeIdentityStore qualified(java.io.File root, NativeIdentityStore.Format format) {\n'
             '        return new com.android.server.pm.NativeIdentityStore(root, format);\n    }\n\n')
REFERENCE = ('    static final java.util.function.BiFunction<java.io.File, NativeIdentityStore.Format,\n'
             '            NativeIdentityStore> STORES = %sNativeIdentityStore::new;\n\n')
DECLARING_FIELD = ('    static Object retired(NativeIdentityStore store) throws ReflectiveOperationException {\n'
                   '        return store.format().getDeclaringClass().getField("V1").get(null);\n    }\n\n')
# Java ends this comment at the escaped line break and compiles the rest of the line as code.
HIDDEN = ('    // \\u000a static final NativeIdentityStore HIDDEN = new NativeIdentityStore('
          'new java.io.File("/"), NativeIdentityStore.Format.V1);\n')
RETIRED_NAME = ('    static NativeIdentityStore.Format earlierFormat() {\n'
                '        return NativeIdentityStore.Format.V1;\n    }\n\n')
# A non native framework source that names the store, and the non native class it goes in.
MENTION = '    private static final String STORE = "NativeIdentityStore";\n'
NON_NATIVE = FRAMEWORK_DIR + 'CeStorageAccessTracker.java'


def guard_mutants():
    """Production format defects, each with the exact set of guard rules it must trip."""
    texts = production_texts()
    settings, persistence = SETTINGS_SECTION, FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
    manager = NATIVE_PATCH + ':' + integration.PREFIX + 'PackageManagerService.java'
    boot = CONSTRUCTION + PRODUCTION + ');\n'
    anchor = '    NativeIdentityPersistence(NativeIdentityStore store) {\n'

    def changed(*edits):
        result = dict(texts)
        for name, old, new in edits:
            result[name] = replace_once(result[name], old, new)
        return result

    # The boot method's head, construction and persistence move to the start of the next file's
    # section. Read as one merged text, that anchored construction would still be found.
    head = texts[settings][texts[settings].index(METHOD):texts[settings].index(BOOT_END) + len(BOOT_END)]
    other_section = changed((settings, head, ''))
    other_section[manager] = head + texts[manager]
    outside = changed((settings, boot, ''))
    outside[settings] = replace_once(outside[settings], METHOD,
                                     '    void openNativeIdentityStoreLPw() {\n' + boot + '    }\n\n' + METHOD)
    second = boot.replace('mNativeIdentityStore =', 'NativeIdentityStore second =', 1)
    result = {
        'regression-to-v1': (changed((settings, boot, CONSTRUCTION + RETIRED + ');\n')), {'format', 'v1'}),
        'second-construction': (changed((settings, BOOT_END, BOOT_END + second)), {'sites'}),
        'framework-construction': (changed((persistence, anchor, HOST_CONSTRUCTION + anchor)), {'sites'}),
        'other-file-section': (other_section, {'sites'}),
        'value-and-property-selection': (changed((settings, boot, CONSTRUCTION + SELECTED)), {'format', 'selector'}),
        'reflective-field-write': (changed((persistence, anchor, REFLECTIVE_WRITE + anchor)), {'selector'}),
        'enumset-complement': (changed((persistence, anchor, COMPLEMENT + anchor)), {'selector'}),
        'enum-version-swap': (changed((STORE, 'V1(1, 1),', 'V1(2, 2),'), (STORE, 'V2(2, 2);', 'V2(1, 1);')),
                              {'enum'}),
        'construction-outside-boot': (outside, {'sites'}),
        'qualified-construction': (changed((persistence, anchor, QUALIFIED + anchor)), {'sites'}),
        'constructor-reference': (changed((persistence, anchor, REFERENCE % '' + anchor)), {'sites'}),
        'qualified-constructor-reference': (
            changed((persistence, anchor, REFERENCE % 'com.android.server.pm.' + anchor)), {'sites'}),
        'declaring-class-field': (changed((persistence, anchor, DECLARING_FIELD + anchor)), {'selector'}),
        'unicode-escape': (changed((persistence, anchor, HIDDEN + anchor)), {'escape'}),
        'format-alone': (changed((settings, boot, CONSTRUCTION + 'productionFormat());\n')), {'format'}),
        'v1-alone': (changed((persistence, anchor, RETIRED_NAME + anchor)), {'v1'}),
        'mention-alone': (changed((NON_NATIVE, 'public final class CeStorageAccessTracker {\n',
                                   'public final class CeStorageAccessTracker {\n' + MENTION)), {'mention'}),
        'non-native-unicode-escape': (changed((NON_NATIVE, 'public final class CeStorageAccessTracker {\n',
                                               'public final class CeStorageAccessTracker {\n' + HIDDEN)),
                                      {'escape'}),
    }
    for name, path in ONE_TOKEN_PATHS.items():
        patched = dict(texts)
        for target, added in patch_sections(one_token_patch(PRODUCTION, RETIRED)):
            patched['%s:%s' % (path, target)] = added
        result[name] = (patched, {'v1', 'mention'})
    return result


def verify_candidate(pinned):
    """Rebuild the ten framework outputs from pinned canonical copies with the current patch.
    Returns each output's hash and whether it matches the profile candidate. Pure Python and
    /usr/bin/patch; no compiler."""
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
    output = integration.targets(original, value)
    return {name: {'sha256': sha(output[name]), 'candidate': sha(output[name]) == row['candidate_sha256']}
            for row in value['files'] for name in [row['path']]}


def source_checks():
    integration.profile()
    texts = production_texts()
    problems = format_violations(texts) + surface_violations() + facade_violations(texts)
    for name, (mutated, rules) in guard_mutants().items():
        tripped = format_rules(mutated)
        if tripped != rules:
            problems.append('guard mutant %s tripped %s, not %s' % (name, sorted(tripped), sorted(rules)))
    # Each anchor must exist exactly once in the current sources, or this raises.
    mutant_sources()
    b0.mutants()
    admission = integration.FRAGMENTS['admission'][1].read_bytes()
    facade = (ROOT / FACADE).read_bytes()
    if facade.count(admission) != 1:
        problems.append('host admission differs from the production fragment')
    predictions = json.loads(PREDICTIONS.read_text())
    d104 = predictions['b0_adapted_suite']['d104e15']
    if (len(d104['focused_failures']) != 41 or len(d104['fault_failures']) != 18
            or not set(d104['focused_failures']) <= set(b0.FOCUSED_NAMES)
            or not set(d104['fault_failures']) <= set(b0.FAULT_NAMES)):
        problems.append('d104 predictions inconsistent')
    for name, expected in predictions['b1_mutants_caught_at_least'].items():
        if name not in MUTANTS or not set(expected) <= set(FOCUSED_NAMES) | set(FAULT_NAMES):
            problems.append('mutant prediction inconsistent: ' + name)
    if len(set(FOCUSED_NAMES)) != len(FOCUSED_NAMES) or len(set(FAULT_NAMES)) != len(FAULT_NAMES):
        problems.append('duplicate check names')
    problems += label_problems()
    for revision in REVISIONS:
        if set(BASELINE_SHA256.get(revision, ())) != set(FRAMEWORK) | {'Settings'}:
            problems.append('baseline pins incomplete: ' + revision)
    return problems


# ---------------------------------------------------------------- JVM builds, guarded

def git_bytes(revision, path):
    result = subprocess.run(['git', '-C', str(ROOT), 'show', '%s:%s' % (revision, path)],
                            capture_output=True, timeout=60,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
    if result.returncode:
        raise ValueError('baseline source unavailable: ' + path)
    return result.stdout


def git_paths(revision, directory):
    result = subprocess.run(['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', revision,
                             directory], capture_output=True, timeout=60,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
    if result.returncode:
        raise ValueError('baseline tree unavailable: ' + directory)
    return sorted(result.stdout.decode().splitlines())


def product_sources(baseline=None, framework_override=None):
    """Framework sources, guarded fixtures and host facades, as relative source path to bytes:
    from the worktree, or exactly from a baseline revision's Git objects."""
    revision = REVISIONS[baseline] if baseline else None
    read = (lambda path: git_bytes(revision, path)) if baseline else (lambda path: (ROOT / path).read_bytes())
    files = {}
    for name in FRAMEWORK:
        files['framework/%s.java' % name] = read(FRAMEWORK_DIR + name + '.java')
    for name in ('AppIdSettingMap', 'ResilientAtomicFile'):
        files['fixtures/%s.java' % name] = read(PLATFORM + name + '.java.inc')
    stubs = {}
    for directory in STUB_DIRECTORIES:
        prefix = PLATFORM + directory + '/'
        paths = (git_paths(revision, prefix) if baseline else
                 sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / prefix).rglob('*.java')))
        for path in paths:
            relative = path[len(prefix):]
            if relative.endswith('/Xml.java'):
                continue
            if relative in stubs and relative != 'android/util/Log.java':
                raise ValueError('unreviewed host facade overlap: ' + relative)
            stubs[relative] = read(path)
    for relative, data in stubs.items():
        files['stubs/' + relative] = data
    if baseline:
        expected = BASELINE_SHA256[baseline]
        for name in FRAMEWORK:
            if sha(files['framework/%s.java' % name]) != expected[name]:
                raise ValueError('baseline drift: %s %s' % (baseline, name))
        if sha(files['stubs/com/android/server/pm/Settings.java']) != expected['Settings']:
            raise ValueError('baseline facade drift: ' + baseline)
    for name, text in (framework_override or {}).items():
        files['framework/%s.java' % name] = text.encode()
    return files


def store_sources():
    """The records, store, strict writer and file facades alone, as the store suites compile."""
    files = {'framework/%s.java' % name: (ROOT / FRAMEWORK_DIR / (name + '.java')).read_bytes()
             for name in ('NativeIdentityRecords', 'NativeIdentityStore')}
    files['fixtures/ResilientAtomicFile.java'] = (ROOT / PLATFORM / 'ResilientAtomicFile.java.inc').read_bytes()
    base = ROOT / PLATFORM / 'native_principal_xml_stubs'
    for path in sorted(base.rglob('*.java')):
        if path.name != 'Xml.java':
            files['stubs/' + path.relative_to(base).as_posix()] = path.read_bytes()
    return files


def with_seams(files):
    files = dict(files)
    files['framework/NativeIdentityStore.java'] = b0.inject(
        files['framework/NativeIdentityStore.java'].decode(), b0.STORE_SEAMS).encode()
    files['fixtures/ResilientAtomicFile.java'] = b0.inject(
        files['fixtures/ResilientAtomicFile.java'].decode(), b0.WRITER_SEAMS).encode()
    return files


def test_sources(names, original_b0=False, adapter=None):
    files = {}
    for name in names:
        path = PLATFORM + name + '.java'
        data = git_bytes(REVISIONS['c926'], path) if original_b0 else (ROOT / path).read_bytes()
        if original_b0 and sha(data) != ORIGINAL_B0_SHA256[name]:
            raise ValueError('archived header footprint suite drift: ' + name)
        files['tests/%s.java' % name] = data
    if adapter:
        files['tests/NativeHeaderApi.java'] = (ROOT / PLATFORM / 'native_header_api' / adapter
                                               / 'NativeHeaderApi.java').read_bytes()
    return files


def build(work, files):
    source = work / 'src'
    for relative, data in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    classes = work / 'classes'
    classes.mkdir(parents=True)
    result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                             '-d', str(classes), *sorted(str(source / name) for name in files)],
                            capture_output=True, text=True, timeout=300)
    return {'returncode': result.returncode, 'output': result.stdout + result.stderr,
            'stdout': result.stdout, 'stderr': result.stderr,
            'inputs': {name: sha(data) for name, data in sorted(files.items())}}


def execute(work, main, args, assertions=True, timeout=900):
    state = work / 'state'
    state.mkdir(exist_ok=True)
    result = subprocess.run(['java', '-Xmx256m', *(['-ea'] if assertions else []),
                             '-Djava.io.tmpdir=' + str(state), '-cp', str(work / 'classes'),
                             'com.android.server.pm.' + main, *args],
                            capture_output=True, text=True, timeout=timeout)
    return {'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr,
            'passed': b0.passed_checks(result.stdout),
            'failed': sorted(b0.failed_checks(result.stdout))}


def suite(work, files, main, args=None):
    work.mkdir(parents=True)
    built = build(work, files)
    record = {'build': built}
    if built['returncode']:
        # A compile failure is a harness failure, never an expected red result.
        record['compile_failure'] = True
        return record
    record['run'] = execute(work, main, [str(work / 'state')] + list(args or []))
    return record


B0_TESTS = {'focused': ('NativeHeaderTestSupport', b0.FOCUSED),
            'faults': ('NativeHeaderTestSupport', b0.FAULTS, 'NativeHeaderWriteFaults')}


def b0_suite(work, baseline, kind, original):
    names = B0_TESTS[kind]
    product = product_sources(baseline)
    if kind == 'faults':
        product = with_seams(product)
    adapter = None if original else ('baseline' if baseline else 'b1')
    return suite(work, {**product, **test_sources(names, original_b0=original, adapter=adapter)},
                 names[1])


def b1_suite(work, kind, framework_override=None):
    product = product_sources(framework_override=framework_override)
    names = ['NativeHeaderTestSupport', 'NativeBindingTestSupport']
    if kind == 'faults':
        product = with_seams(product)
        names += ['NativeHeaderWriteFaults', 'NativeCreationBindingFaultTest']
        main = 'NativeCreationBindingFaultTest'
    else:
        names += ['NativeCreationBindingTest']
        main = 'NativeCreationBindingTest'
    return suite(work, {**product, **test_sources(names, adapter='b1')}, main)


def class_differences(first, second):
    """Class files that differ between two output trees, or exist in only one of them. Pure."""
    trees = [{path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*.class')}
             for root in (first, second)]
    return sorted(name for name in set(trees[0]) | set(trees[1]) if trees[0].get(name) != trees[1].get(name))


def store_class_identity(work):
    """R0 changed only comments of the store helper. Compiled with the same records, strict writer
    and facades, the 78456b3 helper and the current one give identical class files. Guarded."""
    current = store_sources()
    archived = dict(current)
    archived['framework/NativeIdentityStore.java'] = git_bytes(REVISIONS['7845'], STORE)
    if sha(archived['framework/NativeIdentityStore.java']) != BASELINE_SHA256['7845']['NativeIdentityStore']:
        raise ValueError('baseline drift: 7845 NativeIdentityStore')
    record = {'differences': None}
    for name, files in (('current', current), ('7845', archived)):
        (work / name).mkdir(parents=True)
        record[name] = build(work / name, files)
        if record[name]['returncode']:
            return record
    record['differences'] = class_differences(work / 'current/classes', work / '7845/classes')
    record['classes'] = len(list((work / 'current/classes').rglob('*.class')))
    return record


def outcome(record, names):
    """Passed and failed names of a finished suite, or why it is not a result."""
    if record.get('compile_failure'):
        return {'error': 'compile failure', 'build': record['build']}
    run = record['run']
    actual = run['passed'] + run['failed']
    unknown = sorted(set(actual) - set(names))
    return {'passed': run['passed'], 'failed': run['failed'], 'returncode': run['returncode'],
            'unknown': unknown, 'complete': len(actual) == len(names) and set(actual) == set(names),
            'build': record['build'], 'run': run}


def qualify(work):
    """Every guarded JVM step. The caller has passed resource_guard."""
    predictions = json.loads(PREDICTIONS.read_text())
    evidence = {'java': subprocess.run(['java', '-version'], capture_output=True, text=True,
                                       timeout=60).stderr.strip(), 'steps': {}, 'problems': []}
    steps, problems = evidence['steps'], evidence['problems']

    # The store helper's R0 comment change: class files identical to the 78456b3 helper's.
    steps['store classes'] = store_class_identity(work / 'store-classes')
    if steps['store classes']['differences'] != [] or not steps['store classes'].get('classes'):
        problems.append('store helper class files differ from 78456b3: %s' % steps['store classes']['differences'])

    # The archived suite, unchanged, then the adapted suite through each adapter.
    for baseline in ('c926', 'd104'):
        for kind, names in (('focused', b0.FOCUSED_NAMES), ('faults', b0.FAULT_NAMES)):
            original = outcome(b0_suite(work / ('b0-original-%s-%s' % (baseline, kind)), baseline, kind, True), names)
            adapted = outcome(b0_suite(work / ('b0-adapted-%s-%s' % (baseline, kind)), baseline, kind, False), names)
            steps['b0 %s %s' % (baseline, kind)] = {'original': original, 'adapted': adapted}
            if 'error' in original or 'error' in adapted:
                problems.append('b0 %s %s did not compile' % (baseline, kind))
                continue
            if original['failed'] != adapted['failed'] or original['passed'] != adapted['passed']:
                problems.append('b0 %s %s adapted suite differs from the archived suite' % (baseline, kind))
            if not (original['complete'] and adapted['complete']):
                problems.append('b0 %s %s incomplete' % (baseline, kind))
            expected = (predictions['b0_adapted_suite']['d104e15']['focused_failures' if kind == 'focused'
                        else 'fault_failures'] if baseline == 'd104' else [])
            # Reported separately: the archived suite's own failures are the requirement.
            matches = sorted(expected) == adapted['failed']
            steps['b0 %s %s' % (baseline, kind)]['prediction_matches'] = matches
            if not matches:
                problems.append('b0 %s %s exact failure set differs' % (baseline, kind))
            for label, result in (('original', original), ('adapted', adapted)):
                if result['returncode'] != (1 if expected else 0):
                    problems.append('b0 %s %s %s exit status' % (baseline, kind, label))
            count = {'focused': 41, 'faults': 18}[kind] if baseline == 'd104' else 0
            if len(adapted['failed']) != count:
                problems.append('b0 %s %s failed %d, expected %d' % (baseline, kind, len(adapted['failed']), count))
    for kind, names in (('focused', b0.FOCUSED_NAMES), ('faults', b0.FAULT_NAMES)):
        adapted = outcome(b0_suite(work / ('b0-adapted-b1-' + kind), None, kind, False), names)
        steps['b0 b1-v1 ' + kind] = {'adapted': adapted}
        if ('error' in adapted or adapted['failed'] or adapted['passed'] != list(names)
                or adapted['returncode'] != 0):
            problems.append('b0 adapted suite on B1 V1 ' + kind)

    # B1 focused and fault matrices.
    for kind, names in (('focused', FOCUSED_NAMES), ('faults', FAULT_NAMES)):
        record = b1_suite(work / ('b1-' + kind), kind)
        result = outcome(record, names)
        steps['b1 ' + kind] = result
        if 'error' in result or result['failed'] or result['passed'] != list(names) or result['returncode']:
            problems.append('b1 %s matrix' % kind)
        elif 'unqualified' not in record['run']['stdout']:
            problems.append('b1 %s scope statement missing' % kind)
        else:
            refused = execute(work / ('b1-' + kind), record_main(kind), [str(work / ('b1-' + kind) / 'state')],
                              assertions=False, timeout=120)
            if not refused['returncode'] or '-ea' not in refused['stderr']:
                problems.append('b1 %s ran without assertions' % kind)

    # The complete presence and unavailable matrix under the host version 2 format.
    presence = work / 'presence-v2'
    files = {**store_sources(), **test_sources(['NativeIdentityPresenceTest'])}
    presence.mkdir(parents=True)
    built = build(presence, files)
    steps['presence v2'] = {'build': built}
    if built['returncode']:
        problems.append('presence V2 did not compile')
    else:
        # The special-node controls bind real Unix sockets at their actual store paths.
        # Keep that path under the kernel limit, independently of the evidence path.
        with tempfile.TemporaryDirectory(prefix='b1p-', dir='/tmp') as state:
            run = execute(presence, 'NativeIdentityPresenceTest', [state, 'V2'])
        steps['presence v2'].update(returncode=run['returncode'], failed=run['failed'],
                                    passed=len(run['passed']), run=run)
        if run['returncode'] or '93 passed, 0 failed' not in run['stdout'] \
                or 'Unprivileged DAC refused' not in run['stdout']:
            problems.append('presence V2 matrix')

    # Version 2 layouts from the production host writer, read by the version 1 rollback reader,
    # the current sources under Format.V1 and the pinned 78456b3 image, and by archived c9264e4.
    emitter = work / 'layouts-emitter'
    emitter.mkdir(parents=True)
    files = {**with_seams(product_sources()),
             **test_sources(['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHeaderWriteFaults',
                             'NativeCreationBindingLayouts'], adapter='b1')}
    built = build(emitter, files)
    layouts = work / 'layouts'
    if built['returncode']:
        problems.append('layout emitter did not compile')
        steps['readers'] = {'emitter_build': built['output']}
    else:
        emitted = execute(emitter, 'NativeCreationBindingLayouts', [str(layouts), str(emitter / 'state')])
        names = sorted(p.name for p in layouts.iterdir()) if layouts.is_dir() else []
        steps['readers'] = {'emitted': names, 'emitter_returncode': emitted['returncode'],
                            'emitter_build': built, 'emitter_run': emitted}
        if emitted['returncode'] or tuple(names) != LAYOUT_NAMES:
            problems.append('layout emitter')
        steps['readers']['copy_layouts'] = copy_layouts(layouts) if layouts.is_dir() else None
        if steps['readers']['copy_layouts'] != ROLLBACK_COPY_LAYOUTS:
            problems.append('version 2 copy layouts %s, not the predicted %d'
                            % (steps['readers']['copy_layouts'], ROLLBACK_COPY_LAYOUTS))
        for target, baseline, adapter in READERS:
            copy = work / ('layouts-' + target)
            shutil.copytree(layouts, copy, symlinks=True)
            reader = work / ('reader-' + target)
            reader.mkdir(parents=True)
            built = build(reader, {**product_sources(baseline),
                                   **test_sources(['NativeHeaderTestSupport', 'NativeCreationBindingReaderCheck'],
                                                  adapter=adapter)})
            if built['returncode']:
                problems.append('reader %s did not compile' % target)
                steps['readers'][target] = {'build': built}
                continue
            run = execute(reader, 'NativeCreationBindingReaderCheck', [str(copy), str(reader / 'state')])
            steps['readers'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                        'passed': len(run['passed']), 'build': built, 'run': run}
            if (run['returncode'] or run['failed'] or run['passed'] !=
                    ['version 1 reader / ' + name for name in LAYOUT_NAMES]):
                problems.append('reader ' + target)
        # The rollback effects in the Settings facade: no history, holds without pins and every
        # mapped native package kept but refused by the scan.
        steps['rollback'] = {}
        for target in ROLLBACK_READERS:
            baseline = dict((name, revision) for name, revision, _ in READERS)[target]
            copy = work / ('layouts-rollback-' + target)
            shutil.copytree(layouts, copy, symlinks=True)
            checker = work / ('rollback-' + target)
            checker.mkdir(parents=True)
            built = build(checker, {**product_sources(baseline),
                                    **test_sources(['NativeHeaderTestSupport', 'NativeRollbackReaderCheck'],
                                                   adapter='b1')})
            if built['returncode']:
                problems.append('rollback reader %s did not compile' % target)
                steps['rollback'][target] = {'build': built}
                continue
            run = execute(checker, 'NativeRollbackReaderCheck', [str(copy), str(checker / 'state'),
                                                                 str(ROLLBACK_COPY_LAYOUTS), ','.join(ROLLBACK_CONTROLS)])
            steps['rollback'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                         'passed': len(run['passed']), 'build': built, 'run': run}
            if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                    rollback_names('rollback reader', LAYOUT_NAMES, ROLLBACK_CONTROLS)):
                problems.append('rollback reader ' + target)

    # Deliberate B1 defects must compile and be caught.
    steps['mutants'] = {}
    expectations = predictions['b1_mutants_caught_at_least']
    for name, (path, text, suites) in mutant_sources().items():
        override = {Path(path).stem: text}
        failed, record = set(), {}
        for kind in suites:
            result = outcome(b1_suite(work / 'mutants' / name / kind, kind, override),
                             FOCUSED_NAMES if kind == 'focused' else FAULT_NAMES)
            record[kind] = result
            if 'error' in result:
                problems.append('mutant %s did not compile; not a red result' % name)
                continue
            failed |= set(result['failed'])
            if result['failed'] and not result['returncode']:
                problems.append('mutant %s failures did not fail the run' % name)
        missed = sorted(set(expectations[name]) - failed)
        record['missed'] = missed
        steps['mutants'][name] = record
        if missed or not failed:
            problems.append('mutant %s not caught: %s' % (name, missed))
    evidence['labels'] = {step: list(step_labels(step)) for step in steps}
    evidence['reader_labels'] = dict(READER_LABELS)
    return evidence


def record_main(kind):
    return 'NativeCreationBindingFaultTest' if kind == 'faults' else 'NativeCreationBindingTest'


REGRESSIONS = (
    ('scripts/proof/tests', 'test_native_identity_store.py'),
    ('scripts/proof/tests', 'test_native_identity_persistence.py'),
    ('scripts/proof/tests', 'test_native_principal_pins.py'),
    ('scripts/proof/tests', 'test_native_preparation_faults.py'),
    ('scripts/proof/tests', 'test_native_recovery_boot.py'),
    ('scripts/proof/tests', 'test_native_header_footprint.py'),
    ('scripts/proof/tests', 'test_native_identity_writer.py'),
    ('tests/native-identity', 'test_writer.py'),
    ('tests/native-identity', 'test_jvm.py'))


def regressions():
    results = {}
    for directory, module in REGRESSIONS:
        result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-v', '-s',
                                 str(ROOT / directory), '-p', module], capture_output=True, text=True,
                                timeout=7200, cwd=ROOT)
        skipped = re.findall(r'\bskipped\b', result.stderr)
        results[module] = {'returncode': result.returncode, 'skipped': len(skipped),
                           'stdout': result.stdout, 'stderr': result.stderr}
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--verify-candidate', type=Path,
                        help='pinned canonical framework copies; pure patch reproduction only')
    parser.add_argument('--source-checks-only', action='store_true')
    args = parser.parse_args()
    report = {'runtime_qualified': False, 'android_qualified': False, 'activation': False}
    problems = source_checks()
    report['source_checks'] = problems or 'PASS'
    if args.verify_candidate:
        report['candidate'] = verify_candidate(args.verify_candidate.resolve(strict=True))
        if not all(row['candidate'] for row in report['candidate'].values()):
            problems.append('regenerated candidate differs from the profile')
    if args.source_checks_only or args.verify_candidate:
        report['status'] = 'FAIL' if problems else 'SOURCE_ONLY'
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    if not args.evidence:
        parser.error('--evidence is required for a guarded run')
    evidence = args.evidence.resolve()
    if evidence.exists() or ROOT in evidence.parents:
        raise ValueError('fresh evidence outside the repository required')
    reason = resource_guard()
    if reason:
        report.update(status='NOT_RUN', reason=reason)
        print(json.dumps(report, indent=2))
        return 2
    if not (shutil.which('javac') and shutil.which('java')):
        report.update(status='NOT_RUN', reason='no JDK on PATH')
        print(json.dumps(report, indent=2))
        return 2
    try:
        with tempfile.TemporaryDirectory(prefix='andrix-b1-') as directory:
            qualified = qualify(Path(directory))
        report.update(qualified)
        report['regressions'] = regressions()
        for module, result in report['regressions'].items():
            if result['returncode'] or result['skipped']:
                problems.append('regression ' + module)
        problems += qualified['problems']
    except Exception as error:
        report['exception'] = {'type': type(error).__name__, 'message': str(error)}
        if isinstance(error, subprocess.TimeoutExpired):
            report['exception'].update(command=error.cmd, timeout=error.timeout,
                                      stdout=(error.stdout.decode(errors='replace')
                                              if isinstance(error.stdout, bytes) else error.stdout or ''),
                                      stderr=(error.stderr.decode(errors='replace')
                                              if isinstance(error.stderr, bytes) else error.stderr or ''))
        problems.append('qualification did not complete')
    report['status'] = 'FAIL' if problems else 'PASS'
    report['problems'] = problems
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
