#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of the native counter admission correction: a decoded principal
ID above the selected header counter, in a copy of that lineage or of a record that is already
negative evidence, withholds new issuance and changes nothing else. No compiler or JVM starts
unless an actual cgroup bounds this process to 2 GiB of memory, no swap, 2 CPUs and 256 tasks,
with core dumps disabled, and the resolved --work path is short enough for the deepest Unix
socket that the nested B2 and B1 runners bind below it. Otherwise the run is NOT_RUN and creates
and starts nothing. That budget needs a --work of at most 29 ASCII characters, such as /srv/b3w.
A guarded run creates files only under that fresh --work directory, including its checkpoint
progress.json, and the fresh --evidence file. The unchanged behavior of the nested B2 runner is
kept: the B1 runner it starts binds its version 2 presence sockets in a fresh /tmp/b1p-*
directory. Unless the JDK is configured otherwise, each JVM also keeps HotSpot's transient
performance data file in /tmp/hsperfdata_<user> while it runs. A run that stops early keeps
every finished record and its NOT_COMPLETE status; nothing is retried. The surface and the
three sided comparison are archived at 24bfb6a, which carries the correction: they read pinned
Git objects only. The focused suite and its mutants stay living on the current sources.
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
import native_creation_history as b2  # noqa: E402
import native_principal_pins as integration  # noqa: E402

PLATFORM = b1.PLATFORM
FRAMEWORK_DIR = b1.FRAMEWORK_DIR
STORE = FRAMEWORK_DIR + 'NativeIdentityStore.java'
FACADE = b2.FACADE
PREDICTIONS = ROOT / 'scripts/proof/native_counter_admission_predictions.json'
TEST = 'NativeCounterAdmissionTest'
SUPPORT = ('NativeHeaderTestSupport', 'NativeBindingTestSupport')
# The primary's two read only probes, copied verbatim. They inform the matrix; their refusal on
# the corrected sources is an observation, never a pass. The focused suite asserts the refusal.
# The archived sides compile their pinned 24bfb6a objects, which have these bytes.
PROBES = {'UnsupportedCounterProbe': '894bb4d16c4d7170ccba9e358a08bfb3c9f95946246d95868040f9d059d4a087',
          'StaleSlotCounterProbe': '5b222adecd6f4466a789b8f29fde4270481868a6a45f7c70ec1e9d9023c8b1b3'}

# 89491b9, the B2 base of this correction, becomes one more exact baseline of the B1 Git object
# loader, in memory only. 0018a1d is already registered by the B2 runner.
BASE_0018 = b2.BASE
BASE_8949 = '8949'
REVISION_8949 = '89491b90c1038f0a69e481b6fa2e5d9e70ae1e17'
BASELINE_8949 = {
    'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
    'NativePrincipalManager': '1fa50501728a66b676020c83fce44d5868686db37a6b5867498975ae4d57ceb4',
    'NativeIdentityRecords': '412c2271a9efabf9937375bd42f2e49c5e3fb4d09935a9e98d6e5805736a3009',
    'NativeIdentityStore': '4476df1d2d2b9b1e515d31ac429a30a27560fb79eac0c37e66e548390eabcb05',
    'NativeIdentityPersistence': 'f2fd1a5e6d272f99bb06973700d885523c1dbff033731b4a02e969f8bfb29f54',
    'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
    'Settings': '2eaa6c9dae109f949fb23b553b92d8396d4d65c70b42caa83650821ba2b40669'}
b1.REVISIONS[BASE_8949] = REVISION_8949
# The exact R0 bytes of the host facade at 24bfb6a, beside the code comparison with 89491b9: its
# default is the boot construction's Format.V2. They are the archive's pin of that facade.
FACADE_R0_SHA256 = '0b78a6518a21bf3a5a365705a85bde454a41448e561b0c7cdf7d07b287120806'
b1.BASELINE_SHA256[BASE_8949] = dict(BASELINE_8949)
# The other inputs that the archived surface reads at 89491b9: its patch, whose bytes 78456b3 kept,
# its profile, its B1 suite, and its recovery fragments, which are the 24bfb6a fragments.
PATCH_8949_SHA256 = '8e5a3ec75d0e9b0d9d6258c5e332f01c9258092145cbd3e32335aae8bf5f2d3d'
PROFILE_8949_SHA256 = 'cd129b0a9f3dc8ddfef63fdd3a054353c6e66a9fa1ba9cb5d1d7a9f0fa2344e3'
B1_TEST_8949_SHA256 = '1e7c53c30fa161d7bea3e937712d856d1979f122f2f1e4ca4c3afda2998c460e'
# The archived suite and support, and the archived surface's paths at 89491b9 and 24bfb6a, frozen.
ARCHIVED_TEST = 'NativeCounterAdmissionTest'
ARCHIVED_SUPPORT = ('NativeHeaderTestSupport', 'NativeBindingTestSupport')
ARCHIVED_B1_TEST = b1.ARCHIVED_PLATFORM + 'NativeCreationBindingTest.java'
ARCHIVED_STORE_ROW = 'services/core/java/com/android/server/pm/NativeIdentityStore.java'
b1.BASELINE_INPUTS_SHA256[BASE_8949] = {
    b1.ARCHIVED_PATCH: PATCH_8949_SHA256, b1.ARCHIVED_PROFILE: PROFILE_8949_SHA256,
    ARCHIVED_B1_TEST: B1_TEST_8949_SHA256, **{path: b1.ARCHIVE_SHA256[path] for path in b1.ARCHIVED_FRAGMENTS.values()}}
# The corrected side of every archived comparison is the pinned 24bfb6a sources, which carry the
# correction and the later R0 change. The current sources, 'fix', run the focused suite and its
# mutants, which stay living.
CORRECTED = b1.ARCHIVE
ARCHIVED_SIDES = (BASE_0018, BASE_8949, CORRECTED)
# Every guarded phase in order. A run reports those it completed and those it did not.
PHASES = ('candidates', 'focused', 'baselines', 'probes', 'parity', 'mutants', 'b2 runner')
# The labels of this runner's guarded steps, as the B1 runner's HARNESS_LABELS name them: the
# living focused suite and mutants on the current sources, and the archived sides.
STEP_LABELS = {'focused': ('production', 'legacy'), 'baselines': ('archived-baseline',),
               'probes': ('archived-baseline',), 'parity': ('archived-baseline', 'rollback-reader'),
               'mutants': ('production', 'legacy')}
# This runner's archived steps. Every other labelled step is living.
ARCHIVED_STEP_NAMES = ('baselines', 'probes', 'parity')

FOCUSED_NAMES = (
    'gate / a nonzero user above the counter',
    'control / a nonzero user within the counter',
    'control / a selected body above the counter blocks as before',
    'gate / a stale copy beside a selected backup',
    'control / an unselected copy of another package keeps ordinary bindings',
    'gate / conflicting copies without a backup',
    'gate / a damaged preferred backup beside decoded copies',
    'gate / a body naming another app ID',
    'control / an ordinary conflict of another lineage',
    'gate / an unsupported record of another lineage',
    'residual / another lineage above the counter strands a later release',
    'evidence / a failed binding keeps every higher copy',
    'evidence / a failed binding beside an ordinary conflict',
    'evidence / a failed binding of another lineage',
    'evidence / a failed binding keeps a foreign slot copy under a known counter',
    'evidence / a failed binding keeps its sibling evidence',
    'selection / a higher unselected header counter is not the bound',
    'selection / a predecessor counter is not the bound',
    'control / a decodable staging seed is never counted',
    'copies / a higher ID only in the middle copy',
    'copies / a higher ID only in main',
    'copies / a higher ID only in reserve without main',
    'copies / a higher ID in either user order',
    'copies / a higher claim at either app ID order',
    'control / healthy copies at or below the counter',
    'boundary / a Long.MAX_VALUE claim never becomes the counter',
    'boundary / an ID equal to the counter passes without a counter change',
    'control / an ordinary conflict gives no sibling evidence',
    'composition / a counter block withdraws a reservation and keeps bodies',
    'manager / an unsupported higher principal refuses issuance before any effect',
    'manager / a stale higher copy refuses issuance until its own confirmation',
    'manager / a healthy body retires beside a blocked store',
    'manager / a lost BODY cannot be republished while the counter is blocked',
    'manager / a live registry refuses after observing a higher copy',
    'manager / holds and refusals survive reopening and lost replies')
# The archived sides' cases, frozen at 24bfb6a. The living list above follows the current suite;
# this one never does.
ARCHIVED_FOCUSED_NAMES = (
    'gate / a nonzero user above the counter',
    'control / a nonzero user within the counter',
    'control / a selected body above the counter blocks as before',
    'gate / a stale copy beside a selected backup',
    'control / an unselected copy of another package keeps ordinary bindings',
    'gate / conflicting copies without a backup',
    'gate / a damaged preferred backup beside decoded copies',
    'gate / a body naming another app ID',
    'control / an ordinary conflict of another lineage',
    'gate / an unsupported record of another lineage',
    'residual / another lineage above the counter strands a later release',
    'evidence / a failed binding keeps every higher copy',
    'evidence / a failed binding beside an ordinary conflict',
    'evidence / a failed binding of another lineage',
    'evidence / a failed binding keeps a foreign slot copy under a known counter',
    'evidence / a failed binding keeps its sibling evidence',
    'selection / a higher unselected header counter is not the bound',
    'selection / a predecessor counter is not the bound',
    'control / a decodable staging seed is never counted',
    'copies / a higher ID only in the middle copy',
    'copies / a higher ID only in main',
    'copies / a higher ID only in reserve without main',
    'copies / a higher ID in either user order',
    'copies / a higher claim at either app ID order',
    'control / healthy copies at or below the counter',
    'boundary / a Long.MAX_VALUE claim never becomes the counter',
    'boundary / an ID equal to the counter passes without a counter change',
    'control / an ordinary conflict gives no sibling evidence',
    'composition / a counter block withdraws a reservation and keeps bodies',
    'manager / an unsupported higher principal refuses issuance before any effect',
    'manager / a stale higher copy refuses issuance until its own confirmation',
    'manager / a healthy body retires beside a blocked store',
    'manager / a lost BODY cannot be republished while the counter is blocked',
    'manager / a live registry refuses after observing a higher copy',
    'manager / holds and refusals survive reopening and lost replies')

# The correction's code, comments aside, and the 89491b9 code it replaces. The archived surface
# check requires the pinned 24bfb6a Store to differ from 89491b9 by exactly these, so no other
# rule changed. They describe history: the living mutants anchor in the current Store instead.
ARCHIVED_RULE_NEW = '''
            Header selected = header.status == Status.VALID ? header.value : null;
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                boolean evidence = entry.getValue().status == Status.UNSUPPORTED
                        || entry.getValue().unavailable
                        || bindingConflicts.contains(entry.getKey());
                for (Slot copy : entry.getValue().decodedCopies) {
                    if (selected != null && (evidence || copy.lineage.equals(selected.lineage))
                            && claimsAbove(copy, selected.lastId)) blocked = true;
                    if (!evidence) continue;
                    packages.putIfAbsent(copy.packageName, entry.getKey());
'''
ARCHIVED_RULE_OLD = '''
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                if (entry.getValue().status != Status.UNSUPPORTED
                        && !entry.getValue().unavailable
                        && !bindingConflicts.contains(entry.getKey())) continue;
                for (Slot copy : entry.getValue().decodedCopies) {
                    packages.putIfAbsent(copy.packageName, entry.getKey());
'''
ARCHIVED_HELPER = '''
    private static boolean claimsAbove(Slot copy, long counter) {
        for (UserEntry user : copy.users) {
            if (user.id > counter) return true;
        }
        return false;
    }
'''
# The one intentional B1 expectation change: only this readiness check of the mismatch loop, as
# the archived surface finds it in the pinned 24bfb6a suite.
ARCHIVED_B1_NEW = '''
                boolean ready = !body.getKey().equals("two users");
                check(problems, read != null && read.status != Status.VALID && !loaded.bindingUsable(R)
                        && loaded.occupiedAppIds.contains(R) && loaded.creationReady() == ready,
                        "load " + (read == null ? null : read.status) + " ready " + loaded.creationReady());
'''
ARCHIVED_B1_OLD = '''
                check(problems, read != null && read.status != Status.VALID && !loaded.bindingUsable(R)
                        && loaded.occupiedAppIds.contains(R) && loaded.creationReady(),
                        "load " + (read == null ? null : read.status));
'''

_PREDICATE = '(evidence || copy.lineage.equals(selected.lineage))'
_BLOCK = '&& claimsAbove(copy, selected.lastId)) blocked = true;'
_EVIDENCE_TAIL = '                        || bindingConflicts.contains(entry.getKey());\n'
# Deliberate defects of the correction: source, exact replacements. Each runs the complete
# focused suite on the corrected sources. A compile failure is a harness failure, never red.
MUTANTS = {
    'rule-dropped': (STORE, ((
        '                    if (selected != null && (evidence || copy.lineage.equals(selected.lineage))\n'
        '                            && claimsAbove(copy, selected.lastId)) blocked = true;\n', ''),)),
    # Only records that already feed incarnation evidence count; stale ordinary copies do not.
    'existing-evidence-only': (STORE, ((_PREDICATE, 'evidence'),)),
    'observed-header-counter': (STORE, ((
        _BLOCK, '&& claimsAbove(copy, HeaderCopies.of(header) == null ? selected.lastId\n'
                '                                    : HeaderCopies.of(header).observedCounter)) blocked = true;'),)),
    'smallest-header-counter': (STORE, ((
        _BLOCK, '&& claimsAbove(copy, header.decodedCopies.stream().mapToLong(h -> h.lastId)\n'
                '                                    .min().orElse(selected.lastId))) blocked = true;'),)),
    'first-copy-only': (STORE, ((
        _BLOCK, '&& copy == entry.getValue().decodedCopies.get(0)\n'
                '                            ' + _BLOCK),)),
    'last-copy-only': (STORE, ((
        _BLOCK, '&& copy == entry.getValue().decodedCopies.get(entry.getValue().decodedCopies.size() - 1)\n'
                '                            ' + _BLOCK),)),
    # Foreign evidence is missed.
    'same-lineage-only': (STORE, ((_PREDICATE, 'copy.lineage.equals(selected.lineage)'),)),
    # An ordinary conflict of another lineage blocks too.
    'every-lineage': (STORE, ((_PREDICATE, '(evidence || !copy.lineage.isEmpty())'),)),
    'seeds-included': (STORE, ((
        '                    if (record.unavailable || seed.found == Found.UNAVAILABLE) unavailable = true;\n',
        '                    if (record.unavailable || seed.found == Found.UNAVAILABLE) unavailable = true;\n'
        '                    // Mutant: a decodable staging seed counts against the selected counter.\n'
        '                    if (seed.bytes != null && header.status == Status.VALID) {\n'
        '                        try {\n'
        '                            if (claimsAbove(NativeIdentityRecords.decodeSlot(seed.bytes),\n'
        '                                    header.value.lastId)) blocked = true;\n'
        '                        } catch (IllegalArgumentException torn) {\n'
        '                            // A torn seed stays staging.\n'
        '                        }\n'
        '                    }\n'),)),
    'greater-or-equal': (STORE, ((
        '            if (user.id > counter) return true;\n',
        '            if (user.id >= counter) return true;\n'),)),
    # A reopened registry takes the largest decoded principal ID as its counter.
    'restore-max-decoded-id': (FACADE, ((
        '            restored.restoreBindingsWithoutCounter(records, retiring);\n',
        '            // Mutant: a counter derived from the largest decoded principal ID.\n'
        '            long derived = loaded.header.value == null ? 0 : loaded.header.value.lastId;\n'
        '            for (NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> read\n'
        '                    : loaded.slots.values()) {\n'
        '                for (NativeIdentityRecords.Slot copy : read.decodedCopies) {\n'
        '                    for (NativeIdentityRecords.UserEntry user : copy.users) {\n'
        '                        derived = Math.max(derived, user.id);\n'
        '                    }\n'
        '                }\n'
        '            }\n'
        '            restored.restore(new NativePrincipalPins.Snapshot(derived, records, retiring));\n'),)),
    'format-flag-instead-of-block': (STORE, ((
        _BLOCK, '&& claimsAbove(copy, selected.lastId)) unsupported = true;'),)),
    'status-instead-of-block': (STORE, ((
        _BLOCK, '&& claimsAbove(copy, selected.lastId)) {\n'
                '                        entry.setValue(new ReadResult<>(Status.CONFLICT, null,\n'
                '                                entry.getValue().decodedCopies));\n'
                '                    }'),)),
    'ordinary-conflicts-as-evidence': (STORE, ((
        _EVIDENCE_TAIL, '                        || bindingConflicts.contains(entry.getKey())\n'
                        '                        || entry.getValue().status == Status.CONFLICT;\n'),)),
    'ignore-binding-conflicts': (STORE, ((
        '                        || entry.getValue().unavailable\n' + _EVIDENCE_TAIL,
        '                        || entry.getValue().unavailable;\n'),)),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- pure source checks

def archived_normalized(text):
    """Java code with comments removed and every whitespace run one space."""
    return ' '.join(b1.archived_strip_java_comments(text).split())


def archived_code(text):
    return ' '.join(text.split())


def archived_store_problems(current, base):
    """Whether the Store's code, comments aside, differs from the base by exactly the rule and
    its helper. Pure."""
    current, before = archived_normalized(current), archived_normalized(base)
    new, old, helper = (archived_code(ARCHIVED_RULE_NEW), archived_code(ARCHIVED_RULE_OLD),
                        archived_code(ARCHIVED_HELPER))
    if current.count(new) != 1 or current.count(helper) != 1 or before.count(old) != 1:
        return ['Store rule or helper anchor drift']
    if archived_code(current.replace(new, old).replace(helper, '')) != before:
        return ['Store code changed beyond the counter admission rule']
    return []


def archived_b1_test_problems(current, base):
    """Whether the B1 suite, comments aside, differs from the base by exactly the one readiness
    check. Pure."""
    new, old = ARCHIVED_B1_NEW.strip('\n'), ARCHIVED_B1_OLD.strip('\n')
    if current.count(new) != 1 or base.count(old) != 1:
        return ['B1 readiness revision anchor drift']
    if archived_normalized(current.replace(new, old)) != archived_normalized(base):
        return ['B1 suite changed beyond the two users readiness check']
    return []


@b1.archived
def archived_r0_problems(old_profile, profile, patch, facade):
    """Whether the later R0 change of the version 2 normal store is exactly its boot literal: the
    patch is 89491b9's with that one literal, the profile pins that patch and changes only the
    Settings candidate among its file rows, and the facade's code differs only by its default.
    The pinned candidate rebuild checks the Settings candidate itself. The profile, patch and
    facade are given as the surface reads them, the pinned 24bfb6a objects; the 89491b9 side is
    read from its pinned objects."""
    problems = []
    old_patch = b1.pinned_bytes(BASE_8949, b1.ARCHIVED_PATCH)
    if (sha(old_patch) != old_profile['patch_sha256'] or profile['patch_sha256'] != sha(patch)
            or b1.archived_r0_forward(old_patch.decode()) != patch.decode()):
        problems.append('patch differs from 89491b9 beyond the R0 boot literal')
    old_files = {row['path']: row for row in old_profile['files']}
    if [row['path'] for row in profile['files']] != list(old_files):
        problems.append('profile file rows changed')
    for row in profile['files']:
        prior = old_files.get(row['path'], {})
        changed = {key for key in set(row) | set(prior) if row.get(key) != prior.get(key)}
        if changed - ({'candidate_sha256'} if row['path'] == b1.ARCHIVED_SETTINGS else set()):
            problems.append('profile file row differs from 89491b9 beyond the R0 Settings candidate: '
                            + row['path'])
    base = b1.pinned_bytes(BASE_8949, b1.ARCHIVED_FACADE).decode()
    forward = b1.archived_r0_forward(base)
    if (sha(base.encode()) != BASELINE_8949['Settings'] or forward is None
            or archived_normalized(forward) != archived_normalized(facade.decode())):
        problems.append('Settings facade differs from 89491b9 beyond the R0 default')
    if sha(facade) != FACADE_R0_SHA256:
        problems.append('Settings facade differs from its reviewed R0 bytes')
    return problems


@b1.archived
def archived_surface_violations():
    """The correction's surface, archived over the pinned 24bfb6a sources that carry it: only the
    Store's code changed among the product sources, by the one rule and its helper; the patch,
    facade, fragments and other framework sources are the 89491b9 bytes; the profile differs only
    by the Store's hash; and the B1 suite changed only its one incidental readiness check. The
    later R0 boot literal, its profile pins and the facade's default are allowed exactly, as
    archived_r0_problems checks. Reads pinned Git objects only, with the working tree closed."""
    problems = []
    current = lambda path: b1.pinned_bytes(CORRECTED, path)  # noqa: E731
    base = lambda path: b1.pinned_bytes(BASE_8949, path)  # noqa: E731
    for name, digest in BASELINE_8949.items():
        path = b1.ARCHIVED_FACADE if name == 'Settings' else b1.ARCHIVED_FRAMEWORK_DIR + name + '.java'
        if name not in ('NativeIdentityStore', 'Settings') and sha(current(path)) != digest:
            problems.append('%s differs from 89491b9' % name)
    store = current(b1.ARCHIVED_STORE)
    problems += archived_store_problems(store.decode(), base(b1.ARCHIVED_STORE).decode())
    old_profile = json.loads(base(b1.ARCHIVED_PROFILE))
    profile = json.loads(current(b1.ARCHIVED_PROFILE))
    for key in set(old_profile) | set(profile):
        if key in ('added', 'patch_sha256', 'files'):
            continue
        if old_profile.get(key) != profile.get(key):
            problems.append('profile %s differs from 89491b9' % key)
    problems += archived_r0_problems(old_profile, profile, current(b1.ARCHIVED_PATCH), current(b1.ARCHIVED_FACADE))
    old_added = {row['path']: row for row in old_profile.get('added', [])}
    for row in profile.get('added', []):
        prior = old_added.get(row['path'])
        if prior is None or (row['path'] != ARCHIVED_STORE_ROW and row != prior):
            problems.append('profile added row changed: ' + row['path'])
        elif row['path'] == ARCHIVED_STORE_ROW and (row['source'] != prior['source'] or row['sha256'] != sha(store)):
            problems.append('profile Store row is not the regenerated Store hash')
    if [row['path'] for row in profile.get('added', [])] != list(old_added):
        problems.append('profile added rows reordered')
    for name, fragment in b1.ARCHIVED_FRAGMENTS.items():
        if current(fragment) != base(fragment):
            problems.append('fragment differs from 89491b9: ' + name)
    problems += archived_b1_test_problems(current(ARCHIVED_B1_TEST).decode(), base(ARCHIVED_B1_TEST).decode())
    return problems


def mutant_sources():
    """Each mutant applied to the current text of its target, anchored exactly once."""
    result = {}
    for name, (path, replacements) in MUTANTS.items():
        text = (ROOT / path).read_text()
        for old, new in replacements:
            text = b1.replace_once(text, old, new)
        result[name] = (path, text)
    return result


def work_path_problem(work):
    """Why this work path leaves the nested B2 runner's deepest socket too long, or None. The B2
    runner works in <work>/b2. Pure: nothing is created or started."""
    problem = b2.work_path_problem(work / 'b2')
    if problem is None:
        return None
    try:
        limit = '%d' % (b2.SOCKET_LIMIT - 1 - len('/tmp') - len('/b2') - len(b2.presence_tail()))
    except (OSError, ValueError):
        limit = 'an unknown number of'
    return '%s; this runner nests it in <work>/b2, so use a fresh --work of at most %s ASCII' \
        ' characters' % (problem, limit)


@b1.archived
def archived_suite_problems():
    """The archived sides' frozen expectations against the pinned 24bfb6a suite and predictions:
    each frozen case is named once in the suite, their number is the predicted one, and each
    predicted failure, of either baseline and of the corrected sources, and each blocked
    observation label is one of the suite's own."""
    problems = []
    predictions = b1.archived_predictions('counter')
    source = b1.pinned_bytes(CORRECTED, b1.ARCHIVED_PLATFORM + ARCHIVED_TEST + '.java').decode()
    for name in ARCHIVED_FOCUSED_NAMES:
        if source.count('"%s"' % name) != 1:
            problems.append('archived focused case not named once in its pinned source: ' + name)
    if not b1.archived_distinct(ARCHIVED_FOCUSED_NAMES, predictions['focused_cases']):
        problems.append('archived focused cases differ from the pinned prediction')
    for side in (BASE_0018, BASE_8949):
        if not set(predictions['baselines'][side]['focused_failures']) <= set(ARCHIVED_FOCUSED_NAMES):
            problems.append('baseline prediction inconsistent: ' + side)
    if not set(predictions['fix']['focused_failures']) <= set(ARCHIVED_FOCUSED_NAMES):
        problems.append('corrected side prediction inconsistent')
    for label in predictions['blocked_observations']:
        if '"%s"' % label not in source:
            problems.append('blocked observation label not in the pinned suite: ' + label)
    if set(predictions['probes']) != set(PROBES):
        problems.append('pinned probe predictions do not list every probe')
    return problems


# The other module level names of this runner that its archive uses: its pinned revisions and pins,
# and the hash. Every other name the archive uses begins with archived or ARCHIVED_: the frozen
# rule texts, the surface and the observation and probe functions of 24bfb6a among them.
ARCHIVE_SHARED = ('BASE_0018', 'BASE_8949', 'REVISION_8949', 'BASELINE_8949', 'FACADE_R0_SHA256', 'PATCH_8949_SHA256',
                  'PROFILE_8949_SHA256', 'B1_TEST_8949_SHA256', 'CORRECTED', 'PROBES', 'sha')


def boundary_problems():
    """This runner's archive uses only archive names, of its own and of the B1 and B2 archives."""
    b1_names = b1.archive_names(Path(b1.__file__).read_text(), b1.ARCHIVE_SHARED)
    b2_names = b1.archive_names(Path(b2.__file__).read_text(), b2.ARCHIVE_SHARED)
    return b1.archive_boundary(Path(__file__).read_text(), ARCHIVE_SHARED,
                               {'b1': b1_names, 'b2': b2_names, 'integration': None})


def label_problems():
    """Every labelled step is a phase and carries labels its kind allows: living steps only living
    labels and archived steps only archived labels. Every archived step is labelled."""
    problems = []
    for name, labels in STEP_LABELS.items():
        allowed = b1.ARCHIVED_RUN_LABELS if name in ARCHIVED_STEP_NAMES else b1.LIVING_RUN_LABELS
        if name not in PHASES or not labels or not set(labels) <= set(allowed):
            problems.append('step %s carries labels %s' % (name, labels))
    if not set(ARCHIVED_STEP_NAMES) <= set(STEP_LABELS):
        problems.append('an archived step has no labels')
    return problems


def source_checks():
    problems = []
    try:
        integration.profile()
    except ValueError as error:
        problems.append('profile: %s' % error)
    # Every B2 source check still holds, including its B1 and B0 checks and mutant anchors.
    try:
        problems += ['b2: ' + problem for problem in b2.source_checks()]
    except ValueError as error:
        problems.append('b2 source checks: %s' % error)
    try:
        problems += archived_surface_violations()
    except (OSError, ValueError, KeyError) as error:
        problems.append('surface: %s' % error)
    pins = b1.manifest(CORRECTED)
    for name, digest in PROBES.items():
        if pins.get(b1.ARCHIVED_PLATFORM + name + '.java') != digest:
            problems.append('probe pin differs from its archived object: ' + name)
    if FACADE_R0_SHA256 != pins.get(b1.ARCHIVED_FACADE):
        problems.append('R0 facade pin differs from the archived facade')
    try:
        mutated = mutant_sources()
        for name, (path, text) in mutated.items():
            if text == (ROOT / path).read_text():
                problems.append('mutant changes nothing: ' + name)
    except ValueError as error:
        problems.append('mutant anchors: %s' % error)
    predictions = json.loads(PREDICTIONS.read_text())
    names = set(FOCUSED_NAMES)
    source = (ROOT / PLATFORM / (TEST + '.java')).read_text()
    for name in FOCUSED_NAMES:
        if source.count('"%s"' % name) != 1:
            problems.append('focused case not named once in its source: ' + name)
    if len(names) != len(FOCUSED_NAMES):
        problems.append('duplicate check names')
    if set(predictions['mutants_caught_at_least']) != set(MUTANTS):
        problems.append('mutant predictions do not list every mutant')
    for name, checks in predictions['mutants_caught_at_least'].items():
        if not checks or not set(checks) <= names:
            problems.append('mutant prediction inconsistent: ' + name)
    try:
        problems += archived_suite_problems()
    except ValueError as error:
        problems.append('archived suite: %s' % error)
    problems += boundary_problems()
    problems += label_problems()
    try:
        b2.presence_tail()
    except (OSError, ValueError) as error:
        problems.append('work path budget: %s' % error)
    return problems


# ---------------------------------------------------------------- run comparison, pure

def archived_observations(stdout):
    """The OBSERVE lines of one finished suite: (label, format) to facts, ready and restorable."""
    result = {}
    for line in stdout.splitlines():
        if not line.startswith('OBSERVE\t'):
            continue
        fields = line.split('\t')
        if (len(fields) != 6 or fields[4] not in ('ready=true', 'ready=false')
                or fields[5] not in ('restorable=true', 'restorable=false')):
            raise ValueError('malformed observation: ' + line[:160])
        key = (fields[1], fields[2])
        if key in result:
            raise ValueError('duplicate observation: ' + '/'.join(key))
        result[key] = (fields[3], fields[4] == 'ready=true', fields[5] == 'restorable=true')
    return result


def archived_compare_observations(sides, blocked):
    """Problems of the three sides' observations. Every side reports the same layouts with the
    same facts. Readiness differs only at the predicted blocked labels, where the corrected
    sources are neither ready nor restorable and both baselines are ready and agree."""
    problems = []
    keys = set(sides[CORRECTED])
    for side, observed in sorted(sides.items()):
        if set(observed) != keys:
            problems.append('%s observed other layouts than the corrected sources' % side)
    labels = {label for label, _ in keys}
    for label in sorted(set(blocked) - labels):
        problems.append('predicted blocked layout not observed: ' + label)
    for key in sorted(keys):
        values = {side: observed[key] for side, observed in sides.items() if key in observed}
        if len(values) != len(sides):
            continue
        where = '/'.join(key)
        if len({value[0] for value in values.values()}) != 1:
            problems.append('facts differ at %s: %s' % (where, {s: v[0] for s, v in sorted(values.items())}))
        baselines = {value[1:] for side, value in values.items() if side != CORRECTED}
        if key[0] in blocked:
            if values[CORRECTED][1] or values[CORRECTED][2]:
                problems.append('corrected sources not blocked at ' + where)
            if len(baselines) != 1 or not next(iter(baselines))[0]:
                problems.append('baselines not ready or disagreeing at ' + where)
        elif len({value[1:] for value in values.values()}) != 1:
            problems.append('readiness differs at %s: %s' % (where, {s: v[1:] for s, v in sorted(values.items())}))
    return problems


ARCHIVED_HOLDS = re.compile(r'holds=\[([^\]]*)\]')
ARCHIVED_THROWN = re.compile(r'^Exception in thread "main" ([\w.$]+)(?:: (.*))?$', re.M)


def archived_probe_facts(run):
    """What one finished probe run printed and threw. The hold set is sorted: the store's
    Set.copyOf keeps no iteration order."""
    def ordered(match):
        values = sorted(int(value) for value in match.group(1).split(',') if value.strip())
        return 'holds=[%s]' % ', '.join(str(value) for value in values)
    thrown = ARCHIVED_THROWN.search(run['stderr'])
    return {'returncode': run['returncode'],
            'lines': [ARCHIVED_HOLDS.sub(ordered, line) for line in run['stdout'].splitlines() if line],
            'exception': None if thrown is None else thrown.group(1) + ': ' + (thrown.group(2) or '')}


def archived_probe_verdict(facts, expected):
    """RED for a baseline that printed the expected observations and then failed by the probe's
    own assertion; REFUSED for corrected sources that printed the expected view and then refused
    at preparation, an observation only; otherwise UNEXPECTED."""
    if facts['returncode'] != 1 or facts['lines'] != expected['lines'] \
            or facts['exception'] != expected['exception']:
        return 'UNEXPECTED'
    return 'RED' if facts['exception'].startswith('java.lang.AssertionError: ') else 'REFUSED'


# ---------------------------------------------------------------- JVM builds, guarded

def suite_files(settings, names, override=None):
    """Sources of the current sources' side: its product with at most one mutant override, the
    history stubs, its NativeHistoryHarness filled with the current Settings text, the shared host
    support and adapter, and the named tests."""
    override = override or {}
    framework = {Path(path).stem: text for path, text in override.items() if path.startswith(FRAMEWORK_DIR)}
    files = b1.product_sources(framework_override=framework)
    if FACADE in override:
        files['stubs/com/android/server/pm/Settings.java'] = override[FACADE].encode()
    files.update(b2.history_stubs())
    files['tests/NativeHistoryHarness.java'] = b2.harness_source(settings, 'b2').encode()
    files.update(b1.test_sources(list(SUPPORT) + list(names), adapter='b1'))
    return files


def focused(work, settings, override=None):
    """The living focused suite on the current sources, with at most one mutant override."""
    return b1.outcome(b1.suite(work, suite_files(settings, [TEST], override), TEST), FOCUSED_NAMES)


# ---------------------------------------------------------------- the 24bfb6a archive
# The archive of this runner: the surface above, its sides, probes and parity. They read pinned Git
# objects only and run only archive code of the three runners, part of it copied from 24bfb6a and
# compared with it by tests; their expectations come from the frozen data and the pinned 24bfb6a
# predictions.

@b1.archived
def archived_suite_files(side, settings, names):
    """Sources of one archived side: the product of 0018a1d, 89491b9 or 24bfb6a, with the pinned
    24bfb6a history stubs, archived harness of that side's candidate Settings, support, adapter
    and named tests, as the 24bfb6a qualification compiled them."""
    if side not in ARCHIVED_SIDES:
        raise ValueError('not an archived side: %s' % side)
    files = b1.archived_product_sources(side)
    files.update(b2.archived_history_stubs())
    files['tests/NativeHistoryHarness.java'] = b2.archived_harness_source(
        settings, BASE_0018 if side == BASE_0018 else 'b2').encode()
    files.update(b2.archived_tests(list(ARCHIVED_SUPPORT) + list(names)))
    return files


@b1.archived
def archived_parity_files(side, settings):
    """One archived parity side: its suite sources with the pinned 24bfb6a parity driver."""
    files = archived_suite_files(side, settings, [])
    files['tests/NativeHistoryParity.java'] = b1.pinned_bytes(CORRECTED, b2.ARCHIVED_PARITY)
    return files


@b1.archived
def archived_inputs(settings):
    """Every archived input set of this runner, by leg, from each side's candidate Settings texts,
    assembled with the working tree closed."""
    legs = {}
    for side in ARCHIVED_SIDES:
        legs['focused ' + side] = archived_suite_files(side, settings[side], [ARCHIVED_TEST])
        legs['probes ' + side] = archived_suite_files(side, settings[side], list(PROBES))
    for side in (BASE_8949, CORRECTED):
        legs['parity ' + side] = archived_parity_files(side, settings[side])
    return legs


def archived_focused(work, side, settings):
    """The focused suite, frozen at 24bfb6a, on one archived side."""
    return b1.archived_outcome(b1.archived_suite(work, archived_suite_files(side, settings, [ARCHIVED_TEST]),
                                                 ARCHIVED_TEST), ARCHIVED_FOCUSED_NAMES)


def archived_probe_side(work, side, settings):
    work.mkdir(parents=True)
    built = b1.archived_build(work, archived_suite_files(side, settings, list(PROBES)))
    record = {'build': built}
    if built['returncode']:
        record['compile_failure'] = True
        return record
    for probe in PROBES:
        run = b1.archived_execute(work, probe, [str(work / ('state-' + probe))], timeout=300)
        record[probe] = {'run': run, 'facts': archived_probe_facts(run)}
    return record


def archived_parity_side(work, side, settings):
    files = archived_parity_files(side, settings)
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


@b1.archived
def archived_candidate_problems(built):
    """The archived 24bfb6a outputs against the 89491b9 profile: every output unchanged, except the
    later R0 boot literal of Settings and the patch, and only Settings changed against 0018a1d."""
    problems = []
    if built['changed'] != [b1.ARCHIVED_SETTINGS]:
        problems.append('framework targets of 24bfb6a changed against 0018a1d: %s' % built['changed'])
    old_profile = json.loads(b1.pinned_bytes(BASE_8949, b1.ARCHIVED_PROFILE))
    old_rows = {row['path']: row for row in old_profile['files']}
    for path, row in old_rows.items():
        if path != b1.ARCHIVED_SETTINGS and built['archived_outputs'].get(path) != row['candidate_sha256']:
            problems.append('24bfb6a framework output differs from 89491b9: ' + path)
    # R0 changed the boot literal alone: the 24bfb6a Settings with the earlier literal back is
    # 89491b9's candidate, and the 24bfb6a patch is 89491b9's with that one literal.
    current = built[CORRECTED]
    reverted = current.replace(b1.ARCHIVED_CONSTRUCTION + b1.ARCHIVED_PRODUCTION + ');',
                               b1.ARCHIVED_CONSTRUCTION + b1.ARCHIVED_RETIRED + ');', 1)
    if (reverted == current or b1.archived_r0_forward(reverted) != current
            or sha(reverted.encode()) != old_rows[b1.ARCHIVED_SETTINGS]['candidate_sha256']):
        problems.append('24bfb6a Settings output differs from 89491b9 beyond the R0 boot literal')
    old_patch = b1.pinned_bytes(BASE_8949, b1.ARCHIVED_PATCH)
    if (sha(old_patch) != old_profile['patch_sha256']
            or b1.archived_r0_forward(old_patch.decode()) != b1.pinned_bytes(CORRECTED, b1.ARCHIVED_PATCH).decode()):
        problems.append('24bfb6a patch differs from 89491b9 beyond the R0 boot literal')
    return problems


def archived_sides_phase(work, settings, steps, problems, progress):
    """The suite frozen at 24bfb6a on the pinned 0018a1d, 89491b9 and 24bfb6a sides: exactly the
    pinned predicted failures, then the same facts and readiness differences across them."""
    predictions = b1.archived_predictions('counter')
    steps['baselines'], runs = {}, {}
    for side in ARCHIVED_SIDES:
        result = archived_focused(work / ('baseline-' + side), side, settings[side])
        steps['baselines'][side] = result
        red = b2.archived_red_names(result, ARCHIVED_FOCUSED_NAMES)
        expected = set(predictions['fix']['focused_failures'] if side == CORRECTED
                       else predictions['baselines'][side]['focused_failures'])
        if red is None:
            problems.append('archived side %s is not a complete result' % side)
        elif red != expected:
            problems.append('archived side %s failures differ: unexpected %s, missing %s'
                            % (side, sorted(red - expected), sorted(expected - red)))
        if red is not None:
            runs[side] = result['run']['stdout']
        progress.write()
    if set(runs) == set(ARCHIVED_SIDES):
        try:
            compared = archived_compare_observations({side: archived_observations(text) for side, text in runs.items()},
                                            set(predictions['blocked_observations']))
        except ValueError as error:
            compared = ['observations: %s' % error]
        steps['baselines']['observation_problems'] = compared
        problems += compared
    else:
        problems.append('observations not compared: incomplete runs %s' % sorted(set(ARCHIVED_SIDES) - set(runs)))


def archived_probes_phase(work, settings, steps, problems, progress):
    """The primary's probes: red by their own assertion after the exact observations on both
    baselines, and refused at preparation on the pinned 24bfb6a side, which is no pass."""
    predictions = b1.archived_predictions('counter')
    steps['probes'] = {}
    for side in ARCHIVED_SIDES:
        record = archived_probe_side(work / ('probes-' + side), side, settings[side])
        steps['probes'][side] = record
        if record.get('compile_failure'):
            problems.append('probes did not compile on %s; not a red result' % side)
            continue
        for probe, expectation in predictions['probes'].items():
            expected = expectation['fix' if side == CORRECTED else 'baseline']
            verdict = archived_probe_verdict(record[probe]['facts'], expected)
            record[probe]['verdict'] = verdict
            if verdict != ('REFUSED' if side == CORRECTED else 'RED'):
                problems.append('probe %s on %s: %s' % (probe, side, verdict))
        progress.write()


def archived_parity_phase(work, settings, steps, problems, progress):
    """The B2 history parity layouts keep every counter at or above their IDs: the pinned 24bfb6a
    side prints exactly what 89491b9 prints."""
    old_record, old_text = archived_parity_side(work / 'parity-8949', BASE_8949, settings[BASE_8949])
    steps['parity'] = {BASE_8949: old_record}
    progress.write()
    new_record, new_text = archived_parity_side(work / 'parity-24bf', CORRECTED, settings[CORRECTED])
    steps['parity'][CORRECTED] = new_record
    if (old_text is None or new_text is None or old_record['run']['returncode']
            or new_record['run']['returncode']):
        problems.append('parity did not run')
    elif old_text != new_text:
        problems.append('parity with 89491b9 differs')


def candidates(pinned, scratch):
    """The current candidate Settings for the living focused suite and mutants, and the archived
    0018a1d and 24bfb6a candidates, with the problems: the archived 24bfb6a outputs against the
    89491b9 profile and the archived candidate checks of the B2 runner, beside its text checks of
    the current candidate."""
    built = b2.candidates(pinned, scratch)
    problems = archived_candidate_problems(built) + b2.candidate_problems(built)
    return built, problems


def qualify(work, pinned, progress):
    """Every guarded JVM step of this correction, in PHASES order before the B2 runner, each
    recorded into the shared report as it finishes. The caller has passed every guard. An
    exception stops the run where it is: what finished stays recorded, and nothing is retried."""
    report = progress.report
    steps, problems = report['steps'], report['problems']
    predictions = json.loads(PREDICTIONS.read_text())

    progress.begin('candidates')
    report['java'] = subprocess.run(['java', '-version'], capture_output=True, text=True,
                                    timeout=60).stderr.strip()
    (work / 'candidates').mkdir(parents=True)
    built, candidate_problems = candidates(pinned, work / 'candidates')
    steps['candidates'] = {'changed_against_0018': built['changed'], 'outputs': built['outputs'],
                           'archived_outputs': built['archived_outputs'], 'problems': candidate_problems}
    problems += candidate_problems
    # The archived sides fill their harnesses as the 24bfb6a qualification did: 0018a1d with its own
    # candidate, 89491b9 and 24bfb6a with the 24bfb6a candidate, whose harness texts 89491b9 shares.
    settings = {BASE_0018: built[BASE_0018], BASE_8949: built[CORRECTED], CORRECTED: built[CORRECTED],
                'fix': built['b2']}
    progress.done('candidates')

    # Living: the current sources, every case exactly once, all passing, exit status 0.
    progress.begin('focused')
    result = focused(work / 'focused', settings['fix'])
    steps['focused'] = result
    red = b2.red_names(result, FOCUSED_NAMES)
    if red != set():
        problems.append('focused matrix: %s' % ('not a complete result' if red is None else sorted(red)))
    elif 'unqualified' not in result['run']['stdout']:
        problems.append('focused scope statement missing')
    else:
        refused = b1.execute(work / 'focused', TEST, [str(work / 'focused' / 'state-da')],
                             assertions=False, timeout=120)
        steps['focused']['without_assertions'] = refused
        if not refused['returncode'] or '-ea' not in refused['stderr']:
            problems.append('focused suite ran without assertions')
    progress.done('focused')

    # Archived: the suite frozen at 24bfb6a on the pinned 0018a1d, 89491b9 and 24bfb6a sides, with
    # exactly the pinned predicted failures, then the same facts and readiness differences.
    progress.begin('baselines')
    archived_sides_phase(work, settings, steps, problems, progress)
    progress.done('baselines')

    # Archived: the primary's probes on the three pinned sides.
    progress.begin('probes')
    archived_probes_phase(work, settings, steps, problems, progress)
    progress.done('probes')

    # Archived: the pinned 24bfb6a side's parity outcomes are exactly 89491b9's.
    progress.begin('parity')
    archived_parity_phase(work, settings, steps, problems, progress)
    progress.done('parity')

    # Deliberate defects must compile and be caught by complete runs of the focused suite.
    progress.begin('mutants')
    steps['mutants'] = {}
    expectations = predictions['mutants_caught_at_least']
    for name, (path, text) in mutant_sources().items():
        result = focused(work / 'mutants' / name, settings['fix'], {path: text})
        record = {'focused': result}
        steps['mutants'][name] = record
        if 'error' in result:
            problems.append('mutant %s did not compile; not a red result' % name)
            continue
        red = b2.red_names(result, FOCUSED_NAMES)
        if red is None:
            problems.append('mutant %s run is not a complete result; its failures are not counted' % name)
            continue
        record['missed'] = sorted(set(expectations[name]) - red)
        record['failed'] = sorted(red)
        if record['missed'] or not red:
            problems.append('mutant %s not caught: %s' % (name, record['missed']))
        progress.write()
    report['labels'] = {step: list(STEP_LABELS[step]) for step in steps if step in STEP_LABELS}
    progress.done('mutants')


def b2_regression(work, pinned):
    """The B2 runner with its own guard, candidates, matrices, parity, readers, mutants and its
    nested B1 runner, which runs the B0 suites and every regression module. It writes under
    <work>/b2 and <work>/b2-evidence.json, except as the module docstring says."""
    evidence = work / 'b2-evidence.json'
    environment = dict(os.environ, TMPDIR=str(work / 'tmp'))
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/proof/native_creation_history.py'),
                             '--evidence', str(evidence), '--work', str(work / 'b2'),
                             '--pinned-framework', str(pinned)],
                            capture_output=True, text=True, timeout=5 * 3600, cwd=ROOT, env=environment)
    record = {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    if evidence.is_file():
        report = json.loads(evidence.read_text())
        record.update(status=report.get('status'), problems=report.get('problems'),
                      completed_phases=report.get('completed_phases'),
                      evidence_sha256=sha(evidence.read_bytes()))
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--work', type=Path,
                        help='fresh scratch directory outside the repository; a guarded run needs'
                             ' it to resolve to at most 29 ASCII characters, such as /srv/b3w')
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
            work = b2.fresh_outside(args.work, 'work directory')
            work.mkdir(parents=True)
            tempfile.tempdir = str(work)
            built, candidate_problems = candidates(args.pinned_framework.resolve(strict=True), work)
            report['candidate'] = {'changed_against_0018': built['changed'], 'outputs': built['outputs'],
                                   'archived_outputs': built['archived_outputs']}
            problems += candidate_problems
        report['status'] = 'FAIL' if problems else 'SOURCE_ONLY'
        report['problems'] = problems
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    if not (args.evidence and args.work and args.pinned_framework):
        parser.error('--evidence, --work and --pinned-framework are required for a guarded run')
    evidence = b2.fresh_outside(args.evidence, 'evidence path')
    work = b2.fresh_outside(args.work, 'work directory')
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
    progress = b2.Progress(report, work / 'progress.json')
    try:
        qualify(work / 'b3', pinned, progress)
        progress.begin('b2 runner')
        report['b2_runner'] = b2_regression(work, pinned)
        if report['b2_runner']['returncode'] or report['b2_runner'].get('status') != 'PASS':
            problems.append('B2 runner regression')
        progress.done('b2 runner')
        report['status'] = 'FAIL' if problems else 'PASS'
    except Exception as error:
        report['exception'] = b2.exception_record(error)
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
