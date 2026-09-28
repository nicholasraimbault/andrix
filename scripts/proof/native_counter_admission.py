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
every finished record and its NOT_COMPLETE status; nothing is retried.
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
SETTINGS = b2.SETTINGS
PREDICTIONS = ROOT / 'scripts/proof/native_counter_admission_predictions.json'
TEST = 'NativeCounterAdmissionTest'
SUPPORT = ('NativeHeaderTestSupport', 'NativeBindingTestSupport')
B1_TEST = PLATFORM + 'NativeCreationBindingTest.java'
PROFILE_PATH = 'patches/grapheneos-2026081300/native-principal-pins.json'
# The primary's two read only probes, copied verbatim. They inform the matrix; their refusal on
# the corrected sources is an observation, never a pass. The focused suite asserts the refusal.
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
b1.BASELINE_SHA256[BASE_8949] = dict(BASELINE_8949)
SIDES = (BASE_0018, BASE_8949, 'fix')
# Every guarded phase in order. A run reports those it completed and those it did not.
PHASES = ('candidates', 'focused', 'baselines', 'probes', 'parity', 'mutants', 'b2 runner')

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

# The correction's code, comments aside, and the 89491b9 code it replaces. The surface check
# requires the Store to differ from 89491b9 by exactly these, so no other rule changed.
RULE_NEW = '''
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
RULE_OLD = '''
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                if (entry.getValue().status != Status.UNSUPPORTED
                        && !entry.getValue().unavailable
                        && !bindingConflicts.contains(entry.getKey())) continue;
                for (Slot copy : entry.getValue().decodedCopies) {
                    packages.putIfAbsent(copy.packageName, entry.getKey());
'''
HELPER = '''
    private static boolean claimsAbove(Slot copy, long counter) {
        for (UserEntry user : copy.users) {
            if (user.id > counter) return true;
        }
        return false;
    }
'''
# The one intentional B1 expectation change: only this readiness check of the mismatch loop.
B1_NEW = '''
                boolean ready = !body.getKey().equals("two users");
                check(problems, read != null && read.status != Status.VALID && !loaded.bindingUsable(R)
                        && loaded.occupiedAppIds.contains(R) && loaded.creationReady() == ready,
                        "load " + (read == null ? null : read.status) + " ready " + loaded.creationReady());
'''
B1_OLD = '''
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

def normalized(text):
    """Java code with comments removed and every whitespace run one space."""
    return ' '.join(b1.strip_java_comments(text).split())


def code(text):
    return ' '.join(text.split())


def store_problems(current, base):
    """Whether the Store's code, comments aside, differs from the base by exactly the rule and
    its helper. Pure."""
    current, before = normalized(current), normalized(base)
    new, old, helper = code(RULE_NEW), code(RULE_OLD), code(HELPER)
    if current.count(new) != 1 or current.count(helper) != 1 or before.count(old) != 1:
        return ['Store rule or helper anchor drift']
    if code(current.replace(new, old).replace(helper, '')) != before:
        return ['Store code changed beyond the counter admission rule']
    return []


def b1_test_problems(current, base):
    """Whether the B1 suite, comments aside, differs from the base by exactly the one readiness
    check. Pure."""
    new, old = B1_NEW.strip('\n'), B1_OLD.strip('\n')
    if current.count(new) != 1 or base.count(old) != 1:
        return ['B1 readiness revision anchor drift']
    if normalized(current.replace(new, old)) != normalized(base):
        return ['B1 suite changed beyond the two users readiness check']
    return []


def surface_violations():
    """The correction's surface: only the Store's code changed among the product sources, by the
    one rule and its helper; the patch, facade, fragments and other framework sources are the
    89491b9 bytes; the profile differs only by the Store's hash; and the B1 suite changed only
    its one incidental readiness check."""
    problems = []
    for name, digest in BASELINE_8949.items():
        path = FACADE if name == 'Settings' else FRAMEWORK_DIR + name + '.java'
        if name != 'NativeIdentityStore' and sha((ROOT / path).read_bytes()) != digest:
            problems.append('%s differs from 89491b9' % name)
    base = b1.git_bytes(REVISION_8949, STORE).decode()
    if sha(base.encode()) != BASELINE_8949['NativeIdentityStore']:
        problems.append('89491b9 Store object drift')
    problems += store_problems((ROOT / STORE).read_text(), base)
    old_profile = json.loads(b1.git_bytes(REVISION_8949, PROFILE_PATH))
    profile = json.loads((ROOT / PROFILE_PATH).read_text())
    store_row = integration.PREFIX + 'NativeIdentityStore.java'
    for key in set(old_profile) | set(profile):
        if key == 'added':
            continue
        if old_profile.get(key) != profile.get(key):
            problems.append('profile %s differs from 89491b9' % key)
    old_added = {row['path']: row for row in old_profile.get('added', [])}
    for row in profile.get('added', []):
        prior = old_added.get(row['path'])
        if prior is None or (row['path'] != store_row and row != prior):
            problems.append('profile added row changed: ' + row['path'])
        elif row['path'] == store_row and (row['source'] != prior['source']
                                           or row['sha256'] != sha((ROOT / STORE).read_bytes())):
            problems.append('profile Store row is not the regenerated Store hash')
    if [row['path'] for row in profile.get('added', [])] != list(old_added):
        problems.append('profile added rows reordered')
    for name, (_, fragment) in integration.FRAGMENTS.items():
        relative = fragment.relative_to(ROOT).as_posix()
        if fragment.read_bytes() != b1.git_bytes(REVISION_8949, relative):
            problems.append('fragment differs from 89491b9: ' + name)
    problems += b1_test_problems((ROOT / B1_TEST).read_text(),
                                 b1.git_bytes(REVISION_8949, B1_TEST).decode())
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
        problems += surface_violations()
    except (OSError, ValueError, KeyError) as error:
        problems.append('surface: %s' % error)
    for name, digest in PROBES.items():
        if sha((ROOT / PLATFORM / (name + '.java')).read_bytes()) != digest:
            problems.append('probe differs from the primary probe: ' + name)
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
    for side in (BASE_0018, BASE_8949):
        if not set(predictions['baselines'][side]['focused_failures']) <= names:
            problems.append('baseline prediction inconsistent: ' + side)
    for label in predictions['blocked_observations']:
        if '"%s"' % label not in source:
            problems.append('blocked observation label not in the suite: ' + label)
    if set(predictions['probes']) != set(PROBES):
        problems.append('probe predictions do not list every probe')
    try:
        b2.presence_tail()
    except (OSError, ValueError) as error:
        problems.append('work path budget: %s' % error)
    return problems


# ---------------------------------------------------------------- run comparison, pure

def observations(stdout):
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


def compare_observations(sides, blocked):
    """Problems of the three sides' observations. Every side reports the same layouts with the
    same facts. Readiness differs only at the predicted blocked labels, where the corrected
    sources are neither ready nor restorable and both baselines are ready and agree."""
    problems = []
    keys = set(sides['fix'])
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
        baselines = {value[1:] for side, value in values.items() if side != 'fix'}
        if key[0] in blocked:
            if values['fix'][1] or values['fix'][2]:
                problems.append('corrected sources not blocked at ' + where)
            if len(baselines) != 1 or not next(iter(baselines))[0]:
                problems.append('baselines not ready or disagreeing at ' + where)
        elif len({value[1:] for value in values.values()}) != 1:
            problems.append('readiness differs at %s: %s' % (where, {s: v[1:] for s, v in sorted(values.items())}))
    return problems


_HOLDS = re.compile(r'holds=\[([^\]]*)\]')
_THROWN = re.compile(r'^Exception in thread "main" ([\w.$]+)(?:: (.*))?$', re.M)


def probe_facts(run):
    """What one finished probe run printed and threw. The hold set is sorted: the store's
    Set.copyOf keeps no iteration order."""
    def ordered(match):
        values = sorted(int(value) for value in match.group(1).split(',') if value.strip())
        return 'holds=[%s]' % ', '.join(str(value) for value in values)
    thrown = _THROWN.search(run['stderr'])
    return {'returncode': run['returncode'],
            'lines': [_HOLDS.sub(ordered, line) for line in run['stdout'].splitlines() if line],
            'exception': None if thrown is None else thrown.group(1) + ': ' + (thrown.group(2) or '')}


def probe_verdict(facts, expected):
    """RED for a baseline that printed the expected observations and then failed by the probe's
    own assertion; REFUSED for corrected sources that printed the expected view and then refused
    at preparation, an observation only; otherwise UNEXPECTED."""
    if facts['returncode'] != 1 or facts['lines'] != expected['lines'] \
            or facts['exception'] != expected['exception']:
        return 'UNEXPECTED'
    return 'RED' if facts['exception'].startswith('java.lang.AssertionError: ') else 'REFUSED'


# ---------------------------------------------------------------- JVM builds, guarded

def suite_files(side, settings, names, override=None):
    """Sources of one side: its product, the history stubs, its own NativeHistoryHarness filled
    with its own Settings text, the shared host support and adapter, and the named tests. The
    corrected side is the worktree with at most one mutant override. The baselines are exact Git
    objects of 0018a1d and 89491b9."""
    override = override or {}
    if side == 'fix':
        framework = {Path(path).stem: text for path, text in override.items()
                     if path.startswith(FRAMEWORK_DIR)}
        files = b1.product_sources(framework_override=framework)
        if FACADE in override:
            files['stubs/com/android/server/pm/Settings.java'] = override[FACADE].encode()
    else:
        if override:
            raise ValueError('mutants apply to the corrected sources only')
        files = b1.product_sources(side)
    files.update(b2.history_stubs())
    harness_side = BASE_0018 if side == BASE_0018 else 'b2'
    files['tests/NativeHistoryHarness.java'] = b2.harness_source(settings, harness_side).encode()
    files.update(b1.test_sources(list(SUPPORT) + list(names), adapter='b1'))
    return files


def focused(work, side, settings, override=None):
    return b1.outcome(b1.suite(work, suite_files(side, settings, [TEST], override), TEST), FOCUSED_NAMES)


def probe_side(work, side, settings):
    work.mkdir(parents=True)
    built = b1.build(work, suite_files(side, settings, list(PROBES)))
    record = {'build': built}
    if built['returncode']:
        record['compile_failure'] = True
        return record
    for probe in PROBES:
        run = b1.execute(work, probe, [str(work / ('state-' + probe))], timeout=300)
        record[probe] = {'run': run, 'facts': probe_facts(run)}
    return record


def parity_side(work, side, settings):
    files = suite_files(side, settings, [])
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


def candidates(pinned, scratch):
    """The corrected and 0018a1d candidate Settings from the pinned canonical framework copies,
    and the problems of the ten outputs against the 89491b9 profile: every output unchanged."""
    built = b2.candidates(pinned, scratch)
    problems = []
    if built['changed'] != [SETTINGS]:
        problems.append('framework targets changed against 0018a1d: %s' % built['changed'])
    old_profile = json.loads(b1.git_bytes(REVISION_8949, PROFILE_PATH))
    for row in old_profile['files']:
        if built['outputs'].get(row['path']) != row['candidate_sha256']:
            problems.append('framework output differs from 89491b9: ' + row['path'])
    if sha(integration.PATCH.read_bytes()) != old_profile['patch_sha256']:
        problems.append('patch differs from 89491b9')
    problems += b2.b2_text_checks(built['b2'])
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
                           'problems': candidate_problems}
    problems += candidate_problems
    settings = {BASE_0018: built[BASE_0018], BASE_8949: built['b2'], 'fix': built['b2']}
    progress.done('candidates')

    # The corrected sources: every case exactly once, all passing, exit status 0.
    progress.begin('focused')
    runs = {}
    result = focused(work / 'focused', 'fix', settings['fix'])
    steps['focused'] = result
    red = b2.red_names(result, FOCUSED_NAMES)
    if red is not None:
        runs['fix'] = result['run']['stdout']
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

    # The same suite on 0018a1d and 89491b9: exactly the predicted failures, then the same facts
    # and readiness differences across the three sides.
    progress.begin('baselines')
    steps['baselines'] = {}
    for side in (BASE_0018, BASE_8949):
        result = focused(work / ('baseline-' + side), side, settings[side])
        steps['baselines'][side] = result
        red = b2.red_names(result, FOCUSED_NAMES)
        expected = set(predictions['baselines'][side]['focused_failures'])
        if red is None:
            problems.append('baseline %s is not a complete result' % side)
        elif red != expected:
            problems.append('baseline %s failures differ: unexpected %s, missing %s'
                            % (side, sorted(red - expected), sorted(expected - red)))
        if red is not None:
            runs[side] = result['run']['stdout']
        progress.write()
    if set(runs) == set(SIDES):
        try:
            compared = compare_observations({side: observations(text) for side, text in runs.items()},
                                            set(predictions['blocked_observations']))
        except ValueError as error:
            compared = ['observations: %s' % error]
        steps['baselines']['observation_problems'] = compared
        problems += compared
    else:
        problems.append('observations not compared: incomplete runs %s' % sorted(set(SIDES) - set(runs)))
    progress.done('baselines')

    # The primary's probes: red by their own assertion after the exact observations on both
    # baselines, and refused at preparation on the corrected sources, which is no pass.
    progress.begin('probes')
    steps['probes'] = {}
    for side in SIDES:
        record = probe_side(work / ('probes-' + side), side, settings[side])
        steps['probes'][side] = record
        if record.get('compile_failure'):
            problems.append('probes did not compile on %s; not a red result' % side)
            continue
        for probe, expectation in predictions['probes'].items():
            expected = expectation['fix' if side == 'fix' else 'baseline']
            verdict = probe_verdict(record[probe]['facts'], expected)
            record[probe]['verdict'] = verdict
            if verdict != ('REFUSED' if side == 'fix' else 'RED'):
                problems.append('probe %s on %s: %s' % (probe, side, verdict))
        progress.write()
    progress.done('probes')

    # The B2 history parity layouts keep every counter at or above their IDs: the corrected
    # sources print exactly what 89491b9 prints.
    progress.begin('parity')
    old_record, old_text = parity_side(work / 'parity-8949', BASE_8949, settings[BASE_8949])
    steps['parity'] = {BASE_8949: old_record}
    progress.write()
    new_record, new_text = parity_side(work / 'parity-fix', 'fix', settings['fix'])
    steps['parity']['fix'] = new_record
    if (old_text is None or new_text is None or old_record['run']['returncode']
            or new_record['run']['returncode']):
        problems.append('parity did not run')
    elif old_text != new_text:
        problems.append('parity with 89491b9 differs')
    progress.done('parity')

    # Deliberate defects must compile and be caught by complete runs of the focused suite.
    progress.begin('mutants')
    steps['mutants'] = {}
    expectations = predictions['mutants_caught_at_least']
    for name, (path, text) in mutant_sources().items():
        result = focused(work / 'mutants' / name, 'fix', settings['fix'], {path: text})
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
            work = b2.fresh_outside(args.work, 'work directory')
            work.mkdir(parents=True)
            tempfile.tempdir = str(work)
            built, candidate_problems = candidates(args.pinned_framework.resolve(strict=True), work)
            report['candidate'] = {'changed_against_0018': built['changed'], 'outputs': built['outputs']}
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
