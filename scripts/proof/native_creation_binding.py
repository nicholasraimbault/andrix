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
             'd104': 'd104e15bae58a74dbba6e3c3325a93f216773667'}
# Exact baseline inputs taken from Git objects. Only these two revisions are compared.
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
}
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
    'binding-conflict-evidence-dropped': (STORE, ((
        '                        && !entry.getValue().unavailable\n'
        '                        && !bindingConflicts.contains(entry.getKey())) continue;',
        '                        && !entry.getValue().unavailable) continue;'),), ('focused',)),
    # Every CONFLICT record becomes evidence, so an ordinary unbound conflict alone withdraws a
    # sibling that version 1 keeps usable.
    'binding-conflict-evidence-every-conflict': (STORE, ((
        '                        && !bindingConflicts.contains(entry.getKey())) continue;',
        '                        && entry.getValue().status != Status.CONFLICT) continue;'),), ('focused',)),
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


def production_texts():
    """Every production Java text: framework sources, added patch lines and the lab fixture."""
    texts = {path.relative_to(ROOT).as_posix(): path.read_text()
             for path in sorted((ROOT / FRAMEWORK_DIR).glob('*.java'))}
    for patch in sorted((ROOT / 'patches').rglob('*.patch')):
        texts[patch.relative_to(ROOT).as_posix()] = added_java(patch.read_text())
    fixture = ROOT / 'tests/native-identity/writer/NativePrincipalWriterFixture.java'
    texts[fixture.relative_to(ROOT).as_posix()] = fixture.read_text()
    return texts


def format_violations(texts):
    """Production store construction and format selection. Every construction names the
    literal production format V1, and nothing selects a format by value or reflection. The
    enum's own constants are not construction sites."""
    problems, sites = [], []
    for name, raw in texts.items():
        text = strip_java_comments(raw)
        for match in re.finditer(r'new\s+NativeIdentityStore\s*\(', text):
            depth, j = 1, match.end()
            while depth and j < len(text):
                depth += {'(': 1, ')': -1}.get(text[j], 0)
                j += 1
            arguments = re.sub(r'\s+', ' ', text[match.end():j - 1]).strip()
            sites.append((name, arguments))
            if not arguments.endswith(', NativeIdentityStore.Format.V1'):
                problems.append('%s constructs a store with %s' % (name, arguments))
        for pattern in (r'\bFormat\s*\.\s*valueOf\b', r'\bFormat\s*\.\s*values\s*\(',
                        r'\bEnum\s*\.\s*valueOf\b', r'\bFormat\s*\.\s*V2\b',
                        r'\bFormat\s*\.\s*class\b', r'getEnumConstants'):
            for found in re.finditer(pattern, text):
                problems.append('%s selects a store format: %s' % (name, found.group(0)))
    if len(sites) != 1 or not sites[0][0].endswith('native-principal-pins.patch'):
        problems.append('production construction sites %s' % sites)
    return problems


def surface_violations():
    """The B1 production surface: no Snapshot overload beside plans, one fixed format, and the
    encoder's own byte measure."""
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
    if (len(re.findall(r'\benum\s+Format\b', store)) != 1
            or not re.search(r'\benum\s+Format\s*\{\s*V1\(1,\s*1\),\s*V2\(2,\s*2\);', store)):
        problems.append('store format enum is not exactly V1(1, 1) and V2(2, 2)')
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


def guard_mutants():
    """Production format selection defects the pure guard must report."""
    texts = production_texts()
    patch = 'patches/grapheneos-2026081300/native-principal-pins.patch'
    v2 = dict(texts)
    v2[patch] = replace_once(texts[patch], 'NativeIdentityStore.Format.V1);',
                             'NativeIdentityStore.Format.V2);')
    value_of = dict(texts)
    value_of[patch] = replace_once(texts[patch], 'NativeIdentityStore.Format.V1);',
                                   'NativeIdentityStore.Format.valueOf(android.os.SystemProperties.get('
                                   '"persist.andrix.native_format", "V1")));')
    framework = dict(texts)
    persistence = FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
    framework[persistence] = replace_once(texts[persistence], '    NativeIdentityPersistence(NativeIdentityStore store) {\n',
                                          '    static NativeIdentityPersistence host(java.io.File root) {\n'
                                          '        return new NativeIdentityPersistence(new NativeIdentityStore(root,\n'
                                          '                NativeIdentityStore.Format.V2));\n    }\n\n'
                                          '    NativeIdentityPersistence(NativeIdentityStore store) {\n')
    return {'production-v2-construction': v2, 'production-format-value-of': value_of,
            'framework-v2-construction': framework}


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
    problems = format_violations(production_texts()) + surface_violations()
    for name, texts in guard_mutants().items():
        if not format_violations(texts):
            problems.append('guard missed ' + name)
    # Each anchor must exist exactly once in the current sources, or this raises.
    mutant_sources()
    b0.mutants()
    admission = integration.FRAGMENTS['admission'][1].read_bytes()
    facade = (ROOT / PLATFORM / 'native_principal_stubs/com/android/server/pm/Settings.java').read_bytes()
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

    # Version 2 layouts from the host writer, read by B1's V1 format and by c9264e4.
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
        for target, baseline, adapter in (('b1-v1', None, 'b1'), ('c926', 'c926', 'baseline')):
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
