#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact optional lab native store format. Normal framework admission refuses this adaptation.

The lab profile and patch live under tests, outside the production patch directory. The patch
changes exactly one byte of the exact adapted B2 Settings: the literal production Format.V1 of
the boot store construction becomes Format.V2. It is recognized only as its own state,
LAB_FORMAT_V2, never as ordinary ADAPTED.

One decision, require_admission, admits that state, and only with explicit lab history admission
over the complete lab stack: every other native principal file exactly adapted, the exact adapted
writer fixture, the owner lifecycle CE companion adapted, and package verity with its payload sync
companion adapted. Every other inspection refuses it, including the writer tool's own lab
admission. A partial stack refuses every inspection, check, apply and revert. Recovering from one
is a reviewed manual checkout repair; there is no automatic force.

Apply after the normal CE, package verity, payload sync and native principal companions and then
the writer fixture. Reverse this format first, while every companion is still complete, before
the writer fixture and the native and payload companions. Producer liveness is not detected:
retiring the build producer before apply or revert, and admitting any effects, are caller
preconditions. This tool does not enable native execution, a factory, an initializer, retirement
or release, and it qualifies nothing at runtime.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import tempfile

import native_identity_writer as writer
import native_principal_pins as integration

ROOT = Path(__file__).resolve().parents[2]
PROJECT = integration.PROJECT
HEAD = integration.HEAD
FILE = integration.PREFIX + 'Settings.java'
DIRECTORY = ROOT / 'tests/native-identity/lab-history'
PROFILE = DIRECTORY / 'native-store-format-v2.json'
PATCH = DIRECTORY / 'native-store-format-v2.patch'
STATE = 'LAB_FORMAT_V2'
ABSENT = 'ABSENT'
KEYS = {'version', 'project', 'head', 'lab_only', 'native_execution_enabled', 'format',
        'production_format', 'state', 'patch_sha256', 'file', 'requires', 'subject', 'order',
        'scope'}
FILE_KEYS = {'path', 'method', 'upstream_sha256', 'input_sha256', 'output_sha256'}
APPLY_ORDER = ['owner-lifecycle', 'package-verity', 'package-installer-payload-sync',
               'native-principal-pins', 'native-identity-writer', 'native-store-format-v2']
REVERT_ORDER = ['native-store-format-v2', 'native-identity-writer', 'native-principal-pins',
                'package-installer-payload-sync']
# The one boot construction of the adapted Settings and its literal production format.
METHOD = b'    NativeIdentityStore.Loaded readNativeIdentityStoreForBoot() {\n'
CONSTRUCTION = (b'        mNativeIdentityStore = new NativeIdentityStore(\n'
                b'                new File(Environment.getDataSystemDirectory(), "native-principals"),\n'
                b'                ')
BOOT_END = b'        mNativeIdentityPersistence = new NativeIdentityPersistence(mNativeIdentityStore);\n'
PRODUCTION = b'NativeIdentityStore.Format.V1);'
LAB = b'NativeIdentityStore.Format.V2);'
# Value, property, reflection and enum based selection. The lab token is none of these.
SELECTORS = (rb'\bFormat\s*\.\s*valueOf\b', rb'\bFormat\s*\.\s*values\s*\(', rb'\bEnum\s*\.\s*valueOf\b',
             rb'\bFormat\s*\.\s*class\b', rb'getEnumConstants', rb'SystemProperties', rb'\bSettings\.Global\b',
             rb'java\.lang\.reflect', rb'\.forName\(', rb'\.getDeclared', rb'setAccessible\(')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate lab format profile key')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('non-finite lab format profile value')


def relative(path):
    return path.relative_to(ROOT).as_posix()


def subject_constants(text):
    """The fixed subject, development signer, version and user the unchanged helper selects."""
    found = {'package': re.findall(r'^    private static final String SUBJECT = "([^"\n]*)";$', text, re.M),
             'signer_sha256': re.findall(r'^    private static final String FIXTURE_SIGNER =\n'
                                         r'            "([0-9a-f]{64})";$', text, re.M),
             'version_code': re.findall(r'\bchosen\.versionCode != ([0-9]+)\b', text),
             'user_id': re.findall(r'\bchosen\.userId != ([0-9]+)\b', text)}
    if any(len(values) != 1 for values in found.values()) or text.count('Set.of(FIXTURE_SIGNER)') != 1:
        raise ValueError('writer fixture subject constants are not exact')
    return {'package': found['package'][0], 'signer_sha256': found['signer_sha256'][0],
            'version_code': int(found['version_code'][0]), 'user_id': int(found['user_id'][0])}


def patch_change(text):
    """The one hunk of the lab patch: one removed and one added line, the literal format token."""
    lines = text.split('\n')
    if lines[-1] != '' or any('\r' in line for line in lines):
        raise ValueError('lab format patch framing')
    lines = lines[:-1]
    if (lines[:2] != ['--- a/' + FILE, '+++ b/' + FILE]
            or re.findall(r'^(?:---|\+\+\+) (.+)$', text, re.M) != ['a/' + FILE, 'b/' + FILE]):
        raise ValueError('lab format patch scope')
    header = re.fullmatch(r'@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9]+) @@', lines[2] if len(lines) > 2 else '')
    body = lines[3:]
    if (header is None or any(line.startswith('@@') for line in body)
            or header.group(1) != header.group(3) or header.group(2) != header.group(4)
            or len(body) != int(header.group(2)) + 1
            or any(line[:1] not in (' ', '-', '+') for line in body)):
        raise ValueError('lab format patch is not one exact hunk')
    removed = [index for index, line in enumerate(body) if line.startswith('-')]
    added = [index for index, line in enumerate(body) if line.startswith('+')]
    construction = CONSTRUCTION.decode().split('\n')
    if (len(removed) != 1 or len(added) != 1 or added[0] != removed[0] + 1
            or body[removed[0]] != '-' + construction[2] + PRODUCTION.decode()
            or body[added[0]] != '+' + construction[2] + LAB.decode()
            or removed[0] < 2 or body[removed[0] - 2] != ' ' + construction[0]
            or body[removed[0] - 1] != ' ' + construction[1]):
        raise ValueError('lab format patch changes more than the one format token')
    return body[removed[0]], body[added[0]]


def require_location():
    """The lab inputs stay in their test directory, outside the production patch directory, by
    location and never by name alone. The production format guard scans that directory and must
    refuse a copy of this patch there."""
    for path in (PROFILE, PATCH):
        if (path.is_symlink() or path.resolve() != path or path.parent != DIRECTORY
                or ROOT / 'tests' not in path.parents or ROOT / 'patches' in path.parents):
            raise ValueError('lab format inputs must stay outside the production patches')


def profile():
    """Validated lab profile over the current normal native profile and the exact writer fixture.

    The whole native profile is validated, with every source hash it requires, but only its
    Settings pins are pinned here. A Store only correction keeps the lab format admissible.
    """
    require_location()
    value = json.loads(PROFILE.read_text(), object_pairs_hook=unique, parse_constant=invalid_constant)
    native = integration.profile()
    required_writer = writer.profile()
    rows = [row for row in native['files'] if row['path'] == FILE]
    helper = writer.HELPER.read_bytes()
    if (type(value) is not dict or set(value) != KEYS or type(value['version']) is not int
            or value['version'] != 1 or value['project'] != PROJECT or value['head'] != HEAD
            or native['head'] != HEAD or required_writer['head'] != HEAD
            or value['lab_only'] is not True or value['native_execution_enabled'] is not False
            or value['format'] != 'V2' or value['production_format'] != 'V1' or value['state'] != STATE
            or value['patch_sha256'] != sha(PATCH.read_bytes()) or len(rows) != 1
            or type(value['file']) is not dict or set(value['file']) != FILE_KEYS
            or value['file']['path'] != FILE or value['file']['method'] != 'readNativeIdentityStoreForBoot'
            or value['file']['upstream_sha256'] != rows[0]['upstream_sha256']
            or value['file']['input_sha256'] != rows[0]['candidate_sha256']
            or type(value['file']['output_sha256']) is not str
            or not re.fullmatch(r'[0-9a-f]{64}', value['file']['output_sha256'])
            or value['file']['output_sha256'] in (rows[0]['upstream_sha256'], rows[0]['candidate_sha256'])):
        raise ValueError('lab format profile drift')
    if (value['requires'] != {'native_profile': relative(integration.PROFILE),
                              'writer_profile': relative(writer.PROFILE),
                              'writer_profile_sha256': sha(writer.PROFILE.read_bytes()),
                              'writer_helper': relative(writer.HELPER),
                              'writer_helper_sha256': sha(helper)}
            or required_writer['added']['sha256'] != sha(helper)
            or required_writer['lab_only'] is not True
            or required_writer['native_execution_enabled'] is not False):
        raise ValueError('lab format requires the exact writer fixture')
    subject = value['subject']
    if (type(subject) is not dict or type(subject.get('version_code')) is not int
            or type(subject.get('user_id')) is not int or subject != subject_constants(helper.decode())):
        raise ValueError('lab format subject differs from the writer fixture')
    if value['order'] != {'apply': APPLY_ORDER, 'revert': REVERT_ORDER}:
        raise ValueError('lab format order drift')
    patch_change(PATCH.read_text())
    return value


def patched(data, patch=None):
    """Apply one exact single file patch forward in private scratch, never in a checkout."""
    patch = PATCH if patch is None else patch
    with tempfile.TemporaryDirectory(prefix='andrix-lab-format-') as directory:
        scratch = Path(directory)
        target = scratch / FILE
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        try:
            result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
                                     '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                                    cwd=scratch, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            # A missing tool or a timeout refuses like a failed patch. There is no fallback.
            raise ValueError('exact lab format patch unavailable: ' + type(error).__name__) from error
        if result.returncode:
            raise ValueError('exact lab format patch failed: ' + result.stderr.decode(errors='replace'))
        if ({p.relative_to(scratch).as_posix() for p in scratch.rglob('*') if p.is_file()} != {FILE}
                or any(p.is_symlink() for p in scratch.rglob('*'))):
            raise ValueError('unexpected lab format patch output')
        return target.read_bytes()


def one_token(before, after):
    """Pure proof that after is before with only the boot construction's format literal changed."""
    if type(before) is not bytes or type(after) is not bytes or len(before) != len(after):
        raise ValueError('lab format must keep every other byte')
    changed = [index for index, (old, new) in enumerate(zip(before, after)) if old != new]
    if len(changed) != 1:
        raise ValueError('lab format changes %d bytes, not its one token' % len(changed))
    token = before.find(PRODUCTION)
    position = token + PRODUCTION.index(b'1')
    if (before.count(PRODUCTION) != 1 or after.count(LAB) != 1 or changed[0] != position
            or before.count(b'Format.V2') or after.count(b'Format.V1') or after.find(LAB) != token):
        raise ValueError('lab format change is not the one production format literal')
    start = before.find(METHOD)
    site = before.find(CONSTRUCTION + PRODUCTION)
    end = before.find(BOOT_END, max(start, 0))
    if (before.count(METHOD) != 1 or before.count(CONSTRUCTION + PRODUCTION) != 1
            or before.count(b'new NativeIdentityStore(') != 1 or after.count(b'new NativeIdentityStore(') != 1
            or not start < site < end or site + len(CONSTRUCTION) != token):
        raise ValueError('lab format token is outside the boot store construction')
    for pattern in SELECTORS:
        if len(re.findall(pattern, before)) != len(re.findall(pattern, after)):
            raise ValueError('lab format introduces a format selector')
    return position


def candidate(adapted, value=None):
    """The exact lab Settings from the exact adapted B2 Settings. Reads no checkout."""
    value = profile() if value is None else value
    if type(adapted) is not bytes or sha(adapted) != value['file']['input_sha256']:
        raise ValueError('lab format requires the exact adapted B2 Settings')
    output = patched(adapted)
    if sha(output) != value['file']['output_sha256']:
        raise ValueError('lab format candidate differs')
    one_token(adapted, output)
    return output


def stack_problems(ce_state, package, native_state, writer_state):
    """The one definition of the complete lab stack, as the parts it still lacks.

    native_state is the native companion's state with this format in place. Every part is
    required: nothing here is relaxed for a check, an apply or a revert.
    """
    problems = []
    if native_state != STATE:
        problems.append('the complete native principal companion')
    if writer_state != 'ADAPTED':
        problems.append('the exact adapted writer fixture')
    if ce_state != 'ADAPTED':
        problems.append('the owner lifecycle CE companion')
    if package['state'] != 'ADAPTED' or package['payload_sync_companion']['state'] != 'ADAPTED':
        problems.append('package verity with its payload sync companion')
    return problems


def require_admission(ce_state, package, native, writer_result, lab_native_format=False):
    """The shared fence's one decision for this state. Returns LAB_FORMAT_V2 or ABSENT.

    Without the lab Settings state this returns ABSENT at once, before any companion detail is
    read. With it, only explicit lab history admission over the complete lab stack admits it.
    Normal admission, including the writer tool's own lab admission, always refuses it. A partial
    stack refuses every inspection, so no check, apply or revert can proceed over it.
    """
    if native['files'][FILE] != STATE:
        return ABSENT
    if lab_native_format is not True:
        raise ValueError('lab native store format V2 requires explicit lab history admission;'
                         ' reverse it before any normal build, check or revert')
    problems = stack_problems(ce_state, package, native['state'], writer_result['state'])
    if problems:
        raise ValueError('lab native store format requires the complete lab stack: ' + ', '.join(problems))
    return STATE


def inspect(root):
    """The shared fence under explicit lab history admission, then this format's exact bytes."""
    import android_lifecycle
    project, _, _, fence = android_lifecycle.inspect_lab_native_format(root)
    value = profile()
    _, native_target, native = integration.inspect_files(project)
    adapted = native_target[FILE]
    lab = candidate(adapted, value)
    package = fence['package_verity_companion']
    result = {
        'project': PROJECT, 'head': HEAD, 'file': FILE, 'state': fence['lab_native_format'],
        'settings_state': native['files'][FILE], 'format': 'V2', 'production_format': 'V1',
        'lab_only': True, 'native_execution_enabled': False, 'runtime_qualified': False,
        'profile_sha256': sha(PROFILE.read_bytes()), 'patch_sha256': value['patch_sha256'],
        'input_sha256': value['file']['input_sha256'], 'output_sha256': value['file']['output_sha256'],
        'native_principal_pins_profile_sha256': native['profile_sha256'],
        'writer_profile_sha256': value['requires']['writer_profile_sha256'],
        'companions': {'owner-lifecycle': fence['state'], 'package-verity': package['state'],
                       'package-installer-payload-sync': package['payload_sync_companion']['state'],
                       'native-principal-pins': native['state'],
                       'native-identity-writer': fence['native_identity_writer_companion']['state']},
        'order': value['order']}
    if result['state'] != (STATE if native['files'][FILE] == STATE else ABSENT):
        raise ValueError('lab format views disagree')
    return project, adapted, lab, result, fence


def main():
    import android_lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--action', choices=('check', 'apply', 'revert'), default='check')
    parser.add_argument('--lab-history-format', action='store_true',
                        help='explicit lab history admission; required for every action')
    parser.add_argument('--require-lab', action='store_true',
                        help='fail unless the admitted lab format is present afterwards')
    args = parser.parse_args()
    if args.lab_history_format is not True:
        raise ValueError('explicit lab history scope required')
    if args.action == 'revert' and args.require_lab:
        raise ValueError('cannot require the lab format during revert')
    root = args.source_root.resolve(strict=True)
    evidence = args.evidence.resolve()
    if (evidence.exists() or root in evidence.parents or evidence == root or ROOT in evidence.parents
            or android_lifecycle.sealed_ancestor(evidence)):
        raise ValueError('fresh unsealed evidence outside source/repository required')
    project, adapted, lab, result, fence = inspect(root)
    if args.action == 'apply':
        # The same stack the admission requires, with this format as the native state it adds.
        native_state = result['companions']['native-principal-pins']
        problems = stack_problems(fence['state'], fence['package_verity_companion'],
                                  STATE if native_state == 'ADAPTED' else native_state,
                                  result['companions']['native-identity-writer'])
        if problems:
            raise ValueError('apply the complete lab stack first: ' + ', '.join(problems))
        if result['state'] != STATE:
            android_lifecycle.replace(project / FILE, lab)
    elif args.action == 'revert' and result['state'] == STATE:
        # Only this token, while the admitted stack is complete. The exact adapted Settings and
        # every companion stay in place. A partial stack refused above; its repair is manual.
        android_lifecycle.replace(project / FILE, adapted)
    _, _, _, after, _ = inspect(root)
    result.update(action=args.action, state_after=after['state'], companions_after=after['companions'])
    if args.require_lab and after['state'] != STATE:
        raise ValueError('the admitted lab native store format is required')
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
