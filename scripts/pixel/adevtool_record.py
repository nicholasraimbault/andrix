#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Which stock build a GrapheneOS tag uses for caiman, as adevtool at that tag records it.

adevtool records the stock build of a tag as the device config's device.build_id. It
merges config/device/caiman.yml with its includes, each include before the file that
includes it, so the last value in that order wins (src/config/config-loader.ts and
src/config/device.ts). The build index config/build-index/build-index-main.yml lists
each stock build with its factory image digest. The generated module under
vendor-skels/google_devices/caiman records the same build ID and the android-info.txt
generated from that build. This tool reads all three strictly, refuses when they
disagree, and writes one record per tag.

A record is bound to its tag. The tag manifest must hash to the digest that
upstream/bases/TAG.json pins, which grapheneos_carry.py derived from the signed tag. The
manifest's vendor/adevtool revision is stored in the record, and the tree's
vendor/adevtool HEAD must equal it with clean tracked files, as grapheneos_source.py
checks a project. validate_record refuses a record without that binding.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parents[1] / 'proof'))
import caiman  # noqa: E402
from caiman import Refusal, refuse  # noqa: E402

BASES = Path(__file__).resolve().parents[2] / 'upstream' / 'bases'

SCHEMA = 'andrix.pixel.adevtool/1'
CONFIG_DIR = 'config/device'
INDEX = 'config/build-index/build-index-main.yml'
SKEL = 'vendor-skels/google_devices/' + caiman.DEVICE
MAX_FILE = 4 << 20

# device keys that decide which stock build supplies the firmware
BUILD_KEYS = ('build_id', 'backport_build_id', 'prev_build_id')
FLAG_KEYS = ('is_beta_build_id', 'is_beta_backport_build_id',
             'backport_bootloader_firmware', 'backport_radio_firmware')
_KEY = re.compile(r'([A-Za-z_][A-Za-z0-9_]*):(?:( .*))?')
_INCLUDE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_./-]*\.yml')


def read_text(path, what):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        refuse(f'{what} {path} is not a regular file')
    data = path.read_bytes()
    if len(data) > MAX_FILE:
        refuse(f'{what} {path} is larger than {MAX_FILE} bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        refuse(f'{what} {path} is not UTF-8')
    if '\r' in text or '\t' in text or '\0' in text:
        refuse(f'{what} {path} contains carriage returns, tabs or NUL bytes')
    return data, text


def _scalar(raw, where):
    """A plain YAML scalar with an optional trailing comment. Nothing else is accepted."""
    value = raw.strip()
    if value.startswith('#'):
        value = ''
    value = value.split(' #', 1)[0].rstrip()
    if value == '':
        refuse(f'{where} is empty')
    if value[0] in '\'"[]{}&*!|>%@`,?:-' or ': ' in value:
        refuse(f'{where} is not a plain scalar: {value!r}')
    return value


def parse_config(text, name):
    """Reads the parts of an adevtool device config that decide the stock build.

    Only block style is accepted at the top level. Top level keys other than includes,
    device and type are skipped, because adevtool merges them into other sections. The
    device mapping is read one level deep; nested values of other keys are skipped.
    """
    blocks = []
    for number, line in enumerate(text.split('\n'), 1):
        stripped = line.strip()
        if stripped == '' or stripped.startswith('#'):
            continue
        if line.startswith(('---', '...', '%')):
            refuse(f'{name} line {number}: YAML documents and directives are not supported')
        if line[0] == ' ' or line.startswith('- ') or line == '-':
            if not blocks:
                refuse(f'{name} line {number}: content before the first key')
            blocks[-1][2].append((number, line))
            continue
        match = _KEY.fullmatch(line)
        if match is None:
            refuse(f'{name} line {number}: unsupported top level line {line!r}')
        blocks.append((match.group(1), match.group(2), [], number))
    keys = [block[0] for block in blocks]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        refuse(f'{name} repeats top level keys {duplicates}')
    result = {'includes': [], 'device': {}, 'device_lines': {}}
    for key, inline, body, number in blocks:
        if key == 'type':
            if body or _scalar(inline or '', f'{name} type') != 'device':
                refuse(f'{name} line {number}: only device configs are supported')
        elif key == 'includes':
            if inline is not None and inline.split(' #', 1)[0].strip():
                refuse(f'{name} line {number}: includes must be a block sequence')
            for item_number, item in body:
                stripped = item.strip()
                if not stripped.startswith('- '):
                    refuse(f'{name} line {item_number}: includes holds only list items')
                path = _scalar(stripped[2:], f'{name} line {item_number} include')
                if _INCLUDE.fullmatch(path) is None:
                    refuse(f'{name} line {item_number}: unsupported include path {path!r}')
                result['includes'].append(path)
        elif key == 'device':
            if inline is not None and inline.split(' #', 1)[0].strip():
                refuse(f'{name} line {number}: device must be a block mapping')
            _parse_device(body, name, result)
    return result


def _parse_device(body, name, result):
    indent = None
    current = None
    for number, line in body:
        width = len(line) - len(line.lstrip(' '))
        if indent is None:
            if width == 0:
                refuse(f'{name} line {number}: device must be an indented mapping')
            indent = width
        if width < indent:
            refuse(f'{name} line {number}: inconsistent indentation in device')
        if width > indent:
            if current in BUILD_KEYS + FLAG_KEYS + ('name',):
                refuse(f'{name} line {number}: device.{current} must be a single scalar')
            continue
        match = _KEY.fullmatch(line[indent:])
        if match is None:
            refuse(f'{name} line {number}: unsupported device line {line!r}')
        current, inline = match.group(1), match.group(2)
        if current in result['device']:
            refuse(f'{name} line {number}: device.{current} repeats')
        where = f'{name} line {number} device.{current}'
        if current in BUILD_KEYS:
            result['device'][current] = caiman.parse_build_id(_scalar(inline or '', where), where)
        elif current in FLAG_KEYS:
            value = _scalar(inline or '', where)
            if value not in ('true', 'false'):
                refuse(f'{where} is not true or false')
            result['device'][current] = value == 'true'
        elif current == 'name':
            result['device'][current] = _scalar(inline or '', where)
        else:
            result['device'][current] = None
        result['device_lines'][current] = number


def device_config(root, device=caiman.DEVICE):
    """Merges the device config chain in adevtool's order and returns the decisive keys."""
    root = Path(root)
    base = (root / CONFIG_DIR).resolve()
    order = []
    stack = []

    def visit(path):
        relative = path.relative_to(root.resolve()).as_posix()
        if relative in stack:
            refuse(f'include cycle through {relative}')
        data, text = read_text(path, 'device config')
        parsed = parse_config(text, relative)
        stack.append(relative)
        for include in parsed['includes']:
            target = Path(os.path.normpath(path.parent / include))
            if base not in target.parents:
                refuse(f'{relative} includes {include}, outside {CONFIG_DIR}')
            if target.resolve() != target:
                refuse(f'{relative} includes {include} through a symbolic link')
            visit(target)
        stack.pop()
        order.append((relative, caiman.sha256(data), parsed))

    visit((base / f'{device}.yml'))
    merged = {}
    set_by = {}
    for relative, _, parsed in order:
        for key, value in parsed['device'].items():
            if key in BUILD_KEYS + FLAG_KEYS + ('name',):
                merged[key] = value
                set_by[key] = f'{relative}:{parsed["device_lines"][key]}'
    if merged.get('name') != device:
        refuse(f'the merged config names device {merged.get("name")!r}, not {device}')
    if 'build_id' not in merged:
        refuse('no file in the config chain sets device.build_id')
    for key in ('backport_build_id', 'prev_build_id'):
        if key in merged:
            refuse(f'device.{key} is set ({set_by[key]}), so firmware may come from a second '
                   'stock build; this record format does not cover that')
    for key in FLAG_KEYS:
        if merged.get(key):
            refuse(f'device.{key} is true ({set_by[key]}); this record format does not cover that')
    chain = [{'path': relative, 'sha256': digest} for relative, digest, _ in order]
    return {'build_id': merged['build_id'], 'set_by': set_by['build_id'], 'chain': chain}


_INDEX_KEY = re.compile(r'([a-z0-9]+) (' + caiman.BUILD_ID.pattern + r'):')
_INDEX_PROP = re.compile(r'  (desc|factory|ota|vendor/google_devices): (.+)')
_DIGEST_FILE = re.compile(r'([0-9a-f]{64}) ([A-Za-z0-9._-]+)')
_SHAPES = ({'desc', 'factory', 'ota'}, {'desc', 'factory', 'ota', 'vendor/google_devices'},
           {'vendor/google_devices'})


def parse_build_index(text, name=INDEX):
    """Reads adevtool's main build index. Every line must have one of the known forms."""
    entries = {}
    current = None
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for number, line in enumerate(lines, 1):
        key = _INDEX_KEY.fullmatch(line)
        if key is not None:
            current = (key.group(1), key.group(2))
            if current in entries:
                refuse(f'{name} line {number}: {current[0]} {current[1]} repeats')
            entries[current] = {'line': number}
            continue
        prop = _INDEX_PROP.fullmatch(line)
        if prop is None or current is None:
            refuse(f'{name} line {number}: unsupported line {line!r}')
        field, value = prop.groups()
        entry = entries[current]
        if field in entry:
            refuse(f'{name} line {number}: {field} repeats for {current[0]} {current[1]}')
        if field == 'desc':
            entry[field] = _scalar(value, f'{name} line {number} desc')
            continue
        match = _DIGEST_FILE.fullmatch(value)
        if match is None:
            refuse(f'{name} line {number}: {field} is not a digest and a file name')
        digest, filename = match.groups()
        device, build = current
        expected = {'factory': f'{device}-{build.lower()}-factory-{digest[:8]}.zip',
                    'ota': f'{device}-ota-{build.lower()}-{digest[:8]}.zip'}.get(field)
        if expected is not None and filename != expected:
            refuse(f'{name} line {number}: {field} file {filename} does not match {expected}')
        entry[field] = {'sha256': digest, 'file': filename}
    for (device, build), entry in entries.items():
        if set(entry) - {'line'} not in _SHAPES:
            refuse(f'{name}: {device} {build} has fields {sorted(set(entry) - {"line"})}')
    return entries


def caiman_builds(entries, device=caiman.DEVICE):
    builds = {}
    for (entry_device, build), entry in entries.items():
        if entry_device != device:
            continue
        if 'factory' not in entry:
            refuse(f'{device} {build} has no factory image in the index')
        builds[build] = {'desc': entry['desc'], 'factory_sha256': entry['factory']['sha256'],
                         'factory_file': entry['factory']['file']}
    return dict(sorted(builds.items()))


def generated_module(root, build_id):
    root = Path(root)
    found = {}
    data, text = read_text(root / SKEL / f'{caiman.DEVICE}.mk', 'generated module makefile')
    values = re.findall(r'^ifneq \(\$\(BUILD_ID\),(\S+)\)\n  \$\(error BUILD_ID: expected (\S+), '
                        r'got \$\(BUILD_ID\)\)$', text, re.M)
    if len(values) != 1 or values[0][0] != values[0][1]:
        refuse(f'{SKEL}/{caiman.DEVICE}.mk does not hold exactly one BUILD_ID check')
    found[f'{caiman.DEVICE}.mk'] = {'sha256': caiman.sha256(data), 'build_id': values[0][0]}
    data, text = read_text(root / SKEL / 'cmds-for-envsetup.sh', 'generated module environment')
    values = re.findall(r'^export BUILD_ID_' + caiman.DEVICE + r'="([^"\n]*)"$', text, re.M)
    if len(values) != 1:
        refuse(f'{SKEL}/cmds-for-envsetup.sh does not export BUILD_ID_{caiman.DEVICE} exactly once')
    found['cmds-for-envsetup.sh'] = {'sha256': caiman.sha256(data), 'build_id': values[0]}
    for name, value in found.items():
        if value['build_id'] != build_id:
            refuse(f'{SKEL}/{name} records stock build {value["build_id"]}, but the device '
                   f'config records {build_id}')
    data, _ = read_text(root / SKEL / 'firmware/android-info.txt', 'generated android-info.txt')
    info = caiman.parse_android_info(data, f'{SKEL}/firmware/android-info.txt')
    found['android-info.txt'] = dict(info.as_dict(), sha256=caiman.sha256(data))
    return found


def derive_content(adevtool, release):
    """What adevtool at one tree records for caiman. The tag binding is added by derive_record."""
    release = caiman.parse_release(release, allow_preview=False, what='tag')
    root = Path(adevtool)
    config = device_config(root)
    data, text = read_text(root / INDEX, 'build index')
    builds = caiman_builds(parse_build_index(text))
    if config['build_id'] not in builds:
        refuse(f'the build index has no {caiman.DEVICE} {config["build_id"]} entry')
    return {
        'schema': SCHEMA,
        'device': caiman.DEVICE,
        'release': release.number,
        'stock_build': config['build_id'],
        'stock_build_set_by': config['set_by'],
        'config_chain': config['chain'],
        'build_index': {'path': INDEX, 'sha256': caiman.sha256(data), caiman.DEVICE: builds},
        'generated_module': generated_module(root, config['build_id']),
    }


def base_record(release, bases=None):
    """The signed base record of a tag. grapheneos_carry.py writes it from the signed manifest tag."""
    path = Path(bases or BASES) / f'{release}.json'
    if path.is_symlink() or not path.is_file():
        refuse(f'no signed base record upstream/bases/{release}.json; record the tag with '
               'scripts/proof/grapheneos_carry.py first')
    value = json.loads(path.read_text(encoding='utf-8'))
    manifest = value.get('manifest') if isinstance(value, dict) else None
    if (value.get('schema') != 'andrix.upstream.base/1' or value.get('release') != release
            or not isinstance(manifest, dict)
            or caiman.SHA256.fullmatch(str(manifest.get('sha256'))) is None):
        refuse(f'upstream/bases/{release}.json is not a base record for {release}')
    return value


def manifest_revision(manifest, release, bases=None):
    """vendor/adevtool's revision in the tag's manifest, whose digest the base record pins."""
    data = Path(manifest).read_bytes()
    pinned = base_record(release, bases)['manifest']['sha256']
    if caiman.sha256(data) != pinned:
        refuse(f'{manifest} is not the manifest that upstream/bases/{release}.json pins')
    try:
        projects = ET.fromstring(data).findall('project')
    except ET.ParseError:
        refuse(f'{manifest} is not XML')
    found = [entry.get('revision') for entry in projects
             if entry.get('path', entry.get('name')) == 'vendor/adevtool']
    if len(found) != 1 or re.fullmatch(r'[0-9a-f]{40}', found[0] or '') is None:
        refuse(f'{manifest} does not pin exactly one vendor/adevtool commit')
    return found[0], pinned


def tree_head(tree, revision):
    """grapheneos_source.check_project: HEAD equals the revision and tracked files are clean."""
    import grapheneos_source
    result = grapheneos_source.check_project(Path(tree).resolve(),
                                             {'path': 'vendor/adevtool', 'revision': revision})
    if result.get('verdict') != 'PASS':
        refuse(f'vendor/adevtool is not the clean commit {revision}: {result.get("failure")}')
    return result['head']


def derive_record(tree, release, manifest=None, bases=None):
    """A record of one tree, bound to the adevtool commit its tag's signed manifest pins."""
    tree = Path(tree)
    revision, pinned = manifest_revision(manifest or tree / '.repo/manifests/default.xml',
                                         release, bases)
    head = tree_head(tree, revision)
    record = derive_content(tree / 'vendor/adevtool', release)
    record.update(adevtool_revision=revision, manifest_sha256=pinned, tree_head=head,
                  revision_source='the tag manifest pinned by upstream/bases')
    return record


def validate_record(record, what='record', bases=None):
    """Checks a record's shape and its tag binding before the criterion relies on it."""
    if not isinstance(record, dict) or record.get('schema') != SCHEMA:
        refuse(f'{what} is not an {SCHEMA} record')
    if record.get('device') != caiman.DEVICE:
        refuse(f'{what} is not for {caiman.DEVICE}')
    release = caiman.parse_release(record.get('release'), allow_preview=False, what=f'{what} release')
    revision = record.get('adevtool_revision')
    if not isinstance(revision, str) or re.fullmatch(r'[0-9a-f]{40}', revision) is None:
        refuse(f'{what} is not bound to an adevtool commit')
    if record.get('manifest_sha256') != base_record(release.number, bases)['manifest']['sha256']:
        refuse(f'{what} is not bound to the manifest that upstream/bases/{release}.json pins')
    if 'tree_head' in record and record['tree_head'] != revision:
        refuse(f'{what} was derived from a tree at another commit')
    stock = caiman.parse_build_id(record.get('stock_build'), f'{what} stock build')
    builds = (record.get('build_index') or {}).get(caiman.DEVICE)
    if not isinstance(builds, dict) or stock not in builds:
        refuse(f'{what} does not list its own stock build in the build index')
    for build, entry in builds.items():
        caiman.parse_build_id(build, f'{what} index build')
        if (not isinstance(entry, dict) or set(entry) != {'desc', 'factory_sha256', 'factory_file'}
                or not isinstance(entry['desc'], str)
                or not isinstance(entry['factory_sha256'], str)
                or caiman.SHA256.fullmatch(entry['factory_sha256']) is None):
            refuse(f'{what} index entry {build} is malformed')
    info = (record.get('generated_module') or {}).get('android-info.txt')
    if (not isinstance(info, dict)
            or not all(isinstance(info.get(key), str) for key in ('board', 'bootloader', 'baseband'))
            or not isinstance(info.get('partitions'), list)
            or not all(isinstance(item, str) for item in info['partitions'])):
        refuse(f'{what} has no well formed generated android-info.txt')
    text = ''.join([f'require board={info["board"]}\n',
                    f'require version-bootloader={info["bootloader"]}\n',
                    f'require version-baseband={info["baseband"]}\n'] +
                   [f'require partition-exists={item}\n' for item in info['partitions']])
    android_info = caiman.parse_android_info(text.encode('ascii', 'replace'),
                                             f'{what} android-info.txt')
    return release, stock, builds, android_info


def write_new(path, text):
    path = Path(path)
    if path.exists() or path.is_symlink():
        refuse(f'{path} exists; records are never overwritten')
    with open(path, 'x', encoding='utf-8') as handle:
        handle.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    record = sub.add_parser('record', help='derive a record from a GrapheneOS tree at TAG')
    record.add_argument('--tree', required=True, help='the source tree root, checked out at TAG')
    record.add_argument('--release', required=True, help='the tag')
    record.add_argument('--manifest', help='the tag manifest; default TREE/.repo/manifests/default.xml')
    record.add_argument('--out', help='new file to write; default standard output')
    verify = sub.add_parser('verify', help='derive again and compare with a record')
    verify.add_argument('--tree', required=True)
    verify.add_argument('--manifest')
    verify.add_argument('record')
    args = parser.parse_args(argv)
    try:
        if args.command == 'record':
            text = caiman.dump(derive_record(args.tree, args.release, args.manifest))
            if args.out:
                write_new(args.out, text)
            else:
                sys.stdout.write(text)
            return 0
        stored = json.loads(Path(args.record).read_text(encoding='utf-8'))
        validate_record(stored, args.record)
        derived = derive_record(args.tree, stored['release'], args.manifest)
        if derived != stored:
            print(f'REFUSE: {args.record} differs from the record derived from {args.tree}')
            return 1
        print(f'PASS: {args.record} matches {args.tree}')
        return 0
    except (Refusal, OSError, ValueError) as error:
        print(f'REFUSE: {error}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
