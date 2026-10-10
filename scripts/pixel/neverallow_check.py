#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The neverallow check: Andrix's rules on the SELinux policy a caiman phone would load.

adevtool sets SELINUX_IGNORE_NEVERALLOWS := true for caiman, so a caiman build checks none
of Andrix's neverallow rules. This host tool checks them afterwards, on the built files.
It follows item 2 of plans/2026-10-09-caiman-design-items.md, steps A to G:

A. The loaded policy: the vendor precompiled policy, its three hash pairs, and no odm
   precompiled policy and no userdebug_plat_sepolicy.cil anywhere.
B. The owner domains andrixd, andrix_owner and andrix_terminal are domains of that policy.
C. Every literal neverallow in the Andrix policy sources has one entry in the witness table,
   each entry matches its source line, and its expansion is in the build's expanded rule file.
D. sepolicy-analyze neverallow -w on those rules passes only with exit status 0, no
   violation and nothing on standard error.
E. The policy compiled again with init's arguments decompiles to the same text as the loaded
   policy and passes; each rule's mutant fails that rule alone and the whole set.
F. Every other neverallow of the expanded rule file, on this policy and on the official policy
   of the base tag. A violation or a warning that only this policy shows refuses.
G. secilc without -N over the CIL files, which checks neverallowx too, against the same run on
   the official files. A violated rule that only these files show refuses.

Every check runs and reports; the policy passes only if all of them pass. The tool runs the
pinned sepolicy-analyze, secilc and checkpolicy. It contacts nothing.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import caiman  # noqa: E402
from caiman import Refusal, refuse  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WITNESSES = Path(__file__).resolve().parent / 'neverallow_witnesses.json'
SCHEMA = 'andrix.pixel.neverallow_witnesses/1'
# Host tools built in the pinned tree, GrapheneOS 2026081300, out/host/linux-x86/bin
SEPOLICY_ANALYZE_SHA256 = '9d5f2cedaf031f34eafacd1efdb055922f656ca074795c3bed9210e0ee95e825'
SECILC_SHA256 = 'af2916b092a76072513de199aefc78f9948d33eac1b9c52d9f30bf941828b218'
CHECKPOLICY_SHA256 = 'b1f08573cb85d87c4ed847366f05c04b2153a96d5d7093d7d460a9b06c5e451a'
PINS = {'sepolicy-analyze': SEPOLICY_ANALYZE_SHA256, 'secilc': SECILC_SHA256,
        'checkpolicy': CHECKPOLICY_SHA256}
# system/sepolicy/build/soong/policy.go:31 and system/core/init/Android.bp:496
POLICY_VERSION = '30'
OWNER_DOMAINS = ('andrixd', 'andrix_owner', 'andrix_terminal')
VARIANTS = ('user', 'userdebug')
COMMAND_TIMEOUT = 1800
SMALL = 1 << 20
POLICY_LIMIT = 256 << 20

SELINUX = {part: f'/{part}/etc/selinux' for part in ('system', 'system_ext', 'product', 'vendor')}
PRECOMPILED = '/vendor/etc/selinux/precompiled_sepolicy'
ODM_PRECOMPILED = '/odm/etc/selinux/precompiled_sepolicy'
USERDEBUG_POLICY = 'userdebug_plat_sepolicy.cil'
# system/core/init/selinux.cpp:149-156; each hash is of the CIL file then its mapping file
# (system/sepolicy/Android.bp:535-584)
HASH_PAIRS = (
    ('plat', '/system/etc/selinux/plat_sepolicy_and_mapping.sha256',
     '/system/etc/selinux/plat_sepolicy.cil', '/system/etc/selinux/mapping/{v}.cil'),
    ('system_ext', '/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256',
     '/system_ext/etc/selinux/system_ext_sepolicy.cil', '/system_ext/etc/selinux/mapping/{v}.cil'),
    ('product', '/product/etc/selinux/product_sepolicy_and_mapping.sha256',
     '/product/etc/selinux/product_sepolicy.cil', '/product/etc/selinux/mapping/{v}.cil'),
)
# libgenfslabelsversion: the version init uses when the vendor file is absent
GENFS_DEFAULT = 202404
GENFS_REQUIRED = 202504

_HASH_LINE = re.compile(r'[0-9a-f]{64}\n')
_VERSION = re.compile(r'[0-9]{2,8}(?:\.[0-9]{1,4})?')
_WORD = r'(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])'
_NEVERALLOW = re.compile(_WORD.format('neverallow'))
_NEVERALLOWX = re.compile(_WORD.format('neverallowx(?:perm)?'))
_STATEMENT = re.compile(_WORD.format('neverallow') + r'\s[^;]*;')
_NAME = r'[A-Za-z0-9_]+'
_WITNESS = re.compile(rf'\(allow ({_NAME}) ({_NAME}) \(({_NAME}) \(({_NAME})\)\)\)')
_VIOLATION = re.compile(r'(?:libsepol\.report_failure: )?neverallow(?: on line .*?)? violated by '
                        r'(allow \S+ \S+:\S+ \{[^}]*\};)')
_MACRO_CALL = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\(')
_USERDEBUG_OR_ENG = re.compile(r"userdebug_or_eng\(`([^`']*)'\)")


def _environment():
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C',
                   'TMPDIR': tempfile.gettempdir()}
    if 'HOME' in os.environ:
        environment['HOME'] = os.environ['HOME']
    return environment


def run_tool(command, cwd=None):
    """Exit status, standard output and standard error of one tool run."""
    try:
        process = subprocess.run([str(part) for part in command], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=_environment(),
                                 timeout=COMMAND_TIMEOUT, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as error:
        refuse(f'{Path(str(command[0])).name} did not run: {error}')
    return (process.returncode, process.stdout.decode('utf-8', 'replace'),
            process.stderr.decode('utf-8', 'replace'))


def pinned_tools(paths, pins=None):
    """The host tools, each hashed against its pin. A missing or different tool refuses."""
    pins = PINS if pins is None else pins
    tools = {}
    for name, pinned in pins.items():
        path = (paths or {}).get(name)
        if not path:
            refuse(f'the check needs the pinned {name}')
        try:
            digest = caiman.sha256(Path(path).read_bytes())
        except OSError as error:
            refuse(f'{name} cannot be read: {error}')
        if digest != pinned:
            refuse(f'{path} hashes to {digest}, not the pinned {name} {pinned}')
        tools[name] = str(path)
    return tools


# -- Inputs ------------------------------------------------------------------------------


class Inputs:
    """Policy files by their path on the phone, read from a directory or given one by one."""

    def __init__(self, files, complete, root=None):
        self.files = files          # phone path -> host path
        self.complete = complete    # True when every file of the partitions is listed
        self.root = root

    @classmethod
    def from_directory(cls, directory):
        root = Path(directory)
        if not root.is_dir():
            refuse(f'{directory} is not a directory of partition files')
        files = {}
        for top, directories, names in os.walk(root, followlinks=False):
            for name in names:
                host = Path(top) / name
                files['/' + host.relative_to(root).as_posix()] = host
        return cls(files, True, root)

    @classmethod
    def from_pairs(cls, pairs):
        files = {}
        for pair in pairs:
            phone, sep, host = pair.partition('=')
            path = PurePosixPath(phone)
            if (not sep or not path.is_absolute() or any(part in ('.', '..') for part in path.parts)
                    or str(path) != phone):
                refuse(f'--file {pair!r} is not PHONE_PATH=HOST_PATH with an absolute phone path')
            if phone in files:
                refuse(f'--file names {phone} twice')
            files[phone] = Path(host)
        return cls(files, False)

    def has(self, phone):
        return phone in self.files

    def path(self, phone):
        host = self.files.get(phone)
        if host is None:
            refuse(f'the inputs hold no {phone}')
        if host.is_symlink() or not host.is_file():
            refuse(f'{phone} is not a regular file')
        return host

    def read(self, phone, limit=SMALL):
        host = self.path(phone)
        size = host.stat().st_size
        if size > limit:
            refuse(f'{phone} is larger than {limit} bytes')
        return host.read_bytes()


def _first_line_hash(data, phone):
    text = data.decode('ascii', 'replace')
    if _HASH_LINE.fullmatch(text) is None:
        refuse(f'{phone} is not one line of 64 lowercase hexadecimal digits')
    return text[:64]


def _one_line(data, phone, pattern):
    text = data.decode('ascii', 'replace')
    if not text.endswith('\n') or text.count('\n') != 1 or pattern.fullmatch(text[:-1]) is None:
        refuse(f'{phone} is not one line holding {pattern.pattern}')
    return text[:-1]


def build_type(inputs):
    """ro.build.type from /system/build.prop, exactly once."""
    lines = inputs.read('/system/build.prop', 8 << 20).decode('utf-8', 'replace').split('\n')
    values = [line[len('ro.build.type='):] for line in lines if line.startswith('ro.build.type=')]
    if len(values) != 1:
        refuse(f'/system/build.prop sets ro.build.type {len(values)} times, not once')
    return values[0]


def genfs_labels_version(inputs):
    """The vendor's genfs labels version, or init's default when the file is absent."""
    phone = '/vendor/etc/selinux/genfs_labels_version.txt'
    if not inputs.has(phone):
        return GENFS_DEFAULT
    text = inputs.read(phone).decode('ascii', 'replace').strip()
    if re.fullmatch(r'[0-9]{6}', text) is None:
        refuse(f'{phone} holds {text!r}, not a six digit version')
    return int(text)


def init_cil_files(inputs, version, genfs_version):
    """The CIL files init passes to secilc, in its order (system/core/init/selinux.cpp:350-392)."""
    plat = '/system/etc/selinux'
    optional = [f'{plat}/mapping/{version}.compat.cil',
                '/system_ext/etc/selinux/system_ext_sepolicy.cil',
                f'/system_ext/etc/selinux/mapping/{version}.cil',
                f'/system_ext/etc/selinux/mapping/{version}.compat.cil',
                '/product/etc/selinux/product_sepolicy.cil',
                f'/product/etc/selinux/mapping/{version}.cil']
    files = [f'{plat}/plat_sepolicy.cil', f'{plat}/mapping/{version}.cil']
    files += [phone for phone in optional if inputs.has(phone)]
    files += ['/vendor/etc/selinux/plat_pub_versioned.cil', '/vendor/etc/selinux/vendor_sepolicy.cil']
    if inputs.has('/odm/etc/selinux/odm_sepolicy.cil'):
        files.append('/odm/etc/selinux/odm_sepolicy.cil')
    genfs = f'{plat}/plat_sepolicy_genfs_{genfs_version}.cil'
    if inputs.has(genfs):
        files.append(genfs)
    elif genfs_version >= GENFS_REQUIRED:
        refuse(f'genfs labels version {genfs_version} needs {genfs}, which is missing')
    for phone in files:
        inputs.path(phone)
    return files


def secilc_command(secilc, files, inputs, output):
    """init's secilc arguments, with host paths and a host output."""
    host = [str(inputs.path(phone)) for phone in files]
    return [secilc, host[0], '-m', '-M', 'true', '-G', '-N', '-v', '-c', POLICY_VERSION, host[1],
            '-o', str(output), '-f', os.devnull, *host[2:]]


def check_loaded_policy(inputs, variant, state):
    """Step A. The vendor precompiled policy, its hash pairs, and nothing init would prefer."""
    detail = {}
    if inputs.has(ODM_PRECOMPILED):
        refuse(f'the inputs carry {ODM_PRECOMPILED}, which init would load instead')
    debug = sorted(phone for phone in inputs.files if PurePosixPath(phone).name == USERDEBUG_POLICY)
    if debug:
        refuse(f'the inputs carry {", ".join(debug)}; with a debug ramdisk init compiles that '
               'policy instead of loading the precompiled one')
    stray = sorted(phone for phone in inputs.files
                   if PurePosixPath(phone).name == 'precompiled_sepolicy' and phone != PRECOMPILED)
    if stray:
        refuse(f'the inputs carry another precompiled policy: {", ".join(stray)}')
    policy = inputs.path(PRECOMPILED)
    if policy.stat().st_size > POLICY_LIMIT:
        refuse(f'{PRECOMPILED} is larger than {POLICY_LIMIT} bytes')
    state['policy'] = policy
    detail['precompiled_sepolicy_sha256'] = caiman.sha256(policy.read_bytes())
    found = build_type(inputs)
    if found != variant:
        refuse(f'/system/build.prop has ro.build.type={found}, not the variant {variant}')
    detail['variant'] = found
    version = _one_line(inputs.read('/vendor/etc/selinux/plat_sepolicy_vers.txt'),
                        '/vendor/etc/selinux/plat_sepolicy_vers.txt', _VERSION)
    detail['plat_sepolicy_vers'] = version
    pairs = {}
    for name, actual, cil, mapping in HASH_PAIRS:
        precompiled = f'{PRECOMPILED}.{PurePosixPath(actual).name}'
        first = _first_line_hash(inputs.read(actual), actual)
        second = _first_line_hash(inputs.read(precompiled), precompiled)
        mapping = mapping.format(v=version)
        computed = caiman.sha256(inputs.read(cil, POLICY_LIMIT) + inputs.read(mapping, POLICY_LIMIT))
        if first != second:
            refuse(f'{actual} holds {first} and {precompiled} holds {second}; init would not load '
                   'the precompiled policy')
        if computed != first:
            refuse(f'{cil} followed by {mapping} hashes to {computed}, not the {first} that '
                   f'{actual} records')
        pairs[name] = {'sha256': first, 'files': [cil, mapping]}
    detail['hash_pairs'] = pairs
    genfs_version = genfs_labels_version(inputs)
    detail['genfs_labels_version'] = genfs_version
    state['cil_files'] = init_cil_files(inputs, version, genfs_version)
    detail['cil_files'] = state['cil_files']
    if not inputs.complete:
        refuse('the inputs were given as single files, so they cannot show that no image '
               f'carries {ODM_PRECOMPILED} or {USERDEBUG_POLICY}; give the directory of '
               'partition files')
    return detail


# -- Step B ------------------------------------------------------------------------------


def check_owner_domains(tools, policy):
    """Step B. sepolicy-analyze POLICY attribute domain lists every owner domain."""
    status, output, errors = run_tool([tools['sepolicy-analyze'], policy, 'attribute', 'domain'])
    if status != 0 or errors.strip():
        refuse(f'sepolicy-analyze attribute domain exited {status}: {(errors or output).strip()[-300:]!r}')
    domains = set(output.split())
    missing = [name for name in OWNER_DOMAINS if name not in domains]
    if missing:
        refuse(f'the policy has no domain {", ".join(missing)}; it is not a policy with the owner '
               'session on')
    return {'domains': len(domains), 'owner_domains': list(OWNER_DOMAINS)}


# -- Step C ------------------------------------------------------------------------------


def load_witnesses(path):
    try:
        table = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        refuse(f'the witness table cannot be read: {error}')
    if not isinstance(table, dict) or table.get('schema') != SCHEMA:
        refuse(f'the witness table is not {SCHEMA}')
    rules = table.get('rules')
    if not isinstance(rules, list) or not rules:
        refuse('the witness table holds no rules')
    for index, entry in enumerate(rules, 1):
        if (not isinstance(entry, dict) or entry.get('number') != index
                or not isinstance(entry.get('source'), str) or not isinstance(entry.get('line'), int)
                or not isinstance(entry.get('rule'), str) or not isinstance(entry.get('witness'), str)
                or not isinstance(entry.get('expansion'), dict)
                or any(not isinstance(entry['expansion'].get(v), str) for v in VARIANTS)):
            refuse(f'witness table entry {index} is malformed or out of order')
        parse_witness(entry['witness'], index)
    return table


def parse_witness(text, number):
    match = _WITNESS.fullmatch(text)
    if match is None:
        refuse(f'the witness of rule {number} is not one CIL allow of one permission: {text!r}')
    source, target, klass, permission = match.groups()
    return {'source': source, 'target': source if target == 'self' else target,
            'class': klass, 'permission': permission}


def violation_text(witness):
    """The violation line libsepol prints for the witness (libsepol/src/assertion.c:47-68)."""
    return (f'allow {witness["source"]} {witness["target"]}:{witness["class"]} '
            f'{{ {witness["permission"]} }};')


def expand(rule, variant, macros):
    """The rule as m4 expands it for the variant, with the three macros the rules use."""
    text = _USERDEBUG_OR_ENG.sub(lambda m: m.group(1) if variant != 'user' else '', rule)
    calls = sorted(set(_MACRO_CALL.findall(text)))
    if calls:
        refuse(f'the rule {rule!r} calls macros the check does not know: {", ".join(calls)}')
    for name, value in macros.items():
        text = re.sub(_WORD.format(re.escape(name)), lambda m: value, text)
    return ' '.join(text.split())


def _uncommented(line):
    return line.split('#', 1)[0]


def literal_rules(source_root, policy_dirs, patch_dirs):
    """Every literal neverallow in the given policy directories and system/sepolicy patches."""
    root = Path(source_root)
    found = []
    sources = []

    def scan(relative, lines, patch):
        for number, line in enumerate(lines, 1):
            if patch:
                if not line.startswith('+') or line.startswith('+++'):
                    continue
                line = line[1:]
            text = _uncommented(line)
            if _NEVERALLOWX.search(text):
                refuse(f'{relative}:{number} holds a literal extended permission rule, which '
                       'steps C to E cannot check')
            if _NEVERALLOW.search(text):
                found.append((relative, number, text.strip()))

    for directory in policy_dirs:
        base = root / directory
        if base.is_symlink() or not base.is_dir():
            refuse(f'the policy directory {directory} is not a directory of the source tree')
        for path in sorted(base.rglob('*')):
            if path.is_symlink():
                refuse(f'{path.relative_to(root).as_posix()} is a symbolic link')
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                sources.append(relative)
                scan(relative, path.read_text(encoding='utf-8').split('\n'), False)
    for directory in patch_dirs:
        base = root / directory
        if base.is_symlink() or not base.is_dir():
            refuse(f'the patch directory {directory} is not a directory of the source tree')
        for record_path in sorted(base.glob('*.json')):
            try:
                record = json.loads(record_path.read_text(encoding='utf-8'))
            except ValueError as error:
                refuse(f'{record_path.name} is not JSON: {error}')
            if not isinstance(record, dict) or record.get('project') != 'system/sepolicy':
                continue
            name = record.get('patch')
            if not isinstance(name, str) or '/' in name or not name.endswith('.patch'):
                refuse(f'{record_path.name} names no patch file')
            patch = base / name
            data = patch.read_bytes()
            if caiman.sha256(data) != record.get('patch_sha256'):
                refuse(f'{name} does not hash to the patch_sha256 that {record_path.name} records')
            relative = patch.relative_to(root).as_posix()
            sources.append(relative)
            scan(relative, data.decode('utf-8').split('\n'), True)
    return found, sources


def expanded_statements(text):
    """Each neverallow statement of an expanded rule file, comments removed, spaces collapsed."""
    flat = ' '.join('\n'.join(_uncommented(line) for line in text.split('\n')).split())
    return _STATEMENT.findall(flat)


def check_rule_sources(table, source_root, policy_dirs, patch_dirs, expanded, variant):
    """Step C. The witness table against the sources and against the expanded rule file."""
    if not policy_dirs:
        refuse('no Andrix policy directory was given')
    macros = {name: value.get('value') for name, value in (table.get('macros') or {}).items()
              if name != 'userdebug_or_eng'}
    if sorted(macros) != ['capability_class_set', 'no_x_file_perms'] or \
            not all(isinstance(value, str) for value in macros.values()):
        refuse('the witness table does not define exactly capability_class_set and no_x_file_perms')
    found, sources = literal_rules(source_root, policy_dirs, patch_dirs)
    entries = {(entry['source'], entry['line']): entry for entry in table['rules']}
    if len(entries) != len(table['rules']):
        refuse('the witness table names one source line twice')
    problems = []
    seen = set()
    for source, line, text in found:
        entry = entries.get((source, line))
        if entry is None:
            problems.append(f'{source}:{line} has no witness table entry: {text!r}')
            continue
        seen.add((source, line))
        if entry['rule'] != text:
            problems.append(f'rule {entry["number"]} records {entry["rule"]!r}, but {source}:{line} '
                            f'reads {text!r}')
    for key, entry in entries.items():
        if key not in seen:
            problems.append(f'rule {entry["number"]} names {key[0]}:{key[1]}, which holds no literal '
                            'neverallow among the sources')
    statements = expanded_statements(expanded)
    for entry in table['rules']:
        wanted = expand(entry['rule'], variant, macros)
        if entry['expansion'][variant] != wanted:
            problems.append(f'rule {entry["number"]} records the {variant} expansion '
                            f'{entry["expansion"][variant]!r}, not {wanted!r}')
        elif wanted not in statements:
            problems.append(f'the expanded rule file lacks rule {entry["number"]}: {wanted!r}')
    if problems:
        refuse('; '.join(problems))
    return {'sources': sources, 'rules': len(found), 'expanded_neverallows': len(statements)}


# -- Steps D and E -----------------------------------------------------------------------


def analyze(tools, policy, rules, work, name):
    """sepolicy-analyze POLICY neverallow -w on the rules, from a file or with -n for one rule."""
    if isinstance(rules, str):
        command = [tools['sepolicy-analyze'], policy, 'neverallow', '-w', '-n', rules]
    else:
        path = Path(work) / f'{name}.rules'
        path.write_text(''.join(rule + '\n' for rule in rules), encoding='utf-8')
        command = [tools['sepolicy-analyze'], policy, 'neverallow', '-w', '-f', path]
    status, output, errors = run_tool(command)
    violations = [m.group(1) for m in map(_VIOLATION.search, (output + errors).split('\n')) if m]
    warnings = [line for line in errors.split('\n') if line.startswith('Warning!')]
    return {'command': shlex.join(str(part) for part in command), 'status': status,
            'stdout': output, 'stderr': errors, 'violations': violations, 'warnings': warnings}


def require_pass(result, what):
    if result['status'] != 0 or result['violations'] or result['stderr'] or result['stdout']:
        shown = (result['stderr'] or result['stdout']).strip().split('\n')[:6]
        refuse(f'{what}: sepolicy-analyze exited {result["status"]} with {len(result["violations"])} '
               f'violations and {len(result["warnings"])} warnings: {shown!r}')


def check_rules_on_policy(tools, policy, rules, work):
    """Step D. Exit 0, no violation and nothing on standard error or standard output."""
    if not rules:
        refuse('there are no rules to check')
    result = analyze(tools, policy, rules, work, 'andrix')
    require_pass(result, 'the loaded policy')
    return {'command': result['command'], 'rules': len(rules)}


def decompile(tools, binary, output):
    status, out, errors = run_tool([tools['checkpolicy'], '-M', '-b', '-C', '-o', output, binary])
    if status != 0 or not Path(output).is_file():
        refuse(f'checkpolicy could not decompile {Path(binary).name}: {(errors or out).strip()[-300:]!r}')
    return Path(output).read_bytes()


def compile_policy(tools, files, inputs, output, extra=()):
    command = secilc_command(tools['secilc'], files, inputs, output) + [str(path) for path in extra]
    status, out, errors = run_tool(command)
    if status != 0 or not Path(output).is_file():
        refuse(f'secilc exited {status}: {(errors or out).strip()[-300:]!r}')
    return command


def first_difference(a, b):
    left, right = a.split(b'\n'), b.split(b'\n')
    for number, (x, y) in enumerate(zip(left, right), 1):
        if x != y:
            return number
    return min(len(left), len(right)) + 1


def check_mutant(result, witness, what):
    expected = violation_text(witness)
    if result['status'] == 0:
        refuse(f'{what} passed; its witness {expected!r} breaks nothing')
    if result['warnings'] or expected not in result['violations'] or \
            set(result['violations']) != {expected}:
        refuse(f'{what} failed without exactly the witness violation {expected!r}: '
               f'{result["stderr"].strip().split(chr(10))[:6]!r}')


def check_control_and_mutants(tools, inputs, files, policy, table, variant, work):
    """Step E. The control equals the loaded policy and passes; every mutant fails its rule."""
    work = Path(work)
    control = work / 'control.policy'
    command = compile_policy(tools, files, inputs, control)
    loaded_text = decompile(tools, policy, work / 'loaded.cil')
    control_text = decompile(tools, control, work / 'control.cil')
    if loaded_text != control_text:
        refuse('the recompiled control decompiles to text that differs from the loaded policy '
               f'from line {first_difference(loaded_text, control_text)}; the CIL files do not '
               'stand for the policy the phone loads')
    rules = [entry['expansion'][variant] for entry in table['rules']]
    require_pass(analyze(tools, control, rules, work, 'control'), 'the control')
    mutants = []
    problems = []
    for entry in table['rules']:
        number = entry['number']
        witness = parse_witness(entry['witness'], number)
        try:
            mutant_cil = work / f'mutant_{number}.cil'
            mutant_cil.write_text(entry['witness'] + '\n', encoding='utf-8')
            binary = work / f'mutant_{number}.policy'
            try:
                compile_policy(tools, files, inputs, binary, [mutant_cil])
            except Refusal as error:
                refuse(f'the witness does not compile: {error}')
            check_mutant(analyze(tools, binary, entry['expansion'][variant], work, f'alone_{number}'),
                         witness, 'its own rule alone')
            check_mutant(analyze(tools, binary, rules, work, f'set_{number}'), witness,
                         'the whole set')
            mutants.append({'rule': number, 'witness': entry['witness'], 'fails': True})
            binary.unlink()
        except Refusal as error:
            problems.append(f'mutant {number}: {error}')
    if problems:
        refuse('; '.join(problems))
    return {'command': shlex.join(command), 'decompiled_sha256': caiman.sha256(loaded_text),
            'mutants': mutants}


# -- Steps F and G -----------------------------------------------------------------------


def baseline_policy(inputs):
    """The official release's loaded policy and CIL files, read as init would read them."""
    if inputs.has(ODM_PRECOMPILED):
        refuse(f'the official inputs carry {ODM_PRECOMPILED}; caiman has no odm partition')
    policy = inputs.path(PRECOMPILED)
    version = _one_line(inputs.read('/vendor/etc/selinux/plat_sepolicy_vers.txt'),
                        'the official /vendor/etc/selinux/plat_sepolicy_vers.txt', _VERSION)
    return policy, init_cil_files(inputs, version, genfs_labels_version(inputs))


def aosp_rules(expanded, table, variant):
    """Set B: every neverallow of the expanded rule file other than the Andrix rules."""
    andrix = {entry['expansion'][variant] for entry in table['rules']}
    return [statement for statement in expanded_statements(expanded) if statement not in andrix]


_FAILURES = re.compile(r'(?:libsepol\.check_assertions: )?[0-9]+ neverallow failures occurred')
_ALLOW_LINE = re.compile(r'allow (\S+) (\S+):(\S+) \{([^}]*)\};')


def violations_and_warnings(result, what):
    """Violations, one per permission, and warnings. Any other output refuses."""
    other = [line for line in (result['stdout'] + result['stderr']).split('\n')
             if line.strip() and not line.startswith('Warning!') and _VIOLATION.search(line) is None
             and _FAILURES.fullmatch(line.strip()) is None]
    if other or (result['status'] != 0 and not result['violations']):
        refuse(f'sepolicy-analyze on the {what} policy exited {result["status"]}: {other[:4]!r}')
    found = set()
    for line in result['violations']:   # _VIOLATION gave each the form allow S T:C { P... };
        match = _ALLOW_LINE.fullmatch(line)
        for permission in match.group(4).split():
            found.add((match.group(1), match.group(2), match.group(3), permission))
    return found, result['warnings']


def check_aosp_rules(tools, policy, official, rules, work):
    """Step F. Set B on the Andrix policy and on the official policy of the base tag."""
    if not rules:
        refuse('the expanded rule file holds no rule besides the Andrix rules')
    ours, our_warnings = violations_and_warnings(analyze(tools, policy, rules, work, 'aosp'), 'Andrix')
    theirs, their_warnings = violations_and_warnings(
        analyze(tools, official, rules, work, 'aosp_official'), 'official')
    new = sorted(ours - theirs)
    remaining = list(their_warnings)
    unexplained = []
    for warning in our_warnings:
        if warning in remaining:
            remaining.remove(warning)
        else:
            unexplained.append(warning)
    problems = []
    if new:
        problems.append('violations the official policy does not show: '
                        + '; '.join(f'allow {s} {t}:{c} {p}' for s, t, c, p in new[:20]))
    if unexplained:
        problems.append(f'warnings the official policy does not give: {unexplained[:10]!r}')
    if problems:
        refuse('; '.join(problems))
    return {'rules': len(rules),
            'vendor_findings': [f'allow {s} {t}:{c} {p}' for s, t, c, p in sorted(ours & theirs)],
            'warnings_on_both': sorted(set(our_warnings) & set(their_warnings))}


_UNIT_HEAD = re.compile(r'(neverallowx?) check failed at .*')
_GENERATED = re.compile(r'\bbase_typeattr_[0-9]+\b')


def secilc_units(tools, files, inputs, work, name):
    """secilc without -N, with the build's check flags: one unit per violated rule."""
    host = [str(inputs.path(phone)) for phone in files]
    command = [tools['secilc'], '-m', '-M', 'true', '-G', '-c', POLICY_VERSION, *host,
               '-o', os.devnull, '-f', os.devnull, '-v']
    status, output, errors = run_tool(command, cwd=work)
    units = parse_units(output + errors, name)
    if status != 0 and not units:
        refuse(f'secilc without -N on the {name} files exited {status}: {errors.strip()[-300:]!r}')
    return units


def parse_units(text, name):
    """secilc's violation reports as units: the rule and its allow rules, without places."""
    units = set()
    lines = text.split('\n')
    index = 0
    while index < len(lines):
        if _UNIT_HEAD.fullmatch(lines[index].strip()) is None:
            index += 1
            continue
        rule = lines[index + 1].strip() if index + 1 < len(lines) else ''
        allows = []
        index += 2
        while index < len(lines) and lines[index].strip() and \
                _UNIT_HEAD.fullmatch(lines[index].strip()) is None:
            text = lines[index].strip()
            if text.startswith('('):
                allows.append(_GENERATED.sub('base_typeattr', text))
            index += 1
        if not rule.startswith('(neverallow') or not allows:
            refuse(f'secilc on the {name} files printed a violation of unknown form: {rule!r}')
        units.add((_GENERATED.sub('base_typeattr', rule), tuple(sorted(allows))))
    return units


def check_extended_rules(tools, inputs, files, official_inputs, official_files, work):
    """Step G. Every neverallow and neverallowx of the CIL files, against the official run."""
    ours = secilc_units(tools, files, inputs, work, 'Andrix')
    theirs = secilc_units(tools, official_files, official_inputs, work, 'official')
    new = sorted(ours - theirs)
    if new:
        refuse('violated rules the official files do not show: '
               + '; '.join(f'{rule} by {" ".join(allows)}' for rule, allows in new[:10]))
    return {'units': len(ours), 'vendor_findings': [rule for rule, _ in sorted(ours & theirs)]}


# -- The whole check ---------------------------------------------------------------------


def check(inputs, *, expanded, variant, tools, witnesses=WITNESSES, source_root=ROOT,
          policy_dirs=(), patch_dirs=(), scratch=None, pins=None, official=None):
    checks = {}
    state = {}

    def run(name, function):
        try:
            checks[name] = {'ok': True, **function()}
        except (Refusal, OSError, UnicodeDecodeError) as error:
            checks[name] = {'ok': False, 'reason': str(error)}

    def tool_set():
        if 'tools' not in state:
            state['tools'] = pinned_tools(tools, pins)
        return state['tools']

    if variant not in VARIANTS:
        return _finish({'variant': {'ok': False, 'reason': f'variant {variant!r} is not one of '
                                                           f'{", ".join(VARIANTS)}'}})
    work = Path(tempfile.mkdtemp(prefix='neverallow-', dir=scratch))
    try:
        run('tools', lambda: {'pinned': sorted(tool_set())})

        def loaded():
            return check_loaded_policy(inputs, variant, state)

        def owner():
            if 'policy' not in state:
                refuse('step A found no precompiled policy')
            return check_owner_domains(tool_set(), state['policy'])

        def rules():
            table = load_witnesses(witnesses)
            text = Path(expanded).read_text(encoding='utf-8')
            detail = check_rule_sources(table, source_root, policy_dirs, patch_dirs, text, variant)
            state['table'] = table
            return detail

        def on_policy():
            if 'policy' not in state:
                refuse('step A found no precompiled policy')
            if 'table' not in state:
                refuse('step C did not pass, so the rules are not known')
            rules = [entry['expansion'][variant] for entry in state['table']['rules']]
            return check_rules_on_policy(tool_set(), state['policy'], rules, work)

        def control():
            if not checks.get('A_loaded_policy', {}).get('ok'):
                refuse('step A did not pass, so the CIL files are not those of the loaded policy')
            if 'table' not in state:
                refuse('step C did not pass, so the witnesses are not known')
            return check_control_and_mutants(tool_set(), inputs, state['cil_files'], state['policy'],
                                             state['table'], variant, work)

        run('A_loaded_policy', loaded)
        run('B_owner_domains', owner)
        run('C_rule_sources', rules)
        run('D_rules_on_policy', on_policy)
        run('E_control_and_mutants', control)

        def official_set():
            if official is None:
                refuse('no official policy of the base tag was given, so nothing tells vendor '
                       'findings from Andrix ones')
            if 'official' not in state:
                state['official'] = baseline_policy(official)
            return state['official']

        def aosp():
            official_policy, _ = official_set()
            if 'policy' not in state:
                refuse('step A found no precompiled policy')
            if 'table' not in state:
                refuse('step C did not pass, so the Andrix rules cannot be told apart')
            rules = aosp_rules(Path(expanded).read_text(encoding='utf-8'), state['table'], variant)
            return check_aosp_rules(tool_set(), state['policy'], official_policy, rules, work)

        def extended():
            _, official_files = official_set()
            if not checks.get('A_loaded_policy', {}).get('ok'):
                refuse('step A did not pass, so the CIL files are not those of the loaded policy')
            return check_extended_rules(tool_set(), inputs, state['cil_files'], official,
                                        official_files, work)

        run('F_aosp_rules', aosp)
        run('G_extended_rules', extended)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return _finish(checks)


def _finish(checks):
    reasons = [f'{name}: {result["reason"]}' for name, result in checks.items() if not result['ok']]
    return {'verdict': 'PASS' if not reasons else 'REFUSE', 'reasons': reasons, 'checks': checks}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--partitions', help='a directory of partition files, laid out as on the '
                        'phone: DIR/system/etc/selinux, DIR/vendor/etc/selinux and so on')
    source.add_argument('--file', action='append', metavar='PHONE_PATH=HOST_PATH',
                        help='one policy file and its path on the phone; repeat for each file')
    parser.add_argument('--expanded', required=True,
                        help="the build's sepolicy_neverallows.sepolicy_analyze.conf")
    parser.add_argument('--variant', required=True, choices=VARIANTS)
    parser.add_argument('--witnesses', default=str(WITNESSES))
    parser.add_argument('--source-root', default=str(ROOT), help='the Andrix commit that was built')
    parser.add_argument('--policy-dir', action='append', default=[],
                        help='an Andrix policy directory the product adds, relative to the source root')
    parser.add_argument('--patches', action='append', default=[],
                        help='a directory of Andrix patch records, relative to the source root; '
                        'every record for system/sepolicy is read')
    parser.add_argument('--sepolicy-analyze', required=True)
    parser.add_argument('--secilc', required=True)
    parser.add_argument('--checkpolicy', required=True)
    parser.add_argument('--official', help="the official release's partition files, laid out "
                        'like --partitions, for steps F and G')
    parser.add_argument('--scratch', help='a directory for work files')
    args = parser.parse_args(argv)
    try:
        inputs = Inputs.from_directory(args.partitions) if args.partitions else \
            Inputs.from_pairs(args.file)
        official = Inputs.from_directory(args.official) if args.official else None
    except Refusal as error:
        sys.stdout.write(caiman.dump({'verdict': 'REFUSE', 'reasons': [str(error)], 'checks': {}}))
        return 1
    report = check(inputs, expanded=args.expanded, variant=args.variant,
                   tools={'sepolicy-analyze': args.sepolicy_analyze, 'secilc': args.secilc,
                          'checkpolicy': args.checkpolicy},
                   witnesses=args.witnesses, source_root=args.source_root,
                   policy_dirs=args.policy_dir, patch_dirs=args.patches, scratch=args.scratch,
                   official=official)
    sys.stdout.write(caiman.dump(report))
    return 0 if report['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
