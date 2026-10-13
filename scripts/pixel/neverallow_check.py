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
   A patch hunk that changes an existing rule, or m4's processing, needs a record there too.
D. sepolicy-analyze neverallow -w on those rules passes only with exit status 0, no
   violation and nothing on standard error.
E. The policy compiled again with init's arguments decompiles to the same text as the loaded
   policy and passes; each rule's mutant fails that rule alone and the whole set.
F. Every other neverallow of the expanded rule file, on this policy and on the official policy
   of the base tag. A violation or a warning that only this policy shows refuses.
G. secilc without -N over the CIL files, which checks neverallowx too, against the same run on
   the official files. A pair of a violated rule and one offending rule that only these files
   show refuses. Generated attribute names are replaced by their own definitions first.

Every check runs and reports; the policy passes only if all of them pass. The tool runs the
sepolicy-analyze, secilc and checkpolicy that the base tag's reviewed set pins. It contacts
nothing.

The gate reads the Andrix install zip and the official kit of its base tag only through
install_zip.py's verified images, takes the base tag from the zip's signed
com.andrix.build.base_tag property, and binds the zip and the expanded rule file to the release
record's digests. The Andrix policy directories come from board/owner-policy.mk and the patch
set from the base tag's patch directory, never from the caller, and the expanded rule file's
line markers must name no Andrix file outside those directories.

Corpus mode (--corpus) runs the same steps on a real policy that is not a caiman image, the
Andrix Cuttlefish product, where the design lets it depart from the gate. Its only verdicts
are CORPUS and REFUSE, and it never exits 0, so it can never pass the gate.
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
import install_zip  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WITNESSES = Path(__file__).resolve().parent / 'neverallow_witnesses.json'
SCHEMA = 'andrix.pixel.neverallow_witnesses/2'
# Host tools built in the pinned tree, GrapheneOS 2026081300, out/host/linux-x86/bin
SEPOLICY_ANALYZE_SHA256 = '9d5f2cedaf031f34eafacd1efdb055922f656ca074795c3bed9210e0ee95e825'
SECILC_SHA256 = 'af2916b092a76072513de199aefc78f9948d33eac1b9c52d9f30bf941828b218'
CHECKPOLICY_SHA256 = 'b1f08573cb85d87c4ed847366f05c04b2153a96d5d7093d7d460a9b06c5e451a'
PINS = {'sepolicy-analyze': SEPOLICY_ANALYZE_SHA256, 'secilc': SECILC_SHA256,
        'checkpolicy': CHECKPOLICY_SHA256}
# The reviewed host tool digests of each base tag, from that tag's own build host output. A tag
# without a set refuses: equal sources at two tags do not stand for equal compiled tools.
TOOL_PINS = {'2026081300': PINS}
# Sets that serve only the stage 1 corpus. Design item 2: "The 2026081300 set serves only the
# stage 1 corpus." The gate and the release wrapper's check refuse such a set for an image.
CORPUS_ONLY = frozenset({'2026081300'})
RELEASE_SCHEMA = 'andrix.caiman.release/1'
OWNER_POLICY = 'board/owner-policy.mk'
ANDRIX_TREE = 'vendor/andrix/'
# The board variables whose directories sepolicy_neverallows reads as sources
# (system/sepolicy/Android.bp:943-954), and the two other kinds of line owner-policy.mk may hold
POLICY_DIR_VARIABLES = ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS', 'SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS',
                        'PRODUCT_PRIVATE_SEPOLICY_DIRS', 'PRODUCT_PUBLIC_SEPOLICY_DIRS',
                        'BOARD_VENDOR_SEPOLICY_DIRS', 'BOARD_ODM_SEPOLICY_DIRS')
OTHER_BOARD_VARIABLES = ('BOARD_SEPOLICY_M4DEFS', 'TARGET_FS_CONFIG_GEN')
# system/sepolicy/build/soong/policy.go:31 and system/core/init/Android.bp:496
POLICY_VERSION = '30'
OWNER_DOMAINS = ('andrixd', 'andrix_owner', 'andrix_terminal')
VARIANTS = ('user', 'userdebug')
COMMAND_TIMEOUT = 1800
SMALL = 1 << 20
POLICY_LIMIT = 256 << 20
SOURCE_LIMIT = 16 << 20
CORPUS_EXIT = 3
# Rule 11 keeps userdebug_or_eng(`-overlay_remounter'), so on a userdebug policy the user rules
# fail with exactly this violation (design item 2, "Stage 1 corpus")
USERDEBUG_EXCEPTION = 'allow overlay_remounter andrix_owner_entry:file { execute };'
NO_OFFICIAL_RELEASE = 'no official GrapheneOS release exists for the corpus product'
UNBOUND_EXPANDED = ('the expanded rule file is not bound to the release record, so no step '
                    'reads it')

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
CHANGE_KINDS = ('removal', 'inside', 'm4')

_HASH_LINE = re.compile(r'[0-9a-f]{64}\n')
_VERSION = re.compile(r'[0-9]{2,8}(?:\.[0-9]{1,4})?')
_WORD = r'(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])'
_NEVERALLOW = re.compile(_WORD.format('neverallow'))
_NEVERALLOWX = re.compile(_WORD.format('neverallowx(?:perm)?'))
_RULE_KEYWORD = re.compile(_WORD.format('neverallow(?:xperm)?'))
_STATEMENT = re.compile(_WORD.format('neverallow') + r'\s[^;]*;')
_NAME = r'[A-Za-z0-9_]+'
_WITNESS = re.compile(rf'\(allow ({_NAME}) ({_NAME}) \(({_NAME}) \(({_NAME})\)\)\)')
_VIOLATION = re.compile(r'(?:libsepol\.report_failure: )?neverallow(?: on line .*?)? violated by '
                        r'(allow \S+ \S+:\S+ \{[^}]*\};)')
_MACRO_CALL = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\(')
_USERDEBUG_OR_ENG = re.compile(r"userdebug_or_eng\(`([^`']*)'\)")
# m4 builtins that define macros or change how m4 reads the rest of its input
_M4_DIRECTIVE = re.compile(_WORD.format(
    '(?:define|undefine|pushdef|popdef|changequote|changecom|dnl|divert|undivert|include|'
    'sinclude|m4exit|m4wrap|builtin|indir)'))
_DEFINITION = re.compile(_WORD.format('(?:define|pushdef)') + r'\(')
_HUNK = re.compile(r'@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?')


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


def tool_pins(base_tag, image=False):
    """The base tag's reviewed set of host tool digests. A tag without one refuses, and so does
    a set that serves only the stage 1 corpus when an image is checked."""
    pins = TOOL_PINS.get(base_tag)
    if pins is None:
        refuse(f'base tag {base_tag} has no reviewed set of host tool digests; equal sources at '
               'another tag do not stand for compiled tools')
    if image and base_tag in CORPUS_ONLY:
        refuse(f'the {base_tag} host tool set serves only the stage 1 corpus, so it checks no '
               'image (design item 2)')
    return pins


def check_build_tools(base_tag, directory):
    """The release wrapper's check (design item 2): the build's own host tools, in its host
    output directory, hash to the base tag's reviewed set. The wrapper releases images, so a set
    that serves only the stage 1 corpus refuses."""
    pins = tool_pins(base_tag, image=True)
    return {'base_tag': base_tag,
            'pinned': sorted(pinned_tools({name: Path(directory) / name for name in pins}, pins))}


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
            for name in directories:
                if (Path(top) / name).is_symlink():
                    # init would follow it, so files behind it could be loaded but not checked
                    refuse(f'/{(Path(top) / name).relative_to(root).as_posix()} is a symbolic '
                           'link to a directory, which this check does not follow')
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
    if inputs.has(ODM_PRECOMPILED):
        refuse(f'the inputs carry {ODM_PRECOMPILED}, which init would load instead')
    debug = sorted(phone for phone in inputs.files if PurePosixPath(phone).name == USERDEBUG_POLICY)
    if debug:
        refuse(f'the inputs carry {", ".join(debug)}; with a debug ramdisk init compiles that '
               'policy instead of loading the precompiled one')
    return loaded_policy(inputs, variant, state, PRECOMPILED, {})


def check_corpus_policy(inputs, variant, state):
    """Step A in corpus mode. The policy init would load, from odm before vendor
    (system/core/init/selinux.cpp:141-147); a userdebug platform policy is recorded, not refused."""
    precompiled = ODM_PRECOMPILED if inputs.has(ODM_PRECOMPILED) else PRECOMPILED
    debug = sorted(phone for phone in inputs.files if PurePosixPath(phone).name == USERDEBUG_POLICY)
    return loaded_policy(inputs, variant, state, precompiled,
                         {'loaded': precompiled, 'userdebug_policies_recorded': debug})


def loaded_policy(inputs, variant, state, precompiled, detail):
    """The rest of step A for the precompiled policy init loads: its hash pairs, the variant
    and init's CIL files. The hash files lie beside it (system/core/init/selinux.cpp:149-157)."""
    stray = sorted(phone for phone in inputs.files
                   if PurePosixPath(phone).name == 'precompiled_sepolicy'
                   and phone not in (precompiled, PRECOMPILED))
    if stray:
        refuse(f'the inputs carry another precompiled policy: {", ".join(stray)}')
    policy = inputs.path(precompiled)
    if policy.stat().st_size > POLICY_LIMIT:
        refuse(f'{precompiled} is larger than {POLICY_LIMIT} bytes')
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
        beside = f'{precompiled}.{PurePosixPath(actual).name}'
        first = _first_line_hash(inputs.read(actual), actual)
        second = _first_line_hash(inputs.read(beside), beside)
        mapping = mapping.format(v=version)
        computed = caiman.sha256(inputs.read(cil, POLICY_LIMIT) + inputs.read(mapping, POLICY_LIMIT))
        if first != second:
            refuse(f'{actual} holds {first} and {beside} holds {second}; init would not load '
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
    changes = table.get('changes')
    if not isinstance(changes, list):
        refuse('the witness table holds no list of changes to existing rules')
    for index, entry in enumerate(changes, 1):
        if (not isinstance(entry, dict) or entry.get('number') != index
                or not isinstance(entry.get('source'), str) or not isinstance(entry.get('line'), int)
                or entry.get('kind') not in CHANGE_KINDS or not isinstance(entry.get('file'), str)
                or not (entry.get('rule_line') is None or isinstance(entry.get('rule_line'), int))
                or not isinstance(entry.get('lines'), list)
                or not all(isinstance(line, str) for line in entry['lines'])
                or not isinstance(entry.get('effect'), str)):
            refuse(f'witness table change {index} is malformed or out of order')
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


def owner_policy_dirs(source_root):
    """The Andrix policy directories that board/owner-policy.mk adds, relative to the source root.

    The file may hold comments and += additions to the policy directory, m4 definition and file
    system configuration variables of the board. A condition, an include, an expansion, another
    kind of assignment or another variable refuses, because make could read it in a way this
    reading does not. So does a path outside vendor/andrix/, or a directory named twice.
    """
    path = Path(source_root) / OWNER_POLICY
    if path.is_symlink() or not path.is_file():
        refuse(f'the source tree holds no regular file {OWNER_POLICY}')
    statements = []
    current, first = '', None
    for number, line in enumerate(path.read_text(encoding='utf-8').split('\n'), 1):
        if not current and not line.strip():
            continue
        # make continues a line only at a backslash right before the newline, comments included
        if line != line.rstrip() or '\\' in line[:-1]:
            refuse(f'{OWNER_POLICY}:{number} ends in white space or holds a backslash before '
                   'its end')
        if not current and line.lstrip().startswith('#'):
            if line.endswith('\\'):
                refuse(f'{OWNER_POLICY}:{number} is a comment that make continues into the next '
                       'line')
            continue
        if '#' in line or '$' in line or line.startswith('\t'):
            refuse(f'{OWNER_POLICY}:{number} holds a comment, an expansion or a recipe inside a '
                   'statement')
        first = first or number
        current += ' ' + line.rstrip('\\').strip()
        if not line.endswith('\\'):
            statements.append((first, current.strip()))
            current, first = '', None
    if current:
        refuse(f'{OWNER_POLICY} ends inside a continued line')
    dirs = []
    for number, statement in statements:
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)\s*\+=\s*(\S.*)', statement)
        if match is None or match.group(1) not in POLICY_DIR_VARIABLES + OTHER_BOARD_VARIABLES:
            refuse(f'{OWNER_POLICY}:{number} is not a += addition to a policy directory, m4 or file '
                   f'system configuration variable: {statement[:80]!r}')
        variable = match.group(1)
        for value in match.group(2).split():
            if variable == 'BOARD_SEPOLICY_M4DEFS':
                if re.fullmatch(r'[a-z0-9_]+=[A-Za-z0-9_]+', value) is None:
                    refuse(f'{OWNER_POLICY}:{number} defines {value!r}, which is not name=value')
                continue
            relative = value[len(ANDRIX_TREE):] if value.startswith(ANDRIX_TREE) else ''
            if any(part in ('', '.', '..') for part in relative.split('/')):
                refuse(f'{OWNER_POLICY}:{number} names {value}, which is not a path under {ANDRIX_TREE}')
            if variable in POLICY_DIR_VARIABLES:
                if relative in dirs:
                    refuse(f'{OWNER_POLICY} names {value} twice')
                if relative.split('/')[0] == 'tests':   # design item 1: no lab policy
                    refuse(f'{OWNER_POLICY}:{number} names {value}, a lab directory under tests/')
                dirs.append(relative)
    if not dirs:
        refuse(f'{OWNER_POLICY} adds no policy directory')
    return dirs


_LINE_MARKER = re.compile(r'^#line [0-9]+ "([^"]*)"$', re.MULTILINE)


def check_expanded_sources(expanded, policy_dirs):
    """Every Andrix file that the build expanded lies in a directory of board/owner-policy.mk.

    m4 -s writes a line marker naming each source file it reads
    (system/sepolicy/build/soong/policy.go:296), so the expanded rule file shows which Andrix
    files the build read. A file outside the derived directories, such as a lab policy, refuses.
    """
    named = sorted({name for name in _LINE_MARKER.findall(expanded) if name.startswith(ANDRIX_TREE)})
    outside = [name for name in named
               if not any(name.startswith(f'{ANDRIX_TREE}{directory}/') for directory in policy_dirs)]
    if outside:
        refuse(f'the expanded rule file was made from {", ".join(outside)}, which no policy '
               f'directory of {OWNER_POLICY} holds')
    return named


def patch_dirs_for(source_root, base_tag):
    """The base tag's reviewed patch directory. Each of its system/sepolicy records must name
    that tag as its base, so a record carried from another tag without review refuses."""
    release = caiman.parse_release(base_tag, allow_preview=False, what='base tag')
    relative = f'patches/grapheneos-{release.number}'
    base = Path(source_root) / relative
    if base.is_symlink() or not base.is_dir():
        refuse(f'base tag {release} has no reviewed patch directory {relative}')
    # each patch is applied through its record of the same name, which names its project
    unrecorded = sorted(path.name for path in base.glob('*.patch')
                        if not path.with_suffix('.json').is_file())
    if unrecorded:
        refuse(f'{relative} holds {", ".join(unrecorded)} without a record, so nothing tells '
               'which project it patches')
    for record_path in sorted(base.glob('*.json')):
        try:
            record = json.loads(record_path.read_text(encoding='utf-8'))
        except ValueError as error:
            refuse(f'{record_path.name} is not JSON: {error}')
        if isinstance(record, dict) and record.get('project') == 'system/sepolicy' and \
                record.get('base_release') != release.number:
            refuse(f'{relative}/{record_path.name} is for base {record.get("base_release")!r}, not '
                   f'{release}')
    return [relative]


def read_sources(source_root, policy_dirs, patch_dirs):
    """The Andrix policy files and system/sepolicy patches as (path, lines, record).

    A policy file has no record. Every record of a patch directory whose project is
    system/sepolicy is read, and its patch must hash to the record's patch_sha256.
    """
    root = Path(source_root)
    sources = []
    for directory in policy_dirs:
        base = root / directory
        if base.is_symlink() or not base.is_dir():
            refuse(f'the policy directory {directory} is not a directory of the source tree')
        for path in sorted(base.rglob('*')):
            if path.is_symlink():
                refuse(f'{path.relative_to(root).as_posix()} is a symbolic link')
            if path.is_file():
                sources.append((path.relative_to(root).as_posix(),
                                path.read_text(encoding='utf-8').split('\n'), None))
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
            sources.append((patch.relative_to(root).as_posix(), data.decode('utf-8').split('\n'),
                            record))
    return sources


def literal_rules(sources):
    """Every literal neverallow of the sources. For a patch, the text after an added line's +."""
    found = []
    for relative, lines, record in sources:
        for number, line in enumerate(lines, 1):
            if record is not None:
                if not line.startswith('+') or line.startswith('+++'):
                    continue
                line = line[1:]
            text = _uncommented(line)
            if _NEVERALLOWX.search(text):
                refuse(f'{relative}:{number} holds a literal extended permission rule, which '
                       'steps C to E cannot check')
            if _NEVERALLOW.search(text):
                found.append((relative, number, text.strip()))
    return found


def expanded_statements(text):
    """Each neverallow statement of an expanded rule file, comments removed, spaces collapsed."""
    flat = ' '.join('\n'.join(_uncommented(line) for line in text.split('\n')).split())
    return _STATEMENT.findall(flat)


def check_rule_sources(table, source_root, policy_dirs, patch_dirs, expanded, variant, corpus=False):
    """Step C. The witness table against the sources and against the expanded rule file.

    The expanded rule file must hold the variant's expansions. In corpus mode it is the user one,
    because the build expands that module for user only
    (system/sepolicy/build/soong/sepolicy_neverallow.go:96), so the user expansions are looked
    up in it and the variant's expansions are checked against the table alone.
    """
    if not policy_dirs:
        refuse('no Andrix policy directory was given')
    macros = {name: value.get('value') for name, value in (table.get('macros') or {}).items()
              if name != 'userdebug_or_eng'}
    if sorted(macros) != ['capability_class_set', 'no_x_file_perms'] or \
            not all(isinstance(value, str) for value in macros.values()):
        refuse('the witness table does not define exactly capability_class_set and no_x_file_perms')
    sources = read_sources(source_root, policy_dirs, patch_dirs)
    found = literal_rules(sources)
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
    in_file = 'user' if corpus else variant
    for entry in table['rules']:
        for checked in dict.fromkeys((variant, in_file)):
            wanted = expand(entry['rule'], checked, macros)
            if entry['expansion'][checked] != wanted:
                problems.append(f'rule {entry["number"]} records the {checked} expansion '
                                f'{entry["expansion"][checked]!r}, not {wanted!r}')
            elif checked == in_file and wanted not in statements:
                problems.append(f'the expanded rule file lacks rule {entry["number"]}: {wanted!r}')
    if problems:
        refuse('; '.join(problems))
    return {'sources': [relative for relative, _, _ in sources], 'rules': len(found),
            'expanded_neverallows': len(statements), 'expansions_in_file': in_file}


# -- Step C, changes to existing rules ---------------------------------------------------


def patch_files(lines, relative):
    """A unified patch's files, each with its hunks. Every line must belong to a file header
    or to a hunk, and each hunk must hold exactly the lines its header counts."""
    files = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == '' and index == len(lines) - 1:
            break
        if line.startswith('--- '):
            following = lines[index + 1] if index + 1 < len(lines) else ''
            old, new = line[4:], following[4:]
            if not following.startswith('+++ ') or not old.startswith('a/') or \
                    not new.startswith('b/') or old[2:] != new[2:]:
                refuse(f'{relative}:{index + 1} does not patch one file in place')
            files.append({'path': new[2:], 'hunks': []})
            index += 2
            continue
        match = _HUNK.fullmatch(line)
        if match is None or not files:
            refuse(f'{relative}:{index + 1} is neither a file header nor a hunk: {line[:80]!r}')
        old, old_count = int(match.group(1)), 1 if match.group(2) is None else int(match.group(2))
        new, new_count = int(match.group(3)), 1 if match.group(4) is None else int(match.group(4))
        hunk = {'line': index + 1, 'old': old, 'old_count': old_count, 'new': new,
                'new_count': new_count, 'old_lines': [], 'new_lines': [], 'removed': [], 'added': []}
        index += 1
        start = index
        position = old if old_count else old + 1
        while len(hunk['old_lines']) < old_count or len(hunk['new_lines']) < new_count:
            body = lines[index] if index < len(lines) else None
            if body is None or body[:1] not in ('-', '+', ' ') or \
                    (body[:1] == '-' and len(hunk['old_lines']) >= old_count) or \
                    (body[:1] == '+' and len(hunk['new_lines']) >= new_count):
                refuse(f'{relative}:{hunk["line"]} counts lines its hunk does not hold')
            text = body[1:]
            if body[0] != '+':
                hunk['old_lines'].append(text)
            if body[0] != '-':
                hunk['new_lines'].append(text)
            if body[0] == '-':
                hunk['removed'].append((index + 1, position, text))
            elif body[0] == '+':
                hunk['added'].append((index + 1, text))
            if body[0] != '+':
                position += 1
            index += 1
        if index < len(lines) and lines[index].startswith('\\'):
            refuse(f'{relative}:{index + 1} marks a missing final newline, which this check does '
                   'not place')
        hunk['body'] = lines[start:index]
        files[-1]['hunks'].append(hunk)
    return files


def apply_hunks(lines, hunks, relative):
    """The lines with the hunks applied in order. Each hunk's old lines must stand at its place."""
    out = []
    position = 0
    for hunk in hunks:
        start = hunk['old'] - 1 if hunk['old_count'] else hunk['old']
        old = hunk['old_lines']
        if start < position or lines[start:start + len(old)] != old:
            refuse(f'{relative}:{hunk["line"]} does not stand at its place in the file')
        out.extend(lines[position:start])
        if len(out) + (1 if hunk['new_count'] else 0) != hunk['new']:
            refuse(f'{relative}:{hunk["line"]} names a new position that does not follow from '
                   'the hunks before it')
        out.extend(hunk['new_lines'])
        position = start + len(old)
    return out + lines[position:]


def reversed_hunks(hunks):
    return [{'line': hunk['line'], 'old': hunk['new'], 'old_count': hunk['new_count'],
             'new': hunk['old'], 'new_count': hunk['old_count'], 'old_lines': hunk['new_lines'],
             'new_lines': hunk['old_lines']} for hunk in hunks]


def upstream_lines(tree, record, hunks, relative):
    """The patched file at the base tag, read from the tree and held to the record's digests.

    The tree may hold the upstream bytes or the adapted ones. Either way the patch applied to
    the upstream bytes must give the adapted bytes the record pins.
    """
    path = record.get('file')
    if (not isinstance(path, str) or PurePosixPath(path).is_absolute()
            or any(part in ('', '.', '..') for part in path.split('/'))):
        refuse(f'the record of {relative} names no file of system/sepolicy')
    for key in ('upstream_sha256', 'adapted_sha256'):
        if not isinstance(record.get(key), str) or caiman.SHA256.fullmatch(record[key]) is None:
            refuse(f'the record of {relative} holds no {key}')
    host = Path(tree) / 'system/sepolicy' / path
    if host.is_symlink() or not host.is_file():
        refuse(f'the tree holds no regular file system/sepolicy/{path}')
    if host.stat().st_size > SOURCE_LIMIT:
        refuse(f'system/sepolicy/{path} in the tree is larger than {SOURCE_LIMIT} bytes')
    data = host.read_bytes()
    digest = caiman.sha256(data)
    lines = data.decode('utf-8').split('\n')
    if digest == record['upstream_sha256']:
        upstream = lines
    elif digest == record['adapted_sha256']:
        upstream = apply_hunks(lines, reversed_hunks(hunks), relative)
        if caiman.sha256('\n'.join(upstream).encode()) != record['upstream_sha256']:
            refuse(f'{relative} taken back out of the adapted file does not give the upstream '
                   'file its record pins')
    else:
        refuse(f'system/sepolicy/{path} in the tree hashes to {digest}, which is neither the '
               f'upstream nor the adapted file that the record of {relative} pins')
    if caiman.sha256('\n'.join(apply_hunks(upstream, hunks, relative)).encode()) != \
            record['adapted_sha256']:
        refuse(f'{relative} applied to the upstream file does not give the adapted file its '
               'record pins')
    return upstream


def _m4_scan(lines, start=0, column=0):
    """m4's quote and parenthesis depth over the lines; a # outside quotes ends a line.

    Yields (line index, depth) each time a closing parenthesis outside quotes is read, and
    finally (None, (quote, depth, went_negative)).
    """
    quote = depth = 0
    negative = False
    for index in range(start, len(lines)):
        for char in lines[index][column if index == start else 0:]:
            if not quote and char == '#':
                break
            if char == '`':
                quote += 1
            elif char == "'" and quote:
                quote -= 1
            elif not quote and char == '(':
                depth += 1
            elif not quote and char == ')':
                depth -= 1
                negative = negative or depth < 0
                yield index, depth
    yield None, (quote, depth, negative)


def m4_balanced(lines):
    """True when the lines close every m4 quote and parenthesis they open, and no others."""
    for index, value in _m4_scan(lines):
        if index is None:
            quote, depth, negative = value
            return quote == 0 and depth == 0 and not negative
    return True


def rule_regions(lines):
    """The neverallow and neverallowxperm statements and the m4 macro definitions of a source
    file, each as (kind, first line, last line)."""
    regions = []
    start = None
    for number, raw in enumerate(lines, 1):
        code = _uncommented(raw)
        position = 0
        while True:
            if start is None:
                match = _RULE_KEYWORD.search(code, position)
                if match is None:
                    break
                start, position = number, match.end()
            end = code.find(';', position)
            if end < 0:
                break
            regions.append(('rule', start, number))
            start, position = None, end + 1
    if start is not None:
        regions.append(('rule', start, len(lines)))
    for number, raw in enumerate(lines, 1):
        for match in _DEFINITION.finditer(_uncommented(raw)):
            last = len(lines)
            for index, depth in _m4_scan(lines, number - 1, match.end() - 1):
                if index is not None and depth == 0:
                    last = index + 1
                    break
            regions.append(('definition', number, last))
    return regions


def m4_lex(lines, state=(0, 0)):
    """m4's view of the lines from a lexical state (quote depth, parenthesis depth outside
    quotes), with its default quotes ` and ' and its # comments, which it sees only outside
    quotes (a comment inside a quoted string is text). Returns each line's code without the
    comments m4 sees, the state after the lines, and whether the lines left the state they
    started in: closed a quote or a parenthesis opened before them, or added an argument to a
    macro call open around them. Every parenthesis outside quotes counts, which is at least as
    strict as m4, which counts them only inside a macro call.
    """
    quote, depth = state
    left = False
    code = []
    for line in lines:
        kept = []
        for char in line:
            if not quote and char == '#':
                break
            kept.append(char)
            if char == '`':
                quote += 1
            elif char == "'" and quote:
                quote -= 1
                left = left or quote < state[0]
            elif not quote and char in '(),':
                depth += {'(': 1, ')': -1}.get(char, 0)
                left = left or depth < state[1] or (char == ',' and depth == state[1] > 0)
                depth = max(depth, 0)
        code.append(''.join(kept))
    return code, (quote, depth), left


def m4_line_states(lines):
    """m4's lexical state at the start of each line of a file, and after its last line."""
    states = [(0, 0)]
    for line in lines:
        states.append(m4_lex([line], states[-1])[1])
    return states


def hunk_groups(hunk):
    """A hunk's changes: each run of removed and added lines, with the upstream index of its
    first removed line or of the line it is inserted before, the upstream lines it removes, and
    the patch line of its first line. Unchanged context lines are no change."""
    removed, added = iter(hunk['removed']), iter(hunk['added'])
    position = hunk['old'] - 1 if hunk['old_count'] else hunk['old']
    groups = []
    current = None
    for body in hunk['body']:
        if body[0] == ' ':
            position += 1
            current = None
            continue
        if current is None:
            current = {'position': position, 'removed': [], 'added': [], 'lines': []}
            groups.append(current)
        current['lines'].append(body)
        if body[0] == '-':
            line, old_line, text = next(removed)
            current['removed'].append((old_line, text))
            position += 1
        else:
            line, text = next(added)
            current['added'].append(text)
        current.setdefault('line', line)
    return groups


def group_change(group, states, regions):
    """What one change of a hunk alters that needs a record: (kind, upstream line of the rule),
    or None. It is judged with m4's lexical state at its place in the upstream file.

    A removed line that holds a neverallow is a removal. Blank lines and comments that m4 skips
    at the top level change nothing; inside a quoted string a # starts no comment, so such text
    is judged like any other. A change that names an m4 directive, that is not balanced in
    itself, or that leaves the quote and parenthesis state it starts in, changes m4's
    processing. A change inside a statement changes that rule, and one inside a macro
    definition changes m4's processing.
    """
    start = states[group['position']]
    removed = [text for _, text in group['removed']]
    added = group['added']
    removed_code, removed_end, removed_left = m4_lex(removed, start)
    added_code, added_end, added_left = m4_lex(added, start)
    for (old_line, _), code in zip(group['removed'], removed_code):
        if _RULE_KEYWORD.search(code):
            return 'removal', old_line
    if start[1] == 0 and not any(code.strip() for code in removed_code + added_code):
        return None
    if removed_left or added_left or removed_end != start or added_end != start or \
            not m4_balanced(removed) or not m4_balanced(added) or \
            any(_M4_DIRECTIVE.search(code) for code in removed_code + added_code):
        return 'm4', None
    if group['removed']:
        low, high = group['removed'][0][0], group['removed'][-1][0]

        def touches(first, last):
            return low <= last and first <= high
    else:
        after = group['position']      # inserted after this upstream line

        def touches(first, last):
            return first <= after < last
    for kind, first, last in regions:
        if touches(first, last):
            return ('inside' if kind == 'rule' else 'm4'), first
    return None


def rule_changes(sources, tree):
    """The changes to existing rules and to m4's processing that the sources make."""
    found = []
    for relative, lines, record in sources:
        if record is None:
            for number, code in enumerate(m4_lex(lines)[0], 1):
                if _M4_DIRECTIVE.search(code):
                    found.append({'source': relative, 'line': number, 'kind': 'm4',
                                  'file': relative, 'rule_line': None, 'lines': [lines[number - 1]]})
            continue
        files = patch_files(lines, relative)
        if [entry['path'] for entry in files] != [record.get('file')]:
            refuse(f'{relative} patches {", ".join(entry["path"] for entry in files) or "nothing"}, '
                   f'not only the file {record.get("file")!r} its record pins')
        hunks = files[0]['hunks']
        if tree is None:
            refuse('no GrapheneOS tree of the base tag was given, so the hunks of '
                   f'{relative} cannot be placed in the rules they change')
        upstream = upstream_lines(tree, record, hunks, relative)
        regions = rule_regions(upstream)
        states = m4_line_states(upstream)
        for hunk in hunks:
            for group in hunk_groups(hunk):
                change = group_change(group, states, regions)
                if change is None:
                    continue
                found.append({'source': relative, 'line': group['line'], 'kind': change[0],
                              'file': f'system/sepolicy/{record["file"]}', 'rule_line': change[1],
                              'lines': group['lines']})
    return found


def check_rule_changes(table, source_root, policy_dirs, patch_dirs, tree):
    """Step C, changes. A removed or changed rule, or a change to m4's processing, refuses
    unless the witness table records it exactly."""
    found = rule_changes(read_sources(source_root, policy_dirs, patch_dirs), tree)
    records = {(entry['source'], entry['line']): entry for entry in table['changes']}
    if len(records) != len(table['changes']):
        refuse('the witness table records one change twice')
    problems = []
    for change in found:
        entry = records.pop((change['source'], change['line']), None)
        where = f'{change["source"]}:{change["line"]}'
        if entry is None:
            at = f'{change["file"]}:{change["rule_line"]}'
            what = {'removal': f'removes a line of the rule at {at}',
                    'inside': f'changes the rule at {at}',
                    'm4': 'changes how m4 reads the policy'
                          + (f', inside the macro definition at {at}' if change['rule_line'] else '')}
            problems.append(f'{where} {what[change["kind"]]}, which the witness table does not '
                            f'record: {change["lines"]!r}')
            continue
        for key in ('kind', 'file', 'rule_line', 'lines'):
            if entry[key] != change[key]:
                problems.append(f'change {entry["number"]} records {key} {entry[key]!r}, but '
                                f'{where} gives {change[key]!r}')
    for entry in records.values():
        problems.append(f'change {entry["number"]} names {entry["source"]}:{entry["line"]}, '
                        'which changes no existing rule')
    if problems:
        refuse('; '.join(problems))
    return {'changes': [{'source': change['source'], 'line': change['line'], 'kind': change['kind'],
                         'rule': f'{change["file"]}:{change["rule_line"]}'} for change in found]}


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


def check_userdebug_exception(tools, policy, table, work):
    """Corpus step D on a userdebug policy: the user rules fail with exactly the one violation
    that rule 11's userdebug exception allows."""
    result = analyze(tools, policy, [entry['expansion']['user'] for entry in table['rules']], work,
                     'andrix_user')
    _, warnings = violations_and_warnings(result, 'corpus')
    if result['status'] == 0 or warnings or result['violations'] != [USERDEBUG_EXCEPTION]:
        refuse(f'the user rules must fail on a userdebug corpus with exactly {USERDEBUG_EXCEPTION!r}; '
               f'sepolicy-analyze exited {result["status"]} with {result["violations"]!r} and '
               f'{len(warnings)} warnings')
    return {'command': result['command'], 'violations': result['violations']}


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
    """The official release's loaded policy and CIL files, read as init would read them, with
    its hash pairs checked as in step A. An official release is a user build."""
    if inputs.has(ODM_PRECOMPILED):
        refuse(f'the official inputs carry {ODM_PRECOMPILED}; caiman has no odm partition')
    state = {}
    try:
        check_loaded_policy(inputs, 'user', state)
    except Refusal as error:
        refuse(f'the official policy: {error}')
    return state['policy'], state['cil_files']


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
# Generated attribute names: base_typeattr_N in the platform and system_ext files,
# base_typeattr_N_V in the vendor's versioned files
_GENERATED = re.compile(_WORD.format(r'base_typeattr_[0-9]+(?:_[0-9]+)?'))
_GENERATED_NAME = re.compile(r'base_typeattr_[0-9]+(?:_[0-9]+)?')
_TWICE = object()
# The CIL lexer's tokens (external/selinux/libsepol/cil/src/cil_lexer.l:48-65): white space may
# stand between any two tokens, a quoted string is one token that holds no line feed but may hold
# a carriage return, ; is a comment token, and any other character is invalid outside a comment
_CIL_SYMBOL = r"[0-9A-Za-z\[\].@=/*\-_$%+!|&^:~`#{}'<>?,]+"
_CIL_TOKEN = re.compile(r'(?P<newline>[\n\r])|(?P<comment>;)|(?P<open>\()|(?P<close>\))'
                        rf'|(?P<symbol>{_CIL_SYMBOL})|(?P<white>[ \t]+)|(?P<string>"[^"\n\0]*")'
                        r'|(?P<unknown>.)', re.S)
_STRING = object()


def cil_lists(text, phone):
    """The typeattributeset lists of one CIL file, read from its tokens as secilc's parser reads
    them (external/selinux/libsepol/cil/src/cil_parser.c:238-312). A quoted string is one atom
    and never code; it stands for the name it quotes, or for _STRING when it is no name. A comment
    ends at the next newline token, not at the next carriage return character: the parser skips
    whole tokens after ; (:283-291), and a quoted string, which may hold a carriage return, is one
    of them. A parenthesis without its partner, an atom outside parentheses and an invalid
    character outside a comment refuse.
    """
    found = []
    stack = []      # each open list: [first atom, False when it starts with a list, or None; items]
    commented = False
    for match in _CIL_TOKEN.finditer(text):
        kind = match.lastgroup
        if commented:
            commented = kind != 'newline'
            continue
        if kind == 'comment':
            commented = True
            continue
        if kind in ('newline', 'white'):
            continue
        if kind == 'unknown':
            refuse(f'{phone} holds {match.group()!r}, which is no CIL token')
        if kind == 'open':
            parent = stack[-1] if stack else None
            items = [] if parent is not None and parent[1] is not None else None
            if parent is not None:
                if parent[0] is None:
                    parent[0] = False
                if items is not None:
                    parent[1].append(items)
            stack.append([None, items])
            continue
        if kind == 'close':
            if not stack:
                refuse(f'{phone} closes a parenthesis that it never opened')
            head, items = stack.pop()
            if head == 'typeattributeset' and items is not None and (not stack or stack[-1][1] is None):
                found.append(items)
            continue
        value = match.group() if kind == 'symbol' else match.group()[1:-1]
        if kind == 'string' and re.fullmatch(_CIL_SYMBOL, value) is None:
            value = _STRING
        if not stack:
            refuse(f'{phone} holds {match.group()!r} outside parentheses')
        frame = stack[-1]
        if frame[0] is None:
            frame[0] = value
            if value == 'typeattributeset' and frame[1] is None:
                frame[1] = []
        if frame[1] is not None:
            frame[1].append(value)
    for head, items in stack:
        if head == 'typeattributeset' and items and len(items) > 1 and isinstance(items[1], str):
            refuse(f'{phone} does not close the definition of {items[1]}')
    if stack:
        refuse(f'{phone} does not close a parenthesis that it opens')
    return found


def _cil_text(expression, phone, name):
    if expression is _STRING:
        refuse(f'{phone} defines {name} with a quoted string that is no name')
    if isinstance(expression, str):
        return expression
    return '(' + ' '.join(_cil_text(item, phone, name) for item in expression) + ')'


def generated_definitions(files, inputs):
    """Each generated attribute's typeattributeset expression in the run's own CIL files, read
    from their tokens, each written with one space between its tokens."""
    definitions = {}
    for phone in files:
        for items in cil_lists(inputs.read(phone, POLICY_LIMIT).decode('utf-8'), phone):
            name = items[1] if len(items) > 1 else None
            if not isinstance(name, str) or _GENERATED_NAME.fullmatch(name) is None:
                continue
            if len(items) != 3 or not isinstance(items[2], list):
                refuse(f'{phone} defines {name} with an expression that is not a list')
            expression = _cil_text(items[2], phone, name)
            definitions[name] = _TWICE if name in definitions else expression
    return definitions


def expand_generated(text, definitions, name, cache=None):
    """The text with each generated attribute replaced by its expression, recursively."""
    cache = {} if cache is None else cache

    def resolve(attribute, chain):
        if attribute in chain:
            refuse(f'the {name} files define {attribute} through itself: '
                   f'{" -> ".join(chain + (attribute,))}')
        if attribute not in cache:
            expression = definitions.get(attribute)
            if expression is None:
                refuse(f'the {name} files hold no typeattributeset for {attribute}')
            if expression is _TWICE:
                refuse(f'the {name} files define {attribute} more than once')
            cache[attribute] = _GENERATED.sub(lambda m: resolve(m.group(0), chain + (attribute,)),
                                              expression)
        return cache[attribute]
    return _GENERATED.sub(lambda m: resolve(m.group(0), ()), text)


def parse_pairs(text, name, definitions):
    """secilc's violation reports as pairs of the violated rule and one offending rule, without
    places, each generated attribute replaced by its own definition."""
    pairs = set()
    cache = {}
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
                allows.append(text)
            elif text.startswith('Only first'):
                refuse(f'secilc on the {name} files shortened its report: {text!r}')
            index += 1
        if not rule.startswith('(neverallow') or not allows:
            refuse(f'secilc on the {name} files printed a violation of unknown form: {rule!r}')
        violated = expand_generated(rule, definitions, name, cache)
        for allow in allows:
            pairs.add((violated, expand_generated(allow, definitions, name, cache)))
    return pairs


def secilc_pairs(tools, files, inputs, work, name):
    """secilc without -N, with the build's check flags: one pair per violated and offending rule."""
    host = [str(inputs.path(phone)) for phone in files]
    command = [tools['secilc'], '-m', '-M', 'true', '-G', '-c', POLICY_VERSION, *host,
               '-o', os.devnull, '-f', os.devnull, '-v']
    status, output, errors = run_tool(command, cwd=work)
    pairs = parse_pairs(output + errors, name, generated_definitions(files, inputs))
    if status != 0 and not pairs:
        refuse(f'secilc without -N on the {name} files exited {status}: {errors.strip()[-300:]!r}')
    return pairs


def check_extended_rules(tools, inputs, files, official_inputs, official_files, work):
    """Step G. Every neverallow and neverallowx of the CIL files, against the official run."""
    ours = secilc_pairs(tools, files, inputs, work, 'Andrix')
    theirs = secilc_pairs(tools, official_files, official_inputs, work, 'official')
    new = sorted(ours - theirs)
    if new:
        refuse('violated rules the official files do not show: '
               + '; '.join(f'{rule} by {allow}' for rule, allow in new[:10]))
    return {'pairs': len(ours), 'vendor_findings': sorted({rule for rule, _ in ours & theirs})}


def check_corpus_extended_rules(tools, inputs, files, work):
    """Corpus step G. The corpus build checked neverallows, so its files violate no rule."""
    pairs = secilc_pairs(tools, files, inputs, work, 'corpus')
    if pairs:
        refuse('the corpus files violate rules: '
               + '; '.join(f'{rule} by {allow}' for rule, allow in sorted(pairs)[:10]))
    return {'pairs': 0}


def read_expanded(path):
    """The expanded rule file's text. A file that cannot be read refuses with its reason."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            refuse(f'the expanded rule file {path} is not a regular file')
        if path.stat().st_size > POLICY_LIMIT:
            refuse(f'the expanded rule file is larger than {POLICY_LIMIT} bytes')
        return path.read_bytes().decode('utf-8')
    except OSError as error:
        refuse(f'the expanded rule file cannot be read: {error}')
    except UnicodeDecodeError as error:
        refuse(f'the expanded rule file is not UTF-8 text: {error}')


# -- Provenance: the release record and the verified images ------------------------------


def load_release_record(path):
    """The release record that the release wrapper completes (design item 6): the base tag and
    the SHA-256 of the install zip and of the expanded rule file (design item 2, output 3)."""
    try:
        record = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        refuse(f'the release record cannot be read: {error}')
    if not isinstance(record, dict) or record.get('schema') != RELEASE_SCHEMA:
        refuse(f'the release record is not {RELEASE_SCHEMA}')
    tag = caiman.parse_release(record.get('base_tag'), allow_preview=False,
                               what='the release record base tag')
    artifacts = record.get('artifacts')
    digests = {}
    for name in ('install_zip', 'expanded_rule_file'):
        entry = artifacts.get(name) if isinstance(artifacts, dict) else None
        digest = entry.get('sha256') if isinstance(entry, dict) else None
        if not isinstance(digest, str) or caiman.SHA256.fullmatch(digest) is None:
            refuse(f'the release record names no SHA-256 of {name}')
        digests[name] = digest
    return tag.number, digests


_DEBUGFS_BANNER = re.compile(r'debugfs [0-9][0-9.]* \([^)]*\)')
# Where each partition's policy files lie in its ext4 image. The system image holds the root,
# with the system partition under /system.
IMAGE_POLICY = (('system', '/system/etc/selinux'), ('system_ext', '/etc/selinux'),
                ('product', '/etc/selinux'), ('vendor', '/etc/selinux'))


def pinned_debugfs(path):
    """debugfs, pinned in install_zip.py with the verified kit's other image readers."""
    if install_zip.DEBUGFS_SHA256 is None:
        refuse('debugfs is not pinned yet, so no file of an install zip is read')
    return pinned_tools({'debugfs': path}, {'debugfs': install_zip.DEBUGFS_SHA256})['debugfs']


def _debugfs(debugfs, image, request):
    """debugfs on one image, and its messages besides its banner. debugfs exits 0 even when a
    path is missing, so the caller judges the messages."""
    status, output, errors = run_tool([debugfs, '-R', request, image])
    messages = [line.strip() for line in errors.split('\n')
                if line.strip() and _DEBUGFS_BANNER.fullmatch(line.strip()) is None]
    if status != 0:
        refuse(f'debugfs {request.split()[0]} on {Path(image).name} exited {status}: {messages[:3]!r}')
    return output, messages


def read_image_policy(debugfs, images, destination):
    """The files init reads for its policy, out of the verified ext4 images, laid out as on the
    phone under destination: each partition's etc/selinux and /system/build.prop."""
    debugfs = pinned_debugfs(debugfs)
    images, destination = Path(images), Path(destination)
    if any(char.isspace() or char in '"\'\\' for char in str(destination)):
        refuse(f'{destination} holds a space or a quote, which a debugfs request cannot carry')
    reads = [(images / f'{partition}.img', inside, destination / partition / 'etc')
             for partition, inside in IMAGE_POLICY]
    # odm: its own image, or else the vendor image's /odm, where /odm/etc leads without one
    # (build/make/core/board_config.mk:841-846, system/core/rootdir/create_root_structure.mk:76-87)
    if (images / 'odm.img').is_file():
        reads.append((images / 'odm.img', '/etc/selinux', destination / 'odm/etc'))
    for image, _, _ in reads:
        if image.is_symlink() or not image.is_file():
            refuse(f'the verified images hold no {image.name}')
    if not (images / 'odm.img').is_file():
        _, messages = _debugfs(debugfs, images / 'vendor.img', 'stat /odm/etc/selinux')
        if not messages:
            reads.append((images / 'vendor.img', '/odm/etc/selinux', destination / 'odm/etc'))
        elif messages != ['/odm/etc/selinux: File not found by ext2_lookup']:
            refuse(f'debugfs cannot tell whether vendor.img holds /odm/etc/selinux: {messages[:3]!r}')
    for image, inside, target in reads:
        target.mkdir(parents=True)
        _, messages = _debugfs(debugfs, image, f'rdump {inside} {target}')
        if messages or not (target / 'selinux').is_dir():
            refuse(f'debugfs could not read {inside} out of {image.name}: {messages[:3]!r}')
    build_prop = destination / 'system/build.prop'
    _, messages = _debugfs(debugfs, images / 'system.img', f'dump /system/build.prop {build_prop}')
    if messages or not build_prop.is_file():
        refuse(f'debugfs could not read /system/build.prop out of system.img: {messages[:3]!r}')
    return destination


def gate(zip_path, *, official_kit, release_record, expanded, variant, tools, kit, tree,
         witnesses=WITNESSES, source_root=ROOT, scratch=None):
    """The gate on an Andrix install zip: PASS only if its provenance and every step pass.

    kit holds what install_zip.py needs to verify both zips (avbtool, simg2img, lpunpack, the
    allowed signers, the kit's signature, caiman-stable, the base tag's adevtool record and the
    base records) and debugfs. The base tag is the zip's signed com.andrix.build.base_tag
    property. The zip and the expanded rule file must hash to the release record's digests, and
    the official kit must pass install_zip.py's checks for that tag. Both policies are read only
    out of the images that install_zip.py verified.
    """
    if variant not in VARIANTS:
        return _finish({'variant': {'ok': False, 'reason': f'variant {variant!r} is not one of '
                                                           f'{", ".join(VARIANTS)}'}}, 'gate')
    checks = {}
    state = {}
    images = {'simg2img': kit.get('simg2img'), 'lpunpack': kit.get('lpunpack')}

    def run(name, function):
        try:
            checks[name] = {'ok': True, **function()}
        except (Refusal, OSError, UnicodeDecodeError) as error:
            checks[name] = {'ok': False, 'reason': str(error)}

    work = Path(tempfile.mkdtemp(prefix='neverallow-gate-', dir=scratch))
    try:
        def record():
            state['record'] = load_release_record(release_record)
            return {'base_tag': state['record'][0], 'sha256': state['record'][1]}

        def image():
            if 'record' not in state:
                refuse('the release record did not pass, so the zip is bound to no build')
            keep = work / 'andrix-images'
            keep.mkdir()
            identity = install_zip.andrix_identity(zip_path, avbtool=kit.get('avbtool'), tools=images,
                                                   scratch=work, bases=kit.get('bases'), keep=keep)
            tag, digests = state['record']
            if identity['sha256'] != digests['install_zip']:
                refuse(f'the zip hashes to {identity["sha256"]}, not the {digests["install_zip"]} '
                       'that the release record names')
            if identity['base_tag'] != tag:
                refuse(f'the zip carries the signed base tag {identity["base_tag"]}, not the '
                       f'release record\'s {tag}')
            partitions = read_image_policy(kit.get('debugfs'), keep, work / 'andrix')
            state['inputs'], state['tag'] = Inputs.from_directory(partitions), tag
            return {'sha256': identity['sha256'], 'base_tag': tag}

        def expanded_file():
            if 'record' not in state:
                refuse('the release record did not pass, so the expanded rule file is bound to '
                       'no build')
            # read once: the steps check the very text whose digest the record names
            text = read_expanded(expanded)
            digest = caiman.sha256(text.encode('utf-8'))
            wanted = state['record'][1]['expanded_rule_file']
            if digest != wanted:
                refuse(f'the expanded rule file hashes to {digest}, not the {wanted} that the '
                       'release record names')
            state['expanded'] = text
            return {'sha256': digest}

        def official():
            if 'tag' not in state:
                refuse('the zip did not pass, so its base tag is not known')
            keep = work / 'official-images'
            keep.mkdir()
            report = install_zip.check(official_kit, signature=kit.get('signature') or
                                       f'{official_kit}.sig', signers=kit.get('signers'),
                                       release=state['tag'], stable=kit.get('stable'),
                                       record=kit.get('record'), avbtool=kit.get('avbtool'),
                                       tools=images, scratch=work, bases=kit.get('bases'),
                                       keep=keep)
            if report['verdict'] != 'PASS':
                refuse('the official kit does not pass install_zip.py: '
                       + '; '.join(report['reasons'][:6]))
            partitions = read_image_policy(kit.get('debugfs'), keep, work / 'official')
            state['official'] = Inputs.from_directory(partitions)
            return {'sha256': report['sha256'], 'release': state['tag']}

        run('release_record', record)
        run('image', image)
        run('expanded_rule_file', expanded_file)
        run('official_kit', official)
        if 'inputs' in state:
            bound = state.get('expanded', Refusal(UNBOUND_EXPANDED))
            checks.update(_checks(state['inputs'], corpus=False, expanded=expanded, variant=variant,
                                  tools=tools, witnesses=witnesses, source_root=source_root,
                                  base_tag=state['tag'], tree=tree, scratch=work,
                                  official=state.get('official'), bound=bound, image=True))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return _finish(checks, 'gate')


# -- The whole check ---------------------------------------------------------------------


def _checks(inputs, *, corpus, expanded, variant, tools, witnesses, source_root, base_tag, tree,
            scratch, official, bound=None, image=False):
    """Every step of the policy check or of corpus mode, each with its result. The pins, the
    policy directories and the patch set all follow from the base tag and the source tree.

    bound is the expanded rule file's text that the gate bound to the release record, or the
    refusal that left it unbound. No step then reads the file again. image is true for the gate,
    whose tool set must serve an image.
    """
    checks = {}
    state = {} if bound is None else {'expanded': bound}

    def run(name, function):
        try:
            checks[name] = {'ok': True, **function()}
        except (Refusal, OSError, UnicodeDecodeError) as error:
            checks[name] = {'ok': False, 'reason': str(error)}

    def tool_set():
        if 'tools' not in state:
            state['tools'] = pinned_tools(tools, tool_pins(base_tag, image))
        return state['tools']

    def expanded_text():
        if 'expanded' not in state:
            try:
                state['expanded'] = read_expanded(expanded)
            except Refusal as error:
                state['expanded'] = error
        if isinstance(state['expanded'], Refusal):
            refuse(str(state['expanded']))
        return state['expanded']

    work = Path(tempfile.mkdtemp(prefix='neverallow-', dir=scratch))
    try:
        run('tools', lambda: {'pinned': sorted(tool_set())})

        def loaded():
            if corpus:
                return check_corpus_policy(inputs, variant, state)
            return check_loaded_policy(inputs, variant, state)

        def owner():
            if 'policy' not in state:
                refuse('step A found no precompiled policy')
            return check_owner_domains(tool_set(), state['policy'])

        def rules():
            table = load_witnesses(witnesses)
            text = expanded_text()
            policy_dirs = owner_policy_dirs(source_root)
            patch_dirs = patch_dirs_for(source_root, base_tag)
            problems = []
            detail = {'policy_dirs': policy_dirs, 'patch_dirs': patch_dirs}
            for name, function in (
                    ('expanded_sources', lambda: check_expanded_sources(text, policy_dirs)),
                    ('sources', lambda: check_rule_sources(table, source_root, policy_dirs,
                                                           patch_dirs, text, variant, corpus)),
                    ('changes', lambda: check_rule_changes(table, source_root, policy_dirs,
                                                           patch_dirs, tree))):
                try:
                    detail[name] = function()
                except Refusal as error:
                    problems.append(str(error))
            if problems:
                refuse('; '.join(problems))
            state['table'] = table
            return detail

        def on_policy():
            if 'policy' not in state:
                refuse('step A found no precompiled policy')
            if 'table' not in state:
                refuse('step C did not pass, so the rules are not known')
            rules = [entry['expansion'][variant] for entry in state['table']['rules']]
            detail = check_rules_on_policy(tool_set(), state['policy'], rules, work)
            if corpus and variant == 'userdebug':
                detail['user_rules'] = check_userdebug_exception(tool_set(), state['policy'],
                                                                 state['table'], work)
            return detail

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
            rules = aosp_rules(expanded_text(), state['table'], variant)
            return check_aosp_rules(tool_set(), state['policy'], official_policy, rules, work)

        def extended():
            if corpus:
                if not checks.get('A_loaded_policy', {}).get('ok'):
                    refuse('step A did not pass, so the CIL files are not those of the loaded policy')
                return check_corpus_extended_rules(tool_set(), inputs, state['cil_files'], work)
            _, official_files = official_set()
            if not checks.get('A_loaded_policy', {}).get('ok'):
                refuse('step A did not pass, so the CIL files are not those of the loaded policy')
            return check_extended_rules(tool_set(), inputs, state['cil_files'], official,
                                        official_files, work)

        if not corpus:
            run('F_aosp_rules', aosp)
        run('G_extended_rules', extended)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return checks


def check(inputs, *, expanded, variant, tools, base_tag, witnesses=WITNESSES, source_root=ROOT,
          tree=None, scratch=None, official=None):
    """The policy steps on partition files the caller laid out: PASS only if every step passes.
    This is not the gate, which reads the files only out of the verified install zips."""
    if variant not in VARIANTS:
        return _finish({'variant': {'ok': False, 'reason': f'variant {variant!r} is not one of '
                                                           f'{", ".join(VARIANTS)}'}})
    return _finish(_checks(inputs, corpus=False, expanded=expanded, variant=variant, tools=tools,
                           witnesses=witnesses, source_root=source_root, base_tag=base_tag,
                           tree=tree, scratch=scratch, official=official))


def corpus_check(inputs, *, expanded, variant, tools, base_tag, witnesses=WITNESSES,
                 source_root=ROOT, tree=None, scratch=None):
    """Corpus mode: CORPUS when every corpus step passes, REFUSE otherwise, never PASS."""
    if variant not in VARIANTS:
        return _finish_corpus({'variant': {'ok': False, 'reason': f'variant {variant!r} is not '
                                                                  f'one of {", ".join(VARIANTS)}'}})
    return _finish_corpus(_checks(inputs, corpus=True, expanded=expanded, variant=variant,
                                  tools=tools, witnesses=witnesses, source_root=source_root,
                                  base_tag=base_tag, tree=tree, scratch=scratch, official=None))


def _reasons(checks):
    return [f'{name}: {result["reason"]}' for name, result in checks.items() if not result['ok']]


def _finish(checks, mode='policy'):
    reasons = _reasons(checks)
    return {'mode': mode, 'verdict': 'PASS' if not reasons else 'REFUSE', 'reasons': reasons,
            'checks': checks}


def _finish_corpus(checks):
    reasons = _reasons(checks)
    return {'mode': 'corpus', 'verdict': 'CORPUS' if not reasons else 'REFUSE', 'reasons': reasons,
            'checks': checks, 'not_run': {'F_aosp_rules': NO_OFFICIAL_RELEASE},
            'admits': 'nothing; a corpus run shows the tool works on a real policy, not that a '
                      'caiman image may be flashed'}


# Each mode's own options, which it needs, and those it refuses because it takes them elsewhere
NEEDS = {
    'gate': ('zip', 'official_kit', 'release_record', 'expanded', 'variant', 'grapheneos_tree',
             'allowed_signers', 'stable', 'record', 'avbtool', 'simg2img', 'lpunpack', 'debugfs',
             'sepolicy_analyze', 'secilc', 'checkpolicy'),
    'corpus': ('partitions', 'base_tag', 'expanded', 'variant', 'grapheneos_tree',
               'sepolicy_analyze', 'secilc', 'checkpolicy'),
    'build-tools': ('base_tag',),
}
REFUSES = {
    'gate': {'partitions': 'the gate reads the policy files only out of the verified install zips',
             'base_tag': "the gate reads the base tag only from the zip's signed property",
             'official': "the gate reads the official policy only through install_zip.py's "
                         'verified kit, --official-kit'},
    'corpus': {'official': f'corpus mode compares with no official policy, because '
                           f'{NO_OFFICIAL_RELEASE}',
               'official_kit': f'corpus mode compares with no official policy, because '
                               f'{NO_OFFICIAL_RELEASE}',
               'zip': 'corpus mode reads no install zip', 'release_record': 'corpus mode binds no '
               'release record', 'build_tools': 'corpus mode and --build-tools are separate'},
    'build-tools': {'corpus': 'corpus mode and --build-tools are separate'},
}
# What no mode takes from its caller. The lists come from the source tree, so a caller cannot
# leave out a directory or a patch that holds an Andrix rule, and single files cannot show what
# the partitions do not hold.
CALLER_LISTS = {
    'policy_dir': f'the Andrix policy directories come only from {OWNER_POLICY}',
    'patches': 'the patch set comes only from the base tag, patches/grapheneos-TAG',
    'file': 'single files cannot show what the partitions do not hold',
}


def main(argv=None):
    # argparse's own help exits 0 at once, so help is an ordinary option here
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0], add_help=False)
    parser.add_argument('-h', '--help', action='store_true',
                        help='show this help; with --corpus it exits 1, because corpus mode never '
                        'exits 0')
    parser.add_argument('--corpus', action='store_true',
                        help='corpus mode, on a product that is not a caiman image; it never '
                        f'passes and exits {CORPUS_EXIT} for CORPUS or 1 for REFUSE')
    parser.add_argument('--build-tools', metavar='DIR', help="the release wrapper's check: the "
                        "build's own host tools in DIR against the base tag's reviewed set")
    parser.add_argument('--zip', help='the gate: the Andrix install zip to be flashed')
    parser.add_argument('--official-kit', help='the gate: the official install zip of the base tag')
    parser.add_argument('--official-kit-sig', help="the official kit's signature; default KIT.sig")
    parser.add_argument('--release-record', help="the gate: the build's release record")
    parser.add_argument('--allowed-signers', help='the allowed signers file that upstream/bases pins')
    parser.add_argument('--stable', help='caiman-stable, saved fresh with curl -o')
    parser.add_argument('--record', help="the base tag's adevtool record")
    parser.add_argument('--avbtool', help='external/avb/avbtool.py of the pinned tree')
    parser.add_argument('--simg2img', help='the pinned simg2img, to rebuild the super splits')
    parser.add_argument('--lpunpack', help='the pinned lpunpack, to rebuild the super splits')
    parser.add_argument('--debugfs', help='the pinned debugfs, to read files out of the images')
    parser.add_argument('--partitions', help='corpus mode: a directory of partition files, laid '
                        'out as on the phone: DIR/system/etc/selinux, DIR/vendor/etc/selinux and so on')
    parser.add_argument('--base-tag', help='corpus mode and --build-tools: the base tag; the gate '
                        "reads it from the zip's signed property")
    parser.add_argument('--expanded', help="the build's sepolicy_neverallows.sepolicy_analyze.conf")
    parser.add_argument('--variant', choices=VARIANTS)
    parser.add_argument('--witnesses', default=str(WITNESSES))
    parser.add_argument('--source-root', default=str(ROOT), help='the Andrix commit that was built')
    parser.add_argument('--grapheneos-tree', help='the GrapheneOS source tree of the base tag; only '
                        'the system/sepolicy files that patch records pin are read')
    parser.add_argument('--sepolicy-analyze')
    parser.add_argument('--secilc')
    parser.add_argument('--checkpolicy')
    parser.add_argument('--scratch', help='a directory for work files')
    for option, metavar in (('--policy-dir', 'DIR'), ('--patches', 'DIR'),
                            ('--file', 'PHONE_PATH=HOST_PATH')):
        name = option[2:].replace('-', '_')
        parser.add_argument(option, action='append', metavar=metavar,
                            help=f'refused: {CALLER_LISTS[name]}')
    parser.add_argument('--official', help="refused: the official policy is read only through "
                        "install_zip.py's verified kit")
    args = parser.parse_args(argv)
    if args.help:
        parser.print_help()
        # corpus mode never exits 0, not even for its help
        return 1 if args.corpus else 0
    mode = 'build-tools' if args.build_tools else 'corpus' if args.corpus else 'gate'
    tools = {'sepolicy-analyze': args.sepolicy_analyze, 'secilc': args.secilc,
             'checkpolicy': args.checkpolicy}
    refused = 1
    try:
        for name, reason in {**CALLER_LISTS, **REFUSES[mode]}.items():
            if getattr(args, name):
                refuse(f'--{name.replace("_", "-")} is refused: {reason}')
        for name in NEEDS[mode]:
            if not getattr(args, name):
                refuse(f'{mode} needs --{name.replace("_", "-")}')
        if mode == 'build-tools':
            report = {'mode': mode, 'verdict': 'PASS', 'reasons': [],
                      'checks': {'tools': {'ok': True, **check_build_tools(args.base_tag,
                                                                           args.build_tools)}}}
            sys.stdout.write(caiman.dump(report))
            return 0
        if mode == 'corpus':
            inputs = Inputs.from_directory(args.partitions)
        else:
            try:
                record = json.loads(Path(args.record).read_text(encoding='utf-8'))
            except (OSError, ValueError) as error:
                refuse(f'the adevtool record cannot be read: {error}')
    except Refusal as error:
        sys.stdout.write(caiman.dump({'mode': mode, 'verdict': 'REFUSE', 'reasons': [str(error)],
                                      'checks': {}}))
        return refused
    options = dict(expanded=args.expanded, variant=args.variant, tools=tools,
                   witnesses=args.witnesses, source_root=args.source_root,
                   tree=args.grapheneos_tree, scratch=args.scratch)
    if mode == 'corpus':
        report = corpus_check(inputs, base_tag=args.base_tag, **options)
        sys.stdout.write(caiman.dump(report))
        # corpus mode never exits 0, whatever its report says
        return CORPUS_EXIT if report.get('verdict') == 'CORPUS' else refused
    kit = {'avbtool': args.avbtool, 'simg2img': args.simg2img, 'lpunpack': args.lpunpack,
           'debugfs': args.debugfs, 'signers': args.allowed_signers, 'stable': args.stable,
           'signature': args.official_kit_sig, 'record': record}
    report = gate(args.zip, official_kit=args.official_kit, release_record=args.release_record,
                  kit=kit, **options)
    sys.stdout.write(caiman.dump(report))
    return 0 if report['verdict'] == 'PASS' and report.get('mode') == 'gate' else refused


if __name__ == '__main__':
    sys.exit(main())
