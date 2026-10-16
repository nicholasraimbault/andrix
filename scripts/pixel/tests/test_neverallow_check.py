# SPDX-License-Identifier: Apache-2.0
"""The neverallow check, steps A to G and corpus mode, on small SYNTHETIC CIL policies. No
phone, no build.

fixtures/neverallow/partitions holds the CIL files of a synthetic split policy, laid out as on
the phone. Each case copies them into a temporary directory, compiles the precompiled policy
with the pinned secilc in the build's file order and writes the hash files the build would.

Steps B and D to G need sepolicy-analyze, secilc and checkpolicy from the host output of the
pinned tree. Name that tree with ANDRIX_PIXEL_TREES (2026081300=TREE). Without it those cases
skip, and the cases of steps A and C run alone, on synthetic sources where step C needs the
upstream system/sepolicy. With it, the witness table is also checked against the expanded rule
file in that tree's output, when the file is there, and the bridge patch is placed in the
upstream domain.te of each named tree.
"""
import contextlib
import copy
import difflib
import gc
import itertools
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from caiman import Refusal  # noqa: E402
import neverallow_check as nc  # noqa: E402
sys.path.append(str(Path(__file__).resolve().parents[2] / 'proof'))
import grapheneos_base  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'neverallow' / 'partitions'
TABLE = json.loads(nc.WITNESSES.read_text(encoding='utf-8'))
POLICY_DIRS = ['sepolicy/private', 'owner/sepolicy', 'owner/platform/sepolicy']
PATCHES = ['patches/grapheneos-2026081300']
TREES = dict(item.split('=', 1) for item in os.environ.get('ANDRIX_PIXEL_TREES', '').split(':')
             if '=' in item)
PINNED_TREE = TREES.get('2026081300')
BIN = Path(PINNED_TREE) / 'out/host/linux-x86/bin' if PINNED_TREE else None
TOOLS = {name: str(BIN / name) for name in nc.PINS} if BIN else {}
HAVE_TOOLS = bool(BIN) and all(Path(path).is_file() for path in TOOLS.values())
# mke2fs and debugfs of the pinned tree make and read the ext4 images that stand for an install
# zip's verified images
HAVE_E2FS = bool(BIN) and (BIN / 'mke2fs').is_file() and (BIN / 'debugfs').is_file()
DEBUGFS_DIGEST = hashlib.sha256((BIN / 'debugfs').read_bytes()).hexdigest() if HAVE_E2FS else None
EXPANDED_IN_TREE = (Path(PINNED_TREE) / 'out/soong/.intermediates/system/sepolicy/'
                    'sepolicy_neverallows.sepolicy_analyze.conf/android_common/'
                    'sepolicy_neverallows.sepolicy_analyze.conf') if PINNED_TREE else None
# The build's order (system/sepolicy/Android.bp:680-732), not init's
BUILD_ORDER = ['system/etc/selinux/plat_sepolicy.cil', 'system_ext/etc/selinux/system_ext_sepolicy.cil',
               'product/etc/selinux/product_sepolicy.cil',
               'system/etc/selinux/plat_sepolicy_genfs_202504.cil',
               'vendor/etc/selinux/plat_pub_versioned.cil', 'vendor/etc/selinux/vendor_sepolicy.cil',
               'system/etc/selinux/mapping/202404.cil', 'system_ext/etc/selinux/mapping/202404.cil',
               'product/etc/selinux/mapping/202404.cil']
HASHES = [('system/etc/selinux/plat_sepolicy_and_mapping.sha256', 'system/etc/selinux/plat_sepolicy.cil',
           'system/etc/selinux/mapping/202404.cil'),
          ('system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256',
           'system_ext/etc/selinux/system_ext_sepolicy.cil', 'system_ext/etc/selinux/mapping/202404.cil'),
          ('product/etc/selinux/product_sepolicy_and_mapping.sha256',
           'product/etc/selinux/product_sepolicy.cil', 'product/etc/selinux/mapping/202404.cil')]


def write_hashes(partitions, directory=None):
    directory = directory or partitions / 'vendor/etc/selinux'
    for name, cil, mapping in HASHES:
        digest = hashlib.sha256((partitions / cil).read_bytes() + (partitions / mapping).read_bytes())
        line = digest.hexdigest() + '\n'
        (partitions / name).write_text(line)
        (directory / f'precompiled_sepolicy.{Path(name).name}').write_text(line)


def make_partitions(work, *, compile_policy=True, edit=None, extra=None, variant='user',
                    ignore_neverallows=False, add=None, cil=None, remove=(), unbuilt=(),
                    loaded='vendor'):
    """The synthetic partitions, with the precompiled policy and the hash files.

    ignore_neverallows compiles as a caiman build does, with secilc -N. add writes more files;
    cil writes CIL files that the precompiled policy is compiled from too. remove leaves files of
    the fixture out of the partitions and of the compilation, unbuilt only out of the compilation.
    loaded names the partition whose etc/selinux holds the precompiled policy and its hash files,
    as init finds them.
    """
    partitions = Path(work) / 'partitions'
    shutil.copytree(FIXTURE, partitions)
    for relative, function in (edit or {}).items():
        path = partitions / relative
        path.write_text(function(path.read_text()))
    for relative in remove:
        (partitions / relative).unlink()
    for relative, text in {**(add or {}), **(cil or {})}.items():
        (partitions / relative).parent.mkdir(parents=True, exist_ok=True)
        (partitions / relative).write_text(text)
    (partitions / 'system/build.prop').write_text(f'ro.build.id=TEST\nro.build.type={variant}\n')
    directory = partitions / loaded / 'etc/selinux'
    directory.mkdir(parents=True, exist_ok=True)
    policy = directory / 'precompiled_sepolicy'
    if compile_policy:
        order = [name for name in BUILD_ORDER if name not in remove and name not in unbuilt]
        order += list(cil or {})
        sources = [str(partitions / name) for name in order] + [str(path) for path in extra or ()]
        flags = ['-N'] if ignore_neverallows else []
        status, out, errors = nc.run_tool([TOOLS['secilc'], '-m', '-M', 'true', '-G', *flags, '-c',
                                           nc.POLICY_VERSION, *sources, '-o', policy, '-f', os.devnull])
        if status != 0:
            raise AssertionError(f'the fixture does not compile: {errors}')
    else:
        policy.write_bytes(b'not a policy; step A reads only its bytes\n')
    write_hashes(partitions, directory)
    return partitions


def expanded_text(table=TABLE, variant='user', skip=()):
    """An expanded rule file as m4 -s writes it, with line markers and AOSP rules around."""
    lines = ['#line 1 "system/sepolicy/public/domain.te"',
             'neverallow * kernel:process dyntransition;',
             'neverallowxperm * devpts:chr_file ioctl 0x00005412;']
    for entry in table['rules']:
        if entry['number'] in skip:
            continue
        # a patch's rules come from the system/sepolicy file it changes, as in the real file
        where = ('system/sepolicy/private/domain.te' if entry['source'].startswith('patches/')
                 else f'vendor/andrix/{entry["source"]}')
        lines.append(f'#line {entry["line"]} "{where}"')
        text = entry['expansion'][variant]
        if '{ domain -andrixd -andrix_owner ' in text:   # m4 leaves the macro's comment lines
            head, tail = text.split(' } ', 1)
            text = (f'{head} #\n#line {entry["line"]}\n# SUPPRESSED_BY_USERDEBUG_OR_ENG -- this '
                    f'marker is used by CTS -- do not modify\n#line {entry["line"]}\n }} {tail}')
        lines.append(text)
    return '\n'.join(lines) + '\n'


def source_copy(work):
    """A copy of the Andrix policy sources, to edit."""
    source = Path(work) / 'source'
    for directory in POLICY_DIRS + PATCHES + ['board']:
        shutil.copytree(ROOT / directory, source / directory)
    return source


BRIDGE = 'patches/grapheneos-2026081300/owner-session-policy.patch'
# Files init passes when present (system/core/init/selinux.cpp:282-330). The build never compiles
# the compat files into precompiled_sepolicy (system/sepolicy/Android.bp:681-711), so a loaded
# policy built from them is synthetic. Each declares a type a rule uses, so it reaches the binary.
COMPAT = {'system/etc/selinux/mapping/202404.compat.cil':
          '(type compat_plat_file)\n(allow shell compat_plat_file (file (read)))\n',
          'system_ext/etc/selinux/mapping/202404.compat.cil':
          '(type compat_system_ext_file)\n(allow shell compat_system_ext_file (file (read)))\n',
          'odm/etc/selinux/odm_sepolicy.cil':
          '(type odm_marker_file)\n(allow shell odm_marker_file (file (read)))\n'}
# A SYNTHETIC upstream system/sepolicy/private/domain.te, in the forms the real one uses: rules
# over several lines, a rule inside a macro argument, a macro definition that a rule names, a
# commented rule and an extended permission rule.
UPSTREAM = """\
# Rules for all domains.
allow { domain -appdomain -rs } cgroup:dir w_dir_perms;

# Protect most domains from executing data.
neverallow {
  domain
  -appdomain
  userdebug_or_eng(`-overlay_remounter')
} {
  data_file_type
  -apk_data_file # shared libraries
}:file no_x_file_perms;

full_treble_only(`
  neverallow {
    domain
    -coredomain
  } vendor_file:file execute;
')

define(`allowed_domains', `{
  init
  vold
}')
neverallow ~allowed_domains self:capability dac_override;
# neverallow domain kernel:process dyntransition;
neverallowxperm domain devpts:chr_file ioctl 0x5412;
"""


def sha(text):
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def one_hunk(old, removed=(), added=()):
    """A zero context patch of UPSTREAM with one hunk, as the bridge patch is written, and the
    adapted text it gives, made here by list surgery and not by the tool."""
    lines = UPSTREAM.split('\n')
    removed, added = list(removed), list(added)
    if removed:
        assert lines[old - 1:old - 1 + len(removed)] == removed, (old, removed)
        adapted = lines[:old - 1] + added + lines[old - 1 + len(removed):]
        new = old if added else old - 1
    else:
        adapted = lines[:old] + added + lines[old:]
        new = old + 1

    def span(start, count):
        return str(start) if count == 1 else f'{start},{count}'
    patch = (f'--- a/private/domain.te\n+++ b/private/domain.te\n'
             f'@@ -{span(old, len(removed))} +{span(new, len(added))} @@\n'
             + ''.join(f'-{text}\n' for text in removed) + ''.join(f'+{text}\n' for text in added))
    return patch, '\n'.join(adapted)


def bridge_record(patch, adapted, **changes):
    return {'project': 'system/sepolicy', 'file': 'private/domain.te', 'patch': 'x.patch',
            'upstream_sha256': sha(UPSTREAM), 'adapted_sha256': sha(adapted),
            'patch_sha256': sha(patch), **changes}


def ext4_images(partitions, out, odm_image=False):
    """Real ext4 images of SYNTHETIC partitions, made with the pinned tree's mke2fs, standing for
    the images install_zip.py verified. The system image holds the root with /system in it. An
    odm directory goes into an odm image of its own, or else under the vendor image's /odm, as on
    a phone without an odm partition."""
    out.mkdir(parents=True)
    names = ('system', 'system_ext', 'product', 'vendor') + (('odm',) if odm_image else ())
    for name in names:
        root = out / f'{name}-root'
        if name == 'system':
            shutil.copytree(partitions / 'system', root / 'system')
        else:
            shutil.copytree(partitions / name, root)
        if name == 'vendor' and not odm_image and (partitions / 'odm').is_dir():
            shutil.copytree(partitions / 'odm', root / 'odm')
        status, _, errors = nc.run_tool([BIN / 'mke2fs', '-q', '-t', 'ext4', '-d', root, '-b', '4096',
                                         out / f'{name}.img', '8M'])
        if status != 0:
            raise AssertionError(f'mke2fs could not make {name}.img: {errors}')
        shutil.rmtree(root)
    return out


def release_record(path, zip_path, expanded, **changes):
    """A release record in the form the release wrapper is to write (design item 6)."""
    record = {'schema': nc.RELEASE_SCHEMA, 'base_tag': '2026081300', 'artifacts': {
        'install_zip': {'name': Path(zip_path).name, 'sha256': sha(Path(zip_path).read_bytes())},
        'expanded_rule_file': {'name': 'sepolicy_neverallows.sepolicy_analyze.conf',
                               'sha256': sha(Path(expanded).read_bytes())}}}
    record.update(changes)
    Path(path).write_text(json.dumps(record))
    return Path(path)


def verified_zips(andrix_images, official_images, base_tag='2026081300', verdict='PASS', failure=None,
                  seen=None):
    """install_zip.py's two verifications, stood in for. Like the real ones they keep the images,
    here the given ones, and report the zip's identity or the kit's verdict. seen collects the
    release each kit check was asked for."""
    def identity(zip_path, *, avbtool, tools=None, scratch=None, bases=None, keep=None):
        if failure:
            raise Refusal(failure)
        for image in sorted(Path(andrix_images).glob('*.img')):
            shutil.copy(image, Path(keep) / image.name)
        return {'sha256': sha(Path(zip_path).read_bytes()), 'base_tag': base_tag}

    def check(zip_path, *, keep=None, **kwargs):
        if seen is not None:
            seen.append(kwargs.get('release'))
        for image in sorted(Path(official_images).glob('*.img')):
            shutil.copy(image, Path(keep) / image.name)
        return {'verdict': verdict, 'checks': {}, 'sha256': '0' * 64,
                'reasons': [] if verdict == 'PASS' else ['vbmeta: avbtool verify_image exited 1']}
    return mock.patch.multiple(nc.install_zip, andrix_identity=identity, check=check)


class Work(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='neverallow-test-'))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)

    def expanded(self, text=None, name='expanded.conf'):
        path = self.work / name
        path.write_text(expanded_text() if text is None else text)
        return path

    def rules_check(self, table=TABLE, source_root=ROOT, expanded=None, variant='user',
                    policy_dirs=POLICY_DIRS, patch_dirs=PATCHES):
        text = expanded_text(table, variant) if expanded is None else expanded
        return nc.check_rule_sources(table, source_root, policy_dirs, patch_dirs, text, variant)


class WitnessTableTests(Work):
    """Step C, and the witness table against the sources at this commit."""

    def test_the_table_matches_the_sources_at_this_commit(self):
        detail = self.rules_check()
        self.assertEqual(detail['rules'], 28)
        self.assertEqual(len(TABLE['rules']), 28)
        self.assertIn('patches/grapheneos-2026081300/owner-session-policy.patch', detail['sources'])
        counts = {}
        for entry in TABLE['rules']:
            counts[entry['source']] = counts.get(entry['source'], 0) + 1
        self.assertEqual(counts, {'owner/sepolicy/andrix_owner.te': 17,
                                  'owner/sepolicy/andrix_terminal.te': 5,
                                  'owner/platform/sepolicy/owner_lifecycle.te': 2,
                                  'patches/grapheneos-2026081300/owner-session-policy.patch': 4})

    def test_the_table_lists_the_witnesses_of_the_design(self):
        design = (ROOT / 'plans/2026-10-09-caiman-design-items.md').read_text(encoding='utf-8')
        rows = re.findall(r'^\| ([0-9]+) \| `([^`]+)`[^|]*\| `(\(allow [^`]+\))`', design, re.M)
        self.assertEqual(len(rows), 28)
        for number, source, witness in rows:
            entry = TABLE['rules'][int(number) - 1]
            self.assertEqual(f'{entry["source"]}:{entry["line"]}', source)
            self.assertEqual(entry['witness'], witness)

    def test_userdebug_expansion_keeps_the_debug_exception(self):
        entry = TABLE['rules'][10]
        self.assertEqual(entry['expansion']['userdebug'],
                         'neverallow { domain -andrixd -andrix_owner -overlay_remounter } '
                         'andrix_owner_entry:file execute;')
        self.assertEqual(self.rules_check(variant='userdebug')['rules'], 28)
        with self.assertRaisesRegex(Refusal, 'lacks rule 11'):
            self.rules_check(variant='userdebug', expanded=expanded_text(variant='user'))

    def test_a_stale_entry_fails(self):
        table = copy.deepcopy(TABLE)
        table['rules'][4]['rule'] = 'neverallow andrix_owner andrixd:binder { call transfer };'
        with self.assertRaisesRegex(Refusal, r'rule 5 records .* but owner/sepolicy/andrix_owner.te:84 reads'):
            self.rules_check(table, expanded=expanded_text())

    def test_an_entry_on_a_line_without_a_rule_fails(self):
        table = copy.deepcopy(TABLE)
        table['rules'][0]['line'] = 41
        with self.assertRaisesRegex(Refusal, 'andrix_owner.te:42 has no witness table entry.*'
                                    'rule 1 names owner/sepolicy/andrix_owner.te:41'):
            self.rules_check(table, expanded=expanded_text())

    def test_a_source_rule_without_an_entry_fails(self):
        source = source_copy(self.work)
        path = source / 'owner/sepolicy/andrix_terminal.te'
        path.write_text(path.read_text() + 'neverallow andrix_terminal andrixd:process ptrace;\n')
        with self.assertRaisesRegex(Refusal, r'andrix_terminal.te:[0-9]+ has no witness table entry'):
            self.rules_check(source_root=source)

    def test_a_rule_in_another_policy_file_without_an_entry_fails(self):
        source = source_copy(self.work)
        (source / 'sepolicy/private/extra.te').write_text('  neverallow shell andrixd:process ptrace; # new\n')
        with self.assertRaisesRegex(Refusal, 'sepolicy/private/extra.te:1 has no witness table entry'):
            self.rules_check(source_root=source)

    def test_a_patch_rule_without_an_entry_fails(self):
        source = source_copy(self.work)
        base = source / PATCHES[0]
        patch = base / 'owner-session-policy.patch'
        patch.write_text(patch.read_text().replace(
            '+neverallow domain andrix_owner:process dyntransition;\n',
            '+neverallow domain andrix_owner:process dyntransition;\n'
            '+neverallow domain andrixd:process dyntransition;\n'))
        record = json.loads((base / 'owner-session-policy.json').read_text())
        record['patch_sha256'] = hashlib.sha256(patch.read_bytes()).hexdigest()
        (base / 'owner-session-policy.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(Refusal, 'owner-session-policy.patch:18 has no witness table entry'):
            self.rules_check(source_root=source)

    def test_a_patch_that_differs_from_its_record_fails(self):
        source = source_copy(self.work)
        patch = source / PATCHES[0] / 'owner-session-policy.patch'
        patch.write_text(patch.read_text() + '\n')
        with self.assertRaisesRegex(Refusal, 'does not hash to the patch_sha256'):
            self.rules_check(source_root=source)

    def test_a_missing_expansion_fails(self):
        with self.assertRaisesRegex(Refusal, 'the expanded rule file lacks rule 5:'):
            self.rules_check(expanded=expanded_text(skip=(5,)))

    def test_a_recorded_expansion_that_is_not_the_rule_fails(self):
        table = copy.deepcopy(TABLE)
        table['rules'][16]['expansion']['user'] = 'neverallow { andrixd andrix_owner } self:capability *;'
        with self.assertRaisesRegex(Refusal, 'rule 17 records the user expansion'):
            self.rules_check(table, expanded=expanded_text(table))

    def test_a_missing_patch_directory_leaves_the_patch_entries_stale(self):
        with self.assertRaisesRegex(Refusal, 'rule 25 names patches/grapheneos-2026081300/'
                                    'owner-session-policy.patch:14, which holds no literal'):
            self.rules_check(patch_dirs=[])

    def test_source_directories_must_be_plain_directories_and_records_well_formed(self):
        with self.assertRaisesRegex(Refusal, 'the policy directory owner/nothing is not a directory'):
            self.rules_check(policy_dirs=['owner/nothing'])
        with self.assertRaisesRegex(Refusal, 'the patch directory patches/nothing is not a directory'):
            self.rules_check(patch_dirs=['patches/nothing'])
        source = source_copy(self.work)
        (source / 'owner/sepolicy/link.te').symlink_to(source / 'owner/sepolicy/andrix_owner.te')
        with self.assertRaisesRegex(Refusal, 'owner/sepolicy/link.te is a symbolic link'):
            self.rules_check(source_root=source)
        (source / 'owner/sepolicy/link.te').unlink()
        base = source / PATCHES[0]
        (base / 'broken.json').write_text('{')
        with self.assertRaisesRegex(Refusal, 'broken.json is not JSON'):
            self.rules_check(source_root=source)
        (base / 'broken.json').write_text(json.dumps({'project': 'system/sepolicy', 'patch': '../x.patch'}))
        with self.assertRaisesRegex(Refusal, 'broken.json names no patch file'):
            self.rules_check(source_root=source)

    def test_no_policy_directory_fails(self):
        with self.assertRaisesRegex(Refusal, 'no Andrix policy directory'):
            self.rules_check(policy_dirs=[])

    def test_a_literal_extended_permission_rule_is_refused(self):
        source = source_copy(self.work)
        (source / 'owner/sepolicy/x.te').write_text('neverallowxperm shell andrixd_devpts:chr_file ioctl 0x5412;\n')
        with self.assertRaisesRegex(Refusal, 'x.te:1 holds a literal extended permission rule'):
            self.rules_check(source_root=source)

    def test_an_unknown_macro_is_refused(self):
        with self.assertRaisesRegex(Refusal, 'macros the check does not know: eng'):
            nc.expand("neverallow { domain eng(`-su') } shell:file read;", 'user', {})

    def test_an_empty_table_fails(self):
        path = self.work / 'empty.json'
        path.write_text(json.dumps({'schema': nc.SCHEMA, 'macros': TABLE['macros'], 'rules': []}))
        with self.assertRaisesRegex(Refusal, 'holds no rules'):
            nc.load_witnesses(path)

    def test_a_witness_of_another_form_is_refused(self):
        with self.assertRaisesRegex(Refusal, 'not one CIL allow of one permission'):
            nc.parse_witness('(allow shell andrixd (process (ptrace sigkill)))', 3)

    def test_a_table_without_the_two_macros_fails(self):
        table = copy.deepcopy(TABLE)
        del table['macros']['no_x_file_perms']
        with self.assertRaisesRegex(Refusal, 'exactly capability_class_set and no_x_file_perms'):
            self.rules_check(table)

    def test_a_table_naming_one_line_twice_fails(self):
        table = copy.deepcopy(TABLE)
        table['rules'][1]['line'] = table['rules'][0]['line']
        with self.assertRaisesRegex(Refusal, 'names one source line twice'):
            self.rules_check(table, expanded=expanded_text())

    def test_a_malformed_or_unordered_entry_fails(self):
        for change in ({'number': 3}, {'line': '42'}, {'expansion': {'user': 'x'}}):
            with self.subTest(change=change):
                table = copy.deepcopy(TABLE)
                table['rules'][0].update(change)
                path = self.work / 'table.json'
                path.write_text(json.dumps(table))
                with self.assertRaisesRegex(Refusal, 'entry 1 is malformed or out of order'):
                    nc.load_witnesses(path)
        path = self.work / 'other.json'
        path.write_text(json.dumps({**TABLE, 'schema': 'other'}))
        with self.assertRaisesRegex(Refusal, 'is not andrix.pixel.neverallow_witnesses/2'):
            nc.load_witnesses(path)

    def test_every_comment_and_line_marker_is_ignored(self):
        statements = nc.expanded_statements(expanded_text())
        self.assertIn(TABLE['rules'][10]['expansion']['user'], statements)
        self.assertNotIn('neverallowxperm', ' '.join(statements))

    def test_commented_rules_and_trailing_comments(self):
        source = source_copy(self.work)
        terminal = source / 'owner/sepolicy/andrix_terminal.te'
        terminal.write_text(terminal.read_text() + '# neverallow andrix_terminal andrixd:process ptrace;\n'
                            'allow andrix_terminal self:process fork; # no neverallow here\n')
        owner = source / 'owner/sepolicy/andrix_owner.te'
        lines = owner.read_text().split('\n')
        self.assertEqual(lines[41], TABLE['rules'][0]['rule'])
        lines[41] += '  # the owner devpts'
        owner.write_text('\n'.join(lines))
        detail = self.rules_check(source_root=source)
        self.assertEqual(detail['rules'], 28)

    def test_a_directory_symlink_in_a_policy_directory_is_refused(self):
        source = source_copy(self.work)
        (source / 'owner/sepolicy/more').symlink_to('../platform/sepolicy', target_is_directory=True)
        with self.assertRaisesRegex(Refusal, 'owner/sepolicy/more is a symbolic link'):
            self.rules_check(source_root=source)


class LoadedPolicyTests(Work):
    """Step A, which reads only bytes."""

    def loaded(self, partitions, variant='user'):
        return nc.check_loaded_policy(nc.Inputs.from_directory(partitions), variant, {})

    def test_the_fixture_passes(self):
        detail = self.loaded(make_partitions(self.work, compile_policy=False))
        self.assertEqual(sorted(detail['hash_pairs']), ['plat', 'product', 'system_ext'])
        self.assertEqual(len(detail['cil_files']), 9)
        self.assertEqual(detail['cil_files'][:2], ['/system/etc/selinux/plat_sepolicy.cil',
                                                   '/system/etc/selinux/mapping/202404.cil'])
        self.assertEqual(detail['cil_files'][-1], '/system/etc/selinux/plat_sepolicy_genfs_202504.cil')

    def test_differing_hash_files_fail(self):
        partitions = make_partitions(self.work, compile_policy=False)
        (partitions / 'vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256'
         ).write_text('0' * 64 + '\n')
        with self.assertRaisesRegex(Refusal, 'init would not load the precompiled policy'):
            self.loaded(partitions)

    def test_a_hash_computed_again_that_differs_fails(self):
        partitions = make_partitions(self.work, compile_policy=False)
        mapping = partitions / 'system_ext/etc/selinux/mapping/202404.cil'
        mapping.write_text(mapping.read_text() + '; changed after the hash\n')
        with self.assertRaisesRegex(Refusal, 'system_ext_sepolicy.cil followed by .* hashes to'):
            self.loaded(partitions)

    def test_an_empty_or_missing_hash_file_fails(self):
        partitions = make_partitions(self.work, compile_policy=False)
        empty = partitions / 'system/etc/selinux/plat_sepolicy_and_mapping.sha256'
        empty.write_text('')
        with self.assertRaisesRegex(Refusal, 'not one line of 64'):
            self.loaded(partitions)
        empty.unlink()
        with self.assertRaisesRegex(Refusal, 'no /system/etc/selinux/plat_sepolicy_and_mapping.sha256'):
            self.loaded(partitions)

    def test_an_odm_precompiled_policy_fails(self):
        partitions = make_partitions(self.work, compile_policy=False)
        (partitions / 'odm/etc/selinux').mkdir(parents=True)
        shutil.copy(partitions / 'vendor/etc/selinux/precompiled_sepolicy',
                    partitions / 'odm/etc/selinux/precompiled_sepolicy')
        with self.assertRaisesRegex(Refusal, 'odm/etc/selinux/precompiled_sepolicy, which init would load'):
            self.loaded(partitions)

    def test_a_userdebug_platform_policy_fails(self):
        for where in ('system_ext/etc/selinux', 'debug_ramdisk'):
            with self.subTest(where=where):
                partitions = make_partitions(self.work / where.replace('/', '_'), compile_policy=False)
                (partitions / where).mkdir(parents=True, exist_ok=True)
                (partitions / where / 'userdebug_plat_sepolicy.cil').write_text('(type x)\n')
                with self.assertRaisesRegex(Refusal, 'userdebug_plat_sepolicy.cil; with a debug ramdisk'):
                    self.loaded(partitions)

    def test_the_variant_must_be_the_flashed_one(self):
        partitions = make_partitions(self.work, compile_policy=False, variant='userdebug')
        with self.assertRaisesRegex(Refusal, 'ro.build.type=userdebug, not the variant user'):
            self.loaded(partitions)

    def test_a_missing_required_genfs_file_fails(self):
        partitions = make_partitions(self.work, compile_policy=False)
        (partitions / 'system/etc/selinux/plat_sepolicy_genfs_202504.cil').unlink()
        with self.assertRaisesRegex(Refusal, 'genfs labels version 202504 needs'):
            self.loaded(partitions)

    def test_single_files_cannot_show_what_is_absent(self):
        partitions = make_partitions(self.work, compile_policy=False)
        pairs = [f'/{path.relative_to(partitions).as_posix()}={path}'
                 for path in sorted(partitions.rglob('*')) if path.is_file()]
        with self.assertRaisesRegex(Refusal, 'given as single files'):
            nc.check_loaded_policy(nc.Inputs.from_pairs(pairs), 'user', {})
        with self.assertRaisesRegex(Refusal, 'not PHONE_PATH=HOST_PATH'):
            nc.Inputs.from_pairs(['vendor/etc/selinux/precompiled_sepolicy=x'])

    def test_malformed_version_files_and_build_properties_fail(self):
        for relative, content, reason in (
                ('vendor/etc/selinux/plat_sepolicy_vers.txt', '202404\n202504\n', 'is not one line holding'),
                ('vendor/etc/selinux/genfs_labels_version.txt', 'next\n', "holds 'next', not a six digit"),
                ('system/build.prop', 'ro.build.type=user\nro.build.type=user\n', 'sets ro.build.type 2 times')):
            with self.subTest(relative=relative):
                partitions = make_partitions(self.work / Path(relative).name, compile_policy=False)
                (partitions / relative).write_text(content)
                with self.assertRaisesRegex(Refusal, reason):
                    self.loaded(partitions)

    def test_a_policy_too_large_to_be_one_fails(self):
        partitions = make_partitions(self.work, compile_policy=False)
        with mock.patch.object(nc, 'POLICY_LIMIT', 8):
            with self.assertRaisesRegex(Refusal, 'precompiled_sepolicy is larger than 8 bytes'):
                self.loaded(partitions)

    def test_another_precompiled_policy_fails(self):
        partitions = make_partitions(self.work, compile_policy=False)
        shutil.copy(partitions / 'vendor/etc/selinux/precompiled_sepolicy',
                    partitions / 'system/etc/selinux/precompiled_sepolicy')
        with self.assertRaisesRegex(Refusal, 'another precompiled policy: /system/etc/selinux/'):
            self.loaded(partitions)

    def test_output_on_standard_output_fails_D(self):
        with self.assertRaisesRegex(Refusal, "exited 0 with 0 violations and 0 warnings: \\['unexpected'\\]"):
            nc.require_pass({'status': 0, 'violations': [], 'warnings': [], 'stderr': '',
                             'stdout': 'unexpected\n'}, 'the loaded policy')

    def test_a_symbolic_link_or_an_oversized_file_fails(self):
        partitions = make_partitions(self.work / 'link', compile_policy=False)
        plat = partitions / 'system/etc/selinux/plat_sepolicy.cil'
        moved = partitions / 'plat_sepolicy.cil'
        plat.rename(moved)
        plat.symlink_to(moved)
        with self.assertRaisesRegex(Refusal, '/system/etc/selinux/plat_sepolicy.cil is not a regular file'):
            self.loaded(partitions)
        partitions = make_partitions(self.work / 'large', compile_policy=False)
        (partitions / 'vendor/etc/selinux/plat_sepolicy_vers.txt').write_bytes(b'2' * (nc.SMALL + 1))
        with self.assertRaisesRegex(Refusal, 'plat_sepolicy_vers.txt is larger than'):
            self.loaded(partitions)

    def test_require_pass_needs_each_condition(self):
        clean = {'status': 0, 'violations': [], 'warnings': [], 'stderr': '', 'stdout': ''}
        nc.require_pass(clean, 'a clean run')
        for change in ({'status': 1}, {'violations': ['allow a b:c { d };']},
                       {'stderr': 'anything\n'}, {'stdout': 'anything\n'}):
            with self.subTest(change=change):
                with self.assertRaises(Refusal):
                    nc.require_pass({**clean, **change}, 'a run')

    def test_a_mutant_must_fail_with_exactly_its_witness(self):
        witness = nc.parse_witness('(allow andrixd self (capability (chown)))', 17)
        self.assertEqual(nc.violation_text(witness), 'allow andrixd andrixd:capability { chown };')
        failed = {'status': 255, 'violations': ['allow andrixd andrixd:capability { chown };'],
                  'warnings': [], 'stderr': 'x', 'stdout': ''}
        nc.check_mutant(failed, witness, 'its own rule alone')
        for change in ({'status': 0}, {'violations': []},
                       {'violations': ['allow andrixd andrixd:capability { chown };',
                                       'allow shell init:process { ptrace };']},
                       {'warnings': ['Warning!  Class x used in neverallow undefined']}):
            with self.subTest(change=change):
                with self.assertRaises(Refusal):
                    nc.check_mutant({**failed, **change}, witness, 'its own rule alone')

    def test_an_unknown_variant_is_refused(self):
        report = nc.check(nc.Inputs({}, True), expanded='x', variant='eng', tools={},
                          base_tag='2026081300')
        self.assertEqual(report['reasons'], ["variant: variant 'eng' is not one of user, userdebug"])

    def test_tools_that_are_not_the_pinned_ones_fail(self):
        fake = self.work / 'secilc'
        fake.write_bytes(b'#!/bin/sh\n')
        with self.assertRaisesRegex(Refusal, 'not the pinned secilc'):
            nc.pinned_tools({'secilc': fake}, {'secilc': nc.SECILC_SHA256})
        with self.assertRaisesRegex(Refusal, 'needs the pinned checkpolicy'):
            nc.pinned_tools({}, {'checkpolicy': nc.CHECKPOLICY_SHA256})

    def test_compat_files_and_an_odm_policy_follow_inits_order(self):
        detail = self.loaded(make_partitions(self.work, compile_policy=False, add=COMPAT))
        self.assertEqual(detail['cil_files'], [
            '/system/etc/selinux/plat_sepolicy.cil', '/system/etc/selinux/mapping/202404.cil',
            '/system/etc/selinux/mapping/202404.compat.cil',
            '/system_ext/etc/selinux/system_ext_sepolicy.cil',
            '/system_ext/etc/selinux/mapping/202404.cil',
            '/system_ext/etc/selinux/mapping/202404.compat.cil',
            '/product/etc/selinux/product_sepolicy.cil', '/product/etc/selinux/mapping/202404.cil',
            '/vendor/etc/selinux/plat_pub_versioned.cil', '/vendor/etc/selinux/vendor_sepolicy.cil',
            '/odm/etc/selinux/odm_sepolicy.cil', '/system/etc/selinux/plat_sepolicy_genfs_202504.cil'])

    def test_missing_genfs_version_metadata_takes_inits_default(self):
        version = 'vendor/etc/selinux/genfs_labels_version.txt'
        detail = self.loaded(make_partitions(self.work / 'none', compile_policy=False, remove=[version]))
        self.assertEqual(detail['genfs_labels_version'], 202404)
        self.assertEqual(len(detail['cil_files']), 8)
        self.assertNotIn('/system/etc/selinux/plat_sepolicy_genfs_202504.cil', detail['cil_files'])
        old = {'system/etc/selinux/plat_sepolicy_genfs_202404.cil':
               '(genfscon sysfs "/" (u object_r sysfs ((s0) (s0))))\n'}
        detail = self.loaded(make_partitions(self.work / 'old', compile_policy=False, remove=[version],
                                             add=old))
        self.assertEqual(detail['cil_files'][-1], '/system/etc/selinux/plat_sepolicy_genfs_202404.cil')

    def test_a_directory_symlink_in_the_partitions_is_refused(self):
        for link, target in (('odm', 'vendor'), ('vendor/etc/selinux/more', '../../../system/etc')):
            with self.subTest(link=link):
                partitions = make_partitions(self.work / link.replace('/', '_'), compile_policy=False)
                (partitions / link).symlink_to(target, target_is_directory=True)
                with self.assertRaisesRegex(Refusal, f'/{link} is a symbolic link to a directory'):
                    nc.Inputs.from_directory(partitions)

    def test_an_unreadable_expanded_rule_file_refuses_C(self):
        for name, make, reason in (('missing', lambda path: None, 'is not a regular file'),
                                   ('directory', lambda path: path.mkdir(), 'is not a regular file'),
                                   ('binary', lambda path: path.write_bytes(b'\xff\xfe neverallow'),
                                    'is not UTF-8 text')):
            with self.subTest(name=name):
                path = self.work / name
                make(path)
                with self.assertRaisesRegex(Refusal, reason):
                    nc.read_expanded(path)
                report = nc.check(nc.Inputs({}, True), expanded=path, variant='user', tools={},
                                  base_tag='2026081300')
                self.assertIn(f'the expanded rule file {path} {reason}' if 'regular' in reason else reason,
                              report['checks']['C_rule_sources']['reason'])
        path = self.expanded()
        with mock.patch.object(nc, 'POLICY_LIMIT', 4):
            with self.assertRaisesRegex(Refusal, 'the expanded rule file is larger than 4 bytes'):
                nc.read_expanded(path)
        if os.geteuid() != 0:   # root reads a file whatever its mode
            path.chmod(0)
            self.addCleanup(path.chmod, 0o600)
            with self.assertRaisesRegex(Refusal, 'the expanded rule file cannot be read: .*Permission denied'):
                nc.read_expanded(path)

    def test_an_unreadable_source_refuses_C_through_the_step_wrapper(self):
        source = source_copy(self.work)
        broken = source / 'owner/sepolicy/broken.te'
        broken.write_bytes(b'\xff not text\n')
        report = nc.check(nc.Inputs({}, True), expanded=self.expanded(), variant='user', tools={},
                          source_root=source, base_tag='2026081300')
        self.assertIn("codec can't decode", report['checks']['C_rule_sources']['reason'])
        if os.geteuid() != 0:   # root reads a file whatever its mode
            broken.write_text('# unreadable\n')
            broken.chmod(0)
            self.addCleanup(broken.chmod, 0o600)
            report = nc.check(nc.Inputs({}, True), expanded=self.expanded(), variant='user', tools={},
                              source_root=source, base_tag='2026081300')
            self.assertIn('Permission denied', report['checks']['C_rule_sources']['reason'])


class ChangeTests(Work):
    """Step C: patch hunks placed in the upstream rules they change, and their records."""

    def place(self, patch, adapted, holds=None, record=None):
        tree = Path(tempfile.mkdtemp(prefix='tree-', dir=self.work))
        path = tree / 'system/sepolicy/private/domain.te'
        path.parent.mkdir(parents=True)
        path.write_text(UPSTREAM if holds is None else holds)
        record = record or bridge_record(patch, adapted)
        return nc.rule_changes([('patches/x/x.patch', patch.split('\n'), record)], tree)

    def source_root(self, patch, adapted, policy='allow a b:file read;\n'):
        root = Path(tempfile.mkdtemp(prefix='source-', dir=self.work))
        (root / 'policy').mkdir()
        (root / 'policy/a.te').write_text(policy)
        (root / 'patches').mkdir()
        (root / 'patches/x.patch').write_text(patch)
        (root / 'patches/x.json').write_text(json.dumps(bridge_record(patch, adapted)))
        tree = root / 'tree'
        (tree / 'system/sepolicy/private').mkdir(parents=True)
        (tree / 'system/sepolicy/private/domain.te').write_text(UPSTREAM)
        return root, tree

    def test_each_hunk_is_placed_in_the_upstream_rules(self):
        cases = [
            ('exclusion inside a rule', 7, [], ['  -andrix_owner'], [('inside', 5)]),
            ('exclusion inside a rule in a macro argument', 16, [], ['    -andrix_owner'],
             [('inside', 15)]),
            ('member added to a macro definition', 22, [], ['  andrix_owner'], [('m4', 21)]),
            ('macro defined again', 2, [], ["define(`no_x_file_perms', `{ execute }')"], [('m4', None)]),
            ('rule removed', 25, ['neverallow ~allowed_domains self:capability dac_override;'], [],
             [('removal', 25)]),
            ('line of a rule removed', 11, ['  -apk_data_file # shared libraries'], [], [('inside', 5)]),
            ('commented rule removed', 26, ['# neverallow domain kernel:process dyntransition;'], [], []),
            ('comment added inside a rule', 6, [], ['  # the owner stays covered'], []),
            ('m4 quote left open', 3, [], ["ifelse(andrix_owner_session, `true', `', `"], [('m4', None)]),
            ('new rule after a rule', 12, [], ['neverallow andrix_owner kernel:process dyntransition;'], []),
            ('allow before a rule', 4, [], ['allow shell kernel:file read;'], []),
            ('extended rule changed', 27, ['neverallowxperm domain devpts:chr_file ioctl 0x5412;'],
             ['neverallowxperm { domain -andrix_owner } devpts:chr_file ioctl 0x5412;'], [('removal', 27)]),
            ('allow narrowed', 2, ['allow { domain -appdomain -rs } cgroup:dir w_dir_perms;'],
             ["allow { domain -appdomain -rs ifelse(andrix_owner_session, `true', `-andrix_owner') } "
              'cgroup:dir w_dir_perms;'], []),
            ('exclusion with a comment', 7, [], ['  -andrix_owner # (narrowed for the owner'],
             [('inside', 5)]),
            ('macro argument closed early', 19, ["')"], [], [('m4', None)]),
            ('comment and extended rule removed', 26,
             ['# neverallow domain kernel:process dyntransition;',
              'neverallowxperm domain devpts:chr_file ioctl 0x5412;'], [], [('removal', 27)]),
        ]
        for name, old, removed, added, expected in cases:
            with self.subTest(name):
                patch, adapted = one_hunk(old, removed, added)
                found = self.place(patch, adapted)
                self.assertEqual([(change['kind'], change['rule_line']) for change in found], expected)
                if found:
                    self.assertEqual(found[0]['line'], 4)
                    self.assertEqual(found[0]['file'], 'system/sepolicy/private/domain.te')
                    self.assertEqual(found[0]['lines'], patch.split('\n')[3:-1])

    def test_quotes_parentheses_and_comments_are_read_as_m4_reads_them(self):
        self.assertTrue(nc.m4_balanced(["ifelse(x, `true', `)')", 'a # ( comment']))
        for lines in (["ifelse(x, `true', `"], ["')"], ["')", 'x('], ['ifelse(x,', "`a'"]):
            with self.subTest(lines=lines):
                self.assertFalse(nc.m4_balanced(lines))
        self.assertEqual(nc.rule_regions(['neverallow {', '  domain', '} kernel:file read']),
                         [('rule', 1, 3)])
        self.assertEqual(nc.rule_regions(["define(`x', y(z)", ')', 'neverallow a b:file read; # x;']),
                         [('rule', 3, 3), ('definition', 1, 2)])

    def test_the_tree_may_hold_the_upstream_or_the_adapted_file(self):
        patch, adapted = one_hunk(7, [], ['  -andrix_owner'])
        for holds in (UPSTREAM, adapted):
            found = self.place(patch, adapted, holds=holds)
            self.assertEqual([(change['kind'], change['rule_line']) for change in found], [('inside', 5)])
        with self.assertRaisesRegex(Refusal, 'neither the upstream nor the adapted file'):
            self.place(patch, adapted, holds=UPSTREAM + '# changed\n')
        with self.assertRaisesRegex(Refusal, 'does not give the adapted file its record pins'):
            self.place(patch, adapted, record=bridge_record(patch, adapted + '\n'))
        with self.assertRaisesRegex(Refusal, 'taken back out of the adapted file does not give the '
                                    'upstream file'):
            self.place(patch, adapted, holds=adapted,
                       record=bridge_record(patch, adapted, upstream_sha256=sha(UPSTREAM + '\n')))
        record = bridge_record(patch, adapted)
        del record['adapted_sha256']
        with self.assertRaisesRegex(Refusal, 'holds no adapted_sha256'):
            self.place(patch, adapted, record=record)
        with mock.patch.object(nc, 'SOURCE_LIMIT', 10):
            with self.assertRaisesRegex(Refusal, 'domain.te in the tree is larger than 10 bytes'):
                self.place(patch, adapted)
        wrong, _ = one_hunk(8, ["  userdebug_or_eng(`-overlay_remounter')"], [])
        wrong = wrong.replace('-  userdebug', '-  eng')
        with self.assertRaisesRegex(Refusal, 'does not stand at its place in the file'):
            self.place(wrong, adapted)
        with self.assertRaisesRegex(Refusal, 'no GrapheneOS tree of the base tag was given'):
            nc.rule_changes([('patches/x/x.patch', patch.split('\n'), bridge_record(patch, adapted))],
                            None)
        with self.assertRaisesRegex(Refusal, 'the tree holds no regular file system/sepolicy/private/'):
            nc.rule_changes([('patches/x/x.patch', patch.split('\n'), bridge_record(patch, adapted))],
                            self.work)

    def test_a_narrowing_absent_from_the_witness_record_fails(self):
        patch, adapted = one_hunk(7, [], ['  -andrix_owner'])
        root, tree = self.source_root(patch, adapted)
        record = {'number': 1, 'title': 'x', 'source': 'patches/x.patch', 'line': 4, 'kind': 'inside',
                  'file': 'system/sepolicy/private/domain.te', 'rule_line': 5,
                  'lines': ['+  -andrix_owner'], 'effect': 'x'}

        def changes(*records):
            return nc.check_rule_changes({'changes': list(records)}, root, ['policy'], ['patches'], tree)
        with self.assertRaisesRegex(Refusal, 'patches/x.patch:4 changes the rule at system/sepolicy/'
                                    'private/domain.te:5, which the witness table does not record'):
            changes()
        self.assertEqual(changes(record)['changes'], [
            {'source': 'patches/x.patch', 'line': 4, 'kind': 'inside',
             'rule': 'system/sepolicy/private/domain.te:5'}])
        for key, value in (('rule_line', 6), ('kind', 'removal'), ('lines', ['+ -andrix_owner'])):
            with self.subTest(key=key):
                with self.assertRaisesRegex(Refusal, f'change 1 records {key} .* but patches/x.patch:4'):
                    changes({**record, key: value})
        with self.assertRaisesRegex(Refusal, 'change 2 names patches/x.patch:9, which changes no'):
            changes(record, {**record, 'number': 2, 'line': 9})
        with self.assertRaisesRegex(Refusal, 'records one change twice'):
            changes(record, {**record, 'number': 2})

    def test_an_m4_directive_in_a_policy_file_needs_a_record(self):
        patch, adapted = one_hunk(4, [], ['allow shell kernel:file read;'])
        root, tree = self.source_root(patch, adapted, policy="define(`owner_domains', `{ andrixd }')\n")
        with self.assertRaisesRegex(Refusal, 'policy/a.te:1 changes how m4 reads the policy, which the '
                                    'witness table does not record'):
            nc.check_rule_changes({'changes': []}, root, ['policy'], ['patches'], tree)
        (root / 'policy/a.te').write_text('# define the owner rules here\nallow a b:file read;\n')
        self.assertEqual(nc.check_rule_changes({'changes': []}, root, ['policy'], [], None), {'changes': []})

    def test_malformed_patches_are_refused(self):
        for text, reason in (
                ('--- a/x\n+++ b/y\n@@ -1 +1 @@\n-a\n+b\n', 'does not patch one file in place'),
                ('@@ -1 +1 @@\n-a\n+b\n', 'is neither a file header nor a hunk'),
                ('--- a/x\n+++ b/x\n@@ -1,2 +1 @@\n-a\n+b\n', 'counts lines its hunk does not hold'),
                ('--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n\\ No newline at end of file\n',
                 'marks a missing final newline'),
                ('--- a/x\n+++ b/x\nstray\n', 'is neither a file header nor a hunk')):
            with self.subTest(text=text):
                with self.assertRaisesRegex(Refusal, reason):
                    nc.patch_files(text.split('\n'), 'p.patch')
        patch, adapted = one_hunk(7, [], ['  -andrix_owner'])
        with self.assertRaisesRegex(Refusal, "not only the file 'private/other.te' its record pins"):
            self.place(patch, adapted, record=bridge_record(patch, adapted, file='private/other.te'))
        moved = patch.replace('@@ -7,0 +8 @@', '@@ -7,0 +9 @@')
        with self.assertRaisesRegex(Refusal, 'names a new position that does not follow'):
            self.place(moved, adapted, record=bridge_record(moved, adapted))
        escape = patch.replace('private/domain.te', '../escape.te')
        with self.assertRaisesRegex(Refusal, 'names no file of system/sepolicy'):
            self.place(escape, adapted, record=bridge_record(escape, adapted, file='../escape.te'))

    def diffed(self, upstream, adapted, context=0):
        """rule_changes on a patch that difflib writes for these texts, as a review would."""
        patch = ''.join(difflib.unified_diff(upstream.splitlines(True), adapted.splitlines(True),
                                             'a/private/domain.te', 'b/private/domain.te', n=context))
        record = {'project': 'system/sepolicy', 'file': 'private/domain.te',
                  'upstream_sha256': sha(upstream), 'adapted_sha256': sha(adapted)}
        return [(change['kind'], change['rule_line'], change['lines'])
                for change in self.place(patch, adapted, holds=upstream, record=record)]

    def test_a_comment_inside_a_quoted_string_is_text(self):
        # m4 sees a # as a comment only outside quotes: inside full_treble_only's quoted argument
        # this line closes the argument and opens an unused second one, dropping the rule
        # (system/sepolicy/public/te_macros, full_treble_only)
        upstream = ("full_treble_only(`\n  neverallowxperm domain devpts:chr_file ioctl 0x5412;\n  foo(a,\n  b)\n')\n"
                    'ifelse(target_build_variant, user,\n  neverallow {\n    domain\n  } kernel:process dyntransition;\n)\n')
        self.assertEqual(nc.m4_line_states(upstream.split('\n')),
                         [(0, 0), (1, 1), (1, 1), (1, 1), (1, 1), (0, 0), (0, 1), (0, 1), (0, 1), (0, 1), (0, 0),
                          (0, 0)])
        self.assertEqual(nc.m4_line_states([')', 'a(']), [(0, 0), (0, 0), (0, 1)])
        # what m4_lex reports leaving: an outer quote or parenthesis closed, an argument added
        for lines, state, expected in ((["# ', `"], (1, 1), (["# ', `"], (1, 1), True)),
                                       (["'x`"], (1, 1), (["'x`"], (1, 1), True)),
                                       (['  )'], (0, 1), (['  )'], (0, 0), True)),
                                       (['a, b # c, d'], (0, 1), (['a, b '], (0, 1), True)),
                                       (['f(a, b)'], (0, 1), (['f(a, b)'], (0, 1), False)),
                                       (["`a, (b'"], (0, 1), (["`a, (b'"], (0, 1), False))):
            self.assertEqual(nc.m4_lex(lines, state), expected)
        dropped = upstream.replace("full_treble_only(`\n", "full_treble_only(`\n# ', `\n")
        self.assertEqual(self.diffed(upstream, dropped), [('m4', None, ["+# ', `"])])
        root = Path(tempfile.mkdtemp(prefix='source-', dir=self.work))
        (root / 'policy').mkdir()
        (root / 'policy/a.te').write_text('allow a b:file read;\n')
        (root / 'patches').mkdir()
        patch = ''.join(difflib.unified_diff(upstream.splitlines(True), dropped.splitlines(True),
                                             'a/private/domain.te', 'b/private/domain.te', n=0))
        (root / 'patches/x.patch').write_text(patch)
        (root / 'patches/x.json').write_text(json.dumps(
            {'project': 'system/sepolicy', 'file': 'private/domain.te', 'patch': 'x.patch',
             'patch_sha256': sha(patch), 'upstream_sha256': sha(upstream), 'adapted_sha256': sha(dropped)}))
        (root / 'tree/system/sepolicy/private').mkdir(parents=True)
        (root / 'tree/system/sepolicy/private/domain.te').write_text(upstream)
        with self.assertRaisesRegex(Refusal, r"patches/x.patch:4 changes how m4 reads the policy, which the "
                                    r"witness table does not record: \[\"\+# ', `\"\]"):
            nc.check_rule_changes({'changes': []}, root, ['policy'], ['patches'], root / 'tree')
        for name, edit, expected in (
                # comments that m4 skips at the top level stay inert, quotes in them included
                ('top level comment', ('ifelse(', "# don't change ifelse(\nifelse("), []),
                ('top level comment naming a builtin', ('ifelse(', '# dnl\nifelse('), []),
                # inside quotes a # starts no comment: the text is judged where it stands
                ('quoted comment beside the rule', ('ioctl 0x5412;\n', 'ioctl 0x5412;\n# a note\n'), []),
                ('quoted comment naming a builtin', ("full_treble_only(`\n", "full_treble_only(`\n# dnl\n"),
                 [('m4', None, ['+# dnl'])]),
                ('quoted comment opening a quote', ("full_treble_only(`\n", "full_treble_only(`\n# `\n"),
                 [('m4', None, ['+# `'])]),
                # an unquoted argument list: a comma there adds an argument, one in a call does not
                ('argument added', ('user,\n', 'user,\n  ,\n'), [('m4', None, ['+  ,'])]),
                ('call with its own arguments', ('user,\n', "user,\n  foo(a, `b')\n"), []),
                ('comment in an argument list', ('user,\n', 'user,\n  # a note\n'), []),
                # m4 copies a comment inside an unquoted argument into the argument
                ('comment in a rule in an argument list', ('    domain\n', '    domain\n    # a note\n'),
                 [('inside', 7, ['+    # a note'])]),
                # quoted text is read again when its macro expands, so it must be balanced in itself
                ('quoted call left open', ("ioctl 0x5412;\n", "ioctl 0x5412;\n  bar(\n"),
                 [('m4', None, ['+  bar('])]),
                ('quoted call end removed', ('  b)\n', ''), [('m4', None, ['-  b)'])])):
            with self.subTest(name):
                self.assertEqual(self.diffed(upstream, upstream.replace(*edit, 1)), expected)
        # the same comment inside the quoted rule of the fixture is a change of that rule
        patch, adapted = one_hunk(16, [], ['    # a note'])
        self.assertEqual([(change['kind'], change['rule_line']) for change in self.place(patch, adapted)],
                         [('inside', 15)])
        patch, adapted = one_hunk(6, [], ['    # a note'])
        self.assertEqual(self.place(patch, adapted), [])

    def test_unchanged_context_is_no_change(self):
        upstream = ('neverallow domain kernel:file execute;\nallow shell kernel:file read;\n'
                    'neverallow domain kernel:process dyntransition;\n')
        adapted = upstream.replace('kernel:file read;', 'kernel:file getattr;')
        self.assertEqual(self.diffed(upstream, adapted, context=3), [])
        # each run of changed lines is judged at its own place: one in a rule, one beside it
        upstream = ('neverallow {\n  domain\n} kernel:file execute;\nallow shell kernel:file read;\n'
                    'neverallow domain kernel:process dyntransition;\n')
        adapted = upstream.replace('  domain\n', '  domain -andrix_owner\n').replace(
            'kernel:file read;', 'kernel:file getattr;')
        self.assertEqual(self.diffed(upstream, adapted, context=1),
                         [('inside', 1, ['-  domain', '+  domain -andrix_owner'])])
        patch = ''.join(difflib.unified_diff(upstream.splitlines(True), adapted.splitlines(True),
                                             'a/private/domain.te', 'b/private/domain.te', n=1))
        record = {'project': 'system/sepolicy', 'file': 'private/domain.te',
                  'upstream_sha256': sha(upstream), 'adapted_sha256': sha(adapted)}
        found = self.place(patch, adapted, holds=upstream, record=record)
        self.assertEqual([change['line'] for change in found], [5])
        removed = upstream.replace('neverallow domain kernel:process dyntransition;\n', '')
        self.assertEqual(self.diffed(upstream, removed, context=2),
                         [('removal', 5, ['-neverallow domain kernel:process dyntransition;'])])
        # positions follow context and removed lines: an insertion after the rule is beside it
        beside = upstream.replace('} kernel:file execute;\n', '} kernel:file execute;\nallow c d:file read;\n')
        self.assertEqual(self.diffed(upstream, beside, context=1), [])
        upstream = 'allow a b:file read;\nneverallow {\n  domain\n} kernel:file execute;\n'
        adapted = upstream.replace('b:file read', 'b:file getattr') + 'allow c d:file read;\n'
        self.assertEqual(self.diffed(upstream, adapted, context=3), [])

    @unittest.skipUnless(TREES, 'set ANDRIX_PIXEL_TREES to name a GrapheneOS tree')
    def test_the_bridge_narrowings_are_recorded_and_placed_in_each_named_tree(self):
        expected = [{'source': BRIDGE, 'line': 31, 'kind': 'inside',
                     'rule': 'system/sepolicy/private/domain.te:1959'},
                    {'source': BRIDGE, 'line': 33, 'kind': 'inside',
                     'rule': 'system/sepolicy/private/domain.te:2040'}]
        for tag, tree in sorted(TREES.items()):
            with self.subTest(tag=tag):
                detail = nc.check_rule_changes(TABLE, ROOT, POLICY_DIRS, PATCHES, tree)
                self.assertEqual(detail['changes'], expected)
                table = copy.deepcopy(TABLE)
                table['changes'] = []
                with self.assertRaisesRegex(Refusal, 'owner-session-policy.patch:31 changes the rule at '
                                            'system/sepolicy/private/domain.te:1959, which the witness '
                                            'table does not record.*owner-session-policy.patch:33 '
                                            'changes the rule at system/sepolicy/private/domain.te:2040'):
                    nc.check_rule_changes(table, ROOT, POLICY_DIRS, PATCHES, tree)


class PairTests(Work):
    """Step G's unit: one violated rule and one offending rule, generated attributes expanded."""

    FAILURE = ('neverallowx check failed at {where}\n  {rule}\n    <root>\n    allowx at {where}\n'
               '      {allow}\n')

    def report(self, *failures):
        return ''.join(self.FAILURE.format(where=f'f.cil:{n}', rule=rule, allow=allow) + '\n'
                       for n, (rule, allow) in enumerate(failures, 1))

    def test_generated_attributes_expand_recursively_from_their_definitions(self):
        definitions = {'base_typeattr_1': '(domain shell)',
                       'base_typeattr_2': '(and (base_typeattr_1) (not (andrixd)))',
                       'base_typeattr_259_202604': '(not (base_typeattr_2))'}
        rule = '(neverallowx base_typeattr_259_202604 x (ioctl file (0x1)))'
        allow = '(allowx base_typeattr_2 x (ioctl file (0x1)))'
        pairs = nc.parse_pairs(self.report((rule, allow)), 'Andrix', definitions)
        self.assertEqual(pairs, {('(neverallowx (not ((and ((domain shell)) (not (andrixd))))) x '
                                  '(ioctl file (0x1)))',
                                  '(allowx (and ((domain shell)) (not (andrixd))) x (ioctl file (0x1)))')})
        other = nc.parse_pairs(self.report((rule, allow)), 'Andrix',
                               {**definitions, 'base_typeattr_1': '(domain)'})
        self.assertNotEqual(pairs, other)

    def test_unresolved_cyclic_or_twice_defined_attributes_refuse(self):
        rule = '(neverallow base_typeattr_1 x (file (read)))'
        text = self.report((rule, '(allow shell x (file (read)))'))
        for definitions, reason in (
                ({}, 'hold no typeattributeset for base_typeattr_1'),
                ({'base_typeattr_1': '(and (base_typeattr_2) (domain))',
                  'base_typeattr_2': '(not (base_typeattr_1))'},
                 'define base_typeattr_1 through itself: base_typeattr_1 -> base_typeattr_2 -> '
                 'base_typeattr_1'),
                ({'base_typeattr_1': '(base_typeattr_1)'}, 'define base_typeattr_1 through itself'),
                ({'base_typeattr_1': nc._TWICE}, 'define base_typeattr_1 more than once')):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(Refusal, reason):
                    nc.parse_pairs(text, 'Andrix', definitions)

    def compare(self, ours, theirs):
        with mock.patch.object(nc, 'secilc_pairs', side_effect=[ours, theirs]):
            return nc.check_extended_rules(TOOLS, None, [], None, [], self.work)

    def test_same_text_with_different_generated_meanings_is_a_new_pair(self):
        text = self.report(('(neverallow base_typeattr_5 x (file (read)))', '(allow shell x (file (read)))'))
        ours = nc.parse_pairs(text, 'Andrix', {'base_typeattr_5': '(and (domain) (not (andrix_owner)))'})
        theirs = nc.parse_pairs(text, 'official', {'base_typeattr_5': '(and (domain) (not (andrixd)))'})
        with self.assertRaisesRegex(Refusal, r'violated rules the official files do not show: \(neverallow '
                                    r'\(and \(domain\) \(not \(andrix_owner\)\)\) x'):
            self.compare(ours, theirs)
        same = nc.parse_pairs(text.replace('_5', '_9'), 'official',
                              {'base_typeattr_9': '(and (domain) (not (andrix_owner)))'})
        self.assertEqual(self.compare(ours, same)['pairs'], 1)

    def test_an_andrix_subset_of_the_official_offenders_is_no_new_violation(self):
        rule = '(neverallowx shell_202404 vendor_file (ioctl file (0x8008)))'
        first, second = ('(allowx shell vendor_file (ioctl file (0x8008)))',
                         '(allowx shell_202404 vendor_file (ioctl file (0x8008)))')
        theirs = nc.parse_pairs(self.report((rule, first), (rule, second)), 'official', {})
        detail = self.compare(nc.parse_pairs(self.report((rule, first)), 'Andrix', {}), theirs)
        self.assertEqual(detail, {'pairs': 1, 'vendor_findings': [rule]})
        third = '(allowx shell vendor_file (ioctl file (0x8009)))'
        with self.assertRaisesRegex(Refusal, rf'do not show: {re.escape(rule)} by {re.escape(third)}$'):
            self.compare(nc.parse_pairs(self.report((rule, first), (rule, third)), 'Andrix', {}), theirs)

    def test_definitions_are_read_from_the_run_files_without_comments(self):
        path = self.work / 'policy.cil'
        path.write_text('; (typeattributeset base_typeattr_1 (commented))\n'
                        '(typeattribute base_typeattr_2)\n(typeattributeset base_typeattr_2\n'
                        '  (and (domain)\n    (not (andrixd))))  ; trailing words\n'
                        '(genfscon sysfs "/a;b" (u object_r sysfs ((s0) (s0)))) '
                        '(typeattributeset base_typeattr_4 (sysfs))\n'
                        '(typeattributeset base_typeattr_3_202604 (shell))\n'
                        '(typeattributeset base_typeattr_3_202604 (init))\n')
        inputs = nc.Inputs({'/system/etc/selinux/plat_sepolicy.cil': path}, True)
        definitions = nc.generated_definitions(['/system/etc/selinux/plat_sepolicy.cil'], inputs)
        self.assertEqual(definitions, {'base_typeattr_2': '(and (domain) (not (andrixd)))',
                                       'base_typeattr_4': '(sysfs)', 'base_typeattr_3_202604': nc._TWICE})
        for text, reason in (('(typeattributeset base_typeattr_5 shell)\n', 'that is not a list'),
                             ('(typeattributeset base_typeattr_6 (and (x)\n', 'does not close the definition')):
            with self.subTest(reason=reason):
                path.write_text(text)
                with self.assertRaisesRegex(Refusal, reason):
                    nc.generated_definitions(['/system/etc/selinux/plat_sepolicy.cil'], inputs)

    def test_definitions_follow_the_cil_tokens(self):
        # secilc reads tokens (external/selinux/libsepol/cil/src/cil_lexer.l:48-65): white space
        # may follow a parenthesis, and a quoted string is one token, never a definition
        path = self.work / 'tokens.cil'
        inputs = nc.Inputs({'/vendor/etc/selinux/vendor_sepolicy.cil': path}, True)

        def definitions(text):
            path.write_text(text)
            return nc.generated_definitions(['/vendor/etc/selinux/vendor_sepolicy.cil'], inputs)
        self.assertEqual(definitions(
            '(typeattribute base_typeattr_7)\n( typeattributeset base_typeattr_7 (shell andrix_owner))\n'
            '(genfscon sysfs "/(typeattributeset base_typeattr_7 (domain))" (u object_r sysfs ((s0) (s0))))\n'
            '(neverallowx base_typeattr_7 vendor_file (ioctl file (0x9000)))\n'),
            {'base_typeattr_7': '(shell andrix_owner)'})
        # A comment ends at the next newline token: a quoted string in it is one token, so a carriage
        # return inside the string ends nothing (external/selinux/libsepol/cil/src/cil_parser.c:283-291)
        self.assertEqual(definitions(
            '(typeattribute base_typeattr_7)\n'
            '; "\r(typeattributeset base_typeattr_7 (domain))(genfscon sysfs "\r'
            '(typeattributeset base_typeattr_7 (shell andrix_owner))\r;")\n'),
            {'base_typeattr_7': '(shell andrix_owner)'})
        self.assertEqual(definitions('(typeattributeset base_typeattr_7 (shell))\n'
                                     '; "\r(typeattributeset base_typeattr_7 (domain))"\n'),
                         {'base_typeattr_7': '(shell)'})
        # an unquoted carriage return ends a comment, and a quote that never closes is no string
        self.assertEqual(definitions('; words\r(typeattributeset base_typeattr_5 (init))\n'
                                     '; it"s\n(typeattributeset base_typeattr_6 (shell))\n'),
                         {'base_typeattr_5': '(init)', 'base_typeattr_6': '(shell)'})
        self.assertEqual(definitions('(\ttypeattributeset\n  base_typeattr_8_202604\n  ( and ( domain )\n'
                                     '(not (shell)) ) )\n("typeattributeset" "base_typeattr_9" ("init"))\n'
                                     '((x) typeattributeset base_typeattr_6 (y))\n(typeattributeset domain_set (shell))\n'),
                         {'base_typeattr_8_202604': '(and (domain) (not (shell)))', 'base_typeattr_9': '(init)'})
        for text, reason in (('(allow a b (file (read)))\n\\\n', "holds '\\\\\\\\', which is no CIL token"),
                             ('(genfscon sysfs "/a\n" (u))\n', "holds '\"', which is no CIL token"),
                             ('(allow a b (file (read))))\n', 'closes a parenthesis that it never opened'),
                             ('allow\n', "holds 'allow' outside parentheses"),
                             ('(allow a b (file (read))\n', 'does not close a parenthesis that it opens'),
                             ('(typeattributeset base_typeattr_4 ("a b"))\n', 'a quoted string that is no name')):
            with self.subTest(text=text):
                with self.assertRaisesRegex(Refusal, reason):
                    definitions(text)

    def test_a_shortened_report_refuses(self):
        text = ('neverallow check failed at f.cil:1\n  (neverallow a b (file (read)))\n    <root>\n'
                '    allow at f.cil:2\n      (allow a b (file (read)))\n'
                '    Only first 4 of 9 matching rules shown (use "-v" to show all)\n\n')
        with self.assertRaisesRegex(Refusal, 'shortened its report'):
            nc.parse_pairs(text, 'Andrix', {})


class CorpusTests(Work):
    """Corpus mode without the tools: what it reads, what it records, and that it never passes."""

    def test_corpus_reads_odm_before_vendor_and_records_a_userdebug_policy(self):
        partitions = make_partitions(self.work, compile_policy=False, loaded='odm')
        state = {}
        detail = nc.check_corpus_policy(nc.Inputs.from_directory(partitions), 'user', state)
        self.assertEqual((detail['loaded'], detail['userdebug_policies_recorded']), (nc.ODM_PRECOMPILED, []))
        self.assertEqual(state['policy'], partitions / 'odm/etc/selinux/precompiled_sepolicy')
        with self.assertRaisesRegex(Refusal, 'which init would load instead'):
            nc.check_loaded_policy(nc.Inputs.from_directory(partitions), 'user', {})
        (partitions / 'debug_ramdisk').mkdir()
        (partitions / 'debug_ramdisk/userdebug_plat_sepolicy.cil').write_text('(type x)\n')
        shutil.copy(partitions / 'odm/etc/selinux/precompiled_sepolicy',
                    partitions / 'vendor/etc/selinux/precompiled_sepolicy')
        detail = nc.check_corpus_policy(nc.Inputs.from_directory(partitions), 'user', {})
        self.assertEqual((detail['loaded'], detail['userdebug_policies_recorded']),
                         (nc.ODM_PRECOMPILED, ['/debug_ramdisk/userdebug_plat_sepolicy.cil']))
        (partitions / 'odm/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256').unlink()
        with self.assertRaisesRegex(Refusal, 'no /odm/etc/selinux/precompiled_sepolicy.product_sepolicy'):
            nc.check_corpus_policy(nc.Inputs.from_directory(partitions), 'user', {})
        shutil.copy(partitions / 'vendor/etc/selinux/precompiled_sepolicy',
                    partitions / 'system/etc/selinux/precompiled_sepolicy')
        with self.assertRaisesRegex(Refusal, 'another precompiled policy: /system/etc/selinux/'):
            nc.check_corpus_policy(nc.Inputs.from_directory(partitions), 'user', {})
        fresh = make_partitions(self.work / 'single', compile_policy=False, loaded='odm')
        pairs = [f'/{path.relative_to(fresh).as_posix()}={path}'
                 for path in sorted(fresh.rglob('*')) if path.is_file()]
        with self.assertRaisesRegex(Refusal, 'given as single files'):
            nc.check_corpus_policy(nc.Inputs.from_pairs(pairs), 'user', {})

    def test_corpus_step_c_takes_the_user_file_and_the_variant_table(self):
        detail = nc.check_rule_sources(TABLE, ROOT, POLICY_DIRS, PATCHES, expanded_text(variant='user'),
                                       'userdebug', corpus=True)
        self.assertEqual((detail['rules'], detail['expansions_in_file']), (28, 'user'))
        table = copy.deepcopy(TABLE)
        table['rules'][10]['expansion']['userdebug'] = table['rules'][10]['expansion']['user']
        with self.assertRaisesRegex(Refusal, 'rule 11 records the userdebug expansion'):
            nc.check_rule_sources(table, ROOT, POLICY_DIRS, PATCHES, expanded_text(variant='user'),
                                  'userdebug', corpus=True)
        with self.assertRaisesRegex(Refusal, 'the expanded rule file lacks rule 5:'):
            nc.check_rule_sources(TABLE, ROOT, POLICY_DIRS, PATCHES, expanded_text(skip=(5,)),
                                  'userdebug', corpus=True)

    def test_the_userdebug_exception_must_be_exactly_one_violation(self):
        line = f'neverallow violated by {nc.USERDEBUG_EXCEPTION}\n'
        other = 'neverallow violated by allow shell andrix_owner_entry:file { execute };\n'
        exactly = 'must fail on a userdebug corpus with exactly'
        warning = 'Warning!  Type x used in neverallow undefined in policy being checked.\n'
        for name, stderr, status, reason in (('exactly the exception', line, 255, None),
                                             ('nothing', '', 0, exactly),
                                             ('the exception with exit status 0', line, 0, exactly),
                                             ('another violation too', line + other, 255, exactly),
                                             ('a warning too', line + warning, 255, exactly),
                                             ('unknown output too', line + 'Error: unknown\n', 255,
                                              'sepolicy-analyze on the corpus policy exited 255')):
            with self.subTest(name):
                with mock.patch.object(nc, 'run_tool', return_value=(status, '', stderr)):
                    if reason:
                        with self.assertRaisesRegex(Refusal, reason):
                            nc.check_userdebug_exception({'sepolicy-analyze': 'x'}, 'p', TABLE, self.work)
                    else:
                        detail = nc.check_userdebug_exception({'sepolicy-analyze': 'x'}, 'p', TABLE,
                                                              self.work)
                        self.assertEqual(detail['violations'], [nc.USERDEBUG_EXCEPTION])

    def test_the_corpus_help_exits_nonzero(self):
        for argv, status in ((['--corpus', '--help'], 1), (['-h', '--corpus'], 1), (['--corp', '-h'], 1),
                             (['--help'], 0)):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(nc.main(argv), status)
                self.assertTrue(output.getvalue().startswith('usage: '))
        process = subprocess.run([sys.executable, '-B', str(Path(nc.__file__)), '--corpus', '--help'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertIn(b'corpus mode never exits 0', process.stdout.replace(b'\n', b' ').replace(b'  ', b' '))

    def test_the_corpus_exit_is_never_zero(self):
        arguments = ['--corpus', '--partitions', str(make_partitions(self.work, compile_policy=False)),
                     '--expanded', 'x', '--variant', 'user', '--sepolicy-analyze', 'x', '--secilc', 'x',
                     '--checkpolicy', 'x', '--base-tag', '2026081300', '--grapheneos-tree', 'x']
        for verdict, status in (('CORPUS', nc.CORPUS_EXIT), ('PASS', 1), ('REFUSE', 1), (None, 1)):
            with self.subTest(verdict=verdict):
                with mock.patch.object(nc, 'corpus_check', return_value={'verdict': verdict}), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(nc.main(arguments), status)

        def loaded(inputs, variant, state):
            state.update(policy='policy', cil_files=[])
            return {}
        every_step_succeeds = dict(
            pinned_tools=lambda *a: {'secilc': 'x'}, check_corpus_policy=loaded,
            check_owner_domains=lambda *a: {}, load_witnesses=lambda *a: {'rules': []},
            read_expanded=lambda *a: '', check_rule_sources=lambda *a: {},
            check_rule_changes=lambda *a: {}, check_rules_on_policy=lambda *a: {},
            check_control_and_mutants=lambda *a: {}, check_corpus_extended_rules=lambda *a: {})
        with mock.patch.multiple(nc, **every_step_succeeds):
            report = nc.corpus_check(nc.Inputs({}, True), expanded='x', variant='user', tools={},
                                     base_tag='2026081300',
                                     scratch=self.work)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = nc.main(arguments + ['--scratch', str(self.work)])
        self.assertEqual((report['mode'], report['verdict'], report['reasons']), ('corpus', 'CORPUS', []))
        self.assertNotIn('F_aosp_rules', report['checks'])
        self.assertEqual(report['not_run'], {'F_aosp_rules': nc.NO_OFFICIAL_RELEASE})
        self.assertEqual((status, json.loads(output.getvalue())['verdict']), (nc.CORPUS_EXIT, 'CORPUS'))

        def refused(inputs, variant, state):
            raise Refusal('the hash pairs differ')
        with mock.patch.multiple(nc, **{**every_step_succeeds, 'check_corpus_policy': refused}):
            report = nc.corpus_check(nc.Inputs({}, True), expanded='x', variant='user', tools={},
                                     base_tag='2026081300',
                                     scratch=self.work)
            with contextlib.redirect_stdout(io.StringIO()):
                status = nc.main(arguments + ['--scratch', str(self.work)])
        self.assertEqual((report['verdict'], status), ('REFUSE', 1))
        step_a = 'step A did not pass, so the CIL files are not those of the loaded policy'
        self.assertEqual((report['checks']['E_control_and_mutants']['reason'],
                          report['checks']['G_extended_rules']['reason']), (step_a, step_a))

    def test_corpus_mode_refuses_an_official_policy(self):
        partitions = str(make_partitions(self.work, compile_policy=False))
        for option in ('--official', '--official-kit'):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = nc.main(['--corpus', '--partitions', partitions, option, partitions,
                                  '--expanded', 'x', '--variant', 'user', '--sepolicy-analyze', 'x',
                                  '--secilc', 'x', '--checkpolicy', 'x', '--base-tag', '2026081300',
                                  '--grapheneos-tree', 'x'])
            report = json.loads(output.getvalue())
            self.assertEqual((status, report['mode'], report['verdict']), (1, 'corpus', 'REFUSE'))
            self.assertIn('corpus mode compares with no official policy', report['reasons'][0])


class ProvenanceTests(Work):
    """Where the gate's inputs come from. No tool runs: install_zip.py's verification and the
    image reader are stood in for where a case needs them."""

    def board(self, text):
        root = Path(tempfile.mkdtemp(prefix='board-', dir=self.work))
        (root / 'board').mkdir()
        (root / 'board/owner-policy.mk').write_text(text)
        return root

    def test_the_policy_directories_come_from_the_board_file(self):
        self.assertEqual(nc.owner_policy_dirs(ROOT), POLICY_DIRS)
        good = 'SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a\n'
        for text, reason in (
                ('ifeq ($(ANDRIX_OWNER_SESSION),true)\n' + good + 'endif\n', 'holds a comment, an expansion'),
                ('ifeq (a,b)\n' + good + 'endif\n', 'is not a \\+= addition'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS := vendor/andrix/a\n', 'is not a \\+= addition'),
                ('include vendor/andrix/other.mk\n', 'is not a \\+= addition'),
                ('BOARD_PLAT_PRIVATE_SEPOLICY_DIR += vendor/andrix/a\n', 'is not a \\+= addition'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/x\n', 'not a path under vendor/andrix/'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/../x\n', 'not a path under vendor/andrix/'),
                (good + 'PRODUCT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a\n', 'names vendor/andrix/a twice'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a # the owner\n', 'holds a comment'),
                ('\tSYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a\n', 'or a recipe'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a \\', 'ends inside a continued line'),
                # make continues a comment at a final backslash, and only a final one continues
                ('# the owner \\\n' + good, 'is a comment that make continues into the next line'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a \\ \n    vendor/andrix/b\n',
                 'ends in white space or holds a backslash before its end'),
                (good.replace('\n', ' \n'), 'ends in white space'),
                ('SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a\\b\n', 'holds a backslash before its end'),
                ('BOARD_SEPOLICY_M4DEFS += andrix_owner_session=true\n', 'adds no policy directory'),
                (good + 'BOARD_SEPOLICY_M4DEFS += andrix-owner\n', 'is not name=value'),
                (good + 'PRODUCT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/tests/owner-negative\n',
                 'a lab directory under tests/')):
            with self.subTest(text=text):
                with self.assertRaisesRegex(Refusal, reason):
                    nc.owner_policy_dirs(self.board(text))
        root = self.board('# the owner policy\n\nSYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/a \\\n'
                          '    vendor/andrix/b\nBOARD_ODM_SEPOLICY_DIRS += vendor/andrix/c\n'
                          'TARGET_FS_CONFIG_GEN += vendor/andrix/owner/config.fs\n')
        self.assertEqual(nc.owner_policy_dirs(root), ['a', 'b', 'c'])
        with self.assertRaisesRegex(Refusal, 'holds no regular file board/owner-policy.mk'):
            nc.owner_policy_dirs(self.work)

    def test_a_caller_cannot_give_the_directories(self):
        # an incomplete list, a complete one and single files are all refused by name, in each mode
        for flags in ([], ['--corpus'], ['--build-tools', 'x']):
            for option, reason in ((['--policy-dir', 'owner/sepolicy'], '--policy-dir is refused: the Andrix '
                                    'policy directories come only from board/owner-policy.mk'),
                                   ([f'--policy-dir={name}' for name in POLICY_DIRS], '--policy-dir is refused'),
                                   (['--patches', PATCHES[0]], '--patches is refused: the patch set comes only '
                                    'from the base tag, patches/grapheneos-TAG'),
                                   (['--file', 'x=y'], '--file is refused: single files cannot show')):
                with self.subTest(flags=flags, option=option):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        status = nc.main(flags + option)
                    report = json.loads(output.getvalue())
                    self.assertEqual((status, report['verdict'], report['checks']), (1, 'REFUSE', {}))
                    self.assertEqual(len(report['reasons']), 1)
                    self.assertTrue(report['reasons'][0].startswith(reason), report['reasons'])
        for flags, reason in (([], "--official is refused: the gate reads the official policy only through "
                               "install_zip.py's verified kit, --official-kit"),
                              (['--corpus'], '--official is refused: corpus mode compares with no official '
                               'policy')):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(nc.main(flags + ['--official', 'x']), 1)
            self.assertTrue(json.loads(output.getvalue())['reasons'][0].startswith(reason))
        source = source_copy(self.work)
        board = source / 'board/owner-policy.mk'
        board.write_text(board.read_text().replace(' vendor/andrix/owner/platform/sepolicy', ''))

        def step_c(text=None):
            return nc.check(nc.Inputs({}, True), expanded=self.expanded(text), variant='user', tools={},
                            base_tag='2026081300', source_root=source)['checks']['C_rule_sources']
        self.assertIn('rule 23 names owner/platform/sepolicy/owner_lifecycle.te:7, which holds no literal',
                      step_c()['reason'])
        # the build's own expanded rule file names the files it read, so the left out directory shows
        self.assertIn('the expanded rule file was made from vendor/andrix/owner/platform/sepolicy/'
                      'owner_lifecycle.te, which no policy directory of board/owner-policy.mk holds',
                      step_c()['reason'])
        (source / 'extra').mkdir()
        (source / 'extra/extra.te').write_text('neverallow shell andrixd:process ptrace;\n')
        board.write_text(board.read_text() + 'PRODUCT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/extra\n')
        self.assertIn('extra/extra.te:1 has no witness table entry', step_c()['reason'])
        # a build that read a lab policy, which no product directory names, refuses too
        board.write_text((ROOT / 'board/owner-policy.mk').read_text())
        lab = expanded_text() + '#line 1 "vendor/andrix/tests/owner-negative/negative.te"\n'
        self.assertIn('the expanded rule file was made from vendor/andrix/tests/owner-negative/negative.te, '
                      'which no policy', step_c(lab)['reason'])
        self.assertEqual(nc.check_expanded_sources(expanded_text(), POLICY_DIRS),
                         sorted({f'vendor/andrix/{entry["source"]}' for entry in TABLE['rules']
                                 if not entry['source'].startswith('patches/')}))
        with self.assertRaisesRegex(Refusal, 'made from vendor/andrix/sepolicy/private/a.te, which'):
            nc.check_expanded_sources('#line 1 "vendor/andrix/sepolicy/private/a.te"\n',
                                      ['owner/sepolicy', 'sepolicy/privat'])

    def test_the_patch_set_comes_from_the_base_tag(self):
        # The selected base's directory is production. A candidate base's directory may sit beside
        # it, and only grapheneos_candidate.py checks it, so this repository is read for the
        # selected base alone, and a tag without a directory is shown in a copy of the sources.
        selected = grapheneos_base.selected()
        self.assertEqual(PATCHES, [selected.patches.relative_to(ROOT).as_posix()])
        self.assertEqual(nc.patch_dirs_for(ROOT, selected.release), PATCHES)
        source = source_copy(self.work)
        for tag, reason in (('2026100600', 'has no reviewed patch directory patches/grapheneos-2026100600'),
                            ('2026081301', 'security preview'), ('20260813', 'not ten digits')):
            with self.subTest(tag=tag):
                with self.assertRaisesRegex(Refusal, reason):
                    nc.patch_dirs_for(source, tag)
        # a candidate's directory beside it leaves the selected base's patch set as it is
        candidate = source / 'patches/grapheneos-2026100600'
        shutil.copytree(source / PATCHES[0], candidate)
        policy = candidate / 'owner-session-policy.json'
        policy.write_text(policy.read_text().replace('"base_release": "2026081300"',
                                                     '"base_release": "2026100600"'))
        self.assertEqual(nc.patch_dirs_for(source, selected.release), PATCHES)
        shutil.rmtree(candidate)
        record = source / PATCHES[0] / 'owner-session-policy.json'
        record.write_text(record.read_text().replace('"base_release": "2026081300"',
                                                     '"base_release": "2026100600"'))
        with self.assertRaisesRegex(Refusal, "owner-session-policy.json is for base '2026100600', not "
                                    '2026081300'):
            nc.patch_dirs_for(source, '2026081300')
        record.write_text('{')
        with self.assertRaisesRegex(Refusal, 'owner-session-policy.json is not JSON'):
            nc.patch_dirs_for(source, '2026081300')
        record.unlink()
        with self.assertRaisesRegex(Refusal, 'holds owner-session-policy.patch without a record'):
            nc.patch_dirs_for(source, '2026081300')
        report = nc.check(nc.Inputs({}, True), expanded=self.expanded(), variant='user', tools={},
                          base_tag='2026100600', source_root=source)
        self.assertIn('has no reviewed patch directory', report['checks']['C_rule_sources']['reason'])

    def test_unknown_tags_have_no_tool_pins(self):
        self.assertEqual(nc.tool_pins('2026081300'), nc.PINS)
        with self.assertRaisesRegex(Refusal, 'base tag 2026100600 has no reviewed set of host tool digests'):
            nc.tool_pins('2026100600')
        for report in (nc.check(nc.Inputs({}, True), expanded='x', variant='user', tools=TOOLS,
                                base_tag='2026100600'),
                       nc.corpus_check(nc.Inputs({}, True), expanded='x', variant='user', tools=TOOLS,
                                       base_tag='2026100600')):
            self.assertIn('has no reviewed set of host tool digests', report['checks']['tools']['reason'])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nc.main(['--build-tools', str(self.work), '--base-tag', '2026100600'])
        self.assertEqual((status, json.loads(output.getvalue())['verdict']), (1, 'REFUSE'))

    def test_the_gate_refuses_the_corpus_tool_set_for_an_image(self):
        # design item 2: "The 2026081300 set serves only the stage 1 corpus."
        reason = ('the 2026081300 host tool set serves only the stage 1 corpus, so it checks no '
                  'image (design item 2)')
        report = self.gate()
        self.assertEqual((report['verdict'], report['checks']['tools']['reason']), ('REFUSE', reason))
        with mock.patch.object(nc, 'CORPUS_ONLY', frozenset()):
            self.assertEqual(self.gate()['checks']['tools']['reason'],
                             'the check needs the pinned sepolicy-analyze')
        # the set still serves corpus mode and the policy steps on laid out files
        for report in (nc.corpus_check(nc.Inputs({}, True), expanded='x', variant='user', tools={},
                                       base_tag='2026081300'),
                       nc.check(nc.Inputs({}, True), expanded='x', variant='user', tools={},
                                base_tag='2026081300')):
            self.assertEqual(report['checks']['tools']['reason'], 'the check needs the pinned sepolicy-analyze')
        self.assertEqual(nc.tool_pins('2026081300'), nc.PINS)
        for check in (lambda: nc.tool_pins('2026081300', image=True),
                      lambda: nc.check_build_tools('2026081300', self.work)):
            with self.assertRaisesRegex(Refusal, re.escape(reason)):
                check()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nc.main(['--build-tools', str(self.work), '--base-tag', '2026081300'])
        self.assertEqual((status, json.loads(output.getvalue())['reasons']), (1, [reason]))

    def test_altered_tool_bytes_refuse(self):
        directory = self.work / 'bin'
        directory.mkdir()
        for name in nc.PINS:
            (directory / name).write_bytes(f'synthetic {name}\n'.encode())
        pins = {name: sha((directory / name).read_bytes()) for name in nc.PINS}
        # a reviewed image set, here for 2026100600, the tag of a first caiman build
        with mock.patch.dict(nc.TOOL_PINS, {'2026100600': pins}):
            self.assertEqual(nc.check_build_tools('2026100600', directory),
                             {'base_tag': '2026100600', 'pinned': sorted(nc.PINS)})
            tools = {name: str(directory / name) for name in nc.PINS}
            report = nc.check(nc.Inputs({}, True), expanded='x', variant='user', tools=tools,
                              base_tag='2026100600')
            self.assertTrue(report['checks']['tools']['ok'])
            (directory / 'secilc').write_bytes(b'synthetic secilc\n\x00')
            with self.assertRaisesRegex(Refusal, 'secilc hashes to [0-9a-f]{64}, not the pinned secilc'):
                nc.check_build_tools('2026100600', directory)
            report = nc.check(nc.Inputs({}, True), expanded='x', variant='user', tools=tools,
                              base_tag='2026100600')
            self.assertRegex(report['checks']['tools']['reason'], 'not the pinned secilc')
            (directory / 'secilc').unlink()
            with self.assertRaisesRegex(Refusal, 'secilc cannot be read'):
                nc.check_build_tools('2026100600', directory)

    def gate(self, record_changes=None, read=True, source_root=ROOT, **stand_ins):
        zip_path = self.work / 'caiman-install-andrix1.zip'
        zip_path.write_bytes(b'synthetic Andrix install zip\n')
        expanded = self.expanded()
        record = release_record(self.work / 'release.json', zip_path, expanded, **(record_changes or {}))
        fresh = Path(tempfile.mkdtemp(prefix='gate-', dir=self.work))
        partitions = {'andrix': make_partitions(fresh / 'andrix', compile_policy=False),
                      'official': make_partitions(fresh / 'official', compile_policy=False)}
        with contextlib.ExitStack() as stack:
            stack.enter_context(verified_zips(self.work, self.work, **stand_ins))
            if read:
                stack.enter_context(mock.patch.object(
                    nc, 'read_image_policy', lambda debugfs, keep, destination: partitions[destination.name]))
            return nc.gate(zip_path, official_kit=self.work / 'caiman-install-2026081300.zip',
                           release_record=record, expanded=expanded, variant='user', tools={},
                           kit={'debugfs': 'debugfs'}, tree=None, source_root=source_root,
                           scratch=self.work)

    def test_the_release_record_binds_the_zip_and_the_expanded_rule_file(self):
        report = self.gate()
        provenance = ['release_record', 'image', 'expanded_rule_file', 'official_kit']
        self.assertEqual(list(report['checks'])[:5], provenance + ['tools'])
        self.assertTrue(all(report['checks'][name]['ok'] for name in provenance + ['A_loaded_policy']))
        self.assertEqual(report['mode'], 'gate')
        reads, original = [], nc.read_expanded

        def read_once(path):   # the gate reads the file once, and the steps check that text
            reads.append(path)
            return original(path)
        with mock.patch.object(nc, 'read_expanded', read_once):
            report = self.gate()
        self.assertEqual(len(reads), 1)
        # the sources part used the bound text; only the hunks wait for a tree, which this case has not
        self.assertEqual(report['checks']['C_rule_sources']['reason'], 'no GrapheneOS tree of the base tag '
                         'was given, so the hunks of patches/grapheneos-2026081300/owner-session-policy.patch '
                         'cannot be placed in the rules they change')
        for changes, check, reason in (
                ({'artifacts': {'install_zip': {'sha256': '1' * 64},
                                'expanded_rule_file': {'sha256': sha(self.expanded().read_bytes())}}},
                 'image', 'the zip hashes to [0-9a-f]{64}, not the 1{64} that the release record names'),
                ({'artifacts': {'install_zip': {'sha256': sha(b'synthetic Andrix install zip\n')},
                                'expanded_rule_file': {'sha256': '0' * 64}}},
                 'expanded_rule_file', 'the expanded rule file hashes to [0-9a-f]{64}, not the 0{64}'),
                ({'base_tag': '2026100600'}, 'image',
                 "carries the signed base tag 2026081300, not the release record's 2026100600"),
                ({'schema': 'other'}, 'release_record', 'the release record is not andrix.caiman.release/1'),
                ({'base_tag': '2026081301'}, 'release_record', 'security preview'),
                ({'artifacts': {}}, 'release_record', 'names no SHA-256 of install_zip')):
            with self.subTest(check=check, reason=reason):
                report = self.gate(record_changes=changes)
                self.assertEqual(report['verdict'], 'REFUSE')
                self.assertRegex(report['checks'][check]['reason'], reason)
                if check == 'expanded_rule_file':   # the steps that read it refuse it unbound
                    self.assertEqual(report['checks']['C_rule_sources']['reason'], nc.UNBOUND_EXPANDED)
                if check == 'release_record':
                    self.assertEqual((report['checks']['image']['reason'],
                                      report['checks']['expanded_rule_file']['reason']),
                                     ('the release record did not pass, so the zip is bound to no build',
                                      'the release record did not pass, so the expanded rule file is '
                                      'bound to no build'))
        # an image of a tag without a reviewed patch directory, read in a copy of the sources, since
        # a candidate base's directory may sit in this repository beside the selected base's
        seen = []
        report = self.gate(base_tag='2026100600', record_changes={'base_tag': '2026100600'},
                           seen=seen, source_root=source_copy(self.work))
        self.assertEqual(seen, ['2026100600'])
        self.assertIn('has no reviewed set of host tool digests', report['checks']['tools']['reason'])
        self.assertIn('has no reviewed patch directory', report['checks']['C_rule_sources']['reason'])
        report = nc.gate(self.work / 'caiman-install-andrix1.zip', official_kit=self.work / 'kit.zip',
                         release_record=self.work / 'release.json', expanded=self.expanded(),
                         variant='eng', tools={}, kit={}, tree=None, scratch=self.work)
        self.assertEqual((report['mode'], report['reasons']),
                         ('gate', ["variant: variant 'eng' is not one of user, userdebug"]))

    def test_the_official_policy_is_read_only_through_the_verified_kit(self):
        report = self.gate(verdict='REFUSE')
        self.assertEqual(report['checks']['official_kit']['reason'], 'the official kit does not pass '
                         'install_zip.py: vbmeta: avbtool verify_image exited 1')
        self.assertIn('no official policy', report['checks']['F_aosp_rules']['reason'])
        report = self.gate(failure='the workshop key for this phone is not recorded yet')
        self.assertEqual(report['checks']['image']['reason'],
                         'the workshop key for this phone is not recorded yet')
        self.assertEqual(report['checks']['official_kit']['reason'],
                         'the zip did not pass, so its base tag is not known')
        self.assertNotIn('A_loaded_policy', report['checks'])
        report = self.gate(read=False)
        self.assertEqual(report['checks']['image']['reason'],
                         'debugfs is not pinned yet, so no file of an install zip is read')
        with self.assertRaisesRegex(Refusal, 'the release record cannot be read'):
            nc.load_release_record(self.work / 'none.json')

    def test_step_f_lists_rules_naming_each_warned_name(self):
        rules = ['neverallow shell missing_file:file read;',
                 'neverallow missing_file kernel:process transition;',
                 'neverallow shell missing_file_extra:file read;',
                 'neverallow shell kernel:missing_class read;',
                 'neverallow shell kernel:file missing_permission;']
        warnings = ['Warning!  Type or attribute missing_file used in neverallow undefined in '
                    'policy being checked.',
                    'Warning!  Class missing_class used in neverallow undefined in policy being '
                    'checked.',
                    'Warning!  Permission missing_permission used in neverallow undefined in '
                    'class file in policy being checked.']
        result = lambda lines: {'status': 0, 'stdout': '', 'stderr': '', 'violations': [],
                                'warnings': lines}
        with mock.patch.object(nc, 'analyze', side_effect=[result(warnings), result(warnings)]):
            detail = nc.check_aosp_rules({}, 'ours', 'theirs', rules, self.work)
        self.assertEqual(detail['warning_rules'], {'missing_file': rules[:2],
                                                  'missing_class': [rules[3]],
                                                  'missing_permission': [rules[4]]})
        # Warnings only on the official side remain visible without refusing, and a new warning
        # on our side is still refused. No name is hidden by a longer token containing it.
        with mock.patch.object(nc, 'analyze', side_effect=[result([]), result(warnings)]):
            official = nc.check_aosp_rules({}, 'ours', 'theirs', rules, self.work)
        self.assertEqual(official['warning_rules'], detail['warning_rules'])
        with mock.patch.object(nc, 'analyze', side_effect=[result(warnings), result([])]), \
                self.assertRaisesRegex(Refusal, 'warnings the official policy does not give'):
            nc.check_aosp_rules({}, 'ours', 'theirs', rules, self.work)

    def test_step_f_warning_names_are_whole_identifiers(self):
        # Policy identifiers may hold hyphens and, qualified, dots; a leading hyphen in a rule is
        # the exclusion operator. A name matches only a whole identifier.
        rules = ['neverallow shell missing_file:file read;',
                 'neverallow shell missing_file-extra:file read;',
                 'neverallow shell missing-file:file read;',
                 'neverallow { domain -missing-file } kernel:file read;',
                 'neverallow shell missing.qualified:file read;',
                 'neverallow shell missing:file read;']
        warning = ('Warning!  Type or attribute %s used in neverallow undefined in policy being '
                   'checked.')
        names = ['missing_file', 'missing-file', 'missing_file-extra', 'missing.qualified', 'missing']
        self.assertEqual(nc.warning_rules(rules, [warning % name for name in names]),
                         {'missing_file': [rules[0]], 'missing_file-extra': [rules[1]],
                          'missing-file': rules[2:4], 'missing.qualified': [rules[4]],
                          'missing': [rules[5]]})
        # A warning only on the official side keeps its hyphenated name in the passing report.
        result = lambda lines: {'status': 0, 'stdout': '', 'stderr': '', 'violations': [],
                                'warnings': lines}
        official_only = [result([]), result([warning % 'missing-file'])]
        with mock.patch.object(nc, 'analyze', side_effect=official_only):
            detail = nc.check_aosp_rules({}, 'ours', 'theirs', rules, self.work)
        self.assertEqual(detail['warning_rules'], {'missing-file': rules[2:4]})

    def test_own_work_directories_are_private_and_removed(self):
        made, mkdir = [], os.mkdir

        def recording(path, mode=0o777, *args, **kwargs):
            if Path(path).name.startswith(('neverallow-', 'neverallow-gate-')):
                made.append((Path(path), mode))
            return mkdir(path, mode, *args, **kwargs)
        with mock.patch.object(os, 'mkdir', recording):
            self.gate()
        self.assertTrue(any(path.name.startswith('neverallow-gate-') for path, _ in made))
        self.assertTrue(any(path.name.startswith('neverallow-') and
                            not path.name.startswith('neverallow-gate-') for path, _ in made))
        self.assertTrue(all(mode == 0o700 and not path.exists() for path, mode in made))

    def test_own_cleanup_failures_refuse_and_name_the_directory(self):
        real = shutil.rmtree
        for prefix, failure in itertools.product(
                ('neverallow-gate-', 'neverallow-'),
                (PermissionError(13, 'synthetic removal error'),
                 OSError(5, 'synthetic removal error'))):
            with self.subTest(prefix=prefix, failure=type(failure).__name__):
                left = []

                def failing(path, *args, **kwargs):
                    name = Path(path).name
                    matches = name.startswith(prefix) and (prefix != 'neverallow-' or
                                                           not name.startswith('neverallow-gate-'))
                    if matches:
                        left.append(Path(path))
                        if kwargs.get('ignore_errors'):
                            return None
                        raise failure
                    return real(path, *args, **kwargs)
                with mock.patch.object(shutil, 'rmtree', failing), \
                        contextlib.redirect_stderr(io.StringIO()):
                    report = self.gate()
                self.assertTrue(left)
                self.assertEqual(report['verdict'], 'REFUSE')
                self.assertTrue(any(str(left[0]) in reason and 'could not be removed' in reason
                                    for reason in report['reasons']), report['reasons'])
                # Drop the synthetic failure before retrying the same shared cleanup mechanism.
                nc.install_zip.sweep_at_exit()
                self.assertTrue(all(not path.exists() for path in left))

    def test_an_interruption_cleans_own_work_directories(self):
        made = []

        def interrupted(path):
            made.extend(self.work.glob('neverallow-gate-*'))
            raise KeyboardInterrupt
        with mock.patch.object(nc, 'load_release_record', interrupted), \
                self.assertRaises(KeyboardInterrupt):
            self.gate()
        self.assertEqual(len(made), 1)
        self.assertFalse(made[0].exists())

    def test_own_work_has_cleanup_ownership_at_entry_and_exit(self):
        import test_install_zip as copies
        for prefix, boundary in itertools.product(
                ('neverallow-gate-', 'neverallow-'),
                ('the return of __enter__', 'the start of __exit__')):
            with self.subTest(prefix=prefix, boundary=boundary):
                with copies.at_boundary(boundary, prefix, copies.interrupt) as reached, \
                        copies.default_interruptions(), self.assertRaises(KeyboardInterrupt):
                    self.gate()
                gc.collect()
                self.assertEqual(reached, [boundary])
                self.assertEqual(list(self.work.glob('neverallow-gate-*')), [])
                nc.install_zip.sweep_at_exit()

    def test_an_unusable_scratch_directory_is_a_named_refusal(self):
        path = self.work / 'not-a-directory'
        path.write_bytes(b'synthetic')
        report = nc.check(nc.Inputs({}, True), expanded='x', variant='user', tools={},
                          base_tag='2026081300', scratch=path)
        self.assertEqual(report['verdict'], 'REFUSE')
        self.assertIn(str(path), report['reasons'][0])

    def test_each_mode_takes_only_its_own_inputs(self):
        common = {'expanded': 'x', 'variant': 'user', 'sepolicy-analyze': 'x', 'secilc': 'x',
                  'checkpolicy': 'x', 'grapheneos-tree': 'x'}
        gate = {**common, 'zip': 'z', 'official-kit': 'k', 'release-record': 'r', 'allowed-signers': 's',
                'stable': 's', 'record': str(self.work / 'none.json'), 'avbtool': 'a', 'simg2img': 's',
                'lpunpack': 'l', 'debugfs': 'd'}
        corpus = {**common, 'partitions': str(make_partitions(self.work, compile_policy=False)),
                  'base-tag': '2026081300'}

        def arguments(options, flags=()):
            return [*flags, *[part for name, value in options.items() for part in (f'--{name}', value)]]
        for argv, reason in (
                (arguments({**gate, 'partitions': 'p'}), 'the gate reads the policy files only out of the '
                 'verified install zips'),
                (arguments({**gate, 'base-tag': '2026081300'}), "reads the base tag only from the zip's signed"),
                (arguments({k: v for k, v in gate.items() if k != 'release-record'}), 'gate needs --release-record'),
                (arguments(gate), 'the adevtool record cannot be read'),
                (arguments({**corpus, 'zip': 'z'}, ['--corpus']), 'corpus mode reads no install zip'),
                (arguments({**corpus, 'release-record': 'r'}, ['--corpus']), 'corpus mode binds no release'),
                (arguments({k: v for k, v in corpus.items() if k != 'base-tag'}, ['--corpus']),
                 'corpus needs --base-tag'),
                (['--build-tools', 'd'], 'build-tools needs --base-tag'),
                (['--build-tools', 'd', '--base-tag', '2026081300', '--corpus'],
                 '--corpus is refused: corpus mode and --build-tools are separate')):
            with self.subTest(reason=reason):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = nc.main(argv)
                report = json.loads(output.getvalue())
                self.assertEqual((status, report['verdict']), (1, 'REFUSE'))
                self.assertIn(reason, report['reasons'][0])

    def test_the_official_hash_pairs_are_checked_as_in_step_A(self):
        official = make_partitions(self.work / 'hash', compile_policy=False)
        (official / 'vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256'
         ).write_text('0' * 64 + '\n')
        report = nc.check(nc.Inputs({}, True), expanded=self.expanded(), variant='user', tools={},
                          base_tag='2026081300', official=nc.Inputs.from_directory(official))
        self.assertRegex(report['checks']['F_aosp_rules']['reason'],
                         '^the official policy: .* init would not load the precompiled policy$')
        self.assertEqual(report['checks']['G_extended_rules']['reason'],
                         report['checks']['F_aosp_rules']['reason'])
        debug = make_partitions(self.work / 'debug', compile_policy=False, variant='userdebug')
        report = nc.check(nc.Inputs({}, True), expanded=self.expanded(), variant='user', tools={},
                          base_tag='2026081300', official=nc.Inputs.from_directory(debug))
        self.assertEqual(report['checks']['F_aosp_rules']['reason'], 'the official policy: '
                         '/system/build.prop has ro.build.type=userdebug, not the variant user')


@unittest.skipUnless(HAVE_E2FS, 'set ANDRIX_PIXEL_TREES to 2026081300=TREE with mke2fs and debugfs built')
class ReaderTests(Work):
    """The policy files read out of real ext4 images with the pinned tree's debugfs."""

    def test_the_reader_lays_out_the_policy_files_of_the_images(self):
        partitions = make_partitions(self.work / 'p', compile_policy=False,
                                     add={'odm/etc/selinux/odm_sepolicy.cil': '(type odm_marker)\n'})
        images = ext4_images(partitions, self.work / 'images')
        listed = sorted(path.relative_to(partitions).as_posix() for path in partitions.rglob('*')
                        if path.is_file())
        with mock.patch.object(nc.install_zip, 'DEBUGFS_SHA256', DEBUGFS_DIGEST):
            out = nc.read_image_policy(BIN / 'debugfs', images, self.work / 'out')
            self.assertEqual(sorted(path.relative_to(out).as_posix() for path in out.rglob('*')
                                    if path.is_file()), listed)
            for relative in listed:
                self.assertEqual((out / relative).read_bytes(), (partitions / relative).read_bytes())
            own = ext4_images(partitions, self.work / 'own', odm_image=True)
            out = nc.read_image_policy(BIN / 'debugfs', own, self.work / 'own-out')
            self.assertEqual((out / 'odm/etc/selinux/odm_sepolicy.cil').read_text(), '(type odm_marker)\n')
            shutil.rmtree(partitions / 'odm')
            out = nc.read_image_policy(BIN / 'debugfs', ext4_images(partitions, self.work / 'none'),
                                       self.work / 'none-out')
            self.assertFalse((out / 'odm').exists())
            shutil.rmtree(partitions / 'product/etc/selinux')
            (partitions / 'product/etc/empty').write_text('\n')
            broken = ext4_images(partitions, self.work / 'broken')
            with self.assertRaisesRegex(Refusal, "could not read /etc/selinux out of product.img: "
                                        "\\['/etc/selinux: File not found by ext2_lookup'\\]"):
                nc.read_image_policy(BIN / 'debugfs', broken, self.work / 'broken-out')
            (images / 'system_ext.img').unlink()
            with self.assertRaisesRegex(Refusal, 'the verified images hold no system_ext.img'):
                nc.read_image_policy(BIN / 'debugfs', images, self.work / 'missing-out')
            with self.assertRaisesRegex(Refusal, 'holds a space or a quote'):
                nc.read_image_policy(BIN / 'debugfs', own, self.work / 'with space')
        with mock.patch.object(nc.install_zip, 'DEBUGFS_SHA256', '0' * 64):
            with self.assertRaisesRegex(Refusal, 'not the pinned debugfs'):
                nc.read_image_policy(BIN / 'debugfs', own, self.work / 'pin-out')

    def test_debugfs_messages_and_its_exit_status_refuse(self):
        partitions = make_partitions(self.work / 'p', compile_policy=False,
                                     add={'odm/etc/selinux/odm_sepolicy.cil': '(type odm_marker)\n'})
        images = ext4_images(partitions, self.work / 'images')
        for word, status, reason in (
                ('rdump', 0, "could not read /system/etc/selinux out of system.img: \\['debugfs: noise'\\]"),
                ('dump', 0, "could not read /system/build.prop out of system.img: \\['debugfs: noise'\\]"),
                ('stat', 0, "cannot tell whether vendor.img holds /odm/etc/selinux: \\['debugfs: noise'\\]"),
                ('rdump', 1, 'debugfs rdump on system.img exited 1')):
            with self.subTest(word=word, status=status):
                # the pinned debugfs does the work; this wrapper adds a message or a status
                wrapper = self.work / f'debugfs-{word}-{status}'
                wrapper.write_text(f'#!{sys.executable}\nimport subprocess, sys\n'
                                   f'code = subprocess.run([{str(BIN / "debugfs")!r}] + sys.argv[1:]).returncode\n'
                                   f'if sys.argv[2].split()[0] == {word!r}:\n'
                                   f'    print("debugfs: noise", file=sys.stderr)\n    code = {status} or code\n'
                                   'sys.exit(code)\n')
                wrapper.chmod(0o755)
                with mock.patch.object(nc.install_zip, 'DEBUGFS_SHA256', sha(wrapper.read_bytes())):
                    with self.assertRaisesRegex(Refusal, reason):
                        nc.read_image_policy(wrapper, images, self.work / f'out-{word}-{status}')


@unittest.skipUnless(HAVE_TOOLS, 'set ANDRIX_PIXEL_TREES to 2026081300=TREE with its host tools built')
class PolicyTests(Work):
    """Steps B, D and E with the pinned tools, and the whole check."""

    def official(self, **kwargs):
        work = Path(tempfile.mkdtemp(prefix='official-', dir=self.work))
        return nc.Inputs.from_directory(make_partitions(work, **kwargs))

    def full(self, partitions, official=True, expanded=None, **kwargs):
        official = self.official() if official is True else official
        return nc.check(nc.Inputs.from_directory(partitions), expanded=self.expanded(expanded),
                        variant='user', tools=TOOLS, base_tag='2026081300',
                        tree=PINNED_TREE, scratch=self.work, official=official, **kwargs)

    def corpus(self, partitions, variant='user', expanded=None, **kwargs):
        return nc.corpus_check(nc.Inputs.from_directory(partitions),
                               expanded=self.expanded(expanded, name='corpus.conf'), variant=variant,
                               tools=TOOLS, base_tag='2026081300',
                               tree=PINNED_TREE, scratch=self.work, **kwargs)

    def test_the_tools_are_the_pinned_ones(self):
        self.assertEqual(sorted(nc.pinned_tools(TOOLS)), sorted(nc.PINS))

    def test_the_synthetic_policy_passes_and_every_mutant_fails(self):
        report = self.full(make_partitions(self.work))
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(list(report['checks']), ['tools', 'A_loaded_policy', 'B_owner_domains',
                                                  'C_rule_sources', 'D_rules_on_policy',
                                                  'E_control_and_mutants', 'F_aosp_rules',
                                                  'G_extended_rules'])
        self.assertEqual(report['checks']['F_aosp_rules']['rules'], 1)
        self.assertEqual(report['checks']['G_extended_rules']['pairs'], 0)
        mutants = report['checks']['E_control_and_mutants']['mutants']
        self.assertEqual([m['rule'] for m in mutants if m['fails']], list(range(1, 29)))
        self.assertEqual(report['checks']['D_rules_on_policy']['rules'], 28)

    def gate_run(self, andrix, official, **changes):
        """The gate on real ext4 images of synthetic partitions, with install_zip.py's
        verifications stood in for."""
        zip_path = self.work / 'caiman-install-andrix1.zip'
        zip_path.write_bytes(b'synthetic Andrix install zip\n')
        expanded = self.expanded()
        record = release_record(self.work / 'release.json', zip_path, expanded, **changes)
        # the corpus tool set stands in for an image set here; the gate refuses it otherwise
        with verified_zips(andrix, official), mock.patch.object(nc.install_zip, 'DEBUGFS_SHA256', DEBUGFS_DIGEST), \
                mock.patch.object(nc, 'CORPUS_ONLY', frozenset()):
            return nc.gate(zip_path, official_kit=self.work / 'caiman-install-2026081300.zip',
                           release_record=record, expanded=expanded, variant='user', tools=TOOLS,
                           kit={'debugfs': str(BIN / 'debugfs')}, tree=PINNED_TREE, scratch=self.work)

    @unittest.skipUnless(HAVE_E2FS, 'needs mke2fs and debugfs of the pinned tree')
    def test_the_command_line_passes_and_refuses(self):
        andrix = ext4_images(make_partitions(self.work / 'a'), self.work / 'a-images')
        official = ext4_images(make_partitions(self.work / 'o'), self.work / 'o-images')
        zip_path = self.work / 'caiman-install-andrix1.zip'
        zip_path.write_bytes(b'synthetic Andrix install zip\n')
        expanded = self.expanded()
        record = release_record(self.work / 'release.json', zip_path, expanded)
        adevtool = self.work / 'adevtool.json'
        adevtool.write_text('{}')
        arguments = ['--zip', str(zip_path), '--official-kit', str(self.work / 'caiman-install-2026081300.zip'),
                     '--release-record', str(record), '--expanded', str(expanded), '--variant', 'user',
                     '--grapheneos-tree', PINNED_TREE, '--allowed-signers', 'x', '--stable', 'x',
                     '--record', str(adevtool), '--avbtool', 'x', '--simg2img', 'x', '--lpunpack', 'x',
                     '--debugfs', str(BIN / 'debugfs'), '--scratch', str(self.work)]
        arguments += [f'--{name}={path}' for name, path in TOOLS.items()]
        source = source_copy(self.work)
        board = source / 'board/owner-policy.mk'
        board.write_text(board.read_text().replace(' vendor/andrix/owner/platform/sepolicy', ''))
        with verified_zips(andrix, official), mock.patch.object(nc.install_zip, 'DEBUGFS_SHA256', DEBUGFS_DIGEST), \
                mock.patch.object(nc, 'CORPUS_ONLY', frozenset()):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = nc.main(arguments)
            self.assertEqual(status, 0, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['verdict'], 'PASS')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = nc.main(arguments + ['--source-root', str(source), '--grapheneos-tree', str(self.work)])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report['verdict'], 'REFUSE')
        self.assertTrue(report['reasons'][0].startswith('C_rule_sources: '))
        self.assertIn('rule 23 names owner/platform/sepolicy/owner_lifecycle.te:7', report['reasons'][0])
        self.assertIn('the tree holds no regular file system/sepolicy/private/domain.te',
                      report['reasons'][0])
        self.assertTrue(report['reasons'][1].startswith('D_rules_on_policy: step C did not pass'))
        self.assertTrue(report['reasons'][3].startswith('F_aosp_rules: step C did not pass'))

    @unittest.skipUnless(HAVE_E2FS, 'needs mke2fs and debugfs of the pinned tree')
    def test_the_gate_reads_both_policies_out_of_the_verified_images(self):
        andrix = ext4_images(make_partitions(self.work / 'a', cil=COMPAT), self.work / 'a-images')
        official = ext4_images(make_partitions(self.work / 'o'), self.work / 'o-images')
        report = self.gate_run(andrix, official)
        self.assertEqual((report['mode'], report['verdict']), ('gate', 'PASS'), report['reasons'])
        self.assertEqual(list(report['checks']), ['release_record', 'image', 'expanded_rule_file',
                                                  'official_kit', 'tools', 'A_loaded_policy',
                                                  'B_owner_domains', 'C_rule_sources', 'D_rules_on_policy',
                                                  'E_control_and_mutants', 'F_aosp_rules', 'G_extended_rules'])
        self.assertEqual(len(report['checks']['A_loaded_policy']['cil_files']), 12)
        self.assertEqual(report['checks']['C_rule_sources']['policy_dirs'], POLICY_DIRS)
        bad = make_partitions(self.work / 'b')
        (bad / 'vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256'
         ).write_text('0' * 64 + '\n')
        report = self.gate_run(andrix, ext4_images(bad, self.work / 'b-images'))
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['F_aosp_rules', 'G_extended_rules'])
        self.assertRegex(report['checks']['F_aosp_rules']['reason'],
                         '^the official policy: .* init would not load the precompiled policy$')

    def test_a_string_cannot_stand_for_a_definition(self):
        # a spaced definition and a definition shaped string, or a definition hidden from secilc in a
        # comment by a quoted carriage return: the real sets differ, so the pair the Andrix files show
        # is new, as secilc itself sees it
        def files(label, members, form):
            if form == 'string':
                definition = (f'( typeattributeset base_typeattr_7 ({members}))\n'
                              '(genfscon sysfs "/(typeattributeset base_typeattr_7 (domain))" (u object_r sysfs ((s0) (s0))))\n')
            else:
                definition = ('; "\r(typeattributeset base_typeattr_7 (domain))(genfscon sysfs "\r'
                              f'(typeattributeset base_typeattr_7 ({members}))\r;")\n')
            extra = ('(typeattribute base_typeattr_7)\n' + definition
                     + '(allow domain vendor_file (file (ioctl)))\n'
                     '(neverallowx base_typeattr_7 vendor_file (ioctl file (0x9000)))\n'
                     '(allowx domain vendor_file (ioctl file (0x9000)))\n')
            partitions = make_partitions(self.work / label, compile_policy=False, ignore_neverallows=True,
                                         edit={'vendor/etc/selinux/vendor_sepolicy.cil': lambda text: text + extra})
            inputs = nc.Inputs.from_directory(partitions)
            state = {}
            nc.check_loaded_policy(inputs, 'user', state)
            return inputs, state['cil_files']
        for form in ('string', 'comment'):
            with self.subTest(form=form):
                ours = files('ours-' + form, 'shell andrix_owner', form)
                theirs = files('theirs-' + form, 'shell', form)
                with self.assertRaisesRegex(Refusal, r'do not show: \(neverallowx \(shell andrix_owner\) vendor_file '
                                            r'\(ioctl file \(0x9000\)\)\) by \(allowx domain vendor_file'):
                    nc.check_extended_rules(TOOLS, *ours, *theirs, self.work)
                self.assertEqual(nc.check_extended_rules(TOOLS, *theirs, *theirs, self.work),
                                 {'pairs': 1, 'vendor_findings': ['(neverallowx (shell) vendor_file (ioctl file (0x9000)))']})

    def test_the_pinned_trees_tools_are_the_2026081300_set(self):
        # the tree's bytes are that set's, which serves the corpus; the wrapper's check, which
        # serves images, refuses the set, and passes it only where it stands in for an image set
        self.assertEqual(sorted(nc.pinned_tools({name: BIN / name for name in nc.PINS},
                                                nc.tool_pins('2026081300'))), sorted(nc.PINS))
        with mock.patch.object(nc, 'CORPUS_ONLY', frozenset()):
            self.assertEqual(nc.check_build_tools('2026081300', BIN)['pinned'], sorted(nc.PINS))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nc.main(['--build-tools', str(BIN), '--base-tag', '2026081300'])
        report = json.loads(output.getvalue())
        self.assertEqual((status, report['verdict']), (1, 'REFUSE'))
        self.assertIn('serves only the stage 1 corpus', report['reasons'][0])

    def test_each_witness_breaks_its_own_rule_and_only_the_rules_it_declares(self):
        partitions = make_partitions(self.work)
        inputs = nc.Inputs.from_directory(partitions)
        state = {}
        nc.check_loaded_policy(inputs, 'user', state)
        files = state['cil_files']
        rules = [entry['expansion']['user'] for entry in TABLE['rules']]
        for entry in TABLE['rules']:
            with self.subTest(rule=entry['number']):
                mutant = self.work / f'm{entry["number"]}.cil'
                mutant.write_text(entry['witness'] + '\n')
                binary = self.work / f'm{entry["number"]}.policy'
                nc.compile_policy(TOOLS, files, inputs, binary, [mutant])
                broken = {number for number, rule in enumerate(rules, 1)
                          if nc.analyze(TOOLS, binary, rule, self.work, 'one')['status'] != 0}
                self.assertEqual(broken, {entry['number'], *entry.get('also_violates', [])})

    def test_a_policy_without_andrix_owner_fails_B(self):
        def drop(text):
            kept = []
            for line in text.split('\n'):
                if line.startswith('(typeattributeset domain '):
                    kept.append(re.sub(r' andrix_owner(?=[ )])', '', line))
                elif re.search(r'\bandrix_owner\b', line) is None:
                    kept.append(line)
            return '\n'.join(kept)
        partitions = make_partitions(self.work, edit={
            'system/etc/selinux/plat_sepolicy.cil': drop,
            'system_ext/etc/selinux/system_ext_sepolicy.cil': drop})
        report = self.full(partitions)
        self.assertEqual(report['checks']['A_loaded_policy']['ok'], True)
        self.assertEqual(report['checks']['B_owner_domains']['reason'],
                         'the policy has no domain andrix_owner; it is not a policy with the owner '
                         'session on')
        self.assertIn('Type or attribute andrix_owner used in neverallow undefined',
                      report['checks']['D_rules_on_policy']['reason'])

    def test_an_undefined_type_class_or_permission_fails_D_through_the_warning(self):
        partitions = make_partitions(self.work)
        policy = partitions / 'vendor/etc/selinux/precompiled_sepolicy'
        rules = [entry['expansion']['user'] for entry in TABLE['rules']]
        self.assertEqual(nc.check_rules_on_policy(TOOLS, policy, rules, self.work)['rules'], 28)
        for rule, warning in (
                ('neverallow andrix_owner andrix_no_such_type:file execute;',
                 'Type or attribute andrix_no_such_type used in neverallow undefined'),
                ('neverallow andrix_owner andrixd:no_such_class read;',
                 'Class no_such_class used in neverallow undefined'),
                ('neverallow andrix_owner andrixd:process no_such_permission;',
                 'Permission no_such_permission used in neverallow undefined in class process')):
            with self.subTest(rule=rule):
                result = nc.analyze(TOOLS, policy, rules + [rule], self.work, 'undefined')
                self.assertEqual((result['status'], result['violations']), (0, []))
                with self.assertRaisesRegex(Refusal, re.escape(warning)):
                    nc.require_pass(result, 'the loaded policy')
                with self.assertRaisesRegex(Refusal, 'exited 0 with 0 violations and [12] warnings'):
                    nc.check_rules_on_policy(TOOLS, policy, rules + [rule], self.work)

    def test_an_empty_rule_file_fails_D(self):
        policy = make_partitions(self.work) / 'vendor/etc/selinux/precompiled_sepolicy'
        result = nc.analyze(TOOLS, policy, [], self.work, 'empty')
        self.assertNotEqual(result['status'], 0)
        with self.assertRaisesRegex(Refusal, 'sepolicy-analyze exited 255'):
            nc.require_pass(result, 'an empty rule file')
        comments = nc.analyze(TOOLS, policy, ['# no rule at all'], self.work, 'comments')
        self.assertIn('Error while parsing neverallow rules', comments['stderr'])
        with self.assertRaisesRegex(Refusal, 'no rules to check'):
            nc.check_rules_on_policy(TOOLS, policy, [], self.work)

    def test_a_violation_fails_D(self):
        extra = self.work / 'grant.cil'
        extra.write_text('(allow shell andrix_owner (process (transition)))\n')
        partitions = make_partitions(self.work, extra=[extra])
        report = self.full(partitions)
        self.assertIn("allow shell andrix_owner:process { transition };",
                      report['checks']['D_rules_on_policy']['reason'])
        self.assertIn('differs from the loaded policy', report['checks']['E_control_and_mutants']['reason'])

    def test_a_control_that_leaves_one_cil_file_out_fails_E(self):
        partitions = make_partitions(self.work)
        inputs = nc.Inputs.from_directory(partitions)
        state = {}
        nc.check_loaded_policy(inputs, 'user', state)
        self.assertEqual(len(state['cil_files']), 9)
        for left_out in state['cil_files'][1:]:
            with self.subTest(left_out=left_out):
                files = [phone for phone in state['cil_files'] if phone != left_out]
                with self.assertRaisesRegex(Refusal, 'secilc exited|differs from the loaded policy'):
                    nc.check_control_and_mutants(TOOLS, inputs, files, state['policy'], TABLE, 'user',
                                                 self.work)

    def test_a_loaded_policy_from_other_files_fails_E(self):
        extra = self.work / 'more.cil'
        extra.write_text('(type more_file)\n(allow shell more_file (file (read)))\n')
        report = self.full(make_partitions(self.work, extra=[extra]))
        self.assertEqual(report['checks']['D_rules_on_policy']['ok'], True)
        self.assertRegex(report['checks']['E_control_and_mutants']['reason'],
                         'differs from the loaded policy from line [0-9]+')

    def test_a_witness_that_breaks_nothing_or_does_not_compile_fails_E(self):
        table = copy.deepcopy(TABLE)
        table['rules'][26]['witness'] = '(allow andrixd andrix_owner (process (transition)))'
        table['rules'][4]['witness'] = '(allow andrix_owner andrix_no_such_type (binder (call)))'
        partitions = make_partitions(self.work)
        inputs = nc.Inputs.from_directory(partitions)
        state = {}
        nc.check_loaded_policy(inputs, 'user', state)
        with self.assertRaisesRegex(Refusal, r'mutant 5: the witness does not compile.*mutant 27: its '
                                    r'own rule alone passed'):
            nc.check_control_and_mutants(TOOLS, inputs, state['cil_files'], state['policy'], table,
                                         'user', self.work)

    def test_a_violation_carried_by_the_image_files_fails_D_and_the_control(self):
        partitions = make_partitions(self.work, edit={
            'vendor/etc/selinux/vendor_sepolicy.cil':
                lambda text: text + '(allow shell_202404 andrix_owner_pid_prop (property_service (set)))\n'})
        report = self.full(partitions)
        self.assertIn('allow shell andrix_owner_pid_prop:property_service { set };',
                      report['checks']['D_rules_on_policy']['reason'])
        self.assertRegex(report['checks']['E_control_and_mutants']['reason'],
                         '^the control: sepolicy-analyze exited 255 with 1 violations')

    def test_a_file_that_is_no_policy_fails_B(self):
        partitions = make_partitions(self.work, compile_policy=False)
        with self.assertRaisesRegex(Refusal, 'sepolicy-analyze attribute domain exited 1: .*magic number'):
            nc.check_owner_domains(TOOLS, partitions / 'vendor/etc/selinux/precompiled_sepolicy')

    def test_later_steps_refuse_when_step_A_fails(self):
        partitions = make_partitions(self.work / 'hash')
        (partitions / 'vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256'
         ).write_text('0' * 64 + '\n')
        report = self.full(partitions)
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['A_loaded_policy', 'E_control_and_mutants', 'G_extended_rules'])
        self.assertIn('step A did not pass', report['checks']['E_control_and_mutants']['reason'])
        partitions = make_partitions(self.work / 'odm')
        (partitions / 'odm/etc/selinux').mkdir(parents=True)
        (partitions / 'odm/etc/selinux/precompiled_sepolicy').write_bytes(b'x')
        report = self.full(partitions)
        for name in ('B_owner_domains', 'D_rules_on_policy', 'F_aosp_rules'):
            self.assertEqual(report['checks'][name]['reason'], 'step A found no precompiled policy')

    def test_the_whole_set_must_fail_too(self):
        partitions = make_partitions(self.work)
        inputs = nc.Inputs.from_directory(partitions)
        state = {}
        nc.check_loaded_policy(inputs, 'user', state)
        real = nc.analyze

        def set_passes(tools, policy, rules, work, name):
            result = real(tools, policy, rules, work, name)
            if name.startswith('set_'):
                result = {**result, 'status': 0, 'violations': [], 'warnings': [], 'stderr': ''}
            return result
        with mock.patch.object(nc, 'analyze', set_passes):
            with self.assertRaisesRegex(Refusal, 'mutant 1: the whole set passed'):
                nc.check_control_and_mutants(TOOLS, inputs, state['cil_files'], state['policy'],
                                             TABLE, 'user', self.work)

    def test_init_compiles_with_N_so_platform_statements_do_not_stop_a_mutant(self):
        partitions = make_partitions(self.work)
        inputs = nc.Inputs.from_directory(partitions)
        state = {}
        nc.check_loaded_policy(inputs, 'user', state)
        mutant = self.work / 'm28.cil'
        mutant.write_text(TABLE['rules'][27]['witness'] + '\n')
        command = nc.secilc_command(TOOLS['secilc'], state['cil_files'], inputs, self.work / 'x')
        self.assertEqual(command[2:10], ['-m', '-M', 'true', '-G', '-N', '-v', '-c', '30'])
        without = [part for part in command if part != '-N'] + [str(mutant)]
        status, _, errors = nc.run_tool(without)
        self.assertNotEqual(status, 0)
        self.assertIn('neverallow check failed', errors)
        nc.compile_policy(TOOLS, state['cil_files'], inputs, self.work / 'y', [mutant])

    def test_checkpolicy_failure_is_named(self):
        partitions = make_partitions(self.work, compile_policy=False)
        with self.assertRaisesRegex(Refusal, 'checkpolicy could not decompile precompiled_sepolicy'):
            nc.decompile(TOOLS, partitions / 'vendor/etc/selinux/precompiled_sepolicy', self.work / 'o.cil')

    def test_without_an_official_policy_F_and_G_refuse(self):
        report = self.full(make_partitions(self.work), official=None)
        reason = 'no official policy of the base tag was given, so nothing tells vendor findings from Andrix ones'
        self.assertEqual(report['reasons'], [f'F_aosp_rules: {reason}', f'G_extended_rules: {reason}'])

    def test_an_aosp_violation_fails_F_unless_the_official_policy_shows_it(self):
        grant = {'vendor/etc/selinux/vendor_sepolicy.cil':
                 lambda text: text + '(allow shell_202404 kernel (process (dyntransition)))\n'}
        report = self.full(make_partitions(self.work, edit=grant))
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['F_aosp_rules'])
        self.assertEqual(report['checks']['F_aosp_rules']['reason'],
                         'violations the official policy does not show: allow shell kernel:process dyntransition')
        report = self.full(make_partitions(self.work / 'both', edit=grant), official=self.official(edit=grant))
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['F_aosp_rules']['vendor_findings'],
                         ['allow shell kernel:process dyntransition'])

    def test_a_warning_only_the_andrix_policy_gives_fails_F(self):
        text = expanded_text() + ('neverallow shell official_only_file:file read;\n'
                                  'neverallow shell nowhere_file:file read;\n')
        official = self.official(edit={'vendor/etc/selinux/vendor_sepolicy.cil': lambda t: t + (
            '(type official_only_file)\n(allow shell_202404 official_only_file (file (getattr)))\n')})
        report = self.full(make_partitions(self.work), official=official, expanded=text)
        self.assertEqual(report['checks']['F_aosp_rules']['reason'],
                         "warnings the official policy does not give: ['Warning!  Type or attribute "
                         "official_only_file used in neverallow undefined in policy being checked.']")
        report = self.full(make_partitions(self.work / 'nowhere'), expanded=expanded_text() +
                           'neverallow shell nowhere_file:file read;\n')
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['F_aosp_rules']['warnings_on_both'],
                         ['Warning!  Type or attribute nowhere_file used in neverallow undefined in '
                          'policy being checked.'])

    def test_an_owner_tiocsti_allowx_fails_G(self):
        mutant = {'system_ext/etc/selinux/system_ext_sepolicy.cil':
                  lambda text: text + '(allowx andrix_owner andrix_owner_devpts (ioctl chr_file (0x5412)))\n'}
        report = self.full(make_partitions(self.work, edit=mutant, ignore_neverallows=True))
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['G_extended_rules'])
        self.assertEqual(report['checks']['G_extended_rules']['reason'],
                         'violated rules the official files do not show: (neverallowx domain '
                         'andrix_owner_devpts (ioctl chr_file (0x5412))) by (allowx andrix_owner '
                         'andrix_owner_devpts (ioctl chr_file (0x5412)))')

    def test_a_vendor_allowx_fails_G_unless_the_official_files_show_it(self):
        mutant = {'vendor/etc/selinux/vendor_sepolicy.cil':
                  lambda text: text + '(allowx shell vendor_file (ioctl file (0x8008)))\n'}
        report = self.full(make_partitions(self.work, edit=mutant, ignore_neverallows=True))
        self.assertIn('(neverallowx shell_202404 vendor_file (ioctl file (0x8008))) by (allowx shell '
                      'vendor_file (ioctl file (0x8008)))', report['checks']['G_extended_rules']['reason'])
        official = self.official(edit=mutant, ignore_neverallows=True)
        report = self.full(make_partitions(self.work / 'both', edit=mutant, ignore_neverallows=True),
                           official=official)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['G_extended_rules']['vendor_findings'],
                         ['(neverallowx shell_202404 vendor_file (ioctl file (0x8008)))'])

    def test_unknown_output_or_a_failing_official_compile_refuses_F_and_G(self):
        with self.assertRaisesRegex(Refusal, 'on the official policy exited 255'):
            nc.violations_and_warnings({'status': 255, 'violations': [], 'warnings': [], 'stdout': '',
                                        'stderr': 'Error while parsing neverallow rules\n'}, 'official')
        official = make_partitions(self.work / 'official')
        (official / 'vendor/etc/selinux/plat_pub_versioned.cil').write_text('(typeattribute other)\n')
        report = self.full(make_partitions(self.work), official=nc.Inputs.from_directory(official))
        self.assertRegex(report['checks']['G_extended_rules']['reason'],
                         '^secilc without -N on the official files exited 25[0-9]')
        (official / 'odm/etc/selinux').mkdir(parents=True)
        (official / 'odm/etc/selinux/precompiled_sepolicy').write_bytes(b'x')
        report = self.full(make_partitions(self.work / 'odm'), official=nc.Inputs.from_directory(official))
        self.assertIn('caiman has no odm partition', report['checks']['F_aosp_rules']['reason'])

    def test_an_expanded_file_with_only_the_andrix_rules_fails_F(self):
        text = expanded_text().replace('neverallow * kernel:process dyntransition;\n', '')
        report = self.full(make_partitions(self.work), expanded=text)
        self.assertEqual(report['checks']['F_aosp_rules']['reason'],
                         'the expanded rule file holds no rule besides the Andrix rules')

    def test_pairs_drop_places_and_generated_attribute_numbers(self):
        report = ('neverallow check failed at {0}:{1}\n  (neverallow base_typeattr_{2} x (file (read)))\n'
                  '    <root>\n    allow at {0}:{3}\n      (allow base_typeattr_{2} x (file (read)))\n\n')
        meaning = '(and (domain) (not (andrixd)))'
        one = nc.parse_pairs(report.format('a.cil', 10, 12, 20), 'Andrix', {'base_typeattr_12': meaning})
        self.assertEqual(one, nc.parse_pairs(report.format('b.cil', 99, 13, 7), 'official',
                                             {'base_typeattr_13': meaning}))
        self.assertEqual(one, {(f'(neverallow {meaning} x (file (read)))',
                                f'(allow {meaning} x (file (read)))')})
        with self.assertRaisesRegex(Refusal, 'printed a violation of unknown form'):
            nc.parse_pairs('neverallow check failed at a.cil:1\n  something else\n\n', 'Andrix', {})

    def corpus_arguments(self, partitions):
        arguments = ['--corpus', '--partitions', str(partitions), '--variant', 'user',
                     '--expanded', str(self.expanded(name='cli.conf')), '--scratch', str(self.work),
                     '--grapheneos-tree', PINNED_TREE, '--base-tag', '2026081300']
        arguments += [f'--{name}={path}' for name, path in TOOLS.items()]
        return arguments

    def test_corpus_mode_never_passes_even_when_every_corpus_check_succeeds(self):
        partitions = make_partitions(self.work)
        report = self.corpus(partitions)
        self.assertEqual((report['mode'], report['verdict']), ('corpus', 'CORPUS'), report['reasons'])
        self.assertEqual(list(report['checks']), ['tools', 'A_loaded_policy', 'B_owner_domains',
                                                  'C_rule_sources', 'D_rules_on_policy',
                                                  'E_control_and_mutants', 'G_extended_rules'])
        self.assertEqual(report['not_run'], {'F_aosp_rules': nc.NO_OFFICIAL_RELEASE})
        self.assertEqual(report['checks']['A_loaded_policy']['loaded'], nc.PRECOMPILED)
        self.assertEqual(len(report['checks']['E_control_and_mutants']['mutants']), 28)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nc.main(self.corpus_arguments(partitions))
        self.assertEqual((status, json.loads(output.getvalue())['verdict']), (nc.CORPUS_EXIT, 'CORPUS'))

    def test_a_userdebug_corpus_fails_the_user_rules_with_exactly_the_exception(self):
        remounter = {'system/etc/selinux/plat_sepolicy.cil': lambda text: text + (
            '(type overlay_remounter)\n(roletype r overlay_remounter)\n'
            '(typeattributeset domain (overlay_remounter))\n')}
        grant = {**remounter, 'system_ext/etc/selinux/system_ext_sepolicy.cil': lambda text: text + (
            '(allow overlay_remounter andrix_owner_entry (file (execute)))\n')}
        partitions = make_partitions(self.work / 'grant', edit=grant, variant='userdebug', loaded='odm',
                                     add={'debug_ramdisk/userdebug_plat_sepolicy.cil': '(type x)\n'})
        report = self.corpus(partitions, variant='userdebug')
        self.assertEqual(report['verdict'], 'CORPUS', report['reasons'])
        self.assertEqual(report['checks']['D_rules_on_policy']['user_rules']['violations'],
                         [nc.USERDEBUG_EXCEPTION])
        self.assertEqual(report['checks']['A_loaded_policy']['userdebug_policies_recorded'],
                         ['/debug_ramdisk/userdebug_plat_sepolicy.cil'])
        self.assertEqual(report['checks']['A_loaded_policy']['loaded'], nc.ODM_PRECOMPILED)
        gate = nc.check(nc.Inputs.from_directory(partitions), expanded=self.expanded(), variant='userdebug',
                        tools=TOOLS, base_tag='2026081300', tree=PINNED_TREE,
                        scratch=self.work, official=self.official())
        self.assertIn('which init would load instead', gate['checks']['A_loaded_policy']['reason'])
        report = self.corpus(make_partitions(self.work / 'none', edit=remounter, variant='userdebug'),
                             variant='userdebug')
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['D_rules_on_policy'])
        self.assertRegex(report['checks']['D_rules_on_policy']['reason'],
                         'must fail on a userdebug corpus with exactly')

    def test_corpus_step_g_takes_no_violated_rule(self):
        mutant = {'vendor/etc/selinux/vendor_sepolicy.cil':
                  lambda text: text + '(allowx shell vendor_file (ioctl file (0x8008)))\n'}
        report = self.corpus(make_partitions(self.work, edit=mutant, ignore_neverallows=True))
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['G_extended_rules'])
        self.assertEqual(report['checks']['G_extended_rules']['reason'],
                         'the corpus files violate rules: (neverallowx shell_202404 vendor_file (ioctl '
                         'file (0x8008))) by (allowx shell vendor_file (ioctl file (0x8008)))')
        self.assertEqual(report['verdict'], 'REFUSE')

    def test_compat_files_and_an_odm_policy_pass_the_whole_check(self):
        report = self.full(make_partitions(self.work, cil=COMPAT))
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(len(report['checks']['A_loaded_policy']['cil_files']), 12)

    def test_missing_genfs_version_metadata_passes_the_whole_check(self):
        partitions = make_partitions(self.work, remove=['vendor/etc/selinux/genfs_labels_version.txt'],
                                     unbuilt=['system/etc/selinux/plat_sepolicy_genfs_202504.cil'])
        report = self.full(partitions)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['A_loaded_policy']['genfs_labels_version'], 202404)
        self.assertEqual(len(report['checks']['A_loaded_policy']['cil_files']), 8)

    def test_two_offending_permissions_where_the_official_policy_permits_one(self):
        rule = 'neverallow shell kernel:file { read write };\n'
        both, one = ({'vendor/etc/selinux/vendor_sepolicy.cil':
                      lambda text, perms=perms: text + f'(allow shell_202404 kernel (file ({perms})))\n'}
                     for perms in ('read write', 'read'))
        report = self.full(make_partitions(self.work / 'both', edit=both), official=self.official(edit=one),
                           expanded=expanded_text() + rule)
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['F_aosp_rules'])
        self.assertEqual(report['checks']['F_aosp_rules']['reason'],
                         'violations the official policy does not show: allow shell kernel:file write')
        report = self.full(make_partitions(self.work / 'one', edit=one), official=self.official(edit=both),
                           expanded=expanded_text() + rule)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['F_aosp_rules']['vendor_findings'], ['allow shell kernel:file read'])

    def test_generated_attributes_compare_by_their_definitions_in_secilc(self):
        def vendor(number, excluded):
            return {'vendor/etc/selinux/vendor_sepolicy.cil': lambda text: text + (
                f'(typeattribute base_typeattr_{number}_202404)\n'
                f'(typeattributeset base_typeattr_{number}_202404 (and (domain) (not ({excluded}))))\n'
                f'(neverallowx base_typeattr_{number}_202404 vendor_file (ioctl file (0x9000)))\n'
                '(allowx shell_202404 vendor_file (ioctl file (0x9000)))\n')}
        official = self.official(edit=vendor(7, 'andrixd'), ignore_neverallows=True)
        report = self.full(make_partitions(self.work / 'same', edit=vendor(9, 'andrixd'),
                                           ignore_neverallows=True), official=official)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['G_extended_rules']['vendor_findings'],
                         ['(neverallowx (and (domain) (not (andrixd))) vendor_file (ioctl file (0x9000)))'])
        report = self.full(make_partitions(self.work / 'other', edit=vendor(7, 'andrix_owner'),
                                           ignore_neverallows=True), official=official)
        self.assertEqual([name for name, result in report['checks'].items() if not result['ok']],
                         ['G_extended_rules'])
        self.assertEqual(report['checks']['G_extended_rules']['reason'],
                         'violated rules the official files do not show: (neverallowx (and (domain) '
                         '(not (andrix_owner))) vendor_file (ioctl file (0x9000))) by (allowx shell_202404 '
                         'vendor_file (ioctl file (0x9000)))')

    def test_an_andrix_subset_of_the_official_offenders_passes_and_a_new_offender_fails(self):
        first, second = ('(allowx shell vendor_file (ioctl file (0x8008)))\n',
                         '(allowx shell_202404 vendor_file (ioctl file (0x8008)))\n')
        both, one = ({'vendor/etc/selinux/vendor_sepolicy.cil': lambda text, added=added: text + added}
                     for added in (first + second, first))
        report = self.full(make_partitions(self.work / 'one', edit=one, ignore_neverallows=True),
                           official=self.official(edit=both, ignore_neverallows=True))
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual((report['checks']['G_extended_rules']['pairs'],
                          report['checks']['G_extended_rules']['vendor_findings']),
                         (1, ['(neverallowx shell_202404 vendor_file (ioctl file (0x8008)))']))
        report = self.full(make_partitions(self.work / 'both', edit=both, ignore_neverallows=True),
                           official=self.official(edit=one, ignore_neverallows=True))
        self.assertEqual(report['checks']['G_extended_rules']['reason'],
                         'violated rules the official files do not show: (neverallowx shell_202404 '
                         'vendor_file (ioctl file (0x8008))) by ' + second.strip())

    @unittest.skipUnless(EXPANDED_IN_TREE and EXPANDED_IN_TREE.is_file(),
                         "the pinned tree's output holds no expanded rule file")
    def test_the_table_against_the_expanded_rule_file_in_the_pinned_tree(self):
        text = EXPANDED_IN_TREE.read_text(encoding='utf-8')
        detail = self.rules_check(expanded=text)
        self.assertEqual(detail['rules'], 28)
        self.assertEqual(len(nc.check_expanded_sources(text, POLICY_DIRS)), 5)
        statements = nc.expanded_statements(text)
        for entry in TABLE['rules']:
            self.assertEqual(statements.count(entry['expansion']['user']), 1, entry['number'])


if __name__ == '__main__':
    unittest.main()
