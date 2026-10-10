# SPDX-License-Identifier: Apache-2.0
"""The neverallow check, steps A to G, on small SYNTHETIC CIL policies. No phone, no build.

fixtures/neverallow/partitions holds the CIL files of a synthetic split policy, laid out as on
the phone. Each case copies them into a temporary directory, compiles the precompiled policy
with the pinned secilc in the build's file order and writes the hash files the build would.

Steps B, D and E need sepolicy-analyze, secilc and checkpolicy from the host output of the
pinned tree. Name that tree with ANDRIX_PIXEL_TREES (2026081300=TREE). Without it those cases
skip, and the cases of steps A and C run alone. With it, the witness table is also checked
against the expanded rule file in that tree's output, when the file is there.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from caiman import Refusal  # noqa: E402
import neverallow_check as nc  # noqa: E402

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


def write_hashes(partitions):
    for name, cil, mapping in HASHES:
        digest = hashlib.sha256((partitions / cil).read_bytes() + (partitions / mapping).read_bytes())
        line = digest.hexdigest() + '\n'
        (partitions / name).write_text(line)
        (partitions / 'vendor/etc/selinux' / f'precompiled_sepolicy.{Path(name).name}').write_text(line)


def make_partitions(work, *, compile_policy=True, edit=None, extra=None, variant='user',
                    ignore_neverallows=False):
    """The synthetic partitions, with the precompiled policy and the hash files.

    ignore_neverallows compiles as a caiman build does, with secilc -N.
    """
    partitions = Path(work) / 'partitions'
    shutil.copytree(FIXTURE, partitions)
    for relative, function in (edit or {}).items():
        path = partitions / relative
        path.write_text(function(path.read_text()))
    (partitions / 'system/build.prop').write_text(f'ro.build.id=TEST\nro.build.type={variant}\n')
    policy = partitions / 'vendor/etc/selinux/precompiled_sepolicy'
    if compile_policy:
        sources = [str(partitions / name) for name in BUILD_ORDER] + [str(path) for path in extra or ()]
        flags = ['-N'] if ignore_neverallows else []
        status, out, errors = nc.run_tool([TOOLS['secilc'], '-m', '-M', 'true', '-G', *flags, '-c',
                                           nc.POLICY_VERSION, *sources, '-o', policy, '-f', os.devnull])
        if status != 0:
            raise AssertionError(f'the fixture does not compile: {errors}')
    else:
        policy.write_bytes(b'not a policy; step A reads only its bytes\n')
    write_hashes(partitions)
    return partitions


def expanded_text(table=TABLE, variant='user', skip=()):
    """An expanded rule file as m4 -s writes it, with line markers and AOSP rules around."""
    lines = ['#line 1 "system/sepolicy/public/domain.te"',
             'neverallow * kernel:process dyntransition;',
             'neverallowxperm * devpts:chr_file ioctl 0x00005412;']
    for entry in table['rules']:
        if entry['number'] in skip:
            continue
        lines.append(f'#line {entry["line"]} "vendor/andrix/{entry["source"]}"')
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
    for directory in POLICY_DIRS + PATCHES:
        shutil.copytree(ROOT / directory, source / directory)
    return source


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
        with self.assertRaisesRegex(Refusal, 'is not andrix.pixel.neverallow_witnesses/1'):
            nc.load_witnesses(path)

    def test_every_comment_and_line_marker_is_ignored(self):
        statements = nc.expanded_statements(expanded_text())
        self.assertIn(TABLE['rules'][10]['expansion']['user'], statements)
        self.assertNotIn('neverallowxperm', ' '.join(statements))


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
        report = nc.check(nc.Inputs({}, True), expanded='x', variant='eng', tools={})
        self.assertEqual(report['reasons'], ["variant: variant 'eng' is not one of user, userdebug"])

    def test_tools_that_are_not_the_pinned_ones_fail(self):
        fake = self.work / 'secilc'
        fake.write_bytes(b'#!/bin/sh\n')
        with self.assertRaisesRegex(Refusal, 'not the pinned secilc'):
            nc.pinned_tools({'secilc': fake}, {'secilc': nc.SECILC_SHA256})
        with self.assertRaisesRegex(Refusal, 'needs the pinned checkpolicy'):
            nc.pinned_tools({}, {'checkpolicy': nc.CHECKPOLICY_SHA256})


@unittest.skipUnless(HAVE_TOOLS, 'set ANDRIX_PIXEL_TREES to 2026081300=TREE with its host tools built')
class PolicyTests(Work):
    """Steps B, D and E with the pinned tools, and the whole check."""

    def official(self, **kwargs):
        work = Path(tempfile.mkdtemp(prefix='official-', dir=self.work))
        return nc.Inputs.from_directory(make_partitions(work, **kwargs))

    def full(self, partitions, official=True, expanded=None, **kwargs):
        official = self.official() if official is True else official
        return nc.check(nc.Inputs.from_directory(partitions), expanded=self.expanded(expanded),
                        variant='user', tools=TOOLS, policy_dirs=POLICY_DIRS, patch_dirs=PATCHES,
                        scratch=self.work, official=official, **kwargs)

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
        self.assertEqual(report['checks']['G_extended_rules']['units'], 0)
        mutants = report['checks']['E_control_and_mutants']['mutants']
        self.assertEqual([m['rule'] for m in mutants if m['fails']], list(range(1, 29)))
        self.assertEqual(report['checks']['D_rules_on_policy']['rules'], 28)

    def test_the_command_line_passes_and_refuses(self):
        partitions = make_partitions(self.work)
        official = make_partitions(self.work / 'official')
        arguments = ['--partitions', str(partitions), '--expanded', str(self.expanded()),
                     '--variant', 'user', '--scratch', str(self.work), '--official', str(official)]
        arguments += [f'--{name}={path}' for name, path in TOOLS.items()]
        for directory in POLICY_DIRS:
            arguments += ['--policy-dir', directory]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nc.main(arguments + ['--patches', PATCHES[0]])
        self.assertEqual(status, 0, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['verdict'], 'PASS')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nc.main(arguments)
        report = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report['verdict'], 'REFUSE')
        self.assertTrue(report['reasons'][0].startswith('C_rule_sources: '))
        self.assertTrue(report['reasons'][1].startswith('D_rules_on_policy: step C did not pass'))
        self.assertTrue(report['reasons'][3].startswith('F_aosp_rules: step C did not pass'))

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

    def test_units_drop_places_and_generated_attribute_numbers(self):
        report = ('neverallow check failed at {0}:{1}\n  (neverallow base_typeattr_{2} x (file (read)))\n'
                  '    <root>\n    allow at {0}:{3}\n      (allow base_typeattr_{2} x (file (read)))\n\n')
        one = nc.parse_units(report.format('a.cil', 10, 12, 20), 'Andrix')
        self.assertEqual(one, nc.parse_units(report.format('b.cil', 99, 13, 7), 'official'))
        self.assertEqual(one, {('(neverallow base_typeattr x (file (read)))',
                                ('(allow base_typeattr x (file (read)))',))})
        with self.assertRaisesRegex(Refusal, 'printed a violation of unknown form'):
            nc.parse_units('neverallow check failed at a.cil:1\n  something else\n\n', 'Andrix')

    @unittest.skipUnless(EXPANDED_IN_TREE and EXPANDED_IN_TREE.is_file(),
                         "the pinned tree's output holds no expanded rule file")
    def test_the_table_against_the_expanded_rule_file_in_the_pinned_tree(self):
        text = EXPANDED_IN_TREE.read_text(encoding='utf-8')
        detail = self.rules_check(expanded=text)
        self.assertEqual(detail['rules'], 28)
        statements = nc.expanded_statements(text)
        for entry in TABLE['rules']:
            self.assertEqual(statements.count(entry['expansion']['user']), 1, entry['number'])


if __name__ == '__main__':
    unittest.main()
