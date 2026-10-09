# SPDX-License-Identifier: Apache-2.0
"""adevtool records: which stock build each tag uses. Offline, from verbatim fixture files.

Set ANDRIX_PIXEL_TREES to "TAG=TREE:TAG=TREE" with local GrapheneOS source trees to also
derive the records from the real trees and compare them with the committed ones.
"""
import contextlib
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import adevtool_record as record  # noqa: E402
from caiman import Refusal  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'
RECORDS = FIXTURES / 'adevtool' / 'records'
TREES = dict(item.split('=', 1) for item in os.environ.get('ANDRIX_PIXEL_TREES', '').split(':')
             if '=' in item)
EXPECTED = {'2026081300': ('CP2A.260805.005', 'config/device/common/pixel.yml:24',
                           'ripcurrentpro-17.0-15199480', 'g5400c-260317-260429-B-15308590'),
            '2026100600': ('CP3A.261005.005', 'config/device/common/gen9pixel.yml:6',
                           'ripcurrentpro-17.0-15819938', 'g5400c-260604-260807-B-16035863')}


def stored(tag):
    return json.loads((RECORDS / f'{tag}.json').read_text())


def mini_tree(tag, root):
    """An adevtool tree with caiman's real config chain and stub leaf includes."""
    source = FIXTURES / 'adevtool' / tag
    root = Path(root)
    for relative in ('config/device/caiman.yml', 'config/device/common/gen9pixel.yml',
                     'config/device/common/pixel.yml',
                     'vendor-skels/google_devices/caiman/cmds-for-envsetup.sh',
                     'vendor-skels/google_devices/caiman/firmware/android-info.txt'):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, root / relative)
    shutil.copyfile(source / 'vendor-skels/google_devices/caiman/caiman.mk.head',
                    root / 'vendor-skels/google_devices/caiman/caiman.mk')
    (root / 'config/build-index').mkdir(parents=True)
    shutil.copyfile(source / 'config/build-index/build-index-main.excerpt.yml', root / record.INDEX)
    pixel = (root / 'config/device/common/pixel.yml').read_text()
    for leaf in re.findall(r'^  - (\S+\.yml)$', pixel, re.M):
        (root / 'config/device/common' / leaf).write_text('sysprop_exclusions:\n  - ro.example\n')
    return root


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def tree(self, tag):
        return mini_tree(tag, Path(self.tmp.name) / tag)

    def edit(self, root, relative, old, new, count=1):
        path = Path(root) / relative
        text = path.read_text()
        self.assertEqual(text.count(old), count, (relative, old))
        path.write_text(text.replace(old, new))


class StockBuildTests(TreeCase):
    def test_each_tag_records_its_stock_build(self):
        for tag, (build, set_by, bootloader, baseband) in EXPECTED.items():
            with self.subTest(tag=tag):
                derived = record.derive_content(self.tree(tag), tag)
                self.assertEqual(derived['stock_build'], build)
                self.assertEqual(derived['stock_build_set_by'], set_by)
                info = derived['generated_module']['android-info.txt']
                self.assertEqual((info['bootloader'], info['baseband']), (bootloader, baseband))
                chain = [item['path'] for item in derived['config_chain']]
                self.assertEqual(chain[-3:], ['config/device/common/pixel.yml',
                                              'config/device/common/gen9pixel.yml',
                                              'config/device/caiman.yml'])
                self.assertEqual(len(chain), 18)
                rogers = derived['build_index']['caiman']['CP2A.260805.005.A1']
                self.assertEqual(rogers['desc'], 'Aug 2026, Rogers')

    def test_committed_records_agree_with_the_fixture_files(self):
        for tag, (build, set_by, bootloader, baseband) in EXPECTED.items():
            with self.subTest(tag=tag):
                full = stored(tag)
                derived = record.derive_content(self.tree(tag), tag)
                for key in ('stock_build', 'stock_build_set_by', 'release'):
                    self.assertEqual(derived[key], full[key])
                self.assertEqual(full['manifest_sha256'],
                                 record.base_record(tag)['manifest']['sha256'])
                ours = derived['generated_module']['android-info.txt']
                self.assertEqual(ours, full['generated_module']['android-info.txt'])
                for build_id, entry in derived['build_index']['caiman'].items():
                    self.assertEqual(entry, full['build_index']['caiman'][build_id])
                record.validate_record(full)

    def test_later_file_in_the_chain_wins(self):
        root = self.tree('2026100600')
        self.edit(root, 'config/device/caiman.yml', '  name: caiman\n',
                  '  name: caiman\n  build_id: CP3A.260905.009 # an override\n')
        config = record.device_config(root)
        self.assertEqual(config['build_id'], 'CP3A.260905.009')
        self.assertEqual(config['set_by'], 'config/device/caiman.yml:3')
        # the generated module still records CP3A.261005.005, so no record is written
        with self.assertRaisesRegex(Refusal, 'caiman.mk records stock build CP3A.261005.005'):
            record.derive_content(root, '2026100600')
        root = self.tree('2026081300')
        self.edit(root, 'config/device/common/gen9pixel.yml', '  platform: zumapro\n',
                  '  platform: zumapro\n  build_id: CP2A.260705.006\n')
        self.assertEqual(record.device_config(root)['build_id'], 'CP2A.260705.006')

    def test_refused_config_forms(self):
        gen9 = 'config/device/common/gen9pixel.yml'
        cases = [
            ('flow mapping', 'config/device/caiman.yml', 'device:\n  name: caiman\n',
             'device: { name: caiman }\nunused:\n  name: caiman\n'),
            ('quoted value', gen9, 'build_id: CP3A.261005.005', 'build_id: "CP3A.261005.005"'),
            ('anchor', gen9, 'build_id: CP3A.261005.005', 'build_id: &id CP3A.261005.005'),
            ('repeated device key', gen9, '  build_id: CP3A.261005.005\n',
             '  build_id: CP3A.261005.005\n  build_id: CP3A.260905.009\n'),
            ('repeated top level key', gen9, 'device:\n', 'device:\n  platform: x\ndevice:\n'),
            ('tab', gen9, '  build_id', '\tbuild_id'),
            ('multi line scalar', gen9, 'build_id: CP3A.261005.005\n',
             'build_id: CP3A\n    .261005.005\n'),
            ('document marker', gen9, 'includes:', '---\nincludes:'),
            ('unknown top level line', gen9, 'includes:', ']\nincludes:'),
            ('device list type', gen9, 'includes:', 'type: device-list\nincludes:'),
            ('escaping include', gen9, '  - pixel.yml', '  - pixel/../../../../caiman.yml'),
            ('include cycle', gen9, '  - pixel.yml', '  - pixel.yml\n  - gen9pixel.yml'),
            ('backport build', gen9, '  platform: zumapro\n',
             '  platform: zumapro\n  backport_build_id: CP3A.260905.009\n'),
            ('backport radio', gen9, '  platform: zumapro\n',
             '  platform: zumapro\n  backport_radio_firmware: true\n'),
            ('beta build', gen9, '  platform: zumapro\n', '  platform: zumapro\n  is_beta_build_id: true\n'),
            ('previous build', gen9, '  platform: zumapro\n',
             '  platform: zumapro\n  prev_build_id: CP3A.260905.009\n'),
            ('other device', 'config/device/caiman.yml', 'name: caiman', 'name: komodo'),
            ('no build id', gen9, '  build_id: CP3A.261005.005\n', ''),
            ('not a build id', gen9, 'build_id: CP3A.261005.005', 'build_id: latest'),
            ('empty build id', gen9, 'build_id: CP3A.261005.005', 'build_id:'),
            ('unknown stock build', gen9, 'CP3A.261005.005', 'CP3A.261005.099'),
        ]
        for name, relative, old, new in cases:
            with self.subTest(name):
                root = mini_tree('2026100600', Path(self.tmp.name) / name.replace(' ', '-'))
                self.edit(root, relative, old, new)
                with self.assertRaises(Refusal):
                    record.derive_content(root, '2026100600')

    def test_symbolic_link_in_the_chain_is_refused(self):
        root = self.tree('2026100600')
        common = root / 'config/device/common'
        (common / 'pixel.yml').rename(common / 'real-pixel.yml')
        (common / 'pixel.yml').symlink_to('real-pixel.yml')
        with self.assertRaises(Refusal):
            record.derive_content(root, '2026100600')

    def test_generated_module_must_agree(self):
        skel = 'vendor-skels/google_devices/caiman/'
        cases = [
            (skel + 'caiman.mk', 'CP3A.261005.005', 'CP3A.260905.009', 2),
            (skel + 'cmds-for-envsetup.sh', 'CP3A.261005.005', 'CP3A.260905.009', 1),
            (skel + 'caiman.mk', 'endif\n', 'endif\nifneq ($(BUILD_ID),CP3A.261005.005)\n  $(error '
             'BUILD_ID: expected CP3A.261005.005, got $(BUILD_ID))\nendif\n', 1),
            (skel + 'firmware/android-info.txt', '15819938', '15819938|15199480', 1),
        ]
        for index, (relative, old, new, count) in enumerate(cases):
            with self.subTest(relative=relative, index=index):
                root = mini_tree('2026100600', Path(self.tmp.name) / f'skel{index}')
                self.edit(root, relative, old, new, count)
                with self.assertRaises(Refusal):
                    record.derive_content(root, '2026100600')

    def test_tag_must_be_a_release(self):
        root = self.tree('2026100600')
        for tag in ('2026100601', '20261006', 'latest'):
            with self.subTest(tag=tag), self.assertRaises(Refusal):
                record.derive_content(root, tag)


class BuildIndexTests(unittest.TestCase):
    def setUp(self):
        self.text = (FIXTURES / 'adevtool/2026100600/config/build-index/'
                     'build-index-main.excerpt.yml').read_text()

    def test_real_excerpt(self):
        entries = record.parse_build_index(self.text)
        self.assertIn('vendor/google_devices', entries[('tegu', 'BD4A.240925.111')])
        self.assertEqual(set(entries[('bluejay', 'SD2A.220601.001.A1')]), {'line', 'vendor/google_devices'})
        builds = record.caiman_builds(entries)
        self.assertEqual(builds['CP3A.261005.005']['factory_sha256'],
                         '6c37847c9db3601e1228b48a08e7124af24f0fe936a36c2eada98c28abfe144c')
        self.assertEqual(builds['CP2A.260805.005.A1']['desc'], 'Aug 2026, Rogers')
        self.assertEqual(builds['CP2A.260705.006.A1']['desc'], 'Jul 2026, Rogers')
        self.assertNotIn('CD1A.261005.003', builds)

    def test_refused_index_forms(self):
        first = 'caiman CP3A.261005.005:\n'
        cases = {
            'repeated key': self.text + first + '  desc: Oct 2026\n',
            'unknown field': self.text.replace('  desc: Oct 2026\n', '  desc: Oct 2026\n  sha: 00\n', 1),
            'short digest': self.text.replace('6c37847c9db3601e', '6c37847c9db3601', 1),
            'renamed file': self.text.replace('factory-6c37847c.zip', 'factory-00000000.zip', 1),
            'blank line': self.text.replace(first, '\n' + first, 1),
            'comment line': self.text.replace(first, '# note\n' + first, 1),
            'field first': '  desc: Oct 2026\n' + self.text,
            'colon in desc': self.text.replace('desc: Oct 2026', 'desc: Oct: 2026', 1),
            'missing ota': re.sub(r'(caiman CP3A\.261005\.005:\n  desc: .*\n  factory: .*\n)  ota: .*\n',
                                  r'\1', self.text),
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(Refusal):
                record.parse_build_index(text)
        with self.assertRaises(Refusal):
            record.caiman_builds(record.parse_build_index(
                'caiman CP9A.261005.005:\n  vendor/google_devices: ' + '0' * 64 + ' x.tgz\n'))


class RecordValidationTests(unittest.TestCase):
    def test_refused_records(self):
        base = stored('2026100600')
        mutations = {
            'schema': lambda r: r.update(schema='other/1'),
            'device': lambda r: r.update(device='komodo'),
            'preview release': lambda r: r.update(release='2026100601'),
            'stock not listed': lambda r: r.update(stock_build='CP3A.261005.099'),
            'bad entry': lambda r: r['build_index']['caiman']['CP3A.261005.005'].update(factory_sha256='x'),
            'bad info': lambda r: r['generated_module']['android-info.txt'].update(baseband=None),
            'info alternatives': lambda r: r['generated_module']['android-info.txt'].update(
                bootloader='a|b'),
            'no adevtool commit': lambda r: r.pop('adevtool_revision'),
            'short adevtool commit': lambda r: r.update(adevtool_revision='17df3b79'),
            'other manifest': lambda r: r.update(manifest_sha256='0' * 64),
            'relabelled tag': lambda r: r.update(release='2026110500'),
            'tree at another commit': lambda r: r.update(tree_head='0' * 40),
        }
        for name, mutate in mutations.items():
            with self.subTest(name):
                value = json.loads(json.dumps(base))
                mutate(value)
                with self.assertRaises(Refusal):
                    record.validate_record(value)


GIT_ENV = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': '/nonexistent',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_AUTHOR_NAME': 'Record fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
           'GIT_COMMITTER_NAME': 'Record fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}


def git(path, *args):
    return subprocess.run(['git', '-C', str(path), *args], env=GIT_ENV, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


class BoundTreeCase(TreeCase):
    """A synthetic tree: vendor/adevtool as a Git repository, its manifest and a base record."""

    def bound_tree(self, tag='2026100600', name='bound'):
        tree = Path(self.tmp.name) / name
        adevtool = mini_tree(tag, tree / 'vendor/adevtool')
        git(adevtool, 'init', '-q')
        git(adevtool, 'add', '-A')
        git(adevtool, 'commit', '-q', '-m', 'fixture')
        head = git(adevtool, 'rev-parse', 'HEAD')
        manifest = tree / '.repo/manifests/default.xml'
        manifest.parent.mkdir(parents=True)
        manifest.write_text('<manifest><default revision="refs/tags/android-17.0.0_r1"/>'
                            f'<project path="vendor/adevtool" name="adevtool" revision="{head}"/>'
                            '<project path="script" name="script" revision="' + '1' * 40 + '"/></manifest>')
        bases = Path(self.tmp.name) / f'{name}-bases'
        bases.mkdir()
        (bases / f'{tag}.json').write_text(json.dumps({
            'schema': 'andrix.upstream.base/1', 'release': tag,
            'manifest': {'sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()},
            'security_patch_level': {'value': '2026-10-05'}}))
        return tree, head, bases


class BindingTests(BoundTreeCase):
    def test_record_is_bound_to_the_manifest_commit(self):
        tree, head, bases = self.bound_tree()
        derived = record.derive_record(tree, '2026100600', bases=bases)
        self.assertEqual((derived['adevtool_revision'], derived['tree_head']), (head, head))
        self.assertEqual(derived['stock_build'], 'CP3A.261005.005')
        record.validate_record(derived, bases=bases)

    def test_binding_controls(self):
        tree, head, bases = self.bound_tree(name='moved')
        (tree / 'vendor/adevtool/extra').write_text('x')
        git(tree / 'vendor/adevtool', 'add', 'extra')
        git(tree / 'vendor/adevtool', 'commit', '-q', '-m', 'later')
        with self.assertRaisesRegex(Refusal, 'is not the clean commit'):
            record.derive_record(tree, '2026100600', bases=bases)
        tree, head, bases = self.bound_tree(name='dirty')
        with open(tree / 'vendor/adevtool/config/device/caiman.yml', 'a') as handle:
            handle.write('# edited\n')
        with self.assertRaisesRegex(Refusal, 'is not the clean commit'):
            record.derive_record(tree, '2026100600', bases=bases)
        tree, head, bases = self.bound_tree(name='manifest')
        with open(tree / '.repo/manifests/default.xml', 'a') as handle:
            handle.write('\n')
        with self.assertRaisesRegex(Refusal, 'is not the manifest that'):
            record.derive_record(tree, '2026100600', bases=bases)
        tree, head, bases = self.bound_tree(name='relabel')
        with self.assertRaisesRegex(Refusal, 'no signed base record'):
            record.derive_record(tree, '2026110500', bases=bases)
        tree, head, bases = self.bound_tree(name='unpinned')
        manifest = tree / '.repo/manifests/default.xml'
        manifest.write_text(manifest.read_text().replace('path="vendor/adevtool"', 'path="vendor/other"'))
        (bases / '2026100600.json').write_text(json.dumps({
            'schema': 'andrix.upstream.base/1', 'release': '2026100600',
            'manifest': {'sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}}))
        with self.assertRaisesRegex(Refusal, 'does not pin exactly one vendor/adevtool commit'):
            record.derive_record(tree, '2026100600', bases=bases)

    def test_committed_revisions_are_the_sealed_report_rows(self):
        sys.path.insert(0, str(ROOT / 'scripts/proof'))
        import grapheneos_carry
        report = json.loads((ROOT / 'upstream/reports/2026081300-2026100600.json').read_text())
        self.assertEqual(grapheneos_carry.seal(report), report['seal'])
        row = [item for item in report['manifest']['changed'] if item['path'] == 'vendor/adevtool'] \
            if isinstance(report.get('manifest'), dict) and 'changed' in report['manifest'] else None
        text = json.dumps(report)
        match = re.search(r'\{"path": "vendor/adevtool", "base": "([0-9a-f]{40})", "target": '
                          r'"([0-9a-f]{40})"\}', text)
        self.assertIsNotNone(match, row)
        self.assertEqual(stored('2026081300')['adevtool_revision'], match.group(1))
        self.assertEqual(stored('2026100600')['adevtool_revision'], match.group(2))


class CommandLineTests(BoundTreeCase):
    def run_main(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = record.main(list(argv))
        return status, output.getvalue()

    def test_record_and_verify(self):
        tree, head, bases = self.bound_tree()
        out = Path(self.tmp.name) / 'record.json'
        with mock.patch.object(record, 'BASES', bases):
            status, text = self.run_main('record', '--tree', str(tree), '--release', '2026100600',
                                         '--out', str(out))
            self.assertEqual(status, 0, text)
            self.assertEqual(json.loads(out.read_text())['adevtool_revision'], head)
            status, text = self.run_main('record', '--tree', str(tree), '--release', '2026100600',
                                         '--out', str(out))
            self.assertEqual((status, text.startswith('REFUSE')), (1, True))
            self.assertEqual(self.run_main('verify', '--tree', str(tree), str(out))[0], 0)
            self.edit(tree / 'vendor/adevtool', 'config/device/common/gen9pixel.yml',
                      'CP3A.261005.005', 'CP3A.260905.009')
            status, text = self.run_main('verify', '--tree', str(tree), str(out))
            self.assertEqual((status, text.startswith('REFUSE')), (1, True))


@unittest.skipUnless(TREES, 'set ANDRIX_PIXEL_TREES to TAG=TREE pairs of local GrapheneOS trees')
class RealTreeTests(unittest.TestCase):
    def test_records_derive_from_the_real_trees(self):
        for tag, tree in TREES.items():
            with self.subTest(tag=tag):
                content = record.derive_content(Path(tree) / 'vendor/adevtool', tag)
                full = {key: value for key, value in stored(tag).items()
                        if key not in ('adevtool_revision', 'manifest_sha256', 'revision_source')}
                self.assertEqual(content, full)

    def test_fixture_copies_are_verbatim(self):
        for tag, tree in TREES.items():
            for name in ('generate-factory-images-common.sh', 'clear-factory-images-variables.sh'):
                with self.subTest(tag=tag, name=name):
                    self.assertEqual((Path(tree) / 'device/common' / name).read_bytes(),
                                     (FIXTURES / 'device-common' / name).read_bytes())
            adevtool = Path(tree) / 'vendor/adevtool'
            for relative in ('config/device/caiman.yml', 'config/device/common/gen9pixel.yml',
                             'config/device/common/pixel.yml',
                             'vendor-skels/google_devices/caiman/cmds-for-envsetup.sh',
                             'vendor-skels/google_devices/caiman/firmware/android-info.txt'):
                with self.subTest(tag=tag, relative=relative):
                    self.assertEqual((adevtool / relative).read_bytes(),
                                     (FIXTURES / 'adevtool' / tag / relative).read_bytes())
            index = (adevtool / record.INDEX).read_text().split('\n')
            excerpt = (FIXTURES / 'adevtool' / tag / 'config/build-index/'
                       'build-index-main.excerpt.yml').read_text().split('\n')[:-1]
            self.assertTrue(all(line in index for line in excerpt))
            head = (adevtool / 'vendor-skels/google_devices/caiman/caiman.mk').read_bytes()
            self.assertTrue(head.startswith((FIXTURES / 'adevtool' / tag /
                                             'vendor-skels/google_devices/caiman/caiman.mk.head').read_bytes()))


if __name__ == '__main__':
    unittest.main()
