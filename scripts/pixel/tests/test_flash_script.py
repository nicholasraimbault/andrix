# SPDX-License-Identifier: Apache-2.0
"""The flash script reader against GrapheneOS's own generators. Offline, no phone.

The legacy scripts come from running the verbatim generator fixture with bash. The
optimized scripts are FlashCapturer's conversion of those, transcribed in official.py.
Every forbidden command, every deletion and every reordering must be refused.
"""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from caiman import Refusal  # noqa: E402
import flash_script as fs  # noqa: E402
import official  # noqa: E402

BUILD = '2026100600'
BL, BB = 'ripcurrentpro-17.0-15819938', 'g5400c-260604-260807-B-16035863'
OLD_BL, OLD_BB = 'ripcurrentpro-17.0-15199480', 'g5400c-260317-260429-B-15308590'
EXPECT = fs.Expectation(BL, BB, BUILD)
LEGACY = official.render_legacy(BUILD, BL, BB)
OPTIMIZED = official.capture(LEGACY, splits=4)
SCRIPTS = {'legacy': LEGACY, 'optimized': OPTIMIZED}
TREES = dict(item.split('=', 1) for item in os.environ.get('ANDRIX_PIXEL_TREES', '').split(':')
             if '=' in item)
RADIO = f'radio-caiman-{BB.lower()}.img'
BOOTLOADER = f'bootloader-caiman-{BL}.img'

# Each forbidden command, with the reason the reader must give.
FORBIDDEN = [
    ('fastboot flashing lock', 'locks the bootloader'),
    ('fastboot flashing lock_critical', 'locks the bootloader'),
    ('fastboot oem lock', 'locks the bootloader'),
    ('fastboot flashing unlock', 'unlocks'),
    ('fastboot flashing unlock_critical', 'unlocks'),
    ('fastboot set_active a', 'set_active (rule 4)'),
    ('fastboot set_active b', 'set_active (rule 4)'),
    ('fastboot --set-active=b', '--set-active=b outside'),
    ('fastboot --set-active', '--set-active outside'),
    ('fastboot -a b', '--set-active outside'),
    ('fastboot -ab', '--set-active=b outside'),
    ('fastboot --set-act=other', '--set-active=other outside'),
    ('fastboot --set-active=other', None),
    ('fastboot --slot=all flash boot boot.img', '--slot=all outside'),
    ('fastboot flash --slot=b boot boot.img', '--slot=b outside'),
    ('fastboot --slot other flash radio ' + RADIO, '--slot=other outside'),
    ('fastboot flash --slot=other bootloader ' + BOOTLOADER, None),
    ('fastboot --force flash boot boot.img', '--force (rule 4)'),
    ('fastboot --forc flash boot boot.img', '--force (rule 4)'),
    ('fastboot flash persist persist.img', 'writes a partition'),
    ('fastboot flash modem modem.img', 'writes a partition'),
    ('fastboot flash abl abl.img', 'writes a partition'),
    ('fastboot flash bootloader ' + BOOTLOADER, 'writes a partition'),
    ('fastboot flash radio radio-caiman-g5400c-260317-260429-b-15308590.img', 'writes a partition'),
    ('fastboot flash:raw boot kernel', 'writes a partition'),
    ('fastboot erase persist', 'erases persist'),
    ('fastboot erase modemst1', 'erases modemst1'),
    ('fastboot erase frp', 'erases frp'),
    ('fastboot erase super', 'erases super'),
    ('fastboot format userdata', 'formats a partition'),
    ('fastboot format:ext4 metadata', 'formats a partition'),
    ('fastboot flashall', 'not in the official script'),
    ('fastboot boot boot.img', 'not in the official script'),
    ('fastboot wipe-super super_empty.img', 'not in the official script'),
    ('fastboot delete-logical-partition system_a', 'not in the official script'),
    ('fastboot create-logical-partition scratch 1', 'not in the official script'),
    ('fastboot resize-logical-partition system_a 0', 'not in the official script'),
    ('fastboot snapshot-update merge', 'not in the official script'),
    ('fastboot gsi wipe', 'not in the official script'),
    ('fastboot oem uart enable', 'oem uart enable is not in the official script'),
    ('fastboot reboot recovery', 'not in the official script'),
    ('fastboot reboot', 'not in the official script'),
    ('fastboot --disable-verity flash vbmeta vbmeta.img', 'switches verified boot checks off'),
    ('fastboot --disable-verification update image-caiman-2026100600.zip',
     'switches verified boot checks off'),
    ('fastboot --skip-secondary -w --skip-reboot update image-caiman-2026100600.zip',
     'option skip-secondary'),
    ('fastboot -w update other.zip', 'is not the official update'),
    ('fastboot -wa update image-caiman-2026100600.zip', '--set-active outside'),
    ('fastboot flashing lock || true', 'locks the bootloader'),
    ('fastboot "flashing" lock', 'locks the bootloader'),
    ('/usr/bin/fastboot flashing lock', 'locks the bootloader'),
    ('x=$(fastboot flashing lock)', 'locks the bootloader'),
    ('if fastboot flashing lock; then :; fi', 'locks the bootloader'),
    ('eval "fastboot flashing lock"', 'can run commands indirectly'),
    ('sh -c "fastboot flashing lock"', 'can run commands indirectly'),
    ('`fastboot flashing lock`', 'backquote'),
    ('FB=fastboot; $FB flashing lock', 'runs a command through a variable'),
    ('alias x="fastboot flashing lock"', 'fastboot used in a way'),
    ('fastboot flashing \\', 'unparsable shell line'),
]


def verdict(data, expect=EXPECT, form=None):
    """REFUSE when the reader refuses by report or by raising, as callers must treat both."""
    try:
        return fs.read(data, expect, form)['verdict']
    except Refusal:
        return 'REFUSE'


def lines_of(data):
    return data.decode().split('\n')[:-1]


def join(lines):
    return ('\n'.join(lines) + '\n').encode()


class OfficialScriptTests(unittest.TestCase):
    def test_generator_output_passes(self):
        for form, data in SCRIPTS.items():
            with self.subTest(form=form):
                report = fs.read(data, EXPECT)
                self.assertEqual((report['form'], report['verdict'], report['reasons']), (form, 'PASS', []))
        self.assertEqual(fs.read(OPTIMIZED, EXPECT)['super_splits'], 4)

    def test_template_equals_the_sources(self):
        for build, bootloader, baseband in ((BUILD, BL, BB), ('2026081300', OLD_BL, OLD_BB),
                                            ('2026100601', BL, BB)):
            with self.subTest(build=build):
                expect = fs.Expectation(bootloader, baseband, build)
                legacy = official.render_legacy(build, bootloader, baseband)
                self.assertEqual(join(fs.legacy_lines(expect)), legacy)
                for splits in (1, 2, 7):
                    self.assertEqual(join(fs.optimized_head(expect) + fs.optimized_os_lines(expect, splits)),
                                     official.capture(legacy, splits=splits))
                    self.assertEqual(fs.read(official.capture(legacy, splits=splits), expect)['verdict'], 'PASS')

    def test_the_script_names_its_files(self):
        report = fs.read(OPTIMIZED, EXPECT)
        self.assertEqual(report['files'][:4], [BOOTLOADER, RADIO, 'avb_pkmd.bin', 'android-info.zip'])
        self.assertIn('super_4.img', report['files'])
        self.assertIn('vbmeta.img', report['files'])
        self.assertIn('image-caiman-2026100600.zip', fs.read(LEGACY, EXPECT)['files'])

    def test_older_firmware_names_are_refused(self):
        for form, data in SCRIPTS.items():
            with self.subTest(form=form):
                report = fs.read(data, fs.Expectation(OLD_BL, OLD_BB, BUILD))
                self.assertEqual(report['verdict'], 'REFUSE')

    def test_form_must_match(self):
        self.assertEqual(fs.read(LEGACY, EXPECT, 'optimized')['verdict'], 'REFUSE')
        self.assertEqual(fs.read(OPTIMIZED, EXPECT, 'legacy')['verdict'], 'REFUSE')
        with self.assertRaises(Refusal):
            fs.read(b'#!/bin/sh\nfastboot flashing lock\n', EXPECT)
        with self.assertRaises(Refusal):
            fs.read(LEGACY, fs.Expectation(BL, BB))


class ForbiddenCommandTests(unittest.TestCase):
    def positions(self, lines):
        return [lines.index('sleep 5') + 1, lines.index('fastboot erase dpm_b') + 1, len(lines)]

    def test_every_forbidden_command_is_refused(self):
        for form, data in SCRIPTS.items():
            lines = lines_of(data)
            for line, reason in FORBIDDEN:
                for position in self.positions(lines):
                    with self.subTest(form=form, line=line, position=position):
                        report = fs.read(join(lines[:position] + [line] + lines[position:]), EXPECT)
                        self.assertEqual(report['verdict'], 'REFUSE')
                        if reason:
                            self.assertTrue(any(reason in item for item in report['reasons']),
                                            report['reasons'])

    def test_official_lines_changed_to_forbidden_forms(self):
        flash = f'fastboot flash --slot=other bootloader {BOOTLOADER}'
        replacements = [
            (flash, f'fastboot flash --slot=b bootloader {BOOTLOADER}'),
            (flash, f'fastboot flash --slot=all bootloader {BOOTLOADER}'),
            (flash, f'fastboot flash bootloader {BOOTLOADER}'),
            ('fastboot --set-active=other', 'fastboot --set-active=b'),
            ('fastboot --set-active=other', 'fastboot set_active other'),
            ('fastboot --set-active=other', 'fastboot -a other'),
            ('fastboot erase avb_custom_key', 'fastboot format avb_custom_key'),
            ('fastboot oem uart disable', 'fastboot oem uart enable'),
            ('fastboot erase fips', 'fastboot erase fips_b'),
            ('if ! [ $FASTBOOT_VERSION_NUM -ge 3501 ]; then', 'if ! [ $FASTBOOT_VERSION_NUM -ge 3401 ]; then'),
            ('set -e', 'set +e'),
            ('fastboot reboot-bootloader', 'fastboot reboot'),
        ]
        legacy_only = [
            ('if ! [ $product = caiman ]; then', 'if ! [ $product = komodo ]; then'),
            ('fastboot -w --skip-reboot update image-caiman-2026100600.zip',
             'fastboot --force -w --skip-reboot update image-caiman-2026100600.zip'),
            ('fastboot -w --skip-reboot update image-caiman-2026100600.zip',
             'fastboot -w --skip-reboot --slot=all update image-caiman-2026100600.zip'),
            ('fastboot -w --skip-reboot update image-caiman-2026100600.zip',
             'fastboot -w --skip-reboot update image-caiman-2026081300.zip'),
        ]
        optimized_only = [
            ('if ! [ $product = "caiman" ]; then', 'if ! [ $product = "komodo" ]; then'),
            ('fastboot --set-active=a', 'fastboot --set-active=b'),
            ('if ! [ $currentslot = "a" ]; then', 'if ! [ $currentslot = "b" ]; then'),
            ('fastboot snapshot-update cancel', 'fastboot snapshot-update merge'),
            ('fastboot erase userdata', 'fastboot format userdata'),
            ('fastboot flash boot boot.img', 'fastboot flash --slot=b boot boot.img'),
            ('fastboot flash boot boot.img', 'fastboot flash boot_b boot.img'),
            ('fastboot flash vbmeta vbmeta.img', 'fastboot --disable-verity flash vbmeta vbmeta.img'),
            ('fastboot flash super super_2.img', 'fastboot flash system super_2.img'),
            ('fastboot --disable-super-optimization --skip-reboot update android-info.zip',
             'fastboot --force --disable-super-optimization --skip-reboot update android-info.zip'),
        ]
        for form, extra in (('legacy', legacy_only), ('optimized', optimized_only)):
            for old, new in replacements + extra:
                with self.subTest(form=form, old=old, new=new):
                    data = SCRIPTS[form].decode()
                    self.assertIn(old + '\n', data)
                    self.assertEqual(fs.read(data.replace(old + '\n', new + '\n', 1).encode(), EXPECT)['verdict'],
                                     'REFUSE')


class StructureTests(unittest.TestCase):
    def test_every_deleted_line_is_refused(self):
        for form, data in SCRIPTS.items():
            lines = lines_of(data)
            for index in range(len(lines)):
                with self.subTest(form=form, line=index + 1):
                    self.assertEqual(verdict(join(lines[:index] + lines[index + 1:])), 'REFUSE')

    def test_every_reordering_is_refused(self):
        for form, data in SCRIPTS.items():
            lines = lines_of(data)
            steps = [index for index, line in enumerate(lines) if line.startswith(('fastboot ', 'sleep ', 'echo Flashing'))]
            for a in steps:
                for b in steps:
                    if a >= b or lines[a] == lines[b]:
                        continue
                    swapped = list(lines)
                    swapped[a], swapped[b] = swapped[b], swapped[a]
                    with self.subTest(form=form, swap=(a + 1, b + 1)):
                        self.assertEqual(verdict(join(swapped)), 'REFUSE')
            for a in steps:
                for target in range(len(lines)):
                    moved = list(lines)
                    line = moved.pop(a)
                    moved.insert(target, line)
                    if moved == lines:
                        continue
                    with self.subTest(form=form, move=(a + 1, target + 1)):
                        self.assertEqual(verdict(join(moved)), 'REFUSE')

    def test_reordering_is_named(self):
        lines = lines_of(LEGACY)
        radio = lines.index(f'fastboot flash radio {RADIO}')
        first = lines.index(f'fastboot flash --slot=other bootloader {BOOTLOADER}')
        lines.insert(first, lines.pop(radio))
        report = fs.read(join(lines), EXPECT)
        self.assertTrue(any('order differs' in reason for reason in report['reasons']), report['reasons'])

    def test_a_script_without_the_wipe_is_refused(self):
        legacy = LEGACY.replace(b'fastboot -w --skip-reboot update', b'fastboot --skip-reboot update')
        optimized = OPTIMIZED.replace(b'fastboot erase userdata\nfastboot erase metadata\n', b'')
        for data in (legacy, optimized):
            self.assertEqual(verdict(data), 'REFUSE')
        with self.assertRaises(TypeError):
            fs.Expectation(BL, BB, BUILD, wipe=False)

    def test_super_splits_must_be_one_numbered_run(self):
        text = OPTIMIZED.decode()
        cases = {
            'repeated number': text.replace('echo Flashing super, 2/4\nfastboot flash super super_2.img',
                                            'echo Flashing super, 1/4\nfastboot flash super super_1.img'),
            'wrong total': text.replace('echo Flashing super, 2/4', 'echo Flashing super, 2/3'),
            'gap': text.replace('echo Flashing super, 4/4\nfastboot flash super super_4.img\n', ''),
            'file mismatch': text.replace('super super_3.img', 'super super_2.img'),
            'extra line': text + 'fastboot reboot-bootloader\n',
            'no splits': text[:text.index('echo Flashing super, 1/4')],
            'zero split': text.replace('super, 1/4\nfastboot flash super super_1.img', 'super, 0/4\nfastboot flash super super_0.img'),
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertEqual(verdict(data.encode()), 'REFUSE')

    def test_os_image_list_is_fixed_in_code(self):
        reordered = official.FASTBOOT_INFO.replace('flash boot\n', '').replace(
            'flash --apply-vbmeta vbmeta\n', 'flash --apply-vbmeta vbmeta\nflash boot\n')
        self.assertEqual(verdict(official.capture(LEGACY, reordered, splits=2)), 'REFUSE')
        missing = official.capture(LEGACY, official.FASTBOOT_INFO.replace('flash pvmfw\n', ''), splits=2)
        self.assertEqual(verdict(missing), 'REFUSE')
        with self.assertRaises(TypeError):
            fs.Expectation(BL, BB, BUILD, os_images=('boot',))
        self.assertEqual(fs.Expectation(BL, BB).os_images, fs.DEFAULT_OS_IMAGES)

    def test_unreadable_scripts_are_refused(self):
        for data in (LEGACY.replace(b'\n', b'\r\n'), LEGACY.replace(b'  exit 1', b'\texit 1'),
                     LEGACY.replace(b'caiman', b'ca\xc3\xafman'), LEGACY[:-1], LEGACY + b'\0\n', b'',
                     'not bytes'):
            with self.subTest(data=data[:20]), self.assertRaises(Refusal):
                fs.read(data, EXPECT)


class CommandLineTests(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            (work / 'android-info.txt').write_text(official.android_info(BL, BB))
            (work / 'good.sh').write_bytes(OPTIMIZED)
            (work / 'bad.sh').write_bytes(OPTIMIZED + b'fastboot flashing lock\n')
            (work / 'legacy.sh').write_bytes(LEGACY)
            for name, argv, status in (('good', [], 0), ('bad', [], 1), ('legacy', ['--build', BUILD], 0),
                                       ('legacy', [], 1)):
                with self.subTest(name=name, argv=argv), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(fs.main([str(work / f'{name}.sh'), '--android-info',
                                              str(work / 'android-info.txt'), *argv]), status)
            for argv in (['--os-images', 'boot'], ['--wipe-partitions', 'userdata'], ['--no-wipe']):
                with self.subTest(argv=argv), self.assertRaises(SystemExit), \
                        contextlib.redirect_stderr(io.StringIO()):
                    fs.main([str(work / 'good.sh'), '--android-info', str(work / 'android-info.txt'), *argv])


@unittest.skipUnless(TREES, 'set ANDRIX_PIXEL_TREES to TAG=TREE pairs of local GrapheneOS trees')
class RealTreeTests(unittest.TestCase):
    def test_the_trees_generate_the_same_script(self):
        for tag, tree in TREES.items():
            with self.subTest(tag=tag):
                self.assertEqual(official.render_legacy(BUILD, BL, BB, Path(tree) / 'device/common'), LEGACY)


if __name__ == '__main__':
    unittest.main()
