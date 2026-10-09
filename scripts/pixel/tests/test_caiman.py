# SPDX-License-Identifier: Apache-2.0
"""Release numbers, build IDs, android-info.txt and caiman-stable. Offline, no phone."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import caiman  # noqa: E402
from caiman import Refusal  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
INFO_2026100600 = (FIXTURES / 'adevtool/2026100600/vendor-skels/google_devices/caiman/firmware/'
                   'android-info.txt').read_bytes()


class ReleaseTests(unittest.TestCase):
    def test_release_and_preview(self):
        release = caiman.parse_release('2026100600')
        preview = caiman.parse_release('2026100601')
        self.assertEqual((release.base, release.preview), ('2026100600', False))
        self.assertEqual((preview.base, preview.preview), ('2026100600', True))
        self.assertTrue(caiman.same_release(release, preview))
        self.assertFalse(caiman.newer(preview, release))
        self.assertFalse(caiman.newer(release, preview))

    def test_newer_by_release_number(self):
        old, new = caiman.parse_release('2026081300'), caiman.parse_release('2026100600')
        self.assertTrue(caiman.newer(new, old))
        self.assertFalse(caiman.newer(old, new))
        self.assertEqual(caiman.newest([old, new]).number, '2026100600')
        self.assertEqual(caiman.newest([caiman.parse_release('2026100601'), new]).number,
                         '2026100601')

    def test_refused_release_numbers(self):
        for text in ('202610060', '20261006000', '2026100602', '2026100699', '2026133100',
                     '2026023000', ' 2026100600', '2026100600\n', 'abcdefghij', '', None, 2026100600):
            with self.subTest(text=text), self.assertRaises(Refusal):
                caiman.parse_release(text)

    def test_preview_refused_where_no_source_exists(self):
        with self.assertRaisesRegex(Refusal, 'security preview'):
            caiman.parse_release('2026100601', allow_preview=False)

    def test_build_ids(self):
        for text in ('CP3A.261005.005', 'CP2A.260805.005.A1', 'AD1A.240530.030.A2', 'CP41.260831.007'):
            self.assertEqual(caiman.parse_build_id(text), text)
        for text in ('cp3a.261005.005', 'CP3A.261005.5', 'CP3A.261005.005.A', 'CP3A.261005.005.A10',
                     'CP3A.261005.005 ', 'CP3A-261005-005', ''):
            with self.subTest(text=text), self.assertRaises(Refusal):
                caiman.parse_build_id(text)


class AndroidInfoTests(unittest.TestCase):
    def test_real_generated_file(self):
        info = caiman.parse_android_info(INFO_2026100600)
        self.assertEqual(info.bootloader, 'ripcurrentpro-17.0-15819938')
        self.assertEqual(info.baseband, 'g5400c-260604-260807-B-16035863')
        self.assertEqual(info.partitions, ('vendor_kernel_boot',))

    def test_refused_forms(self):
        base = INFO_2026100600.decode()
        cases = {
            'reject line': base + 'reject version-bootloader=x\n',
            'product scoped': base + 'require-for-product:caiman version-baseband=x\n',
            'alternatives': base.replace('15819938', '15819938|other'),
            'wildcard': base.replace('15819938', '1581993*'),
            'repeated key': base + 'require version-baseband=other\n',
            'missing baseband': base.replace('require version-baseband=g5400c-260604-260807-B-16035863\n', ''),
            'other board': base.replace('board=caiman', 'board=komodo'),
            'spaces': base.replace('require board=caiman', 'require board = caiman'),
            'unknown key': base + 'require version-cdma=1\n',
            'carriage return': base.replace('\n', '\r\n'),
            'repeated partition': base + 'require partition-exists=vendor_kernel_boot\n',
            'free text': base + 'hello\n',
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(Refusal):
                caiman.parse_android_info(text.encode())
        with self.assertRaises(Refusal):
            caiman.parse_android_info(b'require board=caiman\n\xff\n')


class StableChannelTests(unittest.TestCase):
    def test_generate_metadata_form(self):
        # script/generate-metadata prints incremental, post-timestamp, pre-device, channel
        self.assertEqual(caiman.parse_stable_channel(b'2026100600 1791230000 caiman stable\n').number,
                         '2026100600')
        self.assertEqual(caiman.parse_stable_channel(b'2026100600 1791230000 caiman stable').number,
                         '2026100600')

    def test_refused(self):
        for data in (b'2026100600 1791230000 komodo stable\n', b'2026100600 1791230000 caiman beta\n',
                     b'2026100600 caiman stable\n', b'2026100600  1791230000 caiman stable\n',
                     b'2026100600 1791230000 caiman stable\nextra\n', b'', b'2026100602 1 caiman stable\n'):
            with self.subTest(data=data), self.assertRaises(Refusal):
                caiman.parse_stable_channel(data)


if __name__ == '__main__':
    unittest.main()
