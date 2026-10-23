# SPDX-License-Identifier: Apache-2.0
"""Source license consistency, not a binary distribution or legal clearance test."""
from pathlib import Path
import hashlib
import json
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import source_licensing  # noqa: E402


def listed(name):
    return [line for line in (ROOT / 'LICENSES' / name).read_text().splitlines()
            if line and not line.startswith('#')]


class SourceLicensingTests(unittest.TestCase):
    def test_full_license_texts_are_retained_verbatim(self):
        apache = (ROOT / 'LICENSES/Apache-2.0.txt').read_bytes()
        self.assertEqual(hashlib.sha256(apache).hexdigest(),
                         'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30')
        self.assertEqual((ROOT / 'LICENSES/GPL-3.0-or-later.txt').read_bytes(),
                         (ROOT / 'toolchain/licenses/make-COPYING').read_bytes())

    def test_explicit_core_file_scope_and_headers(self):
        files = listed('andrix-core-files.txt')
        self.assertTrue(files)
        self.assertEqual(len(files), len(set(files)))
        for name in files:
            with self.subTest(path=name):
                path = Path(name)
                self.assertFalse(path.is_absolute())
                self.assertNotIn('..', path.parts)
                self.assertTrue(name.startswith(('owner/', 'supervision/')))
                self.assertNotIn('/tests/', name)
                self.assertTrue((ROOT / name).is_file())
                if path.suffix in ('.java', '.c', '.cpp', '.h', '.hpp'):
                    self.assertIn('SPDX-License-Identifier: GPL-3.0-or-later',
                                  '\n'.join((ROOT / name).read_text().splitlines()[:2]))

    def test_core_implementation_has_no_unmapped_gpl_header(self):
        files = set(listed('andrix-core-files.txt'))
        for base in ('owner/native', 'owner/terminal', 'owner/platform',
                     'owner/deployment', 'supervision/native', 'supervision/init'):
            for path in (ROOT / base).rglob('*'):
                if path.suffix not in ('.java', '.c', '.cpp', '.h', '.hpp'):
                    continue
                if 'SPDX-License-Identifier: GPL-3.0-or-later' in path.read_text().splitlines()[0]:
                    self.assertIn(path.relative_to(ROOT).as_posix(), files)

    def test_public_aidl_interfaces_remain_apache(self):
        for base in ('owner/aidl', 'owner/platform/aidl'):
            for path in (ROOT / base).rglob('*.aidl'):
                with self.subTest(path=path):
                    self.assertIn('SPDX-License-Identifier: Apache-2.0',
                                  '\n'.join(path.read_text().splitlines()[:3]))

    def test_patch_scope_is_implementation_only_not_external_relicensing(self):
        files = listed('andrix-core-patches.txt')
        self.assertEqual(len(files), len(set(files)))
        for name in files:
            self.assertTrue(name.endswith('.patch'))
            self.assertTrue((ROOT / name).is_file())
            self.assertTrue(name.startswith(('patches/grapheneos-', 'supervision/')))
        policy = (ROOT / 'LICENSING.md').read_text()
        self.assertIn('Copied upstream context', policy)
        self.assertIn('Earlier valid Apache grants', policy)

    def test_named_soong_license_records_and_interfaces(self):
        root = (ROOT / 'Android.bp').read_text()
        self.assertIn('name: "andrix_core_license"', root)
        self.assertIn('SPDX-license-identifier-GPL-3.0-or-later', root)
        self.assertIn('license_text: ["LICENSES/Apache-2.0.txt"]', root)
        self.assertIn('license_text: ["LICENSES/GPL-3.0-or-later.txt"]', root)
        for name in ('owner/Android.bp', 'owner/platform/Android.bp', 'supervision/Android.bp'):
            self.assertIn('default_applicable_licenses: ["andrix_core_license", "vendor_andrix_license"]',
                          (ROOT / name).read_text())
        for name, module in (('owner/Android.bp', 'andrix_session'),
                             ('owner/platform/Android.bp', 'andrix_platform_lifecycle')):
            text = (ROOT / name).read_text()
            body = text.split('name: "' + module + '",', 1)[1].split('}', 1)[0]
            self.assertIn('licenses: ["vendor_andrix_license"]', body)
        self.assertIn('licenses: ["vendor_andrix_license"]',
                      (ROOT / 'owner/platform/overlay/Android.bp').read_text())

    def test_mixed_terminal_library_and_upstream_notices(self):
        text = (ROOT / 'third_party/termux-terminal/Android.bp').read_text()
        self.assertIn('licenses: ["andrix_core_license", "andrix_termux_terminal_license"]', text)
        self.assertIn('SPDX-license-identifier-MIT', text)
        notice = (ROOT / 'third_party/termux-terminal/NOTICE').read_text()
        self.assertIn('Copyright (c) 2014 Jeff Quast', notice)
        self.assertIn('Markus Kuhn -- 2007-05-26', notice)
        self.assertIn('Apache License',
                      (ROOT / 'third_party/termux-terminal/LICENSE').read_text())

    def test_current_helper_recipe_pins_match_relicensed_source(self):
        for release in ('grapheneos-2026081300', 'grapheneos-2026100600'):
            for name in ('native-principal-pins.json', 'owner-lifecycle.json'):
                value = json.loads((ROOT / 'patches' / release / name).read_text())
                rows = value['added'] if isinstance(value['added'], list) else [value['added']]
                for row in rows:
                    with self.subTest(release=release, path=row['source']):
                        self.assertEqual(hashlib.sha256((ROOT / row['source']).read_bytes()).hexdigest(),
                                         row['sha256'])

    def test_exact_licensing_predecessors_preserve_historical_source_ids(self):
        for name, (before, after) in source_licensing.SOURCE_PAIRS.items():
            with self.subTest(path=name):
                data = (ROOT / name).read_bytes()
                self.assertEqual(source_licensing.sha(data), after)
                historical = source_licensing.predecessor_bytes(name, data)
                self.assertEqual(source_licensing.sha(historical), before)
                self.assertEqual(source_licensing.predecessor_bytes(name, historical), historical)
                self.assertEqual(data, source_licensing.AFTER_HEADER
                                 + historical[len(source_licensing.BEFORE_HEADER):])

    def test_licensing_predecessor_does_not_ignore_unknown_comments_or_code(self):
        name = 'owner/platform/framework/NativeIdentityRecords.java'
        data = (ROOT / name).read_bytes()
        for changed in (data + b'\n', data.replace(b'GPL-3.0-or-later', b'GPL-3.0-only', 1),
                        data.replace(b'package ', b'package  ', 1), b'/* extra */\n' + data):
            with self.subTest(digest=source_licensing.sha(changed)):
                with self.assertRaisesRegex(ValueError, 'licensing source drift'):
                    source_licensing.predecessor_bytes(name, changed)
        with self.assertRaisesRegex(ValueError, 'unmapped licensing source'):
            source_licensing.predecessor_bytes('../unknown.java', data)

    def test_historical_profile_views_validate_current_metadata_and_helpers(self):
        for name, (before, after) in source_licensing.PROFILE_PAIRS.items():
            data = (ROOT / name).read_bytes()
            with self.subTest(path=name):
                self.assertEqual(source_licensing.sha(data), after)
                historical = source_licensing.predecessor_profile(name, data)
                encoded = (json.dumps(historical, indent=2) + '\n').encode()
                self.assertEqual(source_licensing.sha(encoded), before)
                with self.assertRaisesRegex(ValueError, 'licensing profile drift'):
                    source_licensing.predecessor_profile(name, data + b'\n')
                with mock.patch.object(Path, 'read_bytes', return_value=b'unknown helper'):
                    with self.assertRaisesRegex(ValueError, 'licensing helper drift'):
                        source_licensing.predecessor_profile(name, data)
        with self.assertRaisesRegex(ValueError, 'unmapped licensing profile'):
            source_licensing.predecessor_profile('../unknown.json', b'{}')

    def test_public_docs_describe_applied_source_terms(self):
        readme = (ROOT / 'README.md').read_text()
        policy = (ROOT / 'docs/licensing.md').read_text()
        self.assertIn('core is licensed under **GPL-3.0-or-later**', readme)
        self.assertNotIn('transition has not yet been applied', readme)
        self.assertNotIn('not\nyet been applied', policy)
        self.assertTrue((ROOT / 'LICENSING.md').is_file())
        self.assertIn('Earlier valid Apache grants', (ROOT / 'LICENSE').read_text())


if __name__ == '__main__':
    unittest.main()
