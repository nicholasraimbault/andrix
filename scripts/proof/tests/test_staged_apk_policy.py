# SPDX-License-Identifier: Apache-2.0
"""Source integration contracts. Compiled policy and Android execution are separate."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


class StagedApkPolicyTests(unittest.TestCase):
    def test_exact_verification_operations_for_existing_staging_type(self):
        text = (ROOT/'sepolicy/private/system_server.te').read_text()
        text = '\n'.join(line.split('#', 1)[0] for line in text.splitlines())
        match = re.fullmatch(
            r'\s*allowxperm\s+system_server\s+staging_data_file:file\s+ioctl\s*'
            r'\{([^}]+)\};\s*', text)
        self.assertIsNotNone(match)
        self.assertEqual(match[1].split(), ['FS_IOC_ENABLE_VERITY', 'FS_IOC_MEASURE_VERITY'])

    def test_common_platform_integration_not_owner_work_privilege(self):
        board = (ROOT/'board/andrix_cf_arm64_only/BoardConfig.mk').read_text()
        declaration = 'SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/andrix/sepolicy/private'
        self.assertEqual(board.count(declaration), 1)
        self.assertLess(board.index(declaration), board.index('ifeq'))
        self.assertNotIn('staging_data_file', (ROOT/'owner/sepolicy/andrix_owner.te').read_text())

    def test_staging_labels_and_verification_properties_not_overridden(self):
        contexts = (ROOT/'sepolicy/private/file_contexts').read_text()
        self.assertNotIn('/data/app-staging', contexts)
        for path in list((ROOT/'products').glob('*.mk')) + list((ROOT/'init').glob('*.rc')):
            text = path.read_text()
            for prop in ['disable_install_time_fsverity_check', 'disable_boot_time_fsverity_check',
                         'disable_same_versionCode_sys_pkg_update_check']:
                self.assertNotIn(prop, text, str(path))


if __name__ == '__main__':
    unittest.main()
