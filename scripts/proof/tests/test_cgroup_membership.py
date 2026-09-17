# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cgroup_membership import unified_cgroup_path


class CgroupMembershipTests(unittest.TestCase):
    def test_unified_and_hybrid_observations(self):
        expected = '/system/uid_7500/pid_42'
        self.assertEqual(unified_cgroup_path('0::' + expected + '\n'), expected)
        observed = '3:cpuset:/\n2:cpu:/background\n1:blkio:/background\n0::' + expected + '\n'
        self.assertEqual(unified_cgroup_path(observed), expected)
        self.assertEqual(unified_cgroup_path('0::/\n1:cpu,cpuacct:/jobs\n2:name=systemd:/\n'), '/')
        self.assertEqual(unified_cgroup_path('0::/raw:name\n'), '/raw:name')
        # Preserve path text, never normalize a different observation into a match.
        for other in ['/system/uid_7500/pid_43', '/system/uid_7500/pid_42/child',
                      '/system/uid_7500/pid_420', '/../system/uid_7500/pid_42']:
            self.assertNotEqual(unified_cgroup_path('0::'+other+'\n'), expected)

    def test_ambiguous_or_malformed_observations_fail(self):
        for value in [None, b'0::/', '', '1:cpu:/\n', '0::/\n0::/', '0:cpu:/',
                      'x::/', '00::/', '0:/', '0::relative', '0::/\0', '0::/\t',
                      '0::/\n\n1:cpu:/', '0::/\n1::/', '0::/\n1:cpu,cpu:/',
                      '0::/\n1:cpu:/\n2:cpu:/', '0::/\n1:cpu:/\n1:blkio:/',
                      '0::/\n1:bad controller:/', '0::/'+'x'*16384]:
            with self.subTest(value=repr(value)[:100]):
                with self.assertRaises(ValueError):
                    unified_cgroup_path(value)


if __name__ == '__main__':
    unittest.main()
