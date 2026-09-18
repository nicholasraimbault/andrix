# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_permissions import allows_all


class PolicyPermissionTests(unittest.TestCase):
    def row(self, source='init', target='ready_socket', perms=()):
        return dict(source=source, target=target, **{'class':'unix_stream_socket'}, perms=perms)

    def test_any_matching_rule_is_not_complete_coverage(self):
        rows=[self.row(perms=['create','getattr'])]
        self.assertFalse(allows_all(rows,'init','ready_socket','unix_stream_socket',{'create','read','write'}))
        self.assertTrue(allows_all(rows,'init','ready_socket','unix_stream_socket',{'create'}))

    def test_separate_matching_rules_can_supply_complete_coverage(self):
        rows=[self.row(perms=['create']), self.row(perms=['read','write'])]
        self.assertTrue(allows_all(rows,'init','ready_socket','unix_stream_socket',{'create','read','write'}))

    def test_other_source_target_or_class_cannot_fill_a_missing_permission(self):
        rows=[self.row(perms=['create']),self.row('other',perms=['read','write']),
              self.row(target='other_socket',perms=['read','write']),
              dict(source='init',target='ready_socket',**{'class':'file'},perms=['read','write'])]
        self.assertFalse(allows_all(rows,'init','ready_socket','unix_stream_socket',{'create','read','write'}))


if __name__=='__main__':unittest.main()
