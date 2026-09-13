# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import json
import unittest

ROOT=Path(__file__).resolve().parents[3]


class NativeTmuxProfileTests(unittest.TestCase):
    def test_same_Bionic_sdk_hardening_not_static_Bionic(self):
        p=json.loads((ROOT/'toolchain/tmux/profile.json').read_text())
        m=json.loads((ROOT/'toolchain/make/profile.json').read_text())
        for key in ['target','sdk_manifest_sha256','bootstrap_project','bootstrap_revision',
                    'bootstrap_directory','bootstrap_version','host_make_project','host_make_revision',
                    'host_make_file','host_make_sha256','cflags','ldflags']:
            self.assertEqual(p[key],m[key])
        self.assertEqual(p['target'],'aarch64-linux-android37')
        self.assertTrue(p['dynamic_Bionic'])
        self.assertIn('--disable-static',p['configure']['tmux'])
        self.assertNotIn('--enable-static',p['configure']['tmux'])
        self.assertNotIn('-static',p['ldflags'])
        self.assertIn('-fsanitize=cfi-icall',p['cflags'])
        self.assertIn('--disable-systemd',p['configure']['tmux'])
        self.assertIn('--disable-cgroups',p['configure']['tmux'])
        self.assertIn('--disable-utempter',p['configure']['tmux'])
        self.assertIn('--disable-openssl',p['configure']['libevent'])
        self.assertIn('--without-shared',p['configure']['ncurses_native'])
        self.assertIn('--sysconfdir=/usr/etc/andrix/tmux',p['configure']['tmux'])
        self.assertIn('tmux-256color',p['terminfo_entries'])

    def test_owner_socket_rule_is_not_a_foreign_domain_grant(self):
        text=(ROOT/'owner/sepolicy/andrix_owner.te').read_text()
        self.assertIn('allow andrix_owner andrix_home_file:sock_file { create getattr setattr read write unlink };',text)
        self.assertIn('neverallow { untrusted_app_all isolated_app_all andrix_terminal andrixd } andrix_home_file:sock_file',text)
        self.assertIn('neverallow { untrusted_app_all isolated_app_all andrix_terminal andrixd } andrix_owner:unix_stream_socket connectto;',text)
        self.assertIn('neverallow { andrixd andrix_owner } self:capability_class_set *;',text)
        self.assertNotIn('allow andrix_owner app_data_file',text)

    def test_distinct_source_assurance_and_selected_versions(self):
        p=json.loads((ROOT/'toolchain/tmux/profile.json').read_text())
        self.assertEqual(set(p['packages']),{'tmux','libevent','ncurses'})
        self.assertEqual(p['packages']['tmux']['version'],'3.7c')
        self.assertEqual(p['packages']['libevent']['version'],'2.1.13-stable')
        self.assertEqual(p['packages']['ncurses']['version'],'6.6-20260912')
        self.assertFalse(p['packages']['tmux']['tag_signed'])
        self.assertEqual(p['packages']['tmux']['commit'],'e476c1230b958df0cb12977517d24b3dc931375b')
        for value in p['packages'].values():
            self.assertRegex(value['archive']['sha256'],r'^[0-9a-f]{64}$')
            self.assertTrue(value['archive']['url'].startswith('https://'))
        for name in ['libevent','ncurses']:
            self.assertRegex(p['packages'][name]['keyring']['sha256'],r'^[0-9a-f]{64}$')
            self.assertRegex(p['packages'][name]['signing_key'],r'^[0-9A-F]{40}$')
            self.assertIn('out-of-band',p['packages'][name]['source_assurance'])


if __name__=='__main__':unittest.main()
