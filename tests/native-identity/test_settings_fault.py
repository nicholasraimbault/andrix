# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

path = Path(__file__).with_name('settings_fault.py')
spec = importlib.util.spec_from_file_location('settings_fault', path)
fault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fault)
A = 'dev.andrix.proof.uidstore'
B = 'dev.andrix.proof.uidstorepeer'


class SettingsFaultTests(unittest.TestCase):
    def source(self):
        return (f'<packages version="fixture"><package name="{A}" userId="10123">'
                '<sigs count="1"><cert index="0" key="aabb"/></sigs></package>'
                f'<package name="{B}" userId="10124"><sigs count="1"><cert index="0"/></sigs>'
                '<perms><item name="test.permission" granted="false"/></perms></package>'
                '<package name="ordinary.other" userId="10125"><sigs count="1">'
                '<cert index="1" key="ccdd"/></sigs></package>'
                '<shared-user name="fixture.shared" userId="10126"><sigs count="1">'
                '<cert index="0"/></sigs></shared-user>'
                '<keyset-settings version="1"><keys><public-key identifier="4" value="fixture"/>'
                '</keys></keyset-settings></packages>').encode()

    def test_removed_definition_does_not_corrupt_peer_signer(self):
        output, report = fault.remove_package(self.source(), A, 10123)
        root = ET.fromstring(output)
        self.assertFalse(any(p.get('name') == A for p in root.findall('package')))
        peer = next(p for p in root.findall('package') if p.get('name') == B)
        self.assertEqual(peer.find('sigs/cert').get('key'), 'aabb')
        self.assertEqual(peer.find('perms/item').get('granted'), 'false')
        self.assertEqual([key for _, key in fault.decode_certificates(root)], ['aabb', 'ccdd', 'aabb'])
        self.assertEqual(root.find('keyset-settings/keys/public-key').get('value'), 'fixture')
        self.assertFalse(report['identity_authority'])

    def test_reference_removal_and_determinism(self):
        first, _ = fault.remove_package(self.source(), B, 10124)
        second, _ = fault.remove_package(self.source(), B, 10124)
        self.assertEqual(first, second)
        self.assertEqual([key for _, key in fault.decode_certificates(ET.fromstring(first))],
                         ['aabb', 'ccdd', 'aabb'])

    def test_exact_scope_and_defined_input_only(self):
        for data, package, uid in [(self.source(), A, 10124), (self.source(), 'ordinary.other', 10125),
                                   (self.source(), A, True), (b'ABX\0foo', A, 10123),
                                   (b'<!DOCTYPE x><packages/>', A, 10123),
                                   (self.source().replace(b'index="0" key="aabb"', b'index="2" key="aabb"'), A, 10123),
                                   (self.source().replace(b'index="0" key="aabb"', b'index="0"'), A, 10123),
                                   (self.source().replace(b'userId="10123"', b'sharedUserId="10123"'), A, 10123)]:
            with self.subTest(package=package, uid=uid), self.assertRaises(ValueError):
                fault.remove_package(data, package, uid)

    def test_unique_certificate_shift_and_past_signer_flags(self):
        data = (f'<packages><package name="{A}" userId="10123"><sigs count="1">'
                '<cert index="0" key="aaaa"/></sigs></package>'
                f'<package name="{B}" userId="10124"><sigs count="1" schemeVersion="3">'
                '<cert index="1" key="bbbb"/><pastSigs count="1">'
                '<cert index="2" key="cccc" flags="4"/></pastSigs></sigs></package></packages>').encode()
        output, _ = fault.remove_package(data, A, 10123)
        root = ET.fromstring(output)
        self.assertEqual([key for _, key in fault.decode_certificates(root)], ['bbbb', 'cccc'])
        self.assertEqual(root.find('package/sigs/cert').get('index'), '0')
        self.assertEqual(root.find('package/sigs/pastSigs/cert').get('flags'), '4')
        self.assertEqual(root.find('package/sigs').get('schemeVersion'), '3')

    def test_keyset_orphan_refused_without_changing_keyset_state(self):
        original = self.source().replace(b'<sigs count="1">',
                b'<proper-signing-keyset identifier="17"/><sigs count="1">', 1)
        with self.assertRaises(ValueError): fault.remove_package(original, A, 10123)
        shared = original.replace((f'name="{B}" userId="10124">').encode(),
                (f'name="{B}" userId="10124"><proper-signing-keyset identifier="17"/>').encode())
        output, report = fault.remove_package(shared, A, 10123)
        self.assertTrue(report['removed_keysets_still_referenced'])
        self.assertEqual(ET.fromstring(output).find('package/proper-signing-keyset').get('identifier'), '17')

    def test_naive_deletion_breaks_shared_certificate_control(self):
        root = ET.fromstring(self.source())
        root.remove(root.find('package'))
        with self.assertRaises(ValueError): fault.decode_certificates(root)


if __name__ == '__main__':
    unittest.main()
