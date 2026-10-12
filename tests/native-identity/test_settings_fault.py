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

    def keyset_source(self, subject_refs, peer_refs, keysets, keys=('4', '5'), counters=('9', '21')):
        """Settings with keyset references on A (the subject) and B (the peer), the given keysets
        (ID -> key IDs), the public keys and the issue counters."""
        refs = lambda items: ''.join('<%s identifier="%s"/>' % item for item in items)
        sets = ''.join('<keyset identifier="%s">%s</keyset>' % (k, ''.join('<key-id identifier="%s"/>' % m for m in members))
                       for k, members in keysets.items())
        return (f'<packages version="fixture"><package name="{A}" userId="10123">{refs(subject_refs)}'
                '<sigs count="1"><cert index="0" key="aabb"/></sigs></package>'
                f'<package name="{B}" userId="10124">{refs(peer_refs)}<sigs count="1"><cert index="0"/></sigs></package>'
                '<keyset-settings version="1"><keys>'
                + ''.join('<public-key identifier="%s" value="k%s"/>' % (k, k) for k in keys)
                + f'</keys><keysets>{sets}</keysets><lastIssuedKeyId value="{counters[0]}"/>'
                f'<lastIssuedKeySetId value="{counters[1]}"/></keyset-settings></packages>').encode()

    def keyset_state(self, output):
        settings = ET.fromstring(output).find('keyset-settings')
        return ({k.get('identifier'): [m.get('identifier') for m in k.findall('key-id')] for k in settings.findall('keysets/keyset')},
                sorted(k.get('identifier') for k in settings.findall('keys/public-key')),
                (settings.find('lastIssuedKeyId').get('value'), settings.find('lastIssuedKeySetId').get('value')))

    def test_an_unreferenced_keyset_and_its_own_key_go_as_android_removes_them(self):
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                    {'17': ['4'], '18': ['5']})
        with self.assertRaisesRegex(ValueError, 'orphan'):
            fault.remove_package(source, A, 10123)
        output, report = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(self.keyset_state(output), ({'18': ['5']}, ['5'], ('9', '21')))
        self.assertEqual((report['removed_unreferenced_keysets'], report['removed_unreferenced_public_keys']), (['17'], ['4']))
        self.assertFalse(report['removed_keysets_still_referenced'])
        self.assertFalse(any(p.get('name') == A for p in ET.fromstring(output).findall('package')))

    def test_a_key_another_keyset_holds_stays(self):
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                    {'17': ['4'], '18': ['4', '5']})
        output, report = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(self.keyset_state(output), ({'18': ['4', '5']}, ['4', '5'], ('9', '21')))
        self.assertEqual((report['removed_unreferenced_keysets'], report['removed_unreferenced_public_keys']), (['17'], []))

    def test_a_keyset_the_peer_counts_stays_in_either_mode(self):
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '17')], {'17': ['4']},
                                    keys=('4',))
        default, _ = fault.remove_package(source, A, 10123)
        removing, report = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(default, removing)
        self.assertEqual(self.keyset_state(removing), ({'17': ['4']}, ['4'], ('9', '21')))
        self.assertEqual(report['removed_unreferenced_keysets'], [])

    def test_a_defined_keyset_alias_goes_with_the_signing_keyset(self):
        source = self.keyset_source([('proper-signing-keyset', '17'), ('defined-keyset', '19'), ('upgrade-keyset', '19')],
                                    [('proper-signing-keyset', '18')], {'17': ['4'], '18': ['5'], '19': ['4']})
        output, report = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(self.keyset_state(output), ({'18': ['5']}, ['5'], ('9', '21')))
        self.assertEqual((report['removed_unreferenced_keysets'], report['removed_unreferenced_public_keys']), (['17', '19'], ['4']))

    def test_unsafe_keyset_states_are_refused_in_removal_mode(self):
        cases = {
            'a keyset no package references already':
                self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                   {'17': ['4'], '18': ['5'], '20': ['5']}),
            'an upgrade keyset of the peer that would go':
                self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18'), ('upgrade-keyset', '17')],
                                   {'17': ['4'], '18': ['5']}),
            'a removed keyset without its definition':
                self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')], {'18': ['5']}),
        }
        for label, source in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        with self.assertRaisesRegex(ValueError, 'refused or removed'):
            fault.remove_package(cases['a keyset no package references already'], A, 10123, orphaned_keysets='drop')

    def test_a_peer_naming_the_keyset_only_as_an_upgrade_is_refused_in_either_mode(self):
        # Package Manager does not count upgrade references, so the keyset would go and the peer's
        # upgrade reference would dangle; the earlier count, which included upgrades, accepted this.
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18'), ('upgrade-keyset', '17')],
                                    {'17': ['4'], '18': ['5']})
        for mode in ('refuse', 'remove-as-android'):
            with self.subTest(mode), self.assertRaisesRegex(ValueError, 'upgrade keyset that would go'):
                fault.remove_package(source, A, 10123, orphaned_keysets=mode)

    def test_keyset_removal_is_deterministic(self):
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                    {'17': ['4'], '18': ['5']})
        first, _ = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        second, _ = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(first, second)

    def test_equivalent_xml_control_preserves_all_semantics(self):
        before = self.source()
        rewritten = fault.rewrite_equivalent(before)
        self.assertEqual(fault.semantic(ET.fromstring(before)), fault.semantic(ET.fromstring(rewritten)))
        token = 'a' * 32
        traced = ET.fromstring(fault.rewrite_equivalent(before, token))
        witness = traced.find('andrix-fixture-parse-' + token)
        self.assertIsNotNone(witness)
        self.assertIs(traced[-1], witness)
        traced.remove(witness)
        self.assertEqual(fault.semantic(ET.fromstring(before)), fault.semantic(traced))
        with self.assertRaises(ValueError): fault.rewrite_equivalent(fault.rewrite_equivalent(before, token), token)
        with self.assertRaises(ValueError): fault.rewrite_equivalent(before, '../wrong')

    def test_inverse_preserves_new_current_package_and_signing_state(self):
        original = self.source()
        removed, _ = fault.remove_package(original, A, 10123)
        root = ET.fromstring(removed)
        added = ET.SubElement(root, 'package', {'name': 'fixture.new', 'userId': '10127'})
        sigs = ET.SubElement(added, 'sigs', {'count': '1'})
        ET.SubElement(sigs, 'cert', {'index': '2', 'key': 'eeee'})
        root.remove(added)
        root.insert(list(root).index(root.find('keyset-settings')), added)
        current = ET.tostring(root)
        restored, report = fault.restore_package(current, original, A, 10123)
        result = ET.fromstring(restored)
        self.assertEqual(next(p for p in result.findall('package') if p.get('name') == 'fixture.new').get('userId'), '10127')
        self.assertTrue(report['current_unrelated_settings_preserved'])
        self.assertFalse(report['app_data_or_keys_restored'])
        self.assertEqual([key for _, key in fault.decode_certificates(result)], ['aabb', 'ccdd', 'aabb', 'eeee', 'aabb'])
        with self.assertRaises(ValueError): fault.restore_package(restored, original, A, 10123)
        occupied = current.replace(b'userId="10127"', b'userId="10123"')
        with self.assertRaises(ValueError): fault.restore_package(occupied, original, A, 10123)
        shared_reference = current.replace(b'userId="10127"', b'sharedUserId="10123"')
        with self.assertRaises(ValueError): fault.restore_package(shared_reference, original, A, 10123)
        with self.assertRaises(ValueError): fault.restore_package(current, original, A, 10128)

    def test_inverse_requires_original_keyset_contents(self):
        source = self.source().replace(b'<sigs count="1">',
                b'<proper-signing-keyset identifier="17"/><sigs count="1">')
        source = source.replace(b'</keys></keyset-settings>',
                b'</keys><keysets><keyset identifier="17"><key-id identifier="4"/></keyset></keysets></keyset-settings>')
        current, _ = fault.remove_package(source, A, 10123)
        restored, _ = fault.restore_package(current, source, A, 10123)
        self.assertIn(A.encode(), restored)
        parsed = ET.fromstring(restored)
        package = next(node for node in parsed if node.tag == 'package' and node.get('name') == A)
        self.assertLess(list(parsed).index(package), list(parsed).index(parsed.find('keyset-settings')))
        moved = ET.fromstring(fault.rewrite_equivalent(source, 'b' * 32, A))
        package = next(node for node in moved if node.tag == 'package' and node.get('name') == A)
        self.assertLess(list(moved).index(package), list(moved).index(moved.find('keyset-settings')))
        for bad in (current.replace(b'value="fixture"', b'value="changed"'),
                    current.replace(b'identifier="17"', b'identifier="18"')):
            with self.assertRaises(ValueError): fault.restore_package(bad, source, A, 10123)

    def test_naive_deletion_breaks_shared_certificate_control(self):
        root = ET.fromstring(self.source())
        root.remove(root.find('package'))
        with self.assertRaises(ValueError): fault.decode_certificates(root)



S = 'dev.andrix.proof.principalclosed'


class SubjectTests(unittest.TestCase):
    """The lifecycle record's fixed subject, installed between the two observers and the first writer
    of a certificate that the peer shares."""

    def source(self):
        return (f'<packages version="fixture"><package name="{A}" userId="10147">'
                '<sigs count="1"><cert index="0" key="aabb"/></sigs></package>'
                f'<package name="{S}" userId="10148"><sigs count="1"><cert index="1" key="874c"/></sigs>'
                '<perms><item name="test.permission" granted="false"/></perms></package>'
                f'<package name="{B}" userId="10149"><sigs count="1"><cert index="1"/></sigs></package>'
                '<keyset-settings version="1"><keys><public-key identifier="4" value="fixture"/>'
                '</keys></keyset-settings></packages>').encode()

    def test_only_the_subject_joins_the_two_observers(self):
        self.assertEqual(fault.ALLOWED, {A, B, S})
        for package in ('dev.andrix.proof.lifecycleother', 'dev.andrix.proof.uidallocation', 'ordinary.other'):
            with self.subTest(package=package), self.assertRaises(ValueError):
                fault.remove_package(self.source().replace(S.encode(), package.encode()), package, 10148)

    def test_the_subject_row_alone_is_removed_and_the_peer_keeps_its_signer(self):
        output, report = fault.remove_package(self.source(), S, 10148)
        root = ET.fromstring(output)
        self.assertEqual([p.get('name') for p in root.findall('package')], [A, B])
        self.assertEqual(next(p for p in root.findall('package') if p.get('name') == B).find('sigs/cert').get('key'),
                         '874c')
        self.assertEqual([key for _, key in fault.decode_certificates(root)], ['aabb', '874c'])
        self.assertEqual((report['removed_package'], report['app_id'], report['identity_authority']), (S, 10148, False))
        rewritten = fault.rewrite_equivalent(self.source())
        self.assertEqual(fault.semantic(ET.fromstring(self.source())), fault.semantic(ET.fromstring(rewritten)))

    def test_wrong_rows_and_unsafe_removals_are_refused(self):
        removed, _ = fault.remove_package(self.source(), S, 10148)
        keyset = self.source().replace(f'name="{S}" userId="10148">'.encode(),
                                       f'name="{S}" userId="10148"><proper-signing-keyset identifier="17"/>'.encode())
        for data, uid in ((self.source(), 10147), (self.source(), 10149),
                          (self.source().replace(b'userId="10148"', b'sharedUserId="10148"'), 10148),
                          (removed, 10148), (keyset, 10148),
                          (self.source().replace(b'index="1" key="874c"', b'index="1"'), 10148)):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                fault.remove_package(data, S, uid)

    def test_naive_deletion_of_the_subject_breaks_the_peer_certificate(self):
        root = ET.fromstring(self.source())
        root.remove(next(p for p in root.findall('package') if p.get('name') == S))
        with self.assertRaises(ValueError):
            fault.decode_certificates(root)


if __name__ == '__main__':
    unittest.main()
