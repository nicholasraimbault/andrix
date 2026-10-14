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
        return (f'<packages version="fixture"><package name="{A}" codePath="/data/app/~~fixture==/{A}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10123">'
                '<sigs count="1"><cert index="0" key="aabb"/></sigs></package>'
                f'<package name="{B}" codePath="/data/app/~~fixture==/{B}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10124"><sigs count="1"><cert index="0"/></sigs>'
                '<perms><item name="test.permission" granted="false"/></perms></package>'
                '<package name="ordinary.other" codePath="/data/app/~~fixture==/ordinary.other-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10125"><sigs count="1">'
                '<cert index="1" key="ccdd"/></sigs></package>'
                '<shared-user name="fixture.shared" userId="10126"><sigs count="1">'
                '<cert index="0"/></sigs></shared-user>'
                '<keyset-settings version="1"><keys><public-key identifier="4" value="fixture"/>'
                '</keys><keysets/><lastIssuedKeyId value="4"/><lastIssuedKeySetId value="0"/>'
                '</keyset-settings></packages>').encode()

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
        data = (f'<packages><package name="{A}" codePath="/data/app/~~fixture==/{A}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10123"><sigs count="1">'
                '<cert index="0" key="aaaa"/></sigs></package>'
                f'<package name="{B}" codePath="/data/app/~~fixture==/{B}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10124"><sigs count="1" schemeVersion="3">'
                '<cert index="1" key="bbbb"/><pastSigs count="1">'
                '<cert index="2" key="cccc" flags="4"/></pastSigs></sigs></package>'
                '<keyset-settings version="1"><keys/><keysets/><lastIssuedKeyId value="0"/>'
                '<lastIssuedKeySetId value="0"/></keyset-settings></packages>').encode()
        output, _ = fault.remove_package(data, A, 10123)
        root = ET.fromstring(output)
        self.assertEqual([key for _, key in fault.decode_certificates(root)], ['bbbb', 'cccc'])
        self.assertEqual(root.find('package/sigs/cert').get('index'), '0')
        self.assertEqual(root.find('package/sigs/pastSigs/cert').get('flags'), '4')
        self.assertEqual(root.find('package/sigs').get('schemeVersion'), '3')

    def test_keyset_orphan_refused_without_changing_keyset_state(self):
        original = self.source().replace(b'<sigs count="1">',
                b'<proper-signing-keyset identifier="17"/><sigs count="1">', 1).replace(
                b'</keys><keysets/>', b'</keys><keysets><keyset identifier="17"><key-id identifier="4"/></keyset>'
                b'</keysets>')
        self.assertIn(b'<keyset identifier="17">', original)
        with self.assertRaises(ValueError): fault.remove_package(original, A, 10123)
        shared = original.replace((f'name="{B}" codePath="/data/app/~~fixture==/{B}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10124">').encode(),
                (f'name="{B}" codePath="/data/app/~~fixture==/{B}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10124"><proper-signing-keyset identifier="17"/>').encode())
        output, report = fault.remove_package(shared, A, 10123)
        self.assertTrue(report['removed_keysets_still_referenced'])
        self.assertEqual(ET.fromstring(output).find('package/proper-signing-keyset').get('identifier'), '17')

    def keyset_source(self, subject_refs, peer_refs, keysets, keys=('4', '5'), counters=('9', '21')):
        """Settings with keyset references on A (the subject) and B (the peer), the given keysets
        (ID -> key IDs), the public keys and the issue counters."""
        refs = lambda items: ''.join(('<%s alias="alias%s" identifier="%s"/>' % (tag, key, key)) if tag == 'defined-keyset'
                                     else '<%s identifier="%s"/>' % (tag, key) for tag, key in items)
        sets = ''.join('<keyset identifier="%s">%s</keyset>' % (k, ''.join('<key-id identifier="%s"/>' % m for m in members))
                       for k, members in keysets.items())
        return (f'<packages version="fixture"><package name="{A}" codePath="/data/app/~~fixture==/{A}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10123">{refs(subject_refs)}'
                '<sigs count="1"><cert index="0" key="aabb"/></sigs></package>'
                f'<package name="{B}" codePath="/data/app/~~fixture==/{B}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10124">{refs(peer_refs)}<sigs count="1"><cert index="0"/></sigs></package>'
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

    def test_an_unreferenced_keyset_already_in_the_capture_is_refused_in_either_mode(self):
        # The target's keyset stays shared, so the removal orphans nothing, but keyset 20 has no
        # package reference already: Package Manager would report and remove it on its next read.
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '17')],
                                    {'17': ['4'], '20': ['5']})
        for mode in ('refuse', 'remove-as-android'):
            with self.subTest(mode), self.assertRaisesRegex(ValueError, 'already holds a keyset no package references'):
                fault.remove_package(source, A, 10123, orphaned_keysets=mode)

    def test_keyset_references_outside_package_rows_are_refused(self):
        base = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                  {'17': ['4'], '18': ['5']})
        # The writer's shared users and disabled system packages hold no keyset references; an
        # element it never writes is refused as such before its contents are read.
        for container, message in (('shared-user', 'outside a package row'), ('updated-package', 'outside a package row'),
                                   ('unknown-element', 'an element the settings writer never writes')):
            source = base.replace(b'<keyset-settings', ('<%s name="x" userId="10199"><proper-signing-keyset identifier="18"/></%s>'
                                                        '<keyset-settings' % (container, container)).encode(), 1)
            for mode in ('refuse', 'remove-as-android'):
                with self.subTest(container=container, mode=mode), self.assertRaisesRegex(ValueError, message):
                    fault.remove_package(source, A, 10123, orphaned_keysets=mode)

    def test_only_the_writer_keyset_shapes_are_admitted_in_either_mode(self):
        # Settings.writeLPr writes keyset references as immediate children of package rows and
        # keyset-settings once, last; nothing else reaches the removal.
        base = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                  {'17': ['4'], '18': ['5']})
        settings = base[base.index(b'<keyset-settings'):base.index(b'</packages>')]
        cases = {
            'a reference nested below a package row': (
                base.replace(b'<sigs count="1"><cert index="0"/></sigs>', b'<sigs count="1"><cert index="0"/></sigs>'
                             b'<perms><proper-signing-keyset identifier="18"/></perms>', 1), 'nested below a package row'),
            'a reference inside signatures': (
                base.replace(b'<sigs count="1"><cert index="0"/>', b'<sigs count="1"><proper-signing-keyset identifier="18"/>'
                             b'<cert index="0"/>', 1), 'signatures outside the places'),
            'a second keyset-settings': (
                base.replace(b'</packages>', settings + b'</packages>'), 'one final keyset-settings'),
            'keyset-settings before a row': (
                base.replace(settings, b'').replace(b'<package name', settings + b'<package name', 1), 'one final keyset-settings'),
            'no keyset-settings': (base.replace(settings, b''), 'one final keyset-settings'),
            'a peer reference naming no defined keyset': (
                base.replace(b'<proper-signing-keyset identifier="18"/>', b'<proper-signing-keyset identifier="18"/>'
                             b'<upgrade-keyset identifier="44"/>', 1), 'names no defined keyset'),
        }
        for label, (source, message) in cases.items():
            for mode in ('refuse', 'remove-as-android'):
                with self.subTest(label=label, mode=mode), self.assertRaisesRegex(ValueError, message):
                    fault.remove_package(source, A, 10123, orphaned_keysets=mode)

    def test_only_the_writer_keyset_settings_tree_is_admitted_in_either_mode(self):
        # KeySetManagerService's readers take every element below keys and keysets by name at any
        # depth, so a wrapped definition or key ID would be read by Package Manager but not here: the
        # first case would remove key 4, which keyset 18 would still hold for Package Manager.
        base = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                  {'17': ['4'], '18': ['5']})

        def edit(source, old, new):
            self.assertEqual(source.count(old), 1, old)
            return source.replace(old, new)
        counters = b'<lastIssuedKeyId value="9"/><lastIssuedKeySetId value="21"/>'
        tree, row = 'not the tree the writer leaves', 'would count otherwise'
        shared = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '17')], {'17': ['4']})
        cases = {
            'a key ID of a surviving keyset in a wrapper': (edit(base, b'<key-id identifier="5"/></keyset>',
                b'<key-id identifier="5"/><unexpected-wrapper><key-id identifier="4"/></unexpected-wrapper></keyset>'), tree),
            'a keyset definition no row counts, in a wrapper': (edit(shared, b'</keysets>',
                b'<unexpected-wrapper><keyset identifier="20"><key-id identifier="4"/></keyset></unexpected-wrapper></keysets>'), tree),
            'a public key in a wrapper': (edit(base, b'</keys>',
                b'<unexpected-wrapper><public-key identifier="6" value="k6"/></unexpected-wrapper></keys>'), tree),
            'no version': (edit(base, b'<keyset-settings version="1">', b'<keyset-settings>'), tree),
            'no issue counters': (edit(base, counters, b''), tree),
            'the issue counters first': (edit(edit(base, counters, b''), b'<keys>', counters + b'<keys>'), tree),
            'an issue counter that is not a long': (edit(base, b'value="9"', b'value="nine"'), tree),
            'a keyset identifier with a leading zero': (edit(base, b'<keyset identifier="18">', b'<keyset identifier="018">'), tree),
            'a reference identifier with a leading zero': (edit(base, b'<proper-signing-keyset identifier="18"/>',
                b'<proper-signing-keyset identifier="018"/>'), 'reference identifier the writer does not leave'),
            'an empty keyset': (edit(base, b'</keysets>', b'<keyset identifier="20"/></keysets>'), 'keyset definition'),
            'a key ID naming no public key': (edit(base, b'<key-id identifier="5"/>', b'<key-id identifier="7"/>'), 'keyset definition'),
            'two signing keysets in one row': (edit(base, b'<proper-signing-keyset identifier="18"/>',
                b'<proper-signing-keyset identifier="18"/><proper-signing-keyset identifier="18"/>'), row),
            'one alias defined twice in a row': (self.keyset_source(
                [('proper-signing-keyset', '17'), ('defined-keyset', '18'), ('defined-keyset', '18')],
                [('proper-signing-keyset', '18')], {'17': ['4'], '18': ['5']}), row),
            'a defined keyset without an alias': (edit(self.keyset_source(
                [('proper-signing-keyset', '17'), ('defined-keyset', '18')], [('proper-signing-keyset', '18')],
                {'17': ['4'], '18': ['5']}), b' alias="alias18"', b''), row),
        }
        for label, (source, message) in cases.items():
            for mode in ('refuse', 'remove-as-android'):
                with self.subTest(label=label, mode=mode), self.assertRaisesRegex(ValueError, message):
                    fault.remove_package(source, A, 10123, orphaned_keysets=mode)
        # The same settings in the writer's tree are admitted. A row without a signing keyset counts
        # nothing, as Package Manager's removal of it takes nothing back, and key 5, which no keyset
        # holds, stays.
        output, report = fault.remove_package(base, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual((report['removed_unreferenced_keysets'], report['removed_unreferenced_public_keys']), (['17'], ['4']))
        unsigned = self.keyset_source([('proper-signing-keyset', '17')], [], {'17': ['4']})
        output, report = fault.remove_package(unsigned, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual((report['removed_unreferenced_keysets'], report['removed_unreferenced_public_keys']), (['17'], ['4']))
        self.assertEqual([k.get('identifier') for k in ET.fromstring(output).findall('keyset-settings/keys/public-key')], ['5'])
        output, report = fault.remove_package(shared, A, 10123, orphaned_keysets='remove-as-android')
        self.assertTrue(report['removed_keysets_still_referenced'])

    def test_a_package_row_the_reader_skips_is_refused_in_either_mode(self):
        # Settings.readPackageLPw skips these rows, so their keyset references would never count:
        # here the peer row's reference to keyset 17 would seem to keep the subject's keyset.
        base = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                  {'17': ['4'], '18': ['5']})
        row = '<package name="probe.reader.skipped" codePath="/data/app/~~p==/probe-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="19999"><proper-signing-keyset identifier="17"/></package>'

        def added(text):
            return base.replace(b'<keyset-settings', text.encode() + b'<keyset-settings', 1)
        cases = {
            'no name': added(row.replace(' name="probe.reader.skipped"', '')),
            'no code path': added(row.replace(' codePath="/data/app/~~p==/probe-1" domainSetId="00000000-0000-4000-8000-000000000001"', '')),
            'app ID 0': added(row.replace('userId="19999"', 'userId="0"')),
            'an app ID with a leading zero': added(row.replace('userId="19999"', 'userId="019999"')),
            'both app IDs': added(row.replace('userId="19999"', 'userId="19999" sharedUserId="10126"')),
            'neither app ID': added(row.replace(' userId="19999"', '')),
            'the name of an earlier row': added(row.replace('probe.reader.skipped', B)),
            'the app ID of an earlier row': added(row.replace('19999', '10124')),
            'a shared user no row defines': added(row.replace('userId="19999"', 'sharedUserId="10126"')),
        }
        for label, source in cases.items():
            for mode in ('refuse', 'remove-as-android'):
                with self.subTest(label=label, mode=mode), self.assertRaisesRegex(ValueError, "reader skips or the writer never leaves"):
                    fault.remove_package(source, A, 10123, orphaned_keysets=mode)
        # A shared user's package row that names a shared user the settings define is admitted.
        shared = base.replace(b'<keyset-settings', b'<shared-user name="fixture.shared" userId="10126"/><keyset-settings', 1)
        shared = shared.replace(b'<keyset-settings', (row.replace('userId="19999"', 'sharedUserId="10126"')
                                                      .replace('identifier="17"', 'identifier="18"')).encode() + b'<keyset-settings', 1)
        output, report = fault.remove_package(shared, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(report['removed_unreferenced_keysets'], ['17'])

    def test_only_the_writer_structure_is_admitted_in_either_mode(self):
        # Settings.readSettingsLPw reads what lies below an element it reads only by its attributes
        # as if it stood under <packages>; it skips an element the writer never writes, with any
        # certificate in it; PackageSignatures reads certificates only in signatures, up to their count.
        base = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                  {'17': ['4'], '18': ['5']})
        row = ('<package name="probe.hidden" codePath="/data/app/~~p==/probe-1" domainSetId="00000000-0000-4000-8000-000000000001" '
               'userId="19999"/>')

        def before_keysets(text):
            return base.replace(b'<keyset-settings', text.encode() + b'<keyset-settings', 1)
        cases = {
            'a package row inside a renamed package': (before_keysets('<renamed-package new="n" old="o">%s</renamed-package>' % row),
                                                       'writes empty holds others'),
            'a shared user inside a renamed package': (before_keysets('<renamed-package new="n" old="o"><shared-user name="s" userId="19999"/>'
                                                                      '</renamed-package>'), 'writes empty holds others'),
            'an element the writer never writes, with a certificate': (
                before_keysets('<probe.ignored-cert><cert index="0"/></probe.ignored-cert>'), 'never writes'),
            'a certificate in a child the package reader skips': (
                base.replace(b'<sigs count="1"><cert index="0"/></sigs>', b'<sigs count="1"><cert index="0"/></sigs><probe><cert index="0"/></probe>', 1),
                'a certificate outside the signatures'),
            'signatures counting more certificates than they hold': (
                base.replace(b'<sigs count="1"><cert index="0"/></sigs>', b'<sigs count="2"><cert index="0"/></sigs>', 1), 'count is not'),
            'a shared user without a name': (before_keysets('<shared-user userId="10199"/>'), 'shared user the settings reader'),
            'two shared users of one name': (before_keysets('<shared-user name="s" userId="10198"/><shared-user name="s" userId="10199"/>'),
                                             'shared user the settings reader'),
            'a domain set that is not a UUID': (before_keysets(row.replace('00000000-0000-4000-8000-000000000001', 'not-a-uuid')),
                                                'reader skips or the writer never leaves'),
        }
        for label, (source, message) in cases.items():
            for mode in ('refuse', 'remove-as-android'):
                with self.subTest(label=label, mode=mode), self.assertRaisesRegex(ValueError, message):
                    fault.remove_package(source, A, 10123, orphaned_keysets=mode)
        # The same row placed as the writer places it is admitted.
        output, report = fault.remove_package(before_keysets(row), A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(report['removed_unreferenced_keysets'], ['17'])

    def test_a_public_key_no_keyset_holds_is_admitted_and_left_alone(self):
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                    {'17': ['4'], '18': ['5']}, keys=('4', '5', '6'))
        output, report = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        self.assertEqual(report['removed_unreferenced_public_keys'], ['4'])
        kept = [k.get('identifier') for k in ET.fromstring(output).findall('keyset-settings/keys/public-key')]
        self.assertEqual(kept, ['5', '6'])

    def test_a_row_removed_with_its_own_keysets_is_not_restored(self):
        source = self.keyset_source([('proper-signing-keyset', '17')], [('proper-signing-keyset', '18')],
                                    {'17': ['4'], '18': ['5']})
        current, _ = fault.remove_package(source, A, 10123, orphaned_keysets='remove-as-android')
        with self.assertRaisesRegex(ValueError, 'original signing keyset is missing or changed'):
            fault.restore_package(current, source, A, 10123)

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
        # The keyset reference goes on the three package rows only: Package Manager's writer puts
        # none on a shared user record, and remove_package refuses one there.
        source = self.source()
        for uid in (10123, 10124, 10125):
            source = source.replace(b'userId="%d"><sigs count="1">' % uid,
                                    b'userId="%d"><proper-signing-keyset identifier="17"/><sigs count="1">' % uid)
        source = source.replace(b'</keys><keysets/>',
                b'</keys><keysets><keyset identifier="17"><key-id identifier="4"/></keyset></keysets>')
        self.assertIn(b'<keyset identifier="17">', source)
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
        return (f'<packages version="fixture"><package name="{A}" codePath="/data/app/~~fixture==/{A}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10147">'
                '<sigs count="1"><cert index="0" key="aabb"/></sigs></package>'
                f'<package name="{S}" codePath="/data/app/~~fixture==/{S}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10148"><sigs count="1"><cert index="1" key="874c"/></sigs>'
                '<perms><item name="test.permission" granted="false"/></perms></package>'
                f'<package name="{B}" codePath="/data/app/~~fixture==/{B}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10149"><sigs count="1"><cert index="1"/></sigs></package>'
                '<keyset-settings version="1"><keys><public-key identifier="4" value="fixture"/>'
                '</keys><keysets/><lastIssuedKeyId value="4"/><lastIssuedKeySetId value="0"/>'
                '</keyset-settings></packages>').encode()

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
        keyset = self.source().replace(f'name="{S}" codePath="/data/app/~~fixture==/{S}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10148">'.encode(),
                                       f'name="{S}" codePath="/data/app/~~fixture==/{S}-1" domainSetId="00000000-0000-4000-8000-000000000001" userId="10148"><proper-signing-keyset identifier="17"/>'.encode())
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
