# SPDX-License-Identifier: Apache-2.0
"""The selected base reader: refusals and a second base in scratch, and the tools' identity on the
repository's selection, the pinned base 2026081300."""
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import grapheneos_base as base  # noqa: E402

PINNED, SECOND = '2026081300', '2026100600'
PINNED_RECORD = 'upstream/bases/2026081300.json'
PINNED_PATCHES = 'patches/grapheneos-2026081300'
FRAMEWORK = 'aab06a8bd44c4c2b58eeec780fde83baa9d43a40'
POLICY = '87a06ed71fd67cff9f77feaa9ae3504edb5d0972'
# The values grapheneos_source.py held as constants before it read the selection.
SOURCE = (PINNED, '5189230024ffe0048e0c351d5101c6b3f8b43eac',
          '84536744f0c06cccbcfa2110e9c937671ddc3278',
          'c50f0096f538e604aa008e8ab4e3f1a3739f142c60c878a32f402c11eb406572', 1108,
          'refs/tags/android-17.0.0_r1')
# The 2026100600 record's identity, read in scratch only.
SECOND_MANIFEST = ('bff830c5e298027889ec3bfa51ba1e48b23801f4',
                   '26f7e8a760d4343a501faf09773ec4cc61a6b56b',
                   '32d30e70ee59d373a17fe8090bdded898afa80651f27c331caca4578b3008888')
SECOND_REVISIONS = {'frameworks/base': '84183aff99be5e156dc0446a6fa2d4a7150f4bc3',
                    'system/sepolicy': '5e359dcf9ae863a593e9055a85e1657c87c4cb18'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ScratchSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root / 'upstream/bases').mkdir(parents=True)
        for release in (PINNED, SECOND):
            shutil.copyfile(ROOT / 'upstream/bases' / (release + '.json'), self.record(release))
        self.selection = self.root / 'upstream/selected-base.json'

    def record(self, release):
        return self.root / 'upstream/bases' / (release + '.json')

    def select(self, of=PINNED, **changes):
        """Write a scratch selection of the base `of`, its fields replaced by any changes."""
        value = {'schema': base.SCHEMA, 'release': of, 'record': 'upstream/bases/%s.json' % of,
                 'record_sha256': sha(self.record(of).read_bytes())}
        value.update(changes)
        self.selection.write_text(json.dumps(value, indent=2) + '\n')

    def refused(self, pattern):
        with self.assertRaisesRegex(base.BaseSelectionError, pattern):
            base.load(root=self.root)

    def test_the_pinned_selection_in_scratch_reads_as_the_repository_does(self):
        self.select(PINNED)
        found, repository = base.load(root=self.root), base.selected()
        self.assertEqual(found.patches, self.root / PINNED_PATCHES)
        for field in dataclasses.fields(base.Base):
            if field.name != 'patches':
                self.assertEqual(getattr(found, field.name), getattr(repository, field.name),
                                 field.name)
        self.assertEqual(base.load(self.selection, self.root), found)

    def test_a_second_base_is_selectable_in_scratch_only(self):
        before = (ROOT / base.SELECTION).read_bytes()
        self.select(SECOND)
        found = base.load(root=self.root)
        self.assertEqual((found.release, found.record), (SECOND, 'upstream/bases/2026100600.json'))
        self.assertEqual(found.record_sha256, sha(self.record(SECOND).read_bytes()))
        self.assertEqual((found.tag_object, found.manifest_commit, found.manifest_sha256),
                         SECOND_MANIFEST)
        self.assertEqual((found.project_count, found.security_patch_level), (1057, '2026-10-05'))
        self.assertEqual(found.aosp_default_revision, 'refs/tags/android-17.0.0_r1')
        self.assertEqual(dict(found.revisions), SECOND_REVISIONS)
        self.assertEqual(found.revision('frameworks/base'), SECOND_REVISIONS['frameworks/base'])
        self.assertEqual(found.patches, self.root / 'patches/grapheneos-2026100600')
        # The repository still selects the pinned base, and its selection is unchanged.
        self.assertEqual(base.selected().release, PINNED)
        self.assertEqual(base.load().release, PINNED)
        self.assertEqual((ROOT / base.SELECTION).read_bytes(), before)

    def test_a_missing_selection_or_record_is_refused(self):
        self.refused('the base selection is missing')
        self.selection.write_text('')
        self.refused('base selection is not JSON')
        self.select(PINNED, release='2026090500', record='upstream/bases/2026090500.json')
        self.refused('the base record is missing')
        for key in base.SELECTION_KEYS:
            self.select(PINNED)
            value = json.loads(self.selection.read_text())
            del value[key]
            self.selection.write_text(json.dumps(value))
            self.refused('the selection must hold exactly')
        self.select(PINNED)
        self.record(PINNED).unlink()
        self.refused('the base record is missing')
        with self.assertRaisesRegex(base.BaseSelectionError, 'the base selection is missing'):
            base.load(self.root / 'upstream/other.json', self.root)

    def test_a_changed_selection_is_refused(self):
        pinned = sha(self.record(PINNED).read_bytes())
        # Another release named with the pinned record's digest, as a partial edit leaves it.
        self.select(SECOND, record_sha256=pinned)
        self.refused('the base record differs from the digest the selection names')
        self.select(PINNED, record_sha256='0' * 64)
        self.refused('the base record differs from the digest the selection names')
        self.select(PINNED, record_sha256=pinned.upper())
        self.refused('the selection names no record digest')
        self.select(PINNED, schema='andrix.upstream.selected_base/2')
        self.refused('unknown selection schema')
        self.select(PINNED, note='switched')
        self.refused('the selection must hold exactly')
        for release in ('latest', '202608130', 2026081300, None, ''):
            self.select(PINNED, release=release)
            self.refused('the selected release is not a release tag')
        self.select(PINNED)
        self.selection.write_text(self.selection.read_text().replace('}', '}}'))
        self.refused('base selection is not JSON')

    def test_an_ambiguous_selection_is_refused(self):
        self.select(PINNED)
        text = self.selection.read_text()
        self.selection.write_text(text.replace('"release": "2026081300",',
                                               '"release": "2026081300", "release": "2026100600",'))
        self.refused("ambiguous: the key 'release' occurs twice")
        for release in ([PINNED, SECOND], [PINNED], {'base': PINNED}):
            self.select(PINNED, release=release)
            self.refused('ambiguous: the selection must name exactly one base')
        # One base by its release, another by its record and digest.
        self.select(PINNED, record='upstream/bases/2026100600.json',
                    record_sha256=sha(self.record(SECOND).read_bytes()))
        self.refused('ambiguous: the selection names release 2026081300 and the record')
        for record in ('upstream/bases/../bases/2026081300.json', '/' + PINNED_RECORD,
                       PINNED_RECORD + ' ', './' + PINNED_RECORD):
            self.select(PINNED, record=record)
            self.refused('ambiguous: the selection names release 2026081300 and the record')

    def test_a_base_record_whose_digest_disagrees_is_refused(self):
        self.select(PINNED)
        path = self.record(PINNED)
        original = path.read_bytes()
        for changed in (original + b'\n', original.replace(FRAMEWORK.encode(), b'1' * 40),
                        original.replace(b'"count": 1108', b'"count": 1107'), b''):
            path.write_bytes(changed)
            self.refused('the base record differs from the digest the selection names')
        # A record changed and selected by its new digest still has to name that base exactly.
        for old, new, pattern in (
                (b'"release": "2026081300"', b'"release": "2026100600"',
                 'ambiguous: the record of 2026081300'),
                (FRAMEWORK.encode(), b'HEAD', 'no exact patched project revisions'),
                (b'"refs/tags/2026081300"', b'"refs/tags/2026100600"',
                 'no exact manifest identity'),
                (b'"count": 1108', b'"count": true', 'no project count'),
                (b'"value": "2026-08-05"', b'"value": "August"', 'no security patch level'),
                (b'"andrix.upstream.base/1"', b'"andrix.upstream.base/2"', 'not a base record'),
                (b'"refs/tags/android-17.0.0_r1"', b'""', 'no AOSP default revision'),
                (b'"count": 1108', b'"count": 1108, "count": 1057',
                 "ambiguous: the key 'count' occurs twice")):
            changed = original.replace(old, new, 1)
            self.assertNotEqual(changed, original)
            path.write_bytes(changed)
            self.select(PINNED)
            self.refused(pattern)
        path.write_bytes(original)
        self.select(PINNED)
        self.assertEqual(base.load(root=self.root).revision('frameworks/base'), FRAMEWORK)
        with self.assertRaisesRegex(base.BaseSelectionError, 'pins no revision of build/release'):
            base.load(root=self.root).revision('build/release')

    def test_symbolic_links_are_refused(self):
        self.select(PINNED)
        moved = self.root / 'elsewhere.json'
        self.selection.rename(moved)
        self.selection.symlink_to(moved)
        self.refused('the base selection is missing or not a regular file')
        self.selection.unlink()
        moved.rename(self.selection)
        record = self.record(PINNED)
        record.rename(self.root / 'record.json')
        record.symlink_to(self.root / 'record.json')
        self.refused('the base record is missing or not a regular file')
        record.unlink()
        (self.root / 'record.json').rename(record)
        bases = self.root / 'upstream/bases'
        bases.rename(self.root / 'bases')
        bases.symlink_to(self.root / 'bases')
        self.refused('the selected record is not in upstream/bases')


class RepositorySelectionTests(unittest.TestCase):
    def test_the_repository_selects_the_pinned_base(self):
        selection = json.loads((ROOT / base.SELECTION).read_text())
        self.assertEqual(selection, {'schema': base.SCHEMA, 'release': PINNED,
                                     'record': PINNED_RECORD,
                                     'record_sha256': sha((ROOT / PINNED_RECORD).read_bytes())})
        found = base.selected()
        self.assertIs(found, base.selected())
        self.assertEqual((found.release, found.record, found.patches),
                         (PINNED, PINNED_RECORD, ROOT / PINNED_PATCHES))
        # The digest the sealed carry report and the ledger record for the pinned base.
        report = json.loads((ROOT / 'upstream/reports/2026081300-2026100600.json').read_text())
        ledger = json.loads((ROOT / 'upstream/ledger/frameworks-base.json').read_text())
        covered = {row['release']: row['record_sha256'] for row in ledger['bases']}
        self.assertEqual(found.record_sha256, report['base']['record_sha256'])
        self.assertEqual(found.record_sha256, covered[PINNED])
        self.assertEqual(dict(found.revisions),
                         {'frameworks/base': FRAMEWORK, 'system/sepolicy': POLICY})
        self.assertEqual((found.security_patch_level, found.project_count), ('2026-08-05', 1108))

    def test_the_tools_take_the_pinned_base_from_the_selection(self):
        import grapheneos_source as source
        import android_lifecycle as lifecycle
        import native_identity_writer as writer
        import native_principal_pins as pins
        import ordinary_app as p5
        import owner_policy as policy
        import package_installer_payload_sync as payload
        import package_verity as verity
        found = base.selected()
        held = (source.TAG, source.TAG_OBJECT, source.MANIFEST_COMMIT, source.MANIFEST_SHA256,
                source.PROJECT_COUNT, source.AOSP_DEFAULT_REVISION)
        self.assertEqual(held, SOURCE)
        self.assertEqual(held, (found.release, found.tag_object, found.manifest_commit,
                                found.manifest_sha256, found.project_count,
                                found.aosp_default_revision))
        self.assertEqual(source.SIGNERS_SHA256, found.allowed_signers_sha256)
        for module, name in ((pins, 'native-principal-pins'), (lifecycle, 'owner-lifecycle'),
                             (verity, 'package-verity'),
                             (payload, 'package-installer-payload-sync'),
                             (writer, 'native-identity-writer')):
            self.assertEqual((module.PROJECT, module.HEAD), ('frameworks/base', FRAMEWORK), name)
            self.assertEqual(module.PROFILE, ROOT / PINNED_PATCHES / (name + '.json'))
            self.assertEqual(module.PATCH, ROOT / PINNED_PATCHES / (name + '.patch'))
            self.assertEqual(module.PROFILE.parent, found.patches)
        self.assertEqual((policy.PROJECT, policy.HEAD), ('system/sepolicy', POLICY))
        self.assertEqual(p5.PLATFORM_PROFILES, ('aosp17', 'grapheneos-2026081300'))
        self.assertEqual(p5.expected_pm_permissions('grapheneos-2026081300'),
                         ['android.permission.OTHER_SENSORS'])

    def test_the_source_verifier_refuses_a_record_of_another_trust_input(self):
        other = dataclasses.replace(base.selected(), allowed_signers_sha256='0' * 64)
        spec = importlib.util.spec_from_file_location('grapheneos_source_other_trust',
                                                      ROOT / 'scripts/proof/grapheneos_source.py')
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(base, 'selected', return_value=other), \
                self.assertRaisesRegex(base.BaseSelectionError, 'another allowed signers input'):
            spec.loader.exec_module(module)

    def test_no_environment_or_option_selects_a_base(self):
        text = (ROOT / 'scripts/proof/grapheneos_base.py').read_text()
        for channel in ('import os', 'environ[', 'environ.get', 'getenv', 'argparse', 'sys.argv'):
            self.assertNotIn(channel, text)
        with mock.patch.dict(os.environ, {'ANDRIX_BASE': SECOND, 'ANDRIX_SELECTED_BASE': SECOND}):
            self.assertEqual(base.load().release, PINNED)


if __name__ == '__main__':
    unittest.main()
