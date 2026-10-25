# SPDX-License-Identifier: Apache-2.0
"""The post scan adapter's frozen historical predictions, source bindings and contrary controls.
Historical comparisons use exact validated predecessors, not an assumption that today's sources
still identify the old images. The default current source check must refuse that provenance.
Host prediction checks only, not a compiler run or Android evidence."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_lifecycle_post_scan as post_scan  # noqa: E402
import source_licensing  # noqa: E402

PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')
S = post_scan.SUBJECT


def base():
    return copy.deepcopy(post_scan.base_section())


def historical_readers(patch=None, deferral=None, recovery=None, diagnostic=None):
    """Validate the historical base before applying intentional historical fixture mutations."""
    read = source_licensing.predecessor_reader(post_scan.working_tree)
    data = {path: read(path) for path in (*post_scan.SOURCES, post_scan.PROFILE)}
    changed = {post_scan.PATCH: patch, post_scan.DEFERRAL: deferral, post_scan.RECOVERY: recovery,
               post_scan.DIAGNOSTIC: diagnostic}
    data.update({path: text.encode() for path, text in changed.items() if text is not None})
    return {'B2': data.__getitem__, 'B1': post_scan.b1.floor_bytes}


def historical_text(path):
    return historical_readers()['B2'](path).decode()


def patch_text():
    return historical_text(post_scan.PATCH)


class FrozenPredictionTests(unittest.TestCase):
    def test_the_frozen_historical_view_is_the_adapters_over_the_unchanged_base(self):
        self.assertEqual(post_scan.prediction_problems(readers=historical_readers()), [])
        frozen, section = post_scan.section(), post_scan.base_section()
        self.assertEqual(frozen['base'], {'section': 'b2_checkpoint_3a.guest_inputs',
                                          'sha256': post_scan.sha(post_scan.canonical(section))})
        self.assertEqual(frozen['checks'], ['deferred set', 'schema 3 rows'])
        self.assertEqual(sorted(frozen['reads']), sorted(section['inputs']))
        # The wrapper changes the two readings of the scanned wrong serial, adding the subject.
        self.assertEqual([(item['input'], item['reader'], item['image'], item['seeded'], item['added'])
                          for item in frozen['changes']],
                         [('reservation-wrong-serial', 'production', 'B2', [], [S]),
                          ('reservation-wrong-serial', 'floor', 'B1', [], [S])])
        for reader in post_scan.READERS:
            after = frozen['reads']['reservation-wrong-serial'][reader]
            before = section['reads']['reservation-wrong-serial'][reader]['schema 3 rows']
            self.assertEqual(after['deferred set'], [S])
            # Only the deferred names change: the fields, the unidentified mark, the holds and the
            # slot rows are the seeded view's.
            self.assertEqual(after['schema 3 rows'], dict(before, deferred=[S]))

    def test_the_seventy_base_readings_by_their_scan_branch(self):
        section = post_scan.base_section()
        branches = {}
        for name, (_, mapping) in section['inputs'].items():
            for reader in post_scan.READERS:
                reading = section['reads'][name][reader]
                outcome = reading['scan outcome'].get('subject')
                if mapping == 'lost':
                    branch = 'lost mapping, already deferred'
                    self.assertIn(S, reading['deferred set'])
                elif outcome == 'admitted':
                    branch = 'admitted'
                elif S in reading['deferred set']:
                    branch = 'refused, already deferred'
                else:
                    branch = 'refused, wrapper adds the subject'
                branches.setdefault(branch, []).append((name, reader))
        self.assertEqual({branch: len(items) for branch, items in branches.items()},
                         {'admitted': 14, 'refused, already deferred': 52, 'refused, wrapper adds the subject': 2,
                          'lost mapping, already deferred': 2})
        self.assertEqual(branches['refused, wrapper adds the subject'],
                         [('reservation-wrong-serial', 'production'), ('reservation-wrong-serial', 'floor')])

    def test_a_changed_frozen_reading_base_or_source_is_refused(self):
        predictions = post_scan.load_predictions()
        self.assertEqual(post_scan.prediction_problems(predictions, readers=historical_readers()), [])
        for change, expected in (
                (lambda value: value['b2_checkpoint_3b']['post_scan']['reads']['reservation']['floor'].update(
                    {'deferred set': [S]}), 'the frozen post scan reads differs'),
                (lambda value: value['b2_checkpoint_3b']['post_scan']['changes'].pop(),
                 'the frozen post scan changes differs'),
                (lambda value: value['b2_checkpoint_3b']['post_scan']['base'].update(sha256='0' * 64),
                 'the frozen post scan base differs'),
                (lambda value: value['b2_checkpoint_3b']['post_scan']['sources'].update(floor_revision='0' * 40),
                 'the frozen post scan sources differs'),
                (lambda value: value['b2_checkpoint_3b']['post_scan'].update(extra=1), 'other keys'),
                (lambda value: value['b2_checkpoint_3a']['guest_inputs']['reads']['lift-v1']['floor'][
                    'boot facts'].append('releasing 10148'), 'the frozen post scan base differs'),
                (lambda value: value.pop('b2_checkpoint_3b'), 'no frozen post scan predictions')):
            broken = copy.deepcopy(predictions)
            change(broken)
            with self.subTest(expected=expected):
                self.assertIn(expected, ' '.join(post_scan.prediction_problems(broken, readers=historical_readers())))


class DesignCaseTests(unittest.TestCase):
    """The four cases of the design, each at both readers: a valid serial gains nothing, a wrong
    serial with its code scanned gains exactly the subject, parked eligible code gains no scan
    deferral, and a reading already deferring the subject is unchanged."""

    def test_the_four_cases(self):
        section = base()
        for reader in post_scan.READERS:
            reads = {name: section['reads'][name][reader] for name in section['reads']}
            with self.subTest(reader=reader):
                valid = post_scan.adapt(reads['reservation'], 'scanned')
                self.assertEqual((valid['deferred set'], reads['reservation']['scan outcome']['subject']),
                                 ([], 'admitted'))
                wrong = post_scan.adapt(reads['reservation-wrong-serial'], 'scanned')
                self.assertEqual(wrong['deferred set'], [S])
                self.assertEqual(set(wrong['deferred set']) - set(reads['reservation-wrong-serial']['deferred set']),
                                 {S})
                self.assertEqual(post_scan.adapt(reads['eligible-v1'], 'parked')['deferred set'], [])
                # Parked code is never scanned, whatever the checks would answer.
                self.assertEqual(post_scan.adapt(reads['reservation-wrong-serial'], 'parked')['deferred set'], [])
                already = [name for name, reading in reads.items()
                           if S in reading['deferred set'] and 'subject' in reading['scan outcome']]
                # 52 in all: the floor also defers the subject of v2-beside-reservation and
                # mixed-suspend-backup, which the production reader admits.
                self.assertEqual(len(already), {'production': 25, 'floor': 27}[reader])
                for name in already:
                    for scan in ('scanned', 'parked'):
                        self.assertEqual(post_scan.adapt(reads[name], scan)['deferred set'],
                                         reads[name]['deferred set'], (name, scan))
                lost = reads['v2-slot-mapping-lost']
                self.assertEqual(post_scan.adapt(lost, 'unmapped')['deferred set'], lost['deferred set'])

    def test_a_guest_boot_keeps_its_other_checks(self):
        reading = base()['reads']['reservation-wrong-serial']['production']
        boot = post_scan.guest_boot(reading, 'scanned')
        self.assertEqual(set(boot), set(reading))
        for check in ('lifecycle', 'pin phase', 'scan outcome', 'boot facts'):
            self.assertEqual(boot[check], reading[check])
        self.assertEqual(boot['deferred set'], [S])

    def test_malformed_adapter_input_is_refused(self):
        reads = base()['reads']
        lost, mapped = reads['v2-slot-mapping-lost']['floor'], reads['v2-slot']['floor']
        torn = copy.deepcopy(mapped)
        torn['schema 3 rows']['deferred'] = []
        unordered = copy.deepcopy(reads['v2-beside-reservation']['production'])
        unordered['deferred set'] = unordered['schema 3 rows']['deferred'] = ['z.b', 'a.b']
        for reading, scan in ((mapped, 'unmapped'), (lost, 'scanned'), (lost, 'parked'), (mapped, 'installed'),
                              (torn, 'scanned'), (unordered, 'scanned'), (None, 'scanned')):
            with self.subTest(scan=scan), self.assertRaises(ValueError):
                post_scan.adapt(reading, scan)


class ContraryPredictionTests(unittest.TestCase):
    """The predictions the adapter must refuse: the unadapted seeded view of the wrong serial, the
    shortcut that every refusal defers, and the shortcut that every refusal is already seeded."""

    def setUp(self):
        self.base = base()
        self.extracted = post_scan.sources(readers=historical_readers())[1]

    def test_the_unadapted_empty_prediction_is_refused(self):
        def unadapted(reading, scan):
            return {'deferred set': reading['deferred set'], 'schema 3 rows': reading['schema 3 rows']}
        found = post_scan.control_problems(self.base, self.extracted, unadapted)
        self.assertEqual([line.split(':')[0] for line in found],
                         ['reservation-wrong-serial production scanned', 'reservation-wrong-serial floor scanned'])
        frozen = post_scan.load_predictions()
        reads = frozen['b2_checkpoint_3b']['post_scan']['reads']['reservation-wrong-serial']
        for reader in post_scan.READERS:
            reads[reader] = unadapted(self.base['reads']['reservation-wrong-serial'][reader], 'scanned')
        self.assertIn('the frozen post scan reads differs',
                      ' '.join(post_scan.prediction_problems(frozen, readers=historical_readers())))

    def test_the_all_refusals_defer_shortcut_is_refused(self):
        def shortcut(reading, scan):
            outcome = reading['scan outcome'].get('subject')
            names = set(reading['deferred set']) | ({S} if outcome not in (None, 'admitted') else set())
            ordered = post_scan.java_order(names)
            return {'deferred set': ordered, 'schema 3 rows': dict(reading['schema 3 rows'], deferred=ordered)}
        found = post_scan.control_problems(self.base, self.extracted, shortcut)
        # It defers a parked subject that no scan reaches.
        self.assertEqual([line.split(':')[0] for line in found],
                         ['reservation-wrong-serial production parked', 'reservation-wrong-serial floor parked'])

    def test_the_all_refusals_seeded_shortcut_is_refused(self):
        seeded = copy.deepcopy(self.base)
        for name, readings in seeded['reads'].items():
            for reading in readings.values():
                refused = reading['scan outcome'].get('subject') not in (None, 'admitted')
                if refused and S not in reading['deferred set']:
                    reading['deferred set'] = reading['schema 3 rows']['deferred'] = post_scan.java_order(
                        set(reading['deferred set']) | {S})
        # The readers' own seeded views contradict it exactly at the wrong serial.
        differing = sorted({name for name in seeded['reads'] for reader in post_scan.READERS
                            if seeded['reads'][name][reader] != self.base['reads'][name][reader]})
        self.assertEqual(differing, ['reservation-wrong-serial'])
        predictions = post_scan.load_predictions()
        predictions['b2_checkpoint_3a']['guest_inputs'] = seeded
        self.assertIn('the frozen post scan base differs',
                      ' '.join(post_scan.prediction_problems(predictions, readers=historical_readers())))


class CurrentSourceBindingTests(unittest.TestCase):
    def test_the_default_refuses_exactly_the_changed_historical_provenance(self):
        recorded, extracted = post_scan.sources()
        frozen = post_scan.section()['sources']
        current_files = {(image, row['path']): row['sha256']
                         for image, value in recorded['images'].items() for row in value['files']}
        frozen_files = {(image, row['path']): row['sha256']
                        for image, value in frozen['images'].items() for row in value['files']}
        self.assertEqual(set(current_files), set(frozen_files))
        self.assertEqual([key for key in current_files if current_files[key] != frozen_files[key]],
                         [('B2', post_scan.RECOVERY)])
        self.assertEqual((frozen_files['B2', post_scan.RECOVERY], current_files['B2', post_scan.RECOVERY]),
                         source_licensing.SOURCE_PAIRS[post_scan.RECOVERY])
        self.assertEqual(current_files['B2', post_scan.RECOVERY],
                         post_scan.sha(post_scan.working_tree(post_scan.RECOVERY)))
        self.assertEqual(recorded['profile']['path'], frozen['profile']['path'])
        self.assertEqual((frozen['profile']['sha256'], recorded['profile']['sha256']),
                         source_licensing.PROFILE_PAIRS[post_scan.PROFILE])
        self.assertEqual(recorded['profile']['sha256'], post_scan.sha(post_scan.working_tree(post_scan.PROFILE)))
        for key in ('candidate', 'floor_revision'):
            self.assertEqual(recorded[key], frozen[key])
        for image in ('B1', 'B2'):
            self.assertEqual(recorded['images'][image]['wrapper_lines'], frozen['images'][image]['wrapper_lines'])
        self.assertEqual(post_scan.control_problems(base(), extracted), [])
        self.assertEqual(post_scan.prediction_problems(),
                         ["the frozen post scan sources differs from the adapter's"])
        self.assertEqual(post_scan.prediction_problems(readers=historical_readers()), [])

    def test_unknown_current_changes_cannot_enter_the_historical_view(self):
        recovery = post_scan.working_tree(post_scan.RECOVERY)
        profile = post_scan.working_tree(post_scan.PROFILE)
        helper = 'owner/platform/framework/NativePrincipalPins.java'
        cases = [(post_scan.RECOVERY, changed, 'licensing source drift') for changed in (
            recovery + b'\n', b'// extra comment\n' + recovery,
            recovery.replace(b'GPL-3.0-or-later', b'GPL-3.0-only', 1),
            recovery.replace(b'deferredCopy.add(packageName);', b'deferredCopy.clear();', 1))]
        cases += [(post_scan.PROFILE, profile + b'\n', 'licensing profile drift'),
                  (helper, post_scan.working_tree(helper) + b'\n', 'licensing helper drift')]
        for path, changed, reason in cases:
            with self.subTest(path=path, digest=post_scan.sha(changed)):
                self.assertNotEqual(changed, post_scan.working_tree(path))

                def actual(source):
                    return changed if source == path else post_scan.working_tree(source)
                readers = {'B2': source_licensing.predecessor_reader(actual), 'B1': post_scan.b1.floor_bytes}
                self.assertEqual(post_scan.prediction_problems(readers=readers),
                                 ['post scan sources: %s: %s' % (reason, path)])

    def test_unmapped_source_comments_still_fail_the_frozen_byte_check(self):
        path = post_scan.DIAGNOSTIC
        self.assertNotIn(path, source_licensing.SOURCE_PAIRS)
        changed = b'// extra comment\n' + post_scan.working_tree(path)

        def actual(source):
            return changed if source == path else post_scan.working_tree(source)
        read = source_licensing.predecessor_reader(actual)
        self.assertEqual(read(path), changed)
        self.assertEqual(post_scan.prediction_problems(readers={'B2': read, 'B1': post_scan.b1.floor_bytes}),
                         ["the frozen post scan sources differs from the adapter's"])


class SourceBindingTests(unittest.TestCase):
    def test_both_historical_images_read_one_wrapper(self):
        recorded, extracted = post_scan.sources(readers=historical_readers())
        self.assertEqual(recorded, post_scan.section()['sources'])
        self.assertEqual(extracted['B1']['wrapper'], extracted['B2']['wrapper'])
        self.assertEqual(extracted['B2']['wrapper']['lines'], {'subject': 4432, 'binding': 4444, 'handler': 4241})
        steps = [('defer', 'scanned package', 'absolute'), ('throw', 'INTERNAL_ERROR_NATIVE_IDENTITY_DEFERRED')]
        self.assertEqual(extracted['B2']['wrapper']['subject'], steps)
        self.assertEqual(extracted['B2']['wrapper']['binding'], steps)
        self.assertEqual(extracted['B2']['wrapper']['handler'], steps[:1])
        files = {image: {row['path']: row['sha256'] for row in value['files']}
                 for image, value in recorded['images'].items()}
        self.assertEqual(files['B1'][post_scan.PATCH], post_scan.b1.FLOOR_SHA256[post_scan.PATCH])
        self.assertEqual(files['B2'][post_scan.PATCH],
                         json.loads(historical_text(post_scan.PROFILE))['patch_sha256'])
        # The images differ in their patch, by the boot literal, and in nothing the wrapper reads.
        self.assertNotEqual(files['B1'][post_scan.PATCH], files['B2'][post_scan.PATCH])
        for path in (post_scan.DEFERRAL, post_scan.RECOVERY, post_scan.DIAGNOSTIC):
            self.assertEqual(files['B1'][path], files['B2'][path])

    def test_each_changed_source_shape_is_refused_beside_its_control(self):
        text = patch_text()
        indent = '+' + ' ' * 20
        subject_defer = (indent + 'mPm.mSettings.deferNativePackage(pkgName, new File(parsedPackage.getPath()));\n'
                         + indent + 'throw PackageManagerException.ofInternalError("Native UID ownership'
                         ' requires recovery",\n')
        handler = '+                mPm.mSettings.deferNativePackage(packageName, result.scanFile);\n'
        self.assertEqual((text.count(subject_defer), text.count(handler)), (1, 1))
        fragment = historical_text(post_scan.DEFERRAL)
        recovery = historical_text(post_scan.RECOVERY)
        diagnostic = historical_text(post_scan.DIAGNOSTIC)
        cases = {
            'the subject check negation dropped': (dict(patch=text.replace(
                'if (!mPm.mSettings.nativeScanSubjectAllowedLPr(', 'if (mPm.mSettings.nativeScanSubjectAllowedLPr(')),
                'not all present once'),
            'another throw code': (dict(patch=text.replace(
                'recovery",\n+' + ' ' * 28 + 'PackageManagerException.INTERNAL_ERROR_NATIVE_IDENTITY_DEFERRED',
                'recovery",\n+' + ' ' * 28 + 'PackageManagerException.INTERNAL_ERROR_OTHERWISE', 1)), None),
            'another deferred path': (dict(patch=text.replace(
                'deferNativePackage(pkgName, new File(parsedPackage.getPath()));',
                'deferNativePackage(pkgName, parsedPackage.getPath());', 1)), 'statement of another shape'),
            'another deferred name': (dict(patch=text.replace(
                'deferNativePackage(packageName, result.scanFile);', 'deferNativePackage(name, result.scanFile);')),
                'statement of another shape'),
            # Lines are replaced, not removed, so every hunk keeps its counts.
            'the handler without its deferral': (dict(patch=text.replace(handler, '+\n')),
                                                 'failure handler of another shape'),
            'the handler without the flag': (dict(patch=text.replace(
                'if (nativeDeferred || mPm.mSettings.isNativePrincipalPackageLPr(packageName)) {',
                'if (mPm.mSettings.isNativePrincipalPackageLPr(packageName)) {')), 'not all present once'),
            'a deferral that marks unidentified code': (dict(deferral=fragment.replace(
                'if (codePath != null && !codePath.isAbsolute())', 'if (codePath != null)')),
                'deferral fragment of another shape'),
            'a defer that keeps the name out': (dict(recovery=recovery.replace(
                '            deferredCopy.add(packageName);\n', '')), 'defer of another shape'),
            'a diagnostic reading more of the view': (dict(diagnostic=diagnostic.replace(
                'recovery.hasUnidentifiedCode()', 'recovery.hasUnresolvedHolds()')),
                'reads the recovery view otherwise'),
        }
        for name, (change, expected) in cases.items():
            with self.subTest(case=name):
                found = ' '.join(post_scan.prediction_problems(readers=historical_readers(**change)))
                if expected is None:
                    # A throw without the native deferral code is read, then refused by the control;
                    # the changed patch is also no longer the one its profile pins.
                    self.assertRaisesRegex(ValueError, 'outside this control', post_scan.control,
                                           base()['reads']['reservation-wrong-serial']['production'], 'scanned',
                                           post_scan.image_sources(historical_readers(**change)['B2']))
                    self.assertIn('the native principal patch differs from its profile', found)
                else:
                    self.assertIn(expected, found)
        # The control: the exact validated historical texts pass.
        self.assertEqual(post_scan.prediction_problems(readers=historical_readers(
            patch=text, deferral=fragment, recovery=recovery, diagnostic=diagnostic)), [])

    def test_the_handler_alone_still_defers(self):
        """With the subject block's own deferral removed, the failure handler still defers the
        scanned subject: the extracted control reads the handler, it does not assume the wrapper."""
        text = patch_text().replace(
            '+                    mPm.mSettings.deferNativePackage(pkgName, new File(parsedPackage.getPath()));\n'
            '+                    throw PackageManagerException.ofInternalError("Native UID ownership', '+\n'
            '+                    throw PackageManagerException.ofInternalError("Native UID ownership', 1)
        self.assertNotEqual(text, patch_text())
        extracted = post_scan.image_sources(historical_readers(patch=text)['B2'])
        self.assertEqual(extracted['wrapper']['subject'], [('throw', 'INTERNAL_ERROR_NATIVE_IDENTITY_DEFERRED')])
        reading = base()['reads']['reservation-wrong-serial']['production']
        self.assertEqual(post_scan.control(reading, 'scanned', extracted), [S])
        self.assertEqual(post_scan.control(reading, 'parked', extracted), [])

    def test_the_candidate_has_the_wrapper_at_its_recorded_lines(self):
        if not PINNED:
            self.skipTest('NOT RUN: ANDRIX_PINNED_FRAMEWORK does not name the pinned framework copies')
        self.assertEqual(post_scan.candidate_problems(PINNED), [])
        recorded = copy.deepcopy(post_scan.section()['sources'])
        recorded['images']['B2']['wrapper_lines']['subject'] += 1
        self.assertIn('line 4433 is not the subject block', ' '.join(post_scan.candidate_problems(PINNED, recorded)))


if __name__ == '__main__':
    unittest.main()
