# SPDX-License-Identifier: Apache-2.0
"""Pure checks of the per phase dump assessment of the reader step's guest phases: every host
prediction passes at its own values and at a guest's, and every contrary form fails, each beside
its passing control. The dumps here are rendered from the documented schema alone."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('b2_dump_assess', Path(__file__).with_name('b2_dump_assess.py'))
assess = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assess)
ROOT = Path(__file__).resolve().parents[2]
PREDICTIONS = json.loads((ROOT / 'scripts/proof/native_lifecycle_record_predictions.json').read_text())
BASE = PREDICTIONS['b2_checkpoint_3a']['guest_inputs']
POST = PREDICTIONS['b2_checkpoint_3b']['post_scan']['reads']
SUBJECT = 'dev.andrix.proof.principalclosed'
IMAGES = {'production': 'B2', 'floor': 'B1'}
SCHEMAS = {'B2': 3, 'B1': 2}
# The host predictions' app IDs, a future guest's, and a guest whose second app ID sorts first.
HOST = {10148: 10148, 10149: 10149}
FUTURE = {10148: 10147, 10149: 11147}
REVERSED = {10148: 12000, 10149: 11000}
SEARCH = 10000
ORDER = ('live_settings', 'authority', 'counter_known', 'cached_header', 'cached_enumeration_complete',
         'creation_ready', 'allocator_search_start', 'unidentified_code')


def b64(text):
    return base64.b64encode(text.encode()).decode()


def render(expected, schema):
    """The diagnostic a prediction describes, from the README's schemas: header, the eight scalars
    in order, the counts, the hold rows, on schema 3 the slot rows, then the deferred names."""
    lines = ['andrix-native-identities-v%d' % schema] + ['%s=%s' % (name, expected['fields'][name]) for name in ORDER]
    lines.append('deferred_count=%d' % len(expected['deferred']))
    if schema == 3:
        lines.append('slot_count=%d' % len(expected['holds']))
    lines += ['hold=%d\t%s\t%s\t%s\t%s' % (app, status, str(pinned).lower(), kind, b64(mapping))
              for app, status, pinned, kind, mapping in expected['holds']]
    if schema == 3:
        lines += ['slot=%d\t%s\t%s\t%s' % tuple(row) for row in expected['slots']]
    lines += ['deferred=' + b64(name) for name in expected['deferred']]
    return '\n'.join(lines) + '\n'


def phase(image, expected):
    return {'image': image, 'schema': SCHEMAS[image], 'dump_prediction': expected, 'phase': 'c1'}


def planned(name, reader, ids=HOST, post=False):
    rows = (POST[name][reader] if post else BASE['reads'][name][reader])['schema 3 rows']
    image = IMAGES[reader]
    return image, assess.expectation(rows, image, SEARCH, ids)


class ExactPredictionTests(unittest.TestCase):
    def test_every_prediction_passes_at_its_values_and_a_guests(self):
        count = 0
        for name in BASE['reads']:
            for reader in IMAGES:
                for post in (False, True):
                    for ids in (HOST, FUTURE, REVERSED):
                        image, expected = planned(name, reader, ids, post)
                        result = assess.assess_phase_dump(render(expected, SCHEMAS[image]), phase(image, expected))
                        with self.subTest(name=name, reader=reader, post=post, ids=ids):
                            self.assertEqual((result['outcome'], result['problems']), ('match', []))
                            self.assertTrue(result['available'] and result['matches'])
                            self.assertFalse(result['authority'])
                        count += 1
        self.assertEqual(count, 35 * 2 * 2 * 3)

    def test_a_guests_values_order_its_holds(self):
        image, expected = planned('v2-beside-reservation', 'production', REVERSED)
        self.assertEqual([row[0] for row in expected['holds']], [11000, 12000])
        self.assertEqual([row[0] for row in expected['slots']], [11000, 12000])
        self.assertEqual(expected['slots'][0], [11000, '2', 'ELIGIBLE', 'true'])
        self.assertEqual(expected['fields']['allocator_search_start'], str(SEARCH))
        # Every app ID the rows name must have the guest's value.
        with self.assertRaises(ValueError):
            assess.expectation(BASE['reads']['v2-beside-reservation']['production']['schema 3 rows'], 'B2', SEARCH,
                               {10148: 10147})

    def test_the_missing_store(self):
        for image in SCHEMAS:
            expected = assess.missing_store(image, SEARCH)
            text = render(expected, SCHEMAS[image])
            self.assertEqual(assess.assess_phase_dump(text, phase(image, expected))['outcome'], 'match')
            self.assertEqual(expected['holds'], [])
            self.assertEqual(expected['deferred'], [])
        self.assertEqual(assess.missing_store('B2', SEARCH)['slots'], [])
        self.assertNotIn('slots', assess.missing_store('B1', SEARCH))

    def test_the_post_scan_view_and_the_unadapted_prediction(self):
        for reader, image in IMAGES.items():
            _, seeded = planned('reservation-wrong-serial', reader)
            _, post = planned('reservation-wrong-serial', reader, post=True)
            text = render(post, SCHEMAS[image])
            self.assertEqual(assess.assess_phase_dump(text, phase(image, post))['outcome'], 'match')
            # The unadapted empty prediction refuses the post scan dump at its deferred names alone.
            result = assess.assess_phase_dump(text, phase(image, seeded))
            self.assertEqual(result['outcome'], 'mismatch')
            self.assertEqual(result['problems'], ['deferred %r, not []' % [SUBJECT]])


class ContraryFormTests(unittest.TestCase):
    """Each contrary form fails, beside the passing control it was made from."""

    def setUp(self):
        self.image, self.expected = planned('v2-beside-reservation', 'production', FUTURE)
        self.text = render(self.expected, 3)
        self.assertEqual(assess.assess_phase_dump(self.text, phase('B2', self.expected))['outcome'], 'match')

    def outcome(self, text, image='B2', expected=None):
        return assess.assess_phase_dump(text, phase(image, self.expected if expected is None else expected))

    def test_the_other_images_schema(self):
        _, floor = planned('v2-beside-reservation', 'floor', FUTURE)
        floor_text = render(floor, 2)
        self.assertEqual(self.outcome(floor_text, 'B1', floor)['outcome'], 'match')
        # B2 refuses the schema 2 dump, B1 the schema 3 one, even with the right rows.
        refused = self.outcome(render(dict(floor), 2))
        self.assertEqual((refused['outcome'], refused['observed_schema']), ('wrong-schema', 2))
        self.assertFalse(refused['matches'] or refused['available'])
        three = dict(floor, slots=[[row[0], 'not-reported', 'not-reported', 'not-reported'] for row in floor['holds']])
        self.assertEqual(self.outcome(render(three, 3), 'B1', floor)['outcome'], 'wrong-schema')
        # A historical version 1 dump names no deferred set and is refused on both images.
        version_1 = '\n'.join(['andrix-native-identities-v1'] + render(floor, 2).splitlines()[1:9]) + '\n'
        for image, expected in (('B2', self.expected), ('B1', floor)):
            self.assertEqual(self.outcome(version_1, image, expected)['outcome'], 'wrong-schema')
        # A plan whose image and schema disagree, or another image, raises.
        for plan in ({'image': 'B2', 'schema': 2, 'dump_prediction': self.expected},
                     {'image': 'B1', 'schema': 3, 'dump_prediction': floor},
                     {'image': 'B3', 'schema': 3, 'dump_prediction': self.expected},
                     {'image': 'B2', 'schema': True, 'dump_prediction': self.expected},
                     {'image': 'B2', 'dump_prediction': self.expected}):
            named = {key: value for key, value in plan.items() if key != 'dump_prediction'}
            with self.subTest(plan=named), self.assertRaises(ValueError):
                assess.assess_phase_dump(self.text, plan)
        # A B1 prediction with slot rows, or a B2 one without them, raises: B1 requires none.
        with self.assertRaises(ValueError):
            assess.assess_phase_dump(floor_text, phase('B1', dict(floor, slots=[])))
        with self.assertRaises(ValueError):
            assess.assess_phase_dump(self.text, phase('B2', {k: v for k, v in self.expected.items() if k != 'slots'}))

    def test_slot_rows(self):
        lines = self.text.splitlines(keepends=True)
        slot = [index for index, line in enumerate(lines) if line.startswith('slot=') and '\t2\t' in line][0]
        suppressed = ''.join(lines[:slot] + lines[slot + 1:])
        recounted = suppressed.replace('slot_count=2', 'slot_count=1')
        extra = ''.join(lines[:slot + 1] + ['slot=19999\t2\tELIGIBLE\ttrue\n'] + lines[slot + 1:])
        for name, text in (('suppressed', suppressed), ('suppressed and recounted', recounted), ('extra', extra),
                           ('duplicated', ''.join(lines[:slot + 1] + lines[slot:]))):
            with self.subTest(name=name):
                self.assertEqual(self.outcome(text)['outcome'], 'unavailable')
        for name, old, new in (('version', '\t2\tELIGIBLE\ttrue', '\t1\tELIGIBLE\ttrue'),
                               ('lifecycle', '\t2\tELIGIBLE\ttrue', '\t2\tRETIRING\ttrue'),
                               ('suspension', '\t2\tELIGIBLE\ttrue', '\t2\tELIGIBLE\tfalse'),
                               ('not reported for a valid lifecycle', '\t2\tELIGIBLE\ttrue',
                                '\tnot-reported\tnot-reported\tnot-reported')):
            with self.subTest(name=name):
                result = self.outcome(self.text.replace(old, new))
                self.assertEqual(result['outcome'], 'mismatch')
                self.assertTrue(result['problems'][0].startswith('slots '))

    def test_counts_duplicates_and_types(self):
        hold = [line for line in self.text.splitlines(keepends=True) if line.startswith('hold=')][0]
        deferred = [line for line in self.text.splitlines(keepends=True) if line.startswith('deferred=')][0]
        for name, text in (('deferred count', self.text.replace('deferred_count=1', 'deferred_count=2')),
                           ('slot count', self.text.replace('slot_count=2', 'slot_count=3')),
                           ('duplicate hold', self.text.replace(hold, hold + hold)),
                           ('duplicate name', self.text.replace(deferred, deferred + deferred)),
                           ('duplicate scalar', self.text.replace('authority=not-reported\n',
                                                                  'authority=not-reported\nauthority=not-reported\n')),
                           ('a Boolean of another form',
                            self.text.replace('creation_ready=true', 'creation_ready=True')),
                           ('a pin of another form', self.text.replace('\tMISSING\ttrue\t', '\tMISSING\t1\t')),
                           ('a count of another form', self.text.replace('deferred_count=1', 'deferred_count=01'))):
            with self.subTest(name=name):
                self.assertEqual(self.outcome(text)['outcome'], 'unavailable')
        # Typed predictions: a pin as text, an app ID as a Boolean or text, a scalar as a Boolean.
        for change in (lambda value: value['holds'][0].__setitem__(2, 'true'),
                       lambda value: value['holds'][0].__setitem__(0, True),
                       lambda value: value['holds'][0].__setitem__(0, '10147'),
                       lambda value: value['slots'][0].__setitem__(0, '10147'),
                       lambda value: value['fields'].__setitem__('counter_known', True),
                       lambda value: value['fields'].__setitem__('allocator_search_start', '010000'),
                       lambda value: value['fields'].pop('allocator_search_start'),
                       lambda value: value['deferred'].append(value['deferred'][0]),
                       lambda value: value.update(extra=[])):
            broken = copy.deepcopy(self.expected)
            change(broken)
            with self.subTest(change=change), self.assertRaises(ValueError):
                assess.assess_phase_dump(self.text, phase('B2', broken))

    def test_every_scalar_hold_and_name_is_compared(self):
        for name, old, new in (('the search start', 'allocator_search_start=10000', 'allocator_search_start=10001'),
                               ('the counter', 'counter_known=true', 'counter_known=false'),
                               ('the header', 'cached_header=VALID', 'cached_header=DAMAGED'),
                               ('unidentified code', 'unidentified_code=true', 'unidentified_code=false')):
            with self.subTest(name=name):
                result = self.outcome(self.text.replace(old, new))
                self.assertEqual(result['outcome'], 'mismatch')
                self.assertTrue(result['problems'][0].startswith('field '))
        other = b64('dev.andrix.proof.lifecycleother')
        for name, text in (('another pin', self.text.replace('\tMISSING\ttrue\t', '\tMISSING\tfalse\t')),
                           ('another name', self.text.replace('deferred=' + other, 'deferred=' + b64(SUBJECT)))):
            with self.subTest(name=name):
                self.assertEqual(self.outcome(text)['outcome'], 'mismatch')

    def test_envelopes_and_unavailable_captures_are_never_an_empty_store(self):
        for image in SCHEMAS:
            empty = assess.missing_store(image, SEARCH)
            control = render(empty, SCHEMAS[image])
            self.assertEqual(self.outcome(control, image, empty)['outcome'], 'match')
            for text in ('andrix-native-identities-v2\nlive_settings=false\n',
                         'andrix-native-identities-v2\nobserver_available=false\n',
                         'andrix-native-identities-v3\nobserver_available=false\n',
                         'andrix-native-identities-v3\nlive_settings=false\n',
                         'andrix-native-identities-v4\n' + control.split('\n', 1)[1], '', 'Permission Denial\n',
                         control[:-1], control.replace('\n', '\r\n'), control + 'deferred=' + b64('a.b') + '\n',
                         control.replace('not-reported', 'not-report\u00e9d'), control.replace('\n', '\x85', 1),
                         None):
                with self.subTest(image=image, text=text if text is None else text[:40]):
                    result = self.outcome(text, image, empty)
                    self.assertEqual(result['outcome'], 'unavailable')
                    self.assertFalse(result['matches'] or result['available'])
                    self.assertEqual(result['raw'], text)
                    self.assertTrue(result['error'])
        with self.assertRaises(ValueError):
            assess.assess_phase_dump(self.text.encode(), phase('B2', self.expected))

    def test_a_dump_cut_at_the_dumpsys_timeout_is_unavailable_never_a_match(self):
        # The missing store's complete dump matches; the same dump with dumpsys's timeout line after it
        # (the service outlived the bound) is unavailable with that reason, never a match.
        for image in SCHEMAS:
            empty = assess.missing_store(image, SEARCH)
            control = render(empty, SCHEMAS[image])
            self.assertEqual(self.outcome(control, image, empty)['outcome'], 'match')
            marker = "\n*** SERVICE 'package' DUMP TIMEOUT (30000ms) EXPIRED ***\n\n"
            result = self.outcome(control + marker + marker, image, empty)
            self.assertEqual((result['outcome'], result['matches'], result['available']), ('unavailable', False, False))
            self.assertEqual(result['problems'], ["unavailable dump: reservation dump unavailable: dumpsys timed out after "
                                                  "30000 ms in service 'package', the dump is cut"])

    def test_a_capture_is_gated_before_it_is_read(self):
        # The whole capture passes the observers' completeness gate first: a complete dump with
        # dumpsys's service error on stderr, a nonzero exit or an unfinished transport is unavailable
        # with the gate's reason and never read; a complete capture is assessed as its text.
        import subprocess
        for image in SCHEMAS:
            empty = assess.missing_store(image, SEARCH)
            control = render(empty, SCHEMAS[image])
            plan = phase(image, empty)
            self.assertEqual(assess.assess_phase_capture(subprocess.CompletedProcess(['adb'], 0, control.encode(), b''), plan)['outcome'],
                             'match')
            record = {'argv': ['dumpsys', '-t', '30', 'package', '--andrix-native-identities'], 'stdout': control, 'stderr': '',
                      'exit_code': 0, 'complete': True}
            self.assertEqual(assess.assess_phase_capture(record, plan)['outcome'], 'match')
            for change, reason in (({'stderr': "Error with service 'package' while dumping: FAILED_TRANSACTION\n"},
                                    "dumpsys reported service 'package' failing while dumping: FAILED_TRANSACTION"),
                                   ({'exit_code': 1}, 'dumpsys exited 1'),
                                   ({'complete': False}, 'its transport did not complete with a result (retired, timed out or stopped)')):
                result = assess.assess_phase_capture(dict(record, **change), plan)
                self.assertEqual((result['outcome'], result['matches'], result['available'], result['raw']), ('unavailable', False, False, None))
                self.assertEqual(result['problems'], ['unavailable dump: native dump unavailable: ' + reason])

    def test_a_swapped_layout_fails_where_its_dump_differs(self):
        """Each input against another input's prediction of the same image. Inputs whose dumps are
        equal cannot be told apart by the dump; their store bytes tell them apart."""
        names = list(BASE['reads'])
        for reader, image in IMAGES.items():
            texts = {name: render(planned(name, reader, FUTURE, True)[1], SCHEMAS[image]) for name in names}
            classes = {}
            for name in names:
                classes.setdefault(texts[name], []).append(name)
            swapped = 0
            for name in names:
                donors = [other for other in names if texts[other] != texts[name]]
                donor = donors[(names.index(name) * 7) % len(donors)]
                result = assess.assess_phase_dump(texts[name], phase(image, planned(donor, reader, FUTURE, True)[1]))
                with self.subTest(reader=reader, name=name, donor=donor):
                    self.assertEqual(result['outcome'], 'mismatch')
                swapped += 1
            self.assertEqual(swapped, 35)
            with self.subTest(reader=reader):
                # B2's dumps tell 19 classes of the 35 apart, the suspended version 2 bodies of the
                # subject the largest; B1's tell 11, every version 2 or later frame of the subject
                # one unsupported footprint.
                largest = max(classes.values(), key=len)
                self.assertIn('v2-slot', largest)
                self.assertEqual((len(classes), len(largest)), {'B2': (19, 8), 'B1': (11, 23)}[image])


if __name__ == '__main__':
    unittest.main()
