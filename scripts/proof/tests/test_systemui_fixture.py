# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import tempfile
import unittest

from scripts.proof.systemui_fixture import (
    BP, CLOCK, DESCRIPTION, MODULE, change_blueprint, change_clock, make_variants,
    prepare, sha,
)

BLUEPRINT = MODULE + '''    platform_apis: true,
    certificate: "platform",
    privileged: true,
    system_ext_specific: true,
}
'''
CLOCK_TEXT = '''class Clock {
    void updateClock() {
        CharSequence smallTime = getSmallTime();
        setText(smallTime);
        setContentDescription(mContentDescriptionFormat.format(mCalendar.getTime()));
    }
    private CharSequence getSmallTime() {
        return "12:34";
    }
    void demo() {
        setText(getSmallTime());
        setContentDescription(mContentDescriptionFormat.format(mCalendar.getTime()));
    }
}
'''


class SystemUiFixtureTests(unittest.TestCase):
    def test_order_and_versions(self):
        variants = make_variants(BLUEPRINT, CLOCK_TEXT, 37)
        self.assertEqual([(v['label'], v['version']) for v in variants],
                         [('A', 38), ('R', 39), ('B', 40), ('C', 41)])

    def test_manifest_authority_fields_unchanged(self):
        for variant in make_variants(BLUEPRINT, CLOCK_TEXT, 37):
            text = variant['sources'][BP]
            self.assertEqual(text.count('aaptflags:'), 1)
            self.assertIn('"--version-code", "'+str(variant['version'])+'"', text)
            for field in ['certificate: "platform"', 'privileged: true',
                          'system_ext_specific: true', 'platform_apis: true']:
                self.assertIn(field, text)

    def test_restore_is_original_clock(self):
        variants = make_variants(BLUEPRINT, CLOCK_TEXT, 37)
        self.assertEqual(variants[1]['sources'][CLOCK], CLOCK_TEXT)
        self.assertEqual(variants[3]['sources'][CLOCK], CLOCK_TEXT)
        self.assertNotIn('Clock.java', variants[1]['patch'])
        self.assertNotIn('Clock.java', variants[3]['patch'])

    def test_marker_and_bad_have_both_visual_and_description_sites(self):
        marker = change_clock(CLOCK_TEXT, 'marker')
        bad = change_clock(CLOCK_TEXT, 'bad')
        for text in [marker, bad]:
            self.assertEqual(text.count('andrixWorkshopTime('), 5)
            self.assertEqual(text.count('setContentDescription(andrixWorkshopTime('), 2)
            self.assertIn('setText(andrixWorkshopTime(getSmallTime()))', text)
            self.assertIn('return "12:34";', text)
        self.assertIn('TextUtils.concat(time, " WS-A")', marker)
        self.assertIn('return "WS-B BAD";', bad)
        self.assertNotIn('throw ', bad)

    def test_missing_or_duplicated_clock_sites_refused(self):
        for text in [CLOCK_TEXT.replace(DESCRIPTION, '', 1), CLOCK_TEXT+CLOCK_TEXT]:
            with self.assertRaises(ValueError):
                change_clock(text, 'marker')
        with self.assertRaises(ValueError):
            change_clock(change_clock(CLOCK_TEXT, 'marker'), 'restore')

    def test_existing_aaptflags_and_changed_target_refused(self):
        for text in [BLUEPRINT.replace(MODULE, MODULE+'    aaptflags: [],\n'),
                     BLUEPRINT+BLUEPRINT,
                     BLUEPRINT.replace('certificate: "platform"', 'certificate: "other"')]:
            with self.assertRaises(ValueError):
                change_blueprint(text, 38)

    def test_version_bounds(self):
        for baseline in [0, -1, 0x7fffffff-3, 0x80000000]:
            with self.assertRaises(ValueError):
                make_variants(BLUEPRINT, CLOCK_TEXT, baseline)
        self.assertEqual(make_variants(BLUEPRINT, CLOCK_TEXT, 0x7fffffff-4)[-1]['version'],
                         0x7fffffff)

    def test_unknown_mode_refused(self):
        with self.assertRaises(ValueError):
            change_clock(CLOCK_TEXT, 'crash')

    def source(self, base):
        source = base/'source'
        for name, text in [(BP, BLUEPRINT), (CLOCK, CLOCK_TEXT)]:
            path = source/'frameworks/base'/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return source

    def test_preparation_does_not_modify_source(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            source = self.source(base)
            report = prepare(source, base/'prepared', sha(BLUEPRINT.encode()),
                             sha(CLOCK_TEXT.encode()), 37)
            self.assertFalse(report['source_modified'])
            self.assertFalse(report['component_built'])
            self.assertFalse(report['signing_or_installation_performed'])
            self.assertEqual((source/'frameworks/base'/BP).read_text(), BLUEPRINT)
            self.assertEqual((source/'frameworks/base'/CLOCK).read_text(), CLOCK_TEXT)
            self.assertTrue((base/'prepared/A/framework.patch').exists())

    def test_source_hash_refused_before_output_creation(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            source = self.source(base)
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                prepare(source, base/'prepared', '0'*64, sha(CLOCK_TEXT.encode()), 37)
            self.assertFalse((base/'prepared').exists())

    def test_no_overwrite_and_no_output_inside_source(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            source = self.source(base)
            existing = base/'prepared'
            existing.mkdir()
            for output in [existing, source/'prepared']:
                with self.assertRaises(ValueError):
                    prepare(source, output, sha(BLUEPRINT.encode()), sha(CLOCK_TEXT.encode()), 37)


if __name__ == '__main__':
    unittest.main()
