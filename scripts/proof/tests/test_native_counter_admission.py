# SPDX-License-Identifier: Apache-2.0
"""Native counter admission: pure source guards, the exact correction surface, the comparison
rules across 0018a1d, 89491b9 and the corrected sources, probe classification and the runner's
refusals and evidence retention. The guarded JVM matrix is only in the runner, which is NOT RUN
without the required resource bounds and a short enough work path. These tests start no compiler
or JVM. Not Android runtime proof."""
from pathlib import Path
import contextlib
import io
import json
import re
import types
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_counter_admission as runner  # noqa: E402
from test_native_creation_history import (  # noqa: E402
    B1_LIVING, fake_tools, frozen_matches, historical_constants, living_code_broken, living_constants_changed,
    pin_data, synthetic_settings)

COUNTER = 'scripts/proof/native_counter_admission.py'
# The archive's names of the 24bfb6a code and data it copies, by their 24bfb6a names.
COPIED = {'archived_normalized': 'normalized', 'archived_code': 'code', 'archived_store_problems': 'store_problems',
          'archived_b1_test_problems': 'b1_test_problems', 'archived_observations': 'observations',
          'archived_compare_observations': 'compare_observations', 'archived_probe_facts': 'probe_facts',
          'archived_probe_verdict': 'probe_verdict', 'ARCHIVED_RULE_NEW': 'RULE_NEW', 'ARCHIVED_RULE_OLD': 'RULE_OLD',
          'ARCHIVED_HELPER': 'HELPER', 'ARCHIVED_B1_NEW': 'B1_NEW', 'ARCHIVED_B1_OLD': 'B1_OLD',
          'ARCHIVED_HOLDS': '_HOLDS', 'ARCHIVED_THROWN': '_THROWN',
          'archived_strip_java_comments': 'strip_java_comments'}


def scratch(test):
    """A fresh directory below the caller's TMPDIR, removed after the test."""
    directory = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, directory)
    return directory


def balanced(text):
    """Whether braces and parentheses of Java code, comments and literals aside, nest. A sanity
    check of generated mutant text only, never a compilation."""
    code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', runner.b1.strip_java_comments(text))
    depth = {'{': 0, '(': 0}
    for c in code:
        if c in '{(':
            depth[c] += 1
        elif c in '})':
            depth['{' if c == '}' else '('] -= 1
            if min(depth.values()) < 0:
                return False
    return depth == {'{': 0, '(': 0}


def observed(label, fmt, facts, ready, restorable):
    return 'OBSERVE\t%s\t%s\t%s\tready=%s\trestorable=%s' % (
        label, fmt, facts, str(ready).lower(), str(restorable).lower())


class CounterAdmissionSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_mutants_anchor_once_and_predictions_are_consistent(self):
        sources = runner.mutant_sources()
        self.assertEqual(set(sources), set(runner.MUTANTS))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        names = set(runner.FOCUSED_NAMES)
        self.assertEqual((len(runner.FOCUSED_NAMES), len(names), predictions['focused_cases']), (35, 35, 35))
        self.assertEqual(len(runner.MUTANTS), 15)
        self.assertEqual(set(predictions['mutants_caught_at_least']), set(runner.MUTANTS))
        for name, expected in predictions['mutants_caught_at_least'].items():
            self.assertTrue(expected and set(expected) <= names, name)
        # Each mutant's expectation names living cases of the current suite alone. The archived
        # baselines' failures are the pinned predictions' own, so a later package that changes the
        # living suite restates its mutants without touching them.
        self.assertEqual(predictions['fix']['focused_failures'], [])
        for name, (path, text) in sources.items():
            self.assertNotEqual(text, (ROOT / path).read_text(), name)
            self.assertTrue(balanced(text), name)
        self.assertTrue(balanced((ROOT / runner.STORE).read_text()))

    def test_every_case_and_observation_label_is_in_the_suite_source(self):
        # Living: the current suite names each living case once, with the observation labels the
        # living predictions list.
        source = (ROOT / runner.PLATFORM / (runner.TEST + '.java')).read_text()
        self.assertTrue(balanced(source))
        for name in runner.FOCUSED_NAMES:
            self.assertEqual(source.count('"%s"' % name), 1, name)
        predictions = json.loads(runner.PREDICTIONS.read_text())
        blocked, unchanged = set(predictions['blocked_observations']), set(predictions['unchanged_observations'])
        self.assertFalse(blocked & unchanged)
        labels = set(re.findall(r'"([a-z0-9]+(?:-[a-z0-9]+)+)"', source)) - {'counter-admission'}
        self.assertEqual(labels, blocked | unchanged)
        # Archived: the pinned 24bfb6a suite names each frozen case once, and the observation labels
        # the archived sides compare are exactly its own, as its pinned predictions list them.
        pinned = runner.b1.archived_predictions('counter')
        archived = runner.b1.pinned_bytes(runner.CORRECTED, runner.b1.ARCHIVED_PLATFORM + runner.ARCHIVED_TEST
                                          + '.java').decode()
        self.assertTrue(balanced(archived))
        for name in runner.ARCHIVED_FOCUSED_NAMES:
            self.assertEqual(archived.count('"%s"' % name), 1, name)
        blocked, unchanged = set(pinned['blocked_observations']), set(pinned['unchanged_observations'])
        self.assertFalse(blocked & unchanged)
        labels = set(re.findall(r'"([a-z0-9]+(?:-[a-z0-9]+)+)"', archived)) - {'counter-admission'}
        self.assertEqual(labels, blocked | unchanged)
        self.assertEqual(runner.archived_suite_problems(), [])
        # The runner's own probe list matches the pinned predictions.
        self.assertEqual(set(pinned['probes']), set(runner.PROBES))
        # A frozen case list that the pinned suite and predictions no longer state is refused.
        with mock.patch.object(runner, 'ARCHIVED_FOCUSED_NAMES', runner.ARCHIVED_FOCUSED_NAMES[1:]):
            self.assertIn('archived focused cases differ from the pinned prediction', runner.archived_suite_problems())
        with mock.patch.object(runner, 'ARCHIVED_FOCUSED_NAMES', runner.ARCHIVED_FOCUSED_NAMES + ('absent',)):
            self.assertIn('archived focused case not named once in its pinned source: absent',
                          runner.archived_suite_problems())
        # The archived baselines' failures are the pinned predictions' own, whatever the living file says.
        with mock.patch.object(runner, 'PREDICTIONS', scratch(self) / 'absent.json'):
            self.assertEqual(runner.archived_suite_problems(), [])
        failures = pinned['baselines'][runner.BASE_0018]['focused_failures']
        self.assertEqual(failures, pinned['baselines'][runner.BASE_8949]['focused_failures'])
        self.assertEqual(len(failures), 25)
        self.assertTrue(set(failures) <= set(runner.ARCHIVED_FOCUSED_NAMES))
        self.assertEqual(pinned['fix']['focused_failures'], [])

    def test_store_differs_from_89491_only_by_the_rule(self):
        # Archived: the pinned 24bfb6a Store, which carries the correction, against 89491b9's.
        base = runner.b1.pinned_bytes(runner.BASE_8949, runner.b1.ARCHIVED_STORE).decode()
        current = runner.b1.pinned_bytes(runner.CORRECTED, runner.b1.ARCHIVED_STORE).decode()
        self.assertEqual(runner.archived_store_problems(current, base), [])
        # Comments are free; code is not.
        self.assertEqual(runner.archived_store_problems(current.replace(
            '    // Whether this decoded slot copy names', '    // Whether the decoded slot copy names'), base), [])
        for old, new in (('if (user.id > counter) return true;', 'if (user.id >= counter) return true;'),
                         ('blocked = header.status != Status.VALID;', 'blocked = header.status == Status.MISSING;'),
                         ('occupied.add(appId);', 'occupied.add(appId + 0);')):
            self.assertTrue(current.count(old) >= 1, old)
            self.assertTrue(runner.archived_store_problems(current.replace(old, new, 1), base), old)
        self.assertTrue(runner.archived_store_problems(base, base))

    def test_the_later_r0_change_is_allowed_exactly(self):
        # Archived: the pinned 24bfb6a profile, patch and facade against 89491b9's.
        pinned = lambda path: runner.b1.pinned_bytes(runner.CORRECTED, path)  # noqa: E731
        old_profile = json.loads(runner.b1.pinned_bytes(runner.BASE_8949, runner.b1.ARCHIVED_PROFILE))
        profile = json.loads(pinned(runner.b1.ARCHIVED_PROFILE))
        patch, facade = pinned(runner.b1.ARCHIVED_PATCH), pinned(runner.b1.ARCHIVED_FACADE)
        self.assertEqual(runner.archived_r0_problems(old_profile, profile, patch, facade), [])
        settings = [row['path'] for row in profile['files']].index(runner.b1.ARCHIVED_SETTINGS)
        other = json.loads(json.dumps(profile))
        other['files'][0]['candidate_sha256'] = '0' * 64
        self.assertTrue(runner.archived_r0_problems(old_profile, other, patch, facade))
        upstream = json.loads(json.dumps(profile))
        upstream['files'][settings]['upstream_sha256'] = '0' * 64
        self.assertTrue(runner.archived_r0_problems(old_profile, upstream, patch, facade))
        stale = json.loads(json.dumps(profile))
        stale['patch_sha256'] = old_profile['patch_sha256']
        self.assertTrue(runner.archived_r0_problems(old_profile, stale, patch, facade))
        self.assertTrue(runner.archived_r0_problems(old_profile, profile, patch + b'\n', facade))
        self.assertEqual(runner.sha(facade), runner.FACADE_R0_SHA256)
        code = 'Settings facade differs from 89491b9 beyond the R0 default'
        reviewed = 'Settings facade differs from its reviewed R0 bytes'
        for changed in (facade.replace(b'        storeHolds.remove(record.appId);\n', b''),
                        facade.replace(b'initialize, NativeIdentityStore.Format.V2); }',
                                       b'initialize, NativeIdentityStore.Format.V1); }')):
            self.assertNotEqual(changed, facade)
            self.assertEqual(runner.archived_r0_problems(old_profile, profile, patch, changed), [code, reviewed])
        # A comment change keeps the code comparison and trips only the exact byte pin.
        commented = facade.replace(b'// Host PMS facade', b'// The host PMS facade')
        self.assertNotEqual(commented, facade)
        self.assertEqual(runner.archived_r0_problems(old_profile, profile, patch, commented), [reviewed])

    def test_b1_suite_changed_only_its_readiness_check(self):
        # Archived: the pinned 24bfb6a B1 suite against 89491b9's.
        base = runner.b1.pinned_bytes(runner.BASE_8949, runner.ARCHIVED_B1_TEST).decode()
        current = runner.b1.pinned_bytes(runner.CORRECTED, runner.ARCHIVED_B1_TEST).decode()
        self.assertEqual(runner.archived_b1_test_problems(current, base), [])
        weakened = current.replace('unchanged(problems, root, "publication",',
                                   'check(problems, true, "publication",', 1)
        self.assertNotEqual(weakened, current)
        self.assertTrue(runner.archived_b1_test_problems(weakened, base))
        self.assertTrue(runner.archived_b1_test_problems(base, base))

    def test_baselines_and_probes_are_pinned(self):
        b1 = runner.b1
        self.assertEqual(b1.REVISIONS[runner.BASE_8949], runner.REVISION_8949)
        self.assertEqual(set(runner.BASELINE_8949), set(b1.ARCHIVED_FRAMEWORK) | {'Settings'})
        for name, digest in runner.BASELINE_8949.items():
            path = b1.ARCHIVED_FACADE if name == 'Settings' else b1.ARCHIVED_FRAMEWORK_DIR + name + '.java'
            self.assertEqual(runner.sha(b1.git_bytes(runner.REVISION_8949, path)), digest, name)
        # The probes the archived sides compile are the pinned 24bfb6a objects.
        for name, digest in runner.PROBES.items():
            path = b1.ARCHIVED_PLATFORM + name + '.java'
            self.assertEqual(runner.sha(b1.git_bytes(b1.REVISIONS[runner.CORRECTED], path)), digest)
            self.assertEqual(b1.manifest(runner.CORRECTED)[path], digest)
        self.assertEqual(b1.manifest(runner.CORRECTED)[b1.ARCHIVED_FACADE], runner.FACADE_R0_SHA256)
        for path, digest in ((b1.ARCHIVED_PATCH, runner.PATCH_8949_SHA256),
                             (b1.ARCHIVED_PROFILE, runner.PROFILE_8949_SHA256),
                             (runner.ARCHIVED_B1_TEST, runner.B1_TEST_8949_SHA256)):
            self.assertEqual(runner.sha(b1.git_bytes(runner.REVISION_8949, path)), digest, path)
            self.assertEqual(b1.manifest(runner.BASE_8949)[path], digest, path)
        # Only the three archived sides assemble from pinned objects; the current sources are living.
        for side in ('fix', 'b2', 'absent'):
            with self.assertRaisesRegex(ValueError, 'not an archived side'):
                runner.archived_suite_files(side, '', [])


class ArchivedCounterTests(unittest.TestCase):
    """The archived surface and sides: pinned inputs only, assembled with the working tree closed,
    archive code alone, its copies of 24bfb6a code and expectations frozen at 24bfb6a. The current
    sources keep the living focused suite and mutants."""

    def test_every_pin_of_every_revision_equals_its_git_object(self):
        b1 = runner.b1
        self.assertEqual(set(b1.REVISIONS), {'c926', 'd104', '7845', '0018', '8949', b1.ARCHIVE})
        for revision in sorted(b1.REVISIONS):
            for path, digest in sorted(b1.manifest(revision).items()):
                with self.subTest(revision=revision, path=path):
                    self.assertEqual(runner.sha(b1.git_bytes(b1.REVISIONS[revision], path)), digest)
            for directory in b1.ARCHIVED_STUB_DIRECTORIES:
                prefix = b1.ARCHIVED_PLATFORM + directory + '/'
                tree = b1.git_paths(b1.REVISIONS[revision], prefix)
                self.assertEqual(b1.pinned_paths(revision, prefix), [p for p in tree if not p.endswith('/Xml.java')])
        self.assertEqual(b1.archive_problems(), [])
        self.assertEqual(runner.b2.archive_problems(), [])

    def test_archived_assembly_reads_no_worktree_file(self):
        fragments = runner.b2.archived_fragments()
        settings = {side: synthetic_settings(fragments, side) for side in runner.ARCHIVED_SIDES}
        legs = runner.archived_inputs(settings)
        sides = {'%s %s' % (kind, side) for kind in ('focused', 'probes') for side in runner.ARCHIVED_SIDES}
        self.assertEqual(set(legs), sides | {'parity ' + runner.BASE_8949, 'parity ' + runner.CORRECTED})
        pinned = {digest for revision in runner.b1.REVISIONS for digest in runner.b1.manifest(revision).values()}
        for leg, files in sorted(legs.items()):
            for name, data in sorted(files.items()):
                with self.subTest(leg=leg, name=name):
                    if runner.sha(data) not in pinned:
                        self.assertEqual(name, 'tests/NativeHistoryHarness.java')
            # Each side's harness is the archived harness of its own candidate Settings.
            side = leg.rsplit(' ', 1)[1]
            harness = files['tests/NativeHistoryHarness.java']
            self.assertEqual(harness, runner.b2.archived_harness_source(
                settings[side], runner.BASE_0018 if side == runner.BASE_0018 else 'b2').encode(), leg)
            self.assertEqual([marker for marker in settings if ('// candidate %s\n' % marker).encode() in harness],
                             [side], leg)
            # And its product is that side's pinned product.
            self.assertEqual(files['framework/NativeIdentityStore.java'],
                             runner.b1.archived_product_sources(side)['framework/NativeIdentityStore.java'], leg)
        # The archived sides compile the pinned probes and parity driver of 24bfb6a.
        for side in runner.ARCHIVED_SIDES:
            for name in runner.PROBES:
                self.assertEqual(runner.sha(legs['probes ' + side]['tests/%s.java' % name]), runner.PROBES[name])
        for side in (runner.BASE_8949, runner.CORRECTED):
            self.assertEqual(legs['parity ' + side]['tests/NativeHistoryParity.java'],
                             runner.b1.pinned_bytes(runner.CORRECTED, runner.b2.ARCHIVED_PARITY))
        leak = lambda revision, path: (ROOT / path).read_bytes()  # noqa: E731
        for check in (lambda: runner.archived_inputs(settings), runner.archived_surface_violations,
                      runner.archived_suite_problems):
            with mock.patch.object(runner.b1, 'pinned_bytes', leak):
                with self.assertRaises(runner.b1.WorktreeRead):
                    check()
        # The archived surface is pinned objects only: the working tree's sources constrain nothing.
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('working tree read')), \
                mock.patch.object(Path, 'read_text', side_effect=AssertionError('working tree read')):
            self.assertEqual(runner.archived_surface_violations(), [])
        # The living side reads the current sources, as it must.
        living = runner.suite_files(settings[runner.CORRECTED], [runner.TEST])
        self.assertEqual(living['tests/%s.java' % runner.TEST],
                         (ROOT / runner.PLATFORM / (runner.TEST + '.java')).read_bytes())
        self.assertEqual(living['framework/NativeIdentityStore.java'], (ROOT / runner.STORE).read_bytes())

    def test_archived_phases_call_no_living_code(self):
        fragments = runner.b2.archived_fragments()
        settings = {side: synthetic_settings(fragments, side) for side in runner.ARCHIVED_SIDES}

        def archived_run(work):
            steps, problems = {}, []
            with mock.patch.object(runner.subprocess, 'run', fake_tools((), parity='same\n')):
                for phase in (runner.archived_sides_phase, runner.archived_probes_phase,
                              runner.archived_parity_phase):
                    phase(work, settings, steps, problems, mock.Mock())
            return json.loads(json.dumps([steps, problems], default=str).replace(str(work), 'WORK'))
        work = scratch(self)
        expected = archived_run(work / 'first')
        self.assertEqual(set(expected[0]), {'baselines', 'probes', 'parity'})
        self.assertTrue(set(runner.ARCHIVED_SIDES) <= set(expected[0]['probes']))
        # The archived phases run without any living function or constant and record the same.
        living_code_broken(self, runner.b1, B1_LIVING)
        living_code_broken(self, runner.b2, ('settings_texts', 'harness_source', 'history_stubs', 'worktree_tests',
                                             'b2_product', 'red_names', 'probe_outcome', 'candidates'))
        living_code_broken(self, runner, ('suite_files', 'focused', 'mutant_sources', 'candidates'))
        living_constants_changed(self, work)
        with mock.patch.multiple(runner, TEST='x', SUPPORT=(), STORE='x', FACADE='x', FOCUSED_NAMES=(),
                                 PREDICTIONS=work / 'absent.json'):
            self.assertEqual(archived_run(work / 'second'), expected)

    def test_frozen_expectations_are_the_24bfb6a_constants(self):
        revision = runner.b1.REVISIONS[runner.CORRECTED]
        # The 24bfb6a names the counter admission runner took from the history and B1 runners.
        history = historical_constants(revision, 'scripts/proof/native_creation_history.py', ('BASE',))
        binding = historical_constants(revision, 'scripts/proof/native_creation_binding.py', ('PLATFORM',))
        counter = historical_constants(revision, COUNTER, (
            'FOCUSED_NAMES', 'PROBES', 'FACADE_R0_SHA256', 'RULE_NEW', 'RULE_OLD', 'HELPER', 'B1_NEW', 'B1_OLD',
            'TEST', 'SUPPORT', 'REVISION_8949', 'BASELINE_8949', 'BASE_0018', 'BASE_8949', 'SIDES', '_HOLDS',
            '_THROWN', 'B1_TEST', 'PROFILE_PATH'), {'re': re, 'b2': types.SimpleNamespace(**history),
                                                    'PLATFORM': binding['PLATFORM']})
        self.assertEqual(runner.ARCHIVED_FOCUSED_NAMES, counter['FOCUSED_NAMES'])
        self.assertEqual((runner.PROBES, runner.FACADE_R0_SHA256), (counter['PROBES'], counter['FACADE_R0_SHA256']))
        for name in ('RULE_NEW', 'RULE_OLD', 'HELPER', 'B1_NEW', 'B1_OLD'):
            self.assertEqual(getattr(runner, 'ARCHIVED_' + name), counter[name], name)
        self.assertEqual((runner.REVISION_8949, runner.BASELINE_8949),
                         (counter['REVISION_8949'], counter['BASELINE_8949']))
        self.assertEqual((runner.ARCHIVED_TEST, runner.ARCHIVED_SUPPORT), (counter['TEST'], counter['SUPPORT']))
        self.assertEqual((runner.ARCHIVED_B1_TEST, runner.b1.ARCHIVED_PROFILE),
                         (counter['B1_TEST'], counter['PROFILE_PATH']))
        # The probe parsers are the 24bfb6a patterns with their flags.
        for name in ('HOLDS', 'THROWN'):
            frozen, original = getattr(runner, 'ARCHIVED_' + name), counter['_' + name]
            self.assertEqual((frozen.pattern, frozen.flags), (original.pattern, original.flags), name)
        # The sides are those of 24bfb6a, but for the corrected side, whose key is now its pinned revision.
        self.assertEqual((runner.BASE_0018, runner.BASE_8949), (counter['BASE_0018'], counter['BASE_8949']))
        self.assertEqual(counter['SIDES'], (runner.BASE_0018, runner.BASE_8949, 'fix'))
        self.assertEqual(runner.ARCHIVED_SIDES, (runner.BASE_0018, runner.BASE_8949, runner.CORRECTED))
        # The archived surface's Store row is the one the 24bfb6a surface computed from the 24bfb6a
        # integration prefix, and both pinned profiles add it once.
        prefix = historical_constants(revision, 'scripts/proof/native_principal_pins.py', ('PREFIX',))['PREFIX']
        self.assertEqual(runner.ARCHIVED_STORE_ROW, prefix + 'NativeIdentityStore.java')
        for side in (runner.BASE_8949, runner.CORRECTED):
            profile = json.loads(runner.b1.pinned_bytes(side, runner.b1.ARCHIVED_PROFILE))
            self.assertEqual([row['path'] for row in profile['added']].count(runner.ARCHIVED_STORE_ROW), 1, side)
        # The living P0 record repeats the counts that the pinned predictions hold.
        pinned = runner.b1.archived_predictions('counter')
        predicted = json.loads(runner.PREDICTIONS.read_text())['p0_archive']
        self.assertIn('PREDICTED', predicted['status'])
        self.assertEqual(predicted['revision'], revision)
        self.assertEqual(predicted['focused_cases'], len(runner.ARCHIVED_FOCUSED_NAMES))
        self.assertEqual(predicted['corrected']['focused_failures'], pinned['fix']['focused_failures'])
        self.assertEqual(predicted['sides'], {
            runner.BASE_0018: {'failures': len(pinned['baselines'][runner.BASE_0018]['focused_failures'])},
            runner.BASE_8949: {'failures': len(pinned['baselines'][runner.BASE_8949]['focused_failures'])},
            runner.CORRECTED: {'failures': len(pinned['fix']['focused_failures'])}})
        self.assertEqual(predicted['observations'], {'blocked': len(pinned['blocked_observations']),
                                                     'unchanged': len(pinned['unchanged_observations'])})
        self.assertEqual(predicted['probes'], {runner.BASE_0018: 'RED', runner.BASE_8949: 'RED',
                                               runner.CORRECTED: 'REFUSED'})
        self.assertEqual(runner.CORRECTED, runner.b1.ARCHIVE)

    def test_frozen_code_is_the_24bfb6a_code(self):
        for name in ('normalized', 'code', 'store_problems', 'b1_test_problems', 'observations', 'probe_facts',
                     'probe_verdict'):
            frozen_matches(self, 'archived_' + name, name, COPIED, path=COUNTER, module=runner)
        frozen_matches(self, 'archived_compare_observations', 'compare_observations', COPIED, replacements=(
            ("sides['fix']", 'sides[CORRECTED]'), ("side != 'fix'", 'side != CORRECTED'),
            ("values['fix'][1] or values['fix'][2]", 'values[CORRECTED][1] or values[CORRECTED][2]')),
            path=COUNTER, module=runner)
        # The R0 check takes the pinned 24bfb6a patch and facade that the archived surface reads.
        frozen_matches(self, 'archived_r0_problems', 'r0_problems', {**COPIED, 'archived_r0_forward': 'r0_forward'}, (
            ('def r0_problems(old_profile, profile):', 'def r0_problems(old_profile, profile, patch, facade):'),
            ('b1.git_bytes(REVISION_8949, b2.PATCH_PATH)', 'b1.pinned_bytes(BASE_8949, b1.ARCHIVED_PATCH)'),
            ('sha(integration.PATCH.read_bytes())', 'sha(patch)'),
            ('integration.PATCH.read_text()', 'patch.decode()'),
            ("row['path'] == SETTINGS", "row['path'] == b1.ARCHIVED_SETTINGS"),
            ('b1.git_bytes(REVISION_8949, FACADE)', 'b1.pinned_bytes(BASE_8949, b1.ARCHIVED_FACADE)'),
            ('    current = (ROOT / FACADE).read_bytes()\n', ''),
            ('normalized(current.decode())', 'normalized(facade.decode())'),
            ('sha(current)', 'sha(facade)')), path=COUNTER, module=runner)
        archived = {**COPIED, 'archived_build': 'build', 'archived_execute': 'execute',
                    'archived_suite_files': 'suite_files'}
        frozen_matches(self, 'archived_focused', 'focused', {
            **archived, 'archived_outcome': 'outcome', 'archived_suite': 'suite', 'ARCHIVED_TEST': 'TEST',
            'ARCHIVED_FOCUSED_NAMES': 'FOCUSED_NAMES'}, (
            ('work, side, settings, override=None', 'work, side, settings'), ('[TEST], override)', '[TEST])')),
            path=COUNTER, module=runner)
        frozen_matches(self, 'archived_probe_side', 'probe_side', archived, path=COUNTER, module=runner)
        frozen_matches(self, 'archived_parity_side', 'parity_side', archived, ((
            "suite_files(side, settings, [])\n    files['tests/NativeHistoryParity.java'] = "
            "(ROOT / PLATFORM / 'NativeHistoryParity.java').read_bytes()", 'archived_parity_files(side, settings)'),),
            path=COUNTER, module=runner)
        # A changed copy no longer matches.
        with self.assertRaises(AssertionError):
            frozen_matches(self, 'archived_code', 'normalized', COPIED, path=COUNTER, module=runner)

    def test_archive_uses_no_living_name(self):
        self.assertEqual(runner.boundary_problems(), [])
        text = Path(runner.__file__).read_text()
        b1 = runner.b1
        foreign = {'b1': b1.archive_names(Path(b1.__file__).read_text(), b1.ARCHIVE_SHARED),
                   'b2': b1.archive_names(Path(runner.b2.__file__).read_text(), runner.b2.ARCHIVE_SHARED),
                   'integration': None}
        for name, old, new, problem in (
                ('living constant', 'b1.pinned_bytes(CORRECTED, b2.ARCHIVED_PARITY)',
                 "b1.pinned_bytes(CORRECTED, PLATFORM + 'NativeHistoryParity.java')",
                 'archive function archived_parity_files uses living PLATFORM'),
                ('living function', '        result = archived_focused(work', '        result = focused(work',
                 'archive function archived_sides_phase uses living focused'),
                ('living B2 function', 'red = b2.archived_red_names(result, ARCHIVED_FOCUSED_NAMES)',
                 'red = b2.red_names(result, ARCHIVED_FOCUSED_NAMES)',
                 'archive function archived_sides_phase uses b2.red_names'),
                ('living predictions', "    predictions = b1.archived_predictions('counter')\n    steps['probes']",
                 "    predictions = json.loads(PREDICTIONS.read_text())\n    steps['probes']",
                 'archive function archived_probes_phase uses living PREDICTIONS'),
                # Module level archive data, built or changed from living names.
                ('archive data', 'ARCHIVED_B1_TEST = b1.ARCHIVED_PLATFORM + ', 'ARCHIVED_B1_TEST = PLATFORM + ',
                 'archive data ARCHIVED_B1_TEST uses living PLATFORM'),
                ('foreign archive data', 'CORRECTED = b1.ARCHIVE\n',
                 "CORRECTED = b1.ARCHIVE\nb1.ARCHIVE_SHA256.update({STORE: 'x'})\n",
                 'archive data b1.ARCHIVE_SHA256.update uses living STORE'),
                ('foreign living data', 'BASE_0018 = b2.BASE\n', 'BASE_0018 = b2.SETTINGS\n',
                 'archive data BASE_0018 uses b2.SETTINGS')):
            with self.subTest(name=name):
                self.assertEqual(text.count(old), 1, name)
                mutated = text.replace(old, new, 1)
                self.assertEqual(b1.archive_boundary(mutated, runner.ARCHIVE_SHARED, foreign), [problem])

    def test_archive_shares_only_its_pins(self):
        # Every name the archive uses without the archived prefix is pinned revision data or the hash;
        # nothing that looks living is archive code or data.
        for name in sorted(set(runner.ARCHIVE_SHARED) - {'sha'}):
            self.assertTrue(pin_data(getattr(runner, name)), name)
        for name in ('ARCHIVED_SIDES', 'ARCHIVED_RULE_NEW', 'ARCHIVED_HOLDS'):
            self.assertFalse(pin_data(getattr(runner, name)), name)

    def test_labels_are_consistent(self):
        self.assertEqual(runner.label_problems(), [])
        self.assertEqual(set(runner.STEP_LABELS), set(runner.PHASES) - {'candidates', 'b2 runner'})
        for name, labels in runner.STEP_LABELS.items():
            allowed = (runner.b1.ARCHIVED_RUN_LABELS if name in runner.ARCHIVED_STEP_NAMES
                       else runner.b1.LIVING_RUN_LABELS)
            self.assertTrue(labels and set(labels) <= set(allowed), name)
        # The archived 24bfb6a parity side's Format.V1 runs are the rollback reader model's.
        self.assertEqual({name: runner.STEP_LABELS[name] for name in runner.ARCHIVED_STEP_NAMES},
                         {'baselines': ('archived-baseline',), 'probes': ('archived-baseline',),
                          'parity': ('archived-baseline', 'rollback-reader')})
        self.assertEqual({name: runner.STEP_LABELS[name] for name in ('focused', 'mutants')},
                         {'focused': ('production', 'legacy'), 'mutants': ('production', 'legacy')})
        rows = [row for row in runner.b1.HARNESS_LABELS if row[1] == COUNTER]
        labelled = {}
        for label, _, classes, _ in rows:
            for name in classes:
                labelled.setdefault(name, set()).add(label)
        # The probes and parity run only on archived sides now; the focused suite on both.
        self.assertEqual(labelled, {'NativeCounterAdmissionTest': {'production', 'legacy', 'archived-baseline'},
                                    'UnsupportedCounterProbe': {'archived-baseline'},
                                    'StaleSlotCounterProbe': {'archived-baseline'},
                                    'NativeHistoryParity': {'archived-baseline', 'rollback-reader'}})
        self.assertEqual(runner.b1.label_problems(), [])
        # The label rules: each break is refused.
        for change in ({'STEP_LABELS': dict(runner.STEP_LABELS, focused=('production', 'rollback-reader'))},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, parity=('archived-baseline', 'legacy'))},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, unknown=('production',))},
                       {'STEP_LABELS': {k: v for k, v in runner.STEP_LABELS.items() if k != 'probes'}},
                       {'ARCHIVED_STEP_NAMES': runner.ARCHIVED_STEP_NAMES + ('mutants',)}):
            with self.subTest(change=sorted(change)), mock.patch.multiple(runner, **change):
                self.assertTrue(runner.label_problems())


class ComparisonTests(unittest.TestCase):
    def sides(self, fix_ready=False, baseline_ready=True, facts=('f', 'f', 'f')):
        lines = {}
        for side, fact, ready in zip(runner.ARCHIVED_SIDES, facts, (baseline_ready, baseline_ready, fix_ready)):
            lines[side] = '\n'.join((observed('blocked', 'V1', fact, ready, ready),
                                     observed('same', 'V1', 'g', True, True), 'PASS a'))
        return {side: runner.archived_observations(text) for side, text in lines.items()}

    def test_blocked_layouts_differ_only_in_readiness(self):
        self.assertEqual(runner.archived_compare_observations(self.sides(), {'blocked'}), [])
        # The corrected sources were still ready.
        self.assertTrue(runner.archived_compare_observations(self.sides(fix_ready=True), {'blocked'}))
        # A baseline was not ready, so the layout proves nothing about the correction.
        self.assertTrue(runner.archived_compare_observations(self.sides(baseline_ready=False), {'blocked'}))
        # An unpredicted readiness difference.
        self.assertTrue(runner.archived_compare_observations(self.sides(), set()))
        # Any other fact differs.
        self.assertTrue(runner.archived_compare_observations(self.sides(facts=('f', 'f', 'x')), {'blocked'}))
        # A predicted layout that no side observed.
        self.assertTrue(runner.archived_compare_observations(self.sides(), {'blocked', 'absent'}))

    def test_missing_or_malformed_observations(self):
        sides = self.sides()
        del sides[runner.BASE_0018][('same', 'V1')]
        self.assertTrue(runner.archived_compare_observations(sides, {'blocked'}))
        for text in ('OBSERVE\tx\tV1\tf\tready=yes\trestorable=true',
                     'OBSERVE\tx\tV1\tf\tready=true',
                     observed('x', 'V1', 'f', True, True) + '\n' + observed('x', 'V1', 'f', True, True)):
            with self.assertRaises(ValueError):
                runner.archived_observations(text)

    def test_probe_facts_and_verdicts(self):
        # The archived probe classification, over the probe lines the pinned 24bfb6a predictions state.
        expected = runner.b1.archived_predictions('counter')['probes']['UnsupportedCounterProbe']
        facts_of, verdict = runner.archived_probe_facts, runner.archived_probe_verdict
        baseline = expected['baseline']
        stdout = '\n'.join(baseline['lines']).replace('holds=[10000, 10001]', 'holds=[10001, 10000]') + '\n'
        red = {'returncode': 1, 'stdout': stdout,
               'stderr': 'Exception in thread "main" ' + baseline['exception'] + '\n\tat x\n'}
        facts = facts_of(red)
        self.assertEqual(facts['lines'], baseline['lines'])
        self.assertEqual(verdict(facts, baseline), 'RED')
        refused = {'returncode': 1, 'stdout': expected['fix']['lines'][0] + '\n',
                   'stderr': 'Exception in thread "main" ' + expected['fix']['exception'] + '\n'}
        self.assertEqual(verdict(facts_of(refused), expected['fix']), 'REFUSED')
        # A refusal is never read as the baseline's red, a crash is neither, and a probe that
        # issued nothing but printed other facts is unexpected.
        self.assertEqual(verdict(facts_of(refused), baseline), 'UNEXPECTED')
        self.assertEqual(verdict(facts_of(dict(red, returncode=137)), baseline), 'UNEXPECTED')
        self.assertEqual(verdict(facts_of(dict(red, stdout=stdout.replace('ID=2', 'ID=3'))), baseline), 'UNEXPECTED')
        self.assertIsNone(facts_of({'returncode': 0, 'stdout': '', 'stderr': ''})['exception'])


class RunnerRefusalAndEvidenceTests(unittest.TestCase):
    def test_work_path_budget_includes_the_nested_b2_runner(self):
        self.assertIsNone(runner.work_path_problem(Path('/srv/b3w')))
        self.assertIsNone(runner.work_path_problem(Path('/' + 'a' * 28)))
        problem = runner.work_path_problem(Path('/' + 'a' * 29))
        self.assertIn('work path too long', problem)
        self.assertIn('at most 29 ASCII characters', problem)

    def test_long_work_path_is_not_run_before_any_effect(self):
        base = scratch(self)
        work, evidence = base / ('w' * 40), base / 'evidence.json'
        started = mock.Mock(side_effect=AssertionError('started'))
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner.b1, 'resource_guard', started), \
                mock.patch.object(runner.shutil, 'which', started), \
                mock.patch.object(runner.subprocess, 'run', started), \
                mock.patch.object(runner.b1, 'build', started), \
                mock.patch.object(runner, 'qualify', started), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        report = json.loads(output.getvalue())
        self.assertEqual((code, report['status']), (2, 'NOT_RUN'))
        self.assertIn('work path too long', report['reason'])
        self.assertEqual(list(base.iterdir()), [])
        started.assert_not_called()

    def test_short_work_path_is_accepted_and_the_next_guard_decides(self):
        base = scratch(self)
        work = base / 'w'
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None) as budget, \
                mock.patch.object(runner.b1, 'resource_guard', return_value='required bounds absent'), \
                mock.patch.object(runner, 'qualify', side_effect=AssertionError('started')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(base / 'evidence.json'), '--work', str(work),
                                '--pinned-framework', str(base)])
        self.assertEqual((code, json.loads(output.getvalue())['reason']), (2, 'required bounds absent'))
        budget.assert_called_once_with(work.resolve())
        self.assertEqual(list(base.iterdir()), [])

    def test_missing_jdk_is_not_run(self):
        base = scratch(self)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value=None), \
                mock.patch.object(runner, 'qualify', side_effect=AssertionError('started')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(base / 'evidence.json'), '--work', str(base / 'w'),
                                '--pinned-framework', str(base)])
        self.assertEqual((code, json.loads(output.getvalue())['reason']), (2, 'no JDK on PATH'))
        self.assertEqual(list(base.iterdir()), [])

    def test_timeout_after_a_recorded_step_keeps_the_record_and_its_streams(self):
        base = scratch(self)
        work, evidence = base / 'w', base / 'evidence.json'
        seen = {}

        def interrupted(directory, pinned, progress):
            progress.begin('candidates')
            progress.report['steps']['candidates'] = {'changed_against_0018': [runner.b1.ARCHIVED_SETTINGS]}
            progress.done('candidates')
            progress.begin('focused')
            seen['checkpoint'] = json.loads((work / 'progress.json').read_text())
            raise subprocess.TimeoutExpired(['java', runner.TEST], 900, output=b'PASS a\n\xff',
                                            stderr=b'stuck\n')
        previous = tempfile.tempdir
        self.addCleanup(setattr, tempfile, 'tempdir', previous)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'qualify', side_effect=interrupted), \
                mock.patch.object(runner, 'b2_regression', side_effect=AssertionError('retried')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        self.assertEqual(code, 1)
        checkpoint = seen['checkpoint']
        self.assertEqual((checkpoint['status'], checkpoint['completed_phases'], checkpoint['phase']),
                         ('RUNNING', ['candidates'], 'focused'))
        report = json.loads(evidence.read_text())
        self.assertEqual(report, json.loads((work / 'progress.json').read_text()))
        self.assertEqual(report['status'], 'NOT_COMPLETE')
        self.assertEqual(report['completed_phases'], ['candidates'])
        self.assertEqual(report['not_completed_phases'], list(runner.PHASES[1:]))
        self.assertEqual(report['exception']['stdout'], 'PASS a\n\ufffd')
        self.assertEqual(report['exception']['stderr'], 'stuck\n')
        self.assertIn('qualification did not complete', report['problems'])

    def test_a_failed_b2_regression_fails_the_run(self):
        base = scratch(self)
        work, evidence = base / 'w', base / 'evidence.json'

        def finished(directory, pinned, progress):
            for phase in runner.PHASES[:-1]:
                progress.begin(phase)
                progress.done(phase)
        previous = tempfile.tempdir
        self.addCleanup(setattr, tempfile, 'tempdir', previous)
        output = io.StringIO()
        with mock.patch.object(runner, 'source_checks', return_value=[]), \
                mock.patch.object(runner, 'work_path_problem', return_value=None), \
                mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'qualify', side_effect=finished), \
                mock.patch.object(runner, 'b2_regression',
                                  return_value={'returncode': 1, 'status': 'FAIL'}), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--evidence', str(evidence), '--work', str(work),
                                '--pinned-framework', str(base)])
        report = json.loads(evidence.read_text())
        self.assertEqual((code, report['status']), (1, 'FAIL'))
        self.assertEqual(report['completed_phases'], list(runner.PHASES))
        self.assertIn('B2 runner regression', report['problems'])

    def test_source_only_mode_is_pure(self):
        output = io.StringIO()
        with mock.patch.object(runner, 'qualify', side_effect=AssertionError('started')), \
                mock.patch.object(runner.b1, 'build', side_effect=AssertionError('compiled')), \
                contextlib.redirect_stdout(output):
            code = runner.main(['--source-checks-only'])
        self.assertEqual((code, json.loads(output.getvalue())['status']), (0, 'SOURCE_ONLY'))


if __name__ == '__main__':
    unittest.main()
