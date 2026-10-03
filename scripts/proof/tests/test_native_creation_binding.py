# SPDX-License-Identifier: Apache-2.0
"""Complete creation bindings and exact byte admission: pure source guards here, and the guarded
JVM matrix, which is NOT RUN without the required resource bounds. Not Android runtime proof."""
from pathlib import Path
import json
import resource
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_binding as runner  # noqa: E402


class CreationBindingSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_production_format_is_one_anchored_v2_construction(self):
        texts = runner.production_texts()
        self.assertEqual(runner.format_violations(texts), [])
        self.assertEqual(runner.boot_literal(texts), runner.PRODUCTION)
        # The patch is read per file section: the boot construction is in the Settings section only.
        sections = [name for name in texts if name.startswith(runner.NATIVE_PATCH + ':')]
        self.assertEqual(sections, [runner.NATIVE_PATCH + ':' + name for name in runner.integration.FILES])
        self.assertEqual([name for name in sections if 'new NativeIdentityStore(' in texts[name]],
                         [runner.SETTINGS_SECTION])
        store = (ROOT / runner.STORE).read_text()
        # The enum's own constants and comments are neither constructions nor format names.
        self.assertIn('V2(2, 2);', store)
        self.assertIn('Production constructs Format.V2 once', store.replace('\n * ', ' '))
        self.assertEqual(runner.enum_definition(runner.strip_java_comments(store)), runner.FORMAT_ENUM)

    def test_each_guard_mutant_trips_exactly_its_rules(self):
        mutants = runner.guard_mutants()
        self.assertEqual(set(mutants), {
            'regression-to-v1', 'second-construction', 'framework-construction', 'other-file-section',
            'value-and-property-selection', 'reflective-field-write', 'enumset-complement',
            'enum-version-swap', 'construction-outside-boot', 'qualified-construction', 'constructor-reference',
            'qualified-constructor-reference', 'declaring-class-field', 'unicode-escape', 'format-alone',
            'v1-alone', 'mention-alone', 'non-native-unicode-escape', *runner.ONE_TOKEN_PATHS})
        predictions = json.loads(runner.PREDICTIONS.read_text())['r0_format_guard']['mutant_rules']
        self.assertEqual(set(predictions), set(mutants))
        # Every rule is tripped alone by at least one mutant, so none is only ever a bystander.
        alone = {next(iter(rules)) for _, rules in mutants.values() if len(rules) == 1}
        self.assertEqual(alone, set(runner.FORMAT_RULES))
        for name, (texts, rules) in mutants.items():
            with self.subTest(name=name):
                self.assertTrue(rules and set(rules) <= set(runner.FORMAT_RULES))
                self.assertEqual(runner.format_rules(texts), rules)
                self.assertEqual(sorted(rules), predictions[name])
        # The two one token patches land at two paths under patches/ and differ only there.
        self.assertEqual(len(set(runner.ONE_TOKEN_PATHS.values())), 2)
        self.assertTrue(all(path.startswith('patches/') for path in runner.ONE_TOKEN_PATHS.values()))

    def test_constructions_selectors_and_escapes_by_scope(self):
        texts = runner.production_texts()
        helper = runner.FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
        other = runner.NON_NATIVE
        self.assertFalse(runner.native_source(other))
        self.assertTrue(runner.native_source(helper))

        def rules(name, code):
            changed = dict(texts)
            changed[name] = texts[name] + '\nclass Probe {\n' + code + '\n}\n'
            return runner.format_rules(changed)
        for code in ('Object a = new NativeIdentityStore(null, null);',
                     'Object a = new com.android.server.pm.NativeIdentityStore(null, null);',
                     'Object a = new com.android.server.pm . NativeIdentityStore (null, null);',
                     'java.util.function.BiFunction<Object, Object, Object> a = NativeIdentityStore::new;',
                     'java.util.function.BiFunction<Object, Object, Object> a = com.android.server.pm.NativeIdentityStore :: new;'):
            with self.subTest(code=code):
                self.assertEqual(rules(helper, code), {'sites'})
                # Outside the native texts the same construction also names the store.
                self.assertEqual(rules(other, code), {'sites', 'mention'})
        # Loaded and other nested types are no construction.
        self.assertEqual(rules(helper, 'Object a = new NativeIdentityStore.ReadResult<Object>(null, null, null);'),
                         set())
        for code in ('Object a = String.class.getField("x");', 'Object a = Thread.State.NEW.getDeclaringClass();'):
            with self.subTest(code=code):
                self.assertEqual(rules(helper, code), {'selector'})
                self.assertEqual(rules(other, code), set())
        # A unicode escape is refused in every production text, in comments as in code.
        for code in ('// \\u0041', 'String a = "\\u0041";', 'char a = \'\\uu0041\';'):
            with self.subTest(code=code):
                self.assertEqual(rules(helper, code), {'escape'})
                self.assertEqual(rules(other, code), {'escape'})
        self.assertEqual(rules(helper, 'String a = "u0041 and \\\\n";'), set())

    def test_a_merged_patch_read_would_miss_a_construction_moved_to_another_section(self):
        texts = runner.guard_mutants()['other-file-section'][0]
        sections = [name for name in texts if name.startswith(runner.NATIVE_PATCH + ':')]
        merged = runner.strip_java_comments('\n'.join(texts[name] for name in sections))
        # As one merged added text the anchors still follow each other, and the old reading passed.
        self.assertIsNotNone(runner.boot_site(merged))
        self.assertIsNone(runner.boot_site(runner.strip_java_comments(texts[runner.SETTINGS_SECTION])))
        self.assertIn('sites', runner.format_rules(texts))

    def test_patch_sections_follow_hunk_counts(self):
        patch = runner.one_token_patch(runner.PRODUCTION, runner.RETIRED)
        self.assertEqual(runner.patch_sections(patch),
                         [(runner.integration.SETTINGS, '                ' + runner.RETIRED + ');')])
        # A content line that looks like a header stays in its section.
        tricky = ('--- a/A.java\n+++ b/A.java\n@@ -1,2 +1,4 @@\n context\n+++ b/B.java\n+added\n other\n')
        self.assertEqual(runner.patch_sections(tricky), [('A.java', '++ b/B.java\nadded')])
        for broken in ('@@ -1 +1 @@\n+x\n', '--- a/A.java\n+++ b/A.java\n@@ -1,2 +1,2 @@\n x\n',
                       '--- a/A.java\n+++ b/A.java\n@@ -1 +1 @@\n*x\n'):
            with self.assertRaises(ValueError):
                runner.patch_sections(broken)
        native = runner.patch_sections(runner.integration.PATCH.read_text())
        self.assertEqual([target for target, _ in native], list(runner.integration.FILES))
        self.assertEqual(''.join(text for _, text in native).count('new NativeIdentityStore('), 1)

    def test_host_facade_default_is_the_boot_literal(self):
        texts = runner.production_texts()
        facade = (ROOT / runner.FACADE).read_text()
        self.assertEqual(runner.facade_default(facade), runner.PRODUCTION)
        self.assertEqual(runner.facade_violations(texts, facade), [])
        retired = facade.replace('initialize, ' + runner.PRODUCTION + '); }', 'initialize, ' + runner.RETIRED + '); }')
        self.assertNotEqual(retired, facade)
        self.assertTrue(runner.facade_violations(texts, retired))
        # The patch literal and the facade cannot drift apart in either direction.
        mutated = runner.guard_mutants()['regression-to-v1'][0]
        self.assertEqual(runner.boot_literal(mutated), runner.RETIRED)
        self.assertTrue(runner.facade_violations(mutated, facade))
        self.assertEqual(runner.facade_violations(mutated, retired), [])
        self.assertIsNone(runner.facade_default(facade.replace('    Settings() { this(null, true); }\n', '')))
        self.assertIsNone(runner.boot_literal(runner.guard_mutants()['construction-outside-boot'][0]))

    def test_r0_forward_is_the_one_literal_change(self):
        old = runner.git_bytes(runner.REVISIONS['7845'], runner.NATIVE_PATCH).decode()
        self.assertEqual(runner.r0_forward(old), runner.integration.PATCH.read_text())
        self.assertIsNone(runner.r0_forward(runner.integration.PATCH.read_text()))
        self.assertIsNone(runner.r0_forward(old + old))
        facade = runner.git_bytes(runner.REVISIONS['7845'], runner.FACADE).decode()
        self.assertEqual(runner.facade_default(runner.r0_forward(facade)), runner.PRODUCTION)

    def test_rollback_copy_count_and_controls_are_predicted(self):
        predictions = json.loads(runner.PREDICTIONS.read_text())['r0_format_guard']
        seed_only = predictions['rollback_seed_only_layouts']
        self.assertEqual(predictions['rollback_copy_layouts'], runner.ROLLBACK_COPY_LAYOUTS)
        self.assertEqual(tuple(predictions['rollback_controls']), runner.ROLLBACK_CONTROLS)
        self.assertEqual(runner.ROLLBACK_COPY_LAYOUTS, len(runner.LAYOUT_NAMES) - len(seed_only))
        self.assertEqual(seed_only, [name for name in runner.LAYOUT_NAMES if name.endswith('-seed-synced')
                                     and not name.startswith('v2-publication-')])
        self.assertTrue(set(runner.ROLLBACK_CONTROLS) <= set(runner.LAYOUT_NAMES) - set(seed_only))
        source = (ROOT / runner.PLATFORM / 'NativeRollbackReaderCheck.java').read_text()
        for name in ('"rollback reader / "', '"rollback reader control / "', '"rollback reader / version 2 copy layouts"'):
            self.assertEqual(source.count(name), 1, name)
        names = runner.rollback_names('rollback reader', runner.LAYOUT_NAMES, runner.ROLLBACK_CONTROLS)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), len(runner.LAYOUT_NAMES) + len(runner.ROLLBACK_CONTROLS) + 1)
        layouts = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, layouts)
        for name, kind in (('a', 'copy\n'), ('b', 'seed\n'), ('c', 'copy\n')):
            (layouts / name).mkdir()
            (layouts / name / 'kind').write_text(kind)
        self.assertEqual(runner.copy_layouts(layouts), 2)

    def test_rollback_reader_and_labels(self):
        self.assertEqual(runner.label_problems(), [])
        self.assertEqual(runner.REVISIONS['7845'], '78456b352267dba916778b90d7c926c4e67ef888')
        for name, digest in runner.BASELINE_SHA256['7845'].items():
            path = runner.FACADE if name == 'Settings' else runner.FRAMEWORK_DIR + name + '.java'
            self.assertEqual(runner.sha(runner.git_bytes(runner.REVISIONS['7845'], path)), digest, name)
        self.assertIn(('7845', '7845', 'b1'), runner.READERS)
        self.assertEqual(set(runner.ROLLBACK_READERS), {'b1-v1', '7845'})
        self.assertEqual({runner.READER_LABELS[target] for target in runner.ROLLBACK_READERS}, {'rollback-reader'})
        self.assertEqual(runner.READER_LABELS['c926'], 'archived-baseline')
        labels = {}
        for label, _, classes, _ in runner.HARNESS_LABELS:
            for name in classes:
                labels.setdefault(name, set()).add(label)
        self.assertEqual(labels['NativeWriterLabRehearsal'], {'production'})
        # The rollback checks read under Format.V1, and their discrimination controls under Format.V2.
        self.assertEqual(labels['NativeRollbackReaderCheck'], {'rollback-reader', 'production'})
        self.assertEqual(labels['NativeRollbackSeedingCheck'], {'rollback-reader', 'production'})
        self.assertEqual(runner.step_labels('rollback'), ('rollback-reader', 'production'))
        for name in ('NativePrincipalWriterFixtureTest', 'NativePrincipalManagerTest', 'NativeIdentityStoreTest'):
            self.assertIn('legacy', labels[name], name)
        self.assertEqual(runner.step_labels('b0 c926 focused'), ('archived-baseline',))
        self.assertEqual(runner.step_labels('b0 b1-v1 faults'), ('legacy',))
        self.assertEqual(runner.step_labels('b1 faults'), ('production',))
        with mock.patch.object(runner, 'HARNESS_LABELS', runner.HARNESS_LABELS + (
                ('retired', 'scripts/proof/native_creation_binding.py', ('Absent',), 'x'),)):
            self.assertTrue(runner.label_problems())

    def test_v1_constructions_in_legacy_and_rollback_tests_are_explicit(self):
        # The host facade's default is the production format, so no test relies on it for V1.
        for path in ('owner/tests/platform/NativePrincipalManagerTest.java',
                     'owner/tests/platform/NativePreparationAdmissionTest.java',
                     'owner/tests/platform/NativePreparationFaultTest.java',
                     'tests/native-identity/writer/NativePrincipalWriterFixtureTest.java',
                     'tests/native-identity/writer/NativePrincipalWriterFixtureFaultTest.java',
                     'tests/native-identity/writer/NativePrincipalWriterFixtureTranscript.java'):
            text = (ROOT / path).read_text()
            self.assertNotIn('new PackageManagerService()', text, path)
            self.assertNotRegex(text, r'new PackageManagerService\([^()]*, (?:true|false)\)', path)
            self.assertIn('LEGACY = NativeIdentityStore.Format.V1;', text, path)
        support = (ROOT / runner.PLATFORM / 'NativeHeaderTestSupport.java').read_text()
        self.assertNotIn('new PackageManagerService(', support)
        b1_api = (ROOT / runner.PLATFORM / 'native_header_api/b1/NativeHeaderApi.java').read_text()
        self.assertEqual(b1_api.count('NativeIdentityStore.Format.V1'), 2)
        self.assertNotIn('Format.V2', runner.strip_java_comments(b1_api))

    def test_comment_stripping_keeps_literals(self):
        text = 'String a = "// not a comment /* either */"; // gone\nchar c = \'"\'; /* gone\n */ int b;'
        stripped = runner.strip_java_comments(text)
        self.assertIn('"// not a comment /* either */"', stripped)
        self.assertNotIn('gone', stripped)
        self.assertIn("'\"'", stripped)
        self.assertIn('int b;', stripped)

    def test_mutants_anchor_once_and_predictions_are_consistent(self):
        sources = runner.mutant_sources()
        self.assertEqual(set(sources), set(runner.MUTANTS))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertIn('PREDICTED', predictions['status'])
        self.assertEqual(set(predictions['b1_mutants_caught_at_least']), set(runner.MUTANTS))
        names = set(runner.FOCUSED_NAMES) | set(runner.FAULT_NAMES)
        for name, expected in predictions['b1_mutants_caught_at_least'].items():
            self.assertTrue(expected and set(expected) <= names, name)
        d104 = predictions['b0_adapted_suite']['d104e15']
        self.assertEqual((len(d104['focused_failures']), len(d104['fault_failures'])), (41, 18))
        self.assertEqual(set(d104['focused_failures']) | set(d104['focused_controls']),
                         set(runner.b0.FOCUSED_NAMES))
        self.assertEqual(set(d104['fault_failures']) | set(d104['fault_controls']),
                         set(runner.b0.FAULT_NAMES))
        self.assertEqual((len(runner.FOCUSED_NAMES), len(runner.FAULT_NAMES), len(runner.LAYOUT_NAMES)),
                         (80, 53, 47))

    def test_class_differences_compare_every_class_file(self):
        first, second = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, first)
        self.addCleanup(shutil.rmtree, second)
        for root in (first, second):
            (root / 'com/android/server/pm').mkdir(parents=True)
            (root / 'com/android/server/pm/NativeIdentityStore.class').write_bytes(b'same')
            (root / 'com/android/server/pm/NativeIdentityStore$Format.class').write_bytes(b'enum')
        self.assertEqual(runner.class_differences(first, second), [])
        (second / 'com/android/server/pm/NativeIdentityStore$Format.class').write_bytes(b'swapped')
        (second / 'com/android/server/pm/Extra.class').write_bytes(b'x')
        self.assertEqual(runner.class_differences(first, second),
                         ['com/android/server/pm/Extra.class', 'com/android/server/pm/NativeIdentityStore$Format.class'])
        predictions = json.loads(runner.PREDICTIONS.read_text())['r0_format_guard']
        self.assertEqual(predictions['store_class_differences_from_7845'], [])
        self.assertEqual(runner.step_labels('store classes'), ('production', 'archived-baseline'))

    def test_compile_failure_keeps_diagnostics_and_is_not_red(self):
        build = {'returncode': 1, 'stdout': '', 'stderr': 'missing symbol', 'inputs': {}}
        result = runner.outcome({'compile_failure': True, 'build': build}, ('case',))
        self.assertEqual(result, {'error': 'compile failure', 'build': build})
        self.assertNotIn('failed', result)

    def test_outcome_requires_complete_unique_names_and_keeps_raw_run(self):
        build = {'returncode': 0, 'inputs': {}}
        run = {'returncode': 1, 'passed': ['case'], 'failed': [],
               'stdout': 'PASS case\n', 'stderr': 'open descriptors'}
        result = runner.outcome({'build': build, 'run': run}, ('case',))
        self.assertEqual(result['returncode'], 1)
        self.assertIs(result['run'], run)
        self.assertTrue(result['complete'])
        run['passed'] = ['case', 'case']
        self.assertFalse(runner.outcome({'build': build, 'run': run}, ('case',))['complete'])

    def test_presence_socket_budget_keeps_the_real_store_path(self):
        with tempfile.TemporaryDirectory(prefix='b1p-', dir='/tmp') as state:
            path = Path(state) / 'presence-V2/c79/store/slots/10123/record.bin-seed'
            self.assertLess(len(str(path)), 100)

    def test_admission_facade_is_the_production_fragment(self):
        fragment = runner.integration.FRAGMENTS['admission'][1].read_bytes()
        facade = (ROOT / runner.PLATFORM /
                  'native_principal_stubs/com/android/server/pm/Settings.java').read_bytes()
        self.assertEqual(facade.count(fragment), 1)

    def test_resource_guard_requires_every_bound(self):
        def tree(values):
            directory = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, directory)
            leaf = directory / 'user.slice' / 'run.scope'
            leaf.mkdir(parents=True)
            for name, value in values.items():
                (leaf / name).write_text(value + '\n')
            membership = directory / 'membership'
            membership.write_text('0::/user.slice/run.scope\n')
            return directory, membership
        exact = {'memory.max': str(2 * runner.GIB), 'memory.swap.max': '0', 'cpu.max': '200000 100000',
                 'pids.max': '256'}
        with mock.patch.object(resource, 'getrlimit', return_value=(0, 0)):
            root, membership = tree(exact)
            self.assertIsNone(runner.resource_guard(root, membership))
            for name, weaker in (('memory.max', str(3 * runner.GIB)), ('memory.swap.max', 'max'),
                                 ('cpu.max', '300000 100000'), ('pids.max', '257')):
                root, membership = tree(dict(exact, **{name: weaker}))
                self.assertIsNotNone(runner.resource_guard(root, membership), name)
            for name in exact:
                root, membership = tree({k: v for k, v in exact.items() if k != name})
                self.assertIsNotNone(runner.resource_guard(root, membership), name)
        with mock.patch.object(resource, 'getrlimit', return_value=(0, 1)):
            root, membership = tree(exact)
            self.assertIn('core dumps', runner.resource_guard(root, membership))


class CreationBindingJvmTests(unittest.TestCase):
    def test_guarded_jvm_matrix(self):
        reason = runner.resource_guard()
        if reason:
            self.skipTest('NOT RUN: resource guard: ' + reason)
        if not (shutil.which('javac') and shutil.which('java')):
            self.skipTest('NOT RUN: no JDK on PATH')
        with tempfile.TemporaryDirectory() as directory:
            evidence = runner.qualify(Path(directory))
        self.assertEqual(evidence['problems'], [], json.dumps(evidence['steps'], indent=2)[-20000:])


if __name__ == '__main__':
    unittest.main()
