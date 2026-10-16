# SPDX-License-Identifier: Apache-2.0
"""Complete creation bindings and exact byte admission: pure source guards here, and the guarded
JVM matrix, which is NOT RUN without the required resource bounds. Not Android runtime proof."""
from pathlib import Path
import ast
import inspect
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_binding as runner  # noqa: E402

PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')


def historical_constants(revision, path, names, namespace=None):
    """Module level constants of a runner as its Git object at one revision states them: each named
    assignment, evaluated in file order with the given namespace and the names before it, and no
    builtins but tuple and sorted."""
    values = {}
    for node in ast.parse(runner.git_bytes(revision, path).decode()).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in names):
            code = compile(ast.Expression(node.value), path, 'eval')
            scope = {'__builtins__': {'tuple': tuple, 'sorted': sorted}, **(namespace or {}), **values}
            values[node.targets[0].id] = eval(code, scope)  # noqa: S307
    return values


def historical_function(revision, path, name):
    """The source of one top level function as a runner's Git object at one revision states it."""
    text = runner.git_bytes(revision, path).decode()
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    raise AssertionError('no function %s in %s' % (name, path))


def normalized_function(source, renames=None):
    """One function's syntax tree as text, decorators dropped and names mapped: two functions that
    differ only in layout, comments and the mapped names compare equal."""
    node = ast.parse(textwrap.dedent(source)).body[0]
    node.decorator_list = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            child.id = (renames or {}).get(child.id, child.id)
        elif isinstance(child, ast.Attribute):
            child.attr = (renames or {}).get(child.attr, child.attr)
        elif isinstance(child, ast.FunctionDef):
            child.name = (renames or {}).get(child.name, child.name)
    return ast.dump(node)


def pin_data(value):
    """Whether a value is pinned revision data: a revision key, a full revision, a SHA-256 digest, or
    a mapping of such data."""
    if isinstance(value, str):
        return re.fullmatch(r'[0-9a-z]{4}|[0-9a-f]{40}|[0-9a-f]{64}', value) is not None
    if isinstance(value, dict):
        return all(isinstance(key, str) and pin_data(item) for key, item in value.items())
    return False


def fake_tools(layouts):
    """A stand in for the compiler and JVM, with Git itself: javac succeeds, a layout emitter writes
    the given layouts, each of version 2 copies, and every other JVM prints one passing check. Their
    effects are the same whichever code starts them."""
    real = subprocess.run

    def run(args, **kwargs):
        if args[0] not in ('javac', 'java'):
            return real(args, **kwargs)
        if args[0] == 'java':
            main = next(index for index, arg in enumerate(args) if arg.startswith('com.android.server.pm.'))
            if args[main].endswith('Layouts'):
                for name in layouts:
                    (Path(args[main + 1]) / name).mkdir(parents=True)
                    (Path(args[main + 1]) / name / 'kind').write_text('copy\n')
        return subprocess.CompletedProcess(args, 0, 'PASS a\n', '')
    return run


def living_code_broken(test, module, names):
    """Patch every named living function of a module to fail the test when it runs."""
    for name in names:
        patcher = mock.patch.object(module, name, side_effect=AssertionError('living %s ran' % name))
        patcher.start()
        test.addCleanup(patcher.stop)


def frozen_matches(test, module, frozen, path, original, renames=None, replacements=()):
    """Assert that one frozen function of a runner is its 24bfb6a original, but for the mapped names
    and the marked replacements applied to the original."""
    source = historical_function(runner.REVISIONS[runner.ARCHIVE], path, original)
    for old, new in replacements:
        test.assertEqual(source.count(old), 1, (frozen, old))
        source = source.replace(old, new)
    mapping = {frozen: original, **(renames or {})}
    test.assertEqual(normalized_function(inspect.getsource(getattr(module, frozen)), mapping),
                     normalized_function(source), frozen)


class CreationBindingSourceTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_production_format_is_one_anchored_v3_construction(self):
        texts = runner.production_texts()
        self.assertEqual(runner.format_violations(texts), [])
        self.assertEqual(runner.boot_literal(texts), runner.PRODUCTION)
        self.assertEqual((runner.PRODUCTION, runner.PREVIOUS, runner.RETIRED),
                         tuple('NativeIdentityStore.Format.V%d' % version for version in (3, 2, 1)))
        # The patch is read per file section: the boot construction is in the Settings section only.
        native = runner.PRODUCTION_NATIVE_PATCH + ':'
        sections = [name for name in texts if name.startswith(native)]
        self.assertEqual(sections, [native + name for name in runner.integration.FILES])
        self.assertEqual([name for name in sections if 'new NativeIdentityStore(' in texts[name]],
                         [runner.SETTINGS_SECTION])
        store = (ROOT / runner.STORE).read_text()
        # The enum's own constants and comments are neither constructions nor format names.
        self.assertIn('V2(2, 2, 1),', store)
        self.assertIn('V3(2, 2, 2);', store)
        self.assertIn('Production constructs Format.V3 once', store.replace('\n * ', ' '))
        self.assertEqual(runner.enum_definition(runner.strip_java_comments(store)), runner.FORMAT_ENUM)
        # The floor's native patch and store helper, from their pinned Git objects, break the rule
        # only by passing and naming the previous format.
        floor = dict(texts)
        for target, added in runner.patch_sections(runner.floor_bytes(runner.NATIVE_PATCH).decode()):
            floor['%s:%s' % (runner.PRODUCTION_NATIVE_PATCH, target)] = added
        floor[runner.STORE] = runner.floor_bytes(runner.STORE).decode()
        self.assertNotEqual(floor, texts)
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_1']['floor']
        self.assertEqual(sorted(runner.format_rules(floor)), predicted['guard_rules'])
        self.assertEqual(runner.boot_literal(floor), runner.PREVIOUS)

    def test_the_structure_view_blanks_annotations_and_literal_data(self):
        text = ('@A(x = "(", y = @B(@C(1))) class T { String s = "{"; Object o = new @P("(") X<@Q(1 < 2) Y>(); }\n'
                '@interface P7Mark { String value(); }\n')
        view = runner.java_structure_view(text)
        self.assertEqual(len(view), len(text))
        self.assertEqual(view.count('\n'), text.count('\n'))
        self.assertNotIn('@', view.split('\n')[0])
        self.assertEqual(view.count('{'), 2)
        self.assertRegex(view, runner.java_creation('X'))
        self.assertIn('@interface P7Mark', view)
        # The value view blanks only each annotation's @ and name: its arguments stay, nested names go.
        values = runner.java_annotation_values(runner.java_code_view('@A(X.class) @ p.B (@C(1)) @interface D {}', False))
        self.assertEqual(values, '  (X.class)' + ' ' * 7 + '(  (1)) @interface D {}')
        self.assertEqual(runner.java_code_outside_ascii('int a\u200cb; String s = "\u00e9";'), ['\u200c'])

    def test_each_guard_mutant_trips_exactly_its_rules(self):
        mutants = runner.guard_mutants()
        self.assertEqual(set(mutants), {
            'regression-to-v1', 'second-construction', 'framework-construction', 'other-file-section',
            'value-and-property-selection', 'reflective-field-write', 'enumset-complement',
            'enum-version-swap', 'construction-outside-boot', 'qualified-construction', 'constructor-reference',
            'qualified-constructor-reference', 'declaring-class-field', 'unicode-escape', 'format-alone',
            'v1-alone', 'mention-alone', 'non-native-unicode-escape', 'harmless-unicode-escape',
            'fullwidth-unicode-escape', 'unicode-carriage-return-escape', 'creation-with-type-arguments',
            'annotated-qualified-creation', 'constructor-reference-with-type-arguments',
            'annotated-creation-holding-a-parenthesis', 'nested-annotation-creation', 'code-outside-ascii',
            'computed-method-lookup', *runner.ONE_TOKEN_PATHS,
            'slot-ceiling-regression', 'regression-to-v2', 'v2-alone'})
        # The R0 guard's mutants as R0 predicted them, and the three P1 adds for the slot ceiling and
        # the lifecycle format, which B2 replaces with their regressions to the previous format.
        recorded = json.loads(runner.PREDICTIONS.read_text())
        # P7 reads every rule through the compiler's escape translation and one lexical view, which
        # widens the two escape mutants' rules, and reads constructions in every syntactic form.
        predictions = {**recorded['r0_format_guard']['mutant_rules'],
                       **recorded['p1_lifecycle_record']['mutant_rules'],
                       **recorded['p7_guard_reading']['mutant_rules']}
        b2 = recorded['b2_checkpoint_1']
        self.assertEqual(set(b2['replaced_mutants']), set(recorded['p1_lifecycle_record']['mutant_rules']))
        self.assertEqual(set(b2['replaced_mutants'].values()), set(b2['mutant_rules']))
        for name in b2['replaced_mutants']:
            del predictions[name]
        predictions.update(b2['mutant_rules'])
        self.assertEqual(recorded['p7_guard_reading']['guard_mutants']['after'], b2['guard_mutants']['before'])
        self.assertEqual(len(mutants), b2['guard_mutants']['after'])
        self.assertEqual(set(predictions), set(mutants))
        # The construction mutants pass the production format now and keep their rules.
        self.assertTrue(set(b2['retargeted_mutants']) <= set(recorded['r0_format_guard']['mutant_rules']))
        self.assertIn(runner.PRODUCTION + ')', runner.HOST_CONSTRUCTION)
        self.assertIn('"V3"', runner.SELECTED)
        # Every rule is tripped alone by at least one mutant, so none is only ever a bystander.
        alone = {next(iter(rules)) for _, rules in mutants.values() if len(rules) == 1}
        self.assertEqual(alone, set(runner.FORMAT_RULES))
        self.assertEqual(sorted(alone), b2['rules_tripped_alone'])
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
        sections = [name for name in texts if name.startswith(runner.PRODUCTION_NATIVE_PATCH + ':')]
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
        # The same holds for the previous format, the floor's.
        previous = facade.replace('initialize, ' + runner.PRODUCTION + '); }', 'initialize, ' + runner.PREVIOUS + '); }')
        self.assertNotEqual(previous, facade)
        self.assertTrue(runner.facade_violations(texts, previous))
        regressed = runner.guard_mutants()['regression-to-v2'][0]
        self.assertEqual(runner.boot_literal(regressed), runner.PREVIOUS)
        self.assertTrue(runner.facade_violations(regressed, facade))
        self.assertEqual(runner.facade_violations(regressed, previous), [])
        self.assertIsNone(runner.facade_default(facade.replace('    Settings() { this(null, true); }\n', '')))
        self.assertIsNone(runner.boot_literal(runner.guard_mutants()['construction-outside-boot'][0]))

    def test_r0_forward_is_the_one_literal_change(self):
        # Archived: the frozen R0 forward change is the whole difference of the pinned 78456b3 and
        # 24bfb6a patches, and, comments aside, of their host facades.
        old = runner.git_bytes(runner.REVISIONS['7845'], runner.ARCHIVED_PATCH).decode()
        archived = runner.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_PATCH).decode()
        self.assertEqual(runner.archived_r0_forward(old), archived)
        self.assertIsNone(runner.archived_r0_forward(archived))
        self.assertIsNone(runner.archived_r0_forward(old + old))
        code = lambda text: ' '.join(runner.archived_strip_java_comments(text).split())  # noqa: E731
        facade = runner.pinned_bytes('7845', runner.ARCHIVED_FACADE).decode()
        self.assertEqual(code(runner.archived_r0_forward(facade)),
                         code(runner.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_FACADE).decode()))

    def test_b2_forward_is_the_one_literal_change(self):
        # Living: B1's floor, from its pinned Git objects. The forward rule gives the current native
        # patch byte for byte, one byte apart.
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_1']
        old = runner.floor_bytes(runner.NATIVE_PATCH).decode()
        current = runner.integration.PATCH.read_text()
        self.assertEqual(runner.b2_forward(old), current)
        self.assertEqual((len(old), sum(a != b for a, b in zip(old, current))),
                         (len(current), predicted['candidate']['patch_byte_differences']))
        self.assertEqual(runner.sha(current.encode()), predicted['candidate']['patch_sha256'])
        self.assertIsNone(runner.b2_forward(current))
        self.assertIsNone(runner.b2_forward(old + old))
        boot = 'store(' + runner.PREVIOUS + ');\n'
        self.assertEqual(runner.b2_forward(boot), 'store(' + runner.PRODUCTION + ');\n')
        self.assertIsNone(runner.b2_forward(boot + boot))
        self.assertIsNone(runner.b2_forward(runner.b2_forward(boot)))
        self.assertIsNone(runner.b2_forward('store(' + runner.RETIRED + ');\n'))
        # Comments aside, it gives the current host facade from the floor one: the default moves.
        code = lambda text: ' '.join(runner.strip_java_comments(text).split())  # noqa: E731
        facade = runner.floor_bytes(runner.FACADE).decode()
        self.assertEqual(runner.facade_default(facade), runner.PREVIOUS)
        self.assertEqual(code(runner.b2_forward(facade)), code((ROOT / runner.FACADE).read_text()))
        self.assertEqual(runner.facade_default((ROOT / runner.FACADE).read_text()), runner.PRODUCTION)
        # The profile moves only the patch, the adapted Settings and the store helper rows.
        floor, profile = json.loads(runner.floor_bytes(runner.NATIVE_PROFILE)), runner.integration.profile()

        def rows(value):
            """Each scalar by key, and each list row by its key and its name, path or position."""
            result = {}
            for key, item in value.items():
                for index, row in enumerate(item) if isinstance(item, list) else ((None, item),):
                    name = row.get('name', row['path']) if isinstance(row, dict) else index
                    result[key if index is None else '%s/%s' % (key, name)] = row
            return result
        before, after = rows(floor), rows(profile)
        self.assertEqual(set(before), set(after))
        self.assertEqual(sorted(name for name in after if before[name] != after[name]),
                         sorted(predicted['candidate']['changed_profile_rows']))
        self.assertEqual(sum(before[name] == after[name] for name in after),
                         predicted['candidate']['unchanged_profile_rows'])
        settings = 'files/' + runner.integration.SETTINGS
        self.assertEqual((before[settings]['candidate_sha256'], after[settings]['candidate_sha256']),
                         (runner.FLOOR_SETTINGS_SHA256, predicted['candidate']['settings_sha256']))
        self.assertEqual(before[settings]['candidate_sha256'], predicted['floor']['settings_sha256'])
        # The store helper changes two comments, each with its line count, and keeps its code.
        store = 'added/' + runner.integration.PREFIX + 'NativeIdentityStore.java'
        self.assertEqual((before[store]['sha256'], after[store]['sha256']),
                         (predicted['floor']['store_sha256'], predicted['candidate']['store_sha256']))
        old_store, new_store = runner.floor_bytes(runner.STORE).decode(), (ROOT / runner.STORE).read_text()
        self.assertNotEqual(old_store, new_store)
        self.assertEqual([line.rstrip() for line in runner.living_code(old_store).split('\n')],
                         [line.rstrip() for line in runner.living_code(new_store).split('\n')])
        # The floor's pins are its Git objects, read without the working tree.
        self.assertEqual((runner.FLOOR, runner.FLOOR_SHA256[runner.NATIVE_PATCH]),
                         (predicted['floor']['revision'], predicted['floor']['patch_sha256']))
        for path, digest in runner.FLOOR_SHA256.items():
            self.assertEqual(runner.sha(runner.git_bytes(runner.FLOOR, path)), digest, path)
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('working tree read')), \
                mock.patch.object(Path, 'read_text', side_effect=AssertionError('working tree read')):
            self.assertEqual(runner.sha(runner.floor_bytes(runner.NATIVE_PATCH)), runner.FLOOR_SHA256[runner.NATIVE_PATCH])
        with self.assertRaisesRegex(ValueError, 'unpinned floor input'):
            runner.floor_bytes('AGENTS.md')
        with mock.patch.object(runner, 'git_bytes', lambda revision, path: b'drifted'):
            with self.assertRaisesRegex(ValueError, 'floor input drift'):
                runner.floor_bytes(runner.NATIVE_PATCH)

    def test_the_floor_manifest_pins_every_floor_input(self):
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2b']['floor_manifest']
        self.assertEqual(runner.floor_problems(), [])
        self.assertEqual((runner.FLOOR, len(runner.FLOOR_SHA256)), (predicted['revision'], predicted['inputs']))
        self.assertEqual([len(group) for _, group in runner.FLOOR_PIN_GROUPS], predicted['by_group'])
        # Checkpoint 1's four pins of the forward rule are the manifest's own.
        old = {runner.NATIVE_PATCH: '59300e3d12a59dcb33acadc104894fd4b015e9fcc14bf456a09a07aee015a04e',
               runner.NATIVE_PROFILE: '37e180b0b4bf7576aee23be6d7298c4c1af9e1037688523be56c20d59547d8f2',
               runner.FACADE: 'a314430a8f0970cfae1cf8df3e5f1532da7b5eb91e3a206b642c20bc332b5dd1',
               runner.STORE: 'e4cd321662733cc781566689e9c0436d7865010ce446548e5fea9ffbd7b85c57'}
        self.assertEqual({path: runner.FLOOR_SHA256[path] for path in old}, old)
        self.assertEqual(sorted(old), sorted(predicted['forward_pins_unchanged']))
        # The floor's own manifest, not the 24bfb6a archive's: the same paths there often differ.
        archive = runner.manifest(runner.ARCHIVE)
        common = [path for path in runner.FLOOR_SHA256 if path in archive]
        self.assertEqual((len(common), len([path for path in common if archive[path] != runner.FLOOR_SHA256[path]])),
                         (predicted['same_path_in_24bfb6a'], predicted['differing_from_24bfb6a']))
        self.assertEqual(len(runner.FLOOR_SHA256) - len(common), predicted['not_in_24bfb6a'])
        # Each stub tree is pinned whole, the unused XML stub aside; a missing pin is refused.
        for directory in runner.FLOOR_STUB_DIRECTORIES:
            self.assertTrue(runner.floor_paths(runner.FLOOR_PLATFORM + directory + '/'))
        stub = runner.FLOOR_PLATFORM + 'native_principal_xml_stubs/android/system/Os.java'
        with mock.patch.object(runner, 'FLOOR_SHA256', {k: v for k, v in runner.FLOOR_SHA256.items() if k != stub}):
            self.assertIn('floor tree drift', ' '.join(runner.floor_problems()))
        # The floor rebuild takes only fresh scratch outside the repository.
        for place in (ROOT / 'floor-scratch', ROOT):
            with self.subTest(place=place), self.assertRaisesRegex(ValueError, 'floor scratch is not fresh'):
                runner.floor_outputs(Path('unused'), place)
        self.assertFalse((ROOT / 'floor-scratch').exists())

    def test_rollback_copy_count_and_controls_are_predicted(self):
        # The living layouts' current predictions: the retirement layouts are the lifecycle emitter's.
        predictions = json.loads(runner.PREDICTIONS.read_text())['p6_checkpoint_1c']
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

    def test_readers_and_labels(self):
        self.assertEqual(runner.label_problems(), [])
        self.assertEqual(runner.REVISIONS['7845'], '78456b352267dba916778b90d7c926c4e67ef888')
        self.assertEqual(runner.REVISIONS[runner.ARCHIVE], '24bfb6ad3c5c9630faca141a93d3531851e280b8')
        for name, digest in runner.BASELINE_SHA256['7845'].items():
            path = runner.ARCHIVED_FACADE if name == 'Settings' else runner.ARCHIVED_FRAMEWORK_DIR + name + '.java'
            self.assertEqual(runner.sha(runner.git_bytes(runner.REVISIONS['7845'], path)), digest, name)
        # The current sources under Format.V1 read the current layouts as a legacy guard. The models of
        # the 78456b3 rollback reader read the archived layouts from pinned objects.
        self.assertEqual(runner.READERS, (('b1-v1', None, None),))
        self.assertEqual(runner.LEGACY_ROLLBACK, ('b1-v1',))
        self.assertEqual(runner.ARCHIVED_READERS, (('24bf-v1', runner.ARCHIVE, 'b1'), ('c926', 'c926', 'baseline'),
                                                   ('7845', '7845', 'b1')))
        self.assertEqual(set(runner.ARCHIVED_ROLLBACK_READERS), {'24bf-v1', '7845'})
        self.assertEqual({runner.READER_LABELS[target] for target in runner.ARCHIVED_ROLLBACK_READERS},
                         {'rollback-reader'})
        self.assertEqual((runner.READER_LABELS['b1-v1'], runner.READER_LABELS['c926']), ('legacy', 'archived-baseline'))
        labels = {}
        for label, _, classes, _ in runner.HARNESS_LABELS:
            for name in classes:
                labels.setdefault(name, set()).add(label)
        # The lab rehearsal constructs Format.V3, the production format; the lab store fixture reads
        # under Format.V2 and Format.V1 and, since B2 checkpoint 2c, under Format.V3 too; the
        # generator constructs no store.
        self.assertEqual(labels['NativeWriterLabRehearsal'], {'production'})
        self.assertEqual(labels['LabHistoryStoreTest'], {'previous', 'legacy', 'production'})
        self.assertEqual(labels['LabHistoryStore'], {'production'})
        # B1's label of the lifecycle format's runs is retired. Its runs are production, and the
        # Format.V2 runs of the current sources, production in B1, are previous. The floor model of
        # B1's image, from its own pinned sources, has its own label, neither living nor archived.
        self.assertEqual(runner.RUN_LABELS,
                         ('production', 'rollback-reader', 'archived-baseline', 'legacy', 'previous', 'floor-model'))
        self.assertEqual(runner.LIVING_RUN_LABELS, ('production', 'legacy', 'previous'))
        self.assertEqual(runner.FLOOR_RUN_LABELS, ('floor-model',))
        predictions = json.loads(runner.PREDICTIONS.read_text())
        predicted, floor = predictions['b2_checkpoint_2'], predictions['b2_checkpoint_2b']
        self.assertEqual(tuple(floor['run_labels']), runner.RUN_LABELS)
        self.assertEqual(predicted['run_labels'] + ['floor-model'], floor['run_labels'])
        self.assertEqual(floor['label_kinds'], {'living': list(runner.LIVING_RUN_LABELS),
                                                'archived': list(runner.ARCHIVED_RUN_LABELS),
                                                'floor': list(runner.FLOOR_RUN_LABELS)})
        self.assertEqual(predicted['retired_labels'], {'new-format': 'production'})
        # The floor label names two rows: the floor model's own reader check, which resolves in the
        # floor manifest, B1's object, not the working tree's or the archive's; and the guest check,
        # the one working-tree class compiled with the floor's pinned compile set.
        self.assertEqual([row[1:3] for row in runner.HARNESS_LABELS if row[0] == 'floor-model'],
                         [('scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReaderCheck',)),
                          ('scripts/proof/native_lifecycle_record.py', ('NativeLifecycleGuestCheck',))])
        self.assertEqual(labels['NativeLifecycleReaderCheck'], {'previous', 'production', 'floor-model'})
        self.assertEqual(runner.LIVING_FLOOR_CHECKS, ('NativeLifecycleGuestCheck',))
        self.assertEqual(labels['NativeLifecycleGuestCheck'], {'production', 'floor-model'})
        self.assertIsNone(runner.harness_class('NativeLifecycleGuestCheck', floor=True))
        self.assertIsNotNone(runner.harness_class('NativeLifecycleGuestCheck'))
        with mock.patch.object(runner, 'LIVING_FLOOR_CHECKS', ()):
            self.assertIn('labelled host class not found once: floor-model NativeLifecycleGuestCheck',
                          runner.label_problems())
        self.assertEqual(runner.harness_class('NativeLifecycleReaderCheck', floor=True),
                         '%s:%sNativeLifecycleReaderCheck.java' % (runner.FLOOR, runner.FLOOR_PLATFORM))
        self.assertIsNone(runner.harness_class('NativeLifecycleRollbackCheck', floor=True))
        with mock.patch.object(runner, 'HARNESS_LABELS', runner.HARNESS_LABELS + (
                ('floor-model', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleRollbackCheck',), 'x'),)):
            self.assertIn('labelled host class not found once: floor-model NativeLifecycleRollbackCheck',
                          runner.label_problems())
        for change in ({'LIVING_RUN_LABELS': runner.LIVING_RUN_LABELS + ('floor-model',)}, {'FLOOR_RUN_LABELS': ()},
                       {'ARCHIVED_RUN_LABELS': runner.ARCHIVED_RUN_LABELS + ('floor-model',)}):
            with self.subTest(change=sorted(change)), mock.patch.multiple(runner, **change):
                self.assertIn('the living, archived and floor labels do not divide the run labels',
                              runner.label_problems())
        # The rollback checks read under Format.V1, and their discrimination controls under Format.V2,
        # each on the current sources and on archived objects.
        everything = {'rollback-reader', 'previous', 'legacy', 'archived-baseline'}
        self.assertEqual(labels['NativeRollbackReaderCheck'], everything)
        self.assertEqual(labels['NativeRollbackSeedingCheck'], everything)
        # Every Format.V1 read by the current sources is legacy: no living class is rollback-reader.
        # Their lifecycle entry points, their own runs under Format.V3, are production. The version
        # gate's format refusal control under Format.V2, its own entry point, and the future format's
        # Format.V2 refusal twins are previous.
        self.assertEqual(labels['NativeIdentityFutureFormatTest'], {'legacy', 'previous', 'production'})
        self.assertEqual(labels['NativeIdentityVersionGateTest'], {'legacy', 'previous', 'production'})
        self.assertEqual(labels['NativeIdentityPresenceTest'], {'legacy', 'previous', 'production'})
        # Its retirement refusals have Format.V2 twins over copies of the same version 1 states.
        self.assertEqual(labels['NativePrincipalManagerTest'], {'legacy', 'previous'})
        # Their common cases also run as production twins under Format.V3, and so do the counter
        # suite's; the production default check runs the facade's default with its controls.
        self.assertEqual(labels['NativeCreationBindingTest'], {'previous', 'legacy', 'production'})
        self.assertEqual(labels['NativeCreationHistoryTest'], {'previous', 'legacy', 'production'})
        self.assertEqual(labels['NativeCounterAdmissionTest'],
                         {'previous', 'legacy', 'production', 'archived-baseline'})
        self.assertEqual(labels['NativeProductionDefaultTest'], {'production', 'previous', 'legacy'})
        self.assertEqual(runner.step_labels('production default'), ('production', 'previous', 'legacy'))
        # The presence matrix runs one step per format: Format.V2's is previous, and Format.V3's
        # production.
        self.assertEqual(runner.step_labels('presence v2'), ('previous',))
        self.assertEqual(runner.step_labels('presence v3'), ('production',))
        for label, _, classes, _ in runner.HARNESS_LABELS:
            if label == 'rollback-reader':
                for name in classes:
                    if name in runner.LIVING_ROLLBACK_CHECKS:
                        continue
                    self.assertIsNotNone(runner.harness_class(name, archived=True), name)
        # The one named exception: the lifecycle rollback check is a working-tree source under the
        # rollback-reader label alone, compiled only with pinned products, and no pinned object.
        self.assertEqual(runner.LIVING_ROLLBACK_CHECKS, ('NativeLifecycleRollbackCheck',))
        self.assertEqual(labels['NativeLifecycleRollbackCheck'], {'rollback-reader'})
        self.assertIsNotNone(runner.harness_class('NativeLifecycleRollbackCheck'))
        self.assertIsNone(runner.harness_class('NativeLifecycleRollbackCheck', archived=True))
        self.assertEqual(runner.step_labels('b1 focused'), ('previous', 'legacy', 'production'))
        self.assertEqual(runner.step_labels('mutants'), ('previous', 'legacy', 'production'))
        self.assertEqual(runner.step_labels('rollback'), ('legacy', 'previous'))
        self.assertEqual(runner.step_labels('archived rollback'), ('rollback-reader', 'archived-baseline'))
        self.assertEqual(runner.step_labels('readers'), ('previous', 'legacy'))
        self.assertEqual(runner.step_labels('archived readers'), ('archived-baseline', 'rollback-reader'))
        for name in ('NativePrincipalWriterFixtureTest', 'NativePrincipalManagerTest', 'NativeIdentityStoreTest'):
            self.assertIn('legacy', labels[name], name)
        self.assertEqual(runner.step_labels('b0 c926 focused'), ('archived-baseline',))
        self.assertEqual(runner.step_labels('b0 24bf faults'), ('archived-baseline',))
        # The refusals' format twins: b0 b1-v1 refuses again under Format.V2, and b1 faults under
        # Format.V1, on copies of the refused states. Their V3 cases are production.
        self.assertEqual(runner.step_labels('current header faults'), ('legacy', 'previous', 'production'))
        self.assertEqual(runner.step_labels('b1 faults'), ('previous', 'legacy', 'production'))
        # Every step a guarded run records carries labels of its kind: archived or living.
        steps = ['store classes', 'b1 focused', 'b1 faults', 'presence v2', 'production default', 'readers',
                 'rollback', 'archived readers', 'archived rollback', 'mutants',
                 *('b0 %s %s' % (leg, kind) for leg in ('c926', 'd104', '24bf')
                   for kind in ('focused', 'faults')),
                 'current header focused', 'current header faults']
        for step in steps:
            archived = step.rsplit(' ', 1)[0] in runner.ARCHIVED_STEP_NAMES or step in runner.ARCHIVED_STEP_NAMES
            allowed = runner.ARCHIVED_RUN_LABELS if archived else runner.LIVING_RUN_LABELS
            self.assertTrue(set(runner.step_labels(step)) <= set(allowed), step)
        with mock.patch.object(runner, 'HARNESS_LABELS', runner.HARNESS_LABELS + (
                ('retired', 'scripts/proof/native_creation_binding.py', ('Absent',), 'x'),)):
            self.assertTrue(runner.label_problems())
        # The reader rules: each break is refused.
        for change in ({'READER_LABELS': dict(runner.READER_LABELS, **{'b1-v1': 'rollback-reader'})},
                       {'READER_LABELS': {k: v for k, v in runner.READER_LABELS.items() if k != '24bf-v1'}},
                       {'READER_LABELS': dict(runner.READER_LABELS, **{'7845': 'archived-baseline'})},
                       {'ARCHIVED_READERS': (('24bf-v1', None, 'b1'),) + runner.ARCHIVED_READERS[1:]},
                       {'READERS': (('b1-v1', 'c926', 'b1'),)},
                       {'ARCHIVED_ROLLBACK_READERS': runner.ARCHIVED_ROLLBACK_READERS + ('b1-v1',)},
                       {'LEGACY_ROLLBACK': ('7845',)},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'b1 focused': ('previous', 'rollback-reader')})},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'b1 focused': ('new-format', 'legacy')})},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'archived readers': ('production',)})},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'readers': ('floor-model',)})},
                       {'STEP_LABELS': dict(runner.STEP_LABELS, **{'archived rollback': ('floor-model',)})},
                       {'HARNESS_LABELS': runner.HARNESS_LABELS + (
                           ('rollback-reader', 'scripts/proof/native_creation_binding.py',
                            ('NativeIdentityRecordsTest',), 'x'),)}):
            with self.subTest(change=sorted(change)), mock.patch.multiple(runner, **change):
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
        self.assertNotIn('NativeHeaderApi', support)
        stripped = runner.strip_java_comments(support)
        self.assertIn('new PackageManagerService(root, initialize, NativeIdentityStore.Format.V1)', stripped)
        self.assertEqual(stripped.count('new PackageManagerService('), 2)  # V1 facade and earlier twin
        self.assertIn('new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1)', stripped)
        self.assertIn('new NativeIdentityPersistence.CreationPlan(snapshot, rows(snapshot))', stripped)
        self.assertIn('format != NativeIdentityStore.Format.V1 && format != NativeIdentityStore.Format.V2', stripped)
        with self.assertRaisesRegex(ValueError, 'direct APIs'):
            runner.test_sources(['NativeHeaderTestSupport'], adapter='b1')

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
        names = set(runner.FOCUSED_RUNS) | set(runner.FAULT_NAMES)
        for name, expected in predictions['b1_mutants_caught_at_least'].items():
            self.assertTrue(expected and set(expected) <= names, name)
        # The production mutants change only the production format's enum line and are predicted
        # against production twins alone.
        for name, line in runner.PRODUCTION_MUTANTS.items():
            path, replacements, suites = runner.MUTANTS[name]
            self.assertEqual((path, replacements, suites), (runner.STORE, ((runner.PRODUCTION_ENUM, line),),
                                                            ('focused',)))
            self.assertTrue(set(predictions['b1_mutants_caught_at_least'][name]) <= set(runner.PRODUCTION_TWINS))
            store = (ROOT / runner.STORE).read_text()
            changed = [(a, b) for a, b in zip(sources[name][1].split('\n'), store.split('\n')) if a != b]
            self.assertEqual(changed, [(line.rstrip('\n'), runner.PRODUCTION_ENUM.rstrip('\n'))])
        d104 = runner.archived_predictions('binding')['b0_adapted_suite']['d104e15']
        self.assertEqual((len(d104['focused_failures']), len(d104['fault_failures'])), (41, 18))
        # The d104e15 legs are archived: their pinned predictions name the frozen 24bfb6a cases.
        self.assertEqual(set(d104['focused_failures']) | set(d104['focused_controls']),
                         set(runner.ARCHIVED_B0_FOCUSED_NAMES))
        self.assertEqual(set(d104['fault_failures']) | set(d104['fault_controls']),
                         set(runner.ARCHIVED_B0_FAULT_NAMES))
        self.assertEqual((len(runner.FOCUSED_NAMES), len(runner.FAULT_NAMES), len(runner.LAYOUT_NAMES)),
                         (80, 63, 38))

    def test_production_twins_follow_their_cases(self):
        # Each common case of b1 focused prints its production twin right after it, under Format.V3.
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2c']['focused']
        self.assertEqual((len(runner.FOCUSED_NAMES), len(runner.PRODUCTION_TWINS), len(runner.FOCUSED_RUNS),
                          len(runner.NO_TWIN)), (80, 68, 148, 12))
        self.assertEqual((predicted['cases'], predicted['production_twins'], predicted['runs'],
                          predicted['without_twin']), (80, 68, 148, 12))
        self.assertEqual({row['case']: row['twin'] for row in predicted['renamed_twins']}, runner.TWIN_NAMES)
        labels = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2c']['labels']
        self.assertEqual(labels, {step: list(runner.step_labels(step)) for step in labels})
        self.assertEqual(runner.twin_problems(json.loads(runner.PREDICTIONS.read_text())), [])
        runs = list(runner.FOCUSED_RUNS)
        for name in runner.FOCUSED_NAMES:
            if name in runner.NO_TWIN:
                self.assertNotIn(runner.production_twin(name), runs)
                continue
            twin = runner.production_twin(name)
            self.assertEqual(runs[runs.index(name) + 1], twin)
            self.assertTrue(twin.startswith(('V3 / ', 'V3 gate / ')), twin)
        self.assertEqual(runner.production_twin('V2 / an owned flow writes the golden version 2 bytes'),
                         'V3 / an owned flow writes the golden version 2 bytes')
        self.assertEqual(runner.production_twin('V2 gate / header version 3 in store.bin'),
                         'V3 gate / header version 3 in store.bin')
        self.assertEqual(runner.production_twin('low level / relabels and downgrades refuse'),
                         'V3 / low level / relabels and downgrades refuse')
        # The earlier runs keep their names, so the lifecycle runner's case map and refusals still
        # find them, and no twin is an earlier run.
        self.assertFalse(set(runner.PRODUCTION_TWINS) & set(runner.FOCUSED_NAMES))
        source = (ROOT / runner.PLATFORM / 'NativeCreationBindingTest.java').read_text()
        for literal in ('"V2 / pending and unpublished RETIRING pins reserve together"',
                        '"V2 / publication and a later reservation keep version 2, and the marker refuses"',
                        '"signer mutation / Q reserves P with its original signers"',
                        '"signer mutation / a durable P reservation does not strand Q"'):
            self.assertEqual(source.count(literal), 1, literal)
        # Their lifecycle refusals stay in the earlier runs alone.
        self.assertEqual(source.count('if (format != V3) {'), 5)
        # A case without a twin must be a case with a reason, and the twins must cover the rest.
        predictions = json.loads(runner.PREDICTIONS.read_text())
        with mock.patch.dict(runner.NO_TWIN, {'no such case': 'x'}):
            self.assertIn('a case without a twin is no focused case, or has no reason',
                          runner.twin_problems(predictions))
        with mock.patch.object(runner, 'PRODUCTION_TWINS', runner.PRODUCTION_TWINS[1:]):
            self.assertIn('the production twins of b1 focused differ from its cases', runner.twin_problems(predictions))
        broken = json.loads(json.dumps(predictions))
        broken['b1_mutants_caught_at_least']['production-header-ceiling-1'].append(runner.FOCUSED_NAMES[2])
        self.assertIn('production mutant production-header-ceiling-1 is not predicted against production twins alone',
                      runner.twin_problems(broken))

    def test_production_default_check_and_its_routing(self):
        predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_2c']['production_default']
        self.assertEqual((len(runner.DEFAULT_NAMES), len(runner.DEFAULT_CASES)),
                         (predicted['names'], predicted['stores']))
        self.assertEqual(len(runner.default_failures()), predicted['routed']['fails'])
        self.assertEqual(set(runner.default_failures()), {name for name in runner.DEFAULT_NAMES
                                                          if not name.startswith('control / ')})
        # The routed facade differs from the current one only in its default route.
        current = (ROOT / runner.FACADE).read_text()
        for format_name in predicted['routed']['formats']:
            routed = runner.default_facade(format_name)
            changed = [(a, b) for a, b in zip(current.split('\n'), routed.split('\n')) if a != b]
            self.assertEqual(changed, [((runner.DEFAULT_ROUTE % runner.PRODUCTION).rstrip('\n'),
                                        (runner.DEFAULT_ROUTE % ('NativeIdentityStore.Format.' + format_name))
                                        .rstrip('\n'))])
            self.assertEqual(runner.facade_default(routed), 'NativeIdentityStore.Format.' + format_name)
            # The source guard refuses the routed facade too; only the check refuses it at run time.
            self.assertTrue(runner.facade_violations(None, routed))
        # The check's Java holds DEFAULT_CASES and both control sets, which the source checks
        # compare.
        predictions = json.loads(runner.PREDICTIONS.read_text())
        with mock.patch.dict(runner.DEFAULT_DIFFERS, {'V2': runner.DEFAULT_DIFFERS['V2'][1:]}):
            self.assertIn('the default check\'s V2 control differs from DEFAULT_DIFFERS',
                          runner.twin_problems(predictions))
        with mock.patch.object(runner, 'DEFAULT_CASES', runner.DEFAULT_CASES[1:] + runner.DEFAULT_CASES[:1]):
            self.assertIn('the default check holds other stores than DEFAULT_CASES', runner.twin_problems(predictions))
        source = (ROOT / runner.PLATFORM / (runner.DEFAULT_TEST + '.java')).read_text()
        self.assertNotIn('new PackageManagerService(root, initialize, NativeIdentityStore.Format.V3)', source)
        self.assertIn('new PackageManagerService(root, initialize)', source)
        self.assertIn('new PackageManagerService()', source)

    def test_class_differences_compare_every_class_file(self):
        first, second = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, first)
        self.addCleanup(shutil.rmtree, second)
        for root in (first, second):
            (root / 'com/android/server/pm').mkdir(parents=True)
            (root / 'com/android/server/pm/NativeIdentityStore.class').write_bytes(b'same')
            (root / 'com/android/server/pm/NativeIdentityStore$Format.class').write_bytes(b'enum')
        self.assertEqual(runner.archived_class_differences(first, second), [])
        (second / 'com/android/server/pm/NativeIdentityStore$Format.class').write_bytes(b'swapped')
        (second / 'com/android/server/pm/Extra.class').write_bytes(b'x')
        self.assertEqual(runner.archived_class_differences(first, second),
                         ['com/android/server/pm/Extra.class', 'com/android/server/pm/NativeIdentityStore$Format.class'])
        predictions = json.loads(runner.PREDICTIONS.read_text())
        self.assertEqual(predictions['r0_format_guard']['store_class_differences_from_7845'], [])
        self.assertEqual(predictions['p0_archive']['store_class_differences_24bf_7845'], [])
        # Archived: the pinned 24bfb6a and 78456b3 helpers beside the same pinned 24bfb6a sources.
        self.assertEqual(runner.step_labels('store classes'), ('archived-baseline',))
        current, archived = runner.archived_store_sources(runner.ARCHIVE), runner.archived_store_sources('7845')
        self.assertEqual(set(current), set(archived))
        self.assertEqual([name for name in current if current[name] != archived[name]],
                         ['framework/NativeIdentityStore.java'])

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


# The base the repository selects, and a candidate base whose patch directory scratch fixtures put
# beside the production one.
PINNED_PATCHES = 'patches/grapheneos-2026081300'
CANDIDATE_PATCHES = 'patches/grapheneos-2026100600'


def scope_fixture(test):
    """A scratch root holding what the production guard reads, copied from this repository: the
    framework sources, the writer fixture, patches/ and the base records."""
    directory = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, directory)
    for path in ('patches', 'upstream/bases', runner.FRAMEWORK_DIR):
        shutil.copytree(ROOT / path, directory / path)
    (directory / runner.WRITER_FIXTURE).parent.mkdir(parents=True)
    shutil.copyfile(ROOT / runner.WRITER_FIXTURE, directory / runner.WRITER_FIXTURE)
    return directory


def add_candidate(root, boot=None):
    """A candidate patch directory beside the production one: a copy of it, whose native patch's
    boot read passes the given format instead of the production one. It replaces a candidate
    directory of that base copied from this repository."""
    shutil.rmtree(root / CANDIDATE_PATCHES, ignore_errors=True)
    shutil.copytree(root / runner.PRODUCTION_PATCHES, root / CANDIDATE_PATCHES)
    if boot is not None:
        patch = root / CANDIDATE_PATCHES / 'native-principal-pins.patch'
        indent = runner.CONSTRUCTION.split('\n')[-1]
        old, new = ('+%s%s);\n' % (indent, literal) for literal in (runner.PRODUCTION, boot))
        patch.write_text(runner.replace_once(patch.read_text(), old, new))


class ProductionScopeTests(unittest.TestCase):
    """The guard reads the selected base's patch directory and the AOSP track as production. A
    candidate base's directory beside them is never read. Anything else under patches/ is
    refused."""

    def test_production_is_the_selected_base_and_the_aosp_track(self):
        import aosp_patches
        selected = runner.integration.BASE.release
        self.assertEqual(runner.PRODUCTION_PATCHES, 'patches/grapheneos-' + selected)
        self.assertEqual(runner.PRODUCTION_PATCHES, PINNED_PATCHES)
        self.assertEqual(runner.AOSP_TRACK, aosp_patches.SERIES.parent.relative_to(ROOT).as_posix())
        self.assertEqual(runner.AOSP_SERIES, aosp_patches.SERIES.relative_to(ROOT).as_posix())
        # On the pinned base the guard's paths are the paths B1's and B2's images keep.
        self.assertEqual(runner.PRODUCTION_NATIVE_PATCH, runner.NATIVE_PATCH)
        self.assertEqual(runner.integration.PROFILE, ROOT / runner.NATIVE_PROFILE)
        self.assertEqual(runner.PRODUCTION_WRITER_PATCH,
                         PINNED_PATCHES + '/native-identity-writer.patch')
        self.assertEqual(runner.SETTINGS_SECTION,
                         runner.NATIVE_PATCH + ':' + runner.integration.SETTINGS)
        self.assertEqual(runner.ONE_TOKEN_PATHS, {
            'one-token-v1-patch-beside-native': PINNED_PATCHES + '/native-store-format-v1.patch',
            'one-token-v1-patch-other-directory': 'patches/lab/any-name.patch'})
        # The texts are those of the earlier reading of every patch under patches/, in order, but a
        # candidate base's.
        earlier = {path.relative_to(ROOT).as_posix(): path.read_text()
                   for path in sorted((ROOT / runner.FRAMEWORK_DIR).glob('*.java'))}
        for patch in sorted((ROOT / 'patches').rglob('*.patch')):
            top = patch.relative_to(ROOT / 'patches').parts[0]
            if runner.CANDIDATE_PATCHES.fullmatch(top) and 'patches/' + top != PINNED_PATCHES:
                continue
            for target, added in runner.patch_sections(patch.read_text()):
                if target.endswith('.java'):
                    earlier['%s:%s' % (patch.relative_to(ROOT).as_posix(), target)] = added
        earlier[runner.WRITER_FIXTURE] = (ROOT / runner.WRITER_FIXTURE).read_text()
        self.assertEqual(list(runner.production_texts().items()), list(earlier.items()))
        read = {name.split(':')[0].rsplit('/', 1)[0] for name in earlier
                if name.startswith('patches/')}
        self.assertEqual(read, {PINNED_PATCHES, runner.AOSP_TRACK})

    def test_a_candidate_directory_is_never_read_as_production(self):
        root = scope_fixture(self)
        alone = [path.relative_to(root) for path in runner.production_patches(root)]
        add_candidate(root, runner.RETIRED)
        beside = [path.relative_to(root) for path in runner.production_patches(root)]
        self.assertEqual(beside, alone)
        self.assertEqual(alone, [path.relative_to(ROOT) for path in runner.production_patches()])
        texts = runner.production_texts(root)
        self.assertEqual(texts, runner.production_texts())
        self.assertEqual(runner.format_violations(texts), [])
        self.assertEqual([name for name in texts if name.startswith(CANDIDATE_PATCHES + '/')], [])
        # Read as production, the candidate's native patch would trip the guard. Only a check run
        # in a scratch checkout that selects the candidate reads it.
        selected = dict(texts)
        candidate = (root / CANDIDATE_PATCHES / 'native-principal-pins.patch').read_text()
        for target, added in runner.patch_sections(candidate):
            selected['%s:%s' % (runner.PRODUCTION_NATIVE_PATCH, target)] = added
        self.assertEqual(runner.format_rules(selected), {'format', 'v1'})

    def test_an_unknown_or_malformed_entry_under_patches_is_refused(self):
        def planted(path):
            def plant(root):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text('+x\n')
            return plant

        def linked_directory(root):
            shutil.rmtree(root / CANDIDATE_PATCHES)
            shutil.copytree(root / PINNED_PATCHES, root / 'elsewhere')
            (root / CANDIDATE_PATCHES).symlink_to(root / 'elsewhere')

        def linked_record(root):
            record = root / 'upstream/bases/2026100600.json'
            record.rename(root / 'record.json')
            record.symlink_to(root / 'record.json')

        def linked_patch(root):
            target = root / PINNED_PATCHES / 'owner-lifecycle.patch'
            (root / CANDIDATE_PATCHES / 'linked.patch').symlink_to(target)

        def emptied_track(root):
            for entry in (root / runner.AOSP_TRACK).iterdir():
                entry.unlink()

        def series(text):
            def write(root):
                (root / runner.AOSP_SERIES).write_text(text)
            return write

        def series_naming(path, moved):
            # A series that names a patch by a path in the fixture, with the track's own patch
            # moved out or kept.
            def write(root):
                if moved:
                    (root / runner.AOSP_TRACK / aosp['patch']).unlink()
                (root / runner.AOSP_SERIES).write_text(json.dumps(dict(aosp, patch=path(root))))
            return write
        # The AOSP track's patch, as its series record names it.
        aosp = json.loads((ROOT / runner.AOSP_SERIES).read_text())
        track = re.escape(runner.AOSP_TRACK)
        named = 'the AOSP track series names no patch of the track: %s$'
        native = PINNED_PATCHES + '/native-principal-pins.patch'
        cases = (
            ('another directory', planted('patches/lab/any-name.patch'),
             'unknown directory under patches/: patches/lab$'),
            ('a tag of another form', planted('patches/grapheneos-20261006/a.patch'),
             'unknown directory under patches/: patches/grapheneos-20261006$'),
            ('a base without a record', planted('patches/grapheneos-2026090500/a.patch'),
             'patches/grapheneos-2026090500 names no base recorded in upstream/bases'),
            ('a file beside the directories', planted('patches/stray.patch'),
             'unknown entry under patches/, not a directory: patches/stray.patch'),
            ('a nested directory', planted(CANDIDATE_PATCHES + '/nested/a.patch'),
             'malformed patch directory %s: nested' % CANDIDATE_PATCHES),
            ('another kind of file', planted(PINNED_PATCHES + '/native-principal-pins.diff'),
             'malformed patch directory %s: native-principal-pins.diff' % PINNED_PATCHES),
            ('a linked patch', linked_patch,
             'malformed patch directory %s: linked.patch' % CANDIDATE_PATCHES),
            ('a linked directory', linked_directory,
             'unknown entry under patches/, not a directory: ' + CANDIDATE_PATCHES),
            ('a linked record', linked_record, CANDIDATE_PATCHES + ' names no base recorded'),
            ('no production directory', lambda root: shutil.rmtree(root / PINNED_PATCHES),
             'the selected base has no patch directory ' + PINNED_PATCHES),
            ('no AOSP track', lambda root: shutil.rmtree(root / runner.AOSP_TRACK),
             'the AOSP track is missing: %s$' % track),
            ('an emptied AOSP track', emptied_track,
             'the AOSP track has no series record %s/series.json$' % track),
            ('an AOSP track without its patch',
             lambda root: (root / runner.AOSP_TRACK / aosp['patch']).unlink(),
             'the AOSP track series names no patch of the track: %s$'
             % re.escape(repr(aosp['patch']))),
            ('an AOSP series naming another patch',
             series(json.dumps(dict(aosp, patch='other.patch'))),
             "the AOSP track series names no patch of the track: 'other.patch'$"),
            ('an AOSP series that is no record', series('[]\n'),
             'the AOSP track series is not a JSON record'),
            ('an AOSP series naming a production patch by an absolute path',
             series_naming(lambda root: str(root / native), moved=True),
             named % ("'/[^']*/" + re.escape(native) + "'")),
            ('an AOSP series naming its own patch by an absolute path',
             series_naming(lambda root: str(root / runner.AOSP_TRACK / aosp['patch']), moved=False),
             named % ("'/[^']*/" + track + '/' + re.escape(aosp['patch']) + "'")),
            ('an AOSP series naming a production patch outside the track',
             series_naming(lambda root: '../grapheneos-2026081300/native-principal-pins.patch',
                           moved=True),
             named % re.escape("'../grapheneos-2026081300/native-principal-pins.patch'")))
        control = scope_fixture(self)
        add_candidate(control)
        self.assertEqual(len(runner.production_patches(control)), 7)
        for name, edit, pattern in cases:
            with self.subTest(case=name):
                root = scope_fixture(self)
                add_candidate(root)
                edit(root)
                with self.assertRaisesRegex(ValueError, pattern):
                    runner.production_patches(root)
                with self.assertRaisesRegex(ValueError, pattern):
                    runner.production_texts(root)

    def test_the_guard_alone_reports_a_refused_layout_and_its_mutants(self):
        refusal = ValueError('unknown directory under patches/: patches/lab')
        with mock.patch.object(runner, 'production_texts', side_effect=refusal):
            self.assertEqual(runner.format_guard(), ['production texts: ' + str(refusal)])
        drift = ValueError('seam drift')
        with mock.patch.object(runner, 'guard_mutant_problems', side_effect=drift):
            self.assertEqual(runner.format_guard(), ['guard mutants: seam drift'])
        mismatch = ['guard mutant m tripped [], not [v1]']
        with mock.patch.object(runner, 'guard_mutant_problems', return_value=mismatch):
            self.assertEqual(runner.format_guard(), mismatch)


class ArchiveTests(unittest.TestCase):
    """The 24bfb6a archive: one loader of pinned Git objects, the closed working tree, archive code
    that uses no living name, its copies of 24bfb6a code and the frozen expectations of every
    archived leg."""

    def test_every_pin_equals_its_git_object(self):
        # The history and counter admission runners register 0018 and 8949 when one process imports them.
        self.assertTrue({'c926', 'd104', '7845', runner.ARCHIVE} <= set(runner.REVISIONS)
                        <= {'c926', 'd104', '7845', runner.ARCHIVE, '0018', '8949'})
        for revision in sorted(runner.REVISIONS):
            for path, digest in sorted(runner.manifest(revision).items()):
                with self.subTest(revision=revision, path=path):
                    self.assertEqual(runner.sha(runner.git_bytes(runner.REVISIONS[revision], path)), digest)
            for directory in runner.ARCHIVED_STUB_DIRECTORIES:
                prefix = runner.ARCHIVED_PLATFORM + directory + '/'
                tree = runner.git_paths(runner.REVISIONS[revision], prefix)
                self.assertEqual(runner.pinned_paths(revision, prefix),
                                 [path for path in tree if not path.endswith('/Xml.java')])
        # The older products are 24bfb6a's fixtures and stubs but for their own framework sources and
        # facade and the recorded stub differences: nothing else differs.
        for revision in ('c926', 'd104', '7845'):
            pins, archive = runner.manifest(revision), runner.manifest(runner.ARCHIVE)
            differing = {path for path in pins if pins[path] != archive.get(path)}
            recorded = {runner.ARCHIVED_FACADE, *runner.PRODUCT_DIFFERENCES.get(revision, {}),
                        *runner.BASELINE_INPUTS_SHA256.get(revision, {}),
                        *(runner.ARCHIVED_FRAMEWORK_DIR + name + '.java' for name in runner.ARCHIVED_FRAMEWORK)}
            self.assertTrue(differing <= recorded, sorted(differing - recorded))
            self.assertTrue(set(runner.PRODUCT_DIFFERENCES.get(revision, {})) <= differing, revision)
        self.assertEqual(runner.archive_problems(), [])

    def test_pinned_reads_refuse_unpinned_drifted_and_unregistered_objects(self):
        with self.assertRaisesRegex(ValueError, 'unpinned archived input'):
            runner.pinned_bytes(runner.ARCHIVE, 'AGENTS.md')
        with self.assertRaisesRegex(ValueError, 'unregistered archive revision'):
            runner.manifest('0018-absent')
        path = runner.ARCHIVED_PLATFORM + 'NativeRollbackReaderCheck.java'
        real, real_paths = runner.git_bytes, runner.git_paths
        drifted = lambda revision, name: real(revision, name) + (b'\n' if name == path else b'')  # noqa: E731
        with mock.patch.object(runner, 'git_bytes', side_effect=drifted):
            with self.assertRaisesRegex(ValueError, 'archived input drift'):
                runner.pinned_bytes(runner.ARCHIVE, path)
        stubs = runner.ARCHIVED_PLATFORM + 'native_principal_stubs/'
        extra = lambda revision, directory: real_paths(revision, directory) + [directory + 'Extra.java']  # noqa: E731
        with mock.patch.object(runner, 'git_paths', side_effect=extra):
            with self.assertRaisesRegex(ValueError, 'archived tree drift'):
                runner.pinned_paths(runner.ARCHIVE, stubs)
        # The loader reads Git objects, never the working tree: a changed working copy changes nothing.
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('working tree read')):
            self.assertEqual(runner.sha(runner.pinned_bytes(runner.ARCHIVE, path)), runner.ARCHIVE_SHA256[path])

    def test_archived_assembly_reads_no_worktree_file(self):
        target = ROOT / 'AGENTS.md'
        reads = {'read_bytes': target.read_bytes, 'read_text': target.read_text,
                 'open': lambda: open(target).close(),
                 'os.open': lambda: os.close(os.open(target, os.O_RDONLY)),
                 'iterdir': lambda: list(ROOT.iterdir()), 'listdir': lambda: os.listdir(ROOT),
                 'glob': lambda: list((ROOT / runner.FRAMEWORK_DIR).glob('*.java')),
                 'rglob': lambda: list((ROOT / runner.PLATFORM).rglob('*.inc')),
                 'relative': lambda: Path(os.path.relpath(target)).read_bytes()}
        for name, read in reads.items():
            with self.subTest(read=name), runner.worktree_closed():
                with self.assertRaises(runner.WorktreeRead):
                    read()
        # No handler of missing files can take the refusal for one, and it ends with the assembly.
        self.assertFalse(issubclass(runner.WorktreeRead, OSError))
        self.assertTrue(target.read_bytes())
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside)
        (outside / 'file').write_bytes(b'x')
        with runner.worktree_closed():
            self.assertEqual((outside / 'file').read_bytes(), b'x')
        # Every archived leg assembles with the tree closed. Each input is a pinned object, or the
        # archived seams injected into a pinned store or strict writer.
        legs = runner.archived_inputs()
        self.assertEqual(len(legs), 18)
        pinned = {digest for revision in runner.REVISIONS for digest in runner.manifest(revision).values()}
        injected = set()
        for revision in ('c926', 'd104', runner.ARCHIVE):
            for name, seams in (('framework/NativeIdentityStore.java', runner.ARCHIVED_STORE_SEAMS),
                                ('fixtures/ResilientAtomicFile.java', runner.ARCHIVED_WRITER_SEAMS)):
                source = runner.archived_product_sources(revision)[name].decode()
                injected.add(runner.sha(runner.archived_inject(source, seams).encode()))
        for leg, files in sorted(legs.items()):
            for name, data in sorted(files.items()):
                with self.subTest(leg=leg, name=name):
                    self.assertIn(runner.sha(data), pinned | injected)
        # A leak in an archived assembly raises: here the loader reads the working tree instead.
        with mock.patch.object(runner, 'pinned_bytes', lambda revision, path: (ROOT / path).read_bytes()):
            with self.assertRaises(runner.WorktreeRead):
                runner.archived_inputs()
        # Living assemblies read the current sources, as they must.
        living = runner.test_sources(['NativeCreationBindingLayouts'])
        self.assertEqual(living['tests/NativeCreationBindingLayouts.java'],
                         (ROOT / runner.PLATFORM / 'NativeCreationBindingLayouts.java').read_bytes())

    def test_archived_seams_enter_every_pinned_store_and_writer_once(self):
        for revision in ('c926', 'd104', runner.ARCHIVE):
            files = runner.archived_with_seams(runner.archived_product_sources(revision))
            for name, seams in (('framework/NativeIdentityStore.java', runner.ARCHIVED_STORE_SEAMS),
                                ('fixtures/ResilientAtomicFile.java', runner.ARCHIVED_WRITER_SEAMS)):
                text = files[name].decode()
                self.assertEqual(text.count('NativeHeaderWriteFaults.at('), len(seams), (revision, name))
                for _, _, _, step, _ in seams:
                    self.assertEqual(text.count('NativeHeaderWriteFaults.at("%s", ' % step), 1, (revision, step))

    def test_frozen_expectations_are_the_24bfb6a_constants(self):
        revision = runner.REVISIONS[runner.ARCHIVE]
        b0 = historical_constants(revision, 'scripts/proof/tests/test_native_header_footprint.py', (
            'FOCUSED', 'FAULTS', 'STEPS', 'FOCUSED_NAMES', 'FAULT_NAMES', 'STORE_SEAMS', 'WRITER_SEAMS'))
        self.assertEqual(runner.ARCHIVED_STEPS, b0['STEPS'])
        self.assertEqual(runner.ARCHIVED_B0_FOCUSED_NAMES, b0['FOCUSED_NAMES'])
        self.assertEqual(runner.ARCHIVED_B0_FAULT_NAMES, b0['FAULT_NAMES'])
        self.assertEqual((runner.ARCHIVED_STORE_SEAMS, runner.ARCHIVED_WRITER_SEAMS),
                         (b0['STORE_SEAMS'], b0['WRITER_SEAMS']))
        self.assertEqual((runner.ARCHIVED_B0_TESTS['focused'][1], runner.ARCHIVED_B0_TESTS['faults'][1]),
                         (b0['FOCUSED'], b0['FAULTS']))
        b1 = historical_constants(revision, 'scripts/proof/native_creation_binding.py', (
            'PLATFORM', 'FRAMEWORK_DIR', 'FRAMEWORK', 'STUB_DIRECTORIES', 'ORIGINAL_B0_SHA256',
            'ROLLBACK_COPY_LAYOUTS', 'ROLLBACK_CONTROLS', 'LAYOUT_NAMES', 'FACADE', 'CONSTRUCTION',
            'PRODUCTION', 'RETIRED', 'NATIVE_PATCH', 'STORE'), {'STEPS': b0['STEPS']})
        self.assertEqual((runner.ARCHIVED_PLATFORM, runner.ARCHIVED_FRAMEWORK_DIR, runner.ARCHIVED_STUB_DIRECTORIES),
                         (b1['PLATFORM'], b1['FRAMEWORK_DIR'], b1['STUB_DIRECTORIES']))
        self.assertEqual((runner.ARCHIVED_FACADE, runner.ARCHIVED_STORE, runner.ARCHIVED_PATCH),
                         (b1['FACADE'], b1['STORE'], b1['NATIVE_PATCH']))
        self.assertEqual((runner.ARCHIVED_CONSTRUCTION, runner.ARCHIVED_PRODUCTION, runner.ARCHIVED_RETIRED),
                         (b1['CONSTRUCTION'], b1['PRODUCTION'], b1['RETIRED']))
        self.assertEqual(runner.ARCHIVED_FRAMEWORK, b1['FRAMEWORK'])
        self.assertEqual(runner.ORIGINAL_B0_SHA256, b1['ORIGINAL_B0_SHA256'])
        self.assertEqual(runner.ARCHIVED_LAYOUT_NAMES, b1['LAYOUT_NAMES'])
        self.assertEqual((runner.ARCHIVED_COPY_LAYOUTS, runner.ARCHIVED_ROLLBACK_CONTROLS),
                         (b1['ROLLBACK_COPY_LAYOUTS'], b1['ROLLBACK_CONTROLS']))
        # The pinned 24bfb6a profile lists exactly these helpers and fragments, and the Settings output.
        profile = json.loads(runner.pinned_bytes(runner.ARCHIVE, runner.ARCHIVED_PROFILE))
        self.assertEqual({row['name']: row['source'] for row in profile['fragments']}, runner.ARCHIVED_FRAGMENTS)
        self.assertEqual([row['source'] for row in profile['added']],
                         [runner.ARCHIVED_FRAMEWORK_DIR + name + '.java' for name in runner.ARCHIVED_FRAMEWORK])
        self.assertIn(runner.ARCHIVED_SETTINGS, [row['path'] for row in profile['files']])
        # The living P0 record repeats the counts the archived expectations hold.
        predictions = json.loads(runner.PREDICTIONS.read_text())
        predicted = predictions['p0_archive']
        self.assertIn('PREDICTED', predicted['status'])
        self.assertEqual(predicted['revision'], revision)
        self.assertEqual(predicted['b0']['cases'], {'focused': 53, 'faults': 27})
        d104 = runner.archived_predictions('binding')['b0_adapted_suite']['d104e15']
        self.assertEqual(predicted['b0']['d104'], {'focused_failures': len(d104['focused_failures']),
                                                   'fault_failures': len(d104['fault_failures'])})
        self.assertEqual((predicted['archived_layouts'], predicted['archived_copy_layouts']), (47, 43))
        self.assertEqual(predicted['archived_readers'],
                         {target: len(runner.ARCHIVED_LAYOUT_NAMES) for target, _, _ in runner.ARCHIVED_READERS})
        rollback = len(runner.ARCHIVED_LAYOUT_NAMES) + len(runner.ARCHIVED_ROLLBACK_CONTROLS) + 1
        self.assertEqual(predicted['archived_rollback'],
                         {target: rollback for target in runner.ARCHIVED_ROLLBACK_READERS})
        current = json.loads(runner.PREDICTIONS.read_text())['p6_checkpoint_1c']
        self.assertEqual(current['living_readers'],
                         {target: len(runner.LAYOUT_NAMES) for target, _, _ in runner.READERS})
        living = len(runner.LAYOUT_NAMES) + len(runner.ROLLBACK_CONTROLS) + 1
        self.assertEqual(current['living_rollback'], {target: living for target in runner.LEGACY_ROLLBACK})
        self.assertEqual(predicted['relabelled'],
                         {target: runner.READER_LABELS[target] for target, _, _ in runner.READERS})
        # A frozen list that the pinned predictions no longer state is refused.
        for name, kind in (('ARCHIVED_LAYOUT_NAMES', 'layout'), ('ARCHIVED_B0_FAULT_NAMES', 'B0')):
            with mock.patch.object(runner, name, getattr(runner, name)[1:]):
                self.assertEqual(runner.archive_problems(),
                                 ['archived %s expectations differ from the pinned predictions' % kind])

    def test_frozen_code_is_the_24bfb6a_code(self):
        binding, b0 = 'scripts/proof/native_creation_binding.py', 'scripts/proof/tests/test_native_header_footprint.py'
        for frozen, original in (('archived_replace_once', 'replace_once'),
                                 ('archived_strip_java_comments', 'strip_java_comments'),
                                 ('archived_outcome', 'outcome'), ('archived_class_differences', 'class_differences'),
                                 ('archived_copy_layouts', 'copy_layouts'),
                                 ('archived_rollback_names', 'rollback_names')):
            frozen_matches(self, runner, frozen, binding, original)
        frozen_matches(self, runner, 'archived_r0_forward', binding, 'r0_forward',
                       {'ARCHIVED_RETIRED': 'RETIRED', 'ARCHIVED_PRODUCTION': 'PRODUCTION'})
        frozen_matches(self, runner, 'archived_suite', binding, 'suite',
                       {'archived_build': 'build', 'archived_execute': 'execute'})
        frozen_matches(self, runner, 'archived_with_seams', binding, 'with_seams', replacements=(
            ('b0.inject(\n        files[\'framework', 'archived_inject(\n        files[\'framework'),
            ('b0.inject(\n        files[\'fixtures', 'archived_inject(\n        files[\'fixtures'),
            ('b0.STORE_SEAMS', 'ARCHIVED_STORE_SEAMS'), ('b0.WRITER_SEAMS', 'ARCHIVED_WRITER_SEAMS')))
        # The tools start as finding the hardened start: in their work directory, without an
        # inherited class path, and with neither implicit sources nor annotation processing.
        frozen_matches(self, runner, 'archived_build', binding, 'build', replacements=(
            ("'-Werror',", "'-Werror', '-implicit:none', '-proc:none',"),
            ('timeout=300)', 'timeout=300, cwd=work, env=archived_tool_environment())')))
        frozen_matches(self, runner, 'archived_execute', binding, 'execute', replacements=(
            ('timeout=timeout)', 'timeout=timeout, cwd=work, env=archived_tool_environment())'),
            ('b0.passed_checks(', 'archived_passed_checks('), ('b0.failed_checks(', 'archived_failed_checks(')))
        for frozen, original in (('archived_passed_checks', 'passed_checks'),
                                 ('archived_failed_checks', 'failed_checks')):
            frozen_matches(self, runner, frozen, b0, original)
        frozen_matches(self, runner, 'archived_inject', b0, 'inject', {'archived_replace_once': 'replace_once'})
        # A changed copy no longer matches.
        with self.assertRaises(AssertionError):
            frozen_matches(self, runner, 'archived_outcome', binding, 'suite')

    def test_archive_uses_no_living_name(self):
        self.assertEqual(runner.boundary_problems(), [])
        text = Path(runner.__file__).read_text()
        foreign = {'b0': None, 'integration': None}
        for name, old, new, problem in (
                ('living function', 'timeout=300, cwd=work, env=archived_tool_environment()',
                 'timeout=300, cwd=work, env=tool_environment()',
                 'archive function archived_build uses living tool_environment'),
                ('living constant', "    for name in ARCHIVED_FRAMEWORK:\n        files['framework/%s.java'",
                 "    for name in FRAMEWORK:\n        files['framework/%s.java'",
                 'archive function archived_product_sources uses living FRAMEWORK'),
                ('living module', "    return re.findall(r'^PASS (.+)$', stdout, re.M)",
                 '    return b0.passed_checks(stdout)',
                 'archive function archived_passed_checks uses b0.passed_checks'),
                # Module level archive data, built from living names or from a module that is no archive.
                ('archive data', "ARCHIVED_FIXTURES = tuple(ARCHIVED_PLATFORM + name + '.java.inc'",
                 "ARCHIVED_FIXTURES = tuple(PLATFORM + name + '.java.inc'",
                 'archive data ARCHIVED_FIXTURES uses living PLATFORM'),
                ('shared data', "    for revision in ('c926', 'd104')}\n",
                 "    for revision in ('c926', 'd104')}\nPRODUCT_DIFFERENCES.update(BASELINE_FRAMEWORK=FRAMEWORK)\n",
                 'archive data PRODUCT_DIFFERENCES.update uses living FRAMEWORK'),
                ('archive data of another module', "ARCHIVED_STEPS = ('seed-synced', ",
                 "ARCHIVED_STEPS = b0.STEPS or ('seed-synced', ",
                 'archive data ARCHIVED_STEPS uses b0.STEPS')):
            with self.subTest(name=name):
                self.assertEqual(text.count(old), 1, name)
                mutated = text.replace(old, new, 1)
                self.assertEqual(runner.archive_boundary(mutated, runner.ARCHIVE_SHARED, foreign), [problem])

    def test_archive_shares_only_its_loader_and_pins(self):
        # Every name the archive uses without the archived prefix is the Git reader, the loader, its
        # closed tree guard and the archive's own check, or pinned revision data; nothing that looks
        # living is archive code or data.
        loader = {'ROOT', 'CLOSED_ROOT', 'READ_EVENTS', 'SPAWN_EVENTS', '_CLOSED', '_SEALED', '_LOADER', 'WorktreeRead',
                  'sha', 'git_bytes', 'git_paths', 'manifest', 'pinned_bytes', 'pinned_paths', 'worktree_closed',
                  'outside_repository', '_refuse_worktree_reads', 'archive_problems'}
        for name in sorted(set(runner.ARCHIVE_SHARED) - loader):
            self.assertTrue(pin_data(getattr(runner, name)), name)
        for name in ('ARCHIVED_ROLLBACK_READERS', 'ARCHIVED_PIN_GROUPS', 'ARCHIVED_STEPS'):
            self.assertFalse(pin_data(getattr(runner, name)), name)

    def test_archived_runs_call_no_living_code(self):
        def archived_run(work):
            with mock.patch.object(runner.subprocess, 'run', fake_tools(layouts)):
                steps, problems = runner.archived_qualify(work)
            return json.loads(json.dumps([steps, problems], default=str).replace(str(work), 'WORK'))
        layouts = runner.ARCHIVED_LAYOUT_NAMES
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        expected = archived_run(work / 'first')
        self.assertTrue({'store classes', 'b0 c926 focused', 'b0 24bf faults', 'archived readers',
                         'archived rollback'} <= set(expected[0]))
        # Every living function and constant a later package may change, and the B0 runner's code:
        # the archived steps run without them and record the same.
        living_code_broken(self, runner, ('build', 'execute', 'suite', 'outcome', 'with_seams', 'product_sources',
                                          'store_sources', 'test_sources', 'current_header_suite', 'b1_suite', 'b2_forward',
                                          'floor_bytes', 'floor_outputs', 'floor_forward',
                                          'floor_patch_outputs', 'floor_paths', 'floor_problems',
                                          'copy_layouts', 'rollback_names', 'replace_once', 'strip_java_comments',
                                          'tool_environment'))
        living_code_broken(self, runner.b0, ('passed_checks', 'failed_checks', 'inject'))
        with mock.patch.multiple(runner, PRODUCTION='x', PREVIOUS='w', RETIRED='y', CONSTRUCTION='z', FRAMEWORK=(),
                                 PLATFORM='x/', FRAMEWORK_DIR='x/', LAYOUT_NAMES=(), ROLLBACK_CONTROLS=(),
                                 ROLLBACK_COPY_LAYOUTS=0, PREDICTIONS=work / 'absent.json', STEPS=()), \
                mock.patch.multiple(runner.b0, STORE_SEAMS=(), WRITER_SEAMS=(), FOCUSED_NAMES=(), FAULT_NAMES=(),
                                    STEPS=()):
            self.assertEqual(archived_run(work / 'second'), expected)

    def test_tools_start_in_their_work_directory_without_an_inherited_class_path(self):
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            return mock.Mock(returncode=0, stdout='PASS a\n', stderr='')
        with mock.patch.dict(os.environ, {'CLASSPATH': '/elsewhere'}), mock.patch.object(runner.subprocess, 'run', run):
            for build, execute in ((runner.build, runner.execute), (runner.archived_build, runner.archived_execute)):
                build(work / build.__name__, {'tests/A.java': b'class A {}'})
                execute(work / build.__name__, 'A', [])
        self.assertEqual(len(calls), 4)
        for args, kwargs in calls:
            self.assertEqual(kwargs['cwd'].parent, work)
            self.assertNotIn('CLASSPATH', kwargs['env'])
            self.assertEqual(kwargs['env']['PATH'], os.environ['PATH'])
        for args, _ in (calls[0], calls[2]):
            self.assertEqual(args[0], 'javac')
            self.assertIn('-implicit:none', args)
            self.assertIn('-proc:none', args)
        for args, _ in (calls[1], calls[3]):
            self.assertEqual((args[0], args[args.index('-cp') + 1].rsplit('/', 1)[1]), ('java', 'classes'))

    def test_labelled_classes_resolve_where_their_runs_come_from(self):
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty)
        # An archived row resolves its classes in the archive alone, a living row in the working tree alone.
        pinned = '%s:%sUnsupportedCounterProbe.java' % (runner.REVISIONS[runner.ARCHIVE], runner.ARCHIVED_PLATFORM)
        self.assertEqual(runner.harness_class('UnsupportedCounterProbe', archived=True), pinned)
        self.assertIsNone(runner.harness_class('NativeIdentityRecordsTest', archived=True))
        self.assertIsNotNone(runner.harness_class('NativeIdentityRecordsTest'))
        with mock.patch.object(runner, 'ROOT', empty):
            # A class deleted from the working tree fails its living rows, though the archive keeps it.
            self.assertIsNone(runner.harness_class('UnsupportedCounterProbe'))
            self.assertIsNotNone(runner.harness_class('UnsupportedCounterProbe', archived=True))
            # A floor-model row resolves in the floor manifest alone.
            self.assertIsNotNone(runner.harness_class('NativeLifecycleReaderCheck', floor=True))
        self.assertIsNone(runner.harness_class('UnsupportedCounterProbe', floor=True))


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


if PINNED:
    class FloorForwardTests(unittest.TestCase):
        """B2 against B1's floor over the pinned canonical framework copies. A test case only when
        ANDRIX_PINNED_FRAMEWORK names them."""

        def test_the_floor_outputs_move_only_the_boot_literal(self):
            predicted = json.loads(runner.PREDICTIONS.read_text())['b2_checkpoint_1']
            record, problems = runner.floor_forward(Path(PINNED))
            self.assertEqual(problems, [])
            settings = runner.integration.SETTINGS
            self.assertEqual((record['revision'], record['differing'], record['settings_forward']),
                             (predicted['floor']['revision'], [settings], True))
            self.assertEqual(record['outputs'][settings], predicted['floor']['settings_sha256'])
            self.assertEqual(record['settings_byte_differences'], predicted['candidate']['settings_byte_differences'])
            self.assertEqual(len(record['outputs']) - len(record['differing']),
                             predicted['candidate']['other_outputs_equal'])
            current = runner.verify_candidate(Path(PINNED))
            self.assertEqual(current[settings], {'sha256': predicted['candidate']['settings_sha256'],
                                                 'candidate': True})
            self.assertEqual({name for name in current if current[name]['sha256'] != record['outputs'][name]},
                             {settings})


if __name__ == '__main__':
    unittest.main()
