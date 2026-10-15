# SPDX-License-Identifier: Apache-2.0
"""The strict JSON Schema subset validator: each keyword passes its instance and fails its contrary
one, strict loading refuses duplicate keys and nonfinite numbers, patterns keep their ECMA-262
meaning, and a schema with a keyword or form the module does not implement is refused before it
validates anything."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import json_schema  # noqa: E402

REF = {'type': 'object', 'additionalProperties': False, 'required': ['path', 'sha256'],
       'properties': {'path': {'type': 'string', 'minLength': 1},
                      'sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}}}
LEDGER = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:example:ledger', 'title': 'x',
    'type': 'object', 'additionalProperties': False, 'required': ['rows', 'status'],
    'properties': {
        'status': {'enum': ['planned', 'qualified']},
        'rows': {'type': 'object', 'additionalProperties': False, 'required': ['a', 'b'],
                 'properties': {'a': {'$ref': '#/$defs/row'}, 'b': {'$ref': '#/$defs/row'}}}},
    '$defs': {'ref': REF,
              'row': {'type': 'object', 'additionalProperties': False, 'required': ['status', 'evidence'],
                      'properties': {'status': {'enum': ['planned', 'qualified']},
                                     'evidence': {'anyOf': [{'$ref': '#/$defs/ref'}, {'type': 'null'}]}},
                      'allOf': [{'if': {'properties': {'status': {'const': 'qualified'}}},
                                 'then': {'properties': {'evidence': {'$ref': '#/$defs/ref'}}}}]}},
    'allOf': [{'if': {'properties': {'status': {'const': 'qualified'}}},
               'then': {'properties': {'rows': {'properties': {
                   name: {'properties': {'status': {'const': 'qualified'}}} for name in ('a', 'b')}}}}}]}
DIGEST = 'ab' * 32


def ledger(status='planned', a='planned', b='planned', evidence=None):
    row = lambda value: {'status': value, 'evidence': evidence if value == 'qualified' else None}
    return {'status': status, 'rows': {'a': row(a), 'b': row(b)}}


class LoadingTests(unittest.TestCase):
    def test_strict_loading(self):
        self.assertEqual(json_schema.loads('{"a": [1, 2.5, null, true]}'), {'a': [1, 2.5, None, True]})
        self.assertEqual(json_schema.loads(b'{"a": 1}'), {'a': 1})
        for text in ('{"a": 1, "a": 1}', '{"a": {"b": 1, "b": 2}}', '[NaN]', '[Infinity]', '[-Infinity]',
                     '{"a": 1', b'\xff', 7):
            with self.subTest(text=text), self.assertRaises(ValueError):
                json_schema.loads(text)

    def test_a_number_beyond_a_double_is_refused(self):
        # The controls: the largest finite magnitudes load, and an underflow is a finite zero.
        self.assertEqual(json_schema.loads('[1e308, -1.7976931348623157e308, 1e-400]'),
                         [1e308, -1.7976931348623157e308, 0.0])
        for text in ('{"a": 1e400}', '[-1e400]', '[1E999]', '[2e308]'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'nonfinite'):
                json_schema.loads(text)


class KeywordTests(unittest.TestCase):
    def valid(self, instance, schema):
        return json_schema.validate(instance, schema) == []

    def test_types_keep_booleans_apart_from_numbers(self):
        for instance, name in ((None, 'null'), (True, 'boolean'), ({}, 'object'), ([], 'array'), ('x', 'string'),
                               (3, 'integer'), (3.0, 'integer'), (3.5, 'number'), (3, 'number')):
            with self.subTest(instance=instance, name=name):
                self.assertTrue(self.valid(instance, {'type': name}))
        for instance, name in ((True, 'integer'), (False, 'number'), (1, 'boolean'), (3.5, 'integer'), ('1', 'number'),
                               (None, 'object'), ([], 'object'), ({}, 'array')):
            with self.subTest(instance=instance, name=name):
                self.assertFalse(self.valid(instance, {'type': name}))
        self.assertTrue(self.valid(None, {'type': ['string', 'null']}))
        self.assertFalse(self.valid(1, {'type': ['string', 'null']}))

    def test_const_enum_and_json_equality(self):
        self.assertTrue(self.valid(1, {'const': 1.0}))
        self.assertFalse(self.valid(True, {'const': 1}))
        self.assertFalse(self.valid(1, {'const': True}))
        self.assertTrue(self.valid({'a': [1, None]}, {'const': {'a': [1.0, None]}}))
        self.assertFalse(self.valid({'a': [1, None]}, {'const': {'a': [None, 1]}}))
        self.assertTrue(self.valid('B2', {'enum': ['B1', 'B2']}))
        self.assertFalse(self.valid(0, {'enum': [False, None]}))
        self.assertTrue(self.valid([1, 2], {'uniqueItems': True}))
        self.assertFalse(self.valid([1, 1.0], {'uniqueItems': True}))
        self.assertTrue(self.valid([1, True], {'uniqueItems': True}))

    def test_objects_arrays_strings_and_numbers(self):
        schema = {'type': 'object', 'required': ['a'], 'properties': {'a': {'type': 'integer', 'minimum': 1,
                                                                          'maximum': 3}},
                  'additionalProperties': False}
        self.assertTrue(self.valid({'a': 2}, schema))
        for instance in ({}, {'a': 0}, {'a': 4}, {'a': 2, 'b': 1}, {'a': '2'}):
            with self.subTest(instance=instance):
                self.assertFalse(self.valid(instance, schema))
        # Keywords of another type's instance do not apply.
        self.assertTrue(self.valid('x', {'minimum': 3, 'required': ['a'], 'minItems': 2}))
        array = {'type': 'array', 'items': {'type': 'string', 'minLength': 1, 'maxLength': 2,
                                            'pattern': '^[a-z]+$'}, 'minItems': 1, 'maxItems': 2}
        self.assertTrue(self.valid(['ab', 'c'], array))
        for instance in ([], ['a', 'b', 'c'], [''], ['abc'], ['A'], [1]):
            with self.subTest(instance=instance):
                self.assertFalse(self.valid(instance, array))
        # A pattern is searched, not matched whole, as JSON Schema defines it.
        self.assertTrue(self.valid('xay', {'pattern': 'a'}))
        self.assertFalse(self.valid('xay', {'pattern': '^a$'}))

    def test_applicators(self):
        either = {'anyOf': [{'type': 'string'}, {'type': 'null'}]}
        self.assertTrue(self.valid(None, either))
        self.assertFalse(self.valid(1, either))
        one = {'oneOf': [{'type': 'integer'}, {'minimum': 2}]}
        self.assertTrue(self.valid(1, one))
        self.assertFalse(self.valid(3, one))
        self.assertFalse(self.valid('x', {'oneOf': [{'type': 'integer'}, {'type': 'number'}]}))
        self.assertTrue(self.valid('x', {'not': {'type': 'integer'}}))
        self.assertFalse(self.valid(1, {'not': {'type': 'integer'}}))
        conditional = {'if': {'type': 'integer'}, 'then': {'minimum': 5}, 'else': {'type': 'string'}}
        for instance, expected in ((6, True), (4, False), ('x', True), (None, False)):
            with self.subTest(instance=instance):
                self.assertEqual(self.valid(instance, conditional), expected)
        self.assertTrue(self.valid(1, {'allOf': [{'type': 'integer'}, {'minimum': 1}]}))
        self.assertFalse(self.valid(0, {'allOf': [{'type': 'integer'}, {'minimum': 1}]}))
        self.assertTrue(self.valid(1, True))
        self.assertFalse(self.valid(1, False))

    def test_references_apply_beside_their_siblings(self):
        schema = {'$defs': {'small': {'maximum': 3}}, '$ref': '#/$defs/small', 'minimum': 2}
        self.assertTrue(self.valid(2, schema))
        self.assertFalse(self.valid(1, schema))
        self.assertFalse(self.valid(4, schema))
        escaped = {'$defs': {'a/b': {'type': 'string'}, 'c~d': {'type': 'integer'}},
                   'properties': {'x': {'$ref': '#/$defs/a~1b'}, 'y': {'$ref': '#/$defs/c~0d'}}}
        self.assertTrue(self.valid({'x': 's', 'y': 1}, escaped))
        self.assertFalse(self.valid({'x': 1, 'y': 's'}, escaped))
        recursive = {'$defs': {'tree': {'type': 'array', 'items': {'$ref': '#/$defs/tree'}}}, '$ref': '#/$defs/tree'}
        self.assertTrue(self.valid([[[]], []], recursive))
        self.assertFalse(self.valid([[1]], recursive))

    def test_errors_name_their_instance(self):
        errors = json_schema.validate({'rows': {'a': {'status': 'qualified', 'evidence': None}}, 'status': 'x'},
                                      LEDGER)
        joined = ' '.join(errors)
        self.assertIn('/rows: required member b is absent', joined)
        self.assertIn('/rows/a/evidence: not of type object', joined)
        self.assertIn('/status: not one of', joined)


class PatternTests(unittest.TestCase):
    """Patterns as ECMA-262 without flags reads them, each case beside its control."""

    def matches(self, instance, pattern):
        return json_schema.validate(instance, {'type': 'string', 'pattern': pattern}) == []

    def test_the_end_anchor_never_matches_before_a_final_newline(self):
        digest, boot = 'ab' * 32, '01234567-89ab-4def-8123-456789abcdef'
        uuid = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        for instance, pattern in ((digest, '^[0-9a-f]{64}$'), (boot, uuid), ('cd' * 16, '^[0-9a-f]{32}$'),
                                  ('xab', 'b$')):
            with self.subTest(pattern=pattern):
                self.assertTrue(self.matches(instance, pattern))
                for suffix in ('\n', '\r', '\r\n', ' '):
                    self.assertFalse(self.matches(instance + suffix, pattern))

    def test_the_dot_and_the_ascii_classes(self):
        self.assertTrue(self.matches('axb', '^a.b$'))
        for terminator in ('\n', '\r', '\u2028', '\u2029'):
            self.assertFalse(self.matches('a%sb' % terminator, '^a.b$'))
        self.assertTrue(self.matches('a\x85b', '^a.b$'))
        self.assertTrue(self.matches('7', '^\\d$'))
        self.assertFalse(self.matches('\u0663', '^\\d$'))
        self.assertTrue(self.matches('\u0663', '^\\D$'))
        self.assertTrue(self.matches('a_1', '^\\w+$'))
        self.assertFalse(self.matches('\u00e9', '^\\w$'))
        # A non-ASCII letter is no word character, so a boundary stands before the word.
        self.assertTrue(self.matches('\u00e9foo', '\\bfoo'))
        self.assertFalse(self.matches('afoo', '\\bfoo'))

    def test_patterns_run_over_utf16_code_units(self):
        emoji = '\U0001F600'
        self.assertFalse(self.matches(emoji, '^.$'))
        self.assertTrue(self.matches(emoji, '^..$'))
        self.assertTrue(self.matches(emoji, '^%s$' % emoji))
        self.assertTrue(self.matches(emoji, '^\\ud83d\\ude00$'))
        # A class lists code units: the character's two units are two members.
        self.assertFalse(self.matches(emoji, '^[%s]$' % emoji))
        self.assertTrue(self.matches(emoji, '^[%s]{2}$' % emoji))
        self.assertEqual(json_schema.validate(emoji, {'minLength': 1, 'maxLength': 1}), [])

    def test_escapes_classes_and_quantifiers(self):
        for instance, pattern, expected in (('A', '^\\x41$', True), ('\u00e9', '^\\u00e9$', True), ('.', '^\\.$', True),
                                            ('x', '^\\.$', False), ('-', '^[\\-a]$', True), ('b', '^[a-c-]$', True),
                                            ('-', '^[a-c-]$', True), ('d', '^[a-c-]$', False), ('\t', '^\\t$', True),
                                            ('aaa', '^a{2,3}?$', True), ('a', '^a{2,}$', False),
                                            ('cdab', '^(?:ab|cd)+$', True), ('x/y', '^x\\/y$', True),
                                            ('q', '^[^a-c]$', True), ('b', '^[^a-c]$', False)):
            with self.subTest(pattern=pattern, instance=instance):
                self.assertEqual(self.matches(instance, pattern), expected)

    def test_syntax_outside_the_subset_is_refused(self):
        self.assertTrue(self.matches('a', 'a'))
        for pattern in ('\\s', '\\S', '(?=a)', '(?!a)', '(?<=a)', '(?P<n>a)', '(?<n>a)', '\\1', '\\k<n>', '[[a]]',
                        '[]', '[^]', 'a{2,1}', '*a', '\\p{L}', '\\cA', '\\0', 'a{,3}', '}', ']', '[a--b]',
                        '[a&&b]', '[a-c-e]', '[\\d-z]', '[z-a]', '^*', '\\b+', 'a**', 'a++', '(a', 'a)', 'a{x}',
                        '\\', '[\\b]', '\\A', '\\Z', '\\z', '(?i)a', 7):
            with self.subTest(pattern=pattern), self.assertRaises(json_schema.SchemaError):
                json_schema.validate('a', {'pattern': pattern})


class SchemaTests(unittest.TestCase):
    def test_a_ledger_is_complete_only_with_every_row_qualified(self):
        evidence = {'path': 'x', 'sha256': DIGEST}
        self.assertEqual(json_schema.validate(ledger(), LEDGER), [])
        self.assertEqual(json_schema.validate(ledger('qualified', 'qualified', 'qualified', evidence), LEDGER), [])
        for value in (ledger('qualified'), ledger('qualified', 'qualified', 'planned', evidence),
                      ledger('planned', 'qualified', 'planned', None), ledger('planned', 'qualified', 'planned',
                                                                               {'path': 'x', 'sha256': 'AB' * 32})):
            with self.subTest(value=value):
                self.assertTrue(json_schema.validate(value, LEDGER))
        omitted = ledger()
        del omitted['rows']['b']
        self.assertIn('/rows: required member b is absent', json_schema.validate(omitted, LEDGER))

    def test_unimplemented_or_malformed_schemas_are_refused(self):
        for schema in ({'format': 'date'}, {'properties': {'a': {'patternProperties': {}}}},
                       {'anyOf': [{'type': 'string'}, {'dependentRequired': {}}]},
                       {'if': True, 'else': {'unevaluatedProperties': False}}, {'$ref': 'other.json#/x'},
                       {'$ref': '#/$defs/absent'}, {'$defs': {'a': {'minimum': 'x'}}}, {'type': 'int'},
                       {'type': []}, {'enum': []}, {'required': ['a', 'a']}, {'minItems': -1}, {'minimum': True},
                       {'pattern': '('}, {'allOf': []}, {'title': 1}, 3, {'items': [{}]}):
            with self.subTest(schema=schema), self.assertRaises(json_schema.SchemaError):
                json_schema.validate(None, schema)
        # A branch no instance reaches is still checked.
        self.assertRaises(json_schema.SchemaError, json_schema.validate, 1,
                          {'if': {'type': 'string'}, 'then': {'contains': {}}})


if __name__ == '__main__':
    unittest.main()
