#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
r"""A strict validator for the subset of JSON Schema draft 2020-12 that host evidence ledgers use.

No schema library is needed. Loading refuses a duplicate object key and a nonfinite number, named
or too large for a double, as 1e400 is, before any validation, since a JSON parser would otherwise
keep one of two values silently or read infinity. A schema is checked whole before it validates
anything: every keyword it uses anywhere must be one this module implements, with a value of its
defined form, so no keyword is ever ignored and no branch that one instance never reaches hides an
unknown keyword.

Implemented: the annotations $schema, $id, $comment, title and description; $defs and $ref to a
JSON pointer within the same document, applied beside its sibling keywords as draft 2020-12
does; type, const and enum; for objects required, properties and additionalProperties; for arrays
items, minItems, maxItems and uniqueItems; for strings minLength, maxLength and pattern; for
numbers minimum and maximum; allOf, anyOf, oneOf, not, and if with then and else. Booleans are
never numbers, and an integer is a number with no fractional part. Equality for const, enum and
uniqueItems is JSON equality. Remote references, formats and vocabularies outside this list are
refused.

A pattern is an ECMA-262 regular expression without flags, searched in the string, from a subset:
literal characters, the escaped syntax characters, slash and hyphen, \d \D \w \W \b \B, \t \n
\v \f \r, \xHH and \uHHHH; character classes of literals, those escapes but \b and \B, and
ranges between single characters; ^ and $, the dot, groups ( ) and (?: ), alternation, and the
quantifiers * + ? {n} {n,} {n,m}, each greedy or lazy. Each is translated to keep its ECMA-262
meaning: $ matches only at the end of the string, never before a final newline; the dot matches
any code unit but the four line terminators; \d, \w and \b are ASCII; and the pattern runs
over the string's UTF-16 code units. A pattern with any other syntax is refused as a schema
error.

Validation reports every failure with the JSON pointer of the failing instance. Schema validity
does not prove a hash, an order across records, an authentic review or a completed execution;
checkers that need those state them separately."""
import functools
import json
import math
import re
import struct

ANNOTATIONS = ('$schema', '$id', '$comment', 'title', 'description')
KEYWORDS = frozenset(ANNOTATIONS + (
    '$defs', '$ref', 'type', 'const', 'enum', 'required', 'properties', 'additionalProperties', 'items',
    'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern', 'minimum', 'maximum',
    'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else'))
TYPES = ('null', 'boolean', 'object', 'array', 'string', 'integer', 'number')


class SchemaError(ValueError):
    """A schema this module cannot apply exactly."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object key: %r' % key)
        result[key] = value
    return result


def _nonfinite(name):
    raise ValueError('nonfinite JSON number: %s' % name)


def _finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('nonfinite JSON number: %s' % text)
    return value


def loads(text):
    """Strict JSON: a duplicate object key or a nonfinite number refuses, whether named or a
    literal beyond a double's range."""
    if type(text) is bytes:
        text = text.decode('utf-8')
    if type(text) is not str:
        raise ValueError('JSON text required')
    return json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite, parse_float=_finite)


# ---------------------------------------------------------------- ECMA-262 patterns

# Escapes that keep their meaning: control characters, the ASCII classes (Python's under re.ASCII
# are ECMA-262's), and every syntax character, slash and hyphen, which stand for themselves.
_CONTROLS = {'t': 0x09, 'n': 0x0A, 'v': 0x0B, 'f': 0x0C, 'r': 0x0D}
_CLASSES = ('d', 'D', 'w', 'W')
_SYNTAX = '^$\\.*+?()[]{}|/-'
_DOT = '[^\\n\\r\\u2028\\u2029]'
_QUANTIFIER = re.compile(r'\{([0-9]+)(?:(,)([0-9]*))?\}')


def _units(text):
    """A string as its UTF-16 code units, one character each, as ECMA-262 without its unicode flag
    reads it."""
    data = text.encode('utf-16-le', 'surrogatepass')
    return ''.join(map(chr, struct.unpack('<%dH' % (len(data) // 2), data)))


def _unit(value):
    return '\\u%04x' % value


def _escape(source, at, in_class):
    """The escape at source[at], a backslash: ('unit', code unit) or ('class', Python text), and the
    index after it."""
    char = source[at + 1] if at + 1 < len(source) else ''
    if char in _CONTROLS:
        return ('unit', _CONTROLS[char]), at + 2
    if char in _CLASSES:
        return ('class', '\\' + char), at + 2
    if char in ('b', 'B') and not in_class:
        return ('assertion', '\\' + char), at + 2
    if char == 'x' and re.fullmatch(r'[0-9A-Fa-f]{2}', source[at + 2:at + 4]):
        return ('unit', int(source[at + 2:at + 4], 16)), at + 4
    if char == 'u' and re.fullmatch(r'[0-9A-Fa-f]{4}', source[at + 2:at + 6]):
        return ('unit', int(source[at + 2:at + 6], 16)), at + 6
    if char and char in _SYNTAX:
        return ('unit', ord(char)), at + 2
    raise SchemaError('pattern escape outside the implemented subset: \\%s' % char)


def _class(source, at):
    """The character class at source[at], a [: its Python text and the index after it. Empty
    classes, nested brackets, doubled set operators and ranges to or from a class escape, where
    Python and ECMA-262 differ, are refused."""
    at += 1
    negated = source.startswith('^', at)
    at += negated
    tokens = []
    while True:
        if at >= len(source):
            raise SchemaError('an unterminated character class')
        char = source[at]
        if char == ']':
            break
        if char == '[' or source.startswith(('--', '&&', '~~', '||'), at):
            raise SchemaError('a character class with a nested bracket or a doubled set operator')
        if char == '\\':
            token, at = _escape(source, at, True)
            tokens.append(token)
        elif char == '-':
            tokens.append(('dash', None))
            at += 1
        else:
            tokens.extend(('unit', value) for value in map(ord, _units(char)))
            at += 1
    if not tokens:
        raise SchemaError('an empty character class')
    parts, index, ranged = [], 0, False
    while index < len(tokens):
        kind, value = tokens[index]
        if kind == 'dash' and 0 < index < len(tokens) - 1:
            (left_kind, low), (right_kind, high) = tokens[index - 1], tokens[index + 1]
            if ranged or left_kind != 'unit' or right_kind != 'unit' or low > high:
                raise SchemaError('a character class range outside the implemented subset')
            parts[-1] = _unit(low) + '-' + _unit(high)
            index, ranged = index + 2, True
            continue
        parts.append(_unit(ord('-')) if kind == 'dash' else _unit(value) if kind == 'unit' else value)
        index, ranged = index + 1, False
    return '[' + ('^' if negated else '') + ''.join(parts) + ']', at + 1


def translate(source):
    """A pattern of the implemented ECMA-262 subset as a Python expression of the same meaning over
    code units, to compile with re.ASCII. Any other syntax raises SchemaError."""
    if type(source) is not str:
        raise SchemaError('a pattern is text')
    out, at, depth, quantifiable = [], 0, 0, False
    while at < len(source):
        char = source[at]
        if char == '\\':
            (kind, value), at = _escape(source, at, False)
            out.append(_unit(value) if kind == 'unit' else value)
            quantifiable = kind != 'assertion'
        elif char == '[':
            text, at = _class(source, at)
            out.append(text)
            quantifiable = True
        elif char == '(':
            if source.startswith('(?:', at):
                out.append('(?:')
                at += 3
            elif source.startswith('(?', at):
                raise SchemaError('a group form outside the implemented subset')
            else:
                out.append('(')
                at += 1
            depth += 1
            quantifiable = False
        elif char == ')':
            if not depth:
                raise SchemaError('an unbalanced )')
            out.append(')')
            depth -= 1
            at += 1
            quantifiable = True
        elif char in '|^$':
            out.append('\\Z' if char == '$' else char)
            at += 1
            quantifiable = False
        elif char == '.':
            out.append(_DOT)
            at += 1
            quantifiable = True
        elif char in '*+?{':
            if char == '{':
                match = _QUANTIFIER.match(source, at)
                if match is None:
                    raise SchemaError('a { that is no quantifier')
                if match[3] and int(match[3]) < int(match[1]):
                    raise SchemaError('a quantifier out of order')
                token, at = match[0], match.end()
            else:
                token, at = char, at + 1
            if not quantifiable:
                raise SchemaError('a quantifier with nothing to repeat')
            if source.startswith('?', at):
                token += '?'
                at += 1
            out.append(token)
            quantifiable = False
        elif char in ']}':
            raise SchemaError('an unescaped %s' % char)
        else:
            out.extend(_unit(ord(unit)) for unit in _units(char))
            at += 1
            quantifiable = True
    if depth:
        raise SchemaError('an unbalanced (')
    return ''.join(out)


@functools.lru_cache(maxsize=256)
def _compiled(source):
    try:
        return re.compile(translate(source), re.ASCII)
    except re.error as error:
        raise SchemaError('pattern: %s' % error) from error


def _number(value):
    return type(value) in (int, float) and not (type(value) is float and not math.isfinite(value))


def _is(value, name):
    if name == 'null':
        return value is None
    if name == 'boolean':
        return type(value) is bool
    if name == 'object':
        return type(value) is dict
    if name == 'array':
        return type(value) is list
    if name == 'string':
        return type(value) is str
    if name == 'number':
        return _number(value)
    return type(value) is int or (type(value) is float and math.isfinite(value) and value.is_integer())


def equal(one, two):
    """JSON equality: numbers by value, Booleans apart from numbers, arrays in order, objects by
    their members."""
    if type(one) is bool or type(two) is bool:
        return type(one) is type(two) and one == two
    if _number(one) and _number(two):
        return one == two
    if type(one) is not type(two):
        return False
    if type(one) is dict:
        return set(one) == set(two) and all(equal(one[key], two[key]) for key in one)
    if type(one) is list:
        return len(one) == len(two) and all(equal(a, b) for a, b in zip(one, two))
    return one == two


def _pointer(root, reference):
    if not reference.startswith('#'):
        raise SchemaError('only references within the document are implemented: %s' % reference)
    node = root
    if reference in ('#', '#/'):
        return node
    if not reference.startswith('#/'):
        raise SchemaError('a reference that is not a JSON pointer: %s' % reference)
    for token in reference[2:].split('/'):
        token = token.replace('~1', '/').replace('~0', '~')
        if type(node) is dict and token in node:
            node = node[token]
        elif type(node) is list and re.fullmatch(r'0|[1-9][0-9]*', token) and int(token) < len(node):
            node = node[int(token)]
        else:
            raise SchemaError('an unresolvable reference: %s' % reference)
    return node


def check_schema(schema, root=None, where='#'):
    """Refuse a schema that uses a keyword this module does not implement, anywhere, or a keyword
    value of another form, or a reference that does not resolve."""
    root = schema if root is None else root
    if type(schema) is bool:
        return
    if type(schema) is not dict:
        raise SchemaError('%s: a schema is an object or a Boolean' % where)
    unknown = sorted(set(schema) - KEYWORDS)
    if unknown:
        raise SchemaError('%s: keywords not implemented: %s' % (where, unknown))
    for name in ANNOTATIONS:
        if name in schema and type(schema[name]) is not str:
            raise SchemaError('%s: %s is text' % (where, name))
    if '$ref' in schema:
        if type(schema['$ref']) is not str:
            raise SchemaError('%s: $ref is text' % where)
        _pointer(root, schema['$ref'])
    if 'type' in schema:
        names = schema['type'] if type(schema['type']) is list else [schema['type']]
        if not names or any(name not in TYPES for name in names) or len(set(names)) != len(names):
            raise SchemaError('%s: type' % where)
    if 'enum' in schema and (type(schema['enum']) is not list or not schema['enum']):
        raise SchemaError('%s: enum is a nonempty array' % where)
    if 'required' in schema and (type(schema['required']) is not list
                                 or any(type(name) is not str for name in schema['required'])
                                 or len(set(schema['required'])) != len(schema['required'])):
        raise SchemaError('%s: required is an array of distinct names' % where)
    for name in ('minItems', 'maxItems', 'minLength', 'maxLength'):
        if name in schema and (type(schema[name]) is not int or schema[name] < 0):
            raise SchemaError('%s: %s is a count' % (where, name))
    for name in ('minimum', 'maximum'):
        if name in schema and not _number(schema[name]):
            raise SchemaError('%s: %s is a number' % (where, name))
    if 'uniqueItems' in schema and type(schema['uniqueItems']) is not bool:
        raise SchemaError('%s: uniqueItems is a Boolean' % where)
    if 'pattern' in schema:
        try:
            _compiled(schema['pattern'])
        except (SchemaError, TypeError) as error:
            raise SchemaError('%s: pattern: %s' % (where, error)) from error
    for name in ('$defs', 'properties'):
        if name in schema:
            if type(schema[name]) is not dict:
                raise SchemaError('%s: %s is an object' % (where, name))
            for key, value in schema[name].items():
                check_schema(value, root, '%s/%s/%s' % (where, name, key))
    for name in ('allOf', 'anyOf', 'oneOf'):
        if name in schema:
            if type(schema[name]) is not list or not schema[name]:
                raise SchemaError('%s: %s is a nonempty array' % (where, name))
            for index, value in enumerate(schema[name]):
                check_schema(value, root, '%s/%s/%d' % (where, name, index))
    for name in ('additionalProperties', 'items', 'not', 'if', 'then', 'else'):
        if name in schema:
            check_schema(schema[name], root, '%s/%s' % (where, name))


def _join(path, key):
    return '%s/%s' % (path, str(key).replace('~', '~0').replace('/', '~1'))


def _errors(instance, schema, root, path, depth):
    if depth > 200:
        raise SchemaError('reference depth beyond 200 at %s' % (path or '/'))
    if schema is True:
        return []
    if schema is False:
        return ['%s: no value is allowed here' % (path or '/')]
    found = []
    here = path or '/'
    if '$ref' in schema:
        found += _errors(instance, _pointer(root, schema['$ref']), root, path, depth + 1)
    if 'type' in schema:
        names = schema['type'] if type(schema['type']) is list else [schema['type']]
        if not any(_is(instance, name) for name in names):
            found.append('%s: not of type %s' % (here, ' or '.join(names)))
    if 'const' in schema and not equal(instance, schema['const']):
        found.append('%s: not the constant %s' % (here, json.dumps(schema['const'])))
    if 'enum' in schema and not any(equal(instance, item) for item in schema['enum']):
        found.append('%s: not one of %s' % (here, json.dumps(schema['enum'])))
    if type(instance) is dict:
        for name in schema.get('required', ()):
            if name not in instance:
                found.append('%s: required member %s is absent' % (here, name))
        properties = schema.get('properties', {})
        for key, value in instance.items():
            if key in properties:
                found += _errors(value, properties[key], root, _join(path, key), depth + 1)
            elif 'additionalProperties' in schema:
                found += _errors(value, schema['additionalProperties'], root, _join(path, key), depth + 1)
    if type(instance) is list:
        if 'items' in schema:
            for index, value in enumerate(instance):
                found += _errors(value, schema['items'], root, _join(path, index), depth + 1)
        if 'minItems' in schema and len(instance) < schema['minItems']:
            found.append('%s: fewer than %d items' % (here, schema['minItems']))
        if 'maxItems' in schema and len(instance) > schema['maxItems']:
            found.append('%s: more than %d items' % (here, schema['maxItems']))
        if schema.get('uniqueItems') and any(equal(instance[i], instance[j]) for i in range(len(instance))
                                             for j in range(i + 1, len(instance))):
            found.append('%s: items repeat' % here)
    if type(instance) is str:
        if 'minLength' in schema and len(instance) < schema['minLength']:
            found.append('%s: shorter than %d' % (here, schema['minLength']))
        if 'maxLength' in schema and len(instance) > schema['maxLength']:
            found.append('%s: longer than %d' % (here, schema['maxLength']))
        if 'pattern' in schema and _compiled(schema['pattern']).search(_units(instance)) is None:
            found.append('%s: does not match %s' % (here, schema['pattern']))
    if _number(instance):
        if 'minimum' in schema and instance < schema['minimum']:
            found.append('%s: below %s' % (here, schema['minimum']))
        if 'maximum' in schema and instance > schema['maximum']:
            found.append('%s: above %s' % (here, schema['maximum']))
    for member in schema.get('allOf', ()):
        found += _errors(instance, member, root, path, depth + 1)
    if 'anyOf' in schema and not any(not _errors(instance, member, root, path, depth + 1)
                                     for member in schema['anyOf']):
        found.append('%s: matches none of anyOf' % here)
    if 'oneOf' in schema:
        count = sum(1 for member in schema['oneOf'] if not _errors(instance, member, root, path, depth + 1))
        if count != 1:
            found.append('%s: matches %d of oneOf, not one' % (here, count))
    if 'not' in schema and not _errors(instance, schema['not'], root, path, depth + 1):
        found.append('%s: matches a schema it must not' % here)
    if 'if' in schema:
        branch = 'then' if not _errors(instance, schema['if'], root, path, depth + 1) else 'else'
        if branch in schema:
            found += _errors(instance, schema[branch], root, path, depth + 1)
    return found


def validate(instance, schema):
    """Every failure of an instance against a schema, each with its instance pointer; empty when it
    is valid. A schema this module cannot apply exactly raises SchemaError first."""
    check_schema(schema)
    return _errors(instance, schema, schema, '', 0)
