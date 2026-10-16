# SPDX-License-Identifier: Apache-2.0
"""Strict canonical side records: the one byte form of the broker's compound evidence manifests and
of the typed action specs it retains.

A side record is a JSON object of printable ASCII strings, integers within 64 signed bits, booleans,
null, lists and objects, nested at most MAX_DEPTH deep. Its canonical bytes are the compact
encoding with sorted keys, the fixed separators ',' and ':', ASCII escapes and one terminal
newline. Parsing accepts exactly those bytes: a duplicate key, a float, NaN or an infinity, any
other spacing or key order, a string outside printable ASCII or a value outside its bound is
refused. The SHA-256 of the canonical bytes identifies the whole record. A digest or a schema name
proves nothing about the fact a record describes."""
import hashlib
import json

MAX_BYTES = 1 << 20
MAX_DEPTH = 8
MAX_ITEMS = 4096
MAX_STRING = 4096
LOW, HIGH = -(1 << 63), (1 << 63) - 1


class SideError(ValueError):
    """A side record of no canonical form."""


def _check(value, depth=0):
    if depth > MAX_DEPTH:
        raise SideError('a side record nested too deep')
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not LOW <= value <= HIGH:
            raise SideError('an integer outside 64 signed bits')
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING or any(ord(c) < 0x20 or ord(c) > 0x7e for c in value):
            raise SideError('a string that is not printable ASCII within its bound')
        return
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise SideError('a list above its bound')
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise SideError('an object above its bound')
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 64 or any(
                    ord(c) < 0x21 or ord(c) > 0x7e for c in key):
                raise SideError('a key that is not short printable ASCII')
            _check(item, depth + 1)
        return
    raise SideError('a value of no side record type: %s' % type(value).__name__)


def canonical(value):
    """The canonical bytes of a side record, an object."""
    if not isinstance(value, dict):
        raise SideError('a side record is an object')
    _check(value)
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            + '\n').encode('ascii')
    if len(data) > MAX_BYTES:
        raise SideError('a side record above its bound')
    return data


def digest(value):
    """The SHA-256 of a side record's canonical bytes, as 64 hexadecimal digits."""
    return hashlib.sha256(canonical(value)).hexdigest()


def parse(data):
    """The side record exact canonical bytes hold."""
    data = bytes(data)
    if len(data) > MAX_BYTES or not data.endswith(b'\n'):
        raise SideError('a side record above its bound or without its terminal newline')

    def pairs(items):
        keys = [key for key, _ in items]
        if len(set(keys)) != len(keys):
            raise SideError('a duplicate key')
        return dict(items)

    def refuse(text):
        raise SideError('a number that is not an integer: %s' % text)
    try:
        value = json.loads(data.decode('ascii'), object_pairs_hook=pairs, parse_float=refuse, parse_constant=refuse)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SideError('not a side record: %s' % error) from error
    if canonical(value) != data:
        raise SideError('a side record not in its canonical form')
    return value
