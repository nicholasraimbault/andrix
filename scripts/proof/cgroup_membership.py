#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Parse kernel membership metadata, not cgroup authority, limits or completed cleanup."""
import re


def unified_cgroup_path(text):
    """Return the one exact v2 path while validating any accompanying v1 rows.

    The returned path is data, not a filesystem capability. Do not traverse it or
    infer authority from it. Callers still compare their exact expected scope and
    independently check real identity, resource controls and lifecycle state.
    """
    if not isinstance(text, str) or not text or len(text) > 16384 or '\0' in text:
        raise ValueError('invalid bounded cgroup observation')
    rows = text.splitlines()
    if len(rows) > 64:
        raise ValueError('too many cgroup hierarchies')
    seen_ids, seen_controllers = set(), set()
    unified = None
    for row in rows:
        fields = row.split(':', 2)
        if len(fields) != 3:
            raise ValueError('malformed cgroup membership row')
        number, controllers, path = fields
        if not re.fullmatch(r'0|[1-9][0-9]*', number) or number in seen_ids:
            raise ValueError('invalid or repeated cgroup hierarchy')
        if not path.startswith('/') or any(ord(c) < 0x20 or ord(c) == 0x7f for c in path):
            raise ValueError('invalid raw cgroup path')
        seen_ids.add(number)
        if number == '0':
            if controllers:
                raise ValueError('controllers on unified membership row')
            unified = path
        else:
            names = controllers.split(',')
            if not all(re.fullmatch(r'[a-zA-Z0-9_.=-]+', name) for name in names):
                raise ValueError('invalid legacy controller list')
            if len(set(names)) != len(names) or seen_controllers.intersection(names):
                raise ValueError('repeated legacy controller')
            seen_controllers.update(names)
    if unified is None:
        raise ValueError('missing unified membership')
    return unified
