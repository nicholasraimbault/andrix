# SPDX-License-Identifier: Apache-2.0
"""Observe authoritative PMS dumps for a controlled allocator test. Never allocate or reserve IDs."""
import re


def package_ids(text):
    if len(text) > 16 * 1024 * 1024:
        raise ValueError('package dump bounds')
    result = {'packages': {}, 'hidden': {}}
    section = None
    pending = None
    app_id = None

    def finish():
        nonlocal pending, app_id
        if pending is not None:
            if section is None or app_id is None or pending in result[section]:
                raise ValueError('incomplete or duplicate package identity')
            result[section][pending] = app_id
        pending, app_id = None, None

    for line in text.splitlines():
        if line in ('Packages:', 'Hidden system packages:'):
            finish(); section = 'packages' if line == 'Packages:' else 'hidden'
            continue
        header = re.fullmatch(r'  Package \[([^\]\r\n]+)\] \([0-9a-f]+\):', line)
        if header:
            finish(); pending = header[1]
        elif pending is not None and line.startswith('    compat name='):
            pending = line[len('    compat name='):]
            if not pending:
                raise ValueError('empty compatibility name')
        elif pending is not None and line.startswith('    appId='):
            value = line[len('    appId='):]
            if app_id is not None or not re.fullmatch(r'-?[0-9]{1,10}', value):
                raise ValueError('package app ID')
            app_id = int(value)
    finish()
    if not result['packages']:
        raise ValueError('package observer unavailable')
    return result


def shared_ids(text):
    if len(text) > 8 * 1024 * 1024:
        raise ValueError('shared user dump bounds')
    result, pending = {}, None
    for line in text.splitlines():
        header = re.fullmatch(r'  SharedUser \[([^\]\r\n]+)\] \([0-9a-f]+\):', line)
        if header:
            if pending is not None:
                raise ValueError('missing shared app ID')
            pending = header[1]
        elif pending is not None and line.startswith('    appId='):
            value = line[len('    appId='):]
            if not re.fullmatch(r'[0-9]{1,10}', value) or pending in result:
                raise ValueError('shared app ID')
            result[pending] = int(value); pending = None
    if pending is not None or 'Shared users:' not in text or not result:
        raise ValueError('shared user observer unavailable')
    return result


def excluded_hole_candidate(packages, shared, search_start, held, target):
    """Return the source algorithm's prediction only when target is the observed first hole."""
    if (type(search_start) is not int or type(target) is not int
            or not 10000 <= search_start <= target <= 19999):
        raise ValueError('target not covered by current allocator cursor')
    used = {value for value in [*packages.values(), *shared.values()] if 10000 <= value <= 19999}
    if target in used or target not in held or not used or target > max(used):
        raise ValueError('target is not a held internal hole')
    ordinary = next((value for value in range(search_start, max(used) + 1) if value not in used), None)
    if ordinary != target:
        raise ValueError('a lower ordinary hole makes this observation inconclusive')
    predicted = next((value for value in range(search_start, 20000) if value not in used and value not in held), None)
    if predicted is None:
        raise ValueError('allocator capacity unavailable')
    return predicted
