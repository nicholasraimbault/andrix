# SPDX-License-Identifier: Apache-2.0
"""Permission coverage for already expanded concrete SELinux allow rules.

An any-permission query returning a rule does not prove every requested permission.
This helper verifies one exact source, target and class, without sharing policy caches
or treating attributes/metadata as authority.
"""

def allows_all(rules, source, target, tclass, permissions):
    granted = set()
    for rule in rules:
        if (rule['source'], rule['target'], rule['class']) == (source, target, tclass):
            granted.update(rule['perms'])
    return set(permissions).issubset(granted)
