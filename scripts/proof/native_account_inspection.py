#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure check of the selected in-place Settings inspection fragment and host facade.

The six-family GrapheneOS source adaptation remains native_principal_pins.profile()/targets().
No extra patch or profile is admitted into the selected patch directory.
"""
from pathlib import Path

import native_principal_pins as pins

ROOT = Path(__file__).resolve().parents[2]
FACADE = ROOT / 'owner/tests/platform/native_principal_stubs/com/android/server/pm/Settings.java'
SETTINGS = pins.PREFIX + 'Settings.java'
MANAGER = pins.PREFIX + 'NativePrincipalManager.java'


def inspect():
    profile = pins.profile()  # Strict schema, pinned patch, helpers, fixtures and fragments.
    if profile['project'] != pins.PROJECT or SETTINGS not in pins.FILES or MANAGER not in pins.ADDED:
        raise ValueError('native account inspection not in the selected framework recipe')
    target, fragment = pins.FRAGMENTS['inspection']
    method = fragment.read_bytes()
    inserted = b''.join(b'+' + line + b'\n' for line in method.splitlines())
    if (target != SETTINGS or FACADE.read_bytes().count(method) != 1
            or pins.PATCH.read_bytes().count(inserted) != 1
            or profile['fragments'][-1]['name'] != 'inspection'
            or profile['fragments'][-1]['source'] != fragment.relative_to(ROOT).as_posix()):
        raise ValueError('selected Settings inspection or host facade drift')
    return 'selected in-place Settings inspection profile, fragment and facade exact'


if __name__ == '__main__':
    print(inspect())
