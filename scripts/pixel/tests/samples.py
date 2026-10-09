# SPDX-License-Identifier: Apache-2.0
"""SYNTHETIC readings records for the tests.

The forms follow what fastboot's source at GrapheneOS 2026100600 prints. None of them was
recorded from a phone, and only a session on the phone can confirm them.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import readings  # noqa: E402

# Readings of a phone on the 2026100600 firmware, unlocked, as from stage 8 on
GOOD = {'product': 'caiman', 'is-userspace': 'no', 'version-bootloader': 'ripcurrentpro-17.0-15819938',
        'version-baseband': 'g5400c-260604-260807-B-16035863', 'current-slot': 'a',
        'unlocked': 'yes', 'snapshot-update-status': 'none', 'get_unlock_ability': '1'}
# the 2026081300 firmware, as adevtool records it for CP2A.260805.005
AUGUST = {'version-bootloader': 'ripcurrentpro-17.0-15199480',
          'version-baseband': 'g5400c-260317-260429-B-15308590'}


def block(command, name, body, status=0):
    return [f'begin {command} {name}'] + body + [f'end {command} {name} status {status}']


def block_version(version=None, path='/sealed/platform-tools/fastboot'):
    return ['begin version', f'fastboot version {version or readings.SEALED_VERSION}',
            f'Installed as {path}', 'end version status 0']


def synthetic(values=None, unknown=(), override=None, taken_at='2026-10-09T11:00:00Z'):
    """A synthetic record in the forms fastboot's source prints."""
    values = dict(GOOD, **(values or {}))
    lines = [readings.HEADER, f'taken-at {taken_at}'] + block_version()
    for command, name in readings.COMMANDS:
        if override and name in override:
            lines += block(command, name, *override[name])
        elif command == 'getvar' and name in unknown:
            lines += block(command, name, [f'getvar:{name}'.ljust(50) + " FAILED (remote: 'GetVar "
                                           "Variable Not found')", 'Finished. Total time: 0.001s'])
        elif command == 'getvar':
            lines += block(command, name, [f'{name}: {values[name]}', 'Finished. Total time: 0.001s'])
        elif name in unknown:
            lines += block(command, name, ["FAILED (remote: 'unknown command')",
                                           'fastboot: error: Command failed'], 1)
        else:
            lines += block(command, name, [f'(bootloader) get_unlock_ability: {values[name]}',
                                           'OKAY [  0.001s]', 'Finished. Total time: 0.002s'])
    return ('\n'.join(lines + [readings.FOOTER]) + '\n').encode()


def parsed(values=None, unknown=(), taken_at='2026-10-09T11:00:00Z'):
    return readings.parse(synthetic(values, unknown, taken_at=taken_at))
