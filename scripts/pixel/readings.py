#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the record that readings.sh prints and applies stop point 3.

The record starts with the sealed fastboot's --version output, which must name the
sealed platform tools, 35.0.2-12147458. A command that ended any other way than an answer
or a refusal by the bootloader, a timeout included, refuses the whole record.

Answer forms come from fastboot's source at GrapheneOS 2026100600 (system/core/fastboot):
DisplayVarOrError prints "VAR: VALUE" for an answer and pads "getvar:VAR" to 50 columns
before "FAILED (remote: '...')" when the bootloader refuses a variable. Both end with
"Finished. Total time: N.NNNs" and exit 0. "flashing get_unlock_ability" prints the
bootloader's INFO text as "(bootloader) ...", then "OKAY [ N.NNNs]"; on failure it prints
"FAILED (...)" and "fastboot: error: Command failed" and exits 1.

These forms are UNCONFIRMED. Only a session on the phone, with the platform tools of the
flashing computer, can confirm them. Anything else is refused, never read as an answer.
"""
import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import caiman  # noqa: E402
from caiman import Refusal, refuse  # noqa: E402

HEADER = 'andrix-readings 3'
# The sealed platform tools of decision 5, r35.0.2. Any other fastboot refuses the record.
SEALED_VERSION = '35.0.2-12147458'
FOOTER = 'end-of-readings'
COMMANDS = (('getvar', 'product'), ('getvar', 'is-userspace'), ('getvar', 'version-bootloader'),
            ('getvar', 'version-baseband'), ('getvar', 'current-slot'), ('getvar', 'unlocked'),
            ('getvar', 'snapshot-update-status'), ('flashing', 'get_unlock_ability'))
SESSION_STAGES = (3, 7, 8, 9)
MAX_RECORD = 64 << 10

# Values each reading may take. Any other value is refused as unparsable.
VALUES = {
    'product': re.compile(r'[a-z0-9_]+'),
    'is-userspace': re.compile(r'yes|no'),
    'version-bootloader': re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*'),
    'version-baseband': re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*'),
    'current-slot': re.compile(r'a|b'),
    'unlocked': re.compile(r'yes|no'),
    # the merge states that libsnapshot reports through the bootloader's misc message
    'snapshot-update-status': re.compile(r'none|unknown|snapshotted|merging|cancelled'),
    'get_unlock_ability': re.compile(r'0|1'),
}
_FINISHED = re.compile(r'Finished\. Total time: [0-9]+\.[0-9]{3}s')
_OKAY = re.compile(r'OKAY \[ *[0-9]+\.[0-9]{3}s\]')
_REMOTE = r"FAILED \(remote: '([ -~]*)'\)"
_END = re.compile(r'end (getvar|flashing) (\S+) status ([0-9]{1,3})')
_VERSION_END = re.compile(r'end version status ([0-9]{1,3})')


@dataclass(frozen=True)
class Reading:
    name: str
    value: object       # the answer, or None when the bootloader did not answer
    message: object     # the bootloader's failure message when unanswered

    @property
    def answered(self):
        return self.value is not None

    def as_dict(self):
        if self.answered:
            return {'answered': True, 'value': self.value}
        return {'answered': False, 'message': self.message}


def _getvar(name, body, status):
    if len(body) != 2 or _FINISHED.fullmatch(body[1]) is None or status != 0:
        refuse(f'getvar {name}: unexpected output {body!r} with status {status}')
    prefix = f'{name}: '
    if body[0].startswith(prefix):
        value = body[0][len(prefix):]
        if VALUES[name].fullmatch(value) is None:
            refuse(f'getvar {name}: unexpected value {value!r}')
        return Reading(name, value, None)
    failed = re.fullmatch(re.escape(f'getvar:{name}'.ljust(50) + ' ') + _REMOTE, body[0])
    if failed is None:
        refuse(f'getvar {name}: neither an answer nor a refusal by the bootloader: {body[0]!r}')
    return Reading(name, None, failed.group(1))


def _unlock_ability(body, status):
    name = 'get_unlock_ability'
    if status == 0:
        if (len(body) != 3 or _OKAY.fullmatch(body[1]) is None
                or _FINISHED.fullmatch(body[2]) is None):
            refuse(f'flashing {name}: unexpected output {body!r}')
        match = re.fullmatch(r'\(bootloader\) get_unlock_ability: (\S+)', body[0])
        if match is None or VALUES[name].fullmatch(match.group(1)) is None:
            refuse(f'flashing {name}: unexpected answer {body[0]!r}')
        return Reading(name, match.group(1), None)
    failed = re.fullmatch(_REMOTE, body[0]) if body else None
    if (status != 1 or len(body) != 2 or failed is None
            or body[1] != 'fastboot: error: Command failed'):
        refuse(f'flashing {name}: unexpected output {body!r} with status {status}')
    return Reading(name, None, failed.group(1))


def parse(data):
    """Returns the eight readings, keyed by variable name."""
    if not isinstance(data, bytes) or len(data) > MAX_RECORD:
        refuse('the record is not bytes or is too large')
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        refuse('the record is not ASCII')
    if '\r' in text or '\0' in text:
        refuse('the record contains carriage returns or NUL bytes')
    if not text.endswith('\n'):
        refuse('the record does not end with a newline; it may be cut short')
    lines = text[:-1].split('\n')
    if not lines or lines[0] != HEADER:
        refuse(f'the record does not start with {HEADER!r}')
    if lines[-1] != FOOTER:
        refuse(f'the record does not end with {FOOTER!r}; the script may not have finished')
    stamp = re.fullmatch(r'taken-at ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)',
                         lines[1] if len(lines) > 1 else '')
    if stamp is None:
        refuse('record line 2: expected the UTC time the readings were taken')
    if len(lines) < 5 or lines[2] != 'begin version':
        refuse("record line 3: expected 'begin version', the sealed fastboot's version")
    body, position = [], 3
    while position < len(lines) - 1 and not lines[position].startswith(('begin ', 'end ')):
        body.append(lines[position])
        position += 1
    end = _VERSION_END.fullmatch(lines[position]) if position < len(lines) - 1 else None
    if end is None or int(end.group(1)) != 0:
        refuse(f'record line {position + 1}: fastboot --version did not end with status 0')
    if (len(body) != 2 or body[0] != f'fastboot version {SEALED_VERSION}'
            or re.fullmatch(r'Installed as /\S+', body[1]) is None):
        refuse(f'fastboot --version printed {body!r}, not the sealed {SEALED_VERSION}')
    position += 1
    readings = {'fastboot-version': Reading('fastboot-version', SEALED_VERSION, None),
                'taken-at': Reading('taken-at', stamp.group(1), None)}
    for command, name in COMMANDS:
        begin = f'begin {command} {name}'
        if position >= len(lines) - 1 or lines[position] != begin:
            refuse(f'record line {position + 1}: expected {begin!r}')
        body = []
        position += 1
        while position < len(lines) - 1 and not lines[position].startswith(('begin ', 'end ')):
            body.append(lines[position])
            position += 1
        end = _END.fullmatch(lines[position]) if position < len(lines) - 1 else None
        if end is None or end.group(1) != command or end.group(2) != name:
            refuse(f'record line {position + 1}: expected the end of {command} {name}')
        status = int(end.group(3))
        position += 1
        if command == 'getvar':
            readings[name] = _getvar(name, body, status)
        else:
            readings[name] = _unlock_ability(body, status)
    if position != len(lines) - 1:
        refuse(f'record line {position + 1}: unexpected content after the last reading')
    return readings


def stop_point_3(readings, stage, os_booted):
    """The continue rules. Returns whether the session may go on, and in which mode.

    os_booted is False under the exception "When the OS does not boot": then a
    snapshot-update-status other than none does not end the session, but restricts it.
    """
    if stage not in SESSION_STAGES:
        refuse(f'stage {stage} has no phone session; sessions are stages {SESSION_STAGES}')
    if not isinstance(os_booted, bool):
        refuse('whether the OS booted must be stated')
    stops, notes = [], []
    restricted = False
    product = readings['product']
    if not product.answered:
        stops.append('product is unanswered')
    elif product.value != caiman.DEVICE:
        stops.append(f'product reads {product.value}, not {caiman.DEVICE}')
    userspace = readings['is-userspace']
    if userspace.value == 'yes':
        stops.append("is-userspace reads yes: this is recovery's own fastboot; go back to the "
                     'bootloader screen that shows "Fastboot Mode"')
    elif not userspace.answered:
        notes.append('is-userspace is unanswered; it does not read yes, as stop point 3 requires, '
                     "and fastboot's own is_userspace_fastboot also treats it as not userspace")
    status = readings['snapshot-update-status']
    if status.value != 'none':
        shown = status.value if status.answered else 'unanswered'
        if os_booted:
            stops.append(f'snapshot-update-status is {shown}, not none; a merge can keep it at '
                         'merging for a while after an update boots, so repeat the readings later')
        else:
            restricted = True
            notes.append(f'snapshot-update-status is {shown} and the OS does not boot: only the '
                         'complete GrapheneOS script or the web installer may run')
    if stage >= 7:
        ability = readings['get_unlock_ability']
        if ability.value != '1':
            stops.append('get_unlock_ability does not read 1 (rule 1)')
    if stage >= 8:
        unlocked = readings['unlocked']
        if unlocked.value != 'yes':
            stops.append('unlocked does not read yes; the session stops, and only a new approved '
                         'session that repeats stage 7 may unlock again')
    return {'continue': not stops, 'restricted': restricted, 'stops': stops, 'notes': notes}


def yes_no(text):
    if text not in ('yes', 'no'):
        raise argparse.ArgumentTypeError('state yes or no')
    return text == 'yes'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('record', help='the output of readings.sh')
    parser.add_argument('--stage', type=int, required=True, choices=SESSION_STAGES)
    parser.add_argument('--os-booted', type=yes_no, required=True,
                        help='yes if stop point 1 ran in the OS; no under the exception')
    args = parser.parse_args(argv)
    try:
        readings = parse(Path(args.record).read_bytes())
        result = stop_point_3(readings, args.stage, args.os_booted)
    except (Refusal, OSError) as error:
        sys.stdout.write(caiman.dump({'verdict': 'REFUSE', 'reasons': [str(error)]}))
        return 1
    result = dict(result, verdict='CONTINUE' if result['continue'] else 'STOP',
                  readings={name: reading.as_dict() for name, reading in readings.items()},
                  formats='unconfirmed: derived from fastboot source, not a phone')
    sys.stdout.write(caiman.dump(result))
    return 0 if result['continue'] else 1


if __name__ == '__main__':
    sys.exit(main())
