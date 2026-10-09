# SPDX-License-Identifier: Apache-2.0
"""Facts and strict parsers shared by the caiman workshop phone checkers.

Every parser here refuses what it does not recognise and names the reason. None of
them guesses. See README.md for the plan rules each checker implements.
"""
from dataclasses import dataclass
import datetime
import hashlib
import json
import re

DEVICE = 'caiman'

# GrapheneOS release numbers are YYYYMMDDNN. NN 00 is a release. NN 01 is the security
# preview of the 00 release of the same day, which the plan counts as that release. No
# other suffix is defined anywhere this project has read, so any other suffix is refused.
_RELEASE = re.compile(r'[0-9]{10}')

# Stock build IDs as Google and adevtool write them, with or without a variant suffix
# such as .A1. Every key of adevtool's build indexes in both source trees matches this.
BUILD_ID = re.compile(r'[A-Z][A-Z0-9]{3}\.[0-9]{6}\.[0-9]{3}(?:\.[A-Z][0-9])?')

SHA256 = re.compile(r'[0-9a-f]{64}')


class Refusal(Exception):
    """An input the checkers cannot accept. The message is the reason."""


def refuse(reason):
    raise Refusal(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Release:
    """A GrapheneOS release number and the release it counts as."""
    number: str
    base: str
    preview: bool

    def __str__(self):
        return self.number


def parse_release(text, allow_preview=True, what='release number'):
    if not isinstance(text, str) or _RELEASE.fullmatch(text) is None:
        refuse(f'{what} {text!r} is not ten digits')
    try:
        datetime.date(int(text[0:4]), int(text[4:6]), int(text[6:8]))
    except ValueError:
        refuse(f'{what} {text} does not start with a calendar date')
    suffix = text[8:]
    if suffix == '00':
        return Release(text, text, False)
    if suffix == '01':
        if not allow_preview:
            refuse(f'{what} {text} is a security preview, which has no public source')
        return Release(text, text[:8] + '00', True)
    refuse(f'{what} {text} ends in {suffix}; only 00 and the security preview suffix 01 are known')


def newer(a, b):
    """True if release a is newer than release b, a preview counting as its base."""
    return int(a.base) > int(b.base)


def same_release(a, b):
    return a.base == b.base


def newest(releases):
    """The newest of the given releases. Among equal bases the first given wins."""
    best = None
    for release in releases:
        if best is None or newer(release, best):
            best = release
    return best


def parse_build_id(text, what='stock build ID'):
    if not isinstance(text, str) or BUILD_ID.fullmatch(text) is None:
        refuse(f'{what} {text!r} is not a stock build ID')
    return text


@dataclass(frozen=True)
class AndroidInfo:
    """The requirements of an android-info.txt, for caiman."""
    board: str
    bootloader: str
    baseband: str
    partitions: tuple

    def as_dict(self):
        return {'board': self.board, 'bootloader': self.bootloader,
                'baseband': self.baseband, 'partitions': list(self.partitions)}


_REQUIRE = re.compile(r'require (board|version-bootloader|version-baseband|partition-exists)'
                      r'=([A-Za-z0-9][A-Za-z0-9._-]*)')


def parse_android_info(data, what='android-info.txt'):
    """Accepts only plain 'require key=value' lines.

    fastboot also understands reject lines, product scoped lines, alternatives with '|'
    and a trailing '*' wildcard, and it skips lines it cannot parse. Any of those would
    make a single expected version ambiguous, so each is refused here.
    """
    if not isinstance(data, bytes):
        refuse(f'{what} is not bytes')
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        refuse(f'{what} is not ASCII')
    if '\r' in text or '\0' in text or '\t' in text:
        refuse(f'{what} contains carriage returns, tabs or NUL bytes')
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    values = {}
    partitions = []
    for number, line in enumerate(lines, 1):
        if line == '':
            continue
        match = _REQUIRE.fullmatch(line)
        if match is None:
            refuse(f'{what} line {number} is not a plain requirement: {line!r}')
        key, value = match.groups()
        if key == 'partition-exists':
            if value in partitions:
                refuse(f'{what} repeats partition-exists={value}')
            partitions.append(value)
            continue
        if key in values:
            refuse(f'{what} repeats {key}')
        values[key] = value
    for key in ('board', 'version-bootloader', 'version-baseband'):
        if key not in values:
            refuse(f'{what} has no {key} requirement')
    if values['board'] != DEVICE:
        refuse(f'{what} names board {values["board"]}, not {DEVICE}')
    return AndroidInfo(values['board'], values['version-bootloader'],
                       values['version-baseband'], tuple(partitions))


_CHANNEL = re.compile(r'([0-9]{10}) ([0-9]{1,12}) ' + DEVICE + r' stable\n?')


def parse_stable_channel(data, what='caiman-stable'):
    """The update server's caiman-stable file, as script/generate-metadata writes it.

    generate-metadata prints the build number, the build timestamp, the device and the
    channel on one line. The release is the build number.
    """
    if not isinstance(data, bytes):
        refuse(f'{what} is not bytes')
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        refuse(f'{what} is not ASCII')
    match = _CHANNEL.fullmatch(text)
    if match is None:
        refuse(f'{what} is not one line of "BUILD_NUMBER TIMESTAMP {DEVICE} stable": {text[:80]!r}')
    return parse_release(match.group(1), what=f'{what} release')


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'
