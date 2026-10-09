#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stop point 4, the version criterion, and the exception "When the OS does not boot".

An image may be written only if each firmware reading equals the version that one of the
session's known releases records, and its release is newer than the phone's release or it
has the same stock build ID as the phone's release. The known releases are the release
recorded at the session's start and every release written in the session. Stock build IDs
are compared only for equality.

No typed value can approve older firmware:
- the image's identity is read from the image by verify, once per session, and kept in the
  session record under its SHA-256; decide hashes the file again and takes that identity;
- the session's facts live in the checker's own session record, which takes each ALLOWed
  release before the write runs and carries the phone's release into the next session;
- the session records of a phone form one chain in their own directory, each naming the
  SHA-256 of the one before it, and a new session starts only from the newest, whose SHA-256
  the owner keeps privately; within a session every start, verify and decide prints the
  record's new SHA-256, and the next verify or decide needs it;
- the first record, and the record of a phone that updated itself, start from the current
  stable release, read from a caiman-stable file fetched at that moment, which the build number
  of stop point 1 must show; after an update it must be newer than every carried release;
- one start, verify or decide at a time holds the session record's lock;
- readings carry the time they were taken, must be newer than the session's last ALLOW and
  must be at most READINGS_MAX_AGE_MINUTES old;
- the release tags come from the signed tags of a local GrapheneOS manifest repository,
  each verified against the pinned allowed signers with pinned signature programs, and every
  record is bound to its tag's signed manifest;
- the session's approval must name the session, its date and the image.

Exit status: 0 ALLOW, 1 REFUSE, 3 WAIT for a fresh approval. See README.md.
"""
import argparse
from dataclasses import dataclass
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adevtool_record  # noqa: E402
import caiman  # noqa: E402
from caiman import Refusal, newer, newest, refuse, same_release  # noqa: E402
import readings as readings_module  # noqa: E402

KINDS = ('grapheneos', 'andrix', 'stock')
CHANNELS = ('stable', 'beta', 'alpha', 'testing')   # script/generate-metadata's channels
ONLY_OFFICIAL = 'only the complete GrapheneOS script or the web installer may run'
EXIT = {'ALLOW': 0, 'REFUSE': 1, 'WAIT': 3}
SESSION_SCHEMA = 'andrix.pixel.session/1'
APPROVAL_SCHEMA = 'andrix.pixel.approval/2'
TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
DAY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
SESSION_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
SESSION_FILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json')
READINGS_MAX_AGE_MINUTES = 15     # the plan's limit; --readings-max-age may only lower it
READINGS_MAX_AGE_LIMIT = 15
STABLE_MAX_AGE_MINUTES = 15       # a caiman-stable file older than this at the start is stale
# git verify-tag runs the program of the signature's own format, which the clone's config
# could point elsewhere. Command line settings win over every config file. Only ssh-keygen may
# verify, the OpenPGP and X.509 programs always fail, a signature counts only for a principal of
# the allowed signers, and no revocation file of the clone applies.
VERIFY_PINS = ('-c', 'gpg.ssh.program=/usr/bin/ssh-keygen',
               '-c', 'gpg.program=/usr/bin/false', '-c', 'gpg.openpgp.program=/usr/bin/false',
               '-c', 'gpg.x509.program=/usr/bin/false', '-c', 'gpg.minTrustLevel=fully',
               '-c', 'gpg.ssh.revocationFile=/dev/null')


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_time(text):
    return datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ')


def check_time(text, what):
    if not isinstance(text, str) or TIME.fullmatch(text) is None:
        refuse(f'{what} {text!r} is not a UTC time like 2026-10-09T10:30:00Z')
    try:
        datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        refuse(f'{what} {text!r} is not a valid time')
    return text


def check_day(text, what):
    if not isinstance(text, str) or DAY.fullmatch(text) is None:
        refuse(f'{what} {text!r} is not a date like 2026-10-09')
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        refuse(f'{what} {text!r} is not a valid date')
    return text


# Signed tags and the records bound to them

def _git(repo, *args):
    import grapheneos_source
    try:
        return grapheneos_source.run(Path(repo), *args)[1]
    except grapheneos_source.SourceError as error:
        refuse(f'git {" ".join(args[-2:])} in the manifest repository failed: {error}')


def signed_tags(repo, signers, low, high, bases=None):
    """Every release tag from low through high in a local GrapheneOS manifest repository.

    Each tag in the range must verify with git verify-tag against the allowed signers file
    whose digest upstream/bases pins, with the signature programs pinned as
    grapheneos_source.py pins them, so the clone's own config cannot change the result.
    """
    import install_zip
    if caiman.sha256(Path(signers).read_bytes()) != install_zip.pinned_signers_digest(bases):
        refuse(f'{signers} is not the allowed signers file that upstream/bases pins')
    names = _git(repo, 'for-each-ref', '--format=%(refname:strip=2)', 'refs/tags').decode().split()
    low, high = sorted((low, high), key=lambda release: int(release.base))
    found = []
    for name in sorted(name for name in names if re.fullmatch(r'[0-9]{10}', name)):
        if int(low.base) <= int(name) <= int(high.base):
            release = caiman.parse_release(name, what='manifest tag')
            _git(repo, *VERIFY_PINS,
                 '-c', 'gpg.ssh.allowedSignersFile=' + str(Path(signers).resolve()),
                 'verify-tag', name)
            found.append(release.number)
    for release in (low, high):
        if release.base not in found:
            refuse(f'{release.base} is not a signed release tag of the manifest repository')
    return found


def adevtool_pin(manifest):
    """vendor/adevtool's revision in a manifest's bytes."""
    import xml.etree.ElementTree as ET
    try:
        projects = ET.fromstring(manifest).findall('project')
    except ET.ParseError:
        refuse('the tag manifest is not XML')
    found = [entry.get('revision') for entry in projects
             if entry.get('path', entry.get('name')) == 'vendor/adevtool']
    if len(found) != 1 or re.fullmatch(r'[0-9a-f]{40}', found[0] or '') is None:
        refuse('the tag manifest does not pin exactly one vendor/adevtool commit')
    return found[0]


def bind_record(record, repo, bases=None):
    """The record's adevtool commit must be the one its tag's signed manifest pins."""
    release = record['release']
    pinned = adevtool_record.base_record(release, bases)['manifest']
    checks = (('tag object', f'refs/tags/{release}', pinned.get('tag_object')),
              ('commit', f'refs/tags/{release}^{{commit}}', pinned.get('commit')))
    for what, ref, wanted in checks:
        actual = _git(repo, 'rev-parse', '--verify', ref).decode().strip()
        if actual != wanted:
            refuse(f'the {what} of tag {release} is {actual}, not the {wanted} upstream/bases pins')
    blob = _git(repo, 'rev-parse', '--verify', f'{pinned.get("commit")}:{pinned.get("path")}').decode().strip()
    if blob != pinned.get('blob'):
        refuse(f'the manifest blob of tag {release} is not the one upstream/bases pins')
    data = _git(repo, 'cat-file', 'blob', blob)
    if caiman.sha256(data) != pinned.get('sha256'):
        refuse(f'the manifest of tag {release} does not hash to the digest upstream/bases pins')
    revision = adevtool_pin(data)
    if record.get('adevtool_revision') != revision:
        refuse(f'the record for {release} names adevtool {record.get("adevtool_revision")}, but the '
               f'signed manifest of {release} pins {revision}')
    return revision


@dataclass(frozen=True)
class Table:
    """Each recorded release's stock build and versions, and the caiman builds of the indexes."""
    stock: dict      # base release number -> stock build ID
    versions: dict   # base release number -> caiman.AndroidInfo that adevtool generated
    builds: dict     # stock build ID -> index entry


def load_table(records, bases=None, repo=None, require_tree_head=True):
    stock, versions, builds, sources = {}, {}, {}, {}
    if not records:
        refuse('no adevtool record was supplied, so no release has a known stock build')
    for number, record in enumerate(records, 1):
        what = f'record {number}'
        release, build, entries, info = adevtool_record.validate_record(record, what, bases)
        if require_tree_head and record.get('tree_head') != record.get('adevtool_revision'):
            refuse(f'{what} for {release} names no tree commit it was derived from; derive it '
                   'again with adevtool_record.py record --tree')
        if repo is not None:
            bind_record(record, repo, bases)
        if release.base in stock and (stock[release.base], versions[release.base]) != (build, info):
            refuse(f'two records for {release.number} disagree')
        stock[release.base], versions[release.base] = build, info
        for entry_build, entry in entries.items():
            if entry_build in builds and builds[entry_build] != entry:
                refuse(f'the indexes of {sources[entry_build]} and {release.number} disagree '
                       f'about {entry_build}')
            builds.setdefault(entry_build, entry)
            sources.setdefault(entry_build, release.number)
    return Table(stock, versions, builds)


def check_coverage(table, tags, first, last):
    """Every signed release tag from first through last has a record, and both are tags."""
    low, high = sorted((first, last), key=lambda release: int(release.base))
    for release in (first, last):
        if release.base not in tags:
            refuse(f'{release.base} is not a signed release tag')
    covered = [number for number in tags if int(low.base) <= int(number) <= int(high.base)]
    missing = [number for number in covered if number not in table.stock]
    if missing:
        refuse(f'no adevtool record for the signed release tags {", ".join(missing)} between '
               f'{low.base} and {high.base}')
    return covered


# The session record

def start_session(session_id, day, previous=None, first=False, now=None,
                  stable=None, stable_fetched_at=None, build_number=None, names=()):
    """A new session record.

    stable is the content of caiman-stable fetched at stable_fetched_at, and build_number is the
    build number that stop point 1 records. The very first record starts from that current
    stable release, see stable_start. Every later record carries the phone's releases over from
    the previous one, and if the phone updated itself since, the current stable release starts
    it beside the carried releases. names are the sessions already in the chain.
    """
    if SESSION_ID.fullmatch(str(session_id)) is None:
        refuse(f'session name {session_id!r} is not a plain name')
    check_day(day, 'session date')
    now = check_time(now or utc_now(), 'session start')
    if (previous is None) != (first is True):
        refuse('a session starts from the previous session record, or once as the first session')
    if session_id in names:
        refuse(f'the chain already holds a session named {session_id}; the new session needs its own name')
    if previous is not None:
        prior = check_session(previous)
        if prior['session'] == session_id:
            refuse('the new session needs its own name')
        last = prior['allowed'][-1]['at'] if prior['allowed'] else prior['started_at']
        if now <= last:
            refuse(f'the new session would start at {now}, not after the previous session\'s '
                   f'last entry at {last}; check the clock')
        known = known_releases(prior)
        start = newest(known)
        carried = {release.number for release in known}
        update = None
        if (stable, stable_fetched_at, build_number) != (None, None, None):
            update = stable_start(stable, stable_fetched_at, build_number, known, now)
            start = caiman.parse_release(update['release'])
            carried.add(start.number)
        carried = sorted(carried)
        origin = caiman.sha256(caiman.dump(prior).encode())
    else:
        update = stable_start(stable, stable_fetched_at, build_number, [], now)
        start = caiman.parse_release(update['release'])
        carried, origin = [start.number], None
    return check_session({'schema': SESSION_SCHEMA, 'session': session_id, 'date': day,
                          'started_at': now, 'start_release': start.number, 'carried': carried,
                          'previous_sha256': origin, 'stable': update, 'verified': {},
                          'allowed': []})


def check_fetch(fetched_at, now, moment):
    """caiman-stable must have been fetched at most STABLE_MAX_AGE_MINUTES before now."""
    check_time(fetched_at, 'caiman-stable fetch time')
    if fetched_at > now:
        refuse(f'caiman-stable is dated {fetched_at}, after {moment} ({now}); check the clock')
    if parse_time(now) - parse_time(fetched_at) > datetime.timedelta(minutes=STABLE_MAX_AGE_MINUTES):
        refuse(f'caiman-stable was fetched at {fetched_at}, more than {STABLE_MAX_AGE_MINUTES} '
               f'minutes before {moment} ({now}); it is stale, fetch it again')


def stable_start(data, fetched_at, build_number, known, now):
    """The current stable release that starts the first record, or the record of a phone that
    updated itself.

    The release comes from caiman-stable, fetched at most STABLE_MAX_AGE_MINUTES before the
    start, never typed. It must be newer than every carried release, and the build number that
    stop point 1 records must show it or its security preview. A phone on the Stable channel runs
    no newer release, so the reference can only rise. Otherwise the session waits.
    """
    if data is None or fetched_at is None or build_number is None:
        refuse('the record starts from the current stable release, so it needs the caiman-stable '
               'file, its fetch time and the build number of stop point 1')
    release = caiman.parse_stable_channel(data)
    check_fetch(fetched_at, now, 'the start')
    older = sorted({number.number for number in known if not newer(release, number)})
    if older:
        refuse(f'the current stable release {release} is not newer than the carried releases '
               f'{", ".join(older)}, so the phone did not update past them; start without '
               '--updated-from-stable')
    build = caiman.parse_release(build_number, what='build number')
    if newer(release, build):
        refuse(f'the build number {build} is older than the current stable release {release}: '
               'the phone has not updated yet, so the session waits until it has, then reads '
               'stop point 1 and caiman-stable again')
    if not same_release(build, release):
        refuse(f'the build number {build} names another release than the current stable release '
               f'{release} or its security preview; fetch caiman-stable again and check the '
               'build number and the Stable channel')
    return {'release': release.number, 'fetched_at': fetched_at, 'build_number': build.number,
            'sha256': caiman.sha256(data)}


def check_session(session):
    if not isinstance(session, dict) or session.get('schema') != SESSION_SCHEMA:
        refuse(f'the session record is not an {SESSION_SCHEMA} document')
    if SESSION_ID.fullmatch(str(session.get('session'))) is None:
        refuse('the session record has no plain session name')
    check_day(session.get('date'), 'session date')
    check_time(session.get('started_at'), 'session start')
    if session['date'] != session['started_at'][:10]:
        refuse(f'the session date {session["date"]} is not the UTC date of its start '
               f'{session["started_at"]}; the session and its approval name the day it starts, in UTC')
    origin = session.get('previous_sha256', '')
    if origin is not None and caiman.SHA256.fullmatch(str(origin)) is None:
        refuse('the session record names no SHA-256 of a previous record, nor null for the first')
    start = caiman.parse_release(session.get('start_release'), what='session start release')
    check_stable_entry(session, start)
    check_verified(session)
    carried = session.get('carried')
    if not isinstance(carried, list) or not carried:
        refuse('the session record carries no known release')
    for number in carried:
        caiman.parse_release(number, what='carried release')
    if session['start_release'] not in carried:
        refuse('the session start release is not among the carried releases')
    if newer(newest([caiman.parse_release(number) for number in carried]), start):
        refuse('the session start release is older than a carried release')
    allowed = session.get('allowed')
    if not isinstance(allowed, list):
        refuse('the session record has no list of allowed writes')
    last = session['started_at']
    for entry in allowed:
        if not isinstance(entry, dict) or set(entry) != {'release', 'sha256', 'kind', 'at'}:
            refuse(f'session entry {entry!r} is not release, sha256, kind and at')
        caiman.parse_release(entry['release'], what='allowed release')
        check_time(entry['at'], 'allowed time')
        if entry['at'] < last:
            refuse('the session record is out of time order')
        last = entry['at']
    return session


def check_stable_entry(session, start):
    """A record that started from the current stable release names how it was read."""
    if 'stable' not in session:
        refuse('the session record does not say whether it started from the current stable release')
    entry = session['stable']
    if entry is None:
        if session.get('previous_sha256') is None:
            refuse('the first session record names no current stable release that it started from')
        return
    if not isinstance(entry, dict) or set(entry) != {'release', 'fetched_at', 'build_number', 'sha256'}:
        refuse('the session record\'s stable entry is not release, fetched_at, build_number and sha256')
    release = caiman.parse_release(entry['release'], what='stable release')
    build = caiman.parse_release(entry['build_number'], what='build number')
    check_time(entry['fetched_at'], 'caiman-stable fetch time')
    if caiman.SHA256.fullmatch(str(entry['sha256'])) is None:
        refuse('the session record\'s stable entry names no SHA-256 of caiman-stable')
    if release.number != start.number or not same_release(build, release):
        refuse('the session record\'s stable entry does not match its start release and build number')
    late = parse_time(session['started_at']) - parse_time(entry['fetched_at'])
    if not datetime.timedelta(0) <= late <= datetime.timedelta(minutes=STABLE_MAX_AGE_MINUTES):
        refuse('the session record\'s caiman-stable was not fetched within '
               f'{STABLE_MAX_AGE_MINUTES} minutes before its start')


IDENTITY_KEYS = {'kind', 'release', 'stock_build', 'android_info', 'source', 'wipes_data', 'at'}


def check_verified(session):
    """The identities that verify read from kits and zips in this session, by SHA-256."""
    verified = session.get('verified')
    if not isinstance(verified, dict):
        refuse('the session record has no map of verified images')
    for digest, entry in verified.items():
        if caiman.SHA256.fullmatch(str(digest)) is None:
            refuse(f'the session record names a verified image by {digest!r}, not a SHA-256')
        if not isinstance(entry, dict) or set(entry) != IDENTITY_KEYS:
            refuse(f'the verified identity of {digest} is not {", ".join(sorted(IDENTITY_KEYS))}')
        if entry['kind'] not in KINDS or not isinstance(entry['source'], str) or \
                not isinstance(entry['wipes_data'], bool):
            refuse(f'the verified identity of {digest} has no valid kind, source or wipe effect')
        caiman.parse_release(entry['release'], what='verified release')
        caiman.parse_build_id(entry['stock_build'], what='verified stock build')
        android_info(entry['android_info'], digest)
        check_time(entry['at'], 'verification time')
        if entry['at'] < session['started_at']:
            refuse(f'the verified identity of {digest} is older than the session')


def android_info(value, digest):
    if not isinstance(value, dict) or set(value) != {'board', 'bootloader', 'baseband', 'partitions'} \
            or not all(isinstance(value[key], str) for key in ('board', 'bootloader', 'baseband')) \
            or not isinstance(value['partitions'], list) \
            or not all(isinstance(item, str) for item in value['partitions']):
        refuse(f'the verified identity of {digest} has no valid android-info.txt')
    return caiman.AndroidInfo(value['board'], value['bootloader'], value['baseband'],
                              tuple(value['partitions']))


def known_releases(session):
    numbers = [session['start_release'], *session['carried'], *(e['release'] for e in session['allowed'])]
    return [caiman.parse_release(number) for number in numbers]


def phone_release(session):
    """The newest of the session's known releases: its start, every carried release and every
    release written since. The start comes first, so it wins among equal bases."""
    return newest(known_releases(session))


def leftover(path):
    return (f'{path} is left from an interrupted start, verify or decide, which never returned. '
            f'Inspect it, compare it with {Path(path).name[:-len(".new")]}, remove it by hand, '
            'and take fresh readings')


class RecordWritten(Refusal):
    """A refusal after the new record took its place. It carries the record's new SHA-256,
    computed from the bytes this command wrote, which the refusal prints on its last line."""

    def __init__(self, path, error, record_sha256):
        super().__init__(
            f'{path} already holds the new record that this command wrote, but finishing the '
            f'write failed: {error}. The command refuses, so write nothing now. Inspect the record '
            'and the disk. To go on, keep the SHA-256 on the last line, as after a command that '
            'did not refuse, and take fresh readings')
        self.record_sha256 = record_sha256


def write_session(path, session):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    text = caiman.dump(session)
    try:
        handle = open(temporary, 'x', encoding='utf-8')
    except FileExistsError:
        refuse(leftover(temporary))
    with handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    try:
        sync_directory(path)     # the rename is durable before the decision returns
    except OSError as error:
        raise RecordWritten(path, error, caiman.sha256(text.encode())) from error


def publish_record(path, session):
    """Writes a new record as write_session does, but never over an existing file."""
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    text = caiman.dump(session)
    try:
        handle = open(temporary, 'x', encoding='utf-8')
    except FileExistsError:
        refuse(leftover(temporary))
    with handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, path)
    except FileExistsError:
        os.unlink(temporary)
        refuse(f'{path} already exists')
    try:
        os.unlink(temporary)
        sync_directory(path)
    except OSError as error:
        raise RecordWritten(path, error, caiman.sha256(text.encode())) from error


def sync_directory(path):
    directory = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class Link:
    """A session record in its directory's chain."""
    path: Path
    record: dict
    sha256: str


def read_chain(directory):
    """Every session record in a directory, verified as one chain from the first session.

    The directory holds only session records, each a NAME.json file in the form the checker
    writes. Exactly one record has no previous record. Every other names the SHA-256 of a record
    in the directory, no two name the same one, and each starts after its previous record's last
    entry. Returns the records in chain order, so the newest is last.
    """
    directory = Path(directory)
    if not directory.is_dir():
        refuse(f'the session directory {directory} does not exist')
    links = {}
    for path in sorted(directory.iterdir()):
        if path.name.endswith('.new'):
            refuse(leftover(path))
        if path.is_symlink() or not path.is_file() or SESSION_FILE.fullmatch(path.name) is None:
            refuse(f'{path} is not a session record; the session directory holds only NAME.json '
                   'session records')
        data = path.read_bytes()
        try:
            record = check_session(json.loads(data))
        except (ValueError, UnicodeDecodeError):
            refuse(f'{path} is not JSON')
        except Refusal as error:
            refuse(f'{path}: {error}')
        if data != caiman.dump(record).encode():
            refuse(f'{path} is not in the form the checker writes')
        digest = caiman.sha256(data)
        if digest in links:
            refuse(f'{path} and {links[digest].path} are the same record')
        links[digest] = Link(path, record, digest)
    if not links:
        return []
    first = [link for link in links.values() if link.record['previous_sha256'] is None]
    if len(first) != 1:
        refuse(f'{len(first)} records in {directory} start a chain; exactly one may')
    child = {}
    for link in links.values():
        parent = link.record['previous_sha256']
        if parent is None:
            continue
        if parent not in links:
            refuse(f'{link.path} names the previous record {parent}, which no record in {directory} '
                   'hashes to; the chain is broken')
        if parent in child:
            refuse(f'{child[parent].path} and {link.path} name the same previous record '
                   f'{links[parent].path}; the chain forks')
        child[parent] = link
    chain, names = [first[0]], {first[0].record['session']}
    while chain[-1].sha256 in child:
        link, before = child[chain[-1].sha256], chain[-1].record
        last = before['allowed'][-1]['at'] if before['allowed'] else before['started_at']
        if link.record['started_at'] <= last:
            refuse(f'{link.path} starts at {link.record["started_at"]}, not after the last entry '
                   f'of its previous record {chain[-1].path}')
        if link.record['session'] in names:
            refuse(f'{link.path} repeats the session name {link.record["session"]}')
        names.add(link.record['session'])
        chain.append(link)
    if len(chain) != len(links):
        refuse(f'{len(links) - len(chain)} records in {directory} are not on the chain from its first record')
    return chain


def newest_link(chain, path, owner_sha256, kept='the SHA-256 the owner keeps'):
    """The chain's newest record, which path must name and the owner's SHA-256 must match."""
    if not chain:
        refuse(f'{Path(path).parent} holds no session record')
    newest_record = chain[-1]
    if Path(path).resolve() != newest_record.path.resolve():
        refuse(f'{path} is not the newest session record of its directory; the newest is '
               f'{newest_record.path.name}')
    if owner_sha256 is not None and owner_sha256 != newest_record.sha256:
        refuse(f'{newest_record.path.name} does not hash to {kept}; it may have been edited since')
    return newest_record


def lock_session(path):
    """Opens the session record and holds an exclusive lock on it, or refuses.

    The lock is held until the handle is closed. A decide that ran meanwhile replaced the file,
    so a handle whose file is no longer at path is refused.
    """
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    if temporary.exists() or temporary.is_symlink():
        refuse(leftover(temporary))
    handle = open(path, 'rb')
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            refuse(f'{path} is locked by another start, verify or decide; let it finish, then take '
                   'fresh readings')
        held, current = os.fstat(handle.fileno()), os.stat(path)
        if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
            refuse(f'{path} was replaced while this command opened it; take fresh readings and '
                   'run the command again')
    except BaseException:
        handle.close()
        raise
    return handle


def locked_record(handle, path, expected):
    """The record behind a held lock. It must be the newest of its chain and hash to the SHA-256
    that the last start, verify or decide printed."""
    newest_link(read_chain(Path(path).parent), path, expected,
                kept='the SHA-256 that the last start, verify or decide printed')
    data = handle.read()
    if caiman.sha256(data) != expected:
        refuse(f'{path} does not hash to the SHA-256 that the last start, verify or decide printed')
    return check_session(json.loads(data))


def lock_directory(directory):
    """Holds an exclusive lock on the session directory while start adds a record, or refuses."""
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        refuse(f'{directory} is locked by another start')
    return descriptor


def record_digest(session):
    return caiman.sha256(caiman.dump(session).encode())


# Images, identified from the image itself

@dataclass(frozen=True)
class Image:
    """An image whose identity was read from the image itself."""
    kind: str
    sha256: str
    release: caiman.Release      # the release it belongs to
    stock_build: str             # its stock build, read from the image or its index entry
    android_info: object         # caiman.AndroidInfo of the image
    source: str                  # how the identity was read
    wipes_data: bool = True      # every official caiman script wipes


def file_sha256(path):
    with open(path, 'rb') as handle:
        return handle_sha256(handle)


def handle_sha256(handle):
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(1 << 20), b''):
        digest.update(block)
    return digest.hexdigest()


def identity_entry(image, at):
    """The identity that verify keeps in the session record under the image's SHA-256."""
    return {'kind': image.kind, 'release': image.release.number, 'stock_build': image.stock_build,
            'android_info': image.android_info.as_dict(), 'source': image.source,
            'wipes_data': image.wipes_data, 'at': at}


def verified_image(session, path, kind, table):
    """The identity verify kept for this file's SHA-256, checked against the records and, for a
    kit or zip, against the identity the zip states itself."""
    with open(path, 'rb') as handle:
        before = os.fstat(handle.fileno())
        digest = handle_sha256(handle)
        entry = session['verified'].get(digest)
        if entry is None:
            refuse(f'{Path(path).name} hashes to {digest}, and the session record holds no verified '
                   'identity under that SHA-256; run verify on this file first')
        if entry['kind'] != kind:
            refuse(f'{Path(path).name} was verified as {entry["kind"]}, not {kind}')
        image = Image(kind, digest, caiman.parse_release(entry['release'], what='verified release'),
                      entry['stock_build'], android_info(entry['android_info'], digest),
                      entry['source'], entry['wipes_data'])
        check_identity(image, table)
        if kind != 'stock':
            check_own_identity(image, path, handle)
        after, current = os.fstat(handle.fileno()), os.stat(path)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or \
                (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
            refuse(f'{Path(path).name} changed or was replaced while decide read it; verify it again')
    return image


def own_identity(path, kind, handle=None):
    """What a kit or zip states about itself: the release that its vbmeta names, as the build
    number of its fingerprints or, for an Andrix zip, its base tag property, the stock build of
    its fingerprints and its android-info.txt. These are small reads, and nothing here verifies
    a signature. Read through the handle that hashed the file to the SHA-256 that verify kept,
    they are the bytes that verify checked."""
    import install_zip
    archive = install_zip.Archive(path, handle=handle)
    try:
        info = caiman.parse_android_info(archive.read('android-info.txt'),
                                         f'the android-info.txt of {Path(path).name}')
        vbmeta = install_zip.parse_vbmeta(archive.read('vbmeta.img'))
    except Refusal:
        raise
    except Exception as error:      # an unreadable member is a refusal, never a pass
        refuse(f'{Path(path).name}: its own identity cannot be read: {type(error).__name__}: {error}')
    finally:
        archive.zip.close()
    if kind == 'andrix':
        return install_zip.andrix_base_tag(vbmeta), install_zip.andrix_stock_build(vbmeta), info
    release, stock, _ = install_zip.build_identity(vbmeta)
    return release, stock, info


def check_own_identity(image, path, handle=None):
    """decide reads a kit's or zip's own identity again and refuses any mismatch with the
    identity kept under its SHA-256, so an identity edited in the record is caught even when
    the record's SHA-256 was computed again by hand."""
    release, stock, info = own_identity(path, image.kind, handle)
    mismatched = [name for name, own, kept in (
        ('release', release.number, image.release.number), ('stock build', stock, image.stock_build),
        ('android-info.txt', info, image.android_info)) if own != kept]
    if mismatched:
        refuse(f'{Path(path).name} itself names release {release}, stock build {stock} and '
               f'android-info.txt {info.as_dict()}, but the session record keeps release '
               f'{image.release}, stock build {image.stock_build} and android-info.txt '
               f'{image.android_info.as_dict()} for {image.sha256}; they differ in '
               f'{", ".join(mismatched)}, so the record no longer holds what verify read. Write '
               'nothing, and inspect the record')


def check_identity(image, table):
    """A kept identity must still agree with the records this decide was given."""
    base = image.release.base
    agrees = table.stock.get(base) == image.stock_build and table.versions.get(base) == image.android_info
    if image.kind == 'stock':
        entry = table.builds.get(image.stock_build)
        built = sorted(number for number, stock in table.stock.items() if stock == image.stock_build)
        agrees = agrees and entry is not None and entry['factory_sha256'] == image.sha256 \
            and built[:1] == [base]
    if not agrees:
        refuse(f'the verified identity of {image.sha256} disagrees with the supplied adevtool '
               'records; verify the file again with the records of this session')


def stock_image(path, table):
    """Google's factory image, identified by the SHA-256 that adevtool's index records."""
    digest = file_sha256(path)
    found = [build for build, entry in table.builds.items() if entry['factory_sha256'] == digest]
    if len(found) != 1:
        refuse(f'{Path(path).name} matches no factory image digest in the supplied adevtool indexes')
    build = found[0]
    releases = sorted(base for base, stock in table.stock.items() if stock == build)
    if not releases:
        refuse(f'no supplied GrapheneOS release is built from stock build {build} '
               f'("{table.builds[build]["desc"]}"); a stock image that no release is built from, '
               'such as a carrier variant, is refused')
    release = caiman.parse_release(releases[0])
    return Image('stock', digest, release, build, table.versions[release.base],
                 f'factory image digest of {build} in adevtool\'s index; the earliest recorded '
                 f'release built from it is {release}')


def grapheneos_image(path, kit):
    """A GrapheneOS install zip, identified by install_zip's verified build number."""
    import install_zip
    name = Path(path).name
    match = re.fullmatch(r'caiman-install-([0-9]{10})\.zip', name)
    if match is None:
        refuse(f'{name} is not named caiman-install-RELEASE.zip')
    record = kit['records'].get(caiman.parse_release(match.group(1)).base)
    if record is None:
        refuse(f'no adevtool record for the release {match.group(1)} that {name} names')
    report = install_zip.check(path, signature=kit.get('signature') or f'{path}.sig',
                               signers=kit['signers'], release=match.group(1), stable=kit['stable'],
                               security_patch=kit.get('security_patch'), record=record,
                               avbtool=kit['avbtool'], tools=kit.get('tools'))
    if report['verdict'] != 'PASS':
        refuse(f'{name} does not pass the checks that need no phone: ' + '; '.join(report['reasons']))
    identity = report['checks']['release_identity']['detail']
    detail = report['checks']['android_info']['detail']
    info = caiman.AndroidInfo(detail['board'], detail['bootloader'], detail['baseband'],
                              tuple(detail['partitions']))
    return Image('grapheneos', report['sha256'],
                 caiman.parse_release(identity['build_number'], what='build number inside the zip'),
                 identity['stock_build'], info, 'the signed build number inside the zip')


def andrix_image(path, kit, table):
    """An Andrix zip: workshop key, base tag record and the official kit's firmware."""
    import install_zip
    identity = install_zip.andrix_identity(path, avbtool=kit['avbtool'], tools=kit.get('tools'))
    base = caiman.parse_release(identity['base_tag'], allow_preview=False, what='base tag')
    if base.base not in table.versions:
        refuse(f'no adevtool record for the Andrix base tag {base}')
    if identity['android_info'] != table.versions[base.base]:
        refuse(f'the Andrix android-info.txt {identity["android_info"].as_dict()} is not the '
               f'{table.versions[base.base].as_dict()} recorded for {base}')
    if identity['stock_build'] != table.stock[base.base]:
        refuse(f'the Andrix fingerprint names stock build {identity["stock_build"]}, not the '
               f'{table.stock[base.base]} recorded for {base}')
    if not kit.get('official'):
        refuse(f'an Andrix zip needs the official GrapheneOS kit of {base} for its firmware')
    official = grapheneos_image(kit['official'], kit)
    if official.release.number != base.number:
        refuse(f'the official kit is {official.release}, not the base tag {base}')
    theirs = install_zip.kit_firmware(kit['official'], official.android_info)
    if identity['firmware'] != theirs:
        refuse(f'the Andrix bootloader and radio images are not byte identical to the official kit of {base}')
    return Image('andrix', identity['sha256'], base, identity['stock_build'], identity['android_info'],
                 f'the workshop signed vbmeta, its base tag {base} and the official kit '
                 f'{official.sha256}')


# The approval and the decision

def load_approval(data):
    """The session's approval: its session, its date and every artifact by SHA-256."""
    try:
        value = json.loads(data)
    except (ValueError, TypeError):
        refuse('the approval is not JSON')
    if not isinstance(value, dict) or value.get('schema') != APPROVAL_SCHEMA:
        refuse(f'the approval is not an {APPROVAL_SCHEMA} document')
    if set(value) != {'schema', 'session', 'date', 'artifacts'}:
        refuse('the approval holds exactly schema, session, date and artifacts')
    if SESSION_ID.fullmatch(str(value['session'])) is None:
        refuse('the approval names no plain session')
    check_day(value['date'], 'approval date')
    artifacts = value['artifacts']
    if not isinstance(artifacts, list) or not artifacts:
        refuse('the approval names no artifact')
    named = {}
    for entry in artifacts:
        if (not isinstance(entry, dict) or set(entry) != {'sha256', 'kind', 'wipes_data'}
                or caiman.SHA256.fullmatch(str(entry.get('sha256'))) is None
                or entry['kind'] not in KINDS or not isinstance(entry['wipes_data'], bool)):
            refuse(f'approval entry {entry!r} is not sha256, kind and wipes_data')
        if entry['sha256'] in named:
            refuse(f'the approval names {entry["sha256"]} twice')
        named[entry['sha256']] = entry
    return {'session': value['session'], 'date': value['date'], 'artifacts': named}


def check_firmware(readings, known, table):
    """Each firmware reading must equal the version that one of the known releases records."""
    matched = {}
    for name, key in (('version-bootloader', 'bootloader'), ('version-baseband', 'baseband')):
        reading = readings[name]
        if not reading.answered:
            refuse(f'{name} is unanswered, so it matches no known release')
        found = []
        for release in known:
            recorded = table.versions.get(release.base)
            if recorded is None:
                refuse(f'no adevtool record gives the versions of the known release {release}')
            if getattr(recorded, key) == reading.value:
                found.append(release.number)
        if not found:
            refuse(f'{name} reads {reading.value}, which none of the session\'s known releases '
                   f'{sorted({r.number for r in known})} records; it may come from newer '
                   'firmware, so every write is refused')
        matched[name] = sorted(set(found))
    return matched


def criterion(image, reference, table):
    if newer(image.release, reference):
        return 'newer', f'{image.release} is newer than {reference}'
    reference_stock = table.stock.get(reference.base)
    if reference_stock is None:
        refuse(f'no supplied record gives the stock build of {reference}')
    if image.stock_build != reference_stock:
        refuse(f'{image.release} is not newer than {reference}, and its stock build '
               f'{image.stock_build} is not the stock build {reference_stock} of {reference}')
    return 'same stock build', f'same stock build {reference_stock} as {reference}'


def decide(image, *, table, tags, readings, stage, os_booted, update_pending, channel, session,
           approval, session_path=None, current_stable=None, stable_fetched_at=None,
           security_previews=None, now=None, readings_max_age=READINGS_MAX_AGE_MINUTES):
    """Returns the decision, ALLOW or WAIT, and records an ALLOW in the session record first."""
    if not isinstance(image, Image):
        refuse('the image identity must come from the image')
    if not isinstance(os_booted, bool) or update_pending not in ('yes', 'no', 'unknown'):
        refuse('whether the OS booted and whether an update is pending must be stated')
    if channel != 'stable':
        refuse(f'the phone is on the {channel!r} channel; this plan requires Stable')
    session = check_session(session)
    if not isinstance(approval, dict) or (approval.get('session'), approval.get('date')) != \
            (session['session'], session['date']):
        refuse(f'the approval does not name session {session["session"]} of {session["date"]}')
    if stage == 3:
        refuse('nothing is written in stage 3')
    if image.kind == 'andrix' and stage < 8:
        refuse(f'no Andrix image is written before stage 8; this is stage {stage}')
    if os_booted and update_pending != 'no':
        refuse('stop point 1: an update is pending or its state is unknown; wait for it, reboot '
               'into it and start again')
    taken = check_time(readings['taken-at'].value, 'readings time')
    now = check_time(now or utc_now(), 'decision time')
    if taken > now:
        refuse(f'the readings are dated {taken}, after now ({now}); check the clock')
    if (isinstance(readings_max_age, bool) or not isinstance(readings_max_age, int)
            or not 1 <= readings_max_age <= READINGS_MAX_AGE_LIMIT):
        refuse(f'the maximum age of readings is 1 to {READINGS_MAX_AGE_LIMIT} minutes, not '
               f'{readings_max_age!r}')
    if parse_time(now) - parse_time(taken) > datetime.timedelta(minutes=readings_max_age):
        unit = 'minute' if readings_max_age == 1 else 'minutes'
        refuse(f'the readings were taken at {taken}, more than {readings_max_age} {unit} before '
               f'now ({now}); take fresh readings')
    last = session['allowed'][-1]['at'] if session['allowed'] else None
    if taken < session['started_at'] or (last is not None and taken <= last):
        refuse(f'the readings were taken at {taken}, before the session start or its last ALLOW; '
               'take fresh readings')
    point_3 = readings_module.stop_point_3(readings, stage, os_booted)
    if not point_3['continue']:
        refuse('stop point 3: ' + '; '.join(point_3['stops']))
    known = known_releases(session)
    reference = phone_release(session)
    matched = check_firmware(readings, known, table)
    decision = {'artifact': {'sha256': image.sha256, 'kind': image.kind,
                             'release': image.release.number, 'stock_build': image.stock_build,
                             'identity': image.source},
                'session': session['session'], 'phone_release': reference.number,
                'known_releases': sorted({release.number for release in known}),
                'firmware_matches': matched, 'readings_taken_at': taken,
                'readings_max_age_minutes': readings_max_age, 'decided_at': now, 'channel': channel,
                'security_previews': security_previews, 'stop_point_3': point_3,
                'conditions': [], 'explanations': []}
    if os_booted:
        decision['mode'] = 'normal'
    else:
        decision['mode'] = 'exception: the OS does not boot, stop point 1 skipped'
        if update_pending != 'no' or point_3['restricted']:
            if not isinstance(current_stable, caiman.Release) or not stable_fetched_at:
                refuse('an update may be pending, so caiman-stable read at this moment, with the '
                       'time of the fetch, is needed')
            check_fetch(stable_fetched_at, now, 'the decision')
            if image.kind != 'grapheneos':
                refuse('while an update is pending only the current stable official GrapheneOS '
                       'release may be written')
            if not same_release(image.release, current_stable):
                refuse(f'while an update is pending only the current stable release '
                       f'{current_stable} or its security preview may be written, not {image.release}')
            if newer(reference, current_stable):
                refuse(f"the phone's release {reference} counts as newer than the current stable "
                       f'release {current_stable}: nothing is written, stop in fastboot mode')
            decision['covered'] = check_coverage(table, tags, reference, image.release)
            decision.update(branch='current stable',
                            stable={'release': current_stable.number, 'fetched_at': stable_fetched_at})
            decision['conditions'].append(ONLY_OFFICIAL)
            decision['explanations'].append(
                f'{image.release} is the current stable release, which counts as newer than '
                f'{reference} while an update is pending')
            return _approve(decision, image, approval, session, session_path, now)
    decision['covered'] = check_coverage(table, tags, reference, image.release)
    branch, explanation = criterion(image, reference, table)
    decision.update(branch=branch)
    decision['explanations'].append(explanation)
    return _approve(decision, image, approval, session, session_path, now)


def _approve(decision, image, approval, session, session_path, now):
    entry = approval['artifacts'].get(image.sha256)
    if entry is None:
        decision.update(verdict='WAIT', approval='the session approval does not name '
                        f'{image.sha256}; wait in fastboot mode for a fresh approval')
        return decision
    if entry['kind'] != image.kind or entry['wipes_data'] != image.wipes_data:
        refuse(f'the approval names {image.sha256} as {entry["kind"]} with wipes_data '
               f'{entry["wipes_data"]}, but it is {image.kind} with wipes_data {image.wipes_data}')
    allowed = {'release': image.release.number, 'sha256': image.sha256, 'kind': image.kind, 'at': now}
    session['allowed'].append(allowed)
    check_session(session)
    if session_path is not None:
        write_session(session_path, session)    # recorded before the write runs
    decision.update(verdict='ALLOW', approval=f'named, {image.kind}, wipes data: {image.wipes_data}',
                    recorded=allowed)
    return decision


def desk(image, *, table, tags, base_tag):
    """Gate step 8 at the desk: the way back judged against the build's base tag, no phone."""
    if not isinstance(image, Image) or image.kind == 'andrix':
        refuse('the desk check judges way back kits: a GrapheneOS kit or Google\'s image')
    base = caiman.parse_release(base_tag, allow_preview=False, what='base tag')
    if base.base not in table.versions:
        refuse(f'no adevtool record for the base tag {base}')
    covered = check_coverage(table, tags, base, image.release)
    result = {'artifact': {'sha256': image.sha256, 'kind': image.kind,
                           'release': image.release.number, 'stock_build': image.stock_build},
              'base_tag': base.number, 'covered': covered}
    if image.kind == 'grapheneos':
        if newer(base, image.release):
            refuse(f'the GrapheneOS kit {image.release} is older than the base tag {base}')
        result.update(verdict='PASS', branch='no older than the base tag')
        return result
    branch, explanation = criterion(image, base, table)
    result.update(verdict='PASS', branch=branch, explanation=explanation)
    return result


def yes_no(text):
    if text not in ('yes', 'no'):
        raise argparse.ArgumentTypeError('state yes or no')
    return text == 'yes'


def minutes_option(text):
    if re.fullmatch(r'[0-9]{1,2}', text) is None or not 1 <= int(text) <= READINGS_MAX_AGE_LIMIT:
        raise argparse.ArgumentTypeError(f'state whole minutes from 1 to {READINGS_MAX_AGE_LIMIT}')
    return int(text)


def sha256_option(text):
    if caiman.SHA256.fullmatch(text) is None:
        raise argparse.ArgumentTypeError('state a SHA-256 as 64 lowercase hex digits')
    return text


def modified_at(handle):
    """A file's modification time, as a UTC time: the fetch time of a file saved by curl -o."""
    seconds = int(os.fstat(handle.fileno()).st_mtime)
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def read_stable(path):
    """caiman-stable as saved by curl -o, and its modification time as the fetch time."""
    if path is None:
        return None, None
    with open(path, 'rb') as handle:
        return handle.read(), modified_at(handle)


def start(args):
    """Writes a new session record beside the chain it continues, in the same directory."""
    out = Path(args.out)
    directory = out.parent
    if SESSION_FILE.fullmatch(out.name) is None:
        refuse(f'the new record {out} is not named NAME.json')
    if args.first:
        if args.previous_sha256 or args.updated_from_stable:
            refuse('--previous-sha256 and --updated-from-stable continue a chain; the first session '
                   'starts --from-stable')
        stable_path = args.from_stable
    else:
        if args.from_stable:
            refuse('--from-stable starts the first session; a later one gives --updated-from-stable '
                   'if the phone updated itself')
        if not args.previous_sha256:
            refuse("a later session needs --previous-sha256, the newest record's SHA-256 as the "
                   'owner keeps it privately')
        if Path(args.previous).resolve().parent != directory.resolve():
            refuse(f'the new record {out} must go beside the previous record {args.previous}')
        stable_path = args.updated_from_stable
    folder = lock_directory(directory)
    lock = None
    try:
        if args.first:
            if read_chain(directory):
                refuse(f'{directory} already holds session records; only the very first session '
                       'starts with --first, every later one from the newest record')
            stable, fetched_at = read_stable(stable_path)
            session = start_session(args.session, args.date, first=True, stable=stable,
                                    stable_fetched_at=fetched_at, build_number=args.build_number)
        else:
            lock = lock_session(args.previous)      # no verify or decide may change it meanwhile
            chain = read_chain(directory)
            link = newest_link(chain, args.previous, args.previous_sha256)
            stable, fetched_at = read_stable(stable_path)
            session = start_session(args.session, args.date, previous=link.record,
                                    stable=stable, stable_fetched_at=fetched_at,
                                    build_number=args.build_number,
                                    names={entry.record['session'] for entry in chain})
        publish_record(out, session)
    finally:
        if lock is not None:
            lock.close()
        os.close(folder)
    return session


def verify(args):
    """Verifies a kit or zip once in this session and keeps its identity in the session record.

    The slow checks run here, under the record's lock. decide later only hashes the file again.
    """
    lock = lock_session(args.session)
    try:
        session = locked_record(lock, args.session, args.record_sha256)
        records = [json.loads(Path(path).read_text(encoding='utf-8')) for path in args.record]
        table = load_table(records, repo=args.manifests)
        by_release = {caiman.parse_release(record['release']).base: record for record in records}
        image = _image(args, table, by_release)
        entry = identity_entry(image, utc_now())
        kept = session['verified'].get(image.sha256)
        if kept is None:
            session['verified'][image.sha256] = entry
            check_session(session)
            write_session(args.session, session)
        elif dict(kept, at=None) != dict(entry, at=None):
            refuse(f'the session record already holds another identity for {image.sha256}')
        report = {'verdict': 'VERIFIED', 'sha256': image.sha256,
                  'identity': session['verified'][image.sha256]}
        return report, record_digest(session)
    finally:
        lock.close()


def _tables(sub):
    sub.add_argument('--record', action='append', required=True,
                     help='adevtool record of a tag, from adevtool_record.py; repeat per tag')
    sub.add_argument('--manifests', required=True,
                     help='a local clone of GrapheneOS platform_manifest with its signed tags')
    sub.add_argument('--allowed-signers', required=True, help='the file upstream/bases pins')
    sub.add_argument('--image', required=True, choices=KINDS)
    sub.add_argument('--zip', required=True, help='the image file; its identity is read from it')


def _common(sub):
    _tables(sub)
    sub.add_argument('--sig', help='a GrapheneOS kit signature; default ZIP.sig')
    sub.add_argument('--official-kit', help="an Andrix zip's base tag kit, with ZIP.sig beside it")
    sub.add_argument('--stable', help='caiman-stable as read at this moment')
    sub.add_argument('--avbtool', help='external/avb/avbtool.py of the pinned tree')
    sub.add_argument('--simg2img', help='the pinned simg2img')
    sub.add_argument('--lpunpack', help='the pinned lpunpack')


def _image(args, table, records):
    if args.image == 'stock':
        return stock_image(args.zip, table)
    kit = {'records': records, 'signers': args.allowed_signers, 'stable': args.stable,
           'signature': args.sig, 'avbtool': args.avbtool, 'official': args.official_kit,
           'tools': {'simg2img': args.simg2img, 'lpunpack': args.lpunpack}}
    if not args.stable or not args.avbtool:
        refuse('a GrapheneOS kit or an Andrix zip needs --stable and --avbtool')
    if args.image == 'grapheneos':
        return grapheneos_image(args.zip, kit)
    return andrix_image(args.zip, dict(kit, signature=None), table)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    begin = sub.add_parser('start', help='write a new session record')
    begin.add_argument('--out', required=True, help='the new session record, NAME.json in the '
                       'session directory, which holds only session records')
    begin.add_argument('--session', required=True, help='the name the approval gives the session')
    begin.add_argument('--date', required=True, help='the approval date, YYYY-MM-DD, the UTC date '
                       'of the start')
    origin = begin.add_mutually_exclusive_group(required=True)
    origin.add_argument('--previous', help="the newest session record, in the same directory")
    origin.add_argument('--first', action='store_true', help='only for the very first session')
    begin.add_argument('--from-stable', metavar='FILE', help='with --first: caiman-stable, saved at '
                       'this moment with curl -o into a fresh file; its modification time is the '
                       'fetch time')
    begin.add_argument('--previous-sha256', type=sha256_option,
                       help="with --previous: the newest record's SHA-256 as the owner keeps it")
    begin.add_argument('--updated-from-stable', metavar='FILE', help='with --previous, only if the '
                       'phone updated itself since: caiman-stable, saved at this moment with curl -o; '
                       'its modification time is the fetch time')
    begin.add_argument('--build-number', help='with --from-stable or --updated-from-stable: the '
                       'build number that stop point 1 records from Settings')
    once = sub.add_parser('verify', help='verify a kit or zip once and keep its identity in the '
                          'session record')
    _common(once)
    once.add_argument('--session', required=True, help="this session's record")
    once.add_argument('--record-sha256', required=True, type=sha256_option,
                      help='the SHA-256 that the last start, verify or decide printed')
    run = sub.add_parser('decide', help='may this image be written now?')
    _tables(run)
    run.add_argument('--stable', help='caiman-stable, saved at this moment with curl -o into a fresh '
                     'file; its modification time is the fetch time')
    run.add_argument('--session', required=True, help="this session's record, updated on ALLOW")
    run.add_argument('--record-sha256', required=True, type=sha256_option,
                     help='the SHA-256 that the last start, verify or decide printed')
    run.add_argument('--readings', required=True, help='the output of readings.sh')
    run.add_argument('--stage', type=int, required=True, choices=readings_module.SESSION_STAGES)
    run.add_argument('--os-booted', type=yes_no, required=True)
    run.add_argument('--update-pending', required=True, choices=('yes', 'no', 'unknown'))
    run.add_argument('--channel', required=True, choices=CHANNELS)
    run.add_argument('--security-previews', type=yes_no, required=True)
    run.add_argument('--approval', required=True, help="the session's approval")
    run.add_argument('--readings-max-age', type=minutes_option, default=READINGS_MAX_AGE_MINUTES,
                     help=f'minutes, default {READINGS_MAX_AGE_MINUTES}')
    check = sub.add_parser('desk', help="gate step 8: the way back against a build's base tag")
    _common(check)
    check.add_argument('--base-tag', required=True)
    args = parser.parse_args(argv)
    lock = None
    try:
        if args.command == 'start':
            session = start(args)
            return report(session, record_digest(session), 0)
        if args.command == 'verify':
            return report(*verify(args), 0)
        if args.command == 'decide':
            # The lock is held from before the record is read until after the ALLOW is written.
            lock = lock_session(args.session)
            session = locked_record(lock, args.session, args.record_sha256)
        records = [json.loads(Path(path).read_text(encoding='utf-8')) for path in args.record]
        table = load_table(records, repo=args.manifests)
        by_release = {caiman.parse_release(record['release']).base: record for record in records}
        if args.command == 'desk':
            image = _image(args, table, by_release)
            base = caiman.parse_release(args.base_tag, allow_preview=False, what='base tag')
            tags = signed_tags(args.manifests, args.allowed_signers, base, image.release)
            return report(desk(image, table=table, tags=tags, base_tag=args.base_tag), None, 0)
        image = verified_image(session, args.zip, args.image, table)
        reference = phone_release(session)
        tags = signed_tags(args.manifests, args.allowed_signers,
                           min(known_releases(session) + [image.release], key=lambda r: int(r.base)),
                           max([reference, image.release], key=lambda r: int(r.base)))
        data, fetched_at = read_stable(args.stable)
        decision = decide(
            image, table=table, tags=tags,
            readings=readings_module.parse(Path(args.readings).read_bytes()),
            stage=args.stage, os_booted=args.os_booted, update_pending=args.update_pending,
            channel=args.channel, security_previews=args.security_previews, session=session,
            session_path=args.session,
            current_stable=caiman.parse_stable_channel(data) if data is not None else None,
            stable_fetched_at=fetched_at,
            approval=load_approval(Path(args.approval).read_bytes()),
            readings_max_age=args.readings_max_age)
        return report(decision, record_digest(session), EXIT[decision['verdict']])
    except (Refusal, OSError, ValueError, KeyError) as error:
        # a refusal after the new record took its place prints that record's SHA-256
        return report({'verdict': 'REFUSE', 'reasons': [str(error)]},
                      getattr(error, 'record_sha256', None), EXIT['REFUSE'])
    finally:
        if lock is not None:
            lock.close()


def report(value, record_sha256, status):
    """Prints the JSON report. After a start, a verify or a decide that did not refuse, the last
    line is the record's new SHA-256, which the next verify or decide needs as --record-sha256.
    So it is after a refusal that came once the new record had taken its place."""
    sys.stdout.write(caiman.dump(value))
    if record_sha256 is not None:
        sys.stdout.write(record_sha256 + '\n')
    return status


if __name__ == '__main__':
    sys.exit(main())
