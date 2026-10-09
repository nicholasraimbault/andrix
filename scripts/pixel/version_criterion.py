#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stop point 4, the version criterion, and the exception "When the OS does not boot".

An image may be written only if each firmware reading equals the version that one of the
session's known releases records, and its release is newer than the phone's release or it
has the same stock build ID as the phone's release. The known releases are the release
recorded at the session's start and every release written in the session. Stock build IDs
are compared only for equality.

No typed value can approve older firmware:
- the image's identity is read from the image, and the decision names its SHA-256;
- the session's facts live in the checker's own session record, which takes each ALLOWed
  release before the write runs and carries the phone's release into the next session;
- readings carry the time they were taken and must be newer than the session's last ALLOW;
- the release tags come from the signed tags of a local GrapheneOS manifest repository,
  each verified against the pinned allowed signers, and every record is bound to its tag's
  signed manifest;
- the session's approval must name the session, its date and the image.

Exit status: 0 ALLOW, 1 REFUSE, 3 WAIT for a fresh approval. See README.md.
"""
import argparse
from dataclasses import dataclass
import datetime
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


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


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
    whose digest upstream/bases pins, as grapheneos_source.py verifies its tag.
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
            _git(repo, '-c', 'gpg.ssh.allowedSignersFile=' + str(Path(signers).resolve()),
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

def start_session(session_id, day, previous=None, first_release=None, now=None):
    """A new session record. The phone's release carries over from the previous record."""
    if SESSION_ID.fullmatch(str(session_id)) is None:
        refuse(f'session name {session_id!r} is not a plain name')
    check_day(day, 'session date')
    if (previous is None) == (first_release is None):
        refuse('a session starts from the previous session record, or once from the first release')
    if previous is not None:
        prior = check_session(previous)
        if prior['session'] == session_id:
            refuse('the new session needs its own name')
        known = known_releases(prior)
        start = newest(known)
        carried = sorted({release.number for release in known})
        origin = caiman.sha256(caiman.dump(prior).encode())
    else:
        start = caiman.parse_release(first_release, what='first release')
        carried, origin = [start.number], None
    return {'schema': SESSION_SCHEMA, 'session': session_id, 'date': day,
            'started_at': now or utc_now(), 'start_release': start.number, 'carried': carried,
            'previous_sha256': origin, 'allowed': []}


def check_session(session):
    if not isinstance(session, dict) or session.get('schema') != SESSION_SCHEMA:
        refuse(f'the session record is not an {SESSION_SCHEMA} document')
    if SESSION_ID.fullmatch(str(session.get('session'))) is None:
        refuse('the session record has no plain session name')
    check_day(session.get('date'), 'session date')
    check_time(session.get('started_at'), 'session start')
    start = caiman.parse_release(session.get('start_release'), what='session start release')
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


def known_releases(session):
    numbers = [session['start_release'], *session['carried'], *(e['release'] for e in session['allowed'])]
    return [caiman.parse_release(number) for number in numbers]


def phone_release(session):
    """The newest of the session's known releases: its start, every carried release and every
    release written since. The start comes first, so it wins among equal bases."""
    return newest(known_releases(session))


def write_session(path, session):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    with open(temporary, 'x', encoding='utf-8') as handle:
        handle.write(caiman.dump(session))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


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
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


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
           security_previews=None, now=None):
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
    now = now or utc_now()
    if taken > now:
        refuse(f'the readings are dated {taken}, after now ({now}); check the clock')
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
                'firmware_matches': matched, 'readings_taken_at': taken, 'channel': channel,
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


def _common(sub):
    sub.add_argument('--record', action='append', required=True,
                     help='adevtool record of a tag, from adevtool_record.py; repeat per tag')
    sub.add_argument('--manifests', required=True,
                     help='a local clone of GrapheneOS platform_manifest with its signed tags')
    sub.add_argument('--allowed-signers', required=True, help='the file upstream/bases pins')
    sub.add_argument('--image', required=True, choices=KINDS)
    sub.add_argument('--zip', required=True, help='the image file; its identity is read from it')
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
    start = sub.add_parser('start', help='write a new session record')
    start.add_argument('--out', required=True, help='the new session record')
    start.add_argument('--session', required=True, help='the name the approval gives the session')
    start.add_argument('--date', required=True, help='the approval date, YYYY-MM-DD')
    origin = start.add_mutually_exclusive_group(required=True)
    origin.add_argument('--previous', help="the previous session's record")
    origin.add_argument('--first-release', help='only for the very first session: the phone\'s '
                        'release as its private record shows it')
    run = sub.add_parser('decide', help='may this image be written now?')
    _common(run)
    run.add_argument('--session', required=True, help="this session's record, updated on ALLOW")
    run.add_argument('--readings', required=True, help='the output of readings.sh')
    run.add_argument('--stage', type=int, required=True, choices=readings_module.SESSION_STAGES)
    run.add_argument('--os-booted', type=yes_no, required=True)
    run.add_argument('--update-pending', required=True, choices=('yes', 'no', 'unknown'))
    run.add_argument('--channel', required=True, choices=CHANNELS)
    run.add_argument('--security-previews', type=yes_no, required=True)
    run.add_argument('--stable-fetched-at')
    run.add_argument('--approval', required=True, help="the session's approval")
    check = sub.add_parser('desk', help="gate step 8: the way back against a build's base tag")
    _common(check)
    check.add_argument('--base-tag', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'start':
            previous = (json.loads(Path(args.previous).read_text(encoding='utf-8'))
                        if args.previous else None)
            session = start_session(args.session, args.date, previous, args.first_release)
            with open(args.out, 'x', encoding='utf-8') as handle:
                handle.write(caiman.dump(session))
            sys.stdout.write(caiman.dump(session))
            return 0
        records = [json.loads(Path(path).read_text(encoding='utf-8')) for path in args.record]
        table = load_table(records, repo=args.manifests)
        by_release = {caiman.parse_release(record['release']).base: record for record in records}
        image = _image(args, table, by_release)
        if args.command == 'desk':
            base = caiman.parse_release(args.base_tag, allow_preview=False, what='base tag')
            tags = signed_tags(args.manifests, args.allowed_signers, base, image.release)
            sys.stdout.write(caiman.dump(desk(image, table=table, tags=tags, base_tag=args.base_tag)))
            return 0
        session = check_session(json.loads(Path(args.session).read_text(encoding='utf-8')))
        reference = phone_release(session)
        tags = signed_tags(args.manifests, args.allowed_signers,
                           min(known_releases(session) + [image.release], key=lambda r: int(r.base)),
                           max([reference, image.release], key=lambda r: int(r.base)))
        stable = caiman.parse_stable_channel(Path(args.stable).read_bytes()) if args.stable else None
        decision = decide(
            image, table=table, tags=tags,
            readings=readings_module.parse(Path(args.readings).read_bytes()),
            stage=args.stage, os_booted=args.os_booted, update_pending=args.update_pending,
            channel=args.channel, security_previews=args.security_previews, session=session,
            session_path=args.session, current_stable=stable,
            stable_fetched_at=(check_time(args.stable_fetched_at, 'stable fetch time')
                               if args.stable_fetched_at else None),
            approval=load_approval(Path(args.approval).read_bytes()))
    except (Refusal, OSError, ValueError, KeyError) as error:
        sys.stdout.write(caiman.dump({'verdict': 'REFUSE', 'reasons': [str(error)]}))
        return EXIT['REFUSE']
    sys.stdout.write(caiman.dump(decision))
    return EXIT[decision['verdict']]


if __name__ == '__main__':
    sys.exit(main())
