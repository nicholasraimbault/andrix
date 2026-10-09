# SPDX-License-Identifier: Apache-2.0
"""Stop point 4, the session record, the signed tags, the approval and the desk check.

Offline, no phone. The records are the committed adevtool records, bound to a SYNTHETIC
manifest repository with SSH signed tags (world.py). The readings are SYNTHETIC.
"""
import contextlib
import copy
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import adevtool_record  # noqa: E402
import caiman  # noqa: E402
from caiman import Refusal  # noqa: E402
import install_zip  # noqa: E402
import samples  # noqa: E402
import version_criterion as vc  # noqa: E402
import world  # noqa: E402

R = caiman.parse_release
FIXTURES = Path(__file__).resolve().parent / 'fixtures'
INFO = {tag: caiman.parse_android_info((FIXTURES / f'adevtool/{tag}/vendor-skels/google_devices/'
                                        'caiman/firmware/android-info.txt').read_bytes())
        for tag in ('2026081300', '2026100600')}
OCTOBER = samples.parsed()
AUGUST = samples.parsed(samples.AUGUST)
# a new bootloader written beside the old radio: the partial write of rule 4
PARTIAL = samples.parsed({'version-baseband': samples.AUGUST['version-baseband']})
NOVEMBER = samples.parsed({'version-bootloader': 'ripcurrentpro-17.0-16280000',
                           'version-baseband': 'g5400c-260901-261007-B-16310000'})
STATE = {}


def setUpModule():
    STATE['tmp'] = tempfile.TemporaryDirectory()
    STATE['world'] = world.World(STATE['tmp'].name)
    w = STATE['world']
    STATE['table'] = vc.load_table(list(w.records.values()), bases=w.bases, repo=w.repo)
    STATE['tags'] = vc.signed_tags(w.repo, w.signers, R('2026081300'), R('2026100600'), bases=w.bases)


def tearDownModule():
    STATE['tmp'].cleanup()


def image(kind, release, stock=None, sha=None):
    base = R(release).base
    table = STATE['table']
    return vc.Image(kind, sha or hashlib.sha256(f'{kind}{release}'.encode()).hexdigest(), R(release),
                    stock or table.stock.get(base, 'CP3A.261005.005'), INFO.get(base), 'test')


def stable_file(release):
    """caiman-stable as script/generate-metadata writes it: build number, timestamp, device, channel."""
    return f'{release} 1791000000 caiman stable\n'.encode()


def utc_seconds(text):
    return vc.parse_time(text).replace(tzinfo=datetime.timezone.utc).timestamp()


def first(name='s1', release='2026100600', now='2026-10-09T10:00:00Z', build=None):
    """A first session record, started from the current stable release fetched five minutes before."""
    return vc.start_session(name, now[:10], first=True, stable=stable_file(release),
                            stable_fetched_at=later(now, -5), build_number=build or release, now=now)


def session(start='2026100600', allowed=()):
    value = first('s1', start)
    for release, at in allowed:
        value['allowed'].append({'release': release, 'sha256': 'f' * 64, 'kind': 'grapheneos', 'at': at})
    return vc.check_session(value)


def approval(*images, name='s1', day='2026-10-09', wipes=True, kind=None):
    return vc.load_approval(json.dumps({'schema': vc.APPROVAL_SCHEMA, 'session': name, 'date': day,
                                        'artifacts': [{'sha256': item.sha256, 'kind': kind or item.kind,
                                                       'wipes_data': wipes} for item in images]}))


def split_output(text):
    """The JSON report, and the record's SHA-256 if the last line holds one."""
    body, _, last = text.rstrip('\n').rpartition('\n')
    if re.fullmatch(r'[0-9a-f]{64}', last):
        return json.loads(body), last
    return json.loads(text), None


def later(text, minutes):
    moment = vc.parse_time(text) + datetime.timedelta(minutes=minutes)
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


class Case(unittest.TestCase):
    def decide(self, item, start='2026100600', allowed=(), readings=None, stage=8, os_booted=True,
               pending='no', stable=None, channel='stable', approved=True, tags=None, table=None,
               session_value=None, session_path=None, now=None, fetched=None, **extra):
        value = session_value or session(start, allowed)
        named = approval(item if approved else image('grapheneos', '2026081300'),
                         name=value['session'], day=value['date'])
        readings = readings or OCTOBER
        return vc.decide(item, table=table or STATE['table'], tags=tags or STATE['tags'],
                         readings=readings, stage=stage, os_booted=os_booted,
                         update_pending=pending, channel=channel, session=value, approval=named,
                         session_path=session_path,
                         current_stable=R(stable) if stable else None,
                         stable_fetched_at=(fetched or '2026-10-09T10:55:00Z') if stable else None,
                         security_previews=False,
                         now=now or later(readings['taken-at'].value, 5), **extra)

    def refused(self, pattern, *args, **kwargs):
        with self.assertRaisesRegex(Refusal, pattern):
            self.decide(*args, **kwargs)


class TableTests(unittest.TestCase):
    def test_records_are_bound_to_their_signed_manifests(self):
        self.assertEqual(STATE['table'].stock, {'2026081300': 'CP2A.260805.005',
                                                '2026100600': 'CP3A.261005.005'})
        self.assertEqual(STATE['tags'], ['2026081300', '2026100600'])

    def test_refused_tables(self):
        w = STATE['world']
        relabelled = copy.deepcopy(w.records['2026081300'])      # the review's probe
        relabelled.update(release='2026100600', manifest_sha256=w.records['2026100600']['manifest_sha256'])
        headless = copy.deepcopy(w.records['2026100600'])
        headless.pop('tree_head')
        other_head = copy.deepcopy(w.records['2026100600'])
        other_head['tree_head'] = '0' * 40
        conflicting = copy.deepcopy(w.records['2026100600'])
        conflicting['stock_build'] = 'CP3A.260905.009'
        for name, records, pattern in (('none', [], 'no adevtool record'),
                                       ('relabelled', [relabelled], 'signed manifest of 2026100600 pins'),
                                       ('no tree head', [headless], 'names no tree commit'),
                                       ('other tree head', [other_head], 'another commit'),
                                       ('conflicting', [w.records['2026100600'], conflicting], 'disagree')):
            with self.subTest(name), self.assertRaisesRegex(Refusal, pattern):
                vc.load_table(records, bases=w.bases, repo=w.repo)
        with self.assertRaisesRegex(Refusal, 'names no tree commit'):
            vc.load_table([world.RECORDS['2026100600']])   # the committed fixtures until regenerated


class SignedTagTests(unittest.TestCase):
    def test_tag_list_controls(self):
        with tempfile.TemporaryDirectory() as work:
            for name, kwargs, pattern in (
                    ('unsigned', {'unsigned': ('2026100200',)}, 'verify-tag'),
                    ('foreign key', {'foreign': ('2026100200',)}, 'verify-tag')):
                with self.subTest(name):
                    w = world.World(Path(work) / name.replace(' ', '-'),
                                    tags=('2026081300', '2026100200', '2026100600'), **kwargs)
                    with self.assertRaisesRegex(Refusal, pattern):
                        vc.signed_tags(w.repo, w.signers, R('2026081300'), R('2026100600'), bases=w.bases)
            w = world.World(Path(work) / 'plain', tags=('2026081300', '2026100200', '2026100600'))
            self.assertEqual(vc.signed_tags(w.repo, w.signers, R('2026100600'), R('2026081300'), bases=w.bases),
                             ['2026081300', '2026100200', '2026100600'])
            with self.assertRaisesRegex(Refusal, 'not a signed release tag'):
                vc.signed_tags(w.repo, w.signers, R('2026081300'), R('2026110500'), bases=w.bases)
            with self.assertRaisesRegex(Refusal, 'not the allowed signers file'):
                vc.signed_tags(w.repo, w.foreign.with_suffix('.pub'), R('2026081300'), R('2026100600'),
                               bases=w.bases)
            table = vc.load_table(list(w.records.values()), bases=w.bases, repo=w.repo)
            tags = vc.signed_tags(w.repo, w.signers, R('2026081300'), R('2026100600'), bases=w.bases)
            with self.assertRaisesRegex(Refusal, 'no adevtool record for the signed release tags 2026100200'):
                vc.check_coverage(table, tags, R('2026081300'), R('2026100600'))

    def test_clone_config_cannot_change_the_verification(self):
        """A clone whose own config points the signature programs at stand-ins that accept all,
        for SSH, OpenPGP and X.509 signatures."""
        status = ('#!/bin/sh\ncat >/dev/null\nprintf \'[GNUPG:] NEWSIG\\n[GNUPG:] GOODSIG '
                  '0123456789ABCDEF contact\\n[GNUPG:] TRUST_ULTIMATE 0 pgp\\n\'\nexit 0\n')
        stand_ins = {
            'ssh': ('gpg.ssh.program', '#!/bin/sh\ncase "$2" in\nfind-principals) echo contact@grapheneos.org ;;\n'
                    'verify) cat >/dev/null; echo \'Good "git" signature for contact@grapheneos.org with '
                    'ED25519 key SHA256:stand-in\' ;;\nesac\nexit 0\n', {'foreign': ('2026100200',)}),
            'openpgp': ('gpg.program', status, {'unsigned': ('2026100200',)}),
            'x509': ('gpg.x509.program', status, {'unsigned': ('2026100200',)})}
        armor = {'openpgp': 'PGP SIGNATURE', 'x509': 'SIGNED MESSAGE'}
        with tempfile.TemporaryDirectory() as work:
            for name, (key, script, kwargs) in stand_ins.items():
                with self.subTest(name):
                    w = world.World(Path(work) / name, tags=('2026081300', '2026100200', '2026100600'), **kwargs)
                    if name in armor:     # an armored block that no key made
                        commit = world.run('git', '-C', w.repo, 'rev-parse', 'refs/tags/2026100200^{commit}')
                        body = (f'object {commit}\ntype commit\ntag 2026100200\ntagger Manifest fixture '
                                '<fixture@example.invalid> 1791000000 +0000\n\n2026100200\n'
                                f'-----BEGIN {armor[name]}-----\n\niQ==\n-----END {armor[name]}-----\n')
                        forged = subprocess.run(['git', '-C', str(w.repo), 'mktag'], input=body.encode(),
                                                env=world.ENV, check=True, stdout=subprocess.PIPE).stdout
                        world.run('git', '-C', w.repo, 'update-ref', 'refs/tags/2026100200', forged.decode().strip())
                    program = Path(work) / name / 'accept-all'
                    program.write_text(script)
                    program.chmod(0o755)
                    world.run('git', '-C', w.repo, 'config', key, program)
                    # the control's premise: without the pins, the clone's config accepts the tag
                    world.run('git', '-C', w.repo, '-c', f'gpg.ssh.allowedSignersFile={w.signers}',
                              'verify-tag', '2026100200')
                    with self.assertRaisesRegex(Refusal, 'verify-tag'):
                        vc.signed_tags(w.repo, w.signers, R('2026081300'), R('2026100600'), bases=w.bases)
                    self.assertEqual(vc.signed_tags(w.repo, w.signers, R('2026081300'), R('2026081300'),
                                                    bases=w.bases), ['2026081300'])


class CriterionTests(Case):
    def test_newer_release_is_allowed_and_recorded(self):
        value = session('2026081300')
        decision = self.decide(image('grapheneos', '2026100600'), readings=AUGUST, session_value=value)
        self.assertEqual((decision['verdict'], decision['branch']), ('ALLOW', 'newer'))
        self.assertEqual(value['allowed'][-1]['release'], '2026100600')

    def test_older_release_with_another_stock_build_is_refused(self):
        self.refused('its stock build CP2A.260805.005 is not the stock build CP3A.261005.005',
                     image('grapheneos', '2026081300'))

    def test_same_stock_build_reruns(self):
        self.assertEqual(self.decide(image('grapheneos', '2026100600'))['branch'], 'same stock build')
        self.assertEqual(self.decide(image('stock', '2026100600'))['branch'], 'same stock build')

    def test_partial_write_can_be_rerun(self):
        # fix 1: the October bootloader is written, the August radio is still there
        for os_booted in (False, True):
            for item in (image('grapheneos', '2026100600'), image('stock', '2026100600')):
                with self.subTest(os_booted=os_booted, kind=item.kind):
                    decision = self.decide(item, start='2026081300',
                                           allowed=[('2026100600', '2026-10-09T10:30:00Z')],
                                           readings=PARTIAL, os_booted=os_booted)
                    self.assertEqual(decision['verdict'], 'ALLOW')
                    self.assertEqual(decision['firmware_matches'], {'version-bootloader': ['2026100600'],
                                                                    'version-baseband': ['2026081300']})
        self.refused('not newer than 2026100600', image('grapheneos', '2026081300'), start='2026081300',
                     allowed=[('2026100600', '2026-10-09T10:30:00Z')], readings=PARTIAL)

    def test_firmware_newer_than_every_known_release_refuses_every_write(self):
        for os_booted in (True, False):
            for item in (image('grapheneos', '2026100600'), image('stock', '2026100600')):
                with self.subTest(os_booted=os_booted, kind=item.kind):
                    # the review's first probe: an August start, nothing written, November readings
                    self.refused('none of the session\'s known releases', item, start='2026081300',
                                 readings=NOVEMBER, os_booted=os_booted)
        self.refused('version-bootloader is unanswered', image('grapheneos', '2026100600'),
                     readings=samples.parsed(unknown=('version-bootloader',)))

    def test_security_preview_counts_as_its_base_release(self):
        self.assertEqual(self.decide(image('grapheneos', '2026100600'), start='2026100601')['branch'],
                         'same stock build')
        self.assertEqual(self.decide(image('grapheneos', '2026100601'))['branch'], 'same stock build')
        self.assertEqual(self.decide(image('grapheneos', '2026100601'), start='2026081300',
                                     readings=AUGUST)['branch'], 'newer')

    def test_stale_readings_are_refused(self):
        # the review's second probe: the session start readings reused after a write
        allowed = [('2026100600', '2026-10-09T11:30:00Z')]
        self.refused('take fresh readings', image('grapheneos', '2026100600'), allowed=allowed)
        self.refused('take fresh readings', image('grapheneos', '2026100600'),
                     readings=samples.parsed(taken_at='2026-10-09T09:59:59Z'))
        fresh = samples.parsed(taken_at='2026-10-09T11:31:00Z')
        self.assertEqual(self.decide(image('grapheneos', '2026100600'), allowed=allowed,
                                     readings=fresh)['verdict'], 'ALLOW')

    def test_readings_older_than_the_maximum_age_are_refused(self):
        kit = image('grapheneos', '2026100600')
        self.assertEqual(self.decide(kit, now='2026-10-09T11:15:00Z')['verdict'], 'ALLOW')
        self.refused('more than 15 minutes before now', kit, now='2026-10-09T11:15:01Z')
        self.refused('more than 5 minutes before now', kit, now='2026-10-09T11:05:01Z', readings_max_age=5)
        self.assertEqual(self.decide(kit, now='2026-10-09T11:10:00Z', readings_max_age=10)['verdict'], 'ALLOW')
        for age in (0, 16, 60, True, '15', None):      # the plan's 15 minutes may only be lowered
            with self.subTest(age=age):
                self.refused('maximum age of readings is 1 to 15 minutes', kit, readings_max_age=age)

    def test_records_cover_every_signed_tag_between(self):
        tags = ['2026081300', '2026100200', '2026100600']
        self.refused('no adevtool record for the signed release tags 2026100200', image('grapheneos', '2026100600'),
                     start='2026081300', readings=AUGUST, tags=tags)
        self.refused('2026110500 is not a signed release tag', image('grapheneos', '2026110500'))

    def test_stock_image_is_identified_by_its_digest(self):
        w = STATE['world']
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'factory.zip'
            path.write_bytes(b'synthetic factory image')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            for build, expected in (('CP3A.261005.005', None), ('CP2A.260805.005.A1', 'Aug 2026, Rogers'),
                                    ('CP3A.260905.009', 'Sep 2026')):
                with self.subTest(build=build):
                    records = copy.deepcopy(w.records)
                    for value in records.values():
                        if build in value['build_index']['caiman']:
                            value['build_index']['caiman'][build]['factory_sha256'] = digest
                    table = vc.load_table(list(records.values()), bases=w.bases, repo=w.repo)
                    if expected:
                        with self.assertRaisesRegex(Refusal, expected):
                            vc.stock_image(path, table)
                        continue
                    stock = vc.stock_image(path, table)
                    self.assertEqual((stock.release.number, stock.sha256), ('2026100600', digest))
                    self.assertEqual(self.decide(stock, start='2026081300', readings=AUGUST,
                                                 table=table)['branch'], 'newer')

    def test_stock_build_ids_are_never_ordered(self):
        table = vc.Table({'2026081300': 'CP3A.260905.009', '2026100600': 'CP2A.260805.005'},
                         {'2026081300': INFO['2026081300'], '2026100600': INFO['2026100600']},
                         STATE['table'].builds)
        self.refused('not newer', image('grapheneos', '2026081300', stock='CP3A.260905.009'), table=table)
        self.assertEqual(self.decide(image('grapheneos', '2026100600', stock='CP2A.260805.005'),
                                     start='2026081300', readings=AUGUST, table=table)['branch'], 'newer')

    def test_identity_must_come_from_the_image(self):
        with self.assertRaises(Refusal):
            vc.decide(None, table=STATE['table'], tags=STATE['tags'], readings=OCTOBER, stage=8,
                      os_booted=True, update_pending='no', channel='stable', session=session(),
                      approval=approval(image('grapheneos', '2026100600')))


class SessionTests(unittest.TestCase):
    def test_the_phone_release_carries_over(self):
        earlier = session('2026081300', [('2026100600', '2026-10-09T10:30:00Z')])
        second = vc.start_session('s2', '2026-10-10', previous=earlier, now='2026-10-10T09:00:00Z')
        self.assertEqual((second['start_release'], second['carried']), ('2026100600', ['2026081300', '2026100600']))
        self.assertEqual(second['previous_sha256'], caiman.sha256(caiman.dump(earlier).encode()))
        for kwargs in ({'previous': earlier, 'first': True}, {},
                       {'previous': dict(earlier, session='s2')}):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(Refusal):
                vc.start_session('s2', '2026-10-10', **kwargs)

    def test_session_record_controls(self):
        good = session('2026100600', [('2026100600', '2026-10-09T10:30:00Z')])
        for name, change in (('schema', {'schema': 'x'}), ('date', {'date': '2026-13-01'}),
                             ('start', {'start_release': '2026100602'}), ('carried', {'carried': []}),
                             ('start not carried', {'carried': ['2026081300']}),
                             ('start older than carried', {'start_release': '2026081300',
                                                           'carried': ['2026081300', '2026100600']}),
                             ('order', {'allowed': [dict(good['allowed'][0], at='2026-10-09T09:00:00Z')]}),
                             ('entry', {'allowed': [{'release': '2026100600'}]}),
                             ('date is not the start date', {'date': '2026-10-10'}),
                             ('previous digest', {'previous_sha256': 'abc'})):
            with self.subTest(name), self.assertRaises(Refusal):
                vc.check_session(dict(copy.deepcopy(good), **change))
        without = copy.deepcopy(good)
        without.pop('previous_sha256')
        with self.assertRaisesRegex(Refusal, 'nor null for the first'):
            vc.check_session(without)

    def test_an_edited_start_cannot_lower_the_reference(self):
        # An edited record: start 2026081300 beside a carried 2026100600, with October readings.
        edited = session('2026081300')
        edited['carried'] = ['2026081300', '2026100600']
        with self.assertRaises(Refusal):
            vc.check_session(edited)
        # Without check_session, the reference is still the newest known release.
        self.assertEqual(vc.phone_release(edited).number, '2026100600')

    def test_session_date_is_the_utc_date_of_its_start(self):
        with self.assertRaisesRegex(Refusal, 'not the UTC date of its start'):
            vc.start_session('s1', '2026-10-10', first=True, stable=stable_file('2026100600'),
                             stable_fetched_at='2026-10-09T23:55:00Z', build_number='2026100600',
                             now='2026-10-09T23:59:59Z')

    def test_a_session_starts_after_the_previous_one(self):
        with self.assertRaisesRegex(Refusal, 'not after the previous session'):
            vc.start_session('s2', '2026-10-09', previous=session('2026081300'), now='2026-10-09T10:00:00Z')

    def test_allow_is_written_before_the_decision_returns(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'session.json'
            value = session('2026081300')
            path.write_text(caiman.dump(value))
            Case.decide(self, image('grapheneos', '2026100600'), readings=AUGUST, session_value=value,
                        session_path=path)
            self.assertEqual(json.loads(path.read_text())['allowed'][0]['release'], '2026100600')
            waiting = session('2026081300')
            path.write_text(caiman.dump(waiting))
            self.assertEqual(Case.decide(self, image('grapheneos', '2026100600'), readings=AUGUST,
                                         session_value=waiting, session_path=path, approved=False)['verdict'], 'WAIT')
            self.assertEqual(json.loads(path.read_text())['allowed'], [])


class UpdatedFromStableTests(Case):
    """Stop point 4: a phone that updated itself since the last session starts from the current
    stable release, which caiman-stable names and the build number of stop point 1 shows."""

    def previous(self):
        return first('s0', '2026081300', now='2026-10-09T08:00:00Z')

    def follow(self, release='2026100600', build=None, previous=None, data=None,
               fetched_at='2026-10-09T09:55:00Z', updated=True):
        if not updated:
            return vc.start_session('s1', '2026-10-09', previous=previous or self.previous(),
                                    now='2026-10-09T10:00:00Z')
        return vc.start_session('s1', '2026-10-09', previous=previous or self.previous(),
                                stable=stable_file(release) if data is None else data,
                                stable_fetched_at=fetched_at, build_number=build or release,
                                now='2026-10-09T10:00:00Z')

    def test_stable_release_starts_the_record(self):
        value = self.follow()
        self.assertEqual((value['start_release'], value['carried']), ('2026100600', ['2026081300', '2026100600']))
        self.assertEqual(value['stable'], {'release': '2026100600', 'fetched_at': '2026-10-09T09:55:00Z',
                                           'build_number': '2026100600',
                                           'sha256': hashlib.sha256(stable_file('2026100600')).hexdigest()})
        self.assertEqual(vc.phone_release(value).number, '2026100600')
        self.assertIsNone(self.follow(updated=False)['stable'])

    def test_security_preview_of_the_stable_release_is_allowed(self):
        value = self.follow(build='2026100601')
        self.assertEqual((value['start_release'], value['stable']['build_number']), ('2026100600', '2026100601'))

    def test_stable_not_newer_than_every_carried_release_is_refused(self):
        written = self.previous()
        written['allowed'].append({'release': '2026100600', 'sha256': 'f' * 64, 'kind': 'grapheneos',
                                   'at': '2026-10-09T08:30:00Z'})
        for release, previous in (('2026081300', None), ('2026081301', None), ('2026071500', None),
                                  ('2026100600', written), ('2026090100', written)):
            with self.subTest(release=release), \
                    self.assertRaisesRegex(Refusal, 'not newer than the carried releases'):
                self.follow(release, previous=previous)

    def test_build_number_must_show_the_stable_release(self):
        for build in ('2026081300', '2026081301', '2026090100'):     # the phone has not updated yet
            with self.subTest(build=build), self.assertRaisesRegex(
                    Refusal, f'build number {build} is older than the current stable release 2026100600: '
                             'the phone has not updated yet, so the session waits until it has'):
                self.follow(build=build)
        for build in ('2026110500', '2026110501'):
            with self.subTest(build=build), self.assertRaisesRegex(
                    Refusal, f'build number {build} names another release than the current stable release'):
                self.follow(build=build)
        for build in ('2026100602', 'latest', '', None):
            with self.subTest(build=build), self.assertRaisesRegex(Refusal, 'build number'):
                vc.start_session('s1', '2026-10-09', previous=self.previous(), stable=stable_file('2026100600'),
                                 stable_fetched_at='2026-10-09T09:55:00Z', build_number=build,
                                 now='2026-10-09T10:00:00Z')

    def test_malformed_or_stale_stable_file_is_refused(self):
        for data in (b'', b'2026100600 1791000000 caiman beta\n', b'2026100600 1791000000 komodo stable\n',
                     stable_file('2026100600') + stable_file('2026110500'), b'2026100600 caiman stable\n',
                     b'<html>2026100600 1791000000 caiman stable</html>\n', b'2026100602 1791000000 caiman stable\n',
                     '2026100600 1791000000 caiman stable\u00a0\n'.encode()):
            with self.subTest(data=data), self.assertRaisesRegex(Refusal, 'caiman-stable'):
                self.follow(data=data)
        self.assertEqual(self.follow(fetched_at='2026-10-09T09:45:00Z')['stable']['fetched_at'], '2026-10-09T09:45:00Z')
        for fetched_at, pattern in (('2026-10-09T09:44:59Z', 'more than 15 minutes before the start .* stale'),
                                    ('2026-10-08T23:00:00Z', 'stale, fetch it again'),
                                    ('2026-10-09T10:00:01Z', 'after the start'),
                                    ('2026-10-09 09:55', 'not a UTC time'), (None, 'needs the caiman-stable file')):
            with self.subTest(fetched_at=fetched_at), self.assertRaisesRegex(Refusal, pattern):
                self.follow(fetched_at=fetched_at)
        with self.assertRaisesRegex(Refusal, 'or once as the first session'):
            vc.start_session('s1', '2026-10-09', previous=self.previous(), first=True,
                             stable=stable_file('2026100600'), stable_fetched_at='2026-10-09T09:55:00Z',
                             build_number='2026100600', now='2026-10-09T10:00:00Z')

    def test_stable_entry_controls(self):
        good = self.follow()
        for name, change in (('missing', None), ('not a dict', '2026100600'),
                             ('keys', {'release': '2026100600'}),
                             ('other release', dict(good['stable'], release='2026081300')),
                             ('other build', dict(good['stable'], build_number='2026081300')),
                             ('digest', dict(good['stable'], sha256='abc')),
                             ('fetched long before', dict(good['stable'], fetched_at='2026-10-09T09:00:00Z')),
                             ('fetched after', dict(good['stable'], fetched_at='2026-10-09T10:00:01Z'))):
            with self.subTest(name), self.assertRaises(Refusal):
                value = copy.deepcopy(good)
                if change is None:
                    value.pop('stable')
                else:
                    value['stable'] = change
                vc.check_session(value)
        opening = session('2026100600')
        opening['stable'] = None
        with self.assertRaisesRegex(Refusal, 'the first session record names no current stable release'):
            vc.check_session(opening)
        self.assertIsNone(self.follow(updated=False)['stable'])

    def test_official_kit_of_the_stable_release_is_allowed(self):
        kit = image('grapheneos', '2026100600')
        # without the stable release, the October readings refuse every write
        self.refused('none of the session\'s known releases', kit, session_value=self.follow(updated=False))
        decision = self.decide(kit, session_value=self.follow())
        self.assertEqual((decision['verdict'], decision['branch'], decision['phone_release']),
                         ('ALLOW', 'same stock build', '2026100600'))

    def test_wrongly_typed_build_number_only_raises_the_reference(self):
        # The phone is still on August firmware, but the build number was typed as the stable release.
        august = image('grapheneos', '2026081300')
        self.assertEqual(self.decide(august, readings=AUGUST, session_value=self.follow(updated=False))['verdict'],
                         'ALLOW')
        self.refused('not newer than 2026100600', august, readings=AUGUST, session_value=self.follow())
        decision = self.decide(image('grapheneos', '2026100600'), readings=AUGUST, session_value=self.follow())
        self.assertEqual((decision['verdict'], decision['phone_release']), ('ALLOW', '2026100600'))

    def test_newer_firmware_is_still_refused_at_the_readings(self):
        # A stale file and a build number typed to match it: the November firmware still refuses.
        for item in (image('grapheneos', '2026100600'), image('stock', '2026100600')):
            with self.subTest(kind=item.kind):
                self.refused('none of the session\'s known releases', item, readings=NOVEMBER,
                             session_value=self.follow())


class ChainTests(unittest.TestCase):
    """The session records of one phone form one chain in their own directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / 'sessions'
        self.dir.mkdir()
        clock = iter(f'2026-10-09T{hour:02}:00:00Z' for hour in range(1, 24))
        patch = mock.patch.object(vc, 'utc_now', side_effect=lambda: next(clock))
        patch.start()
        self.addCleanup(patch.stop)
        self.assertEqual(self.start('s1', '--first', '--from-stable', str(self.stable('00:55:00', '2026081300')),
                                    '--build-number', '2026081300')[0], 0)
        self.assertEqual(self.follow('s2', 's1')[0], 0)
        self.assertEqual(self.follow('s3', 's2')[0], 0)

    def call(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = vc.main(list(argv))
        report, self.printed = split_output(output.getvalue())
        return status, report

    def start(self, name, *extra, directory=None):
        return self.call('start', '--out', str((directory or self.dir) / f'{name}.json'), '--session', name,
                         '--date', '2026-10-09', *extra)

    def sha(self, name):
        return hashlib.sha256((self.dir / f'{name}.json').read_bytes()).hexdigest()

    def follow(self, name, previous, sha=None, *extra):
        return self.start(name, '--previous', str(self.dir / f'{previous}.json'),
                          '--previous-sha256', sha or self.sha(previous), *extra)

    def refused(self, pattern, result):
        status, report = result
        self.assertEqual((status, report['verdict']), (1, 'REFUSE'))
        self.assertRegex(report['reasons'][0], pattern)

    def test_the_chain_continues_from_the_newest_record(self):
        chain = vc.read_chain(self.dir)
        self.assertEqual([link.record['session'] for link in chain], ['s1', 's2', 's3'])
        self.assertEqual(chain[2].record['previous_sha256'], self.sha('s2'))
        status, record = self.follow('s4', 's3', None, '--updated-from-stable', str(self.stable('03:55:00')),
                                     '--build-number', '2026100601')
        self.assertEqual((status, record['start_release'], record['carried']),
                         (0, '2026100600', ['2026081300', '2026100600']))
        self.assertEqual((record['stable']['fetched_at'], record['stable']['build_number']),
                         ('2026-10-09T03:55:00Z', '2026100601'))

    def stable(self, saved_at, release='2026100600'):
        """caiman-stable saved outside the session directory, its modification time set by hand."""
        path = Path(self.tmp.name) / f'caiman-stable-{release}-{saved_at.replace(":", "")}'
        path.write_bytes(stable_file(release))
        moment = utc_seconds(f'2026-10-09T{saved_at}Z')
        os.utime(path, (moment, moment))
        return path

    def test_updated_from_stable_on_the_command_line(self):
        clock = mock.patch.object(vc, 'utc_now', return_value='2026-10-09T04:00:00Z')    # every start at 04:00
        clock.start()
        self.addCleanup(clock.stop)
        for saved_at, pattern in (('03:44:59', 'stale, fetch it again'), ('04:00:01', 'after the start')):
            with self.subTest(saved_at=saved_at):
                self.refused(pattern, self.follow('s4', 's3', None, '--updated-from-stable',
                                                  str(self.stable(saved_at)), '--build-number', '2026100600'))
        self.refused('session waits until it has', self.follow(
            's4', 's3', None, '--updated-from-stable', str(self.stable('03:58:00')), '--build-number', '2026081300'))
        self.refused('needs the caiman-stable file', self.follow('s4', 's3', None, '--build-number', '2026100600'))
        self.refused('No such file', self.follow('s4', 's3', None, '--updated-from-stable',
                                                 str(Path(self.tmp.name) / 'missing'), '--build-number', '2026100600'))
        self.assertFalse((self.dir / 's4.json').exists())

    def test_the_first_record_starts_from_the_stable_release(self):
        record = json.loads((self.dir / 's1.json').read_text())
        self.assertEqual((record['start_release'], record['carried'], record['previous_sha256']),
                         ('2026081300', ['2026081300'], None))
        self.assertEqual((record['stable']['release'], record['stable']['fetched_at'],
                          record['stable']['build_number']), ('2026081300', '2026-10-09T00:55:00Z', '2026081300'))
        elsewhere = Path(self.tmp.name) / 'elsewhere'
        elsewhere.mkdir()
        clock = mock.patch.object(vc, 'utc_now', return_value='2026-10-09T04:00:00Z')
        clock.start()
        self.addCleanup(clock.stop)
        for extra, pattern in (
                (['--build-number', '2026081300'], 'the session waits until it has'),
                (['--build-number', '2026110500'], 'names another release'),
                (['--build-number', '2026100600'], None),
                ([], 'needs the caiman-stable file')):
            with self.subTest(extra=extra):
                path = elsewhere / 't1.json'
                result = self.start('t1', '--first', '--from-stable', str(self.stable('03:58:00')), *extra,
                                    directory=elsewhere) if extra else \
                    self.start('t1', '--first', '--build-number', '2026100600', directory=elsewhere)
                if pattern is None:
                    self.assertEqual((result[0], result[1]['start_release']), (0, '2026100600'))
                    self.assertEqual(self.printed, hashlib.sha256(path.read_bytes()).hexdigest())
                    path.unlink()
                else:
                    self.refused(pattern, result)
                    self.assertFalse(path.exists())
        self.refused('stale, fetch it again', self.start(
            't1', '--first', '--from-stable', str(self.stable('03:44:59')), '--build-number', '2026100600',
            directory=elsewhere))

    def test_the_typed_first_release_is_not_an_option(self):
        elsewhere = Path(self.tmp.name) / 'elsewhere'
        elsewhere.mkdir()
        for extra in (['--first-release', '2026100600'], ['--first', '--first-release', '2026100600']):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()) as error:
                self.start('t1', *extra, directory=elsewhere)
        self.assertIn('unrecognized arguments: --first-release', error.getvalue())
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_start_writes_atomically(self):
        printed = self.follow('s4', 's3')
        self.assertEqual(self.printed, self.sha('s4'))
        self.assertEqual(printed[0], 0)
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ['s1.json', 's2.json', 's3.json', 's4.json'])
        # a start that stops between the new file and its rename leaves only the .new file
        with mock.patch.object(vc.os, 'link', side_effect=OSError('stopped')):
            self.refused('stopped', self.follow('s5', 's4'))
        self.assertFalse((self.dir / 's5.json').exists())
        self.refused(r's5.json.new is left from an interrupted start, verify or decide.*remove it by hand',
                     self.follow('s5', 's4'))
        (self.dir / 's5.json.new').unlink()
        (self.dir / 's9.json.new').write_text('{}')
        with self.assertRaisesRegex(Refusal, 's9.json.new is left from an interrupted'):
            vc.publish_record(self.dir / 's9.json', json.loads((self.dir / 's4.json').read_text()))
        self.assertEqual(((self.dir / 's9.json.new').read_text(), (self.dir / 's9.json').exists()), ('{}', False))
        (self.dir / 's9.json.new').unlink()
        with self.assertRaisesRegex(Refusal, 'already exists'):
            vc.publish_record(self.dir / 's4.json', json.loads((self.dir / 's4.json').read_text()))
        self.assertFalse((self.dir / 's4.json.new').exists())
        descriptor = os.open(self.dir, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)      # another start holds it
            self.refused('sessions is locked by another start$', self.follow('s5', 's4'))
        finally:
            os.close(descriptor)
        self.assertEqual(self.follow('s5', 's4')[0], 0)

    def test_the_typed_updated_release_is_not_an_option(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()) as error:
            self.follow('s4', 's3', None, '--updated-release', '2026100600')
        self.assertIn('unrecognized arguments: --updated-release', error.getvalue())
        self.assertFalse((self.dir / 's4.json').exists())

    def test_stale_previous_is_refused(self):
        self.refused('not the newest session record of its directory; the newest is s3.json',
                     self.follow('s4', 's2'))
        self.assertFalse((self.dir / 's4.json').exists())

    def test_edited_newest_record_is_refused(self):
        kept = self.sha('s3')
        record = json.loads((self.dir / 's3.json').read_text())
        record['carried'] = ['2026100600']      # drops the carried August release
        record['start_release'] = '2026100600'
        (self.dir / 's3.json').write_text(caiman.dump(record))
        self.assertEqual(len(vc.read_chain(self.dir)), 3)     # the chain alone cannot see it
        self.refused('does not hash to the SHA-256 the owner keeps', self.follow('s4', 's3', kept))
        self.refused('needs --previous-sha256', self.start('s4', '--previous', str(self.dir / 's3.json')))

    def test_broken_chain_is_refused(self):
        record = json.loads((self.dir / 's2.json').read_text())
        record['carried'] = ['2026081300', '2026100600']
        record['start_release'] = '2026100600'
        (self.dir / 's2.json').write_text(caiman.dump(record))
        self.refused('the chain is broken', self.follow('s4', 's3'))
        (self.dir / 's2.json').unlink()
        self.refused('the chain is broken', self.follow('s4', 's3'))

    def test_fork_is_refused(self):
        parent = json.loads((self.dir / 's2.json').read_text())
        fork = vc.start_session('s3b', '2026-10-09', previous=parent, now='2026-10-09T20:00:00Z')
        (self.dir / 's3b.json').write_text(caiman.dump(fork))
        self.refused('name the same previous record .*s2.json; the chain forks', self.follow('s4', 's3'))
        self.refused('name the same previous record', self.follow('s4', 's3b'))

    def test_a_second_first_record_is_refused(self):
        self.refused('already holds session records', self.start(
            's9', '--first', '--from-stable', str(self.stable('03:58:00')), '--build-number', '2026100600'))
        other = first('s9', '2026100600', now='2026-10-09T20:00:00Z')
        (self.dir / 's9.json').write_text(caiman.dump(other))
        self.refused('2 records .* start a chain', self.follow('s4', 's3'))

    def test_directory_controls(self):
        elsewhere = Path(self.tmp.name) / 'elsewhere'
        elsewhere.mkdir()
        self.refused('must go beside the previous record',
                     self.start('s4', '--previous', str(self.dir / 's3.json'), '--previous-sha256',
                                self.sha('s3'), directory=elsewhere))
        self.refused('session named s2', self.follow('s2', 's3'))
        self.refused('not named NAME.json', self.call(
            'start', '--out', str(self.dir / 's4.txt'), '--session', 's4', '--date', '2026-10-09',
            '--previous', str(self.dir / 's3.json'), '--previous-sha256', self.sha('s3')))
        with open(self.dir / 's3.json', 'rb') as holder:
            fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)     # a decide still runs on s3
            self.refused('s3.json is locked by another', self.follow('s4', 's3'))
        self.refused('continue a chain', self.start('t1', '--first', '--updated-from-stable',
                                                    str(self.stable('03:58:00')), '--build-number', '2026100600',
                                                    directory=elsewhere))
        self.refused('--from-stable starts the first session', self.follow(
            's4', 's3', None, '--from-stable', str(self.stable('03:58:00')), '--build-number', '2026100600'))
        for name, content, pattern in (
                ('notes.txt', 'x', 'not a session record'),
                ('approval.json', '{}', 'not an andrix.pixel.session/1 document'),
                ('broken.json', '{', 'not JSON'),
                ('s3.json.new', '{}', r's3.json.new is left from an interrupted start, verify or decide.*'
                                      'remove it by hand'),
                ('respaced.json', json.dumps(json.loads((self.dir / 's3.json').read_text())),
                 'not in the form the checker writes')):
            with self.subTest(name):
                (self.dir / name).write_text(content)
                self.refused(pattern, self.follow('s4', 's3'))
                (self.dir / name).unlink()
        self.assertEqual(self.follow('s4', 's3')[0], 0)


class VerifiedIdentityTests(Case):
    """decide takes the identity that verify kept in the session record, by the file's SHA-256."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'caiman-install-2026100600.zip'
        self.path.write_bytes(b'synthetic install zip')

    def kept(self, kind='grapheneos', **change):
        value = session('2026081300')
        item = image(kind, '2026100600', sha=hashlib.sha256(self.path.read_bytes()).hexdigest())
        value['verified'][item.sha256] = dict(vc.identity_entry(item, '2026-10-09T10:01:00Z'), **change)
        return value, item

    def test_the_kept_identity_is_the_image(self):
        value, item = self.kept()
        found = vc.verified_image(vc.check_session(value), self.path, 'grapheneos', STATE['table'])
        self.assertEqual(found, item)
        self.assertEqual(self.decide(found, readings=AUGUST, session_value=value)['verdict'], 'ALLOW')

    def test_lookups_that_are_refused(self):
        value, item = self.kept()
        with self.assertRaisesRegex(Refusal, 'was verified as grapheneos, not andrix'):
            vc.verified_image(value, self.path, 'andrix', STATE['table'])
        self.path.write_bytes(b'another synthetic install zip')
        with self.assertRaisesRegex(Refusal, 'holds no verified identity under that SHA-256; run verify'):
            vc.verified_image(value, self.path, 'grapheneos', STATE['table'])

    def test_an_identity_that_disagrees_with_the_records_is_refused(self):
        other = dict(INFO['2026100600'].as_dict(), bootloader='ripcurrentpro-17.0-15199480')
        for kind, change in (('grapheneos', {'stock_build': 'CP2A.260805.005'}),
                             ('grapheneos', {'android_info': other}),
                             ('grapheneos', {'release': '2026081300'}),
                             ('stock', {})):        # no factory digest in the index is this file's
            with self.subTest(kind=kind, change=change), \
                    self.assertRaisesRegex(Refusal, 'disagrees with the supplied adevtool records'):
                value, _ = self.kept(kind, **change)
                vc.verified_image(vc.check_session(value), self.path, kind, STATE['table'])

    def test_record_controls(self):
        value, item = self.kept()
        entry = value['verified'][item.sha256]
        for name, verified in (('not a map', []), ('key', {'abc': entry}),
                               ('keys', {item.sha256: dict(entry, extra=1)}),
                               ('kind', {item.sha256: dict(entry, kind='other')}),
                               ('release', {item.sha256: dict(entry, release='2026100602')}),
                               ('stock build', {item.sha256: dict(entry, stock_build='cp3a')}),
                               ('android-info', {item.sha256: dict(entry, android_info={'board': 'caiman'})}),
                               ('wipe', {item.sha256: dict(entry, wipes_data='yes')}),
                               ('before the session', {item.sha256: dict(entry, at='2026-10-09T09:00:00Z')})):
            with self.subTest(name), self.assertRaises(Refusal):
                vc.check_session(dict(copy.deepcopy(value), verified=verified))
        missing = copy.deepcopy(value)
        missing.pop('verified')
        with self.assertRaisesRegex(Refusal, 'no map of verified images'):
            vc.check_session(missing)


class ApprovalTests(Case):
    def test_unnamed_image_waits(self):
        decision = self.decide(image('grapheneos', '2026100600'), approved=False)
        self.assertEqual((decision['verdict'], vc.EXIT[decision['verdict']]), ('WAIT', 3))

    def test_approval_names_the_session_kind_and_wipe(self):
        item = image('grapheneos', '2026100600')
        for named in (approval(item, wipes=False), approval(item, kind='stock'), approval(item, name='s2'),
                      approval(item, day='2026-10-10')):
            with self.subTest(named=(named['session'], named['date'])), self.assertRaises(Refusal):
                vc.decide(item, table=STATE['table'], tags=STATE['tags'], readings=OCTOBER, stage=8,
                          os_booted=True, update_pending='no', channel='stable', session=session(),
                          approval=named, now='2026-10-09T11:05:00Z')

    def test_malformed_approvals(self):
        sha = 'a' * 64
        base = {'schema': vc.APPROVAL_SCHEMA, 'session': 's1', 'date': '2026-10-09'}
        for value in (b'not json', b'{}', json.dumps(dict(base, artifacts=[])).encode(),
                      json.dumps(dict(base, schema='andrix.pixel.approval/1', artifacts=[
                          {'sha256': sha, 'kind': 'grapheneos', 'wipes_data': True}])).encode(),
                      json.dumps({'schema': vc.APPROVAL_SCHEMA, 'artifacts': [
                          {'sha256': sha, 'kind': 'grapheneos', 'wipes_data': True}]}).encode(),
                      json.dumps(dict(base, artifacts=[{'sha256': sha, 'kind': 'grapheneos'}])).encode(),
                      json.dumps(dict(base, artifacts=[{'sha256': sha, 'kind': 'grapheneos',
                                                        'wipes_data': True}] * 2)).encode()):
            with self.subTest(value=value[:50]), self.assertRaises(Refusal):
                vc.load_approval(value)

    def test_stages(self):
        self.refused('nothing is written in stage 3', image('grapheneos', '2026100600'), stage=3)
        self.refused('no Andrix image is written before stage 8', image('andrix', '2026100600'), stage=7)
        self.assertEqual(self.decide(image('andrix', '2026100600'))['verdict'], 'ALLOW')
        self.assertEqual(self.decide(image('grapheneos', '2026100600'), stage=7,
                                     readings=samples.parsed({'unlocked': 'no'}))['verdict'], 'ALLOW')


class StopPointTests(Case):
    def test_stop_points_come_first(self):
        for pending in ('yes', 'unknown'):
            with self.subTest(pending=pending):
                self.refused('stop point 1', image('grapheneos', '2026100600'), pending=pending)
        self.refused("'beta' channel", image('grapheneos', '2026100600'), channel='beta')
        self.refused('stop point 3: snapshot-update-status is merging', image('grapheneos', '2026100600'),
                     readings=samples.parsed({'snapshot-update-status': 'merging'}))
        self.refused('stop point 3: product reads komodo', image('grapheneos', '2026100600'),
                     readings=samples.parsed({'product': 'komodo'}))


class ExceptionTests(Case):
    def test_reference_is_the_newer_of_recorded_and_written(self):
        allowed = [('2026100600', '2026-10-09T10:30:00Z')]
        self.refused('not newer than 2026100600', image('grapheneos', '2026081300'), start='2026081300',
                     allowed=allowed, os_booted=False)
        decision = self.decide(image('grapheneos', '2026100600'), start='2026081300', allowed=allowed,
                               os_booted=False)
        self.assertEqual((decision['phone_release'], decision['branch']), ('2026100600', 'same stock build'))

    def test_pending_update_allows_only_the_current_stable_release(self):
        for pending in ('yes', 'unknown'):
            with self.subTest(pending=pending):
                decision = self.decide(image('grapheneos', '2026100600'), start='2026081300', os_booted=False,
                                       pending=pending, stable='2026100600', readings=AUGUST)
                self.assertEqual((decision['branch'], decision['conditions']), ('current stable', [vc.ONLY_OFFICIAL]))
        self.assertEqual(self.decide(image('grapheneos', '2026100600'), start='2026081300', os_booted=False,
                                     pending='yes', stable='2026100600', readings=AUGUST,
                                     approved=False)['verdict'], 'WAIT')
        self.refused('current stable release 2026100600 or its security preview', image('grapheneos', '2026081300'),
                     start='2026081300', os_booted=False, pending='yes', stable='2026100600', readings=AUGUST)
        for item in (image('andrix', '2026100600'), image('stock', '2026100600')):
            with self.subTest(kind=item.kind):
                self.refused('only the current stable official GrapheneOS release', item, os_booted=False,
                             pending='yes', stable='2026100600')
        self.refused('with the time of the fetch', image('grapheneos', '2026100600'), os_booted=False,
                     pending='yes')


    def test_a_stale_or_future_fetch_time_is_refused(self):
        kit = image('grapheneos', '2026100600')
        pending = {'start': '2026081300', 'os_booted': False, 'pending': 'yes', 'stable': '2026100600',
                   'readings': AUGUST}         # the decision comes at 11:05
        for fetched, pattern in (('2020-01-01T00:00:00Z', 'stale, fetch it again'),
                                 ('2026-10-09T10:49:59Z', 'more than 15 minutes before the decision'),
                                 ('2026-10-09T11:05:01Z', 'after the decision'),
                                 ('2026-10-09 10:55', 'not a UTC time')):
            with self.subTest(fetched=fetched):
                self.refused(pattern, kit, fetched=fetched, **pending)
        self.assertEqual(self.decide(kit, fetched='2026-10-09T10:50:00Z', **pending)['verdict'], 'ALLOW')

    def test_snapshot_status_restricts_like_a_pending_update(self):
        merging = samples.parsed({'snapshot-update-status': 'merging'})
        decision = self.decide(image('grapheneos', '2026100600'), os_booted=False, readings=merging,
                               stable='2026100600')
        self.assertEqual(decision['conditions'], [vc.ONLY_OFFICIAL])
        self.refused('only the current stable official GrapheneOS release', image('andrix', '2026100600'),
                     os_booted=False, readings=merging, stable='2026100600')


class DeskTests(unittest.TestCase):
    def test_gate_step_8(self):
        table, tags = STATE['table'], STATE['tags']
        self.assertEqual(vc.desk(image('stock', '2026100600'), table=table, tags=tags,
                                 base_tag='2026100600')['branch'], 'same stock build')
        self.assertEqual(vc.desk(image('grapheneos', '2026100600'), table=table, tags=tags,
                                 base_tag='2026100600')['verdict'], 'PASS')
        for item, base, pattern in ((image('stock', '2026081300'), '2026100600', 'not newer'),
                                    (image('grapheneos', '2026081300'), '2026100600', 'older than the base tag'),
                                    (image('andrix', '2026100600'), '2026100600', 'way back kits'),
                                    (image('stock', '2026100600'), '2026100200', 'no adevtool record for the base tag')):
            with self.subTest(kind=item.kind, base=base), self.assertRaisesRegex(Refusal, pattern):
                vc.desk(item, table=table, tags=tags, base_tag=base)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        work = Path(self.tmp.name)
        self.world = STATE['world']
        self.zip = work / 'caiman-factory.zip'
        self.zip.write_bytes(b'synthetic factory image')
        self.digest = hashlib.sha256(self.zip.read_bytes()).hexdigest()
        self.paths = {}
        for tag, value in self.world.records.items():
            value = copy.deepcopy(value)
            if 'CP3A.261005.005' in value['build_index']['caiman']:
                value['build_index']['caiman']['CP3A.261005.005']['factory_sha256'] = self.digest
            self.paths[tag] = work / f'{tag}.json'
            self.paths[tag].write_text(json.dumps(value))
        for name, sha in (('named', self.digest), ('other', 'b' * 64)):
            self.paths[name] = work / name
            self.paths[name].write_text(json.dumps({'schema': vc.APPROVAL_SCHEMA, 'session': 's1',
                                                    'date': '2026-10-09', 'artifacts': [
                {'sha256': sha, 'kind': 'stock', 'wipes_data': True}]}))
        self.sessions = work / 'sessions'      # the session directory holds only session records
        self.sessions.mkdir()
        self.paths['session'] = self.sessions / 's1.json'
        clock = iter(f'2026-10-09T10:{minute:02}:00Z' for minute in range(60))
        patches = (mock.patch.object(adevtool_record, 'BASES', self.world.bases),
                   mock.patch.object(install_zip, 'BASES', self.world.bases),
                   mock.patch.object(vc, 'utc_now', side_effect=lambda: next(clock)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.record_sha = None

    def call(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = vc.main(list(argv))
        report, self.printed = split_output(output.getvalue())
        if self.printed is not None:
            self.record_sha = self.printed
        return status, report

    def stable(self, saved_at, release='2026081300'):
        """caiman-stable saved with curl -o; its modification time is set by hand here."""
        path = Path(self.tmp.name) / f'caiman-stable-{release}-{saved_at.replace(":", "")}'
        path.write_bytes(stable_file(release))
        moment = utc_seconds(f'2026-10-09T{saved_at}Z')
        os.utime(path, (moment, moment))
        return path

    def tables(self):
        return ('--record', str(self.paths['2026081300']), '--record', str(self.paths['2026100600']),
                '--manifests', str(self.world.repo), '--allowed-signers', str(self.world.signers))

    def verify(self, *extra, sha=None):
        return self.call('verify', *self.tables(), '--image', 'stock', '--zip', str(self.zip),
                         '--session', str(self.paths['session']), '--record-sha256', sha or self.record_sha,
                         *extra)

    def decide(self, approval, taken=None, *extra, session=None, sha=None, booted='yes', pending='no'):
        taken = taken or self.taken
        readings = Path(self.tmp.name) / f'readings-{taken}'
        readings.write_bytes(samples.synthetic(samples.AUGUST, taken_at=taken))
        return self.call('decide', *self.tables(), '--image', 'stock',
                         '--zip', str(self.zip), '--session', str(session or self.paths['session']),
                         '--record-sha256', sha or self.record_sha,
                         '--readings', str(readings), '--stage', '8', '--os-booted', booted,
                         '--update-pending', pending, '--channel', 'stable', '--security-previews', 'no',
                         '--approval', str(self.paths[approval]), *extra)

    def begin(self, verify=True):
        """start at 10:00, verify at 10:01, readings at 10:02."""
        status, started = self.call('start', '--out', str(self.paths['session']), '--session', 's1',
                                    '--date', '2026-10-09', '--first', '--from-stable',
                                    str(self.stable('09:55:00')), '--build-number', '2026081300')
        self.assertEqual((status, started['start_release']), (0, '2026081300'))
        self.assertEqual(self.printed, hashlib.sha256(self.paths['session'].read_bytes()).hexdigest())
        if verify:
            status, verified = self.verify()
            self.assertEqual((status, verified['verdict'], verified['sha256']), (0, 'VERIFIED', self.digest))
        self.taken = vc.utc_now()

    def refused(self, pattern, result):
        status, report = result
        self.assertEqual((status, report['verdict']), (1, 'REFUSE'))
        self.assertRegex(report['reasons'][0], pattern)
        self.assertIsNone(self.printed)

    def test_decide_takes_the_identity_that_verify_kept(self):
        self.begin()
        kept = json.loads(self.paths['session'].read_text())['verified']
        self.assertEqual(list(kept), [self.digest])
        self.assertEqual((kept[self.digest]['kind'], kept[self.digest]['release'], kept[self.digest]['at']),
                         ('stock', '2026100600', '2026-10-09T10:01:00Z'))
        self.assertEqual(self.printed, hashlib.sha256(self.paths['session'].read_bytes()).hexdigest())
        before = self.record_sha
        status, again = self.verify()           # the same file again changes nothing
        self.assertEqual((status, self.printed), (0, before))
        other = vc.Image('stock', self.digest, R('2026081300'), 'CP2A.260805.005', INFO['2026081300'], 'other')
        with mock.patch.object(vc, '_image', return_value=other):
            self.refused('already holds another identity', self.verify(sha=before))
        with mock.patch.object(vc, 'stock_image', side_effect=AssertionError('no image check in decide')):
            status, result = self.decide('named', sha=before)
        self.assertEqual((status, result['verdict'], result['artifact']['sha256']), (0, 'ALLOW', self.digest))

    def test_a_file_that_changed_since_verify_is_refused(self):
        self.begin()
        self.zip.write_bytes(b'another synthetic factory image')
        changed = hashlib.sha256(self.zip.read_bytes()).hexdigest()
        self.refused(f'hashes to {changed}, and the session record holds no verified identity under that '
                     'SHA-256; run verify on this file first', self.decide('named'))

    def test_an_identity_not_in_the_record_is_refused(self):
        self.begin(verify=False)
        self.refused('holds no verified identity under that SHA-256', self.decide('named'))
        self.refused('was verified as stock, not grapheneos', (lambda: (self.verify(), self.call(
            'decide', *self.tables(), '--image', 'grapheneos', '--zip', str(self.zip), '--session',
            str(self.paths['session']), '--record-sha256', self.record_sha, '--readings', 'r', '--stage', '8',
            '--os-booted', 'yes', '--update-pending', 'no', '--channel', 'stable', '--security-previews', 'no',
            '--approval', str(self.paths['named'])))[1])())

    def test_an_identity_edited_in_the_record_is_caught_by_the_chain(self):
        self.begin()
        record = json.loads(self.paths['session'].read_text())
        record['verified'][self.digest]['release'] = '2026110500'   # an edit in the checker's own form
        self.paths['session'].write_text(caiman.dump(record))
        self.refused('does not hash to the SHA-256 that the last start, verify or decide printed',
                     self.decide('named'))
        self.assertEqual(json.loads(self.paths['session'].read_text())['allowed'], [])

    def test_each_decide_needs_the_sha256_the_last_command_printed(self):
        self.begin()
        after_verify = self.record_sha
        started = hashlib.sha256(b'')       # neither the record before verify nor any other value
        for sha in (started.hexdigest(), 'a' * 64):
            with self.subTest(sha=sha):
                self.refused('does not hash to the SHA-256 that the last start, verify or decide printed',
                             self.decide('named', sha=sha))
        status, result = self.decide('other')
        self.assertEqual((status, result['verdict'], self.printed), (3, 'WAIT', after_verify))
        status, result = self.decide('named')
        self.assertEqual((status, result['verdict']), (0, 'ALLOW'))
        self.assertNotEqual(self.printed, after_verify)
        self.assertEqual(self.printed, hashlib.sha256(self.paths['session'].read_bytes()).hexdigest())
        self.taken = vc.utc_now()
        self.refused('does not hash to the SHA-256', self.decide('named', sha=after_verify))   # stale
        self.refused('does not hash to the SHA-256', self.verify(sha=after_verify))
        for command in ('decide', 'verify'):
            with self.subTest(command=command), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                vc.main([command, *self.tables(), '--image', 'stock', '--zip', str(self.zip),
                         '--session', str(self.paths['session'])])

    def test_pending_update_takes_the_fetch_time_from_the_stable_file(self):
        self.begin()
        clock = mock.patch.object(vc, 'utc_now', return_value='2026-10-09T10:04:00Z')    # every decision
        clock.start()
        self.addCleanup(clock.stop)
        for saved_at, pattern in (('09:48:59', 'more than 15 minutes before the decision .* stale'),
                                  ('10:04:01', 'after the decision')):
            with self.subTest(saved_at=saved_at):
                self.refused(pattern, self.decide('named', None, '--stable', str(self.stable(saved_at, '2026100600')),
                                                  booted='no', pending='yes'))
        # a fresh file passes the fetch time, and the stock image is then refused for its kind
        self.refused('only the current stable official GrapheneOS release', self.decide(
            'named', None, '--stable', str(self.stable('10:00:00', '2026100600')), booted='no', pending='yes'))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()) as error:
            self.decide('named', None, '--stable', str(self.stable('10:00:00', '2026100600')),
                        '--stable-fetched-at', '2026-10-09T10:00:00Z', booted='no', pending='yes')
        self.assertIn('unrecognized arguments: --stable-fetched-at', error.getvalue())

    def test_a_held_lock_refuses_a_second_decide(self):
        self.begin()
        with open(self.paths['session'], 'rb') as holder:
            fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)     # another decide holds it
            self.refused('s1.json is locked by another start, verify or decide', self.decide('named'))
            self.refused('s1.json is locked by another start, verify or decide', self.verify())
        self.assertEqual(json.loads(self.paths['session'].read_text())['allowed'], [])
        self.assertEqual(self.decide('named')[1]['verdict'], 'ALLOW')

    def test_a_record_replaced_while_locking_is_refused(self):
        self.begin()
        path, flock = self.paths['session'], fcntl.flock

        def replaced_meanwhile(descriptor, operation):
            # another decide wrote its ALLOW between this one's open and its lock
            (self.sessions / 'other').write_bytes(path.read_bytes())
            os.replace(self.sessions / 'other', path)
            return flock(descriptor, operation)
        with mock.patch.object(vc.fcntl, 'flock', side_effect=replaced_meanwhile), \
                self.assertRaisesRegex(Refusal, 'was replaced while this command opened it'):
            vc.lock_session(path)
        vc.lock_session(path).close()

    def test_a_leftover_new_file_is_refused_until_removed_by_hand(self):
        self.begin()
        leftover = self.sessions / 's1.json.new'
        leftover.write_text('{}')
        pattern = f'{leftover} is left from an interrupted start, verify or decide.*Inspect it.*remove it by hand'
        self.refused(pattern, self.decide('named'))
        self.refused(pattern, self.verify())
        for check in (vc.lock_session, lambda path: vc.read_chain(path.parent),
                      lambda path: vc.write_session(path, json.loads(path.read_text()))):
            with self.assertRaisesRegex(Refusal, pattern):
                check(self.paths['session'])
        self.assertEqual(json.loads(self.paths['session'].read_text())['allowed'], [])
        leftover.unlink()
        self.assertEqual(self.decide('named')[1]['verdict'], 'ALLOW')

    def test_decide_needs_the_newest_record(self):
        self.begin()
        status, _ = self.call('start', '--out', str(self.sessions / 's2.json'), '--session', 's2',
                              '--date', '2026-10-09', '--previous', str(self.paths['session']),
                              '--previous-sha256', self.record_sha)
        self.assertEqual(status, 0)
        self.refused('s1.json is not the newest session record of its directory',
                     self.decide('named', sha=hashlib.sha256(self.paths['session'].read_bytes()).hexdigest()))

    def test_readings_max_age_option(self):
        self.begin()
        vc.utc_now()        # two minutes pass
        self.refused('more than 1 minute before now', self.decide('named', None, '--readings-max-age', '1'))
        for value in ('0', '16', '60', '15.5', 'x'):
            with self.subTest(value=value), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.decide('named', None, '--readings-max-age', value)
        self.assertEqual(self.decide('named', None, '--readings-max-age', '15')[1]['verdict'], 'ALLOW')

    def test_session_flow(self):
        self.begin()
        status, result = self.decide('other', taken='2099-01-01T00:00:00Z')   # from the future
        self.assertEqual((status, result['verdict']), (1, 'REFUSE'))
        status, result = self.decide('other')
        self.assertEqual((status, result['verdict']), (3, 'WAIT'))
        status, result = self.decide('named')
        self.assertEqual((status, result['verdict'], result['branch']), (0, 'ALLOW', 'newer'))
        self.assertEqual(json.loads(self.paths['session'].read_text())['allowed'][0]['sha256'], self.digest)
        status, result = self.decide('named')      # the same readings again, after the ALLOW
        self.assertEqual((status, result['verdict']), (1, 'REFUSE'))
        status, result = self.call('desk', *self.tables(), '--image', 'stock',
                                   '--zip', str(self.zip), '--base-tag', '2026100600')
        self.assertEqual((status, result['verdict'], self.printed), (0, 'PASS', None))

    def test_typed_session_facts_are_not_options(self):
        base = ['decide', '--record', 'r', '--manifests', 'm', '--allowed-signers', 's',
                '--image', 'stock', '--zip', 'z', '--session', 's', '--record-sha256', 'a' * 64,
                '--readings', 'r', '--stage', '8', '--os-booted', 'yes', '--update-pending', 'no',
                '--channel', 'stable', '--security-previews', 'no', '--approval', 'a']
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vc.main(base), 1)       # the base line parses and refuses for its files
        for extra in (['--phone-release', '2026081300'], ['--written', '2026100600'],
                      ['--image-release', '2026110500'], ['--releases', 'page.html'],
                      ['--stable-fetched-at', '2026-10-09T10:00:00Z'], ['--first-release', '2026081300']):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                vc.main([*base, *extra])


if __name__ == '__main__':
    unittest.main()
