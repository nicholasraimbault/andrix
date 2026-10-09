# SPDX-License-Identifier: Apache-2.0
"""Stop point 4, the session record, the signed tags, the approval and the desk check.

Offline, no phone. The records are the committed adevtool records, bound to a SYNTHETIC
manifest repository with SSH signed tags (world.py). The readings are SYNTHETIC.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
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


def session(start='2026100600', allowed=()):
    value = vc.start_session('s1', '2026-10-09', first_release=start, now='2026-10-09T10:00:00Z')
    for release, at in allowed:
        value['allowed'].append({'release': release, 'sha256': 'f' * 64, 'kind': 'grapheneos', 'at': at})
    return vc.check_session(value)


def approval(*images, name='s1', day='2026-10-09', wipes=True, kind=None):
    return vc.load_approval(json.dumps({'schema': vc.APPROVAL_SCHEMA, 'session': name, 'date': day,
                                        'artifacts': [{'sha256': item.sha256, 'kind': kind or item.kind,
                                                       'wipes_data': wipes} for item in images]}))


class Case(unittest.TestCase):
    def decide(self, item, start='2026100600', allowed=(), readings=None, stage=8, os_booted=True,
               pending='no', stable=None, channel='stable', approved=True, tags=None, table=None,
               session_value=None, session_path=None):
        value = session_value or session(start, allowed)
        named = approval(item) if approved else approval(image('grapheneos', '2026081300'))
        return vc.decide(item, table=table or STATE['table'], tags=tags or STATE['tags'],
                         readings=readings or OCTOBER, stage=stage, os_booted=os_booted,
                         update_pending=pending, channel=channel, session=value, approval=named,
                         session_path=session_path,
                         current_stable=R(stable) if stable else None,
                         stable_fetched_at='2026-10-09T10:55:00Z' if stable else None,
                         security_previews=False, now='2026-10-09T23:00:00Z')

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
        first = session('2026081300', [('2026100600', '2026-10-09T10:30:00Z')])
        second = vc.start_session('s2', '2026-10-10', previous=first, now='2026-10-10T09:00:00Z')
        self.assertEqual((second['start_release'], second['carried']), ('2026100600', ['2026081300', '2026100600']))
        self.assertEqual(second['previous_sha256'], caiman.sha256(caiman.dump(first).encode()))
        for kwargs in ({'previous': first, 'first_release': '2026100600'}, {},
                       {'previous': dict(first, session='s2')}):
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
                             ('entry', {'allowed': [{'release': '2026100600'}]})):
            with self.subTest(name), self.assertRaises(Refusal):
                vc.check_session(dict(copy.deepcopy(good), **change))

    def test_an_edited_start_cannot_lower_the_reference(self):
        # An edited record: start 2026081300 beside a carried 2026100600, with October readings.
        edited = session('2026081300')
        edited['carried'] = ['2026081300', '2026100600']
        with self.assertRaises(Refusal):
            vc.check_session(edited)
        # Without check_session, the reference is still the newest known release.
        self.assertEqual(vc.phone_release(edited).number, '2026100600')

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
        self.paths['session'] = work / 'session.json'
        patches = (mock.patch.object(adevtool_record, 'BASES', self.world.bases),
                   mock.patch.object(install_zip, 'BASES', self.world.bases))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def call(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = vc.main(list(argv))
        return status, json.loads(output.getvalue())

    def decide(self, approval, taken=None):
        taken = taken or self.taken
        readings = Path(self.tmp.name) / f'readings-{taken}'
        readings.write_bytes(samples.synthetic(samples.AUGUST, taken_at=taken))
        return self.call('decide', '--record', str(self.paths['2026081300']), '--record',
                         str(self.paths['2026100600']), '--manifests', str(self.world.repo),
                         '--allowed-signers', str(self.world.signers), '--image', 'stock',
                         '--zip', str(self.zip), '--session', str(self.paths['session']),
                         '--readings', str(readings), '--stage', '8', '--os-booted', 'yes',
                         '--update-pending', 'no', '--channel', 'stable', '--security-previews', 'no',
                         '--approval', str(self.paths[approval]))

    def test_session_flow(self):
        status, started = self.call('start', '--out', str(self.paths['session']), '--session', 's1',
                                    '--date', '2026-10-09', '--first-release', '2026081300')
        self.assertEqual((status, started['start_release']), (0, '2026081300'))
        self.taken = vc.utc_now()
        status, result = self.decide('other', taken='2099-01-01T00:00:00Z')   # from the future
        self.assertEqual((status, result['verdict']), (1, 'REFUSE'))
        status, result = self.decide('other')
        self.assertEqual((status, result['verdict']), (3, 'WAIT'))
        status, result = self.decide('named')
        self.assertEqual((status, result['verdict'], result['branch']), (0, 'ALLOW', 'newer'))
        self.assertEqual(json.loads(self.paths['session'].read_text())['allowed'][0]['sha256'], self.digest)
        status, result = self.decide('named')      # the same readings again, after the ALLOW
        self.assertEqual((status, result['verdict']), (1, 'REFUSE'))
        status, result = self.call('desk', '--record', str(self.paths['2026081300']), '--record',
                                   str(self.paths['2026100600']), '--manifests', str(self.world.repo),
                                   '--allowed-signers', str(self.world.signers), '--image', 'stock',
                                   '--zip', str(self.zip), '--base-tag', '2026100600')
        self.assertEqual((status, result['verdict']), (0, 'PASS'))

    def test_typed_session_facts_are_not_options(self):
        for extra in (['--phone-release', '2026081300'], ['--written', '2026100600'],
                      ['--image-release', '2026110500'], ['--releases', 'page.html']):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                vc.main(['decide', '--record', 'r', '--manifests', 'm', '--allowed-signers', 's',
                         '--image', 'stock', '--zip', 'z', '--session', 's', '--readings', 'r',
                         '--stage', '8', '--os-booted', 'yes', '--update-pending', 'no', '--channel',
                         'stable', '--security-previews', 'no', '--approval', 'a', *extra])


if __name__ == '__main__':
    unittest.main()
