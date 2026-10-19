# SPDX-License-Identifier: Apache-2.0
"""Owner store role, capture, value and stage checks on synthetic captures. No Android runtime."""
import copy
import re
import unittest

import fixtures as f
import owner_fixtures as of
import owner_stores as own
from protocol import PACKAGE

ACCESS = '/data/misc_de/0/apexdata/com.android.permission'
POLICY = '/data/system/notification_policy.xml'
JOBS = '/data/system/job'


def assess(stage='retained', captures=None, dumps=None, baselines=None):
    return own.assess(captures or of.owner_captures(stage), dumps or of.owner_dumps(stage),
                      f.CONTRACT, stage, baselines or of.baselines(stage))


def edit_stat(record, **changes):
    fields = record['stdout'].rstrip('\n').split('|')
    names = ['device', 'inode', 'links', 'blocks', 'unit', 'uid', 'gid', 'mode', 'size', 'atime',
             'mtime', 'ctime', 'context', 'type', 'name']
    for key, value in changes.items():
        fields[names.index(key)] = str(value)
    record['stdout'] = '|'.join(fields) + '\n'


class RoleTests(unittest.TestCase):
    def test_each_owner_rule_names_every_sibling(self):
        self.assertEqual(own.roles('notification', {'notification_policy.xml',
                                                    'notification_policy.xml.new',
                                                    'notification_policy.xml.bak'}),
                         {'notification_policy.xml': 'base', 'notification_policy.xml.new': 'new',
                          'notification_policy.xml.bak': 'legacy-backup'})
        self.assertEqual(own.roles('access', {'access.abx.reservecopy.bak'}),
                         {'access.abx.reservecopy.bak': 'reserve-legacy-backup'})
        self.assertEqual(own.roles('packages', {'packages-backup.xml'}),
                         {'packages-backup.xml': 'backup'})
        self.assertEqual(own.roles('jobs', {'jobs.xml', 'jobs_10123.xml.new'}),
                         {'jobs.xml': 'primary', 'jobs_10123.xml.new': 'new'})
        self.assertEqual(own.roles('native', {'slots/10123/record.bin-backup'}),
                         {'slots/10123/record.bin-backup': 'entry'})
        # Each owner's own rule only: no .new for Package Manager, no native names elsewhere.
        for family, name in [('notification', 'notification_policy.xml.tmp'),
                             ('notification', 'notification_policy.xml.reservecopy'),
                             ('access', 'access.abx.old'), ('access', 'access.abx-backup'),
                             ('packages', 'packages.xml.new'), ('packages', 'packages.xml.bak'),
                             ('restrictions', 'package-restrictions.xml.new'),
                             ('jobs', 'jobs_0123.xml'), ('jobs', 'jobs_1Xxml'),
                             ('jobs', 'jobs.xml.tmp'), ('jobs', 'jobs_10123.xml.new.new'),
                             ('jobs', 'jobs_4294967296.xml'), ('access', 'record.bin-backup')]:
            with self.subTest(family=family, name=name), self.assertRaises(ValueError):
                own.roles(family, {name})

    def test_next_read_and_transactions_follow_each_owner_source(self):
        same, other = {'packages.xml': 'a', 'packages.xml.reservecopy': 'a'}, \
            {'packages.xml': 'a', 'packages.xml.reservecopy': 'b'}
        cases = [
            ('packages', {'packages.xml', 'packages.xml.reservecopy'}, same, 'packages.xml', []),
            # A backup is read first and removes the main, so it must never stand beside one.
            ('packages', {'packages.xml', 'packages.xml.reservecopy', 'packages-backup.xml'},
             same, 'packages-backup.xml', ['backup-present']),
            ('packages', {'packages.xml.reservecopy'}, same, 'packages.xml.reservecopy',
             ['main-missing']),
            ('packages', {'packages.xml'}, same, 'packages.xml', ['reserve-missing']),
            ('packages', {'packages.xml', 'packages.xml.reservecopy'}, other, 'packages.xml',
             ['reserve-lag']),
            ('access', {'access.abx', 'access.abx.reservecopy'},
             {'access.abx': 'a', 'access.abx.reservecopy': 'a'}, 'access.abx', []),
            # The Access store never falls back to its reserve for an absent main.
            ('access', {'access.abx.reservecopy'}, {}, None, ['main-missing']),
            ('access', {'access.abx', 'access.abx.bak', 'access.abx.reservecopy'},
             {'access.abx': 'a', 'access.abx.reservecopy': 'a'}, 'access.abx.bak',
             ['legacy-backup']),
            ('access', {'access.abx', 'access.abx.reservecopy', 'access.abx.reservecopy.new'},
             {'access.abx': 'a', 'access.abx.reservecopy': 'a'}, 'access.abx', ['reserve-new']),
            ('notification', {'notification_policy.xml'}, {}, 'notification_policy.xml', []),
            ('notification', {'notification_policy.xml.new'}, {}, None, ['new']),
            ('notification', {'notification_policy.xml', 'notification_policy.xml.bak'}, {},
             'notification_policy.xml.bak', ['legacy-backup']),
        ]
        for family, names, digests, next_read, transactions in cases:
            with self.subTest(family=family, names=sorted(names)):
                shape = own.layout(family, names, digests)
                self.assertEqual(shape['next_read'], next_read)
                self.assertEqual(shape['transactions'], transactions)
                self.assertEqual(shape['settled'], not transactions)
        jobs = own.layout('jobs', {'jobs.xml', 'jobs_10123.xml', 'jobs_10050.xml'}, {})
        self.assertTrue(jobs['settled'])
        self.assertEqual(jobs['primaries'], ['jobs.xml', 'jobs_10050.xml', 'jobs_10123.xml'])
        self.assertEqual(own.layout('jobs', {'jobs_10123.xml', 'jobs_10123.xml.new'}, {})
                         ['transactions'], ['new:jobs_10123.xml.new'])
        orphan = own.layout('jobs', {'jobs_10123.xml.bak'}, {})
        self.assertEqual((orphan['transactions'], orphan['next_read']),
                         (['legacy-backup:orphan:jobs_10123.xml.bak'], {}))


class NamespaceTests(unittest.TestCase):
    def test_settled_controls_for_every_family(self):
        for family, capture in [
                ('packages', of.packages_family()),
                ('restrictions', of.namespace('restrictions', {
                    'package-restrictions.xml': (b'<package-restrictions/>', None,
                                                 {'mode': '660'}),
                    'package-restrictions.xml.reservecopy': (b'<package-restrictions/>', None,
                                                             {'mode': '660'})})),
                ('access-system', of.namespace('access-system', {
                    'access.abx': (b'ABX\x00x', None, None),
                    'access.abx.reservecopy': (b'ABX\x00x', None, None)})),
                ('native', of.namespace('native', {
                    'store.bin': (b'header', None, None),
                    'store.bin.reservecopy': (b'header', None, None),
                    'slots/10123/record.bin': (b'body', None, None)},
                    directories=('slots', 'slots/10123'), root={'mode': '700'}))]:
            with self.subTest(family=family):
                state = own.namespace(family, capture)
                self.assertTrue(state['present'] and state['layout']['settled'])
        # A missing native store is admitted only as a phase's explicit exception.
        missing = own.namespace('native', of.namespace('native', {}, missing=True),
                                absent_allowed=True)
        self.assertFalse(missing['present'])
        with self.assertRaisesRegex(ValueError, 'owner directory absent'):
            own.namespace('native', of.namespace('native', {}, missing=True))
        captures = of.owner_captures()
        for family in own.SUBJECT_FAMILIES:
            state = own.namespace(family, captures[family])
            # Version 21: the real layout's five job files after initialize (four other files, the subject's).
            self.assertEqual(len(own.selected_records(state)), 5 if family == 'jobs' else 1)
            self.assertTrue(all(x['binary_xml'] for x in state['files'].values()))
        # The Access store's selected record is its main; the reserve only binds it.
        access = own.namespace('access', captures['access'])
        self.assertEqual(list(own.selected_records(access)), ['access.abx'])
        legacy = own.namespace('jobs', of.owner_captures(legacy=True, extra_jobs={
            'jobs_10050.xml': of.job_xml(False)})['jobs'])
        self.assertEqual(sorted(own.selected_records(legacy)), sorted(['jobs.xml', 'jobs_10050.xml', *f.other_job_files()]))

    def test_text_xml_is_read_directly_and_bound_to_its_digest(self):
        policy = of.notification_xml()
        capture = of.namespace('notification', {'notification_policy.xml': (policy, None, None)})
        state = own.namespace('notification', capture)
        self.assertEqual(own.selected_records(state), {'notification_policy.xml': policy})
        capture['files'][POLICY]['decode'] = of.capture(['abx2xml', POLICY, '-'], policy)
        with self.assertRaisesRegex(ValueError, 'text file'):
            own.namespace('notification', capture)

    def test_moving_capture_is_unsettled_never_refused(self):
        def moved(change):
            captures = of.owner_captures()
            change(captures)
            for family in own.SUBJECT_FAMILIES:
                own.namespace(family, captures[family])

        changes = {
            'stat after': lambda c: edit_stat(c['notification']['files'][POLICY]['stat_after'],
                                              mtime=of.LATER),
            'digest after': lambda c: c['access']['files'][ACCESS + '/access.abx']
            ['sha256_after'].update(stdout='0' * 64 + '  ' + ACCESS + '/access.abx\n'),
            'listing after': lambda c: c['notification']['listing_after'][0].update(
                stdout=POLICY + '\n' + POLICY + '.new\n'),
            'dedicated directory times': lambda c: edit_stat(c['jobs']['root_after'],
                                                             ctime=of.LATER),
        }
        for name, change in changes.items():
            with self.subTest(name=name), self.assertRaises(own.Unsettled):
                moved(change)
        # A shared directory changes its times for unrelated siblings, which is not instability.
        captures = of.owner_captures()
        edit_stat(captures['notification']['root_after'], mtime=of.LATER, ctime=of.LATER)
        own.namespace('notification', captures['notification'])
        appearing = of.namespace('native', {}, missing=True)
        appearing['root_after'] = of.stat('/data/system/native-principals', kind='directory',
                                          mode='700')
        with self.assertRaises(own.Unsettled):
            own.namespace('native', appearing, absent_allowed=True)

    def test_transaction_siblings_and_lagging_reserves_are_unsettled(self):
        raw = of.binary(of.access_xml())
        variants = {
            'backup beside main': ('packages', of.packages_family(backup=b'<packages/>')),
            'lagging package reserve': ('packages', of.packages_family(reserve=b'<older/>')),
            'lagging access reserve': ('access', of.namespace('access', {
                'access.abx': (raw, of.access_xml(), None),
                'access.abx.reservecopy': (of.binary(of.access_xml(24592)), of.access_xml(24592),
                                           None)})),
            'missing access reserve': ('access', of.namespace('access', {
                'access.abx': (raw, of.access_xml(), None)})),
            'access write in progress': ('access', of.namespace('access', {
                'access.abx': (raw, of.access_xml(), None), 'access.abx.new': (b'ABX\x00', None,
                                                                               None),
                'access.abx.reservecopy': (raw, of.access_xml(), None)})),
            'legacy notification backup': ('notification', of.namespace('notification', {
                'notification_policy.xml': (b'<a/>', None, None),
                'notification_policy.xml.bak': (b'<b/>', None, None)})),
            'failed job write': ('jobs', of.namespace('jobs', {
                'jobs_10123.xml': (b'<job-info version="1"/>', None, None),
                'jobs_10123.xml.new': (b'<job-info', None, None)})),
        }
        for name, (family, capture) in variants.items():
            with self.subTest(name=name), self.assertRaises(own.Unsettled):
                own.namespace(family, capture)

    def test_refused_evidence_is_never_an_empty_state(self):
        path = ACCESS + '/access.abx'

        def access(change):
            capture = of.owner_captures()['access']
            change(capture)
            return capture

        variants = {
            'symbolic link': access(lambda c: [edit_stat(c['files'][path][k], type='symbolic link')
                                               for k in ('stat_before', 'stat_after')]),
            'hard link': access(lambda c: [edit_stat(c['files'][path][k], links=2)
                                           for k in ('stat_before', 'stat_after')]),
            'alias': access(lambda c: [edit_stat(c['files'][path + '.reservecopy'][k],
                                                 inode=c['files'][path]['stat_before']['stdout']
                                                 .split('|')[1])
                                       for k in ('stat_before', 'stat_after')]),
            'unknown sibling': of.namespace('access', {
                'access.abx': (b'ABX\x00a', b'<access/>', None),
                'access.abx.reservecopy': (b'ABX\x00a', b'<access/>', None),
                'access.abx.tmp': (b'x', None, None)}),
            'duplicate listing': access(lambda c: c['listing'][0].update(
                stdout=c['listing'][0]['stdout'] * 2)),
            'outside parent': access(lambda c: c['listing'][0].update(
                stdout=c['listing'][0]['stdout'] + '/data/system/access.abx\n')),
            'missing record': access(lambda c: c['files'].pop(path + '.reservecopy')),
            'pull differs': access(lambda c: c['files'][path]['pull'].update(
                bytes=b'ABX\x00' + b'0' * (len(c['files'][path]['pull']['bytes']) - 4))),
            'truncated pull': access(lambda c: c['files'][path]['pull'].update(
                bytes=c['files'][path]['pull']['bytes'][:-1])),
            'incomplete command': access(lambda c: c['files'][path]['sha256_before'].update(
                complete=False)),
            'other digest argv': access(lambda c: c['files'][path]['sha256_before'].update(
                argv=['sha256sum', '-b', path])),
            'converter failed': access(lambda c: c['files'][path]['decode'].update(
                exit_code=1, stdout=b'')),
            'converter error output': access(lambda c: c['files'][path]['decode'].update(
                stderr='java.lang.IllegalStateException\n')),
            'converter of another file': access(lambda c: c['files'][path]['decode'].update(
                argv=['abx2xml', path + '.reservecopy', '-'])),
            'binary without converter': access(lambda c: c['files'][path].update(decode=None)),
            'reserve decodes differently': access(lambda c: c['files'][path + '.reservecopy']
                                                  ['decode'].update(stdout=of.access_xml(24592))),
            'directory in a file family': access(lambda c: c['directories'].update(
                {ACCESS + '/x': {}})),
            'absent required directory': of.namespace('access', {}, missing=True),
        }
        for name, capture in variants.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as caught:
                    own.namespace('access', capture)
                self.assertNotIsInstance(caught.exception, own.Unsettled)
        wrong_mode = of.packages_family(mode='600')
        with self.assertRaisesRegex(ValueError, 'owner, mode or label'):
            own.namespace('packages', wrong_mode)
        decoded = of.packages_family()
        decoded['files']['/data/system/packages.xml']['decode'] = of.capture(
            ['abx2xml', '/data/system/packages.xml', '-'], b'<packages/>')
        with self.assertRaisesRegex(ValueError, 'never decodes'):
            own.namespace('packages', decoded)
        odd = of.namespace('native', {}, missing=True)
        odd['root']['stderr'] = 'stat: permission denied\n'
        with self.assertRaises(ValueError):
            own.namespace('native', odd)

    def test_required_owner_files_and_explicit_absence(self):
        # Every main and reserve gone: no transaction is left, and no persistence either.
        for family in ('packages', 'restrictions', 'access', 'access-system', 'notification'):
            with self.subTest(family=family), self.assertRaisesRegex(ValueError,
                                                                    'required owner files'):
                own.namespace(family, of.namespace(family, {}))
        for family in ('packages', 'restrictions', 'access', 'access-system', 'jobs'):
            with self.subTest(family=family), self.assertRaisesRegex(ValueError,
                                                                    'inadmissible absence'):
                own.namespace(family, of.namespace(family, {}), absent_allowed=True)
        # The notification policy before its first write, only where the phase says so.
        empty = own.namespace('notification', of.namespace('notification', {}),
                              absent_allowed=True)
        self.assertEqual((empty['present'], own.selected_records(empty)), (True, {}))
        # A job directory with no persisted job at all is an ordinary settled family.
        self.assertEqual(own.selected_records(own.namespace('jobs', of.namespace('jobs', {}))),
                         {})
        baseline = of.owner_captures('baseline')
        baseline['notification'] = of.namespace('notification', {})
        with self.assertRaisesRegex(ValueError, 'required owner files'):
            assess('baseline', captures=copy.deepcopy(baseline))
        allowed = own.assess(baseline, of.owner_dumps('baseline'), f.CONTRACT, 'baseline',
                             of.baselines('baseline'), absent_allowed=('notification',))
        self.assertTrue(allowed['matches'])
        with self.assertRaisesRegex(ValueError, 'absence exceptions'):
            own.assess(baseline, of.owner_dumps('baseline'), f.CONTRACT, 'baseline',
                       of.baselines('baseline'), absent_allowed=('access',))

    def test_fingerprints_name_every_change(self):
        first = own.fingerprint(own.namespace('jobs', of.owner_captures()['jobs']))
        self.assertEqual(own.differences(first, copy.deepcopy(first)), [])
        second = copy.deepcopy(first)
        second['files']['jobs_10123.xml']['sha256'] = '0' * 64
        second['root']['mtime'] = of.LATER
        self.assertEqual(own.differences(first, second), ['root', 'file:jobs_10123.xml'])


class ValueTests(unittest.TestCase):
    def test_every_stage_control_matches_and_agrees(self):
        for stage in own.STAGES:
            with self.subTest(stage=stage):
                result = assess(stage)
                self.assertTrue(result['settled'], result['unsettled'])
                self.assertEqual((result['mismatches'], result['refused_readers']), ([], []))
                self.assertTrue(result['matches'])
        deferred = assess(dumps=of.owner_dumps(admitted=False),
                          baselines=of.baselines(admitted=False))
        self.assertTrue(deferred['matches'])

    def test_contrary_forms_are_named_findings(self):
        def run(stage='retained', captures=None, dumps=None, baselines=None):
            result = assess(stage, captures, dumps, baselines)
            self.assertTrue(result['settled'], result['unsettled'])
            self.assertFalse(result['matches'])
            return result['mismatches']

        reset = of.notification_xml('reset')
        moved = of.notification_xml(uid=10124)
        other_extras = (b'<extras><string name="andrix.b2.setup">' + b'9' * 32
                        + b'</string></extras>')
        cases = {
            'wrong flags': (['permission-flags'], {
                'captures': of.owner_captures(access=of.access_xml(24592)),
                'dumps': of.owner_dumps(flags=24592)}),
            'extra flag': (['permission-flags'], {
                'captures': of.owner_captures(access=of.access_xml(24624 | 64)),
                'dumps': of.owner_dumps(flags=24624 | 64)}),
            # Version 21: the old prediction, refused as a finding.
            'old prediction 48': (['permission-flags'], {
                'captures': of.owner_captures(access=of.access_xml(48)),
                'dumps': of.owner_dumps(flags=48)}),
            'uid override': (['uid-override'], {
                'captures': of.owner_captures(access=of.access_xml(uid_mode=1)),
                'dumps': of.owner_dumps(uid_mode=1)}),
            'package mode reset': (['package-mode'], {
                'captures': of.owner_captures(access=of.access_xml(package_mode=None)),
                'dumps': of.owner_dumps(package_mode=None, appops=of.appops_texts(None))}),
            'preference reset': (['preference-reset'], {
                'captures': of.owner_captures(policy=reset),
                'dumps': of.owner_dumps(preference='reset')}),
            'preference moved': (['preference-lost', 'preference-moved-uid'], {
                'captures': of.owner_captures(policy=moved),
                'dumps': of.owner_dumps(notification=of.notification_text(uid=10124))}),
            'preference lost': (['preference-lost'], {
                'captures': of.owner_captures(policy=of.notification_xml('absent')),
                'dumps': of.owner_dumps(preference='absent')}),
            'job lost': (['job-lost'], {
                'captures': of.owner_captures(jobs=of.job_xml(False)),
                'dumps': of.owner_dumps(job=False)}),
            'job replaced markers': (['job-replaced'], {
                'captures': of.owner_captures(jobs=of.job_xml(extras=other_extras))}),
            'job replaced periodic': (['job-replaced'], {
                'captures': of.owner_captures(jobs=of.job_xml(timing='periodic'))}),
            'job replaced due': (['job-replaced'], {
                'captures': of.owner_captures(jobs=of.job_xml(due=f.DUE + 120000)),
                'dumps': of.owner_dumps(rtc=of.RTC_SECONDS + 120)}),
            'job executed on disk': (['job-executed'], {
                'captures': of.owner_captures(jobs=of.job_xml(runs=(1800000000000, 0, 15)))}),
            'job executed in history': (['job-executed'], {
                'dumps': of.owner_dumps(jobs=of.job_text().replace(
                    'Recently completed jobs:\n  None\n',
                    'Recently completed jobs:\n  #u0a123/21802 stopped\n'))}),
            'job component': (['job-component'], {
                'dumps': of.owner_dumps(admitted=False)}),
            'appops history': (['appops-history'], {
                'dumps': of.owner_dumps(appops=('VIBRATE: ignore; time=+1s0ms ago\n',
                                                of.appops_texts()[1]))}),
        }
        for name, (expected, kwargs) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(run(**kwargs), expected)
        self.assertEqual(run('baseline', captures=of.owner_captures(
            'baseline', policy=of.notification_xml('created')), dumps=of.owner_dumps(
            'baseline', preference='created')), ['preference-preexisting'])
        self.assertEqual(run('baseline', captures=of.owner_captures('baseline',
                                                                    jobs=of.job_xml()),
                             dumps=of.owner_dumps('baseline', job=True)), ['job-preexisting'])
        # A pinned field outside the selected values is still caught, by the strict readers.
        refused = assess(captures=of.owner_captures(policy=of.notification_xml().replace(
            b'orig_imp="2"', b'orig_imp="3"')))
        self.assertEqual(refused['mismatches'], [])
        self.assertTrue(refused['refused_readers'] and not refused['matches'])

    def test_disk_and_dump_disagreement_is_unsettled_not_a_finding(self):
        cases = {
            'access:permission_flags': {'dumps': of.owner_dumps(flags=24592)},
            'notification:channel': {'dumps': of.owner_dumps(preference='reset')},
            'jobs:identity': {'dumps': of.owner_dumps(job=False)},
            'jobs:due': {'dumps': of.owner_dumps(rtc=of.RTC_SECONDS + 61)},
        }
        for reason, kwargs in cases.items():
            with self.subTest(reason=reason):
                result = assess(**kwargs)
                self.assertFalse(result['settled'] or result['matches'])
                self.assertIn(reason, result['unsettled'][0])
        within = assess(dumps=of.owner_dumps(rtc=of.RTC_SECONDS + 59))
        self.assertTrue(within['matches'])

    def test_dump_grammar_refusals(self):
        retained = of.permission_text()
        variants = {
            'flag order': retained.replace('[RUNTIME_GRANTED|USER_SET|',
                                           '[USER_SET|RUNTIME_GRANTED|'),
            'unknown flag': retained.replace('[RUNTIME_GRANTED|USER_SET|', '[RUNTIME_GRANTED|NEW|'),
            'grant against flags': retained.replace('granted=true, flags=[RUNTIME',
                                                    'granted=false, flags=[RUNTIME'),
        }
        for name, text in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                assess(dumps=of.owner_dumps(permission=text))
        package = of.permission_text().replace(f'version=20', 'version=16')
        dumps = of.owner_dumps()
        dumps['permission_package']['stdout'] = package
        with self.assertRaisesRegex(ValueError, 'selectors disagree'):
            assess(dumps=dumps)
        for appops in [('VIBRATE: ignore\nVIBRATE: ignore\n', of.appops_texts()[1]),
                       ('VIBRATE: ignore\nUid mode: VIBRATE: ignore\n', of.appops_texts()[1]),
                       ('VIBRATE: ignore; later\n', of.appops_texts()[1]),
                       ('Uid mode: VIBRATE: ignore\nVIBRATE: ignore\n', of.appops_texts()[1])]:
            with self.subTest(appops=appops[0]), self.assertRaises(ValueError):
                assess(dumps=of.owner_dumps(appops=appops))
        for jobs in [of.job_text().replace('Registered 11 jobs:', 'Registered 12 jobs:'),
                     of.job_text().split('Pending queue:')[0],
                     of.job_text().replace('    Source:', '    Source: x\n    Source:')]:
            with self.subTest(jobs=jobs[-40:]), self.assertRaises(ValueError):
                assess(dumps=of.owner_dumps(jobs=jobs))
        stray = of.notification_text().replace('Restored without uid:\n',
                                               'Restored without uid:\n    ' + PACKAGE + '\n')
        with self.assertRaisesRegex(ValueError, 'outside its package block'):
            assess(dumps=of.owner_dumps(notification=stray))
        duplicate = of.job_xml().replace(b'</extras>', b'<string name="andrix.b2.setup">x'
                                                       b'</string></extras>')
        with self.assertRaisesRegex(ValueError, 'duplicate stored job extra'):
            assess(captures=of.owner_captures(jobs=duplicate))
        rtc = of.owner_dumps()
        rtc['rtc']['stdout'] = '17974080010\n'.replace('0\n', '.5\n')
        with self.assertRaises(ValueError):
            assess(dumps=rtc)

    def test_duplicate_or_misfiled_job_records_are_refused(self):
        # Both files name one job identity; JobStore would keep whichever it lists first.
        for extra in [{'jobs.xml': of.job_xml()}, {'jobs_10050.xml': of.job_xml()}]:
            with self.subTest(extra=sorted(extra)), self.assertRaisesRegex(ValueError,
                                                                          'stored job'):
                assess(captures=of.owner_captures(extra_jobs=extra))
        other = of.job_xml().replace(b'uid="10123"', b'uid="10050"').replace(
            f'package="{PACKAGE}"'.encode(), b'package="com.example.other"')
        legacy = assess(captures=of.owner_captures(extra_jobs={'jobs.xml': other.replace(
            b'jobid="21802"', b'jobid="7"')}))
        self.assertTrue(legacy['matches'])

    def test_baselines_pin_later_observations(self):
        first = assess()
        later = own.comparable(assess())
        self.assertEqual(own.selected_changes(own.comparable(first), later), [])
        shifted = own.comparable(assess(captures=of.owner_captures(jobs=of.job_xml(
            due=f.DUE + 30000)), dumps=of.owner_dumps(rtc=of.RTC_SECONDS + 30)))
        self.assertEqual(own.selected_changes(own.comparable(first), shifted), [])
        far = own.comparable(assess(captures=of.owner_captures(jobs=of.job_xml(
            due=f.DUE + 61000)), dumps=of.owner_dumps(rtc=of.RTC_SECONDS + 61),
            baselines=of.baselines(original_due_ms=f.DUE + 61000)))
        self.assertEqual(own.selected_changes(own.comparable(first), far), ['due_ms'])
        channel = first['values']['dump']['rendered']['packages'][0]['channels'][
            "'andrix.b2.state'"]
        stored_channel = first['values']['disk']['policy']['packages'][0]['channels'][
            'andrix.b2.state']
        pinned = of.baselines(channel=channel, stored_channel=stored_channel)
        self.assertTrue(assess(baselines=pinned)['matches'])
        changed = dict(stored_channel, orig_imp='3')
        refused = assess(baselines=of.baselines(channel=channel, stored_channel=changed))
        self.assertTrue(any(x.startswith('stored-notification') for x in
                            refused['refused_readers']))

    def test_access_grammar_holds_at_every_stage(self):
        # An unknown owner element and an unknown section at the grant stage, beside the same
        # record left well formed.
        granted = of.access_xml(24592, None)
        self.assertTrue(assess('granted', captures=of.owner_captures('granted',
                                                                   access=granted))['matches'])
        bogus = re.sub(rb'<app-id id="10123">(.*?)</app-id>', rb'<bogus id="10123">\1</bogus>', granted, count=1, flags=re.S)
        section = granted.replace(b'<package-versions>',
                                  b'<unknown-selected-section/><package-versions>', 1)
        for name, data in (('unknown owner element', bogus), ('unknown section', section)):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Access'):
                assess('granted', captures=of.owner_captures('granted', access=data))
        # Every stage keeps the same grammar, whatever value it expects.
        for stage in own.STAGES:
            flags, mode = of.STAGE_STATE[stage][:2]
            data = of.access_xml(flags, mode)
            wrong = re.sub(rb'<app-id id="10123">(.*?)</app-id>', rb'<bogus id="10123">\1</bogus>', data, count=1, flags=re.S)
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, 'Access'):
                assess(stage, captures=of.owner_captures(stage, access=wrong))
        valid = of.access_xml()
        variants = {
            'repeated owner': valid.replace(b'<app-id id="10035">', b'<app-id id="10123">'),
            'repeated row': valid.replace(b'<permission name="android.permission.VIBRATE"',
                                          b'<permission name="android.permission.POST_NOTIFI'
                                          b'CATIONS"'),
            'unknown attribute': valid.replace(b'flags="24624"', b'flags="24624" extra="1"'),
            'missing attribute': valid.replace(b' flags="24624"', b''),
            'nested row': valid.replace(b'<app-op name="android:vibrate" mode="1" />',
                                        b'<app-op name="android:vibrate" mode="1"><x/></app-op>'),
            'wrong row element': valid.replace(b'<app-op name="android:vibrate" mode="1" />',
                                               b'<permission name="android:vibrate" flags="1"/>'),
            'owner attribute': valid.replace(b'<package name="dev.andrix.proof.principalclosed">\n'
                                             b'      <app-op', b'<package name="dev.andrix.proof.'
                                             b'principalclosed" uid="1">\n      <app-op'),
            'section attribute': valid.replace(b'<app-id-app-ops />', b'<app-id-app-ops v="1" />'),
            'repeated section': valid.replace(b'<app-id-app-ops />',
                                              b'<app-id-app-ops /><app-id-app-ops />'),
            'missing section': valid.replace(b'  <app-id-app-ops />\n', b''),
            'malformed device rows': valid.replace(
                b'<app-id-device-permissions />', b'<app-id-device-permissions><app-id id="10123">'
                b'<permission name="x" flags="1"/></app-id></app-id-device-permissions>'),
            'malformed fingerprint': valid.replace(
                b'<default-permission-grant fingerprint="" />', b'<default-permission-grant />'),
        }
        for name, data in variants.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Access'):
                own.access_values(data, f.UID)
        accepted = valid.replace(
            b'<default-permission-grant fingerprint="" />', b'<default-permission-grant fingerprint="build/1"/>'
            b'<app-function-pregrant fingerprint="build/1"/>').replace(
            b'<app-id-device-permissions />',
            b'<app-id-device-permissions><app-id id="10035"><device id="remote:1">'
            b'<permission name="android.permission.CAMERA" flags="16"/></device></app-id>'
            b'</app-id-device-permissions>').replace(
            b'<app-id-app-function-accesses />', b'<app-id-app-function-accesses><app-id id="10035">'
            b'<app-function-access targetUid="10123" flags="1"/></app-id>'
            b'</app-id-app-function-accesses>')
        self.assertEqual(own.access_values(accepted, f.UID)['permission_flags'], 24624)
        # Version 21 (the source check, section 3): an empty fingerprint is the writer's own form, in both grant sections.
        empty = valid.replace(b'<default-permission-grant fingerprint="" />',
                              b'<default-permission-grant fingerprint="" /><app-function-pregrant fingerprint="" />')
        self.assertEqual(own.access_values(empty, f.UID)['device_permissions'], {})

    def test_retained_unscanned_subject_matches_with_its_bare_row(self):
        # Version 22 (the source check's B1): an unscanned retained subject prints its saved AppSettings row bare (NMS takes the
        # suffix from PM's live enumeration, scanned packages only). The strict readers judge that bare row and match.
        result = assess(dumps=of.owner_dumps(admitted=False), baselines=of.baselines(admitted=False))
        self.assertTrue(result['settled'])
        self.assertEqual((result['mismatches'], result['refused_readers'], result['matches']), ([], [], True))
        bare = ' importance=DEFAULT userSet=true'
        self.assertNotIn(bare, of.owner_dumps(admitted=False)['notification']['stdout'])
        # The suffix still binds: the stage's suffix on an unscanned subject, or a bare row on a scanned one, is refused.
        scanned_row = of.notification_text()
        unscanned = assess(dumps=of.owner_dumps(admitted=False, notification=scanned_row), baselines=of.baselines(admitted=False))
        self.assertEqual(unscanned['refused_readers'], ['notification: subject notification preferences differ from the stage'])
        self.assertFalse(unscanned['matches'])
        bare_row = of.notification_text(admitted=False)
        scanned = assess(dumps=of.owner_dumps(notification=bare_row), baselines=of.baselines())
        self.assertEqual(scanned['refused_readers'], ['notification: subject notification preferences differ from the stage'])
        self.assertFalse(scanned['matches'])
        # Another suffix on the unscanned subject is refused too.
        other = bare_row.replace(f'({f.UID})\n', f'({f.UID}) importance=NONE userSet=false\n', 1)
        self.assertNotEqual(other, bare_row)
        self.assertFalse(assess(dumps=of.owner_dumps(admitted=False, notification=other), baselines=of.baselines(admitted=False))['matches'])

    def test_designed_transitions_keep_the_comparable_state(self):
        def state(**dumps):
            return own.comparable(assess(dumps=of.owner_dumps(**dumps),
                                         baselines=of.baselines(admitted=dumps.get('admitted',
                                                                                   True))))

        admitted = state()
        # Only component usability differs across a designed suspension and lift.
        self.assertEqual(own.selected_changes(admitted, state(admitted=False)), [])
        self.assertEqual(own.selected_changes(state(admitted=False), admitted), [])
        # JobStore's first write turns parcelled extras into a map; a deferred package loses
        # the notification permission suffix of its AppSettings row.
        self.assertEqual(own.selected_changes(admitted, state(jobs=of.job_text(parcelled=False))),
                         [])
        bare = of.notification_text().replace(' importance=DEFAULT userSet=true', '', 1)
        self.assertEqual(own.selected_changes(admitted, state(notification=bare)), [])
        # Controls: stored state still compares, and usability is still judged in its phase.
        markers = of.job_xml().replace(f.CONTRACT['setup'].encode(), b'9' * 32)
        changed = own.comparable(assess(captures=of.owner_captures(jobs=markers),
                                        baselines=of.baselines()))
        self.assertEqual(own.selected_changes(admitted, changed), ['jobs'])
        channel = of.notification_text().replace('mOriginalImp=2', 'mOriginalImp=3')
        self.assertIn('rendered', own.selected_changes(admitted, state(notification=channel)))
        self.assertEqual(assess(dumps=of.owner_dumps(admitted=True),
                                baselines=of.baselines(admitted=False))['mismatches'],
                         ['job-component'])

    def test_flag_names_follow_the_permission_service_rendering(self):
        self.assertEqual(own.flags_names(48), ['RUNTIME_GRANTED', 'USER_SET'])
        self.assertEqual(own.flags_value(['RUNTIME_GRANTED', 'USER_SET']), 48)
        self.assertEqual(own.flags_names(1 << 27), ['0x8000000'])
        self.assertEqual(own.flags_value(['INSTALL_GRANTED', '0x8000000']), 1 | 1 << 27)
        self.assertTrue(own.granted(48) and own.granted(1) and not own.granted(0))
        self.assertFalse(own.granted(16 | own.BIT['PURPOSE_REVOKED']))
        self.assertFalse(own.granted(16 | own.BIT['RESTRICTION_REVOKED']))


if __name__ == '__main__':
    unittest.main()
