# SPDX-License-Identifier: Apache-2.0
"""The readers on the real owner forms (checkpoint 5 B version 21, the version 21 specification, parts 1 to 3 and T10),
each beside its refusals. Synthetic captures over the repository's UID 10123; no Android runtime."""
import unittest
from unittest import mock

import fixtures as f
import observations as obs
import owner_fixtures as of
import owner_stores as own
import stored
from protocol import PACKAGE, dumpsys_argv

PERMISSION_APP_ID = dumpsys_argv('permissionmgr', '--app-id', str(f.UID))
NOTIFICATION = dumpsys_argv('notification', '--noredact', '--package', PACKAGE)
JOBSCHEDULER = dumpsys_argv('jobscheduler')


def assess(stage, captures=None, dumps=None, baselines=None):
    return own.assess(captures or of.owner_captures(stage), dumps or of.owner_dumps(stage), f.CONTRACT, stage,
                      baselines or of.baselines(stage))


class StageTableTests(unittest.TestCase):
    def test_the_stage_table_is_the_specifications(self):
        flags = {stage: own.EXPECTED[stage]['flags'] for stage in own.STAGES}
        self.assertEqual(flags, {'baseline': 24576, 'initialized': 24576, 'granted': 24592, 'user-set': 24624,
                                 'ignored': 24624, 'retained': 24624})
        self.assertEqual([own.EXPECTED[s]['package_mode'] for s in own.STAGES], [None, None, None, None, 1, 1])
        self.assertEqual([own.EXPECTED[s]['channel'] for s in own.STAGES],
                         ['absent', 'created', 'created', 'created', 'created', 'retained'])
        self.assertEqual([own.EXPECTED[s]['job'] for s in own.STAGES], [False, True, True, True, True, True])
        self.assertEqual({s: own.EXPECTED[s]['app_settings'] for s in own.STAGES}, f.APP_SETTINGS)
        self.assertEqual({s: (own.EXPECTED[s]['flags'], own.EXPECTED[s]['package_mode'], own.EXPECTED[s]['channel'],
                              own.EXPECTED[s]['job']) for s in own.STAGES}, f.STAGE_STATE)
        self.assertEqual(own.flags_names(24624), ['RUNTIME_GRANTED', 'USER_SET', 'USER_SENSITIVE_WHEN_GRANTED',
                                                  'USER_SENSITIVE_WHEN_REVOKED'])
        self.assertFalse(own.granted(24576))
        self.assertTrue(own.granted(24592) and own.granted(24624))

    def test_every_stage_matches_its_real_state(self):
        for stage in own.STAGES:
            with self.subTest(stage=stage):
                result = assess(stage)
                self.assertTrue(result['settled'], result['unsettled'])
                self.assertEqual((result['mismatches'], result['refused_readers']), ([], []))

    def test_each_old_prediction_is_refused(self):
        # The version 19 readers' values: 0 at the baseline and after initialize, 16 after the grant, 48 from the user
        # set on. Each is now a finding, on disk and in the dump.
        old = {'baseline': 0, 'initialized': 0, 'granted': 16, 'user-set': 48, 'ignored': 48, 'retained': 48}
        for stage, value in old.items():
            mode = f.STAGE_STATE[stage][1]
            with self.subTest(stage=stage):
                result = assess(stage, captures=of.owner_captures(stage, access=of.access_xml(value, mode)),
                                dumps=of.owner_dumps(stage, flags=value))
                self.assertIn('permission-flags', result['mismatches'])
                self.assertTrue(any(r.startswith('stored-access') for r in result['refused_readers']))
                self.assertTrue(any(r.startswith('permission') for r in result['refused_readers']))

    def test_each_stages_neighbour_is_refused(self):
        for stage in own.STAGES:
            for other in own.STAGES:
                if f.STAGE_STATE[other][:2] == f.STAGE_STATE[stage][:2]:
                    continue
                flags, mode = f.STAGE_STATE[other][:2]
                with self.subTest(stage=stage, other=other):
                    with self.assertRaises(ValueError):
                        stored.access(f.access_document(flags, mode), f.UID, f.VERSION,
                                      flags=own.EXPECTED[stage]['flags'], package_mode=own.EXPECTED[stage]['package_mode'])
                    facts = obs.permissionmgr(f.capture(PERMISSION_APP_ID, f.permission_dump(flags, mode)), f.UID)
                    with self.assertRaises(ValueError):
                        obs.require_permission_state(facts, f.VERSION, own.EXPECTED[stage])

    def test_the_sdk_level_is_a_required_baseline(self):
        for value in (None, 0, 1000, '37', 37.0):
            baselines = of.baselines()
            if value is None:
                del baselines['sdk_int']
            else:
                baselines['sdk_int'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                assess('retained', baselines=baselines)


class PermissionTests(unittest.TestCase):
    """T1 and T6: the permission service's dump and the Access user document."""

    def permission(self, text):
        return obs.permissionmgr(f.capture(PERMISSION_APP_ID, text), f.UID)

    def test_the_four_requested_permissions_and_both_selectors(self):
        for stage in own.STAGES:
            facts = self.permission(f.permission_text(stage))
            self.assertEqual(sorted(facts['permissions']), sorted([
                'android.permission.VIBRATE', 'android.permission.POST_NOTIFICATIONS',
                'android.permission.OTHER_SENSORS', 'android.permission.RECEIVE_BOOT_COMPLETED']))
            self.assertEqual((facts['users'], facts['device_permissions'], facts['version']), ([0], {}, f.VERSION))
            obs.require_permission_state(facts, f.VERSION, own.EXPECTED[stage])

    def test_the_printers_grammar_is_order_free_within_a_section(self):
        text = f.permission_text()
        rows = text.split('    App ops:\n')[0].split('    Permissions:\n')[1]
        reordered = text.replace(rows, ''.join(reversed(rows.splitlines(True))))
        self.assertEqual(self.permission(reordered)['permissions'], self.permission(text)['permissions'])
        # Another package of the app ID and a migration version null still parse.
        shared = text + '    Package: app.example.shared\n      version=null\n      App ops:\n'
        self.assertEqual(self.permission(shared)['version'], f.VERSION)

    def test_device_sections_and_other_users_are_findings_not_hidden(self):
        device = f.permission_text().replace('    App ops:\n', '    Permissions (Device 0:virtual):\n'
                                             '      android.permission.CAMERA: granted=false, flags=[]\n'
                                             '    App ops:\n', 1)
        facts = self.permission(device)
        self.assertEqual(facts['device_permissions'], {'0:virtual': {'android.permission.CAMERA':
                                                                     {'granted': False, 'flags': []}}})
        with self.assertRaisesRegex(ValueError, 'device permission'):
            obs.require_permission_state(facts, f.VERSION, own.EXPECTED['retained'])
        second = f.permission_text() + '  User: 10\n    Permissions:\n    App ops:\n'
        facts = self.permission(second)
        self.assertEqual(facts['users'], [0, 10])
        with self.assertRaisesRegex(ValueError, 'another user'):
            obs.require_permission_state(facts, f.VERSION, own.EXPECTED['retained'])
        result = assess('retained', dumps=dict(of.owner_dumps(), permission_app_id=f.capture(PERMISSION_APP_ID, second),
                                               permission_package=f.capture(dumpsys_argv('permissionmgr', '--package', PACKAGE),
                                                                            second)))
        self.assertIn('permission-other-user', result['mismatches'])
        for text, reason in ((f'Unknown app ID {f.UID}.\n', 'names no saved state'),
                             (f.permission_text().replace('    Permissions:\n', ''), 'permission|section'),
                             (f.permission_text().replace('    App ops:\n', '', 1), 'permission|section')):
            with self.subTest(text=text[:40]), self.assertRaisesRegex(ValueError, reason):
                self.permission(text)

    def test_the_access_document_and_its_controls(self):
        self.assertEqual(own.access_values(f.access_xml(), f.UID)['permission_flags'], 24624)
        self.assertEqual(stored.access(f.access_xml(), f.UID, f.VERSION, flags=24624, package_mode=1)['package_mode'], 1)
        refusals = {
            'flags 0 at baseline': (f.access_document(0, None), 'baseline'),
            'flags 48 at retained': (f.access_document(48, 1), 'retained'),
            'subject device owner': (f.access_document(24624, 1, devices='<device id="0:virtual"><permission '
                                                                           'name="android.permission.CAMERA" flags="0" /></device>'),
                                     'retained'),
        }
        for name, (data, stage) in refusals.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                stored.access(data, f.UID, f.VERSION, flags=own.EXPECTED[stage]['flags'],
                              package_mode=own.EXPECTED[stage]['package_mode'])
        device = f.access_document(24624, 1, devices='<device id="0:virtual"><permission '
                                                    'name="android.permission.CAMERA" flags="0" /></device>')
        self.assertEqual(own.access_values(device, f.UID)['device_permissions'], {'0:virtual': {'android.permission.CAMERA': 0}})
        result = assess('retained', captures=of.owner_captures(access=device))
        self.assertFalse(result['settled'])
        self.assertIn('access:device_permissions', result['unsettled'][0])


class NotificationTests(unittest.TestCase):
    """T3, T4 and T7."""

    def test_the_dumps_appsettings_suffix_follows_the_stage(self):
        for stage in own.STAGES:
            with self.subTest(stage=stage):
                obs.notification(f.capture(NOTIFICATION, f.notification_text(stage)), f.UID,
                                 own.EXPECTED[stage]['channel'], app_settings=own.EXPECTED[stage]['app_settings'])
        # The fresh baseline's second legal form: no AppSettings row at all.
        obs.notification(f.capture(NOTIFICATION, f.notification_text('baseline', row=False)), f.UID, 'absent',
                         app_settings=own.EXPECTED['baseline']['app_settings'])
        self.assertTrue(assess('baseline', dumps=of.owner_dumps('baseline', notification=f.notification_text(
            'baseline', row=False)))['matches'])
        wrong = f.notification_text('initialized').replace(' importance=NONE userSet=false',
                                                            ' importance=DEFAULT userSet=true')
        with self.assertRaisesRegex(ValueError, 'differ from the stage'):
            obs.notification(f.capture(NOTIFICATION, wrong), f.UID, 'created', app_settings=own.EXPECTED['initialized']['app_settings'])
        missing = f.notification_text('initialized', row=False)
        with self.assertRaises(ValueError):
            obs.notification(f.capture(NOTIFICATION, missing), f.UID, 'created', app_settings=own.EXPECTED['initialized']['app_settings'])

    def test_the_policy_bubbles_version_is_the_images_sdk(self):
        stored.notification_policy(f.notification_xml(), f.UID, sdk_int=37)
        stored.notification_policy(f.notification_xml('baseline'), f.UID, stage='absent', sdk_int=37)
        stored.notification_policy(f.notification_xml('baseline', package=True), f.UID, stage='absent', sdk_int=37)
        for data, sdk in ((f.notification_xml(sdk=36), 37), (f.notification_xml(), 36),
                          (f.notification_xml().replace(b' last_bubbles_version_upgrade="37"', b''), 37),
                          (f.notification_xml().replace(b'<ranking version="4"', b'<ranking version="3"'), 37)):
            with self.subTest(data=data[180:240], sdk=sdk), self.assertRaisesRegex(ValueError, 'ranking|attribute'):
                stored.notification_policy(data, f.UID, sdk_int=sdk)
        with self.assertRaises(TypeError):
            stored.notification_policy(f.notification_xml(), f.UID)

    def test_the_policy_is_present_from_the_fresh_baseline(self):
        state = own.namespace('notification', of.owner_captures('baseline')['notification'])
        self.assertTrue(state['present'])
        self.assertEqual(own.notification_values(next(iter(own.selected_records(state).values())))['packages'], [])


class JobTests(unittest.TestCase):
    """T5 and T8: the shared header grammar, relative times and the job files."""

    HEADERS = (('  JOB #1000/-1: 2b3c4d5 android/com.android.server.example.NegativeIdJobService',
                '    1000 tag=*job*r/android/com.android.server.example.NegativeIdJobService', (None, '1000', -1)),
               ('  JOB system maintenance/a:b:1000/7: 4d5e6f7 @system maintenance/a:b@android/com.android.server.example.'
                'NamespacedJobService', '    1000 tag=*job*r/@system maintenance/a:b@android/com.android.server.example.'
                'NamespacedJobService', ('system maintenance/a:b', '1000', 7)),
               ('  JOB #u0a35/-7: 5e6f708 app.example.other/.SyncService', '    u0a35 tag=*job*r/app.example.other/.SyncService',
                (None, 'u0a35', -7)),
               ('  JOB work manager:u0a35/12: 6f70819 @work manager@app.example.other/.Worker',
                '    u0a35 tag=*job*r/@work manager@app.example.other/.Worker', ('work manager', 'u0a35', 12)),
               ('  JOB #u0a123/21802: 123abc ' + PACKAGE + '/.B2StateJobService',
                '    u0a123 tag=*job*r/' + PACKAGE + '/.B2StateJobService', (None, 'u0a123', 21802)))

    def test_the_header_grammar(self):
        for line, body, identity in self.HEADERS:
            with self.subTest(line=line):
                value = obs.job_header(line, body)
                self.assertEqual((value['namespace'], value['calling'], value['id']), identity)
        for line, body in (('  JOB #u0a35/-7: 5e6f708 app.example.other/.SyncService', '    u0a36 tag=*job*r/x'),
                           ('  JOB #u0a35/2147483648: 5e6f708 x/.S', '    u0a35 tag=*job*r/x'),
                           ('  JOB #u0a35/-7: 5e6f7081a x/.S', '    u0a35 tag=*job*r/x'),
                           ('  JOB #u0a35/-7: 5e6f708 ', '    u0a35 tag=*job*r/x'),
                           ('  JOB #u0a35/-7: 5e6f708 x/.S', None)):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, 'registered job identity'):
                obs.job_header(line, body)

    def test_both_readers_accept_the_real_dump_and_select_the_same_job(self):
        capture = f.capture(JOBSCHEDULER, f.job_text())
        strict = obs.jobscheduler(capture, f.CONTRACT, True)
        owned = own.job_dump_values(capture, f.UID)
        self.assertEqual((strict['id'], strict['namespace']), (21802, None))
        self.assertEqual([(j['namespace'], j['calling'], j['id']) for j in owned['jobs']], [(None, 'u0a123', 21802)])
        absent = f.capture(JOBSCHEDULER, f.job_text_absent())
        self.assertEqual(obs.jobscheduler(absent, f.CONTRACT, True, False), {'uid': f.UID, 'jobs': []})
        self.assertEqual(own.job_dump_values(absent, f.UID)['jobs'], [])
        # A header whose calling UID disagrees with its first body line is refused by both readers.
        bad = f.job_text().replace('  JOB #u0a35/-7: 5e6f708', '  JOB #u0a36/-7: 5e6f708')
        for reader in (lambda c: obs.jobscheduler(c, f.CONTRACT, True), lambda c: own.job_dump_values(c, f.UID)):
            with self.assertRaisesRegex(ValueError, 'registered job identity'):
                reader(f.capture(JOBSCHEDULER, bad))
        # Another app's block naming the subject in its Source line is the subject's: two own jobs, refused.
        other = f.job_text().replace('    Source: uid=u0a35 user=0 pkg=app.example.other\n    Required constraints: TIMING_DELAY'
                                     ' [0x80000000]\n    Ready: false (job=false user=true !restricted=true !pending=true !active=true '
                                     '!backingup=true comp=true)\n  JOB work', '    Source: uid=u0a123 user=0 pkg=' + PACKAGE + '\n'
                                     '    Required constraints: TIMING_DELAY [0x80000000]\n    Ready: false (job=false user=true '
                                     '!restricted=true !pending=true !active=true !backingup=true comp=true)\n  JOB work', 1)
        self.assertNotEqual(other, f.job_text())
        with self.assertRaisesRegex(ValueError, 'one original own job'):
            obs.jobscheduler(f.capture(JOBSCHEDULER, other), f.CONTRACT, True)

    def test_relative_times(self):
        self.assertEqual((obs.relative_time('--'), obs.relative_time('0'), obs.relative_time('-1s0ms')), (None, 0, -1000))
        # `--` positively only where its caller can print it (Enqueue time); version 22 (the source check's B2).
        deferred = '    Standby bucket: ACTIVE\n      Deferred since: %s\n'
        for old, new in (('    Enqueue time: -1s0ms', '    Enqueue time: --'), ('    Enqueue time: -1s0ms', '    Enqueue time: 0'),
                         # Version 23: every history entry at the same time as now, the timeline as it stands.
                         ('      -1s0ms = ', '      0 = '),
                         ('    Standby bucket: ACTIVE\n', deferred % '-5s0ms'),
                         ('      Extras: mParcelledData.dataSize=248', '      Extras: {andrix.b2.setup=' + f.CONTRACT['setup']
                          + ', andrix.b2.contract_sha256=' + f.CONTRACT['contract_sha256'] + '}')):
            with self.subTest(new=new):
                obs.jobscheduler(f.capture(JOBSCHEDULER, f.job_text().replace(old, new)), f.CONTRACT, True)
        # Version 22 (the source check's B2): the constraint history and the deferral print only a nonzero stored time, so `--` there is
        # excess grammar the source cannot print, and is refused.
        # Version 23: the same refusal on the timeline's oldest entry.
        for old, new in (('      -1s0ms = FLEXIBILITY [0x200000]', '      -- = FLEXIBILITY [0x200000]'),
                         ('    Standby bucket: ACTIVE\n', deferred % '--'),
                         ('    Standby bucket: ACTIVE\n', '    Standby bucket: ACTIVE\n      Time since first force batch attempt: --\n')):
            with self.subTest(refused=new), self.assertRaisesRegex(ValueError, 'prints only when set'):
                obs.jobscheduler(f.capture(JOBSCHEDULER, f.job_text().replace(old, new)), f.CONTRACT, True)
        with self.assertRaisesRegex(ValueError, 'future'):
            obs.jobscheduler(f.capture(JOBSCHEDULER, f.job_text().replace('    Enqueue time: -1s0ms', '    Enqueue time: +1s0ms')),
                             f.CONTRACT, True)

    def test_the_job_fixtures_follow_the_writers(self):
        # Version 22 (the source check's B2): every stored job as JobStore writes it: its constraints, its timing, then its extras element
        # (empty where it has none), and each ordinary periodic job a finite deadline before its delay.
        import xml.etree.ElementTree as ET
        for name, data in dict(f.other_job_files(), **{'jobs_10123.xml': f.job_xml()}).items():
            for job in ET.fromstring(data):
                with self.subTest(name=name, job=job.get('jobid')):
                    self.assertEqual([child.tag for child in job][0], 'constraints')
                    self.assertIn([child.tag for child in job][1], ('one-off', 'periodic'))
                    self.assertEqual([child.tag for child in job][2:], ['extras'])
                    timing = job[1]
                    if timing.tag == 'periodic':
                        self.assertEqual(list(timing.keys()), ['period', 'flex', 'deadline', 'delay'])
        # The subject's ordinary job requires FLEXIBILITY and prints both flexible counts (JobStatus); the source tagged
        # sync job's battery name carries ':' and its service's package, in its header and its wakelock tag.
        text = f.job_text()
        self.assertIn('    Required constraints: TIMING_DELAY FLEXIBILITY [0x80200000]\n', text)
        self.assertIn('    Num Required Flexible constraints: 0\n    Num Dropped Flexible constraints: 0\n', text)
        self.assertIn(': 4d5e6f0 *sync*/app.example.synced:android\n    1000 tag=*job*r/*sync*/app.example.synced:android\n', text)
        selected = obs.jobscheduler(f.capture(JOBSCHEDULER, text), f.CONTRACT, True)
        self.assertEqual((selected['id'], selected['dynamic']['Num Required Flexible constraints']), (f.JOB_ID, '0'))

    def test_the_job_history_ends_in_its_current_mask(self):
        # Version 23 (the version 22 source recheck): JobStatus records the whole satisfied mask on every change, so the selected
        # block's history is a timeline from no constraint, one constraint changing per entry, at most ten entries, and its
        # newest entry is the current satisfied mask; the required and unsatisfied masks agree with it.
        lines = f.job_text().split('  JOB #u0a123/%d: ' % f.JOB_ID, 1)[1].splitlines()

        def mask(text):
            names = [name for name in text.split() if not name.startswith('[')]
            value = int(text.rsplit('[0x', 1)[1].rstrip(']'), 16) if '[' in text else 0
            self.assertEqual(value, sum(obs.CONSTRAINTS[name] for name in names), text)
            return value
        field = {line.split(':', 1)[0].strip(): line.split(':', 1)[1] for line in lines
                 if line.startswith('    ') and not line.startswith('     ') and ':' in line}
        satisfied, required = mask(field['Satisfied constraints']), mask(field['Required constraints'])
        self.assertEqual(mask(field['Unsatisfied constraints']), (required | obs.CONSTRAINTS['WITHIN_QUOTA']) & ~satisfied)
        start = lines.index('    Constraint history:')
        rows = []
        for line in lines[start + 1:]:
            if not line.startswith('      '):
                break
            rows.append(mask(line.split(' =', 1)[1]))
        self.assertTrue(0 < len(rows) <= 10)
        self.assertEqual(rows[-1], satisfied)
        for before, after in zip([0] + rows, rows):
            self.assertEqual(bin(before ^ after).count('1'), 1, (hex(before), hex(after)))
        # The fixture refuses to print a block whose newest history entry is not its current mask: version 22's history under
        # version 22's current mask, and an empty timeline.
        stale = (0x3600000, ['      -1s0ms = DEVICE_NOT_DOZING [0x2000000]\n'])
        with mock.patch.object(f, 'job_constraints', lambda changes=None: stale):
            with self.assertRaisesRegex(AssertionError, 'newest history entry'):
                f.job_text()
        with self.assertRaisesRegex(AssertionError, 'newest history entry'):
            f.job_constraints(())

    def test_the_job_files_and_their_versions(self):
        files = dict(f.other_job_files(), **{'jobs_10123.xml': f.job_xml()})
        self.assertEqual(stored.jobs(files, f.CONTRACT, f.DUE)['delay_utc_ms'], f.DUE)
        self.assertEqual(stored.jobs(f.other_job_files(), f.CONTRACT, initialized=False)['jobs'], [])
        self.assertEqual(len(own.job_values(files, f.UID)['jobs']), 1)
        legacy = f.other_job_files('0')['jobs_10060.xml'].replace(b'uid="10060"', b'uid="10070"')
        stored.jobs(dict(files, **{'jobs_10070.xml': legacy}), f.CONTRACT, f.DUE)
        for name, data, reason in (('jobs_10070.xml', legacy.replace(b'version="0"', b'version="2"'), 'JobStore version'),
                                   ('jobs_10123.xml', f.job_xml('0'), 'version 1')):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, reason):
                stored.jobs(dict(files, **{name: data}), f.CONTRACT, f.DUE)


class SdkTests(unittest.TestCase):
    """T9: the setup's SDK read."""

    def test_the_sdk_read_and_its_refusals(self):
        self.assertEqual(obs.sdk_level(f.capture(obs.SDK_ARGV, '37\n')), 37)
        for text, code, stderr in (('', 0, ''), ('37.0\n', 0, ''), ('37\n', 1, ''), ('037\n', 0, ''), ('37\n', 0, 'x\n'),
                                   ('1000\n', 0, '')):
            with self.subTest(text=text, code=code), self.assertRaises(ValueError):
                obs.sdk_level(f.capture(obs.SDK_ARGV, text, code, stderr))


class ParserPredictionRegression(unittest.TestCase):
    """The source check's check_parser_predictions.py, its findings turned into expectations: the version 19 readers refused 24576,
    24592 and 24624 at their stages and the negative job in the strict reader; these readers accept each."""

    def test_the_real_values_and_the_negative_job(self):
        for flags, stage in ((24576, 'baseline'), (24592, 'granted'), (24624, 'retained')):
            mode = own.EXPECTED[stage]['package_mode']
            facts = obs.permissionmgr(f.capture(PERMISSION_APP_ID, f.permission_dump(flags, mode)), f.UID)
            obs.require_permission_state(facts, f.VERSION, own.EXPECTED[stage])
            self.assertEqual(own.access_values(f.access_document(flags, mode), f.UID)['permission_flags'], flags)
            stored.access(f.access_document(flags, mode), f.UID, f.VERSION, flags=flags, package_mode=mode)
        negative = f.capture(JOBSCHEDULER, f.job_text_absent())
        self.assertEqual(obs.jobscheduler(negative, f.CONTRACT, True, False)['jobs'], [])
        self.assertEqual(own.job_dump_values(negative, f.UID)['jobs'], [])
        for version in (17, 19, 20):
            text = f.permission_dump(24576, None, version=version)
            self.assertEqual(obs.permissionmgr(f.capture(PERMISSION_APP_ID, text), f.UID)['version'], version)


if __name__ == '__main__':
    unittest.main()
