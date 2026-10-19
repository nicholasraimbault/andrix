# SPDX-License-Identifier: Apache-2.0
"""Synthetic source derived forms for host tests. These are not Android captures.

Checkpoint 5 B version 21 (the version 21 specification, part 3): the subject's rows take the real forms the pinned
source prints and the real records show, over this repository's synthetic UID 10123; everything outside the subject's
rows is illustrative and only has to be legal under the readers' grammars. The owner state at each stage is STAGE_STATE
(T0), the specification's stage table.
"""
import json
from protocol import CHANNEL, JOB_ID, NOTIFICATION_SETUP, PACKAGE, SERVICE, make_contract
from observations import CHANNEL_FIELDS

CONTRACT = make_contract(10123, 0, '1' * 32, '2' * 32, '3' * 32)
UID = CONTRACT['uid']
FU = 'u0a' + str(UID - 10000)
NONCE = '4' * 32
GUEST = '5' * 64
DUE = 1800000000000
# The migration version (one of the source's 17, 19 and 20; the source check, section 2) and the B2 image's SDK level.
VERSION = 20
SDK = 37
# T0: the owner state at each setup stage, as (POST_NOTIFICATIONS flags, package mode, preference, job present).
STAGE_STATE = {'baseline': (24576, None, 'absent', False), 'initialized': (24576, None, 'created', True),
               'granted': (24592, None, 'created', True), 'user-set': (24624, None, 'created', True),
               'ignored': (24624, 1, 'created', True), 'retained': (24624, 1, 'retained', True)}
# The subject's AppSettings suffix at each stage (the source check, section 6); the fresh baseline may also print no row.
APP_SETTINGS = {'baseline': ' importance=NONE userSet=false', 'initialized': ' importance=NONE userSet=false',
                'granted': ' importance=DEFAULT userSet=false', 'user-set': ' importance=DEFAULT userSet=true',
                'ignored': ' importance=DEFAULT userSet=true', 'retained': ' importance=DEFAULT userSet=true'}
FLAG_NAMES = {1: 'INSTALL_GRANTED', 16: 'RUNTIME_GRANTED', 32: 'USER_SET', 64: 'USER_FIXED',
              8192: 'USER_SENSITIVE_WHEN_GRANTED', 16384: 'USER_SENSITIVE_WHEN_REVOKED'}
OTHER_SENSORS = 24592


def capture(argv, text, code=0, stderr=''):
    return {'argv': argv, 'stdout': text, 'stderr': stderr, 'exit_code': code, 'complete': True}


def flag_text(flags):
    """A permission row's rendered grant and flag names: ascending bits, no spaces (PermissionFlags.toString)."""
    names = [FLAG_NAMES.get(1 << bit, '0x%X' % (1 << bit)) for bit in range(31) if flags >> bit & 1]
    granted = bool(flags & 1) or (bool(flags & 16) and not flags & 2)
    return 'granted=' + str(granted).lower() + ', flags=[' + '|'.join(names) + ']'


def permission_dump(flags, package_mode, uid_mode=None, version=VERSION, uid=UID, vibrate=1):
    """T1: the permission service's dump of the subject's app ID, both selectors one text; the four permissions are U's
    real requested set (U 166-reboot-subject-settings), the subject's rows exact, the row order illustrative."""
    rows = []
    if vibrate is not None:
        rows.append('      android.permission.VIBRATE: ' + flag_text(vibrate) + '\n')
    if flags is not None:
        rows.append('      android.permission.POST_NOTIFICATIONS: ' + flag_text(flags) + '\n')
    rows.append('      android.permission.OTHER_SENSORS: ' + flag_text(OTHER_SENSORS) + '\n')
    rows.append('      android.permission.RECEIVE_BOOT_COMPLETED: ' + flag_text(1) + '\n')
    modes = ('allow', 'ignore', 'deny', 'default', 'foreground')
    return (f'App ID: {uid}\n  User: 0\n    Permissions:\n' + ''.join(rows) + '    App ops:\n'
            + ('' if uid_mode is None else f'      android:vibrate: mode={modes[uid_mode]}\n')
            + f'    Package: {PACKAGE}\n      version={version}\n      App ops:\n'
            + ('' if package_mode is None else f'        android:vibrate: mode={modes[package_mode]}\n'))


def permission_text(stage='retained'):
    flags, mode, _, _ = STAGE_STATE[stage]
    return permission_dump(flags, mode)


def channel_values():
    values = ["'" + CHANNEL + "'", 'Andrix B2 state', '', '2', 'false', '-1000',
              'null', 'false', '0', 'null', 'null', '100', 'false', 'false', 'true',
              'false', '-1', "'null'", 'AudioAttributes: usage=USAGE_NOTIFICATION '
              'content=CONTENT_TYPE_SONIFICATION flags=0x800(FLAG_MUTE_HAPTIC)  tags= bundle=null',
              'false', '1', 'false', '2', 'null', 'null', 'false', 'false', '0', 'false', 'null']
    assert len(values) == len(CHANNEL_FIELDS)
    return dict(zip(CHANNEL_FIELDS, values))


def channel_text(preference='retained'):
    values = channel_values()
    if preference == 'old-shell':
        values['mUserLockedFields'] = '0'
    elif preference in ('created', 'reset'):
        values['mUserLockedFields'] = '0'; values['mAllowBubbles'] = '-1'
    elif preference != 'retained':
        raise ValueError('synthetic preference state')
    return 'NotificationChannel{' + ', '.join(k + '=' + v for k, v in values.items()) + '}'


def notification_text(stage='retained', preference=None, uid=UID, row=True, admitted=True):
    """T3: the subject's filtered notification dump; the section lines exact, the preamble and the listeners body
    illustrative. PREFERENCE overrides the stage's channel state ('absent' prints no channel line); ROW False prints no
    AppSettings row, the second legal form of the fresh baseline. Version 22 (the source check's B1): ADMITTED False, a package PM has
    not scanned, prints its saved row bare: NMS takes the suffix from PM's live enumeration, which lists scanned packages
    only (PermissionHelper, PreferencesHelper)."""
    _, _, state, _ = STAGE_STATE[stage]
    preference = state if preference is None else preference
    app = (f'      AppSettings: {PACKAGE} ({uid}){APP_SETTINGS[stage] if admitted else ""}\n'
           + ('' if preference == 'absent' else '        ' + channel_text(preference) + '\n')) if row else ''
    return (f"Current Notification Manager state (filtered to '{PACKAGE}'):\n\n Notification Preferences:\n"
            '    per-package config version: 4\nPackagePreferences:\n' + app
            + 'Restored without uid:\n\n  Notification listeners:\n    mListenerHints: 0\n')


# T5 and T8: the other registered jobs, ten of them in four files (C-C1, C-F2 and F-C2 logcats: JobStore read four job
# files and ten jobs), their headers the grammar's test cases and their bodies illustrative. Version 22 (the source check's B2): a job
# with a source tag prints the tag, ':' and its service's package as its battery name (JobStatus), so the sync job's is
# `*sync*/app.example.synced:android`, and its wakelock tag carries the same.
OTHER_JOBS = (
    # file, jobid, package, class, namespace, source tag, source package, calling, timing, constraints, battery
    ('jobs_1000.xml', -1, 'android', 'com.android.server.example.NegativeIdJobService', None, None, 'android', '1000',
     'one-off', {}, 'android/com.android.server.example.NegativeIdJobService'),
    ('jobs_1000.xml', 800, 'android', 'com.android.server.example.IdleMaintenanceJobService', None, None, 'android',
     '1000', 'periodic', {'idle': 'true', 'charging': 'true'}, 'android/com.android.server.example.IdleMaintenanceJobService'),
    ('jobs_1000.xml', 100000, 'android', 'com.android.server.example.ForPackageJobService', None, '*sync*/app.example.synced',
     'app.example.synced', '1000', 'deadline', {}, '*sync*/app.example.synced:android'),
    ('jobs_1000.xml', 7, 'android', 'com.android.server.example.NamespacedJobService', 'system maintenance/a:b', None,
     'android', '1000', 'one-off', {}, '@system maintenance/a:b@android/com.android.server.example.NamespacedJobService'),
    ('jobs_10035.xml', -7, 'app.example.other', 'app.example.other.SyncService', None, None, 'app.example.other', 'u0a35',
     'one-off', {'battery-not-low': 'true'}, 'app.example.other/.SyncService'),
    ('jobs_10035.xml', 12, 'app.example.other', 'app.example.other.Worker', 'work manager', None, 'app.example.other',
     'u0a35', 'one-off', {}, '@work manager@app.example.other/.Worker'),
    ('jobs_10035.xml', 13, 'app.example.other', 'app.example.other.UploadService', None, None, 'app.example.other', 'u0a35',
     'one-off', {}, 'app.example.other/.UploadService'),
    ('jobs_10060.xml', 1, 'app.example.notes', 'app.example.notes.ReminderService', None, None, 'app.example.notes',
     'u0a60', 'extras', {}, 'app.example.notes/.ReminderService'),
    ('jobs_10060.xml', 2, 'app.example.notes', 'app.example.notes.CleanupService', None, None, 'app.example.notes',
     'u0a60', 'periodic', {}, 'app.example.notes/.CleanupService'),
    ('jobs_10135.xml', 1, 'app.example.periodic', 'app.example.periodic.PeriodicService', None, None,
     'app.example.periodic', 'u0a135', 'clamped', {}, 'app.example.periodic/.PeriodicService'),
)
FILE_UIDS = {'jobs_1000.xml': 1000, 'jobs_10035.xml': 10035, 'jobs_10060.xml': 10060, 'jobs_10135.xml': 10135}
JOB_HASHES = ('2b3c4d5', '3c4d5e6', '4d5e6f0', '4d5e6f7', '5e6f708', '6f70819', '708192a', '8192a3b', '92a3b4c', 'a3b4c5d')


def other_job_headers():
    """Each other registered job's block as T5 prints it: its header, its first body line and its Source line."""
    text = ''
    for (name, jobid, package, cls, namespace, tag, source, calling, _, _, battery), digest in zip(OTHER_JOBS, JOB_HASHES):
        prefix = '#' if namespace is None else namespace + ':'
        source_uid = calling if source == package else 'u0a40'
        text += (f'  JOB {prefix}{calling}/{jobid}: {digest} {battery}\n    {calling} tag=*job*r/{battery}\n'
                 f'    Source: uid={source_uid} user=0 pkg={source}\n'
                 '    Required constraints: TIMING_DELAY [0x80000000]\n    Ready: false (job=false user=true !restricted=true '
                 '!pending=true !active=true !backingup=true comp=true)\n')
    return text


# Version 23 (the version 22 source recheck): JobStatus.dumpConstraints prints each constraint of a mask by its name in this
# order, then the mask in lowercase hex.
CONSTRAINT_BITS = (('CHARGING', 1), ('BATTERY_NOT_LOW', 2), ('STORAGE_NOT_LOW', 8), ('TIMING_DELAY', 1 << 31), ('DEADLINE', 1 << 30),
                   ('IDLE', 4), ('CONNECTIVITY', 1 << 28), ('FLEXIBILITY', 1 << 21), ('CONTENT_TRIGGER', 1 << 26),
                   ('DEVICE_NOT_DOZING', 1 << 25), ('BACKGROUND_NOT_RESTRICTED', 1 << 22), ('PREFETCH', 1 << 23), ('WITHIN_QUOTA', 1 << 24))
# The selected job's requested and internal constraints: its delay and the flexibility its ordinary job takes (version 22).
JOB_REQUIRED = ('TIMING_DELAY', 'FLEXIBILITY')
# Version 23: JobStatus records every change of a satisfied constraint as the whole resulting mask (setConstraintSatisfied),
# from no satisfied constraint, and the full dump prints its current satisfied mask, then that history oldest first, so the
# newest entry is the current mask. The selected job's satisfied constraints and its history are one timeline, the one its
# scheduling records: the scheduler's controllers start tracking the new job in their order, and each that applies sets its
# constraint, each change recording the whole mask. FlexibilityController sets FLEXIBILITY, BackgroundJobsController
# BACKGROUND_NOT_RESTRICTED, DeviceIdleJobsController DEVICE_NOT_DOZING and QuotaController WITHIN_QUOTA; the delay stays
# unsatisfied. Every change is at the enqueue time. The times are illustrative.
JOB_SATISFIED_CHANGES = (('-1s0ms', 'FLEXIBILITY'), ('-1s0ms', 'BACKGROUND_NOT_RESTRICTED'), ('-1s0ms', 'DEVICE_NOT_DOZING'),
                         ('-1s0ms', 'WITHIN_QUOTA'))


def constraint_text(mask):
    """JobStatus.dumpConstraints: each constraint of MASK by name in its printing order, each after one space, then the
    mask in lowercase hex; nothing for an empty mask."""
    return ''.join(' ' + name for name, bit in CONSTRAINT_BITS if mask & bit) + (' [0x%x]' % mask if mask else '')


def job_constraints(changes=JOB_SATISFIED_CHANGES):
    """The selected job's current satisfied mask and its constraint history rows from one timeline of CHANGES (each a time
    and the constraint whose satisfaction changed): each row the whole mask after its change, at most the ten the ring keeps,
    the newest the current mask (asserted)."""
    bits = dict(CONSTRAINT_BITS)
    mask, rows = 0, []
    for when, name in changes:
        mask ^= bits[name]
        rows.append('      %s =%s\n' % (when, constraint_text(mask)))
    rows = rows[-10:]
    assert rows and rows[-1].endswith(' =%s\n' % constraint_text(mask)), 'the newest history entry is the current satisfied mask'
    return mask, rows


def job_text(admitted=True, parcelled=True):
    """T5 after initialize: the ten other jobs and the subject's. Version 22 (the source check's B2): the subject's ordinary job lacks
    the system wide flexible constraints, so its JobStatus requires FLEXIBILITY and its dump prints both flexible counts;
    the counts and which constraints are satisfied are runtime values, illustrative here. Version 23: its required,
    satisfied and unsatisfied masks and its constraint history print from one timeline (job_constraints), and the block as
    printed is checked: its newest history entry is its current satisfied mask."""
    comp = str(admitted).lower()
    bits = dict(CONSTRAINT_BITS)
    required = sum(bits[name] for name in JOB_REQUIRED)
    satisfied, history = job_constraints()
    # JobStatus prints as unsatisfied the required constraints and the quota, less the satisfied ones.
    unsatisfied = (required | bits['WITHIN_QUOTA']) & ~satisfied
    extras = 'mParcelledData.dataSize=248' if parcelled else (
        '{andrix.b2.setup=' + CONTRACT['setup'] + ', andrix.b2.contract_sha256='
        + CONTRACT['contract_sha256'] + '}')
    text = (f'Settings:\n  min_ready_non_active_jobs_count=5\n\nRegistered {len(OTHER_JOBS) + 1} jobs:\n'
            + other_job_headers() +
            f'  JOB #u0a123/{JOB_ID}: 123abc {PACKAGE}/.B2StateJobService\n'
            f'    u0a123 tag=*job*r/{PACKAGE}/.B2StateJobService\n'
            f'    Source: uid=u0a123 user=0 pkg={PACKAGE}\n'
            f'    JobInfo:\n      Service: {PACKAGE}/.B2StateJobService\n'
            '      PERSISTED\n      Priority: 300 [DEFAULT]\n'
            '      Requires: charging=false batteryNotLow=false deviceIdle=false\n'
            '      Has media backup exemption=false \n'
            f'      Extras: {extras}\n'
            '      Minimum latency: +30d0h0m0s0ms\n      Backoff: policy=1 initial=+30s0ms\n'
            '      Has early constraint\n'
            '    Required constraints:' + constraint_text(required) + '\n'
            '    Dynamic constraints:\n'
            '    Satisfied constraints:' + constraint_text(satisfied) + '\n'
            '    Unsatisfied constraints:' + constraint_text(unsatisfied) + '\n'
            '    Num Required Flexible constraints: 0\n'
            '    Num Dropped Flexible constraints: 0\n'
            '    Constraint history:\n' + ''.join(history) +
            '    Tracking: TIME QUOTA\n    Implicit constraints:\n'
            '      readyNotDozing: true\n      readyNotRestrictedInBg: true\n'
            f'      readyComponentEnabled: {comp}\n'
            '    Started with foreground flag: false\n    Standby bucket: ACTIVE\n'
            '    Enqueue time: -1s0ms\n'
            '    Run time: earliest=+29d23h59m59s0ms, latest=none, original latest=none\n'
            '    Restricted due to: none.\n'
            '    Ready: false (job=false user=true !restricted=true !pending=true '
            f'!active=true !backingup=true comp={comp})\n'
            '\nTimeController:\n  tracked\nPending queue:\n  None\n'
            'Active jobs:\n  N/A\nRecently completed jobs:\n  None\n')
    # Version 23: the fixture's own check of the block as printed, so its current mask and its newest recorded snapshot
    # cannot drift apart again: the newest history entry is the Satisfied line's mask.
    block = text.split(f'  JOB #u0a123/{JOB_ID}: ', 1)[1].split('\n\n', 1)[0]
    current = block.split('    Satisfied constraints:', 1)[1].split('\n', 1)[0]
    printed = block.split('    Constraint history:\n', 1)[1].split('    Tracking:', 1)[0].splitlines()
    assert printed and printed[-1].split(' =', 1)[1] == current, 'the newest history entry is the current satisfied mask'
    return text


def job_text_absent():
    """T5 before initialize: the ten other jobs and no subject job."""
    return (f'Settings:\n  min_ready_non_active_jobs_count=5\n\nRegistered {len(OTHER_JOBS)} jobs:\n' + other_job_headers()
            + '\nPending queue:\n  None\nActive jobs:\n  N/A\nRecently completed jobs:\n  None\n')


def access_document(flags, package_mode, uid_mode=None, version=VERSION, uid=UID, vibrate=1, devices=''):
    """T6: the decoded Access user document; the subject's rows exact, the other app's rows and the section order
    illustrative, the default grant's fingerprint empty as the writer emits it. DEVICES is the subject's device
    permission owner's inner XML, none by default."""
    perms = ('' if vibrate is None else f'      <permission name="android.permission.VIBRATE" flags="{vibrate}" />\n') + (
        '' if flags is None else f'      <permission name="android.permission.POST_NOTIFICATIONS" flags="{flags}" />\n') + (
        f'      <permission name="android.permission.OTHER_SENSORS" flags="{OTHER_SENSORS}" />\n'
        '      <permission name="android.permission.RECEIVE_BOOT_COMPLETED" flags="1" />\n')
    return ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<access>\n  <package-versions>\n"
            f'    <package name="android" version="{version}" />\n    <package name="app.example.other" version="{version}" />\n'
            f'    <package name="{PACKAGE}" version="{version}" />\n  </package-versions>\n'
            '  <default-permission-grant fingerprint="" />\n  <app-id-permissions>\n'
            '    <app-id id="10035">\n      <permission name="android.permission.INTERNET" flags="1" />\n    </app-id>\n'
            f'    <app-id id="{uid}">\n' + perms + '    </app-id>\n  </app-id-permissions>\n'
            + ('  <app-id-device-permissions />\n' if not devices else
               f'  <app-id-device-permissions>\n    <app-id id="{uid}">{devices}</app-id>\n  </app-id-device-permissions>\n')
            + ('  <app-id-app-ops />\n' if uid_mode is None else
               f'  <app-id-app-ops>\n    <app-id id="{uid}">\n      <app-op name="android:vibrate" mode="{uid_mode}" />\n'
               '    </app-id>\n  </app-id-app-ops>\n')
            + ('  <package-app-ops />\n' if package_mode is None else
               f'  <package-app-ops>\n    <package name="{PACKAGE}">\n      <app-op name="android:vibrate" mode="{package_mode}" />\n'
               '    </package>\n  </package-app-ops>\n')
            + '  <app-id-app-function-accesses />\n</access>\n').encode()


def access_xml(stage='retained'):
    flags, mode, _, _ = STAGE_STATE[stage]
    return access_document(flags, mode)


def notification_setup_ack():
    value = {'version': 1, 'operation': NOTIFICATION_SETUP, 'package': PACKAGE, 'uid': UID,
             'user': 0, 'channel': CHANNEL, 'process_uid': 2000, 'nonce': NONCE,
             'setup': CONTRACT['setup'], 'contract_sha256': CONTRACT['contract_sha256'],
             'stage': 'update_returned', 'setter_calls': 1, 'state_proven': False}
    return 'ANDRIX_B2_NOTIFICATION_SETUP: ' + json.dumps(value) + '\n'


CREATED_CHANNEL = (f'<channel id="{CHANNEL}" name="Andrix B2 state" importance="2" usage="5" content_type="4" '
                   'flags="0" show_badge="true" orig_imp="2" />')
RETAINED_CHANNEL = (f'<channel id="{CHANNEL}" name="Andrix B2 state" importance="2" usage="5" content_type="4" '
                    'flags="0" locked="256" show_badge="true" allow_bubbles="1" orig_imp="2" />')


def notification_xml(stage='retained', preference=None, uid=UID, sdk=SDK, package=None):
    """T7: the decoded notification policy; the ranking and the subject's package exact, the other root sections
    illustrative (`example-root-section` stands in for the real zen, listener and snooze sections). At the fresh
    baseline the subject's package is absent (PACKAGE True: present without children, the second legal form)."""
    _, _, state, _ = STAGE_STATE[stage]
    preference = state if preference is None else preference
    if preference == 'absent':
        own = '' if not package else (f'    <package name="{PACKAGE}" show_badge="true" app_user_locked_fields="0" '
                                      'sent_invalid_msg="false" sent_valid_msg="false" user_demote_msg_app="false" '
                                      f'sent_valid_bubble="false" uid="{uid}" />\n')
    else:
        channel = {'retained': RETAINED_CHANNEL, 'created': CREATED_CHANNEL, 'reset': CREATED_CHANNEL,
                   'old-shell': RETAINED_CHANNEL.replace(' locked="256"', '')}[preference]
        own = (f'    <package name="{PACKAGE}" show_badge="true" app_user_locked_fields="0" sent_invalid_msg="false" '
               'sent_valid_msg="false" user_demote_msg_app="false" sent_valid_bubble="false" '
               f'uid="{uid}">\n      {channel}\n    </package>\n')
    return ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<notification-policy version=\"1\">\n"
            '  <example-root-section />\n'
            f'  <ranking version="4" last_bubbles_version_upgrade="{sdk}">\n'
            '    <package name="app.example.other" show_badge="true" app_user_locked_fields="0" sent_invalid_msg="false" '
            'sent_valid_msg="false" user_demote_msg_app="false" sent_valid_bubble="false" uid="10035" />\n'
            + own + '  </ranking>\n</notification-policy>\n').encode()


def job_xml(version='1'):
    """T8: the subject's job file, exact (attribute order as JobStore writes it, the source check, section 8)."""
    return ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
            f'<job-info version="{version}">\n'
            f'  <job jobid="{JOB_ID}" package="{PACKAGE}" class="{SERVICE}" sourcePackageName="{PACKAGE}" sourceUserId="0" '
            f'uid="{UID}" bias="0" priority="300" flags="0" lastSuccessfulRunTime="0" lastFailedRunTime="0" '
            'cumulativeExecutionTime="0">\n    <constraints />\n'
            f'    <one-off delay="{DUE}" />\n    <extras>\n'
            f'      <string name="andrix.b2.setup">{CONTRACT["setup"]}</string>\n'
            '      <string name="andrix.b2.contract_sha256">' + CONTRACT['contract_sha256'] + '</string>\n'
            '    </extras>\n  </job>\n</job-info>\n').encode()


def other_job_files(version='1'):
    """T8: the four other primary job files and their ten jobs, legal in their variety (negative and large IDs,
    namespaces, a source tag, periodic and deadline timing, constraints and typed extras); content illustrative. Version
    22 (the source check's B2): every stored job has its extras element, empty where it has none (JobStore always writes it, and its
    reader drops a job without it), and each ordinary periodic job its finite deadline beside its delay."""
    files = {}
    for name, jobid, package, cls, namespace, tag, source, calling, timing, constraints, _ in OTHER_JOBS:
        attrs = f'jobid="{jobid}" package="{package}" class="{cls}" sourcePackageName="{source}"'
        attrs += '' if namespace is None else f' namespace="{namespace}"'
        attrs += '' if tag is None else f' sourceTag="{tag}"'
        attrs += (f' sourceUserId="0" uid="{FILE_UIDS[name]}" bias="0" priority="300" flags="0" '
                  'lastSuccessfulRunTime="0" lastFailedRunTime="0" cumulativeExecutionTime="0"')
        cons = ''.join(f' {k}="{v}"' for k, v in constraints.items())
        body = {'one-off': '    <one-off delay="1800000000000" />\n    <extras />\n',
                'periodic': ('    <periodic period="86400000" flex="86400000" deadline="1800086400000" delay="1800000000000" />\n'
                             '    <extras />\n'),
                'deadline': '    <one-off deadline="1800000600000" delay="1800000000000" />\n    <extras />\n',
                'extras': ('    <one-off delay="1800000000000" />\n    <extras>\n      <int name="count" value="3" />\n'
                           '      <string name="label">reminder</string>\n    </extras>\n'),
                'clamped': ('    <periodic period="86400000" flex="86400000" deadline="9000000000000" delay="1800000000000" />\n'
                            '    <extras />\n')}[timing]
        files.setdefault(name, []).append(f'  <job {attrs}>\n    <constraints{cons} />\n' + body + '  </job>\n')
    return {name: ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
                   f'<job-info version="{version}">\n' + ''.join(jobs) + '</job-info>\n').encode()
            for name, jobs in files.items()}
