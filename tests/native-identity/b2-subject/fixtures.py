# SPDX-License-Identifier: Apache-2.0
"""Synthetic source derived forms for host tests. These are not Android captures."""
import json
from protocol import CHANNEL, JOB_ID, NOTIFICATION_SETUP, PACKAGE, SERVICE, make_contract
from observations import CHANNEL_FIELDS

CONTRACT = make_contract(10123, 0, '1' * 32, '2' * 32, '3' * 32)
UID = CONTRACT['uid']
NONCE = '4' * 32
GUEST = '5' * 64
DUE = 1800000000000


def capture(argv, text, code=0, stderr=''):
    return {'argv': argv, 'stdout': text, 'stderr': stderr, 'exit_code': code, 'complete': True}


def permission_text(initialized=True):
    flags = '[RUNTIME_GRANTED|USER_SET]' if initialized else '[]'
    grant = 'true' if initialized else 'false'
    return (f'App ID: {UID}\n  User: 0\n    Permissions:\n'
            f'      android.permission.POST_NOTIFICATIONS: granted={grant}, flags={flags}\n'
            '      android.permission.VIBRATE: granted=true, flags=[INSTALL_GRANTED]\n'
            '    App ops:\n    Package: ' + PACKAGE + '\n      version=15\n      App ops:\n'
            + ('        android:vibrate: mode=ignore\n' if initialized else ''))


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


def notification_text(initialized=True, preference='retained'):
    return ('Notification manager state:\n\n Notification Preferences:\n'
            '    per-package config version: 4\nPackagePreferences:\n'
            + (f'      AppSettings: {PACKAGE} ({UID}) importance=DEFAULT userSet=true\n'
               + '        ' + channel_text(preference) + '\n' if initialized else '')
            + 'Restored without uid:\n\n  Notification listeners:\n'
            + '    mListenerHints: 0\n')


def job_text(admitted=True, parcelled=True):
    comp = str(admitted).lower()
    extras = 'mParcelledData.dataSize=248' if parcelled else (
        '{andrix.b2.setup=' + CONTRACT['setup'] + ', andrix.b2.contract_sha256='
        + CONTRACT['contract_sha256'] + '}')
    return (f'JobScheduler:\nStarted users: [0]\nRegistered 1 jobs:\n'
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
            '    Required constraints: TIMING_DELAY [0x80000000]\n'
            '    Dynamic constraints:\n'
            '    Satisfied constraints: DEVICE_NOT_DOZING BACKGROUND_NOT_RESTRICTED WITHIN_QUOTA '
            '[0x3400000]\n'
            '    Unsatisfied constraints: TIMING_DELAY [0x80000000]\n'
            '    Constraint history:\n'
            '      -1s0ms = DEVICE_NOT_DOZING [0x2000000]\n'
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
            'Active jobs:\n  None\nRecently completed jobs:\n  None\n')


def access_xml(initialized=True):
    return (f'<access><package-versions><package name="{PACKAGE}" version="15"/>'
            '</package-versions><app-id-permissions><app-id id="10123">'
            '<permission name="android.permission.POST_NOTIFICATIONS" flags="'
            + ('48' if initialized else '0') + '"/></app-id></app-id-permissions>'
            '<app-id-app-ops/><package-app-ops>' + (f'<package name="{PACKAGE}">'
            '<app-op name="android:vibrate" mode="1"/></package>' if initialized else '')
            + '</package-app-ops></access>').encode()


def notification_setup_ack():
    value = {'version': 1, 'operation': NOTIFICATION_SETUP, 'package': PACKAGE, 'uid': UID,
             'user': 0, 'channel': CHANNEL, 'process_uid': 2000, 'nonce': NONCE,
             'setup': CONTRACT['setup'], 'contract_sha256': CONTRACT['contract_sha256'],
             'stage': 'update_returned', 'setter_calls': 1, 'state_proven': False}
    return 'ANDRIX_B2_NOTIFICATION_SETUP: ' + json.dumps(value) + '\n'


def notification_xml(initialized=True, preference='retained'):
    channel = (f'<channel id="{CHANNEL}" name="Andrix B2 state" importance="2" '
               'locked="256" show_badge="true" allow_bubbles="1" orig_imp="2" '
               'usage="5" content_type="4" flags="0"/>')
    if preference == 'old-shell':
        channel = channel.replace(' locked="256"', '')
    elif preference in ('created', 'reset'):
        channel = channel.replace(' locked="256"', '').replace(' allow_bubbles="1"', '')
    elif preference != 'retained':
        raise ValueError('synthetic preference state')
    return (f'<notification-policy version="1"><ranking version="4" '
            'last_bubbles_version_upgrade="37">'
            f'<package name="{PACKAGE}" uid="{UID}" show_badge="true" '
            'app_user_locked_fields="0" sent_invalid_msg="false" sent_valid_msg="false" '
            'user_demote_msg_app="false" sent_valid_bubble="false">'
            + (channel if initialized else '')
            + '</package></ranking></notification-policy>').encode()


def job_xml():
    return (f'<job-info version="1"><job jobid="{JOB_ID}" uid="{UID}" '
            f'package="{PACKAGE}" class="{SERVICE}" sourcePackageName="{PACKAGE}" '
            'sourceUserId="0" bias="0" priority="300" flags="0" '
            'lastSuccessfulRunTime="0" lastFailedRunTime="0" cumulativeExecutionTime="0">'
            f'<constraints/><one-off delay="{DUE}"/><extras>'
            f'<string name="andrix.b2.setup">{CONTRACT["setup"]}</string>'
            '<string name="andrix.b2.contract_sha256">' + CONTRACT['contract_sha256']
            + '</string></extras></job></job-info>').encode()
