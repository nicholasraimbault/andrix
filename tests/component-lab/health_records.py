# SPDX-License-Identifier: Apache-2.0
"""The health package's side metadata codec: the exact forms of the records the health
composition, its baselines and its setup actions keep beside the deployment records.

Every form here is a canonical side value (lab_evidence.py) or a ledger record of exact keys. A
check returns why a value is not of its form, or None; nothing is repaired or defaulted. These
are the forms:

- a UI state reading, the parse of one whole UiStateRead reply for one user;
- a SystemUI process identity, one user's genuine main process as full_users.py joins it;
- a health baseline's facts, one user's process, history and current error baseline;
- an identity baseline's projection, each user's expected SystemUI identity read while the factory
  copy is active, which a later read never redefines;
- a preparation's result, the record a health preparation keeps of the capture conditions and
  the credential unlock that bits 2 and 3 judge;
- the setup records of USER_PIN and CE_SENTINEL: their intent before any effect, and the
  settlement a readback proves.

A form says what a record holds. It proves nothing about the guest by itself."""
import re

import full_users
import lab_actions
import lab_evidence

HEX16 = re.compile(r'[0-9a-f]{32}')
HEX32 = re.compile(r'[0-9a-f]{64}')
SYSTEMUI = full_users.SYSTEMUI
COMM = full_users.COMM
PER_USER_RANGE = full_users.PER_USER_RANGE
# The questions the fixed UI state helper answers, in its order (tests/ui-state-read).
UI_STATE_CAPABILITIES = ('interactive', 'keyguard_locked', 'keyguard_secure', 'device_locked', 'device_secure',
                         'ce_unlocked')
UI_STATE_KEYS = ('user', 'values', 'unavailable', 'complete')
UNAVAILABLE = re.compile(r'service-absent|not-boolean|unknown|[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*')
PROCESS_FIELDS = full_users.PROCESS_FIELDS
STATES = lab_actions.USER_STATES
BASELINE_FACTS = 'andrix-health-baseline-facts-v1'
BASELINE_KEYS = ('schema', 'user', 'serial', 'state', 'app_id', 'uid', 'process', 'absent', 'history',
                 'current_errors', 'complete')
WITNESS_PARTS = ('history', 'current_errors')
IDENTITY_KEYS = ('user', 'serial', 'uid', 'app_id', 'context', 'name', 'comm')
IDENTITY_PROJECTION_KEYS = ('qualified', 'why_not', 'active', 'identities')
PREPARATION_RESULT = 'andrix-health-preparation-result-v1'
PREPARATION_KEYS = ('schema', 'user', 'serial', 'criteria')
UI_CAPTURE_KEYS = ('path', 'acknowledged', 'before', 'after')
UNLOCK_KEYS = ('route', 'before', 'after')
CONDITION_KEYS = ('current_user', 'ui_state')
UNLOCK_CONDITION_KEYS = ('current_user', 'state', 'ui_state')
UNLOCK_ROUTES = ('CREDENTIAL_UI',)
# The UI capture's fresh hierarchy path: one file named by its preparation's operation, never a
# path an earlier capture used.
HIERARCHY = re.compile(r'/data/local/tmp/andrix-d5/health/hierarchy-([0-9a-f]{32})\.xml')
# The setup records of USER_PIN and CE_SENTINEL in the `user-setup` ledger kind, beside full user
# setup's CREATED and IDENTIFIED. Each names the ledger entries a reopening checks it against.
SETUP_RECORDS = {
    'PIN_INTENT': ('record', 'action_id', 'begin', 'user', 'serial', 'digits', 'private', 'readback', 'wall_ns'),
    'PIN_SET': ('record', 'action_id', 'begin', 'intent', 'user', 'serial', 'capture', 'readback', 'wall_ns'),
    'SENTINEL_INTENT': ('record', 'action_id', 'begin', 'user', 'serial', 'package', 'nonce', 'readback', 'wall_ns'),
    'SENTINEL_SET': ('record', 'action_id', 'begin', 'intent', 'user', 'serial', 'nonce', 'readback', 'wall_ns'),
}
PRIVATE_NAME = re.compile(r'pin-[0-9a-f]{32}')
PIN_DIGITS = lab_actions.PIN_DIGITS


def _int(value, low=0, high=(1 << 63) - 1):
    return type(value) is int and low <= value <= high


def _side(value):
    try:
        lab_evidence.canonical({'value': value})
        return True
    except lab_evidence.SideError:
        return False


def ui_state_problem(reading, user=None):
    """Why a parsed UI state reading is not of its exact form, or None. Each value is a boolean,
    or None with its reason when the helper reported the call unavailable; complete exactly when
    no value is None."""
    if not isinstance(reading, dict) or set(reading) != set(UI_STATE_KEYS):
        return 'a UI state reading has exactly its keys'
    if not _int(reading['user'], 0, full_users.MAX_USER_ID) or (user is not None and reading['user'] != user):
        return 'a UI state reading of another user or of no user'
    values, missing = reading['values'], reading['unavailable']
    if not isinstance(values, dict) or set(values) != set(UI_STATE_CAPABILITIES):
        return 'a UI state reading names every capability once'
    if any(v is not None and type(v) is not bool for v in values.values()):
        return 'a UI state value is a boolean or unavailable'
    if not isinstance(missing, dict) or set(missing) != {k for k, v in values.items() if v is None}:
        return 'an unavailable UI state value names its reason, and only an unavailable one'
    if any(not isinstance(r, str) or not UNAVAILABLE.fullmatch(r) for r in missing.values()):
        return 'an unavailable reason of no known form'
    if reading['complete'] is not (not missing):
        return 'a UI state reading is complete exactly when every value is a boolean'
    return None


def process_problem(process, user=None, uid=None):
    """Why a joined process is not one genuine main SystemUI process of its user's package UID."""
    if not isinstance(process, dict) or set(process) != set(PROCESS_FIELDS):
        return 'a process has exactly its fields'
    if not _int(process['pid'], 1, 9_999_999) or not _int(process['start_ticks']) or not _int(process['uid']):
        return 'a process names its PID, start ticks and UID'
    if process['uids'] != [process['uid']] * 4 or (uid is not None and process['uid'] != uid):
        return "a process runs with its user's package UID in all four status fields"
    if user is not None and process['uid'] // PER_USER_RANGE != user:
        return 'a process of another user'
    if (process['name'], process['comm']) != (SYSTEMUI, COMM):
        return 'a process is not named as the main SystemUI process'
    if not isinstance(process['context'], str) or not re.fullmatch(r'u:r:[a-z0-9_]+:s0(?::c[0-9]+,c[0-9]+'
                                                                   r'(?:,c[0-9]+,c[0-9]+)?)?', process['context']):
        return 'a process context of no known form'
    return None


def witness_part_problem(part):
    """A baseline's history or current error part: NOT_ADMITTED until the witness reader of
    section 5.4 is admitted, or OK with that reader's schema and its whole reading."""
    if part == {'status': 'NOT_ADMITTED'}:
        return None
    if (not isinstance(part, dict) or set(part) != {'status', 'schema', 'reading'} or part['status'] != 'OK'
            or not isinstance(part['schema'], str) or not re.fullmatch(r'andrix-[a-z0-9-]{1,64}', part['schema'])
            or not _side(part['reading'])):
        return 'a witness part is NOT_ADMITTED, or OK with its schema and a whole side reading'
    return None


def baseline_facts_problem(facts, user, serial):
    """Why one user's baseline facts are not of their exact form, or None. A baseline is complete
    only with the user's genuine main process present and both witness parts read whole."""
    if not isinstance(facts, dict) or set(facts) != set(BASELINE_KEYS) or facts['schema'] != BASELINE_FACTS:
        return 'baseline facts have exactly their keys and schema'
    if (facts['user'], facts['serial']) != (user, serial):
        return 'baseline facts of another user or serial'
    if facts['state'] not in STATES or type(facts['absent']) is not bool or type(facts['complete']) is not bool:
        return 'baseline facts name the state, whether no SystemUI process ran, and completeness'
    if facts['app_id'] is not None and not _int(facts['app_id'], 1, PER_USER_RANGE - 1):
        return 'a baseline app ID of no known form'
    if facts['uid'] is not None and (not _int(facts['uid']) or facts['app_id'] is None
                                     or facts['uid'] != user * PER_USER_RANGE + facts['app_id']):
        return "a baseline UID that is not the user's package UID"
    if facts['process'] is not None:
        why = process_problem(facts['process'], user, facts['uid'])
        if why is not None or facts['absent']:
            return why or 'a process joined although pidof found none'
    for name in WITNESS_PARTS:
        why = witness_part_problem(facts[name])
        if why is not None:
            return why
    complete = (facts['process'] is not None and facts['state'] in lab_actions.RUNNING
                and all(facts[name]['status'] == 'OK' for name in WITNESS_PARTS))
    if facts['complete'] is not complete:
        return 'a baseline is complete exactly with its process and both witness parts'
    return None


def identity_problem(identity):
    """Why an expected identity is not one user's genuine main SystemUI identity, or None."""
    if not isinstance(identity, dict) or set(identity) != set(IDENTITY_KEYS):
        return 'an identity has exactly its keys'
    if not _int(identity['user'], 0, full_users.MAX_USER_ID) or not _int(identity['serial']):
        return 'an identity names its user and serial'
    if not _int(identity['app_id'], 1, PER_USER_RANGE - 1) or identity['uid'] != (
            identity['user'] * PER_USER_RANGE + identity['app_id']):
        return "an identity's UID is its user's UID of its app ID"
    if (identity['name'], identity['comm']) != (SYSTEMUI, COMM):
        return 'an identity names the main SystemUI process'
    process = {'pid': 1, 'start_ticks': 0, 'uid': identity['uid'], 'uids': [identity['uid']] * 4,
               'name': identity['name'], 'comm': identity['comm'], 'context': identity['context']}
    return process_problem(process, identity['user'], identity['uid'])


def identity_projection_problem(projection):
    """Why an identity baseline's projection is not of its exact form, or None."""
    if not isinstance(projection, dict) or set(projection) != set(IDENTITY_PROJECTION_KEYS):
        return 'an identity baseline has exactly its keys'
    if type(projection['qualified']) is not bool or (projection['qualified'] == (projection['why_not'] is not None)):
        return 'an identity baseline is qualified exactly without a reason'
    if projection['why_not'] is not None and (not isinstance(projection['why_not'], str)
                                              or not _side(projection['why_not'])):
        return 'a reason of no known form'
    active = projection['active']
    if active is not None and (not isinstance(active, dict) or set(active) != {'apk', 'factory_apk', 'uid', 'context'}
                               or not all(isinstance(active[k], str) and HEX32.fullmatch(active[k])
                                          for k in ('apk', 'factory_apk'))
                               or not _int(active['uid']) or not isinstance(active['context'], str)):
        return 'the active copy of an identity baseline of no known form'
    identities = projection['identities']
    if not isinstance(identities, list):
        return 'identities are a list'
    serials = set()
    for identity in identities:
        why = identity_problem(identity)
        if why is not None:
            return why
        if identity['serial'] in serials:
            return 'a serial identified twice'
        serials.add(identity['serial'])
    if projection['qualified'] and (active is None or not identities):
        return 'a qualified identity baseline names the factory copy active and at least one identity'
    return None


def _condition_problem(condition, user, keys):
    if not isinstance(condition, dict) or set(condition) != set(keys):
        return 'a condition has exactly its keys'
    if not _int(condition['current_user'], 0, full_users.MAX_USER_ID):
        return 'a condition names the current user'
    if 'state' in keys and condition['state'] not in STATES:
        return 'a condition names the user state'
    return ui_state_problem(condition['ui_state'], user)


def preparation_problem(result, user, serial, criteria, operation):
    """Why a health preparation's result is not of its exact form for one user and its criteria,
    or None. The result names each prepared criterion's part: the UI capture (2) with its fresh
    hierarchy path, named by the operation, and the capture conditions read before and after it;
    the credential unlock (3) with its route and the conditions before and after it. The native
    work part (5) is the work fixture's own form, a later package's, kept whole."""
    if not isinstance(result, dict) or set(result) != set(PREPARATION_KEYS) or result['schema'] != PREPARATION_RESULT:
        return 'a preparation result has exactly its keys and schema'
    if (result['user'], result['serial']) != (user, serial):
        return 'a preparation result of another user or serial'
    parts = result['criteria']
    if not isinstance(parts, dict) or not set(parts) <= {str(c) for c in criteria} or not parts:
        return 'a preparation result names only criteria its preparation served'
    capture = parts.get('2')
    if capture is not None:
        if not isinstance(capture, dict) or set(capture) != set(UI_CAPTURE_KEYS):
            return 'a UI capture has exactly its keys'
        match = HIERARCHY.fullmatch(capture['path']) if isinstance(capture['path'], str) else None
        if match is None or match[1] != operation or type(capture['acknowledged']) is not bool:
            return "a UI capture names its operation's fresh hierarchy path and whether the dump acknowledged it"
        for name in ('before', 'after'):
            why = _condition_problem(capture[name], user, CONDITION_KEYS)
            if why is not None:
                return why
    unlock = parts.get('3')
    if unlock is not None:
        if not isinstance(unlock, dict) or set(unlock) != set(UNLOCK_KEYS) or unlock['route'] not in UNLOCK_ROUTES:
            return 'a credential unlock has exactly its keys and route'
        for name in ('before', 'after'):
            why = _condition_problem(unlock[name], user, UNLOCK_CONDITION_KEYS)
            if why is not None:
                return why
    work = parts.get('5')
    if work is not None and (not isinstance(work, dict) or not isinstance(work.get('schema'), str) or not _side(work)):
        return "a native work part is the work fixture's own schema, whole"
    return _side_problem(result)


def _side_problem(value):
    return None if _side(value) else 'a value no side record can hold'


def setup_problem(record):
    """Why a USER_PIN or CE_SENTINEL setup record is not of its exact form, or None."""
    keys = SETUP_RECORDS.get(record.get('record')) if isinstance(record, dict) else None
    if keys is None or set(record) - {'number', 'kind'} != set(keys):
        return 'a health setup record of no known form'
    if not isinstance(record['action_id'], str) or not HEX16.fullmatch(record['action_id']):
        return 'a health setup record names its action'
    for name in ('begin', 'intent', 'capture', 'readback'):
        if name in record and not _int(record[name], 1):
            return 'a health setup record names its ledger entries'
    if not _int(record['user'], 0, full_users.MAX_USER_ID) or not _int(record['serial']) or type(
            record['wall_ns']) is not int:
        return 'a health setup record names a user, its serial and its time'
    if 'digits' in record and not _int(record['digits'], *PIN_DIGITS):
        return 'a PIN has %d to %d digits' % PIN_DIGITS
    if 'private' in record and (not isinstance(record['private'], str) or not PRIVATE_NAME.fullmatch(record['private'])):
        return 'a PIN intent names its private record by a fresh name, never by the PIN'
    if 'nonce' in record and (not isinstance(record['nonce'], str) or not HEX16.fullmatch(record['nonce'])
                              or record['nonce'] == '00' * 16):
        return 'a CE sentinel names its nonzero nonce'
    if 'package' in record and (not isinstance(record['package'], str) or not lab_actions.PACKAGE.fullmatch(
            record['package']) or record['package'] == SYSTEMUI):
        return 'a CE sentinel names its ordinary fixture package'
    return None
