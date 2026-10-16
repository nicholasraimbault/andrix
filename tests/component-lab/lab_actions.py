# SPDX-License-Identifier: Apache-2.0
"""Typed lab actions of the next campaign profile: their registry, the exact action specs that a
version 3 admission binds, and how an action's user is resolved from a whole typed user inventory.

An action is never a command. A spec names one registered type, its phase and cell, its authority,
its user selector, typed parameters, pinned inputs, the preconditions of its type, the action it
must follow and the actions that may follow it, its uses and its bounds. The broker reconstructs
every command itself: a type's fixed command, or the fixed commands of the admitted adapter of its
family, each checked against that adapter's allowlist. Lab authority is LAB_USER_ADMIN or
LAB_CONTROL. No installation grant, no ACTIVATE and no caller text acquires either.

A user is resolved immediately before a use from a whole typed inventory that the broker reads and
records: the observed system user, the user that one named create action made, or a required
recipient of the stored ticket's issued notice. An inventory that is not whole, a user that is
being removed, partial or precreated, another type or another serial resolves nothing. Nothing is
guessed: no current user and no user ID that the inventory did not show.

The registry has thirteen types. NOTICE_VISIBILITY captures and reads the current visibility of an
issued notice for one required recipient, through the notice adapter. HEALTH_PREPARATION runs the
UI, user and work steps that a full health probe of one user needs, through the health adapter,
under a fresh preparation ID and challenge. PLAIN_KERNEL_CONFIRM is a plain kernel reboot that
confirms a ticket's wait in a later boot: its preflight proves from a whole global session
inventory that no armed or unknown session could activate, and it settles on a new boot ID, a
completed boot and a committed checkpoint. DIRECT_STAGE, DIRECT_COMMIT and NEGATIVE_ACTIVATION
are the steps of one admitted direct negative control, N2 or N3: a staged session of its pinned
negative payload under its own referrer, its commit after explicit per control consent, and its
activating reboot, which settles only on the intended rejection and a safe recovery. They are the
only native commits before F0, and only in their admitted order.

FRAMEWORK_RESTART, version 2's `am restart`, is withdrawn from this profile: a spec naming it is
refused by name.

The seven user setup types are the lab's own user administration, under LAB_USER_ADMIN, with the
fixed commands and reply forms of full_users.py and health_records.py. USER_CREATE creates the one
full secondary user: one spec, used once, the only creating type, so a CREATED_BY selector names
it. USER_START starts that user in the background, USER_SWITCH brings a user to the foreground,
USER_SETUP drives the image's own setup with admitted key and tap steps and settles only on the
setup that Android records, and USER_FIXTURE installs an admitted ordinary fixture, already
installed for the system user with its pinned bytes, for the created user and enables it.
USER_PIN sets a disposable lab PIN that the broker generates itself, through `locksettings` and
private standard input, so the PIN never enters a command, a capture or the ledger; it never
replaces a credential. CE_SENTINEL has the work fixture keep a fresh nonce in its own CE storage
and settles on reading that nonce back: the origin that bit 3 compares the fixture's CE storage
with after an unlock. None stops or removes a user or writes to the settings provider."""
import re

import lab_evidence

# The next campaign profile, as the admission and the bridge configuration name it.
PROFILE = 'd5-next-vehicle-1'
# CELLS is the carried G1a cells' phase: the cohort refusal and the five preactivation attempts.
PHASES = ('ENTRY', 'CELLS', 'N1', 'N2', 'N3', 'F0', 'A', 'R', 'FINAL')
AUTHORITIES = ('LAB_USER_ADMIN', 'LAB_CONTROL')
SELECTORS = ('SYSTEM_USER', 'CREATED_BY', 'NOTICE_RECIPIENT')
EFFECT_CLASSES = ('direct', 'admin', 'fixture', 'control')
SPEC_KEYS = ('id', 'type', 'phase', 'cell', 'runtime', 'installation', 'authority', 'user_selector', 'parameters',
             'inputs', 'preconditions', 'predecessor', 'successors', 'max_uses', 'timeout_ms', 'stdout_max',
             'stderr_max')
MAX_SPECS = 64
MAX_USES = 100
MAX_TIMEOUT_MS = 3_600_000
MAX_STDOUT = 64 << 20
MAX_STDERR = 1 << 20
MAX_EFFECTS = 10_000
CELL = re.compile(r'[a-z0-9][a-z0-9-]{0,63}')
HEX16 = re.compile(r'[0-9a-f]{32}')
HEX32 = re.compile(r'[0-9a-f]{64}')
# Criteria a preparation may serve: the UI marker, unlock with CE return, and ordinary native work.
PREPARED_CRITERIA = (2, 3, 5)
# Each registered type: its authority, the selectors it admits, its parameters and their kinds, its
# pinned inputs, the effect class its effect commands count against, its preconditions, whether a
# use may follow a use whose effect stayed uncertain (only an idempotent capture and read), the
# adapter of its family, and the phase its specs belong to (None: any).
TYPES = {
    'NOTICE_VISIBILITY': {'authority': 'LAB_CONTROL', 'selectors': ('NOTICE_RECIPIENT',), 'parameters': {},
                          'inputs': 'none', 'effect': 'fixture', 'preconditions': ['NOTICE_ISSUED'],
                          'after_uncertain': True, 'adapter': 'notice', 'phase': None},
    'HEALTH_PREPARATION': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER', 'CREATED_BY'),
                           'parameters': {'criteria': 'criteria', 'max_probe_ms': 'milliseconds'}, 'inputs': 'none',
                           'effect': 'fixture', 'preconditions': [], 'after_uncertain': False, 'adapter': 'health',
                           'phase': None},
    'PLAIN_KERNEL_CONFIRM': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER',), 'parameters': {},
                             'inputs': 'none', 'effect': 'control',
                             'preconditions': ['ISSUING_TICKET_WAITS', 'CHECKPOINT_RECORDED', 'WITHIN_BOOT_LIMIT',
                                               'WHOLE_GLOBAL_SESSIONS', 'NO_ARMED_SESSION', 'CHECKPOINT_COMMITTED',
                                               'TARGET_ESTABLISHED'],
                             'after_uncertain': False, 'adapter': None, 'phase': 'CELLS'},
    'DIRECT_STAGE': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER',),
                     'parameters': {'control': 'id', 'role': 'role'}, 'inputs': 'payload', 'effect': 'direct',
                     'preconditions': ['BEFORE_F0', 'PAYLOAD_PINNED', 'NO_LIVE_SESSION', 'CHECKPOINT_COMMITTED'],
                     'after_uncertain': False, 'adapter': None, 'phase': 'role'},
    'DIRECT_COMMIT': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER',),
                      'parameters': {'control': 'id', 'role': 'role'}, 'inputs': 'none', 'effect': 'direct',
                      'preconditions': ['BEFORE_F0', 'CONSENT', 'OWN_SESSION_OPEN', 'FACTORY_ACTIVE',
                                        'CHECKPOINT_COMMITTED'],
                      'after_uncertain': False, 'adapter': None, 'phase': 'role'},
    'NEGATIVE_ACTIVATION': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER',),
                            'parameters': {'control': 'id', 'role': 'role'}, 'inputs': 'none', 'effect': 'direct',
                            'preconditions': ['BEFORE_F0', 'CONSENT', 'OWN_SESSION_READY', 'NO_OTHER_ARMED_SESSION',
                                              'CHECKPOINT_COMMITTED'],
                            'after_uncertain': False, 'adapter': None, 'phase': 'role'},
    'USER_CREATE': {'authority': 'LAB_USER_ADMIN', 'selectors': ('SYSTEM_USER',),
                    'parameters': {'user_type': 'user_type', 'name': 'user_name'}, 'inputs': 'none', 'effect': 'admin',
                    'preconditions': ['WHOLE_USER_INVENTORY', 'ONLY_SYSTEM_USER', 'MULTIPLE_USERS_SUPPORTED',
                                      'CREATOR_UNRESTRICTED', 'BELOW_USER_MAXIMUM'],
                    'after_uncertain': False, 'adapter': None, 'phase': 'F0'},
    'USER_START': {'authority': 'LAB_USER_ADMIN', 'selectors': ('CREATED_BY',), 'parameters': {}, 'inputs': 'none',
                   'effect': 'admin',
                   'preconditions': ['WHOLE_USER_INVENTORY', 'CREATED_USER_STOPPED', 'BELOW_RUNNING_MAXIMUM'],
                   'after_uncertain': False, 'adapter': None, 'phase': None},
    'USER_SWITCH': {'authority': 'LAB_USER_ADMIN', 'selectors': ('CREATED_BY', 'SYSTEM_USER'), 'parameters': {},
                    'inputs': 'none', 'effect': 'admin',
                    'preconditions': ['WHOLE_USER_INVENTORY', 'TARGET_RUNNING', 'TARGET_IN_BACKGROUND',
                                      'OUTGOING_USER_KEEPS_RUNNING'],
                    'after_uncertain': False, 'adapter': None, 'phase': None},
    'USER_SETUP': {'authority': 'LAB_USER_ADMIN', 'selectors': ('CREATED_BY',),
                   'parameters': {'steps': 'ui_steps', 'settle_ms': 'milliseconds'}, 'inputs': 'none',
                   'effect': 'admin', 'preconditions': ['WHOLE_USER_INVENTORY', 'TARGET_FOREGROUND', 'TARGET_CE_UNLOCKED'],
                   'after_uncertain': False, 'adapter': None, 'phase': 'F0'},
    'USER_FIXTURE': {'authority': 'LAB_USER_ADMIN', 'selectors': ('CREATED_BY',), 'parameters': {'package': 'package'},
                     'inputs': 'fixture', 'effect': 'fixture',
                     'preconditions': ['WHOLE_USER_INVENTORY', 'FIXTURE_INSTALLED_FOR_SYSTEM_USER', 'PINNED_BYTES'],
                     'after_uncertain': False, 'adapter': None, 'phase': 'F0'},
    'USER_PIN': {'authority': 'LAB_USER_ADMIN', 'selectors': ('CREATED_BY', 'SYSTEM_USER'),
                 'parameters': {'digits': 'pin_digits'}, 'inputs': 'none', 'effect': 'admin',
                 'preconditions': ['WHOLE_USER_INVENTORY', 'TARGET_CE_UNLOCKED', 'UI_STATE_ADMITTED',
                                   'NO_SECURE_CREDENTIAL', 'NO_EARLIER_PIN', 'PRIVATE_STORE'],
                 'after_uncertain': False, 'adapter': None, 'phase': 'F0'},
    'CE_SENTINEL': {'authority': 'LAB_USER_ADMIN', 'selectors': ('CREATED_BY', 'SYSTEM_USER'),
                    'parameters': {'package': 'package'}, 'inputs': 'none', 'effect': 'fixture',
                    'preconditions': ['WHOLE_USER_INVENTORY', 'TARGET_CE_UNLOCKED', 'UI_STATE_ADMITTED',
                                      'NO_EARLIER_SENTINEL'],
                    'after_uncertain': False, 'adapter': 'work', 'phase': 'F0'},
}
# The full user setup types, in the order of a user's setup, which read the full user forms
# instead of the global sessions. The last two end the sequence: the disposable lab PIN, and the
# CE sentinel the fixture keeps in CE storage.
USER_TYPES = ('USER_CREATE', 'USER_START', 'USER_SWITCH', 'USER_SETUP', 'USER_FIXTURE', 'USER_PIN', 'CE_SENTINEL')
USER_SEQUENCE = USER_TYPES
# Types this profile names only to refuse them: the shell framework restart is not admitted.
WITHDRAWN = ('FRAMEWORK_RESTART',)
# The steps of one direct negative control, in order.
DIRECT_STEPS = ('DIRECT_STAGE', 'DIRECT_COMMIT', 'NEGATIVE_ACTIVATION')
# The direct negative roles, in their admitted order, each with its payload's members and the
# rejection cause its activation must end in.
ROLES = ('N2', 'N3')
ROLE_MEMBERS = {'N2': ('base.apk', 'base.apk.idsig'), 'N3': ('base.apk',)}
ROLE_CAUSES = {'N2': 'SIGNATURE', 'N3': 'FS_VERITY'}
CONTROL_REFERRER = 'andrix-lab-control:'
# Types whose records name the user they created: the one full secondary user's create.
CREATING_TYPES = ('USER_CREATE',)
# An admitted user name: no space or shell syntax, so it is one argument of the fixed create.
USER_NAME = re.compile(r'[A-Za-z][A-Za-z0-9]{0,31}')
# Setup steps are admitted key events and taps only: never typed text, so no credential or other
# text can enter a capture through them.
UI_KEYS = ('KEYCODE_WAKEUP', 'KEYCODE_ENTER', 'KEYCODE_TAB', 'KEYCODE_SPACE', 'KEYCODE_DPAD_UP', 'KEYCODE_DPAD_DOWN',
           'KEYCODE_DPAD_LEFT', 'KEYCODE_DPAD_RIGHT', 'KEYCODE_DPAD_CENTER', 'KEYCODE_PAGE_UP', 'KEYCODE_PAGE_DOWN',
           'KEYCODE_MOVE_HOME', 'KEYCODE_MOVE_END')
MAX_STEPS = 32
MAX_TAP = 10000
# A disposable lab PIN's length: at least the six digits of LockPatternUtils.
# MIN_AUTO_PIN_REQUIREMENT_LENGTH (core/java/com/android/internal/widget/LockPatternUtils.java:137).
PIN_DIGITS = (6, 16)
BOOT_POLICY_KEYS = ('activation_services', 'confirmation_services', 'observed_boots', 'poll_interval_ms',
                    'settle_ms', 'negative_settle_ms', 'unexpected_boot')
BRANCHES = ('FULL', 'LIMITED', 'REFUSED')
# The typed user inventory's states and the full user types the profile resolves.
USER_STATES = ('RUNNING_UNLOCKED', 'RUNNING_LOCKED', 'NOT_RUNNING')
RUNNING = ('RUNNING_UNLOCKED', 'RUNNING_LOCKED')
SYSTEM_TYPE = 'android.os.usertype.full.SYSTEM'
SECONDARY_TYPE = 'android.os.usertype.full.SECONDARY'
USER_TYPE = re.compile(r'android\.os\.usertype\.[a-z]+\.[A-Z_]+')
INVENTORY_KEYS = ('whole', 'current_user', 'users')
USER_KEYS = ('id', 'serial', 'type', 'state', 'flags', 'restrictions', 'parent', 'removing', 'partial', 'precreated')
NO_USER = -10000


class AdmissionError(ValueError):
    """A version 3 admission part of no exact form."""


def _fail(reason):
    raise AdmissionError(reason)


def _int(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        _fail('%s is an integer from %d to %d' % (name, low, high))


def _hex16(value, name):
    if not isinstance(value, str) or not HEX16.fullmatch(value) or value == '00' * 16:
        _fail('%s is a nonzero 16 byte ID' % name)


def _hex32(value, name):
    if not isinstance(value, str) or not HEX32.fullmatch(value) or value == '00' * 32:
        _fail('%s is a nonzero SHA-256' % name)


def check_specs(specs, installation):
    """The admitted action specs, in order, each exact. Returns them by ID."""
    if not isinstance(specs, list) or not specs or len(specs) > MAX_SPECS:
        _fail('lab actions are an ordered list of 1 to %d specs' % MAX_SPECS)
    by_id, runtime = {}, None
    for at, spec in enumerate(specs):
        if not isinstance(spec, dict) or set(spec) != set(SPEC_KEYS):
            _fail('an action spec has exactly its keys')
        _hex16(spec['id'], 'an action ID')
        if spec['id'] in by_id:
            _fail('an action ID is admitted once')
        if spec['type'] in WITHDRAWN:
            _fail('the %s action is withdrawn from this profile' % spec['type'])
        kind = TYPES.get(spec['type'])
        if kind is None:
            _fail('an action of no registered type')
        if spec['phase'] not in PHASES or not isinstance(spec['cell'], str) or not CELL.fullmatch(spec['cell']):
            _fail('an action names a known phase and a cell')
        _hex16(spec['runtime'], 'an action runtime')
        if runtime is not None and spec['runtime'] != runtime:
            _fail('every action is of one runtime')
        runtime = spec['runtime']
        if spec['installation'] != installation:
            _fail("an action of another installation than the admission's")
        if spec['authority'] != kind['authority']:
            _fail("an action's authority is its type's lab authority")
        _selector(spec['user_selector'], kind, by_id)
        _parameters(spec['parameters'], kind)
        if kind['phase'] is not None and spec['phase'] != (spec['parameters']['role'] if kind['phase'] == 'role'
                                                           else kind['phase']):
            _fail("a %s action belongs to its phase" % spec['type'])
        if kind['inputs'] == 'payload':
            _payload(spec['inputs'], spec['parameters']['role'])
        elif kind['inputs'] == 'fixture':
            _fixture(spec['inputs'])
        elif spec['inputs'] != []:
            _fail('only a direct stage and a fixture pin inputs')
        if spec['preconditions'] != kind['preconditions']:
            _fail("an action's preconditions are exactly its type's")
        if spec['predecessor'] is not None:
            if spec['predecessor'] not in by_id:
                _fail('a predecessor is an earlier admitted action')
        if not isinstance(spec['successors'], list) or len(set(spec['successors'])) != len(spec['successors']):
            _fail('successors are a list of distinct actions')
        _int(spec['max_uses'], 1, MAX_USES, 'max_uses')
        _int(spec['timeout_ms'], 1, MAX_TIMEOUT_MS, 'timeout_ms')
        _int(spec['stdout_max'], 1, MAX_STDOUT, 'stdout_max')
        _int(spec['stderr_max'], 1, MAX_STDERR, 'stderr_max')
        by_id[spec['id']] = dict(spec, order=at)
    for spec in specs:
        for successor in spec['successors']:
            if successor not in by_id or by_id[successor]['order'] <= by_id[spec['id']]['order']:
                _fail('a successor is a later admitted action')
            if by_id[successor]['predecessor'] != spec['id']:
                _fail("a successor names this action as its predecessor")
        if spec['predecessor'] is not None and spec['id'] not in by_id[spec['predecessor']]['successors']:
            _fail("a predecessor lists the action among its successors")
    creates = [s for s in by_id.values() if s['type'] in CREATING_TYPES]
    if len(creates) > 1 or any(s['max_uses'] != 1 for s in creates):
        _fail('one create action, used once: exactly one secondary user is created')
    _direct_controls(by_id)
    return {ident: {k: v for k, v in spec.items() if k != 'order'} for ident, spec in by_id.items()}


def _payload(inputs, role):
    """A direct stage's pinned negative payload: exactly its role's members, in order, each its
    SHA-256 and size. N2 is a wrong signer APK with its matching sidecar, N3 an APK and explicitly
    no sidecar."""
    members = ROLE_MEMBERS[role]
    if not isinstance(inputs, list) or [i.get('role') if isinstance(i, dict) else None for i in inputs] != list(members):
        _fail('a %s payload pins exactly %s' % (role, ', '.join(members)))
    for item in inputs:
        if set(item) != {'role', 'sha256', 'bytes'}:
            _fail('a pinned member is its role, SHA-256 and size')
        _hex32(item['sha256'], 'a pinned member digest')
        _int(item['bytes'], 1, 1 << 30, 'a pinned member size')


def _fixture(inputs):
    """A fixture's pinned bytes: exactly its base APK's SHA-256 and size."""
    if (not isinstance(inputs, list) or len(inputs) != 1 or not isinstance(inputs[0], dict)
            or set(inputs[0]) != {'role', 'sha256', 'bytes'} or inputs[0]['role'] != 'base.apk'):
        _fail('a fixture pins exactly its base.apk')
    _hex32(inputs[0]['sha256'], 'a pinned fixture digest')
    _int(inputs[0]['bytes'], 1, 1 << 30, 'a pinned fixture size')


def step_problem(step):
    """Why a setup step is not one admitted key event or one tap at a point, or None."""
    if not isinstance(step, dict) or len(step) != 1:
        return 'a setup step is one key or one tap'
    if 'key' in step:
        return None if step['key'] in UI_KEYS else 'a setup key outside the admitted keys'
    tap = step.get('tap')
    if (not isinstance(tap, list) or len(tap) != 2
            or any(type(v) is not int or not 0 <= v <= MAX_TAP for v in tap)):
        return 'a setup step is one key or one tap at a point'
    return None


def _direct_controls(by_id):
    """The admitted direct negative controls are exact: each control is one stage, one commit
    and one activation of one role, each used once, chained in that order; at most one control
    of each role; and N3 only after N2's activation."""
    controls = {}
    for spec in sorted(by_id.values(), key=lambda s: s['order']):
        if spec['type'] in DIRECT_STEPS:
            controls.setdefault(spec['parameters']['control'], []).append(spec)
    roles = {}
    for control, steps in controls.items():
        if [s['type'] for s in steps] != list(DIRECT_STEPS) or len({s['parameters']['role'] for s in steps}) != 1:
            _fail('a direct control is exactly one stage, commit and activation of one role')
        if any(s['max_uses'] != 1 for s in steps):
            _fail('each step of a direct control runs once')
        if steps[1]['predecessor'] != steps[0]['id'] or steps[2]['predecessor'] != steps[1]['id']:
            _fail("a direct control's steps follow each other")
        role = steps[0]['parameters']['role']
        if role in roles:
            _fail('one direct control of each role')
        roles[role] = steps
    for control, steps in controls.items():
        first = steps[0]['predecessor']
        if first is not None and by_id[first]['type'] in DIRECT_STEPS and steps[0]['parameters']['role'] != 'N3':
            _fail('only N3 follows another direct control')
    if 'N3' in roles and ('N2' not in roles or roles['N3'][0]['predecessor'] != roles['N2'][2]['id']):
        _fail("N3 follows N2's activation")


def _selector(selector, kind, by_id):
    if not isinstance(selector, dict) or selector.get('kind') not in kind['selectors']:
        _fail("a user selector of a kind its type admits")
    if selector['kind'] == 'CREATED_BY':
        if set(selector) != {'kind', 'action'}:
            _fail('a created user is selected by its one create action')
        creator = by_id.get(selector['action'])
        if creator is None or creator['type'] not in CREATING_TYPES:
            _fail('a created user is selected by an earlier admitted create action')
    elif set(selector) != {'kind'}:
        _fail('a selector names no user itself')


def _parameters(parameters, kind):
    if not isinstance(parameters, dict) or set(parameters) != set(kind['parameters']):
        _fail("an action's parameters are exactly its type's")
    for name, form in kind['parameters'].items():
        value = parameters[name]
        if form == 'criteria':
            if (not isinstance(value, list) or not value or value != sorted(set(value))
                    or any(type(v) is not int or v not in PREPARED_CRITERIA for v in value)):
                _fail('prepared criteria are a sorted list of distinct bits from %s' % (PREPARED_CRITERIA,))
        elif form == 'milliseconds':
            _int(value, 1, MAX_TIMEOUT_MS, name)
        elif form == 'id':
            _hex16(value, name)
        elif form == 'role':
            if value not in ROLES:
                _fail('a direct control is N2 or N3')
        elif form == 'user_type':
            if value != SECONDARY_TYPE:
                _fail('the one created user is a full secondary user, never a profile or another type')
        elif form == 'user_name':
            if not isinstance(value, str) or not USER_NAME.fullmatch(value):
                _fail('a user name of letters and digits')
        elif form == 'ui_steps':
            if not isinstance(value, list) or len(value) > MAX_STEPS or any(step_problem(s) for s in value):
                _fail('setup steps are at most %d admitted keys or taps' % MAX_STEPS)
        elif form == 'package':
            if not isinstance(value, str) or not PACKAGE.fullmatch(value) or value == 'com.android.systemui':
                _fail('a fixture is an ordinary package, never the component')
        elif form == 'pin_digits':
            _int(value, PIN_DIGITS[0], PIN_DIGITS[1], 'the PIN digits')
        else:
            raise AssertionError(form)


def check_effect_limits(value, crossings):
    """Separate caps of managed crossings by name, direct, admin, fixture and control effects,
    and of each phase's action effects. Zero forbids; nothing is unlimited."""
    if not isinstance(value, dict) or set(value) != set(EFFECT_CLASSES) | {'crossings', 'phases'}:
        _fail('effect limits name crossings, phases and each effect class')
    if not isinstance(value['crossings'], dict) or set(value['crossings']) != set(crossings):
        _fail('effect limits cap every device crossing')
    for name, cap in value['crossings'].items():
        _int(cap, 0, MAX_EFFECTS, 'the %s cap' % name)
    for name in EFFECT_CLASSES:
        _int(value[name], 0, MAX_EFFECTS, 'the %s cap' % name)
    if not isinstance(value['phases'], dict) or set(value['phases']) != set(PHASES):
        _fail('effect limits cap every phase')
    for name, cap in value['phases'].items():
        _int(cap, 0, MAX_EFFECTS, 'the %s phase cap' % name)
    return value


def check_boot_policy(value):
    """The activation and confirmation service allowances, the observed boot allowance, the poll
    bound, the settle bounds of a confirmation and of a negative activation with its native
    recovery, and the halt on an unexpected boot. Activations are the managed REBOOT crossings and
    the negative activations; confirmations are the plain kernel reboots."""
    if not isinstance(value, dict) or set(value) != set(BOOT_POLICY_KEYS):
        _fail('a boot policy has exactly its keys')
    _int(value['activation_services'], 0, 16, 'activation_services')
    _int(value['confirmation_services'], 0, 16, 'confirmation_services')
    _int(value['observed_boots'], 1, 64, 'observed_boots')
    _int(value['poll_interval_ms'], 1, 600_000, 'poll_interval_ms')
    _int(value['settle_ms'], 1, MAX_TIMEOUT_MS, 'settle_ms')
    _int(value['negative_settle_ms'], 1, MAX_TIMEOUT_MS, 'negative_settle_ms')
    if value['unexpected_boot'] != 'HALT':
        _fail('an unexpected boot halts')
    return value


def check_branches(value, specs):
    """The F0 branches: FULL and REFUSED, and LIMITED or null when it is not admitted. Each binds
    its frozen predicate's SHA-256 and the ordered actions it admits. `positive` names the plan
    and attempt that only a qualified F0 admits: positive A attempt 6."""
    if not isinstance(value, dict) or set(value) != set(BRANCHES) | {'positive'}:
        _fail('branches are exactly FULL, LIMITED and REFUSED, and the positive attempt they gate')
    positive = value['positive']
    if not isinstance(positive, dict) or set(positive) != {'plan', 'attempt'}:
        _fail('the positive attempt is a plan and an attempt')
    _hex16(positive['plan'], 'the positive plan')
    _int(positive['attempt'], 1, (1 << 31) - 1, 'the positive attempt')
    for name in BRANCHES:
        branch = value[name]
        if branch is None and name == 'LIMITED':
            continue
        if not isinstance(branch, dict) or set(branch) != {'predicate_sha256', 'actions'}:
            _fail('a branch binds its predicate and its actions')
        _hex32(branch['predicate_sha256'], 'a branch predicate')
        actions = branch['actions']
        if not isinstance(actions, list) or len(set(actions)) != len(actions) or any(a not in specs for a in actions):
            _fail("a branch's actions are distinct admitted actions")
    return value


def spec_bytes(spec):
    """The canonical bytes of one admitted spec, which the broker retains by digest."""
    return lab_evidence.canonical(spec)


# ---------------------------------------------------------------- the typed user inventory

def check_inventory(reading):
    """A typed user inventory as a reader projects it from its whole raw dump: whether the dump
    was whole, the current user, and each user's ID, serial, type, state, flags, restrictions,
    parent and removing, partial and precreated markers. Returns why it is not of that form, or
    None."""
    if not isinstance(reading, dict) or set(reading) != set(INVENTORY_KEYS):
        return 'an inventory has exactly its keys'
    if type(reading['whole']) is not bool or type(reading['current_user']) is not int:
        return 'an inventory names whether it is whole and its current user'
    users = reading['users']
    if not isinstance(users, list) or not 1 <= len(users) <= 64:
        return 'an inventory lists 1 to 64 users'
    ids, serials = set(), set()
    for u in users:
        if not isinstance(u, dict) or set(u) != set(USER_KEYS):
            return 'a user has exactly its keys'
        for name in ('id', 'serial', 'flags', 'parent'):
            if type(u[name]) is not int:
                return 'a user ID, serial, flags and parent are integers'
        if u['id'] < 0 or u['serial'] < 0 or u['flags'] < 0 or (u['parent'] < 0 and u['parent'] != NO_USER):
            return 'a user ID, serial, flags or parent out of bounds'
        if not isinstance(u['type'], str) or not USER_TYPE.fullmatch(u['type']) or u['state'] not in USER_STATES:
            return 'a user type or state of no known form'
        # A restriction key may hold digits, as no_cellular_2g does (UserManager.java:1990).
        if not isinstance(u['restrictions'], list) or any(not isinstance(r, str)
                                                           or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', r)
                                                           for r in u['restrictions']):
            return 'user restrictions are names'
        if any(type(u[name]) is not bool for name in ('removing', 'partial', 'precreated')):
            return 'user markers are booleans'
        if u['id'] in ids or u['serial'] in serials:
            return 'a user ID or serial listed twice'
        ids.add(u['id'])
        serials.add(u['serial'])
    if reading['current_user'] not in ids:
        return 'the current user is not listed'
    return None


def usable(user, user_type):
    """Whether an inventory user can be an action's target: of the expected type, running and not
    being removed, partial or precreated."""
    return (user['type'] == user_type and user['state'] in RUNNING and not user['removing'] and not user['partial']
            and not user['precreated'])


def resolve_system(reading):
    """The observed system user from a whole inventory, or why not."""
    if not reading['whole']:
        return None, 'the user inventory is not whole'
    found = [u for u in reading['users'] if u['id'] == 0]
    if len(found) != 1 or not usable(found[0], SYSTEM_TYPE):
        return None, 'the system user is not a usable full system user'
    return found[0], None


def resolve_created(reading, identified, running=True):
    """The user one create action identified, from a whole inventory, or why not: listed with the
    returned ID and the serial and full secondary type that identified it, unmarked, and running
    unless `running` is False, as for a start's own stopped target. Only a whole inventory that no
    longer lists the ID shows the user removed; one that lists another user under it names another
    user. A reading that is not whole shows nothing."""
    if identified is None:
        return None, 'the create action has identified no user'
    if not reading['whole']:
        return None, 'the user inventory is not whole'
    found = [u for u in reading['users'] if u['id'] == identified['user']]
    if not found:
        return None, 'a whole inventory no longer lists the created user: it was removed'
    u = found[0]
    if (u['serial'], u['type']) != (identified['serial'], identified['type']):
        return None, 'the created user ID now names another user'
    if u['removing'] or u['partial'] or u['precreated']:
        return None, 'the created user is being removed, partial or precreated'
    if running and u['state'] not in RUNNING:
        return None, 'the created user does not run'
    return u, None


def resolve_recipient(reading, issue, serial):
    """A required recipient of an issued notice, by its serial, from a whole inventory, or why not.
    It must still be the user the issue recorded: the same ID and type, running and unmarked."""
    if not reading['whole']:
        return None, 'the user inventory is not whole'
    required = [r for r in issue['required'] if r['serial'] == serial]
    if len(required) != 1:
        return None, 'the serial is not a required recipient of the issued notice'
    found = [u for u in reading['users'] if u['serial'] == serial]
    if len(found) != 1 or found[0]['id'] != required[0]['user'] or not usable(found[0], required[0]['type']):
        return None, 'the recipient is not the usable user the issue recorded'
    return found[0], None


def notice_recipients(reading):
    """The users a notice under the lab operator's ACTIVATE is owed to: every running full secondary
    user, by ID, serial and type, from a whole inventory. The system user stands in for the owner
    and needs none. A user being removed, partial or precreated, or of another type, refuses the
    whole issue instead of quietly dropping that user."""
    if not reading['whole']:
        return None, 'the user inventory is not whole'
    required = []
    for u in sorted(reading['users'], key=lambda u: u['id']):
        if u['id'] == 0 or u['state'] not in RUNNING:
            continue
        if not usable(u, SECONDARY_TYPE):
            return None, 'a running user %d that is not a usable full secondary user' % u['id']
        required.append({'user': u['id'], 'serial': u['serial'], 'type': u['type']})
    return required, None


# ---------------------------------------------------------------- the global session inventory

# One whole installer session dump as a reader projects it before any SystemUI projection: every
# session of every package, in every section, with its referrer, family and commitment. A field the
# reader could not establish is None, which never counts as safe.
GLOBAL_KEYS = ('whole', 'sessions')
SESSION_KEYS = ('section', 'id', 'package', 'referrer', 'staged', 'multi_package', 'parent', 'children', 'sealed',
                'committed', 'ready', 'applied', 'failed', 'destroyed', 'created', 'installer', 'cause')
SECTIONS = ('ACTIVE', 'FINALIZED', 'HISTORICAL')
FLAGS = ('staged', 'multi_package', 'sealed', 'committed', 'ready', 'applied', 'failed', 'destroyed')
CAUSES = ('SIGNATURE', 'FS_VERITY', 'OTHER')
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')
NO_PARENT = -1
MAX_SESSIONS = 256


def check_global(reading):
    """A global session inventory of exact form, or why not."""
    if not isinstance(reading, dict) or set(reading) != set(GLOBAL_KEYS) or type(reading['whole']) is not bool:
        return 'a global inventory is whether it is whole and its sessions'
    rows = reading['sessions']
    if not isinstance(rows, list) or len(rows) > MAX_SESSIONS:
        return 'a global inventory lists at most %d sessions' % MAX_SESSIONS
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(SESSION_KEYS):
            return 'a session has exactly its fields'
        if row['section'] not in SECTIONS or type(row['id']) is not int or not 0 < row['id'] <= 0x7fffffff:
            return 'a session names its section and ID'
        if row['id'] in seen:
            return 'a session listed twice'
        seen.add(row['id'])
        if row['package'] is not None and (not isinstance(row['package'], str) or not PACKAGE.fullmatch(row['package'])):
            return 'a session package of no known form'
        if row['referrer'] is not None and (not isinstance(row['referrer'], str) or len(row['referrer']) > 255
                                            or any(ord(c) < 0x21 or ord(c) > 0x7e for c in row['referrer'])):
            return 'a session referrer of no known form'
        if any(row[name] is not None and type(row[name]) is not bool for name in FLAGS):
            return 'session flags are booleans or unknown'
        if row['parent'] is not None and (type(row['parent']) is not int or row['parent'] < NO_PARENT):
            return 'a session parent of no known form'
        if row['children'] is not None and (not isinstance(row['children'], list)
                                            or any(type(c) is not int or c <= 0 for c in row['children'])):
            return 'session children of no known form'
        for name in ('created', 'installer'):
            if row[name] is not None and (type(row[name]) is not int or row[name] < 0):
                return 'a session %s of no known form' % name
        if row['cause'] is not None and row['cause'] not in CAUSES:
            return 'a session cause of no known class'
    return None


def terminal(row):
    """Whether a session can never activate: finalized or historical, applied, failed or destroyed.
    None when its section says active but a flag that decides it is unknown."""
    if row['section'] != 'ACTIVE' or True in (row['applied'], row['failed'], row['destroyed']):
        return True
    if None in (row['applied'], row['failed'], row['destroyed']):
        return None
    return False


def single(row, component):
    """Whether a session is one staged session of the component: no family."""
    return (row['package'] == component and row['staged'] is True and row['multi_package'] is False
            and row['parent'] == NO_PARENT and row['children'] == [])


def uncommitted(row, component):
    """Whether a live session is positively uncommitted: one staged session of the component, open
    or sealed, with commitment and readiness read false."""
    return single(row, component) and row['sealed'] in (True, False) and row['committed'] is False \
        and row['ready'] is False


def control_referrer(control):
    return CONTROL_REFERRER + control


def confirmation_safety(reading, component):
    """Why a plain kernel reboot is not safe now, or None: the inventory must be whole, and every
    live session positively uncommitted. A committed, ready or unknown session, a foreign package
    or an unexpected family refuses: no reboot may activate an unapproved armed session."""
    if not reading['whole']:
        return 'the global session inventory is not whole'
    for row in reading['sessions']:
        state = terminal(row)
        if state is None:
            return 'session %d: whether it can still activate is unknown' % row['id']
        if state:
            continue
        if row['package'] != component:
            return 'session %d: a live session of another package' % row['id']
        if not single(row, component):
            return 'session %d: a live session of an unexpected or unknown family' % row['id']
        if not uncommitted(row, component):
            return 'session %d: a live session committed, ready or of unknown commitment' % row['id']
    return None


def live_rows(reading):
    """The sessions that are not terminal, unknown ones included."""
    return [row for row in reading['sessions'] if terminal(row) is not True]


def own_row(reading, control, component, reference=None):
    """The one live session of a direct control in a whole inventory: its referrer, the
    component, staged and single, and, when a reference is known, its ID, creation time and
    installer. Returns (row, None) or (None, why). An inventory that is not whole joins nothing:
    it cannot show that no other live session exists, so nothing is armed or written by it."""
    if not reading.get('whole'):
        return None, 'the global session inventory is not whole'
    found = [row for row in live_rows(reading) if row['referrer'] == control_referrer(control)]
    if len(found) != 1:
        return None, 'no single live session of the control'
    row = found[0]
    if not single(row, component):
        return None, "the control's session is not one staged session of the component"
    if reference is not None and (row['id'], row['created'], row['installer']) != (
            reference['id'], reference['created'], reference['installer']):
        return None, "the control's live session is not the one its stage created"
    return row, None


def activation_safety(reading, control, component, reference):
    """Why a direct control's activating reboot is not safe now, or None: the inventory whole, its
    own session committed and ready, every other session terminal or positively uncommitted."""
    if not reading['whole']:
        return 'the global session inventory is not whole'
    row, why = own_row(reading, control, component, reference)
    if row is None:
        return why
    if row['committed'] is not True or row['ready'] is not True:
        return "the control's session is not committed and ready"
    for other in reading['sessions']:
        if other['id'] == row['id']:
            continue
        state = terminal(other)
        if state is None or (not state and not uncommitted(other, component)):
            return 'session %d: another live session committed, ready, foreign or unknown' % other['id']
    return None


def rejection(reading, control, component, reference, role):
    """Why a direct control's activation did not end in its intended rejection, or None: its own
    session terminal and failed with its role's cause, and no live session left."""
    if not reading['whole']:
        return 'the global session inventory is not whole'
    if live_rows(reading):
        return 'a session is still live'
    found = [row for row in reading['sessions'] if row['referrer'] == control_referrer(control)
             and row['id'] == reference['id']]
    if len(found) != 1:
        return "the control's session is not in the inventory"
    row = found[0]
    if row['failed'] is not True or row['applied'] is not False:
        return "the control's session did not fail"
    if row['cause'] != ROLE_CAUSES[role]:
        return "the control's session failed for another cause than its role's"
    return None
