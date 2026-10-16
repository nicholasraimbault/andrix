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

Version 1 of this registry has three types. FRAMEWORK_RESTART is the broker's own `am restart`,
with its precondition and its settle wait. NOTICE_VISIBILITY captures and reads the current
visibility of an issued notice for one required recipient, through the notice adapter.
HEALTH_PREPARATION runs the UI, user and work steps that a full health probe of one user needs,
through the health adapter, under a fresh preparation ID and challenge. No type creates a user, so
no spec may yet select one by its create action."""
import re

import lab_evidence

# The next campaign profile, as the admission and the bridge configuration name it.
PROFILE = 'd5-next-vehicle-1'
PHASES = ('ENTRY', 'N1', 'N2', 'N3', 'F0', 'A', 'R', 'FINAL')
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
# Each registered type: its authority, the selectors it admits, its parameters and their kinds, the
# effect class its effect commands count against, its preconditions, whether a use may follow a use
# whose effect stayed uncertain (only an idempotent capture and read), and the adapter of its
# family.
TYPES = {
    'FRAMEWORK_RESTART': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER',), 'parameters': {},
                          'effect': 'control', 'preconditions': ['WHOLE_LISTING', 'NO_COMMITTED_SESSION'],
                          'after_uncertain': False, 'adapter': None},
    'NOTICE_VISIBILITY': {'authority': 'LAB_CONTROL', 'selectors': ('NOTICE_RECIPIENT',), 'parameters': {},
                          'effect': 'fixture', 'preconditions': ['NOTICE_ISSUED'], 'after_uncertain': True,
                          'adapter': 'notice'},
    'HEALTH_PREPARATION': {'authority': 'LAB_CONTROL', 'selectors': ('SYSTEM_USER', 'CREATED_BY'),
                           'parameters': {'criteria': 'criteria', 'max_probe_ms': 'milliseconds'},
                           'effect': 'fixture', 'preconditions': [], 'after_uncertain': False,
                           'adapter': 'health'},
}
# Types whose settled END names the user they created. None yet.
CREATING_TYPES = ()
BOOT_POLICY_KEYS = ('activation_services', 'observed_boots', 'poll_interval_ms', 'settle_ms', 'unexpected_boot')
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
        if spec['inputs'] != []:
            _fail('no registered type pins an input yet')
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
    return {ident: {k: v for k, v in spec.items() if k != 'order'} for ident, spec in by_id.items()}


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
    """The activation service allowance, the observed boot allowance, the poll and settle bounds of
    a boot transition, and the halt on an unexpected boot."""
    if not isinstance(value, dict) or set(value) != set(BOOT_POLICY_KEYS):
        _fail('a boot policy has exactly its keys')
    _int(value['activation_services'], 0, 16, 'activation_services')
    _int(value['observed_boots'], 1, 64, 'observed_boots')
    _int(value['poll_interval_ms'], 1, 600_000, 'poll_interval_ms')
    _int(value['settle_ms'], 1, MAX_TIMEOUT_MS, 'settle_ms')
    if value['unexpected_boot'] != 'HALT':
        _fail('an unexpected boot halts')
    return value


def check_branches(value, specs):
    """The F0 branches: FULL and REFUSED, and LIMITED or null when it is not admitted. Each binds
    its frozen predicate's SHA-256 and the ordered actions it admits."""
    if not isinstance(value, dict) or set(value) != set(BRANCHES):
        _fail('branches are exactly FULL, LIMITED and REFUSED')
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
        if not isinstance(u['restrictions'], list) or any(not isinstance(r, str) or not re.fullmatch(r'[a-z_]{1,64}', r)
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
