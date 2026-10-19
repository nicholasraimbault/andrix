# SPDX-License-Identifier: Apache-2.0
"""The next vehicle's remaining matrix as one ordered campaign: its cells, their faults, the plain
kernel confirmations each asks, its forward milestones and the expected outcome of each cell, with
the conditions that qualify it. G1a's own sequence stays in cells.py, unchanged.

A cell names a phase of lab_actions.PHASES and is one of four kinds: a managed attempt of a plan's
ticket (the cohort refusal's plan, A or the repair R), a direct negative control (N1 to N3), the F0
decision, or the final reads. Plans are named by role, COHORT, A and R; the admission, the schedule
and the cells record bind their actual IDs. Each managed attempt names the grants it gets beside a
fresh STAGE, its crossing, host and point cells and its read and round losses, each at its whole
address, the ticket's states in which it asks a plain kernel confirmation, in order, and its
prediction: the ticket's end, cause and crossings, the native commands the guest saw, the host
calls that replied, the ticket's boot count, the confirmations and the forward milestones its
rounds reached, in order.

The predictions are of the nominal world: a running full secondary user, so the activations owe
notices, and a FULL F0. `qualified` gives a cell's prediction in another world. Without a running
secondary user no NOTICE is owed, so the notice faults and entries drop out and their cells are not
captured. A LIMITED F0 keeps every application and forward repair step and changes no ticket
prediction, but owes no full health qualification. A REFUSED F0 leaves the positive attempt
uncreated, R with it, and the final reads of R's end state unpredicted. Health per serial is a
qualified outcome too: HEALTHY only for a full probe of every criterion over the whole window,
otherwise INCONCLUSIVE, never a guessed pass.

F0 is a gate, not a prediction. A campaign's declaration, frozen before launch, names whether
notices are owed and the F0 branches its admission admits: FULL and REFUSED always, LIMITED only
when reviewers admit it. The cells record freezes every declared branch's qualified predictions,
and the schedule arms every fault a declared branch can reach. The driver then selects the branch
F0 actually decides; until F0 decides, a world's branch is None and nothing after F0 is predicted.

A forward milestone a guest need not show is conditional: APPLIED_PROVISIONAL, when the checkpoint
commits before the first reachable read. A round loss at such a milestone may stay unconsumed only
when the milestone was not reached; the cell then records it NOT_CAPTURED, never a pass. A reached
conditional milestone owes its loss like any other. HEALTH_WINDOW_PROGRESS repeats.

The final reads predict the end state of a whole read group: no open ticket, R chosen at revision
2 and found current, R's exact bytes, versionCode, UID and context active on the original cohort,
the checkpoint COMMITTED, and no live session the campaign owns in the whole global session
inventory, where terminal history may stay.

The nominal boot schedule is the contract's: one initial boot, six plain confirmations, two
negative activations each with its native recovery, and the A and R activations, thirteen nominal
identities and ten reboot services. A rejecting boot may never be observed, so fewer observed IDs
prove nothing, and none is ever invented. A ticket counts only the new boots it observed after its
CREATE entry: 0, 1, 1, 1, 3 and 1 for A's attempts 1 to 6, and 1 for R.

Host data only: the predictions come from the evidence contract's matrix and hold on the simulated
guest before a guest relies on them."""
import hashlib

import lab_actions
import lab_evidence
import lab_losses
import lab_protocol as proto

SCHEMA = 'andrix-next-cells-v2'
PROFILE = lab_actions.PROFILE
ROLES = ('COHORT', 'A', 'R')
KINDS = ('managed', 'direct', 'gate', 'final')
CALLS = ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'reboot')
TERMINAL = ('CLOSED_APPLIED', 'CLOSED_FAILED', 'CANCELLED', 'VOID', 'DIVERGED', 'SUPERSEDED')
# The waits a later kernel boot resolves: a plain confirmation is asked only in one of them.
CONFIRM_WAITS = ('SESSION_INTENT', 'COMMIT_INTENT', 'ABANDON_INTENT')
MILESTONES = tuple(sorted(proto.MILESTONES, key=proto.MILESTONES.get))
# A milestone a guest need not show, and the one a window repeats.
CONDITIONAL = ('APPLIED_PROVISIONAL',)
REPEATED = ('HEALTH_WINDOW_PROGRESS',)
# The worlds a prediction is qualified by: whether a full secondary user runs, owing notices, and
# F0's branch, None until F0 decides.
NOMINAL = {'notice': True, 'f0': 'FULL'}
BRANCHES = lab_actions.BRANCHES
# A campaign's declaration, frozen before launch: whether notices are owed, and the F0 branches its
# admission admits. LIMITED joins only when reviewers admit it.
DECLARED = {'notice': True, 'branches': ['FULL', 'REFUSED']}
# Health outcomes per serial, as the reconciler names them.
HEALTHY, INCONCLUSIVE = 'HEALTHY', 'INCONCLUSIVE'
# The rejection each direct staged control must end in, and N1's refusal, from the source.
CAUSES = {'N1': 'Package com.android.systemui is a persistent app. Persistent apps are not updateable.',
          'N2': lab_actions.ROLE_CAUSES['N2'], 'N3': lab_actions.ROLE_CAUSES['N3']}


def fault(cell, on, crossing, occurrence, mode, needs=None):
    """A crossing or host cell of the next schedule, keyed later to its cell's plan and attempt.
    `needs` names the world part it needs: 'notice' for a NOTICE crossing."""
    return {'cell': cell, 'on': on, 'crossing': crossing, 'occurrence': occurrence, 'mode': mode, 'needs': needs}


def point(cell):
    """The coordinator's BETWEEN_WRITES halt on the selection move."""
    return {'cell': cell, 'on': 'point', 'point': proto.POINTS[0], 'mode': 'halt', 'needs': None}


def loss(cell, on, milestone, occurrence=1, reader=None):
    """A read or round loss at its whole address but the plan and attempt, its cell's."""
    ordinal = 0 if reader is None else lab_losses.READERS.index(reader)
    return {'cell': cell, 'on': on, 'operation': lab_losses.OPERATIONS[on], 'milestone': milestone,
            'ordinal': ordinal, 'occurrence': occurrence, 'mode': 'halt', 'needs': None}


def calls(create=0, write=0, commit=0, abandon=0, reboot=0):
    return {'CREATE': create, 'WRITE': write, 'COMMIT': commit, 'ABANDON': abandon, 'reboot': reboot}


def managed(name, cell, phase, plan, attempt, grants, faults, confirmations, end, cause, ledger, native, signs,
            publishes, boots, milestones, notice=None):
    """A managed attempt. `notice` holds the ledger and native calls in a world without notices
    where they differ; the nominal ones owe them."""
    return {'name': name, 'cell': cell, 'kind': 'managed', 'phase': phase, 'plan': plan, 'attempt': attempt,
            'grants': grants, 'faults': faults, 'confirmations': confirmations,
            'prediction': {'end': end, 'cause': cause, 'ledger': ledger, 'calls': native, 'signs': signs,
                           'publishes': publishes, 'boots': boots, 'confirmations': len(confirmations),
                           'milestones': milestones},
            'without_notice': notice}


# The window's milestones as one A or R activation reaches them through rounds of one generation:
# READY, then for A a second READY after its lost reboot's timeout, the activation boot,
# APPLIED_PROVISIONAL if a read sees it, APPLIED, the window's entry and progress, and the close.
WINDOW = ['BOOT_OBSERVED', 'APPLIED_PROVISIONAL', 'APPLIED', 'HEALTH_WINDOW_ENTRY', 'HEALTH_WINDOW_PROGRESS',
          'TERMINAL']

SEQUENCE = (
    {'name': 'cohort refusal', 'cell': 'cohort', 'kind': 'managed', 'phase': 'CELLS', 'plan': 'COHORT',
     'attempt': 1, 'grants': [], 'faults': [], 'confirmations': [],
     'prediction': {'end': 'VOID', 'cause': 'VOID_BASE', 'ledger': [], 'calls': calls(), 'signs': 0,
                    'publishes': 0, 'boots': 0, 'confirmations': 0, 'milestones': ['TERMINAL']},
     'without_notice': None},
    # A's first attempt is the plan's own ticket under its own grants: SIGN for both inputs, STAGE
    # and ACTIVATE. Its signing request is lost before its effect, so it can never complete.
    managed('H1', 'h1', 'CELLS', 'A', 1, [], [fault('h1-sign', 'host', 'SIGN', 1, 'loss-before')], [],
            'CLOSED_FAILED', None, ['SIGN'], calls(), 0, 0, 0, ['TERMINAL']),
    # Nothing is published yet, so the second attempt signs again under a fresh SIGN grant. C0's
    # CREATE is lost before its effect: the same boot's emptiness settles nothing, and one plain
    # confirmation lets the next boot's whole listing settle NO_SESSION, a boot the ticket counts.
    managed('H2 and C0', 'h2-c0', 'CELLS', 'A', 2, ['SIGN'],
            [fault('h2-sign', 'host', 'SIGN', 1, 'loss-after'), fault('h2-publish-before', 'host', 'PUBLISH', 1,
                                                                      'loss-before'),
             fault('h2-publish-after', 'host', 'PUBLISH', 2, 'loss-after'),
             fault('c0-create', 'cross', 'CREATE', 1, 'loss-before')],
            ['SESSION_INTENT'], 'CLOSED_FAILED', None, ['SIGN', 'PUBLISH', 'PUBLISH', 'CREATE'], calls(), 1, 1, 1,
            ['TERMINAL']),
    # The publication reads back published from here on, so later attempts neither sign nor publish.
    managed('C1, W0 and B1', 'c1-w0-b1', 'CELLS', 'A', 3, [],
            [fault('c1-create', 'cross', 'CREATE', 1, 'drop-reply'), fault('w0-write', 'cross', 'WRITE', 1,
                                                                           'loss-before'),
             fault('b1-abandon', 'cross', 'ABANDON', 1, 'loss-after')],
            ['ABANDON_INTENT'], 'CLOSED_FAILED', None, ['CREATE', 'WRITE', 'ABANDON'], calls(create=1, abandon=1), 0,
            0, 1, ['TERMINAL']),
    managed('C2, W1 and B2', 'c2-w1-b2', 'CELLS', 'A', 4, [],
            [fault('c2-create', 'cross', 'CREATE', 1, 'loss-after'), fault('w1-write', 'cross', 'WRITE', 1,
                                                                           'loss-after'),
             fault('b2-abandon', 'cross', 'ABANDON', 1, 'drop-reply')],
            ['ABANDON_INTENT'], 'CLOSED_FAILED', None, ['CREATE', 'WRITE', 'ABANDON'],
            calls(create=1, write=2, abandon=1), 0, 0, 1, ['TERMINAL']),
    # M0 loses its COMMIT before the effect: nothing commits before F0, and the before effect halt
    # launches nothing. The first confirmation's boot takes COMMIT_INTENT to BOOT_OBSERVED; the live
    # unready session then waits the plan's verification wait from this boot's first observed
    # completion, and the first ABANDON is lost before its effect. The second boot observes again,
    # and the earlier abandon permits one real repeat; the third proves the session gone with the
    # prior bytes active: ABANDONED, then CLOSED_FAILED, three boots counted.
    managed('M0 and B0', 'm0-b0', 'CELLS', 'A', 5, [],
            [fault('m0-commit', 'cross', 'COMMIT', 1, 'loss-before'), fault('b0-abandon', 'cross', 'ABANDON', 1,
                                                                            'loss-before')],
            ['COMMIT_INTENT', 'ABANDON_INTENT', 'ABANDON_INTENT'], 'CLOSED_FAILED', None,
            ['CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'ABANDON'], calls(create=1, write=2, abandon=1), 0, 0, 3,
            ['BOOT_OBSERVED', 'BOOT_OBSERVED', 'BOOT_OBSERVED', 'TERMINAL']),
    # The direct controls own no ticket. N1's nonstaged refusal has no lab action yet. N2 and N3
    # each stage, commit and activate once; the activation's boot and its native recovery's are two
    # physical boots, of which a poll may observe only the last: at least one new boot, at most two.
    {'name': 'N1', 'cell': 'n1', 'kind': 'direct', 'phase': 'N1', 'role': 'N1', 'staged': False,
     'prediction': {'cause': CAUSES['N1'], 'calls': calls(), 'new_boots': [0, 0], 'factory_active': True}},
    {'name': 'N2', 'cell': 'n2', 'kind': 'direct', 'phase': 'N2', 'role': 'N2', 'staged': True,
     'prediction': {'cause': CAUSES['N2'], 'calls': calls(create=1, write=2, commit=1, reboot=1),
                    'new_boots': [1, 2], 'factory_active': True}},
    {'name': 'N3', 'cell': 'n3', 'kind': 'direct', 'phase': 'N3', 'role': 'N3', 'staged': True,
     'prediction': {'cause': CAUSES['N3'], 'calls': calls(create=1, write=1, commit=1, reboot=1),
                    'new_boots': [1, 2], 'factory_active': True}},
    {'name': 'F0', 'cell': 'f0', 'kind': 'gate', 'phase': 'F0',
     'prediction': {'FULL': 'qualified', 'LIMITED': 'qualified-limited', 'REFUSED': 'positive-uncreated'}},
    # A's positive attempt 6 after a qualified F0: no SIGN and no PUBLISH. Its NOTICE is lost before
    # its effect and the reconciler repeats it; the COMMIT reply is dropped and READY resolves it;
    # the first REBOOT is lost before its effect, its timeout passes in the same boot, and Java
    # halts after the second, real, reboot service. The selection move halts between its two
    # writes. Its rounds halt once at each forward milestone, and one health read halts in the
    # window.
    managed('A', 'a', 'A', 'A', 6, [],
            [fault('a-notice', 'cross', 'NOTICE', 1, 'loss-before', needs='notice'),
             fault('a-commit', 'cross', 'COMMIT', 1, 'drop-reply'),
             fault('a-reboot-before', 'cross', 'REBOOT', 1, 'loss-before'),
             fault('a-reboot-after', 'cross', 'REBOOT', 2, 'loss-after'), point('a-selection'),
             loss('a-ready-round', 'round', 'READY'), loss('a-boot-round', 'round', 'BOOT_OBSERVED'),
             loss('a-provisional-round', 'round', 'APPLIED_PROVISIONAL'), loss('a-applied-round', 'round', 'APPLIED'),
             loss('a-entry-round', 'round', 'HEALTH_WINDOW_ENTRY'),
             loss('a-window-read', 'read', 'HEALTH_WINDOW_PROGRESS', 2, 'health'),
             loss('a-terminal-round', 'round', 'TERMINAL')],
            [], 'CLOSED_APPLIED', None, ['CREATE', 'WRITE', 'COMMIT', 'NOTICE', 'NOTICE', 'REBOOT', 'REBOOT'],
            calls(create=1, write=2, commit=1, reboot=1), 0, 0, 1, ['READY', 'READY'] + WINDOW,
            notice={'ledger': ['CREATE', 'WRITE', 'COMMIT', 'REBOOT', 'REBOOT']}),
    # R after A closed: a new plan repairing A that signs nothing, made from A's current baseline,
    # with its own STAGE and ACTIVATE. Its signing is skipped and its publication bound; its NOTICE
    # is lost after its delivered effect and receipts recover; its COMMIT is lost after its effect;
    # one read round halts in its window. One selection move, from revision 1 to 2.
    managed('R', 'r', 'R', 'R', 1, [],
            [loss('r-signing-round', 'round', 'REPAIR_SIGNING_SKIPPED'),
             loss('r-publication-round', 'round', 'REPAIR_PUBLICATION_BOUND'),
             fault('r-notice', 'cross', 'NOTICE', 1, 'loss-after', needs='notice'),
             fault('r-commit', 'cross', 'COMMIT', 1, 'loss-after'),
             loss('r-window-read', 'read', 'HEALTH_WINDOW_PROGRESS', 3, 'sessions')],
            [], 'CLOSED_APPLIED', None, ['PUBLISH', 'CREATE', 'WRITE', 'COMMIT', 'NOTICE', 'REBOOT'],
            calls(create=1, write=2, commit=1, reboot=1), 0, 1, 1,
            ['REPAIR_SIGNING_SKIPPED', 'REPAIR_PUBLICATION_BOUND', 'READY'] + WINDOW,
            notice={'ledger': ['PUBLISH', 'CREATE', 'WRITE', 'COMMIT', 'REBOOT']}),
    # The final reads: no new activation, one whole read group of the current boot and its join.
    {'name': 'Final', 'cell': 'final', 'kind': 'final', 'phase': 'FINAL',
     'prediction': {'open_tickets': 0, 'choice': 'PLAN', 'plan': 'R', 'revision': 2, 'realization': 'CURRENT',
                    'checkpoint': 'COMMITTED', 'active': 'R', 'cohort': 'ORIGINAL', 'live_owned': 0}},
)

# The nominal kernel boot schedule, by ordinal label, the transition that makes each and its cell.
BOOTS = (('B0', 'INITIAL', 'entry'), ('B1', 'CONFIRMATION', 'h2-c0'), ('B2', 'CONFIRMATION', 'c1-w0-b1'),
         ('B3', 'CONFIRMATION', 'c2-w1-b2'), ('B4', 'CONFIRMATION', 'm0-b0'), ('B5', 'CONFIRMATION', 'm0-b0'),
         ('B6', 'CONFIRMATION', 'm0-b0'), ('B7', 'NEGATIVE_ACTIVATION', 'n2'), ('B8', 'NATIVE_RECOVERY', 'n2'),
         ('B9', 'NEGATIVE_ACTIVATION', 'n3'), ('B10', 'NATIVE_RECOVERY', 'n3'), ('B11', 'MANAGED_ACTIVATION', 'a'),
         ('B12', 'MANAGED_ACTIVATION', 'r'))
SERVICE_KINDS = ('CONFIRMATION', 'NEGATIVE_ACTIVATION', 'MANAGED_ACTIVATION')
# The contract's notice budget: the request limit plus one per boot, seventeen in all.
NOTICE_BUDGET = 17


def cells(sequence=SEQUENCE, kind=None):
    return [c for c in sequence if kind is None or c['kind'] == kind]


def by_cell(name, sequence=SEQUENCE):
    found = [c for c in sequence if c['cell'] == name]
    if len(found) != 1:
        raise KeyError(name)
    return found[0]


def by_fault(cell, name):
    """One fault of a cell by its name."""
    found = [f for f in cell.get('faults', []) if f['cell'] == name]
    if len(found) != 1:
        raise KeyError(name)
    return found[0]


# ---------------------------------------------------------------- forms

FAULT_KEYS = {'cross': ('cell', 'on', 'crossing', 'occurrence', 'mode', 'needs'),
              'host': ('cell', 'on', 'crossing', 'occurrence', 'mode', 'needs'),
              'point': ('cell', 'on', 'point', 'mode', 'needs'),
              'read': ('cell', 'on', 'operation', 'milestone', 'ordinal', 'occurrence', 'mode', 'needs'),
              'round': ('cell', 'on', 'operation', 'milestone', 'ordinal', 'occurrence', 'mode', 'needs')}
MODES = {'cross': ('loss-before', 'loss-after', 'drop-reply', 'loss-between-members'),
         'host': ('loss-before', 'loss-after', 'drop-reply'), 'point': ('halt',), 'read': ('halt',), 'round': ('halt',)}
MANAGED_KEYS = {'name', 'cell', 'kind', 'phase', 'plan', 'attempt', 'grants', 'faults', 'confirmations',
                'prediction', 'without_notice'}
PREDICTION_KEYS = {'end', 'cause', 'ledger', 'calls', 'signs', 'publishes', 'boots', 'confirmations', 'milestones'}
DIRECT_KEYS = {'name', 'cell', 'kind', 'phase', 'role', 'staged', 'prediction'}
GATE_KEYS = {'name', 'cell', 'kind', 'phase', 'prediction'}
FINAL_KEYS = {'open_tickets', 'choice', 'plan', 'revision', 'realization', 'checkpoint', 'active', 'cohort',
              'live_owned'}
CROSSING_NAMES = ('SIGN', 'PUBLISH') + proto.DEVICE_CROSSINGS


def check_fault(item):
    """Refuses one fault of no known form: its keys for where it acts, a known mode, a crossing of
    its place, and for a loss the whole address lab_losses checks."""
    on = item.get('on') if isinstance(item, dict) else None
    if on not in FAULT_KEYS or set(item) != set(FAULT_KEYS[on]) or not isinstance(item['cell'], str) \
            or not lab_losses.CELL.fullmatch(item['cell']):
        raise ValueError('a fault of no known form: %s' % (item,))
    if item['mode'] not in MODES[on] or item['needs'] not in (None, 'notice'):
        raise ValueError('a fault of no known mode or need: %s' % item['cell'])
    if on == 'host' and (item['crossing'] not in proto.HOST_CROSSINGS or item['occurrence'] not in (1, 2)):
        raise ValueError('a host fault on SIGN or PUBLISH, occurrence 1 or 2: %s' % item['cell'])
    if on == 'cross' and (item['crossing'] not in proto.DEVICE_CROSSINGS or type(item['occurrence']) is not int
                          or not 1 <= item['occurrence'] < 100):
        raise ValueError('a crossing fault on a device crossing and an occurrence: %s' % item['cell'])
    if on == 'cross' and item['mode'] == 'loss-between-members' and item['crossing'] != 'WRITE':
        raise ValueError('only WRITE has two members: %s' % item['cell'])
    if (item['needs'] == 'notice') != (on == 'cross' and item['crossing'] == 'NOTICE'):
        raise ValueError('a NOTICE fault, and only one, needs notices: %s' % item['cell'])
    if on in lab_losses.OPERATIONS:
        try:
            lab_losses.loss(dict(_scheduled(item), plan='01' * 16, attempt=1))
        except lab_losses.ScheduleError as error:
            raise ValueError('%s: %s' % (item['cell'], error)) from error
    return True


def check_milestones(milestones):
    """Refuses a milestone prediction of no known form: forward milestones of the fixed enum."""
    if not isinstance(milestones, list) or not milestones or any(m not in MILESTONES for m in milestones):
        raise ValueError('milestones of the fixed enum, at least the close')
    return True


def check_cell(cell):
    """Refuses one cell of no known form. A managed attempt names every key, a known plan role,
    an attempt, its grants, each fault, the confirm waits it asks, and a complete prediction."""
    if not isinstance(cell, dict) or cell.get('kind') not in KINDS or cell.get('phase') not in lab_actions.PHASES:
        raise ValueError('a cell of no known kind or phase')
    if not isinstance(cell.get('cell'), str) or not lab_losses.CELL.fullmatch(cell['cell']):
        raise ValueError('a cell names itself in lower case')
    if cell['kind'] == 'direct':
        p = cell.get('prediction')
        if set(cell) != DIRECT_KEYS or cell['role'] not in CAUSES or cell['phase'] != cell['role'] \
                or not isinstance(p, dict) or set(p) != {'cause', 'calls', 'new_boots', 'factory_active'} \
                or p['cause'] != CAUSES[cell['role']] or set(p['calls']) != set(CALLS) \
                or cell['staged'] != (cell['role'] in lab_actions.ROLES) or p['factory_active'] is not True:
            raise ValueError('a direct control cell of no known form: %s' % cell.get('name'))
        return True
    if cell['kind'] == 'gate':
        if set(cell) != GATE_KEYS or set(cell['prediction']) != set(BRANCHES):
            raise ValueError('the F0 cell names the outcome of each branch')
        return True
    if cell['kind'] == 'final':
        if set(cell) != GATE_KEYS or set(cell['prediction']) != FINAL_KEYS:
            raise ValueError('the final cell names the end state it reads')
        return True
    if set(cell) != MANAGED_KEYS or cell['plan'] not in ROLES or type(cell['attempt']) is not int \
            or cell['attempt'] < 1:
        raise ValueError('a managed cell of no known form: %s' % cell.get('name'))
    if not set(cell['grants']) <= {'SIGN', 'ACTIVATE'} or (cell['attempt'] == 1 and cell['grants']):
        raise ValueError("grants of no known form, or beside a plan's own first attempt: %s" % cell['name'])
    names = [f['cell'] for f in cell['faults']]
    if len(set(names)) != len(names):
        raise ValueError('a fault named twice in %s' % cell['name'])
    for item in cell['faults']:
        check_fault(item)
    if not isinstance(cell['confirmations'], list) or any(s not in CONFIRM_WAITS for s in cell['confirmations']):
        raise ValueError('confirmations are asked only in waits a later boot resolves: %s' % cell['name'])
    p = cell['prediction']
    if set(p) != PREDICTION_KEYS or p['end'] not in TERMINAL or not isinstance(p['ledger'], list) \
            or not set(p['ledger']) <= set(CROSSING_NAMES):
        raise ValueError('a prediction of no known form: %s' % cell['name'])
    if set(p['calls']) != set(CALLS) or any(type(n) is not int or n < 0 for n in p['calls'].values()) \
            or any(type(p[k]) is not int or p[k] < 0 for k in ('signs', 'publishes', 'boots', 'confirmations')):
        raise ValueError('a prediction names every native call and its counts: %s' % cell['name'])
    if p['confirmations'] != len(cell['confirmations']) or p['boots'] < p['confirmations']:
        raise ValueError("a ticket counts at least the boots its own confirmations made: %s" % cell['name'])
    check_milestones(p['milestones'])
    alternative = cell['without_notice']
    if alternative is not None and (set(alternative) != {'ledger'} or 'NOTICE' in alternative['ledger']):
        raise ValueError('a prediction without notices names its ledger alone: %s' % cell['name'])
    return True


def check_sequence(sequence=SEQUENCE):
    """Refuses a campaign of no known form: cells in the profile's phase order, each named once,
    each fault named once across the campaign, a plan's attempts in order from 1, every cell well
    formed."""
    seen_cells, seen_faults, attempts, phase = set(), set(), {}, 0
    for cell in sequence:
        check_cell(cell)
        if cell['cell'] in seen_cells:
            raise ValueError('a cell named twice: %s' % cell['cell'])
        seen_cells.add(cell['cell'])
        at = lab_actions.PHASES.index(cell['phase'])
        if at < phase:
            raise ValueError('cells in the profile phase order: %s' % cell['cell'])
        phase = at
        if cell['kind'] != 'managed':
            continue
        if cell['attempt'] != attempts.get(cell['plan'], 0) + 1:
            raise ValueError("a plan's attempts in order from 1: %s" % cell['cell'])
        attempts[cell['plan']] = cell['attempt']
        for item in cell['faults']:
            if item['cell'] in seen_faults:
                raise ValueError('a fault named twice in the campaign: %s' % item['cell'])
            seen_faults.add(item['cell'])
    return True


# ---------------------------------------------------------------- qualified predictions

def check_world(world):
    if not isinstance(world, dict) or set(world) != set(NOMINAL) or type(world['notice']) is not bool \
            or (world['f0'] is not None and world['f0'] not in BRANCHES):
        raise ValueError('a world names whether notices are owed and F0 branch, None before F0 decides')
    return True


def declaration(notice=True, limited=False):
    """A campaign's declaration: whether notices are owed, and the F0 branches its admission admits,
    FULL and REFUSED always and LIMITED only when admitted."""
    return {'notice': notice, 'branches': [b for b in BRANCHES if b != 'LIMITED' or limited]}


def check_declaration(value):
    if not isinstance(value, dict) or set(value) != set(DECLARED) or type(value['notice']) is not bool \
            or value['branches'] not in (['FULL', 'REFUSED'], ['FULL', 'LIMITED', 'REFUSED']):
        raise ValueError('a declaration names whether notices are owed and the F0 branches it admits')
    return True


def worlds(declared):
    """The world of each declared F0 branch, in branch order."""
    check_declaration(declared)
    return [{'notice': declared['notice'], 'f0': branch} for branch in declared['branches']]


def undecided(declared):
    """The world before F0 decides: the declaration's notices and no branch yet."""
    check_declaration(declared)
    return {'notice': declared['notice'], 'f0': None}


def reached(cell, world):
    """Whether a cell runs at all in the world: a REFUSED F0 leaves A's positive attempt and R
    uncreated, and the final reads of R's end state unpredicted. Before F0 decides, whether they run
    is not known: asking is an error, never a guess."""
    check_world(world)
    if cell['kind'] == 'final' or (cell['kind'] == 'managed' and cell['phase'] in ('A', 'R')):
        if world['f0'] is None:
            raise ValueError('F0 has not decided whether %s runs' % cell['name'])
        return world['f0'] != 'REFUSED'
    return True


def faults(cell, world):
    """The cell's faults the world can act on: without notices, no NOTICE fault."""
    if not reached(cell, world):
        return []
    return [f for f in cell.get('faults', []) if world['notice'] or f['needs'] != 'notice']


def uncaptured(cell, world):
    """The cell's faults the world leaves NOT_CAPTURED: those it cannot reach."""
    kept = {f['cell'] for f in faults(cell, world)}
    return [f['cell'] for f in cell.get('faults', []) if f['cell'] not in kept]


def qualified(cell, world):
    """The managed cell's prediction in a world, or None when it does not run there."""
    if cell['kind'] != 'managed' or not reached(cell, world):
        return None
    p = dict(cell['prediction'], calls=dict(cell['prediction']['calls']),
             milestones=list(cell['prediction']['milestones']))
    if not world['notice'] and cell['without_notice'] is not None:
        p['ledger'] = list(cell['without_notice']['ledger'])
    return p


def health(world, full_probe):
    """The qualified health outcome of each observed serial of A or R: HEALTHY only under a FULL F0
    whose probes read every criterion over the whole window; otherwise INCONCLUSIVE."""
    check_world(world)
    if world['f0'] is None:
        raise ValueError('no health outcome is predicted before F0 decides')
    return HEALTHY if world['f0'] == 'FULL' and full_probe else INCONCLUSIVE


def milestones_match(predicted, found):
    """Whether the milestones a ticket's boundaries recorded, in order, are the prediction: each
    milestone exactly where predicted, a conditional one there at most once, a repeated one there
    at least once."""
    at = 0
    for name in predicted:
        if name in CONDITIONAL:
            if at < len(found) and found[at] == name:
                at += 1
            continue
        if name in REPEATED:
            if at >= len(found) or found[at] != name:
                return False
            while at < len(found) and found[at] == name:
                at += 1
            continue
        if at >= len(found) or found[at] != name:
            return False
        at += 1
    return at == len(found)


# ---------------------------------------------------------------- what the admission binds

def plan_ids(plans):
    """The plan ID of each role, checked: three distinct nonzero IDs."""
    if not isinstance(plans, dict) or set(plans) != set(ROLES) or len(set(plans.values())) != len(ROLES) \
            or any(not lab_actions.HEX16.fullmatch(v or '') or v == '00' * 16 for v in plans.values()):
        raise ValueError('a plan ID for each role, distinct and nonzero')
    return dict(plans)


def _scheduled(item):
    """A fault's schedule form: its own keys, without the campaign's need."""
    return {k: v for k, v in item.items() if k != 'needs'}


def schedule_faults(plans, declared=DECLARED, sequence=SEQUENCE):
    """Every fault of the campaign that a declared branch's world can act on, each keyed to its
    cell's plan ID and attempt, in campaign order: the faults a version 3 admission binds through
    its schedule, armed before F0 decides which branch runs. A fault no declared branch reaches is
    never armed."""
    plans = plan_ids(plans)
    alternatives = worlds(declared)
    out = []
    for cell in sequence:
        kept = {f['cell'] for world in alternatives for f in faults(cell, world)}
        for item in cell.get('faults', []):
            if item['cell'] in kept:
                out.append(dict(_scheduled(item), plan=plans[cell['plan']], attempt=cell['attempt']))
    return out


def schedule_bytes(installation, plans, declared=DECLARED, sequence=SEQUENCE):
    """The canonical fault schedule of the campaign, `andrix-fault-schedule-v1`."""
    return lab_evidence.canonical({'schema': lab_losses.SCHEMA, 'profile': PROFILE, 'installation': installation,
                                   'faults': schedule_faults(plans, declared, sequence)})


def record(plans, declared=DECLARED, sequence=SEQUENCE):
    """The cells record whose SHA-256 a version 3 admission binds: the plans by role, whether
    notices are owed, and the campaign's cells under each declared F0 branch with whether they run
    and their qualified predictions, all frozen before launch; then the nominal boot schedule and
    budgets."""
    plans = plan_ids(plans)
    check_declaration(declared)
    check_sequence(sequence)
    branches = {}
    for world in worlds(declared):
        entries = []
        for cell in sequence:
            entry = {k: v for k, v in cell.items() if k not in ('faults', 'prediction', 'without_notice')}
            entry['runs'] = reached(cell, world)
            entry['faults'] = [f['cell'] for f in faults(cell, world)]
            entry['not_captured'] = uncaptured(cell, world)
            entry['prediction'] = qualified(cell, world) if cell['kind'] == 'managed' else cell['prediction']
            entries.append(entry)
        branches[world['f0']] = entries
    return {'schema': SCHEMA, 'profile': PROFILE, 'plans': plans, 'notice': declared['notice'],
            'branches': branches, 'boots': [list(b) for b in BOOTS], 'nominal': nominal(sequence)}


def record_bytes(plans, declared=DECLARED, sequence=SEQUENCE):
    return lab_evidence.canonical(record(plans, declared, sequence))


def nominal(sequence=SEQUENCE):
    """The campaign's nominal counts, from its cells: what the contract's budgets must match."""
    managed_cells = cells(sequence, 'managed')
    entries = {name: sum(c['prediction']['ledger'].count(name) for c in managed_cells) for name in CROSSING_NAMES}
    launched = {name: sum(c['prediction']['calls'][name] for c in managed_cells) for name in CALLS}
    direct = {name: sum(c['prediction']['calls'][name] for c in cells(sequence, 'direct')) for name in CALLS}
    confirmations = sum(len(c['confirmations']) for c in managed_cells)
    activations = sum(1 for _, kind, _ in BOOTS if kind in ('NEGATIVE_ACTIVATION', 'MANAGED_ACTIVATION'))
    return {'entries': entries, 'launched': launched, 'direct': direct, 'confirmations': confirmations,
            'activations': activations, 'services': confirmations + activations, 'identities': len(BOOTS),
            'boots': [c['prediction']['boots'] for c in managed_cells if c['plan'] == 'A'],
            'repair_boots': [c['prediction']['boots'] for c in managed_cells if c['plan'] == 'R'],
            'member_writes': launched['WRITE'] + direct['WRITE']}


# ---------------------------------------------------------------- the admitted action specs

# The helper jars a guest needs, each pushed once with byte readback before any read uses it.
HELPERS = ('ui-state', 'process-health')


def action_id(kind, name):
    """A deterministic, nonzero action ID for one of the campaign's specs."""
    value = hashlib.sha256(('andrix-next-action:%s:%s' % (kind, name)).encode('ascii')).hexdigest()[:32]
    return value if value != '00' * 16 else '01' * 16


def confirmation_cells(sequence=SEQUENCE):
    """Each plain confirmation of the campaign, in order: (spec cell name, managed cell, wait)."""
    out = []
    for cell in cells(sequence, 'managed'):
        for at, state in enumerate(cell['confirmations'], 1):
            suffix = '-confirm' if len(cell['confirmations']) == 1 else '-confirm-%d' % at
            out.append((cell['cell'] + suffix, cell, state))
    return out
