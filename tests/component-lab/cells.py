# SPDX-License-Identifier: Apache-2.0
"""The loss cells of the first durable component transaction's lab step, as one ordered sequence of
attempts on one plan.

Each attempt names the fault records the broker admits before the attempt's first generation and
the prediction its records must meet once the ticket is terminal. The driver asks a framework
restart only when a generation leaves the ticket unchanged in one of RESTART_WAITS and that
generation's own reads show a wait a later framework instance resolves, and the broker records each
restart with the state that asked it; the prediction names those states too. A prediction is judged
from the store's ticket and from the broker's ledger (native commands launched, host calls replied,
restarts asked, faults acted), never from the driver's own counters: these are launch and request
counts, and the closure judges their effects. Host data only: the predictions come from the
design's cell table and are confirmed on the simulated guest before a guest relies on them."""

import lab_broker

# The intent states whose waits a later framework instance can resolve. Being in one is not enough:
# the driver also needs the generation's reads to show such a wait (LabDriver.restart_resolves).
RESTART_WAITS = ('SESSION_INTENT', 'COMMIT_INTENT', 'ABANDON_INTENT')
CROSSINGS = ('SIGN', 'PUBLISH', 'CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'REBOOT', 'NOTICE')
TERMINAL = ('CLOSED_APPLIED', 'CLOSED_FAILED', 'CANCELLED', 'VOID', 'DIVERGED', 'SUPERSEDED')


def fault(cell, on, crossing, occurrence, mode):
    """One broker fault record, keyed later to the plan and the attempt."""
    return {'cell': cell, 'on': on, 'crossing': crossing, 'occurrence': occurrence, 'mode': mode}


# The ticket's end, the crossings its ledger names in order, the native calls the guest saw, the host
# calls that completed (signs and publishes; one halted before its effect does not count), and the
# restarts with the states that asked them. Native calls, host calls and restarts are read from the
# broker's ledger since the attempt began; the end and the ticket's ledger from the store.
SEQUENCE = (
    # Attempt 1 is the plan's first ticket with the plan's own grants: SIGN for both inputs, STAGE
    # and ACTIVATE.
    {'name': 'H1', 'attempt': 1, 'grants': [],
     'faults': [fault('h1-sign', 'host', 'SIGN', 1, 'loss-before')],
     'end': 'CLOSED_FAILED', 'ledger': ['SIGN'],
     'calls': {'CREATE': 0, 'WRITE': 0, 'COMMIT': 0, 'ABANDON': 0, 'reboot': 0},
     'signs': 0, 'publishes': 0, 'restarts': []},
    # Nothing is published yet, so the second attempt signs again under a fresh SIGN grant.
    {'name': 'H2 and C0', 'attempt': 2, 'grants': ['SIGN'],
     'faults': [fault('h2-sign', 'host', 'SIGN', 1, 'loss-after'),
                fault('h2-publish-before', 'host', 'PUBLISH', 1, 'loss-before'),
                fault('h2-publish-after', 'host', 'PUBLISH', 2, 'loss-after'),
                fault('c0-create', 'cross', 'CREATE', 1, 'loss-before')],
     'end': 'CLOSED_FAILED', 'ledger': ['SIGN', 'PUBLISH', 'PUBLISH', 'CREATE'],
     'calls': {'CREATE': 0, 'WRITE': 0, 'COMMIT': 0, 'ABANDON': 0, 'reboot': 0},
     'signs': 1, 'publishes': 1, 'restarts': ['SESSION_INTENT']},
    # The plan's publication is read back published, so later attempts neither sign nor publish
    # (Reconciler.signingNeeded) and need only their fresh STAGE grant.
    {'name': 'C1, W0 and B1', 'attempt': 3, 'grants': [],
     'faults': [fault('c1-create', 'cross', 'CREATE', 1, 'drop-reply'),
                fault('w0-write', 'cross', 'WRITE', 1, 'loss-before'),
                fault('b1-abandon', 'cross', 'ABANDON', 1, 'loss-after')],
     'end': 'CLOSED_FAILED', 'ledger': ['CREATE', 'WRITE', 'ABANDON'],
     'calls': {'CREATE': 1, 'WRITE': 0, 'COMMIT': 0, 'ABANDON': 1, 'reboot': 0},
     'signs': 0, 'publishes': 0, 'restarts': ['ABANDON_INTENT']},
    {'name': 'C2, W1 and B2', 'attempt': 4, 'grants': [],
     'faults': [fault('c2-create', 'cross', 'CREATE', 1, 'loss-after'),
                fault('w1-write', 'cross', 'WRITE', 1, 'loss-after'),
                fault('b2-abandon', 'cross', 'ABANDON', 1, 'drop-reply')],
     'end': 'CLOSED_FAILED', 'ledger': ['CREATE', 'WRITE', 'ABANDON'],
     'calls': {'CREATE': 1, 'WRITE': 2, 'COMMIT': 0, 'ABANDON': 1, 'reboot': 0},
     'signs': 0, 'publishes': 0, 'restarts': ['ABANDON_INTENT']},
    {'name': 'M0 and B0', 'attempt': 5, 'grants': [],
     'faults': [fault('m0-commit', 'cross', 'COMMIT', 1, 'loss-before'),
                fault('b0-abandon', 'cross', 'ABANDON', 1, 'loss-before')],
     'end': 'CLOSED_FAILED', 'ledger': ['CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'ABANDON'],
     'calls': {'CREATE': 1, 'WRITE': 2, 'COMMIT': 0, 'ABANDON': 1, 'reboot': 0},
     'signs': 0, 'publishes': 0, 'restarts': ['COMMIT_INTENT', 'ABANDON_INTENT', 'ABANDON_INTENT']},
)


# The cohort refusal: a second plan whose cohort T0's facts contradict closes before any crossing.
COHORT_REFUSAL = {'name': 'cohort refusal', 'end': 'VOID', 'cause': 'VOID_BASE', 'ledger': [], 'faults': [],
                  'calls': {'CREATE': 0, 'WRITE': 0, 'COMMIT': 0, 'ABANDON': 0, 'reboot': 0},
                  'signs': 0, 'publishes': 0, 'restarts': []}

KEYS = {'name', 'attempt', 'grants', 'faults', 'end', 'ledger', 'calls', 'signs', 'publishes', 'restarts'}
CALLS = ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'reboot')


def check_spec(spec):
    """Refuses one attempt of no known form: every key, each fault of a known kind, every
    prediction complete and of known names."""
    if not isinstance(spec, dict) or set(spec) != KEYS or type(spec['attempt']) is not int or spec['attempt'] < 1:
        raise ValueError('a cell of no known form')
    # Attempt 1's grants are the plan's own; a later attempt names what it gets beside a fresh STAGE.
    if (spec['attempt'] == 1 and spec['grants'] != []) or not set(spec['grants']) <= {'SIGN', 'ACTIVATE'}:
        raise ValueError('grants of no known form: %s' % spec['name'])
    cells = [item.get('cell') for item in spec['faults']]
    if len(set(cells)) != len(cells):
        raise ValueError('a fault named twice in %s' % spec['name'])
    for item in spec['faults']:
        if set(item) != {'cell', 'on', 'crossing', 'occurrence', 'mode'} or not isinstance(item['cell'], str) or not item['cell']:
            raise ValueError('a fault record of no known form: %s' % item)
        if item['on'] not in ('host', 'cross') or item['mode'] not in lab_broker.CELL_MODES[item['on']]:
            raise ValueError('a fault of no known place or mode: %s' % item)
        crossings = ('SIGN', 'PUBLISH') if item['on'] == 'host' else ('CREATE', 'WRITE', 'COMMIT', 'ABANDON', 'REBOOT', 'NOTICE')
        if item['mode'] == 'loss-between-members' and item['crossing'] != 'WRITE':
            raise ValueError('only WRITE has two members: %s' % item)
        occurrences = (1, 2) if item['on'] == 'host' else range(1, 100)
        if (item['crossing'] not in crossings or type(item['occurrence']) is not int
                or item['occurrence'] not in occurrences):
            raise ValueError('a fault on no known crossing or occurrence: %s' % item)
    if (spec['end'] not in TERMINAL or not isinstance(spec['ledger'], list) or not set(spec['ledger']) <= set(CROSSINGS)
            or not isinstance(spec['restarts'], list) or any(state not in RESTART_WAITS for state in spec['restarts'])):
        raise ValueError('a prediction of no known form: %s' % spec['name'])
    if (set(spec['calls']) != set(CALLS) or any(type(n) is not int or n < 0 for n in spec['calls'].values())
            or any(type(spec[k]) is not int or spec[k] < 0 for k in ('signs', 'publishes'))):
        raise ValueError('a prediction names every native call and its host calls by count: %s' % spec['name'])
    return True


def check_sequence(sequence=SEQUENCE):
    """Refuses a sequence of no known form: attempts in order from 1, each named once, each fault
    named once across the sequence (the broker refuses a reused cell name), every attempt well formed."""
    names, seen = set(), set()
    for index, spec in enumerate(sequence, 1):
        check_spec(spec)
        if spec['attempt'] != index or spec['name'] in names:
            raise ValueError('attempts in order from 1, each named once')
        names.add(spec['name'])
        for item in spec['faults']:
            if item['cell'] in seen:
                raise ValueError('a fault named twice in the sequence: %s' % item['cell'])
            seen.add(item['cell'])
    return True
