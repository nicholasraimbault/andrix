# SPDX-License-Identifier: Apache-2.0
"""The health baselines of the next campaign profile, host side: what a baseline holds, which one
a probe may rely on, and each serial's expected SystemUI identity.

There are two kinds, kept apart as the contract asks:

- **A health baseline** is one user's process, history and current error baseline: the genuine
  main SystemUI process from full_users.py's discovery over a whole typed inventory, with its PID,
  start ticks, UID and context, and the exit history and current errors of the witness reader of
  section 5.4, a later part's hook. It is complete only with the process present and both witness
  parts read whole. The broker reads it between generations, outside any round, and keeps it as a
  compound group with its raw captures.
- **An identity baseline** is each listed user's expected identity, the UID, app ID and exact
  context of its main SystemUI process, read while the factory copy is active. The first qualified
  identity of a serial stands; a later read that differs is kept as a conflict and never redefines
  it, and no boot or framework change touches it.

Which health baseline a probe relies on, `select`:

- Only whole reads count. A read that was unavailable, refused or stopped never replaces the last
  whole one, and the last whole one before the probe's limit is the one relied on; an incomplete
  one relies on nothing.
- It must be of the probe's boot and framework instance: a new boot or framework invalidates an
  older one, whose process continuity may be lost.
- It must have completed by the window's start, unless the user was newly unlocked in the window:
  when a whole user listing in the window's boot, after the window began and before the user's
  first observed unlock, showed the user locked, stopped or absent, the user's span starts at the
  latest such listing, as the reconciler judges it (Reconciler.java:1084-1094). The baseline must
  then begin at or after that listing and complete before the user's first full probe in the
  window. Nothing taken later rescues a window: a baseline after the first probe relies on
  nothing, so a convenient new process never erases the doubt of the original one."""
import full_users
import health_records as records
import lab_actions
import lab_readers

NOT_ADMITTED = {'status': 'NOT_ADMITTED'}
BEFORE_WINDOW, NEWLY_UNLOCKED = 'BEFORE_WINDOW', 'NEWLY_UNLOCKED'
UNLOCKED = 'RUNNING_UNLOCKED'


class BaselineReader:
    """One user's health baseline through the reader's bound run function. `witness` is the
    witness reader's hook, a later part's: an object with `allowed(command)` and
    `baseline(run, context)` giving the history and current error parts. Without it both parts
    are NOT_ADMITTED and the baseline is never complete."""

    def __init__(self, witness=None):
        self.witness = witness

    def allowed(self, command):
        return full_users.read_allowed(command) or (self.witness is not None and self.witness.allowed(command))

    def read(self, run, context):
        """{'user', 'serial', 'facts'}. A read that does not complete whole raises, so it is kept
        unavailable and never replaces the last whole baseline."""
        user, serial = context['user'], context['serial']
        reader = full_users.UserReader(run)
        inventory = reader.inventory()
        found = full_users.find(inventory, user)
        if not inventory['whole'] or len(found) != 1 or found[0]['serial'] != serial:
            raise lab_readers.Unavailable('a whole inventory does not list the user with its serial')
        processes = reader.processes(inventory)
        joined = [u for u in processes['users'] if (u['user'], u['serial']) == (user, serial)]
        if len(joined) != 1:
            raise full_users.FormError('the process discovery does not list the user once')
        history, current = NOT_ADMITTED, NOT_ADMITTED
        if self.witness is not None:
            history, current = self.witness.baseline(run, dict(context, processes=processes))
        process = joined[0]['process']
        facts = {'schema': records.BASELINE_FACTS, 'user': user, 'serial': serial, 'state': found[0]['state'],
                 'app_id': processes['app_id'], 'uid': joined[0]['uid'], 'process': process,
                 'absent': processes['absent'], 'history': history, 'current_errors': current,
                 'complete': (process is not None and found[0]['state'] in lab_actions.RUNNING
                              and history.get('status') == 'OK' and current.get('status') == 'OK')}
        why = records.baseline_facts_problem(facts, user, serial)
        if why is not None:
            raise full_users.FormError(why)
        return {'user': user, 'serial': serial, 'facts': facts}


def first_unlock(listings, user, serial):
    """When a whole listing of the boot first showed the user unlocked, or None."""
    times = [elapsed for elapsed, states in listings if states.get((user, serial)) == UNLOCKED]
    return min(times) if times else None


def span_start(listings, window, user, serial):
    """Where the user's span starts, as the reconciler judges it: the window's start, or the
    latest whole listing before the user's first observed unlock when that unlock came after the
    window began."""
    start = window['start']
    unlocked = first_unlock(listings, user, serial)
    if unlocked is not None and unlocked > window['start']:
        for elapsed, _ in listings:
            if elapsed < unlocked:
                start = max(start, elapsed)
    return start


def select(baselines, listings, probes, window, user, serial, instance):
    """The baseline a probe of one user in its window may rely on: (its group, its rule) or
    (None, why). `baselines` are the user's whole baseline groups of the window's boot in ledger
    order, `listings` that boot's whole user listings as (elapsed, {(user, serial): state}),
    `probes` the begin times of the user's probes in the window, this one included, and
    `instance` the probe's framework instance."""
    start = span_start(listings, window, user, serial)
    whole = [b for b in baselines if b.get('status') == 'facts' and b.get('brackets')]
    if start == window['start']:
        rule = BEFORE_WINDOW
        candidates = [b for b in whole if b['brackets']['end']['elapsed'] <= window['start']]
        if not candidates:
            return None, 'no whole baseline completed by the window start'
    else:
        rule = NEWLY_UNLOCKED
        first = min(probes) if probes else None
        candidates = [b for b in whole if b['brackets']['begin']['elapsed'] >= start
                      and (first is None or b['brackets']['end']['elapsed'] <= first)]
        if not candidates:
            return None, ('the user was newly unlocked in the window, and no whole baseline was taken after it '
                          'and before its first full probe')
    chosen = candidates[-1]
    if chosen['brackets']['instance'] != instance:
        return None, 'a later framework instance invalidates the last whole baseline'
    facts = (chosen.get('projection') or {}).get('facts')
    if records.baseline_facts_problem(facts, user, serial) is not None:
        return None, 'the last whole baseline is of no known form'
    if not facts['complete']:
        return None, ('the last whole baseline is incomplete: %s' % (
            'no main SystemUI process' if facts['process'] is None else 'the witness parts were not read whole'))
    return chosen, rule


def identity_projection(factory, active, inventory, processes):
    """An identity baseline's projection from the facts and readings one bracket read: the
    factory and active copies' facts, a whole typed inventory and the process discovery over it.
    Qualified only with the factory copy active, its bytes the factory's, and the system user's
    process the one the active read names; then each listed user's process is its serial's
    expected identity."""
    def refused(why, active_value=None):
        return {'qualified': False, 'why_not': why, 'active': active_value, 'identities': []}
    if factory is None or active is None or inventory is None or processes is None:
        return refused('a read of the identity baseline is not whole')
    if active['classification'] != 'FACTORY_COPY':
        return refused('the factory copy is not active')
    current = {'apk': active['facts']['apk'], 'factory_apk': factory['facts']['apk'], 'uid': active['facts']['uid'],
               'context': active['facts']['context']}
    if current['apk'] != current['factory_apk']:
        return refused("the active bytes are not the factory copy's", current)
    if not inventory['whole']:
        return refused('the user inventory is not whole', current)
    identities = []
    for u in processes['users']:
        p = u['process']
        if p is None:
            continue
        identities.append({'user': u['user'], 'serial': u['serial'], 'uid': p['uid'], 'app_id': processes['app_id'],
                           'context': p['context'], 'name': p['name'], 'comm': p['comm']})
    system = [i for i in identities if i['user'] == 0]
    if len(system) != 1 or (system[0]['uid'], system[0]['context']) != (current['uid'], current['context']):
        return refused("the system user's process is not the one the active read names", current)
    return {'qualified': True, 'why_not': None, 'active': current, 'identities': identities}


def expected(identities, projection):
    """The expected identities after one more identity baseline: each serial's first qualified
    identity stands. Returns (the new map, the serials whose identity the projection contradicts).
    `identities` maps a serial to its identity and is not changed."""
    found, conflicts = dict(identities), []
    if not projection['qualified']:
        return found, conflicts
    for identity in projection['identities']:
        first = found.get(identity['serial'])
        if first is None:
            found[identity['serial']] = identity
        elif first != identity:
            conflicts.append(identity['serial'])
    return found, sorted(conflicts)
