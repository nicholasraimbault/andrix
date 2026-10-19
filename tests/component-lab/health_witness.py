# SPDX-License-Identifier: Apache-2.0
"""The crash and ANR witness of the health composition's criterion bit 1, host side: an identity
and time join of the process history reader's replies with the genuine main SystemUI process that
full_users.py's discovery identifies, and the reader that fills the composer's bit 1 hook and the
baseline reader's witness hook.

**One read.** Between two reads of the boot ID and of the framework instance (system_server's start
ticks), the user's main SystemUI process is discovered, the helper of process_health.py reads the
exit history and the current error list, and the process is discovered again. A read whose boot or
framework changed, whose discovery or reply is not whole, or whose helper is not the pinned one is
no evidence.

**Baselines.** Each baseline keeps the whole sets the helper read, not a latest time. A probe judges
only against repeated whole baselines taken before its window opens (health_baseline.eligible), at
least BASELINE_REPEATS of them, in its boot and framework instance, the last of them the one the
probe relies on. Their rows and reports are the old sets. An earlier baseline that is no whole
repeat, read while the process was absent or by another reader, never vetoes later whole ones: the
first adds its rows and reports to the old sets, the second is passed over.

**The birth identity.** The relied baseline's process: boot, framework instance, user, serial, UID,
PID, start ticks, exact process name and context. A current report joins it, or a later process of
the user, only by UID, user, serial, process name, PID and start ticks, the same before and after
the call. A process that is gone keeps its last identified identity and the interval in which it
went: after the last read that saw it living, by the first read that saw it gone. The probes'
earlier witness decisions and HELD rows of this boot, which the broker passes with each probe's own
recorded helper reply, give those reads. Each reply is read again whatever its probe decided: its
samples are the boot's clock, a partial read's included, and its whole history part is an earlier
observation. A held probe carries no decision and saw the identity living; a probe that judged
nothing, as its helper's read was partial, still discovered the process whole before and after the
call, which counts once the relied baseline has read the identity living.

**Each discovery state.** A discovery before the call is placed at the helper's first sample, one
after it at the last. Found before and after the call, the identity lived at the last sample; found
before it only, it lived at the first and was gone by the last; found neither time, it was gone by
the first. Found after the call only, it lived at the last sample, but its absence before the call
after reads that found it is an identity contradiction, which never supplies a join. So is a
baseline that misses it between baselines that find it. A read that finds it living after one that
found it gone refuses the join.

**The window.** A failure is the health window's only when it happened inside it. An exit row must
be placed after the window's start and before its end, beyond the scale tolerance at both, on the
probes' elapsed scale in which the broker passes the window, and the window must be the relied
baseline's boot. A row placed between the last baseline and the window's start is a prewindow exit:
it keeps a living read from holding, as any row new since the baselines does, but it is no newly
induced failure. Neither is a loss already seen before the window opened. A window that is missing,
of no known form or of another boot places no row.

**Decisions.** One of QUALIFIED_CURRENT_ERROR, QUALIFIED_LIFECYCLE_JOIN, PENDING and INCONCLUSIVE,
with its exact exclusions, or none when the row holds:

- QUALIFIED_CURRENT_ERROR: exactly one new CRASHED or NOT_RESPONDING report of the identified living
  process, in no baseline, and absent from an earlier read inside the window that found the same
  process living before and after its call, with a current list that covered it: a whole reply,
  whose history part shows the shell's DUMP for that read, so that its list was not filtered to
  the shell's own UID, for the shell's own user or with INTERACT_ACROSS_USERS_FULL qualified. An
  empty list alone shows nothing absent. A report carries no time, so one first seen otherwise may
  have begun before the window opened: it is INCONCLUSIVE, which prevents a hold but is no newly
  induced failure. The row is BAD, a witnessed failure, never a partial hold.
- QUALIFIED_LIFECYCLE_JOIN: the birth identity gone, exactly one new exit row agreeing on every
  identity field with reason CRASH, CRASH_NATIVE or ANR, placed in time after the identity was last
  seen living, no later than the first read that saw it gone and inside the health window, never a
  record any earlier read showed with other contents, however often its new contents are read
  again, and independent evidence that it belongs to this boot. History is a bounded, asynchronous
  record kept in wall time, and no inspected source gives a safe maximum publication delay, so a
  new publication or a late wall time is no such evidence. No reader of this part supplies it: the
  `freshness` hook stays empty until a later part qualifies one.
- PENDING: the identity gone with no qualified row yet, or with one but without independent
  evidence, within the declared bound after the loss. With nothing stronger, INCONCLUSIVE after it.
- INCONCLUSIVE: anything else that is not clean. A late row from before the identity was last seen
  living, an updated reason or time of an earlier row, a wall clock offset change, another boot or
  framework, a reused PID, another user, UID or process, a reason such as LOW_MEMORY, SIGNALED or
  USER_STOPPED, duplicate candidates, a report already in a baseline or not shown to begin in the
  window, an identity contradiction, a prewindow exit or loss, missing or partial evidence.

The row holds only when the birth identity lives before and after the call, the user's SystemUI
exit history is the baselines', no report relates to the user's SystemUI now or in a baseline (a
baseline error prevents a hold even once cleared), in a current list that covers the user: the
shell's own user, whose DUMP the whole history read shows
(ActivityManagerService.java:11184-11205), or another user once the shell's
INTERACT_ACROSS_USERS_FULL is qualified (`cross_user`; ActivityManagerService.java:10865-10879).
Missing or ambiguous evidence is INCONCLUSIVE, a row the composition classifies INCONCLUSIVE, never
CRASH, so it never starts a restoration. A host test shows this join on source derived forms; no
Android form is qualified."""
import re

import full_users
import health_compose
import health_records
import lab_readers
import process_health
from scripts.proof import systemui_sessions as readback

SCHEMA = 'andrix-witness-decision-v1'
DECISIONS = ('QUALIFIED_CURRENT_ERROR', 'QUALIFIED_LIFECYCLE_JOIN', 'PENDING', 'INCONCLUSIVE')
DECISION_KEYS = ('schema', 'decision', 'exclusions', 'user', 'serial', 'birth', 'observed', 'living', 'loss',
                 'pending_until', 'old', 'new_rows', 'errors', 'qualified', 'freshness')
BIT = health_compose.NO_CRASH_OR_ANR
BOOT_ID = 'cat /proc/sys/kernel/random/boot_id'
FRAMEWORK_PID = 'pidof system_server'
_STAT = re.compile(r'cat /proc/[1-9][0-9]{0,6}/stat')
# The exit reasons that may qualify a lifecycle join: CRASH, CRASH_NATIVE and ANR
# (core/java/android/app/ApplicationExitInfo.java:105-115).
QUALIFIED_REASONS = (4, 5, 6)
# The shell's own user, whose processes the current list holds without INTERACT_ACROSS_USERS_FULL.
SHELL_USER_ID = 0
STATES = ('ALIVE', 'GONE', 'WENT', 'UNKNOWN')
OBSERVED_KEYS = ('boot', 'instance', 'state', 'uid', 'before', 'after', 'samples')
# Declared values, not measured ones. The pending bound is the exit tracker's own window in which a
# record's reason may still be updated (services/core/java/com/android/server/am/
# AppExitInfoTracker.java:511-516, 1803-1818). The offset tolerance bounds the drift of the wall
# clock against the elapsed time between the baselines and a probe, and the scale tolerance the
# disagreement of SystemClock.elapsedRealtime with /proc/uptime, both counted since boot.
BASELINE_REPEATS = 2
PENDING_BOUND_MS = 300_000
OFFSET_TOLERANCE_MS = 2_000
SCALE_TOLERANCE_MS = 1_000
PART_READING_KEYS = ('boot', 'instance', 'user', 'serial', 'uid', 'process', 'sha256', 'samples')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')


def allowed(command):
    """Whether a command is one of the witness's fixed reads: the boot ID, the framework instance,
    the full user reads and the process health helper's bracketed invocation."""
    return (command in (BOOT_ID, FRAMEWORK_PID) or bool(_STAT.fullmatch(command)) or full_users.read_allowed(command)
            or process_health.read_allowed(command))


def _boot(run):
    code, stdout, stderr = run(BOOT_ID)
    if stderr != '':
        raise lab_readers.Unclassified('a boot ID read with an error')
    try:
        return readback.boot_id(code, stdout)
    except ValueError as error:
        raise lab_readers.Unclassified(str(error)) from error


def _framework(run):
    """(system_server's PID, its start ticks): the framework instance on the observer's scale."""
    code, stdout, stderr = run(FRAMEWORK_PID)
    try:
        if stderr != '':
            raise ValueError('a framework read with an error')
        pid = readback.single_pid(code, stdout)
        code, stdout, stderr = run('cat /proc/%d/stat' % pid)
        if stderr != '':
            raise ValueError('a framework read with an error')
        return pid, readback.start_ticks(code, stdout, pid, 'system_server')
    except ValueError as error:
        raise lab_readers.Unavailable('no running framework read: %s' % error) from error


def identity(processes, user, serial):
    """(the user's package UID, its genuine main SystemUI process as [PID, start ticks, UID,
    context] or None) in one process discovery. A user it does not list has neither."""
    found = [u for u in processes['users'] if (u['user'], u['serial']) == (user, serial)]
    if len(found) > 1:
        raise lab_readers.Unclassified('a user listed twice')
    if not found:
        return None, None
    p = found[0]['process']
    return found[0]['uid'], None if p is None else [p['pid'], p['start_ticks'], p['uid'], p['context']]


def observe(run, user, serial):
    """One read of the user's SystemUI and the helper's two parts, between two reads of the boot
    and of the framework: {'boot', 'instance', 'user', 'serial', 'uid', 'before', 'after',
    'reading'}. A boot or framework that changed, or a package UID that changed, is unavailable."""
    boot = _boot(run)
    framework = _framework(run)
    reader = full_users.UserReader(run)
    inventory = reader.inventory()
    uid, before = identity(reader.processes(inventory), user, serial)
    reading = process_health.read(run, user)
    uid_after, after = identity(reader.processes(inventory), user, serial)
    if _framework(run) != framework:
        raise lab_readers.Unavailable('the framework restarted during the read')
    if _boot(run) != boot:
        raise lab_readers.Unavailable('the device rebooted during the read')
    if uid != uid_after:
        raise lab_readers.Unavailable("the user's SystemUI package UID changed during the read")
    return {'boot': boot, 'instance': framework[1], 'user': user, 'serial': serial, 'uid': uid, 'before': before,
            'after': after, 'reading': reading}


def part_problem(part, kind):
    """Why a baseline's history or current error part is not this reader's whole reading, or
    None. `kind` is 'history' or 'current'."""
    if not isinstance(part, dict) or set(part) != {'status', 'schema', 'reading'} or part['status'] != 'OK':
        return 'a baseline part that is not a whole reading'
    if part['schema'] != process_health.SCHEMA:
        return "a baseline part of another reader's schema"
    r = part['reading']
    keys = PART_READING_KEYS + (('rows',) if kind == 'history' else ('returned', 'entries'))
    if not isinstance(r, dict) or set(r) != set(keys):
        return 'a baseline reading has exactly its keys'
    if (not isinstance(r['boot'], str) or not _UUID.fullmatch(r['boot']) or type(r['instance']) is not int
            or type(r['user']) is not int or type(r['serial']) is not int or type(r['uid']) is not int):
        return 'a baseline reading names its boot, framework, user, serial and UID'
    p = r['process']
    if p is not None and (not isinstance(p, list) or len(p) != 4 or not all(type(v) is int for v in p[:3])
                          or not isinstance(p[3], str) or p[2] != r['uid']):
        return 'a baseline reading names its process, or none'
    reading = {'user': r['user'], 'complete': True, 'sha256': r['sha256'],
               'history': {'status': 'OK', 'reason': None, 'samples': r['samples'], 'rows': r.get('rows', [])},
               'current': {'status': 'OK', 'reason': None, 'samples': r['samples'], 'returned': r.get('returned', 'null'),
                           'entries': r.get('entries', [])}}
    return process_health.reading_problem(reading)


def baseline_parts(observation, serial):
    """A whole read's history and current error parts, for a baseline's facts."""
    reading = observation['reading']
    common = {'boot': observation['boot'], 'instance': observation['instance'], 'user': observation['user'],
              'serial': serial, 'uid': observation['uid'], 'process': observation['after'],
              'sha256': reading['sha256']}
    history = dict(common, samples=reading['history']['samples'], rows=reading['history']['rows'])
    current = dict(common, samples=reading['current']['samples'], returned=reading['current']['returned'],
                   entries=reading['current']['entries'])
    return ({'status': 'OK', 'schema': process_health.SCHEMA, 'reading': history},
            {'status': 'OK', 'schema': process_health.SCHEMA, 'reading': current})


def _key(row):
    """The identity of an exit record: PID, real, package and defining UID and process name."""
    return (row[1], row[2], row[3], row[4], row[6])


def _entry_key(entry):
    return (entry[0], entry[1], entry[2], entry[3])


def _name(token):
    return process_health.decode_text(token)


def _relates(entry, user, uid):
    """Whether a current report is about the user's SystemUI: its package UID, or a SystemUI process
    name in the user's UID range."""
    name = _name(entry[3]) or ''
    systemui = name == process_health.PACKAGE or name.startswith(process_health.PACKAGE + ':')
    return entry[2] == uid or (systemui and entry[2] // full_users.PER_USER_RANGE == user)


def _row_identity_problem(row, birth):
    """Why an exit row does not agree with the birth identity on every field, or None."""
    if row[1] != birth['pid']:
        return 'another PID'
    if row[5] != birth['user'] or row[3] // full_users.PER_USER_RANGE != birth['user']:
        return 'another user'
    if (row[2], row[3], row[4]) != (birth['uid'],) * 3:
        return 'another UID'
    if _name(row[6]) != process_health.PACKAGE:
        return 'another process'
    return None


def _state(before, after, born):
    """The birth identity in one read's discovery before and after the helper's call: ALIVE in
    both, WENT when only the first found it, UNKNOWN when only the second did, else GONE."""
    return ('ALIVE' if before == born and after == born else 'WENT' if before == born
            else 'UNKNOWN' if after == born else 'GONE')


def _decision(user, serial):
    return {'schema': SCHEMA, 'decision': None, 'exclusions': [], 'user': user, 'serial': serial, 'birth': None,
            'observed': None, 'living': None, 'loss': None, 'pending_until': None, 'old': None, 'new_rows': [],
            'errors': [], 'qualified': None, 'freshness': None}


def decision_problem(decision):
    """Why a witness decision is not of this reader's exact form, or None."""
    if not isinstance(decision, dict) or set(decision) != set(DECISION_KEYS) or decision['schema'] != SCHEMA:
        return 'a witness decision of another form'
    if decision['decision'] not in DECISIONS or not isinstance(decision['exclusions'], list):
        return 'a witness decision of no known decision'
    observed = decision['observed']
    if observed is not None and (not isinstance(observed, dict) or set(observed) != set(OBSERVED_KEYS)
                                 or observed['state'] not in STATES or not _samples(observed['samples'])
                                 or not all(_process(observed[k]) for k in ('before', 'after'))):
        return 'a witness decision of no known observation'
    return None


def _process(value):
    """Whether a discovered process is none or [PID, start ticks, UID, context]."""
    return value is None or (isinstance(value, list) and len(value) == 4 and all(type(v) is int for v in value[:3])
                             and isinstance(value[3], str))


def _window_problem(window, boot):
    """Why a health window as the broker passes it is not this boot's whole window, on the probes'
    elapsed scale, or None. `boot` is the relied baseline's bracket boot, in the broker's own form:
    the baselines' readings are this read's boot, so a window of that boot is this read's too."""
    if (not isinstance(window, dict) or not {'boot', 'start', 'end'} <= set(window) or type(window['start']) is not int
            or type(window['end']) is not int or not 0 <= window['start'] < window['end']):
        return 'a health window of no known form'
    if not isinstance(boot, str) or window['boot'] != boot:
        return 'a health window of another boot than the baselines'
    return None


def _samples(samples):
    return (isinstance(samples, list) and len(samples) == 4
            and all(isinstance(s, list) and len(s) == 2 and all(type(v) is int for v in s) for s in samples))


def _foreign(part):
    """Whether a baseline part is none of this reader's: NOT_ADMITTED, or another reader's."""
    return not isinstance(part, dict) or part.get('status') != 'OK' or part.get('schema') != process_health.SCHEMA


def _usable(context, user, serial):
    """(the baselines before the window this reader judges against, as (digest, brackets, facts,
    history, current) in order, why not). A baseline whose parts are another reader's or none is
    passed over. One whose facts are incomplete, its process absent, keeps its rows and reports in
    the old sets but is no repeat, so an older incomplete baseline never vetoes later whole ones. A
    reading that contradicts its own baseline refuses them all. At least BASELINE_REPEATS complete
    ones of the relied one's framework instance are needed, the relied one, complete, last."""
    relied = context.get('baseline')
    if relied is None:
        return None, 'no valid baseline relied on'
    eligible = context.get('baselines') or []
    if not eligible or eligible[-1].get('digest') != relied['digest']:
        return None, 'the relied baseline is not the last whole one before the window'
    found = []
    for b in eligible:
        facts = (b.get('projection') or {}).get('facts')
        if health_records.baseline_facts_problem(facts, user, serial) is not None:
            return None, 'a baseline before the window of no known form'
        if _foreign(facts['history']) or _foreign(facts['current_errors']):
            continue
        for kind, name in (('history', 'history'), ('current', 'current_errors')):
            why = part_problem(facts[name], kind)
            if why is not None:
                return None, 'a baseline before the window has no whole witness reading: %s' % why
        history, current = facts['history']['reading'], facts['current_errors']['reading']
        process = facts['process']
        own = None if process is None else [process['pid'], process['start_ticks'], process['uid'], process['context']]
        shared = [k for k in PART_READING_KEYS if k != 'samples']
        if ({k: history[k] for k in shared} != {k: current[k] for k in shared} or history['process'] != own
                or (history['user'], history['serial']) != (user, serial)):
            return None, "a baseline's witness reading is not its own process's"
        brackets = b['brackets']
        if history['instance'] != brackets['instance'] or not _within(history['samples'] + current['samples'],
                                                                      brackets):
            return None, "a baseline's witness reading is not on its bracket's framework and elapsed scale"
        found.append((b['digest'], brackets, facts, history, current))
    if not found or found[-1][0] != relied['digest'] or not found[-1][2]['complete']:
        return None, "the relied baseline is not this reader's whole reading"
    instance = found[-1][1]['instance']
    found = [f for f in found if f[1]['instance'] == instance]
    repeats = [f for f in found if f[2]['complete']]
    if len(repeats) < BASELINE_REPEATS:
        return None, 'the baseline was not repeated before the window: %d whole of %d' % (len(repeats),
                                                                                         BASELINE_REPEATS)
    return found, None


def _within(samples, brackets):
    begin, end = brackets['begin']['elapsed'], brackets['end']['elapsed']
    return all(begin - SCALE_TOLERANCE_MS <= s[0] <= end + SCALE_TOLERANCE_MS for s in samples)


def _seen_without(context, observation, live, born, key, window):
    """Whether an earlier read inside the window, of this framework, found the same process living
    before and after its call, with a current error list that covered it and did not hold this
    report: what shows that a current report began inside the window. Only a read of the trail
    whose own recorded helper reply is read again whole and on its bracket's scale counts: a held
    probe, which found the birth identity living with no report of the user's SystemUI, or a
    decision whose discovery found this process before and after its call. The caller has already
    required the user's coverage."""
    for entry in context.get('trail') or []:
        brackets = entry['brackets']
        if brackets['instance'] != observation['instance'] or brackets['begin']['elapsed'] < window['start']:
            continue
        earlier, again = entry['decision'], _again(entry, context['user'])
        # Without DUMP the list silently leaves out every UID but the shell's own, and is then null
        # just as a clean list is (ActivityManagerService.java:10870-10881). The same reply's whole
        # history part, which SystemUI's history gives only with DUMP (11196-11205), shows that this
        # read's list was not so filtered: an empty list alone never shows a report absent.
        if again is None or not again['complete']:
            continue
        replied = again['history']['samples'] + again['current']['samples']
        if not _within(replied, brackets):
            continue
        if earlier is None:
            if entry['status'] != 'HELD' or not again['complete'] or live != born:
                continue
        else:
            seen = earlier['observed'] if decision_problem(earlier) is None else None
            if (seen is None or seen['samples'] != replied or seen['before'] != live or seen['after'] != live
                    or (seen['boot'], seen['instance']) != (observation['boot'], observation['instance'])):
                continue
        if all(_entry_key(e) != key for e in again['current']['entries']):
            return True
    return False


def _again(entry, user):
    """An earlier probe's own recorded helper reply read again: its reading, or None when the
    probe recorded none, more than one, or one of no known form."""
    replies = entry.get('helper') or []
    if len(replies) != 1:
        return None
    try:
        code, stdout, stderr = replies[0]
        return process_health.parse_reply(code, stdout, stderr, user)
    except (lab_readers.Unavailable, lab_readers.Unclassified, ValueError, TypeError):
        return None


def judge(observation, failure, context, cross_user=False, freshness=None, bound_ms=PENDING_BOUND_MS):
    """Bit 1 from one read and its context: (status, reason, decision). The status is HELD with
    no decision, BAD with a qualified one, or UNKNOWN with PENDING or INCONCLUSIVE and its exact
    exclusions, the reason being the first. `failure` is why the read gave no observation, or
    None."""
    user, serial = context['user'], context['serial']
    d = _decision(user, serial)

    def unknown(reasons, name='INCONCLUSIVE'):
        for reason in reasons:
            if reason not in d['exclusions']:
                d['exclusions'].append(reason)
        d['decision'] = name
        return 'UNKNOWN', d['exclusions'][0], d
    if failure is not None:
        return unknown(['the read is no evidence: %s' % failure])
    reading = observation['reading']
    samples = reading['history']['samples'] + reading['current']['samples']
    d['observed'] = {'boot': observation['boot'], 'instance': observation['instance'], 'state': 'UNKNOWN',
                     'uid': observation['uid'], 'before': observation['before'], 'after': observation['after'],
                     'samples': samples}
    for name, part in (('exit history', reading['history']), ('current error list', reading['current'])):
        if part['status'] != 'OK':
            return unknown(['the %s was not read whole: %s %s, never zero rows' % (name, part['status'],
                                                                                  part['reason'])])
    baselines, why = _usable(context, user, serial)
    if why is not None:
        return unknown([why])
    history = baselines[-1][3]
    birth = {'boot': history['boot'], 'instance': history['instance'], 'user': user, 'serial': serial,
             'uid': history['uid'], 'pid': history['process'][0], 'start_ticks': history['process'][1],
             'process': process_health.PACKAGE, 'context': history['process'][3]}
    d['birth'] = birth
    old_rows = [list(r) for b in baselines for r in b[3]['rows']]
    old_entries = [list(e) for b in baselines for e in b[4]['entries']]
    old_errors = {_entry_key(e) for e in old_entries}
    d['old'] = {'baselines': [b[0] for b in baselines], 'rows': len(old_rows), 'errors': len(old_errors)}
    if any(b[3]['boot'] != observation['boot'] for b in baselines):
        return unknown(['another boot than the baselines: no identity continues across a boot'])
    if any(b[3]['instance'] != observation['instance'] for b in baselines):
        return unknown(['another framework instance than the baselines'])
    uid = birth['uid']
    if observation['uid'] is not None and observation['uid'] != uid:
        return unknown(["the user's SystemUI package UID is not the baselines'"])
    born = [birth['pid'], birth['start_ticks'], uid, birth['context']]
    before, after = observation['before'], observation['after']
    state = _state(before, after, born)
    d['observed']['state'] = state
    if state == 'UNKNOWN':
        return unknown(['the identity was seen again after it was gone'])
    live = after if after is not None and before == after else None
    new_rows = [r for r in reading['history']['rows'] if r not in old_rows]
    related = [e for e in reading['current']['entries'] if _relates(e, user, uid)]
    d['new_rows'], d['errors'] = new_rows, related
    exclusions = []
    # A current report: joined to the process discovered living before and after the call.
    joined = [e for e in related if live is not None and (e[1], e[2]) == (live[0], live[2])
              and _name(e[3]) == process_health.PACKAGE]
    unjoined = [e for e in related if e not in joined]
    if unjoined:
        exclusions.append("a current report of the user's SystemUI that joins no process living before and after "
                          'the call')
    if len(joined) > 1:
        exclusions.append('duplicate candidates: %d current reports of one process' % len(joined))
    elif joined and _entry_key(joined[0]) in old_errors:
        exclusions.append('a current report already present in a baseline: no newly induced failure, and no hold')
    elif joined and joined[0][0] not in process_health.CONDITIONS:
        exclusions.append('a current report of no known condition')
    elif joined:
        # A report carries no time: it is the window's new failure only when an earlier read inside
        # the window found the same process living without it. One first seen otherwise may have
        # begun before the window opened: it prevents a hold, but it is no newly induced failure.
        window = context.get('window')
        why = _window_problem(window, baselines[-1][1].get('boot'))
        if why is not None:
            exclusions.append('a current report, and %s: no earlier read can be placed in it' % why)
        elif user != SHELL_USER_ID and not cross_user:
            exclusions.append("a current report not shown to begin in the window: the shell's "
                              'INTERACT_ACROSS_USERS_FULL is not qualified, so no read shows it absent')
        elif not _seen_without(context, observation, live, born, _entry_key(joined[0]), window):
            exclusions.append('a current report not shown to begin in the window: no earlier read in it found '
                              'its process living without it')
        else:
            d['qualified'], d['decision'], d['exclusions'] = joined[0], 'QUALIFIED_CURRENT_ERROR', exclusions
            return 'BAD', ('a new current %s report of the identified living process, absent from an earlier '
                           'read of it in the window' % process_health.CONDITIONS[joined[0][0]]), d
    if state == 'ALIVE':
        # The exit history: a row of the baselines' sets is old, one that only changed an old
        # record's reason or time is an update, never a new exit.
        old_keys = {_key(r) for r in old_rows}
        if any(_key(r) in old_keys for r in new_rows):
            exclusions.append('an updated reason or time of an earlier exit row: never a new exit')
        for r in new_rows:
            if _key(r) in old_keys:
                continue
            exclusions.append('an exit row naming the identified process while it lives: a late row or a reused PID'
                              if _row_identity_problem(r, birth) is None
                              else "a new exit row of the user's SystemUI: its exit history is not the baselines'")
        # A baseline error prevents a hold even when the report is gone and its process lives on,
        # as a cleared ANR or a waited crash dialog leaves the same process: it is no new failure.
        if any(_relates(e, user, uid) for e in old_entries):
            exclusions.append("a report of the user's SystemUI in a baseline: no hold, and no newly induced "
                              'failure')
        if user != SHELL_USER_ID and not cross_user:
            exclusions.append("the current error list's coverage of this user is not shown: the shell's "
                              'INTERACT_ACROSS_USERS_FULL is not qualified')
        if exclusions:
            return unknown(exclusions)
        return 'HELD', '', None
    # The birth identity is gone. Its last living read and the first read that saw it gone, from the
    # baselines, the earlier probes of this boot and framework, and this read. Each earlier probe is
    # read again from its own recorded helper reply, whatever it decided: a held one keeps its clock
    # and rows that way, and a partial one its clock, its whole part and its whole discovery.
    living, first_gone, offsets, earlier_rows, doubts = [], None, [], [], []
    for b in baselines:
        if b[3]['process'] == born:
            living.append(b[4]['samples'][1][0])
        elif living:
            # Missed by a baseline after one that found it, and found again by the relied one: the
            # same identity contradiction as an earlier read's. One before them all may precede it.
            doubts.append('a baseline did not find the identity between baselines that did: an identity '
                          'contradiction, never a qualified join')
        offsets += [w - e for e, w in b[3]['samples'] + b[4]['samples']]
    relied_end = baselines[-1][1]['end']['elapsed']
    for entry in context.get('trail') or []:
        if entry['brackets']['instance'] != observation['instance']:
            continue
        begin = entry['brackets']['begin']['elapsed']
        earlier, again = entry['decision'], _again(entry, user)
        if earlier is not None and decision_problem(earlier) is not None:
            return unknown(["an earlier probe's witness decision of no known form"])
        seen = None if earlier is None else earlier['observed']
        replied = None if again is None else again['history']['samples'] + again['current']['samples']
        if seen is not None and replied != seen['samples']:
            return unknown(["an earlier probe's decision is not its own recorded helper reply"])
        held = earlier is None and entry['status'] == 'HELD'
        if held and (again is None or not again['complete']):
            return unknown(["an earlier held probe's helper reply cannot be read again: its clock is unknown"])
        if again is not None:
            # The clock is the boot's, not one identity's: every earlier reply's samples count, a
            # partial read's included, and its whole history part is an earlier observation.
            if not _within(replied, entry['brackets']):
                return unknown(["an earlier read's helper clock is not on its bracket's elapsed scale"])
            offsets += [w - e for e, w in replied]
            if again['history']['status'] == 'OK':
                earlier_rows += [list(r) for r in again['history']['rows']]
        # What that read found of the identity, each state handled: living, for a held probe; and
        # for a decision on this birth identity, or one that judged nothing, as a partial read,
        # once the relied baseline had read the identity living, what its whole discovery found
        # before and after the call. A discovery is placed at the helper's sample next to it.
        if held:
            then = 'ALIVE'
        elif (seen is not None and (earlier['birth'] == birth or (earlier['birth'] is None and begin >= relied_end))
              and (seen['boot'], seen['instance']) == (observation['boot'], observation['instance'])):
            then = _state(seen['before'], seen['after'], born)
        else:
            continue
        if then == 'GONE':
            # Found neither before nor after the call: gone by its first sample, if not before.
            if first_gone is None:
                first_gone = replied[0][0]
            continue
        # Found before the call, after it, or both: living after a read that found it gone is a
        # contradiction that no loss survives.
        if first_gone is not None:
            return unknown(['the identity was seen again after it was gone'])
        if then == 'WENT':
            # Found before the call, not after it: living at its first sample, gone by its last.
            living.append(replied[0][0])
            first_gone = replied[3][0]
        else:
            # Found after the call: living at its last sample. UNKNOWN, missed before the call
            # though a read before it found the identity living, is an identity contradiction: it
            # never supplies a join.
            living.append(replied[3][0])
            if then == 'UNKNOWN':
                doubts.append('an earlier read found the identity only after the call: an identity '
                              'contradiction, never a qualified join')
    if state == 'WENT':
        # This read found the identity before the call: living at its first sample.
        living.append(samples[0][0])
    if first_gone is None and state == 'GONE':
        first_gone = samples[0][0]
    alive_at = max(living)
    d['living'] = {'first': min(living), 'last': alive_at}
    d['loss'] = {'after': alive_at, 'by': first_gone}
    if first_gone is not None and first_gone < alive_at:
        # A read found the identity living after one that found it gone, a baseline or this read
        # after an earlier probe: no loss can be placed.
        return unknown(['the identity was seen again after it was gone'])
    # A loss seen during this read has no sampled end yet: its bound starts at the last sample.
    upper = first_gone if first_gone is not None else samples[3][0]
    pending_until = upper + bound_ms
    d['pending_until'] = pending_until
    offsets += [w - e for e, w in samples]
    if max(offsets) - min(offsets) > OFFSET_TOLERANCE_MS:
        return unknown(['a wall clock offset change: no exit row can be placed in time'] + doubts + exclusions)
    offset = samples[0][1] - samples[0][0]
    # A newly induced failure is one of the health window: its exit row must be placed inside the
    # window, which the broker passes on the probes' elapsed scale, beyond the scale tolerance at
    # both bounds. A window that is not this boot's whole window places no row, and a loss seen
    # before the window opened was no failure of it.
    window = context.get('window')
    why = _window_problem(window, baselines[-1][1].get('boot'))
    if why is not None:
        return unknown(['%s: no exit row can be placed in it' % why] + doubts + exclusions)
    opened, closed = window['start'] + SCALE_TOLERANCE_MS, window['end'] - SCALE_TOLERANCE_MS
    if upper < window['start'] - SCALE_TOLERANCE_MS:
        doubts.append('the identity was gone before the window opened: a prewindow loss, not a newly induced '
                      'failure')
    # Every row read before this one is an earlier observation, the window's first publications
    # included. A record whose identity any of them showed with other contents is an update, never
    # a new exit, however often its new contents are read again.
    seen_rows = old_rows + earlier_rows
    updates = [r for r in new_rows if any(_key(s) == _key(r) and s != r for s in seen_rows)]
    fresh = [r for r in new_rows if r not in updates]
    if updates:
        exclusions.append('an updated reason or time of an earlier exit row: never a new exit')
    birth_key = (birth['pid'], uid, uid, uid, process_health.encode_text(process_health.PACKAGE))
    if any(_key(r) == birth_key for r in updates):
        doubts.append("an updated reason or time of the identity's earlier exit row: never a new exit")
    if any((e[1], e[2]) == (birth['pid'], uid) for e in old_entries):
        doubts.append('the identity was in an error state in a baseline: no newly induced failure')
    candidates, matched = [], []
    for r in fresh:
        why = _row_identity_problem(r, birth)
        if why is not None:
            exclusions.append('an exit row of another identity: %s' % why)
            continue
        matched.append(r)
        at = r[0] - offset
        if r[7] not in QUALIFIED_REASONS:
            exclusions.append('an exit row with reason %s: not a crash or ANR'
                              % process_health.REASONS.get(r[7], 'code %d' % r[7]))
        elif at <= alive_at + SCALE_TOLERANCE_MS:
            exclusions.append('a late exit row from before the identity was last seen living')
        elif at > upper + SCALE_TOLERANCE_MS:
            # Its loss is bounded above too: a later occupant of the PID may share every field.
            doubts.append('an exit row placed after the identity was already gone: not its exit')
        elif at <= opened:
            # Between the last baseline and the window's start, or too near that start to tell: a
            # prewindow exit, which keeps the probe from holding but is no newly induced failure.
            doubts.append('an exit row placed before the window opened, or within the clock tolerance of '
                          'its start: a prewindow exit, not a newly induced failure')
        elif at >= closed:
            doubts.append('an exit row placed after the window closed, or within the clock tolerance of its '
                          'end: not a failure of the window')
        else:
            candidates.append(r)
    if len(matched) > 1:
        doubts.append('duplicate candidates: %d new exit rows for one identity' % len(matched))
    # A loss that an exit row of another reason explains, or that is ambiguous, is never pending.
    settled = bool(doubts) or any(r[7] not in QUALIFIED_REASONS for r in matched)
    if candidates and not doubts:
        evidence = freshness.fresh(candidates[0], birth, d['loss'], context) if freshness is not None else None
        if evidence is not None:
            d['qualified'], d['freshness'], d['decision'] = candidates[0], evidence, 'QUALIFIED_LIFECYCLE_JOIN'
            d['exclusions'] = exclusions
            return 'BAD', 'a unique crash or ANR exit row of the gone identity, with independent evidence of this boot', d
        exclusions.append('no independent evidence that the exit row belongs to this boot')
    elif not matched:
        exclusions.append('no qualified exit row of the gone identity was published')
    if settled or samples[3][0] > pending_until:
        return unknown(doubts + exclusions)
    return unknown(doubts + exclusions, 'PENDING')


class WitnessReader:
    """The bit 1 reader, for `Composer(witness=)` and `BaselineReader(witness=)`. `cross_user`
    says that a guest qualified the shell's INTERACT_ACROSS_USERS_FULL, so that the current list
    covers every user; `freshness` is a later part's independent evidence that an exit row belongs
    to the current boot, an object with `fresh(row, birth, loss, context)` giving its side record or
    None; `bound_ms` the declared pending bound."""

    def __init__(self, cross_user=False, freshness=None, bound_ms=PENDING_BOUND_MS):
        if type(cross_user) is not bool or type(bound_ms) is not int or bound_ms <= 0:
            raise ValueError('a witness reader with its coverage and a positive pending bound')
        self.cross_user, self.freshness, self.bound_ms = cross_user, freshness, bound_ms

    def allowed(self, command):
        return allowed(command)

    def baseline(self, run, context):
        """A baseline's history and current error parts: the helper's whole read between reads of
        the boot and the framework, with the same process, or the same absence, discovered before
        it (the baseline reader's discovery) and after it. Anything less raises, so the baseline is
        kept unavailable. A baseline without a process stays incomplete, as its facts say."""
        user, serial = context['user'], context['serial']
        uid, before = identity(context['processes'], user, serial)
        if uid is None:
            raise lab_readers.Unavailable('the discovery names no SystemUI package UID of the user')
        boot, framework = _boot(run), _framework(run)
        reading = process_health.read(run, user)
        uid_after, after = identity(full_users.UserReader(run).processes(context['inventory']), user, serial)
        if _framework(run) != framework or _boot(run) != boot:
            raise lab_readers.Unavailable('the boot or the framework changed during the baseline')
        if before != after or uid != uid_after:
            raise lab_readers.Unavailable('the main SystemUI process changed during the baseline')
        if not reading['complete']:
            raise lab_readers.Unavailable('the helper did not read both parts whole: %s, %s' % (
                reading['history']['reason'], reading['current']['reason']))
        return baseline_parts({'boot': boot, 'instance': framework[1], 'user': user, 'uid': uid, 'after': after,
                               'reading': reading}, serial)

    def read(self, calls, context):
        """Bit 1's row and decision for one composition, through the composer's counted run."""
        positions = []

        def run(command):
            positions.append(calls.count)
            return calls.run(command)
        observation, failure = None, None
        try:
            observation = observe(run, context['user'], context['serial'])
        except health_compose.ComposerError:
            raise
        except lab_readers.Unavailable as error:
            failure = 'unavailable: %s' % error
        except (lab_readers.Unclassified, ValueError, KeyError, TypeError) as error:
            failure = 'of no known form: %s: %s' % (type(error).__name__, error)
        status, reason, decision = judge(observation, failure, context, self.cross_user, self.freshness,
                                         self.bound_ms)
        relied = (context.get('baseline') or {}).get('digest')
        row = health_compose.row(BIT, status, reason, positions, baseline=relied if status == 'HELD' else None)
        return row, decision
