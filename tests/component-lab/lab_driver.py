# SPDX-License-Identifier: Apache-2.0
"""The lab driver: the coordinator processes that one broker runs on one admitted guest runtime, and
the deployment store's setup from that guest's own baseline.

The driver decides no ticket. The accepted reconciler does, inside each generation, and the broker
owns every guest command, the ledger, the fault cells and the fences. The driver:

- writes the store with the factory choice and the bridge's version 2 configuration, which names
  the lab host configuration's digest (`init`), before the broker's admission binds that
  configuration's digest, so the admission binds the host configuration too;
- runs the cohort check as the first generation, so the baseline is the guest's own record. T0, the
  boot a plan binds, comes only from positive evidence in the broker's ledger: the check generation
  completed, its own reads all returned facts, its clock read named one boot, each of its boot,
  checkpoint, factory and active reads carried at least one fact of its own kind (a completed boot,
  a checkpoint state, the factory copy, the active copy) of that boot, no read carried a fact of
  another boot, and the selection then records that boot as checked. A check that completed
  without reading, for instance with the clock unavailable, establishes nothing; any later
  generation, of any kind or outcome, ends T0;
- makes the immutable plan, its lab grants and its first ticket from T0's facts (`plan`), only while
  T0 stands, and refused when the store holds facts of another boot or T0's facts are missing,
  doubtful or contradictory;
- rounds a ticket one generation at a time until its PUBLISH has run, then reads the plan's
  publication back through the artifact store and pins the published variant's two members for the
  broker's WRITE, and then settles. While the plan has no publication yet it keeps rounding, since the
  coordinator may still publish it and creates no session before it reads the publication. A
  publication that cannot be exported stops the driver before another round, so no CREATE or WRITE
  follows a failed staging;
- reads each generation's outcome as the broker recorded it. A deliberate halt is followed by a new
  generation on the same store, which continues by observation; nothing is replayed. FAILED, STOPPED,
  KILLED and LOST stop the driver;
- runs the design's loss cells as one sequence of attempts on one plan (`cells.py`): the cohort
  refusal first (`contradict`), then each attempt only when the store holds exactly the plan's
  earlier attempts, each terminal, with its faults admitted before its first generation, a framework
  restart through the broker only when a generation leaves the ticket unchanged in a wait that a
  later framework instance resolves, the next generation's own reads required to show that later
  instance in the same boot, and the attempt's records compared with its prediction from the store
  and the broker's ledger, never from what the driver did.

Each Java process gets the lab host configuration and its digest as the system properties
andrix.lab.host and andrix.lab.hostSha256, and, once the broker's admission exists, the bridge
configuration digest that admission binds as andrix.lab.admittedConfig, taken from the admission the
broker opened, never from the configuration file itself; every command after `init` refuses a bridge
configuration with another digest, and the configuration names the host configuration's digest.

The next campaign profile has its own driver below, `NextDriver`, and its own admission writer,
`next_admission`. They run the remaining matrix of next_cells.py through the same broker and Java
entry, with explicit boot phases, one round per generation, plain kernel confirmations in place of
framework restarts, the APPLIED boundary's baselines, the scheduled loss control, the immutable
baseline cache, and the current baseline and repair of R. G1a's driver above is unchanged.
Host code: it starts no guest itself."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import time

import cells
import lab_actions
import lab_broker
import lab_evidence
import lab_protocol as proto
import lab_records
import next_cells

MAIN = 'dev.andrix.lab.component.LabDriverMain'
# A generation may sign: the host signer holds both 43 MB SystemUI inputs and their signed copies, so
# the heap is the one the sealed signing comparison needs, not the bridge suites' 256 MB.
JVM = ('-Xmx768m', '-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1', '-XX:MaxMetaspaceSize=128m',
       '-XX:ReservedCodeCacheSize=48m', '-ea')
MEMBERS = ('base.apk', 'base.apk.idsig')
# The reads of the coordinator's cohort check, each a reader group in the broker's ledger, and the
# fact each must carry: its kind and the classifications that count. A read that returned no such
# fact read nothing, whatever its status.
CHECK_READS = {'boot': ('BOOT', ('COMPLETED',)), 'checkpoint': ('CHECKPOINT', ('PENDING', 'COMMITTED')),
               'factory': ('FACTORY', ('PRESENT',)), 'active': ('ACTIVE', ('FACTORY_COPY', 'DATA_COPY'))}
NOT_PUBLISHED = 3
# The native mutations the guest sees, by the command each crossing sends.
NATIVE_COMMANDS = (('CREATE', 'pm install-create '), ('WRITE', 'pm install-write '), ('COMMIT', 'pm install-commit '),
                   ('ABANDON', 'pm install-abandon '), ('reboot', 'adb service reboot:'))
TERMINAL = ('CLOSED_APPLIED', 'CLOSED_FAILED', 'CANCELLED', 'VOID', 'DIVERGED', 'SUPERSEDED')


def progress(state):
    """What a generation changes when it moves a ticket, as the driver sees it: the state, the flags,
    the crossing names and the session ID. Equal values mean no progress by these four, not that the
    stored ticket is unchanged byte for byte."""
    return (state['state'], state['flags'], state['ledger'], state['session'])
CONTINUING = ('COMPLETE', 'DELIBERATE_HALT')
HEX16 = re.compile(r'[0-9a-f]{32}')
NO_ID = '0' * 32
HEX32 = re.compile(r'[0-9a-f]{64}')


class DriverError(Exception):
    """A driver step that did not complete. The store and the ledger keep whatever it wrote."""


class LabDriver:
    """One broker's coordinator processes. `classpath` holds the deployment package, the bridge, the
    apksig engine and this driver's Java entry, with the pinned apksigner jar."""

    def __init__(self, directory, java, classpath, host_config, host_sha256, broker=None, clock=None):
        self.dir = Path(directory)
        self.java = str(java)
        self.classpath = str(classpath)
        if not HEX32.fullmatch(host_sha256):
            raise DriverError('the host configuration digest is a SHA-256')
        self.host = (str(host_config), host_sha256)
        self.config = self.dir / 'bridge.config'
        self.broker = broker
        self.generations = []
        self.staged = {}
        # T0: the boot of a completed baseline check that is still the last generation, or None.
        self.t0 = None
        # After a framework restart: (boot, the instance the broker's precondition read, the later
        # instance its settle wait found), which the next generation's own reads must show, or None.
        self.restart_due = None
        # The deployment store, once `init` made it; the driver keeps a snapshot of its records after
        # every step, for the closure: the store replaces a ticket's record with its successor.
        self.store = None
        self.snapshots = 0
        # The lab operator's clock for plan and grant times, in milliseconds: the host's wall clock,
        # which a real guest's wall clock follows. A grant later than the device's clock is not yet
        # in force, so a simulated guest's driver takes the simulated clock instead.
        self.clock = clock or (lambda: time.time_ns() // 1_000_000)

    def _argv(self, *args):
        state = self.dir / 'jvm'
        state.mkdir(exist_ok=True)
        admitted = ['-Dandrix.lab.admittedConfig=%s' % self.broker.admission['config']] if self.broker is not None else []
        return [self.java, *JVM, '-Djava.io.tmpdir=%s' % state, '-Dandrix.lab.host=%s' % self.host[0],
                '-Dandrix.lab.hostSha256=%s' % self.host[1], *admitted, '-cp', self.classpath, MAIN, *args]

    def run(self, *args, timeout=300, accept=(0,)):
        """One driver process outside any generation; its standard output, or DriverError. An exit in
        `accept` other than 0 returns None."""
        done = subprocess.run(self._argv(*args), capture_output=True, text=True, timeout=timeout)
        if done.returncode not in accept:
            raise DriverError('%s failed: %s' % (args[0], done.stderr[-2000:]))
        return done.stdout if done.returncode == 0 else None

    def init(self, store, manifest_sha256, installation, coordinator, trust):
        """The store with the factory choice, and the bridge configuration. Returns its digest, which
        the broker's admission must name."""
        for value, pattern, what in ((installation, HEX16, 'installation'), (coordinator, HEX16, 'coordinator'),
                                     (trust, HEX32, 'trust policy'), (manifest_sha256, HEX32, 'manifest')):
            if not pattern.fullmatch(value):
                raise DriverError('the %s is lower case hexadecimal of its size' % what)
        digest = self.run('init', str(self.dir), str(store), manifest_sha256, installation, coordinator, trust,
                          str(self.clock())).strip()
        if not HEX32.fullmatch(digest):
            raise DriverError('init printed no configuration digest')
        self.store = Path(store)
        self.snapshot('init')
        return digest

    def snapshot(self, label):
        """A copy of every record the store holds, with a manifest of their SHA-256, under the next
        numbered snapshot directory. Staging files are not records and are left out."""
        if self.store is None:
            return None
        self.snapshots += 1
        target = self.dir / 'store-snapshots' / ('%04d-%s' % (self.snapshots, label))
        target.mkdir(parents=True)
        manifest = {}
        for path in sorted(self.store.rglob('*')):
            relative = path.relative_to(self.store)
            if path.is_symlink() or not path.is_file() or any(part.startswith('.') for part in relative.parts):
                continue
            data = path.read_bytes()
            (target / relative).parent.mkdir(parents=True, exist_ok=True)
            (target / relative).write_bytes(data)
            manifest[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        (target / 'manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
        return target

    def generation(self, *args):
        """One coordinator generation through the broker, with the lab host wired in."""
        if self.broker is None:
            raise DriverError('generations need the admitted broker')
        self.t0 = None  # A plan binds only the boot of a check that is the last generation.
        summary = self.broker.run_generation(self._argv(str(self.config), *args))
        self.generations.append(summary)
        self.snapshot('generation-%d' % summary['generation'])
        if self.restart_due is not None:
            (boot, before, later), self.restart_due = self.restart_due, None
            groups = self._groups(summary['generation'])
            readings = [g['reading'] for g in groups if g['reader'] == 'clock' and g['status'] == 'facts']
            if not readings or any(r['boot'] != boot or r['instance'] < later or r['instance'] <= before for r in readings):
                raise DriverError('the generation after a framework restart did not read the later instance of the same boot')
            if not any(g['reader'] == 'checkpoint' and g['status'] == 'facts'
                       and any(o['kind'] == 'CHECKPOINT' for o in g['observations']) for g in groups):
                raise DriverError('the generation after a framework restart did not read the checkpoint again')
        return summary

    def _groups(self, generation):
        return [e.content for e in self.broker.ledger.entries if e.kind == 'group' and e.content.get('generation') == generation]

    def restart_framework(self, reason):
        """A later framework instance in the same boot, through the broker's admitted lab action, between
        generations. T0 ends. The broker's record names the instance its precondition read and the
        later one its settle wait found; the next generation's own clock reads must show that later
        instance, or a larger one, of the same boot, and it must read the checkpoint again, or the
        driver stops."""
        self.t0 = None
        summary = self.broker.framework_restart(reason)
        self.restart_due = (summary['before']['boot'], summary['before']['instance'], summary['settled']['instance'])
        return summary

    def restart_resolves(self, generation):
        """Whether the generation's own last reads show a wait that a later framework instance resolves:
        a clock reading, a COMMITTED checkpoint, and one whole session listing of the clock's instance
        with no session committed or of unknown commitment. A pending checkpoint, an unavailable read
        or a committed session is another wait, which a restart does not resolve."""
        last = {}
        for group in self._groups(generation):
            last[group['reader']] = group
        clock, checkpoint, sessions = last.get('clock'), last.get('checkpoint'), last.get('sessions')
        if any(g is None or g['status'] != 'facts' for g in (clock, checkpoint, sessions)):
            return False
        if [o['classification'] for o in checkpoint['observations'] if o['kind'] == 'CHECKPOINT'] != ['COMMITTED']:
            return False
        instance = clock['reading']['instance']
        listings = [o for o in sessions['observations'] if o['kind'] == 'LISTING']
        if (len(listings) != 1 or listings[0]['classification'] not in lab_broker.COMPLETE_LISTINGS
                or any(o['instance'] != instance for o in sessions['observations'])):
            return False
        return not any(o['kind'] == 'SESSION' and o['classification'] in lab_broker.RESTART_BLOCKING
                       for o in sessions['observations'])

    def advance(self, *args):
        """A generation that must end COMPLETE or as an ordered halt; anything else stops the driver."""
        summary = self.generation(*args)
        if summary['status'] not in CONTINUING:
            raise DriverError('generation %s ended %s' % (summary.get('generation'), summary['status']))
        return summary

    def check(self):
        """The cohort check of the guest as it is: the baseline that a plan is made from. T0 is the boot
        that this generation's own reads establish, and only when the selection records it as checked."""
        summary = self.generation('check')
        if summary['status'] != 'COMPLETE':
            raise DriverError('the baseline check ended %s' % summary['status'])
        boot = self.read_boot(summary['generation'])
        if boot is None:
            raise DriverError('the check did not read one current boot and its baseline whole')
        checked = self.selection()['checked']
        if checked != boot:
            raise DriverError('the selection records %s as checked, not the boot %s this check read' % (checked, boot))
        self.t0 = boot
        return summary

    def read_boot(self, generation):
        """The boot one generation's own reads establish, from the broker's ledger: every read group
        of the generation returned facts, its clock reads named one boot, every fact it read is of
        that boot, and each of its boot, checkpoint, factory and active reads carried a fact of its
        own kind. None otherwise."""
        groups = [e.content for e in self.broker.ledger.entries if e.kind == 'group' and e.content.get('generation') == generation]
        if not groups or any(g['status'] != 'facts' for g in groups):
            return None
        clocks = {g['reading']['boot'] for g in groups if g['reader'] == 'clock'}
        if len(clocks) != 1:
            return None
        boot = next(iter(clocks))
        if any(o['boot'] != boot for g in groups for o in g['observations']):
            return None
        for reader, (kind, classifications) in CHECK_READS.items():
            facts = [o for g in groups if g.get('purpose') == 'observe' and g['reader'] == reader for o in g['observations']]
            if not any(o['kind'] == kind and o['classification'] in classifications for o in facts):
                return None
        return boot

    def selection(self):
        """The component's selection: choice, revision, realization and checked boot."""
        line = self.run('selection', str(self.config)).strip()
        return dict(part.split('=', 1) for part in line.split(' '))

    def plan(self, plan, ticket, boot_limit, command='plan'):
        """The immutable plan from T0's facts, its lab grants and its first ticket. With command
        'contradict', the lab's cohort refusal control: the same, its cohort's factory copy changed."""
        if not (HEX16.fullmatch(plan) and HEX16.fullmatch(ticket)) or not 1 <= int(boot_limit) <= 32:
            raise DriverError('a plan and ticket ID and a boot limit of 1 to 32')
        if command not in ('plan', 'contradict'):
            raise DriverError('a plan or the cohort refusal control')
        if self.t0 is None:
            raise DriverError('a plan is made right after a complete baseline check, and none is the last generation')
        line = self.run(command, str(self.config), plan, ticket, str(int(boot_limit)), str(self.clock()), self.t0).strip()
        self.snapshot(command)
        return dict(part.split('=', 1) for part in line.split(' '))

    def ticket(self, plan, ticket, activate=False, sign=False):
        """The plan's next attempt, with a fresh STAGE grant, and a fresh SIGN grant for both inputs or
        ACTIVATE when asked. A SIGN grant serves one signing transaction."""
        options = (('sign',) if sign else ()) + (('activate',) if activate else ())
        self.run('ticket', str(self.config), plan, ticket, str(self.clock()), *options)
        self.snapshot('ticket')

    def inspect(self, ticket):
        line = self.run('inspect', str(self.config), ticket).strip()
        return dict(part.split('=', 1) for part in line.split(' '))

    def stage_publication(self, plan):
        """Reads the plan's publication back and pins the published variant's members for WRITE. None
        while the plan has no publication yet; DriverError when one exists but cannot be exported
        whole. A plan is pinned once; a second call returns the members already pinned."""
        if plan in self.staged:
            return self.staged[plan]
        reads = self.dir / 'published' / plan
        reads.mkdir(parents=True, exist_ok=True)
        out = reads / ('read-%d' % len(list(reads.iterdir())))
        out.mkdir()
        text = self.run('published', str(self.config), plan, str(out), accept=(0, NOT_PUBLISHED))
        if text is None:
            return None
        members = {}
        for line in text.splitlines():
            name, digest, size = line.split(' ')
            if name not in MEMBERS or name in members or not HEX32.fullmatch(digest) or int(size) <= 0:
                raise DriverError('an unexpected published member line: %r' % line)
            members[name] = {'host': str(out / name), 'sha256': digest, 'bytes': int(size)}
        if set(members) != set(MEMBERS):
            raise DriverError('the publication gave %s' % sorted(members))
        self.broker.pin_artifacts(plan, members)
        self.staged[plan] = members
        return members

    def run_attempt(self, spec, plan, ticket, generations=40, rounds=40, between=None, staged=None):
        """One attempt of the cell sequence on the plan: its faults admitted before its first
        generation, its ticket made (the plan's own first ticket is attempt 1), driven until terminal
        with framework restarts only where a later instance resolves a wait, then its durable records
        compared with the prediction. Returns the comparison; a difference raises DriverError."""
        cells.check_spec(spec)
        # The store decides: attempt 1 is the plan's only ticket, made by `plan` and never moved;
        # attempt N follows exactly N - 1 earlier attempts, each terminal.
        found = self.tickets(plan)
        if spec['attempt'] == 1:
            if [(t['ticket'], t['attempt'], t['state']) for t in found] != [(ticket, 1, 'PLANNED')]:
                raise DriverError("attempt 1 is the plan's first ticket, still PLANNED: %s" % found)
        elif ([t['attempt'] for t in found] != list(range(1, spec['attempt']))
              or any(t['state'] not in TERMINAL for t in found)):
            raise DriverError('an attempt begins only after the previous ticket is terminal: %s' % found)
        self.broker.admit_faults([dict(item, plan=plan, attempt=spec['attempt']) for item in spec['faults']])
        if spec['attempt'] > 1:
            self.ticket(plan, ticket, sign='SIGN' in spec['grants'], activate='ACTIVATE' in spec['grants'])
            made = self.tickets(plan)
            if (made[:-1] != found or (made[-1]['ticket'], made[-1]['attempt'], made[-1]['state'])
                    != (ticket, spec['attempt'], 'PLANNED')):
                raise DriverError('the new ticket is not the attempt the sequence names: %s' % made)
        mark = len(self.broker.ledger.entries)
        state = self.drive(ticket, plan, lambda s: s['state'] in TERMINAL, generations=generations, rounds=rounds,
                           between=between, staged=staged, restart_waits=True)
        return self.compare(spec, plan, ticket, state, mark)

    def run_cohort_refusal(self, plan, ticket, generations=6):
        """The design's cohort refusal: a plan whose cohort T0's facts contradict, made right after a
        complete check, must close before any crossing. Its records are compared with
        cells.COHORT_REFUSAL from the store and the broker's ledger."""
        self.plan(plan, ticket, 4, command='contradict')
        if [(t['ticket'], t['attempt']) for t in self.tickets(plan)] != [(ticket, 1)]:
            raise DriverError("the cohort refusal is its plan's only ticket")
        mark = len(self.broker.ledger.entries)
        state = self.drive(ticket, plan, lambda s: s['state'] in TERMINAL, generations=generations)
        return self.compare(cells.COHORT_REFUSAL, plan, ticket, state, mark)

    def tickets(self, plan):
        """The plan's tickets as the store holds them, in attempt order."""
        rows = []
        for line in self.run('tickets', str(self.config), plan).splitlines():
            values = dict(part.split('=', 1) for part in line.split(' '))
            if set(values) != {'ticket', 'attempt', 'state'}:
                raise DriverError('a tickets line of no known form: %r' % line)
            rows.append({'ticket': values['ticket'], 'attempt': int(values['attempt']), 'state': values['state']})
        return rows

    def compare(self, spec, plan, ticket, state, mark):
        """The attempt's records against its prediction: the ticket's end, cause and crossing names from
        the store; and from the broker's ledger since the attempt began, the native commands launched,
        the host calls whose END records a reply, the restarts asked, and each admitted fault's action.
        Launch and request counts, not proof of their effects, which the closure judges."""
        entries = self.broker.ledger.entries[mark:]
        launched = {}
        for entry in entries:
            if entry.kind != 'capture' or (entry.content.get('result') or {}).get('launch') != 'launched':
                continue
            command = entry.content['intent'].get('command')
            # A member's push has no shell command; its install-write is counted.
            for name, prefix in NATIVE_COMMANDS if isinstance(command, str) else ():
                if command.startswith(prefix):
                    launched[name] = launched.get(name, 0) + 1
        restarts = [e.content['reason'] for e in entries if e.kind == 'lab-action' and e.content.get('phase') == 'BEGIN']
        # A host call completed when its END records a reply; one halted before its effect ends only
        # as the generation's end closes it (PROCESS_ENDED).
        host = [e.content for e in entries if e.kind == 'host' and e.content.get('phase') == 'END'
                and e.content.get('ticket') == ticket and e.content.get('outcome') == 'REPLY']
        found = {'end': state['state'], 'cause': state['cause'], 'ledger': [c for c in state['ledger'].split(',') if c],
                 'calls': {name: launched.get(name, 0) for name, _ in NATIVE_COMMANDS},
                 'signs': sum(1 for h in host if h['crossing'] == 'SIGN'),
                 'publishes': sum(1 for h in host if h['crossing'] == 'PUBLISH'),
                 'restarts': [reason.split(':', 1)[0] for reason in restarts],
                 'faults': sorted(e.content['cell'] for e in entries if e.kind in ('fault', 'escrow') and e.content.get('cell'))}
        expected = {key: spec.get(key) for key in found}
        expected['faults'] = sorted(item['cell'] for item in spec['faults'])
        if spec.get('cause') is None:
            found.pop('cause')
            expected.pop('cause')
        if found != expected:
            raise DriverError('attempt %s differs from its prediction: %s' % (spec['name'], json.dumps(
                {k: {'found': found[k], 'predicted': expected[k]} for k in found if found[k] != expected[k]}, sort_keys=True)))
        return found

    def drive(self, ticket, plan, done, generations=12, rounds=40, between=None, staged=None, restart_waits=False):
        """Advances a ticket until `done(state)`. Before the plan's variant is pinned, one round per
        generation, so that its publication is staged after PUBLISH and before the WRITE that needs
        it (a round issues one crossing); then settles. `staged(members)` runs once the variant is
        pinned, `between(state)` after each generation that did not finish, for instance to let lab
        time pass. Returns the last state, or raises DriverError after `generations`."""
        state = self.inspect(ticket) if restart_waits else None
        for _ in range(generations):
            before = state
            if plan in self.staged:
                summary = self.advance('settle', ticket, str(rounds))
            else:
                summary = self.advance('round', ticket)
            state = self.inspect(ticket)
            if (restart_waits and before is not None and progress(before) == progress(state)
                    and state['state'] in cells.RESTART_WAITS and self.restart_resolves(summary['generation'])):
                # No progress, in a wait that the generation's own reads show a later instance resolves.
                self.restart_framework('%s: no progress in a wait that a later framework instance resolves' % state['state'])
            if plan not in self.staged and 'PUBLISH' in state['ledger'].split(','):
                # A failed export raises here, before another round could create a session.
                members = self.stage_publication(plan)
                if members is not None and staged:
                    staged(members)
            if done(state):
                return state
            if between:
                between(state)
        raise DriverError('the ticket did not get there: %s' % state)


# ---------------------------------------------------------------- the next campaign profile

# The next campaign's own records beside the snapshots: synced run checkpoints, the immutable
# baseline cache and the current baseline, each a canonical side record written once.
RUN_CHECKPOINTS = 'run-checkpoints'
BASELINES = 'baselines'
CURRENT_SCHEMA = 'andrix-next-run-checkpoint-v1'
CACHE_SCHEMA = 'andrix-next-baseline-cache-v1'
FIXTURES_SCHEMA = 'andrix-next-fixtures-v1'
PAYLOADS_SCHEMA = 'andrix-next-payloads-v1'
# Plain confirmation, negative activation and helper push bounds: each action's deadline covers
# its transition's settle bound with room to record its END.
CONFIRM_TIMEOUT_MS = 1_500_000
NEGATIVE_TIMEOUT_MS = 2_700_000
PUSH_TIMEOUT_MS = 600_000
PREPARATION_TIMEOUT_MS = 600_000
# The design's per boot poll and settle bounds, proposals reviewed before admission.
BOOT_POLICY = {'poll_interval_ms': 5000, 'settle_ms': 1_200_000, 'negative_settle_ms': 2_400_000,
               'unexpected_boot': 'HALT'}
# Whole health baselines a running user needs before the round that opens a window, and how many
# reads the driver tries for them.
BASELINES_PER_USER = 2
BASELINE_ATTEMPTS = 4
# A window's prepared probes per user at most, and the effect commands one preparation may launch.
PROBES = 16
PREPARATION_EFFECTS = 1
# The design's health window and its largest gap between probes, in seconds.
WINDOW_S = 900
WINDOW_GAP_S = 225
# The final reads: one whole read group between generations, bracketed by two clock reads.
FINAL_READS = ('clock', 'boot', 'checkpoint', 'factory', 'active', 'global-sessions', 'inventory', 'clock')
# The ordinary read wait's own admitted budget, frozen here before launch: how long, on the host's
# monotonic clock, the driver reads an unchanged intent again before it stops with the ticket
# unresolved. It is the profile's budget, not an alias of the plan's verification wait, which stays
# the product's M0 threshold. The starting value is 600000 ms. It equals the time the product's
# plans give a staged session's verification to run, so an ordinary wait never stops sooner than
# the product itself would judge a session stuck. It covers the COMMIT's own 60 s staged ready
# timeout ten times over, and thirty reads at the driver's default 20 s pace. It is a proposal:
# guest timings may revise it, by review, before the admission that freezes it.
WAIT_POLICY = {'ordinary_wait_ms': 600_000}


def _canonical_digest(value):
    return hashlib.sha256(lab_evidence.canonical(value)).hexdigest()


def final_join(reading, component, references):
    """The whole global session inventory joined against the campaign's own native references:
    (the live sessions the campaign owns, the live sessions whose owner the join cannot tell, by
    ID; and the live sessions of other packages, each its whole row). A session is the campaign's
    when its referrer is one of the campaign's ticket nonces or direct control referrers, or its
    ID, creation time and installer are a ticket's recorded session. Live means not terminal, an
    unknown state included. A live session of the component or of no known package, or under the
    campaign's referrer forms, that names none of its references has an owner the join cannot
    tell. A live session of another package under another referrer is not the campaign's: it is
    reported, never owned and never uncertain. Terminal history of every kind may stay."""
    referrers = {'andrix-ticket:' + nonce for nonce in references['nonces']}
    referrers |= {lab_actions.control_referrer(control) for control in references['controls']}
    sessions = {tuple(session) for session in references['sessions']}
    owned, uncertain, others = [], [], []
    for row in lab_actions.live_rows(reading):
        if row['referrer'] in referrers or (row['id'], row['created'], row['installer']) in sessions:
            owned.append(row['id'])
        elif row['package'] in (component, None) or str(row['referrer']).startswith(
                ('andrix-ticket:', lab_actions.CONTROL_REFERRER)):
            uncertain.append(row['id'])
        else:
            others.append(dict(row))
    return owned, uncertain, others


def session_classification(row):
    """A live session's state as the whole inventory shows it: READY; COMMITTED, not ready;
    SEALED, uncommitted; OPEN; or UNKNOWN when a flag that decides it is unknown."""
    if lab_actions.terminal(row) is None or None in (row['ready'], row['committed'], row['sealed']):
        return 'UNKNOWN'
    if row['ready']:
        return 'READY'
    if row['committed']:
        return 'COMMITTED'
    return 'SEALED' if row['sealed'] else 'OPEN'


def fixtures_record(helpers):
    """The fixture manifest a version 3 admission binds: here the helper jars by name, each its
    SHA-256 and size. The fixture APKs join it with the user setup."""
    if set(helpers) != set(next_cells.HELPERS):
        raise DriverError('the fixtures name every helper of the campaign')
    return {'schema': FIXTURES_SCHEMA, 'helpers': {k: dict(v) for k, v in sorted(helpers.items())}, 'fixtures': []}


def payloads_record(payloads):
    """The direct negative payloads a version 3 admission binds: each role's members in order."""
    return {'schema': PAYLOADS_SCHEMA, 'payloads': {k: [dict(m) for m in v] for k, v in sorted(payloads.items())}}


def _spec(ident, kind, phase, cell, runtime, installation, parameters=None, inputs=None, uses=1, timeout_ms=600_000,
          predecessor=None, selector=None):
    return {'id': ident, 'type': kind, 'phase': phase, 'cell': cell, 'runtime': runtime, 'installation': installation,
            'authority': lab_actions.TYPES[kind]['authority'],
            'user_selector': selector or {'kind': lab_actions.TYPES[kind]['selectors'][0]},
            'parameters': parameters or {}, 'inputs': inputs or [],
            'preconditions': list(lab_actions.TYPES[kind]['preconditions']), 'predecessor': predecessor,
            'successors': [], 'max_uses': uses, 'timeout_ms': timeout_ms, 'stdout_max': 65536, 'stderr_max': 65536}


def next_specs(runtime, installation, helpers, payloads=None, sequence=next_cells.SEQUENCE, probes=PROBES):
    """The part of the next campaign's typed action specs that exists now, in order: the two
    helper pushes, each plain confirmation of the campaign chained in its order, the N2 and N3
    direct controls the campaign names with their pinned payloads, chained after the last
    confirmation, and one health preparation of the system user for each window. The user setup
    specs follow with it."""
    specs = []
    for name in next_cells.HELPERS:
        pin = helpers[name]
        specs.append(_spec(next_cells.action_id('helper', name), 'HELPER_PUSH', 'ENTRY', 'entry-%s-helper' % name,
                           runtime, installation, {'helper': name},
                           [{'role': 'helper', 'sha256': pin['sha256'], 'bytes': pin['bytes']}],
                           timeout_ms=PUSH_TIMEOUT_MS))
    previous = None
    for name, _, _ in next_cells.confirmation_cells(sequence):
        specs.append(_spec(next_cells.action_id('confirm', name), 'PLAIN_KERNEL_CONFIRM', 'CELLS', name, runtime,
                           installation, timeout_ms=CONFIRM_TIMEOUT_MS, predecessor=previous))
        previous = specs[-1]['id']
    # Only the staged controls the campaign names, each with its pinned payload.
    named = [c['role'] for c in next_cells.cells(sequence, 'direct') if c['staged']]
    for role in lab_actions.ROLES if payloads else ():
        if role not in payloads or role not in named:
            continue
        control = next_cells.action_id('control', role)
        for kind in lab_actions.DIRECT_STEPS:
            specs.append(_spec(next_cells.action_id(kind.lower(), role), kind, role,
                               '%s-%s' % (role.lower(), kind.lower().replace('_', '-')), runtime, installation,
                               {'control': control, 'role': role},
                               [dict(m) for m in payloads[role]] if kind == 'DIRECT_STAGE' else [],
                               timeout_ms=NEGATIVE_TIMEOUT_MS if kind == 'NEGATIVE_ACTIVATION' else 600_000,
                               predecessor=previous))
            previous = specs[-1]['id']
    for phase in ('A', 'R'):
        specs.append(_spec(next_cells.action_id('prepare', phase), 'HEALTH_PREPARATION', phase,
                           '%s-window-probe' % phase.lower(), runtime, installation,
                           {'criteria': list(lab_actions.PREPARED_CRITERIA), 'max_probe_ms': 120_000}, uses=probes,
                           timeout_ms=PREPARATION_TIMEOUT_MS))
    by_id = {s['id']: s for s in specs}
    for s in specs:
        if s['predecessor'] is not None:
            by_id[s['predecessor']]['successors'].append(s['id'])
    return specs


def next_effect_limits(specs, notice, sequence=next_cells.SEQUENCE, probes=PROBES, effects=PREPARATION_EFFECTS):
    """The admitted effect caps from the campaign's own nominal counts: each managed crossing's
    launches (a WRITE crossing writes both members), the NOTICE budget when notices are owed, the
    direct controls' commands and reboots, no admin effect before the user setup joins, the helper
    pushes and every window's preparations, and the confirmations, by class and by phase. Zero
    forbids."""
    managed = next_cells.cells(sequence, 'managed')
    crossings = {}
    for name in proto.DEVICE_CROSSINGS:
        if name == 'NOTICE':
            crossings[name] = next_cells.NOTICE_BUDGET if notice else 0
        elif name == 'WRITE':
            crossings[name] = sum(1 for c in managed if c['prediction']['calls']['WRITE'] > 0)
        else:
            key = 'reboot' if name == 'REBOOT' else name
            crossings[name] = sum(c['prediction']['calls'][key] for c in managed)
    roles = {s['parameters']['role'] for s in specs if s['type'] == 'DIRECT_STAGE'}
    direct = {c['role']: sum(c['prediction']['calls'].values()) for c in next_cells.cells(sequence, 'direct')
              if c['role'] in roles}
    helpers = sum(1 for s in specs if s['type'] == 'HELPER_PUSH')
    windows = sum(1 for s in specs if s['type'] == 'HEALTH_PREPARATION')
    confirms = sum(1 for s in specs if s['type'] == 'PLAIN_KERNEL_CONFIRM')
    phases = {phase: 0 for phase in lab_actions.PHASES}
    phases.update(ENTRY=helpers, CELLS=confirms, N2=direct.get('N2', 0), N3=direct.get('N3', 0))
    for s in specs:
        if s['type'] == 'HEALTH_PREPARATION':
            phases[s['phase']] += probes * effects
    return {'crossings': crossings, 'direct': sum(direct.values()), 'admin': 0,
            'fixture': helpers + windows * probes * effects, 'control': confirms, 'phases': phases}


def next_admission(*, installation, coordinator, trust, manifest, config, serial, target_scope, device_dir, fences,
                   limits, store, plans, runtime, helpers, predicates, payloads=None, notice=True,
                   sequence=next_cells.SEQUENCE, limited=False, probes=PROBES, wait_policy=None):
    """A version 3 admission of the next campaign profile, as part 1 writes it: version 2's base and
    launch set with every key of the profile, the cells record and fault schedule of the campaign's
    declaration bound by SHA-256, the fixture and payload manifests, the specs above, the F0
    branches (LIMITED only when admitted), the effect caps, the boot policy (four activation and
    six confirmation services, thirteen observed boots and the reviewed poll and settle bounds) and
    the wait policy, the ordinary read wait's own budget (`WAIT_POLICY` unless given).

    The declaration is whether notices are owed and the admitted F0 branches. The cells record
    freezes every declared branch's predictions, and the schedule arms what any of them can reach,
    so no caller predicts F0's result. The broker checks the admission whole when it is
    initialized; nothing here launches or decides anything."""
    declared = next_cells.declaration(notice, limited)
    plans = next_cells.plan_ids(plans)
    specs = next_specs(runtime, installation, helpers, payloads, sequence, probes)
    positive = [c for c in next_cells.cells(sequence, 'managed') if c['plan'] == 'A' and c['phase'] == 'A']
    if len(positive) != 1 or set(predicates) != set(lab_actions.BRANCHES):
        raise DriverError('one positive attempt of A and a predicate for each F0 branch')
    before = [s['id'] for s in specs if lab_actions.PHASES.index(s['phase']) < lab_actions.PHASES.index('F0')]
    all_ids = [s['id'] for s in specs]
    nominal = next_cells.nominal(sequence)
    value = {'version': 3, 'installation': installation, 'component': 'com.android.systemui',
             'coordinator': coordinator, 'trust': trust, 'manifest': manifest, 'config': config, 'serial': serial,
             'target_scope': target_scope, 'device_dir': device_dir, 'fences': dict(fences), 'limits': dict(limits),
             'launches': list(proto.DEVICE_CROSSINGS), 'store': str(store), 'profile': lab_actions.PROFILE,
             'cells_sha256': hashlib.sha256(next_cells.record_bytes(plans, declared, sequence)).hexdigest(),
             'fixtures_sha256': _canonical_digest(fixtures_record(helpers)),
             'payloads_sha256': _canonical_digest(payloads_record(payloads or {})),
             'fault_schedule_sha256': hashlib.sha256(next_cells.schedule_bytes(installation, plans, declared,
                                                                                 sequence)).hexdigest(),
             'lab_actions': specs,
             'branches': {'FULL': {'predicate_sha256': predicates['FULL'], 'actions': all_ids},
                          'LIMITED': ({'predicate_sha256': predicates['LIMITED'], 'actions': all_ids} if limited
                                      else None),
                          'REFUSED': {'predicate_sha256': predicates['REFUSED'], 'actions': before},
                          'positive': {'plan': plans['A'], 'attempt': positive[0]['attempt']}},
             'effect_limits': next_effect_limits(specs, notice, sequence, probes),
             'boot_policy': dict(BOOT_POLICY, activation_services=nominal['activations'],
                                 confirmation_services=nominal['confirmations'], observed_boots=nominal['identities']),
             'wait_policy': dict(wait_policy or WAIT_POLICY)}
    lab_broker.check_admission(value)
    return value


def _write_synced(path, data, sync=True):
    """One file written once, whole: created exclusively, its bytes and then its name synced.
    Without `sync`, a host test's speed, the same writes without the barriers."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        if sync:
            os.fsync(fd)
    finally:
        os.close(fd)
    if sync:
        _sync_dir(path.parent)


def _sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdirs(path, sync=True):
    """Makes a directory and each missing parent, syncing each new name in its parent."""
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir()
        if sync:
            _sync_dir(directory.parent)


class NextDriver(LabDriver):
    """The next campaign profile's driver: one broker's coordinator processes on one admitted guest,
    run through the matrix of next_cells.py. It decides no ticket and owns no guest command: the
    reconciler decides in each generation, and the broker runs every command, confirmation, direct
    control, baseline and push. What it adds is order, pacing and its own synced records:

    - **The entry and identities.** The schedule admitted, both helpers pushed with their byte
      readback, a complete check establishing T0, and an identity baseline while the factory copy
      is active, read again just before the positive attempt's gate.
    - **Explicit boot phases.** Every kernel boot ID the broker's ledger shows, in ledger order and
      never by wall time, is a boot of the campaign with the transition that made it: the initial
      boot, a plain confirmation, a negative activation and its native recovery, or a managed
      REBOOT. Any other new boot, or one past the admitted observed boots, stops the driver. After
      a confirmation or a negative activation the transition's renewed reads must all be facts. In
      every new boot both helpers must read back their pinned bytes before any read uses them: at
      once after a confirmation or a negative activation, and at the APPLIED boundary, before its
      baselines, after a managed activation.
    - **One round pacing.** Every ticket generation is one public round, so each round's boundary is
      checkpointed and no settle loop crosses a milestone. A round that leaves the ticket's stored
      bytes unchanged in an intent wait is one of two waits, told apart by the round's own reads, as
      G1a's driver tells a wait a later framework instance resolves. Where they show only a later
      boot can resolve it (a COMMITTED checkpoint, a whole listing of the clock's instance and no
      session committed or of unknown commitment), the round asks the next plain confirmation its
      cell names, and only that one; an unpredicted one stops the driver. Anything else, such as a
      committed session still verifying, a pending checkpoint or a read that was not whole, is an
      ordinary read wait: read again at the driver's pace, without a replay or a reboot.
    - **The ordinary read wait's budget.** A wait is of one intent: the ticket, its state, its
      ledger's length and its boot. It has the admission's own wait policy as its budget, never the
      plan's verification wait, which stays the product's M0 threshold. Its deadline is on the
      host's monotonic clock, from the round that opened it. Every read of a waiting round is cut
      to what is left of it, by the broker, and so is each pause; nothing is read past it. Each
      waiting round's guest clock reading is kept beside its host time. When the intent changes,
      the wait is recorded resolved; at the deadline it is recorded unresolved and the driver
      stops: no replay, no reboot, and no claim that the native session failed.
    - **The APPLIED boundary.** At APPLIED the driver stops rounding, checks the helpers and takes,
      for each running user, at least two whole health baselines, then lets one round open the
      window. In the window each round follows the probe's preparation hook.
    - **The scheduled loss control.** The campaign's schedule is admitted once. A halted generation
      must have decided exactly one scheduled fault, a complete one none, and no loss is ever left
      not acted; at a cell's end every fault the world reaches has acted once, except one at a
      milestone a guest need not show that its rounds did not reach, which is recorded
      NOT_CAPTURED. A reached conditional milestone owes its loss.
    - **F0's branch.** The campaign's declaration, frozen before launch, names the branches the
      admission admits, and the cells record binds every declared branch's predictions. F0 is a
      gate, not a prediction: the driver selects the branch the broker's F0 decision establishes,
      and A, R and the final reads then run or stay NOT_CAPTURED by it.
    - **The immutable baseline cache.** Each identity and health baseline, whatever it read, is a
      synced cache entry naming the broker's group, never rewritten; the last whole ones of the
      current boot and framework instance are the ones counted, and a new boot or framework never
      inherits them.
    - **The current baseline and R.** After A is terminal, a check generation that is the last
      generation establishes the newest checked boot from its own reads. The current baseline and
      the repair plan come from that boot alone, then the repair's grants by explicit approval and
      its ticket, each phase its own process with a synced checkpoint after it.
    - **The final reads.** A complete check, then one whole read group between generations: the
      boot, checkpoint, factory and active copy, the whole global session inventory and the whole
      user inventory, bracketed by two clock reads of one boot and framework instance. The active
      copy must be R's exact bytes, versionCode, UID and context on the original cohort, and no
      live session the campaign owns may remain in the whole join; a read that is not whole, or a
      live session of the component whose owner the join cannot tell, leaves Final UNKNOWN. Live
      sessions of other packages under other referrers are reported, each with its whole native
      reference and its classification, outside that claim: they never fail Final.
    - **Records.** A synced store snapshot after every step, and synced run checkpoints at every
      boot, milestone boundary, baseline, confirmation, control and cell end. The plan's
      publication is exported and pinned, with its record's digest, before any WRITE.

    `between(driver, state)` lets time pass after a round that changed nothing (the default sleeps
    `pause_s`: `pace_s`, and `window_pace_s` in a health window, a declared probe cadence below the
    window's largest gap that F0 must qualify, each cut to what is left of an ordinary wait);
    `prepare(driver, ticket, plan, users)` is the window probe's preparation, a named hook until
    its adapter exists. `monotonic` is the host's monotonic clock in nanoseconds, the broker's."""

    def __init__(self, directory, java, classpath, plans, host_config=None, host_sha256=None, broker=None, clock=None,
                 main=MAIN, properties=(), declaration=None, sequence=next_cells.SEQUENCE, between=None,
                 prepare=None, pace_s=20.0, window_pace_s=120.0, full_probe=False, sync=True, monotonic=None):
        self.dir = Path(directory)
        self.java = str(java)
        self.classpath = str(classpath)
        if (host_config is None) != (host_sha256 is None) or (host_sha256 is not None
                                                                and not HEX32.fullmatch(host_sha256)):
            raise DriverError('a host configuration comes with its SHA-256')
        self.host = None if host_config is None else (str(host_config), host_sha256)
        self.main = main
        self.properties = list(properties)
        self.config = self.dir / 'bridge.config'
        self.broker = broker
        self.generations = []
        self.staged = {}
        self.t0 = None
        self.restart_due = None
        self.store = None
        self.snapshots = 0
        self.clock = clock if clock is not None else (lambda: time.time_ns() // 1_000_000)
        self.monotonic = monotonic if monotonic is not None else time.monotonic_ns
        # The open ordinary read wait, and the deadline its rounds' reads are cut to.
        self.waiting = None
        self.read_deadline_ns = None
        self.plans = next_cells.plan_ids(plans)
        # The frozen declaration; the world's F0 branch stays None until F0 decides it.
        declared = declaration or next_cells.DECLARED
        self.declaration = {'notice': declared['notice'], 'branches': list(declared['branches'])}
        self.world = next_cells.undecided(self.declaration)
        next_cells.check_sequence(sequence)
        self.sequence = sequence
        self.between_hook = between
        self.prepare_hook = prepare
        self.pace_s = pace_s
        # A window's probes are this far apart at most: within the window's largest gap, and few
        # enough for the admitted preparations of one window.
        if not 0 < window_pace_s < WINDOW_GAP_S or WINDOW_S / window_pace_s > PROBES:
            raise DriverError('a window pace within the largest gap and the admitted probes')
        self.window_pace_s = window_pace_s
        self.full_probe = full_probe
        # The barriers of every record the driver writes; a host test may run without them.
        self.sync = sync
        # Explicit boot phases: each boot in ledger order, the ledger entries already scanned.
        self.boots = []
        self.scanned = 0
        self.checkpoints = 0
        # The immutable baseline cache, mirrored in synced files, and the current baseline.
        self.cache = []
        self.current = None
        # Each scheduled fault that acted, by cell, with its record; and each cell's result.
        self.acted = {}
        self.results = {}
        self.cell = None

    # ------------------------------------------------ processes and records

    def _argv(self, *args):
        state = self.dir / 'jvm'
        state.mkdir(exist_ok=True)
        admitted = ['-Dandrix.lab.admittedConfig=%s' % self.broker.admission['config']] if self.broker is not None else []
        host = (['-Dandrix.lab.host=%s' % self.host[0], '-Dandrix.lab.hostSha256=%s' % self.host[1]] if self.host
                else [])
        return [self.java, *JVM, '-Djava.io.tmpdir=%s' % state, *host, *self.properties, *admitted, '-cp',
                self.classpath, self.main, *args]

    def init(self, store, manifest_sha256, installation, coordinator, trust):
        """The store with the factory choice and the version 3 configuration. Returns its digest,
        which the broker's admission must name."""
        for value, pattern, what in ((installation, HEX16, 'installation'), (coordinator, HEX16, 'coordinator'),
                                     (trust, HEX32, 'trust policy'), (manifest_sha256, HEX32, 'manifest')):
            if not pattern.fullmatch(value):
                raise DriverError('the %s is lower case hexadecimal of its size' % what)
        digest = self.run('init3', str(self.dir), str(store), manifest_sha256, installation, coordinator, trust,
                          str(self.clock())).strip()
        if not HEX32.fullmatch(digest):
            raise DriverError('init3 printed no configuration digest')
        self.store = Path(store)
        self.snapshot('init')
        return digest

    def snapshot(self, label):
        """A synced copy of every record the store holds, under the next numbered snapshot
        directory, with a manifest of their SHA-256 written last: a snapshot without its manifest
        is an honest prefix, never a complete store state."""
        if self.store is None:
            return None
        self.snapshots += 1
        target = self.dir / 'store-snapshots' / ('%04d-%s' % (self.snapshots, label))
        _mkdirs(target, self.sync)
        manifest = {}
        for path in sorted(self.store.rglob('*')):
            relative = path.relative_to(self.store)
            if path.is_symlink() or not path.is_file() or any(part.startswith('.') for part in relative.parts):
                continue
            data = path.read_bytes()
            _mkdirs((target / relative).parent, self.sync)
            _write_synced(target / relative, data, self.sync)
            manifest[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        _write_synced(target / 'manifest.json', (json.dumps(manifest, indent=1, sort_keys=True) + '\n').encode(),
                      self.sync)
        return target

    def checkpoint(self, label, **facts):
        """One synced run checkpoint: the step, the broker's last ledger entry, the stored ticket
        and selection digests when given, the latest snapshot and the facts, written once."""
        self.checkpoints += 1
        directory = self.dir / RUN_CHECKPOINTS
        _mkdirs(directory, self.sync)
        # Facts as JSON reads them back: a record's tuples, such as a ticket's health, are lists.
        record = {'schema': CURRENT_SCHEMA, 'ordinal': self.checkpoints, 'label': label,
                  'ledger': len(self.broker.ledger.entries) if self.broker is not None else 0,
                  'generation': self.generations[-1]['generation'] if self.generations else None,
                  'snapshot': self.snapshots, 'cell': self.cell, 'facts': json.loads(json.dumps(facts))}
        path = directory / ('%04d-%s.json' % (self.checkpoints, label))
        _write_synced(path, lab_evidence.canonical(record), self.sync)
        return path

    def _record(self, kind, name):
        try:
            return (self.store / kind / (name + '.rec')).read_bytes()
        except FileNotFoundError:
            return None

    def ticket_state(self, ticket):
        data = self._record('tickets', ticket)
        if data is None:
            raise DriverError('the ticket cannot be read')
        return dict(lab_records.decode_ticket(data), sha256=hashlib.sha256(data).hexdigest())

    def plan_record(self, plan):
        data = self._record('plans', plan)
        return None if data is None else lab_records.decode_plan(data)

    def selection(self):
        """The component's selection, read strictly from its stored record."""
        data = self._record('selections', self.broker.admission['component'])
        if data is None:
            raise DriverError('the selection cannot be read')
        s = lab_records.decode_selection(data)
        return dict(s, checked=s['checkedBoot'], sha256=hashlib.sha256(data).hexdigest())

    def tickets(self, plan):
        """The plan's tickets as the store holds them, in attempt order."""
        rows = []
        for path in sorted((self.store / 'tickets').glob('*.rec')):
            if path.name.startswith('.'):
                continue
            t = lab_records.decode_ticket(path.read_bytes())
            if t['plan'] == plan:
                rows.append({'ticket': t['ticket'], 'attempt': t['attempt'], 'state': t['state']})
        return sorted(rows, key=lambda r: r['attempt'])

    def grants(self, plan):
        """The plan's authorizations as the store holds them."""
        found = []
        for path in sorted((self.store / 'authorizations').glob('*.rec')):
            if not path.name.startswith('.'):
                a = lab_records.decode_authorization(path.read_bytes())
                if a['plan'] == plan:
                    found.append(a)
        return found

    def open_tickets(self):
        component = self.broker.admission['component']
        return [t for t in (lab_records.decode_ticket(p.read_bytes()) for p in sorted((self.store / 'tickets').glob('*.rec'))
                            if not p.name.startswith('.'))
                if t['component'] == component and t['state'] not in TERMINAL]

    # ------------------------------------------------ generations, boots and losses

    def generation(self, *args):
        """One coordinator generation through the broker, its reads cut to an open ordinary wait's
        deadline; then the synced snapshot, the boot phases and the loss control of its ledger
        entries."""
        if self.broker is None:
            raise DriverError('generations need the admitted broker')
        # Any generation ends T0: a plan or a current baseline binds the last generation's check.
        self.t0 = None
        mark = len(self.broker.ledger.entries)
        summary = self.broker.run_generation(self._argv(str(self.config), *args), deadline_ns=self.read_deadline_ns)
        self.generations.append(summary)
        self.snapshot('generation-%d' % summary['generation'])
        self.observe_boots()
        self.control_losses(summary, mark)
        return summary

    def observe_boots(self):
        """The explicit boot phases: every boot ID the ledger shows since the last scan, in ledger
        order. Each new one is a boot of the transition that made it, or stops the driver."""
        entries = self.broker.ledger.entries
        last_reboot = None
        for entry in entries[:self.scanned]:
            if entry.kind == 'crossing' and entry.content.get('crossing') == 'REBOOT':
                last_reboot = entry.number
        for entry in entries[self.scanned:]:
            c = entry.content
            if entry.kind == 'crossing' and c.get('crossing') == 'REBOOT':
                last_reboot = entry.number
            if not (entry.kind == 'group' and c.get('reader') == 'clock' and c.get('status') == 'facts'):
                continue
            boot = c['reading']['boot']
            if any(b['boot'] == boot for b in self.boots):
                continue
            kind, cell, transition = self._boot_kind(entry.number, last_reboot)
            record = {'ordinal': len(self.boots), 'boot': boot, 'kind': kind, 'cell': cell, 'first_entry': entry.number,
                      'transition': transition}
            self.boots.append(record)
            self.checkpoint('boot-%d' % record['ordinal'], **record)
            if kind == 'UNEXPECTED':
                raise DriverError('boot %d is unexpected: no transition or managed reboot made it' % record['ordinal'])
            if len(self.boots) > self.broker.admission['boot_policy']['observed_boots']:
                raise DriverError('the observed boots pass the admitted allowance')
        self.scanned = len(entries)

    def _boot_kind(self, number, last_reboot):
        """How the boot first read at ledger entry `number` came, with its cell and transition: the
        first boot is the initial one; a later one belongs to the boot transition whose poll read
        it, a second one of a negative activation being its native recovery, or follows a managed
        REBOOT whose capture may have launched since the previous boot; any other is unexpected."""
        if not self.boots:
            return 'INITIAL', 'entry', None
        c = self.broker.ledger.entries[number - 1].content
        ident = c.get('transition')
        if ident is not None:
            begin = self.broker.transitions[ident]['begin']
            seen = [b for b in self.boots if b['transition'] == ident]
            if seen and begin['transition_kind'] != 'NEGATIVE_ACTIVATION':
                return 'UNEXPECTED', begin['cell'], ident
            return (begin['transition_kind'] if not seen else 'NATIVE_RECOVERY'), begin['cell'], ident
        previous = self.boots[-1]['first_entry']
        if last_reboot is not None and last_reboot > previous and any(
                e.kind == 'capture' and (e.content.get('intent') or {}).get('crossing') == last_reboot
                and lab_broker.Broker._may_have_launched(e) for e in self.broker.ledger.entries[last_reboot:number]):
            return 'MANAGED_ACTIVATION', self.cell, None
        return 'UNEXPECTED', self.cell, None

    def control_losses(self, summary, mark):
        """The scheduled loss control of one generation's entries: a halted generation decided
        exactly one scheduled fault, a complete one none, and no loss was left not acted."""
        entries = self.broker.ledger.entries[mark:]
        decided = [e for e in entries if e.kind == 'fault']
        dropped = [e for e in entries if e.kind == 'escrow']
        scheduled = {c['cell'] for c in self.broker.cells}
        for e in decided + dropped:
            cell = e.content.get('cell')
            if cell not in scheduled or cell in self.acted:
                raise DriverError('fault %s acted outside the schedule or twice' % cell)
            if e.content.get('decision') == 'not-acted':
                raise DriverError('loss %s was left not acted' % cell)
            self.acted[cell] = {'record': e.number, 'kind': e.kind, 'generation': summary['generation'],
                                'cell': self.cell}
        halts = [e for e in decided if str(e.content.get('decision', '')).startswith('halt')]
        if summary['status'] == 'DELIBERATE_HALT' and len(halts) != 1:
            raise DriverError('a halted generation decided %d scheduled faults, not one' % len(halts))
        if summary['status'] != 'DELIBERATE_HALT' and halts:
            raise DriverError('a generation that did not halt decided a halting fault')

    def new_boot_gates(self, purpose):
        """After a new boot: both helpers read back their pinned bytes, or the driver stops."""
        for name in next_cells.HELPERS:
            found = self.broker.helper_check(name, purpose)
            if not found['ok']:
                raise DriverError('the %s helper reads back %s, not its pinned bytes' % (name, found['sha256']))
        self.checkpoint('helpers', boot=self.boots[-1]['boot'] if self.boots else None)

    def remaining_wait_s(self):
        """What is left of the open ordinary wait, in seconds of the host's monotonic clock, or None
        when no wait is open."""
        if self.waiting is None:
            return None
        return max(0.0, (self.waiting['deadline_ns'] - self.monotonic()) / 1_000_000_000)

    def pause_s(self, state):
        """How long time passes after a round that changed nothing: the window's own pace in a
        window and the driver's pace elsewhere, each cut to what is left of an open ordinary
        wait."""
        pace = self.window_pace_s if state['state'] == 'HEALTH_WINDOW' else self.pace_s
        remaining = self.remaining_wait_s()
        return pace if remaining is None else min(pace, remaining)

    def wait(self, state):
        """Lets time pass after a round that changed nothing, for `pause_s`, or through the hook."""
        if self.between_hook is not None:
            self.between_hook(self, state)
        else:
            time.sleep(self.pause_s(state))

    # ------------------------------------------------ entry

    def bound_declaration(self):
        """Refuses an admission that does not bind this campaign's frozen declaration: its cells
        record, with every declared branch's predictions, and exactly the declared F0 branches."""
        admission = self.broker.admission
        digest = hashlib.sha256(next_cells.record_bytes(self.plans, self.declaration, self.sequence)).hexdigest()
        admitted = [b for b in next_cells.BRANCHES if admission['branches'].get(b) is not None]
        if admission.get('cells_sha256') != digest or admitted != self.declaration['branches']:
            raise DriverError("the admission does not bind this campaign's declaration and its predictions")
        self.checkpoint('declaration', cells_sha256=digest, notice=self.declaration['notice'], branches=admitted)

    def admit(self, schedule):
        """Admits the campaign's fault schedule once, before its first generation."""
        self.broker.admit_schedule(schedule)
        self.checkpoint('schedule', sha256=hashlib.sha256(schedule).hexdigest(), faults=len(self.broker.cells))

    def push_helpers(self, hosts):
        """Puts both helper jars on the guest through their admitted pushes, each settled only on
        its byte readback, before any read uses them."""
        for name in next_cells.HELPERS:
            end = self.broker.run_action(next_cells.action_id('helper', name), 'the %s helper before its reads' % name,
                                         host=str(hosts[name]))
            if (end['status'], end['settled']) != ('OK', True):
                raise DriverError('the %s helper push ended %s' % (name, end['status']))
        self.checkpoint('helpers-pushed')

    def identity_baseline(self, purpose):
        """Each listed user's expected identity, while the factory copy is active: refused unless
        the broker's group qualified. Kept in the cache whatever it read."""
        number = self.broker.identity_baseline(purpose)
        group = self.broker.ledger.entries[number - 1].content
        self._cache('identity', number, group)
        projection = group.get('projection') or {}
        if group['status'] != 'facts' or not projection.get('qualified'):
            raise DriverError('the identity baseline did not qualify: %s' % (projection.get('why_not') or group['reason']))
        return group

    def _cache(self, kind, number, group, **facts):
        """One immutable baseline cache entry: the broker's group, its status, bracket and what it
        is of, synced and never rewritten."""
        directory = self.dir / BASELINES
        _mkdirs(directory, self.sync)
        brackets = group.get('brackets') or {}
        entry = {'schema': CACHE_SCHEMA, 'ordinal': len(self.cache) + 1, 'kind': kind, 'group': number,
                 'compound': group.get('compound'), 'status': group['status'], 'boot': brackets.get('boot'),
                 'instance': brackets.get('instance'), 'user': group.get('user'), 'serial': group.get('serial'),
                 'complete': bool(group.get('complete')), 'cell': self.cell, 'facts': facts}
        _write_synced(directory / ('%04d-%s.json' % (entry['ordinal'], kind)), lab_evidence.canonical(entry),
                      self.sync)
        self.cache.append(entry)
        return entry

    def whole_baselines(self, boot, instance, user, serial):
        """The cache's whole health baselines of one user in one boot and framework instance."""
        return [e for e in self.cache if e['kind'] == 'health' and e['status'] == 'facts' and e['complete']
                and (e['boot'], e['instance'], e['user'], e['serial']) == (boot, instance, user, serial)]

    def entry(self, schedule, hosts):
        """The campaign's entry: the admission's binding of the declaration checked, the schedule
        admitted, the helpers pushed, a complete check establishing T0, and the identity baseline
        while the factory copy is active."""
        self.cell = 'entry'
        self.bound_declaration()
        self.admit(schedule)
        self.push_helpers(hosts)
        self.check()
        self.new_boot_gates('the initial boot')
        self.identity_baseline('the entry: each serial with the factory copy active')
        self.checkpoint('entry', t0=self.t0)

    # ------------------------------------------------ publication

    def export(self, plan, out):
        """The plan's publication as the Java entry reads it back through the artifact store: its
        variant's two members written under `out`, and their lines with the publication's SHA-256,
        or None while there is no publication yet."""
        return self.run('published', str(self.config), plan, str(out), accept=(NOT_PUBLISHED, 0))

    def stage_publication(self, plan):
        """As G1a's export, and the version 3 pin names the publication record's SHA-256. A plan is
        pinned once, before any WRITE could need it; a failed export stops the driver."""
        if plan in self.staged:
            return self.staged[plan]
        reads = self.dir / 'published' / plan
        _mkdirs(reads, self.sync)
        out = reads / ('read-%d' % len(list(reads.iterdir())))
        _mkdirs(out, self.sync)
        text = self.export(plan, out)
        if text is None:
            return None
        members, publication = {}, None
        for line in text.splitlines():
            parts = line.split(' ')
            if len(parts) == 2 and parts[0] == 'publication' and publication is None and HEX32.fullmatch(parts[1]):
                publication = parts[1]
                continue
            if len(parts) != 3 or parts[0] not in MEMBERS or parts[0] in members or not HEX32.fullmatch(parts[1]) \
                    or not parts[2].isdigit() or int(parts[2]) <= 0:
                raise DriverError('an unexpected published member line: %r' % line)
            members[parts[0]] = {'host': str(out / parts[0]), 'sha256': parts[1], 'bytes': int(parts[2])}
        if set(members) != set(MEMBERS) or publication is None:
            raise DriverError('the publication gave %s and %s publication digest' % (sorted(members),
                                                                                    'a' if publication else 'no'))
        self.broker.pin_artifacts(plan, members, publication)
        self.staged[plan] = members
        self.checkpoint('pinned', plan=plan, publication=publication,
                        members={k: v['sha256'] for k, v in sorted(members.items())})
        return members

    # ------------------------------------------------ managed attempts

    def running_users(self):
        """The users the last generation's whole listing showed running, as (user, serial)."""
        for entry in reversed(self.broker.ledger.entries):
            c = entry.content
            if entry.kind == 'group' and c.get('reader') == 'users' and c.get('status') == 'facts':
                return sorted({(o['user'], o['serial']) for o in c['observations']
                               if o['classification'] in ('RUNNING_UNLOCKED', 'RUNNING_LOCKED')})
        return []

    def last_clock(self):
        for entry in reversed(self.broker.ledger.entries):
            c = entry.content
            if entry.kind == 'group' and c.get('reader') == 'clock' and c.get('status') == 'facts':
                return c['reading']
        return None

    def account_boot(self, before, after):
        """The boot accounting of one round: a ticket's boot count never falls and rises by at
        most one, only with its boot changed to an observed one; each change is a synced record."""
        if (before['boot'], before['bootCount']) == (after['boot'], after['bootCount']):
            return
        if after['bootCount'] < before['bootCount'] or after['bootCount'] > before['bootCount'] + 1:
            raise DriverError('the ticket boot count moved from %d to %d' % (before['bootCount'], after['bootCount']))
        if after['bootCount'] != before['bootCount'] and after['boot'] == before['boot']:
            raise DriverError('the ticket counted a boot it had already observed')
        ordinal = [b['ordinal'] for b in self.boots if b['boot'] == after['boot']]
        if not ordinal:
            raise DriverError('the ticket names a boot the ledger never showed')
        self.checkpoint('boot-accounting', ticket=after['ticket'], old_boot=before['boot'], new_boot=after['boot'],
                        old_count=before['bootCount'], new_count=after['bootCount'], ordinal=ordinal[0],
                        before_sha256=before['sha256'], after_sha256=after['sha256'],
                        selection_sha256=self.selection()['sha256'])

    def confirm(self, cell, ticket, number, state):
        """The cell's next plain confirmation of the ticket's wait, then the new boot's gates."""
        names = [n for n, c, _ in next_cells.confirmation_cells(self.sequence) if c is cell]
        name = names[number - 1]
        end = self.broker.run_action(next_cells.action_id('confirm', name),
                                     '%s: a later boot confirms the %s wait' % (cell['name'], state), ticket=ticket)
        self.observe_boots()
        if (end['status'], end['settled']) != ('OK', True):
            raise DriverError('the %s confirmation ended %s: %s' % (name, end['status'], end['uncertainty']))
        transition = self.broker.transitions[end['outcome']['transition']]['end']
        renewed = end['outcome'].get('renewed') or {}
        if transition['status'] != 'OK' or len(transition['new_boots']) != 1 or not renewed \
                or any(r['status'] != 'facts' for r in renewed.values()):
            raise DriverError('the %s confirmation did not renew every read of one new boot' % name)
        self.new_boot_gates('after the %s confirmation' % name)
        self.checkpoint('confirmation', name=name, ticket=ticket, transition=end['outcome']['transition'],
                        boot=transition['new_boots'][0])

    def applied_boundary(self, ticket, plan):
        """At APPLIED, before the round that opens the window: the helpers read back, then at
        least two whole health baselines of every running user in this boot and framework
        instance, each kept in the cache. Fewer stops the driver: the window would not qualify."""
        self.new_boot_gates('at the APPLIED boundary')
        state = self.ticket_state(ticket)
        clock = self.last_clock()
        taken = {}
        for user, serial in self.running_users():
            for attempt in range(BASELINE_ATTEMPTS):
                if len(self.whole_baselines(state['boot'], clock['instance'], user, serial)) >= BASELINES_PER_USER:
                    break
                number = self.broker.health_baseline(ticket, plan, user, serial,
                                                     'before the round that opens the window, read %d' % (attempt + 1))
                self._cache('health', number, self.broker.ledger.entries[number - 1].content)
            whole = self.whole_baselines(state['boot'], clock['instance'], user, serial)
            if len(whole) < BASELINES_PER_USER:
                raise DriverError('user %d has %d whole health baselines before its window' % (user, len(whole)))
            taken['%d/%d' % (user, serial)] = [e['group'] for e in whole]
        if not taken:
            raise DriverError('no running user at the APPLIED boundary')
        self.checkpoint('applied-boundary', ticket=ticket, boot=state['boot'], instance=clock['instance'],
                        baselines=taken, ticket_sha256=state['sha256'])

    def prepare_probe(self, ticket, plan):
        """The window probe's preparation for every running user, through the named hook."""
        if self.prepare_hook is not None:
            self.prepare_hook(self, ticket, plan, self.running_users())

    def later_boot_resolves(self, generation):
        """Whether a round's own reads show a wait only a later boot resolves. The rule is G1a's for
        a wait a later framework instance resolves, which a kernel boot also gives: a clock reading,
        a COMMITTED checkpoint, one whole session listing of the clock's instance, and no session
        committed or of unknown commitment. Anything else is an ordinary read wait."""
        return self.restart_resolves(generation)

    @staticmethod
    def intent(state):
        """The intent an ordinary wait is of: the ticket, its state, its ledger's length and its
        boot. A flag a round sets or clears, such as the one a lost read sets, keeps the intent."""
        return (state['ticket'], state['state'], len(state['ledger']), state['boot'])

    def guest_sample(self, generation, unchanged):
        """One waiting round's sample: its generation, the host's monotonic time, whether it left
        the ticket unchanged, and its own last guest clock reading, None when it read none."""
        readings = [g['reading'] for g in self._groups(generation) if g['reader'] == 'clock'
                    and g['status'] == 'facts']
        guest = {k: readings[-1][k] for k in ('boot', 'instance', 'elapsed')} if readings else None
        return {'generation': generation, 'host_ns': self.monotonic(), 'unchanged': unchanged, 'guest': guest}

    def open_wait(self, state, generation):
        """Opens an ordinary read wait of the intent a round left unchanged. Its budget is the
        admission's own wait policy, and its deadline is on the host's monotonic clock, from now;
        both are kept in a synced checkpoint before any waiting round."""
        budget = self.broker.admission['wait_policy']['ordinary_wait_ms']
        now = self.monotonic()
        self.waiting = {'intent': self.intent(state), 'ticket': state['ticket'], 'state': state['state'],
                        'budget_ms': budget, 'since_ns': now, 'deadline_ns': now + budget * 1_000_000,
                        'samples': [self.guest_sample(generation, True)]}
        self.checkpoint('ordinary-wait-open', ticket=state['ticket'], state=state['state'], budget_ms=budget,
                        since_ns=now, deadline_ns=self.waiting['deadline_ns'], ticket_sha256=state['sha256'])
        return self.waiting

    def close_wait(self, outcome, state):
        """Records the open wait's end with every sample kept: resolved once its intent changed,
        later-boot when only a later boot resolves it now, or unresolved at its deadline. An
        unresolved wait stops the driver, the ticket as the store holds it: no replay, no reboot,
        and no claim that the native session failed."""
        waiting, self.waiting = self.waiting, None
        self.checkpoint('ordinary-wait', outcome=outcome, ticket=waiting['ticket'], state=waiting['state'],
                        end_state=state['state'], ticket_sha256=state['sha256'], budget_ms=waiting['budget_ms'],
                        since_ns=waiting['since_ns'], deadline_ns=waiting['deadline_ns'], ended_ns=self.monotonic(),
                        samples=waiting['samples'])
        if outcome == 'unresolved':
            raise DriverError('the %s wait did not resolve within its admitted budget of %d ms; the ticket stays '
                              'unresolved' % (waiting['state'], waiting['budget_ms']))

    def drive(self, cell, ticket, plan, generations=160):
        """Rounds one managed attempt to its end, one public round a generation: the APPLIED
        boundary's baselines before the round that opens the window, a probe's preparation before
        each window round, the publication pinned once PUBLISH ran, and for an intent the round left
        unchanged, the cell's next confirmation when the round's reads show only a later boot
        resolves it, or else an ordinary read wait within the admission's own budget. Returns the
        terminal state."""
        pending = list(cell['confirmations'])
        state = self.ticket_state(ticket)
        self.waiting = None
        for _ in range(generations):
            if state['state'] in TERMINAL:
                if pending:
                    raise DriverError('the ticket ended with confirmations still predicted: %s' % pending)
                return state
            # Nothing more is read past an open wait's deadline: the wait ends unresolved.
            if self.waiting is not None and self.monotonic() >= self.waiting['deadline_ns']:
                self.close_wait('unresolved', state)
            if state['state'] == 'APPLIED':
                self.applied_boundary(ticket, plan)
            elif state['state'] == 'HEALTH_WINDOW':
                self.prepare_probe(ticket, plan)
            # A waiting round's reads are cut to the wait's deadline by the broker.
            self.read_deadline_ns = None if self.waiting is None else self.waiting['deadline_ns']
            try:
                summary = self.advance('round', ticket)
            finally:
                self.read_deadline_ns = None
            after = self.ticket_state(ticket)
            self.account_boot(state, after)
            if plan not in self.staged and 'PUBLISH' in [e[0] for e in after['ledger']]:
                self.stage_publication(plan)
            unchanged = summary['status'] == 'COMPLETE' and after['sha256'] == state['sha256']
            state = after
            if self.waiting is not None:
                self.waiting['samples'].append(self.guest_sample(summary['generation'], unchanged))
                if state['state'] in TERMINAL or self.intent(state) != self.waiting['intent']:
                    self.close_wait('resolved', state)
            if not unchanged or state['state'] in TERMINAL:
                continue
            if state['state'] in next_cells.CONFIRM_WAITS:
                if self.later_boot_resolves(summary['generation']):
                    # Only a later boot resolves it: the cell's next confirmation, and only that.
                    if not pending or pending[0] != state['state']:
                        raise DriverError('an unpredicted wait in %s' % state['state'])
                    if self.waiting is not None:
                        self.close_wait('later-boot', state)
                    self.confirm(cell, ticket, len(cell['confirmations']) - len(pending) + 1, state['state'])
                    pending.pop(0)
                    continue
                # An ordinary read wait: read again, with no replay or reboot, within its budget.
                if self.waiting is None:
                    self.open_wait(state, summary['generation'])
            self.wait(state)
        raise DriverError('the ticket did not end: %s' % state['state'])

    def run_managed(self, cell, ticket, boot_limit=4):
        """One managed attempt, made only where the store holds exactly the plan's earlier attempts,
        each terminal; the positive attempt only after its gate. Returns the cell's comparison."""
        self.cell = cell['cell']
        plan = self.plans[cell['plan']]
        mark = len(self.broker.ledger.entries)
        # The positive attempt is gated before anything creates it or grants it a STAGE, and each
        # listed serial's identity is read again first, while the factory copy is still active.
        positive = cell['phase'] == 'A'
        if positive:
            self.identity_baseline('before the positive attempt, with the factory copy active')
        if cell['attempt'] == 1 and cell['plan'] in ('COHORT', 'A'):
            self.check()
            if positive:
                self.broker.gate_positive(plan, cell['attempt'], 'the positive attempt after a qualified F0')
            self.plan(plan, ticket, boot_limit, command='contradict' if cell['plan'] == 'COHORT' else 'plan')
        else:
            found = self.tickets(plan)
            if [t['attempt'] for t in found] != list(range(1, cell['attempt'])) or any(
                    t['state'] not in TERMINAL for t in found) or self.open_tickets():
                raise DriverError('an attempt begins only after the previous ticket is terminal: %s' % found)
            if positive:
                self.broker.gate_positive(plan, cell['attempt'], 'the positive attempt after a qualified F0')
            self.ticket(plan, ticket, sign='SIGN' in cell['grants'], activate='ACTIVATE' in cell['grants'])
        made = self.tickets(plan)
        if (made[-1]['ticket'], made[-1]['attempt'], made[-1]['state']) != (ticket, cell['attempt'], 'PLANNED'):
            raise DriverError('the new ticket is not the attempt the cell names: %s' % made)
        self.checkpoint('attempt', plan=plan, ticket=ticket, attempt=cell['attempt'])
        state = self.drive(cell, ticket, plan)
        return self.compare(cell, ticket, plan, state, mark)

    def compare(self, cell, ticket, plan, state, mark):
        """The cell's records against its qualified prediction: the ticket's end, cause, crossings
        and boot count from the store; from the ledger since the cell began, the native commands of
        its crossings that may have launched, its host calls that replied, its confirmations, its
        boundaries' milestones and each fault that acted. A fault at a milestone a guest need not
        show may stay unconsumed only when the cell's boundaries never reached that milestone: it is
        then NOT_CAPTURED. A reached one owes its loss. Any other difference stops the driver."""
        expected = next_cells.qualified(cell, self.world)
        entries = self.broker.ledger.entries
        crossings = {e.number: e.content for e in entries if e.kind == 'crossing' and e.complete}
        native = {name: 0 for name in next_cells.CALLS}
        for e in entries[mark:]:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if not intent or crossings.get(intent.get('crossing'), {}).get('ticket') != ticket \
                    or not lab_broker.Broker._may_have_launched(e) or not isinstance(intent.get('command'), str):
                continue
            for name, prefix in NATIVE_COMMANDS:
                if intent['command'].startswith(prefix):
                    native[name] += 1
        host = [e.content for e in entries[mark:] if e.kind == 'host' and e.content.get('phase') == 'END'
                and e.content.get('ticket') == ticket and e.content.get('outcome') == 'REPLY']
        begins = {e.number: e.content for e in entries if e.kind == 'lab-action' and e.content.get('record') == 'BEGIN'}
        confirmations = [e.content for e in entries[mark:] if e.kind == 'lab-action' and e.content.get('record') == 'END'
                         and e.content['type'] == 'PLAIN_KERNEL_CONFIRM' and e.content['status'] == 'OK'
                         and begins[e.content['begin']]['request'].get('ticket') == ticket]
        milestones = [e.content['milestone'] for e in entries[mark:] if e.kind == 'checkpoint'
                      and e.content['ticket'] == ticket and e.content['milestone'] is not None]
        found = {'end': state['state'], 'cause': state['cause'], 'ledger': [e[0] for e in state['ledger']],
                 'calls': native, 'signs': sum(1 for h in host if h['crossing'] == 'SIGN'),
                 'publishes': sum(1 for h in host if h['crossing'] == 'PUBLISH'), 'boots': state['bootCount'],
                 'confirmations': len(confirmations)}
        wanted = {k: expected[k] for k in found}
        if expected['cause'] is None:
            found.pop('cause')
            wanted.pop('cause')
        differences = {k: {'found': found[k], 'predicted': wanted[k]} for k in found if found[k] != wanted[k]}
        if not next_cells.milestones_match(expected['milestones'], milestones):
            differences['milestones'] = {'found': milestones, 'predicted': expected['milestones']}
        owed = [f for f in next_cells.faults(cell, self.world)]
        acted = sorted(c for c, a in self.acted.items() if a['cell'] == cell['cell'])
        unacted = [f['cell'] for f in owed if f['cell'] not in self.acted]
        # Only a conditional milestone the cell's boundaries never recorded excuses its loss.
        conditional = [c for c in unacted if next_cells.by_fault(cell, c).get('milestone') in next_cells.CONDITIONAL
                       and next_cells.by_fault(cell, c)['milestone'] not in milestones]
        if sorted(set(acted)) != sorted(f['cell'] for f in owed if f['cell'] not in conditional):
            differences['faults'] = {'found': acted, 'predicted': sorted(f['cell'] for f in owed)}
        if cell['phase'] in ('A', 'R') and state['state'] == 'CLOSED_APPLIED':
            selection = self.selection()
            revision = self.plan_record(plan)['selectionRevision'] + 1
            if (selection['choice'], selection['plan'], selection['revision']) != ('PLAN', plan, revision):
                differences['selection'] = {'found': [selection['choice'], selection['plan'], selection['revision']],
                                            'predicted': ['PLAN', plan, revision]}
            outcome = next_cells.health(self.world, self.full_probe)
            if not state['health'] or any(h[2] != outcome for h in state['health']):
                differences['health'] = {'found': state['health'], 'predicted': outcome}
        if differences:
            self.checkpoint('cell-differs', cell=cell['cell'], differences=differences)
            raise DriverError('cell %s differs from its prediction: %s' % (cell['name'], json.dumps(differences,
                                                                                                  sort_keys=True)))
        result = dict(found, milestones=milestones, faults=acted,
                      not_captured=conditional + next_cells.uncaptured(cell, self.world), status='PASSED')
        self.results[cell['cell']] = result
        self.checkpoint('cell', cell=cell['cell'], result=result)
        return result

    # ------------------------------------------------ direct controls and F0

    def _direct_step(self, role, kind):
        end = self.broker.run_action(next_cells.action_id(kind.lower(), role), '%s %s' % (role, kind))
        if (end['status'], end['settled']) != ('OK', True):
            raise DriverError('%s %s ended %s: %s' % (role, kind, end['status'], end['uncertainty']))
        return end

    def run_direct(self, cell, payload):
        """One direct negative control in its admitted order: its payload pinned, its stage, the
        explicit consent before arming, its commit and its activation, which settles only on the
        role's intended rejection with the factory copy active; then the new boot's gates. N1 has
        no lab action yet: NOT_CAPTURED."""
        self.cell = cell['cell']
        role = cell['role']
        if not cell['staged'] or payload is None:
            self.results[cell['cell']] = {'status': 'NOT_CAPTURED',
                                          'reason': 'no lab action of this control exists or is admitted'}
            self.checkpoint('cell', cell=cell['cell'], result=self.results[cell['cell']])
            return self.results[cell['cell']]
        mark = len(self.broker.ledger.entries)
        control = next_cells.action_id('control', role)
        self.broker.pin_payload(control, payload)
        self._direct_step(role, 'DIRECT_STAGE')
        self.broker.consent(control, 'the lab may arm and activate %s once' % role)
        self._direct_step(role, 'DIRECT_COMMIT')
        end = self._direct_step(role, 'NEGATIVE_ACTIVATION')
        self.observe_boots()
        transition = self.broker.transitions[end['outcome']['transition']]['end']
        low, high = cell['prediction']['new_boots']
        if transition['status'] != 'OK' or not low <= len(transition['new_boots']) <= high \
                or end['outcome'].get('active') != 'FACTORY_COPY':
            raise DriverError('%s did not settle in its rejection with the factory copy active' % role)
        self.new_boot_gates('after the %s activation and its recovery' % role)
        ends = {e.content['begin'] for e in self.broker.ledger.entries[mark:] if e.kind == 'lab-action'
                and e.content.get('record') == 'END'}
        native = {name: 0 for name in next_cells.CALLS}
        for e in self.broker.ledger.entries[mark:]:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if intent and intent.get('lab_action') in ends and intent.get('operation') == 'lab-action-effect' \
                    and lab_broker.Broker._may_have_launched(e):
                for name, prefix in NATIVE_COMMANDS:
                    if intent['command'].startswith(prefix):
                        native[name] += 1
        if native != cell['prediction']['calls']:
            raise DriverError('%s launched %s, not %s' % (role, native, cell['prediction']['calls']))
        result = {'status': 'PASSED', 'calls': native, 'new_boots': transition['new_boots'],
                  'transition': end['outcome']['transition'], 'cause': cell['prediction']['cause']}
        self.results[cell['cell']] = result
        self.checkpoint('cell', cell=cell['cell'], result=result)
        return result

    def decide_f0(self, capabilities, reason):
        """F0's decision, once, from the trial's capability record. F0 is a gate, not a prediction:
        the broker decides the branch the record establishes and refuses one its admission does not
        admit, and the driver selects that branch among the declared ones, whose predictions the
        cells record froze before launch. A, R and the final reads then run or stay NOT_CAPTURED by
        it."""
        self.cell = 'f0'
        decision = self.broker.record_f0(capabilities, reason)
        branch = decision['branch']
        if branch not in self.declaration['branches']:
            raise DriverError('F0 decided %s, a branch the declaration does not admit' % branch)
        self.world = dict(self.world, f0=branch)
        gate = [c for c in self.sequence if c['kind'] == 'gate']
        self.results['f0'] = {'status': 'DECIDED', 'branch': branch, 'qualified': decision['qualified'],
                              'outcome': gate[0]['prediction'][branch] if gate else None}
        self.checkpoint('f0', branch=branch, qualified=decision['qualified'])
        return decision

    # ------------------------------------------------ the current baseline and R

    def current_baseline(self):
        """The repaired plan's current baseline: a check generation, the last generation, whose own
        reads establish the newest checked boot, and the Java entry's baseline of that boot
        alone."""
        self.check()
        boot = self.t0
        line = self.run('baseline', str(self.config), self.plans['A'], boot).strip()
        current = dict(part.split('=', 1) for part in line.split(' '))
        if current.get('boot') != boot or current.get('plan') != self.plans['A']:
            raise DriverError('the current baseline is not of the checked boot')
        self.current = current
        directory = self.dir / BASELINES
        _mkdirs(directory, self.sync)
        entry = {'schema': CACHE_SCHEMA, 'ordinal': len(self.cache) + 1, 'kind': 'current', 'group': None,
                 'compound': None, 'status': 'facts', 'boot': boot, 'instance': None, 'user': None, 'serial': None,
                 'complete': True, 'cell': self.cell, 'facts': current}
        _write_synced(directory / ('%04d-current.json' % entry['ordinal']), lab_evidence.canonical(entry),
                      self.sync)
        self.cache.append(entry)
        return current

    def run_repair(self, cell, ticket):
        """R after A closed: the current baseline of the newest checked boot, then the repair's
        three phases, each its own process followed by a synced snapshot and checkpoint and a read
        of what it wrote, then the repair's rounds as a managed attempt."""
        self.cell = cell['cell']
        repair, repaired = self.plans['R'], self.plans['A']
        mark = len(self.broker.ledger.entries)
        attempts = self.tickets(repaired)
        if not attempts or attempts[-1]['state'] != 'CLOSED_APPLIED' or self.open_tickets():
            raise DriverError('R needs A closed applied and no open ticket: %s' % attempts)
        current = self.current_baseline()
        self.run('repair-plan', str(self.config), repair, repaired, current['boot'], str(self.clock()))
        self.snapshot('repair-plan')
        r = self.plan_record(repair)
        a = self.plan_record(repaired)
        if r is None or (r['repairs'], r['signing'], r['selectionRevision'], r['baseApk'], str(r['baseVersion']),
                         str(r['baseUid']), r['baseContext'], r['bundleInput'], r['bundleVersion']) != (
                repaired, 0, a['selectionRevision'] + 1, current['base'], current['version'], current['uid'],
                current['context'], a['restorationInput'], a['restorationVersion']):
            raise DriverError('the repair plan is not the one its current baseline names')
        self.checkpoint('repair-plan', plan=repair, repairs=repaired, boot=current['boot'])
        self.run('repair-grants', str(self.config), repair, str(self.clock()), 'stage', 'activate')
        self.snapshot('repair-grants')
        effects = sorted(g['effect'] for g in self.grants(repair))
        if effects != ['ACTIVATE', 'STAGE'] or any(g['actor'] != 'LAB_OPERATOR' for g in self.grants(repair)):
            raise DriverError('the repair grants are %s, not STAGE and ACTIVATE' % effects)
        self.checkpoint('repair-grants', plan=repair, effects=effects)
        self.run('repair-ticket', str(self.config), repair, ticket)
        self.snapshot('repair-ticket')
        made = self.tickets(repair)
        if [(t['ticket'], t['attempt'], t['state']) for t in made] != [(ticket, 1, 'PLANNED')]:
            raise DriverError('the repair ticket is not its plan only attempt: %s' % made)
        self.checkpoint('repair-ticket', plan=repair, ticket=ticket)
        state = self.drive(cell, ticket, repair)
        return self.compare(cell, ticket, repair, state, mark)

    def campaign_references(self):
        """Every native reference the campaign made, from the store and the admission: each ticket's
        nonces, those of its CREATE entries included, each ticket's recorded session as its ID,
        creation time and installer, and each admitted direct control's referrer."""
        component = self.broker.admission['component']
        nonces, sessions = set(), set()
        for path in sorted((self.store / 'tickets').glob('*.rec')):
            if path.name.startswith('.'):
                continue
            t = lab_records.decode_ticket(path.read_bytes())
            if t['component'] != component:
                continue
            reference = t['reference']
            nonces.update(n for n in [reference[5]] + [e[5] for e in t['ledger'] if e[0] == 'CREATE']
                          if n != proto.ZERO_ID)
            if reference[1] > 0:
                sessions.add((reference[1], reference[2], reference[4]))
        controls = sorted({s['parameters']['control'] for s in self.broker.admission['lab_actions']
                           if s['type'] == 'DIRECT_STAGE'})
        return {'nonces': sorted(nonces), 'sessions': sorted(sessions), 'controls': controls}

    def _final_unknown(self, read):
        """Why the final reads are not one whole group of the checked boot, or None."""
        for name, groups in read.items():
            for group in groups:
                if not group.ok:
                    return 'the %s read ended %s: %s' % (name, group.status, group.reason)
        begin, end = read['clock'][0].reading, read['clock'][-1].reading
        if (begin['boot'], begin['instance']) != (end['boot'], end['instance']) or begin['instance'] < 0 \
                or begin['boot'] != self.t0:
            return 'the reads are not of one framework instance of the checked boot'
        if not read['global-sessions'][0].reading['whole']:
            return 'the global session inventory is not whole'
        if not read['inventory'][0].reading['whole']:
            return 'the user inventory is not whole'
        return None

    def final(self):
        """The final reads. A complete check of the current boot, then one whole read group between
        generations: the boot, checkpoint, factory and active copy, the whole global session
        inventory and the whole user inventory, bracketed by two clock reads of the checked boot's
        one framework instance. The end state: no open ticket; the selection R's at its revision,
        current; the checkpoint COMMITTED; the active copy R's exact bytes, versionCode, UID and
        context, which R's publication and plan name, on R's original cohort; and no live session
        the campaign owns in the whole join, where terminal history may stay. A read that is not
        whole, or a live session of the component whose owner the join cannot tell, leaves Final
        UNKNOWN; either stops the driver, as any difference does.

        Live sessions of other packages under other referrers are reported in every outcome the
        join reached, as observations: each its whole native reference as the inventory read it,
        its classification and the inventory's group. They are outside Final's claim of no live
        owned reference and never fail Final by themselves."""
        self.cell = 'final'
        self.check()
        groups = self.broker.controller_read(list(FINAL_READS), 'the final reads and their join')
        numbers = [g.number for g in groups]
        read = {}
        for name, group in zip(FINAL_READS, groups):
            read.setdefault(name, []).append(group)
        why = self._final_unknown(read)
        references = self.campaign_references()
        owned, uncertain, others = [], [], []
        if why is None:
            owned, uncertain, others = final_join(read['global-sessions'][0].reading,
                                                  self.broker.admission['component'], references)
            if uncertain:
                why = 'live sessions %s of the component, whose owner the join cannot tell' % uncertain
        reported = {'other_live': [{'classification': session_classification(row), 'session': row} for row in others],
                    'other_live_group': read['global-sessions'][0].number}
        if why is not None:
            self.results['final'] = dict(reported, status='UNKNOWN', reason=why, groups=numbers)
            self.checkpoint('final-unknown', reason=why, groups=numbers, **reported)
            raise DriverError('the final reads leave Final UNKNOWN: %s' % why)
        selection = self.selection()
        repair = self.plan_record(self.plans['R'])
        boot = lab_broker.Broker._one(read['boot'][0], 'BOOT', 'COMPLETED')
        factory = lab_broker.Broker._one(read['factory'][0], 'FACTORY', 'PRESENT')
        active = lab_broker.Broker._one(read['active'][0], 'ACTIVE')
        checkpoint = lab_broker.Broker._one(read['checkpoint'][0], 'CHECKPOINT')
        variant = (self.staged.get(self.plans['R']) or {}).get('base.apk', {}).get('sha256')
        identity = None if active is None else {'kind': active['classification'], 'apk': active['facts']['apk'],
                                                'version': active['facts']['version'], 'uid': active['facts']['uid'],
                                                'context': active['facts']['context']}
        exact = None if repair is None else {'kind': 'DATA_COPY', 'apk': variant, 'version': repair['bundleVersion'],
                                             'uid': repair['baseUid'], 'context': repair['baseContext']}
        original = repair is not None and boot is not None and factory is not None and (
            boot['facts']['fingerprint'], factory['facts']['apk'], factory['facts']['version']) == (
            repair['fingerprint'], repair['factoryApk'], repair['factoryVersion'])
        found = {'open_tickets': len(self.open_tickets()), 'choice': selection['choice'], 'plan': selection['plan'],
                 'revision': selection['revision'], 'realization': selection['realization'],
                 'checkpoint': checkpoint['classification'] if checkpoint else None,
                 'active': 'R' if identity is not None and variant is not None and identity == exact else identity,
                 'cohort': 'ORIGINAL' if original else 'OTHER', 'live_owned': len(owned)}
        wanted = dict(next_cells.by_cell('final', self.sequence)['prediction'], plan=self.plans['R'],
                      revision=repair['selectionRevision'] + 1 if repair else None)
        if found != wanted:
            differences = {k: {'found': found[k], 'predicted': wanted[k]} for k in found if found[k] != wanted[k]}
            self.checkpoint('cell-differs', cell='final', differences=differences, owned=owned, groups=numbers,
                            **reported)
            raise DriverError('the final reads differ: %s' % json.dumps({'found': found, 'predicted': wanted},
                                                                       sort_keys=True))
        users = [{k: u[k] for k in ('id', 'serial', 'type', 'state')}
                 for u in read['inventory'][0].reading['users']]
        self.results['final'] = dict(found, status='PASSED', users=users, groups=numbers, **reported)
        self.checkpoint('final', groups=numbers, users=users, **dict(found, **reported))
        return found

    def run_campaign(self, tickets, schedule, helpers, payloads=None, capabilities=None, boot_limit=4):
        """The whole matrix in its order: the entry, every cell of the sequence, and the final
        reads. `tickets` names each managed cell's ticket, `helpers` each helper jar's host path,
        `payloads` each direct control's pinned members and `capabilities` F0's record. Returns
        each cell's result; the first difference stops the campaign."""
        self.entry(schedule, helpers)
        for cell in self.sequence:
            if cell['kind'] in ('managed', 'final') and not next_cells.reached(cell, self.world):
                self.results[cell['cell']] = {'status': 'NOT_CAPTURED',
                                              'reason': 'not reached under the %s F0' % self.world['f0']}
                self.checkpoint('cell', cell=cell['cell'], result=self.results[cell['cell']])
            elif cell['kind'] == 'managed' and cell['plan'] == 'R':
                self.run_repair(cell, tickets[cell['cell']])
            elif cell['kind'] == 'managed':
                self.run_managed(cell, tickets[cell['cell']], boot_limit)
            elif cell['kind'] == 'direct':
                self.run_direct(cell, (payloads or {}).get(cell['role']))
            elif cell['kind'] == 'gate':
                self.decide_f0(capabilities, 'F0 after the direct controls')
            else:
                self.final()
        return self.results
