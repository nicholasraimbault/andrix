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
Host code: it starts no guest itself."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import time

import cells
import lab_broker

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
