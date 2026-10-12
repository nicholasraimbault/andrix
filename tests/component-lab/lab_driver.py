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
  another boot, and the selection then records that boot as checked. A check that completed without reading, for instance with the clock unavailable,
  establishes nothing; any later generation, of any kind or outcome, ends T0;
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
  KILLED and LOST stop the driver.

Each Java process gets the lab host configuration and its digest as the system properties
andrix.lab.host and andrix.lab.hostSha256, and, once the broker's admission exists, the bridge
configuration digest that admission binds as andrix.lab.admittedConfig, taken from the admission the
broker opened, never from the configuration file itself; every command after `init` refuses a bridge
configuration with another digest, and the configuration names the host configuration's digest.
Host code: it starts no guest itself."""
from pathlib import Path
import re
import subprocess
import time

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
        return digest

    def generation(self, *args):
        """One coordinator generation through the broker, with the lab host wired in."""
        if self.broker is None:
            raise DriverError('generations need the admitted broker')
        self.t0 = None  # A plan binds only the boot of a check that is the last generation.
        summary = self.broker.run_generation(self._argv(str(self.config), *args))
        self.generations.append(summary)
        return summary

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

    def plan(self, plan, ticket, boot_limit):
        """The immutable plan from T0's facts, its lab grants and its first ticket."""
        if not (HEX16.fullmatch(plan) and HEX16.fullmatch(ticket)) or not 1 <= int(boot_limit) <= 32:
            raise DriverError('a plan and ticket ID and a boot limit of 1 to 32')
        if self.t0 is None:
            raise DriverError('a plan is made right after a complete baseline check, and none is the last generation')
        line = self.run('plan', str(self.config), plan, ticket, str(int(boot_limit)), str(self.clock()), self.t0).strip()
        return dict(part.split('=', 1) for part in line.split(' '))

    def ticket(self, plan, ticket, activate=False):
        """The plan's next attempt, with a fresh STAGE grant, and ACTIVATE when asked."""
        self.run('ticket', str(self.config), plan, ticket, str(self.clock()), *(('activate',) if activate else ()))

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

    def drive(self, ticket, plan, done, generations=12, rounds=40, between=None, staged=None):
        """Advances a ticket until `done(state)`. Before the plan's variant is pinned, one round per
        generation, so that its publication is staged after PUBLISH and before the WRITE that needs
        it (a round issues one crossing); then settles. `staged(members)` runs once the variant is
        pinned, `between(state)` after each generation that did not finish, for instance to let lab
        time pass. Returns the last state, or raises DriverError after `generations`."""
        state = None
        for _ in range(generations):
            if plan in self.staged:
                self.advance('settle', ticket, str(rounds))
            else:
                self.advance('round', ticket)
            state = self.inspect(ticket)
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
