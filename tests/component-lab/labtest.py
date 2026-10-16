# SPDX-License-Identifier: Apache-2.0
"""Host test support for the lab broker: a broker on a simulated guest in a temporary directory,
a client that sends exact protocol frames, and a small reader of observation records for checks."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest.mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for _path in (str(HERE), str(REPO)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import lab_actions  # noqa: E402
import lab_broker  # noqa: E402
import lab_evidence  # noqa: E402
import lab_losses  # noqa: E402
import lab_protocol as proto  # noqa: E402
import sim_android  # noqa: E402
import source_manifest  # noqa: E402
from scripts.proof import component_transaction_records as encoder  # noqa: E402

INSTALLATION = '00112233445566778899aabbccddeeff'
COORDINATOR = 'c0' * 16
TRUST = '7a' * 32
CONFIG = '3c' * 32
PLAN = '01' * 16
TICKET = '04' * 16
NONCE = '5e1f0c9a7d3b4e2f8a6c1d0b9e7f3a25'
GRANT = '2a' * 16
DEVICE_DIR = '/data/local/tmp/andrix-d5'
LAB_FILES = ('tests/component-lab/lab_protocol.py', 'tests/component-lab/lab_broker.py',
             'tests/component-lab/capture_ledger.py', 'tests/component-lab/lab_crossings.py',
             'tests/component-lab/lab_readers.py', 'tests/component-lab/shell_transport.py',
             'tests/component-lab/source_manifest.py', 'tests/component-lab/lab_actions.py',
             'tests/component-lab/lab_evidence.py', 'tests/component-lab/lab_records.py',
             'tests/component-lab/lab_losses.py', 'tests/component-lab/full_users.py')
LIMITS = {'read_timeout_s': 30, 'mutation_timeout_s': 60, 'commit_timeout_s': 150, 'push_timeout_s': 300,
          'reboot_timeout_s': 10, 'read_stdout_max': 4 << 20, 'read_stderr_max': 65536, 'reply_stdout_max': 65536,
          'reply_stderr_max': 65536, 'generation_idle_s': 30, 'drain_grace_s': 5, 'exit_grace_s': 30}


def manifest_bytes():
    return source_manifest.build(REPO, LAB_FILES)


def admission(directory, **changes):
    manifest = manifest_bytes()
    value = {'version': 1, 'installation': INSTALLATION, 'component': sim_android.PACKAGE, 'coordinator': COORDINATOR,
             'trust': TRUST, 'manifest': source_manifest.digest(manifest), 'config': CONFIG,
             'serial': '127.0.0.1:6520', 'target_scope': 'ESTABLISHED_EMPTY', 'device_dir': DEVICE_DIR,
             'fences': {'stop_file': str(Path(directory) / 'STOP'), 'lease_file': None, 'lease_token': None,
                        'deadline_wall_ns': None},
             'limits': dict(LIMITS)}
    value.update(changes)
    return value


# The next campaign profile: one runtime, three admitted typed actions and generous effect limits.
# The plain kernel confirmation is the profile's control action; the shell framework restart is
# withdrawn from it.
RUNTIME = 'e1' * 16
CONFIRM_ACTION, VISIBILITY_ACTION, PREPARATION_ACTION = '0a' * 16, '0b' * 16, '0c' * 16
PARAMETERS = {'PLAIN_KERNEL_CONFIRM': {}, 'NOTICE_VISIBILITY': {},
              'HEALTH_PREPARATION': {'criteria': [2, 3, 5], 'max_probe_ms': 120_000}}
# The positive attempt the F0 decision gates: the plan's attempt 6.
POSITIVE_ATTEMPT = 6
BOOT_POLICY = {'activation_services': 4, 'confirmation_services': 6, 'observed_boots': 13, 'poll_interval_ms': 5000,
               'settle_ms': 1_200_000, 'negative_settle_ms': 2_400_000, 'unexpected_boot': 'HALT'}


def action_spec(ident, kind, phase='F0', cell='f0-control', **changes):
    """One exact typed action spec of a registered type, with its type's authority, first selector,
    preconditions and parameters."""
    value = {'id': ident, 'type': kind, 'phase': phase, 'cell': cell, 'runtime': RUNTIME, 'installation': INSTALLATION,
             'authority': lab_actions.TYPES[kind]['authority'],
             'user_selector': {'kind': lab_actions.TYPES[kind]['selectors'][0]},
             'parameters': dict(PARAMETERS.get(kind, {})), 'inputs': [],
             'preconditions': list(lab_actions.TYPES[kind]['preconditions']), 'predecessor': None, 'successors': [],
             'max_uses': 10, 'timeout_ms': 600_000, 'stdout_max': 65536, 'stderr_max': 65536}
    value.update(changes)
    return value


def default_specs():
    return [action_spec(CONFIRM_ACTION, 'PLAIN_KERNEL_CONFIRM', phase='CELLS', cell='c0-confirm'),
            action_spec(VISIBILITY_ACTION, 'NOTICE_VISIBILITY'),
            action_spec(PREPARATION_ACTION, 'HEALTH_PREPARATION', phase='A', cell='a-window')]


# The full user setup's actions: one create, then the created user's start, switch, setup and
# fixture, and a switch back to the system user. An ordinary fixture with its pinned bytes.
CREATE_ACTION, START_ACTION, SWITCH_ACTION, SETUP_ACTION, FIXTURE_ACTION, HOME_ACTION = (
    '1a' * 16, '1b' * 16, '1c' * 16, '1d' * 16, '1e' * 16, '1f' * 16)
USER_NAME = 'AndrixLab'
FIXTURE_PACKAGE = 'dev.andrix.lab.notice'
FIXTURE_APK = b'F' * 4096 + b'an ordinary notice fixture'


def user_specs(steps=None, settle_ms=5000, start_uses=3):
    """The default specs and the full user setup's, each user action selecting the created user."""
    created = {'kind': 'CREATED_BY', 'action': CREATE_ACTION}
    steps = [{'key': 'KEYCODE_ENTER'}] if steps is None else steps
    pin = [{'role': 'base.apk', 'sha256': hashlib.sha256(FIXTURE_APK).hexdigest(), 'bytes': len(FIXTURE_APK)}]
    return default_specs() + [
        action_spec(CREATE_ACTION, 'USER_CREATE', cell='f0-create-user', max_uses=1,
                    parameters={'user_type': lab_actions.SECONDARY_TYPE, 'name': USER_NAME}),
        action_spec(START_ACTION, 'USER_START', cell='f0-start-user', user_selector=created, max_uses=start_uses),
        action_spec(SWITCH_ACTION, 'USER_SWITCH', cell='f0-switch-user', user_selector=created),
        action_spec(SETUP_ACTION, 'USER_SETUP', cell='f0-setup-user', user_selector=created,
                    parameters={'steps': steps, 'settle_ms': settle_ms}),
        action_spec(FIXTURE_ACTION, 'USER_FIXTURE', cell='f0-user-fixture', user_selector=created,
                    parameters={'package': FIXTURE_PACKAGE}, inputs=pin),
        action_spec(HOME_ACTION, 'USER_SWITCH', cell='f0-switch-home', user_selector={'kind': 'SYSTEM_USER'})]


def schedule(faults, installation=INSTALLATION):
    """The canonical bytes of a fault schedule of the next profile."""
    return lab_evidence.canonical({'schema': lab_losses.SCHEMA, 'profile': lab_actions.PROFILE,
                                   'installation': installation, 'faults': list(faults)})


def effect_limits(cap=100):
    return {'crossings': {name: cap for name in proto.DEVICE_CROSSINGS}, 'direct': cap, 'admin': cap, 'fixture': cap,
            'control': cap, 'phases': {phase: cap for phase in lab_actions.PHASES}}


def admission3(directory, store=None, specs=None, **changes):
    """A version 3 admission of the next campaign profile on the version 1 base."""
    value = admission(directory)
    specs = default_specs() if specs is None else specs
    value.update(version=3, launches=list(proto.DEVICE_CROSSINGS), store=str(store or Path(directory) / 'store'),
                 profile=lab_actions.PROFILE, cells_sha256='c1' * 32, fixtures_sha256='f1' * 32,
                 payloads_sha256='a1' * 32, fault_schedule_sha256='b1' * 32, lab_actions=specs,
                 branches={'FULL': {'predicate_sha256': 'd1' * 32, 'actions': [s['id'] for s in specs]},
                           'LIMITED': None, 'REFUSED': {'predicate_sha256': 'd2' * 32, 'actions': []},
                           'positive': {'plan': PLAN, 'attempt': POSITIVE_ATTEMPT}},
                 effect_limits=effect_limits(), boot_policy=dict(BOOT_POLICY))
    value.update(changes)
    return value


def plan_record(plan=PLAN, **changes):
    """A whole stored plan of the independent encoder, of this installation and component."""
    return encoder.plan(dict(encoder.base_plan(1), plan=plan, **changes))


def ticket_record(sim, state, ticket=TICKET, plan=PLAN, attempt=1, ledger=None, **changes):
    """A whole stored ticket of the independent encoder in one state, its boot the guest's, by
    default after a CREATE entry under the STAGE grant with the ticket's nonce."""
    value = dict(encoder.base_ticket(1, plan), ticket=ticket, attempt=attempt, state=state, boot=sim.boot,
                 reference=(16, 0, 0, '', 0, NONCE))
    value['ledger'] = ([('CREATE', sim.boot, sim.instance, 5000, GRANT, NONCE, encoder.TIME)] if ledger is None
                       else ledger)
    value.update(changes)
    return encoder.ticket(value)


def f0_record(branch, installation=INSTALLATION, **extra):
    """An F0 capability record of the next profile naming its branch: the fields the broker's fence
    reads. The trial's whole record is a later package's."""
    return lab_evidence.canonical(dict({'schema': lab_broker.F0_SCHEMA, 'profile': lab_actions.PROFILE,
                                        'installation': installation, 'branch': branch}, **extra))


def state_code(name):
    """A ticket state's code, as an OBSERVE names it."""
    return encoder.STATES.index(name) + 1


# Two direct negative controls, N2 and N3, each a stage, a commit and an activation, in order.
N2_CONTROL, N3_CONTROL = 'a2' * 16, 'a3' * 16
N2_PAYLOAD = (('base.apk', b'N' * 2048 + b'signed by another key'), ('base.apk.idsig', b'S' * 256 + b'its sidecar'))
N3_PAYLOAD = (('base.apk', b'M' * 2048 + b'correctly signed, no sidecar'),)
DIRECT_IDS = {('N2', 'DIRECT_STAGE'): 'd1' * 16, ('N2', 'DIRECT_COMMIT'): 'd2' * 16,
              ('N2', 'NEGATIVE_ACTIVATION'): 'd3' * 16, ('N3', 'DIRECT_STAGE'): 'd4' * 16,
              ('N3', 'DIRECT_COMMIT'): 'd5' * 16, ('N3', 'NEGATIVE_ACTIVATION'): 'd6' * 16}


def direct_specs(roles=('N2', 'N3')):
    """The admitted specs of the direct negative controls of these roles, chained in order."""
    specs, previous = [], None
    for role in roles:
        control, payload = (N2_CONTROL, N2_PAYLOAD) if role == 'N2' else (N3_CONTROL, N3_PAYLOAD)
        for kind in lab_actions.DIRECT_STEPS:
            ident = DIRECT_IDS[(role, kind)]
            inputs = [{'role': m, 'sha256': hashlib.sha256(d).hexdigest(), 'bytes': len(d)} for m, d in payload]
            specs.append(action_spec(ident, kind, phase=role, cell='%s-%s' % (role.lower(), kind.lower().replace('_', '-')),
                                     parameters={'control': control, 'role': role},
                                     inputs=inputs if kind == 'DIRECT_STAGE' else [], max_uses=1, predecessor=previous))
            if previous is not None:
                specs[-2]['successors'] = [ident]
            previous = ident
    return specs


class SyncTrace:
    """Records, in order, every file created, written and synced, every directory made and
    synced and every rename under one root, through the broker's injected sync and the os calls,
    and builds the image a power loss at a mark would leave: a path whose name, and its parents'
    names, were synced in their directories after they appeared, and a file whose content was
    synced after its last write. Content that was not synced is lost."""

    def __init__(self, root):
        self.root, self.events, self.fds = str(root), [], {}
        self._real = {name: getattr(os, name) for name in ('open', 'write', 'rename', 'mkdir', 'fsync', 'close')}
        self._patches = []

    def _under(self, path):
        path = os.path.abspath(str(path))
        return path == self.root or path.startswith(self.root + os.sep)

    def fsync(self, fd):
        path = self.fds.get(fd) or os.readlink('/proc/self/fd/%d' % fd)
        if self._under(path):
            self.events.append(('fsync-dir' if os.path.isdir(path) else 'fsync-file', path))
        return self._real['fsync'](fd)

    def __enter__(self):
        real = self._real

        def opened(path, flags, *args, **kwargs):
            fd = real['open'](path, flags, *args, **kwargs)
            full = os.path.abspath(os.fspath(path))
            if self._under(full):
                self.fds[fd] = full
                if flags & os.O_CREAT:
                    self.events.append(('create', full))
            return fd

        def written(fd, data):
            count = real['write'](fd, data)
            if fd in self.fds:
                self.events.append(('write', self.fds[fd]))
            return count

        def renamed(src, dst, *args, **kwargs):
            real['rename'](src, dst, *args, **kwargs)
            if self._under(dst):
                self.events.append(('rename', os.path.abspath(os.fspath(src)), os.path.abspath(os.fspath(dst))))

        def made(path, *args, **kwargs):
            real['mkdir'](path, *args, **kwargs)
            if self._under(path):
                self.events.append(('mkdir', os.path.abspath(os.fspath(path))))

        def closed(fd):
            self.fds.pop(fd, None)
            return real['close'](fd)
        for name, fake in (('open', opened), ('write', written), ('rename', renamed), ('mkdir', made),
                           ('close', closed), ('fsync', self.fsync)):
            patch = unittest.mock.patch.object(os, name, fake)
            patch.start()
            self._patches.append(patch)
        return self

    def __exit__(self, *failure):
        for patch in reversed(self._patches):
            patch.stop()
        self._patches = []

    def mark(self, label):
        self.events.append(('mark', label))

    def at(self, label):
        return self.events.index(('mark', label))

    def durable(self, upto):
        """(durable names, files whose content is durable, names that appeared) of the events
        before index `upto`."""
        born, named, content, dirty = {}, set(), set(), set()
        for at, event in enumerate(self.events[:upto]):
            kind = event[0]
            if kind in ('create', 'mkdir'):
                born[event[1]] = at
                if kind == 'create':
                    dirty.add(event[1])
            elif kind == 'write':
                dirty.add(event[1])
                content.discard(event[1])
            elif kind == 'fsync-file':
                if event[1] in dirty:
                    dirty.discard(event[1])
                content.add(event[1])
            elif kind == 'rename':
                src, dst = event[1], event[2]
                born[dst] = at
                named.discard(src)
                if src in content:
                    content.discard(src)
                    content.add(dst)
                dirty.discard(src)
            elif kind == 'fsync-dir':
                for path, when in born.items():
                    if os.path.dirname(path) == event[1] and when < at:
                        named.add(path)
        return named, content, set(born)

    def image(self, label, target):
        """Copies under `target` what a loss right at the mark would leave of the root. Paths the
        trace saw made, written or renamed are kept only when durable, and a file whose content
        was not synced is left empty; what existed before the trace is kept as it was."""
        named, content, born = self.durable(self.at(label))
        changed = {e[1] for e in self.events if e[0] in ('create', 'write')} | {e[2] for e in self.events
                                                                                 if e[0] == 'rename'}
        made = {e[1] for e in self.events if e[0] == 'mkdir'}

        def reachable(path):
            # A name that appeared during the trace needs its directory's sync; one that was
            # already there is as durable as it was.
            while path != self.root:
                if path in born and path not in named:
                    return False
                path = os.path.dirname(path)
            return True
        target = Path(target)
        shutil.copytree(self.root, target, symlinks=True)
        for directory, dirs, files in os.walk(target, topdown=False):
            for name in files:
                copy = Path(directory) / name
                source = os.path.join(self.root, os.path.relpath(copy, target))
                if source in changed and not reachable(source):
                    copy.unlink()
                elif source in changed and source not in content:
                    copy.write_bytes(b'')
            for name in dirs:
                copy = Path(directory) / name
                source = os.path.join(self.root, os.path.relpath(copy, target))
                if source in made and not reachable(source):
                    shutil.rmtree(copy)
        return target


class Clock:
    """A host clock that tests move by hand."""

    def __init__(self):
        self.wall = 1_791_504_000_000_000_000
        self.mono = 1_000_000_000
        self.slept = []

    def wall_ns(self):
        return self.wall

    def monotonic_ns(self):
        return self.mono

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.wall += int(seconds * 1e9)
        self.mono += int(seconds * 1e9)


class Processes:
    """Process control for a lost generation: alive until killed."""

    def __init__(self, alive=False):
        self.living, self.killed = alive, []

    def alive(self, pid, start):
        return self.living

    def kill(self, pid):
        self.killed.append(pid)
        self.living = False


class Harness:
    """A broker over a simulated guest, and a client for one generation."""

    def __init__(self, directory=None, sim=None, cells=(), pins=True, notice=None, processes=None, sync=False,
                 target=None, source_root=None, target_read=False, next_profile=False, specs=None, reader=None,
                 health=None, publication=None, fsync=None, **changes):
        self._temp = None
        self.target = target
        self.target_read = target_read
        self.source_root = source_root or REPO
        if directory is None:
            self._temp = tempfile.TemporaryDirectory()
            directory = self._temp.name
        self.broker = None
        try:
            self._setup(Path(directory), sim, cells, pins, notice, processes, sync, next_profile, specs, reader,
                        health, publication, fsync, changes)
        except BaseException:
            # A refused setup, such as a malformed fault schedule a test expects the broker
            # to refuse, leaves no open broker and no temporary directory behind.
            if self.broker is not None:
                self.broker.close()
            if self._temp is not None:
                self._temp.cleanup()
            raise

    def _setup(self, directory, sim, cells, pins, notice, processes, sync, next_profile, specs, reader, health,
               publication, fsync, changes):
        self.directory = directory
        self.root = self.directory / 'broker'
        self.sim = sim or sim_android.SimAndroid()
        self.clock = Clock()
        # The next profile admits its typed actions, and its reader the inventory, receipts, health
        # and the global session inventory. Its faults come only from the schedule it binds.
        self.reader_options = dict(reader or ({'inventory': True, 'receipts': True, 'health': True, 'witness': True,
                                               'global_sessions': True} if next_profile else {}))
        self.health = health
        self.schedule = schedule(cells) if next_profile and cells else None
        if self.schedule is not None:
            changes.setdefault('fault_schedule_sha256', hashlib.sha256(self.schedule).hexdigest())
        self.admission = (admission3(self.directory, specs=specs, **changes) if next_profile
                          else admission(self.directory, **changes))
        self.manifest = self.admission['manifest']
        self.notice = notice
        self.processes = processes or Processes()
        self.sync = sync
        self.fsync = fsync
        lab_broker.Broker.initialize(self.root, self.admission, manifest_bytes())
        self.open()
        if self.schedule is not None:
            self.broker.admit_schedule(self.schedule)
        elif cells:
            self.broker.admit_faults(list(cells))
        self.apk = b'A' * 4096 + b'variant'
        self.idsig = b'S' * 512 + b'sidecar'
        if pins:
            self.pin(PLAN, self.apk, self.idsig, publication if publication or not next_profile else '9f' * 32)
        self.state = None
        self.requests = 0

    def pin(self, plan, apk, idsig, publication=None):
        members = {}
        for member, data in (('base.apk', apk), ('base.apk.idsig', idsig)):
            path = self.directory / ('%s-%s' % (plan, member))
            path.write_bytes(data)
            members[member] = {'host': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        self.broker.pin_artifacts(plan, members, publication)
        self.sim.apks[hashlib.sha256(apk).hexdigest()] = 40

    def open(self):
        self.broker = lab_broker.Broker.open(self.root, self.source_root, sim_android.SimTransport(self.sim),
                                             sim_android.SimReader(INSTALLATION, target=self.target_read,
                                                                   **self.reader_options), notice=self.notice,
                                             wall=self.clock.wall_ns, monotonic=self.clock.monotonic_ns,
                                             sleep=self.clock.sleep, ids=lambda n: os.urandom(n),
                                             processes=self.processes, sync=self.sync, target=self.target,
                                             target_read=self.target_read, health=self.health, fsync=self.fsync)
        return self.broker

    def open_at(self, root):
        """A broker on another directory, such as a copy, over the same guest and clocks."""
        return lab_broker.Broker.open(root, self.source_root, sim_android.SimTransport(self.sim),
                                      sim_android.SimReader(INSTALLATION, target=self.target_read, **self.reader_options),
                                      notice=self.notice, wall=self.clock.wall_ns, monotonic=self.clock.monotonic_ns,
                                      sleep=self.clock.sleep, ids=lambda n: os.urandom(n), processes=self.processes,
                                      sync=self.sync, target=self.target, target_read=self.target_read,
                                      health=self.health)

    def pin_payloads(self, roles=('N2', 'N3')):
        """Pins each direct control's negative payload, and makes N2's APK one of another signer."""
        for role in roles:
            control, payload = (N2_CONTROL, N2_PAYLOAD) if role == 'N2' else (N3_CONTROL, N3_PAYLOAD)
            members = {}
            for member, data in payload:
                path = self.directory / ('%s-%s' % (control, member))
                path.write_bytes(data)
                members[member] = {'host': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            self.broker.pin_payload(control, members)
        self.sim.wrong_signer.add(hashlib.sha256(N2_PAYLOAD[0][1]).hexdigest())

    def reopen(self):
        self.broker.close()
        return self.open()

    def close(self):
        self.broker.close()
        if self._temp is not None:
            self._temp.cleanup()

    # ------------------------------------------------ one generation, without a process

    def begin(self, pid=None, start_ticks=None):
        self.state = self.broker.begin_generation(pid, start_ticks)
        return self.state

    def end(self, code=0):
        return self.broker.end_served(self.state, code)

    def call(self, kind, manifest=None, **fields):
        """One request through the exact encoding, its reply decoded from the exact encoding."""
        self.requests += 1
        request = '%032x' % (0xabc000 + self.requests)
        message = proto.message(kind, request, manifest or self.manifest, **fields)
        version = self.broker.protocol
        data = proto.encode(message, version)
        reply = self.broker.handle(proto.decode(data, version), self.state)
        decoded = proto.decode(proto.encode(reply, version), version)
        assert decoded['request'] == request and decoded['type'] == proto.reply_type(kind)
        return decoded

    def hello(self, **changes):
        fields = {'installation': INSTALLATION, 'coordinator': COORDINATOR, 'config': CONFIG,
                  'component': sim_android.PACKAGE, 'trust': TRUST, 'route': 1}
        fields.update(changes)
        return self.call('HELLO', **fields)

    def clock_read(self):
        return self.call('CLOCK')

    def observe(self, scope='TICKET', boot=None, state=6):
        ticket = TICKET if scope == 'TICKET' else proto.ZERO_ID
        plan = PLAN if scope == 'TICKET' else proto.ZERO_ID
        return self.call('OBSERVE', scope=proto.SCOPES[scope], component=sim_android.PACKAGE,
                         boot=boot or self.sim.boot, ticket=ticket, plan=plan, state=state if scope == 'TICKET' else 0)

    def cross(self, crossing, index, occurrence=1, native=None, entry_boot=None, entry_instance=None, ticket=TICKET,
              plan=PLAN, attempt=1, bundle_apk=None, entry_elapsed=1000, granted_at=None, window=None,
              ticket_digest='11' * 32, plan_digest='22' * 32, actor=None):
        granted = crossing in proto.GRANTED
        activated = crossing in proto.ACTIVATED
        if granted_at is None:
            # By default the grant was given at the simulated guest's wall time zero of uptime, for a
            # window far longer than any test, so it is valid at launch.
            granted_at = sim_android.WALL_BASE if activated else 0
        if window is None:
            window = 10 ** 9 if activated else 0
        if native is None:
            native = (proto.NONCE, 0, 0, '', 0, NONCE) if crossing == 'CREATE' else self.bound()
        if bundle_apk is None:
            bundle_apk = hashlib.sha256(self.apk).hexdigest() if crossing == 'WRITE' else proto.ZERO_DIGEST
        return self.call('CROSS', ticket=ticket, ticket_digest=ticket_digest, plan=plan, plan_digest=plan_digest,
                         attempt=attempt, component=sim_android.PACKAGE, index=index,
                         crossing=proto.CROSSINGS[crossing][0], occurrence=occurrence,
                         entry_boot=entry_boot or self.sim.boot,
                         entry_instance=self.sim.instance if entry_instance is None else entry_instance,
                         entry_elapsed=entry_elapsed, grant=GRANT if granted else proto.ZERO_ID,
                         reference=NONCE if crossing == 'CREATE' else proto.ZERO_ID, native=native,
                         bundle_apk=bundle_apk, actor=(2 if granted else 0) if actor is None else actor,
                         granted=granted_at, window=window)

    def round_done(self, ticket=TICKET, plan=PLAN, attempt=1, ordinal=None, milestone=0, **changes):
        """One ROUND_DONE naming the stored ticket and selection by their SHA-256 and, unless given,
        the ticket's next checkpoint ordinal."""
        store = Path(self.admission['store'])
        fields = {'ticket': ticket, 'plan': plan, 'attempt': attempt, 'milestone': milestone,
                  'checkpoint_ordinal': (len(self.broker.checkpoints.get(ticket, [])) + 1 if ordinal is None
                                         else ordinal)}
        fields.update(changes)
        if 'ticket_digest' not in fields:
            fields['ticket_digest'] = hashlib.sha256((store / 'tickets' / (ticket + '.rec')).read_bytes()).hexdigest()
        if 'selection_digest' not in fields:
            fields['selection_digest'] = hashlib.sha256((store / 'selections' / (sim_android.PACKAGE + '.rec'))
                                                        .read_bytes()).hexdigest()
        return self.call('ROUND_DONE', **fields)

    def bound(self, nonce=NONCE):
        """The shell route's whole reference of the session that carries the nonce, as a ticket binds it."""
        for s in self.sim.sessions.values():
            if s.nonce == nonce:
                return (31, s.identity, s.created, '/data/app-staging/session_%d' % s.identity, 2000, nonce)
        return (31, 77, 5, '/data/app-staging/session_77', 2000, nonce)

    def entries(self, kind=None):
        return [e for e in self.broker.ledger.entries if kind is None or e.kind == kind]


def read_observation(frame):
    """The common fields of an observation record, and a REPLY's facts, from the README layout."""
    magic, kind, version, length = struct.unpack('<IHHI', frame[:12])
    assert (magic, kind, version, length) == (0x52445841, 4, 1, len(frame))
    assert hashlib.sha256(frame[:-32]).digest() == frame[-32:]
    at = 12
    out = {'installation': frame[at:at + 16].hex(), 'observation': frame[at + 16:at + 32].hex()}
    at += 32
    size = struct.unpack('<H', frame[at:at + 2])[0]
    out['component'] = frame[at + 2:at + 2 + size].decode('ascii')
    at += 2 + size
    out['boot'] = frame[at:at + 16].hex()
    at += 16
    out['user'], out['serial'], out['kind'], out['route'], out['instance'], out['elapsed'], out['wall'] = \
        struct.unpack('<iqBBqqq', frame[at:at + 38])
    at += 38
    out['raw'] = frame[at:at + 32].hex()
    out['classification'] = frame[at + 32]
    at += 33
    if out['kind'] == 7:
        out['ticket'] = frame[at:at + 16].hex()
        out['index'], out['crossing'] = struct.unpack('<HB', frame[at + 16:at + 19])
        at += 19
        presence, session, created = struct.unpack('<Biq', frame[at:at + 13])
        at += 13
        size = struct.unpack('<H', frame[at:at + 2])[0]
        stage = frame[at + 2:at + 2 + size].decode('ascii')
        at += 2 + size
        installer = struct.unpack('<i', frame[at:at + 4])[0]
        nonce = frame[at + 4:at + 20].hex()
        out['reference'] = (presence, session, created, stage, installer, nonce)
    return out


REPLY_CODES = {'SUCCESS': 1, 'REFUSED': 2, 'READY': 3, 'ACCEPTED': 4, 'PENDING': 5, 'UNRECOGNIZED': 6}
