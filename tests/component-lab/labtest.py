# SPDX-License-Identifier: Apache-2.0
"""Host test support for the lab broker: a broker on a simulated guest in a temporary directory,
a client that sends exact protocol frames, and a small reader of observation records for checks."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for _path in (str(HERE), str(REPO)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import lab_actions  # noqa: E402
import lab_broker  # noqa: E402
import lab_protocol as proto  # noqa: E402
import sim_android  # noqa: E402
import source_manifest  # noqa: E402

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
             'tests/component-lab/lab_evidence.py', 'tests/component-lab/lab_records.py')
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
RUNTIME = 'e1' * 16
RESTART_ACTION, VISIBILITY_ACTION, PREPARATION_ACTION = '0a' * 16, '0b' * 16, '0c' * 16
PARAMETERS = {'FRAMEWORK_RESTART': {}, 'NOTICE_VISIBILITY': {},
              'HEALTH_PREPARATION': {'criteria': [2, 3, 5], 'max_probe_ms': 120_000}}


def action_spec(ident, kind, phase='F0', cell='f0-control', **changes):
    """One exact typed action spec of a registered type, with its type's authority, first selector,
    preconditions and parameters."""
    value = {'id': ident, 'type': kind, 'phase': phase, 'cell': cell, 'runtime': RUNTIME, 'installation': INSTALLATION,
             'authority': lab_actions.TYPES[kind]['authority'],
             'user_selector': {'kind': lab_actions.TYPES[kind]['selectors'][0]},
             'parameters': dict(PARAMETERS[kind]), 'inputs': [],
             'preconditions': list(lab_actions.TYPES[kind]['preconditions']), 'predecessor': None, 'successors': [],
             'max_uses': 10, 'timeout_ms': 600_000, 'stdout_max': 65536, 'stderr_max': 65536}
    value.update(changes)
    return value


def default_specs():
    return [action_spec(RESTART_ACTION, 'FRAMEWORK_RESTART'), action_spec(VISIBILITY_ACTION, 'NOTICE_VISIBILITY'),
            action_spec(PREPARATION_ACTION, 'HEALTH_PREPARATION', phase='A', cell='a-window')]


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
                           'LIMITED': None, 'REFUSED': {'predicate_sha256': 'd2' * 32, 'actions': []}},
                 effect_limits=effect_limits(), boot_policy={'activation_services': 4, 'observed_boots': 8,
                                                             'poll_interval_ms': 5000, 'settle_ms': 600_000,
                                                             'unexpected_boot': 'HALT'})
    value.update(changes)
    return value


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
                 health=None, publication=None, **changes):
        self._temp = None
        self.target = target
        self.target_read = target_read
        self.source_root = source_root or REPO
        if directory is None:
            self._temp = tempfile.TemporaryDirectory()
            directory = self._temp.name
        self.directory = Path(directory)
        self.root = self.directory / 'broker'
        self.sim = sim or sim_android.SimAndroid()
        self.clock = Clock()
        # The next profile admits its typed actions, and its reader the inventory, receipts and
        # health.
        self.reader_options = dict(reader or ({'inventory': True, 'receipts': True, 'health': True, 'witness': True}
                                              if next_profile else {}))
        self.health = health
        self.admission = (admission3(self.directory, specs=specs, **changes) if next_profile
                          else admission(self.directory, **changes))
        self.manifest = self.admission['manifest']
        self.notice = notice
        self.processes = processes or Processes()
        self.sync = sync
        lab_broker.Broker.initialize(self.root, self.admission, manifest_bytes())
        self.open()
        if cells:
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
                                             target_read=self.target_read, health=self.health)
        return self.broker

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
