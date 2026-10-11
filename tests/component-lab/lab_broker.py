# SPDX-License-Identifier: Apache-2.0
"""The broker of one admitted guest runtime: the only writer of guest commands, raw captures and
fault decisions, and the far end of the Java bridge.

A broker directory holds:

    <root>/lock            held with an exclusive lock by the one open broker
    <root>/admission.json  the admitted configuration, written once
    <root>/manifest.json   the exact source manifest, written once
    <root>/ledger/         the numbered ledger, capture_ledger.py
    <root>/jvm/NNNNNN.stderr  each coordinator generation's diagnostics, outside the ledger

One coordinator JVM at a time, a generation, talks to the broker over its own standard input and
output, which the broker created. Requests are handled one at a time to the end, so at most one
guest command is in flight. The broker checks every fence, the stop file, the lease and the runtime
deadline, before every guest command, reads included. Once a fence trips the stop is latched in
the ledger, and no guest command follows it in this broker or any later one on the same ledger.

The broker never repeats a crossing: it records each crossing before its first command and refuses
any later request for the same ticket and ledger index. A reply that an admitted fault cell drops
is executed once, recorded with an escrow entry and withheld; it is never given to any generation
later. A loss before or after an effect is consumed in the ledger before the broker tells the
generation to halt. That a command was not launched is recorded for the closure and never becomes
an observation, so it can never serve as proof that the guest has no session.

When a generation ends, the broker reaps its process before it serves another. When the broker
itself is lost, the next broker quarantines the incomplete last entry, waits out the bound of a
command whose effect is unknown, and ends the lost generation's process before it serves again.
Host evidence only."""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _path in (str(HERE), str(ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import capture_ledger as ledgers  # noqa: E402
import lab_crossings as crossings  # noqa: E402
import lab_protocol as proto  # noqa: E402
import lab_readers as readers  # noqa: E402
import shell_transport  # noqa: E402
import source_manifest  # noqa: E402
from scripts.proof import component_transaction_records as encoder  # noqa: E402

ADMISSION = 'admission.json'
MANIFEST = 'manifest.json'
LEDGER = 'ledger'
LOCK = 'lock'
JVM = 'jvm'
HALT_STATUS = 99
STOPPED_STATUS = 125
TARGET_SCOPES = ('ESTABLISHED_EMPTY', 'HELD', 'UNKNOWN')
LIMIT_KEYS = ('read_timeout_s', 'mutation_timeout_s', 'commit_timeout_s', 'push_timeout_s', 'reboot_timeout_s',
              'read_stdout_max', 'read_stderr_max', 'reply_stdout_max', 'reply_stderr_max', 'generation_idle_s',
              'drain_grace_s', 'exit_grace_s')
CELL_KEYS = {'cross': ('plan', 'attempt', 'crossing', 'occurrence'), 'host': ('plan', 'attempt', 'crossing', 'occurrence'),
             'point': ('plan', 'attempt', 'point')}
CELL_MODES = {'cross': ('loss-before', 'loss-after', 'drop-reply', 'loss-between-members'),
              'host': ('loss-before', 'loss-after', 'drop-reply'), 'point': ('halt',)}
LIVE = ('OPEN', 'SEALED', 'VERIFYING', 'LIVE_NOT_READY', 'READY')
GROUP_KINDS = {'boot': ('BOOT',), 'checkpoint': ('CHECKPOINT',), 'factory': ('FACTORY',), 'active': ('ACTIVE',),
               'sessions': ('LISTING', 'SESSION'), 'users': ('USER',), 'receipts': ('RECEIPT',)}
DEVICE_KINDS = ('BOOT', 'CHECKPOINT', 'USER')
MEMBER_MODE = 0o644

# The ledger's command text for the reboot service, which has no shell command.
REBOOT_LABEL = 'adb service reboot:'


class BrokerError(Exception):
    """The broker cannot open or continue safely. Nothing further is served."""


class Stopped(Exception):
    """A fence tripped: no guest command follows."""


class Group:
    """One recorded group: its ledger number, facts, encoded frames, status, reason and, for a
    clock group, its reading."""

    def __init__(self, number, facts, frames, status, reason, reading):
        self.number, self.facts, self.frames = number, facts, frames
        self.status, self.reason, self.reading = status, reason, reading

    @property
    def ok(self):
        return self.status == 'facts'


class _NotLaunched(readers.Unavailable):
    """A command was refused before it was sent: the device's features could not be read, or an
    activation grant may have expired before its launch. Nothing was launched."""


class _TransferBound(Exception):
    """A request or reply transfer did not finish within its bound."""


class _Halt(Exception):
    def __init__(self, record):
        super().__init__('halt')
        self.record = record


def _hex(value, width):
    return isinstance(value, str) and len(value) == 2 * width and all(c in '0123456789abcdef' for c in value)


def check_admission(value):
    """The admitted configuration, every field checked."""
    try:
        return _check_admission(value)
    except (ValueError, TypeError, KeyError) as error:
        raise BrokerError('admission: %s' % error) from error


def _check_admission(value):
    expected = {'version', 'installation', 'component', 'coordinator', 'trust', 'manifest', 'config', 'serial',
                'target_scope', 'device_dir', 'fences', 'limits'}
    if not isinstance(value, dict) or set(value) != expected or value['version'] != 1:
        raise BrokerError('not a version 1 admission')
    for name, width in (('installation', 16), ('coordinator', 16), ('trust', 32), ('manifest', 32), ('config', 32)):
        if not _hex(value[name], width) or value[name] == '00' * width:
            raise BrokerError('admission %s is not a nonzero digest' % name)
    proto.check_package(value['component'])
    if not isinstance(value['serial'], str) or not value['serial'] or any(ord(c) < 0x21 or ord(c) > 0x7e
                                                                          for c in value['serial']):
        raise BrokerError('admission serial')
    if value['target_scope'] not in TARGET_SCOPES:
        raise BrokerError('admission target scope')
    crossings.staged_path(value['device_dir'] + '/x')
    fences = value['fences']
    if not isinstance(fences, dict) or set(fences) != {'stop_file', 'lease_file', 'lease_token', 'deadline_wall_ns'}:
        raise BrokerError('admission fences')
    if not isinstance(fences['stop_file'], str) or not fences['stop_file'].startswith('/'):
        raise BrokerError('a stop file is required')
    if (fences['lease_file'] is None) != (fences['lease_token'] is None):
        raise BrokerError('a lease file exactly with its token')
    if fences['lease_file'] is not None and (not str(fences['lease_file']).startswith('/')
                                             or not isinstance(fences['lease_token'], str) or not fences['lease_token']):
        raise BrokerError('a lease is an absolute file and a nonempty token')
    deadline = fences['deadline_wall_ns']
    if deadline is not None and (not isinstance(deadline, int) or isinstance(deadline, bool) or deadline <= 0):
        raise BrokerError('a runtime deadline is a positive wall time')
    limits = value['limits']
    if not isinstance(limits, dict) or set(limits) != set(LIMIT_KEYS):
        raise BrokerError('admission limits')
    for name in LIMIT_KEYS:
        if not isinstance(limits[name], (int, float)) or isinstance(limits[name], bool) or limits[name] <= 0:
            raise BrokerError('admission limit %s' % name)
    return value


class Fences:
    """The stop file, the lease and the runtime deadline."""

    def __init__(self, spec, wall):
        self.spec, self._wall = spec, wall

    def check(self):
        if os.path.lexists(self.spec['stop_file']):
            return 'the stop file exists'
        if self.spec['lease_file'] is not None:
            try:
                with open(self.spec['lease_file'], 'rb') as handle:
                    token = handle.read(4096)
            except OSError:
                return 'the lease is not held'
            if token.strip() != self.spec['lease_token'].encode('ascii'):
                return 'the lease is not held'
        if self.spec['deadline_wall_ns'] is not None and self._wall() >= self.spec['deadline_wall_ns']:
            return 'the runtime deadline passed'
        return None


def activation_deadline(wall_ms, started_ns, granted, window):
    """The host monotonic instant before which an ACTIVATE grant stays valid by the reconciler's
    rule, or None when the clock reading itself is outside it. By that rule a grant is expired before
    its grant time and from its grant time plus its window on. Grant and reading share the reader's
    wall clock, the domain the reconciler judges grants in; the lab's observer stamps its readings
    with the host's. The deadline assumes that this wall clock advances no faster than the host
    monotonic clock from `started_ns`, when the clock read began. A step of the wall clock is not
    covered."""
    if wall_ms < granted or wall_ms - granted >= window:
        return None
    return started_ns + (granted + window - wall_ms) * 1_000_000


def proc_start_ticks(pid):
    """(state, start ticks) of a live process from /proc, or None."""
    try:
        text = Path('/proc/%d/stat' % pid).read_text()
    except OSError:
        return None
    fields = text[text.rindex(')') + 2:].split()
    return fields[0], int(fields[19])


class ProcessControl:
    """How the broker ends the process of a generation that a lost broker left."""

    def alive(self, pid, start):
        found = proc_start_ticks(pid)
        return found is not None and found[1] == start and found[0] != 'Z'

    def kill(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def matches(native, seen):
    """Whether an observed reference is the ticket's exact one: the reconciler's rule. The IDs agree,
    every field both know agrees, and createdMillis or the nonce is known to both."""
    presence, session, created, stage, installer, nonce = native
    p2, s2, c2, st2, i2, n2 = seen
    both = presence & p2
    if not both & proto.SESSION or session != s2:
        return False
    if (both & proto.CREATED and created != c2 or both & proto.STAGE_DIR and stage != st2
            or both & proto.INSTALLER and installer != i2 or both & proto.NONCE and nonce != n2):
        return False
    return bool(both & (proto.CREATED | proto.NONCE))


class Broker:
    """Open with `Broker.open`. `transport` is a shell_transport.AdbClient or a fake with the same
    methods, `reader` a lab_readers.ReaderAdapter, `notice` an optional notice adapter."""

    def __init__(self):
        raise TypeError('use Broker.initialize and Broker.open')

    # ------------------------------------------------ creation and opening

    @staticmethod
    def initialize(root, admission, manifest_bytes):
        """Creates a broker directory with its admission, manifest and an empty ledger."""
        check_admission(admission)
        if source_manifest.digest(manifest_bytes) != admission['manifest']:
            raise BrokerError('the manifest is not the admitted one')
        source_manifest.parse(manifest_bytes)
        root = Path(root)
        root.mkdir(mode=0o700)
        for name, data in ((ADMISSION, ledgers.encode_json(admission)), (MANIFEST, bytes(manifest_bytes))):
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
        (root / JVM).mkdir(mode=0o700)
        ledgers.Ledger.create(root / LEDGER)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @classmethod
    def open(cls, root, source_root, transport, reader, notice=None, wall=time.time_ns, monotonic=time.monotonic_ns,
             sleep=time.sleep, ids=os.urandom, processes=None, sync=True, target=None):
        """Opens a broker directory. `target`, when given, is called at HELLO and at every crossing's
        gate and returns the native target scope as it stands: ESTABLISHED_EMPTY, HELD or UNKNOWN.
        Without it the admitted scope stands. A target that cannot be read is UNKNOWN."""
        self = object.__new__(cls)
        self.root = Path(root)
        self.transport, self.reader, self.notice = transport, reader, notice
        self._target = target
        self._source_root = Path(source_root)
        self._wall, self._monotonic, self._sleep, self._ids = wall, monotonic, sleep, ids
        self.processes = processes or ProcessControl()
        self._shell2 = False
        self._lock = os.open(self.root / LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(self._lock)
            raise BrokerError('another broker holds this ledger') from error
        try:
            self._open(source_root, sync)
        except BaseException:
            self.close()
            raise
        return self

    def close(self):
        if getattr(self, '_lock', None) is not None:
            os.close(self._lock)
            self._lock = None

    def _open(self, source_root, sync):
        raw = (self.root / ADMISSION).read_bytes()
        self.admission = check_admission(json.loads(raw.decode('ascii')))
        if ledgers.encode_json(self.admission) != raw:
            raise BrokerError('the admission is not in its canonical encoding')
        manifest = (self.root / MANIFEST).read_bytes()
        if source_manifest.digest(manifest) != self.admission['manifest']:
            raise BrokerError('the manifest differs from the admission')
        self._manifest_bytes = manifest
        problems = source_manifest.verify(source_root, manifest)
        if problems:
            raise BrokerError('the sources differ from the admitted manifest: %s' % '; '.join(problems[:5]))
        if self.reader.installation != self.admission['installation'] or self.reader.component != self.admission['component']:
            raise BrokerError('the reader serves another installation or component')
        self.limits = self.admission['limits']
        self.fences = Fences(self.admission['fences'], self._wall)
        try:
            self.ledger = ledgers.Ledger.open(self.root / LEDGER, sync=sync)
        except ledgers.LedgerDamaged as error:
            raise BrokerError('the ledger is damaged: %s' % error) from error
        # Every capture whose effect is unknown bounds the wait, quarantined or not, so a reopening
        # that is itself lost before or during its wait leaves the same obligation to the next one.
        drain = self._outstanding_drain()
        quarantined = []
        for entry in self.ledger.unquarantined():
            intent = entry.content.get('intent') if entry.kind == 'capture' else None
            launched = 'unknown' if entry.state == 'interrupted' else False
            self.ledger.record('quarantine', {'entry': entry.number, 'entry_kind': entry.kind, 'state': entry.state,
                                              'launched': launched, 'intent': intent})
            quarantined.append(entry.number)
        self._rebuild()
        self._close_lost(quarantined)
        if drain > self._wall():
            # A command whose effect is unknown may still run on the guest within its bound.
            self._sleep((drain - self._wall()) / 1e9)
        self.ledger.record('open', {'pid': os.getpid(), 'manifest': self.admission['manifest'],
                                    'quarantined': quarantined, 'drained_until_wall_ns': drain,
                                    'wall_ns': self._wall()})

    def _outstanding_drain(self):
        """The wall time until which a command whose effect is unknown may still run on the guest: the
        latest bound of every capture with a whole intent and no result. A capture without a whole
        intent was never launched."""
        drain = 0
        for entry in self.ledger.entries:
            if entry.kind == 'capture' and entry.state == 'interrupted':
                intent = entry.content['intent']
                drain = max(drain, intent['started_wall_ns'] + int((intent['timeout_s'] + self.limits['drain_grace_s'])
                                                                   * 1e9))
        return drain

    def _rebuild(self):
        """The broker's state from the ledger's complete entries."""
        self.generation = 0
        self.open_generation = None
        self.stopped = None
        self.cells, self.consumed, self.pinned = [], set(), {}
        self.crossed, self.open_crossings = set(), {}
        self.host_begun, self.host_ended = {}, set()
        self.users_seen = {}
        self.scale = {}
        for entry in self.ledger.entries:
            if not entry.complete:
                continue
            c = entry.content
            kind = entry.kind
            if kind == 'generation':
                self.generation = c['generation']
                self.open_generation = c
            elif kind == 'generation-end':
                self.open_generation = None
            elif kind == 'stop':
                self.stopped = c['reason']
            elif kind == 'faults':
                self.cells.extend(c['cells'])
            elif kind == 'artifacts':
                self.pinned[c['plan']] = c['members']
            elif kind == 'crossing':
                self.crossed.add((c['ticket'], c['index']))
                self.open_crossings[entry.number] = c
                if c['cell'] is not None:
                    self.consumed.add(c['cell'])
            elif kind == 'outcome':
                self.open_crossings.pop(c['crossing'], None)
                self._scaled(c.get('reply'))
            elif kind == 'host':
                key = (c['ticket'], c['index'])
                if c['phase'] == 'BEGIN':
                    self.host_begun[key] = (entry.number, c['cell'])
                    if c['cell'] is not None:
                        self.consumed.add(c['cell'])
                else:
                    self.host_ended.add(key)
            elif kind == 'fault':
                self.consumed.add(c['cell'])
            elif kind == 'group':
                self._users(c)
                if c['emitted']:
                    for item in c['observations']:
                        self._scaled(item)
                    self._scaled(c.get('reading'))

    def _close_lost(self, quarantined):
        """Ends what a lost broker left open: first the generation whose process may still run, so
        that no host call it made can still complete, then its crossings without an outcome and its
        host calls without an end."""
        killed = False
        g = self.open_generation
        if g is not None and g['pid'] is not None and self.processes.alive(g['pid'], g['start_ticks']):
            self.processes.kill(g['pid'])
            killed = True
            for _ in range(300):
                if not self.processes.alive(g['pid'], g['start_ticks']):
                    break
                self._sleep(0.1)
            else:
                raise BrokerError('the lost generation %d still runs' % g['generation'])
        for number, c in sorted(self.open_crossings.items()):
            self.ledger.record('outcome', {'crossing': number, 'status': 'LOST', 'captures': [], 'reply': None,
                                           'frame_sha256': None, 'cell': c['cell'],
                                           'reason': 'the broker was lost during the crossing; its effect is unknown'})
        self.open_crossings = {}
        for key, (number, cell) in sorted(self.host_begun.items()):
            if key not in self.host_ended:
                self.ledger.record('host', {'phase': 'END', 'ticket': key[0], 'index': key[1], 'begin': number,
                                            'outcome': 'LOST', 'reply': None, 'cell': None,
                                            'reason': 'the broker was lost during the host call'})
                self.host_ended.add(key)
        if g is not None:
            self.ledger.record('generation-end', {'generation': g['generation'], 'status': 'LOST', 'exit': None,
                                                  'signal': None, 'killed': killed, 'halt_ordered': False,
                                                  'stopped_sent': False, 'violation': 'the broker was lost',
                                                  'stderr_sha256': None, 'stderr_bytes': None,
                                                  'quarantined': quarantined, 'wall_ns': self._wall()})
            self.open_generation = None

    def _users(self, group):
        for item in group.get('observations', ()):
            if item['kind'] != 'USER':
                continue
            key = '%d/%d' % (item['user'], item['serial'])
            if item['classification'] == 'REMOVED':
                self.users_seen.pop(key, None)
            else:
                self.users_seen[key] = (item['user'], item['serial'])

    def _scaled(self, item):
        if not item:
            return
        boot = self.scale.setdefault(item['boot'], {'elapsed': -1, 'instance': -1})
        boot['elapsed'] = max(boot['elapsed'], item['elapsed'])
        boot['instance'] = max(boot['instance'], item['instance'])

    def _scale_ok(self, item):
        boot = self.scale.get(item['boot'])
        return boot is None or (item['elapsed'] >= boot['elapsed']
                                and (item['instance'] < 0 or item['instance'] >= boot['instance']))

    # ------------------------------------------------ controller operations, never reachable by a generation

    def admit_faults(self, cells):
        """Admits fault cells. A cell names its own ID, where it acts, its key and its mode."""
        known = {cell['cell'] for cell in self.cells}
        checked = []
        for cell in cells:
            on = cell.get('on')
            if on not in CELL_KEYS or set(cell) != {'cell', 'on', 'mode'} | set(CELL_KEYS[on]):
                raise BrokerError('a fault cell of no known form')
            if not isinstance(cell['cell'], str) or not cell['cell'] or cell['cell'] in known:
                raise BrokerError('a fault cell ID is new and nonempty')
            if (cell['mode'] not in CELL_MODES[on] or not _hex(cell['plan'], 16) or not isinstance(cell['attempt'], int)
                    or isinstance(cell['attempt'], bool) or cell['attempt'] < 1):
                raise BrokerError('a fault cell mode, plan or attempt')
            if on == 'point' and cell['point'] not in proto.POINTS:
                raise BrokerError('an unknown lab point')
            if on in ('cross', 'host') and (not isinstance(cell['occurrence'], int) or isinstance(cell['occurrence'], bool)):
                raise BrokerError('an occurrence is an integer')
            if on == 'cross':
                if cell['crossing'] not in proto.DEVICE_CROSSINGS or cell['occurrence'] < 1:
                    raise BrokerError('a cross cell names a device crossing and an occurrence')
                if cell['mode'] == 'loss-between-members' and cell['crossing'] != 'WRITE':
                    raise BrokerError('only WRITE has two members')
            if on == 'host' and (cell['crossing'] not in proto.HOST_CROSSINGS or cell['occurrence'] not in (1, 2)):
                raise BrokerError('a host cell names SIGN or PUBLISH and an occurrence')
            known.add(cell['cell'])
            checked.append(dict(cell))
        self.ledger.record('faults', {'cells': checked})
        self.cells.extend(checked)

    def pin_artifacts(self, plan, members):
        """Pins one plan's bundle members: each member's host path, SHA-256 and size. The guest
        paths follow from the admitted staging directory."""
        if not _hex(plan, 16) or plan == proto.ZERO_ID:
            raise BrokerError('a plan ID')
        if set(members) != set(crossings.MEMBERS):
            raise BrokerError('a bundle has exactly base.apk and base.apk.idsig')
        pinned = {}
        for member, spec in members.items():
            if (set(spec) != {'host', 'sha256', 'bytes'} or not _hex(spec['sha256'], 32)
                    or not isinstance(spec['bytes'], int) or spec['bytes'] <= 0 or not str(spec['host']).startswith('/')):
                raise BrokerError('a pinned member names its host path, digest and size')
            pinned[member] = dict(spec, guest=crossings.staged_path('%s/%s/%s' % (self.admission['device_dir'], plan,
                                                                                  member)))
        if plan in self.pinned:
            if self.pinned[plan] != pinned:
                raise BrokerError('a plan is pinned once')
            return
        self.ledger.record('artifacts', {'plan': plan, 'members': pinned})
        self.pinned[plan] = pinned

    def _target_scope(self):
        """The native target scope as it stands now. A target that cannot be read, or reads as no
        known scope, is UNKNOWN: never established."""
        if self._target is None:
            return self.admission['target_scope']
        try:
            scope = self._target()
        except Exception:  # Any failure to read the target leaves it unknown.
            return 'UNKNOWN'
        return scope if scope in TARGET_SCOPES else 'UNKNOWN'

    def _verify_sources(self):
        """The admitted sources, read again before a crossing. A difference latches a stop."""
        problems = source_manifest.verify(self._source_root, self._manifest_bytes)
        if problems:
            self.stop('the admitted sources changed: %s' % '; '.join(problems[:3]))
            raise Stopped(self.stopped)

    def stop(self, reason):
        """The controller's own stop: latched like a fence."""
        if self.stopped is None:
            self.stopped = reason
            self.ledger.record('stop', {'reason': reason, 'wall_ns': self._wall()})

    # ------------------------------------------------ fences and captures

    def _fence(self):
        if self.stopped is not None:
            raise Stopped(self.stopped)
        reason = self.fences.check()
        if reason is not None:
            self.stop(reason)
            raise Stopped(reason)

    def _require_shell2(self, context):
        """Once in each broker's lifetime, before its first guest command: the device must offer
        shell protocol v2. A definite answer without it latches a stop. An answer that cannot be read
        launches nothing and is asked again before the next command."""
        if self._shell2:
            return
        command = 'host-serial:%s:features' % self.admission['serial']
        timeout = self.limits['read_timeout_s']
        _, result = self._record_command('features', command, context, lambda: self.transport.features(timeout),
                                         timeout)
        if result.status == 'ok' and shell_transport.FEATURE_SHELL2 in result.features:
            self._shell2 = True
            return
        if result.status == 'ok':
            self.stop('the device does not offer shell protocol v2')
            raise Stopped(self.stopped)
        raise _NotLaunched('the device features could not be read: %s' % result.status)

    def _capture(self, operation, command, context, call, timeout, not_after_ns=None):
        """One guest command: the shell protocol check, then the fences, the intent synced, the call,
        then its streams and result. A launch bound to an activation grant names the host monotonic
        instant from which it is refused."""
        self._require_shell2(context)
        return self._record_command(operation, command, context, call, timeout, not_after_ns)

    def _record_command(self, operation, command, context, call, timeout, not_after_ns=None):
        # Every command, the feature query included, is fenced right before its intent: a fence that
        # trips while an earlier command runs stops the next one.
        self._fence()
        intent = dict(context, operation=operation, command=command, timeout_s=timeout,
                      started_wall_ns=self._wall(), started_monotonic_ns=self._monotonic())
        if not_after_ns is not None:
            intent['not_after_monotonic_ns'] = not_after_ns
        entry = self.ledger.begin_capture(intent)
        # The final launch gate, once the intent is durable: a launch whose activation grant may have
        # expired since the gate's clock reading sends nothing.
        if not_after_ns is not None and self._monotonic() >= not_after_ns:
            self._not_sent(entry, 'the activation grant may have expired before the launch')
        try:
            result = call()
        except Exception as error:  # A transport defect still ends the capture with a result.
            self.ledger.finish_capture(entry, b'', b'', {'launch': 'unknown', 'transport': 'broker-error',
                                                         'completion': 'unknown', 'exit': None,
                                                         'error': '%s: %s' % (type(error).__name__, error),
                                                         'ended_wall_ns': self._wall()})
            raise
        stdout, stderr = result.streams()
        self.ledger.finish_capture(entry, stdout, stderr, dict(result.summary(), ended_monotonic_ns=self._monotonic()))
        if not_after_ns is not None and result.launch == 'not-launched' and result.transport == 'launch-deadline':
            raise _NotLaunched('the activation grant may have expired before the service request')
        return entry.number, result

    def _not_sent(self, entry, reason):
        """Ends a capture whose command was never sent, then refuses its launch."""
        self.ledger.finish_capture(entry, b'', b'', {'launch': 'not-launched', 'transport': 'not-sent',
                                                     'completion': 'not-started', 'exit': None, 'error': reason,
                                                     'ended_wall_ns': self._wall(),
                                                     'ended_monotonic_ns': self._monotonic()})
        raise _NotLaunched(reason)

    def _may_send(self, not_after_ns):
        """The transport's last question before a launch's service request, or None without a deadline:
        connecting and selecting the device take time too."""
        if not_after_ns is None:
            return None
        return lambda: self._monotonic() < not_after_ns

    def _shell(self, operation, command, context, timeout, stdout_max, stderr_max, not_after_ns=None):
        gate = self._may_send(not_after_ns)
        extra = {} if gate is None else {'may_send': gate}
        return self._capture(operation, command, context,
                             lambda: self.transport.shell(command, timeout, stdout_max, stderr_max, **extra), timeout,
                             not_after_ns)

    # ------------------------------------------------ groups of reads

    def _group(self, name, call, context, expect_boot, emitted=True):
        """One reader call as one group, recorded with its captures, raw digest and facts."""
        captures = []

        def run(command):
            if not self.reader.allowed(command):
                raise readers.Unclassified('a command outside the reader allowlist: %r' % command)
            number, result = self._shell('read', command, dict(context, group=name),
                                         self.limits['read_timeout_s'], int(self.limits['read_stdout_max']),
                                         int(self.limits['read_stderr_max']))
            if not result.completed or result.overflow is not None:
                captures.append((number, command, None, result.stdout, result.stderr))
                raise readers.Unavailable('capture %d did not complete: %s' % (number, result.completion))
            captures.append((number, command, result.exit, result.stdout, result.stderr))
            return (result.exit, result.stdout.decode('utf-8', 'surrogateescape'),
                    result.stderr.decode('utf-8', 'surrogateescape'))

        self.reader.bind(run)
        facts, frames, status, reason, reading = [], [], 'facts', None, None
        try:
            value = call()
            if name == 'clock':
                reading = {'boot': value[0], 'instance': value[1], 'elapsed': value[2], 'wall': value[3]}
            else:
                facts = list(value)
        except Stopped as error:
            status, reason = 'stopped', str(error)
        except readers.Unavailable as error:
            status, reason = 'unavailable', str(error)
        except (readers.Unclassified, ValueError, KeyError, TypeError) as error:
            status, reason = 'unclassified', '%s: %s' % (type(error).__name__, error)
        finally:
            self.reader.bind(None)
        raw = readers.raw_digest([(c[1], c[2], c[3], c[4]) for c in captures]) if captures else None
        if status == 'facts':
            if name == 'clock':
                problem = self._reading_problem(reading, expect_boot)
            else:
                problem = self._facts_problem(name, facts, raw, expect_boot)
            if problem is not None:
                status, reason, frames = 'refused', problem, []
            elif name != 'clock':
                frames = [encoder.observation(f) for f in facts]
        if status != 'facts':
            facts, frames, reading = [], [], None
        observations = [{'id': f['observation'], 'kind': f['kind'], 'classification': f['classification'],
                         'boot': f['boot'], 'instance': f['instance'], 'elapsed': f['elapsed'], 'user': f['user'],
                         'serial': f['serial'], 'sha256': hashlib.sha256(frame).hexdigest()}
                        for f, frame in zip(facts, frames)]
        record = dict(context, reader=name, captures=[c[0] for c in captures], status=status, reason=reason,
                      raw=raw, observations=observations, reading=reading, emitted=emitted and status == 'facts')
        number = self.ledger.record('group', record)
        self._users(record)
        if record['emitted']:
            for item in observations:
                self._scaled(item)
            self._scaled(reading)
        if status == 'stopped':
            raise Stopped(reason)
        return Group(number, facts, frames, status, reason, reading)

    def _reading_problem(self, reading, expect_boot):
        boot, instance, elapsed = reading['boot'], reading['instance'], reading['elapsed']
        if not _hex(boot, 16) or boot == proto.ZERO_ID or not isinstance(instance, int) or instance < -1:
            return 'a clock reading of no known form'
        if not isinstance(elapsed, int) or elapsed < 0:
            return 'a clock reading of no known form'
        if expect_boot is not None and boot != expect_boot:
            return 'the boot changed'
        if not self._scale_ok(reading):
            return 'the uptime or framework instance went back'
        return None

    def _facts_problem(self, name, facts, raw, expect_boot):
        allowed = GROUP_KINDS[name]
        for f in facts:
            if f.get('kind') not in allowed:
                return 'a %s fact from the %s reader' % (f.get('kind'), name)
            if f.get('installation') != self.admission['installation'] or f.get('route') != 'SHELL':
                return 'a fact of another installation or route'
            device = f['kind'] in DEVICE_KINDS
            if f.get('component') != ('' if device else self.admission['component']):
                return 'a fact of another component scope'
            if f.get('raw') != raw:
                return "a fact whose raw digest is not its group's captures"
            if expect_boot is not None and f.get('boot') != expect_boot:
                return 'the boot changed'
            if not self._scale_ok(f):
                return 'the uptime or framework instance went back'
        return None

    def _clock_group(self, context, expect_boot=None, emitted=True):
        return self._group('clock', self.reader.clock, context, expect_boot, emitted)

    # ------------------------------------------------ serving a generation

    def run_generation(self, argv, env=None, cwd=None):
        """Spawns one coordinator generation, serves it to its end, and reaps it."""
        if self.open_generation is not None:
            raise BrokerError('a generation is still open')
        stderr_path = self.root / JVM / ('%06d.stderr' % (self.generation + 1))
        with open(stderr_path, 'xb') as err:
            # Unbuffered pipes: a frame is never held in a buffer that select cannot see.
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, env=env,
                                       cwd=cwd, close_fds=True, bufsize=0)
        found = proc_start_ticks(process.pid)
        state = self.serve(process.stdout, process.stdin, process.pid, found[1] if found else None)
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        killed = False
        try:
            code = process.wait(timeout=self.limits['exit_grace_s'])
        except subprocess.TimeoutExpired:
            process.kill()
            killed = True
            try:
                code = process.wait(timeout=self.limits['exit_grace_s'])
            except subprocess.TimeoutExpired as error:
                # The generation stays open in the ledger, so no other is served until a reopening
                # ends its process.
                raise BrokerError('the generation process was not reaped after its kill') from error
        data = stderr_path.read_bytes()
        return self._end_generation(state, code, killed, hashlib.sha256(data).hexdigest(), len(data))

    def begin_generation(self, pid=None, start_ticks=None):
        """Records the start of one generation, after every earlier one ended. Returns its state."""
        if self.open_generation is not None:
            raise BrokerError('a generation is still open')
        self.generation += 1
        record = {'generation': self.generation, 'pid': pid, 'start_ticks': start_ticks, 'wall_ns': self._wall()}
        self.ledger.record('generation', record)
        self.open_generation = record
        return {'generation': self.generation, 'hello': False, 'halt_ordered': False, 'stopped_sent': False,
                'violation': None, 'requests': set(), 'served': 0}

    def serve(self, rfile, wfile, pid=None, start_ticks=None):
        """Serves one generation over an unbuffered stream pair until it ends. Returns its state."""
        state = self.begin_generation(pid, start_ticks)
        while state['violation'] is None:
            try:
                data = self._read_frame(rfile)
            except proto.ProtocolError as error:
                state['violation'] = 'unreadable request: %s' % error
                break
            if data is None:
                break
            try:
                request = proto.decode(data)
            except proto.ProtocolError as error:
                state['violation'] = 'malformed request: %s' % error
                break
            try:
                reply = self.handle(request, state)
            except (Stopped, ledgers.LedgerDamaged, BrokerError):
                raise
            except Exception as error:  # A broker defect ends the generation, recorded.
                for number in sorted(self.open_crossings):
                    self.ledger.record('outcome', {'crossing': number, 'status': 'ERROR', 'captures': [],
                                                   'reply': None, 'frame_sha256': None, 'cell': None,
                                                   'reason': '%s: %s' % (type(error).__name__, error)})
                self.open_crossings = {}
                state['violation'] = 'broker error: %s: %s' % (type(error).__name__, error)
                reply = self._reply(request, 'REFUSED', reason='the broker failed on this request')
            try:
                self._write_reply(wfile, proto.encode(reply))
            except _TransferBound:
                state['violation'] = 'the reply transfer exceeded its bound'
                break
            except OSError:
                state['violation'] = 'the generation was lost before its reply'
                break
            state['served'] += 1
        return state

    @staticmethod
    def _fileno(stream):
        """A stream's descriptor, or None for an in memory stream. A buffered stream with a descriptor
        is refused: its buffer could hold bytes that select cannot see."""
        try:
            fileno = stream.fileno()
        except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
            return None
        if isinstance(stream, io.BufferedIOBase):
            raise BrokerError('a generation stream must be unbuffered')
        return fileno

    def _read_frame(self, rfile):
        """One request frame. The generation may be idle for its bound before a request begins. Once
        its first byte arrives, the whole frame must arrive within the same bound, so a stalled peer
        cannot hold the broker inside a frame."""
        idle = self.limits['generation_idle_s']
        fileno = self._fileno(rfile)
        if fileno is None:
            return proto.read_frame(rfile)
        ready, _, _ = select.select([fileno], [], [], idle)
        if not ready:
            raise proto.ProtocolError('the generation was idle beyond its bound')
        deadline = time.monotonic() + idle

        class Bounded:
            @staticmethod
            def read(count):
                left = deadline - time.monotonic()
                ready = select.select([fileno], [], [], left)[0] if left > 0 else []
                if not ready:
                    raise proto.ProtocolError('the request transfer exceeded its bound')
                return os.read(fileno, count)
        return proto.read_frame(Bounded)

    def _write_reply(self, wfile, data):
        """Writes one reply frame whole within the generation's bound, or raises _TransferBound."""
        fileno = self._fileno(wfile)
        if fileno is None:
            view = memoryview(data)
            while view:
                written = wfile.write(view)
                view = view[written if written is not None else len(view):]
            wfile.flush()
            return
        deadline = time.monotonic() + self.limits['generation_idle_s']
        blocking = os.get_blocking(fileno)
        os.set_blocking(fileno, False)
        try:
            view = memoryview(data)
            while view:
                left = deadline - time.monotonic()
                ready = select.select([], [fileno], [], left)[1] if left > 0 else []
                if not ready:
                    raise _TransferBound()
                try:
                    view = view[os.write(fileno, view):]
                except BlockingIOError:
                    continue
        finally:
            os.set_blocking(fileno, blocking)

    def end_served(self, state, code=None, signal_number=None, killed=False):
        """Ends a generation served over streams, as `run_generation` does for a process."""
        return self._end_generation(state, code if signal_number is None else -signal_number, killed, None, None)

    def _end_generation(self, state, code, killed, stderr_sha, stderr_bytes):
        open_host = [key for key in self.host_begun if key not in self.host_ended]
        for key in sorted(open_host):
            number, _ = self.host_begun[key]
            self.ledger.record('host', {'phase': 'END', 'ticket': key[0], 'index': key[1], 'begin': number,
                                        'outcome': 'PROCESS_ENDED', 'reply': None, 'cell': None,
                                        'reason': 'the generation ended during the host call'})
            self.host_ended.add(key)
        exit_code = code if code is not None and code >= 0 else None
        signal_number = -code if code is not None and code < 0 else None
        if exit_code == 0 and state['violation'] is None and state['hello']:
            status = 'COMPLETE'
        elif exit_code == HALT_STATUS and state['halt_ordered']:
            status = 'DELIBERATE_HALT'
        elif exit_code == STOPPED_STATUS and state['stopped_sent']:
            status = 'STOPPED'
        elif signal_number is not None:
            status = 'KILLED'
        else:
            status = 'FAILED'
        summary = {'generation': state['generation'], 'status': status, 'exit': exit_code, 'signal': signal_number,
                   'killed': killed, 'halt_ordered': state['halt_ordered'], 'stopped_sent': state['stopped_sent'],
                   'violation': state['violation'], 'served': state['served'], 'stderr_sha256': stderr_sha,
                   'stderr_bytes': stderr_bytes, 'wall_ns': self._wall()}
        self.ledger.record('generation-end', summary)
        self.open_generation = None
        return summary

    # ------------------------------------------------ requests

    def _reply(self, request, status, **fields):
        kind = proto.reply_type(request['type'])
        body = {name: None for name, _ in proto.BODIES[kind]}
        body.update(status=proto.STATUSES[status], reason='' if status == 'OK' else fields.pop('reason', status))
        defaults = {'u8': 0, 'u16': 0, 'u32': 0, 'i32': 0, 'i64': 0, 'id': proto.ZERO_ID, 'd32': proto.ZERO_DIGEST,
                    'text': '', 'blob': b'', 'frames': [], 'codes': []}
        for name, field in proto.BODIES[kind]:
            if body[name] is None:
                body[name] = defaults[field]
        body.update(fields)
        return proto.message(kind, request['request'], self.admission['manifest'], **body)

    def handle(self, request, state):
        """One request to its one reply."""
        kind = request['type']
        if kind not in ('HELLO', 'CLOCK', 'OBSERVE', 'CROSS', 'POINT', 'HOST', 'REPORT'):
            state['violation'] = 'a reply type sent as a request'
            return self._reply({'type': 'HELLO', 'request': request['request']}, 'REFUSED', reason='not a request')
        if request['manifest'] != self.admission['manifest']:
            state['violation'] = 'a request of another source manifest'
            return self._reply(request, 'REFUSED', reason='another source manifest')
        if request['request'] in state['requests']:
            state['violation'] = 'a request ID used twice'
            return self._reply(request, 'REFUSED', reason='a request ID used twice')
        state['requests'].add(request['request'])
        if state['halt_ordered']:
            state['violation'] = 'a request after a halt order'
            return self._reply(request, 'REFUSED', reason='the generation was told to halt')
        if kind == 'HELLO':
            return self._hello(request, state)
        if not state['hello']:
            state['violation'] = 'a request before HELLO'
            return self._reply(request, 'REFUSED', reason='HELLO first')
        handler = {'CLOCK': self._clock, 'OBSERVE': self._observe, 'CROSS': self._cross, 'POINT': self._point,
                   'HOST': self._host, 'REPORT': self._report}[kind]
        reply = handler(request, state)
        status = proto.STATUS_NAMES[reply['status']]
        if status == 'HALT':
            state['halt_ordered'] = True
        if status == 'STOPPED':
            state['stopped_sent'] = True
        return reply

    def _hello(self, m, state):
        if state['hello']:
            state['violation'] = 'a second HELLO'
            return self._reply(m, 'REFUSED', reason='HELLO once')
        a = self.admission
        expected = (a['installation'], a['coordinator'], a['config'], a['component'], a['trust'])
        if (m['installation'], m['coordinator'], m['config'], m['component'], m['trust']) != expected:
            state['violation'] = 'a generation of another configuration'
            return self._reply(m, 'REFUSED', reason='the configuration differs from the admission')
        state['hello'] = True
        if self.stopped is not None:
            state['stopped_sent'] = True
            return self._reply(m, 'STOPPED', reason=self.stopped)
        return self._reply(m, 'OK', generation=state['generation'], target=proto.TARGETS[self._target_scope()])

    def _clock(self, m, state):
        context = {'request': m['request'], 'generation': state['generation'], 'purpose': 'clock'}
        try:
            group = self._clock_group(context)
        except Stopped as error:
            return self._reply(m, 'STOPPED', reason=str(error))
        if not group.ok:
            return self._reply(m, 'UNAVAILABLE', group=group.number, reason=group.reason)
        reading = group.reading
        return self._reply(m, 'OK', boot=reading['boot'], instance=reading['instance'], elapsed=reading['elapsed'],
                           wall=reading['wall'], group=group.number)

    def _observe(self, m, state):
        if m['component'] != self.admission['component']:
            return self._reply(m, 'REFUSED', reason='another component')
        names = ['boot', 'checkpoint', 'factory', 'active']
        if m['scope'] == proto.SCOPES['TICKET']:
            names += ['sessions', 'users'] + (['receipts'] if self.reader.receipts_admitted else [])
        context = {'request': m['request'], 'generation': state['generation'], 'purpose': 'observe',
                   'ticket': m['ticket'] if m['ticket'] != proto.ZERO_ID else None}
        frames = []
        try:
            for name in names:
                if name == 'receipts':
                    call = lambda: self.reader.receipts(m['ticket'])  # noqa: E731
                elif name == 'users':
                    call = lambda: self.reader.users(sorted(self.users_seen.values()))  # noqa: E731
                else:
                    call = getattr(self.reader, name)
                group = self._group(name, call, context, m['boot'])
                frames += [(group.number, frame) for frame in group.frames]
                if group.status == 'refused' and group.reason == 'the boot changed':
                    break
        except Stopped as error:
            return self._reply(m, 'STOPPED', reason=str(error))
        return self._reply(m, 'OK', frames=frames[:proto.MAX_FRAMES])

    def _match(self, on, **key):
        for cell in self.cells:
            if cell['on'] == on and cell['cell'] not in self.consumed and all(cell[k] == v for k, v in key.items()):
                return cell
        return None

    def _point(self, m, state):
        cell = self._match('point', plan=m['plan'], attempt=m['attempt'], point=m['point'])
        if cell is None:
            return self._reply(m, 'OK')
        self.consumed.add(cell['cell'])
        number = self.ledger.record('fault', {'cell': cell['cell'], 'on': 'point', 'decision': 'halt',
                                              'ticket': m['ticket'], 'plan': m['plan'], 'point': m['point'],
                                              'request': m['request'], 'generation': state['generation']})
        return self._reply(m, 'HALT', record=number, reason='admitted fault cell %s at %s' % (cell['cell'], m['point']))

    def _host(self, m, state):
        name = 'SIGN' if m['crossing'] == proto.HOST_CROSSINGS['SIGN'] else 'PUBLISH'
        key = (m['ticket'], m['index'])
        common = {'ticket': m['ticket'], 'index': m['index'], 'plan': m['plan'], 'attempt': m['attempt'],
                  'crossing': name, 'occurrence': m['occurrence'], 'reference': m['reference'],
                  'request': m['request'], 'generation': state['generation']}
        if m['phase'] == proto.HOST_PHASES['BEGIN']:
            if key in self.host_begun:
                return self._reply(m, 'REFUSED', reason='a host call of one ledger entry begins once')
            cell = self._match('host', plan=m['plan'], attempt=m['attempt'], crossing=name, occurrence=m['occurrence'])
            if cell is not None:
                self.consumed.add(cell['cell'])
            number = self.ledger.record('host', dict(common, phase='BEGIN', cell=cell and cell['cell']))
            self.host_begun[key] = (number, cell and cell['cell'])
            if cell is not None and cell['mode'] == 'loss-before':
                fault = self.ledger.record('fault', {'cell': cell['cell'], 'on': 'host', 'decision': 'halt-before-effect',
                                                     'host': number, 'request': m['request']})
                return self._reply(m, 'HALT', record=fault, reason='admitted loss before the host effect')
            return self._reply(m, 'OK', record=number)
        if key not in self.host_begun or key in self.host_ended:
            return self._reply(m, 'REFUSED', reason='a host call ends once, after it began')
        begin, cell_id = self.host_begun[key]
        outcome = {1: 'REPLY', 2: 'NULL', 3: 'THREW'}[m['outcome']]
        reply = m['reply'] if m['reply'] != proto.ZERO_DIGEST else None
        number = self.ledger.record('host', dict(common, phase='END', begin=begin, outcome=outcome, reply=reply,
                                                 cell=cell_id))
        self.host_ended.add(key)
        cell = next((c for c in self.cells if c['cell'] == cell_id), None)
        if cell is not None and cell['mode'] == 'loss-after':
            fault = self.ledger.record('fault', {'cell': cell['cell'], 'on': 'host', 'decision': 'halt-after-effect',
                                                 'host': number, 'request': m['request']})
            return self._reply(m, 'HALT', record=fault, reason='admitted loss after the host effect')
        if cell is not None and cell['mode'] == 'drop-reply':
            escrow = self.ledger.record('escrow', {'cell': cell['cell'], 'host': number, 'reply_sha256': reply,
                                                   'request': m['request']})
            return self._reply(m, 'WITHHELD', record=escrow, reason='admitted dropped host reply')
        return self._reply(m, 'OK', record=number)

    def _report(self, m, state):
        number = self.ledger.record('report', {'ticket': m['ticket'], 'state': m['state'], 'flags': m['flags'],
                                               'cause': m['cause'], 'ledger': m['ledger'], 'note': m['note'],
                                               'request': m['request'], 'generation': state['generation']})
        return self._reply(m, 'OK', record=number)

    # ------------------------------------------------ crossings

    def _cross(self, m, state):
        name = proto.CROSSING_NAMES[m['crossing']]
        if m['component'] != self.admission['component']:
            return self._reply(m, 'REFUSED', reason='another component')
        key = (m['ticket'], m['index'])
        if key in self.crossed:
            return self._reply(m, 'REFUSED', reason='a crossing of one ledger entry is issued once')
        cell = self._match('cross', plan=m['plan'], attempt=m['attempt'], crossing=name, occurrence=m['occurrence'])
        if cell is not None:
            self.consumed.add(cell['cell'])
        fields = {k: m[k] for k in ('ticket', 'ticket_digest', 'plan', 'plan_digest', 'attempt', 'index', 'occurrence',
                                    'entry_boot', 'entry_instance', 'entry_elapsed', 'grant', 'reference', 'bundle_apk',
                                    'actor', 'granted', 'window')}
        number = self.ledger.record('crossing', dict(fields, crossing=name, native=list(m['native']),
                                                     request=m['request'], generation=state['generation'],
                                                     cell=cell and cell['cell']))
        self.crossed.add(key)
        self.open_crossings[number] = m
        captures = []
        try:
            self._fence()
            self._verify_sources()
            if cell is not None and cell['mode'] == 'loss-before':
                fault = self.ledger.record('fault', {'cell': cell['cell'], 'on': 'cross', 'crossing': number,
                                                     'decision': 'halt-before-effect', 'launched': False,
                                                     'captures': []})
                self._outcome(number, 'HALT', captures, None, cell, 'admitted loss before the effect', fault=fault)
                return self._reply(m, 'HALT', record=number, reason='admitted loss before the effect')
            try:
                classification, fact, reason = self._execute(name, m, number, captures, cell, state)
            except _NotLaunched as error:
                classification, fact, reason = None, None, '%s: nothing launched' % error
        except Stopped as error:
            self._outcome(number, 'STOPPED', captures, None, cell, str(error))
            return self._reply(m, 'STOPPED', record=number, reason=str(error))
        except _Halt as halt:
            self._outcome(number, 'HALT', captures, None, cell, 'admitted loss between the two members',
                          fault=halt.record)
            return self._reply(m, 'HALT', record=number, reason='admitted loss between the two members')
        frame = encoder.observation(fact) if fact is not None else None
        if cell is not None and cell['mode'] == 'loss-after':
            fault = self.ledger.record('fault', {'cell': cell['cell'], 'on': 'cross', 'crossing': number,
                                                 'decision': 'halt-after-effect', 'captures': list(captures),
                                                 'withheld_sha256': frame and hashlib.sha256(frame).hexdigest()})
            self._outcome(number, 'HALT', captures, fact, cell, 'admitted loss after the effect', frame, fault=fault)
            return self._reply(m, 'HALT', record=number, reason='admitted loss after the effect')
        if cell is not None and cell['mode'] == 'drop-reply':
            escrow = self.ledger.record('escrow', {'cell': cell['cell'], 'crossing': number, 'captures': captures,
                                                   'classification': classification,
                                                   'frame': frame.hex() if frame else None,
                                                   'frame_sha256': frame and hashlib.sha256(frame).hexdigest()})
            self._outcome(number, 'WITHHELD', captures, fact, cell, 'admitted dropped reply', frame, escrow=escrow)
            return self._reply(m, 'WITHHELD', record=number, reason='admitted dropped reply')
        if fact is None:
            self._outcome(number, 'NO_REPLY', captures, None, cell, reason)
            return self._reply(m, 'NO_REPLY', record=number, reason=reason)
        self._outcome(number, 'OK', captures, fact, cell, None, frame)
        self._scaled(fact)
        return self._reply(m, 'OK', record=number, frame=frame)

    def _outcome(self, crossing, status, captures, fact, cell, reason, frame=None, **extra):
        reply = None
        if fact is not None:
            reply = {'boot': fact['boot'], 'instance': fact['instance'], 'elapsed': fact['elapsed'],
                     'classification': fact['classification'], 'observation': fact['observation'],
                     'raw': fact['raw']}
        self.ledger.record('outcome', dict({'crossing': crossing, 'status': status, 'captures': list(captures),
                                            'reply': reply, 'frame_sha256': frame and hashlib.sha256(frame).hexdigest(),
                                            'cell': cell and cell['cell'], 'reason': reason}, **extra))
        self.open_crossings.pop(crossing, None)

    def _reply_fact(self, name, m, classification, raw, elapsed, instance, reference=proto.NO_REFERENCE):
        return {'installation': self.admission['installation'], 'observation': proto.fresh_id(self._ids),
                'component': self.admission['component'], 'boot': m['entry_boot'], 'user': proto.NO_USER,
                'serial': -1, 'kind': 'REPLY', 'route': 'SHELL', 'instance': instance, 'elapsed': elapsed,
                'wall': self._wall() // 1_000_000, 'raw': raw, 'classification': classification,
                'facts': {'ticket': m['ticket'], 'index': m['index'], 'crossing': name, 'reference': reference}}

    def _gate(self, name, m, context, purpose):
        """The command gate, read just before a crossing's guest mutation and, for WRITE, again before
        each member. Returns (clock reading, launch deadline, None) when the crossing may launch, else
        (None, None, why).

        The native target scope as it stands; for a session crossing the ticket's exact session, open
        for WRITE and COMMIT; then the clock as its own group, the last read before the launch, of the
        entry's boot and, for a framework crossing, the entry's framework instance. An ACTIVATE grant
        must be valid at that reading's wall time by the reconciler's rule. Its launch deadline is the
        host monotonic instant until which it stays valid, counted from the start of the clock read
        under activation_deadline's assumption. The launch is refused once that instant has passed:
        after its durable intent, and by the transport right before the service request. The exact own
        session may be abandoned whatever the target reads. The gate validates the requested crossing
        only: it never chooses another."""
        if name != 'ABANDON':
            scope = self._target_scope()
            if scope != 'ESTABLISHED_EMPTY':
                return None, None, 'the native target scope is %s, not established empty' % scope
        if name in ('WRITE', 'COMMIT', 'ABANDON'):
            confirmed = self._confirm(m, context, ('OPEN',) if name != 'ABANDON' else LIVE)
            if confirmed is not None:
                return None, None, '%s: %s' % (purpose, confirmed)
        # The clock is read last: no slow read comes between it and the launch.
        started = self._monotonic()
        clock = self._clock_group(dict(context, purpose=purpose), emitted=False)
        if not clock.ok:
            return None, None, '%s: the clock is unavailable' % purpose
        reading = clock.reading
        if reading['boot'] != m['entry_boot']:
            return None, None, '%s: the boot changed since the entry' % purpose
        if name in proto.FRAMEWORK_CROSSINGS and reading['instance'] != m['entry_instance']:
            return None, None, '%s: the framework instance changed since the entry' % purpose
        deadline = None
        if name in proto.ACTIVATED:
            deadline = activation_deadline(reading['wall'], started, m['granted'], m['window'])
            if deadline is None:
                return None, None, '%s: the activation grant is not valid at the wall time of launch' % purpose
        return reading, deadline, None

    def _execute(self, name, m, crossing, captures, cell, state):
        """Runs one typed crossing. Returns (classification or None, REPLY fact or None, reason)."""
        context = {'request': m['request'], 'generation': state['generation'], 'crossing': crossing}
        reading, deadline, why = self._gate(name, m, context, 'preflight')
        if reading is None:
            return None, None, '%s: nothing launched' % why
        framework = name in proto.FRAMEWORK_CROSSINGS
        elapsed = reading['elapsed']
        instance = m['entry_instance'] if framework else reading['instance']
        limits = self.limits
        if name == 'CREATE':
            command = crossings.create_command(self.admission['component'], m['reference'])
            number, result = self._shell('mutation', command, context, limits['mutation_timeout_s'],
                                         int(limits['reply_stdout_max']), int(limits['reply_stderr_max']))
            captures.append(number)
            classification, session = crossings.classify_create(result)
            if classification is None:
                return None, None, 'the create did not complete: its effect is unknown'
            raw = readers.raw_digest([(command, result.exit, result.stdout, result.stderr)])
            reference = proto.NO_REFERENCE
            if classification == 'SUCCESS':
                reference = self._join(m, context, session)
            return classification, self._reply_fact(name, m, classification, raw, elapsed, instance, reference), None
        if name == 'WRITE':
            return self._write(m, context, captures, cell, elapsed, instance)
        if name in ('COMMIT', 'ABANDON'):
            session = m['native'][1]
            command = crossings.commit_command(session) if name == 'COMMIT' else crossings.abandon_command(session)
            timeout = limits['commit_timeout_s'] if name == 'COMMIT' else limits['mutation_timeout_s']
            number, result = self._shell('mutation', command, context, timeout, int(limits['reply_stdout_max']),
                                         int(limits['reply_stderr_max']), deadline)
            captures.append(number)
            classify = crossings.classify_commit if name == 'COMMIT' else crossings.classify_abandon
            classification = classify(result)
            if classification is None:
                return None, None, 'the %s did not complete: its effect is unknown' % name.lower()
            raw = readers.raw_digest([(command, result.exit, result.stdout, result.stderr)])
            return classification, self._reply_fact(name, m, classification, raw, elapsed, instance), None
        if name == 'REBOOT':
            gate = self._may_send(deadline)
            number, result = self._capture('reboot', REBOOT_LABEL, context,
                                           lambda: self.transport.reboot(limits['reboot_timeout_s'], may_send=gate),
                                           limits['reboot_timeout_s'], deadline)
            captures.append(number)
            return None, None, 'a reboot has no shell reply: a new boot ID resolves it'
        # NOTICE
        if self.notice is None:
            return None, None, 'no notice route is admitted: nothing launched'
        return self._notice(m, context, captures, elapsed, instance, deadline)

    def _confirm(self, m, context, states):
        """None when the ticket's exact session is the one live session with its ID in the entry's
        framework instance, else why not."""
        group = self._group('sessions', self.reader.sessions, dict(context, purpose='confirm'), m['entry_boot'],
                            emitted=False)
        if not group.ok:
            return 'the session readback is unavailable (%s)' % group.reason
        same = [f for f in group.facts if f['kind'] == 'SESSION' and f['instance'] == m['entry_instance']
                and f['facts']['reference'][1] == m['native'][1] and f['classification'] in LIVE]
        if len(same) != 1:
            return 'no single live session with the ticket\'s ID'
        if not matches(m['native'], tuple(same[0]['facts']['reference'])):
            return "the live session with the ticket's ID is another session"
        if same[0]['classification'] not in states:
            return 'the session is %s' % same[0]['classification']
        return None

    def _join(self, m, context, session):
        """The created session's whole reference from one readback in the same framework instance, or
        the ID alone. Nothing is invented."""
        alone = (proto.SESSION, session, 0, '', 0, proto.ZERO_ID)
        group = self._group('sessions', self.reader.sessions, dict(context, purpose='join'), m['entry_boot'],
                            emitted=False)
        if not group.ok:
            return alone
        found = [f for f in group.facts if f['kind'] == 'SESSION' and f['facts']['reference'][1] == session
                 and f['instance'] == m['entry_instance'] and f['classification'] in LIVE]
        if len(found) != 1:
            return alone
        ref = tuple(found[0]['facts']['reference'])
        presence = ref[0]
        whole = presence & proto.CREATED and presence & proto.INSTALLER and presence & (proto.STAGE_DIR | proto.NONCE)
        if not whole or (presence & proto.NONCE and ref[5] != m['reference']):
            return alone
        return ref

    def _write(self, m, context, captures, cell, elapsed, instance):
        pinned = self.pinned.get(m['plan'])
        if pinned is None or pinned['base.apk']['sha256'] != m['bundle_apk']:
            return None, None, 'the bundle is not the pinned artifact of the plan: nothing launched'
        session = m['native'][1]
        for member in crossings.MEMBERS:
            spec = pinned[member]
            try:
                data = Path(spec['host']).read_bytes()
            except OSError as error:
                return None, None, 'the pinned %s cannot be read: %s' % (member, error)
            if (hashlib.sha256(data).hexdigest(), len(data)) != (spec['sha256'], spec['bytes']):
                return None, None, 'the pinned %s has other bytes: nothing launched' % member
            number, pushed = self._capture('push', None, dict(context, member=member, path=spec['guest'],
                                                              data_sha256=spec['sha256']),
                                           lambda d=data, s=spec: self.transport.push(d, s['guest'], MEMBER_MODE, 0,
                                                                                      self.limits['push_timeout_s']),
                                           self.limits['push_timeout_s'])
            captures.append(number)
            command = crossings.digest_command(spec['guest'])
            number, check = self._shell('read', command, dict(context, member=member), self.limits['read_timeout_s'],
                                        4096, 4096)
            captures.append(number)
            if crossings.classify_digest(check, spec['guest']) != spec['sha256']:
                return None, None, 'the staged %s does not read back exactly: nothing written' % member
        replies = []
        for at, member in enumerate(crossings.MEMBERS):
            spec = pinned[member]
            # Staging can take long, and a member can change the session: the exact target is read
            # again before each member, never assumed from the preflight.
            reading, _, why = self._gate('WRITE', m, context, 'revalidation before %s' % member)
            if reading is None:
                if at == 0:
                    return None, None, '%s: nothing written' % why
                return None, None, '%s: the first member was written and the second was not' % why
            elapsed = reading['elapsed']
            command = crossings.write_command(session, member, spec['guest'])
            number, result = self._shell('mutation', command, dict(context, member=member),
                                         self.limits['mutation_timeout_s'], int(self.limits['reply_stdout_max']),
                                         int(self.limits['reply_stderr_max']))
            captures.append(number)
            replies.append((command, result.exit, result.stdout, result.stderr))
            classification = crossings.classify_write(result, spec['bytes'])
            if classification is None:
                return None, None, 'the write of %s did not complete: its effect is unknown' % member
            if classification != 'SUCCESS':
                raw = readers.raw_digest(replies)
                return classification, self._reply_fact('WRITE', m, classification, raw, elapsed, instance), None
            if at == 0 and cell is not None and cell['mode'] == 'loss-between-members':
                raise _Halt(self.ledger.record('fault', {'cell': cell['cell'], 'on': 'cross',
                                                         'crossing': context['crossing'],
                                                         'decision': 'halt-between-members', 'written': member,
                                                         'captures': list(captures)}))
        raw = readers.raw_digest(replies)
        return 'SUCCESS', self._reply_fact('WRITE', m, 'SUCCESS', raw, elapsed, instance), None

    def _notice(self, m, context, captures, elapsed, instance, deadline):
        """The admitted notice route: a separately qualified fixture. The adapter runs its fixed
        commands through the broker's captures and classifies its own exact forms. Each of its
        commands is sent only before the activation grant's launch deadline."""
        replies = []

        def run(command):
            if not self.notice.allowed(command):
                raise readers.Unclassified('a command outside the notice allowlist')
            number, result = self._shell('notice', command, context, self.limits['mutation_timeout_s'],
                                         int(self.limits['reply_stdout_max']), int(self.limits['reply_stderr_max']),
                                         deadline)
            captures.append(number)
            replies.append((command, result.exit, result.stdout, result.stderr))
            return result

        try:
            classification = self.notice.notice(run, m['ticket'], m['index'], m['plan'])
        except _NotLaunched as error:
            if not replies:
                return None, None, '%s: nothing launched' % error
            return None, None, 'the notice did not complete: %s' % error
        except (readers.Unclassified, readers.Unavailable) as error:
            return None, None, 'the notice did not complete: %s' % error
        if classification not in ('SUCCESS', 'REFUSED', 'UNRECOGNIZED'):
            return None, None, 'the notice gave no qualified reply'
        raw = readers.raw_digest(replies)
        return classification, self._reply_fact('NOTICE', m, classification, raw, elapsed, instance), None
