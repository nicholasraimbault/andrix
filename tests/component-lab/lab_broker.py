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
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _path in (str(HERE), str(ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import capture_ledger as ledgers  # noqa: E402
import lab_actions  # noqa: E402
import lab_crossings as crossings  # noqa: E402
import lab_evidence as evidence  # noqa: E402
import lab_protocol as proto  # noqa: E402
import lab_readers as readers  # noqa: E402
import lab_records as records  # noqa: E402
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
# Lab actions the broker runs between generations when the admission names them, each with its
# launch limit, at most LAB_ACTION_LIMIT.
LAB_ACTIONS = ('framework-restart',)
LAB_ACTION_LIMIT = 100
FRAMEWORK_RESTART = 'am restart'
# A framework restart runs only beside sessions positively uncommitted: OPEN and SEALED live ones,
# or terminal ones. A committed live session (VERIFYING, READY) could activate, and one whose
# commitment the reader does not state (LIVE_NOT_READY) is refused too.
RESTART_BLOCKING = ('VERIFYING', 'LIVE_NOT_READY', 'READY')
# A session listing is whole only when its LISTING fact says so.
COMPLETE_LISTINGS = ('NONE_FOR_PACKAGE', 'SESSIONS_FOR_PACKAGE')
# Fixed diagnostic reads the controller may ask between generations, and their output bound.
DIAGNOSTICS = {'logcat': 'logcat -b all -d'}
DIAGNOSTIC_STDOUT_MAX = 64 << 20
DIAGNOSTIC_TIMEOUT_S = 120
# Reader groups the controller may ask between generations.
CONTROLLER_READS = ('clock', 'boot', 'checkpoint', 'factory', 'active', 'sessions', 'target')
# The deployment store's record directories and file suffix, as DeploymentStore writes them.
STORE_SUFFIX = '.rec'
RECORDS = 'records'
# After `am restart` the broker waits for the later framework instance: a poll every
# RESTART_POLL_S seconds, at most RESTART_SETTLE_S seconds.
RESTART_POLL_S = 5
RESTART_SETTLE_S = 300
# Within a bound, a command starts only when at least this much of the bound remains.
BOUND_COMMAND_MIN_S = 1.0
CELL_KEYS = {'cross': ('plan', 'attempt', 'crossing', 'occurrence'), 'host': ('plan', 'attempt', 'crossing', 'occurrence'),
             'point': ('plan', 'attempt', 'point')}
CELL_MODES = {'cross': ('loss-before', 'loss-after', 'drop-reply', 'loss-between-members'),
              'host': ('loss-before', 'loss-after', 'drop-reply'), 'point': ('halt',)}
LIVE = ('OPEN', 'SEALED', 'VERIFYING', 'LIVE_NOT_READY', 'READY')
GROUP_KINDS = {'boot': ('BOOT',), 'checkpoint': ('CHECKPOINT',), 'factory': ('FACTORY',), 'active': ('ACTIVE',),
               'sessions': ('LISTING', 'SESSION'), 'users': ('USER',), 'receipts': ('RECEIPT',), 'target': ()}
DEVICE_KINDS = ('BOOT', 'CHECKPOINT', 'USER')
MEMBER_MODE = 0o644

# The ledger's command text for the reboot service, which has no shell command.
REBOOT_LABEL = 'adb service reboot:'

# A version 3 admission adds these keys to version 2's base, whose lab action map it replaces.
ADMISSION_3 = ('profile', 'cells_sha256', 'fixtures_sha256', 'payloads_sha256', 'fault_schedule_sha256', 'lab_actions',
               'branches', 'effect_limits', 'boot_policy')
# The broker's compound evidence manifests, each kept by its SHA-256 under COMPOUND. Under a version
# 3 admission only the compound writer makes a group of these readers, and it names no manifest only
# in its own record of one it could not keep, whose reason begins with UNKEPT.
COMPOUND = 'compound'
SCHEMAS = {'notice-visibility': 'andrix-notice-visibility-v1', 'receipts': 'andrix-receipt-read-v1',
           'health-baseline': 'andrix-health-baseline-v1', 'health': 'andrix-health-composition-v1'}
UNKEPT = 'the compound manifest could not be kept: '
# The notice text a ticket's NOTICE shows, bound by its SHA-256 in the issue before any launch.
NOTICE_TEXT = ('Andrix will restart this device to change %s. The device owner approved it. Notice %s, ticket %s, '
               'entry %d.')
HEALTH_WINDOW_STATE = 17
ROW_KEYS = ('row', 'purpose', 'installation', 'component', 'plan', 'ticket', 'index', 'control', 'boot', 'text_sha256',
            'event', 'uid', 'user', 'serial', 'candidate_elapsed')
VISIBILITY_KEYS = ('user', 'serial', 'current_user', 'awake', 'focused', 'challenge', 'visible')
HEALTH_ROW_KEYS = ('bit', 'status', 'reason', 'commands', 'preparation', 'baseline')
WITNESS_DECISIONS = ('QUALIFIED_CURRENT_ERROR', 'QUALIFIED_LIFECYCLE_JOIN', 'PENDING', 'INCONCLUSIVE')
# Criterion bits a health baseline serves, and those a preparation serves.
BASELINE_CRITERIA = (proto.NO_CRASH_OR_ANR,)


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


def _sync_directory(path):
    """Syncs one directory, so the names it holds are durable."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _NotLaunched(readers.Unavailable):
    """A command was refused before it was sent: the device's features could not be read, or its
    launch deadline (an activation grant's end, or a bound) passed before its launch. Nothing was
    launched. A refusal after the command's intent names its capture and command."""


class _TransferBound(Exception):
    """A request or reply transfer did not finish within its bound."""


class _Halt(Exception):
    def __init__(self, record):
        super().__init__('halt')
        self.record = record


def _hex(value, width):
    return isinstance(value, str) and len(value) == 2 * width and all(c in '0123456789abcdef' for c in value)


# Each typed action type's run request: what the controller names beyond the action and its reason.
REQUESTS = {'FRAMEWORK_RESTART': (), 'NOTICE_VISIBILITY': ('ticket', 'index', 'serial'), 'HEALTH_PREPARATION': ()}


def _request_problem(kind, request):
    """Why a typed action's run request is not exactly its type's, or None."""
    names = REQUESTS[kind]
    if set(request) != set(names):
        return 'a %s request names exactly: %s' % (kind, ', '.join(names) or 'nothing')
    if kind == 'NOTICE_VISIBILITY' and (
            not _hex(request['ticket'], 16) or request['ticket'] == proto.ZERO_ID or type(request['index']) is not int
            or not 0 <= request['index'] < proto.MAX_LEDGER or type(request['serial']) is not int or request['serial'] < 0):
        return 'a visibility request names a ticket, its notice entry and a recipient serial'
    return None


def _visibility_problem(projection, issue, user, brackets):
    """Why one visibility read does not qualify a notice's delivery to a recipient, or None."""
    if not isinstance(projection, dict) or set(projection) != set(VISIBILITY_KEYS):
        return 'a visibility of no known form'
    if brackets is None:
        return 'the read bracket changed or did not complete'
    if brackets['boot'] != issue['boot']:
        return "a visibility in another boot than its notice's"
    if (projection['user'], projection['serial']) != (user['id'], user['serial']):
        return 'a visibility of another user'
    if projection['current_user'] != user['id']:
        return "the recipient is not the display's current user"
    if projection['awake'] is not True or projection['focused'] is not True or projection['visible'] is not True:
        return 'the notice is not visible and focused on an awake display'
    if projection['challenge'] != issue['challenge']:
        return "the visible challenge is not the notice's"
    return None


def _side(value):
    """A reader's value as a side record value: itself when it has the canonical form, else a
    bounded printable description, so that a malformed projection is kept as evidence without
    being trusted."""
    try:
        evidence.canonical({'value': value})
        return value
    except evidence.SideError:
        text = ''.join(c if 0x20 <= ord(c) <= 0x7e else '?' for c in repr(value))
        return {'unencodable': text[:2000]}


def _side_text(value):
    """Whether a value is a string a side record can hold: printable ASCII within its bound."""
    return (isinstance(value, str) and len(value) <= evidence.MAX_STRING
            and all(0x20 <= ord(c) <= 0x7e for c in value))


def _emitted(mode, fact, raw):
    """One compound fact as its group emits it: its frame, whose raw digest is the manifest's, and
    the observation the ledger group records for it."""
    fact = dict(fact, raw=raw)
    frame = encoder.observation(fact)
    return frame, {'id': fact['observation'], 'kind': fact['kind'], 'mode': proto.MODE_NAMES[mode],
                   'classification': fact['classification'], 'boot': fact['boot'], 'instance': fact['instance'],
                   'elapsed': fact['elapsed'], 'user': fact['user'], 'serial': fact['serial'],
                   'sha256': hashlib.sha256(frame).hexdigest()}


def _whole_listing(facts, instance):
    """Whether a session group's facts are one whole listing of the framework instance: exactly one
    LISTING fact, of a complete classification, and every fact of that instance."""
    listings = [f for f in facts if f['kind'] == 'LISTING']
    return (len(listings) == 1 and listings[0]['classification'] in COMPLETE_LISTINGS
            and all(f['instance'] == instance for f in facts))


def _regular_bytes(path, limit=16 << 20):
    """The bytes of a regular file opened without following a link, or None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                return None
        return b''.join(chunks)
    finally:
        os.close(fd)


def check_admission(value):
    """The admitted configuration, every field checked."""
    try:
        return _check_admission(value)
    except (ValueError, TypeError, KeyError) as error:
        raise BrokerError('admission: %s' % error) from error


def _check_admission(value):
    expected = {'version', 'installation', 'component', 'coordinator', 'trust', 'manifest', 'config', 'serial',
                'target_scope', 'device_dir', 'fences', 'limits'}
    # Version 2 adds, for a guest: the lab actions the broker may run between generations, each with
    # its launch limit; the device crossings it may launch at all; and the deployment store whose
    # records each crossing names, which the broker retains.
    if isinstance(value, dict) and value.get('version') == 2:
        expected = expected | {'lab_actions', 'launches', 'store'}
    # Version 3, the next campaign profile, keeps version 2's launches and store and replaces its
    # action map with the ordered typed action specs, the bound manifests, the branches, the effect
    # limits and the boot policy. Its bridge speaks protocol version 2.
    if isinstance(value, dict) and value.get('version') == 3:
        expected = expected | {'launches', 'store'} | set(ADMISSION_3)
    if not isinstance(value, dict) or set(value) != expected or value['version'] not in (1, 2, 3):
        raise BrokerError('not a version 1, 2 or 3 admission')
    if value['version'] == 3:
        _check_admission_3(value)
    if value['version'] == 2:
        actions = value['lab_actions']
        if (not isinstance(actions, dict) or any(action not in LAB_ACTIONS for action in actions)
                or any(type(limit) is not int or not 1 <= limit <= LAB_ACTION_LIMIT for limit in actions.values())):
            raise BrokerError('admission lab actions are known names, each with a launch limit of 1 to %d'
                              % LAB_ACTION_LIMIT)
        launches = value['launches']
        if (not isinstance(launches, list) or len(set(launches)) != len(launches)
                or any(name not in proto.DEVICE_CROSSINGS for name in launches)):
            raise BrokerError('admission launches are device crossings, each once')
        if not isinstance(value['store'], str) or not value['store'].startswith('/'):
            raise BrokerError('admission store is an absolute path')
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


def _check_admission_3(value):
    """The next campaign profile's own keys: exact, every digest nonzero, no old action map."""
    launches = value['launches']
    if (not isinstance(launches, list) or len(set(launches)) != len(launches)
            or any(name not in proto.DEVICE_CROSSINGS for name in launches)):
        raise BrokerError('admission launches are device crossings, each once')
    if not isinstance(value['store'], str) or not value['store'].startswith('/'):
        raise BrokerError('admission store is an absolute path')
    if value['profile'] != lab_actions.PROFILE:
        raise BrokerError('an admission of another profile')
    for name in ('cells_sha256', 'fixtures_sha256', 'payloads_sha256', 'fault_schedule_sha256'):
        if not _hex(value[name], 32) or value[name] == '00' * 32:
            raise BrokerError('admission %s is not a nonzero digest' % name)
    specs = lab_actions.check_specs(value['lab_actions'], value['installation'])
    lab_actions.check_branches(value['branches'], specs)
    lab_actions.check_effect_limits(value['effect_limits'], proto.DEVICE_CROSSINGS)
    lab_actions.check_boot_policy(value['boot_policy'])


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
        # The broker directory's own name lives in a directory the broker did not make: synced now,
        # and again at every opening.
        _sync_directory(root.parent)
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
             sleep=time.sleep, ids=os.urandom, processes=None, sync=True, target=None, target_read=False, health=None):
        """Opens a broker directory. The native target scope is read at HELLO and at every
        crossing's gate. With `target_read`, the reader's admitted target reader reads it from
        the guest as the broker's own recorded group, and the scope is established empty only
        when both the admission and that read say so. Otherwise `target`, when given, is a host
        callable that returns the scope as it stands (ESTABLISHED_EMPTY, HELD or UNKNOWN), and
        without either the admitted scope stands. A target that cannot be read is UNKNOWN.
        `health`, under a version 3 admission, is the health adapter whose fixed commands a
        HEALTH_PREPARATION runs."""
        if target_read and (target is not None or not getattr(reader, 'target_admitted', False)):
            raise BrokerError("a target read needs the reader's admitted target reader and no host target")
        self = object.__new__(cls)
        self.root = Path(root)
        self.transport, self.reader, self.notice, self.health = transport, reader, notice, health
        self._target = target
        self._target_read = bool(target_read)
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
        # Every opening syncs the directory holding the broker's name, and the broker's own, before
        # anything relies on the durable history, so a barrier that an interrupted initialization or
        # an earlier failed sync never reached is never skipped.
        try:
            _sync_directory(self.root.parent)
            _sync_directory(self.root)
        except OSError as error:
            raise BrokerError('the broker directory cannot be made durable: %s' % error) from error
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
        self._launches = (frozenset(self.admission['launches']) if self.admission['version'] in (2, 3)
                          else frozenset(proto.DEVICE_CROSSINGS))
        # A version 3 admission's bridge speaks protocol version 2, and only it.
        self.protocol = proto.VERSION_2 if self.admission['version'] == 3 else proto.VERSION
        self.specs = (lab_actions.check_specs(self.admission['lab_actions'], self.admission['installation'])
                      if self.admission['version'] == 3 else {})
        self.fences = Fences(self.admission['fences'], self._wall)
        try:
            self.ledger = ledgers.Ledger.open(self.root / LEDGER, sync=sync)
        except ledgers.LedgerDamaged as error:
            raise BrokerError('the ledger is damaged: %s' % error) from error
        except OSError as error:
            raise BrokerError('the ledger cannot be made durable: %s' % error) from error
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
                                    'target_read': self._target_read,
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
        self.cells, self.consumed, self.pinned, self.publications = [], set(), {}, {}
        self.crossed, self.open_crossings = set(), {}
        self.host_begun, self.host_ended = {}, set()
        self.users_seen = {}
        self.scale = {}
        # The next campaign profile's state, all of it from complete ledger entries.
        self.issues = {}
        self.visibility = {}
        self.rows_seen, self.proofs = {}, {}
        self.baselines = {}
        self.preparations, self.used_preparations = {}, set()
        self.action_begins, self.action_ends, self.open_actions = {}, {}, {}
        for entry in self.ledger.entries:
            if not entry.complete:
                continue
            c = entry.content
            kind = entry.kind
            if kind == 'group' and self.admission['version'] == 3:
                self._check_unkept_compound(c)
            if kind == 'notice-issue':
                self.issues[(c['ticket'], c['index'])] = c
            elif kind == 'lab-action' and c.get('record') in ('BEGIN', 'END', 'REFUSED'):
                self._action_record(c)
            elif kind == 'group' and c.get('compound') is not None:
                self._check_compound(c)
                self._compound_record(c)
                continue
            elif kind == 'group' and c.get('reader') == 'receipts' and 'rows' in c:
                self._pin_rows(c)
            elif kind == 'group' and c.get('reader') == 'clock' and 'offered' in c and c['status'] == 'facts':
                # A probe's begin bracket: the preparations it offered are used from then on.
                self.used_preparations.update(c['offered'])
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
                if 'publication' in c:
                    self.publications[c['plan']] = c['publication']
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
                                            'reason': 'the broker was lost during the host call',
                                            'wall_ns': self._wall(), 'monotonic_ns': self._monotonic()})
                self.host_ended.add(key)
        # A typed action that a lost broker left without its END: its effect is unknown, and it is
        # never run again to find out. Its captures, an interrupted one included, are its uncertain
        # effects.
        for number, begun in sorted(self.open_actions.items()):
            self._end_action(begun, number, 'LOST', None, 'the broker was lost during the action; its effect is unknown',
                             False, [])
        if g is not None:
            self.ledger.record('generation-end', {'generation': g['generation'], 'status': 'LOST', 'exit': None,
                                                  'signal': None, 'killed': killed, 'halt_ordered': False,
                                                  'stopped_sent': False, 'violation': 'the broker was lost',
                                                  'stderr_sha256': None, 'stderr_bytes': None,
                                                  'quarantined': quarantined, 'wall_ns': self._wall()})
            self.open_generation = None

    def _action_record(self, c):
        """A typed action's BEGIN, END or refusal, as it stands in the ledger."""
        if c['record'] == 'BEGIN':
            self.action_begins.setdefault(c['action_id'], []).append(c['number'])
            self.open_actions[c['number']] = c
        elif c['record'] == 'END':
            self.action_ends[c['begin']] = c
            begun = self.open_actions.pop(c['begin'], None)
            if (begun is not None and begun['type'] == 'HEALTH_PREPARATION' and c['status'] == 'OK' and c['settled']
                    and c['outcome'] and c['outcome']['classification'] == 'PREPARED'):
                self.preparations[begun['operation']] = {'begin': begun, 'end': c}

    def _compound_record(self, c):
        """A compound group's joins, and its read bracket on the clock scale when it was emitted. An
        emitted receipt's event time never moves the scale: only the current read's bracket does."""
        reader = c['reader']
        if reader == 'notice-visibility':
            self.visibility.setdefault((c['ticket'], c['index'], c['serial']), []).append(c)
        elif reader == 'receipts':
            self._pin_rows(c)
            for row in c['rows']:
                if c['status'] == 'facts' and row['judgment'] == 'EMITTED':
                    self.proofs.setdefault(row['key'], row['proof'])
        elif reader == 'health-baseline' and c['status'] == 'facts':
            self.baselines.setdefault((c['brackets']['boot'], c['user'], c['serial']), []).append(c)
        elif reader == 'health':
            self.used_preparations.update(c['preparations'])
        if c['emitted']:
            self._scaled(c['brackets']['end'])

    def _pin_rows(self, c):
        """The first bytes of every row a receipt read judged, from its ledger group, whether or
        not the read emits and whether or not its manifest was kept. A pin only ever refuses."""
        for row in c['rows']:
            if row['key'] is not None:
                self.rows_seen.setdefault(row['key'], row['sha256'])

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
            if on == 'cross' and cell['crossing'] not in self._launches and cell['mode'] != 'loss-before':
                raise BrokerError('a cell that needs a launch, on a crossing this guest may not launch')
            known.add(cell['cell'])
            checked.append(dict(cell))
        self.ledger.record('faults', {'cells': checked})
        self.cells.extend(checked)

    def framework_restart(self, reason):
        """Asks Android for a later framework instance in the same boot, with `am restart`, between
        generations. Refused unless the admission names it, while a generation is open, after a stop
        or without a reason; then, after its BEGIN record, unless the broker's own clock read and
        complete session listing, in one framework instance, show no committed session of the
        component that could still activate. The command's exit proves nothing: after it the broker
        polls, each time a clock group and, when that clock shows a later instance of the same boot, a
        session listing group, until one poll shows the same boot, a larger framework instance than the
        precondition's and a whole listing of that instance, or the settle bound passes. Records the action around the command's capture and the polls, and
        returns the summary; a restart that does not settle is refused after its END record. A later
        generation's own clock reads must still show the later instance."""
        if 'framework-restart' not in self.admission.get('lab_actions', {}):
            raise BrokerError('the framework restart is not an admitted lab action')
        if self.open_generation is not None:
            raise BrokerError('a lab action runs only between generations')
        if not isinstance(reason, str) or not reason.strip():
            raise BrokerError('a lab action names its reason')
        self._fence()
        begin = self.ledger.record('lab-action', {'action': 'framework-restart', 'phase': 'BEGIN', 'reason': reason})
        context = {'request': None, 'generation': None, 'purpose': 'lab-action', 'lab_action': begin}
        refused, before = self._restart_refusal(dict(context, purpose='lab-action-precondition'))
        launched = sum(1 for e in self.ledger.entries if e.kind == 'capture'
                       and e.content['intent'].get('operation') == 'lab-action'
                       and e.content['intent'].get('command') == FRAMEWORK_RESTART)
        if refused is None and launched >= self.admission['lab_actions']['framework-restart']:
            refused, before = 'the admitted limit of %d framework restarts is reached' % launched, None
        if refused is not None:
            self.ledger.record('lab-action', {'action': 'framework-restart', 'phase': 'END', 'begin': begin,
                                              'refused': refused})
            raise BrokerError('the framework restart is refused: %s' % refused)
        number, result = self._shell('lab-action', FRAMEWORK_RESTART, context, self.limits['mutation_timeout_s'],
                                     int(self.limits['reply_stdout_max']), int(self.limits['reply_stderr_max']))
        summary = {'capture': number, 'launch': result.launch, 'completion': result.completion, 'exit': result.exit,
                   'before': {'boot': before[0], 'instance': before[1]}}
        settled, settle, why = self._restart_settle(dict(context, purpose='lab-action-settle'), before)
        summary.update(settled=settled, polls=len(settle['polls']), settle=settle)
        if settled is None:
            self.ledger.record('lab-action', dict(summary, action='framework-restart', phase='END', begin=begin,
                                                  refused=why))
            raise BrokerError('the framework restart did not settle: %s' % why)
        self.ledger.record('lab-action', dict(summary, action='framework-restart', phase='END', begin=begin))
        return summary

    def _restart_settle(self, context, before):
        """Polls within one hard monotonic bound until a clock group shows the same boot and a larger
        framework instance than `before` and a session listing group right after it is whole in that
        instance. No poll command starts once the bound has passed, each command's timeout and each
        sleep are cut to the time remaining, and a poll that ends after the bound settles nothing.
        Returns (the two group numbers and the instance, or None; the record of the bound and its
        polls; why not)."""
        boot, instance = before
        started = self._monotonic()
        deadline = started + RESTART_SETTLE_S * 1_000_000_000
        record = {'started_monotonic_ns': started, 'deadline_monotonic_ns': deadline, 'polls': []}
        why = 'no later framework instance with a whole listing within %d s' % RESTART_SETTLE_S
        while self._monotonic() < deadline:
            poll = {'clock': None, 'sessions': None}
            record['polls'].append(poll)
            clock = self._clock_group(context, emitted=False, deadline_ns=deadline)
            poll['clock'] = clock.number
            if clock.ok and clock.reading['boot'] != boot:
                poll['ended_monotonic_ns'] = self._monotonic()
                return None, record, 'a poll read another boot'
            if clock.ok and clock.reading['instance'] > instance and self._monotonic() < deadline:
                later = clock.reading['instance']
                group = self._group('sessions', self.reader.sessions, context, boot, emitted=False, deadline_ns=deadline)
                poll['sessions'] = group.number
                poll['ended_monotonic_ns'] = self._monotonic()
                if group.ok and _whole_listing(group.facts, later):
                    if poll['ended_monotonic_ns'] > deadline:
                        return None, record, 'the settling poll ended after the %d s bound' % RESTART_SETTLE_S
                    return {'clock': clock.number, 'sessions': group.number, 'instance': later}, record, None
            poll.setdefault('ended_monotonic_ns', self._monotonic())
            remaining = (deadline - self._monotonic()) / 1_000_000_000
            if remaining <= 0:
                break
            self._sleep(min(RESTART_POLL_S, remaining))
        return None, record, why

    def _restart_refusal(self, context):
        """(None, (boot, instance)) when a clock read and a complete session listing of the same
        framework instance show no committed session of the component that could activate, else
        (why not, None)."""
        clock = self._clock_group(context, emitted=False)
        if not clock.ok:
            return 'the clock read is unavailable (%s)' % clock.reason, None
        boot, instance = clock.reading['boot'], clock.reading['instance']
        if instance < 0:
            return 'no framework instance is running', None
        group = self._group('sessions', self.reader.sessions, context, boot, emitted=False)
        if not group.ok:
            return 'the session listing is unavailable (%s)' % group.reason, None
        if not _whole_listing(group.facts, instance):
            return "the session listing is not whole in the clock's framework instance", None
        if any(f['kind'] == 'SESSION' and f['classification'] in RESTART_BLOCKING for f in group.facts):
            return 'a session of the component is committed or of unknown commitment', None
        return None, (boot, instance)

    def controller_read(self, names, purpose):
        """Reader groups the controller asks between generations, in the order named, recorded as the
        broker's own groups and never given to a coordinator: clock, boot, checkpoint, factory, active,
        sessions and, when admitted, target. Each group after a clock group is checked against that
        clock's boot. Returns the groups."""
        if self.open_generation is not None:
            raise BrokerError('a controller read runs only between generations')
        if (not isinstance(names, (list, tuple)) or not names or any(name not in CONTROLLER_READS for name in names)
                or not isinstance(purpose, str) or not purpose.strip()):
            raise BrokerError('a controller read names known groups and its purpose')
        if 'target' in names and not self._target_read:
            raise BrokerError('no target reader is admitted')
        self._fence()
        context = {'request': None, 'generation': None, 'purpose': 'controller: ' + purpose}
        groups, boot = [], None
        for name in names:
            if name == 'clock':
                group = self._clock_group(context, emitted=False)
                boot = group.reading['boot'] if group.ok else boot
            elif name == 'target':
                group = self._group('target', self.reader.target, context, None, emitted=False)
            else:
                group = self._group(name, getattr(self.reader, name), context, boot, emitted=False)
            groups.append(group)
        return groups

    def diagnostic(self, name):
        """One fixed diagnostic read between generations, fenced and captured like any command, with
        its own output bound. Returns the capture's number and result."""
        if self.open_generation is not None:
            raise BrokerError('a diagnostic runs only between generations')
        if name not in DIAGNOSTICS:
            raise BrokerError('a diagnostic of no known name')
        context = {'request': None, 'generation': None, 'purpose': 'diagnostic', 'diagnostic': name}
        return self._shell('diagnostic', DIAGNOSTICS[name], context, DIAGNOSTIC_TIMEOUT_S, DIAGNOSTIC_STDOUT_MAX,
                           int(self.limits['read_stderr_max']))

    # ---------------------------------------------- typed lab actions of the next campaign profile

    def run_action(self, action_id, reason, **request):
        """One use of an admitted typed lab action, between generations. Returns its END record.

        Nothing is recorded unless the version 3 admission names the action, no generation is
        open, a reason and the type's exact request are given, no fence has tripped, a use is
        left, the last use settled (only an idempotent capture and read may follow an uncertain
        one) and the predecessor has a settled use. The broker keeps the spec's exact bytes by
        digest, reads a whole typed inventory as its own group and resolves the selected user
        from it. A user that does not resolve is refused with that inventory kept, and no use is
        consumed. The BEGIN record then pins the spec digest, authority, resolved user, inputs,
        predecessor checkpoint, phase and cell before any precondition or effect. Every command
        is the type's or its admitted adapter's fixed form, fenced, within the action's deadline
        and output bounds, and an effect command first checks the effect limits, counted from the
        ledger's captures. The END record names its captures, later reads, outcome, what stayed
        uncertain and whether it settled."""
        if self.admission['version'] != 3:
            raise BrokerError('typed lab actions need a version 3 admission')
        spec = self.specs.get(action_id)
        if spec is None:
            raise BrokerError('not an admitted typed lab action')
        if self.open_generation is not None:
            raise BrokerError('a typed lab action never runs beside a generation')
        if not isinstance(reason, str) or not reason.strip():
            raise BrokerError('a typed lab action names its reason')
        kind = lab_actions.TYPES[spec['type']]
        problem = _request_problem(spec['type'], request)
        if problem is not None:
            raise BrokerError(problem)
        self._fence()
        uses = self.action_begins.get(action_id, [])
        if len(uses) >= spec['max_uses']:
            raise BrokerError('the %d admitted uses of the action are spent' % spec['max_uses'])
        if uses and not kind['after_uncertain']:
            last = self.action_ends.get(uses[-1])
            if last is None or not last['settled']:
                raise BrokerError('the last use of the action did not settle: it is observed or halted, never repeated')
        checkpoint = None
        if spec['predecessor'] is not None:
            settled = [self.action_ends[n] for n in self.action_begins.get(spec['predecessor'], [])
                       if n in self.action_ends and self.action_ends[n]['settled'] and self.action_ends[n]['status'] == 'OK']
            if not settled:
                raise BrokerError('the predecessor action has no settled use')
            checkpoint = settled[-1]['number']
        adapter = {'notice': self.notice, 'health': self.health, None: None}[kind['adapter']]
        if kind['adapter'] is not None and adapter is None:
            raise BrokerError('no %s adapter is admitted' % kind['adapter'])
        if not self.reader.inventory_admitted:
            raise BrokerError('no typed user inventory is admitted')
        issue = None
        if spec['type'] == 'NOTICE_VISIBILITY':
            issue = self.issues.get((request['ticket'], request['index']))
            if issue is None:
                raise BrokerError('no notice of that ticket and entry was issued')
        data = lab_actions.spec_bytes(spec)
        spec_sha = hashlib.sha256(data).hexdigest()
        try:
            self._keep(spec_sha, data)
        except (BrokerError, OSError) as error:
            raise self._writer_failed('the action spec could not be kept: %s' % error) from error
        context = {'request': None, 'generation': None, 'purpose': 'lab-action-resolve', 'action_id': action_id}
        inventory = self._group('inventory', self.reader.inventory, context, None, emitted=False)
        user, why = None, 'the user inventory is unavailable (%s)' % inventory.reason
        if inventory.ok:
            user, why = self._resolve(spec, inventory.reading, issue, request)
        if user is None:
            self.ledger.record('lab-action', {'record': 'REFUSED', 'action_id': action_id, 'type': spec['type'],
                                              'spec_sha256': spec_sha, 'reason': reason, 'request': request,
                                              'inventory_group': inventory.number, 'refused': why,
                                              'wall_ns': self._wall(), 'monotonic_ns': self._monotonic()})
            raise BrokerError('the action resolves no user: %s' % why)
        started = self._monotonic()
        begin = {'record': 'BEGIN', 'action_id': action_id, 'type': spec['type'], 'operation': proto.fresh_id(self._ids),
                 'spec_sha256': spec_sha, 'authority': spec['authority'],
                 'resolved_user': {'id': user['id'], 'serial': user['serial'], 'type': user['type'],
                                   'inventory_group': inventory.number},
                 'input_digests': [], 'predecessor_checkpoint': checkpoint, 'phase': spec['phase'], 'cell': spec['cell'],
                 'use': len(uses) + 1, 'reason': reason, 'request': request, 'parameters': spec['parameters'],
                 'deadline_monotonic_ns': started + spec['timeout_ms'] * 1_000_000, 'wall_ns': self._wall(),
                 'monotonic_ns': started}
        if spec['type'] == 'HEALTH_PREPARATION':
            begin['challenge'] = proto.fresh_id(self._ids)
        self._fence()
        number = self.ledger.record('lab-action', begin)
        begin = dict(begin, number=number, kind='lab-action')
        self._action_record(begin)
        context = {'request': None, 'generation': None, 'purpose': 'lab-action', 'lab_action': number,
                   'action_id': action_id}
        command = self._action_commands(spec, kind, adapter, context, begin['deadline_monotonic_ns'])
        try:
            if spec['type'] == 'FRAMEWORK_RESTART':
                result = self._act_restart(context, command)
            elif spec['type'] == 'NOTICE_VISIBILITY':
                result = self._act_visibility(context, command, begin, issue, user)
            else:
                result = self._act_preparation(context, command, begin, spec, user)
        except Stopped as error:
            self._end_action(begin, number, 'STOPPED', None, str(error), False, [])
            raise
        except (readers.Unavailable, readers.Unclassified, ValueError, KeyError, TypeError) as error:
            # The action ends here. An effect command that may have launched leaves it uncertain; a
            # refusal before any launch, an effect limit or the bound, refuses it.
            launched = self._action_counts(number)
            uncertain = launched['effects_launched'] + launched['effects_uncertain'] > 0
            status = 'UNKNOWN' if uncertain else 'REFUSED' if isinstance(error, _NotLaunched) else 'UNAVAILABLE'
            result = (status, None, '%s: %s' % (type(error).__name__, error), not uncertain, [])
        return self._end_action(begin, number, *result)

    def _resolve(self, spec, reading, issue, request):
        selector = spec['user_selector']['kind']
        if selector == 'SYSTEM_USER':
            return lab_actions.resolve_system(reading)
        if selector == 'NOTICE_RECIPIENT':
            return lab_actions.resolve_recipient(reading, issue, request['serial'])
        return None, 'no admitted action creates a user in this version'

    def _action_commands(self, spec, kind, adapter, context, deadline):
        """The one way an action's commands reach the guest: a type's own fixed command or its
        adapter's allowlisted form, an effect only within the effect limits, every command fenced
        and refused once less than BOUND_COMMAND_MIN_S of the action's deadline is left, with the
        spec's output bounds."""
        def command(operation, text):
            allowed = text == FRAMEWORK_RESTART if adapter is None else adapter.allowed(text)
            if not allowed:
                raise readers.Unclassified('a command outside the %s allowlist' % (kind['adapter'] or spec['type']))
            if operation == 'lab-action-effect':
                spent = self._effect_spent(kind['effect'], spec['phase'])
                if spent is not None:
                    raise _NotLaunched('%s: nothing launched' % spent)
            left = deadline - self._monotonic()
            if left < BOUND_COMMAND_MIN_S * 1_000_000_000:
                raise _NotLaunched("too little of the action's bound remains for another command")
            timeout = min(self.limits['mutation_timeout_s' if operation == 'lab-action-effect' else 'read_timeout_s'],
                          left / 1_000_000_000)
            capture, result = self._shell(operation, text, dict(context, effect_class=kind['effect'], phase=spec['phase']),
                                          timeout, spec['stdout_max'], spec['stderr_max'], not_after_ns=deadline,
                                          bound_ns=deadline)
            if not result.completed or result.overflow is not None:
                raise readers.Unavailable('action capture %d did not complete: %s' % (capture, result.completion))
            return result
        return command

    def _effect_spent(self, effect_class, phase):
        """Why the admitted effect limits refuse one more action effect command of a class in a
        phase, or None. Effects are counted from the ledger's captures that may have launched,
        never from ENDs."""
        limits = self.admission['effect_limits']
        by_class = by_phase = 0
        for e in self.ledger.entries:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if intent and intent.get('operation') == 'lab-action-effect' and self._may_have_launched(e):
                by_class += intent.get('effect_class') == effect_class
                by_phase += intent.get('phase') == phase
        if by_class >= limits[effect_class]:
            return 'the admitted %d %s effects are spent' % (limits[effect_class], effect_class)
        if by_phase >= limits['phases'][phase]:
            return 'the admitted %d effects of phase %s are spent' % (limits['phases'][phase], phase)
        return None

    def _action_counts(self, number):
        """One use's effect and read captures by what they may have done: launched, uncertain (an
        interrupted intent or an unknown launch) or not launched."""
        counts = {'effects_launched': 0, 'effects_uncertain': 0, 'effects_not_launched': 0, 'reads': 0}
        for e in self.ledger.entries:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if not intent or intent.get('lab_action') != number:
                continue
            if intent.get('operation') != 'lab-action-effect':
                counts['reads'] += 1
            elif e.state == 'interrupted' or (e.complete and e.content['result'].get('launch') == 'unknown'):
                counts['effects_uncertain'] += 1
            elif e.complete and e.content['result'].get('launch') == 'not-launched':
                counts['effects_not_launched'] += 1
            else:
                counts['effects_launched'] += 1
        return counts

    def _end_action(self, begin, number, status, outcome, uncertainty, settled, postreads):
        """Records one use's END. It names only its own captures, those of its own BEGIN."""
        captures = [e.number for e in self.ledger.entries
                    if e.kind == 'capture' and (e.content.get('intent') or {}).get('lab_action') == number]
        record = {'record': 'END', 'begin': number, 'action_id': begin['action_id'], 'type': begin['type'],
                  'operation': begin['operation'], 'status': status, 'captures': captures,
                  'postread_groups': list(postreads), 'outcome': outcome, 'uncertainty': uncertainty,
                  'settled': settled, 'counts': self._action_counts(number), 'wall_ns': self._wall(),
                  'monotonic_ns': self._monotonic()}
        end = self.ledger.record('lab-action', record)
        record = dict(record, number=end, kind='lab-action')
        self._action_record(record)
        return record

    def _act_restart(self, context, command):
        """FRAMEWORK_RESTART: the version 2 restart's precondition, command and settle wait, as one
        typed use. A restart that does not settle stays uncertain."""
        refused, before = self._restart_refusal(dict(context, purpose='lab-action-precondition'))
        if refused is not None:
            return 'REFUSED', {'refused': refused}, None, True, []
        result = command('lab-action-effect', FRAMEWORK_RESTART)
        later, polls, why = self._restart_settle(dict(context, purpose='lab-action-settle'), before)
        outcome = {'before': {'boot': before[0], 'instance': before[1]}, 'exit': result.exit, 'settled': later,
                   'polls': len(polls['polls']), 'settle': polls}
        if later is None:
            return 'UNKNOWN', outcome, why, False, []
        return 'OK', outcome, None, True, [later['clock'], later['sessions']]

    def _act_visibility(self, context, command, begin_record, issue, user):
        """NOTICE_VISIBILITY: the notice adapter's fixed capture and read of one required
        recipient's current display between two clock reads, kept as a compound notice-visibility
        group that is never a deployment fact. It qualifies only in the notice's boot with one
        running framework through the bracket, for the recipient as the display's current user,
        awake and focused, showing the issue's own challenge. Its completion is the delivery time
        a receipt may prove."""
        deadline = begin_record['deadline_monotonic_ns']
        first = len(self.ledger.entries)
        begin = self._clock_group(dict(context, purpose='lab-action-read', part='begin'), issue['boot'], emitted=False,
                                  deadline_ns=deadline)
        projection, status, reason, end, stopped = None, 'unavailable', 'the read bracket did not begin', None, None
        if begin.ok:
            binding = {'id': user['id'], 'serial': user['serial'], 'type': user['type']}
            try:
                projection = self.notice.visibility(lambda c: command('lab-action-effect', c),
                                                    lambda c: command('lab-action-read', c), dict(issue), binding)
                status, reason = 'facts', None
            except Stopped as error:
                status, reason, stopped = 'stopped', str(error), error
            except readers.Unavailable as error:
                status, reason = 'unavailable', str(error)
            except (readers.Unclassified, ValueError, KeyError, TypeError) as error:
                status, reason = 'unclassified', '%s: %s' % (type(error).__name__, error)
            if status == 'facts':
                end = self._clock_group(dict(context, purpose='lab-action-read', part='end'), issue['boot'],
                                        emitted=False, deadline_ns=deadline)
        brackets = self._brackets(begin, end, issue['boot'])
        why = reason
        if status == 'facts':
            why = _visibility_problem(projection, issue, user, brackets)
        qualified = status == 'facts' and why is None
        captures = [e.number for e in self.ledger.entries[first:] if e.kind == 'capture'
                    and (e.content.get('intent') or {}).get('operation') in ('lab-action-effect', 'lab-action-read')]
        group, _ = self._compound('notice-visibility', dict(context, purpose='notice-visibility'), captures,
                                  {'begin': begin.number, 'end': end.number if end is not None else None},
                                  status, reason, brackets,
                                  {'projection': _side(projection), 'qualified': qualified, 'why_not': why},
                                  extra={'ticket': issue['ticket'], 'index': issue['index'], 'issue': issue['number'],
                                         'user': user['id'], 'serial': user['serial'], 'qualified': qualified})
        if stopped is not None:
            raise stopped
        outcome = {'qualified': qualified, 'why_not': why, 'group': group}
        if status in ('facts', 'unavailable', 'unclassified') and self._action_counts(begin_record['number'])['effects_uncertain']:
            return 'UNKNOWN', outcome, 'a capture command did not complete', False, [group]
        return ('OK' if status == 'facts' else 'UNAVAILABLE'), outcome, None if status == 'facts' else reason, True, [group]

    def _act_preparation(self, context, command, begin_record, spec, user):
        """HEALTH_PREPARATION: the health adapter's fixed UI, user and work steps for the spec's
        criteria of one user, under the BEGIN's fresh challenge, between two clock reads. Its
        interval is that bracket: a probe may use it once, only within the window and its maximum
        probe width. After an effect, a use settles only with a PREPARED or REFUSED form within its
        whole bracket."""
        deadline = begin_record['deadline_monotonic_ns']
        begin = self._clock_group(dict(context, purpose='lab-action-read', part='begin'), None, emitted=False,
                                  deadline_ns=deadline)
        if not begin.ok:
            return 'UNAVAILABLE', None, 'the begin clock is unavailable (%s)' % begin.reason, True, [begin.number]
        binding = {'id': user['id'], 'serial': user['serial'], 'type': user['type'],
                   'criteria': list(spec['parameters']['criteria']), 'challenge': begin_record['challenge'],
                   'operation': begin_record['operation']}
        classification = self.health.prepare(lambda c: command('lab-action-effect', c),
                                             lambda c: command('lab-action-read', c), binding)
        end = self._clock_group(dict(context, purpose='lab-action-read', part='end'), begin.reading['boot'],
                                emitted=False, deadline_ns=deadline)
        brackets = self._brackets(begin, end)
        if classification not in ('PREPARED', 'REFUSED', 'UNRECOGNIZED'):
            return 'UNKNOWN', None, 'the preparation gave no qualified form', False, [begin.number, end.number]
        outcome = {'classification': classification, 'criteria': binding['criteria'], 'challenge': binding['challenge'],
                   'interval': None if brackets is None else {
                       'boot': brackets['boot'], 'instance': brackets['instance'], 'begin': brackets['begin']['elapsed'],
                       'end': brackets['end']['elapsed'], 'begin_wall': brackets['begin']['wall'],
                       'end_wall': brackets['end']['wall']}}
        # Only a qualified form within its whole bracket settles a use. An unrecognized form, or a
        # bracket that changed or did not complete, after an effect that may have launched leaves
        # that effect uncertain: the use is observed or halted, never repeated.
        counts = self._action_counts(begin_record['number'])
        uncertain = counts['effects_launched'] + counts['effects_uncertain'] > 0
        if classification == 'UNRECOGNIZED' or brackets is None:
            why = ('the preparation gave an unrecognized form' if classification == 'UNRECOGNIZED'
                   else 'the interval bracket changed or did not complete')
            return ('UNKNOWN' if uncertain else 'UNAVAILABLE'), outcome, why, not uncertain, [begin.number, end.number]
        return 'OK', outcome, None, True, [begin.number, end.number]

    def health_baseline(self, ticket, plan, user, serial, purpose):
        """One user's health baseline, read between generations by the admitted composer between
        two clock reads and kept as a compound group that is never a deployment fact. The user
        must show running and unmarked in a whole typed inventory. A probe relies only on a
        baseline completed by its window's start in its own framework instance, so take it before
        the round that opens the window. An unavailable read is kept and never replaces the last
        good one. Returns its group."""
        if self.admission['version'] != 3 or not self.reader.health_admitted or not self.reader.inventory_admitted:
            raise BrokerError('a health baseline needs a version 3 admission and its admitted readers')
        if self.open_generation is not None:
            raise BrokerError('a health baseline is never read beside a generation')
        if (not _hex(ticket, 16) or not _hex(plan, 16) or type(user) is not int or type(serial) is not int
                or not isinstance(purpose, str) or not purpose.strip()):
            raise BrokerError('a health baseline names its ticket, plan, user, serial and purpose')
        self._fence()
        context = {'request': None, 'generation': None, 'purpose': 'health-baseline', 'reason': purpose,
                   'ticket': ticket, 'plan': plan, 'user': user, 'serial': serial}
        inventory = self._group('inventory', self.reader.inventory, context, None, emitted=False)
        found = ([u for u in inventory.reading['users'] if (u['id'], u['serial']) == (user, serial)]
                 if inventory.ok and inventory.reading['whole'] else [])
        if len(found) != 1 or not any(lab_actions.usable(found[0], t)
                                      for t in (lab_actions.SYSTEM_TYPE, lab_actions.SECONDARY_TYPE)):
            raise BrokerError('a whole inventory shows no usable full user of that ID and serial')
        begin = self._clock_group(dict(context, part='begin'), None, emitted=False)
        projection, captured, status, reason, end = None, [], 'unavailable', 'the read bracket did not begin', None
        if begin.ok:
            reader_context = {'ticket': ticket, 'plan': plan, 'user': user, 'serial': serial}
            projection, captured, status, reason = self._call_reader(
                'health-baseline', lambda: self.reader.health_baseline(reader_context), context, None, lambda v: v)
            if status == 'facts':
                end = self._clock_group(dict(context, part='end'), begin.reading['boot'], emitted=False)
        brackets = self._brackets(begin, end)
        if status == 'facts' and brackets is None:
            status, reason = 'unavailable', 'the read bracket changed or did not complete'
        if status == 'facts' and (not isinstance(projection, dict) or set(projection) != {'user', 'serial', 'facts'}
                                  or (projection['user'], projection['serial']) != (user, serial)):
            status, reason = 'unclassified', 'a baseline of another form or user'
        number, _ = self._compound('health-baseline', context, [c[0] for c in captured],
                                   {'inventory': inventory.number, 'begin': begin.number,
                                    'end': end.number if end is not None else None},
                                   status, reason, brackets, {'projection': _side(projection)},
                                   extra={'user': user, 'serial': serial,
                                          'projection': _side(projection) if status == 'facts' else None})
        if status == 'stopped':
            raise Stopped(reason)
        return number

    def _retain_records(self, m):
        """The exact store records a crossing names, kept by digest in the broker's records: the ticket
        and the plan, whose bytes must hash to the digests the crossing carries, its grant, and the
        component's selection as they stand. Returns (digests by name, or why the crossing is refused)."""
        store = Path(self.admission['store'])
        names = [('ticket', 'tickets', m['ticket']), ('plan', 'plans', m['plan']),
                 ('selection', 'selections', self.admission['component'])]
        if m['grant'] != proto.ZERO_ID:
            names.append(('grant', 'authorizations', m['grant']))
        found = {}
        for label, directory, ident in names:
            data = _regular_bytes(store / directory / (ident + STORE_SUFFIX))
            if data is None:
                return found, 'the stored %s cannot be read whole' % label
            digest = hashlib.sha256(data).hexdigest()
            if label in ('ticket', 'plan') and digest != m[label + '_digest']:
                return found, 'the stored %s is not the record the crossing names' % label
            self._keep(digest, data)
            found[label] = digest
        return found, None

    def _keep(self, digest, data, where=RECORDS):
        """Keeps one record under its digest, or checks the one already there. A new one is written
        whole to a fresh temporary name, synced, read back and compared, and only then renamed into
        place, so a short or failed write never leaves bytes under the record's name. Retained store
        records and action specs live in `records`, compound manifests in `compound`."""
        if hashlib.sha256(data).hexdigest() != digest:
            raise BrokerError('a record does not hash to the digest it is kept under')
        directory = self.root / where
        path = directory / digest
        if not os.path.lexists(directory):
            directory.mkdir(mode=0o700)
        # The broker root holds the records directory's name: synced every time, so a sync that an
        # earlier call could not finish is never skipped.
        _sync_directory(self.root)
        if os.path.lexists(path):
            if _regular_bytes(path) != data:
                raise BrokerError('a retained record differs from its digest')
            # A name found here may come from a rename whose directory sync never ran: sync it now.
            _sync_directory(directory)
            return
        temporary = directory / ('.%s.%s' % (digest, os.urandom(8).hex()))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise BrokerError('a retained record could not be written whole')
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if _regular_bytes(temporary) != data:
            raise BrokerError('a retained record did not read back whole')
        os.rename(temporary, path)
        _sync_directory(directory)
        if _regular_bytes(path) != data:
            raise BrokerError('a retained record differs after it was kept')

    def pin_artifacts(self, plan, members, publication=None):
        """Pins one plan's bundle members: each member's host path, SHA-256 and size. The guest
        paths follow from the admitted staging directory. Under a version 3 admission, and only
        then, the pin also names the SHA-256 of the plan's publication record, which a health
        composition binds."""
        if not _hex(plan, 16) or plan == proto.ZERO_ID:
            raise BrokerError('a plan ID')
        if (publication is not None) != (self.admission['version'] == 3) or (
                publication is not None and (not _hex(publication, 32) or publication == proto.ZERO_DIGEST)):
            raise BrokerError("a version 3 pin names its plan's publication digest, and only a version 3 pin")
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
            if self.pinned[plan] != pinned or self.publications.get(plan) != publication:
                raise BrokerError('a plan is pinned once')
            return
        record = {'plan': plan, 'members': pinned}
        if publication is not None:
            record['publication'] = publication
        self.ledger.record('artifacts', record)
        self.pinned[plan] = pinned
        if publication is not None:
            self.publications[plan] = publication

    def _target_scope(self, context):
        """The native target scope as it stands now. A target that cannot be read, or reads as no
        known scope, is UNKNOWN: never established. A recorded target read can only narrow the
        admitted scope: an admission that is not established empty stands whatever the read says."""
        if self._target_read:
            group = self._group('target', self.reader.target, dict(context, purpose='target'), None, emitted=False)
            read = group.reading['scope'] if group.ok else 'UNKNOWN'
            admitted = self.admission['target_scope']
            return read if admitted == 'ESTABLISHED_EMPTY' else admitted
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

    def _require_shell2(self, context, bound_ns=None):
        """Once in each broker's lifetime, before its first guest command: the device must offer
        shell protocol v2. A definite answer without it latches a stop. An answer that cannot be read
        launches nothing and is asked again before the next command. Under the first command's launch
        deadline, `bound_ns`, the query is refused once that has passed, after its durable intent too,
        and is given only what is left of it."""
        if self._shell2:
            return
        command = 'host-serial:%s:features' % self.admission['serial']
        timeout = self.limits['read_timeout_s']
        gate = self._may_send(bound_ns)
        extra = {} if gate is None else {'may_send': gate}

        def call():
            allowed = timeout if bound_ns is None else min(timeout, max(0.0, (bound_ns - self._monotonic()) / 1_000_000_000))
            return self.transport.features(allowed, **extra)
        number, result = self._record_command('features', command, context, call, timeout, bound_ns)
        if result.status == 'ok' and shell_transport.FEATURE_SHELL2 in result.features:
            self._shell2 = True
            return
        if result.status == 'ok':
            self.stop('the device does not offer shell protocol v2')
            raise Stopped(self.stopped)
        error = _NotLaunched('the device features could not be read: %s' % result.status)
        error.capture, error.command = number, command
        raise error

    def _capture(self, operation, command, context, call, timeout, not_after_ns=None):
        """One guest command: the shell protocol check, then the fences, the intent synced, the call,
        then its streams and result. A launch with a deadline (an activation grant's end, or a bound)
        names the host monotonic instant from which it is refused; the feature query before a broker's
        first command keeps that deadline too."""
        self._require_shell2(context, not_after_ns)
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
        # The final launch gate, once the intent is durable: a launch whose deadline has passed since
        # the gate's clock reading (an activation grant that may have expired, or a bound) sends nothing.
        if not_after_ns is not None and self._monotonic() >= not_after_ns:
            self._not_sent(entry, command, 'the activation grant may have expired before the launch, or its bound passed')
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
        if (not_after_ns is not None and getattr(result, 'launch', None) == 'not-launched'
                and getattr(result, 'transport', None) == 'launch-deadline'):
            error = _NotLaunched('the activation grant may have expired before the service request, or its bound passed')
            error.capture, error.command = entry.number, command
            raise error
        return entry.number, result

    def _not_sent(self, entry, command, reason):
        """Ends a capture whose command was never sent, then refuses its launch."""
        self.ledger.finish_capture(entry, b'', b'', {'launch': 'not-launched', 'transport': 'not-sent',
                                                     'completion': 'not-started', 'exit': None, 'error': reason,
                                                     'ended_wall_ns': self._wall(),
                                                     'ended_monotonic_ns': self._monotonic()})
        error = _NotLaunched(reason)
        error.capture, error.command = entry.number, command
        raise error

    def _may_send(self, not_after_ns):
        """The transport's last question before a launch's service request, or None without a deadline:
        connecting and selecting the device take time too."""
        if not_after_ns is None:
            return None
        return lambda: self._monotonic() < not_after_ns

    def _shell(self, operation, command, context, timeout, stdout_max, stderr_max, not_after_ns=None, bound_ns=None):
        """One shell command. With `bound_ns`, the transport's timeout is what is left of that bound at
        the moment of the call, never more than `timeout`."""
        gate = self._may_send(not_after_ns)
        extra = {} if gate is None else {'may_send': gate}

        def call():
            allowed = timeout if bound_ns is None else min(timeout, max(0.0, (bound_ns - self._monotonic()) / 1_000_000_000))
            return self.transport.shell(command, allowed, stdout_max, stderr_max, **extra)
        return self._capture(operation, command, context, call, timeout, not_after_ns)

    # ------------------------------------------------ groups of reads

    def _group(self, name, call, context, expect_boot, emitted=True, deadline_ns=None):
        """One reader call as one group, recorded with its captures, raw digest and facts. With
        `deadline_ns`, a host monotonic instant, a command is admitted only with at least
        BOUND_COMMAND_MIN_S of it left; the deadline is then each command's launch deadline (a fresh
        broker's feature query included), refused after its durable intent and by the transport right
        before its request, and each command is given only what is left of it. A clock, target or
        typed inventory group records a reading instead of facts."""
        def project(value):
            if name == 'clock':
                return [], {'boot': value[0], 'instance': value[1], 'elapsed': value[2], 'wall': value[3]}
            if name == 'target':
                return [], {'scope': value}
            if name == 'inventory':
                return [], value
            return list(value), None
        projected, captures, status, reason = self._call_reader(name, call, context, deadline_ns, project)
        facts, frames, reading = [], [], None
        if status == 'facts':
            facts, reading = projected
        raw = readers.raw_digest([(c[1], c[2], c[3], c[4]) for c in captures]) if captures else None
        if status == 'facts':
            if name == 'clock':
                problem = self._reading_problem(reading, expect_boot)
            elif name == 'target':
                problem = None if reading['scope'] in TARGET_SCOPES else 'a target scope of no known name'
            elif name == 'inventory':
                problem = lab_actions.check_inventory(reading)
            else:
                problem = self._facts_problem(name, facts, raw, expect_boot)
            if problem is not None:
                status, reason, frames = 'refused', problem, []
            elif name not in ('clock', 'target', 'inventory'):
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

    def _call_reader(self, name, call, context, deadline_ns, project):
        """One reader call with the broker's run function bound: (its projected value, its
        captures as (number, command, exit, stdout, stderr), status, reason). The status is
        facts, stopped, unavailable or unclassified. Nothing is recorded here beyond the captures
        themselves."""
        captures = []

        def run(command):
            if not self.reader.allowed(command):
                raise readers.Unclassified('a command outside the reader allowlist: %r' % command)
            timeout = self.limits['read_timeout_s']
            if deadline_ns is not None:
                remaining = (deadline_ns - self._monotonic()) / 1_000_000_000
                if remaining < BOUND_COMMAND_MIN_S:
                    raise readers.Unavailable('too little of the bound remains for another command')
                timeout = min(timeout, remaining)
            try:
                # Within a bound, the deadline is also the command's launch deadline: refused after the
                # durable intent and by the transport right before the service request, and the
                # transport's own timeout is what the bound has left when it is called.
                number, result = self._shell('read', command, dict(context, group=name),
                                             timeout, int(self.limits['read_stdout_max']),
                                             int(self.limits['read_stderr_max']), not_after_ns=deadline_ns,
                                             bound_ns=deadline_ns)
            except _NotLaunched as error:
                # A refused capture is the group's: its own command, the feature query included.
                if getattr(error, 'capture', None) is not None:
                    captures.append((error.capture, getattr(error, 'command', command), None, b'', b''))
                raise
            if not result.completed or result.overflow is not None:
                captures.append((number, command, None, result.stdout, result.stderr))
                raise readers.Unavailable('capture %d did not complete: %s' % (number, result.completion))
            captures.append((number, command, result.exit, result.stdout, result.stderr))
            return (result.exit, result.stdout.decode('utf-8', 'surrogateescape'),
                    result.stderr.decode('utf-8', 'surrogateescape'))

        self.reader.bind(run)
        value, status, reason = None, 'facts', None
        try:
            value = project(call())
        except Stopped as error:
            status, reason = 'stopped', str(error)
        except readers.Unavailable as error:
            status, reason = 'unavailable', str(error)
        except (readers.Unclassified, ValueError, KeyError, TypeError) as error:
            status, reason = 'unclassified', '%s: %s' % (type(error).__name__, error)
        finally:
            self.reader.bind(None)
        return value, captures, status, reason

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

    def _clock_group(self, context, expect_boot=None, emitted=True, deadline_ns=None):
        return self._group('clock', self.reader.clock, context, expect_boot, emitted, deadline_ns)

    # ------------------------------------------------ the next campaign profile: compound groups

    def _capture_ref(self, number):
        """One child capture of a compound group, by its ledger entry: its operation, the digest of
        its command, and when it ended its launch, completion, exit and both streams' digests."""
        entry = self.ledger.entries[number - 1]
        intent, result = entry.content.get('intent', {}), entry.content.get('result')
        command = intent.get('command') or 'push %s' % intent.get('path')
        ref = {'capture': number, 'operation': intent.get('operation'),
               'command_sha256': hashlib.sha256(command.encode('utf-8', 'surrogateescape')).hexdigest(),
               'complete': entry.complete}
        if result is not None:
            ref.update(launch=result.get('launch'), completion=result.get('completion'), exit=result.get('exit'),
                       stdout_sha256=result['stdout_sha256'], stdout_bytes=result['stdout_bytes'],
                       stderr_sha256=result['stderr_sha256'], stderr_bytes=result['stderr_bytes'])
        return ref

    def _compound(self, reader, context, captures, children, status, reason, brackets, projection, facts=(),
                  emitted=False, extra=None):
        """Writes one compound group and returns (its ledger number, its envelopes). Its
        children, every capture and child group, are already in the ledger. Its manifest is
        written whole, synced and kept by its SHA-256 before the ledger group that names it, its
        status and its frames. An emitted fact's raw digest is the manifest's, so the manifest
        names neither its own digest nor those frames. The manifest also says whether its facts
        are emitted or only kept, as a probe that ended after its window is, so a reopening takes
        that from the manifest, never from the group. A group whose manifest has no side record
        form is unavailable and emits nothing. When the manifest cannot be written or synced, the
        failed writer first latches the broker's stop, then the group is kept unavailable with its
        reason, and no later command or effect starts. One whose status is not facts keeps its
        children and reason and emits nothing."""
        extra = dict(extra or {})
        manifest = {'schema': SCHEMAS[reader], 'profile': lab_actions.PROFILE, 'group_id': proto.fresh_id(self._ids),
                    'installation': self.admission['installation'], 'component': self.admission['component'],
                    'sources': self.admission['manifest'], 'context': dict(context), 'status': status,
                    'reason': reason, 'captures': [self._capture_ref(n) for n in captures], 'children': children,
                    'brackets': brackets, 'projection': projection, 'extra': extra,
                    'emits': [{'mode': mode, 'block': {k: list(map(list, v)) if k == 'rows' else v
                                                       for k, v in block.items()},
                               'fact': fact} for mode, fact, block in facts],
                    'emitted': bool(emitted and status == 'facts')}
        kept, failed = None, None
        try:
            data = evidence.canonical(manifest)
            digest = hashlib.sha256(data).hexdigest()
            self._keep(digest, data, COMPOUND)
            kept = {'path': '%s/%s' % (COMPOUND, digest), 'sha256': digest, 'bytes': len(data)}
        except evidence.SideError as error:
            status, reason = 'unavailable', UNKEPT + str(error)
        except (BrokerError, OSError) as error:
            status, reason = 'unavailable', UNKEPT + str(error)
            failed = self._writer_failed(reason)
        emitted = emitted and status == 'facts' and kept is not None
        out, observations = [], []
        for mode, fact, block in (facts if emitted else ()):
            frame, item = _emitted(mode, fact, kept['sha256'])
            out.append({'mode': mode, 'evidence': kept['sha256'], 'block': block, 'observation': frame})
            observations.append(item)
        record = dict(context, reader=reader, compound=kept, status=status, reason=reason, captures=list(captures),
                      children=children, brackets=brackets, observations=observations, emitted=emitted, **extra)
        number = self.ledger.record('group', record)
        if kept is not None:
            self._compound_record(dict(record, number=number))
        elif reader == 'receipts':
            self._pin_rows(record)
        if failed is not None:
            raise failed
        for envelope in out:
            envelope['group'] = number
        return number, out

    def _writer_failed(self, reason):
        """Latches the broker's stop for a failed write or sync of its own evidence, before
        anything else is recorded, and returns the Stopped to raise: no later command or effect
        starts, in this broker or after a reopening."""
        self.stop('the evidence writer failed: %s' % reason)
        return Stopped(self.stopped)

    def _check_unkept_compound(self, c):
        """Under a version 3 admission, refuses a reopening whose group has a compound writer's
        form, a compound reader or a compound group's own fields, but names no manifest, unless
        it is that writer's record of a manifest it could not keep: its reference present and
        null, unavailable with the writer's reason, and emitting nothing. Such a record restores
        nothing but first row bytes. A group that names a manifest is checked against it."""
        if c.get('compound') is not None or (c.get('reader') not in SCHEMAS
                                             and {'compound', 'children', 'brackets'}.isdisjoint(c)):
            return
        if ('compound' not in c or c.get('reader') not in SCHEMAS or c.get('status') != 'unavailable'
                or not isinstance(c.get('reason'), str) or not c['reason'].startswith(UNKEPT)
                or c.get('emitted') is not False or c.get('observations') != []):
            raise BrokerError('group %d has the form of a compound group but names no kept manifest, and is '
                              'not a record of one that could not be kept' % c['number'])

    def _check_compound(self, c):
        """Refuses a reopening whose compound group names a manifest that is missing, damaged or
        changed, or that the group does not summarize: its path, size, SHA-256 and canonical form,
        its schema, profile and scope, its context, status, reason, children, bracket and extra
        joins, its captures as the ledger holds them, and whether and what the group emitted,
        both of which only the manifest decides."""
        kept, why, data = c['compound'], None, None
        directory = self.root / COMPOUND
        name = kept.get('sha256') if isinstance(kept, dict) else None
        if (_hex(name, 32) and kept.get('path') == '%s/%s' % (COMPOUND, name) and os.path.isdir(directory)
                and not os.path.islink(directory)):
            data = _regular_bytes(directory / name, evidence.MAX_BYTES)
        if data is None or len(data) != kept.get('bytes') or hashlib.sha256(data).hexdigest() != name:
            why = 'its bytes are missing or not the ones its group names'
        else:
            try:
                why = self._compound_problem(c, evidence.parse(data))
            except evidence.SideError as error:
                why = 'it is not a canonical side record: %s' % error
            except (KeyError, TypeError, AttributeError, IndexError, ValueError) as error:
                why = 'it is of no known form: %s: %s' % (type(error).__name__, error)
        if why is not None:
            raise BrokerError('the compound manifest of group %d is damaged or changed: %s' % (c['number'], why))

    def _compound_problem(self, c, m):
        """Why a compound group's whole manifest is not the one it summarizes, or None."""
        a = self.admission
        if ((m['schema'], m['profile']) != (SCHEMAS[c['reader']], lab_actions.PROFILE) or not _hex(m['group_id'], 16)
                or m['group_id'] == proto.ZERO_ID or (m['installation'], m['component'], m['sources'])
                != (a['installation'], a['component'], a['manifest'])):
            return 'another schema, profile, group ID or scope'
        numbers = [ref['capture'] for ref in m['captures']]
        if any(type(n) is not int or not 0 < n < c['number'] or self.ledger.entries[n - 1].kind != 'capture'
               for n in numbers) or m['captures'] != [self._capture_ref(n) for n in numbers]:
            return "its captures are not the ledger's"
        # Whether the group emitted, and what, follows from the manifest alone: an emitting receipt
        # read or health probe of facts emits every fact it holds, and a kept one none.
        emits = m['emitted']
        if type(emits) is not bool or (emits and (m['status'] != 'facts'
                                                  or c['reader'] not in ('receipts', 'health'))):
            return 'an emission of no known form'
        observations = [_emitted(e['mode'], e['fact'], c['compound']['sha256'])[1] for e in m['emits']]
        summary = dict(m['context'], reader=c['reader'], compound=c['compound'], status=m['status'],
                       reason=m['reason'], captures=numbers, children=m['children'], brackets=m['brackets'],
                       observations=observations if emits else [], emitted=emits, **m['extra'])
        if summary != {k: v for k, v in c.items() if k not in ('number', 'kind')}:
            return 'its group does not summarize it'
        return None

    def _brackets(self, begin, end, boot=None):
        """A compound read's bracket from its two clock groups, or None: both read, one boot (the
        expected one when given), one running framework instance, the end not before the begin."""
        if begin is None or end is None or not begin.ok or not end.ok:
            return None
        b, e = begin.reading, end.reading
        if (b['boot'] != e['boot'] or (boot is not None and b['boot'] != boot) or b['instance'] != e['instance']
                or b['instance'] < 0 or e['elapsed'] < b['elapsed']):
            return None
        return {'boot': b['boot'], 'instance': b['instance'],
                'begin': {'group': begin.number, 'boot': b['boot'], 'instance': b['instance'], 'elapsed': b['elapsed'],
                          'wall': b['wall']},
                'end': {'group': end.number, 'boot': e['boot'], 'instance': e['instance'], 'elapsed': e['elapsed'],
                        'wall': e['wall']}}

    def _simple_envelope(self, group, fact, frame):
        return {'group': group, 'mode': proto.MODES['SIMPLE_CURRENT'], 'evidence': fact['raw'], 'block': {},
                'observation': frame}

    def _observe_2(self, m, state):
        """Version 2's observation. Each current group's facts are SIMPLE_CURRENT envelopes. For
        a ticket, the notice receipts follow as RECEIPT_EVENT envelopes and, in its health
        window, each running user's prepared full probe as a COMPOSED_HEALTH envelope. Nothing is
        cut to fit: more facts than MAX_FRAMES, or a reply above the frame bound, refuses the
        whole observation."""
        if m['component'] != self.admission['component']:
            return self._reply(m, 'REFUSED', reason='another component')
        ticket = m['scope'] == proto.SCOPES['TICKET']
        names = ['boot', 'checkpoint', 'factory', 'active'] + (['sessions', 'users'] if ticket else [])
        context = {'request': m['request'], 'generation': state['generation'], 'purpose': 'observe',
                   'ticket': m['ticket'] if ticket else None}
        envelopes, users, changed = [], None, False
        try:
            for name in names:
                if name == 'users':
                    call = lambda: self.reader.users(sorted(self.users_seen.values()))  # noqa: E731
                else:
                    call = getattr(self.reader, name)
                group = self._group(name, call, context, m['boot'])
                envelopes += [self._simple_envelope(group.number, f, frame) for f, frame in zip(group.facts, group.frames)]
                if name == 'users' and group.ok:
                    users = group.facts
                if group.status == 'refused' and group.reason == 'the boot changed':
                    changed = True
                    break
            if ticket and not changed and self.reader.receipts_admitted:
                envelopes += self._receipt_group(m, context)
            if (ticket and not changed and m['state'] == HEALTH_WINDOW_STATE and self.reader.health_admitted
                    and users is not None):
                envelopes += self._health_groups(m, context, users)
        except Stopped as error:
            return self._reply(m, 'STOPPED', reason=str(error))
        if len(envelopes) > proto.MAX_FRAMES:
            return self._reply(m, 'REFUSED', reason='the observation holds %d facts, above its bound of %d: none is cut'
                               % (len(envelopes), proto.MAX_FRAMES))
        reply = self._reply(m, 'OK', envelopes=envelopes)
        try:
            proto.encode(reply, self.protocol)
        except proto.ProtocolError as error:
            return self._reply(m, 'REFUSED', reason='the observation does not fit one frame: %s' % error)
        return reply

    # ------------------------------------------------ receipts past the clock guard

    def _receipt_group(self, m, context):
        """One whole read of the notice fixture's provider between two clock reads of one boot
        and one framework instance, as a compound receipt read. A row becomes a RECEIPT_EVENT
        only with its issued notice, its unchanged first bytes and its first qualified visibility
        group, completed before the read ended. Its time is that group's completion, the first
        proven delivery, never the row's own candidate time and never the read's time. The read's
        bracket, not the event, moves the clock scale. A row of another ticket, boot or purpose,
        or one without a qualified visibility yet, is kept and gives nothing. A contrary row
        refuses the whole group, wherever it stands in the read. Every row of a whole read keeps
        its first bytes all the same: one that emits, one that is refused, and one whose bracket
        did not complete."""
        context = dict(context, purpose='receipt-read')
        begin = self._clock_group(dict(context, part='begin'), m['boot'], emitted=False)
        rows, captures, status, reason, end, judged = None, [], 'unavailable', 'the read bracket did not begin', None, []
        if begin.ok:
            rows, captured, status, reason = self._call_reader(
                'receipts', lambda: self.reader.receipt_rows(m['ticket']), context, None, list)
            captures = [c[0] for c in captured]
            if status == 'facts':
                end = self._clock_group(dict(context, part='end'), m['boot'], emitted=False)
        brackets = self._brackets(begin, end, m['boot'])
        if status == 'facts' and brackets is None:
            status, reason = 'unavailable', 'the read bracket changed or did not complete'
            judged, _ = self._judge_rows(m, rows, None)
        if status == 'facts':
            judged, problem = self._judge_rows(m, rows, brackets)
            if problem is not None:
                status, reason = 'refused', problem
        facts = []
        for row in judged if status == 'facts' else ():
            if row['judgment'] != 'EMITTED':
                continue
            proof = row['proof']
            fact = {'installation': self.admission['installation'], 'observation': proto.fresh_id(self._ids),
                    'component': self.admission['component'], 'boot': brackets['boot'], 'user': row['user'],
                    'serial': row['serial'], 'kind': 'RECEIPT', 'route': 'SHELL', 'instance': brackets['instance'],
                    'elapsed': proof['proven_elapsed'], 'wall': proof['wall'], 'classification': 'FULL_SCREEN',
                    'facts': {'ticket': m['ticket'], 'index': row['index']}}
            block = {'read_boot': brackets['boot'], 'read_instance': brackets['instance'],
                     'read_begin_elapsed': brackets['begin']['elapsed'], 'read_end_elapsed': brackets['end']['elapsed'],
                     'plan': m['plan'], 'ticket': m['ticket'], 'notice_index': row['index'],
                     'issue_ticket_digest': row['issue_ticket_digest'], 'event': row['event'], 'row': row['sha256'],
                     'delivery_group': proof['delivery_group'], 'delivery_instance': proof['delivery_instance'],
                     'delivery_begin': proof['delivery_begin'], 'proven_elapsed': proof['proven_elapsed'],
                     'delivery_end': proof['delivery_end']}
            facts.append((proto.MODES['RECEIPT_EVENT'], fact, block))
        children = {'begin': begin.number, 'end': end.number if end is not None else None}
        _, envelopes = self._compound('receipts', context, captures, children, status, reason, brackets,
                                      {'rows': judged}, facts, emitted=True, extra={'rows': judged})
        if status == 'stopped':
            raise Stopped(reason)
        return envelopes

    def _row_problem(self, row):
        """Why a provider row's projection is of no known form, or None."""
        if not isinstance(row, dict) or set(row) != set(ROW_KEYS):
            return 'a row has exactly its fields'
        if not isinstance(row['row'], (bytes, bytearray)) or not 1 <= len(row['row']) <= proto.MAX_RECORD:
            return 'a row is its whole bytes'
        if row['purpose'] not in ('TICKET_NOTICE', 'QUALIFICATION'):
            return 'a row of no known purpose'
        for name in ('installation', 'boot', 'event'):
            if not _hex(row[name], 16) or row[name] == proto.ZERO_ID:
                return 'a row names its installation, boot and event'
        if not _hex(row['text_sha256'], 32) or not isinstance(row['component'], str):
            return 'a row names its component and text digest'
        for name in ('uid', 'user', 'serial'):
            if type(row[name]) is not int or row[name] < 0:
                return 'a row names its app UID, user and serial'
        if row['candidate_elapsed'] is not None and (type(row['candidate_elapsed']) is not int
                                                     or row['candidate_elapsed'] < 0):
            return 'a row candidate time is a nonnegative integer'
        notice = row['purpose'] == 'TICKET_NOTICE'
        if notice != (row['control'] is None) or (row['control'] is not None and not _hex(row['control'], 16)):
            return 'a row names a notice or a control action, not both'
        for name in ('plan', 'ticket'):
            if notice != (row[name] is not None) or (notice and (not _hex(row[name], 16) or row[name] == proto.ZERO_ID)):
                return 'only a ticket notice row names its plan and ticket'
        if notice != (row['index'] is not None) or (notice and (type(row['index']) is not int
                                                                or not 0 <= row['index'] < proto.MAX_LEDGER)):
            return 'only a ticket notice row names its notice index'
        return None

    def _judge_rows(self, m, rows, brackets):
        """Each row's judgment, and the reason the first contrary row refuses the group, or None.
        A row of this ticket must name a notice the broker issued, of the issue's installation,
        component, plan, boot, event and text, for a user the issue required, once in the read and
        with its first bytes. Judgment goes on past a contrary row, so that every row the read
        holds keeps its first bytes, though nothing of a refused read is emitted. Without a
        bracket, a row is judged only that far, so that its first bytes are kept."""
        judged, keys, refusal = [], set(), None

        def contrary(item, reason):
            nonlocal refusal
            item['judgment'] = 'CONTRARY'
            refusal = refusal or reason
        for row in rows:
            problem = self._row_problem(row)
            if problem is not None:
                data = row.get('row') if isinstance(row, dict) else None
                whole = isinstance(data, (bytes, bytearray))
                judged.append({'sha256': hashlib.sha256(bytes(data)).hexdigest() if whole else None,
                               'bytes': len(data) if whole else None, 'key': None, 'judgment': None,
                               'proof': None, 'issue': None, 'issue_ticket_digest': None})
                contrary(judged[-1], 'a provider row of no known form: %s' % problem)
                continue
            sha = hashlib.sha256(bytes(row['row'])).hexdigest()
            item = {'sha256': sha, 'bytes': len(row['row']), 'key': None, 'judgment': None, 'proof': None,
                    'issue': None, 'issue_ticket_digest': None}
            item.update({k: row[k] for k in ROW_KEYS if k != 'row'})
            judged.append(item)
            if row['purpose'] == 'QUALIFICATION':
                item['judgment'] = 'QUALIFICATION'
                continue
            if row['ticket'] != m['ticket']:
                item['judgment'] = 'OTHER_TICKET'
                continue
            issue = self.issues.get((row['ticket'], row['index']))
            if issue is None:
                contrary(item, 'a row of this ticket names a notice that was never issued')
                continue
            item['issue'], item['issue_ticket_digest'] = issue['number'], issue['ticket_sha256']
            if ((row['installation'], row['component'], row['plan']) != (self.admission['installation'],
                                                                         self.admission['component'], issue['plan'])
                    or row['plan'] != m['plan']):
                contrary(item, 'a row of another installation, component or plan than its notice')
                continue
            if row['boot'] != issue['boot']:
                contrary(item, "a row whose boot token is not its notice's boot")
                continue
            if (row['event'], row['text_sha256']) != (issue['challenge'], issue['text_sha256']):
                contrary(item, "a row whose event or text is not its notice's")
                continue
            if (row['user'], row['serial']) not in {(r['user'], r['serial']) for r in issue['required']}:
                contrary(item, 'a row of a user the notice was not owed to')
                continue
            key = '%s/%s/%s/%d/%d/%d' % (row['purpose'], row['boot'], row['ticket'], row['index'], row['user'],
                                         row['serial'])
            if key in keys:
                contrary(item, 'two rows of one notice and user in one read')
                continue
            keys.add(key)
            item['key'] = key
            if self.rows_seen.get(key, sha) != sha:
                contrary(item, 'a row changed after it was first read')
                continue
            if brackets is None:
                item['judgment'] = 'UNBRACKETED'
                continue
            if issue['boot'] != brackets['boot']:
                item['judgment'] = 'OTHER_BOOT'
                continue
            proof = self.proofs.get(key) or self._first_visibility(issue, row, brackets)
            if proof is None:
                item['judgment'] = 'NO_VISIBILITY'
                continue
            if not (issue['entry_elapsed'] <= proof['proven_elapsed'] <= proof['delivery_end']
                    <= brackets['end']['elapsed'] and proof['delivery_instance'] <= brackets['instance']):
                contrary(item, 'a receipt event outside its issue, its delivery or its read')
                continue
            item['judgment'], item['proof'] = 'EMITTED', proof
        return judged, refusal

    def _first_visibility(self, issue, row, brackets):
        """The first qualified visibility of a notice for one recipient in this boot, completed
        before the current read ended, as a proof: the delivery group's manifest digest and
        bracket, and the proven time, its completion. A later qualified group never replaces the
        first."""
        for group in self.visibility.get((issue['ticket'], issue['index'], row['serial']), ()):
            if (group['qualified'] and group['issue'] == issue['number'] and group['user'] == row['user']
                    and group['brackets']['boot'] == brackets['boot']
                    and group['brackets']['end']['elapsed'] <= brackets['end']['elapsed']):
                end = group['brackets']['end']
                return {'delivery_group': group['compound']['sha256'], 'group': group['number'],
                        'delivery_instance': group['brackets']['instance'],
                        'delivery_begin': group['brackets']['begin']['elapsed'], 'delivery_end': end['elapsed'],
                        'proven_elapsed': end['elapsed'], 'wall': end['wall']}
        return None

    # ------------------------------------------------ full health compositions

    def _store_window(self, m):
        """The ticket's health window from the admitted store's own records: (window, None) or
        (None, why). The ticket and plan must be the observation's, of this installation and
        component, the ticket in HEALTH_WINDOW and the plan declaring every criterion."""
        store = Path(self.admission['store'])
        try:
            ticket = records.decode_ticket(_regular_bytes(store / 'tickets' / (m['ticket'] + STORE_SUFFIX)) or b'')
            plan = records.decode_plan(_regular_bytes(store / 'plans' / (m['plan'] + STORE_SUFFIX)) or b'')
        except records.RecordError as error:
            return None, "the ticket's window cannot be read from the store: %s" % error
        a = self.admission
        if ((ticket['ticket'], ticket['plan'], ticket['installation'], ticket['component'])
                != (m['ticket'], m['plan'], a['installation'], a['component'])
                or (plan['plan'], plan['installation'], plan['component']) != (m['plan'], a['installation'], a['component'])):
            return None, 'the stored ticket or plan is not the observation\'s'
        if ticket['state'] != 'HEALTH_WINDOW' or plan['criteria'] != proto.CRITERIA_ALL:
            return None, 'the stored ticket is not in a health window of every criterion'
        start = ticket['windowStart']
        return {'boot': ticket['windowBoot'], 'start': start, 'end': start + plan['healthWindow']}, None

    def _fresh_preparations(self, user, serial, window):
        """The settled preparations of one user in the window's boot, begun at or after its start
        and not used by any probe, in ledger order."""
        fresh = []
        for operation, prep in sorted(self.preparations.items(), key=lambda item: item[1]['end']['number']):
            resolved, interval = prep['begin']['resolved_user'], prep['end']['outcome']['interval']
            if (operation not in self.used_preparations and (resolved['id'], resolved['serial']) == (user, serial)
                    and interval['boot'] == window['boot'] and interval['begin'] >= window['start']):
                fresh.append(prep)
        return fresh

    def _health_groups(self, m, context, users):
        """A prepared full probe of each running user that this observation's whole listing
        shows. No preparation, no probe: an unprepared user gives nothing, which leaves a gap,
        never a claim."""
        window, why = self._store_window(m)
        if window is None or window['boot'] != m['boot']:
            self._compound('health', dict(context, purpose='health'), [], {}, 'refused',
                           why or "the window is of another boot than the round's", None, {}, extra={
                               'preparations': [], 'user': None, 'serial': None})
            return []
        envelopes = []
        running = sorted({(f['user'], f['serial']) for f in users
                          if f['classification'] in ('RUNNING_UNLOCKED', 'RUNNING_LOCKED')})
        for user, serial in running:
            fresh = self._fresh_preparations(user, serial, window)
            if fresh:
                envelopes += self._health_group(m, context, window, user, serial, fresh)
        return envelopes

    def _baseline(self, boot, user, serial, window, instance):
        """The last good baseline of one user in this boot that completed by the window's start,
        in the current read's framework instance, or None. A baseline read after the window
        opened is never one, and a later framework instance invalidates it: the continuity it
        witnesses is lost."""
        found = None
        for group in self.baselines.get((boot, user, serial), ()):
            if group['brackets']['end']['elapsed'] <= window['start']:
                found = group
        if found is None or found['brackets']['instance'] != instance:
            return None
        return found

    def _health_group(self, m, context, window, user, serial, fresh):
        """One user's full probe: fresh current reads by the admitted composer between two clock
        reads, joined to the preparations it used and the baseline it relied on. The broker
        checks each row and only ever lowers it to UNKNOWN: a HELD or BAD row needs the current
        reads it judged; a no crash or ANR row needs an admitted witness reader, HELD a valid
        baseline and no witness decision, BAD a qualified witness; a UI marker, unlock or native
        work row needs a fresh preparation of that criterion in the read's framework instance that
        began in the window and ended before the read, within its maximum probe width. The
        classification follows the rows. Every preparation offered to a probe that began is used
        up by it, whatever its rows or its manifest give. A probe that ends after the window is
        kept as evidence outside the window and emits nothing."""
        context = dict(context, purpose='health', user=user, serial=serial)
        offered = [{'operation': p['begin']['operation'], 'criteria': p['begin']['parameters']['criteria'],
                    'challenge': p['begin']['challenge'], 'max_probe_ms': p['begin']['parameters']['max_probe_ms'],
                    'instance': p['end']['outcome']['interval']['instance'],
                    'begin': p['end']['outcome']['interval']['begin'], 'end': p['end']['outcome']['interval']['end'],
                    'action_end': p['end']['number']} for p in fresh]
        # The begin bracket's own group names the preparations offered to the composer. Once it is
        # read they are used, whatever becomes of the probe's reads, rows or manifest, and a
        # reopening restores that use from the same group.
        begin = self._clock_group(dict(context, part='begin', offered=[p['operation'] for p in offered]), m['boot'],
                                  emitted=False)
        if begin.ok:
            self.used_preparations.update(p['operation'] for p in offered)
        status, reason, candidate, captured, end = 'unavailable', 'the read bracket did not begin', None, [], None
        baseline = None
        if begin.ok:
            baseline = self._baseline(m['boot'], user, serial, window, begin.reading['instance'])
            reader_context = {'ticket': m['ticket'], 'plan': m['plan'], 'user': user, 'serial': serial,
                              'window': dict(window), 'preparations': offered,
                              'baseline': None if baseline is None else {'digest': baseline['compound']['sha256'],
                                                                         'projection': baseline['projection']},
                              'active_apk': self._pinned_apk(m['plan'])}
            candidate, captured, status, reason = self._call_reader(
                'health', lambda: self.reader.health_composition(reader_context), context, None, lambda v: v)
            if status == 'facts':
                end = self._clock_group(dict(context, part='end'), m['boot'], emitted=False)
        captures = [c[0] for c in captured]
        brackets = self._brackets(begin, end, m['boot'])
        if status == 'facts' and brackets is None:
            status, reason = 'unavailable', 'the read bracket changed or did not complete'
        rows, used, problem = None, [], None
        if status == 'facts':
            rows, used, problem = self._health_rows(candidate, user, serial, captures, offered, baseline, brackets)
            if problem is not None:
                status, reason = 'unclassified', problem
        facts, emitted, extra = [], status == 'facts', {'user': user, 'serial': serial, 'preparations': []}
        if begin.ok:
            # The probe's assignment: every preparation its composer was given.
            extra['preparations'] = [p['operation'] for p in offered]
        if status == 'facts':
            probe_begin = min([brackets['begin']['elapsed']] + [p['begin'] for p in used])
            probe_end = brackets['end']['elapsed']
            if probe_end > window['end']:
                emitted, reason = False, 'the probe ended after its window: evidence outside the window'
            statuses = [row['status'] for row in rows]
            classification = proto.health_classification(proto.ROW_STATUSES[s] for s in statuses)
            names = {code: name for name, code in proto.HEALTH_CLASSIFICATIONS.items()}
            baseline_digest = (baseline['compound']['sha256'] if rows[proto.NO_CRASH_OR_ANR]['baseline'] is not None
                               else evidence.digest({'baseline': None, 'boot': m['boot'], 'user': user,
                                                     'serial': serial}))
            fact = {'installation': self.admission['installation'], 'observation': proto.fresh_id(self._ids),
                    'component': self.admission['component'], 'boot': brackets['boot'], 'user': user,
                    'serial': serial, 'kind': 'HEALTH', 'route': 'SHELL', 'instance': brackets['instance'],
                    'elapsed': probe_end, 'wall': brackets['end']['wall'], 'classification': names[classification],
                    'facts': {'count': proto.CRITERIA_ALL}}
            block = {'read_boot': brackets['boot'], 'read_instance': brackets['instance'],
                     'read_begin_elapsed': brackets['begin']['elapsed'], 'read_end_elapsed': probe_end,
                     'plan': m['plan'], 'ticket': m['ticket'], 'window_boot': window['boot'],
                     'window_start': window['start'], 'publication': self._pinned_publication(m['plan']),
                     'active_apk': self._pinned_apk(m['plan']), 'baseline': baseline_digest,
                     'preparation_root': evidence.digest({'preparations': used}), 'probe_begin': probe_begin,
                     'probe_end': probe_end, 'criteria': proto.CRITERIA_ALL,
                     'rows': tuple((row['bit'], proto.ROW_STATUSES[row['status']], evidence.digest(row))
                                   for row in rows)}
            if block['publication'] is None or block['active_apk'] is None:
                emitted, reason = False, 'the plan has no pinned publication: no window fact is placed'
            else:
                facts.append((proto.MODES['COMPOSED_HEALTH'], fact, block))
        _, envelopes = self._compound('health', context, captures,
                                      {'begin': begin.number, 'end': end.number if end is not None else None},
                                      status, reason, brackets,
                                      {'purpose': 'TICKET_WINDOW', 'candidate': _side(candidate), 'rows': rows,
                                       'offered': offered, 'window': window}, facts, emitted=emitted, extra=extra)
        if status == 'stopped':
            raise Stopped(reason)
        return envelopes

    def _health_rows(self, candidate, user, serial, captures, offered, baseline, brackets):
        """The composer's seven rows as the broker accepts them, the preparations they used, or
        why the candidate is of no known form. Each row's child is its judged captures, its
        preparation or baseline, its reason and, for a witnessed failure, the witness."""
        if (not isinstance(candidate, dict) or set(candidate) != {'user', 'serial', 'rows', 'witness'}
                or (candidate['user'], candidate['serial']) != (user, serial)):
            return None, [], 'a composition of another form or user'
        rows = candidate['rows']
        if not isinstance(rows, list) or len(rows) != proto.CRITERIA:
            return None, [], 'a composition has seven rows'
        witness = candidate['witness']
        if witness is not None and (not isinstance(witness, dict) or witness.get('decision') not in WITNESS_DECISIONS):
            return None, [], 'a witness of no known decision'
        offers = {p['operation']: p for p in offered}
        accepted, used = [], []
        for bit, row in enumerate(rows):
            if (not isinstance(row, dict) or set(row) != set(HEALTH_ROW_KEYS) or row['bit'] != bit
                    or row['status'] not in proto.ROW_STATUSES or not _side_text(row['reason'])
                    or not isinstance(row['commands'], list)
                    or any(type(i) is not int or not 0 <= i < len(captures) for i in row['commands'])):
                return None, [], 'criterion row %d of no known form' % bit
            status, why = row['status'], row['reason']
            prep, base = None, None
            # A row names only the reference its criterion can use: a baseline for no crash or ANR,
            # a preparation for the UI marker, unlock and native work, nothing for the others.
            uses = 'baseline' if bit in BASELINE_CRITERIA else 'preparation' if bit in lab_actions.PREPARED_CRITERIA else None
            if any(row[name] is not None for name in ('baseline', 'preparation') if name != uses):
                return None, [], 'criterion row %d names a preparation or baseline it does not use' % bit
            if status != 'UNKNOWN' and not row['commands']:
                status, why = 'UNKNOWN', 'no current read of this criterion'
            if uses == 'baseline' and status != 'UNKNOWN':
                if not self.reader.witness_admitted:
                    status, why = 'UNKNOWN', 'no witness reader is admitted, so failure coverage is unknown'
                elif status == 'BAD' and (witness is None or not witness['decision'].startswith('QUALIFIED_')):
                    status, why = 'UNKNOWN', 'a failure without a qualified witness'
                elif status == 'HELD' and witness is not None:
                    status, why = 'UNKNOWN', 'a %s witness decision leaves the row in doubt' % witness['decision']
                elif status == 'HELD' and (baseline is None or row['baseline'] != baseline['compound']['sha256']):
                    status, why = 'UNKNOWN', 'no valid baseline from before the window in this framework instance'
                elif status == 'HELD':
                    base = baseline['compound']['sha256']
            elif uses == 'preparation' and status != 'UNKNOWN':
                offer = offers.get(row['preparation'])
                if (offer is None or bit not in offer['criteria'] or offer['end'] > brackets['begin']['elapsed']
                        or offer['instance'] != brackets['instance']
                        or brackets['end']['elapsed'] - offer['begin'] > offer['max_probe_ms']):
                    status, why = 'UNKNOWN', ('no fresh preparation of this criterion in this framework within '
                                              'the probe width')
                else:
                    prep = offer
            if prep is not None and prep not in used:
                used.append(prep)
            accepted.append({'bit': bit, 'status': status, 'reason': why if status != 'HELD' else '',
                             'children': [self._capture_ref(captures[i]) for i in row['commands']],
                             'preparation': prep and prep['operation'], 'baseline': base,
                             'witness': _side(witness) if bit == proto.NO_CRASH_OR_ANR and status == 'BAD' else None})
        return accepted, used, None

    def _pinned_apk(self, plan):
        pinned = self.pinned.get(plan)
        return pinned['base.apk']['sha256'] if pinned else None

    def _pinned_publication(self, plan):
        return self.publications.get(plan)

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
                request = proto.decode(data, self.protocol)
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
                self._write_reply(wfile, proto.encode(reply, self.protocol))
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
                                        'reason': 'the generation ended during the host call',
                                        'wall_ns': self._wall(), 'monotonic_ns': self._monotonic()})
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
        layout = proto.bodies(self.protocol)[kind]
        body = {name: None for name, _ in layout}
        body.update(status=proto.STATUSES[status], reason='' if status == 'OK' else fields.pop('reason', status))
        defaults = {'u8': 0, 'u16': 0, 'u32': 0, 'i32': 0, 'i64': 0, 'id': proto.ZERO_ID, 'd32': proto.ZERO_DIGEST,
                    'text': '', 'blob': b'', 'frames': [], 'codes': [], 'envelopes': []}
        for name, field in layout:
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
        try:
            scope = self._target_scope({'request': m['request'], 'generation': state['generation'], 'purpose': 'hello'})
        except Stopped as error:
            state['stopped_sent'] = True
            return self._reply(m, 'STOPPED', reason=str(error))
        return self._reply(m, 'OK', generation=state['generation'], target=proto.TARGETS[scope])

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
        if self.protocol == proto.VERSION_2:
            return self._observe_2(m, state)
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
        # The broker's own host times: a BEGIN's come before the host effect, an END's after it.
        common = {'ticket': m['ticket'], 'index': m['index'], 'plan': m['plan'], 'attempt': m['attempt'],
                  'crossing': name, 'occurrence': m['occurrence'], 'reference': m['reference'],
                  'request': m['request'], 'generation': state['generation'], 'wall_ns': self._wall(),
                  'monotonic_ns': self._monotonic()}
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
        # Under a version 2 or 3 admission the exact records the crossing names are kept first; a
        # crossing whose stored records cannot be kept or differ launches nothing and consumes no
        # cell.
        retained, refusal = {}, None
        if self.admission['version'] in (2, 3):
            try:
                retained, refusal = self._retain_records(m)
            except (BrokerError, OSError) as error:
                refusal = 'the crossing records cannot be retained: %s' % error
        cell = None
        if refusal is None:
            cell = self._match('cross', plan=m['plan'], attempt=m['attempt'], crossing=name, occurrence=m['occurrence'])
        if cell is not None:
            self.consumed.add(cell['cell'])
        fields = {k: m[k] for k in ('ticket', 'ticket_digest', 'plan', 'plan_digest', 'attempt', 'index', 'occurrence',
                                    'entry_boot', 'entry_instance', 'entry_elapsed', 'grant', 'reference', 'bundle_apk',
                                    'actor', 'granted', 'window')}
        number = self.ledger.record('crossing', dict(fields, crossing=name, native=list(m['native']),
                                                     request=m['request'], generation=state['generation'],
                                                     cell=cell and cell['cell'], records=retained))
        self.crossed.add(key)
        self.open_crossings[number] = m
        captures = []
        try:
            self._fence()
            self._verify_sources()
            if refusal is not None:
                reason = '%s: nothing launched' % refusal
                self._outcome(number, 'NO_REPLY', captures, None, None, reason)
                return self._reply(m, 'NO_REPLY', record=number, reason=reason)
            if cell is not None and cell['mode'] == 'loss-before':
                fault = self.ledger.record('fault', {'cell': cell['cell'], 'on': 'cross', 'crossing': number,
                                                     'decision': 'halt-before-effect', 'launched': False,
                                                     'captures': []})
                self._outcome(number, 'HALT', captures, None, cell, 'admitted loss before the effect', fault=fault)
                return self._reply(m, 'HALT', record=number, reason='admitted loss before the effect')
            # The admitted launch set is a fence of its own, whatever the fault schedule holds.
            if name not in self._launches:
                reason = 'the crossing is not admitted to launch on this guest: nothing launched'
                self._outcome(number, 'NO_REPLY', captures, None, cell, reason)
                return self._reply(m, 'NO_REPLY', record=number, reason=reason)
            # A version 3 admission also caps each crossing's effects, counted from the ledger.
            capped = self._crossing_cap(name) if self.admission['version'] == 3 else None
            if capped is not None:
                reason = '%s: nothing launched' % capped
                self._outcome(number, 'NO_REPLY', captures, None, cell, reason)
                return self._reply(m, 'NO_REPLY', record=number, reason=reason)
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
            scope = self._target_scope(context)
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
        if self.admission['version'] == 3:
            return self._notice_issued(m, context, captures, elapsed, instance, deadline, crossing)
        return self._notice(m, context, captures, elapsed, instance, deadline)

    def _notice_issued(self, m, context, captures, elapsed, instance, deadline, crossing):
        """The next profile's notice. Before any presentation the broker records its issue: the
        stored ticket and grant the crossing retained, the required recipients from a whole typed
        inventory, a fresh unpredictable challenge and the SHA-256 of the exact text. Only the
        lab operator's ACTIVATE is admitted, so the system user stands in for the owner and needs
        no notice. The adapter then presents that issue with its fixed commands, each sent only
        before the grant's launch deadline. Its reply says the fixture accepted the request,
        never that a user saw it."""
        if m['actor'] != proto.ACTORS['LAB_OPERATOR']:
            return None, None, "this profile admits a notice only under the lab operator's ACTIVATE: nothing launched"
        if not self.reader.inventory_admitted:
            return None, None, 'no typed user inventory is admitted: nothing launched'
        inventory = self._group('inventory', self.reader.inventory, dict(context, purpose='notice-inventory'), None,
                                emitted=False, deadline_ns=deadline)
        if not inventory.ok:
            return None, None, 'the user inventory is unavailable (%s): nothing launched' % inventory.reason
        required, why = lab_actions.notice_recipients(inventory.reading)
        if required is None:
            return None, None, '%s: nothing launched' % why
        if not required:
            return None, None, 'the whole inventory shows no user owed the notice: nothing launched'
        retained = self.ledger.entries[crossing - 1].content['records']
        challenge = proto.fresh_id(self._ids)
        text = NOTICE_TEXT % (self.admission['component'], challenge, m['ticket'], m['index'])
        issue = {'crossing': crossing, 'request': m['request'], 'generation': context['generation'],
                 'purpose': 'TICKET_NOTICE', 'installation': self.admission['installation'],
                 'component': self.admission['component'], 'ticket': m['ticket'], 'plan': m['plan'], 'attempt': m['attempt'],
                 'index': m['index'], 'ticket_sha256': retained.get('ticket'), 'grant_sha256': retained.get('grant'),
                 'actor': 'LAB_OPERATOR', 'boot': m['entry_boot'], 'entry_instance': m['entry_instance'],
                 'entry_elapsed': m['entry_elapsed'], 'challenge': challenge, 'text': text,
                 'text_sha256': hashlib.sha256(text.encode('ascii')).hexdigest(), 'required': required,
                 'inventory': inventory.number}
        number = self.ledger.record('notice-issue', issue)
        issue = dict(issue, number=number, kind='notice-issue')
        self.issues[(m['ticket'], m['index'])] = issue
        replies = []

        def run(command):
            if not self.notice.allowed(command):
                raise readers.Unclassified('a command outside the notice allowlist')
            launched, result = self._shell('notice', command, dict(context, issue=number),
                                           self.limits['mutation_timeout_s'], int(self.limits['reply_stdout_max']),
                                           int(self.limits['reply_stderr_max']), deadline)
            captures.append(launched)
            replies.append((command, result.exit, result.stdout, result.stderr))
            return result

        try:
            classification = self.notice.present(run, dict(issue))
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

    @staticmethod
    def _may_have_launched(entry):
        """Whether a capture's command may have run: a whole intent and no result, or a result
        that is not a refusal before the launch. A capture without a whole intent never launched."""
        if entry.state == 'interrupted':
            return True
        return entry.complete and entry.content['result'].get('launch') != 'not-launched'

    def _crossing_cap(self, name):
        """Why a version 3 admission's effect limit refuses one more crossing of a name, or None.
        The crossings of that name whose effect commands may have launched, completed or
        interrupted, are counted from the ledger's captures, never from replies; a REBOOT also
        counts against the boot policy's activation services."""
        names = {e.number: e.content['crossing'] for e in self.ledger.entries if e.kind == 'crossing' and e.complete}
        effective, services = set(), 0
        for e in self.ledger.entries:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if (intent and intent.get('operation') in ('mutation', 'push', 'reboot', 'notice')
                    and intent.get('crossing') in names and self._may_have_launched(e)):
                effective.add(intent['crossing'])
                services += intent['operation'] == 'reboot'
        limit = self.admission['effect_limits']['crossings'][name]
        if sum(1 for number in effective if names[number] == name) >= limit:
            return 'the admitted limit of %d %s crossings with an effect is reached' % (limit, name)
        allowed = self.admission['boot_policy']['activation_services']
        if name == 'REBOOT' and services >= allowed:
            return 'the admitted %d activation services are spent' % allowed
        return None

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
