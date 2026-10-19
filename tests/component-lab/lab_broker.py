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
import re
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
import full_users  # noqa: E402
import health_baseline  # noqa: E402
import health_compose  # noqa: E402
import health_records  # noqa: E402
import lab_actions  # noqa: E402
import lab_crossings as crossings  # noqa: E402
import lab_evidence as evidence  # noqa: E402
import lab_losses as losses  # noqa: E402
import lab_protocol as proto  # noqa: E402
import lab_readers as readers  # noqa: E402
import lab_records as records  # noqa: E402
import process_health  # noqa: E402
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
           'health-baseline': 'andrix-health-baseline-v1', 'health': 'andrix-health-composition-v1',
           'confirmation-preflight': 'andrix-confirmation-preflight-v1',
           'activation-preflight': 'andrix-activation-preflight-v1',
           'identity-baseline': 'andrix-identity-baseline-v1'}
UNKEPT = 'the compound manifest could not be kept: '
# The environment variable through which a version 3 broker tells each generation how many round
# boundaries of each ticket it has recorded, so the bridge can name the next checkpoint ordinal.
# The broker verifies every ordinal against its own ledger.
CHECKPOINT_ENV = 'ANDRIX_LAB_CHECKPOINTS'
# The states in which a ticket waits for a later boot to show what a lost crossing did: a plain
# kernel confirmation may be issued only for a ticket in one of them.
CONFIRM_WAITS = ('SESSION_INTENT', 'COMMIT_INTENT', 'ABANDON_INTENT')
# The boot transitions the broker runs itself: a plain kernel confirmation and a direct negative
# control's activation with its native recovery, and the most new boot IDs each may show.
TRANSITIONS = {'CONFIRMATION': 1, 'NEGATIVE_ACTIVATION': 2}
# The ticket flag the reconciler sets at a ticket's boot limit.
FLAG_BOOT_LIMIT = 2
# The next profile's ledger records and their exact keys, by kind and, where a kind has several
# records, by record.
CHECKPOINT_KEYS = ('ticket', 'plan', 'attempt', 'ordinal', 'milestone', 'milestone_code', 'state', 'ticket_sha256',
                   'selection_sha256', 'plan_sha256', 'round_start', 'occurrence', 'loss_cell', 'request', 'generation',
                   'wall_ns', 'monotonic_ns')
NEXT_RECORDS = {
    'checkpoint': CHECKPOINT_KEYS,
    'consent': ('control', 'role', 'reason', 'wall_ns'),
    'boot-transition': {
        'BEGIN': ('record', 'transition', 'transition_kind', 'action', 'action_id', 'cell', 'phase', 'preflight', 'old',
                  'ordinal', 'caps', 'poll', 'subject', 'wall_ns', 'monotonic_ns'),
        'PROGRESS': ('record', 'transition', 'capture', 'launch', 'acknowledgement', 'stream_end', 'wall_ns',
                     'monotonic_ns'),
        'END': ('record', 'transition', 'status', 'new_boots', 'polls', 'settled_poll', 'reason', 'wall_ns',
                'monotonic_ns')},
    'direct-control': {
        'PAYLOAD': ('record', 'control', 'role', 'members', 'wall_ns'),
        'CREATED': ('record', 'control', 'role', 'action', 'capture', 'join_group', 'reference', 'wall_ns'),
        'WRITTEN': ('record', 'control', 'role', 'action', 'members', 'wall_ns'),
        'COMMITTED': ('record', 'control', 'role', 'action', 'capture', 'classification', 'wall_ns')},
    'qualification': {
        'DECISION': ('record', 'branch', 'qualified', 'capabilities_sha256', 'predicate_sha256', 'reason', 'wall_ns'),
        'GATE': ('record', 'plan', 'attempt', 'allowed', 'reason', 'purpose', 'wall_ns')},
}
DIRECT_RECORDS = ('PAYLOAD', 'CREATED', 'WRITTEN', 'COMMITTED')
# A read or round loss's decision record: a halt after its child or boundary, or not acted when
# the observation or boundary it was due at ended first.
LOSS_RECORD_KEYS = ('cell', 'on', 'decision', 'evidence', 'ticket', 'plan', 'attempt', 'operation', 'milestone',
                    'ordinal', 'occurrence', 'request', 'generation', 'groups', 'reason')
LOSS_DECISIONS = ('halt', 'not-acted')
# The F0 capability record the trial writes: these keys at least, its schema and its branch.
F0_SCHEMA = 'andrix-f0-capabilities-v1'
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
REQUESTS = {'NOTICE_VISIBILITY': ('ticket', 'index', 'serial'), 'HEALTH_PREPARATION': (),
            'PLAIN_KERNEL_CONFIRM': ('ticket',), 'DIRECT_STAGE': (), 'DIRECT_COMMIT': (), 'NEGATIVE_ACTIVATION': (),
            'USER_CREATE': (), 'USER_START': (), 'USER_SWITCH': (), 'USER_SETUP': (), 'USER_FIXTURE': (),
            'USER_PIN': (), 'CE_SENTINEL': ()}
# USER_PIN's one effect: a constant command, `sh`, given the credential dependent command on its
# private standard input. The command sits in a function that the input's last token calls, so an
# input cut short in transit never runs a partial command: cut inside the body, it is a syntax
# error at the end of input; cut before the call, the function is never called. Every stream of
# `locksettings` is discarded, since it prints the PIN it set (services/core/java/com/android/
# server/locksettings/LockSettingsShellCommand.java:299-306).
PRIVATE_COMMAND = 'sh'
PIN_INPUT = 'f(){ exec locksettings set-pin --user %d %s </dev/null >/dev/null 2>&1; }; f\n'
# The private store's directory and record names: a fresh name, never derived from the PIN.
PRIVATE_PIN = 'pin-%s'
# A private command's output kept privately: at most this many bytes of each field.
PRIVATE_KEEP = 2048
WITHHELD = 'withheld with the output of a command given private input'
# The typed readings of the full user reads: what each group records instead of facts.
USER_READINGS = ('inventory', 'user-limits', 'systemui-processes')
# An identity baseline's children in the order it reads them, each with its reader.
IDENTITY_CHILDREN = (('begin', 'clock'), ('factory', 'factory'), ('active', 'active'), ('inventory', 'inventory'),
                     ('processes', 'systemui-processes'), ('end', 'clock'))
UNREAD = 'the reader cannot read the children of an identity baseline again'
# A user action settles by reading again: at most this many whole reads, this far apart, within
# its own deadline.
USER_POLLS = 10
USER_POLL_S = 1.0


def _request_problem(kind, request):
    """Why a typed action's run request is not exactly its type's, or None."""
    names = REQUESTS[kind]
    if set(request) != set(names):
        return 'a %s request names exactly: %s' % (kind, ', '.join(names) or 'nothing')
    if kind == 'NOTICE_VISIBILITY' and (
            not _hex(request['ticket'], 16) or request['ticket'] == proto.ZERO_ID or type(request['index']) is not int
            or not 0 <= request['index'] < proto.MAX_LEDGER or type(request['serial']) is not int or request['serial'] < 0):
        return 'a visibility request names a ticket, its notice entry and a recipient serial'
    if kind == 'PLAIN_KERNEL_CONFIRM' and (not _hex(request['ticket'], 16) or request['ticket'] == proto.ZERO_ID):
        return 'a confirmation names the ticket whose wait it confirms'
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


def _witness_copy(status, rows, kept):
    """Bit 1 of a health composition as the broker accepted it, with the witness decision its kept
    candidate holds: what later probes of the user in the boot are told, and what a reopening
    derives again from the composition's manifest. None for a composition without rows."""
    if status != 'facts' or not rows:
        return None
    whole = isinstance(kept, dict) and set(kept) == {'user', 'serial', 'rows', 'witness'}
    return {'status': rows[proto.NO_CRASH_OR_ANR]['status'], 'decision': kept['witness'] if whole else None}


def _result_digest(result):
    """The SHA-256 of a preparation's result as a side record, or None without one."""
    return None if result is None else evidence.digest({'result': result})


def _pin_reply(code, stdout, stderr):
    """USER_PIN's reply: SET, FAILED or UNRECOGNIZED. Every stream of its command is discarded, so a
    whole reply is its exit status alone, both streams empty: 0 is success and any other status a
    refusal. Which status `cmd` gives a refusal is frameworks/native's, not pinned here."""
    if type(code) is not int or stdout not in (b'', '') or stderr not in (b'', ''):
        return 'UNRECOGNIZED'
    return 'SET' if code == 0 else 'FAILED'


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
             sleep=time.sleep, ids=os.urandom, processes=None, sync=True, target=None, target_read=False, health=None,
             fsync=None, work=None, private=None):
        """Opens a broker directory. The native target scope is read at HELLO and at every
        crossing's gate. With `target_read`, the reader's admitted target reader reads it from
        the guest as the broker's own recorded group, and the scope is established empty only
        when both the admission and that read say so. Otherwise `target`, when given, is a host
        callable that returns the scope as it stands (ESTABLISHED_EMPTY, HELD or UNKNOWN), and
        without either the admitted scope stands. A target that cannot be read is UNKNOWN.
        `health`, under a version 3 admission, is the health adapter whose fixed commands a
        HEALTH_PREPARATION runs. `fsync`, when given, is the one sync of every file and directory
        the broker and its ledger make durable, so a test can record their order; otherwise the
        broker syncs with os.fsync and the ledger with its own. `work` is the work fixture's
        adapter, whose fixed commands CE_SENTINEL runs. `private` is the private store, a directory
        outside the broker's evidence that only USER_PIN writes: the disposable lab PIN it
        generates, which never enters the ledger."""
        if target_read and (target is not None or not getattr(reader, 'target_admitted', False)):
            raise BrokerError("a target read needs the reader's admitted target reader and no host target")
        self = object.__new__(cls)
        self._fsync = fsync
        self.root = Path(root)
        self.transport, self.reader, self.notice, self.health = transport, reader, notice, health
        self.work = work
        self._private = None if private is None else Path(private)
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

    def _sync_fd(self, fd):
        """Syncs one descriptor through the injected sync, or os.fsync as it stands at the call."""
        (self._fsync or os.fsync)(fd)

    def _sync_dir(self, path):
        """Syncs one directory, so the names it holds are durable: through the injected sync when
        one was given, else through the module's `_sync_directory` as it stands at the call."""
        if self._fsync is None:
            _sync_directory(path)
            return
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self._fsync(fd)
        finally:
            os.close(fd)

    def _open(self, source_root, sync):
        # Every opening syncs the directory holding the broker's name, and the broker's own, before
        # anything relies on the durable history, so a barrier that an interrupted initialization or
        # an earlier failed sync never reached is never skipped.
        try:
            self._sync_dir(self.root.parent)
            self._sync_dir(self.root)
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
            self.ledger = (ledgers.Ledger.open(self.root / LEDGER, sync=sync) if self._fsync is None
                           else ledgers.Ledger.open(self.root / LEDGER, sync=sync, fsync=self._fsync))
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
        # Losses, round boundaries, boot transitions, direct controls and F0.
        self.schedule = None
        self.checkpoints, self.boundary_counts, self.read_counts = {}, {}, {}
        self.loss_evidence, self.loss_records = {}, {}
        self.transitions, self.observed_boots = {}, set()
        self.consents, self.direct, self.payloads = {}, {}, {}
        self.f0 = None
        # The full user setup: each create action's CREATED and IDENTIFIED records, and every
        # serial a typed inventory has listed, which no later user may reuse.
        self.created, self.serials_seen = {}, {}
        # The health package: each serial's expected SystemUI identity and the identity baselines
        # that contradicted it, each boot's whole user listings, each user's probe begins, and each
        # serial's PIN and CE sentinel setup records.
        self.identities, self.identity_conflicts = {}, {}
        self.listings, self.probe_begins = {}, {}
        self.pins, self.sentinels = {}, {}
        # Bit 1 of each user's compositions in each boot, with their witness decisions, in order.
        self.witness_trail = {}
        for entry in self.ledger.entries:
            if not entry.complete:
                continue
            c = entry.content
            kind = entry.kind
            if kind == 'group' and self.admission['version'] == 3:
                self._check_unkept_compound(c)
            if kind == 'group' and self.admission['version'] == 3 and c.get('reader') in USER_READINGS:
                self._check_typed(c)
            if kind in NEXT_RECORDS:
                self._next_record(kind, c)
                continue
            if kind == 'user-setup':
                self._setup_record(c)
                continue
            if kind == 'group':
                self._read_record(c)
                if c.get('reader') == 'inventory' and c.get('status') == 'facts':
                    self._serials(c['reading'])
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
                self._probe_begun(c)
            if kind == 'generation':
                self.generation = c['generation']
                self.open_generation = c
            elif kind == 'generation-end':
                self.open_generation = None
            elif kind == 'stop':
                self.stopped = c['reason']
            elif kind == 'faults':
                # A version 3 broker's faults come only from its admitted schedule's own bytes.
                self.cells.extend(self._schedule_record(c) if self.admission['version'] == 3 else c['cells'])
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
                if c.get('on') in losses.OPERATIONS:
                    self._loss_record(c)
                if c.get('on') == 'point' and self.admission['version'] == 3 and any(
                        self._kept_problem(c.get(name)) for name in ('ticket_sha256', 'selection_sha256')):
                    raise BrokerError('the point fault %d names a ticket or selection the broker did not keep'
                                      % c['number'])
                self.consumed.add(c['cell'])
            elif kind == 'group':
                self._users(c)
                self._listing(c)
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
        # A boot transition a lost broker left open: its reboot may have run, and it is never sent
        # again. A loss that an observation or boundary named due, and that was never decided, is
        # recorded as not acted: it never acts later at another address.
        for ident, transition in sorted(self.transitions.items()):
            if transition['end'] is None:
                self._end_transition(ident, 'LOST', [], [], None,
                                     'the broker was lost during the transition; whether it rebooted is unknown')
        self._settle_unacted('the broker was lost before the loss acted')
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
        elif reader == 'health-baseline' and c['brackets'] is not None:
            # Every bracketed baseline is kept: which one a probe relies on is the rule of
            # health_baseline.select alone, so output that is unavailable or of no known form
            # never replaces a whole one.
            self.baselines.setdefault((c['brackets']['boot'], c['user'], c['serial']), []).append(c)
        elif reader == 'health':
            self.used_preparations.update(c['preparations'])
            if c.get('witness') is not None and c['brackets'] is not None:
                self.witness_trail.setdefault((c['brackets']['boot'], c['user'], c['serial']), []).append(
                    {'group': c['number'], 'brackets': c['brackets'], 'status': c['witness']['status'],
                     'decision': c['witness']['decision'], 'captures': list(c['captures'])})
        elif reader == 'identity-baseline':
            # Each serial's first qualified identity stands; a later one that differs is a conflict
            # the group names, never a new expectation.
            self._identity_record(c)
        if c['emitted']:
            self._scaled(c['brackets']['end'])

    def _identity_record(self, c):
        """One identity baseline's expectations, from its children alone: its bracket, status and
        projection must be exactly what its named children's own captures give when read again,
        and its conflicts what that projection makes against the identities before it. Only then
        does a qualified projection give expectations. A group whose children the reader cannot
        read again is unclassified and gives none. Anything else refuses the reopening: a changed
        copy never puts in an identity that the factory reads did not show."""
        brackets, derived = self._identity_derived(c['children'], c['number'])
        if derived is NotImplemented:
            derived = ('unclassified', None)
            if c['status'] != 'unclassified' or c['reason'] != UNREAD:
                raise BrokerError('identity baseline %d: the reader cannot read its children again' % c['number'])
        if ledgers.encode_json([brackets, list(derived)]) != ledgers.encode_json([c['brackets'],
                                                                                [c['status'], c['projection']]]):
            raise BrokerError("identity baseline %d is not what its children's captures give" % c['number'])
        if c['status'] != 'facts':
            if c['conflicts'] != []:
                raise BrokerError('identity baseline %d names conflicts without a projection' % c['number'])
            return
        known = {serial: kept['identity'] for serial, kept in self.identities.items()}
        found, conflicts = health_baseline.expected(known, c['projection'])
        if conflicts != c['conflicts']:
            raise BrokerError('identity baseline %d names other conflicts than its projection makes' % c['number'])
        for serial in conflicts:
            self.identity_conflicts.setdefault(serial, []).append(c['number'])
        for serial, identity in found.items():
            self.identities.setdefault(serial, {'identity': identity, 'group': c['number']})

    def _pin_rows(self, c):
        """The first bytes of every row a receipt read judged, from its ledger group, whether or
        not the read emits and whether or not its manifest was kept. A pin only ever refuses."""
        for row in c['rows']:
            if row['key'] is not None:
                self.rows_seen.setdefault(row['key'], row['sha256'])

    # ------------------------------------------ the next profile's records, rebuilt and checked

    def _next_record(self, kind, c):
        """One complete checkpoint, boot transition, direct control step, consent or F0 record into
        the broker's state. A record that breaks the rules its writer keeps refuses the reopening:
        an ordinal out of sequence, retained bytes that are missing or differ, a second END or
        decision, a consent given twice, or a step of an unadmitted control."""
        keys = NEXT_RECORDS[kind] if isinstance(NEXT_RECORDS[kind], tuple) else NEXT_RECORDS[kind].get(c.get('record'))
        if keys is None or set(c) != set(keys) | {'number', 'kind'}:
            raise BrokerError('the ledger holds a %s record %d of no known form' % (kind, c.get('number')))
        if kind == 'checkpoint':
            ticket = c['ticket']
            if c['ordinal'] != len(self.checkpoints.get(ticket, [])) + 1:
                raise BrokerError('the ledger holds checkpoint %d out of its ticket\'s sequence' % c['number'])
            if c['milestone'] is not None and c['milestone'] not in proto.MILESTONES:
                raise BrokerError('the ledger holds checkpoint %d of no known milestone' % c['number'])
            start = c['round_start']
            digests = [c[name] for name in ('ticket_sha256', 'selection_sha256', 'plan_sha256')]
            if start is not None and (not isinstance(start, dict) or set(start) != {'sha256', 'state', 'source'}
                                      or start['source'] not in ('observe', 'checkpoint')):
                raise BrokerError('the ledger holds checkpoint %d of no known round start' % c['number'])
            for digest in digests + ([start['sha256']] if start is not None else []):
                if self._kept_problem(digest) is not None:
                    raise BrokerError('checkpoint %d names bytes the broker did not keep' % c['number'])
            self.checkpoints.setdefault(ticket, []).append(c)
            if c['milestone'] is not None:
                key = (ticket, c['milestone'])
                self.boundary_counts[key] = self.boundary_counts.get(key, 0) + 1
            if c['loss_cell'] is not None:
                self.loss_evidence[c['loss_cell']] = c['number']
        elif kind == 'boot-transition':
            self._transition_record(c)
        elif kind == 'consent':
            if c['control'] in self.consents or c['control'] not in self._controls():
                raise BrokerError('the ledger holds consent %d given twice or for no admitted control' % c['number'])
            self.consents[c['control']] = c
        elif kind == 'direct-control':
            if c.get('control') not in self._controls() or c.get('record') not in DIRECT_RECORDS:
                raise BrokerError('the ledger holds direct control record %d of no admitted control' % c['number'])
            if c['record'] == 'PAYLOAD':
                if c['control'] in self.payloads:
                    raise BrokerError('the ledger holds a second payload of one direct control')
                self.payloads[c['control']] = c
            else:
                self.direct.setdefault(c['control'], {})[c['record']] = c
        elif kind == 'qualification':
            if c.get('record') == 'DECISION':
                if self.f0 is not None or c['branch'] not in lab_actions.BRANCHES:
                    raise BrokerError('the ledger holds a second or unknown F0 decision')
                # The fence's qualification is restored only from a decision its kept capability
                # record still makes, never from the ledger's summary of it.
                why = self._decision_problem(c)
                if why is not None:
                    raise BrokerError('the ledger holds F0 decision %d that its record does not make: %s'
                                      % (c['number'], why))
                self.f0 = c
            elif c.get('record') != 'GATE':
                raise BrokerError('the ledger holds an F0 record of no known form')

    def _kept_problem(self, digest):
        """Why bytes the ledger names by their SHA-256 are not kept whole under RECORDS, or None."""
        data = _regular_bytes(self.root / RECORDS / str(digest)) if _hex(digest, 32) else None
        if data is None or hashlib.sha256(data).hexdigest() != digest:
            return 'the bytes of %s are not kept whole' % digest
        return None

    def _transition_record(self, c):
        record, ident = c.get('record'), c.get('transition')
        if record == 'BEGIN':
            if ident in self.transitions or c.get('transition_kind') not in TRANSITIONS:
                raise BrokerError('the ledger holds a boot transition begun twice or of no known kind')
            self.transitions[ident] = {'begin': c, 'progress': [], 'end': None}
        elif record in ('PROGRESS', 'END') and ident in self.transitions and self.transitions[ident]['end'] is None:
            self.transitions[ident]['progress' if record == 'PROGRESS' else 'end'] = (
                self.transitions[ident]['progress'] + [c] if record == 'PROGRESS' else c)
        else:
            raise BrokerError('the ledger holds boot transition record %d without its BEGIN, or after its END'
                              % c['number'])

    def _read_record(self, c):
        """A group's clock reading among the observed boots, and its read marker: the completed run
        of one reader of a ticket's observation at a milestone, and a loss it was due for."""
        if c.get('reader') == 'clock' and c.get('status') == 'facts' and c.get('reading'):
            self.observed_boots.add(c['reading']['boot'])
        read = c.get('read')
        if read is None:
            return
        if c.get('status') != 'stopped':
            key = (c['ticket'], read['milestone'], read['ordinal'])
            self.read_counts[key] = self.read_counts.get(key, 0) + 1
        if read.get('loss_cell') is not None:
            self.loss_evidence[read['loss_cell']] = c['number']

    def _schedule_record(self, c):
        """The admitted faults on reopening, from the schedule's kept canonical bytes alone: they
        must hash to the digest the admission binds and parse as one schedule of this
        installation and profile, and the ledger's summary of them must be exactly those faults.
        A summary that differs refuses the reopening: it never moves or adds a fault."""
        if (set(c) != {'cells', 'schedule_sha256', 'number', 'kind'} or self.schedule is not None
                or c['schedule_sha256'] != self.admission.get('fault_schedule_sha256')):
            raise BrokerError('the ledger holds a second schedule, or one the admission does not bind')
        data = _regular_bytes(self.root / RECORDS / c['schedule_sha256'])
        if data is None or hashlib.sha256(data).hexdigest() != c['schedule_sha256']:
            raise BrokerError('the admitted schedule is not kept whole')
        try:
            faults = [dict(f) for f in losses.parse(data, self.admission['installation'], lab_actions.PROFILE)]
        except losses.ScheduleError as error:
            raise BrokerError('the admitted schedule: %s' % error) from error
        if c['cells'] != faults:
            raise BrokerError("the ledger's summary of the schedule is not the admitted schedule")
        self.schedule = c['schedule_sha256']
        return faults

    def _loss_record(self, c):
        """A read or round loss's decision: of an admitted cell of its kind, decided once, and a
        halt only after the record that named it due."""
        if set(c) != set(LOSS_RECORD_KEYS) | {'number', 'kind'}:
            raise BrokerError('the ledger holds loss record %d of no known form' % c['number'])
        cell = next((x for x in self.cells if x['cell'] == c['cell']), None)
        if cell is None or cell['on'] != c['on'] or c['cell'] in self.loss_records:
            raise BrokerError('the ledger holds loss record %d of no admitted cell, or a cell consumed twice'
                              % c['number'])
        if c['decision'] not in LOSS_DECISIONS or self.loss_evidence.get(c['cell']) != c['evidence']:
            raise BrokerError('the ledger holds loss record %d without the record that named it due' % c['number'])
        self.loss_records[c['cell']] = c['number']

    def _controls(self):
        """The admitted direct negative controls: control ID to role."""
        return {s['parameters']['control']: s['parameters']['role'] for s in self.specs.values()
                if s['type'] in lab_actions.DIRECT_STEPS}

    def _users(self, group):
        for item in group.get('observations', ()):
            if item['kind'] != 'USER':
                continue
            key = '%d/%d' % (item['user'], item['serial'])
            if item['classification'] == 'REMOVED':
                self.users_seen.pop(key, None)
            else:
                self.users_seen[key] = (item['user'], item['serial'])

    def _listing(self, group):
        """A whole user listing a users group read: its boot, time and each user's state. The USER
        reader gives every user or none, so a user it does not show running is locked, stopped or
        absent, as the reconciler reads it."""
        if group.get('reader') != 'users' or group.get('status') != 'facts':
            return
        items = [o for o in group.get('observations', ()) if o['kind'] == 'USER']
        if not items:
            return
        states = {(o['user'], o['serial']): o['classification'] for o in items}
        self.listings.setdefault(items[0]['boot'], []).append((items[0]['elapsed'], states))

    def _probe_begun(self, group):
        """A probe's begin bracket, read: the user's probe begins in that boot."""
        reading = group['reading']
        if type(group.get('user')) is int and type(group.get('serial')) is int:
            self.probe_begins.setdefault((reading['boot'], group['user'], group['serial']), []).append(
                reading['elapsed'])

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
        """Admits fault cells. A cell names its own ID, where it acts, its key and its mode. A
        version 3 broker admits faults only from the schedule its admission binds."""
        if self.admission['version'] == 3:
            raise BrokerError('a version 3 broker admits faults only from its bound schedule')
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

    def admit_schedule(self, data):
        """Admits the fault schedule a version 3 admission binds, once, between generations: its
        exact canonical bytes must hash to the admitted digest. Every fault is checked before any
        is admitted, and the whole schedule is refused for one that is malformed, foreign or
        wrongly timed: a cell that is not new, an address named twice, a crossing cell of no known
        form, a read loss of a reader this broker does not admit, a plan of another installation
        or component in the store, or an address its history has already passed. Nothing is
        skipped: an admitted fault either acts at its address or stays visibly unconsumed."""
        if self.admission['version'] != 3:
            raise BrokerError('a fault schedule needs a version 3 admission')
        if self.open_generation is not None:
            raise BrokerError('a schedule is admitted only between generations')
        if self.schedule is not None:
            raise BrokerError('the schedule is admitted once')
        data = bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        if digest != self.admission['fault_schedule_sha256']:
            raise BrokerError('the schedule is not the one the admission binds')
        try:
            faults = losses.parse(data, self.admission['installation'], lab_actions.PROFILE)
        except losses.ScheduleError as error:
            raise BrokerError('the fault schedule: %s' % error) from error
        known = {cell['cell'] for cell in self.cells}
        addresses = set()
        for fault in faults:
            if fault['cell'] in known:
                raise BrokerError('a fault cell ID is new and named once: %s' % fault['cell'])
            known.add(fault['cell'])
            if fault['on'] in losses.OPERATIONS:
                key = losses.address(fault)
            else:
                self._check_cell(fault)
                key = tuple(fault[k] for k in ('on', 'plan', 'attempt') + CELL_KEYS[fault['on']][2:])
            if key in addresses:
                raise BrokerError('an address named twice: %s' % fault['cell'])
            addresses.add(key)
            problem = self._fault_problem(fault)
            if problem is not None:
                raise BrokerError('fault %s: %s' % (fault['cell'], problem))
        try:
            self._keep(digest, data)
        except (BrokerError, OSError) as error:
            raise self._writer_failed('the fault schedule could not be kept: %s' % error) from error
        cells = [dict(f) for f in faults]
        self.ledger.record('faults', {'cells': cells, 'schedule_sha256': digest})
        self.schedule = digest
        self.cells.extend(cells)

    def _check_cell(self, cell):
        """A crossing, host or point cell of its version 1 and 2 form, as admit_faults checks it."""
        on = cell.get('on')
        if on not in CELL_KEYS or set(cell) != {'cell', 'on', 'mode'} | set(CELL_KEYS[on]):
            raise BrokerError('a fault cell of no known form')
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
            if cell['crossing'] not in self._launches and cell['mode'] != 'loss-before':
                raise BrokerError('a cell that needs a launch, on a crossing this guest may not launch')
        if on == 'host' and (cell['crossing'] not in proto.HOST_CROSSINGS or cell['occurrence'] not in (1, 2)):
            raise BrokerError('a host cell names SIGN or PUBLISH and an occurrence')

    def _fault_problem(self, fault):
        """Why a well formed fault is foreign or wrongly timed for this broker, or None."""
        plan = _regular_bytes(Path(self.admission['store']) / 'plans' / (fault['plan'] + STORE_SUFFIX))
        if plan is not None:
            try:
                stored = records.decode_plan(plan)
            except records.RecordError:
                return 'its plan in the store cannot be read'
            if (stored['installation'], stored['component']) != (self.admission['installation'],
                                                                 self.admission['component']):
                return 'a plan of another installation or component'
        on = fault['on']
        if on == 'read' and fault['ordinal'] == losses.RECEIPTS and not self.reader.receipts_admitted:
            return 'no receipt reader is admitted'
        if on == 'read' and fault['ordinal'] == losses.HEALTH and not self.reader.health_admitted:
            return 'no health reader is admitted'
        tickets = self._tickets_of(fault['plan'], fault['attempt'])
        if on == 'round':
            passed = sum(self.boundary_counts.get((t, fault['milestone']), 0) for t in tickets)
        elif on == 'read':
            passed = sum(self.read_counts.get((t, fault['milestone'], fault['ordinal']), 0) for t in tickets)
        elif on == 'cross':
            passed = sum(1 for e in self.ledger.entries if e.kind == 'crossing' and e.complete
                         and (e.content['plan'], e.content['attempt'], e.content['crossing'],
                              e.content['occurrence']) == (fault['plan'], fault['attempt'], fault['crossing'],
                                                           fault['occurrence']))
            passed = fault['occurrence'] if passed else 0
        elif on == 'host':
            passed = sum(1 for e in self.ledger.entries if e.kind == 'host' and e.complete
                         and e.content['phase'] == 'BEGIN'
                         and (e.content['plan'], e.content['attempt'], e.content['crossing'],
                              e.content['occurrence']) == (fault['plan'], fault['attempt'], fault['crossing'],
                                                           fault['occurrence']))
            passed = fault['occurrence'] if passed else 0
        else:
            passed = 0
        if passed >= fault.get('occurrence', 1) and on != 'point':
            return 'its address has already passed'
        return None

    def _tickets_of(self, plan, attempt):
        """The tickets of a plan's attempt that the broker's records name."""
        found = set()
        for ticket, records_ in self.checkpoints.items():
            if any((c['plan'], c['attempt']) == (plan, attempt) for c in records_):
                found.add(ticket)
        for entry in self.ledger.entries:
            c = entry.content
            if entry.kind == 'group' and entry.complete and c.get('read') and (
                    c['read']['plan'], c['read']['attempt']) == (plan, attempt):
                found.add(c['ticket'])
        return found

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
        one), the predecessor has a settled use and, for a user action, every boot transition
        settled with its intended outcome. The broker keeps the spec's exact bytes by
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
        adapter = {'notice': self.notice, 'health': self.health, 'work': self.work, None: None}[kind['adapter']]
        if kind['adapter'] is not None and adapter is None:
            raise BrokerError('no %s adapter is admitted' % kind['adapter'])
        if not self.reader.inventory_admitted:
            raise BrokerError('no typed user inventory is admitted')
        user_type = spec['type'] in lab_actions.USER_TYPES
        if user_type and not self.reader.users_admitted:
            raise BrokerError('no full user reader is admitted')
        if kind['adapter'] is None and not user_type and not self.reader.global_admitted:
            raise BrokerError('no global session inventory is admitted')
        gate = self._direct_gate(spec)
        if gate is None:
            gate = self._user_gate(spec)
        if gate is not None:
            raise BrokerError(gate)
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
            user, why = self._resolve(spec, inventory.reading, issue, request, inventory)
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
        command = self._action_commands(spec, kind, adapter, context, begin['deadline_monotonic_ns'], user)
        try:
            if spec['type'] == 'USER_CREATE':
                result = self._act_user_create(context, command, begin, spec)
            elif spec['type'] == 'USER_START':
                result = self._act_user_start(context, command, begin, user)
            elif spec['type'] == 'USER_SWITCH':
                result = self._act_user_switch(context, command, begin, user)
            elif spec['type'] == 'USER_SETUP':
                result = self._act_user_setup(context, command, begin, spec, user)
            elif spec['type'] == 'USER_FIXTURE':
                result = self._act_user_fixture(context, command, begin, spec, user)
            elif spec['type'] == 'USER_PIN':
                result = self._act_user_pin(context, command, begin, spec, user)
            elif spec['type'] == 'CE_SENTINEL':
                result = self._act_ce_sentinel(context, command, begin, spec, user)
            elif spec['type'] == 'NOTICE_VISIBILITY':
                result = self._act_visibility(context, command, begin, issue, user)
            elif spec['type'] == 'HEALTH_PREPARATION':
                result = self._act_preparation(context, command, begin, spec, user)
            elif spec['type'] == 'PLAIN_KERNEL_CONFIRM':
                result = self._act_confirm(context, begin, spec, request)
            elif spec['type'] == 'DIRECT_STAGE':
                result = self._act_direct_stage(context, command, begin, spec)
            elif spec['type'] == 'DIRECT_COMMIT':
                result = self._act_direct_commit(context, command, begin, spec)
            else:
                result = self._act_negative_activation(context, begin, spec)
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

    def _direct_gate(self, spec):
        """Why a direct control's step is refused before anything is recorded, from the ledger
        alone, or None: no direct step after F0's decision, a stage only with its payload pinned, a
        commit only after the control's consent and written members, an activation only after its
        commit. A refused step spends no use."""
        if spec['type'] not in lab_actions.DIRECT_STEPS:
            return None
        control, steps = spec['parameters']['control'], self.direct.get(spec['parameters']['control'], {})
        if self.f0 is not None:
            return 'a direct negative control runs only before F0'
        if spec['type'] == 'DIRECT_STAGE' and control not in self.payloads:
            return 'no payload is pinned for the control'
        if spec['type'] != 'DIRECT_STAGE' and control not in self.consents:
            return 'no consent was given before arming'
        if spec['type'] == 'DIRECT_COMMIT' and 'WRITTEN' not in steps:
            return "the control's stage did not complete"
        if spec['type'] == 'NEGATIVE_ACTIVATION' and 'COMMITTED' not in steps:
            return "the control's commit is not recorded"
        return None

    def _user_gate(self, spec):
        """Why a user action is refused before anything is recorded, from the ledger alone, or
        None: no user effect follows while a boot transition is unsettled or unexpected, as no
        managed crossing launches then. An uncertain reboot may still take effect, and no later
        inventory read settles it. The ledger keeps the transition, so a reopening refuses alike.
        A refused use spends nothing."""
        if spec['type'] not in lab_actions.USER_TYPES:
            return None
        return self._unsettled_transition()

    def _resolve(self, spec, reading, issue, request, group=None):
        """The selected user from a whole inventory, or why not. A created user is the one its
        create action's reply named, identified by its serial and type from a whole inventory: the
        create's own later read, or this one when that read could not identify it."""
        selector = spec['user_selector']['kind']
        if selector == 'SYSTEM_USER':
            return lab_actions.resolve_system(reading)
        if selector == 'NOTICE_RECIPIENT':
            return lab_actions.resolve_recipient(reading, issue, request['serial'])
        creator = spec['user_selector']['action']
        records = self.created.get(creator, {})
        if 'CREATED' not in records:
            return None, 'the create action recorded no returned user ID'
        if 'IDENTIFIED' not in records and group is not None:
            identified, why = self._identify(creator, group)
            if identified is None:
                return None, why
        return lab_actions.resolve_created(reading, self.created[creator].get('IDENTIFIED'),
                                           running=spec['type'] != 'USER_START')

    def _action_commands(self, spec, kind, adapter, context, deadline, user=None):
        """The one way an action's commands reach the guest: a type's own fixed command or its
        adapter's allowlisted form, an effect only within the effect limits, every command fenced
        and refused once less than BOUND_COMMAND_MIN_S of the action's deadline is left, with the
        spec's output bounds."""
        def command(operation, text, private=None):
            # A type's own fixed forms first, then its adapter's. Private input only for USER_PIN's
            # one constant effect, whose input never enters the intent, a capture or the ledger.
            allowed = self._own_command(spec, text, user) or (adapter is not None and adapter.allowed(text))
            if private is not None:
                allowed = spec['type'] == 'USER_PIN' and operation == 'lab-action-effect' and text == PRIVATE_COMMAND
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
                                          bound_ns=deadline, private=private)
            if not result.completed or result.overflow is not None:
                raise readers.Unavailable('action capture %d did not complete: %s' % (capture, result.completion))
            return result
        return command

    def _own_command(self, spec, text, user=None):
        """Whether a shell command is one of the broker's own fixed forms for this action: a
        direct control's create under its own referrer, its staged member's digest read and write,
        and its commit; a user action's fixed effects and reads for its resolved user. Reboots are
        services, never shell text."""
        if spec['type'] in lab_actions.USER_TYPES:
            return text in self._user_commands(spec, user) or (
                spec['type'] == 'USER_FIXTURE' and text.startswith('sha256sum ')
                and bool(full_users.data_path(spec['parameters']['package']).fullmatch(text[len('sha256sum '):])))
        control = spec['parameters'].get('control')
        if spec['type'] == 'DIRECT_STAGE':
            path = re.escape('%s/control-%s/' % (self.admission['device_dir'], control))
            return (text == crossings.control_create_command(self.admission['component'], control)
                    or bool(re.fullmatch(r'sha256sum %s(base\.apk|base\.apk\.idsig)' % path, text))
                    or bool(re.fullmatch(r'pm install-write [1-9][0-9]{0,9} (base\.apk|base\.apk\.idsig) %s\1' % path,
                                         text)))
        if spec['type'] == 'DIRECT_COMMIT':
            return bool(re.fullmatch(r'pm install-commit --staged-ready-timeout %d [1-9][0-9]{0,9}'
                                     % crossings.COMMIT_READY_TIMEOUT_MS, text))
        return False

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
        counts = {'effects_launched': 0, 'effects_uncertain': 0, 'effects_not_launched': 0, 'reads': 0, 'pushes': 0}
        for e in self.ledger.entries:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if not intent or intent.get('lab_action') != number:
                continue
            if intent.get('operation') == 'lab-action-push':
                counts['pushes'] += 1
            elif intent.get('operation') != 'lab-action-effect':
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

    # ---------------------------------------------- confirmations and direct negative controls

    def consent(self, control, reason):
        """The lab operator's explicit consent to arm and activate one admitted direct negative
        control, given once, between generations, before its commit. It is a lab record, never a
        deployment authorization and never an ACTIVATE grant."""
        if self.admission['version'] != 3:
            raise BrokerError('a consent needs a version 3 admission')
        if self.open_generation is not None:
            raise BrokerError('a consent is given only between generations')
        controls = self._controls()
        if control not in controls:
            raise BrokerError('not an admitted direct negative control')
        if control in self.consents:
            raise BrokerError('a consent is given once')
        if not isinstance(reason, str) or not reason.strip():
            raise BrokerError('a consent names its reason')
        record = {'control': control, 'role': controls[control], 'reason': reason, 'wall_ns': self._wall()}
        number = self.ledger.record('consent', record)
        self.consents[control] = dict(record, number=number, kind='consent')
        return number

    def pin_payload(self, control, members):
        """Pins a direct control's negative payload once: each member's host path, SHA-256 and
        size, exactly the members and digests its admitted stage pins. The guest paths follow from
        the admitted staging directory."""
        if self.admission['version'] != 3:
            raise BrokerError('a payload needs a version 3 admission')
        controls = self._controls()
        if control not in controls or control in self.payloads:
            raise BrokerError('a payload of an admitted direct control, pinned once')
        stage = next(s for s in self.specs.values() if s['type'] == 'DIRECT_STAGE'
                     and s['parameters']['control'] == control)
        expected = {item['role']: (item['sha256'], item['bytes']) for item in stage['inputs']}
        if not isinstance(members, dict) or set(members) != set(expected):
            raise BrokerError('a payload pins exactly the members its stage admits')
        pinned = {}
        for member, spec in members.items():
            if (not isinstance(spec, dict) or set(spec) != {'host', 'sha256', 'bytes'}
                    or (spec['sha256'], spec['bytes']) != expected[member] or not str(spec['host']).startswith('/')):
                raise BrokerError('a pinned member names its host path and its admitted digest and size')
            pinned[member] = dict(spec, guest=crossings.staged_path('%s/control-%s/%s' % (
                self.admission['device_dir'], control, member)))
        record = {'record': 'PAYLOAD', 'control': control, 'role': controls[control], 'members': pinned,
                  'wall_ns': self._wall()}
        number = self.ledger.record('direct-control', record)
        self.payloads[control] = dict(record, number=number, kind='direct-control')

    def _read(self, name, context, deadline, expect_boot=None):
        """One reader group an action reads for itself, never given to a coordinator, within the
        action's deadline."""
        if name == 'clock':
            return self._clock_group(context, expect_boot, emitted=False, deadline_ns=deadline)
        if name == 'target':
            return self._group('target', self.reader.target, context, None, emitted=False, deadline_ns=deadline)
        if name == 'global-sessions':
            return self._group('global-sessions', self.reader.global_sessions, context, None, emitted=False,
                               deadline_ns=deadline)
        if name == 'user-limits':
            return self._group('user-limits', self.reader.user_limits, context, None, emitted=False,
                               deadline_ns=deadline)
        if name == 'users':
            return self._group('users', lambda: self.reader.users(sorted(self.users_seen.values())), context,
                               expect_boot, emitted=False, deadline_ns=deadline)
        return self._group(name, getattr(self.reader, name), context, expect_boot, emitted=False, deadline_ns=deadline)

    @staticmethod
    def _one(group, kind, classification=None):
        """The one fact of a kind a group read, of a classification when given, or None."""
        found = [f for f in group.facts if f['kind'] == kind] if group.ok else []
        if len(found) != 1 or (classification is not None and found[0]['classification'] != classification):
            return None
        return found[0]

    def _captures_of(self, numbers):
        """Every capture of the given groups, in order."""
        return [n for g in numbers if g is not None for n in self.ledger.entries[g - 1].content.get('captures', [])]

    def _issuing(self, ticket):
        """The ticket a confirmation confirms, from the store and the ledger: (facts, None) or
        (facts so far, why not). It must be of this installation and component, in a wait a later
        boot resolves, unchanged since its last recorded boundary, below its boot limit, and not
        the positive attempt before a qualified F0. Its ticket, plan, selection and the grant of
        its last granted entry are kept by digest; a failed keep latches the writer's stop."""
        store, facts = Path(self.admission['store']), {'ticket': ticket}
        tdata = _regular_bytes(store / 'tickets' / (ticket + STORE_SUFFIX))
        if tdata is None:
            return facts, 'the stored ticket cannot be read whole'
        try:
            t = records.decode_ticket(tdata)
            pdata = _regular_bytes(store / 'plans' / (t['plan'] + STORE_SUFFIX)) or b''
            p = records.decode_plan(pdata)
        except records.RecordError as error:
            return facts, 'the stored ticket or plan: %s' % error
        sdata = _regular_bytes(store / 'selections' / (self.admission['component'] + STORE_SUFFIX))
        facts.update(plan=t['plan'], attempt=t['attempt'], state=t['state'], boot_count=t['bootCount'],
                     boot_limit=p['bootLimit'])
        if (t['installation'], t['component']) != (self.admission['installation'], self.admission['component']):
            return facts, 'a ticket of another installation or component'
        if t['state'] not in CONFIRM_WAITS:
            return facts, 'the ticket is %s, not in a wait a later boot resolves' % t['state']
        found = self.checkpoints.get(ticket, [])
        if not found or found[-1]['ticket_sha256'] != hashlib.sha256(tdata).hexdigest():
            return facts, "the stored ticket is not the one its last recorded boundary kept"
        facts['predecessor_checkpoint'] = found[-1]['number']
        if t['flags'] & FLAG_BOOT_LIMIT or t['bootCount'] + 1 >= p['bootLimit']:
            return facts, "a confirmation would reach the ticket's boot limit"
        problem = self._positive_problem(t['plan'], t['attempt'])
        if problem is not None:
            return facts, problem
        grants = [entry[4] for entry in t['ledger'] if entry[4] != proto.ZERO_ID]
        gdata = (_regular_bytes(store / 'authorizations' / (grants[-1] + STORE_SUFFIX)) if grants else None)
        if sdata is None or (grants and gdata is None):
            return facts, 'the stored selection or grant cannot be read whole'
        retained = {}
        try:
            for name, data in (('ticket', tdata), ('plan', pdata), ('selection', sdata), ('grant', gdata)):
                if data is not None:
                    retained[name] = hashlib.sha256(data).hexdigest()
                    self._keep(retained[name], data)
        except (BrokerError, OSError) as error:
            raise self._writer_failed('the issuing records could not be kept: %s' % error) from error
        facts['retained'] = retained
        return facts, None

    def _boot_budget(self, kind, spec, current=None):
        """The reboot services and observed boots a transition of one kind would use, and why
        the admission does not allow one more, or None: its action's effect caps, its kind's
        service allowance, the observed boot allowance, or an unsettled earlier transition."""
        policy, services = self.admission['boot_policy'], self._reboot_services()
        budget = {'services': services, 'observed': len(self.observed_boots), 'problem': None}
        spent = self._effect_spent(lab_actions.TYPES[spec['type']]['effect'], spec['phase'])
        if spent is not None:
            budget['problem'] = spent
        elif kind == 'CONFIRMATION' and services['CONFIRMATION'] >= policy['confirmation_services']:
            budget['problem'] = 'the admitted %d confirmation services are spent' % policy['confirmation_services']
        elif kind == 'NEGATIVE_ACTIVATION' and (services['MANAGED_ACTIVATION'] + services['NEGATIVE_ACTIVATION']
                                                >= policy['activation_services']):
            budget['problem'] = 'the admitted %d activation services are spent' % policy['activation_services']
        elif len(self.observed_boots) + TRANSITIONS[kind] > policy['observed_boots']:
            budget['problem'] = 'the transition could pass the admitted %d observed boots' % policy['observed_boots']
        else:
            budget['problem'] = self._unsettled_transition(current)
        return budget

    def _preflight(self, kind, context, groups, why, projection):
        """A transition's preflight as one compound group: every read it judged, kept before the
        judgment, and the judgment, recorded for a refusal too."""
        number, _ = self._compound(kind, context, self._captures_of(groups.values()), groups,
                                   'facts' if why is None else 'refused', why, None, dict(projection, why=why),
                                   extra={'judged': why is None})
        return number

    def _act_confirm(self, context, begin, spec, request):
        """PLAIN_KERNEL_CONFIRM: a plain kernel reboot that confirms the issuing ticket's wait in a
        later boot. Its preflight reads the clock, the completed boot, the checkpoint, the factory
        and active copies, the SystemUI listing, the whole global session inventory and the target,
        and refuses unless the ticket waits as its last boundary recorded, below its boot limit, the
        checkpoint is COMMITTED, the target established, every live session positively
        uncommitted, the SystemUI listing joins the global inventory, and the admitted services and
        observed boots allow it. The reboot is then a boot transition."""
        deadline = begin['deadline_monotonic_ns']
        pre = dict(context, purpose='confirmation-preflight')
        issuing, why = self._issuing(request['ticket'])
        reads, groups = {}, {}
        names = ('clock', 'boot', 'checkpoint', 'factory', 'active', 'sessions', 'global-sessions')
        for name in names + (('target',) if self._target_read else ()):
            boot = reads['clock'].reading['boot'] if name in ('boot', 'checkpoint', 'factory', 'active', 'sessions') \
                and reads['clock'].ok else None
            reads[name] = self._read(name, dict(pre, part=name), deadline, boot)
            groups[name] = reads[name].number
        why = why or self._confirm_problem(reads)
        budget = self._boot_budget('CONFIRMATION', spec)
        why = why or budget['problem']
        preflight = self._preflight('confirmation-preflight', pre, groups, why,
                                    {'issuing': issuing, 'budget': budget, 'reason': begin['reason']})
        if why is not None:
            return 'REFUSED', {'preflight': preflight, 'refused': why}, why, True, []
        clock = reads['clock'].reading
        old = {'boot': clock['boot'], 'instance': clock['instance'], 'elapsed': clock['elapsed']}
        subject = {'ticket': issuing['ticket'], 'plan': issuing['plan'], 'attempt': issuing['attempt'],
                   'state': issuing['state'], 'predecessor_checkpoint': issuing['predecessor_checkpoint'],
                   'retained': issuing['retained']}
        return self._boot_transition('CONFIRMATION', begin, spec, dict(context, purpose='confirmation'), deadline, old,
                                     preflight, subject, self._confirmed)

    def _confirm_problem(self, reads):
        """Why a confirmation's preflight reads do not make a reboot safe now, or None."""
        clock = reads['clock']
        if not clock.ok or clock.reading['instance'] < 0:
            return 'the clock is unavailable or no framework is running'
        if self._one(reads['boot'], 'BOOT', 'COMPLETED') is None:
            return 'the boot is not read completed'
        if self._one(reads['checkpoint'], 'CHECKPOINT', 'COMMITTED') is None:
            return 'the checkpoint is not read COMMITTED'
        if self._one(reads['factory'], 'FACTORY') is None or self._one(reads['active'], 'ACTIVE') is None:
            return 'the factory or active copy is not read'
        if not reads['sessions'].ok or not _whole_listing(reads['sessions'].facts, clock.reading['instance']):
            return "the SystemUI listing is not whole in the clock's framework instance"
        if not reads['global-sessions'].ok:
            return 'the global session inventory is unavailable (%s)' % reads['global-sessions'].reason
        inventory = reads['global-sessions'].reading
        problem = lab_actions.confirmation_safety(inventory, self.admission['component'])
        if problem is not None:
            return problem
        listed = {f['facts']['reference'][1] for f in reads['sessions'].facts
                  if f['kind'] == 'SESSION' and f['classification'] in LIVE}
        live = {row['id'] for row in lab_actions.live_rows(inventory) if row['package'] == self.admission['component']}
        if listed != live:
            return 'the SystemUI listing and the global session inventory disagree'
        if 'target' in reads and (not reads['target'].ok or reads['target'].reading['scope'] != 'ESTABLISHED_EMPTY'):
            return 'the native target scope is not read established empty'
        return None

    def _confirmed(self, boot, clock, poll, context, deadline):
        """A confirmation settles in its new boot on a completed BOOT and a COMMITTED checkpoint,
        then renews the factory, active, SystemUI listing, users, global inventory and target
        reads of that boot. A pending or unknown checkpoint is a read only wait."""
        reads = {}
        for name in ('boot', 'checkpoint'):
            reads[name] = self._read(name, dict(context, part=name), deadline, boot)
            poll['groups'].append(reads[name].number)
        if self._one(reads['boot'], 'BOOT', 'COMPLETED') is None:
            poll['missing'] = 'the new boot is not read completed'
            return None
        if self._one(reads['checkpoint'], 'CHECKPOINT', 'COMMITTED') is None:
            poll['missing'] = 'the checkpoint is pending or unknown: a read only wait'
            return None
        renewed = {}
        for name in ('factory', 'active', 'sessions', 'users', 'global-sessions') + (
                ('target',) if self._target_read else ()):
            group = self._read(name, dict(context, part=name), deadline,
                               boot if name not in ('global-sessions', 'target') else None)
            poll['groups'].append(group.number)
            renewed[name] = {'group': group.number, 'status': group.status}
        outcome = {'new_boot': boot, 'instance': clock.reading['instance'], 'boot_group': reads['boot'].number,
                   'checkpoint_group': reads['checkpoint'].number, 'renewed': renewed}
        return 'OK', outcome, [reads['boot'].number, reads['checkpoint'].number] + [r['group'] for r in renewed.values()]

    def _boot_transition(self, kind, action, spec, context, deadline, old, preflight, subject, settle):
        """One boot transition the broker owns. Its BEGIN, with its preflight, old boot, ordinal,
        caps and poll bound, is written and synced before the reboot service, which is a fenced,
        effect limited capture with its own launch deadline. PROGRESS records the service's
        acknowledgement, which proves no boot. Then a poll every interval, within the transition's
        bound: a clock group, and in a new boot what `settle` reads. The same boot never settles;
        more new boots than the kind admits, or a boot past the observed allowance, is
        unexpected and halts. The END names every poll, the new boots and the settling poll.
        Returns the action's END fields."""
        policy = self.admission['boot_policy']
        bound_ms = policy['settle_ms'] if kind == 'CONFIRMATION' else policy['negative_settle_ms']
        started = self._monotonic()
        settle_deadline = min(deadline, started + bound_ms * 1_000_000)
        ident = proto.fresh_id(self._ids)
        begin = {'record': 'BEGIN', 'transition': ident, 'transition_kind': kind, 'action': action['number'],
                 'action_id': action['action_id'], 'cell': spec['cell'], 'phase': spec['phase'], 'preflight': preflight,
                 'old': old, 'ordinal': self._reboot_services()['total'] + 1,
                 'caps': {'activation_services': policy['activation_services'],
                          'confirmation_services': policy['confirmation_services'],
                          'reboot_services': policy['activation_services'] + policy['confirmation_services'],
                          'observed_boots': policy['observed_boots']},
                 'poll': {'interval_ms': policy['poll_interval_ms'], 'settle_ms': bound_ms,
                          'started_monotonic_ns': started, 'deadline_monotonic_ns': settle_deadline},
                 'subject': subject, 'wall_ns': self._wall(), 'monotonic_ns': started}
        self._fence()
        number = self.ledger.record('boot-transition', begin)
        self._transition_record(dict(begin, number=number, kind='boot-transition'))
        context = dict(context, transition=ident)
        new_boots, polls = [], []
        try:
            try:
                capture, result = self._reboot_effect(action, spec, context, deadline, ident, kind)
            except _NotLaunched as error:
                reason = '%s: nothing launched' % error
                self._end_transition(ident, 'REFUSED', [], [], None, reason)
                return 'REFUSED', {'transition': ident}, reason, True, []
            progress = {'record': 'PROGRESS', 'transition': ident, 'capture': capture, 'launch': result.launch,
                        'acknowledgement': result.acknowledgement, 'stream_end': result.stream_end,
                        'wall_ns': self._wall(), 'monotonic_ns': self._monotonic()}
            progress_number = self.ledger.record('boot-transition', progress)
            self._transition_record(dict(progress, number=progress_number, kind='boot-transition'))
            if result.launch == 'not-launched':
                reason = 'the reboot service was not launched (%s)' % result.transport
                self._end_transition(ident, 'REFUSED', [], [], None, reason)
                return 'REFUSED', {'transition': ident, 'capture': capture}, reason, True, []
            status, reason, outcome, postreads, settled_poll = None, None, None, [], None
            while self._monotonic() < settle_deadline:
                poll = {'started_monotonic_ns': self._monotonic(), 'groups': [], 'boot': None, 'missing': None}
                polls.append(poll)
                clock = self._read('clock', dict(context, purpose='boot-poll'), settle_deadline)
                poll['groups'].append(clock.number)
                if not clock.ok:
                    poll['missing'] = 'the clock is unavailable (%s)' % clock.reason
                elif clock.reading['boot'] == old['boot']:
                    poll['missing'] = 'the same boot: no new boot is observed yet'
                else:
                    poll['boot'] = boot = clock.reading['boot']
                    if boot not in new_boots:
                        new_boots.append(boot)
                    if len(new_boots) > TRANSITIONS[kind] or boot != new_boots[-1]:
                        status, reason = 'UNEXPECTED', 'an unexpected boot: %d new boots where %d are admitted' % (
                            len(new_boots), TRANSITIONS[kind])
                    elif len(self.observed_boots) > policy['observed_boots']:
                        status, reason = 'UNEXPECTED', 'a boot past the admitted %d observed boots' % (
                            policy['observed_boots'])
                    else:
                        found = settle(boot, clock, poll, dict(context, purpose='boot-poll'), settle_deadline)
                        if found is not None:
                            status, outcome, postreads = found
                            reason = outcome.get('why')
                            settled_poll = len(polls)
                poll['ended_monotonic_ns'] = self._monotonic()
                if status is not None:
                    break
                remaining = (settle_deadline - self._monotonic()) / 1_000_000_000
                if remaining <= 0:
                    break
                self._sleep(min(policy['poll_interval_ms'] / 1000, remaining))
        except Stopped as error:
            # A poll the stop interrupted keeps its stopped group and says so.
            if polls and polls[-1]['missing'] is None:
                last = self.ledger.last
                if last.kind == 'group' and last.content.get('transition') == ident and \
                        last.number not in polls[-1]['groups']:
                    polls[-1]['groups'].append(last.number)
                polls[-1].update(missing='stopped: %s' % error, ended_monotonic_ns=self._monotonic())
            self._end_transition(ident, 'STOPPED', new_boots, polls, None, str(error))
            raise
        if status is None:
            status, reason = 'UNKNOWN', 'no settled new boot within the %d ms bound' % bound_ms
        self._end_transition(ident, status, new_boots, polls, settled_poll, reason)
        outcome = dict(outcome or {}, transition=ident, new_boots=new_boots, polls=len(polls))
        return status, outcome, reason, status in ('OK', 'UNEXPECTED') and settled_poll is not None, postreads

    def _end_transition(self, ident, status, new_boots, polls, settled_poll, reason):
        record = {'record': 'END', 'transition': ident, 'status': status, 'new_boots': list(new_boots), 'polls': polls,
                  'settled_poll': settled_poll, 'reason': reason, 'wall_ns': self._wall(),
                  'monotonic_ns': self._monotonic()}
        number = self.ledger.record('boot-transition', record)
        self._transition_record(dict(record, number=number, kind='boot-transition'))

    def _reboot_effect(self, action, spec, context, deadline, ident, kind):
        """The reboot service of a transition as one effect capture: within the effect limits, the
        transition's service allowance and the action's deadline, fenced, its intent synced first,
        and refused by the transport once the deadline passed. Returns (capture, result)."""
        effect_class = lab_actions.TYPES[spec['type']]['effect']
        budget = self._boot_budget(kind, spec, ident)
        if budget['problem'] is not None:
            raise _NotLaunched(budget['problem'])
        left = deadline - self._monotonic()
        if left < BOUND_COMMAND_MIN_S * 1_000_000_000:
            raise _NotLaunched("too little of the action's bound remains for the reboot")
        timeout = min(self.limits['reboot_timeout_s'], left / 1_000_000_000)
        gate = self._may_send(deadline)
        return self._capture('lab-action-effect', REBOOT_LABEL,
                             dict(context, effect_class=effect_class, phase=spec['phase'], transition_kind=kind),
                             lambda: self.transport.reboot(timeout, may_send=gate), timeout, deadline)

    def _act_direct_stage(self, context, command, begin, spec):
        """DIRECT_STAGE: one staged session of a direct control's pinned negative payload under its
        own referrer, before F0, with no other live session: the create, its whole reference
        joined from the global inventory, then each member pushed, read back by digest and
        written, the exact session read again before each write."""
        control, role = spec['parameters']['control'], spec['parameters']['role']
        deadline, component = begin['deadline_monotonic_ns'], self.admission['component']
        if self.f0 is not None:
            return 'REFUSED', None, 'a direct negative control runs only before F0', True, []
        payload = self.payloads.get(control)
        if payload is None:
            return 'REFUSED', None, 'no payload is pinned for the control', True, []
        pre = dict(context, purpose='direct-precondition')
        reads = {name: self._read(name, dict(pre, part=name), deadline) for name in ('clock', 'checkpoint',
                                                                                     'global-sessions')}
        groups = [g.number for g in reads.values()]
        why = None
        if not reads['clock'].ok or reads['clock'].reading['instance'] < 0:
            why = 'the clock is unavailable or no framework is running'
        elif self._one(reads['checkpoint'], 'CHECKPOINT', 'COMMITTED') is None:
            why = 'the checkpoint is not read COMMITTED'
        elif not reads['global-sessions'].ok or not reads['global-sessions'].reading['whole']:
            why = 'the global session inventory is not read whole'
        elif lab_actions.live_rows(reads['global-sessions'].reading):
            why = 'a session is live: a direct control stages alone'
        if why is not None:
            return 'REFUSED', {'groups': groups}, why, True, groups
        result = command('lab-action-effect', crossings.control_create_command(component, control))
        capture = self.ledger.last.number
        classification, session = crossings.classify_create(result)
        if classification != 'SUCCESS':
            return 'UNKNOWN', {'capture': capture}, 'the create gave no qualified reply: its effect is unknown', False, []
        join = self._read('global-sessions', dict(pre, part='join'), deadline)
        row, why = lab_actions.own_row(join.reading, control, component) if join.ok else (None, join.reason)
        reference = row and {'id': row['id'], 'created': row['created'], 'installer': row['installer'],
                             'referrer': row['referrer']}
        if row is None or row['id'] != session or None in reference.values():
            return 'UNKNOWN', {'capture': capture}, 'the created session is not joined whole: %s' % why, False, [
                join.number]
        self._direct_record('CREATED', control, role, action=begin['number'], capture=capture,
                            join_group=join.number, reference=reference)
        written = []
        for member in lab_actions.ROLE_MEMBERS[role]:
            pin = payload['members'][member]
            data = _regular_bytes(pin['host'], 1 << 30)
            if data is None or (hashlib.sha256(data).hexdigest(), len(data)) != (pin['sha256'], pin['bytes']):
                return 'UNEXPECTED', {'reference': reference}, 'the pinned %s has other bytes' % member, True, []
            pushed, _ = self._capture('lab-action-push', None, dict(context, member=member, path=pin['guest'],
                                                                     data_sha256=pin['sha256']),
                                      lambda d=data, p=pin['guest']: self.transport.push(d, p, MEMBER_MODE, 0,
                                                                                         self.limits['push_timeout_s']),
                                      self.limits['push_timeout_s'], deadline)
            check = command('lab-action-read', crossings.digest_command(pin['guest']))
            if crossings.classify_digest(check, pin['guest']) != pin['sha256']:
                return 'UNEXPECTED', {'reference': reference}, 'the staged %s does not read back exactly' % member, \
                    True, []
            again = self._read('global-sessions', dict(pre, part='revalidation', member=member), deadline)
            row, why = lab_actions.own_row(again.reading, control, component, reference) if again.ok else (
                None, again.reason)
            if row is None or not lab_actions.uncommitted(row, component):
                return 'UNEXPECTED', {'reference': reference}, 'the session cannot be written: %s' % (
                    why or 'it is not open and uncommitted'), True, [again.number]
            result = command('lab-action-effect', crossings.write_command(reference['id'], member, pin['guest']))
            classification = crossings.classify_write(result, pin['bytes'])
            if classification != 'SUCCESS':
                return 'UNKNOWN', {'reference': reference}, 'the write of %s gave no qualified reply' % member, \
                    False, []
            written.append({'member': member, 'push': pushed, 'write': self.ledger.last.number})
        self._direct_record('WRITTEN', control, role, action=begin['number'], members=written)
        return 'OK', {'reference': reference, 'members': written}, None, True, [join.number]

    def _act_direct_commit(self, context, command, begin, spec):
        """DIRECT_COMMIT: the one native commit before F0, of a direct control's own staged
        session only, after its consent, with its whole reference read again open and uncommitted,
        no other live session, the factory copy active and the checkpoint COMMITTED. A managed
        crossing never takes this path."""
        control, role = spec['parameters']['control'], spec['parameters']['role']
        deadline, component = begin['deadline_monotonic_ns'], self.admission['component']
        steps = self.direct.get(control, {})
        why = None
        if self.f0 is not None:
            why = 'a direct negative control commits only before F0'
        elif control not in self.consents:
            why = 'no consent was given before arming'
        elif 'WRITTEN' not in steps:
            why = "the control's stage did not complete"
        if why is not None:
            return 'REFUSED', None, why, True, []
        reference = steps['CREATED']['reference']
        pre = dict(context, purpose='direct-precondition')
        reads = {}
        for name in ('clock', 'checkpoint', 'factory', 'active', 'global-sessions'):
            boot = reads['clock'].reading['boot'] if name != 'clock' and name != 'global-sessions' \
                and reads['clock'].ok else None
            reads[name] = self._read(name, dict(pre, part=name), deadline, boot)
        groups = [g.number for g in reads.values()]
        inventory = reads['global-sessions'].reading if reads['global-sessions'].ok else None
        row, why = lab_actions.own_row(inventory, control, component, reference) if inventory else (
            None, 'the global session inventory is unavailable')
        if not reads['clock'].ok or reads['clock'].reading['instance'] < 0:
            why = 'the clock is unavailable or no framework is running'
        elif self._one(reads['checkpoint'], 'CHECKPOINT', 'COMMITTED') is None:
            why = 'the checkpoint is not read COMMITTED'
        elif self._one(reads['factory'], 'FACTORY') is None or self._one(reads['active'], 'ACTIVE',
                                                                         'FACTORY_COPY') is None:
            why = 'the factory copy is not read active'
        elif row is not None and not lab_actions.uncommitted(row, component):
            why = "the control's session is not open and uncommitted"
        elif row is not None and len(lab_actions.live_rows(inventory)) != 1:
            why = 'another session is live'
        if why is not None or row is None:
            return 'REFUSED', {'groups': groups}, why, True, groups
        result = command('lab-action-effect', crossings.commit_command(reference['id']))
        capture = self.ledger.last.number
        classification = crossings.classify_commit(result)
        self._direct_record('COMMITTED', control, role, action=begin['number'], capture=capture,
                            classification=classification)
        if classification not in ('READY', 'ACCEPTED', 'PENDING'):
            return 'UNKNOWN', {'capture': capture}, 'the commit gave no qualified reply: its effect is unknown', False, []
        return 'OK', {'classification': classification, 'capture': capture}, None, True, groups

    def _act_negative_activation(self, context, begin, spec):
        """NEGATIVE_ACTIVATION: a direct control's activating reboot under its consent, before F0,
        only with its own session committed and ready and every other session positively
        uncommitted. It settles only on its intended rejection and a safe recovery: a completed
        boot, a COMMITTED checkpoint, the factory copy active, its session failed for its role's
        cause and no session live. Its native recovery may show a second new boot."""
        control, role = spec['parameters']['control'], spec['parameters']['role']
        deadline, component = begin['deadline_monotonic_ns'], self.admission['component']
        steps = self.direct.get(control, {})
        if self.f0 is not None or control not in self.consents or 'COMMITTED' not in steps:
            return 'REFUSED', None, 'a negative activation needs its consent and its commit, before F0', True, []
        reference = steps['CREATED']['reference']
        pre = dict(context, purpose='activation-preflight')
        reads = {}
        for name in ('clock', 'checkpoint', 'global-sessions'):
            boot = reads['clock'].reading['boot'] if name == 'checkpoint' and reads['clock'].ok else None
            reads[name] = self._read(name, dict(pre, part=name), deadline, boot)
        groups = {name: group.number for name, group in reads.items()}
        why = None
        if not reads['clock'].ok or reads['clock'].reading['instance'] < 0:
            why = 'the clock is unavailable or no framework is running'
        elif self._one(reads['checkpoint'], 'CHECKPOINT', 'COMMITTED') is None:
            why = 'the checkpoint is not read COMMITTED'
        elif not reads['global-sessions'].ok:
            why = 'the global session inventory is unavailable'
        else:
            why = lab_actions.activation_safety(reads['global-sessions'].reading, control, component, reference)
        budget = self._boot_budget('NEGATIVE_ACTIVATION', spec)
        why = why or budget['problem']
        preflight = self._preflight('activation-preflight', pre, groups, why,
                                    {'control': control, 'role': role, 'reference': reference,
                                     'consent': self.consents[control]['number'], 'budget': budget,
                                     'reason': begin['reason']})
        if why is not None:
            return 'REFUSED', {'preflight': preflight, 'refused': why}, why, True, []
        clock = reads['clock'].reading
        old = {'boot': clock['boot'], 'instance': clock['instance'], 'elapsed': clock['elapsed']}
        subject = {'control': control, 'role': role, 'consent': self.consents[control]['number'],
                   'reference': reference}
        return self._boot_transition('NEGATIVE_ACTIVATION', begin, spec, dict(context, purpose='activation'),
                                     deadline, old, preflight, subject, self._rejected(control, role, reference))

    def _rejected(self, control, role, reference):
        """The settle reads of a negative activation in a new boot."""
        component = self.admission['component']

        def settle(boot, clock, poll, context, deadline):
            reads = {}
            for name in ('boot', 'checkpoint', 'factory', 'active', 'global-sessions'):
                reads[name] = self._read(name, dict(context, part=name), deadline,
                                         boot if name != 'global-sessions' else None)
                poll['groups'].append(reads[name].number)
            if self._one(reads['boot'], 'BOOT', 'COMPLETED') is None:
                poll['missing'] = 'the new boot is not read completed'
                return None
            if self._one(reads['checkpoint'], 'CHECKPOINT', 'COMMITTED') is None:
                poll['missing'] = 'the checkpoint is pending or unknown: recovery may still run'
                return None
            active = self._one(reads['active'], 'ACTIVE')
            if active is None or self._one(reads['factory'], 'FACTORY') is None or not reads['global-sessions'].ok:
                poll['missing'] = 'the active copy, the factory copy or the global inventory is not read'
                return None
            postreads = [g.number for g in reads.values()]
            outcome = {'new_boot': boot, 'instance': clock.reading['instance'], 'active': active['classification']}
            if active['classification'] != 'FACTORY_COPY':
                return 'UNEXPECTED', dict(outcome, why='the negative payload is active: no safe recovery'), postreads
            why = lab_actions.rejection(reads['global-sessions'].reading, control, component, reference, role)
            if why is not None:
                return 'UNEXPECTED', dict(outcome, why='not the intended rejection: %s' % why), postreads
            return 'OK', outcome, postreads
        return settle

    def _direct_record(self, record, control, role, **fields):
        value = dict(fields, record=record, control=control, role=role, wall_ns=self._wall())
        number = self.ledger.record('direct-control', value)
        self.direct.setdefault(control, {})[record] = dict(value, number=number, kind='direct-control')
        return number

    # ---------------------------------------------- the full user setup

    def _serials(self, reading):
        """Every serial a typed inventory lists, kept through reopening: no later user may reuse
        one."""
        for u in reading['users']:
            self.serials_seen.setdefault(u['serial'], u['id'])

    def _entry(self, number, kind, before):
        """A complete ledger entry's content when it is of that kind and precedes `before`, or
        None."""
        if type(number) is not int or not 0 < number < before:
            return None
        entry = self.ledger.entries[number - 1]
        return entry.content if entry.kind == kind and entry.complete else None

    @staticmethod
    def _streams(result):
        return result.stdout.decode('utf-8', 'surrogateescape'), result.stderr.decode('utf-8', 'surrogateescape')

    def _capture_reply(self, entry):
        """A complete capture's reply as a reader saw it: its exit status when it exited, else None,
        and both streams as text."""
        result = entry.content.get('result') or {}
        streams = []
        for name in ('stdout', 'stderr'):
            data = _regular_bytes(entry.path / name, int(self.limits['read_stdout_max']) + (1 << 20))
            if data is None:
                raise BrokerError('capture %d has no %s' % (entry.number, name))
            streams.append(data.decode('utf-8', 'surrogateescape'))
        code = result.get('exit') if result.get('completion') == 'exited' else None
        return (code,) + tuple(streams)

    def _write_setup(self, record, **fields):
        """Records one user setup step durably, and returns it."""
        value = dict(fields, record=record, wall_ns=self._wall())
        why = full_users.setup_problem(value)
        if why is not None:
            raise BrokerError(why)
        number = self.ledger.record('user-setup', value)
        value = dict(value, number=number, kind='user-setup')
        self.created.setdefault(value['action_id'], {})[record] = value
        return value

    def _identify(self, action_id, group):
        """Identifies a created user from a whole inventory group and records it: (record, None) or
        (None, why)."""
        created = self.created[action_id]['CREATED']
        user, why = full_users.identify(created, group.reading)
        if user is None:
            return None, why
        return self._write_setup('IDENTIFIED', action_id=action_id, begin=created['begin'], created=created['number'],
                                 user=user['id'], serial=user['serial'], type=user['type'], flags=user['flags'],
                                 inventory_group=group.number), None

    def _setup_record(self, c):
        """One complete user setup record into the broker's state, checked against what it names. A
        CREATED record must belong to a use of the admitted create action, name that use's own
        create capture, whose recorded reply names the same user ID, and the whole inventory read
        just before it, with the users and every serial known then. An IDENTIFIED record must
        follow its CREATED record and name a later whole inventory group that identifies exactly
        that user. Anything else refuses the reopening: a changed copy never moves or invents a
        created user. USER_PIN's and CE_SENTINEL's records are checked by their own rules."""
        if c.get('record') in health_records.SETUP_RECORDS:
            self._health_setup_record(c)
            return
        why = full_users.setup_problem(c)
        spec = self.specs.get(c.get('action_id')) if why is None else None
        begin = self._entry(c.get('begin'), 'lab-action', c['number']) if why is None else None
        if why is None and (spec is None or spec['type'] not in lab_actions.CREATING_TYPES or begin is None
                            or begin.get('record') != 'BEGIN' or begin.get('action_id') != c['action_id']):
            why = 'it names no use of an admitted create action'
        records = self.created.get(c['action_id'], {}) if why is None else {}
        if why is None and c['record'] == 'CREATED':
            why = 'a second CREATED record' if records else self._created_problem(c, spec)
        elif why is None:
            created = records.get('CREATED')
            if created is None or 'IDENTIFIED' in records or c['created'] != created['number']:
                why = 'an IDENTIFIED record without its CREATED record, or a second one'
            else:
                why = self._identified_problem(c, created)
        if why is not None:
            raise BrokerError('the ledger holds user setup record %d that its evidence does not make: %s'
                              % (c['number'], why))
        self.created.setdefault(c['action_id'], {})[c['record']] = c

    def _created_problem(self, c, spec):
        if not 0 < c['capture'] < c['number'] or self.ledger.entries[c['capture'] - 1].kind != 'capture':
            return 'its capture is not a capture before it'
        capture = self.ledger.entries[c['capture'] - 1]
        intent = capture.content.get('intent') or {}
        if (not capture.complete or intent.get('lab_action') != c['begin']
                or intent.get('operation') != 'lab-action-effect'
                or intent.get('command') != full_users.create_command(spec['parameters']['name'])):
            return "its capture is not its own action's whole create"
        if full_users.classify_create(*self._capture_reply(capture)) != ('CREATED', c['user']):
            return 'its capture does not name that user ID'
        before = self._entry(c['before_group'], 'group', c['capture'])
        if (before is None or before.get('reader') != 'inventory' or before.get('status') != 'facts'
                or (before.get('lab_action'), before.get('part')) != (c['begin'], 'create-inventory')):
            return 'it names no whole inventory its action read before the create'
        if c['before_users'] != sorted(u['id'] for u in before['reading']['users']):
            return 'its users before the create are not those of the inventory it names'
        if c['serials_before'] != sorted(self.serials_seen):
            return 'its serials before the create are not every serial an inventory had listed'
        return None

    def _identified_problem(self, c, created):
        group = self._entry(c['inventory_group'], 'group', c['number'])
        if (group is None or c['inventory_group'] < created['number'] or group.get('reader') != 'inventory'
                or group.get('status') != 'facts'):
            return 'it names no whole inventory read after the create'
        user, why = full_users.identify(created, group['reading'])
        if user is None:
            return 'its inventory does not identify the user: %s' % why
        if (user['id'], user['serial'], user['type'], user['flags']) != (c['user'], c['serial'], c['type'], c['flags']):
            return 'its user is not the one its inventory lists'
        return None

    def _check_typed(self, c):
        """Refuses a reopening whose typed user reading is not the one its own captures give, when
        the reader can read them again: the same parse over the recorded replies, the processes
        over the inventory group they name. A changed reading, or captures of other reads, is a
        changed copy. The two compare as their exact encodings, so a number never passes for a
        boolean it compares equal to."""
        rederive = getattr(self.reader, 'rederive', None)
        if c.get('status') != 'facts' or rederive is None:
            return
        captures = self._group_captures(c, 'the typed reading of group %d names no capture of its own')
        inventory = None
        if c['reader'] == 'systemui-processes':
            source = self._entry(c.get('inventory_group'), 'group', c['number'])
            inventory = source.get('reading') if source and source.get('reader') == 'inventory' else None
        try:
            value = rederive(c['reader'], captures, inventory)
        except (readers.Unavailable, readers.Unclassified, ValueError, KeyError, TypeError) as error:
            raise BrokerError('the typed reading of group %d is not what its captures give: %s'
                              % (c['number'], error)) from error
        if value is not NotImplemented and ledgers.encode_json(value) != ledgers.encode_json(c.get('reading')):
            raise BrokerError('the typed reading of group %d is not what its captures give' % c['number'])

    def _group_captures(self, c, refusal):
        """A group's recorded captures as its reader saw them, in order: (command, exit status or
        None, standard output, standard error). A number that is no capture before the group
        refuses the reopening with `refusal`, formatted with the group's number."""
        captures = []
        for n in c.get('captures', ()):
            if type(n) is not int or not 0 < n < c['number'] or self.ledger.entries[n - 1].kind != 'capture':
                raise BrokerError(refusal % c['number'])
            entry = self.ledger.entries[n - 1]
            captures.append(((entry.content.get('intent') or {}).get('command'),) + self._capture_reply(entry))
        return captures

    def _user_commands(self, spec, user):
        """Every fixed command a user action may send for its resolved user."""
        kind, parameters = spec['type'], spec['parameters']
        if kind == 'USER_CREATE':
            return {full_users.create_command(parameters['name'])}
        if user is None:
            return set()
        target = user['id']
        if kind == 'USER_START':
            return {full_users.start_command(target)}
        if kind == 'USER_SWITCH':
            return {full_users.switch_command(target), full_users.CURRENT, full_users.visible_command(target)}
        if kind == 'USER_SETUP':
            return ({full_users.step_command(step) for step in parameters['steps']}
                    | {full_users.CURRENT, full_users.setup_command(target)})
        if kind in ('USER_PIN', 'CE_SENTINEL'):
            # The UI state helper's admitted reads for the user. USER_PIN's one effect is its
            # private constant command, which only the private input rule admits; CE_SENTINEL's
            # effect and readback are the work fixture's.
            return {health_compose.SHELL_IDENTITY, health_compose.HELPER_DIGEST,
                    health_compose.ui_state_command(target)}
        package = parameters['package']
        return {full_users.install_existing_command(target, package), full_users.enable_command(target, package),
                full_users.package_uid_command(0, package), full_users.package_uid_command(target, package),
                full_users.package_path_command(0, package), full_users.package_path_command(target, package)}

    def _try_read(self, command, text, parser, *args):
        """One read of an action's own: (its parsed value, None), or (None, why) when it did not
        complete or has no known form. A stop still raises."""
        try:
            result = command('lab-action-read', text)
            return parser(result.exit, *self._streams(result), *args), None
        except (readers.Unavailable, readers.Unclassified) as error:
            return None, '%s: %s' % (type(error).__name__, error)

    def _settle(self, read, done, deadline, polls=USER_POLLS):
        """Reads again with `read()` until `done(value)`, at most `polls` times, USER_POLL_S apart,
        while the deadline leaves room: the last value."""
        value = read()
        for _ in range(polls - 1):
            if done(value) or deadline - self._monotonic() < (USER_POLL_S + BOUND_COMMAND_MIN_S) * 1e9:
                break
            self._sleep(USER_POLL_S)
            value = read()
        return value

    def _act_user_create(self, context, command, begin, spec):
        """USER_CREATE: the one full secondary user. Its whole inventory and limits are read first:
        only the system user listed, switchable users supported, the type enabled, the system user
        without no_add_user and no maximum reached. The create's reply ID is recorded the moment it
        is read, CREATED, before anything else; a whole inventory read after it then identifies the
        user, IDENTIFIED, with its actual serial and type, never a guessed ID or serial. A refusal
        reply settles only when a whole inventory shows no new user. An inventory that is not read
        whole leaves the outcome uncertain: it never shows the user absent."""
        deadline = begin['deadline_monotonic_ns']
        pre = dict(context, purpose='user-precondition')
        reads = {name: self._read(name, dict(pre, part='create-' + name), deadline) for name in ('inventory',
                                                                                                  'user-limits')}
        groups = [g.number for g in reads.values()]
        if not all(g.ok for g in reads.values()):
            return 'REFUSED', {'groups': groups}, 'the whole user inventory or the user limits are unavailable', True, \
                groups
        before = reads['inventory'].reading
        why = full_users.creation_problem(before, reads['user-limits'].reading)
        if why is not None:
            return 'REFUSED', {'groups': groups, 'limits': reads['user-limits'].reading}, why, True, groups
        users = sorted(u['id'] for u in before['users'])
        result = command('lab-action-effect', full_users.create_command(spec['parameters']['name']))
        capture = self.ledger.last.number
        reply, detail = full_users.classify_create(result.exit, *self._streams(result))
        if reply == 'CREATED':
            self._write_setup('CREATED', action_id=spec['id'], begin=begin['number'], capture=capture, user=detail,
                              before_group=reads['inventory'].number, before_users=users,
                              serials_before=sorted(self.serials_seen))
        outcome = {'reply': reply, 'detail': detail, 'capture': capture}
        after = self._read('inventory', dict(context, purpose='user-postread', part='identify'), deadline)
        if not after.ok:
            return 'UNKNOWN', outcome, 'the whole inventory after the create is unavailable (%s): nothing is ' \
                'known absent' % after.reason, False, [after.number]
        if reply == 'CREATED':
            identified, why = self._identify(spec['id'], after)
            if identified is None:
                return 'UNEXPECTED', outcome, why, True, [after.number]
            outcome.update(user=identified['user'], serial=identified['serial'], type=identified['type'],
                           flags=identified['flags'], identified=identified['number'])
            return 'OK', outcome, None, True, [after.number]
        outcome['new_users'] = [u['id'] for u in after.reading['users'] if u['id'] not in users]
        if reply == 'REFUSED' and outcome['new_users']:
            return 'UNEXPECTED', outcome, 'the create reply refused, yet a whole inventory lists a new user', True, \
                [after.number]
        if reply == 'REFUSED':
            return 'FAILED', outcome, 'the user service refused the create', True, [after.number]
        return 'UNKNOWN', outcome, 'the create gave no qualified reply: its effect is unknown', False, [after.number]

    def _act_user_start(self, context, command, begin, user):
        """USER_START: a background start of the created user, listed whole, unmarked and stopped,
        with room under the running limit so that Android stops no running user for it. Exit status
        0 is not success: `Error: could not start user` on standard error is a failure. The outcome
        rests on a whole inventory read after the reply, polled until the user runs or the polls are
        spent, which must still list every user that ran before as running."""
        deadline = begin['deadline_monotonic_ns']
        pre, post = dict(context, purpose='user-precondition'), dict(context, purpose='user-postread')
        reads = {name: self._read(name, dict(pre, part='start-' + name), deadline) for name in ('inventory',
                                                                                                 'user-limits')}
        groups = [g.number for g in reads.values()]
        if not all(g.ok for g in reads.values()):
            return 'REFUSED', {'groups': groups}, 'the whole user inventory or the user limits are unavailable', True, \
                groups
        before = reads['inventory'].reading
        why = full_users.start_problem(before, reads['user-limits'].reading, user)
        if why is not None:
            return 'REFUSED', {'groups': groups}, why, True, groups
        result = command('lab-action-effect', full_users.start_command(user['id']))
        outcome = {'reply': full_users.classify_start(result.exit, *self._streams(result)),
                   'capture': self.ledger.last.number}
        postreads = []

        def read():
            group = self._read('inventory', dict(post, part='after-start'), deadline)
            postreads.append(group.number)
            return group

        def runs(group):
            found = full_users.find(group.reading, user['id']) if group.ok else []
            return len(found) == 1 and found[0]['state'] != 'NOT_RUNNING'
        after = self._settle(read, lambda g: outcome['reply'] != 'STARTED' or runs(g), deadline)
        if not after.ok:
            return 'UNKNOWN', outcome, 'the whole inventory after the start is unavailable', False, postreads
        found = full_users.find(after.reading, user['id'])
        outcome.update(condition=full_users.condition(after.reading, user['id']),
                       stopped=[list(p) for p in full_users.still_running(before, after.reading)])
        if len(found) != 1 or (found[0]['serial'], found[0]['type']) != (user['serial'], user['type']):
            return 'UNEXPECTED', outcome, 'a whole inventory no longer lists the created user as identified', True, \
                postreads
        if outcome['reply'] == 'UNRECOGNIZED':
            return 'UNKNOWN', outcome, 'the start gave no qualified reply: its effect is unknown', False, postreads
        if outcome['stopped']:
            return 'UNEXPECTED', outcome, 'a user that ran before the start no longer runs', True, postreads
        if outcome['reply'] == 'STARTED' and runs(after):
            return 'OK', outcome, None, True, postreads
        if outcome['reply'] == 'STARTED':
            return 'UNEXPECTED', outcome, 'the reply said started, yet the user does not run', True, postreads
        if runs(after):
            return 'UNEXPECTED', outcome, 'the reply reported a failure, yet the user runs', True, postreads
        return 'FAILED', outcome, 'the start failed: its reply reported the failure on standard error, with exit ' \
            'status 0', True, postreads

    def _act_user_switch(self, context, command, begin, user):
        """USER_SWITCH: a running user to the foreground. Its whole inventory and the current user
        are read first: the user runs in the background, both reads name the same current user,
        and the outgoing user, unless it is the system user, may run in the background, since
        Android stops one that may not (UserController.java:2736-2750). After the reply the
        foreground, the state and the visibility are each confirmed by their own read, polled
        until all hold or the polls are spent: `am get-current-user`, a whole inventory naming the
        user current and running, and `cmd user is-user-visible`. Every user that ran before must
        still run."""
        deadline = begin['deadline_monotonic_ns']
        pre, post = dict(context, purpose='user-precondition'), dict(context, purpose='user-postread')
        before = self._read('inventory', dict(pre, part='switch-inventory'), deadline)
        current, why = self._try_read(command, full_users.CURRENT, full_users.parse_current)
        groups = [before.number]
        if not before.ok or current is None:
            return 'REFUSED', {'groups': groups}, 'the whole inventory or the current user is unavailable: %s' % (
                why or before.reason), True, groups
        found = full_users.find(before.reading, user['id'])
        outgoing = full_users.find(before.reading, current)
        if len(found) != 1 or found[0]['serial'] != user['serial'] or found[0]['state'] == 'NOT_RUNNING':
            why = 'the user is not listed running as resolved: a switch never starts a user'
        elif before.reading['current_user'] != current:
            why = 'the two current user reads disagree'
        elif current == user['id']:
            why = 'the user is in the foreground already'
        elif current != 0 and (len(outgoing) != 1 or 'no_run_in_background' in outgoing[0]['restrictions']):
            why = 'the switch would stop user %d, which may not run in the background' % current
        if why is not None:
            return 'REFUSED', {'groups': groups, 'current': current}, why, True, groups
        result = command('lab-action-effect', full_users.switch_command(user['id']))
        outcome = {'reply': full_users.classify_switch(result.exit, *self._streams(result), user['id']),
                   'capture': self.ledger.last.number, 'outgoing': current}
        postreads = []

        def read():
            now, missing = self._try_read(command, full_users.CURRENT, full_users.parse_current)
            group = self._read('inventory', dict(post, part='after-switch'), deadline)
            postreads.append(group.number)
            visible, unseen = self._try_read(command, full_users.visible_command(user['id']), full_users.parse_visible)
            return {'current': now, 'group': group, 'visible': visible, 'missing': missing or unseen}

        def confirmed(poll):
            state = full_users.condition(poll['group'].reading, user['id']) if poll['group'].ok else None
            return (poll['current'] == user['id'] and state is not None and state['condition'] == 'FOREGROUND'
                    and poll['visible'] is True)
        poll = self._settle(read, lambda p: outcome['reply'] != 'SWITCHED' or confirmed(p), deadline)
        group = poll['group']
        if outcome['reply'] == 'UNRECOGNIZED':
            return 'UNKNOWN', outcome, 'the switch gave no qualified reply: its effect is unknown', False, postreads
        if poll['current'] is None or poll['visible'] is None or not group.ok:
            return 'UNKNOWN', outcome, 'a read after the switch is unavailable: %s' % (poll['missing'] or group.reason), \
                False, postreads
        state = full_users.condition(group.reading, user['id'])
        outcome.update(foreground=poll['current'], dump_current=group.reading['current_user'], visible=poll['visible'],
                       condition=state, stopped=[list(p) for p in full_users.still_running(before.reading,
                                                                                         group.reading)])
        if outcome['stopped']:
            return 'UNEXPECTED', outcome, 'a user that ran before the switch no longer runs', True, postreads
        if outcome['reply'] != 'SWITCHED':
            if poll['current'] == current and group.reading['current_user'] == current:
                return 'FAILED', outcome, 'the switch failed, and user %d stays in the foreground' % current, True, \
                    postreads
            return 'UNEXPECTED', outcome, 'the switch reported a failure, yet the foreground changed', True, postreads
        if confirmed(poll):
            return 'OK', outcome, None, True, postreads
        if poll['current'] != user['id'] or group.reading['current_user'] != user['id']:
            return 'UNEXPECTED', outcome, 'the switch reported done, yet user %d is current' % poll['current'], True, \
                postreads
        if state is None or state['condition'] != 'FOREGROUND':
            return 'UNEXPECTED', outcome, 'the user is current but does not run', True, postreads
        return 'UNEXPECTED', outcome, 'the user is current but not visible', True, postreads

    def _act_user_setup(self, context, command, begin, spec, user):
        """USER_SETUP: the image's own setup of the created user, in the foreground with CE storage
        unlocked. Its admitted key and tap steps drive the setup the image shows; nothing writes a
        setting. It settles only on the setup Android records: `user_setup_complete` 1 for the user,
        polled within the spec's settle bound, and a whole inventory showing the user initialized,
        current and unlocked. A setup that was already complete runs no step."""
        deadline = begin['deadline_monotonic_ns']
        pre, post = dict(context, purpose='user-precondition'), dict(context, purpose='user-postread')
        before = self._read('inventory', dict(pre, part='setup-inventory'), deadline)
        current, why = self._try_read(command, full_users.CURRENT, full_users.parse_current)
        value, unseen = self._try_read(command, full_users.setup_command(user['id']), full_users.parse_setup)
        groups = [before.number]
        if not before.ok or current is None or value is None:
            return 'REFUSED', {'groups': groups}, 'a read before the setup is unavailable: %s' % (
                why or unseen or before.reason), True, groups
        state = full_users.condition(before.reading, user['id'])
        if current != user['id'] or state is None or state['condition'] != 'FOREGROUND' or not state['ce_unlocked']:
            return 'REFUSED', {'groups': groups, 'current': current, 'condition': state}, \
                'the user is not the foreground user with CE storage unlocked', True, groups
        found = full_users.find(before.reading, user['id'])[0]
        if value == '1' and found['flags'] & full_users.FLAG_INITIALIZED:
            return 'OK', {'already_complete': True, 'setup': value, 'groups': groups}, None, True, groups
        for at, step in enumerate(spec['parameters']['steps']):
            result = command('lab-action-effect', full_users.step_command(step))
            if full_users.classify_input(result.exit, *self._streams(result)) != 'INJECTED':
                return 'UNKNOWN', {'step': at}, 'setup step %d gave no qualified reply' % at, False, []
        settle_ms = spec['parameters']['settle_ms']
        settle_deadline = min(deadline, self._monotonic() + settle_ms * 1_000_000)
        polled = self._settle(lambda: self._try_read(command, full_users.setup_command(user['id']),
                                                     full_users.parse_setup),
                              lambda v: v[0] == '1', settle_deadline, polls=1 + settle_ms // int(USER_POLL_S * 1000))
        after = self._read('inventory', dict(post, part='after-setup'), deadline)
        outcome = {'setup': polled[0], 'steps': len(spec['parameters']['steps'])}
        if polled[0] is None or not after.ok:
            return 'UNKNOWN', outcome, 'a read after the setup is unavailable: %s' % (polled[1] or after.reason), \
                False, [after.number]
        state = full_users.condition(after.reading, user['id'])
        found = full_users.find(after.reading, user['id'])
        outcome.update(condition=state, initialized=bool(found and found[0]['flags'] & full_users.FLAG_INITIALIZED))
        if (polled[0] == '1' and outcome['initialized'] and state is not None and state['condition'] == 'FOREGROUND'
                and state['ce_unlocked'] and after.reading['current_user'] == user['id']):
            return 'OK', outcome, None, True, [after.number]
        return 'UNEXPECTED', outcome, 'the setup Android records did not complete', True, [after.number]

    def _act_user_fixture(self, context, command, begin, spec, user):
        """USER_FIXTURE: one ordinary fixture for the created user. It must be installed for the
        system user already, at a base APK whose bytes are the pinned ones. Then
        `pm install-existing` and `pm enable` for the user, whose replies prove nothing by
        themselves; it settles only when reads show the package installed for the user under the
        user's UID of the same app ID, at the same base APK with the pinned bytes, and enabled."""
        package, pin = spec['parameters']['package'], spec['inputs'][0]
        target = user['id']
        uid, why = self._try_read(command, full_users.package_uid_command(0, package), full_users.parse_package_uid,
                                  package, 0)
        path, unseen = (self._try_read(command, full_users.package_path_command(0, package),
                                       full_users.parse_package_path, package) if uid is not None else (None, None))
        digest, unread = (self._try_read(command, full_users.digest_command(path, package), full_users.parse_digest,
                                         path) if path is not None else (None, None))
        if digest is None or digest != pin['sha256']:
            return 'REFUSED', {'uid': uid, 'path': path, 'digest': digest}, why or unseen or unread or (
                'the fixture is not installed for the system user with its pinned bytes'), True, []
        installed, why = self._try_read(command, full_users.package_uid_command(target, package),
                                        full_users.parse_package_uid, package, target)
        if why is not None:
            return 'REFUSED', {'uid': uid}, why, True, []
        outcome = {'system_uid': uid, 'path': path}
        if installed is None:
            result = command('lab-action-effect', full_users.install_existing_command(target, package))
            outcome['install'] = full_users.classify_install_existing(result.exit, *self._streams(result), package,
                                                                       target)
            if outcome['install'] == 'UNRECOGNIZED':
                return 'UNKNOWN', outcome, 'the install gave no qualified reply: its effect is unknown', False, []
            if outcome['install'] == 'MISSING':
                return 'FAILED', outcome, 'the package does not exist for the install', True, []
        result = command('lab-action-effect', full_users.enable_command(target, package))
        outcome['enabled'] = full_users.classify_enable(result.exit, *self._streams(result), package)
        if outcome['enabled'] == 'UNRECOGNIZED':
            return 'UNKNOWN', outcome, 'the enable gave no qualified reply: its effect is unknown', False, []
        reads = [self._try_read(command, full_users.package_uid_command(target, package), full_users.parse_package_uid,
                                package, target),
                 self._try_read(command, full_users.package_path_command(target, package),
                                full_users.parse_package_path, package)]
        if reads[1][0] is not None:
            reads.append(self._try_read(command, full_users.digest_command(reads[1][0], package),
                                        full_users.parse_digest, reads[1][0]))
        missing = [r[1] for r in reads if r[1] is not None]
        if missing:
            return 'UNKNOWN', outcome, 'a read after the install is unavailable: %s' % missing[0], False, []
        outcome.update(uid=reads[0][0], user_path=reads[1][0], digest=reads[2][0] if len(reads) > 2 else None)
        expected = target * full_users.PER_USER_RANGE + uid % full_users.PER_USER_RANGE
        if (outcome['uid'] == expected and outcome['user_path'] == path and outcome['digest'] == pin['sha256']
                and outcome['enabled'] == 'enabled'):
            return 'OK', outcome, None, True, []
        return 'UNEXPECTED', outcome, 'the fixture is not read installed and enabled for the user with its pinned ' \
            'bytes', True, []

    # ---------------------------------------------- the disposable lab PIN and the CE sentinel

    def _ui_state(self, command, user):
        """One user's UI state through the fixed helper, as an action reads it for itself, between
        reads of the shell user and the helper's pinned bytes: (reading, the helper's capture,
        None) or (None, None, why). An unavailable answer is None in the reading, never false."""
        captures = []

        def run(text):
            result = command('lab-action-read', text)
            captures.append((text, self.ledger.last.number))
            return (result.exit,) + self._streams(result)
        try:
            reading = health_compose.read_ui_state(run, user)
        except (readers.Unavailable, readers.Unclassified, ValueError) as error:
            return None, None, '%s: %s' % (type(error).__name__, error)
        helper = [n for text, n in captures if text == health_compose.ui_state_command(user)]
        return reading, helper[0], None

    def _new_pin(self, digits):
        """A fresh disposable lab PIN of that many digits, from the broker's own random source: no
        caller supplies it, so no personal credential can enter."""
        value = int.from_bytes(self._ids(16), 'big') % (10 ** digits)
        return '%0*d' % (digits, value)

    def _keep_private(self, name, value):
        """Writes one private record, exclusively, synced and its name synced, in the private store,
        a directory outside the broker's evidence that it creates on first use."""
        directory = self._private
        if not directory.is_dir():
            os.makedirs(directory, mode=0o700, exist_ok=True)
            self._sync_dir(directory.parent)
        data = evidence.canonical(value)
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, data)
            self._sync_fd(fd)
        finally:
            os.close(fd)
        self._sync_dir(directory)

    def private_pin(self, serial):
        """The disposable lab PIN USER_PIN generated for one serial, from the private store, for
        a later credential unlock: (PIN, its intent record) or None. It never enters the ledger."""
        intent = self.pins.get(serial, {}).get('PIN_INTENT')
        if intent is None or self._private is None:
            return None
        data = _regular_bytes(self._private / intent['private'], 4096)
        try:
            value = evidence.parse(data or b'')
        except evidence.SideError:
            return None
        if (value.get('user'), value.get('serial'), value.get('begin')) != (intent['user'], serial, intent['begin']):
            return None
        return value['pin'], intent

    def _write_health_setup(self, record, **fields):
        """Records one USER_PIN or CE_SENTINEL setup step durably, and returns it."""
        value = dict(fields, record=record, wall_ns=self._wall())
        why = health_records.setup_problem(value)
        if why is not None:
            raise BrokerError(why)
        number = self.ledger.record('user-setup', value)
        value = dict(value, number=number, kind='user-setup')
        target = self.pins if record.startswith('PIN_') else self.sentinels
        target.setdefault(value['serial'], {})[record] = value
        return value

    def _act_user_pin(self, context, command, begin, spec, user):
        """USER_PIN: a disposable lab PIN for a user with CE storage unlocked and no secure
        credential, through `locksettings set-pin`, which actually changes the credential
        (LockSettingsShellCommand.java:299-306; LockSettingsService.java:3180-3201). The broker
        generates the PIN and keeps it in the private store before anything else, then records
        PIN_INTENT naming that private record by a fresh name, never the PIN; only then is the
        effect sent, the constant `sh` given the command on private standard input. A user with a
        secure credential, or one whose state is unknown, is refused: a PIN is never replaced or
        guessed, and no old credential is ever passed. The UI state helper's device secure answer
        decides: PIN_SET only when it reads true after a reply of success. An uncertain effect
        stays uncertain and is never repeated; its PIN stays in the private store. The effect's
        output, which success never has, is withheld from the ledger whole, decoded or not."""
        deadline = begin['deadline_monotonic_ns']
        serial = user['serial']
        if self._private is None:
            return 'REFUSED', None, 'no private store is admitted for the disposable PIN', True, []
        if self.pins.get(serial):
            return 'REFUSED', None, 'a PIN was already attempted for this serial: it is never replaced', True, []
        inventory = self._read('inventory', dict(context, purpose='user-precondition', part='pin-inventory'), deadline)
        groups = [inventory.number]
        state = full_users.condition(inventory.reading, user['id']) if inventory.ok else None
        if state is None or not state['ce_unlocked']:
            return 'REFUSED', {'groups': groups}, 'a whole inventory does not show the user with CE storage unlocked', \
                True, groups
        before, readback, why = self._ui_state(command, user['id'])
        if before is None:
            return 'REFUSED', {'groups': groups}, 'the UI state is unavailable: %s' % why, True, groups
        if before['values']['device_secure'] is not False:
            return 'REFUSED', {'groups': groups, 'device_secure': before['values']['device_secure']}, \
                'the user has a secure credential, or whether it has one is unknown: none is replaced', True, groups
        digits = spec['parameters']['digits']
        pin = self._new_pin(digits)
        name = PRIVATE_PIN % proto.fresh_id(self._ids)
        try:
            self._keep_private(name, {'action_id': spec['id'], 'begin': begin['number'], 'user': user['id'],
                                      'serial': serial, 'pin': pin})
        except (OSError, evidence.SideError) as error:
            raise self._writer_failed('the private PIN record could not be kept: %s' % error) from error
        intent = self._write_health_setup('PIN_INTENT', action_id=spec['id'], begin=begin['number'], user=user['id'],
                                          serial=serial, digits=digits, private=name, readback=readback)

        def withheld(output):
            # The effect's withheld output, up to PRIVATE_KEEP bytes of each field, with its sizes.
            error = (output['error'] or '').encode('utf-8', 'backslashreplace')
            self._keep_private(name + '-withheld', {
                'stdout_hex': output['stdout'][:PRIVATE_KEEP].hex(), 'stdout_bytes': len(output['stdout']),
                'stderr_hex': output['stderr'][:PRIVATE_KEEP].hex(), 'stderr_bytes': len(output['stderr']),
                'residual_hex': output['residual'][:PRIVATE_KEEP].hex(), 'residual_bytes': output['residual_bytes'],
                'error_hex': error[:PRIVATE_KEEP].hex()})
        private = {'input': (PIN_INPUT % (user['id'], pin)).encode('ascii'), 'keep': withheld}
        outcome = {'intent': intent['number']}
        try:
            result = command('lab-action-effect', PRIVATE_COMMAND, private=private)
        except readers.Unavailable as error:
            return 'UNKNOWN', outcome, 'the PIN effect did not complete: %s' % error, False, groups
        entry = self.ledger.last
        outcome.update(capture=entry.number, withheld=bool(entry.content['result'].get('withheld')))
        outcome['reply'] = 'UNRECOGNIZED' if outcome['withheld'] else _pin_reply(result.exit, result.stdout,
                                                                                    result.stderr)
        after, readback, why = self._ui_state(command, user['id'])
        if after is None:
            return 'UNKNOWN', outcome, 'the UI state after the PIN is unavailable: %s' % why, False, groups
        outcome['device_secure'] = secure = after['values']['device_secure']
        if outcome['reply'] == 'UNRECOGNIZED' or secure is None:
            return 'UNKNOWN', outcome, 'whether the PIN was set is unknown', False, groups
        if outcome['reply'] == 'SET' and secure:
            done = self._write_health_setup('PIN_SET', action_id=spec['id'], begin=begin['number'],
                                            intent=intent['number'], user=user['id'], serial=serial,
                                            capture=entry.number, readback=readback)
            outcome['set'] = done['number']
            return 'OK', outcome, None, True, groups
        if outcome['reply'] == 'FAILED' and not secure:
            return 'FAILED', outcome, 'the PIN was refused, and the user has no secure credential', True, groups
        return 'UNEXPECTED', outcome, 'the PIN reply and the credential the helper reads disagree', True, groups

    def _act_ce_sentinel(self, context, command, begin, spec, user):
        """CE_SENTINEL: the work fixture keeps a fresh nonce in its own CE storage, for a user whose
        CE storage a whole inventory and the framework both read unlocked. SENTINEL_INTENT records
        the nonce before the effect, the fixture's fixed write; SENTINEL_SET only when the
        fixture's own read only readback shows exactly that nonce. That record is the origin bit 3
        compares the fixture's CE storage with after an unlock. A serial gets one sentinel, never
        rewritten. An uncertain write stays uncertain and is never repeated."""
        deadline = begin['deadline_monotonic_ns']
        serial, package = user['serial'], spec['parameters']['package']
        if self.sentinels.get(serial):
            return 'REFUSED', None, 'a CE sentinel was already attempted for this serial: it is never rewritten', True, []
        inventory = self._read('inventory', dict(context, purpose='user-precondition', part='sentinel-inventory'),
                               deadline)
        groups = [inventory.number]
        state = full_users.condition(inventory.reading, user['id']) if inventory.ok else None
        if state is None or not state['ce_unlocked']:
            return 'REFUSED', {'groups': groups}, 'a whole inventory does not show the user with CE storage unlocked', \
                True, groups
        before, readback, why = self._ui_state(command, user['id'])
        if before is None or before['values']['ce_unlocked'] is not True:
            return 'REFUSED', {'groups': groups}, 'the framework does not read CE storage unlocked: %s' % (
                why or 'it reads %s' % before['values']['ce_unlocked']), True, groups
        nonce = proto.fresh_id(self._ids)
        intent = self._write_health_setup('SENTINEL_INTENT', action_id=spec['id'], begin=begin['number'],
                                          user=user['id'], serial=serial, package=package, nonce=nonce,
                                          readback=readback)
        binding = {'id': user['id'], 'serial': serial, 'type': user['type'], 'package': package, 'nonce': nonce}
        outcome = {'intent': intent['number']}
        outcome['reply'] = self.work.write_sentinel(lambda c: command('lab-action-effect', c),
                                                    lambda c: command('lab-action-read', c), binding)
        if outcome['reply'] not in ('WRITTEN', 'REFUSED'):
            return 'UNKNOWN', outcome, 'the sentinel write gave no qualified reply: its effect is unknown', False, groups
        captures = []

        def read(text):
            result = command('lab-action-read', text)
            captures.append(self.ledger.last.number)
            return result
        try:
            found = self.work.read_sentinel(read, binding)
        except (readers.Unavailable, readers.Unclassified, ValueError) as error:
            return 'UNKNOWN', outcome, 'the sentinel readback is unavailable: %s' % error, False, groups
        outcome['found'] = found
        if len(captures) != 1:
            return 'UNKNOWN', outcome, 'the sentinel readback is not one read', False, groups
        if outcome['reply'] == 'WRITTEN' and found == {'status': 'PRESENT', 'nonce': nonce}:
            done = self._write_health_setup('SENTINEL_SET', action_id=spec['id'], begin=begin['number'],
                                            intent=intent['number'], user=user['id'], serial=serial, nonce=nonce,
                                            readback=captures[0])
            outcome['set'] = done['number']
            return 'OK', outcome, None, True, groups
        if outcome['reply'] == 'REFUSED' and found.get('status') == 'ABSENT':
            return 'FAILED', outcome, 'the fixture refused the sentinel, and its CE storage holds none', True, groups
        return 'UNEXPECTED', outcome, "the fixture's CE readback is not the sentinel it was given", True, groups

    def _health_setup_record(self, c):
        """One USER_PIN or CE_SENTINEL setup record into the broker's state, checked against what it
        names. An intent must follow its own BEGIN of an admitted spec of its type, be the first of
        its serial, and name the action's own helper read before it, whose reply reads the user
        without a secure credential, or with CE storage unlocked. A settlement must follow its
        intent, name the action's own effect and a later readback whose reply proves it: the
        helper reading the user secure, or the fixture's readback showing exactly the nonce.
        Anything else refuses the reopening: a changed copy never moves or invents a credential
        or a CE origin."""
        why = health_records.setup_problem(c)
        kind = 'USER_PIN' if c.get('record', '').startswith('PIN_') else 'CE_SENTINEL'
        spec = self.specs.get(c.get('action_id')) if why is None else None
        begin = self._entry(c.get('begin'), 'lab-action', c['number']) if why is None else None
        if why is None and (spec is None or spec['type'] != kind or begin is None or begin.get('record') != 'BEGIN'
                            or begin.get('action_id') != c['action_id']
                            or (begin['resolved_user']['id'], begin['resolved_user']['serial']) != (c['user'],
                                                                                                   c['serial'])):
            why = 'it names no use of an admitted %s of its user' % kind
        target = self.pins if kind == 'USER_PIN' else self.sentinels
        kept = target.get(c['serial'], {}) if why is None else {}
        intent_name = 'PIN_INTENT' if kind == 'USER_PIN' else 'SENTINEL_INTENT'
        if why is None and c['record'] == intent_name:
            why = ('a second intent for the serial' if kept else
                   self._readback_problem(c, c['begin'], kind, before=True))
        elif why is None:
            intent = kept.get(intent_name)
            if intent is None or c['intent'] != intent['number'] or len(kept) != 1 or intent['begin'] != c['begin']:
                why = 'a settlement without its intent, or a second one'
            elif kind == 'CE_SENTINEL' and c['nonce'] != intent['nonce']:
                why = 'a settlement of another nonce than its intent'
            else:
                why = self._readback_problem(c, intent['number'], kind, before=False)
        if why is not None:
            raise BrokerError('the ledger holds health setup record %d that its evidence does not make: %s'
                              % (c['number'], why))
        target.setdefault(c['serial'], {})[c['record']] = c

    def _readback_problem(self, c, after, kind, before):
        """Why a health setup record's named captures do not prove it, or None."""
        def own(number, low):
            entry = self.ledger.entries[number - 1] if type(number) is int and low < number < c['number'] else None
            intent = (entry.content.get('intent') or {}) if entry is not None and entry.kind == 'capture' else {}
            return entry if entry is not None and entry.complete and intent.get('lab_action') == c['begin'] else None
        readback = own(c['readback'], after)
        if readback is None:
            return 'its readback is not a whole capture of its own action after its intent'
        command = readback.content['intent']['command']
        code, stdout, stderr = self._capture_reply(readback)
        if kind == 'CE_SENTINEL' and not before:
            if self.work is None:
                return 'the work fixture adapter that reads the sentinel is not admitted'
            try:
                found = self.work.parse_sentinel(code, stdout, stderr, {'id': c['user'], 'serial': c['serial'],
                                                                         'nonce': c['nonce']})
            except (readers.Unavailable, readers.Unclassified, ValueError) as error:
                return 'its readback has no known form: %s' % error
            return None if found == {'status': 'PRESENT', 'nonce': c['nonce']} else 'its readback shows another nonce'
        if command != health_compose.ui_state_command(c['user']):
            return 'its readback is not the UI state helper for its user'
        try:
            reading = health_compose.parse_ui_state(code, stdout, stderr, c['user'])
        except readers.Unclassified as error:
            return 'its readback has no known form: %s' % error
        wanted = {('USER_PIN', True): ('device_secure', False), ('USER_PIN', False): ('device_secure', True),
                  ('CE_SENTINEL', True): ('ce_unlocked', True)}[(kind, before)]
        if reading['values'][wanted[0]] is not wanted[1]:
            return 'its readback does not read %s %s' % wanted
        if kind == 'USER_PIN' and not before:
            effect = own(c['capture'], after)
            intent = (effect.content.get('intent') or {}) if effect is not None else {}
            if (effect is None or intent.get('operation') != 'lab-action-effect' or intent.get('command') != PRIVATE_COMMAND
                    or intent.get('private_input') is not True or not effect.number < c['readback']
                    or effect.content['result'].get('withheld')
                    or _pin_reply(*self._capture_reply(effect)) != 'SET'):
                return 'its effect is not its own private PIN command, replying success, before its readback'
        return None

    def systemui_processes(self, purpose):
        """Each listed user's genuine main SystemUI process, read between generations: a whole
        typed inventory, then the process discovery over it, each the broker's own recorded group
        and never a deployment fact. Returns (inventory group, process group or None)."""
        if self.admission['version'] != 3 or not self.reader.users_admitted:
            raise BrokerError('the process discovery needs a version 3 admission and its full user reader')
        if self.open_generation is not None:
            raise BrokerError('the process discovery never runs beside a generation')
        if not isinstance(purpose, str) or not purpose.strip():
            raise BrokerError('the process discovery names its purpose')
        self._fence()
        context = {'request': None, 'generation': None, 'purpose': 'systemui-processes', 'reason': purpose}
        inventory = self._group('inventory', self.reader.inventory, context, None, emitted=False)
        if not inventory.ok:
            return inventory, None
        reading = inventory.reading
        processes = self._group('systemui-processes', lambda: self.reader.systemui_processes(reading),
                                dict(context, inventory_group=inventory.number), None, emitted=False)
        return inventory, processes

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
        # The adapter may name what it established, the capture conditions and the credential unlock
        # bits 2 and 3 judge, as one result of its exact form. A result of no known form settles
        # nothing: the use is unrecognized.
        result = None
        if isinstance(classification, tuple) and len(classification) == 2:
            classification, result = classification
            if classification == 'PREPARED' and health_records.preparation_problem(
                    result, user['id'], user['serial'], binding['criteria'], begin_record['operation']) is not None:
                classification = 'UNRECOGNIZED'
            if classification != 'PREPARED':
                result = None
        if classification not in ('PREPARED', 'REFUSED', 'UNRECOGNIZED'):
            return 'UNKNOWN', None, 'the preparation gave no qualified form', False, [begin.number, end.number]
        outcome = {'classification': classification, 'criteria': binding['criteria'], 'challenge': binding['challenge'],
                   'result': result,
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
        two clock reads and kept as a compound group that is never a deployment fact: the user's
        process, history and current error baseline (health_baseline.py), whose facts must have
        their exact form (health_records.py). The user must show running and unmarked in a whole
        typed inventory. A probe relies only on the last whole baseline that health_baseline.select
        admits: completed by its window's start in its own framework instance, so taken before the
        round that opens the window, or for a user newly unlocked in the window, taken after that
        and before its first full probe; and complete. An unavailable read is kept and never
        replaces the last whole one. Returns its group."""
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
        if status == 'facts':
            why = health_records.baseline_facts_problem(projection['facts'], user, serial)
            if why is not None:
                status, reason = 'unclassified', 'baseline facts of no known form: %s' % why
        number, _ = self._compound('health-baseline', context, [c[0] for c in captured],
                                   {'inventory': inventory.number, 'begin': begin.number,
                                    'end': end.number if end is not None else None},
                                   status, reason, brackets, {'projection': _side(projection)},
                                   extra={'user': user, 'serial': serial,
                                          'projection': _side(projection) if status == 'facts' else None,
                                          'complete': status == 'facts' and projection['facts']['complete']})
        if status == 'stopped':
            raise Stopped(reason)
        return number

    def identity_baseline(self, purpose):
        """Each listed user's expected SystemUI identity, read between generations while the
        factory copy is active, kept as a compound group that is never a deployment fact: between
        two clock reads of one boot and framework instance, the factory and active copies, a whole
        typed inventory and the process discovery over it (health_baseline.identity_projection). It
        qualifies only with the factory copy active, its bytes the factory's, and the system user's
        process the one the active read names. Each serial's first qualified identity is bit 0's
        expectation from then on; a later one that differs is named as a conflict and never
        replaces it, and no boot or framework change touches it. Returns its group."""
        if self.admission['version'] != 3 or not self.reader.users_admitted or not self.reader.health_admitted:
            raise BrokerError('an identity baseline needs a version 3 admission, its full user reader and its '
                              'health reader')
        if self.open_generation is not None:
            raise BrokerError('an identity baseline is never read beside a generation')
        if not isinstance(purpose, str) or not purpose.strip():
            raise BrokerError('an identity baseline names its purpose')
        self._fence()
        context = {'request': None, 'generation': None, 'purpose': 'identity-baseline', 'reason': purpose}
        begin = self._clock_group(dict(context, part='begin'), None, emitted=False)
        groups, end = {}, None
        if begin.ok:
            boot = begin.reading['boot']
            for name in ('factory', 'active'):
                groups[name] = self._group(name, getattr(self.reader, name), dict(context, part=name), boot,
                                           emitted=False)
            groups['inventory'] = self._group('inventory', self.reader.inventory, dict(context, part='inventory'),
                                              None, emitted=False)
            if groups['inventory'].ok:
                listed = groups['inventory'].reading
                groups['processes'] = self._group(
                    'systemui-processes', lambda: self.reader.systemui_processes(listed),
                    dict(context, part='processes', inventory_group=groups['inventory'].number), None, emitted=False)
            end = self._clock_group(dict(context, part='end'), boot, emitted=False)
        children = {name: group.number for name, group in groups.items()}
        children.update(begin=begin.number, end=end.number if end is not None else None)
        # The projection is what the children's own recorded captures give when the reader reads
        # them again, exactly as a reopening reads them: nothing the live reads returned decides it.
        brackets, derived = self._identity_derived(children, None)
        projection, status, reason = None, 'unavailable', 'the read bracket changed or did not complete'
        if derived is NotImplemented:
            status, reason = 'unclassified', UNREAD
        elif brackets is not None:
            status, projection = derived
            reason = None if status == 'facts' else 'an identity baseline of no known form'
        known = {serial: kept['identity'] for serial, kept in self.identities.items()}
        conflicts = health_baseline.expected(known, projection)[1] if projection is not None else []
        number, _ = self._compound('identity-baseline', context, [], children, status, reason, brackets,
                                   {'projection': projection}, extra={'projection': projection, 'conflicts': conflicts})
        return number

    def _identity_derived(self, children, number):
        """An identity baseline's bracket, and its (status, projection) as its named children's own
        captures give it when the reader reads them again: health_baseline.identity_projection
        over the factory and active facts, the inventory and the process discovery over it, each
        read again from its recorded replies. The status and projection are NotImplemented when
        the reader cannot read a child again. `number` is the group's own ledger number, or None
        for one not yet written. The children must be this read's own groups: each a group of its
        reader, part and purpose, in the order they were read, the processes over that inventory,
        with no other identity baseline read among them. A child of another form, a child's
        summary that its captures do not give, or a reading they do not give refuses."""
        limit = len(self.ledger.entries) + 1 if number is None else number
        names = [name for name, _ in IDENTITY_CHILDREN]
        if (not isinstance(children, dict) or set(children) - set(names) or 'begin' not in children
                or 'end' not in children):
            raise BrokerError('an identity baseline names children of no known form')
        groups, last = {}, 0
        for name, reader in IDENTITY_CHILDREN:
            n = children.get(name)
            if n is None:
                continue
            entry = self.ledger.entries[n - 1] if type(n) is int and last < n < limit else None
            c = entry.content if entry is not None and entry.complete and entry.kind == 'group' else None
            if (c is None or c.get('reader') != reader or c.get('purpose') != 'identity-baseline'
                    or c.get('part') != name or c.get('request') is not None or c.get('generation') is not None
                    or (name == 'processes' and c.get('inventory_group') != children.get('inventory'))):
                raise BrokerError('an identity baseline names a child that is not its own %s read' % name)
            groups[name], last = c, n
        begun = groups.get('begin', {}).get('status') == 'facts'
        wanted = ({'begin', 'factory', 'active', 'inventory', 'end'} if begun else {'begin'})
        if begun and groups.get('inventory', {}).get('status') == 'facts':
            wanted.add('processes')
        if set(groups) != wanted or (children['end'] is None) == begun:
            raise BrokerError('an identity baseline names other children than its read makes')
        for n in range(children['begin'] + 1, limit):
            entry = self.ledger.entries[n - 1]
            if (entry.kind == 'group' and entry.complete and entry.content.get('purpose') == 'identity-baseline'
                    and n not in children.values()):
                raise BrokerError('another identity baseline read lies among the children of one')

        def clock(name):
            c = groups.get(name)
            return None if c is None else Group(c['number'], [], [], c['status'], None, c.get('reading'))
        brackets = self._brackets(clock('begin'), clock('end'))
        if brackets is None:
            return None, ('unavailable', None)
        rederive = getattr(self.reader, 'rederive', None)
        if rederive is None:
            return brackets, NotImplemented

        def again(name, inventory=None):
            c = groups.get(name)
            if c is None or c['status'] != 'facts':
                return None
            reader = dict(IDENTITY_CHILDREN)[name]
            try:
                value = rederive(reader, self._group_captures(c, 'an identity baseline child %d names no capture of '
                                                                 'its own'), inventory)
            except (readers.Unavailable, readers.Unclassified, ValueError, KeyError, TypeError) as error:
                raise BrokerError('the %s read of an identity baseline is not what its captures give: %s'
                                  % (name, error)) from error
            if value is NotImplemented:
                return value
            if reader in USER_READINGS:
                if ledgers.encode_json(value) != ledgers.encode_json(c.get('reading')):
                    raise BrokerError('the %s read of an identity baseline is not what its captures give' % name)
                return value
            summary = c.get('observations')
            keys = ('kind', 'classification', 'boot', 'instance', 'elapsed', 'user', 'serial')
            if (not isinstance(value, list) or not isinstance(summary, list) or len(value) != len(summary)
                    or any([f.get(k) for k in keys] != [o.get(k) for k in keys] or f.get('raw') != c.get('raw')
                           for f, o in zip(value, summary))):
                raise BrokerError('the %s read of an identity baseline is not what its captures give' % name)
            return value[0] if len(value) == 1 else None
        factory, active, inventory = again('factory'), again('active'), again('inventory')
        processes = again('processes', inventory) if inventory is not NotImplemented else None
        if any(value is NotImplemented for value in (factory, active, inventory, processes)):
            return brackets, NotImplemented
        projection = health_baseline.identity_projection(factory, active, inventory, processes)
        if health_records.identity_projection_problem(projection) is not None:
            return brackets, ('unclassified', None)
        return brackets, ('facts', projection)

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
        self._sync_dir(self.root)
        if os.path.lexists(path):
            if _regular_bytes(path) != data:
                raise BrokerError('a retained record differs from its digest')
            # A name found here may come from a rename whose directory sync never ran: sync it now.
            self._sync_dir(directory)
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
            self._sync_fd(fd)
        finally:
            os.close(fd)
        if _regular_bytes(temporary) != data:
            raise BrokerError('a retained record did not read back whole')
        os.rename(temporary, path)
        self._sync_dir(directory)
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

    # ---------------------------------------------- the F0 commit fence of the next profile

    def record_f0(self, capabilities, reason):
        """Records F0's decision once, between generations: the trial's capability record, a
        canonical side record of this profile and installation naming its branch, is kept by
        digest. FULL qualifies, and LIMITED only when the admission admits it; REFUSED never does.
        F0 comes after N2 and N3: every admitted negative activation must have settled its
        intended rejection and safe recovery first, and no boot transition may be unsettled. The
        decision never changes once recorded."""
        if self.admission['version'] != 3:
            raise BrokerError('F0 needs a version 3 admission')
        if self.open_generation is not None:
            raise BrokerError('F0 is decided only between generations')
        if self.f0 is not None:
            raise BrokerError('F0 is decided once')
        if not isinstance(reason, str) or not reason.strip():
            raise BrokerError('an F0 decision names its reason')
        data = bytes(capabilities)
        branch = self._capability_branch(data)
        branches = self.admission['branches']
        problem = self._f0_order_problem()
        if problem is not None:
            raise BrokerError(problem)
        digest = hashlib.sha256(data).hexdigest()
        try:
            self._keep(digest, data)
        except (BrokerError, OSError) as error:
            raise self._writer_failed('the F0 capability record could not be kept: %s' % error) from error
        record = {'record': 'DECISION', 'branch': branch, 'qualified': branch in ('FULL', 'LIMITED'),
                  'capabilities_sha256': digest, 'predicate_sha256': branches[branch]['predicate_sha256'],
                  'reason': reason, 'wall_ns': self._wall()}
        number = self.ledger.record('qualification', record)
        self.f0 = dict(record, number=number, kind='qualification')
        return dict(record, number=number)

    def gate_positive(self, plan, attempt, purpose):
        """The gate a driver passes before it creates the positive attempt or grants its STAGE:
        recorded either way, and refused unless F0 qualified."""
        positive = self.admission['branches']['positive'] if self.admission['version'] == 3 else None
        if positive is None or (plan, attempt) != (positive['plan'], positive['attempt']):
            raise BrokerError('not the positive attempt the admission gates')
        if not isinstance(purpose, str) or not purpose.strip():
            raise BrokerError('a gate names its purpose')
        problem = self._positive_problem(plan, attempt)
        self.ledger.record('qualification', {'record': 'GATE', 'plan': plan, 'attempt': attempt, 'allowed': problem is None,
                                  'reason': problem, 'purpose': purpose, 'wall_ns': self._wall()})
        if problem is not None:
            raise BrokerError(problem)

    def _capability_branch(self, data):
        """The branch an F0 capability record names, or BrokerError: the record is one canonical
        side record of the F0 schema, this profile and this installation, and its branch is one
        the admission admits. Its content rules beyond these are C3's."""
        try:
            value = evidence.parse(data)
        except evidence.SideError as error:
            raise BrokerError('the F0 capability record: %s' % error) from error
        if (value.get('schema'), value.get('profile'), value.get('installation')) != (
                F0_SCHEMA, lab_actions.PROFILE, self.admission['installation']):
            raise BrokerError('a capability record of another schema, profile or installation')
        branch = value.get('branch')
        if branch not in lab_actions.BRANCHES or self.admission['branches'][branch] is None:
            raise BrokerError('a branch the admission does not admit')
        return branch

    def _f0_order_problem(self):
        """Why F0 may not be decided now, or None: every admitted negative activation must have
        settled its intended rejection, and no boot transition may be unsettled."""
        pending = [s['id'] for s in self.specs.values() if s['type'] == 'NEGATIVE_ACTIVATION'
                   and not self._settled_ok(s['id'])]
        if pending:
            return 'N2 and N3 settle their intended rejection and safe recovery before F0'
        return self._unsettled_transition()

    def _decision_problem(self, c):
        """Why a recorded F0 decision cannot restore the fence, or None: the capability record it
        names must be kept whole under its digest and still decide on its own, under this
        admission, the branch, qualification and predicate the decision records, and the
        decision must follow the negative activations and boot transitions before it, as its
        writer required."""
        why = self._kept_problem(c['capabilities_sha256'])
        if why is not None:
            return 'its capability record: %s' % why
        try:
            branch = self._capability_branch(_regular_bytes(self.root / RECORDS / c['capabilities_sha256']))
        except BrokerError as error:
            return 'its capability record: %s' % error
        if (c['branch'], c['qualified'], c['predicate_sha256']) != (
                branch, branch in ('FULL', 'LIMITED'), self.admission['branches'][branch]['predicate_sha256']):
            return 'its branch, qualification or predicate is not the one its capability record decides'
        return self._f0_order_problem()

    def _f0_qualified(self):
        return self.f0 is not None and self.f0['qualified']

    def _positive_problem(self, plan, attempt):
        """Why the positive attempt may not act yet, or None: before a qualified F0 it stays
        uncreated and unarmed, whatever the fault schedule holds."""
        if self.admission['version'] != 3:
            return None
        positive = self.admission['branches']['positive']
        if (plan, attempt) != (positive['plan'], positive['attempt']) or self._f0_qualified():
            return None
        return ('positive attempt %d of plan %s before a qualified F0: it stays uncreated and unarmed'
                % (attempt, plan))

    def _commit_fence(self, name, m):
        """Why a version 3 managed crossing launches nothing, whatever the fault schedule holds:
        the positive attempt before a qualified F0, any managed COMMIT before it, or any crossing
        while a boot transition is unsettled."""
        problem = self._positive_problem(m['plan'], m['attempt'])
        if problem is not None:
            return problem
        if name == 'COMMIT' and not self._f0_qualified():
            return 'no managed COMMIT launches before F0 qualifies'
        return self._unsettled_transition()

    def _settled_ok(self, action_id):
        return any(n in self.action_ends and self.action_ends[n]['settled'] and self.action_ends[n]['status'] == 'OK'
                   for n in self.action_begins.get(action_id, []))

    def _unsettled_transition(self, current=None):
        """Why no forward effect may follow now, or None: a boot transition, other than the one
        being run, did not end settled with its intended outcome. Nothing continues while one is
        uncertain."""
        for ident, transition in self.transitions.items():
            end = transition['end']
            if ident == current:
                continue
            if end is None or end['status'] not in ('OK', 'REFUSED'):
                return 'boot transition %s is unsettled or unexpected: nothing continues' % ident
        return None

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
        # A command given private input names that it had some, never what it was.
        private = getattr(call, 'private', None)
        if private is not None:
            intent['private_input'] = True
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
        summary = dict(result.summary(), ended_monotonic_ns=self._monotonic())
        kept = True
        residual = bytes(getattr(result, 'residual', b'') or b'')
        if private is not None and (stdout or stderr or residual):
            # A command given private input has none of its output in the ledger: any byte of it, in
            # either stream or undecoded in the residual, withholds every field that holds output,
            # the decoder's account of the stream included, since it may quote header bytes. They
            # are kept privately, as sensitive operating material. The capture names what was
            # withheld and its size; its launch, transport, completion and exit stay, so its
            # outcome is classified as it would be without them.
            withheld = {'stdout': stdout, 'stderr': stderr, 'residual': residual,
                        'residual_bytes': summary.get('residual_bytes', len(residual)), 'error': summary.get('error')}
            try:
                private['keep'](withheld)
            except Exception:  # The capture still ends without them, and the writer latches.
                kept = False
            stdout, stderr = b'', b''
            summary = dict(summary, residual_hex='', residual_bytes=0, withheld=True, withheld_kept=kept,
                           withheld_bytes={'stdout': len(withheld['stdout']), 'stderr': len(withheld['stderr']),
                                           'residual': withheld['residual_bytes']},
                           error=None if withheld['error'] is None else WITHHELD)
        self.ledger.finish_capture(entry, stdout, stderr, summary)
        if not kept:
            raise self._writer_failed('withheld private output could not be kept privately')
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

    def _shell(self, operation, command, context, timeout, stdout_max, stderr_max, not_after_ns=None, bound_ns=None,
               private=None):
        """One shell command. With `bound_ns`, the transport's timeout is what is left of that bound at
        the moment of the call, never more than `timeout`. With `private`, USER_PIN's {'input',
        'keep'}, the constant command is given its input on private standard input; the capture
        records only that it had private input, and none of its output is written to the ledger:
        any byte of it is withheld and given to `keep` (_record_command)."""
        gate = self._may_send(not_after_ns)
        extra = {} if gate is None else {'may_send': gate}
        if private is not None:
            extra['private'] = private['input']

        def call():
            allowed = timeout if bound_ns is None else min(timeout, max(0.0, (bound_ns - self._monotonic()) / 1_000_000_000))
            return self.transport.shell(command, allowed, stdout_max, stderr_max, **extra)
        call.private = private
        return self._capture(operation, command, context, call, timeout, not_after_ns)

    # ------------------------------------------------ groups of reads

    def _group(self, name, call, context, expect_boot, emitted=True, deadline_ns=None):
        """One reader call as one group, recorded with its captures, raw digest and facts. With
        `deadline_ns`, a host monotonic instant, a command is admitted only with at least
        BOUND_COMMAND_MIN_S of it left; the deadline is then each command's launch deadline (a fresh
        broker's feature query included), refused after its durable intent and by the transport right
        before its request, and each command is given only what is left of it. A clock, target or
        typed inventory, user limits, SystemUI process or global session inventory group records a
        reading instead of facts."""
        def project(value):
            if name == 'clock':
                return [], {'boot': value[0], 'instance': value[1], 'elapsed': value[2], 'wall': value[3]}
            if name == 'target':
                return [], {'scope': value}
            if name in USER_READINGS or name == 'global-sessions':
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
            elif name == 'user-limits':
                problem = full_users.check_limits(reading)
            elif name == 'systemui-processes':
                problem = full_users.check_processes(reading)
            elif name == 'global-sessions':
                problem = lab_actions.check_global(reading)
            else:
                problem = self._facts_problem(name, facts, raw, expect_boot)
            if problem is not None:
                status, reason, frames = 'refused', problem, []
            elif name not in ('clock', 'target', 'global-sessions') + USER_READINGS:
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
        self._read_record(dict(record, number=number))
        self._users(record)
        self._listing(record)
        if name == 'inventory' and status == 'facts':
            self._serials(reading)
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
        self._read_record(dict(record, number=number))
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
        # A composition's copy of bit 1 and its witness decision is what its projection holds.
        if c['reader'] == 'health' and 'witness' in m['extra'] and m['extra']['witness'] != _witness_copy(
                m['status'], (m['projection'] or {}).get('rows'), (m['projection'] or {}).get('candidate')):
            return "its copy of bit 1's witness is not its projection's"
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
        # A ticket's read address comes from the stored ticket and plan. A read loss admitted for
        # the plan is never skipped because the store cannot be read: the observation is refused.
        address, due = None, {}
        if ticket:
            address, why = self._read_address(m, state)
            if address is None and any(c['on'] == 'read' and c['plan'] == m['plan'] and c['cell'] not in self.consumed
                                       for c in self.cells):
                return self._reply(m, 'REFUSED', reason='a read loss is admitted for this plan, and the read '
                                   'address cannot be derived: %s' % why)
            if address is not None:
                problem = self._positive_problem(m['plan'], address['attempt'])
                if problem is not None:
                    return self._reply(m, 'REFUSED', reason=problem)
                due = self._due_reads(m['ticket'], address)
        envelopes, users, changed, groups = [], None, False, []
        try:
            for ordinal, name in enumerate(names):
                if name == 'users':
                    call = lambda: self.reader.users(sorted(self.users_seen.values()))  # noqa: E731
                else:
                    call = getattr(self.reader, name)
                group = self._group(name, call, dict(context, **self._marker(m, address, ordinal, due)), m['boot'])
                groups.append(group.number)
                envelopes += [self._simple_envelope(group.number, f, frame) for f, frame in zip(group.facts, group.frames)]
                if name == 'users' and group.ok:
                    users = group.facts
                changed = group.status == 'refused' and group.reason == 'the boot changed'
                halt = self._read_loss(m, state, due, ordinal, group.number, groups)
                if halt is not None:
                    return halt
                if changed:
                    break
            if ticket and not changed and self.reader.receipts_admitted:
                found, number = self._receipt_group(m, context, self._marker(m, address, losses.RECEIPTS, due))
                envelopes += found
                groups.append(number)
                halt = self._read_loss(m, state, due, losses.RECEIPTS, number, groups)
                if halt is not None:
                    return halt
            if (ticket and not changed and m['state'] == HEALTH_WINDOW_STATE and self.reader.health_admitted
                    and users is not None):
                found, numbers, marked = self._health_groups(m, context, users,
                                                             self._marker(m, address, losses.HEALTH, due))
                envelopes += found
                groups += numbers
                if marked is not None:
                    halt = self._read_loss(m, state, due, losses.HEALTH, marked, groups)
                    if halt is not None:
                        return halt
        except Stopped as error:
            self._settle_unacted('the observation was stopped before its read loss acted')
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

    # ------------------------------------------------ read losses

    def _read_address(self, m, state):
        """A ticket observation's read address from the stored ticket and plan, (address, None) or
        (None, why): the plan, the stored attempt, OBSERVE and the milestone whose state the stored
        ticket is in, which the request's state must name. The first one of a round also takes the
        stored ticket as the round's start: its digest and state, and its bytes, which the round's
        boundary keeps with its own records before its checkpoint names them. An observation
        writes nothing of its own here."""
        store = Path(self.admission['store'])
        tdata = _regular_bytes(store / 'tickets' / (m['ticket'] + STORE_SUFFIX))
        pdata = _regular_bytes(store / 'plans' / (m['plan'] + STORE_SUFFIX))
        if tdata is None or pdata is None:
            return None, 'the stored ticket or plan cannot be read whole'
        try:
            t, p = records.decode_ticket(tdata), records.decode_plan(pdata)
        except records.RecordError as error:
            return None, 'the stored ticket or plan: %s' % error
        a = self.admission
        if ((t['ticket'], t['plan'], t['installation'], t['component'])
                != (m['ticket'], m['plan'], a['installation'], a['component'])
                or (p['plan'], p['installation'], p['component']) != (m['plan'], a['installation'], a['component'])):
            return None, "the stored ticket or plan is not the observation's"
        if encoder.STATES.index(t['state']) + 1 != m['state']:
            return None, 'the observation names another state than the stored ticket'
        signed, repair = self._signed_repair(t, p)
        round_ = state.get('round')
        if round_ is not None and round_['start'] is None and round_['ticket'] == m['ticket']:
            round_['start'] = {'sha256': hashlib.sha256(tdata).hexdigest(), 'state': t['state'], 'source': 'observe'}
            round_['start_bytes'] = tdata
        return {'plan': m['plan'], 'attempt': t['attempt'], 'operation': 'OBSERVE',
                'milestone': proto.read_milestone(t['state'], signed, repair)}, None

    @staticmethod
    def _signed_repair(ticket, plan):
        """Whether a decoded ticket's ledger holds a SIGN, and whether its plan repairs another plan
        without signing."""
        return (any(entry[0] == 'SIGN' for entry in ticket['ledger']),
                plan['repairs'] != proto.ZERO_ID and plan['signing'] == 0)

    def _due_reads(self, ticket, address):
        """The admitted read losses due in this observation, by reader ordinal: of this plan,
        attempt and milestone, whose occurrence is the reader's next completed run."""
        due = {}
        if address['milestone'] is None:
            return due
        for cell in self.cells:
            if cell['on'] != 'read' or cell['cell'] in self.consumed:
                continue
            if (cell['plan'], cell['attempt'], cell['milestone']) != (address['plan'], address['attempt'],
                                                                     address['milestone']):
                continue
            if cell['occurrence'] == self.read_counts.get((ticket, address['milestone'], cell['ordinal']), 0) + 1:
                due[cell['ordinal']] = cell
        return due

    def _marker(self, m, address, ordinal, due):
        """The read marker a reader's completing group carries: its address with the reader's
        ordinal and occurrence, and the loss due at it. Nothing without a milestone."""
        if address is None or address['milestone'] is None:
            return {}
        count = self.read_counts.get((m['ticket'], address['milestone'], ordinal), 0)
        return {'read': dict(address, ordinal=ordinal, occurrence=count + 1,
                             loss_cell=due[ordinal]['cell'] if ordinal in due else None)}

    def _read_loss(self, m, state, due, ordinal, child, groups):
        """The HALT of a read loss due at this reader, once its raw child completed and drained:
        the decision is written and synced first, and the reply names it and carries nothing of
        the observation. None when no loss is due here."""
        cell = due.get(ordinal)
        if cell is None:
            return None
        number = self._decide_loss(cell, 'halt', child, m['ticket'], m['request'], state['generation'], list(groups),
                                   'the observation halts after its selected reader; nothing of it is replied')
        return self._reply(m, 'HALT', control_record=number, reason='admitted read loss %s' % cell['cell'])

    def _decide_loss(self, cell, decision, evidence, ticket, request, generation, groups, reason):
        """Records a read or round loss's one decision and consumes its cell. Returns its record."""
        number = self.ledger.record('fault', {
            'cell': cell['cell'], 'on': cell['on'], 'decision': decision, 'evidence': evidence, 'ticket': ticket,
            'plan': cell['plan'], 'attempt': cell['attempt'], 'operation': cell['operation'],
            'milestone': cell['milestone'], 'ordinal': cell['ordinal'], 'occurrence': cell['occurrence'],
            'request': request, 'generation': generation, 'groups': groups, 'reason': reason})
        self.consumed.add(cell['cell'])
        self.loss_records[cell['cell']] = number
        return number

    def _settle_unacted(self, reason):
        """Records every loss that a recorded group or checkpoint named due and that was never
        decided as not acted, so it never acts at a later address."""
        for cell_id, evidence in sorted(self.loss_evidence.items(), key=lambda item: item[1]):
            if cell_id in self.consumed:
                continue
            cell = next(c for c in self.cells if c['cell'] == cell_id)
            named = self.ledger.entries[evidence - 1].content
            self._decide_loss(cell, 'not-acted', evidence, named.get('ticket'), named.get('request'),
                              named.get('generation'), [], reason)

    # ------------------------------------------------ receipts past the clock guard

    def _receipt_group(self, m, context, marker=None):
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
        number, envelopes = self._compound('receipts', context, captures, children, status, reason, brackets,
                                           {'rows': judged}, facts, emitted=True,
                                           extra=dict({'rows': judged}, **(marker or {})))
        if status == 'stopped':
            raise Stopped(reason)
        return envelopes, number

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

    def _health_groups(self, m, context, users, marker=None):
        """A prepared full probe of each running user that this observation's whole listing
        shows. No preparation, no probe: an unprepared user gives nothing, which leaves a gap,
        never a claim. Returns the envelopes, the groups recorded and the one that carries the
        health reader's read marker, the first, or None when the reader recorded nothing."""
        window, why = self._store_window(m)
        if window is None or window['boot'] != m['boot']:
            number, _ = self._compound('health', dict(context, purpose='health'), [], {}, 'refused',
                                       why or "the window is of another boot than the round's", None, {},
                                       extra=dict({'preparations': [], 'user': None, 'serial': None}, **(marker or {})))
            return [], [number], number if marker else None
        envelopes, numbers, marked = [], [], None
        running = sorted({(f['user'], f['serial']) for f in users
                          if f['classification'] in ('RUNNING_UNLOCKED', 'RUNNING_LOCKED')})
        for user, serial in running:
            fresh = self._fresh_preparations(user, serial, window)
            if fresh:
                selected = marker if not numbers else None
                found, number = self._health_group(m, context, window, user, serial, fresh, selected)
                envelopes += found
                numbers.append(number)
                if selected and selected['read']['loss_cell'] is not None:
                    # A read loss is due at this completed child: it acts now, so no later user's
                    # composition is read and no later preparation is used.
                    break
        if numbers and marker:
            marked = numbers[0]
        return envelopes, numbers, marked

    def _baseline(self, boot, user, serial, window, instance):
        """The baseline of one user in this boot that a probe in the current read's framework
        instance relies on, by health_baseline.select, or None, and why not: the last whole one
        completed by the window's start, or for a user newly unlocked in the window the last
        whole one taken after that and before its first full probe; complete, and of this
        framework instance, since a later one invalidates the continuity it witnesses."""
        chosen, rule = health_baseline.select(self.baselines.get((boot, user, serial), []),
                                              self.listings.get(boot, []),
                                              self.probe_begins.get((boot, user, serial), []), window, user, serial,
                                              instance)
        return (chosen, None) if chosen is not None else (None, rule)

    def _trail(self, boot, user, serial):
        """Each earlier composition of one user in this boot, for the witness reader: its bracket,
        bit 1 as the broker accepted it, its witness decision, and the replies its own captures
        recorded for the process health helper's invocation. A held probe carries no decision, so
        the reader reads its clock and rows again from that recorded reply."""
        command = process_health.command(user)
        found = []
        for t in self.witness_trail.get((boot, user, serial), []):
            helper = []
            for n in t['captures']:
                entry = self.ledger.entries[n - 1]
                if entry.kind == 'capture' and (entry.content.get('intent') or {}).get('command') == command:
                    try:
                        helper.append(list(self._capture_reply(entry)))
                    except BrokerError:
                        # A reply the ledger cannot give whole is no reply the reader may read.
                        helper.append([None, '', ''])
            found.append({'group': t['group'], 'brackets': t['brackets'], 'status': t['status'],
                          'decision': t['decision'], 'helper': helper})
        return found

    def _repeated(self, boot, user, serial, window):
        """Every whole baseline of one user in this boot that a probe in its window may rely on, by
        health_baseline.eligible's rule, in ledger order: the repeated baselines the witness reader
        judges against. The last of them is the one `_baseline` checks."""
        found, _ = health_baseline.eligible(self.baselines.get((boot, user, serial), []), self.listings.get(boot, []),
                                            self.probe_begins.get((boot, user, serial), []), window, user, serial)
        return [{'digest': b['compound']['sha256'], 'projection': b['projection'], 'brackets': b['brackets']}
                for b in found]

    def _health_group(self, m, context, window, user, serial, fresh, marker=None):
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
                    'action_end': p['end']['number'],
                    'result_sha256': _result_digest(p['end']['outcome'].get('result'))} for p in fresh]
        # Each preparation's result, which the manifest binds by its digest: the capture conditions
        # and the credential unlock that bits 2 and 3 judge.
        results = {p['begin']['operation']: p['end']['outcome']['result'] for p in fresh
                   if p['end']['outcome'].get('result') is not None}
        # The begin bracket's own group names the preparations offered to the composer. Once it is
        # read they are used, whatever becomes of the probe's reads, rows or manifest, and a
        # reopening restores that use from the same group.
        begin = self._clock_group(dict(context, part='begin', offered=[p['operation'] for p in offered]), m['boot'],
                                  emitted=False)
        if begin.ok:
            self.used_preparations.update(p['operation'] for p in offered)
            self._probe_begun({'reading': begin.reading, 'user': user, 'serial': serial})
        status, reason, candidate, captured, end = 'unavailable', 'the read bracket did not begin', None, [], None
        baseline, baseline_why = None, None
        if begin.ok:
            baseline, baseline_why = self._baseline(m['boot'], user, serial, window, begin.reading['instance'])
            reader_context = {'ticket': m['ticket'], 'plan': m['plan'], 'user': user, 'serial': serial,
                              'window': dict(window), 'preparations': offered,
                              'baseline': None if baseline is None else {'digest': baseline['compound']['sha256'],
                                                                         'projection': baseline['projection']},
                              'active_apk': self._pinned_apk(m['plan']), 'results': results,
                              'identity': self._expected_identity(m['plan'], user, serial),
                              'ce_origin': self._ce_origin(serial),
                              # The witness reader's joins: the repeated baselines, and bit 1
                              # of each earlier probe of the user in this boot with its decision.
                              'baselines': self._repeated(m['boot'], user, serial, window),
                              'trail': self._trail(m['boot'], user, serial)}
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
            rows, used, problem = self._health_rows(candidate, user, serial, captures, offered, baseline, brackets,
                                                    baseline_why)
            if problem is not None:
                status, reason = 'unclassified', problem
        facts, emitted, extra = [], status == 'facts', {'user': user, 'serial': serial, 'preparations': []}
        if begin.ok:
            # The probe's assignment: every preparation its composer was given.
            extra['preparations'] = [p['operation'] for p in offered]
        # Bit 1 as the broker accepted it, with the witness decision, for later probes' joins.
        extra['witness'] = _witness_copy(status, rows, _side(candidate))
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
        number, envelopes = self._compound('health', context, captures,
                                           {'begin': begin.number, 'end': end.number if end is not None else None},
                                           status, reason, brackets,
                                           {'purpose': 'TICKET_WINDOW', 'candidate': _side(candidate), 'rows': rows,
                                            'offered': offered, 'window': window}, facts, emitted=emitted,
                                           extra=dict(extra, **(marker or {})))
        if status == 'stopped':
            raise Stopped(reason)
        return envelopes, number

    def _health_rows(self, candidate, user, serial, captures, offered, baseline, brackets, baseline_why=None):
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
                    status, why = 'UNKNOWN', 'no valid baseline relied on: %s' % (
                        baseline_why or 'the row names another baseline')
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

    def _expected_identity(self, plan, user, serial):
        """Bit 0's expectations for one serial: its first qualified identity baseline, and for the
        system user the stored plan's own base UID and context."""
        kept = self.identities.get(serial)
        base = None
        if user == 0:
            try:
                stored = records.decode_plan(_regular_bytes(Path(self.admission['store']) / 'plans'
                                                            / (plan + STORE_SUFFIX)) or b'')
                base = {'uid': stored['baseUid'], 'context': stored['baseContext']}
            except records.RecordError:
                base = None
        return {'expected': None if kept is None else kept['identity'], 'plan_base': base}

    def _ce_origin(self, serial):
        """The CE nonce CE_SENTINEL settled for one serial, with its record, or None."""
        kept = self.sentinels.get(serial, {}).get('SENTINEL_SET')
        return None if kept is None else {'nonce': kept['nonce'], 'record': kept['number']}

    def _pinned_publication(self, plan):
        return self.publications.get(plan)

    # ------------------------------------------------ serving a generation

    def run_generation(self, argv, env=None, cwd=None):
        """Spawns one coordinator generation, serves it to its end, and reaps it. A version 3
        broker tells the generation, in its environment, how many round boundaries of each ticket
        it has recorded, so the bridge names each next checkpoint ordinal; every ordinal is
        verified against the ledger."""
        if self.open_generation is not None:
            raise BrokerError('a generation is still open')
        if self.admission['version'] == 3:
            env = dict(os.environ if env is None else env)
            env[CHECKPOINT_ENV] = self.checkpoint_counts()
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

    def checkpoint_counts(self):
        """Each ticket's recorded round boundaries as `ticket:count` pairs in ticket order, joined
        by commas: what a generation is told."""
        return ','.join('%s:%d' % (ticket, len(found)) for ticket, found in sorted(self.checkpoints.items()))

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
        if kind not in ('HELLO', 'CLOCK', 'OBSERVE', 'CROSS', 'POINT', 'HOST', 'REPORT', 'ROUND_DONE'):
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
        if self.protocol == proto.VERSION_2:
            self._track_round(request, state)
        handler = {'CLOCK': self._clock, 'OBSERVE': self._observe, 'CROSS': self._cross, 'POINT': self._point,
                   'HOST': self._host, 'REPORT': self._report, 'ROUND_DONE': self._round_done}[kind]
        reply = handler(request, state)
        status = proto.STATUS_NAMES[reply['status']]
        if status == 'HALT':
            state['halt_ordered'] = True
        if status == 'STOPPED':
            state['stopped_sent'] = True
        return reply

    @staticmethod
    def _track_round(m, state):
        """A round begins at its CLOCK, which the coordinator reads first in every round, and ends
        at its ROUND_DONE. The first ticket a request of the round names is the round's ticket; a
        request naming another one is remembered, so the round's ROUND_DONE is refused."""
        kind = m['type']
        if kind == 'CLOCK':
            state['round'] = {'ticket': None, 'others': False, 'start': None, 'start_bytes': None}
            return
        round_ = state.get('round')
        named = m['ticket'] if kind in ('CROSS', 'POINT', 'HOST') or (
            kind == 'OBSERVE' and m['scope'] == proto.SCOPES['TICKET']) else None
        if round_ is None or named is None:
            return
        if round_['ticket'] is None:
            round_['ticket'] = named
        elif round_['ticket'] != named:
            round_['others'] = True

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
        """The coordinator's lab point. An admitted point cell halts the generation there. Under a
        version 3 admission the broker first keeps the store as the point left it, the old ticket
        and the new selection between their writes, and the fault record names both by SHA-256: a
        point whose records cannot be read whole launches no halt, and a failed write or sync of
        them latches the writer's stop. Both answers are REFUSED, the only other answer a point
        has, and neither consumes the cell."""
        problem = self._positive_problem(m['plan'], m['attempt'])
        if problem is not None:
            return self._reply(m, 'REFUSED', reason=problem)
        cell = self._match('point', plan=m['plan'], attempt=m['attempt'], point=m['point'])
        if cell is None:
            return self._reply(m, 'OK')
        retained = {}
        if self.admission['version'] == 3:
            try:
                self._fence()
            except Stopped as error:
                return self._reply(m, 'REFUSED', reason=str(error))
            retained, why = self._point_records(m)
            if why is not None:
                return self._reply(m, 'REFUSED', reason='%s: the point does not halt' % why)
            try:
                for name in ('ticket', 'selection'):
                    self._keep(*retained[name])
            except (BrokerError, OSError) as error:
                stopped = self._writer_failed("the point's records could not be kept: %s" % error)
                return self._reply(m, 'REFUSED', reason=str(stopped))
        self.consumed.add(cell['cell'])
        record = {'cell': cell['cell'], 'on': 'point', 'decision': 'halt', 'ticket': m['ticket'], 'plan': m['plan'],
                  'point': m['point'], 'request': m['request'], 'generation': state['generation']}
        if retained:
            record.update(ticket_sha256=retained['ticket'][0], selection_sha256=retained['selection'][0])
        number = self.ledger.record('fault', record)
        return self._reply(m, 'HALT', record=number, reason='admitted fault cell %s at %s' % (cell['cell'], m['point']))

    def _point_records(self, m):
        """The stored ticket and selection at a point, each as (SHA-256, bytes), or why not: both
        read whole, the ticket the point's own, of this installation and component."""
        store = Path(self.admission['store'])
        tdata = _regular_bytes(store / 'tickets' / (m['ticket'] + STORE_SUFFIX))
        sdata = _regular_bytes(store / 'selections' / (self.admission['component'] + STORE_SUFFIX))
        if tdata is None or sdata is None:
            return {}, 'the stored ticket or selection cannot be read whole'
        try:
            t = records.decode_ticket(tdata)
        except records.RecordError as error:
            return {}, 'the stored ticket: %s' % error
        a = self.admission
        if (t['ticket'], t['plan'], t['attempt'], t['installation'], t['component']) != (
                m['ticket'], m['plan'], m['attempt'], a['installation'], a['component']):
            return {}, "the stored ticket is not the point's"
        return {'ticket': (hashlib.sha256(tdata).hexdigest(), tdata),
                'selection': (hashlib.sha256(sdata).hexdigest(), sdata)}, None

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
            problem = self._positive_problem(m['plan'], m['attempt'])
            if problem is not None:
                return self._reply(m, 'REFUSED', reason=problem)
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

    # ------------------------------------------------ round boundaries

    def _round_done(self, m, state):
        """One public round's boundary, after the round returned and before any next round or
        report. It is a boundary of the lab bridge, never a deployment hook and never a decision
        about the ticket. Refused unless a round began since the last boundary and named no other
        ticket, the stored ticket, plan and selection are the ones the request names by its
        identity and digests, the ordinal is the ticket's next recorded boundary, and the milestone
        is the one the stored bytes show the round reached. The broker then keeps the exact
        ticket, selection and plan bytes, and the round start's that its first observation read,
        writes the checkpoint, and only then consumes a round loss due at this boundary, ordering
        the halt by the decision's record. A failed write or sync of those bytes latches the
        writer's stop: the answer is STOPPED, and no checkpoint, loss or later effect follows."""
        try:
            self._fence()
        except Stopped as error:
            return self._reply(m, 'STOPPED', reason=str(error))
        round_, state['round'] = state.get('round'), None
        if round_ is None:
            return self._reply(m, 'REFUSED', reason='no round began since the last boundary: one ROUND_DONE ends one '
                                                    'round')
        if round_['others'] or round_['ticket'] not in (None, m['ticket']):
            return self._reply(m, 'REFUSED', reason='a ROUND_DONE of another ticket than its round named')
        problem = self._positive_problem(m['plan'], m['attempt'])
        if problem is not None:
            return self._reply(m, 'REFUSED', reason=problem)
        store = Path(self.admission['store'])
        tdata = _regular_bytes(store / 'tickets' / (m['ticket'] + STORE_SUFFIX))
        pdata = _regular_bytes(store / 'plans' / (m['plan'] + STORE_SUFFIX))
        sdata = _regular_bytes(store / 'selections' / (self.admission['component'] + STORE_SUFFIX))
        if tdata is None or pdata is None or sdata is None:
            return self._reply(m, 'REFUSED', reason='the stored ticket, plan or selection cannot be read whole')
        try:
            t, p = records.decode_ticket(tdata), records.decode_plan(pdata)
        except records.RecordError as error:
            return self._reply(m, 'REFUSED', reason='the stored ticket or plan: %s' % error)
        a = self.admission
        if ((t['ticket'], t['plan'], t['attempt'], t['installation'], t['component'])
                != (m['ticket'], m['plan'], m['attempt'], a['installation'], a['component'])
                or (p['plan'], p['installation'], p['component']) != (m['plan'], a['installation'], a['component'])):
            return self._reply(m, 'REFUSED', reason='a ROUND_DONE of another ticket, plan or attempt than the store holds')
        digests = {'ticket': hashlib.sha256(tdata).hexdigest(), 'selection': hashlib.sha256(sdata).hexdigest(),
                   'plan': hashlib.sha256(pdata).hexdigest()}
        if (digests['ticket'], digests['selection']) != (m['ticket_digest'], m['selection_digest']):
            return self._reply(m, 'REFUSED', reason='stale digests: the stored ticket or selection is not the one the '
                                                    'ROUND_DONE names')
        found = self.checkpoints.get(m['ticket'], [])
        if m['checkpoint_ordinal'] != len(found) + 1:
            return self._reply(m, 'REFUSED', reason='checkpoint %d is not the ticket\'s next boundary, %d'
                               % (m['checkpoint_ordinal'], len(found) + 1))
        start = round_['start']
        if start is None and found:
            start = {'sha256': found[-1]['ticket_sha256'], 'state': found[-1]['state'], 'source': 'checkpoint'}
        signed, repair = self._signed_repair(t, p)
        milestone = proto.boundary_milestone(start and start['state'], t['state'], signed, repair)
        code = proto.MILESTONES[milestone] if milestone else proto.NO_MILESTONE
        if m['milestone'] != code:
            return self._reply(m, 'REFUSED', reason='the round reached %s, not the milestone the ROUND_DONE names'
                               % (milestone or 'no milestone'))
        kept = [(digests[name], data) for name, data in (('ticket', tdata), ('selection', sdata), ('plan', pdata))]
        if start is not None and start['source'] == 'observe':
            kept.append((start['sha256'], round_['start_bytes']))
        try:
            for digest, data in kept:
                self._keep(digest, data)
        except (BrokerError, OSError) as error:
            # A failed write or sync of the boundary's own evidence latches the writer: no
            # checkpoint, no loss and no later command or effect.
            stopped = self._writer_failed("the boundary's records could not be kept: %s" % error)
            return self._reply(m, 'STOPPED', reason=str(stopped))
        occurrence = self.boundary_counts.get((m['ticket'], milestone), 0) + 1 if milestone else None
        due = next((c for c in self.cells if c['on'] == 'round' and c['cell'] not in self.consumed
                    and (c['plan'], c['attempt'], c['milestone'], c['occurrence'])
                    == (m['plan'], m['attempt'], milestone, occurrence)), None) if milestone else None
        record = {'ticket': m['ticket'], 'plan': m['plan'], 'attempt': m['attempt'], 'ordinal': len(found) + 1,
                  'milestone': milestone, 'milestone_code': code, 'state': t['state'],
                  'ticket_sha256': digests['ticket'], 'selection_sha256': digests['selection'],
                  'plan_sha256': digests['plan'], 'round_start': start, 'occurrence': occurrence,
                  'loss_cell': due and due['cell'], 'request': m['request'], 'generation': state['generation'],
                  'wall_ns': self._wall(), 'monotonic_ns': self._monotonic()}
        number = self.ledger.record('checkpoint', record)
        self._next_record('checkpoint', dict(record, number=number, kind='checkpoint'))
        if due is None:
            return self._reply(m, 'OK', record=number)
        fault = self._decide_loss(due, 'halt', number, m['ticket'], m['request'], state['generation'], [],
                                  'the generation halts after its durable boundary')
        return self._reply(m, 'HALT', record=fault, reason='admitted round loss %s' % due['cell'])

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
            # The next profile's commit fence, independent of any fault: the positive attempt and
            # every managed COMMIT wait for a qualified F0, and nothing follows an unsettled boot.
            fenced = self._commit_fence(name, m) if self.admission['version'] == 3 else None
            if fenced is not None:
                reason = '%s: nothing launched' % fenced
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
        counts against the boot policy's activation services, which the negative activations
        share."""
        names = {e.number: e.content['crossing'] for e in self.ledger.entries if e.kind == 'crossing' and e.complete}
        effective = set()
        for e in self.ledger.entries:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if (intent and intent.get('operation') in ('mutation', 'push', 'reboot', 'notice')
                    and intent.get('crossing') in names and self._may_have_launched(e)):
                effective.add(intent['crossing'])
        limit = self.admission['effect_limits']['crossings'][name]
        if sum(1 for number in effective if names[number] == name) >= limit:
            return 'the admitted limit of %d %s crossings with an effect is reached' % (limit, name)
        allowed = self.admission['boot_policy']['activation_services']
        services = self._reboot_services()
        if name == 'REBOOT' and services['MANAGED_ACTIVATION'] + services['NEGATIVE_ACTIVATION'] >= allowed:
            return 'the admitted %d activation services are spent' % allowed
        return None

    def _reboot_services(self):
        """The reboot services that may have launched, by kind: the managed REBOOT crossings, the
        plain confirmations and the negative activations, counted from the ledger's captures."""
        counts = {'MANAGED_ACTIVATION': 0, 'CONFIRMATION': 0, 'NEGATIVE_ACTIVATION': 0}
        for e in self.ledger.entries:
            intent = e.content.get('intent') if e.kind == 'capture' else None
            if not intent or not self._may_have_launched(e):
                continue
            if intent.get('operation') == 'reboot':
                counts['MANAGED_ACTIVATION'] += 1
            elif intent.get('operation') == 'lab-action-effect' and intent.get('command') == REBOOT_LABEL:
                counts[intent['transition_kind']] += 1
        counts['total'] = sum(counts.values())
        return counts

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
