# SPDX-License-Identifier: Apache-2.0
"""Host test support: a small simulated guest behind the broker's transport and reader interfaces.

It models only what the broker and the bridge tests exercise: kernel boots, framework instances,
uptime, the checkpoint, the factory and active SystemUI, staged sessions with their native
references, users, and the typed crossing commands. Shell results are built with the real
ShellResult type, so the broker's completion rules apply unchanged. The reader reads through the
broker's run function with fixed `sim:` commands, which are test fakes, not guest forms. Nothing
here is Android evidence.

A notice receipt carries the guest's boot and uptime of the moment the fixture fake wrote it: its
event time, never the time a later read happens. For the next campaign profile the guest also has
a typed user inventory, a notice fixture that writes one immutable row per notice and user when it
presents, a display whose current visibility a capture records, and per user health state that a
preparation, a baseline and a probe read. Its whole global session inventory lists every session of
every package with its referrer, commitment and end. A kernel boot keeps uncommitted sessions,
applies a ready managed one, and rejects a ready direct negative control's payload: a wrong signer
or a missing sidecar fails the session, the factory copy stays active, and a native recovery boot
follows at once, so a poll may never see the rejecting boot.

With `enable_user_forms`, the users are sim_users.py's model instead: the guest then answers the
user commands of full_users.py in their source derived forms, and the fake reads above see the same
users.

For the health package the guest also answers the fixed UI state helper in its exact form from a
model of the display, the keyguard and each user's disposable PIN and lock; the shell user's `id`;
a fresh hierarchy file a fake UI preparation dumps, with the status bar clock the active APK draws;
`locksettings set-pin` given on private standard input; and the work fixture's fake CE sentinel
write and read. Every one is a test fake of the form, not Android evidence."""
from dataclasses import dataclass, field
import hashlib
import json
import os
import re

import full_users
import health_compose
import health_witness
import lab_crossings
import lab_evidence
import lab_readers
import lab_target
import process_health
import shell_transport
import sim_users

PACKAGE = 'com.android.systemui'
FINGERPRINT = 'andrix/cf/cf:17/BP4A.260813.001/2026081300:userdebug/test-keys'
CONTEXT = 'u:r:platform_app:s0:c512,c768'
UID = 10112
FACTORY_APK = 'f0' * 32
FACTORY_VERSION = 37
# The simulated guest's wall clock in milliseconds is this base plus its uptime.
WALL_BASE = 1_791_504_000_000
NOTICE_COMMAND = 'sim:notice'
SIM_READS = ('sim:clock', 'sim:boot', 'sim:checkpoint', 'sim:factory', 'sim:active', 'sim:sessions', 'sim:users',
             'sim:receipts', 'pidof system_server')
# The next profile's fake reads and the fixture fakes' fixed command forms.
NEXT_READS = ('sim:inventory', 'sim:rows', 'sim:global-sessions')
PER_USER_READ = re.compile(r'sim:(baseline|health) ([0-9]+)')
PRESENT = re.compile(r'sim:present ([0-9]+) ([0-9a-f]{32}) ([0-9a-f]{32}) ([0-9]+) ([0-9a-f]{32}) ([0-9a-f]{32}) '
                     r'([0-9a-f]{32}) ([0-9a-f]{64})')
VISIBILITY = re.compile(r'sim:(capture|read)-visibility ([0-9]+)')
PREPARE = re.compile(r'sim:prepare ([0-9]+) ([235](?:,[235])*) ([0-9a-f]{32})')
SYSTEM_TYPE = 'android.os.usertype.full.SYSTEM'
SECONDARY_TYPE = 'android.os.usertype.full.SECONDARY'
NO_CHALLENGE = '00' * 16
APP_ID = 10123
# The health package's fakes: the UI preparation's effects, the work fixture's CE sentinel, the PIN
# script on private standard input, the shell user's `id` as a guest printed it, and the notice
# fixture whose window a dump may show.
SIM_UI = re.compile(r'sim:(relock|credential-unlock [0-9]+|dump-windows (\S+))')
SENTINEL = re.compile(r'sim:sentinel-(write [0-9]+ [0-9a-f]{32}|read [0-9]+)')
PIN_SCRIPT = re.compile(r'f\(\)\{ exec locksettings set-pin --user ([0-9]+) ([0-9]{6,16}) </dev/null >/dev/null '
                        r'2>&1; \}; f\n')
SHELL_ID = (b'uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),'
            b'1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),'
            b'3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs) context=u:r:shell:s0\n')
NOTICE_PACKAGE = 'dev.andrix.lab.notice'


def streams(reply):
    """A broker command's reply as a reader sees it: (exit status, stdout, stderr) as text."""
    return reply.exit, reply.stdout.decode('utf-8', 'surrogateescape'), reply.stderr.decode('utf-8', 'surrogateescape')


def result(command, code=0, stdout=b'', stderr=b'', completion='exited', launch='launched', transport='ok',
           error=None):
    """A ShellResult as the transport would give it."""
    frame = code if completion in ('exited', 'malformed') else None
    return shell_transport.ShellResult(shell_transport.SHELL_PREFIX + command, launch, transport, completion, frame,
                                       stdout, stderr, None, False, None, error, 1, 2, 1)


def _bounded(name, value):
    """A diagnostic string as the process health helper prints it: cut to its bound in UTF-16
    units, never inside a surrogate pair, with its whole length; null as '-' and -1."""
    if value is None:
        return '%s=- %s-length=-1' % (name, name)
    units = value.encode('utf-16-le', 'surrogatepass')
    whole = len(units) // 2
    end = min(whole, process_health.MAX_TEXT)
    if end < whole and 0xd800 <= int.from_bytes(units[2 * end - 2:2 * end], 'little') <= 0xdbff:
        end -= 1
    cut = units[:2 * end].decode('utf-16-le', 'surrogatepass')
    return '%s=%s %s-length=%d' % (name, process_health.encode_text(cut), name, whole)


def process_health_reply(user, history, current, samples):
    """The process health helper's reply in its exact form, as tests/process-health-read prints
    it: (exit status, text). `history` is ('OK', rows) or (status, reason), each row a dict of
    process_health.ROW_FIELDS with the process name as text; `current` is ('OK', entries) or
    (status, reason), each entry a dict of its condition, PID, UID, process, tag, short, long and
    stack; `samples` the four [elapsed, wall] samples around the two calls. A test fake of the
    form, which the helper's host runs compare with the helper's own output."""
    lines = [process_health.HEADER, 'user=%d' % user, 'package=' + process_health.PACKAGE,
             'capabilities=' + ','.join(process_health.CAPABILITIES)]
    for prefix, part, (before, after) in (('history', history, samples[:2]), ('current-errors', current, samples[2:])):
        lines.append('%s sample=before elapsed=%d wall=%d' % (prefix, before[0], before[1]))
        if part[0] != 'OK':
            lines.append('%s status=%s reason=%s' % (prefix, part[0], part[1]))
        elif prefix == 'history':
            lines.append('history status=OK count=%d' % len(part[1]))
            for i, r in enumerate(part[1]):
                lines.append('history row=%d timestamp=%d pid=%d real-uid=%d package-uid=%d defining-uid=%d user=%d '
                             'process=%s reason=%d subreason=%d status=%d'
                             % (i, r['timestamp'], r['pid'], r['real_uid'], r['package_uid'], r['defining_uid'],
                                r['user'], process_health.encode_text(r['process']), r['reason'], r['subreason'],
                                r['status']))
        else:
            lines.append('current-errors status=OK count=%d returned=%s' % (len(part[1]), 'list' if part[1] else 'null'))
            for i, e in enumerate(part[1]):
                lines.append('current-errors entry=%d condition=%d pid=%d uid=%d process=%s %s %s %s %s'
                             % (i, e['condition'], e['pid'], e['uid'], process_health.encode_text(e['process']),
                                _bounded('tag', e.get('tag')), _bounded('short', e.get('short')),
                                _bounded('long', e.get('long')), _bounded('stack', e.get('stack'))))
        lines.append('%s sample=after elapsed=%d wall=%d' % (prefix, after[0], after[1]))
    complete = history[0] == 'OK' and current[0] == 'OK'
    lines.append('status=' + ('complete' if complete else 'unavailable'))
    body = ''.join(line + '\n' for line in lines)
    end = 'end=%s lines=%d sha256=%s\n' % (process_health.HEADER, len(lines),
                                         hashlib.sha256(body.encode('ascii')).hexdigest())
    return (0 if complete else 5), body + end


class EventRows(list):
    """Receipts a fixture fake writes. Each is stamped, when it is written, with the guest's boot
    and uptime at that moment unless the writer names them: its event, not a later read."""

    def __init__(self, sim):
        super().__init__()
        self._sim = sim

    def append(self, row):
        row = dict(row)
        row.setdefault('boot', self._sim.boot)
        row.setdefault('elapsed', self._sim.uptime)
        super().append(row)


@dataclass
class Session:
    identity: int
    created: int
    nonce: str
    state: str = 'OPEN'
    members: dict = field(default_factory=dict)
    instance: int = 0
    # A direct negative control's ID when its referrer is the control's, never a ticket's nonce.
    control: str = None
    package: str = PACKAGE
    cause: str = None


class SimAndroid:
    def __init__(self, seed=1):
        self.seed = seed
        self.boots = 0
        self.boot = None
        self.new_boot()
        self.checkpoint = 'COMMITTED'
        self.factory = (FACTORY_APK, FACTORY_VERSION)
        self.active = ('FACTORY_COPY', FACTORY_APK, FACTORY_VERSION)
        self.sessions = {}
        # The native identity diagnostic's whole reply: the fresh form unless a test changes it.
        self.native_dump = (0, lab_target.FRESH_FORM.encode(), b'')
        self.users = [(0, 0, 'RUNNING_UNLOCKED')]
        # Receipts a test fixture says users gave: dicts of user, serial, ticket, index and route,
        # each stamped with its event's boot and uptime when it is written.
        self.receipts = EventRows(self)
        # The next profile: user types and markers, the current user and whether a dump is whole;
        # the notice fixture's rows, what each user's display shows and each capture of it; and
        # health.
        self.user_types = {}
        self.user_marks = {}
        self.current_user = 0
        self.inventory_whole = True
        self.rows = []
        self.shown = {}
        self.captured = {}
        self.awake = True
        self.focused = True
        self.health_statuses = {}
        self.prepared = {}
        self.witness = {}
        self.files = {}
        self.calls = []
        self.next_session = 1189842383 + seed
        # The global session inventory: whether a dump is whole, and rows of other packages or
        # families a test adds as they stand.
        self.global_whole = True
        self.foreign_sessions = []
        # Kernel boots: whether the boot completed, the framework instance a next boot starts at
        # when a test sets it, base.apk digests signed by another key, and whether a rejected
        # activation's native recovery boots again at once.
        self.boot_completed = True
        self.next_instance = None
        self.wrong_signer = set()
        self.recovery_boots = True
        # command prefix -> list of scripted outcomes, consumed in order: 'before' (no effect, no reply),
        # 'after' (effect, no reply), or a callable(command) returning a ShellResult.
        self.scripts = {}
        self.hooks = []
        self.apks = {}
        self.features = ('cmd', 'shell_v2', 'stat_v2')
        # The health package: whether the UI state helper's pinned bytes are at their path, the
        # keyguard, each user's disposable PIN and lock, UI state answers a test makes unavailable,
        # the APKs that draw variant A's marker, and the work fixture's CE sentinels.
        self.ui_helper = True
        self.keyguard_locked = False
        self.pins = {}
        self.locked_users = set()
        self.ui_unavailable = {}
        self.marker_apks = set()
        self.ce_sentinels = {}
        self.private_scripts = []
        self.clock = ('10:42', '10:42 PM')
        self.hierarchy_change = None
        # The full user forms' model, when a test enables it.
        self.forms = None
        # The process health helper: whether its pinned bytes are at their path, the exit records
        # Android keeps for each package UID, the processes now in an error state, the reads a test
        # makes fail, and a step of the wall clock against the elapsed time.
        self.process_helper = True
        self.exit_rows = []
        self.error_states = []
        self.process_failures = {}
        self.wall_step = 0

    def enable_user_forms(self, serial=0):
        """Answers the user commands of full_users.py from sim_users.py's model of the users."""
        self.forms = sim_users.SimUsers(self, serial)
        self.forms.sync()
        return self.forms

    # ------------------------------------------------ world events

    def new_boot(self):
        self.boots += 1
        self.boot = hashlib.sha256(b'boot-%d-%d' % (self.seed, self.boots)).hexdigest()[:32]
        self.uptime = 30_000
        self.instance = 4000 + self.boots if getattr(self, 'next_instance', None) is None else self.next_instance
        self.next_instance = None
        self.framework = True
        if getattr(self, 'pins', None):
            self.locked_users = set(self.pins)
            self.keyguard_locked = 0 in self.pins
        if getattr(self, 'forms', None) is not None:
            self.forms.boot()

    def tick(self, ms):
        self.uptime += ms

    def wall(self):
        """The guest's wall clock in milliseconds: its base, its uptime and any step a test made."""
        return WALL_BASE + self.uptime + self.wall_step

    def boot_uuid(self):
        """The kernel's boot ID as `/proc/sys/kernel/random/boot_id` prints it: this boot's
        identity in the form of a random UUID."""
        h = self.boot
        v = h[:12] + '4' + h[13:16] + '89ab'[int(h[16], 16) % 4] + h[17:32]
        return '%s-%s-%s-%s-%s' % (v[:8], v[8:12], v[12:16], v[16:20], v[20:32])

    def systemui_exit(self, user, reason=4, published=True, restarted=True, pid=None, **fields):
        """The user's main SystemUI process ends, as a test says: Android's exit record of it at the
        guest's wall time when it is published, and a new process when Android restarts it.
        Returns the record."""
        old = self.forms.processes.pop(user)
        uid = user * 100000 + sim_users.APP_ID
        row = dict({'timestamp': self.wall(), 'pid': old[0] if pid is None else pid, 'real_uid': uid,
                    'package_uid': uid, 'defining_uid': uid, 'user': user, 'process': PACKAGE, 'reason': reason,
                    'subreason': 0, 'status': 0}, **fields)
        if published:
            self.exit_rows.append(row)
        if restarted:
            self.forms.new_process(user)
        return row

    def _process_health(self, command):
        """The process health helper's forms: its digest, its reply for one user from the model, the
        boot ID and system_server's stat. None for another command."""
        if command == process_health.HELPER_DIGEST:
            if not self.process_helper:
                return result(command, 1, b'', ('sha256sum: %s: No such file or directory\n'
                                                % process_health.HELPER).encode())
            digest = process_health.HELPER_SHA256 if self.process_helper is True else self.process_helper
            return result(command, 0, ('%s  %s\n' % (digest, process_health.HELPER)).encode())
        match = process_health._INVOCATION.fullmatch(command)
        if match:
            user = int(match[1])
            self.calls.append(('process-health', user))
            uid = user * 100000 + sim_users.APP_ID
            rows = sorted((r for r in self.exit_rows if r['package_uid'] == uid), key=lambda r: -r['timestamp'])
            history = self.process_failures.get('history') or ('OK', rows)
            current = self.process_failures.get('current') or ('OK', list(self.error_states))
            code, text = process_health_reply(user, history, current, [[self.uptime, self.wall()]] * 4)
            return result(command, code, text.encode())
        if command == health_witness.BOOT_ID:
            return result(command, 0, (self.boot_uuid() + '\n').encode())
        if command == 'cat /proc/937/stat' and self.framework:
            fields = ['S', '1', '937', '0', '0', '-1', '1077936384', '412113', '0', '1302', '0', '9241', '4532', '0',
                      '0', '18', '-2', '187', '0', str(self.instance), '18043473920', '86017']
            return result(command, 0, ('937 (system_server) %s\n' % ' '.join(fields)).encode())
        return None

    def framework_restart(self):
        """A later framework instance in the same boot. Uncommitted sessions are kept in this model."""
        self.instance += 100
        self.uptime += 1000

    def reboot(self):
        """A kernel boot: a ready session applies its bundle, unless it is a direct control's
        negative payload, which fails with its cause and leaves the factory copy active; its
        native recovery then boots again at once. Uncommitted sessions are kept."""
        rejected = False
        for s in self.sessions.values():
            if s.state != 'READY':
                continue
            apk = s.members.get('base.apk')
            if s.control is not None and 'base.apk.idsig' not in s.members:
                s.state, s.cause, rejected = 'FAILED', 'FS_VERITY', True
            elif s.control is not None and apk in self.wrong_signer:
                s.state, s.cause, rejected = 'FAILED', 'SIGNATURE', True
            else:
                self.active = ('DATA_COPY', apk, self.apks.get(apk, 40))
                s.state = 'APPLIED'
        self.new_boot()
        if rejected and self.recovery_boots:
            self.new_boot()

    # ------------------------------------------------ transport

    def _script(self, command):
        for prefix, outcomes in self.scripts.items():
            if command.startswith(prefix) and outcomes:
                return outcomes.pop(0)
        return None

    def shell(self, command, timeout, stdout_max, stderr_max, may_send=None, private=None):
        for hook in list(self.hooks):
            hook(command)
        # The hooks stand for the transport's connection and device selection; the launch deadline
        # is asked after them, right before the service request.
        if may_send is not None and not may_send():
            return result(command, completion='not-started', launch='not-launched', transport='launch-deadline',
                          error='the launch deadline passed before the service request')
        # A command given private input takes its scripted outcome only from `private_scripts`.
        if private is not None:
            scripted = self.private_scripts.pop(0) if self.private_scripts else None
        else:
            scripted = self._script(command)
        if callable(scripted):
            return scripted(command)
        if scripted == 'before':
            return result(command, completion='eof-before-exit', transport='closed', error='scripted loss')
        reply = self._private(command, private) if private is not None else self._run(command)
        if scripted == 'after':
            return result(command, completion='eof-before-exit', transport='closed', error='scripted loss')
        if scripted == 'timeout':
            return result(command, completion='timeout', transport='timeout', error='scripted timeout')
        return reply

    def push(self, data, path, mode, mtime, timeout):
        for hook in list(self.hooks):
            hook('push ' + path)
        self.calls.append(('push', path))
        self.files[path] = bytes(data)
        return shell_transport.PushResult(path, len(data), 'launched', 'ok', 'ok', None, None, 1, 2, 1)

    def reboot_service(self, may_send=None):
        for hook in list(self.hooks):
            hook('adb service reboot:')
        if may_send is not None and not may_send():
            return shell_transport.RebootResult('not-launched', 'launch-deadline', 'none', 'not-started', b'', None,
                                                'the launch deadline passed before the service request', 1, 2, 1)
        self.calls.append(('reboot', self.boot))
        self.reboot()
        return shell_transport.RebootResult('launched', 'ok', 'accepted', 'eof', b'', None, None, 1, 2, 1)

    def _run(self, command):
        if command == NOTICE_COMMAND:
            # A test fake of a notice fixture: it accepts the request. No user sees anything, and no
            # receipt follows from it.
            self.calls.append(('NOTICE',))
            return result(command, 0, b'notice requested\n')
        if command == 'logcat -b all -d':
            self.calls.append(('logcat',))
            return result(command, 0, b'--------- beginning of main\n')
        if command == lab_target.COMMAND:
            code, stdout, stderr = self.native_dump
            return result(command, code, stdout, stderr)
        if command == 'am restart':
            # The framework restarts in the same boot: a later instance; uncommitted sessions are kept.
            self.calls.append(('am restart', self.boot))
            self.framework_restart()
            return result(command, 0)
        if command == 'pidof system_server':
            return result(command, 0, b'937\n') if self.framework else result(command, 1)
        if command in SIM_READS or command in NEXT_READS or PER_USER_READ.fullmatch(command):
            return result(command, 0, json.dumps(self._read(command), sort_keys=True).encode() + b'\n')
        reply = self._health(command)
        if reply is not None:
            return reply
        if self.forms is not None:
            reply = self.forms.run(command)
            if reply is not None:
                self.calls.append(('user', command))
                return reply
        match = PRESENT.fullmatch(command)
        if match:
            return self._present(command, match)
        match = VISIBILITY.fullmatch(command)
        if match:
            user = int(match[2])
            if match[1] == 'capture':
                self.calls.append(('capture-visibility', user))
                self.captured[user] = self._display(user)
                return result(command, 0, b'captured\n')
            if user not in self.captured:
                return result(command, 1, b'', b'no capture\n')
            return result(command, 0, json.dumps(self.captured[user], sort_keys=True).encode() + b'\n')
        match = PREPARE.fullmatch(command)
        if match:
            self.calls.append(('prepare', int(match[1])))
            self.prepared[int(match[1])] = {'criteria': [int(c) for c in match[2].split(',')], 'challenge': match[3]}
            return result(command, 0, b'prepared\n')
        if command.startswith('sha256sum '):
            path = command[len('sha256sum '):]
            if path not in self.files:
                return result(command, 1, b'', b'sha256sum: %s: No such file or directory\n' % path.encode())
            digest = hashlib.sha256(self.files[path]).hexdigest()
            return result(command, 0, ('%s  %s\n' % (digest, path)).encode())
        match = re.fullmatch(r'pm install-create --user 0 -r --pkg (\S+) --staged --referrer '
                             r'andrix-(ticket|lab-control):([0-9a-f]{32})', command)
        if match:
            control = match[2] == 'lab-control'
            self.calls.append(('CREATE', match[3]))
            self.next_session += 7
            s = Session(self.next_session, WALL_BASE + self.uptime, None if control else match[3], instance=self.instance,
                        control=match[3] if control else None)
            self.sessions[s.identity] = s
            return result(command, 0, b'Success: created install session [%d]\n' % s.identity)
        match = re.fullmatch(r'pm install-write ([0-9]+) (base\.apk|base\.apk\.idsig) (\S+)', command)
        if match:
            self.calls.append(('WRITE', int(match[1]), match[2]))
            s = self.sessions.get(int(match[1]))
            data = self.files.get(match[3])
            if s is None or s.state != 'OPEN' or data is None:
                return result(command, 1, b'', b'Error: write failed\n')
            s.members[match[2]] = hashlib.sha256(data).hexdigest()
            return result(command, 0, b'Success: streamed %d bytes\n' % len(data))
        match = re.fullmatch(r'pm install-commit --staged-ready-timeout 60000 ([0-9]+)', command)
        if match:
            self.calls.append(('COMMIT', int(match[1])))
            s = self.sessions.get(int(match[1]))
            if s is None or s.state != 'OPEN':
                return result(command, 1, b'Failure [unknown]\n')
            s.state = 'READY'
            return result(command, 0, lab_crossings.READY)
        match = re.fullmatch(r'pm install-abandon ([0-9]+)', command)
        if match:
            self.calls.append(('ABANDON', int(match[1])))
            s = self.sessions.get(int(match[1]))
            if s is None:
                return result(command, 1, b'', b'Error: no session\n')
            s.state = 'ABANDONED'
            return result(command, 0, b'Success\n')
        return result(command, 127, b'', b'/system/bin/sh: unknown command\n')

    def _read(self, command):
        if command == 'sim:clock':
            return {'boot': self.boot, 'instance': self.instance if self.framework else -1, 'elapsed': self.uptime}
        if command == 'sim:boot':
            return {'boot': self.boot, 'elapsed': self.uptime, 'fingerprint': FINGERPRINT,
                    'state': 'COMPLETED' if self.boot_completed else 'BOOTING'}
        if command == 'sim:checkpoint':
            return {'boot': self.boot, 'elapsed': self.uptime, 'state': self.checkpoint}
        if command == 'sim:factory':
            return {'boot': self.boot, 'elapsed': self.uptime, 'apk': self.factory[0], 'version': self.factory[1]}
        if command == 'sim:active':
            return {'boot': self.boot, 'elapsed': self.uptime, 'kind': self.active[0], 'apk': self.active[1],
                    'version': self.active[2]}
        if command == 'sim:sessions':
            live = [s for s in self.sessions.values() if s.state not in ('ABANDONED',)]
            return {'boot': self.boot, 'elapsed': self.uptime, 'instance': self.instance,
                    'sessions': [[s.identity, s.created, s.nonce, s.state] for s in sorted(live, key=lambda x: x.identity)
                                 if s.package == PACKAGE]}
        if command == 'sim:receipts':
            return {'boot': self.boot, 'elapsed': self.uptime, 'receipts': list(self.receipts)}
        if command == 'sim:inventory':
            return self.inventory()
        if command == 'sim:global-sessions':
            return self.global_sessions()
        if command == 'sim:rows':
            return {'rows': [dict(row) for row in self.rows]}
        match = PER_USER_READ.fullmatch(command)
        if match and match[1] == 'baseline':
            user = int(match[2])
            return {'user': user, 'pid': 5000 + user, 'start_ticks': 7000 + self.instance, 'errors': 0}
        if match:
            user = int(match[2])
            prepared = self.prepared.get(user)
            return {'user': user, 'statuses': self.health_statuses.get(user, ['HELD'] * 7),
                    'challenge': prepared['challenge'] if prepared else None, 'witness': self.witness.get(user)}
        return {'boot': self.boot, 'elapsed': self.uptime, 'instance': self.instance,
                'users': [list(u) for u in self.users]}

    # ------------------------------------------------ the health package's guest

    def user_unlocked(self, user):
        """Whether a user runs with CE storage unlocked, in whichever user model is on."""
        if self.forms is not None:
            u = self.forms.users.get(user)
            return u is not None and u.state == 'RUNNING_UNLOCKED'
        return any(u == user and state == 'RUNNING_UNLOCKED' for u, _, state in self.users)

    def _current(self):
        return self.forms.current if self.forms is not None else self.current_user

    def _private(self, command, data):
        """`sh` given its input on private standard input. Only the PIN script's exact form does
        anything: it sets the user's PIN unless the user has a credential or does not run with CE
        storage unlocked, and every stream of `locksettings` is discarded. Anything else fails as a
        shell would. `private_echo` stands for a guest whose output still shows the PIN."""
        self.calls.append(('private', command))
        match = PIN_SCRIPT.fullmatch(data.decode('ascii', 'replace'))
        if command != 'sh' or match is None:
            return result(command, 1, b'', b'sh: syntax error\n')
        user, pin = int(match[1]), match[2]
        if user in self.pins or not self.user_unlocked(user):
            return result(command, 255)
        self.pins[user] = pin
        if getattr(self, 'private_echo', False):
            return result(command, 0, b"Pin set to '%s'\n" % pin.encode())
        return result(command, 0)

    def _ui_state(self, command, user):
        """The UI state helper's reply from the model, in its exact form."""
        values = {'interactive': self.awake, 'keyguard_locked': self.keyguard_locked,
                  'keyguard_secure': user in self.pins, 'device_locked': user in self.locked_users,
                  'device_secure': user in self.pins, 'ce_unlocked': self.user_unlocked(user)}
        lines = [health_compose.UI_STATE_HEADER, 'user=%d' % user,
                 'capabilities=' + ','.join(health_compose.UI_STATE_CAPABILITIES)]
        for name in health_compose.UI_STATE_CAPABILITIES:
            missing = self.ui_unavailable.get(name)
            lines.append('%s=%s' % (name, 'unavailable:' + missing if missing else 'true' if values[name] else 'false'))
        complete = not self.ui_unavailable
        lines += ['status=' + ('complete' if complete else 'unavailable'), 'end=' + health_compose.UI_STATE_HEADER]
        return result(command, 0 if complete else 5, ('\n'.join(lines) + '\n').encode())

    def hierarchy(self):
        """A dump of all windows of the default display as the dumper writes one: the status bar
        with its clock as the active APK draws it, the launcher, and the notice fixture's window
        when a notice shows on the current user's display. `hierarchy_change` may rewrite it."""
        from xml.sax.saxutils import quoteattr
        text, description = self.clock
        if self.active[1] in self.marker_apks:
            text, description = text + ' WS-A', description + ' WS-A'

        def node(index, text, ident, kind, package, description, bounds, inner=''):
            return ('<node index="%d" text=%s resource-id=%s class=%s package=%s content-desc=%s checkable="false" '
                    'checked="false" clickable="false" enabled="true" focusable="false" focused="false" '
                    'scrollable="false" long-clickable="false" password="false" selected="false" bounds=%s '
                    'drawing-order="0" hint="">%s</node>' % (index, quoteattr(text), quoteattr(ident), quoteattr(kind),
                                                              quoteattr(package), quoteattr(description),
                                                              quoteattr(bounds), inner))

        def window(index, title, bounds, active, kind, nodes):
            return ('<window index="%d" title=%s bounds=%s active="%s" focused="%s" accessibility-focused="false" '
                    'id="%d" layer="%d" type="%s"><hierarchy rotation="0">%s</hierarchy></window>'
                    % (index, quoteattr(title), quoteattr(bounds), active, active, 7 + index, 3 - index, kind, nodes))
        clock = node(0, text, health_compose.CLOCK_ID, 'android.widget.TextView', PACKAGE, description, '[42,0][150,63]')
        windows = [window(0, 'StatusBar', '[0,0][1080,63]', 'false', 'TYPE_SYSTEM',
                          node(0, '', '', 'android.widget.FrameLayout', PACKAGE, '', '[0,0][1080,63]', clock))]
        shown = self.shown.get(self._current())
        if shown is not None:
            windows.append(window(len(windows), 'Notice', '[0,0][1080,2400]', 'true', 'TYPE_APPLICATION',
                                  node(0, shown['challenge'], '', 'android.widget.TextView', NOTICE_PACKAGE, '',
                                       '[0,600][1080,900]')))
        windows.append(window(len(windows), 'Launcher', '[0,0][1080,2400]', 'false' if shown else 'true',
                              'TYPE_APPLICATION', node(0, '', '', 'android.widget.FrameLayout', 'com.android.launcher3',
                                                       '', '[0,0][1080,2400]')))
        xml = ("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><displays><display id=\"0\">%s</display>"
               "</displays>" % ''.join(windows))
        return self.hierarchy_change(xml) if self.hierarchy_change else xml

    def _health(self, command):
        """The health package's forms and fakes, or None for another command."""
        if command == health_compose.SHELL_IDENTITY:
            return result(command, 0, SHELL_ID)
        if command == health_compose.HELPER_DIGEST:
            if not self.ui_helper:
                return result(command, 1, b'', ('sha256sum: %s: No such file or directory\n'
                                                % health_compose.UI_STATE_HELPER).encode())
            digest = health_compose.UI_STATE_HELPER_SHA256 if self.ui_helper is True else self.ui_helper
            return result(command, 0, ('%s  %s\n' % (digest, health_compose.UI_STATE_HELPER)).encode())
        match = health_compose._UI_STATE.fullmatch(command)
        if match:
            self.calls.append(('ui-state', int(match[1])))
            return self._ui_state(command, int(match[1]))
        if health_compose._HIERARCHY_READ.fullmatch(command):
            path = command[len('cat '):]
            if path not in self.files:
                return result(command, 1, b'', ('cat: %s: No such file or directory\n' % path).encode())
            return result(command, 0, self.files[path])
        match = SIM_UI.fullmatch(command)
        if match:
            self.calls.append(('ui', match[1].split(' ')[0]))
            current = self._current()
            if match[1] == 'relock':
                if current in self.pins:
                    self.keyguard_locked = True
                    self.locked_users.add(current)
            elif match[1].startswith('credential-unlock'):
                user = int(match[1].split(' ')[1])
                if user != current or user not in self.pins:
                    return result(command, 1, b'', b'no credential prompt\n')
                self.keyguard_locked = False
                self.locked_users.discard(user)
                if self.forms is not None and self.forms.users[user].state == 'RUNNING_LOCKED':
                    self.forms.users[user].state = 'RUNNING_UNLOCKED'
                    self.forms.sync()
            else:
                path = match[2]
                self.files[path] = self.hierarchy().encode('utf-8')
                return result(command, 0, ('UI hierchary dumped to: %s\n' % path).encode())
            return result(command, 0)
        reply = self._process_health(command)
        if reply is not None:
            return reply
        match = SENTINEL.fullmatch(command)
        if match:
            parts = match[1].split(' ')
            user = int(parts[1])
            self.calls.append(('sentinel', parts[0], user))
            if parts[0] == 'write':
                if not self.user_unlocked(user):
                    return result(command, 1, b'', b'locked\n')
                self.ce_sentinels[user] = parts[2]
                return result(command, 0, b'written\n')
            if not self.user_unlocked(user):
                return result(command, 1, b'', b'locked\n')
            found = self.ce_sentinels.get(user)
            return result(command, 0, ('nonce=%s\n' % found).encode() if found else b'absent\n')
        return None

    # ------------------------------------------------ the next profile's guest

    def serial(self, user):
        return [s for u, s, _ in self.users if u == user][0]

    def global_sessions(self):
        """Every session in the global inventory's projected form, then the rows a test added."""
        rows = []
        for s in sorted(self.sessions.values(), key=lambda x: x.identity):
            live = s.state in ('OPEN', 'READY')
            rows.append({'section': 'ACTIVE' if live else 'FINALIZED', 'id': s.identity, 'package': s.package,
                         'referrer': ('andrix-lab-control:%s' % s.control) if s.control else 'andrix-ticket:%s' % s.nonce,
                         'staged': True, 'multi_package': False, 'parent': -1, 'children': [],
                         'sealed': s.state != 'OPEN', 'committed': s.state not in ('OPEN', 'ABANDONED'),
                         'ready': s.state == 'READY', 'applied': s.state == 'APPLIED', 'failed': s.state == 'FAILED',
                         'destroyed': s.state == 'ABANDONED', 'created': s.created, 'installer': 2000,
                         'cause': s.cause})
        return {'whole': self.global_whole, 'sessions': rows + [dict(row) for row in self.foreign_sessions]}

    def inventory(self):
        users = []
        for user, serial, state in self.users:
            marks = self.user_marks.get(user, {})
            users.append({'id': user, 'serial': serial,
                          'type': self.user_types.get(user, SYSTEM_TYPE if user == 0 else SECONDARY_TYPE),
                          'state': state, 'flags': 0x13 if user == 0 else 0x10, 'restrictions': [], 'parent': -10000,
                          'removing': marks.get('removing', False), 'partial': marks.get('partial', False),
                          'precreated': marks.get('precreated', False)})
        return {'whole': self.inventory_whole, 'current_user': self.current_user, 'users': users}

    def _present(self, command, match):
        """The notice fixture fake shows a notice on one user's display and writes that user's
        row once: its user and serial from the guest, its candidate time now. A repeat shows it
        again and never rewrites the first row."""
        user, installation, ticket, index, plan, boot, challenge, text = match.groups()
        user, index = int(user), int(index)
        self.calls.append(('present', user))
        if user not in [u for u, _, _ in self.users]:
            return result(command, 1, b'', b'no such user\n')
        row = {'purpose': 'TICKET_NOTICE', 'installation': installation, 'component': PACKAGE, 'plan': plan,
               'ticket': ticket, 'index': index, 'control': None, 'boot': boot, 'text_sha256': text, 'event': challenge,
               'uid': user * 100000 + APP_ID, 'user': user, 'serial': self.serial(user),
               'candidate_elapsed': self.uptime}
        key = (row['purpose'], boot, ticket, index, user, row['serial'])
        if not any((r['purpose'], r['boot'], r['ticket'], r['index'], r['user'], r['serial']) == key for r in self.rows):
            self.rows.append(row)
        self.shown[user] = {'challenge': challenge, 'ticket': ticket, 'index': index}
        return result(command, 0, b'presented\n')

    def _display(self, user):
        """What a capture of one user's display records now: the notice is visible only on the
        current user's awake display."""
        shown = self.shown.get(user)
        current = user == self.current_user
        return {'user': user, 'serial': self.serial(user), 'current_user': self.current_user, 'awake': self.awake,
                'focused': self.focused and current and shown is not None,
                'challenge': shown['challenge'] if shown and current else NO_CHALLENGE,
                'visible': bool(shown) and current and self.awake}


class SimNotice:
    """A test notice route: its one fixed command, classified SUCCESS only when it completed whole
    with status 0. SUCCESS says only that the fake accepted the request. For the next profile it
    presents an issued notice to each required recipient, and captures then reads one recipient's
    display for its visibility."""

    def allowed(self, command):
        return command == NOTICE_COMMAND or bool(PRESENT.fullmatch(command) or VISIBILITY.fullmatch(command))

    def notice(self, run, ticket, index, plan):
        result_ = run(NOTICE_COMMAND)
        if not result_.completed:
            raise lab_readers.Unavailable('the notice did not complete')
        return 'SUCCESS' if result_.exit == 0 and result_.stderr == b'' else 'UNRECOGNIZED'

    def present(self, run, issue):
        for r in issue['required']:
            result_ = run('sim:present %d %s %s %d %s %s %s %s' % (
                r['user'], issue['installation'], issue['ticket'], issue['index'], issue['plan'], issue['boot'],
                issue['challenge'], issue['text_sha256']))
            if not result_.completed:
                raise lab_readers.Unavailable('the presentation did not complete')
            if (result_.exit, result_.stdout, result_.stderr) != (0, b'presented\n', b''):
                return 'UNRECOGNIZED'
        return 'SUCCESS'

    def visibility(self, effect, read, issue, user):
        captured = effect('sim:capture-visibility %d' % user['id'])
        if (captured.exit, captured.stdout) != (0, b'captured\n'):
            raise lab_readers.Unclassified('a capture of no known form')
        value = json.loads(read('sim:read-visibility %d' % user['id']).stdout)
        return {key: value[key] for key in ('user', 'serial', 'current_user', 'awake', 'focused', 'challenge',
                                            'visible')}


class SimHealth:
    """A test health adapter: one fixed preparation command per use, PREPARED for its exact form."""

    def allowed(self, command):
        return bool(PREPARE.fullmatch(command))

    def prepare(self, effect, read, binding):
        done = effect('sim:prepare %d %s %s' % (binding['id'], ','.join(str(c) for c in binding['criteria']),
                                                binding['challenge']))
        return 'PREPARED' if (done.exit, done.stdout, done.stderr) == (0, b'prepared\n', b'') else 'UNRECOGNIZED'


class SimUiPreparation:
    """A test health adapter for the real composer: a credential unlock (criterion 3) from a
    relocked keyguard, then a fresh dump of all windows (criterion 2) under the operation's own
    path, each between reads of the current user and the UI state helper, and for the unlock of a
    whole inventory, returning the result their readers judge. Its effects are test fakes; its
    reads are the forms the composer reads. `changes` may rewrite the result, for a contrary one."""

    def __init__(self, changes=None, relock=True):
        self.changes, self.relock = changes, relock

    def allowed(self, command):
        return bool(command in (full_users.CURRENT, full_users.DUMP, full_users.LIST, health_compose.SHELL_IDENTITY,
                                health_compose.HELPER_DIGEST) or health_compose._UI_STATE.fullmatch(command)
                    or SIM_UI.fullmatch(command))

    def prepare(self, effect, read, binding):
        user, criteria = binding['id'], binding['criteria']

        def run(command):
            return streams(read(command))

        def condition(with_state):
            value = {'current_user': full_users.parse_current(*run(full_users.CURRENT)),
                     'ui_state': health_compose.read_ui_state(run, user)}
            if with_state:
                found = full_users.find(full_users.UserReader(run).inventory(), user)
                value['state'] = found[0]['state'] if found else 'NOT_RUNNING'
            return value
        parts = {}
        if 3 in criteria:
            if self.relock:
                effect('sim:relock')
            before = condition(True)
            effect('sim:credential-unlock %d' % user)
            parts['3'] = {'route': 'CREDENTIAL_UI', 'before': before, 'after': condition(True)}
        if 2 in criteria:
            before = condition(False)
            path = health_compose.hierarchy_path(binding['operation'])
            done = effect('sim:dump-windows ' + path)
            parts['2'] = {'path': path, 'acknowledged': streams(done) == (0, 'UI hierchary dumped to: %s\n' % path, ''),
                          'before': before, 'after': condition(False)}
        result_ = {'schema': 'andrix-health-preparation-result-v1', 'user': user, 'serial': binding['serial'],
                   'criteria': parts}
        if self.changes is not None:
            result_ = self.changes(result_)
        return 'PREPARED', result_


class SimWork:
    """A test work fixture adapter: CE_SENTINEL's fixed write and read only readback, test
    fakes of the work fixture that is a later package."""

    def allowed(self, command):
        return bool(SENTINEL.fullmatch(command))

    def write_sentinel(self, effect, read, binding):
        done = effect('sim:sentinel-write %d %s' % (binding['id'], binding['nonce']))
        if streams(done) == (0, 'written\n', ''):
            return 'WRITTEN'
        if streams(done) == (1, '', 'locked\n'):
            return 'REFUSED'
        return 'UNRECOGNIZED'

    def read_sentinel(self, read, binding):
        return self.parse_sentinel(*streams(read('sim:sentinel-read %d' % binding['id'])), binding)

    @staticmethod
    def parse_sentinel(code, stdout, stderr, binding):
        match = re.fullmatch(r'nonce=([0-9a-f]{32})\n', stdout) if isinstance(stdout, str) else None
        if code == 0 and stderr == '' and match:
            return {'status': 'PRESENT', 'nonce': match[1]}
        if (code, stdout, stderr) == (0, 'absent\n', ''):
            return {'status': 'ABSENT'}
        if code == 1 and stderr == 'locked\n':
            raise lab_readers.Unavailable('the fixture cannot read its CE storage now')
        raise lab_readers.Unclassified('a sentinel read of no known form')


class SimCeReader:
    """The composer's CE nonce hook over the same fake read: the work fixture's own read only
    readback, a later package's."""

    def allowed(self, command):
        return bool(re.fullmatch(r'sim:sentinel-read [0-9]+', command))

    def read(self, calls, context):
        return SimWork.parse_sentinel(*calls.run('sim:sentinel-read %d' % context['user']), context)


class SimTransport:
    """The broker's transport over the simulated guest."""

    def __init__(self, sim):
        self.sim = sim

    def shell(self, command, timeout, stdout_max, stderr_max, may_send=None, private=None):
        if private is not None:
            return self.sim.shell(command, timeout, stdout_max, stderr_max, may_send, private)
        return self.sim.shell(command, timeout, stdout_max, stderr_max, may_send)

    def push(self, data, path, mode, mtime, timeout):
        return self.sim.push(data, path, mode, mtime, timeout)

    def features(self, timeout, may_send=None):
        if may_send is not None and not may_send():
            return shell_transport.FeaturesResult('launch-deadline', (), None, 'the launch deadline passed before the request')
        self.sim.calls.append(('features',))
        if self.sim.features is None:
            return shell_transport.FeaturesResult('unknown', (), None, 'scripted loss')
        return shell_transport.FeaturesResult('ok', tuple(self.sim.features), None, None)

    def reboot(self, timeout, may_send=None):
        return self.sim.reboot_service(may_send)


class SimReader(lab_readers.ReaderAdapter):
    """Facts from the simulated guest, through the broker's run function."""

    def __init__(self, installation, component=PACKAGE, ids=None, receipts=False, target=False, inventory=False,
                 health=False, witness=False, global_sessions=False, users=False, composer=None, baseline=None):
        self.installation, self.component = installation, component
        # A receipt reader is admitted only when a test asks for one; the target reader likewise,
        # and the next profile's inventory, health and witness readers. With `users`, the full
        # user readers of full_users.py read the guest's user forms, the inventory included.
        self.receipts_admitted = receipts
        self.target_admitted = target
        self.inventory_admitted = inventory or users
        self.health_admitted = health
        self.witness_admitted = witness
        self.global_admitted = global_sessions
        self.users_admitted = users
        self._run = None
        self._captures = []
        self._count = 0
        self._ids = ids
        # The health package's real readers over the simulated guest's forms, when a test gives
        # them.
        self.composer, self.baseline_reader = composer, baseline

    def allowed(self, command):
        return (command in SIM_READS or command in NEXT_READS or bool(PER_USER_READ.fullmatch(command))
                or (self.target_admitted and command == lab_target.COMMAND)
                or (self.users_admitted and full_users.read_allowed(command))
                or (self.composer is not None and self.composer.allowed(command))
                or (self.baseline_reader is not None and self.baseline_reader.allowed(command)))

    def target(self):
        if self._run is None:
            raise lab_readers.Unavailable('no group is open')
        code, stdout, stderr = self._run(lab_target.COMMAND)
        self._captures.append((lab_target.COMMAND, code, stdout.encode('utf-8', 'surrogateescape'),
                               stderr.encode('utf-8', 'surrogateescape')))
        return lab_target.scope(code, stdout, stderr)

    def bind(self, run):
        self._run, self._captures = run, []

    def _read(self, command):
        if self._run is None:
            raise lab_readers.Unavailable('no group is open')
        code, stdout, stderr = self._run(command)
        self._captures.append((command, code, stdout.encode('utf-8', 'surrogateescape'),
                               stderr.encode('utf-8', 'surrogateescape')))
        if code != 0:
            raise lab_readers.Unclassified('a read of no known form')
        return json.loads(stdout)

    def _id(self):
        self._count += 1
        if self._ids is not None:
            return self._ids(self._count)
        return os.urandom(16).hex()

    def _fact(self, value, kind, classification, component=None, instance=-1, user=-10000, serial=-1, facts=None,
              captures=None):
        # A fact read again from recorded captures takes no observation ID from the sequence.
        return {'installation': self.installation, 'observation': self._id() if captures is None else '00' * 16,
                'component': self.component if component is None else component, 'boot': value['boot'],
                'user': user, 'serial': serial, 'kind': kind, 'route': 'SHELL', 'instance': instance,
                'elapsed': value['elapsed'], 'wall': WALL_BASE + value['elapsed'],
                'raw': lab_readers.raw_digest(self._captures if captures is None else captures),
                'classification': classification, 'facts': facts or {}}

    def clock(self):
        value = self._read('sim:clock')
        return value['boot'], value['instance'], value['elapsed'], WALL_BASE + value['elapsed']

    def boot(self):
        value = self._read('sim:boot')
        return [self._fact(value, 'BOOT', value['state'], '', facts={'fingerprint': value['fingerprint']})]

    def checkpoint(self):
        value = self._read('sim:checkpoint')
        return [self._fact(value, 'CHECKPOINT', value['state'], '')]

    def factory(self, captures=None):
        value = self._read('sim:factory') if captures is None else self._again('sim:factory', captures)
        return [self._fact(value, 'FACTORY', 'PRESENT', facts={'apk': value['apk'], 'version': value['version']},
                           captures=captures)]

    def active(self, captures=None):
        value = self._read('sim:active') if captures is None else self._again('sim:active', captures)
        return [self._fact(value, 'ACTIVE', value['kind'], facts={'apk': value['apk'], 'version': value['version'],
                                                                   'uid': UID, 'context': CONTEXT}, captures=captures)]

    @staticmethod
    def _again(command, captures):
        """A fake read's value from its one recorded capture, which must be that read, whole."""
        if len(captures) != 1 or captures[0][0] != command or captures[0][1] != 0:
            raise lab_readers.Unclassified('the captures are not the reads a %s fact makes' % command)
        return json.loads(captures[0][2])

    def sessions(self):
        value = self._read('sim:sessions')
        rows = value['sessions']
        facts = [self._fact(value, 'LISTING', 'SESSIONS_FOR_PACKAGE' if rows else 'NONE_FOR_PACKAGE',
                            instance=value['instance'], facts={'count': len(rows)})]
        for identity, created, nonce, state in rows:
            # A direct control's session has no ticket nonce: its reference names none.
            reference = (31 if nonce else 15, identity, created, '/data/app-staging/session_%d' % identity, 2000,
                         nonce or '00' * 16)
            facts.append(self._fact(value, 'SESSION', state, instance=value['instance'],
                                    facts={'reference': reference}))
        return facts

    def receipts(self, ticket):
        """Every receipt the fixture lists, as RECEIPT facts at their event's boot and time. The
        broker and the bridge judge them."""
        value = self._read('sim:receipts')
        return [self._fact(dict(value, boot=r['boot'], elapsed=r['elapsed']), 'RECEIPT', r['route'], user=r['user'],
                           serial=r['serial'], facts={'ticket': r['ticket'], 'index': r['index']})
                for r in value['receipts']]

    # ------------------------------------------------ the next profile's readers

    def inventory(self):
        if self.users_admitted:
            return full_users.UserReader(self._raw).inventory()
        return self._read('sim:inventory')

    def _raw(self, command):
        """One command's whole reply as the broker's run function gives it."""
        if self._run is None:
            raise lab_readers.Unavailable('no group is open')
        code, stdout, stderr = self._run(command)
        self._captures.append((command, code, stdout.encode('utf-8', 'surrogateescape'),
                               stderr.encode('utf-8', 'surrogateescape')))
        return code, stdout, stderr

    def user_limits(self):
        return full_users.UserReader(self._raw).limits()

    def systemui_processes(self, inventory):
        return full_users.UserReader(self._raw).processes(inventory)

    def rederive(self, name, captures, inventory=None):
        if name in ('factory', 'active'):
            # The fake factory and active reads again, from their recorded bytes.
            return getattr(self, name)([(command, code, stdout.encode('utf-8', 'surrogateescape'),
                                         stderr.encode('utf-8', 'surrogateescape'))
                                        for command, code, stdout, stderr in captures])
        if not self.users_admitted:
            return NotImplemented
        return full_users.rederive(name, captures, inventory)

    def global_sessions(self):
        return self._read('sim:global-sessions')

    def receipt_rows(self, ticket):
        """Every row the provider returns, each with its exact bytes: the canonical form the fake
        fixture writes."""
        rows = []
        for row in self._read('sim:rows')['rows']:
            rows.append(dict(row, row=lab_evidence.canonical(row)))
        return rows

    def health_baseline(self, context):
        """The real baseline reader when a test gives one; otherwise one fake read, in the strict
        facts form, whose witness parts stand for a witness reader only when one is admitted."""
        if self.baseline_reader is not None:
            return self.baseline_reader.read(self._raw, context)
        value = self._read('sim:baseline %d' % context['user'])
        uid = context['user'] * full_users.PER_USER_RANGE + UID
        part = ({'status': 'OK', 'schema': 'andrix-sim-witness-v1', 'reading': {'errors': value['errors']}}
                if self.witness_admitted else {'status': 'NOT_ADMITTED'})
        process = {'pid': value['pid'], 'start_ticks': value['start_ticks'], 'uid': uid, 'uids': [uid] * 4,
                   'name': PACKAGE, 'comm': full_users.COMM, 'context': CONTEXT}
        facts = {'schema': 'andrix-health-baseline-facts-v1', 'user': context['user'], 'serial': context['serial'],
                 'state': 'RUNNING_UNLOCKED', 'app_id': UID, 'uid': uid, 'process': process, 'absent': False,
                 'history': part, 'current_errors': part, 'complete': self.witness_admitted}
        return {'user': context['user'], 'serial': context['serial'], 'facts': facts}

    def health_composition(self, context):
        """The real composer when a test gives one. Otherwise seven rows from one fresh read: each
        row names that read. The UI marker, unlock and native work rows name the offered
        preparation whose challenge the guest shows; the no crash row the offered baseline."""
        if self.composer is not None:
            return self.composer.compose(self._raw, context)
        at = len(self._captures)
        value = self._read('sim:health %d' % context['user'])
        rows = []
        for bit, status in enumerate(value['statuses']):
            preparation, baseline = None, None
            if bit in (2, 3, 5):
                offered = [p for p in context['preparations'] if p['challenge'] == value['challenge']
                           and bit in p['criteria']]
                preparation = offered[0]['operation'] if offered else None
            if bit == 1 and context['baseline'] is not None:
                baseline = context['baseline']['digest']
            rows.append({'bit': bit, 'status': status, 'reason': '' if status == 'HELD' else 'the guest read %s' % status,
                         'commands': [at], 'preparation': preparation, 'baseline': baseline})
        return {'user': context['user'], 'serial': context['serial'], 'rows': rows, 'witness': value['witness']}

    def users(self, previous):
        value = self._read('sim:users')
        facts = []
        shown = set()
        for user, serial, state in value['users']:
            shown.add((user, serial))
            facts.append(self._fact(value, 'USER', state, '', instance=value['instance'], user=user, serial=serial))
        for user, serial in previous:
            if (user, serial) not in shown:
                facts.append(self._fact(value, 'USER', 'REMOVED', '', instance=value['instance'], user=user,
                                        serial=serial))
        return facts
