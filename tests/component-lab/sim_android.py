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
users."""
from dataclasses import dataclass, field
import hashlib
import json
import os
import re

import full_users
import lab_crossings
import lab_evidence
import lab_readers
import lab_target
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


def result(command, code=0, stdout=b'', stderr=b'', completion='exited', launch='launched', transport='ok',
           error=None):
    """A ShellResult as the transport would give it."""
    frame = code if completion in ('exited', 'malformed') else None
    return shell_transport.ShellResult(shell_transport.SHELL_PREFIX + command, launch, transport, completion, frame,
                                       stdout, stderr, None, False, None, error, 1, 2, 1)


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
        # The full user forms' model, when a test enables it.
        self.forms = None

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
        if getattr(self, 'forms', None) is not None:
            self.forms.boot()

    def tick(self, ms):
        self.uptime += ms

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

    def shell(self, command, timeout, stdout_max, stderr_max, may_send=None):
        for hook in list(self.hooks):
            hook(command)
        # The hooks stand for the transport's connection and device selection; the launch deadline
        # is asked after them, right before the service request.
        if may_send is not None and not may_send():
            return result(command, completion='not-started', launch='not-launched', transport='launch-deadline',
                          error='the launch deadline passed before the service request')
        scripted = self._script(command)
        if callable(scripted):
            return scripted(command)
        if scripted == 'before':
            return result(command, completion='eof-before-exit', transport='closed', error='scripted loss')
        reply = self._run(command)
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


class SimTransport:
    """The broker's transport over the simulated guest."""

    def __init__(self, sim):
        self.sim = sim

    def shell(self, command, timeout, stdout_max, stderr_max, may_send=None):
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
                 health=False, witness=False, global_sessions=False, users=False):
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

    def allowed(self, command):
        return (command in SIM_READS or command in NEXT_READS or bool(PER_USER_READ.fullmatch(command))
                or (self.target_admitted and command == lab_target.COMMAND)
                or (self.users_admitted and full_users.read_allowed(command)))

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

    def _fact(self, value, kind, classification, component=None, instance=-1, user=-10000, serial=-1, facts=None):
        return {'installation': self.installation, 'observation': self._id(),
                'component': self.component if component is None else component, 'boot': value['boot'],
                'user': user, 'serial': serial, 'kind': kind, 'route': 'SHELL', 'instance': instance,
                'elapsed': value['elapsed'], 'wall': WALL_BASE + value['elapsed'],
                'raw': lab_readers.raw_digest(self._captures), 'classification': classification,
                'facts': facts or {}}

    def clock(self):
        value = self._read('sim:clock')
        return value['boot'], value['instance'], value['elapsed'], WALL_BASE + value['elapsed']

    def boot(self):
        value = self._read('sim:boot')
        return [self._fact(value, 'BOOT', value['state'], '', facts={'fingerprint': value['fingerprint']})]

    def checkpoint(self):
        value = self._read('sim:checkpoint')
        return [self._fact(value, 'CHECKPOINT', value['state'], '')]

    def factory(self):
        value = self._read('sim:factory')
        return [self._fact(value, 'FACTORY', 'PRESENT', facts={'apk': value['apk'], 'version': value['version']})]

    def active(self):
        value = self._read('sim:active')
        return [self._fact(value, 'ACTIVE', value['kind'], facts={'apk': value['apk'], 'version': value['version'],
                                                                   'uid': UID, 'context': CONTEXT})]

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
        value = self._read('sim:baseline %d' % context['user'])
        return {'user': context['user'], 'serial': context['serial'], 'facts': value}

    def health_composition(self, context):
        """Seven rows from one fresh read: each row names that read. The UI marker, unlock and
        native work rows name the offered preparation whose challenge the guest shows; the no
        crash row the offered baseline."""
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
