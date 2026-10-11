# SPDX-License-Identifier: Apache-2.0
"""Host test support: a small simulated guest behind the broker's transport and reader interfaces.

It models only what the broker and the bridge tests exercise: kernel boots, framework instances,
uptime, the checkpoint, the factory and active SystemUI, staged sessions with their native
references, users, and the typed crossing commands. Shell results are built with the real
ShellResult type, so the broker's completion rules apply unchanged. The reader reads through the
broker's run function with fixed `sim:` commands, which are test fakes, not guest forms. Nothing
here is Android evidence."""
from dataclasses import dataclass, field
import hashlib
import json
import os
import re

import lab_crossings
import lab_readers
import shell_transport

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


def result(command, code=0, stdout=b'', stderr=b'', completion='exited', launch='launched', transport='ok',
           error=None):
    """A ShellResult as the transport would give it."""
    frame = code if completion in ('exited', 'malformed') else None
    return shell_transport.ShellResult(shell_transport.SHELL_PREFIX + command, launch, transport, completion, frame,
                                       stdout, stderr, None, False, None, error, 1, 2, 1)


@dataclass
class Session:
    identity: int
    created: int
    nonce: str
    state: str = 'OPEN'
    members: dict = field(default_factory=dict)
    instance: int = 0


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
        self.users = [(0, 0, 'RUNNING_UNLOCKED')]
        # Receipts a test fixture says users gave: dicts of user, serial, ticket, index and route.
        self.receipts = []
        self.files = {}
        self.calls = []
        self.next_session = 1189842383 + seed
        # command prefix -> list of scripted outcomes, consumed in order: 'before' (no effect, no reply),
        # 'after' (effect, no reply), or a callable(command) returning a ShellResult.
        self.scripts = {}
        self.hooks = []
        self.apks = {}
        self.features = ('cmd', 'shell_v2', 'stat_v2')

    # ------------------------------------------------ world events

    def new_boot(self):
        self.boots += 1
        self.boot = hashlib.sha256(b'boot-%d-%d' % (self.seed, self.boots)).hexdigest()[:32]
        self.uptime = 30_000
        self.instance = 4000 + self.boots
        self.framework = True

    def tick(self, ms):
        self.uptime += ms

    def framework_restart(self):
        """A later framework instance in the same boot. Uncommitted sessions are kept in this model."""
        self.instance += 100
        self.uptime += 1000

    def reboot(self):
        """A kernel boot: a ready session applies its bundle."""
        for s in self.sessions.values():
            if s.state == 'READY':
                apk = s.members.get('base.apk')
                self.active = ('DATA_COPY', apk, self.apks.get(apk, 40))
                s.state = 'APPLIED'
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
        if command == 'pidof system_server':
            return result(command, 0, b'937\n') if self.framework else result(command, 1)
        if command in SIM_READS:
            return result(command, 0, json.dumps(self._read(command), sort_keys=True).encode() + b'\n')
        if command.startswith('sha256sum '):
            path = command[len('sha256sum '):]
            if path not in self.files:
                return result(command, 1, b'', b'sha256sum: %s: No such file or directory\n' % path.encode())
            digest = hashlib.sha256(self.files[path]).hexdigest()
            return result(command, 0, ('%s  %s\n' % (digest, path)).encode())
        match = re.fullmatch(r'pm install-create --user 0 -r --pkg (\S+) --staged --referrer andrix-ticket:([0-9a-f]{32})',
                             command)
        if match:
            self.calls.append(('CREATE', match[2]))
            self.next_session += 7
            s = Session(self.next_session, WALL_BASE + self.uptime, match[2], instance=self.instance)
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
            return {'boot': self.boot, 'elapsed': self.uptime, 'fingerprint': FINGERPRINT}
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
                    'sessions': [[s.identity, s.created, s.nonce, s.state] for s in sorted(live, key=lambda x: x.identity)]}
        if command == 'sim:receipts':
            return {'boot': self.boot, 'elapsed': self.uptime, 'receipts': list(self.receipts)}
        return {'boot': self.boot, 'elapsed': self.uptime, 'instance': self.instance,
                'users': [list(u) for u in self.users]}


class SimNotice:
    """A test notice route: its one fixed command, classified SUCCESS only when it completed whole
    with status 0. SUCCESS says only that the fake accepted the request."""

    def allowed(self, command):
        return command == NOTICE_COMMAND

    def notice(self, run, ticket, index, plan):
        result_ = run(NOTICE_COMMAND)
        if not result_.completed:
            raise lab_readers.Unavailable('the notice did not complete')
        return 'SUCCESS' if result_.exit == 0 and result_.stderr == b'' else 'UNRECOGNIZED'


class SimTransport:
    """The broker's transport over the simulated guest."""

    def __init__(self, sim):
        self.sim = sim

    def shell(self, command, timeout, stdout_max, stderr_max, may_send=None):
        return self.sim.shell(command, timeout, stdout_max, stderr_max, may_send)

    def push(self, data, path, mode, mtime, timeout):
        return self.sim.push(data, path, mode, mtime, timeout)

    def features(self, timeout):
        self.sim.calls.append(('features',))
        if self.sim.features is None:
            return shell_transport.FeaturesResult('unknown', (), None, 'scripted loss')
        return shell_transport.FeaturesResult('ok', tuple(self.sim.features), None, None)

    def reboot(self, timeout, may_send=None):
        return self.sim.reboot_service(may_send)


class SimReader(lab_readers.ReaderAdapter):
    """Facts from the simulated guest, through the broker's run function."""

    def __init__(self, installation, component=PACKAGE, ids=None, receipts=False):
        self.installation, self.component = installation, component
        # A receipt reader is admitted only when a test asks for one.
        self.receipts_admitted = receipts
        self._run = None
        self._captures = []
        self._count = 0
        self._ids = ids

    def allowed(self, command):
        return command in SIM_READS

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
        return [self._fact(value, 'BOOT', 'COMPLETED', '', facts={'fingerprint': value['fingerprint']})]

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
            reference = (31, identity, created, '/data/app-staging/session_%d' % identity, 2000, nonce)
            facts.append(self._fact(value, 'SESSION', state, instance=value['instance'],
                                    facts={'reference': reference}))
        return facts

    def receipts(self, ticket):
        """Every receipt the fixture lists, as RECEIPT facts. The broker and the bridge judge them."""
        value = self._read('sim:receipts')
        return [self._fact(value, 'RECEIPT', r['route'], user=r['user'], serial=r['serial'],
                           facts={'ticket': r['ticket'], 'index': r['index']}) for r in value['receipts']]

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
