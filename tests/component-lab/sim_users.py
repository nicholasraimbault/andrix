# SPDX-License-Identifier: Apache-2.0
"""Host test support: the simulated guest's users as the user commands of full_users.py print
them. Each form follows the Android source that full_users.py cites for its parser; the values are
illustrative. The model keeps the users, their states, flags, restrictions and setup, the current
and visible users, the limits, the fixtures installed for each user and the main SystemUI process
of each running user. Tests change it, or script a reply, to make the forms an honest or a contrary
guest would print. Nothing here is Android evidence: it shows no user created, started, switched
or set up, and no process."""
from dataclasses import dataclass, field
import hashlib

import full_users
import shell_transport

SYSTEM_TYPE = full_users.SYSTEM_TYPE
SECONDARY_TYPE = full_users.SECONDARY_TYPE
# The captured SystemUI UID of the system user, and the context a retained capture shows for it.
APP_ID = 10112
CONTEXT = 'u:r:platform_app:s0:c512,c768'
FINGERPRINT = 'andrix/cf/cf:17/BP4A.260813.001/2026081300:userdebug/test-keys'
TYPES = ('android.os.usertype.full.SYSTEM', 'android.os.usertype.full.SECONDARY', 'android.os.usertype.full.GUEST',
         'android.os.usertype.profile.MANAGED', 'android.os.usertype.profile.PRIVATE')
SECONDARY_DEFAULTS = ['no_outgoing_calls', 'no_sms']
PROPERTY_VALUES = {'mPropertiesPresent': '0', 'mShowInLauncher': '0', 'mStartWithParent': 'false',
                   'mShowInSettings': '0', 'mInheritDevicePolicy': '0', 'mUseParentsContacts': 'false',
                   'mUpdateCrossProfileIntentFiltersOnOTA': 'false', 'mCrossProfileIntentFilterAccessControl': '0',
                   'mCrossProfileIntentResolutionStrategy': '0', 'mMediaSharedWithParent': 'false',
                   'mCredentialShareableWithParent': 'false', 'mAuthAlwaysRequiredToDisableQuietMode': 'false',
                   'mAllowStoppingUserWithDelayedLocking': 'false', 'mDeleteAppWithParent': 'false',
                   'mAlwaysVisible': 'false', 'mCrossProfileContentSharingStrategy': '1', 'mProfileApiVisibility': '0',
                   'mItemsRestrictedOnHomeScreen': 'false'}


def result(command, code=0, stdout=b'', stderr=b''):
    return shell_transport.ShellResult(shell_transport.SHELL_PREFIX + command, 'launched', 'ok', 'exited', code, stdout,
                                       stderr, None, False, None, None, 1, 2, 1)


@dataclass
class SimUser:
    id: int
    serial: int
    type: str
    flags: int
    state: str = '-1'
    name: str = None
    base: list = field(default_factory=list)
    policy: list = field(default_factory=list)
    cached: bool = True
    setup: str = 'null'
    removing: bool = False
    partial: bool = False
    precreated: bool = False
    # Whether the user has ever run, so its login time and fingerprint are known.
    logged_in: bool = False


def flag_names(value):
    """DebugUtils.flagsToString of UserInfo's flags, in their names' order, as dex lists fields."""
    if value == 0:
        return '0'
    names = [name for name, bit in sorted(full_users.FLAGS.items()) if value & bit == bit]
    rest = value & ~sum(full_users.FLAGS[n] for n in names)
    return '|'.join(names + (['%x' % rest] if rest else []))


class SimUsers:
    """The simulated guest's users and their command forms."""

    def __init__(self, sim, serial=0):
        self.sim = sim
        self.users = {0: SimUser(0, serial, SYSTEM_TYPE, 0x4c13, 'RUNNING_UNLOCKED', setup='1', logged_in=True)}
        self.current = 0
        # Android takes the lowest unused ID from 10 on; a test may start higher, so no code relies
        # on user 10 or serial 10.
        self.next_user = 10
        self.next_serial = 17
        self.supports = True
        self.max_switchable = 4
        self.built_in = 32
        self.type_max = 3
        # UserTypeDetails.mEnabled, a boolean the dump prints as true or false.
        self.type_enabled = True
        self.max_running = 3
        self.global_restrictions = None
        self.guest_restrictions = ['no_outgoing_calls', 'no_sms']
        self.limit_reached = None
        # Each running user's main SystemUI process: user -> [pid, start ticks].
        self.processes = {0: [1839, 9120]}
        self.next_pid = 4721
        # Ordinary fixtures on the device: package -> its app ID, path, bytes and users.
        self.fixtures = {}
        # The setup each user's wizard still waits for, as steps; empty completes it.
        self.wizard = {}
        # Test levers: scripted replies by command prefix, process quirks, extra users.
        self.replies = {}
        self.pid_order = None
        self.proc_denied = set()
        self.extra_processes = []
        self.lru = [0]

    # ------------------------------------------------ helpers

    def running(self, user):
        return self.users[user].state in full_users.RUNNING_STATES

    def coarse(self, user):
        return full_users.COARSE[self.users[user].state]

    def sync(self):
        """The fake readers' view of the same users: (id, serial, coarse state), types and marks."""
        self.sim.users = [(u.id, u.serial, self.coarse(u.id)) for u in sorted(self.users.values(), key=lambda x: x.id)]
        self.sim.user_types = {u.id: u.type for u in self.users.values()}
        self.sim.user_marks = {u.id: {'removing': u.removing, 'partial': u.partial, 'precreated': u.precreated}
                               for u in self.users.values()}
        self.sim.current_user = self.current

    def effective(self, user):
        u = self.users[user]
        return sorted(set(u.base) | set(u.policy) | set(self.global_restrictions or ()))

    def boot(self):
        """A kernel boot: every user but the system user stops, the system user is current again,
        and every SystemUI process has a new identity."""
        # A user with a disposable PIN runs with CE storage locked until its credential unlock.
        for u in self.users.values():
            u.state = ('RUNNING_LOCKED' if u.id in self.sim.pins else 'RUNNING_UNLOCKED') if u.id == 0 else '-1'
        self.current = 0
        self.processes = {0: [1839 + self.sim.boots, 9120 + self.sim.boots]}
        self.lru = [0]
        self.sync()

    def new_process(self, user):
        self.next_pid += 13
        self.processes[user] = [self.next_pid, 50_000 + self.sim.uptime // 10]

    # ------------------------------------------------ the forms

    @staticmethod
    def _restrictions(lines, prefix, values):
        if values is None:
            lines.append(prefix + 'null')
        elif not values:
            lines.append(prefix + 'none')
        else:
            lines.extend(prefix + v for v in values)

    def dump(self):
        """UserManagerService.dump with no argument, its sections in their order."""
        lines = ['Current user: %d' % self.current, '', 'Users:']
        for u in sorted(self.users.values(), key=lambda x: x.id):
            head = '  UserInfo{%d:%s:%x} serialNo=%d isPrimary=%s' % (u.id, u.name if u.name is not None else 'null',
                                                                    u.flags, u.serial,
                                                                    'true' if u.flags & 1 else 'false')
            head += ' <removing> ' if u.removing else ''
            head += ' <partial>' if u.partial else ''
            head += ' <pre-created>' if u.precreated else ''
            lines.append(head)
            lines += ['    Type: ' + u.type, '    Flags: %d (%s)' % (u.flags, flag_names(u.flags)), '    State: ' + u.state,
                      '    Created: ' + ('<unknown>' if u.id == 0 else '+2h14m3s211ms ago'),
                      '    Last logged in: ' + ('+8m41s502ms ago' if u.logged_in else '<unknown>'),
                      '    Last logged in fingerprint: ' + (FINGERPRINT if u.logged_in else 'null'),
                      '    Start time: ' + ('+8m52s117ms ago' if self.running(u.id) else '<unknown>'),
                      '    Unlock time: ' + ('+8m41s498ms ago' if u.state == 'RUNNING_UNLOCKED' else '<unknown>'),
                      '    Last entered foreground: ' + ('+8m41s502ms ago' if u.id == self.current else '<unknown>'),
                      '    Restrictions:']
            self._restrictions(lines, '      ', u.base or None)
            lines.append('    Device policy restrictions:')
            self._restrictions(lines, '      ', u.policy or None)
            lines.append('    Effective restrictions:')
            self._restrictions(lines, '      ', (self.effective(u.id) or None) if u.cached else None)
            lines.append('    UserProperties:')
            lines += ['        %s=%s' % (name, PROPERTY_VALUES[name]) for name in full_users.PROPERTIES]
            lines.append('    Ignore errors preparing storage: false')
        lines += ['', 'Device properties:', '  Device policy global restrictions:']
        self._restrictions(lines, '    ', self.global_restrictions)
        lines.append('  Guest restrictions:')
        self._restrictions(lines, '    ', self.guest_restrictions)
        lines.append('')
        if any(u.removing for u in self.users.values()):
            lines.append('  Recently removed userIds: []')
        started = ['%d=%s' % (u.id, u.state) for u in sorted(self.users.values(), key=lambda x: x.id) if u.state != '-1']
        lines.append('  Started users state: [%s]' % ', '.join(started))
        ids = [u.id for u in sorted(self.users.values(), key=lambda x: x.id)]
        lines.append('  Cached user IDs: [%s]' % ', '.join(str(i) for i in ids if not self.users[i].partial
                                                            and not self.users[i].precreated))
        lines.append('  Cached user IDs (including pre-created): [%s]' % ', '.join(
            str(i) for i in ids if not self.users[i].partial))
        lines.append('')
        maximum = '  Max switchable users: %d' % self.max_switchable
        if self.built_in is not None and self.built_in != self.max_switchable:
            maximum += ' (built-in value: %d)' % self.built_in
        reached = self.limit_reached
        if reached is None:
            reached = self.allowance()[1] >= self.max_switchable
        maximum += ' (limit reached)' if reached else ''
        lines += ['  Supports switchable users: %s' % ('true' if self.supports else 'false'), maximum,
                  '  All guests ephemeral: false', '  Force ephemeral users: false', '  Is headless-system mode: false',
                  '  Is main user permanent admin: true', '  User version: 11', '  Owner name: Owner',
                  '  Guest name: null', '  Unnamed user name: User', '  Boot user: N/A', '  Device owner user: N/A',
                  '', 'UserVisibilityMediator', '  DBG: false', '  Current user id: %d' % self.current,
                  '  Visible users: [%d]' % self.current,
                  '  Number of started visible user / profile group mappings: 1',
                  '    u:%d -> pg:%d' % (self.current, self.current),
                  '  Supports visible background users on displays: false',
                  '  Supports visible background users on default display: false', '  No user / display mappings',
                  '  No extra display / user mappings', '  Visible users per display cache: N/A',
                  '  Number of listeners: 1', '    0: com.android.server.pm.UserManagerService$1@5f0a3c2', '', '',
                  'Number of listeners for', '  restrictions: 5', '  user lifecycle events: 12', '',
                  'User types version: 1', 'User types (%d types):' % len(TYPES)]
        for name in TYPES:
            enabled = self.type_enabled if name == SECONDARY_TYPE else True
            maximum_allowed = self.type_max if name == SECONDARY_TYPE else 1
            lines += ['    %s: ' % name, '        mName: ' + name,
                      '        mBaseType: ' + ('PROFILE' if '.profile.' in name else 'FULL|SYSTEM' if name == SYSTEM_TYPE
                                                else 'FULL'),
                      '        mEnabled: ' + ('true' if enabled else 'false'),
                      '        mMaxAllowed: %d' % maximum_allowed,
                      '        mMaxAllowedPerParent: -1', '        mDefaultUserInfoFlags: 0',
                      '        UserProperties:']
            lines += ['            %s=%s' % (p, PROPERTY_VALUES[p]) for p in full_users.PROPERTIES]
            lines.append('        mDefaultRestrictions: ')
            self._restrictions(lines, '            ', SECONDARY_DEFAULTS if name == SECONDARY_TYPE else None)
            lines += ['        mProfileParentRequired: %s' % ('true' if '.profile.' in name else 'false'),
                      '        mIconBadge: 0', '        mBadgePlain: 0', '        mBadgeNoBackground: 0',
                      '        mStatusBarIcon: 0', '        mBadgeLabels.length: 0(null)',
                      '        mBadgeColors.length: 0(null)', '        mDarkThemeBadgeColors.length: 0(null)',
                      '        mLabels.length: 0(null)', '        mActivitiesAllowlist: null',
                      '        mActivitiesAllowlistMode: 0 (ALLOWLIST_MODE_DISABLED)']
        lines += ['', 'Allowlisted packages per user type', '  Mode: 13 (enforced) (implicit) (ignore OTAs)', '  Legend']
        lines += ['    %d -> %s' % (at, name) for at, name in enumerate(TYPES)]
        lines += ['  No packages', '', 'Non-compliant events:', '  Not logging getMainUser() calls', '  ',
                  '  Not logging isMainUser() calls', '  ', '  Not logging blocked HSU activities', '  ',
                  '  Not logging launched HSU activities', '  ', '  Not logging blocked HSU notifications', '  ',
                  '  Not logging posted HSU notifications']
        return '\n'.join(lines) + '\n'

    def listing(self):
        rows = ['Users:']
        for u in sorted(self.users.values(), key=lambda x: x.id):
            if u.partial or u.precreated:
                continue
            name = u.name if u.name is not None else ('Owner' if u.id == 0 else 'User')
            rows.append('\tUserInfo{%d:%s:%x}%s' % (u.id, name, u.flags, ' running' if self.running(u.id) else ''))
        return '\n'.join(rows) + '\n'

    def uid(self, user, app_id):
        return user * full_users.PER_USER_RANGE + app_id

    def allowance(self):
        """(users of the secondary type, switchable users, how many more the device allows), as
        UserManagerService.getRemainingCreatableUserCount counts them."""
        count = len([u for u in self.users.values() if u.type == SECONDARY_TYPE and not u.removing and not u.precreated])
        switchable = len([u for u in self.users.values() if u.type in (SYSTEM_TYPE, SECONDARY_TYPE)
                          and not u.removing and not u.precreated])
        return count, switchable, max(0, min(self.type_max - count, self.max_switchable - switchable))

    # ------------------------------------------------ the commands

    def run(self, command):
        """The reply to one user command, or None for a command that is not one."""
        for prefix, replies in self.replies.items():
            if command.startswith(prefix) and replies:
                scripted = replies.pop(0)
                return scripted(command) if callable(scripted) else result(command, *scripted)
        if command == full_users.DUMP:
            return result(command, 0, self.dump().encode())
        if command == full_users.LIST:
            return result(command, 0, self.listing().encode())
        if command == full_users.SUPPORTS:
            return result(command, 0, b'Are multiple switchable users supported: %s\n'
                          % (b'true' if self.supports else b'false'))
        if command == full_users.MAX_USERS:
            return result(command, 0, b'Maximum supported switchable users: %d\n' % self.max_switchable)
        if command == full_users.MAX_OF_TYPE:
            count, _, remaining = self.allowance()
            return result(command, 0, ('Maximum supported users of type %s: %d\n'
                                       % (SECONDARY_TYPE, count + remaining)).encode())
        if command == full_users.MAX_RUNNING:
            return result(command, 0, b'Maximum supported running users: %d\n' % self.max_running)
        if command == full_users.CURRENT:
            return result(command, 0, b'%d\n' % self.current)
        parts = command.split(' ')
        if command.startswith('pm create-user --user-type ') and len(parts) == 5:
            return self.create(command, parts[3], parts[4])
        if command.startswith('am start-user -w ') and len(parts) == 4:
            return self.start(command, int(parts[3]))
        if command.startswith('am switch-user -w ') and len(parts) == 4:
            return self.switch(command, int(parts[3]))
        if command.startswith('cmd user is-user-visible ') and len(parts) == 4:
            return result(command, 0, b'true\n' if int(parts[3]) == self.current else b'false\n')
        if command.startswith('settings get --user ') and len(parts) == 6:
            user = self.users.get(int(parts[3]))
            if user is None:
                return result(command, 255, b'', b'Invalid user: %d\n' % int(parts[3]))
            return result(command, 0, user.setup.encode() + b'\n')
        if command.startswith('input keyevent ') or command.startswith('input tap '):
            return self.step(command)
        if command.startswith('pm install-existing --user ') and len(parts) == 5:
            return self.install_existing(command, int(parts[3]), parts[4])
        if command.startswith('pm enable --user ') and len(parts) == 5:
            return result(command, 0, ('Package %s new state: enabled\n' % parts[4]).encode())
        if command.startswith('pm list packages --user ') and len(parts) == 7 and parts[5] == '-U':
            return self.packages(command, int(parts[4]), parts[6])
        if command.startswith('pm path --user ') and len(parts) == 5:
            return self.path(command, int(parts[3]), parts[4])
        if command == full_users.PIDOF:
            return self.pidof(command)
        if command.startswith('cat /proc/'):
            return self.proc(command)
        return None

    def create(self, command, user_type, name):
        if 'no_add_user' in self.effective(0):
            return result(command, 1, b'', b'Error: android.os.ServiceSpecificException: Cannot add user: no_add_user is '
                                           b'enabled. (code 10)\nError: couldn\'t create User.\n')
        if not self.allowance()[2] or not self.supports:
            return result(command, 1, b'', ('Error: android.os.ServiceSpecificException: Cannot add more users of type '
                                            '%s. Maximum number of that type already exists. (code 6)\nError: couldn\'t '
                                            'create User.\n' % user_type).encode())
        user = self.next_user
        while user in self.users:
            user += 1
        self.users[user] = SimUser(user, self.next_serial, user_type, 0x400, '-1', name=name, base=list(SECONDARY_DEFAULTS))
        self.next_serial += 1
        self.wizard.setdefault(user, [{'key': 'KEYCODE_ENTER'}])
        self.sync()
        return result(command, 0, b'Success: created user id %d\n' % user)

    def start(self, command, user):
        if user not in self.users or self.running(user):
            return result(command, 0, b'', b'Error: could not start user\n')
        u = self.users[user]
        u.state = 'RUNNING_LOCKED' if user in self.sim.pins else 'RUNNING_UNLOCKED'
        u.flags |= full_users.FLAG_INITIALIZED
        u.logged_in = True
        self.lru.append(user)
        self.new_process(user)
        # Android trims the least recently used background user beyond the running limit.
        running = [i for i in self.lru if self.running(i)]
        for i in list(running):
            if len([x for x in self.lru if self.running(x)]) <= self.max_running:
                break
            if i not in (0, self.current, user):
                self.users[i].state = '-1'
                self.processes.pop(i, None)
        self.sync()
        return result(command, 0, b'Success: user started\n')

    def switch(self, command, user):
        if user not in self.users or not self.running(user):
            return result(command, 1, b'Error: Failed to switch to user %d\n' % user)
        self.current = user
        if self.wizard.get(user) == []:
            # An image whose setup completes by itself at the first foreground.
            self.users[user].setup = '1'
        self.sync()
        return result(command, 0)

    def step(self, command):
        user = self.current
        expected = self.wizard.get(user)
        if expected:
            want = expected[0]
            text = full_users.step_command(want)
            if command == text:
                expected.pop(0)
            if not expected:
                self.users[user].setup = '1'
        return result(command, 0)

    def install_existing(self, command, user, package):
        fixture = self.fixtures.get(package)
        if fixture is None:
            return result(command, 1, ("android.content.pm.PackageManager$NameNotFoundException: Package %s doesn't "
                                       "exist\n" % package).encode())
        fixture['users'].add(user)
        return result(command, 0, ('Package %s installed for user: %d\n' % (package, user)).encode())

    def packages(self, command, user, needle):
        """Every package of the user whose name holds the filter, in no fixed order."""
        installed = []
        if user in self.users:
            installed += [('com.android.systemui', APP_ID), ('com.android.systemui.accessibility.accessibilitymenu',
                                                             10095)]
        installed += [(package, f['app_id']) for package, f in sorted(self.fixtures.items()) if user in f['users']]
        rows = ['package:%s uid:%d' % (package, self.uid(user, app)) for package, app in installed if needle in package]
        return result(command, 0, ''.join(r + '\n' for r in reversed(rows)).encode())

    def path(self, command, user, package):
        fixture = self.fixtures.get(package)
        if fixture is None or user not in fixture['users']:
            return result(command, 1)
        return result(command, 0, ('package:%s\n' % fixture['path']).encode())

    def add_fixture(self, package, apk, app_id=10150):
        """An ordinary fixture installed for the system user, its bytes at its base APK path."""
        stem = hashlib.sha256(package.encode()).hexdigest()
        path = '/data/app/~~%s==/%s-%s==/base.apk' % (stem[:22], package, stem[22:44])
        self.fixtures[package] = {'app_id': app_id, 'path': path, 'users': {0}}
        self.sim.files[path] = bytes(apk)
        return path

    def pidof(self, command):
        processes = [(user, pid) for user, (pid, _) in self.processes.items()] + [
            (p['user'], p['pid']) for p in self.extra_processes]
        pids = [pid for _, pid in sorted(processes)]
        if self.pid_order is not None:
            pids = self.pid_order(pids)
        if not pids:
            return result(command, 1)
        return result(command, 0, (' '.join(str(p) for p in pids) + '\n').encode())

    def _process(self, pid):
        for user, (p, ticks) in self.processes.items():
            if p == pid:
                return {'user': user, 'pid': pid, 'start_ticks': ticks, 'name': full_users.SYSTEMUI,
                        'uid': self.uid(user, APP_ID)}
        for extra in self.extra_processes:
            if extra['pid'] == pid:
                return extra
        return None

    def proc(self, command):
        pid, leaf = command[len('cat /proc/'):].split('/', 1)
        process = self._process(int(pid))
        if int(pid) in self.proc_denied:
            return result(command, 1, b'', b'cat: /proc/%s/%s: Permission denied\n' % (pid.encode(), leaf.encode()))
        if process is None:
            return result(command, 1, b'', b'cat: /proc/%s/%s: No such file or directory\n' % (pid.encode(),
                                                                                              leaf.encode()))
        name = process['name']
        comm = name[-15:] if len(name) >= 15 and '.' in name else name
        if leaf == 'cmdline':
            return result(command, 0, name.encode() + b'\x00' * 12)
        if leaf == 'status':
            uids = process.get('uids') or [process['uid']] * 4
            text = ('Name:\t%s\nUmask:\t0077\nState:\tS (sleeping)\nTgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t386\n'
                    'TracerPid:\t0\nUid:\t%s\nGid:\t%s\nFDSize:\t256\nGroups:\t3002 3003\n'
                    % (comm, int(pid), int(pid), '\t'.join(str(u) for u in uids), '\t'.join(str(u) for u in uids)))
            return result(command, 0, text.encode())
        if leaf == 'stat':
            fields = ['S', '386', '386', '0', '0', '-1', '1077952832', '61423', '0', '201', '0', '1288', '711', '0', '0',
                      '10', '-10', '43', '0', str(process['start_ticks']), '17221877760', '41207']
            return result(command, 0, ('%d (%s) %s\n' % (int(pid), comm, ' '.join(fields))).encode())
        user = process['user']
        context = process.get('context') or ('u:r:platform_app:s0:c%d,c768' % (512 + user))
        return result(command, 0, context.encode() + b'\x00')
