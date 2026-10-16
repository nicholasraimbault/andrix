# SPDX-License-Identifier: Apache-2.0
"""The full user setup package of the next campaign profile, host side: the guest's user forms
read whole and strictly, the typed user inventory and limits they give, the fixed commands and
reply forms of the user setup actions, their durable records, and the discovery of each user's
genuine main SystemUI process.

Every form here is derived from the pinned Android source, `frameworks/base` at the GrapheneOS tag
the guest image is built from. Each parser cites the code that prints its form. A form is
unqualified until a guest shows it: its captures are kept raw, and a guest form that differs is
refused, never repaired. A refusal raises `FormError`, an Unclassified read, and a read that could
not complete raises lab_readers.Unavailable. Neither gives a reading, so an incomplete, duplicated
or disagreeing dump never shows a user absent, removed or allowed to change.

What a host test of this module shows is that these parsers, joins and gates hold on source
derived forms. It shows no user created, started, switched or set up on a device, no foreground
drawing and no SystemUI process."""
import hashlib
import re

import lab_actions
import lab_readers

SYSTEMUI = 'com.android.systemui'
SYSTEM_TYPE = lab_actions.SYSTEM_TYPE
SECONDARY_TYPE = lab_actions.SECONDARY_TYPE
NO_USER = lab_actions.NO_USER
# UserHandle.PER_USER_RANGE and the largest user ID (core/java/android/os/UserHandle.java:52,
# 321-327 and 414-420: a UID is the user times the range plus the app ID).
PER_USER_RANGE = 100000
MAX_USER_ID = 21474
OUTPUT_MAX = 4 << 20

# ---------------------------------------------------------------- the fixed commands

# Read forms. `pm list users` hands the user service its own "list" command and ignores any later
# argument (services/core/java/com/android/server/pm/PackageManagerShellCommand.java:802-806), so
# it has one form.
DUMP = 'dumpsys user'
LIST = 'pm list users'
SUPPORTS = 'pm supports-multiple-users'
MAX_USERS = 'pm get-max-users'
MAX_OF_TYPE = 'pm get-max-users --user-type ' + SECONDARY_TYPE
MAX_RUNNING = 'pm get-max-running-users'
CURRENT = 'am get-current-user'
PIDOF = 'pidof ' + SYSTEMUI
PROC_LEAVES = ('cmdline', 'status', 'stat', 'attr/current')
_PACKAGE_NAME = r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+'
# The reader's own reads: the whole user forms, the limits, and the process discovery's. An action's
# reads, such as the current user, a visibility, the setup setting or a fixture's path, are the
# broker's fixed forms for that action alone.
READS = (DUMP, LIST, SUPPORTS, MAX_USERS, MAX_OF_TYPE, MAX_RUNNING, PIDOF)
_UID_READ = re.compile(r'pm list packages --user (0|[1-9][0-9]{0,4}) -U ' + re.escape(SYSTEMUI))
_PROC_READ = re.compile(r'cat /proc/([1-9][0-9]{0,6})/(cmdline|status|stat|attr/current)')


def _user(user):
    if type(user) is not int or not 0 <= user <= MAX_USER_ID:
        raise ValueError('a user ID from 0 to %d' % MAX_USER_ID)
    return user


def _package(package):
    if not isinstance(package, str) or not lab_actions.PACKAGE.fullmatch(package):
        raise ValueError('a package name')
    return package


def create_command(name):
    """`pm create-user --user-type <full secondary> <name>`: one full secondary user of an admitted
    name (PackageManagerShellCommand.java:3143-3258)."""
    if not isinstance(name, str) or not lab_actions.USER_NAME.fullmatch(name):
        raise ValueError('an admitted user name')
    return 'pm create-user --user-type %s %s' % (SECONDARY_TYPE, name)


def start_command(user):
    """`am start-user -w <id>`: a background start that waits for its listener
    (services/core/java/com/android/server/am/ActivityManagerShellCommand.java:3054-3123)."""
    return 'am start-user -w %d' % _user(user)


def switch_command(user):
    """`am switch-user -w <id>` (ActivityManagerShellCommand.java:2965-3043)."""
    return 'am switch-user -w %d' % _user(user)


def visible_command(user):
    """`cmd user is-user-visible <id>` (UserManagerServiceShellCommand.java:476-501)."""
    return 'cmd user is-user-visible %d' % _user(user)


def setup_command(user):
    """`settings get --user <id> secure user_setup_complete`
    (packages/SettingsProvider/src/com/android/providers/settings/SettingsService.java:131-273,
    350-375)."""
    return 'settings get --user %d secure user_setup_complete' % _user(user)


def package_uid_command(user, package):
    """`pm list packages --user <id> -U <package>` (PackageManagerShellCommand.java:975-1180)."""
    return 'pm list packages --user %d -U %s' % (_user(user), _package(package))


def package_path_command(user, package):
    """`pm path --user <id> <package>` (PackageManagerShellCommand.java:741-775)."""
    return 'pm path --user %d %s' % (_user(user), _package(package))


def install_existing_command(user, package):
    """`pm install-existing --user <id> <package>` (PackageManagerShellCommand.java:1998-2073)."""
    return 'pm install-existing --user %d %s' % (_user(user), _package(package))


def enable_command(user, package):
    """`pm enable --user <id> <package>` (PackageManagerShellCommand.java:2431-2471)."""
    return 'pm enable --user %d %s' % (_user(user), _package(package))


def step_command(step):
    """One admitted setup UI step as its `input` command: a key event of the admitted keys or a
    tap at a point (services/core/java/com/android/server/input/InputShellCommand.java:272-315,
    403-489; cmds/input/input.sh runs `cmd input`). No text is ever typed."""
    why = lab_actions.step_problem(step)
    if why is not None:
        raise ValueError(why)
    if 'key' in step:
        return 'input keyevent %s' % step['key']
    return 'input tap %d %d' % tuple(step['tap'])


def proc_command(pid, leaf):
    if type(pid) is not int or not 0 < pid < 10_000_000 or leaf not in PROC_LEAVES:
        raise ValueError('a /proc read of a process')
    return 'cat /proc/%d/%s' % (pid, leaf)


def read_allowed(command):
    """Whether a command is one of the full user reader's fixed read forms."""
    return command in READS or bool(_UID_READ.fullmatch(command) or _PROC_READ.fullmatch(command))


# ---------------------------------------------------------------- common checks


class FormError(lab_readers.Unclassified):
    """Output of no known form: no reading."""


def _fail(reason):
    raise FormError(reason)


def _reply(code, stdout, stderr, limit=OUTPUT_MAX):
    if type(code) is not int or not isinstance(stdout, str) or not isinstance(stderr, str):
        _fail('a reply without its exit status and both streams')
    if len(stdout) > limit or len(stderr) > 65536:
        _fail('a reply above its bound')


def _plain(code, stdout, stderr, what, limit=OUTPUT_MAX):
    """A read's whole reply: exit status 0, nothing on standard error, its output ended by a
    newline, with no carriage return or NUL."""
    _reply(code, stdout, stderr, limit)
    if code != 0 or stderr != '' or not stdout.endswith('\n') or '\r' in stdout or '\x00' in stdout:
        _fail('%s of no known form' % what)
    return stdout


def _int(text, low, high, what):
    if not re.fullmatch(r'-?(0|[1-9][0-9]{0,18})', text) or not low <= int(text) <= high:
        _fail('%s of no known form' % what)
    return int(text)


def _bool(text, what):
    if text not in ('true', 'false'):
        _fail('%s of no known form' % what)
    return text == 'true'


def _ids(text, what):
    """`Arrays.toString(int[])`, `IntArray.toString()` or a list's toString: `[1, 2]` or `[]`
    (core/java/android/util/IntArray.java:243-260)."""
    match = re.fullmatch(r'\[((?:0|[1-9][0-9]{0,8})(?:, (?:0|[1-9][0-9]{0,8}))*)?\]', text)
    if not match:
        _fail('%s of no known form' % what)
    return [int(i) for i in match[1].split(', ')] if match[1] else []


def _digest(text):
    return hashlib.sha256(text.encode('utf-8', 'surrogateescape')).hexdigest()


# ---------------------------------------------------------------- `dumpsys user`, whole

# UserInfo's flag constants, which DebugUtils.flagsToString names by reflection in no fixed order
# (core/java/android/content/pm/UserInfo.java:76-203;
# core/java/android/util/DebugUtils.java:246-271).
FLAGS = {'PRIMARY': 0x1, 'ADMIN': 0x2, 'GUEST': 0x4, 'RESTRICTED': 0x8, 'INITIALIZED': 0x10,
         'MANAGED_PROFILE': 0x20, 'DISABLED': 0x40, 'QUIET_MODE': 0x80, 'EPHEMERAL': 0x100, 'DEMO': 0x200,
         'FULL': 0x400, 'SYSTEM': 0x800, 'PROFILE': 0x1000, 'EPHEMERAL_ON_CREATE': 0x2000, 'MAIN': 0x4000,
         'FOR_TESTING': 0x8000}
FLAG_INITIALIZED = FLAGS['INITIALIZED']
# UserState.stateToString (services/core/java/com/android/server/am/UserState.java:36-48,
# 109-119): a name, or the number of a state with none, -1 for a user that has no state.
STATES = ('BOOTING', 'RUNNING_LOCKED', 'RUNNING_UNLOCKING', 'RUNNING_UNLOCKED', 'STOPPING', 'SHUTDOWN', '-1')
RUNNING_STATES = ('BOOTING', 'RUNNING_LOCKED', 'RUNNING_UNLOCKING', 'RUNNING_UNLOCKED')
# How a state projects onto the typed inventory's coarse states: CE storage unlocked only in
# RUNNING_UNLOCKED; booting and unlocking users run with CE storage still locked.
COARSE = {'RUNNING_UNLOCKED': 'RUNNING_UNLOCKED', 'RUNNING_LOCKED': 'RUNNING_LOCKED', 'BOOTING': 'RUNNING_LOCKED',
          'RUNNING_UNLOCKING': 'RUNNING_LOCKED', 'STOPPING': 'NOT_RUNNING', 'SHUTDOWN': 'NOT_RUNNING',
          '-1': 'NOT_RUNNING'}
# UserProperties.println, in its order (core/java/android/content/pm/UserProperties.java:1119-1147).
PROPERTIES = ('mPropertiesPresent', 'mShowInLauncher', 'mStartWithParent', 'mShowInSettings', 'mInheritDevicePolicy',
              'mUseParentsContacts', 'mUpdateCrossProfileIntentFiltersOnOTA', 'mCrossProfileIntentFilterAccessControl',
              'mCrossProfileIntentResolutionStrategy', 'mMediaSharedWithParent', 'mCredentialShareableWithParent',
              'mAuthAlwaysRequiredToDisableQuietMode', 'mAllowStoppingUserWithDelayedLocking', 'mDeleteAppWithParent',
              'mAlwaysVisible', 'mCrossProfileContentSharingStrategy', 'mProfileApiVisibility',
              'mItemsRestrictedOnHomeScreen')
_PROPERTY_VALUE = re.compile(r'-?(?:0|[1-9][0-9]{0,18})|true|false')

# The user line of dumpUserLU (services/core/java/com/android/server/pm/UserManagerService.java:
# 8473-8499) with UserInfo.toString (UserInfo.java:595-600): the name is free text, so it is
# matched greedily and the line's own suffix, which the dump prints last, ends the match.
_USER_LINE = re.compile(r'  UserInfo\{(0|[1-9][0-9]{0,4}):(.*):(0|[1-9a-f][0-9a-f]{0,7})\} '
                        r'serialNo=(0|[1-9][0-9]{0,9}) isPrimary=(true|false)( parentId=(?:0|[1-9][0-9]{0,4}))?'
                        r'( <removing> )?( <partial>)?( <pre-created>)?( <converted>)?( <guestToRemove>)?')
# dumpTimeAgo with TimeUtils.formatDuration (UserManagerService.java:8612-8621;
# core/java/android/util/TimeUtils.java:250-319): <unknown>, or a duration and " ago".
_TIME = re.compile(r'<unknown>|(?:0|[+-](?:[1-9][0-9]*d)?(?:[0-9]+h)?(?:[0-9]+m)?(?:[0-9]+s)?[0-9]+ms) ago')
_RESTRICTION = re.compile(r'[a-z][a-z0-9_]{0,63}')


class _Lines:
    """A whole output's lines, consumed in order; running out is an incomplete output."""

    def __init__(self, text, what):
        if not text.endswith('\n'):
            _fail('%s does not end its last line' % what)
        self.what, self.lines, self.at = what, text[:-1].split('\n'), 0

    def peek(self):
        return self.lines[self.at] if self.at < len(self.lines) else None

    def take(self, what):
        if self.at >= len(self.lines):
            _fail('%s ends before %s: cut short' % (self.what, what))
        self.at += 1
        return self.lines[self.at - 1]

    def exact(self, text, what=None):
        line = self.take(what or repr(text))
        if line != text:
            _fail('%s: %r where %r belongs' % (self.what, line[:120], text))

    def match(self, pattern, what):
        line = self.take(what)
        found = re.fullmatch(pattern, line)
        if not found:
            _fail('%s: %s of no known form: %r' % (self.what, what, line[:120]))
        return found

    def optional(self, pattern):
        line = self.peek()
        found = re.fullmatch(pattern, line) if line is not None else None
        if found:
            self.at += 1
        return found


def _flags(decimal, names, header):
    """The Flags line's value and names, which must name exactly the flags its value holds, and
    the user line's hexadecimal flags, which must be the same value."""
    value = _int(decimal, 0, 0x7fffffff, 'a flags value')
    if value != int(header, 16):
        _fail('the flags of the user line and the Flags line disagree')
    known = value & sum(FLAGS.values())
    parts = names.split('|')
    if value == 0:
        if parts != ['0']:
            _fail('flags 0 not shown as 0')
        return value
    rest = value & ~known
    named = parts[:-1] if rest else parts
    if rest and parts[-1] != '%x' % rest:
        _fail('flags whose unknown bits are not shown in hexadecimal last')
    if len(set(named)) != len(named) or any(n not in FLAGS for n in named):
        _fail('flags with a repeated or unknown name')
    if sum(FLAGS[n] for n in named) != known:
        _fail('flag names that are not the flags of the value')
    return value


def _restrictions(lines, prefix, what):
    """UserRestrictionsUtils.dumpRestrictions (services/core/java/com/android/server/pm/
    UserRestrictionsUtils.java:929-944): each set restriction's key on its own line, or `none` for
    an empty bundle, or `null` for none at all. None stands for `null`. RestrictionsSet keeps no
    entry for an empty bundle (RestrictionsSet.java:77-91), so `null` is the usual empty form."""
    found = []
    while True:
        line = lines.peek()
        if line is None or not line.startswith(prefix) or line[len(prefix):len(prefix) + 1] in ('', ' '):
            break
        lines.at += 1
        found.append(line[len(prefix):])
    if not found:
        _fail('%s: %s lists nothing' % (lines.what, what))
    if found in (['none'], ['null']):
        return [] if found == ['none'] else None
    if any(not _RESTRICTION.fullmatch(key) or key in ('none', 'null') for key in found) or len(set(found)) != len(found):
        _fail('%s: %s of no known form' % (lines.what, what))
    return sorted(found)


def _user_block(lines):
    header = lines.match(_USER_LINE, 'a user line')
    user = {'id': int(header[1]), 'name_sha256': _digest(header[2]), 'serial': int(header[4]),
            'primary': header[5] == 'true',
            'parent': int(header[6][len(' parentId='):]) if header[6] else NO_USER,
            'removing': bool(header[7]), 'partial': bool(header[8]), 'precreated': bool(header[9]),
            'converted': bool(header[10]), 'guest_to_remove': bool(header[11])}
    if user['id'] > MAX_USER_ID or user['parent'] > MAX_USER_ID:
        _fail('a user ID beyond the largest one')
    user['type'] = lines.match(r'    Type: (android\.os\.usertype\.[a-z]+\.[A-Z_]+)', 'a user type')[1]
    flags = lines.match(r'    Flags: (0|[1-9][0-9]{0,9}) \(([A-Za-z0-9_|]+)\)', 'a user flags line')
    user['flags'] = _flags(flags[1], flags[2], header[3])
    if user['primary'] != bool(user['flags'] & FLAGS['PRIMARY']):
        _fail('isPrimary and the PRIMARY flag disagree')
    state = lines.match(r'    State: ([A-Z_]+|-?[0-9]{1,10})', 'a user state')[1]
    if state not in STATES:
        _fail('a user state of no known name: %s' % state)
    user['state'] = state
    for label in ('Created', 'Last logged in'):
        lines.match(r'    %s: (%s)' % (label, _TIME.pattern), label)
    lines.match(r'    Last logged in fingerprint: [^\n]*', 'a fingerprint')
    for label in ('Start time', 'Unlock time', 'Last entered foreground'):
        lines.match(r'    %s: (%s)' % (label, _TIME.pattern), label)
    lines.exact('    Restrictions:')
    base = _restrictions(lines, '      ', 'base restrictions')
    lines.exact('    Device policy restrictions:')
    local = _restrictions(lines, '      ', 'device policy restrictions')
    lines.exact('    Effective restrictions:')
    cached = _restrictions(lines, '      ', 'effective restrictions')
    user['restriction_lists'] = {'base': base, 'policy': local, 'cached': cached}
    lines.optional(r'    Account name: [^\n]*')
    if lines.optional(r'    Seed account name: [^\n]*'):
        lines.optional(r'         account type: [^\n]*')
        lines.optional(r'         account options exist')
    if lines.optional(r'    UserProperties:'):
        for name in PROPERTIES:
            value = lines.match(r'        %s=([^\n]*)' % name, 'a user property')[1]
            if not _PROPERTY_VALUE.fullmatch(value):
                _fail('a user property value of no known form')
    lines.match(r'    Ignore errors preparing storage: (true|false)', 'the storage line')
    return user


def _sparse(lines, description, key, value):
    """UserVisibilityMediator.dumpSparseIntArray (UserVisibilityMediator.java:1256-1281)."""
    if lines.optional(r'  No %s mappings' % re.escape(description)):
        return None
    count = int(lines.match(r'  Number of %s mappings: (0|[1-9][0-9]{0,4})' % re.escape(description), description)[1])
    pairs = {}
    for _ in range(count):
        pair = lines.match(r'    %s:(-?[0-9]{1,10}) -> %s:(-?[0-9]{1,10})' % (key, value), description)
        pairs[int(pair[1])] = int(pair[2])
    if len(pairs) != count:
        _fail('a mapping listed twice')
    return pairs


def _counted(lines, empty, header, row, what):
    """One subsection of MultiuserNonComplianceLogger.dump: `Not logging ...`, or a count and
    exactly that many rows (services/core/java/com/android/server/pm/
    MultiuserNonComplianceLogger.java:276-354)."""
    if lines.optional(empty):
        return 0
    count = int(lines.match(header, what)[1])
    for _ in range(count):
        lines.match(row, what)
    return count


def parse_dump(code, stdout, stderr):
    """`dumpsys user`, whole: UserManagerService.dump with no argument
    (services/core/java/com/android/server/pm/UserManagerService.java:8245-8460). A single service
    dump has no header or trailer of its own: retained captures of `dumpsys -t 25 package installs`
    begin and end with the service's own text. The parse follows every section to the output's
    end: the users, the device properties with the started states and cached user IDs, the
    switchable user capabilities, the visibility mediator with the current and visible users, the
    listener counts, every user type, the system package allowlist and the non-compliance log,
    whose last subsection is counted. Only the allowlist section's body is not interpreted. Users
    must be listed in increasing ID order, each once with a unique serial, and the dump must agree
    with itself: the started states with each user's state, the cached user IDs with the users
    that are not partial, each user's effective restrictions with its base, device policy and
    global restrictions, the two current users, the visible users with the listed ones, and each
    user's type with the listed types. Returns the typed dump; refuses anything else."""
    text = _plain(code, stdout, stderr, 'a user dump')
    lines = _Lines(text, 'the user dump')
    dump = {}
    head = lines.match(r'Current user: (N/A|0|[1-9][0-9]{0,4})', 'the current user')[1]
    dump['current_user'] = None if head == 'N/A' else int(head)
    lines.exact('')
    lines.exact('Users:')
    users = []
    while lines.peek() not in ('', None):
        users.append(_user_block(lines))
    if not users:
        _fail('the user dump lists no user')
    ids = [u['id'] for u in users]
    if ids != sorted(set(ids)) or len({u['serial'] for u in users}) != len(users):
        _fail('a user or serial listed twice, or users out of their order')
    lines.exact('')
    lines.exact('Device properties:')
    lines.exact('  Device policy global restrictions:')
    global_restrictions = _restrictions(lines, '    ', 'global restrictions')
    lines.exact('  Guest restrictions:')
    dump['guest_restrictions'] = _restrictions(lines, '    ', 'guest restrictions')
    lines.exact('')
    removed = lines.optional(r'  Recently removed userIds: (\[[0-9, ]*\])')
    dump['recently_removed'] = _ids(removed[1], 'recently removed IDs') if removed else None
    started_text = lines.match(r'  Started users state: \[([^\]\n]*)\]', 'the started users')[1]
    started = {}
    for pair in started_text.split(', ') if started_text else []:
        match = re.fullmatch(r'(0|[1-9][0-9]{0,4})=([A-Z_]+|-?[0-9]{1,10})', pair)
        if not match or int(match[1]) in started or match[2] not in STATES:
            _fail('a started user of no known form')
        started[int(match[1])] = match[2]
    if started != {u['id']: u['state'] for u in users if u['state'] != '-1'}:
        _fail('the users section and the started users disagree')
    cached = _ids(lines.match(r'  Cached user IDs: (\[[0-9, ]*\])', 'the cached user IDs')[1], 'cached IDs')
    every = _ids(lines.match(r'  Cached user IDs \(including pre-created\): (\[[0-9, ]*\])', 'the cached user IDs')[1],
                 'cached IDs')
    if (cached != [u['id'] for u in users if not u['partial'] and not u['precreated']]
            or every != [u['id'] for u in users if not u['partial']]):
        _fail('the cached user IDs and the users section disagree')
    lines.exact('')
    dump['creation_override'] = bool(lines.optional(r' Creation override mode is enabled'))
    dump['supports_switchable'] = _bool(lines.match(r'  Supports switchable users: (true|false)', 'support')[1],
                                        'support')
    maximum = lines.match(r'  Max switchable users: (0|[1-9][0-9]{0,4})( \(built-in value: (-?[0-9]{1,10})\))?'
                          r'( \(limit reached\))?', 'the switchable maximum')
    dump['max_switchable'] = int(maximum[1])
    dump['built_in_max'] = int(maximum[3]) if maximum[2] else None
    if dump['built_in_max'] == dump['max_switchable']:
        _fail('a built-in maximum shown although it equals the effective one')
    dump['limit_reached'] = bool(maximum[4])
    for label in ('All guests ephemeral', 'Force ephemeral users'):
        lines.match(r'  %s: (true|false)' % label, label)
    headless = _bool(lines.match(r'  Is headless-system mode: (true|false)', 'the system user mode')[1], 'mode')
    dump['headless'] = headless
    lines.optional(r'  \(differs from the current default build value\)')
    if lines.optional(r"  \(emulated by 'cmd user set-system-user-mode-emulation'\)"):
        lines.optional(r'  \(and being updated after boot\)')
    if headless:
        lines.match(r'  Can switch to headless system user: (true|false)', 'the headless switch')
        lines.match(r'  HSUM Boot Strategy: (-?[0-9]{1,10})', 'the boot strategy')
    lines.match(r'  Is main user permanent admin: (true|false)', 'the main user admin')
    lines.match(r'  User version: (-?[0-9]{1,10})', 'the user version')
    for label in ('Owner name', 'Guest name', 'Unnamed user name'):
        lines.match(r'  %s: [^\n]*' % label, label)
    for label in ('Boot user', 'Device owner user'):
        lines.match(r'  %s: (N/A|0|[1-9][0-9]{0,4})' % label, label)
    # UserVisibilityMediator.dump (UserVisibilityMediator.java:1202-1254, 1284-1290).
    lines.exact('')
    lines.exact('UserVisibilityMediator')
    lines.match(r'  DBG: (true|false)', 'the mediator debug flag')
    dump['mediator_current_user'] = _int(lines.match(r'  Current user id: (-?[0-9]{1,10})', 'the current user id')[1],
                                         -(1 << 31), (1 << 31) - 1, 'the current user id')
    dump['visible'] = _ids(lines.match(r'  Visible users: (\[[0-9, ]*\])', 'the visible users')[1], 'visible users')
    _sparse(lines, 'started visible user / profile group', 'u', 'pg')
    lines.optional(r'  Profiles started invisible: [^\n]*')
    for label in ('Supports visible background users on displays',
                  'Supports visible background users on default display'):
        lines.match(r'  %s: (true|false)' % label, label)
    _sparse(lines, 'user / display', 'u', 'd')
    _sparse(lines, 'extra display / user', 'd', 'u')
    lines.match(r'  Visible users per display cache: [^\n]*', 'the per display cache')
    listeners = int(lines.match(r'  Number of listeners: (0|[1-9][0-9]{0,4})', 'the mediator listeners')[1])
    for at in range(listeners):
        lines.match(r'    %d: [^\n]*' % at, 'a mediator listener')
    for line in ('', '', 'Number of listeners for'):
        lines.exact(line)
    lines.match(r'  restrictions: (0|[1-9][0-9]{0,9})', 'the restriction listeners')
    lines.match(r'  user lifecycle events: (0|[1-9][0-9]{0,9})', 'the lifecycle listeners')
    lines.exact('')
    lines.match(r'User types version: (-?[0-9]{1,10})', 'the user types version')
    count = int(lines.match(r'User types \((0|[1-9][0-9]{0,3}) types\):', 'the user types')[1])
    types = {}
    for _ in range(count):
        name = lines.match(r'    (android\.os\.usertype\.[a-z]+\.[A-Z_]+): ', 'a user type')[1]
        details = []
        while lines.peek() is not None and lines.peek().startswith('        '):
            details.append(lines.take('a user type detail'))
        values = {}
        for detail in details:
            found = re.fullmatch(r'        (mName|mEnabled|mMaxAllowed): ([^\n]*)', detail)
            if found:
                if found[1] in values:
                    _fail('a user type detail listed twice')
                values[found[1]] = found[2]
        # UserTypeDetails.dump
        # (services/core/java/com/android/server/pm/UserTypeDetails.java:411-443). mEnabled is a
        # boolean (:55) printed as true or false (:414); only its builder holds the configured
        # integer, which it converts (:458, :651-654). An integer here is of no known form.
        if name in types or values.get('mName') != name or set(values) != {'mName', 'mEnabled', 'mMaxAllowed'}:
            _fail('a user type listed twice or of no known form')
        types[name] = {'enabled': _bool(values['mEnabled'], 'mEnabled'),
                       'max_allowed': _int(values['mMaxAllowed'], -(1 << 31), (1 << 31) - 1, 'mMaxAllowed')}
    dump['types'] = types
    # The system package allowlist (UserSystemPackageInstaller.java:739-785) is kept, not read.
    lines.exact('')
    lines.exact('Allowlisted packages per user type')
    while lines.peek() is not None and lines.peek().startswith('  '):
        lines.take('the package allowlist')
    lines.exact('')
    lines.exact('Non-compliant events:')
    for method in ('getMainUser', 'isMainUser'):
        _counted(lines, r'  Not logging %s\(\) calls' % method, r'  (0|[1-9][0-9]{0,4}) apps called %s\(\)' % method,
                 r'    UID (-?[0-9]{1,10}) \([^\n]*\): (0|[1-9][0-9]{0,9}) calls', method)
        lines.exact('  ')
    for what in ('blocked', 'launched'):
        _counted(lines, r'  Not logging %s HSU activities' % what,
                 r'  (0|[1-9][0-9]{0,4}) activities %s on HSU' % what, r'    [^\n]*: (0|[1-9][0-9]{0,9}) times', what)
        lines.exact('  ')
    _counted(lines, r'  Not logging blocked HSU notifications', r'  (0|[1-9][0-9]{0,4}) notifications blocked on HSU',
             r'    \[pkg=[^\n]*\]: (0|[1-9][0-9]{0,9}) times', 'blocked notifications')
    lines.exact('  ')
    _counted(lines, r'  Not logging posted HSU notifications', r'  (0|[1-9][0-9]{0,4}) notifications posted on HSU',
             r'    \[pkg=[^\n]*\]: (0|[1-9][0-9]{0,9}) times', 'posted notifications')
    if lines.peek() is not None:
        _fail('the user dump goes on after its last section: %r' % lines.peek()[:120])
    # The dump agrees with itself.
    if dump['current_user'] is not None and dump['current_user'] != dump['mediator_current_user']:
        _fail('the two current users of the dump disagree')
    if any(v not in ids for v in dump['visible']) or len(set(dump['visible'])) != len(dump['visible']):
        _fail('a visible user the users section does not list')
    if any(u['type'] not in types for u in users):
        _fail('a user of a type the dump does not list')
    for u in users:
        lists = u['restriction_lists']
        # Effective restrictions are the base, the device policy global and the device policy local
        # ones together (UserManagerService.java:3905-3921). Their cache is computed lazily, so its
        # `null` is either none or not yet computed; a cache that is shown must agree.
        effective = set(lists['base'] or ()) | set(lists['policy'] or ()) | set(global_restrictions or ())
        if lists['cached'] is not None and set(lists['cached']) != effective:
            _fail('the effective restrictions of user %d disagree with its base and policy ones' % u['id'])
        u['restrictions'] = sorted(effective)
    dump['global_restrictions'] = global_restrictions
    dump['users'] = users
    return dump


# ---------------------------------------------------------------- `pm list users`

_LIST_ROW = re.compile(r'\tUserInfo\{(0|[1-9][0-9]{0,4}):(.*):(0|[1-9a-f][0-9a-f]{0,7})\}( running)?')


def parse_list(code, stdout, stderr):
    """`pm list users`: `Users:`, then one tab indented `UserInfo{id:name:flags}` line for each
    user that is not partial and not precreated, dying users included, in ID order, with
    ` running` when ActivityManager calls it running (services/core/java/com/android/server/pm/
    UserManagerServiceShellCommand.java:205-320; UserManagerService.java:1738-1792;
    UserFilter.java:57-66; services/core/java/com/android/server/am/UserController.java:3650-3693).
    Names are resolved here, so they may differ from the dump's; flags and IDs may not."""
    text = _plain(code, stdout, stderr, 'a user list')
    lines = _Lines(text, 'the user list')
    lines.exact('Users:')
    rows = []
    while lines.peek() is not None:
        row = lines.match(_LIST_ROW, 'a listed user')
        if int(row[1]) > MAX_USER_ID:
            _fail('a listed user ID beyond the largest one')
        rows.append({'id': int(row[1]), 'flags': int(row[3], 16), 'running': bool(row[4])})
    ids = [r['id'] for r in rows]
    if not rows or ids != sorted(set(ids)):
        _fail('a user list that is empty, repeats a user or is out of order')
    return rows


def check_list(dump, rows):
    """Why a user list and a whole dump read just before or after it disagree, or None: the same
    users that are not partial or precreated, with the same flags, running exactly when the dump
    shows a state of a started user."""
    expected = [{'id': u['id'], 'flags': u['flags'], 'running': u['state'] in RUNNING_STATES}
                for u in dump['users'] if not u['partial'] and not u['precreated']]
    if rows != expected:
        return 'the user list and the user dump disagree'
    return None


# ---------------------------------------------------------------- small read forms

def parse_supports(code, stdout, stderr):
    """`pm supports-multiple-users` (PackageManagerShellCommand.java:3489-3493; UserManager.java:
    2795-2799)."""
    match = re.fullmatch(r'Are multiple switchable users supported: (true|false)\n',
                         _plain(code, stdout, stderr, 'a support answer', 256))
    if not match:
        _fail('a support answer of no known form')
    return match[1] == 'true'


def parse_max_users(code, stdout, stderr):
    """`pm get-max-users`: the effective switchable maximum (PackageManagerShellCommand.java:
    3496-3520; UserManager.java:6754-6757: the fw.max_users property or its resource, at least
    1)."""
    match = re.fullmatch(r'Maximum supported switchable users: (0|[1-9][0-9]{0,4})\n',
                         _plain(code, stdout, stderr, 'a switchable maximum', 256))
    if not match:
        _fail('a switchable maximum of no known form')
    return int(match[1])


def parse_max_of_type(code, stdout, stderr, user_type=SECONDARY_TYPE):
    """`pm get-max-users --user-type <type>`: how many users of the type the device allows now,
    those that exist and those it can still create (PackageManagerShellCommand.java:3511-3518;
    UserManagerService.java:4232-4242, 4285-4331)."""
    match = re.fullmatch(r'Maximum supported users of type %s: (0|[1-9][0-9]{0,4})\n' % re.escape(user_type),
                         _plain(code, stdout, stderr, 'a type maximum', 256))
    if not match:
        _fail('a type maximum of no known form')
    return int(match[1])


def parse_max_running(code, stdout, stderr):
    """`pm get-max-running-users` (PackageManagerShellCommand.java:3552-3558): the running user
    limit beyond which a background start trims other running users
    (UserController.java:276-290, 660-751, 2427-2437)."""
    match = re.fullmatch(r'Maximum supported running users: (0|[1-9][0-9]{0,4})\n',
                         _plain(code, stdout, stderr, 'a running maximum', 256))
    if not match:
        _fail('a running maximum of no known form')
    return int(match[1])


def parse_current(code, stdout, stderr):
    """`am get-current-user` (ActivityManagerShellCommand.java:3045-3052)."""
    match = re.fullmatch(r'(0|[1-9][0-9]{0,4})\n', _plain(code, stdout, stderr, 'a current user', 64))
    if not match or int(match[1]) > MAX_USER_ID:
        _fail('a current user of no known form')
    return int(match[1])


def parse_visible(code, stdout, stderr):
    """`cmd user is-user-visible <id>` (UserManagerServiceShellCommand.java:476-501)."""
    match = re.fullmatch(r'(true|false)\n', _plain(code, stdout, stderr, 'a visibility answer', 64))
    if not match:
        _fail('a visibility answer of no known form')
    return match[1] == 'true'


def parse_setup(code, stdout, stderr):
    """`settings get --user <id> secure user_setup_complete`: the setting's value, or null
    (SettingsService.java:257-265, 350-375). SystemUI reads the same setting per user
    (packages/SystemUI/src/com/android/systemui/statusbar/policy/
    DeviceProvisionedControllerImpl.kt:63, 181-194). Only `1` is a completed setup."""
    match = re.fullmatch(r'(null|-?[0-9]{1,10})\n', _plain(code, stdout, stderr, 'a setup setting', 64))
    if not match:
        _fail('a setup setting of no known form')
    return match[1]


def parse_package_uid(code, stdout, stderr, package, user):
    """`pm list packages --user <id> -U <package>`: every package whose name holds the filter, in
    no fixed order, each with its UID for that user; the exact package's UID, or None when the user
    does not have it (PackageManagerShellCommand.java:975-1180). The UID is in the user's range."""
    _reply(code, stdout, stderr)
    if code != 0 or stderr != '' or (stdout and not stdout.endswith('\n')) or '\r' in stdout or '\x00' in stdout:
        _fail('a package list of no known form')
    found = []
    for row in stdout[:-1].split('\n') if stdout else []:
        match = re.fullmatch(r'package:(%s) uid:(0|[1-9][0-9]{0,9})' % _PACKAGE_NAME, row)
        if not match:
            _fail('a package list row of no known form')
        if match[1] == package:
            found.append(int(match[2]))
    if len(found) > 1:
        _fail('a package listed twice')
    if found and found[0] // PER_USER_RANGE != user:
        _fail("a package UID outside its user's range")
    return found[0] if found else None


def data_path(package):
    """An installed app's base APK path: `/data/app/~~<random>==/<package>-<random>==/base.apk`,
    the form a retained capture shows for SystemUI's data copy (scripts/proof/systemui_sessions.py
    DATA_PATH)."""
    return re.compile(r'/data/app/~~[A-Za-z0-9_-]{22}==/' + re.escape(_package(package))
                      + r'-[A-Za-z0-9_-]{22}==/base\.apk')


def parse_package_path(code, stdout, stderr, package):
    """`pm path --user <id> <package>`: `package:` and the base APK path, then any split's, exit 0;
    status 1 with nothing printed when the user does not have the package
    (PackageManagerShellCommand.java:741-775). Returns the base path of an installed app with no
    split, or None."""
    _reply(code, stdout, stderr)
    if (code, stdout, stderr) == (1, '', ''):
        return None
    match = re.fullmatch(r'package:(\S+)\n', _plain(code, stdout, stderr, 'a path', 8192))
    if not match or not data_path(package).fullmatch(match[1]):
        _fail('a package path of no known form, or with splits')
    return match[1]


def digest_command(path, package):
    """toybox `sha256sum <path>` of an installed app's base APK."""
    if not isinstance(path, str) or not data_path(package).fullmatch(path):
        raise ValueError('not an installed base APK path')
    return 'sha256sum ' + path


def parse_digest(code, stdout, stderr, path):
    """toybox `sha256sum <path>`: the digest of exactly that file."""
    match = re.fullmatch(r'([0-9a-f]{64})  (\S+)\n', _plain(code, stdout, stderr, 'a file digest', 8192))
    if not match or match[2] != path:
        _fail('a file digest of no known form')
    return match[1]


# ---------------------------------------------------------------- the effects' replies

def classify_create(code, stdout, stderr):
    """`pm create-user`'s reply: ('CREATED', returned ID), ('REFUSED', (code, message)) or
    ('UNRECOGNIZED', None). Success prints `Success: created user id <id>` with status 0. A
    refusal the user service reports prints the ServiceSpecificException and `Error: couldn't
    create User.` on standard error with status 1 (PackageManagerShellCommand.java:3238-3257;
    core/java/android/os/ServiceSpecificException.java:52-54). Its codes are UserManager's
    (core/java/android/os/UserManager.java:2556-2613): 6 the maximum, 10 a restriction. Anything
    else leaves the effect unknown."""
    _reply(code, stdout, stderr)
    match = re.fullmatch(r'Success: created user id (0|[1-9][0-9]{0,4})\n', stdout)
    if code == 0 and stderr == '' and match and int(match[1]) <= MAX_USER_ID:
        return 'CREATED', int(match[1])
    refused = re.fullmatch(r"(?:Error: android\.os\.ServiceSpecificException(?:: ([^\n]*))? \(code (-?[0-9]{1,10})\)\n)?"
                           r"Error: couldn't create User\.\n", stderr)
    if code == 1 and stdout == '' and refused:
        return 'REFUSED', {'code': int(refused[2]) if refused[2] else None, 'message': refused[1]}
    return 'UNRECOGNIZED', None


def classify_start(code, stdout, stderr):
    """`am start-user -w`'s reply. It exits 0 either way: `Success: user started` on standard
    output, or `Error: could not start user` on standard error (ActivityManagerShellCommand.java:
    3117-3122). STARTED, FAILED or UNRECOGNIZED. A STARTED reply proves no running user."""
    _reply(code, stdout, stderr)
    if (code, stdout, stderr) == (0, 'Success: user started\n', ''):
        return 'STARTED'
    if (code, stdout, stderr) == (0, '', 'Error: could not start user\n'):
        return 'FAILED'
    return 'UNRECOGNIZED'


def classify_switch(code, stdout, stderr, user):
    """`am switch-user -w`'s reply (ActivityManagerShellCommand.java:2965-3043). Nothing and
    status 0 after the switch observer saw it complete, or at once when the user was current
    already: SWITCHED. `Error: Failed to switch to user <id>` on standard output with status 1:
    FAILED. `Error: UserSwitchabilityResult=<n>` on standard error with status 255: REFUSED.
    An interrupted wait prints an error and still exits 0: UNRECOGNIZED, as is anything else."""
    _reply(code, stdout, stderr)
    if (code, stdout, stderr) == (0, '', ''):
        return 'SWITCHED'
    if (code, stdout, stderr) == (1, 'Error: Failed to switch to user %d\n' % user, ''):
        return 'FAILED'
    if code == 255 and stdout == '' and re.fullmatch(r'Error: UserSwitchabilityResult=-?[0-9]{1,10}\n', stderr):
        return 'REFUSED'
    return 'UNRECOGNIZED'


def classify_input(code, stdout, stderr):
    """An `input` command's reply: nothing and status 0 (InputShellCommand.java:272-315)."""
    _reply(code, stdout, stderr)
    return 'INJECTED' if (code, stdout, stderr) == (0, '', '') else 'UNRECOGNIZED'


def classify_install_existing(code, stdout, stderr, package, user):
    """`pm install-existing`'s reply (PackageManagerShellCommand.java:1998-2073). It reports the
    package installed for the user with status 0 whatever installExistingPackageAsUser returned
    unless the package does not exist, so REPORTED proves nothing until a readback shows it.
    MISSING when the package does not exist; UNRECOGNIZED otherwise."""
    _reply(code, stdout, stderr)
    if (code, stdout, stderr) == (0, 'Package %s installed for user: %d\n' % (package, user), ''):
        return 'REPORTED'
    if (code, stdout, stderr) == (1, "android.content.pm.PackageManager$NameNotFoundException: Package %s doesn't "
                                     "exist\n" % package, ''):
        return 'MISSING'
    return 'UNRECOGNIZED'


ENABLED_STATES = ('default', 'enabled', 'disabled', 'disabled-user', 'disabled-until-used', 'unknown')


def classify_enable(code, stdout, stderr, package):
    """`pm enable`'s reply: the package's enabled state as it reads it back after the change
    (PackageManagerShellCommand.java:2431-2471), or UNRECOGNIZED."""
    _reply(code, stdout, stderr)
    match = re.fullmatch(r'Package %s new state: (%s)\n' % (re.escape(package), '|'.join(ENABLED_STATES)), stdout)
    if code == 0 and stderr == '' and match:
        return match[1]
    return 'UNRECOGNIZED'


# ---------------------------------------------------------------- the typed inventory and limits

def inventory(dump, rows):
    """The typed inventory, lab_actions.check_inventory's form, from a whole dump and a user list
    that agrees with it: the current user, and each user's ID, serial, type, coarse state, flags,
    effective restrictions, parent and markers. A user marked guest to remove is being removed.
    Refuses a dump with no current user."""
    why = check_list(dump, rows)
    if why is not None:
        _fail(why)
    if dump['current_user'] is None:
        _fail('the user dump names no current user')
    reading = {'whole': True, 'current_user': dump['current_user'], 'users': [
        {'id': u['id'], 'serial': u['serial'], 'type': u['type'], 'state': COARSE[u['state']], 'flags': u['flags'],
         'restrictions': list(u['restrictions']), 'parent': u['parent'],
         'removing': u['removing'] or u['guest_to_remove'], 'partial': u['partial'], 'precreated': u['precreated']}
        for u in dump['users']]}
    why = lab_actions.check_inventory(reading)
    if why is not None:
        _fail(why)
    return reading


LIMIT_KEYS = ('supports_multiple', 'dump_supports', 'max_switchable', 'built_in_max', 'limit_reached', 'type',
              'type_enabled', 'type_max_allowed', 'type_allowed', 'type_count', 'max_running', 'running',
              'creator_restrictions')


def limits(dump, supports, max_switchable, type_allowed, max_running):
    """The typed user limits from one whole dump and the four limit reads around it: whether
    switchable users are supported, the effective switchable maximum and whether the dump says it
    is reached, the full secondary type's enabled flag, configured and currently allowed maximum and
    how many users of it count, the running user limit and how many users run, and the system
    user's effective restrictions, those a shell creation is checked against
    (UserManagerService.java:6340-6378, 9223-9232). The reads must agree with the dump."""
    if supports != dump['supports_switchable'] or max_switchable != dump['max_switchable']:
        _fail('the limit reads and the user dump disagree')
    if SECONDARY_TYPE not in dump['types']:
        _fail('the user dump does not list the full secondary type')
    system = [u for u in dump['users'] if u['id'] == 0]
    if len(system) != 1:
        _fail('the user dump lists no system user')
    # Users of a type counted toward its maximum: not dying, not precreated, not a guest to remove
    # (UserManagerService.java:4337-4352).
    count = len([u for u in dump['users'] if u['type'] == SECONDARY_TYPE and not u['removing']
                 and not u['precreated'] and not u['guest_to_remove']])
    reading = {'supports_multiple': supports, 'dump_supports': dump['supports_switchable'],
               'max_switchable': max_switchable, 'built_in_max': dump['built_in_max'],
               'limit_reached': dump['limit_reached'], 'type': SECONDARY_TYPE,
               'type_enabled': dump['types'][SECONDARY_TYPE]['enabled'],
               'type_max_allowed': dump['types'][SECONDARY_TYPE]['max_allowed'], 'type_allowed': type_allowed,
               'type_count': count, 'max_running': max_running,
               'running': len([u for u in dump['users'] if u['state'] in RUNNING_STATES]),
               'creator_restrictions': list(system[0]['restrictions'])}
    why = check_limits(reading)
    if why is not None:
        _fail(why)
    return reading


def check_limits(reading):
    """Why a user limits reading is not of its exact form, or None."""
    if not isinstance(reading, dict) or set(reading) != set(LIMIT_KEYS):
        return 'user limits have exactly their keys'
    for name in ('supports_multiple', 'dump_supports', 'limit_reached', 'type_enabled'):
        if type(reading[name]) is not bool:
            return 'a user limit flag is a boolean'
    for name in ('max_switchable', 'type_max_allowed', 'type_allowed', 'type_count', 'max_running', 'running'):
        if type(reading[name]) is not int or not -(1 << 31) <= reading[name] < (1 << 31):
            return 'a user limit count is an integer'
    if reading['built_in_max'] is not None and type(reading['built_in_max']) is not int:
        return 'a built-in maximum is an integer or null'
    if reading['type'] != SECONDARY_TYPE:
        return 'user limits are of the full secondary type'
    restrictions = reading['creator_restrictions']
    if not isinstance(restrictions, list) or any(not isinstance(r, str) or not _RESTRICTION.fullmatch(r)
                                                 for r in restrictions):
        return "the creator's restrictions are names"
    return None


def creation_problem(reading, user_limits):
    """Why creating the one full secondary user is refused now, or None. The inventory must be
    whole and list only the system user: exactly one secondary user is ever created, on a guest
    whose only user is its own, and never beside an unexpected profile. Switchable users must
    be supported and the type enabled, the system user must not have no_add_user, and neither the
    switchable maximum nor the type's allowed number may be reached. A disabled type is refused even
    where a debuggable build's creation override would let Android create it
    (UserManagerService.java:4407-4419, 6437-6441)."""
    if not reading['whole']:
        return 'the user inventory is not whole'
    if [u['id'] for u in reading['users']] != [0]:
        return 'a user other than the system user is listed: exactly one secondary user is created, beside no other'
    if not user_limits['supports_multiple']:
        return 'switchable users are not supported'
    if user_limits['type_enabled'] is not True:
        return 'the full secondary user type is not enabled'
    if 'no_add_user' in user_limits['creator_restrictions']:
        return 'the system user has the no_add_user restriction'
    if (user_limits['limit_reached'] or user_limits['type_allowed'] <= user_limits['type_count']
            or user_limits['max_switchable'] <= 1):
        return 'the maximum number of users is reached'
    return None


def find(reading, user):
    """The users of an inventory with an ID."""
    return [u for u in reading['users'] if u['id'] == user]


def start_problem(reading, user_limits, target):
    """Why starting the created user is refused now, or None. It must be listed whole as the
    user its create action identified, unmarked and stopped, so the start's effect is its own; and
    one more running user must stay within the running limit, since Android trims other running
    users after a background start beyond it (UserController.java:660-751, 2427-2437). A start
    never stops a running user to make room."""
    if not reading['whole']:
        return 'the user inventory is not whole'
    found = find(reading, target['id'])
    if len(found) != 1 or (found[0]['serial'], found[0]['type']) != (target['serial'], target['type']):
        return 'the created user is not listed as its create action identified it'
    if found[0]['removing'] or found[0]['partial'] or found[0]['precreated']:
        return 'the created user is being removed, partial or precreated'
    if found[0]['state'] != 'NOT_RUNNING':
        return 'the created user runs already'
    running = len([u for u in reading['users'] if u['state'] != 'NOT_RUNNING'])
    if running + 1 > user_limits['max_running']:
        return 'another running user would pass the running limit, and Android would stop a running user'
    return None


def still_running(before, after):
    """The users running in one whole inventory that a later whole one shows stopped or no longer
    lists, as (id, serial): a start or switch that stopped a running user."""
    later = {(u['id'], u['serial']): u for u in after['users']}
    return [(u['id'], u['serial']) for u in before['users'] if u['state'] != 'NOT_RUNNING'
            and ((u['id'], u['serial']) not in later or later[(u['id'], u['serial'])]['state'] == 'NOT_RUNNING')]


def removed(previous, reading):
    """The (id, serial) pairs of `previous` that a later inventory no longer lists, or None when
    that inventory is not whole: only a whole later inventory shows a removal. A user that is
    still listed while being removed is not removed yet."""
    if reading is None or not reading['whole']:
        return None
    shown = {(u['id'], u['serial']) for u in reading['users']}
    return sorted(pair for pair in previous if tuple(pair) not in shown)


def condition(reading, user):
    """One listed user's condition in a whole inventory: FOREGROUND for the current running user,
    BACKGROUND for another running one, STOPPED for one that does not run, each with whether its
    CE storage is unlocked. The dump shows no keyguard: a locked screen over an unlocked user reads
    unlocked, and only CE storage locked again, RUNNING_LOCKED, reads locked. None when the
    inventory is not whole or does not list the user once."""
    if reading is None or not reading['whole']:
        return None
    found = find(reading, user)
    if len(found) != 1:
        return None
    u = found[0]
    if u['state'] == 'NOT_RUNNING':
        return {'condition': 'STOPPED', 'ce_unlocked': False}
    return {'condition': 'FOREGROUND' if reading['current_user'] == user else 'BACKGROUND',
            'ce_unlocked': u['state'] == 'RUNNING_UNLOCKED'}


# ---------------------------------------------------------------- the setup records

# The `user-setup` ledger records a create action writes: CREATED the moment its reply names a
# new user's ID, before anything else is read, with the inventory read just before the effect and
# the serials known then; IDENTIFIED once a whole inventory lists that ID, with its actual serial
# and type. A reopening checks each against the capture and the group it names.
SETUP_RECORDS = {
    'CREATED': ('record', 'action_id', 'begin', 'capture', 'user', 'before_group', 'before_users', 'serials_before',
                'wall_ns'),
    'IDENTIFIED': ('record', 'action_id', 'begin', 'created', 'user', 'serial', 'type', 'flags', 'inventory_group',
                   'wall_ns'),
}


def setup_problem(record):
    """Why a user setup record is not of its exact form, or None."""
    keys = SETUP_RECORDS.get(record.get('record')) if isinstance(record, dict) else None
    if keys is None or set(record) - {'number', 'kind'} != set(keys):
        return 'a user setup record of no known form'
    if not isinstance(record['action_id'], str) or not lab_actions.HEX16.fullmatch(record['action_id']):
        return 'a user setup record names its action'
    for name in ('begin', 'capture', 'before_group', 'created', 'inventory_group'):
        if name in record and (type(record[name]) is not int or record[name] <= 0):
            return 'a user setup record names its ledger entries'
    if type(record['user']) is not int or not 0 <= record['user'] <= MAX_USER_ID or type(record['wall_ns']) is not int:
        return 'a user setup record names a user ID and its time'
    if record['record'] == 'IDENTIFIED' and record['user'] == 0:
        return 'an identified user is never the system user'
    if record['record'] == 'CREATED':
        for name in ('before_users', 'serials_before'):
            values = record[name]
            if not isinstance(values, list) or any(type(v) is not int or v < 0 for v in values) \
                    or values != sorted(set(values)):
                return 'a create names the users and serials it knew, each once'
    else:
        if type(record['serial']) is not int or record['serial'] < 0 or record['type'] != SECONDARY_TYPE \
                or type(record['flags']) is not int or record['flags'] < 0:
            return 'an identified user names its serial, its full secondary type and its flags'
    return None


def identify(created, reading):
    """The created user as a whole inventory lists it, or why not: exactly one user with the
    returned ID, of the full secondary type, unmarked, whose serial no inventory showed before the
    create and whose ID no user had then. Android takes a new user's ID from the unused ones and
    gives each user a new serial; a reused one is not this user."""
    if not reading['whole']:
        return None, 'the user inventory is not whole'
    found = find(reading, created['user'])
    if created['user'] in created['before_users']:
        return None, 'the returned ID was already a user before the create'
    if len(found) != 1:
        return None, 'a whole inventory does not list the returned user ID'
    u = found[0]
    if u['type'] != SECONDARY_TYPE:
        return None, 'the returned user is of another type: %s' % u['type']
    if u['serial'] in created['serials_before']:
        return None, 'the returned user has a serial seen before the create'
    if u['removing'] or u['partial'] or u['precreated']:
        return None, 'the returned user is being removed, partial or precreated'
    if u['flags'] & (FLAGS['EPHEMERAL'] | FLAGS['GUEST']):
        # Android stops a guest or ephemeral user once it leaves the foreground
        # (UserController.java:1883-1905), which would stop a running user.
        return None, 'the returned user is ephemeral or a guest'
    return u, None


# ---------------------------------------------------------------- genuine main SystemUI processes

# The main process is named after the package exactly (packages/SystemUI/AndroidManifest.xml:
# 436-444); its other processes carry a suffix. Zygote and AndroidRuntime set the kernel task name
# to the last 15 characters of a longer dotted name (core/jni/com_android_internal_os_Zygote.cpp:
# 147, 958-984, 2124-2130; core/jni/AndroidRuntime.cpp:274, 352-370), and argv[0] to the name.
COMM = SYSTEMUI[-15:]


def parse_pidof(code, stdout, stderr):
    """`pidof <name>`: one or more distinct PIDs on one line, or the quiet failure, status 1 with
    nothing printed, for no match. Toybox's pidof matches argv[0] exactly; its source is not
    pinned here. Any other failure is an unavailable read, never absence."""
    _reply(code, stdout, stderr)
    if (code, stdout, stderr) == (1, '', ''):
        return []
    match = re.fullmatch(r'([1-9][0-9]{0,6}(?: [1-9][0-9]{0,6})*)\n', stdout)
    if code != 0 or stderr != '' or not match:
        raise lab_readers.Unavailable('pidof failed other than quietly')
    found = [int(pid) for pid in match[1].split(' ')]
    if len(set(found)) != len(found):
        _fail('a process listed twice')
    return found


def _proc(code, stdout, stderr, what):
    """A /proc read: a refusal or a process that ended is unavailable, never an observation."""
    _reply(code, stdout, stderr, 65536)
    if code != 0 or stderr != '':
        raise lab_readers.Unavailable('the %s read was refused or the process ended' % what)


def parse_cmdline(code, stdout, stderr):
    """`/proc/<pid>/cmdline` of a zygote child: its name, then NULs only, since AndroidRuntime
    clears the whole argument block before copying the name in (AndroidRuntime.cpp:363-365). How
    much of the cleared block the kernel shows is not pinned here."""
    _proc(code, stdout, stderr, 'cmdline')
    match = re.fullmatch(r'([\x21-\x7e]{1,255})\x00+', stdout)
    if not match:
        _fail('a command line of no known form')
    return match[1]


_STATUS_LINE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*):(?:\t(.*))?')


def parse_status(code, stdout, stderr, pid):
    """`/proc/<pid>/status`: its Name, Pid and the four Uid fields, real, effective, saved and file
    system, each named once. The kernel's task_state source is not pinned here."""
    _proc(code, stdout, stderr, 'status')
    if not stdout.endswith('\n'):
        _fail('a process status of no known form')
    seen = {}
    for line in stdout[:-1].split('\n'):
        match = _STATUS_LINE.fullmatch(line)
        if not match:
            _fail('a process status line of no known form')
        if match[1] in ('Name', 'Pid', 'Uid'):
            if match[1] in seen:
                _fail('a process status names %s twice' % match[1])
            seen[match[1]] = match[2] or ''
    if set(seen) != {'Name', 'Pid', 'Uid'} or seen['Pid'] != str(pid):
        _fail('a process status of another process or without its identity')
    uids = seen['Uid'].split('\t')
    if len(uids) != 4 or not all(re.fullmatch(r'0|[1-9][0-9]{0,9}', u) for u in uids):
        _fail('process UIDs of no known form')
    return {'name': seen['Name'], 'uids': [int(u) for u in uids]}


def parse_stat(code, stdout, stderr, pid):
    """`/proc/<pid>/stat`: its task name and its start time in clock ticks since the boot, field
    22. The name ends at the last parenthesis, since a name may hold one."""
    _proc(code, stdout, stderr, 'stat')
    if not stdout.endswith('\n') or '\n' in stdout[:-1] or ' (' not in stdout or ')' not in stdout:
        _fail('a process stat of no known form')
    head, tail = stdout[:stdout.rindex(')')], stdout[stdout.rindex(')') + 1:-1]
    number, name = head.split(' (', 1)
    fields = tail.split(' ')
    if number != str(pid) or fields[0] != '' or len(fields) < 21 or not fields[20].isdigit():
        _fail('a process stat of another process or of no known form')
    return {'comm': name, 'start_ticks': int(fields[20])}


def parse_context(code, stdout, stderr):
    """`/proc/<pid>/attr/current`: the exact SELinux context, ended by one NUL. Its categories are
    kept as read; their rule for each user is libselinux's, not pinned here, so none is guessed."""
    _proc(code, stdout, stderr, 'context')
    match = re.fullmatch(r'(u:r:[a-z0-9_]+:s0(?::c[0-9]+,c[0-9]+(?:,c[0-9]+,c[0-9]+)?)?)\x00', stdout)
    if not match:
        _fail('a context of no known form')
    return match[1]


PROCESS_KEYS = ('package', 'app_id', 'absent', 'users')
PROCESS_USER_KEYS = ('user', 'serial', 'state', 'uid', 'process')
PROCESS_FIELDS = ('pid', 'start_ticks', 'uid', 'uids', 'name', 'comm', 'context')


def join_processes(reading, uids, candidates, recheck, again):
    """The genuine main SystemUI process of each listed user, joined by the user's actual package
    UID and serial, never by pidof's order: `uids` maps each user to the package's UID for it,
    `candidates` holds each listed PID's stat, read first, then its command line, status and
    context, `recheck` each PID's stat read again after every other read, and `again` pidof's
    second reading.

    A candidate is genuine only with the package's exact name, the task name Android gives it, all
    four status UIDs equal and the start identity unchanged at the end. Its UID must be one user's
    package UID; two for one user, or one of no listed user, has no known form. Every user's
    package UID must be in that user's range with one app ID. A PID set or start identity that
    changed during the read is unavailable: a process may have ended and its PID been reused. Only
    the quiet failure of pidof, twice, shows no process at all."""
    if not reading['whole']:
        _fail('the user inventory is not whole')
    if sorted(again) != sorted(candidates):
        raise lab_readers.Unavailable('the SystemUI processes changed during the read')
    by_uid, app = {}, None
    for u in reading['users']:
        uid = uids.get(u['id'])
        if uid is None:
            continue
        if uid // PER_USER_RANGE != u['id'] or (app is not None and uid % PER_USER_RANGE != app):
            _fail('package UIDs outside their users or of two app IDs')
        app = uid % PER_USER_RANGE
        by_uid[uid] = u
    joined = {}
    for pid, c in sorted(candidates.items()):
        if recheck.get(pid) != {'comm': c['comm'], 'start_ticks': c['start_ticks']}:
            raise lab_readers.Unavailable('process %d changed during the read' % pid)
        if c['name'] != SYSTEMUI or c['comm'] != COMM or c['status_name'] != COMM:
            _fail('process %d is not named as the main SystemUI process' % pid)
        if len(set(c['uids'])) != 1:
            _fail('the UIDs of process %d disagree' % pid)
        owner = by_uid.get(c['uids'][0])
        if owner is None:
            _fail('process %d runs with no listed user\'s package UID' % pid)
        if owner['id'] in joined:
            _fail('two main SystemUI processes for user %d' % owner['id'])
        joined[owner['id']] = {'pid': pid, 'start_ticks': c['start_ticks'], 'uid': c['uids'][0], 'uids': c['uids'],
                               'name': c['name'], 'comm': c['comm'], 'context': c['context']}
    result = {'package': SYSTEMUI, 'app_id': app, 'absent': not candidates, 'users': [
        {'user': u['id'], 'serial': u['serial'], 'state': u['state'], 'uid': uids.get(u['id']),
         'process': joined.get(u['id'])} for u in reading['users']]}
    why = check_processes(result)
    if why is not None:
        _fail(why)
    return result


def check_processes(reading):
    """Why a SystemUI process reading is not of its exact form, or None."""
    if not isinstance(reading, dict) or set(reading) != set(PROCESS_KEYS) or reading['package'] != SYSTEMUI:
        return 'a process reading has exactly its keys'
    if type(reading['absent']) is not bool or (reading['app_id'] is not None and type(reading['app_id']) is not int):
        return 'a process reading names whether pidof found none and the app ID'
    users = reading['users']
    if not isinstance(users, list) or not users:
        return 'a process reading lists every listed user'
    pids = []
    for u in users:
        if not isinstance(u, dict) or set(u) != set(PROCESS_USER_KEYS) or type(u['user']) is not int:
            return 'a user of a process reading has exactly its keys'
        if u['uid'] is not None and type(u['uid']) is not int:
            return "a user's package UID is an integer or null"
        p = u['process']
        if p is None:
            continue
        if not isinstance(p, dict) or set(p) != set(PROCESS_FIELDS) or p['uid'] != u['uid'] or p['uids'] != [u['uid']] * 4:
            return "a process is joined by its user's package UID"
        pids.append(p['pid'])
    if len(set(pids)) != len(pids) or (reading['absent'] and pids):
        return 'a process joined twice, or joined although pidof found none'
    return None


# ---------------------------------------------------------------- the reader

class UserReader:
    """The typed user reads through a run function, `run(command) -> (status, stdout, stderr)`,
    which runs exactly the command and raises lab_readers.Unavailable for any reply that did not
    complete whole. Each method reads whole forms and returns its reading."""

    def __init__(self, run):
        self._run = run

    def _read(self, command):
        if not read_allowed(command):
            raise FormError('a command outside the user reads: %r' % command)
        return self._run(command)

    def dump(self):
        return parse_dump(*self._read(DUMP))

    def inventory(self):
        """The typed inventory: the whole dump, the user list, and the dump again, which must be the
        same, so the list was read inside one unchanged inventory."""
        first = self.dump()
        rows = parse_list(*self._read(LIST))
        second = self.dump()
        if inventory_key(first) != inventory_key(second):
            raise lab_readers.Unavailable('the users changed during the read')
        return inventory(second, rows)

    def limits(self):
        supports = parse_supports(*self._read(SUPPORTS))
        maximum = parse_max_users(*self._read(MAX_USERS))
        allowed = parse_max_of_type(*self._read(MAX_OF_TYPE))
        running = parse_max_running(*self._read(MAX_RUNNING))
        return limits(self.dump(), supports, maximum, allowed, running)

    def processes(self, reading):
        """Each listed user's genuine main SystemUI process from a whole inventory just read:
        pidof, twice when it finds none, every candidate's start identity from its stat and then
        its command line, status and context, each listed user's package UID, then every
        candidate's stat and pidof again. Every identity field is read between the two start
        identities, so a PID reused at any point between them changes it."""
        if not reading or not reading.get('whole'):
            raise FormError('the user inventory is not whole')
        pids = parse_pidof(*self._read(PIDOF))
        if not pids and parse_pidof(*self._read(PIDOF)):
            raise lab_readers.Unavailable('pidof did not repeat its quiet failure')
        candidates = {}
        for pid in pids:
            stat = parse_stat(*self._read(proc_command(pid, 'stat')), pid)
            name = parse_cmdline(*self._read(proc_command(pid, 'cmdline')))
            status = parse_status(*self._read(proc_command(pid, 'status')), pid)
            context = parse_context(*self._read(proc_command(pid, 'attr/current')))
            candidates[pid] = {'name': name, 'status_name': status['name'], 'uids': status['uids'],
                               'comm': stat['comm'], 'start_ticks': stat['start_ticks'], 'context': context}
        uids = {}
        for u in reading['users']:
            if u['partial'] or u['precreated']:
                continue
            uid = parse_package_uid(*self._read(package_uid_command(u['id'], SYSTEMUI)), SYSTEMUI, u['id'])
            if uid is not None:
                uids[u['id']] = uid
        recheck = {pid: parse_stat(*self._read(proc_command(pid, 'stat')), pid) for pid in pids}
        again = parse_pidof(*self._read(PIDOF)) if pids else []
        return join_processes(reading, uids, candidates, recheck, again)


def rederive(name, captures, inventory=None):
    """The typed reading a group's recorded captures give when the same reader reads them again:
    each capture is (command, exit status or None, standard output, standard error), and they must
    be exactly the reads that reading makes, in order. NotImplemented for another group."""
    queue = list(captures)

    def run(command):
        if not queue or queue[0][0] != command:
            raise FormError('the captures are not the reads a %s reading makes' % name)
        _, code, stdout, stderr = queue.pop(0)
        if code is None:
            raise lab_readers.Unavailable('a capture did not complete')
        return code, stdout, stderr
    reader = UserReader(run)
    if name == 'inventory':
        value = reader.inventory()
    elif name == 'user-limits':
        value = reader.limits()
    elif name == 'systemui-processes':
        if inventory is None:
            raise FormError('a process reading names no inventory')
        value = reader.processes(inventory)
    else:
        return NotImplemented
    if queue:
        raise FormError('captures beyond the reads a %s reading makes' % name)
    return value


def inventory_key(dump):
    """What two dumps of one unchanged inventory share: the current user and every user's
    identity, state, flags and restrictions."""
    return (dump['current_user'], [(u['id'], u['serial'], u['type'], u['state'], u['flags'], u['restrictions'],
                                    u['removing'], u['partial'], u['precreated'], u['guest_to_remove'])
                                   for u in dump['users']])
