# SPDX-License-Identifier: Apache-2.0
"""The health composition of the next campaign profile, host side: one full probe of one user,
read afresh and judged criterion by criterion, and the guest forms those reads have.

Every composition declares all seven criteria of the plan's Definitions, the mask 127, and is one
full probe of one user and serial. Its criterion readers are pure functions over whole reads: each
gives one row, HELD, BAD or UNKNOWN with its reason and the reads it judged, never a fact of its
own. Only the broker emits a fact, at most one HEALTH for a completed probe, and HELD only when all
seven rows hold. An unavailable read, a missing reader or any doubt leaves its row UNKNOWN, which
classifies the probe INCONCLUSIVE: partial evidence is doubt to the reconciler's judge, which also
takes a held mask short of the plan's criteria as doubt (Reconciler.java:1054-1100).

The readers of this part:

- **Bit 0, UID and context.** The user's genuine main SystemUI process from full_users.py's
  discovery over a whole typed inventory, compared with the identity baseline of its serial, read
  while the factory copy was active: the UID, the app ID and the exact SELinux context. For the
  system user, the plan's own base UID and context too. A process that is not there, or a read
  that is not whole, is unknown: process loss alone is no failure.
- **Bit 2, the UI marker.** The status bar clock node of one fresh dump of all windows, which a UI
  preparation wrote under a path named by its operation and the composer now reads. The capture
  must have been taken with the user in the foreground, the display awake and the user unlocked
  with a secure credential, and the fixture notice out of view. Variant A shows its time with the
  marker ` WS-A` in both the text and the content description; the original clock shows the time
  alone, with no workshop marker anywhere on the display. A marker in another window does not
  qualify.
- **Bit 3, keyguard unlock and CE authority.** A preparation's credential unlock from a genuine
  locked state of a user with a secure credential, then the user unlocked; now the framework's CE
  state, the whole listing's RUNNING_UNLOCKED and the fixture's nonce read back from its own CE
  storage, equal to the nonce CE_SENTINEL recorded. The CE read is the work fixture's, a hook here.
  A screen relock is not CE withdrawal.

Bits 1, 4, 5 and 6 are named hooks: the crash and ANR witness (section 5.4), which
health_witness.py fills, the active bytes reader, the work fixture's ordinary native work and the
recovery route reader. Until one is admitted, its row is UNKNOWN with the reason naming it.

The UI state comes from the fixed read only helper of tests/ui-state-read, run only after reads of
the shell user and of its pinned bytes, which are read again after it. A host test of this module
shows these parsers and judgments on source derived forms; no Android form here is qualified."""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import full_users  # noqa: E402
import health_records as records  # noqa: E402
import lab_readers  # noqa: E402
from scripts.proof import systemui_sessions as readback  # noqa: E402

# The design's starting values, which the lab driver declares and writes into every plan
# (driver/dev/andrix/lab/component/LabDriverMain.java:72-76): declared values, not measured
# performance. The notice delay is both the ordinary and the emergency one.
HEALTH_WINDOW_MS = 15 * 60_000
NOTICE_DELAY_MS = 2 * 60_000
REQUEST_LIMIT = 3
REBOOT_TIMEOUT_MS = 5 * 60_000
ACTIVATE_WINDOW_MS = 24 * 3_600_000
VERIFICATION_WAIT_MS = 10 * 60_000
# Reconciler.WINDOW_PARTS: probes leave no gap above a quarter of the window, 225 s for 15 min.
WINDOW_PARTS = 4
MAX_GAP_MS = HEALTH_WINDOW_MS // WINDOW_PARTS
# The criteria as DeploymentRecords.Criterion numbers them. Every composition declares them all.
UID_AND_CONTEXT, NO_CRASH_OR_ANR, UI_MARKER, UNLOCK_AND_CE, BYTES_UNCHANGED, NATIVE_WORK, RECOVERY_ROUTE = range(7)
CRITERIA = 7
CRITERIA_ALL = (1 << CRITERIA) - 1
ROW_KEYS = ('bit', 'status', 'reason', 'commands', 'preparation', 'baseline')
# The hooks of later parts, and the reason each gives while it is not admitted.
HOOKS = {NO_CRASH_OR_ANR: 'no witness reader is admitted: the process history reader is not given',
         BYTES_UNCHANGED: 'no active bytes reader is admitted in this part',
         NATIVE_WORK: 'no ordinary native work reader is admitted: the work fixture is a later part',
         RECOVERY_ROUTE: 'no recovery route reader is admitted in this part'}

# ---------------------------------------------------------------- the UI state helper

# The fixed read only helper of tests/ui-state-read: its pinned jar, the one path the vehicle
# pushes it to, and its one invocation for a bounded user. The composer never pushes.
UI_STATE_HELPER = '/data/local/tmp/andrix-d5/andrix-ui-state-read.jar'
UI_STATE_HELPER_SHA256 = 'ac428bd1d540f47e92af9841d855d748af878e30b956e399e366a1c58aeec3dc'
UI_STATE_HEADER = 'andrix-ui-state-read-v1'
UI_STATE_CAPABILITIES = records.UI_STATE_CAPABILITIES
# The helper's bound, UserHandle.MAX_SECONDARY_USER_ID (core/java/android/os/UserHandle.java:
# 134-135).
UI_STATE_MAX_USER = 21473
SHELL_IDENTITY = 'id'
SHELL_USER = (2000, 2000, 'u:r:shell:s0')
HELPER_DIGEST = 'sha256sum ' + UI_STATE_HELPER
_UI_STATE = re.compile('CLASSPATH=' + re.escape(UI_STATE_HELPER) + r' app_process /system/bin UiStateRead '
                       r'(0|[1-9][0-9]{0,4})')
# Where UI preparations write their fresh hierarchies, one file named by each operation.
HEALTH_DIR = '/data/local/tmp/andrix-d5/health'
_HIERARCHY_READ = re.compile('cat ' + records.HIERARCHY.pattern)
MAX_HIERARCHY = 4 << 20


class FormError(lab_readers.Unclassified):
    """Output of no known form: no reading."""


class ComposerError(lab_readers.Unclassified):
    """The composer asked for a command its reader does not admit: the composition has no form."""


def _user(user, limit=UI_STATE_MAX_USER):
    if type(user) is not int or not 0 <= user <= limit:
        raise ValueError('a user ID from 0 to %d' % limit)
    return user


def ui_state_command(user):
    """The helper's one invocation for one user: `CLASSPATH=<jar> app_process /system/bin
    UiStateRead <user>`, as the shell user."""
    return 'CLASSPATH=%s app_process /system/bin UiStateRead %d' % (UI_STATE_HELPER, _user(user))


def hierarchy_path(operation):
    """The fresh hierarchy path of one UI preparation's operation."""
    if not isinstance(operation, str) or not records.HEX16.fullmatch(operation):
        raise ValueError('an operation ID')
    return '%s/hierarchy-%s.xml' % (HEALTH_DIR, operation)


def hierarchy_command(path):
    if not isinstance(path, str) or not records.HIERARCHY.fullmatch(path):
        raise ValueError('a fresh hierarchy path')
    return 'cat ' + path


def read_allowed(command):
    """Whether a command is one of the composer's own fixed read forms: the shell user, the
    helper's digest, the helper for a bounded user, and a fresh hierarchy's read. The typed
    inventory and the process discovery are full_users.py's reads."""
    if command in (SHELL_IDENTITY, HELPER_DIGEST) or _HIERARCHY_READ.fullmatch(command):
        return True
    match = _UI_STATE.fullmatch(command)
    return bool(match) and int(match[1]) <= UI_STATE_MAX_USER


def parse_ui_state(code, stdout, stderr, user):
    """One whole reply of the UI state helper for one user: its version line, the user, the
    capabilities of this build, one line for each question in order, the status and the end
    marker, with nothing on standard error. Each answer is true, false, or unavailable with the
    helper's reason, which is None in the reading and never false. Exit status 0 is complete and
    5 unavailable; anything else, a reply cut short before its end marker included, has no known
    form."""
    if type(code) is not int or not isinstance(stdout, str) or not isinstance(stderr, str) or len(stdout) > 4096:
        raise FormError('a UI state reply without its status and both streams')
    if stderr != '' or '\r' in stdout or '\x00' in stdout or not stdout.endswith('\n'):
        raise FormError('a UI state reply of no known form')
    lines = stdout[:-1].split('\n')
    head = [UI_STATE_HEADER, 'user=%d' % _user(user), 'capabilities=' + ','.join(UI_STATE_CAPABILITIES)]
    if len(lines) != len(head) + len(UI_STATE_CAPABILITIES) + 2 or lines[:3] != head:
        raise FormError('a UI state reply of another version, user or build, or cut short')
    if lines[-1] != 'end=' + UI_STATE_HEADER:
        raise FormError('a UI state reply without its end marker')
    values, missing = {}, {}
    for name, line in zip(UI_STATE_CAPABILITIES, lines[3:3 + len(UI_STATE_CAPABILITIES)]):
        key, _, value = line.partition('=')
        if key != name:
            raise FormError('a UI state answer out of order')
        if value in ('true', 'false'):
            values[name] = value == 'true'
        elif value.startswith('unavailable:') and records.UNAVAILABLE.fullmatch(value[len('unavailable:'):]):
            values[name], missing[name] = None, value[len('unavailable:'):]
        else:
            raise FormError('a UI state answer of no known form')
    complete = not missing
    if lines[-2] != 'status=' + ('complete' if complete else 'unavailable') or code != (0 if complete else 5):
        raise FormError('a UI state status that does not follow its answers')
    reading = {'user': user, 'values': values, 'unavailable': missing, 'complete': complete}
    why = records.ui_state_problem(reading, user)
    if why is not None:
        raise FormError(why)
    return reading


def read_ui_state(run, user):
    """The UI state of one user through the helper, bracketed by the shell user and the helper's
    pinned bytes, each read before and after it, as the observer admits its checkpoint helper."""
    def admitted():
        if readback.shell_identity(*run(SHELL_IDENTITY)) != SHELL_USER:
            raise FormError('the commands do not run as the shell user')
        code, stdout, stderr = run(HELPER_DIGEST)
        if stderr != '' or readback.file_digest(code, stdout, UI_STATE_HELPER) != UI_STATE_HELPER_SHA256:
            raise FormError('the UI state helper is not the admitted bytes')
    admitted()
    reading = parse_ui_state(*run(ui_state_command(user)), user)
    admitted()
    return reading


# ---------------------------------------------------------------- the fresh hierarchy

# The SystemUI clock's view ID (packages/SystemUI/res/layout/status_bar.xml:92-93), as the
# dumper prints a view ID (cmds/uiautomator/library/core-src/com/android/uiautomator/core/
# AccessibilityNodeInfoDumper.java:204).
CLOCK_ID = 'com.android.systemui:id/clock'
# The window type of the status bar as AccessibilityWindowInfo.typeToString names it
# (core/java/android/view/accessibility/AccessibilityWindowInfo.java:895-922). Which type the
# status bar window has on the guest is a capture to make.
STATUS_BAR_TYPE = 'TYPE_SYSTEM'
# The clock's time, as ICU's best pattern for the hm or Hm skeleton formats it in the default
# locales, seconds and an AM or PM mark included (packages/SystemUI/src/com/android/systemui/
# statusbar/policy/Clock.java:263-273, 365-440). Another locale's form is unknown, never a failure.
TIME = re.compile(r'[0-9]{1,2}[:.][0-9]{2}(?:[:.][0-9]{2})?(?:[ \u00a0\u202f]?[A-Za-z.]{1,5})?')
# Variant A's marker, appended to both the text and the content description
# (scripts/proof/systemui_fixture.py:43-65), and any workshop marker.
MARKER_A = ' WS-A'
WORKSHOP = re.compile(r'WS-[A-Z]')
EXPECTATIONS = ('WS-A', 'ORIGINAL')
_BOUNDS = re.compile(r'\[(-?[0-9]+),(-?[0-9]+)\]\[(-?[0-9]+),(-?[0-9]+)\]')


def parse_hierarchy(code, stdout, stderr):
    """`cat` of one fresh `uiautomator dump --windows` file: the XML that
    AccessibilityNodeInfoDumper.dumpWindowsToFile writes, displays of windows of hierarchies of
    nodes (AccessibilityNodeInfoDumper.java:115-239). A refused or missing file, a bound passed,
    a document type or entity, or another root has no known form."""
    if type(code) is not int or not isinstance(stdout, str) or not isinstance(stderr, str):
        raise FormError('a hierarchy read without its status and both streams')
    if code != 0 or stderr != '' or not stdout or len(stdout) > MAX_HIERARCHY:
        raise lab_readers.Unavailable('the fresh hierarchy could not be read whole')
    upper = stdout.upper()
    if '<!DOCTYPE' in upper or '<!ENTITY' in upper:
        raise FormError('a hierarchy with a document type or an entity')
    try:
        root = ET.fromstring(stdout)
    except (ET.ParseError, ValueError, UnicodeError) as error:
        raise FormError('a hierarchy of no known form: %s' % type(error).__name__) from error
    if root.tag != 'displays':
        raise FormError('not a dump of all windows')
    return root


def _visible(bounds):
    match = _BOUNDS.fullmatch(bounds or '')
    return bool(match) and int(match[3]) > int(match[1]) and int(match[4]) > int(match[2])


def clock_reading(root, notice_package=None):
    """The status bar clock as one dump of all windows shows it on the default display: (its text,
    its content description, whether any other node on that display shows a workshop marker),
    or (None, why) when the dump does not show exactly one visible clock node in a status bar
    window, or shows the notice fixture."""
    displays = [d for d in root.findall('display') if d.get('id') == '0']
    if len(displays) != 1:
        return None, 'the dump shows no unique default display'
    display = displays[0]
    if notice_package is not None and any(n.get('package') == notice_package for n in display.iter('node')):
        return None, 'the notice fixture is in view'
    clocks = []
    for window in display.iter('window'):
        hierarchies = window.findall('hierarchy')
        if len(hierarchies) > 1:
            return None, 'a window with two hierarchies'
        for node in (hierarchies[0].iter('node') if hierarchies else ()):
            if node.get('package') == full_users.SYSTEMUI and node.get('resource-id') == CLOCK_ID:
                clocks.append((window, node))
    if len(clocks) != 1:
        return None, 'the dump shows %d SystemUI clock nodes, not exactly one' % len(clocks)
    window, node = clocks[0]
    if window.get('type') != STATUS_BAR_TYPE or not _visible(node.get('bounds')):
        return None, 'the clock node is not visible in a status bar window'
    text, description = node.get('text'), node.get('content-desc')
    if text is None or description is None:
        return None, 'the clock node has no text or content description'
    elsewhere = any(n is not node and (WORKSHOP.search(n.get('text') or '') or WORKSHOP.search(n.get('content-desc') or ''))
                    for n in display.iter('node'))
    return (text, description, elsewhere), None


def marker_status(text, description, elsewhere, expectation):
    """The UI marker row's status for one clock node: (status, reason)."""
    if expectation not in EXPECTATIONS:
        return 'UNKNOWN', 'no admitted marker expectation'
    original = bool(TIME.fullmatch(text) and TIME.fullmatch(description))
    marked = (text.endswith(MARKER_A) and description.endswith(MARKER_A)
              and bool(TIME.fullmatch(text[:-len(MARKER_A)]) and TIME.fullmatch(description[:-len(MARKER_A)])))
    workshop = bool(WORKSHOP.search(text) or WORKSHOP.search(description))
    if expectation == 'WS-A':
        if marked:
            return 'HELD', ''
        if original or workshop:
            return 'BAD', "the clock does not show variant A's marker in its text and content description"
        return 'UNKNOWN', 'the clock shows a time of no known form'
    if original and not elsewhere:
        return 'HELD', ''
    if workshop or (original and elsewhere):
        return 'BAD', 'a workshop marker is on the display: the original clock is not restored'
    return 'UNKNOWN', 'the clock shows a time of no known form'


# ---------------------------------------------------------------- the criterion readers

def row(bit, status, reason, commands=(), preparation=None, baseline=None):
    """One criterion row in the form the broker accepts: never a fact of its own."""
    return {'bit': bit, 'status': status, 'reason': '' if status == 'HELD' else reason,
            'commands': sorted(set(commands)), 'preparation': preparation, 'baseline': baseline}


def _listed(inventory, user, serial):
    found = full_users.find(inventory, user) if inventory and inventory.get('whole') else []
    return found[0] if len(found) == 1 and found[0]['serial'] == serial else None


def identity_row(inventory, processes, user, serial, expected, plan_base, commands):
    """Bit 0: the user's genuine main SystemUI process against the identity baseline of its
    serial, read while the factory copy was active, and for the system user against the plan's
    base too: the same UID, app ID and exact context. A changed identity of a process that is
    there is BAD; no baseline, a read that is not whole, a user not listed running, or no process
    is UNKNOWN."""
    if expected is None:
        return row(UID_AND_CONTEXT, 'UNKNOWN', 'no factory identity baseline for this serial', commands)
    if (expected['user'], expected['serial']) != (user, serial):
        return row(UID_AND_CONTEXT, 'UNKNOWN', 'the identity baseline of this serial names another user', commands)
    if plan_base is not None and (plan_base['uid'], plan_base['context']) != (expected['uid'], expected['context']):
        return row(UID_AND_CONTEXT, 'UNKNOWN', "the identity baseline and the plan's base disagree", commands)
    listed = _listed(inventory, user, serial)
    if listed is None or listed['state'] not in ('RUNNING_UNLOCKED', 'RUNNING_LOCKED'):
        return row(UID_AND_CONTEXT, 'UNKNOWN', 'a whole inventory does not show the user running', commands)
    if processes is None:
        return row(UID_AND_CONTEXT, 'UNKNOWN', 'the process discovery is not whole', commands)
    found = [u for u in processes['users'] if (u['user'], u['serial']) == (user, serial)]
    if len(found) != 1 or found[0]['process'] is None:
        return row(UID_AND_CONTEXT, 'UNKNOWN', 'no main SystemUI process of the user now: process loss alone is no '
                                               'failure', commands)
    process = found[0]['process']
    if processes['app_id'] != expected['app_id'] or process['uid'] != expected['uid']:
        return row(UID_AND_CONTEXT, 'BAD', 'the main SystemUI process runs with another UID or app ID than the '
                                           'factory baseline', commands)
    if process['context'] != expected['context']:
        return row(UID_AND_CONTEXT, 'BAD', 'the main SystemUI process runs in another context than the factory '
                                           'baseline', commands)
    return row(UID_AND_CONTEXT, 'HELD', '', commands)


def capture_problem(capture, user):
    """Why a UI preparation's capture conditions do not qualify its hierarchy, or None: the dump
    acknowledged its fresh path, and before and after it the user was in the foreground, the
    display awake and the user unlocked with a secure credential. An unavailable answer is never
    taken as the one wanted."""
    if not capture['acknowledged']:
        return 'the dump did not acknowledge its fresh path'
    for name in ('before', 'after'):
        condition = capture[name]
        values = condition['ui_state']['values']
        if condition['current_user'] != user:
            return 'the user was not in the foreground %s the capture' % name
        if values['interactive'] is not True:
            return 'the display was not read awake %s the capture' % name
        if values['keyguard_locked'] is not False or values['device_locked'] is not False:
            return 'the user was not read unlocked %s the capture' % name
        if values['device_secure'] is not True:
            return 'the user has no secure credential %s the capture: not a legitimate unlock' % name
    return None


def unlock_problem(unlock, user):
    """(status, reason) of a preparation's credential unlock, before the current reads: unknown
    unless it started from a genuine locked state of a user with a secure credential in the
    foreground; BAD when after it the user stayed locked or CE storage stayed locked."""
    before, after = unlock['before'], unlock['after']
    b, a = before['ui_state']['values'], after['ui_state']['values']
    if before['current_user'] != user or after['current_user'] != user:
        return 'UNKNOWN', 'the user was not in the foreground at the unlock'
    if b['device_secure'] is not True or b['keyguard_secure'] is not True:
        return 'UNKNOWN', 'the user has no secure credential: an insecure dismissal is no credential unlock'
    if b['keyguard_locked'] is not True or b['device_locked'] is not True:
        return 'UNKNOWN', 'no genuine locked state was read before the unlock'
    if None in (a['keyguard_locked'], a['device_locked'], a['ce_unlocked']):
        return 'UNKNOWN', 'the state after the unlock is unavailable'
    if a['keyguard_locked'] or a['device_locked']:
        return 'BAD', 'the credential unlock left the user locked'
    if a['ce_unlocked'] is not True or after['state'] != 'RUNNING_UNLOCKED':
        if a['ce_unlocked'] is False and after['state'] != 'RUNNING_UNLOCKED':
            return 'BAD', 'CE storage did not unlock after the credential unlock'
        return 'UNKNOWN', 'the framework and the listing disagree whether CE storage unlocked'
    return None, None


def unlock_row(unlock, ui_now, inventory, user, serial, ce_read, origin, commands, preparation):
    """Bit 3: the preparation's credential unlock, then now the framework's CE state, the whole
    listing's RUNNING_UNLOCKED and the fixture's CE nonce equal to its recorded origin."""
    if unlock is None:
        return row(UNLOCK_AND_CE, 'UNKNOWN', 'no fresh credential unlock was prepared', commands)
    status, why = unlock_problem(unlock, user)
    if status is not None:
        return row(UNLOCK_AND_CE, status, why, commands, preparation if status == 'BAD' else None)
    listed = _listed(inventory, user, serial)
    values = ui_now['values'] if ui_now is not None else None
    if values is None or values['ce_unlocked'] is None or values['device_secure'] is None or listed is None:
        return row(UNLOCK_AND_CE, 'UNKNOWN', 'the current CE state is unavailable', commands)
    if values['ce_unlocked'] is not True or listed['state'] != 'RUNNING_UNLOCKED':
        return row(UNLOCK_AND_CE, 'UNKNOWN', 'CE storage is not unlocked now: no claim', commands)
    if values['device_secure'] is not True:
        return row(UNLOCK_AND_CE, 'UNKNOWN', 'the user has no secure credential now', commands)
    if origin is None:
        return row(UNLOCK_AND_CE, 'UNKNOWN', 'no CE sentinel was recorded for this serial', commands)
    if ce_read is None:
        return row(UNLOCK_AND_CE, 'UNKNOWN', "the fixture's CE nonce was not read", commands)
    if ce_read.get('status') != 'PRESENT' or ce_read.get('nonce') != origin['nonce']:
        return row(UNLOCK_AND_CE, 'BAD', "the fixture's CE storage does not hold its recorded nonce", commands,
                   preparation)
    return row(UNLOCK_AND_CE, 'HELD', '', commands, preparation)


def ui_marker_row(capture, hierarchy, user, expectation, notice_package, commands, preparation):
    """Bit 2: the fresh hierarchy of a qualified capture, judged at its one status bar clock
    node."""
    if capture is None:
        return row(UI_MARKER, 'UNKNOWN', 'no fresh UI capture was prepared', commands)
    why = capture_problem(capture, user)
    if why is not None:
        return row(UI_MARKER, 'UNKNOWN', why, commands)
    if hierarchy is None:
        return row(UI_MARKER, 'UNKNOWN', 'the fresh hierarchy was not read whole', commands)
    reading, why = clock_reading(hierarchy, notice_package)
    if reading is None:
        return row(UI_MARKER, 'UNKNOWN', why, commands)
    status, why = marker_status(*reading, expectation)
    return row(UI_MARKER, status, why, commands, preparation if status != 'UNKNOWN' else None)


# ---------------------------------------------------------------- the composer

class _Read:
    def __init__(self, value, positions, why):
        self.value, self.positions, self.why = value, positions, why

    @property
    def ok(self):
        return self.why is None


class _Calls:
    """The composer's run function, counting each command's position among the probe's captures:
    the broker records one capture for every command it is given, an incomplete one included. A
    command the reader does not admit has no capture and stops the composition."""

    def __init__(self, run):
        self._run, self.count = run, 0

    def run(self, command):
        self.count += 1
        try:
            return self._run(command)
        except ComposerError:
            raise
        except lab_readers.Unclassified as error:
            raise ComposerError('a command the reader does not admit: %s' % error) from error

    def read(self, call):
        start = self.count
        try:
            value = call()
        except ComposerError:
            raise
        except lab_readers.Unavailable as error:
            return _Read(None, list(range(start, self.count)), 'unavailable: %s' % error)
        except (lab_readers.Unclassified, ValueError, KeyError, TypeError) as error:
            return _Read(None, list(range(start, self.count)), 'of no known form: %s' % type(error).__name__)
        return _Read(value, list(range(start, self.count)), None)


class Composer:
    """One user's full probe from fresh reads, through the reader's bound run function.

    `markers` maps each admitted active APK's SHA-256 to the clock it must show: 'WS-A' for
    variant A, 'ORIGINAL' for the factory copy or the restoration. `notice_package` is the notice
    fixture whose window must be out of view. `ce_reader` is the work fixture's CE nonce read, and
    `witness`, `bytes_reader`, `work` and `recovery` the readers of bits 1, 4, 5 and 6: later
    parts' hooks, each an object with `allowed(command)` and `read(calls, context)` giving its row
    (for the witness, its row and its decision). Without one, its row is UNKNOWN."""

    def __init__(self, markers, notice_package=None, ce_reader=None, witness=None, bytes_reader=None, work=None,
                 recovery=None):
        if not isinstance(markers, dict) or any(not isinstance(k, str) or not records.HEX32.fullmatch(k)
                                                or v not in EXPECTATIONS for k, v in markers.items()):
            raise ValueError('markers map APK digests to an admitted clock expectation')
        self.markers, self.notice_package = dict(markers), notice_package
        self.ce_reader = ce_reader
        self.hooks = {NO_CRASH_OR_ANR: witness, BYTES_UNCHANGED: bytes_reader, NATIVE_WORK: work,
                      RECOVERY_ROUTE: recovery}

    def allowed(self, command):
        return (read_allowed(command) or full_users.read_allowed(command)
                or any(h is not None and h.allowed(command) for h in [self.ce_reader] + list(self.hooks.values())))

    @staticmethod
    def _prepared(context, bit, part):
        """The latest offered preparation of a criterion with its result's part, or (None, None)."""
        found = None
        for offer in context.get('preparations', ()):
            result = context.get('results', {}).get(offer['operation'])
            if bit in offer['criteria'] and result is not None and part in result['criteria']:
                if found is None or offer['end'] >= found[0]['end']:
                    found = (offer, result['criteria'][part])
        return found or (None, None)

    def compose(self, run, context):
        """The composition {'user', 'serial', 'rows', 'witness'} of one user and serial."""
        calls = _Calls(run)
        user, serial = context['user'], context['serial']
        users = full_users.UserReader(calls.run)
        inventory = calls.read(users.inventory)
        processes = calls.read(lambda: users.processes(inventory.value)) if inventory.ok else _Read(None, [], 'none')
        ui_now = calls.read(lambda: read_ui_state(calls.run, user))
        capture_offer, capture = self._prepared(context, UI_MARKER, '2')
        hierarchy = (calls.read(lambda: parse_hierarchy(*calls.run(hierarchy_command(capture['path']))))
                     if capture is not None else _Read(None, [], 'no capture'))
        unlock_offer, unlock = self._prepared(context, UNLOCK_AND_CE, '3')
        origin = context.get('ce_origin')
        ce_read = (calls.read(lambda: self.ce_reader.read(calls, {'user': user, 'serial': serial}))
                   if self.ce_reader is not None and origin is not None else _Read(None, [], 'no reader'))
        rows = {UID_AND_CONTEXT: identity_row(inventory.value, processes.value, user, serial,
                                              (context.get('identity') or {}).get('expected'),
                                              (context.get('identity') or {}).get('plan_base'),
                                              inventory.positions + processes.positions)}
        rows[UI_MARKER] = ui_marker_row(capture, hierarchy.value, user, self.markers.get(context.get('active_apk')),
                                        self.notice_package, hierarchy.positions,
                                        capture_offer['operation'] if capture_offer else None)
        rows[UNLOCK_AND_CE] = unlock_row(unlock, ui_now.value, inventory.value, user, serial, ce_read.value, origin,
                                         ui_now.positions + inventory.positions + ce_read.positions,
                                         unlock_offer['operation'] if unlock_offer else None)
        witness = None
        for bit, hook in self.hooks.items():
            if hook is None:
                rows[bit] = row(bit, 'UNKNOWN', HOOKS[bit])
                continue
            found = calls.read(lambda: hook.read(calls, context))
            if not found.ok:
                rows[bit] = row(bit, 'UNKNOWN', 'its reader gave no reading: %s' % found.why, found.positions)
            elif bit == NO_CRASH_OR_ANR:
                rows[bit], witness = found.value
            else:
                rows[bit] = found.value
        return {'user': user, 'serial': serial, 'rows': [rows[bit] for bit in range(CRITERIA)], 'witness': witness}
