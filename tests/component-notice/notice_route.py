# SPDX-License-Identifier: Apache-2.0
"""Host notice route of the next campaign profile: the broker's notice adapter for the full screen
fixture. It presents an issued notice through the fixed shell helper, and captures and reads one
recipient's display for an independent visibility group. Host evidence only: every guest form here
is source derived from the pinned tree and needs guest calibration.

`present(run, issue)` checks the helper jar's pinned SHA-256, runs the helper once for each required
recipient with the issue's exact fields, and checks the jar again. The helper's result carries the
activity's own decision, sent by the recipient's app before anything is shown. SUCCESS needs every
recipient's START_SUCCESS reply for the fixture activity and its presented decision; it says that
the fixture accepted the request, never that a user saw it. REFUSED needs every reply to be a
refusal: before any start, a failed start, or the activity's refusal, a conflicting row under the
request's key included, with nothing shown and nothing written. Anything else is UNRECOGNIZED.

`visibility(effect, read, issue, binding)` reads the current user, the global wakefulness and the
default display's focused window and focused app, writes a fresh hierarchy dump to a new unique
path, reads that whole file, and reads the three states again. The projection holds the current user
only when both reads agree, awake and focused only when both reads show it, the challenge of the one
challenge node of the fixture's window, and visible only when the active window is the fixture's and
that node lies on it with a nonempty area. A reported dump with no file, or a refused dump, is
unavailable; any other form is unclassified. The broker brackets the action with clock reads and
judges the projection.

Each call admits only the exact commands it is about to run: the allowlist is per family and per
call, so a presentation never runs a capture command and a capture never runs the helper."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
LAB = HERE.parent / 'component-lab'
if str(LAB) not in sys.path:
    sys.path.insert(0, str(LAB))

import lab_protocol  # noqa: E402
import lab_readers  # noqa: E402

PACKAGE = 'dev.andrix.lab.notice'
ACTIVITY_LONG = PACKAGE + '/' + PACKAGE + '.NoticeActivity'
ACTIVITY_SHORT = PACKAGE + '/.NoticeActivity'
DEVICE_DIR = '/data/local/tmp/andrix-notice'
JAR = DEVICE_DIR + '/andrix-notice-present.jar'
HELPER = 'dev.andrix.lab.notice.NoticePresent'
HELPER_HEADER = 'andrix-notice-present-v2'
DIGEST_COMMAND = 'sha256sum ' + JAR
CURRENT_USER = 'am get-current-user'
POWER = 'dumpsys power'
WINDOWS = 'dumpsys window displays'
HIERARCHY = DEVICE_DIR + '/hierarchy-%s.xml'
CHALLENGE_ID = PACKAGE + ':id/challenge'
NO_CHALLENGE = '00' * 16
MAX_TEXT = 1024
MAX_HIERARCHY = 4 << 20
TICKET_NOTICE, QUALIFICATION = 'TICKET_NOTICE', 'QUALIFICATION'
ID16 = re.compile(r'[0-9a-f]{32}')
COMPONENT = re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')
PINS = HERE / 'pins.json'
# Refusals the helper prints before any start, and start exceptions that refuse the call.
REFUSED_BEFORE_START = {2: 'arguments', 3: 'identity', 4: 'service-absent', 5: 'signature'}
REFUSING_EXCEPTIONS = ('java.lang.SecurityException', 'java.lang.IllegalArgumentException')
# Why the activity refuses a request, as NoticeRequest.REFUSALS names them.
ACTIVITY_REFUSALS = ('request', 'launcher', 'uid', 'user', 'serial', 'conflict', 'corrupt', 'store')
RESULT_FIELDS = ('result', 'timeout', 'who', 'total_time', 'launch_state', 'activity', 'reporter')
# The attributes of one node in the pinned dumper, AccessibilityNodeInfoDumper.dumpNodeRec. NAF is
# optional.
NODE_ATTRIBUTES = frozenset(('index', 'text', 'resource-id', 'class', 'package', 'content-desc', 'checkable',
                             'checked', 'clickable', 'enabled', 'focusable', 'focused', 'scrollable',
                             'long-clickable', 'password', 'selected', 'bounds', 'drawing-order', 'hint'))
BOUNDS = re.compile(r'\[(-?[0-9]{1,6}),(-?[0-9]{1,6})\]\[(-?[0-9]{1,6}),(-?[0-9]{1,6})\]')


def _strict_json(text):
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate key')
        return dict(items)
    return json.loads(text, object_pairs_hook=pairs)


def pinned_jar_digest():
    """The helper jar's pinned SHA-256, from pins.json."""
    return _strict_json(PINS.read_text(encoding='ascii'))['helper_jar']['sha256']


def _id(value):
    return isinstance(value, str) and ID16.fullmatch(value) is not None and value != NO_CHALLENGE


# ------------------------------------------------------------------ the presentation


def helper_arguments(issue, recipient):
    """The helper's 14 arguments for one recipient of an issue, the twin of
    NoticeRequest.arguments(). Raises lab_readers.Unclassified for an issue of no known form."""
    def refuse(why):
        raise lab_readers.Unclassified('an issue of no known form for the helper: %s' % why)
    purpose = issue.get('purpose')
    notice = purpose == TICKET_NOTICE
    if not notice and purpose != QUALIFICATION:
        refuse('purpose')
    for name in ('installation', 'boot', 'challenge'):
        if not _id(issue.get(name)):
            refuse(name)
    component = issue.get('component')
    if not isinstance(component, str) or len(component) > 255 or not COMPONENT.fullmatch(component):
        refuse('component')
    if notice:
        if not _id(issue.get('plan')) or not _id(issue.get('ticket')):
            refuse('plan or ticket')
        index = issue.get('index')
        if type(index) is not int or not 0 <= index < lab_protocol.MAX_LEDGER:
            refuse('index')
        plan, ticket, index_text, control = issue['plan'], issue['ticket'], str(index), '-'
    else:
        if not _id(issue.get('control')):
            refuse('control')
        plan, ticket, index_text, control = '-', '-', '-', issue['control']
    text = issue.get('text')
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_TEXT or any(not 0x20 <= ord(c) <= 0x7e for c in text):
        refuse('text')
    if issue.get('text_sha256') != hashlib.sha256(text.encode('ascii')).hexdigest():
        refuse('text digest')
    user, serial = recipient.get('user'), recipient.get('serial')
    if type(user) is not int or type(serial) is not int or not 0 <= user <= 21473 or not 0 <= serial <= 2 ** 31 - 1:
        refuse('recipient')
    return ['1', str(user), str(serial), purpose, issue['installation'], component, plan, ticket, index_text, control,
            issue['boot'], issue['challenge'], issue['text_sha256'], text.encode('ascii').hex()]


def helper_command(arguments):
    return 'CLASSPATH=%s app_process /system/bin %s %s' % (JAR, HELPER, ' '.join(arguments))


def _whole(result):
    if not getattr(result, 'completed', False) or getattr(result, 'overflow', None) is not None:
        raise lab_readers.Unavailable('a fixture command did not complete')
    return result.exit, bytes(result.stdout), bytes(result.stderr)


def jar_digest(result):
    """The jar's SHA-256 from one whole sha256sum reply, or Unclassified."""
    code, out, err = _whole(result)
    m = re.fullmatch(rb'([0-9a-f]{64})  ' + re.escape(JAR.encode()) + rb'\n', out)
    if code != 0 or err or m is None:
        raise lab_readers.Unclassified('a jar digest of no known form')
    return m[1].decode('ascii')


def classify_helper(result, user):
    """SUCCESS, REFUSED or UNRECOGNIZED for one whole helper reply to a recipient user. A decision
    counts only when an ordinary application UID of that user reported it."""
    code, out, err = _whole(result)
    try:
        text = out.decode('ascii')
    except UnicodeDecodeError:
        return 'UNRECOGNIZED'
    lines = text.split('\n')
    if err or not text.endswith('\n') or lines[0] != HELPER_HEADER:
        return 'UNRECOGNIZED'
    lines = lines[1:-1]
    if code in REFUSED_BEFORE_START and lines == ['error=' + REFUSED_BEFORE_START[code]]:
        return 'REFUSED'
    if code == 6 and len(lines) == 1 and lines[0].startswith('error=start:'):
        return 'REFUSED' if lines[0][len('error=start:'):] in REFUSING_EXCEPTIONS else 'UNRECOGNIZED'
    fields = [line.partition('=') for line in lines]
    if code not in (0, 7, 9, 10) or tuple(name for name, _, _ in fields) != RESULT_FIELDS:
        return 'UNRECOGNIZED'
    values = {name: value for name, _, value in fields}
    if not re.fullmatch(r'-?(0|[1-9][0-9]{0,9})', values['result']) \
            or not re.fullmatch(r'-?(0|[1-9][0-9]{0,18})', values['total_time']) \
            or not re.fullmatch(r'[0-4]', values['launch_state']) \
            or not re.fullmatch(r'-1|[1-9][0-9]{0,9}', values['reporter']):
        return 'UNRECOGNIZED'
    start, reporter, activity = int(values['result']), int(values['reporter']), values['activity']
    reported = reporter // 100000 == user and 10000 <= reporter % 100000 <= 19999
    if code == 7:
        unreported = activity == 'unreported' and reporter == -1
        return 'REFUSED' if start < 0 and unreported else 'UNRECOGNIZED'
    if start != 0 or not reported:
        return 'UNRECOGNIZED'
    if code == 0 and activity == 'presented' and values['timeout'] == 'false' and values['who'] == ACTIVITY_SHORT:
        return 'SUCCESS'
    if code == 9 and activity.startswith('refused:') and activity[len('refused:'):] in ACTIVITY_REFUSALS:
        return 'REFUSED'
    return 'UNRECOGNIZED'


# ------------------------------------------------------------------ the visibility capture


def current_user(result):
    code, out, err = _whole(result)
    m = re.fullmatch(rb'(0|[1-9][0-9]{0,4})\n', out)
    if code != 0 or err or m is None:
        raise lab_readers.Unclassified('a current user of no known form')
    return int(m[1])


def awake(result):
    """Whether the global wakefulness is Awake, from one whole `dumpsys power`."""
    code, out, err = _whole(result)
    text = _ascii(out, 'a power dump')
    lines = text.split('\n')
    states = [m[1] for m in (re.fullmatch(r'  mWakefulness=(Awake|Asleep|Dreaming|Dozing|-?[0-9]+)', line)
                             for line in lines) if m]
    if code != 0 or err or not lines or lines[0] != 'POWER MANAGER (dumpsys power)' or len(states) != 1:
        raise lab_readers.Unclassified('a power dump of no known form')
    return states[0] == 'Awake'


WINDOW = re.compile(r'Window\{[0-9a-f]+ u(0|[1-9][0-9]*) (\S+?)( EXITING)?\}')
RECORD = re.compile(r'ActivityRecord\{[0-9]+ u(0|[1-9][0-9]*) (\S+) t(-?[0-9]+)( f\})?( isExiting)?\}')
RECORD_FIRST = re.compile(r'ActivityRecord\{[0-9]+ u(0|[1-9][0-9]*) (\S+)')


def focus(result, user):
    """Whether the default display's focused window and focused app are the fixture's activity
    in this user, from one whole `dumpsys window displays`."""
    code, out, err = _whole(result)
    lines = _ascii(out, 'a window dump').split('\n')
    if code != 0 or err or lines[0] != 'WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)':
        raise lab_readers.Unclassified('a window dump of no known form')
    starts = [i for i, line in enumerate(lines) if re.fullmatch(r'  Display: mDisplayId=[0-9]+( \(organized\))?', line)]
    first = [i for i in starts if re.fullmatch(r'  Display: mDisplayId=0( \(organized\))?', lines[i])]
    if len(first) != 1:
        raise lab_readers.Unclassified('a window dump without one default display')
    later = [i for i in starts if i > first[0]]
    section = lines[first[0] + 1:later[0] if later else len(lines)]
    windows = [line[len('  mCurrentFocus='):] for line in section if line.startswith('  mCurrentFocus=')]
    apps = [line[len('  mFocusedApp='):] for line in section if line.startswith('  mFocusedApp=')]
    if len(windows) != 1 or len(apps) != 1:
        raise lab_readers.Unclassified('a default display without one focus line each')
    window, app = windows[0], apps[0]
    w = WINDOW.fullmatch(window)
    r = RECORD.fullmatch(app)
    if (window != 'null' and w is None) or (app != 'null' and r is None and RECORD_FIRST.fullmatch(app) is None):
        raise lab_readers.Unclassified('a focus line of no known form')
    window_ours = w is not None and int(w[1]) == user and w[2] == ACTIVITY_LONG and w[3] is None
    app_ours = r is not None and int(r[1]) == user and r[2] == ACTIVITY_SHORT and r[4] is None and r[5] is None
    return window_ours and app_ours


def dump_reply(result, path):
    """Checks one whole uiautomator dump reply: the success line naming the path, or a refusal."""
    code, out, err = _whole(result)
    if code == 0 and not err and out == ('UI hierchary dumped to: %s\n' % path).encode('ascii'):
        return
    if code == 0 and not out and err in (b'ERROR: null root node returned by UiTestAutomationBridge.\n',
                                         b'ERROR: could not get idle state.\n'):
        raise lab_readers.Unavailable('the hierarchy dump refused: %s' % err.decode('ascii').strip())
    raise lab_readers.Unclassified('a hierarchy dump reply of no known form')


def hierarchy_bytes(result, path):
    """The whole bytes of the fresh hierarchy file. A reported dump without its file is
    unavailable: never an older file's bytes."""
    code, out, err = _whole(result)
    if code == 1 and not out and err == ('cat: %s: No such file or directory\n' % path).encode('ascii'):
        raise lab_readers.Unavailable('no hierarchy file after a reported dump')
    if code != 0 or err or not out or len(out) > MAX_HIERARCHY:
        raise lab_readers.Unclassified('a hierarchy read of no known form')
    return out


def _bounds(text):
    m = BOUNDS.fullmatch(text or '')
    if m is None:
        raise lab_readers.Unclassified('node bounds of no known form')
    return tuple(int(v) for v in m.groups())


def hierarchy(data):
    """{'root_package', 'root_bounds', 'challenges'} from one whole dump, strictly: a hierarchy
    root with its rotation and exactly one node, and only nodes with the pinned dumper's attributes
    below it. 'challenges' are (text, bounds) of the fixture's challenge nodes."""
    if b'<!' in data:
        raise lab_readers.Unclassified('a hierarchy with a declaration, comment or section')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise lab_readers.Unclassified('a hierarchy that is not XML: %s' % error) from error
    if root.tag != 'hierarchy' or set(root.attrib) != {'rotation'} or root.attrib['rotation'] not in '0123' \
            or len(root.attrib['rotation']) != 1 or len(root) != 1 or (root.text or '').strip():
        raise lab_readers.Unclassified('a hierarchy root of no known form')
    challenges = []
    for node in root.iter():
        if node is root:
            continue
        names = set(node.attrib)
        if node.tag != 'node' or names - {'NAF'} != NODE_ATTRIBUTES or (node.text or '').strip() \
                or (node.tail or '').strip():
            raise lab_readers.Unclassified('a hierarchy node of no known form')
        bounds = _bounds(node.attrib['bounds'])
        if node.attrib['resource-id'] == CHALLENGE_ID and node.attrib['package'] == PACKAGE:
            challenges.append((node.attrib['text'], bounds))
    top = root[0]
    return {'root_package': top.attrib['package'], 'root_bounds': _bounds(top.attrib['bounds']),
            'challenges': challenges}


def _ascii(data, what):
    try:
        return data.decode('ascii')
    except UnicodeDecodeError as error:
        raise lab_readers.Unclassified('%s that is not ASCII' % what) from error


def project(user, serial, before, after, tree):
    """The broker's visibility projection from the reads before and after the dump and the
    parsed hierarchy. `before` and `after` are (current user, awake, focused)."""
    current = before[0] if before[0] == after[0] else -1
    challenge, visible = NO_CHALLENGE, False
    if len(tree['challenges']) == 1:
        text, (left, top, right, bottom) = tree['challenges'][0]
        if ID16.fullmatch(text) and text != NO_CHALLENGE:
            challenge = text
            rl, rt, rr, rb = tree['root_bounds']
            visible = (tree['root_package'] == PACKAGE and right > left and bottom > top and left >= rl and top >= rt
                       and right <= rr and bottom <= rb)
    return {'user': user, 'serial': serial, 'current_user': current, 'awake': before[1] and after[1],
            'focused': before[2] and after[2], 'challenge': challenge, 'visible': visible}


class NoticeRoute:
    """The broker's notice adapter for the full screen fixture under the next profile."""

    def __init__(self, jar_sha256=None, nonce=None):
        self.jar_sha256 = jar_sha256 or pinned_jar_digest()
        self._nonce = nonce or (lambda: os.urandom(16).hex())
        self._expected = frozenset()

    def allowed(self, command):
        return command in self._expected

    @contextlib.contextmanager
    def _family(self, commands):
        self._expected = frozenset(commands)
        try:
            yield
        finally:
            self._expected = frozenset()

    def notice(self, run, ticket, index, plan):
        raise lab_readers.Unclassified('the full screen route serves only the next profile')

    def present(self, run, issue):
        """Presents an issue to each required recipient through the helper."""
        required = issue.get('required')
        if not isinstance(required, list) or not required:
            raise lab_readers.Unclassified('an issue without recipients')
        commands = [(helper_command(helper_arguments(issue, r)), r['user']) for r in required]
        with self._family([DIGEST_COMMAND, *(command for command, _ in commands)]):
            if jar_digest(run(DIGEST_COMMAND)) != self.jar_sha256:
                return 'REFUSED'
            outcomes = [classify_helper(run(command), user) for command, user in commands]
            if jar_digest(run(DIGEST_COMMAND)) != self.jar_sha256:
                return 'UNRECOGNIZED'
        if all(o == 'SUCCESS' for o in outcomes):
            return 'SUCCESS'
        if all(o == 'REFUSED' for o in outcomes):
            return 'REFUSED'
        return 'UNRECOGNIZED'

    def visibility(self, effect, read, issue, binding):
        """One recipient's visibility capture and read: the projection the broker judges."""
        user, serial = binding['id'], binding['serial']
        path = HIERARCHY % self._nonce()
        dump, cat = 'uiautomator dump ' + path, 'cat ' + path
        with self._family([CURRENT_USER, POWER, WINDOWS, dump, cat]):
            before = (current_user(read(CURRENT_USER)), awake(read(POWER)), focus(read(WINDOWS), user))
            dump_reply(effect(dump), path)
            tree = hierarchy(hierarchy_bytes(read(cat), path))
            after = (current_user(read(CURRENT_USER)), awake(read(POWER)), focus(read(WINDOWS), user))
        return project(user, serial, before, after, tree)
