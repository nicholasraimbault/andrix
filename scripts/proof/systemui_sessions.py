# SPDX-License-Identifier: Apache-2.0
"""Pinned shell-output parsing only, not package authority or activation evidence."""
from dataclasses import dataclass
import re

PACKAGE = 'com.android.systemui'
READY = 'Success. Reboot device to apply staged session'


def created_session(code, output):
    match = re.fullmatch(r'Success: created install session \[([0-9]+)\]\s*', output)
    if code != 0 or not match or not 0 < int(match[1]) <= 0x7fffffff:
        raise ValueError('No exact acknowledged install session identity')
    return int(match[1])


def commit_observation(code, output):
    text = output.strip()
    if code == 0 and text == READY:
        return 'ready'
    if code == 0 and text == 'Success':
        return 'accepted_without_readiness'
    if code == 1 and re.fullmatch(
            r"Failure \[timed out after [0-9]+ ms\]\. Ending this command now but session is still being staged asynchronously\. Use 'pm list staged-sessions' to check the session status later\.", text):
        return 'pending_after_timeout'
    # Neither a failed command nor malformed output is a proof that no session
    # committed. Its issued identity remains owned for explicit reconciliation.
    return 'unknown'


@dataclass(frozen=True)
class StagedSession:
    identity: int
    package: str | None
    staged: bool
    ready: bool
    applied: bool
    failed: bool
    error: str


ROW = re.compile(
    r'sessionId = ([0-9]+); appPackageName = ([A-Za-z0-9_.]+); '
    r'isStaged = (true|false); isReady = (true|false); '
    r'isApplied = (true|false); isFailed = (true|false); errorMsg = (.*?);'
    r'(?=\s*sessionId = |$)')


def parent_sessions(code, output):
    if code != 1 or len(output) > 65536:
        raise ValueError('Unexpected staged-session listing result')
    # --only-parent has zero indentation. The pinned writer hard-wraps at120,
    # potentially in a token. Join physical lines, not whitespace inside values.
    # Embedded newlines/errors cannot grant authority; callers retain raw output.
    text = output.replace('\r\n', '\n').replace('\n', '').strip()
    rows = []
    ids = set()
    while text:
        match = ROW.match(text)
        if not match:
            raise ValueError('Malformed or unsupported parent-session listing')
        identity = int(match[1])
        if not 0 < identity <= 0x7fffffff or identity in ids:
            raise ValueError('Invalid or duplicate session identity')
        flags = [match[n] == 'true' for n in range(3, 7)]
        if sum(flags[1:]) > 1:
            raise ValueError('Contradictory terminal/readiness state')
        package = None if match[2] == 'null' else match[2]
        rows.append(StagedSession(identity, package, *flags, match[7]))
        ids.add(identity)
        text = text[match.end():].lstrip()
    return rows


def require_state(rows, identity, state, package=PACKAGE):
    if state not in ['ready', 'applied', 'failed']:
        raise ValueError('Unsupported expected state')
    found = [r for r in rows if r.identity == identity]
    if len(found) != 1 or found[0].package != package or not found[0].staged:
        raise ValueError('Exact package/session association not observed')
    row = found[0]
    if not getattr(row, state):
        raise ValueError('Requested session state not observed')
    return row


@dataclass(frozen=True)
class HistoricalFailure:
    identity: int
    installer_uid: int
    user: int
    package: str
    status: int
    message: str


def historical_failure(code, output, identity, package=PACKAGE):
    """Inspect an exact removed session, not absence from the live session list.

    Pinned `dumpsys package installs` supplies these volatile historical records.
    This is not durable receipt recovery. Ambiguous/truncated formats are refused.
    """
    if code != 0 or len(output) > 4 * 1024 * 1024:
        raise ValueError('Historical session dump unavailable')
    if output.count('Historical install sessions:') != 1:
        raise ValueError('No unique historical session section')
    section = output.split('Historical install sessions:', 1)[1]
    if section.count('Legacy install sessions:') != 1:
        raise ValueError('Historical session dump truncated or ambiguous')
    section = section.split('Legacy install sessions:', 1)[0]
    headers = list(re.finditer(r'(?m)^\s*Session ([0-9]+):[ \t]*$', section))
    matches = [i for i, header in enumerate(headers) if int(header[1]) == identity]
    if len(matches) != 1:
        raise ValueError('Exact historical session not found uniquely')
    i = matches[0]
    raw = section[headers[i].end():headers[i+1].start() if i+1 < len(headers) else len(section)]
    # The dump uses indentation and hard wrapping, possibly inside a field name.
    # Keep the original command output separately; this is the parsing view only.
    text = ''.join(line.lstrip() for line in raw.splitlines())

    def scalar(name, expression):
        values = re.findall(r'(?<![A-Za-z0-9_])'+re.escape(name)+r'=('+expression+r')(?=\s|$)', text)
        if len(values) != 1:
            raise ValueError('Historical field missing or ambiguous: '+name)
        return values[0]

    user = int(scalar('userId', r'[0-9]+'))
    installer = int(scalar('mInstallerUid', r'[0-9]+'))
    original = int(scalar('mOriginalInstallerUid', r'[0-9]+'))
    target = scalar('mAppPackageName', r'[A-Za-z0-9_.]+')
    status = int(scalar('mFinalStatus', r'-?[0-9]+'))
    applied = scalar('mSessionApplied', r'true|false')
    ready = scalar('mSessionReady', r'true|false')
    if (user != 0 or installer != 2000 or original != 2000 or target != package
            or status >= 0 or applied != 'false' or ready != 'false'):
        raise ValueError('Historical record is not this shell/user/package rejection')
    messages = re.findall(r'(?<![A-Za-z0-9_])mFinalMessage=(.*?)\s+mParentSessionId=', text)
    if len(messages) != 1 or not messages[0] or messages[0] == 'null':
        raise ValueError('No unambiguous terminal failure cause')
    return HistoricalFailure(identity, installer, user, target, status, messages[0])


def intended_rejection(label, message):
    """Match the cause, not generic status names such as BAD_SIGNATURE."""
    if label == 'nonstaged':
        return 'Persistent apps are not updateable.' in message
    if label == 'wrong-signer':
        return ('New package has a different signature: '+PACKAGE in message
                or 'Existing package '+PACKAGE+' signatures do not match newer version; ignoring!' in message
                or 'System package update '+PACKAGE+" signature doesn't match the signature of system image package" in message)
    if label == 'missing-sidecar':
        return ('fs-verity not set up for system package update' in message
                and "APK doesn't have fs-verity:" in message
                and 'Permission denied' not in message)
    if label == 'mismatched-sidecar':
        return ('Actual digest does not match the v4 signature' in message
                and 'Permission denied' not in message)
    raise ValueError('Unknown negative control')


# ---------------------------------------------------------------- exact readbacks
#
# The parsers below accept only exact forms. The staged listing and install dump parsers rebuild
# the writer's calls from the fields they read and render them again through a model of
# android.util.IndentingPrintWriter, so a truncated, reordered, extended or rewrapped output is
# refused rather than repaired. The other parsers match whole line forms. A refusal raises
# ValueError. Callers keep the raw capture, and an output that matches no known form gives no fact.

READBACK_LIMIT = 4 * 1024 * 1024
NONCE_SCHEME = 'andrix-ticket:'
FACTORY_PATH = '/system_ext/priv-app/SystemUI/SystemUI.apk'
_PACKAGE_NAME = r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+'
_INT = re.compile(r'-?[0-9]{1,19}')


class IndentingWriter:
    """android.util.IndentingPrintWriter at the pinned revision: one write per print call."""

    def __init__(self, single='  ', wrap=120):
        self.single, self.wrap = single, wrap
        self.indent, self.length, self.empty, self.out = '', 0, True, []

    def increase(self):
        self.indent += self.single

    def decrease(self):
        self.indent = self.indent[len(self.single):]

    def _maybe_indent(self):
        if self.empty:
            self.empty = False
            self.out.append(self.indent)

    def write(self, text):
        indent = len(self.indent)
        start = end = 0
        while end < len(text):
            char = text[end]
            end += 1
            self.length += 1
            if char == '\n':
                self._maybe_indent()
                self.out.append(text[start:end])
                start, self.empty, self.length = end, True, 0
            if self.wrap > 0 and self.length >= self.wrap - indent:
                if not self.empty:
                    self.out.append('\n')
                    self.empty, self.length = True, end - start
                else:
                    self._maybe_indent()
                    self.out.append(text[start:end] + '\n')
                    start, self.empty, self.length = end, True, 0
        if start != end:
            self._maybe_indent()
            self.out.append(text[start:end])

    def println(self, text=''):
        if text:
            self.write(text)
        self.write('\n')

    def pair(self, key, value):
        self.write(key + '=' + value + ' ')

    def text(self):
        return ''.join(self.out)


def _logical(segment, indent):
    """Physical lines of one indented record joined, without the writer's indent and wraps."""
    lines = segment.split('\n')
    if lines[-1] != '':
        raise ValueError('Record does not end its line')
    joined = []
    for line in lines[:-1]:
        if not line.startswith(indent):
            raise ValueError('Record line outside its indentation')
        joined.append(line[len(indent):])
    return ''.join(joined)


def _bounded(code, output, expected_code, limit=READBACK_LIMIT):
    if code != expected_code or not isinstance(output, str) or len(output) > limit:
        raise ValueError('Unexpected command result')
    if '\r' in output or '\x00' in output:
        raise ValueError('Unexpected control characters')


def _id(text):
    value = int(text)
    if not 0 < value <= 0x7fffffff or text != str(value):
        raise ValueError('Invalid session identity')
    return value


def _boolean(text):
    if text not in ('true', 'false'):
        raise ValueError('Unexpected boolean')
    return text == 'true'


def _number(text, low=-(1 << 63), high=(1 << 63) - 1):
    if not _INT.fullmatch(text) or str(int(text)) != text or not low <= int(text) <= high:
        raise ValueError('Unexpected number')
    return int(text)


# ------------------------------------------------ pm list staged-sessions

@dataclass(frozen=True)
class ListedSession:
    identity: int
    package: str | None
    ready: bool
    applied: bool
    failed: bool
    error: str
    child: bool
    found: bool


@dataclass(frozen=True)
class StagedListing:
    sessions: tuple
    complete: bool

    def for_package(self, package=PACKAGE):
        return tuple(s for s in self.sessions if s.package == package)


LISTED = re.compile(
    r'sessionId = ([0-9]+); appPackageName = (null|' + _PACKAGE_NAME + r'); isStaged = (true|false); '
    r'isReady = (true|false); isApplied = (true|false); isFailed = (true|false); errorMsg = (.*);', re.S)
MISSING_CHILD = re.compile(r'sessionId = ([0-9]+); not found')


def _listed_row(logical, child):
    match = LISTED.fullmatch(logical)
    if match:
        if match[3] != 'true':
            raise ValueError('A staged listing row that is not staged')
        flags = [match[n] == 'true' for n in (4, 5, 6)]
        if sum(flags) > 1:
            raise ValueError('Contradictory terminal or readiness state')
        package = None if match[2] == 'null' else match[2]
        return ListedSession(_id(match[1]), package, *flags, match[7], child, True)
    match = MISSING_CHILD.fullmatch(logical)
    if match and child:
        return ListedSession(_id(match[1]), None, False, False, False, '', True, False)
    raise ValueError('Malformed or unsupported staged listing row')


def staged_listing(code, output, only_parent):
    """`pm list staged-sessions`, plain or with --only-parent, exactly as the pinned shell prints it.

    The plain listing prints each multiple package parent's children indented below it, and is
    the complete listing. With --only-parent the children are hidden, so it is complete only
    when no listed session is a parent, which this form cannot show. Android prints success
    with exit status 1.
    """
    _bounded(code, output, 1, 1 << 20)
    rows, seen, position, parent = [], set(), 0, False
    while position < len(output):
        found = []
        for child in ((False, True) if parent and not only_parent else (False,)):
            indent = '  ' if child else ''
            end = output.find('\n', position)
            while end != -1 and end - position <= 8192:
                segment = output[position:end + 1]
                try:
                    logical = _logical(segment, indent)
                    row = _listed_row(logical, child)
                except ValueError:
                    row = None
                if row is not None:
                    writer = IndentingWriter()
                    writer.indent = indent
                    writer.println(logical)
                    if writer.text() == segment:
                        found.append((row, end + 1))
                end = output.find('\n', end + 1)
        if len(found) != 1:
            raise ValueError('Staged listing does not parse uniquely')
        row, position = found[0]
        if row.identity in seen:
            raise ValueError('Duplicate session identity')
        seen.add(row.identity)
        rows.append(row)
        parent = True
    return StagedListing(tuple(rows), complete=not only_parent)


# ------------------------------------------------ dumpsys package installs

HEADER_KEYS = ('userId', 'mOriginalInstallerUid', 'mOriginalInstallerPackageName', 'installerPackageName',
               'installInitiatingPackageName', 'installOriginatingPackageName', 'mInstallerUid',
               'createdMillis', 'updatedMillis', 'committedMillis', 'stageDir', 'stageCid')
PARAMS_KEYS = ('mode', 'installFlags', 'installLocation', 'installReason', 'installScenario', 'sizeBytes',
               'appPackageName', 'appIcon', 'appLabel', 'originatingUri', 'originatingUid', 'referrerUri',
               'abiOverride', 'volumeUuid', 'mPermissionStates', 'packageSource',
               'whitelistedRestrictedPermissions', 'autoRevokePermissions', 'installerPackageName',
               'isMultiPackage', 'isStaged', 'forceQueryable', 'requireUserAction',
               'requiredInstalledVersionCode', 'dataLoaderParams', 'rollbackDataPolicy',
               'rollbackLifetimeMillis', 'rollbackImpactLevel', 'applicationEnabledSettingPersistent',
               'developmentInstallFlags', 'unarchiveId', 'dexoptCompilerFilter', 'forceVerification',
               'isAutoInstallDependenciesEnabled', 'extensionParams')
_STATE_HEAD = ('mClientProgress', 'mProgress', 'mCommitted', 'mPreapprovalRequested', 'mSealed',
               'mPermissionsManuallyAccepted', 'mStageDirInUse', 'mDestroyed', 'mFds', 'mBridges',
               'mFinalStatus', 'mFinalMessage')
_STATE_FLAGS = ('mParentSessionId', 'mChildSessionIds', 'mSessionApplied', 'mSessionFailed', 'mSessionReady',
                'mSessionErrorCode', 'mSessionErrorMessage', 'mPreapprovalDetails')
_POLICIES = ('mInitialVerificationPolicy', 'mCurrentVerificationPolicy')
# PackageInstallerSession.dumpLocked prints mPreVerifiedDomains only when it is set.
LIVE_KEYS = _STATE_HEAD + ('params.isMultiPackage', 'params.isStaged') + _STATE_FLAGS + _POLICIES
LIVE_KEYS_DOMAINS = _STATE_HEAD + ('params.isMultiPackage', 'params.isStaged') + _STATE_FLAGS + (
    'mPreVerifiedDomains',) + _POLICIES
HISTORICAL_KEYS = _STATE_HEAD + _STATE_FLAGS + ('mPreVerifiedDomains', 'mAppPackageName') + _POLICIES
SECTIONS = ('Active', 'Finalized', 'Historical')


@dataclass(frozen=True)
class DumpedSession:
    section: str
    identity: int
    user: int
    installer_uid: int
    original_installer_uid: int
    created_millis: int
    updated_millis: int
    committed_millis: int
    stage_dir: str | None
    package: str | None
    referrer: str | None
    staged: bool
    multi_package: bool
    committed: bool
    sealed: bool
    destroyed: bool
    final_status: int
    final_message: str | None
    parent: int
    children: tuple
    applied: bool
    failed: bool
    ready: bool
    error_code: int
    error_message: str


@dataclass(frozen=True)
class InstallsDump:
    sessions: tuple
    skipped: tuple = ()

    def section(self, name):
        return tuple(s for s in self.sessions if s.section == name)


_FIELD_INSIDE = re.compile(r' [A-Za-z_$][A-Za-z0-9_$.]*=')


def _pairs(logical, keys):
    """Split `key=value ` pairs in their pinned order. A key that occurs more often than the order
    allows, as inside a free text value, makes the split ambiguous and refuses the record."""
    text = ' ' + logical
    for key in set(keys):
        if text.count(' ' + key + '=') != keys.count(key):
            raise ValueError('Field missing, repeated or ambiguous')
    if not logical.endswith(' '):
        raise ValueError('Record does not end its last field')
    values, position = [], 0
    for index, key in enumerate(keys):
        if not logical.startswith(key + '=', position):
            raise ValueError('Field out of its pinned order')
        start = position + len(key) + 1
        if index + 1 < len(keys):
            end = logical.find(' ' + keys[index + 1] + '=', start)
            if end < 0:
                raise ValueError('Field missing')
        else:
            end = len(logical) - 1
        values.append(logical[start:end])
        position = end + 1
    if position != len(logical):
        raise ValueError('Trailing text after the last field')
    # A pair the order does not know would hide inside the value before it, because the writer
    # prints both alike. No value of a known form holds a space followed by a field name and '='.
    for value in values:
        if _FIELD_INSIDE.search(value):
            raise ValueError('A value holds another field')
    return values


def _nullable(text):
    return None if text == 'null' else text


def _session(section, identity, logical):
    historical = section == 'Historical'
    if historical:
        options = (HISTORICAL_KEYS,)
    else:
        options = (LIVE_KEYS, LIVE_KEYS_DOMAINS)
    parsed = []
    for state_keys in options:
        try:
            parsed.append((state_keys, _pairs(logical, HEADER_KEYS + PARAMS_KEYS + state_keys)))
        except ValueError:
            continue
    if len(parsed) != 1:
        raise ValueError('Session record of no known form')
    state_keys, values = parsed[0]
    header = dict(zip(HEADER_KEYS, values[:len(HEADER_KEYS)]))
    params = dict(zip(PARAMS_KEYS, values[len(HEADER_KEYS):len(HEADER_KEYS) + len(PARAMS_KEYS)]))
    state = dict(zip(state_keys, values[len(HEADER_KEYS) + len(PARAMS_KEYS):]))
    package = _nullable(params['appPackageName'])
    if package is not None and not re.fullmatch(_PACKAGE_NAME, package):
        raise ValueError('Unexpected package name')
    if historical and state['mAppPackageName'] != params['appPackageName']:
        raise ValueError('Historical package differs from its parameters')
    if not historical and (state['params.isStaged'] != params['isStaged']
                           or state['params.isMultiPackage'] != params['isMultiPackage']):
        raise ValueError('Session parameters disagree')
    if not re.fullmatch(r'0x[0-9a-f]{1,8}', params['installFlags']):
        raise ValueError('Unexpected install flags')
    stage = _nullable(header['stageDir'])
    if stage is not None and not re.fullmatch(r'/data/[A-Za-z0-9_.~/=+-]+', stage):
        raise ValueError('Unexpected stage directory')
    children = state['mChildSessionIds']
    if not re.fullmatch(r'\[(?:[0-9]+(?:, [0-9]+)*)?\]', children):
        raise ValueError('Unexpected child sessions')
    child_ids = tuple(_id(c) for c in children[1:-1].split(', ') if c)
    for key in ('mClientProgress', 'mProgress'):
        if not re.fullmatch(r'-?[0-9]+\.[0-9]+(?:E-?[0-9]+)?|NaN|-?Infinity', state[key]):
            raise ValueError('Unexpected progress')
    for key in ('mPreapprovalRequested', 'mPermissionsManuallyAccepted', 'mStageDirInUse', 'appIcon',
                'forceQueryable', 'applicationEnabledSettingPersistent', 'forceVerification',
                'isAutoInstallDependenciesEnabled'):
        _boolean(state[key] if key in state else params[key])
    for key in ('mode', 'installLocation', 'installReason', 'installScenario', 'sizeBytes', 'originatingUid',
                'packageSource', 'autoRevokePermissions', 'requiredInstalledVersionCode', 'rollbackDataPolicy',
                'rollbackLifetimeMillis', 'rollbackImpactLevel', 'unarchiveId'):
        _number(params[key])
    for key in ('mFds', 'mBridges') + _POLICIES:
        _number(state[key], 0, 0x7fffffff)
    message = state['mFinalMessage']
    session = DumpedSession(
        section=section, identity=identity,
        user=_number(header['userId'], 0, 0x7fffffff),
        installer_uid=_number(header['mInstallerUid'], -1, 0x7fffffff),
        original_installer_uid=_number(header['mOriginalInstallerUid'], -1, 0x7fffffff),
        created_millis=_number(header['createdMillis'], 0),
        updated_millis=_number(header['updatedMillis'], 0),
        committed_millis=_number(header['committedMillis'], 0),
        stage_dir=stage, package=package, referrer=_nullable(params['referrerUri']),
        staged=_boolean(params['isStaged']), multi_package=_boolean(params['isMultiPackage']),
        committed=_boolean(state['mCommitted']), sealed=_boolean(state['mSealed']),
        destroyed=_boolean(state['mDestroyed']),
        final_status=_number(state['mFinalStatus'], -(1 << 31), (1 << 31) - 1),
        final_message=None if message == 'null' else message,
        parent=_number(state['mParentSessionId'], -1, 0x7fffffff), children=child_ids,
        applied=_boolean(state['mSessionApplied']), failed=_boolean(state['mSessionFailed']),
        ready=_boolean(state['mSessionReady']),
        error_code=_number(state['mSessionErrorCode'], -(1 << 31), (1 << 31) - 1),
        error_message=state['mSessionErrorMessage'])
    if sum([session.applied, session.failed, session.ready]) > 1:
        raise ValueError('Contradictory terminal or readiness state')
    return session, values, state_keys


def _render_session(writer, section, identity, values, state_keys, child=False):
    """PackageInstallerSession.dumpLocked, or PackageInstallerHistoricalSession.dump."""
    if section != 'Historical':
        writer.write(section + (' Child ' if child else ' '))
    writer.println('Session %d:' % identity)
    writer.increase()
    header = len(HEADER_KEYS)
    params = header + len(PARAMS_KEYS)
    for key, value in zip(HEADER_KEYS, values[:header]):
        writer.pair(key, value)
    writer.println()
    if section == 'Historical':
        # The historical session keeps its parameters as one string, printed with one call.
        writer.write(''.join(k + '=' + v + ' ' for k, v in zip(PARAMS_KEYS, values[header:params])) + '\n')
    else:
        for key, value in zip(PARAMS_KEYS, values[header:params]):
            writer.pair(key, value)
        writer.println()
    for key, value in zip(state_keys, values[params:]):
        writer.pair(key, value)
    writer.println()
    writer.decrease()


_HEADER = re.compile(r'  (?:(Active|Finalized) )?Session ([0-9]+):')
_CHILD = re.compile(r'    (Active|Finalized) Child Session ([0-9]+):')
_PREFIX_KEYS = HEADER_KEYS + PARAMS_KEYS[:PARAMS_KEYS.index('appPackageName') + 1]
_OPTIONAL_PACKAGE = r'null|' + _PACKAGE_NAME
# The forms of the prefix fields that are not numbers.
_PREFIX_FORMS = {'mOriginalInstallerPackageName': _OPTIONAL_PACKAGE, 'installerPackageName': _OPTIONAL_PACKAGE,
                 'installInitiatingPackageName': _OPTIONAL_PACKAGE, 'installOriginatingPackageName': _OPTIONAL_PACKAGE,
                 'stageDir': r'null|/[A-Za-z0-9_.~/=+-]+', 'stageCid': r'null|[A-Za-z0-9_.:-]+',
                 'installFlags': r'0x[0-9a-f]{1,8}', 'appPackageName': _OPTIONAL_PACKAGE}


# How often the pinned layout prints each prefix key in one record: installerPackageName twice, in
# the header and in the parameters, and every other key once.
_PREFIX_COUNTS = {key: (HEADER_KEYS + PARAMS_KEYS).count(key) for key in _PREFIX_KEYS}


def prefix_package(logical):
    """The package that a record names before its first free text field, or None.

    Every field up to appPackageName is a number, a package name, a path or null, so none holds a
    space, and text inside a later value cannot change this answer. The installer is the exception:
    the shell's -i option can set it to free text that prints a whole prefix of its own, naming
    another package. Such text repeats the prefix keys, so the prefix counts only when each of its
    keys occurs as often as the pinned layout prints it. None means that the prefix has no known
    form or names no package."""
    tokens = logical.split(' ')
    if len(tokens) <= len(_PREFIX_KEYS):
        return None
    for key, count in _PREFIX_COUNTS.items():
        if sum(token.startswith(key + '=') for token in tokens) != count:
            return None
    for key, token in zip(_PREFIX_KEYS, tokens):
        if not token.startswith(key + '=') or not re.fullmatch(_PREFIX_FORMS.get(key, r'-?[0-9]{1,19}'),
                                                                token[len(key) + 1:]):
            return None
    value = tokens[len(_PREFIX_KEYS) - 1][len('appPackageName='):]
    return value if re.fullmatch(_PACKAGE_NAME, value) else None


@dataclass(frozen=True)
class _Record:
    """One record as the section printed it: parsed exactly, or only its prefix's package."""
    identity: int
    child: bool
    session: DumpedSession | None
    package: str | None


def _record(name, identity, child, lines):
    indent = '      ' if child else '    '
    logical = _logical('\n'.join(lines[1:]) + '\n', indent)
    try:
        session, values, state_keys = _session(name, identity, logical)
        writer = IndentingWriter()
        writer.indent = indent[2:]
        _render_session(writer, name, identity, values, state_keys, child)
        if writer.text() != '\n'.join(lines) + '\n':
            raise ValueError('Record differs from the pinned form')
    except ValueError:
        return _Record(identity, child, None, prefix_package(logical))
    return _Record(identity, child, session, session.package)


def _section(raw, name):
    """One section of PackageInstallerService.dump as families: a record and, in the active and
    finalized sections, the child records of a multiple package parent. The skeleton is exact.
    A record that fails the exact parse keeps only the package of its prefix."""
    title = name + ' install sessions:\n'
    lines = raw[len(title):].split('\n')
    if not raw.startswith(title) or lines[-2:] != ['  ', '']:
        raise ValueError('Section title or end missing')
    lines, families, index = lines[:-2], [], 0
    while index < len(lines):
        header = _HEADER.fullmatch(lines[index])
        if header is None or (header[1] or 'Historical') != name:
            raise ValueError('Session header missing or of another section')
        start, index = index, index + 1
        while index < len(lines) and lines[index].startswith('    '):
            index += 1
        if index == start + 1 or index == len(lines) or lines[index] != '  ':
            raise ValueError('Session record not closed')
        family = [_record(name, _id(header[2]), False, lines[start:index])]
        index += 1
        while name != 'Historical' and index < len(lines) and _CHILD.fullmatch(lines[index]):
            child = _CHILD.fullmatch(lines[index])
            if child[1] != name:
                raise ValueError('Child header of another section')
            start, index = index, index + 1
            while index < len(lines) and lines[index].startswith('      '):
                index += 1
            if index == start + 1 or index == len(lines) or lines[index] != '    ':
                raise ValueError('Child record not closed')
            family.append(_record(name, _id(child[2]), True, lines[start:index]))
            index += 1
        families.append(family)
    return families


_TAIL = re.compile(
    r'(?P<silent>Last silent updated Infos:\n(?:  installerPackageName=\S+ packageName=\S+ '
    r'silentUpdatedMillis=[0-9]+ \n)*)?'
    r'Gentle update with constraints info:\n  hasPendingIdleJob=(?:true|false) \n'
    r'  Num of PendingIdleFutures=[0-9]+ \n  Num of PendingChecks=0 \n'
    r'    VerificationPolicyPerUser=\{(?:-?[0-9]+=-?[0-9]+(?:, -?[0-9]+=-?[0-9]+)*)?\} ')


def _foreign(package):
    """Certainly about another package than SystemUI."""
    return package is not None and package != PACKAGE


def installs_dump(code, output, package=PACKAGE):
    """`dumpsys package installs`: the active, finalized and historical sections, exactly.

    `sessions` holds every single package session that parsed exactly, of any package. A record
    or a multiple package family that is certainly about another package than `package` gives no
    session and blocks nothing, and is listed in `skipped`. Anything that could concern
    `package` and has no known form refuses the whole dump: a record of it or of no known package,
    and a family with a child of it or of no known package. So do the orphaned section, legacy
    sessions, pending install constraint checks, and output whose sections are missing,
    repeated, reordered, truncated or rewrapped.
    """
    if package != PACKAGE:
        raise ValueError('Only SystemUI has known forms')
    _bounded(code, output, 0)
    titles = [m.start() for m in re.finditer(r'(?m)^[A-Z][A-Za-z ]* install sessions:$', output)]
    names = [output[t:output.index(' install sessions:', t)] for t in titles]
    if names != ['Active', 'Finalized', 'Historical', 'Legacy'] or titles[0] != 0:
        raise ValueError('Install sections missing, repeated or reordered')
    legacy = output[titles[3]:]
    if not legacy.startswith('Legacy install sessions:\n  {}\n  \n'):
        raise ValueError('Legacy sessions of no known form')
    tail = legacy[len('Legacy install sessions:\n  {}\n  \n'):]
    # The silent update records are source derived. A record long enough to wrap has no known form.
    if not _TAIL.fullmatch(tail):
        raise ValueError('Dump tail of no known form, or truncated')
    sessions, skipped, live = [], [], []
    for n, name in enumerate(SECTIONS):
        families = _section(output[titles[n]:titles[n + 1]], name)
        if name == 'Historical':
            members = [family[0] for family in families]
            packages = {}
            for record in members:
                packages.setdefault(record.identity, []).append(record.package)
            for record in members:
                session = record.session
                if session is None:
                    if not _foreign(record.package):
                        raise ValueError('A removed record that could concern the package has no known form')
                    skipped.append((name, record.identity, record.package))
                elif not (session.multi_package or session.children or session.parent != -1):
                    sessions.append(session)
                elif _foreign(session.package) or (
                        session.package is None and session.parent == -1 and session.children and all(
                            len(packages.get(c, [])) == 1 and _foreign(packages[c][0]) for c in session.children)):
                    skipped.append((name, record.identity, session.package))
                else:
                    raise ValueError('A removed multiple package session that could concern the package')
            continue
        for family in families:
            live += [record.identity for record in family]
            parent, children = family[0], family[1:]
            single = not children and parent.session is not None and not (
                parent.session.multi_package or parent.session.children or parent.session.parent != -1)
            if single:
                sessions.append(parent.session)
            elif not children and _foreign(parent.package) and (
                    parent.session is None or not parent.session.multi_package):
                skipped.append((name, parent.identity, parent.package))
            elif children and parent.package != PACKAGE and all(_foreign(c.package) for c in children) and (
                    parent.session is None or (parent.session.multi_package and sorted(parent.session.children)
                                               == sorted(c.identity for c in children))):
                skipped += [(name, record.identity, record.package) for record in family]
            else:
                raise ValueError('A session that could concern the package has no known form')
    if len(live) != len(set(live)):
        raise ValueError('A live session listed twice')
    return InstallsDump(tuple(sessions), tuple(skipped))


# ------------------------------------------------ the ticket nonce in the referrer

def nonce_referrer(nonce):
    """The referrer a ticket passes to `pm install-create --referrer`. Uri.parse keeps it verbatim."""
    if not re.fullmatch(r'[0-9a-f]{32}', nonce) or nonce == '0' * 32:
        raise ValueError('Not a ticket nonce')
    return NONCE_SCHEME + nonce


def referrer_nonce(referrer):
    """The nonce of a session's referrer, None when it has no referrer or another one."""
    if referrer is None or not referrer.startswith(NONCE_SCHEME):
        return None
    nonce = referrer[len(NONCE_SCHEME):]
    if not re.fullmatch(r'[0-9a-f]{32}', nonce) or nonce == '0' * 32:
        raise ValueError('Malformed ticket referrer')
    return nonce


def sessions_by_nonce(dump, nonce, package=PACKAGE):
    """Live and finalized sessions of the package that carry the ticket's nonce."""
    expected = nonce_referrer(nonce)
    return tuple(s for s in dump.sessions if s.section != 'Historical' and s.package == package
                 and s.referrer == expected)


# ------------------------------------------------ active package bytes, boot and cohort

DATA_PATH = re.compile(r'/data/app/~~[A-Za-z0-9_-]{22}==/' + re.escape(PACKAGE) + r'-[A-Za-z0-9_-]{22}==/base\.apk')


def package_path(code, output, package=PACKAGE):
    """`pm path --user 0 <package>` for SystemUI: the factory APK or one data copy, no splits."""
    _bounded(code, output, 0, 4096)
    match = re.fullmatch(r'package:(\S+)\n', output)
    if package != PACKAGE or not match:
        raise ValueError('Package path of no known form')
    path = match[1]
    if path == FACTORY_PATH:
        return 'factory', path
    if DATA_PATH.fullmatch(path):
        return 'data', path
    raise ValueError('Unexpected package path')


def file_digest(code, output, path):
    """toybox `sha256sum <path>`: the digest of exactly that file."""
    _bounded(code, output, 0, 4096)
    match = re.fullmatch(r'([0-9a-f]{64})  (\S+)\n', output)
    if not match or match[2] != path:
        raise ValueError('File digest of no known form')
    return match[1]


def package_uid(code, output, package=PACKAGE):
    """`cmd package list packages -U <filter>`: the UID of exactly that package."""
    _bounded(code, output, 0, 65536)
    if not output.endswith('\n'):
        raise ValueError('Package list truncated')
    rows = output[:-1].split('\n')
    found = []
    for row in rows:
        match = re.fullmatch(r'package:(' + _PACKAGE_NAME + r') uid:([0-9]+)', row)
        if not match:
            raise ValueError('Package list row of no known form')
        if match[1] == package:
            found.append(_number(match[2], 0, 0x7fffffff))
    if len(found) != 1:
        raise ValueError('Package not listed exactly once')
    return found[0]


def package_version_uid(code, output, package=PACKAGE):
    """`pm list packages --user 0 --show-versioncode -U <filter>`, source derived: versionCode and UID."""
    _bounded(code, output, 0, 65536)
    if not output.endswith('\n'):
        raise ValueError('Package list truncated')
    found = []
    for row in output[:-1].split('\n'):
        match = re.fullmatch(r'package:(' + _PACKAGE_NAME + r') versionCode:([0-9]+) uid:([0-9]+)', row)
        if not match:
            raise ValueError('Package list row of no known form')
        if match[1] == package:
            found.append((_number(match[2], 0), _number(match[3], 0, 0x7fffffff)))
    if len(found) != 1:
        raise ValueError('Package not listed exactly once')
    return found[0]


def boot_id(code, output):
    """`cat /proc/sys/kernel/random/boot_id`: the kernel's random UUID for this boot."""
    _bounded(code, output, 0, 64)
    match = re.fullmatch(r'([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\n', output)
    if not match:
        raise ValueError('Boot ID of no known form')
    return match[1]


FINGERPRINT = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:[A-Za-z0-9_.]+/'
                         r'[A-Za-z0-9_.]+/[A-Za-z0-9_.-]+:(?:user|userdebug|eng)/[A-Za-z0-9_.,-]+')


def build_fingerprint(code, output):
    """`getprop ro.build.fingerprint`: brand/product/device:release/id/incremental:type/tags."""
    _bounded(code, output, 0, 256)
    if not output.endswith('\n') or not FINGERPRINT.fullmatch(output[:-1]):
        raise ValueError('Fingerprint of no known form')
    return output[:-1]


@dataclass(frozen=True)
class Cohort:
    fingerprint: str
    factory_digest: str


def cohort(fingerprint_reply, factory_digest_reply):
    """The target cohort read on a guest: the build fingerprint and the factory SystemUI digest.

    Each reply is (exit status, output). The factory APK is read at its fixed image path,
    whichever copy is active, so a data copy never stands in for it."""
    return Cohort(build_fingerprint(*fingerprint_reply), file_digest(*factory_digest_reply, FACTORY_PATH))


def cohort_matches(expected, observed):
    """The plan's cohort against a guest's: both fields equal, nothing else decides."""
    if not isinstance(expected, Cohort) or not isinstance(observed, Cohort):
        raise ValueError('Not a cohort')
    if not FINGERPRINT.fullmatch(expected.fingerprint) or not re.fullmatch(r'[0-9a-f]{64}', expected.factory_digest):
        raise ValueError('Malformed expected cohort')
    return expected == observed


# ------------------------------------------------ the checkpoint through the storage service
#
# The fixed helper of tests/checkpoint-read runs as the shell user and asks the framework's storage
# service two questions, supportsCheckpoint() and needsCheckpoint(), through the platform's own
# IStorageManager proxy. It prints a header line, then either both answers or one error line, and
# its exit status follows from what it printed.

CHECKPOINT_READ_HEADER = 'andrix-checkpoint-read-v1'
_JAVA_CLASS = r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*'
_HELPER_ANSWER = r'(true|false|error:(?:not-boolean|unknown|' + _JAVA_CLASS + r'))'
_HELPER_ANSWERS = re.compile(CHECKPOINT_READ_HEADER + r'\nsupports=' + _HELPER_ANSWER + r'\nneeds=' + _HELPER_ANSWER
                             + r'\n')
_HELPER_REFUSALS = {2: re.compile(CHECKPOINT_READ_HEADER + r'\nerror=(arguments)\n'),
                    3: re.compile(CHECKPOINT_READ_HEADER + r'\nerror=(service-absent)\n'),
                    4: re.compile(CHECKPOINT_READ_HEADER + r'\nerror=(lookup:' + _JAVA_CLASS + r')\n')}


@dataclass(frozen=True)
class CheckpointReading:
    """One reply of the checkpoint helper. `supports` and `needs` are the answers of
    supportsCheckpoint() and needsCheckpoint(), or None where the helper got no answer. `refusal`
    is empty for an answer. Otherwise it holds the helper's own words: `arguments`,
    `service-absent`, `lookup:<class>`, or the two answers as printed when a call failed."""
    supports: bool | None
    needs: bool | None
    refusal: str


def checkpoint_read(code, output, error):
    """The checkpoint helper's reply, by its exact protocol in tests/checkpoint-read.

    Status 0: the header, `supports=` and `needs=`, each `true` or `false`. Status 5: the same lines
    where at least one answer is `error:` and the failure, `not-boolean`, `unknown` or an exception
    class. Status 2, 3 and 4: the header and one line, `error=arguments`, `error=service-absent` or
    `error=lookup:` and an exception class. Those four are refusals, which carry no answer to rely
    on. Anything else is of no known form: another header or status, a status that disagrees with
    the answers, another line, a missing newline, or any standard error, such as a runtime warning.
    The answers' meaning is the storage service's: whether the device supports a checkpoint, and
    whether this boot mounts with checkpointing or is checkpointing now."""
    if type(code) is not int or not isinstance(output, str) or not isinstance(error, str) or len(output) > 4096:
        raise ValueError('Checkpoint read of no known form')
    if error != '':
        raise ValueError('Checkpoint read with standard error')
    match = _HELPER_ANSWERS.fullmatch(output)
    if match:
        answers = [None if answer.startswith('error:') else answer == 'true' for answer in (match[1], match[2])]
        if code == 0 and None not in answers:
            return CheckpointReading(answers[0], answers[1], '')
        if code == 5 and None in answers:
            return CheckpointReading(answers[0], answers[1], 'supports=%s needs=%s' % (match[1], match[2]))
        raise ValueError('Checkpoint read whose status disagrees with its answers')
    refusal = _HELPER_REFUSALS.get(code)
    match = refusal.fullmatch(output) if refusal is not None else None
    if not match:
        raise ValueError('Checkpoint read of no known form')
    return CheckpointReading(None, None, match[1])


_ID_NAME = r'[a-z_][a-z0-9_]*'
_ID_NUMBER = r'(?:0|[1-9][0-9]{0,9})'
_IDENTITY = re.compile(r'uid=(' + _ID_NUMBER + r')\(' + _ID_NAME + r'\) gid=(' + _ID_NUMBER + r')\(' + _ID_NAME
                       + r'\) groups=' + _ID_NUMBER + r'\(' + _ID_NAME + r'\)(?:,' + _ID_NUMBER + r'\(' + _ID_NAME
                       + r'\))* context=(u:r:[a-z0-9_]+:s0(?::c[0-9]+(?:,c[0-9]+)*)?)\n')


def shell_identity(code, output, error):
    """`id` on the shell route: the UID, GID and SELinux context that its commands run with.

    The captured form is one line: the UID and GID with their names, every supplementary group
    with its name, and the context. Toybox's source is not pinned here, so any other form, status
    or standard error is unknown."""
    match = _IDENTITY.fullmatch(output) if isinstance(output, str) else None
    if code != 0 or error != '' or not match:
        raise ValueError('Identity of no known form')
    return int(match[1]), int(match[2]), match[3]


def sm_supports_checkpoint(code, output, error):
    """`sm supports-checkpoint`: Android's own client of supportsCheckpoint(), status 0 and the
    boolean on one line. `true` is the captured form; `false` is taken to print the same way. Any
    other status, output or standard error, a refusal included, is unknown. It reads support only,
    never a pending or committed checkpoint, so no CHECKPOINT fact rests on it."""
    if code != 0 or error != '' or output not in ('true\n', 'false\n'):
        raise ValueError('Checkpoint support of no known form')
    return output == 'true\n'


# ------------------------------------------------ vdc checkpoint, withdrawn
#
# The shell route does not read vdc. A D3 guest showed that the shell user cannot run it at all:
# `vdc checkpoint ...` exits 127 with `/system/bin/sh: vdc: inaccessible or not found`. These two
# parsers and their source derived forms stay unqualified, and no reader calls them.

def checkpoint_state(code, output, error):
    """`vdc checkpoint needsCheckpoint`, source derived from system/vold, withdrawn and unqualified.

    vdc answers with its exit status and prints nothing. 1: vold is checkpointing this boot, so
    /data writes are still provisional. 0: no checkpoint is pending, either committed or never
    started in this boot. A failed binder call exits with ENOTTY and a missing vold with EINVAL;
    both, and any output at all, are unknown.
    """
    if output != '' or error != '' or code not in (0, 1):
        raise ValueError('Checkpoint state of no known form')
    return 'pending' if code == 1 else 'not_checkpointing'


def checkpoint_support(code, output, error):
    """`vdc checkpoint supportsCheckpoint`, source derived, withdrawn and unqualified: 1 supported, 0 not."""
    if output != '' or error != '' or code not in (0, 1):
        raise ValueError('Checkpoint support of no known form')
    return code == 1


# ------------------------------------------------ boot, process and framework instance

def uptime_ms(code, output):
    match = re.fullmatch(r'([0-9]{1,12})\.([0-9]{2}) [0-9]{1,12}\.[0-9]{2}\n', output)
    if code != 0 or not match:
        raise ValueError('Uptime of no known form')
    return int(match[1]) * 1000 + int(match[2]) * 10


def single_pid(code, output):
    """`pidof <name>`: exactly one process."""
    match = re.fullmatch(r'([1-9][0-9]{0,6})\n', output)
    if code != 0 or not match:
        raise ValueError('Not exactly one process')
    return int(match[1])


def pids(code, output):
    """`pidof <name>` for a process that runs once for each running user: one or more distinct PIDs
    on one line, separated by single spaces, in any order. Source derived: toybox's pidof prints
    every match on one line. The toybox source is not pinned here."""
    match = re.fullmatch(r'([1-9][0-9]{0,6}(?: [1-9][0-9]{0,6})*)\n', output)
    if code != 0 or not match:
        raise ValueError('No process list of known form')
    found = [int(pid) for pid in match[1].split(' ')]
    if len(set(found)) != len(found):
        raise ValueError('A process listed twice')
    return found


_STATUS_LINE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*):(?:\t(.*))?')


def status_uid(code, output, pid):
    """`/proc/<pid>/status`: the process's UID. Each line is a key, a colon and a tab separated
    value. Exactly one Pid line names the PID, and exactly one Uid line holds four equal decimal
    IDs, real, effective, saved and file system. Source derived from the kernel's task_state(),
    whose source is not pinned here."""
    if code != 0 or not output.endswith('\n') or len(output) > 65536:
        raise ValueError('Process status of no known form')
    seen = {}
    for line in output[:-1].split('\n'):
        match = _STATUS_LINE.fullmatch(line)
        if not match:
            raise ValueError('Process status of no known form')
        key, value = match[1], match[2] or ''
        if key in ('Pid', 'Uid'):
            if key in seen:
                raise ValueError('Process status names %s twice' % key)
            seen[key] = value
    if seen.get('Pid') != str(pid):
        raise ValueError('Process status of another process')
    ids = seen.get('Uid', '').split('\t')
    if len(ids) != 4 or not all(re.fullmatch(r'0|[1-9][0-9]{0,9}', i) for i in ids) or len(set(ids)) != 1:
        raise ValueError('Process UID of no known form')
    return int(ids[0])


# The user states that `UserState.stateToString` prints, and -1 for a user with no state.
USER_STATES = ('BOOTING', 'RUNNING_LOCKED', 'RUNNING_UNLOCKING', 'RUNNING_UNLOCKED', 'STOPPING', 'SHUTDOWN', '-1')
_USER_HEADER = re.compile(r'  UserInfo\{(0|[1-9][0-9]{0,8}):(.*):([0-9a-f]{1,8})\} serialNo=(0|[1-9][0-9]{0,18}) '
                          r'isPrimary=(true|false)( parentId=(?:0|[1-9][0-9]{0,8}))?( <removing> )?( <partial>)?'
                          r'( <pre-created>)?( <converted>)?( <guestToRemove>)?')


# `Device properties:` up to `Started users state:`: two restriction lists, each line indented by
# four spaces, an empty line and, while users are being removed, the recently removed IDs.
_STARTED = re.compile(r'Device properties:\n  Device policy global restrictions:\n(?:    [^\n]+\n)*'
                      r'  Guest restrictions:\n(?:    [^\n]+\n)*\n'
                      r'(?:  Recently removed userIds: \[(?:0|[1-9][0-9]{0,8})(?:, (?:0|[1-9][0-9]{0,8}))*\]\n)?'
                      r'  Started users state: \[([^\]\n]*)\]\n')


@dataclass(frozen=True)
class AndroidUser:
    user: int
    serial: int
    state: str
    removing: bool
    partial: bool


def users(code, output):
    """`dumpsys user`: every user in the users section, with its serial and state, or nothing.

    Source derived from `UserManagerService.dump` and `dumpUserLU`: a current user line, an empty
    line and `Users:`, then for each user a `UserInfo{id:name:flags}` line with its serial and
    markers, and its own lines indented by at least four spaces, one of them `    State: `. The
    section ends with an empty line before `Device properties:`, whose restrictions lead to
    `Started users state:`. That list comes from the same user states, so every user it names must
    be in the section with the same state, and every user in the section with a state must be in
    it. The notice rule is only as complete as this listing, so a listing cut short, a block of no
    known form, a repeated user or a disagreement refuses the whole read."""
    if code != 0 or len(output) > 4 * 1024 * 1024:
        raise ValueError('User listing of no known form')
    head = re.match(r'Current user: (?:N/A|0|[1-9][0-9]{0,8})\n\nUsers:\n', output)
    end = output.find('\n\nDevice properties:\n')
    if not head or end < head.end() - 1:
        raise ValueError('User listing cut short or of no known form')
    section = output[head.end():end + 1]
    found, block = [], None
    for line in section[:-1].split('\n') if section else []:
        # A user's name is free text and may hold `} serialNo=` itself. The greedy name still
        # leaves the line's own suffix, which the dump prints last.
        header = _USER_HEADER.fullmatch(line)
        if header:
            block = {'user': int(header[1]), 'serial': int(header[4]), 'removing': bool(header[7]),
                     'partial': bool(header[8]), 'states': [], 'types': 0}
            found.append(block)
        elif block is not None and line.startswith('    ') and line.strip():
            if line.startswith('    State: '):
                block['states'].append(line[len('    State: '):])
            elif line.startswith('    Type: '):
                block['types'] += 1
        else:
            raise ValueError('A user listing line of no known form')
    result = []
    for b in found:
        if len(b['states']) != 1 or b['states'][0] not in USER_STATES or b['types'] != 1:
            raise ValueError('A user without one known state')
        result.append(AndroidUser(b['user'], b['serial'], b['states'][0], b['removing'], b['partial']))
    if len({u.user for u in result}) != len(result) or len({u.serial for u in result}) != len(result):
        raise ValueError('A user or serial listed twice')
    if not result:
        raise ValueError('No users listed')
    started = _STARTED.match(output, end + 2)
    if not started:
        raise ValueError('User listing without its started users of known form')
    states = {}
    for pair in started[1].split(', ') if started[1] else []:
        match = re.fullmatch(r'(0|[1-9][0-9]{0,8})=([A-Z_]+)', pair)
        if not match or int(match[1]) in states:
            raise ValueError('A started user of no known form')
        states[int(match[1])] = match[2]
    if states != {u.user: u.state for u in result if u.state != '-1'}:
        raise ValueError('The users section and the started users disagree')
    return result


def start_ticks(code, output, pid, name):
    """`/proc/<pid>/stat`: the process start time in clock ticks since the boot."""
    match = re.fullmatch(r'([0-9]+) \(([^)]*)\) (.*)\n', output)
    if code != 0 or not match or int(match[1]) != pid or match[2] != name[:15]:
        raise ValueError('Process status of no known form')
    fields = match[3].split(' ')
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError('Process status of no known form')
    return int(fields[19])


def process_context(code, output):
    """`/proc/<pid>/attr/current`: the SELinux context, ended by one NUL."""
    match = re.fullmatch(r'(u:r:[a-z0-9_]+:s0(?::c[0-9]+,c[0-9]+(?:,c[0-9]+,c[0-9]+)?)?)\x00', output)
    if code != 0 or not match:
        raise ValueError('Context of no known form')
    return match[1]


def boot_completed(code, output):
    """`getprop sys.boot_completed`, source derived: '1' once completed, empty before."""
    if code != 0 or output not in ('1\n', '\n'):
        raise ValueError('Boot completion of no known form')
    return output == '1\n'


def factory_version(code, output, package=PACKAGE):
    """`pm list packages --factory-only --show-versioncode <filter>`, source derived."""
    if code != 0 or not output.endswith('\n') or len(output) > 65536:
        raise ValueError('Package list of no known form')
    found = []
    for row in output[:-1].split('\n'):
        match = re.fullmatch(r'package:([A-Za-z0-9_.]+) versionCode:([0-9]{1,19})', row)
        if not match:
            raise ValueError('Package list row of no known form')
        if match[1] == package:
            found.append(int(match[2]))
    if len(found) != 1:
        raise ValueError('Package not listed exactly once')
    return found[0]
