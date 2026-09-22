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
