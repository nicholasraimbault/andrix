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
    r'isApplied = (true|false); isFailed = (true|false); errorMsg = ([^;]*);')


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
