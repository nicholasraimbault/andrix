# SPDX-License-Identifier: Apache-2.0
"""The typed shell crossings: the only guest commands that change state, and how each reply is
classified.

No caller supplies command text. The broker builds each command from typed, bounded fields: the
admitted component, the ticket's nonce, a session ID, a pinned guest path. A reply is classified
only from a command whose remote completion was observed whole, with the exact success form that a
guest capture showed: exit status 0, nothing on standard error, and exactly the expected output.
Any other completed output is UNRECOGNIZED. A command that did not complete gives no reply at all,
so the ticket stays unresolved and reconciliation decides by observation. No form here maps to
REFUSED: no refusal form has been captured, and a refusal would read as proof that nothing
happened.

The forms are those the D3 guest run checked exactly: `Success: created install session [N]`,
`Success: streamed N bytes`, `Success. Reboot device to apply staged session` and `Success`.
COMMIT's accepted and pending forms follow the session parsers' commit observation, which derives
them from the pinned Package Manager shell command. A reboot has no shell reply at all."""
import re

NONCE_SCHEME = 'andrix-ticket:'
CREATED = re.compile(rb'Success: created install session \[([1-9][0-9]{0,9})\]\n')
WRITTEN = re.compile(rb'Success: streamed ([0-9]{1,12}) bytes\n')
READY = b'Success. Reboot device to apply staged session\n'
ACCEPTED = b'Success\n'
PENDING = re.compile(rb"Failure \[timed out after [0-9]+ ms\]\. Ending this command now but session is still being "
                     rb"staged asynchronously\. Use 'pm list staged-sessions' to check the session status later\.\n")
ABANDONED = b'Success\n'
MEMBERS = ('base.apk', 'base.apk.idsig')
STAGED_PATH = re.compile(r'/data/local/tmp/[a-z0-9][a-z0-9-]{0,62}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127}){1,3}')
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')
MAX_SESSION = 0x7fffffff
COMMIT_READY_TIMEOUT_MS = 60000


def _nonce(value):
    if not re.fullmatch(r'[0-9a-f]{32}', value) or value == '0' * 32:
        raise ValueError('not a ticket nonce')
    return value


def _session(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= MAX_SESSION:
        raise ValueError('not a session ID')
    return value


def staged_path(value):
    """A pinned guest path for a staged member: under /data/local/tmp, no shell syntax."""
    if not isinstance(value, str) or not STAGED_PATH.fullmatch(value) or '/../' in value + '/' or '/./' in value + '/':
        raise ValueError('not an admitted staging path')
    return value


def create_command(component, nonce):
    if not PACKAGE.fullmatch(component):
        raise ValueError('not a package')
    return 'pm install-create --user 0 -r --pkg %s --staged --referrer %s%s' % (component, NONCE_SCHEME, _nonce(nonce))


def write_command(session, member, path):
    if member not in MEMBERS:
        raise ValueError('not a bundle member')
    return 'pm install-write %d %s %s' % (_session(session), member, staged_path(path))


def commit_command(session):
    return 'pm install-commit --staged-ready-timeout %d %d' % (COMMIT_READY_TIMEOUT_MS, _session(session))


def abandon_command(session):
    return 'pm install-abandon %d' % _session(session)


def digest_command(path):
    return 'sha256sum %s' % staged_path(path)


def _exact(result, code):
    return result.completed and result.exit == code and result.stderr == b''


def classify_create(result):
    """('SUCCESS', session), ('UNRECOGNIZED', None) for other completed output, or (None, None)."""
    if not result.completed:
        return None, None
    match = CREATED.fullmatch(result.stdout) if _exact(result, 0) else None
    if match and 0 < int(match[1]) <= MAX_SESSION:
        return 'SUCCESS', int(match[1])
    return 'UNRECOGNIZED', None


def classify_write(result, size):
    """SUCCESS only for the whole streamed form with the member's exact size."""
    if not result.completed:
        return None
    match = WRITTEN.fullmatch(result.stdout) if _exact(result, 0) else None
    return 'SUCCESS' if match and int(match[1]) == size else 'UNRECOGNIZED'


def classify_commit(result):
    """READY, ACCEPTED or PENDING for the known forms. A timeout sentence is neither a refusal nor
    proof of no effect: the session may still be staged."""
    if not result.completed:
        return None
    if _exact(result, 0) and result.stdout == READY:
        return 'READY'
    if _exact(result, 0) and result.stdout == ACCEPTED:
        return 'ACCEPTED'
    if _exact(result, 1) and PENDING.fullmatch(result.stdout):
        return 'PENDING'
    return 'UNRECOGNIZED'


def classify_abandon(result):
    if not result.completed:
        return None
    return 'SUCCESS' if _exact(result, 0) and result.stdout == ABANDONED else 'UNRECOGNIZED'


def classify_digest(result, path):
    """The SHA-256 a `sha256sum <path>` read gives, or None for any other form."""
    if not _exact(result, 0):
        return None
    match = re.fullmatch(rb'([0-9a-f]{64})  ' + re.escape(path.encode('ascii')) + rb'\n', result.stdout)
    return match[1].decode('ascii') if match else None


# A direct negative control's session is created under its own referrer namespace, never a
# ticket's: a separate exact parser reads it, and no ticket's nonce can name it.
CONTROL_SCHEME = 'andrix-lab-control:'


def control_create_command(component, control):
    """The create of a direct negative control's staged session, referred by its control ID."""
    if not PACKAGE.fullmatch(component):
        raise ValueError('not a package')
    if not re.fullmatch(r'[0-9a-f]{32}', control) or control == '0' * 32:
        raise ValueError('not a control ID')
    return 'pm install-create --user 0 -r --pkg %s --staged --referrer %s%s' % (component, CONTROL_SCHEME, control)


# N1's one shot nonstaged install. `pm install` takes every option `install-create` takes but
# --multi-package, --referrer among them (PackageManagerShellCommand.java:171-173, 3567-3800), and
# creates, writes, commits and waits for its own session (1582-1680). Its result is `Success` with
# exit status 0, or `Failure [<status message>]` with exit status 1 (4456-4500), where the message
# is installStatusToString's `<status name>: <message>` (PackageInstallerSession.java:6884-6885,
# PackageManager.java:11035-11051). A persistent app's nonstaged update fails with
# INSTALL_FAILED_INVALID_APK and Package Manager's own sentence
# (InstallPackageHelper.java:1803-1808); a lab guest's session dump recorded exactly that message
# for such a refusal. The reply is only classified here: N1 settles on its post reads, never on a
# reply.
PERSISTENT_REFUSAL = ('Failure [INSTALL_FAILED_INVALID_APK: Package %s is a persistent app. Persistent apps are '
                      'not updateable.]\n')
INSTALLED = b'Success\n'


def control_install_command(component, control, path):
    """The nonstaged control's one install of its pinned APK, referred by its control ID."""
    if not PACKAGE.fullmatch(component):
        raise ValueError('not a package')
    if not re.fullmatch(r'[0-9a-f]{32}', control) or control == '0' * 32:
        raise ValueError('not a control ID')
    if not staged_path(path).endswith('/base.apk'):
        raise ValueError('the nonstaged control installs its base.apk')
    return 'pm install --user 0 -r --pkg %s --referrer %s%s %s' % (component, CONTROL_SCHEME, control, path)


def classify_install(result, component):
    """REFUSED_PERSISTENT for the exact persistent app refusal of the component, SUCCESS for an
    install that completed, UNRECOGNIZED for any other completed output, or None."""
    if not result.completed:
        return None
    if _exact(result, 1) and result.stdout == (PERSISTENT_REFUSAL % component).encode('ascii'):
        return 'REFUSED_PERSISTENT'
    if _exact(result, 0) and result.stdout == INSTALLED:
        return 'SUCCESS'
    return 'UNRECOGNIZED'
