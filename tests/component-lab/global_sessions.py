# SPDX-License-Identifier: Apache-2.0
"""The whole global session inventory: every installer session of every package and user, read
whole before any SystemUI projection, in the typed form lab_actions.check_global defines.

One read runs the public shell observer's own fixed commands, all in its allowlist, between two
boot ID reads and two framework instance reads: the complete staged session listing
(`pm list staged-sessions`) and the whole installer dump (`dumpsys -t 25 package installs`). Each
is parsed by the strict parsers of scripts/proof/systemui_sessions.py, which rebuild the writer's
output and refuse anything else. In the pinned source the dump prints every session Package
Manager holds, of every user and package, as active, finalized (a staged session in a terminal
state) or historical (PackageInstallerService.dump, services/core/java/com/android/server/pm/
PackageInstallerService.java:2604-2662, reached through DumpHelper.java:551-560), each record by
PackageInstallerSession.dumpLocked (PackageInstallerSession.java:6776-6832). The listing is every
staged session that is not destroyed (PackageManagerShellCommand.java:1294-1360,
PackageInstallerService.java:1492-1505).

The two must agree on every field both print. The listing prints each session's SessionInfo:
its ID, its package, staged, readiness, end and error message, at the top level only a session
with no parent, and under a multiple package parent each of its children
(PackageManagerShellCommand.java:1320-1366). That package is the preapproval's, else the parsed
APK's, else the session parameters' (PackageInstallerSession.java:1547-1548), and the error
message is the session's own (1578, PackageInstaller.java:4992-4995). The dump prints the
parameters' package (PackageInstaller.java:4156) and the session's staged flag, family, readiness,
end and error message (PackageInstallerSession.java:6814-6822). So every listed session is in the
dump's active or finalized section. A package the dump knows is the listed one, while a package
only the listing knows stays unknown in the inventory. A record the dump left as certainly another
package's is never listed as SystemUI's. A record that parsed exactly is staged, not destroyed,
with the same readiness, end and error message, and a single session, listed at the top level
with no children below it. Every staged session the dump holds live and not destroyed is listed.
A read that crossed a boot or a framework restart, a disagreement, or a dump the parsers refuse
gives no reading at all. A record certainly about another package that has no exact form, as the
parsers leave it, is listed with its section, ID and package and every other field unknown, which
never counts as safe. So the reading is whole or there is none.

A failed session's recorded cause is classified only by its exact source forms, each joined to the
session's own ID and package. N2's is the signature mismatch, INSTALL_FAILED_UPDATE_INCOMPATIBLE's
`Existing package <package> signatures do not match newer version; ignoring!`
(PackageManagerServiceUtils.java:527-531); N3's the missing file verification of a system package
update, `fs-verity not set up for system package update ` and the nested `APK doesn't have
fs-verity: <path>` of the session's own base APK (InstallPackageHelper.java:2141-2161,
PackageVerityExt.java:158-167). A staged session's activation failure is recorded in its recovery
boot inside the revert sentence, `Reverting back to safe state. Marking <id> as failed. Reason for
revert: Failed to install sessionId: <id> Error: <message>`, with INSTALL_FAILED_INTERNAL_ERROR
(StagingManager.java:383-392 and 426-429). N1's is the nonstaged persistent app refusal,
INSTALL_FAILED_INVALID_APK and `Package <package> is a persistent app. Persistent apps are not
updateable.` (InstallPackageHelper.java:1803-1808), which the session keeps as its error message
through installStatusToString and as its final status and message (PackageInstallerSession.java:
4167-4172, 6355-6367). Any other failure is OTHER, and a session that did not fail has no cause.

The captured lab guest forms of these records are the fixtures of scripts/proof/tests; a whole
listing and dump of a guest of the next profile, with N1 to N3 and the managed tickets' sessions,
needs a guest capture. Host evidence only."""
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _path in (str(HERE), str(ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import lab_readers  # noqa: E402
from scripts.proof import systemui_observer as observer  # noqa: E402
from scripts.proof import systemui_sessions as readback  # noqa: E402

# The observer's own fixed reads, in the order one global read makes them.
BOOT_ID = observer.BOOT_ID
FRAMEWORK_PID = observer.FRAMEWORK_PID
LISTING = observer.LISTING
INSTALLS = observer.INSTALLS
STAT = re.compile(r'cat /proc/([1-9][0-9]{0,6})/stat')
SECTIONS = {'Active': 'ACTIVE', 'Finalized': 'FINALIZED', 'Historical': 'HISTORICAL'}
# The exact source forms of the classified causes.
SIGNATURE = 'Existing package %s signatures do not match newer version; ignoring!'
FS_VERITY = ("fs-verity not set up for system package update com.android.server.pm.PackageManagerException: "
             "APK doesn't have fs-verity: %s/base.apk")
PERSISTENT = 'Package %s is a persistent app. Persistent apps are not updateable.'
REVERT = ('Reverting back to safe state. Marking %d as failed. Reason for revert: Failed to install sessionId: %d '
          'Error: ')
INVALID_APK, INTERNAL_ERROR = -2, -110


def allowed(command):
    """Whether a command is one of this reader's fixed reads, each in the observer's allowlist."""
    return command in (BOOT_ID, FRAMEWORK_PID, LISTING, INSTALLS) or bool(STAT.fullmatch(command))


def cause(session):
    """The class of a parsed session's recorded failure cause, or None when it did not fail."""
    if not session.failed:
        return None
    package = session.package
    if package is None:
        return 'OTHER'
    if not session.staged:
        if ((session.error_code, session.error_message, session.final_status, session.final_message)
                == (INVALID_APK, 'INSTALL_FAILED_INVALID_APK: ' + PERSISTENT % package, INVALID_APK,
                    PERSISTENT % package)):
            return 'PERSISTENT'
        return 'OTHER'
    prefix = REVERT % (session.identity, session.identity)
    if session.error_code != INTERNAL_ERROR or not session.error_message.startswith(prefix):
        return 'OTHER'
    inner = session.error_message[len(prefix):]
    if inner == SIGNATURE % package:
        return 'SIGNATURE'
    if session.stage_dir is not None and inner == FS_VERITY % session.stage_dir:
        return 'FS_VERITY'
    return 'OTHER'


def row(session):
    """One exactly parsed session as the inventory lists it."""
    return {'section': SECTIONS[session.section], 'id': session.identity, 'package': session.package,
            'referrer': session.referrer, 'staged': session.staged, 'multi_package': session.multi_package,
            'parent': session.parent, 'children': list(session.children), 'sealed': session.sealed,
            'committed': session.committed, 'ready': session.ready, 'applied': session.applied,
            'failed': session.failed, 'destroyed': session.destroyed, 'created': session.created_millis,
            'installer': session.installer_uid if session.installer_uid >= 0 else None, 'cause': cause(session)}


def unknown(section, identity, package):
    """A record certainly about another package that has no exact form: its section, ID and package,
    and every other field unknown."""
    return {'section': SECTIONS[section], 'id': identity, 'package': package, 'referrer': None, 'staged': None,
            'multi_package': None, 'parent': None, 'children': None, 'sealed': None, 'committed': None, 'ready': None,
            'applied': None, 'failed': None, 'destroyed': None, 'created': None, 'installer': None, 'cause': None}


def _parse(call, reader, *args):
    try:
        return reader(*call, *args)
    except ValueError as error:
        raise lab_readers.Unclassified(str(error)) from error


def join(listing, dump):
    """Refuses a listing and a dump that do not agree, as lab_readers.Unclassified. Nothing is
    chosen between two contrary parts, and no row is dropped to make them agree."""
    if not listing.complete:
        raise lab_readers.Unclassified('the staged listing is not complete')
    live = {s.identity: s for s in dump.sessions if s.section != 'Historical'}
    # The records the dump left as another package's, each with the package it still knows or None.
    skipped = {identity: package for section, identity, package in dump.skipped if section != 'Historical'}
    # Each top level row with the rows the listing printed below it, a missing child's included.
    below, top = {}, None
    for entry in listing.sessions:
        if entry.child:
            below.setdefault(top, []).append(entry.identity)
        else:
            top = entry.identity
            below[top] = []
    listed = {s.identity: s for s in listing.sessions if s.found}
    for identity, entry in listed.items():
        session = live.get(identity)
        if session is None and identity not in skipped:
            raise lab_readers.Unclassified('listed session %d is not in the dump' % identity)
        known = session.package if session is not None else skipped[identity]
        if known is not None and entry.package != known:
            raise lab_readers.Unclassified('the listing and the dump name other packages for session %d' % identity)
        if session is None:
            if known is None and entry.package == readback.PACKAGE:
                raise lab_readers.Unclassified('listed session %d of %s is a record of another package in the dump'
                                               % (identity, readback.PACKAGE))
            continue
        if entry.child or below.get(identity):
            raise lab_readers.Unclassified('the listing and the dump disagree on the family of session %d'
                                           % identity)
        if not session.staged or session.destroyed or (entry.ready, entry.applied, entry.failed, entry.error) \
                != (session.ready, session.applied, session.failed, session.error_message):
            raise lab_readers.Unclassified('the listing and the dump disagree on session %d' % identity)
    for identity, session in live.items():
        if session.staged and not session.destroyed and identity not in listed:
            raise lab_readers.Unclassified('dumped staged session %d is not listed' % identity)


def read(run):
    """One whole global session inventory through `run(command) -> (exit, stdout, stderr)`, which
    raises lab_readers.Unavailable for a command that did not complete whole. Raises Unavailable
    when no framework runs and Unclassified for any read of no known form, one that crossed a boot
    or a framework restart, or a listing and dump that disagree."""
    def boot():
        code, stdout, stderr = run(BOOT_ID)
        if stderr:
            raise lab_readers.Unclassified('the boot ID read wrote to standard error')
        return _parse((code, stdout), readback.boot_id)

    def instance():
        reply = run(FRAMEWORK_PID)
        if reply == (1, '', ''):
            raise lab_readers.Unavailable('no framework runs, so no session inventory can be read')
        if reply[2]:
            raise lab_readers.Unclassified('the framework read wrote to standard error')
        pid = _parse(reply[:2], readback.single_pid)
        code, stdout, stderr = run('cat /proc/%d/stat' % pid)
        if stderr:
            raise lab_readers.Unclassified('the framework stat read wrote to standard error')
        return pid, _parse((code, stdout), readback.start_ticks, pid, 'system_server')
    first, framework = boot(), instance()
    code, stdout, stderr = run(LISTING)
    if stderr:
        raise lab_readers.Unclassified('the staged listing wrote to standard error')
    listing = _parse((code, stdout), readback.staged_listing, False)
    code, stdout, stderr = run(INSTALLS)
    if stderr:
        raise lab_readers.Unclassified('the installer dump wrote to standard error')
    dump = _parse((code, stdout), readback.installs_dump)
    if instance() != framework or boot() != first:
        raise lab_readers.Unclassified('the framework or the device restarted during the read')
    join(listing, dump)
    rows = [row(s) for s in dump.sessions] + [unknown(*skipped) for skipped in dump.skipped]
    order = list(SECTIONS.values())
    rows.sort(key=lambda r: (order.index(r['section']), r['id']))
    return {'whole': True, 'sessions': rows}


def rederive(captures):
    """What a group's recorded captures give when read again: they must be exactly the reads one
    global read makes, in order, each (command, exit status or None, stdout, stderr)."""
    queue = list(captures)

    def run(command):
        if not queue or queue[0][0] != command:
            raise lab_readers.Unclassified('the captures are not the reads a global inventory makes')
        _, code, stdout, stderr = queue.pop(0)
        if code is None:
            raise lab_readers.Unavailable('a capture did not complete')
        return code, stdout, stderr
    value = read(run)
    if queue:
        raise lab_readers.Unclassified('captures beyond the reads a global inventory makes')
    return value
