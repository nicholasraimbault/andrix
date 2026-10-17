# SPDX-License-Identifier: Apache-2.0
"""Observe authoritative PMS dumps for a controlled allocator test. Never allocate or reserve IDs."""
import re

# dumpsys (frameworks/native/cmds/dumpsys/dumpsys.cpp at GrapheneOS 2026081300, SHA-256 6b4e0a0b...)
# exits 0 after every outcome but a refused argument (main returns 0 at line 313), so neither its exit
# status nor the absence of one line shows a dump complete. When a service's dump outlives the timeout
# (-t SECONDS, default 10 s), dumpsys stops reading, writes this line after whatever the service had
# written (writeDump, lines 558-562, and again in main, lines 299-302) and exits 0.
DUMP_TIMEOUT = re.compile(r"^\*\*\* SERVICE '([^'\n]*)' DUMP TIMEOUT \(([0-9]+)ms\) EXPIRED \*\*\*$", re.M)
# Its other outcomes each print one line on stderr, by these source lines, and still exit 0 (the refused
# timeout argument exits -1). Each is the reason the capture is unavailable.
DUMPSYS_ERRORS = (
    # reportDumpError (418-422): a part of the dump failed, after anything written before it; for the
    # dump itself once service->dump returned (469-470), so a partial dump may end at a whole line.
    (re.compile(r"^Error with service '([^'\n]*)' while ([A-Za-z ]+): (.+)$"),
     "dumpsys reported service '{0}' failing while {1}: {2}"),
    # startDumpThread (434, 440-441): no such service, or no pipe for its dump; nothing was dumped.
    (re.compile(r"^Can't find service: (.+)$"), "dumpsys found no service '{0}'"),
    (re.compile(r"^Failed to create pipe to dump service info for (.+?): (.+)$"),
     "dumpsys opened no pipe for service '{0}': {1}"),
    # writeDump (528-529, 540-541, 550-551): the dump's transfer failed partway, the dump is cut.
    (re.compile(r"^Error in poll while dumping service (.+?) : (.+)$"),
     "dumpsys failed polling the dump of service '{0}': {1}, the dump is cut"),
    (re.compile(r"^Failed to read while dumping service (.+?): (.+)$"),
     "dumpsys failed reading the dump of service '{0}': {1}, the dump is cut"),
    (re.compile(r"^Failed to write while dumping service (.+?): (.+)$"),
     "dumpsys failed writing the dump of service '{0}': {1}, the dump is cut"),
    # main (196, 207): a refused timeout argument, exit -1.
    (re.compile(r"^Error: invalid timeout\((seconds|milliseconds)\) number: '(.*)'$"),
     "dumpsys refused its timeout argument in {0}: '{1}'"),
)


class DumpUnavailable(ValueError):
    """A dumpsys capture that is not one complete dump: unavailable evidence, with its reason."""


def _capture_text(value):
    if type(value) is bytes:
        return value.decode('utf-8', 'surrogateescape')
    return value if type(value) is str else None


def dumpsys_error(stderr):
    """The reason dumpsys's stderr states, by its source form, or its first line as written."""
    lines = [line for line in stderr.splitlines() if line.strip()]
    for line in lines:
        for pattern, form in DUMPSYS_ERRORS:
            found = pattern.fullmatch(line)
            if found:
                return form.format(*found.groups())
    return 'dumpsys wrote to stderr: %s' % (lines[0][:240] if lines else repr(stderr[:240]))


def stdout_cut(text):
    """Why one dump's text alone is not one complete dump, or None: cut at dumpsys's timeout, or ending
    inside a line. Only the stdout part of the gate; complete_capture is the gate."""
    found = DUMP_TIMEOUT.search(text)
    if found:
        return "dumpsys timed out after %s ms in service '%s', the dump is cut" % (found[2], found[1])
    if text and not text.endswith('\n'):
        return 'the dump ends inside a line'
    return None


def complete_capture(capture, what):
    """The completeness gate of one dumpsys capture, before any reader parses it: its stdout as captured
    when it is one complete dump, DumpUnavailable naming WHAT and the reason otherwise.

    CAPTURE is a completed process (returncode, stdout, stderr; the trials' transport returns one only
    once its command ended with a result) or a capture record with complete, exit_code, stdout and
    stderr. One complete dump: its transport completed, dumpsys exited 0, its stdout carries no timeout
    line and ends with a line feed, and its stderr is empty. Each other outcome is unavailable with its
    own reason: a transport retired, timed out or stopped before a result, a nonzero exit, the timeout
    line, each of dumpsys's stderr forms (DUMPSYS_ERRORS), any other stderr, a dump ending inside a line."""
    if type(capture) is dict:
        complete, code = capture.get('complete'), capture.get('exit_code')
        out, err = capture.get('stdout'), capture.get('stderr')
    elif all(hasattr(capture, name) for name in ('returncode', 'stdout', 'stderr')):
        complete, code, out, err = True, capture.returncode, capture.stdout, capture.stderr
    else:
        raise DumpUnavailable('%s unavailable: not a capture' % what)
    if complete is not True:
        raise DumpUnavailable('%s unavailable: its transport did not complete with a result (retired, timed out or '
                              'stopped)' % what)
    text, errors = _capture_text(out), _capture_text(err)
    if text is None or errors is None or type(code) is not int:
        raise DumpUnavailable('%s unavailable: no recorded stdout, stderr and exit status' % what)
    if code != 0:
        raise DumpUnavailable('%s unavailable: dumpsys exited %d%s' % (what, code, ('; ' + dumpsys_error(errors)) if errors else ''))
    found = DUMP_TIMEOUT.search(text)
    if found:
        raise DumpUnavailable("%s unavailable: dumpsys timed out after %s ms in service '%s', the dump is cut"
                              % (what, found[2], found[1]))
    if errors:
        raise DumpUnavailable('%s unavailable: %s' % (what, dumpsys_error(errors)))
    if text and not text.endswith('\n'):
        raise DumpUnavailable('%s unavailable: the dump ends inside a line' % what)
    return out


def package_ids(text):
    if len(text) > 16 * 1024 * 1024:
        raise ValueError('package dump bounds')
    cut = stdout_cut(text)
    if cut is not None:
        raise DumpUnavailable('package dump unavailable: ' + cut)
    result = {'packages': {}, 'hidden': {}}
    section = None
    pending = None
    app_id = None

    def finish():
        nonlocal pending, app_id
        if pending is not None:
            if section is None or app_id is None or pending in result[section]:
                raise ValueError('incomplete or duplicate package identity')
            result[section][pending] = app_id
        pending, app_id = None, None

    for line in text.splitlines():
        if line in ('Packages:', 'Hidden system packages:'):
            finish(); section = 'packages' if line == 'Packages:' else 'hidden'
            continue
        header = re.fullmatch(r'  Package \[([^\]\r\n]+)\] \([0-9a-f]+\):', line)
        if header:
            finish(); pending = header[1]
        elif pending is not None and line.startswith('    compat name='):
            pending = line[len('    compat name='):]
            if not pending:
                raise ValueError('empty compatibility name')
        elif pending is not None and line.startswith('    appId='):
            value = line[len('    appId='):]
            if app_id is not None or not re.fullmatch(r'-?[0-9]{1,10}', value):
                raise ValueError('package app ID')
            app_id = int(value)
    finish()
    if not result['packages']:
        raise ValueError('package observer unavailable')
    return result


def shared_ids(text):
    if len(text) > 8 * 1024 * 1024:
        raise ValueError('shared user dump bounds')
    cut = stdout_cut(text)
    if cut is not None:
        raise DumpUnavailable('shared user dump unavailable: ' + cut)
    result, pending = {}, None
    for line in text.splitlines():
        header = re.fullmatch(r'  SharedUser \[([^\]\r\n]+)\] \([0-9a-f]+\):', line)
        if header:
            if pending is not None:
                raise ValueError('missing shared app ID')
            pending = header[1]
        elif pending is not None and line.startswith('    appId='):
            value = line[len('    appId='):]
            if not re.fullmatch(r'[0-9]{1,10}', value) or pending in result:
                raise ValueError('shared app ID')
            result[pending] = int(value); pending = None
    if pending is not None or 'Shared users:' not in text or not result:
        raise ValueError('shared user observer unavailable')
    return result


def excluded_hole_candidate(packages, shared, search_start, held, target):
    """Return the source algorithm's prediction only when target is the observed first hole."""
    if (type(search_start) is not int or type(target) is not int
            or not 10000 <= search_start <= target <= 19999):
        raise ValueError('target not covered by current allocator cursor')
    used = {value for value in [*packages.values(), *shared.values()] if 10000 <= value <= 19999}
    if target in used or target not in held or not used or target > max(used):
        raise ValueError('target is not a held internal hole')
    ordinary = next((value for value in range(search_start, max(used) + 1) if value not in used), None)
    if ordinary != target:
        raise ValueError('a lower ordinary hole makes this observation inconclusive')
    predicted = next((value for value in range(search_start, 20000) if value not in used and value not in held), None)
    if predicted is None:
        raise ValueError('allocator capacity unavailable')
    return predicted
