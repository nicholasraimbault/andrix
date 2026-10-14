# SPDX-License-Identifier: Apache-2.0
"""The checks that need no phone, on small SYNTHETIC install zips built in scratch.

Keys are generated for the test and thrown away. The zips copy the layout that
optimize-factory-image writes, with dummy firmware and dummy super splits. Nothing is
downloaded and no real kit is read.

Cases that build or verify vbmeta need external/avb/avbtool.py of the pinned tree. Name
that tree with ANDRIX_PIXEL_TREES (2026081300=TREE) or ANDRIX_GRAPHENEOS_ROOT.
"""
import contextlib
import errno
import gc
import hashlib
import inspect
import io
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import warnings
import weakref
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from caiman import Refusal  # noqa: E402
import install_zip as iz  # noqa: E402
import official  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'
RECORD = json.loads((FIXTURES / 'adevtool/records/2026100600.json').read_text())
INFO = (FIXTURES / 'adevtool/2026100600/vendor-skels/google_devices/caiman/firmware/'
        'android-info.txt').read_bytes()
PINNED_SIGNERS = ROOT / 'scripts/proof/tests/fixtures/grapheneos_carry/allowed_signers'
TREES = dict(item.split('=', 1) for item in os.environ.get('ANDRIX_PIXEL_TREES', '').split(':')
             if '=' in item)
PINNED_TREE = TREES.get('2026081300') or os.environ.get('ANDRIX_GRAPHENEOS_ROOT')
AVBTOOL = Path(PINNED_TREE) / 'external/avb/avbtool.py' if PINNED_TREE else None
HAVE_AVBTOOL = bool(AVBTOOL and AVBTOOL.is_file() and shutil.which('openssl'))
HAVE_SSH = bool(shutil.which('ssh-keygen'))
RELEASE = '2026100600'
BL, BB = 'ripcurrentpro-17.0-15819938', 'g5400c-260604-260807-B-16035863'
OLD_BL, OLD_BB = 'ripcurrentpro-17.0-15199480', 'g5400c-260317-260429-B-15308590'
ROLLBACK = 1791158400   # 2026-10-05T00:00:00Z
FINGERPRINT = 'google/caiman/caiman:17/CP3A.261005.005/{}:user/release-keys'
STATIC = ('boot', 'init_boot', 'dtbo', 'vendor_kernel_boot', 'pvmfw', 'vendor_boot')
PLAN_GOOD_LINE = ('Good "factory images" signature for contact@grapheneos.org with ED25519 key '
                  'SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM')


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=300, **kwargs)


def sha(data):
    return hashlib.sha256(data).hexdigest()


OLD_NS = 10 ** 18     # 2001-09-09T01:46:40Z: no write during a check leaves this modification time
TICK_NS = 2 * 10 ** 9     # a coarse timestamp clock, as on a filesystem with two second times
BOUNDARIES = ('during the copy', 'after the copy', 'after the signature check',
              'during the archive reads', 'after the archive checks')
CHANGES = ('replaced', 'removed', 'rewritten in place', 'rewritten in place, its times put back',
           'grown in place')
# The steps of the copy once its private directory exists, at which Watch can make it fail: a
# read of the zip, a write of the copy, the close of the copy, the close of the zip once the copy
# is complete, and the end of the digest.
COPY_STEPS = ('during the copy', 'writing the copy', 'closing the copy', 'closing the zip',
              'finishing the copy')
ERRORS = {'an I/O error': lambda: OSError(5, 'synthetic I/O error'),
          'an interruption': KeyboardInterrupt}
COPIERS = ('ZipCopy', 'check', 'andrix_identity', 'verified_image')
# The boundaries of the zip's private copy at which a real SIGINT is tested: the return of its
# constructor, the start of __enter__, right before its directory is made, right after, during the
# copy, the line of __enter__'s last return statement, once the copy is complete, and the with
# body. From the fourth on, the copy's directory exists.
LIFETIME = ('the constructor returns', 'the start of __enter__', 'the directory is to be made',
            'the directory is made', 'during the copy', 'the end of __enter__', 'the with body')
# The boundaries of a private directory that no handler covers, so that its backstop removes it
# once the interruption has gone on and the object is dropped: the return of __enter__, before the
# with statement holds the object, the start of __exit__, the start of remove_private, a line of
# shutil once its removal took an entry of the directory away, and the end of the removal, before
# the backstop is detached.
UNCOVERED = ('the return of __enter__', 'the start of __exit__', 'the start of the removal',
             'inside shutil.rmtree', 'the end of the removal')
# What can be at the path of a private directory before it is made: kinds of another's path.
TAKEN = ('a directory', 'a file', 'a link', 'a dangling link')
LOCKED = b'fastboot erase dpm_b\nfastboot flashing lock\n'
# A Python process that copies the zip at argv[2] under argv[3] (ZipCopy), with a real SIGINT
# through Python's default handler at argv[1] (UNCOVERED), and with argv[4] 'locked' once the
# copy's directory was made read only. Nothing catches the interruption, and Python exits
# through it.
INTERRUPTED_PROCESS = '''
import signal, sys
from pathlib import Path
import install_zip as iz
import test_install_zip as tests
boundary, source, root, locked = sys.argv[1:]
signal.signal(signal.SIGINT, signal.default_int_handler)

def fire():
    if locked == 'locked':
        tests.lock_private(Path(root))
    tests.interrupt()
with tests.at_boundary(boundary, 'zip-', fire):
    with iz.ZipCopy(source, root) as copy:
        pass
print('not interrupted')
'''
# The second boundaries of a private directory, once a first interruption kept its own cleanup
# from removing it: the call of its backstop, before any line of it, and the backstop's first line,
# before its handler is set up. No handler of the backstop can take an interruption there.
BACKSTOP_ENTRY = ('the call of the backstop', 'the first line of the backstop')
# A Python process that runs the plan in argv[1] (exit_after_two_interruptions) and then exits as
# a program does. With argv[2] 'sweep first', a finalizer made before install_zip is imported
# registers weakref.finalize._exitfunc before the exit sweep, so that atexit runs the sweep first;
# with 'sweep last', the first finalizer comes after, and atexit runs the sweep last.
TWICE_INTERRUPTED_PROCESS = '''
import json, sys, weakref
if sys.argv[2] == 'sweep first':
    class Anchor:
        pass
    anchor = Anchor()
    weakref.finalize(anchor, int)
import test_install_zip as tests
held = tests.exit_after_two_interruptions(json.loads(sys.argv[1]), sys.argv[2])
'''
# A Python process that owns a private directory under argv[1] and forks: the child ends through
# Python's exit, with its cleanup, while the parent waits, and the parent prints what is left in
# its directory once the child has exited, and then removes it.
FORKING_PROCESS = '''
import os, sys
import install_zip as iz
directory = iz.PrivateDirectory('probe-', sys.argv[1])
work = directory.__enter__()
(work / 'copy').write_bytes(b'private bytes')
child = os.fork()
if child:
    status = os.waitstatus_to_exitcode(os.waitpid(child, 0)[1])
    left = sorted(item.name for item in work.iterdir()) if work.is_dir() else 'gone'
    print(status, left, flush=True)
    if work.is_dir():
        directory.__exit__(None, None, None)
'''


def changes(path, data):
    """How a zip can change under its path: replaced through a rename by data, removed, rewritten
    in place with its size kept (a byte near its start and one in its middle), rewritten so with
    its times put back to OLD_NS, or grown in place with its times put back."""
    def replaced():
        path.with_name('replacement').write_bytes(data)
        os.replace(path.with_name('replacement'), path)

    def rewritten():
        with open(path, 'r+b') as handle:
            for offset in (100, path.stat().st_size // 2):
                handle.seek(offset)
                byte = handle.read(1)
                handle.seek(offset)
                handle.write(bytes([byte[0] ^ 0xff]))

    def dated_back():
        os.utime(path, ns=(OLD_NS, OLD_NS))

    def rewritten_and_dated_back():
        rewritten()
        dated_back()

    def grown():
        with open(path, 'ab') as handle:
            handle.write(b'more')
        dated_back()
    return {'replaced': replaced, 'removed': path.unlink, 'rewritten in place': rewritten,
            'rewritten in place, its times put back': rewritten_and_dated_back,
            'grown in place': grown}


def rewritten_and_restored(path, data):
    """Two changes: the zip rewritten in place by data, a valid archive of its size, and then put
    back, each with the zip's times put back. This is the probe that found one shared handle not
    enough, when both writes fell within one tick of a coarse timestamp clock."""
    original = path.read_bytes()

    def write(content):
        with open(path, 'r+b') as handle:
            handle.write(content)
        os.utime(path, ns=(OLD_NS, OLD_NS))
    return (lambda: write(data)), (lambda: write(original))


def restore(path, data):
    """Puts the zip's bytes back at path, as a new file with the modification time OLD_NS."""
    path.with_name('restored').write_bytes(data)
    os.utime(path.with_name('restored'), ns=(OLD_NS, OLD_NS))
    os.replace(path.with_name('restored'), path)


class CoarseStat:
    """A stat result whose modification and change times have the resolution TICK_NS."""

    def __init__(self, actual):
        self.actual = actual
        self.st_mtime_ns = actual.st_mtime_ns // TICK_NS * TICK_NS
        self.st_ctime_ns = actual.st_ctime_ns // TICK_NS * TICK_NS

    def __getattr__(self, name):
        return getattr(self.actual, name)


def coarse_times(path, coarse=True):
    """A patch under which os.fstat gives the file now at path coarse times, as a filesystem
    whose timestamp clock ticks every TICK_NS would, or no patch."""
    if not coarse:
        return contextlib.nullcontext()
    target, fstat = path.stat(), os.fstat

    def coarse_fstat(descriptor):
        actual = fstat(descriptor)
        if (actual.st_dev, actual.st_ino) != (target.st_dev, target.st_ino):
            return actual
        return CoarseStat(actual)
    return mock.patch.object(iz.os, 'fstat', coarse_fstat)


class Reading:
    """The zip's handle while install_zip copies it. Its first read is kept to 1024 bytes and is
    followed by the change at 'during the copy'. The read that finds the zip's end is followed by
    the change at 'after the copy', and its close by the change at 'closing the zip'. The bytes
    read up to that end go to watch.copied."""

    def __init__(self, handle, watch):
        self.handle, self.watch, self.first, self.ended = handle, watch, True, False

    def read(self, size=-1):
        first, self.first = self.first, False
        data = self.handle.read(1024 if first else size)
        if not self.ended:
            self.watch.copied += data
            if not data:
                self.ended = True
                self.watch.change('after the copy')
        if first:
            self.watch.change('during the copy')
        return data

    def __getattr__(self, name):
        return getattr(self.handle, name)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.handle.close()
        self.watch.change('closing the zip')


class Writing:
    """The zip's private copy while install_zip writes it. Its first write is followed by the
    change at 'writing the copy', and its close by the change at 'closing the copy'."""

    def __init__(self, handle, watch):
        self.handle, self.watch, self.first = handle, watch, True

    def write(self, data):
        written = self.handle.write(data)
        first, self.first = self.first, False
        if first:
            self.watch.change('writing the copy')
        return written

    def __getattr__(self, name):
        return getattr(self.handle, name)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.handle.close()
        self.watch.change('closing the copy')


class Watch:
    """Watches install_zip read the zip at path, and runs each change of plan once, at its
    boundary (BOUNDARIES): after the zip's first read, after the read that found its end, after
    ssh-keygen returned, after the first archive member was read (avb_pkmd.bin), or after the
    last archive read (the firmware digests). The steps of the copy (COPY_STEPS) are boundaries
    too: after the copy's first write, after the copy's close, after the zip's close, and when
    the digest of the bytes copied is finished. A change that raises makes its step fail.

    copied receives the bytes read from the zip up to its end, verified the bytes that each
    ssh-keygen had as its standard input, and members each archive member read, with its bytes.
    plan keeps the changes that did not run."""

    def __init__(self, path, plan=None):
        self.path, self.plan = Path(path), dict(plan or {})
        self.copied, self.verified, self.members, self.opened = b'', [], [], False
        self.writing = False
        self.patches = contextlib.ExitStack()

    def change(self, boundary):
        change = self.plan.pop(boundary, None)
        if change is not None:
            change()

    def __enter__(self):
        real_open, real_run, read = open, subprocess.run, iz.Archive.read
        verify, firmware = iz.check_signature, iz._firmware
        watch = self

        def watched_open(file, mode='r', *args, **kwargs):
            handle = real_open(file, mode, *args, **kwargs)
            if Path(file) == self.path and not self.opened:
                self.opened = True
                return Reading(handle, self)
            if Path(file).parent.name.startswith('zip-') and 'r' not in mode and not self.writing:
                self.writing = True
                return Writing(handle, self)
            return handle

        class Digest:
            """install_zip's hashlib.sha256, whose end is the boundary 'finishing the copy'."""

            def __init__(self, *data):
                self.digest = hashlib.sha256(*data)

            def update(self, data):
                self.digest.update(data)

            def hexdigest(self):
                watch.change('finishing the copy')
                return self.digest.hexdigest()

        def watched_run(command, *args, **kwargs):
            if list(command[:3]) == ['ssh-keygen', '-Y', 'verify']:
                descriptor = kwargs['stdin'].fileno()
                self.verified.append(os.pread(descriptor, os.fstat(descriptor).st_size, 0))
            return real_run(command, *args, **kwargs)

        def watched_read(archive, name, *args, **kwargs):
            data = read(archive, name, *args, **kwargs)
            self.members.append((name, data))
            if name == 'avb_pkmd.bin':
                self.change('during the archive reads')
            return data

        def watched_verify(*args, **kwargs):
            try:
                return verify(*args, **kwargs)
            finally:
                self.change('after the signature check')

        def watched_firmware(*args):
            found = firmware(*args)
            self.change('after the archive checks')
            return found
        for owner, name, value in ((iz, 'open', watched_open), (iz.subprocess, 'run', watched_run),
                                   (iz.Archive, 'read', watched_read),
                                   (iz, 'check_signature', watched_verify),
                                   (iz, '_firmware', watched_firmware),
                                   (iz, 'hashlib', types.SimpleNamespace(sha256=Digest))):
            self.patches.enter_context(mock.patch.object(owner, name, value, create=name == 'open'))
        return self

    def __exit__(self, *exception):
        self.patches.close()


def read_as_copied(case, watch, report):
    """The report's SHA-256 names the bytes that were copied, and ssh-keygen and every archive
    read saw exactly those bytes, never the zip as it is now."""
    case.assertEqual(report['sha256'], sha(watch.copied))
    case.assertEqual(report['checks']['inputs']['detail']['sha256'], sha(watch.copied))
    case.assertEqual(watch.verified, [watch.copied])
    members = {}
    with zipfile.ZipFile(io.BytesIO(watch.copied)) as archive:
        for info in archive.infolist():
            with contextlib.suppress(zipfile.BadZipFile):     # a member that a change broke
                members[PurePosixPath(info.filename).name] = archive.read(info)
    case.assertTrue(watch.members)
    for name, data in watch.members:
        case.assertEqual(data, members.get(name), name)


def kind_of(path, root):
    """A private file or directory under root, named by the prefix of its directory."""
    parts = path.relative_to(root).parts
    return (parts[0].split('-')[0],) + parts[1:]


def outcome(call):
    """What call returns, or the exception it raises, an interruption too, so that a test can
    look at it."""
    try:
        return call()
    except BaseException as error:
        return error


def copied_by(copier, kit, path, root):
    """Copies the zip at path under root as copier (COPIERS) does: ZipCopy itself, whose with body
    reads one member of the copy, check, andrix_identity, or version_criterion.verified_image, as
    decide reads a kit, with this kit's identity kept under the zip's SHA-256 and the system's
    temporary directory at root. Its result, for a copy that fails before any check needs
    avbtool."""
    if copier == 'ZipCopy':
        with iz.ZipCopy(path, root) as copy:
            archive = iz.Archive(copy.path, RELEASE)
            try:
                archive.read('android-info.txt')
            finally:
                archive.zip.close()
            return copy.sha256
    if copier == 'check':
        return kit.check(path, scratch=root)
    if copier == 'andrix_identity':
        return iz.andrix_identity(path, avbtool=None, scratch=root)
    import version_criterion as vc
    digest, info = sha(Path(path).read_bytes()), iz.caiman.parse_android_info(INFO)
    kept = vc.Image('grapheneos', digest, iz.caiman.parse_release(RELEASE), 'CP3A.261005.005',
                    info, 'this kit')
    session = {'verified': {digest: vc.identity_entry(kept, '2026-10-09T10:01:00Z')}}
    with mock.patch.object(tempfile, 'tempdir', str(root)):
        return vc.verified_image(session, path, 'grapheneos',
                                 vc.Table({RELEASE: 'CP3A.261005.005'}, {RELEASE: info}, {}))


@contextlib.contextmanager
def default_interruptions():
    """Python's own handler of SIGINT, which raises KeyboardInterrupt, for the duration."""
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def interrupt():
    """A real SIGINT. Python's default handler raises KeyboardInterrupt where it takes the signal,
    which is right here, after the call of raise_signal."""
    signal.raise_signal(signal.SIGINT)


@contextlib.contextmanager
def after_mkdir(prefix, action, before=False):
    """os.mkdir, which runs action with the path once it made the first directory whose name
    starts with prefix, or with before, right before it makes it. The paths it ran action for
    are given."""
    made, done = os.mkdir, []

    def mkdir(path, *args, **kwargs):
        if not done and Path(path).name.startswith(prefix):
            done.append(Path(path))
            if before:
                action(Path(path))
            made(path, *args, **kwargs)
            if not before:
                action(Path(path))
            return
        made(path, *args, **kwargs)
    with mock.patch.object(iz.os, 'mkdir', mkdir):
        yield done


def last_return_line(function):
    """The line of the last return statement in function."""
    lines, first = inspect.getsourcelines(function)
    return first + max(index for index, text in enumerate(lines)
                       if text.lstrip().startswith('return'))


@contextlib.contextmanager
def traced(boundary, action):
    """A trace function, as a debugger sets one, that runs action once at boundary of a ZipCopy:
    the return of its constructor, the first line of its __enter__, or the line of __enter__'s
    last return statement. An exception that action raises is raised in the traced frame."""
    if boundary == 'the constructor returns':
        code, event, line = iz.ZipCopy.__init__.__code__, 'return', None
    else:
        enter = iz.ZipCopy.__enter__
        code, event = enter.__code__, 'line'
        line = None if boundary == 'the start of __enter__' else last_return_line(enter)
    done = []

    def local(frame, what, arg):
        if not done and what == event and (line is None or frame.f_lineno == line) \
                and isinstance(frame.f_locals.get('self'), iz.ZipCopy):
            done.append(frame.f_lineno)
            action()
        return local

    previous = sys.gettrace()
    sys.settrace(lambda frame, what, arg: local if frame.f_code is code and not done else None)
    try:
        yield done
    finally:
        sys.settrace(previous)


@contextlib.contextmanager
def interrupted(boundary, path, before=None):
    """A real SIGINT, once, at boundary (LIFETIME) of the private copy of the zip at path, after
    before, when given, has run. The boundaries of the constructor and of __enter__ are taken
    with a trace function; the others by os.mkdir, the zip's handle (Watch) or the first member
    read (Archive.read). The boundary is given in a list once the signal was sent."""
    fired = []

    def fire(*_):
        fired.append(boundary)
        if before is not None:
            before()
        interrupt()
    with contextlib.ExitStack() as stack:
        stack.enter_context(default_interruptions())
        if boundary in ('the directory is to be made', 'the directory is made'):
            stack.enter_context(after_mkdir('zip-', fire, before=boundary.endswith('to be made')))
        elif boundary == 'during the copy':
            stack.enter_context(Watch(path, {'during the copy': fire}))
        elif boundary == 'the with body':
            read = iz.Archive.read

            def first_read(archive, *args, **kwargs):
                if not fired:
                    fire()
                return read(archive, *args, **kwargs)
            stack.enter_context(mock.patch.object(iz.Archive, 'read', first_read))
        else:
            stack.enter_context(traced(boundary, fire))
        yield fired


@contextlib.contextmanager
def at_boundary(boundary, prefix, action):
    """A trace function, as a debugger sets one, that runs action once at boundary (UNCOVERED) of
    the first private directory whose name starts with prefix: the return of its __enter__, the
    first line of its __exit__, the first line or the return of remove_private for it, or the
    first line that shutil runs once the removal took one of the directory's entries away. An
    exception that action raises is raised in the traced frame. The boundary is given in a list
    once action ran."""
    enter, leave = iz.PrivateDirectory.__enter__.__code__, iz.PrivateDirectory.__exit__.__code__
    remove = iz.remove_private.__code__
    code, event = {'the return of __enter__': (enter, 'return'),
                   'the start of __exit__': (leave, 'line'),
                   'the start of the removal': (remove, 'line'),
                   'inside shutil.rmtree': (None, 'line'),
                   'the end of the removal': (remove, 'return')}[boundary]
    done, removing = [], []

    def ours(frame):
        if frame.f_code is remove:
            return Path(frame.f_locals['work']).name.startswith(prefix)
        return getattr(frame.f_locals.get('self'), 'prefix', None) == prefix

    def entries(directory):
        try:
            return len(os.listdir(directory))
        except OSError:
            return -1

    def local(frame, what, arg):
        if done or what != event:
            return local
        if code is None:    # inside shutil.rmtree, once an entry of the directory is gone
            directory, count = removing[0]
            if not 0 <= entries(directory) < count:
                return local
        done.append(boundary)
        action()
        return local

    def start(frame, what, arg):
        if done:
            return None
        if frame.f_code is remove and not removing and ours(frame):
            removing.append((Path(frame.f_locals['work']),
                             entries(frame.f_locals['work'])))
        if code is None:
            return local if removing and frame.f_code.co_filename == shutil.__file__ else None
        return local if frame.f_code is code and ours(frame) else None
    previous = sys.gettrace()
    sys.settrace(start)
    try:
        yield done
    finally:
        sys.settrace(previous)


@contextlib.contextmanager
def at_entry_event(index, prefix, action):
    """A trace function that runs action once, at the event numbered index, from 0, among the
    lines and the return of the __enter__ of the first private directory whose name starts with
    prefix. The event and its line are given in a list once action ran, and the lines of every
    event up to it in a second list."""
    enter, seen, done = iz.PrivateDirectory.__enter__.__code__, [], []

    def local(frame, what, arg):
        if not done and what in ('line', 'return'):
            seen.append(frame.f_lineno)
            if len(seen) == index + 1:
                done.append((what, frame.f_lineno))
                action()
        return local

    def start(frame, what, arg):
        if frame.f_code is enter and not seen and \
                getattr(frame.f_locals.get('self'), 'prefix', None) == prefix:
            return local
        return None
    previous = sys.gettrace()
    sys.settrace(start)
    try:
        yield done, seen
    finally:
        sys.settrace(previous)


def interrupted_at(boundary, prefix, call):
    """call with a real SIGINT, through Python's default handler, at boundary (UNCOVERED) of its
    private directory whose name starts with prefix. Gives the boundaries reached and the type of
    what call raised or returned, only once that exception and everything its traceback held are
    dropped and garbage is collected, as when the interruption has gone on."""
    with default_interruptions(), at_boundary(boundary, prefix, interrupt) as done:
        result = outcome(call)
    kind = type(result)
    del result
    gc.collect()
    return done, kind


@contextlib.contextmanager
def finalizer_output():
    """The lines that finalizers, such as the backstops of private directories, write on stderr
    meanwhile, and what they raise, which Python reports as unraisable, as 'Type: value'. Both
    lists are complete once the block ends and garbage is collected."""
    stream, raised, lines = io.StringIO(), [], []

    def unraisable(found):
        raised.append(f'{found.exc_type.__name__}: {found.exc_value}')
    with contextlib.redirect_stderr(stream), mock.patch.object(sys, 'unraisablehook', unraisable):
        try:
            yield lines, raised
        finally:
            gc.collect()
    lines.extend(stream.getvalue().splitlines())


@contextlib.contextmanager
def backstop_warnings():
    """The lines that the backstops of private directories write on stderr meanwhile, in a list
    that is complete once the block ends and garbage is collected. A finalizer that raises fails
    the block: the backstop warns instead."""
    with finalizer_output() as (lines, raised):
        yield lines
    if raised:
        raise AssertionError(f'a finalizer raised instead of warning: {raised}')


def backstop_trace(boundary, prefix, action, done):
    """A trace function, as a debugger sets one, that runs action once, at boundary
    (BACKSTOP_ENTRY) of the backstop of the first private directory whose name starts with prefix,
    as weakref.finalize calls it: at its call, before any of its lines, or at its first line. An
    exception that action raises is raised there. done receives the boundary once action ran."""
    code, caller = iz.remove_leftover.__code__, weakref.finalize.__call__.__code__

    def local(frame, what, arg):
        if not done and what == 'line':
            done.append(boundary)
            action()
        return local

    def start(frame, what, arg):
        if done or frame.f_code is not code or frame.f_back is None \
                or frame.f_back.f_code is not caller \
                or not os.path.basename(frame.f_locals['work']).startswith(prefix):
            return None
        if boundary == BACKSTOP_ENTRY[0]:
            done.append(boundary)
            action()
            return None
        return local
    return start


@contextlib.contextmanager
def at_backstop(boundary, prefix, action):
    """backstop_trace for the duration. The boundary is given in a list once action ran."""
    done, previous = [], sys.gettrace()
    sys.settrace(backstop_trace(boundary, prefix, action, done))
    try:
        yield done
    finally:
        sys.settrace(previous)


def sweep_trace(action, done):
    """A trace function that runs action once, at the call of the exit sweep, before any of its
    lines, where no handler of the sweep can take an exception that action raises. done receives
    the boundary once action ran."""
    code = iz.sweep_at_exit.__code__

    def start(frame, what, arg):
        if not done and frame.f_code is code:
            done.append('the call of the exit sweep')
            action()
        return None
    return start


def lock_prefixed(root, prefix):
    """Makes every directory in root whose name starts with prefix read only, so that the copies
    in it cannot be removed."""
    for directory in root.glob(f'{prefix}*'):
        directory.chmod(0o500)


def unlock_and_remove(root):
    """Makes every directory under root writable again and removes root."""
    for directory in [root, *root.rglob('*')]:
        if directory.is_dir() and not directory.is_symlink():
            directory.chmod(0o700)
    shutil.rmtree(root)


def interrupted_twice(prefix, call, second, lock=None):
    """call with a real SIGINT, through Python's default handler, at the start of __exit__ of its
    private directory whose name starts with prefix, once that directory is made read only when
    lock, its parent, is given. Once that interruption has gone on, a second real SIGINT comes at
    second (BACKSTOP_ENTRY) of the directory's backstop, as the first is dropped and garbage is
    collected. Gives the boundaries reached and the type of what call raised or returned."""
    def fire():
        if lock is not None:
            lock_prefixed(lock, prefix)
        interrupt()
    with default_interruptions():
        with at_boundary('the start of __exit__', prefix, fire) as first:
            result = outcome(call)
        kind = type(result)
        with at_backstop(second, prefix, interrupt) as reached:
            del result
            gc.collect()
    return first + reached, kind


@contextlib.contextmanager
def at_event(index, codes, action):
    """A trace function that runs action once, at the event numbered index, from 0, among the
    calls, lines and returns of the functions whose code objects codes holds. The event, its
    function and its line are given in a list once action ran, and every event seen up to it in
    a second list."""
    seen, done = [], []

    def fire(frame, what):
        seen.append((frame.f_code.co_name, what, frame.f_lineno))
        if len(seen) == index + 1:
            done.append(seen[-1])
            action()

    def local(frame, what, arg):
        if not done and what in ('line', 'return'):
            fire(frame, what)
        return local

    def start(frame, what, arg):
        if done or frame.f_code not in codes:
            return None
        fire(frame, 'call')
        return local
    previous = sys.gettrace()
    sys.settrace(start)
    try:
        yield done, seen
    finally:
        sys.settrace(previous)


def warnings_naming(lines, path):
    """The warnings among lines that name the private directory at path as one that could not be
    removed."""
    return [line for line in lines
            if line.startswith(f'warning: the private directory {path} could not be removed: ')]


def owned_under(root):
    """The paths in install_zip's registry of owned directories that lie in root."""
    return sorted(path for path in iz.OWNED if Path(path).parent == Path(root))


def called_as(case, plan, kit):
    """Runs case of plan (exit_after_two_interruptions) as its caller does: a zip copied by a
    caller of COPIERS, the signed tags of plan['tags'] verified, or the kit of plan['dynamic']
    checked with its dynamic partitions rebuilt from its super splits by plan['tools']."""
    root, caller = Path(case['root']), case['caller']
    if caller in COPIERS:
        return copied_by(caller, kit, Path(plan['zip']), root)
    if caller == 'signed_tags':
        import version_criterion as vc
        tags = plan['tags']
        with mock.patch.object(tempfile, 'tempdir', str(root)):
            release = iz.caiman.parse_release('2026081300')
            return vc.signed_tags(tags['repo'], tags['signers'], release, release,
                                  bases=tags['bases'])
    tools = plan['tools']
    with mock.patch.object(iz, 'SIMG2IMG_SHA256', sha(Path(tools['simg2img']).read_bytes())), \
            mock.patch.object(iz, 'LPUNPACK_SHA256', sha(Path(tools['lpunpack']).read_bytes())):
        return kit.check(Path(plan['dynamic']), scratch=root, tools=tools)


def case_name(case):
    """The name of case of a plan (exit_after_two_interruptions)."""
    return f"{case['prefix']} {case['caller']}{' locked' if case['locked'] else ''}"


def exit_after_two_interruptions(plan, order):
    """Runs in a Python process that exits once this returns (TWICE_INTERRUPTED_PROCESS), with
    the exit sweep run first or last at that exit (order). Each case of plan runs as its caller
    does (called_as), with a real SIGINT through Python's default handler at the start of
    __exit__ of its private directory, once that directory is made read only when the case is
    locked. The interruption is caught. With plan['when'] 'collection', the case is then dropped
    with a second real SIGINT at plan['second'] (BACKSTOP_ENTRY) of its backstop, as garbage is
    collected. With 'exit', every interruption, and so every directory's object, is kept until
    the process exits, given back for that, and plan['second'] of the first backstop that runs at
    the exit takes the second SIGINT. plan['sweep'] 'interrupted' sends one at the call of the
    exit sweep instead. Prints, as JSON, the boundaries that each case reached."""
    signal.signal(signal.SIGINT, signal.default_int_handler)
    registered = weakref.finalize._registered_with_atexit
    if registered != (order == 'sweep first'):
        raise AssertionError(f'{order}, but _exitfunc registered already: {registered}')
    kit = Kit.reopened(plan['kit'])
    held, reached = [], {}
    for case in plan['cases']:
        root = Path(case['root'])

        def fire(case=case, root=root):
            if case['locked']:
                lock_prefixed(root, case['prefix'])
            interrupt()
        with at_boundary('the start of __exit__', case['prefix'], fire) as first:
            result = outcome(lambda: called_as(case, plan, kit))
        if not isinstance(result, KeyboardInterrupt):
            raise AssertionError(f'{case} was not interrupted: {result!r}')
        second = []
        if plan['when'] == 'collection':
            with at_backstop(plan['second'], case['prefix'], interrupt) as second:
                del result
                gc.collect()
        else:
            held.append(result)
        reached[case_name(case)] = first + second
    print(json.dumps(reached), flush=True)
    if plan['when'] == 'exit' and plan['second']:
        sys.settrace(backstop_trace(plan['second'], '', interrupt, []))
    if plan['sweep'] == 'interrupted':
        sys.settrace(sweep_trace(interrupt, []))
    return held


def assert_stopped_backstops_leave_their_directories_to_the_sweep(test, plan):
    """For each case of plan (exit_after_two_interruptions) and each boundary of BACKSTOP_ENTRY,
    in this process: a first real SIGINT at the start of __exit__ of the case's private directory,
    and a second at that boundary of its backstop, as the first is dropped and garbage is
    collected (interrupted_twice). Nothing in the backstop can take the second: Python reports a
    KeyboardInterrupt that the finalizer raised, and no warning comes. The directory stays, and
    stays owned. The exit sweep (sweep_at_exit) then removes it, without a warning, or, when the
    case is locked, names it in one warning and leaves it owned."""
    kit = Kit.reopened(plan['kit'])
    for case, second in itertools.product(plan['cases'], BACKSTOP_ENTRY):
        with test.subTest(directory=case['prefix'], caller=case['caller'], second=second,
                          locked=case['locked']):
            root = Path(tempfile.mkdtemp(dir=plan['work']))
            case = dict(case, root=str(root))
            before = set(iz.OWNED)
            try:
                with finalizer_output() as (lines, raised):
                    reached, kind = interrupted_twice(
                        case['prefix'], lambda: called_as(case, plan, kit), second,
                        root if case['locked'] else None)
                test.assertEqual((reached, kind, lines, raised),
                                 (['the start of __exit__', second], KeyboardInterrupt, [],
                                  ['KeyboardInterrupt: ']))
                [left] = set(iz.OWNED) - before
                test.assertTrue(Path(left).name.startswith(case['prefix']))
                # the splits lie in the directory of the extracted images, which its own removal
                # took away with them; every other directory is left with its copies
                nested = case['prefix'] == 'splits-'
                test.assertEqual(Path(left).is_dir(), not nested)
                stream = io.StringIO()
                with contextlib.redirect_stderr(stream):
                    test.assertIsNone(iz.sweep_at_exit())
                swept = stream.getvalue().splitlines()
                if case['locked']:
                    test.assertEqual(len(warnings_naming(swept, left)), 1, swept)
                    test.assertTrue(Path(left).is_dir())
                    test.assertIn(left, iz.OWNED)
                else:
                    test.assertEqual(warnings_naming(swept, left), [])
                    test.assertNotIn(left, iz.OWNED)
                    test.assertEqual(list(root.iterdir()), [])
            finally:
                unlock_and_remove(root)


def assert_python_exit_removes_what_stopped_backstops_left(test, plan):
    """Runs the cases of plan (exit_after_two_interruptions) in Python processes that exit once
    they ran: with the second real SIGINT at each boundary of BACKSTOP_ENTRY of every backstop as
    the first interruptions are dropped and collected, or of the first backstop that runs at the
    exit, with the exit sweep first or last at that exit. Once the process exited, nothing is
    left of any case, but the directories of the locked cases, each named in one warning on
    stderr. Then the limit, the exit sweep itself interrupted at its call: what it did not reach
    stays, unnamed, but at the exit the backstops that run after it remove what they own."""
    scenarios = [('collection', second, 'sweep last', None) for second in BACKSTOP_ENTRY]
    scenarios += [('exit', second, order, None) for second in BACKSTOP_ENTRY
                  for order in ('sweep last', 'sweep first')]
    scenarios += [('collection', BACKSTOP_ENTRY[0], 'sweep last', 'interrupted'),
                  ('exit', None, 'sweep first', 'interrupted')]
    for when, second, order, sweep in scenarios:
        with test.subTest(when=when, second=second, order=order, sweep=sweep):
            work = Path(tempfile.mkdtemp(dir=plan['work']))
            cases = [dict(case, root=str(work / str(index)))
                     for index, case in enumerate(plan['cases'])]
            for case in cases:
                Path(case['root']).mkdir()
            try:
                status, reached, stderr = exit_twice_interrupted(
                    dict(plan, cases=cases, when=when, second=second, sweep=sweep), order)
                test.assertEqual(status, 0, stderr)
                expected = ['the start of __exit__'] + ([second] if when == 'collection' else [])
                test.assertEqual(reached, {case_name(case): expected for case in cases}, stderr)
                if when == 'collection':
                    test.assertEqual(stderr.count('Exception ignored in: <finalize object'),
                                     len(cases), stderr)
                if second and when == 'exit':
                    test.assertIn('Exception ignored in atexit callback <bound method '
                                  'finalize._exitfunc', stderr)
                if sweep:
                    test.assertIn('Exception ignored in atexit callback <function sweep_at_exit',
                                  stderr)
                lines = stderr.splitlines()
                for case in cases:
                    root = Path(case['root'])
                    left = sorted(root.rglob(f"{case['prefix']}*"))
                    if when == 'collection' and sweep and case['prefix'] != 'splits-':
                        # the limit: no backstop is left to run after the interrupted sweep
                        test.assertEqual((len(left), warnings_naming(lines, left[0])), (1, []))
                    elif case['locked']:
                        test.assertEqual(len(left), 1, stderr)
                        test.assertEqual(len(warnings_naming(lines, left[0])), 1, stderr)
                    else:
                        test.assertEqual(list(root.iterdir()), [], stderr)
            finally:
                unlock_and_remove(work)


def exit_twice_interrupted(plan, order='sweep last'):
    """Runs plan (exit_after_two_interruptions) in a Python process that exits once it ran, with
    the exit sweep first or last at that exit (order). Gives the process's exit status, the
    boundaries that each case reached, and its stderr."""
    here = Path(__file__).resolve().parent
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PYTHONPATH=os.pathsep.join((str(here.parent), str(here))))
    process = subprocess.run([sys.executable, '-B', '-c', TWICE_INTERRUPTED_PROCESS,
                              json.dumps(plan), order], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, timeout=120)
    stdout = process.stdout.decode()
    return process.returncode, json.loads(stdout) if stdout else {}, process.stderr.decode()


def entered(directory):
    """Enters directory, a PrivateDirectory, in its with statement, as its callers do, and leaves
    it at once."""
    with directory:
        return 'entered'


def lock_private(root):
    """Makes every directory in root read only, so that the copies in them cannot be removed."""
    for directory in root.iterdir():
        directory.chmod(0o500)


def unlock_private(root):
    """Undoes lock_private."""
    for directory in root.iterdir():
        directory.chmod(0o700)


def warning_of(root, prefix, reason):
    """The pattern of the backstop's warning that it could not remove a private directory under
    root whose name starts with prefix, for reason, a pattern."""
    return (f'^warning: the private directory {re.escape(str(root))}/{prefix}[0-9a-f]+ could '
            f'not be removed: {reason}')


def make_taken(path, kind, victim):
    """Puts kind (TAKEN) of another's path at path: a directory with a file in it, a file, a link
    to victim, or a link to nowhere."""
    if kind == 'a directory':
        path.mkdir()
        (path / 'victim').write_bytes(b'not to be removed')
    elif kind == 'a file':
        path.write_bytes(b'not to be removed')
    elif kind == 'a link':
        path.symlink_to(victim)
    else:
        path.symlink_to(victim.with_name('nowhere'))


def everything(root):
    """Every path under root, with its kind and its bytes or the target of its link."""
    found = []
    for item in sorted(root.rglob('*')):
        if item.is_symlink():
            found.append((str(item.relative_to(root)), 'link', os.readlink(item)))
        elif item.is_dir():
            found.append((str(item.relative_to(root)), 'directory', None))
        else:
            found.append((str(item.relative_to(root)), 'file', item.read_bytes()))
    return found


@contextlib.contextmanager
def source_reads(path):
    """How install_zip reads the zip at path: each open of it through install_zip's open, each
    read of that handle with the offset it started at and the number of bytes it gave, any seek
    or other read of the handle, and any read of the zip's file through os, such as os.pread."""
    path = Path(path)
    status = path.stat()
    identity, real_open = (status.st_dev, status.st_ino), open
    seen = {'opens': 0, 'reads': [], 'other': [], 'os': []}

    class Recorded:
        def __init__(self, handle):
            self.handle = handle

        def read(self, *args):
            offset = os.lseek(self.handle.fileno(), 0, os.SEEK_CUR)
            data = self.handle.read(*args)
            seen['reads'].append((offset, len(data)))
            return data

        def __getattr__(self, name):
            if name.startswith(('read', 'seek', 'peek')):
                seen['other'].append(name)
            return getattr(self.handle, name)

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            self.handle.close()

    def recorded_open(file, *args, **kwargs):
        handle = real_open(file, *args, **kwargs)
        if Path(file) == path:
            seen['opens'] += 1
            return Recorded(handle)
        return handle

    def watched(name):
        real = getattr(os, name)

        def call(descriptor, *args, **kwargs):
            with contextlib.suppress(OSError):
                found = os.fstat(descriptor)
                if (found.st_dev, found.st_ino) == identity:
                    seen['os'].append(name)
            return real(descriptor, *args, **kwargs)
        return call
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(iz, 'open', recorded_open, create=True))
        for name in ('read', 'pread', 'readv', 'preadv'):
            stack.enter_context(mock.patch.object(iz.os, name, watched(name)))
        yield seen


def unblock_later(fifo, done, delay=3):
    """After delay seconds, gives a reader that waits to open the FIFO an end of file, so that a
    check that waits for a writer fails instead of hanging."""
    if done.wait(delay):
        return
    while not done.wait(0.05):
        with contextlib.suppress(OSError):    # nothing reads the FIFO yet
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))


def member_keyword(name):
    """The keyword that Kit.zip takes for the member called name."""
    return name.replace('.', '__').replace('-', '_dash_')


class Kit:
    """One synthetic kit: keys, images, vbmeta and the zip members."""

    def __init__(self, work, avb):
        self.work = Path(work)
        self.avb = avb
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', self.work / 'ssh')
        kind, blob = (self.work / 'ssh.pub').read_text().split()[:2]
        self.signers = self.work / 'allowed_signers'
        self.signers.write_text(f'contact@grapheneos.org {kind} {blob}\n')
        self.fingerprint = run('ssh-keygen', '-l', '-f', self.work / 'ssh.pub').stdout.decode().split()[1]
        self.bases = self.work / 'bases'
        self.bases.mkdir()
        base = json.loads((ROOT / 'upstream/bases/2026100600.json').read_text())
        base['manifest']['allowed_signers_sha256'] = sha(self.signers.read_bytes())
        (self.bases / '2026100600.json').write_text(json.dumps(base))
        self.stable = self.stable_file('2026100600')
        legacy = official.render_legacy(RELEASE, BL, BB)
        self.members = {
            'flash-all.sh': official.capture(legacy, splits=2), 'flash-all.bat': b'synthetic\r\n',
            'script.txt': b'synthetic\n', 'android-info.txt': INFO, 'android-info.zip': b'synthetic',
            f'bootloader-caiman-{BL}.img': b'synthetic bootloader',
            f'radio-caiman-{BB.lower()}.img': b'synthetic radio',
            'super_1.img': b'synthetic super 1', 'super_2.img': b'synthetic super 2'}
        if avb:
            self.rsa = self.key('avb')
            run(sys.executable, '-B', AVBTOOL, 'extract_public_key', '--key', self.rsa, '--output',
                self.work / 'avb_pkmd.bin')
            self.members['avb_pkmd.bin'] = (self.work / 'avb_pkmd.bin').read_bytes()
            for name in STATIC:
                self.members[f'{name}.img'] = self.image(name)
            self.members['vbmeta.img'] = self.vbmeta()
        else:
            self.members['avb_pkmd.bin'] = b'synthetic avb key'
            for name in STATIC + ('vbmeta',):
                self.members[f'{name}.img'] = f'synthetic {name}'.encode()
        self.count = 0

    def key(self, name):
        path = self.work / f'{name}.pem'
        run('openssl', 'genrsa', '-out', path, '4096')
        return path

    def stable_file(self, release):
        path = self.work / f'stable-{release}'
        path.write_text(f'{release} 1791230000 caiman stable\n')
        return path

    def image(self, name, size=4096, kind='hash'):
        path = self.work / f'{name}.img'
        path.write_bytes(bytes([len(name)]) * size)
        props = (['--prop', f'com.android.build.boot.fingerprint:{FINGERPRINT.format(RELEASE)}']
                 if name == 'boot' else [])
        if kind == 'hash':
            run(sys.executable, '-B', AVBTOOL, 'add_hash_footer', '--image', path, '--partition_name',
                name, '--partition_size', 262144, *props)
        else:
            run(sys.executable, '-B', AVBTOOL, 'add_hashtree_footer', '--image', path,
                '--partition_name', name, '--partition_size', 1048576, '--do_not_generate_fec')
        return path.read_bytes()

    def vbmeta(self, key=None, algorithm='SHA256_RSA4096', rollback=ROLLBACK, flags=0, props=None,
               include=STATIC, extra=(), location=0):
        if props is None:
            props = [('com.android.build.system.fingerprint', FINGERPRINT.format(RELEASE)),
                     ('com.android.build.system.security_patch', '2026-10-05')]
        for name in include:
            (self.work / f'{name}.img').write_bytes(self.members.get(f'{name}.img') or
                                                    (self.work / f'{name}.img').read_bytes())
        args = ['make_vbmeta_image', '--output', self.work / 'vbmeta.img', '--rollback_index',
                rollback, '--flags', flags, '--rollback_index_location', location]
        if algorithm != 'NONE':
            args += ['--key', key or self.rsa, '--algorithm', algorithm]
        for prop, value in props:
            args += ['--prop', f'{prop}:{value}']
        for name in include:
            args += ['--include_descriptors_from_image', self.work / f'{name}.img']
        run(sys.executable, '-B', AVBTOOL, *args, *extra)
        return (self.work / 'vbmeta.img').read_bytes()

    def zip(self, release=RELEASE, name=None, prefix=None, sign=True, namespace='factory images',
            entries=(), **changes):
        self.count += 1
        folder = self.work / f'zip{self.count}'
        folder.mkdir()
        members = dict(self.members)
        for member, data in changes.items():
            member = member.replace('__', '.').replace('_dash_', '-')
            if data is None:
                members.pop(member, None)
            else:
                members[member] = data
        path = folder / (name or f'caiman-install-{release}.zip')
        prefix = prefix if prefix is not None else f'caiman-install-{release}/'
        with zipfile.ZipFile(path, 'w') as archive, warnings.catch_warnings():
            warnings.simplefilter('ignore')   # a duplicate entry is one of the controls
            for member, data in members.items():
                archive.writestr(prefix + member, data)
            for info, data in entries:
                archive.writestr(info, data)
        if sign:
            run('ssh-keygen', '-Y', 'sign', '-n', namespace, '-f', self.work / 'ssh', path)
        return path

    def state(self):
        """What check needs of this kit, as JSON, for Kit.reopened in another process."""
        return {'work': str(self.work), 'avb': self.avb, 'signers': str(self.signers),
                'stable': str(self.stable), 'bases': str(self.bases),
                'pkmd': self.members['avb_pkmd.bin'].hex(), 'fingerprint': self.fingerprint}

    @classmethod
    def reopened(cls, state):
        """The kit that state (Kit.state) describes, without making its keys again: enough for
        check, in another process."""
        kit = cls.__new__(cls)
        kit.work, kit.avb, kit.fingerprint = Path(state['work']), state['avb'], state['fingerprint']
        kit.signers, kit.stable, kit.bases = (Path(state[name])
                                              for name in ('signers', 'stable', 'bases'))
        kit.members = {'avb_pkmd.bin': bytes.fromhex(state['pkmd'])}
        return kit

    def check(self, path, **overrides):
        arguments = dict(signature=f'{path}.sig', signers=self.signers, release=RELEASE,
                         stable=self.stable, security_patch='2026-10-05', record=RECORD,
                         avbtool=AVBTOOL if self.avb else self.work / 'no-avbtool',
                         bases=self.bases, scratch=self.work)
        arguments.update(overrides)
        with mock.patch.object(iz, 'PKMD_SHA256', sha(self.members['avb_pkmd.bin'])), \
                mock.patch.object(iz, 'KEY_FINGERPRINT', self.fingerprint):
            return iz.check(path, **arguments)


class ConstantTests(unittest.TestCase):
    def test_values_from_the_plan(self):
        self.assertEqual(iz.PKMD_SHA256, 'f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86')
        self.assertEqual(iz.good_line(), PLAN_GOOD_LINE)
        self.assertEqual(iz.signature_command('allowed_signers', 'caiman-install-VERSION.zip.sig'),
                         ['ssh-keygen', '-Y', 'verify', '-f', 'allowed_signers', '-I',
                          'contact@grapheneos.org', '-n', 'factory images', '-s',
                          'caiman-install-VERSION.zip.sig'])

    def test_allowed_signers_digest_is_the_upstream_pin(self):
        self.assertEqual(iz.pinned_signers_digest(),
                         '344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0')
        self.assertEqual(iz.check_signers(PINNED_SIGNERS)['sha256'], iz.pinned_signers_digest())
        with tempfile.TemporaryDirectory() as work:
            changed = Path(work) / 'allowed_signers'
            changed.write_bytes(PINNED_SIGNERS.read_bytes() + b'\n')
            with self.assertRaises(Refusal):
                iz.check_signers(changed)
            bases = Path(work) / 'bases'
            bases.mkdir()
            for index, digest in enumerate(('a' * 64, 'b' * 64)):
                (bases / f'{index}.json').write_text(json.dumps({'manifest': {'allowed_signers_sha256': digest}}))
            with self.assertRaisesRegex(Refusal, '2 different'):
                iz.pinned_signers_digest(bases)

    def test_patch_timestamp(self):
        self.assertEqual(iz.patch_timestamp('2026-10-05'), ROLLBACK)
        for level in ('2026-10-5', '2026-13-01', '05-10-2026', '', None):
            with self.subTest(level=level), self.assertRaises(Refusal):
                iz.patch_timestamp(level)

    def test_malformed_vbmeta_is_refused(self):
        header = bytearray(256)
        header[0:4] = b'AVB0'
        for data in (b'', b'AVB0', bytes(256), bytes(header[:200]),
                     bytes(header[:12]) + (64).to_bytes(8, 'big') + bytes(header[20:])):
            with self.subTest(size=len(data)), self.assertRaises(Refusal):
                iz.parse_vbmeta(data)

    def test_descriptor_policy(self):
        good = [{'type': 'hash', 'partition': 'boot', 'digest_size': 32},
                {'type': 'hashtree', 'partition': 'system', 'digest_size': 20},
                {'type': 'property', 'key': 'k', 'value': 'v'}, {'type': 'kernel_cmdline'}]
        self.assertEqual(iz.images_to_verify({'descriptors': good}), ['boot', 'system'])
        cases = {
            'unknown tag': [{'type': 'unknown', 'tag': 9}],
            'chain': [{'type': 'chain', 'partition': 'vbmeta_system'}],
            'no digest': [{'type': 'hash', 'partition': 'boot', 'digest_size': 0}],
            'repeated': [good[0], good[0]],
            'path in name': [{'type': 'hash', 'partition': '../boot', 'digest_size': 32}],
            'vbmeta itself': [{'type': 'hash', 'partition': 'vbmeta', 'digest_size': 32}],
            'empty name': [{'type': 'hashtree', 'partition': '', 'digest_size': 32}],
        }
        for name, descriptors in cases.items():
            with self.subTest(name), self.assertRaises(Refusal):
                iz.images_to_verify({'descriptors': descriptors})

    @unittest.skipUnless(HAVE_AVBTOOL, 'needs external/avb/avbtool.py of the pinned tree')
    def test_avbtool_is_the_pinned_file(self):
        self.assertEqual(sha(AVBTOOL.read_bytes()), iz.AVBTOOL_SHA256)


@unittest.skipUnless(HAVE_SSH, 'needs ssh-keygen')
class ChecksWithoutVbmetaTests(unittest.TestCase):
    """Every check but vbmeta and the identity it carries. Runs without avbtool."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.kit = Kit(cls.tmp.name, avb=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def assert_only_failing(self, report, *names):
        failing = sorted(name for name, result in report['checks'].items() if not result['ok'])
        self.assertEqual(failing, sorted(set(names) | {'vbmeta', 'release_identity'}), report['reasons'])
        self.assertEqual(report['verdict'], 'REFUSE')

    def test_base_kit(self):
        self.assert_only_failing(self.kit.check(self.kit.zip()))

    def test_signature_controls(self):
        kit = self.kit
        good = kit.zip()
        tampered = kit.zip(sign=False, flash_dash_all__sh=kit.members['flash-all.sh'] + b'\n')
        shutil.copyfile(f'{good}.sig', f'{tampered}.sig')
        self.assert_only_failing(kit.check(tampered), 'signature', 'flash_script')
        self.assert_only_failing(kit.check(kit.zip(namespace='file')), 'signature')
        other = kit.work / 'other_signers'
        other.write_text(kit.signers.read_text().replace('contact@grapheneos.org', 'other@example.invalid'))
        other_bases = kit.work / 'other-bases'
        other_bases.mkdir(exist_ok=True)
        base = json.loads((kit.bases / '2026100600.json').read_text())
        base['manifest']['allowed_signers_sha256'] = sha(other.read_bytes())
        (other_bases / '2026100600.json').write_text(json.dumps(base))
        report = kit.check(good, signers=other, bases=other_bases)
        self.assertFalse(report['checks']['signature']['ok'])
        with mock.patch.object(iz, 'KEY_FINGERPRINT', 'SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM'):
            self.assertFalse(iz.check(good, signature=f'{good}.sig', signers=kit.signers, release=RELEASE,
                                      stable=kit.stable, security_patch='2026-10-05', record=RECORD,
                                      avbtool=kit.work / 'none', bases=kit.bases)['checks']['signature']['ok'])
        missing = kit.zip(sign=False)
        self.assert_only_failing(kit.check(missing), 'signature')

    def test_allowed_signers_must_be_the_pinned_file(self):
        self.assert_only_failing(self.kit.check(self.kit.zip(), bases=ROOT / 'upstream/bases'),
                                 'allowed_signers')

    def test_layout_controls(self):
        kit = self.kit
        symlink = zipfile.ZipInfo(f'caiman-install-{RELEASE}/link')
        symlink.external_attr = 0o120777 << 16
        cases = [
            kit.zip(name=f'caiman-install-2026100200.zip'),
            kit.zip(prefix='other/'),
            kit.zip(entries=[(f'caiman-install-{RELEASE}/../escape', b'x')]),
            kit.zip(entries=[(f'caiman-install-{RELEASE}/nested/file', b'x')]),
            kit.zip(entries=[(symlink, b'target')]),
            kit.zip(entries=[(f'caiman-install-{RELEASE}/script.txt', b'again')]),
        ]
        for path in cases:
            with self.subTest(path=path.name):
                report = kit.check(path)
                self.assertFalse(report['checks']['zip_layout']['ok'])
                self.assertEqual(report['verdict'], 'REFUSE')

    def test_more_layout_controls(self):
        kit = self.kit
        garbage = kit.work / 'garbage' / f'caiman-install-{RELEASE}.zip'
        garbage.parent.mkdir()
        garbage.write_bytes(b'not a zip at all')
        report = kit.check(garbage)
        self.assertIn('not a readable zip', report['checks']['zip_layout']['reason'])
        path = kit.zip(sign=False)
        data = bytearray(path.read_bytes())
        central = data.rfind(b'PK\x01\x02')   # the last central directory entry
        data[central + 8] |= 0x01                 # its general purpose flag: encrypted
        path.write_bytes(bytes(data))
        run('ssh-keygen', '-Y', 'sign', '-n', 'factory images', '-f', kit.work / 'ssh', path)
        self.assertIn('is encrypted', kit.check(path)['checks']['zip_layout']['reason'])
        with mock.patch.object(iz, 'SMALL', 64):
            report = kit.check(kit.zip())
        self.assertIn('is larger than 64 bytes', report['checks']['android_info']['reason'])

    def test_patch_level_comes_from_the_base_record(self):
        kit = self.kit
        report = kit.check(kit.zip(), security_patch='2026-09-05')
        self.assertEqual(report['checks'], {})
        self.assertIn('not the 2026-10-05 of upstream/bases/2026100600.json', report['reasons'][0])
        report = kit.check(kit.zip(), security_patch=None)
        self.assertEqual(report['checks']['inputs']['detail']['security_patch'], '2026-10-05')
        self.assertEqual(len(report['sha256']), 64)

    def test_avb_pkmd_must_have_the_published_digest(self):
        kit = self.kit
        report = iz.check(kit.zip(), signature=f'{kit.zip()}.sig', signers=kit.signers, release=RELEASE,
                          stable=kit.stable, security_patch='2026-10-05', record=RECORD,
                          avbtool=kit.work / 'none', bases=kit.bases)
        self.assertIn('not f729cab8', report['checks']['avb_pkmd']['reason'])

    def test_android_info_controls(self):
        kit = self.kit
        for text in (INFO.replace(b'16035863', b'15308590'), INFO.replace(b'board=caiman', b'board=komodo'),
                     INFO.replace(b'ripcurrentpro-17.0-15819938', b'ripcurrentpro-17.0-15199480'),
                     INFO + b'require partition-exists=vendor_dlkm\n'):
            with self.subTest(text=text):
                self.assert_only_failing(kit.check(kit.zip(android_dash_info__txt=text)), 'android_info')
        # the optimized script reads android-info.zip, so only the android-info check fails
        self.assert_only_failing(kit.check(kit.zip(android_dash_info__txt=None)), 'android_info')

    def test_flash_script_controls(self):
        kit = self.kit
        script = kit.members['flash-all.sh']
        locked = script.replace(b'fastboot erase dpm_b\n', b'fastboot erase dpm_b\nfastboot flashing lock\n')
        self.assert_only_failing(kit.check(kit.zip(flash_dash_all__sh=locked)), 'flash_script')
        self.assert_only_failing(kit.check(kit.zip(super_2__img=None)), 'flash_script')
        older = kit.zip(**{f'bootloader-caiman-{BL}.img'.replace('.', '__').replace('-', '_dash_'): None})
        self.assert_only_failing(kit.check(older), 'flash_script')

    def test_inputs_are_checked_first(self):
        kit = self.kit
        other = json.loads(json.dumps(RECORD))
        other['release'] = '2026081300'
        for overrides in ({'record': other}, {'release': '2026100602'},
                          {'stable': kit.work / 'missing'}, {'record': {'schema': 'x'}}):
            with self.subTest(overrides=list(overrides)):
                report = kit.check(kit.zip(), **overrides)
                self.assertEqual((report['verdict'], report['checks']), ('REFUSE', {}))

    def other_kit(self):
        """A zip that fails every check that reads it: unsigned, another avb_pkmd.bin, another
        android-info.txt and a lock in flash-all.sh."""
        kit = self.kit
        other = kit.zip(sign=False, avb_pkmd__bin=b'other synthetic key',
                        flash_dash_all__sh=kit.members['flash-all.sh'].replace(
                            b'fastboot erase dpm_b\n', LOCKED),
                        android_dash_info__txt=INFO.replace(b'board=caiman', b'board=komodo'))
        return other.read_bytes()

    def test_a_zip_changed_after_it_was_copied_changes_nothing(self):
        # Every check reads the private copy, never the zip. However the zip changes after it was
        # copied, with fine or coarse timestamps, the report is that of the bytes copied, and
        # ssh-keygen and every archive read saw exactly them.
        kit = self.kit
        other = self.other_kit()
        path = kit.zip()
        original = path.read_bytes()
        unchanged = kit.check(path)
        self.assert_only_failing(unchanged)
        bootloader = f'bootloader-caiman-{BL}.img'
        intermediate = kit.zip(**{member_keyword(bootloader): b'different bootloader'}).read_bytes()
        self.assertEqual(len(intermediate), len(original))
        for coarse in (False, True):
            for boundary in BOUNDARIES[1:]:
                for kind in CHANGES + ('rewritten and restored',):
                    if kind == 'rewritten and restored' and boundary == BOUNDARIES[-1]:
                        continue    # the zip is put back after the last archive read
                    with self.subTest(coarse=coarse, boundary=boundary, kind=kind):
                        restore(path, original)
                        if kind == 'rewritten and restored':
                            rewrite, put_back = rewritten_and_restored(path, intermediate)
                            plan = {boundary: rewrite, BOUNDARIES[-1]: put_back}
                        else:
                            plan = {boundary: changes(path, other)[kind]}
                        with coarse_times(path, coarse), Watch(path, plan) as watch:
                            report = kit.check(path)
                        self.assertEqual(watch.plan, {})
                        self.assertEqual(watch.copied, original)
                        self.assertEqual(report, unchanged)
                        read_as_copied(self, watch, report)

    def test_a_zip_changed_while_it_is_copied_is_checked_as_read(self):
        # The copy holds the bytes as they were read, and the report names and checks exactly
        # them. A zip replaced or removed meanwhile is still read to its end through the file
        # opened. Changed in place, the bytes read are not the bytes signed, so the signature
        # fails on them.
        kit = self.kit
        other = self.other_kit()
        path = kit.zip()
        original = path.read_bytes()
        unchanged = kit.check(path)
        for kind in CHANGES:
            with self.subTest(kind=kind):
                restore(path, original)
                with Watch(path, {'during the copy': changes(path, other)[kind]}) as watch:
                    report = kit.check(path)
                self.assertEqual(watch.plan, {})
                read_as_copied(self, watch, report)
                if kind in ('replaced', 'removed'):
                    self.assertEqual((watch.copied, report), (original, unchanged))
                    continue
                self.assertNotEqual(watch.copied, original)
                self.assertFalse(report['checks']['signature']['ok'])
                if kind == 'grown in place':    # the bytes appended are read, all else is intact
                    self.assertEqual(watch.copied, original + b'more')
                    self.assert_only_failing(report, 'signature')
                else:   # the byte near the start was read before it changed, the other after
                    self.assertNotEqual(watch.copied, path.read_bytes())

    def test_the_signature_and_the_allowed_signers_are_read_once(self):
        # Each file is replaced right after its one read, by bytes that give the other verdict.
        kit = self.kit
        path = kit.zip()
        good = {'signature': Path(f'{path}.sig').read_bytes(), 'allowed_signers': kit.signers.read_bytes()}
        bad = {'signature': Path(f'{kit.zip(namespace="file")}.sig').read_bytes(),
               'allowed_signers': good['allowed_signers'].replace(b'contact@grapheneos.org',
                                                                  b'other@example.invalid')}
        folder = Path(tempfile.mkdtemp(dir=kit.work))
        files = {name: folder / name for name in good}
        real_read, reads = iz.read_small, []
        for first, then, failing in ((good, bad, ()), (bad, good, ('signature', 'allowed_signers'))):
            for name, data in first.items():
                files[name].write_bytes(data)

            def read_then_replace(file, what):
                data = real_read(file, what)
                reads.append(Path(file).name)
                Path(file).write_bytes(then[Path(file).name])
                return data
            with self.subTest(first='good' if first is good else 'bad'), \
                    mock.patch.object(iz, 'read_small', read_then_replace):
                report = kit.check(path, signature=files['signature'], signers=files['allowed_signers'])
                self.assert_only_failing(report, *failing)
                self.assertEqual(files['allowed_signers'].read_bytes(), then['allowed_signers'])
                if not failing:
                    self.assertEqual(report['checks']['allowed_signers']['detail']['sha256'],
                                     sha(good['allowed_signers']))
                    detail = report['checks']['signature']['detail']
                    self.assertEqual((detail['allowed_signers_sha256'], detail['signature_sha256']),
                                     (sha(good['allowed_signers']), sha(good['signature'])))
        self.assertEqual(reads, ['signature', 'allowed_signers'] * 2)

    def test_ssh_keygen_verifies_private_copies_of_the_bytes_read(self):
        kit = self.kit
        path = kit.zip()
        scratch = Path(tempfile.mkdtemp(dir=kit.work))
        real_run, seen = subprocess.run, []

        def recording_run(command, *args, **kwargs):
            if command[:3] == ['ssh-keygen', '-Y', 'verify']:
                signers = Path(command[command.index('-f') + 1])
                signature = Path(command[command.index('-s') + 1])
                [copy] = scratch.glob('zip-*/*')
                stdin, copied = os.fstat(kwargs['stdin'].fileno()), copy.stat()
                seen.append({'directory': signers.parent,
                             'beside': signature.parent == signers.parent,
                             'signers': signers.read_bytes(), 'signature': signature.read_bytes(),
                             'copy': copy.read_bytes(), 'name': copy.name,
                             'stdin': (stdin.st_dev, stdin.st_ino) == (copied.st_dev, copied.st_ino),
                             'offset': os.lseek(kwargs['stdin'].fileno(), 0, os.SEEK_CUR)})
            return real_run(command, *args, **kwargs)
        with mock.patch.object(iz.subprocess, 'run', recording_run):
            report = kit.check(path, scratch=scratch)
        self.assert_only_failing(report)
        [call] = seen
        # ssh-keygen reads the zip's private copy from its start, with copies of the bytes read
        self.assertEqual((call['beside'], call['directory'].parent, call['name'], call['stdin'],
                          call['offset']), (True, scratch, path.name, True, 0))
        self.assertEqual((call['signers'], call['signature'], call['copy']),
                         (kit.signers.read_bytes(), Path(f'{path}.sig').read_bytes(),
                          path.read_bytes()))
        self.assertEqual(list(scratch.iterdir()), [])
        self.assertEqual(report['checks']['signature']['detail']['command'],
                         'ssh-keygen -Y verify -f allowed_signers -I contact@grapheneos.org '
                         f"-n 'factory images' -s signature < {path.name}")
        with mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint):
            detail = iz.check_signature(path, Path(f'{path}.sig').read_bytes(),
                                        kit.signers.read_bytes(), scratch)
        self.assertEqual(detail['output'],
                         iz.good_line().replace(iz.KEY_FINGERPRINT, kit.fingerprint))
        self.assertEqual(list(scratch.iterdir()), [])

    def test_the_private_copies_are_private_and_removed(self):
        kit = self.kit
        path = kit.zip()
        expected = {('zip',): 0o700, ('zip', path.name): 0o600, ('signature',): 0o700,
                    ('signature', 'allowed_signers'): 0o600, ('signature', 'signature'): 0o600}
        real_run = subprocess.run
        for where in ('scratch', 'the system temporary directory'):
            with self.subTest(where=where):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                elsewhere = Path(tempfile.mkdtemp(dir=kit.work))
                system = root if where != 'scratch' else elsewhere
                seen = []

                def looking_run(command, *args, **kwargs):
                    if command[:3] == ['ssh-keygen', '-Y', 'verify']:
                        seen.append({kind_of(item, root): stat.S_IMODE(item.stat().st_mode)
                                     for item in root.rglob('*')})
                    return real_run(command, *args, **kwargs)
                umask = os.umask(0)     # the modes do not come from the umask
                try:
                    with mock.patch.object(iz.subprocess, 'run', looking_run), \
                            mock.patch.object(tempfile, 'tempdir', str(system)):
                        report = kit.check(path, scratch=root if where == 'scratch' else None)
                finally:
                    os.umask(umask)
                self.assert_only_failing(report)
                self.assertEqual(seen, [expected])
                self.assertEqual((list(root.iterdir()), list(elsewhere.iterdir())), ([], []))
        # Removed also when a check raises, when the copy fails and when the copy's path exists.
        failures = {'a check that raises': ('_firmware', RuntimeError('synthetic error')),
                    'an interrupted check': ('_firmware', KeyboardInterrupt()),
                    'a read that fails': (None, OSError(5, 'synthetic read error'))}
        for name, (target, error) in failures.items():
            with self.subTest(name):
                root = Path(tempfile.mkdtemp(dir=kit.work))

                def fail():
                    raise error
                with contextlib.ExitStack() as stack:
                    if target is None:
                        stack.enter_context(Watch(path, {'during the copy': fail}))
                    else:
                        stack.enter_context(mock.patch.object(iz, target, side_effect=error))
                    if isinstance(error, KeyboardInterrupt):
                        stack.enter_context(self.assertRaises(KeyboardInterrupt))
                    report = kit.check(path, scratch=root)
                self.assertEqual(list(root.iterdir()), [])
                if name == 'a check that raises':
                    self.assert_only_failing(report, 'flash_script')
                    self.assertEqual(report['checks']['flash_script']['reason'],
                                     'RuntimeError: synthetic error')
                elif name == 'a read that fails':
                    self.assertEqual(report, {'verdict': 'REFUSE', 'checks': {},
                                              'reasons': ['[Errno 5] synthetic read error']})
        # A file or a symbolic link planted at a copy's path, once its directory is made, refuses,
        # and nothing is written through it: the zip's copy refuses the zip, and a signature copy
        # fails the signature.
        for (prefix, name), planted in itertools.product(
                (('zip', path.name), ('signature', 'allowed_signers'), ('signature', 'signature')),
                ('file', 'symbolic link')):
            with self.subTest(copy=f'{prefix}-*/{name}', planted=planted):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                victim = root / 'victim'
                victim.write_bytes(b'not to be written')

                def plant(directory):
                    if planted == 'file':
                        (directory / name).write_bytes(b'planted')
                    else:
                        (directory / name).symlink_to(victim)
                with after_mkdir(f'{prefix}-', plant):
                    report = kit.check(path, scratch=root)
                if prefix == 'zip':
                    self.assertEqual((report['verdict'], report['checks']), ('REFUSE', {}))
                    self.assertIn('File exists', report['reasons'][0])
                else:
                    self.assert_only_failing(report, 'signature')
                    self.assertRegex(report['checks']['signature']['reason'],
                                     f'^FileExistsError: .*File exists: .*/signature-[^/]+/{name}')
                self.assertEqual((victim.read_bytes(), list(root.iterdir())),
                                 (b'not to be written', [victim]))

    def test_a_copy_that_fails_once_its_directory_exists_leaves_nothing(self):
        # Each step of the copy fails with an I/O error, or is interrupted, once its private
        # directory exists, up to the zip's close and the digest's end. Whoever copies the zip,
        # the error goes on, as a refusal in check's report, and nothing is left.
        kit = self.kit
        path = kit.zip()
        for step, (name, error), copier in itertools.product(COPY_STEPS, ERRORS.items(), COPIERS):
            with self.subTest(step=step, error=name, copier=copier):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                raised = error()

                def fail():
                    raise raised
                with Watch(path, {step: fail}) as watch:
                    result = outcome(lambda: copied_by(copier, kit, path, root))
                if copier == 'check' and isinstance(raised, OSError):
                    self.assertEqual(result, {'verdict': 'REFUSE', 'checks': {},
                                              'reasons': ['[Errno 5] synthetic I/O error']})
                else:
                    self.assertIs(result, raised)
                self.assertEqual((watch.plan, list(root.iterdir())), ({}, []))

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_a_failed_copy_that_cannot_be_removed_refuses(self):
        # The zip's close fails, or is interrupted, once the copy is complete, and the copy's
        # directory cannot be removed either. The removal refuses, whoever copies the zip, with
        # its own error and then the first error in its context, and the copy is still there, as
        # the refusal says.
        kit = self.kit
        path = kit.zip()
        for (name, error), copier in itertools.product(ERRORS.items(), COPIERS):
            with self.subTest(error=name, copier=copier):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                raised = error()

                def lock_then_fail():
                    [directory] = root.glob('zip-*')
                    directory.chmod(0o500)
                    raise raised
                try:
                    with Watch(path, {'closing the zip': lock_then_fail}) as watch:
                        result = outcome(lambda: copied_by(copier, kit, path, root))
                    self.assertEqual(watch.plan, {})
                    if copier == 'check':
                        self.assertIsInstance(result, dict)
                        self.assertEqual((result['verdict'], result['checks']), ('REFUSE', {}))
                        reason = result['reasons'][0]
                    else:
                        self.assertIsInstance(result, Refusal)
                        self.assertIsInstance(result.__context__, PermissionError)
                        self.assertIs(result.__context__.__context__, raised)
                        reason = str(result)
                    self.assertRegex(reason, f'^the private directory {re.escape(str(root))}/'
                                     'zip-[^/]+ could not be removed: ')
                    self.assertEqual([item.name for item in root.glob('zip-*/*')], [path.name])
                finally:
                    for directory in root.iterdir():
                        directory.chmod(0o700)
                    shutil.rmtree(root)

    def test_an_interruption_at_any_boundary_of_the_copy_leaves_nothing(self):
        # A real SIGINT, taken by Python's default handler, at each boundary of the zip's private
        # copy: the return of its constructor, the start of __enter__, right after its directory
        # is made, during the copy, the end of __enter__ before it returns, and the with body.
        # Whoever copies the zip, the interruption goes on and nothing is left.
        kit = self.kit
        path = kit.zip()
        for boundary, copier in itertools.product(LIFETIME, COPIERS):
            with self.subTest(boundary=boundary, copier=copier):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                with interrupted(boundary, path) as fired:
                    result = outcome(lambda: copied_by(copier, kit, path, root))
                self.assertEqual(fired, [boundary])
                self.assertIsInstance(result, KeyboardInterrupt)
                self.assertEqual(list(root.iterdir()), [])

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_an_interrupted_copy_that_cannot_be_removed_refuses(self):
        # The same interruption once the copy's directory exists, whose parent was just made read
        # only, or closed even to a look, so that the directory cannot be removed. The removal
        # refuses, with its own error and then the interruption in its context, and the directory
        # is still there, as the refusal says. check reports the refusal while the copy is made,
        # and raises it after. The backstop stays, and warns of the directory, which it cannot
        # remove either, when the object is dropped.
        kit = self.kit
        path = kit.zip()
        for boundary, copier, mode in itertools.product(LIFETIME[3:], COPIERS, (0o500, 0)):
            with self.subTest(boundary=boundary, copier=copier, parent=oct(mode)):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                try:
                    with backstop_warnings() as warned:
                        with interrupted(boundary, path, before=lambda: root.chmod(mode)) \
                                as fired:
                            result = outcome(lambda: copied_by(copier, kit, path, root))
                        if isinstance(result, dict):
                            seen = (dict, result['verdict'], result['checks'], None, None)
                            reason = result['reasons'][0]
                        else:
                            seen = (type(result), None, None, type(result.__context__),
                                    type(result.__context__.__context__))
                            reason = str(result)
                        del result
                        gc.collect()
                    root.chmod(0o700)
                    self.assertEqual(fired, [boundary])
                    if copier == 'check' and boundary != 'the with body':
                        self.assertEqual(seen, (dict, 'REFUSE', {}, None, None))
                    else:
                        self.assertEqual(seen, (Refusal, None, None, PermissionError,
                                                KeyboardInterrupt))
                    self.assertRegex(reason, f'^the private directory {re.escape(str(root))}/'
                                     'zip-[^/]+ could not be removed: ')
                    self.assertEqual([item.name[:4] for item in root.iterdir()], ['zip-'])
                    self.assertEqual(len(warned), 1)
                    self.assertRegex(warned[0], warning_of(root, 'zip-', r'\[Errno 13\] '))
                finally:
                    root.chmod(0o700)
                    shutil.rmtree(root)

    def test_two_copies_alive_at_once_have_their_own_directories(self):
        kit = self.kit
        path = kit.zip()
        root = Path(tempfile.mkdtemp(dir=kit.work))
        with iz.ZipCopy(path, root) as first, iz.ZipCopy(path, root) as second:
            self.assertNotEqual(first.work, second.work)
            self.assertEqual(sorted(root.iterdir()), sorted((first.work, second.work)))
            self.assertEqual(first.path.read_bytes(), second.path.read_bytes())
        self.assertEqual(list(root.iterdir()), [])

    def test_an_interruption_once_the_signature_directory_is_made_leaves_nothing(self):
        # A real SIGINT right after the directory of the signature's copies is made, with the
        # zip's copy alive: both directories go, and the interruption goes on.
        kit = self.kit
        path = kit.zip()
        root = Path(tempfile.mkdtemp(dir=kit.work))
        seen = []

        def look_then_interrupt(directory):
            seen.append(sorted(item.name[:item.name.index('-') + 1] for item in root.iterdir()))
            interrupt()
        with default_interruptions(), after_mkdir('signature-', look_then_interrupt) as made, \
                self.assertRaises(KeyboardInterrupt):
            kit.check(path, scratch=root)
        self.assertEqual((len(made), seen), (1, [['signature-', 'zip-']]))
        self.assertEqual(list(root.iterdir()), [])

    def test_a_private_directory_whose_path_exists_is_refused_and_left_alone(self):
        # The random name of a private directory names one that exists, with a file in it. That
        # path is refused and nothing in it is touched: the zip's copy refuses the zip, whoever
        # copies it, and the signature's copies fail the signature.
        kit = self.kit
        path = kit.zip()
        for prefix, copier in [('zip-', copier) for copier in COPIERS] + [('signature-', 'check')]:
            with self.subTest(directory=prefix, copier=copier):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                taken = root / f'{prefix}taken'
                taken.mkdir()
                (taken / 'victim').write_bytes(b'not to be removed')
                with mock.patch.object(iz.secrets, 'token_hex', return_value='taken'):
                    result = outcome(lambda: copied_by(copier, kit, path, root))
                refusal = f'the private directory {taken} exists already'
                if prefix == 'signature-':
                    self.assert_only_failing(result, 'signature')
                    self.assertEqual(result['checks']['signature']['reason'], refusal)
                elif copier == 'check':
                    self.assertEqual(result, {'verdict': 'REFUSE', 'checks': {},
                                              'reasons': [refusal]})
                else:
                    self.assertIsInstance(result, Refusal)
                    self.assertEqual(str(result), refusal)
                self.assertEqual([item.name for item in root.iterdir()], [taken.name])
                self.assertEqual([(item.name, item.read_bytes()) for item in taken.iterdir()],
                                 [('victim', b'not to be removed')])

    def test_an_interruption_that_no_handler_covers_leaves_nothing_once_it_went_on(self):
        # A real SIGINT, taken by Python's default handler, where no handler can remove a private
        # directory (UNCOVERED): the return of __enter__, the start of __exit__ or of
        # remove_private, inside shutil.rmtree, and the end of the removal. For the zip's copy,
        # whoever copies the zip, also when the copy failed and __enter__'s cleanup is the removal
        # interrupted, and for the signature's copies and the signed tags' signers copy. The
        # interruption goes on, and once it has, and the object is dropped, the backstop has
        # removed the directory, without a warning.
        import version_criterion as vc
        import world
        kit = self.kit
        path = kit.zip()
        tags = world.World(Path(tempfile.mkdtemp(dir=kit.work)), tags=('2026081300',))

        def failed_copy(copier, root):
            def fail():
                raise OSError(5, 'synthetic I/O error')
            with Watch(path, {'closing the zip': fail}):
                return copied_by(copier, kit, path, root)

        def signed_tags(root):
            with mock.patch.object(tempfile, 'tempdir', str(root)):
                release = iz.caiman.parse_release('2026081300')
                return vc.signed_tags(tags.repo, tags.signers, release, release, bases=tags.bases)
        cases = [(boundary, 'zip-', copier, lambda root, copier=copier: copied_by(
                     copier, kit, path, root)) for boundary in UNCOVERED for copier in COPIERS]
        cases += [(boundary, 'zip-', f'{copier}, its copy failed', lambda root, copier=copier:
                   failed_copy(copier, root)) for boundary in UNCOVERED[2:] for copier in COPIERS]
        cases += [(boundary, 'signature-', 'check', lambda root: kit.check(path, scratch=root))
                  for boundary in UNCOVERED]
        cases += [(boundary, 'signers-', 'signed_tags', signed_tags) for boundary in UNCOVERED]
        for boundary, prefix, caller, call in cases:
            with self.subTest(boundary=boundary, directory=prefix, caller=caller):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                with backstop_warnings() as warned:
                    reached, kind = interrupted_at(boundary, prefix, lambda: call(root))
                self.assertEqual((reached, kind, warned), ([boundary], KeyboardInterrupt, []))
                self.assertEqual(list(root.iterdir()), [])

    def test_a_path_that_exists_is_left_alone_wherever_an_interruption_comes(self):
        # The random name of a private directory names another's path: a directory with a file
        # in it, a file, a link or a dangling link. A real SIGINT comes at each line of __enter__
        # in turn, and at its return, and at last none comes. Whoever makes the directory, the
        # path is refused, or the interruption goes on, before mkdir is reached, and once the
        # object is dropped, everything that was there is as it was.
        kit = self.kit
        path = kit.zip()
        lines, first = inspect.getsourcelines(iz.PrivateDirectory.__enter__)
        owned = [first + index for index, text in enumerate(lines)
                 if text.lstrip().startswith(('self.work = Path(work)', 'OWNED.add(', 'os.mkdir('))]
        self.assertEqual(len(owned), 3)
        callers = [('zip-', copier) for copier in COPIERS]
        callers += [('signature-', 'check'), ('probe-', 'PrivateDirectory')]
        for kind, (prefix, caller) in itertools.product(TAKEN, callers):
            for index in itertools.count():
                with self.subTest(taken=kind, directory=prefix, caller=caller, event=index):
                    root = Path(tempfile.mkdtemp(dir=kit.work))
                    make_taken(root / f'{prefix}taken', kind, root / 'victim')
                    (root / 'victim').write_bytes(b'not to be written')
                    before = everything(root)
                    with mock.patch.object(iz.secrets, 'token_hex', return_value='taken'), \
                            default_interruptions(), \
                            at_entry_event(index, prefix, interrupt) as (fired, seen):
                        result = outcome(lambda: entered(iz.PrivateDirectory('probe-', root))
                                         if caller == 'PrivateDirectory' else
                                         copied_by(caller, kit, path, root))
                    refusal = f'the private directory {root / prefix}taken exists already'
                    if fired:
                        self.assertIsInstance(result, KeyboardInterrupt)
                    elif prefix == 'signature-':
                        self.assertEqual(result['checks']['signature']['reason'], refusal)
                    elif caller == 'check':
                        self.assertEqual(result, {'verdict': 'REFUSE', 'checks': {},
                                                  'reasons': [refusal]})
                    else:
                        self.assertEqual((type(result), str(result)), (Refusal, refusal))
                    del result
                    gc.collect()
                    iz.sweep_at_exit()
                    self.assertEqual([line for line in seen if line in owned], [])
                    self.assertEqual((everything(root), owned_under(root)), (before, []))
                if not fired:
                    break
            self.assertGreater(index, 3)

    def test_a_path_that_another_makes_after_the_check_is_refused_and_left_alone(self):
        # Another process makes a directory at the private directory's path once the check has
        # found the path free, right before mkdir. mkdir fails, so the path is given up without
        # removing anything and refused, and its backstop is detached: the other's directory is
        # left as it is, also once the object is dropped.
        kit = self.kit
        path = kit.zip()
        callers = [('zip-', copier) for copier in COPIERS]
        callers += [('signature-', 'check'), ('probe-', 'PrivateDirectory')]
        for prefix, caller in callers:
            with self.subTest(directory=prefix, caller=caller):
                root = Path(tempfile.mkdtemp(dir=kit.work))

                def make(directory):
                    directory.mkdir()
                    (directory / 'victim').write_bytes(b'not to be removed')
                with after_mkdir(prefix, make, before=True) as made:
                    result = outcome(lambda: entered(iz.PrivateDirectory('probe-', root))
                                     if caller == 'PrivateDirectory' else
                                     copied_by(caller, kit, path, root))
                [other] = made
                refusal = f'the private directory {other} exists already'
                if prefix == 'signature-':
                    self.assert_only_failing(result, 'signature')
                    self.assertEqual(result['checks']['signature']['reason'], refusal)
                elif caller == 'check':
                    self.assertEqual(result, {'verdict': 'REFUSE', 'checks': {},
                                              'reasons': [refusal]})
                else:
                    self.assertEqual((type(result), str(result)), (Refusal, refusal))
                del result
                gc.collect()
                self.assertEqual(owned_under(root), [])
                iz.sweep_at_exit()
                self.assertEqual(everything(root), [(other.name, 'directory', None),
                                                    (f'{other.name}/victim', 'file',
                                                     b'not to be removed')])

    def test_a_device_replaced_by_a_regular_file_once_opened_is_refused(self):
        # The zip's path names a device when it is opened, and a regular file right after. The
        # check of a regular file looks at what was opened, not at what the path names: whoever
        # reads the path, and for Google's image too, the device is refused and nothing is read.
        import version_criterion as vc
        kit = self.kit
        data = kit.zip().read_bytes()
        opener = iz._without_waiting
        for copier in COPIERS + ('a stock image',):
            with self.subTest(copier=copier):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                path = root / 'device' / f'caiman-install-{RELEASE}.zip'
                path.parent.mkdir()
                path.symlink_to(os.devnull)
                opened = []

                def open_then_replace(file, flags):
                    descriptor = opener(file, flags)
                    if Path(file) == path and not opened:
                        opened.append(stat.S_ISCHR(os.fstat(descriptor).st_mode))
                        path.unlink()
                        path.write_bytes(data)
                    return descriptor
                with mock.patch.object(iz, '_without_waiting', open_then_replace):
                    if copier == 'a stock image':
                        result = outcome(lambda: vc.verified_image(
                            {'verified': {}}, path, 'stock', vc.Table({}, {}, {})))
                    else:
                        result = outcome(lambda: copied_by(copier, kit, path, root))
                refusal = f'{path.name} is not a regular file'
                if copier == 'check':
                    self.assertEqual(result, {'verdict': 'REFUSE', 'checks': {},
                                              'reasons': [refusal]})
                else:
                    self.assertEqual((type(result), str(result)), (Refusal, refusal))
                self.assertEqual((opened, path.read_bytes()), ([True], data))
                self.assertEqual([item.name for item in root.iterdir()], ['device'])

    def test_the_zip_is_read_once_from_its_start_to_its_end(self):
        # Whoever copies the zip, its one handle is read from offset 0, each read starting where
        # the one before ended, until one read finds its end, and the zip is not read again: no
        # seek, no other read of the handle and no read of its file through os, such as os.pread.
        kit = self.kit
        for name, path in (('a small zip', kit.zip()),
                           ('a zip of several blocks', kit.zip(script__txt=os.urandom(5 << 19)))):
            size = path.stat().st_size
            for copier in COPIERS:
                with self.subTest(name, copier=copier):
                    root = Path(tempfile.mkdtemp(dir=kit.work))
                    with source_reads(path) as seen:
                        outcome(lambda: copied_by(copier, kit, path, root))
                    reads = seen['reads']
                    self.assertEqual(seen['opens'], 1)
                    self.assertEqual([offset for offset, _ in reads],
                                     [0] + [offset + length for offset, length in reads[:-1]])
                    self.assertEqual(reads[-1], (size, 0))
                    self.assertEqual([length for _, length in reads].count(0), 1)
                    self.assertEqual((seen['other'], seen['os']), ([], []))
                    self.assertEqual(list(root.iterdir()), [])
        self.assertGreater(len(reads), 2)

    def test_each_small_input_is_read_in_one_read(self):
        # read_small opens the signature and the allowed signers file once each, and reads each
        # in one read of at most SMALL + 1 bytes, with no seek: no byte of them is read twice.
        kit = self.kit
        path = kit.zip()
        signature, seen, real_open = Path(f'{path}.sig'), [], open

        class Counted:
            def __init__(self, handle, name):
                self.handle, self.name = handle, name

            def read(self, *args):
                seen.append((self.name, 'read', *args))
                return self.handle.read(*args)

            def __getattr__(self, name):
                if name.startswith(('read', 'seek', 'peek')):
                    seen.append((self.name, name))
                return getattr(self.handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *exception):
                self.handle.close()

        def counted_open(file, *args, **kwargs):
            handle = real_open(file, *args, **kwargs)
            if Path(file) in (signature, kit.signers):
                seen.append((Path(file).name, 'open'))
                return Counted(handle, Path(file).name)
            return handle
        with mock.patch.object(iz, 'open', counted_open, create=True):
            report = kit.check(path)
            data = iz.read_small(kit.signers, 'allowed_signers')
        self.assert_only_failing(report)
        self.assertEqual(data, kit.signers.read_bytes())
        once = [[(file.name, 'open'), (file.name, 'read', iz.SMALL + 1)]
                for file in (signature, kit.signers, kit.signers)]
        self.assertEqual(seen, [step for steps in once for step in steps])

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_a_private_copy_that_cannot_be_removed_refuses(self):
        # The directory loses its write permission once ssh-keygen has read the copies, so they
        # cannot be removed. Nothing ignores that: the signature fails, or check raises. The
        # backstop, when the object is dropped, cannot remove them either, and warns of them.
        kit = self.kit
        path = kit.zip()
        real_run = subprocess.run
        for prefix in ('signature', 'zip'):
            with self.subTest(prefix=prefix):
                root = Path(tempfile.mkdtemp(dir=kit.work))

                def locking_run(command, *args, **kwargs):
                    completed = real_run(command, *args, **kwargs)
                    if command[:3] == ['ssh-keygen', '-Y', 'verify']:
                        [directory] = root.glob(f'{prefix}-*')
                        directory.chmod(0o500)
                    return completed
                try:
                    with backstop_warnings() as warned, \
                            mock.patch.object(iz.subprocess, 'run', locking_run):
                        if prefix == 'signature':
                            report = kit.check(path, scratch=root)
                        else:
                            with self.assertRaisesRegex(Refusal, '^the private directory '
                                                    f'{re.escape(str(root))}/zip-[^/]+ could not '
                                                    'be removed: '):
                                kit.check(path, scratch=root)
                    self.assertEqual(len(warned), 1)
                    self.assertRegex(warned[0], warning_of(root, f'{prefix}-', r'\[Errno 13\] '))
                    if prefix == 'signature':
                        self.assert_only_failing(report, 'signature')
                        self.assertRegex(report['checks']['signature']['reason'],
                                         f'^the private directory {re.escape(str(root))}/'
                                         'signature-[^/]+ could not be removed: ')
                    # the copies are still there, as the refusal says
                    self.assertEqual(len(list(root.glob(f'{prefix}-*/*'))),
                                     2 if prefix == 'signature' else 1)
                finally:
                    for directory in root.iterdir():
                        directory.chmod(0o700)
                    shutil.rmtree(root)

    def test_a_path_that_is_not_a_regular_file_is_refused_without_waiting(self):
        kit = self.kit
        root = Path(tempfile.mkdtemp(dir=kit.work))
        fifo = root / 'fifo' / f'caiman-install-{RELEASE}.zip'
        fifo.parent.mkdir()
        os.mkfifo(fifo)
        directory = root / 'directory' / f'caiman-install-{RELEASE}.zip'
        directory.mkdir(parents=True)
        done = threading.Event()
        helper = threading.Thread(target=unblock_later, args=(fifo, done), daemon=True)
        helper.start()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always', ResourceWarning)    # a refused path left open
            try:
                started = time.monotonic()
                report = kit.check(fifo, scratch=root)
                with self.assertRaisesRegex(Refusal, f'^{fifo.name} is not a regular file$'):
                    iz.andrix_identity(fifo, avbtool=None, scratch=root)
                elapsed = time.monotonic() - started
            finally:
                done.set()
                helper.join()
            devnull = kit.check(Path(os.devnull), scratch=root)
        self.assertLess(elapsed, 2)
        self.assertEqual(report, {'verdict': 'REFUSE', 'checks': {},
                                  'reasons': [f'{fifo.name} is not a regular file']})
        self.assertEqual(devnull, {'verdict': 'REFUSE', 'checks': {},
                                   'reasons': [f'{Path(os.devnull).name} is not a regular file']})
        self.assertEqual([str(warning.message) for warning in caught
                          if issubclass(warning.category, ResourceWarning)], [])
        report = kit.check(directory, scratch=root)
        self.assertEqual((report['verdict'], report['checks']), ('REFUSE', {}))
        self.assertIn('Is a directory', report['reasons'][0])
        self.assertEqual(sorted(item.name for item in root.iterdir()), ['directory', 'fifo'])

    def test_unreadable_and_oversized_signature_inputs_are_refused(self):
        kit = self.kit
        path = kit.zip()
        report = kit.check(path, signature=kit.work / 'missing.sig')
        self.assert_only_failing(report, 'signature')
        self.assertRegex(report['checks']['signature']['reason'],
                         '^the signature cannot be read: .*missing.sig')
        report = kit.check(path, signers=kit.work / 'missing_signers')
        self.assert_only_failing(report, 'signature', 'allowed_signers')
        for name in ('signature', 'allowed_signers'):
            self.assertRegex(report['checks'][name]['reason'],
                             '^allowed_signers cannot be read: .*missing_signers')
        large = kit.work / 'large.sig'
        large.write_bytes(Path(f'{path}.sig').read_bytes() + b'\n' * iz.SMALL)
        report = kit.check(path, signature=large)
        self.assert_only_failing(report, 'signature')
        self.assertEqual(report['checks']['signature']['reason'],
                         f'the signature is larger than {iz.SMALL} bytes')

    def test_unreadable_firmware_refuses_the_flash_script(self):
        with mock.patch.object(iz, 'IMAGE', 16):
            report = self.kit.check(self.kit.zip())
        self.assert_only_failing(report, 'flash_script')
        self.assertEqual(report['checks']['flash_script']['reason'],
                         f'bootloader-caiman-{BL}.img is larger than 16 bytes')
        self.assertNotIn('firmware', report)

    def double_interruption_plan(self):
        """The private directories that these checks make, as cases of exit_after_two_interruptions:
        the zip's copy by each of COPIERS, the signature's copies by check and the signers copy by
        signed_tags. check's zip copy is made read only, and so are the signature's copies and the
        signers copy in a second case each."""
        import world
        kit = self.kit
        tags = world.World(Path(tempfile.mkdtemp(dir=kit.work)), tags=('2026081300',))
        cases = [{'prefix': 'zip-', 'caller': caller, 'locked': caller == 'check'}
                 for caller in COPIERS]
        cases += [{'prefix': prefix, 'caller': caller, 'locked': locked}
                  for prefix, caller in (('signature-', 'check'), ('signers-', 'signed_tags'))
                  for locked in (False, True)]
        return {'kit': kit.state(), 'work': str(kit.work), 'zip': str(kit.zip()), 'cases': cases,
                'tags': {'repo': str(tags.repo), 'signers': str(tags.signers),
                         'bases': str(tags.bases)}, 'tools': None, 'dynamic': None}

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_a_backstop_stopped_at_its_entry_leaves_its_directory_to_the_exit_sweep(self):
        # A first SIGINT at the start of __exit__, and a second at the call or the first line of
        # the backstop as the first is collected, for the zip's copy by ZipCopy, check,
        # andrix_identity and verified_image, the signature's copies and the signers copy.
        assert_stopped_backstops_leave_their_directories_to_the_sweep(
            self, self.double_interruption_plan())

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_python_removes_at_its_exit_what_a_stopped_backstop_left(self):
        # The same two interruptions, the second at collection or at the interpreter's exit, in
        # processes that then exit; and the exit sweep itself interrupted at its call.
        assert_python_exit_removes_what_stopped_backstops_left(
            self, self.double_interruption_plan())

    def test_a_link_to_a_regular_zip_is_read_as_the_zip(self):
        # The zip's path is a symbolic link to the zip, as is its signature's. Whoever reads it,
        # the link is followed to the regular file it names, which is read as if named itself;
        # and decide hashes a stock image through a link alike.
        import version_criterion as vc
        kit = self.kit
        path = kit.zip()
        link = Path(tempfile.mkdtemp(dir=kit.work)) / path.name
        link.symlink_to(path)
        Path(f'{link}.sig').symlink_to(f'{path}.sig')

        def seen(result):
            return (type(result), str(result)) if isinstance(result, BaseException) else result
        for copier in COPIERS:
            with self.subTest(copier=copier):
                root = Path(tempfile.mkdtemp(dir=kit.work))
                direct = seen(outcome(lambda: copied_by(copier, kit, path, root)))
                linked = seen(outcome(lambda: copied_by(copier, kit, link, root)))
                self.assertEqual(linked, direct)
                self.assertEqual(list(root.iterdir()), [])
        report = kit.check(link)
        self.assert_only_failing(report)
        self.assertEqual(report['sha256'], sha(path.read_bytes()))
        digest, info = sha(path.read_bytes()), iz.caiman.parse_android_info(INFO)
        kept = vc.Image('stock', digest, iz.caiman.parse_release(RELEASE), 'CP3A.261005.005', info,
                        'this image')
        session = {'verified': {digest: vc.identity_entry(kept, '2026-10-09T10:01:00Z')}}
        table = vc.Table({RELEASE: 'CP3A.261005.005'}, {RELEASE: info},
                         {'CP3A.261005.005': {'factory_sha256': digest}})
        self.assertEqual(vc.verified_image(session, link, 'stock', table), kept)

    def test_a_zip_with_a_member_larger_than_128_mib_is_checked_as_any_other(self):
        # An unchanged zip whose stored member holds 129 MiB is copied and checked as a small
        # one: every check that needs no avbtool passes, on the digest of its bytes.
        kit = self.kit
        path = kit.zip(script__txt=bytes(129 << 20))
        report = kit.check(path)
        self.assert_only_failing(report)
        self.assertEqual(report['sha256'], sha(path.read_bytes()))
        path.unlink()


class FailingCopy(iz.ZipCopy):
    """A ZipCopy whose copy fails with an I/O error once it is complete, so that __enter__'s
    cleanup removes it."""

    def fill(self):
        super().fill()
        raise OSError(5, 'synthetic I/O error')


class PrivateDirectoryTests(unittest.TestCase):
    """PrivateDirectory itself: its name, its backstop, and the removal's errors."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'private'
        self.root.mkdir()
        self.source = Path(self.tmp.name) / f'caiman-install-{RELEASE}.zip'
        self.source.write_bytes(os.urandom(3 << 19))

    def test_a_private_directory_is_named_by_128_random_bits(self):
        names = []
        for _ in range(2):
            with iz.PrivateDirectory('probe-', self.root) as work:
                names.append(work.name)
            with iz.ZipCopy(self.source, self.root) as copy:
                names.append(copy.work.name)
        for name in names:
            self.assertRegex(name, '^(probe|zip)-[0-9a-f]{32}$')
        self.assertEqual(len(set(names)), 4)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_a_directory_that_mkdir_cannot_make_is_given_up_with_its_error(self):
        # mkdir fails for another reason than a path that exists: the parent is missing, or is a
        # file. mkdir made nothing, so the path is given up untouched, mkdir's own error goes on,
        # and the backstop, detached, has nothing to say when the object is dropped.
        a_file = Path(self.tmp.name) / 'a file'
        a_file.write_bytes(b'not a directory')
        for name, parent, error in (
                ('a missing parent', Path(self.tmp.name) / 'missing', FileNotFoundError),
                ('a parent that is a file', a_file, NotADirectoryError)):
            with self.subTest(name):
                with backstop_warnings() as warned:
                    result = outcome(lambda: entered(iz.PrivateDirectory('probe-', parent)))
                    seen = (type(result), result.__context__,
                            str(getattr(result, 'filename', None)))
                    del result
                    owned = owned_under(parent)
                    iz.sweep_at_exit()
                self.assertEqual(seen[:2], (error, None))
                self.assertRegex(seen[2], f'^{re.escape(str(parent))}/probe-[0-9a-f]+$')
                self.assertEqual((warned, owned), ([], []))
        self.assertEqual(a_file.read_bytes(), b'not a directory')

    def test_the_backstop_is_detached_once_a_removal_succeeded(self):
        # Once the end of the with block, or __enter__'s cleanup, has removed the directory, its
        # backstop is detached: a directory that another process then makes at the same path is
        # left alone when the object is dropped.
        for name, kind in (('the end of the with block', iz.ZipCopy),
                           ("__enter__'s cleanup", FailingCopy)):
            with self.subTest(name):
                root = Path(tempfile.mkdtemp(dir=self.root))
                copy = kind(self.source, root)
                with contextlib.suppress(OSError), copy:
                    pass
                self.assertEqual((list(root.iterdir()), owned_under(root)), ([], []))
                copy.work.mkdir()
                (copy.work / 'victim').write_bytes(b'not to be removed')
                del copy
                gc.collect()
                iz.sweep_at_exit()
                [other] = root.iterdir()
                self.assertEqual([(item.name, item.read_bytes()) for item in other.iterdir()],
                                 [('victim', b'not to be removed')])

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_the_backstop_warns_of_a_directory_that_it_cannot_remove(self):
        # A real SIGINT at the return of __enter__, once the copy's directory was made read only.
        # The interruption goes on, as nothing could take a refusal there, and when the object is
        # dropped the backstop cannot remove the directory. It raises nothing: a warning on
        # stderr names the directory, which stays with its copy.
        def lock_then_interrupt():
            lock_private(self.root)
            interrupt()
        try:
            with backstop_warnings() as warned:
                with default_interruptions(), at_boundary('the return of __enter__', 'zip-',
                                                          lock_then_interrupt) as reached:
                    result = outcome(lambda: entered(iz.ZipCopy(self.source, self.root)))
                kind = type(result)
                del result
                gc.collect()
        finally:
            unlock_private(self.root)
        [work] = self.root.iterdir()
        self.assertEqual((reached, kind), (['the return of __enter__'], KeyboardInterrupt))
        self.assertEqual(len(warned), 1)
        self.assertRegex(warned[0], warning_of(self.root, 'zip-', r'\[Errno 13\] Permission '))
        self.assertIn(str(work), warned[0])
        self.assertEqual([(item.name, item.read_bytes()) for item in work.iterdir()],
                         [(self.source.name, self.source.read_bytes())])
        shutil.rmtree(work)
        # The end of the with block cannot remove the directory and refuses. The backstop stays,
        # and once the directory can be removed, it removes it when the object is dropped.
        copy = iz.ZipCopy(self.source, self.root)
        try:
            with self.assertRaisesRegex(Refusal, f'^the private directory '
                                        f'{re.escape(str(self.root))}/zip-[0-9a-f]+ could not '
                                        'be removed: '), copy:
                copy.work.chmod(0o500)
        finally:
            copy.work.chmod(0o700)
        self.assertEqual([item.name for item in copy.work.iterdir()], [self.source.name])
        with backstop_warnings() as warned:
            del copy
        self.assertEqual((warned, list(self.root.iterdir())), ([], []))

    def test_the_backstop_warns_when_an_interruption_stops_its_own_removal(self):
        # A real SIGINT at the start of __exit__ leaves the copy to the backstop, and a second one
        # stops the backstop's removal when the object is dropped. Nothing can take that
        # interruption there: the backstop raises nothing, a warning on stderr names the
        # directory, and the copy stays.
        with default_interruptions():
            with at_boundary('the start of __exit__', 'zip-', interrupt) as first:
                result = outcome(lambda: entered(iz.ZipCopy(self.source, self.root)))
            kind = type(result)
            [work] = self.root.iterdir()
            with backstop_warnings() as warned, \
                    at_boundary('the start of the removal', 'zip-', interrupt) as second:
                del result
                gc.collect()
        self.assertEqual((first, kind, second), (['the start of __exit__'], KeyboardInterrupt,
                                                 ['the start of the removal']))
        self.assertEqual(warned, [f'warning: the private directory {work} could not be removed: '
                                  'KeyboardInterrupt'])
        self.assertEqual([item.name for item in work.iterdir()], [self.source.name])

    def exit_through(self, boundary, root, locked=''):
        """A process interrupted at boundary of its ZipCopy under root (INTERRUPTED_PROCESS),
        and its stderr once Python exited through the interruption."""
        here = Path(__file__).resolve().parent
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                   PYTHONPATH=os.pathsep.join((str(here.parent), str(here))))
        process = subprocess.run([sys.executable, '-B', '-c', INTERRUPTED_PROCESS, boundary,
                                  str(self.source), str(root), locked],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                 timeout=120)
        self.assertEqual((process.returncode, process.stdout), (-signal.SIGINT, b''))
        stderr = process.stderr.decode()
        self.assertIn('\nKeyboardInterrupt\n', stderr)
        return stderr

    def test_the_backstop_removes_the_copy_as_python_exits_through_an_interruption(self):
        # Nothing catches the interruption, as when the owner interrupts a check, and Python
        # exits through it. At each boundary that no handler covers, the backstop removes the
        # copy at that exit, without a warning.
        for boundary in UNCOVERED:
            with self.subTest(boundary=boundary):
                root = Path(tempfile.mkdtemp(dir=self.root))
                stderr = self.exit_through(boundary, root)
                self.assertNotIn('warning', stderr)
                self.assertEqual(list(root.iterdir()), [])

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_the_backstop_warns_at_the_exit_of_what_it_cannot_remove(self):
        # The copy, which cannot be removed, is named twice as Python exits: by its backstop,
        # which weakref.finalize runs at the exit as the object is still held, and by the exit
        # sweep, which names every directory that stays.
        try:
            stderr = self.exit_through('the return of __enter__', self.root, 'locked')
        finally:
            unlock_private(self.root)
        [work] = self.root.iterdir()
        warnings = [line for line in stderr.splitlines() if line.startswith('warning')]
        self.assertEqual(len(warnings), 2, stderr)
        self.assertEqual(warnings_naming(warnings, work), warnings)
        self.assertRegex(warnings[0], warning_of(self.root, 'zip-', r'\[Errno 13\] Permission '))
        self.assertEqual(warnings[0], warnings[1])
        self.assertEqual([item.name for item in work.iterdir()], [self.source.name])
        shutil.rmtree(work)

    def test_a_removal_that_fails_with_another_error_refuses_too(self):
        # Not only a permission error: any error of the removal, here an I/O error, refuses, at
        # the end of the with block and in __enter__'s cleanup alike, and the copy stays as the
        # refusal says. The backstop warns of it in turn while the error lasts.
        real = shutil.rmtree

        def failing(directory, *args, **kwargs):
            if Path(directory).name.startswith('zip-'):
                raise OSError(errno.EIO, 'synthetic removal error')
            return real(directory, *args, **kwargs)
        for name, kind in (('the end of the with block', iz.ZipCopy),
                           ("__enter__'s cleanup", FailingCopy)):
            with self.subTest(name):
                root = Path(tempfile.mkdtemp(dir=self.root))
                refusal = (f'^the private directory {re.escape(str(root))}/zip-[0-9a-f]+ could '
                           r'not be removed: \[Errno 5\] synthetic removal error$')
                with backstop_warnings() as warned, \
                        mock.patch.object(iz.shutil, 'rmtree', failing):
                    with self.assertRaisesRegex(Refusal, refusal) as raised, kind(self.source,
                                                                                  root):
                        pass
                    self.assertIsInstance(raised.exception.__context__, OSError)
                    del raised      # the object, which the error's context held, while it lasts
                    gc.collect()
                [work] = root.iterdir()
                self.assertEqual([item.name for item in work.iterdir()], [self.source.name])
                self.assertEqual(len(warned), 1)
                self.assertRegex(warned[0], warning_of(root, 'zip-',
                                                       r'\[Errno 5\] synthetic removal error$'))

    def owned_directories(self, root, count):
        """count private directories under root, each with a copy in it, whose objects own them
        and are kept, as when interruptions kept their with blocks from removing them."""
        directories = [iz.PrivateDirectory('probe-', root) for _ in range(count)]
        works = sorted(directory.__enter__() for directory in directories)
        for work in works:
            (work / 'copy').write_bytes(b'private bytes')
        return directories, works

    def test_a_path_is_owned_from_its_entry_until_a_removal_of_it_succeeded(self):
        # The registry of owned directories holds a private directory's path from the moment
        # __enter__ owns it, before mkdir, until a removal of it succeeded: at the end of the
        # with block, in __enter__'s cleanup, or by the backstop. A removal that refuses leaves
        # it there.
        seen = []
        made = os.mkdir

        def mkdir(path, *args, **kwargs):
            seen.append(owned_under(self.root))
            return made(path, *args, **kwargs)
        with mock.patch.object(iz.os, 'mkdir', mkdir):
            with iz.PrivateDirectory('probe-', self.root) as work:
                self.assertEqual(owned_under(self.root), [str(work)])
        self.assertEqual((seen, owned_under(self.root)), ([[str(work)]], []))
        with self.assertRaises(OSError):
            entered(FailingCopy(self.source, self.root))
        self.assertEqual((owned_under(self.root), list(self.root.iterdir())), ([], []))

        def refused(directory, *args, **kwargs):
            raise OSError(errno.EIO, 'synthetic removal error')
        copy = iz.ZipCopy(self.source, self.root)
        with mock.patch.object(iz.shutil, 'rmtree', refused), self.assertRaises(Refusal), copy:
            pass
        self.assertEqual(owned_under(self.root), [str(copy.work)])
        with backstop_warnings() as warned:
            del copy
        self.assertEqual((warned, owned_under(self.root), list(self.root.iterdir())), ([], [], []))

    def test_the_exit_sweep_removes_every_directory_still_owned(self):
        # Three directories whose objects own them still, one gone already. The exit sweep
        # removes the others and gives every path up, without a warning. It is idempotent: a
        # second sweep, and the backstops once the objects are dropped, find nothing to do.
        with backstop_warnings() as warned, mock.patch.object(iz, 'OWNED', set()):
            directories, works = self.owned_directories(self.root, 3)
            shutil.rmtree(works[0])
            self.assertEqual(len(iz.OWNED), 3)
            self.assertIsNone(iz.sweep_at_exit())
            self.assertEqual((list(self.root.iterdir()), iz.OWNED), ([], set()))
            self.assertIsNone(iz.sweep_at_exit())
            del directories
            gc.collect()
        self.assertEqual(warned, [])

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_an_interruption_or_a_failure_on_one_directory_goes_on_to_the_next(self):
        # Three directories that the exit sweep finds still owned, the second read only. A real
        # SIGINT comes at each call, line and return of the sweep, of remove_leftover, warn_left
        # and remove_private in turn, and at last none comes. At its call or its first line,
        # before its handler is set up, the interruption ends the sweep: that is the limit that
        # no Python handler can cover. Anywhere else, the sweep goes on: every directory that
        # stays is named in a warning, the read only one always, and at most one other, whose
        # removal the interruption stopped. (Inside shutil.rmtree, a trace that raises at the
        # try of its finally, as a failed removal unwinds, leaves that failure as the thread's
        # handled exception: a quirk of CPython that only a trace can reach, so it is not traced
        # here.)
        codes = {iz.sweep_at_exit.__code__, iz.remove_leftover.__code__, iz.warn_left.__code__,
                 iz.remove_private.__code__}
        for index in itertools.count():
            with self.subTest(event=index), mock.patch.object(iz, 'OWNED', set()):
                root = Path(tempfile.mkdtemp(dir=self.root))
                directories, works = self.owned_directories(root, 3)
                works[1].chmod(0o500)
                stream = io.StringIO()
                try:
                    with contextlib.redirect_stderr(stream), default_interruptions(), \
                            at_event(index, codes, interrupt) as (done, seen):
                        result = outcome(iz.sweep_at_exit)
                finally:
                    works[1].chmod(0o700)
                lines = stream.getvalue().splitlines()
                left = [work for work in works if work.exists()]
                named = [work for work in works if warnings_naming(lines, work)]
                if index < 2:
                    self.assertEqual(seen[index][:2], ('sweep_at_exit', ('call', 'line')[index]))
                    self.assertIsInstance(result, KeyboardInterrupt)
                    self.assertEqual((left, named), (works, []))
                elif done and done[0][:2] == ('sweep_at_exit', 'return'):
                    # the sweep had ended; its return is no longer inside its handler
                    self.assertIsInstance(result, KeyboardInterrupt)
                    self.assertEqual((left, named), ([works[1]], [works[1]]))
                else:
                    self.assertIsNone(result, done)
                    self.assertIn(works[1], named)
                    self.assertEqual([work for work in left if work not in named], [], done)
                    self.assertLessEqual(len(left), 2 if done else 1, done)
                    self.assertEqual(len(lines), len([line for line in lines
                                                      if line.startswith('warning: ')]))
                unlock_and_remove(root)
                del directories
                gc.collect()
            if not done:
                break
        self.assertGreater(index, 40)
        # A real SIGINT at the start of every directory's removal: each is named, none stops
        # the sweep.
        with mock.patch.object(iz, 'OWNED', set()):
            root = Path(tempfile.mkdtemp(dir=self.root))
            directories, works = self.owned_directories(root, 3)
            real, stopped = iz.remove_private, []

            def interrupted_removal(work, *args, **kwargs):
                stopped.append(work)
                interrupt()
                return real(work, *args, **kwargs)
            stream = io.StringIO()
            with contextlib.redirect_stderr(stream), default_interruptions(), \
                    mock.patch.object(iz, 'remove_private', interrupted_removal):
                self.assertIsNone(iz.sweep_at_exit())
            lines = stream.getvalue().splitlines()
            self.assertEqual(stopped, [str(work) for work in works])
            self.assertEqual(lines, [f'warning: the private directory {work} could not be '
                                     'removed: KeyboardInterrupt' for work in works])
            self.assertEqual(sorted(iz.OWNED), [str(work) for work in works])
            iz.sweep_at_exit()
            self.assertEqual(list(root.iterdir()), [])
            del directories

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_no_warning_raises_whatever_stderr_is(self):
        # stderr is closed, fails, is None, has no write, or its write is interrupted by a real
        # SIGINT. The backstops of two copies that cannot be removed raise nothing as their
        # objects are dropped, nor does the exit sweep, and warn_left says that it wrote
        # nothing. The directories stay, still owned, and the next sweep that can write names
        # them.
        class Failing:
            def write(self, text):
                raise OSError(errno.EIO, 'synthetic stderr error')

        class Interrupted:
            def write(self, text):
                interrupt()
        closed = io.StringIO()
        closed.close()
        streams = {'closed': closed, 'failing': Failing(), 'None': None,
                   'without write': object(), 'interrupted': Interrupted()}
        for name, stream in streams.items():
            with self.subTest(stderr=name):
                root = Path(tempfile.mkdtemp(dir=self.root))
                raised = []

                @contextlib.contextmanager
                def broken():
                    lock_private(root)
                    try:
                        with default_interruptions(), mock.patch.object(sys, 'stderr', stream), \
                                mock.patch.object(sys, 'unraisablehook', raised.append):
                            yield
                    finally:
                        unlock_private(root)
                copies = [iz.ZipCopy(self.source, root) for _ in range(2)]
                works = sorted(copy.__enter__().work for copy in copies)
                with broken():
                    del copies
                    gc.collect()
                self.assertEqual([found.exc_type for found in raised], [])
                with broken():
                    swept = outcome(iz.sweep_at_exit)
                    written = iz.warn_left(root / 'nowhere', OSError(errno.EIO, 'synthetic'))
                self.assertEqual((swept, written, raised), (None, False, []))
                self.assertEqual(owned_under(root), [str(work) for work in works])
                lock_private(root)
                stderr = io.StringIO()
                try:
                    with contextlib.redirect_stderr(stderr):
                        iz.sweep_at_exit()
                finally:
                    unlock_private(root)
                lines = stderr.getvalue().splitlines()
                named = [len(warnings_naming(lines, work)) for work in works]
                self.assertEqual((named, len(lines)), ([1, 1], 2))
                iz.sweep_at_exit()
                self.assertEqual((list(root.iterdir()), owned_under(root)), ([], []))

    def test_a_relative_scratch_path_gives_absolute_private_paths(self):
        # scratch, and the zip's path, are relative to the working directory. Every private
        # path is absolute, so that a tool that runs in the private directory finds it.
        previous = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            with iz.PrivateDirectory('probe-', 'private') as work:
                self.assertTrue(work.is_absolute())
                self.assertTrue(work.parent.samefile(self.root))
            with iz.ZipCopy(self.source.name, Path('private')) as copy:
                self.assertTrue(copy.work.is_absolute() and copy.path.is_absolute())
                self.assertEqual(copy.path.read_bytes(), self.source.read_bytes())
        finally:
            os.chdir(previous)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_a_forked_child_leaves_its_parents_directories_alone(self):
        # A process that owns a private directory forks, and the child exits through Python's
        # cleanup. The child owns none of its parent's directories: neither the exit sweep nor
        # the backstops that it inherited remove the parent's, which the parent removes itself.
        here = Path(__file__).resolve().parent
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(here.parent))
        process = subprocess.run([sys.executable, '-B', '-c', FORKING_PROCESS, str(self.root)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                 timeout=60)
        self.assertEqual((process.returncode, process.stdout, process.stderr),
                         (0, b"0 ['copy']\n", b''))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_a_path_given_up_is_left_alone_by_the_backstop_and_the_sweep(self):
        # The end of the with block removed the directory and took the path out of the registry,
        # and a real SIGINT comes before it detached the backstop. A directory that another
        # process then makes at that path is left alone, by the backstop as the object is
        # dropped and by the exit sweep. One that it makes in the instant between the removal
        # and the registry is the theoretical case of the limits: the cleanup removes it.
        lines, first = inspect.getsourcelines(iz.PrivateDirectory.disown)
        detach = first + next(index for index, text in enumerate(lines)
                              if 'self.backstop.detach()' in text)
        for name, line in (('after the registry', detach), ('before the registry', None)):
            with self.subTest(name):
                root = Path(tempfile.mkdtemp(dir=self.root))
                fired = []

                def local(frame, what, arg):
                    if not fired and what == 'line' and frame.f_lineno == line:
                        fired.append(line)
                        interrupt()
                    return local

                def start(frame, what, arg):
                    if fired or frame.f_code is not iz.PrivateDirectory.disown.__code__:
                        return None
                    if line is None:
                        fired.append('call')
                        interrupt()
                    return local
                copy = iz.ZipCopy(self.source, root)
                with default_interruptions(), self.assertRaises(KeyboardInterrupt):
                    sys.settrace(start)
                    try:
                        with copy:
                            pass
                    finally:
                        sys.settrace(None)
                self.assertEqual(len(fired), 1)
                copy.work.mkdir()
                (copy.work / 'victim').write_bytes(b'not to be removed')
                with backstop_warnings() as warned:
                    del copy
                    gc.collect()
                    iz.sweep_at_exit()
                left = [item.name for item in root.glob('zip-*/*')]
                self.assertEqual((warned, left), ([], ['victim'] if line else []))


@unittest.skipUnless(HAVE_AVBTOOL and HAVE_SSH, 'needs ssh-keygen, openssl and the pinned avbtool.py')
class FullKitTests(unittest.TestCase):
    """The complete checks with real signatures made by the pinned avbtool."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.kit = Kit(cls.tmp.name, avb=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def refused(self, path, check, pattern=None, **overrides):
        report = self.kit.check(path, **overrides)
        self.assertEqual(report['verdict'], 'REFUSE')
        self.assertFalse(report['checks'][check]['ok'], report['checks'][check])
        if pattern:
            self.assertRegex(report['checks'][check]['reason'], pattern)
        return report

    def test_synthetic_kit_passes(self):
        report = self.kit.check(self.kit.zip())
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        identity = report['checks']['release_identity']['detail']
        self.assertEqual((identity['build_number'], identity['stock_build']), (RELEASE, 'CP3A.261005.005'))
        self.assertEqual(sorted(report['checks']['vbmeta']['detail']['verified_images']), sorted(STATIC))
        self.assertEqual(report['checks']['flash_script']['detail']['super_splits'], 2)
        self.assertEqual(report['checks']['signature']['detail']['output'],
                         iz.good_line().replace(iz.KEY_FINGERPRINT, self.kit.fingerprint))

    def test_vbmeta_controls(self):
        kit = self.kit
        other = kit.key('other')
        cases = [
            ('unsigned', {'algorithm': 'NONE'}, 'NONE, not SHA256_RSA4096'),
            ('other key', {'key': other}, 'not byte identical to avb_pkmd.bin'),
            ('rollback', {'rollback': 0}, 'rollback index is 0'),
            ('flags', {'flags': 1}, 'flags 1'),
            ('patch level', {'props': [('com.android.build.system.fingerprint', FINGERPRINT.format(RELEASE)),
                                       ('com.android.build.system.security_patch', '2026-09-05')]},
             'security patch'),
            ('chain', {'extra': ('--chain_partition', f'vbmeta_system:1:{kit.work / "avb_pkmd.bin"}')},
             'chains to vbmeta_system'),
        ]
        for name, arguments, pattern in cases:
            with self.subTest(name):
                self.refused(kit.zip(vbmeta__img=kit.vbmeta(**arguments)), 'vbmeta', pattern)

    def test_kernel_command_line_descriptor_is_reported(self):
        vbmeta = self.kit.vbmeta(extra=('--kernel_cmdline', 'synthetic=1'))
        report = self.kit.check(self.kit.zip(vbmeta__img=vbmeta))
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['vbmeta']['detail']['kernel_cmdline_descriptors'], 1)

    def fake_tools(self, system, b_copy=b'', extra=None, fail=False):
        """Synthetic stand-ins for simg2img and lpunpack; neither real tool is built yet."""
        directory = Path(tempfile.mkdtemp(dir=self.kit.work))
        prepared = directory / 'system-prepared.img'
        prepared.write_bytes(system)
        simg2img = directory / 'simg2img'
        simg2img.write_text('#!/usr/bin/env python3\nimport sys\n' + ('sys.exit(3)\n' if fail else '') +
                            "open(sys.argv[-1], 'wb').write(b''.join(open(p, 'rb').read() for p in sys.argv[1:-1]))\n")
        lpunpack = directory / 'lpunpack'
        lpunpack.write_text('#!/usr/bin/env python3\nimport pathlib, shutil, sys\nout = pathlib.Path(sys.argv[2])\n'
                            f'shutil.copyfile({str(prepared)!r}, out / "system_a.img")\n'
                            f'(out / "system_b.img").write_bytes({b_copy!r})\n'
                            + (f'(out / {extra!r}).write_bytes(b"x")\n' if extra else ''))
        for tool in (simg2img, lpunpack):
            tool.chmod(0o755)
        return {'simg2img': str(simg2img), 'lpunpack': str(lpunpack)}

    def pinned(self, tools):
        return (mock.patch.object(iz, 'SIMG2IMG_SHA256', sha(Path(tools['simg2img']).read_bytes())),
                mock.patch.object(iz, 'LPUNPACK_SHA256', sha(Path(tools['lpunpack']).read_bytes())))

    def test_descriptor_without_its_image_is_refused(self):
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        vbmeta = kit.vbmeta(include=STATIC + ('system',))
        self.refused(kit.zip(vbmeta__img=vbmeta), 'vbmeta', 'needs the pinned simg2img')
        self.refused(kit.zip(vbmeta__img=vbmeta), 'vbmeta', 'simg2img is not built and pinned yet',
                     tools=self.fake_tools(system))
        self.assertEqual(kit.check(kit.zip(vbmeta__img=vbmeta, system__img=system))['verdict'], 'PASS')

    def test_dynamic_images_are_rebuilt_from_the_super_splits(self):
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        vbmeta = kit.vbmeta(include=STATIC + ('system',))
        path = kit.zip(vbmeta__img=vbmeta)
        tools = self.fake_tools(system)
        first, second = self.pinned(tools)
        with first, second:
            report = kit.check(path, tools=tools)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['vbmeta']['detail']['rebuilt_from_super'], ['system'])
        cases = [('full b copy', self.fake_tools(system, b_copy=b'data'), 'is not empty'),
                 ('other file', self.fake_tools(system, extra='notes.txt'), 'not a slot image'),
                 ('undescribed partition', self.fake_tools(system, extra='product_a.img'),
                  'holds product, which vbmeta does not describe'),
                 ('failing simg2img', self.fake_tools(system, fail=True), 'simg2img exited 3')]
        for name, tools, pattern in cases:
            with self.subTest(name):
                first, second = self.pinned(tools)
                with first, second:
                    self.refused(path, 'vbmeta', pattern, tools=tools)
        tools = self.fake_tools(system)
        first, _ = self.pinned(tools)
        with first, mock.patch.object(iz, 'LPUNPACK_SHA256', '0' * 64):
            self.refused(path, 'vbmeta', 'is not the pinned lpunpack', tools=tools)
        changed = system[:100] + bytes([system[100] ^ 1]) + system[101:]   # a data byte
        tools = self.fake_tools(changed)
        first, second = self.pinned(tools)
        with first, second:
            self.refused(path, 'vbmeta', 'avbtool verify_image exited 1', tools=tools)

    def test_the_private_directories_of_vbmeta_are_owned(self):
        # The extracted images and the super splits each have a private directory, made with
        # mode 0700 whatever the umask. An interruption right after either is made leaves
        # nothing. A path that exists already is refused and vbmeta fails, and a directory that
        # exists at the images' path is left as it is.
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        path = kit.zip(vbmeta__img=kit.vbmeta(include=STATIC + ('system',)))
        tools = self.fake_tools(system)
        first, second = self.pinned(tools)
        with first, second:
            self.assertEqual(kit.check(path, tools=tools)['verdict'], 'PASS')
            for prefix in ('avb-', 'splits-'):
                with self.subTest(prefix=prefix, case='interrupted once made'):
                    scratch = Path(tempfile.mkdtemp(dir=kit.work))
                    modes = []

                    def look_then_interrupt(directory):
                        modes.append(stat.S_IMODE(directory.stat().st_mode))
                        interrupt()
                    umask = os.umask(0)     # the mode does not come from the umask
                    try:
                        with default_interruptions(), \
                                after_mkdir(prefix, look_then_interrupt) as made, \
                                self.assertRaises(KeyboardInterrupt):
                            kit.check(path, tools=tools, scratch=scratch)
                    finally:
                        os.umask(umask)
                    self.assertEqual((len(made), modes), (1, [0o700]))
                    self.assertEqual(list(scratch.iterdir()), [])
                with self.subTest(prefix=prefix, case='exists already'):
                    scratch = Path(tempfile.mkdtemp(dir=kit.work))
                    taken = scratch / 'avb-taken' / 'splits-taken'
                    if prefix == 'avb-':
                        taken = taken.parent
                        taken.mkdir()
                        (taken / 'victim').write_bytes(b'not to be removed')
                    refusal = f'^the private directory {re.escape(str(taken))} exists already$'
                    with mock.patch.object(iz.secrets, 'token_hex', return_value='taken'), \
                            after_mkdir('avb-', lambda avb: (avb / 'splits-taken').mkdir()):
                        self.refused(path, 'vbmeta', refusal, tools=tools, scratch=scratch)
                    left = [(item.relative_to(scratch).as_posix(), item.is_dir())
                            for item in sorted(scratch.rglob('*'))]
                    self.assertEqual(left, [] if prefix == 'splits-' else
                                     [('avb-taken', True), ('avb-taken/victim', False)])

    def test_an_interruption_that_no_handler_covers_leaves_no_extracted_image(self):
        # The boundaries that no handler covers (UNCOVERED), for the directory of the extracted
        # images and for that of the super splits, which lies in the former. The interruption goes
        # on, and once it has, and the objects are dropped, nothing is left, without a warning.
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        path = kit.zip(vbmeta__img=kit.vbmeta(include=STATIC + ('system',)))
        tools = self.fake_tools(system)
        first, second = self.pinned(tools)
        with first, second:
            for prefix, boundary in itertools.product(('avb-', 'splits-'), UNCOVERED):
                with self.subTest(directory=prefix, boundary=boundary):
                    scratch = Path(tempfile.mkdtemp(dir=kit.work))
                    with backstop_warnings() as warned:
                        reached, kind = interrupted_at(boundary, prefix, lambda: kit.check(
                            path, tools=tools, scratch=scratch))
                    self.assertEqual((reached, kind, warned), ([boundary], KeyboardInterrupt, []))
                    self.assertEqual(list(scratch.iterdir()), [])

    def double_interruption_plan(self):
        """The private directories of the extracted images, in a second case made read only, and
        of the super splits, which lie in the former, as a kit whose system image is rebuilt from
        its super splits makes them, as cases of exit_after_two_interruptions."""
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        dynamic = kit.zip(vbmeta__img=kit.vbmeta(include=STATIC + ('system',)))
        cases = [{'prefix': 'avb-', 'caller': 'dynamic check', 'locked': locked}
                 for locked in (False, True)]
        cases += [{'prefix': 'splits-', 'caller': 'dynamic check', 'locked': False}]
        return {'kit': kit.state(), 'work': str(kit.work), 'zip': None, 'cases': cases,
                'tags': None, 'tools': self.fake_tools(system), 'dynamic': str(dynamic)}

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_a_backstop_stopped_at_its_entry_leaves_no_extracted_image(self):
        # A first SIGINT at the start of __exit__, and a second at the call or the first line of
        # the backstop as the first is collected, for the extracted images and the super splits.
        assert_stopped_backstops_leave_their_directories_to_the_sweep(
            self, self.double_interruption_plan())

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_python_removes_at_its_exit_the_extracted_images_that_a_stopped_backstop_left(self):
        assert_python_exit_removes_what_stopped_backstops_left(
            self, self.double_interruption_plan())

    def test_a_kit_with_a_member_larger_than_128_mib_passes(self):
        # An unchanged kit whose stored member holds 129 MiB passes as a small one, with the
        # digest of its bytes, and decide takes the identity kept under that digest.
        kit = self.kit
        path = kit.zip(script__txt=bytes(129 << 20))
        report = kit.check(path)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['sha256'], sha(path.read_bytes()))
        image = copied_by('verified_image', kit, path, Path(tempfile.mkdtemp(dir=kit.work)))
        self.assertEqual(image.sha256, report['sha256'])
        path.unlink()

    def test_a_relative_scratch_directory_passes(self):
        # scratch is relative to the working directory, and avbtool runs in the private
        # directory of the extracted images: it finds them, as their paths are absolute.
        kit = self.kit
        path = kit.zip()
        scratch = Path(tempfile.mkdtemp(dir=kit.work))
        previous = os.getcwd()
        os.chdir(scratch.parent)
        try:
            report = kit.check(path, scratch=Path(scratch.name))
        finally:
            os.chdir(previous)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(list(scratch.iterdir()), [])

    def test_a_passing_check_keeps_the_verified_images(self):
        kit = self.kit
        keep = Path(tempfile.mkdtemp(dir=kit.work))
        report = kit.check(kit.zip(), keep=keep)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(sorted(path.name for path in keep.iterdir()), sorted(f'{name}.img' for name in STATIC))
        for name in STATIC:
            self.assertEqual((keep / f'{name}.img').read_bytes(), kit.members[f'{name}.img'])
        system = kit.image('system', size=16384, kind='hashtree')
        tools = self.fake_tools(system)
        first, second = self.pinned(tools)
        rebuilt = Path(tempfile.mkdtemp(dir=kit.work))
        with first, second:
            report = kit.check(kit.zip(vbmeta__img=kit.vbmeta(include=STATIC + ('system',))), tools=tools,
                               keep=rebuilt)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual((rebuilt / 'system.img').read_bytes(), system)
        boot = bytearray(kit.members['boot.img'])
        boot[100] ^= 0xff
        refused = Path(tempfile.mkdtemp(dir=kit.work))
        # check_vbmeta itself moves nothing before every vbmeta check passed, cleanup or not
        with mock.patch.object(iz, 'discard', lambda keep: None):
            self.refused(kit.zip(boot__img=bytes(boot)), 'vbmeta', 'avbtool verify_image exited 1', keep=refused)
        self.assertEqual(list(refused.iterdir()), [])
        # vbmeta passes and keeps its images, then a later check fails: the images go again
        report = self.refused(kit.zip(flash_dash_all__sh=b'#!/bin/sh\nexit 1\n'), 'flash_script', keep=refused)
        self.assertTrue(report['checks']['vbmeta']['ok'])
        self.assertEqual(list(refused.iterdir()), [])
        (refused / 'stale.img').write_bytes(b'stale')
        report = kit.check(kit.zip(), keep=refused)
        self.assertEqual((report['verdict'], report['checks']), ('REFUSE', {}))
        self.assertIn('is not an empty directory to keep the verified images in', report['reasons'][0])
        self.assertEqual([path.name for path in refused.iterdir()], ['stale.img'])
        andrix = Path(tempfile.mkdtemp(dir=kit.work))
        with mock.patch.object(iz, 'BASES', kit.bases), \
                mock.patch.object(iz, 'WORKSHOP_PKMD_SHA256', sha(kit.members['avb_pkmd.bin'])):
            with self.assertRaisesRegex(Refusal, 'neither the legacy nor the optimized form'):
                iz.andrix_identity(self.andrix_zip(name='2026100600-broken',
                                                   extra={'flash-all.sh': b'#!/bin/sh\nexit 1\n'}),
                                   avbtool=AVBTOOL, keep=andrix)
            self.assertEqual(list(andrix.iterdir()), [])
            identity = iz.andrix_identity(self.andrix_zip(name='2026100600-kept'), avbtool=AVBTOOL, keep=andrix)
            with self.assertRaisesRegex(Refusal, 'is not an empty directory'):
                iz.andrix_identity(self.andrix_zip(name='2026100600-again'), avbtool=AVBTOOL, keep=andrix)
        self.assertEqual(identity['base_tag'], '2026100600')
        self.assertEqual(sorted(path.name for path in andrix.iterdir()),
                         sorted(f'{name}.img' for name in STATIC if name != 'boot'))

    def test_the_andrix_zip_is_read_once_into_a_private_copy(self):
        # The zip is replaced or changed at each boundary of andrix_identity's reads. The copy is
        # read, never the zip, so the identity, its SHA-256, its firmware and the kept images are
        # those of the bytes copied, and the copy goes with its directory every time.
        kit = self.kit
        good = self.andrix_zip(name='2026100600-handle')
        data = good.read_bytes()
        untagged = self.andrix_zip(name='2026100600-untagged', props=[
            ('com.android.build.system.fingerprint',
             'google/caiman/caiman:17/CP3A.261005.005/andrix1:userdebug/release-keys'),
            ('com.android.build.system.security_patch', '2026-10-05')]).read_bytes()
        scratch = Path(tempfile.mkdtemp(dir=kit.work))
        images = sorted(f'{name}.img' for name in STATIC if name != 'boot')
        cases = [('during the copy', 'replaced'), ('during the copy', 'removed')]
        cases += [(boundary, kind) for boundary in ('after the copy', 'during the archive reads',
                                                    'after the archive checks')
                  for kind in ('replaced', 'removed', 'rewritten in place')]
        with mock.patch.object(iz, 'BASES', kit.bases), \
                mock.patch.object(iz, 'WORKSHOP_PKMD_SHA256', sha(kit.members['avb_pkmd.bin'])):
            identity = iz.andrix_identity(good, avbtool=AVBTOOL, scratch=scratch)
            self.assertEqual(identity['sha256'], sha(data))
            for boundary, kind in cases:
                with self.subTest(boundary=boundary, kind=kind):
                    restore(good, data)
                    keep = Path(tempfile.mkdtemp(dir=kit.work))
                    with Watch(good, {boundary: changes(good, untagged)[kind]}) as watch:
                        self.assertEqual(iz.andrix_identity(good, avbtool=AVBTOOL, scratch=scratch,
                                                            keep=keep), identity)
                    self.assertEqual((watch.plan, watch.copied), ({}, data))
                    self.assertEqual(sorted(path.name for path in keep.iterdir()), images)
                    self.assertEqual(list(scratch.iterdir()), [])
            # interrupted, or refused, it keeps nothing and leaves no copy
            restore(good, data)
            keep = Path(tempfile.mkdtemp(dir=kit.work))
            with mock.patch.object(iz, '_firmware', side_effect=KeyboardInterrupt), \
                    self.assertRaises(KeyboardInterrupt):
                iz.andrix_identity(good, avbtool=AVBTOOL, scratch=scratch, keep=keep)
            self.assertEqual((list(keep.iterdir()), list(scratch.iterdir())), ([], []))
            with mock.patch.object(iz, 'WORKSHOP_PKMD_SHA256', None), \
                    self.assertRaisesRegex(Refusal, 'workshop key for this phone is not recorded'):
                iz.andrix_identity(good, avbtool=AVBTOOL, scratch=scratch)
            self.assertEqual(list(scratch.iterdir()), [])
            # read again, the file now at the path holds other bytes, which refuse
            restore(good, untagged)
            with self.assertRaisesRegex(Refusal, 'is not a file directly under caiman-install-2026100600-handle/'):
                iz.andrix_identity(good, avbtool=AVBTOOL, scratch=scratch)

    def test_a_kit_changed_after_it_was_copied_passes_as_copied(self):
        # The earlier probe replaced the kit with a validly signed one right after the real
        # signature check, and every later check passed on the replacement. The checks read the
        # private copy now: a kit changed after it was copied passes as the bytes copied, with
        # their digest, their firmware and their images, whatever replaced it.
        kit = self.kit
        others = {'a validly signed kit':
                  kit.zip(script__txt=b'replacement bytes not covered by vbmeta\n'),
                  'a kit that fails every check': kit.zip(
                      sign=False, flash_dash_all__sh=kit.members['flash-all.sh'].replace(
                          b'fastboot erase dpm_b\n', LOCKED), avb_pkmd__bin=b'other synthetic key',
                      android_dash_info__txt=INFO.replace(b'board=caiman', b'board=komodo'))}
        cases = [(name, 'replaced', other.read_bytes()) for name, other in others.items()]
        cases += [('none', kind, b'') for kind in ('removed', 'rewritten in place')]
        path = kit.zip()
        original = path.read_bytes()
        keep = Path(tempfile.mkdtemp(dir=kit.work))
        unchanged = kit.check(path, keep=keep)
        self.assertEqual(unchanged['verdict'], 'PASS', unchanged['reasons'])
        images = {image.name: image.read_bytes() for image in keep.iterdir()}
        for boundary in BOUNDARIES[1:]:
            for name, kind, data in cases:
                with self.subTest(boundary=boundary, kind=kind, replacement=name):
                    restore(path, original)
                    keep = Path(tempfile.mkdtemp(dir=kit.work))
                    with Watch(path, {boundary: changes(path, data)[kind]}) as watch:
                        report = kit.check(path, keep=keep)
                    self.assertEqual((watch.plan, watch.copied), ({}, original))
                    self.assertEqual(report, unchanged)
                    self.assertEqual({image.name: image.read_bytes() for image in keep.iterdir()},
                                     images)
                    read_as_copied(self, watch, report)

    def test_a_kit_changed_while_it_is_copied_is_checked_as_read(self):
        # Replaced meanwhile, the kit opened before is read to its end and passes. Rewritten in
        # place, the bytes read are not those signed: the report names them and refuses them,
        # and keeps no image.
        kit = self.kit
        path = kit.zip()
        original = path.read_bytes()
        unchanged = kit.check(path)
        for kind in ('replaced', 'rewritten in place'):
            with self.subTest(kind=kind):
                restore(path, original)
                keep = Path(tempfile.mkdtemp(dir=kit.work))
                change = changes(path, kit.zip().read_bytes())[kind]
                with Watch(path, {'during the copy': change}) as watch:
                    report = kit.check(path, keep=keep)
                self.assertEqual(watch.plan, {})
                read_as_copied(self, watch, report)
                if kind == 'replaced':
                    self.assertEqual(report, unchanged)
                    continue
                self.assertEqual(report['verdict'], 'REFUSE')
                self.assertFalse(report['checks']['signature']['ok'])
                self.assertNotEqual(watch.copied, original)
                self.assertEqual(list(keep.iterdir()), [])
                self.assertNotIn('firmware', report)

    def test_a_rewrite_put_back_within_one_timestamp_tick_changes_nothing(self):
        # The probe that found one shared handle not enough. Right after ssh-keygen verified the
        # kit, it is rewritten in place by a valid archive of its size whose bootloader differs,
        # and put back once the firmware digests are read, its times put back each time. Within
        # one tick of a coarse timestamp clock, the handle's last comparison saw nothing, and a
        # passing report named the other bootloader. The checks read the private copy now.
        kit = self.kit
        bootloader = f'bootloader-caiman-{BL}.img'
        path = kit.zip()
        original = path.read_bytes()
        intermediate = kit.zip(**{member_keyword(bootloader): b'different bootloader'}).read_bytes()
        self.assertEqual(len(intermediate), len(original))
        firmware = {bootloader: sha(b'synthetic bootloader'),
                    f'radio-caiman-{BB.lower()}.img': sha(b'synthetic radio')}
        for coarse in (False, True):
            with self.subTest(coarse=coarse):
                restore(path, original)
                keep = Path(tempfile.mkdtemp(dir=kit.work))
                rewrite, put_back = rewritten_and_restored(path, intermediate)
                plan = {'after the signature check': rewrite, 'after the archive checks': put_back}
                with coarse_times(path, coarse), Watch(path, plan) as watch:
                    report = kit.check(path, keep=keep)
                self.assertEqual((watch.plan, path.read_bytes()), ({}, original))
                self.assertEqual(report['verdict'], 'PASS', report['reasons'])
                self.assertEqual((report['sha256'], report['firmware']), (sha(original), firmware))
                self.assertEqual({image.name: image.read_bytes() for image in keep.iterdir()},
                                 {f'{name}.img': kit.members[f'{name}.img'] for name in STATIC})
                read_as_copied(self, watch, report)

    def test_every_private_copy_goes_when_a_check_raises(self):
        kit = self.kit
        path = kit.zip()
        scratch = Path(tempfile.mkdtemp(dir=kit.work))
        keep = Path(tempfile.mkdtemp(dir=kit.work))
        # vbmeta has kept its images when the interruption comes
        with mock.patch.object(iz, '_firmware', side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            kit.check(path, scratch=scratch, keep=keep)
        self.assertEqual((list(scratch.iterdir()), list(keep.iterdir())), ([], []))

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_a_zip_copy_that_cannot_be_removed_discards_the_kept_images(self):
        # Every check passes and vbmeta keeps its images, then the zip's private copy cannot be
        # removed. The refusal discards the images, in check as in andrix_identity, and the
        # backstop warns of the copy, which it cannot remove either, when the object is dropped.
        kit = self.kit
        andrix = self.andrix_zip(name='2026100600-locked')
        firmware = iz._firmware
        for copier in ('check', 'andrix_identity'):
            with self.subTest(copier=copier):
                scratch = Path(tempfile.mkdtemp(dir=kit.work))
                keep = Path(tempfile.mkdtemp(dir=kit.work))
                kept = []

                def read_then_lock(*args):
                    found = firmware(*args)
                    kept.extend(sorted(image.name for image in keep.iterdir()))
                    [directory] = scratch.glob('zip-*')
                    directory.chmod(0o500)
                    return found
                try:
                    with backstop_warnings() as warned, \
                            mock.patch.object(iz, '_firmware', read_then_lock), \
                            mock.patch.object(iz, 'BASES', kit.bases), \
                            mock.patch.object(iz, 'WORKSHOP_PKMD_SHA256',
                                              sha(kit.members['avb_pkmd.bin'])), \
                            self.assertRaisesRegex(Refusal, '^the private directory '
                                                   f'{re.escape(str(scratch))}/zip-[^/]+ could '
                                                   'not be removed: '):
                        if copier == 'check':
                            kit.check(kit.zip(), scratch=scratch, keep=keep)
                        else:
                            iz.andrix_identity(andrix, avbtool=AVBTOOL, scratch=scratch, keep=keep)
                    images = STATIC if copier == 'check' else STATIC[1:]   # Andrix's without boot
                    self.assertEqual(kept, sorted(f'{name}.img' for name in images))
                    self.assertEqual(list(keep.iterdir()), [])
                    self.assertEqual(len(warned), 1)
                    self.assertRegex(warned[0], warning_of(scratch, 'zip-', r'\[Errno 13\] '))
                finally:
                    for directory in scratch.iterdir():
                        directory.chmod(0o700)
                    shutil.rmtree(scratch)

    @unittest.skipIf(os.geteuid() == 0, 'root removes files from a directory it cannot write')
    def test_extracted_images_that_cannot_be_removed_refuse_vbmeta(self):
        kit = self.kit
        path = kit.zip()
        scratch = Path(tempfile.mkdtemp(dir=kit.work))
        real_run = subprocess.run

        def locking_run(command, *args, **kwargs):
            completed = real_run(command, *args, **kwargs)
            if 'info_image' in command:
                [directory] = scratch.glob('avb-*')
                directory.chmod(0o500)
            return completed
        try:
            with backstop_warnings() as warned, \
                    mock.patch.object(iz.subprocess, 'run', locking_run):
                report = kit.check(path, scratch=scratch)
            self.assertEqual(report['verdict'], 'REFUSE')
            self.assertRegex(report['checks']['vbmeta']['reason'],
                             f'^the private directory {re.escape(str(scratch))}/avb-[^/]+ '
                             'could not be removed: ')
            # the backstop cannot remove it either, and warns of it when the object is dropped
            self.assertEqual(len(warned), 1)
            self.assertRegex(warned[0], warning_of(scratch, 'avb-', r'\[Errno 13\] '))
        finally:
            for directory in scratch.iterdir():
                directory.chmod(0o700)
            shutil.rmtree(scratch)

    def test_a_passing_report_names_the_firmware_it_read(self):
        kit = self.kit
        report = kit.check(kit.zip())
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['firmware'], {f'bootloader-caiman-{BL}.img': sha(b'synthetic bootloader'),
                                              f'radio-caiman-{BB.lower()}.img': sha(b'synthetic radio')})
        refused = kit.check(kit.zip(flash_dash_all__sh=b'#!/bin/sh\nexit 1\n'))
        self.assertEqual(refused['verdict'], 'REFUSE')
        self.assertNotIn('firmware', refused)

    def test_the_official_kit_is_not_opened_again_after_its_check(self):
        # The kit's firmware digests come from its verified bytes. The path is replaced once the
        # check returned, with other firmware or with the Andrix zip's, and changes nothing.
        kit = self.kit
        bootloader = f'bootloader-caiman-{BL}.img'.replace('.', '__').replace('-', '_dash_')
        andrix = self.andrix_zip(name='2026100600-official')
        checked = iz.check
        other = {bootloader: b'other bootloader bytes'}
        for name, verified, replacement, pattern in (
                ('verified alike, replaced by other firmware', kit.zip(), kit.zip(**other), None),
                ('verified with other firmware, replaced by the same', kit.zip(**other), kit.zip(),
                 'not byte identical to the official kit of 2026100600')):
            original = verified.read_bytes()

            def check_then_replace(path, **kwargs):
                report = checked(path, **kwargs)
                verified.with_name('replacement').write_bytes(replacement.read_bytes())
                os.replace(verified.with_name('replacement'), path)
                return report
            with self.subTest(name), mock.patch.object(iz, 'check', check_then_replace):
                if pattern:
                    with self.assertRaisesRegex(Refusal, pattern):
                        self.andrix_check(andrix, official=verified)
                else:
                    identity = self.andrix_check(andrix, official=verified)
                    self.assertTrue(identity.source.endswith(f'the official kit {sha(original)}'))
                self.assertEqual(verified.read_bytes(), replacement.read_bytes())

    def test_rollback_location_and_image_size(self):
        self.refused(self.kit.zip(vbmeta__img=self.kit.vbmeta(location=1)), 'vbmeta',
                     'rollback index location 1')
        with mock.patch.object(iz, 'IMAGE', 1000):
            self.refused(self.kit.zip(), 'vbmeta', 'is larger than 1000 bytes')

    def andrix_zip(self, props=None, name='2026100600-andrix1', extra=None):
        kit = self.kit
        if props is None:
            props = [('com.android.build.system.fingerprint',
                      'google/caiman/caiman:17/CP3A.261005.005/andrix1:userdebug/release-keys'),
                     ('com.android.build.system.security_patch', '2026-10-05'),
                     ('com.andrix.build.base_tag', '2026100600')]
        vbmeta = kit.vbmeta(props=props, include=tuple(item for item in STATIC if item != 'boot'))
        changes = {'vbmeta.img': vbmeta, **(extra or {})}
        return kit.zip(release=name, sign=False, **{member.replace('-', '_dash_').replace('.', '__'): data
                                                  for member, data in changes.items()})

    def andrix_check(self, path, **overrides):
        """andrix_image with this kit's key as the workshop key and this kit as the official one."""
        import version_criterion as vc
        kit = self.kit
        official = overrides.pop('official', None) or kit.zip()
        details = {'records': {'2026100600': RECORD}, 'signers': kit.signers, 'stable': kit.stable,
                   'avbtool': AVBTOOL, 'official': official}
        details.update(overrides.pop('details', {}))
        key = overrides.pop('workshop', sha(kit.members['avb_pkmd.bin']))
        table = vc.load_table([RECORD], require_tree_head=False)
        with mock.patch.object(iz, 'PKMD_SHA256', sha(kit.members['avb_pkmd.bin'])), \
                mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                mock.patch.object(iz, 'BASES', kit.bases), \
                mock.patch.object(iz, 'WORKSHOP_PKMD_SHA256', key):
            return vc.andrix_image(path, details, table)

    def test_andrix_identity_is_cross_checked(self):
        kit = self.kit
        path = self.andrix_zip()
        identity = self.andrix_check(path)
        self.assertEqual((identity.kind, identity.release.number, identity.stock_build),
                         ('andrix', '2026100600', 'CP3A.261005.005'))
        self.assertEqual(identity.sha256, sha(path.read_bytes()))
        fingerprint = ('com.android.build.system.fingerprint',
                       'google/caiman/caiman:17/CP3A.261005.005/andrix1:userdebug/release-keys')
        patch = ('com.android.build.system.security_patch', '2026-10-05')
        tag = ('com.andrix.build.base_tag', '2026100600')
        for name, props, pattern in (
                ('no base tag', [fingerprint, patch], 'no single signed com.andrix.build.base_tag'),
                ('preview base tag', [fingerprint, patch, (tag[0], '2026100601')], 'security preview'),
                ('test keys', [(fingerprint[0], fingerprint[1].replace('release-keys', 'test-keys')), patch, tag],
                 'not one caiman release-keys'),
                ('other stock build', [(fingerprint[0], fingerprint[1].replace('CP3A.261005.005', 'CP3A.260905.009')),
                                       patch, tag], 'not the CP3A.261005.005 recorded')):
            with self.subTest(name), self.assertRaisesRegex(Refusal, pattern):
                self.andrix_check(self.andrix_zip(props, name=f'2026100600-{name.replace(" ", "-")}'))
        with self.assertRaisesRegex(Refusal, 'workshop key for this phone is not recorded'):
            self.andrix_check(path, workshop=None)
        with self.assertRaisesRegex(Refusal, 'not signed with the workshop key'):
            self.andrix_check(path, workshop='0' * 64)
        with self.assertRaisesRegex(Refusal, 'needs the official GrapheneOS kit'):
            self.andrix_check(path, details={'official': None})
        other = self.andrix_zip(name='2026100600-otherfirmware',
                                extra={f'bootloader-caiman-{BL}.img': b'other bootloader bytes'})
        with self.assertRaisesRegex(Refusal, 'not byte identical to the official kit'):
            self.andrix_check(other)

    def test_andrix_zip_with_other_firmware_is_refused(self):
        # the review's probe: base tag 2026100600 claimed, August firmware carried
        legacy = official.render_legacy(RELEASE, OLD_BL, OLD_BB)
        members = {'android-info.txt': official.android_info(OLD_BL, OLD_BB).encode(),
                   'flash-all.sh': official.capture(legacy, splits=2),
                   f'bootloader-caiman-{OLD_BL}.img': b'august bootloader',
                   f'radio-caiman-{OLD_BB.lower()}.img': b'august radio',
                   f'bootloader-caiman-{BL}.img': None, f'radio-caiman-{BB.lower()}.img': None}
        path = self.andrix_zip(name='2026100600-august', extra=members)
        with self.assertRaisesRegex(Refusal, 'is not the .* recorded for 2026100600'):
            self.andrix_check(path)

    def test_grapheneos_identity_for_the_criterion(self):
        import version_criterion as vc
        kit = self.kit
        path = kit.zip()
        details = {'records': {'2026100600': RECORD}, 'signers': kit.signers, 'stable': kit.stable,
                   'avbtool': AVBTOOL}
        with mock.patch.object(iz, 'PKMD_SHA256', sha(kit.members['avb_pkmd.bin'])), \
                mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                mock.patch.object(iz, 'BASES', kit.bases):
            identity = vc.grapheneos_image(path, details)
            self.assertEqual((identity.release.number, identity.stock_build, identity.sha256),
                             ('2026100600', 'CP3A.261005.005', sha(path.read_bytes())))
            locked = kit.zip(flash_dash_all__sh=kit.members['flash-all.sh'] + b'fastboot flashing lock\n')
            with self.assertRaisesRegex(Refusal, 'does not pass the checks that need no phone'):
                vc.grapheneos_image(locked, details)

    def test_changed_image_fails_avbtool(self):
        kit = self.kit
        boot = bytearray(kit.members['boot.img'])
        boot[100] ^= 0xff
        self.refused(kit.zip(boot__img=bytes(boot)), 'vbmeta', 'avbtool verify_image exited 1')

    def test_unpinned_avbtool_is_refused(self):
        copy = self.kit.work / 'avbtool-copy.py'
        copy.write_bytes(AVBTOOL.read_bytes() + b'\n')
        self.refused(self.kit.zip(), 'vbmeta', 'not external/avb/avbtool.py of the pinned tree', avbtool=copy)

    def test_release_identity_controls(self):
        kit = self.kit
        system = 'com.android.build.system.fingerprint'
        patch = ('com.android.build.system.security_patch', '2026-10-05')
        no_boot = tuple(name for name in STATIC if name != 'boot')   # boot.img carries its own
        cases = [
            ('older build', [(system, FINGERPRINT.format('2026100200')), patch], no_boot,
             'is 2026100200, not'),
            ('other device', [(system, 'google/komodo/komodo:17/CP3A.261005.005/2026100600:user/release-keys'),
                              patch], no_boot, 'not a caiman user release-keys'),
            ('userdebug', [(system, FINGERPRINT.format(RELEASE).replace(':user/', ':userdebug/')), patch],
             no_boot, 'not a caiman user release-keys'),
            ('test keys', [(system, FINGERPRINT.format(RELEASE).replace('release-keys', 'test-keys')), patch],
             no_boot, 'not a caiman user release-keys'),
            ('other stock build', [(system, FINGERPRINT.format(RELEASE).replace('CP3A.261005.005',
                                                                                'CP3A.260905.009')), patch],
             no_boot, 'adevtool records CP3A.261005.005'),
            ('fingerprints disagree', [(system, FINGERPRINT.format('2026100200')), patch], STATIC,
             'fingerprints inside the zip disagree'),
            ('no system fingerprint', [patch], STATIC, 'no com.android.build.system.fingerprint'),
        ]
        for name, props, include, pattern in cases:
            with self.subTest(name):
                self.refused(kit.zip(vbmeta__img=kit.vbmeta(props=props, include=include)),
                             'release_identity', pattern)
        self.refused(kit.zip(), 'release_identity', 'older than the zip release',
                     stable=kit.stable_file('2026100200'))

    def test_security_preview_kit(self):
        kit = self.kit
        props = [('com.android.build.system.fingerprint', FINGERPRINT.format('2026100601')),
                 ('com.android.build.system.security_patch', '2026-10-05')]
        # boot.img carries a 2026100600 fingerprint, so its descriptor stays out of this vbmeta
        vbmeta = kit.vbmeta(props=props, include=tuple(name for name in STATIC if name != 'boot'))
        path = kit.zip(release='2026100601', vbmeta__img=vbmeta)
        report = kit.check(path, release='2026100601')
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['release_identity']['detail']['build_number'], '2026100601')


@unittest.skipUnless(HAVE_SSH, 'needs ssh-keygen')
class CommandLineTests(unittest.TestCase):
    def test_exit_code_and_report(self):
        with tempfile.TemporaryDirectory() as work:
            kit = Kit(work, avb=False)
            path = kit.zip()
            record = Path(work) / 'record.json'
            record.write_text(json.dumps(RECORD))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), \
                    mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                    mock.patch.object(iz, 'BASES', kit.bases):
                status = iz.main(['--zip', str(path), '--allowed-signers', str(kit.signers),
                                  '--release', RELEASE, '--stable', str(kit.stable),
                                  '--security-patch', '2026-10-05', '--record', str(record),
                                  '--avbtool', str(Path(work) / 'none')])
            report = json.loads(output.getvalue())
            self.assertEqual((status, report['verdict']), (1, 'REFUSE'))
            self.assertTrue(report['checks']['signature']['ok'])

    def test_a_copy_that_cannot_be_removed_is_a_refusal(self):
        # check raises Refusal only when the zip's private copy cannot be removed
        refusal = Refusal('the private directory zip-copy could not be removed: synthetic error')
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as work, contextlib.redirect_stdout(output), \
                mock.patch.object(iz, 'check', side_effect=refusal):
            record = Path(work) / 'record.json'
            record.write_text(json.dumps(RECORD))
            status = iz.main(['--zip', f'caiman-install-{RELEASE}.zip', '--allowed-signers',
                              'allowed_signers', '--release', RELEASE, '--stable', 'caiman-stable',
                              '--record', str(record), '--avbtool', 'avbtool.py'])
        self.assertEqual((status, json.loads(output.getvalue())),
                         (1, {'verdict': 'REFUSE', 'reasons': [str(refusal)], 'checks': {}}))

    def test_an_io_error_that_keeps_the_copy_is_printed_as_a_refusal(self):
        # The zip's private copy cannot be removed after the checks because of an I/O error, not
        # a permission error. The command line prints that refusal rather than letting the error
        # escape, and the backstop warns of the copy, which it cannot remove either.
        with tempfile.TemporaryDirectory() as work:
            kit = Kit(work, avb=False)
            path = kit.zip()
            record = Path(work) / 'record.json'
            record.write_text(json.dumps(RECORD))
            system = Path(work) / 'temporary'
            system.mkdir()
            real = shutil.rmtree

            def failing(directory, *args, **kwargs):
                if Path(directory).name.startswith('zip-'):
                    raise OSError(errno.EIO, 'synthetic removal error')
                return real(directory, *args, **kwargs)
            output = io.StringIO()
            with backstop_warnings() as warned, contextlib.redirect_stdout(output), \
                    mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                    mock.patch.object(iz, 'BASES', kit.bases), \
                    mock.patch.object(tempfile, 'tempdir', str(system)), \
                    mock.patch.object(iz.shutil, 'rmtree', failing):
                status = iz.main(['--zip', str(path), '--allowed-signers', str(kit.signers),
                                  '--release', RELEASE, '--stable', str(kit.stable),
                                  '--security-patch', '2026-10-05', '--record', str(record),
                                  '--avbtool', str(Path(work) / 'none')])
                gc.collect()
            [left] = system.iterdir()
            refusal = (f'the private directory {left} could not be removed: [Errno 5] synthetic '
                       'removal error')
            self.assertEqual((status, json.loads(output.getvalue())),
                             (1, {'verdict': 'REFUSE', 'reasons': [refusal], 'checks': {}}))
            self.assertEqual([item.name for item in left.iterdir()], [path.name])
            self.assertEqual(warned, [f'warning: {refusal}'])
            iz.remove_private(left)


if __name__ == '__main__':
    unittest.main()
