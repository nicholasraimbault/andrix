#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The checks that need no phone, for a GrapheneOS caiman install zip.

"The way back" in plans/2026-10-09-caiman-workshop-phone.md lists them: the zip's SSH
signature through the pinned allowed signers, the release identity from the build number
inside the zip, the avb_pkmd.bin digest GrapheneOS publishes for the Pixel 9 Pro, the
android-info.txt requirements, the flash script, and avbtool verify_image on vbmeta with
an embedded key byte identical to avb_pkmd.bin. Every check runs and reports; the zip
passes only if all of them pass. The tool reads the zip and runs ssh-keygen and the
pinned avbtool.py. It contacts nothing.

The zip is read once, from its start to its end, into a private copy, and its SHA-256 is that
of the bytes copied. ssh-keygen's verification, every archive check and the firmware digests
read only that copy, so each concerns exactly the bytes that the SHA-256 names, whatever
happens to the zip meanwhile. The signature and the allowed signers file are read once each.

The build number is read from the fingerprints in vbmeta's signed property descriptors.
avbtool verify_image needs every image that a vbmeta descriptor names beside vbmeta.img.
An install zip written by optimize-factory-image carries the dynamic partitions only
inside super splits, so for such a zip this check refuses and names the missing images.
"""
import argparse
import atexit
import calendar
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import weakref
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adevtool_record  # noqa: E402
import caiman  # noqa: E402
from caiman import Refusal, refuse  # noqa: E402
import flash_script  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BASES = ROOT / 'upstream' / 'bases'
SIGNER = 'contact@grapheneos.org'
NAMESPACE = 'factory images'
KEY_FINGERPRINT = 'SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM'
# GrapheneOS's published avb_pkmd.bin SHA-256 for the Pixel 9 Pro
PKMD_SHA256 = 'f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86'
# external/avb/avbtool.py in the pinned tree, GrapheneOS 2026081300
AVBTOOL_SHA256 = '1aa6f2b462aa67aa3fdf488bee83ab517de8ad9d8228c7b45c35267ab2cf6781'
# simg2img and lpunpack built from the pinned tree. Neither is built yet, so the rebuild of the
# dynamic partitions refuses until their SHA-256 values are recorded here.
SIMG2IMG_SHA256 = None
LPUNPACK_SHA256 = None
# debugfs reads files out of the verified ext4 images (neverallow_check.py). It is pinned with the
# two above, from the same reviewed host tool set, and refuses until its SHA-256 is recorded here.
DEBUGFS_SHA256 = None
# The workshop key set's avb_pkmd.bin for this phone (decision 2). It is not generated yet, so
# every Andrix zip is refused until its SHA-256 is recorded here.
WORKSHOP_PKMD_SHA256 = None
SHA256_RSA4096 = 2
SMALL = 1 << 20
IMAGE = 512 << 20
COMMAND_TIMEOUT = 1800

_FINGERPRINT_KEY = re.compile(r'com\.android\.build\.([a-z0-9_]+)\.fingerprint')
_FINGERPRINT = re.compile(r'([^/\s]+)/([^/\s]+)/([^/:\s]+):([^/\s]+)/(' + caiman.BUILD_ID.pattern
                          + r')/([0-9]{10}):([a-z]+)/([a-z-]+)')
_PARTITION = re.compile(r'[a-z0-9_]{1,64}')
# an Andrix build number need not be a release number, so only its form is checked
_ANDRIX_FINGERPRINT = re.compile(r'[^/\s]+/[^/\s]+/([^/:\s]+):[^/\s]+/(' + caiman.BUILD_ID.pattern
                                 + r')/[A-Za-z0-9._-]+:(user|userdebug)/([a-z-]+)')
ALGORITHMS = {0: 'NONE', 1: 'SHA256_RSA2048', 2: 'SHA256_RSA4096', 3: 'SHA256_RSA8192',
              4: 'SHA512_RSA2048', 5: 'SHA512_RSA4096', 6: 'SHA512_RSA8192', 7: 'MLDSA65',
              8: 'MLDSA87'}


def good_line():
    return f'Good "{NAMESPACE}" signature for {SIGNER} with ED25519 key {KEY_FINGERPRINT}'


def pinned_signers_digest(bases=None):
    """The allowed signers digest that every upstream base record pins."""
    digests = set()
    for path in sorted(Path(bases or BASES).glob('*.json')):
        record = json.loads(path.read_text(encoding='utf-8'))
        digest = (record.get('manifest') or {}).get('allowed_signers_sha256')
        if not isinstance(digest, str) or caiman.SHA256.fullmatch(digest) is None:
            refuse(f'{path.name} pins no allowed signers digest')
        digests.add(digest)
    if len(digests) != 1:
        refuse(f'the upstream base records pin {len(digests)} different allowed signers digests')
    return digests.pop()


def _environment():
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C',
                   'TMPDIR': tempfile.gettempdir()}
    if 'HOME' in os.environ:
        environment['HOME'] = os.environ['HOME']
    return environment


def signature_command(signers, signature):
    return ['ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', SIGNER, '-n', NAMESPACE,
            '-s', str(signature)]


def read_small(path, what):
    """A small input file's bytes, read once."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read(SMALL + 1)
    except (OSError, TypeError, ValueError) as error:
        refuse(f'{what} cannot be read: {error}')
    if len(data) > SMALL:
        refuse(f'{what} is larger than {SMALL} bytes')
    return data


def _private(path, flags):
    """An opener for a new file that only this user can read and write."""
    return os.open(path, flags, 0o600)


def _without_waiting(path, flags):
    """An opener that never waits: a FIFO or a device opens at once, so that it can be refused
    before it is read, and a terminal does not become the controlling terminal."""
    return os.open(path, flags | os.O_NONBLOCK | os.O_NOCTTY)


def open_regular(path):
    """path opened for reading, unbuffered, or a refusal if it is not a regular file. The open
    never waits (_without_waiting), so a FIFO or a device is refused before any read."""
    source = open(path, 'rb', buffering=0, opener=_without_waiting)
    try:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            refuse(f'{Path(path).name} is not a regular file')
        os.set_blocking(source.fileno(), True)
    except BaseException:
        source.close()
        raise
    return source


def write_private(path, data):
    """Writes data into a new file at path that only this user can read and write. The file is
    created exclusively: a path that names anything already raises FileExistsError."""
    with open(path, 'xb', opener=_private) as handle:
        handle.write(data)


def remove_private(work, missing_ok=False):
    """Removes a private directory and the copies in it. A directory that cannot be removed
    refuses, so that no copy is left behind unnoticed. With missing_ok, a directory that does not
    exist is no error: PrivateDirectory owns its path before it makes the directory."""
    try:
        if missing_ok:
            try:
                os.lstat(work)
            except FileNotFoundError:
                return
        shutil.rmtree(work)
    except OSError as error:
        refuse(f'the private directory {work} could not be removed: {error}')


# The registry of owned directories: the private directories that PrivateDirectory objects of this
# process own now, each by its path as a string. A path is added when it becomes an object's,
# before its directory is made, and taken out only once a removal of the directory succeeded, or
# when mkdir failed and made nothing. remove_leftover, as a backstop or in the exit sweep, removes
# only what is here. A child that os.fork makes starts with none, so that its exit leaves its
# parent's directories alone.
OWNED = set()


def warn_left(work, error):
    """Names the private directory at work, which remove_leftover could not remove because of
    error, in a warning on stderr, and gives whether the warning was written.

    A stderr that is closed, that fails, or that was replaced by anything, and an interruption of
    the write, are no errors here: the warning is then lost, and False says so. Everything that
    this function does is inside its handler, so nothing raises past it. Only an interruption at
    its very first instruction, before the handler is set up, or a second one while the handler
    runs, which no handler of its own can take, goes on to its caller."""
    try:
        reason = str(error) if isinstance(error, Refusal) else \
            f'the private directory {work} could not be removed: {type(error).__name__}'
        sys.stderr.write(f'warning: {reason}\n')
        return True
    except BaseException:   # whatever stderr is or does, an interruption of the write too
        return False


def remove_leftover(work):
    """Removes what is left of the private directory at work while this process owns it (OWNED),
    as remove_private does, and gives whether the directory is now gone or named in a warning.

    It is PrivateDirectory's backstop: weakref.finalize runs it when the object that owns the
    directory is dropped, or at the interpreter's exit. It is given the path alone, so that it
    keeps no reference to that object, and it does nothing once a removal succeeded and took the
    path out of OWNED, or the object gave the path up. The exit sweep (sweep_at_exit) runs it too,
    for every directory still owned.

    It runs where nothing can take a refusal: Python only reports what a finalizer raises, and
    goes on. So it warns rather than refuses: a directory that it cannot remove, also when an
    interruption stops its removal, stays, still owned, and a warning on stderr names it
    (warn_left). An interruption at its very first instruction, before its handler is set up, or
    a second one while its handler runs, goes on to its caller, as no handler of its own can take
    it there. The directory is then still owned, so the exit sweep removes it or names it."""
    try:
        if work in OWNED:
            remove_private(work, missing_ok=True)
            OWNED.discard(work)
        return True
    except BaseException as error:  # an interruption too: the finalizer's caller would drop it
        return warn_left(work, error)


def sweep_at_exit():
    """Removes every private directory that this process still owns (OWNED), at the interpreter's
    exit: this module registers it with atexit when it is imported. remove_leftover removes each
    directory or names it in a warning on stderr, inside its own handler, which takes whatever
    the removal meets, an interruption too. A directory that it neither removed nor named, as
    when stderr did not take the warning or an interruption stopped it, is tried once more. An
    interruption anywhere else in the sweep, between two directories or on the way into
    remove_leftover, starts the sweep again on what is still owned. So an interruption or a
    failure on one directory goes on to the next, and each directory that stays is named, unless
    stderr cannot take the warning or a second interruption stops it too.

    The backstops remove a directory earlier, when its object is dropped, and at the exit
    through weakref.finalize._exitfunc, which atexit runs too. An interruption can stop a
    backstop at its very first instruction, where no handler can take it, and the directory
    stays, still owned. When that happens as the object is collected during the run, this sweep
    removes the directory at the exit. When it happens at the exit, the interruption also stops
    _exitfunc and every backstop that it had still to run, but atexit reports it and goes on to
    its next function, so this sweep runs all the same. That holds whatever order atexit runs
    them in: it runs its functions in the reverse order of their registration, and _exitfunc is
    registered when the process makes its first finalizer, which can be before this module is
    imported or after. Run first, the sweep leaves the backstops only what it could not remove;
    run last, it removes what they left. Both are idempotent: a directory that is gone, or no
    longer owned, is no error.

    No handler can take an interruption at the very first instruction of the sweep itself,
    before its handler is set up, nor one at the first instruction of the new start that an
    earlier interruption gives it. Such an interruption ends the sweep, atexit reports it, and
    the directories that the sweep did not reach stay, unnamed, unless a backstop that runs
    after it removes them. Only blocking SIGINT could close that."""
    try:
        for work in sorted(OWNED):
            if not remove_leftover(work):   # neither removed nor named: once more
                remove_leftover(work)
    except BaseException:   # between two directories, or on the way into remove_leftover
        sweep_at_exit()


atexit.register(sweep_at_exit)
os.register_at_fork(after_in_child=OWNED.clear)


class PrivateDirectory:
    """A new directory that only this user can enter, for private copies, which the end of its
    with block removes with them.

    The constructor only records its arguments. __enter__ chooses the directory's path: prefix
    and 128 random bits (secrets.token_hex(16)) under scratch or else the system's temporary
    directory, made absolute. Anything at that path, even a dangling link, is another's, and
    __enter__ refuses it at once and leaves it as it is. Only then does the path become this
    object's: __enter__ records it, adds it to OWNED, registers the backstop below and makes the
    directory with mode 0700. If mkdir fails, it made nothing, so __enter__ gives the path up
    without removing anything (disown), and when something exists there, which another process
    made since the check, it refuses.

    Anything that fails or interrupts __enter__ once the path is this object's, as it makes the
    directory or fills it (fill), removes whatever of the directory exists before the error goes
    on, and the end of the with block removes the directory. A directory that cannot be removed
    there refuses (remove_private). So a caller enters it in its with statement, with nothing
    between. Each of these removals gives the path up only once it succeeded.

    The backstop is a weakref.finalize that removes what is left of the directory when this
    object is dropped, or at the interpreter's exit (remove_leftover). It covers every exit that
    does not reach a removal or does not finish one, where no handler can: an interruption at the
    return of __enter__, before the with statement holds this object, which only a trace or
    profile function can raise there, or one at the start of __exit__ or of remove_private, or
    inside shutil.rmtree, where CPython checks for one. The exit sweep (sweep_at_exit) removes,
    at the interpreter's exit, every directory still in OWNED, also one whose backstop a second
    interruption stopped at its very first instruction, where no handler can take it.

    Limits. A process ended without Python's cleanup leaves its private copies behind: one killed
    by SIGKILL, or by a signal that Python does not handle by default such as SIGTERM, or one
    that calls os._exit. So does an interruption at the very first instruction of the exit sweep
    itself, or of the new start that an earlier interruption gives it, which no Python handler can
    cover and only blocking SIGINT could close: the directories that the sweep did not reach
    stay, unnamed, unless a backstop that runs after it removes them. Every other directory that
    the cleanup cannot remove is named. A strict removal, at the end of a with block or after a
    failed entry, refuses, and its refusal names the directory. The backstop and the exit sweep
    cannot refuse: a directory that they cannot remove, also when an interruption stops its
    removal, stays, and a warning on stderr names it. At the exit, the sweep tries each directory
    that stays, and writes once more a warning that stderr did not take, as when an interruption
    stopped it; only a stderr that is closed or fails, or a second interruption of the same
    warning, loses the warning. One case remains theoretical: another process that makes a
    directory of the same random name after PrivateDirectory found the path free. If an
    interruption came before the path was given up, after that check but before mkdir made the
    directory, or after a removal ended but before the path left the registry of owned
    directories, while the backstop and the exit sweep are still armed for it, the cleanup could
    remove that directory.
    """

    def __init__(self, prefix, scratch=None):
        self.prefix, self.scratch, self.work, self.backstop = prefix, scratch, None, None

    def __enter__(self):
        parent = tempfile.gettempdir() if self.scratch is None else self.scratch
        work = os.path.abspath(os.path.join(parent, self.prefix + secrets.token_hex(16)))
        if os.path.lexists(work):   # another's: refused before this object owns the path
            refuse(f'the private directory {work} exists already')
        self.work = Path(work)      # this object's from here on, before the directory exists
        OWNED.add(work)
        self.backstop = weakref.finalize(self, remove_leftover, work)
        try:
            try:
                os.mkdir(work, 0o700)
            except OSError as error:
                # mkdir made nothing, and whatever is at the path now is another's: give it up
                self.disown()
                self.work = None
                if isinstance(error, FileExistsError):
                    refuse(f'the private directory {work} exists already')
                raise
            entered = self.fill()
            return entered
        except BaseException:
            if self.work is not None:
                remove_private(self.work, missing_ok=True)
                self.disown()       # only once the removal succeeded
            raise

    def disown(self):
        """Gives the path up: takes it out of OWNED, so that neither the backstop nor the exit
        sweep touches it from here on, and detaches the backstop. It is called only once a removal
        of the directory succeeded, or once mkdir failed and made nothing."""
        OWNED.discard(str(self.work))
        self.backstop.detach()

    def fill(self):
        """Fills the new directory, inside __enter__'s cleanup, and gives what the with statement
        binds. Here nothing is filled, and the with statement binds the directory's path."""
        return self.work

    def __exit__(self, *exception):
        remove_private(self.work)
        self.disown()       # only once the removal succeeded


class ZipCopy(PrivateDirectory):
    """A zip read once into a private copy, which every check reads instead of the zip.

    The constructor only records its arguments. __enter__ makes a private directory, as
    PrivateDirectory does, under scratch or else the system's temporary directory, and fills it
    with the copy (fill). The zip is read from its start to its end, and hashed as it is copied,
    so sha256 names exactly the bytes of the copy at path. A path that is not a regular file is
    refused before any read, without waiting (open_regular). The copy is created exclusively, as
    a file that only this user can read and write. It carries the zip's name, so Archive and the
    report name it as the zip. Anything that fails or interrupts __enter__ once the directory's
    path is this object's, up to the zip's close and the digest's end, removes whatever of the
    directory exists, and so does the end of the with block. A directory that cannot be removed
    there refuses. PrivateDirectory's backstop and the exit sweep remove the copy on every other
    exit, and their limits are the copy's. Every caller enters the copy directly in its with
    statement: with ZipCopy(path, scratch) as copy.

    Nothing reads the zip again, so a zip changed or replaced after it was copied changes nothing
    that is checked, and a zip changed while it was copied is checked as the bytes that were read.
    """

    def __init__(self, zip_path, scratch=None):
        super().__init__('zip-', scratch)
        self.zip_path, self.path, self.sha256 = zip_path, None, None

    def fill(self):
        """Copies the zip into the new directory, hashing its bytes as it copies them."""
        self.path = self.work / Path(self.zip_path).name
        digest = hashlib.sha256()
        with open_regular(self.zip_path) as source, open(self.path, 'xb', opener=_private) as copy:
            for block in iter(lambda: source.read(1 << 20), b''):
                digest.update(block)
                copy.write(block)
        self.sha256 = digest.hexdigest()
        return self


def check_signature(zip_copy, signature, signers, scratch=None):
    """ssh-keygen's verification of the zip's private copy at zip_copy (ZipCopy).

    signature and signers are the bytes that were read once from each file. ssh-keygen reads
    private copies of exactly them (write_private), in a new directory that only this user can
    enter (PrivateDirectory) and that is removed afterwards, so it cannot read a file that was
    replaced since. A directory that cannot be removed refuses the signature.
    """
    with PrivateDirectory('signature-', scratch) as work:
        write_private(work / 'allowed_signers', signers)
        write_private(work / 'signature', signature)
        command = signature_command(work / 'allowed_signers', work / 'signature')
        with open(zip_copy, 'rb') as stdin:
            process = subprocess.run(command, stdin=stdin, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=_environment(),
                                     timeout=COMMAND_TIMEOUT)
    output = process.stdout.decode('utf-8', 'replace')
    if process.returncode != 0 or output != good_line() + '\n':
        refuse(f'ssh-keygen exited {process.returncode} and printed {output.strip()!r}; '
               f'expected {good_line()!r}; stderr {process.stderr.decode("utf-8", "replace").strip()!r}')
    # the command as it ran, with the private copies named by their roles and the zip by its name
    return {'command': shlex.join(signature_command('allowed_signers', 'signature')) + ' < '
            + shlex.quote(Path(zip_copy).name), 'allowed_signers_sha256': caiman.sha256(signers),
            'signature_sha256': caiman.sha256(signature), 'output': output.strip()}


def check_signers(signers, bases=None):
    """The allowed signers digest against the pin of the upstream base records. signers is the
    file's bytes as check read them once, or the path of a file to read once."""
    data = signers if isinstance(signers, bytes) else read_small(signers, 'allowed_signers')
    digest = caiman.sha256(data)
    pinned = pinned_signers_digest(bases)
    if digest != pinned:
        refuse(f'allowed_signers hashes to {digest}, not the pinned {pinned}')
    return {'sha256': digest}


class Archive:
    """The members of one install zip, all directly under the directory its name gives."""

    def __init__(self, path, release=None):
        self.path = Path(path)
        if release is None:   # an Andrix zip: optimize-factory-image names the directory alike
            if re.fullmatch(r'caiman-install-[A-Za-z0-9._-]+\.zip', self.path.name) is None:
                refuse(f'{self.path.name} is not named caiman-install-BUILD.zip')
            release = self.path.name[len('caiman-install-'):-len('.zip')]
        self.prefix = f'{caiman.DEVICE}-install-{release}/'
        if self.path.name != f'{caiman.DEVICE}-install-{release}.zip':
            refuse(f'{self.path.name} is not named {caiman.DEVICE}-install-{release}.zip')
        try:
            self.zip = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as error:
            refuse(f'{self.path.name} is not a readable zip: {error}')
        self.members = {}
        for info in self.zip.infolist():
            name = info.filename
            if name == self.prefix and info.is_dir():
                continue
            parts = PurePosixPath(name).parts
            if (not name.startswith(self.prefix) or '\\' in name or len(parts) != 2
                    or any(part in ('', '.', '..') for part in parts) or info.is_dir()):
                refuse(f'zip entry {name!r} is not a file directly under {self.prefix}')
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                refuse(f'zip entry {name!r} is a symbolic link')
            if info.flag_bits & 0x1:
                refuse(f'zip entry {name!r} is encrypted')
            base = parts[1]
            if base in self.members:
                refuse(f'zip entry {base!r} appears twice')
            self.members[base] = info

    def read(self, name, limit=None):
        limit = SMALL if limit is None else limit
        info = self.members.get(name)
        if info is None:
            refuse(f'the zip has no {name}')
        if info.file_size > limit:
            refuse(f'{name} is larger than {limit} bytes')
        with self.zip.open(info) as handle:
            data = handle.read(limit + 1)
        if len(data) != info.file_size:
            refuse(f'{name} does not have its recorded size')
        return data

    def extract(self, name, directory, limit=None):
        target = Path(directory) / name
        target.write_bytes(self.read(name, IMAGE if limit is None else limit))
        return target


def parse_vbmeta(data):
    """The fields of a vbmeta image these checks use. Bounds are checked, nothing assumed."""
    header = '!4s2L2QL2Q2Q2Q2Q2QQLL47sx80x'
    if len(data) < 256:
        refuse('vbmeta.img is shorter than its header')
    (magic, _, _, auth_size, aux_size, algorithm, hash_offset, hash_size, signature_offset,
     signature_size, key_offset, key_size, _, _, descriptors_offset, descriptors_size,
     rollback_index, flags, rollback_location, _) = struct.unpack(header, data[:256])
    if magic != b'AVB0':
        refuse('vbmeta.img does not start with AVB0')
    if auth_size % 64 or aux_size % 64 or 256 + auth_size + aux_size > len(data):
        refuse('vbmeta.img block sizes are malformed')
    for offset, size, block in ((hash_offset, hash_size, auth_size),
                                (signature_offset, signature_size, auth_size),
                                (key_offset, key_size, aux_size),
                                (descriptors_offset, descriptors_size, aux_size)):
        if offset + size > block:
            refuse('vbmeta.img points outside its blocks')
    aux = data[256 + auth_size:256 + auth_size + aux_size]
    blob = aux[descriptors_offset:descriptors_offset + descriptors_size]
    descriptors = []
    position = 0
    while position < len(blob):
        if position + 16 > len(blob):
            refuse('a vbmeta descriptor header is cut short')
        tag, following = struct.unpack('!QQ', blob[position:position + 16])
        if following % 8 or position + 16 + following > len(blob):
            refuse('a vbmeta descriptor is malformed')
        descriptors.append(_descriptor(tag, blob[position:position + 16 + following]))
        position += 16 + following
    return {'algorithm': algorithm, 'algorithm_name': ALGORITHMS.get(algorithm, str(algorithm)),
            'rollback_index': rollback_index, 'flags': flags,
            'rollback_index_location': rollback_location,
            'public_key': aux[key_offset:key_offset + key_size], 'descriptors': descriptors}


def _named(raw, fixed, layout, kind):
    if len(raw) < fixed:
        refuse(f'a vbmeta {kind} descriptor is cut short')
    values = struct.unpack(layout, raw[:fixed])
    return values


def _descriptor(tag, raw):
    if tag == 0:
        _, _, key_size, value_size = _named(raw, 32, '!QQQQ', 'property')
        if 32 + key_size + 1 + value_size + 1 > len(raw):
            refuse('a vbmeta property descriptor is malformed')
        key = raw[32:32 + key_size].decode('utf-8', 'replace')
        value = raw[33 + key_size:33 + key_size + value_size]
        return {'type': 'property', 'key': key, 'value': value.decode('utf-8', 'replace')}
    if tag in (1, 2):
        if tag == 1:
            fields = _named(raw, 180, '!QQLQQQLLLQQ32sLLLL60s', 'hashtree')
            name_size, salt_size, digest_size = fields[12], fields[13], fields[14]
            fixed, kind = 180, 'hashtree'
        else:
            fields = _named(raw, 132, '!QQQ32sLLLL60s', 'hash')
            name_size, salt_size, digest_size = fields[4], fields[5], fields[6]
            fixed, kind = 132, 'hash'
        if fixed + name_size + salt_size + digest_size > len(raw):
            refuse(f'a vbmeta {kind} descriptor is malformed')
        name = raw[fixed:fixed + name_size].decode('utf-8', 'replace')
        return {'type': kind, 'partition': name, 'digest_size': digest_size}
    if tag == 3:
        _named(raw, 24, '!QQLL', 'kernel command line')
        return {'type': 'kernel_cmdline'}
    if tag == 4:
        fields = _named(raw, 92, '!QQLLLL60s', 'chain')
        name = raw[92:92 + fields[3]].decode('utf-8', 'replace')
        return {'type': 'chain', 'partition': name}
    return {'type': 'unknown', 'tag': tag}


def patch_timestamp(level):
    try:
        day = datetime.date.fromisoformat(level)
    except (TypeError, ValueError):
        refuse(f'security patch level {level!r} is not YYYY-MM-DD')
    if day.isoformat() != level:
        refuse(f'security patch level {level!r} is not YYYY-MM-DD')
    # the build sets the rollback index to the patch level's midnight in GMT, in seconds
    return calendar.timegm((day.year, day.month, day.day, 0, 0, 0))


def build_identity(vbmeta):
    """The build number and stock build that a GrapheneOS vbmeta's fingerprints name."""
    fingerprints = {}
    for descriptor in vbmeta['descriptors']:
        if descriptor['type'] == 'property':
            match = _FINGERPRINT_KEY.fullmatch(descriptor['key'])
            if match:
                if match.group(1) in fingerprints:
                    refuse(f'vbmeta repeats the {match.group(1)} fingerprint')
                fingerprints[match.group(1)] = descriptor['value']
    if 'system' not in fingerprints:
        refuse('vbmeta carries no com.android.build.system.fingerprint, so no build number '
               'inside the zip names its release')
    numbers, builds = set(), set()
    for part, value in sorted(fingerprints.items()):
        match = _FINGERPRINT.fullmatch(value)
        if match is None:
            refuse(f'the {part} fingerprint {value!r} is not a build fingerprint')
        device, build_id, number, kind, tags = (match.group(3), match.group(5), match.group(6),
                                                match.group(7), match.group(8))
        if device != caiman.DEVICE or kind != 'user' or tags != 'release-keys':
            refuse(f'the {part} fingerprint {value!r} is not a {caiman.DEVICE} user release-keys build')
        numbers.add(number)
        builds.add(build_id)
    if len(numbers) != 1 or len(builds) != 1:
        refuse(f'the fingerprints inside the zip disagree: {sorted(fingerprints.values())}')
    inside = caiman.parse_release(numbers.pop(), what='build number inside the zip')
    return inside, builds.pop(), sorted(fingerprints)


def check_identity(vbmeta, release, stable, record_stock=None):
    inside, stock, fingerprints = build_identity(vbmeta)
    if inside.number != release.number:
        refuse(f'the build number inside the zip is {inside}, not the expected {release}')
    if record_stock is not None and stock != record_stock:
        refuse(f'the zip is built from stock build {stock}, but adevtool records {record_stock}')
    if caiman.newer(inside, stable):
        refuse(f'caiman-stable names {stable}, which is older than the zip release {inside}')
    return {'build_number': inside.number, 'stock_build': stock, 'stable': stable.number,
            'fingerprints': fingerprints}


def images_to_verify(vbmeta):
    """The partitions whose images avbtool verify_image reads, after the descriptor policy."""
    images = []
    for descriptor in vbmeta['descriptors']:
        if descriptor['type'] == 'chain':
            refuse(f'vbmeta chains to {descriptor["partition"]}; caiman has a single vbmeta')
        if descriptor['type'] == 'unknown':
            refuse(f'vbmeta has a descriptor with unknown tag {descriptor["tag"]}')
        if descriptor['type'] in ('hash', 'hashtree'):
            name = descriptor['partition']
            if _PARTITION.fullmatch(name) is None or name in images or name == 'vbmeta':
                refuse(f'vbmeta names partition {name!r}, which is malformed or repeated')
            if descriptor['digest_size'] == 0:
                refuse(f'the {name} descriptor has no digest, so avbtool would not check it')
            images.append(name)
    return images


def _pinned_tool(tools, name, pinned):
    path = (tools or {}).get(name)
    if not path:
        refuse(f'rebuilding the dynamic partitions needs the pinned {name}')
    if pinned is None:
        refuse(f'{name} is not built and pinned yet, so the dynamic partitions cannot be rebuilt')
    if caiman.sha256(Path(path).read_bytes()) != pinned:
        refuse(f'{path} is not the pinned {name}')
    return str(path)


def rebuild_dynamic(archive, work, tools, described):
    """The dynamic partition images, rebuilt from the super splits with the pinned tools.

    simg2img merges every split into one image, because lpunpack refuses sparse input
    (lpunpack.cc). lpunpack writes NAME_a.img and NAME_b.img; each _a image is renamed to
    NAME.img beside vbmeta.img, and every _b image must be empty. The splits are extracted into
    a private directory in work (PrivateDirectory), removed once the images are renamed or the
    rebuild refuses.
    """
    simg2img = _pinned_tool(tools, 'simg2img', SIMG2IMG_SHA256)
    lpunpack = _pinned_tool(tools, 'lpunpack', LPUNPACK_SHA256)
    numbers = sorted(int(m.group(1)) for m in (re.fullmatch(r'super_([1-9][0-9]{0,2})\.img', name)
                                               for name in archive.members) if m)
    if not numbers or numbers != list(range(1, len(numbers) + 1)):
        refuse(f'the zip does not hold one numbered run of super splits: {numbers}')
    with PrivateDirectory('splits-', work) as splits:
        paths = [str(archive.extract(f'super_{number}.img', splits)) for number in numbers]
        unpacked = work / 'unpacked'
        unpacked.mkdir()
        for command in ([simg2img, *paths, str(work / 'super.img')],
                        [lpunpack, str(work / 'super.img'), str(unpacked)]):
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=_environment(), timeout=COMMAND_TIMEOUT, cwd=work)
            if process.returncode != 0:
                refuse(f'{Path(command[0]).name} exited {process.returncode}: '
                       f'{process.stderr.decode("utf-8", "replace").strip()[-300:]!r}')
        rebuilt = set()
        for path in sorted(unpacked.iterdir()):
            match = re.fullmatch(r'([a-z0-9_]+)_(a|b)\.img', path.name)
            if match is None or path.is_symlink() or not path.is_file():
                refuse(f'lpunpack wrote {path.name}, which is not a slot image')
            if match.group(2) == 'b':
                if path.stat().st_size != 0:
                    refuse(f'{path.name} is not empty; the install zip writes slot a only')
                continue
            name = match.group(1)
            if name not in described:
                refuse(f'the super image holds {name}, which vbmeta does not describe')
            if f'{name}.img' in archive.members or name == 'vbmeta':
                refuse(f'the super image holds {name}, which the zip also holds outside it')
            path.rename(work / f'{name}.img')
            rebuilt.add(name)
    (work / 'super.img').unlink()
    return rebuilt


def check_vbmeta(archive, vbmeta_data, pkmd, security_patch, avbtool, scratch, tools=None,
                 keep=None):
    """vbmeta's signature, key and properties, and avbtool verify_image on every image it names.

    With keep, an empty directory, the images that avbtool verified are moved there once every
    vbmeta check has passed, for a caller that reads files from them. check and andrix_identity
    empty it again when their whole check does not pass. The images are extracted into a private
    directory (PrivateDirectory), removed before this returns or refuses, and a directory that
    cannot be removed refuses vbmeta.
    """
    vbmeta = parse_vbmeta(vbmeta_data)
    if vbmeta['algorithm'] != SHA256_RSA4096:
        refuse(f'vbmeta is signed with {vbmeta["algorithm_name"]}, not SHA256_RSA4096')
    if vbmeta['public_key'] != pkmd:
        refuse('the public key embedded in vbmeta is not byte identical to avb_pkmd.bin')
    if vbmeta['flags'] != 0 or vbmeta['rollback_index_location'] != 0:
        refuse(f'vbmeta flags {vbmeta["flags"]} and rollback index location '
               f'{vbmeta["rollback_index_location"]} are not both 0')
    wanted = patch_timestamp(security_patch)
    if vbmeta['rollback_index'] != wanted:
        refuse(f'the rollback index is {vbmeta["rollback_index"]}, not {wanted}, the patch '
               f'timestamp of {security_patch}')
    levels = [d['value'] for d in vbmeta['descriptors']
              if d['type'] == 'property' and d['key'] == 'com.android.build.system.security_patch']
    if levels != [security_patch]:
        refuse(f'vbmeta records system security patch {levels}, not [{security_patch!r}]')
    images = images_to_verify(vbmeta)
    tool = Path(avbtool)
    if caiman.sha256(tool.read_bytes()) != AVBTOOL_SHA256:
        refuse(f'{tool} is not external/avb/avbtool.py of the pinned tree')
    with PrivateDirectory('avb-', scratch) as work:
        missing = [name for name in images if f'{name}.img' not in archive.members]
        rebuilt = rebuild_dynamic(archive, work, tools, set(images)) if missing else set()
        absent = [name for name in missing if name not in rebuilt]
        if absent:
            refuse('vbmeta has descriptors for images neither the zip nor its super splits '
                   f'hold: {", ".join(absent)}')
        image = archive.extract('vbmeta.img', work, SMALL)
        for name in images:
            if name not in rebuilt:
                archive.extract(f'{name}.img', work)
        process = subprocess.run([sys.executable, '-B', str(tool), 'verify_image', '--image',
                                  str(image)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=_environment(), timeout=COMMAND_TIMEOUT, cwd=work)
        output = process.stdout.decode('utf-8', 'replace').split('\n')
        verified = {line.split(':', 1)[0] for line in output
                    if re.fullmatch(r'[a-z0-9_]+: Successfully verified .+', line)}
        expected = f'vbmeta: Successfully verified SHA256_RSA4096 vbmeta struct in {image}'
        if process.returncode != 0 or expected not in output or verified != {'vbmeta', *images}:
            refuse(f'avbtool verify_image exited {process.returncode}: '
                   f'{process.stderr.decode("utf-8", "replace").strip()[-400:]!r}')
        key = work / 'embedded_key.bin'
        process = subprocess.run([sys.executable, '-B', str(tool), 'info_image', '--image',
                                  str(image), '--output_pubkey', str(key)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=_environment(), timeout=COMMAND_TIMEOUT, cwd=work)
        if process.returncode != 0 or not key.is_file() or key.read_bytes() != pkmd:
            refuse("the key avbtool extracts from vbmeta is not byte identical to avb_pkmd.bin")
        if keep is not None:
            for name in images:
                shutil.move(str(work / f'{name}.img'), str(Path(keep) / f'{name}.img'))
    return vbmeta, {'algorithm': 'SHA256_RSA4096', 'rollback_index': wanted,
                    'verified_images': images, 'rebuilt_from_super': sorted(rebuilt),
                    'kernel_cmdline_descriptors': sum(d['type'] == 'kernel_cmdline'
                                                      for d in vbmeta['descriptors'])}


def patch_level(release, given=None, bases=None):
    """The release's security patch level, from its base record where one exists."""
    try:
        recorded = adevtool_record.base_record(release.base, bases)['security_patch_level']['value']
    except Refusal:
        recorded = None
    if recorded is not None and given is not None and recorded != given:
        refuse(f'the given patch level {given} is not the {recorded} of upstream/bases/{release.base}.json')
    level = recorded or given
    if level is None:
        refuse(f'no base record gives the patch level of {release.base}, and none was given')
    patch_timestamp(level)
    return level


def check(zip_path, *, signature, signers, release, stable, record, avbtool, security_patch=None,
          tools=None, scratch=None, bases=None, keep=None):
    """Runs every check. Returns the report; the verdict is PASS only if all pass.

    The zip is read once into a private copy (ZipCopy), and the report's SHA-256 is that of the
    bytes copied. ssh-keygen's verification, every archive check and the firmware digests read
    only that copy, so each concerns exactly the bytes that the SHA-256 names. A zip changed or
    replaced after it was copied changes nothing that is checked or reported, and a zip changed
    while it was copied is checked as the bytes that were read. The signature and
    allowed_signers files are read once each, and both checks that use allowed_signers see the
    same bytes.

    keep, an empty directory, receives the images that avbtool verified (check_vbmeta). It holds
    them only when the verdict is PASS, and is emptied otherwise. Only a PASS report has
    firmware: the SHA-256 of the bootloader and radio images in the copy.

    Every private copy is removed before check returns, and one that cannot be removed is never
    ignored: it fails the check that made it, or refuses the zip when its copy failed. Once the
    checks have run, a copy of the zip that cannot be removed makes check raise Refusal, after
    it has discarded the kept images.
    """
    checks = {}

    def run(name, function):
        try:
            checks[name] = {'ok': True, 'detail': function()}
        except Refusal as error:
            checks[name] = {'ok': False, 'reason': str(error)}
        except Exception as error:  # anything unexpected is a refusal, never a pass
            checks[name] = {'ok': False, 'reason': f'{type(error).__name__}: {error}'}
        return checks[name]['ok']

    state, given = {}, {}

    def given_bytes(what):
        if isinstance(given[what], Refusal):
            refuse(str(given[what]))
        return given[what]

    def layout():
        state['archive'] = Archive(copy.path, state['release'].number)
        return {'members': len(state['archive'].members)}

    def pkmd():
        data = archive.read('avb_pkmd.bin')
        if caiman.sha256(data) != PKMD_SHA256:
            refuse(f'avb_pkmd.bin hashes to {caiman.sha256(data)}, not {PKMD_SHA256}')
        state['pkmd'] = data
        return {'sha256': PKMD_SHA256}

    def android_info():
        info = caiman.parse_android_info(archive.read('android-info.txt'), 'the zip android-info.txt')
        if info != state['info']:
            refuse(f'the zip android-info.txt {info.as_dict()} differs from adevtool\'s '
                   f'{state["info"].as_dict()}')
        return info.as_dict()

    def vbmeta():
        if 'pkmd' not in state:
            refuse('avb_pkmd.bin did not pass, so the embedded key cannot be compared')
        parsed, detail = check_vbmeta(archive, archive.read('vbmeta.img'), state['pkmd'],
                                      security_patch, avbtool, scratch, tools, keep)
        state['vbmeta'] = parsed
        return detail

    def identity():
        if 'vbmeta' not in state:
            refuse('vbmeta did not pass, so the build number inside it is not trusted')
        return check_identity(state['vbmeta'], state['release'], state['stable'], state['stock'])

    def script():
        expect = flash_script.Expectation(state['info'].bootloader, state['info'].baseband,
                                          state['release'].number)
        report = flash_script.read(archive.read('flash-all.sh'), expect)
        if report['verdict'] != 'PASS':
            refuse('flash-all.sh: ' + '; '.join(report['reasons']))
        absent = [name for name in report['files'] if name not in archive.members]
        if absent:
            refuse(f'flash-all.sh writes files the zip does not contain: {absent}')
        # the bootloader and radio images that the script writes, from the archive checked here
        state['firmware'] = _firmware(archive, state['info'])
        return {key: report[key] for key in ('form', 'super_splits', 'os_images', 'unconfirmed')
                if key in report}

    try:
        state['release'] = caiman.parse_release(release, what='expected release')
        state['stable'] = caiman.parse_stable_channel(Path(stable).read_bytes())
        _, state['stock'], _, state['info'] = adevtool_record.validate_record(record, bases=bases)
        if caiman.parse_release(record['release']).number != state['release'].base:
            refuse(f'the adevtool record is for {record["release"]}, not {state["release"].base}')
        security_patch = patch_level(state['release'], security_patch, bases)
        empty_directory(keep)
    except (Refusal, OSError) as error:
        return {'verdict': 'REFUSE', 'reasons': [str(error)], 'checks': {}}
    copied = False      # whether ZipCopy's __enter__ returned the copy
    try:
        with ZipCopy(zip_path, scratch) as copy:
            copied = True
            checks['inputs'] = {'ok': True, 'detail': {'zip': Path(zip_path).name,
                                                       'sha256': copy.sha256,
                                                       'release': state['release'].number,
                                                       'stable': state['stable'].number,
                                                       'security_patch': security_patch,
                                                       'record_stock_build': state['stock']}}
            # Each small input is read once. A refusal to read it is kept and given to every
            # check that needs it, so no check reads the file again.
            for what, path in (('the signature', signature), ('allowed_signers', signers)):
                try:
                    given[what] = read_small(path, what)
                except Refusal as error:
                    given[what] = error
            run('signature', lambda: check_signature(copy.path, given_bytes('the signature'),
                                                     given_bytes('allowed_signers'), scratch))
            run('allowed_signers', lambda: check_signers(given_bytes('allowed_signers'), bases))
            if run('zip_layout', layout):
                archive = state['archive']
                try:
                    run('avb_pkmd', pkmd)
                    run('android_info', android_info)
                    run('vbmeta', vbmeta)
                    run('release_identity', identity)
                    run('flash_script', script)
                finally:
                    archive.zip.close()
    except (Refusal, OSError) as error:
        if not copied:      # the copy failed, so the zip is refused as an input is
            return {'verdict': 'REFUSE', 'reasons': [str(error)], 'checks': {}}
        discard(keep)
        raise
    except BaseException:
        discard(keep)
        raise
    report = _finish(checks, copy.sha256)
    if report['verdict'] == 'PASS':
        report['firmware'] = state['firmware']
    else:
        discard(keep)
    return report


def empty_directory(keep):
    """A directory that is to receive verified images must exist and be empty."""
    if keep is not None and (Path(keep).is_symlink() or not Path(keep).is_dir()
                             or any(Path(keep).iterdir())):
        refuse(f'{keep} is not an empty directory to keep the verified images in')


def discard(keep):
    """Removes the images that a check which did not pass had kept."""
    if keep is not None:
        for path in Path(keep).iterdir():
            path.unlink()


def _finish(checks, digest=None):
    reasons = [f'{name}: {result["reason"]}' for name, result in checks.items() if not result['ok']]
    return {'verdict': 'PASS' if not reasons else 'REFUSE', 'reasons': reasons, 'checks': checks,
            'sha256': digest}


def andrix_identity(zip_path, *, avbtool, tools=None, scratch=None, bases=None, keep=None):
    """An Andrix zip's identity from its signed vbmeta: base tag, stock build and versions.

    The base tag is the signed vbmeta property com.andrix.build.base_tag, which Andrix's
    release signing must add (design item 6). Until it does, every Andrix zip is refused.
    keep, an empty directory, receives the verified images (check_vbmeta). It holds them only
    when this returns, and is emptied when it refuses. The zip is read once into a private copy
    (ZipCopy), as check reads a kit, and every check reads only that copy, so the SHA-256 is that
    of the bytes checked, whatever happens to the zip meanwhile. The copy is removed before this
    returns or refuses, and a copy that cannot be removed refuses.
    """
    empty_directory(keep)
    try:
        with ZipCopy(zip_path, scratch) as copy:
            archive = Archive(copy.path)
            try:
                pkmd = archive.read('avb_pkmd.bin')
                if WORKSHOP_PKMD_SHA256 is None:
                    refuse('the workshop key for this phone is not recorded yet, so no Andrix zip '
                           'is trusted')
                if caiman.sha256(pkmd) != WORKSHOP_PKMD_SHA256:
                    refuse('the Andrix zip is not signed with the workshop key recorded for this '
                           'phone')
                vbmeta = parse_vbmeta(archive.read('vbmeta.img'))
                base = andrix_base_tag(vbmeta)
                level = patch_level(base, None, bases)
                _, detail = check_vbmeta(archive, archive.read('vbmeta.img'), pkmd, level, avbtool,
                                         scratch, tools, keep)
                stock = andrix_stock_build(vbmeta)
                info = caiman.parse_android_info(archive.read('android-info.txt'),
                                                 'the Andrix android-info.txt')
                report = flash_script.read(archive.read('flash-all.sh'),
                                           flash_script.Expectation(info.bootloader, info.baseband))
                if report['verdict'] != 'PASS':
                    refuse('the Andrix flash-all.sh: ' + '; '.join(report['reasons']))
                firmware = _firmware(archive, info)
            finally:
                archive.zip.close()
    except BaseException:
        discard(keep)
        raise
    return {'sha256': copy.sha256, 'base_tag': base.number, 'stock_build': stock,
            'android_info': info, 'vbmeta': detail, 'firmware': firmware}


def andrix_base_tag(vbmeta):
    """The base tag that an Andrix vbmeta's single com.andrix.build.base_tag property names."""
    tags = [d['value'] for d in vbmeta['descriptors']
            if d['type'] == 'property' and d['key'] == 'com.andrix.build.base_tag']
    if len(tags) != 1:
        refuse('the Andrix zip carries no single signed com.andrix.build.base_tag property')
    return caiman.parse_release(tags[0], allow_preview=False, what='Andrix base tag')


def andrix_stock_build(vbmeta):
    """The one stock build that an Andrix vbmeta's caiman release-keys fingerprints name."""
    fingerprints = [d['value'] for d in vbmeta['descriptors'] if d['type'] == 'property'
                    and _FINGERPRINT_KEY.fullmatch(d['key'])]
    parsed = [_ANDRIX_FINGERPRINT.fullmatch(value) for value in fingerprints]
    if not parsed or None in parsed or {m.group(1) for m in parsed} != {caiman.DEVICE} \
            or {m.group(4) for m in parsed} != {'release-keys'} or len({m.group(2) for m in parsed}) != 1:
        refuse(f'the Andrix fingerprints {fingerprints} are not one caiman release-keys build')
    return parsed[0].group(2)


def _firmware(archive, info):
    """The SHA-256 of the bootloader and radio images that info names, read from archive."""
    expect = flash_script.Expectation(info.bootloader, info.baseband)
    return {name: caiman.sha256(archive.read(name, IMAGE))
            for name in (expect.bootloader_file, expect.radio_file)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--zip', required=True, help='caiman-install-RELEASE.zip')
    parser.add_argument('--sig', help='its signature; default ZIP.sig')
    parser.add_argument('--allowed-signers', required=True)
    parser.add_argument('--release', required=True, help='the expected release')
    parser.add_argument('--stable', required=True, help='caiman-stable, as read at this moment')
    parser.add_argument('--security-patch', help="the release's YYYY-MM-DD, when no base record "
                        'gives it; a given value must equal the base record')
    parser.add_argument('--simg2img', help='the pinned simg2img, to rebuild the super splits')
    parser.add_argument('--lpunpack', help='the pinned lpunpack, to rebuild the super splits')
    parser.add_argument('--record', required=True, help="the release's adevtool record")
    parser.add_argument('--avbtool', required=True, help='external/avb/avbtool.py of the pinned tree')
    args = parser.parse_args(argv)
    try:
        record = json.loads(Path(args.record).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        sys.stdout.write(caiman.dump({'verdict': 'REFUSE', 'reasons': [str(error)]}))
        return 1
    try:
        report = check(args.zip, signature=args.sig or args.zip + '.sig',
                       signers=args.allowed_signers, release=args.release, stable=args.stable,
                       security_patch=args.security_patch, record=record, avbtool=args.avbtool,
                       tools={'simg2img': args.simg2img, 'lpunpack': args.lpunpack})
    except Refusal as error:    # the zip's private copy could not be removed
        report = {'verdict': 'REFUSE', 'reasons': [str(error)], 'checks': {}}
    sys.stdout.write(caiman.dump(report))
    return 0 if report['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
