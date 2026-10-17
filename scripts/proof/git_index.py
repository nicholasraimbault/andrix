# SPDX-License-Identifier: Apache-2.0
"""A private copy of a Git project's index, so that a check never writes into a source tree.

Porcelain git diff stores a refreshed index when it finds entries whose stat data is stale but
whose content is unchanged, as in a copied tree, even with --no-optional-locks. A check that reads
the index through a private copy leaves the tree's own index alone. See grapheneos_source.md.
This module has no other repository dependency, so a tool that follows no GrapheneOS base can
use it too.
"""
import contextlib
import os
from pathlib import Path
import stat
import tempfile

# An index entry takes about 160 bytes, so this allows over a million entries. The bound keeps
# a sparse or growing index file from filling the temporary file system.
LIMIT = 256 * 1024 * 1024


class Refused(Exception):
    """The temporary directory or the index file cannot be used without risk to a tree."""


def temporary_base(*trees):
    """The directory for private temporary files, which must be outside each given tree. It is
    the directory tempfile uses: tempfile.tempdir when set, else TMPDIR, TEMP or TMP, else /tmp.
    It is found without the probe file tempfile writes on first use, so a refused directory is
    never written."""
    base = tempfile.tempdir
    if base is None:
        base = next((os.environ[name] for name in ('TMPDIR', 'TEMP', 'TMP')
                     if os.environ.get(name)), '/tmp')
    base = Path(os.fsdecode(base)).resolve()
    if any(base.is_relative_to(Path(tree).resolve()) for tree in trees if tree is not None):
        raise Refused('The temporary directory must be outside source trees: ' + str(base))
    return base


@contextlib.contextmanager
def private_copy(index, trees):
    """A copy of the index file at index, in a new private directory removed afterwards. Only a
    regular file of at most LIMIT bytes is read, without blocking, so a FIFO or a device fails at
    once. The copy keeps the file's mtime: Git checks the content of each entry whose recorded
    mtime is not older than that, so the same entries are checked. A missing index stays
    missing, and Git reads it as an empty one, as from the tree."""
    base = temporary_base(*trees)
    try:
        status = os.stat(index)
    except FileNotFoundError:
        status = None
    if status is not None:
        refuse(index, status)
    with tempfile.TemporaryDirectory(prefix='private-index-', dir=base) as directory:
        copy = Path(directory) / 'index'
        if status is not None:
            descriptor = os.open(index, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
            with os.fdopen(descriptor, 'rb') as source:
                opened = os.fstat(source.fileno())
                if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
                    raise Refused('The index file changed while it was read: ' + str(index))
                refuse(index, opened)
                with copy.open('xb') as target:
                    remaining = opened.st_size
                    while remaining:
                        chunk = source.read(min(remaining, 1 << 20))
                        if not chunk:
                            break
                        target.write(chunk)
                        remaining -= len(chunk)
            os.utime(copy, ns=(opened.st_atime_ns, opened.st_mtime_ns))
        yield copy


def refuse(index, status):
    if not stat.S_ISREG(status.st_mode):
        raise Refused('The index is not a regular file: ' + str(index))
    if status.st_size > LIMIT:
        raise Refused('The index is larger than %d bytes: %s' % (LIMIT, index))
