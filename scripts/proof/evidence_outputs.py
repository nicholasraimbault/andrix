# SPDX-License-Identifier: Apache-2.0
"""Reject declared sealer outputs that overlap its input tree.

Check paths in the controller BEFORE opening/redirection can truncate a file.
An additional descriptor check in the sealer catches direct inherited aliases.
This does not prove that other processes or downstream pipeline writers ceased.
Borrowed descriptors must remain owned and stable throughout the check.
"""
from pathlib import Path
import os
import stat


def require_external_outputs(input_root, outputs, descriptors=()):
    root = Path(input_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Evidence input must be a directory')
    paths = [Path(name).resolve() for name in outputs]
    for path in paths:
        if path.is_relative_to(root):
            raise ValueError(f'Sealer output is inside input tree: {path}')

    # Path spelling alone misses hard links. Do not follow links encountered
    # within the input tree, including links to directories outside that tree.
    identities = set()
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
        identities.add((info.st_dev, info.st_ino))

    for path in paths:
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        if (info.st_dev, info.st_ino) in identities:
            raise ValueError(f'Sealer output aliases input inode: {path}')
    for fd in descriptors:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) in identities:
            raise ValueError(f'Sealer output descriptor aliases input inode: {fd}')
