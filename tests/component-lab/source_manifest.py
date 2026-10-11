# SPDX-License-Identifier: Apache-2.0
"""The exact source manifest that a broker and its bridge are admitted with.

The manifest lists files relative to one root, each with its SHA-256 and size, sorted by path, in
one canonical JSON encoding. Its own SHA-256 is the manifest digest that every protocol frame
carries. A broker verifies every listed file before it opens and refuses to serve when any file is
missing, is not a regular file, sits behind a link, or has other bytes. The driver package chooses
the files: the Java sources or classes, the Python modules, parsers and encoder, helper jars,
fixtures, host tools, the role manifest and the admission inputs."""
import hashlib
import json
import os
from pathlib import Path
import stat

VERSION = 1


def _check_path(relative):
    if (not isinstance(relative, str) or not relative or relative.startswith('/')
            or any(ord(c) < 0x21 or ord(c) > 0x7e for c in relative)):
        raise ValueError('a manifest path is relative printable ASCII without spaces')
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('a manifest path has an empty, current or parent component')
    return parts


def _regular(root, relative):
    """The bytes of a regular file reached without any link, or None."""
    path = Path(root)
    for part in _check_path(relative):
        path = path / part
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            return None
        if stat.S_ISLNK(mode):
            return None
    if not stat.S_ISREG(mode):
        return None
    return path.read_bytes()


def encode(files):
    entries = sorted(files, key=lambda entry: entry[0])
    if len({path for path, _, _ in entries}) != len(entries):
        raise ValueError('a path listed twice')
    for path, sha, size in entries:
        _check_path(path)
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
            raise ValueError('a digest that is not 32 lowercase hexadecimal bytes')
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError('a size below zero')
    value = {'version': VERSION, 'files': [{'path': p, 'sha256': s, 'bytes': n} for p, s, n in entries]}
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def build(root, paths):
    files = []
    for relative in paths:
        data = _regular(root, relative)
        if data is None:
            raise ValueError('not a regular file reached without links: ' + relative)
        files.append((relative, hashlib.sha256(data).hexdigest(), len(data)))
    return encode(files)


def parse(data):
    """The listed files of an exact manifest encoding."""
    value = json.loads(bytes(data).decode('ascii'))
    if not isinstance(value, dict) or set(value) != {'version', 'files'} or value['version'] != VERSION:
        raise ValueError('not a version 1 manifest')
    files = []
    for entry in value['files']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'bytes'}:
            raise ValueError('a manifest entry of no known form')
        files.append((entry['path'], entry['sha256'], entry['bytes']))
    if encode(files) != bytes(data):
        raise ValueError('not the canonical manifest encoding')
    return files


def digest(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def verify(root, data):
    """Every problem with the files under root against the manifest; empty when all match."""
    try:
        files = parse(data)
    except ValueError as error:
        return ['manifest: %s' % error]
    problems = []
    for path, sha, size in files:
        try:
            content = _regular(root, path)
        except ValueError as error:
            problems.append('%s: %s' % (path, error))
            continue
        if content is None:
            problems.append('%s is missing, behind a link or not a regular file' % path)
        elif (hashlib.sha256(content).hexdigest(), len(content)) != (sha, size):
            problems.append('%s has other bytes' % path)
    return problems
