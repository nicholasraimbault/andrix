# SPDX-License-Identifier: Apache-2.0
"""The broker's durable ledger: one numbered sequence of entries under one directory.

Layout:

    <root>/LEDGER                 "andrix-lab-ledger 1", written once when the ledger is created
    <root>/NNNNNN-<kind>/         one entry, numbered from 1 without gaps

A record entry holds `record.json`. A capture entry holds `intent.json`, written and synced
before its command is launched, then `stdout` and `stderr` with the bytes unchanged, then
`result.json`, written last with the digest and size of both streams. Every file is created
exclusively, written whole and synced through its own descriptor, and each directory change is
synced, so nothing is ever rewritten. Each JSON file repeats its entry's number and kind.

Reopening checks the marker, every name, the numbering, each entry's files and each complete
capture's stream digests. Only the last entry can be incomplete after a crash of the one writer,
because the broker writes one entry at a time. An incomplete last entry is never completed,
repeated or removed: the reopening broker writes a quarantine record naming it, and the record
says whether its command was certainly never launched (no complete intent) or has an unknown
effect (an intent without a result). A crash during that reopening can leave a run of quarantine
entries at the end, which the next reopening completes. An incomplete entry that no quarantine
record names, or any other irregularity, refuses the reopening."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MARKER = b'andrix-lab-ledger 1\n'
MARKER_NAME = 'LEDGER'
KINDS = ('open', 'generation', 'generation-end', 'capture', 'group', 'crossing', 'outcome', 'fault', 'escrow',
         'host', 'quarantine', 'stop', 'faults', 'artifacts', 'report', 'lab-action', 'notice-issue')
NAME = re.compile(r'([0-9]{6})-([a-z][a-z-]*)')
MAX_ENTRIES = 999999
CAPTURE_FILES = ('intent.json', 'stdout', 'stderr', 'result.json')
RECORD_FILE = 'record.json'
MAX_JSON = 1 << 20


class LedgerDamaged(Exception):
    """The ledger breaks a rule that no crash of its one writer can explain. Nothing is written."""


def encode_json(value):
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _strict_json(data):
    def refuse(constant):
        raise ValueError('a number that is not finite: ' + constant)
    value = json.loads(data.decode('ascii'), parse_constant=refuse)
    if not isinstance(value, dict):
        raise ValueError('not an object')
    return value


@dataclass
class Entry:
    number: int
    kind: str
    state: str
    content: dict
    path: Path

    @property
    def complete(self):
        return self.state == 'complete'


class Ledger:
    """One writer's numbered entries. Create with `create`, reopen with `open`."""

    def __init__(self, root, entries, sync=True, fsync=os.fsync):
        self.root, self.entries, self._sync, self._fsync = Path(root), entries, sync, fsync
        # The first write or sync that fails in this process: from then on nothing more is written,
        # so no later entry, and no command, ever stands on a barrier that did not complete.
        self._failed = None

    # ------------------------------------------------ durability primitives

    def _write_new(self, path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            if self._sync:
                self._fsync(fd)
        finally:
            os.close(fd)

    def _sync_dir(self, path):
        if not self._sync:
            return
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self._fsync(fd)
        finally:
            os.close(fd)

    def _sync_file(self, path):
        if not self._sync:
            return
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self._fsync(fd)
        finally:
            os.close(fd)

    def _writing(self, write):
        """Runs one entry's writes; a failed write or sync latches the ledger against any later one."""
        if self._failed is not None:
            raise LedgerDamaged('an earlier write or sync failed in this process: %s' % self._failed)
        try:
            return write()
        except OSError as error:
            self._failed = error
            raise

    @classmethod
    def create(cls, root, sync=True, fsync=os.fsync):
        """A new empty ledger. The directory must not exist or must be empty."""
        root = Path(root)
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        if any(root.iterdir()):
            raise LedgerDamaged('a new ledger needs an empty directory')
        ledger = cls(root, [], sync, fsync)
        ledger._write_new(root / MARKER_NAME, MARKER)
        ledger._sync_dir(root)
        ledger._sync_dir(root.parent)
        return ledger

    @classmethod
    def open(cls, root, sync=True, fsync=os.fsync):
        """The ledger as it stands, every entry checked. Raises LedgerDamaged. Before anything relies
        on the history, every file it holds (the marker, and each entry's files) is synced again,
        then each entry's directory and the ledger's own: an entry that reads whole may still have had
        a file or directory sync fail in an earlier writer. A sync that fails raises OSError, so the
        opening is refused until every barrier completes. A loss the kernel already reported to an
        earlier sync can go unreported to a later one; no reading from user space can see it, which is
        why a writer never writes on after a failed write or sync."""
        ledger = cls(Path(root), scan(root), sync, fsync)
        ledger._sync_file(ledger.root / MARKER_NAME)
        for entry in ledger.entries:
            for name in sorted(os.listdir(entry.path)):
                ledger._sync_file(entry.path / name)
            ledger._sync_dir(entry.path)
        ledger._sync_dir(ledger.root)
        return ledger

    # ------------------------------------------------ writing

    @property
    def last(self):
        return self.entries[-1] if self.entries else None

    def _allocate(self, kind):
        if kind not in KINDS:
            raise ValueError('an unknown entry kind')
        if self.last is not None and not self.last.complete and kind != 'quarantine':
            raise LedgerDamaged('an incomplete entry must be quarantined before anything else')
        number = len(self.entries) + 1
        if number > MAX_ENTRIES:
            raise LedgerDamaged('the ledger is full')
        path = self.root / ('%06d-%s' % (number, kind))
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as error:
            raise LedgerDamaged('entry %d exists: a second writer' % number) from error
        self._sync_dir(self.root)
        entry = Entry(number, kind, 'incomplete', {}, path)
        self.entries.append(entry)
        return entry

    def record(self, kind, value):
        """Writes one record entry durably and returns its number."""
        if kind == 'capture':
            raise ValueError('a capture has its own protocol')
        content = dict(value, number=len(self.entries) + 1, kind=kind)
        data = encode_json(content)
        if len(data) > MAX_JSON:
            raise ValueError('a record above its bound')
        def write():
            entry = self._allocate(kind)
            self._write_new(entry.path / RECORD_FILE, data)
            self._sync_dir(entry.path)
            entry.content, entry.state = content, 'complete'
            return entry.number
        return self._writing(write)

    def begin_capture(self, intent):
        """Writes a capture's intent and syncs it. Only after this returns may its command run."""
        content = dict(intent, number=len(self.entries) + 1, kind='capture')
        data = encode_json(content)
        def write():
            entry = self._allocate('capture')
            self._write_new(entry.path / 'intent.json', data)
            self._sync_dir(entry.path)
            entry.content, entry.state = {'intent': content}, 'interrupted'
            return entry
        return self._writing(write)

    def finish_capture(self, entry, stdout, stderr, result):
        """Writes a capture's streams, then its result last."""
        if entry is not self.last or entry.state != 'interrupted':
            raise ValueError('only the open capture can finish')
        stdout, stderr = bytes(stdout), bytes(stderr)
        content = dict(result, number=entry.number, kind='capture',
                       stdout_sha256=hashlib.sha256(stdout).hexdigest(), stdout_bytes=len(stdout),
                       stderr_sha256=hashlib.sha256(stderr).hexdigest(), stderr_bytes=len(stderr))

        def write():
            self._write_new(entry.path / 'stdout', stdout)
            self._write_new(entry.path / 'stderr', stderr)
            self._write_new(entry.path / 'result.json', encode_json(content))
            self._sync_dir(entry.path)
            entry.content = {'intent': entry.content['intent'], 'result': content, 'stdout': stdout, 'stderr': stderr}
            entry.state = 'complete'
            return entry.number
        return self._writing(write)

    def unquarantined(self):
        """Every incomplete entry that no quarantine record names yet."""
        named = {e.content.get('entry') for e in self.entries if e.kind == 'quarantine' and e.complete}
        return [e for e in self.entries if not e.complete and e.number not in named]


# ---------------------------------------------------------------- reading

def _lstat_kind(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return 'link'
    if stat.S_ISDIR(st.st_mode):
        return 'dir'
    if stat.S_ISREG(st.st_mode):
        return 'file'
    return 'other'


def _read(path):
    if _lstat_kind(path) != 'file':
        raise LedgerDamaged('%s is not a regular file' % path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def _json_or_none(path, number, kind):
    """A file's JSON when it is whole and repeats its entry, else None (a write cut short)."""
    try:
        value = _strict_json(_read(path))
    except (ValueError, UnicodeDecodeError):
        return None
    if value.get('number') != number or value.get('kind') != kind:
        raise LedgerDamaged('%s does not repeat its entry' % path)
    return value


def scan(root):
    """Every entry of a ledger, in order, each with its state. Raises LedgerDamaged."""
    root = Path(root)
    try:
        if _lstat_kind(root) != 'dir':
            raise LedgerDamaged('the ledger root is not a directory')
        if _read(root / MARKER_NAME) != MARKER:
            raise LedgerDamaged('the ledger marker differs')
        names = sorted(os.listdir(root))
    except OSError as error:
        raise LedgerDamaged('the ledger cannot be read: %s' % error) from error
    entries = []
    for name in names:
        if name == MARKER_NAME:
            continue
        match = NAME.fullmatch(name)
        if not match or match[2] not in KINDS:
            raise LedgerDamaged('an unknown name %r' % name)
        number, kind = int(match[1]), match[2]
        if number != len(entries) + 1:
            raise LedgerDamaged('entry %d where %d was due' % (number, len(entries) + 1))
        path = root / name
        if _lstat_kind(path) != 'dir':
            raise LedgerDamaged('entry %d is not a directory' % number)
        present = sorted(os.listdir(path))
        entries.append(_entry(path, number, kind, present))
    # A reopening writes a quarantine record for each incomplete entry before anything else. Its own
    # crash can leave a run of quarantine entries after the entries it was naming.
    named = {e.content.get('entry') for e in entries if e.kind == 'quarantine' and e.complete}
    for i, e in enumerate(entries[:-1]):
        if not e.complete and e.number not in named and any(x.kind != 'quarantine' for x in entries[i + 1:]):
            raise LedgerDamaged('entry %d is incomplete and no quarantine record names it' % e.number)
    for e in entries:
        if e.kind == 'quarantine' and e.complete and e.content.get('entry') not in [x.number for x in entries
                                                                                    if not x.complete]:
            raise LedgerDamaged('quarantine record %d names a complete or missing entry' % e.number)
    return entries


def _entry(path, number, kind, present):
    if kind != 'capture':
        if present not in ([], [RECORD_FILE]):
            raise LedgerDamaged('entry %d holds %s' % (number, present))
        if not present:
            return Entry(number, kind, 'incomplete', {}, path)
        content = _json_or_none(path / RECORD_FILE, number, kind)
        return Entry(number, kind, 'complete' if content is not None else 'incomplete', content or {}, path)
    allowed = ([], ['intent.json'], ['intent.json', 'stdout'], ['intent.json', 'stderr', 'stdout'],
               sorted(CAPTURE_FILES))
    if present not in allowed:
        raise LedgerDamaged('capture %d holds %s' % (number, present))
    intent = _json_or_none(path / 'intent.json', number, 'capture') if present else None
    if intent is None:
        if len(present) > 1:
            raise LedgerDamaged('capture %d has streams without a whole intent' % number)
        return Entry(number, 'capture', 'intent-incomplete', {}, path)
    if 'result.json' not in present:
        return Entry(number, 'capture', 'interrupted', {'intent': intent}, path)
    result = _json_or_none(path / 'result.json', number, 'capture')
    if result is None:
        return Entry(number, 'capture', 'interrupted', {'intent': intent}, path)
    stdout, stderr = _read(path / 'stdout'), _read(path / 'stderr')
    for label, data in (('stdout', stdout), ('stderr', stderr)):
        if (hashlib.sha256(data).hexdigest(), len(data)) != (result.get(label + '_sha256'), result.get(label + '_bytes')):
            raise LedgerDamaged('capture %d %s differs from its recorded digest' % (number, label))
    return Entry(number, 'capture', 'complete', {'intent': intent, 'result': result, 'stdout': stdout,
                                                  'stderr': stderr}, path)
