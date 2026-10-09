#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Carry check of a GrapheneOS release against Andrix's recorded base.

Read only, from public sources: the signed manifest tag, single Git trees and blobs
fetched by object ID, commit metadata bounded by a tag or a date, Android security
bulletins, AOSP Gitiles logs and the GrapheneOS release notes. No clone, sync or source
tree is used. Patches are applied in private scratch with the patch tools' exact command
at fuzz 0. A failing hunk is reported as a conflict. Nothing is fuzzed, dropped or
edited. See grapheneos_carry.md.
"""
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
import argparse
import base64
import datetime
import difflib
import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import grapheneos_source as source

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / 'upstream'
SURFACE = UPSTREAM / 'surface.json'
BACKPORTS = UPSTREAM / 'backports.json'
MANIFEST_URL = 'https://github.com/GrapheneOS/platform_manifest'
PRODUCT = 'andrix_gos_cf_arm64_only_phone'
# The patch tools' exact command. Never a higher fuzz, never --force or a reject skip.
PATCH_COMMAND = ('/usr/bin/patch', '--batch', '--forward', '--fuzz=0',
                 '--no-backup-if-mismatch', '-p1')
OBJECT_HOSTS = frozenset({'github.com'})                  # trees and blobs by object ID
GITILES_HOSTS = frozenset({'android.googlesource.com'})   # raw path plus listed blob ID
HTTP_HOSTS = frozenset({'source.android.com', 'android.googlesource.com', 'grapheneos.org'})
BULLETINS = 'https://source.android.com/docs/security/bulletin/'
RELEASES = 'https://grapheneos.org/releases'
LEDGER_PROJECT = 'frameworks/base'
LEDGER_AOSP_PROJECT = 'platform/frameworks/base'
SECURITY_FLAG = 'RELEASE_PLATFORM_SECURITY_PATCH'
SCHEMA = {'base': 'andrix.upstream.base/1', 'ledger': 'andrix.upstream.ledger/1',
          'carry': 'andrix.upstream.carry/1', 'surface': 'andrix.upstream.surface/1',
          'backports': 'andrix.upstream.backports/1'}
HEX40 = re.compile(r'[0-9a-f]{40}')
TAG_FORM = re.compile(r'[0-9]{10}')
CHANGE_ID = re.compile(r'^Change-Id:[ \t]*(I[0-9a-f]{40})[ \t]*$', re.M)
CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
ADJACENT = 3                    # lines beyond a hunk's context that still count as overlap
SCRATCH_BUDGET = 512 << 20      # whole scratch; the task limit is 1 GiB
FILE_LIMIT = 128 << 20          # any single file a Git child process writes
HTTP_LIMIT = 8 << 20
HTTP_INTERVAL = 1.0             # seconds between requests to one host, to stay within its budget
GIT_TIMEOUT = 300
CHERRYPICK_PREFIX = 'https://googleplex-android-review.googlesource.com/q/commit:'
CLASSES = ('identical', 'changed clean', 'moved', 'overlap', 'conflict', 'missing')
# Lists rendered one row per line. Patch file entries are not among them; they expand.
ROW_LISTS = frozenset({'fixes', 'watched_projects', 'changed', 'added', 'removed', 'commits', 'checks',
                       'sources', 'bases', 'overlaps', 'upstream_commits', 'api_added', 'api_removed',
                       'surface', 'kernel_changed', 'limits', 'not_run'})


class CarryError(Exception):
    """A verification failed or an input is invalid. Nothing past it is inferred."""


class NotRun(Exception):
    """A public source was unavailable, rate limited or over budget. Nothing is guessed."""


# ---------------------------------------------------------------- JSON records

def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CarryError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def _constant(value):
    raise CarryError('non-finite JSON value')


def load_json(path):
    try:
        return json.loads(Path(path).read_text(), object_pairs_hook=_unique, parse_constant=_constant)
    except (OSError, ValueError) as error:
        raise CarryError('unreadable JSON %s: %s' % (path, error)) from error


def render(value, key=None, level=0):
    """Reviewable JSON: small values inline, one line per row in row lists."""
    compact = json.dumps(value, ensure_ascii=False, separators=(', ', ': '))
    pad = '  ' * (level + 1)
    if not isinstance(value, (dict, list)) or not value or len(compact) + 2 * level <= 96:
        return compact
    if isinstance(value, list):
        rows = [json.dumps(item, ensure_ascii=False, separators=(', ', ': ')) if key in ROW_LISTS
                else render(item, None, level + 1) for item in value]
        return '[\n' + ',\n'.join(pad + row for row in rows) + '\n' + '  ' * level + ']'
    rows = [json.dumps(name) + ': ' + render(item, name, level + 1) for name, item in value.items()]
    return '{\n' + ',\n'.join(pad + row for row in rows) + '\n' + '  ' * level + '}'


def dump(value):
    text = render(value) + '\n'
    if json.loads(text) != value:
        raise CarryError('record rendering changed its value')
    return text.encode()


def write_new(path, value, replace=False):
    """Write a record. An existing record is never replaced unless explicitly allowed."""
    path = Path(path).absolute()
    data = dump(value)
    if path.exists() and not replace:
        raise CarryError('refusing to overwrite ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.carry-', delete=False) as out:
        temporary = Path(out.name)
        try:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
            os.fchmod(out.fileno(), 0o644)
        except BaseException:
            temporary.unlink()
            raise
    if replace:
        os.replace(temporary, path)
    else:
        try:
            os.link(temporary, path)        # fails rather than replacing a concurrent writer
        finally:
            temporary.unlink()
    return sha(data)


def repo_path(path):
    path = Path(path).resolve()
    return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)


# ---------------------------------------------------------------- Git objects

def _limit_files():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))


def _summary(stderr):
    text = ' '.join(stderr.decode(errors='replace').split())
    return text[-400:] if text else 'no error output'


class Git:
    """Git in private scratch: isolated configuration, explicit fetches, no lazy fetch."""

    def __init__(self, scratch, protocols=('https',), budget=SCRATCH_BUDGET):
        self.scratch = Path(scratch)
        self.protocols = tuple(protocols)
        self.budget = budget
        self.stores = {}

    def environment(self):
        env = source.git_environment()
        env.update({'GIT_ALLOW_PROTOCOL': ':'.join(self.protocols), 'GIT_NO_LAZY_FETCH': '1',
                    'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'})
        return env

    def check_url(self, url, hosts=OBJECT_HOSTS | GITILES_HOSTS):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme == 'https' and 'https' in self.protocols and parts.hostname in hosts \
                and not parts.username and not parts.password and parts.port is None:
            return url
        if parts.scheme == 'file' and 'file' in self.protocols:
            return url  # offline fixtures only; the command line always uses https
        raise CarryError('refused source URL: ' + url)

    def run(self, cwd, args, data=None, network=False):
        # Scratch object stores are disposable and every object is hashed again when read, so
        # they skip fsync. Nothing here writes outside the scratch store.
        command = ['git', '--no-pager', '--no-replace-objects', '-c', 'core.hooksPath=' + os.devnull,
                   '-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false',
                   '-c', 'protocol.version=2', '-c', 'fetch.writeCommitGraph=false', '-c', 'core.fsync=none',
                   *args]
        try:
            process = subprocess.run(command, cwd=cwd, env=self.environment(), input=data,
                                     capture_output=True, timeout=GIT_TIMEOUT if network else 120,
                                     preexec_fn=_limit_files)
        except subprocess.TimeoutExpired as error:
            if network:
                raise NotRun('Git network operation timed out') from error
            raise CarryError('local Git operation timed out') from error
        if process.returncode:
            message = _summary(process.stderr)
            if network:
                limited = re.search(r'\b429\b|rate.?limit|too many requests', message, re.I)
                raise NotRun(('rate limited: ' if limited else 'Git fetch failed: ') + message)
            raise CarryError('Git failed: ' + message)
        if network:
            self.check_budget()
        return process.stdout, process.stderr

    def check_budget(self):
        total = sum(p.stat().st_size for p in self.scratch.rglob('*') if p.is_file() and not p.is_symlink())
        if total > self.budget:
            raise NotRun('scratch budget exceeded: %d bytes' % total)

    def ls_remote(self, url, refs):
        out, _ = self.run(None, ['ls-remote', self.check_url(url), *refs], network=True)
        result = {}
        for line in out.decode().splitlines():
            oid, _, name = line.partition('\t')
            if name in refs and HEX40.fullmatch(oid):
                result[name] = oid
        return result

    def store(self, url, purpose='files'):
        key = (self.check_url(url, OBJECT_HOSTS), purpose)
        if key not in self.stores:
            path = self.scratch / 'objects' / ('%s-%s' % (sha(url.encode())[:16], purpose))
            self.stores[key] = Store(self, url, path)
        return self.stores[key]


def parse_tree(data):
    entries, i = {}, 0
    while i < len(data):
        space = data.index(b' ', i)
        nul = data.index(b'\0', space)
        mode = data[i:space].decode()
        name = data[space + 1:nul].decode('utf-8', 'surrogateescape')
        entries[name] = (mode, data[nul + 1:nul + 21].hex())
        i = nul + 21
    return entries


def parse_commit(oid, raw):
    head, _, message = raw.partition(b'\n\n')
    tree, parents, time = None, [], None
    for line in head.split(b'\n'):
        if line.startswith(b'tree '):
            tree = line[5:].decode()
        elif line.startswith(b'parent '):
            parents.append(line[7:].decode())
        elif line.startswith(b'committer '):
            time = int(line.rsplit(b' ', 2)[1])
    if tree is None or time is None:
        raise CarryError('malformed commit object ' + oid)
    return {'oid': oid, 'tree': tree, 'parents': parents, 'time': time,
            'message': message.decode('utf-8', 'replace')}


class Store:
    """One bare promisor repository in scratch for one remote and purpose."""

    def __init__(self, git, url, path):
        self.git, self.url, self.path = git, url, Path(path)
        if not self.path.exists():
            self.path.mkdir(parents=True)
            for args in (['init', '-q', '--bare', '.'], ['config', 'core.repositoryformatversion', '1'],
                         ['config', 'extensions.partialClone', 'origin'],
                         ['config', 'remote.origin.url', url],
                         ['config', 'remote.origin.promisor', 'true']):
                git.run(self.path, args)
        self.trees = {}

    def run(self, args, data=None, network=False):
        return self.git.run(self.path, args, data=data, network=network)

    def fetch(self, wants=(), depth=None, exclude=None, since=None):
        """Explicit wants only. Commits always carry a depth, exclusion or date bound.

        No-op negotiation sends no haves, so the server cannot omit a wanted tree or blob
        because a local commit already reaches it. This is how Git's own lazy fetch asks.
        """
        args = ['-c', 'fetch.negotiationAlgorithm=noop', 'fetch', '--filter=tree:0', '--no-tags',
                '--no-write-fetch-head', '--stdin']
        if depth is not None:
            args.append('--depth=%d' % depth)
        if exclude is not None:
            args.append('--shallow-exclude=' + exclude)
        if since is not None:
            args.append('--shallow-since=' + since)
        args.append('origin')
        wants = sorted(set(wants))
        if wants:
            self.run(args, ('\n'.join(wants) + '\n').encode(), network=True)

    def missing(self, oids):
        oids = sorted(set(oids))
        if not oids:
            return []
        out, _ = self.run(['cat-file', '--batch-check'], ('\n'.join(oids) + '\n').encode())
        return [line.split()[0] for line in out.decode().splitlines() if line.endswith(' missing')]

    def ensure(self, oids, commits=False):
        missing = self.missing(oids)
        if missing:
            self.fetch(missing, depth=1 if commits else None)
            still = self.missing(missing)
            if still:
                raise NotRun('the remote did not send requested objects: ' + ', '.join(still[:3]))

    def read(self, oids):
        oids = sorted(set(oids))
        if not oids:
            return {}
        out, _ = self.run(['cat-file', '--batch'], ('\n'.join(oids) + '\n').encode())
        result, i = {}, 0
        while i < len(out):
            end = out.index(b'\n', i)
            header = out[i:end].decode().split()
            if len(header) != 3:
                raise CarryError('object unavailable: ' + header[0])
            oid, kind, size = header[0], header[1], int(header[2])
            result[oid] = (kind, out[end + 1:end + 1 + size])
            i = end + 2 + size
        return result

    def commits(self, oids):
        self.ensure(oids, commits=True)
        result = {}
        for oid, (kind, raw) in self.read(oids).items():
            if kind != 'commit':
                raise CarryError('not a commit: ' + oid)
            result[oid] = parse_commit(oid, raw)
        return result

    def resolve(self, roots, paths):
        """{key: root tree} x paths -> {key: {path: (mode, oid) or None}}, one object per need."""
        result = {key: {} for key in roots}
        pending = [(key, path, PurePosixPath(path).parts, 0, root)
                   for key, root in roots.items() for path in paths]
        while pending:
            self.listings(sorted({item[4] for item in pending}))   # one fetch per tree level
            following = []
            for key, path, parts, index, tree in pending:
                entry = self.trees[tree].get(parts[index])
                if entry is None or (index + 1 < len(parts) and entry[0] != '40000'):
                    result[key][path] = None
                elif index + 1 == len(parts):
                    result[key][path] = entry
                else:
                    following.append((key, path, parts, index + 1, entry[1]))
            pending = following
        return result

    def listings(self, oids):
        """Tree listings for several tree IDs, fetched in one batch: [{name: (mode, oid)}]."""
        needed = [oid for oid in oids if oid not in self.trees]
        if needed:
            self.ensure(needed)
            for oid, (kind, data) in self.read(needed).items():
                if kind != 'tree':
                    raise CarryError('not a tree: ' + oid)
                self.trees[oid] = parse_tree(data)
        return [self.trees[oid] for oid in oids]

    def listing(self, oid):
        return self.listings([oid])[0]

    def blobs(self, oids):
        self.ensure(oids)
        result = {}
        for oid, (kind, data) in self.read(oids).items():
            if kind != 'blob':
                raise CarryError('not a blob: ' + oid)
            result[oid] = data
        return result

    def files(self, commit, paths):
        """Regular files at a commit by blob: {path: (blob, bytes)} or None if absent."""
        tree = self.commits([commit])[commit]['tree']
        entries = self.resolve({commit: tree}, paths)[commit]
        regular = {path: entry for path, entry in entries.items()
                   if entry is not None and entry[0] in ('100644', '100755')}
        data = self.blobs([entry[1] for entry in regular.values()])
        return {path: (regular[path][1], data[regular[path][1]]) if path in regular else None
                for path in paths}

    def walk(self, tip, stop):
        """Commits from tip back to, not including, stop. None if the fetched range is incomplete."""
        listed, _ = self.run(['rev-list', tip])
        found = self.commits(listed.decode().split())
        seen, todo = set(), [tip]
        while todo:
            oid = todo.pop()
            if oid == stop or oid in seen:
                continue
            if oid not in found:
                return None
            seen.add(oid)
            todo.extend(found[oid]['parents'])
        return [found[oid] for oid in listed.decode().split() if oid in seen]


# ---------------------------------------------------------------- HTTP sources

class Http:
    """Single public documents over HTTPS from a fixed host list, with size and rate limits."""

    def __init__(self, hosts=HTTP_HOSTS, limit=HTTP_LIMIT, interval=HTTP_INTERVAL):
        self.hosts, self.limit, self.retrieved = frozenset(hosts), limit, []
        self.interval, self.last = interval, {}

    def get(self, url, allow_missing=False):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != 'https' or parts.hostname not in self.hosts:
            raise CarryError('refused document URL: ' + url)
        wait = self.last.get(parts.hostname, -self.interval) + self.interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)  # paced, not retried: a refusal still ends in NOT_RUN
        self.last[parts.hostname] = time.monotonic()
        request = urllib.request.Request(url, headers={'User-Agent': 'andrix-carry-check/1'})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != 'https' or final.hostname not in self.hosts:
                    raise CarryError('redirected outside the source list: ' + response.geturl())
                data = response.read(self.limit + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404 and allow_missing:
                return None
            if error.code in (403, 429):
                raise NotRun('rate limited or refused by %s (HTTP %d)' % (parts.hostname, error.code)) from error
            raise NotRun('HTTP %d from %s' % (error.code, url)) from error
        except (urllib.error.URLError, OSError) as error:
            raise NotRun('network unavailable for %s: %s' % (parts.hostname, error)) from error
        if len(data) > self.limit:
            raise NotRun('document over the size limit: ' + url)
        self.retrieved.append({'url': url, 'sha256': sha(data), 'bytes': len(data)})
        return data


def gitiles_json(data):
    text = data.decode('utf-8')
    if not text.startswith(")]}'"):
        raise CarryError('unexpected Gitiles JSON prefix')
    return json.loads(text[4:])


def gitiles_entries(http, url, commit, paths):
    """{path: listed entry or None} from the Gitiles listing of each path's directory."""
    result, listings = {}, {}
    for path in paths:
        parent, _, name = path.rpartition('/')
        if parent not in listings:
            listing = http.get('%s/+/%s/%s?format=JSON' % (url, commit, parent), allow_missing=True)
            listings[parent] = {} if listing is None else \
                {e['name']: e for e in gitiles_json(listing).get('entries', [])}
        result[path] = listings[parent].get(name)
    return result


def gitiles_files(http, url, commit, paths):
    """Single files by raw path from Gitiles, each checked against its listed blob ID."""
    result = {}
    for path, entry in gitiles_entries(http, url, commit, paths).items():
        if entry is None:
            result[path] = None
            continue
        if entry['type'] == 'tree':
            result[path] = (entry['id'], None)
            continue
        data = base64.b64decode(http.get('%s/+/%s/%s?format=TEXT' % (url, commit, path)))
        if hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest() != entry['id']:
            raise CarryError('Gitiles content differs from its listed blob: ' + path)
        result[path] = (entry['id'], data)
    return result


# ---------------------------------------------------------------- manifests

MANIFEST_ELEMENTS = frozenset({'remote', 'default', 'project', 'contactinfo', 'superproject', 'notice',
                               'manifest-server', 'repo-hooks'})
PROJECT_CHILDREN = frozenset({'copyfile', 'linkfile', 'annotation'})


def parse_manifest(data):
    """The project table of one flat, fully pinned Repo manifest. Unknown structure fails."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise CarryError('malformed manifest XML') from error
    if root.tag != 'manifest':
        raise CarryError('not a Repo manifest')
    for child in root:
        if child.tag not in MANIFEST_ELEMENTS:
            raise CarryError('unsupported manifest element: ' + child.tag)
    defaults = root.findall('default')
    if len(defaults) != 1:
        raise CarryError('manifest needs exactly one default element')
    default = dict(defaults[0].attrib)
    remotes = {}
    for remote in root.findall('remote'):
        name = remote.get('name')
        if not name or name in remotes or not remote.get('fetch'):
            raise CarryError('invalid manifest remote')
        remotes[name] = dict(remote.attrib)
    projects = {}
    for entry in root.findall('project'):
        name = entry.get('name')
        try:
            path = source.relative(entry.get('path', name)).as_posix()
        except source.SourceError as error:
            raise CarryError('unsafe project path: %r' % entry.get('path', name)) from error
        remote = entry.get('remote', default.get('remote'))
        if not name or remote not in remotes or path in projects:
            raise CarryError('invalid or duplicate project: ' + path)
        revision = entry.get('revision') or remotes[remote].get('revision') or default.get('revision')
        if not HEX40.fullmatch(revision or ''):
            raise CarryError('project revision is not a pinned commit: ' + path)
        files = []
        for child in entry:
            if child.tag not in PROJECT_CHILDREN:
                raise CarryError('unsupported project element: ' + child.tag)
            if child.tag != 'annotation':
                files.append([child.tag, child.get('src', ''), child.get('dest', '')])
        projects[path] = {'path': path, 'name': name, 'remote': remote, 'revision': revision,
                          'groups': entry.get('groups', ''), 'files': files}
    return {'default': default, 'remotes': remotes, 'projects': projects}


def project_rows(manifest):
    return [manifest['projects'][path] for path in sorted(manifest['projects'])]


def project_url(manifest, path):
    project = manifest['projects'][path]
    fetch = manifest['remotes'][project['remote']]['fetch']
    if '://' not in fetch:
        raise CarryError('relative remote fetch URLs are not supported: ' + fetch)
    return fetch.rstrip('/') + '/' + project['name']


def manifest_diff(base, target):
    old, new = base['projects'], target['projects']
    changed = []
    for path in sorted(set(old) & set(new)):
        a, b = old[path], new[path]
        if a == b:
            continue
        row = {'path': path, 'base': a['revision'], 'target': b['revision']}
        for field in ('name', 'remote', 'groups', 'files'):
            if a[field] != b[field]:
                row[field] = [a[field], b[field]]
        changed.append(row)
    brief = lambda p: {'path': p['path'], 'name': p['name'], 'remote': p['remote'], 'revision': p['revision']}
    return {'aosp_default_revision': {'base': base['default'].get('revision'),
                                      'target': target['default'].get('revision')},
            'counts': {'base': len(old), 'target': len(new)},
            'renamed': sum(1 for row in changed if 'name' in row or 'remote' in row),
            'changed': changed,
            'added': [brief(new[p]) for p in sorted(set(new) - set(old))],
            'removed': [brief(old[p]) for p in sorted(set(old) - set(new))]}


# ---------------------------------------------------------------- signed tags and base records

def check_signers(path):
    path = Path(path).resolve(strict=True)
    if sha(path.read_bytes()) != source.SIGNERS_SHA256:
        raise CarryError('allowed signers bytes differ from the approved trust input')
    return path


def parse_tag(raw):
    head, _, _ = raw.partition(b'\n\n')
    fields = {}
    for line in head.decode('utf-8', 'replace').split('\n'):
        key, _, value = line.partition(' ')
        fields.setdefault(key, value)
    return fields


def verify_release(git, tag, signers, manifest_url=MANIFEST_URL):
    """Signed tag, tag name, commit and manifest blob, as grapheneos_source.inspect checks them."""
    if not TAG_FORM.fullmatch(tag):
        raise CarryError('unexpected release tag form: ' + tag)
    signers = check_signers(signers)
    ref = 'refs/tags/' + tag
    remote = git.ls_remote(manifest_url, [ref, ref + '^{}'])
    if set(remote) != {ref, ref + '^{}'}:
        raise CarryError('release tag absent or not annotated: ' + tag)
    store = git.store(manifest_url, 'manifest-' + tag)
    store.fetch(['+%s:%s' % (ref, ref)], depth=1)
    local = store.run(['rev-parse', '--verify', ref])[0].decode().strip()
    kind, raw = store.read([local])[local]
    fields = parse_tag(raw)
    if (local != remote[ref] or kind != 'tag' or fields.get('object') != remote[ref + '^{}']
            or fields.get('type') != 'commit' or fields.get('tag') != tag):
        raise CarryError('tag object does not name this release and commit')
    try:
        _, err = store.run(['-c', 'gpg.ssh.program=/usr/bin/ssh-keygen',
                            '-c', 'gpg.ssh.allowedSignersFile=' + str(signers), 'verify-tag', local])
    except CarryError as error:
        raise CarryError('tag signature rejected: ' + tag) from error
    signer = re.search(r'Good "git" signature for (\S+) with', err.decode(errors='replace'))
    if signer is None:
        raise CarryError('no accepted signature reported for ' + tag)
    commit = fields['object']
    manifest = store.files(commit, ['default.xml'])['default.xml']
    if manifest is None:
        raise CarryError('signed manifest commit has no default.xml')
    return {'tag': tag, 'tag_object': local, 'commit': commit, 'blob': manifest[0],
            'manifest': manifest[1], 'signer': signer.group(1)}


def lunch_target():
    text = (ROOT / 'AndroidProducts.mk').read_text()
    found = set(re.findall(r'\b%s-([A-Za-z0-9_]+)-(user|userdebug|eng)\b' % PRODUCT, text))
    if len(found) != 1:
        raise CarryError('expected one lunch choice for ' + PRODUCT)
    return found.pop()


def _textproto_strings(text, field):
    return tuple(re.findall(r'\b%s:\s*"([^"]*)"' % field, text))


def patch_level(store, commit, release, variant):
    """The effective security patch level of one lunch release, within build/release only.

    Resolution follows aliases and inheritance. A definition found at the same precedence with
    different values, or a build variant definition that would compete, fails rather than guess.
    Directory listings and the small configuration blobs are fetched in a few batches.
    """
    root = store.commits([commit])[commit]['tree']
    top = store.listing(root)
    if 'release_config_map.textproto' not in top or 'release_configs' not in top or 'flag_values' not in top:
        raise CarryError('build/release lacks its release configuration')
    configs, flags = store.listings([top['release_configs'][1], top['flag_values'][1]])
    flag_dirs = dict(zip([name for name, e in flags.items() if e[0] == '40000'],
                         store.listings([e[1] for e in flags.values() if e[0] == '40000'])))
    texts = store.blobs([top['release_config_map.textproto'][1]] +
                        [e[1] for name, e in configs.items() if name.endswith('.textproto')])
    aliases = dict(re.findall(r'aliases:?\s*\{\s*name:\s*"([^"]+)"\s*target:\s*"([^"]+)"\s*\}',
                              texts[top['release_config_map.textproto'][1]].decode()))
    flag_file = SECURITY_FLAG + '.textproto'
    steps, needed = [], {}

    def candidate(name):
        entry = flag_dirs.get(name, {}).get(flag_file)
        if entry is not None:
            needed[name] = entry[1]
        return entry

    def resolve(name, depth):
        if depth > 16:
            raise CarryError('release config inheritance too deep')
        seen = set()
        while name in aliases:
            if name in seen:
                raise CarryError('release config alias cycle at ' + name)
            seen.add(name)
            steps.append('%s aliases %s' % (name, aliases[name]))
            name = aliases[name]
        if candidate(name) is not None:
            steps.append('%s sets it' % name)
            return {name}
        entry = configs.get(name + '.textproto')
        if entry is None:
            raise CarryError('unknown release config: ' + name)
        parents = re.findall(r'^\s*inherits:\s*"([^"]+)"\s*$', texts[entry[1]].decode(), re.M)
        steps.append('%s inherits %s' % (name, ', '.join(parents) or 'nothing'))
        found = set()
        for parent in parents:
            found |= resolve(parent, depth + 1)
        return found

    found = resolve(release, 0)
    if not found:
        raise CarryError('no security patch level for release ' + release)
    competing = candidate(variant)
    values = store.blobs(list(needed.values()))
    chosen = {_textproto_strings(values[needed[name]].decode(), 'string_value') for name in found}
    if len(chosen) != 1:
        raise CarryError('ambiguous inherited security patch level for ' + release)
    value = chosen.pop()
    if competing is not None and _textproto_strings(values[competing[1]].decode(), 'string_value') != value:
        raise CarryError('the build variant also sets the security patch level')
    if len(value) != 1 or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value[0]):
        raise CarryError('unexpected security patch level value')
    name = sorted(found)[0]
    return {'value': value[0], 'release': release, 'variant': variant, 'resolution': steps,
            'project': 'build/release', 'revision': commit,
            'path': 'flag_values/%s/%s' % (name, flag_file), 'blob': needed[name]}


def derive_record(git, tag, signers, patched_projects, manifest_url=MANIFEST_URL):
    """A base record for one release, derived only from its signed manifest and single objects."""
    release = verify_release(git, tag, signers, manifest_url)
    manifest = parse_manifest(release['manifest'])
    for path in ['build/release', *patched_projects]:
        if path not in manifest['projects']:
            raise CarryError('release lacks project ' + path)
    rows = project_rows(manifest)
    lunch_release, variant = lunch_target()
    store = git.store(project_url(manifest, 'build/release'))
    level = patch_level(store, manifest['projects']['build/release']['revision'], lunch_release, variant)
    record = {
        'schema': SCHEMA['base'],
        'release': tag,
        'manifest': {'repository': manifest_url, 'tag': 'refs/tags/' + tag,
                     'tag_object': release['tag_object'], 'commit': release['commit'],
                     'path': 'default.xml', 'blob': release['blob'],
                     'sha256': sha(release['manifest']), 'signer': release['signer'],
                     'allowed_signers_sha256': source.SIGNERS_SHA256},
        'aosp_default_revision': manifest['default'].get('revision'),
        'projects': {'count': len(rows), 'table_sha256': sha(canonical(rows)),
                     'table_form': 'canonical JSON list of path, name, remote, revision, groups '
                                   'and copyfile/linkfile rows, sorted by path'},
        'security_patch_level': level,
        'kernel_prebuilts': {path: manifest['projects'][path]['revision']
                             for path in sorted(manifest['projects']) if path.startswith('kernel/prebuilts/')},
        'patched_projects': {path: {'name': manifest['projects'][path]['name'],
                                    'remote': manifest['projects'][path]['remote'],
                                    'url': project_url(manifest, path),
                                    'revision': manifest['projects'][path]['revision']}
                             for path in sorted(patched_projects)},
    }
    if tag == source.TAG:
        check_pinned(record, release['manifest'], manifest)
    return record, manifest, release


def check_pinned(record, data, manifest):
    """The pinned release must agree with grapheneos_source.py's constants and parser."""
    projection = [{key: row[key] for key in ('path', 'revision', 'remote', 'groups')}
                  for row in project_rows(manifest)]
    if (record['manifest']['tag_object'] != source.TAG_OBJECT
            or record['manifest']['commit'] != source.MANIFEST_COMMIT
            or record['manifest']['sha256'] != source.MANIFEST_SHA256
            or record['projects']['count'] != source.PROJECT_COUNT
            or source.parse_projects(data) != projection):
        raise CarryError('base record disagrees with the pinned source verifier')


BASE_KEYS = ('schema', 'release', 'manifest', 'aosp_default_revision', 'projects',
             'security_patch_level', 'kernel_prebuilts', 'patched_projects')


def validate_record(record):
    if (not isinstance(record, dict) or tuple(record) != BASE_KEYS or record['schema'] != SCHEMA['base']
            or not TAG_FORM.fullmatch(str(record['release']))
            or record['manifest']['allowed_signers_sha256'] != source.SIGNERS_SHA256
            or not all(HEX40.fullmatch(p['revision']) for p in record['patched_projects'].values())):
        raise CarryError('invalid base record')
    return record


def load_record(path):
    return validate_record(load_json(path))


# ---------------------------------------------------------------- the patch set

def load_patch_set(base_tag):
    """The six exact patches, validated by their own tools' profile checks (unchanged)."""
    directory = ROOT / 'patches' / ('grapheneos-' + base_tag)
    import android_lifecycle as lifecycle
    import native_identity_writer as writer
    import native_principal_pins as pins
    import owner_policy as policy
    import package_installer_payload_sync as payload
    import package_verity as verity
    for module in (lifecycle, writer, pins, payload, verity):
        if module.PROFILE.parent != directory:
            raise CarryError('no patch set recorded for base ' + base_tag)
    names = {'native-principal-pins', 'owner-lifecycle', 'package-verity',
             'package-installer-payload-sync', 'native-identity-writer', 'owner-session-policy'}
    present = {p.stem for p in directory.glob('*.json')}
    if present != names or {p.stem for p in directory.glob('*.patch')} != names:
        raise CarryError('unexpected patch directory content: ' + repo_path(directory))
    value = pins.profile()
    files = [dict(path=r['path'], upstream=r['upstream_sha256'], candidate=r['candidate_sha256'])
             for r in value['files']]
    fixtures = {path: fixture.read_bytes() for path, fixture in pins.FIXTURES.items()}
    fragments = {name: (target, fragment.read_bytes()) for name, (target, fragment) in pins.FRAGMENTS.items()}

    def pins_checks(outputs, originals):
        checks = [{'name': 'fixture ' + PurePosixPath(path).name, 'path': path,
                   'result': 'pass' if outputs[path] == data else 'fail'} for path, data in fixtures.items()]
        checks += [{'name': 'fragment ' + name, 'path': target,
                    'result': 'pass' if outputs[target].count(data) == 1 else 'fail'}
                   for name, (target, data) in fragments.items()]
        return checks

    specs = [dict(name='native-principal-pins', project=pins.PROJECT, head=pins.HEAD, profile=pins.PROFILE,
                  patch=pins.PATCH, files=files, added=list(pins.ADDED), checks=pins_checks)]

    value = lifecycle.profile()
    methods = lifecycle.EXTRACTED.read_bytes()

    def lifecycle_checks(outputs, originals):
        try:
            same = lifecycle.extracted_methods(outputs[lifecycle.FILES[1]]) == methods
        except ValueError:
            same = False
        return [{'name': 'extracted CE methods', 'path': lifecycle.FILES[1], 'result': 'pass' if same else 'fail'}]

    specs.append(dict(name='owner-lifecycle', project=lifecycle.PROJECT, head=lifecycle.HEAD,
                      profile=lifecycle.PROFILE, patch=lifecycle.PATCH,
                      files=[dict(path=r['path'], upstream=r['upstream_sha256'], candidate=r['candidate_sha256'])
                             for r in value['files']], added=[lifecycle.ADDED], checks=lifecycle_checks))

    value = verity.profile()
    upstream_method, tested_method = verity.UPSTREAM_METHOD.read_bytes(), verity.EXTRACTED.read_bytes()

    def method(data):
        try:
            return verity.extracted_method(data)
        except (ValueError, UnicodeDecodeError):
            return None

    def verity_checks(outputs, originals):
        return [{'name': 'upstream method', 'path': verity.FILE,
                 'result': 'pass' if method(originals[verity.FILE]) == upstream_method else 'fail'},
                {'name': 'tested method', 'path': verity.FILE,
                 'result': 'pass' if method(outputs[verity.FILE]) == tested_method else 'fail'}]

    specs.append(dict(name='package-verity', project=verity.PROJECT, head=verity.HEAD, profile=verity.PROFILE,
                      patch=verity.PATCH, files=[dict(path=verity.FILE, upstream=value['upstream_sha256'],
                                                      candidate=value['candidate_sha256'])],
                      added=[], checks=verity_checks))

    value = payload.profile()
    base_regions = payload.tested_regions(payload.HOST_BASE_FRAGMENT)
    tested_regions = payload.tested_regions(payload.HOST_FRAGMENT)

    def payload_checks(outputs, originals):
        data, before = outputs[payload.FILE], originals[payload.FILE]
        return [{'name': 'host base fragment', 'path': payload.FILE,
                 'result': 'pass' if all(before.count(r) == 1 for r in base_regions) else 'fail'},
                {'name': 'host candidate fragment', 'path': payload.FILE,
                 'result': 'pass' if all(data.count(r) == 1 for r in tested_regions) else 'fail'},
                {'name': 'verity method kept', 'path': payload.FILE,
                 'result': 'pass' if method(data) == tested_method else 'fail'}]

    specs.append(dict(name='package-installer-payload-sync', project=payload.PROJECT, head=payload.HEAD,
                      profile=payload.PROFILE, patch=payload.PATCH, after='package-verity',
                      files=[dict(path=payload.FILE, upstream=value['base_sha256'],
                                  candidate=value['candidate_sha256'])], added=[], checks=payload_checks))

    value = writer.profile()
    specs.append(dict(name='native-identity-writer', project=writer.PROJECT, head=writer.HEAD,
                      profile=writer.PROFILE, patch=writer.PATCH, lab_only=True,
                      files=[dict(path=writer.FILE, upstream=value['file']['upstream_sha256'],
                                  candidate=value['file']['candidate_sha256'])],
                      added=[writer.ADDED], checks=lambda outputs, originals: []))

    profile = directory / 'owner-session-policy.json'
    value = load_json(profile)
    review = directory / value.get('patch', '')
    if (value.get('base_release') != base_tag or value.get('project') != policy.PROJECT
            or value.get('head') != policy.HEAD or value.get('file') != policy.FILE
            or value.get('upstream_sha256') != policy.BEFORE or review.parent != directory
            or not review.is_file() or value.get('patch_sha256') != sha(review.read_bytes())):
        raise CarryError('owner session policy profile drift')
    specs.append(dict(name='owner-session-policy', project=policy.PROJECT, head=policy.HEAD, profile=profile,
                      patch=review, method='policy bridge',
                      files=[dict(path=policy.FILE, upstream=policy.BEFORE, candidate=value['adapted_sha256'])],
                      added=[], checks=lambda outputs, originals: []))
    for spec in specs:
        spec.setdefault('after', None)
        spec.setdefault('lab_only', False)
        spec.setdefault('method', 'patch')
    return specs


def policy_bridge(original):
    """owner_policy.patched's anchored replacement without its pinned digest gate."""
    import owner_policy as policy
    text = original.decode('utf-8')
    counts = (text.count(policy.PREFIX), text.count(policy.ORIGINAL_EXEC_PREFIX),
              text.count(policy.ORIGINAL_DATA_PREFIX), text.count('allow ' + policy.CGROUP_SUBJECT + ' cgroup'))
    if counts != (1, 1, 1, 4):
        return None, counts
    text = text.replace(policy.PREFIX, policy.DECLARATIONS, 1)
    text = text.replace(policy.ORIGINAL_EXEC_PREFIX, policy.BRIDGE_EXEC_PREFIX, 1)
    text = text.replace(policy.ORIGINAL_DATA_PREFIX, policy.BRIDGE_DATA_PREFIX, 1)
    text = text.replace('allow ' + policy.CGROUP_SUBJECT + ' cgroup',
                        'allow ' + policy.CGROUP_BRIDGE_SUBJECT + ' cgroup')
    result = text.encode()
    if sha(original) == policy.BEFORE and result != policy.patched(original):
        raise CarryError('policy bridge mirror differs from owner_policy.patched')
    return result, counts


def policy_anchor_lines(original):
    import owner_policy as policy
    text = original.decode('utf-8')
    anchors = [policy.PREFIX, policy.ORIGINAL_EXEC_PREFIX, policy.ORIGINAL_DATA_PREFIX,
               'allow ' + policy.CGROUP_SUBJECT + ' cgroup']
    return [text.count('\n', 0, text.index(anchor)) + 1 if anchor in text else None for anchor in anchors]


# ---------------------------------------------------------------- applying and classifying

def parse_patch(text):
    """Per file hunks: old span, changed old lines and insertion points (1-based)."""
    files, path, lines, i = {}, None, text.split('\n'), 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('+++ '):
            path = line[4:].split('\t')[0]
            path = path[2:] if path.startswith('b/') else path
            files[path] = []
        elif line.startswith('@@ ') and path is not None:
            match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            if match is None:
                raise CarryError('malformed hunk header: ' + line)
            start, length = int(match.group(1)), int(match.group(2) or 1)
            new_length = int(match.group(4) or 1)
            old = start if length else start + 1
            removed, inserted, seen_old, seen_new = [], [], 0, 0
            i += 1
            while i < len(lines) and (seen_old < length or seen_new < new_length):
                body = lines[i]
                if body.startswith('\\'):
                    i += 1
                    continue
                if body.startswith('-'):
                    removed.append(old + seen_old)
                    seen_old += 1
                elif body.startswith('+'):
                    inserted.append(old + seen_old)
                    seen_new += 1
                else:
                    seen_old += 1
                    seen_new += 1
                i += 1
            span = (start, start + length - 1) if length else (start, start + 1)
            files[path].append({'span': span, 'edits': sorted(set(removed + inserted)) or [span[0]]})
            continue
        i += 1
    return files


def parse_patch_output(text):
    result, current = {}, None
    for line in text.splitlines():
        match = re.match(r'patching file (.+)$', line)
        if match:
            current = match.group(1).strip("'")
            result[current] = {'offsets': [], 'failed': [], 'reversed': False}
            continue
        if current is None:
            continue
        match = re.match(r'Hunk #(\d+) succeeded at (\d+)(?: \(offset (-?\d+) lines?\))?\.', line)
        if match and match.group(3):
            result[current]['offsets'].append([int(match.group(1)), int(match.group(3))])
        match = re.match(r'Hunk #(\d+) (?:FAILED|ignored)', line)
        if match:
            result[current]['failed'].append(int(match.group(1)))
        if 'Reversed (or previously applied) patch detected' in line:
            result[current]['reversed'] = True
    return result


def apply_patch(patch, files, workdir):
    """The tools' exact command in private scratch. Outputs only when every hunk applied."""
    root = Path(tempfile.mkdtemp(prefix='apply-', dir=workdir))
    try:
        for path, data in files.items():
            if data is not None:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        process = subprocess.run([*PATCH_COMMAND, '-i', str(patch)], cwd=root, capture_output=True,
                                 timeout=60, env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
        outcome = parse_patch_output(process.stdout.decode(errors='replace'))
        outputs = None
        if process.returncode == 0:
            produced = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
            if produced != {p for p, d in files.items() if d is not None} or any(
                    p.is_symlink() for p in root.rglob('*')):
                raise CarryError('unexpected patch output files')
            outputs = {path: (root / path).read_bytes() for path in files}
        return process.returncode, outcome, outputs
    finally:
        shutil.rmtree(root)


CONTROL = re.compile(r'(?:if|else|for|while|do|switch|try|catch|finally|synchronized|return|case|default|'
                     r'throw|new|yield|assert)\b')
ANNOTATION = re.compile(r'@[\w.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?')
METHOD = re.compile(r'\w\s*(?:<[^>]*>)?\s*\([^;]*\)\s*(?:throws\s+[\w.,\s<>]+)?$')


def _header_kind(header):
    """('type', text) for a type body, ('member', text) for a method, constructor or initializer."""
    text = re.sub(r'^\w+\s*:(?!:)\s*', '', ' '.join(ANNOTATION.sub(' ', header).split()))  # loop labels
    if re.search(r'\b(?:class|interface|enum|record)\s+\w', text) and not CONTROL.match(text) \
            and '=' not in text and 'new ' not in text:
        return 'type', text
    if not text or '->' in text or '=' in text or CONTROL.match(text) or text.endswith('new'):
        return None, text
    if text == 'static' or METHOD.search(text):
        return 'member', text
    return None, text


def java_members(text, declarations=False):
    """Approximate method, constructor and initializer spans: (first line, last line, header).

    With declarations, bodiless method declarations in a type body (abstract and interface
    methods) are included as single statement spans too.
    """
    spans, stack, header, line, i, n = [], [], [], 1, 0, len(text)
    header_line = None
    while i < n:
        c = text[i]
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = n if end < 0 else end
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = n if end < 0 else end + 2
            line += text.count('\n', i, end)
            i = end
            continue
        if text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end < 0 else end + 3
            line += text.count('\n', i, end)
            header.append('""')
            i = end
            continue
        if c in '"\'':
            j = i + 1
            while j < n and text[j] != c and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            header.append(c + c)
            i = j + 1
            continue
        if c == '\n':
            line += 1
            header.append(' ')
        elif c == '{':
            kind, signature = _header_kind(''.join(header))
            stack.append((kind, signature, header_line or line))
            header, header_line = [], None
        elif c == '}':
            if stack:
                kind, signature, start = stack.pop()
                if kind == 'member':
                    spans.append((start, line, signature))
            header, header_line = [], None
        elif c == ';':
            if declarations and stack and stack[-1][0] == 'type':
                kind, signature = _header_kind(''.join(header))
                if kind == 'member':
                    spans.append((header_line or line, line, signature))
            header, header_line = [], None
        else:
            if header_line is None and not c.isspace():
                header_line = line
            header.append(c)
        i += 1
    return spans


def upstream_changes(base, target):
    """Changed base line ranges (1-based, inclusive); an insertion is a point between lines.

    Lines split on newlines only, as GNU patch numbers them, not on form feeds.
    """
    a, b = base.decode('utf-8', 'replace').split('\n'), target.decode('utf-8', 'replace').split('\n')
    ranges = []
    for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == 'equal':
            continue
        ranges.append((i1 + 1, i2) if i2 > i1 else (i1, i1 + 1))
    return ranges


def overlaps(path, base, target, hunks):
    """Upstream edits beside an Andrix hunk or in a member an Andrix hunk edits."""
    changes = upstream_changes(base, target)
    members = java_members(base.decode('utf-8', 'replace')) if path.endswith('.java') else []
    found = []
    for number, hunk in enumerate(hunks, 1):
        first, last = hunk['span']
        # The innermost members that contain a line this hunk edits.
        owners = {(s, e, k) for s, e, k in members if any(s <= line <= e for line in hunk['edits'])}
        inner = [m for m in owners if not any(o != m and m[0] <= o[0] and o[1] <= m[1] for o in owners)]
        for start, end in changes:
            if start <= last + ADJACENT and end >= first - ADJACENT:
                found.append({'hunk': number, 'reason': 'adjacent', 'upstream_lines': [start, end]})
                continue
            for s, e, kind in inner:
                if start <= e and end >= s:
                    found.append({'hunk': number, 'reason': 'same member', 'member': kind[:120],
                                  'upstream_lines': [start, end]})
    return found


def classify(base, target, outcome, found, failed_check):
    """One target file: missing, conflict, identical, overlap, moved or changed clean."""
    if target is None:
        return 'missing'
    if outcome is None or outcome['failed'] or outcome['reversed']:
        return 'conflict'
    if base == target:
        return 'identical'
    if found or failed_check:
        return 'overlap'
    return 'moved' if outcome['offsets'] else 'changed clean'


def worst(classes):
    return max(classes, key=CLASSES.index) if classes else 'identical'


def apply_spec(spec, inputs, workdir):
    """(per file outcome, outputs only if every hunk applied, extra facts) for one input set."""
    if spec['method'] != 'policy bridge':
        _, outcome, outputs = apply_patch(spec['patch'], inputs, workdir)
        return outcome, outputs, {}
    outcome, outputs, extra = {}, {}, {}
    for path, data in inputs.items():
        if data is None:
            outputs[path] = None
            continue
        result, counts = policy_bridge(data)
        outputs[path] = result
        outcome[path] = {'offsets': [], 'failed': [] if result is not None else ['anchors'], 'reversed': False}
        _, _, review = apply_patch(spec['patch'], {path: data}, workdir)
        extra[path] = {'anchor_lines': policy_anchor_lines(data), 'anchor_counts': list(counts),
                       'review_record': 'agrees' if review is not None and result is not None
                       and review[path] == result else 'stale'}
    return outcome, outputs if all(v is not None for v in outputs.values()) else None, extra


def carry_patch(spec, base_inputs, target_inputs, workdir):
    """One exact patch: positive control on its base, then the target. Returns the report row
    and both output sets; the target outputs are None unless every hunk applied."""
    hunks = parse_patch(Path(spec['patch']).read_text())
    _, base_out, base_extra = apply_spec(spec, base_inputs, workdir)
    if base_out is None or any(sha(base_inputs[row['path']]) != row['upstream']
                               or sha(base_out[row['path']]) != row['candidate'] for row in spec['files']):
        raise CarryError('positive control failed: %s does not reproduce its pinned candidate' % spec['name'])
    if any(check['result'] != 'pass' for check in spec['checks'](base_out, base_inputs)):
        raise CarryError('positive control failed: %s checks fail at its own base' % spec['name'])
    outcome, outputs, extra = apply_spec(spec, target_inputs, workdir)
    checks = spec['checks'](outputs, target_inputs) if outputs is not None else \
        [{'name': 'tool checks', 'path': None, 'result': 'not run: the patch does not apply'}]
    failed = {check['path'] for check in checks if check['result'] == 'fail'}
    files = []
    for row in spec['files']:
        path = row['path']
        base, target, result = base_inputs[path], target_inputs[path], outcome.get(path)
        if spec['method'] == 'policy bridge' and result is not None and extra[path]['anchor_lines'] \
                != base_extra[path]['anchor_lines']:
            result['offsets'] = [[n + 1, (after or 0) - (before or 0)] for n, (before, after) in enumerate(
                zip(base_extra[path]['anchor_lines'], extra[path]['anchor_lines'])) if before != after]
        found = overlaps(path, base, target, hunks.get(path, [])) if target is not None and base != target \
            and result is not None and not result['failed'] else []
        cls = classify(base, target, result, found, path in failed)
        entry = {'path': path, 'class': cls, 'base_sha256': sha(base),
                 'target_sha256': sha(target) if target is not None else None,
                 'offsets': result['offsets'] if result else [],
                 'pinned_candidate_sha256': row['candidate'],
                 'candidate_sha256': sha(outputs[path]) if outputs is not None else None}
        if result and result['failed']:
            entry['failed_hunks'] = result['failed']
        if result and result['reversed']:
            entry['note'] = 'reversed or previously applied hunks. --forward refused them'
        if found:
            entry['overlaps'] = found
        if path in extra:
            entry['review_record'] = extra[path]['review_record']
            entry['review_record_at_base'] = base_extra[path]['review_record']
        if cls == 'identical' and entry['candidate_sha256'] not in (row['candidate'], None):
            raise CarryError('identical input produced a different candidate: ' + path)
        files.append(entry)
    row = {'name': spec['name'], 'project': spec['project'], 'lab_only': spec['lab_only'],
           'method': spec['method'] if spec['method'] != 'patch' else ' '.join(PATCH_COMMAND),
           'profile': repo_path(spec['profile']), 'profile_sha256': sha(Path(spec['profile']).read_bytes()),
           'patch': repo_path(spec['patch']), 'patch_sha256': sha(Path(spec['patch']).read_bytes()),
           'applies': outputs is not None, 'class': worst([f['class'] for f in files]),
           'files': files, 'checks': checks}
    return row, base_out, outputs


# ---------------------------------------------------------------- history and trailers

def trailers(message):
    lines = message.splitlines()
    change_ids = CHANGE_ID.findall(message)
    info = re.findall(r'^CVE-Info:\s*(.+?)\s*$', message, re.M)
    return {'subject': lines[0] if lines else '',
            'change_id': change_ids[-1] if change_ids else None,
            'cves': sorted(set(CVE.findall(message))),
            'cve_info': info,
            'cve_fix_flag': bool(re.search(r'^Flag:\s*EXEMPT\s+CVE_FIX\b', message, re.M)),
            'cherrypick_from': re.findall(r'^Cherrypick-From:\s*(\S+)\s*$', message, re.M),
            'cherry_picked_from': re.findall(r'^\(cherry picked from commit ([0-9a-f]{40})\)\s*$', message, re.M),
            'merged_in': re.findall(r'^Merged-In:\s*(I[0-9a-f]{40})\s*$', message, re.M)}


def history(git, url, base, target, base_tag, tracked, base_tree):
    """Commits in base..target with trailers and the tracked paths each changed."""
    store = git.store(url, 'history')
    remote = git.ls_remote(url, ['refs/tags/%s^{}' % base_tag])
    if remote.get('refs/tags/%s^{}' % base_tag) == base:
        store.fetch([target], exclude='refs/tags/' + base_tag)
        bound = 'excluding refs/tags/' + base_tag
    else:
        time = git.store(url).commits([base])[base]['time']
        store.fetch([target], since=str(time - 1))
        bound = 'since the base commit time'
    commits = store.walk(target, base)
    if commits is None:
        return {'complete': False, 'bound': bound,
                'not_run': 'the fetched range does not reach the base. History may be rewritten'}
    roots = {c['oid']: c['tree'] for c in commits}
    roots[base] = base_tree
    entries = store.resolve(roots, tracked)
    rows = []
    for commit in commits:
        parent = commit['parents'][0] if commit['parents'] else None
        touched = [p for p in tracked if parent is None or entries[commit['oid']][p] != entries.get(parent, {}).get(p)]
        found = trailers(commit['message'])
        found['cherrypick_from'] = [url.rsplit(':', 1)[-1] if url.startswith(CHERRYPICK_PREFIX) else url
                                    for url in found['cherrypick_from']]
        found['merged_in'] = [m for m in found['merged_in'] if m != found['change_id']]
        row = {'commit': commit['oid'][:12], **found}
        row = {key: value for key, value in row.items() if value not in ([], None, False)}
        if touched:
            row['touches'] = touched
        rows.append(row)
    return {'complete': True, 'bound': bound, 'range': '%s..%s' % (base[:12], target[:12]),
            'cherrypick_from_form': 'googleplex-android-review commit hash',
            'count': len(rows), 'with_cve': sum(1 for r in rows if 'cves' in r or 'cve_fix_flag' in r),
            'with_cherrypick': sum(1 for r in rows if 'cherrypick_from' in r or 'cherry_picked_from' in r),
            'commits': rows}


def touching(history_value, path):
    """The commits of a history that changed one tracked path, briefly."""
    rows = []
    for row in history_value.get('commits', []):
        if path in row.get('touches', []):
            brief = {'commit': row['commit'], 'subject': row['subject'][:100]}
            brief.update({key: row[key] for key in ('change_id', 'cves') if key in row})
            rows.append(brief)
    return rows


# ---------------------------------------------------------------- dependency surface

def load_surface(path=SURFACE):
    """The declared dependency surface. Runtime rows must cite repository evidence that exists.

    Each runtime row names a file and line in this repository and a term that line contains,
    so a reason cannot silently point at nothing.
    """
    value = load_json(path)
    if value.get('schema') != SCHEMA['surface'] or set(value) != {'schema', 'projects', 'paths', 'runtime'}:
        raise CarryError('invalid dependency surface declaration')
    for row in value['projects']:
        if set(row) != {'project', 'reason'}:
            raise CarryError('invalid surface project row')
    for row in value['paths']:
        if set(row) != {'project', 'path', 'reason'}:
            raise CarryError('invalid surface path row')
        source.relative(row['path'])
    for row in value['runtime']:
        if set(row) != {'project', 'path', 'reason', 'evidence', 'cites'}:
            raise CarryError('invalid surface runtime row')
        source.relative(row['path'])
        cited, _, line = row['evidence'].rpartition(':')
        try:
            lines = (ROOT / source.relative(cited)).read_text().split('\n')  # a repository path only
        except (source.SourceError, OSError):
            lines = []
        if not line.isdigit() or not 1 <= int(line) <= len(lines) or row['cites'] not in lines[int(line) - 1]:
            raise CarryError('runtime surface evidence does not cite %s: %s' % (row['cites'], row['evidence']))
    projects = {row['project'] for row in value['projects']}
    if not {row['project'] for row in value['paths'] + value['runtime']} <= projects:
        raise CarryError('surface path in a project that is not watched')
    return value


def surface_rows(surface):
    """Declared paths and runtime paths as one list, each tagged with its list."""
    return ([{'project': r['project'], 'path': r['path'], 'list': 'paths'} for r in surface['paths']]
            + [{'project': r['project'], 'path': r['path'], 'list': 'runtime'} for r in surface['runtime']])


def signatures(data):
    return {kind for _, _, kind in java_members(data.decode('utf-8', 'replace'), declarations=True)}


def surface_side(git, http, manifest, project, revision, paths):
    """(content reader, {path: (object, 'blob' or 'tree') or None}) for one project revision."""
    url = project_url(manifest, project)
    if urllib.parse.urlsplit(url).hostname in GITILES_HOSTS:
        entries = gitiles_entries(http, url, revision, paths)
        return (lambda path, oid: gitiles_files(http, url, revision, [path])[path][1],
                {p: e and (e['id'], 'tree' if e['type'] == 'tree' else 'blob') for p, e in entries.items()})
    store = git.store(url)
    tree = store.commits([revision])[revision]['tree']
    entries = store.resolve({revision: tree}, paths)[revision]
    return (lambda path, oid: store.blobs([oid])[oid],
            {p: e and (e[1], 'tree' if e[0] == '40000' else 'blob') for p, e in entries.items()})


def surface_paths(git, http, rows, base_manifest, target_manifest, histories):
    """Declared and runtime dependency paths compared by object ID at base and target.

    Every path must exist at the base, also in an unchanged project. A changed project's paths
    are compared by object ID. Changed Java files are fetched as single blobs so that added and
    removed member signatures show API drift that host stubs would hide.
    """
    result, by_project = [], {}
    for row in rows:
        by_project.setdefault(row['project'], []).append(row)
    for project, items in sorted(by_project.items()):
        old, new = base_manifest['projects'].get(project), target_manifest['projects'].get(project)
        if old is None:
            raise CarryError('surface project absent at base: ' + project)
        paths = sorted({row['path'] for row in items})
        changed = new is not None and new['revision'] != old['revision']
        sides = {'base': surface_side(git, http, base_manifest, project, old['revision'], paths)}
        if changed:
            sides['target'] = surface_side(git, http, target_manifest, project, new['revision'], paths)
        for row in items:
            path = row['path']
            before = sides['base'][1][path]
            if before is None:
                raise CarryError('declared surface path absent at base: %s/%s' % (project, path))
            entry = {'project': project, 'path': path, 'list': row['list']}
            if not changed:
                entry.update({'class': 'missing' if new is None else 'identical', 'base_object': before[0],
                              'note': 'project removed' if new is None else 'project revision unchanged'})
                result.append(entry)
                continue
            after = sides['target'][1][path]
            entry.update({'class': 'missing' if after is None else 'identical' if before[0] == after[0]
                          else 'changed', 'base_object': before[0], 'target_object': after[0] if after else None})
            if entry['class'] == 'changed' and path.endswith('.java') and before[1] == after[1] == 'blob':
                old_api = signatures(sides['base'][0](path, before[0]))
                new_api = signatures(sides['target'][0](path, after[0]))
                if new_api - old_api:
                    entry['api_added'] = sorted(new_api - old_api)
                if old_api - new_api:
                    entry['api_removed'] = sorted(old_api - new_api)
            if entry['class'] == 'changed' and project in histories:
                entry['upstream_commits'] = touching(histories[project], path)
            result.append(entry)
    return result


# ---------------------------------------------------------------- security ledger

class BulletinTables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows, self.level, self.component = [], None, None
        self._heading, self._text, self._row, self._cell = None, [], None, None

    def handle_starttag(self, tag, attrs):
        if tag in ('h2', 'h3'):
            self._heading, self._text = tag, []
        elif tag == 'tr':
            self._row = []
        elif tag == 'td' and self._row is not None:
            self._cell = {'text': [], 'links': []}
        elif tag == 'a' and self._cell is not None:
            href = dict(attrs).get('href')
            if href:
                self._cell['links'].append(href)

    def handle_endtag(self, tag):
        if tag == self._heading:
            text = ' '.join(''.join(self._text).split())
            if tag == 'h2':
                self.level = text
            else:
                self.component = text
            self._heading = None
        elif tag == 'td' and self._cell is not None and self._row is not None:
            self._row.append(self._cell)
            self._cell = None
        elif tag == 'tr' and self._row is not None:
            if self._row:
                self.rows.append((self.level, self.component, self._row))
            self._row = None

    def handle_data(self, data):
        if self._heading:
            self._text.append(data)
        if self._cell is not None:
            self._cell['text'].append(data)


def _cell(cell):
    return ' '.join(''.join(cell['text']).split())


def bulletin_fixes(data, bulletin, aosp_project=LEDGER_AOSP_PROJECT, version='17'):
    """Rows of one bulletin that link this AOSP project and name this Android version."""
    parser = BulletinTables()
    parser.feed(data.decode('utf-8', 'replace'))
    link = re.compile(r'^https://android\.googlesource\.com/%s/\+/([0-9a-f]{40})\b' % re.escape(aosp_project))
    rows = []
    for _, component, cells in parser.rows:
        if len(cells) != 5 or not CVE.fullmatch(_cell(cells[0])):
            continue
        if version not in [v.strip() for v in _cell(cells[4]).split(',')]:
            continue
        commits = [m.group(1) for m in (link.match(href) for href in cells[1]['links']) if m]
        if commits:
            rows.append({'cve': _cell(cells[0]), 'commits': commits, 'type': _cell(cells[2]),
                         'severity': _cell(cells[3]), 'bulletin': bulletin, 'component': component})
    return rows


def bulletin_months(data):
    return sorted(set(re.findall(r'/docs/security/bulletin/(\d{4}/\d{4}-\d{2}-01)\b', data.decode('utf-8', 'replace'))))


def preview_lists(data, tags):
    """GrapheneOS security preview CVE lists for exact release tags. Not public source.

    The lists cover the whole OS. Their fixes have no public commit, so no project is named.
    """
    text = data.decode('utf-8', 'replace')
    result = {}
    for match in re.finditer(r'<article id=["\']?(\d{10})["\']?>(.*?)</article>', text, re.S):
        tag, body = match.groups()
        if tag not in tags:
            continue
        found = re.search(r'included in the (\d{10}) security preview release\.\s*List of additional fixed CVEs:'
                          r'\s*</p>\s*<ul>(.*?)</ul>', body, re.S)
        if found:
            lists = {}
            for severity, items in re.findall(r'<li>\s*([A-Za-z]+):\s*(.*?)</li>', found.group(2), re.S):
                lists[severity] = CVE.findall(items)
            result[tag] = {'preview': found.group(1), 'cves': lists}
    return result


def security_branch(aosp_revision):
    match = re.fullmatch(r'refs/tags/android-(\d+)\.\d+\.\d+_r\d+', aosp_revision or '')
    if match is None:
        raise CarryError('cannot name the AOSP security branch for ' + str(aosp_revision))
    return 'android%s-security-release' % match.group(1)


def load_backports(path=BACKPORTS):
    if not Path(path).exists():
        return []
    value = load_json(path)
    if value.get('schema') != SCHEMA['backports'] or set(value) != {'schema', 'backports'}:
        raise CarryError('invalid backport declaration')
    for row in value['backports']:
        if set(row) != {'release', 'change_id', 'patch'} or not (ROOT / row['patch']).is_file():
            raise CarryError('invalid backport row')
    return value['backports']


def ledger_paths(specs, surface):
    targets = sorted({row['path'] for spec in specs if spec['project'] == LEDGER_PROJECT for row in spec['files']})
    added = sorted({path for spec in specs if spec['project'] == LEDGER_PROJECT for path in spec['added']})
    watched = sorted({row['path'] for row in surface_rows(surface) if row['project'] == LEDGER_PROJECT})
    return targets, added, watched


def _within(path, prefixes):
    return [p for p in prefixes if path == p or path.startswith(p + '/')]


# A fix's own diff, tried against a base's files: dry run only, never fuzz above 0.
DRY_RUN = (*PATCH_COMMAND, '--dry-run')
REGULAR = ('100644', '100755')


def _safe(path):
    try:
        source.relative(path)
        return True
    except source.SourceError:
        return False


def split_diff(data):
    """File sections of a git diff, each with its paths and why patch cannot check it, if so."""
    sections, current = [], []
    for line in data.splitlines(keepends=True):
        if line.startswith(b'diff --git ') and current:
            sections.append(b''.join(current))
            current = []
        current.append(line)
    if current:
        sections.append(b''.join(current))
    result = []
    for section in sections:
        names = {}
        for marker, prefix in ((b'--- ', b'a/'), (b'+++ ', b'b/')):
            found = re.search(rb'^' + re.escape(marker) + rb'(.+?)\t?$', section, re.M)
            if found:
                name = found.group(1)
                names[marker] = None if name == b'/dev/null' else \
                    name[2:].decode('utf-8', 'surrogateescape') if name.startswith(prefix) else None
        header = re.match(rb'diff --git a/(\S+) b/(\S+)', section)
        path = names.get(b'+++ ') or names.get(b'--- ') or \
            (header.group(2).decode('utf-8', 'surrogateescape') if header else '?')
        if not all(_safe(name) for name in [path, *[n for n in names.values() if n]]):
            skip = 'unsafe path'  # a path from a remote document must stay inside the scratch tree
        elif re.search(rb'^(?:GIT binary patch|Binary files .* differ)$', section, re.M):
            skip = 'binary'
        elif re.search(rb'^(?:rename|copy) (?:from|to) ', section, re.M):
            skip = 'rename or copy'
        elif not re.search(rb'^@@ ', section, re.M):
            skip = 'no text hunks'
        elif b'"' in section.split(b'\n@@', 1)[0]:
            skip = 'quoted path'
        else:
            skip = None
        result.append({'path': path, 'paths': sorted({n for n in names.values() if n}), 'text': section,
                       'skip': skip})
    return result


def content_state(sections, files, workdir):
    """(state, per file results, skipped files) for one fix's own diff at one base.

    Each text file section is tried forward and in reverse at fuzz 0, dry run only, against
    the base's own bytes in scratch. Reverse clean for every file is present, forward clean
    for every file is absent. Anything else is unresolved and is never guessed.
    """
    found, skipped = {}, {}
    for section in sections:
        if section['skip']:
            skipped[section['path']] = section['skip']
            continue
        root = Path(tempfile.mkdtemp(prefix='content-', dir=workdir))
        try:
            tree = root / 'tree'
            tree.mkdir()
            for path in section['paths']:
                if files.get(path) is not None:
                    target = tree / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(files[path])
            diff = root / 'own.diff'
            diff.write_bytes(section['text'])
            ways = {}
            for way, extra in (('forward', ()), ('reverse', ('-R',))):
                process = subprocess.run([*DRY_RUN, *extra, '-i', str(diff)], cwd=tree, capture_output=True,
                                         timeout=60, env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
                ways[way] = process.returncode == 0
        finally:
            shutil.rmtree(root)
        found[section['path']] = ('both' if ways['forward'] and ways['reverse'] else 'present' if ways['reverse']
                                  else 'absent' if ways['forward'] else 'neither')
    values = set(found.values())
    state = 'present' if values == {'present'} else 'absent' if values == {'absent'} else 'unresolved'
    return state, found, skipped


def tree_changes(store, old, new):
    """(path, old entry, new entry) for every changed non tree entry, fetching differing trees only."""
    changes, level = [], [('', old, new)]
    while level:
        store.listings(sorted({tree for _, a, b in level for tree in (a, b) if tree}))
        following = []
        for prefix, a, b in level:
            left, right = (store.trees[a] if a else {}), (store.trees[b] if b else {})
            for name in sorted(set(left) | set(right)):
                x, y = left.get(name), right.get(name)
                if x == y:
                    continue
                tree_x = x[1] if x and x[0] == '40000' else None
                tree_y = y[1] if y and y[0] == '40000' else None
                if tree_x or tree_y:
                    following.append((prefix + name + '/', tree_x, tree_y))
                if (x and not tree_x) or (y and not tree_y):
                    changes.append((prefix + name, None if tree_x else x, None if tree_y else y))
        level = following
    return changes


def commit_diff(store, commit, workdir):
    """A GrapheneOS commit's own diff against its first parent, rebuilt from single objects."""
    parent = commit['parents'][0]
    changes = tree_changes(store, store.commits([parent])[parent]['tree'], commit['tree'])
    data = store.blobs([e[1] for _, a, b in changes for e in (a, b) if e and e[0] in REGULAR])
    parts = []
    root = Path(tempfile.mkdtemp(prefix='commit-diff-', dir=workdir))
    try:
        for path, a, b in changes:
            name = path.encode('utf-8', 'surrogateescape')
            header = b'diff --git a/%s b/%s\n' % (name, name)
            if any(e and e[0] not in REGULAR for e in (a, b)):
                parts.append(header + b'(not a regular file)\n')
                continue
            old, new = (data[a[1]] if a else b''), (data[b[1]] if b else b'')
            if b'\0' in old or b'\0' in new:
                parts.append(header + b'Binary files a/%s and b/%s differ\n' % (name, name))
                continue
            (root / 'old').write_bytes(old)
            (root / 'new').write_bytes(new)
            process = subprocess.run(['/usr/bin/diff', '-u', '--label', 'a/' + path if a else '/dev/null',
                                      '--label', 'b/' + path if b else '/dev/null', str(root / 'old'),
                                      str(root / 'new')], capture_output=True, timeout=60,
                                     env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
            if process.returncode not in (0, 1):
                raise CarryError('diff failed for ' + path)
            parts.append(header + process.stdout)
    finally:
        shutil.rmtree(root)
    return b''.join(parts)


# The order in which evidence decides a status. The method names the evidence that decided.
METHODS = ('change_id', 'content', 'backport', 'merged_in', 'cve')


def decide(evidence):
    """(status, method) for one fix at one base, from evidence gathered by every method."""
    if evidence['change_id']:
        return 'present', 'change_id'
    if evidence['content'] == 'present':
        return 'present', 'content'
    if evidence['backport']:
        return 'backported', 'backport'
    if evidence['merged_in']:
        return 'backported', 'merged_in'
    if evidence['cve']:
        return 'backported', 'cve'
    if evidence['content'] == 'absent':
        return 'absent', 'content'
    if evidence['later']:
        return 'absent', 'change_id'
    return 'unresolved', 'content'


def disagreement(status, method, evidence):
    """Why the content check contradicts the deciding method, if it does."""
    content = evidence['content']
    if method == 'content':
        return 'its Change-Id lands only in a later base' if content == 'present' and evidence['later'] else None
    if method == 'backport':
        return None  # an Andrix patch carries it on top of the base, so the base files lack it
    if status in ('present', 'backported') and content == 'absent':
        return 'the content check finds the change absent'
    if status == 'absent' and content == 'present':
        return 'the content check finds the change present'
    return None


def build_ledger(git, http, records, specs, surface, backports, workdir, aosp_url=None):
    """Security fixes for frameworks/base keyed by Change-Id, with a status per base record.

    Every fix is also checked by content: its own diff, from the AOSP security branch or from
    its GrapheneOS commit, is tried against each base's files at fuzz 0 as a dry run. The
    method behind each status is recorded, and any contradiction between methods is listed.
    """
    records = sorted(records, key=lambda r: r['release'])
    aosp = {r['aosp_default_revision'] for r in records}
    urls = {r['patched_projects'][LEDGER_PROJECT]['url'] for r in records}
    if len(aosp) != 1 or len(urls) != 1:
        raise CarryError('ledger bases must share one AOSP release and one project URL')
    aosp_ref, url = aosp.pop(), urls.pop()
    aosp_url = aosp_url or 'https://android.googlesource.com/' + LEDGER_AOSP_PROJECT
    branch = security_branch(aosp_ref)
    refs = git.ls_remote(aosp_url, [aosp_ref + '^{}', 'refs/heads/' + branch])
    if set(refs) != {aosp_ref + '^{}', 'refs/heads/' + branch}:
        raise CarryError('AOSP base tag or security branch not found')
    aosp_base, branch_head = refs[aosp_ref + '^{}'], refs['refs/heads/' + branch]
    targets, added, watched = ledger_paths(specs, surface)

    # GrapheneOS commit metadata from the AOSP base to each base record, bounded by date.
    store = git.store(url, 'ledger')
    base_time = store.commits([aosp_base])[aosp_base]['time']
    tips = [r['patched_projects'][LEDGER_PROJECT]['revision'] for r in records]
    store.fetch(tips, since=str(base_time - 1))
    members, gos, newest = {}, {}, []
    for record, tip in zip(records, tips):
        commits = store.walk(tip, aosp_base)
        if commits is None:
            raise NotRun('GrapheneOS history for %s does not reach the AOSP base' % record['release'])
        members[record['release']] = {c['oid'] for c in commits}
        gos.update({c['oid']: c for c in commits})
        newest = [c['oid'] for c in commits]
    info = {oid: trailers(commit['message']) for oid, commit in gos.items()}

    # AOSP: bulletins published since the AOSP base month, then the security branch log.
    # Bulletin pages carry per request nonces. Each source records the digest of the
    # canonical JSON extracted from it, not of the page bytes.
    overview = http.get(BULLETINS + 'asb-overview')
    first = datetime.datetime.fromtimestamp(base_time, datetime.timezone.utc).strftime('%Y-%m')
    months = [m for m in bulletin_months(overview) if m.split('/')[1][:7] >= first]
    sources = [{'id': 'asb-overview', 'url': BULLETINS + 'asb-overview', 'months': len(months),
                'extract_sha256': sha(canonical(months))}]
    rows = []
    for month in months:
        found = bulletin_fixes(http.get(BULLETINS + month), month.split('/')[1])
        sources.append({'id': 'asb-' + month.split('/')[1], 'url': BULLETINS + month, 'rows': len(found),
                        'extract_sha256': sha(canonical(found))})
        rows += found
    log_url = '%s/+log/%s..refs/heads/%s?format=JSON&n=1000&name-status=1' % (aosp_url, aosp_base, branch)
    log = gitiles_json(http.get(log_url))
    if log.get('next'):
        raise NotRun('AOSP security branch log is longer than one page')
    sources.append({'id': 'aosp-security-branch', 'url': log_url, 'head': branch_head,
                    'commits': len(log['log']), 'extract_sha256': sha(canonical(log))})
    aosp_commits = {c['commit']: c for c in log['log'] if len(c['parents']) == 1}
    on_branch = set(aosp_commits)
    for row in rows:
        for oid in row['commits']:
            if oid not in aosp_commits:
                commit_url = '%s/+/%s?format=JSON' % (aosp_url, oid)
                aosp_commits[oid] = gitiles_json(http.get(commit_url))
                sources.append({'id': 'aosp-commit-' + oid[:12], 'url': commit_url,
                                'extract_sha256': sha(canonical(aosp_commits[oid]))})

    fixes = {}

    def fix(key, subject):
        item = fixes.setdefault(key, {'subject': subject, 'cves': [], 'aosp': [], 'branch': False,
                                      'files': set(), 'flags': set()})
        item['subject'] = item['subject'] or subject
        return item

    for oid, commit in aosp_commits.items():
        found = trailers(commit['message'])
        if found['change_id'] is None:
            raise CarryError('AOSP security commit without Change-Id: ' + oid)
        item = fix(found['change_id'], found['subject'])
        item['aosp'].append(oid)
        item['branch'] |= oid in on_branch
        item['files'] |= {d['old_path'] if d['new_path'] == '/dev/null' else d['new_path']
                          for d in commit.get('tree_diff', [])}
    for row in rows:
        for oid in row['commits']:
            item = fixes[trailers(aosp_commits[oid]['message'])['change_id']]
            cve = {'id': row['cve'], 'source': 'asb-' + row['bulletin'], 'type': row['type'],
                   'severity': row['severity']}
            if cve not in item['cves']:
                item['cves'].append(cve)

    # GrapheneOS commits: exact Change-Id matches, plus commits that carry their own CVE trailers.
    exact, related = {}, {}
    for oid, found in info.items():
        if found['change_id'] in fixes:
            exact.setdefault(found['change_id'], set()).add(oid)
        for other in found['merged_in']:
            if other in fixes and other != found['change_id']:
                related.setdefault(other, set()).add(oid)
        if found['change_id'] not in fixes and not any(m in fixes for m in found['merged_in']) \
                and (found['cves'] or found['cve_fix_flag']):
            key = found['change_id'] or 'grapheneos:' + oid
            fix(key, found['subject'])
            exact.setdefault(key, set()).add(oid)
    for key, oids in exact.items():
        for oid in oids:
            found = info[oid]
            for text in found['cve_info']:
                match = re.match(r'(CVE-\d{4}-\d{4,7})\s*\|\s*Severity:\s*(\w+)\s*\|\s*Type:\s*(\w+)', text)
                if match and not any(c['id'] == match.group(1) for c in fixes[key]['cves']):
                    fixes[key]['cves'].append({'id': match.group(1), 'source': 'grapheneos-trailer',
                                               'type': match.group(3), 'severity': match.group(2)})
            for cve in found['cves']:
                if not any(c['id'] == cve for c in fixes[key]['cves']):
                    fixes[key]['cves'].append({'id': cve, 'source': 'grapheneos-trailer'})
            if found['cve_fix_flag']:
                fixes[key]['flags'].add('Flag: EXEMPT CVE_FIX')
    by_cve = {}
    for oid, found in info.items():
        for cve in found['cves']:
            by_cve.setdefault(cve, set()).add(oid)

    # Tracked Andrix paths each GrapheneOS fix commit changes, walked by tree object.
    walked = sorted({oid for oids in exact.values() for oid in oids})
    roots = {oid: gos[oid]['tree'] for oid in walked}
    parents = {oid: gos[oid]['parents'][0] for oid in walked}
    roots.update({p: (gos[p] if p in gos else store.commits([p])[p])['tree'] for p in parents.values()})
    tracked = targets + added + watched
    resolved = store.resolve(roots, tracked) if walked else {}
    for key, oids in exact.items():
        for oid in oids:
            fixes[key]['files'] |= {p for p in tracked if resolved[oid][p] != resolved[parents[oid]][p]}

    # Each fix's own diff: its AOSP security branch commit through Gitiles, as one object,
    # or its newest GrapheneOS commit rebuilt from single Git objects.
    diffs, origin = {}, {}
    for key, item in fixes.items():
        branch_commits = [oid for oid in item['aosp'] if oid in on_branch] or item['aosp']
        if branch_commits:
            oid = branch_commits[0]
            encoded = http.get('%s/+/%s^!/?format=TEXT' % (aosp_url, oid))
            try:
                diffs[key] = base64.b64decode(encoded, validate=False)
            except ValueError as error:
                raise CarryError('undecodable Gitiles diff for ' + oid) from error
            origin[key] = 'aosp ' + oid[:12]
        else:
            oid = next(o for o in newest + sorted(gos) if o in exact[key])
            diffs[key] = commit_diff(store, gos[oid], workdir)
            origin[key] = 'grapheneos ' + oid[:12]
    sections = {key: split_diff(data) for key, data in diffs.items()}
    needed = sorted({path for parts in sections.values() for part in parts if not part['skip']
                     for path in part['paths']})
    base_files = {}
    for record in records:
        revision = record['patched_projects'][LEDGER_PROJECT]['revision']
        base_files[record['release']] = {path: entry[1] if entry else None
                                         for path, entry in store.files(revision, needed).items()}
    contents = {key: {r['release']: content_state(sections[key], base_files[r['release']], workdir)
                      for r in records} for key in fixes}

    declared = {(row['release'], row['change_id']): row['patch'] for row in backports}
    later_bases = {r['release']: set().union(*[members[o['release']] for o in records
                                               if o['release'] > r['release']]) for r in records}
    rendered, disagreements, unconfirmed = [], [], []
    for key, item in sorted(fixes.items(), key=lambda kv: (not kv[1]['aosp'], kv[0])):
        status = {}
        for record in records:
            release = record['release']
            same = exact.get(key, set()) & members[release]
            cve_hits = set().union(*[by_cve.get(c['id'], set()) for c in item['cves']])
            state, per_file, skipped = contents[key][release]
            evidence = {'change_id': same, 'content': state,
                        'later': (exact.get(key, set()) & later_bases[release]) - members[release],
                        'backport': declared.get((release, key)),
                        'merged_in': (related.get(key, set()) & members[release]) - same,
                        'cve': (cve_hits & members[release]) - same}
            verdict, method = decide(evidence)
            entry = {'status': verdict, 'method': method, 'content': state}
            if method == 'backport':
                entry['patch'] = evidence['backport']
            if method in ('merged_in', 'cve'):
                entry['via'] = sorted(o[:12] for o in evidence[method])
            if state == 'unresolved':
                entry['content_files'] = per_file
            if skipped:
                entry['content_skipped'] = skipped
            status[release] = entry
            conflict = disagreement(verdict, method, evidence)
            if conflict:
                disagreements.append({'change_id': key, 'release': release, 'status': verdict, 'method': method,
                                      'content': state, 'note': conflict})
            elif method != 'content' and state == 'unresolved':
                unconfirmed.append({'change_id': key, 'release': release, 'status': verdict, 'method': method,
                                    'content_files': per_file})
        sources_for = [name for name, test in (
            ('bulletin', any(c['source'].startswith('asb-') for c in item['cves'])),
            ('security_branch', item['branch']), ('grapheneos', bool(exact.get(key)))) if test]
        row = {'change_id': key, 'subject': (item['subject'] or '')[:100], 'sources': sources_for,
               'cves': item['cves'], 'flags': sorted(item['flags']), 'aosp': [o[:12] for o in item['aosp']],
               'grapheneos': sorted(o[:12] for o in exact.get(key, ())),
               'andrix_targets': sorted(p for p in item['files'] if p in targets or p in added),
               'andrix_surface': sorted({w for p in item['files'] for w in _within(p, watched)}),
               'content_from': origin[key], 'diff_sha256': sha(diffs[key])}
        rendered.append({k: v for k, v in row.items() if v != []} | {'status': status})

    # Possible matches by subject, for absent fixes only. A hint for review, never a status.
    subjects = {}
    for oid, found in info.items():
        subjects.setdefault(' '.join(found['subject'].lower().split()), []).append(oid)
    for row in rendered:
        key = ' '.join(row['subject'].lower().split())
        hints = {release: sorted(o[:12] for o in subjects.get(key, []) if o in members[release])
                 for release, entry in row['status'].items() if entry['status'] == 'absent'}
        hints = {release: hits for release, hits in hints.items() if hits}
        if hints:
            row['same_subject'] = hints

    lists = preview_lists(http.get(RELEASES), [r['release'] for r in records])
    sources.append({'id': 'grapheneos-releases', 'url': RELEASES, 'extract_sha256': sha(canonical(lists)),
                    'preview_lists_are_public_source': False})
    preview_rows = []
    for record in records:
        found = lists.get(record['release'])
        preview_rows.append({'release': record['release'], 'public_source': False,
                             'preview_release': found['preview'] if found else None,
                             'counts': {k: len(v) for k, v in found['cves'].items()} if found else {},
                             'cves': found['cves'] if found else {}})
    results = {r['release']: {state: sum(1 for key in fixes if contents[key][r['release']][0] == state)
                              for state in ('present', 'absent', 'unresolved')} for r in records}
    return {
        'schema': SCHEMA['ledger'],
        'project': LEDGER_PROJECT,
        'aosp': {'project': LEDGER_AOSP_PROJECT, 'base': aosp_ref, 'base_commit': aosp_base,
                 'security_branch': branch, 'security_branch_head': branch_head},
        'bases': [{'release': r['release'], 'record_sha256': sha(dump(r)),
                   'revision': r['patched_projects'][LEDGER_PROJECT]['revision'],
                   'security_patch_level': r['security_patch_level']['value'],
                   'grapheneos_commits_since_aosp_base': len(members[r['release']])} for r in records],
        'retrieved': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
        'rules': {
            'extract_sha256': 'SHA-256 of the canonical JSON the ledger extracted from a source.',
            'status': 'The first evidence that applies decides, in this order. A GrapheneOS commit with the '
                      'Change-Id in the base range is present by change_id. A clean reverse dry run of the '
                      'fix\'s own diff is present by content. A declared Andrix backport, a GrapheneOS commit '
                      'that names the Change-Id in Merged-In, or one that carries one of its CVEs is '
                      'backported by backport, merged_in or cve. A clean forward dry run is absent by content. '
                      'A Change-Id that lands only in a later base is absent by change_id. Anything else is '
                      'unresolved.',
            'content': 'The fix\'s own diff, from its AOSP security branch commit or its GrapheneOS commit, '
                       'tried against the base files at fuzz 0, dry run only. Reverse clean for every file is '
                       'present. Forward clean for every file is absent. Anything else is unresolved.',
            'disagreements': 'Cases where the content check contradicts the deciding method. They are listed, '
                             'never resolved silently.',
            'unconfirmed': 'Cases decided by another method where the content check is unresolved.',
            'preview': 'CVEs GrapheneOS lists as fixed only in the security preview build of a release. They '
                       'are OS wide and have no public commit, so they are absent from that base by necessity.',
            'same_subject': 'GrapheneOS commits with the same subject as an absent fix. A review hint only.',
            'andrix_targets': 'Paths an Andrix patch edits or adds that the AOSP commit or the GrapheneOS '
                              'commit changes. GrapheneOS commits are walked for tracked paths only.'},
        'content_check': {'command': ' '.join(DRY_RUN) + ' [-R] -i <own diff>',
                          'diffs': {'aosp': sum(1 for v in origin.values() if v.startswith('aosp')),
                                    'grapheneos': sum(1 for v in origin.values() if v.startswith('grapheneos'))},
                          'results': results, 'disagreements': disagreements, 'unconfirmed': unconfirmed},
        'sources': sources,
        'fixes': rendered,
        'preview': preview_rows,
    }


def validate_ledger(value):
    if not isinstance(value, dict) or value.get('schema') != SCHEMA['ledger'] or \
            value.get('project') != LEDGER_PROJECT or not isinstance(value.get('fixes'), list):
        raise CarryError('invalid ledger')
    return value


def ledger_summary(ledger, base, target):
    """Counts for the status line, from the ledger and only from it."""
    state = lambda fix, release: fix['status'].get(release, {}).get('status')
    absent = [f for f in ledger['fixes'] if state(f, base) == 'absent']
    check = ledger.get('content_check', {})
    return {'absent_at_base': len(absent),
            'bulletin_linked': sum(1 for f in absent if 'bulletin' in f['sources']),
            'security_branch_only': sum(1 for f in absent if 'bulletin' not in f['sources']
                                        and 'security_branch' in f['sources']),
            'grapheneos_only': sum(1 for f in absent if f['sources'] == ['grapheneos']),
            'unresolved_at_base': sum(1 for f in ledger['fixes'] if state(f, base) == 'unresolved'),
            'present_at_base': sum(1 for f in ledger['fixes'] if state(f, base) == 'present'),
            'in_patch_targets': sum(1 for f in absent if f.get('andrix_targets')),
            'in_patch_targets_bulletin_linked': sum(1 for f in absent if f.get('andrix_targets')
                                                    and 'bulletin' in f['sources']),
            'in_dependency_surface': sum(1 for f in absent if f.get('andrix_surface')),
            'present_at_target': sum(1 for f in absent if state(f, target) == 'present'),
            'absent_at_target': sum(1 for f in absent if state(f, target) == 'absent'),
            'content_disagreements': len(check.get('disagreements', [])),
            'content_unconfirmed': len(check.get('unconfirmed', [])),
            'preview_only_at_target': sum(sum(p['counts'].values()) for p in ledger.get('preview', [])
                                          if p['release'] == target)}


# ---------------------------------------------------------------- the carry report

def status_line(base, target, patches, summary):
    """The one line divergence status the plans and evidence register can quote."""
    files = [f for p in patches for f in p['files']]
    count = lambda c: sum(1 for f in files if f['class'] == c)
    if count('conflict') or count('missing'):
        carry = '%d conflicting and %d missing patch targets' % (count('conflict'), count('missing'))
    elif count('overlap'):
        carry = 'all patches apply at fuzz 0, %d targets overlap upstream changes' % count('overlap')
    elif count('moved'):
        carry = 'all patches apply at fuzz 0, %d targets with line offsets' % count('moved')
    else:
        carry = 'all patches apply clean'
    lab = ', %d of them lab only' % summary['in_lab_only_targets'] if summary.get('in_lab_only_targets') else ''
    open_ = ', %d unresolved by content' % summary['unresolved_at_base'] if summary.get('unresolved_at_base') else ''
    return ('base %s (patch level %s); latest %s (%s); %d known frameworks/base security fixes absent '
            '(%d bulletin linked, %d fixed in latest)%s, %d in Andrix patch targets%s; %s' % (
                base['release'], base['security_patch_level']['value'], target['release'],
                target['security_patch_level']['value'], summary['absent_at_base'], summary['bulletin_linked'],
                summary['present_at_target'], open_, summary['in_patch_targets'], lab, carry))


def seal(report):
    body = {key: value for key, value in report.items() if key != 'seal'}
    return {'algorithm': 'sha256 over canonical JSON of every other field', 'sha256': sha(canonical(body))}


def run_check(git, http, base_path, target_tag, signers, ledger_path, workdir, target_record_path=None,
              manifest_url=MANIFEST_URL, specs=None, surface=None):
    """The sealed carry report of one target release against one base record.

    Both records are derived again from their signed releases and must match. Every patch target
    and added path is read by blob at base and target, every patch is applied at fuzz 0 to both,
    and the dependency surface, commit trailers and ledger counts are joined into one report.
    """
    base = load_record(base_path)
    specs = load_patch_set(base['release']) if specs is None else specs
    surface = load_surface() if surface is None else surface
    patched = sorted({spec['project'] for spec in specs})
    for spec in specs:
        if base['patched_projects'][spec['project']]['revision'] != spec['head']:
            raise CarryError('patch set head differs from the base record: ' + spec['name'])
    derived_base, base_manifest, _ = derive_record(git, base['release'], signers, patched, manifest_url)
    if derived_base != base:
        raise CarryError('base record does not match its signed release')
    target, target_manifest, _ = derive_record(git, target_tag, signers, patched, manifest_url)
    if target_record_path is not None and load_record(target_record_path) != target:
        raise CarryError('target record does not match its signed release')
    ledger = validate_ledger(load_json(ledger_path))
    covered = {row['release']: row['record_sha256'] for row in ledger['bases']}
    for record in (base, target):
        if covered.get(record['release']) != sha(dump(record)):
            raise CarryError('ledger does not cover base record ' + record['release'])
    diff = manifest_diff(base_manifest, target_manifest)

    # Patch targets, added paths and surface paths in the patched projects, by blob.
    tracked, inputs = {}, {}
    for spec in specs:
        tracked.setdefault(spec['project'], set()).update(row['path'] for row in spec['files'])
        tracked[spec['project']].update(spec['added'])
    for row in surface_rows(surface):
        if row['project'] in tracked:
            tracked[row['project']].add(row['path'])
    histories, missing_projects = {}, []
    for project in patched:
        paths = sorted({row['path'] for spec in specs if spec['project'] == project for row in spec['files']}
                       | {p for spec in specs if spec['project'] == project for p in spec['added']})
        old = base_manifest['projects'][project]
        new = target_manifest['projects'].get(project)
        url = project_url(base_manifest, project)
        store = git.store(url)
        inputs[(project, 'base')] = store.files(old['revision'], paths)
        if new is None:
            missing_projects.append(project)
            inputs[(project, 'target')] = {p: None for p in paths}
            continue
        target_store = git.store(project_url(target_manifest, project))
        inputs[(project, 'target')] = target_store.files(new['revision'], paths)
        if new['revision'] != old['revision']:
            base_tree = store.commits([old['revision']])[old['revision']]['tree']
            histories[project] = history(git, project_url(target_manifest, project), old['revision'],
                                         new['revision'], base['release'], sorted(tracked[project]), base_tree)

    patches, outputs = [], {}
    for spec in specs:
        base_files, target_files = inputs[(spec['project'], 'base')], inputs[(spec['project'], 'target')]
        base_in = {row['path']: base_files[row['path']][1] for row in spec['files']}
        target_in = {row['path']: target_files[row['path']][1] if target_files[row['path']] else None
                     for row in spec['files']}
        if spec['after']:
            # An ordered companion starts from the exact outputs of the patch it follows.
            prior_base, prior_target = outputs[spec['after']]
            base_in = {p: prior_base[p] for p in base_in}
            if prior_target is None:
                patches.append({'name': spec['name'], 'project': spec['project'], 'lab_only': spec['lab_only'],
                                'profile': repo_path(spec['profile']), 'patch': repo_path(spec['patch']),
                                'applies': False, 'class': 'conflict', 'checks': [],
                                'files': [{'path': p, 'class': 'conflict', 'note': 'requires ' + spec['after']}
                                          for p in base_in]})
                outputs[spec['name']] = (base_in, None)
                continue
            target_in = {p: prior_target[p] for p in target_in}
        result, base_produced, produced = carry_patch(spec, base_in, target_in, workdir)
        outputs[spec['name']] = (base_produced, produced)
        for path in spec['added']:
            present = inputs[(spec['project'], 'target')].get(path) is not None
            result.setdefault('added', []).append({'path': path, 'upstream': 'exists' if present else 'absent'})
            if present:
                result['class'] = 'conflict'
        for entry in result['files']:
            if spec['project'] in histories and entry['class'] != 'identical':
                entry['upstream_commits'] = touching(histories[spec['project']], entry['path'])
        patches.append(result)

    surface_report = surface_paths(git, http, surface_rows(surface), base_manifest, target_manifest, histories)
    watched = []
    for row in surface['projects']:
        old, new = base_manifest['projects'].get(row['project']), target_manifest['projects'].get(row['project'])
        item = {'project': row['project'], 'base': old['revision'] if old else None,
                'target': new['revision'] if new else None}
        item['class'] = 'missing' if new is None else 'identical' if old and old['revision'] == new['revision'] \
            else 'changed'
        watched.append(item)
    kernels = sorted(set(base['kernel_prebuilts']) | set(target['kernel_prebuilts']))
    kernel_changed = [{'path': k, 'base': base['kernel_prebuilts'].get(k), 'target': target['kernel_prebuilts'].get(k)}
                      for k in kernels if base['kernel_prebuilts'].get(k) != target['kernel_prebuilts'].get(k)]
    summary = ledger_summary(ledger, base['release'], target['release'])
    lab_paths = {row['path'] for spec in specs if spec['lab_only'] for row in spec['files']}
    lab_paths |= {path for spec in specs if spec['lab_only'] for path in spec['added']}
    summary['in_lab_only_targets'] = sum(
        1 for f in ledger['fixes'] if f['status'].get(base['release'], {}).get('status') == 'absent'
        and f.get('andrix_targets') and set(f['andrix_targets']) <= lab_paths)
    classes = [f['class'] for p in patches for f in p['files']] + [p['class'] for p in patches]
    verdict = 'CONFLICT' if {'conflict', 'missing'} & set(classes) else \
        'REVIEW' if 'overlap' in classes else 'CARRIED'
    histories_out = {project: value for project, value in sorted(histories.items())}
    report = {
        'schema': SCHEMA['carry'],
        'base': {'release': base['release'], 'record': repo_path(base_path), 'record_sha256': sha(dump(base)),
                 'security_patch_level': base['security_patch_level']['value']},
        'target': {'release': target['release'], 'record_sha256': sha(dump(target)),
                   **({'record': repo_path(target_record_path)} if target_record_path else {}),
                   'security_patch_level': target['security_patch_level']['value'],
                   'tag_object': target['manifest']['tag_object'], 'manifest_commit': target['manifest']['commit'],
                   'manifest_sha256': target['manifest']['sha256']},
        'verdict': verdict,
        'status': status_line(base, target, patches, summary),
        'trust': {'signed_tags': 'git verify-tag with the pinned allowed signers file, for base and target',
                  'allowed_signers_sha256': source.SIGNERS_SHA256,
                  'objects': 'trees and blobs fetched one by one by object ID from the signed manifest commits',
                  'documents': 'bulletins, Gitiles JSON and release notes are trusted over HTTPS'},
        'manifest': diff,
        'watched_projects': watched,
        'kernel_prebuilts': {'count': len(kernels), 'kernel_changed': kernel_changed},
        'patches': patches,
        'surface': surface_report,
        'history': histories_out,
        'ledger': {'path': repo_path(ledger_path), 'sha256': sha(Path(ledger_path).read_bytes()), **summary},
        'limits': [
            'Source facts only. No build, boot or runtime result follows from this report.',
            'Fuzz 0 still accepts line offsets. Moved means a hunk landed at another line than reviewed.',
            'Overlap uses an approximate Java member parser and a %d line window. '
            'No overlap is not a semantic proof.' % ADJACENT,
            'Preview fixes listed by GrapheneOS are not public source and cannot be carried.',
            'The existing patch tools still refuse the target until a reviewed patch directory exists.',
        ],
        'generated': {'tool': 'scripts/proof/grapheneos_carry.py',
                      'tool_sha256': sha(Path(__file__).read_bytes()),
                      'at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
    }
    if missing_projects:
        report['not_run'] = ['patched project absent at target: ' + p for p in missing_projects]
    report['seal'] = seal(report)
    return report


def verify_report(path):
    report = load_json(path)
    if report.get('schema') != SCHEMA['carry'] or report.get('seal') != seal(report):
        raise CarryError('report seal does not verify')
    drift = []
    checked = [('base record', report['base']['record'], report['base']['record_sha256']),
               ('ledger', report['ledger']['path'], report['ledger']['sha256'])]
    if 'record' in report['target']:
        checked.append(('target record', report['target']['record'], report['target']['record_sha256']))
    for label, rel, digest in checked:
        file = ROOT / rel
        if not file.exists():
            actual = None
        elif label.endswith('record'):
            actual = sha(dump(load_json(file)))
        else:
            actual = sha(file.read_bytes())
        if actual != digest:
            drift.append(label + ' changed since the report: ' + rel)
    for patch in report['patches']:
        for key in ('profile', 'patch'):
            file = ROOT / patch[key]
            digest = patch.get(key + '_sha256')
            if digest and (not file.exists() or sha(file.read_bytes()) != digest):
                drift.append('%s %s changed since the report' % (key, patch[key]))
    return report, drift


# ---------------------------------------------------------------- command line

def scratch_dir(path):
    """(path, created). Scratch is outside the repository and starts new or empty."""
    path = Path(path).absolute()
    if path.resolve().is_relative_to(ROOT):
        raise CarryError('scratch must be outside the repository')
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise CarryError('scratch must be new or empty: ' + str(path))
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True)
    return path, created


def clear_scratch(path, created):
    if created:
        shutil.rmtree(path, ignore_errors=True)
        return
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    record = commands.add_parser('record', help='derive one base record from its signed release')
    record.add_argument('--tag', required=True)
    record.add_argument('--allowed-signers', required=True, type=Path)
    record.add_argument('--scratch', required=True, type=Path)
    group = record.add_mutually_exclusive_group(required=True)
    group.add_argument('--out', type=Path)
    group.add_argument('--verify', type=Path)
    ledger = commands.add_parser('ledger', help='build the frameworks/base security ledger')
    ledger.add_argument('--base', required=True, type=Path, action='append')
    ledger.add_argument('--scratch', required=True, type=Path)
    ledger.add_argument('--out', required=True, type=Path)
    ledger.add_argument('--replace', action='store_true')
    check = commands.add_parser('check', help='write a sealed carry report for a target release')
    check.add_argument('--base', required=True, type=Path)
    check.add_argument('--target-tag', required=True)
    check.add_argument('--target-record', type=Path)
    check.add_argument('--allowed-signers', required=True, type=Path)
    check.add_argument('--ledger', required=True, type=Path)
    check.add_argument('--scratch', required=True, type=Path)
    check.add_argument('--out', required=True, type=Path)
    for name in ('verify', 'status'):
        command = commands.add_parser(name, help='%s a sealed carry report' % name)
        command.add_argument('report', type=Path)
    args = parser.parse_args(argv)
    os.umask(0o022)
    scratch = created = None
    try:
        if args.command in ('verify', 'status'):
            report, drift = verify_report(args.report)
            if args.command == 'status':
                print(report['status'])
                for line in drift:
                    print('note: ' + line, file=sys.stderr)
                return 0
            print(json.dumps({'seal': 'verified', 'verdict': report['verdict'], 'drift': drift}, indent=2))
            return 2 if drift else 0
        scratch, created = scratch_dir(args.scratch)
        git, http = Git(scratch), Http()
        if args.command == 'record':
            specs = load_patch_set(source.TAG)
            value, _, _ = derive_record(git, args.tag, args.allowed_signers, sorted({s['project'] for s in specs}))
            if args.out:
                digest = write_new(args.out, value)
                print(json.dumps({'record': repo_path(args.out), 'sha256': digest}, indent=2))
            elif load_record(args.verify) != value:
                raise CarryError('record does not match its signed release: ' + repo_path(args.verify))
            else:
                print(json.dumps({'record': repo_path(args.verify), 'verified': True}, indent=2))
            return 0
        if args.command == 'ledger':
            records = [load_record(path) for path in args.base]
            specs = load_patch_set(source.TAG)
            work = scratch / 'content'
            work.mkdir()
            value = build_ledger(git, http, records, specs, load_surface(), load_backports(), work)
            digest = write_new(args.out, value, replace=args.replace)
            print(json.dumps({'ledger': repo_path(args.out), 'sha256': digest,
                              'fixes': len(value['fixes']), 'preview': len(value['preview'])}, indent=2))
            return 0
        work = scratch / 'apply'
        work.mkdir()
        report = run_check(git, http, args.base, args.target_tag, args.allowed_signers, args.ledger, work,
                           args.target_record)
        digest = write_new(args.out, report)
        print(json.dumps({'report': repo_path(args.out), 'sha256': digest, 'verdict': report['verdict']}, indent=2))
        print(report['status'])
        return 0 if report['verdict'] == 'CARRIED' else 2
    except NotRun as error:
        print('NOT_RUN: ' + str(error), file=sys.stderr)
        return 3
    except (CarryError, source.SourceError, OSError, ValueError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 1
    finally:
        if scratch is not None:
            clear_scratch(scratch, created)


if __name__ == '__main__':
    sys.exit(main())
