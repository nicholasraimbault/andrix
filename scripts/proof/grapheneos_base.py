# SPDX-License-Identifier: Apache-2.0
"""The selected GrapheneOS base: the one base record the tools build on.

upstream/selected-base.json names one release, its record upstream/bases/<release>.json and the
SHA-256 of that record's bytes. The record must have exactly that digest and the base record
form before any tool reads it. A missing selection or record, a changed selection or record and
a selection that does not name exactly one base are refused. Nothing is inferred and there is no
default.

The tools take the base's identity from selected(): the release tag, the manifest tag object,
commit and digest, the AOSP default revision, the project count, the security patch level, the
HEAD revisions of the patched projects and the patch directory patches/grapheneos-<release>/.
selected() reads only the repository's selection, once per process. No option or environment
variable selects another base. load() takes a selection and a root for tests in scratch. The
record's allowed signers digest is exposed for grapheneos_source.py, which pins the trust input
itself. grapheneos_carry.py derives base records from signed tags. This module fetches and
derives nothing.
"""
from dataclasses import dataclass
import functools
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import types

ROOT = Path(__file__).resolve().parents[2]
SELECTION = 'upstream/selected-base.json'
SCHEMA = 'andrix.upstream.selected_base/1'
RECORD_SCHEMA = 'andrix.upstream.base/1'
SELECTION_KEYS = ('schema', 'release', 'record', 'record_sha256')
# The base record's own key order, as grapheneos_carry.py writes and validates it.
RECORD_KEYS = ('schema', 'release', 'manifest', 'aosp_default_revision', 'projects',
               'security_patch_level', 'kernel_prebuilts', 'patched_projects')
LIMIT = 1 << 20
RELEASE = re.compile(r'[0-9]{10}')
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')
DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')


class BaseSelectionError(ValueError):
    """The selection or its base record is missing, changed or ambiguous."""


@dataclass(frozen=True)
class Base:
    release: str
    record: str
    record_sha256: str
    tag_object: str
    manifest_commit: str
    manifest_sha256: str
    allowed_signers_sha256: str
    aosp_default_revision: str
    project_count: int
    security_patch_level: str
    revisions: types.MappingProxyType
    patches: Path

    def revision(self, project):
        """The HEAD revision the base record pins for a patched project."""
        if project not in self.revisions:
            raise BaseSelectionError('the selected base record pins no revision of ' + project)
        return self.revisions[project]


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BaseSelectionError('ambiguous: the key %r occurs twice' % key)
        result[key] = value
    return result


def _constant(value):
    raise BaseSelectionError('non-finite JSON value ' + value)


def _read(path, what):
    """The bytes of a regular file, not a symbolic link, of at most LIMIT bytes."""
    if path.is_symlink() or not path.is_file():
        raise BaseSelectionError('the %s is missing or not a regular file: %s' % (what, path))
    with path.open('rb') as handle:
        data = handle.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise BaseSelectionError('the %s is larger than %d bytes: %s' % (what, LIMIT, path))
    return data


def _json(data, what):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=_constant)
    except BaseSelectionError as error:
        raise BaseSelectionError('%s: %s' % (what, error)) from error
    except ValueError as error:
        raise BaseSelectionError('%s is not JSON: %s' % (what, error)) from error


def _text(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _selection(value):
    if not isinstance(value, dict) or set(value) != set(SELECTION_KEYS):
        raise BaseSelectionError('the selection must hold exactly ' + ', '.join(SELECTION_KEYS))
    if value['schema'] != SCHEMA:
        raise BaseSelectionError('unknown selection schema: %r' % (value['schema'],))
    release = value['release']
    if isinstance(release, (list, dict)):
        raise BaseSelectionError('ambiguous: the selection must name exactly one base, not %r'
                                 % (release,))
    if not _text(release, RELEASE):
        raise BaseSelectionError('the selected release is not a release tag: %r' % (release,))
    if value['record'] != 'upstream/bases/%s.json' % release:
        raise BaseSelectionError('ambiguous: the selection names release %s and the record %r'
                                 % (release, value['record']))
    if not _text(value['record_sha256'], HEX64):
        raise BaseSelectionError('the selection names no record digest')
    return value


def _record(value, release):
    if (not isinstance(value, dict) or tuple(value) != RECORD_KEYS
            or value['schema'] != RECORD_SCHEMA):
        raise BaseSelectionError('not a base record')
    if value['release'] != release:
        raise BaseSelectionError('ambiguous: the record of %s names release %r'
                                 % (release, value['release']))
    manifest, projects = value['manifest'], value['projects']
    level, patched = value['security_patch_level'], value['patched_projects']
    if (not isinstance(manifest, dict) or manifest.get('tag') != 'refs/tags/' + release
            or not _text(manifest.get('tag_object'), HEX40)
            or not _text(manifest.get('commit'), HEX40)
            or not _text(manifest.get('sha256'), HEX64)
            or not _text(manifest.get('allowed_signers_sha256'), HEX64)):
        raise BaseSelectionError('the base record has no exact manifest identity')
    if not isinstance(value['aosp_default_revision'], str) or not value['aosp_default_revision']:
        raise BaseSelectionError('the base record has no AOSP default revision')
    if (not isinstance(projects, dict) or type(projects.get('count')) is not int
            or projects['count'] < 1 or not _text(projects.get('table_sha256'), HEX64)):
        raise BaseSelectionError('the base record has no project count')
    if not isinstance(level, dict) or not _text(level.get('value'), DATE):
        raise BaseSelectionError('the base record has no security patch level')
    if (not isinstance(patched, dict) or not patched
            or not all(isinstance(row, dict) and _text(row.get('revision'), HEX40)
                       for row in patched.values())):
        raise BaseSelectionError('the base record has no exact patched project revisions')
    return value


def load(selection=None, root=None):
    """The base a selection record names, verified against its record's digest and form.

    The defaults are the repository's selection and root. Tests pass a scratch selection and root.
    """
    root = (ROOT if root is None else Path(root)).resolve()
    selection = root / SELECTION if selection is None else Path(selection).absolute()
    chosen = _selection(_json(_read(selection, 'base selection'), 'base selection'))
    path = root.joinpath(*PurePosixPath(chosen['record']).parts)
    if path.parent.resolve() != root / 'upstream' / 'bases':
        raise BaseSelectionError('the selected record is not in upstream/bases: '
                                 + chosen['record'])
    data = _read(path, 'base record')
    if hashlib.sha256(data).hexdigest() != chosen['record_sha256']:
        raise BaseSelectionError('the base record differs from the digest the selection names: '
                                 + chosen['record'])
    value = _record(_json(data, 'base record'), chosen['release'])
    manifest = value['manifest']
    revisions = {project: row['revision'] for project, row in value['patched_projects'].items()}
    return Base(release=chosen['release'], record=chosen['record'],
                record_sha256=chosen['record_sha256'], tag_object=manifest['tag_object'],
                manifest_commit=manifest['commit'], manifest_sha256=manifest['sha256'],
                allowed_signers_sha256=manifest['allowed_signers_sha256'],
                aosp_default_revision=value['aosp_default_revision'],
                project_count=value['projects']['count'],
                security_patch_level=value['security_patch_level']['value'],
                revisions=types.MappingProxyType(revisions),
                patches=root / 'patches' / ('grapheneos-' + chosen['release']))


@functools.lru_cache(maxsize=None)
def selected():
    """The repository's selected base, read and verified once per process."""
    return load()
