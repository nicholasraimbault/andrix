#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One digest-guarded, opt-in private SELinux bridge; not a general patch tool."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import tempfile

import grapheneos_base
import grapheneos_source as source

PROJECT = 'system/sepolicy'
HEAD = grapheneos_base.selected().revision(PROJECT)
FILES = tuple('private/' + name + '.te' for name in ('domain', 'shell', 'system_app', 'traceur_app'))
BEFORE = dict(zip(FILES, (
    'b6097259d6529f010896778f4802e1556b5c70643c9eab3e793ea91c45d26934',
    'a06ae61869fe11bf6e14790b4a87d014ce2653e11436a473a7d42c3c14b19e56',
    '764b20d7d1684147b16ae487c8559f499c2851f005d658f0110cf913dda1a373',
    '38b9243de67384310a3b7635856b5b0f62b80b1265d841c8a653647faf860e89',
)))
SERVICE = 'andrix_native_accounts_service'
FIND = {name: 'allow ' + name + ' {\n  service_manager_type\n'
        for name in ('shell', 'system_app', 'traceur_app')}
PREFIX = '# Rules for all domains.\n'
DECLARATIONS = '''# Rules for all domains.

# Andrix private owner-workload integration. Empty on ordinary upstream builds;
# no vendor/public policy API; all preexisting service grants remain. The opt-in
# product supplies andrix_owner_session=true and the matching system_ext implementation.
ifelse(andrix_owner_session, `true', `
type andrixd, domain, coredomain;
type andrix_owner, domain, coredomain;
type andrix_home_file, file_type, data_file_type, core_data_file_type;
type andrix_native_accounts_service, service_manager_type, system_server_service;
# Native owner work is deliberately separate from the APK/appdomain model.
# Only its own labelled CE home is executable writable data.
neverallow andrix_owner { data_file_type -andrix_home_file }:file no_x_file_perms;
neverallow { domain -andrix_owner } andrix_home_file:file no_x_file_perms;
neverallow { domain -andrixd } andrix_owner:process transition;
neverallow domain andrix_owner:process dyntransition;
')
'''
ORIGINAL_EXEC_PREFIX = '''neverallow {
    domain
    -appdomain
    with_asan(`-asan_extract')
    -shell
'''
BRIDGE_EXEC_PREFIX = '''neverallow {
    domain
    -appdomain
    ifelse(andrix_owner_session, `true', `-andrix_owner')
    with_asan(`-asan_extract')
    -shell
'''
ORIGINAL_DATA_PREFIX = '''# Protect most domains from executing arbitrary content from /data.
neverallow {
  domain
  -appdomain
'''
BRIDGE_DATA_PREFIX = '''# Protect most domains from executing arbitrary content from /data.
neverallow {
  domain
  -appdomain
  ifelse(andrix_owner_session, `true', `-andrix_owner')
'''
CGROUP_SUBJECT = '{ domain -appdomain -rs }'
CGROUP_BRIDGE_SUBJECT = "{ domain -appdomain -rs ifelse(andrix_owner_session, `true', `-andrix_owner') }"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def contexts(originals):
    """Exact anchored occurrences for each of the four pinned private policy files."""
    if set(originals) != set(FILES):
        raise ValueError('policy bridge needs exactly four private files')
    domain = originals[FILES[0]].decode('utf-8')
    counts = {FILES[0]: (domain.count(PREFIX), domain.count(ORIGINAL_EXEC_PREFIX),
                         domain.count(ORIGINAL_DATA_PREFIX),
                         domain.count('allow ' + CGROUP_SUBJECT + ' cgroup'))}
    for path in FILES[1:]:
        name = path.removeprefix('private/').removesuffix('.te')
        counts[path] = (originals[path].decode('utf-8').count(FIND[name]),)
    return counts


def anchors(path):
    if path == FILES[0]:
        return (PREFIX, ORIGINAL_EXEC_PREFIX, ORIGINAL_DATA_PREFIX,
                'allow ' + CGROUP_SUBJECT + ' cgroup')
    name = path.removeprefix('private/').removesuffix('.te')
    return (FIND[name],)


def bridge(originals):
    """Anchored four file transformation; callers supply either pinned or carry inputs."""
    counts = contexts(originals)
    if counts != {FILES[0]: (1, 1, 1, 4), **{path: (1,) for path in FILES[1:]}}:
        raise ValueError('ambiguous or missing policy bridge context')
    text = originals[FILES[0]].decode('utf-8')
    text = text.replace(PREFIX, DECLARATIONS, 1)
    text = text.replace(ORIGINAL_EXEC_PREFIX, BRIDGE_EXEC_PREFIX, 1)
    text = text.replace(ORIGINAL_DATA_PREFIX, BRIDGE_DATA_PREFIX, 1)
    # Remove only the existing native owner from broad non-app cgroup write grants.
    text = text.replace('allow ' + CGROUP_SUBJECT + ' cgroup',
                        'allow ' + CGROUP_BRIDGE_SUBJECT + ' cgroup')
    outputs = {FILES[0]: text.encode('utf-8')}
    for path in FILES[1:]:
        name = path.removeprefix('private/').removesuffix('.te')
        text = originals[path].decode('utf-8')
        text = text.replace(FIND[name], FIND[name] +
                            "  ifelse(andrix_owner_session, `true', `-" + SERVICE + "')\n", 1)
        outputs[path] = text.encode('utf-8')
    return outputs


def patched(originals):
    if set(originals) != set(FILES) or any(sha(originals[path]) != BEFORE[path] for path in FILES):
        raise ValueError('pinned upstream policy bytes do not match')
    return bridge(originals)


def profile_files(record):
    """Refuse legacy single-file or incomplete policy records before any carry/export."""
    rows = record.get('files')
    if set(record) != {'base_release', 'project', 'head', 'files', 'patch', 'patch_sha256',
                       'activation', 'public_policy_api_changed', 'existing_domain_grants_changed',
                       'patch_format', 'scope'}:
        raise ValueError('owner session policy profile must name four pinned files')
    if not isinstance(rows, list) or len(rows) != len(FILES) or any(
            not isinstance(row, dict) or set(row) != {'path', 'upstream_sha256', 'candidate_sha256'}
            or row.get('path') != path or row.get('upstream_sha256') != BEFORE[path]
            or not isinstance(row.get('candidate_sha256'), str)
            or len(row['candidate_sha256']) != 64
            or any(c not in '0123456789abcdef' for c in row['candidate_sha256'])
            for row, path in zip(rows, FILES)):
        raise ValueError('owner session policy profile must name four pinned files')
    return rows


def inspect(root):
    root = root.resolve(strict=True)
    project = root/PROJECT
    if project.resolve(strict=True) != project or any(
            not (project/path).is_file() or (project/path).resolve(strict=True) != project/path
            for path in FILES):
        raise ValueError('unexpected project/path containment')
    head = source.run(project, 'rev-parse', 'HEAD')[1].decode().strip()
    if head != HEAD:
        raise ValueError('wrong pinned SELinux project revision')
    originals = {path: source.run(project, 'show', 'HEAD:'+path)[1] for path in FILES}
    targets = patched(originals)
    current = {path: (project/path).read_bytes() for path in FILES}
    if current == originals: state = 'UPSTREAM'
    elif current == targets: state = 'ANDRIX_PRIVATE_BRIDGE'
    else: raise ValueError('unexpected policy file modification or mixed bridge state')
    # Use the same callback-disabled Git inspection profile as the base verifier, through a
    # refreshed private copy of the project's index, so the tree's index is not written.
    with source.refreshed_index(project, root) as git:
        worktree = git(*source.WORKTREE_DIFF).decode().splitlines()
        staged = git(*source.STAGED_DIFF).decode().splitlines()
    if staged or sorted(worktree) != (sorted(FILES) if state != 'UPSTREAM' else []):
        raise ValueError('unexpected staged or other tracked project changes')
    return project, originals, targets, {'project': PROJECT, 'head': head, 'state': state,
        'files': [{'path': path, 'upstream_sha256': sha(originals[path]),
                   'bridge_sha256': sha(targets[path])} for path in FILES],
        'effective_on_unflagged_products': False, 'runtime_proved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--action', choices=['check','apply','revert'], default='check')
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    if args.evidence.exists(): raise ValueError('evidence already exists')
    root = args.source_root.resolve(strict=True)
    evidence = args.evidence.resolve()
    repository = Path(__file__).resolve().parents[2]
    if evidence == root or root in evidence.parents or evidence == repository or repository in evidence.parents:
        raise ValueError('evidence must be outside source and repository')
    project, originals, targets, report = inspect(root)
    wanted = targets if args.action == 'apply' else originals
    if args.action != 'check' and report['state'] != (
            'ANDRIX_PRIVATE_BRIDGE' if args.action == 'apply' else 'UPSTREAM'):
        # Stage all four complete images before replacing anything. Never adopt unknown or
        # partially adapted source; a failed replacement remains observable as mixed state.
        temporary = {}
        try:
            for name in FILES:
                path = project/name
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.andrix-policy-',
                                                 delete=False) as file:
                    temporary[name] = Path(file.name)
                    file.write(wanted[name])
                    file.flush()
                    os.fsync(file.fileno())
                    os.fchmod(file.fileno(), path.stat().st_mode & 0o777)
            for name in FILES:
                os.replace(temporary.pop(name), project/name)
        finally:
            for path in temporary.values():
                path.unlink(missing_ok=True)
    _, _, _, after = inspect(root)
    report.update({'action':args.action,'state_after':after['state']})
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
