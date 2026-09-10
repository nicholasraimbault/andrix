#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One digest-guarded, opt-in private SELinux bridge; not a general patch tool."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import tempfile

import grapheneos_source as source

PROJECT = 'system/sepolicy'
HEAD = '87a06ed71fd67cff9f77feaa9ae3504edb5d0972'
FILE = 'private/domain.te'
BEFORE = 'b6097259d6529f010896778f4802e1556b5c70643c9eab3e793ea91c45d26934'
PREFIX = '# Rules for all domains.\n'
DECLARATIONS = '''# Rules for all domains.

# Andrix private owner-workload integration. Empty on ordinary upstream builds;
# no vendor/public policy API and no existing domain changes. The opt-in product
# supplies andrix_owner_session=true and the matching system_ext implementation.
ifelse(andrix_owner_session, `true', `
type andrixd, domain, coredomain;
type andrix_owner, domain, coredomain;
type andrix_home_file, file_type, data_file_type, core_data_file_type;
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


def patched(original):
    if sha(original) != BEFORE:
        raise ValueError('pinned upstream policy bytes do not match')
    text = original.decode('utf-8')
    if (text.count(PREFIX) != 1 or text.count(ORIGINAL_EXEC_PREFIX) != 1
            or text.count(ORIGINAL_DATA_PREFIX) != 1
            or text.count('allow ' + CGROUP_SUBJECT + ' cgroup') != 4):
        raise ValueError('ambiguous or missing policy bridge context')
    text = text.replace(PREFIX, DECLARATIONS, 1)
    text = text.replace(ORIGINAL_EXEC_PREFIX, BRIDGE_EXEC_PREFIX, 1)
    text = text.replace(ORIGINAL_DATA_PREFIX, BRIDGE_DATA_PREFIX, 1)
    # Remove only this NEW native worker from broad non-app cgroup write grants.
    text = text.replace('allow ' + CGROUP_SUBJECT + ' cgroup',
                        'allow ' + CGROUP_BRIDGE_SUBJECT + ' cgroup')
    return text.encode()


def inspect(root):
    root = root.resolve(strict=True)
    project = root/PROJECT
    if (project.resolve(strict=True) != project or not (project/FILE).is_file()
            or (project/FILE).resolve(strict=True) != project/FILE):
        raise ValueError('unexpected project/path containment')
    head = source.run(project, 'rev-parse', 'HEAD')[1].decode().strip()
    if head != HEAD:
        raise ValueError('wrong pinned SELinux project revision')
    original = source.run(project, 'show', 'HEAD:'+FILE)[1]
    target = patched(original)
    current = (project/FILE).read_bytes()
    if current == original: state = 'UPSTREAM'
    elif current == target: state = 'ANDRIX_PRIVATE_BRIDGE'
    else: raise ValueError('unexpected policy file modification')
    # Use the same callback-disabled Git inspection profile as the base verifier.
    flags = source.filter_overrides(project)
    worktree = source.run(project, *flags, 'diff', '--no-ext-diff', '--no-textconv', '--name-only', 'HEAD', '--')[1].decode().splitlines()
    staged = source.run(project, *flags, 'diff', '--no-ext-diff', '--no-textconv', '--cached', '--name-only', '--')[1].decode().splitlines()
    if staged or worktree != ([FILE] if state != 'UPSTREAM' else []):
        raise ValueError('unexpected staged or other tracked project changes')
    return project, original, target, {'project':PROJECT,'head':head,'file':FILE,'state':state,
        'upstream_sha256':sha(original),'bridge_sha256':sha(target),
        'effective_on_unflagged_products':False,'runtime_proved':False}


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
    project, original, target, report = inspect(root)
    wanted = target if args.action == 'apply' else original
    if args.action != 'check' and (project/FILE).read_bytes() != wanted:
        path = project/FILE
        before_stat = path.stat()
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.andrix-policy-', delete=False) as file:
            temporary = Path(file.name)
            try:
                file.write(wanted)
                file.flush()
                os.fsync(file.fileno())
                os.fchmod(file.fileno(), before_stat.st_mode & 0o777)
            except BaseException:
                temporary.unlink()
                raise
        # No index update, reset, hidden clean filter or source normalization.
        os.replace(temporary, path)
    _, _, _, after = inspect(root)
    report.update({'action':args.action,'state_after':after['state']})
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
