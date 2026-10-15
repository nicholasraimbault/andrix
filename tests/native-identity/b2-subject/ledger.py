#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Durable one issue setup ownership. This module never executes guest commands."""
import json
import os
from pathlib import Path
import secrets
from protocol import (PACKAGE, hex_value, instrumentation_argv, require, setup_commands, sha,
                      strict_json, validate_contract)


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _root(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and path.is_dir()
            and not path.is_symlink(), 'canonical private ledger root')
    return path


def _new(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    _sync(path.parent)
    return sha(data)


def _read_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        import stat
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 32768,
                'ledger record metadata')
        data = stream.read(32769)
    require(len(data) <= 32768, 'ledger record bounds')
    return data


def _read(path):
    return strict_json(_read_bytes(path))


def prepare(root, instance_sha256, contract, provenance, phase, guest_binding):
    """Before any effect. One directory per guest instance and package, not per setup token.

    provenance hashes refer to independent, complete baseline captures. The caller must assess
    those captures with the parsers and the preflight protocol before calling this function.
    A partial prepare consumes the name too. It can only be inspected, never retried as new work.
    """
    root = _root(root)
    validate_contract(contract)
    require(hex_value(instance_sha256) and type(provenance) is dict and set(provenance) == {
        'apk', 'pms', 'user', 'permissionmgr', 'appops', 'notification', 'jobscheduler',
        'files', 'native', 'image', 'setup_jar'} and all(hex_value(v) for v in provenance.values()),
        'independent baseline provenance')
    nonce = secrets.token_hex(16)
    argv = instrumentation_argv(contract, 'initialize', nonce, phase, guest_binding)
    directory = root / (instance_sha256 + '.' + PACKAGE)
    directory.mkdir(mode=0o700)  # EEXIST refuses even a different UID, serial or token.
    _sync(root)
    request = {'version': 1, 'instance_sha256': instance_sha256, 'package': PACKAGE,
               'uid': contract['uid'], 'user_serial': contract['serial'], 'setup': contract['setup'],
               'contract_sha256': contract['contract_sha256'], 'nonce': nonce,
               'provenance': provenance, 'initialize_argv': argv,
               'setup_commands': setup_commands(contract, nonce)}
    request_hash = _new(directory / 'request.json', request)
    contract_hash = _new(directory / 'contract.json', {
        k: v.decode('ascii') if type(v) is bytes else v for k, v in contract.items()})
    _new(directory / 'prepared.json', {'request_sha256': request_hash,
                                       'contract_sha256': contract_hash})
    return directory


def _prepared(directory):
    seal = _read(directory / 'prepared.json')
    require(type(seal) is dict and set(seal) == {'request_sha256', 'contract_sha256'}
            and all(hex_value(v) for v in seal.values())
            and seal['request_sha256'] == sha(_read_bytes(directory / 'request.json'))
            and seal['contract_sha256'] == sha(_read_bytes(directory / 'contract.json')),
            'prepared setup records changed')
    return seal


def _request(directory):
    request = _read(directory / 'request.json')
    contract = _read(directory / 'contract.json')
    require(type(request) is dict and type(contract) is dict, 'owned request and contract')
    for field in ('ce_bytes', 'de_bytes', 'intent_bytes', 'contract_bytes'):
        require(type(contract.get(field)) is str, 'stored contract byte encoding')
        contract[field] = contract[field].encode('ascii')
    validate_contract(contract)
    require(request.get('version') == 1 and request.get('package') == PACKAGE
            and request.get('uid') == contract['uid'] and request.get('user_serial') == contract['serial']
            and request.get('setup') == contract['setup']
            and request.get('contract_sha256') == contract['contract_sha256']
            and request.get('setup_commands') == setup_commands(contract, request.get('nonce')),
            'owned setup request')
    return request


def _argv(request, step):
    return request['initialize_argv'] if step == 0 else request['setup_commands'][step - 1]


def _claimed_issue(directory, step, request, request_hash):
    claim = _read(directory / f'{step}.claim.json')
    data = _read_bytes(directory / f'{step}.issued.json')
    require(type(claim) is dict and set(claim) == {'request_sha256', 'issue_sha256'}
            and claim['request_sha256'] == request_hash and hex_value(claim['issue_sha256'])
            and sha(data) == claim['issue_sha256'], 'issue bytes changed after claim')
    issue = strict_json(data)
    require(type(issue) is dict and set(issue) == {'request_sha256', 'precondition_sha256', 'argv'}
            and issue['request_sha256'] == request_hash and hex_value(issue['precondition_sha256'])
            and issue['argv'] == _argv(request, step), 'issue differs from the claimed request')
    return claim['issue_sha256']


def claim(directory, step, fresh_precondition_sha256):
    """Fsync issue AND its exact byte commitment before returning any command to submit.

    Step 0 is initialize; 1..4 are grant, flags, appop and the shell copy command. A partial
    claim consumes its issue name too. A timeout or lost acknowledgement can never be reissued.
    """
    directory = _root(directory)
    require(type(step) is int and 0 <= step <= 4 and hex_value(fresh_precondition_sha256),
            'setup step and precondition')
    seal = _prepared(directory)
    request = _request(directory)
    if step:
        previous = _read(directory / f'{step - 1}.outcome.json')
        previous_issue = _claimed_issue(directory, step - 1, request, seal['request_sha256'])
        require(previous.get('outcome') == 'observed-success'
                and previous.get('request_sha256') == seal['request_sha256']
                and previous.get('issue_sha256') == previous_issue,
                'previous step incomplete, changed or unknown')
    require(not (directory / f'{step}.outcome.json').exists(), 'completed issue')
    argv = _argv(request, step)
    issue_hash = _new(directory / f'{step}.issued.json', {
        'request_sha256': seal['request_sha256'], 'precondition_sha256': fresh_precondition_sha256,
        'argv': argv})
    _new(directory / f'{step}.claim.json', {
        'request_sha256': seal['request_sha256'], 'issue_sha256': issue_hash})
    return argv


def complete(directory, step, outcome, capture_sha256):
    directory = _root(directory)
    require(type(step) is int and 0 <= step <= 4 and outcome in
            ('observed-success', 'observed-refusal', 'unknown') and hex_value(capture_sha256),
            'setup outcome')
    seal = _prepared(directory)
    request = _request(directory)
    issue_hash = _claimed_issue(directory, step, request, seal['request_sha256'])
    _new(directory / f'{step}.outcome.json', {'outcome': outcome, 'capture_sha256': capture_sha256,
          'request_sha256': seal['request_sha256'], 'issue_sha256': issue_hash})
