# SPDX-License-Identifier: Apache-2.0
"""Strict writer fixture metadata, never execution authority or a live lease."""
import json
import re

SUBJECT = 'dev.andrix.proof.principalclosed'
BASE = {'version', 'instance', 'subject', 'request', 'state', 'selection_intent', 'intent_violated',
        'rebind_verified', 'busy', 'result', 'attempt', 'operation', 'observation_attempt',
        'error_class', 'observation_error_class', 'prepare_acknowledged', 'prepare_ack_attempt',
        'first_prepare_ack_attempt', 'commit_acknowledged', 'commit_ack_attempt',
        'first_commit_ack_attempt', 'last_commit_result', 'unexpected_handle_retained',
        'execution_authorized', 'retirement_complete'}
SELECTED = {'app_id', 'user_id', 'user_serial', 'version_code', 'signer_sha256'}
RECORD = {'principal_id', 'pin_phase'}
OPTIONAL = SELECTED | RECORD | {'expected_principal_id', 'unexpected_principal_id'}
REFUSALS = {'SERVICE_UNAVAILABLE', 'ARGUMENTS', 'STALE_INSTANCE', 'NONCE_FORMAT', 'OPERATION',
            'SELECTION_REQUIRED', 'OTHER_REQUEST_RETAINED', 'INTENT_CHANGED',
            'INTENT_VIOLATION_RETAINED', 'SELECTION_UNAVAILABLE', 'COMMIT_ALREADY_ATTEMPTED',
            'ORIGINAL_HANDLE_REQUIRED', 'REBIND_NOT_VERIFIED', 'ATTEMPT_CAPACITY'}


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate writer result field')
        result[name] = value
    return result


def _decode(text):
    if len(text) > 16384 or len(text.strip().splitlines()) != 1:
        raise ValueError('writer reply missing or not bounded JSON')
    value = json.loads(text, object_pairs_hook=_unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if type(value) is not dict or type(value.get('version')) is not int or value['version'] != 1:
        raise ValueError('writer schema')
    return value


def _token(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{32}', value)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= (1 << 63) - 1


def _identifier(value):
    if type(value) is not str or not re.fullmatch(r'[1-9][0-9]{0,18}', value) or int(value) >= 1 << 63:
        raise ValueError('native principal identifier')
    return int(value)


def _parse(text, *, instance=None, nonce=None, selected=None):
    """Internal decoder. Public operation parsers require captured scope."""
    value = _decode(text)
    if not BASE <= value.keys() or value.keys() - BASE - OPTIONAL:
        raise ValueError('writer field set')
    if (not _token(value['instance']) or value['subject'] != SUBJECT
            or (instance is not None and value['instance'] != instance)
            or (nonce is not None and value['request'] != nonce)
            or (value['request'] != '' and not _token(value['request']))):
        raise ValueError('writer operation scope')
    for field in ('intent_violated', 'rebind_verified', 'busy', 'prepare_acknowledged',
                  'commit_acknowledged', 'unexpected_handle_retained', 'execution_authorized', 'retirement_complete'):
        if type(value[field]) is not bool:
            raise ValueError('writer boolean')
    if value['execution_authorized'] or value['retirement_complete']:
        raise ValueError('fixture cannot supply execution or retirement authority')
    for field in ('attempt', 'observation_attempt', 'prepare_ack_attempt', 'commit_ack_attempt',
                  'first_prepare_ack_attempt', 'first_commit_ack_attempt'):
        if not _integer(value[field]) or value[field] > value['attempt']:
            raise ValueError('writer attempt provenance')
    for kind in ('prepare', 'commit'):
        latest = value[kind + '_ack_attempt']; first = value['first_' + kind + '_ack_attempt']
        if value[kind + '_acknowledged'] != (latest != 0) or bool(first) != bool(latest) or first > latest:
            raise ValueError('writer acknowledgement provenance')
    if value['state'] not in {'empty', 'selecting', 'selected', 'selection-refused', 'preparing',
                              'prepare-refused', 'prepared', 'committing', 'durable-pin', 'uncertain'}:
        raise ValueError('writer state')
    if value['selection_intent'] not in {'', 'select-new', 'select-rebind'} or value['operation'] not in {
            '', 'select-new', 'select-rebind', 'prepare', 'commit'}:
        raise ValueError('writer operation kind')
    if value['result'] not in {'info', 'recorded', 'in-flight'} or value['last_commit_result'] not in {
            'not-called', 'in-flight', 'true', 'false', 'exception'}:
        raise ValueError('writer outcome kind')
    for field in ('error_class', 'observation_error_class'):
        if type(value[field]) is not str or not re.fullmatch(r'[A-Za-z0-9_.$-]{0,200}', value[field]):
            raise ValueError('writer error field')
    if value.keys() & SELECTED:
        if not SELECTED <= value.keys() or type(selected) is not dict or set(selected) != SELECTED:
            raise ValueError('independent selected identity required')
        if (any(type(selected[name]) is not int for name in ('app_id', 'user_id', 'user_serial', 'version_code'))
                or type(selected['signer_sha256']) is not str):
            raise ValueError('independent selected identity types')
        if (not _integer(value['app_id'], 10000) or value['app_id'] > 19999
                or type(value['user_id']) is not int or value['user_id'] != 0
                or not _integer(value['user_serial']) or type(value['version_code']) is not int
                or value['version_code'] != 1 or type(value['signer_sha256']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', value['signer_sha256'])
                or {name: value[name] for name in SELECTED} != selected):
            raise ValueError('selected Android identity mismatch')
    elif selected is not None:
        raise ValueError('selected identity absent')
    if value.keys() & RECORD:
        if not RECORD <= value.keys() or not SELECTED <= value.keys() or value['observation_attempt'] == 0:
            raise ValueError('writer record observation incomplete')
        _identifier(value['principal_id'])
        if value['pin_phase'] not in {'PENDING', 'ACTIVE', 'RETIRING', 'RETIRED'}:
            raise ValueError('native pin metadata phase')
    for name in ('expected_principal_id', 'unexpected_principal_id'):
        if name in value:
            _identifier(value[name])
    if 'unexpected_principal_id' in value and not value['unexpected_handle_retained']:
        raise ValueError('unexpected handle observation without retained ownership')
    return value


def parse(text, *, instance=None, nonce=None, selected=None):
    """Selected identity and operation scope must come from independent captures."""
    if not _token(instance) or not _token(nonce):
        raise ValueError('captured writer instance and request nonce required')
    return _parse(text, instance=instance, nonce=nonce, selected=selected)


def parse_info(text, *, returncode, stderr, selected=None):
    if type(returncode) is not int or returncode != 0 or type(stderr) is not str or stderr.strip():
        raise ValueError('successful info transport required')
    value = _parse(text, selected=selected)
    if value['result'] != 'info':
        raise ValueError('writer info reply required')
    return value


def _require_commit(value, expected_id, intent):
    """A positive lab assertion is stricter than a historical commit acknowledgement."""
    if (value['state'] != 'durable-pin' or value['last_commit_result'] != 'true' or value['result'] != 'recorded'
            or value['operation'] != 'commit' or value['selection_intent'] != intent
            or (intent == 'select-new' and (value['rebind_verified'] or 'expected_principal_id' in value))
            or not value['prepare_acknowledged'] or not value['commit_acknowledged'] or value['commit_ack_attempt'] != value['attempt']
            or value['observation_attempt'] != value['attempt'] or value['busy']
            or value['intent_violated'] or value['unexpected_handle_retained']
            or value['error_class'] or value['observation_error_class']
            or value.get('pin_phase') != 'ACTIVE' or _identifier(value.get('principal_id')) != expected_id
            or (value['selection_intent'] == 'select-rebind' and (not value['rebind_verified']
                or _identifier(value.get('expected_principal_id')) != expected_id))):
        raise ValueError('writer commit not qualified by this reply')
    return value


def assess_commit(text, *, instance, nonce, selected, expected_id, intent, transport_operation,
                  returncode, stderr):
    """The issued ledger, never the reply, identifies direct response vs reconciliation."""
    if (not _integer(expected_id, 1) or intent not in {'select-new', 'select-rebind'}
            or transport_operation not in {'commit', 'status'} or type(returncode) is not int
            or returncode != 0 or type(stderr) is not str or stderr.strip()):
        raise ValueError('original identity, intent and successful transport required')
    value = _require_commit(parse(text, instance=instance, nonce=nonce, selected=selected), expected_id, intent)
    return {**value, 'assessment_origin': 'commit-reply' if transport_operation == 'commit' else 'status-reconciliation'}


def refusal(text, code, current_instance, *, requested_instance, returncode, stderr):
    value = _decode(text)
    if (type(returncode) is not int or returncode != 1 or type(stderr) is not str or stderr.strip()
            or set(value) != {'version', 'instance', 'result', 'code'} or code not in REFUSALS
            or value['code'] != code or value['result'] != 'refused' or value['instance'] != current_instance):
        raise ValueError('specific writer refusal not established')
    if code == 'SERVICE_UNAVAILABLE':
        if current_instance != '' or (requested_instance is not None and not _token(requested_instance)):
            raise ValueError('unavailable service has no current instance')
        # This invocation was refused. An older operation's outcome is not resolved.
    elif (not _token(current_instance) or not _token(requested_instance)
          or (code == 'STALE_INSTANCE' and current_instance == requested_instance)
          or (code != 'STALE_INSTANCE' and current_instance != requested_instance)):
        raise ValueError('refusal instance scope')
    return value


def caller_denied(stdout, stderr, code):
    if type(code) is not int or code != 1 or stdout.strip() or stderr.strip() != 'native writer fixture refused: CALLER_DENIED':
        raise ValueError('caller refusal not established')
