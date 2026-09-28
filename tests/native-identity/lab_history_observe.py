# SPDX-License-Identifier: Apache-2.0
"""Strict lab observers for the header only false commit arm and its store bytes.

writer_observe.assess_commit qualifies positive commits only. This module adds the separate
false or uncertain commit arm of an original select-new operation. A false reply never shows
that nothing changed or that no reservation exists: effects stay unknown until the header and
filesystem bytes are observed separately and compared exactly with predictions that the actual
record codec produced. An unresolved request is retained as an UNKNOWN envelope keyed to its
issued ledger record, whether or not any reply arrives. Nothing here is execution, designation,
retry or recovery authority.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

_SPEC = importlib.util.spec_from_file_location('lab_history_writer_observe',
                                               Path(__file__).with_name('writer_observe.py'))
writer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(writer)

SUBJECT = writer.SUBJECT
FIXTURE_SIGNER = '874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3'
# The issued ledger, never the reply, says whether a reply answered the commit itself or an
# explicit status reconciliation of the same original request.
ISSUED = {'commit': 'commit-reply', 'status': 'status-reconciliation'}
UNAVAILABLE = 'native writer fixture outcome unknown: REPLY_UNAVAILABLE'
HEADERS = ('store.bin', 'store.bin.reservecopy')
PREDICTED = ('v2-creating-header.bin', 'v2-live-header.bin', 'v2-slot-body.bin')
GENERATION_KEYS = ('version', 'mode', 'format', 'lab_input_only', 'authority', 'lineage',
                   'header_sha256', 'header_bytes', 'entries')
PREDICTION_KEYS = ('version', 'mode', 'format', 'prediction_only', 'authority', 'subject',
                   'signer_sha256', 'lineage', 'app_id', 'user_id', 'user_serial', 'principal_id', 'files')
# Fields an in scope reply contributes to an UNKNOWN envelope, exactly as reported.
RETAINED = ('subject', 'request', 'state', 'selection_intent', 'attempt', 'operation', 'observation_attempt',
            'error_class', 'observation_error_class', 'prepare_acknowledged', 'prepare_ack_attempt',
            'first_prepare_ack_attempt', 'commit_acknowledged', 'commit_ack_attempt', 'first_commit_ack_attempt',
            'last_commit_result', 'busy', 'principal_id', 'pin_phase')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value, digits):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % digits, value) is not None


def _strict_json(text):
    if type(text) is not str or len(text) > 16384 or len(text.strip().splitlines()) != 1:
        raise ValueError('bounded single line JSON required')
    return json.loads(text, object_pairs_hook=writer._unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def assess_false_commit(text, *, instance, nonce, selected, expected_id, intent, issued_kind,
                        returncode, stderr):
    """The completed original commit attempt of a select-new operation returned false.

    Requires the captured instance and nonce, the independently captured selected identity, the
    prepared principal ID, the recorded select-new intent, the kind of the issued request and a
    successful bounded transport. The reply must show one acknowledged prepare, then exactly one
    completed, not in flight commit attempt that returned false, a fresh observation of the same
    PENDING record and no historical positive commit acknowledgement. An exception, a missing or
    unavailable reply, a stale observation or any other state is refused here. The result keeps
    the effects unknown: it never infers no effect or no reservation.
    """
    if (intent != 'select-new' or type(issued_kind) is not str or issued_kind not in ISSUED
            or type(expected_id) is not int or not 1 <= expected_id < 1 << 63
            or type(returncode) is not int or returncode != 0
            or type(stderr) is not str or stderr.strip()):
        raise ValueError('original select-new intent, issued commit or status and successful transport required')
    value = writer.parse(text, instance=instance, nonce=nonce, selected=selected)
    attempt = value['attempt']
    if (value['result'] != 'recorded' or value['busy'] or value['state'] != 'uncertain'
            or value['operation'] != 'commit' or value['last_commit_result'] != 'false'
            or value['selection_intent'] != 'select-new' or value['intent_violated'] or value['rebind_verified']
            or value['unexpected_handle_retained'] or 'expected_principal_id' in value
            or 'unexpected_principal_id' in value or value['error_class'] or value['observation_error_class']
            or not value['prepare_acknowledged']
            or value['first_prepare_ack_attempt'] != value['prepare_ack_attempt']
            or attempt != value['prepare_ack_attempt'] + 1 or value['observation_attempt'] != attempt
            or value['commit_acknowledged'] or value['commit_ack_attempt'] or value['first_commit_ack_attempt']
            or value.get('pin_phase') != 'PENDING' or 'principal_id' not in value
            or writer._identifier(value['principal_id']) != expected_id):
        raise ValueError('header only false commit not established by this reply')
    return {**value, 'assessment_origin': ISSUED[issued_kind], 'assessment': 'false-or-uncertain-commit',
            'effects': 'unknown', 'no_effect_inferred': False, 'store_observation_required': True,
            'retry_authorized': False}


def issued_record(issued):
    """One issued ledger record of a commit or status request: its kind, instance and nonce."""
    if (type(issued) is not dict or set(issued) != {'kind', 'instance', 'nonce'}
            or type(issued['kind']) is not str or issued['kind'] not in ISSUED
            or not writer._token(issued['instance']) or not writer._token(issued['nonce'])):
        raise ValueError('issued ledger record of a commit or status request required')
    return dict(issued)


def captured_selection(selected):
    """The independently captured selected identity, required of every caller."""
    if (type(selected) is not dict or set(selected) != writer.SELECTED
            or any(type(selected[name]) is not int for name in ('app_id', 'user_id', 'user_serial', 'version_code'))
            or not _hex(selected['signer_sha256'], 64)):
        raise ValueError('independently captured selected identity required')
    return dict(selected)


def retain_unknown(text, *, issued, returncode, stderr, selected):
    """A deliberate UNKNOWN envelope for an issued commit or status request. Never false.

    The issued ledger record keys the obligation, not the reply: its kind, original instance and
    nonce stay retained whatever arrives. A missing or unavailable reply keeps them. So does a
    reply that is present but unparseable or in another scope, without trusting its fields.
    The hashes fingerprint the supplied text encoded as strict UTF-8; they retain no bytes.
    Before assessment the caller retains the raw stdout and stderr with the issued ledger. A
    fingerprint matches that capture only after strict UTF-8 decoding without newline translation. Only a reply that parses strictly in the issued
    scope and the captured selection adds its request, intent, attempts and acknowledgements, as
    reported. Nothing invents an acknowledgement, infers no effect, or authorizes a retry or
    replay. Invalid ledger or capture inputs are the caller's error and raise.
    """
    issued = issued_record(issued)
    selected = captured_selection(selected)
    if ((text is not None and type(text) is not str) or (stderr is not None and type(stderr) is not str)
            or (returncode is not None and type(returncode) is not int)):
        raise ValueError('captured transport values')
    try:
        reply_bytes = None if text is None else text.encode('utf-8')
        stderr_bytes = None if stderr is None else stderr.encode('utf-8')
    except UnicodeError as error:
        raise ValueError('captured transport must be strict UTF-8 text; retain the raw capture') from error
    envelope = {'outcome': 'UNKNOWN', 'issued': issued, 'returncode': returncode,
                'reply_sha256': None if reply_bytes is None else _sha(reply_bytes),
                'stderr_sha256': None if stderr_bytes is None else _sha(stderr_bytes),
                'no_effect_inferred': False, 'store_observation_required': True,
                'retry_authorized': False, 'replay_authorized': False}
    if text is None or not text.strip():
        unavailable = stderr is not None and stderr.strip() == UNAVAILABLE
        return {**envelope, 'reason': 'reply-unavailable' if unavailable else 'reply-missing'}
    try:
        writer._decode(text)
    except Exception:
        return {**envelope, 'reason': 'reply-unparseable'}
    try:
        value = writer.parse(text, instance=issued['instance'], nonce=issued['nonce'], selected=selected)
    except Exception:
        return {**envelope, 'reason': 'reply-unrecognized'}
    return {**envelope, 'reason': 'reply-' + value['last_commit_result'],
            'retained': {name: value[name] for name in RETAINED if name in value}}


def load_generation(text):
    """The generator's own report of one empty version 1 lab input. Lab input, never authority."""
    value = _strict_json(text)
    if (type(value) is not dict or tuple(value) != GENERATION_KEYS or type(value['version']) is not int
            or value['version'] != 1 or value['mode'] != 'empty-v1' or value['format'] != 'V1'
            or value['lab_input_only'] is not True or value['authority'] is not False
            or not _hex(value['lineage'], 32) or not _hex(value['header_sha256'], 64)
            or type(value['header_bytes']) is not int or value['header_bytes'] != 70
            or value['entries'] != ['slots', *HEADERS]):
        raise ValueError('lab generation report')
    return value


def _regular(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
        raise ValueError('bounded regular unaliased file required')
    return Path(path).read_bytes()


def _root(directory):
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError('absolute real directory required')
    return root


def load_prediction(directory, *, signer=FIXTURE_SIGNER):
    """The predictor's files and manifest, exactly. Prediction only, never a store or authority."""
    root = _root(directory)
    if sorted(os.listdir(root)) != sorted(('prediction.json', *PREDICTED)):
        raise ValueError('prediction files')
    manifest = _regular(root / 'prediction.json')
    value = _strict_json(manifest.decode('ascii'))
    files = {name: _regular(root / name) for name in PREDICTED}
    if (type(value) is not dict or tuple(value) != PREDICTION_KEYS or type(value['version']) is not int
            or value['version'] != 1 or value['mode'] != 'predict-v2' or value['format'] != 'V2'
            or value['prediction_only'] is not True or value['authority'] is not False
            or value['subject'] != SUBJECT or not _hex(signer, 64) or value['signer_sha256'] != signer
            or not _hex(value['lineage'], 32) or type(value['app_id']) is not int
            or not 10000 <= value['app_id'] <= 19999 or type(value['user_id']) is not int
            or value['user_id'] != 0 or type(value['user_serial']) is not int
            or not 0 <= value['user_serial'] < 1 << 63 or type(value['principal_id']) is not int
            or value['principal_id'] != 1 or manifest != (json.dumps(value, separators=(',', ':')) + '\n').encode()
            or value['files'] != {name: {'sha256': _sha(data), 'bytes': len(data)} for name, data in files.items()}):
        raise ValueError('prediction manifest')
    return {**value, 'bytes': files}


def prediction_arguments(generation, prepared, selected, *, signer=FIXTURE_SIGNER):
    """Predictor identifiers validated from the ledger's own records: the generated lineage, and
    the selection and principal ID 1 of the strictly parsed, acknowledged original prepare."""
    if (type(generation) is not dict or type(prepared) is not dict or type(selected) is not dict
            or set(selected) != writer.SELECTED or selected.get('signer_sha256') != signer
            or {name: prepared.get(name) for name in writer.SELECTED} != selected
            or prepared.get('operation') != 'prepare' or prepared.get('selection_intent') != 'select-new'
            or prepared.get('state') != 'prepared' or prepared.get('prepare_acknowledged') is not True
            or prepared.get('prepare_ack_attempt') != prepared.get('attempt')
            or prepared.get('intent_violated') is not False or prepared.get('pin_phase') != 'PENDING'
            or prepared.get('principal_id') != '1' or selected.get('user_id') != 0):
        raise ValueError('predictor inputs are not the recorded original selection and preparation')
    load_generation(json.dumps(generation, separators=(',', ':')))
    return [generation['lineage'], str(selected['app_id']), str(selected['user_serial']), '1']


# Every regular file must have one link, so an alias of another copy or of an outside file refuses.
def _tree(root):
    files, directories = {}, set()
    for current, names, entries in os.walk(root, followlinks=False):
        relative = os.path.relpath(current, root)
        directories.add('' if relative == '.' else relative)
        for name in names + entries:
            path = os.path.join(current, name)
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                files[os.path.relpath(path, root)] = _regular(path)
    return files, directories


def assess_store(snapshot, phase, *, generation=None, prediction=None):
    """Exact store snapshot of one phase: empty-v1, creating or live. No extra, missing, backup,
    seed, slot directory, link or alias, and every byte equal to the lab input or prediction."""
    root = _root(snapshot)
    files, directories = _tree(root)
    if generation is not None and prediction is not None and generation['lineage'] != prediction['lineage']:
        raise ValueError('prediction lineage differs from the generated input')
    if phase == 'empty-v1' and generation is not None:
        expected_directories = {'', 'slots'}
        if (set(files) != set(HEADERS) or files[HEADERS[0]] != files[HEADERS[1]]
                or _sha(files[HEADERS[0]]) != generation['header_sha256']
                or len(files[HEADERS[0]]) != generation['header_bytes']):
            raise ValueError('store bytes differ from the generated input')
    elif phase in ('creating', 'live') and prediction is not None:
        predicted = prediction['bytes']
        header = predicted['v2-creating-header.bin' if phase == 'creating' else 'v2-live-header.bin']
        expected = {name: header for name in HEADERS}
        expected_directories = {'', 'slots'}
        if phase == 'live':
            slot = 'slots/%d' % prediction['app_id']
            expected.update({slot + '/record.bin': predicted['v2-slot-body.bin'],
                             slot + '/record.bin.reservecopy': predicted['v2-slot-body.bin']})
            expected_directories.add(slot)
        if files != expected:
            raise ValueError('store bytes differ from the %s prediction' % phase)
    else:
        raise ValueError('known phase with its lab input or prediction required')
    if directories != expected_directories:
        raise ValueError('store directories differ from the %s phase' % phase)
    return {'phase': phase, 'files': {name: _sha(data) for name, data in sorted(files.items())},
            'directories': sorted(directories), 'authority': False}
