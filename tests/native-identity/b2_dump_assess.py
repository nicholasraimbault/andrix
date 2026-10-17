# SPDX-License-Identifier: Apache-2.0
"""Per phase assessment of one raw native identity dump of a guest phase of the reader step.

The phase plan names the booted image and the schema it renders: B2's normal image renders schema
3 and B1's, the rollback floor, schema 2. A phase requires exactly its own. A dump of the other
schema, or of the historical version 1, is refused as wrong schema evidence, never read as a
partial success. The not live envelope, the unavailable envelope, a malformed or truncated dump
and a missing capture are unavailable evidence, kept with their raw text and error. None of them
is an empty store: an empty prediction matches only a dump that renders an empty store.

The phase's dump prediction states every scalar, including the allocator's search start, which only
the guest reports, every hold in order, the exact deferred names and, on B2, every slot row. On B1
it has no slot rows, and the schema 2 dump has none to compare. Every value is compared; nothing a
prediction omits is ignored. Cached metadata only: no lease, admission or authority.

lab_history_observe.assess_dump stays the B1 guest stage's assessment of its phases, unchanged."""
import hashlib
import importlib.util
from pathlib import Path
import re

_SPEC = importlib.util.spec_from_file_location('b2_dump_assess_observe', Path(__file__).with_name('observe.py'))
dump = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(dump)
# The observers' one completeness gate of a dumpsys capture (uid_observe.complete_capture).
_GATE_SPEC = importlib.util.spec_from_file_location('b2_dump_assess_gate', Path(__file__).with_name('uid_observe.py'))
gate = importlib.util.module_from_spec(_GATE_SPEC)
_GATE_SPEC.loader.exec_module(gate)

# The schema each image renders.
IMAGE_SCHEMAS = {'B2': 3, 'B1': 2}
SCALARS = dump.SCALARS
BOOLEAN_SCALARS = ('counter_known', 'cached_enumeration_complete', 'creation_ready', 'unidentified_code')
KINDS = ('empty', 'package', 'shared', 'other')
SUSPENDED = ('true', 'false', 'not-reported')
# The fields the host readers predict, in the prediction rows' order; the other three scalars are
# the live envelope's two constants and the guest's search start.
ROW_FIELDS = ('counter_known', 'cached_header', 'cached_enumeration_complete', 'creation_ready',
              'unidentified_code')
COUNT = re.compile(r'0|[1-9][0-9]{0,9}')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def phase_schema(phase):
    """The image and schema a phase plan names, which must agree."""
    if type(phase) is not dict or phase.get('image') not in IMAGE_SCHEMAS:
        raise ValueError('a phase plan naming B1 or B2 required')
    image, schema = phase['image'], phase.get('schema')
    if type(schema) is not int or schema != IMAGE_SCHEMAS[image]:
        raise ValueError('the phase plan names %s with schema %r; %s renders schema %d'
                         % (image, schema, image, IMAGE_SCHEMAS[image]))
    return image, schema


def _app_id(value):
    if type(value) is not int or not 10000 <= value <= 19999:
        raise ValueError('an ordinary app ID')
    return value


def prediction(value, image):
    """One phase's dump prediction, validated exactly: every scalar as rendered text, the holds as
    [app ID, cached slot, memory pin, mapping kind, mapping] in increasing app ID order, on B2 one
    slot row [app ID, version, lifecycle, suspended] per hold in the same order and on B1 none,
    and the deferred names in Java String order."""
    keys = {'fields', 'holds', 'deferred'} | ({'slots'} if image == 'B2' else set())
    if type(value) is not dict or set(value) != keys:
        raise ValueError('a dump prediction of %s holds exactly %s' % (image, sorted(keys)))
    fields = value['fields']
    if (type(fields) is not dict or set(fields) != set(SCALARS)
            or any(type(item) is not str for item in fields.values())):
        raise ValueError('a dump prediction states every scalar as text')
    if (fields['live_settings'] != 'true' or fields['authority'] != 'not-reported'
            or any(fields[name] not in ('true', 'false') for name in BOOLEAN_SCALARS)
            or fields['cached_header'] not in dump.STATUSES or not COUNT.fullmatch(fields['allocator_search_start'])
            or int(fields['allocator_search_start']) > 2147483647):
        raise ValueError('a dump prediction scalar outside the rendered forms')
    holds = value['holds']
    if type(holds) is not list or any(type(row) is not list or len(row) != 5 for row in holds):
        raise ValueError('hold predictions')
    for app_id, status, pinned, kind, mapping in holds:
        _app_id(app_id)
        if (status not in dump.STATUSES or type(pinned) is not bool or kind not in KINDS or type(mapping) is not str
                or (kind == 'empty') != (mapping == '') or len(mapping.encode('utf-8')) > 255):
            raise ValueError('a hold prediction')
    ids = [row[0] for row in holds]
    if ids != sorted(set(ids)):
        raise ValueError('hold predictions out of app ID order or repeated')
    if image == 'B2':
        slots = value['slots']
        if (type(slots) is not list or any(type(row) is not list or len(row) != 4 for row in slots)
                or [row[0] for row in slots] != ids):
            raise ValueError('one slot prediction per hold, in hold order')
        for _, version, lifecycle, suspended in slots:
            if version not in dump.SLOT_VERSIONS or lifecycle not in dump.SLOT_STATES or suspended not in SUSPENDED:
                raise ValueError('a slot prediction')
    deferred = value['deferred']
    if (type(deferred) is not list or any(type(name) is not str or not name for name in deferred)
            or deferred != sorted(set(deferred), key=lambda name: name.encode('utf-16-be'))):
        raise ValueError('deferred names, once each, in Java String order')
    return value


def _observed(value, schema):
    rows = {'schema': value['schema_version'], 'fields': dict(value['fields']),
            'holds': [[app_id, hold['cached_slot'], hold['memory_pin'], hold['mapping_kind'], hold['mapping']]
                      for app_id, hold in value['holds'].items()],
            'deferred': list(value['deferred_names'])}
    if schema == 3:
        rows['slots'] = [[app_id, slot['version'], slot['lifecycle'], slot['suspended']]
                         for app_id, slot in value['slots'].items()]
    return rows


def assess_phase_capture(capture, phase):
    """One raw dump capture of a guest phase, through the completeness gate first: a capture that is not
    one complete dump (its transport, exit status, timeout line, stderr or last line) is unavailable
    with the gate's reason and never read; a complete one is assessed by assess_phase_dump. CAPTURE is
    the trials' completed process or a capture record (gate.complete_capture)."""
    image, schema = phase_schema(phase)
    prediction(phase.get('dump_prediction'), image)
    try:
        out = gate.complete_capture(capture, 'native dump')
    except ValueError as error:
        return {'image': image, 'schema': schema, 'authority': False, 'outcome': 'unavailable', 'available': False, 'matches': False,
                'raw_sha256': None, 'raw': None, 'error': str(error), 'problems': ['unavailable dump: %s' % error]}
    return assess_phase_dump(out.decode('ascii', 'surrogateescape') if type(out) is bytes else out, phase)


def assess_phase_dump(text, phase):
    """One raw dump of a guest phase against its plan: the plan's image and schema, and its
    dump_prediction. The outcome is 'match', 'mismatch', 'wrong-schema' or 'unavailable'; only a
    match is a success. A missing capture is None. A malformed plan or prediction raises."""
    image, schema = phase_schema(phase)
    expected = prediction(phase.get('dump_prediction'), image)
    result = {'image': image, 'schema': schema, 'authority': False}
    if text is None:
        return dict(result, outcome='unavailable', available=False, matches=False, raw_sha256=None, raw=None,
                    error='no dump capture', problems=['no dump capture'])
    if type(text) is not str:
        raise ValueError('a raw dump text, or None for a missing capture')
    raw_sha256 = _sha(text.encode('utf-8', 'surrogateescape'))
    try:
        # The dump's own schema first: an envelope or a malformed dump raises here.
        value = dump.parse_reservations(text)
    except ValueError as error:
        return dict(result, outcome='unavailable', available=False, matches=False, raw_sha256=raw_sha256, raw=text,
                    error=str(error), problems=['unavailable dump: %s' % error])
    observed = value.get('schema_version', 1)
    if observed != schema:
        message = 'a schema %d dump where %s requires schema %d' % (observed, image, schema)
        return dict(result, outcome='wrong-schema', available=False, matches=False, raw_sha256=raw_sha256,
                    raw=text, observed_schema=observed, error=message, problems=[message])
    value = dump.parse_reservations(text, schema=schema)
    rows = _observed(value, schema)
    problems = ['field %s is %r, not %r' % (name, rows['fields'][name], expected['fields'][name])
                for name in SCALARS if rows['fields'][name] != expected['fields'][name]]
    for key in ('holds', 'slots', 'deferred') if schema == 3 else ('holds', 'deferred'):
        if rows[key] != expected[key]:
            problems.append('%s %r, not %r' % (key, rows[key], expected[key]))
    if schema == 2 and 'slots' in value:
        problems.append('slot rows in a schema 2 dump')
    return dict(result, outcome='mismatch' if problems else 'match', available=True, matches=not problems,
                raw_sha256=raw_sha256, observed=rows, problems=problems)


def expectation(rows, image, allocator_search_start, ids):
    """A phase's dump prediction from one reading's diagnostic rows, as the host predictions write
    them: the reader's schema, the five predicted fields, the holds 'app ID, cached slot, pinned or
    unpinned, mapping kind, mapping or -', the slot rows 'app ID, version, lifecycle, suspended'
    and the deferred names. ids maps each app ID of the rows to the guest's own, so the prediction
    is the guest's: holds and slot rows follow the guest's app ID order. The search start is the
    guest's report."""
    image_schema = IMAGE_SCHEMAS.get(image)
    if type(rows) is not dict or image_schema is None or rows.get('schema') != image_schema:
        raise ValueError('diagnostic rows of the schema %s renders' % image)
    if set(rows) != {'schema', 'fields', 'holds', 'deferred'} | ({'slots'} if image_schema == 3 else set()):
        raise ValueError('diagnostic rows of another form')
    if type(ids) is not dict or any(type(key) is not int for key in ids):
        raise ValueError('guest app IDs by host app ID')
    for value in ids.values():
        _app_id(value)
    if len(set(ids.values())) != len(ids):
        raise ValueError('distinct guest app IDs')
    fields = dict(item.split('=', 1) for item in rows['fields'])
    if list(fields) != list(ROW_FIELDS) or len(rows['fields']) != len(ROW_FIELDS):
        raise ValueError('the five predicted fields, in order')
    if type(allocator_search_start) is not int or not 0 <= allocator_search_start <= 2147483647:
        raise ValueError('the guest\'s allocator search start')

    def guest(app):
        if not re.fullmatch(r'1[0-9]{4}', app) or int(app) not in ids:
            raise ValueError('an app ID the guest values do not map: %s' % app)
        return ids[int(app)]
    holds = []
    for row in rows['holds']:
        parts = row.split(' ')
        if len(parts) != 5 or parts[2] not in ('pinned', 'unpinned'):
            raise ValueError('a hold row')
        holds.append([guest(parts[0]), parts[1], parts[2] == 'pinned', parts[3], '' if parts[4] == '-' else parts[4]])
    order = sorted(range(len(holds)), key=lambda index: holds[index][0])
    value = {'fields': {'live_settings': 'true', 'authority': 'not-reported', **fields,
                        'allocator_search_start': str(allocator_search_start)},
             'holds': [holds[index] for index in order], 'deferred': list(rows['deferred'])}
    value['fields'] = {name: value['fields'][name] for name in SCALARS}
    if image_schema == 3:
        slots = []
        for row in rows['slots']:
            parts = row.split(' ')
            if len(parts) != 4:
                raise ValueError('a slot row')
            slots.append([guest(parts[0])] + parts[1:])
        if [slot[0] for slot in slots] != [hold[0] for hold in holds]:
            raise ValueError('slot rows out of their holds\' order')
        value['slots'] = [slots[index] for index in order]
    return prediction(value, image)


def missing_store(image, allocator_search_start):
    """A phase's dump prediction for a store that does not exist: header MISSING, nothing
    enumerated, the counter unknown, creation not ready, no unidentified code, and no hold, slot
    row or deferred name."""
    if image not in IMAGE_SCHEMAS:
        raise ValueError('B1 or B2')
    rows = {'schema': IMAGE_SCHEMAS[image],
            'fields': ['counter_known=false', 'cached_header=MISSING', 'cached_enumeration_complete=false',
                       'creation_ready=false', 'unidentified_code=false'], 'holds': [], 'deferred': []}
    if image == 'B2':
        rows['slots'] = []
    return expectation(rows, image, allocator_search_start, {})
