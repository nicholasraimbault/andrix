# SPDX-License-Identifier: Apache-2.0
"""Bounded location fixture observations. No silence-only permission verdicts."""
import json
import re

PROVIDER = 'andrix_principal_test'
ATTRIBUTION = 'native-principal-proof'


def stream(raw, nonce, uid, package, *, action='watch', complete=False):
    if (not isinstance(raw, bytes) or len(raw) > 1024 * 1024 or type(uid) is not int
            or uid < 0 or not 10000 <= uid % 100000 <= 19999
            or not isinstance(nonce, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', nonce)
            or not isinstance(package, str) or not package or action not in ['info', 'watch']):
        raise ValueError('invalid expected stream identity or size')
    if complete and raw and not raw.endswith(b'\n'):
        raise ValueError('partial terminal event')
    # Never interpret an unfinished pipe write as an event.
    raw = raw[:raw.rfind(b'\n') + 1]
    rows = [json.loads(line) for line in raw.decode('utf-8').split('\n') if line]
    if len(rows) > 512:
        raise ValueError('event count bound')
    previous = -1
    pid = None
    callbacks = 0
    terminal = False
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or terminal or type(row.get('schema')) is not int
                or row['schema'] != 1 or type(row.get('sequence')) is not int
                or row['sequence'] != index + 1):
            raise ValueError('invalid event sequence')
        if pid is None:
            pid = row.get('pid')
            if type(pid) is not int or pid <= 1:
                raise ValueError('invalid diagnostic PID')
        if (row.get('uid') != uid or row.get('pid') != pid or row.get('nonce') != nonce
                or row.get('provider') != PROVIDER or row.get('action') != action):
            raise ValueError('mixed request identity')
        if index and row.get('action') != rows[0]['action']:
            raise ValueError('mixed action')
        when = row.get('elapsed_realtime_ms')
        if type(when) is not int or when < previous:
            raise ValueError('nonmonotonic observation time')
        previous = when
        if any(key in row for key in ['latitude', 'longitude', 'altitude', 'location', 'raw_location']):
            raise ValueError('unexpected location contents')
        phase = row.get('phase')
        if phase == 'callback':
            callbacks += 1
            if (row.get('mock') is not True or type(row.get('marker_time_ms')) is not int
                    or row['marker_time_ms'] <= 0 or type(row.get('location_elapsed_realtime_ns')) is not int
                    or row['location_elapsed_realtime_ns'] <= 0):
                raise ValueError('invalid synthetic callback')
        if type(row.get('callback_count')) is not int or row['callback_count'] != callbacks or callbacks > 128:
            raise ValueError('callback accounting mismatch')
        if phase in ['context', 'heartbeat']:
            if any(type(row.get(key)) is not bool for key in ['coarse_granted', 'fine_granted', 'background_granted']):
                raise ValueError('invalid permission observation')
        if 'status' in row:
            if row['status'] != 'refused_or_failed' or phase == 'complete':
                raise ValueError('unknown failure status')
            terminal = True
        elif phase == 'complete':
            terminal = True
    for name in ['entry', 'context', 'provider', 'registered', 'cleanup', 'complete']:
        if sum(row['phase'] == name for row in rows) > 1:
            raise ValueError('duplicate singleton phase')
    if rows and rows[0]['phase'] != 'entry':
        raise ValueError('missing kernel entry')
    if rows:
        entry = rows[0];kernel = entry['kernel_fields']
        for key in ['Uid', 'Gid']:
            if kernel.get(key, '').split() != [str(uid)] * 4: raise ValueError('kernel tuple mismatch')
        for key in ['CapInh', 'CapPrm', 'CapEff', 'CapAmb']:
            if not re.fullmatch('0{1,16}', kernel.get(key, '')): raise ValueError('unexpected capabilities')
        if not re.fullmatch(r'u:r:runas_app:s0(?::c[0-9]+(?:,c[0-9]+)*)?', entry.get('selinux_context', '')):
            raise ValueError('unexpected reference domain')
    contexts = [r for r in rows if r['phase'] == 'context']
    if contexts:
        if len(contexts) != 1 or rows[1] is not contexts[0]: raise ValueError('ambiguous context')
        context = contexts[0]
        if (context.get('context_package') != package or context.get('context_uid') != uid
                or context.get('attribution_uid') != uid or context.get('attribution_package') != package
                or context.get('attribution_tag') != ATTRIBUTION):
            raise ValueError('context/operation identity mismatch')
    registered = [r for r in rows if r['phase'] == 'registered']
    if len(registered) > 1: raise ValueError('repeated registration')
    if registered:
        row = registered[0]
        if (not contexts or row.get('request_returned_not_delivery') is not True
                or not re.fullmatch('[0-9A-F]{8}', row.get('listener_diagnostic_hash', ''))):
            raise ValueError('invalid registration observation')
    providers = [r for r in rows if r['phase'] == 'provider']
    if providers and type(providers[0].get('fixed_provider_present')) is not bool:
        raise ValueError('invalid provider observation')
    if complete:
        if not rows or not terminal: raise ValueError('no terminal observation')
        if rows[-1]['phase'] == 'complete' and (not contexts or len(providers) != 1):
            raise ValueError('incomplete metadata prefix')
        if rows[-1]['phase'] == 'complete' and action == 'watch':
            if providers[0]['fixed_provider_present'] is not True:
                raise ValueError('successful watch without fixture provider')
            cleanup = [r for r in rows if r['phase'] == 'cleanup']
            if (len(registered) != 1 or len(cleanup) != 1 or cleanup[0].get('remove_updates_returned') is not True
                    or cleanup[0].get('executor_retired') is not True):
                raise ValueError('registration/executor retirement not observed')
    return rows


def registration_state(text, uid, package, listener_hash):
    """Pinned named-provider diagnostic dump, never the event log or full location history.

    None means no matching current registration in a complete fixture section, not denial.
    A controller must pair actual state, live callbacks and a witness before judging policy.
    """
    if (not isinstance(text, str) or len(text) > 1024 * 1024 or type(uid) is not int or uid < 0
            or not isinstance(package, str) or not package
            or not re.fullmatch('[0-9A-F]{8}', listener_hash)):
        raise ValueError('invalid provider observation')
    lines = text.split('\n')
    if lines[:2] != ['Provider:', '  ' + PROVIDER + ' provider [mock]:'] or lines.count('Event Log:') != 1:
        raise ValueError('not the complete fixed mock-provider dump')
    section = lines[2:lines.index('Event Log:')]
    last = [n for n, line in enumerate(section) if line.startswith('    last location=')]
    enabled = [line for line in section[last[0] + 1:] if line.startswith('    enabled=')] if len(last) == 1 else []
    if len(last) != 1 or len(enabled) != 1 or enabled[0] not in ['    enabled=true', '    enabled=false']:
        raise ValueError('incomplete provider section')
    provider_enabled = enabled[0] == '    enabled=true'
    indices = [n for n, line in enumerate(section) if line == '    listeners:']
    if not indices: return None
    if len(indices) != 1 or indices[0] >= last[0]: raise ValueError('invalid listener section')
    expression = re.compile(r'^      ([0-9]+)/([A-Za-z0-9_.]+)\[' + ATTRIBUTION
            + r'\]/([0-9A-F]{8})(?: \{((?:bg|na)(?:, (?:bg|na))?)\})?'
            + r'( \(COARSE\))? (Request\[.*\])( \(inactive\))?$')
    found = []
    for line in section[indices[0] + 1:last[0]]:
        match = expression.fullmatch(line)
        if match is None: raise ValueError('unrecognized current listener record')
        if match[2] != package: continue
        if int(match[1]) != uid: raise ValueError('package observed under unexpected UID')
        if match[3] != listener_hash: raise ValueError('unexpected listener identity for fixture UID')
        flags = set((match[4] or '').split(', ')) - {''}
        found.append({'provider_enabled': provider_enabled, 'background': 'bg' in flags, 'permitted': 'na' not in flags,
                      'active': match[7] is None, 'coarse': match[5] is not None,
                      'request': match[6], 'listener_hash': match[3]})
    if len(found) > 1: raise ValueError('duplicate current listener')
    return found[0] if found else None


def appop_mode(text, operation):
    """Configured mode from the exact single-operation shell query, not evaluated UID state."""
    if operation not in ['COARSE_LOCATION', 'FINE_LOCATION', 'MOCK_LOCATION'] or not isinstance(text, str):
        raise ValueError('unexpected app operation observation')
    modes = []
    expression = re.compile(r'^(Uid mode: )?' + operation + r': (allow|ignore|deny|default|foreground)(?:[; (].*)?$')
    for line in text.split('\n'):
        match = expression.fullmatch(line)
        if match: modes.append((bool(match[1]), match[2]))
    uid = [mode for is_uid, mode in modes if is_uid]
    package = [mode for is_uid, mode in modes if not is_uid]
    if len(uid) > 1 or len(package) > 1: raise ValueError('ambiguous app operation mode')
    if uid: return uid[0]
    if package: return package[0]
    match = re.fullmatch(r'No operations\.\nDefault mode: (allow|ignore|deny|default|foreground)\n?', text)
    if match: return match[1]
    raise ValueError('unrecognized app operation state')


def device_state(power, window_policy):
    """Controller observations, not an extra framework dependency in the principal process."""
    if (not isinstance(power, str) or not isinstance(window_policy, str)
            or len(power) > 1024 * 1024 or len(window_policy) > 1024 * 1024
            or not power.startswith('Power Manager State:\n')
            or not window_policy.startswith('WINDOW MANAGER POLICY STATE (dumpsys window policy)')):
        raise ValueError('unknown power/window diagnostic format')
    wake = re.findall(r'^  mWakefulness=([A-Za-z]+)$', power, re.M)
    changing = re.findall(r'^  mWakefulnessChanging=(true|false)$', power, re.M)
    if len(wake) != 1 or len(changing) != 1 or power.count('Battery saver state machine:') != 1:
        raise ValueError('incomplete power state')
    parts = power.split('Battery saver state machine:\n', 1)
    if len(parts) != 2: raise ValueError('incomplete battery saver heading')
    section = parts[1].split('\n')
    if len(section) < 3:
        raise ValueError('missing battery saver state')
    enabled = re.fullmatch(r'  Enabled=(true|false)', section[0])
    full = re.fullmatch(r'    full=(true|false)', section[1])
    adaptive = re.fullmatch(r'    adaptive=(true|false)(?: \(advertise=(?:true|false)\))?', section[2])
    if not all([enabled, full, adaptive]):
        raise ValueError('invalid battery saver state')
    lines = window_policy.split('\n')
    found = [(i, re.fullmatch(r'( +)KeyguardServiceDelegate', line)) for i, line in enumerate(lines)]
    found = [(i, match) for i, match in found if match]
    if len(found) != 1: raise ValueError('keyguard delegate observation missing/ambiguous')
    index, match = found[0];prefix = match[1] + '  ';values = {}
    for line in lines[index+1:]:
        if not line.startswith(prefix): break
        name, separator, value = line[len(prefix):].partition('=')
        if not separator or name in values: raise ValueError('invalid keyguard state')
        values[name] = value
    required = ['showing', 'inputRestricted', 'systemReady', 'bootCompleted']
    if any(values.get(name) not in ['true', 'false'] for name in required):
        raise ValueError('incomplete keyguard state')
    return {'interactive': wake[0] == 'Awake' and changing[0] == 'false',
            'power_save': enabled[1] == 'true' or full[1] == 'true' or adaptive[1] == 'true',
            'keyguard_showing': values['showing'] == 'true',
            'keyguard_input_restricted': values['inputRestricted'] == 'true',
            'keyguard_ready': values['systemReady'] == values['bootCompleted'] == 'true',
            'keyguard_screen_on': values.get('screenState') == 'SCREEN_STATE_ON',
            'keyguard_awake': values.get('interactiveState') == 'INTERACTIVE_STATE_AWAKE'}
