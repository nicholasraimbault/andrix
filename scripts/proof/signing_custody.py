# SPDX-License-Identifier: Apache-2.0
"""Read only observations for the finite custody vehicle, not authorization.

A parsed provider reply does not authenticate a caller or prove that an uncertain
mutation never ran. Credential targeting accepts no credential material and must
be paired with a fresh actual UI observation in the declared guest/user context.
"""
from dataclasses import dataclass
import re
import shlex
import xml.etree.ElementTree as ET
try:
    from .signing_identity import strict_json
except ImportError:
    from signing_identity import strict_json


UI_FIELDS = {
    'wait': {'seconds'}, 'snapshot': {'label'}, 'console': {'label'},
    'key': {'code'}, 'tap': {'x', 'y'}, 'swipe': {'x1', 'y1', 'x2', 'y2', 'duration'},
    'custody-pin': {'context', 'label'},
    'custody-prepare': set(), 'custody-negative': set(), 'custody-status': set(),
    'custody-request': {'label'}, 'custody-open': {'label'}, 'custody-cancel': {'label'},
    'custody-observe': {'label', 'state'}, 'custody-replay': {'label'},
    'custody-restart': {'label'}, 'custody-finish': set(), 'finish': set(),
    'artifact-request': {'label'}, 'artifact-open': {'label'},
    'artifact-observe': {'label', 'state'}, 'artifact-cancel': {'label'},
    'artifact-retry': {'label'}, 'artifact-replay': {'label'},
    'artifact-restart': {'label'}, 'artifact-install': {'label'},
    'artifact-status': {'label'}, 'artifact-finish': set(),
}


def recordable_ui_request(data):
    """Refuse/redact undeclared inputs BEFORE an evidence writer sees them.

    This is a closed test action schema, not a general private data detector.
    It accepts no literal credential, private key or arbitrary text input field.
    """
    try:
        value = strict_json(data)
    except (ValueError, TypeError):
        return {'action': 'malformed', 'input_redacted_before_recording': True}, False
    if not isinstance(value, dict) or not isinstance(value.get('action'), str):
        return {'action': 'malformed', 'input_redacted_before_recording': True}, False
    action = value['action']
    redacted = {'action': action if action in UI_FIELDS else 'unsupported',
                'input_redacted_before_recording': True}
    if action not in UI_FIELDS or not set(value) <= UI_FIELDS[action] | {'action'}:
        return redacted, False
    required = UI_FIELDS[action] - ({'duration'} if action == 'swipe' else set())
    if not required <= set(value):
        return redacted, False
    for name, item in value.items():
        if name == 'action':
            continue
        if name == 'label':
            valid = isinstance(item, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', item)
        elif name == 'context':
            valid = item in ['setup', 'authenticate']
        elif name == 'state':
            valid = item in ['COMPLETE', 'CANCELLED']
        elif name == 'code':
            valid = type(item) is int and item in [3, 4, 19, 20, 21, 22, 61, 66, 82, 111, 187, 223, 224]
        else:
            lower, upper = (0, 719) if name.startswith('x') else (0, 1279) if name.startswith('y') else (100, 1000) if name == 'duration' else (0, 120)
            valid = type(item) is int and lower <= item <= upper
        if not valid:
            return redacted, False
    return value, True


def raw_input_command(adb, serial, remote_args):
    """Keep the shell v2 session alive after stdin EOF and retain exit status.

    exec-in is not interchangeable: it closes its raw exec connection when
    copying stdin finishes, without waiting for the remote process. The caller
    must supply private bytes separately on stdin, never as remote arguments.
    """
    if (not isinstance(adb, str) or not adb.startswith('/')
            or serial != '127.0.0.1:6520'
            or not isinstance(remote_args, list) or not remote_args
            or any(not isinstance(arg, str) or not arg or '\x00' in arg or '\n' in arg
                   for arg in remote_args)):
        raise ValueError('Expected explicit private fixture transport and command')
    return [adb, '-s', serial, 'shell', '-T', '-e', 'none', shlex.join(remote_args)]


@dataclass(frozen=True)
class ProviderObservation:
    result: dict | None
    error_class: str | None


def provider_observation(code, output):
    if code != 0 or not isinstance(output, str) or len(output) > 1024 * 1024:
        raise ValueError('No complete provider reply observation')
    success = re.fullmatch(r'Result: Bundle\[\{result=(\{.*\})\}\]\s*', output, re.S)
    if success:
        result = strict_json(success[1].encode('utf-8'))
        if not isinstance(result, dict):
            raise ValueError('Unexpected provider value')
        return ProviderObservation(result, None)
    failure = re.fullmatch(
        r'Result: Bundle\[\{error_class=([A-Za-z_$][A-Za-z0-9_.$]*)\}\]\s*', output)
    if failure:
        return ProviderObservation(None, failure[1])
    raise ValueError('Unknown or ambiguous provider reply')


def _credential_nodes(xml):
    if (not isinstance(xml, str) or len(xml) > 4 * 1024 * 1024
            or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper()):
        raise ValueError('Unsupported credential hierarchy')
    root = ET.fromstring(xml)
    if root.tag != 'displays':
        raise ValueError('A fresh all windows hierarchy is required')
    displays = [display for display in root.findall('display') if display.get('id') == '0']
    if len(displays) != 1:
        raise ValueError('No unique primary display')
    windows = [window for window in displays[0].iter('window')
               if window.get('focused') == window.get('active') == 'true']
    if len(windows) != 1 or len(windows[0].findall('hierarchy')) != 1:
        raise ValueError('No unique active focused credential window')
    # Do not borrow a matching field from another window or a nested child
    # window which is not the observed input target.
    return list(windows[0].find('hierarchy').iter('node'))


def credential_target(xml, context):
    if context not in ['setup', 'authenticate']:
        raise ValueError('Unsupported credential context')
    nodes = _credential_nodes(xml)
    if context == 'setup':
        fields = [n for n in nodes if n.get('package') == 'com.android.settings'
                  and n.get('resource-id') == 'com.android.settings:id/password_entry'
                  and n.get('enabled') == n.get('focused') == n.get('password') == 'true']
        if len(fields) == 1:
            return 'settings-credential-field'
    else:
        enabled = [n for n in nodes if n.get('package') == 'com.android.systemui'
                   and n.get('enabled') == 'true']
        ids = [n.get('resource-id') for n in enabled]
        required = ['com.android.systemui:id/pinEntry'] + [
            'com.android.systemui:id/key' + str(i) for i in range(10)]
        if all(ids.count(name) == 1 for name in required):
            return 'systemui-pin-keypad'
        fields = [n for n in enabled if n.get('resource-id') in [
            'com.android.systemui:id/lockPassword', 'lockPassword']
                  and n.get('focused') == n.get('password') == 'true']
        if len(fields) == 1:
            return 'systemui-credential-field'
        if ids.count('cred_pin_pad') == 1:
            compose_pin_observation(xml)
            return 'systemui-compose-pin-pad'
    raise ValueError('No unique observed credential target, no input authorized')


def compose_pin_observation(xml):
    """Observe named SystemUI Compose credential controls, without any PIN.

    The caller must separately match the prompt's application/title/key to its
    owned operation. Returned coordinates are public UI geometry, not a grant.
    """
    nodes = _credential_nodes(xml)
    def one(name, within=nodes):
        candidates = [n for n in within if n.get('package') == 'com.android.systemui'
                      and n.get('enabled') == 'true' and n.get('resource-id') == name]
        if len(candidates) != 1:
            raise ValueError('Missing or ambiguous Compose credential control')
        return candidates[0]
    container = one('com.android.systemui:id/compose_credential_view')
    pad = one('cred_pin_pad', list(container.iter('node')))
    def bounds(node):
        match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds', ''))
        if not match:
            raise ValueError('Missing credential control bounds')
        x1, y1, x2, y2 = map(int, match.groups())
        if not 0 <= x1 < x2 <= 720 or not 0 <= y1 < y2 <= 1280:
            raise ValueError('Unsupported credential display geometry')
        return x1, y1, x2, y2
    px1, py1, px2, py2 = bounds(pad)
    rectangles = []
    def center(node):
        x1, y1, x2, y2 = bounds(node)
        if not px1 <= x1 < x2 <= px2 or not py1 <= y1 < y2 <= py2:
            raise ValueError('Control outside the observed PIN pad')
        if any(x1 < right and left < x2 and y1 < bottom and top < y2
               for left, top, right, bottom in rectangles):
            raise ValueError('Overlapping credential controls')
        rectangles.append((x1, y1, x2, y2))
        return (x1 + x2) // 2, (y1 + y2) // 2
    controls = list(pad.iter('node'))
    digits = {}
    for digit in '0123456789':
        candidates = []
        for node in controls:
            if (node.get('package') != 'com.android.systemui' or node.get('enabled') != 'true'
                    or node.get('clickable') != 'true'):
                continue
            labels = [n.get('text') for n in node.iter('node')
                      if n.get('package') == 'com.android.systemui'
                      and re.fullmatch(r'[0-9]', n.get('text', ''))]
            if labels == [digit]:
                candidates.append(node)
        if len(candidates) != 1:
            raise ValueError('Digit label does not uniquely identify a clickable control')
        digits[digit] = center(candidates[0])
    enter = one('com.android.systemui:id/key_enter', controls)
    if enter.get('clickable') != 'true' or not any(
            n.get('package') == 'com.android.systemui' and n.get('content-desc') == 'Enter'
            for n in enter.iter('node')):
        raise ValueError('No observed Enter control')
    return {'digits': digits, 'enter': center(enter),
            'application_label': one('logo_description').get('text', ''),
            'title': one('title').get('text', ''), 'subtitle': one('subtitle').get('text', '')}
