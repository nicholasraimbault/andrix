# SPDX-License-Identifier: Apache-2.0
"""PermissionController fixture observations, never grant or input authority."""
import re
import xml.etree.ElementTree as ET

PERMISSION = 'android.permission.POST_NOTIFICATIONS'


def permission_state(text, *, package, uid, user_id):
    if (not isinstance(text, str) or len(text.encode()) > 1024 * 1024
            or type(uid) is not int or type(user_id) is not int or user_id < 0
            or uid // 100000 != user_id or not 10000 <= uid % 100000 <= 19999
            or not isinstance(package, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package)):
        raise ValueError('invalid independent permission subject')
    lines = text.splitlines()
    if not lines or lines[0] != 'App ID: ' + str(uid % 100000):
        raise ValueError('permission dump app ID mismatch')
    if sum(line.startswith('App ID:') for line in lines) != 1:
        raise ValueError('duplicate permission subject')
    users = {}
    current = None
    for line in lines[1:]:
        match = re.fullmatch(r'  User: (0|[1-9][0-9]*)', line)
        if match:
            current = int(match[1])
            if current in users:
                raise ValueError('duplicate permission user')
            users[current] = []
        elif current is None:
            if line.strip():
                raise ValueError('permission data before user')
        else:
            users[current].append(line)
    if user_id not in users:
        raise ValueError('permission user missing')
    section = users[user_id]
    if section.count('    Package: ' + package) != 1 or sum(line.startswith('    Package: ') for line in section) != 1:
        raise ValueError('permission package mismatch')
    if section.count('    Permissions:') != 1:
        raise ValueError('default device permission section missing or duplicated')
    rows = {}
    start = section.index('    Permissions:') + 1
    for line in section[start:]:
        if line.strip() and not line.startswith('      '):
            break
        if not line.strip():
            continue
        match = re.fullmatch(r'      ([A-Za-z0-9_.]+): granted=(true|false), flags=\[([A-Z0-9_|]*)\]', line)
        if not match or match[1] in rows:
            raise ValueError('malformed or duplicate permission record')
        flags = match[3].split('|') if match[3] else []
        if len(flags) != len(set(flags)) or any(not re.fullmatch(r'[A-Z][A-Z0-9_]*', flag) for flag in flags):
            raise ValueError('malformed permission flags')
        rows[match[1]] = {'stored': True, 'granted': match[2] == 'true', 'flags': sorted(flags)}
    # Zero flags have no entry in the platform map. Absence is interpreted only
    # inside an established user/package/default-device section, never an empty dump.
    return rows.get(PERMISSION, {'stored': False, 'granted': False, 'flags': []})


def focused_hierarchy(xml, *, package, display_id=0):
    """Select one reported input focused application window, not accessibility focus.

    The caller also checks Window Manager's current focus and the permission subject.
    This standard all windows observation never changes a grant or view protection.
    """
    if (not isinstance(xml, str) or len(xml.encode()) > 1024 * 1024
            or '<!DOCTYPE' in xml or '<!ENTITY' in xml or type(display_id) is not int
            or display_id < 0 or not isinstance(package, str) or not package):
        raise ValueError('invalid all windows observation')
    root = ET.fromstring(xml)
    if root.tag != 'displays':
        raise ValueError('wrong all windows root')
    displays = [node for node in root.findall('display') if node.get('id') == str(display_id)]
    if len(displays) != 1:
        raise ValueError('display missing or duplicated')
    focused = [node for node in displays[0].findall('window') if node.get('focused') == 'true']
    if len(focused) != 1 or focused[0].get('type') != 'TYPE_APPLICATION':
        raise ValueError('focused application window missing or ambiguous')
    trees = focused[0].findall('hierarchy')
    if len(trees) != 1 or not list(trees[0].iter('node')):
        raise ValueError('focused hierarchy unavailable')
    if any(node.get('package') != package for node in trees[0].iter('node')):
        raise ValueError('focused hierarchy package mismatch')
    return ET.tostring(trees[0], encoding='unicode')


def notification_settings_switch(xml, *, app_label, expected_checked):
    """Fixture target only. The caller separately binds the public app settings route.

    App label text is not package identity. The controller must use its captured package
    and user, no channel or group extras, and independently check permission state.
    """
    if not isinstance(app_label, str) or not app_label or type(expected_checked) is not bool:
        raise ValueError('invalid settings subject')
    focused = focused_hierarchy(xml, package='com.android.settings')
    root = ET.fromstring(focused)
    nodes = list(root.iter('node'))
    bars = [node for node in nodes if node.get('resource-id') == 'com.android.settings:id/main_switch_bar']
    if len(bars) != 1 or bars[0].get('enabled') != 'true' or bars[0].get('clickable') != 'true':
        raise ValueError('enabled main switch bar missing or ambiguous')
    labels = [node for node in bars[0].iter('node') if node.get('resource-id') == 'com.android.settings:id/switch_text']
    switches = [node for node in bars[0].iter('node') if node.get('resource-id') == 'android:id/switch_widget']
    if (len(labels) != 1 or labels[0].get('text') != 'All ' + app_label + ' notifications'
            or len(switches) != 1 or switches[0].get('class') != 'android.widget.Switch'
            or switches[0].get('enabled') != 'true'
            or switches[0].get('checked') != str(expected_checked).lower()):
        raise ValueError('main switch subject or checked state mismatch')
    categories = [node for node in nodes if node.get('text') == 'Notification categories'
                  and node.get('resource-id') == 'android:id/title']
    if len(categories) != 1 or nodes.index(bars[0]) >= nodes.index(categories[0]):
        raise ValueError('not the expected application notification page')
    return ui_target(focused, package='com.android.settings',
                     resource_id='com.android.settings:id/main_switch_bar')


def ui_target(xml, *, package, text=None, resource_id=None, width=720, height=1280):
    if (not isinstance(xml, str) or len(xml.encode()) > 1024 * 1024
            or '<!DOCTYPE' in xml or '<!ENTITY' in xml
            or not isinstance(package, str) or not package
            or (text is None) == (resource_id is None)
            or type(width) is not int or type(height) is not int or width <= 0 or height <= 0):
        raise ValueError('invalid UI observation')
    root = ET.fromstring(xml)
    if root.tag != 'hierarchy':
        raise ValueError('wrong hierarchy root')
    key, wanted = ('text', text) if text is not None else ('resource-id', resource_id)
    matches = [node for node in root.iter('node') if node.get('package') == package
               and node.get(key) == wanted and node.get('enabled') == 'true'
               and node.get('clickable') == 'true']
    if len(matches) != 1:
        raise ValueError('UI target missing or ambiguous')
    match = re.fullmatch(r'\[(0|[1-9][0-9]*),(0|[1-9][0-9]*)\]\[(0|[1-9][0-9]*),(0|[1-9][0-9]*)\]', matches[0].get('bounds', ''))
    if not match:
        raise ValueError('UI bounds missing')
    x1, y1, x2, y2 = map(int, match.groups())
    if not (0 <= x1 < x2 <= width and 0 <= y1 < y2 <= height):
        raise ValueError('UI target outside observed display')
    return {'x': (x1 + x2) // 2, 'y': (y1 + y2) // 2}
