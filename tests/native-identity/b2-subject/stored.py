#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Selected persistent records from complete decoded XML copies. Never writes service state.

Binary Android XML must first be decoded by a separately qualified decoder on a captured copy.
ABX bytes, DTDs, entities, comments and processing instructions are refused here. These parsers
are not an ABX codec and cannot establish AtomicFile selection or capture stability themselves.
"""
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat
from protocol import (CHANNEL, JOB_ID, PACKAGE, SERVICE, notification_preference, require, sha,
                      validate_contract)


MAX_BYTES = 16 * 1024 * 1024


def decoded_root(data, name):
    require(type(data) is bytes and 0 < len(data) <= MAX_BYTES and not data.startswith(b'ABX'),
            'complete decoded XML bytes required')
    parser = expat.ParserCreate('UTF-8')
    stack = []
    root = None
    count = 0

    def start(tag, attrs):
        nonlocal root, count
        count += 1
        require(len(stack) < 32 and count <= 200000 and len(attrs) <= 64
                and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]*', tag), 'XML bounds or namespace')
        node = ET.Element(tag, attrs)
        if stack:
            stack[-1].append(node)
        else:
            require(root is None and tag == name, 'one correct XML root')
            root = node
        stack.append(node)

    def end(tag):
        require(stack and stack[-1].tag == tag, 'XML nesting')
        stack.pop()

    def text(value):
        if value.strip():
            require(stack and stack[-1].tag == 'string', 'unexpected XML text')
            stack[-1].text = (stack[-1].text or '') + value

    def refuse(*_):
        raise ValueError('XML declaration, entity or comment outside writer grammar')

    parser.StartElementHandler = start; parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = refuse; parser.EntityDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse; parser.ProcessingInstructionHandler = refuse
    parser.CommentHandler = refuse
    try:
        parser.Parse(data, True)
    except expat.ExpatError as error:
        raise ValueError('malformed or duplicated XML') from error
    require(root is not None and not stack, 'incomplete XML document')
    return root


def _one(nodes, message):
    require(len(nodes) == 1, message)
    return nodes[0]


def _children(node, tags):
    require(all(x.tag in tags for x in node), 'unexpected selected XML element')


def _attrs(node, required, optional=()):
    require(set(required) <= set(node.attrib) <= set(required) | set(optional),
            'unexpected or missing selected XML attribute')


def _rows(section, tag, id_attr, allowed_attrs):
    _children(section, {tag})
    seen = set()
    for row in section:
        _attrs(row, allowed_attrs)
        identity = row.get(id_attr)
        require(identity not in seen, 'duplicate stored identity')
        seen.add(identity)
    return list(section)


def access(data, uid, baseline_version, initialized=True):
    root = decoded_root(data, 'access')
    require(not root.attrib, 'access root attributes')
    known = {'package-versions', 'default-permission-grant', 'app-function-pregrant',
             'app-id-permissions', 'app-id-device-permissions', 'app-id-app-ops',
             'package-app-ops', 'app-id-app-function-accesses'}
    _children(root, known)
    require(len({x.tag for x in root}) == len(root), 'duplicate access section')
    versions = _one(root.findall('package-versions'), 'package versions section')
    require(not versions.attrib, 'package versions attributes')
    rows = _rows(versions, 'package', 'name', {'name', 'version'})
    own_version = [x for x in rows if x.get('name') == PACKAGE]
    require(len(own_version) <= 1 and all(len(x) == 0 for x in rows), 'stored package version')
    version = own_version[0].get('version') if own_version else None
    require(version == (str(baseline_version) if baseline_version is not None else None),
            'stored migration version changed')
    permissions = _one(root.findall('app-id-permissions'), 'stored permissions section')
    require(not permissions.attrib, 'permission section attributes')
    ids = _rows(permissions, 'app-id', 'id', {'id'})
    flag = None
    for row in ids:
        require(re.fullmatch(r'0|[1-9][0-9]*', row.get('id')), 'stored app ID')
        perms = _rows(row, 'permission', 'name', {'name', 'flags'})
        require(all(len(x) == 0 and re.fullmatch(r'0|[1-9][0-9]*', x.get('flags')) for x in perms),
                'permission integer or nesting')
        if row.get('id') == str(uid):
            values = [x for x in perms if x.get('name') == 'android.permission.POST_NOTIFICATIONS']
            if values:
                flag = int(values[0].get('flags'))
    modes = {}
    for tag, ident, target in [('app-id-app-ops', 'id', str(uid)),
                               ('package-app-ops', 'name', PACKAGE)]:
        section = _one(root.findall(tag), 'stored app operation section')
        require(not section.attrib, 'app operation section attributes')
        rows = _rows(section, 'app-id' if ident == 'id' else 'package', ident, {ident})
        mode = None
        for row in rows:
            ops = _rows(row, 'app-op', 'name', {'name', 'mode'})
            require(all(len(x) == 0 and re.fullmatch(r'[0-4]', x.get('mode')) for x in ops),
                    'operation mode integer or nesting')
            if row.get(ident) == target:
                values = [x for x in ops if x.get('name') == 'android:vibrate']
                if values:
                    mode = int(values[0].get('mode'))
        modes[tag] = mode
    require(modes['app-id-app-ops'] is None, 'stored nondefault UID VIBRATE mode')
    require((flag == 48 and modes['package-app-ops'] == 1) if initialized
            else (flag in (None, 0) and modes['package-app-ops'] is None),
            'stored permission flags or package mode')
    return {'uid': uid, 'package': PACKAGE, 'permission_flags': flag, 'package_mode': modes[
        'package-app-ops'], 'uid_mode': None, 'migration_version': baseline_version,
        'decoded_sha256': sha(data)}


def notification_policy(data, uid, baseline=None, stage='retained'):
    require(type(stage) is str and stage in ('absent', 'created', 'retained'),
            'stored preference observation stage')
    root = decoded_root(data, 'notification-policy')
    require(root.attrib == {'version': '1'}, 'notification policy version')
    ranking = _one(root.findall('ranking'), 'notification ranking section')
    require(len(root.findall('.//ranking')) == 1, 'nested or duplicate ranking')
    _attrs(ranking, {'version'}, {'last_bubbles_version_upgrade'})
    require(ranking.get('version') == '4'
            and ranking.get('last_bubbles_version_upgrade', '37') == '37', 'ranking version')
    _children(ranking, {'package', 'silent_status_icons'})
    packages = ranking.findall('package')
    identities = [(x.get('name'), x.get('uid')) for x in packages]
    require(len(identities) == len(set(identities)), 'duplicate stored package preferences')
    own = [x for x in packages if x.get('name') == PACKAGE]
    require(len(own) <= 1 and len(root.findall('.//package[@name="' + PACKAGE + '"]')) == len(own),
            'stranded or misnested notification preference')
    if stage == 'absent' and not own:
        return {'uid': uid, 'package': PACKAGE, 'channels': []}
    package = _one(own, 'stored subject preferences')
    require(package.get('uid') == str(uid), 'stored notification UID')
    _attrs(package, {'name', 'uid', 'show_badge', 'app_user_locked_fields', 'sent_invalid_msg',
                     'sent_valid_msg', 'user_demote_msg_app', 'sent_valid_bubble'},
           {'importance', 'priority', 'visibility', 'allow_bubble'})
    defaults = {'show_badge': 'true', 'app_user_locked_fields': '0', 'sent_invalid_msg': 'false',
                'sent_valid_msg': 'false', 'user_demote_msg_app': 'false', 'sent_valid_bubble': 'false',
                'importance': '-1000', 'priority': '0', 'visibility': '-1000', 'allow_bubble': '0'}
    require(all(package.get(k, v) == v for k, v in defaults.items()),
            'nondefault package wide notification preference')
    require(all(x.tag == 'channel' for x in package), 'group, delegate or other stored preference')
    require(len(root.findall('.//package[@name="' + PACKAGE + '"]')) == 1,
            'misnested selected preference')
    channels = list(package)
    require(len({x.get('id') for x in channels}) == len(channels), 'duplicate stored channel')
    if stage == 'absent':
        require(not channels, 'preexisting channel including deleted state')
        return {'uid': uid, 'package': PACKAGE, 'channels': []}
    channel = _one(channels, 'one stored channel')
    allowed = {'id', 'name', 'importance', 'locked', 'show_badge', 'allow_bubbles', 'orig_imp',
               'visibility', 'priority', 'sound', 'usage', 'content_type', 'flags', 'lights',
               'light_color', 'vibration_enabled', 'vibration', 'vibration_effect', 'fgservice',
               'deleted', 'del_time', 'group', 'blockable_system', 'parent', 'conv_id', 'imp_conv',
               'dem', 'is_bundle', 'emoji', 'desc'}
    _attrs(channel, {'id', 'name', 'importance', 'show_badge'}
           | ({'locked', 'allow_bubbles'} if stage == 'retained' else set()), allowed)
    require(not len(channel), 'channel nesting')
    attrs = dict(channel.attrib)
    required = {'id': CHANNEL, 'name': 'Andrix B2 state', 'importance': '2', 'show_badge': 'true'}
    bubbles, user_lock = notification_preference(stage)
    require(all(attrs[k] == v for k, v in required.items())
            and attrs.get('locked', '0') == str(user_lock)
            and attrs.get('allow_bubbles', '-1') == str(bubbles), 'stored channel preference')
    require(attrs.get('usage', '5') == '5' and attrs.get('content_type', '4') == '4'
            and attrs.get('flags', '0') == '0', 'stored public audio attribute defaults')
    require(attrs.get('orig_imp') == '2' and all(attrs.get(k, v) == v for k, v in {
        'visibility': '-1000', 'priority': '0', 'light_color': '0', 'fgservice': 'false',
        'del_time': '-1'}.items()), 'stored remaining channel defaults')
    require(all(attrs.get(k, default) == default for k, default in {
        'deleted': 'false', 'vibration_enabled': 'false', 'lights': 'false', 'dem': 'false',
        'imp_conv': 'false', 'is_bundle': 'false', 'blockable_system': 'false'}.items()),
        'stored channel changed defaults')
    require(not any(k in attrs for k in ('sound', 'vibration', 'vibration_effect', 'group', 'parent',
                                         'conv_id', 'emoji', 'desc')), 'stored sound or conversation')
    if baseline is not None:
        require(attrs == baseline, 'stored channel baseline changed')
    return {'uid': uid, 'package': PACKAGE, 'channel': attrs, 'decoded_sha256': sha(data)}


def jobs(files, contract, original_due_ms=None, tolerance_ms=60000, initialized=True):
    """files maps actual primary JobStore filenames to decoded XML bytes.

    The vehicle must separately capture AtomicFile siblings and prove selection and stability.
    Never combine main and backup as though they were independent live jobs. Duplicates across
    primary split/legacy files, alternate namespaces, or jobs under this dedicated UID fail.
    """
    validate_contract(contract)
    require(type(initialized) is bool and type(files) is dict and len(files) <= 10000
            and (files or not initialized) and type(tolerance_ms) is int
            and 0 <= tolerance_ms <= 60000, 'complete primary job files')
    identities = set()
    own = []
    for name, data in files.items():
        filename = re.fullmatch(r'jobs(?:_(0|[1-9][0-9]*))?\.xml', name)
        require(filename is not None and (filename[1] is None or int(filename[1]) < 1 << 31),
                'JobStore primary filename')
        root = decoded_root(data, 'job-info')
        require(root.attrib == {'version': '1'}, 'JobStore version')
        _children(root, {'job'})
        for job in root:
            require(filename[1] is None or job.get('uid') == filename[1], 'split file UID mismatch')
            identity = (job.get('uid'), job.get('namespace'), job.get('jobid'))
            require(None not in (identity[0], identity[2]) and identity not in identities,
                    'duplicate stored job across files')
            identities.add(identity)
            if job.get('uid') == str(contract['uid']) or job.get('package') == PACKAGE:
                own.append((name, job))
    if not initialized:
        require(not own, 'preexisting stored job in some namespace')
        return {'uid': contract['uid'], 'jobs': []}
    name, job = _one(own, 'one stored dedicated UID job')
    required = {'jobid': str(JOB_ID), 'uid': str(contract['uid']), 'package': PACKAGE, 'class': SERVICE,
                'sourcePackageName': PACKAGE, 'sourceUserId': '0', 'bias': '0', 'priority': '300',
                'flags': '0', 'lastSuccessfulRunTime': '0', 'lastFailedRunTime': '0',
                'cumulativeExecutionTime': '0'}
    _attrs(job, set(required), {'internalFlags'})
    require(all(job.get(k) == v for k, v in required.items())
            and job.get('internalFlags', '0') == '0', 'stored job identity, flags or run history')
    require([x.tag for x in job] == ['constraints', 'one-off', 'extras'], 'stored one off job shape')
    constraints, timing, extras = list(job)
    require(not constraints.attrib and len(constraints) == 0 and len(timing) == 0
            and set(timing.attrib) == {'delay'}, 'job constraints or timing fields')
    delay = timing.get('delay')
    require(re.fullmatch(r'[1-9][0-9]{0,18}', delay) is not None and int(delay) < 1 << 63
            and type(original_due_ms) is int and abs(int(delay) - original_due_ms) <= tolerance_ms,
            'stored UTC due time')
    require(not extras.attrib, 'extras attributes')
    values = {}
    for item in extras:
        require(item.tag == 'string' and set(item.attrib) == {'name'} and not len(item)
                and item.get('name') not in values, 'duplicate or incorrectly typed job extras')
        values[item.get('name')] = item.text or ''
    require(values == {'andrix.b2.setup': contract['setup'],
                       'andrix.b2.contract_sha256': contract['contract_sha256']}, 'stored job markers')
    return {'file': name, 'uid': contract['uid'], 'jobid': JOB_ID, 'namespace': None,
            'service': SERVICE, 'source_user': 0, 'persisted': True, 'periodic': False,
            'delay_utc_ms': int(delay), 'extras': values, 'flags': 0}
