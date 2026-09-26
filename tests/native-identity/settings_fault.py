#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remove one known ordinary test package from decoded PMS XML. Disposable fault input only.

Input is a captured, decoded packages.xml from the fixture guest. This is not a production
migration or identity recovery tool. Reindex certificates so another package never loses a
shared certificate definition when the removed package was its first writer.
"""
import copy
import hashlib
import re
import xml.etree.ElementTree as ET

MAX_BYTES = 16 * 1024 * 1024
ALLOWED = {'dev.andrix.proof.uidstore', 'dev.andrix.proof.uidstorepeer'}


def decode_certificates(root):
    table = []
    values = []
    for cert in root.iter('cert'):
        index = cert.get('index', '')
        if not re.fullmatch(r'0|[1-9][0-9]{0,5}', index):
            raise ValueError('certificate index')
        index = int(index)
        key = cert.get('key')
        if key is None:
            if index >= len(table):
                raise ValueError('undefined certificate reference')
            key = table[index]
        else:
            if (index != len(table) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,16384}', key)):
                raise ValueError('noncanonical certificate definition')
            key = key.lower()
            table.append(key)
        values.append((cert, key))
    return values


def canonical_tree(root):
    for node in root.iter():
        ordered = sorted(node.attrib.items())
        node.attrib.clear(); node.attrib.update(ordered)
    return ET.tostring(root, encoding='utf-8')


def semantic(root):
    value = copy.deepcopy(root)
    for cert, key in decode_certificates(value):
        cert.attrib.pop('index', None)
        cert.set('key', key)
    return canonical_tree(value)


def _decoded_root(data):
    if (type(data) is not bytes or not 0 < len(data) <= MAX_BYTES
            or b'<!DOCTYPE' in data or b'<!ENTITY' in data or data.startswith(b'ABX')):
        raise ValueError('fresh decoded XML required')
    root = ET.fromstring(data)
    if root.tag != 'packages':
        raise ValueError('package settings root')
    return root


def _expand(root):
    for cert, key in decode_certificates(root):
        cert.attrib.pop('index', None)
        cert.set('key', key)
    return root


def _encode_expanded(root):
    result = copy.deepcopy(root)
    assigned = {}
    for cert in result.iter('cert'):
        key = cert.get('key')
        if key in assigned:
            cert.set('index', str(assigned[key])); cert.attrib.pop('key', None)
        else:
            assigned[key] = len(assigned)
            cert.set('index', str(assigned[key]))
    output = ET.tostring(result, encoding='utf-8', xml_declaration=True)
    if semantic(ET.fromstring(output)) != canonical_tree(copy.deepcopy(root)):
        raise ValueError('certificate reindex changed settings semantics')
    return output


def _insert_before_keysets(root, package):
    keysets = [node for node in root if node.tag == 'keyset-settings']
    if len(keysets) > 1:
        raise ValueError('duplicate keyset settings')
    root.insert(list(root).index(keysets[0]) if keysets else len(root), package)


def rewrite_equivalent(data, token=None, move_package=None):
    """Parser control. Optional fixture reordering exercises certificate reindexing, not state loss."""
    root = _expand(_decoded_root(data))
    if move_package is not None:
        if move_package not in ALLOWED:
            raise ValueError('only a fixture package may be reordered')
        packages = [node for node in root if node.tag == 'package' and node.get('name') == move_package]
        if len(packages) != 1 or packages[0].get('sharedUserId') is not None:
            raise ValueError('ordinary fixture package required')
        root.remove(packages[0])
        _insert_before_keysets(root, packages[0])
    if token is not None:
        if type(token) is not str or not re.fullmatch(r'[0-9a-f]{32}', token):
            raise ValueError('fresh parser witness token')
        if any(node.tag.startswith('andrix-fixture-parse-') for node in root):
            raise ValueError('earlier parser witness is not a fresh PMS capture')
        ET.SubElement(root, 'andrix-fixture-parse-' + token)
    return _encode_expanded(root)


def _keysets(root):
    settings = root.find('keyset-settings')
    if settings is None:
        return {}
    keys, sets = {}, {}
    for key in settings.findall('keys/public-key'):
        identifier, value = key.get('identifier'), key.get('value')
        if identifier is None or value is None or identifier in keys:
            raise ValueError('public keyset key definitions')
        keys[identifier] = value
    for keyset in settings.findall('keysets/keyset'):
        identifier = keyset.get('identifier')
        members = [key.get('identifier') for key in keyset.findall('key-id')]
        if (identifier is None or identifier in sets or not members or len(set(members)) != len(members)
                or any(key not in keys for key in members)):
            raise ValueError('keyset definition')
        sets[identifier] = tuple(sorted(keys[key] for key in members))
    return sets


def restore_package(current_data, original_data, package, app_id):
    """Reinsert only the original fixture element into CURRENT XML, never restore an old database."""
    if package not in ALLOWED or type(app_id) is not int or not 10000 <= app_id <= 19999:
        raise ValueError('captured fixture identity required')
    current, original = _decoded_root(current_data), _decoded_root(original_data)
    target = [node for node in original if node.tag == 'package' and node.get('name') == package]
    if (len(target) != 1 or target[0].get('userId') != str(app_id)
            or target[0].get('sharedUserId') is not None):
        raise ValueError('original fixture element identity')
    for node in current.iter():
        if node.get('userId') == str(app_id) or node.get('sharedUserId') == str(app_id):
            raise ValueError('current app ID already occupied')
        if node.tag in ('package', 'updated-package', 'shared-user') and node.get('name') == package:
            raise ValueError('current package name already occupied')
    reference_tags = {'proper-signing-keyset', 'defined-keyset', 'upgrade-keyset'}
    references = {node.get('identifier') for node in target[0].iter() if node.tag in reference_tags}
    old_sets, new_sets = _keysets(original), _keysets(current)
    for key in references:
        if key not in old_sets or key not in new_sets or old_sets[key] != new_sets[key]:
            raise ValueError('original signing keyset is missing or changed')
    expected_current = semantic(current)
    _expand(current); _expand(original)
    target = next(node for node in original if node.tag == 'package' and node.get('name') == package)
    inserted = copy.deepcopy(target)
    # KeySetManager consumes the accumulated references when it reads keyset-settings.
    # Appending after that element would undercount A even if the XML were well formed.
    _insert_before_keysets(current, inserted)
    output = _encode_expanded(current)
    check = _expand(ET.fromstring(output))
    restored = [node for node in check if node.tag == 'package' and node.get('name') == package]
    if len(restored) != 1 or canonical_tree(copy.deepcopy(restored[0])) != canonical_tree(copy.deepcopy(inserted)):
        raise ValueError('restored element differs from its original binding')
    check.remove(restored[0])
    if canonical_tree(check) != expected_current:
        raise ValueError('repair changed unrelated current settings')
    return output, {'restored_package': package, 'app_id': app_id,
                    'current_input_sha256': hashlib.sha256(current_data).hexdigest(),
                    'original_input_sha256': hashlib.sha256(original_data).hexdigest(),
                    'output_sha256': hashlib.sha256(output).hexdigest(),
                    'current_unrelated_settings_preserved': True,
                    'separate_user_or_permission_files_restored': False,
                    'app_data_or_keys_restored': False, 'runtime_qualified': False}


def remove_package(data, package, app_id):
    if (type(data) is not bytes or not 0 < len(data) <= MAX_BYTES
            or b'<!DOCTYPE' in data or b'<!ENTITY' in data or data.startswith(b'ABX')):
        raise ValueError('fresh decoded XML required')
    if package not in ALLOWED or type(app_id) is not int or not 10000 <= app_id <= 19999:
        raise ValueError('only a captured ordinary fixture subject may be removed')
    root = ET.fromstring(data)
    if root.tag != 'packages':
        raise ValueError('package settings root')
    targets = [child for child in root if child.tag == 'package' and child.get('name') == package]
    if len(targets) != 1 or targets[0].get('userId') != str(app_id) or targets[0].get('sharedUserId') is not None:
        raise ValueError('exact fixture package/app ID not found')
    reference_tags = {'proper-signing-keyset', 'defined-keyset', 'upgrade-keyset'}
    removed_keysets = {node.get('identifier') for node in targets[0].iter() if node.tag in reference_tags}
    remaining_keysets = {node.get('identifier') for child in root if child is not targets[0]
                         for node in child.iter() if node.tag in reference_tags}
    if (any(value is None or not re.fullmatch(r'[0-9]{1,19}', value) for value in removed_keysets)
            or not removed_keysets <= remaining_keysets):
        raise ValueError('removal would orphan signing keysets; use a narrower fixture')
    certificates = {id(cert): key for cert, key in decode_certificates(root)}
    root.remove(targets[0])
    # Expand before reindexing so no output certificate refers to the deleted node.
    retained = [(cert, certificates[id(cert)]) for cert in root.iter('cert')]
    assigned = {}
    for cert, key in retained:
        if key in assigned:
            cert.set('index', str(assigned[key])); cert.attrib.pop('key', None)
        else:
            assigned[key] = len(assigned)
            cert.set('index', str(assigned[key])); cert.set('key', key)
    output = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    # The expected semantic tree contains all original surviving nodes and cert bytes.
    expected = ET.fromstring(data)
    original_certs = {id(cert): key for cert, key in decode_certificates(expected)}
    for child in list(expected):
        if child.tag == 'package' and child.get('name') == package:
            expected.remove(child)
    for cert in expected.iter('cert'):
        cert.attrib.pop('index', None); cert.set('key', original_certs[id(cert)])
    if semantic(ET.fromstring(output)) != canonical_tree(expected):
        raise ValueError('unrelated settings semantics changed')
    return output, {'removed_package': package, 'app_id': app_id,
                    'input_sha256': hashlib.sha256(data).hexdigest(),
                    'output_sha256': hashlib.sha256(output).hexdigest(),
                    'retained_certificate_elements': len(retained),
                    'removed_keysets_still_referenced': True,
                    'identity_authority': False, 'runtime_qualified': False}
