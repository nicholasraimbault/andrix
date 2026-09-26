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
