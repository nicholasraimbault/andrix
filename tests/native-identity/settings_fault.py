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
# The two ordinary key observers and the lifecycle record's fixed subject, whose settings row the
# mapping loss guest removes. No other package.
ALLOWED = {'dev.andrix.proof.uidstore', 'dev.andrix.proof.uidstorepeer', 'dev.andrix.proof.principalclosed'}


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


# The keyset references Package Manager counts when it reads settings (Settings.readPackageLPw): a
# package's proper signing keyset and its defined keysets. Upgrade keysets name defined ones.
COUNTED_KEYSET_TAGS = ('proper-signing-keyset', 'defined-keyset')


def _counted_keyset_references(root, skip=None):
    """keyset ID -> the references Package Manager counts, from every element but keyset-settings
    and `skip`."""
    counts = {}
    for child in root:
        if child is skip or child.tag == 'keyset-settings':
            continue
        for node in child.iter():
            if node.tag in COUNTED_KEYSET_TAGS:
                counts[node.get('identifier')] = counts.get(node.get('identifier'), 0) + 1
    return counts


def _remove_unreferenced_keysets(root, candidates):
    """Removes, as KeySetManagerService.removeAppKeySetDataLPw does when a package's last reference
    goes, each candidate keyset that no remaining package counts, and then each public key that no
    remaining keyset holds; the issue counters stay. Returns (removed keyset IDs, removed key IDs)."""
    settings = root.find('keyset-settings')
    counts = _counted_keyset_references(root)
    gone = sorted(k for k in candidates if counts.get(k, 0) == 0)
    if not gone:
        return [], []
    keysets = settings.find('keysets') if settings is not None else None
    elements = {k.get('identifier'): k for k in keysets.findall('keyset')} if keysets is not None else {}
    if any(k not in elements for k in gone):
        raise ValueError('a removed keyset has no definition')
    held = set()
    for keyset in gone:
        held.update(member.get('identifier') for member in elements[keyset].findall('key-id'))
        keysets.remove(elements[keyset])
    still = {member.get('identifier') for keyset in keysets.findall('keyset') for member in keyset.findall('key-id')}
    keys = settings.find('keys')
    removed_keys = []
    for key in list(keys.findall('public-key')) if keys is not None else []:
        if key.get('identifier') in held and key.get('identifier') not in still:
            keys.remove(key)
            removed_keys.append(key.get('identifier'))
    return gone, sorted(removed_keys)


def remove_package(data, package, app_id, orphaned_keysets='refuse'):
    """The settings without one captured fixture package's row and app ID. A row whose signing or
    defined keyset no other package references is refused by default; with orphaned_keysets set to
    'remove-as-android', such keysets and the public keys only they hold are removed with the row,
    exactly as Package Manager's own removal of a package does, and nothing else changes."""
    if orphaned_keysets not in ('refuse', 'remove-as-android'):
        raise ValueError('orphaned keysets are refused or removed as Android removes them')
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
    if any(value is None or not re.fullmatch(r'[0-9]{1,19}', value) for value in removed_keysets | remaining_keysets):
        raise ValueError('removal would orphan signing keysets; use a narrower fixture')
    # Orphans by Package Manager's own count: a keyset the row counts that no remaining package counts.
    # Upgrade references are not counted, so one naming such a keyset would be left dangling.
    after = _counted_keyset_references(root, skip=targets[0])
    candidates = {node.get('identifier') for node in targets[0].iter() if node.tag in COUNTED_KEYSET_TAGS}
    orphans = {k for k in candidates if after.get(k, 0) == 0}
    upgrades = {node.get('identifier') for child in root if child is not targets[0] and child.tag != 'keyset-settings'
                for node in child.iter() if node.tag == 'upgrade-keyset'}
    dangling = {k for k in upgrades if after.get(k, 0) == 0}
    own_upgrades = {node.get('identifier') for node in targets[0].iter() if node.tag == 'upgrade-keyset'}
    if not own_upgrades <= candidates | set(after):
        raise ValueError('the row names an upgrade keyset that no package counts')
    if dangling:
        raise ValueError('another package names an upgrade keyset that would go')
    if orphans and orphaned_keysets == 'refuse':
        raise ValueError('removal would orphan signing keysets; use a narrower fixture')
    if orphans:
        _keysets(root)
        settings = root.find('keyset-settings')
        defined = {k.get('identifier') for k in settings.findall('keysets/keyset')} if settings is not None else set()
        before = _counted_keyset_references(root)
        if any(before.get(k, 0) == 0 for k in defined):
            raise ValueError('the capture already holds a keyset no package references')
    certificates = {id(cert): key for cert, key in decode_certificates(root)}
    root.remove(targets[0])
    gone_keysets, gone_keys = _remove_unreferenced_keysets(root, candidates) if orphans else ([], [])
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
    settings = expected.find('keyset-settings')
    for keyset in list(settings.findall('keysets/keyset')) if settings is not None and gone_keysets else []:
        if keyset.get('identifier') in gone_keysets:
            settings.find('keysets').remove(keyset)
    for key in list(settings.findall('keys/public-key')) if settings is not None and gone_keys else []:
        if key.get('identifier') in gone_keys:
            settings.find('keys').remove(key)
    for cert in expected.iter('cert'):
        cert.attrib.pop('index', None); cert.set('key', original_certs[id(cert)])
    if semantic(ET.fromstring(output)) != canonical_tree(expected):
        raise ValueError('unrelated settings semantics changed')
    return output, {'removed_package': package, 'app_id': app_id,
                    'input_sha256': hashlib.sha256(data).hexdigest(),
                    'output_sha256': hashlib.sha256(output).hexdigest(),
                    'retained_certificate_elements': len(retained),
                    'removed_keysets_still_referenced': not orphans,
                    'removed_unreferenced_keysets': gone_keysets, 'removed_unreferenced_public_keys': gone_keys,
                    'identity_authority': False, 'runtime_qualified': False}
