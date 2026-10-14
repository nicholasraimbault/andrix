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


KEYSET_REFERENCE_TAGS = ('proper-signing-keyset', 'defined-keyset', 'upgrade-keyset')


def _counted_keyset_references(root, skip=None):
    """keyset ID -> the references Package Manager counts: the proper signing and defined keysets
    that are immediate children of each top level package row (Settings.readPackageLPw), but `skip`."""
    counts = {}
    for child in root:
        if child is skip or child.tag != 'package':
            continue
        for node in child:
            if node.tag in COUNTED_KEYSET_TAGS:
                counts[node.get('identifier')] = counts.get(node.get('identifier'), 0) + 1
    return counts


# The tree KeySetManagerService.writeKeySetManagerServiceLPr writes under keyset-settings, in order.
KEYSET_SETTINGS_TREE = ('keys', 'keysets', 'lastIssuedKeyId', 'lastIssuedKeySetId')


def _long_id(value):
    """An identifier as the writer's attributeLong leaves it: canonical decimal, within a long."""
    return type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,18}', value) is not None and int(value) < 1 << 63


def _positive_id(value):
    """An app ID as the writer's attributeInt leaves it: canonical decimal, positive, within an int."""
    return type(value) is str and re.fullmatch(r'[1-9][0-9]{0,9}', value) is not None and int(value) < 1 << 31


# The elements Settings.writeLPr writes under <packages>, and those of them it writes empty, which the
# reader's loop reads by their attributes without consuming what is below them (readSettingsLPw).
WRITER_ELEMENTS = ('version', 'verifier', 'permission-trees', 'permissions', 'package', 'updated-package', 'shared-user',
                   'renamed-package', 'domain-verifications', 'domain-verifications-legacy', 'keyset-settings')
WRITER_EMPTY = ('version', 'verifier', 'renamed-package')
UUID_FORM = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def _check_writer_structure(root):
    """Refuses settings with an element outside the places Package Manager's writer puts it, where its
    reader would read it differently from this module: an element under <packages> the writer does
    not write (the reader skips it), a child of an element the writer writes empty (the reader's loop
    reads what is below it as if it stood under <packages>), a certificate outside a package's or a
    shared user's signatures (PackageSignatures.writeXml writes each cert in sigs, in
    install-initiator-sigs or in their pastSigs; the reader takes certificates only from those, up to
    their count), signatures whose count is not their certificates', and a shared user without a
    name and a positive app ID of its own (readSharedUserLPw, addSharedUserLPw)."""
    rows = list(root)
    for row in rows:
        if row.tag not in WRITER_ELEMENTS:
            raise ValueError('an element the settings writer never writes: %s' % row.tag)
        if row.tag in WRITER_EMPTY and len(row):
            raise ValueError('an element the settings writer writes empty holds others: %s' % row.tag)
    parent = {id(child): node for node in root.iter() for child in node}
    top = {id(row) for row in rows}
    for node in root.iter():
        if node.tag in ('sigs', 'install-initiator-sigs'):
            holder = parent.get(id(node))
            places = ('package', 'shared-user') if node.tag == 'sigs' else ('package',)
            past = [x for x in node if x.tag == 'pastSigs']
            if (holder is None or id(holder) not in top or holder.tag not in places
                    or any(x.tag not in ('cert', 'pastSigs') for x in node) or len(past) > 1):
                raise ValueError('signatures outside the places the settings writer writes them')
        elif node.tag == 'pastSigs':
            holder = parent.get(id(node))
            if holder is None or holder.tag not in ('sigs', 'install-initiator-sigs') or any(x.tag != 'cert' for x in node):
                raise ValueError('past signatures outside the places the settings writer writes them')
        elif node.tag == 'cert':
            if parent.get(id(node)) is None or parent[id(node)].tag not in ('sigs', 'install-initiator-sigs', 'pastSigs') or len(node):
                raise ValueError('a certificate outside the signatures the settings writer writes')
        if node.tag in ('sigs', 'install-initiator-sigs', 'pastSigs'):
            count = node.get('count')
            if not (count == '0' or _positive_id(count)) or int(count) != sum(1 for x in node if x.tag == 'cert'):
                raise ValueError('signatures whose count is not their certificates')
    names, ids = set(), set()
    for row in rows:
        if row.tag == 'shared-user':
            if not row.get('name') or row.get('name') in names or not _positive_id(row.get('userId')) or row.get('userId') in ids:
                raise ValueError('a shared user the settings reader does not admit as the writer leaves it')
            names.add(row.get('name'))
            ids.add(row.get('userId'))


def _check_package_rows(rows):
    """Refuses a package row that Package Manager's reader skips, so that its keyset references would
    never be counted. The writer (Settings.writePackageLPr) always writes a row's name and code
    path, and its app ID as userId or, for a shared user's package, as sharedUserId; the reader
    (readPackageLPw) skips a row without a name or code path, with neither a positive userId nor a
    positive sharedUserId, or whose name or ordinary app ID an earlier row already holds
    (addPackageLPw). The writer's rows also name each package once, and a shared user it defines."""
    shared = {row.get('userId') for row in rows if row.tag == 'shared-user'}
    names, ordinary = set(), set()
    for row in rows:
        if row.tag != 'package':
            continue
        user, shared_user = row.get('userId'), row.get('sharedUserId')
        # The writer always writes the row's domain set as a UUID, which the reader parses
        # (UUID.fromString) and fails the whole file on otherwise.
        if (not row.get('name') or not row.get('codePath') or (user is None) == (shared_user is None)
                or re.fullmatch(UUID_FORM, row.get('domainSetId') or '') is None
                or not _positive_id(user if shared_user is None else shared_user) or row.get('name') in names
                or (user is not None and (user in ordinary or user in shared)) or (shared_user is not None and shared_user not in shared)):
            raise ValueError("a package row Package Manager's reader skips or the writer never leaves")
        names.add(row.get('name'))
        if user is not None:
            ordinary.add(user)


def _check_keyset_shape(root):
    """Refuses settings whose keysets Package Manager's writer does not leave, in either mode.

    What remove_package claims holds for settings Package Manager's own writer wrote, such as a
    decoded capture of a guest's packages.xml: there it removes what Android's removal of the package
    removes. These checks are a second line, refusing the shapes they name; they are not a complete
    model of the settings reader, and settings no writer wrote are outside the claim.

    Settings.writeLPr writes a package row's keyset references as its immediate children: one
    proper-signing-keyset, its upgrade keysets and one defined-keyset per alias
    (writeSigningKeySetLPr, writeUpgradeKeySetsLPr, writeKeySetAliasesLPr).
    KeySetManagerService.writeKeySetManagerServiceLPr then writes keyset-settings once, last: a
    version, keys holding public-key elements, keysets holding keyset elements of key-id elements,
    and the two issue counters, every identifier a canonical decimal long. This matters because
    Package Manager's readers take any element below theirs by name at any depth (readKeysLPw,
    readKeySetListLPw), and the package reader counts every proper-signing-keyset and
    defined-keyset element (readPackageLPw) while a removal takes back one signing keyset and one
    keyset per alias (removeAppKeySetDataLPw). Any other shape could make Package Manager's keysets
    or counts differ from the ones seen here.

    Admitted: that tree, every package row one the reader admits (_check_package_rows), with at most
    one proper-signing-keyset in a row (a row without one counts nothing) and distinct defined keyset
    aliases; every reference naming a defined keyset; every
    keyset's key IDs naming defined public keys; every defined keyset counted by some row. A public
    key no keyset holds is admitted, and a removal never touches it. Everything else is refused,
    including a defined keyset no row counts, which Package Manager reports as a terrible failure
    and removes when it reads its settings (addRefCountsFromSavedPackagesLPw)."""
    rows = list(root)
    settings = [child for child in rows if child.tag == 'keyset-settings']
    if len(settings) != 1 or rows[-1] is not settings[0]:
        raise ValueError('not the one final keyset-settings element the writer leaves')
    _check_writer_structure(root)
    _check_package_rows(rows)
    tree = list(settings[0])
    if (settings[0].get('version') is None or [child.tag for child in tree] != list(KEYSET_SETTINGS_TREE)
            or any(len(counter) or not _long_id(counter.get('value')) for counter in tree[2:])
            or any(key.tag != 'public-key' or len(key) or not _long_id(key.get('identifier')) for key in tree[0])
            or any(keyset.tag != 'keyset' or not _long_id(keyset.get('identifier'))
                   or any(member.tag != 'key-id' or len(member) or not _long_id(member.get('identifier')) for member in keyset)
                   for keyset in tree[1])):
        raise ValueError('keyset-settings is not the tree the writer leaves')
    # Distinct key and keyset identifiers, each keyset's key IDs defined, none empty or repeated.
    _keysets(root)
    references = set()
    for child in rows:
        if child.tag == 'package':
            for node in child:
                if node.tag in KEYSET_REFERENCE_TAGS:
                    if not _long_id(node.get('identifier')):
                        raise ValueError('a keyset reference identifier the writer does not leave')
                    references.add(node.get('identifier'))
                if any(inner.tag in KEYSET_REFERENCE_TAGS for inner in node.iter() if inner is not node):
                    raise ValueError('a keyset reference nested below a package row')
            aliases = [node.get('alias') for node in child if node.tag == 'defined-keyset']
            if (sum(1 for node in child if node.tag == 'proper-signing-keyset') > 1
                    or None in aliases or len(set(aliases)) != len(aliases)):
                raise ValueError('a package row whose keyset references Package Manager would count otherwise')
        elif any(node.tag in KEYSET_REFERENCE_TAGS for node in child.iter()):
            raise ValueError('a keyset reference outside a package row')
    defined = {keyset.get('identifier') for keyset in tree[1]}
    if not references <= defined:
        raise ValueError('a keyset reference names no defined keyset')
    counts = _counted_keyset_references(root)
    if any(counts.get(k, 0) == 0 for k in defined):
        raise ValueError('the capture already holds a keyset no package references')


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
    """The settings without one captured fixture package's row and app ID. Only the keyset shapes
    Package Manager's writer leaves are admitted, in either mode (_check_keyset_shape): one final
    keyset-settings element in the writer's tree, every keyset reference an immediate child of a top
    level package row naming a defined keyset, and every defined keyset counted by one. A row whose
    signing or defined keyset no other package row counts is refused by default; with
    orphaned_keysets set to 'remove-as-android', such keysets and the public keys only they hold are
    removed with the row, as Package Manager's own removal of a package does, and nothing else
    changes. A row removed with its own keysets cannot be put back by restore_package, which needs
    them."""
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
    # In either mode: the keysets as Package Manager's writer leaves them, before anything is removed.
    _check_keyset_shape(root)
    reference_tags = {'proper-signing-keyset', 'defined-keyset', 'upgrade-keyset'}
    removed_keysets = {node.get('identifier') for node in targets[0] if node.tag in reference_tags}
    remaining_keysets = {node.get('identifier') for child in root if child is not targets[0] and child.tag == 'package'
                         for node in child if node.tag in reference_tags}
    if any(value is None or not re.fullmatch(r'[0-9]{1,19}', value) for value in removed_keysets | remaining_keysets):
        raise ValueError('removal would orphan signing keysets; use a narrower fixture')
    # Orphans by Package Manager's own count: a keyset the row counts that no remaining package counts.
    # Upgrade references are not counted, so one naming such a keyset would be left dangling.
    after = _counted_keyset_references(root, skip=targets[0])
    candidates = {node.get('identifier') for node in targets[0] if node.tag in COUNTED_KEYSET_TAGS}
    orphans = {k for k in candidates if after.get(k, 0) == 0}
    upgrades = {node.get('identifier') for child in root if child is not targets[0] and child.tag == 'package'
                for node in child if node.tag == 'upgrade-keyset'}
    dangling = {k for k in upgrades if after.get(k, 0) == 0}
    own_upgrades = {node.get('identifier') for node in targets[0] if node.tag == 'upgrade-keyset'}
    if not own_upgrades <= candidates | set(after):
        raise ValueError('the row names an upgrade keyset that no package counts')
    if dangling:
        raise ValueError('another package names an upgrade keyset that would go')
    if orphans and orphaned_keysets == 'refuse':
        raise ValueError('removal would orphan signing keysets; use a narrower fixture')
    if orphans:
        _keysets(root)
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
