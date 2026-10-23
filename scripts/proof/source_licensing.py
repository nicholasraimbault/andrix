# SPDX-License-Identifier: Apache-2.0
"""Exact licence-only predecessors for historical source comparisons.

These are checked source identities, not a general SPDX/comment normalization rule.
Historical generators still read their original Git objects. No execution result or
historical prediction is rebound to newly licensed bytes by these helpers.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
BASELINE = '3bbf6b9a4637c14117b223a7d6b0d5cb3e183794'
BEFORE_HEADER = b'// SPDX-License-Identifier: Apache-2.0\n'
AFTER_HEADER = b'// SPDX-License-Identifier: GPL-3.0-or-later\n'

# path: (pre-licensing SHA256, licensed SHA256), both exact complete file bodies.
SOURCE_PAIRS = {
    'owner/platform/framework/CeStorageAccessTracker.java': (
        '49d892ba32cc0cb4828fbd0eb48cc8c072d48a14eea3c36564be2c8da93dbcd8',
        '5e8d59e76d9851f1a1dc50befc513f217ef9b2297ae89342376823fcbd15c577'),
    'owner/platform/framework/NativeIdentityPersistence.java': (
        'a3d6d23e3378611f6d82df07a4ede7ba7949f1f69cc24873a788a64d24e1604b',
        'f177c04290a20523f49ba00ed2913bee67abcb797791f23b7fb92037b21788a5'),
    'owner/platform/framework/NativeIdentityRecords.java': (
        '4be9c8a0135d3793bb4153e9dc794c2afbf6e4bdbc3466d447b883fe30e0b032',
        '50d1ff4869fe670658dd1e750eccd600ac0552ca590498cfc2b9f731e1f7b9a5'),
    'owner/platform/framework/NativeIdentityStore.java': (
        'ebcbf4a43281bf02b0e367831518778c96ef34f15edee034229aacd437c5247b',
        '386515606f1e5d2c8b94eb7e3b828c480d74a144639c4b4fe565cdd3db2c34c8'),
    'owner/platform/framework/NativePrincipalManager.java': (
        '7c76194cc441507f2ffe8224f6e9e4d013b6fabadde56723430fd18d17f6fcee',
        '03663dba3cd66286bfa8454cb89a92cc324b4e620a3dea35fc6b3e0c9a21e4be'),
    'owner/platform/framework/NativePrincipalPins.java': (
        'c8b58f864fedb0fc522bdb622b9dee150a3407d967b2f703011fcb1b2de4401b',
        'd782f3d32831f7025750c534b9d0e2fc57eff97b16f79dcf51145a48411b1dbc'),
    'owner/platform/framework/NativePrincipalPinsXml.java': (
        '41a3e354442ce90252e3c21dda375f1b77489c04fe36d5b4bc1ec778c979364c',
        '929f38a886f6746627b4a97e08802b18e7bd467baec9ff9842d092291a81022a'),
    'owner/platform/framework/NativePrincipalRecovery.java': (
        'e6370a2bc822c78602c97b3a04803916184095a6dc796d1360a48b47791fbda8',
        '24736c91ebba8587f7db450fefbd834e84c8992837743aaa14d779c3853c9b59'),
}

# Exact current producer recipes; historical profile bytes remain separately identified.
PROFILE_PAIRS = {
    'patches/grapheneos-2026081300/native-principal-pins.json': (
        '55afa1c42ebb0b82f87944a82ff3a7cfbb7ec248c6db3eee87bc8a606c6d8081',
        'e72d3875ccfe3f1c16963b61816052fb749b45ccb916fb26535a6e0c77ce8eab'),
    'patches/grapheneos-2026081300/owner-lifecycle.json': (
        '657d3ccf5ea4f261c63a8707a606f1caba4b04eb10572ea6e0092b0b75db97a2',
        '7aca5107e5d2b3da5c7a77852f15d8e5d4aeaa1a208a4b3d570443bab1db29cb'),
    'patches/grapheneos-2026100600/native-principal-pins.json': (
        '163fbd55411359b0434e4aab9c75b43dbee48398f5fb280dc1d47ec4053c80ae',
        'abfb4f12e3c3324b97717b0b6824fbd149fc993a96193dacc87099ef6838eb0d'),
    'patches/grapheneos-2026100600/owner-lifecycle.json': (
        'a78c7d5a03320b3557528f7523f3415134412dc75af61fe10ebd65f4f094e2a4',
        '9b8a7d89209a01e9e6d527265ef240e60e9af3541ad23a60582423589c2ee7f7'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def predecessor_bytes(path, data):
    """Accept only an exact pinned original or its one pinned SPDX-only successor."""
    if path not in SOURCE_PAIRS:
        raise ValueError('unmapped licensing source: ' + path)
    before, after = SOURCE_PAIRS[path]
    digest = sha(data)
    if digest == before:
        return data
    if digest != after or not data.startswith(AFTER_HEADER):
        raise ValueError('licensing source drift: ' + path)
    original = BEFORE_HEADER + data[len(AFTER_HEADER):]
    if sha(original) != before:
        raise ValueError('licensing predecessor drift: ' + path)
    return original


def predecessor_profile(path, data, root=ROOT):
    """Verify current recipe/helpers, then recover only the exact pre-licensing recipe.

    This view is for historical comparisons. Current builds keep the current profile,
    and historical predictions and compiled inputs are not rewritten.
    """
    if path not in PROFILE_PAIRS:
        raise ValueError('unmapped licensing profile: ' + path)
    before, after = PROFILE_PAIRS[path]
    if sha(data) != after:
        raise ValueError('licensing profile drift: ' + path)
    value = json.loads(data)
    added = value['added']
    rows = added if isinstance(added, list) else [added]
    original = data
    for row in rows:
        source = row['source']
        if source not in SOURCE_PAIRS:
            raise ValueError('unmapped licensing helper: ' + source)
        old_digest, new_digest = SOURCE_PAIRS[source]
        current = (root / source).read_bytes()
        if row['sha256'] != new_digest or sha(current) != new_digest:
            raise ValueError('licensing helper drift: ' + source)
        if sha(predecessor_bytes(source, current)) != old_digest:
            raise ValueError('licensing helper predecessor drift: ' + source)
        token = new_digest.encode('ascii')
        if original.count(token) != 1:
            raise ValueError('licensing helper digest occurrence: ' + source)
        original = original.replace(token, old_digest.encode('ascii'), 1)
    if sha(original) != before:
        raise ValueError('licensing profile predecessor drift: ' + path)
    return json.loads(original)
