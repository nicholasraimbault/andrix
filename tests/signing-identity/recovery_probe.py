#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable host identities only. Never point this vehicle at personal keys.

The provisioner exits before a separate recovery process starts. Only ciphertext,
a native recovery identity and public owner records cross that boundary. The
vehicle is not an Android protected signer, installer or secure erasure test.
"""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/proof'))
import signing_recovery as sr


def memfd(data):
    fd = os.memfd_create('disposable-signing-input', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise OSError('short write')
            view = view[count:]
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def certificate(tools, key, name):
    fd = memfd(key)
    try:
        return tools._run([tools.openssl, 'req', '-new', '-x509', '-sha256', '-days', '365',
                           '-keyform', 'DER', '-key', '/proc/self/fd/' + str(fd),
                           '-outform', 'DER', '-subj', '/CN=Andrix disposable ' + name + '/'],
                          pass_fds=(fd,))
    finally:
        os.close(fd)


def public_records(root, expected):
    # No private material, recovery identity or decrypted document goes here.
    (root / 'manifest.json').write_bytes(sr.canonical(expected))
    (root / 'expected-manifest.sha256').write_text(sr.validate_manifest(expected) + '\n')


def provision(root, tools):
    for part in ['backup', 'recovery-secret', 'owner-record']:
        (root / part).mkdir(mode=0o700)
    secret_keys = {}; keys = []; uses = []
    for slot, bits, kind, purpose, component in [
            ('platform', 2048, 'certificate', 'apk', 'platform'),
            ('usr-container', 2048, 'certificate', 'apex-container', 'dev.andrix.usr'),
            ('usr-payload', 4096, 'avb', 'apex-payload', 'dev.andrix.usr'),
            ('boot', 4096, 'avb', 'avb', 'root'),
            ('ota', 2048, 'certificate', 'ota-package', 'system')]:
        pem = tools._run([tools.openssl, 'genpkey', '-algorithm', 'RSA',
                          '-pkeyopt', 'rsa_keygen_bits:' + str(bits)])
        pkcs8 = tools._run([tools.openssl, 'pkcs8', '-topk8', '-nocrypt', '-outform', 'DER'], pem)
        certs = [certificate(tools, pkcs8, slot)] if kind == 'certificate' else []
        key = sr.key_description(slot, pkcs8, tools, certs, avb=kind == 'avb')
        secret_keys[slot] = pkcs8; keys.append(key)
        encoding = sr.PURPOSE_ENCODING[purpose]
        blob = base64.b64decode(key['certificates'][0] if certs else key['avb_public_key'])
        uses.append({'purpose': purpose, 'component': component, 'slot': slot,
                     'identity': {'encoding': encoding, 'sha256': sr.digest(blob)}})
        if slot == 'ota':
            uses.append({'purpose': 'ota-payload', 'component': component, 'slot': slot,
                         'identity': {'encoding': 'spki-der',
                                      'sha256': sr.digest(base64.b64decode(key['spki']))}})
    manifest = {'version': 1, 'installation': str(uuid.uuid4()), 'generation': 1,
                'keys': keys, 'uses': uses}
    keygen = tools.age.with_name('age-keygen')
    identity = tools._run([keygen, '-pq'])
    recipient = tools._run([keygen, '-y'], identity).decode().strip()
    encrypted, expected = sr.encrypt_bundle(manifest, secret_keys, recipient, tools)
    (root / 'backup/bundle.age').write_bytes(encrypted)
    (root / 'recovery-secret/identity.txt').write_bytes(identity)
    public_records(root / 'owner-record', manifest)
    (root / 'owner-record/recipient.txt').write_text(recipient + '\n')
    print(json.dumps({'provisioned_disposable_keys': len(keys), 'uses': len(uses),
                      'manifest_sha256': expected, 'bundle_sha256': sr.digest(encrypted),
                      'plaintext_private_keys_written_to_files': False,
                      'recovery_secret_is_private_transfer_material': True}))


def recover(root, evidence, tools):
    before = len(list(Path('/proc/self/fd').iterdir()))
    cipher = (root / 'backup/bundle.age').read_bytes()
    identity = (root / 'recovery-secret/identity.txt').read_bytes()
    expected = (root / 'owner-record/expected-manifest.sha256').read_text().strip()
    manifest = json.loads((root / 'owner-record/manifest.json').read_text())
    recipient = (root / 'owner-record/recipient.txt').read_text().strip()
    recovered = sr.decrypt_bundle(cipher, identity, expected, tools)
    assert recovered.manifest == manifest
    challenge = b'ANDRIX_DISPOSABLE_RECOVERY_PROOF\x00' + expected.encode()
    public = evidence / 'public'; public.mkdir()
    signatures = []
    for entry in manifest['keys']:
        slot = entry['slot']; fd = memfd(recovered.private_keys[slot])
        try:
            signature = tools._run([tools.openssl, 'pkeyutl', '-sign', '-inkey',
                                    '/proc/self/fd/' + str(fd), '-keyform', 'DER',
                                    '-rawin', '-digest', 'sha256'], challenge, pass_fds=(fd,))
        finally:
            os.close(fd)
        spki = base64.b64decode(entry['spki']); (public / (slot + '.spki')).write_bytes(spki)
        (public / (slot + '.signature')).write_bytes(signature)
        tools._run([tools.openssl, 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
                    '-inkey', public / (slot + '.spki'), '-sigfile', public / (slot + '.signature'),
                    '-rawin', '-digest', 'sha256'], challenge)
        signatures.append({'slot': slot, 'spki_sha256': sr.digest(spki),
                           'signature_sha256': sr.digest(signature), 'verified': True})
    (public / 'challenge.bin').write_bytes(challenge)
    public_records(public, manifest)
    (evidence / 'restored-signatures.json').write_text(json.dumps(signatures, indent=2) + '\n')

    cases = []
    def refuse(label, ciphertext, secret=identity, commitment=expected):
        try:
            sr.decrypt_bundle(ciphertext, secret, commitment, tools)
        except sr.RecoveryError as error:
            cases.append({'case': label, 'refused': True, 'reason': str(error)})
        else:
            raise AssertionError('unexpected acceptance: ' + label)
    refuse('wrong-identity', cipher, tools._run([tools.age.with_name('age-keygen'), '-pq']))
    refuse('wrong-expected-inventory', cipher, commitment='0' * 64)
    refuse('truncated-file', cipher[:-1])
    refuse('partial-transfer', cipher[:len(cipher)//2])
    damaged = bytearray(cipher); damaged[-1] ^= 1
    refuse('corrupt-final-tag', bytes(damaged))
    refuse('trailing-ciphertext-data', cipher + b'unexpected')

    original = {'version': 1, 'manifest': manifest,
                'private_keys': {slot: base64.b64encode(key).decode()
                                 for slot, key in recovered.private_keys.items()}}
    def encrypt_untrusted(data):
        # Deliberately bypass the vehicle's export validation. Anyone holding
        # the RECIPIENT PUBLIC KEY can encrypt a new valid age file.
        return tools._run([tools.age, '--encrypt', '--recipient', recipient, '--output', '-'],
                          sr.canonical(data))
    for label in ['missing-key', 'extra-key', 'foreign-private-key', 'invalid-private-key',
                  'changed-purpose', 'changed-generation', 'new-container-version']:
        data = copy.deepcopy(original)
        if label == 'missing-key': del data['private_keys']['boot']
        if label == 'extra-key': data['private_keys']['unrequested'] = data['private_keys']['boot']
        if label == 'foreign-private-key': data['private_keys']['platform'] = data['private_keys']['ota']
        if label == 'invalid-private-key': data['private_keys']['platform'] = 'AA=='
        if label == 'changed-purpose': data['manifest']['uses'][0]['purpose'] = 'ota-package'
        if label == 'changed-generation': data['manifest']['generation'] = 2
        if label == 'new-container-version': data['version'] = 2
        refuse(label, encrypt_untrusted(data))

    data = copy.deepcopy(original)
    replacement = certificate(tools, recovered.private_keys['platform'], 'same key different cert')
    platform = next(key for key in data['manifest']['keys'] if key['slot'] == 'platform')
    assert tools.certificate_spki(replacement) == base64.b64decode(platform['spki'])
    platform['certificates'] = [base64.b64encode(replacement).decode()]
    data['manifest']['uses'][0]['identity']['sha256'] = sr.digest(replacement)
    refuse('same-key-different-certificate', encrypt_untrusted(data))

    # A caller can also supply an internally bad public record. Matching its
    # commitment is not a substitute for deriving every public representation.
    data = copy.deepcopy(original)
    a = next(key for key in data['manifest']['keys'] if key['slot'] == 'usr-payload')
    b = next(key for key in data['manifest']['keys'] if key['slot'] == 'boot')
    a['avb_public_key'] = b['avb_public_key']
    next(use for use in data['manifest']['uses'] if use['purpose'] == 'apex-payload')['identity']['sha256'] = sr.digest(base64.b64decode(b['avb_public_key']))
    refuse('inconsistent-AVB-public-record', encrypt_untrusted(data),
           commitment=sr.validate_manifest(data['manifest']))
    data = copy.deepcopy(original)
    a = next(key for key in data['manifest']['keys'] if key['slot'] == 'platform')
    b = next(key for key in data['manifest']['keys'] if key['slot'] == 'ota')
    a['certificates'] = b['certificates']
    data['manifest']['uses'][0]['identity']['sha256'] = sr.digest(base64.b64decode(b['certificates'][0]))
    refuse('inconsistent-certificate-record', encrypt_untrusted(data),
           commitment=sr.validate_manifest(data['manifest']))

    plaintext = sr.canonical(original) + b' ' * (3 * 65536)
    padded = tools._run([tools.age, '--encrypt', '--recipient', recipient, '--output', '-'], plaintext)
    truncated = padded[:-1]
    fd = sr._identity_fd(identity)
    try:
        direct = subprocess.run([str(tools.age), '--decrypt', '--identity', '/proc/self/fd/' + str(fd),
                                 '--output', '-'], input=truncated, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, pass_fds=(fd,), close_fds=True, timeout=30,
                                env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent'})
    finally:
        os.close(fd)
    assert direct.returncode != 0 and len(direct.stdout) >= len(sr.canonical(original))
    # Record only the byte count, never the private plaintext or its digest.
    partial_count = len(direct.stdout); del direct
    refuse('authenticated-prefix-with-invalid-end', truncated)
    assert len(list(Path('/proc/self/fd').iterdir())) == before
    (evidence / 'controls.json').write_text(json.dumps({
        'cases': cases, 'raw_age_partial_plaintext_bytes': partial_count,
        'partial_plaintext_not_published_or_recorded': True,
        'private_fd_count_preserved': True, 'restored_keys': len(signatures),
        'separate_recovery_process': True,
        'protected_Android_custody_qualified': False}, indent=2) + '\n')
    print(json.dumps({'recovered_and_signed': len(signatures), 'refused_controls': len(cases),
                      'expected_manifest_sha256': expected, 'all_passed': True}))


def main():
    if len(sys.argv) != 7: raise SystemExit('mode private-transfer evidence age openssl avbtool')
    mode, root, evidence, age, openssl, avbtool = sys.argv[1:]
    os.umask(0o077)
    root = Path(root).resolve(strict=True); evidence = Path(evidence).resolve(strict=True)
    assert not root.is_relative_to(evidence) and not evidence.is_relative_to(root)
    assert root.stat().st_mode & 0o077 == 0
    tools = sr.Tools(Path(age), Path(openssl), Path(avbtool))
    if mode == 'provision': provision(root, tools)
    elif mode == 'recover': recover(root, evidence, tools)
    else: raise SystemExit('unknown mode')


if __name__ == '__main__': main()
