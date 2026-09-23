# Signing identity and recovery controls

These are observation and host recovery vehicles, not a privileged Android signer or a
personal key provisioner. See the
[scope and qualification](../../plans/2026-09-22-signing-identity-recovery-proof.md).

`ApkIdentityProbe.java` compiles against the pinned `apksigner.jar`. It verifies an APK or
APEX container for one explicitly selected Android SDK level and emits public certificate
and SubjectPublicKeyInfo observations. It does not enumerate complete rotation lineages,
authorize the signer or inspect APKs inside an APEX payload.

`ApkLineageProbe.java` separately reports lineages exposed by successful verification at
one SDK, including per signer targeting and capability declarations. Its scheme flags mean
verified at that SDK, not every signing block present. `apex_inventory.py` checks this schema
and bounded debugfs directory observations. The
[expanded inventory](../../plans/2026-09-23-apex-trust-inventory.md) covers the selected APEX
payloads and their nested regular APKs, not all container formats or installed history.

`signing_identity.py` parses the original exact observation schema, aapt2 manifest identity fields
and certificate MAC selectors. It keeps certificate, public key and AVB encoding hashes
separate. Its supplied tests are parser checks, not cryptographic verification.

`signing_recovery.py` checks a typed public manifest and complete private material set around
an age encrypted file. The expected manifest commitment must arrive through an independently
trusted owner record, not be adopted from the untrusted backup. It waits for complete file
authentication and key matching before returning anything. It does not publish files, import
keys into Android or authorize installation.

`recovery_probe.py` creates disposable RSA identities and a native hybrid age recovery
credential. Run it only with an explicitly private disposable transfer directory outside
the evidence tree. The provisioner must exit before starting the separate recovery process.
The external controller retains public results, checks the exact transfer scope, and retires
the generated recovery credential only after both processes have exited. Do not point this
vehicle at personal or existing project private keys.

The real recovery controls exercise five keys, six uses, challenge signing and seventeen
refusals, including a fresh valid ciphertext with substituted contents and a damaged final
chunk after valid plaintext was emitted by raw age. No partial private output is published.
This is not proof of protected Android custody, atomic provisioning or physical erasure.
The same source also compiled and ran as ordinary Android native age tools in a separate
finite interoperability test. That result likewise does not establish protected signing or
key import. Its directory probe denials and staging observation limit are retained in the
qualification record.

Run the supplied parser/model checks with:

```sh
python3 -B -m unittest scripts.proof.tests.test_signing_identity \
    scripts.proof.tests.test_signing_recovery scripts.proof.tests.test_apex_inventory
```

Real cryptographic controls additionally require the qualified age/age-keygen executables,
OpenSSL and the pinned avbtool. Resource limits, no swap/core dumps, private scratch space
and retained failure records are part of that execution protocol, not properties provided
by the Python codec alone.
