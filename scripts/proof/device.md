# Provenance-bound `/usr` runtime checks

`device.sh` runs the shared factory-APEX, byte/inode, ARM64/Bionic, read-only `/usr`,
Android `/etc`, enforcing SELinux and relevant-AVC checks against an already booted
fixture. It does not launch/connect a VM, change Android policy, grant permissions,
root adbd or establish hardware attestation.

Supply the **frozen image's** expected APEX, its independently verified/extracted
ELF, and the exact image fingerprint. A device pull cannot serve as its own oracle.
Select the authorized fixture explicitly with `ANDROID_SERIAL`; no signing keys
belong on the runtime host/guest filesystem exposed by the launcher.

## Profiles

- **`legacy-local-rkp` (default):** preserves the earlier Cuttlefish local-keys
  prerequisite: RKP hostname empty and RKP-only `false`, or failure before any
  APEX/payload reads. Existing parser/negative tests and PASS wording remain.
- **`offline-core` and `grapheneos-core` (explicit):** scoped to the GrapheneOS migration product
  `andrix_gos_cf_arm64_only_phone` / `andrix_cf_arm64_only`, Android 17 fingerprint
  family, exact supplied fingerprint equality, matching `ro.product.name`, and
  nonempty `ANDROID_SERIAL`. Unknown profiles and other products fail closed.
  The default profile refuses this migration product, even if RKP properties
  happen to resemble the old local-keys configuration.

Both GrapheneOS core profiles require successful reads of both RKP properties but
record their values as **INFO**, never an RKP-policy PASS. Empty/false values do
not earn policy credit; a nonempty hostname is not a reason to rewrite the guest
or block these narrower core observations. The remaining core oracles are the
same straight-line code in all profiles, not copied or weakened implementations.

```sh
export ANDROID_SERIAL='EXPLICIT_AUTHORIZED_FIXTURE'
export ANDRIX_EXPECTED_FINGERPRINT='EXACT_FROZEN_IMAGE_FINGERPRINT'
export ANDRIX_EXPECTED_APEX='/private/frozen/dev.andrix.usr.apex'
export ANDRIX_EXPECTED_PROOF_ELF='/private/frozen/payload/bin/andrix-hello'
ANDRIX_DEVICE_PROFILE=offline-core scripts/proof/device.sh
```

The profile name declares **claim scope**, not measured network isolation. Use
`offline-core` for the earlier offline procedure, whose caller independently
establishes the isolated namespace, absence of an uplink and capture-before-boot.
Use `grapheneos-core` when checking the same core invariants in a separately
qualified connected fixture. It does not grant network authority or relax any
oracle; network, service and capture results remain separate evidence.
A successful core result says nothing about RKP consumers, TLS/CT delivery, guest
Internet, Google-connection policy, Safe Browsing, phone/carrier support or full
upstream GrapheneOS hardening.

Keep full logs. Run the core check before the ordinary-app negative test, whose
expected denials may match the broad relevant-AVC scan. A prior denial or failed
observer must be retained and classified, not removed merely to obtain PASS.

Host tests exercise legacy gates and the new admission, observation-only and
shared-core negatives with labelled dummy artifacts/fake ADB. Passing them is not
an actual device, signature, isolation or runtime result.
