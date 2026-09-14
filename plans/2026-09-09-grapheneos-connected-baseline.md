# Connected GrapheneOS foundation

**Status:** bounded emulator checks exercised core/native isolation, ordinary WebView
HTTPS, time/CT consumers and reboot on the adopted GrapheneOS base. This is not full
network-policy, hardware-attestation or phone qualification.

## Product findings

The emulator's virtual SIM required the existing sample APN input. Add it only to
the emulator product; do not generalize it into Pixel carrier/vendor configuration.
Retain upstream application signing, package update identity and genuine provisioning
paths. The browser's tested blank page was not established as a defect on supported
GrapheneOS devices.

## Verification boundaries

Apply the [accepted direct-client networking policy](../docs/architecture.md).
Do not manufacture quiet captures with destination blackholes, fake successful
clients or disabled security consumers. Reachable conditional app behavior requires
its own controls; source inventory and one workload's observed traffic are distinct.

Preserve TLS/hostname checks, signed CT input freshness, ordinary application identity
and real security-consumer outcomes. Software provisioning in an emulator is not
hardware-backed attestation proof. See [network tooling](../docs/proof-network.md),
[policy review](../docs/grapheneos-connected-policy-review.md) and
[current work](current.md).
