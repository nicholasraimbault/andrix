# Phase 1 — authenticated `/usr` on direct AOSP 17

**Status:** historical foundation demonstrated in the ARM64 emulator. The later
[GrapheneOS migration](2026-09-08-grapheneos-migration.md) is the adopted base; this
milestone is not authority to mix platform source generations.

## Scope

Build an ARM64-only Android image with a signed, non-flattened `dev.andrix.usr`
APEX. Run the packaged Bionic executable through both its APEX path and the read-only
`/usr` view. Android retains its linker, init, identities, services and `/etc`.

## Result and boundaries

The bounded emulator checks established authenticated APEX contents, native execution,
read-only `/usr`, SELinux enforcement and ordinary-application execution isolation.
They do not establish supported-phone behavior, native ARM/KVM performance, complete
network-policy compliance, production signing or update recovery.

## Reusable verification sequence

1. Authenticate an exact platform source generation and reject undeclared changes.
2. Build and inspect the signed APEX, ELF ABI/linker metadata and payload manifest.
3. Build a complete image and freeze matching images and host tools.
4. Verify boot, APEX activation and exact packaged executable behavior.
5. Exercise ordinary-app negatives with live positive controls.
6. Record scoped product outcomes separately from private execution evidence.

See [source provenance](../docs/source-provenance.md), the
[architecture](../docs/architecture.md), [proof tooling](../scripts/proof/device.md)
and [artifact handling](../docs/development-artifacts.md).
