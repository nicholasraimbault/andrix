# Offline ARM64 QEMU smoke

**Status:** the direct-AOSP prototype booted under ARM64 CPU emulation and passed
bounded signed-APEX, read-only `/usr`, native execution and ordinary-app boundary
checks. This is a historical functional result, not native ARM/KVM or phone qualification.

## Method

Use a frozen image set and its matching host tools. Keep guest security enforcement
on, disable optional reporting/exposure, isolate guest networking, and never mount
signing keys or the platform build tree into the guest. Inspect generated VM settings
rather than assuming requested flags took effect.

A failed boot or helper is not an isolation-denial pass. Establish positive controls
in the same test scope, and preserve diagnostic detail privately.

Connected networking, supported hardware, suspend, pressure and release/update behavior
remain separate gates. See [artifact handling](../docs/development-artifacts.md) and
[current work](current.md).
