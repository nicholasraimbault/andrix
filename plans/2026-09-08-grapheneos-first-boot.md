# GrapheneOS-derived ARM64 image and offline boot

**Status:** bounded offline emulator checks passed for the GrapheneOS-derived
foundation, authenticated `/usr`, native execution, ordinary-app isolation and
normal reboot. This is not connected privacy or supported-Pixel qualification.

## Verification method

Build a complete product and matching host package. Inspect extracted images for
APEX activation, init configuration, identities, linker metadata and read-only `/usr`.
Rehash frozen inputs before each new guest; do not invent placeholders to match an
older product's file count or boot mutable output.

Use the ordinary application boundary probe with same-scope positive controls.
A failed observer or missing target is not a denial pass. Test reboot as a separate
lifecycle event rather than inferring it from process disappearance.

## Follow-up

The [UI milestone](2026-09-09-grapheneos-ui.md) addresses emulator-profile behavior;
the [connected baseline](2026-09-09-grapheneos-connected-baseline.md) addresses Android
network consumers. Runtime configuration, raw traces and detailed receipts remain
private operator evidence.
