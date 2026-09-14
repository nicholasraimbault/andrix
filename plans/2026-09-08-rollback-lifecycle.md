# Rollback lifecycle and checked metadata commits

**Status:** bounded direct-AOSP experiments covered available-record expiry, staged
restoration, metadata reload and refusal to expire an in-flight operation. No
GrapheneOS adoption or power-loss guarantee is implied.

## Technical findings

Rollback dependency retention must survive metadata reload and release dependencies
only when the relevant record/lifecycle permits it. An operation that was requested
or staged is not necessarily committed or applied.

The experiment introduced checked metadata-commit handling rather than assuming an
atomic-file helper had durably completed. Error propagation and rollback state must
remain coherent when metadata persistence fails.

## Verification boundaries

Use actual framework lifecycle APIs and negative controls, not edited state flags or
permission bypasses. Manifest-only package generations do not prove a real browser
version migration. See the [retention milestone](2026-09-07-rollback-retention.md)
and [preserved patch series](../patches/android-17.0.0_r1/README.md).
