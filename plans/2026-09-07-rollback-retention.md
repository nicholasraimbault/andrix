# Android rollback static-library retention

**Status:** bounded direct-AOSP tests demonstrated dependency retention through
pruning and reboot, plus automatic consumer recovery. This remains distinct from
adoption into the current GrapheneOS base.

## Implementation

An available consumer rollback may still require an otherwise-unused static library.
Retain the exact referenced library while that rollback record exists. A manual
signed-library reinstall is a useful control, not a replacement for automatic
retention and recovery.

## Verification boundary

Exercise normal removal and free-storage pruning, persistence through reboot, and
actual PackageWatchdog-triggered recovery with the prerequisite retained. Distinguish
request acceptance, rollback availability and successful application of the rollback.

The [lifecycle follow-up](2026-09-08-rollback-lifecycle.md) examines expiry, staged
restoration and checked metadata commits. Broader version migration and power-loss
behavior remain unqualified by this bounded experiment.
