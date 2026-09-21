# Rolling composition, updates and installation

Status: accepted product contract from the
[vision revision](2026-09-21-owner-composable-android.md). Package formats, compatibility
metadata, transaction protocols and installer implementation remain proposals.

## Owner experience

The recommended installer provides a usable Android phone and native Unix environment.
The advanced path lets the owner assemble component choices. Both use the same system and
package model, and choices remain replaceable afterward. Basic phone use must not require
becoming a ROM maintainer or completing a desktop style manual installation.

Updates follow a rolling release direction. Individual components can update where their
contracts permit; coupled framework, system app, policy, kernel and vendor changes need a
compatible set. A complete OS rebuild is not the required response to every small UI edit.
Conversely, rolling cadence is not a guarantee that arbitrary partial versions will work.

Checking, downloading and staging follow configured owner policy. Activation that restarts
services, ends work or reboots follows consent or an explicit policy. Staging permission is
not permission for an unexpected interruption. The installer should expose those choices,
not permanently fix them on first boot.

## Composition model to design

Track package identity, provenance, selected signer/authority, source recipe, build inputs,
version, dependencies, compatibility requirements and activation/recovery behavior. Native
programs and APKs remain different execution and packaging mechanisms within one system.
`/usr` is one maintained component, not the entire update model. Do not adopt a particular
package manager or manifest format merely because an early fixture uses it.

Locally changed packages are explicit owner selections. If an upstream update remains
compatible, preserve that choice. If a rebuild or merge is required, make it visible and
supportable. Do not silently overwrite local software or imply that a pinned local version
received security fixes that were never incorporated. An owner may deliberately force an
unsupported combination, but the supported update path must not call it compatible.

## Transactions and recovery

Define commit boundaries, interruption behavior, capacity checks, rollback and data
migration for each update class. An application restart, an APEX activation and a boot
partition update are not one universal operation. Data or firmware rollback constraints
must be explicit; returning to old code does not necessarily undo a data migration.

Review compatible grouped transactions, A/B or other staged core updates and component
rollback mechanisms against the selected Android source. These are candidates, not already
qualified guarantees. Preserve a known good recovery route before advertising mutable
workshop or locked operation as supported.

## First gates

Use the [workshop component proof](2026-09-21-workshop-components.md) to establish one real
package change and restoration workflow. Combine it with the
[signing model](2026-09-21-owner-authority.md), then test local SystemUI selection across a
compatible update, an incompatible dependency update, a rebuild/conflict and interrupted
activation. Verify that configuration and user data behave as declared.

Only then generalize the package model into recommended/custom installer profiles and
on-device build tooling. Test owner cancellation, storage shortage, wrong signer, absent
recovery material and user switching during activation. Keep optional history/export off
unless enabled; package state required for safe operation is not authority to capture
arbitrary user activity.
