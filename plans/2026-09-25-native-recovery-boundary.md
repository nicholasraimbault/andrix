# Native identity recovery and fault containment

Status: proposed persistence redesign after source review. The current implementation still
stores native reservations in `packages.xml`. The separate store described here is not yet
implemented or qualified. No native factory is active and no new UID range or catastrophic
recovery policy has been selected.

## Scope

Supported Andrix operation must handle interrupted writes, process restarts and damaged metadata
without silently reassigning native identity. Reusing Andrix user data under an unsupported OS
is not a supported compatibility promise. Moving to such a system needs an explicit owner
approved wipe or supported migration. Andrix's own updates and rollback targets still need
compatible state handling.

No measured field failure rate is available for complete Android identity record loss. Treat
loss of every authoritative record and its recovery copies as a disaster case, not the premise
around which every normal boot is designed. The earlier choice between stopping the phone and
guessing new IDs was too broad for the next integration milestone.

## The useful separation

Two different facts are needed:

1. **This app ID is held and must not be allocated to someone else.**
2. **This particular principal is authorized to run under it now.**

A small durable reservation can preserve the first fact even if the richer account record cannot
establish the second. Then the affected native account is unavailable, but its identity stays
protected and ordinary Android operation can continue. A reservation is not installed state,
a permission grant, owner consent or a live process lease.

The existing `NativePrincipalManager.Selection` supplies a further boundary: the designation
controller must bind its decision to the actual installed object, UID, user serial, version and
current signer set. A selection neither authorizes the account nor reserves the UID. A restored
reservation cannot automatically recover designation or execution authority.

## Recommended shape

Package Manager owns one small native reservation store outside the frequently rewritten
`packages.xml`. It remains the sole UID allocator. There is no second installed package database
or permission store.

Use stable slots keyed by app ID, with normal recovery copies. The protected slot name retains
minimal allocation occupancy even when its record contents cannot be parsed. The record carries
the principal ID, package, user and serial, signer binding, lifecycle phase and persistence
generation. Filesystem layout and encoding remain implementation details to verify.

- Durably establish the slot and its recovery copies before any native exposure.
- Keep the slot name stable while replacing account metadata atomically.
- Preserve unreadable records for recovery, rather than deleting the reservation on a read error.
- Durably record RETIRING before quiescence or removal proceeds.
- Remove the reservation only after actual work, manager, API and data obligations are complete,
  and confirm durable removal before permitting reuse.
- Load allocation holds before package scans can allocate new IDs. Do not let them reject the
  legitimate installed mapping while Package Manager reads its settings.
- Restore a principal's own UID only through a trusted stored binding and verified current
  package/user/signing identity. A package name alone is insufficient.
- Restore account state as inactive. Live designation, CE authority and captured manager
  supervision are still required before execution.

Two copies provide recovery from the specified copy failures, not protection from destruction
of their entire filesystem. Conflicting records cannot be combined into a new grant. A damaged
counter or lineage can close native account creation while known slots still protect their IDs.

## Intended failure behavior

| Failure | Intended result |
| --- | --- |
| Framework restart | Old work is retired through captured init instances. A new framework cannot adopt it merely by matching a PID or UID. |
| Interrupted creation | Any retained slot continues to hold the ID. No execution without complete durable publication and live authority. |
| Interrupted retirement | The retirement marker persists. The old account cannot return as active. Reconcile exact retirement before final removal. |
| One bad record or copy | Recover from a validated copy where possible. Otherwise keep the ID held and only the affected native account unavailable. |
| Both record bodies unreadable, slot identity intact | Keep the negative reservation. Do not infer positive ownership or permission from the slot name. |
| Ordinary package settings recovery | Native reservations are not erased by recovery of the unrelated settings document. New allocation skips their IDs. |
| Missing or inconsistent native lineage/counter | Close native creation and recovery grants, preserve known holds and do not invent a new lineage that adopts old resources. |
| Destruction of all reservation evidence and recovery copies | General disaster recovery remains necessary. This design does not claim to reconstruct authority from nothing. |

These are design targets, not runtime results. An ID conflict or exhaustion must not flow into
Android's ordinary invalid APK deletion path. Uncertain account identity is also not permission
to automatically change the native home's owner, lend old keys to a new signer or replay work.
Any backing package data migration needs its own explicit recovery contract.

## Why not infer identities from surviving files?

The pinned framework at `aab06a8bd44c4c2b58eeec780fde83baa9d43a40` can rebuild package state when
settings copies are absent. `AppDataHelper.prepareAppData` can migrate package data to a new app
ID; keystore clearing is separate, and `Domain.APP` ownership checks use the UID. This establishes
a source identified risk, not a reproduced key disclosure.

A package data directory's name and inode owner do not preserve the old signer identity.
Assigning that UID to a newly found APK of the same name could transfer authority to a different
signer. Such evidence can at most contribute to conservative quarantine. Neither a guessed
highest observed UID plus a margin nor a `/proc` snapshot establishes a safe allocation boundary
or a live lease. CE home metadata must not be assumed accessible before unlock.

A compact monolithic native ledger with recovery copies remains a reasonable baseline. Per ID
slots are preferred if their modest structural separation makes a bad record stay local to one
account and preserves allocation occupancy independently of record parsing. They are one logical
Package Manager store, not a collection of competing journals.

A fixed native subset of the ordinary app ID range would provide stronger structural separation,
but introduces allocation, account creation, migration and capacity policy. Permanent ID
retirement also consumes finite identifier space. Neither is selected merely to cover this rare
failure. General restoration of every Android app identity or redesigning keystore is not a
prerequisite for the native account milestone.

## Verification before activation

The implementation needs a precise crash matrix for record creation, both copy acknowledgements,
retirement markers and final removal. Verify that no acknowledged live reservation becomes free
through an interrupted write or a supported copy failure. Exercise missing/corrupt records,
conflicting generations, package settings recovery, verified restoration of the original subject,
wrong signers, stale selections, ordinary allocation and exhaustion without APK or data deletion.

Init's actual captured slot table, not reconstructed PID evidence, remains the warm restart
boundary. UID reuse must also wait for real API and data retirement, including UID keyed keystore
state and the exclusion of new producers during removal. These obligations are not discharged
by a process exit notification or a successful settings write.

After those checks, continue the protected manager, CE home, lifecycle, resource, policy and API
binding integration. The unsupported downgrade scenario and an impossible promise to survive
arbitrary destruction of all authority should not block that bounded work.
