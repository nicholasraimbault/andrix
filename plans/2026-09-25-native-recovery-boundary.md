# Native account recovery boundary

Status: implementation boundary awaiting an owner policy decision. No native factory is
active. This is not a new accepted restriction or a device recovery qualification.

## Implemented preparation

Package Manager now reserves native identities through its own allocator and persists
retirement before removal can proceed. The next authority step captures an exact installed
subject for a separate designation decision. It compares the actual installed object, UID,
user serial, version and current signer set, rather than accepting reconstructed numbers.
Selecting a subject neither authorizes it nor reserves a UID. A restored reservation is not
an automatically recovered designation.

The manager factory can reuse init's delegated supervision and credential transition. Source
inspection confirmed that init already calls `setgroups` for an empty vector and applies an
explicit empty capability set through `SetCapsForExec`. Duplicating those setters is not
necessary. The manager must still verify the resulting credentials after exec. Native zygote's
empty group handling is different, and isolated native service lifetime is not this factory.

system_server is a zygote child, not an init service named `system_server`. A factory request
needs actual transport credentials, SID and captured process lifetime. A PID label or service
name cannot supply them. Existing manager work ends when its framework authority dies; a new
framework instance cannot silently adopt it.

## The remaining recovery problem

The inspected framework is pinned at `aab06a8bd44c4c2b58eeec780fde83baa9d43a40`.
`Settings.readSettingsLPw` treats missing settings copies as first boot. A completely missing
`packages.xml` also loses the native reservation section. Older readers ignore unknown
sections and omit them when writing. The current native error latch cannot reconstruct records
that are no longer present.

This is not just an availability problem for native processes. `AppDataHelper.prepareAppData`
can migrate package data to a newly allocated app ID. `clearKeystoreData` separately clears a
`Domain.APP` namespace identified by the Android UID. Keystore's ownership check for that domain
compares the caller UID with the key namespace. A numeric UID assigned to a different subject
cannot be assumed harmless merely because the native manager is stopped. This is a source
identified risk, not a reproduced key disclosure on a device.

A separate reservation ledger owned and enforced by Package Manager can isolate reservations
from routine package database recovery. It would contain reservations and their lineage, not
another installed package database, permission store or UID allocator. It still cannot recover
ownership after every authoritative copy is lost. An older OS which does not enforce the ledger
can also ignore it while running. Supported composition must check compatibility, rather than
claim that a side file constrains old code.

A scan of `/proc` is not a live UID lease. Nor can a bounded salvage parser prove that it found
all lost reservations. Warm restart must coordinate captured init instances before replacing
native authority. Known reservation IDs can remain excluded from allocation while other
Android subjects continue normally. These are engineering obligations, not a reason to ask
again whether ordinary native programs should use their actual Android permissions.

## Decision needed before activating the recovery boundary

When valid state still identifies the protected UIDs, close only affected native accounts and
retain their reservations. Normal Android operation need not be blocked by that condition.

When no authoritative record can establish which UIDs still own native account resources,
there is a different choice. Continuing normal allocation can assign an old identity to a new
subject. Refusing all allocations from inside normal package scanning is not acceptable either:
scan failures can delete valid APKs or data.

Recommended boundary:

- Stop automatic startup before unsafe identity allocation and enter an explicit recovery state.
- Preserve data and keys. Do not automatically wipe, change ownership, assign a replacement UID
  or replay native work.
- Resume normal startup only after coherent identity state is restored or the owner deliberately
  authorizes a different recovery outcome.

This may prevent normal phone startup until recovery completes. That availability tradeoff is
a product decision, not something the factory should hide in an error handler. It does not
remove deliberate general administration; choosing to override it changes the guarantees.

The question is whether that recovery default is acceptable. Phone operation continuing despite
unresolved ownership would require a different explicit risk policy. No such alternative has
been selected.

## Still separate

This decision does not select account UI, production key topology, permission defaults,
permanent quotas, a path spelling for the home, or broad Force stop/Clear storage semantics.
Those must not be smuggled into a bootstrap profile. Home CE identity, principal lifecycle
binding, resource and SELinux integration, maintained API bindings and device qualification
remain implementation work.
