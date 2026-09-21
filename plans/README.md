# Plans

[`current.md`](current.md) records product-level progress and the next milestone.
Dated milestones retain scope, design decisions, concise outcomes and open gates.
They are not execution diaries or runtime inventories.

The [2026-09-21 accepted vision revision](2026-09-21-owner-composable-android.md) expands
Andrix from a Unix focused layer to an owner composable Android OS. Its platform work is
separate from the retained Unix milestones:

- [Workshop component workflow](2026-09-21-workshop-components.md), the next Cuttlefish proof.
- [Owner authority and signing](2026-09-21-owner-authority.md).
- [Android accounts with Unix](2026-09-21-android-unix-accounts.md).
- [Rolling composition and installation](2026-09-21-rolling-composition.md).
- [Later Pixel integration](2026-09-21-pixel-integration.md).

Accepted capability does not select an unproved mechanism or authorize a deployment action.

The [design evidence register](../docs/design-evidence.md) is the maintained bridge
between prototypes/tests and long term intent. Update the relevant entries alongside
source and milestone changes that affect implementation status, evidence, design
lessons or decisions. Keep evidence scope and source revisions explicit. A milestone
pass does not promote a prototype into the accepted architecture automatically.

Machine-local state, process identities, job scheduling, cross-project coordination
and detailed run receipts belong in ignored operator records and private evidence.
The [architecture](../docs/architecture.md) remains the accepted system design.
