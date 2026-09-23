# Plans

[`current.md`](current.md) records product-level progress and the next milestone.
Dated milestones retain scope, design decisions, concise outcomes and open gates.
They are not execution diaries or runtime inventories.

The [2026-09-21 accepted vision revision](2026-09-21-owner-composable-android.md) expands
Andrix from a Unix focused layer to an owner composable Android OS. Its platform work is
separate from the retained Unix milestones:

- [Workshop component workflow](2026-09-21-workshop-components.md), the next Cuttlefish proof,
  with its [SystemUI source assessment](2026-09-21-systemui-component-assessment.md) and
  [execution plan](2026-09-21-systemui-execution-plan.md), followed by the
  [staged verification policy correction](2026-09-22-staged-apk-verity.md) and the
  [finite SystemUI runtime qualification](2026-09-22-systemui-component-runtime.md), then
  the [session restoration correction](2026-09-22-package-verity-restoration.md).
- [Installation signing identity recovery](2026-09-22-installation-key-recovery.md) accepts
  portable encrypted recovery and protected device signing as the default. Provisioning
  mechanisms remain to be implemented and qualified. The first
  [identity inventory and independent recovery vehicle](2026-09-22-signing-identity-recovery-proof.md)
  supplies artifact observations and disposable host controls, not protected Android custody.
  The [protected signing request](2026-09-22-protected-signing-request.md) has passed a
  finite disposable Android flow. The [APK artifact gate](2026-09-23-protected-apk-artifact.md)
  also qualified protected signing, verified export and ordinary installed execution for
  one captured project APK. The [APEX and nested APK inventory](2026-09-23-apex-trust-inventory.md)
  extends the public role evidence. The [authorization scope decision](2026-09-23-signing-authorization-scope.md)
  separates the accepted transaction approval default from candidate key mechanisms.
  Neither a timed key window nor platform transaction token issuance is selected. These
  proofs are not a production signer or a new administrative policy.
- [Owner authority and signing](2026-09-21-owner-authority.md).
- [Android accounts with Unix](2026-09-21-android-unix-accounts.md).
- [Rolling composition and installation](2026-09-21-rolling-composition.md), with a
  [long term architecture assessment](2026-09-23-composition-architecture-assessment.md)
  covering source variants, exact artifacts, version selection and native activation.
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
