# Owner trust, selection and deployment contract

Status: proposal for review. This makes the missing integration contracts concrete without
selecting a key topology, package language, store, version encoding, native selection API or
update mechanism. It changes no accepted architecture or running policy. No signing,
provisioning, build, installation or handset operation is authorized by this document.

Android is the platform. The objective is a maintainable owner controlled Android lineage,
not a terminal attachment or a collection of verification exceptions. The
[accepted vision](2026-09-21-owner-composable-android.md),
[authority requirements](2026-09-21-owner-authority.md),
[recovery default](2026-09-22-installation-key-recovery.md) and
[composition assessment](2026-09-23-composition-architecture-assessment.md) are inputs.
The companion [native principal proposal](2026-09-24-native-principal-contract.md) defines
ordinary subjects of the system. A login, installed APK or build recipe does not thereby
become a platform administrator, signer or deployment authority.

## 1. Required owner experience

The owner can configure, extend, build and replace software through supported interfaces.
Ordinary native execution and ordinary APK development do not require platform signing or
entry into a composition database. General authorized root commands remain available.
Managed composition makes changes explainable and recoverable; it is not the only permitted
way to use the computer.

For a managed component, the system can answer: what did the owner select, what source and
local changes produced it, what is installed, what is running, which upstream fixes are
missing, and how can it be repaired? An unfamiliar combination can be unsupported without
being forbidden. Supported operation must not silently change that classification.

## 2. Identities and authoritative state

These are different objects, not interchangeable version numbers:

| Object | Meaning and owner |
| --- | --- |
| Owner intent | Account maintained source/configuration choices, upstream tracking and update policy. An ordinary planner may read and resolve it. It is not installation authority. |
| Resolved inputs | Exact source objects, owner changes, recipes, toolchains, dependencies and target assumptions. The resolver owns this description, not Android's installed state. |
| Artifact bundle | Immutable output bytes and all required members, signatures and sidecars. An artifact publisher owns completeness and access control. A digest is not provenance or approval. |
| Installation trust policy | The installation identity, role bindings, approved issuers/delegations and policy revision. A protected platform authority owns it. Logical roles need not all use one key or one trust mechanism. |
| Managed selection | An authorized choice of a component variant and compatibility set, with an update responsibility and selection revision. Its authority is part of the OS contract, even if its metadata is stored outside Package Manager. |
| Deployment attempt | One retained attempt to realize a precise authorized plan on an installation. A coordinator owns its operation records, resources and reconciliation, not unilateral claims of native success. |
| Native state | Package Manager, package installer, apexd, Android user/credential services and boot/update authorities own their actual state. Native userland profiles own their declared namespace; native code delivered inside an APK, APEX or image still follows that platform deployment authority. |
| Observed result | A scoped observation of installed bytes, active instances, boot state and health. It names the observation's context and freshness. It is not a permanent assertion that desired state is running. |

External intent, provenance and operation records are legitimate. A second database that
claims installation or activation succeeded against contrary native state is not. New
framework state must have a defined owner and recovery rule, not exist merely to mirror a
planner's wishes. Process layout and storage placement follow these responsibilities.

Authority and deployment references bind to an installation and relevant policy/selection
incarnation. A recycled numeric user, package session, alias, pathname or PID is not sufficient
identity. Immutable artifact identifiers need not be installation specific; sharing bytes does
not share deployment authority. Native
operations that legitimately survive reboot must remain reconcilable through their native
persistence contract; an arbitrary new boot identifier must not make them disappear.

## 3. Owner authorization and trust roles

Distribution signatures establish provenance under an owner selected trust policy. Owner
deployment authorization is a separate relationship. Owners can authorize their own source
and configuration without obtaining distribution approval. No universal project private
platform key is distributed to owners.

Each managed role specifies its scope: affected components, permitted signer relationship,
privileges, delegation limits, policy revision and recovery requirements. An owner authorized
SystemUI variant does not authorize an arbitrary APK to join its UID or receive its grants.
Roles include APK certificate/shared UID/permission/MAC relationships, APEX container and
payload verification, OTA verification and verified boot. Vendor firmware trust outside
Andrix's control remains a separate constraint.

Existing third party identities are preserved unless the owner deliberately chooses a fork
or identity transition with its own data and permission consequences. Re-signing changes
identity unless the exact accepted certificate/key relationship is retained or an explicitly
qualified transition applies. Matching a public key alone is not a universal Android signer
identity check. Authorization metadata does not magically satisfy existing Android checks.

### Authority crossings

Resolving, fetching, building and inspecting ordinary artifacts do not borrow signing or
installation credentials. Trusted services validate actual caller authority, target scope,
immutable inputs, current native base and current trust policy before accepting a privileged
effect. An untrusted recipe cannot nominate its own privileged role or rebind an approval.

The [accepted default](2026-09-23-signing-authorization-scope.md) is one explicit approval and
fresh authentication for a complete protected signing transaction. The approved context
identifies installation, principal, exact input bundle, roles, purposes, required formats,
derived operation plan and expected output membership/identity rules. Approval binds the
immutable inputs and permitted derivation; it need not predict future signature bytes that
depend on cryptographic randomness. Verified results record the produced bytes and digests.
Derived signing inputs must follow that plan; a provider alias or recent unlock cannot
stand in for it. The key mechanism remains open.

Signing, installation and disruptive activation are separate grants. A combined owner
interaction may cover an explicit bounded set of effects; omitted effects are not implied.
An existing owner policy may authorize routine update actions within its scope. It does not
by itself waive fresh authentication for protected signing. A deliberately approved batch or
broader administrative context is a distinct authorization, not a permanent grant to a UID
or permission to interrupt unrelated work unexpectedly.

A trust or selection change invalidates stale uncommitted plans. An already accepted native
operation may still complete: revocation closes new admission and requires reconciliation,
not a claim that an issued signature or committed deployment has ceased to exist.

### Mechanisms to compare

| Candidate | Required contract and cost |
| --- | --- |
| Personalized identities for selected roles | Provision and retain exact owner identities. Updates affecting those roles need the corresponding signing path. Do not infer that every file or third party APK must be personalized. Preserve certificate, data and recovery continuity. |
| Delegated owner deployment trust | Keep suitable distribution identities while native enforcement recognizes explicitly authorized owner variants or trust relationships. Define each change to privilege, signer, shared UID, MAC, APEX and boot checks. A detached approval is not already such an implementation. |
| A role specific combination | Use different mechanisms where their native responsibilities differ. Explain the complete trust path and rotation/recovery behavior; do not conceal ambiguity behind a single installation key label. |

None is selected here. The [source comparison](2026-09-24-integration-mechanism-assessment.md)
maps several existing checks and their distinct trust inputs. Compare candidates against the
same owner variant, upstream update, ordinary app denial and recovery cases. Native framework changes are legitimate when they
produce a cleaner contract. Global verification bypasses and package database edits are not
a managed trust design. The accepted workshop mode can deliberately reduce boot verification;
that declared mode does not silently disable APK/APEX checks or acquire assurances of locked operation.
Further owner experiments can change guarantees, but must not be labelled verified managed
operation without the corresponding contract. A small patch count is not the measure of
architectural quality.

## 4. Selection and upstream continuity

Enrollment of a managed component declares who may change its selection and how its ordinary
updater interacts with that choice. Updaters must not silently compete. Leaving management
is also an explicit, compatible transition, not deletion of the only explanation of a data
partition override.

An update resolves a new candidate from upstream inputs and the owner's recorded variant.
It either preserves the intended change with stated compatibility evidence, or exposes the
conflict, rebuild requirement or missing fix. A clean textual merge is not semantic review.
Direct administrative edits outside the managed model are divergence, not automatically
reproducible recipes. The system may offer to capture them, without claiming it can infer
all intent or safely merge every edit.

A selection change uses an expected prior revision and target base. The native acceptance
boundary revalidates those assumptions. A simultaneous updater, changed factory image,
changed signer policy or another user action cannot silently retarget the plan. Code may be
shared across users even when installation state and data are not; effects on other users
must be explicit.

VersionCode remains an Android compatibility and ordering input, not the owner selection
identity. Coordinated deployment codes for factory and data artifacts remain a candidate.
So do explicit native selection and coherent image realizations. Compare all of them with
factory versions below, equal to and above data artifacts, transitions between deployment
classes, ordinary independent APK updates and interrupted native sessions. Do not adopt an
integer encoding first or prohibit legitimate external intent records.

Stable configuration and extension interfaces should handle common changes where appropriate.
Deeper source forks remain legitimate, with explicit carry and requalification responsibility.
Measure merge/rebuild effort, compatibility failures and security update delay over actual
upstream transitions. Cached component builds may be assembled into an image without
recompiling everything; an image is an activation choice, not proof of unnecessary rebuilds.

## 5. Durable operation and activation contract

A deployment plan names exact bundles, trust/selection revisions, native base, compatibility
set, affected users, required authority, disruption policy, data transition and recovery route.
Its meaning cannot change after approval. Later repair that needs different inputs or effects
is a linked new plan with its own authority, not an invisible mutation of the old request.

Conceptual operations, not a selected wire API:

- **Prepare:** resolve and validate a candidate and its recovery/resource requirements without
  deploying it. Capture an immutable plan reference.
- **Authorize:** bind permitted effects to that plan and the actual approving principal/policy.
- **Execute:** durably reserve operation identity and resource ownership before crossing into
  a signer or native installer. Record acceptance and exact native references separately.
- **Query/reconcile:** recover retained facts and unresolved native operations under the same
  identity. A missing reply or unknown record is not permission to submit again as new work.
- **Cancel:** close admission and request supported cancellation of accepted effects. Retain
  ownership until their actual outcome and cleanup are known.
- **Repair:** propose a new authorized transition from observed state when the original plan
  cannot finish safely. Preserve the failed attempt and its evidence.

Builders and signers retain outputs in owned private staging until the complete required
bundle passes verification and publication commitment. A later failed signature or missing
sidecar cannot expose earlier members as a completed transaction. Published objects are not
mutated in place. A lost publication acknowledgement can conceal an already visible commit;
reconcile the exact object rather than deleting it or blindly publishing again.

The same reference with identical context returns retained progress or results. Changed
context is refused. Exceptions after submission do not establish nonacceptance. A completed
signature, complete verified bundle, durable publication, accepted native install, activation
and health confirmation are separate facts. Cancellation cannot unpublish an already
published result or undo a native commit by changing a coordinator flag.

Each native operation has a captured ticket and a recovery query contract. The coordinator
reconciles those tickets with the intended artifacts and authority after process loss or
reboot. If that cannot establish an outcome, the attempt remains unresolved and prevents
conflicting work. It does not guess success, delete native state, or replay a mutation.

Activation is not one universal atomic operation. The planner declares the native commit and
failure boundary of each class. A grouping that requires unsupported atomic semantics
must be refused or redesigned as explicit stages with an approved repair strategy. A profile
pointer change is not an atomic APK/APEX/image/data transition.

Health criteria are declared before activation and checked against actual instances. Staged
ready, boot complete and a responsive launcher each establish less than complete phone health.
A supported deployment reports committed, active, healthy, degraded, recovering and unknown
facts without collapsing them into a single success flag.

## 6. Recovery and retention

Before the first disruptive effect, a usable recovery route and sufficient completion/recovery
capacity must exist. The route must still work if the replaced UI, service or signer frontend
is unavailable. An initial host assisted route can be explicit; it must not masquerade as
standalone phone recovery or require a component already declared broken.

Known good code, signing authority, CE data, app secrets, policy state and firmware are different
recovery objects. State the permitted backward/forward data transitions for each affected user.
A/B slot fallback and userdata checkpoints are candidate mechanisms, not a general data rollback
guarantee. Filesystem, platform, commit timing and firmware rollback constraints need their own
qualification. Where data cannot be restored, recovery may require compatible forward repair.

The portable encrypted identity recovery default remains. The expected installation/role
manifest commitment must be trusted independently of the recovered bundle. Restoration must
validate the complete role set and material before exposing private keys. It does not itself
authorize a deployment, recover CE data, undo revocation or qualify migration to a new device.
Trust policy recovery and protection against restoring a stale role set need an explicit design.

Declare the minimum trust and selection metadata needed before user unlock and during
recovery. Keep private sources and user contents under their actual CE/access policy rather
than copying a whole private composition into less protected storage for convenience.

Retention roots include active and recovery selections, candidates, native pending sessions,
owned builders/signers/installers and running readers of old objects. Space reclamation cannot
release unresolved ownership. Artifact stores preserve user/CE access control; immutability
is not permission to publish private inputs. Minimal operational state is distinct from
optional command or activity history. Do not log arbitrary root commands, credentials or
private build contents merely to support reconciliation.

## 7. Signing trust when the running OS is compromised

A protected device signing copy remains an accepted default. Its guarantees need a named
threat boundary, not an inference from nonexportability or a locked bootloader:

| Situation | Proposed claim boundary |
| --- | --- |
| Untrusted ordinary program, trusted authorization/signing platform | It cannot borrow another request's approval, change approved inputs, use a protected role or read private material. Qualify this boundary and actual credential/user binding. |
| Legitimate administrator deliberately changes the platform | The owner can change the system and its guarantees. Ordinary application isolation is not a promise against that administrator. |
| Exploit compromises the main OS or kernel | Do not rely on checks, UI or intent stored solely in that compromised domain to prove exact owner approval. This attacker is not an authorized administrator. Nonexportability alone does not prevent misuse of a live signer. |

For a later locked profile, separately state whether it claims to prevent an exploited main
OS from authorizing altered platform artifacts into the trusted boot/update chain. Do not
promise that verified boot removes all persistence through mutable data or owner startup code.
If the stronger signing claim is selected, approval and verification need a trust boundary
that the compromised domain cannot substitute. A protected execution domain, separate signing
boot or external signer is only a candidate until its input, intent and authentication path
is qualified. It must support legitimate owner variants, not restrict the owner to a vendor
manifest in the name of provenance.

This does not select a signer available only on a host, weaken the current key policy, require a protected VM
or withdraw the accepted on-device goal. The tradeoff between a workshop trusted-OS signer
and stronger assurance in locked operation must be resolved explicitly, with physical backend evidence
where needed. A human PIN prompt does not make an untrusted presentation path trustworthy.

## 8. Decisions and deciding gates

The proposed responsibilities and invariants can be reviewed now. Mechanism choices remain:
principal representation in the companion contract; trust binding for each installation role;
selection/version realization by deployment class; durable native submission/query support;
and the exact signing claim for locked operation and recovery environment.

Next, construct bounded comparisons rather than implement a universal privileged daemon:

1. Map the role and privilege consequences of one ordinary APK, one owner SystemUI variant
   and one APEX/boot set. Compare personalization and delegation with disposable identities.
2. Carry an owner variant and upstream fixes across real upstream changes, including a conflict,
   a stale plan, an independent updater and a return to unmodified source. Measure carry cost.
3. Exercise accepted/rejected/unknown submission, late completion after Cancel, partial signing,
   incomplete publication, reboot reconciliation and data migration failure under exact tickets.
4. Break the modified UI and recover through the declared independent route. Qualify any stronger
   compromised-OS signing claim separately; emulator success cannot supply physical assurance.

A proposal is selected only with an explicit rationale and evidence at the relevant layer.
The native principal and composition gates must both succeed: useful ordinary programmability
without maintainable updates, or maintainable images without useful owner programming, does
not meet the goal.
