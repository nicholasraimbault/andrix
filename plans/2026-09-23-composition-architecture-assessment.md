# Owner composition: identity, builds and activation

Status: assessment and recommendation, not a selected implementation. The owner requested
a clean long term approach consistent with Andrix's values, not adoption of Nix by analogy.
The [vision](../docs/vision.md), [authority contract](2026-09-21-owner-authority.md) and
[rolling composition requirements](2026-09-21-rolling-composition.md) remain accepted inputs.
No package format, expression language, version encoding, store implementation or new Android
installation policy is selected by this assessment.

## Recommendation

Build one Andrix composition model with several build and activation mechanisms. Make owner
intent, exact artifacts, compatibility and deployment outcomes explicit. Integrate it with
Android's actual package, account, signing and boot authorities. Do not bolt an independent
package database over Android and hope that its chosen files become the running system.

Borrow the explicit inputs and retained selections of Nix and Guix, the source maintenance
practices of distributions, and the coherent deployments of image systems. Assess reuse of
their implementations where useful. Neither writing everything ourselves nor importing a
whole tool stack is a default virtue.

The stable product abstraction should be an owner selected component and its required
compatibility set, not an APK version integer, a directory in a store, a Soong target or a
complete image. Those are different pieces of its realization.

## Criteria from Andrix's values

A good solution must satisfy all of these, not just produce reproducible files:

1. **Practical ownership.** Find a component's source or configuration, change it, build,
   authorize, install, activate and recover without becoming a full ROM release engineer.
2. **One functioning Android phone.** Retain Bionic, Binder, ART, Android identities, hardware
   services and phone behavior. A platform change is legitimate when the coherent design
   requires it; GrapheneOS and the ordinary APK prototype are not policy ceilings.
3. **Deliberate authority.** Ordinary builds and jobs do not acquire installation signing or
   administration. Authorized general root commands and shells remain available, not a menu
   limited to the composition manager's actions.
4. **Preserved owner choices.** Updates incorporate local selections or expose the conflict.
   They neither overwrite a modification silently nor claim it received missing fixes.
5. **Honest recovery.** Identify what can be restored, what mutable state changes, and what
   requires compatible forward repair. Old code is not necessarily old data.
6. **Privacy and resource discipline.** Private build inputs are not a public cache. Keys are
   not build inputs. Retention must fit a phone and preserve actual recovery requirements.
7. **Maintainable responsibility boundaries.** State and authority have clear owners. Choose
   reuse or replacement on correctness and coherence, not prior investment or patch size.

Host assistance is an initial execution location, not the architectural owner of the model.
Ordinary component development on the phone remains a product goal.

## What the evidence establishes

The existing SystemUI loop proves focused component builds, staged replacement and forward
restoration within one platform cohort. The protected artifact proof establishes immutable
input capture, exact approval, signing, verification and ordinary installed execution in its
finite scope. Neither establishes a rolling composition manager.

The following source observations constrain a real design:

- Android exposes APK versionCode and versionName to applications. The fixture's 37 through
  41 were explicit package ordering values, not upstream source revisions.
- Package Manager's normal downgrade check compares version codes and, for equal codes,
  base and split revision codes. This protects a package that inherits existing data, but
  does not know that data's actual schema or prove compatibility.
- Factory versus data selection considers paths, versions and shared user changes. A local
  SystemUI at 41 can hide a later factory build at 37; a later factory 42 can replace it.
  Neither choice knows whether the owner intended to preserve a modification.
- GrapheneOS additionally rejects an ordinary system APK update with a version not strictly
  greater than its factory package. APEX's inspected repository rules admit equal version
  data copies. One universal integer rule does not even describe these two classes.
- Staged session restoration refuses a changed platform fingerprint because prior
  verification assumptions may no longer hold. This is a compatibility guard we can redesign
  with a complete target contract, not proof that composed image and component updates are
  fundamentally impossible.
- APK package code is shared across Android users, while app installation state and CE/DE
  data have user distinctions. A separate Unix profile does not give each user an independent
  SystemUI package version.
- APEX, staged APK and image updates have different state and recovery machinery. The staged
  manager's checkpoint handling does not make arbitrary image, APK, APEX and data changes one
  atomic transaction. Ready is not applied, and applied is not a complete health result.

The public inventory also found 33 APKs inside APEX payloads. Editing a nested APK may require
rebuilding and signing a containing payload and container. A source component, a build target,
an artifact bundle and a compatible activation set are not necessarily the same boundary.

These are source facts and bounded proof results. They do not qualify a new version policy,
actual multiuser composition, durable publication, physical device recovery or live rekeying.

## Alternatives and what to reuse

| Approach | Useful properties | Limits for Andrix | Assessment |
| --- | --- | --- | --- |
| Conventional distribution recipes | Upstream version plus package revision, patch series, build configuration and dependency declarations | A binary installer does not automatically retain owner patches or understand Android identity and activation | Reuse the source maintenance discipline and suitable tools; do not use file unpacking as Android installation |
| Nix or Guix model | Explicit build inputs, separate build identities, retained profiles, cache substitution and reachability based retention | A profile pointer is not Android activation; build isolation does not prove reproducibility or runtime compatibility | Strong model to learn from; evaluator, store, builder and cache reuse remain concrete candidates |
| OSTree or bootc model | Exact filesystem trees, retained deployments, incremental transfer and coherent base system updates | Android partition verification, package identity and mutable state require their own integration | Useful image composition and delivery ideas; not a drop in Android installer |
| Android integrated composition | One owner model using native package, APEX, work, signing and boot services | Requires explicit policy, durable reconciliation and possibly framework changes | Recommended product architecture, with implementation reuse evaluated inside it |

This is not a claim that Nix requires a second glibc OS. An evaluator, a store library, a
host build service or Bionic targeted recipes could be reusable. The portability, path,
linker, sandbox and storage costs have not been measured here. Adopting a parallel Linux
userspace as the phone platform would conflict with our accepted direction; using a suitable
build or storage mechanism does not by itself do that.

Likewise, assembling an image from cached component artifacts is not recompiling the entire
OS. Image deployment remains a valid option for coupled sets. It must be compared with
component activation on correctness, recovery, phone behavior and measured cost, not dismissed
because the output is an image.

The inspected Nix documentation distinguishes input addressing from addressing store objects
by content. Guix describes isolated builds as helping reproducibility, not making it automatic.
OSTree describes a tree delivery system that can complement a package manager and leaves
mutable state management to the OS. These distinctions must survive any reuse decision.

## Proposed model and ownership

### 1. Owner intent and resolved inputs

Keep a human maintainable record of selected components, upstream tracks or revisions,
local source/configuration changes and update policy. A recommended installation and an
advanced assembly should be different selections over the same model.

Resolve that intent into exact source objects, patches, configuration, toolchains, recipes,
dependencies and target platform assumptions. A patch that applies without conflict is not
proof that its behavior or security meaning remains correct. Keep the original intent and
the resolved input record distinct so an upstream update can be explained.

Do not choose a language before the model. A declarative description can call general build
tools; it need not prohibit programmable recipes. Evaluation, source preparation and ordinary
builds should not need platform signing keys or install credentials. Network fetches and
host builders follow explicit source and privacy policy, not accidental build script access.

Direct execution of ordinary owner programs remains independent of package registration.
The manifest is a tool for repeatable ownership, not a restriction against manual work.

### 2. Artifacts and publication

Record exact output bytes and their relationship to resolved inputs. Distinguish unsigned
build output, already signed developer artifacts and newly authorized installation artifacts.
A complete APK and its required sidecar form a bundle; an APEX may have nested signing roles.
A completed signature is not a completed bundle.

Published artifact objects must remain immutable. Builders and signers use owned staging
objects until complete verification and publication. Keep identity of the build inputs,
measured output content and claims about reproducibility separate. A digest identifies bytes;
it neither proves their source nor says that they are newer, authorized or compatible.

Artifact storage is also an access control boundary. Immutability does not mean world readable.
Private project sources, configuration and outputs need appropriate user and CE ownership.
Public cache substitution must not publish private inputs or import trust just because an
object has a matching name. Private signing and recovery credentials never belong in recipes,
general artifact stores, command arguments or normal build logs.

### 3. Composition and compatibility

A resolved composition names exact artifact bundles, signing identities and compatibility
claims for a target. A deployment record is a separate attempt to realize that composition
on a particular installation. Neither should be confused with a signing identity generation
or a user's CE generation.

Initially, platform components using private framework interfaces should have conservative
cohort bindings. A matching SDK number or successful Soong build is not enough. Public SDK,
NDK, versioned native API and explicitly tested interfaces can permit more independent updates.
Refine these boundaries with evidence rather than making every component depend forever on
an entire image fingerprint.

Keep at least these identity dimensions separate:

- Upstream release or source revision.
- Owner changes and recipe revision.
- Resolved build input identity and produced artifact digest.
- Android package/APEX name, signer relationships and application version fields.
- Selected composition and deployment attempt identity.
- Observed active artifacts and declared data compatibility.

### 4. Authority and execution

The composition planner proposes work. It does not receive universal privilege merely because
it understands the graph. Use narrow, authenticated crossings for protected signing,
installation, disruptive activation and recovery. The
[accepted signing unit](2026-09-23-signing-authorization-scope.md) is one complete approved
transaction, with the key mechanism still open.

An ordinary recipe cannot appoint itself platform signer, an administrator or another user.
Actual caller identity and the independently trusted role map govern those crossings.
Distribution provenance and owner deployment authorization remain separate. Preserve independent
developer identities unless a particular fork or identity transition is deliberately selected.

Owner authorized general administration remains possible, including unsupported changes.
Track divergence for managed components where it affects guarantees. Do not automatically
record arbitrary root command arguments, environments, output or unrelated user activity.
Unsupported does not mean forbidden, but it must not be presented as a qualified composition.

### 5. Selection, activation and observed state

There should be one composition model, not one universal activation operation:

| Deployment class | Native responsibility to integrate | Required distinction |
| --- | --- | --- |
| Ordinary APK | Package Manager and package installer | Package acceptance, data compatibility, process replacement and per user installation state |
| Persistent/system APK | Package Manager, staging and relevant platform lifecycle | Current SystemUI requires staged reboot; any future live replacement needs its own complete contract |
| APEX and contained APKs | apexd, staging, verified payload/container roles | Container/payload/nested identities and checkpoint outcomes |
| Framework, policy, kernel, vendor and boot sets | Matching image production, update and boot verification mechanisms | Target cohort, slot selection, firmware limits and recovery |
| Native owner packages | Bionic environment/profile selection and ordinary work lifecycle | New selection versus already running work, private data and ABI compatibility |

Desired intent, selected deployment, staged native sessions, observed installed bytes and
running health are separate facts. Android services retain responsibility for actual package,
UID, user data and boot state. Andrix must reconcile its operation records with those authorities,
not create a second fictional database of what it wishes were installed.

Assign update responsibility explicitly for managed components. Do not let an Andrix updater
and an independent store silently compete over an owner selected variant. Ordinary developer
applications retain their normal update path unless the owner deliberately brings them under
a different policy. A deployment must revalidate its exact base state at the authority crossing;
a stale plan cannot silently transfer approval to changed artifacts or a different installation.

Where the native service needs an owner selection policy, integrate that contract deliberately.
It need not remain an external shell script. Equally, it need not move every planner or build
tool into system_server. Process layout follows authority and lifetime responsibilities.

Treat a rebooted composition as a result to observe, not the inevitable consequence of a
successful staging call. Define the strongest commit boundary actually supported by each
activation class. A manifest pointer switch alone is not atomic activation of the phone.

## Version and selection strategy

The long term requirement is explicit owner selection and preserved version meaning. The
current versionCode bump is only one possible projection of that model into Android.

| Candidate | What it can achieve | What must be established |
| --- | --- | --- |
| Managed deployment codes plus composition records | Can express owner selections, provenance and desired/observed state while retaining current native gates | One coherent allocation policy for owned factory and data artifacts, restart/recovery continuity, and acceptable application facing version semantics |
| Structured upstream/local encoding in version fields | May provide an ordering under current comparisons | Real upstream ordering, field limits, reset/overflow behavior, app consumers and external update compatibility; spare bits are not a rationale |
| Explicit managed selection in Android | Can make owner composition identity a first class input to factory/data reconciliation while preserving application version fields | Durable state ownership, trusted interface, signer/data/cohort validation, recovery and coexistence with ordinary package updates |
| Coherent image realizations | Can avoid depending on data APK overrides for core selections and reuse cached builds | Image/component transition semantics, update payload construction, target verification and declared restart scope |

An external record with consistently allocated codes is not incapable of representing the
right state. Nor is a native generation record automatically correct because it lives beside
PackageSetting. Compare these candidates against the same cases before selecting one.

My preference is an explicit managed selection contract integrated with Android, with existing
numeric fields treated as compatibility inputs or carefully defined projections. That contract
may be realized initially through coordinated version allocation where it preserves meaning.
Do not commit to generic bit packing or a permanently increasing local counter as the product
identity model. Change framework policy if that produces a cleaner complete contract, rather
than layering exceptions around a scalar that no longer means what callers expect.

The invariants are identity continuity, authorized selection and honest data compatibility.
The exact integer comparison and current fingerprint refusal are mechanisms, not vendor ceilings.
Replacing a mechanism requires a complete alternative check, not global downgrade switches,
package database edits, blind data deletion or disabling signature/fs-verity verification.

Changing versionCode changes signed APK bytes. Signing the result with the same certificate
and key does not create a new signer identity. The same key under a different certificate is
not assumed to be the same Android signer. For an independent third party APK, however, changing bytes
invalidates its existing signature, and we generally do not possess that developer's key.
Even when we control a key, application facing version semantics and data behavior still matter.

## Updates, recovery and retained state

An upstream update should produce a candidate for the owner's chosen variant. Keep the local
change when compatible, surface merge or rebuild requirements, and identify security fixes
not incorporated. Never confuse a large local deployment number with current upstream code.

Software generations should retain exact known compositions and their recovery recipes.
Mutable app data, CE keys, settings, databases and firmware are outside that immutable artifact
claim. Recovery may require forward repair, a declared data migration or an independent route
that does not rely on the broken SystemUI. The blocked factory uninstall path and the finite
higher version restoration are not a universal recovery implementation.

Durable operation ownership is necessary before a product service is advertised. After reply
loss or process death, reconcile the exact retained native session and artifact identities.
Do not blindly resubmit signing or installation as a new request. Pending cancellation,
accepted signing, applied deployment and actual cleanup retirement remain different outcomes.

Garbage collection roots include active selections, known good recovery, owned builds/signing
operations, candidate bundles, pending native sessions and readers. An object absent from the
current composition may still have an owner. Admission must preserve space for completion and
recovery before old material is reclaimed. Exact quotas and retained generation counts need
phone measurements, not adoption of laboratory constants.

## Decisive next gates

1. **One owner variant across an upstream change.** Use a small SystemUI source delta. Resolve
   original source, a compatible upstream change and a conflicting change as separate inputs.
   Prove preservation or explicit refusal, exact provenance and a visible missing fix. Compare
   factory below/equal/above data versions, including the GrapheneOS equality rule. Include a
   return to unmodified source and a wrong signer control. Do not pick a numeric scheme first.
2. **One durable component transaction.** Capture, build/import, authorize, sign all required
   formats, verify, stage and reconcile a complete bundle. Exercise loss and cancellation at
   publication and native submission boundaries. Preserve known results without duplicate
   mutation. Make mutable data changes observable in a disposable fixture so code restoration
   cannot be mistaken for data restoration.
3. **Composition boundary and implementation reuse.** Compare a focused APK change, an APEX
   change and an image assembled from cached components. Test a platform fingerprint change
   crossing staged work, real per user data versus shared code, and the actual recovery scope.
   In parallel, make a small Android/Bionic build and cache trial for shortlisted existing
   evaluator/store tools. Measure assumptions before adopting or dismissing those tools.

Each gate needs its own bounded plan and actual admission. This assessment authorizes no
handset flash, personal key provisioning, live policy change or mutation of frozen proof inputs.
The first implementation should exercise a vertical component workflow, not begin with a new
package language, a universal privileged daemon or a complete replacement of Soong and Package
Manager. Such replacements remain possible when the evidence and coherent design justify them.

## Assessment sources and remaining choices

This recommendation does not depend on claiming that native generation selection is the only
option, that image deployment means a full source rebuild, or that Nix store reuse necessarily
means another OS. None of those conclusions follows from the inspected source. Android source
observations refer to the pinned GrapheneOS 2026081300 foundation, not all Android releases.

Reusable source references:

- [Debian version structure](https://manpages.debian.org/bookworm/dpkg-dev/deb-version.7.en.html)
  and [Arch recipe fields](https://man.archlinux.org/man/PKGBUILD.5.en).
- [Nix derivations](https://nix.dev/manual/nix/2.34/language/derivations.html),
  [profiles](https://nix.dev/manual/nix/2.34/package-management/profiles.html) and
  [store object content addressing](https://nix.dev/manual/nix/2.34/store/store-object/content-address.html).
- [Guix features](https://guix.gnu.org/manual/1.5.0/en/html_node/Features.html).
- [OSTree introduction](https://ostreedev.github.io/ostree/introduction/) and
  [bootc model](https://bootc.dev/bootc/).
- Pinned Android source: PackageManagerServiceUtils.checkDowngrade;
  InstallPackageHelper.addForInitLI; PackageVerityExt.checkSystemPackageUpdate;
  StagingManager.restoreSessions; ApexFileRepository.AddDataApexFiles;
  release tooling's separate APK/container/payload key maps and PRESIGNED handling.
- The [SystemUI runtime](2026-09-22-systemui-component-runtime.md),
  [artifact signing flow](2026-09-23-protected-apk-artifact.md) and
  [expanded public trust inventory](2026-09-23-apex-trust-inventory.md).

Still open: concrete schema and evaluator, storage implementation, version projection versus
native selection integration, compatibility metadata refinement, native package profiles,
durable transaction protocol, owner role provisioning and physical device recovery. The proposed
architecture narrows those questions without pretending that a familiar tool or successful
fixture has already answered them.
