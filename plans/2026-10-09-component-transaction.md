# First durable component transaction

Status: accepted by the owner on 2026-10-09. This is the first durable component transaction, for
gate 3 of [current work](current.md). It applies the proposed
[owner trust, selection and deployment contract](2026-09-24-owner-composition-contract.md) under
the accepted [signing default](2026-09-23-signing-authorization-scope.md), with one narrow
exception in decision 8. The owner decided seven of its eight decisions on 2026-10-09, after an
independent review of the recommendations. Decision 5, the rollback target, waits for test
results. A read only study of the pinned Package Manager and
apexd sources shaped this plan, and independent reviews in three rounds checked it against the
same sources. It enables nothing by itself. D1 and D2 can start now on the host. D3 can be
written now, and D4's comparison can run now.

## Why

Gate 3 asks for a durable component transaction with exact artifacts, all required signatures,
publication, native installation and recovery from interrupted or uncertain outcomes.

The [SystemUI loop](2026-09-22-systemui-component-runtime.md) already changed real SystemUI code
through component builds, staged installation, activation and forward restoration. A host operator
ran each step, and signing used the public development key. There was no installation grant,
artifact store, durable ticket or coordinator to reconcile after a lost reply or an unclean stop.
Ready also proved weak. A wrong signer and a missing sidecar both reached ready.

The composition contract describes the missing transaction in general terms. A deployment plan is
immutable. Signing, installation and disruptive activation are separate grants. Outputs stay
private until a complete verified bundle is published. Every native operation has a ticket and a
recovery query, and an unresolved attempt blocks conflicting work. The pinned sources add six facts
that the contract does not yet account for:

- **Android's own records of a staged operation are lossy and short lived.** Package Manager
  writes most session changes from a background queue. A failed write is retried five times, then
  left until the next change. Commit writes the sealed flag at once, but the committed and ready
  flags only with later writes. Sessions that Android cannot parse are skipped, and their stage
  directories deleted. Finished sessions that are not staged live only in memory. An abandoned
  staged session leaves the file when it finishes. A terminal one is removed at a framework start
  once 21 days have passed since its last change. Session IDs are random and can be issued again
  after a reboot. apexd rewrites its session state in place, without a sync or rename.
- **A ready staged session applies at the next boot, whatever causes that boot.** Nothing
  distinguishes a requested reboot from a crash.
- **The activation boot runs under a userdata checkpoint** on a device that supports one, as the
  lab emulator does. Writes to `/data` in that boot are provisional until the checkpoint commits.
- **An image change fails every committed staged session.** Reflashing to another image and an OTA
  update both count. A staged session that is not yet committed survives.
- **An image change usually keeps the variant, on a base it was not built for.** A data copy whose
  versionCode is above the new factory copy's stays active. The
  [SystemUI assessment](2026-09-21-systemui-component-assessment.md) found that the build gives
  factory SystemUI the platform SDK level, 37, as its versionCode, unless the build sets another
  code. Images at SDK 37 therefore ship 37, and any variant at 38 or above hides the new factory
  SystemUI and its fixes. The variant's restoration bundle was built on the old base too. Staged
  sessions fail across the change, so a rebuilt variant cannot be staged in advance. A variant that
  stays runs at least one boot on the new base.
- **Otherwise Android deletes the displaced owner copy at boot.** A GrapheneOS check rejects a data
  copy of a system package in three cases. Its versionCode is not strictly above the factory
  copy's. It lacks `fs-verity`. Or its signer is not compatible with the factory signer, signing
  lineage included. The boot scan then deletes it. A factory copy with a higher version or a
  changed shared user also replaces it. apexd likewise removes data APEXes that are not mounted.

The native store work adds a lesson. A durable record needs a fixed format, strict and
informational fields, a stable prefix and a settled rollback contract before its first writer
ships. The [lifecycle record](2026-10-08-native-lifecycle-record.md) settles that contract with a
floor image that reads its records. For deployment records, decision 5 chooses between such a floor
and records that stay safe to ignore.

## Owner decisions

Accepted on 2026-10-09, after an independent review of the recommendations that the owner
requested. Each applies from the step that needs it. Decision 5 is still open.

- **Decision 1. Installation authority.** A distinct device grant, normally held by the owner,
  governs staging and activating code that every Android user runs, starting with SystemUI. The
  owner can delegate it for one component at a time. It governs the managed path only. An
  authorized administrator can still change the system through root, as the
  [architecture](../docs/architecture.md#administrative-elevation) allows, outside these records.
  The grant confers no account or user administration, and those grants confer no installation
  authority.
- **Decision 2. Late commit by default.** Signing, publication and Andrix's own checks run ahead of
  time. The owner's activation then arms the change and starts the reboot. A crash after the change
  is armed still applies it. Early commit stays available as an explicit owner policy.
- **Decision 3. Activation and health responses.** Each activating reboot needs the owner's
  consent. Automatic restoration from the restoration bundle runs only when the original approval
  listed it. That approval names the restoration reboot and its interruption of every user, and
  gives the restoration's STAGE and ACTIVATE grants up front. A health observation that is
  unavailable never counts as a failure.
- **Decision 4. The device copy of the platform role.** The accepted
  [installation key recovery](2026-09-22-installation-key-recovery.md) default stands. The protected
  device signing copy holds the platform role. That needs personalization. The image's platform
  packages carry the owner's own platform certificate, and every later image needs the owner's
  platform signature. The threat boundary for signing on a compromised OS is written before
  personal keys are provisioned.
- **Decision 6. Update responsibility across image updates.** An image update waits a declared
  rebuild window, for example two weeks, while the variant is rebuilt on the new base. The rebuilt
  variant's paired restoration is signed before the image applies. If the rebuild is not ready
  within the window, the owner can approve a temporary switch to the new image's own SystemUI,
  built from its factory source, until the rebuild lands. The owner's change stays the recorded
  choice and is never silently dropped. The owner may also choose a longer hold, or keep the old
  variant knowingly as a stale base.
- **Decision 7. Reboot consent with several Android users.** The installation grant holder consents.
  Other running users get notice and a declared delay first, but cannot block the change. A
  restoration approved in advance may run with shorter notice when SystemUI cannot deliver the
  notice, but only under an explicit emergency policy, which the installation grant does not imply.
  Notice must not depend only on the UI being repaired.
- **Decision 8. Signing approval for a variant and its restoration.** This is a narrow exception to
  the accepted [signing default](2026-09-23-signing-authorization-scope.md). One approval and one
  fresh authentication cover exactly a SystemUI variant and its restoration. They are signed in one
  transaction of six key operations, and published together or not at all. The prompt shows both
  input digests and says which APK is the recovery copy. The exception covers no other set of
  inputs, and signing implies no installation or activation.

## Open owner decision

### 5. The supported rollback target once deployment records exist

The owner accepted B1's image, in the [lifecycle record](2026-10-08-native-lifecycle-record.md),
as the supported rollback target. Deployment records raise the question again. An image that reads
them can show a base move after a rollback. Rollback protection applies to whole images, though.
Enforcing a newer floor ends B1's image as a fallback, for unrelated platform defects too.

- **Options.**
  - (a) A floor image just before the first device writer of deployment records. It reads
    lifecycle version 2 slots and deployment records, runs the cohort check and reports the result,
    and writes no deployment record.
  - (b) A minimal deployment reader and cohort checker on a retained known good base close to B1's
    image. This too replaces the exact accepted B1 artifact.
  - (c) Keep B1's image. Deployment records are then ignored while it runs, so they must stay safe
    to ignore. On return, every open ticket and the selection record are reconciled by observation
    before any new crossing.
- **Next.** Build and compare candidate floors. Qualify them on Android with both kinds of records
  present, and measure how far verified boot rollback indexes reach. The owner decides with that
  evidence.
- **Needed** before D7 starts.

## Alternatives considered

- **Installation authority held elsewhere.** Any Android user administrator could then change code
  that all users run. The native account administration grant would couple system code to account
  administration. A holder named for each component, without a common grant, would need an
  assignment for every component.
- **Early commit by default.** Activation would need only a reboot, but any later reboot would
  activate the change, a crash included, and the armed session could be abandoned by Android's
  storage freeing.
- **Report and wait on a failed health window.** A degraded UI would stay until the owner acts,
  through a repair route that works without SystemUI. No such product route exists yet.
- **The platform role off the device.** Every SystemUI change would need a signer elsewhere. The
  audit treats that as a change of owner capability that needs its own decision.
- **An open ended hold of image updates.** It would block every fix in the image, not only
  SystemUI's.
- **Letting the factory copy win at once.** The owner's change would stop until it is rebuilt, and
  uninstall cannot bring the factory copy back.
- **Keeping the old variant by default.** SystemUI would run on a base it was not built for, with
  the new factory fixes hidden.
- **Other reboot consent rules.** The grant holder alone, with no notice, can cost other users their
  work. Requiring every running user to consent gives each of them an indefinite veto.
- **Two signing transactions.** Each would have its own approval and fresh authentication. They
  would publish just as safely, through the artifact store, at the cost of a second prompt. A
  deliberately approved development batch was also possible, but the default leaves its
  publication rules open.

## Later owner decisions

These are not needed for gate 3:

- How the installation grant is held, delegated and revoked, including across credential reset
  and Android user removal, belongs to the [authority design](2026-09-21-owner-authority.md), as
  for the account administration grant.
- APEX updates on user builds are needed before D9. The `/usr` APEX is still a prototype vehicle.
  The options are image updates only, APEXes that Andrix owns under the grant of decision 1, or
  removing the refusal. The recommendation is the second, keeping the refusal for vendor and
  upstream modules.
- The signing claim against a compromised OS belongs to locked operation.
- If a weaker key boundary ever proves necessary, that tradeoff returns to the owner, as the
  signing default requires.

## The design

Android's PackageInstaller, StagingManager and apexd stay in charge of native state. Andrix adds
plans, grants, tickets, an artifact store, a selection record, reconciliation, a health window and
repair around them.

These are engineering choices within this design, not owner decisions:

- Record schemas, encoding and placement.
- The protocol and reconciliation.
- The store layout, observers and health probes.
- The signing mechanism, among candidates that keep per operation key checks.
- Lab versionCode allocation, retention budgets and the lab's default commit mode.

The product's version projection belongs to gate 2.

### The first component

| | SystemUI staged APK | Signed `/usr` APEX | Ordinary Andrix APK |
| --- | --- | --- | --- |
| Qualified base | The SystemUI loop, the staged verity policy, the verity and payload sync companions, the session parser | APEX build, artifact verifier, trust inventory | Protected APK flow |
| Required signatures | APK v2 and v3, plus a signed v4 sidecar for `fs-verity`, which a system package update needs. v3 follows the factory APK. | Container signature and payload AVB. The payload key must equal the factory key. | v2 |
| Native machinery | Staged session, StagingManager, checkpoint | The same, plus apexd sessions, a backup, revert and a 600 second boot timeout | Nonstaged commit |
| Restart scope | Kernel boot | Kernel boot | Process restart |
| Path in this pin | Open, staged only, because SystemUI is persistent | Refused on user builds | Open |

SystemUI comes first, as a staged persistent system APK with its v4 sidecar.

- It is the change the vision names.
- Each of its APKs is the three operation signing case that the accepted default was written for.
  A variant with its restoration takes six operations in one transaction, under decision 8.
- Its first trials can start from an existing sealed normal image with the frozen SystemUI
  variants, if that image's factory SystemUI matches the `985c9a4` baseline.

The signed `/usr` APEX comes second, for gate 4, on the same records. Its container certificate is
shared today with the Terminal APK and the signing custody test APKs. Separate it first.

### Artifact identity

- **Resolved inputs** describe and never authorize. They are the `frameworks/base` revision and the
  SystemUI tree digest, the owner patch digest, and the recipe and toolchain. They also name the
  target cohort, which is the build fingerprint plus the factory SystemUI APK digest.
- **The signing input** is the exact APK bytes and their `SHA-256`. Trusted code parses facts from
  them: package, versionCode, `sharedUserId`, the persistent flag and the SDK fields. The input also
  carries a digest of every ZIP entry outside the signing block. A built APK may already carry
  signatures, which prove nothing about the outputs, so that entry digest is the input's identity
  for signing.
- **A bundle** has two members, `base.apk` and `base.apk.idsig`, and a canonical manifest. The
  manifest lists the member digests, the signer certificate and key digests, the schemes verified
  over the APK's declared SDK range, the v4 check, the versionCode, the input digests and the
  signing transaction ID. Each scheme is checked explicitly, because `apksigner verify` can report
  v2 as unverified at a high minimum SDK although its block is present. The operations' own IDs stay
  in the signer's records. No time enters the manifest, so the same bytes always give the same
  bundle ID, which is the manifest digest. It names bytes, not approval.
- **A restoration bundle** carries known good source at the next versionCode. It is signed in the
  same transaction and kept as a recovery root.
- **A native session reference** is the session ID, `createdMillis`, the stage directory and the
  installer UID, plus a ticket nonce carried in `referrerUri`. Android persists the referrer with
  the session, and `pm` sets it with `--referrer`. The session API returns it unscrubbed only to the
  installer UID and to UIDs below 10000. The session ID alone is not enough, because Android can
  issue it again after a reboot. The readback routes below say where each field can be read.

Publication makes a variant and its restoration visible together, under decision 8:

1. Stage the members of both bundles privately and verify both.
2. Sync every file through its writing descriptor.
3. Rename each bundle into `bundles/<id>`, then sync the parent directory.
4. Write the plan's publication record, which names both bundles and each one's signing
   transaction, and sync it. Its rename is the single commit point. A bundle that no publication
   names is not published.

A published bundle never changes. A lost acknowledgement is resolved by reading the exact bytes,
never by publishing again. A publication that stopped before its record was written had no effect.
The store shows this by reading the plan's publication record absent after the PUBLISH call has
ended, in an observation that names that PUBLISH attempt. The ticket may then publish once more,
from the exact bundles the store already holds, and never by signing again. D1's ledger allows two
PUBLISH entries for this. A publication record that names other bytes than the store holds is
damage, which never heals on its own. The ticket then holds with the REQUEST_LIMIT alert, and only
cancelling or voiding ends it. After PUBLISHED, a read of the plan's publication that is missing or
disagrees with another holds the ticket with the same alert. A recorded cause, such as a
cancellation, still abandons a live session, because an abandon needs no bundle digest.

A repair plan that installs the restoration of the plan it repairs signs nothing. Such a plan,
whether approved in advance under decision 3 or approved when it runs, is the only kind that may
publish without signing, and its target is the variant role. Its publication record names exactly
one bundle, in that role: the bundle signed as the restoration of the plan it repairs, which that
plan's publication already binds in its restoration role. The bundle carries the plan's signer,
signing input and versionCode, and keeps its own signing transaction. The store verifies it again
before it writes the record. No bundle signed as a variant ever fills a restoration role, so
decision 8's approval of which APK is the recovery copy stays the only way a bundle becomes one.
Approval in advance matters only for activation. It is what allows decision 3's automatic
restoration and decision 7's shorter notice, never publication.

### Signatures and grants

The accepted default is one explicit confirmation and one fresh authentication for a complete
signing transaction, with no partial publication. The qualified Android vehicle signs one v2
operation and needs authentication for each key operation. SystemUI is signed with the platform
key. In the lab image that is the public AOSP development key.

- **Approval scope.** The accepted default confirms one input artifact. Under decision 8, one
  approval and one fresh authentication cover exactly a variant and its restoration. They are signed
  in one transaction of six operations, three for each APK, and published together or not at all.
  Neither output may be published alone, because the restoration is the variant's recovery route.
  The three operations are the v2, v3 and v4 signatures. No v1 signature is made. These APKs require
  SDK 37 and always carry v2 and v3 signatures, so Android never verifies a v1 signature for them.
- **Approved context.** It names the installation, the actor, the input digests and facts of both
  APKs, and the platform role by certificate and key digest. It also names the purpose, the
  schemes, the SDK range and the four expected outputs. The facts of each APK are read from its own
  manifest before signing: package, versionCode, `sharedUserId`, the persistent flag and the SDK
  fields. A mismatch with the plan refuses before any key operation. The bundle manifest needs no
  field for them, because its entry digest already pins the APK's manifest bytes. The signer's
  record is where the approval will name them, when the device signer's approval is designed.
- **Private outputs.** Nothing is published until both bundles verify against the trusted role
  manifest of the [recovery vehicle](2026-09-22-signing-identity-recovery-proof.md). A refused or
  lost operation publishes nothing. A lost reply is resolved by its request ID, never by signing
  again. When the signer proves that a request can no longer complete, the ticket records
  SIGN_FAILED.
- **Signer records.** The signer keeps its own durable record of each transaction, written before the
  first key operation. It holds the request ID, the six operation IDs and the four expected outputs,
  and a request ID that has a record is never signed again. The signer keeps the record for as long
  as the ticket that made the request exists. The host signer proves that a request can no longer
  complete when it finds the record still open, or absent, because one coordinator serializes every
  call to it. A completed record also proves it when an output is gone, damaged or fails its
  facts, because only signing again could heal it, and that is forbidden. A read or staging error
  proves nothing. It gives no fact, so the ticket waits and reads again. The protected device signer
  needs its own proof, designed with it. Its approval must bind to each operation's scheme or
  data, because an approval that sees only an operation's position could be spent on other data.
- **Separate grants.** Each grant is its own record. SIGN covers the transaction. STAGE covers one
  session for one bundle on one native base. ACTIVATE covers one activating reboot for that plan,
  and a reboot request that never took effect does not use it. An ACTIVATE that no reboot has used
  expires after a window the plan states. One interaction may grant all three if it lists each
  effect.
- **Signer location.** First a host signer with the development key. That host then belongs to the
  operation's trusted base, which the [integrated model](2026-09-25-integrated-platform-model.md)
  permits. Then the protected device signer, under decision 4. Its mechanism is an
  engineering choice among the candidates that keep per operation key checks. The recommendation is
  the platform transaction token candidate. It authenticates through SystemUI's credential UI, so it
  cannot be the only way to authorize a repair.
- **Delegated trust.** A SystemUI key that Android accepts without the platform signature is one of
  the contract's mechanisms still under comparison. It is not an owner option in this plan.
- **The lab.** The operator stands in for installation authority through the authenticated shell,
  and the records say so.

### Records

There are five record kinds:

- **Plan**, immutable. Lineage, component and class, native base, the signing input digests of the
  bundle and its restoration, affected users and a forward only data statement. A plan cannot name
  the bundles its own signing produces, because their IDs cover the signed bytes. The publication
  record binds them to the plan instead. It names the selection revision and trust policy it
  expects. It also holds the health criteria and window, the recovery route and the commit mode,
  with a boot limit, a reboot time limit, a limit on repeated requests and an expiry window for an
  unused ACTIVATE. The affected users are all users, because the code is shared.
- **Authorization**, append only. Plan, one effect, actor, and the grant reference with its
  component scope. An interaction that grants several effects writes one record for each.
- **Ticket**, one attempt with exactly one owning coordinator. ID, plan, attempt, state, an
  UNRESOLVED flag, a recorded cause, a boot count, native references and an issued ledger. It keeps
  one health outcome for each user it observed. Each ledger entry is written and synced before its
  crossing.
- **Observation**, append only. Boot ID, Android user and serial, kind, digest of the raw capture,
  and classification. An observation of the boot or the device carries a value that means no user.
  Observations are facts scoped to one boot, not standing assertions. Facts about the host, such
  as a signer's reply or a publication read tied to a PUBLISH attempt, carry no boot and answer only
  for their request or attempt. A read that finds a plan's publication PUBLISHED stays true across
  boots, because a published bundle never changes. Every observation of the device is repeated in
  each boot.
- **Selection**, one for each component. It holds the owner's choice, which is a plan or the
  factory copy, with a revision and the update responsibility from decision 6. A separate
  realization status says how the active bytes relate to that choice.

They follow the rules the native store established:

- Each kind has a fixed version, and its layout is fixed before its first writer ships.
- Strict fields refuse unknown values. Informational fields decide nothing and accept new codes.
  Informational fields never carry authority.
- A change of meaning needs a new version. No state hides in file names that older readers do not
  know.
- Each kind begins with a stable prefix that every later version keeps. An older reader can then
  still tell what a newer record concerns, and fail closed.
- The bundle manifest and the publication records, which serve as the artifact index, follow the
  same rules.
- No device writer reaches the normal image until the rollback contract of decision 5 is in place.

Native accounts are out of scope for version 1. It refuses any target that the native store holds
or that carries a native account. The coordinator checks this at planning and again before each
native crossing, because the contract revalidates target scope at every crossing. This is the
simpler safe choice. Otherwise the coordinator would owe each account a receipt for the lifecycle
record's MAINTENANCE and PACKAGE_CHANGES obligations, kept in system DE storage. Suspension would
also have to close an account's own maintenance. SystemUI carries no native account, so the first
transaction loses nothing, and Android already refuses an update to a package that the native store
holds. In the lifecycle record even "nothing to do" is a receipt with a bound reference. The account
controller's design must say how the coordinator supplies it.

Placement:

- Stages coordinated from the host keep their records on the host.
- On the device, the coordinator runs before unlock. Its records, the restoration bundles and their
  grants live in system DE storage.
- `/metadata` is not needed, as long as no action depends on writes made during the checkpointed
  boot.
- Deployment records stay out of the native identity store.
- Records name actors, components and causes, never credentials or private sources.

### Selection and realization

The selection record holds the owner's choice, not the bytes that Android happens to run.

- A plan names the selection revision it expects. When its ticket reaches APPLIED, the choice moves
  to that plan and the revision increments. A plan whose expected revision no longer matches is
  void.
- Only an authorized plan changes the choice. A plan that chooses the factory copy while it is
  already active makes no native crossing, so its authorization alone changes the record. Until
  gate 2 provides a way back to the factory copy, choosing it while a variant is active means a
  restoration plan built from factory source.
- The chosen plan's records, bundle and restoration bundle are kept for as long as the choice names
  it.

The realization status says how the active bytes relate to the choice. The coordinator sets it in
the cohort check at every kernel boot. The check compares the active bytes with the choice, and the
build fingerprint and factory SystemUI digest with the chosen plan's cohort.

- **CURRENT.** The chosen bytes are active on their cohort, or the factory copy is chosen and
  active.
- **STALE_BASE.** The chosen bytes are active on another base. The compatibility claim and the
  restoration bundle are void, and the owner is shown that the new factory fixes are hidden. A
  linked repair plan is required. It either rebuilds the variant on the new base, or restores
  factory source from the new base at a version above the active one. A stale base is never
  reported as compatible or healthy.
- **DISPLACED.** Android removed the chosen bytes, and the factory copy is active. The owner is
  told, and the choice stays as it was. The owner can repair it under the update responsibility, or
  choose the factory copy.
- **DIVERGED.** Other bytes are active, such as a change made through root or by another
  installer.

### Ticket states

A ticket covers one attempt under one plan. Every state has an exit:

| State | Exits |
| --- | --- |
| PLANNED | AUTHORIZED, CANCELLED, VOID |
| AUTHORIZED | SIGNING, CANCELLED, VOID |
| SIGNING | SIGNED. SIGN_FAILED on a refusal, or when the signer proves that the request can no longer complete. |
| SIGNED, verified and private | PUBLISHED, CANCELLED, VOID. A publication that had no effect allows one more PUBLISH. A second one with no effect, or a publication that names other bytes, holds the ticket with REQUEST_LIMIT. |
| PUBLISHED | SESSION_INTENT, CANCELLED, VOID |
| SESSION_INTENT | SESSION_BOUND, NO_SESSION |
| SESSION_BOUND | WRITTEN or ABANDON_INTENT. NATIVE_RECORD_LOST when the session is gone. |
| WRITTEN | COMMIT_INTENT or ABANDON_INTENT. NATIVE_RECORD_LOST when the session is gone. |
| COMMIT_INTENT | READY, FAILED_NATIVE or NATIVE_RECORD_LOST. BOOT_OBSERVED after a kernel boot. ABANDON_INTENT when a later framework instance shows the session live but not ready. |
| READY | REBOOT_INTENT or ABANDON_INTENT. BOOT_OBSERVED after a boot nobody requested. NATIVE_RECORD_LOST when Android drops the session. |
| READY_AGAIN | Under late commit, as soon as the boot allows a crossing and after any notice that decision 7 requires: REBOOT_INTENT if the ticket holds an unexpired ACTIVATE that no reboot has used, otherwise ABANDON_INTENT. Under early commit, as READY. BOOT_OBSERVED or NATIVE_RECORD_LOST if either comes first. |
| REBOOT_INTENT | BOOT_OBSERVED once a new boot ID is seen. READY when the same boot is still seen after the time limit. ABANDON_INTENT at the request limit. |
| ABANDON_INTENT | ABANDONED. BOOT_OBSERVED when a kernel boot comes first and the ticket had reached COMMIT_INTENT. |
| BOOT_OBSERVED | APPLIED_PROVISIONAL, FAILED_NATIVE, READY_AGAIN, ABANDONED or NATIVE_RECORD_LOST. DIVERGED when other bytes are active and no session of the ticket lives. ABANDON_INTENT when the session is live but still not ready after verification had time to run, or when other bytes are active while it lives. |
| APPLIED_PROVISIONAL | APPLIED once the checkpoint is observed committed. BOOT_OBSERVED after another boot. |
| APPLIED | HEALTH_WINDOW |
| HEALTH_WINDOW | CLOSED_APPLIED or SUPERSEDED. DIVERGED when other bytes become active. An image change ends the window, and the ticket closes as CLOSED_APPLIED with the outcomes observed so far, while the realization status reports DISPLACED or STALE_BASE. |
| SIGN_FAILED, NO_SESSION, ABANDONED | By the recorded cause |
| FAILED_NATIVE | VOID when the cause is a changed build fingerprint, otherwise by the recorded cause |
| NATIVE_RECORD_LOST | APPLIED_PROVISIONAL when the ticket reached COMMIT_INTENT and the active bytes are the bundle's. By the recorded cause when they are the prior bytes. Otherwise VOID if the ticket never reached COMMIT_INTENT or the cohort changed, and DIVERGED if it did. |

The terminal states are CLOSED_APPLIED, CLOSED_FAILED, CANCELLED, VOID, DIVERGED and SUPERSEDED.

- An outcome that changes nothing closes by the cause the ticket recorded: CANCELLED, VOID or
  DIVERGED. Without a recorded cause it closes as CLOSED_FAILED.
- CLOSED_APPLIED keeps one health outcome for each user observed, bound by serial: HEALTHY,
  DEGRADED, UNHEALTHY, INCONCLUSIVE or REMOVED. It claims nothing for a user it did not observe.
- SUPERSEDED links to the repair plan that took over. DIVERGED waits for the owner's next plan.

Rules:

- The intent states are SIGNING, SESSION_INTENT, COMMIT_INTENT, ABANDON_INTENT and REBOOT_INTENT.
  An intent whose reply is lost or ambiguous carries the UNRESOLVED flag. While it is set, the
  ticket blocks conflicting work, and the call is never replayed.
- Two kinds of evidence clear the flag. One is an observation of the exact native reference. The
  other is proof of absence. A complete listing in a later framework instance that shows no staged
  session for the package is one such proof. The signer's proof that a request can no longer
  complete is another. On the device route, a listing of the staged sessions with each one's nonce
  is a third, once D7 qualifies that it reads the referrer of every listed session.
- A new crossing follows only when observation shows that the earlier one had no effect, as for an
  abandon whose session is still live in a later framework instance.
- A ticket's ledger only grows. Each ticket counts the kernel boots it observes from SESSION_INTENT
  on. Its state returns to an earlier one only along four loops:
  - REBOOT_INTENT returns to READY after a lost reboot request. The plan's request limit bounds
    this loop, and at the limit the ticket abandons the session. Only lost requests count toward
    it. A ticket's ledger holds at most 16 reboot requests, and a full ledger also abandons the
    session.
  - The health window restarts after a reboot. The boot limit bounds this loop, and at the limit
    the window ends as UNHEALTHY for every user still observed.
  - BOOT_OBSERVED recurs after APPLIED_PROVISIONAL while a checkpointed install repeats. Only
    Android can end this loop. At the boot limit the ticket holds its state and alerts the owner.
  - ABANDON_INTENT issues a new abandon when the earlier one had no effect. Only Android can remove
    the session. At the request limit the ticket holds its state and alerts the owner.

  The boot limit alert applies to every path that repeats across boots, including a READY_AGAIN
  that recurs under early commit.
- Under late commit, ACTIVATE is required before SESSION_INTENT. READY_AGAIN goes to REBOOT_INTENT
  if the ticket holds an unexpired ACTIVATE that no reboot has used, and otherwise to
  ABANDON_INTENT. It does so as soon as the boot allows a crossing, after any notice that decision
  7 requires.
- In a checkpointed boot, a crossing waits until the checkpoint is observed committed, so a session
  made ready again waits ready until then. The wait is safe while the checkpoint holds.
  Verification after boot completion writes the ready flag into Android's session file under
  `/data`. A crash before the commit rolls that flag back with `/data`, and nothing activates. This
  rests on the checkpoint's rollback, which must be measured.
- Cancellation and voiding never cut an unresolved intent short. They are recorded at once and
  take effect once the intent resolves. A live session is then abandoned first. If the change
  applies anyway, the ticket closes as CLOSED_APPLIED with the cancellation as its recorded cause.
  The choice stays as it was, and the realization reports DIVERGED until a repair plan.
- A change to the selection revision or the trust policy voids the plan before COMMIT_INTENT.
  From then on it closes new crossings. A session not yet activated is abandoned, and one already
  activating is observed to its end.
- When other bytes become active, a ticket that has not reached COMMIT_INTENT abandons any live
  session and closes as VOID. A ticket that has reached it abandons any live session and closes as
  DIVERGED.
- Only one ticket may be open for each component. Android's own overlap check sees only sessions
  verified in the current framework instance, so the coordinator does not rely on it.
- Nothing irreversible happens before the activation boot's checkpoint is observed committed. That
  covers closing a ticket, dropping a retention root and reporting success. No native crossing is
  issued in a checkpointed boot before then either, because a synced ledger entry can still roll
  back.
- Repair is a new linked plan. A retry is a new attempt under the same plan, after the earlier
  ticket has closed.
- D7 takes over host tickets only by a handover recorded in each ticket.

### Staging, activation and restart scope

What the source establishes:

- A persistent app updates only through a staged install.
- A staged install needs `INSTALL_PACKAGES`. A caller other than system, root or shell must also
  be an allowlisted staged installer.
- Creation reaches the session file only with a later write. A framework restart can therefore
  lose a session that is not yet committed.
- Commit seals the session, and a sealed session refuses further writes. Keeping its files
  unchanged during verification is the platform's duty.
- Verification runs the common checks, then the APK checks, then the staged checks, including
  overlapping packages. A last step arms the checkpoint with two tries and marks the session ready.
- Commit writes the sealed flag at once. The committed and ready flags reach the session file only
  with later writes. A session that replied ready can therefore come back from an unclean stop
  still unready.
- A commit refused at validation leaves the active sessions for an in memory history, which lasts
  until the next framework start.
- Signer compatibility with the installed package is checked only at boot.
- On success at boot, the session is marked applied and its stage directory removed.
- On failure at boot, Android stores the reason on `/metadata`, aborts the checkpoint and reboots.
  The next boot fails the session with that reason.
- After a framework restart, nothing is applied or verified again until the next kernel boot. A
  committed session whose verification was cut short is verified again after that boot completes.
- Android does not expire a staged session that is not terminal. Every attempt that ends early
  abandons its own session explicitly.

Commit modes:

- **Late commit**, the default under decision 2. Signing, publication and Andrix's own checks run ahead
  of time. The checks are a signer equal to the installed signer, a versionCode above both the
  factory and the active copy, and a cohort match. ACTIVATE comes before the session is created.
  Creation, write, commit and the reboot then run as one short sequence.
- **Early commit**, an explicit policy. The owner is told that the change applies at any reboot.

Restart scope:

- This plan uses two terms. A framework instance is one system_server lifetime, which the lifecycle
  record counts as a boot. A kernel boot restarts the whole device.
- A staged change needs one kernel boot. That ends all native jobs and apps, and CE storage then
  needs a fresh unlock.
- A framework restart applies nothing, because StagingManager skips restoration once boot has
  completed.
- Every user sees the change, because the code is shared.

### Readback routes

| Stage | Lab shell route, D5 and D6 | Device route, D7 |
| --- | --- | --- |
| Signing | The host signer's reply and request ID, then the artifact store | The protected signer's request ID, then the artifact store |
| Create | The `pm` reply with the session ID | The returned session ID, then `getStagedSessions` matched by nonce |
| Write | The `pm` reply | The call result |
| Commit | The `pm` reply, then the listing and the sections of `dumpsys package installs`, by session ID | The call result, then `getSessionInfo` |
| Abandon | The `pm` reply, then the listing and dumpsys in a later framework instance | The call result, then `getSessionInfo` in a later framework instance |
| Reboot and boot | Boot ID, fingerprint, factory SystemUI digest, the active package's path, bytes and versionCode, and `vdc` checkpoint state | The same facts through Package Manager, StorageManager's checkpoint query and the kernel |
| Health | Observations for each user through the shell | The coordinator's observations for each user |

- `pm list staged-sessions` prints only the session ID, the package, the staged, ready, applied and
  failed flags, and the error message. It prints no referrer, `createdMillis`, stage directory,
  installer UID, sealed flag or committed flag.
- The listing therefore cannot tell a commit refused at validation from a lost record, because
  both vanish from it. Nor can it tell a verifying session from one that is sealed but not
  committed.
- `dumpsys package installs` has active, finalized and historical sections. Each entry shows the
  installer UID, `createdMillis`, the stage directory and the sealed and committed flags. The
  historical section also keeps the final status and message of a removed session until the next
  framework start. The existing `historical_failure` parser already reads it.
- dumpsys shows the referrer only through `SessionParams.dump`, which this plan did not inspect. On
  the shell route, a lost create reply therefore stays UNRESOLVED until D3 qualifies a referrer
  readback.
- If `SessionParams.dump` omits the referrer, the fallback is a helper run under the shell UID that
  calls `getStagedSessions`. The session API returns the referrer unscrubbed to UIDs below 10000.
- A complete listing in a later framework instance that shows no staged session for the package at
  all still gives NO_SESSION.
- The device coordinator creates its own sessions and reads them as their installer UID, which gets
  the referrer unscrubbed. A coordinator outside system, root and shell must also be an allowlisted
  staged installer.

### Before unlock

SystemUI is Direct Boot aware and draws the keyguard. A broken variant can therefore block every
user's unlock.

- The coordinator itself runs before unlock. Everything it needs for repair lives in system DE
  storage, as the placement rules say.
- Repair must not depend on SystemUI. That is a second reason to sign the restoration bundle in
  advance. When the owner chose automatic restoration, its STAGE and ACTIVATE grants are given up
  front.
- A base move voids the only repair signed in advance, so automatic restoration cannot run after
  it. If the variant then breaks the keyguard on the new base, only the host route remains. Under
  decision 6, a rebuilt variant's paired restoration is therefore signed before the image applies.
- In the lab, the repair route is the authenticated host shell. A product route that works without
  SystemUI is a gap.

### Recovery from interruption and uncertain outcomes

| Event | What Android may leave | Ticket rule |
| --- | --- | --- |
| Create reply lost | A session written to Android's file lazily, or none | Find it by nonce on the device route. On the shell route it stays UNRESOLVED, unless a complete listing in a later framework instance shows no staged session for the package. That gives NO_SESSION. |
| Framework restart before commit | Nothing, if the session's creation never reached the file. Its stage directory is then deleted. | NATIVE_RECORD_LOST, and a new attempt |
| Write fails, or its reply is lost | An open, partial session | ABANDON_INTENT for that exact session. A retry is a new attempt. |
| Commit reply lost | Verifying, ready or failed, or refused into the in memory history | Observe by session ID, through the listing and the dumpsys sections. Android defers an abandon while verification runs. |
| Framework restart during commit | A sealed session, perhaps not yet recorded as committed, that nothing verifies until the next kernel boot | Stay in COMMIT_INTENT. A later framework instance that shows the session live but not ready leads to ABANDON_INTENT and a new attempt. A kernel boot first leads to BOOT_OBSERVED. |
| Framework restart while READY | No change. Android's overlap check forgets the session. | Stay in READY. |
| Unclean stop after READY | Applied at the next boot. If the ready flag had not reached the file, verified again after that boot completes. If the commit had not either, the session stays unready. | APPLIED_PROVISIONAL or READY_AGAIN, or ABANDON_INTENT for a session left unready |
| Reboot request lost | The same boot continues | After the time limit, back to READY, and the reboot is requested again under the same ACTIVATE. At the request limit, ABANDON_INTENT. |
| Abandon reply lost | The session hidden as destroyed, or still live | Observe in a later framework instance. Gone gives ABANDONED. Still live means the abandon had no lasting effect, and a new abandon follows. The component stays blocked until then. |
| Install fails at boot | A checkpoint abort, an extra reboot and a failed session with its cause | FAILED_NATIVE, with no retry |
| Stop before the checkpoint commits | `/data` rolled back. The install repeats while the checkpoint has tries left. Once Android aborts it, the session fails as "Reverting back to safe state". | Observe again. The boot count rises. |
| Cancellation | Whatever the current step left | Before any session, CANCELLED. With a session not yet activated, abandon it, then CANCELLED. Once activation has started, observe it to its end, then plan a repair. |
| Trust or selection change | As for cancellation | VOID before commit. After commit, abandon a session not yet activated, and observe one already activating. |
| Image change while a session is pending | Committed sessions fail at the next boot. An uncommitted one survives. | VOID. Abandon an uncommitted session. |
| Image change deletes the variant | The factory copy active | DISPLACED. The choice stays, and the owner is told. |
| Image change keeps the variant | The variant active on a new base | STALE_BASE, with a linked repair plan. Never compatible or healthy. |
| Session file damaged | Sessions skipped and their stage directories deleted | NATIVE_RECORD_LOST. The active bytes decide. |
| Storage freeing while a session waits | Sessions more than eight hours old abandoned, ready ones included | Observe the exact session. If its record is gone, NATIVE_RECORD_LOST. |
| Another installer, or a downgrade through root | Active bytes that match no recorded plan | The realization becomes DIVERGED. A ticket before COMMIT_INTENT abandons any live session, then closes as VOID. A later ticket abandons any live session, then closes as DIVERGED. |
| A user added, removed or switched during activation | Shared code for every user, with per user state changed | Observe each user by serial. A new user gets its own outcome from its first unlock. A removed user's outcome is REMOVED. |
| Coordinator lost | Android continues | Resume by observation |
| Crash during the health window | A SystemUI crash or ANR, or a device reboot | UNHEALTHY for each user a crash affected. A reboot restarts the window and counts toward the boot limit. |
| Unhealthy after APPLIED | No automatic APK revert in the inspected sources. RescueParty is off on userdebug. It acts on user builds, and that interaction was not inspected. | A repair plan with the restoration bundle, or a rebuild if the base is stale |

The checkpoint rows rest on StagingManager and apexd. vold and init, which commit and abort the
checkpoint, were not inspected, so the rollback behavior must be measured.

### Definitions

- **Ready.** The exact session is staged and ready, observed in a named boot. It means validated
  files and an armed checkpoint with two tries. It does not mean a signer check, boot acceptance,
  compatibility or health. Under early commit it also means that the change applies at any reboot.
- **Applied.** All of these hold in one boot:
  - The session is applied, or its record is gone after the ticket reached COMMIT_INTENT.
  - The active package has the bundle's bytes, versionCode and signer.
  - The UID and SELinux context are unchanged.
  - The checkpoint is observed committed.

  Without the checkpoint fact, the state is APPLIED_PROVISIONAL.
- **Compatible.** A claim made before activation, with evidence for each part:
  - The same cohort, meaning fingerprint and factory digest, because SystemUI uses private
    interfaces.
  - Unchanged authority fields.
  - A signer equal to the factory signer.
  - A versionCode above the factory and active copies.
  - A forward only data statement.

  The claim lasts only while the realization is CURRENT. A base move voids it.
- **Healthy.** Judged for each user observed, by serial. The declared criteria held across the whole
  window for that user:
  - SystemUI runs with the expected UID and context.
  - No crash or ANR.
  - The UI marker is present.
  - Keyguard unlock works and CE authority returns.
  - The active bytes are unchanged.
  - Ordinary native work runs.
  - The recovery route is reachable.

  Boot completion and a responsive launcher are not enough. A stale base is never healthy. A user
  removed during the window gets REMOVED instead.

### Rollback limits

- **Code.** A version at or below the factory copy cannot return. GrapheneOS refuses an equal
  version at install, and one that is not above the factory copy at boot. Debuggable builds have
  properties that turn these checks off, and this design does not use them. A version above the
  factory copy but below the active one can return through a requested downgrade. Android allows
  that on debuggable builds, such as the lab's, and on user builds only from system or root. The
  observer reports a downgrade by another actor as DIVERGED. The factory uninstall route stops at
  the keyguard permission gate. Recovery is therefore forward restoration, which is why the
  restoration bundle is signed in advance.
- **Data.** Returning to known good code does not undo a data migration. Each plan states its data
  transition, and the first plan declares it forward only.
- **Checkpoint.** It covers one boot until it commits. Its rollback reverts all of `/data` written
  in that boot, for every user. Its timing must be measured. The checkpoint counts as observed
  committed only when one bracketed reading in that boot shows that the device supports checkpoints
  and that none is pending, so no rollback can follow in that boot. A device that reports no
  checkpoint support gives no such observation. Until a rule for such devices is designed, its
  crossings wait.
- **RollbackManager.** Android asks it to enable rollback only when a session requests that, and
  does not fail the install if it cannot. RollbackManager itself is outside the inspected sources.
  It is a candidate only. Earlier direct AOSP rollback experiments showed that the dependencies of
  a recoverable generation must outlive its records.
- **Images.** The variant stays when its versionCode is above the new factory copy's, which is the
  usual case, and becomes a stale base. It is deleted when the new factory copy's version is equal
  or higher, when the factory copy's shared user changes, or when the variant's signer no longer
  matches the factory signer. The realization then becomes DISPLACED, and the choice stays.
- **Records.** Device records need the rollback contract of decision 5.

### Relation to Android's staging

| Ticket | PackageInstaller and StagingManager | apexd, for the APEX class |
| --- | --- | --- |
| COMMIT_INTENT | Sealed, then committed and verifying | VERIFIED, after a backup of the active APEXes |
| READY | Ready, with the checkpoint armed | STAGED |
| APPLIED_PROVISIONAL | Applied in the checkpointed boot | ACTIVATED |
| APPLIED | Checkpoint committed, which these sources do not show | SUCCESS at boot completion |
| FAILED_NATIVE | Failed. A failure at boot keeps its reason on `/metadata` across the checkpoint abort. | Failed or reverted. apexd reverts when an updatable native process crashes, or after 600 seconds without boot completion. |

Andrix replaces none of this. It adds plans, grants, tickets, the artifact store, the selection
record, reconciliation, the health window and repair.

The APEX class adds rules of its own:

- For an APEX with a factory copy, the payload key must match the factory key. Brand new APEXes
  follow a separate rule.
- apexd skips a data copy below the factory version, and accepts an equal one.
- Package Manager refuses a version below the active one, unless a downgrade is permitted.
- The parent session of a multiple package install cannot be an APEX.
- apexd fails sessions staged under another build fingerprint. On a device with checkpoints it
  refuses to activate outside checkpoint mode.
- apexd keeps its session state on `/metadata`, which a userdata rollback does not revert.
- At boot completion apexd deletes finalized sessions and unlinks data APEXes that are not mounted.

## Reuse and gaps

| Existing piece | Reuse as | Must change |
| --- | --- | --- |
| `scripts/proof/systemui_fixture.py` and the A, R, B and C variants | Variants and factory reproduction | The versionCode stays a lab projection |
| `scripts/proof/systemui_sessions.py` | Reply, listing and historical cause parsers | Add complete listings, the active and finalized dumpsys sections, the active digest, checkpoint state, boot ID and the cohort check. The nonce needs a qualified readback route. |
| The staged verity policy, `package-verity.*` and `package-installer-payload-sync.*` | Required base | Rename and directory durability remain open |
| `tests/apk-signing` and `tests/signing-custody` | Captive callback, capture, retained result, no partial output | Today v2 only, one prompt per operation, a volatile epoch and a shell entry |
| `scripts/proof/signing_recovery.py` | Trusted role manifest | Add the SystemUI platform role |
| Native store persistence in `owner/platform/framework/NativeIdentityStore.java` | Its rules: a strict codec, copies, checked descriptor syncs, presence as present, absent or unknown, and footprints | Not the store itself, and not its Java package |
| The writer fixture and its observers | Issued ledger, nonce, and the UNKNOWN envelope as the model for the UNRESOLVED flag | They use a root lab route only |
| Guarded runners, the staged layout and image switch protocols of the [version 2 work](2026-10-02-native-store-v2-normal.md), the cold reader | Harness, staging and image switch | A QMP stop is not power loss |

Gaps:

- No ticket store or coordinator, no artifact store, no selection record and no installation
  grant.
- No signing of several operations under one approval.
- No SystemUI health probe for each user.
- No product repair route that works without SystemUI.
- No qualified readback of the referrer on the shell route.
- No observation of the checkpoint commit.
- No version projection.
- No AVB signing on the device. avbtool was not inspected.
- RollbackManager is unevaluated.

## Steps

Each step names what it changes, what qualifies it, what stays off and what it needs. The native
account work owns the build slot and the emulator until further notice.

### D1. Records and state machine

- **Changes.** The plan, authorization, ticket, observation and selection records, their codec,
  the ticket state machine, the cohort check and reconciliation, in Java. The code lives in its own
  Java package. Host facades model the Android behavior cited here, including both readback routes.
  The records allow one or two signing transactions for each plan, so a later change to decision 8
  still fits the fixed layout.
- **Qualified by.** Golden bytes and mutation fuzzing of every record kind. A check that every
  state has an exit, and that each loop is either bounded or held with an alert. Fault sweeps at
  every step. Mutants for a replay, an early outcome, a second create or commit, a READY_AGAIN that
  waits under late commit, a boot during COMMIT_INTENT, an Android deletion that resets the choice,
  and a stale base reported as healthy. Guards test rules with mutants rather than byte identity
  wherever possible, because byte pinned guards must be rewritten at every change.
- **Stays off.** Every device writer and every native call.
- **Needs.** The host only.

### D2. Artifact store and bundle builder

- **Changes.** The artifact store with durable publication. A bundle builder that signs the variant
  and its restoration with six apksig operations in one transaction, under decision 8, through a
  host signer with the development key. It verifies both bundles against the role manifest. It
  defines the observation that shows a publication had no effect, after which the ticket may
  publish again, and the ledger allows that second publication.
- **Qualified by.** Refusing each signing callback in turn publishes nothing. Both bundles verify
  against the role manifest with the SystemUI platform role added. A lost acknowledgement resolves
  by reading the exact bytes. A lost signing reply resolves by request ID, or by the host signer's
  proof that the request can no longer complete.
- **Stays off.** The protected device signer, every nondisposable key, and any new SystemUI build.
  D2 signs existing frozen outputs.
- **Needs.** The host only.

### D3. Shell observer

- **Changes.** A read only shell observer for the session listing, the active, finalized and
  historical dumpsys sections, nonce correlation, active package bytes, `vdc` checkpoint state, boot
  ID, fingerprint and the cohort check. It extends the existing session parsers. If dumpsys cannot
  show the referrer, a helper run under the shell UID reads it through `getStagedSessions`.
- **Qualified by.** Parser checks against forms captured on a guest, from
  `pm list staged-sessions`, `dumpsys package installs` and `vdc`. An inspection of
  `SessionParams.dump` in the pinned framework core sources, or the helper's readback instead.
  Output that matches no known form stays unknown, as the current parsers already require. Until
  D3 qualifies, a lost create reply stays UNRESOLVED on the shell route.
- **Stays off.** Every change to the device.
- **Needs.** The host and the pinned framework core sources to write it, and the emulator to
  qualify it.

### D4. Image selection

- **Changes.** No source. Select the newest sealed normal image with the verity, payload sync and
  policy companions. Compare its factory SystemUI with the `985c9a4` baseline, and record the
  producer and fingerprint.
- **Qualified by.** A byte comparison of the factory SystemUI APK.
- **Stays off.** Building, unless the comparison fails.
- **Needs.** The host. The build slot only on a mismatch.

### D5. First emulator trials

- **Changes.** Nothing in the image. Fresh guests, coordinated from the host through the shell
  route, run these trials:
  - The baseline and the three negative controls.
  - Variant A under a full ticket, then R restored from the paired bundle.
  - The health window, observed for each user by serial.
  - Coordinator loss at each step, and dropped create, commit and abandon replies.

  The lab defaults to late commit, as an engineering choice.
- **Qualified by.** Each ticket closes from observation alone, with active bytes, UID, context,
  checkpoint state and health as the plan predicts. No dropped reply or coordinator loss leads to a
  replay.
- **Stays off.** The device coordinator and protected signing. The operator stands in for
  installation authority, and the records say so.
- **Needs.** The emulator, after D3 qualifies on it. Each guest stays bound to its producer image.

### D6. Interruption and image trials

- **Changes.** Nothing in the image. The trials are:
  - Unclean stops after create, write, commit and READY, during the activation boot, and after
    APPLIED.
  - A framework restart before commit, during commit and while READY.
  - A lost reboot request up to the request limit, and a lost abandon reply.
  - READY_AGAIN under late commit, with and without an unexpired ACTIVATE that no reboot has
    used.
  - An unclean stop while a session made ready again waits for the checkpoint commit, which must
    activate nothing.
  - A cancellation at each step, and a downgrade by another installer.
  - A pending session across an image switch, committed and uncommitted.
  - A forward image switch to a factory version below the variant's, which must give STALE_BASE.
  - A control where the factory version is at or above the variant's, which must give DISPLACED
    and leave the choice unchanged.
  - Early commit against late commit.
- **Qualified by.** Each event ends in the state the recovery table predicts, without a replay. The
  selection record keeps the owner's choice, and the realization status reports each base move as
  predicted.
- **Stays off.** As in D5.
- **Needs.** The emulator. The control with a higher factory version needs an image built for it,
  so it also needs the build slot.

### D7. Coordinator on the device

- **Changes.** The device coordinator. It runs before unlock and keeps its records in system DE
  storage. It creates its own sessions and reads them through `getSessionInfo` as their installer
  UID. It takes over open host tickets by recorded handover. Decision 5 is settled first, with the
  candidate floor images it compares. Each reads deployment records, runs the cohort check and
  reports it, and writes none. D7 starts after decision 5.
- **Qualified by.** Image and artifact inspection, then fresh guests and the D5 and D6 trials under
  the device coordinator. A repair through a route that does not depend on SystemUI, including the
  automatic restoration of decision 3. The floor that decision 5 selects is qualified on Android
  with lifecycle version 2 slots and deployment records present, before the writer reaches the
  normal image.
- **Stays off.** The writer in the normal image, until the rollback contract of decision 5 is in
  place. A guard keeps it off, not only the absence of a caller. Protected signing and the APEX
  class stay off too.
- **Needs.** The build slot, then the emulator.

### D8. Protected signing

- **Changes.** First the role map and threat statement for the platform role. Then protected
  signing with the chosen mechanism, with its request IDs joined to the tickets.
- **Qualified by.** The qualification list of the signing default. Trials of accepted signing loss,
  in which a lost reply resolves by request ID, never by a second signature. The signer's proof
  that a request can no longer complete, which lets SIGNING end in SIGN_FAILED. A repair
  authorization that still works when SystemUI is broken.
- **Stays off.** Every nondisposable key, until the threat boundary of decision 4 is written.
  Personalization, which decision 4 needs, has its own compatibility, interruption and recovery
  checks.
- **Needs.** The build slot and the emulator.

### D9. The `/usr` APEX class

- **Changes.** The APEX class on the same records. It starts after the APEX decision under Later
  owner decisions, once the container certificate no longer serves other APKs.
- **Qualified by.** The D5 and D6 trials on the APEX class, including the payload key match, the
  version rules and apexd's revert. apexd's session state on `/metadata` survives a userdata
  rollback, and the trials compare it with the ticket afterward.
- **Stays off.** Whatever the APEX decision keeps refused. The userdebug lab cannot show the
  refusal on user builds, so D9 cannot qualify it.
- **Needs.** The build slot and the emulator.

### Scheduling

The native account work owns the build slot and the emulator until further notice. Under that:

- D1 and D2 can start now on the host. D1 keeps its code outside `com.android.server.pm`, the
  native store's Java package, where package access cannot stop construction of the store's
  release capability. Neither step touches the sources, runners or pins that B1 freezes.
- D2 signs existing frozen outputs. A new SystemUI build needs the build slot.
- D3 can be written now, with the pinned framework core sources for `SessionParams.dump`. Its
  referrer, dumpsys and `vdc` forms need guest captures, so it cannot qualify while the native
  account work holds the emulator.
- D4's comparison can run on the host. Its fallback build, and everything from D5 onward, waits for
  the build slot or the emulator. If D4's comparison passes, D5 and D6 need only the emulator,
  except for D6's control with a higher factory version.

When builds resume:

- Builds have peaked at 47.4 GiB.
- Leave `native-principal-pins.*` and the Package Manager files alone while the lifecycle record's
  B1 to B3 change them.
- Order any new Package Installer companion after the verity and payload sync companions.

## Limits

- In early commit mode, any reboot activates the change, a crash included.
- Late commit is not inert. A crash after commit still applies the change. A commit cut short is
  rebooted under an unexpired activation that no reboot has used, after any notice that decision 7
  requires, or abandoned. In a checkpointed boot it waits ready for the checkpoint commit first.
- Android's session records can vanish without notice, and session IDs can be reused. Sessions are
  therefore bound with every field of the native reference.
- On the shell route, the referrer cannot be read until D3 qualifies a readback. A lost create
  reply can stay UNRESOLVED there.
- Every abandon blocks the component until a later framework instance confirms its outcome,
  whether or not its reply arrived.
- Ready is weak. A wrong signer and a missing sidecar both reach ready. A session that replied
  ready can also come back unready.
- The checkpoint's commit trigger and timing are unknown, because vold and init were not inspected.
  Its rollback affects every user's writes in that boot.
- A boot count written during a checkpointed boot rolls back with `/data`, so a coordinator on the
  device can undercount boots toward the boot limit. D7 keeps the count outside that rollback, or
  allows for it.
- The design assumes userdata checkpoint support, which the lab emulator has. Without it, Android
  installs at boot with no rollback of `/data`. This plan does not cover that case.
- That a framework restart applies nothing assumes the boot completed property stays set across
  the restart. init and its configuration were not inspected.
- An image update either deletes the variant, which leaves the choice DISPLACED, or keeps it on a
  base it was not built for and hides the new factory fixes. The realization status makes both
  visible, and the second needs a repair plan.
- A base move voids the only repair signed in advance. A variant that breaks the keyguard on the
  new base then leaves only the host route.
- A broken variant can block every user's unlock. The lab's repair route is the host shell. A
  product route without SystemUI is a gap.
- There is no automatic APK revert, and crash loop recovery is unqualified.
- Each variant and its restoration consume two increasing versionCodes.
- The lab platform key is public. A real key needs decision 4 and personalization.
- The lab is userdebug. RescueParty is off there, any installer can request a downgrade, and the
  APEX refusal on user builds cannot be observed.
- Multiple users are not qualified.
- Version 1 refuses targets that the native store holds or that carry a native account, at planning
  and before each native crossing.
- A QMP stop is not power loss. Directory times are not durability evidence.
  `pm list staged-sessions` returns 1 on success.
- Open questions:
  - RollbackManager behavior for persistent system apps.
  - Whether the user build APEX refusal is specific to GrapheneOS.
  - Whether the chosen image's factory SystemUI equals the `985c9a4` baseline.
  - What `SessionParams.dump` prints.
  - What the checkpoint's two tries mean to vold.
  - The durability of the stage directory entry and its rename.
  - avbtool's support for external signing, and how far verified boot rollback indexes reach.
- This plan inspected only the Package Manager and apexd sources. RollbackManager,
  StorageManagerService, vold, init, RescueParty, PackageWatchdog, `AtomicFile`, avbtool,
  update_engine, the framework core sources and Soong were not inspected.
