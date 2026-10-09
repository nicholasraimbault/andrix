# Deployment records, version 1

This is step D1 of the [first durable component transaction](../../plans/2026-10-09-component-transaction.md):
the plan, authorization, ticket, observation and selection records, their codec, the ticket
state machine, the cohort check and reconciliation, and durable host storage. It runs on the host
only. Nothing here is built into an image, writes on a device or calls Android.

The code is the Java package `dev.andrix.server.deployment` in
`java/dev/andrix/server/deployment/`. It lives outside `com.android.server.pm`, as the plan's
scheduling requires, and outside `owner/platform/java/`, whose `Android.bp` compiles every Java
file below it into the system_server jar `andrix-owner-lifecycle`. No build file reaches this
directory. Step D7 decides where the device coordinator's code lives.

| File | Contents |
| --- | --- |
| `DeploymentRecords.java` | The five record kinds, their codec and the stable prefix reader |
| `TicketMachine.java` | The exit table, the edge classes, the four loops and the step check |
| `Reconciler.java` | Reconciliation from observations: the step and the cohort check |
| `DeploymentStore.java` | Durable host storage |
| `Coordinator.java` | The host driver that writes each ledger entry before its crossing |

The tests are in `owner/tests/deployment/`, with host facades of Package Manager, StagingManager,
the userdata checkpoint and both readback routes. `scripts/proof/component_transaction_records.py`
runs them under the guarded host discipline and checks the goldens against its own encoder.

The layouts are version 1 and can still change until D7 ships a writer. Any change before then
replaces this text, the goldens and the runner's encoder together.

## Encoding

Every record is one frame:

```
u32  magic      0x52445841, "AXDR" in file order
u16  type       1 plan, 2 authorization, 3 ticket, 4 observation, 5 selection
u16  version    1
u32  length     of the whole record, checksum included
     body
d32  checksum   SHA-256 of every preceding byte
```

Integers are fixed width and little endian: `u8`, `u16`, `u32` unsigned, `i32`, `i64` signed.
`id` is 16 raw bytes and `d32` is 32 raw bytes. `text` is a `u16` length, then that many bytes of
printable ASCII, 0x20 to 0x7e, at most 255. `pkg` is text with the package grammar: at least two
dot separated segments, each a letter followed by letters, digits or `_`. A record is at most
65,536 bytes. The all zero `id` means none, and the all zero `d32` means no bundle.

A reference block appears in tickets and in session and reply observations:

```
u8    presence    bit 0 session, 1 created, 2 stage dir, 3 installer, 4 nonce; others 0   strict
i32   session     > 0 when present, else 0
i64   created     createdMillis, >= 0 when present, else 0
text  stageDir    1..255 when present, else empty
i32   installer   >= 0 when present, else 0
id    nonce       nonzero when present, else zero
```

### Plan, type 1

```
id    installation          nonzero                                         prefix
id    plan                  nonzero                                         prefix
pkg   component                                                             prefix
u8    class                 1 STAGED_SYSTEM_APK, 2 STAGED_APEX, 3 NONSTAGED_APK     strict
u8    target                1 VARIANT, 2 FACTORY, 3 TEMPORARY_FACTORY              strict
id    repairs               the plan this one repairs or replaces, or zero
d32   bundleInput           signing input entry digest: VARIANT nonzero, FACTORY zero
i64   bundleVersion         VARIANT above factoryVersion and baseVersion, FACTORY 0
d32   signer                signer certificate digest, the same presence as bundleInput
d32   restorationInput      the restoration's signing input entry digest or zero, always
                            zero for FACTORY, never bundleInput
i64   restorationVersion    above bundleVersion when present, else 0
u8    signing               0, 1 or 2 transactions; 2 needs a restoration; FACTORY 0  strict
text  fingerprint           the cohort's build fingerprint
d32   factoryApk            the cohort's factory APK, nonzero
i64   factoryVersion        >= 0
d32   baseApk               the APK active when planned, nonzero; FACTORY: factoryApk
i64   baseVersion           >= factoryVersion, equal when baseApk is factoryApk
i32   baseUid               >= 0
text  baseContext           the SELinux context active when planned
u8    users                 1 ALL_USERS                                             strict
u8    data                  1 FORWARD_ONLY                                          strict
i64   selectionRevision     >= 0
d32   trustPolicy           nonzero
u8    commitMode            1 LATE, 2 EARLY                                         strict
u16   criteria              nonzero, bits 0..6 only                                strict
i64   healthWindow          ms, > 0
u8    healthResponse        1 REPORT_AND_WAIT, 2 RESTORE_AUTOMATICALLY (needs a restoration)  strict
id    restorationPlan       the restoration plan approved up front, nonzero exactly for
                            RESTORE_AUTOMATICALLY, neither this plan nor the one it repairs
u8    recoveryRoute         1 HOST_SHELL, 2 DEVICE_COORDINATOR                      strict
i64   noticeDelay           ms, >= 0, the declared delay after notice to other running users
i64   emergencyNoticeDelay  ms, 0 to noticeDelay, below it only when repairs is nonzero and the
                            target is not TEMPORARY_FACTORY
u16   bootLimit             1..32
i64   rebootTimeLimit       ms, > 0
u16   requestLimit          1..16
i64   activateWindow        ms, > 0
i64   verificationWait      ms, > 0
i64   created               wall clock ms                                           informational
```

The criteria bits are 0 UID and context, 1 no crash or ANR, 2 UI marker, 3 unlock and CE
authority, 4 active bytes unchanged, 5 native work runs, 6 recovery route reachable. A plan does
not repair itself. A TEMPORARY_FACTORY plan names its bundle's input, versionCode and signer as a
VARIANT plan does, and in `repairs` the chosen plan it stands in for.

A signing input entry digest is the SHA-256 over the input APK's ZIP entries outside its
signatures: the APK Signing Block and the v1 signature files, as `ApkEntries` defines it under
"Host signer and bundle builder". It is the input's identity for signing, because a built APK may
already carry signatures that prove nothing about the outputs. The plan names its signing inputs, never its
bundle IDs: a bundle ID covers the signed bytes that the plan's own signing produces. The plan's
publication record binds the produced bundles to it. The same holds for each signed APK's digest,
so the plan keeps only facts known before signing: inputs, versionCodes and the signer
certificate. Wherever reconciliation compares the active bytes with the bundle, it reads the APK
digest from the BUNDLE fact that read the plan's publication back PUBLISHED.

### Authorization, type 2

```
id    installation          nonzero                                         prefix
id    authorization         nonzero                                         prefix
pkg   component                                                             prefix
id    plan                  nonzero                                         prefix
u8    effect                1 SIGN, 2 STAGE, 3 ACTIVATE, 4 SELECT, 5 EMERGENCY_NOTICE  strict
u8    inputs                SIGN: bit 0 variant, bit 1 restoration, nonzero; else 0  strict
u8    actorClass            1 GRANT_HOLDER, 2 LAB_OPERATOR                          strict
i32   actorUser             >= 0, or -10000 exactly for LAB_OPERATOR
i64   actorSerial           >= 0 with a user, -1 with -10000
id    grant                 nonzero exactly for GRANT_HOLDER
u8    grantScope            0 NONE exactly without a grant, 1 ALL_COMPONENTS,
                            2 ONE_COMPONENT, which is this record's component      strict
id    interaction           nonzero
i64   grantedAt             wall clock ms, > 0; decides an ACTIVATE's expiry       strict
```

EMERGENCY_NOTICE is decision 7's explicit emergency policy. The installation grant does not imply
it.

### Ticket, type 3

```
id    installation          nonzero                                         prefix
id    ticket                nonzero                                         prefix
pkg   component                                                             prefix
id    plan                  nonzero                                         prefix
i32   attempt               >= 1                                            prefix
u8    coordinatorClass      1 HOST, 2 DEVICE                                        strict
id    coordinator           nonzero
u8    state                 1..28, see below                                        strict
u8    flags                 bit 0 UNRESOLVED, 1 BOOT_LIMIT, 2 REQUEST_LIMIT; others 0  strict
u8    cause                 0 NONE, 1 CANCELLED, 2 VOID_SELECTION, 3 VOID_TRUST,
                            4 VOID_TARGET, 5 VOID_BASE, 6 OTHER_BYTES               strict
u16   bootCount
id    boot                  the last kernel boot observed, or zero
ref   reference
id    windowBoot            nonzero exactly in HEALTH_WINDOW
i64   windowStart           ms since that boot, 0 outside HEALTH_WINDOW
id    successor             nonzero exactly in SUPERSEDED
u16   count, then health entries ascending by user, then serial, at most 64:
      i32 user >= 0, i64 serial >= 0, u8 outcome                                   strict
      0 OBSERVING, 1 HEALTHY, 2 DEGRADED, 3 UNHEALTHY, 4 INCONCLUSIVE, 5 REMOVED
u16   count, then ledger entries in issue order, at most 60:
      u8 crossing, id boot, i64 instance, i64 elapsed, id grant, id reference, i64 issuedAt
```

The states are 1 PLANNED, 2 AUTHORIZED, 3 SIGNING, 4 SIGNED, 5 PUBLISHED, 6 SESSION_INTENT,
7 SESSION_BOUND, 8 WRITTEN, 9 COMMIT_INTENT, 10 READY, 11 READY_AGAIN, 12 REBOOT_INTENT,
13 ABANDON_INTENT, 14 BOOT_OBSERVED, 15 APPLIED_PROVISIONAL, 16 APPLIED, 17 HEALTH_WINDOW,
18 SIGN_FAILED, 19 NO_SESSION, 20 ABANDONED, 21 FAILED_NATIVE, 22 NATIVE_RECORD_LOST,
23 CLOSED_APPLIED, 24 CLOSED_FAILED, 25 CANCELLED, 26 VOID, 27 DIVERGED, 28 SUPERSEDED. The
attempt is at least 1.

The crossings, with the most entries of each in one ledger, are 1 SIGN (2), 2 PUBLISH (2),
3 CREATE (1), 4 WRITE (1), 5 COMMIT (1), 6 ABANDON (16), 7 REBOOT (16), 8 NOTICE (17) and
9 HANDOVER (4). An entry's `issuedAt` is informational. Its rules:

- SIGN, CREATE, COMMIT, REBOOT and NOTICE name the authorization they rely on in `grant`. The
  others have a zero grant.
- SIGN names its signing request in `reference`, PUBLISH its attempt, CREATE the ticket nonce,
  and HANDOVER the new coordinator. The others have a zero reference.
- CREATE, WRITE, COMMIT and ABANDON need their boot and a framework instance, which is at least 0.
  REBOOT and NOTICE need their boot. SIGN, PUBLISH and HANDOVER may have a zero boot, and then
  instance -1 and elapsed 0.
- SIGN, PUBLISH, CREATE, WRITE and COMMIT appear in that order. WRITE needs a CREATE before it,
  COMMIT a WRITE, ABANDON a CREATE and REBOOT a COMMIT.

The ticket's relations:

- UNRESOLVED appears only in the intent states SIGNING, SESSION_INTENT, COMMIT_INTENT,
  ABANDON_INTENT and REBOOT_INTENT.
- CANCELLED needs cause CANCELLED. VOID needs a VOID cause or OTHER_BYTES. DIVERGED needs
  OTHER_BYTES. CLOSED_FAILED has no cause.
- Health entries exist only in APPLIED, HEALTH_WINDOW, CLOSED_APPLIED, SUPERSEDED and DIVERGED,
  and OBSERVING only in APPLIED and HEALTH_WINDOW.
- The nonce is present exactly when the ledger holds a CREATE, and it is the CREATE's reference.
  No other reference field is present without a CREATE, and every state from SESSION_INTENT on
  holds one, except SIGN_FAILED and the closings CANCELLED, VOID and CLOSED_FAILED.
- A HANDOVER's reference is the coordinator, when the ledger holds one.
- A boot count above zero needs a boot.

### Observation, type 4

```
id    installation          nonzero                                         prefix
id    observation           nonzero                                         prefix
text  component             a pkg, or empty for the boot or the device       prefix
id    boot                  nonzero, zero only for a HOST fact               prefix
i32   user                  >= 0, or -10000 (USER_NULL) for no user          prefix
i64   serial                >= 0 with a user, -1 with -10000                 prefix
u8    kind                  see below                                               strict
u8    route                 1 SHELL, 2 DEVICE, 3 HOST                               strict
i64   instance              framework instance, >= 0, or -1
i64   elapsed               ms since the boot at capture, >= 0
i64   wall                  wall clock ms                                           informational
d32   raw                   SHA-256 of the raw capture, nonzero
u8    classification        by kind, see below                                      strict
      then the kind's facts
```

| Kind | Scope | Facts | Classifications |
| --- | --- | --- | --- |
| 1 BOOT | device | text fingerprint | 1 BOOTING, 2 COMPLETED |
| 2 CHECKPOINT | device | none | 1 PENDING, 2 COMMITTED |
| 3 FACTORY | component | d32 apk, i64 version | 1 PRESENT |
| 4 ACTIVE | component | d32 apk, i64 version, i32 uid, text context | 1 FACTORY_COPY, 2 DATA_COPY |
| 5 LISTING | component | u16 count of the package's listed sessions | 1 NONE_FOR_PACKAGE, 2 SESSIONS_FOR_PACKAGE, 3 INCOMPLETE |
| 6 SESSION | component | ref, with its session | 1 OPEN, 2 SEALED, 3 VERIFYING, 4 LIVE_NOT_READY, 5 READY, 6 APPLIED, 7 FAILED, 8 ABANDONED, 9 REFUSED |
| 7 REPLY | component | id ticket, u16 ledger index, u8 crossing, ref | 1 SUCCESS, 2 REFUSED, 3 READY, 4 ACCEPTED, 5 PENDING, 6 UNRECOGNIZED |
| 8 USER | user | none | 1 RUNNING_UNLOCKED, 2 RUNNING_LOCKED, 3 NOT_RUNNING, 4 REMOVED |
| 9 HEALTH | component and user | u16 criteria covered, nonzero, bits 0..6 | 1 HELD, 2 DEGRADED, 3 CRASH, 4 INCONCLUSIVE |
| 10 SIGNER | component | id request | 1 PENDING, 2 COMPLETED, 3 REFUSED, 4 CANNOT_COMPLETE |
| 11 BUNDLE | component | id attempt, id plan, d32 publication, d32 bundleApk, d32 restorationApk | 1 PUBLISHED, 2 ABSENT, 3 MISMATCH |

The observation's relations:

- The device scope has an empty component and no user. The component scope has a component and
  no user. The user scope has a user and an empty component. HEALTH has both.
- SIGNER and BUNDLE may be read on the HOST route, and only they. With a zero boot they need
  instance -1 and elapsed 0.
- A BUNDLE fact is the artifact store's read of the publication record of the plan it names in
  `plan`, taken after the PUBLISH call it names in `attempt` had ended. Both are nonzero.
  PUBLISHED means that the record reads back and every bundle it names is exact. Its
  `publication` is then the record's SHA-256, `bundleApk` the SHA-256 of `base.apk` in the
  bundle that the publication binds to the plan's VARIANT role, nonzero, and `restorationApk` the
  same for its RESTORATION role, or zero when it names none. The two APK digests differ. ABSENT
  means that no record exists, and MISMATCH that it names other bytes. Both have all three
  digests zero. A record that cannot be read gives no fact.
- LISTING and SESSION need an instance. The listing's count is above zero exactly for
  SESSIONS_FOR_PACKAGE.
- REPLY answers CREATE, WRITE, COMMIT, ABANDON, REBOOT or NOTICE, and a framework crossing needs
  an instance. READY, ACCEPTED and PENDING answer only COMMIT, and COMMIT never answers SUCCESS.
  A reply carries a reference exactly when it is a CREATE's SUCCESS, and then it holds the
  session. The ledger index is below 60.

### Selection, type 5

```
id    installation          nonzero                                         prefix
pkg   component                                                             prefix
i64   revision              >= 0                                            prefix
u8    choice                1 FACTORY, 2 PLAN                                       strict
id    plan                  nonzero exactly for PLAN
u8    responsibility        1 REBUILD_WINDOW, 2 KEEP_STALE                          strict
i64   rebuildWindow         ms, > 0 exactly for REBUILD_WINDOW, else 0
u8    realization           1 UNCHECKED, 2 CURRENT, 3 STALE_BASE, 4 DISPLACED, 5 DIVERGED,
                            6 TEMPORARY_FACTORY                                     strict
id    checkedBoot           zero exactly for UNCHECKED
id    repair                a linked repair plan, only with STALE_BASE, DISPLACED, DIVERGED or
                            TEMPORARY_FACTORY
id    temporary             the owner approved temporary factory plan, nonzero exactly for
                            TEMPORARY_FACTORY
i64   changedAt             wall clock ms of the last choice change                 informational
```

The factory copy is never STALE_BASE, DISPLACED or TEMPORARY_FACTORY. The chosen plan never
repairs itself or serves as its own temporary plan, and the temporary plan is not the repair
plan.

### Codec rules

They follow the native store's record discipline:

- Each kind has the fixed version 1, and every valid value has exactly one encoding. Decoding
  checks the size, the frame and checksum first, then the version, every strict code and bound,
  every relation above and the absence of trailing bytes. It never repairs input.
- Strict fields refuse unknown codes. Informational fields accept any value and decide nothing:
  a plan's creation time, a ledger entry's issue time, an observation's wall time and a
  selection's change time. A new code in a strict field needs a new version.
- Each kind begins with the stable prefix marked above, which every later version keeps.
  `decodePrefix` reads it from an intact frame of a later version. It verifies the frame first,
  then each prefix field's rule, and reads nothing after the prefix. The result tells what the
  record concerns and decides nothing else. The store treats a newer ticket's component as having
  an open ticket.
- The checksum detects accidental damage only. It is not authenticity.

## State machine

`TicketMachine` holds the plan's exit table exactly. Each edge is FORWARD, BOOT or REQUEST:

- BOOT edges are COMMIT_INTENT, READY, READY_AGAIN, REBOOT_INTENT, ABANDON_INTENT and
  APPLIED_PROVISIONAL to BOOT_OBSERVED, and the health window's restart. They are taken only when
  the ticket observes a new kernel boot. From SESSION_INTENT on each boot raises the boot count,
  and the BOOT_LIMIT alert is set at the plan's limit on every such path.
- REQUEST edges are REBOOT_INTENT to READY, after a lost reboot request, and a repeated abandon.
  The ledger counts them against the request limit.
- Every cycle of the table passes through a BOOT or REQUEST edge. The four loops of the rules are
  the reboot request loop, bounded, which abandons at the request limit; the health window,
  bounded, which ends as UNHEALTHY for every user still observed at the boot limit, and under
  RESTORE_AUTOMATICALLY supersedes to the listed restoration plan; the provisional loop, held with
  the alert; and the abandon loop, held with the REQUEST_LIMIT alert.

`TicketMachine.check` refuses any successor that leaves the table, rewrites or shrinks the
ledger, adds more than one entry, enters an intent state without its crossing, takes a BOOT edge
without a new boot, withdraws an alert, lowers the cause or the boot count, changes a known
reference field or a final health outcome, or changes a terminal ticket. It also refuses
ABANDON_INTENT to BOOT_OBSERVED, and every exit into DIVERGED, unless the ledger holds a COMMIT,
because the table allows both only once COMMIT_INTENT was reached. SIGNING alone may be entered
without a request, when nothing is left to sign. The store applies the check to every ticket
update.

## Reconciliation

`Reconciler.step` reads the plan, the ticket, the plan's authorizations and tickets, the
selection, the current trust policy, whether the native store holds the target, and the
observations of the current boot. It returns the next ticket value and at most one crossing. The
coordinator writes and syncs that ticket, whose ledger already holds the crossing's entry, then
issues the crossing and records the reply as an observation. A lost reply records nothing.

- **Never a replay.** A step sees no crossing in flight. A ledger entry without a settling reply
  or other evidence is lost or ambiguous, which sets UNRESOLVED in an intent state, and no step
  issues anything while it is set. The flag clears on an observation of the exact native
  reference, on a proof of absence, on a new boot where the table names one, or at the reboot
  time limit. The proofs of absence are a complete listing in a later framework instance with no
  staged session for the package, on the device route a complete listing in a later instance whose
  sessions all carry a nonce and none the ticket's, and the signer's proof that a request can no
  longer complete. The only repeated crossings are the reboot request after its time limit and the
  abandon whose session a later framework instance still shows live.
- **Publication.** SIGNED issues PUBLISH with a fresh attempt ID as the entry's reference. The
  ticket moves to PUBLISHED once a BUNDLE fact naming the plan and a PUBLISH attempt of any of the
  plan's tickets reads the plan's publication PUBLISHED, and no attempt read MISMATCH. A plan has
  one publication, so a later attempt of the same plan skips signing once an earlier attempt's
  publication read back. A MISMATCH read holds the ticket in SIGNED with the REQUEST_LIMIT alert,
  because store damage never heals on its own. A record that cannot be read gives no fact, so the
  ticket waits. A lost acknowledgement is resolved by reading, never by publishing again.
  Only a BUNDLE fact that names the ticket's last attempt and reads the record ABSENT shows that
  the attempt had no effect. The record's rename is the single commit point, the store has one
  writer, and no step sees a crossing in flight, so a read taken after the call ended proves
  absence. One more PUBLISH then follows, which the store completes from the bundles it already
  holds, never by signing again. After a second attempt without effect the ticket holds in SIGNED
  with the REQUEST_LIMIT alert. Cancellation and voiding remain its exits.
- **Signed bytes.** The bundle's APK digest is signed output. Every rule that compares the active
  bytes with the bundle reads it from a BUNDLE fact that read the plan's publication back
  PUBLISHED, whichever attempt it followed, because a publication never changes. Two such reads
  that disagree bind nothing. A ticket reaches PUBLISHED only on such a fact, so from there on a
  missing or disagreeing read is missing evidence, never other bytes. The ticket holds with the
  REQUEST_LIMIT alert, and boots and causes are still recorded. A recorded cause still takes
  effect wherever no bytes are judged, so a cancellation abandons a live session, which needs no
  APK digest.
- **Latest evidence.** The session's state is its latest exact observation, unless a complete
  listing taken after it no longer shows it. A session is gone only when such a listing comes from
  a later framework instance than the crossing in question, so a session destroyed in memory is
  never taken as gone in the instance that destroyed it.
- **Exact references.** A session matches when its ID matches, every field both sides know agrees,
  and createdMillis or the nonce is known to both. Session IDs can be issued again, and a staged
  session's stage directory is `/data/app-staging/session_<id>`, so the directory alone never tells
  a reused ID apart. A create reply binds only with the route's whole reference. On the shell route
  that is the ID with createdMillis, the stage directory and the installer UID from dumpsys in the
  same framework instance. On the device route it is the ID with createdMillis, the installer UID
  and the nonce from `getSessionInfo`.
- **Causes.** A cancellation, a changed selection revision or trust policy before APPLIED, a target
  that the native store holds, a changed cohort and other active bytes are recorded at once. A
  later cause replaces a recorded one only when its code is higher. A cause takes effect once the
  intent resolves: before any session the ticket closes, and with a live session it abandons first.
- **Grants.** Under late commit, SESSION_INTENT needs an unused STAGE and an unexpired ACTIVATE
  that no reboot has used. Under both modes COMMIT_INTENT needs such an ACTIVATE. An ACTIVATE
  expires when the wall clock is before its grant time or the plan's window has passed. It is used
  once a reboot requested under it took effect, which is a later boot observed after the request.
- **READY_AGAIN.** Under late commit, as soon as the boot's checkpoint is observed committed and
  after any notice, it requests the reboot under such an ACTIVATE, or abandons. It waits for
  nothing else. Under early commit it acts as READY.
- **Request limit.** The plan's request limit counts lost reboot requests, the REQUEST edges of
  the table. A request is lost when the same boot outlived it, which the next request in that
  boot, or the time limit in the current boot, shows. A request that took effect is not counted,
  so a READY_AGAIN holding an unused, unexpired ACTIVATE requests its reboot. The ledger holds at
  most 16 REBOOT entries, and a ticket whose ledger is full abandons instead of requesting again.
- **Notice.** Other running users get one notice in each boot, at most the request limit plus one
  in all, and the plan's declared delay, and cannot block the change. The holder needs none: the
  ACTIVATE's actor, or user 0 for the lab operator who stands in for the owner. Without user facts
  for the boot the notice is owed. A restoration approved in advance waits only its shorter
  emergency delay, and only under an EMERGENCY_NOTICE grant when its notice was not delivered.
  Such a restoration is a VARIANT plan whose repaired plan names it as its `restorationPlan`, whose
  bundle input and versionCode are that plan's restoration, and whose publication binds the APK
  that the repaired plan's publication bound to its restoration role. The coordinator reads the
  repaired plan from the store and passes it to the step. A rebuilt variant, any other repair and
  a TEMPORARY_FACTORY plan wait the full delay, and the codec refuses a shorter delay for a
  TEMPORARY_FACTORY plan. The ACTIVATE's expiry bounds every wait.
- **Checkpoint.** Every crossing into the device, and every closing of a ticket that may have a
  session, waits until the boot's checkpoint is observed committed. APPLIED needs it too.
- **Activation boots.** In BOOT_OBSERVED, a session observed applied while other or prior bytes
  are active on the same cohort closes DIVERGED with OTHER_BYTES, because no session of the ticket
  lives. On another cohort it waits for the record to go, and the lost record decides. In
  NATIVE_RECORD_LOST the bundle's bytes lead to APPLIED_PROVISIONAL only once COMMIT_INTENT was
  reached. Before it, those bytes came from elsewhere: the ticket records OTHER_BYTES, closes VOID
  and never moves the choice.
- **Refused commit.** A refused commit ends the attempt. When the session is still open the ticket
  abandons it first, as the plan's rule for attempts that end early requires. When it failed or
  left the listing, the ticket goes to FAILED_NATIVE.
- **Applied.** APPLIED needs, in one boot, the session observed applied or, once COMMIT_INTENT was
  reached, its record gone, the bundle's bytes and versionCode active with the plan's base UID and
  context, and the checkpoint observed committed. Only then, and only for a plan with no recorded
  cause whose expected revision still matches, does the choice move to the plan at the next
  revision. A TEMPORARY_FACTORY plan never moves it: its selection keeps the choice and revision,
  becomes TEMPORARY_FACTORY and names the plan as `temporary`. The move is computed from the
  records, so it is owed until the selection holds it: at APPLIED and in every step of the health
  window, a ticket with no recorded cause whose plan still expects the selection's revision moves
  the choice, or sets TEMPORARY_FACTORY, with that step. The owed realization comes from that
  step's cohort facts, so a step that closes DIVERGED on other bytes moves the choice with
  DIVERGED, and TEMPORARY_FACTORY is set only while the stand in's bytes are active. When the
  step's facts are incomplete the move keeps the realization it names, and the next round's cohort
  check reads it again. The plan's own move, at the revision after the one it expected, is no
  change of revision and voids nothing.
- **Health.** The window starts at APPLIED and restarts after each reboot. Users are bound by
  serial. A crash makes a user UNHEALTHY at once, a removal REMOVED, and a user first seen during
  the window gets its own outcome. At the window's end a user is HEALTHY only when every probe held
  with the plan's criteria and the cohort is the plan's. An image change ends the window with the
  outcomes so far, so a stale base is never healthy. An unavailable health observation never
  counts as a failure: it leaves the user observed, and a user without held probes ends
  INCONCLUSIVE. On a failure the window supersedes to the plan's `restorationPlan` only under
  RESTORE_AUTOMATICALLY, which the approval lists. Under REPORT_AND_WAIT the failure stays in the
  outcomes and the window runs to its end, unless another linked repair plan takes over. The boot
  limit is such a failure: every user still observed becomes UNHEALTHY, and the window closes
  SUPERSEDED to the `restorationPlan` under RESTORE_AUTOMATICALLY, otherwise CLOSED_APPLIED.

`Reconciler.cohortCheck` sets the realization status from the boot's fingerprint, factory APK and
active APK. A factory choice is CURRENT or DIVERGED. A plan choice is CURRENT on its cohort,
STALE_BASE on another, DISPLACED when the factory copy is active instead, and DIVERGED otherwise.
The chosen plan's bytes, and its stand in's, are the APKs their publications bound, from the
BUNDLE facts. Without such a read the facts are incomplete and the status stands.
While the bytes of the selection's `temporary` plan are active it is TEMPORARY_FACTORY, which is
the owner's approved stand in and not Android's deletion of the data copy.
It never changes the choice or the revision. While an open ticket that has not reached APPLIED has
its bundle active, the previous status stands, because the ticket reports that activation. The
`repair` link names the open ticket's plan while the status needs a repair, when that plan repairs
the chosen plan and is no TEMPORARY_FACTORY plan. A status change keeps the link while the new
status still needs a repair, CURRENT clears it, and a new choice starts without one.
`Reconciler.selectFactory` moves the choice to the factory copy on a SELECT authorization when the
factory copy is active, with no crossing.

`Coordinator` drives one component's tickets from the host. A round observes through its route,
records each observation, runs the cohort check, steps, writes and syncs the step's selection and
then the stepped ticket, and only then issues the step's crossing. The selection goes first, so a
coordinator lost between the two writes leaves the choice moved and the ticket one step behind,
and the next step reads that move as the plan's own. A host fault point sits between the two
writes. A fact identical to the latest recorded fact about the same thing, in the same boot and
framework instance, is not recorded again, so a polling coordinator does not grow the store with
every round. The same thing is the kind, route, component, user, request, PUBLISH attempt or
ledger entry, and for a session its ID. The latest such fact is the one with the largest elapsed
time in its boot, never a position in a list, because a new coordinator lists the store by ID and
IDs need not rise with time. When several share that time, a new fact repeats only if it equals
each of them. Signer and bundle facts are decided by precedence, so any identical fact settles
them. An older identical fact does not count, so bytes that return after other bytes are recorded
again and the realization follows them. User and health
observations are always recorded, because the window judges them by time. A new coordinator on the
same store resumes by observation.

## Storage

`DeploymentStore` keeps one directory for each kind under its root, each record in a file named
by its ID, or a selection by its component, with the suffix `.rec`. The reader checks that the
name repeats the record, so no state lives in a name. A write stages the bytes in a hidden sibling
ending in `.staging`, writes and syncs it through its own descriptor, reads it back, renames it over
the target, syncs the parent directory, and reads the target back. Updates are compare and set on
the exact stored bytes. Presence comes from one stat that does not follow links: only
NoSuchFileException is absence, a link or special node is damage, and any other failure leaves the
record unavailable. Damaged, newer, unavailable and unknown entries block every new ticket.

Plans, authorizations and observations are written once. A ticket is created only as the next
attempt of its plan and only when no ticket of its component is open. A selection's choice, plan
and responsibility change only with the next revision, and its realization only at the same one.

On the device the same discipline needs these differences:

- The records live in system DE storage, owned by system with modes 0700 and 0600 and their own
  SELinux label, written before unlock. The host uses POSIX modes only.
- Directory sync uses `android.system.Os` on an `O_RDONLY` descriptor, as the native store does.
  The host uses `FileChannel.force` on the directory, which works on Linux.
- Writes in a checkpointed boot are provisional until the checkpoint commits, so a device record
  written then can roll back. The reconciler already issues nothing and closes nothing before the
  commit. Host records do not roll back with the device's `/data`, which is why the host checks
  Android's state again after every boot.
- The rename relies on the single coordinator's serialization, because a plain rename replaces an
  existing target. On f2fs the rename's durability is an open question of the plan.
- The device coordinator reads its sessions as their installer UID, so its references carry the
  nonce. The host's shell route reads no referrer until D3 qualifies one.
- A process crash is not power loss. The host fault points simulate crashes between the write
  protocol's steps only.

The public constructor always syncs. A package private `unsynced` store, used only by the host
sweeps of the reconciler, skips the syncs, which those sweeps cannot observe. The store's own suite
runs with every sync, and the runner checks that the public constructor syncs and that no main
source other than the store names `unsynced`.

## Host facades

`owner/tests/deployment/AndroidFacade.java` models what the plan cites, not Android itself:

- Sessions are created in memory and reach the session file only with a later write. Commit writes
  the sealed flag at once, and the committed and ready flags with later writes. A framework restart
  reloads from the file, so a session that never reached it is lost. Destroyed sessions leave the
  file with a later write. Sessions more than eight hours old are freed.
- Verification marks a session ready and arms the checkpoint with two tries. Each armed boot runs
  under the checkpoint. A stop before the commit rolls `/data` back, and once the tries are spent
  Android fails the session as "Reverting back to safe state". A session rejected at boot stores its
  reason, Android reboots, and the next boot fails it. The model keeps an arm made in the same boot
  across that boot's commit. vold and init were not inspected, so this is an assumption to measure.
- An image change fails committed sessions and deletes a data copy whose versionCode is not above
  the new factory copy's, or which lacks verity or the factory signer.
- The shell route reads the listing joined with dumpsys by session ID, with createdMillis, the stage
  directory and the installer UID, and dumpsys's history of sessions removed in the same framework
  instance. It never reads the referrer. The device route reads `getStagedSessions` as the
  installer, with the referrer and without the stage directory, and sees no destroyed session.
- Faults are injected by crossing: a lost reply, a refusal, a crash of the coordinator before or
  after the effect, a framework restart or an unclean stop after it, an unrecognized reply, and no
  effect at all. Every crossing first checks that the store holds its entry.

## Artifact store

This part of step D2 keeps signed bundles on the host. `ArtifactRecords.java` holds its record
kinds, the bundle manifest, the publication and the host signer's signing transaction, and
`ArtifactStore.java` the store. They use the frame above with types 6, 7 and 8, version 1, and at
most 4,096 bytes.

### Bundle manifest, type 6

```
id    installation          nonzero                                         prefix
pkg   component                                                             prefix
u8    role                  1 VARIANT, 2 RESTORATION                        prefix
id    transaction           the signing transaction, nonzero                prefix
d32   input                 SHA-256 of the exact input APK bytes, nonzero
d32   inputEntries          the input's identity: SHA-256 over its ZIP entries outside its
                            signatures, nonzero
i64   versionCode           > 0
d32   apk                   SHA-256 of base.apk, nonzero, and it may equal input
i64   apkBytes              > 0
d32   idsig                 SHA-256 of base.apk.idsig, nonzero
i64   idsigBytes            > 0
d32   certificate           SHA-256 of the signer certificate, nonzero
d32   key                   SHA-256 of the signer public key, nonzero
u8    schemes               bit 0 v2, 1 v3, 2 v4: exactly 7                         strict
u16   sdkMin                >= 1, the low end of the APK's declared SDK range
u16   sdkMax                >= sdkMin, the high end of that range
u8    v4                    1 VERIFIED                                              strict
```

The bundle ID is the SHA-256 of the manifest's whole frame, checksum included. It names bytes,
not approval: the manifest names the signing transaction but no plan or grant. Each scheme was
checked explicitly over the SDK range, because `apksigner verify` can report v2 as unverified at
a high minimum SDK although its block is present. The manifest holds no time,
so the same bytes always give the same ID. The operations' own IDs stay in the signer's records.
Built inputs may already carry signatures, which prove nothing about the outputs, so the input's
identity is `inputEntries`, and signing that reproduces its input exactly is still a valid
bundle.

### Publication, type 7

```
id    installation          nonzero                                         prefix
id    plan                  nonzero                                         prefix
pkg   component                                                             prefix
u8    count                 1 or 2                                                  strict
      then for each: d32 bundle, nonzero, u8 role, VARIANT first, then RESTORATION,
      and id transaction, the bundle's own signing transaction, nonzero
i64   publishedAt           wall clock ms                                           informational
```

A publication never names one bundle twice. Each entry's role is the bundle's role in this plan,
while the manifest keeps the role it was signed in. Each bundle names its own signing transaction,
so a pair from two transactions fits the layout. `decodePrefix` reads a later version's installation,
then a manifest's component and transaction or a publication's plan and component, and nothing
after.

### Layout and publication

```
<root>/bundles/<id>/manifest.rec        the manifest, whose digest is <id>
<root>/bundles/<id>/base.apk
<root>/bundles/<id>/base.apk.idsig
<root>/publications/<plan>.rec          the publication of one plan
<root>/.staging-<id>/                   the private staging copy of one bundle
```

- **Visible only when complete.** A bundle is PUBLISHED only when a publication names it and its
  directory holds exactly the three files, with the manifest's digest as its name and the members'
  digests and sizes as the manifest's. A directory that no publication names is ABSENT, whatever
  it holds. A named bundle that differs, lacks a file or holds another is MISMATCH. A damaged,
  newer or unreadable publication makes every ID UNAVAILABLE, because it might name it.
- **Together or not at all.** A plan's publication names its bundle and, when it has one, its
  restoration, in that order. The store refuses any other set, so a bundle is never published
  alone (decision 8).
- **Bound to the plan.** The plan names only facts known before signing. Each bundle must carry
  the plan's input entry digest and versionCode for its role in this plan, the plan's `signer` as
  its `certificate`, and the transaction the publication names for it, which is the bundle's own.
  The publication record is what binds the produced bundles to the plan. `apks` reads back the
  APK digests it binds, for the BUNDLE fact.
- **A plan that signs nothing.** Only decision 3's restoration plan signs nothing and publishes.
  It must name the plan it repairs in `repairs`, target the variant role, and have no restoration
  of its own, so a temporary factory plan that signs nothing publishes nothing. It publishes
  exactly one bundle, in its VARIANT role. That bundle's manifest says it was signed as
  RESTORATION, and the publication of the plan it repairs must read back PUBLISHED and bind the
  same bundle ID in its RESTORATION role. The pair was therefore published together first. The
  bundle must carry the plan's input entries, versionCode and signer, and keeps its own
  transaction. It is verified again before the record is written. Every other plan that signs
  nothing is refused. A plan that signs publishes each bundle only in the role it was signed in,
  so no bundle signed as a variant ever fills a RESTORATION role.
- **Order.** Staging writes each member and the manifest through its own descriptor, syncs each,
  then syncs the staging directory and the root. Publication then reads every staged bundle back,
  verifies all of them, renames each into `bundles/<id>`, syncs `bundles/`, and writes the
  publication by the deployment store's protocol: stage, sync, read back, rename, sync the parent,
  read back. Nothing is visible before that last rename, so a stop at any point leaves both
  bundles visible or neither.
- **A lost acknowledgement.** It resolves by reading the exact bytes. A second publication of a
  plan that has a publication writes nothing: it is true only when the stored publication has
  exactly its bytes and every bundle it names reads back PUBLISHED.
- **No effect, then once more.** `planPublication` reads a plan's record: PUBLISHED, ABSENT,
  MISMATCH or UNAVAILABLE. Read after a PUBLISH call has ended, ABSENT shows that the call had no
  effect, because the record's rename is the single commit point. The staging directories are
  never evidence. A second publication then completes from the exact bundles the store already
  holds, whether still staged or already renamed into `bundles/<id>` with no record naming them.
  `held` reads such a bundle back without its bytes being supplied again, and every bundle is
  verified again before the record is written. Nothing is signed again.
- **Resuming.** A bundle already in `bundles/<id>` with the exact bytes is the same content,
  because its name is its manifest's digest. A resumed publication keeps it and drops the staging
  copy. Other bytes under that name are never replaced, and the publication fails.

The store holds no lock, like the deployment store, and its one coordinator serializes every
call. On the device, restoration bundles live in system DE storage, which D7 owns.

### Signing transaction, type 8

The host signer's durable record of one signing transaction:

```
id    installation          nonzero                                         prefix
id    transaction           the ticket's SIGN request ID, nonzero           prefix
pkg   component                                                             prefix
id    plan                  the approved plan, nonzero
id    authorization         the SIGN grant, nonzero
d32   certificate           the platform role's certificate digest, nonzero
d32   key                   the role's public key digest, nonzero
u16   sdkMin                >= 1, the declared range's low end
u16   sdkMax                >= sdkMin; 65535 means no maximum
u8    state                 1 OPEN, 2 COMPLETED, 3 REFUSED, 4 CANNOT_COMPLETE        strict
u8    refused               the refused operation, 1 to the count, nonzero exactly for REFUSED
u8    count                 3 or 6, three operations for each APK
      then for each: id operation, nonzero and distinct, u8 role, u8 scheme 1 V2, 2 V3, 3 V4;
      the variant's three first, then the restoration's, each in scheme order
u8    outputs               two for each APK
      then for each: u8 role, u8 member 1 APK, 2 IDSIG, u8 facts, d32 input, d32 inputEntries,
      i64 versionCode, d32 digest, i64 bytes; each APK's base.apk, then its base.apk.idsig
```

The four expected outputs of a variant and its restoration are named by role and member. Each
names its input's SHA-256, entry digest and versionCode, and the facts it must meet, as bits:
0 its entries are the input's, 1 v2 verifies below SDK 28, 2 v3 verifies over the range, 3 v4
verifies over the range, 4 every signer has the platform role. An APK's facts are exactly bits 0,
1, 2 and 4, and a sidecar's exactly 3 and 4. An output's digest and size are nonzero exactly
when the transaction COMPLETED. `decodePrefix` reads a later version's installation,
transaction and component.

### Host signer and bundle builder

`HostSigner` signs one transaction under one approval, as decision 8 asks: three key operations
for each APK, v2, v3 and v4, so six for a variant and its restoration. Each key operation first
asks the captive callback.

- **Durable record.** The record is written OPEN before the first key operation, with fresh
  operation IDs and the four expected outputs. The outputs are retained privately under
  `outputs/<transaction>/` and synced. The record is then replaced once, by COMPLETED with their
  digests and sizes, which is the commit point.
- **Refusal.** A refused operation ends the transaction REFUSED, names the operation, and keeps no
  output. The signer latches the refusal itself. An engine that swallows the callback's exception
  and signs on still ends REFUSED, and every later key operation of the transaction is refused
  without asking the callback or using the key.
- **Signatures that the operations made.** The engine signs each input without its APK Signing
  Block, so signatures that a built input already carries never reach the outputs. Each APK takes
  exactly three key operations: a fourth is refused before the key is used, and fewer or more end
  the transaction CANNOT_COMPLETE. Each operation's result must appear in the output's signing
  block or its sidecar.
- **Approval by index.** The host callback sees the transaction and the operation's index, not the
  scheme or the data the operation signs. The protected device signer must bind each approval to
  the scheme or to the data it signs.
- **Lost replies.** A transaction ID that has a record is never signed again, so a lost reply is
  resolved by reading the record by that ID. A read that finds the transaction still OPEN, or no
  record at all, proves that the request can no longer complete. Calls are serialized and the
  signer never resumes a transaction, so the read records CANNOT_COMPLETE, and the ticket records
  SIGN_FAILED.

`BundleBuilder` is the coordinator's host.

- **Signing.** It signs the plan's inputs for the SIGN grant, under the ticket's SIGN request ID
  as the transaction ID. An input is never signed unless its entry digest is the plan's, it holds
  no v1 signature files, and its own binary manifest declares the plan's and the component's
  facts. For SystemUI those are the package `com.android.systemui`, the shared user
  `android.uid.systemui`, the persistent flag, the plan's versionCode for its role, and a minimum
  SDK and maximum SDK equal to the transaction's declared range. apksig's binary manifest parser
  reads them. The manifest records none of them except the versionCode and the SDK range, so
  recording the package, the shared user and the persistent flag would need a new manifest
  version.
- **Verification.** Before a bundle is staged, each output must meet its facts. v2 must verify with
  a pass below SDK 28, v3 and v4 over the declared range, 37 and up, and every signer of every
  scheme must have the certificate and key digests of the platform role. The role comes from the
  trusted role manifest of `scripts/proof/signing_recovery.py`, whose SystemUI platform role binds
  the platform slot. Only then does the ticket see SIGN_COMPLETED, so SIGNED means verified and
  private. A COMPLETED transaction whose retained outputs are gone, damaged or fail their facts is
  reported as CANNOT_COMPLETE. A read that fails, or a staging failure after every output passed,
  proves nothing, so it gives no fact. The ticket waits, and a later read stages the same outputs
  again.
- **Publication.** It names exactly the bundles of the ticket's own SIGN requests, each with its
  transaction, which is that request's ID. A plan that signs nothing is decision 3's restoration
  plan, and names the restoration that the repaired plan's publication bound. The store publishes
  both bundles together or neither, and verifies each again first.
- **Reads.** A read takes each SIGN request by its ID. A request without a record is recorded as
  CANNOT_COMPLETE with the roles and inputs of the grant its entry names, so a plan that signs twice
  records the restoration's request with the restoration's role and input. A read also returns the
  store's publication with the APKs it binds, for the BUNDLE fact, after the last PUBLISH attempt
  and in every later state.

`ApkEntries` gives an input's identity. It is the SHA-256 over each central directory entry's name,
method, CRC-32, sizes and the SHA-256 of its stored data. The signing block, the v1 signature
files, offsets, local extra fields and the comment are left out, so signing and realigning keep
it. The v1 signature file names match with only ASCII letters folded, so a file whose name differs
from one only by a letter outside ASCII, such as the long s or the dotless i, stays an entry. An
archive whose entry runs past its central directory is refused as invalid.

`apksig/` holds the apksig engine and builds only against the pinned apksigner jar, SHA-256
`6b96559764325d085a6bad6be109cc3053791d63826f84dc0e74032db136a196`.
- **Why the jar is pinned.** The tree's apksig sources compile with `javac --release 8 -g` to 257
  of the jar's 274 apksig classes byte for byte. The other 17 differ at least in the order of
  compiler generated lambda methods, so the jar itself is pinned, not the sources.
- **Options.** They are the options of the sealed outputs: `--v4-signing-enabled true
  --min-sdk-version 37`, and every other option at the tool's default.
- **Key operations.** Each goes through a KMS key configuration whose provider calls the host
  signer, so apksig never holds the key.
- **v1.** The tool's default also signs v1, which takes a fourth key operation for each APK, and
  the sealed outputs carry it. The transaction's engine therefore signs without v1, and an engine
  with v1 serves only the byte for byte comparison.

## Qualification

| Suite | Cases | What it shows |
| --- | --- | --- |
| `DeploymentRecordsTest` | 52 | 23 goldens, two layouts by hand, every strict code refused by position, informational fields free, every relation, a bundle fact's attempt and plan and its digests set exactly when it read the publication, resealed mutations of every kind refused or canonical, the stable prefix |
| `TicketMachineTest` | 70 | the exit table equals the plan's, every cycle passes a counted edge, each loop meets its limit, and every rule in single steps, including a second publication only after a read of absence that names the attempt, a read of other bytes held with the alert, and the bundle's bytes read from its own publication |
| `DeploymentStoreTest` | 14 | write once, compare and set, a crash at each write step, presence and footprints, one open ticket, the selection's revision rules |
| `TransactionTest` | 44 | both routes and both commit modes end to end, decisions 3, 6 and 7 over whole runs, each row of the recovery table, fault sweeps at every crossing, a coordinator lost between the selection and ticket writes, world events at every round, and the invariants of every run |
| `ArtifactStoreTest` | 22 | 6 goldens, the signing transaction record, strict codes by position, informational times, the stable prefix, resealed mutations refused or canonical, one bundle ID for the same bytes, and publication: together or not at all, bound to the plan's inputs and signer, verified first, a stop at every step, a lost acknowledgement read back, a second publication from the held bundles, a pair from two transactions, a restoration plan publishing the published restoration and only in the variant role, damage as MISMATCH |
| `SigningTest` | 24 | with a fake apksig: the record written OPEN before the first operation, refusing each callback in turn publishes nothing, a refusal latched although the engine swallows it, an engine that returns its input or discards its operations' results, a fourth key operation, a lost reply resolved by the transaction ID, the proof that a request can no longer complete, a request recorded under its own grant, a staging error and an unreadable output that give no fact, every scheme and every signer verified, other entries, other input bytes, v1 files and other manifest facts refused, both bundles together or neither, a lost acknowledgement, a second publication from the held bundles, a pair from two transactions, a restoration plan publishing the published restoration, one whole coordinator run to PUBLISHED and a repair plan after it, and the input entry digest's ASCII folding and refusal of a name past the end |

`scripts/proof/component_transaction_records.py` checks every golden against its own encoder,
written from the tables above, and runs 109 deliberate defects against the suites predicted to catch
them. Given the pinned apksigner jar, the sealed SystemUI build, the development platform key and a
role manifest with its commitment, it also runs `SealedOutputsTest`. That suite reproduces the
sealed outputs byte for byte with the tool's options, then signs, verifies and publishes the pair in
one transaction of six operations. The runner first signs a reference without v1 with the jar's own
command line, and the transaction's outputs must equal it byte for byte. An engine that also signs
v1 is refused by the operation count. It also checks that the inputs are signed without their
signing block and that every key operation's result is in the outputs, reads both APKs' own facts
with apksig's binary manifest parser, and refuses one operation through apksig. Whenever any
sealed input is given, the run passes only if the sealed phase ran and passed. Every compiler and
JVM it starts has a capped heap, metaspace and code cache, the serial collector and one client JIT
compiler thread, so the run stays well inside its 2 GiB guard.

## What the owner decisions changed

The owner's decisions in 2c7a250 replaced the options that version 1 had kept open. The layouts
keep version 1, because no device has written them.

- **Decision 1.** The authorization gains `grantScope`. A grant holder's record says whether the
  grant covers every component or only this record's component, so a grant delegated for one
  component is recorded as such. A lab operator's record has neither grant nor scope. D1 holds no
  grant record, so the device writer of D7 must check the scope against the grant itself.
- **Decision 2.** No layout change. Late commit is the fixtures' default. Early commit stays a
  plan's explicit `commitMode`, and the machine keeps both.
- **Decision 3.** The plan gains `restorationPlan`, nonzero exactly under RESTORE_AUTOMATICALLY.
  The approval names that plan and grants its STAGE and ACTIVATE up front, as authorization records
  of the restoration plan. The window supersedes to it only on an observed failure, which includes
  the boot limit. An unavailable
  health observation is no failure and ends INCONCLUSIVE. Each activating reboot still needs its
  own unexpired ACTIVATE that no reboot has used.
- **Decision 6.** The selection's responsibility is now REBUILD_WINDOW, with its length in
  `rebuildWindow`, or KEEP_STALE. The codes UNDECIDED, HOLD_IMAGE_UPDATES, FACTORY_WINS and
  KEEP_VARIANT are gone. A longer hold is a longer window. The plan gains the target
  TEMPORARY_FACTORY, for the owner's approved build from the new image's factory source. The
  selection gains the realization TEMPORARY_FACTORY and the `temporary` plan. The choice and its
  revision stay with the variant, and DISPLACED still means only that Android deleted the data copy.
  A rebuilt variant that repairs the choice moves it at APPLIED and clears `temporary`.
- **Decision 7.** The plan's `notice` kind is gone. Its `noticeDelay` applies whenever another user
  is running, and `emergencyNoticeDelay` may be shorter only for a restoration approved in advance:
  the repaired plan must name it as its `restorationPlan`, and it must install that plan's
  restoration bundle. The effect CONSENT
  and the actor class ANDROID_USER are gone, because other users cannot block the change. The
  effect EMERGENCY_NOTICE is the explicit emergency policy. It shortens the wait only when the
  notice was not delivered, and no other grant implies it.
- **Decision 8.** No layout change. The fixtures sign a variant and its restoration in one SIGN
  with both inputs. The signing count still allows two transactions, as the plan's D1 section asks
  at line 689. The artifact store's publication names each bundle's own signing transaction, so a
  pair from two transactions fits there too.
- **Decisions 4 and 5.** No change. Decision 5 is open, so the layouts may still change before D7.

The qualification follows. The consent mutant became a grant scope mutant, six new mutants guard
the rules above, and each decision has cases in the codec, machine, store or transaction suites.

## Field choices the plan leaves open

The plan names these records' contents but not their fields. These are D1's choices:

- **Lineage.** The plan's lineage is two fields: `installation`, which binds every record to one
  store as the native store's lineage does, and `repairs`, the plan it repairs or replaces.
- **Bundle facts.** The plan names each APK's signing input by its entry digest, its versionCode
  and the signer certificate's digest, which are all known before signing. It names no bundle ID
  and no signed APK digest, because both cover the signed bytes that the plan's own signing
  produces. The publication record binds the produced bundles to the plan, and the BUNDLE fact
  that reads it back carries each bound APK's digest, so the cohort check reads the store's facts,
  not the store.
- **Native base.** The base is the cohort, which is the fingerprint and the factory APK with its
  versionCode, plus the bytes, versionCode, UID and context active when planned. The UID and
  context serve the Applied definition's "unchanged" test.
- **Decision fields.** The signing count (decision 8), the commit mode (2), the health response
  and its restoration plan (3), the notice delays (7), the grant scope (1), and the update
  responsibility with its rebuild window (6) are fields. The owner's decisions are recorded in
  them. See "What the owner decisions changed".
- **Verification wait.** The plan's "after verification had time to run" needs a duration. It is
  the plan's `verificationWait`.
- **Grants.** One effect per authorization record, because each grant is its own record. One
  interaction that grants several effects writes several records with one `interaction` ID. A
  SIGN names its inputs, so one transaction covers both APKs and two cover one each.
- **Observations.** Beyond the boot, user, serial, kind, raw digest and classification, an
  observation carries its route, framework instance, elapsed and wall time, and its kind's facts.
  Replies are observations too, tied to their ledger entry, so reconciliation reads replies and
  readbacks alike. Times within a boot use the elapsed clock. Only an ACTIVATE's expiry uses the
  wall clock, because it spans boots.
- **Ticket fields.** The alerts are flags. The boot count goes with the last boot observed. The
  health window keeps its boot and start, and the reference keeps presence bits, because each
  route reads only some fields.
- **Causes.** VOID_TARGET covers the native store's targets, and OTHER_BYTES becomes VOID before
  COMMIT_INTENT and DIVERGED after it.
- **Signing count 0.** A plan whose bundles are already signed, such as a repair with the
  restoration, signs nothing, and its PUBLISH binds the bundles that another publication made
  visible. A later attempt of a plan whose earlier attempt published its bundles signs nothing
  either: the step needs a fact that reads the plan's publication back PUBLISHED after an earlier
  attempt's PUBLISH, and never infers publication from a ledger alone.

## Where the plan is contradictory or underspecified

Line numbers refer to `plans/2026-10-09-component-transaction.md` at 2c7a250, which holds the
owner's decisions. Each item says what D1 does.

- **One grant per record, or several effects per record.** Line 259 says each grant is its own
  record, and lines 262 to 263 let one interaction grant three effects. Line 284 gives the
  authorization "effects", in the plural. D1 writes one effect per record and ties the records of
  one interaction with an `interaction` ID.
- **Applied after a lost record.** Applied needs "the session is applied" (line 576), but line 384
  lets NATIVE_RECORD_LOST reach APPLIED_PROVISIONAL from the active bytes alone, when no session can
  be observed. D1 accepts a session gone from a complete listing in place of the applied flag, but
  only once COMMIT_INTENT was reached. Before it, the bundle's bytes came from elsewhere, and a lost
  record closes VOID with OTHER_BYTES.
- **A lost record across an image change.** Line 384 closes a ticket that reached COMMIT_INTENT as
  DIVERGED when other bytes are active, but line 556 voids a pending session at an image change and
  line 356 reserves DIVERGED for root and other installers. D1 closes as VOID with VOID_BASE when
  the cohort changed.
- **A publication that never completes.** SIGNED has no failure exit (line 368), and a lost
  acknowledgement is never resolved by publishing again (lines 237 to 238). D1 held in SIGNED
  until the owner cancelled. The amendment at 9334d70 settles it, and D2 follows it: a read of the
  plan's publication record absent, naming the attempt, allows one more publication from the held
  bundles, and a second attempt without effect holds with the REQUEST_LIMIT alert.
- **How long verification may take.** Line 378 abandons a session "still not ready after
  verification had time to run" without a duration. D1 adds the plan field `verificationWait`.
- **ACTIVATE under early commit.** Decision 3 needs the owner's consent for each activating reboot
  (lines 80 to 81), and line 478 only says that under early commit the owner is told the change
  applies at any reboot. Lines 261 to 263 expire an unused ACTIVATE, but nothing says whether early
  commit needs one before COMMIT_INTENT, or what a ready session does when it expires. D1 requires
  an unexpired ACTIVATE before COMMIT_INTENT in both modes and abandons a ready session whose
  ACTIVATE expired.
- **Whose consent.** Decision 3 asks for the owner's consent (line 80), decision 7 for the
  installation grant holder's (line 98), and decision 1 lets the owner delegate the grant for one
  component (line 72). D1 takes the holder of a grant whose scope covers the component, and the lab
  operator in the lab, which stands in for the owner as user 0.
- **When an ACTIVATE is used.** A reboot request that never took effect does not use it (line 261),
  but a boot after a request cannot be told from a crash. The trial at line 761 implies a crash boot
  without any request does not use it. D1 counts it used once any boot is observed after a request
  under it, and unused otherwise.
- **The expected revision after APPLIED.** Lines 332 to 334 move the choice at APPLIED and void a
  plan whose expected revision no longer matches, which every plan's own APPLIED causes. D1 applies
  the revision check before APPLIED only, as lines 429 to 431 suggest.
- **Closing after a late cancellation or voiding.** Line 554 observes an activation "to its end,
  then plan a repair", and lines 429 to 431 likewise, without naming the closing state. D1 lets the
  ticket reach APPLIED and close CLOSED_APPLIED with the cause recorded, and never moves the choice
  for it. The realization then reports DIVERGED until the repair.
- **Abandons with a successful reply.** Line 498 confirms every abandon in a later framework
  instance, so even a successful abandon blocks the component until a framework restart or boot.
  Line 851 states the block only for lost replies. D1 follows line 498.
- **Absence on the device route.** The proofs of absence name only a listing with no staged session
  for the package (lines 400 to 402 and 517 to 518), while line 543 finds a session by nonce on the
  device route. D1 also accepts a complete device listing in a later instance whose sessions all
  carry a nonce and none the ticket's.
- **The stage directory in the reference.** Lines 225 to 226 bind a session by its stage directory
  too. In the pinned `PackageInstallerService.buildSessionDir` a staged session's directory is
  `/data/app-staging/session_<id>`, so it never tells a reused ID apart, and `SessionInfo` carries
  none. Only createdMillis and the nonce distinguish a reused ID.
- **The notice under late commit.** Lines 474 to 477 run creation, write, commit and the reboot as
  one short sequence, and line 418 puts any notice before the reboot. D1 gives the notice before
  SESSION_INTENT, so the sequence stays short.
- **How the notice is delivered.** Decision 7 says notice must not depend only on the UI being
  repaired (line 102), and lets a restoration shorten it when SystemUI cannot deliver it (lines 99
  to 101). Nothing names the other route or how a failed delivery is observed. D1 models the notice
  as one crossing with a reply and treats any reply but a success as not delivered.
- **The temporary factory build.** Decision 6 approves "the new image's own SystemUI, built from
  its factory source" (lines 94 to 95), which is neither the factory copy nor the variant. D1 makes
  it a plan of its own target, installed like a variant, that never moves the choice.
- **A refused commit with its session still open.** Line 373 sends a refusal to FAILED_NATIVE, but
  line 469 requires every attempt that ends early to abandon its own session. D1 abandons an open
  session first.
- **Outcomes when an image change ends the window.** Line 381 closes with "the outcomes observed
  so far", but users still observed have none yet. D1 records them INCONCLUSIVE, never HEALTHY.
- **The target check before an abandon.** Lines 309 to 310 check the target before each native
  crossing. D1 exempts the abandon of the ticket's own session, so a held target never strands a
  live session.

## Assessment of the open items

An independent review of the first D1 candidate assessed the nineteen items above and found three
more. D1 and D2 do not edit the plan. Plan amendments come separately, and those that need an
owner decision go to the owner first. Line numbers in the items refer to the plan at 2c7a250.

The plan amendments in ac61668 and 9334d70 settled these, and the records follow them:

- **1.** An authorization holds one effect, with the grant's component scope.
- **2, applied after a lost record.** Applied accepts an absent record only after COMMIT_INTENT,
  and the NATIVE_RECORD_LOST row has the same limit.
- **3, a lost record across an image change.** The row voids the ticket when the cohort changed.
- **4, a publication that never completes.** The plan's publication record read absent after the
  PUBLISH call has ended, in a fact naming that attempt, shows that the attempt had no effect. The
  ledger allows two PUBLISH entries, and the second publishes from the bundles the store holds.
- **10, closing after a late cancellation or voiding.** CLOSED_APPLIED with the cause recorded,
  the choice unchanged, and DIVERGED until a repair plan.
- **11, abandons with a successful reply.** Every abandon blocks the component until a later
  framework instance confirms it.
- **12, absence on the device route.** The device nonce listing is a proof of absence once D7
  qualifies that it reads the referrer of every listed session.
- **21, the boot count on the device.** D7 keeps the count outside the checkpoint rollback, or
  allows for it.
- **22, the REBOOT ledger bound.** The ledger holds at most 16 reboot requests, only lost requests
  count toward the request limit, and a full ledger abandons.

These still need a plan amendment or design work before D7, by the review's assessment:

- **6, ACTIVATE under early commit.** Real. State under "Commit modes" that both modes need an
  ACTIVATE before COMMIT_INTENT, and that an early commit session whose ACTIVATE expires unused is
  abandoned. This follows from decision 3, but the owner should see it.
- **15, how the notice is delivered.** Real. D3 or D7 needs a notice route that avoids SystemUI
  and gives an observable receipt. Ask the owner whether the route changes what other users see.
  Until then a lost reply counts as undelivered and shortens the delay.
- **20, the restoration's ACTIVATE.** Decision 3's ACTIVATE, granted in advance, expires on the
  restoration plan's own `activateWindow`. A restoration that is needed later than that waits for
  a new grant.

Design work in D2 settled two more without a plan amendment:

- **The plan's APK digests.** The plan no longer copies them. Like a bundle ID, an APK digest
  covers the signed bytes, so a plan whose own signing produces them cannot know it before
  signing. Each comes from the BUNDLE fact that read the plan's publication back, which plan lines
  291 to 294 and 598 support.
- **The restoration plan's binding.** A plan that signs nothing writes its own publication of
  bundles that another publication already made visible together. This keeps decision 8, because
  the pair was published together first.

The review finds that this note settles the rest, optionally with a one line wording fix:

- **5.** Keep `verificationWait`. D5 and D6 measure it.
- **7.** The consenting party is the holder of a grant covering the component, from decisions 1
  and 7. The owner may confirm decision 3's wording.
- **8.** Any boot after a request uses the ACTIVATE.
- **9.** Read line 333 as "before APPLIED".
- **13.** Correct if the pinned source matches AOSP. The review could not read the pinned framework
  sources, because only `prebuilts` is present.
- **14.** Notice before SESSION_INTENT.
- **16.** Install the temporary build like a variant, as line 337 implies.
- **17.** Abandon the open session first.
- **18.** INCONCLUSIVE.
- **19.** Exempt only the abandon of the ticket's own session.

The repair link is fixed: the cohort check links the open repair plan and keeps the link across
a status change. These items stay open:

- **`selectFactory`.** Only the tests call it. No coordinator applies a factory plan's SELECT
  yet. D4 or D7 must call it, or the plan must say who does.
- **Voiding evidence.** `targetHeld`, `trustPolicy` and `rebootRequested` are coordinator
  fields, not observations, so the evidence for voiding is not recorded. Recording them needs new
  observation kinds, which changes the observation layout. D1 does not do this yet.

## Questions for later steps

- Whether `SessionParams.dump` prints the referrer is D3's question. Until then a lost create reply
  stays UNRESOLVED on the shell route unless a later framework instance lists no staged session for
  the package.
- A ticket that held with an alert waits for the owner. No product route for that exists yet.
- Automatic restoration under decision 3 supersedes the window to the restoration plan that the
  approval listed. Opening that plan's ticket, and holding image updates for a rebuild window under
  decision 6, are D7's.
- The notice route that does not depend on SystemUI alone is D3's or D7's question.
