# Native account lifecycle record

Status: accepted by the owner on 2026-10-08. This is stage B of retirement and identity recovery
under the accepted [native account lifecycle authority](2026-10-06-native-account-lifecycle.md). It
folds in the split of retirement from release. It enables nothing by itself, and B1 is next.
Independent reviews in four rounds, and a separate review of the recommendations that the owner
requested, shaped this design. Their findings were checked in the code and are applied here.

## Why

The accepted policy needs facts that the store cannot hold today:

- whether an account is suspended, who suspended it and why;
- that an account is retired, by whom, and which of its duties remain;
- the progress of a separate data deletion;
- the unfinished obligations of an account whose Android user was removed.

A slot's user entry holds a principal ID, an Android user, a user serial and one flag byte. Its only
defined bit means retiring, and the other bits must be zero. Slots are version 1 in every format.
A new meaning therefore needs a new slot version.

The code also calls release "finishing retirement" in all three layers: the manager's
`finishRetirementAfterQuiescence`, the store transaction `finishRetirement`, and the pins'
`finishRetire` with its end phase `RETIRED`. None of this runs today, and R8 removes it from the
normal image. But an account authority wired to retirement would release the UID, which the policy
forbids.

## Owner decisions

Accepted on 2026-10-08:

1. **Suspension reasons.** Every suspension entry carries a specific reason code, with no catch-all
   code. The account's user and the grant holders in scope can see each entry's actor and reason
   code. The suspender may add an optional private note. It is kept with a random salt in the
   suspender's credential encrypted storage, and the record names it only by its salted digest.
   Only the suspender can read the note. It changes neither the explanation nor the suspension's
   authority.
2. **Rollback floor.** B1's image, the image just before the switch, is the supported rollback
   target, qualified on Android. 24bfb6a and 78456b3 are kept as host models, and returning to them
   is unsupported once lifecycle records exist.
3. **This plan**, including two normal image changes, as the owner approved the version 2 switch for
   its format:
   - **B1's image.** It changes boot behavior even though nothing writes lifecycle records. A
     retiring version 1 body's package is deferred at seeding as well as at the scan. Beside a slot
     of version 2 or any later version, package names are protected and a sibling naming the same
     package or principal reads as a conflict.
   - **B2's switch.** The normal image then reads lifecycle records. It still writes none.

## Requirements that follow

- B1 fixes the record layout for good, including the reason code and the note's salted digest.
- The note is unreadable while the suspender is locked and is lost if the suspender's Android user
  is removed. Lifting the entry deletes it. Reading the record cannot confirm guesses about its
  text.
- No lifecycle writer ships to production until the floor reads version 2 slots and verified boot
  rollback protection enforces the floor. Until a lifecycle writer ships, the owner's phone holds no
  lifecycle records, so going back to the current normal image stays possible.

## Alternatives considered

- **A reason code only.** Simpler, with no room to explain. It remains what an entry carries when no
  note is written.
- **Free text in the record.** At most about 40 bytes per entry. It would be readable by the system
  before any user unlocks and survive user removal, against the accepted rule that sensitive
  persistent records use credential encrypted storage.
- **24bfb6a as the floor.** It keeps every hold and defers the account's package. If the package's
  Package Manager mapping were also lost, it would install the package again as an ordinary app
  under a fresh UID, stranded there on return to the new image. No lifecycle writer could ship
  without raising the floor later.
- **No floor.** No rollback qualification at all.

## Left for later owner decisions

These belong to the authority design and the recovery route:

- how the administration grant is held, delegated, revoked and ranked, including whether a grant
  holder may lift an account user's own suspension and who lifts a recovery hold;
- whether any suspension, including a recovery hold, may block the account user's data deletion.
  The record defines scope bit 0 for this, but no writer sets it until the owner accepts a design
  that grants that power;
- what authenticates recovery when credentials or the grant holder are lost.

The policy assigns what suspension closes beyond running work, and the completion evidence of
retirement, deletion and migration, to design work.

A version 2 record holds up to six suspension entries: the account's user, a recovery hold and four
grant references. That is a bound of this record version, not a limit on the authority design. A
later slot version can raise it without losing rollback protection, as the record section explains.

## States

| Policy state | Slot lifecycle | Pin phase | Header entry |
| --- | --- | --- | --- |
| Eligible | ELIGIBLE, no suspensions. Encoded as version 1. | PENDING until designation binds it, then ACTIVE | LIVE |
| Suspended | ELIGIBLE with one to six suspension entries | Unchanged. Every activation point refuses. | LIVE |
| Retiring | RETIRING with actor and obligation inventory. A legacy marker's inventory is unknown. | RETIRING | LIVE |
| Retired, data kept | RETIRED. Retirement obligations discharged, disposition obligations outstanding. | RETIRING | LIVE |
| Deletion in progress | RETIRED with some disposition obligations DISPOSING | RETIRING | LIVE |
| Release in progress (off) | Tombstone with its release ticket, then no directory | RETIRING, or none after a restart | LIVE, then RELEASING |
| Released (off) | None | RELEASED, the handle is stale. The app ID stays held in memory until the next boot. | Omitted |
| Restored by recovery | The last known state, with a recovery hold | PENDING or RETIRING | As found |

Suspension is not a pin phase. Pins are reservation metadata whose phases only move forward.
Suspension entries may exist in any lifecycle state. In RETIRING and RETIRED they keep the record of
who suspended and why.

A boot means a new system_server instance. A runtime restart counts.

### Transitions

- **Suspend.** The account's user, or the grant holder for an account in scope. The manager closes
  admission in memory first: it defers the package name in the recovery view and marks the handle.
  Then the entry is written. An uncertain write keeps the closure. After a restart the durable
  record is the truth, so the caller keeps its own durable intent and retries until the entry is
  confirmed. The caller applies its pending suspension intents before it designates anything at
  boot. A repeated suspension by the same actor confirms the existing entry unchanged. To change
  its reason or scope, the actor lifts and suspends again.
- **Lift.** In this stage only the actor that placed an entry may lift it, which fails closed. A
  recovery hold has no lift path in this stage. Ranking across actors comes from the authority
  design. A lift takes effect when it is durable. The caller learns that from the acknowledgement
  or, after an uncertain result, from a later read. Eligibility returns only through a fresh
  designation. Nothing restarts by itself.
- **Retire.** The account's user with their credential, or the grant holder with authentication.
  RETIRING, the actor and the inventory, with every kind outstanding, are written before quiescence
  starts.
- **Confirm retired.** The account authority, when every retirement kind is discharged. It releases
  nothing.
- **Begin deletion or migration.** The account's own user. Across users, only the grant holder with
  destructive confirmation. Never automatic. Allowed only in a retired boot, defined below. Refused
  while any suspension entry with scope bit 0 exists, which cannot happen until a writer may set
  that bit. It moves every disposition kind to DISPOSING at once, before anything is deleted. Once
  deletion has begun, the DISPOSING kinds complete, because a partial deletion cannot be safely
  paused.
- **Confirm disposal.** The storage, key and policy owners, on observed evidence, in a retired boot.
- **Release (off).** Nobody chooses it. A gated engine starts only when the durable record is
  RETIRED with every obligation discharged and no suspension entry, in a retired boot, and only once
  release is qualified. It completes a CREATING header entry to LIVE before the user is omitted, as
  the store already requires. It clears the key namespace once more, then writes the ticketed
  tombstone, then RELEASING, then removes the directory and omits the entry. An interrupted release
  continues in a boot that began with this account's ticketed tombstone, or with its RELEASING entry
  and no directory. The app ID stays held in memory until the next boot.
- **Restore.** The independent recovery route writes the last known state, with a recovery hold. The
  last known state is the intact copy with the highest generation in the account's lineage, never
  an earlier one. If the state cannot be established, it restores ELIGIBLE with scope bit 1, which
  tells whoever lifts the hold that the account may have been retired.

A **retired boot** is one whose Settings instance began with the account RETIRED, so the package
was deferred at seeding and at the scan and nothing under its UID started. Settings records the boot
facts once, at construction, and never changes them: the accounts that are RETIRED, the ticketed
tombstones and the RELEASING entries without a directory, each with its package's deferral. That
record is the evidence for a retired boot and for continuing a release. The cached store view is not
evidence, because every store read replaces it. Nor are the remembered histories, which grow as
accounts appear and do not exist for tombstones. The rule needs a package dedicated to the account,
which holds for user 0 in this stage.

Forbidden:

- RETIRING or RETIRED back to ELIGIBLE, and RETIRED with an unknown inventory;
- any change to the retirement block's class, actor, grant or time once written;
- a writer creating LEGACY_MARKER, which only comes from decoding a version 1 retiring flag;
- USER_REMOVAL from anything but the Android user removal path;
- an ACCOUNT_USER entry whose actor is not the enclosing entry's own user and serial;
- two entries from one actor;
- a bound obligation reference of zero, and a second binding of a reference;
- an obligation transition not listed below;
- release while a suspension entry exists, and anything after release;
- a restored record becoming active directly;
- any lifecycle write under the existing formats.

Installation, signing and Android user administration are not actor classes.

## The record

### Slot version 2

A version 2 slot begins with a stable prefix: the version 1 body's lineage, app ID, generation,
package name, signer set and user count, then every user's identity, which is its principal ID,
Android user and serial. The lifecycle blocks follow, one per user in the same order, in place of
version 1's flag bytes. A tombstone's ticket comes last. Every later slot version must keep the same
stable prefix. A reader that does not understand a later version can then still take its package
name and principal IDs as negative evidence, and a later version can change everything after the
prefix, including the entry bound. Version 1 keeps its own encoding, in which each user's flag byte
follows that user's identity, so its bytes do not change.

Strict fields refuse unknown values. Informational fields decide nothing and accept new codes. The
layout is fixed in B1 and never changes afterwards, because B1's image must read every later version
2 record. Each user's lifecycle block:

```
state           u8   1 ELIGIBLE, 2 RETIRING, 3 RETIRED                          strict
suspensions     u8   0..6, ascending by (class, actor serial, grant)
  class         u8   1 ACCOUNT_USER, 2 ADMIN_GRANT, 3 RECOVERY_HOLD             strict
  scope         u8   bit 0 blocks deletion and migration (no writer sets it),
                     bit 1 prior lifecycle state unknown (recovery holds
                     only), others 0                                          strict
  actor user    i32  Android user that acted, or that ran recovery
  actor serial  i64  that user's serial
  grant         16   opaque grant reference, nonzero exactly for ADMIN_GRANT
  reason        u16  reason code                                              informational
  time          i64  wall clock milliseconds, never an expiry                 informational
  note          u8   0 none, 1 present: salted SHA-256 32  (the reason decision)
retirement      present exactly when state is RETIRING or RETIRED
  class         u8   1 ACCOUNT_USER, 2 ADMIN_GRANT, 4 USER_REMOVAL, 5 LEGACY_MARKER  strict
  actor user, actor serial, grant, time   as above, zero for LEGACY_MARKER
  inventory     u8   1 this design's 16 kinds, 0 unknown                       strict
  obligations   u8   16 under inventory 1, 0 under inventory 0, ascending by kind
    kind        u8   1..16, see below                                         strict
    state       u8   1 OUTSTANDING, 2 DISPOSING, 3 DISCHARGED,
                     4 ORPHANED_WITH_USER                                     strict
    reference   16   the owner's record ID, zero until bound, bound once
    code        u8   method or evidence                                       informational
    time        i64                                                           informational
```

In version 2 a slot with no users is a tombstone, and its user list is followed by its release
ticket: the last principal ID (i64, positive), user (i32, not negative), serial (i64, not negative)
and a 16 byte ticket ID, which is never zero. The ticket gives an interrupted release an owner after
a restart. A tombstone without a ticket is version 1. The last tail, a RELEASING entry whose
directory is gone, needs only its app ID.

### Encoding rules

- **Version 1 values.** A slot is written as version 1 exactly when it has users and every user
  entry is either ELIGIBLE with no suspensions, or RETIRING with class LEGACY_MARKER, zero actor,
  grant and time, inventory 0, no obligations and no suspensions, or when it is a tombstone without
  a ticket. Every other value is version 2. The version 2 decoder refuses a value that version 1 can
  express, so every value has one encoding. Confirming an existing legacy marker therefore rewrites
  version 1 bytes.
- **Lifting the last suspension** of an eligible account writes version 1 again, so older images
  admit the account again.
- **Inventory.** Inventory 1 lists all 16 kinds exactly once. Inventory 0 lists none and is valid
  only for a LEGACY_MARKER in RETIRING, where every kind counts as outstanding. RETIRED, disposition
  and release require inventory 1. The inventory changes at most once, from 0 to 1 with every kind
  outstanding, by the continuation of that account's retirement.
- **Obligation transitions.**
  - Retirement kinds: OUTSTANDING to DISCHARGED.
  - Disposition kinds: OUTSTANDING to DISPOSING only through the deletion or migration step, then
    DISPOSING to DISCHARGED on observed evidence.
  - Any kind, only through the Android user removal path: OUTSTANDING or DISPOSING to
    ORPHANED_WITH_USER.
  - ORPHANED_WITH_USER to DISCHARGED for disposition kinds only, on observed destruction, as stage C
    defines. Retirement kinds left ORPHANED_WITH_USER block release until stage C defines their
    discharge.
- **Decoder invariants.** The decoder also refuses values no writer can produce: DISPOSING on a
  retirement kind or outside RETIRED, and RETIRED with any retirement kind not DISCHARGED.
- **Entries.** At most one entry per actor: one for the account's user, one per grant reference
  whatever its actor fields, and one recovery hold. A seventh distinct actor is refused with an
  explicit result, and the account stays suspended by the others. The refused suspension stays a
  pending durable intent of its caller, which designates nothing for that account while the intent
  is pending and applies it as soon as an entry is free. A later slot version can raise the bound.
- **Scope bits.** Writers refuse scope bit 0 until the owner accepts a design that grants that
  power. The decoder accepts it, so a later writer's records stay readable. Bit 1 is valid only on a
  recovery hold, in the writer and the decoder.
- **Reasons.** Every entry carries a specific reason code. B1 defines the initial registry with no
  catch-all code. Writers refuse codes outside the registry. Readers show an unknown code as
  unknown. New codes need no new version, because the field is informational.
- **Store transitions.** These replace the current rule that only a retiring user may be dropped:
  - the state only moves forward;
  - suspension entries change only through suspend and lift;
  - the retirement block is fixed except for the inventory rule;
  - a user leaves a slot only when RETIRED with every obligation discharged and no suspension
    entry, and only through the release engine;
  - LIVE to RELEASING needs the engine's ticketed tombstone;
  - every slot write refuses, before its first effect, a version above the store format's slot
    ceiling.
- **Size.** The fixed slot part is at most 1,357 bytes. A suspension entry takes 41 bytes, or 73
  with a note. One user takes at most 931 bytes: 20 for its identity, 2 for state and count, 438 for
  six noted entries and 471 for the retirement block with 16 obligations. 64 users take at most
  60,941 bytes, under the 65,536 byte record limit. Every valid value encodes, so a suspension is
  never refused for size. The encoder measures the exact length first.
- **Damage.** Like the retirement marker today, suspension needs only an intact body. It works with
  a damaged header.

Version 2 freezes this wire contract, not the product's lists forever. A new safety obligation, or
a reason with enforcement meaning, needs a new slot version and a requalified rollback contract.
Informational fields never carry authorization, expiry or discharge.

### Formats

The codec decodes slots up to version 2 in every format. The existing formats still read slots only
up to version 1. They treat an intact version 2 frame as an unsupported footprint, whose decoded
copies act only as negative evidence: package names, principal IDs and sibling conflicts. Nothing is
restored from them. An intact slot frame above a format's slot ceiling is always an unsupported
footprint, whatever its body holds, as the accepted format rule requires: a valid older copy never
hides an intact newer record. For a version above 2, every format also reads the stable prefix, as
the same negative evidence. If the prefix fails validation, that copy gives no evidence, and the
record stays an unsupported footprint. The prefix reader is separate from the full slot decoder and
gives no lifecycle state. The prefix's bounds are frozen with it: at most 64 users and 32 signers, a
package name of at most 255 characters, and an app ID in the application range. The prefix covers
slot evidence only. A later header version still needs its own rollback analysis. The existing
formats' writers refuse any slot above version 1. Every lifecycle operation refuses
under them before any effect, including the in memory closure and pin changes. The store already
treats newer header copies this way. A new format reads and writes headers and slots up to version
2. The codec stays in the records class and the release engine in the persistence class, so no
source file is added.

Today's suites retire and release under both existing formats. Under B1 those flows become
refusals, and their positive cases move to the new format under a run label for new format cases
that are not production in B1. B3's lab image constructs the new format.

### What older images do

Checked in the code. 24bfb6a decodes slots only up to version 1, as does 78456b3, which shares its
store class. An intact newer frame is an unsupported footprint even beside a valid older copy. Holds
come from slot directory names, and from header copies that decode, before any slot is decoded. An
unsupported slot gives no history. Under a version 1 or version 2 header in 24bfb6a, and a version 1
header in 78456b3:

- the app ID stays held;
- no pin or history is restored for that account;
- seeding defers the mapped package and the scan refuses it.

78456b3 under a version 2 header already withdraws every binding.

Further effects:

- **Reservation histories elsewhere.** Any unsupported slot blocks creation readiness for the whole
  store. No account then has a reservation history and the counter is not restored, while body
  histories survive. A package mapped to a bound reservation elsewhere is therefore deferred too.
  This fails closed, and it also holds for B1's image.
- **A lost mapping.** An older image decodes no copy of a version 2 slot, and a LIVE header entry
  carries no package name. If the package's Package Manager mapping is also lost, the package is not
  known as native. The boot capture of data directory owners defers its name, but neither the scan
  gate nor app ID registration consults deferred names. So the package is installed as an ordinary
  app under a fresh UID. Its old data stays untouched: data preparation refuses it, installd's
  strict preparation refuses the owner mismatch, Android's destroy and recreate recovery is blocked
  for preserved names, boot cleanup skips while holds are unresolved, and the old app ID's keys stay
  fenced. App specific external directories and permission state stored by package name were not
  checked. On return to the new image, the package stays stranded at the fresh UID and deferred.
- **B1's image.** It decodes the copy, and the stable prefix of any later slot version, so the
  package name protects and app ID registration refuses the fresh UID. A valid sibling slot naming
  the same package or principal as a version 2 slot then reads as a conflict, which 24bfb6a would
  read as valid. Both fail closed.

### Rejected representations

- **A separate lifecycle file beside the slot.** Older readers open only the slot record, its
  reserve and its backup. They would see a version 1 body that is not retiring, restore it and
  admit its package. It also breaks the accepted format rule against unique state in files the old
  protocol does not know.
- **A record in the header.** A version 3 header would decode to nothing in older readers. Holds of
  reservations with no directory yet, and of RELEASING entries whose directory is gone, would
  vanish. One header also has no room for the detail.

## Retirement and release

| Layer | Now | Proposed |
| --- | --- | --- |
| Manager | `beginRetirement(Handle)` | `beginRetirement(Handle, Retirement)`, recording actor and inventory |
| Manager | `finishRetirementAfterQuiescence(Handle)`, gated on the in memory `retirementCommitted` | `confirmRetired(Handle, Receipts)`, which releases nothing, and `releaseUid(Handle, ReleaseCapability)`, gated on the durable RETIRED record and a retired boot |
| Manager | `Handle.retired`, "Retired handles are removed" | `Handle.released`, release wording |
| Manager | none | `suspend`, `lift`, `beginDisposition`, `confirmDisposition`, each without a caller |
| Store transaction | `markRetiring` | Writes the retirement block. Its doc drops "before account removal". |
| Store transaction | `finishRetirement` | `release`, with the ticket |
| Store transaction | none | `suspend`, `lift`, `markRetired`, `beginDisposition`, `confirmDisposition` |
| Store history | `History.retiring` | The lifecycle state and suspension facts |
| Pins | `finishRetire`, `Phase.RETIRED` | `finishRelease`, `Phase.RELEASED` |
| Pins | `snapshotWithout` | Removed. It has no production caller. |
| Pins | "retiring pin must finish first" | A message saying the UID stays held until release |
| Settings | `finishNativeIdentityReleaseLPw` removes the app ID from the held set | Same name. It forgets the remembered history but keeps the app ID held until a new Settings instance. |
| Comments | Held app ID field, AppDataHelper key clearing, recovery view, pins and persistence class docs, `confirmReleasedSlot`, `removeReleasingSlot`, `validHeaderTransition`, principal-pins.md phase table | Release wording |

Release stays unreachable:

- every class lives in one Java package, so access rules cannot stop construction of the release
  capability. A source rule refuses its construction anywhere but the release engine's tests;
- a source rule refuses, in production text, calls and method references to the manager's release,
  the store release, the pins' release, Settings' release finish, and the store primitives that only
  release uses: removing a releasing slot, confirming a released slot, RELEASING and omission header
  writes, and dropping a user. One mutant per entry point;
- the next final DEX inspection lists every lifecycle and release member, and
  `finishNativeIdentityReleaseLPw`, as absent.

Release at the next boot, when it is enabled later: the omission is durable, but the app ID stays in
Settings' held set, so the allocator skips it, the key fence holds, preparation refuses and package
mutation stays blocked until a new Settings instance. In this tree Android likewise refuses to reuse
a removed user ID within the same system_server instance. Waiting for the boot drops every callback
queued in memory by numeric user and app ID, on the background handler and the Package Manager
handler alike. It does not touch persisted state keyed by UID or package. That is covered only by
the obligations, discharged in a retired boot.

## Obligations

| Kind | Class | Evidence |
| --- | --- | --- |
| 1 WORK | Retirement | Init and supervised work retired |
| 2 API_EFFECTS | Retirement | Managed interface sessions and effects retired or reconciled |
| 3 DELEGATIONS | Retirement | Delegations revoked |
| 4 PUBLICATIONS | Retirement | Pending publication records reconciled |
| 5 LEASE_OPERATIONS | Retirement | Lease operations in flight reconciled. Existing leases and private objects stay rooted. |
| 6 MAINTENANCE | Retirement | Maintenance tickets reconciled |
| 7 ERASERS | Retirement | Generic asynchronous erasers queued earlier completed |
| 8 RESTRICTED_SUBJECTS | Retirement | Restricted subjects and their reservations retired |
| 9 PACKAGE_CHANGES | Retirement | Package and user changes in flight settled |
| 10 ANDROID_STATE | Disposition | Android state keyed by the UID, or by the package for that user, reset |
| 11 KEYSTORE | Disposition | Key namespace cleared, which also removes grants it received |
| 12 DATA_CE | Disposition | Credential encrypted data deleted or migrated |
| 13 DATA_DE | Disposition | Device encrypted data deleted or migrated |
| 14 DATA_EXTERNAL | Disposition | External app data deleted or migrated |
| 15 HOME | Disposition | Home deleted or migrated |
| 16 MANAGED_OBJECTS | Disposition | Private managed objects deleted or migrated, and the account's leases released |

Retirement kinds come from the integrated model's list of distinct completion evidence. Retirement
deletes and releases nothing, so leases and private objects stay rooted until disposition.

ANDROID_STATE covers runtime permissions, app operations, notification preferences, preferred
activities, domain verification, jobs, alarms and similar state. Each store needs a reset route that
deletes no data, works while the package is deferred, and runs under the native authority's own
exemption from the native fence, as its key clear does. Android's package removal paths do not
qualify: they destroy data first, return before resetting anything when data is kept, and the
native fence refuses them while the app ID is held. Data and keys stay under their own kinds. These
routes belong to the disposition design. B1 fixes only the kind.

Security records name the account by its incarnation, the principal ID and serial, so they are
history rather than an obligation.

- **What a reference names.** One owner's retained record for one kind of duty of one account. The
  account is the enclosing user entry's principal ID and serial. The store holds only the kind,
  state, opaque reference, an informational code and a time.
- **When.** Retirement records every kind as outstanding. Each owner discharges its own kind
  explicitly, and "nothing to do" is itself a receipt. Nothing is written in ordinary operation.
- **Where contents live.** With their owners. Interface journals and delegations live in the
  account user's credential encrypted storage. Leases and pending publications use the managed
  store's minimal device encrypted holder references. Keys and data need no private record, because
  their targets follow from the user, app ID and package.
- **Restarts.** The references are in system device encrypted storage. Outstanding obligations
  restore with the retiring pin. A restart discharges nothing.
- **Locked storage.** An obligation whose private record is locked stays outstanding. Unavailable is
  never discharged.
- **Android user removal (stage C).** Android runs its user lifecycle listeners, then destroys the
  user's storage keys, then cleans up Package Manager, then destroys user data. The disposition is
  written at the listener. Obligations whose records died with the user become ORPHANED_WITH_USER,
  bound to the old serial. Disposition kinds are discharged only on observed destruction. Android
  reuses a removed user's ID after a reboot, so its key namespace must be disposed before the ID
  serves a new user.

## Suspension

| Area | While suspended | On lift |
| --- | --- | --- |
| Running work | Stopped | Not restarted |
| New work, login, terminal attach | Refused | Only under a new authority epoch |
| Delegation | No new delegations. Existing ones are dormant. | Dormant ones work again |
| Publication | No new admission. Already published objects stay published. | Reopens |
| Interface admission | New bindings refused. Accepted persistent effects are not undone. | New admission |
| The account's own maintenance | Closed. A shared carrier update is not deferred by one account. | Reopens |
| Data, keys, UID | All kept. No clearing. | No clearing |

This table is the design proposal for what suspension closes. It is design work under the policy.

In this stage, with only user 0 and no native execution:

- **Every activation point refuses a suspended account.** Publication, preparation, commit,
  `currentIdentity`, the published binding check, the scan rule and seeding, each with a mutant.
  The publication refusal sits in the publication transaction, not in the shared slot confirmation
  that retirement and header phase changes also use.
- **The in memory closure** defers the package name. For the rest of that boot this refuses data
  preparation for the package and makes later reconciles skip invalid directory cleanup. Data fixup
  runs only at boot, so the closure does not affect it. B2 and B3 observe this.
- **The boot scan defers the package** of a suspended account, as it does a retired one. Seeding
  defers both too, so the recovery view agrees with the scan. Under the current format that is an
  observable change for a version 1 retiring body whose package is not scanned at that boot. B1
  predicts and stages it. The native identity dump names the deferred packages, because without
  them the old and new seeding look the same on a guest when the package's code is absent.
- **Resuming needs a fresh boot.** A per UID gate in process start and Binder is needed before
  shared carriers or other users.
- **Reversibility is unproven.** Whether a deferred boot prunes permissions, app operations,
  notification preferences or jobs is unknown. B2 proves it with an instrumented subject.

Android's own package suspension is a different mechanism and must not carry this record.

## Steps

### B1. Host source, guards and image

- **Changes.**
  - The renames and the split, with the new release body.
  - The slot version 2 codec, decoded in every format, the stable prefix reader for later
    versions, and the slot ceiling on write.
  - The store transition, inventory, obligation and decoder rules, and the new store transactions.
  - The manager's lifecycle methods with no callers, the gated release engine with its retired boot
    and continuation rules, and the suspension refusals.
  - Settings restoration, scan and seeding for suspended and retired accounts, and its boot facts
    record.

  The production construction stays at the current format.
- **Host qualification.**
  - Golden bytes, with version 1 unchanged, and codec mutation fuzzing. These include confirming a
    legacy marker, every version 1 value refused in version 2, each inventory and decoder invariant
    refused when broken, the maximum size record, and tombstones with and without a ticket, with
    each ticket field's bounds. Intact frames of a later version stay unsupported footprints and
    give their prefix as negative evidence only. A broken prefix gives no evidence and the record
    stays an unsupported footprint that writers refuse to write through. Controls place such a
    frame beside a valid older main, reserve or backup, and in a staging seed, and assert that
    nothing is restored from the older copy and every writer refuses before any effect.
  - The writer refuses scope bit 0, and bit 1 outside a recovery hold, each with a mutant.
  - The transition rules, and fault sweeps at every writer step of each transaction. Release sweeps
    expect continuation from the ticketed tombstone and from RELEASING without a directory.
  - Every lifecycle operation refused under the existing formats before any effect, and a version 2
    slot write refused there before any effect, each with a mutant.
  - The release body: after a durable omission, in the same Settings instance, the allocator skips
    the app ID, the key fence holds, preparation refuses and mutation is blocked. A fresh instance
    frees it. With mutants.
  - The retired boot rule: disposition and release refused in the Settings instance where the
    account became RETIRED, and allowed in a fresh instance that began with it RETIRED. With
    mutants.
  - Rollback models of 24bfb6a and 78456b3, pinned to their Git objects, over every emitted version
    2 layout. They expect holds kept, no history and the package deferred, plus the reservation
    histories elsewhere and the lost mapping case.
  - The same layouts read by B1's own current format, expecting package names protected, the lost
    mapping refused and the sibling conflict.
  - Settings harness parity and mutants.
- **Image.** An image built at B1, whose final DEX differs from 24bfb6a's only in predicted classes,
  with every lifecycle and release member absent.
- **Guest checks.** The staging generator and oracle are extended to version 2 slots. A fresh guest
  boot, then staged layouts:
  - version 1 retiring bodies, scanned and unscanned;
  - version 2 slots read as negative evidence;
  - a version 2 slot beside a bound reservation;
  - a version 2 slot beside a valid sibling naming the same package;
  - a version 2 only slot with its mapping removed. The boot scan rejects the unknown package
    before any app ID is registered, and an install of it is refused even earlier, so this layout
    shows the protection: the code is kept, the app ID stays held and no other owner receives it.
    The registration guard itself is qualified on the host.

  The image is the candidate floor.
- **Frozen guards to update.**
  - The counter admission surface, which requires sources byte identical to 89491b9.
  - The history runner: its one byte rollback rule, its probe and support pins, surface needles and
    mutant anchors. Its probe asserts the old refusal message.
  - The binding runner: the store class identity, the pinned format enum text and its version swap
    mutant, the mutant anchors, focused names, harness labels, name lists and counts.
  - The rollback readers, which today use the current sources under version 1 and must move to
    pinned 24bfb6a and 78456b3 objects. 24bfb6a is not yet a pinned revision.
  - The future format tests, which need version 3 slot frames for their unknown version cases.
    Their expectations and case count change, because a relabeled version 1 body now has a valid
    prefix.
  - The native profile and its test, the recovery boot test, and the recovery seeding, scan and
    restore history fragments.
  - The archived header suites with their adapter, and the pins' closed surface test.
  - The index copy count.
  - The writer fixture's forbidden lists, which must name the new lifecycle and release methods, and
    its call set, then the lab runner's pins.

  Each archived comparison keeps running over its pinned Git objects, and its cases are ported to
  the new interface rather than adapted.
- **Stays off.** Every caller, release, creation, execution, and the production reading of version
  2 slots as positive state.

### B2. The reader in the normal image

The construction literal moves to the new format, in the pattern of the version 2 work:

- the production format rule moves to the new format and refuses the current one as it refuses
  version 1, with its forward check, the facade default and the final DEX enum check updated;
- host models, with the floor modelled from its sources pinned from Git objects;
- an image whose final DEX differs from B1's by that one operand;
- a fresh guest;
- staged layouts;
- rollback to the floor, B1's image, and back, over every staged layout.

The staged layouts are:

- suspension by the user, by a grant, and with scope bits;
- a recovery hold;
- retiring with an inventory, retired, disposing;
- a legacy marker, and an interrupted legacy continuation with a version 1 backup beside a version 2
  main;
- mixed copies in both directions;
- a ticketed tombstone under LIVE and under RELEASING, and RELEASING with its directory gone;
- a noted entry and a maximum size record;
- controls the new reader must read as damaged: a version 2 encoding of a version 1 value, RETIRED
  with an unknown inventory, and a decoder invariant broken;
- slot version 3 frames, one with a valid stable prefix read as negative evidence and one with a
  broken prefix that stays an unsupported footprint with no evidence, and the serial control;
- a version 2 slot beside a bound reservation, as a positive control;
- a version 2 only slot with a lost mapping, read by B2 and by the floor;
- a lift restaged at a later boot, which admits the account again with the same UID, keys and
  data.

An instrumented subject with keys, canary data, a granted permission, an app operation, a
notification preference and a job is carried through suspension, lift and a further boot. The
diagnostic dump gains the lifecycle state and slot version, without reasons, and its header version
changes. Every caller, writer, release and deletion stays off.

### B3. Lab writer

A lab image that constructs the new format gains exact lifecycle commands. They are qualified by:

- predicted bytes;
- unclean stops at each writer step;
- cold reads;
- a read of the lab image's output by the floor image, under a deliberate exception to producer
  binding as in the version 2 rollback work.

Release and deletion stay off even in the lab. The normal image keeps no writer.

## Limits

- Stage C, the Android user removal barrier, comes before any account outside user 0. It also needs
  a path for a suspension whose actor's Android user is removed: in this stage only that actor can
  lift it, so it would hold the UID for good.
- Deletion and release need a boot after retirement, and a released UID becomes free only at the
  boot after release.
- With release off, a retired account's package can never host a new account for that user. This
  includes a retired normal login on a shared carrier.
- Retired accounts keep counting toward the 64 pin and 64 header entry limits. Their leases,
  including leases on shared objects, stay until disposition, which may never come.
- No writer sets scope bit 0 in this stage. If a later accepted design enables it, an entry set by
  the account's user also blocks the grant holder's deletion until someone with sufficient
  authority lifts it, and Android user removal destroys data regardless, as the policy authorizes.
- A damaged record cannot be suspended. It is already inactive, and recovery restores it held.
- The actor's user and serial sit in device encrypted storage, readable by the system. The policy
  requires recording who acted.
- Lab images older than `cac0ba6` lack format preservation and could overwrite a version 2 slot as
  damage. Lab guests stay bound to their producers.
- Android state keyed by package name, such as app specific external directories, is not yet
  checked across a lost mapping.
