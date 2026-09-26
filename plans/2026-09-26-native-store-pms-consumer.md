# PMS consumes the separate native identity store

Status: implementation and host checks, with Android module and runtime qualification tracked
separately. No product enables the native manager factory. This joins the
[slot storage component](2026-09-25-native-identity-store.md) to Package Manager's identity and
mutation paths. It is not a new UID allocator, installed package database or permission authority.

## Persistent bindings, not settings XML

The PMS adapter stops writing native identities inside `packages.xml`. Its native store is read
before the constructor's install/state lock block. After ordinary settings have loaded, the
adapter applies the union of every native store hold and every in memory pin before scanning
can allocate app IDs. A malformed ordinary settings file cannot delete this separate store.

Only eligible slot records restore pin metadata. Stored signer sets and lineage are retained
separately from a current installed selection. A current APK, matching numeric UID or directory
owner cannot replace the prior binding. Restored pins stay PENDING or RETIRING until the account
authority rebinds designation and actual package/signing/user facts are checked.

Counter availability is separate. With an unavailable counter, intact bindings can be found,
confirmed and retired without minting new IDs. New issuance and whole counter snapshots refuse;
no maximum surviving ID is promoted into a counter. One registry instance has one lineage.

## Exact operation ownership and I/O

`NativeIdentityPersistence` performs per target reservation, publication, marker and release
transactions. Before advancing the counter it reserves every pending core identity, so committing
ID 2 before ID 1 does not strand ID 1. A creation already RETIRING in memory still needs its
negative reservation before a retirement marker can be published. Publication never activates it.

The manager captures immutable operation inputs under the PMS state lock, releases that lock,
performs checked store I/O under the install lock, and then revalidates before commitment. No
store I/O belongs on an AMS, WM or work Stop lane. A failed or lost acknowledgement retains the
original handle and obligations. It does not authorize a new operation or convert unknown into
no effect.

Final release still requires the account authority's complete producer/work/API/key/data
retirement and disposition. Tombstone, directory removal and index omission have separate
acknowledgements. The allocator barrier cannot drop because a later read returned fewer records.

## Boot recovery is preservation and refusal, not invented installation

A negative recovery view is published immutably by live PMS. It carries held app IDs, protected
and deferred names, actual retained code paths, and unresolved code coverage. It never creates
a PackageSetting, grants permissions or authenticates a native account.

Source review identified several independent destructive paths, not just scan errors:

- `/data` parse/reconcile failures delete code in `processParseResult`.
- `StorageEventHelper` later removes code not covered by package settings.
- app data reconciliation destroys unknown CE/DE directories;
- preparation failure can destroy and recreate data as a recovery attempt;
- system fallback/disabled package cleanup can remove settings, code and data;
- keystore cleanup is keyed by UID and can run after its initiating operation.

The adapter retains actual code paths, including their enclosing deletion footprint, and
prevents these cleanup paths from treating recovery as invalid or uninstalled data. DE owner
observations before the scan, and authorized data directory observations during reconciliation,
are **negative preservation evidence only**. CE access still follows actual storage authority.

Code admission is also fenced. A foreign package or mismatched signer cannot execute at a held
native UID merely because a stale settings mapping names it. Structural checks precede reconcile;
the signer check follows normal verification and precedes registration/commit. Held subjects
force certificate collection rather than relying only on an old cached signer. Ordinary install
and replacement cannot bypass the held-UID fence through another package name or shared user.

Unfilterable bulk cleanup is deferred while recovery is unresolved. Per-package normal work can
continue where it is not affected. The deferred boot preparation batch is serialized with native
designation; its queueing is not treated as completion. Install-existing holds its mutation
obligation through the asynchronous restore completion, not just the initiating Binder return.

## Deliberate limits

- The first adapter remains user 0 and an ordinary internal package. A dedicated policy carrier
  is the target vehicle; this does not admit arbitrary APK code as a login.
- Interrupted CREATING entries without a body, and retirement tombstone/index tails after process
  loss, still need an owned recovery continuation. They stay held and unavailable. A tombstone
  cannot reopen APK producers while a release is pending.
- Missing installed mappings are quarantined, not silently assigned fresh UIDs. Automatic
  restoration into an empty held slot is not supplied by this cut. It needs a unique captured
  candidate and a verified ownership ticket after the complete scan.
- A conflicting required system package remains an open boot/recovery qualification case. This
  work does not select a product default that sacrifices boot or allows UID inheritance.
- This cut does not qualify an APK data directory as an owner home. The proposed independent
  CE home provider avoids generic APK mode/group repair, but is not implemented here.
- General moves, rollback restore, user reuse, all queued producer retirement and physical
  filesystem behavior still need joined qualification before activation.
- No automatic record destruction on read failure, generic CREATING cleanup, key clear on enable,
  permanent UID partition or reservation release based on a timeout is introduced.

## Evidence

The actual Java transaction tests run against the actual store and strict framework writer
fixture, with host Android API facades and real files. They cover pending creation order,
retirement before first publication, stored signer/serial mismatches, header damage, unrelated
holds, and every injected directory-sync acknowledgement point through publication and release.
A primary regression first failed against the interrupted writer's skip-retiring-reservations
logic, then passed after correction. The complete matrix ran successfully; no worker timeout is
counted as a pass.

The manager tests use the real slot store beneath PMS facades. They check exact selection,
restored signer continuity, unknown counters, marker-before removal, retained handles and a
monitor check against store writer I/O under the PMS state lock. The immutable negative view has
separate path-boundary and copy tests. These are host checks, not Android boot or permission proof.

The combined focused suite currently passes 24 checks. Seven exact framework fragments are
compiled in a host boot/control fixture and checked against the adapted source by the profile.
The original `7cfcacc` fragments fail controls for healthy data package boot, code retention without name attribution,
data observation without identity attribution and refused system collision deletion; the corrected fragments pass.
Installing name cleanup now also requires the exact request that acquired the marker, so a refused
or old completion cannot remove another request's hold.

The first Android consumer compile exposed a missing `Environment` import in Settings. That failed
trial remains separate and the import was corrected, not bypassed. Framework source guards include
all changed cleanup paths. Android module compilation, emulator recovery and the complete native
account journey must report their own producers and observed results.
