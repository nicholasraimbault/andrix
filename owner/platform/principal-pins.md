# Package Manager native principal reservations

Status: internal implementation and Android module build, not runtime qualification or native
account activation. The first adapter supports Android user 0 only. No Binder or shell endpoint,
manifest flag, package signer or ordinary installation can invoke this designation mechanism.
The trusted owner account authority and native manager factory are not connected yet.

This component extends Package Manager's own UID lifetime machinery. It does not allocate a
second set of UIDs, maintain fictional installed state, store permission grants or appoint an
APK as an owner login. It is one prerequisite for the
[ordinary principal launch path](../principal-entry.md).

## Ownership and state

`NativePrincipalManager` is an internal system_server API registered after Package Manager
construction. A trusted account authority must validate owner designation and signer/identity
continuity before calling it. `select` captures the exact installed object, app ID, user serial,
version and current signer certificate digests under Package Manager's locks. It grants nothing
and reserves no UID. The authority binds its designation decision to that selection, then
`prepare` rechecks the complete selection under the same mutation locks. Raw UID/package
numbers are no longer accepted as a substitute. A replacement installation with the same
numbers cannot inherit an old selection, and a retired selection cannot create a new account.
Commit and current identity checks retain this binding. A restored pin is only metadata until
the authority explicitly rebinds its recovered designation to a current selection. This is not
a production signer rotation policy or an owner consent UI.

The initial subject must be an installed ordinary package on internal storage, with no shared
UID, archive, instant, system, updated system, APEX, static library or SDK library role. Its
actual allocator slot must identify that PackageSetting. This is a bounded first integration,
not a permanent product restriction on native account representation.

`NativePrincipalPins` owns exact handles and reservation state:

| Operation/state | Meaning |
| --- | --- |
| Prepare / PENDING | The UID is held immediately. Persistence and current identity still require confirmation. |
| Commit / ACTIVE | The reservation was durably written and the actual package/user identity revalidated. This is not execution, CE or foreground authority. |
| Begin retirement / RETIRING | New activation is closed. The retirement marker must be durable before account removal or quiescence proceeds. |
| Final omission | After confirmed work, manager, API and data obligations, publish a snapshot omitting only this exact retiring pin. Other retiring pins may still own work. |
| Finish / RETIRED | Only after that publication is confirmed does the allocator reservation leave memory. The old handle cannot act on a replacement. |

A lost write, reply, caller or handle never releases a reservation automatically. Exact local
retries retain the same handle. On restore, retiring markers remain RETIRING; other records
become PENDING and require revalidation. No restored record automatically becomes active.
Counters survive an empty reservation set. Undurable prepares are not authority across service
incarnations.

The Package Manager component does not itself prove that native processes or API effects have
retired. That confirmation must come from the trusted account/supervision authority. There is
no caller supplied `retired=true` bit and no automatic close/finalizer on the pin handle.

## Real allocator and package operations

Reservations are persisted inside `packages.xml`. The ordinary app ID allocator skips held IDs
both in existing holes and while extending its array. Removing an installed setting need not
create a fictional replacement setting: the UID can remain reserved while the installed lookup
is absent. Explicit registration/replacement is fenced too. The existing high water mark is
not mistaken for a durable reservation.

Normal uninstall, code replacement and clear data paths check the actual reservation state,
including PENDING and RETIRING. Acquisition takes the install lock and package mutation lock.
Install admission coordinates with the installing package set. Clear data uses a captured
mutation ticket inside its queued operation, before GOS hooks or the freezer run. Acquisition
cannot race that ticket, and an ActivityManager wait is not moved under the install lock.
A system image package with a pinned backing package's name is also refused before it can
change the system package verification catalog or inherit the old data package's UID through
a refused delete. Such a collision needs deliberate account/update maintenance.
These are conservative package level fences for the initial implementation, not final UI or
maintenance policy for every Android user.

Force stop, disable, hide, suspend, permission changes, unusual package repair/move paths and
native work retirement still need their full account lifecycle integration. Holding a UID does
not by itself implement those semantics or make a cached package name live authority.

## Persistence is more than readback

The ordinary Settings writer does not provide the acknowledgement this lifecycle requires.
`FileUtils.sync` returns a boolean after catching an I/O exception, and the existing resilient
writer does not check that result. A later reader can see matching cached bytes without proving
that the original write completed durably.

The native reservation path therefore checks the actual main and reserve writing descriptors,
keeps the preferred old backup until both writes complete, checks backup removal and syncs the
parent directory. Strict write failure leaves the original reservation held. Readback of both
copies and absence of the preferred backup then verify the exact serialized reservation and
retirement markers. Readback is not a substitute for the writer acknowledgement.

Normal Package Manager writes preserve all held records, including retirement markers. The
final candidate drops only the target whose quiescence was confirmed. It cannot accidentally
drop another retiring account which still owns work.

## Recovery and activation limits

The native extension is written after the ordinary package, shared user and key state. An
unsupported or invalid but structurally readable native section is rejected locally, rather than
making Package Manager delete both settings copies. The parser keeps the surrounding package
state. A sticky fence is set for that rejection, duplicate native sections, or a larger settings
read failure, including one before the native section was seen. It blocks native prepare, activation and retirement
until a recovery path exists. It does not refuse every app ID at boot: doing that would turn
normal scan failures into APK/data deletion or a failed boot.

Only reservations successfully understood by this reader can protect the allocator. This cut
does not reconstruct unknown reservation metadata or provide format preserving rollback.

**This is not a complete recovery barrier for unknown or entirely lost Package Manager state.**
Nor can an older framework reader preserve fields it does not understand. Native environment
reconciliation, settings loss/corruption recovery and compatible OS selection must be connected
before a native manager can be activated. No code here silently treats missing records as proof
that old native work ended. General owner administration remains possible, but changing these
assumptions changes which guarantees apply.

Other activation fences remain: owner designation, manager specialization and authentication,
real user/CE authority, home storage identity, resource policy, API bindings and presentation.
User IDs other than 0 require a UserManager deletion/reuse barrier. A serial number alone is not
that barrier.

## Verification and source integration

The state machine, exact handles, allocator holes/appends, unknown write handling, target
retirement, restart markers and concurrency passed JVM checks. Selection tests also cover
changed signer/version/user serial, replaced package objects, foreign service handles, immutable
signer metadata and refusal to recreate a retired account from its old selection. XML and strict writer failures
were exercised with real host files and writing descriptors plus explicit Android API facades.
Those checks do not qualify Android ABX, fs-verity or device filesystem crash behavior.

The adapted Android `services.core` module compiled successfully against the pinned platform.
Its resulting jar contains the three native principal implementation classes and their nested
types. This is an actual framework module build, not a full image or device runtime pass. An
initial compile failure exposed an unavailable Java `O_DIRECTORY` constant and unqualified
error constants; separate corrected inputs passed without suppressing the errors.

The digest guarded adaptation is in
[`native-principal-pins.patch`](../../patches/grapheneos-2026081300/native-principal-pins.patch)
and its profile. `scripts/proof/native_principal_pins.py` applies, checks or reverts only those
exact files. The complete framework fence also verifies the existing CE and Package Installer
companions. The native reservation adaptation was reverted after the module build; the earlier
CE and Package Installer adaptations were preserved.

The exact adapted `AppIdSettingMap` and `ResilientAtomicFile` sources are retained as Apache 2.0
host fixtures with their upstream notices. The source guard checks them against the patched
framework bytes, so the tests do not exercise a parallel rewrite.
