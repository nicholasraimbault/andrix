# Native identity boot recovery observers

These are disposable ordinary UID APKs and host observers for the PMS slot consumer. They are
not part of `PRODUCT_PACKAGES`, native account designation, native execution bootstrap or
production signing custody. They request no runtime permission or shared UID and disable backup.

## Observer contract

Each instrumentation invocation targets its own package and has a bounded operation, fresh request
nonce and setup identifier:

- `initialize` requires no existing fixture canary or key. It creates a dummy signing key in
  its own AndroidKeyStore namespace and dummy CE/DE canary files. Partial initialization is an
  unknown operation, not permission to initialize again.
- `observe` requires an independently retained public key digest. It creates no missing key,
  canary or directory. It reads the original canaries and signs a fresh public challenge with
  the existing key. Host verification uses only public material.
- `absent` checks that the same fixture names do not exist in another UID. It creates no fixture state.

This is not a claim that starting an Android process or using keystore changes no system files.
The platform may prepare caches or upgrade a key blob. The invariants concern the original canary
bytes and key identity. Initialization also creates its `files` directories. Require a clean
baseline reboot before faults; the fixture does not qualify directory durability under power loss.

Results identify the actual UID, package, current APK signer and request. The host observer
requires exactly one successful instrumentation result with matching scope, before state and
old key identity. Missing output or transport failure is UNKNOWN, not proof of quarantine or
success. `assess` combines strict parsing with independent public signature verification using
the controller's nonce. `parse_refusal` recognizes only exact admitted negative controls, not a
missing result. Never regenerate a missing key or update the expected fingerprint from a later reply.

`request_ledger.py` records independent PMS, UserManager and APK certificate capture hashes. It
creates a fresh unpredictable nonce, records it before command submission and permits one issue
and one outcome only. Unknown stays attached to that operation. An old capture or a repeated
initialize is not a new successful attempt. Initialize anchors a key only after the externally
supplied UID, serial and APK signer are checked.

The fixture APKs share a development test certificate but not a UID. They declare no signature
permission. This tests UID/package boundaries independently of signer uniqueness. A separate
signer variant, if used, needs its own captured artifact and expected certificate.

## Controlled metadata, not designation

`FixtureStore.java` uses the actual `NativeIdentityRecords` codec to create a fresh input tree
for a controlled recovery fault in a new disposable guest. Package, UID, signer and user serial
must first be observed from Android and checked against the artifact. Copying these bytes
into a guest does not establish production native authority or test the production writer.

The controlled fixture layout belongs at `/data/system/native-principals`, with UID/GID 1000,
directories mode 0700 and record files mode 0600. The lab controller must quiesce the relevant
writer or stage offline, restore the actual policy label, require identical main/reserve input
bytes and no preferred backup sibling, and reboot fully. Capture hashes, listings, ownership,
modes and labels before and after each boot. VALID alone cannot distinguish main from reserve.
A permission or label failure can look like missing state, not just damaged state.

`dumpsys package --andrix-native-identities` uses the existing privileged dump permission gate.
Its bounded output describes cached store state, allocator holds and cursor only. It neither
reads private terminal contents nor reports a live work, CE or execution lease. The instrumented
APK has no authority to change those holds.

## Deciding runtime sequence

1. Establish no-store controls. Run and reboot A and its independent UID peer. Record dummy
   canaries, the original public key and actual PMS identity. Check observation before creation
   on a separate disposable subject so a missing fixture cannot be mistaken for success.
2. Inject a healthy controlled reservation for A. Require both normal A admission and positive
   evidence that the hold was consumed, not merely a successful boot. The privileged dump and
   an admitted A's refused install-existing operation provide distinct observations.
3. Exercise reserve fallback and then a damaged rich record with its occupancy intact. A must
   become unavailable when identity cannot be verified, without freeing its ID or destroying
   its code, data or keys. Its peer must remain usable.
4. Restore only the exact metadata fault and reboot. Verify the same data and key through A's
   own ordinary authority. Never restore app data or a keystore database to manufacture survival.
5. Qualify an empty held allocator slot and a lost PMS mapping separately. Allocation observations
   must use the actual current cursor and mappings, not a guessed UID floor. A diagnostic process
   scan is not a lease. XML/ABX surgery is controlled fault injection, not a reproduced field loss.
6. Run destructive clear/uninstall negatives last in their disposable instance.

Capture fresh settings recovery copies before each relevant fault. A backup can take precedence
over the file that was edited. Never restore stale package settings over intervening installs.
If a snapshot is used, freeze and restore the complete guest state while it is powered off,
including FBE and KeyMint storage, not just a userdata file.

`settings_fault.py` removes only one top level fixture `<package>` element from a decoded copy.
It preserves the semantics of all remaining certificate references, including their shared global
indices, and refuses to orphan the removed package's signing keyset. It does not remove package
restrictions, permission or domain state elsewhere. Wrong signer and serial records, kept intact
rather than malformed, must separately exercise the corresponding scan fences.

No runtime result is recorded by this source alone. Android boot, actual storage/keystore behavior,
locked CE, secondary users, production designation, writer crash durability and native lifecycle
remain distinct qualification claims. Required system UID collisions and unowned CREATING or
retirement tails are not repaired by this fixture.
