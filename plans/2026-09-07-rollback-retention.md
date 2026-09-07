# Android rollback static-library retention

Follow the [dependency-aware cohort rehearsal](2026-09-07-webview-cohort-rollback.md).
The observed failure was deletion of an unused non-factory library while Android
still offered a consumer rollback requiring that exact version. Manual signed
prerequisite restoration worked; automatic recovery must not depend on it.

## Implementation under qualification

Keep ownership in Android's existing machinery, not a fake client, new privileged
service or alternate installer. Five changes in the pinned `frameworks/base`
project extend the declared adaptation to seventeen files in nine projects:

- Capture direct static-library names/versions from the **old installed base
  APK**, validating its package/version against PackageManager's observation.
  Exact r1 `ApkLite` includes these declarations even with parser flags0; an APK
  without declarations has an empty list. The incoming update is not the source.
- Store references alongside the existing `AtomicFile` rollback JSON. Reject
  malformed supplied metadata; the field is optional for historical compatibility.
  Existing r1 fingerprint-upgrade behavior invalidates prior-image active records;
  no retroactive protection of legacy active records is claimed.
- Publish an immutable union through a wait-free `RollbackManagerInternal` query.
  Complete initial worker-thread load/publication before publishing that service,
  because staged application and delay-zero PM pruning precede boot-complete.
- Add the check to PM's normal used-library uninstall guard, also rechecking after
  waiting for its install lock. Explicit versioned uninstall and unused-library
  pruning use that path. PM takes no rollback-handler wait and does no disk I/O
  for the retention query. SDK-library behavior remains unchanged.
- Refresh on record/dependency/state changes. Retain while enabling, available or
  `restoreUserDataInProgress`; set the restore flag before entering COMMITTED.
  Release on normal completion once live PM client references take over, and when
  the rollback record is expired/deleted. Multiple records are unioned, not a
  hand-maintained reference count. Retained library packages remain ordinary
  clients of their own nested dependencies.

Enable/availability publication now checks atomic metadata-save success. A failed
commit also persists the restored AVAILABLE state for retry after reboot. No
signature, certificate, Android identity, SELinux, TLS/CT or kernel rule changes.
The WebView/library/config APKs and `/usr` payload are unchanged inputs.

## Verification boundary

Changed-function host trials extract code from the declared patch and compile it
with explicit mocked Android value/container/service surroundings. They exercise
empty/invalid/identity-mismatched old APK metadata, exact versions, state predicates,
union/release, JSON type validation, immutable snapshots and concurrent nonblocking
readers. These are not full framework or persistence/Watchdog runtime proof.

Build the adapted framework/image and inspect actual packaged code before boot.
Use a fresh rootless ARM64/TCG fixture and capture before boot; require real guest
connectivity separately from host protocols. Retain original failed attempts.

Primary runtime targets:

1. Stage B and C libraries separately; update only consumer pairs with rollback.
2. With C active and C→B available, require normal deletion of unused B to fail
   for the **rollback** reason, while unrelated versions remain governed normally.
3. Reboot Android (no host reassembly/data-policy switch); require persisted
   references and protection before/after normal startup pruning.
4. Exercise real unused-library pruning with a disclosed, temporary aggressive
   cache-age setting in disposable state, restoring it afterwards. No clock
   changes, prune disable, invented age or storage exhaustion. Require B preserved.
5. Drive a genuine PackageWatchdog crash-recovery path without an operator
   `pm rollback-app` substitute. Verify complete consumers, exact old library and
   configuration, ordinary WebView behavior and unchanged security boundaries.
6. Show pins release when no retaining record remains, using authorized expiry
   or later completed-state controls—not deleting metadata files or changing keys.

Staged rollback variants, expiry/commit-boundary races, adverse filesystem-I/O
concurrency, all profiles, real Chromium-version migrations and native ARM/KVM
remain separate gates until actually qualified. Existing r1 record invalidation,
explicit expiry and broken-client cleanup paths are not replaced by this patch.
A supported release or production signing/update policy is not established here.
