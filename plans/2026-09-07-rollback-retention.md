# Android rollback static-library retention

Follow the [dependency-aware cohort rehearsal](2026-09-07-webview-cohort-rollback.md).
The observed failure was deletion of an unused non-factory library while Android
still offered a consumer rollback requiring that exact version. Manual signed
prerequisite restoration worked; automatic recovery must not depend on it.

## Result — bounded retention and automatic recovery pass

Producer `f5ff864` built successfully in 761.000 seconds, completing
2026-09-07T18:29:25Z. Twenty-eight images and both actual host packages were
frozen. Extracted images retained the exact signed WebView/Library/Config APKs
and `/usr` APEX; packaged `services.jar` contained the retention implementation.
The 217 host tests passed; framework/image compilation and runtime are separate
observations from those tests.

A fresh enforcing ARM64/TCG guest selected the provider normally. On non-factory
C→B rollback record177674029, the exact B library reference appeared in Android's
rollback dump. Normal removal of unused B returned
`DELETE_FAILED_USED_SHARED_LIBRARY`, with PM explicitly logging
**“retained by rollback.”** Actual free-storage pruning selected B and hit that
guard. A normal Android reboot preserved the record/library and protected B
during startup pruning with the disclosed aggressive cache-age setting. The
original setting was restored; no clock or verifier changes were made.

Five distinct real service-process crashes between 19:33:49.453Z and 19:34:21.771Z
then triggered PackageWatchdog. The health observer selected APP_CRASH mitigation;
RollbackManager logged `commitRollback id=177674029 caller=android` at 19:34:21.851Z,
followed by `ROLLBACK_SUCCESS` at 19:34:33.949Z. No operator rollback command was
used. Independent follow-up verified exact B797708534/Config207 bytes and trusted
configuration initialization. A later normal C update **without** rollback made
B unused, and its normal uninstall succeeded: completed records did not pin it
forever.

The final ordinary C probe passed normal ALLOW consent, JS DOM42/HTTPS204,
hostname-only TLS cancellation and uninstall. Safe Browsing protection remains
false. Original hello bytes/output, read-only `/usr`, Android `/etc`, ARM64-only
ABI and enforcing SELinux were reobserved; this was not a new native/KVM or full
P5 qualification.

Capture: **145,260 packets, zero kernel drops**,
2026-09-07T18:35:58.135271Z–19:58:27.236027Z. Observed guest destinations were the
owned fixture, public CT delivery and local multicast; namespace IPv6 was local
only. No unparsed traffic or Google guest destination was observed. This is a
connected measured workload, not universal privacy or every security consumer.
VM and services stopped with exit 0; the heavy-work lease was released.
Private evidence `rollback-retention-20260907T171946Z` seals 4,534 regular files;
raw captures, APKs, runtime credentials and keys are not published.

### Failed attempts and remaining limits

All original failures remain distinct:

- Host marker-label grammar failed before sending a prune request; cleanup
  restored the cache setting. Continuation revalidated the existing C cohort.
- Android rejected a background service start normally. Foreground DevUI launch
  with render waiting timed out; scheduling crashes before main-thread delivery
  also failed to generate the required events. Reusing a still-crashing PID did
  not count as another failure, and normal background kill did not dismiss its
  crash dialog. The successful driver kept real DevUI foreground, required unique
  service PIDs and actual crash events, and used normal **Close app** interaction
  on observed crash dialogs. No background exemption, threshold tuning, dialog
  suppression, adopted identity or direct rollback call was substituted.
- The successful fault sequence's host driver attempted a sixth start while
  Android was applying rollback and failed to find a service PID. That driver
  FAIL was not relabelled. Actual platform success, committed record/cause, hashes
  and configuration were independently checked before further updates.
- An additional expiry-release setup tried an ordinary C→B consumer installation.
  Android rejected `INSTALL_FAILED_VERSION_DOWNGRADE`; no `-d` or bypass followed.
  **Expiry-release runtime qualification remains open.** Final disposable state
  was C/208 with A/B/C libraries; re-staged unused B was explicit prerequisite
  leftover, not partial consumer activation.

Staged variants, expiry/commit-boundary races, interrupted updates/adverse I/O,
multiple-user/transitive runtime variants and genuine Chromium-payload migrations
remain gates. This does not establish production signing/update ownership.

## Implementation

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

Runtime protocol:

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
