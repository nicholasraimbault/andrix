# Vanadium trust, recovery and package-session qualification

**Executed: focused trust/recovery checks passed; three-package rollback failed.**
See [observed results](#observed-results--2026-09-07) and the remaining gate below.

Continue testing the existing signed Vanadium152 integration. The working
`09d890f` image and original APKs remain frozen. No production promotion, new
browser choice, security-policy relaxation, public host listener or paid resource
is implied. Static inspection, test instrumentation and normal app authority
are separate claims.

## Configuration trust: two different gates

1. A wrong-signer APK update must be rejected by Android PackageManager. In a
   multi-package session, rejection must not leave a partially updated cohort.
2. Vanadium's own compiled `ConfigInfo` gate must refuse an untrusted Config
   package. PackageManager rejection alone cannot exercise this code path.

A **negative-only image** therefore uses the same source revision, WebView and
library APKs as the working candidate but bakes the original Config payload and
manifest under a different existing non-platform proof certificate. Its distinct
fingerprint ends in `.cfgneg`. The exact input difference is recorded; normal
three-APK verification correctly fails for its Config signer. It is not a
qualified/deployable candidate or an exception to the normal verifier.

Only the ignored Config prebuilt is temporarily staged for this negative build,
under the exclusive heavy-work lease. The positive input is restored and rehashed
on exit, with a fresh mtime to invalidate subsequent build caches. No compiled
trust pin, Config payload bytes, permission or Android verification rule is altered.

A self-targeted test initializes the actual WebView and reads, without mutation,
the pinned provider's config state through its public WebView classloader.
Read-only reflection is limited to its own third-party DEX fields, not Android
hidden APIs. Require the exact DEX hash and compiled certificate pin before use.
Positive controls must show the trusted config version; the negative must show
real signer mismatch and no parsed/future config, alongside retained logs.

## Recovery: white-box and cross-UID controls

The existing SafeMode DevUI is read-only. Upstream `SafeModeService` explicitly
permits the provider's **same UID** for testing. A same-certificate test-only
instrumentation APK may target that provider UID without changing its APK.
This is white-box testing, not ordinary-app authority. A companion's same
certificate alone does not make its different UID a trusted SafeMode caller.

Use the existing AIDL, public Context/JobScheduler/ContentResolver/PackageManager
APIs, exact manifest components and `fast_variations_seed` action. Confirm the
cross-UID setter is rejected while permitted getters work. Confirm activation
persists the action and enables SafeMode but creates no seed job under the
compiled policy; deactivation must clear it normally.

R8 removed the dead scheduling methods. The actual compiled fetcher callback
cancels job **83** and returns false. A synthetic same-UID persisted job can
exercise retirement: stage a uniquely marked, delayed job, reboot, verify it
survived, then let the real JobScheduler invoke the callback. Do not spoof Play,
edit private preferences, alter clocks, invoke pruned test methods, disable
services or bypass Binder/job permissions. Remove only fixture-owned state.

## Coordinated update/rollback rehearsal

The test generation changes manifest version metadata only:

- WebView/library code and static-library version 797708434 → 797708534;
- Config code 206 → 207;
- original DEX, native code, resources and configuration payload remain.

AAPT2's emitted manifest is checked against precisely the planned changes;
resource protobufs and all other archive payloads are compared. Re-sign with the
same disposable experiment signer and retain the usual APK/ARM64/static-library
checks. These APKs are **not a new Chromium release** and prove no real-version
schema migration or new security behavior.

Use ordinary Android multi-package installation and its rollback API from the
explicit owner/shell test control plane. Record package versions, selected
provider, static-library dependencies, rollback availability and behavior before
and after. Test one wrong-signer child before the positive transaction. No
`--disable-verification`, rollback bypass, platform-signer substitution or
unlabelled downgrade may stand in for a real result.

## Runtime boundary

Use fresh rootless connected QEMU/TCG state, matching host packages, valid owned
services/public CT delivery and capture before boot. Test ordinary WebView
behavior separately, including the normal local-network permission dialog when
using the private HTTPS fixture. Safe Browsing remains unavailable, not a claimed
protection. Preserve first failures and stop/clean disposable state explicitly.
All results remain bounded by this provider, image, workload and emulated host.

## Observed results — 2026-09-07

**Partial qualification; rollback is a real blocker.** The ordinary positive
image remains producer `09d890f`; the negative image uses the same source and the
explicit Config-certificate override above. Test APK producers were `378bc61`
and the observer repair `42f140e`. Neither changed the frozen provider/library.

| Check | Actual result |
| --- | --- |
| Compiled Config trust | PASS. Normal WebView initialization read the exact compiled 32-byte certificate pin and parsed trusted Config 206. The negative factory Config had a different real signer, `hasSigningCertificate=false`, and both parser fields remained null; the actual parser logged refusal. No mocked PackageManager or changed pin. |
| Cross-UID SafeMode authority | PASS. Permitted bind/getter/query controls worked; `setSafeMode()` alone threw the expected trusted-app SecurityException. The caller had a distinct UID even though its certificate matched. |
| Fast recovery | PASS for this action. Same-UID instrumentation activated only `fast_variations_seed`, observed enabled alias/actions/timestamp and no job 83, then cleared state normally. An ordinary app passed JS 42, HTTPS 204 and cancel-only hostname rejection while the action was active, with visibly approved normal permission flow. |
| Persisted-job retirement | PASS after a normal Android reboot. The marked same-UID job survived; real JobScheduler execution recorded START, `onStartJob returned false`, and `cancel() called by app` with the provider UID/job 83. Subsequent observation found no pending job. This synthetic job does not prove this disabled build naturally schedules one. |
| Atomic wrong-signer update | PASS negative. The three-child session failed with `INSTALL_FAILED_UPDATE_INCOMPATIBLE` for Config. All three installed versions stayed unchanged, including the static-library inventory. |
| Manifest-only generationB | PASS installation/initialization. WebView/library 797708534 and Config 207 installed together; old library 797708434 remained. Exact updated WebView/Config hashes matched; the selected provider had relros 1/1 and initialization parsed trusted Config 207. Not a real Chromium-version migration or an updated-JS/TLS test. |
| Three-child rollback | **FAIL.** No available rollback; no forced downgrade substituted. |

### Why the rollback failed

At 12:04:38 UTC the actual r1 `RollbackManager` logged:

```text
dev.andrix.experiment.trichromelibrary is not installed
```

The library was present in the preceding `--match-libraries` inventory.
`RollbackManagerServiceImpl.enableRollbackForPackageSession()` nevertheless
received `NameNotFoundException` from its package lookup. Its `getPackageInfo()`
uses `MATCH_ANY_USER`, then `MATCH_APEX`, not the static-library match flag. The
historical rollback record contained only WebView and Config and was deleted
with **“Failed to enable rollback for all packages in session.”** The ordinary
`pm rollback-app` then reported no available rollback. Installation success and
`--enable-rollback` did **not** guarantee recoverability.

Next, assess a separately staged immutable/versioned library prerequisite and a
rollback-managed atomic WebView/Config consumer session. Verify old-library
retention, dependency resolution, failed-commit behavior and real rollback before
adopting that strategy. It is a candidate test design, not a tested solution or a
production signing/update decision. All-path recovery, hardened-runtime claims
and actual-version data/schema migration remain open.

### Preserved test/fixture failures and limits

- The first config observer hit Chromium's filtered public classloader. The
  repair uses its permitted support-glue entry and public Class metadata to find
  the *existing* defining loader; no private Android/delegate field or duplicate
  DEX loader is used. Read-only internal inspection remains white-box, not a
  supported app API. The original ClassNotFoundException remains.
- The ordinary-probe host runner mistook a substring package-name match for a
  pre-existing probe. Exact package-token parsing repaired the observer; neither
  app nor Android permissions changed. A separate input-command timeout and its
  operator-created broken-pipe diagnostic are retained.
- An attempted host-level Cuttlefish resume changed data policy from the
  generated instance image to the seed image. Assembly logged deletion of the
  instance userdata and a composite-disk mismatch. The absent old job/package
  was **not** an Android-persistence failure or a retirement pass. A newly marked
  job was then tested through normal `adb reboot`, without reassembly.
- The resumed VM reached its controller deadline (status 124) before one positive
  install command reached ADB. PID/namespace guards rejected it. The actual
  positive update used a separately booted fresh image, not that failed attempt.
- The long baseline capture had **73,363 packets and 167 kernel-reported drops**.
  No Google destination appeared in classified packets, but lost packets cannot
  be classified. The short negative/update windows did not establish guest
  Internet connectivity; update inspection saw only loopback IPv4. Their fixture
  protocols/uplink worked, but that is not guest connectivity. Negative capture:
  9,462 packets/zero drops; update capture: 28,495 packets/976 drops. **No new
  no-Google qualification is claimed from these runs.** The earlier public-CT
  result is unchanged. Safe Browsing remains false/unavailable.

Primary verification: **212 host-proof tests plus 11 fixture source tests**,
actual r1 public AIDL/Java compilation, Soong APK builds, signed artifact/image
checks and the emulated checks above. The implementation worker ran no tests;
its output was independently reviewed. The r1 D8 API37 warning remains in build
logs; SDK targets were not lowered. All task VMs/services are stopped. Test APKs,
raw captures, credentials and signing keys remain outside public source.
