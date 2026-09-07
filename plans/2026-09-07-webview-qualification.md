# Vanadium trust, recovery and package-session qualification

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
