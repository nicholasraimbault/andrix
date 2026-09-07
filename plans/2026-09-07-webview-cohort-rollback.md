# Versioned WebView library prerequisites and consumer rollback

**Executed: split consumer rollback and dependency repair passed; automatic
library retention remains a release gate.**

Follow up the [three-child rollback failure](2026-09-07-webview-qualification.md).
This is a disposable ARM64/TCG rehearsal on the frozen positive `09d890f` image,
not a production updater or a new Chromium release. Preserve Android's package
identities, signature checks, SELinux and normal rollback API.

## Proposed transaction boundary

A new TrichromeLibrary version is an immutable, side-by-side dependency, not an
ordinary replacement of one app. Install it first without rollback. Commit
WebView and Config together in one rollback-enabled two-child session. Failure
must leave the old active consumer pair intact; an extra unused library is an
explicit staged prerequisite, not a partially activated consumer generation.

Use the already signed manifest-only generation B (WebView/library 797708534,
Config 207), plus generation C (797708634/208), preserving original native code,
DEX, resource semantics and configuration payload. Verify exact manifests,
signatures, library relationships and payload hashes before installation. This
cannot prove real Chromium-version schema migration.

A representative **test-only** control sequence (after the signature/hash guards):

```sh
adb install --user 0 generation-b-TrichromeLibrary64.apk
adb install-multi-package -r -t --enable-rollback \
  generation-b-TrichromeWebView64.apk generation-b-VanadiumConfig.apk
adb shell dumpsys rollback
# Ensure the prior matching library is still installed, or restore its exact
# authenticated APK through normal installation before invoking rollback.
adb shell pm rollback-app dev.andrix.experiment.webview
```

## Checks

1. Require actual guest network readiness separately from the host fixture's
   DNS/TLS/NTP controls. Capture before boot, increase the host packet buffer and
   retain loss counters. No offline-silence privacy verdict.
2. Stage Library B. Verify both library versions and the unchanged active A pair.
   Reject a wrong-signer two-child consumer transaction atomically.
3. Update the B consumer pair; require a real *available* two-package rollback,
   actual selected provider/dependency paths and parsed Config 207. Attempt to
   remove the actively used B library: require Android's used-library rejection.
4. Roll back to factory A through `pm rollback-app`, not `install -d`. Verify
   exact restored consumers, Config 206 and old library binding.
5. Advance to B again, stage C and update both C consumers. Roll back to
   **non-factory B**, verifying actual B code paths/hashes and Config 207. Factory
   A's immutable retention must not conceal a dependency-lifetime problem.

## Retention is a separate gate

Exact r1 source inspection finds no rollback-record reference in static-library
pruning or current-client dependency enumeration. Rollback stores only its
session children, not their static-library dependencies. Recently installed or
factory libraries may survive without being protected for the rollback lifetime.

Only after successful normal controls, a deliberate disposable negative may
remove the unused non-factory B library while C is active and a C→B rollback is
available. It must never target an unrelated package or an actively used library.
Retain the exact signed B APK. If removal succeeds, test whether Android rejects
rollback without partially changing consumers. Reinstalling that identical
prerequisite through normal PackageInstaller, then retrying the real rollback,
is a distinct repair test—not a forced downgrade or proof of automatic retention.
Preserve every failure and do not turn a short successful rollback into a
supported-release claim.

No policy patch, reference-holder package, privileged shim, owner-update daemon,
production key decision, clock manipulation or storage-pressure simulation is
part of this test. Automatic rollback under pruning/expiry remains a separate
requirement even if owner-mediated dependency preparation works.

## Result — connected ARM64 QEMU/TCG, 2026-09-07

**The split transaction works. Automatic dependency retention does not follow
from rollback availability.** No image, Android policy, provider code or trust
pin was changed. The new C fixture passed signed-APK/ARM64/library checks and
round-trip manifest/resource comparison. The existing `42f140e` test helper was
used unchanged.

| Check | Observed result |
| --- | --- |
| Library prerequisite | B installed alongside factory A; active WebView/Config stayed A/206. |
| Wrong-signer consumer pair | Rejected with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`; the active pair and library inventory stayed unchanged. |
| Consumer B update | WebView B/Config 207 installed atomically. A real available rollback contained exactly the two consumers. |
| Current-client library protection | Removing actively used B returned `DELETE_FAILED_USED_SHARED_LIBRARY`. |
| Factory rollback | Normal `pm rollback-app` restored exact WebView A/Config 206; initialization parsed 206. |
| Non-factory rollback | After B→C, normal rollback restored exact data-installed WebView B/Config 207 and used B's library. Factory A did not stand in for B. |
| Unused rollback dependency | With C active and C→B rollback available, removal of **unused non-factory B** succeeded. The available record did not pin that library. |
| Missing-library rollback | Failed with `INSTALL_FAILED_MISSING_SHARED_LIBRARY`; both consumers remained exact C/208, not a partially restored pair. |
| Dependency repair | Ordinary installation of the retained, identical signed B library followed by retry of the real rollback restored B/207. No `install -d`, changed certificate or verifier bypass. |
| Post-repair ordinary WebView | Passed real JS 42/HTTPS 204, hostname-only rejection/cancel, normal local-network permission approval and cleanup/uninstall. Safe Browsing remained false/unavailable. |

Exact consumer/library hashes, code paths, versions, parsed configuration,
rollback records and failed attempts are retained separately from the frozen
original image. The final active test pair was B/207; unused C remained explicitly
installed. Both disposable probes were removed. Normal shell still ran the
original hashed `andrix-hello`, `/usr` remained read-only and SELinux enforcing.
VM and fixture stopped with exit 0.

### What this establishes—and what it does not

A dependency-aware **owner-mediated** rollback can prepare the authenticated
library before asking Android to restore the atomic consumer pair. A bare
RollbackManager record is not a complete Trichrome generation backup. An
unattended/Watchdog path must not assume the old library is still available.
A durable authenticated dependency store and retention/repair policy for the
whole rollback lifetime remain implementation/release gates. No production
updater, retention anchor or platform patch was introduced here.

Primary inspection of exact r1 `SharedLibrariesImpl`, `DeletePackageHelper` and
`Rollback` corroborates the runtime result: shared-library dependency checks
consult current installed clients, not rollback records; rollback restores its
child APKs, not their library graph.
The periodic prune default is seven days; storage-reclamation code has a separate
two-hour default, each subject to the existing global setting. These are source
observations, not an executed age/storage-pressure test. No clock or pruning
setting was changed. Factory A appeared in the system-package inventory; the
new B/C library versions were data installations. Immediate success is still not
proof of real Chromium schema migration, every Android profile or native ARM/KVM.

### Network and observer boundaries

The fixture's first DNSSEC-negative control timed out; an unchanged bounded
retry passed. Public CT files were fetched through strict hostname-verified TLS
and both original signature/freshness formats verified. Guest readiness was
then required independently: boot-complete initially had no data subscription
or IPv4 route, despite SIM/service readiness. Without changing settings, the
normal data path appeared and a guest connection to the public owned CT endpoint
succeeded. The later ordinary WebView probe supplied real guest HTTPS evidence.
Host protocol checks were not substituted for guest connectivity.

Capture began before boot: **85,812 packets, zero kernel-reported drops**,
16:12:02–16:47:49 UTC. Classified guest destinations were the owned private
fixture, public CT delivery and local multicast; namespace IPv6 was local only.
No Google guest destination was observed in this workload. The host capture
buffer was raised to 32 MiB; no endpoint filter, denylist or guest policy changed.
This remains bounded evidence, not complete no-Google qualification.

Two observer failures remain intact:

- Active rollback records are unindented in the actual r1 dump, unlike historical
  records. The original parser rejected a real available pair. Its correction
  was tested against that output and committed/historical-only/wrong-version
  negatives; execution continued from the verified B state.
- The ordinary-probe host wrapper still expected factory version 797708434.
  Android's unchanged report passed with the predeclared restored B 797708534.
  Independent version-aware review passed all original stage, UID, permission,
  JS/TLS, callback and uninstall checks without changing guest/result bytes.

The existing fixture's 11 source regressions also passed. Independent I17 was
read-only source review, not runtime evidence. Full production signing, automatic
recovery, actual-version migration and the broader native/privacy gates stay open.
