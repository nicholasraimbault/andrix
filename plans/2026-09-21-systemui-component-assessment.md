# SystemUI component assessment and first proof proposal

Status: source and existing APK inspection only. No SystemUI modification, build, signing,
installation, remount, reboot or runtime experiment was performed for this assessment.
This refines the [workshop component plan](2026-09-21-workshop-components.md), not the
accepted vision or the owner's authority to change the OS.

Followup source review corrected an omission in the first assessment: the proposed factory
uninstall escape encounters an earlier keyguard protection gate. It is withdrawn as an
assumed SystemUI recovery route. The original assessment remains preserved; no runtime
failure or successful recovery is being inferred from this correction.

## Recommendation

Start with the existing **staged APK update and reboot** path on a disposable Cuttlefish
fixture. Build only SystemUI and its declared dependencies for each variant. Do not require
a complete OS build for every UI iteration, and do not disable package checks merely to
make ordinary installation succeed.

The current source explicitly refuses an ordinary update to a persistent app. SystemUI is
persistent. Therefore "install an APK and kill SystemUI" is not yet an established positive
path. The staged exception provides a concrete existing route to test first. It requires
reboot for activation in this source, not another complete Android image build.

A faster administrative update/restart transaction remains a possible later Andrix design.
This recommendation does not make today's persistent app rule a permanent product ceiling.

## Inspected scope

The Android source is the pinned GrapheneOS framework revision
`aab06a8bd44c4c2b58eeec780fde83baa9d43a40`, with the existing separately recorded Andrix CE
adapter. Those adapter files were not changed here. The persistent update check was also
compared with the public [AOSP `android-17.0.0_r1` source](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/pm/InstallPackageHelper.java)
and has the same condition.
The additional system package version and file verification checks below are GrapheneOS
integration, not that AOSP persistent app condition.

The existing frozen SystemUI APK from the `985c9a4` image was inspected independently of
mutable build output. Its bytes were checked against the separately corrected image
inventory before metadata inspection. It declares:

- Package `com.android.systemui`, versionCode 37, versionName 17, minimum and target SDK 37.
- Shared user name `android.uid.systemui`, not a declaration that its numeric UID is 1000.
- A persistent, Direct Boot aware application with `allowClearUserData=false`.
- One signer, matching the public AOSP development platform certificate.
- A valid APK v3 signature. The factory APK inspection did not establish a v4 update pair.

These observations do not establish a newly installed package, current process identity or
personal owner key custody. Actual package paths, numeric UID, MAC context and activation
state must be observed in the proposed runtime.

## Build and dependency map

`frameworks/base/packages/SystemUI/Android.bp` declares `SystemUI` as an `android_app`,
using platform APIs, the platform certificate, privileged installation and
`system_ext_specific`. The corresponding factory artifact is
`system_ext/priv-app/SystemUI/SystemUI.apk`.

The target includes `SystemUI-application`, `SystemUI-core` and `SystemUI-res`. The build
links a substantial dependency closure, including framework SystemUI libraries,
WindowManager Shell, SettingsLib, generated flags, Dagger/KSP and AndroidX/Compose pieces.
A component build is not a standalone ordinary application build against an unrelated SDK.

The target requires `privapp_whitelist_com.android.systemui`, installed under
`system_ext/etc/permissions`. That permission input is not bundled away by rebuilding the
APK. The package's shared UID, signer, declared permissions and existing installation state
must remain consistent. Keep optimization and warning checks enabled.

Soong's `build/soong/java/aar.go` uses the platform SDK as a default APK version code when
no explicit `--version-code` aapt flag exists. A plain rebuild can therefore retain 37,
which is insufficient for the update checks in this image. A proof build needs an explicit
higher version code, verified in the final APK rather than assumed from its build label.

## Installation gates found in source

| Gate | Inspected behavior | Consequence for the proof |
| --- | --- | --- |
| Persistent application | `InstallPackageHelper.java:1803–1808` rejects a persistent package replacement unless `INSTALL_STAGED` is set | Ordinary `install-multiple -r` is a negative control, not the positive path |
| Staged installer authority | `PackageInstallerService.java:924–978` requires `INSTALL_PACKAGES` for staged APKs and checks installer eligibility, with explicit system/root/shell handling | A host controlled shell installation is not proof that the ordinary Unix account can administer packages |
| APK file verification | `PackageInstallerSession.java:1836–1855,4594–4598` sets up fs-verity for added APKs accompanied by IDsigs; `InstallPackageHelper.java:2140–2178` checks system package updates | Produce and verify a matching APK/v4 sidecar pair; do not rely on overall signer-tool exit status alone |
| Version continuity | The same install helper rejects equality with the factory version; `PackageVerityExt.checkSystemPackageUpdate` rejects a normal system update at or below the factory version during boot scan | Use increasing versions and retain both install-time and boot-time checks |
| Signer and shared UID | `InstallPackageHelper.java:2223–2306` and `ReconcilePackageUtils` verify signer relationships and reject changed shared UID declarations | Matching the package name or possessing an unrelated key is insufficient |
| Staged activation | `StagingManager.restoreSessions` and `resumeSession` apply staged APK sessions during boot; an OS fingerprint change can invalidate the pending session | Committed/ready is not applied. Keep the underlying baseline fixed across the declared update reboots |

The debug properties that bypass file verification or equal-version checks are not part
of the proposed path. Neither is removal of `android:persistent` or a blanket relaxation
of installer/signature policy.

## Lifetime and restoration

SystemUI is not a named init native service. `SystemServer.startSystemUi` resolves
`config_systemUIServiceComponent` and starts that Android service as the system user.
`SystemUIService.onCreate` starts the system user components. ActivityManager contains
conditional persistent process restart machinery. That is not a public guarantee that
killing a process activates a new APK or preserves all surfaces and clients.

A staged activation reboots this first candidate. Existing native jobs end with that reboot;
they must not be required to retain their old PIDs or silently reappear under new identities.
Before reboot, a ready staged session should not be mistaken for an active replacement.
After normal boot/unlock, explicitly start fresh native work and check retained owner data.
This is not another genuine CE withdrawal race qualification.

### Preferred restoration: known good code at a newer version

Prebuild a sequence such as:

- Factory baseline, version 37 in the inspected artifact.
- A, version 38, a small visible clock or status bar marker while preserving normal behavior.
- R, version 39, restoring the known good factory source behavior through another staged
  update. Prove this host controlled path before introducing the bad variant.
- B, version 40, a deliberately incorrect but noncrashing marker/rendering result.
- C, version 41, restoring the same known good source behavior as R.

Numbers are examples tied to this baseline, not a product versioning scheme. Verify each
APK's actual signer, manifest, version and payload. R and C are new artifacts restoring
known good code, not byte-identical rollback to an older APK. They require a working
independent host connection, Package Manager and staged activation path; none is guaranteed
merely by possession of a signed APK. If the preflight restoration cannot be demonstrated,
do not proceed to B. First use a functional fault, not an uncontrolled persistent crash
loop. This deliberately does not qualify recovery from every startup crash.

### Factory uninstall is not an assumed escape route

`pm uninstall-system-updates com.android.systemui` must not be relied on as the SystemUI
fallback. `DeletePackageHelper.deletePackageLIF` at lines 390–396 rejects a system package
with `CONTROL_KEYGUARD` granted in user0 before calling `mayDeletePackageLocked`. This
condition has no caller UID or uninstall flag exception; it checks the user0 grant even
when another user is the deletion target.

SystemUI requests `CONTROL_KEYGUARD`; the framework defines it as a signature permission.
Its verified factory signer matches the platform certificate, and the inspected signature
grant policy supports that normal grant, including a request present in the factory package.
This establishes the expected refusal, not a fresh measurement of the installed permission
state. Observe the actual grant in runtime preflight, but do not assume it absent in order
to make a recovery plan work. Root/shell installer authority alone does not avoid this gate.

The helper's generic system downgrade machinery exists below that gate. If reached for an
eligible package, it requires an administrative user, removes the update and restores the
disabled factory package. `deleteInstalledSystemPackage` clears `DELETE_KEEP_DATA` if the
factory version is lower or the appId differs. Those conditional data loss findings remain
valid; they do not establish that SystemUI can reach the fallback. Shared system package
restoration can affect all users, not only the current UI account.

A refused uninstall is not necessarily free of side effects. The outer deletion path can
freeze and kill package processes before reaching this guard. Do not use an attempted
uninstall as a harmless permission probe or infer unchanged process state from refusal.

Forward package replacement uses a separate commit path in `InstallPackageHelper`, so
this deletion guard alone does not invalidate the staged higher-version proposal. That
path still needs its own actual qualification; no guard removal, permission stripping,
manual package database editing or blind deletion of `/data/app` is adopted here.

An investigation must always name the exact package; omitting the argument enumerates
system updates. The inspected shell method returns **1 on its success path and 0 on handled failure**.
It can also print Success when there is no updated system package to remove. A collector
must therefore inspect the actual package path/version/hash and restored behavior, not
substitute a conventional exit-zero test or a success string for restoration evidence.

RescueParty's inspected source disables its normal path on userdebug unless explicitly
enabled for testing. Do not assume production crash recovery behavior from this lab build
or enable/disable rescue controls merely to manufacture a result.

## Proposed first run

The first run is an explicitly limited host assisted package workflow, initially observing
one full Android user. This is not a product account limit or multiuser qualification.
Prefer an unchanged verified base with a development signer already matching it, plus
separate disposable APK variants. A benchmark using the existing public development platform key proves neither
personalized trust provisioning nor protected signing on the phone. A private owner keyed
baseline remains a separate authority workstream, not a silently inherited result.

Package updates under `/data` need not require remounting or disabling partition verification.
Keep that distinction: this first experiment can test modular system APK installation
without claiming the entire mutable workshop mode or native sudo interface is complete.

1. **Baseline and recovery preflight.** Verify the full chosen image inventory and tools,
   APK signers/versions, shell installer authority, package state and an independent host
   connection. Include the actual user0 keyguard permission grant. Declare how to abandon
   and preserve the disposable fixture if Package Manager or staged restoration is lost;
   resetting a fixture is not recovery of an owner's existing data. Record user, boot,
   framework, verification mode and native execution positives.
2. **Negative controls.** A correctly prepared nonstaged replacement should encounter the
   persistent app guard. Separately exercise a staged wrong signer and a missing/mismatched
   sidecar without conflating the reason for refusal. Retain exact session identities and
   resolve or abandon them before proceeding. Check that refused requests changed no active
   SystemUI package and did not stop unrelated work.
3. **A: real component update.** Stage the higher-version APK pair. Observe ready but not
   applied and the still active baseline. Reboot within the same declared fixture, wait for
   actual application, identify the active APK/UID/MAC and observe the visible change.
   Explicitly start fresh native work and verify its prior saved data.
4. **R, then B and C: preflight restoration and bad behavior.** Demonstrate the independent
   host controlled forward restoration with R first. Only after that succeeds introduce
   the noncrashing B and restore through C. Observe behavior, not just package versions.
   Record preference/data behavior without generalizing a few retained settings into
   complete migration guarantees. If the declared recovery prerequisites fail, stop and
   preserve the incomplete attempt rather than improvising a bypass.
5. **Close.** Check the Android UI/framework, declared package state, native environment,
   session outcomes and owned resources. Reboots are expected parts of this one experiment,
   not old state relabelled as a fresh trial. No pending session or old process absence alone
   substitutes for completed cleanup.

All APK variants and controller inputs must be frozen before the runtime. Each compilation
gets its own exact source change and dependency record. A collector designed to require an
unchanged boot ID throughout the older transport trial is not suitable unchanged here.

## Alternatives and next decisions

- A controlled persistent app update/restart transaction may later improve iteration speed.
  It needs a design for quiescence, package state, shared users, callers, activation and
  recovery. Simply deleting the current guard is not that design.
- A raw remount/replacement workflow is a legitimate workshop direction, but brings different
  integrity, shadowing, compiled-artifact and recovery questions. It is not selected merely
  to avoid the existing package path.
- Resource overlays can be useful owner customization, but are not equivalent to proving
  SystemUI APK/code replacement. Do not silently substitute an easier test.
- A new complete image may be needed for initial personalization or coupled platform changes,
  not necessarily for every later APK variant.

Before execution, select the baseline, development signing scope, source fixture changes,
controller/session/reboot handling, storage/resource budget and restoration acceptance
criteria. No build, signing, installation or reboot is authorized by this source assessment
alone. Actual failure to support the staged path would require a revised proposal, not a
relaxed oracle. General on-device elevation/signing, multiple account qualification, fast
persistent app replacement and Pixel behavior remain separate gates.
