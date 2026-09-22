# Staged APK file verification integration

Status: the first SystemUI runtime stopped at an earlier SELinux refusal. The narrow
correction passes normal and selected Android policy compilation. Both decoded policies
add exactly the two required ioctls, with no other access changes. A matching selected
image is now built and verified. A fresh runtime is still required.

## Observed failure

The [component build](2026-09-21-systemui-execution-plan.md) reproduced the factory SystemUI
APK and produced the four planned variants with verified v4 sidecars. In the first fresh
Cuttlefish guest:

- Factory version 37 matched the frozen APK, with UID 10112 and
  `u:r:platform_app:s0:c512,c768` in that user0 fixture.
- `CONTROL_KEYGUARD` was actually granted. The earlier factory uninstall guard therefore
  remains relevant; no uninstall attempt was made.
- The original clock, ordinary owner compilation/profile and independently managed native
  work passed their baseline controls.
- A valid ordinary nonstaged update was refused with `Persistent apps are not updateable.`
  The active package remained unchanged, with live native work before and after.
- The staged wrong signer control did **not** reach its intended check. `system_server`
  was denied ioctl `0x6685` on the APK's `staging_data_file` object. Package Installer reported
  failure enabling fs-verity, then removed the session. The shell command only returned
  `Failure [failed to retrieve SessionInfo]`.

The denial occurred before signature verification. It is not a successful wrong signer
negative. Missing sidecar, A/R/B/C activation and all declared reboots remain unexecuted.
The incomplete attempt and its original command failure were retained. Its known native
scopes retired and the guest shut down. Shutdown success is not a pass for the experiment.

A host staging helper also failed before guest launch because an artifact dictionary
shadowed its inventory function. That separate failure was retained. Every already copied
input and link set was reverified before completing the still unstarted stage. No consumed
guest state was reused or active input edited.

## Source explanation

The pinned Package Installer enables file verification for nonincremental APKs with v4
sidecars before parsing those APKs:

- `PackageInstallerSession.validateApkInstallLocked` calls
  `enableFsVerityToAddedApksWithIdsig`.
- That method calls `VerityUtils.setUpFsverity`, whose native implementation issues
  `FS_IOC_ENABLE_VERITY`, `0x6685`.
- `ApkSignatureSchemeV4Verifier.extractCertificates` subsequently calls
  `VerityUtils.getFsverityDigest` and compares the kernel digest with the signed sidecar.
  Its native path issues `FS_IOC_MEASURE_VERITY`, `0x6686`.

The existing platform policy allows both operations on ordinary APK installation types,
but omits `staging_data_file`. It already grants `system_server` creation and access to
staging directories/files. `/data/app-staging` deliberately uses the staging type, also
used by other staged package paths. Changing the label to evade that policy is not the fix.

## Correction

[Common Andrix policy](../sepolicy/private/system_server.te) adds only these two extended
ioctl permissions for `system_server` on `staging_data_file:file`:

```
FS_IOC_ENABLE_VERITY
FS_IOC_MEASURE_VERITY
```

This completes file verification in an already authorized package staging path. It does
not disable verification, grant all ioctls, add installer principals, change package signer
or version requirements, grant native owner package authority, or weaken app isolation.
Existing staging type access restrictions and neverallow rules remain. Because the type
also covers other staging locations, the grant is scoped to the existing type and trusted
system service, not exclusively to the SystemUI package name.

The correction belongs to common platform integration, not the Unix work supervisor or a
special test caller. The current board already includes that policy directory outside the
owner environment selection. No new policy selection switch is needed.

## Qualification and remaining gates

The host suite passed 465 checks. Normal and selected Android policy builds passed with
existing neverallow checks. Each decoded binary policy differs from its corresponding
qualified baseline by exactly one extended rule, covering only `0x6685` and `0x6686` for
`system_server` on `staging_data_file:file`. No rule was removed and the existing boundary
checks passed. Framework and the accepted owner policy bridge remained unchanged.

An initial observer incorrectly required an entirely clean upstream policy checkout,
although the accepted owner bridge deliberately changes `private/domain.te`. It stopped
before compilation. That failed record is retained. The corrected observer verifies the
existing bridge through its digest guarded inspector, rather than reverting or ignoring it.

A subsequent selected image contains that exact compiled policy. Thirteen frozen native
controls passed, and the original factory SystemUI version 37 was rebuilt and verified
byte for byte against the component baseline. Temporary init/LMKD adaptations were restored.
No complete normal image was produced in this step. The new image is not runtime qualified.

The observer now checks exact historical session identity, shell installer identity, user,
package and terminal cause when the shell loses live `SessionInfo`. It rejects generic
`BAD_SIGNATURE` as a wrong signer result, since file verification setup failures use that
code too. Four additional parser tests bring the full host suite to 469 checks. Fifteen
supplied observer checks passed. Historical observations are volatile, not durable receipts.

Remaining gate: run the declared sequence on fresh guest state with this coherent image
and the compatible sealed APK pairs. Do not patch a running policy, relabel an active
staging file or reuse the consumed failed fixture.

The observer should capture an exact session's actual failure cause when a session
vanishes during the shell command's readiness wait. Absence or a generic command failure
must not be interpreted as the intended negative. Any fallback observation needs exact
session correlation and an unchanged active package, not a guessed error class.

This is an integration correction supported by an observed denial and the verification
call chain. It is not evidence that staged SystemUI restoration already works.
