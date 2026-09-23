# SystemUI component execution plan

Status: the [finite component runtime](2026-09-22-systemui-component-runtime.md) passed after
baseline reproduction, A/R/B/C builds and the narrow
[staged verification correction](2026-09-22-staged-apk-verity.md). Earlier failed and
incomplete attempts remain separate records. The [source assessment](2026-09-21-systemui-component-assessment.md) defines its limits,
including the withdrawn factory uninstall escape.

## Selected candidate baseline

Use the already inspected `985c9a4` selected Cuttlefish image as the candidate baseline,
not mutable build output. Its factory SystemUI is `com.android.systemui`, version 37,
platform signed, persistent and Direct Boot aware. This selection tests a component
workflow; it does not qualify the later request recovery implementation or a complete
workshop image configuration.

Before any reuse, verify the full current image inventory and its corrective attestation.
The original image manifest remains nonmatching due to its historical sealer log/status
error; matching its manifest digest alone is not sufficient. Preserve the original and
check the separate observed inventory, symlinks and image/native references.

Reproduce the unmodified SystemUI component against the baseline source/product
configuration before building variants. Pin the framework, build toolchain, product flags,
resource/dependency inputs and baseline build variables. Use the matching `985c9a4` Andrix
product inputs for that reproduction, not a newer work manager copied into the older image.
The preparation tooling's revision is a separate observer input. An initial comparison
found the retained and current Soong variable objects equal; that is not proof that every build
input or intermediate is equivalent. Compare the unmodified component against the frozen
factory APK and investigate any unexplained difference before continuing. Never boot mixed
mutable output.

## Prepared source variants

The [fixture generator](../scripts/proof/systemui_fixture.py) writes candidate source copies
and framework patches to a fresh external directory. It checks the supplied original source
hashes and source shape. It has no apply, build, signing or install operation.

| Variant | Version | Clock behavior |
| --- | --- | --- |
| Factory | 37 | Existing original behavior |
| A | 38 | Append ` WS-A` to the displayed clock and its accessibility description |
| R | 39 | Original Clock source, proving forward restoration before a fault |
| B | 40 | Display `WS-B BAD`, an intentional noncrashing functional error |
| C | 41 | Original Clock source again |

A and B change normal and demo clock update sites consistently. They do not change the
system time, permissions, signer declaration, shared UID, persistence flag or keyguard
behavior. R and C leave Clock source byte identical to the original. Their version code
change means they are new APKs, not byte-identical rollback to a prior artifact.

The only proposed framework source changes are `packages/SystemUI/Android.bp` for explicit
version codes and `packages/SystemUI/src/com/android/systemui/statusbar/policy/Clock.java`
for A/B. The generated patches pass a read-only apply check against the inspected source.
That does not establish Java compilation, package validity or visible runtime behavior.

## Build and signing scope

Use a bounded component build of `SystemUI` and its required dependencies,
not a complete image build for each variant. Keep optimization, warning checks, the existing
CE adapter and declared framework/product fences. Apply only the exact variant patch while
its producer owns the inputs, freeze the output, then restore and verify the source before
the next variant. A restoration failure leaves ownership unresolved and blocks further work.

The first bench uses the public development platform signer already matching the baseline.
It must not use production or personal owner keys, generate new keys, distribute a shared
production signing secret or claim protected on-device signing. A different existing public
development signer may prepare the wrong signer negative control. Record and verify both
expected certificate identities explicitly.

For each positive variant:

1. Verify the built APK package, version, shared UID, relevant manifest flags and signer.
2. Prepare a separate APK/v4 `.idsig` update pair under the bounded signing process.
3. Verify the v4 result and signer explicitly, not just the signing tool's exit status.
4. Check that signing did not change nonsignature payload entries and verify alignment.
5. Freeze the APK, sidecar, build inputs, recipe and inspection tools before a runtime uses them.

Compare R and C code/resources after accounting for the declared manifest version and
signing differences. Do not silently accept unexpected payload changes. Prepare all
variants and negative inputs before launching the fresh runtime; do not edit active inputs.

## Exact package session protocol

The proposed host controller uses the authenticated lab shell in the disposable guest.
It is not an ordinary owner's native elevation facility. Only the exact SystemUI package
and owned sessions are in scope, initially with user0 observations.

The inspected command sequence is:

```
pm install-create --staged -r --user 0
pm install-write ID base.apk /guest/path/SystemUI.apk
pm install-write ID base.apk.idsig /guest/path/SystemUI.apk.idsig
pm install-commit --staged-ready-timeout 60000 ID
pm list staged-sessions --only-parent
```

These are proposed guest commands, not instructions to run on a physical phone. Take `ID`
from the actual `Success: created install session [ID]` response. File paths supply their
sizes; stdin writes require `-S BYTES`. Source inspection confirms that the `.apk.idsig`
filename is accepted, excluded from APK parsing and preserved for fs-verity processing.

Important command-specific semantics:

- The timeout belongs on `install-commit` before the ID. A timeout option passed to create
  does not configure the later commit command.
- Ready commit returns zero and says to reboot. It is not proof of application.
- A commit timeout returns nonzero while asynchronous staging continues. Retain the session
  ID, inspect its actual state and resolve it; do not create another transaction blindly.
- A zero readiness timeout skips waiting. Plain Success does not establish readiness.
- In this pinned source, successful `list staged-sessions` returns **1**. Record command
  outcomes explicitly; do not use a generic `set -e`/`&&` success rule for this query.
- Full session listing can wrap lines. Preserve raw output and parse the inspected format
  deliberately. The compact `--only-sessionid` and `--only-ready` options can aid correlation,
  but current package state and actual behavior still establish activation.

No default all-user assumption should enter the controller merely because create uses it
when no user is specified. SystemUI code is nevertheless shared system software; user0
selection does not make its replacement private to that account.

## Runtime sequence and acceptance

Use fresh disks, queue and runtime identity. In-trial reboots are declared steps of this one
experiment, not reuse of consumed state as a new trial. Keep the base image and fingerprint
fixed. An unexplained platform fingerprint change invalidates the staged update assumptions.

1. **Baseline.** Observe package path/version/hash, UID/MAC, signer, persistence and actual
   user0 `CONTROL_KEYGUARD` grant. Verify framework/UI health, owner native execution and a
   CE home sentinel. Establish host access independent of SystemUI and record the fixture
   abandonment route if the package service becomes unavailable.
2. **Negatives.** Test a valid nonstaged pair, a staged wrong signer pair, and a staged input
   without a sidecar as separate cases. A staged negative may reach ready before installed
   package compatibility checks. In that case, make a declared activation attempt and
   observe the exact refusal cause afterward, including any platform checkpoint reboot.
   Resolve exact sessions and confirm the factory package, UI, native execution and saved
   data remain usable. Do not count readiness or a different earlier rejection as the
   intended control.
3. **A.** Stage and observe ready/not applied while factory code remains active. Check that
   unrelated native work has not been stopped by staging. Reboot, observe a new boot identity
   with the same baseline fingerprint, the applied session and the expected active APK.
   Observe the marker and explicit fresh native execution after ordinary unlock.
4. **R.** Use the independent host path to stage the known good source at version 39 and
   activate it. Require a visible functioning clock without the A marker, correct package
   state and fresh native positives. Do not introduce B unless this forward restoration works.
5. **B and C.** Stage/activate the deliberately bad display, then restore through C. Observe
   both changes and data/settings behavior. Absence of a marker in a dead or missing UI is
   not restored behavior.
6. **Closure.** Account for session outcomes, final APK identity, framework/user state and
   work/resource retirement. Capture and assess failures without relabelling partial stages
   as a complete pass.

Reboot ends prior ordinary jobs. Do not require old process identities to survive or interpret
newly started jobs as resumed old work. Actual UID/MAC and package identity checks accompany
UI observations; a success string, version number or screenshot alone is insufficient.

No factory uninstall, permission stripping, package database editing, blind file removal,
verification bypass, uncontrolled crash loop or assumption of RescueParty recovery is in
scope. If the host/package/staged restoration prerequisites fail, preserve the incomplete
fixture and stop. Resetting disposable state is not recovery of a real owner's data.

## Preparation checks

Eleven host tests cover the recipe's source guards, authority field preservation, bounded
version ordering, both clock presentation paths, original R/C sources and fresh output
requirements. All four generated patches pass `git apply --check` against the inspected
framework; its files remain unchanged. The complete host regression suite passed 456 checks
in 220.135 s. None of these checks compiles SystemUI or qualifies an Android package session.

The staged command findings were independently checked in the pinned source, including
explicit sidecar filenames, commit timeout behavior, successful listing return of 1 and
output line wrapping. They are not observed command results from a running guest.

The subsequent component producer reproduced the unmodified version 37 APK byte for byte
against the retained image. It built all four variants without a new complete OS image,
then verified their package, version, unchanged manifest authority fields, signer, v4 pair,
alignment and nonsignature payload preservation during signing. A separate wrong signer
pair passed its own cryptographic checks with the intentionally different development
certificate. R and C have identical nonsignature entries except the declared manifest
version change. Framework, init/LMKD adaptations and the temporary product checkout were
restored and checked afterward. Upstream compiler warnings were retained, not suppressed.

Six added session parser tests bring the host suite to 462 passing checks. Separate
supplied-fact controller checks reject implicit transaction/reboot retries after unknown
outcomes and prevent treating an applied package as verified UI behavior. The runtime
controller separates reboot/package observation from subsequent UI/native checks, and
retrieves all interactive windows for the status bar clock. These are observer checks,
not an Android installation or recovery result.

## Resource and qualification boundaries

Use explicit CPU, memory, storage and deadline limits for the chosen build and test host,
with actual limit readback and no job swap or core dumps. Keep installation and reboot
outcomes distinct from their deadlines. A timeout does not erase a package session or
release unresolved obligations.

Admission must account for staging and verification overlap on the actual filesystems,
including recovery reserves. Reclaim only verified closed disposable copies. Preserve
canonical inputs, keys and immutable evidence. A component build does not require another
full image build when the selected baseline is already compatible and verified. See the
[reusable artifact procedure](../docs/development-artifacts.md).

Exact machine capacities and operating records do not belong in this product plan.
No general on-device elevation, personal key custody or complete multiuser/locked-mode
qualification follows from this first experiment.
