# Phase 1 — prove `andrix-hello` under `/usr` on direct AOSP 17

This prepared milestone is a recipe, not execution authority. Live
implementation and proof state are recorded in [current work](current.md).

## Goal and target scope

A 64-bit-only ARM64 Cuttlefish image built from one accepted, exact direct AOSP
17 tag boots `dev.andrix.usr` as a signed APEX. The exact packaged
`bin/andrix-hello` runs through both
`/apex/dev.andrix.usr/bin/andrix-hello` and `/usr/bin/andrix-hello` with the
Android linker and Bionic. Android remains Android.

The first implementation path is only `andrix_cf_arm64_only_phone`, inheriting
the direct AOSP `aosp_cf_arm64_only_phone` source. Pixel 9 Pro (`caiman`) remains
an intended later target but has no current product recipe or buildability
claim. It requires an explicit pinned device, vendor and kernel decision.

## Direct AOSP source boundary

The manifest provider is exactly:

```text
https://android.googlesource.com/platform/manifest
```

`android17-release` is the platform family. Every source initialization uses one
explicit immutable tag matching `android-17.0.0_rN`, verifies that tag, and
records its manifest commit. The tag observed while preparing BASE-1 was
`android-17.0.0_r1`; that observation is not an advancement policy.

The future bootstrap procedure, recorded but not run here, follows current AOSP
guidance with the accepted exact tag substituted for the moving branch:

```text
repo init --partial-clone --no-use-superproject \
  -b "$ANDRIX_AOSP_TAG" \
  -u https://android.googlesource.com/platform/manifest
repo sync -c -j8
```

Stop before initialization unless `ANDRIX_AOSP_TAG` is the exact tag authorized
for that source operation. LineageOS is not a manifest, framework, product, device,
build, update, or release dependency. LineageOS and GrapheneOS may appear only
as separately pinned and attributed references; they must not enter the active
Repo manifest or product inheritance.

## Fixed architecture and security constraints

All work preserves the [accepted architecture](../docs/architecture.md). For
this milestone:

- No foreign interpreter or libc, including as a bootstrap.
- Do not substitute mainline Linux or mix target kernel, module or firmware
  revisions.
- `/usr` is a read-only bind view over the active signed APEX. `/etc` remains
  Android's `/system/etc` link.
- Do not flatten the APEX, disable verification, set SELinux permissive, weaken
  untrusted-app execute policy, fork unrelated AOSP platform source, or use a
  pushed/stock replacement artifact.
- AOSP source fetching is source supply, not compliance with the
  [no-Google runtime boundary](../docs/architecture.md#foundation).

## Explicitly unresolved

This recipe does not decide:

- AOSP release-advancement policy beyond an exact tag per source operation;
- package or APEX generation/granularity design beyond this first proof APEX;
- writable `/home`, `/var`, or `/tmp` layout;
- owner-controlled versus official signing ownership;
- the ARM64 Cuttlefish execution host;
- an app-facing native ABI;
- package-manager implementation;
- AppFunctions integration; or
- the agent privilege model.

No later gate may silently choose one of these to make a check pass.

## Evidence directory

Use an operator-selected directory outside tracked source and preserve complete
commands and raw output. Each gate records, as applicable, the exact AOSP tag,
revision-pinned manifest and SHA-256, Andrix commit/tree/status and overlay
diff, signing inputs, packaged APEX, image fingerprint, artifact hashes, and
selected device instance. Network gates also preserve exact controls, raw
DNS/destination logs, and review results.

## SRC-0 — establish the pinned direct AOSP tree

**Input:** an exact Android 17 tag and explicitly authorized source
initialization.

1. Verify the AOSP release tag against the official release key.
2. Initialize and sync only the official platform manifest using the commands
   above; preserve the first failure without force-sync or source substitution.
3. Export `repo manifest -r`, hash it, and prove it contains no Lineage project,
   remote, revision, or product source.
4. Place the exact committed Andrix checkout at `vendor/andrix` without copying
   uncommitted workstation files.
5. Do not source envsetup, generate keys, or build.

**Pass:** one clean direct AOSP 17 tree and exact Andrix commit are pinned with
no Lineage dependency or source shortcut.

## P0-A17 — prove the exact source graph

**Input:** reviewed SRC-0.

1. Record `repo status`, the pinned manifest hash, Andrix HEAD/tree/status, host
   architecture, and output path state.
2. Source `build/envsetup.sh`; run product discovery and require only
   `andrix_cf_arm64_only_phone` from the Andrix overlay.
3. For `android-17.0.0_r1`, run
   `lunch andrix_cf_arm64_only_phone-cp2a-userdebug` and record
   `PLATFORM_VERSION` (17), platform SDK (37), `TARGET_PRODUCT`,
   `TARGET_DEVICE` (`andrix_cf_arm64_only`), `TARGET_ARCH` (`arm64`),
   `TARGET_CPU_ABI` (`arm64-v8a`), empty secondary architecture/ABI, and
   `PRODUCT_OUT`. Record `TARGET_RELEASE` (`cp2a`) from the lunch environment
   and generated release-config arguments, not Make's deliberately blanked
   dumpvar. The first r1 execution defeated the prepared `trunk_staging`
   choice: it reports `Baklava`, not `17`. `cp2a` is the stable release config
   in the same pinned tag; this is not source-tag advancement or a platform
   version override.
4. Prove the direct AOSP Cuttlefish product, BoardConfig, release config, Soong
   graph inputs, init inputs, and SELinux directories resolve.
5. Prove there is no registered or buildable Andrix Caiman product.

**Pass:** the pinned direct AOSP 17 tree resolves one ARM64-only Cuttlefish
product and the expected Andrix graph without Lineage or Caiman source.

## P1-A17 — build the signed proof modules

**Input:** reviewed P0-A17 and an explicit signing decision.

1. Generate only the authorized proof keys using the pinned tree's `avbtool`.
2. Re-run the exact lunch selection.
3. Build only `dev.andrix.usr` and `andrix.rc` first.
4. Preserve the first Soong/init/SELinux diagnostic. Make only already-authorized
   overlay-local mechanical repairs.

**Pass:** a non-flattened, updatable, system-ext APEX and init module build from
the pinned tree, packaging exactly `bin/andrix-hello` as a 64-bit executable.

## P2-A17 — establish the packaged-artifact oracle

1. Run `scripts/proof/apex_artifact.sh` on the exact built APEX.
2. Preserve container-signature, AVB, embedded-key, extracted-payload, ELF, and
   SHA-256 output.
3. Inspect the payload: normal APEX metadata, linker configuration, and
   `bin/andrix-hello` are allowed; a foreign root/interpreter/libc is not.

**Pass:** both APEX signatures verify; the embedded key matches; packaged
`andrix-hello` is AArch64, requests `/system/bin/linker64`, needs Android
`libc.so`, meets 16 KiB LOAD alignment, and has a recorded SHA-256.

## P3-A17 — build and statically review the complete image

1. Build the complete `andrix_cf_arm64_only_phone` image and matching ARM64
   Cuttlefish host package from the same pinned tree.
2. Prove the image contains the exact P2 APEX and baked `/usr` mountpoint; hash
   images, APEX, host package, and its AArch64 `launch_cvd`.
3. Record the fingerprint, complete product package/module inventory, and
   relevant runtime configuration/defaults.
4. Review for prohibited Google components, privileged compatibility layers,
   and configured Google DNS, time, connectivity, captive-portal, location/SUPL,
   update, or configuration endpoints.

**Pass:** the complete image and matching host package are provenance-bound and
the static no-Google review exposes no prohibited component or endpoint. Static
review is not runtime compliance.

## P4-A17 — prove `andrix-hello` at runtime

**Input:** reviewed P3-A17 and an explicitly authorized ARM64 KVM/egress fixture.

1. Start controlled external egress capture before the image's first boot.
2. Launch only the exact P3 image and matching host package; record launch and
   boot logs and wait for `sys.boot_completed=1`.
3. Set `ANDRIX_EXPECTED_APEX`, `ANDRIX_EXPECTED_PROOF_ELF`, and
   `ANDRIX_EXPECTED_FINGERPRINT` from P2/P3 evidence.
4. Clear logcat, run `scripts/proof/device.sh`, and preserve all output.
5. Stop capture only after the proof; explain every attempted destination.

**Pass:** the expected factory APEX is active; device/APEX/artifact hashes and
fingerprint agree; `/usr/bin/andrix-hello` and the canonical APEX path are the
same mounted read-only file and both print exactly `andrix`; the executable uses
Bionic on the sole ARM64 ABI; `/etc` is Android; SELinux is enforcing; no
relevant unexpected AVC occurs; and no successful, blocked, or unexplained
Google-directed attempt occurs.

## P5-A17 — prove the ordinary-app boundary

Use an explicitly authorized disposable ordinary app to show its ARM64 JNI library
uses the same Android linker/Bionic ABI while `execve` from writable app-private
storage remains denied. Do not use a privileged app, shell-domain proxy, or
policy relaxation.

## P6-A17 — existence review and stop

Review the pinned source manifest, overlay commit/diff, keys, build logs, exact
APEX/image/host-package hashes, fingerprint, static and runtime no-Google
evidence, P4 device proof, and later P5 app proof without editing evidence.

The first runtime claim is only that `andrix-hello` exists under `/usr` in one
direct-AOSP-17 Cuttlefish image with the declared invariants. Caiman, package
composition, writable layout, tools, daemons, agents, UI, AppFunctions, and a
package manager require later project decisions.
