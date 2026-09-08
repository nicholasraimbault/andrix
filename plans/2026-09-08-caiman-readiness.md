# Pixel 9 Pro / caiman — read-only readiness inventory

## Scope and result

Read-only preparation for the owner's selected first physical development target,
Pixel 9 Pro (`caiman`). No phone access, unlock, flash, bootloader-state change,
vendor-package execution, source import, device build or large factory-image
extraction occurred. The working Cuttlefish image and immutable AOSP pins remain
unchanged. The source guard passed again; no compiler/runtime tests were needed
for this documentation-only inventory. Private evidence
`caiman-readiness-20260908T072333Z` seals 37 regular files. There is still no
buildable or flashable Andrix Pixel product.

**Finding:** this is a device-support port, not simply enabling a product already
present in `android-17.0.0_r1`. A bounded, separately pinned hardware-support layer
must be selected and reviewed before implementation. Existing milestone rules do
not authorize importing GrapheneOS/Lineage product inheritance or replacing the
platform base merely because a reference exists.

## Inspected facts

### 1. Exact AOSP checkout has no caimito/caiman target

The inspected manifest remains at
`5bc9a7ce1cd78dd53613bbfd0ebf506e1e4adb0f` (`android-17.0.0_r1`). Its device/kernel/
vendor entries contain no `caiman`, `caimito` or Tensor-platform project. Local
`device/google/caimito` is absent. The manifest has 1,087 project declarations;
three Darwin-only `notdefault` projects are not checked out, consistent with the
previous 1,084-project checkout inventory. This count is not a new release audit.
The existing eighteen-file adaptation still passes its exact source guard.

The public [Google caimito repository](https://android.googlesource.com/device/google/caimito/)
exists, but its `android-17.0.0_r1` tree request returned 404 and the observed refs
contained no Android16/17 release branch/tag. The older Android15 QPR2 reference
`26a0f4faf91d0f14570832d74f7dbe73353246fb` contains `aosp_caiman` recipes. That is
historical reference material, not an Android17 recipe or permission to mix releases.

### 2. Public driver packages do not close the vendor gap

The fetched [Google driver page](https://developers.google.com/android/drivers)
lists 27 Pixel 9 Pro packages, spanning Android14/15 and ending in the displayed
May2025 Android15 builds. It did not list an Android17 caiman driver package.
This is an observation of that page, not a claim that every relevant component
is unavailable elsewhere.

The [factory-image page](https://developers.google.com/android/images) exposes
restoration/wipe/licensing information, with its download listing behind an
acknowledgement step. No terms acknowledgement or image download was performed.
Licensing and permitted use/redistribution of device binaries need explicit review;
a tool's open-source license does not license its proprietary inputs.

### 3. There is an exact-AOSP17 public reference path

GrapheneOS's public `2026081300` manifest resolves to commit
`84536744f0c06cccbcfa2110e9c937671ddc3278` (annotated tag object
`5189230024ffe0048e0c351d5101c6b3f8b43eac`). Its
[commit-pinned manifest](https://raw.githubusercontent.com/GrapheneOS/platform_manifest/84536744f0c06cccbcfa2110e9c937671ddc3278/default.xml)
has AOSP default `refs/tags/android-17.0.0_r1`. GitHub reported the tag signature
valid; no separate local signing-key verification or source sync was performed.
The fetched [release page](https://grapheneos.org/releases#caiman) listed caiman's
stable channel as `2026081300` and separately described `2026081301` as its security
preview variant. The attempted `2026081301` source-manifest URL returned 404; the
verified public source reference here is the `00` tag, not a reconstruction of
the additional preview patch set or an inspection of the handset.

The manifest separately pins:

- `adevtool`: `5019450d9235c48a987250c890e346b416f8dfd4`.
- `device_google_caimito-kernels_6.1`:
  `8345e10be6d15080cd9700ca64c096f7ba8514e8`.

The [pinned adevtool documentation](https://raw.githubusercontent.com/GrapheneOS/adevtool/5019450d9235c48a987250c890e346b416f8dfd4/docs/usage.md)
describes vendor-module generation, file-hash specifications, state collection,
firmware extraction, missing properties/SELinux/VINTF/sysconfig handling and
stock-image inputs. Its tool license is MIT; this does not apply that license to
firmware or extracted binaries.

The inspected caiman config includes the gen9 config, which identifies platform
`zumapro` and includes the shared Pixel config. That shared config names stock
build `CP2A.260805.005`. This is a reference configuration, not a fully resolved
Andrix vendor specification or established compatibility with the handset.
No generator was executed and no generated device/vendor tree was imported.

The [GrapheneOS build guide](https://grapheneos.org/build) documents caiman support
and its separate kernel/vendor workflow. It describes GrapheneOS-specific
platform features and its own updater/signing arrangement too; those do not become
Andrix dependencies, identities, services or security claims by reference.

### 4. Pixel kernel lineage is distinct from Cuttlefish

The [official Pixel-kernel guide](https://source.android.com/docs/setup/build/building-pixel-kernels)
maps Pixel9/9Pro/9ProXL to `caimito`, branch
`android-gs-caimito-6.1-android16`, GKI lineage `android14-6.1`.
The fetched kernel-manifest branch tip was
`cdef6011c8645d62360c08c557291cf54d930596`; its individual projects still require
revision resolution before a build. Branch naming is not a claim that Android17
must be downgraded.

The reference GrapheneOS Android17 manifest likewise names a caimito6.1 kernel
prebuilt project; its tree includes `Image.lz4`, DTB/DTBO and module files.
No kernel binary was downloaded or verified. Cuttlefish's working6.12 kernel and
virtual-device modules are not interchangeable with this Pixel hardware stack.

## Device and recovery facts still needed

The handset's installed build is owner-reported, not an inspected firmware
inventory. Before a particular flash, record its current security-patch level,
bootloader/baseband versions, model/SKU and OEM-unlock eligibility without
publishing device identifiers. Keep normal security updates enabled meanwhile.

Do not infer downgrade safety from the phone being retail/unlockable. The factory
page's displayed May2025 anti-rollback warning names Pixel6/8, and its May2026
warning names Pixel10; neither proves caiman has no rollback restrictions.
Do not apply another device's flashing instructions to it.

Plan a complete data wipe, app-specific exports/authentication recovery, a
compatible signed restoration image and a defined Andrix signing/AVB setup.
Restoring an OS is not restoring application data. A specific unlock/flash remains
an explicit owner decision after inspected artifacts exist; do not relock blindly.

## Recommended next decision

Prepare a **separate, pinned Pixel device-support study**: compare the public
AOSP17 reference generation workflow, its stock inputs and kernel/module outputs
against direct AOSP17, identifying the minimum device-specific deltas and their
licenses. Keep platform, phone services, APK identities, SELinux and verified boot
intact. Review vendor networking/eSIM/carrier paths rather than stripping components
to produce a quiet capture.

Then present the proposed device/vendor/kernel pins, necessary source-boundary
changes, signing/restoration plan and build gates for approval. This inventory does
not choose those inputs, authorize their extraction/import, replace Android with
a VM/distro, or advance glibc/Wayland implementation.
