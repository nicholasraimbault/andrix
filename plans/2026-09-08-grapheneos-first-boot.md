# GrapheneOS-derived ARM64 image and first offline boot

## Authorized scope

The owner approved continuing from the [verified source and minimal APEX](2026-09-08-grapheneos-migration.md)
to a complete ARM64 test image and its first boot. This is an **offline functional
migration test**, not connected/no-Google qualification, native ARM64 execution,
Pixel hardware support or flash authority.

Preserve the existing AOSP checkout, frozen images, keys and evidence. Keep the
Pixel locked and untouched. Do not run a vendor generator, download/extract stock
factory inputs, deploy services, select production keys or add glibc/GUI software.

## Fixed producer and build

- Public GrapheneOS `2026081300`, authenticated manifest
  `84536744f0c06cccbcfa2110e9c937671ddc3278`, all 1,108 project pins unchanged.
- Image overlay `be031f983a80dc99ee132f82f7379333ac18c2a3` remains the minimal
  `andrix_gos_cf_arm64_only_phone-cur-userdebug` producer. New host observers are
  recorded separately; updating a checker is not silently changing the image.
- Reuse the existing lab APEX keys locally. No private signing material is placed
  in the runtime namespace or public repository.
- `droid hosttar`, eight jobs, exclusive heavy-work lease, recorded resources and
  relative `OUT_DIR=out`; RBE and official-build opt-in remain off.
- Build the optional ordinary-app test separately from the image, so it is not a
  preinstalled/system app. Verify its signer, manifest, ABI and bytes independently.

A real failed build remains failed; changes require a new recorded producer/input
set. Do not force an unsupported target or weaken hardening to turn it green.

## Pre-boot artifact gates

After successful build:

1. Freeze and rehash every image plus both generated host packages. Launch only
   a fresh writable copy with the matching host package—not mutable build output.
2. Verify the actual image contains the exact signed `/usr` APEX, baked mountpoint,
   init entry and policy inputs. Extract the image fingerprint and its actual
   `/system/bin/sh` for the ordinary-app control. Bind all expected hashes before
   guest access; a fresh device pull cannot be its own oracle.
3. Record product/module/package inventory, kernel and build metadata. Retained
   upstream GrapheneOS components/settings are not an Andrix network-policy pass.
4. Recheck the base-source pins and overlay status with the current restricted-Git
   verifier. Keep any observer timeout and its bounded recheck separately.

## Offline runtime containment

Use the existing T330 with the pinned image's x86 host package and packaged ARM64
QEMU/TCG, four guest CPUs/4 GiB, software rendering and enforcing SELinux. This is
CPU emulation, not KVM translating ISA or native/Pixel qualification.

Reuse the reviewed rootless user/mount/PID/network-namespace approach with fresh
runtime directories and an unused recorded vsock CID. Expose only test images,
host tools, scoped TUN/vsock devices, ordinary proof artifacts and evidence paths.
Do not mount the build tree, host home, Android signing keys or credentials.
No fake `/manager.sock`, capability output or hostwide route/security changes.

Create only private guest TAP/bridge interfaces; there is **no external interface
or default route**. Metrics/WebRTC remain explicitly off. Capture all guest-facing
traffic **before assembly**, retaining errors, attempted traffic and drop counts
through shutdown. There is no resolver/TLS/NTP/security-data success to claim in
this disconnected profile, and no Google-address-specific filtering or fake reply.

Inspect the assembled configuration, exact VM argv and interfaces before launch.
Use normal Cuttlefish/ADB control in this namespace, one explicit guest serial and
no root-adbd workaround. Boot and command deadlines must preserve failure logs.

## First-boot oracles

Run [the shared core checker](../scripts/proof/device.md) with the explicit
`offline-core` profile. Admission requires the exact supplied fingerprint, the
GrapheneOS ARM64 proof product family, matching product property and explicit ADB
serial. The default old local-RKP profile is **not** reused or relaxed.

Both profiles retain the same APEX/XML/hash/ELF/inode/output, read-only `/usr`,
Android `/etc`, enforcing SELinux and relevant-AVC checks. In offline-core, RKP
properties are successfully read and reported as **INFO**, not a policy PASS.
Do not change those properties just to make an old observer pass.

After the core check, run the freshly built ordinary-app fixture through normal
installation/instrumentation. Require its independent UID, no APK-declared
permissions or shared UID, non-platform signer, no capabilities, valid
system-shell control and byte-identical private-copy `execve` rejection with **EACCES**.
No grants, `run-as`, debugger, adopted identity or SELinux change is permitted.
Verify cleanup and retain the expected denial separately from core boot logs.
For this base, use the explicitly pinned P5 platform profile: GrapheneOS's parser
adds `OTHER_SENSORS` to code-bearing apps' PackageManager metadata. The APK still
declares none; the host accepts only that exact source-defined entry in this
profile, never an arbitrary permission list. No permission grant/revoke or APK/
platform change is used. See the [fixture contract](../tests/p5-ordinary-app/README.md#grapheneos-migration-metadata-profile).

Record available GrapheneOS-specific kernel/process protections honestly. The
Cuttlefish kernel is not the Pixel kernel; absent flags or documented upstream
compatibility behavior must not become a claim of full GrapheneOS hardening.
The pinned debug/emulator path returns zero SELinux flags when the kernel lacks
support and dev builds warn about missing DCL/ptrace protection or 48-bit VA.
These upstream fallback paths are not Andrix fixes; observe and report them rather
than suppressing their warnings or attributing Pixel protections to this guest.

If boot/core passes, observe a normal Android reboot with the same guest data
rather than host reassembly, then recheck the stable `/usr` identity and relevant
state. Do not relabel a host data-policy reset as Android persistence behavior.

## Stopping and promotion boundaries

Stop only owned guest/capture/controller processes and release the heavy-work
lease. Preserve original failures and freeze the evidence before publishing a
bounded result. A runtime success here is an emulated offline functional result,
not a release, all-app/renderer security proof or phone reliability assessment.

Connected testing follows the migration milestone's separate identity, updater,
app-catalog, RKP, TLS/CT and service-policy review. Caiman vendor/license/firmware,
restoration and explicit flash approval remain separate gates. The objective is
one bounded migration qualification, then the useful owner terminal/development
workflow—not endless synthetic provider rehearsals.
