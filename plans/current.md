# Current work

**Active milestone:** [Phase 1 — prove `andrix-hello` under `/usr` on direct
AOSP 17](2026-08-28-phase1-andrix-hello-aosp17.md).

**Experimental and unbooted.** Host builds and artifact checks have succeeded;
there is no runtime `/usr`, ordinary-app boundary or no-Google network proof.
No supported release or phone-installation image is available.

## Pinned source

- Manifest provider: `https://android.googlesource.com/platform/manifest`.
- Tag: `android-17.0.0_r1`, verified against the published AOSP release key.
- Manifest commit: `5bc9a7ce1cd78dd53613bbfd0ebf506e1e4adb0f`.
- Revision-pinned manifest SHA-256:
  `bf899d1468b31536794c54d4ef680102a7eb8a162af84daf6879a63bab79d131`.
- All 1,084 project HEADs matched their release-tag commits at source review.
  No Lineage dependency, force sync or source substitution was used. The first
  checkout failures were retained and recovered with a bounded serial retry.
- Product: `andrix_cf_arm64_only_phone-cp2a-userdebug`, Android 17 REL/API 37,
  device `andrix_cf_arm64_only`, sole ABI `arm64-v8a`.
  The initial recipe's `trunk_staging` selection reported `Baklava`, not `17`;
  `cp2a` is the released configuration in the same immutable tag.

The source/artifact work predates public publication. Original revision pins
and unedited evidence are retained privately; the publication revision mapping
is described in [source provenance](../docs/source-provenance.md).

## Verified host-side results

| Gate | Result |
| --- | --- |
| SRC-0 | Complete pinned direct-AOSP source and committed Andrix overlay. |
| P0 | Product/board/init/policy inputs resolve; ARM64-only; no registered Andrix Caiman product. |
| P1 | Non-flattened, updatable system-ext APEX and init module build; AOSP init/APEX/linkerconfig/SELinux build checks pass. |
| P2 | APK-container and AVB-payload signatures verify; embedded key matches; exact packaged ELF inspected. |
| P3 | Full image and matching ARM64 host package build. Image-content checks pass, but no-Google review remains blocked. |
| P5 preparation | Optional ordinary-app APK builds and passes static signer/manifest/JNI checks. It has not been installed or executed. |

The APEX contains only `apex_manifest.pb`, `etc/linker.config.pb` and
`bin/andrix-hello`. Its AArch64 PIE requests `/system/bin/linker64`, needs Android
`libc.so`, `libm.so` and `libdl.so`, and has four 16 KiB-aligned LOAD segments.

- APEX SHA-256:
  `e49cc8b098893e64f5015aa940edcd1611a81e5cf13399e11d74bb0d90335aec`.
- Packaged `andrix-hello` SHA-256:
  `e05d7dc2a5403213a8b4c86c1c68ccf5fa38acd7de8e014f12cc8f092d62dd93`.
- Optional P5 APK SHA-256:
  `5fbd9929f03d9c96083f1add02e2e25d1d2a2ee44f41e0764594a0fe6782f807`.

Offline EROFS inspection found the exact APEX and init rc, a baked root-owned
mode-0755 `/usr` directory, and `/etc -> /system/etc`. The ARM64 host tarball
contains an AArch64 `launch_cvd` entry. These are image-content observations,
not evidence that the bind mount or executable works on a running system.

The Cuttlefish-only early-init network module now sets RKP-only false and
clears the remote-provisioning hostname using AOSP's supported no-endpoint
handling. Its rebuilt image was inspected; the proof APEX is unchanged. The
runtime effect of that action is not yet proved. No AOSP source, SELinux rule,
trust store or signature-verification change was made for that control.

The Cuttlefish HTTP(S) probe RROs also compile, with SDK/min/target 37. Their
signatures, exact packaged endpoints and host-generated idmaps were verified
against the built NetworkStack/Connectivity resource APKs with overlayability
checks enabled. This was a module-only build: existing image bytes are unchanged
and do not yet contain these RROs.

A public-CA certificate for `probe.andrix.org` was issued using DNS-01. Host
verification against the built Conscrypt APEX's CA bundle passed, as did empty
HTTP/HTTPS 204 responses and a wrong-hostname rejection in a temporary loopback
fixture. No public endpoint is deployed; this is not Android runtime validation.

All **52 host-only regression tests** pass. Wrong-certificate and corrupted-
payload checks fail closed. Host-preflight probes do not certify a runtime host.
Private signing keys, certificate keys and raw evidence remain outside Git.

## Next gates

1. Finish valid no-Google configuration and static component/endpoint review.
   Existing images still have Google connectivity/time defaults; the new probe
   RROs require image integration. DNS/NTP and other conditional endpoints still
   need disposition. The inherited RKP property text remains in the product
   image, with the early-init override; do not
   mistake text removal for effective configuration or source supply for
   runtime compliance. See the [network preparation map](../docs/proof-network.md).
2. Deploy the controlled `probe.andrix.org` endpoint using the issued certificate.
   Endpoint DNS/routing, hosting and Android-client validation remain pending.
   No private CA or TLS-disable option has been selected.
3. Freeze reviewed images, matching host package, proof APK and capture/launch
   procedure before beginning paid runtime testing. Qualify an ARM64 Linux/KVM
   fixture with controlled external egress before the first Android boot.
4. Perform P4/P5 runtime checks and P6 existence review. Do not substitute an
   x86 image, software-emulated ARM, stock/pushed replacement artifacts or a
   physical phone port. Do not disable verification or relax SELinux/app policy.

Caiman, package composition, owner writable layout, tools, daemons, agents,
UI and a package manager remain outside this first proof. The accepted
[architecture](../docs/architecture.md) is a requirement, not a shipping claim.
