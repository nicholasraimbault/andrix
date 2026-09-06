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
- The new candidate additionally applies the explicit, digest-checked
  [network endpoint adaptation](../patches/android-17.0.0_r1/README.md): six
  working-tree files in three AOSP projects. Their HEADs remain pinned, but the
  manifest alone does not describe this build; the declared patch is required.
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
| P3 | Adapted full image and matching ARM64 host package build. Three baked overlays and key image contents pass offline checks; packaged-app endpoint review remains open. |
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

The new complete candidate built successfully in 12:26 with overlay producer
`52eb1c22ffc81aecc086696070142c8c8cb5bbcc` and the recorded endpoint patch. Its
expected fingerprint is:

```text
Andrix/andrix_cf_arm64_only_phone/andrix_cf_arm64_only:17/CP2A.260605.016/andrix.r1.52eb1c2:userdebug/test-keys
```

All three HTTP(S)/NTP RROs are now in the actual product image, with
SDK/min/target 37. Their signatures, exact resource values and host-generated
idmaps were checked against image-extracted targets with overlayability checks
enabled. NetworkStack and connectivity-service dex contain the adapted DNS/CT
names. The actual system-ext image contains the exact signed P2 APEX and init
files; `/usr` and Android's `/etc` link remain. The APEX, proof ELF, optional P5
APK and ARM64 host tarball are byte-identical to the previously checked ones.
All 28 image files, both host packages and proof packages are separately frozen
and hashed outside source. This is not runtime activation or complete P3 clearance.

The public-CA certificate for `probe.andrix.org` verifies against the built
Conscrypt CA bundle. The bounded service passed real loopback HTTP/HTTPS 204,
wrong-hostname rejection, exact signed CT-file responses, HTTPS-only CT access
and clean signal shutdown checks. The CT files retain the original signature
and match the resource APK's unchanged key allowlist; no live upstream proxy
is needed. No public endpoint is deployed, and this is not Android validation.

All **110 host-only regression tests** pass, covering artifact/app checks,
overlays, patch guards, probe/CT handling and fixture configuration. Wrong-certificate and corrupted-
payload checks fail closed. Native/Java extracted-function tests also checked
DNS wire names, record types and nonce behavior without network traffic.
Host preflight/config/parser checks do not qualify a real runtime host. Private
signing/certificate keys and raw evidence remain outside published Git.

## Next gates

1. Complete the remaining packaged-app endpoint review, especially inherited
   QuickSearchBox and the pinned prebuilt WebView's variations behavior. Literal
   presence is not automatically a connection, but neither is it clearance.
   Do not disable TLS/WebView or substitute source to force a pass. See the
   [network review](../docs/proof-network.md) for implemented controls and limits.
2. Finalize the real fixture's DNS/RIL/DHCP/RDNSS, qualified NTP source, routing,
   TLS/CT service and external-capture bindings. Config renderers and the
   [capture-before-boot procedure](../docs/runtime-fixture.md) are prepared;
   deployment and Android-client validation remain pending.
3. Complete P3 review before paid runtime testing, then qualify the explicitly
   authorized ARM64 Linux/KVM fixture and matching host package. No rental,
   network administration or boot is authorized by a successful build alone.
4. Perform P4/P5 runtime checks and P6 existence review. Do not substitute an
   x86 image, software-emulated ARM, stock/pushed replacement artifacts or a
   physical phone port. Do not disable verification or relax SELinux/app policy.

Caiman, package composition, owner writable layout, tools, daemons, agents,
UI and a package manager remain outside this first proof. The accepted
[architecture](../docs/architecture.md) is a requirement, not a shipping claim.
