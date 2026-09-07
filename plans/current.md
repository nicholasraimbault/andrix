# Current work

**Active milestone:** [Phase 1 — prove `andrix-hello` under `/usr` on direct
AOSP 17](2026-08-28-phase1-andrix-hello-aosp17.md).

**Experimental; first emulated runtime checks passed.** The ARM64 image has
booted in an [offline QEMU/TCG smoke test](2026-09-06-qemu-smoke.md) on x86-64.
Signed APEX activation, read-only `/usr` and the ordinary-app execution boundary
passed there with SELinux enforcing. Native ARM64/KVM and no-Google network
validation remain unproved. No supported release or phone-installation image
is available.

## Pinned source

- Manifest provider: `https://android.googlesource.com/platform/manifest`.
- Tag: `android-17.0.0_r1`, verified against the published AOSP release key.
- Manifest commit: `5bc9a7ce1cd78dd53613bbfd0ebf506e1e4adb0f`.
- Revision-pinned manifest SHA-256:
  `bf899d1468b31536794c54d4ef680102a7eb8a162af84daf6879a63bab79d131`.
- All 1,084 project HEADs matched their release-tag commits at source review.
  No Lineage dependency, force sync or source substitution was used. The first
  checkout failures were retained and recovered with a bounded serial retry.
- The frozen `9eb0bd4` image used the recorded seven-file adaptation. Current
  source extends the digest-checked [network/product adaptation](../patches/android-17.0.0_r1/README.md)
  to twelve files in eight projects after the first connected WebView candidate.
  The new files address wallpaper app-link verification, DSU/attestation
  endpoints and owner-selected maps. Their HEADs remain pinned; the manifest
  alone does not describe an adapted
  build, and the exact patch revision plus candidate opt-in must be recorded.
- Product: `andrix_cf_arm64_only_phone-cp2a-userdebug`, Android 17 REL/API 37,
  device `andrix_cf_arm64_only`, sole ABI `arm64-v8a`.
  The initial recipe's `trunk_staging` selection reported `Baklava`, not `17`;
  `cp2a` is the released configuration in the same immutable tag.

The source/artifact work predates public publication. Original revision pins
and unedited evidence are retained privately; the publication revision mapping
is described in [source provenance](../docs/source-provenance.md).

## Verified results

| Gate | Result |
| --- | --- |
| SRC-0 | Complete pinned direct-AOSP source and committed Andrix overlay. |
| P0 | Product/board/init/policy inputs resolve; ARM64-only; no registered Andrix Caiman product. |
| P1 | Non-flattened, updatable system-ext APEX and init module build; AOSP init/APEX/linkerconfig/SELinux build checks pass. |
| P2 | APK-container and AVB-payload signatures verify; embedded key matches; exact packaged ELF inspected. |
| P3 | Adapted full image and matching ARM64 host package build. Three baked overlays and key image contents pass offline checks; packaged-app endpoint review remains open. |
| P5 preparation | Optional ordinary-app APK builds and passes static signer/manifest/JNI checks. |
| Additional offline emulated test | QEMU/TCG boot completed; device/APEX/`/usr` checks passed; ordinary ARM64/Bionic app control succeeded and byte-identical private-copy `execve` returned EACCES. Test package removal verified. Not native ARM64 or no-Google qualification. |

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
offline emulated run observed the intended property values. No AOSP source, SELinux rule,
trust store or signature-verification change was made for that control.

The current complete candidate built successfully in 9:29 with overlay producer
`9eb0bd462d63c86c37fe4cfddad764ab379e7d48` and the recorded network/product patch. Its
expected fingerprint is:

```text
Andrix/andrix_cf_arm64_only_phone/andrix_cf_arm64_only:17/CP2A.260605.016/andrix.r1.9eb0bd4:userdebug/test-keys
```

All three HTTP(S)/NTP RROs are now in the actual product image, with
SDK/min/target 37. Their signatures, exact resource values and host-generated
idmaps were checked against image-extracted targets with overlayability checks
enabled. NetworkStack and connectivity-service dex contain the adapted DNS/CT
names. The actual system-ext image contains the exact signed P2 APEX and init
files; `/usr` and Android's `/etc` link remain. The APEX, proof ELF, optional P5
APK and ARM64 host tarball are byte-identical to the previously checked ones.
QuickSearchBox is absent from the resolved package list, installed inventory
and extracted product image. The omission is scoped to Andrix Cuttlefish; a
pinned-Makefile regression test preserves other products' package membership.
Launcher3 handles a missing provider in its source; its APK remains unchanged,
and launcher runtime/visual behavior is unproved. No substitute search backend
was selected. The WebView APK is also unchanged.

All 28 image files, both host packages and proof packages are separately frozen
and hashed outside source. The additional offline emulated run subsequently
verified activation of this exact APEX and both executable paths, but did not
clear the remaining P3/network or native-host gates.

The public-CA certificate for `probe.andrix.org` verifies against the built
Conscrypt CA bundle. The bounded service passed real loopback HTTP/HTTPS 204,
wrong-hostname rejection, exact signed CT-file responses, HTTPS-only CT access
and clean signal shutdown checks. The CT files retain the original signature
and match the resource APK's unchanged key allowlist; no live upstream proxy
is needed. No public endpoint is deployed, and this is not Android validation.

All **191 host-only regression tests** pass, covering artifact/app checks,
overlays, patch guards, probe/CT handling and fixture configuration. Wrong-certificate and corrupted-
payload checks fail closed. Native/Java extracted-function tests also checked
DNS wire names, record types and nonce behavior without network traffic.
Host preflight/config/parser checks do not qualify a real runtime host. Private
signing/certificate keys and raw evidence remain outside published Git.

The [emulated test record](2026-09-06-qemu-smoke.md) preserves the first runtime
inspection failure: `adbd` could not traverse the `andrix_exec` directory for
`adb pull`, while Android's `shell` context could read and execute the payload.
The device checker now uses guarded raw `exec-out` reads without changing policy
or rooting adbd. Exact bytes/inodes and enforcing SELinux were verified. Earlier
failed-read and expected app-negative-test audit records remain preserved; the
repaired device check passed in a separate recorded log window. The offline VM
was stopped and its packet capture retained, not presented as a no-Google pass.

## Connected candidate and next gates

The [second connected candidate](2026-09-07-connected-candidate.md), producer
`e65e656`, booted with the signed WebView 152 package selected normally. P4/P5
passed; the revised ordinary WebView probe passed JavaScript, real HTTPS 204,
normal local-network permission approval and wrong-host TLS rejection. Safe
Browsing initialization truthfully returned false. The 45,111-packet window
observed only owned guest service destinations, local multicast and the explicit
public TCP control, with zero kernel-reported drops. Both VM and fixture stopped
cleanly. **This is not a complete no-Google pass.**

1. Resolve CT update delivery. The enabled CT service's alarm ran, but Android's
   DownloadProvider retries/timeouts prevented fetching even the public key from
   the private fixture. Its missing local-network permission is relevant evidence,
   not a proven root cause. A protected-broadcast trigger was denied; no root or
   permission workaround was used. Establish a successful delivery path without
   weakening Android. The owner authorized the [public CT Pages fixture](2026-09-07-public-ct-fixture.md)
   at `ct.probe.andrix.org`; its branch/site/DNS are configured and private/public
   resolver separation is tested. GitHub certificate provisioning and successful
   HTTPS publication verification remain pending. No Android image was changed
   by publication, and no private key or public host listener was added.
2. Complete remaining runtime/config-trust, recovery, update and rollback checks.
   The three-APK checker and exact image imports passed. The compiled ConfigInfo
   digest and fail-closed PackageManager gate were inspected; full negative/runtime
   coverage is still separate. Normal SafeMode and security services remain.
   Default builds retain WebView 145; the new provider is an explicit candidate
   opt-in, not a production signing/update decision.
3. Keep qualifying actual network profiles, rather than infer them from config
   renderers. Connected IPv4, owned DNS/DoT/NTP/TLS, host security-data expiry and
   the owner DSU catalogue have observations. IPv6 Internet, other carrier
   configurations and every conditional app path are not thereby cleared.
4. Complete P3 before a supported runtime/release claim, then native ARM64/KVM,
   native P4/P5 and P6. Use available hardware; no new rental, purchase, phone port,
   substituted artifact or relaxed Android policy follows from emulated success.

Caiman, package composition, owner writable layout, tools, daemons, agents,
UI and a package manager remain outside this first proof. The accepted
[architecture](../docs/architecture.md) is a requirement, not a shipping claim.
