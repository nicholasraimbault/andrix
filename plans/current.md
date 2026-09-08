# Current work

**Active milestone:** [Phase 1 — prove `andrix-hello` under `/usr` on direct
AOSP 17](2026-08-28-phase1-andrix-hello-aosp17.md).

**Experimental; first emulated runtime checks passed.** The ARM64 image has
booted in an [offline QEMU/TCG smoke test](2026-09-06-qemu-smoke.md) on x86-64.
Signed APEX activation, read-only `/usr` and the ordinary-app execution boundary
passed there with SELinux enforcing. Native ARM64/KVM and complete no-Google
network qualification remain unproved. No supported release or phone-installation
image is available.

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
  to twelve files in eight projects for the frozen connected candidates.
  The current [rollback-retention implementation](2026-09-07-rollback-retention.md)
  added five framework files for frozen `f5ff864`. The current
  [lifecycle correction](2026-09-08-rollback-lifecycle.md) adds checked AtomicFile
  commits and staged reconciliation: eighteen files in nine projects under qualification.
  The earlier additions address wallpaper app-link verification, DSU/attestation
  endpoints and owner-selected maps. Project HEADs remain pinned; the manifest
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
| P3 | Adapted full image and matching host packages build. Normal product-policy overlays and key image contents pass offline checks; complete packaged-app endpoint review remains open. |
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

### Earlier stock-provider baseline

The frozen stock-provider candidate built successfully in 9:29 with overlay producer
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
is needed. That initial check was local; the later public CT publication and
Android installation result are recorded below.

All **212 host-only regression tests** pass, covering artifact/app checks,
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

## Latest connected result and next gates

The [public-CT candidate](2026-09-07-public-ct-runtime.md), producer
`09d890f00e9eca90538287d72e03c4d6f9294885`, built and booted under ARM64 QEMU/TCG.
All five CT downloads succeeded without retries; Android verified and installed
v2 89.30 and v3 90.5. Normal shell reads confirmed both current links and exact
published file hashes. CT permissions, signatures, allowlist and scheduling were
unchanged. The original private-endpoint and version-assumption failures remain.

APEX/read-only `/usr`, ordinary-app isolation and the WebView JS/HTTPS/hostname
negative passed again, including ordinary permission approval and uninstall.
Safe Browsing initialization remains false/unavailable. The 36,109-packet
capture observed only owned guest service destinations, local multicast and
public CT delivery, with zero kernel-reported drops. IPv6 was local/loopback only.
Both VM and fixture stopped cleanly. **This is bounded connected evidence, not a
complete no-Google or native-runtime qualification.**

The subsequent [Vanadium qualification](2026-09-07-webview-qualification.md)
verified the compiled Config signer gate with real trusted/untrusted factory
packages, cross-UID SafeMode rejection, fast-mode activation/deactivation and
persisted-job retirement after an Android reboot. The manifest-only three-APK
update installed and loaded Config 207, but **rollback failed**: r1's
RollbackManager reported the static TrichromeLibrary not installed and discarded
the whole rollback record. These are bounded API/state results, not new privacy
qualification: the long capture dropped 167 packets, and the short negative/update
windows did not establish guest Internet connectivity.

The [split-cohort follow-up](2026-09-07-webview-cohort-rollback.md) then staged
immutable libraries separately and obtained real atomic WebView/Config rollbacks
to both factory and non-factory versions. Deliberate removal of an unused old
library was allowed despite an available rollback; rollback failed closed without
partially changing consumers. Reinstalling the identical signed prerequisite
made the normal rollback succeed. Post-repair ordinary JS/HTTPS/hostname checks
passed. This connected workload captured 85,812 packets with zero reported drops
and no observed Google guest destination; it is still not universal qualification.

The [retention image and recovery test](2026-09-07-rollback-retention.md), producer
`f5ff864`, then preserved unused B through normal deletion attempts, real pruning
and an Android reboot. Five distinct real process crashes triggered PackageWatchdog
itself: caller `android`, rollback177674029, success at 2026-09-07T19:34:33.949Z;
exact non-factory B/207 and Config initialization were independently rechecked.
Completed pins released on a later normal C update. Final ordinary C consent,
JS/HTTPS/hostname checks passed; Safe Browsing remains false. Capture: 145,260 packets,
zero drops showed only owned/public-CT/local guest destinations. Failed fault drivers,
the rejected expiry-setup downgrade and unqualified lifecycle edges remain explicit.
Both probes were removed; VM/services stopped with exit 0 and the lease was released.

The [lifecycle follow-up](2026-09-08-rollback-lifecycle.md) has now demonstrated
available-expiry release, ready staged upgrade abandonment across reboot and normal
staged D→C restoration on frozen `f5ff864`. It also reproduced a defect: expiry of
an in-flight staged restore released its required library. Source review confirmed
that AtomicFile's logging-only commit hid some errors and staged READY deleted
backups too early. Corrections pass 221 host tests. Final image `d2ffbd8` then
passed typed in-flight expiry refusal before/after metadata reload, protected
library retention, staged restoration, completed-pin release and normal available
expiry. Final ordinary D consent/JS/HTTPS/hostname checks passed; Safe Browsing
remains false. Its 87,707-packet/zero-drop capture showed owned/public-CT/local guest
destinations only. Intermediate malformed Binder errors and other failed observers
remain preserved. All task VMs/services stopped with exit 0. These synthetic generations are
not real Chromium migrations or production-power-loss qualification.

1. Continue broader recovery/hardening and explicitly pinned real-version
   migration checks, rather than repeating provider selection. Remaining lifecycle
   limits include the forward-new-library pending-install window, real Android
   I/O/power-cut behavior, system-owned rollback cancellation and ambiguous
   concurrent owner changes. No production updater or signing policy was selected.
   Vanadium152 is already the tested default provider; only the recipe remains
   opt-in, with unflagged builds retaining145. No promotion.
2. Qualify conditional/manual app and other carrier/network paths. DSU and
   attestation snapshot delivery is not replaced by CT-data proof. IPv6 Internet
   and every supported endpoint profile remain untested.
3. Complete P3 before a supported runtime/release claim, then native ARM64/KVM,
   native P4/P5 and P6 using available hardware. No new rental, purchase, phone
   port, substituted artifact or relaxed Android policy follows from emulated
   success. The accepted architecture and signing/update ownership still apply.

Caiman, package composition, owner writable layout, tools, daemons, agents,
UI and a package manager remain outside this first proof. The accepted
[architecture](../docs/architecture.md) is a requirement, not a shipping claim.
