# Vanadium WebView integration assessment

## Conclusion

**A WebView-only Vanadium derivative is a credible prototype candidate on
Andrix's retained AOSP framework. It is not a drop-in APK or a validated
no-Google provider.** The reviewed GrapheneOS hooks mostly have reflective
fallbacks; this assessment found no need to import GrapheneOS framework APIs,
a privileged compatibility proxy, its allocator, or its SELinux policy just
to satisfy those hooks. That does not reproduce GrapheneOS's hardening.

Prefer evaluating this maintained upstream before starting an independently
curated Chromium privacy fork. Keep the upstream patch series intact initially
and build only the required WebView/shared/config outputs; pruning patches by
"browser" in their titles is not a dependency analysis. The outstanding work
is provider packaging, source/signing/update ownership, network defaults and
security/API behavior—not an assumed whole-OS port.

This is a **reference-only assessment**, not adoption authority. Andrix still
ships the unchanged r1 `com.android.webview` 145.0.7632.218 prebuilt. No provider,
product, manifest dependency, TLS, sandbox or security-component change was
made. No Chromium/Vanadium APK build, Android boot or device capture occurred.

## Exact references and checks

- [GrapheneOS/Vanadium `fdcc1b50ce6fb34c87b2fb11978f9f3ce76fe226`](https://github.com/GrapheneOS/Vanadium/tree/fdcc1b50ce6fb34c87b2fb11978f9f3ce76fe226):
  326 reference files, including 309 primary patches. Reconstructed its 214
  `vanadium/` extension files in private reference storage, including later
  fixups; no patch was applied to the Android checkout.
- Matching [Chromium `152.0.7977.84`](https://chromium.googlesource.com/chromium/src/+/refs/tags/152.0.7977.84/)
  build, manifest, bridge and service references. This is not the shipped 145
  binary; old component assumptions must not silently carry across versions.
- Direct AOSP `android-17.0.0_r1` framework source and the actual built
  framework resource APK/hidden-API flags.
- Independent integration-recipe reference:
  [GrapheneOS/platform_external_vanadium `e33c1c04b22a1aa1ffbd6ad68152c14c7be4d012`](https://github.com/GrapheneOS/platform_external_vanadium/blob/e33c1c04b22a1aa1ffbd6ad68152c14c7be4d012/Android.mk).
  This separately pinned packaging recipe is not a matching Andrix product or
  proof of a particular Vanadium binary.
- [Upstream build documentation](https://grapheneos.org/build#browser-and-webview)
  was captured and hashed on 2026-09-06; it is a mutable documentation snapshot,
  not authority to follow its moving-version or key-generation commands.

Two bounded host checks supplement the source review:

1. Unchanged `CustomOSApis`, `CustomOSPermissions`, `MemberCache` and
   `ConnChecksUtil` compiled and ran against the built r1 public API stub jar,
   with explicit logging/annotation/generated-feature adapters. Missing custom
   APIs returned null; missing OS connectivity settings selected **GRAPHENEOS**.
   Disabling the respect-OS-setting feature also selected GRAPHENEOS.
2. An unsigned, uninstalled reference RRO mapping
   `android:xml/config_webview_packages` passed `idmap2 --policy product` against
   the image-extracted framework APK. Public-policy-only mapping failed. No
   overlayability bypass was used.

Neither check runs ART, Binder, a WebView renderer, native sandbox code or a
network client. Raw references, commands, failures and checks remain in private
engineering evidence. The public report records their scope, not a runtime pass.

## OS dependency matrix

| Area | Observed behavior | Andrix consequence |
| --- | --- | --- |
| Custom `Environment` execmem/DCL methods | `0173`, `0204`, `0280`: reflective lookup; missing methods return null and do not force JITless mode | No API shim indicated. GrapheneOS DCL protections are not thereby present. |
| `OTHER_SENSORS` | `0174`: nullable reflective permission lookup; principally browser UI consumers | Do not add a fake permission or claim equivalent sensor policy. |
| `grapheneos.version` and Pixel config rows | `0181`, `0282`: unavailable feature/device conditions skip those rows | Do not spoof GrapheneOS identity. Untargeted config rows still apply. |
| `GosPackageState` | No reference in this snapshot | Not an established dependency of this version. |
| hardened_malloc | README describes OS-supplied protection; not supplied/replaced by this patch series | AOSP Bionic remains. Functional feasibility is not hardening equivalence. |
| MTE | `0119`, `0234`, `0235`: Android/Chromium memory tagging, with a disabled-at-startup path | Hardware/kernel behavior still needs ARM64 tests. Do not turn it off to force a pass. |
| CFI, stack protection, JITless seccomp | Compiler/Chromium sandbox changes; OS DCL hooks can be unavailable | Validate generated ELF, process startup and sandbox behavior; no platform policy relaxation. |
| Config parser's WebView package query | Reflects standard `WebViewUpdateService.getCurrentWebViewPackageName()` | Exact built r1 hidden-API flags mark the method `sdk,system-api,test-api`; no new hidden-API exemption indicated. Config parsing still needs runtime proof. |

Browser UI, passwords, default search, browser site isolation and browser CT
feature defaults are not automatically WebView behavior. In particular,
Vanadium's `0243` CT feature patch is in `chrome/browser`, not a proof of WebView
CT behavior or a replacement for Android's separately reviewed CT service.

## Minimum proposed product integration

For the upstream Trichrome packaging shape:

1. Build ARM64-only **TrichromeWebView + TrichromeLibrary + VanadiumConfig**.
   The Chrome browser APK is not required by the inspected WebView import rule.
   Trichrome's shared native library still contains shared/browser code; absent
   browser APK does not mean every browser string disappears.
2. Install the APKs as presigned product packages, retaining AOSP's
   `libwebviewchromium_loader` and `libwebviewchromium_plat_support`. Do not let
   the import step re-sign an APK behind embedded certificate pins.
3. Supply the provider-list resource using normal product policy. AOSP r1
   currently lists only `com.android.webview`; listing a new provider is a
   deliberate trusted-image decision, not an application permission bypass.
4. Choose derivative package names and signing ownership. Upstream defaults are
   `app.vanadium.webview`, `.trichromelibrary` and `.config`, with upstream
   certificate digests. Modified owner builds must not pretend to be official
   GrapheneOS-signed releases.
5. Preserve static-library version/certificate matching and config-APK signature
   verification. Upstream uses one signer for these outputs; Android's essential
   requirement is matching declared trust relationships, not a platform key.
   Design coordinated updates/rollback before shipping.

The pinned GN graph exposes `trichrome_webview_64_apk` and
`trichrome_library_64_apk`; `args.gn` disables the secondary ABI. The captured
website's generic `64_32` command must not be copied into an ARM64-only recipe.
A standalone WebView target also exists upstream, but changing the released
packaging shape would add another qualification task; it is not the preferred
first prototype.

Basic SDK constraints do not reveal an incompatibility: the Vanadium Trichrome
patch sets minSdk 34, matching Chromium's default target SDK is 36, and the
**actual r1 implementation** accepts WebView target SDK >= 33. The framework's
comment about targeting its own release is stricter than that implementation;
API-37 operation still requires real tests.

AOSP provider validation retains target/version checks, library metadata and
normal signature rules. Preinstalled system providers are trusted through the
verified image; non-system providers need configured signer matching on release
builds. Do not rely on the userdebug signature/version exceptions as release
validation.

## Network and security behavior needing disposition

- **GrapheneOS fallback is not “no configuration.”** `0205`/`0206` retain the
  GrapheneOS DoH probe hostname when the custom OS setting is absent. An Andrix
  derivative needs an explicit valid endpoint/default decision; toggling the
  feature off does not select the owned probe. Do not blackhole probes.
- **Seed gates are narrower than the entire service surface.** `0063`/`0065`
  stop shared field-trial setup/ordinary WebView seed initialization. The matching
  152 manifest still declares the fetcher and SafeMode services; the unchanged
  fast action can schedule the fetcher directly. No Vanadium patch in this
  snapshot changes those Java service files. Trusted-caller/developer activation
  and native paths still need attribution; the ordinary gate is not blanket
  no-Google proof.
- **Browser updater URLs are not established WebView traffic.** `0118` retargets
  shared updater code to `update.vanadium.app` / `dl.vanadium.app`, while `0088`
  disables pings, not updates. However, the 152 WebView manifest/source no longer
  contains the 145 APK's `AwComponentUpdateService` and
  `ComponentsProviderService`. Do not call these active WebView dependencies
  merely because their old names or shared-library URLs exist. Config APK data
  delivery and the actual linked/started update paths require separate checking.
- **Safe Browsing callbacks are not a protection claim.** `0306`/`0307` enable a
  config-controlled success callback for WebView Safe Browsing initialization
  and allowlist calls without invoking the checking backend. The matching pure
  upstream 145/152 bridge defaults instead report unavailable/false and have no
  GMS backend. The actual shipped 145 binary's bridge binding and embedding-app
  compatibility need comparison; do not disguise a security-feature removal as
  a networking fix or present a success callback as successful URL checking.
- **Config APK is part of intended behavior.** Its verified data affects flags,
  filtering and compatibility. Missing/untrusted config can fall back without a
  crash, but losing those controls is not a faithful working integration.
- TLS/CT, crash upload consent, media/DRM and remaining conditional endpoints
  still need source/artifact/runtime checks. No blanket component-updater,
  SafeMode, Safe Browsing or TLS disable is proposed by this assessment.

## Build, updates and licensing

Following Vanadium reuses maintained security/privacy work; it does not transfer
Andrix's release responsibility to GrapheneOS. Its documented Chromium/downstream
update cadence is separate from monthly Android releases. Andrix would own
prompt source tracking, builds, signing, tests, distribution and rollback for
its derivative. Freezing Chromium 152 indefinitely is not a support strategy.

A reproducible build needs the exact Vanadium commit, Chromium tag/commit,
DEPS/tool/PGO inputs, build arguments and signing public identities. `.gclient`
also downloads filter lists from mutable third-party URLs; archive/pin those
bytes and notices instead of claiming the repository commit alone specifies
all inputs. No hooks or full Chromium sync/build were run in this assessment.

The captured `generate-release` continues after individual signing failures
(`|| true`) and missing inputs. An Andrix pipeline must fail closed and verify
all expected APKs, signatures, pins and image-extracted bytes; upstream's script
alone is not an artifact oracle. No private keys were generated or accessed.

Vanadium carries GPL-2.0 code with explicit Apache-2.0/FTL compatibility notes
and a note that embedding apps using WebView are not derivative works merely
for that use. Preserve those terms, upstream notices and corresponding source
for any distributed derivative. Do not relabel Vanadium as Andrix Apache-2.0
code. The license is an integration obligation, not evidence that the whole
Andrix OS must change its architecture or original-code license.

## Follow-up decision

The owner subsequently authorized **one isolated WebView-only build feasibility
experiment** using named Vanadium/Chromium/tool pins and declared derivative
identities. Its scope is recorded in the [experiment plan](../plans/2026-09-06-webview-build-experiment.md).
This is an explicit exception to the earlier reference-only boundary, not
permission to import GrapheneOS or replace the default image immediately.

Before any promotion: establish exact APK/signature/library/config identities;
verify provider selection with normal policy; prove rendering/JS, valid TLS and
wrong-certificate rejection, subprocess/sandbox/MTE behavior, fresh and updated
userdata, normal and recovery paths, config updates and rollback; capture all
traffic from before boot through ordinary WebView use. Preserve the old image
and stop on unexplained behavior. Build/signing costs and ARM64 runtime authority
remain separate gates.
