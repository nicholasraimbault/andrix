# WebView privacy control review

This is a source/artifact review, not runtime proof or a WebView-provider change.
The current milestone still uses the exact AOSP r1 prebuilt `com.android.webview`
**145.0.7632.218**. No Vanadium APK, GrapheneOS inheritance, different Chromium
version, TLS-disable flag or modified trust store has been introduced.

The subsequent [Vanadium integration assessment](vanadium-assessment.md)
examines the full patch set, actual AOSP provider rules, reflective fallback
checks and packaging/update responsibilities. It finds a credible WebView-only
prototype route, not a validated provider or authorization to replace this APK.

## What Vanadium demonstrates

Reference: [GrapheneOS/Vanadium at
`fdcc1b50ce6fb34c87b2fb11978f9f3ce76fe226`](https://github.com/GrapheneOS/Vanadium/tree/fdcc1b50ce6fb34c87b2fb11978f9f3ce76fe226).
Its `args.gn` selects Chromium **152.0.7977.84**, not the 145 prebuilt above.

The relevant methods are concrete, not a generic “degoogled” label:

- Patches `0062`/`0063` add `FIELDTRIAL_SEED_ENABLED`, default false, and gate
  shared native field-trial setup. `0064` gates Chrome's first-run fetch; that
  patch alone is **browser-only**, not the WebView control.
- `0065` gates WebView's `WebViewChromiumAwInit.startVariationsInit()` and
  `finishVariationsInitLocked()`, using generated Java build flags and Vanadium
  GN extension dependencies. This is a source/build feature, not an Android
  resource overlay or a runtime switch already present in our APK.
- `0106` stops appending variations headers. This is distinct from preventing
  seed downloads or applying seeds.
- Updater pings off, HTTPS-required updates, and routing component downloads to
  `update.vanadium.app` / `dl.vanadium.app` are **not** the same as disabling
  background updates. They introduce a separately operated service dependency.
- `enable_reporting=false` is a build argument. The inspected crashpad patch
  changes packaging of its trampoline; that alone does not prove every crash
  reporting path was compiled out.

The [Vanadium README](https://github.com/GrapheneOS/Vanadium/blob/fdcc1b50ce6fb34c87b2fb11978f9f3ce76fe226/README.md)
explicitly relies on GrapheneOS hardening/compatibility. Its full product also
uses different package names, Trichrome/config packaging and signing inputs.
Individual privacy-control ideas need not depend on all that hardening, but the
whole product is not an automatically compatible WebView replacement. Some new
build-flag scaffolding carries GPL-2.0-only notices; copying it would require
licensing review, not relabeling it under this repository's Apache license.

## Matching 145 source observations

Separately attributed Chromium references use the immutable tag
[`145.0.7632.218`](https://chromium.googlesource.com/chromium/src/+/refs/tags/145.0.7632.218/),
not Vanadium's newer base:

- `android_webview/glue/java/src/com/android/webview/chromium/WebViewChromiumAwInit.java`
  starts and finishes `VariationsSeedLoader` without the Vanadium build-flag gate.
- `android_webview/java/src/org/chromium/android_webview/variations/VariationsSeedLoader.java`
  requests a seed through `VariationsSeedServer` when needed. A failed bind is
  handled and its file descriptor closed; that is an important compatibility
  path, not evidence that renderer behavior has been tested here.
- `android_webview/nonembedded/java/src/org/chromium/android_webview/services/AwVariationsSeedFetcher.java`
  schedules a job after seed requests, with charging/throttling conditions.
  A URL in the APK is not proof of a boot-time request.
- `components/variations/android/java/src/org/chromium/components/variations/firstrun/VariationsSeedFetcher.java`
  contains the Google normal/fast seed URLs. Its `variations-server-url` command
  line option is a **retarget**, not a verified product-level disable mechanism.
  An empty/broken endpoint is not a valid no-Google control.

Those source references guide examination of the pinned APK; they do not by
themselves prove binary behavior, supported flag delivery or all entry points.

## Component-default trial: mechanism works, recovery gap remains

The exact r1 `SystemConfig.readComponentOverrides()` accepts per-component
`enabled=false` configuration. `ScanPackageUtils.configurePackageComponents()`
applies it to system-app activities, receivers, providers and services during
package scanning. Product/system-ext sysconfig directories are read. This is
separate from resource overlays and does not require rewriting a WebView APK.

The actual 145 manifest declares separate variations seed server/fetcher,
safe-mode variations provider, metrics/minidump upload and component-update
services. A host-only source trial exercised two candidate disabled sets:

| Trial | Source-level result |
| --- | --- |
| `AwVariationsSeedFetcher` only | The ordinary seed server still asks JobScheduler to schedule it. The disabled service is not found, causing an uncaught `IllegalArgumentException` in the scheduling path. |
| `AwVariationsSeedFetcher` + `VariationsSeedServer` | The ordinary loader takes its handled failed-bind path and schedules no seed job. Fast/safe-mode activation can still call the disabled fetcher and propagate the same exception. |

The test used extracted r1 `SystemConfig.readComponentOverrides`,
`ScanPackageUtils.configurePackageComponents`, `PackageUserStateUtils.isEnabled`
and JobScheduler request validation, plus the matching Chromium fast-action/
recovery-dispatch methods. DOM, package-manager/context and fresh scheduling
adapters supplied the surrounding host environment. The XML/default-state
mechanism affected only the selected components; renderer, general recovery,
local seed provider and component-update defaults stayed enabled. Explicit
user-enabled state still overrides a parsed default.

This is **not Android runtime or rendering proof**. It tests source-method
behavior with named adapters, not real Binder, PackageManager or JobScheduler
services. It also does not establish the absence of native download paths.

### Why the simple disabled set is not accepted as a complete solution

`VariationsSeedHolder.SeedWriter` schedules before writing a seed, with no catch
for JobScheduler's exception. Disabling the server as well avoids that ordinary
entry point. However, `NonEmbeddedFastVariationsSeedSafeModeAction.onActivate()`
also schedules directly; neither it nor the shared recovery dispatcher catches
that exception. The registered component-reset action precedes the fast action;
do not misreport that earlier action as skipped. The fast activation still
fails to complete normally, and source review identifies startup/persisted-state
risks that require further validation.

Disabling the safe-mode seed content provider would not fix scheduling: it
serves local bytes, not downloads. Disabling general `SafeModeService` or security
component updates to hide this gap would violate the intended scope. Their
other functions must remain available. A fresh Cuttlefish image without Play
may not activate fast mode, but that is not a general safety or privacy proof.

**No component override is included in the default product, and the WebView APK
is unchanged.** The trial XML and source harness are retained with private
engineering evidence, not silently shipped as a working no-Google feature.

A complete solution needs a graceful control for both ordinary and fast seed
paths, then authorized rendering/network tests and separate review of reporting/
component-update behavior. A source-level gate or guarded scheduling change
would require an explicit compatible WebView build/provider decision; it cannot
be inserted into the current prebuilt by an RRO. No GrapheneOS/Vanadium adoption,
APK replacement or trust-policy change is authorized by this trial.
