# WebView privacy control review

This is a source/artifact review, not runtime proof or a WebView-provider change.
The current milestone still uses the exact AOSP r1 prebuilt `com.android.webview`
**145.0.7632.218**. No Vanadium APK, GrapheneOS inheritance, different Chromium
version, TLS-disable flag or modified trust store has been introduced.

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

## Narrower AOSP mechanism worth validating

The exact r1 `SystemConfig.readComponentOverrides()` accepts per-component
`enabled=false` configuration. `ScanPackageUtils.configurePackageComponents()`
applies it to system-app activities, receivers, providers and services during
package scanning. Product/system-ext sysconfig directories are read. This is
separate from resource overlays and does not require rewriting a WebView APK.

The actual 145 manifest declares separate variations seed server/fetcher,
safe-mode variations provider, metrics/minidump upload, and component-update
services. This provides a candidate path for configuring **specific optional
background components**, while retaining the provider and rendering services.
It has **not** been selected or applied yet. Before relying on it, check all
normal/fast-mode callers, disabled-service/provider error handling, fresh/update
behavior and what data each component carries. Do not blanket-disable WebView,
safety/component updates, TLS, or the whole service process.

The next decision should be based on that same-base control review and eventual
properly authorized rendering/network tests. A source-only Vanadium-style gate
would instead require an explicit compatible WebView build/provider decision;
it cannot be applied to the existing prebuilt by an RRO. The current
GrapheneOS-reference-only/source boundary remains in force.
