# Optional ordinary-app WebView probe

Disposable self-targeting instrumentation for the **separately authorized**
Andrix no-Google candidate evaluation. This is a fixture, not a runtime result,
provider-selection mechanism, product package or qualification of a provider.
No provider/product, trust store, server route or permanent provider setting is
changed. Host orchestration, artifact/signing checks and runtime are separate.

Public SDK/min/target **37**, no third-party libraries or native code. Package
`dev.andrix.proof.webview` requests only `INTERNET`; its Activity is not exported.
It uses the existing non-platform `:dev.andrix.usr.certificate`, not a new key.
Like the [P5 fixture](../p5-ordinary-app/README.md), `android_test` may produce a
debuggable APK, but the probe uses no root, `run-as`, UiAutomation, adopted
permissions, hidden/platform APIs or privileged installation.

## Contract and evidence

All three string arguments are mandatory; there are **no endpoint/provider
defaults**:

- `good_url`: canonical `https://HOST[:PORT]/generate_204` on the caller's owned,
  authorized fixture, with a valid system-trusted certificate for that host.
- `bad_url`: the same path and port on a **different owned hostname routed to
  the same server/TLS fixture**, intentionally absent from that certificate's
  names. The certificate must otherwise be trusted and currently valid.
- `expected_provider`: the exact already-selected, independently qualified
  WebView package name. No provider switch is performed by this APK.

Both URLs require lowercase ASCII DNS names, at least two labels and an
alphabetic DNS suffix. IP literals/alternate numeric IP spellings, local or
reserved `.localhost`, `.local`, `.invalid`, `.test`, `.example` suffixes,
userinfo, query, fragment, escapes, whitespace, backslashes, trailing dots and
noncanonical ports are rejected. Omit default `:443`; other ports must be
1..65535 without leading zeros. Only the exact `/generate_204` path is accepted,
not `/`, another path, or redirects. The app cannot attest domain ownership,
DNS/routing to a common fixture, SAN contents or artifact provenance: the host
must establish these before use. Do not substitute third-party browsing URLs.

The UI-thread Activity performs four ordered stages:

1. Record `WebView.getCurrentWebViewPackage()` package/version before and after
   `new WebView(Activity)`, requiring `expected_provider` both times. Record
   ordinary app/package UID, flags, permissions, source path, SDK and fingerprint.
2. Call public `WebView.startSafeBrowsing`, requiring a non-null Boolean callback,
   recording its exact value and `WebSettings.getSafeBrowsingEnabled()` before
   and after. **Both true and false callback/setting observations are allowed.**
   Neither is evidence that a checking backend exists or protects URLs. The probe
   never changes that setting, uses an allowlist or calls a Safe Browsing bypass.
3. Enable JavaScript and use `loadDataWithBaseURL` with local, fixed HTML and the
   good HTTPS origin plus `/` as both base and history URL. Neither loads HTML
   from the server. Inline JS changes a DOM node to `42`, then calls
   `fetch('/generate_204')` with same-origin mode, omitted credentials, no cache,
   no referrer and redirects rejected. `evaluateJavascript` polls the result;
   require exact origin/base URL, DOM value, response URL, basic response type,
   no redirect and **status 204**, not merely `ok`. This fetch, not the local
   HTML's assigned origin, is the positive HTTPS control. No JS-to-Java bridge,
   external HTML/subresources or new server routes are needed. A restrictive
   page CSP, disabled file/content access and no mixed content bound page loads.
4. In the same WebView, navigate to `bad_url`. Every `onReceivedSslError` call
   unconditionally calls **cancel**, including unexpected or late errors.
   Require the exact bad URL, `SSL_IDMISMATCH` alone and a returned cancellation
   call. Expiry/untrusted-chain errors, generic handshake/DNS errors, HTTP errors,
   navigation/redirects, or timeout cannot substitute for hostname rejection.
   A successfully trusted wrong-host 204 with no SSL callback **times out and
   fails**, even if WebView never commits a page. A main-frame error following
   cancellation is only diagnostic, not a separate proof. `onPageFinished` is
   deliberately not treated as success: cancellation can also invoke it.

Each stage has a **180-second worker-thread wait**, also covering a stalled UI
thread/provider initialization; no UI-thread waits or unbounded `runOnMainSync`/
`startActivitySync` are used. All asynchronous exceptions handled by the fixture
are retained with a stack trace and FAIL, including cleanup failures and renderer
loss. In `finally`, the runner requests main-thread `stopLoading`, detachment,
`removeAllViews`, `destroy` and Activity `finish`, with another 180-second bound
and `onDestroy` acknowledgement. Pause/resume APIs are retained. Timeouts cannot
forcibly repair a hung main thread; failed/missing cleanup needs host reconciliation.

The final instrumentation bundle contains:

- `webview_probe`: schema-1 JSON with `status`, package/UID, timeout,
  `safe_browsing_protection_verified: false`, and ordered timestamped
  `observations` (arguments, app, providers, stage data/completions, failures,
  cleanup). Failed runs retain partial observations and exception stacks.
- `webview_probe_status`: `PASS` or `FAIL`.
- Instrumentation code **-1** (`Activity.RESULT_OK`) only after all stages and
  acknowledged cleanup without a failure; **0** (`RESULT_CANCELED`) otherwise.

Do not use `adb`'s shell exit code alone. Missing/malformed/truncated JSON, app or
instrumentation death, missing completion/cleanup, unexpected package/version,
or any failure means FAIL/incomplete, never a pass. A PASS establishes only
these app-visible behaviors. It does not prove no-Google egress, Safe Browsing
protection, CT enforcement, sandbox/hardening, visual rendering, update policy
or image-wide correctness. Capture and attribution are independent requirements:
a returned cancellation call is not a packet-level rejection attestation.

## Build/review and authorized invocation (not executed here)

In the pinned AOSP ARM64-only SDK-37 lunch environment, explicitly build:

```sh
m AndrixWebViewProbe
```

Before installation, hash/freeze the actual APK and inspect its manifest and
signer using pinned tools. Require the existing proof certificate, **not** the
platform signer; test-only self-instrumentation, sole `INTERNET` permission, SDK
37, non-exported Activity and no shared UID/native/third-party payload or
product inclusion. Independently bind observed provider package/version to the
qualified APK/library/config artifacts and candidate fingerprint.

Only the primary host runner/operator may establish an authorized device lease,
unlocked user 0, the intended provider, fresh ordinary `/data/app` installation
(`-t --user 0`, no replacement/grants) and capture **before** app/provider startup.
Refuse a pre-existing package or retained data in any user: a fresh profile
excludes old cookies, service workers/cache and cached certificate decisions.
No root adbd, policy relaxations, trust overrides or provider-setting changes
are part of this recipe. The following is only the instrumentation invocation,
not a safe-install/cleanup orchestrator; variables must come from reviewed host
fixture inputs, never shell-interpolated untrusted input:

```sh
: "${ANDROID_SERIAL:?explicit authorized device}"
: "${GOOD_URL:?canonical owned HTTPS 204 URL}"
: "${BAD_URL:?canonical owned wrong-host HTTPS 204 URL}"
: "${EXPECTED_PROVIDER:?exact qualified provider package}"
adb -s "$ANDROID_SERIAL" shell am instrument -w -r --user 0 \
  -e good_url "$GOOD_URL" -e bad_url "$BAD_URL" \
  -e expected_provider "$EXPECTED_PROVIDER" \
  dev.andrix.proof.webview/.WebViewProbeInstrumentation
```

Allow at least **1000 seconds** for the instrumentation command (four stages
plus cleanup can take 900 seconds). Preserve complete output, logs, fixture
DNS/TLS/server observations and external traffic capture, including failures.
Recheck device/package identity before removing only the acknowledged disposable
installation and verifying its removal; no blind uninstall/`pm clear`, global
WebView cleanup, or provider change. A hung Activity/process or lost install/
cleanup acknowledgement needs explicit host reconciliation. This APK destroys
its own WebView/Activity; it does not uninstall itself or erase provider data.

## Host-only URL regression checks (not executed here)

With a JDK, from the repository root; outputs stay outside source:

```sh
classes=$(mktemp -d)
javac -d "$classes" \
  tests/webview-probe/src/dev/andrix/proof/webview/ProbeConfig.java \
  tests/webview-probe/host-tests/ProbeConfigTest.java && \
java -cp "$classes" dev.andrix.proof.webview.ProbeConfigTest
# Remove only the temporary classes directory after retaining the result.
```

These tests only parse documentation-domain strings, without DNS/network,
Android, keys or ADB. They cover both URL arguments, canonical origin/ports,
missing provider and hostile/ambiguous input. They do not compile the Android
fixture or execute WebView. Primary verification still needs an SDK-37 build,
manifest/signer checks and authorized slow-QEMU runtime, including missing/
invalid args, wrong provider, non-204/redirect/offline positive controls,
non-hostname TLS failures, a distinct certificate-covered alias as `bad_url`
(which must fail/timeout, not pass), actual hostname rejection, Safe Browsing
callback observations and lifecycle/timeout cleanup.
