# WebView trust, recovery and package sessions

**Status:** historical direct-AOSP/Vanadium experiment. Focused trust/recovery checks
passed; the tested three-package rollback model failed and was not promoted. The
[split-cohort follow-up](2026-09-07-webview-cohort-rollback.md) addresses the dependency model.

## Distinct trust gates

Android PackageManager must reject an update with the wrong signer. Separately,
WebView's own configuration-signer gate must reject an untrusted configuration
package. PM rejection alone cannot exercise the latter path.

Use explicit negative-only candidates to test compiled trust decisions without
changing normal platform permissions or weakening package verification.

## Observed results — 2026-09-07

The bounded experiment exercised signer rejection and focused recovery controls.
A three-child rollback session did not provide the desired Trichrome behavior:
versioned static-library prerequisites are not interchangeable with ordinary consumer
APK updates. That failure motivated an explicit library/consumer transaction boundary.

## Remaining scope

A controlled package-session test is not a production updater, real-version migration,
power-loss or general recovery proof. See [reusable qualification fixtures](../tests/webview-qualification/README.md).
