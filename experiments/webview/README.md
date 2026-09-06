# Isolated WebView build inputs

The [approved experiment](../../plans/2026-09-06-webview-build-experiment.md)
builds ARM64-only WebView/shared/config APKs outside the AOSP checkout. It does
not register, install or release a new provider. `inputs.json` records the
chosen upstream revisions, targets, experimental package identities, public
signer fingerprint and frozen filter-input manifest hash. Private keys and raw
build evidence are not repository inputs.

Preparation has fetched the pinned Chromium source/dependencies, applied all
309 primary plus five subproject patches without skips, staged 23 public list
URLs into 21 outputs, and completed dependency hooks. Hook control uses a
separate gclient file: upstream automatic patch abort/skip and live list hooks
are not run. Their reviewed work is performed explicitly and recorded.

The experimental GN arguments retain the upstream security settings, change
package identities/public certificate pins, and set `use_remoteexec=false`.
ThinLTO rejects an explicit `concurrent_links` override; the first failure is
retained and the corrected generation uses Chromium's memory/CPU-derived pools,
not an LTO/CFI disable. GN generation passed with unused arguments rejected.
The compiler is invoked for the three declared targets with eight local jobs
and `--offline`; a start or graph-generation pass is not an APK build pass.

The [artifact checker](../../scripts/proof/webview_artifacts.md) verifies
container signatures, actual manifest/static-library relationships and ARM64
packaging. Its mocked regressions and a separate real-tool fixture run passed;
those fixtures are deliberately not WebView providers. Compiled ConfigInfo
trust, complete ELF/hardening analysis and actual experiment artifacts remain
separate checks. No static result authorizes provider promotion or runtime use.
