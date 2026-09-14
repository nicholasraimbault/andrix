# Isolated Vanadium WebView build experiment

**Status:** historical, separately selected WebView build experiment. It did not
adopt a second platform base or authorize production-provider replacement. The
[GrapheneOS foundation](2026-09-08-grapheneos-migration.md) is now the adopted path.

## Scope

Build an ARM64-only TrichromeWebView, its matching library and configuration package
from an exact Vanadium/Chromium generation. Keep experimental package identities and
signing distinct from production identities. Preserve upstream patch ordering and
record attributable downstream changes.

## Verification

- Authenticate source and package relationships before building.
- Inspect actual APK manifests, ABI, signatures, DEX/native dependencies and payloads.
- Do not treat an APK filename or a successful compile as runtime compatibility.
- Keep platform trust, permission policy and provider selection unchanged until a
  separately scoped installation/runtime test justifies promotion.

See [Vanadium assessment](../docs/vanadium-assessment.md) and
[experimental inputs and tooling](../experiments/webview/README.md).
