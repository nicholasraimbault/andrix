# Isolated WebView APK checks

Host-only, read-only with respect to inputs. No build, signing, installation,
ADB, network access or private key input. Requires Python 3.10+ (stdlib SSL)
and explicit pinned `aapt2` / `apksigner` executables. Example placeholders,
**not observed artifacts or selected package names**:

```sh
python3 -B scripts/proof/webview_artifacts.py \
  --webview-apk /isolated/output/TrichromeWebView.apk \
  --library-apk /isolated/output/TrichromeLibrary.apk \
  --config-apk /isolated/output/VanadiumConfig.apk \
  --webview-package dev.example.webview \
  --library-package dev.example.trichromelibrary \
  --config-package dev.example.config \
  --expected-cert /public/experiment-certificate.pem \
  --aapt2 /pinned/tools/aapt2 --apksigner /pinned/tools/apksigner \
  --evidence /external/evidence/NEW-webview-check
```

Supply **one public X.509 certificate PEM**, not a private key, public-key-only
PEM or certificate chain. All three APKs must verify with that certificate's
DER SHA-256. There is no platform-signer requirement or exclusion.

The new evidence directory must be outside this checkout. It retains APK
snapshots (allow space for all three), the public certificate, numbered raw
stdout/stderr and command JSON, and `summary.json`, including failures after
preflight. Input/snapshot hashes are compared before and after inspection;
stop the producer and use stable artifacts, not outputs being rebuilt. Nothing
is overwritten, installed or cleaned up. Exit 0 means **only the scoped static
checks passed**; nonzero means failure. Do not interpret partial evidence as a
pass.

Checks cover single-signer container verification (`apksigner verify --Werr`),
package/version/SDK agreement between binary-manifest XML tree and badging,
application-level literal `WebViewLibrary` metadata, one static-library
namespace/version/certificate pin matching the library declaration and signer,
and the named native payload's presence in the library APK. ZIP paths, native
ABI badging and ELF class/endianness/machine/type headers must agree on ARM64
ET_DYN shared-library payloads; Java/resource-only APKs may have no native
entries. Recognizable ELF or `.so` payloads outside `lib/arm64-v8a/` are rejected.
Binary manifest/native payload hashes, tool launcher hashes/version output and
checker source hashes are saved.

The sole non-ELF exception is the **exact zero-byte regular ZIP entry
`lib/arm64-v8a/libplaceholder.so` in the WebView APK role only**. In the
[pinned Chromium 152 experiment](../../plans/2026-09-06-webview-build-experiment.md),
`build/android/gyp/apkbuilder.py` writes `native_lib_placeholders` as empty ZIP
entries (lines 501–507 in the patched experiment tree); Trichrome WebView uses
the static-library APK for real native code. The checker records this entry's
path, size and SHA-256 under `archive.abi_markers`, never `native_libraries`.
`native_abis` includes `arm64-v8a` for this marker, so badging must still agree.
The marker is forbidden in Library/Config roles, at other paths/ABIs, as a
directory or with any contents (even a valid ELF). Arbitrary empty `.so` files
remain rejected. The low-level `check_archive(apk)` stays strict; the exception
requires explicit `role="webview"`. All actual native payloads still require
ELF64 little-endian AArch64 ET_DYN v1 headers, never ET_EXEC. An ABI marker
cannot satisfy the `WebViewLibrary` payload requirement in the TrichromeLibrary
APK.

This intentionally supports the single-signer, unsplit, positive-int32-version
experiment, not arbitrary Android packaging. Both legacy `Signer #1` and AOSP
17 scheme-labelled signer output, and both aapt2 attribute/SDK spellings are
handled. Multiple signer/rotation/stamp records, additional static-library
certificates, resource-valued trust metadata, major versions, malformed or
unrecognized security-relevant output, and unexpected tool stderr fail closed.
The sole stderr exception is a standalone recognized `aapt2 version` row with
empty stdout, matching the pinned AOSP tool. Review a new tool format against
its exact public source/raw evidence rather than weakening parsing to force a
pass. Tool launcher hashes do not identify Java/JAR/shared-library or other
transitive toolchain inputs.

For the AOSP shell launcher on JDK25, a pinned wrapper may pass
`-J-enable-native-access=ALL-UNNAMED` to `apksigner` so its Conscrypt native loader
has explicit JVM permission. Do not filter diagnostics out of captured output.
This changes the host Java invocation, not APK/TLS verification policy.

**Compiled ConfigInfo trust remains UNVERIFIED even on exit 0.** A valid Config
APK signature does not prove WebView's compiled expected config package or
certificate. Final build review must inspect generated ConfigInfo, source/build
inputs and their relationship to these exact artifact paths. No strings scan
is used as proof. This also does not qualify ELF linking/alignment/CFI/MTE,
sandboxing, provider integration, updates/rollback, rendering, runtime config,
TLS/CT or no-Google behavior; it grants no installation or promotion authority.

Host-only synthetic tests (including a marker-only WebView plus a native
TrichromeLibrary fixture; all subprocesses mocked, no real APK signatures):

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p test_webview_artifacts.py
```

The primary also exercised pinned real aapt2/apksigner output using three tiny
signed manifest fixtures and a cross-compiled ARM64 shared library. Those are
verifier fixtures, **not Vanadium or usable WebView providers**. The first
version-query stderr rejection was preserved before the narrow parser repair.
The first signed Trichrome152 output check also retained FAIL on WebView's exact
empty ARM64 `libplaceholder.so`; the ABI-marker exception does not retroactively
change that result. The repaired checker still requires a fresh evidence run on
the actual experiment APKs, not a fixture-based qualification.
