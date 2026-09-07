# Connected no-Google candidate

The owner authorized advancing the working ARM64 prototype toward no-Google
operation, including the WebView candidate and controlled online evaluation.
This extends the isolated build experiment to an **opt-in test image**, not a
supported release or production signing/update decision. The old image and APKs
remain frozen. No cloud purchase, unrelated DNS change or public listener on the
build/signing host is included.

## Candidate inputs

The original Vanadium/Chromium pins remain unchanged. The explicit six-file
[derivative policy](../experiments/webview/policy-inputs.json) is applied after
all upstream patches:

- Reuse upstream `FIELDTRIAL_SEED_ENABLED=false` in the WebView fetch scheduler,
  direct scheduling entry and job execution, including cancellation of old jobs.
  Keep service declarations and general SafeMode/local recovery actions intact.
- Use `probe.andrix.org` for the custom Chromium DNS probe name, without choosing
  Google's standard mode or disabling validation. This is a query name sent to
  the selected resolver, not an HTTP 204 or a new DoH server implementation.
- Include the corresponding Java JNI dependency in WebView. The baseline
  mapping did not contain `ConnChecksUtil`; the rebuilt mapping now does.
- Remove the Safe Browsing success shortcuts and the config row enabling them.
  Retain the normal platform-bridge initialization and native allowlist path.
  An unavailable checking backend must not be represented as protection; a
  successful local allowlist operation is not a URL-checking verdict either.

The policy build completed successfully with CFI/ThinLTO retained. Its three
APKs were signed by the existing disposable experiment key and passed the
signature/manifest/static-library/ARM64 checks. Their identities are recorded
in [candidate.json](../experiments/webview/candidate.json). Compiled config
consumption, rendering, TLS, sandbox and connected runtime behavior still need
qualification. No compiler/header check alone clears those gates.

Real Trichrome packaging exposed one verifier assumption: the WebView APK
contains a zero-byte `lib/arm64-v8a/libplaceholder.so` ABI marker while its real
native code is in the shared-library APK. The checker now records only that
exact empty WebView-role marker separately; it cannot satisfy a native-library
requirement or weaken actual ELF validation. The first failure is preserved.

## Explicit image selection

Stage the three exact signed APKs from `candidate.json` under the ignored
`experiments/webview/prebuilts/` directory in the build overlay. Do not commit
APKs/private keys or silently fetch a different version. Recheck hashes and
signatures before building.

```sh
export ANDRIX_WEBVIEW_EXPERIMENT=true
# Use the existing pinned lunch/build procedure and record the producer revision.
m droid hosttar AndrixWebViewProbe AndrixP5OrdinaryApp
```

The opt-in enables three presigned/preprocessed product imports and a normal
product-policy provider-list RRO. Preprocessed APK checks stay enabled. It
retains AOSP's WebView loader/support libraries and pins the experimental public
certificate in the provider list. The owning `media_product.mk` condition omits
the stock provider only for this exact product plus the explicit opt-in.
Without it, the previous product remains independently buildable and unchanged
in provider selection. No hidden-API or overlayability bypass is introduced.

## Connected test requirements

Use fresh copies and a separately attributable rootless network namespace with
real Internet egress. QEMU keeps its TAP backend. A separately configured
`slirp4netns` uplink does not inject QEMU SLIRP's hardcoded DNS; its implicit DNS
proxy is disabled and the guest gets the controlled resolver explicitly.
Rootless NAT and a real hostname-verified HTTPS request have been exercised on
the host; that is not an Android result.

Before boot, prepare and test real DNS/DoT, synchronized NTP, hostname-valid
HTTP(S) 204 and the unchanged signed CT data. Keep TLS service keys separate
from the VM's filesystem, and product signing keys outside both. Capture before
assembly/boot, including resolver/upstream service traffic. No Google-address
filter, fake response, invalid endpoint, TLS/CT disable or permissive policy may
be used to manufacture success.

Use the optional [ordinary WebView probe](../tests/webview-probe/README.md) for
provider identity, JavaScript, a real HTTPS 204 and an explicit wrong-hostname
TLS rejection. Record renderer/sandbox behavior separately. Exercise boot,
idle, normal WebView use, available recovery/job paths and updates with full
traffic attribution. Repeat the APEX/`/usr` and ordinary-app checks on the new
image. Keep emulation and native hardware qualifications distinct.

## Remaining conditional-app work

The source review identifies automatic Google revocation-list requests during
DSU installation and device-diagnostic attestation-result verification. Preserve
those security checks while arranging valid owned data delivery; do not skip
revocation. IMS/FCM depends on actual carrier configuration and must be checked.
Explicit Contacts/Dialer browsing intents differ from background clients, but
must be documented rather than silently called harmless. These findings and the
online workload results bound any eventual no-Google claim; no blanket pass is
recorded here.
