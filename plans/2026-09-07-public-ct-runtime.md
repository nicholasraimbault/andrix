# Public CT delivery comparison

**Status:** the direct-AOSP experiment demonstrated CT download, signature validation
and installation through the public fixture, alongside bounded WebView HTTPS and
hostname-rejection controls. This is not complete privacy or supported-phone assurance.

## Controlled change

Change only the declared CT delivery URL between the compared candidates. Preserve
upstream source pins, CT keys/signature checks, update scheduling, permissions and
provider packages. Reconstruct and verify the exact adapted source rather than
stacking an unreviewed patch onto a working tree.

## Verification boundary

Separate server reachability, TLS trust, freshness validation and installation.
Retain a failed delivery as a failure; absence of traffic alone does not prove a
working security consumer. Use actual guest behavior rather than a host HTTP client
as the Android result.

See [CT fixture instructions](../docs/ct-pages-fixture.md),
[WebView qualification](2026-09-07-webview-qualification.md) and the
[current architecture](../docs/architecture.md).
