# Historical connected candidate

**Status:** useful direct-AOSP emulator results, not complete network-policy or
release qualification. The adopted foundation is now [GrapheneOS](2026-09-08-grapheneos-migration.md).

## Result

The candidate preserved Android/Bionic execution and the authenticated `/usr`
boundary while exercising the experimental WebView stack. A source-level unwanted
request was corrected, but CT delivery still failed. A workload without an observed
prohibited destination is not a pass when a required security update did not complete.

## Follow-up

Use the [public CT delivery comparison](2026-09-07-public-ct-runtime.md) for that
specific delivery path. Keep endpoint reachability, certificate/hostname checks,
configuration trust and conditional application behavior distinct. No broad TLS,
permission or security-consumer relaxation is justified by a fixture failure.

The [accepted networking policy](../docs/architecture.md) governs current work.
