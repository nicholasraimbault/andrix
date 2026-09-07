# Pinned Andrix AOSP adaptation

The current seventeen-file adaptation spans nine pinned projects in exact
`android-17.0.0_r1`. The original twelve files cover owned network endpoints,
inherited Google app-link registration and product-scoped package selection.
Five framework files additionally retain static-library dependencies needed by
Android rollback records. No supported resource hook covers that lifecycle bug.
These are not a substitute source distribution or an unrelated platform fork.
The official manifest/project HEADs remain at their pinned release commits;
`series.json` records each base commit and before/after file digest. The patch
and applied diff must accompany build provenance. A pristine manifest alone
no longer describes an image built with this adaptation.

## Changes and preserved behavior

- Rollback captures the old installed APK's exact static-library names/versions,
  stores them in the existing atomic rollback metadata and publishes an immutable
  internal snapshot. PM's normal uninstall/unused-library guard rejects removing
  a required version while its rollback is enabling, available or restoring.
  Startup load/publication precedes staged application and boot pruning; PM never
  waits on the rollback worker. State changes, completion, expiry and deletion
  refresh the snapshot. Metadata-write failures cannot advertise a newly enabled
  or available rollback. Signature/installation verification is unchanged, no
  fake client or privileged shim is added, and ordinary pruning remains enabled.
  See the [retention implementation/gates](../../plans/2026-09-07-rollback-retention.md).

- WallpaperPicker2 no longer registers Google's `g.co/wallpaper` verified link.
  The first connected candidate actually triggered a `g.co` lookup through
  domain verification. Only that Google intent filter is removed; wallpaper
  activities, local entry points and Android's verifier remain unchanged.
- Settings' default DSU catalogue is owned; its existing persistent owner URL
  override remains available. The experimental catalogue explicitly has no
  released Andrix GSI images. DSU installation, AVB and revocation checks are
  retained. Its revocation-list resource uses a normal product RRO, not a patch.
- The attestation library's status URL uses the owned public-data snapshot.
  Certificate-chain/status processing remains unchanged: no skipped revocation
  or invented validity. Public revocation data is not a signed CT bundle; the
  source fetch, byte identity and freshness must be recorded separately.
- Contacts directions use the existing `geo:` helper instead of selecting
  Google Maps HTTPS. Address encoding and owner-selected map handling remain.
- The media-product leaf keeps the stock `webview` unless both the exact Andrix
  Cuttlefish product and `ANDRIX_WEBVIEW_EXPERIMENT=true` are selected. The opt-in
  supplies the separately signed experimental provider/library/config packages;
  no stub, post-boot uninstall or silent provider replacement is used. Without
  the opt-in, stock provider membership is unchanged.
- The inherited handheld-product leaf omits `QuickSearchBox` only when
  `TARGET_PRODUCT` is `andrix_cf_arm64_only_phone`. Other products retain it,
  and no replacement search backend, dummy package or post-boot uninstall is
  introduced. Downstream filtering of `PRODUCT_PACKAGES` would operate on
  inheritance markers before this list is expanded, so the omission belongs at
  its source leaf. Launcher3's missing-provider path remains unchanged; actual
  launcher behavior still needs runtime verification.
- Native DnsResolver and NetworkStack Private DNS validation keep their random
  cache-bypassing nonce and DNS packet semantics, but query under
  `probe.andrix.org` instead of `metric.gstatic.com`. Native automatic/
  opportunistic DoT is included, not just NetworkMonitor's strict-mode check.
  TLS, certificate checking, validation outcomes, timeouts and UDP/DoT latency
  comparison are unchanged. The native test-server probe classifier follows
  the new suffix rather than silently failing to recognize validation traffic.
- Connectivity diagnostics keep ICMP checks to real gateways and supplied DNS,
  and UDP/DoT checks to configured resolvers. They no longer inject Google DNS
  addresses as extra targets; their nonce qname uses the owned domain too.
  Both `--diag` and high-priority diagnostic dumps can reach this code.
- Tethering continues to use upstream DNS whenever provided. If upstream DNS is
  absent, its fallback is empty instead of silently inventing Google resolvers.
  Pinned netd accepts an empty forwarder list and its `--no-resolv` dnsmasq
  instance clears prior dynamic forwarders. This is not an empty NTP list or
  a way to pretend a functioning resolver exists. The fixture must supply valid
  DNS; tethering without any upstream DNS cannot resolve names through that
  missing service. Tethering/IP forwarding and app/SELinux policy remain intact.

- Certificate Transparency keeps its enabled service, downloaded-key allowlist,
  RSA signature verification and log-list handling. Only its download prefix
  changes to `https://ct.probe.andrix.org/certificate_transparency/`. The
  [public Pages fixture](../../docs/ct-pages-fixture.md) serves the same staged,
  signature-verified data without a live upstream proxy. The earlier private
  prefix and its DownloadProvider failures remain recorded. No CT checks,
  signing keys, permissions or trust anchors are disabled/replaced.

The owned DNS zone/fixture must answer the nonce names appropriately, including
positive records when testing strict Private DNS. Replacing a qname is not
endpoint deployment, a successful encrypted-DNS check or runtime compliance.
No Google-address firewall/DNS blackhole, TLS-disable flag, privileged proxy,
permission relaxation, foreign libc or kernel substitution is introduced.

Google DoH upgrade table entries are not unconditional destinations: they match
explicitly selected DNS IPs/hostnames. A controlled fixture must not supply
Google DNS. Connect-only route/MTU address literals are separately reviewed,
not blindly treated as sent packets or modified to game a string scan.

## Explicit application

Check first (read-only):

```sh
python3 scripts/proof/aosp_patches.py --aosp-root "$AOSP_ROOT"
```

Apply only to the reviewed tree, recording a **new** evidence directory outside
source. This writes the declared working-tree files, not project HEADs/indexes:

```sh
python3 scripts/proof/aosp_patches.py --aosp-root "$AOSP_ROOT" \
  --apply --evidence-dir "$ANDRIX_EVIDENCE/endpoint-patch-application"
```

The helper checks manifest/project revisions, exact source/patch digests,
contained paths, no staged/untracked/unrelated changes, and `git apply --check`
before one application transaction. Known applied state is idempotent; partial
or unexpected state fails closed. When extending a series, first verify and
archive the previous applied series. For a replacement, reverse only that exact
known patch, check its pristine state, then apply the new series. A strictly
additive extension may instead modify only new files whose exact base bytes
were checked, retain every old applied file, then verify the complete expanded
series. Record that transition; do not bypass the partial-state guard or
restore over unrelated work. Do not use `--reject`, force-sync, replace
source revisions, or restore over unknown edits to make it pass. Preserve the
first failure and inspect any failed post-application state.

Build and test the adapted modules/image, re-run the packaged-artifact oracle,
and record actual image contents. Static patch tests do not prove Android
execution, TLS validation or absence of runtime destinations. Host launch must
still use TAP, valid preconfigured interfaces and explicit fixture RIL/DHCP DNS;
QEMU SLIRP's other hardcoded DNS defaults are not an allowed shortcut.
