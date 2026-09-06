# Phase 1 network preparation

Scope: the exact `android-17.0.0_r1` ARM64 Cuttlefish proof. This is not a
production-service selection or a runtime no-Google claim. The current candidate
has been rebuilt and inspected offline; **P3 endpoint review and runtime fixture
qualification are not complete**. See [current work](../plans/current.md).

## Implemented controls

Only the Cuttlefish product includes these image controls; they are not future
physical-phone defaults. Android identities, Bionic, TLS, SELinux and image/APEX
verification remain intact.

### Local keys without remote provisioning

`andrix-cuttlefish-network.rc` sets `remote_provisioning.tee.rkp_only=false` and
clears `remote_provisioning.hostname` at `early-init`. The inherited product
property text is not erased: it is overridden before consumers. Pinned init
loads properties and system-ext scripts before `early-init`. Existing property
permissions allow this without a policy change. RKPD's empty default URL stops
scheduled/on-demand provisioning and keystore2 permits local keys when RKP-only
is false. The device proof checks actual values; boot execution remains unproved.

### Preinstalled product overlays

| Module | Target and inputs |
| --- | --- |
| `AndrixCuttlefishNetworkStackOverlay` | `com.android.networkstack` / `NetworkStackConfig`: HTTP/HTTPS strings, both URL arrays and nonempty HTTP fallback array select `probe.andrix.org/generate_204`. |
| `AndrixCuttlefishConnectivityOverlay` | `com.android.connectivity.resources` / `ServiceConnectivityResourcesConfig`: the legacy `config_networkCaptivePortalServerUrl` selects the same HTTP endpoint. |
| `AndrixCuttlefishFrameworkOverlay` | `android`: `config_ntpServers` contains `ntp://probe.andrix.org`. Android's SNTP client and timeout/polling behavior are unchanged. An HTTPS 204 server is not an NTP server. |

All use the pinned platform's built public SDK (`current`, API 37), product
installation and static priority 999. Both probe strings and arrays are needed:
NetworkMonitor's nonempty arrays override provider/additional URLs, while
strings cover fallback paths. Empty fallback arrays select Google defaults.
Do not overlay non-overlayable `default_*` resources or use invalid URLs/lists.

The framework defines no named overlayable set in r1. Native idmap's normal
preinstalled-product policy therefore permits its NTP resource; no target name,
platform signer or enforcement bypass is needed. All three signed APKs are in
the rebuilt product image, with SDK/min/target 37. Offline idmap generation
against image-extracted target APKs maps all seven resources with checks enabled.
This does not prove runtime activation, MCC selection or precedence.

## Necessary pinned source adaptations

Some remaining destinations have no configuration hook. The narrowly scoped
[seven-file patch](../patches/android-17.0.0_r1/README.md) records exact base project
commits, source digests and applied digests. `aosp_patches.py` verifies them and
records explicit working-tree changes without moving any AOSP project HEAD.
The baseline manifest **plus this patch**, not a pristine manifest alone,
describes the adapted build.

- Native DnsResolver validates DoT with a cache-bypassing nonce qname even in
  default **opportunistic** mode. Successful DoT validation can also send that
  qname via UDP for latency comparison. NetworkMonitor separately probes in
  strict mode. Both now use `*-dnsotls-ds.probe.andrix.org`; protocols, randomness,
  TLS behavior, validation and latency logic remain unchanged. The native test
  responder recognizes the new suffix. Compiled-source wire-format checks
  verified native AAAA and diagnostic A packets without sending DNS traffic.
- `NetworkDiagnostics` is reached by `--diag` and high-priority connectivity
  dumps, not only ordinary dumps. It no longer injects Google DNS4/DNS6 as extra
  targets. Router/configured-DNS ICMP, UDP and DoT checks remain; its nonce name
  is now `*-android-ds.probe.andrix.org`.
- Tethering uses upstream DNS normally. An upstream with no DNS no longer
  silently selects Google's resolvers. Pinned netd accepts empty forwarders and
  its `--no-resolv` dnsmasq clears old dynamic entries. This is not a functioning
  resolver by itself: the fixture must supply valid DNS. Tethering and routing
  are not disabled, and no substitute public provider was invented.
- The Certificate Transparency updater runs after boot by default on this
  release. Its fixed download prefix now points to
  `https://probe.andrix.org/certificate_transparency/`. The service remains
  enabled, with its original allowed signing keys, RSA signature checks and
  log-list handling. The fixture serves separately staged, signature-verified
  public data rather than forwarding device requests to Google. No CT/TLS
  checks, trust anchors or signing keys are replaced.

The rebuilt image's NetworkStack dex contains the owned Private DNS suffix;
its connectivity service dex contains the owned diagnostic suffix and CT URLs,
not the old CT prefix. Source/project state and image identities are recorded
with the offline checks. Android execution remains unproved.

## Do not confuse literals, defaults and actual traffic

- Cuttlefish `--ril_dns` defaults to Google. Supply an explicit private fixture
  resolver and verify a valid mobile bridge/TAP first. The r1 failed-interface
  path ends with unusable empty fields; it is not a safe fallback.
- QEMU SLIRP has independent hardcoded DNS for its virtual interfaces. The proof
  profile uses native crosvm/TAP instead. Set usage statistics explicitly to `n`;
  the generated config must record metrics enum `No`, not `Unknown`.
- Private DNS's Google DoH upgrade table matches selected IPs/hostnames. Do not
  supply Google DNS from RIL, DHCP, RDNSS, VPN or a strict-hostname setting.
- The old framework `config_default_dns_server` literal has no identified r1
  consumer in the examined network paths. NetworkStack's actual DHCP fallback
  array is empty; the fixture must offer valid DNS rather than depend on it.
- CLAT and source-address selection use some Google-address literals in UDP
  connect/route-MTU lookups without send/write. They are not demonstrated DNS
  queries or packet-based PMTU probes. Do not change non-traffic literals just
  to make a string scan empty.
- Normal Private DNS remains enabled. Do not rely on TLS failing, switch it off,
  blacklist Google addresses, or synthesize successful Google DNS/HTTP responses
  to force a pass. The controlled resolver must log real attempted queries.

## Bundled search omission and remaining app review

QuickSearchBox is now omitted from the Andrix Cuttlefish package graph, installed
inventory and actual product image. The owning inherited Makefile excludes it
only for `andrix_cf_arm64_only_phone`; the stock and other product package sets
are preserved by a pinned-leaf Make regression test. No app stub, search-server
replacement or post-boot uninstall was introduced.

Launcher3's source permits no active search provider: `OSEManager` handles a
missing/disabled package and its fallback resource is empty. The existing widget
fallback can show unavailable search and a blank-browser intent; no new search
UI was built. Launcher and WebView APKs remain byte-identical to the prior
candidate. Runtime/visual behavior still needs the actual boot proof.

A broader image scan also found Google URL literals in other bundled apps. They are
not all background requests: help links, map intents, XML metadata namespaces
and user-selected diagnostics differ from automatic service connections.
The following still require complete source/condition/control disposition:

- The bundled WebView is the tag's prebuilt `145.0.7632.218`. Its variations
  service contains Google seed URLs; the matching Chromium source describes
  scheduling after WebView requests a seed. Its presence is not proof of a
  boot-time request, but WebView use cannot be silently declared safe or disabled
  to avoid the review. The [pinned Vanadium and same-base Chromium review](webview-review.md)
  distinguishes source-only seed controls from a candidate AOSP component-default
  mechanism. No alternate WebView, component-state change or source substitution
  was made.
- Device diagnostics, IMS entitlement, dynamic-system installation, captive
  portal fallback and other manual/conditional links need attribution to the
  selected proof profile. No blanket no-Google clearance follows from removing
  only the first detected endpoints or from a prohibited-package-name scan.

These open checks are why the current candidate is not yet P3-cleared or ready
for an unqualified first boot.

## Controlled services and capture

The public-CA certificate for `probe.andrix.org` was issued through DNS-01 and
verified against the built Conscrypt APEX's CA bundle. The bounded
[probe service](../scripts/proof/probe_server.md) passed real loopback HTTP/HTTPS
204, wrong-hostname rejection, exact signed CT-file responses, HTTPS-only CT
access and clean signal shutdown checks. This is not an Android-client or
public-endpoint test. No public listener remains on the build/signing host.

CT data is staged offline from its disclosed public source and checked against
the target APK's unchanged key allowlist; the server has no live upstream proxy.
The snapshot must remain inside the pinned 70-day freshness window. The HTTPS
certificate and DNS/NTP time source also require freshness/accuracy checks.
Private keys, credentials and raw captures remain outside published Git.

The [runtime fixture procedure](runtime-fixture.md) prepares private DNS/DoT,
valid NTP, HTTP(S)/CT services, explicit TAP/RIL configuration and capture before
assembly/boot. Host-side configuration/parser checks are not qualified hardware
or network results. Every attempted destination, including blocked and failed
ones, must be explained before any runtime claim.
