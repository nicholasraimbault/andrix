# Phase 1 network preparation

Scope: the exact `android-17.0.0_r1` Cuttlefish proof, not a DNS/NTP upstream
selection or production trust policy. Live results are in
[current work](../plans/current.md). No runtime no-Google claim follows from
this source review or the host tests.

## Implemented: no remote key-provisioning endpoint

Only the Cuttlefish product includes `andrix-cuttlefish-network.rc`. During
`early-init` it sets `remote_provisioning.tee.rkp_only=false`, then clears
`remote_provisioning.hostname`. This does not remove the inherited text from
`product/build.prop`; it overrides the effective boot configuration before
consumers start. The device proof requires both resulting property values.

The pinned source supports this state:

- `system/core/init/init.cpp`: `PropertyInit()` precedes `LoadBootScripts()`,
  which imports `/system_ext/etc/init`, before queuing `early-init`.
- `system/sepolicy/private/init.te` already allows init to set properties;
  `property_contexts` defines the hostname as a string and RKP-only as a bool.
  No SELinux allow rule is added.
- `packages/modules/RemoteKeyProvisioning/app/.../utils/Settings.java` returns
  an empty default URL for an empty hostname. `PeriodicProvisioner` cancels
  work, and `RemoteProvisioningService` reports unsupported, before network
  provisioning when the default URL is empty.
- `system/security/keystore2/src/remote_provisioning.rs` permits local key
  handling when RKP is disabled and RKP-only is false. Leaving RKP-only true
  would instead cause a permanent out-of-keys error for that path.

These are source/control checks, not evidence that the new boot actions have
run. Android image/APEX verification and app execution policy remain intact.

## Implemented in source: Cuttlefish HTTP(S) probe URLs

Only `products/andrix_cf_arm64_only_phone.mk` includes the two RROs under
[`overlays/cuttlefish`](../overlays/cuttlefish). They are not included by the
generic `andrix.mk` or intended as a future-phone default. Both use the pinned
platform's built public SDK (`sdk_version: "current"`, API 37 in the selected
release), the repository license and `product_specific: true`, with static
manifest priority 999 (the maximum). They add no custom signing configuration, AOSP patch,
SELinux rule or trust change.

| Module / pinned target | Configured resources |
| --- | --- |
| `AndrixCuttlefishNetworkStackOverlay` / `com.android.networkstack`, `NetworkStackConfig` | `config_captive_portal_http_url` and the singleton `config_captive_portal_http_urls` array use `http://probe.andrix.org/generate_204`. `config_captive_portal_https_url` and the singleton `config_captive_portal_https_urls` array use `https://probe.andrix.org/generate_204`. The nonempty `config_captive_portal_fallback_urls` array uses the same HTTP URL. |
| `AndrixCuttlefishConnectivityOverlay` / `com.android.connectivity.resources`, `ServiceConnectivityResourcesConfig` | `config_networkCaptivePortalServerUrl` uses the same HTTP URL for the ConnectivityService legacy API; this hook wins over Settings and the Java Google constant. |

NetworkMonitor's nonempty arrays take precedence over provider/additional URLs;
strings also cover exception/legacy fallback paths. An empty fallback array
would still select Google defaults. Only supported `config_*` hooks are changed,
never the non-overlayable `default_*` resources.

Both RROs compile in the pinned product with SDK/min/target 37, and their APK
signatures and packaged resource values were inspected. Host `idmap2` mapped
all six hooks against the built target APKs using the `product` policy, with
normal overlayability checks enabled. A public-policy-only negative check
rejected the NetworkStack overlay. These are static checks, not activation or
precedence observations on Android.

The existing image bytes are unchanged by this module-only build: the new RROs
are not yet baked into a rebuilt image. Full image integration and runtime proof
must confirm effective URLs (including fallback/MCC paths), successful HTTP(S)
204 responses and normal certificate validation, with external egress capture.
Configured source URLs are not a no-Google network pass.

## Other endpoint controls: mapped, not yet configured

| Consumer | Pinned control and requirement |
| --- | --- |
| Network time | Framework `config_ntpServers` must contain valid `ntp://host[:port]` entries. Empty lists throw; malformed URIs are not an acceptable way to disable traffic. The exact overlay/idmap mechanism still needs a compiled test. |
| DHCP/default DNS | NetworkStack's `config_default_dns_servers` is a DHCP fallback hook, not a reason to choose a public resolver. Configure and inspect the actual fixture's offered DNS servers. The legacy framework resource `config_default_dns_server=8.8.8.8` alone does not establish an active consumer in this revision. |
| Cuttlefish host | Review actual launch configuration, including RIL/network DNS and usage-statistics controls, before launch. Host package provenance does not imply safe defaults. |

No DNS or NTP upstream is selected by the probe overlays. MCC-specific Google
defaults still need to be excluded by effective configuration. Do not use
firewall rejection, invalid URLs or disabled HTTPS validation to force a pass.

## Distinguish hardcoded addresses from actual traffic

- `NetworkDiagnostics` adds Google DNS addresses for explicit
  `dumpsys connectivity --diag` probes. Ordinary connectivity dumps are not
  the same invocation. It is not a boot resolver setting; that diagnostic
  remains a separate Google-directed path requiring disposition.
- `NetworkMonitor` strict Private DNS probes use
  `-dnsotls-ds.metric.gstatic.com` in both synchronous and asynchronous paths.
  The source gates these on strict-mode hostname configuration. Do not claim
  they are boot traffic without observing the selected mode, or omit them
  from the review if strict DNS is exercised.
- `ClatCoordinator` passes `8.8.8.8` to native `detect_mtu`. The pinned native
  implementation connects a UDP socket, reads `IPV6_MTU`, and closes it; it
  contains no send/write. This is a route-MTU lookup, not a demonstrated
  packet-based PMTU probe or DNS query. Do not infer Google traffic solely
  from the literal address.

Full component/endpoint review and external destination capture remain
required. This table is not a blanket clearance of unexamined paths.

## Owned-domain HTTPS probe: provisioning pending

The owner selected **self-hosting `probe.andrix.org` with a certificate trusted
by the existing Android store**. The configured paths must serve HTTP(S) 204
responses, without redirects or a response body. A public-CA certificate has
been issued through DNS-01 and its hostname/chain verified with OpenSSL against
the trust anchors extracted from the built r1 Conscrypt APEX. An ephemeral
loopback fixture also returned empty HTTP and HTTPS 204 responses; its TLS
client used that CA bundle, rejected a wrong hostname, and kept normal TLS
verification enabled. All test listeners were closed. This is not an Android-
client handshake or a deployed endpoint. Endpoint addressing/deployment and
image validation remain pending; they are not supplied by these RROs. This does
not select DNS/NTP upstreams or a third-party connectivity backend, nor require
a general public Andrix service.

The HTTPS service must present a chain and hostname the Android client actually
validates. Domain ownership alone is not a deployed or validated endpoint. No
private CA, network security configuration override or TLS-disable option is
selected. Credentials and certificate private keys stay with the operator,
outside Git and communication channels.

Do not casually place a CA under `/system/etc/security/cacerts`: r1 Conscrypt
and Network Security Config normally choose the nonempty
`/apex/com.android.conscrypt/cacerts` store instead. Emptying that store merely
activates the system fallback. Do not strip Google-named trust anchors: trust
anchors are not network destinations, and non-Google sites may use those
chains. Existing TLS verification must be preserved.

Until the owned-domain endpoint and certificate are provisioned and validated,
do not invent public providers, add a CA, disable validation, or call the image
ready for paid runtime testing.
