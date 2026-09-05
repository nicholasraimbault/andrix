# Phase 1 network preparation

Scope: the exact `android-17.0.0_r1` Cuttlefish proof, not a public-service
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

## Other endpoint controls: mapped, not yet configured

| Consumer | Pinned control and requirement |
| --- | --- |
| NetworkStack `NetworkMonitor` | RRO targeting `com.android.networkstack`, `NetworkStackConfig`. Set non-empty `config_captive_portal_http_url`, `config_captive_portal_https_url`, both `*_urls` arrays, and `config_captive_portal_fallback_urls`. Arrays take precedence over provider/additional URLs; strings also cover exception/legacy fallback paths. Empty fallback configuration still selects Google defaults. |
| ConnectivityService legacy API | RRO targeting `com.android.connectivity.resources`, `ServiceConnectivityResourcesConfig`, with non-empty `config_networkCaptivePortalServerUrl`. The existing hook wins over Settings and the Java Google constant; a code patch is not needed for that URL. |
| Network time | Framework `config_ntpServers` must contain valid `ntp://host[:port]` entries. Empty lists throw; malformed URIs are not an acceptable way to disable traffic. The exact overlay/idmap mechanism still needs a compiled test. |
| DHCP/default DNS | NetworkStack's `config_default_dns_servers` is a DHCP fallback hook, not a reason to choose a public resolver. Configure and inspect the actual fixture's offered DNS servers. The legacy framework resource `config_default_dns_server=8.8.8.8` alone does not establish an active consumer in this revision. |
| Cuttlefish host | Review actual launch configuration, including RIL/network DNS and usage-statistics controls, before launch. Host package provenance does not imply safe defaults. |

The NetworkStack `default_*` resources are deliberately not overlayable.
Change the supported `config_*` hooks, not those defaults. MCC-specific Google
defaults also need to be excluded by effective configuration. Do not use
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

## Decision needed: valid HTTPS probe trust

A self-contained fixture can provide private DNS, NTP and HTTP(S) 204 responses.
But the HTTPS service must have a chain and hostname the Android client
actually validates. No owner-controlled hostname/certificate or new trust
policy has yet been selected.

The least invasive choice is an **owner-controlled probe hostname with a
certificate trusted by the existing Android store**. Its DNS can direct the
lab guest to the controlled fixture; it need not become a public Andrix
service or a third-party connectivity backend.

If that is unavailable, an alternative requiring explicit approval is a
**lab-only CA restricted to NetworkStack's fixture domain** through its network
security configuration. That would require a narrowly related APK manifest/
resource change, not a global CA addition, trust-all client, TLS-disable flag,
or a decision about official/owner release signing. Private keys must remain
outside Git and communication channels; no such key has been generated here.

Do not casually place a CA under `/system/etc/security/cacerts`: r1 Conscrypt
and Network Security Config normally choose the nonempty
`/apex/com.android.conscrypt/cacerts` store instead. Emptying that store merely
activates the system fallback. Do not strip Google-named trust anchors: trust
anchors are not network destinations, and non-Google sites may use those
chains. Existing TLS verification must be preserved.

Until the endpoint/trust choice is explicit, do not invent public providers,
add a CA, disable validation, or call the image ready for paid runtime testing.
