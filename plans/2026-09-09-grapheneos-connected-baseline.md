# GrapheneOS connected baseline — bounded diagnostic trial

## Scope and authority

The owner approved continuing the endpoint/update inventory and a bounded connected
emulator test; the Pixel is not connected and is excluded. Use the
[accepted direct-client networking policy](../docs/architecture.md), genuine
GrapheneOS provisioning paths, existing hardware and the exclusive heavy-work
lease. No new public service, production key, vendor terms or handset action is
approved here. Silvervine is out of scope.

This is a **diagnostic baseline**, not a promise that every reachable feature
already satisfies release policy. A known WebView recovery path remains open
below. No Google-IP denylist, DNS blackhole, fake successful client or disabled
security consumer may manufacture a quiet capture. Unexpected traffic and failures
remain evidence, not results to discard.

## Reviewed producer and defaults

Start with frozen image/host inputs from `108d8574dcfc9a09bb29977e67d694e82c94d758`;
no old AOSP platform patch series or experimental 152 APK is silently substituted.
Keep the source producer separate from the new host observer.

| Area | Inspected selection | Qualification still needed |
| --- | --- | --- |
| Connectivity checks | `ConnChecksSetting` defaults 0; `NetworkMonitor` selects GrapheneOS HTTP/HTTPS and GrapheneOS fallback URLs. Compiled NetworkStack resources corroborate those choices. | Runtime effective setting, DNS and real validation. Standard Google values remain a separately selectable path. |
| Private DNS probes | Native `DnsTlsTransport` and Java `DnsUtils` select `dnscheck.grapheneos.org` by default; disabling connectivity checks does not silently disable DNS validation. | Actual resolver traffic and all guest network DNS configuration. |
| Time | `NtpTrustedTime.forceRefreshLocked` selects HTTPS; compiled `config_httpsTimeUrls` points to `time.grapheneos.org`. The old `ntp://time.android.com` literal is not selected by this path. | Successful guest HTTPS time acquisition, not simply a property/string scan. |
| Diagnostics/tethering | Diagnostic nonce suffix selects GrapheneOS; fallback DNS addresses are Cloudflare, not Google's resolvers. | Broader tethering/carrier behavior is not covered by the first window. |
| CT | Default `Config.baseUrl` is `https://gstatic.grapheneos.org/android/certificate_transparency/`. | Real downloads, original signature validation and installation. |
| RKP | The GrapheneOS URL override precedes the stored/default-property URL. | Actual request destination/redirect behavior. Cuttlefish is not a Pixel hardware-attestation proof. |
| Widevine | The OS provisioning worker uses the GrapheneOS proxy override. | Browser per-origin provisioning is separate. No protected-playback test is part of this baseline. |
| Vanadium | Normal variations initialization is disabled; component updates use `update.vanadium.app` and `dl.vanadium.app`; browser network probes respect the OS connection-check setting. | Runtime paths, configuration updates and the recovery exception below. |

The new image review initially enumerated 134 APKs in system/system_ext/product.
Extracting the frozen vendor image accounted for the remaining 11, matching the
145 direct-partition APK inventory. This count excludes APKs inside APEX payloads;
it is not an exhaustive count of every installed package. No Updater APK is in
that inventory.

## Update identity and trust

- `media_system.mk` includes the official GrapheneOS OS Updater only for
  `OFFICIAL_BUILD=true`; the Andrix proof product rejects that configuration.
  Do not turn its absence into a supported Andrix OTA claim. Andrix production
  OTA identity, signing and delivery remain future release gates.
- The existing GrapheneOS Apps client is an unchanged, privileged upstream
  preprocessed APK, version 36. Source/image bytes match and its APK signature
  verifies against certificate SHA-256
  `3384c31fce4a7c008a8f7b2652bc48cc4321f1d2c877b18e30a4ed619af12f6b`.
- The corresponding public source is AppStore tag 36,
  `9bdf70a2c9a2dd757fe163c599907dcda3960c62`. This is source correspondence, not a
  reproduced APK build. The actual DEX corroborates `apps.grapheneos.org` catalog/
  package prefixes and the repository signing key.
- A current real catalog verified under that Ed25519 key; changed JSON failed.
  The catalog's Apps 36 archive was downloaded and independently matched its
  signed hash/size and the frozen APK bytes. This is a host delivery result,
  not Android installation or privacy qualification.
- Apps 36 schedules a six-hour update check by default. Code-package auto updates
  wait for idle; no-code updates may be requested sooner. Do not suppress these
  silently. Record actual runtime package versions/signers and any downloads or
  updates; an updated app is not the original frozen app evidence.
- For this test, Apps remains the genuine upstream channel for its upstream-signed
  apps, not an Andrix OS/APEX updater. Google-app installation is not exercised or
  required. No signer, package identity or catalog trust is impersonated.

## Known recovery-path gap

The exact Chromium 151 source contains a SafeMode action which calls
`AwVariationsSeedFetcher.scheduleIfNeeded(true)`. Vanadium 151's normal initialization
buildflag guards do not cover that scheduler or `onStartJob`; the frozen WebView
DEX retains the scheduler and Google variations URLs. This is more than a bare
URL-string observation, but is **not an observed network request**.

The earlier Andrix 152 derivative has explicit scheduler/start-job guards. None
of that derivative is present in this image. A narrow, attributable source fix and
appropriate rebuild/requalification are needed before a broad release-policy
claim. Do not activate the known path against Google merely to get a negative
packet trace, pretend startup disable covers it, or swap APKs without provenance.
The first connected window exercises ordinary boot/setup/browsing, not this
recovery path. A successful window cannot close the known gap.

## Fixture and measurements

- Fresh rootless namespaces, userdata and runtime directories; frozen/rehashed
  images and matching host packages only. No signing keys/build trees in the VM
  filesystem, no public host listener, no hostwide route/clock/security changes.
- Actual DNS/DoT, DHCP and a bounded owned HTTPS probe, with TLS keys isolated to
  the service filesystem. Upstream GrapheneOS services remain real endpoints,
  not local fake replacements. Use fresh valid supplied data where a fixture
  route serves it; do not retimestamp expired snapshots.
- Start capture before assembly and keep it through cleanup. Establish genuine
  guest Internet access and retain resolver logs, routes, versions and loss counts.
- Complete normal setup/launcher observation through the fixture's private display
  console and ordinary UI input. Do not alter Android credential-screen capture
  protection, forge setup-complete state or grant app permissions behind the UI.
- Use explicit `grapheneos-core` for the shared `/usr`/APEX/ABI/SELinux oracles.
  Its RKP values are observation-only; it makes no network-policy claim. Admission,
  property-read failures and the shared negative oracles are host-tested alongside
  the unchanged offline/legacy profiles: 30 device tests and 259 total host tests
  pass. These are not device or network results.
- Check normal non-Google activity, service delivery and a normal reboot with
  the same data. Any direct Google attempt in those scoped operations is a
  finding/failure, not a reason to hide traffic or expand the explicit-use exception.
- Stop only owned processes, preserve failed attempts and seal the completed
  window. Native/Pixel hardening, actual hardware RKP, carrier/eSIM, protected
  playback and complete recovery coverage remain separate gates.

## Initial evidence

Private preparation evidence is `grapheneos-connected-prep-20260909T212949Z`.
It includes exact source samples, all 304 files of the public Vanadium 151 source
archive checked against GitHub tree blob hashes, Apps 36 source/artifact/catalog
observations, compiled resource dumps and the retained WebView recovery-path
analysis. Cancelled reviewers supplied no substantive findings; primary reviewed
these inputs independently.

Current public CT data fetched through the configured GrapheneOS endpoint verifies
against the exact image's unchanged allowlist: v2 `89.30`, v3 `91.0`. The actual
GrapheneOS-tree `flatc` independently decoded v3 metadata; wrong guesses at the
installed tool path and the first missing-`ANDROID_HOST_OUT` extraction attempt
are retained. These are host cryptographic/artifact checks, not guest CT delivery.
