# GrapheneOS connected baseline — bounded diagnostic trial

## Scope and authority

The owner approved continuing the endpoint/update inventory and a bounded connected
emulator test; the Pixel is not connected and is excluded. Use the
[accepted direct-client networking policy](../docs/architecture.md), genuine
GrapheneOS provisioning paths, existing hardware and the exclusive heavy-work
lease. No new public service, production key, vendor terms or handset action is
approved here. Silvervine is out of scope.

This is a **diagnostic baseline**, not a promise that every reachable feature
already satisfies release policy. A WebView recovery source finding needs
trigger/reachability qualification below. No Google-IP denylist, DNS blackhole, fake successful client or disabled
security consumer may manufacture a quiet capture. Unexpected traffic and failures
remain evidence, not results to discard.

## Reviewed producer and defaults

The first window used frozen image/host inputs from
`108d8574dcfc9a09bb29977e67d694e82c94d758`. The APN-corrected retry used producer
`a28d17095493cdfd7147bc957df4e40ea73920ca` and host/probe observer `1fa4fd2`.
No old AOSP platform patch series or experimental 152 APK was substituted.
Source producer, observer, runtime package versions and documentation HEAD remain
separate identities.

| Area | Inspected selection | Initial qualification gap; runtime results below |
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

## Recovery-path source finding — operational reachability unqualified

The exact Chromium 151 source contains a SafeMode action which calls
`AwVariationsSeedFetcher.scheduleIfNeeded(true)`. Vanadium 151's normal initialization
buildflag guards do not cover that scheduler or `onStartJob`; the frozen WebView
DEX retains the scheduler and Google variations URLs. This is more than a bare
URL-string observation, but is **not an observed scheduling event or network request**.
The trigger conditions and surrounding gates under the retained upstream
configuration still need verification before this is treated as an operational
policy defect.

The earlier Andrix 152 derivative has explicit scheduler/start-job guards. None
of that derivative is present in this image. The separate exact-151 context trial
shows that a narrow change is mechanically possible, not that a downstream change
is necessary. No direct Google variations download was observed in the connected
window. Retain upstream Vanadium while checking the finding; there is no adopted
browser fork or preselected fix. Do not activate a suspected path against Google
merely to obtain a negative trace, hide traffic or swap APKs without provenance.
The ordinary window cannot establish that every recovery path is unreachable,
just as source inspection alone cannot establish that the suspected fetch occurs.
This clarification changes the interpretation and work priority, not the sealed
source or runtime observations.

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
  the unchanged offline/legacy profiles: 30 device tests pass. The full host suite,
  including the WebView fixture profile and APN product check, passes 262 tests.
  These are not device or network results.
- The ordinary WebView fixture has an explicit `grapheneos-2026081300` profile,
  matching the earlier P5 distinction between APK declarations and implicit PM
  metadata. The APK still declares only INTERNET and ACCESS_LOCAL_NETWORK; only
  the expected GrapheneOS OTHER_SENSORS PM entry is additionally accepted for the
  pinned product/generation. Its grant state is not claimed measured. Normal
  visible local-network permission consent, provider checks, JS/HTTPS and wrong-
  hostname TLS rejection remain unchanged. The fixture is built separately, not
  installed as a product app, and is not a Safe Browsing protection proof.
- Check normal non-Google activity, service delivery and a normal reboot with
  the same data. Any direct Google attempt in those scoped operations is a
  finding/failure, not a reason to hide traffic or expand the explicit-use exception.
- Stop only owned processes, preserve failed attempts and seal the completed
  window. Native/Pixel hardening, actual hardware RKP, carrier/eSIM, protected
  playback and complete recovery coverage remain separate gates.

## First diagnostic window: guest connectivity failed

The real host DNS/DoT, DNSSEC, NTP, TLS and CT fixture checks passed. The guest
booted and passed the shared core checks, but **had no active default network**;
the public ping returned `Network is unreachable`. Cellular evaluation repeatedly
reported `NO_SUITABLE_DATA_PROFILE`. Both `/system/etc/apns-conf.xml` and
`/product/etc/apns-conf.xml` were absent. Source comparison confirms the GrapheneOS
generic base omits the sample APN copies present in the old AOSP product.
The virtual SIM reported MCC/MNC 311740. Cuttlefish's secondary `eth1` is deliberately
restricted by its upstream overlay, and normal Wi-Fi enablement found no AP in
this fixture. No real carrier, radio identity or phone was changed.

Normal setup was completed through the private virtual display and ordinary
visible Skip/Start actions; the launcher and main Settings screen were observed.
The initial console observer used the wrong long socket directory, an external
ADB observer initially lacked its namespace environment, and QEMU lacked PNG
screendump support. Those failures remain. The working observer used the actual
short UDS directory and retained QEMU's PPM output, converted to PNG without pixel
changes. Android's credential-window SECURE flag and screenshot protection were
not changed; no credential was entered. This is an operator display, not a claim
that an ordinary app can capture protected content.

The window was stopped as a connectivity failure, before the WebView/P5 probes
or reboot. Runner/stop and all service/capture cleanup exited 0; the controller and
orchestration correctly remained FAIL. Capture: 66,172 packets, zero reported drops.
That is **not a guest-Internet or privacy pass**. The closed window seals 1,169
regular files; original failures are not relabelled.

Producer `a28d170` restores the existing
`device/sample/etc/apns-full-conf.xml` as `/product/etc/apns-conf.xml` **only in the
Andrix GrapheneOS Cuttlefish product**. It does not change Pixel carrier/vendor
configuration, weaken the restricted Ethernet interface, fake a network response,
change RKP or override Android permission state. A GNU make host test checks the
exact copy declaration and its separation from the shared/legacy products. The
corrected image and retry results follow.

## Corrected connected window

The eight-job `droid hosttar` build exited 0 in **556.454 seconds**. All 27 images
and both host packages were frozen/rehashed. The actual product image contains
byte-identical pinned sample APN data, including the virtual SIM's default profile;
TelephonyProvider selects that product file through its existing precedence rules.
The signed `/usr` APEX and image shell remain byte-identical to the earlier verified
artifacts. No platform source patch or security-setting workaround was needed.

A fresh rootless runtime ran from 2026-09-10T00:06:32Z to 01:07:07Z. Its first host
DNSSEC check timed out; the preserved bounded second attempt passed before VM
launch. Guest core checks passed, with real Cuttlefish readiness at 00:26:13Z.
The initial public ping still failed **before setup completion**: the corrected
APN now satisfied telephony, but data was disabled during onboarding. Normal visible
setup completion enabled data; no shell setting or grant did so. The inspected
SetupWizard `FinishActions` writes normal provisioning completion, which
`DataSettingsManager` observes to leave its provisioning-data gate. Android
established and validated network 100, with the controlled resolver and working DoT. This is
protocol validation under the existing DNS profile, not a new strict-hostname DNS
policy. A later public ping received both replies; its original failure remains.

| Measurement | Observed result |
| --- | --- |
| `/usr`, APEX, Bionic/ABI, `/etc`, SELinux | Shared core oracles passed before and after ordinary `adb reboot`; boot ID changed. |
| Normal setup | Visible Skip/Start controls completed setup without a PIN, backup restoration or forged provisioning state. Credential screenshot protection was not changed. |
| WebView ordinary app | Normal visible local-network ALLOW; real JavaScript result 42 and HTTPS 204; wrong-hostname TLS rejected/cancelled. Provider remained Vanadium 151.0.7922.137.0. Installation and removal verified. |
| Safe Browsing | Initialization callback **false**, despite its setting remaining true; backend protection was not verified. |
| P5 ordinary app | UID 10145, untrusted-app domain, zero effective Linux capability mask; exact image-shell control succeeded; identical private-copy `execve` failed EACCES with `execute_no_trans` denial. APK declares no permissions; only expected implicit OTHER_SENSORS PM metadata accepted, grant state unmeasured. Removal verified. |
| Time | Actual successful `https://time.grapheneos.org/generate_204` acquisition, recorded by the Android time service. |
| CT | Android installed v2 **89.30** and v3 **91.0**. Ordinary shell reads confirmed both current links and exact independently verified file hashes. |
| RKP | Real client traffic used GrapheneOS's proxy; the client logged **12 provisioned keys** for Cuttlefish's software implementation. Not Pixel hardware-security or backend-server proof. |
| Widevine | The OS worker reported Widevine unsupported in this guest; no provisioning/playback success is claimed. |
| Package updates | Apps 36, Vanadium 151 and Config 200 remained at their factory APK versions through reboot. Native Apps catalog/install/rollback lifecycle was not qualified. Browser component traffic did occur separately. |
| Reboot connectivity | Android again reported an active, validated cellular network and validated private-DNS transport. |
| Cleanup | Controller, UI session, runner, stop, all fixture services and capture exited 0. No owned runtime remains. |

**Full browser rendering failed this bounded check.** Vanadium's toolbar/menu and
notification prompt responded, but `https://example.org/` content stayed blank,
including after a normal second-tab navigation. QMP and Android captures agree;
the browser window was focused. EGL native-fence errors were logged, but their
causal role is not established. No renderer/security disable, debugger or page
state fabrication was used. The successful ordinary WebView probe is not a full
browser-rendering pass, and neither is protected-playback qualification.

### Capture and claim boundary

Capture started before assembly and covered cleanup: **111,280 packets**, zero
kernel-reported drops and zero truncated packet records,
00:06:33.704001Z–01:07:05.067990Z. Guest IPv4 traffic was separated from fixture
upstream/control traffic. IPv6 observations were local/multicast only; IPv6
Internet remains unqualified.

Initial TCP streams were reassembled with duplicate/overlap checks. All 52 guest
TCP connections were accounted for by observed HTTP Host/TLS ClientHello names or
the owned DoT endpoint. Names included GrapheneOS connectivity/time/CT/RKP,
`update.vanadium.app`, `dl.vanadium.app`, the owned positive/wrong-host probe and
`example.org`. The parser retained no incomplete/unparsed initial-stream issue;
independent synthetic split/overlap/truncation controls also ran. This does not
turn passive TLS metadata into payload decryption or server-implementation proof.

Twelve component-download requests initially used **HTTP** to `dl.vanadium.app`;
the capture contains 301 redirects to **HTTPS on the same host**, not Google.
HTTPS component-update/download connections were also observed. This is not a
claim that every component installed, or that all initial requests used TLS.

**No automatic direct Google connection was observed in the exercised window.**
There was real guest Internet, not a denylist/blackhole or an offline-silence pass.
Provider-side Google processing remains allowed and is not excluded by this result.
The WebView recovery source finding, emulator browser-rendering failure, native Apps lifecycle,
other settings/carrier consumers and Pixel/hardware paths remain open. Accordingly
this is **not a complete release-policy qualification**.

The second closed window seals **1,822 regular files**. The first failed window,
its 1,169-file seal and original source/observer failures remain intact.

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
are retained. Those initial checks were host cryptographic/artifact evidence;
the corrected runtime subsequently installed the same verified bytes, as recorded
above.

Post-build/runtime source verification again authenticated the manifest and
accounted for all 1,108 exact project HEADs and tracked cleanliness. The first pass
had 1,107 PASS results and a preserved 120-second `build/release` diff timeout; the
unchanged single-project check passed in 6.107 seconds on a bounded serial retry.
No source normalization, reset or persistent Git configuration change was used.
The complete preparation/result evidence seals **7,217 regular files**, excluding
symlinks; raw captures, APKs and private operating material stay outside public Git.
