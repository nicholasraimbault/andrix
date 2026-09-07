# Connected candidate result — e65e656

## Verdict

**Useful connected runtime evidence; no complete no-Google qualification yet.**
The first Google wallpaper-verification request was fixed in source and absent
from the next image's manifest/runtime link declarations. The second measured
window observed no Google destination from the guest. It also preserved a
failing CT download, so absence of Google packets is not a sufficient pass.

This is ARM64 Android/Bionic running under QEMU TCG on the existing x86 host,
not a native ARM/KVM result or a supported release. The working earlier images
and both connected windows remain frozen.

## Exact candidate

- Image producer: `e65e656d6a6534c8ec33f19d4c888eea6e11ed9d`, with explicit
  `ANDRIX_WEBVIEW_EXPERIMENT=true`; 28 image files frozen.
- Android `android-17.0.0_r1`, API 37, ARM64-only. The declared AOSP adaptation
  is twelve files in eight pinned projects; no platform project HEAD advanced.
- The three signed APK hashes are in
  [candidate.json](../experiments/webview/candidate.json). Extraction from the
  product image matched them exactly. Native-only/config-only APKs do not have
  DEX to precompile; the actual WebView retains normal DEX precompilation.
- Normal product-policy idmaps accepted the WebView-provider and DSU URL RROs.
  The previous public-only WebView-overlay negative was rejected normally.

## Observed passes

- Boot completed, WebView `dev.andrix.experiment.webview` 152.0.7977.84.0
  selected without a post-boot substitution, relro 1/1, SELinux enforcing.
- The exact signed factory APEX activated; both hello paths had the same hash
  and inode and printed `andrix`. `/usr` remained read-only and `/etc` Android.
- The ordinary ARM64/Bionic app's real system-shell control succeeded; its
  byte-identical private executable copy was denied `EACCES`. Uninstall checked.
- Ordinary WebView initialization, JavaScript DOM result `42`, real same-origin
  HTTPS 204, and wrong-hostname TLS rejection passed. The test first requested
  `ACCESS_LOCAL_NETWORK` through the normal system permission dialog, which was
  visibly approved; no shell grant, adopted permissions or LNA-disable flag.
  Its initial Internet-only failure is retained in the earlier window.
- Safe Browsing initialization returned **false**; the WebView setting remained
  true. Neither a setting nor a callback is claimed as backend protection.
- The host fixture passed real DNS/DoT, DNSSEC positive and invalid-signature
  negative, synchronized NTP, HTTP(S) 204 and wrong-host TLS. Android observed
  validated opportunistic DoT and a successful owned NTP result.
- Security snapshot HTTPS responses matched all raw input hashes; HTTP access
  was refused and a real shortened-expiry TLS test returned 503, not stale 200.
  Settings fetched the explicit empty owner DSU catalogue and displayed
  “No DSU available for this device.” No released Andrix GSI was invented.
- A guest TCP connection to `example.org:443` succeeded, exercising real public
  Internet forwarding. It is a TCP control, not a separate HTTPS validation.
- Host checks: 190 proof tests, seven permission-source checks, and the existing
  129 URL-parser cases. The revised fixture also compiled against actual r1
  public API stubs and was built/signed normally in AOSP.

## Capture scope

Capture started before assembly. The second fixture window ran from
2026-09-07 03:07:46Z to 04:27:14Z: **45,111 captured packets**, zero kernel-reported
drops. Guest IPv4 destinations were the private fixture's DNS/DoT/NTP/HTTP(S),
local multicast, and the explicitly requested `example.org` TCP control.
Resolver names were the owned probe/nonce/wrong-host names and `example.org`.
Namespace IPv6 destinations were local/link-local multicast, not public egress.
Host resolver/time traffic and loopback control traffic are classified separately.

This is not a universal privacy guarantee, an IPv6 Internet qualification, or
coverage of every manual navigation, carrier, recovery and update path. No
Google destination blocklist, fake response or DNS blackhole produced this
observation. Both VM and fixture were stopped with exit 0; the heavy-work lease
is free and signing/TLS private material remains outside Git.

## Remaining blocker: CT update completion

The CT service is enabled, registered, and its normal alarm ran. DownloadProvider
attempted the correct owned URL:

```text
https://probe.andrix.org/certificate_transparency/log_list.pub
status=194, numfailed=4, current_bytes=0
failed to connect ... 192.168.96.1 ... after 20000ms
```

The update has **not** completed or installed a newly verified log list. General
DownloadProvider network policy reported no effective block; its API-37 manifest
has no `ACCESS_LOCAL_NETWORK`, and no packet for the inspected timed-out source
port reached the fixture capture. These observations suggest local-network
access is relevant, but do not prove the exact cause. The successful foreground
WebView fetch must not be substituted for DownloadProvider success.

A shell attempt to send the protected CT update broadcast was denied. No root,
permission grant, service disable, direct log-list injection or verification
bypass followed. A proposed shell-side public download control was rejected by
the `content` command's binding parser before insertion; it was not a public
DownloadProvider connectivity test.

Next work must establish working CT delivery without weakening Android's
boundaries. A controlled **public HTTPS static-data endpoint**, kept off the
build/signing host, is a candidate for the next comparison. Creating a public
fixture service / additional owned hostname needs an explicit deployment choice;
no hosting purchase, account creation or public host listener was made here.
Native validation, full ConfigInfo negative/runtime coverage, coordinated update
and rollback testing, and production signing remain separate open gates.
