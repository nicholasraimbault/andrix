# Vanadium DRM and Silvervine's role

Read-only source/documentation assessment, 2026-09-09. The primary review did not
run a browser/CDM, make a license or provisioning request, or use an account,
purchase, vendor terms or handset operation. A later owner-reported phone
observation is separately labelled below. The owner subsequently decided that
**Andrix does not need Silvervine**: no bundle, port or optional-package integration
is planned. The source comparison is retained as rationale. Retaining genuine
hardware attestation through GrapheneOS's proxy is a separate owner-approved
decision.

## Two different integration paths

```text
Desktop Chromium -> desktop Widevine CDM component files
                    (Silvervine installs/manages these)

Vanadium on Android -> Chromium MediaDrmBridge -> Android MediaDrm
                       -> device's Widevine DRM implementation
```

The difference is not merely x86 versus ARM. A Rust helper can be ported without
making the proprietary CDM binary or its hosting API compatible with another OS.
Current Silvervine master `240b326cf356620eae9cffbebc533d88922a0889` supports Linux
x86_64 and Intel/ARM64 macOS, not Linux ARM64 or Android/Bionic. Its desktop
component publication path is not the Android DRM provider interface.

The Chromium `151.0.7922.137` reference source contains
`media/base/android/media_drm_bridge_factory.cc`, which selects Widevine security
level 1 or 3 depending on hardware-secure-codec requirements. The Java
`MediaDrmBridge` imports `android.media.MediaDrm`, constructs a `MediaDrm` instance
and uses its session/provisioning APIs. It does not use Silvervine's desktop
`libwidevinecdm.so` installation layout.

For Andrix's Android browser, the first task is therefore to qualify the normal
platform DRM path with legitimate, compatible device inputs—not inject a desktop
CDM or replace the phone's media stack.

## What Vanadium already provides

The upstream Vanadium `151.0.7922.137.0` tag resolves via the public GitHub API to
`45400d8e0e54113389796e2e7b26cf3b52fd2611`. This generation matches the migration
anchor's recorded version/Config 200 inputs. Source inspection is not a binary
playback qualification.

Its reviewed patches include:

- [`0076-ask-before-playing-protected-media-by-default.patch`](https://github.com/GrapheneOS/Vanadium/blob/45400d8e0e54113389796e2e7b26cf3b52fd2611/patches/0076-ask-before-playing-protected-media-by-default.patch):
  changes protected-media permission from ALLOW to ASK.
- [`0086-disable-media-DRM-preprovisioning-by-default.patch`](https://github.com/GrapheneOS/Vanadium/blob/45400d8e0e54113389796e2e7b26cf3b52fd2611/patches/0086-disable-media-DRM-preprovisioning-by-default.patch):
  disables proactive MediaDrm origin preprovisioning, retaining on-demand behavior.

Thus a general description of DRM being disabled by default must not be read as
proof that Vanadium lacks a DRM integration or needs a desktop CDM installer.
Owner consent, the actual device provider and service behavior still matter.
The OS's Widevine provisioning worker and the browser's own MediaDrm provisioning
path need separate endpoint review; a proxy setting in one does not by itself
prove every client request uses it.

## YouTube movies on the web

Not bundling Silvervine does **not** inherently prevent movie playback in Vanadium.
Ordinary YouTube video playback does not require Silvervine. Protected movie
playback requires a working browser/platform DRM path, appropriate permission,
a valid license and acceptance by the service. No actual purchased/rented movie
playback on Andrix has been qualified.

**Owner-reported observation, 2026-09-09:** on the owner's Pixel running GrapheneOS,
both Vanadium and Brave rejected a YouTube movie with a message reported as
"video unavailable watch on the yt app the content isnt avail on your mobile
browser". This is evidence of the observed mobile-web rejection, not a successful
Andrix playback test. It points to YouTube's client/content eligibility policy;
it does not establish the DRM session's security level, a missing CDM, the exact
enforcement mechanism or every title/browser combination. No L1 failure is
inferred, and installing Silvervine cannot be assumed to change that eligibility.

**Owner-reported follow-up:** enabling the browser's normal Desktop site option
made the movie work in Vanadium, but not in Brave. This narrows the earlier failure:
the existing Vanadium setup was sufficient for the reported playback in that mode,
without adding Silvervine. Browser mode mattered in this case; the precise cause
of Brave's different result remains unknown. This is not an instrumented Andrix
result, a measured L1/L3 session, a resolution measurement or a guarantee for other
titles and versions. Preserve both the original mobile-mode failure and this
successful Vanadium follow-up.

The current [YouTube system-requirements page](https://support.google.com/youtube/answer/78358?hl=en)
lists Chrome/Firefox/Safari and desktop OS requirements for premium web playback.
It states that browser HD streaming is unavailable except in Safari; this is a
service policy, not a capability an installer can promise to change. The separate
[HD/UHD help page](https://support.google.com/youtube/answer/3306741?hl=en)
says availability depends on studio licensing agreements and the device. Neither
page establishes support for this exact Vanadium/Andrix/Pixel combination.

Explicit owner use of YouTube, including the associated service requests, is
allowed by the [accepted networking policy](architecture.md). That does not
permit unrelated automatic Google connections. No identity spoofing, fake
certificates, DRM bypass or guaranteed resolution is proposed.

## Accepted scope decision

The owner decided that **Andrix does not need Silvervine**. The earlier suggestion
of a possible optional package is superseded: no Silvervine bundle, port,
Andrix-specific package or dependency is planned. Silvervine remains a separate
project, and owner-installed software remains the owner's choice.

Andrix will qualify Vanadium with Android's native MediaDrm integration. Do not
add a second DRM provider, choose a new ABI or modify authenticated `/usr` to solve
an unproven missing-component problem. The retained source assessment and the
owner's successful Vanadium Desktop site observation explain the scope decision;
neither substitutes for actual Andrix playback or network qualification.
