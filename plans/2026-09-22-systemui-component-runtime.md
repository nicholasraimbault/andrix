# SystemUI component change and recovery qualification

Status: the finite Cuttlefish component loop passed on the matching `56c5512` image.
This qualifies the declared host assisted development workflow, not a complete workshop
mode, personal signing system or general administrative interface.

## What ran

The [execution plan](2026-09-21-systemui-execution-plan.md) used a pinned platform cohort,
component builds of SystemUI and its dependencies, and the existing public development
platform signer. The unmodified component reproduced the factory APK byte for byte.
Every update pair was frozen after package, version, signer, v4, alignment and payload
checks. No complete OS image was built for each APK variation.

The first staged attempt exposed a missing file verification permission. The
[narrow policy correction](2026-09-22-staged-apk-verity.md) adds only the enable and measure
ioctls for `system_server` on the existing staging file type. Both policy selections
compiled with exactly that access delta, and a new coherent selected image carried it.
The successful runtime did not change policy, remount partitions or disable package checks.

## Observed sequence

| Component | Version | Observed behavior after activation |
| --- | --- | --- |
| Factory | 37 | Original clock and functioning native environment |
| A | 38 | Clock displayed its time with `WS-A` |
| R | 39 | Original clock restored before introducing B |
| B | 40 | Deliberately incorrect `WS-B BAD` clock text |
| C | 41 | Original clock restored again |

For each positive update, the exact session first reached ready while the prior APK was
still active and unrelated native work remained live. After the declared reboot, the
session was applied, the active package bytes matched the frozen candidate, and the
expected UI behavior was observed. Package UID, MAC context and the actual user0 keyguard
permission grant remained consistent.

R demonstrated the independent host controlled forward restoration route before B.
C restored the same good source afterward. R and C are new higher version artifacts;
this is not installation of the byte identical old APK, arbitrary downgrade, or a claim
that application data migrations can always be reversed.

## Negative controls

- A valid nonstaged replacement was refused because SystemUI is persistent. The factory
  APK remained active, with live native work bracketing the refusal.
- A cryptographically valid update signed with a different development key reached staged
  ready. Activation rejected its mismatch with the installed package signer.
- An update without the required sidecar also reached ready. Activation rejected the
  missing file verification state.

Both staged negatives triggered the platform checkpoint recovery path. The original
factory package, working clock, saved test data and explicit fresh native execution were
verified afterward. Ready is not installed package compatibility or successful activation.
The recorded sequence includes six explicit activation attempts and the two additional
checkpoint recovery reboot requests. It does not infer every intermediate boot identity
from the final observed bookends.

No factory uninstall, permission stripping, manual package database editing, blind file
removal, signer bypass or verification switch was used.

## Native work and data

The ordinary owner environment compiled and executed the test payload. Its observed
profile included the intended Unix credentials and MAC domain, empty capabilities,
`no_new_privs`, filtering and no leaked management descriptors.

A live accepted job kept the same sampled identity and scope while an APK waited ready.
Reboots ended old jobs. Fresh native execution after every activation attempt checked the
saved CE home sentinel and profile. This is explicit new work, not revival of old process
identities. Genuine CE authority was checked before native submission; neither boot
completion nor lockscreen state was treated as storage authority.

The fixture used user0 without a PIN challenge. The saved sentinel is a finite data
preservation check, not a proof of every application's data or SystemUI settings migration.
The final work and service retirement completed, and the owned hierarchy was observed empty.

## Evidence and retained failures

The final assessment checked raw create/write/commit replies, exact session states,
installed package hashes, UID/MAC observations, fresh UI hierarchies and display captures,
native payload outputs, CE reports, ordering and final closure. The guest stopped, volatile
RAM backing disappeared, frozen inputs remained equal, and the packet capture was complete.
Original failed and incomplete attempts remain separate records.

Four read only UI observations did not initially succeed in the final run. Two saw the
still locked UI. Two hierarchy commands reported success without producing their file.
Those failures were retained. Later observation used fresh evidence names against the same
boot and package. No update, reboot or native submission was repeated because of them.

The platform also logged attempts to enable file verification again on already protected
staged APKs during boot restoration, returning `File exists`. Its existing package parsing
fallback continued through rejection or installation. That warning was not suppressed or
fixed in this proof. The separate
[idempotency correction](2026-09-22-package-verity-restoration.md) subsequently passed its
own source, compiled image and fresh runtime regression. The original sealed runtime
evidence remains unchanged.

Source review, 470 host checks, the matching image's 13 frozen native checks and this
finite Android runtime are distinct evidence layers. The result is limited to the artifact
and runtime controls described above.

## Boundaries and next work

This demonstrates a real SystemUI code change through build, signing, staged installation,
activation and forward source restoration while retaining the Android and native environment.
It is not just an overlay or an edited screenshot.

Still separate are protected owner key custody, ordinary native elevation, on-device builds
and signing, activation without reboot, startup crash loop recovery, multiple full users,
and general component/data compatibility across platform releases. The public development
keys used here are not secure personal installation keys.

Next work should turn this mechanism into a reusable owner component transaction, with
clear compatibility and interruption information. The later file verification restoration
fix is qualified separately. The accepted authority and signing plan remains the place for
the distinct owner authorization and key custody design.
