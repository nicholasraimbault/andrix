# Accepted revision: an owner composable Android OS

Status: the owner accepted this expanded product direction on 2026-09-21 after discussion.
This record revises goals and architecture, not implementation or qualification results.
The [vision](../docs/vision.md) is the product statement and
[architecture](../docs/architecture.md) records its accepted contracts.

## Goal

Make Android itself a computer the owner can compose and administer. Native Unix execution
remains essential, but the product boundary also includes APKs, SystemUI, framework and
native services, signing, installation, updates and recovery. A practical component change
workflow matters more than the theoretical ability to fork and rebuild an entire ROM.

The earlier small downstream layer was a deliberate scope choice. This revision removes
that ceiling without discarding the subsystem already developed or reclassifying old proofs.

## Decisions and rationale

| Area | Accepted direction | What changes or remains open |
| --- | --- | --- |
| Product ownership | Andrix is the OS, with native execution and APKs equally important | `vendor/andrix` remains a possible repository placement, not a restriction on platform changes |
| Foundation | Initially retain a pinned GrapheneOS source release as a useful integration base | Andrix defines its policies and capabilities; no automatic inheritance of official GrapheneOS assurances |
| Native platform | One Android/Bionic userspace, preserving phone services | No separate glibc/distro or alternative desktop product roadmap; owner experiments are not prohibited |
| Accounts | Multiple full Android accounts, each with integrated Unix identity, home and jobs | One human may use many accounts, or multiple people may use the phone; current user0 qualification is not sufficient |
| Administration | Explicit general owner authorized elevation, including root commands | Daily programs and ordinary APKs do not automatically gain that authority; mechanisms need design and tests |
| Trust | Separate distribution provenance from the owner's installed-system authority | Personal initial signing is a candidate; enrollment, key custody, certificate continuity and recovery are unproved |
| Workshop | A legitimate unlocked configuration permitting deliberate system modification | SELinux, app isolation and CE encryption remain defaults; precise verification settings and recovery need qualification |
| Locked operation | Later owner keyed mode of the same system | Not the only acceptable product mode and not yet a qualified Pixel deployment |
| Component development | Focused build, sign, install and lifecycle operations | Host assistance first is acceptable; ordinary component development on the phone is an explicit end goal |
| Releases | Rolling updates with compatible component groups and recoverable activation | No arbitrary partial upgrade guarantee; local selections, conflicts and missed security fixes stay visible |
| Installer | Recommended usable defaults plus an advanced assembly path | One component model, with choices replaceable after installation |
| Update control | Owner consent or configured policy governs disruptive activation | Download or staging permission does not silently grant permission to interrupt work |
| Sequence | Cuttlefish/QEMU first, mature Pixel integration later | Emulator success never establishes radio, firmware, hardware security or phone recovery behavior |
| Agents | Defer dedicated agent architecture | Focus on human accounts and ordinary programmable interfaces |

## Source base alternatives

Direct AOSP plus independently maintained Pixel integration remains possible. It offers a
smaller upstream Android policy delta, but requires selecting, integrating and maintaining
the device support and hardening we want. AOSP also receives security fixes; GrapheneOS's
value is not that it is the only source of CVE patches.

The current recommendation, accepted by the owner, is to retain GrapheneOS as an engineering
foundation. Its coherent Pixel integration and additional hardening may reduce continuing
maintenance compared with assembling selected pieces. This is not a sunk cost argument or
a requirement to keep Andrix's changes small at the expense of its goals. Revisit the base
if concrete compatibility or maintenance costs defeat that rationale.

The earlier [base assessment](../docs/grapheneos-base-assessment.md) remains evidence for
its inspected source and old scope. Its small layer ceiling and later glibc/Wayland research
track are superseded as product direction. Existing Cuttlefish execution demonstrates the
Unix half, not the expanded administration and component replacement workflow.

## Authority and failure boundaries

The owner chooses what system to trust. That does not make every signed package equally
privileged or remove runtime identity boundaries. APK signatures, shared UIDs, privileged
permissions, SELinux, APEX verification and boot verification are distinct mechanisms.
Ordinary software remains ordinary until a deliberate authority crossing occurs.

The owner's administration authority can change the OS and its guarantees. Workshop
operation must describe its reduced physical integrity protection. Locked accounts' CE
keys do not become readable merely because an administrator changes a pathname, and user
switching does not by itself prove withdrawal of those keys. An actively modified OS can
also undermine future user privacy; do not promise isolation against a malicious platform
administrator.

A component change can fail, break UI or require a broader update. Recovery must be designed
before describing the workflow as supported. Neither a successful package install nor a
service restart proves that callers, user data and phone functions survived safely.

## What remains deliberately unchanged

- Native owner execution, CE homes, authenticated `/usr`, compiler and job supervision.
- Android supervises environments, Andrix manages work, the kernel contains it, Console is a client.
- Detach, hangup, ordinary exit, Stop, restart, wake and locked input remain distinct.
- Original identity/epoch fencing and actual ownership through cleanup remain required.
- Ordinary APKs do not masquerade as Unix login identities.
- No automatic direct Google connections by official components, with explicit owner use
  remaining permitted under the existing networking policy.
- Minimal protected diagnostics; persistent activity/output history and export remain off
  unless enabled. No new persistence arises merely from this vision revision.
- Historical proofs, incomplete attempts and original evidence remain preserved.

## Workstreams and next gate

1. [Workshop component workflow](2026-09-21-workshop-components.md): first Cuttlefish proof,
   beginning with a small SystemUI change and a tested restoration route.
2. [Owner authority and signing](2026-09-21-owner-authority.md): general elevation, key
   ownership, protected signing and recovery, not signature bypasses.
3. [Android accounts and Unix](2026-09-21-android-unix-accounts.md): real account boundaries
   and lifecycle integration, not cloned homes under one shared UID.
4. [Rolling composition and installation](2026-09-21-rolling-composition.md): package
   selections, compatibility, activation and recommended/custom installation.
5. [Pixel integration](2026-09-21-pixel-integration.md): later maintained hardware product,
   with its own installation and recovery authorization.

The immediate change is documentation only. The next implementation proposal must specify
its source changes, development signing configuration, recovery path and finite observations
before execution. This decision does not itself authorize generating production keys,
flashing a phone, weakening a current fixture's guards or rewriting sealed evidence.

## Inspected references

- [GrapheneOS build guidance](https://grapheneos.org/build): development builds, incremental
  work, signing and derivative update configuration. It is not Andrix product policy.
- [AOSP release signing](https://source.android.com/docs/core/ota/sign_builds) and
  [APEX](https://source.android.com/docs/core/ota/apex): signing and update building blocks,
  not proof of a complete owner personalization or on-device signing workflow.
- [Verified boot device state](https://source.android.com/docs/security/features/verifiedboot/device-state):
  locked/unlocked state and user supplied roots on supporting hardware.
- [Arch system maintenance](https://wiki.archlinux.org/title/System_maintenance): rolling
  releases still require compatible upgrades, local rebuilds and configuration handling.
