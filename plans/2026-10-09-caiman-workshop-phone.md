# Pixel 9 Pro (caiman) workshop phone

Status: accepted by the owner on 2026-10-09. Its eight owner decisions remain open, and each is
needed only before the stage that names it. Independent reviews in four rounds checked every rule
that protects the phone against Google's, GrapheneOS's and Android's own documentation and code.

This plan turns the [Pixel integration](2026-09-21-pixel-integration.md) workstream into stages for
one device, the owner's Pixel 9 Pro, codename caiman, run in workshop mode. It enables nothing by
itself. No stage touches the phone without a separately approved session. The
[caiman readiness assessment](2026-09-08-caiman-readiness.md) remains a reference.

## Why

The [vision](../docs/vision.md) builds in a testable order. Cuttlefish comes first, then a SystemUI
component change and recovery workflow, then Pixel integration "using maintained device/vendor
knowledge and explicit hardware qualification". The
[SystemUI component loop](2026-09-22-systemui-component-runtime.md) has passed on one platform
cohort. The earlier Pixel plans set gates, but no procedure for a real phone.

On 2026-10-09 the owner offered their own phone as the test device, on the conditions below. Those
conditions set the priorities. The phone must never be bricked, the essentials must keep working,
and every flash is a deliberate act with a way back that was checked beforehand.

A desk study of caiman, checked against GrapheneOS, Google and Android sources, found four things
that shape this plan:

- **The pinned base is too old for the phone.** GrapheneOS 2026081300 supports caiman, but it
  carries August 2026 firmware. The [upstream records](../upstream/README.md) show that it lacks 51
  known frameworks/base security fixes that 2026100600 has. All six Andrix patches still apply to
  2026100600 at fuzz 0, two of them at line offsets. A source tree at 2026100600 is now synced
  beside the pinned tree, with all 1,057 projects verified at the signed tag.
- **The vendor side is generated from Google's files.** GrapheneOS keeps no separate caiman device
  trees. Its adevtool supplies the device makefiles and generates the vendor module, firmware
  included, from Google's factory image. The owner has decided that Andrix may do the same.
- **A caiman build checks none of Andrix's neverallow rules.** adevtool switches the checks off for
  every device with extracted vendor policy. Andrix must replace that check, not copy the setting.
- **The Andrix layer is mostly independent of the device**, but its product, board, overlay and lab
  guards are keyed to the Cuttlefish product.

## Owner decisions already made

1. **The test device.** On 2026-10-09 the owner allowed their Pixel 9 Pro to be Andrix's hardware
   test device, on these conditions:
   - the phone must never be bricked;
   - it must keep working for the essentials;
   - factory resets are acceptable, and so is losing special apps;
   - every flash needs the owner's explicit approval of a specific build, a backup, and a way back
     prepared and checked in advance.
2. **Google's vendor files.** On 2026-10-09 the owner decided that Andrix Pixel builds may include
   Google's vendor files, extracted with adevtool as GrapheneOS does. Such builds may be published,
   matching the practice of GrapheneOS and LineageOS. The files stay out of the Andrix source
   repository. Nothing is published yet. Publishing a specific build is a release step that comes
   to the owner when a build is ready. The way back kits are no longer held.
3. **Running the phone unlocked (decision 1).** On 2026-10-09 the owner accepted running the phone
   unlocked for the length of this plan, after an independent review recommended bounded trials
   instead. The owner accepts that fixing a problem may take time. The owner also accepts the
   remaining risk that "Never brick it" describes.
4. **The flashing computer (decision 5).** On 2026-10-09 the owner first chose their own laptop,
   then the same day chose the build machine instead, because the flow is simpler there. The owner
   authorised the download of Google's platform tools. A USB rule that lets only the project's
   account open the phone comes later, before the phone is first connected.

The vendor files decision did not cover who downloads Google's images. Google's download page asks whoever
downloads to accept its terms. So this plan proposes that the owner downloads them, or authorises
each such download explicitly, adevtool's included.

This plan also relies on earlier accepted decisions:

- Workshop operation is a legitimate mode. It is unlocked, with weaker physical tamper and theft
  protection than a locked system. A locked mode with owner controlled keys comes later
  ([architecture](../docs/architecture.md#workshop-and-locked-operation)).
- Boot and modification state must be reported honestly, including workshop operation.
- [Signing recovery](2026-09-22-installation-key-recovery.md) defaults to an encrypted recovery
  bundle held by the owner and a protected signing copy on the device. No personal installation
  keys exist yet.
- Detailed operating records and raw captures remain private ([current work](current.md)).

## Starting facts

- **The phone.** It starts as a standard GrapheneOS installation, locked, with OEM unlocking off,
  as GrapheneOS's guide leaves it. Its exact build and the owner's answers to decision 4 stay in
  private records.
- **The build tag.** A phone build uses a GrapheneOS tag that meets the version criterion at each
  session, and never the pinned 2026081300.
- **Preview fixes.** GrapheneOS's security preview releases carry fixes that are not in public
  source, so no Andrix build can include them. For the preview of 2026100600, GrapheneOS lists 122
  such fixes, 8 critical and 114 high. A phone that moves from a preview release to Andrix loses
  them, and the owner has been told so.
- **Storage.** The build machine has room for the second tree and a caiman build.

## Open owner decisions

These belong to the owner. Each lists its options, their consequences, a recommendation and the
stage that needs it. Decision 1 is decided, and its facts stay here for the record.

### 1. Running the phone unlocked

Decided on 2026-10-09: accepted for the length of this plan, as "Owner decisions already made"
records. A strong lock screen credential and keeping the phone in the owner's physical control
remain recommended.

Rule 2 excludes locking until a separate locked mode plan exists. So the phone runs unlocked from
stage 7 until it returns to GrapheneOS for good.

- **Accept for the length of this plan.** The phone shows the ORANGE warning at every boot.
  Android's suggested text for that screen says: "Any data stored on the device might be available
  to attackers. Do not store any sensitive data on the device." This plan restores the owner's data
  onto that phone. The phone accepts any OS flashed to it without a wipe. Because the warning shows
  at every boot anyway, a phone whose OS someone else replaced looks the same at boot. Android
  recommends showing a key ID on that screen, but whether this phone does is unverified. Unlocking
  wipes all data and the secure element. Apps that check device integrity may refuse to run.
- **Wait for the locked mode plan.** The phone track waits with it.

Recommendation: accept, knowing Android's warning applies to the data restored onto the phone. Use
a strong lock screen credential and keep the phone in the owner's physical control. Needed before
stage 7.

### 2. Custody of the phone's signing keys

- **A private workshop key set for this phone.** It is generated for this phone and encrypted under
  a passphrase only the owner holds, with a copy in the owner's recovery bundle. Every build reuses
  it, because changing keys needs a wipe. Signing needs the passphrase each time. The release
  script decrypts the keys into memory on the build machine for the length of the run, so custody
  also depends on that machine and its swap. Moving to the personal installation identity later
  costs one wipe, which the owner has accepted. A lost key set forces a wipe at the next build, but
  cannot brick an unlocked phone.
- **The personal installation identity first.** This blocks the phone until provisioning is
  implemented and qualified.

Public test keys are not an option, as "Boot and trust" explains. Recommendation: the workshop key
set, signed on a build machine whose swap is encrypted or off. Needed before stage 6.

### 3. Build variant

- **user.** adb is off by default, and it asks for authorization even while the phone is unlocked,
  because GrapheneOS's build sets `ro.adb.secure=1` on user builds. GrapheneOS calls user builds
  "significantly more secure". Diagnosis on the phone is harder.
- **userdebug.** adb is on by default, and the adb daemon skips authorization on such builds unless
  `ro.adb.secure` is set, which GrapheneOS's build does not do for them. So after every wipe, until
  USB debugging is switched off, anyone with a cable gets adb and root. The `su` domain is also
  permissive. Choosing userdebug therefore needs three conditions:
  - the product sets `ro.adb.secure=1`, and a build change keeps adb off by default, because
    Android's build turns adb on whenever `ro.debuggable=1`;
  - "USB debugging off" is part of essentials item 15;
  - the gate's permissive check allows exactly `su`.

Recommendation: user. Needed before stage 6.

### 4. What counts as essential

The proposed [essentials checklist](#essentials-checklist) decides when a flash passes and when the
phone goes back to GrapheneOS. Anything not on it may break unnoticed. The owner confirms the list
and answers these questions:

- physical SIM or eSIM;
- whether sandboxed Google Play is used, which changes the push notification check;
- tethering, car Bluetooth and wireless charging, where used;
- which apps and services the owner depends on daily, such as messaging, authentication, VPN or
  Wi-Fi calling;
- how long the observation window for items that need time lasts, and how the owner stays
  reachable while it runs.

The answers stay in private records. Recommendation: confirm the list as proposed, with these
answers and a window of two days. Needed before stage 7.

### 5. The flashing computer

Decided on 2026-10-09: the build machine, as "Owner decisions already made" records. The owner
chose it knowing that processes there could reach the phone while it is connected, which is why the
recommendation below preferred a separate computer. These conditions keep that exposure small:

- The machine runs on bare metal, and the phone connects directly to a rear port with a good cable.
- A USB rule installed by the owner as root lets only the project's account open the phone. The
  phone is connected only during sessions.
- The readings, the plan's checkers and each complete script run from the project's account.
  Nothing is written before the owner approves it in that session. The sealed platform tools'
  directory comes first in `PATH` for every script, because the official script finds `fastboot`
  through `PATH`.
- The build lock is held for the whole session, so no build or emulator runs during a write.
- Each write runs as its own background service, so nothing else in the session can interrupt it.
- The owner's laptop keeps GrapheneOS's web installer as a second way back.

GrapheneOS's guide fixes what the computer needs (rule 8). The owner's choice is which computer.

- **A bare metal computer the owner chooses.** It gets platform tools r35.0.2, checked against the
  SHA-256 that GrapheneOS publishes, and udev rules. These are changes outside the project.
- **The build machine**, only if it is bare metal with a direct USB port. Processes running there
  could then reach the phone over USB.

GrapheneOS's web installer in a browser with WebUSB serves as a second way back on either computer.
It installs only the current official release, so it cannot flash Andrix, and it serves a way back
only when that release is one the session's approval names.

Recommendation: a separate computer the owner controls. Needed before stage 2.

### 6. What may be recorded from the phone

Phone logs contain personal data. Without them, some failures cannot be diagnosed.

- **Targeted readings only.** Boot state, verity mode, SELinux mode, versions, and the specific
  service state that a check needs.
- **Full logs or bug reports** when diagnosing a failure.
- **Pass or fail notes only.**

Recommendation: targeted readings by default, and full logs only with the owner's approval at the
time, deleted once the finding is written up. Everything stays private and is never committed.
Needed before stage 7.

### 7. Update cadence

From the first Andrix flash, the phone lacks the preview fixes. Each week that Andrix lags behind
GrapheneOS adds public fixes it lacks as well. In the 31 days from 2026-09-05 to 2026-10-06,
GrapheneOS published 8 releases for the Pixel 9 Pro. Following each one means a build, an approved
session and, until updates that keep data are qualified, a wipe and a restore every time.

A security or firmware release here is one that raises the security patch level or changes
firmware. By the release notes, 3 of the 8 changed firmware and 3 raised the patch level. One did
both, so 5 of the 8 count.

- **Follow every stable caiman release**, within a lag limit.
- **Follow only security or firmware releases**, within a lag limit. The other releases, which can
  carry kernel updates and other fixes, wait for the next one that counts.
- **No commitment.** Return to GrapheneOS whenever Andrix falls behind.

Recommendation: security or firmware releases until updates that keep data are qualified, then
every stable release. In both cases the lag limit is two weeks, counted from the GrapheneOS release
date. Past it, the phone returns to GrapheneOS until Andrix catches up. Needed before stage 8.

### 8. Approving the way back in advance

A failed flash leaves the phone needing another flash. Rule 9 asks how that one is approved.

- **Named in advance.** Each session's approval names the build to flash and every artifact the
  way back may write: the official GrapheneOS release, and Google's stock image if the stock route
  is allowed, each with its wipe effect. That release is no older than the build's base tag, so the
  way back never writes older firmware than the build just wrote. A return within that session to
  a named artifact needs no new approval. If the stop points or their exception require any other
  release, the session stops in fastboot mode, where nothing is written, until the owner approves
  that release.
- **Approved at the time.** The phone waits for a fresh approval before the way back runs.

Recommendation: named in advance, so no decision is improvised under pressure. Needed before
stage 7.

## Never brick it

Bricked here means the phone can neither boot an OS nor be flashed. Every session starts with the
stop points below. The rules after them hold throughout, and each names its source. Where a source
states a general Android rule rather than a Pixel fact, the rule says so.

These rules make an unrecoverable state very unlikely, but they cannot make it impossible. No
source read for this plan says what an interrupted firmware write does, for example. Each flashing
session carries that remaining risk, as GrapheneOS's own installation does, and the owner approves
each session knowing it.

### Stop points at the start of every session

The phone keeps updating itself, and the build number in Settings cannot show an update that is
installed and waiting for a reboot. Readings from an earlier session therefore approve nothing.

1. **No update pending.** In the OS, no update is downloading, installing or waiting for a reboot.
   If one is, wait for it, reboot into it, and start again. On GrapheneOS the system updater shows
   its state. Andrix carries no updater, so on Andrix only a sideloaded update can be pending. The
   session also records the phone's release channel, which must be Stable, and whether security
   previews are enabled.
2. **Fixed readings.** On the bootloader screen that shows "Fastboot Mode", a fixed script runs
   only these commands: `fastboot getvar product`, `is-userspace`, `version-bootloader`,
   `version-baseband`, `current-slot`, `unlocked` and `snapshot-update-status`, then
   `fastboot flashing get_unlock_ability`. It runs the sealed platform tools' `fastboot`, named by
   its path, and first records that fastboot's version, which contacts no phone. A variable the
   bootloader does not know makes that one reading fail. The script records it as unanswered and
   goes on. Any other failure is not an answer, and the readings are refused.
3. **Continue only if** the product is caiman, `is-userspace` does not read `yes`, and
   `snapshot-update-status` reads `none`. Recovery's own fastboot always answers `is-userspace`
   with `yes`, so an unanswered `is-userspace` means the bootloader. A merge can keep that status at `merging` for a while
   after an update boots, so the readings may need repeating later. From stage 7 on, the unlock
   ability must also read 1, and from stage 8 on `unlocked` must read `yes`. If it does not read
   `yes`, the session stops, and only a new approved session that repeats stage 7 may unlock again.
   If the OS cannot boot then, that session relies on the unlock ability of 1 that rule 1 keeps,
   instead of switching OEM unlocking on in the OS.
4. **The version criterion.** Every image that writes firmware belongs to a GrapheneOS release.
   An Andrix build belongs to its base tag, and a security preview to its base release. Google's
   stock image belongs to the earliest release built from that stock build, as adevtool at that
   release records, for example CP3A.261005.005 for 2026100600. The image may be written only if
   each firmware reading equals the version that one of the session's known releases records, and
   one of these holds:
   - its release is newer than the phone's release, by GrapheneOS's release numbers;
   - it has the same stock build ID as the phone's release.

   The session's known releases are every release the phone's record carries over from earlier
   sessions, its release at the session's start among them, and every release written in this
   session. Carrying them over keeps a write interrupted in one session from blocking the next. The
   comparison still uses the phone's release, the newest of them, so the carried releases allow
   only writes that do not go back. A reading that matches none of them refuses every write,
   because it may come from newer firmware. A partial write, such as a new bootloader beside an
   older radio, still matches known releases, so the whole script can run again as rule 4
   requires. Every known release then carries firmware no newer than the image's, on this plan's
   assumption that a newer release never ships older firmware, so no component goes back.

   Stock build IDs are compared only for equality, never ordered, because adevtool's index lists
   carrier variants beside their base builds. A stock image that no GrapheneOS release is built
   from, such as a carrier variant, is refused. This one criterion applies everywhere in this plan.

   Its inputs are fixed so that no typed value can approve older firmware:
   - **The image's identity** is read from the image itself, never typed: the signed build number
     of a GrapheneOS zip, the signed `vbmeta` of an Andrix zip, and the stock build inside Google's
     image. The decision names the image's SHA-256, and only that file is written. An Andrix zip's
     `vbmeta` must verify against the workshop key recorded for this phone. Its `android-info.txt`
     and stock build must equal its base tag's record, and its bootloader and radio images must be
     byte identical to the official kit of that tag.
   - **The phone's release** is the release recorded at the session's start, and it counts as the
     newer of that release and any image written in the session. The checker keeps both in its
     own session record, written before each write runs, so neither is typed. Readings carry the
     time they were taken, and readings older than the session's last write are refused. Fresh
     readings come before each write.
   - **The records** cover every signed caiman release tag from the phone's release through the
     image's release. The tag list comes from the signed tags of GrapheneOS's manifest repository,
     each with its verified signature, never from a page or a file passed in. Each record is bound
     to the adevtool revision that its tag's manifest pins, and names the tree commit it was
     derived from. If any is missing, the image is refused.
   - **Release numbers** end in 00 for a release and 01 for its security preview. Any other ending
     is refused until a rule covers it. GrapheneOS states that a security preview uses the same
     sources as its regular release, which implies the same firmware. The readings are still
     compared with the known releases' recorded versions.
   - **The approval.** The session's approval must name the image. An image that meets the
     criterion but is not named waits in fastboot mode for a fresh approval. Nothing is written in
     stage 3, and no Andrix image is written before stage 8.

**When the OS does not boot.** After a failed flash the OS may not boot, so stop point 1 cannot
run. It is then skipped. The phone's release then counts as the newer of the last release
recorded for it and the release of any image written in this session. While an update is pending,
only the current stable official GrapheneOS release, or its security preview, may be written,
through its complete script or the web installer. That release is read from
`releases.grapheneos.org/caiman-stable` at that moment, with the time of the fetch recorded. It
counts as newer than the phone's release, because the phone stays on the Stable channel and no
stable update can be newer than it, with a security preview counted as its base release. If the
phone's release counts as newer than the current stable release, nothing is written, and the
session stops in fastboot mode. When it is unknown whether an update is pending, it counts as
pending. If that release is not one the session's approval names, the session waits in fastboot
mode for a fresh approval before writing it. If `snapshot-update-status` then
reads anything but `none`, stop point 3 does not end the session.
Instead, only the complete GrapheneOS script or the web installer may run. Both cancel the pending
update themselves. The web installer does so in its code. GrapheneOS's fastboot writes
`fastboot snapshot-update cancel` into the scripts it generates, but that stays unverified until
the script in a real install zip is read. The version criterion still applies.

The script writes its own bootloader first. So the requirement check inside `fastboot update`
compares against that new bootloader, not the phone's original one, and no tool catches an older
kit. The fastboot readings also cannot show the secure element firmware in the vendor image. That
is why the criterion rests on GrapheneOS releases and their stock builds, which fix all the
firmware. Sources: GrapheneOS's
`fastboot.cpp` and its web installer, which reads the same variables and cancels pending updates
before it flashes. Android's [Virtual A/B](https://source.android.com/docs/core/ota/virtual_ab)
page, on the merge after boot. The fastboot protocol's description of `is-userspace`.

### Rules

1. **From stage 7 on, keep OEM unlocking enabled, and check it at every session.** Android's
   guidance is that fastboot refuses to unlock unless OEM unlocking is enabled. The setting can
   only be enabled from a booted OS, and it persists across reboots and factory resets. GrapheneOS
   confirms for Pixels that it is enabled from within the OS. A locked phone whose OS cannot boot
   while OEM unlocking is off cannot be unlocked or flashed by its owner. GrapheneOS's setup wizard
   tries to switch OEM unlocking off whenever its final toggle is left checked, which is the
   default, whatever the lock state. An Andrix caiman product inherits the same wizard. So the
   toggle is unchecked at every setup. `fastboot flashing get_unlock_ability` must read 1 at the
   start and end of every session, and that reading decides.
   Sources: [Android, lock and unlock the bootloader](https://source.android.com/docs/core/architecture/bootloader/locking_unlocking).
   [GrapheneOS CLI install guide](https://grapheneos.org/install/cli), "Enabling OEM unlocking" and
   "Disabling OEM unlocking". GrapheneOS's setup wizard source. The fastboot command help.
2. **Never lock the bootloader in this plan.** A locked phone boots only an OS signed by Google's
   key or by the key in `avb_custom_key`, and it refuses to flash, format or erase partitions. With
   a mismatched key it shows the RED "no valid OS" screen and cannot boot. Getting out then needs an
   unlock, which only rule 1 still allows. Every change of lock state wipes all data. So every route
   to a lock stays unused:
   - `fastboot flashing lock`;
   - the web installer's "Lock bootloader" button;
   - the relock that Google's factory image page asks for after a stock flash;
   - any lock option in Google's flash tool, if it offers one, which was not confirmed.

   Outside a complete script's own lines, erasing `avb_custom_key`, which the web installer offers
   as "Remove non-stock key", happens only as the first step of the return to stock. The official
   script erases it and then writes the release's key. Locking belongs to the separate locked mode plan.
   Sources: [Android, device state](https://source.android.com/docs/security/features/verifiedboot/device-state).
   [Android, boot flow](https://source.android.com/docs/security/features/verifiedboot/boot-flow).
   The [AVB README](https://android.googlesource.com/platform/external/avb/+/refs/tags/android-17.0.0_r1/README.md),
   "Locked and Unlocked mode" and "Pixel 2 and later". The GrapheneOS CLI and
   [web install](https://grapheneos.org/install/web) guides.
   [Google's factory image page](https://developers.google.com/android/images).
3. **Flash firmware only from the official release, and only under the version criterion.** The
   firmware's verification key and rollback index are burned into fuses, and firmware security
   updates raise the index. Google documents bootloader rollback increments after which older builds
   cannot be flashed and booted: Pixel 6 and 8 in May 2025, Pixel 10 in May 2026. None is listed for
   the Pixel 9 as of 2026-10-08. So the bootloader and radio images must be byte identical to those
   in GrapheneOS's official install zip for the same release. The vendor image also carries the
   secure element's firmware and its updater, so an older vendor image counts as older firmware.
   That the OS applies that firmware at boot is inferred, not verified. The fastboot readings
   cannot show it, so the version criterion rests on releases and their stock builds. Check
   Google's page for new
   Pixel 9 notices before every session.
   Sources: the GrapheneOS CLI install guide, "Verifying installation". Google's factory image page.
   The [GrapheneOS build guide](https://grapheneos.org/build) on why firmware is not built from
   source. adevtool's file list for caiman's vendor module.
4. **Only listed commands, complete scripts and complete updates run.** Google warns about the
   state after an update: "The inactive slot contains an older bootloader". If the active slot is
   then flashed with a build that fails to boot, the phone falls back to that slot and "enters an
   unbootable state". GrapheneOS's updates use the same A/B mechanism, so every session may start
   in that state. An Andrix build is the likeliest thing to fail to boot. The install script
   protects against this by writing the bootloader to both slots before anything else. So in
   fastboot mode only these run:
   - the fixed reading script;
   - `fastboot flashing unlock`, or the web installer's unlock, in stage 7 only;
   - `fastboot erase avb_custom_key`, or the web installer's "Remove non-stock key", as the first
     step of the stock route only;
   - a complete flash script that was read line by line beforehand, run from its first line, or the
     web installer's flash of an official release;
   - `fastboot reboot` or `fastboot reboot-bootloader`.

   Nothing else runs. That excludes `fastboot set_active`, the `--slot`, `--set-active` and
   `--force` options, and any single step of a script. A script's own lines are the only uses of
   the slot options. After any failure, the phone goes back to the bootloader screen that shows
   "Fastboot Mode", and the whole script runs again. A failure can leave the phone in recovery's own
   fastboot instead, which reads `is-userspace` as `yes`.

   An update that keeps data is a complete update sideloaded through recovery. After its first
   successful boot, the stop points run again and the same full update is applied a second time,
   as Google's remedy does. After each of the two boots, `current-slot` reads a different slot and
   `version-bootloader` reads the new version. That shows both slots hold the new bootloader without
   switching slots by hand. Google's stock flash script is read under this rule before the stock
   route uses it.

   Sources: Google's factory image page. GrapheneOS's
   `device/common/generate-factory-images-common.sh`, its `fastboot.cpp`, and the
   [GrapheneOS usage guide](https://grapheneos.org/usage), "Sideloading".
5. **Right device, official script, official order.** The script refuses any product other than
   caiman. The legacy form of the script warns "This would likely brick your device". The form
   that `fastboot optimize-factory-image` writes says "Error: this factory image is for caiman",
   and it also checks `slot-count`, `max-download-size` and `current-slot`. The script refuses
   fastboot older than 35.0.1. GrapheneOS's guide covers custom builds as well as official ones, and asks for its steps
   "without skipping, reordering or adding any steps". This plan departs from it in two ways only.
   The bootloader stays unlocked, and the setup toggle that disables OEM unlocking is unchecked. The
   readings this plan adds write nothing. Andrix's script runs only after it has been compared line
   by line with the official script for the same release.
   Sources: `generate-factory-images-common.sh`. The GrapheneOS CLI install guide.
6. **Write only what the official script writes.** For caiman the script writes the bootloader to
   both slots, then the radio. It erases `avb_custom_key` and writes the release's key. It runs
   `oem uart disable` and erases `fips`, `dpm_a` and `dpm_b`. It writes the OS images, through
   `fastboot update` in the legacy form or image by image in the other form. Both forms always wipe
   data: the legacy form with `-w`, and the other form by erasing `userdata` and `metadata`. Nothing else is flashed, erased or formatted. Some partitions hold data
   written in the factory. GrapheneOS names one example, the carrier ID on `persist`.
   Sources: GrapheneOS's `script/generate-release.sh`, which selects those steps for caiman, and
   `generate-factory-images-common.sh`. The GrapheneOS CLI install guide, "Prerequisites".
7. **Keep the vendor side identical to the official build.** `vendor`, `vendor_dlkm`,
   `vendor_boot`, `vendor_kernel_boot`, `dtbo`, the kernel and its modules stay identical in content
   to GrapheneOS's release of the same tag. A mismatch can stop the phone booting or break the
   essentials. That this is recoverable from fastboot while the phone is unlocked is reasoned from
   unlocked boot behavior, not verified. It also creates the unmaintained mixture of generations
   that the Pixel plan warns against.
   Sources: the [Pixel integration plan](2026-09-21-pixel-integration.md). The GrapheneOS build
   guide on what device support needs.
8. **Flash from a safe setup.** GrapheneOS's guide documents these needs:
   - a bare metal computer running a supported OS, with at least 2 GB of free memory and 32 GB of
     free storage;
   - a direct USB port and a good cable, preferably the phone's own, with no hub and no virtual
     machine passthrough;
   - fwupd stopped;
   - `TMPDIR` pointed at a directory with room, when `/tmp` is too small;
   - no touching the phone until the script ends.

   No source read for this plan states what an interrupted firmware write does, so treat it as
   unrecoverable. As project precautions without a source, charge the battery, disable the
   computer's sleep and keep a second phone at hand.
   Source: the GrapheneOS CLI install guide, "Prerequisites", "Working around fwupd bugs on Linux
   distributions", "Flashing factory images" and "Troubleshooting".
9. **Every flash is approved and prepared.** The owner approves the specific build. A restore from
   the backup has been tested. The way back is prepared and checked. The way back flash itself is
   approved as decision 8 sets. Under either answer to decision 8, a release that no approval names
   is never written without a fresh approval.
   Source: the owner's decision of 2026-10-09.

## The way back

The way back restores a working OS, not data. Data comes back from the backup. It works only while
the bootloader still works and rules 1 and 2 hold.

**Back to GrapheneOS, the main route.** From fastboot mode while unlocked, after the stop points,
run the `flash-all.sh` of GrapheneOS's official caiman install zip, or use the web installer. When
the OS does not boot, the stop points' own exception applies. The script GrapheneOS generates
writes both bootloader slots and the radio, puts GrapheneOS's key in `avb_custom_key` and wipes
data. In setup, uncheck the toggle that disables OEM unlocking. Leaving the track for good means
following GrapheneOS's own guide, which ends locked. That is the owner's choice and happens outside
this plan's sessions.

**Back to stock, the second route.** Erase `avb_custom_key` first. Then flash Google's caiman
factory image with its own script, read under rule 4. Google's web flashing tool has no script that
can be read, so it is used only with its default options, nothing forced. Do not relock.

Both kits are official, unmodified images for this phone. They stay in private storage and are
never republished.

### Checks that need no phone

- The GrapheneOS zip verifies with
  `ssh-keygen -Y verify -f allowed_signers -I contact@grapheneos.org -n "factory images" -s caiman-install-VERSION.zip.sig < caiman-install-VERSION.zip`.
  The output must read
  `Good "factory images" signature for contact@grapheneos.org with ED25519 key SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM`.
  The `allowed_signers` file must hash to the digest already pinned in `upstream/bases/`, which
  equals the file GrapheneOS serves today.
- **Release identity.** A validly signed older zip would also pass that check. So the build number
  in the fingerprint properties of the zip's signed `vbmeta`, not only its file name, must name the
  expected release, and
  `releases.grapheneos.org/caiman-stable` must name that release or a newer one.
- The zip's `avb_pkmd.bin` hashes to the value GrapheneOS publishes for the Pixel 9 Pro,
  `f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86`. Android derives the boot
  screen's key ID from the same public key form that `avbtool extract_public_key` writes.
- The zip's flash script checks for caiman and for fastboot 35.0.1. It writes both bootloader
  slots, then the radio, `avb_custom_key`, the UART, FIPS and DPM steps, and a wiping update. It
  never locks. GrapheneOS produces the published script with `fastboot optimize-factory-image`, so
  it is read from the real zip, not assumed.
- Its `android-info.txt` names board caiman and its release's bootloader and baseband versions. For
  2026100600, adevtool records `ripcurrentpro-17.0-15819938` and
  `g5400c-260604-260807-B-16035863`, from stock build CP3A.261005.005. The comparison with the
  phone happens at the session's stop points.
- The dynamic partition images are rebuilt from the zip's super splits. `simg2img` merges every
  split into one image, because `lpunpack` refuses sparse input, and `lpunpack` extracts the
  partitions, whose `_b` copies must be empty. Both tools are built from the pinned tree and pinned
  by SHA-256. The release identity check above and gate step 3 depend on these images.
- `avbtool verify_image` passes on its `vbmeta`, with those images beside it. The public key
  embedded there is byte identical to its `avb_pkmd.bin`, and the rollback index is the release's
  patch timestamp.
- Google's factory image matches the SHA-256 that adevtool's build index records for that stock
  build. Google's page served today shows no table of checksums.
- On the flashing computer, `fastboot --version` reports 35.0.1 or later, and the platform tools
  zip matched GrapheneOS's published SHA-256. The USB rule is installed, fwupd is absent or
  stopped, and the web installer loads on the owner's laptop.
- The runbook is written with its stop points, and it is readable away from the flashing computer.

### Checks that need the phone

These are the stop points, in an approved session. GrapheneOS's web installer reads `unlocked` and
`snapshot-update-status` on caiman too, which supports relying on them.

## Build inputs and design items

### Inputs

- **Tag.** The newest stable caiman release at build time, and one that meets the version criterion
  against the phone's release. Today that is 2026100600, with stock build CP3A.261005.005. Its
  manifest tag verifies against the pinned allowed signers. The second tree holds it, and builds use
  that tree once the build slot is free.
- **Device makefiles.** GrapheneOS's adevtool at the tag's revision supplies them. It needs Node.js
  24 LTS and yarn. Node.js comes from the official download, checked against its published checksum
  and kept in project storage, not installed as a host package. adevtool's own lock file pins the
  packages it installs.
- **Vendor module.** adevtool downloads Google's factory image for the tag's stock build,
  CP3A.261005.005 for 2026100600, from Google's download server. It checks the image against the
  SHA-256 in its build index and then generates `vendor/google_devices/caiman`. Its output must
  pass adevtool's check against the file hashes in its vendor specification. Under this plan's
  proposal, the owner authorises that download explicitly. adevtool builds its host tools with the
  platform build, so this input needs the build slot.
- **Kernel.** The prebuilt caimito 6.1 kernel, modules and device trees at the tag. They changed
  between 2026081300 and 2026100600.
- **Firmware.** The tag's bootloader and radio images, from Google's image through adevtool, never
  built from source.
- **Andrix.** A reviewed patch directory for the tag, which the patch tools require before they
  accept a new base. The carry report found that all six patches apply at fuzz 0. Only the normal
  image composition goes to the phone: no lab vehicle, test hook or native account lifecycle writer.
- **Keys.** The workshop key set from decision 2.
- **Build steps.** GrapheneOS's own: `m vendorbootimage vendorkernelbootimage target-files-package`,
  then `m otatools-package`, `script/finalize.sh` and `script/generate-release.sh`, extended for
  Andrix's signing.

### What differs from the Cuttlefish product

- caiman is `armv9-a` with memory tagging. Heap tagging covers every binary built from source,
  kernel tagging is forced on and kernel tag faults panic. Latent memory bugs in Andrix native code
  will crash.
- `PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO` is set, so native code that uses `PAGE_SIZE` does not compile.
- 64 bit only carries over.
- caiman has one `vbmeta`. Andrix tooling written for Cuttlefish's four vbmeta images needs a caiman
  variant.
- The kernel is GKI 6.1 with Pixel modules. The emulator's 6.12 kernel is not a substitute.
- Keys and credential encryption use Trusty KeyMint and the phone's secure element. Cuttlefish
  established none of these hardware properties.
- pKVM and `pvmfw` are present. Andrix does not depend on them.
- There are no snapshots and no host disk inspection. Every reset is an approved flash.
- The dynamic partitions must fit caiman's super partition limit beside a real vendor partition.

### Design items

These must be designed for caiman, not copied from the Cuttlefish product.

1. **Product and board composition.** `PRODUCT_DEVICE` stays `caiman`, because the generated module
   registers its firmware only for that device and GrapheneOS's release scripts are keyed to it.
   The generated board file is marked "do not edit". Andrix needs a reviewed way to add its policy
   directories, M4 definitions and `config.fs` without editing generated files. The Cuttlefish
   board keys these on the Cuttlefish product name, so none of them reach a caiman build today.
   Every lab vehicle must keep refusing any product other than its Cuttlefish one.
2. **The neverallow check.** adevtool sets `SELINUX_IGNORE_NEVERALLOWS := true` for every device
   with extracted vendor policy, and its 2026100600 revision still does. It also drops the
   `neverallow` statements from that policy. Under the flag, `secilc` runs with `-N` at both policy
   stages, and the neverallow test module only writes its timestamp. So a caiman build checks none
   of Andrix's rules. There are 22 in `owner/sepolicy` and 2 in `owner/platform/sepolicy`. The
   `owner-session-policy` patch adds 4 more to `system/sepolicy` and narrows some AOSP rules for the
   owner domain. The replacement is a separate check after the build.
   - It checks the policy the phone loads, which is the vendor partition's precompiled policy. Init
     uses that policy only when its hash files match the system, system_ext and product policies,
     so the check confirms they match.
   - It checks the variant that is flashed, built with `andrix_owner_session=true`, so the owner
     policy is really present.
   - `sepolicy-analyze` runs in neverallow mode with Andrix's rules in their expanded form, using
     `-w`. Any warning fails the check, because names it cannot resolve are otherwise ignored
     silently.
   - Each Andrix rule has its own mutant policy that violates it, and every mutant must fail.
   - The AOSP rules, as patched in the Andrix tree, run against the same policy. A violation that
     GrapheneOS's own release policy also shows is reported as coming from the vendor policy. Any
     other violation fails the gate. This also covers the AOSP rules the patch narrows.

   None of this is built or tested yet.
3. **Device services overlay.** Andrix's overlay replaces `config_deviceSpecificSystemServices` with
   one service, `OwnerLifecycleService`. It adapts owner sessions to Android's user and storage
   lifecycle, and it is not a native account lifecycle writer. The overlay's own comment warns that
   other device cohorts must keep their existing services. At the pinned tag no generated caiman
   source overlay sets the array. Prebuilt overlays and the newer tag are unchecked. Merge with
   caiman's effective array, or register the service another way.
4. **Owner resource controls.** `andrixd` relies on `memory.max`, `memory.swap.max` and
   `memory.oom.group` in a cgroup2 directory for the owner UID. At the pinned tag the generated
   caiman product installs a vendor `task_profiles.json` and no vendor `cgroups.json`. Whether
   caiman exposes a version 2 memory controller there is unverified. Without it, owner sessions fail
   closed. That is safe, but broken.
5. **Product identity.** The generated product names the brand google and the model Pixel 9 Pro,
   with separate identity values for attestation. Choose brand, model and fingerprint so the phone
   is honest without impersonating GrapheneOS or Google, and without breaking vendor or carrier
   matching. Keep the attestation values as generated.
6. **Signing and updates.** GrapheneOS's release script lists every APEX it signs. `dev.andrix.usr`
   must be added, with the release key and the verified boot key as for the others. Console trust
   must use the workshop set instead of the lab certificate. The guard against `OFFICIAL_BUILD`,
   which keeps the Updater out, must cover every Andrix product. Updates that keep data follow rule
   4. They must never lower any patch level, because KeyMint keys become unusable after a rollback,
   and they must keep the same keys.
7. **Hardware qualification method.** Few flashes, no snapshots, the essentials checklist, emergency
   calling never dialed, and recording within decision 6.
8. **Connected policy for Pixel components.** Review remote key provisioning, carrier provisioning,
   eSIM, location assistance and connectivity checks against the accepted networking policy. Do not
   carry the emulator's blank provisioning host onto the phone.
9. **Boot state shown to apps.** GrapheneOS's build adds
   `ro.appcompat_override.ro.boot.verifiedbootstate=green` to every user build. Its comment reads
   "at least one app (Revolut) refuses to work with yellow verifiedbootstate". Processes that start
   with the override enabled then read green instead of the real boot state. Which apps those are
   was not traced. The accepted rule is that boot state is reported honestly, and in workshop mode
   the real state is orange. So Andrix does not carry the override. That needs a reviewed change,
   because the property comes from GrapheneOS's build script for every user build. Apps that refuse
   any state other than green may refuse to run. The owner accepted losing special apps.

## Boot and trust in workshop mode

- **Unlocked throughout.** From stage 7 until the phone returns to GrapheneOS for good, the
  bootloader stays unlocked (decision 1). The phone shows the ORANGE screen at every boot and
  reports `androidboot.verifiedbootstate=orange`. While unlocked, key, signature and rollback
  failures are not fatal, and the bootloader need not check or update rollback indexes.
- **Honest state.** Andrix reports the boot state and verity mode as they are, including workshop
  operation, and carries no override that tells apps otherwise (design item 9).
- **Workshop keys.** Every phone build is signed with the workshop key set from decision 2 through
  GrapheneOS's release signing. The set holds the keys the GrapheneOS build guide lists, an RSA 4096
  verified boot key and an SSH key for signing install zips. GrapheneOS signs every APEX with the
  release key and the verified boot key, so `dev.andrix.usr` needs no keys of its own in this plan.
  An APEX updated outside full OS updates would need its own key pair, as GrapheneOS's guide notes.
  The set is reused for every build. Signing decrypts it into memory on the build machine, so that
  machine's swap must be encrypted or off, as GrapheneOS's guide advises.
- **Never test keys.** Android's test keys are public. Android's own signing guide warns that
  anybody can then sign software that may replace or hijack the system's apps. GrapheneOS keeps
  such builds to a dedicated development device with no security requirements. This phone is not
  that device.
- **Verity on.** Builds ship with `vbmeta` flags 0. If decision 3 chooses userdebug, switching
  verity off is a deliberate owner act, and it is reported.
- **Custom boot key.** The first Andrix flash writes the workshop public key into `avb_custom_key`,
  as GrapheneOS's script does with its own key. If the phone were ever locked by mistake, it would
  then boot Andrix builds with a YELLOW notice instead of failing. The gate checks that this key is
  the one that signed `vbmeta`. Locking needs a fastboot command and a confirmation on the phone,
  and it wipes data. So this is a safety net, not a locked mode.
- **Patch levels in updates that keep data.** The rollback index is the security patch timestamp.
  An update that keeps data never lowers it, even while unlocked, because KeyMint keys stop working
  after a version or patch level rollback. A flash that wipes data is not bound by this.
- **Later.** The locked owner keyed mode is a separate future plan. Nothing here prepares or
  permits locking.

## Essentials and the gate

### Essentials checklist

Run after every flash. An item passes only when the owner sees it work. Notes stay short and hold
no personal content. Andrix's own features are checked separately, and their failure alone does not
send the phone back.

Items that need time, such as reconnection after sleep, the overnight alarm and overnight drain,
are checked over an observation window after the session. Its length is part of decision 4. During
the window the owner keeps another way to communicate.

1. **Boot and unlock**, with PIN and fingerprint. The fingerprint hardware never ran on Cuttlefish.
2. **Calls.** Place and receive, with VoLTE registered where the carrier uses it, the earpiece, the
   microphone, and the proximity sensor turning the screen off.
3. **Emergency calling.** Never dial an emergency number to test. Check that the emergency dialer
   opens from the lock screen. Use a carrier or regional test procedure if one exists. This shows
   that the dialer opens, not that an emergency call would connect.
4. **SMS and MMS**, sent and received. MMS also exercises mobile data and the APN.
5. **Mobile data**, and tethering if used.
6. **Wireless networks.** Connect, reconnect after sleep, and get through a captive portal.
7. **Bluetooth audio**, and the car's hands free system if used.
8. **Audio and vibration.** Speaker, earpiece, and wired and Bluetooth audio.
9. **Camera.** Rear and front, video, the torch and QR codes.
10. **Location.** An outdoor satellite fix and a maps app.
11. **Notifications and alarms.** Local and push notifications, and an alarm that fires overnight
    while the phone is idle.
12. **Charging and battery.** Wired and wireless charging. Overnight drain and temperature within
    the GrapheneOS baseline.
13. **Display and touch.**
14. **Files and backup.** USB file transfer, and the backup and restore route the owner uses.
15. **Integrity.** SELinux enforcing, the boot state reported honestly, still unlocked,
    `get_unlock_ability` still 1, USB debugging off, and fastboot mode reachable with the buttons.
16. **Updates.** Not testable until a second build exists. One forward update then becomes part of
    stage 9.
17. **The way back.** Checked before every flash, not after it.

NFC payments, banking apps and apps that check device integrity are not on the list, because the
owner accepted losing special apps. If an essential checked in the session fails and cannot be
fixed then, the phone goes back to GrapheneOS through the way back. A failure found during the
observation window leads to a new approved session, usually the way back to GrapheneOS.

### Before the baseline session

Before stage 7:

- the owner has answered decisions 1, 4, 5, 6 and 8;
- an estimate of the update workload under decision 7 is ready, so the phone is not unlocked
  without a way to keep it maintained;
- a restore from the backup has been tested;
- the GrapheneOS kit passes every check that needs no phone, and the runbook has been reviewed;
- the gate has passed for an Andrix build that meets the version criterion against the phone's
  current release;
- stage 8 is planned within three days of stage 7.

### Before asking for the first Andrix flash

1. **Provenance.** The tag's signature verifies. The Andrix commit and its patch profiles for the
   tag are recorded, and their inspectors pass. adevtool's file hash check passes. The Cuttlefish
   suite passes on the same Andrix commit and tag (stage 5).
2. **Comparison with GrapheneOS's release of the same tag.** Unpack both install zips and compare
   them partition by partition.
   - Bootloader and radio are byte identical.
   - `boot`, `init_boot`, `vendor_boot`, `vendor_kernel_boot`, `dtbo`, `pvmfw`, `system_dlkm` and
     `vendor_dlkm` are identical apart from signatures, verified boot footers and build identity
     properties.
   - `vendor` differs only in the same ways and in its precompiled SELinux policy and that policy's
     hash files, which Andrix's system_ext policy changes.
   - `system`, `system_ext` and `product` differ only by the Andrix delta, the keys and the build
     identity.

   Any other difference is unexplained. To separate build noise from Andrix's changes, an
   unmodified GrapheneOS build is then made with the official `BUILD_NUMBER`, `BUILD_DATETIME` and
   `OFFICIAL_BUILD=true`. It is compared, never flashed.
3. **Verified boot.** `vbmeta` is signed with SHA256_RSA4096 by the workshop key, not a test key.
   Its rollback index is the build's security patch timestamp, its flags are 0, and every OS
   partition has a descriptor. `avbtool verify_image --key`, given the workshop public key, passes
   on `vbmeta`. That checks the signature, the key and every descriptor. The zip's `avb_pkmd.bin`
   is byte identical to `avbtool extract_public_key` of the same key, so the custom boot key is the
   key that signed `vbmeta`. avbtool accepts the public half, so neither step needs the passphrase.
   The key's SHA-256 is recorded.
4. **Firmware.** The byte equality from step 2 holds, and the `android-info.txt` requirements match
   the official zip. The comparison with the phone happens at the session's stop points.
5. **Partitions.** The image names match the official zip. Every image fits its partition, and the
   super partition limits hold.
6. **Content.**
   - No test certificate or test key anywhere. That covers APK signatures, each APEX's container
     signature and payload key, the OTA certificates and `vbmeta`. Release signing replaces both
     keys of every APEX.
   - The build description and fingerprint end in `release-keys`, as release signing rewrites them.
   - No lab modules or patches, no proof policies and no native identity writer lab patch.
   - No emulator CE hooks such as `lock-ce-user0` and `delay-next-snapshot`, no emulator RKP
     profile and no native account lifecycle writer.
   - No Updater, and `ro.product.device=caiman`.
   - No `ro.appcompat_override.ro.boot.verifiedbootstate` property.
   - The gate runs `sepolicy-analyze permissive` on every build. A user build shows no permissive
     domain. A userdebug build shows exactly `su`, and it sets `ro.adb.secure=1` with adb off by
     default.
   - The neverallow check of design item 2 passes, and every one of its mutants fails.
   - The Andrix artifact oracles pass.
7. **Flash script.** It is read line by line against "Never brick it" and compared with the official
   script for the same release.
8. **Way back.** The kit passes every check that needs no phone. The GrapheneOS kit's release is no
   older than the base tag of the build to be flashed. Google's image meets the version criterion
   with that base tag in place of the phone's release.

## Backup and data

Unlocking wipes all data and the secure element. Every flash through an install zip's script also
wipes, as rule 6 describes. Keys bound to the secure element cannot be exported, so anything that depends
on them, such as some passkeys, must be enrolled again.

1. **Inventory.** The owner lists what must survive. That covers photos and files, contacts,
   calendar, SMS and MMS, and the call log. It also covers authenticator seeds, recovery codes,
   passwords, passkeys, messaging app backups with their passphrases, saved wireless networks, and
   the SIM or eSIM setup.
2. **Export and test restore.** Export everything to an encrypted archive outside project storage.
   Before every flash, prove a restore by opening files and importing contacts.
3. **Two factor codes.** Move them to another device, or confirm that the recovery codes work.
4. **eSIM.** If the phone uses one, keep the carrier's reactivation route ready. Whether a wipe
   keeps eSIM profiles is unverified.
5. **Phone state.** Record the build number and security update date right before each session, in
   private records.
6. **After each wipe.** Restore, and back up again before every later flash.

Personal data from the phone never enters the repository or the operating records.

## Stages

The native account work owns the build slot and the emulator until further notice. Stages that
need either wait for that notice. No stage touches the phone without a separately approved session,
and every session starts with the stop points. Stages 1 and 2 can start now. The phone keeps running
GrapheneOS, unchanged, until stage 7.

### Stage 0. Review and decisions

- **Changes:** nothing.
- **Qualifies:** the owner accepts this plan and answers each open decision before the stage that
  needs it.
- **Stays off:** everything else.
- **Needs:** the owner. No build slot, emulator or phone.

### Stage 1. Desk design

- **Changes:** design notes in the repository for the nine design items, and the session runbooks.
  Host checkers for the gate are written too. They cover the flash script, the image comparison, the
  boot checks and the neverallow check.
- **Qualifies:** reviewed design notes. Each checker passes its own failing controls. The neverallow
  check fails on every mutant policy and on an unresolved name.
- **Stays off:** downloads of Google's files, builds and the phone.
- **Needs:** the repository only, with the owner for review. No emulator or phone. Any part that
  needs a freshly built host tool waits for the build slot.

### Stage 2. Way back preparation

- **Changes:** the build machine, under decision 5. It gets platform tools r35.0.2 checked by
  SHA-256, and the USB rule that the owner installs as root. The runbook is written, with the stop
  points, the fixed reading script and decision 5's conditions. The allowed signers file already
  pinned in the upstream records is the trust anchor for the kits.
- **Qualifies:** `fastboot --version` reports 35.0.1 or later, the USB rule is installed, the web
  installer loads in a WebUSB browser on the owner's laptop, and the runbook is reviewed.
- **Stays off:** the phone.
- **Needs:** the owner, for the USB rule and the laptop check. No build slot, emulator or phone.

### Stage 3. Session 1, an optional rehearsal

- **Changes:** nothing on the phone. It reboots to fastboot mode, the fixed reading script runs, and
  it boots back to the OS. This rehearses the computer, the cable and the runbook.
- **Qualifies:** the script runs, with any variable the bootloader does not know recorded as
  unanswered. The product reads caiman, and the phone boots normally
  afterwards. The readings are recorded privately but approve nothing, because they go stale.
- **Stays off:** OEM unlocking, unlocking, flashing and erasing.
- **Needs:** the owner and the phone, in a separately approved session, with stage 2 done. No build
  slot or emulator.

### Stage 4. Way back kits

- **Changes:** private storage gains GrapheneOS's caiman install zip and its signature for the
  current stable release, and Google's caiman factory image for the matching stock build. As this
  plan proposes, the owner downloads Google's image, or authorises that download explicitly.
- **Qualifies:** every check that needs no phone. Each session's stop points then decide whether
  the kit is new enough. The GrapheneOS kit must also be no older than the base tag of any build
  flashed in the same session. Google's image must meet the version criterion with that base tag in
  place of the phone's release. An older kit is replaced, not used.
- **Stays off:** the phone, builds and any republishing of either kit.
- **Needs:** the owner, for Google's image. No build slot, emulator or phone.

### Stage 5. Andrix at the phone's tag on Cuttlefish

- **Changes:** a reviewed patch directory for the tag, and Andrix's Cuttlefish product built from
  the second tree at that tag.
- **Qualifies:** the patch inspectors pass, and the existing Cuttlefish suite passes on the same
  Andrix commit and tag.
- **Stays off:** the choice of project base, which the upstream carry work makes separately. The
  pinned tree stays the anchor for other work, and lab vehicles stay on the emulator.
- **Needs:** the build slot and the emulator. No owner session or phone.

### Stage 6. Vendor module and the first caiman build

- **Changes:** adevtool's host tools and the vendor module, generated in the second tree. The Andrix
  caiman product. The workshop key set, generated with the owner, and the first signed release.
  Where step 2 of the gate needs one, an unmodified GrapheneOS caiman build for comparison.
- **Qualifies:** adevtool's file hash check, then the gate before the first Andrix flash.
- **Stays off:** the phone, and publication, which is a separate release step for the owner.
  Before any public release, a second build made independently from the same sources must match the
  published images apart from their signatures, as GrapheneOS's reproducible build method
  describes.
- **Needs:** decisions 2 and 3, the owner's authorisation of adevtool's download, the build slot,
  and the owner for the key passphrase. No emulator or phone.

### Stage 7. Session 2, unlock and the GrapheneOS baseline

- **Changes:** in the OS, the owner switches OEM unlocking on, and then the stop points run. The
  bootloader is unlocked, which wipes all data and the secure element. The official GrapheneOS
  release from the kit is flashed with its own script. Setup runs with the toggle that disables OEM
  unlocking unchecked, and data is restored.
- **Qualifies:** the essentials pass on GrapheneOS, including those checked over the observation
  window, and are recorded as the baseline. The unlock
  ability reads 1 after setup. The way back has now been exercised for real.
- **Stays off:** Andrix images and locking.
- **Needs:** the owner and the phone, in a separately approved session, with everything in "Before
  the baseline session". No build slot or emulator.
- **If stage 8 slips** past three days, the phone keeps running official GrapheneOS, unlocked. If it
  moves meanwhile to a release with a different stock build, the Andrix build is redone at the new
  tag.
  The gate then runs again before stage 8. If the delay grows long, the owner may leave the track
  for good through GrapheneOS's own guide, which locks the phone again.

### Stage 8. Session 3, the first Andrix flash

- **Changes:** after the stop points, Andrix's install zip is flashed with its own script, which
  wipes data and writes the workshop key into `avb_custom_key`. Setup runs with the toggle
  unchecked, and data is restored.
- **Qualifies:** every essential checked in the session passes as on the baseline, the rest pass
  over the observation window, and the integrity checks hold. Daily use on Andrix starts only after
  the window. Andrix's
  own checks are recorded separately. On failure the phone returns to GrapheneOS from the kit in the
  same session. If the Andrix build does not boot, the stop points run without stop point 1, as
  their exception for a phone that cannot boot says.
- **Stays off:** locking, lab images and publication.
- **Needs:** the owner and the phone, in a separately approved session. The session needs a tested
  restore, the gate passed and decision 7. Its build must meet the version criterion at the stop
  points. No emulator. A rebuild, when the stop points require one, needs the build slot first.

### Stage 9. Updates

- **Changes:** one flash or sideloaded update for each new build. Until updates that keep data are
  qualified, each one is a wipe and a restore through the install script. Updates that keep data
  follow rule 4. They need their design (design item 6) and Cuttlefish qualification first, then
  one approved session. Recovery is reached through the bootloader menu, as GrapheneOS's usage
  guide describes. Whether recovery accepts the same full update a second time is unverified, so
  Cuttlefish checks that first.
- **Qualifies:** the essentials again. For an update that keeps data, the data and keystore keys
  survive and no patch level falls. The readings after each of the two boots show both bootloader
  slots on the new version, as rule 4 describes.
- **Stays off:** locking.
- **Needs:** for each update, the build slot for the build. Then the owner and the phone, in an
  approved session, with the stop points, a tested restore and the way back checked. The emulator
  qualifies updates that keep data.

Hardware qualification beyond the essentials, such as sensors, power, thermal behavior, suspend,
resource pressure and Andrix's own features on hardware, needs its own plan. So does the locked
owner keyed mode.

## Risks

Most severe first.

1. **Unbootable firmware state.** A firmware downgrade, possibly approved by stale readings, a
   bootloader slot left behind after a rollback increment, or an interrupted firmware write. The
   stop points and rules 3, 4 and 8.
2. **No way to flash.** A lock with the wrong key, or OEM unlocking switched off by a setup default,
   while the OS cannot boot. Rules 1 and 2, and the readings at every session. A pending update
   cannot block the way back, because of the stop points' exception for a phone that cannot boot.
3. **A wrong write.** A command outside rule 4's list, a partial or edited flash script, a wrong
   partition or a wrong device. Rules 4, 5 and 6, and the gate's script review.
4. **Weaker security on the phone.** Running unlocked, a userdebug build if chosen, the lost preview
   fixes and any lag behind GrapheneOS. Decisions 1, 3 and 7.
5. **Key exposure.** Public test keys, or a leaked workshop key set that can sign trusted builds for
   this phone. Test keys are never used. The workshop keys stay encrypted and held by the owner, and
   they are decrypted only during signing on a machine without unencrypted swap.
6. **Silent loss of Andrix's SELinux assertions.** Design item 2.
7. **Essentials broken by Andrix plumbing.** The services overlay, the owner cgroups, memory tagging
   crashes in Andrix native code, the page size macro or the super partition budget. The design
   items, stage 5 and the way back.
8. **Data loss at each wipe.** Two factor seeds, messages, passkeys and keys bound to the hardware,
   with eSIM behavior unverified. "Backup and data".
9. **Gaps in hardware evidence.** No snapshots, logs that hold personal data, and emergency calling
   that cannot be dialed. Design item 7 and decision 6.
10. **Contention on the build machine** that slows the native account work. Build stages wait for
    the slot, and phone sessions hold the build lock while they run.
11. **Exposure of the connected phone to the build machine.** While the phone is connected in
    fastboot mode, processes of the project's account could write to it. Decision 5's conditions.
12. **Rights in Google's files.** The owner's decision follows the practice of GrapheneOS and
    LineageOS, and publication waits for a release step with the owner.
13. **Unreviewed network traffic from Pixel components.** Design item 8.
14. **An early stop if OEM unlocking cannot be enabled.** Low. The internet check that GrapheneOS's
    guide describes belongs to the stock OS, and GrapheneOS ignores the carrier ID.

## Limits

- This is desk work. Nothing touched the phone, and nothing was downloaded from Google's Pixel
  images.
- The facts come from the pinned tree at 2026081300 and from single public files. Those files are
  at the 2026100600 revisions of adevtool, the release scripts, the build scripts, adb, fastboot
  and bionic. The second tree itself was not inspected.
- Unverified:
  - what an interrupted firmware write does;
  - whether the Pixel binds data keys to the verified boot key while unlocked;
  - whether the Pixel 9 Pro shows a key ID on its ORANGE screen, and from which key;
  - that the OS applies the secure element firmware from the vendor image at boot;
  - that a vendor mismatch is recoverable from fastboot while unlocked;
  - whether Google's flash tool offers a lock option;
  - the content of Google's stock flash script;
  - whether recovery accepts the same full update a second time;
  - which app processes get the boot state override;
  - whether caiman exposes the cgroup2 memory controller that owner sessions need;
  - whether prebuilt overlays set the device services array;
  - factory reset protection on a return to stock;
  - whether a wipe keeps eSIM profiles;
  - the exact flash script that `fastboot optimize-factory-image` writes into the install zip,
    including its image list, its wipe lines and whether it cancels a pending update, and where
    the build number sits inside a real install zip;
  - that GrapheneOS never ships older firmware in a newer release, which the version criterion
    assumes and GrapheneOS's own updates depend on;
  - that a security preview carries the same firmware as its regular release, which GrapheneOS's
    statement that previews use the same sources implies;
  - where the build sets the rollback index. The patch level comes from the base records in
    `upstream/bases/`;
  - how long a first caiman build takes.
- The accepted [lifecycle record](2026-10-08-native-lifecycle-record.md) keeps native account
  lifecycle writers out of production until two conditions hold. The rollback floor must read
  version 2 slots, and verified boot rollback protection must enforce the floor. An unlocked phone
  does not enforce rollback indexes, so the second condition cannot hold in workshop mode. The phone
  images in this plan therefore carry no lifecycle writer. This is separate from the owner
  lifecycle service of design item 3.
- The owner's decision on Google's files follows the practice of GrapheneOS and LineageOS. This
  plan does not establish a license basis for it.
- Component transactions under the accepted
  [component transaction plan](2026-10-09-component-transaction.md) are not part of this plan. That
  plan has the device signing copy hold the platform role, which needs personalization. The
  workshop keys here provide no such copy.
- Workshop mode protects the phone less than locked GrapheneOS does. This plan does not claim
  otherwise.
