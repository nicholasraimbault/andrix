# Workshop component change workflow

Status: accepted capability and next proof target under the
[vision revision](2026-09-21-owner-composable-android.md). Procedure and implementation are
proposals. No new image, signing operation or component restart is qualified here.

## Goal and boundary

On Cuttlefish/QEMU, change a small visible part of SystemUI, build that component, install
it through deliberate authority, observe the required restart and restore a known good
version after a bad change. The existing native Unix environment must remain useful.
This is a separate platform workstream, not another terminal separation feature.

Start with host assistance where needed. Explicitly distinguish a host controlled lab
installation from a completed on-device administration interface. The end goal includes
ordinary APK/native component editing, building, signing and installation on the phone.
Do not make a complete OS generation necessary for every subsequent UI iteration.

## Design before the run

- Pin the upstream source and Andrix changes. Identify the exact SystemUI package, UID,
  permissions, dependencies, source target, signing identity and installation mechanism.
- Define the workshop's unlocked/partition verification configuration. Boot verification,
  APK signature checks and file verification are distinct; do not silently disable all
  of them under one ambiguous "verity off" label.
- Keep SELinux enforcement, app isolation and CE encryption as defaults. The existing
  verified APK update mechanism, including required signature sidecars, is an input to
  inspect, not a reason to bypass package checks.
- Use an explicitly scoped development signing setup. Establish initial certificate
  consistency before attempting a replacement; matching a package name is not authority.
- Define a recovery route independent of the modified SystemUI. Host or recovery assisted
  restoration is an acceptable first proof if that dependency is stated.
- Keep qualification inputs frozen during a run. A new component iteration gets new
  declared inputs. Ordinary workshop iteration need not become a full image qualification.

## Proposed finite controls

1. Boot a matching baseline and record the relevant framework, user and component state.
2. Compile and run an ordinary native owner program as a positive control.
3. Build a small recognizable SystemUI change against that platform generation.
4. Install the correctly signed component. Retain a wrong signer or malformed package
   negative control without broadening ordinary application authority.
5. Observe the UI change and actual process/restart scope. Record which applications,
   surfaces, work and framework processes survived or were recreated.
6. Introduce a recoverable broken component and restore the known good version through
   the declared independent route. Observe the restored behavior, not just install success.
7. Recheck native work, account/CE state, app boundaries and final resource retirement.

These controls do not promise live replacement of all framework code. A system_server
change may need broader restart or reboot; it is not a universal rule either way.
SurfaceFlinger replacement also needs its own caller/surface recovery observations.
Cuttlefish observations are not physical radio or telephony qualification.

## Exit gate and later work

Accept the component workflow only for the tested package, compatibility and restart
conditions. Record failures and recovery limits. Then extend the
[owner authority path](2026-09-21-owner-authority.md), Android SDK/build tooling on the
phone and the [package selection model](2026-09-21-rolling-composition.md).
