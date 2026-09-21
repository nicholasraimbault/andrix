# Andrix is Android you own

Accepted product direction, revised on 2026-09-21. This describes the system we intend
to build, not features already delivered. See the [architecture](architecture.md),
[decision record](../plans/2026-09-21-owner-composable-android.md) and
[current work](../plans/current.md) for contracts, rationale and qualification status.

Andrix makes the phone a computer its owner can program, administer and change. If you
see something you dislike, there should be an understandable path to finding its source
or configuration, changing it, building it, installing it and recovering from a mistake.
Source availability alone is not practical ownership if every small change requires
maintaining a complete private ROM release process.

## One Android system, two ways to program it

The phone stays Android: its Linux kernel, Bionic, Binder, ART, applications, hardware
services and radios remain the platform. Andrix is not a guest distribution, a VM based
owner environment or a desktop Linux replacement for Android. Emulators remain development
tools. Bionic is the supported native ABI; a parallel glibc userspace and alternative
desktop compositor are not product tracks.

Native Andrix execution and APKs are equally important:

- The Unix environment supplies real identities, homes, processes, terminals, compilers,
  programs and jobs that can outlive a terminal.
- APKs supply applications and Android UI components. A launcher, SystemUI or Settings
  component is software the owner can replace through the appropriate authority and
  compatibility checks.

An ordinary APK does not become a Unix login or gain platform authority merely because
it is installed or signed by its owner. Both execution paths belong to the same OS,
with explicit crossings between their identities and responsibilities.

## Compose the OS, not just its Unix environment

Andrix owns its platform integration, policies, packages, signing and updates. It initially
uses a pinned GrapheneOS source release as a maintained engineering foundation. GrapheneOS
contributes useful Android and Pixel integration and hardening, not a permanent ceiling on
Andrix's product goals. We can change the framework, SystemUI, init or platform policy when
the owner capability and coherent design require it.

The existing Unix work remains part of this system. It is the native execution half,
not the boundary of the project. Signed `/usr` is one maintained component among others,
not the sole route for updating the OS.

Common changes should have focused build and installation workflows. Some require only
an application or service restart; others require compatible component updates or reboot.
Restart scope is something to establish through actual behavior, not a blanket promise
that every part of Android can be replaced live.

On-device editing, building, signing and installing ordinary APK and native components
is an explicit end goal. Host assistance can come first and remain useful, especially for
large platform builds. It must not become a permanent requirement for ordinary component
work merely because the prototype uses a build server.

## Real accounts and deliberate authority

One person may use many accounts, or several people may use separate accounts on a device.
Each full Android user should have an integrated Unix identity, home and work environment.
Use Android's actual account and credential storage lifecycle, rather than inventing an
unrelated login system beside it. Resource limits are real, but prototype account counts
are not product restrictions.

Daily programs run with ordinary user authority. An authorized device administrator can
elevate for genuine system administration, including arbitrary root commands or a root
shell. This is not a permanent root identity for daily work, a menu limited to predefined
administrative actions, or a Magisk/LSPosed hook layer on someone else's installed OS.
Having an account does not automatically confer administration or signing authority.

Andrix distribution signatures establish provenance. The individual owner must have a
practical path to controlling the installed system's trust and deployment authority.
There is no universal private platform key handed to every user. Key custody, protected
signing and recovery must serve that ownership without silently giving everyday programs
the power to sign trusted system replacements.

## Useful defaults, replaceable choices

The recommended installation should provide a usable phone and Unix environment. An
advanced installation can select and assemble components. Both use the same system and
package model; initial choices remain changeable afterward.

Andrix follows a rolling release direction with compatible component sets and recoverable
activation. Rolling does not mean arbitrary partial versions are compatible. Updates must
respect tracked owner component selections, expose rebuild or merge conflicts and make
security divergence visible. They must not silently overwrite a local choice or pretend
it received an upstream fix.

Checking, downloading and staging follow owner policy. Activation that restarts services,
ends work or reboots follows explicit consent or a configured policy, not a surprise
caused by a background update.

## Honest operating modes

Workshop operation is a legitimate supported direction: unlocked, with verified boot and
partition verification configured for deliberate modification. App isolation, SELinux
enforcement and credential encryption remain defaults. This mode has weaker protection
against physical tampering and theft. It is neither equivalent to a locked GrapheneOS
release nor categorically safer than every rooted ROM.

A locked configuration with owner controlled keys is a later mode of the same underlying
system. It is not the only legitimate form of ownership. Hardware trust roots, closed
firmware, dependencies and data migration impose real constraints. Signing software does
not make it safe or alone define the whole trusted computing base.

These are supported product choices, not new restrictions on what an owner may experiment
with. Deliberately changing them changes which guarantees Andrix can substantiate.

## Build the vision in a testable order

Cuttlefish/QEMU is the first development and testing environment. The next platform proof
is a SystemUI component change and recovery workflow, not an immediate phone flash.
Pixel integration follows when the system is more mature, using maintained device/vendor
knowledge and explicit hardware qualification.

Preserve the Unix milestones and their evidence. Keep the phone functional. Keep privacy
and recording defaults explicit. Agents and dedicated autonomous delegation machinery are
deferred; build human accounts and ordinary programmable interfaces first.
