# Architecture

This is the accepted system design: requirements for the system being built,
not a claim that the current prototype implements or proves them. There is no
supported Andrix release yet. Live implementation and proof state belong in
[`plans/current.md`](../plans/current.md).

## Foundation

Andrix's Android/Pixel platform follows an explicitly pinned public GrapheneOS
Android 17 release and its reviewed Pixel support inputs, on Android's ACK/GKI
kernel with the target modules and disclosed firmware required by the hardware.
The target is ARM64 with one Android userspace and ABI using Bionic and Android's
system linker. Android retains init, ART, Binder, SELinux, SurfaceFlinger, Package
Manager, application identities, profiles and the phone runtime.

Andrix maintains a small, attributable downstream layer for owner computing,
network/release policy and independently verified fixes. The owner adopted this
sourcing decision after the [base assessment](grapheneos-base-assessment.md);
implementation proceeds through the [isolated migration trial](../plans/2026-09-08-grapheneos-migration.md).
The earlier direct-AOSP checkout and proof results remain a separate preserved
baseline, not evidence that the new base is already built or qualified.

The owner Unix runs as native Android processes in this system. Official images,
bundled apps and services make no automatic direct connections to Google-operated
services. Connections arising from the owner's explicit use of Google products
or services, such as visiting Google Search or YouTube, are permitted. Unrelated
background requests do not acquire that permission merely because the owner uses
a Google product.

Non-Google services may use Google on their backend. This is a direct-client
networking requirement, not a claim that Google never processes forwarded data or
that every service is independent of Google infrastructure. The
[owner's clarification](grapheneos-connected-policy-review.md#accepted-networking-policy)
supersedes the earlier prohibition on proprietary Google service dependence and
forwarded device/user data. Open-source AOSP inputs may still come from
Google-hosted repositories as recorded source supply. User-installed applications
remain the owner's choice.

## Authority, identity and state

The human owner is the legitimate authority. Daily processes receive bounded
Android authority; the owner retains constitutional control of build,
installation, trust roots and recovery. Android UID, profile, SELinux and
Binder identity remain authoritative.

The system has three tiers: immutable trusted system state; one stable owner
Unix identity with a credential-encrypted home, normal processes and direct
ARM64/Bionic execution; and isolated Android application identities. Crossings
use explicit Binder operations, file descriptors, URI grants or equivalent
scoped capabilities.

One bounded `andrixd` coordinates sessions, PTYs and explicit Android
crossings from the owner domain. Android retains installation, signing, init
and platform-policy authority.

## Trusted `/usr`

`/usr` is a read-only view of authenticated Android system modules. Android
`/etc` remains Android's; owner code and packages remain separate from system
content.

The accepted first generation is one reboot-staged `dev.andrix.usr` APEX built
and signed on the build host. Official and owner-controlled trust roots are
valid, and private signing keys stay off the phone. Platform trust, init and
policy changes travel through an image or OTA.

A generation commits after platform health and Andrix self-tests pass. Recovery
can return to the prior complete system generation while leaving owner home and
packages unchanged.

## Owner userland

Direct execution and managed packages are separate capabilities. The public
base is the API-37 NDK/Bionic ABI plus versioned Andrix C APIs and AIDL process
boundaries.

The complete environment includes a shell, core tools, PTYs, an editor, build
and debugging tools, archives, offline package operations, resource inspection,
a supportable on-device ARM64/Bionic compiler and later SSH into the same owner
environment.

Managed packages use complete versioned objects, pinned profile generations,
package-private libraries and owner-only relative RUNPATHs. Transactions
provide atomicity and rollback. Deliberately executed owner code shares owner
authority; automatic untrusted hooks use proved Android isolation. Unsigned
software remains an owner choice.

## Lifecycle and networking

Owner processes participate in Android memory pressure, LMKD and kernel OOM,
suspend, battery and thermal policy. Daily owner work stays below
phone-critical services. Ordinary work runs directly; active overnight work
requests bounded wake authority. Explicitly enabled, version-pinned services
use Android supervision and return after unlock. Android init remains PID 1.

Ordinary owner processes have outbound networking and may use ephemeral
loopback listeners. External or persistent exposure is explicit. Isolated
jobs, package hooks and agent jobs receive scoped network grants.

Owner home and ordinary SSH become available after first unlock. Screen relock
preserves ordinary jobs and enabled services, blocks locked-UI attachment and
new SSH by default, and follows visible owner policy for existing SSH. CE-key
state is proved and reported independently of relock policy. Reboot ends
ordinary jobs.

## Agents

Owner operations remain available independently of any agent or model
provider. Agents act as attributable principals through scoped, revocable
delegation and the same inspectable OS operations available to other authorized
clients. The owner supplies intent and authority; the operating system supplies
enforcement, state, evidence and recovery.
