# Architecture

This is the accepted system design: requirements for the system being built,
not a claim that the current prototype implements or proves them. There is no
supported Andrix release yet. Live implementation and proof state belong in
[`plans/current.md`](../plans/current.md). The [design evidence register](design-evidence.md)
tracks which mechanisms are prototypes, what their tests establish, what those results
imply and which long term intentions are accepted or still proposed. The
[owner composable Android vision](vision.md) and its
[2026-09-21 decision record](../plans/2026-09-21-owner-composable-android.md) expand the
product boundary while retaining the Unix work and its evidence.

## Design method

Andrix is an owner controlled Android OS, including its native Unix environment and
Android application and system components. Long term correctness, coherence,
maintainability and owner control determine the design.
Neither time and effort already spent nor the cost or difficulty of replacement is
a reason to retain an inferior design or take an architectural shortcut.

Tests and prototypes establish what actually works, expose assumptions and inform the
system we should build. Prototype code is replaceable, including from scratch when
that is the sound approach. Reuse must earn its place in the long term design; a
rewrite is a means to that design, not a goal by itself.

Establish focused tests and observations before committing to uncertain design choices,
then verify the actual replacement through host, artifact and runtime checks. Keep
observed facts, accepted requirements and prototype assumptions distinct. Test
expectations may change when the intended contract deliberately changes, not merely
to make an implementation pass. Preserve previous evidence with its original scope.

Proof limits, fixed entry points, temporary API shapes and simplified lifecycle modes
do not become permanent product restrictions by accident. Apply this review to the
whole developed system, not only its terminal. Preserve the phone and boundaries that
protect its owner; reject restrictions whose purpose is vendor control.

### Deliberate decisions

Every significant architectural choice must have an explicit rationale, including
choices inherited from earlier work. Record the following in the relevant design or
milestone, linked from the [design evidence register](design-evidence.md):

- The owner capability or system requirement being served, and the guarantees to preserve.
- Who owns the state, authority, resources and lifetime, including each trusted crossing.
- The credible alternatives, inspected evidence and assumptions that remain unproved.
- The chosen contract, reasons for choosing it, costs and failure or recovery behavior.
- What is accepted, what remains a proposal, what is implemented, and what is qualified.
- The next verification gates and circumstances that would justify revisiting the choice.

Acceptance of an ownership model does not qualify its implementation or settle every
API, process layout or mechanism. A successful fixture does not select an architecture
by itself. Small patches, familiar conventions, existing code and previous effort are
not substitutes for this reasoning.

Apply the same discipline to platform integration, trust and updates, resources, files,
networking, tools, terminals and administration authority. Review existing decisions against
their rationale and current evidence; do not assume they were accidental or discard
accepted requirements without an explicit revision. The register is the review map,
not a claim that all areas have already completed this assessment.

Keep the depth of documentation and verification proportional to consequence and
uncertainty. Routine implementation inside an accepted contract need not become a
formal architecture decision. Changes to authority boundaries, owner visible semantics,
platform responsibility or product restrictions must be made and accepted explicitly.

## Foundation

Andrix initially uses an explicitly pinned public GrapheneOS source release as a
maintained Android integration foundation. AOSP remains the underlying platform;
GrapheneOS contributes source, hardening and Pixel device knowledge, not a permanent
ceiling on Andrix's goals or policies. The current Android 17 pin is a reproducible
anchor, not an indefinite release policy.

Andrix owns its full OS integration, package choices, signing, release and recovery
responsibilities. Changes to SystemUI, the framework, init, installation or policy are
legitimate product work when the capability and coherent design require them. A small
downstream layer is no longer a product boundary. Maintainable, attributable changes
remain valuable; source ownership does not require rewriting useful upstream components.
The [base assessment](grapheneos-base-assessment.md) and
[migration](../plans/2026-09-08-grapheneos-migration.md) retain their historical scope.
Direct AOSP remains an alternative if observed compatibility or maintenance costs warrant it.

The supported native target is ARM64/Bionic with Android's system linker, in one Android
userspace on its Linux kernel. Init, ART, Binder, SELinux, SurfaceFlinger, Package Manager,
application identities and the phone runtime remain the platform. Andrix is not a guest
distribution, a VM based owner environment or a parallel glibc/desktop product. These are
product design choices, not prohibitions on owner experiments.

Cuttlefish/QEMU is the first development and testing environment. Pixel integration follows
when the platform is more mature, using matching device/vendor, kernel/module and firmware
inputs. Hardware requirements still inform the design now. Closed firmware remains a real
boundary; neither source availability nor an emulator pass qualifies a physical phone or
confers the guarantees of an official GrapheneOS release.

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

Genuine hardware attestation remains an owner verification capability where supported.
Boot and modification state must be reported honestly, including workshop operation.
The currently accepted GrapheneOS remote key provisioning proxy choice remains subject
to this networking policy and the eventual device/service review. Attestation does not gate ordinary owner
computing, impersonate an official build or impose external certification on legitimate
owner controlled systems.

## Authority, identity and state

The human owner is the legitimate authority over the device. Daily programs receive
ordinary user authority. Shared system installation, platform signing and elevation are
explicit administrative capabilities; ordinary app installation and app signing do not
thereby require a root session. Android UID, user lifecycle, SELinux and Binder
identity remain authoritative for the running system. The owner can deliberately change
the system and its policy; that does not make every ordinary process an administrator.

### Accounts

One person may use many accounts, or several people may use separate accounts. Each full
Android user has an integrated Unix login identity, credential encrypted home, processes,
jobs and preferences. Accounts share the OS and baseline system components without sharing
private homes or work control. Actual credentials and MAC boundaries must separate them;
changing HOME while retaining one common UID is insufficient.

Use Android's genuine account and CE lifecycle, not a disconnected account system beside
it. Account switching, background execution, explicit session end and CE withdrawal have
different meanings. Resource constraints are explicit, not a product limit inherited from
a user0 prototype. The current implementation does not yet qualify this account model.
See the [account plan](../plans/2026-09-21-android-unix-accounts.md).

APKs retain Android application identities. Installation or owner signing does not make an
ordinary APK a Unix login or grant it platform privileges. Native execution and APKs are
both first class interfaces to the same OS. Trusted crossings use explicit operations,
file descriptors or scoped capabilities, never caller supplied IDs as authentication.

### Administrative elevation

An authorized device administrator can execute general administrative commands, including
root commands or a root shell. Elevation is not limited to a curated action menu. It is
also not permanent root for daily work, automatic authority for every account, or a hook
layer on somebody else's installed ROM.

The authorization path must establish the request and a complete execution context before
administrative code runs. Ordinary work submission cannot select elevated credentials or
borrow coordinator authority. The current `andrixd` layout is a prototype, not a mandate
to combine jobs, administration and terminal presentation in one process. Authentication,
consent duration, role construction and recovery require a separate
[authority design](../plans/2026-09-21-owner-authority.md).

### Signing and trust

Distribution signatures establish that inputs came from Andrix. Individual owners must
also have a practical path to controlling their installed system's signing and deployment
authority. A universal private platform key is not distributed to all owners. Ordinary app
keys, platform APK identities, APEX signing and verified boot are distinct relationships,
not interchangeable proof of authority.

On-device component signing is a goal. Platform private material must not silently become
available to everyday programs. The [accepted recovery default](../plans/2026-09-22-installation-key-recovery.md)
is an owner held portable encrypted recovery bundle, with a separately protected signing
copy on the device. Recovery of the installation signing identity must not require the
original hardware or approval from Andrix or a vendor service. An account does not by itself
confer signing or deployment authority.

Protected signing mechanisms, initial personalization, certificate continuity and the
recovery format remain implementation and qualification work. A signing identity backup
is not a backup of CE keys, hardware bound application secrets or user data. This replaces
the earlier absolute requirement that all private signing keys stay off the phone, not
the requirement to protect keys or support independent recovery.

Signed software is not automatically safe. The trusted computing base includes code,
policy, services and hardware/firmware relied on for the relevant guarantee. Ordinary
accounts must be isolated, but protection against an actively malicious platform
administrator is not promised. Administrative access does not itself supply a locked
account's CE keys.

## Workshop and locked operation

Workshop operation is a legitimate mode of Andrix. It supports bootloader unlock and
disabling boot verification enforcement for mutable OS partitions on the chosen target. SELinux enforcement,
application isolation and credential encryption remain defaults. APK/APEX verification
and boot verification are separate mechanisms; workshop setup is not a blanket instruction
to disable every check or make every process privileged.

The mode has weaker physical tamper and theft protection than a correctly locked system.
It is not equivalent to locked GrapheneOS, and no categorical advantage over every rooted
ROM is claimed. Owners can deliberately change more of the system, with the loss of
particular guarantees made explicit.

A locked configuration with owner controlled keys is a later mode of the same underlying
OS and package model, not the only legitimate product configuration. Hardware root
support, closed vendor components, rollback protection and recovery need actual device
qualification. Planning either mode is not authorization to flash a handset or change
current qualification inputs.

## Component composition and development

The owner can modify and replace applications, SystemUI, Settings, launchers, native services
and platform components. `/usr` is one maintained component among them. The supported path
must identify source/configuration, dependencies, build and signing inputs, installation
authority, activation and recovery. Source access without a practical change workflow is
not sufficient ownership.

Build and replace individual components where compatible. Some changes require related
components, framework restart or reboot. Neither SystemUI's APK packaging nor a successful
installation establishes restart safety; system_server changes do not universally imply
a kernel reboot either. The first [workshop proof](../plans/2026-09-21-workshop-components.md)
will establish a small SystemUI change and restoration route on Cuttlefish.

On-device editing, building, signing and installation of ordinary native/APK components is
an explicit end goal. Host assisted workflows may come first and remain useful. The
prototype's full image build/qualification procedure is not a permanent requirement for
every UI tweak. Controlled qualification still requires declared, frozen inputs and
honest evidence for each changed component.

## Updates and installation

Andrix follows a rolling release direction with compatible component sets and recoverable
activation. Where contracts permit, update a component independently. Where they do not,
update a compatible group. Rolling cadence does not make arbitrary partial upgrades safe.
Define transaction and health boundaries, restart needs, interruption handling and recovery
for each class; do not assume a package install or an old code image rolls back user data
migrations or firmware state.

Owner modifications are explicit component selections and reproducible build inputs.
Updates must not silently replace them. Expose incompatibilities, rebuild/merge requirements
and security fixes absent from a local version. Owners may choose unsupported combinations,
but the supported update path must not misrepresent their compatibility or protection.

Checking, downloading and staging follow owner policy. Disruptive activation, including
service restart, work interruption or reboot, follows explicit consent or a configured
policy. Permission to stage does not silently authorize interruption.

The recommended installer supplies a usable phone and Unix environment with replaceable
defaults. An advanced path lets the owner assemble choices. Both use the same OS and
component model, with selections changeable after installation. Exact package formats,
installer interfaces and update machinery remain in the
[rolling composition plan](../plans/2026-09-21-rolling-composition.md).

## Trusted `/usr`

`/usr` is normally a read only view of authenticated system components. Android `/etc`
remains Android's; writable owner programs, data and package selections remain distinct
from the authenticated base. An authorized owner can replace that base or deliberately
modify it in workshop mode; read only daily access is not an owner control ceiling.

The first generation is one reboot staged `dev.andrix.usr` APEX built and signed on a host.
It remains a useful implementation and evidence baseline, not the only permissible update
format, signing location or system generation boundary. Broader native package operations,
component activation and recovery need their own transaction and compatibility proofs.

## Owner userland

Direct execution and managed packages are separate capabilities. Bionic and Android's
system linker are the supported native foundation. The current prototype targets the
API-37 NDK surface plus versioned Andrix C APIs and AIDL boundaries; that version is an
implementation anchor, not a requirement to freeze the OS indefinitely.

The complete environment includes a shell, core tools, PTYs, an editor, build
and debugging tools, archives, offline package operations, resource inspection,
a supportable on-device ARM64/Bionic compiler and later SSH into the same owner
environment. Android APK build and signing tools belong in the development roadmap too;
they are not implied by the existing native C/C++ compiler result.

Managed packages need complete versioned objects, explicit dependencies and compatible
profiles. Package private libraries and owner relative RUNPATHs remain tools for native
software without replacing Android's runtime. Transaction atomicity, rollback and data
migration must be designed and qualified rather than inferred from package installation.
Deliberately executed code shares its user's authority; automatic untrusted hooks need
proved isolation. Unsigned native software remains an owner choice. Neither execution
path requires becoming a platform package merely to run ordinary owner code.

## Work supervision

Android supervises the owner environment. Andrix manages work inside it. The kernel
enforces containment, and Console is a client. This ownership model remains accepted
within the expanded OS vision. The
[contract and failure matrix](../plans/2026-09-17-delegated-supervision-contract.md),
[comparative experiments](../plans/2026-09-17-work-factory-comparison.md) and subsequent
service results have distinct implementation and qualification scopes. None selects an
unchangeable process layout or turns the subsystem into the whole product. See
[current work](../plans/current.md) for remaining gates.

### Android's service boundary

Android starts the trusted control machinery under a complete declared profile, sets
protected aggregate resource ceilings and delegates only the required controls inside
its supervised subtree. Trusted control and owner work occupy separate parts of that
resource hierarchy. Exact helper processes and API details remain design work.

Init owns generic service supervision: starting a declared service, controlling its
exact instance and reporting its lifecycle and cleanup state. It does not acquire
Andrix work IDs, admission decisions, terminal state or owner job restart policy.
Generic service instance identity is still necessary to prevent stale control or
cleanup from targeting a replacement.

On manager failure or an authorized end of that service instance, Android has the whole
subtree as its cleanup boundary. Cleanup must terminate its processes, observe quiescence,
reclaim empty groups and retire identities safely, without stalling unrelated init work.
Acceptance of Stop, process termination, directory reclamation and release of accounting
are distinct facts. Unknown state is not success. Incomplete cleanup must remain visible
and retain the identity protection needed to prevent unsafe reuse.

This can require deliberate Android integration changes. Keeping init unchanged is not
a product requirement. The platform contract is generic delegated supervision, not an
Andrix work factory in PID 1. Neither the prototype's PID property/reclaim sequence nor
its dependency on a guardian exiting is the production contract.

### Andrix work and launch

The Andrix work manager owns work identities, authenticated client operations, admission,
cancellation, scope resources and job policy. Control binds to the exact work and kernel
objects, not a reusable PID, name or path alone. It has direct scope control; complete
Stop must not require cooperation from payloads or work guardians. Manager failure has
Android's enclosing subtree as its backstop. That failure does not silently restart
ordinary jobs under a new identity; separately enabled services have explicit policy.

Start is accepted at most once. Owner execution stays gated until its prerequisites
are established. Stop closes that gate irreversibly, including during admission. A late
successful creation must be cleaned up without releasing a stopped payload. Admission
and terminal I/O must not block the control path by sharing its locks or execution lane.

Trusted launch machinery constructs execution from a complete immutable profile. Actual
identity, groups, explicit capabilities, SELinux role, resource membership and limits,
descriptors and execution state must be established before owner code runs. Identity
changes and descriptor sanitization are steps of that complete transition, not general
privileged mutation operations offered to callers.

The ordinary work launch interface selects only its declared profiles and fixed trusted
bootstraps. Caller executable, argument, environment and working directory inputs direct
ordinary execution, not privileged bootstrap execution or selection of its authority.
This restriction is not a ban on general administrative commands. Separately authorized
elevation can establish an administrative profile and execute the owner's chosen command.
It must not silently turn ordinary work submission into root access or expose partially
constructed privilege transitions.

Android's framework remains the source of genuine user and CE authority. The manager
and launch/input gates enforce its freshness and revocation; init does not gain Andrix
CE admission policy. A positive check is not permanent permission, and a late result
cannot revive a stopped or revoked identity.

A work scope defines lifetime and resource accounting, not automatic mutual security
isolation between programs deliberately run as the same user. Untrusted hooks and other
isolated work require explicit authority boundaries. Sharing one Unix identity is not
proof that hostile programs are isolated from each other.

### Work records and diagnostics

Live work state, security diagnostics, optional durable work history and output capture
are separate responsibilities. Live ownership and control remain required regardless of
recording preferences. Historical records describe confirmed observations, not permission
to execute, restart or control a replacement instance.

The accepted default is minimal, protected local recording of security relevant events
and supervisor failures. This includes important successful authority and policy changes,
not an automatic record of every ordinary owner program or shell command. Persistent work
activity history, persistent terminal/output capture, debug verbosity and remote or
archive export are disabled unless the owner explicitly enables them. Raw arguments,
environments and sensitive contents are not collected automatically.

The owner controls recording policy through authorized interfaces. Arbitrary applications
and log producers cannot change it. Disabling persistence must not disable safe ordinary
computation or silently reproduce the same activity collection elsewhere in Andrix.

Recording has bounded memory, storage and ingestion, with visible loss and coverage limits.
Filesystem and export work stay out of shared control paths. They must not block Stop,
genuine CE withdrawal or unrelated supervision. Ordinary execution without a durability
requirement does not depend on a writable history store. Sensitive persistent records
use CE storage, without a silent less protected fallback
when CE is unavailable. A bounded memory buffer may lose events on failure. Recording
alone grants neither wake authority nor network exposure, and has no automatic export.

Durability, retention, access revocation, logical deletion and physical erasure remain
different promises. Optional durable receipts need explicit commitment semantics and
qualification before the API promises them. Local records are not complete forensic
evidence or protection against full system compromise. Specific event fields, retention
values and implementations remain subject to measurement and tests. The
[decision and source review](../plans/2026-09-19-logging-defaults-review.md) retains the
rationale, alternatives, limitations and verification gates. This policy concerns Andrix
recording, not an implicit replacement of Android's diagnostic facilities.

## Lifecycle and networking

Owner workload lifetime and terminal presentation are separate abstractions. Android
supervision governs workload identity, user/CE authority, resource bounds and cleanup;
Console is a client of that work, not the definition of its lifetime. Explicit
policies distinguish foreground work, detached jobs and enabled services. Terminal
persistence may use an ordinary tool such as tmux; choosing that tool neither grants
retention authority nor becomes a prerequisite for every retained workload.

Lifetime behavior follows what the owner expects from a general purpose Unix
computer, not a blanket rule to keep every terminal job or kill every process when
an application closes. Leaving a view, screen relock or Console process reclamation
is not an owner request to end work. Detach revokes the presentation connection.
Explicitly closing a terminal performs terminal hangup, with the normal kernel,
shell and program signal behavior. Running a command with `&` alone does not promise
survival of hangup. Shell exit is not an additional Andrix instruction to kill every
remaining descendant.

Owner code can use ordinary job control, `nohup`, `disown` where supported by the
chosen shell, `setsid` and optional terminal multiplexers for their actual Unix
semantics. A detached job need not have a terminal or depend on Console's process.
These mechanisms do not exempt work from Android user/CE authority, resource limits
or explicit owner Stop. Stop targets the complete supervised work scope and remains
distinct from terminal hangup. Neither closing a terminal nor ending its shell is a
reason to silently restart it.

This separation does not imply automatic restart, wake or network authority.
Foreground/unlocked terminal access remains a separate permission from continuing
computation. Starting and supervising ordinary owner work must not require a
particular terminal application, multiplexer or a product specific Keep operation;
the prototype's existing modes remain compatibility behavior until replaced and
qualified.

Owner processes participate in Android memory pressure, LMKD and kernel OOM,
suspend, battery and thermal policy. Daily owner work stays below
phone-critical services. Ordinary work runs directly; active overnight work
requests bounded wake authority. Explicitly enabled, version-pinned services
use Android supervision and return after unlock. Android init remains PID 1.

Ordinary owner processes have outbound networking and may use ephemeral
loopback listeners. External or persistent exposure is explicit. Isolated
jobs and package hooks receive scoped network grants.

Each account's home and ordinary SSH availability follow that Android user's actual
unlock and CE authority. Screen relock preserves ordinary jobs and enabled services,
blocks locked UI attachment and new SSH by default, and follows visible owner policy
for existing SSH. Account switching is not itself proof of CE withdrawal or an explicit
whole work Stop. Android user stop, resource policy and actual credential withdrawal
remain lifecycle events the design must handle. Reboot ends ordinary jobs.

## Agents

Dedicated agent orchestration and delegation architecture is deferred. Build human
accounts, ordinary programs and inspectable OS interfaces first. Owner operations must
not require an agent or model provider. Future automation may use those interfaces, but
a running program does not establish human presence or silently inherit authorization
to elevate. Additional unattended authority policy would need its own decision and tests.
