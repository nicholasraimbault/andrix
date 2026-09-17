# Architecture

This is the accepted system design: requirements for the system being built,
not a claim that the current prototype implements or proves them. There is no
supported Andrix release yet. Live implementation and proof state belong in
[`plans/current.md`](../plans/current.md). The [design evidence register](design-evidence.md)
tracks which mechanisms are prototypes, what their tests establish, what those results
imply and which long term intentions are accepted or still proposed.

## Design method

Andrix is making Android a general purpose, owner controlled Unix computer. Long term
correctness, coherence, maintainability and owner control determine the design.
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
networking, tools, terminals and agent authority. Review existing decisions against
their rationale and current evidence; do not assume they were accidental or discard
accepted requirements without an explicit revision. The register is the review map,
not a claim that all areas have already completed this assessment.

Keep the depth of documentation and verification proportional to consequence and
uncertainty. Routine implementation inside an accepted contract need not become a
formal architecture decision. Changes to authority boundaries, owner visible semantics,
platform responsibility or product restrictions must be made and accepted explicitly.

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

Andrix retains genuine hardware-backed attestation as an owner-verification
capability, with remote key provisioning through GrapheneOS's proxy under this
networking policy. Attestation does not gate ordinary owner computing or impose
an external certification requirement on legitimate owner-controlled builds.

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

Trusted native components mediate explicit Android crossings from the owner domain.
Their roles and authority are deliberate boundaries, not permission to execute owner
commands with coordinator privileges. The current `andrixd` process layout is a
prototype, not a requirement to combine work, launch and terminal responsibilities in
one process. Android retains installation, signing, init and platform policy authority.

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

## Work supervision

Android supervises the owner environment. Andrix manages work inside it. The kernel
enforces containment, and Console is a client. This ownership model is accepted; the
combined delegation, activation and cleanup contract still needs design and qualification.
The [comparative experiments](../plans/2026-09-17-work-factory-comparison.md) establish
useful mechanisms, not a production implementation of this contract.

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

The privileged interface selects only declared profiles and fixed trusted bootstraps.
It does not accept an arbitrary privileged program, UID or filesystem path. The ordinary
owner work API does accept executable, argument, environment and working directory
requests. Those inputs may direct owner execution, never redirect privileged bootstrap
execution or select its authority.

Android's framework remains the source of genuine user and CE authority. The manager
and launch/input gates enforce its freshness and revocation; init does not gain Andrix
CE admission policy. A positive check is not permanent permission, and a late result
cannot revive a stopped or revoked identity.

A work scope defines lifetime and resource accounting, not automatic mutual security
isolation between programs deliberately run as the same owner. Untrusted hooks, agent
principals and other isolated work require their own explicit authority boundaries.

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
