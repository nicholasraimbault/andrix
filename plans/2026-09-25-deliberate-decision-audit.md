# Deliberate decision audit

Status: review, not a revision of the accepted architecture or permission to activate new
mechanisms. The owner asked to pause implementation and review Andrix's deliberate decisions
with the same scrutiny applied to native identity recovery.

Baseline: `8b9adf47273ac5248d99e26d5fa6b230d1a5595f`. This review covers the accepted architecture,
vision, all 18 areas of the design evidence register, their material decision records, and
selected implementation paths. It is not a complete audit of Android, every source line,
every historical experiment or a physical phone. Independent reviews informed this assessment;
the conclusions below are the primary assessment, not automatic acceptance of those reports.

## Answer

**No blanket claim that every current mechanism is a clean, uncompromised solution is justified.**

The strongest decisions are responsibility boundaries: ordinary authority versus administration,
actual Android policy versus invented grants, work versus presentation, accepted work versus
lost replies, code restoration versus data recovery, and signing approval versus backend key
operations. Those boundaries generally hold up.

Several present mechanisms are explicitly temporary and should not become product defaults.
There is also a concrete privacy defect in the terminal adapter, a real availability cost in
short lifecycle query deadlines, and important integration decisions still open. Many remaining
gaps are unfinished work, not evidence that the underlying requirement is wrong.

A clean solution does not remove every tradeoff. It makes necessary tradeoffs explicit, avoids
unnecessary coupling, contains failures, has one accountable owner for each kind of authority,
and is supported by evidence at the layer where the claim matters.

### What should stand

- One Android/Bionic system, preserving the phone and permitting native and APK programming.
- Owner control of the OS without making ordinary programs permanent administrators.
- Shared Unix login authority, with separate real principals when restriction is wanted.
- Genuine Android user/CE, permissions, AppOps and network/power authorities.
- Exact work identity, gated entry, independent Stop and captured kernel cleanup.
- Separate terminal presentation, Unix hangup, work lifetime and restart policy.
- Authenticated system components and separately writable owner programs/data.
- Portable encrypted installation identity recovery and protected device custody, with explicit
  limits on what is backed up and what the running OS is trusted to do.
- One complete immutable protected signing transaction as the approval unit.
- Explicit owner selections, compatible updates, declared disruption and honest recovery.
- Minimal recording by default and an honest distinction between evidence levels.

### What needs attention first

1. Fix the terminal parser's unintended logging route.
2. Finish the transition away from the legacy Console lifetime and control coupling.
3. Define a native policy subject and its update/delegation contract without granting an
   arbitrary helper APK the login's authority by accident.
4. Integrate native work with genuine Android UID importance, foreground, networking and power
   state, rather than qualifying only individual Binder calls.
5. Revisit observation timeout behavior and resource profiles as a joint safety/availability
   design, not by weakening revocation or freezing proof constants.
6. Implement the proposed native reservation fault containment rather than keeping its current
   global settings coupling.
7. Close signing authority, provisioning, compromise response and independent recovery gaps
   before personal installation.
8. Prove owner variant carry, compatible activation and data recovery across a real upstream
   change before choosing a universal composition mechanism.

## Review vocabulary

**Retain** means the rationale remains sound, not that every implementation is qualified.
**Refine** means keep the goal but improve its mechanism, scope or failure handling.
**Replace vehicle** means a prototype cannot be the product implementation.
**Decide** marks an unselected contract or policy. It does not imply that unrelated work must stop.
**Qualify** marks missing evidence, not a newly discovered architectural defect.

The inventory groups related decisions so that small proof constants are not mistaken for
separate accepted product rules. Every R01 to R18 area is covered. Detailed findings follow.

## Decision inventory

### Foundation, platform and system state

| ID | Decision and current state | Assessment, alternative and remaining gate |
| --- | --- | --- |
| D01 / R01 | Android/Bionic, Binder, ART and hardware services are the one platform. Accepted. | **Retain.** Fits the stated mobile computer goal and preserves Android applications and phone integration. The cost is Android ABI/policy integration rather than transparent desktop Linux compatibility. A second glibc OS or replacement compositor is a different product, not a shortcut required by the current evidence. |
| D02 / R01 | GrapheneOS is the initial engineering base, not a policy ceiling. Accepted. | **Retain and qualify maintenance.** Its coherent Pixel integration is a reason to reuse it. Neither patch count nor its reputation proves Andrix's security. Compare actual carry cost and release cadence with direct AOSP if the rationale stops holding. No maintained derivative release has been qualified. |
| D03 / R01, R17 | Pinned source and Cuttlefish first, physical Pixel later. Accepted development sequence. | **Retain, do not mistake a pin for an update policy.** Repeatable inputs and cheap failure experiments are useful. Hardware constraints should influence design before a late port discovers incompatibility. Emulator results cannot establish radios, emergency use, MTE, thermal behavior or physical key protection. |
| D04 / R02 | Authenticated, normally read only `/usr`; owner programs and state stay separately writable. Accepted boundary. | **Retain.** This separates trusted system inputs from ordinary execution without forbidding unsigned owner code. It does not require every useful tool to become a platform component. |
| D05 / R02, R18 | One host produced, reboot staged `/usr` APEX carries the first tool environment. Prototype. | **Refine, not a permanent package model.** It is coherent for a trusted base but costly as the only shared tool update path. Compare ordinary private packages, authenticated shared packages and component profiles before putting every tool update behind a reboot. |
| D06 / R02, R11 | ARM64/API 37 and pinned SDK/toolchain inputs. Current build anchor. | **Retain exact inputs; qualify evolution.** Not a permanent freeze of API level, CPU targets or supported language features. A working compiler for this cohort does not establish compatibility after its libraries or platform change. |

### Accounts, ordinary authority and Android capabilities

| ID | Decision and current state | Assessment, alternative and remaining gate |
| --- | --- | --- |
| D07 / R03, R04 | Full Android users have integrated Unix identities, homes and work. Accepted. | **Retain.** Reuse genuine UserManager and CE authority rather than a disconnected account database. The unavoidable cost is mapping Unix expectations to Android user stop/switch behavior. User 0 is only a qualification bound. User ID reuse and other users remain unqualified. |
| D08 / R03 | Programs deliberately sharing a Unix login share ordinary authority; optional restriction needs another real principal. Accepted. | **Retain and explain.** This is ordinary Unix composition, not a sandbox per binary. Malicious code deliberately run in that login can misuse that login's grants. Another cgroup or display name cannot remove that cost. Restricted execution is a separate capability still to implement. |
| D09 / R03 | An installed or owner signed APK, file grant or editor connection is not a login or admin grant. Accepted. | **Retain.** File access, work submission, work control and administration need separate authenticated delegation. A convenient editor must not silently receive the login's Android policy identity. |
| D10 / R03 | A Package Manager backed native account role is the first bounded implementation direction. Production representation is open. | **Decide the product subject, not by inertia.** Using an arbitrary existing APK shares its policy and some UID resources with that APK's code. A dedicated account policy subject created by trusted platform code is a credible cleaner candidate. An explicit framework principal remains an alternative. Neither requires an APK per executable. See F3. |
| D11 / R03 | Immutable principal profile, exact installed subject Selection, ordinary UID manager and protected worker role. Inactive implementation. | **Retain with qualification.** Caller argv/env/path must not select UID, capabilities, management descriptors or privilege. Sealed data is not authority. Factory, live identity lease, home provider, groups, MAC and lifecycle binding still need connection. |
| D12 / R03 | Native APIs use actual Android permissions and attribution, or genuine supported delegation. Accepted direction with bounded reference evidence. | **Retain.** Native adapters and correctly initialized helpers under the same principal are both credible. A root broker with labels is not delegation. Diagnostic `run-as` and private context bootstrap are not production bindings. |
| D13 / R03, R08 | Native work participates truthfully in UID importance, foreground, networking, battery and power policy. Proposed integration contract. | **Decide and implement one coherent connection.** Init containment does not itself feed ActivityManager/NetworkPolicy UID state. A visible association can affect that state; retention or recent input cannot fake foreground. Ordinary outbound networking is not an uninterrupted Doze guarantee or a universal foreground service requirement. See F4. |
| D14 / R03 | Native pins in `packages.xml`, strict writes and a global native recovery latch. Current inactive mechanism. | **Refine as already proposed.** Coupling every native account to ordinary settings recovery is avoidable. A small PMS owned reservation store with stable UID occupancy and recovery copies is the preferred next comparison. No second allocator, guessed UID floor or positive recovery from directory names. |
| D15 / R03, R18 | Refuse backing package deletion, data clearing and replacement while pinned. Current conservative fence. | **Retain safety, refine maintenance.** It prevents premature identity reuse, but refusing every code update cannot be the permanent rolling update contract. Define updates that preserve the principal and quiescence when an API/helper really must be replaced. Do not merely remove the fence. |
| D16 / R03, R06 | User serial, principal identity, framework epoch, init instance, manager and work IDs are distinct. Implemented in separate components. | **Retain distinct identities; specify their binding.** Each authority should mint the identity it owns. A single global counter would not replace the meanings of these different lifetimes. Publish an ownership/binding matrix and reconcile stale references explicitly. |

### Lifecycle, execution, supervision and resources

| ID | Decision and current state | Assessment, alternative and remaining gate |
| --- | --- | --- |
| D17 / R04 | Genuine user and CE authority, separate from screen relock, directory readability and fscrypt format. Accepted and partly exercised. | **Retain.** Neither an open home FD nor fscrypt v2 proves the current CE key. A proper home provider must supply storage identity and a live lifecycle binding. |
| D18 / R04 | No cleanup wait delays Android key withdrawal; native work ends on authority loss. Accepted contract with finite CE trials. | **Retain.** Key withdrawal, process termination and physical key/plaintext erasure remain different facts. An uninterruptible holder cannot be described as already gone. No new owner decision is needed to rediscover this contract. |
| D19 / R04 | One second query and two second lease; timeout permanently fails the manager. Prototype mechanism. | **Refine.** Source shows a delayed observation can end all work under that manager. Do not freeze the numbers or treat a delayed reply as equivalent to every underlying cause. A better revocation/liveness design must still cover running work; staleness is not permission to continue indefinitely. See F5. |
| D20 / R05 | Android supervises the environment; Andrix owns work; kernel contains; Console is a client. Accepted. | **Retain.** Avoid both application UI lifetime and a parallel unconstrained process world. The new ordinary UID factory needs a real authenticated platform crossing and captured instance capability, not a property or fictional init `system_server` service. |
| D21 / R05 | Captured cgroups, independent cleanup, truthful Empty/Removed/Unknown, complete retirement before replacement. Accepted with finite runtime evidence. | **Retain the fence.** Reconstructed PIDs/paths and synchronous cleanup in PID 1 are worse alternatives. A new root and ID beside a stuck old scope do not alone prove safety: old kernel mutations, CE authority and resources still matter. Availability improvements must establish that isolation first. |
| D22 / R05 | One protected ordinary UID manager per principal. Approved bounded direction, not production layout freeze. | **Retain as the next candidate.** It avoids root transitions for every job and gives a comprehensible failure boundary. Its failure ends that principal's work. MAC, resources, API effect ownership and Android UID integration must make that boundary real. |
| D23 / R06 | Start accepted at most once, exact retry/reconciliation, immutable entry and irreversible Stop. Accepted and partly qualified. | **Retain.** The complexity pays for avoiding duplicate execution and late release after cancellation. A missing reply is not permission to start again. That does not create a general promise of exactly once external effects. |
| D24 / R06 | Stop has an exact retained capability and independent execution lane. Accepted, new work backend has evidence. | **Retain; complete client integration.** A control reference must not become a fresh blocking registry lookup. The legacy Console still queues Stop behind other control work. Its correctness cannot be inherited from the newer service. |
| D25 / R05, R06 | Manager/framework death ends work; ordinary jobs do not restart. Settled behavior. | **Retain and expose as disruption.** Durable configured services may have explicit restart policy, but ordinary work must not be replayed. A framework or manager update therefore has a declared work interruption cost. |
| D26 / R05, R10 | Detach, terminal hangup, shell exit, Stop and reboot are distinct. Accepted Unix semantics. | **Retain; replace legacy coupling.** Console process death and shell exit still end legacy plain work. The newer backend can retain descendants, but does not yet give the Console that full contract. See F2. |
| D27 / R07 | Keep/notification policy is optional, not permission to compute. Accepted. | **Retain the distinction.** Exact notification Stop and owner indication are useful. Do not require notification channel availability or tmux for all ordinary work. An optional retained presentation mode need not be removed merely because it is optional. |
| D28 / R08 | Work participates in pressure, thermal and power policy below essential phone functions. Accepted. | **Retain; qualify on real workloads and hardware.** No universal promise of uninterrupted CPU/network. Authorized administration can change policy, with changed guarantees. |
| D29 / R08 | 256 MiB, NPROC 32, 128 FDs, 64 MiB per file, fixed priorities and small record pools. Proof class. | **Replace as product defaults, retain bounded experiments.** NPROC counts threads across the real UID, including helpers; file size is not a disk quota. These limits are not justified for a useful compiler environment, multiple accounts or all native workloads. See F6. |
| D30 / R03, R09 | NNP, scoped MAC, complete descriptor closure and an additional seccomp filter. Implemented boundaries. | **Retain the transition; document restrictions.** Legacy Binder denial protects UID 7500 and must not be removed by analogy. The ordinary principal path is separate. The inherited io_uring denial needs a stated attack surface/compatibility rationale, not silent promotion from a test filter into a permanent owner computing ceiling. |

### Terminal, tools, files and recording

| ID | Decision and current state | Assessment, alternative and remaining gate |
| --- | --- | --- |
| D31 / R10 | Reuse a pinned terminal parser/view behind a process free adapter, not Termux's launcher. Implemented. | **Retain reuse; fix integration defects.** This avoids another parser implementation while retaining Andrix process ownership. Dependency logging, clipboard, accessibility and update maintenance are still our responsibility. F1 is a concrete counterexample to assuming the adapter already satisfies privacy policy. |
| D32 / R10 | Revocable streams, acknowledgements, bounded queues and explicit gaps. Implemented. | **Retain transport honesty; refine presentation recovery.** A missing byte interval cannot reconstruct a parser. Killing the work or requiring tmux is not the only possible product answer. Compare retained parser state, safe snapshots/redraw and explicit terminal unavailability without ending unrelated work. |
| D33 / R10 | Foreground/unlocked terminal I/O, explicit clipboard actions and guarded accessibility. Implemented partly, broad behavior unqualified. | **Retain authority separation.** Automatic OSC clipboard access stays distinct from user copy/paste. Authorizing an IME/accessibility service is an explicit information crossing. Task snapshots, caches, malformed output, diverse input methods and accessibility need coverage. Do not invent complete privacy from disabling key logging. |
| D34 / R11 | Native compiler and ordinary build tools on ARM64/Bionic with pinned dependencies. Demonstrated in bounded workloads. | **Retain.** Native development is real functionality, not an APK launcher trick. Optional languages, plugins, large builds and phone resource behavior remain qualification work. Serial examples and excluded build features are not permanent product limits. |
| D35 / R11 | Static C++ runtime for standalone programs, explicit package private shared runtime for plugins. Qualified bounded profiles. | **Retain useful profiles; refine the product library model.** This solved a real isolated namespace failure without globally opening Android lookup. Static/private copies require rebuild or explicit replacement to receive fixes. Evaluate a scoped native linker namespace and coherent package closures, not a blanket global path addition. See F9. |
| D36 / R12 | Debug ordinary owner programs, not coordinator/other app identities. Finite LLDB and negative controls. | **Retain.** Same login debugging deliberately shares authority. The LLVM Android client adaptations and missing scripting/JIT/expression combinations are maintenance/qualification limits, not a complete upstream supported debugger. |
| D37 / R13 | User files, live work state, durable result history and output recording are distinct. Accepted. | **Retain.** Program exit or Stop is not storage durability. Ordinary execution must not need a writable history database. Durable receipts require separate commitments rather than inferred success from saved terminal output. |
| D38 / R13 | Minimal protected security records; activity/output history, debug and export off unless enabled. Accepted policy. | **Retain; implement and audit the whole path.** This deliberately sacrifices complete forensic history for privacy. Event selection, flood resistance, coverage indicators and secondary copies remain unqualified. Raw parser error logging already violates the intended direction. |
| D39 / R13 | Sensitive persistent records use CE, without an automatic DE fallback. Accepted. | **Retain the privacy choice and disclose gaps.** Events may be lost while CE is unavailable. Essential operation and identity recovery metadata is not optional history; define its minimum DE needs rather than misclassifying it as either secret transcripts or discardable logs. |

### Administration, signing, composition and recovery

| ID | Decision and current state | Assessment, alternative and remaining gate |
| --- | --- | --- |
| D40 / R18 | Deliberate general root, complete administrative context, no permanent elevation for daily work. Accepted requirement. | **Retain; mechanism unselected.** Define authorizing principal, effect scope, lifetime and revocation. Do not let a view own accepted root work merely because its presentation closes. Signing remains separately scoped. |
| D41 / R18 | Distribution provenance, developer identity, owner deployment authority and boot/APEX/APK roles are distinct. Accepted/proposed contracts. | **Retain.** A common key or one trust boolean would hide real differences. The Terminal and `/usr` APEX container currently share a development certificate; do not inherit that coupling into a production topology. |
| D42 / R18 | Portable encrypted recovery plus a protected on-device signing copy. Accepted default. | **Retain, add compromise response and provisioning gates.** It serves independent owner recovery but creates a valuable exportable backup. Loss recovery is not compromise recovery or user data recovery. The generated/imported plaintext interval, trusted manifest commitment and role specific rotation limits need explicit treatment. |
| D43 / R18 | One immutable protected signing transaction and fresh authentication, not one prompt per cryptographic callback. Accepted policy. | **Retain; implement the mechanism.** The current one-operation Android vehicle does not implement a complete multi-format transaction. Do not silently select a timed key window to paper over that gap. See F10. |
| D44 / R18 | Nonexportable custody is not exact intent protection against a compromised OS. Proposed threat boundary. | **Retain honesty; select stronger claims explicitly.** A real PIN prompt cannot authenticate an untrusted display or altered input. Keeping boot/OTA roots off device or introducing another trusted execution path changes capabilities and cannot be silently imposed as a refinement. |
| D45 / R18 | Workshop modification is legitimate; locked owner keyed operation is a later option. Accepted. | **Retain the capabilities; refine assurance reporting.** Workshop does not require disabled verification for every edit. Mutable factory partitions weaken trust anchors even if data APK checks still run. Lock state, key identity, partition verification and runtime MAC are separate axes. Physical mode changes and data consequences need qualification. |
| D46 / R18 | Rolling compatible sets, preserved owner selections and visible missing security fixes. Accepted. | **Retain; demonstrate upstream carry.** Owner modifications cannot automatically be merged safely forever. Stable configuration/extension interfaces may reduce the burden; source forks stay legitimate. A clean textual merge or large versionCode is not a security update. |
| D47 / R18 | Owner intent, resolved inputs, artifacts, native deployment and observed health are separate facts. Proposed model. | **Retain responsibility boundaries; avoid premature universal machinery.** Implement the minimum vertical workflow before a package language, universal privileged daemon or full store framework. Reuse Nix/Guix/tree deployment mechanisms only after actual Android/Bionic cost checks. |
| D48 / R18 | APK/APEX versions are not composition identity; realization may use native selection, coordinated codes or images. Unselected. | **Decide through comparison.** Neither image based activation nor a framework extension is inherently cleaner. Image assembly can reuse cached artifacts; focused APK changes need not rebuild an OS. Preserve independent developer signatures and application facing version meaning. |
| D49 / R18 | Signing, installation, staging and disruptive activation are separate effects. Accepted/proposed contract. | **Retain.** Staging cannot authorize surprise restart or reboot. A UI may approve a clearly bounded combined operation, but omitted effects are not implied. Accepted native effects remain owned after reply loss or cancellation. |
| D50 / R15, R18 | Known good code, mutable data, trust identity and firmware have separate recovery contracts. Accepted. | **Retain.** Forward good code restoration is demonstrated, not universal data rollback. Native rollback/checkpoint and slot mechanisms have class specific limits; they are not all forbidden or all atomic. A real independent recovery route and crash escalation policy remain missing. |
| D51 / R18 | Active/recovery generations, pending operations and readers retain artifacts; reclamation needs capacity. Proposed. | **Retain; qualify under phone storage constraints.** Ordinary package GC cannot remove unresolved dependencies. Conversely, safety holds need visible repair/reconciliation rather than invisible permanent capacity loss. Retention counts and shared/private store placement are still unselected. |

### Networking, hardware, evidence and sequencing

| ID | Decision and current state | Assessment, alternative and remaining gate |
| --- | --- | --- |
| D52 / R14 | Official components do not automatically connect directly to Google; explicit owner use and non-Google provider backends are allowed. Accepted owner policy. | **Retain the actual boundary.** This is not zero Google involvement or a general no-tracking guarantee. Genuine service behavior, redirects and fallback paths require testing; an offline capture or hostname alone is inadequate. |
| D53 / R14 | Genuine attestation via the reviewed proxy, honest boot state, no certification gate on owner computing. Accepted direction. | **Retain and qualify hardware.** It preserves a capability without adopting vendor approval as authority. Proxy/backend trust remains a real dependency. Cuttlefish software provisioning does not establish physical attestation or DRM behavior. |
| D54 / R14, R17 | Ordinary outbound access; explicit external/persistent exposure; SSH follows account/CE and locked access policy. Accepted direction, SSH incomplete. | **Retain; qualify actual networking.** Sharing a UID does not prove VPN, data saver, Doze or wake behavior. New SSH disabled while locked is an access policy, not evidence of CE withdrawal or a reason to kill every running job. |
| D55 / R16 | Distinguish source/model, host execution, artifacts, emulator and hardware evidence. Preserve failures and producer identities. Accepted method. | **Retain.** The method has caught real errors. Aggregate test counts and independent model reviews are not end-to-end qualification. Test the oracles too, and keep current decision status separate from long historical run narratives. |
| D56 / R16 | Private raw operating records, exact public provenance, immutable sealed evidence and bounded test resources. Accepted method. | **Retain scope, avoid product leakage.** These protect reproducibility and privacy. Host quotas, disposable guest bounds and test API limits are not phone product policy. Evidence integrity is not protection against compromise of the whole producer. |
| D57 / R17 | Pixel deployment, firmware/license inputs, locked operation and phone qualification come after controlled platform work. Accepted sequence. | **Retain with earlier constraint review.** No current deployable phone or official GrapheneOS assurance exists. Radio, emergency use, suspend, battery, thermal, install and recovery need real hardware plans and authorization. |
| D58 / architecture Agents | Human accounts and ordinary programmable interfaces first; dedicated agents deferred. Accepted. | **Retain.** No owner operation should require a model provider or let automation infer human presence/elevation. Development assistants and their operating machinery are not product agent architecture. |

## Material findings and cleaner directions

### F1. The terminal adapter can leak parser payloads into logging

This is a concrete implementation finding, not a new privacy preference.

`owner/terminal/adapter/TerminalSession.java` creates `TerminalEmulator` with a null logging
client. In the pinned terminal library, `Logger` falls back to `android.util.Log` when that
client is null. Some termcap/DCS error paths log their payload without being guarded by the
escape logging flag. Turning off terminal key logging in `ConsoleActivity` does not cover it.

A host JVM run of the unchanged adapter and parser, with the existing Android Log test facade,
emitted a dummy canary from a malformed termcap sequence. Ordinary text was a negative control.
An initial harness attempt had the wrong odd/even length and failed its own precondition; the
corrected run is retained separately. No Android logd run or actual credential disclosure was
performed or claimed.

Cleaner action: supply a first party logging adapter that emits approved event codes without
terminal contents, or deliberately discards unsupported parser diagnostics. Add canary controls
for malformed escape sequences as well as ordinary input/output and inspect the real Android
logging/secondary-copy path. Reusing Termux remains sensible; passing an unreviewed default
logging policy through that adapter does not.

### F2. The qualified terminal vehicle still compromises ordinary work lifetime

`TerminalController` uses one scheduled `control` executor for discovery, attachment, resize,
renewal and `endSession` Stop. A stalled operation can therefore delay the UI control request.
Legacy plain work also ends with the Console process. The new work service's independent Stop
lane and descendant retention do not fix those clients by analogy.

The accepted distinction between Detach, hangup and work Stop is sound. Complete the Console as
a client of that service and retire duplicate product pathways after proving the replacement.
A terminal output gap must remain explicit, but loss of parser state should not force an unrelated
work scope to be killed. tmux can remain useful, not mandatory recovery machinery for all work.

### F3. A native policy subject is not just an arbitrary APK with a pin

The current adapter deliberately admits an ordinary installed data package. That is a bounded
implementation vehicle, not the chosen product representation. APK code under that UID shares
Android grants, UID accounting, some data/key authority and UID counted limits with the native
login. Adding another MAC role does not automatically split Android's UID permission subject.

A dedicated account policy subject, created through trusted platform code rather than appointed
by an APK manifest, is a credible candidate. The terminal/editor would remain separate clients
with explicit delegation. A framework native subject is another candidate. Compare actual
permission, lifecycle, update and upstream carry behavior; do not decide by the number of changed
files or freeze a manifest permission ceiling as a product limit.

`NativePrincipalManager`'s exact Selection is worth retaining as a designation boundary. It is
not a durable consent record. The eventual account authority must own designation continuity,
recovery and maintenance across package updates without turning every update into permanent
refusal or silently replacing the account.

### F4. Containment and Android UID policy still need one coherent integration

Init/LMKD containment and Andrix work ownership are well separated. But ordinary app UID work
also needs truthful process importance, foreground association, AppOps, VPN, data saver, power
and battery behavior. The notification and mock location references qualify particular paths,
not the entire UID policy surface.

Implement an explicit participant/association in the real Android authorities, whether through
an appropriate representative or deliberate framework support. Do not introduce a shadow TOP
flag, fake activity, a privileged broker using attribution labels as delegation, or a foreground
service requirement for every Unix job. Exact default presentations and resource policy remain
open. A new manager must not simply copy the fixed UID 7500 lifecycle endpoint or socket roles.

### F5. Observation latency currently has a whole manager failure cost

`LifecycleGate::valid` revokes on the issued query deadline. `PlatformLifecycle::failed` makes
that permanent, and the work manager exits when it observes that failure. The observer sleeps
between synchronous snapshot calls. Consequently a late reply can end all work in that manager,
not merely prevent a new launch. This is source established behavior, not a measured frequency
of false withdrawals on a phone.

Preserve genuine revocation and the rule that a delayed positive cannot buy a new lease. Review
whether a supervised authority channel/gate and explicit invalidation can reduce unnecessary
coupling to routine observation latency. An implementation cannot merely keep running forever
after its authority becomes uncertain. Any separation between admission staleness and running
work must come with a proved independent revocation/liveness path. Measure under scheduling
pressure, suspension and backend failure before selecting product timeouts.

### F6. Proof limits and failure holds need product design, not a higher constant

`CheckWorkLimits` enforces the old NPROC, descriptor, file and priority bounds. NPROC is per real
UID and includes threads, so a managed helper can consume capacity intended for native work.
A file size limit does not bound total storage. The delegated adapter also sets group OOM kill
on the aggregate, so independent work IDs do not imply that one job's memory failure is isolated
from the other jobs in that environment. Per work budgets, reserved control capacity and the
aggregate kill boundary need a deliberate product profile. Several managers/accounts also need
global admission and phone priorities, not independent promises based on each local ceiling.

Use measured resource classes with truthful aggregate and work accounting. Keep the Stop lane
independent under saturation. Preserve incomplete cleanup as an owned state, but expose it with
a bounded diagnosis and recovery interface. Starting a replacement beside an unretired group is
not safe merely because its numeric identity differs. Do not weaken the retirement fence to make
an availability demonstration pass.

### F7. Native reservation fault containment is a real redesign, not a completed fix

The current native XML section, strict settings writer and global recovery latch were built and
compiled as an inactive candidate. They still couple native state to ordinary package settings.
The proposed stable slot store separates negative ID occupancy from account usability and is
proportionate to interrupted writes and damaged records/copies. It is not yet implemented.

Keep UID allocation inside PMS, use real signer/user binding for own-slot restoration, and do
not feed identity uncertainty into ordinary invalid APK deletion. Treat arbitrary destruction
of every authoritative copy as disaster recovery, not a reason to guess UID ownership or make
every boot depend on a universal availability versus confidentiality decision.

### F8. Small development conveniences must not become the production trust topology

`owner/Android.bp` and `apex/dev.andrix.usr/Android.bp` both select
`:dev.andrix.usr.certificate`. This couples the Terminal APK and the `/usr` APEX container in the
development configuration. The payload AVB key and platform certificate are separate roles.
This is not evidence of a present exploit or a selected production key layout.

Document the role map and evaluate separation before personal provisioning. Likewise decide who
holds installation authority across Android users, admin grants, credential reset and user
removal. Android user administrator status is a candidate input, not blanket authority for every
app in that user and not the same thing as an APK's device administration role.

The portable recovery default remains sound, but the backup is a high authority object. Qualify
its compromise response and role specific rotation/replacement consequences as well as simple
loss recovery. Package the independently trusted manifest commitment into a usable recovery
flow. Moving some signing roots off device would change owner capability and requires an explicit
decision, not adoption as an allegedly policy neutral implementation detail.

### F9. `/usr` and C++ profiles need a native package update layer

The APEX and current compiler profiles provide useful actual functionality. They are not a
complete native package transaction or shared/private store design. Making all shared tools
APEX contents ties ordinary updates to privileged signing and reboot. Static or project copied
C++ runtimes do not receive new bytes when the base library is updated.

Keep the authenticated base and ordinary owner files. Compare a scoped native linker namespace,
package private dependency closures, ordinary per-user profiles and an authenticated shared
package layer. Each must preserve Bionic, library identity, access control and updates. A Nix
style store, root owned public DE store or image realization is a candidate, not an accepted
answer. Do not globally relax Android library visibility to avoid designing the boundary.

### F10. Signing policy is cleaner than the current signing vehicle

The accepted unit is a complete immutable signing transaction with fresh authentication. The
qualified Android artifact vehicle used one signing operation; a host multi-format case required
several. Neither a timed authentication window nor a platform transaction token issuer has been
selected and qualified for the whole contract.

Build the transaction authority around exact input capture, declared derivation, role scope,
complete output verification/publication and durable reconciliation. Make the approval human
meaningful through source/selection context, not only a digest. A cancellation flag cannot undo
an accepted signature, and a missing result cannot justify a new signing operation.

Nonexportability is not an independent trustworthy intent path when the main OS is compromised.
A workshop trusted-OS claim and a stronger physical signing claim are different products of
qualification. The audit does not pick a timed policy or silently reduce on-device capability.

### F11. Composition needs measured maintenance and real recovery, not only a graph

The separation of intent, artifacts, compatibility, native state and observed health is clean.
It does not itself preserve a local SystemUI change across an upstream release, choose an update
owner, or restore migrated data. No production composition manager has been qualified.

Run one complete owner variant through a compatible upstream change, a conflict and a missing
security fix. Compare focused component and cached image realizations with actual carry and
activation cost. Define the exact native commit and repair boundary for each. Do not conclude
that owner keys force full image activation, that external intent records are necessarily shadow
state, or that a native selection API is automatically simpler.

Recovery must work when the changed UI or signer frontend is broken. The finite SystemUI test
used forward good code restoration and checkpoint rejection controls, not a general crash loop
repair system. The pinned CrashRecovery `RescueParty` source has feature/build dependent reset,
reboot and factory reset prompt paths. It disables itself for normal `userdebug`/`eng` operation
unless explicitly enabled for testing, so our debug fixture is not production rescue behavior.
Its interaction with owner managed components needs deliberate qualification, not a blanket
claim about every Android release or silent disabling of rescue.

### F12. Assurance and evidence must stay as precise as the intended contracts

Unlocked bootloader, chosen boot key, mutable or verified partitions, signed data updates and
runtime SELinux are different axes. Disabling verification of a partition can also make its
factory package certificates, APEX keys and policy unverified anchors. Continuing to check an
update signature does not make that anchor independently trustworthy.

Workshop remains an accepted owner capability. This audit does not narrow it into a mandatory
verified-only mode or require a temporary bench mode. Describe the actual assurance of each
configuration and verify physical transitions before promising painless movement to locked
operation. Similarly, proxy based networking is not zero upstream Google involvement, software
attestation is not hardware protection, and source inspection is not runtime qualification.

The evidence register has valuable scope discipline, but several at-a-glance vehicles and
"next" statements describe historical checkpoints rather than the current integrated product.
Maintain a concise decision/status map and link historical evidence beneath it. This audit adds
that map; it does not convert old component tests into a completed phone.

## Necessary tradeoffs that are not defects to hide

- Bionic/Android integration costs compatibility work for software assuming a desktop Linux ABI.
- Shared login authority makes arbitrary programs under that login mutually trusted for that
  authority. Optional restriction requires a real boundary, not a new label.
- General administration can change the OS and its guarantees. The design does not promise
  protection against a deliberately malicious platform administrator.
- Mutable workshop operation has weaker physical integrity than a qualified locked deployment.
- Portable signing recovery creates an exportable object worth protecting, while purely device
  bound keys risk irrecoverable loss. The owner deliberately chose portability as the default.
- Minimal logging and CE-only sensitive history reduce forensic completeness. More collection
  cannot be silently introduced in the name of recovery.
- Phone resource, power and thermal priorities can interrupt computation. They should be visible
  and measured, not arbitrary quotas or fake foreground exemptions.
- Owner source modifications have continuing compatibility and security maintenance cost.
- Closed firmware and vendor hardware trust remain real limits of the chosen physical platform.

These tradeoffs should remain owner visible. Calling them "no compromise" would conceal them.
They do not excuse avoidable global failure coupling or prototype restrictions.

## Decisions still open, without turning every gap into a question now

The production native subject, durable designation/maintenance contract, authenticated factory
and UID policy integration need a concrete comparison. Resource/presentation policy then follows
real workloads. The native reservation store is an implementation proposal inside that work.

Installation authority across users, role specific trust realization, complete signing mechanism,
compromise recovery, managed selection realization, shared native package layer, elevation grant
lifetime/domain and independent recovery are still unselected or incomplete. Some require owner
policy input at their actual boundary. Many can first be narrowed through implementation and
bounded comparison. This review does not select them by implication.

Do not reopen already settled Android, broad shared login authority, genuine CE withdrawal,
general root administration, optional Keep, transaction approval or portable recovery as though
they were accidental. If new evidence warrants changing them, bring an explicit revision with
its consequences to the owner.

## Recommended order after this review

1. Resolve the concrete terminal logging defect and define the missing direct terminal recovery
   contract, without making the terminal own work lifetime.
2. Settle the native subject and controller/supervisor/UID state binding, including recoverable
   designation and update behavior. Implement the small reservation store and its crash matrix.
3. Connect the protected manager, genuine CE home, resource profiles and first maintained API,
   then qualify the whole path rather than accumulate isolated component passes.
4. In parallel, define installation authority and compare a complete protected signing/component
   transaction with independent repair and an upstream carry case.
5. Qualify pressure, suspend, multiuser, VPN, real phone, physical signing and update behavior
   before making a supported release claim.

Implementation of the new recovery design remains paused for the owner's review of this audit.
No accepted architecture was edited, no policy was weakened, no personal keys were provisioned
and no physical device operation was performed. The only new execution in this review was the
bounded host parser logging reproduction described in F1; it is not another Android runtime pass.

## Primary references

- [Accepted architecture](../docs/architecture.md) and [vision](../docs/vision.md).
- [Design evidence register](../docs/design-evidence.md), R01 to R18, and [current work](current.md).
- [Native principal contract](2026-09-24-native-principal-contract.md),
  [runtime integration proposal](2026-09-24-native-runtime-integration.md),
  [principal entry](../owner/principal-entry.md) and
  [PMS reservation implementation](../owner/platform/principal-pins.md).
- [Delegated supervision](2026-09-17-delegated-supervision-contract.md),
  [work service](2026-09-20-work-service-integration.md),
  [CE integration](2026-09-13-android-lifecycle.md) and
  [terminal adapter](../owner/terminal/adapter/TerminalSession.java).
- [Native toolchain](../toolchain/README.md), [LLDB](../toolchain/lldb/README.md) and
  [logging decision](2026-09-19-logging-defaults-review.md).
- [Owner authority](2026-09-21-owner-authority.md),
  [portable recovery](2026-09-22-installation-key-recovery.md),
  [signing approval](2026-09-23-signing-authorization-scope.md),
  [composition assessment](2026-09-23-composition-architecture-assessment.md) and
  [composition contract](2026-09-24-owner-composition-contract.md).
- [Connected policy](../docs/grapheneos-connected-policy-review.md),
  [GrapheneOS base assessment](../docs/grapheneos-base-assessment.md),
  [Pixel plan](2026-09-21-pixel-integration.md) and
  [artifact/evidence method](../docs/development-artifacts.md).
