# Native runtime integration proposal

Status: proposal for owner review. The notification and mock location references are measured;
the production mechanisms below are not implemented or qualified. Accepted architecture is
unchanged. This document recommends an initial integration direction, not UID allocation,
package formats, signer topology, a software store or new administrative policy.

## 1. Capability being built

An Android user has an ordinary Unix login with native programs, files, pipelines, jobs and
optional services. A program can use supported Android capabilities as that principal, without
root, a package for every executable or a resident Activity. Native program and APK entry are
first class interfaces to the same Android system.

The [principal contract](2026-09-24-native-principal-contract.md) defines the authority rules.
This proposal specifies the next integration shape. It keeps three axes separate:

1. **Principal representation:** the subject Android's permission and policy services recognize.
2. **Execution and accounting:** the processes, descendants and resources that implement work.
3. **API binding and presentation:** how a program calls Android and how real interaction affects
   its eligibility for capabilities that require foreground use.

A work scope is not automatically a sandbox. Programs deliberately sharing one Unix identity
share its ordinary authority. Restricted principals are optional real boundaries, not different
names or cgroups under the same credentials. An APK/editor receives neither a Unix login nor
administrative authority merely by being installed or signed by its owner.

## 2. What the evidence changes

The [notification reference](2026-09-24-native-principal-reference.md) and
[location reference](2026-09-24-native-principal-location.md) establish a useful reference:

- A process running independently of an APK Activity can use an Android recognized package/UID
  subject. Correct operation attribution matters in addition to resource/package lookup.
- Notification ownership and grant checks for each user operated under ordinary application UIDs.
- Fine location permission withdrawal affected an existing native listener without killing its
  process. Regrant and observed UID foreground transitions changed delivery on that same listener.
- Grants and provider setup were privileged fixture operations, not owner consent UI proof.
  The location source was a controlled mock, not physical sensor or power qualification.

They also reject shortcuts. `run-as` retained shell groups and launcher resource placement.
The private context factory is not a complete application runtime: added keyguard telemetry
failed on missing `ApplicationSharedMemory`. Fabricating that memory or disabling its checks
would make a false platform state, not a supported binding.

These results support the direction. They do not select a production principal representation,
make every Android API available, or qualify the current launch profile.

## 3. Recommended initial direction

**Use a framework recognized native principal role, integrated with Package Manager policy
subjects first, together with an explicit native work entry and maintained API bindings.**

This is a recommended first implementation path to approve, not a permanent requirement that
the representation be an ordinary APK. Principal registration is account state. Executing,
compiling or changing an ordinary binary must not install or register that binary as a package.

For the initial path:

- Reuse Package Manager's authoritative package/UID/user relationships and Android's permission,
  AppOps, network and attribution machinery. Add explicit lifecycle semantics for native principals
  where needed; do not hide a Unix account behind an accidentally uninstallable dummy app.
- Establish a complete native execution profile before owner code runs. Integrate its real
  lifecycle with Android's process/UID importance and resource authorities, while retaining
  Andrix's distinct work admission, Stop, result and job policies.
- Expose maintained native interfaces for capabilities. Prefer native bindings where practical;
  use a correctly initialized runtime or helper under the same principal when an API needs it.
  Do not make every ordinary program import private framework internals.
- Derive foreground eligibility from genuine platform observed presentation and explicit
  association with the native principal. A daemon, retained job, open socket or recent input
  timestamp does not appoint itself foreground.

An explicit framework principal record remains an alternative if package lifecycle semantics
require excessive special cases. The comparison must stay open until the first integration and
an upstream carry exercise establish the actual cost.

## 4. State and responsibility

| State or effect | Authority | Integration responsibility |
| --- | --- | --- |
| Android user, incarnation and genuine CE availability | User and credential services | Bind native accounts/work to the real user lifecycle; fail closed on stale authority |
| Installed subject, UID and signing continuity | Package Manager and its native trust rules | Resolve a principal role from authoritative state, never from a supplied UID or package string |
| Native principal association and incarnation | Framework validated binding to the above authorities | Keep only necessary mapping/generation records; close old bindings before reuse |
| Permissions, AppOps, capability use and revocation | Existing Android capability authorities | Preserve actual caller or explicit supported delegation; no second consent database |
| Ordinary work admission, identity, Stop, retention and result | Andrix work authority | Capture kernel scope/process objects; retain uncertain effects until reconciled |
| Outer resource/lifecycle containment | Android init, LMKD, kernel and process policy | Enforce complete subtree cleanup and phone priorities without acquiring Andrix job policy |
| Visible interaction and foreground eligibility | Window/activity/process policy authorities | Validate presentation ownership and association, then apply normal UID/capability rules |
| Administrative execution or installation signing | Separate deliberately authorized mechanisms | Never infer these powers from ordinary native submission or an API context |

A binding record may carry a native principal ID and incarnation, the Android user/serial,
resolved UID, policy subject and relevant native lifecycle references. It is auxiliary state,
not a competing account, package or grant authority. Exact storage and wire shapes remain open.

Recommended ownership defaults are that the Unix home belongs to the native account under
that Android user's real CE authority, not to a replaceable helper's app data cache, and that
removing a native principal is an explicit account operation. It closes admission, resolves
work and API retirement, handles data retention and only then permits identity reuse. Generic
package operations must route through or refuse pending that contract rather than silently
reassign a live account's UID. This is data and authority protection, not a restriction on an
authorized owner replacing the system. Exact paths, representation format and UI remain open.

Package lifecycle needs explicit treatment. Updating a principal's representation is not an
owner command to restart ordinary jobs. Uninstall, force stop, data clearing, removal for an
individual user and identity reuse cannot silently acquire new meanings for the Unix home. The production
role must define and reconcile those operations with the native account/work authorities.
That includes stopped state, revocation of unused application permissions, hibernation and
standby buckets. If a policy depends on use, supply truthful native usage or declared behavior
for the account role,
not fake UI activity. Usage integration must preserve the accepted policy for minimal recording;
it does not authorize collecting raw commands, environments or work history by default.

Updates that replace a helper can end its live API objects. That must produce an explicit
capability/runtime transition or a declared quiescence requirement in the deployment operation.
It must not silently replay ordinary jobs. If the selected package path cannot preserve this
contract, revise the representation rather than hide stops or restarts caused by updates.

## 5. Entry contract

The public ordinary launch request describes ordinary execution: executable, arguments,
environment, working directory and declared data/standard descriptors. It cannot choose a
trusted bootstrap, UID/GID, MAC label, capability set, authority epoch or management descriptor.
This does not forbid normal mutable owner code, `LD_*` values or ordinary Unix descriptor
composition after the authority transition. It does not restrict separately authorized root
commands to a curated menu.

The trusted path performs these conceptual steps:

1. Authenticate the submitting client and any explicit delegation to a native principal.
2. Resolve current principal/user/CE authority and reserve one work identity. No execution yet.
3. Prepare a captured work scope and complete profile: credentials and supplementary groups,
   capabilities, MAC, syscall policy, resource membership/priorities, descriptor map, mount and
   runtime state. Do not inherit the submitting APK's or shell's incidental environment.
4. Establish the selected framework integration for that native work before capability use.
   This may be native attachment or a correctly managed runtime representative, not necessarily
   a `ProcessRecord` for every payload. Bind its result to the same work, principal and captured
   process/scope, not a later PID guess.
5. Release the irreversible execution gate only after all prerequisites are established.
   Close management descriptors and apply ordinary payload inputs only at the ordinary entry.
6. Reconcile execution, framework attachment, API effects and actual retirement independently.
   A lost reply is not nonacceptance. A stopped or stale entry is cleaned up, not released late.

Unmodified `fork`, `exec`, shell pipelines and detached descendants must work. Requiring every
child program to link an Android application callback interface is not an acceptable Unix
execution contract. Framework integration must account for the captured work population and
its descendants, or provide a legitimate native runtime representative with equivalent lifetime
and cleanup guarantees. A representative would not be a UI process or a privilege lender.
Its necessity, cost and failure behavior require measurement. Once the trusted entry establishes
a principal and work association, ordinary descendants inherit that association; they do not
perform a fresh framework attachment merely to use a permitted native API. An interface that
specifically requires a managed component may use the corresponding supported helper.

Requests through a shared helper also need their real work association, not just a shared UID.
Use a scoped endpoint or descriptor issued by the trusted entry and bind it to actual caller
and work membership where required. It is not an init/coordinator management handle. A supplied
work ID or a reconstructed PID cannot establish which scope owns an API request for Stop.

## 6. Reuse the platform's native process work, but do not overstate it

The pinned Android tree already contains a significant candidate that the next spike must
compare before inventing parallel process machinery:

- `ActivityManagerService.attachNativeApplication` adapts an `INativeApplicationThread` to the
  ordinary application attachment path. The existing UID, PID, start sequence and pending
  `ProcessRecord` checks still apply. An arbitrary already running process cannot simply claim
  attachment by supplying a label or guessed sequence.
- The native zygote and `native_activity_thread` runtime provide native process initialization,
  Binder attachment, native service callbacks, process state updates and lifecycle reporting.
  GrapheneOS also routes native app starts through its exec spawning mechanism where selected.
- This route currently targets native **isolated services** declared by APKs. Service setup
  selects it for `nativeService` together with `isolatedProcess`. The runtime loads a library
  and calls `ANativeService_onCreate`; it is not an ordinary Unix `execve` launch API.
- Its wrapper has explicit incomplete areas and empty callbacks. Its native bind message
  currently carries system font data, not the full Java application bootstrap. The native
  launch adapter also documents incomplete argument parity. The presence of specialization
  code is not proof that every required group, descriptor or resource input is applied.
  Prototype support is not a promise of complete compatibility with application services.

The source CP2A release configuration enables the native framework prototype flag as read only.
This is source configuration evidence, not an observation of the feature on our retained image.
No live flag changes or native service runtime qualification have been performed here.

The credible execution alternatives are therefore:

| Route | Reason to compare | Constraint |
| --- | --- | --- |
| Extend the existing native launch/attachment route | Reuses real process records, specialization and Android lifecycle | Must support ordinary native principals and unmodified Unix execution, not merely isolated service libraries |
| A native runtime representative attached through that route | May let ordinary descendants retain Unix semantics while Android sees an explicit work participant | Must not couple lifetime to an APK UI or automatic service restart; overhead and cleanup of the whole scope need proof |
| An ordinary managed helper under the principal, started through Android's normal component path | Provides real SDK initialization and an existing participant in process policy without attaching each Unix child | It must add no unrelated authority. Native work when the helper is absent, helper death/restart, UID idle state, networking and accounting still need qualification |
| Direct integration of native work scopes in framework process policy | Could model descendants without a representative per program | Must feed the real Android authorities, not maintain a shadow foreground/importance registry |
| Retain only the static UID launcher and add capability exceptions | Superficially reuses the current prototype | Rejected as the production direction: it does not establish coherent Android identity, lifecycle or policy |

No route may turn native service isolation off globally or make an ordinary APK's manifest an
automatic grant to an owner login. Creating or entering the owner principal remains separately
controlled. Native isolated services can remain useful for optional restricted work. The reference
results do not prove that every Unix child needs an ActivityManager record, nor that unregistered work
already has correct behavior for every Android policy surface. The managed helper comparator
must be evaluated on those surfaces rather than assumed sufficient from notification/location.

A process has one membership location in a cgroup hierarchy. The native zygote's usual Android
process group and the Andrix work scope cannot both be assumed to own the same process.
Select one coordinated hierarchy: either adopt a scope created by the framework through captured
handles, or make specialization target the validated work scope and update native cleanup and
accounting accordingly. Moving a PID afterward while leaving another manager's cleanup
assumptions based on paths intact is not integration. A helper in another scope needs equally
explicit request retirement when its work ends; it cannot escape the work manager's cleanup contract.

## 7. API binding and authentic runtime state

A supported native API context identifies the actual principal, relevant user/incarnation and
current binding. Caller supplied descriptions may identify the program for presentation, but
cannot replace kernel/platform identity. The library is not itself the security authority;
Android services must still enforce the real subject.

The recommended binding strategy depends on the capability:

- Use public native interfaces where they provide the required semantics.
- Where platform Binder interfaces are private or evolving, maintain an Andrix native adapter
  alongside the matching platform revision and expose an owned versioned interface to programs.
  An Android release change must not silently change the ordinary program ABI.
- Where a managed API/runtime is necessary, compare an initialized runtime/helper under the
  principal's ordinary authority. Same UID alone is insufficient: its MAC, capabilities,
  descriptors and delegation must not lend unrelated service authority.
- A privileged broker is permissible only through an explicit delegation contract supported by
  native authorities, with equivalent grant, attribution, revocation and accounting behavior.
  A broker's permanent permission plus a private boolean is not equivalent. Attribution labels and
  `WorkSource` identify usage; they are not themselves grants or delegation authority.

The ordinary managed application bootstrap illustrates the required standard: system_server
creates the real shared state, AMS conveys the intended read view in `bindApplication`, and
ActivityThread maps it as nonmutable before using it. A client must not create an imitation of
`ApplicationSharedMemory` and present it as that state. Pure native programs need only the
runtime inputs needed by their interfaces; they need not become a full ART application to perform Unix work.

API requests have explicit owner/work association and retirement. Stop must retire the work's
live subscriptions even if a shared helper remains alive for other work. Permission loss must
follow the native capability rules, including existing streams where applicable. Results already
returned cannot be recalled. Notifications and other retained service objects need explicit
release/cancel semantics; process exit alone must not be called complete cleanup.

Helper loss is not necessarily loss of the work manager. The contract must say whether it degrades
only API availability or ends the work whose runtime state it owns. A kill under memory pressure,
user/CE stop, supervisor failure and an explicit owner Stop have different causes, but all
require honest retirement and result handling. No implicit restart or new subscription is
allowed merely because a replacement helper is available.

The current authority contract does not promise work survives loss of its framework instance.
Close old admission and follow its declared policy for loss of authority. Any future recovery
across a framework restart must reconcile real instances and outstanding effects, never adopt
an old process or group implicitly under a new authority epoch.

## 8. Foreground and resource contract

Foreground eligibility is not work retention. Closing or losing a presentation withdraws the
presentation association and applicable foreground contribution. Accepted computation continues
according to its work, user/CE and resource policy. Terminal hangup, shell exit, explicit Stop,
user stop, CE withdrawal and process pressure remain distinct events.

Recommended presentation semantics for owner review:

- A genuine visible native surface or an explicitly attached, authorized Console presentation
  may contribute foreground eligibility to the represented principal through Android's policy.
  The association does not authorize a login, bypass lock/CE attachment rules or extend a
  revoked submission grant.
- An editor's file grant alone does not create that association. Ordinary work submission and
  live presentation are separate delegations. Only the defined visible work presentation counts,
  not merely having a project open or keeping a Binder connection alive. Detaching the work,
  switching to a job list or switching the represented principal withdraws that association
  even if Console itself remains `TOP`. Another valid presentation can still contribute to
  the same shared UID; withdrawal is of the original association, not a forced global state.
- Background/SSH activity, a retained job or an enabled service does not impersonate a visible
  Activity. Use the principal's real background grants and separately authorized wake policy.
  A deliberately authorized ongoing foreground operation may have a real native foreground
  service contract with explicit initiation, capability types, indicators and Stop. Retention
  alone does not create it, and no such service policy is selected here.
- Because the policy subject is shared, a foreground contribution can benefit other programs
  deliberately sharing its UID. Do not advertise permission isolation between programs under one
  identity. Use an optional restricted principal when a separate authority boundary is wanted.

Existing Android service connections already distinguish importance and capability propagation,
including explicit `BIND_INCLUDE_CAPABILITIES` and adjustment associated with an Activity.
Compare that mechanism against a dedicated native presentation association before selecting
another API. Standard component binding requires a suitable helper/representative in the target
principal. A direct integration of work scopes without that component needs another validated association;
separating the design axes does not make their implementations independent.
A binding is only a candidate if its actual visibility, lifetime and permission semantics fit;
it must not inherit unwanted service restart or coupling to UI lifetime into ordinary work.

Memory protection, LMKD adjustment, CPU placement, thermal policy and AppOps foreground
capabilities are related but not identical. The integration must update the real Android UID
state/capability and accounting paths. Do not implement a separate flag that says foreground
while AppOps, network or power policy sees something else. No automatic foreground service,
wake lock, unrestricted background network or priority above work critical to the phone is implied.
Ordinary outbound network authority is not a promise of uninterrupted availability or wake
through Doze. Those accepted requirements are complementary, not contradictory.

Android may still stop, freeze or deprioritize work through declared resource and lifecycle
policy. Work manager ownership of explicit Stop is not immunity from the OS. Conversely, an
ordinary retained job must not be treated as an unused cached UI process simply because it has
no Activity. Package force stop, freezing, hibernation, memory pressure and update effects need
explicit scope and reason reporting, not unrecorded work loss or blanket exemption flags.

## 9. What earns reuse from the current implementation

| Existing part | Preserve as a contract | Revisit in implementation |
| --- | --- | --- |
| Work identity, exact retry/query and catalog rules | Unknown results retain identity; no duplicate accepted Start | Persistent storage/API shape and binding for multiple principals |
| Irreversible admission gate | Stop wins before entry; late preparation creates cleanup duties only | Principal incarnation and expanded authority inputs for the actual user |
| Complete launch staging and descriptor closure | No caller code/environment in privileged preparation; explicit ordinary handoff | Static UID/profile, checks limited to the primary user and limited descriptor map |
| Captured cgroup cleanup and generic init/LMKD supervision | Stop of the whole work scope and a backstop for manager loss, no PID/path reuse | Mapping to Android native process/UID policy and production resource classes |
| CE observer and epoch contract | Genuine credential authority, not screen lock or readable paths | Supported users and the replacement runtime's complete cleanup coverage |
| Filter blocking Binder for the reserved UID | Preserve the existing vehicle's safety and evidence until replaced | It is not the policy of the new recognized principal; neither keeping it nor merely deleting it implements the new contract |
| `run-as`, private context factory and fixture UI | Keep their measured results and failures | Do not ship them as the supported entry/foreground/runtime implementation |

The current ordinary execution description, gate and supervision code are valuable evidence,
not a requirement to preserve every class or process. The replacement may reorganize them if
that yields one clearer complete authority and lifecycle contract.

## 10. Next bounded integration gates

1. **Characterize the available routes.** Inspect actual build/flag availability and run a
   minimal native service lifecycle/profile control, without changing a frozen image's flags.
   Compare an ordinary managed helper using the real SDK bootstrap where appropriate.
   Establish what attaches, which identity/profile it receives, what callbacks exist and how
   the exact instance retires. These test reusable components, not support for an owner login.
2. **After direction approval, implement one ordinary native entry.** One user/principal/work,
   an unmodified native executable and descendants, authenticated framework registration before
   entry, real resource policy and complete descriptor closure. Keep arbitrary UID, SID,
   bootstrap and selection of management descriptors out of the ordinary request.
3. **Join entry to capabilities and presentation.** Repeat notification/location positives and
   negatives under the new complete profile. Observe real UID importance/capabilities and
   background transitions through an authorized presentation association, without dummy UI.
4. **Exercise failure and reuse.** Stop during preparation/attachment, late replies, helper and
   manager loss, callback/descriptor retirement, genuine CE withdrawal, user stop and identity
   deletion/recreation. Include editor file/submission/presentation delegation separation.
5. **Carry the integration.** Repeat the contracts across an upstream change and measure which
   native framework, package and policy assumptions need adaptation. Network/VPN, Doze/power,
   physical sensors and phone behavior remain independent qualification gates.

No probe budget is selected as a permanent owner restriction. Every build/runtime still needs
its ordinary resource admission and exact input/retirement discipline.

Revisit the selected route if package lifecycle cannot protect the account without opaque
exceptions, if a helper must lend unrelated authority, if native process support forces every
program into an application callback model, or if ordinary forks/descendants cannot be accounted
and stopped coherently. A route that cannot preserve native grants, user/CE authority and
retirement across an upstream change has not met the contract merely because one capability
worked once.

## 11. Owner decisions and what can proceed now

The following recommendation needs review before becoming the production direction:

1. Start with a **Package Manager backed native principal role** and explicit account lifecycle,
   while retaining the alternative of a dedicated framework subject if the package contract
   proves unsuitable. This does not choose an APK per executable, UID values, keys or a store.
2. Choose **which genuine authorized presentation establishes foreground association**, with
   background work remaining independent and no authority from an editor's file access alone.
   Shared login authority is already accepted. The resulting foreground eligibility for the
   whole UID must be clear, not reopened as a requirement to isolate every program.
3. Confirm how **native account or restricted principal** permissions are presented to the owner
   and initial capability coverage. Do not imply separate security grants to executables sharing
   credentials. The exact permission declarations/defaults need a concrete review.

Routine source comparison, characterization of existing native routes and tests can proceed
without new authority or personal provisioning. A new principal role, ordinary native attachment
and presentation delegation must have an accepted authority contract before product integration.
A work ticket does not itself give the work manager authority to start or bind an ActivityManager
component. The trusted crossing that creates that association
must authenticate the controller, principal, work and current user authority. Reusing an upstream
native entry does not remove this requirement.
General authorized administration and the accepted signing/recovery defaults are unchanged.

## Source anchors

These are source observations, not new runtime qualification. Full inspected files were matched
to committed blobs. Public pins contain no local operating paths.

| Repository / revision | Relevant source |
| --- | --- |
| `frameworks/base` at `aab06a8bd44c4c2b58eeec780fde83baa9d43a40` | `ActivityManagerService.java:5198–5267,5554–5583` attachment and checks for a pending start; `ActivityThread.java:1490–1500` managed bootstrap; `ApplicationSharedMemory.java:208–217` and its JNI implementation:227–243 |
| Same framework pin | `ServiceRecord.java:1192–1197`, `ActiveServices.java:6387–6394`, `Process.java:797–805`, `NativeZygoteProcess.java` native selection and integration with exec spawning |
| Same framework pin | `INativeApplicationThread.aidl`; `NativeApplicationThreadWrapper.java:77–110,247–300`; `libs/native_activity_thread/src/lib.rs:46–109` and `native_activity_thread.rs:316–342` |
| Same framework pin | `psc/OomAdjusterImpl.java:1315–1336,1929–1938,2116–2131,2202–2216`; `ActivityManagerService.java:16088–16103,16319–16367`; `AppOpsUidStateTrackerImpl.java:219–276` |
| `system/zygote` at `20eebb7f90f66ca9bcf4aea620d4168b48101773` | `zygote/src/child_process.rs:56–151` and `zygote/src/species/android_native.rs:175–215,267–365`, specialization and native runtime entry, not an ordinary owner launch proof |
| `build/release` at `fb0e00657d596e48fc45ed86c9eb6a7c4071d72c` | `aconfig/cp2a/android.os/native_framework_prototype_flag_values.textproto`; source flag enabled/read only, not a measurement of the retained image |
| Andrix at `ee90e2c` | `owner/native/{work_entry,work_launcher,work_profile,worker_filter}.cpp`, admission/launch/lifecycle headers and `supervision/native/service_handoff.h`; preserved prototype contracts and explicit limitations |
