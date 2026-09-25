# Design evidence register

Andrix's goal is a mature, owner controlled Android OS with first class native Unix programs
and APKs. The current prototypes are instruments for learning how to build that system,
not the architecture we must preserve. Correctness and coherence take priority over the time
or effort needed to replace them.

This is the running map from experiments and implementation to evidence, design lessons
and long term intent. It is not a release checklist or an execution diary.

- [Architecture](architecture.md) holds accepted requirements and design decisions.
- This register connects those decisions to evidence, temporary mechanisms and open questions.
- Significant choices follow the [deliberate decision discipline](architecture.md#deliberate-decisions).
  Linked designs record their goal, alternatives, ownership, costs, failure behavior and next gates.
- [Current work](../plans/current.md) selects the next work from those gaps.
- Linked milestones retain the details and limits of their particular checkpoints.
  An older milestone's pending follow-up is not necessarily the current global status.
- Raw captures, machine inventories, credentials and operating records remain private.

## How to read and maintain it

**Vehicle** says what exists: an integrated prototype, component candidate, test facility,
historical experiment or planned capability. None of these labels means production ready.

**Evidence** states what was inspected or exercised. Source/host models, compiled artifacts,
Android emulator behavior and physical device behavior are separate levels. A later source
revision does not inherit an earlier runtime result automatically. Suite totals are not
proof of every feature. Failed or incomplete runs stay visible alongside their useful
observations.

**Implication** is the interpretation of that evidence, not another test result.
**Intent** links an accepted architectural requirement, or explicitly labels a proposal.
**Disposition** says what to retain, reassess or replace. It is not a guarantee that the
current code satisfies the intent or permission to remove preserved artifacts.
**Next gate** names the evidence or design work needed before adoption or expansion.

Update the relevant entry when a prototype changes, a significant test succeeds or fails,
a limitation is found, or a design decision is accepted. Do that in the same change as the
milestone/current-work update. Add new areas rather than hiding them in a completed feature
label. Keep stable entry IDs and mark superseded vehicles instead of erasing their lessons.
Promote intent into the architecture only through an explicit accepted decision. A passing
prototype must never silently promote its own limits, API or process layout into a requirement.
An accepted responsibility model can still have open mechanisms and unqualified failure paths.
Use every area below as a review surface, including inherited choices. Do not claim that an
architecture wide review is complete merely because this register lists the areas.

The register is initially populated from the published milestones and inspected source at
`24a0b84`. It is maintained by area; each evidence statement retains its own source scope.
The [2026-09-21 revision](../plans/2026-09-21-owner-composable-android.md) expands accepted
product intent without adding implementation evidence. R18 tracks that platform work
separately from the retained Unix subsystem. There is no supported release or qualified
physical phone deployment at this checkpoint.

## At a glance

| ID | Area | Current vehicle | Disposition |
| --- | --- | --- | --- |
| [R01](#r01-android-foundation) | Android foundation | Adopted source direction, emulator integration | Retain foundation, qualify maintained device releases |
| [R02](#r02-trusted-usr-and-abi) | Trusted `/usr` and ABI | Integrated APEX/compiler payload | Retain trust/ABI boundary, qualify lifecycle and updates |
| [R03](#r03-owner-identity-and-android-crossings) | Owner identity and crossings | Bounded native owner prototype | Retain authority separation, reassess entry mechanisms |
| [R04](#r04-user-and-ce-authority) | User/CE authority | Platform adapter, host models, lab faults | Retain provenance/freshness rules, extend evidence |
| [R05](#r05-work-and-terminal-lifetime) | Work and terminal lifetime | Terminal prototype and comparative scope fixtures | Implement accepted delegated supervision and Unix lifetime contracts |
| [R06](#r06-work-discovery-admission-and-stop) | Work discovery, admission, Stop | New API and corrected UI candidate | Complete admission/control design and runtime checks |
| [R07](#r07-keep-and-notification-controls) | Keep and notifications | Optional prototype grant/Stop channel | Retain owner control, do not make Keep universal |
| [R08](#r08-resource-policy) | Resource policy | Fixed proof limits | Design product policy from measured workloads |
| [R09](#r09-program-entry-and-environment) | Program entry/environment | Fixed shell/tmux runner entry | Replace narrow entry contract, retain execution boundary |
| [R10](#r10-terminal-state-and-input) | Terminal state/input | VT adapter, journal, leases and UI fixtures | Retain explicit ownership, complete recovery/compatibility |
| [R11](#r11-native-development-tools) | Native development tools | Compiler, C++ profiles and Make candidates | Retain useful tools, extend workload qualification |
| [R12](#r12-owner-debugging) | Owner debugging | LLDB integration and boundary probes | Retain owner debugging, qualify remaining features |
| [R13](#r13-files-projects-and-output) | Files, projects, output | Normal file workflows and bounded output | Keep data independent of presentation, complete output design |
| [R14](#r14-networking-and-attestation) | Networking/attestation | Source review and bounded connected fixture | Retain accepted policy, qualify conditional/device paths |
| [R15](#r15-webview-updates-and-rollback) | WebView updates/rollback | Historical direct AOSP experiments | Retain lessons, no automatic GrapheneOS adoption |
| [R16](#r16-verification-machinery) | Verification machinery | Host models, artifact tools, emulator controllers | Retain strict evidence boundaries, improve fixtures |
| [R17](#r17-phone-release-and-later-capabilities) | Phone release and later capabilities | Requirements/readiness work | Later Pixel work, not a current deployment |
| [R18](#r18-os-composition-and-administration) | OS composition and administration | Scoped component proofs and proposed integration contracts | Define trust and selection, then qualify maintained updates and recovery |

## R01 Android foundation

- **Vehicle:** pinned GrapheneOS Android 17 source and an Andrix Cuttlefish overlay.
  Earlier direct AOSP experiments are a separate historical substrate.
- **Evidence:** source verification, image builds, offline boot and bounded connected/UI
  checks are recorded in the [migration](../plans/2026-09-08-grapheneos-migration.md),
  [offline](../plans/2026-09-08-grapheneos-first-boot.md) and
  [connected](../plans/2026-09-09-grapheneos-connected-baseline.md) milestones.
  Emulator APN and Bluetooth expectations needed corrections specific to that product.
- **Implication:** observed emulator requirements must not become guessed Pixel configuration.
- **Intent, accepted:** [one maintained Android/Bionic foundation](architecture.md#foundation),
  with Andrix owning the full OS design and policy. GrapheneOS is an initial engineering
  base, not a small layer ceiling or permanent restriction on owner capabilities.
- **Disposition:** retain useful upstream integration and hardening deliberately. The
  `2026081300` pin is a reproducible starting point, not an indefinite update policy or
  a qualified device release. Revisit the base on observed compatibility/maintenance costs.
- **Next gate:** test the expanded component workflow on Cuttlefish (R18). Later verify
  compatible device/kernel/firmware inputs and licensing and qualify the actual phone (R17).

## R02 Trusted `/usr` and ABI

- **Vehicle:** the integrated `dev.andrix.usr` APEX, with compiler/tool payload variants
  and strict package input verification. This is not a native package transaction system.
- **Evidence:** [offline checks](../plans/2026-09-08-grapheneos-first-boot.md) observed the
  authenticated active APEX, read only `/usr`, Android `/etc`, ARM64/Bionic execution and
  ordinary app isolation. [Package tooling](../toolchain/README.md) verifies the selected
  source, SDK, libraries, payload layout and license closure. These are bounded results.
- **Implication:** payload identity and a working mounted ABI need actual artifact/runtime
  checks; a source manifest or successful packaging command alone is insufficient.
- **Intent, accepted:** [authenticated system state with owner controlled trust roots](architecture.md#trusted-usr),
  one Bionic/system-linker ABI and separately writable owner software/data.
- **Disposition:** retain the first generation APEX as a subsystem implementation and its
  evidence, not the sole system update or signing path. The
  [expanded composition contract](architecture.md#updates-and-installation) permits other
  components and update boundaries. Owner programs need not be APKs or receive platform
  identity; a parallel glibc/desktop product is not adopted.
- **Next gate:** qualify component compatibility, update transactions and recovery on the
  foundation. Do not infer production rollback, data preservation or power loss guarantees
  from current boot tests.

## R03 Owner identity and Android crossings

- **Vehicle:** [`andrixd`, the runner and Console](../owner/README.md), dedicated owner UID/MAC
  roles, a CE home, a narrow platform policy bridge and worker syscall restrictions.
- **Evidence:** the [owner session](../plans/2026-09-10-owner-session.md) exercised real native
  execution, inherited bounds and complete group cleanup, with live owner positives and
  ordinary app negatives. A factory APK signature sidecar caused PackageManager rejection;
  factory packaging and the normal verified APK update path are now kept distinct.
- **Implication:** direct owner execution and controlled Android crossings are different
  capabilities. A trusted UI or coordinator must not execute owner payloads with its authority.
- **Intent, accepted:** [owner authority with native daily processes and isolated applications](architecture.md#authority-identity-and-state).
- **Disposition:** retain actual identity, worker/coordinator separation and scoped crossings.
  Extend the model to full Android users with their own Unix environments, not copies of a
  home under one common UID. Account membership is separate from administrative authority.
  The prototype UID number, fixed entry API and Console implementation are not the product goal.
- **Contract proposal:** the
  [native principal contract](../plans/2026-09-24-native-principal-contract.md) defines the
  proposed identity and policy responsibilities for useful ordinary native Android access.
  UID mapping and process supervision alone do not establish permission, attribution,
  VPN or power policy integration. No principal representation is selected by the proposal.
- **Mechanism source evidence:** the
  [integration comparison](../plans/2026-09-24-integration-mechanism-assessment.md) inspected
  exact committed permission, notification, location, attribution, AppOps and VPN paths.
  UID permission fallback, package ownership and operation policy are distinct checks.
  Default VPN user ranges do not establish package list behavior or packet enforcement.
  A notification test can exercise its permission path without qualifying location,
  foreground importance or power behavior. These are source findings, not a new native
  principal implementation or a reason to grant an ordinary UID a system bypass.
- **Reference vehicle preparation:** the
  [ordinary principal experiment](../plans/2026-09-24-native-principal-reference.md) adds
  an optional permission Activity and a separately invoked ART command. Fifty host argument
  and kernel observation guard checks passed, as did public SDK compilation. Stock `run-as`
  selects a debug domain with additional debugging access; it is not the final owner launcher.
  Reflective framework context bootstrap may still fail at runtime. The subsequent standalone
  SDK build from `cbe739e` produced three verified ordinary APKs with exact package, permission,
  certificate and debug flag controls. API 36 compile/code generation inputs do not lower the
  unchanged API 37 minimum and target declarations. Earlier compiler selection and artifact
  observer failures remain separate. Neither compilation nor artifact verification is an
  Android permission, UI delivery, Soong module or process lifetime result.
- **Initial runtime:** a fresh emulator run of the reference at APK producer `cbe739e`
  and observer `d4923a4` reached own-package contexts for two ordinary app UIDs without
  starting their Activities. Nondebuggable entry and direct shell payload controls refused.
  The debug route retained shell supplementary groups and launcher cgroup placement, not a
  sanitized production profile. Notification construction/submission raised `SecurityException`
  before the granted positive was attempted. That initial result did not identify the layer.
  A second fresh diagnostic at `01da2ca` observed the notification grant as true, but attribution
  package `android` under the ordinary app UID. Notification Manager rejected the operation
  package mismatch, as its source ownership checks require. Context creation had retained the
  system container's operation identity. Both results and successful cleanup/VM retirement
  are retained separately. Neither qualifies delivery, revocation or another user.
- **Corrected reference runtime:** source `c1a51ff` resolves the actual UID's fixture package
  through Package Manager and uses a private application context factory without inheriting the
  system operation package. The notification service matrix passed in a fresh guest: three own
  granted positives, foreign package refusal after an own positive, cancellation, denial of new
  posts after revocation, and separate grant behavior for a newly created full Android user.
  Nine raw service protobuf observations were checked by two decoders. No fixture Activity was
  started. User/package cleanup and VM retirement completed. This qualifies that bounded
  reference path, not visible SystemUI delivery, owner consent UI, live location revocation,
  a stable native API or the production launch profile. Earlier failures remain unchanged.
- **Location reference:** the [bounded location matrix](../plans/2026-09-24-native-principal-location.md)
  at `2b5212f` passed with fixed mock input, a peer delivery witness, current UID/registration
  state and finite retirement. Ordinary background grants delivered fresh markers. Revoking
  fine permission deactivated an existing fine listener without killing its process; regrant
  restored delivery. Foreground grants followed observed Activity/UID transitions while the
  native listener remained the same. New requests without location permission were refused.
  Native mock/setup state was restored and the fixtures retired. Four earlier incomplete
  attempts are retained, including the unrelated shared memory diagnostic limitation and
  an ignored Home action. This is not real sensor, UI consent, power/VPN or production launch
  qualification.
- **Integration proposal:** the [native runtime contract proposal](../plans/2026-09-24-native-runtime-integration.md)
  recommends a Package Manager backed native principal role and compares framework entry,
  ordinary managed helpers and native runtime representatives without selecting their physical
  layout. Source inspection found guarded native application attachment, native zygote support
  and an incomplete isolated native service lifecycle in the pinned platform. These are reuse
  candidates, not an ordinary native entry qualification. The first
  [runtime route comparison](../tests/native-runtime/README.md#observed-result) observed native
  isolated entry/Binder communication and normal managed SDK initialization. Its full callback
  gate remains false: Android killed the isolated process as no longer needed before its destroy
  callback was observed. Complete launch profiles, captured work ownership, cgroup coordination
  and authentic platform bootstrap state remain necessary.
- **Next gate:** review that direction, characterize the available runtime routes and implement
  the supported native entry, API binding and foreground contract. Qualify the
  [account mapping](../plans/2026-09-21-android-unix-accounts.md) and
  [general elevation](../plans/2026-09-21-owner-authority.md) independently. Existing
  ordinary app/coordinator negatives do not establish those new boundaries.

## R04 User and CE authority

- **Vehicle:** Android lifecycle adaptation, native issued-query freshness gate, host models
  and compile time lab fault controls. The earlier ordinary app witness/public polling and
  proposed synchronous cleanup barrier were not adopted as native key authority.
- **Evidence:** [platform integration](../plans/2026-09-13-android-lifecycle.md) records reset
  provenance and backend publication race corrections. The [fixed fault trials](../plans/2026-09-14-lab-lifecycle-faults.md)
  exercised real CE locking with busy files and a delayed genuine reply. Old work groups were
  removed and normal PIN/fresh-work recovery was observed without a framework restart or reboot.
  Complete physical key removal, abnormal backend failure and general suspend/pressure are open.
  The [new admission CE trial](../plans/2026-09-19-owner-admission-ce-trial.md) at `8621e11`
  passed its listed finite controls after 420 host tests and matching selected artifacts.
  Real withdrawal closed the original admission. Release, late creator completion and
  retry did not revive it after normal PIN regrant. Fresh owner execution bound the new
  epoch, read saved CE data and exited zero. Both enclosing environments retired, the
  final owned hierarchy was empty and authority bookends matched. Four earlier incomplete
  attempts remain preserved. The helper's own startup timeout won before regrant, so this
  is not a live late helper result or proof of physical key erasure.
- **Implication:** directory policy, an open descriptor, a cached unlocked flag or a surviving
  app is not continuous key authority. A late positive must not extend an expired query lease.
- **Intent, accepted:** [Android user/CE authority independent of screen relock](architecture.md#lifecycle-and-networking),
  with no fake availability or cleanup barrier delaying key withdrawal.
- **Disposition:** retain provenance, epoch and freshness principles. Reuse or replace the
  adapter according to the final design. Lab injection endpoints stay absent from normal images.
- **Next gate:** carry those invariants into new work supervision and test the unqualified
  backend/suspend/pressure cases separately. The older comparison factory manager has no
  original platform binding; a late guardian starts its own current binding. Its two
  successful trials stayed within one epoch and did not close that gap. The new admission
  component binds the original epoch, with the finite real CE result above. Complete
  product integration and broader failure controls without weakening the fence.
  A successful real lock call with busy files is not erasure proof. The expanded account
  model also requires actual user specific authority and cross-account isolation; these
  primary user results cannot supply it by analogy.

## R05 Work and terminal lifetime

- **Vehicle:** plain work tied to Console process lifetime and explicit Keep using tmux.
  `TerminalProcessState` now separates terminal process role from the retention flag.
- **Evidence:** [Keep](../plans/2026-09-14-keep.md) and
  [retained presentation](../plans/2026-09-13-retained-terminal.md) exercised return, relock,
  frontend retirement, Stop and reboot in the emulator. The
  [separation record](../plans/2026-09-16-work-terminal-separation.md) scopes later component,
  module and partial runtime observations. These do not prove general Unix job lifetime.
  Ten [real Linux process/shell probes](../tests/owner-work-lifetime/README.md) now distinguish
  last-master hangup, ignored HUP, parent exit, subreaper adoption, `setsid` membership and
  configured Bash/nohup/disown behavior. The complete host suite passed 354 tests, followed
  by 100 further case executions. Those are host observations, not Android mksh results.
- **Implication:** a shell, a replaceable frontend, the UI connection and the supervised
  process scope cannot all share one implicit lifetime. The current root-exit policy would
  terminate detached descendants too; its test is a prototype policy test, not a Unix requirement.
- **Intent, accepted:** [Unix lifetime semantics](architecture.md#lifecycle-and-networking):
  view loss/Detach is not terminal hangup, shell exit is not blanket descendant Stop,
  detached work needs no Console or mandatory multiplexer, and explicit Stop is complete.
  The [delegated supervision model](architecture.md#work-supervision) assigns work to
  Andrix and the outer service boundary to Android without fixing a helper process layout.
- **Disposition:** replace the coupling. One work per coordinator/init cgroup is the current
  tested cleanup mechanism, not a required final process layout. No identity reuse or weaker
  cleanup is allowed merely to add more work scopes.
- **Next gate:** specify and qualify the accepted [delegated service and work contracts](architecture.md#work-supervision).
  The [current contract draft and source impact map](../plans/2026-09-17-delegated-supervision-contract.md)
  separates generic service lifetime from work policy. Its executable ordering model
  checks cancellation, late resources, mutation/observation fencing and restart identity;
  it is not kernel or Android authority evidence. A separate Linux probe exercised
  captured group kill after leader reap, stepped directory reclamation, interrupted
  cursor recovery and refusal of a stale control after pathname reuse. Its unrelated
  control responses do not prove Android init responsiveness. A
  [native state/cgroup candidate](../supervision/README.md) adds bounded tickets, captured
  control FDs, cursor ownership and limits. Native host tests also exercised a real late
  member, permission denial and deterministic replacement while retaining restart fences.
  At `8a7ddd1`, 386 host tests, Android library/link compilation and frozen Soong host
  tests passed. At that checkpoint these components were not an Android service adapter;
  cleanup/reap/control integration and runtime qualification were the next gates.
  The initial optional init adapter at `f78d91e` compiled and passed four actual parser
  construction cases, not Android execution. Source review then identified LMKD's separate
  UID/PID group lookup. Its [captured registration extension](../supervision/lmkd/README.md)
  compiled and linked together with init at `5f9c893`; frozen actual parser and packet/FD
  transport tests passed. This is still not Android execution, control responsiveness,
  actual MAC/resource binding or memory pressure qualification. Normal/selected modules,
  policy and complete images later passed at `40696f3` with 395 host tests. Its first
  Android run reached ordinary peer RPC and actual captured LMKD registration, but
  full readiness failed on init re-exec and readiness socket MAC checks. No scoped
  descendant, cleanup/restart or memory kill result was reached. The failed attempt
  also exposed a policy inspection error: a query matching any requested permission
  is not evidence that all requested permissions exist. Required permission coverage
  is now checked per exact source, target and class. The corrected worker and directory
  retirement candidate at `c11e707` passed 399 host tests, real host kernel recovery
  controls, Android module/policy gates and matching complete images. Its second Android
  run stopped before worker initialization. The held bootstrap did not proceed, its
  exact process was terminated, and framework authority bookends matched. Source review
  identified SIGKILL/SIGSTOP in the spawn default signal set, which Bionic rejects before
  exec. The correction at `b05d656` passes 400 host tests and the selected native/policy
  artifact gate, including five actual init parser/event tests and the LMKD transport
  host test. Its added actual Bionic signal controls are compiled but unexecuted.
  The third fresh trial at `3441868`, from matching complete images, passed the actual
  Bionic positive/negative controls. The helper initialized and retired seven rejected
  startup scopes before replacement. Readiness role observation still failed on missing
  `process getattr`; bootstrap library searches were also denied. Source inspection of
  the running kernel distinguishes the ignored open-side ptrace helper failure from
  the SID read permission. No ptrace authority or socket-label substitute is proposed.
  The narrow observation/library correction at `b504a97` passes 401 host tests and both
  normal/selected native and compiled policy gates. The actual init parser/event and
  LMKD host transport cases also pass. A subsequent fresh selected image and matching
  tools at `df1a4b8` completed the
  [listed finite Android controls](../plans/2026-09-18-delegated-service-qualification.md):
  real activation, detached contained descendants, independent init progress during
  stopped cleanup, complete retirement before replacement, stale Stop rejection, worker
  recovery, fresh work and the captured LMKD reaper operation. Independent process
  samples and init/LMKD logs supported the result; framework authority bookends matched.
  This is not ordinary owner execution, real pressure, fresh CE loss, uninterruptible
  I/O or phone qualification. Those remain separate gates, along with Andrix admission
  and Console integration. The next [internal admission gate](../plans/2026-09-18-work-admission-gate.md)
  at `d211b25` binds the original authority epoch, uses one shared atomic release/entry
  object and makes Stop independent of the admission/terminal lock. Updated 404 host
  tests, sanitizer checks, selected concurrent orderings and real separate processes
  exercised queued wake rejection, expiry, late old-epoch helpers and new explicit work.
  Normal/Keep Android native modules and the frozen Soong host admission test passed.
  Those component checks did not qualify Android owner execution. The subsequent
  [ordinary owner launch trial](../plans/2026-09-19-owner-launch-qualification.md) at
  `fbccb19` passed its listed enforcing Android controls after 412 host tests and matching
  selected images. It compiled and ran owner code with caller argv/cwd/env/preload,
  checked actual profiles and descriptor closure, and exercised ordinary app negatives,
  late creator Stop, real queued wake rejection, independent work, detached descendants,
  manager exit cleanup and an empty replacement followed by new work. The mutable gate
  remained in the coordinator role; the inherited filter and fixed NNP transition preceded
  ordinary execution. A subsequent [finite CE trial](../plans/2026-09-19-owner-admission-ce-trial.md)
  at `8621e11` exercised original request refusal through genuine withdrawal/regrant and
  new explicit owner execution. Neither result qualifies the public work/Console API,
  pressure, exhaustive races or physical phones. The earlier
  [supervision candidate and proof matrix](../plans/2026-09-16-unix-work-supervision.md)
  retains its evidence limits and the open Android shell controls.
- **Supporting mechanism record:** the [scope boundary experiment](../tests/owner-scope/README.md)
  uses fixed named slots. Source review rejected the direct temporary-service shortcut
  because it does not establish the required empty capability bounding set. Source `57a43b6`
  passed module/image inspection; its first Android attempt registered both guardians but
  failed on owner access to inherited coordinator pipes before payload release. Dedicated
  fixture channels in `101f253` then reached both held workers. That run stopped on a collector
  assumption that cgroup membership was v2-only. A fresh corrected observation then recorded
  both released scopes, detached descendants and ordinary-app negatives. Its Stop control failed
  because a synchronous caller-PID check was applied to `oneway`. Corrected `0e60a42` then completed
  the listed fixed-slot Android controls: independent complete Stop, live scope B, old Binder/ID
  rejection, held-entry cancellation and late release refusal. Actual oneway PID zero was observed.
  Init killed the released detached descendants; a denied parent-death signal is not cleanup proof.
  The owner approved a [comparison](../plans/2026-09-17-work-factory-comparison.md) of an
  external manager using existing Android facilities and a narrow init extension.
  A focused real Linux host test confirmed recursive nested group kill, but empty child
  directories still prevented parent removal with `EBUSY`, not assumed `ENOTEMPTY`.
  Captured control/directory FDs also did not resolve a replacement after path reuse.
  Actual init parser construction tests passed four cases at `166ff64`, preserving the
  explicit empty capability/profile fields without copying live service state. These
  are mechanism results, not an Android backend verdict. The next separately gated
  Android variants at `7b8a117` passed native/policy/image gates. A reached two held
  dynamic workers, then its observer hit private directory permissions. B exercised
  dynamic creation, independent Stop, stale IDs and blocked allocation cancellation.
  Init also logged complete cleanup after manager loss, but an observer mistook a removed
  group for a populated one and stopped before recovery. Those runs remain incomplete.
  The corrections then passed 366 host tests and complete matching artifacts at `409fc6d`.
  Both fresh Android trials completed the listed controls, including manager failure,
  a fresh epoch with no restarted jobs, old hierarchy retirement, new work and final
  cleanup. A observed Empty nested groups before explicit reconciliation, including
  init's parent removal retry; B observed groups already Removed by init. Each retained
  its platform and boot identities. The owner then accepted the refined
  [delegated supervision ownership model](architecture.md#work-supervision), not either
  fixture unchanged. Complete profiles and generic Android subtree cleanup are required
  alongside manager ownership of work. The combined contract, resource failure, forced
  PID reuse, blocked components and broad product qualification remain unproved.

## R06 Work discovery, admission and Stop

- **Vehicle:** `WorkInfo`, `describeWork`, exact Binder/work ID `stopWork`, and Console's bounded
  metadata tracker. Work creation still occurs through legacy Attach/New kept operations.
  A separate [bounded registry core](../plans/2026-09-19-work-registry-core.md) implements
  the next internal reservation/control and completion bookkeeping boundary.
- **Evidence:** [source `13a1af0`](../plans/2026-09-16-work-terminal-separation.md#observed-candidate-behavior)
  has matched native/Console builds and a lab image. Observations covered idle discovery without
  work creation, detached plain End, cold kept discovery/End without a new frontend, and repeated
  fault recovery. The overall fixture reached its deadline; it is not a full runtime pass.
  [Correction `1571c7b`](../plans/2026-09-16-work-terminal-separation.md#review-correction-and-remaining-responsiveness-limit)
  passes 353 host tests and both Android module configurations, but has no new runtime result.
  The [scope experiment](../tests/owner-scope/README.md#released-work-observation-and-binder-correction)
  also exposed the difference between synchronous Binder caller metadata and oneway's absent PID.
  Both factory vehicles at `409fc6d` then exercised Stop during a blocked allocation and
  late helper completion without payload, plus exact old identity controls. That separate
  fixture does not fix Console's shared control lane or establish arbitrary RPC responsiveness.
  Source inspection also leaves queued/concurrent Release versus Stop unqualified: the
  fixture's Stop check and Release send are separate, as are guardian authority checking
  and the payload release write. The blocked allocation result is not proof of those
  release interleavings.
  The new registry uses the separately tested shared gate. Focused optimized/sanitizer
  checks cover bounded allocation and creator tickets, ordered stream replay, forgotten
  keys, pinned handle capacity, immutable descriptions, ordinary exit without descendant
  Stop, stale observations and cleanup timeouts. Selected thread races exercise duplicate
  Start, Start/Stop and late gate allocation. At `fd75e1e`, all 423 host tests, separate
  ThreadSanitizer execution, ARM64 library compilation and the frozen Soong host test
  pass. Normal native binaries match the retained reference. An archive dependency and
  inspection assumptions about ELF versus multiple LLVM bitcode modules were corrected,
  with failures retained and no disabled compiler checks. These are actual component
  executions with supplied backend facts, not authentication or kernel cleanup proof
  for a new service.
  The subsequent [gateway and stream slice](../plans/2026-09-19-work-gateway-boundary.md)
  adds bounded packet/descriptor ownership and exact input binding retries. Host controls
  use real Unix sockets, credentials, processes and pipes. The host lacks socket LSM
  context data, and the authorization path refuses that absence; supplied role policy
  cases are not Android MAC qualification. The endpoint authorizes an owner principal,
  not a PID, and allows descriptor sharing within that principal subject to MAC.
  Source `070a842` passed normal/selected native-policy gates and eight frozen Soong host
  executables. A later real pipe regression showed that its retained metadata also kept
  writers open. The correction separates immutable input identity from live descriptor
  leases, with EOF checked while work metadata remains. Corrected `0e6f7a8` passed its own
  426 host tests, sanitizer controls, ARM64 compilation and three frozen Soong host tests.
  Unchanged policy is explicitly referenced, not newly built. No Android runtime or
  end to end work service qualification follows from these component checks.
  The [selected service integration](../plans/2026-09-20-work-service-integration.md)
  subsequently adds an authenticated dispatcher/client and actual resource backend.
  Finite Linux cgroup controls exercise initial reaping, retained descendants, an
  independently responsive termination lane, late creator handling, invalidated late
  observations and scope retirement. The instrumented backend run also passes. At
  `04348a5`, 431 host tests, normal/selected native-policy gates and eleven frozen host
  executables pass, including the added activation receipt and runtime retirement fences.
  Normal legacy binaries match the retained reference. The kernel fixture's epoch/profile
  inputs are supplied host facts, not Android MAC/lifecycle runtime qualification. No new
  image/VM or Console replacement follows from these checks.
  A fresh matching `58b9d94` image then passed the
  [first finite Android service controls](../plans/2026-09-20-work-service-runtime.md),
  including actual owner clients, app endpoint denials bracketed by owner controls,
  file/pipe/PTY streams, independent work and scope retirement. Initial exit preserved
  a detached descendant, separately from submitting client exit and caller environment
  retirement. Stopped logs exposed denied direct initial signals after owner transition;
  captured cgroup termination still succeeded. Final retired status did not disclose those
  earlier denied attempts. Correct routing uses the pidfd only in the placement gap and
  the captured scope afterward, without broader signal permission. Corrected `4829af5`
  passed 433 host tests and its own fresh matching Android image/runtime trial. Binary
  policy stayed identical and the earlier signal denials were absent. Static syscall and
  Bionic payload controls distinguish kernel closed stdin handoff from later runtime
  reopening, without changing Bionic hardening. The subsequent
  [service CE trial](../plans/2026-09-20-work-service-ce.md) observes genuine withdrawal,
  old enclosing retirement before explicit Stop, normal PIN recovery, refusal by the old
  endpoints and fresh owner execution under the restored generation. Old volatile records
  are not recovered. Generic init restart attempts during negative availability remain
  distinct from work admission. The subsequent
  [known identity transport trial](../plans/2026-09-20-work-service-uncertain-replies.md)
  passes with an ordinary owner compiled client at `acdba46` and unchanged `4829af5` service.
  Unread Prepare/Start replies after submitter death, exact retries, retained control
  capacity/lifetime and actual raw stale namespace rejection are distinguished. A live
  owner client survived manager replacement in a separate captured scope. 434 host checks
  and codec sanitizers are separate evidence. A later catalog source race showed that
  `Capture` could republish a collected forgotten record from a live registry control and
  pin identity capacity. The [host correction](../plans/2026-09-20-work-catalog-capture.md)
  refuses that publication under the catalog lock. The allocator-paused reproduction is
  not Android scheduling evidence. Matching `985c9a4` images later passed native/policy
  gates, the frozen capture test, unchanged binary policy and the known identity transport
  controls without claiming that paused interleaving on Android. Initial
  stream/reservation identity loss, stream recovery, pending admission/entry across CE and
  broader terminal/pressure/phone behavior remain unqualified. The
  [initial identity recovery slice](../plans/2026-09-20-work-request-recovery.md) subsequently
  adds nonallocating request lookup, conditional unused stream closure and early volatile
  CLI references. At `26812e5`, 445 host checks, sanitizer controls, normal/selected Android
  native and policy gates, and thirteen frozen host executables pass. Binary policies and
  normal legacy artifacts remain unchanged. Those metadata, memfd/pipe, compilation and
  host execution checks do not yet qualify new Android socket loss or CLI recovery cases.
- **Implication:** stale-result rejection is necessary but not sufficient: the new foreground
  intent must eventually be observed after an obsolete query or attachment retires. Sharing one
  control executor still lets UI Stop wait behind blocked admission.
- **Intent, accepted:** [manager ownership of work and exact control](architecture.md#andrix-work-and-launch),
  independent of presentation. Start is accepted at most once; Stop permanently closes
  the execution gate, defeats late completion and does not depend on payload cooperation.
  Metadata does not create work or grant authority.
- **Disposition:** retain identity and stale completion rules. Complete or replace the admission,
  cancellation and client control design; append-only prototype transactions are not a final ABI mandate.
- **Next gate:** specify the actual reservation/admission/control protocol and qualify
  pending Stop, stale identities, eventual discovery, initial identity recovery and blocked
  operations. The registry now has an authenticated crossing and captured resource backend;
  known identity uncertain replies and retained controls have a finite Android result, and
  catalog capture after Forget has a host correction. Stream lifetime and pending admission
  across CE remain.
  A control reference must not become a locked numeric lookup on the Stop path. The [earlier ordering proposal](../plans/2026-09-16-unix-work-supervision.md#3-proposed-admission-and-control-ordering)
  is not itself the implemented general API. Reverify the corrected UI on Android. These
  remain subsystem gates; R18 and current work define the revised overall platform priority.

## R07 Keep and notification controls

- **Vehicle:** optional Keep grant, quiet notification, owner blockable channel and process bound
  notification Stop. Keep remains off by default in the current implementation.
- **Evidence:** [notification controls](../plans/2026-09-14-keep-failure-controls.md) exercised
  blocking active work, refusing blocked admission, persistence through reboot, re-enabling
  without work restart, and locked Stop under the owner's notification visibility settings.
- **Implication:** indication, owner consent, Stop, continuation and terminal access are distinct.
  A posted or stopped notification is not itself acknowledgement of group cleanup.
- **Intent, accepted:** inspectable [owner supervised computation](architecture.md#lifecycle-and-networking),
  without requiring a special Keep action for ordinary Unix work or granting locked terminal I/O.
- **Disposition:** retain owner control and exact Stop targeting. Do not turn the optional
  prototype Keep channel into an accidental universal permission gate for computing.
- **Next gate:** design how work inspection, indication and Stop fit ordinary work and detached
  jobs while respecting owner preferences. Exact notification mechanics remain design work, not a new accepted default.

## R08 Resource policy

- **Vehicle:** [fixed native proof bounds](../owner/README.md#bounds-and-lifecycle): 256 MiB aggregate
  memory, 32 tasks, 128 descriptors, 64 MiB per file, no core dumps and fixed scheduling/OOM policy.
  The per-file limit is not a total storage quota.
- **Evidence:** guard and worker tests exercise admission/restrictions; emulator checks observed
  inherited limits and complete init cleanup. The listed tools ran under this profile.
  Both factory trials also checked protected aggregate and individual work bounds and
  worker control denial. They did not inject resource exhaustion or measure complete
  physical accounting release. Suspend, thermal behavior and device suitability remain open.
- **Implication:** those numbers prove a bounded experiment, not universal limits suitable for
  all owner programs. A larger workload failing under them would not establish an ABI defect.
- **Intent, accepted:** [bounded Android resource and phone policy participation](architecture.md#lifecycle-and-networking),
  with owner control and work below essential phone services.
- **Disposition:** reassess exact limits and policy mechanisms. Visible owner configurable
  workload profiles are a proposal to evaluate, not implemented policy or permission for unlimited use.
- **Next gate:** measure representative interactive, build, background and pressure workloads
  on the actual target, then define and verify aggregate/per-work policy and storage accounting.

## R09 Program entry and environment

- **Vehicle:** the [fixed runner](../owner/native/runner.cpp) enters the owner domain, validates
  home/bounds, constructs an environment and starts a shell or fixed tmux operation.
- **Evidence:** owner programs already run normally inside that shell, including native builds.
  The narrow entry and worker restrictions were checked separately from ordinary app execution.
  This is not evidence that the existing Binder entry is a complete program launch API.
  The [scope experiment](../tests/owner-scope/README.md#first-android-observation-and-channel-correction)
  further demonstrated that FD inheritance/use and permission to access the backing object
  are separate: its coordinator-labelled pipes were denied across owner-domain exec.
- **Implication:** fixing the trusted crossing is useful, but fixing every future owner command,
  shell, working directory or stream to that prototype would defeat normal Unix composition.
- **Intent, accepted:** [direct owner execution and a programmable userland](architecture.md#owner-userland),
  with a [complete trusted launch boundary](architecture.md#andrix-work-and-launch).
  Ordinary work's privileged bootstrap selection comes from declared profiles, not caller
  supplied programs, UIDs or filesystem paths. This does not prohibit separately authorized
  general administrative commands. A complete administrative context and explicit grant
  must precede that execution; ordinary work is not automatically root.
- **Disposition:** retain the execution boundary and deliberate handling of inherited state;
  replace the narrow entry contract as needed. Exact request/descriptor design remains a proposal.
- **Next gate:** define command, argument, environment, working-directory and standard-stream
  ownership; test invalid requests, descriptor races, cancellation and partial launch failure.

## R10 Terminal state and input

- **Vehicle:** pinned VT libraries through an Andrix adapter, native owned PTY, revocable stream,
  128 KiB output journal, parser acknowledgements and bounded UI/input queues.
- **Evidence:** [terminal checks](../plans/2026-09-10-owner-tools.md) and
  [cold attachment](../plans/2026-09-11-cold-attachment.md) found that main-thread preparation
  could outlast a received lease. Pending ownership/renewal and guarded promotion corrected it.
  tmux fresh redraw worked; a tail cannot reconstruct a lost parser. Broad IME/accessibility
  and arbitrary scheduler stalls remain unqualified.
- **Implication:** transport delivery, parser acknowledgement, input permission and screen
  reconstruction are different facts. A successful retry does not explain an earlier failure.
- **Intent, accepted:** usable [owner terminals independent of work lifetime](architecture.md#lifecycle-and-networking),
  with explicit foreground/unlocked access and optional ordinary multiplexers.
- **Disposition:** retain bounded ownership, explicit gaps and deliberate clipboard/accessibility
  crossings. The current parser location, journal size and recovery modes are candidates, not permanent restrictions.
- **Next gate:** establish a complete direct-terminal recovery contract without silent screen
  invention, then qualify actual UI, input methods, accessibility and backpressure under it.

## R11 Native development tools

- **Vehicle:** native LLVM compiler, pinned API/NDK/Bionic inputs, standalone and project private
  C++ runtime profiles, and GNU Make in the authenticated payload.
- **Evidence:** [compiler](../plans/2026-09-11-native-compiler.md),
  [C++ defaults](../plans/2026-09-11-cxx-defaults.md) and [Make](../plans/2026-09-11-native-build-tools.md)
  record actual edit/build/run, incremental/recursive builds, relocation and reboot/rebuild.
  A global C++ runtime lookup failure led to static C++ for standalone programs and an explicit
  private shared profile, without static Bionic or broader global namespace access.
- **Implication:** diagnose the ABI/library closure rather than solve a local lookup problem
  by weakening the whole platform. Native tools should remain ordinary composable programs.
- **Intent, accepted:** a supportable [on-device ARM64/Bionic development environment](architecture.md#owner-userland).
- **Disposition:** retain useful tools and the verified ABI approach, not every bootstrap pin,
  wrapper, disabled optional feature or serial-build default as a permanent product limitation.
- **Next gate:** qualify realistic larger projects, remaining languages/plugins/libraries and
  resource behavior. Expand features or replace integration only with a complete dependency and test story.

## R12 Owner debugging

- **Vehicle:** native LLDB/client/server integration and same-owner/cross-identity probes.
- **Evidence:** [debugger checks](../plans/2026-09-12-native-debugger.md) started with a real
  unchanged-policy launch denial. Narrow owner tracing/PTY rules enabled bounded C/C++ breakpoints,
  stepping, backtraces and inspection while retaining ASLR, ordinary app and coordinator negatives.
- **Implication:** the owner should be able to debug owner programs without making every
  Android process a tracing target. A missing target is not a useful denial control.
- **Intent, accepted:** [ordinary owner programming and debugging](architecture.md#owner-userland),
  retaining the [identity boundaries](architecture.md#authority-identity-and-state).
- **Disposition:** retain the capability and isolation principle. The downstream client and
  disabled feature combinations remain candidates, not a claim of complete upstream support.
- **Next gate:** qualify remaining expression, JIT/scripting/library, workload and device paths.

## R13 Files, projects and output

- **Vehicle:** normal owner home file operations, a small multi-file project fixture and a bounded
  terminal journal. There is no general durable job-output service demonstrated by that journal.
- **Evidence:** [project controls](../plans/2026-09-11-owner-project-input.md) exercised header
  editing, selective rebuild, relocation, failed-build recovery and reboot/rebuild. Lifecycle
  trials read saved files from fresh work after cleanup and normal PIN recovery. These are not power loss tests.
  The [logging defaults source review](../plans/2026-09-19-logging-defaults-review.md)
  supports minimal protected security records, optional work history and data minimization.
  It also identifies limits: a small retention cap is not forensic coverage, flooding can
  displace records, CE unavailability creates a persistence gap, and shared logs/backups
  can create unintended copies. The candidate seven day/1 MiB budget is not measured or
  qualified. This is external guidance and design analysis, not a logging implementation.
- **Implication:** saved data, process lifetime, terminal history and persistent output are
  different objects. Neither End nor a successful command is a durability acknowledgement.
- **Intent, accepted:** [owner controlled Unix files and composable tools](architecture.md#owner-userland),
  with owner state separate from [trusted system generations](architecture.md#trusted-usr).
- **Disposition:** retain ordinary file behavior and that separation. Optional bounded job logs
  and output redirection independent of Console need design; no automatic complete transcript is assumed.
  The owner accepted [separate recording controls and privacy focused defaults](architecture.md#work-records-and-diagnostics)
  after the review, not a mandatory activity trail or automatic archive export. This
  acceptance does not qualify retention constants, a writer implementation or durable receipts.
- **Next gate:** define stream/file ownership for nonterminal work, failure/truncation reporting,
  and the actual storage commit/recovery contract before making durability claims. Select
  and test the security event catalogue, resource bounds, retention and secondary copy
  exclusions separately from optional work history.

## R14 Networking and attestation

- **Vehicle:** endpoint source reviews, isolated connected emulator fixtures and real security
  consumers. Offline owner-work fixtures are not connected policy tests.
- **Evidence:** the [connected policy review](grapheneos-connected-policy-review.md) records an
  exercised GrapheneOS proxy endpoint and successful Cuttlefish software provisioning. A hostname
  property alone did not identify the effective endpoint. No direct Google connection was observed
  in that window; hardware attestation, all redirects/fallbacks and conditional consumers remain open.
- **Implication:** semantic client behavior matters, not an empty capture, destination blocklist
  or superficial hostname. Software keys do not establish hardware security.
- **Intent, accepted:** [no automatic direct Google connections by official components](architecture.md#foundation),
  explicit owner Google use allowed, backend use by non-Google services permitted, and genuine
  hardware attestation through the planned proxy without gating ordinary owner computing.
- **Disposition:** retain that policy and genuine consumers. Earlier stricter backend-independence
  language is superseded, not a reason to fake provisioning or invent replacement certification.
- **Next gate:** exercise conditional endpoints, redirects/fallbacks and actual supported-device
  hardware paths. No blanket privacy or DRM playback result follows from these checks.

## R15 WebView updates and rollback

- **Vehicle:** historical direct AOSP/Vanadium signer, package-session and rollback experiments.
  They are not adopted changes to the current GrapheneOS platform.
- **Evidence:** the [three-package rollback attempt](../plans/2026-09-07-webview-qualification.md)
  failed its intended model. [Split cohorts](../plans/2026-09-07-webview-cohort-rollback.md)
  worked with an exact signed library prerequisite. [Retention](../plans/2026-09-07-rollback-retention.md)
  and [lifecycle/metadata commits](../plans/2026-09-08-rollback-lifecycle.md) examined pruning,
  reboot, expiry, in-flight refusal and persistence errors. Manifest-only versions were not real browser upgrades.
- **Implication:** dependencies referenced by recoverable generations must outlive those records.
  Requested, available, staged, committed and applied states must not be collapsed into success.
- **Intent, accepted:** [compatible authenticated component updates and explicit recovery](architecture.md#updates-and-installation),
  with user data migrations and rollback limits stated separately.
- **Disposition:** retain the lessons, not automatic adoption of the old patch series or a claim
  that a production updater/native package manager exists.
- **Next gate:** review against the adopted foundation; test genuine version changes, dependency
  closure, persistence failure, power loss and recovery before promoting an update design.

## R16 Verification machinery

- **Vehicle:** host state/facade tests, source contracts, artifact inspectors, UI request queues,
  captured runtime fixtures and development artifact handling procedures. These are test facilities.
- **Evidence:** [UI freshness](../plans/2026-09-14-keep-failure-controls.md#test-driver-freshness-defect)
  found that a successful command could leave no new hierarchy. Later
  [work API observations](../plans/2026-09-16-work-terminal-separation.md#observed-candidate-behavior)
  distinguished a changed label from a broken terminal and retained an overall timed-out fixture.
  Native/API source models did not supply actual Android identities or key authority.
  The [Unix lifetime fixture](../tests/owner-work-lifetime/README.md#fixture-correction) also
  found that a selected login shell marked auxiliary observation FDs close-on-exec. Corrected
  observation setup was required before testing that shell's lifetime behavior. A policy
  inspection audit also found class-level rule caches: separate fresh processes with a
  differing-policy positive control independently rechecked the coordinator cgroup rules.
  The older shared-process comparison is not relied on as independent evidence. The scope
  collector also had to distinguish the unified cgroup row from accompanying legacy
  hierarchy rows, rather than treating a valid hybrid observation as wrong membership.
  The factory comparison then exposed observer directory permissions and the distinction
  between a populated group, an empty group, a removed captured object and an unknown
  read result. Host tests of the corrected C++ observer preserve those distinctions;
  the fresh Android trials then observed Empty for A and Removed for B at manager loss,
  followed by successful recovery. An unreadable file alone is still not proof of cleanup.
  The new CE collector also incorrectly required another generation increment on regrant,
  then exceeded a diagnostic sampling budget. Those attempts remain incomplete. A later
  trial reached fresh owner execution but exposed C string truncation of binary output
  after a proc SID. Explicit retained lengths and actual host serializer/packet tests now
  preserve NUL and all byte values. A fresh matching Android image then completed the
  corrected CE sequence and observed the NUL plus following marker. It does not
  retroactively pass the failed runtime. A later image sealer hashed its own stdout before
  finishing writing it, leaving a mismatched log and an unlisted completion status. Full
  verification found the other image/native records and runtime references unchanged; the
  runtime bundle also matched. A separate corrective inventory preserves the original
  failure without rewriting its manifest. Output path and inode alias guards now have eight
  tests, within 443 passing host checks. This does not add another Android runtime result.
- **Implication:** fixtures have bugs too. Check intended inputs, exact acknowledgements, actual
  process identities, positive controls and lifecycle completion, not only exit codes or self hashes.
- **Intent, accepted:** [tests inform architecture through scoped observed reality](architecture.md#design-method),
  with [deliberate decision records](architecture.md#deliberate-decisions) across the whole
  system. Acceptance, implementation and qualification must remain distinct.
- **Disposition:** retain explicit evidence boundaries and [artifact preservation](development-artifacts.md).
  Test-driver limits and fixture configuration are not mobile product policy. Failed attempts stay available.
- **Next gate:** update fixture contracts when product semantics deliberately change, verify
  independently, and repeat fresh artifact/runtime checks. Do not reuse consumed queues or amend sealed evidence.

## R17 Phone release and later capabilities

- **Vehicle:** [physical-device readiness](../plans/2026-09-08-caiman-readiness.md) and the
  later [Pixel integration plan](../plans/2026-09-21-pixel-integration.md). Services, SSH,
  package transactions and hardware deployment are not completed product features.
  Dedicated agent architecture is deferred.
- **Evidence:** the current platform/tool/work results are bounded emulator evidence. There is
  no buildable Andrix Pixel deployment product or supported release. The register does not fill
  these gaps with inferred success from tests on other substrates.
- **Implication:** useful owner tools are necessary but not sufficient for a mature mobile computer.
- **Intent, accepted:** the [Android/Pixel foundation](architecture.md#foundation),
  [owner userland](architecture.md#owner-userland), [lifecycle/network policy](architecture.md#lifecycle-and-networking)
  and later workshop/locked hardware modes, while preserving essential phone functions.
- **Disposition:** planned. Exact implementations and qualification remain work, not blanket
  authorization to flash phones, change signing roots, run package transactions or expose services.
- **Next gate:** develop the platform on Cuttlefish first. When sufficiently mature, establish
  supported Pixel inputs, installation/recovery procedures and actual phone/security/power/
  update behavior. Emulator proofs are not authorization to flash a handset.

## R18 OS composition and administration

- **Vehicle:** the [accepted expanded vision](vision.md), its
  [decision record](../plans/2026-09-21-owner-composable-android.md), and the finite component,
  recovery and signing vehicles below. They do not form a production administration,
  enrollment, installer or rolling composition service.
- **System component evidence:** the
  [SystemUI source assessment](../plans/2026-09-21-systemui-component-assessment.md) identified
  persistent package staging, signer/version/file verification requirements and the
  CONTROL_KEYGUARD deletion guard. Factory uninstall is not a qualified recovery route.
  The [component execution recipe](../plans/2026-09-21-systemui-execution-plan.md) reproduced
  the factory APK and built changed and restored variants without compiling a complete OS
  for each change. The
  [finite runtime](../plans/2026-09-22-systemui-component-runtime.md) observed visible changes,
  forward good source restoration, retained package identity, native staging continuity and
  fresh native/data positives after activation. Wrong signer and missing sidecar controls
  were rejected at activation. Ready was not treated as compatibility or application.
  The [narrow verification policy correction](../plans/2026-09-22-staged-apk-verity.md)
  enabled only the required staging file ioctls. The
  [restoration correction](../plans/2026-09-22-package-verity-restoration.md) made redundant
  setup conditional on kernel state while preserving later signature/digest checks. Its
  separate Android regression included a mismatched sidecar refusal. None of these results
  establishes arbitrary data rollback, crash recovery or personal platform key custody.
- **Recovery evidence:** the
  [identity and recovery vehicle](../plans/2026-09-22-signing-identity-recovery-proof.md)
  restored five disposable keys with six uses in a separate process and verified their
  signatures. Seventeen intended invalid controls were refused. Complete decryption and
  key/role checks precede exposure; a valid plaintext prefix followed by failure is not
  completed recovery. Recipient encryption does not authenticate the sender, so an
  independently trusted expected public manifest commitment is required. Ordinary Android
  age interoperability passed separately, with the recorded directory denial and staging
  observation limits. It does not establish protected signing or hardware custody.
- **Protected request evidence:** the
  [ordinary APK vehicle](../plans/2026-09-22-protected-signing-request.md) qualified disposable
  AndroidKeyStore import, exact public identity, explicit immutable request approval,
  credential authentication and a verified signature. A new unauthenticated operation was
  refused after success. Foreign namespace controls, decline, replay, authentication
  cancellation, broker replacement and exact logical key deletion passed in their stated
  scopes. The model separately exercised 400 cancellation/claim/completion races.
  Transport must retain remote completion, and presentation changes must not retarget a
  live request. Earlier capture privacy claims were corrected because adbd independently
  recorded credential dependent command arguments. Constant service arguments, private
  stdin and actual capture checks address that observed path, not every possible disclosure.
  Sensitive original recordings remain private and are not retroactively declared clean.
- **Artifact evidence:** the
  [APK artifact vehicle](../plans/2026-09-23-protected-apk-artifact.md) separates parsing,
  callback readiness, approval, signing, verification, publication and worker retirement.
  Host controls covered mutable caller buffers, refusal, invalid signatures, cancellation,
  lock ordering, accepted work despite executor exceptions, and captive provider loading.
  A ZIP prefix or successful signature is not a completed artifact. Actual Android controls
  then captured, approved, signed, verified and exported one ordinary project APK; Package
  Manager installed it and instrumentation executed with the expected certificate.
  Independent verification confirmed the expected identity and nonsignature contents and
  rejected modified code at the digest layer. Retained retry made no extra signing call;
  changed context, completed presentation replay and authentication cancellation granted no
  other result. This is the declared v2/SDK 37/user0 scope, not general platform signing,
  durable publication, accepted signing loss or multiuser authority.
- **Trust inventory evidence:** the
  [expanded inventory](../plans/2026-09-23-apex-trust-inventory.md) verified all 94 APEX payload
  signatures and hash trees against container key declarations. Including 33 nested APKs,
  it covers 180 APK files and 94 containers with 72 certificate identities. Sixty three
  artifacts use the platform certificate. No lineage or hybrid signer record was exposed
  by successful SDK 37 verification; this does not establish all SDK selections or installed
  history. Wrong expected key and changed filesystem data controls were refused. The host
  suite reached 520 checks. Public relationships are not key possession or authority to
  replace independent developer identities.
- **Authorization implication:** a separate host v2/v3/v4 control required three signatures
  for one APK. Refusal of the last operation left the same APK but no required sidecar.
  The [accepted approval unit](../plans/2026-09-23-signing-authorization-scope.md) is one
  complete protected signing transaction. Multiple cryptographic operations do not by
  themselves require multiple human prompts in an OS Andrix controls. Timed key use and
  platform transaction token issuance are unselected mechanisms, not qualified alternatives.
  No key policy change follows from a host format control or source review.
- **Composition assessment:** the
  [long term assessment](../plans/2026-09-23-composition-architecture-assessment.md) compares
  distribution recipes, functional build/store/profile models, tree/image deployment and
  Android integration. It recommends distinct intent, resolved inputs, artifacts, compatibility
  and observed deployment, with ordinary planning/builds and explicit authority crossings.
  It does not select Nix, a package language, numeric version encoding or native generation
  mechanism. Image assembly from cached components need not be a complete source rebuild.
- **Contract proposal:** the
  [owner trust, selection and deployment contract](../plans/2026-09-24-owner-composition-contract.md)
  separates role scoped installation authority, owner intent, native selected/observed state
  and durable operation ownership. It keeps personalization, delegated trust, version
  projection and image/component mechanisms open. It also separates ordinary signing
  protection from a possible later claim against a compromised main OS. These are proposed
  responsibilities and gates, not new key policy, a universal rollback mechanism or runtime
  qualification. External intent records and Android backed mediation are not rejected
  merely because they live outside a native service.
- **Mechanism source evidence:** the
  [integration comparison](../plans/2026-09-24-integration-mechanism-assessment.md) separates
  installed signer compatibility, permission grants, MAC matching, trusted factory image
  scanning, APEX payload key selection and OTA payload verification. Factory image trust
  is not an interchangeable ordinary APK installation path. Existing system reconciliation
  code does not qualify lossless rekeying, and an added signer rule cannot replace all the
  other checks. No key topology, native selection implementation or data rollback guarantee
  follows from this comparison.
- **Intent, accepted:** Andrix owns its whole OS; native execution and APKs are equally
  important. Ordinary identities remain separate from explicit general administration.
  Multiple accounts, ordinary development on the device, retained owner component choices,
  compatible rolling updates and controlled activation are requirements. Workshop is a
  legitimate mode with explicit reduced integrity guarantees; owner keyed locked operation
  is a separate later gate. Portable encrypted signing identity recovery must not depend
  on the original hardware or vendor approval and must not expose keys to everyday jobs.
- **Disposition:** the earlier small downstream layer, single owner product limit and sole
  host signed `/usr` update model are not architectural ceilings. Preserve their evidence
  while designing the coherent replacement. GrapheneOS remains a useful foundation, not a
  permanent policy limit. General root administration is not restricted to a curated menu.
- **Next gate:** review the proposed native principal and trust/selection contracts; carry an
  owner variant and upstream fixes across real updates or expose its conflict; qualify a
  durable complete component transaction; then establish actual APK,
  APEX and image activation/recovery boundaries. Continue
  [authority/signing](../plans/2026-09-21-owner-authority.md),
  [accounts](../plans/2026-09-21-android-unix-accounts.md) and
  [composition/installation](../plans/2026-09-21-rolling-composition.md) through their distinct
  contracts and evidence. Product intent does not qualify phone deployment, personal key
  enrollment or a weaker security boundary.
