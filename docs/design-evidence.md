# Design evidence register

Andrix's goal is a mature, general purpose, owner controlled Unix computer on mobile.
The current prototypes are instruments for learning how to build that system, not the
architecture we must preserve. Correctness and coherence take priority over the time
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
There is no supported release or qualified physical phone deployment at this checkpoint.

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
| [R17](#r17-phone-release-and-later-capabilities) | Phone release and later capabilities | Requirements/readiness work | Planned, not delivered features |

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
  retaining the phone framework and an attributable owner computing layer.
- **Disposition:** retain the foundation choice. The `2026081300` pin is a reproducible
  starting point, not an indefinite update policy or a qualified device release.
- **Next gate:** verify a mutually compatible maintained platform/device/kernel/firmware
  generation and its licensing, then qualify the actual phone. See R17.

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
- **Disposition:** retain the accepted first generation APEX and trust/ABI boundaries.
  Exact payload contents and version numbers are not permanent product limits; a different
  packaging architecture would require a separate decision. Owner programs need not be
  packaged as APKs or receive platform identity.
- **Next gate:** qualify generation commit, update, rollback and recovery on the adopted
  foundation. Do not infer production update or power loss guarantees from current boot tests.

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
  The prototype UID number, fixed entry API and Console implementation are not the product goal.
- **Next gate:** prove equivalent authority and cleanup boundaries for replacement work
  admission and command/stream handling; keep ordinary app and coordinator negative controls.

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
  A successful real lock call with busy files is not erasure proof.

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
  pending Stop, stale identities, eventual discovery, uncertain replies and blocked
  operations. The [earlier ordering proposal](../plans/2026-09-16-unix-work-supervision.md#3-proposed-admission-and-control-ordering)
  is not itself the implemented general API. Reverify the corrected UI on Android.

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
  Privileged bootstrap selection comes from declared profiles, not caller supplied
  programs, UIDs or filesystem paths. Ordinary owner program and environment requests
  remain supported after entering owner authority; the restriction does not limit which
  commands the owner may run.
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
- **Implication:** saved data, process lifetime, terminal history and persistent output are
  different objects. Neither End nor a successful command is a durability acknowledgement.
- **Intent, accepted:** [owner controlled Unix files and composable tools](architecture.md#owner-userland),
  with owner state separate from [trusted system generations](architecture.md#trusted-usr).
- **Disposition:** retain ordinary file behavior and that separation. Optional bounded job logs
  and output redirection independent of Console need design; no automatic complete transcript is assumed.
- **Next gate:** define stream/file ownership for nonterminal work, failure/truncation reporting,
  and the actual storage commit/recovery contract before making durability claims.

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
- **Intent, accepted:** [complete authenticated generations with rollback and owner data preserved](architecture.md#trusted-usr).
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
  retroactively pass the failed runtime.
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

- **Vehicle:** [physical-device readiness](../plans/2026-09-08-caiman-readiness.md) and accepted
  architectural requirements. Services, SSH, native package transactions and attributable agent
  delegation are later capabilities, not completed features of the owner terminal prototype.
- **Evidence:** the current platform/tool/work results are bounded emulator evidence. There is
  no buildable Andrix Pixel deployment product or supported release. The register does not fill
  these gaps with inferred success from tests on other substrates.
- **Implication:** useful owner tools are necessary but not sufficient for a mature mobile computer.
- **Intent, accepted:** the [Android/Pixel foundation](architecture.md#foundation),
  [owner userland](architecture.md#owner-userland), [lifecycle/network policy](architecture.md#lifecycle-and-networking)
  and [attributable agent operations](architecture.md#agents), while preserving essential phone functions.
- **Disposition:** planned. Exact implementations and qualification remain work, not blanket
  authorization to flash phones, change signing roots, run package transactions or expose services.
- **Next gate:** establish supported inputs, owner installation/recovery procedures and real
  phone/security/power/update behavior, then qualify later capabilities through explicit scoped work.
