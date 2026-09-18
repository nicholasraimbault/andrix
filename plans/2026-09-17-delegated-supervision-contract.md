# Delegated supervision and owner work contract

**Status:** contract design following the owner accepted
[ownership model](../docs/architecture.md#work-supervision). This specifies required
behavior and a proposed first implementation boundary. It is not a released API,
platform patch or qualification of the combined system. The successful
[comparison vehicles](2026-09-17-work-factory-comparison.md#corrected-android-results)
remain separately scoped evidence.

## 1. Purpose and limits

Make ordinary owner computing independent of terminal presentation while retaining
Android authority, protected phone resources and complete scope control. Android
supervises the owner environment; Andrix owns work inside it; kernel objects enforce
containment. A personal computer is the product, not an always available server.
Owner chosen background jobs or services remain capabilities, not forbidden uses.

This design does not select glibc, Wayland, a second platform ABI or a replacement
Android desktop. Those remain later compatibility research. It also does not freeze
fixture UID numbers, request counts, resource values, transports or helper counts.

The immediate deliverables are the two contracts below, a source impact map and a
failure matrix. Implement only uncertain mechanisms needed to qualify these contracts,
not two complete operating systems or another permanent test-only API.

## 2. Ownership and authority

| Owner | Owns | Must not acquire |
| --- | --- | --- |
| Android service supervisor | Declared service profile, exact service instance, protected aggregate scope, activation and final cleanup | Andrix work IDs, terminal state, user job admission or ordinary job restart policy |
| Authorized platform controller | Permission to inspect/start the declared environment and stop its exact instance, independently of manager responsiveness | Arbitrary service, UID, privileged executable or filesystem selection by an ordinary caller |
| Android user/CE authority source | Genuine availability, epoch and revocation state | A dependency on work cleanup finishing before withdrawing authority |
| Andrix work manager | Work reservation/identity, client authorization, admission, scope resources, cancellation and direct control | Permission to invent platform authority or execute owner payloads as the coordinator |
| Trusted launch machinery | Fixed bootstrap and complete profile transition, staged child/FD ownership, execution gate | An unrestricted privileged exec, setuid, capability or process migration interface |
| Owner payload | Ordinary programs, files, arguments, environment, child processes and Unix behavior within its authority | Supervisor control descriptors or authority to escape/modify its protected boundary |
| Presentation client | Authorized terminal/display connection and input eligibility | Ownership of accepted work lifetime or renewal of work authority merely by attachment |

Platform controller is a responsibility, not a commitment to a new process. It must
remain callable when the work manager is stuck. Existing Android service and caller
authority must be inspected before selecting a transport or implementation location.

A request to stop one work item must not silently become Stop all when the manager is
unresponsive. The fallback is a separately authorized, visibly broader operation to
stop that exact environment instance. Work manager failure may terminate all its work;
that is failure containment, not a successful individual job result.

## 3. Generic Android service contract

The names here describe operations, not final AIDL methods, properties or init syntax.
Only a declared service is eligible. Ordinary Android services must not silently change
behavior when the optional delegated contract is introduced.

### Operations

| Operation | Inputs and caller | Required result |
| --- | --- | --- |
| Inspect declared service | Authorized platform controller; trusted definition key | Current instance reference or absence, definition generation and lifecycle state. Observation creates no instance. |
| Request declared service start | Existing authorized Android lifecycle or platform controller; trusted definition key | Allocate a fresh instance before activation and expose its identity. Do not create a duplicate active instance or attach to leftover resources. |
| Stop exact service instance | Authorized platform controller; captured instance reference | Latch Stop, close activation, initiate complete subtree cleanup. A stale reference cannot stop a replacement. |
| Observe exact service instance | Authorized platform controller; captured instance reference | Versioned launch, process, cleanup and failure facts. Unknown is not absent, empty or successful. |
| Delegation handoff | Internal startup step to the fixed trusted bootstrap belonging to that instance | Only the declared subordinate controls and observation channel. No caller chosen cgroup path or unrelated process target. |

A name selects a declared service for an explicit new start. It is not an exact Stop
capability. A lost start reply must be resolved from the supervisor's instance record,
not treated as permission to start a second instance. Resolving a new instance after
an old one ends is new observation, never retargeting an old control reference.

The exact instance reference needs an authenticated endpoint and immutable incarnation
identity. Random numbers or possession of diagnostic metadata alone do not authorize
operations. Generic service identity is not an Andrix work identity.

### Declared profile

The trusted definition supplies the fixed bootstrap, real UID/GID/groups, explicit
capability sets, SELinux role, initial limits and scheduling, resource controller and
aggregate policy, bootstrap environment, permitted descriptors and restart policy.
Unsupported or absent security relevant fields fail before activation. In particular,
absent capabilities must not be treated as equivalent to an explicitly empty profile.

No public operation accepts arbitrary privileged program, UID, SELinux context or
filesystem path. No independent general `setUid`, `setCaps` or `moveProcess` operations
are exposed. Required mutations are internal parts of the declared transition.

Each start gets fresh instance state. Do not clone live service PID fields, callbacks,
restart flags, open descriptors or prior admission state. Startup is not complete merely
because fork returned or an `init.svc` name reports running.

### Resource ownership

The platform retains ownership of the aggregate ceilings and ancestors above the
service scope. The manager receives only the controls required for subordinate work.
Owner payloads cannot migrate across scope boundaries or write supervisor controls,
including when their UID is shared with trusted code under a different MAC role.

A candidate hierarchy has a protected instance root, a trusted control leaf and a
delegated work subtree. The exact layout remains a mechanism choice. Delegating only a
leaf directory is not sufficient by itself: cgroup migration checks include the common
ancestor's `cgroup.procs`. The permitted control set must support staged child placement
without allowing migration outside the aggregate or changes to aggregate ceilings.

The first mechanism proof will require real cgroup v2, recursive `cgroup.kill`, captured
kernel handles and explicit profile support. Unsupported features fail activation. A
future fallback needs its own equivalent contract and proof; a nonrecursive PID scan is
not a silent substitute. This proof prerequisite is not a permanent device support policy.

### Activation

1. Reserve a fresh instance and its cleanup responsibility.
2. Create a genuinely fresh resource root. An existing pathname is not success.
3. Establish aggregate bounds, controller state, subordinate permissions and actual
   kernel identity. Read back the controls on the objects that will be used.
4. Start only the fixed trusted bootstrap under the complete declared profile, behind
   the required startup gate. Capture process ownership before asynchronous handoff.
5. Bind the handoff and readiness acknowledgement to that actual child, its kernel
   identity and this instance. Reject stale, duplicate or foreign acknowledgements.
6. Publish Active only after the defined profile/delegation readiness conditions hold
   and Stop has not won. Owner work has a separate later execution gate.

If a stage fails, the instance still owns every resource already created. No failed
return may abandon a forked child or forget an allocated group. Cleanup starts from
that instance's captured resources, not a reconstructed current PID or service name.

## 4. Service lifetime and cleanup

Track launch, Stop and cleanup separately. Suggested vocabulary is:

- Launch: Preparing, Active, Failed, Exited.
- Stop: an irreversible latch for this instance.
- Cleanup: NotStarted, Signalling, WaitingForQuiescence, Reclaiming, Retired, Blocked.

These names are explanatory, not an adopted wire enum. A failure reason does not
itself mean cleanup is complete. A completion or observer event cannot clear Stop.
Exit of the initial declared service process closes activation and latches cleanup,
even if readiness arrives late. This is the manager/service lifetime, not an owner
shell's exit inside a work scope.

### Required sequence

1. Close activation and stop accepting new delegation for the instance.
2. Terminate the captured subtree through its kernel identity. A staged child not yet
   assigned must also have an exact owned process cleanup path.
3. Fence outstanding startup and mutation operations. None may later add a member or
   directory to an instance being reclaimed. Their resources and uncertain outcomes
   remain owned until cancelled, completed or safely quarantined.
4. Observe population and child exit evidence without blocking unrelated init work.
5. Remove empty descendant directories before their parents, within the owned cgroup
   filesystem and captured boundary only. Reject an unexpected object or boundary.
6. Retire process/control references and publish the precise completed facts.

An empty population read alone is not stable quiescence while an external creator still
has permission to place a staged child or mutate the subtree. Reclamation requires both
a closed mutation boundary and fresh kernel quiescence evidence after that closure.
A cached Empty read from before the final mutation completed is invalid, even when the
pending counter later reaches zero. Delayed observations need instance and boundary
correlation from query issuance, not merely from reply delivery. Invalidating a query
does not justify an unbounded replacement reader pool. Descriptor relative lookup protects
object selection, but does not replace exclusive ownership of names being unlinked.

Empty, Removed and Unknown must remain different observations. No permission error,
missing reply or failed read becomes evidence of an empty group. Directory removal
and a captured descriptor's lifetime are distinct; link count is not a removal oracle.
Accounting observations must be reported separately from process and directory cleanup.
Recovery after a lost removal reply may use a separate authoritative confirmation from
formerly valid captured core descriptors and the absent owned parent entry, while the
mutation and process boundary remains closed. A missing pathname or a generic Removed
observation alone cannot authorize retirement. Definite failure with no initial process
or no allocated root must likewise be recorded explicitly, not as invented exit/reap or
removal events.

A stopped or failed instance cannot be reactivated. Proposed initial restart fencing:
the same declared delegated service does not activate a replacement until the old
instance is Retired. A cleanup deadline produces a visible Blocked/quarantined result,
not fabricated success or unbounded replacement instances. Any future overlapping
recovery policy needs a separate ownership and resource argument.

### Asynchronous execution and identity protection

The init loop accepts requests and schedules bounded steps. It must not wait in a
multi-second polling/rmdir loop, nor create unbounded cleanup workers. Every completion
belongs to its original instance and cannot mutate a newer service incarnation.

This requires more than moving the current helper into a thread. Cleanup owns stable
resource references rather than borrowing mutable `Service` fields across restart.
Restart, stop notifications, reap callbacks and temporary service removal must respect
that ownership. A lost cleanup worker must not lose the platform's remaining obligation.
A private process worker is the current candidate. Its death can be established before
replacement, while a timed out thread cannot safely be assumed cancelled. This adds
process and IPC costs. The supervisor retains the original kernel handles and bounded
operation slots across failure; replies carry exact instance/worker/request correlation.
Host descriptor transfer, paused worker, recovery and lost reply controls have been
exercised. The Android bootstrap profile, peer MAC, reaper and event loop integration
remain separate proof questions.

No delayed numeric PID/PGID signal is permitted after its lifetime pin is released.
A pidfd is an exact signal target, not permission to use that numeric PID later. The
current synchronous `WNOWAIT` pin cannot simply be dropped while old numeric fallback
operations remain. Conversely, leaving a pending zombie visible to an unchanged
`waitid(P_ALL, ... WNOWAIT)` loop can prevent useful progress.

The leading mechanism to test is instance bound group handles and fresh group creation
whose identity cannot be confused by numeric PID reuse. An instance qualified directory
name is one candidate; its exact spelling is not an ABI. For the opted in contained
service, captured group kill should not require an additional numeric PGID fallback.
Other Android services' existing signal behavior must not be changed by that assumption.
Reap ordering and PID/path reuse need actual tests before this mechanism is adopted.

If the kernel cannot terminate a task promptly, the contract remains Stopping/Blocked.
It cannot promise immediate quiescence. Other Android supervision must still progress.
The selected profile must bound subtree size, outstanding handles and cleanup work;
concrete values require measurements rather than copying fixture constants.

## 5. Andrix work contract

The service instance is the outer lifetime. Work, launch request, terminal, attachment,
caller registration and platform authority epoch remain separate identities.

### Owner operations

| Operation | Contract |
| --- | --- |
| Reserve work | Return one exact work control reference without payload execution. Reservation keys are scoped to authenticated caller and manager epoch. Bounded abandoned reservations may expire. |
| Start reserved work | Accept one bounded immutable launch description at most once. A duplicate identical request returns its existing state; a conflicting description is rejected. Lost reply means inspect the same request. |
| Inspect/list work | Return bounded metadata only. Do not create payload, PTY, grant or implicit permission renewal. |
| Stop exact work | Irreversibly close its execution gate and terminate its complete scope. Stop must work during admission and must not need the admission/terminal lock or execution lane. |
| Observe completion | Distinguish entry exit, surviving descendants, stop acceptance, scope quiescence, reclamation and final reason. Retained results cannot become replacement identities. |
| Attach/close presentation | Operate on separate terminal/attachment identities and foreground/unlocked input authority. This is not implicit work creation or complete work Stop. |

The ordinary launch description contains executable, argument vector, environment,
working directory and explicit stream/descriptor requests. It is not a shell command
unless the owner explicitly selected a shell. These inputs direct ordinary owner
execution after crossing the trusted boundary. They do not select privileged bootstrap
code, loader environment, credentials or an arbitrary supervisor resource path.

Authorization uses actual caller identity and scoped capabilities. A package name,
claimed PID, untrusted profile string or copied work number is not authority. Binder
oneway calls do not supply a usable calling PID. Owner tools and future delegated
principals need a proved crossing; neither broad Binder access nor a label in a request
creates that permission.

### Admission and release

Admission may perform external I/O, but only while the payload gate remains closed.
Do not hold the registry/control lock across it. Bound outstanding operations; abandoned
or stuck admission cannot consume an unlimited replacement thread pool.

The Stop latch and release commitment need a defined atomic ordering for that work:

- Stop winning before release commitment prevents payload release, even if creation or
  admission succeeds later. Late resources are cleaned up under the old identity.
- Release commitment winning first means execution was authorized before Stop. The
  subsequent Stop still kills the scope. Stop acceptance is not a claim that no further
  instruction can run before kernel termination.
- A check followed by an unrelated write to a release pipe is not sufficient arbitration.

A staged child's numeric identity must remain pinned through any numeric placement
operation. A pidfd alone does not justify a later write of its PID to `cgroup.procs`.
Creating directly into the target cgroup and a gated fork with explicit parent/reap
ownership are candidate mechanisms; their kernel, policy and race behavior need proof.
Owner code must never run before its actual scope and profile are established.

The fixed bootstrap passes only declared descriptors into owner execution. Supervisor
control handles and unrelated inherited descriptors do not cross. FD possession/use
and permission on the backing object must both work under the real owner MAC role.
The exact single threaded launcher or helper arrangement is still open.

### Android authority and presentation

The framework is authoritative for real user/CE state. Registration, query issuance,
platform epoch, freshness and revocation must be explicit. Neither a path being readable,
an old FD nor screen unlock is a CE availability oracle. Receipt of a late positive
response must not create a new lease or clear revocation.

An execution admission attempt must bind to its trusted platform instance, user and
authority epoch before asynchronous creation can outlive that authorization. Unbound
reservations carry no execution permission. The precise binding point is part of the
work protocol, not an epoch chosen independently by a later helper. Request, admission
operation, helper handoff and release must retain that binding. Epoch fields are checked
against genuine framework authority; caller supplied numbers do not confer permission.

Revocation or an incompatible platform/authority epoch invalidates the old admission
and its execution gate irreversibly. A new positive may authorize a fresh explicit
request under the new epoch, not revive the old request, completion or helper. Late
helpers remain owned for cleanup, and their current snapshot must match the request's
bound epoch rather than silently rebind it. This belongs to Andrix work admission, not
to init's generic service lifecycle.

Release must reject known unavailable, stale or mismatched authority. The combined
contract still needs a precise authorization point and measured revocation/freshness
bounds for a concurrent CE transition. Do not invent instantaneous global atomicity
between a native release and key withdrawal. Do not delay actual CE withdrawal until
cleanup finishes. This is a qualification gate, not permission for an undocumented grace.

UI loss, detach and relock do not cancel accepted work. Explicit terminal close performs
real hangup. Shell exit does not add a blanket descendant kill. Foreground/unlocked input,
automatic restart, wake authority and network exposure remain separate permissions.
Natural completion needs actual evidence that owned payloads are gone, not merely entry
exit or a helper's disappearance. A work scope is not mutual isolation of same-owner code.

## 6. Source impact map

Inspected Android reference: `system/core` at
`84ebea5e21110f31b632473a2fdb1c656b599b24`. This is source evidence, not new runtime proof.

| Area | Inspected constraint | Required design work |
| --- | --- | --- |
| `init/service.cpp`, `Service::Start` / `RunService` | Child activation FIFO brackets parent cgroup setup. UID/PID group creation and mutable running state are part of the current path. | Optional delegated profile activation, actual readiness, fresh resource identity and exact handoff; no owner command arguments in privileged start. |
| `init/service.cpp`, `KillProcessGroup` / `Reap` | Cleanup is called synchronously before callback/state/restart processing; fields such as PID and running flags are then retired. | Separate instance cleanup ownership from mutable service/restart state; preserve unrelated service behavior. |
| `init/sigchld_handler.cpp`, `ReapOneProcess` | `WNOWAIT` pins the child through cleanup; a scope guard waitpids on return, even for an untracked child. | A reaper that progresses while cleanup is pending, without releasing an identity still used by numeric signaling. |
| `libprocessgroup/processgroup.cpp` | The ordinary path uses UID/PID derivation, accepts `EEXIST` in `MkdirAndChown`, adds numeric PGID signaling even with cgroup kill, removes one directory and defaults to a 2200 ms loop. | Fresh instance bound group operations, no unpinned delayed fallback, bounded asynchronous subtree reclamation. Do not globally remove fallbacks used by other Android services. |
| `createCGroupForCloneInto` and `task_profiles.cpp` | A separate existing helper creates a group using zygote PID/start sequence; it still uses `MkdirAndChown`. Process profile attribute paths for v2 derive from supplied UID/PID, while task paths can use actual membership. `RunService` applies process profiles before dropping UID. | Inspect reusable primitives rather than inventing them, but do not assume the clone helper is a delegated init service contract or that a profile write reaches the actual new group. |
| `init/init.cpp` control/restart processing and `ServiceList` | Existing controls resolve reusable service or interface names. | Exact instance control and restart fences, bounded retirement records, authorized platform mediation. |
| Running kernel `3ec022196c4e`, `fs/proc/base.c` / SELinux `selinux_lsm_getattr` | Process attribute open attempts `__mem_open` for write safety but ignores that result; the subsequent read asks `security_getprocattr`. Reading another task's current SID requires `process getattr`. A ptrace AVC on open does not alone show that SID read needs ptrace authority. | Keep actual task SID observation and its original PID lifetime pin. Add only the declared bootstrap role's read metadata permission. Preserve no ptrace authority and failure on missing evidence. |
| Running kernel `3ec022196c4e`, `include/net/scm.h` / SELinux socket hooks | `SCM_SECURITY` is derived from the Unix socket inode SID. Socketpair peer SID is also fixed from socket security, not a fresh sending task SID. | Do not substitute a socket label or a payload SID assertion for actual task role verification. A descriptor handoff proposal was not needed after inspecting the narrower proc attribute path. |
| Bionic `libc/bionic/spawn.cpp` at `b95b08888b9eb6465c21d5840cce59dc463bfdef`, `ApplyAttrs` | Requested default dispositions are applied with `sigaction64`. Including uncatchable SIGKILL/SIGSTOP causes child exit 127 before exec; parent spawn success is not readiness. | Exclude only those unchangeable dispositions. Retain explicit mask/defaults and require the actual initialized worker reply before release. Bracket a bad signal set with valid actual Bionic controls. |
| `Service::RunService` activation read | The pinned failure path logs a Result error and then dereferences it. The second trial observed EOF followed by `bad_variant_access` while the initial child was still held. | The selected profile exits on that read failure before dereference or bootstrap execution. Keep ordinary service behavior separate from this opt in integration. |
| Core SELinux DAC and proc neverallows | A new cleanup domain cannot receive general DAC override or generic proc file reads. Delegated directories can outlive their owner with restrictive modes. | Keep both prohibitions. The [directory retirement candidate](2026-09-18-directory-retirement.md) takes back only verified empty cgroup directories through exact descriptors, with CHOWN and explicit kernel ABI checks. |
| `init/epoll.cpp`, `UnregisterHandler` / `Wait` | Kernel interest removal precedes deferred handler map erasure. Closing and reusing a numeric FD inside the reap callback can collide with the old registry entry even when callbacks check instance identity. | End communication, retain the descriptor number through actual dispatcher retirement, then allow reuse. Test the actual Epoll path, not only a model of FD identity. |
| LMKD at `c3601e823bd07c9c190f67e2f9bc7486e4978328`, `register_oom_adj_proc` / reaper | Service registration opens a pidfd from a numeric PID and derives its group control from UID/PID. Type only changes application soft limit policy. Missing controls fall back to the initial pidfd; a leftover pathname could select the wrong group. | Supply captured process and aggregate group handles through authenticated init registration, fence removal/reconnect with the service incarnation, and retain ordinary registration behavior. Do not skip memory supervision to fit the new layout. |
| Owner `guards.cpp`, `worker_filter.h`, sepolicy and fixed entry | Actual UID/caps, protected resource controls, owner MAC and descriptor/backing-object restrictions are checked. | Preserve outcomes under the new resource layout and ordinary program API; do not weaken guards to fit a shortcut. |
| Owner `platform_lifecycle.cpp` and framework lifecycle service | Query issuance and fixed platform binding matter; current daemon death recipient exits rather than waits for its main loop. `UserManagerInternal` and `CeStorageAccessTracker` supply authority, not fscrypt policy metadata. | Explicit authority/release race contract and independent failure cleanup for the new manager lifetime. Reuse principles, not accidental one-work assumptions. |
| Factory `manager.cpp`, `tick_work`, and `guardian.cpp`, Release handling | The current fixture checks `!stopped` separately from sending Release. Its guardian checks `platform.ready()` separately from writing the release byte. | Define and exercise queued/concurrent Release versus Stop and authority revocation. The successful blocked allocation case does not qualify these interleavings or supply global atomicity with key withdrawal. |
| Factory manager admission, `wire.h` and guardian startup | The manager has no `PlatformLifecycle` binding. The handoff carries manager/work IDs but no platform epoch. Each new guardian establishes its own first current binding. | Bind and invalidate the original admission epoch. No proof yet covers an allocator blocked across real CE revocation and regrant before a late guardian starts. A helper's new positive is not permission to revive an old request. |
| Console/native session protocol | Creation, attachment and control still have prototype coupling. | Keep existing behavior until a qualified work API replaces it. Do not make a UI-only executor fix stand in for supervision. |

## 7. Qualification matrix

Every result must identify source, substrate and the exact contract clause exercised.
Host models establish ordering, not Android identity. Kernel probes establish kernel
behavior, not Android MAC. Artifacts establish construction, not execution.

| ID | Control | Required observation |
| --- | --- | --- |
| D01 | Missing/invalid declared profile or wrong caller | No privileged mutation or owner payload; explicit refusal. |
| D02 | Existing group path or stale service instance | Refuse adoption/retargeting; replacement remains untouched. |
| D03 | Resource/controller/permission setup fails at each stage | Gate remains closed; every created child/group/FD retains cleanup ownership. |
| D04 | Stop races activation, an already queued Release and every work admission boundary | Defined release/Stop commitment ordering; a separate eligibility check and later send is not treated as proof. Late success cannot revive a stopped identity. |
| D05 | Duplicate Start and lost reply | Same exact request, no duplicate payload; inspect uncertain outcome. |
| D06 | Descriptor reuse, extra descriptors and backing-object denial | No leaked supervisor authority, no stale descriptor retarget, explicit setup failure. |
| D07 | Manager crashes with multiple active works | Whole enclosing scope terminated; old identities retire; no ordinary job restart. |
| D08 | Manager remains alive but stuck | Independently authorized exact environment Stop works; unrelated init work progresses. No false claim of individual Stop. |
| D09 | Work guardian/launcher is stuck | Direct work scope Stop does not wait for cooperation; another work continues. |
| D10 | Child exit and numeric PID reuse during assignment/reaping | No migration or signal of a replacement; no unbounded reaper spin. Model/path reuse is not forced real PID reuse. |
| D11 | Cleanup pauses, fails or loses its worker | Visible pending/Blocked state, bounded resources, exact ownership retained and safe resumption. |
| D12 | Empty nested directories and cleanup budget exhaustion | Reclaim the owned tree without a long init loop stall; no unrelated path removal or premature restart. |
| D13 | Real CE loss, platform death, delayed positive responses, and revoke/regrant before a blocked request's late helper starts | Old admission/gate remains invalid after a new positive; mismatched late helper is cleaned up without payload. A fresh explicit request may succeed under the new epoch. Also exercise revocation between readiness checking and release commitment. No reply-based lease renewal or key-withdrawal barrier. |
| D14 | Entry exits but descendants live; final descendant exits | Preserve Unix lifetime; distinguish entry result from natural scope completion. |
| D15 | Memory/process/FD and control transport pressure | Protected aggregate preserved; bounded admission/control; honest failure, no unlimited helpers. |
| D16 | Old clients/terminals/attachments and locked UI | No new work or authority from discovery, no stale input/control, no implicit whole-work Stop from UI loss. |
| D17 | Fresh manager after complete retirement | New instance, no restored ordinary jobs, old handles inert, fresh work succeeds. |
| D18 | Normal product and unrelated Android services | No lab controls or permission leaks, no changed legacy service behavior; real phone qualification remains separate. |

## 8. First implementation boundary

Start with captured instance cleanup and lifecycle ordering, not another per-work init
factory. The first proof should expose the currently coupled kill, reap, wait and directory
removal operations as separate bounded steps on an exact owned kernel group. Include a
live unrelated group, interrupted progress and path/PID identity hazards. Preserve failures.

Next prove profile/delegation activation with payload held behind the gate. Then connect
one manager and an ordinary program launch description, without making a terminal a
prerequisite. Reuse existing identity/filter/authority code only where its assumptions
still hold. Add presentation after the work boundary is coherent.

### Design checks so far

The [ordering model and kernel mechanism probe](../tests/delegated-supervision/README.md)
are deliberately separate. Review found two model defects despite initial test passes:
cached emptiness surviving mutation completion, and activation remaining possible after
service process exit. The revised model invalidates observations by boundary, correlates
queries from issuance, and closes activation on service process exit. Its selected
sequential orderings are not concurrent platform execution.

The first new Linux kernel probe killed a captured nested group after the manager had
already been reaped, removed empty directories in steps with unrelated control responses,
resumed after dropping a traversal cursor, and rejected an old open control after path
reuse. It did not use a delayed numeric PID/PGID signal. It did not force actual numeric
PID reuse, prove hostile namespace races or execute Android init. No platform source,
normal owner policy or runtime ABI was changed by these design checks.

A [native component candidate](../supervision/README.md) now implements the state and
captured kernel operations in C++. State methods do no I/O, issue bounded typed tickets,
separate process exit from reap and fence restart. The captured cgroup component owns its
actual root/control FDs and provides one bounded traversal cursor with cumulative limits.
Its strict lookup currently requires `openat2` support and fails without a weaker fallback.
That is a candidate prerequisite, not a newly adopted universal device requirement.

Optimized and sanitizer host units passed. The same native components were exercised on
the real Linux kernel with a late member invalidating an old Empty sample, an occupied
timeout slot, cursor interruption, independent live control responses, budget failures,
actual permission denial and deterministic root entry replacement. No numeric signal
was used for captured group cleanup after leader reap. The replacement remained live.
A supplied lifecycle fact in a host driver is not proof of Android authentication/reaping,
and a step quantum does not guarantee kernel syscall latency. The adapter, cleanup lane
and Android restart/control integration are still required; no init behavior changed.
The `8a7ddd1` candidate passed 386 host tests, Android library/link compilation and
separately frozen Soong host unit execution. It remains uninstalled and has no new
Android runtime result.

The implementation choice is not final until source review, actual kernel controls,
selected Android artifact checks and fresh Android fault trials support the combined
contract. Broader hardware, application compatibility, glibc/Wayland, packages, services
and agent capabilities do not replace these base gates.
