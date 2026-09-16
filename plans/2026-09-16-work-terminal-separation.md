# Work and terminal separation

**Status:** work discovery and exact work Stop are implemented. Source `13a1af0`
passed host, Android module and lab image checks. The runtime observations below are
scoped and the overall fixture ended at its deadline. A subsequent source review found
and corrected an eventual rediscovery gap. Existing lifetime policies, launch modes,
product defaults and Android authority stay unchanged.

This follows the [two scoped lifecycle trials](2026-09-14-lab-lifecycle-faults.md)
and implements the separation required by the
[accepted architecture](../docs/architecture.md#lifecycle-and-networking). The tests
identify boundaries to preserve. They do not require preserving the prototype's
structure or establish every storage, suspend or pressure case.

## Owner direction

The target is the behavior expected from a general purpose, owner controlled Unix
computer. It is not a choice between keeping every terminal job forever and killing
all work when Console disappears. View detach, real terminal hangup, shell job control,
detached jobs and complete work Stop must have their distinct meanings.

The [design method](../docs/architecture.md#design-method) applies throughout this
work. Tests should inform the replacement before we commit to its architecture. The
implementation may be rebuilt from scratch if that yields the correct system. Time,
difficulty and effort spent on the prototype do not determine what must survive.

The next [supervision design candidate and proof matrix](2026-09-16-unix-work-supervision.md)
uses real process experiments and Android implementation source to evaluate replacement
mechanisms. It does not adopt a new factory or change this prototype's public behavior.

## Couplings identified by the initial review

| Location | Current coupling | Design consequence |
| --- | --- | --- |
| [`OwnerSession`](../owner/native/andrixd.cpp), `startKept`, `attach_locked` | Attach can also start work. New kept work requests retention and starts a tmux client in one operation. | Work creation and work observation need interfaces distinct from attachment. |
| Native child handling, before this extraction | The tracked child is either the work's shell or a disposable tmux client. A Keep flag also chooses whether to close its PTY. | Process role and continuation permission must not be inferred from each other. |
| Native work identity and [`andrixd.rc`](../owner/andrixd.rc) | One immutable work identity occupies one coordinator process and init cgroup. Exiting the coordinator cleans up every descendant. | Do not recycle work inside that process or introduce multiple independent workloads without a new complete cleanup boundary. |
| [`TerminalController`](../owner/terminal/src/dev/andrix/terminal/TerminalController.java) | Work becomes known to the UI when attachment finishes. `kept` also chooses parser recovery and Stop behavior. | Work discovery, lifetime policy and presentation recovery need separate descriptions. A failed attachment is not evidence that no work exists. |
| [`IOwnerSession`](../owner/aidl/dev/andrix/session/IOwnerSession.aidl) | Plain End uses an attachment generation; kept Stop uses the exact service Binder independently of terminal attachment. | The eventual workload API should target work identity. Stopping computation must not confer terminal access or depend on a healthy parser. |
| [`runner.cpp`](../owner/native/runner.cpp) and [`runner_command.h`](../owner/native/runner_command.h) | The fixed kept entry always selects tmux creation or attachment. | Selecting an optional presentation tool must not grant continuation. A workload need not require a terminal frontend. |

The platform side already has a useful separation. [`KeepWork`](../owner/platform/java/dev/andrix/server/KeepWork.java)
holds a notification backed grant for an actual native lifetime Binder and work ID.
It is not a PTY manager. Its grant posting, epoch recheck, Stop and retirement ordering
should remain independent of terminal presentation.

## Responsibility split

### Work scope

Own the work identity, creation/admission state, lifetime policy and termination.
Android user/CE authority, platform freshness and resource supervision govern this
scope. The owner home is validated state, not a fallback directory or key oracle.

The prototype supports one active work scope per coordinator generation. Its process
bound identity and init cleanup are a tested mechanism, not a required final process
layout. Keep that mechanism until a replacement establishes equally clear work identity,
resource accounting and complete cleanup. Do not add multiple scopes by merely removing
the current checks or recycle an identity that old requests can still target.

A work Stop remains irreversible. A replacement may admit an explicit new request,
but it must not resurrect stopped work or an old grant. Natural shell exit and terminal
hangup are different events: surviving detached descendants do not become an implicit
Stop request merely because their original shell ended.

### Presentation

Own the terminal process role, PTY, presentation identity and terminal output state.
A direct interactive shell can be a work root. A tmux attachment is instead a client
of other work in the owned scope. Their exits mean different things, regardless of
whether the scope is permitted to continue without Console.

A replacement presentation gets a new parser/output identity. Do not reconstruct an
old screen by silently rebasing a bounded output tail. A retained direct terminal
would need an explicit recovery contract before it can be exposed as a new mode.

### Attachment

Own the current UI stream, input permission, lease and delivery acknowledgement.
Foreground/unlocked UI checks and the existing BOOTTIME lease are independent of
work continuation. Revocation discards pending input and shuts down the old stream.
Late replies, queued callbacks and old generations cannot restore access.

The work ID, presentation ID, attachment generation, Console registration epoch and
Android platform epoch are distinct identities. Do not collapse them into a single
session number while simplifying the code.

## Policies and compatibility

The existing modes are compatibility mappings, not the target Unix lifetime policy:

| Current entry | Continuation permission | Terminal role |
| --- | --- | --- |
| Ordinary Attach that creates work | Bound to the registered Console process | Direct work root |
| New kept | Explicit Android notification backed grant | Replaceable tmux client |

A Console process being alive is not the same as an Activity being foreground.
The current plain mode permits Activity detach while the process remains alive.
Calling that policy merely "foreground" would obscure its real behavior.

No new combination is made available by the internal extraction. In particular:

- Attachment loss alone does not create a retention grant.
- A replaceable frontend does not make its workload retained.
- Retention does not permit restarting a dead work root.
- Retention, automatic restart, wake authority and locked UI access remain distinct.
- Keep stays off by default. Services, SSH and package transactions remain separate work.

Before exposing new creation modes, define their start, detach, Console loss, terminal
hangup, natural exit, Stop and recovery behavior according to the accepted Unix policy.
Ordinary owner work must not require a specific terminal, tmux or a product specific
Keep action. These tools retain their actual Unix semantics; they do not bypass Android
user/CE authority, resource supervision or explicit Stop. The next workload interface
must express that policy rather than inherit restrictions from the prototype.

## First implementation slice

[`TerminalProcessState`](../owner/native/terminal_process.h) now records the directly
forked terminal process's role, exit routing and bounded retirement. It receives real
fork/waitpid observations from the coordinator. It does not discover processes,
provide Android authority, signal PIDs or claim ownership of a descendant tree.

The coordinator uses this component for PTY retirement, frontend replacement and
terminal exit handling. The existing Keep flag now describes retention/admission and
the compatible public result, not the terminal role or runner selection. The New kept
adapter explicitly selects both the confirmed grant and the tmux client role.

The existing five second retirement bound remains. A hung client still ends the whole
work scope through init. The shared cgroup has not become independent supervision of
presentation descendants. That limitation must stay explicit until a different cleanup
design is implemented and qualified.

Tests exercise the actual component and the production revoke/exit/stream methods with
host PTYs and sockets. They also vary retention and terminal role independently, so
accidental recoupling is detectable. These extra combinations are host model controls,
not new Android modes.

Source `f0a5e7f` passed all 347 host tests, including optimized and sanitizer checks of
the process model. Both Android native module configurations, ordinary and explicit
Keep, compiled successfully. Their ARM64 binaries and configurations were frozen and
rechecked, including the linked terminal process methods. Framework adaptation checks
passed before and after the builds. The kept runner retains its prior bytes.

These are host and native module results, not a new complete image or runtime result.
The earlier lifecycle trials used source `17b998c`; their observations do not silently
transfer to the modified coordinator.

## Work discovery and Stop candidate

`WorkInfo` describes the immutable work identity, observed idle/preparing/running/
stopping state, lifetime policy and terminal recovery strategy. It carries no terminal
FD, command, home path or execution authority. `describeWork` requires the authenticated,
registered Console process. It neither starts work nor renews a lease or grant. It can
notice already lost platform authority and expose that the scope is stopping.

`stopWork(workId)` accepts only the exact service Binder and matching work ID. It does
not need an attachment generation, a healthy terminal parser or a tmux presentation.
A Stop of pending Keep admission prevents later completion from admitting work. A true
return means request acceptance, not completed group cleanup. Old transactions remain
in their original order; these operations and attachment work metadata are appended.

Console discovers metadata while foreground and unlocked, independently of successful
attachment. End can therefore stop observed detached work, including a kept workload
after a cold Console start. It captures the selected Binder and work ID before queuing
Stop and never resolves a replacement service for that operation. The existing platform
notification Stop path remains separate and does not wait on the native main lock.

Metadata queries have a separate bounded reservation and intent fence. An old query,
attachment or Stop completion cannot overwrite a newer work selection or resurrect a
stopping identity. Query failures are not treated as idle-work observations. Attachment
replies carry their own work metadata, avoiding an extra synchronous call during the
short terminal lease promotion window. Parser recovery uses its own strategy rather
than the Keep permission bit.

This changes discovery and Stop availability, not permission to keep computing. Ordinary
work still ends with Console process death; explicit Keep still requires its Android
grant. No new creation mode, restart, wake or locked terminal access is introduced.
Matched Android native and Console artifacts, followed by runtime checks, remain
separate verification gates.

### Observed candidate behavior

Source `13a1af0` passed 352 host tests. Ordinary and Keep native/Console modules built,
and the lab image was frozen with matching host tools. Inspection checked the actual
work API in native code and Console bytecode, along with unchanged platform authority,
owner payload and policy inputs.

In the fresh offline ARM64 emulator:

- Opening Console discovered idle state without creating a shell or grant.
- Explicit Detach left plain work alive and terminal input disabled. End then removed
  that workload group without reattachment.
- Console process loss left kept work alive. A cold Console discovered it and enabled
  End without adding a new terminal client. End removed the complete group.
- The repeated genuine reply delay lasted 2.501 seconds. Native work ended after
  1.003 seconds and its group was removed after 1.115 seconds, before the late reply.
- Real CE locking again reported busy files. Old work was cleaned up; normal PIN entry
  restored availability and fresh work read its saved file, compiled and ran C.
- Ordinary app home/service access remained denied before and after the faults.

The original readiness observer rejected the new two line status label without sending
input. A separately recorded observer update accepts only the exact supported labels
and still requires a fresh hierarchy plus an enabled, focused terminal view. Frozen
fixture inputs were not edited. One initially named detached End observation was in
fact still attached; only the later explicit Detach trial supports the detached claim.

The fixture subsequently reached its UI deadline. Guest shutdown and capture completed,
but final planned End/process death checks and a final authority snapshot were not
reached. The overall run is incomplete, not a blanket runtime pass. Complete physical
key removal and broader storage/pressure/phone behavior remain unqualified.

### Review correction and remaining responsiveness limit

Source review found an eventual rediscovery gap. If Console left and returned while
an old query or attachment was outstanding, the old result was correctly rejected,
but the new foreground intent could remain without an observation after the old
operation completed. Completion now requests a fresh observation for that current
intent after retiring the old reservation. It does not retry an RPC failure for the
same intent indefinitely. Tests exercise eventual discovery after stale success,
stale failure and cancelled attachment completion, not just stale-result rejection.

The correction in `1571c7b` passes all 353 host tests and matched ordinary/Keep Android
native and Console module checks. The native coordinator and runner bytes match the
`13a1af0` builds; Console changes. The correction does not yet have its own complete
image or runtime result.

Console still has one control executor. Discovery and UI Stop can wait behind a
blocked admission RPC even though native Stop does not require an attachment lease.
The independent Android notification Stop path remains available for kept work. This
client responsiveness limitation needs a coherent admission/control design; it is not
claimed solved by the metadata API or by the rediscovery correction.

## Subsequent gates

1. Validate independent work discovery and exact Stop on Android, including idle
   discovery, pending/cancelled attachment, detached plain End, cold kept discovery,
   stale Binder/work targets and complete group cleanup.
2. Design explicit work creation/admission and cancellation separately from terminal
   attachment, with a bounded control path that remains usable during blocked admission.
   Current modes may serve as temporary compatibility adapters, not design constraints.
   Metadata and presentation choices are not execution authority.
3. Separate owner command/argument/stream handling from optional terminal frontend
   selection. Preserve the trusted execution boundary, owner identity, worker filter
   and resource admission, not necessarily the runner's present implementation or
   fixed command list. The coordinator must not execute owner payloads with its authority.
4. Establish Unix hangup and detached descendant behavior, including work without a
   terminal or tmux. Keep output recovery explicit and bounded; never silently invent
   a recovered screen. Detach is not terminal hangup, and neither is complete work Stop.
   No automatic restart or wake authority follows from these semantics.
5. Repeat host, artifact and Android runtime checks for the implementation. Include
   controller loss during admission, late grants/replies, stale work and presentation
   IDs, output gaps, frontend exit/hang, locked UI, Stop, CE loss and fresh work recovery.

## Boundaries that remain mandatory

- Actual Binder UID/SID and Console process identity, not caller supplied identities.
- Worker Binder restrictions, no owner cgroup control, and fixed inherited bounds.
- Genuine Android user/CE epochs and issued query deadlines. A late positive is stale.
- No lifecycle, grant or native main lock held across synchronous Binder or notification calls.
- Android notification Stop keeps its process bound path without waiting for the terminal
  or a stalled native main lock.
- Complete init cleanup, not a guessed PID or Unix process group.
- No automatic grant, work or parser restoration after authority or identity loss.
- No claim that a CE cache value or successful method return proves physical key removal.
