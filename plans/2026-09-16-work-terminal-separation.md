# Work and terminal separation

**Status:** source review and first native component extraction. Public lifecycle
behavior, Binder transactions, product defaults and Android authority are unchanged.
The complete workload API and new lifetime policies are not implemented yet.

This follows the [two scoped lifecycle trials](2026-09-14-lab-lifecycle-faults.md)
and implements the separation required by the
[accepted architecture](../docs/architecture.md#lifecycle-and-networking). The tests
identify boundaries to preserve. They do not require preserving the prototype's
structure or establish every storage, suspend or pressure case.

## What the prototype currently couples

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

For the next implementation, retain one active work scope per coordinator generation.
A work end remains irreversible. An idle replacement coordinator may admit an explicit
new request, but it does not resurrect the old work or its grant. Supporting multiple
work scopes is not part of this first separation.

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

The existing modes are compatibility mappings, not a complete future policy model:

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

Before exposing new creation modes, define their start, detach, Console loss, natural
exit, Stop and recovery behavior explicitly. The next workload interface should make
those choices visible rather than inheriting them from a terminal implementation.

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
not new Android modes. Android builds and runtime evidence remain separate gates.

## Subsequent gates

1. Introduce a workload description and explicit admission/discovery boundary that
   does not require successful terminal attachment. Preserve current modes as explicit
   compatibility adapters while the lifetime policies are defined.
2. Separate Stop targeting from presentation health, retaining exact work/process
   identity and the distinction between a request and completed group cleanup.
3. Separate the work launch description from optional terminal frontend selection.
   Keep the fixed trusted runner boundary, owner identity, worker filter and resource
   admission. Do not turn this into privileged arbitrary execution by the coordinator.
4. Demonstrate explicitly retained work without a tmux prerequisite. Define output and
   reconnection semantics before adding another terminal mode. No automatic retention
   or restart follows from the internal model alone.
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
