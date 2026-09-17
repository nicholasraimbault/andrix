# Work factory proposal

**Status:** candidate B in the owner approved [comparative tests](2026-09-17-work-factory-comparison.md),
not accepted product architecture. Candidate A uses existing Android facilities without
changing init. The [fixed-slot Android trial](../tests/owner-scope/README.md#observed-fixed-slot-result)
supplies scoped evidence for independent lifetime, identity and cleanup, not a general
factory or a conclusion that init must be extended. The subsequent
[accepted ownership decision](2026-09-17-work-factory-comparison.md#accepted-ownership-direction)
requires a generic delegated service contract, complete profiles and manager ownership
of work. It does not adopt this particular factory in PID 1. The proposal below remains
a record of the alternative and its useful launch guarantees.

## Candidate to compare

Prototype a narrow init facility that instantiates an image defined native work profile
with a fresh instance identity. Preserve Android init's actual resource setup, capability
handling, lifetime pinning and complete group cleanup instead of recreating those rules
in a terminal application or granting owner programs cgroup control.

This would modify Android init, a phone critical trusted component. The next experiment
should remain separately selected in a lab image until its interface and failure behavior
are qualified. It is not permission for arbitrary root commands, caller selected UIDs,
capabilities, SELinux contexts or filesystem paths.

## Evidence leading here

- Named init profiles established the actual zero capability sets, resource limits and
  independent complete cleanup used by the successful scope trial.
- Plain `exec_background` does not carry the complete profile. Its absent capability
  configuration does not establish the required zero bounding set. Do not weaken the
  guard to make that shortcut qualify.
- Ordinary process-group helpers create UID/PID sibling groups, not children of the
  caller's group. Moving processes into them does not preserve the current parent's
  cleanup guarantee automatically.
- Nested groups remain an alternative, but the current helpers do not provide a complete
  nested-scope admission/removal contract. Controller activation, recursive cleanup,
  directory removal and trusted resource authority would need separate design and proof.
- The successful fixed slot count and property triggers are test machinery, not a mature
  work model. Shipping them as permanent restrictions would ignore what the tests taught us.

## Proposed boundary

The interface should select a validated, read only profile, not accept privileged launch
parameters supplied by a work program. A profile identifies the fixed trusted guardian
entry and its complete identity, capability, resource and scheduling constraints.
Changing a trusted profile follows the approved system configuration/update authority.

A new instance has its own identity, process/resource lifetime and completion state.
It must not copy a live service's PID, restart flags, callbacks or other mutable runtime
state. Profile data and instance state need an explicit separation. Unsupported profile
features must be rejected, not silently dropped during instantiation.

The Android work registry authorizes a particular instance request and supplies its
bounded launch/admission data to the owner execution entry through a separate crossing.
Owner command text is not passed to init for privileged shell evaluation. Actual owner
program execution remains under owner identity and the worker restrictions.

Creation, cancellation and Stop must refer to the same immutable instance. Repeated,
late or lost requests cannot create duplicates or target a replacement. Resource admission
must precede payload execution. A caller disappearing, a cancelled reservation and an
accepted owner job are different events. No ordinary job restarts because its guardian
or registry restarted.

Do not choose a concrete transport just because the prototype used properties. Caller
identity, bounded delivery, acknowledgements, replay handling and failure recovery must
be demonstrated for the chosen interface. Binder oneway PID is not available; numeric
PID alone is not an instance capability. The interface is not exposed directly to
ordinary applications or native owner code as an ambient management privilege.

## Experiment gates

1. Specify a minimal profile/instance interface and threat model, including authenticated
   callers, resource ownership, unsupported settings and result-versus-cleanup semantics.
2. Test complete profile preservation and rejection before integration. In particular,
   distinguish an explicitly empty capability set from an absent configuration.
3. Exercise bounded reservation, duplicate request, cancellation, timeout and late creation
   handling against the actual implementation, not only a parallel state model.
4. Repeat the existing two-scope positive/negative controls, now with dynamically created
   instances rather than fixed slots. Preserve the actual PID lifetime pin through cleanup.
5. Fail creation at each boundary, lose the registry/guardian, and race cleanup with a new
   request. Check both complete cleanup and survival of unrelated admitted work.
6. Verify normal-image exclusion of experiment controls, compiled policy, matching frozen
   images/tools and fresh runtime evidence. Do not modify the handset or production keys.

The goal is a correct reusable Android supervision mechanism. If this experiment exposes
a better alternative, change the design. Neither keeping the prototype nor minimizing
the patch to init is the architectural criterion.
