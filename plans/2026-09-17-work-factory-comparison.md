# Work factory comparison

**Status:** both backends completed the listed Android comparison controls at `409fc6d`.
The owner accepted the refined [delegated supervision ownership model](../docs/architecture.md#work-supervision),
not either fixture as the production implementation. The earlier
[init factory proposal](2026-09-17-work-factory-proposal.md) remains comparative design
work, not an adopted Andrix work factory in PID 1.

## Candidates

- **A, existing Android init unchanged:** an Andrix work manager creates and supervises
  dynamic workloads using existing kernel and Android facilities. The experiment must
  account for the manager's trusted resource authority and its own failure cleanup.
- **B, narrow init extension:** an Andrix manager requests new instances of a complete
  image defined native work profile. The experiment must preserve init's launch and
  lifetime guarantees without exposing arbitrary privileged execution.

Both reuse Android supervision and the Linux kernel. This is not a comparison with
systemd installed as another PID 1, nor permission to weaken worker isolation. Normal
owner programs still use ordinary fork/exec, streams and job control inside their scope.

## Common requirements

1. Apply and verify owner identity, explicit capability settings, resource admission
   and execution authority before releasing payload code.
2. Give each admitted scope an immutable identity. A reusable name, PID or directory
   path alone is not a capability. Old requests must not affect a replacement.
3. Separate reserve, accepted Start, cancellation, execution and completed cleanup.
   Unknown replies do not authorize duplicate starts. UI loss is not an implicit Stop.
4. Keep control bounded and independent of a blocked launch or terminal operation.
5. Preserve actual Unix terminal/signal behavior. An entry's exit is not a blanket kill
   of surviving detached descendants. Explicit scope Stop does terminate all its work.
6. Stop one scope without terminating another. Exercise ordinary completion, explicit
   Stop, guardian loss, manager loss, cancellation and resource/setup failure.
7. Prove worker and ordinary-app negatives with real positive controls. No worker
   control of cgroups, arbitrary Android services or privileged launch parameters.
8. Keep phone services and unrelated resources outside the experiment. No production
   installation, signing changes, SSH, package transactions or data deletion is implied.

Process termination, resource accounting release and empty directory reclamation are
separate observations. An implementation must bound and reconcile residual state and
prevent identity reuse hazards. Do not select a design merely because a particular
prototype reports one of those facts earlier than another.

## Proof sequence

| Stage | A: existing facilities | B: init extension | Evidence boundary |
| --- | --- | --- | --- |
| Source feasibility | Trace group creation, nesting, permissions, manager death, group kill and directory removal | Trace parsed profiles, mutable service state, capability setup, launch gates and reap ordering | Source findings only; no runtime pass |
| Focused mechanism tests | Real nested cgroup/process behavior plus actual manager state/cleanup paths | Actual profile construction/rejection tests, not a separate model of init | Host/kernel and Android distinctions remain explicit |
| Android experiment | Use an image whose init implementation is unchanged | Use the separately enabled extension and exactly identified modified inputs | Separate matching frozen image/tool sets, fresh data |
| Common failure controls | Same request/cancel/identity/descendant/manager-failure cases | Same cases | Report partial failures, not a score based only on successful starts |
| Decision | Identify remaining authority, correctness and recovery gaps | Identify remaining authority, correctness and recovery gaps | Choose on correctness, coherence, maintainability and owner control |

A source finding may rule out a particular shortcut without ruling out the whole
candidate. For example, the current library's nonrecursive directory removal needs
examination for nested scopes; it is not itself proof that no external manager can
implement safe cleanup. Conversely, a small init patch is not automatically the better
architecture. Prototype only uncertain mechanisms, not two complete operating systems.

## Initial mechanism results

The [mechanism tests](../tests/work-factory/README.md) now provide two distinct results:

- Real Linux host cgroup operations established nested process termination, independent
  Stop with another live group, nonrecursive `cgroup.procs`, recursive population/kill,
  required controller activation, separate directory reclamation and stale FD refusal
  after path reuse. The manager PID was retained unreaped through explicit cleanup.
- Four tests compiled with the actual Android `libinit_host` established fresh profile
  construction through `ServiceParser`, exact declared identity/capability/limit fields,
  no copying of mutable instance state, and rejection without partial publication.
  The existing temporary-service constructor's absent capability profile was observed
  directly in its object, without executing a service or changing credentials.

Both have useful mechanisms. The next native implementations and normal/A/B image
gates passed at `7b8a117`, followed by separate fresh Android attempts. A created two
held scopes but observer permissions prevented the planned kernel inspection. B
completed creation, worker lifetime, access negatives, independent Stop, stale-ID and
blocked-allocation controls. Actual init/kernel cleanup after manager loss was logged,
but a population observer error stopped the run before recovery.

Those initial runs remain incomplete. The corrections at `7127cc7` passed 366 host
tests and both Android native/policy configurations. The later documentation commit
`409fc6d`, with identical native code, then passed another 366 host tests and complete
normal/A/B artifact gates before the corrected trials below. The earlier result with fixed slots is not substituted for either.

## Corrected Android results

Both backends completed the [listed finite controls](../tests/work-factory/README.md#corrected-android-comparison-result)
in separate fresh fixtures at `409fc6d`. These included actual authority and resource
observations, duplicate creation, detached descendants, ordinary app negatives with
live positives, independent Stop, old identities, held cancellation and blocked
allocation followed by late helper cleanup without payload. Both then completed
manager failure, a fresh manager epoch with no restarted jobs, old hierarchy retirement,
new work and final graceful cleanup. Platform and boot identities remained unchanged
within each trial. A's init binary matched the unmodified baseline.

| Observed boundary | A | B |
| --- | --- | --- |
| Work containment | Nested groups under the manager's init group | Separate complete init service instances |
| Worker control authority | MAC still denies cgroup writes, despite shared UID with the trusted creator | MAC and protected init group ownership deny writes |
| Manager death | Init kills the nested processes; captured child groups become Empty | Guardians exit on loss of the manager connection; init kills descendants and removes their groups |
| Directory cleanup | Init first retries parent removal with `EBUSY`; the new manager removes known empty children and requests the existing parent `rmdir` action | Init removes each shallow group; captured objects become Removed |
| Recovery | New identity, no restored jobs, old controls retired, fresh work and final cleanup | Same listed outcomes |

A's init retry interval, about two seconds in this fixture, and directory reconciliation
are real costs, not hidden cleanup success. B's guardian connection and init service association
are also real parts of its failure contract. A process being killed, a group being
empty, a directory being removed and all physical accounting being released remain
different observations.

The broader common requirements are not fully qualified. Still open are resource and
setup failure injection, natural completion of all remaining descendants, deliberately
forced numeric PID reuse, uncertain launch replies, arbitrary blocked operations and
saturated control transports. This experiment did not repeat CE loss, pressure, suspend,
durability or phone qualification. Fixture request counts, limits and property transport
are not a product API or owner defaults.

## Accepted ownership direction

The owner accepted a refined contract: **Android supervises the owner environment,
Andrix manages work inside it, and the kernel enforces containment.** The decision is
recorded in the [architecture](../docs/architecture.md#work-supervision). It accepts
responsibility boundaries, not a finished API, process layout or qualified implementation.

### Goal and alternatives

The goal is ordinary owner computing independent of Console, with genuine Android
authority, inspectable resources and complete scope control. A reusable PID or name
must not let old control affect new work.

A demonstrated nested containment and direct manager control without an init work
factory. Its residual directory reconciliation and init retries are real costs. B
constructed complete fresh profiles and used init's service cleanup, with less direct
cgroup authority in the manager. Its current Stop and manager loss paths depend on
guardian exit. Neither result proves the complete failure contract or requires keeping
its particular prototype mechanism.

### Decision and reasons

Use the delegated resource ownership hierarchy, complete declared launch profiles and
a proper generic Android cleanup contract. Andrix owns work identities, admission,
resources and direct group control. Init owns the outer service instance and its
cleanup boundary, not Andrix work IDs, admission or terminals. Manager failure therefore
has kernel containment rather than requiring each guardian to cooperate.

The privileged side starts only fixed trusted bootstraps under declared profiles. Actual
identity, capabilities, resource placement and descriptor state are parts of a complete
transition, not independently exposed privileged mutation operations. Owner program,
argument, environment and working directory requests remain normal work API inputs;
they must not redirect privileged bootstrap execution. User/CE authority stays with
Android's framework and is enforced by the manager and launch/input gates, not new
Andrix policy in init.

Keeping init unchanged is not the objective. Generic delegation and cleanup may need
Android changes. Those changes must reclaim owned subtrees without stalling unrelated
init work, preserve exact instance identity and report incomplete cleanup honestly.
Neither A's property/reclaim workaround nor B's dependency on guardian exit is adopted
as the production interface. This is an ownership and guarantee decision, not a choice
based on patch size or prior implementation effort.

### Costs, open choices and next gates

The [delegated supervision contract draft](2026-09-17-delegated-supervision-contract.md)
is the next design and proof surface, not a qualified implementation. Name its operations, authorized callers,
permitted inputs, profile provenance, instance and descriptor ownership, activation
states, cleanup progress and failure outcomes. Keep generic service instance identity
distinct from Andrix work identity. Exact wire APIs and helper processes remain open.

Qualify the combined contract with failed launch, stuck manager or guardian, identity
reuse, interrupted cleanup, resource failure and CE loss. Include Stop during admission,
late completion, independent work, ordinary app/worker negatives and normal image
exclusion. Do not infer those results from the two successful component vehicles.

Revisit mechanisms if they cannot preserve these boundaries or make supervision and
recovery incoherent. Preserve the accepted owner guarantees unless deliberately revised;
do not silently replace them with what a prototype happens to support.

## Qualification bounds

Use measured resource admission, hard memory/swap bounds and filesystem reserves suited to
the test environment. Preserve immutable evidence and required recovery state. New comparison budgets
must account for both images, extraction, staging and fresh guest working data before
launch. If the required overlap does not fit, obtain storage/retention authority rather
than deleting old attempts or quietly lowering a reserve.

Normal/proof selection, source provenance, artifact checks and actual Android authority
remain separate gates. Update the [design evidence register](../docs/design-evidence.md)
with what each stage establishes and what it does not. No candidate becomes accepted
architecture just because its local fixture passes.
