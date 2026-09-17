# Work factory comparison

**Status:** both backends completed the listed Android comparison controls at `409fc6d`.
A proposed direction follows below, but neither backend is selected for the product.
The earlier [init factory proposal](2026-09-17-work-factory-proposal.md) remains one
candidate, not a conclusion justified merely by the successful trial with fixed slots.

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

## Interpretation and proposed direction

The evidence defeats the assumption that a work factory must live in init to preserve
the demonstrated boundaries. Both mechanisms work for these controls. It does not show
that either prototype is already the correct complete product implementation.

The proposed next direction is **A's ownership model**, not automatic promotion of its
fixture code. Keep work admission, identities, resource scopes and direct group control
in an Andrix manager, with Android init supervising that manager. The nested containment
also gives manager failure a kernel group boundary, rather than relying on every work
guardian to cooperate. This fits the goal of keeping most work policy outside PID 1.
It is an ownership and control argument, not a preference for fewer changed lines.

B remains a useful alternative: it constructs complete fresh profiles and gives each
work instance init's existing service cleanup. It avoids A's residual child directories
and reduces the manager's direct cgroup authority, but adds a privileged instance factory
and activation path. The current B vehicle's Stop and manager loss paths still depend
on guardian exit; stronger handling of an unresponsive guardian remains untested.

Before adopting a product layout, resolve A's cleanup/restart behavior and both candidates'
remaining failure obligations. A narrower generic cleanup improvement would be a separate
proposal, not an excuse to claim this trial with unchanged init qualified new init code.
Neither backend has been accepted for the product. The owner must explicitly accept
or revise this proposed direction before production integration.

## Operational limits

Use the existing resource admission helper, hard memory/swap bounds and filesystem
reserves. Preserve sealed evidence and all retained guest state. New comparison budgets
must account for both images, extraction, staging and fresh guest working data before
launch. If the required overlap does not fit, obtain storage/retention authority rather
than deleting old attempts or quietly lowering a reserve.

Normal/proof selection, source provenance, artifact checks and actual Android authority
remain separate gates. Update the [design evidence register](../docs/design-evidence.md)
with what each stage establishes and what it does not. No candidate becomes accepted
architecture just because its local fixture passes.
