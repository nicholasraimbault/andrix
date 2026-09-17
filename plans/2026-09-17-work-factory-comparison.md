# Work factory comparison

**Status:** the owner approved focused comparative tests. Neither backend is selected
for the product. The earlier [init factory proposal](2026-09-17-work-factory-proposal.md)
is one candidate, not a conclusion justified merely by the successful fixed-slot trial.

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

Neither has passed the full common contract. The corrections at `7127cc7` passed 366
host tests and both Android native/policy configurations. They still need matching
corrected images and fresh trials. The earlier
fixed-slot Android result is not substituted for either. See the
[scoped observations](../tests/work-factory/README.md#first-android-comparison-observations).

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
