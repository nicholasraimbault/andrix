# Native identity preparation admission

Status: implemented with independent source review and host controls. Android compilation and
runtime qualification remain separate.
The version 1 writer remains selected. No version 2 publication or native account execution is enabled.

## The observed problem

The durable index can contain holds whose bodies are unavailable. Those holds count toward the
store's format bound, but they are not all restorable in memory pins. The old manager checked only
the latter before preparing a new identity.

A controlled host reproduction loaded 64 valid index entries, counter 64 and no usable bodies.
The old manager returned a new pending handle with native ID 65. Its commit then refused because
the index could not hold a 65th entry. The original pending obligation remained. This was not a
UID reuse or execution grant, but the manager had accepted an operation it could not publish.
The count is the existing parser bound, not a new product quota.

## Admission before issuance

The core now supplies an immutable preparation proposal with its own next ID and complete proposed
snapshot. It issues nothing. The proposal is bound to the core instance and a mutation epoch.
Changing the core invalidates it, and publishing reruns the same validation. An existing pin uses
an exact retry, not a second issuance token. The former unchecked string issuance path is removed;
core test fixtures explicitly supply their own test provenance. The epoch is an opaque
memory identity, not another account ID or a durable counter.

A pure reservation projection is shared by the admission check and the actual writer. It keeps
every durable entry, including unavailable bodies and legacy tails, plus every unreserved pending
pin. RETIRING pins also count. The Settings check reads the cached store view under the PMS lock;
it performs no filesystem I/O. The writer still reloads actual storage outside that lock and checks
the exact expected base. A preview does not promise future storage availability or acknowledgement.

The same mechanism will need complete binding data and encoded byte admission before a future
version 2 writer is enabled. This change does not enable that format transition.

## Ownership through an interrupted reply

A newly issued manager pin retains an opaque reference to the original issuance inputs. The
manager owns their interpretation: exact selection, record, lineage and one canonical handle.
The core neither serializes those references nor treats them as grants. A lost auxiliary lookup
or a failure before returning a handle cannot substitute a newly observed APK for that history.
Restored pins still require their existing durable binding and explicit designation.

Allocating index changes are constructed separately before publication. Subject remembering and
UID hold refresh are idempotent steps completed by the original retry. If a later step fails,
the original pin, inputs and handle remain owned. No timeout, absence or exception releases them.
This is not a guarantee that every possible JVM or process failure is recoverable in memory.

## Controls

- The exact previous manager fails the full durable index admission test. The corrected manager
  refuses before issuing an ID, changing a hold, remembering a subject or refreshing the allocator.
- Boundary and pending tests cover 63 durable entries, two uncommitted pins, unpublished retirement,
  and legacy CREATING and RELEASING entries.
- Twenty capacity projections and additional ownership, counter, user and stale cache cases are
  compared with actual version 1 store writes. The real Settings method is
  a profile bound framework fragment and is also exercised through the host manager facade.
- Foreign and stale proposals refuse, including a different instance with the same counter.
  A lineage lookup failure consumes no ID. The source scratch candidate was regenerated with
  all current added helpers; the build adapter also copies those helpers from the guarded source.
- Failures after issuance retain the original handle and inputs. Retries finish remembering and
  refreshing without issuing another ID.
- Controlled errors at each index insertion and removal step preserve the prior core state.
  A failure immediately after issuance but before handle construction retains the original input
  binding. Deliberately broken index publication, discarded provenance and ignored epoch controls
  are rejected by the tests.

These are strict Java and host filesystem results with Android facades and controlled source fault
injection. They are not physical memory exhaustion, Android runtime or native execution qualification.
