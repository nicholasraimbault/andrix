# Work admission and release gate

Status: internal implementation candidate at `d211b25`. Updated host, sanitizer and
separate process controls pass, along with 404 general host tests and normal/Keep Android
native compilation. The Soong host admission test also ran from frozen artifacts. This
is not a new public work API, ordinary owner launcher, Android MAC crossing or a qualified
CE fault result.

## Goal and ownership

Use the qualified generic Android environment boundary without moving work or CE policy
into init. Andrix must bind an execution admission to its original trusted Android
platform instance, user and authority generation before asynchronous payload creation.
Stop must remain independent of blocked admission, presentation and transport I/O.

The work registry owns unique work identities, bounded reservations, caller authentication,
immutable launch descriptions, creators, processes and resource cleanup. The platform
adapter supplies genuine authority and query issue based freshness. This component owns
only admission, permission publication, a single entry claim and irreversible closure.
Neither a copied identity nor memfd metadata authenticates a caller.

## Candidate mechanism

Each reservation has its own sealed size memfd with a lock free shared atomic word.
Reservation alone is unbound and cannot execute. It occurs outside control locks and
before admission. The authority binds the original epoch exactly once. A trusted completed
staging profile/resource transition must then report preparation. It is not a public
credential or resource operation. The [ordinary launch boundary](2026-09-18-owner-launch-boundary.md)
keeps the gate in the trusted role; its fixed final owner transition and actual profile
checks still precede arbitrary program execution.

The manager publishes permission only while its original epoch is still current and
fresh. The publication stores the observer's issue based deadline, not a new deadline
from reply arrival or wake delivery. An outstanding query's earlier failure deadline
also caps a new publication; the cap can shorten permission but never extend it. A
later local revocation closes the shared gate rather than rewriting an old grant's
publication metadata. Publication and the launcher's one entry claim are
separate facts. A queued transport message is only a wake. The trusted launcher must
claim the same shared gate at the declared launch commitment, with the expected work
and epoch and a fresh monotonic clock sample. It must close/unmap management handles
before the final owner-role transition. Claim success authorizes that complete transition;
it is not a report that an ordinary program successfully executed.

Stop is an atomic sticky bit on that object. It takes no registry, platform, terminal or
admission mutex and performs no syscall. If it precedes publication or entry claim, the
late action fails. If entry wins first, Stop still closes the gate, but scope termination
is a separate mandatory action. No claim is made that an instruction cannot run between
entry and actual kernel termination. A publication interrupted while writing metadata
never becomes releasable. The entry bit remains observable after Stop.

The authority control lock covers only bounded memory operations. Binder I/O, memfd
creation, descriptor transfer, process creation, placement and destruction stay outside
it. A fixed number of registered admissions gives backpressure; stopped slots do not
silently become free. Retiring a slot is not evidence that its creator/process/resource
obligations have been discharged. The surrounding work registry must retain those facts.
Unbound reservation allocation also needs that registry's own bound.

The current `PlatformLifecycle` adapter already binds one remote platform incarnation
and generation for its process lifetime. Its successful query now supplies the admission
controller with that same epoch and issue based lease deadline. Its failure path closes
registered gates. The current framework observes user 0 only, so this slice carries that
trusted fixed user, not a caller selected user or a claim of multi user support. Existing
Console/plain/Keep paths do not call the new admission methods.

## Ordering and limitations

- A stopped or revoked request can never bind again, even in a fresh authority object.
- Authority instance/user/generation mismatch, observed expiry, backward clock or explicit
  revocation permanently fails that authority object. A later positive cannot revive it.
- A continuously fresh positive in the same epoch can authorize pending work. Once a
  release deadline is published, later renewals do not extend that old entry grant.
- Local authority operations are serialized. Revocation closes all registered gates
  before it returns. A child entry racing a gate's closure may have won before that
  closure. This is not instantaneous atomicity with Android CE key withdrawal.
- A clock sample and an atomic instruction are not one hardware operation. Scheduling,
  suspend and real revocation latency remain qualification work. The existing native
  monotonic freshness model is preserved rather than inventing a key withdrawal barrier.
- A failed manager's whole environment is still Android's cleanup responsibility. The
  gate is not a replacement for containment or independent environment Stop.

The private launcher and its received gate are trusted. Size seals prevent truncation,
not writes through another authorized mapping. The gate must never be exposed to owner
payloads or arbitrary clients. Descriptor adoption verifies type, access, seals, framing,
work and original epoch, but relies on separately authenticated private transport.

## Alternatives and costs

A check followed by a pipe write lets already queued data outlive Stop. Holding the work
registry lock across allocation or transport blocks control. A shared process lock held
by the launcher can become unavailable when that process stops or dies. The chosen gate
instead gives Stop a single atomic operation, at the cost of one mapping/descriptor per
reservation, an explicit shared ABI, trusted descriptor handoff and entry validation.
The first ABI requires lock free shared uint32 atomics and Linux memfd seals, without a
weaker fallback. These are mechanism constraints, not final public API shapes or quotas.

## First gates

Host units must cover unbound refusal, original epoch binding, preparation, one publication
and entry, stale/foreign requests, timeout without renewal, capacity and real concurrent
Stop/publication/claim orderings. Separate fixed host processes must exercise transferred
descriptors, a queued wake while the launcher is actually stopped, expiry without parent
progress, and a late helper after old authority revocation plus a new explicit epoch.
A positive entry followed by Stop must not be mislabeled physical cleanup.

Source review after an initial passing suite found that an outstanding query can fail
earlier than the last positive lease. The correction exports the earliest known deadline
and allows only a narrowing publication cap. A separate Android build attempt exposed a
missing `linux/memfd.h` in the hermetic host sysroot. The corrected build uses the same
required Linux syscall and ABI flags, with no weaker fallback or warning suppression.
Both incomplete evidence checkpoints remain separate from the final gate.

The first focused checks passed optimized units, ASan/UBSan units, 1,000 selected
three thread Stop/publication/entry races and 500 release/revocation races. Separate
self-executed host processes passed actual transferred gate, queued wake, expiry without
parent progress, late old epoch helper and positive new request controls. The admitted
entry remained a separate live process after gate closure until the test supervisor
actually killed and reaped it. These are finite checks, not exhaustive concurrency.

These checks supply authority facts on the host. They do not replace a fresh Android
trial using genuine CE withdrawal/regrant, actual caller and owner MAC boundaries, late
scope/process creation, complete cleanup or a real ordinary program launch. Those are
required before changing user visible behavior.
