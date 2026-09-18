# Current work

## Governing direction

Make Android a general purpose, owner controlled Unix computer. Tests and prototypes
inform the long term design; they do not require preserving prototype code. Follow the
[design method](../docs/architecture.md#design-method): retain, refactor or replace
components according to correctness and coherence, including starting again when
necessary. Past investment, implementation time and difficulty do not justify an
inferior design.

Unix semantics, not a universal Keep switch or Android UI process lifetime, guide work
behavior. Detach, terminal hangup, shell job control and complete work Stop are distinct.
This target is an accepted direction, not a claim that the current prototype implements
it. The same review applies to existing resource policy, execution entry points, output
handling and owner tools before proof constraints become product restrictions.

## Prototype and design tracking

Use the [design evidence register](../docs/design-evidence.md) for the running list of
prototype/test vehicles, observed results, design implications, accepted intent,
proposals and next gates across the developed system. Update it with relevant source,
proof and milestone changes. The architecture holds accepted decisions; the register
must not turn prototype limits or successful tests into product requirements silently.

Apply the [deliberate decision discipline](../docs/architecture.md#deliberate-decisions)
to significant choices throughout Andrix, including existing components. Use R01 through
R17 as the review map. Record goals, ownership, authority, credible alternatives,
evidence, costs, failure behavior and next gates in the relevant design. Review does
not mean reopening accepted requirements automatically, nor claiming every area has
already been reviewed. Match the depth of the work to its risk and uncertainty.

## Product checkpoint

Andrix has a bounded ARM64/Bionic development environment on its GrapheneOS-derived
Android foundation. The emulator workflow supports terminal editing, native C/C++
compilation, Make, LLDB and tmux while retaining Android's application identities,
phone framework and authenticated read-only `/usr`.

[Explicit Keep](2026-09-14-keep.md) is implemented as an opt-in feature. Kept work can
survive Console-process loss and screen relock, with a fresh terminal presentation
on return. Stop/End and tested platform-loss paths clean up the complete workload;
reboot does not automatically restore a Keep grant.

The [notification follow-up](2026-09-14-keep-failure-controls.md) made the optional
Keep channel owner-blockable. Blocking active work, preserving that preference
through reboot, re-enabling without automatic work, and locked Stop were exercised
within the documented emulator scope. Keep remains off by default.

There is no supported Andrix release or buildable Pixel deployment product. Emulator
results are not general phone, privacy, power-loss or hardware qualification.

The [two approved lifecycle faults](2026-09-14-lab-lifecycle-faults.md) have now been
exercised on a fresh frozen lab image. A delayed genuine reply caused complete native
cleanup before the reply returned. The real CE lock produced a vold busy file outcome,
revoked availability and cleaned up the old workload. Normal PIN entry restored CE
availability; fresh work could read its saved file and compile and run a C program.
Neither fault required a framework restart or reboot. Complete physical key removal
is not claimed. The incomplete delay sampler and subsequent independent observations
are documented separately. Normal images omit the lab controls.

## Current milestone

Implement the [work and terminal separation](2026-09-16-work-terminal-separation.md)
identified by the source review. Android supervision stays authoritative. Console
becomes a client and tmux an optional presentation tool. Keep may remain a convenience
shortcut rather than the only form of retained work.

The first native slice separates terminal process role and retirement from permission
to keep computing. It passed 347 host tests and both Android native module builds.
Work discovery and exact work Stop now have matched Android module/image checks and
scoped runtime observations, including detached plain End and cold kept-work discovery.
The full runtime fixture ended at its deadline, so it is not a blanket pass. Review
found an eventual rediscovery gap; its correction passes 353 host tests and both
Android module configurations, but has no new runtime result yet. Console control
calls still share a lane, so Stop can wait behind blocked admission. Existing creation
modes, lifetime policies and defaults stay unchanged.

A [supervision design candidate and proof matrix](2026-09-16-unix-work-supervision.md)
now separate the intended contract from proposed mechanisms. Ten real host experiments
exercise PTY hangup, signal dispositions, descendant survival/adoption and configured
shell behavior. Source review identified Android group creation, cleanup and PID lifetime
constraints. These are not new Android runtime results or an adopted factory/process layout.

The [scope boundary experiment](../tests/owner-scope/README.md#observed-fixed-slot-result)
completed its listed Android controls at `0e60a42`, after 360 host tests and matching
module/policy/image checks. Two fixed init owned scopes retained detached descendants
after entry exit. A's complete cleanup left B live; old Binder/ID requests did not affect
a replacement, and held-entry Stop defeated late release. Real UID/MAC, protected limits,
worker restrictions and ordinary-app negatives were checked. The earlier failed attempts
and their lessons remain recorded, not reclassified as passes.

This validates the fixed-slot boundary, not a general dynamic factory or new product
lifetime policy. Plain `exec_background` lacks the full capability profile; inherited
FD use does not bypass backing-object MAC policy; oneway caller PID is absent; and
parent-death signals cannot replace init cleanup. These findings now constrain the
factory design.

## Next gates

The owner approved [comparative factory tests](2026-09-17-work-factory-comparison.md):
an Andrix manager using existing Android facilities with init unchanged, and a narrow
init extension that creates fresh instances from complete trusted profiles. Neither
fixture is adopted unchanged as the product. The first `7b8a117` attempts exposed two observer defects and remain
incomplete. Corrected source at `409fc6d` passed 366 host tests and complete normal/A/B
artifact gates. Both fresh Android trials then completed the listed creation, authority,
descendant, independent Stop, stale identity, blocked allocation and manager recovery
controls, including fresh work and final cleanup. These are finite fixture results,
not full product, resource failure, pressure or phone qualification.

The owner accepted the refined [delegated supervision contract](../docs/architecture.md#work-supervision):
Android supervises the owner environment, Andrix manages work inside it, and the kernel
enforces containment. This combines the delegated ownership hierarchy with complete
launch profiles and generic Android cleanup. It does not adopt either fixture's API or
require init to stay unchanged. The [decision rationale](2026-09-17-work-factory-comparison.md#accepted-ownership-direction)
retains the alternatives, observed costs and qualification gaps.

1. Refine and exercise the [delegated supervision and work contract](2026-09-17-delegated-supervision-contract.md).
   The draft names operations, callers, permitted inputs, exact instance identities,
   profile/descriptor ownership, activation and cleanup states, and the source impact
   map. It is not a released wire API. The ordering model checks Stop, late resources,
   observation/mutation fencing and replacement safety, not Android authority. A separate
   host kernel probe exercises captured group kill after leader reap and stepped empty
   directory reclamation. Neither result qualifies the combined Android contract.
   Init must not acquire Andrix work IDs, admission or terminal policy. User/CE authority
   remains in Android's framework and is enforced by the manager and launch/input gates.
2. Qualify the combined contract, not just its parts. Exercise failed launch, stuck
   components, identity reuse, interrupted cleanup, resource failure and CE loss, along
   with cancellation, independent work and actual authority negatives. Also qualify
   Android shell behavior and terminal separation. Stop acceptance is not cleanup success.
3. Implement the coherent design, replacing prototype components where needed, and
   repeat host, artifact and runtime verification before changing ordinary defaults.
   Fixture request counts, fixed payloads, property transport and limits are not product
   restrictions. Restart, wake and locked UI access remain separate from computation.

This direction is owner approved. Current plain work bound to Console and Keep backed
by tmux remain compatibility behavior until the replacement is implemented
and tested. No prototype component is protected from redesign by its development cost.
Existing safety boundaries and accepted product decisions remain deliberate inputs;
changing a requirement must be explicit, not hidden inside a rewrite.

The immediate implementation question is cleanup split into bounded steps on an exact
owned instance, with safe reaping, closed mutation ownership and no delayed numeric
signal hazards. A [native candidate](../supervision/README.md) now provides the bounded
state/ticket and captured cgroup primitives, with host unit/sanitizer and actual Linux
kernel controls. At `8a7ddd1`, 386 host tests and Android library/link compilation
passed, and the Soong host tests executed from frozen artifacts. It is not installed
as a normal product behavior. The optional init adapter subsequently compiled, followed
by captured LMKD registration at `5f9c893`. Actual parser construction and frozen protocol
host tests passed. The [Android vehicle](../tests/delegated-supervision/android/README.md)
now supplies the next selected program/policy and fresh runtime controls. At `c11e707`,
399 host tests, bounded directory takeback kernel controls, Android module/policy checks
and complete normal/test images passed. Two fresh Android attempts remain incomplete.
The first exposed helper execution/readiness MAC boundaries. The second kept the
bootstrap held and stopped its exact process on provider failure, but worker signal
setup failed before initialization. Actual LMKD registration was observed; full delegated
cleanup, recovery and its memory kill control were not reached. The startup correction
at `b05d656` passes 400 host tests and the selected native/policy gate, with no fresh
Android runtime result yet.

Next qualify the corrected worker startup and complete delegated lifecycle. Then bind
Andrix work admission to its original trusted CE epoch, close queued Release versus Stop
races, and connect ordinary owner program launch and Console presentation. These are
separate gates. Do not merely put synchronous cleanup in a thread, weaken a guard to
fit a prototype, or promote finite controls into pressure or phone qualification.

Pinned glibc and an Android hosted Wayland path remain later compatibility research.
They may reduce application friction, but no second ABI or GUI stack is adopted by
continuing the base work. Personal computing is the priority, not automatic persistent
server exposure; owner chosen background jobs and services remain capabilities.

Broader pressure/suspend testing, abnormal storage-backend failure and phone/release
qualification remain open. Native package transactions and explicitly enabled SSH
are later capabilities, not implied by the current milestone.

## Foundations and references

- [Accepted architecture](../docs/architecture.md)
- [GrapheneOS migration](2026-09-08-grapheneos-migration.md)
- [Android lifecycle integration](2026-09-13-android-lifecycle.md)
- [Native compiler](2026-09-11-native-compiler.md), [C++ defaults](2026-09-11-cxx-defaults.md),
  [Make](2026-09-11-native-build-tools.md) and [debugger](2026-09-12-native-debugger.md)
- [Terminal and input](2026-09-10-owner-tools.md), [cold attachment](2026-09-11-cold-attachment.md),
  [native tmux](2026-09-13-retained-terminal.md)
- [Development artifact handling](../docs/development-artifacts.md)

Live operating state and detailed run records are maintained privately, not here.
