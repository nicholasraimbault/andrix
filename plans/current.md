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

The [next factory experiment](2026-09-17-work-factory-proposal.md) is proposed for an
explicit decision: a narrow init facility that instantiates a complete image defined
profile with a fresh lifetime identity. It would extend a privileged Android launch
interface, so it is not treated as already approved by the fixed-slot trial. No init
changes for that facility have been made.

1. Design and qualify a general factory that preserves the complete trusted launch
   profile and exact instance lifetime. Use the fixed-slot evidence, not its slot
   count or property interface, as the basis. Compare init instantiation that preserves
   the profile with alternative Android owned boundaries before adopting a layout.
2. Use focused tests for Android shell behavior, descendant topology, admission
   cancellation and control responsiveness before committing to the replacement.
   Preserve genuine user/CE authority, bounded resources and complete work Stop. Keep
   restart, wake and locked UI access separate from continuing computation.
3. Implement the coherent design, replacing prototype components where needed, and
   repeat host, artifact and runtime verification before changing ordinary defaults.

This direction is owner approved. Current plain work bound to Console and Keep backed
by tmux remain compatibility behavior until the replacement is implemented
and tested. No prototype component is protected from redesign by its development cost.
Existing safety boundaries and accepted product decisions remain deliberate inputs;
changing a requirement must be explicit, not hidden inside a rewrite.

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
