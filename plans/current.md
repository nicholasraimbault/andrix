# Current work

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

## Current milestone

Prepare the [approved lab lifecycle fault controls](2026-09-14-lab-lifecycle-faults.md):

- invoke Android's real primary-user CE-storage lock operation;
- delay one genuine lifecycle snapshot reply beyond the native freshness deadline.

The source candidate and focused host tests exist; Android artifact inspection and
runtime qualification remain to be completed. Normal images must omit these controls.
No broad application/Shell permission or synthetic availability flag is part of the
scope. Actual key-withdrawal outcomes, including busy-file behavior, remain distinct
from screen relock and from asynchronous process cleanup.

## Next gates

1. Verify fault-enabled and normal build artifacts, including absence of the lab
   commands from normal images.
2. Exercise real key-withdrawal and delayed-reply cleanup/recovery in a fresh fixture.
3. After those controls, separate owner workload lifetime from terminal attachment.
   Android supervision stays authoritative; Console becomes a client and tmux an
   optional presentation tool. Keep may remain a convenience shortcut rather than
   the only form of retained work.
4. Define and qualify the resulting foreground/detached-work policies before changing
   ordinary defaults. Separation alone does not enable automatic retention or restart.

This direction is owner-approved. The current Console-bound/plain and tmux-backed
Keep implementation remains unchanged until that follow-up is implemented and tested.
Other proposed long-term improvements are not blanket authorization to redesign it.

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
