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

## Next gates

1. Define workload identity, lifetime policy and terminal presentation separately.
   Retain the demonstrated Android authority, freshness, resource, Stop and complete
   group cleanup boundaries. Choose the sound long term design, not the design that
   preserves the most prototype code.
2. Define the resulting foreground and detached work policies before implementing
   their externally visible behavior. Keep retention, restart, wake and locked UI
   access as distinct decisions. Separation alone enables none of them automatically.
3. Implement the separation and repeat the relevant host, artifact and runtime
   proofs before changing ordinary defaults.

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
