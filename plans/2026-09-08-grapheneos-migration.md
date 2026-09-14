# GrapheneOS-derived foundation

## Accepted decision

Andrix uses GrapheneOS's maintained Android foundation with a small, attributable
owner-computing layer. Android retains ARM64/Bionic, init, ART, Binder, SELinux,
PackageManager, profiles, verified boot and phone services. An independent glibc or
Wayland environment is not adopted by this milestone.

The initial reproducible migration anchor is GrapheneOS `2026081300`, based on
`android-17.0.0_r1`. It is not an indefinite update policy. Earlier direct-AOSP
experiments retain their own provenance and are not silently treated as patches to
this foundation.

## Source and integration gates

Authenticate the release manifest and complete project graph, then verify actual
checkout contents with callbacks/filters and undeclared modifications excluded.
Keep the Andrix overlay, framework adaptations and product/policy inputs attributable.
Build matching images and host tools before a fresh runtime qualification.

## Result

The source graph was verified and the ARM64 emulator foundation built and booted.
Subsequent milestones exercised [offline boundaries](2026-09-08-grapheneos-first-boot.md),
[connected Android services](2026-09-09-grapheneos-connected-baseline.md), and the
[owner environment](2026-09-10-owner-session.md).

This does not establish Pixel deployment, production signing, proprietary-input
rights, complete privacy or hardware behavior. See [architecture](../docs/architecture.md),
[source provenance](../docs/source-provenance.md), [source-verifier instructions](../scripts/proof/grapheneos_source.md)
and the [reviewed integration patches](../patches/grapheneos-2026081300/README.md).
