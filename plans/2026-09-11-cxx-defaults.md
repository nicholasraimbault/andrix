# Dependable standalone C++ defaults

**Status:** implementing and qualifying the next compiler package profile; no new
Android result is claimed yet. The earlier [C/private-runtime C++ demonstration](2026-09-11-native-compiler.md)
and its failed default-runtime lookup remain recorded.

## Goal and implementation choice

Make ordinary `clang++ hello.cpp -o hello && ./hello` work from an owner project
without a manual runtime copy or linker flag. Preserve Android's linker namespaces,
Bionic/system linker, native owner identity, immutable `/usr` and current bounds.

For **standalone executable builds**, the default C++ profile now links the pinned
Android NDK `libc++_static.a` and `libc++abi.a` into the output. This is static **C++**,
not static Bionic: API37 dynamic CRTs, `/system/bin/linker64`, libc/libm/libdl remain
Android's. It embeds the runtime in the owner-controlled program instead of creating
a writable global library directory or secretly copying files beside compiler outputs.
No alternate libc, platform namespace change or authority expansion is introduced.

Projects exchanging C++ objects/exceptions across shared-library boundaries should
use the explicit `clang++-shared` / `c++-shared` profile and **one** project-private
shared C++ runtime. Its only default RUNPATHs are literal `$ORIGIN` and `$ORIGIN/lib`,
not `/usr` or a host path. The owner supplies that runtime with the project. A shared
profile is not an automatic package manager or a claim that arbitrary DSO layouts
work. Multiple copies of a static C++ runtime across DSOs are not the default
profile's interoperability guarantee.

This is a compiler-package default within the existing owner-code/package model,
not a revision to the accepted Android/Bionic architecture. Shared linking remains
an explicit owner choice. Managed package generations, transactions and runtime
updates still need their own design/qualification.

## Inputs and safeguards

Reuse the already frozen, digest-bound Android NDK C++ archives from the selected
22.0.1 bootstrap, with the same `__ndk1` headers/configuration:

- `libc++_static.a`: 24,613,594 bytes,
  `b5503d3e2b52e541f73025feb6a16088290fd8091ac57ce568e02012f01a5251`.
- `libc++abi.a`: 4,930,052 bytes,
  `c0520f2e83ab27bd14c5079bc3b8629d07d234ef4b9f0bbf73647c51cfe7e865`.

The native Clang/LLD23 binaries and their own shared runtime remain unchanged.
No compiler security flag is removed. Default link-only archive groups do not
turn compile-only operations into links, and runtime symbols are hidden from
accidental export. Existing file hashes and license notices remain authoritative;
no static Bionic CRT is invented or moved into `/37`.

APEX version3 identifies this compiler payload; the unflagged baseline remains
version1. The factory console APK must still have **no** update-only `.idsig` beside
it. APK+v4 update pairs remain a separate, verified artifact path.

## Qualification

- Real host cross-links against the staged API37 SDK: exceptions, iostreams,
  vectors and nonconstant math; default output must remain AArch64/dynamic Bionic,
  with no `libc++_shared.so` dependency or project RUNPATH. Shared mode must retain
  the explicit shared runtime and only relative RUNPATHs. Host checks are not
  Android execution proof.
- Dispatcher forwarding tests for ordinary/default/shared/cc/archive modes; input
  integrity and generated package checks; actual APEX signatures, payload hashes,
  aliases and factory APK layout.
- Native owner emulator: ordinary C++ invocation without project `lib/`, nested
  output and relocation, exceptions/RTTI/threads, invalid source, C/archive
  regressions and explicit shared-DSO C++ interoperability with one private runtime.
- Observe output ELF dependencies and resource use; preserve limits unless a
  measured need justifies changing them. Repeat ordinary-app isolation, normal
  relock/unlock, reboot/persistence and cleanup.

New evidence is selected by `out/owner-cxx-defaults/EVIDENCE`. Do not append to the
sealed 40,338-file compiler-package set or earlier source/build/runtime sets.
Denied linker probes into unrelated shell/test directories remain a separate
finding; no access is granted merely to silence them.
