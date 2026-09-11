# Dependable standalone C++ defaults

**Status:** the standalone default and explicit project-private shared profile passed
bounded ARM64 emulator checks. Ordinary `clang++` compiled and ran without a project
runtime copy; a shared-library/string/exception test also worked, including package
relocation. Both ran after reboot, and the standalone program rebuilt successfully.
The earlier [version 2 runtime lookup failure](2026-09-11-native-compiler.md) remains
recorded, not retroactively relabelled.

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

APEX version 3 identifies this compiler payload; the unflagged baseline remains
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

## Observed result

Source/image producer `a653644` passed `droid hosttar` in **667.177 seconds**. The
APEX version 3 payload has 3,637 pinned files grouped into 185 data directories;
both signatures, file digests and dispatcher aliases were checked. The actual
factory terminal APK remained unchanged and had no update-only v4 sidecar beside
it. All 27 images and both matching host packages were frozen/rehashed before boot.
No native Clang/LLD rebuild, platform-policy change or owner limit change was needed.

In the offline ARM64 emulator, with normal setup and a disposable PIN:

- `vi` created a 531-byte C++ source using iostreams, a vector, `std::thread`/join,
  `dynamic_cast` RTTI, and a thrown/caught `std::runtime_error`. Ordinary
  `clang++ hello.cpp -o hello` compiled and ran, reporting
  `DEFAULT_CPP_OK value=7 uid=7500`, with no project runtime directory.
- Native Toybox `readelf` showed ELF64/ARM64/DYN and `/system/bin/linker64`. Its only
  dynamic dependencies were Android's `libm.so`, `libdl.so` and `libc.so`: no shared
  C++ runtime or RUNPATH. The executable was 4,672,320 bytes.
- A separate build to `bin/nested`, moved to another directory, ran unchanged.
  The original and separately built/moved executable hashes matched. No library
  copying or extra linker flags were required by either standalone build.
- `clang++-shared` built a DSO and `c++-shared` built its client using one deliberately
  supplied private runtime. Returning a `std::string` and throwing an exception
  across the DSO boundary worked. The whole relocated package still ran; its
  RUNPATH was only `$ORIGIN:$ORIGIN/lib`. Removing the private runtime made execution
  fail; restoring it made the same program run again.
- C compilation and `ar`/`ranlib` regression checks passed. Invalid C++ was rejected
  with no output executable. The same-signer ordinary owner-negative and P5 passed
  with live program positive controls before/after, and both probes were removed.
- Relock detached the UI; normal PIN return preserved shell 5143 and the established
  `KEEP=cxx_ready` variable. After reboot, the user was locked with no owner service
  or CE flag until normal PIN unlock. Both standalone/shared programs then ran,
  the standalone source/executable hashes were unchanged, and ordinary `clang++`
  rebuilt and ran the standalone program again under a new shell 3591.
- UID/GID7500, zero capabilities, NNP/seccomp and existing bounds remained intact.
  The highest sampled group `memory.peak` was **212,590,592 bytes (202.7421875 MiB)**
  within the unchanged 256 MiB limit; sampled OOM-event counters were 0. End removed
  the prior native processes; all core/UI/controller/runner/capture/cleanup exit
  codes were 0. This is not a general resource-pressure or quota guarantee.

The standalone source SHA-256 is
`5395f35c4d973938c4c79c176505b5c09462988dfd0430cb07aaa23fb71786a0`;
the original/moved executable is
`68c04b5667d2129e1c891bd84b008877ee63b42443f1d64e38bca6b9342dd182`.
These were observed through native owner commands and the real terminal display,
not by giving the observer access to the owner home.

The test fixture also exposed input timing problems: an early command was incomplete,
a host batch wait expired just before all actions completed, and two long `adb input
text` commands exceeded their 45-second deadlines. Later queued text interleaved and
an initial nested-output attempt failed. Those failures and the initial assessment's
incorrect one-timeout count are retained. After normal Ctrl-C recovery, short input
chunks and a sequential fail-stop host queue, the intended checks completed. The
queue no longer submits follow-on actions after an earlier failure. No mounted guest
script, keyboard/security setting or compiler check was changed to force success.
Startup/input timing remains separate from the successful compiler result.

I20's read-only snapshot review identified stale tests and README text while the
primary was updating them. Both were corrected and the current tests rerun; that
review was not independent runtime qualification. The final repository suite passed
**292 tests in 132.585 seconds**, with no skips. Six relevant upstream projects,
the exact existing owner-policy bridge and pinned staged compiler inputs were
rechecked; no fresh whole-manifest audit is claimed. Nonconstant math was tested by
host cross-linking, not newly claimed as an Android runtime test in this window.

The closed runtime retains **8,171 regular files** and 297,916 offline packets,
zero reported drops and zero truncated records. The complete set selected by
`out/owner-cxx-defaults/EVIDENCE` is sealed across **22,681 regular files**, with the
runtime sub-seal reverified and symlinks excluded. All owned guests and jobs are
stopped. The prior 40,338-file package set and all earlier seals remain untouched. Denied linker probes into unrelated shell/test directories
remain recorded; no access is granted merely to silence them.

**Next:** broaden representative project-build, resource and shared-library testing,
and improve the observed startup/input timing. This result does not deliver a full
package manager, arbitrary static-STL multi-DSO interoperability, services surviving
console-process death, or phone/release/networking-privacy qualification.
