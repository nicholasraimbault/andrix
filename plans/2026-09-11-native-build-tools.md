# Native project build tools

**Status:** signed GNU source authenticated; a narrowly adapted ARM64/Bionic Make
cross-build and host regression suite passed. Packaging and Android Make execution
remain unqualified. No native debugger is adopted yet.

The compiler, multi-file fixture and cold-attachment correction are demonstrated.
The next useful step is an ordinary incremental build driver, instead of rewriting
small project build scripts. This does not replace Android's platform build system.

## Selection and scope

The pinned platform tree contains host `make` binaries, not a device Make source
project. Its ARM64 host Make needs `libc_musl.so`; it is not adopted into the one-Bionic
owner environment. The host package source manifest includes an older Ninja project,
but Ninja's parallel default would need particular care under the current 256 MiB
compiler budget. GNU Make's serial default fits the demonstrated workload without
changing limits or inventing a wrapper policy.

Select GNU Make 4.4.1 from the official GNU release archive. The detached signature
verified using GNU's HTTPS-published keyring: primary fingerprint
`6D4EEB02AD834703510B117680CB727A20C79BB2`, signing subkey
`B2508A90102F8AE3B12A0090DEACCAAEDB78137A` (Paul D. Smith). Archive SHA-256:
`dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3`.
This records the source/bootstrap trust route, not out-of-band maintainer identity.
Retain GPL terms, the complete corresponding source, build configuration and any
patches; no relicensing or anonymous prebuilt substitution.

Cross-build a native AArch64/API37 dynamic-Bionic tool with the pinned bootstrap 22
and existing verified SDK. Keep compiler hardening and actual ELF checks. The initial
profile excludes optional Guile, native-load extensions and NLS dependencies; ordinary
Makefiles/recipes, incremental dependencies and recursive builds remain in scope.
A Makefile executes owner-authorized code, not isolated untrusted package hooks.

The image already has `/bin -> /system/bin`, and the runner supplies a private TMPDIR.
A native build exposed the missing Bionic `confstr(_CS_PATH)` API in Make's spawn
fallback. A single source adaptation uses Bionic's `_PATH_DEFPATH`, matching its own
`execvp()` behavior when PATH is absent. It adds no global path or access. Configure
uses a real cross C++ compiler under the name `c++`, so Make saves the on-device
compiler name rather than a host command or unavailable `g++`.

Two earlier orchestration failures are retained: asking for only the top-level
binary missed the recursive `libgnu` build, and a driver named `build.sh` inside the
build directory collided with configure's legitimate generated bootstrap link. The
reproducible recipe keeps orchestration separate and uses the normal recursive target.
No compiler/hardening check was suppressed. Configure's working-fork cross guess is
not a target execution result. The host Make build passed 1424 tests in 132 categories,
with platform/disabled-feature categories marked N/A, not a full Android Make PASS.

## Qualification

- Authenticate and freeze source/configuration/build outputs separately; host build
  success is not Android execution. Record target ABI, dependencies and hardening.
- Integrate only into the existing explicit owner-compiler toolset, preserving the
  unflagged small baseline and authenticated read-only `/usr`. If image packaging
  changes, freeze/re-hash the new images and matching hosts before launch.
- Use native owner `make` on the multi-file fixture: first build, no-op rebuild,
  source/header-triggered rebuilds, failure propagation and recovery, recursive
  jobs using bounded parallelism, relocation and reboot persistence.
- Keep 256 MiB/32-task/128-FD/64 MiB-file limits, ordinary-app negatives and live positive
  controls. Do not claim resource exhaustion, package transactions or phone readiness.

## Debugger inventory, not adoption

The selected bootstrap includes an AArch64 `lldb-server`, while its LLDB frontend is
host-side; LLVM23 LLDB source also exists. None is yet qualified as a phone-native
same-owner debugger. Frontend/server provenance, runtime dependencies, local transport
and same-owner ptrace authority need their own observed checks. No root/shell identity
adoption, cross-app attach authority or debugging of the coordinator is authorized.
The read-only I25 assignment ended without usable findings; it supplies no review PASS.
Primary inspection found the prebuilt server to be an ARM64 static ET_EXEC with an
Android API30/r29 note, not the desired dynamic API37 frontend/server pair. An actual
compiled-policy query found no owner-to-owner ptrace allow, while shell/app self-ptrace
positive controls were present. No policy change was made. Debugger launch/ptrace,
its local transport and same-owner-only boundaries need separate qualification.

New raw evidence: `out/owner-build-tools/EVIDENCE`. Existing images/seals, Vanadium,
Pixel and accepted architecture remain unchanged unless a separately recorded scoped
implementation requires new owner-tool packaging.
