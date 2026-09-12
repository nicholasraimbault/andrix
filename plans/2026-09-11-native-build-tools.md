# Native project build tools

**Status:** native GNU Make is packaged in authenticated `/usr` and passed bounded
Android incremental-project checks, including rebuild selection, failure recovery,
recursive jobs and rebuilding after reboot. The compiler-disabled baseline remains
byte-identical. No native debugger is adopted yet.

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

## Packaged and observed result

Recipe producer `067cb66` built the final native artifact in **9.227 seconds** and
checked 34 actual C compilation commands. The 260,416-byte Make binary uses Android's
`/system/bin/linker64`, needs only `libc.so`/`libdl.so`, and passed ELF64/AArch64,
PIE/RELRO/NOW/NX-stack and 16 KiB alignment gates. ThinLTO/indirect-call CFI and the
recorded hardening flags remained in place. Its SHA-256 is
`653bce34fb476c68a3db9fca5d1229bce19d5c76718254328d14a8c9eb62df94`.

Package/image producer `ca6347c` adds Make and separate GPL/source-reference notices
to the existing explicit owner-compiler profile: **APEX version 4, 3,640 pinned files,
186 data directories**. The compiler/SDK/C++ runtime pins remain unchanged. With both
owner/compiler flags unset and staged inputs absent, the 539.713-second build
reproduced the original small APEX exactly
(`96a27a78175991582615743489602e9a94771042f5820181a38f14639769f6aa`).
The compiler-enabled `droid hosttar` build passed in **789.779 seconds**. Both APEX
signatures, every selected payload file and dispatcher alias were checked; the actual
factory terminal was version 6 with **no update-only `.idsig`**. All 27 images and both
matching host packages were frozen/rehashed before boot. No new policy/identity/limit
change accompanied the Make addition.

In a fresh offline ARM64 emulator, using normal Setup/PIN and native UID7500:

- `make --version` reported GNU Make 4.4.1 for AArch64 Android. Actual defaults were
  `CC=cc CXX=c++ AR=ar SHELL=/bin/sh`.
- The reviewed fixture was entered through the owner terminal, not written directly
  into home by the observer; all eight functional source hashes matched. Native
  Make compiled three translation units, made the archive, linked and ran the CLI.
- A repeated build reported nothing to do, `make -q` returned 0, and the recorded
  object/executable timestamps were unchanged.
- Editing the header in `vi` changed the program from `v1` to `v2` and caused all
  three affected objects to rebuild. Editing one `.cpp` file rebuilt only its object
  plus the dependent archive/executable; the other two object timestamps stayed fixed.
- A deliberate compile error propagated as Make exit 2. The last working executable's
  hash stayed unchanged; restoring the source rebuilt successfully. This fixture's
  temporary archive/link outputs are not a general package-transaction guarantee.
- Recursive `make -j2 --output-sync=target` completed both tiny shell jobs without a
  jobserver error. This did not run parallel C++ compilers or establish pressure safety.
  The child-PATH-unexported recipe ran `uname -m` and reported `aarch64`, exercising
  the Bionic default-search adaptation without a global path change.
- Moving the project into a directory containing a space retained no-op status and
  successful execution. The output remained ARM64/dynamic Bionic, with no shared-STL
  dependency or RUNPATH. The `v2` program hash was
  `b002184fbc111d9e609e814f405a0d99df01278a3519c0bbec4bacc88f5fab7c`.
- Ordinary owner-negative and P5 probes passed with real project positives before
  and after; both were removed. Relock/PIN return preserved shell 5282 and
  `KEEP=make_alive`. After reboot, normal unlock preceded owner availability; all
  source/executable hash checks and no-op status persisted, and shell 3620 performed
  a forced full rebuild and successful run from the relocated directory.
- The highest sampled owner-group peak was **235,216,896 bytes (224.3203125 MiB)**,
  with sampled OOM-event counters 0 within the unchanged 256 MiB limit. Capabilities
  remained 0 and NNP/seccomp remained active. End and all core/UI-loop/runner/capture/
  cleanup exit codes were 0. Total CPU/storage quotas and resource exhaustion remain
  separate work.

The final repository suite passed **309 tests in 146.333 seconds**, with no skips.
Eight relevant upstream projects, the exact existing owner-policy bridge and the
new pinned aggregate stage were rechecked; no fresh whole-manifest audit is claimed.
I26's read-only source review found no actionable regression, but did not independently
build, inspect frozen outputs or execute Android tests.

### Retained observer limitations

The first artifact-assessment helper expected JSON from a tool that prints protobuf
text; that assessment failure was retained and corrected without changing the signed
APEX. A 180-second host batch wait expired while its final snapshot was completing;
all 12 actions later completed. On return from relock, the first readiness wait still
saw Detached and withheld all queued input. An explicit Attach retry worked. The
retained trace showed the expected lock revocation but did not establish a new
Make or cold-lease defect. These observations are not an all-actions-PASS claim.

The closed runtime retains **7,804 regular files** and 282,458 offline packets with
zero reported drops/truncation. The complete set selected by
`out/owner-build-tools/EVIDENCE` is sealed across **24,131 regular files**, with its
runtime sub-seal reverified and symlinks excluded. All owned guests/jobs are stopped;
earlier sealed sets remain untouched. Denied linker probes into unrelated shell/test
directories remain recorded, not silenced by grants.
The initial orchestration/build failures above and a later seal-launch quoting error
are retained separately from the successful Android result.

**Next:** prepare and qualify a native same-owner debugger with explicit ptrace and
cross-identity negative controls, rather than adopting the host frontend/static server
as a phone solution. Broader projects, resource pressure, package transactions and
phone/release/privacy qualification remain open. Vanadium, Pixel and accepted
architecture remain unchanged.
