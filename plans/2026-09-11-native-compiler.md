# Native ARM64/Bionic compiler

**Status:** this records the version 2 native C/project-private C++ demonstration,
including return after relock and recompilation after reboot. Its global C++ runtime
lookup failed under Android's isolated linker namespace, and that failure remains
recorded. The [new standalone/shared defaults](2026-09-11-cxx-defaults.md) now pass
their own bounded Android checks without widening namespaces. The compiler remains
in authenticated read-only `/usr`.

## Scope

Extend the [terminal/editor foundation](2026-09-10-owner-tools.md) with a compiler
that **runs as the native owner on Android**, not merely a host cross-compiler.
The first proof is edit C/C++ → compile/link → execute → return after relock/reboot.
GrapheneOS, the Android linker/Bionic ABI, owner UID/SELinux boundary and authenticated
read-only `/usr` remain the foundation. No Pixel deployment or second libc/OS.

Use the already pinned full `external/opencl/llvm-project` source
`37c265b53612ef8085c15455d10ec718590bba00` (23.0.0git) for an experimental Clang/LLD
build. This is not a stable-release/support claim inferred from its stale CPE label.
The build host uses the release-selected `clang-r584948b`/22.0.1 and matching
Android NDK C++ runtime inputs. Record compiler source, bootstrap compiler, SDK,
C++ library and final package versions independently.

## Input reality and first controls

The generated sysroot initially supported shared-library builds but lacked
`crtbegin_dynamic.o` and `crtend_android.o`. A real host cross-link failed on
those missing files. The ordinary **`m ndk` on the current cur/API37 ARM64 product**
completed that Bionic portion. Do not use the all-architecture helper's different
release, missing-dependency or global LTO overrides merely for convenience.

That target does not supply a complete C++ SDK. Use the matching bootstrap's
common libc++ headers **and** Android NDK target configuration (`__ndk1`, hardening
mode2), its `libc++_shared.so` and `libunwind.a`. The target-specific include directory
alone contains configuration, not `iostream`; the initial missing-header failure
is retained. Explicit `-nostdlib++` plus the NDK library mapping avoids accidentally
linking the host or platform C++ ABI. Do not assume absent `libc++.so` linker scripts
exist. Static Bionic CRTs are current-only and must not be relabelled as `/37`.

A small C++ exception/filesystem/function-pointer program cross-linked successfully
with the completed inputs and the proposed hardening flags. Its ELF is AArch64,
uses `/system/bin/linker64` and needs the Android NDK C++ shared runtime plus Bionic
libraries. This is **not yet execution on Android or on-device compilation**.

## Build sequence

1. Verify source project pins/cleanliness with the existing callback-disabled Git
   profile. Freeze the selected generated API37 SDK and matching C++ files with
   per-file digests and licensing material. Generated OUT is not a release input.
2. Build matching **host-only TableGen tools** from the same LLVM source. They are
   build tools, not payload executables. Keep their host dependencies explicit.
3. Cross-build native Clang, LLD and archive tools for `aarch64-linux-android37`,
   initially with only the AArch64 code generator. Use out-of-tree build directories,
   eight compile jobs and bounded link concurrency under the shared heavy-work lease.
4. Retain PIE, RELRO/NOW, non-executable stack, stack protection, fortification,
   zero-initialized automatic variables, Android NDK libc++ hardening, 16 KiB ELF
   alignment, ThinLTO and the explicitly scoped `cfi-icall` build profile. This is
   not a blanket claim of all CFI modes or native Pixel hardening. If an input or
   configuration fails, retain the failure and diagnose it; do not disable security
   checks or hide unsupported features to manufacture success.
5. Disable optional HTTP/debuginfod and plugin functionality in this first compiler
   profile; no automatic network/update dependency is needed for local compilation.
   Optional documentation/benchmark/test build targets are separate from the payload;
   excluding them is not a claim that upstream's complete test suite passed.
6. Inspect the native ELF/runtime closure and package the toolchain/SDK into the
   authenticated `/usr` generation, with correct default paths and explicit C++
   linkage. Do not ship a directory of host binaries or promise arbitrary target
   architectures/static linking from this initial profile.
7. In the bounded owner emulator, compile valid and invalid C and C++, inspect and
   run the result, test header/library resolution and the ordinary-app negative
   boundary. Measure memory/process/file-size behavior before changing the prototype's
   256 MiB/32-task/64 MiB-file limits. A resource adjustment needs demonstrated need;
   compiler jobs must remain below phone-critical work.

The cross-CMake file uses Linux plus the Android target flag, as LLVM's existing
Android platform recipe does, but explicitly selects AArch64/API37 and prevents
host header/library discovery. It does not invent NDK release metadata or another
userspace ABI. Its C++ dependencies are explicit because Soong's NDK dependency
mapping is not a standalone SDK's driver configuration.

## Build and artifact result

The current-product NDK step passed in 76.018s. The frozen dynamic API37 SDK/C++
profile contains 3,348 regular files. The initial rejected common-header symlink
pointed to a **host** `__config_site`; the corrected freezer explicitly omits it
and supplies the separate Android target configuration first. Its manifest is
independently pinned and file bytes, extra files, symlinks and path escapes are
checked before a build.

The first host-generator configuration succeeded, but platform Ninja 1.9 rejected
a multiple-output depfile rule. That build remains FAIL. A copied, hashed existing
Ninja 1.12.1 host input from the preserved browser-build workspace supported the
same graph. No Vanadium source or installed component changed. The corrected
host-generator step passed in 90.738s; those executables are observed x86-64/GNU
libstdc++/glibc tools, not Android payloads.

The native configuration passed in 10.989s. All 3,496 recorded compile commands had
the explicit AArch64/API37 target and declared hardening flags. The native build
then passed **3,204 steps in 2,217.431s**, retaining ThinLTO and `cfi-icall`. Relative
resource-install-path CMake policy warnings remain recorded, not suppressed.

Frozen native artifacts:

| Tool | Stripped bytes | SHA-256 |
| --- | ---: | --- |
| Clang | 102,273,912 | `36cd2c9d173ca67643757fdcd39ba5184765fe681d51ff5378d730c05e38a559` |
| LLD | 55,666,088 | `86d0b8edbbec08205909549d6c754888ae36467b1154e5162b0a27837f65f793` |
| llvm-ar / ranlib | 9,011,176 | `02198cd0c19346931846df0bfb9bfec30912a4a9abca4e564841346e88ecaea0` |

Unstripped counterparts and strip commands are retained. All three pass the
AArch64, Bionic `/system/bin/linker64`, 16 KiB LOAD alignment, PIE, RELRO/NOW and
non-executable-stack checks. Their RUNPATH is `$ORIGIN/../lib64`, with dependencies
limited to `libc++_shared.so`, `libc.so`, `libm.so`, `libdl.so` and `libz.so`.
CFI-related symbols in unstripped outputs corroborate the flags; this is not a
runtime CFI attack test. The same ELF gate rejected a real host TableGen binary.

Clang's stripped size exceeds the prototype's 64 MiB per-file write limit. That is
an artifact-size observation, not a reason to raise owner authority or memory
limits: the planned authenticated read-only `/usr` deployment avoids copying this
system tool into the owner home. Runtime memory/process use remains unmeasured.

The generated Clang 23 resource headers and separately identified bootstrap 22
builtins/unwind archives are also frozen as **candidate packaging inputs**. They
are not silently relabelled as compiler-rt 23 or a complete sanitizer-runtime set;
compatibility/default-path qualification remains required. C++ default library
wiring and the immutable SDK/APEX layout still need implementation and testing.

## Compiler package and Android result

The opt-in package adds APEX version 2 with 3,634 pinned payload files grouped into
184 data directories. Compiler, SDK and library bytes are verified against the
frozen input manifests; all non-signature APK resources remain separately accounted
for. `ANDRIX_OWNER_COMPILER=true` requires the owner-session option. An unflagged
build with no compiler inputs staged passed and reproduced the original APEX bytes.
No platform Soong patch was applied: a shell-wrapper dependency caused a retained
APEX check panic, and prebuilt symlink properties did not reach the extracted
payload. A small native argument dispatcher now supplies the verified C++/cc/ar/
ranlib aliases without changing identity, environment or sandbox.

The package needs explicitly scoped read/map access to its immutable SDK and C++
library types. The first image boot also exposed missing `getattr/search` on that
library directory for the existing shell-side proof. Only those directory rights
were added beside the existing shell file-access rule. The original runtime stays
**FAIL**: 47 closed files and 33,904 offline packets; cleanup succeeded.

The next image passed core and normal setup but Package Manager rejected the
terminal's **factory** APK because a v4 update sidecar had been installed beside
it. Its attempt to measure per-file fs-verity failed; neither the ioctl policy nor
certificate check was bypassed. Factory APKs now omit that sidecar, and
`terminal_update.py` prepares a separately verified APK+v4 update pair outside the
image tree. It reproduced the exact pair previously accepted by normal installation.
That second runtime remains **FAIL**, despite zero cleanup exit codes: 1,360 closed
files and 72,532 offline packets. The failed terminal launch is retained.

Producer `fbcb4ad` built the corrected image, after normal `installclean` removed
obsolete installed outputs. The actual extracted image contained the factory APK
without `.idsig`. All 27 images and both matching host packages were frozen and
rehashed. The compiler APEX remained
`dfa99149d5a5b562e214dfe566ebe991208194d8a1bf3e73daad3cbedb6b4f40`, with both signatures,
version 2, exact payload files and native aliases verified. The terminal registered
normally as a privileged system_ext package. Vanadium and other upstream bundled
apps retained their image hashes.

### Bounded runtime observations

- **C:** `vi` created `hello.c`; its unsaved buffer survived Activity detach/Home/
  return with the same native shell and editor. `clang hello.c -o hello` succeeded,
  and the new executable printed `ANDRIX_C_OK`, returning 0 only for UID7500.
- **C++:** `clang++ hello.cpp -o hello_cpp` compiled successfully, but that executable
  could not find `libc++_shared.so` through `/usr/lib64`. Actual linker configuration
  places `/data` executables in the isolated system namespace, whose permitted paths
  exclude `/usr`. The failure remains a failure, not a complete default-toolchain PASS.
- A deliberate owner copy of the exact runtime into the project's `lib/` directory,
  followed by `-Wl,-rpath,'$ORIGIN/lib'`, worked. The program threw and caught
  `std::runtime_error`, used iostreams and printed `ANDRIX_CPP_OK uid=7500`.
  This exercises the accepted package-private-library model, not a namespace opening
  or an APK executing under another identity. Runtime provisioning/defaults still
  need a coherent packaged interface; no static-C++ default has been adopted here.
- Invalid C and C++ source returned 1 and left no output executable. `cc`, `ar` and
  `ranlib` compiled, archived, indexed, linked and ran a C executable successfully.
- Native Toybox `readelf` inspected the produced ELF64/ARM64 binaries, Android's
  `/system/bin/linker64`, dynamic dependencies and the private `$ORIGIN/lib` RUNPATH.
  The observer was not granted direct access to the owner home.
- The ordinary same-signer negative and P5 passed and were removed, with real owner
  program execution before and after the negative. Native UID/GID7500, zero capability
  masks, NNP/seccomp and the existing limits remained intact.
- Relock detached the UI; normal PIN return preserved shell 5300, the established
  `OWNER_KEEP` variable and working C/C++ programs. After a normal reboot, Android
  was `RUNNING_LOCKED` with no owner service/CE flag before PIN. Normal unlock restored
  the service; source, executables and private library hashes were unchanged, and
  both languages compiled and ran again under a new native shell 3620. End removed
  the prior native processes; all runtime cleanup statuses were 0.
- The highest sampled cgroup `memory.peak` was **186,712,064 bytes (178.0625 MiB)**,
  within the unchanged 256 MiB limit. Sampled max/OOM counters were 0. This is not a
  pressure, power-loss, total-CPU/storage-quota or supported-phone guarantee.
- Executing home binaries also logged denied linker path probes into shell/test
  directories. Those AVCs remain recorded; no access to those directories was
  granted merely to silence probes. Core passed before the workload and after reboot,
  not a blanket zero-AVC claim for every owner command.

Observed persistence hashes (native output, not host home reads):

| File | SHA-256 |
| --- | --- |
| `hello.c` (105 bytes) | `b13431da40db1749738137986cef35a2056f360109cb9646f8a0911bb8e716ac` |
| `hello.cpp` (248 bytes) | `dfb9a8b8745e1e92286631413922310acf0f132cac5d57286ad103de6c04ffd6` |
| `hello` | `bb2f2172f620b8334c62b5eb2bb54b4898dfd3f6b12759452744e71bf22911ce` |
| `hello_cpp_local` | `2bc0cc08d2df9f95246222e5a386e403714e2c60e747015768a1450ee820c36d` |
| private `libc++_shared.so` | `60382b9a9dd56064a27a5dc0fd12326f6e834e1bfae5df606ebc90fbe8455459` |

The third window retains 6,382 closed regular files and **235,949 offline packets**,
zero drops/truncated records. All three windows remain separate. The complete
package/integration set selected by `out/owner-compiler-package/EVIDENCE` is sealed
across **40,338 regular files**, with all three runtime sub-seals reverified and
symlinks excluded. All owned jobs and guests are stopped. These are bounded emulator
results, not phone, networking/privacy or full compiler-feature assurance.

## Evidence and limits

The earlier build-only set selected by `out/owner-compiler/EVIDENCE` is sealed across **5,745
regular files** (symlinks excluded), including frozen artifacts, SDK/resources,
source/configuration receipts, tests and retained failures. All prior owner/terminal
sets remain sealed. All owned build/check/hash jobs are stopped; no guest was
launched for this build step. I18 supplied useful read-only corroboration of `m ndk`, CRT
placement and NDK STL mappings. Primary source/artifact checks establish the claims
here; neither the completed first research note nor its partial follow-up is an
independent compiler build/runtime PASS.

That build-only checkpoint's repository host suite passed **282 tests in 130.380s**,
with no skips.
The compiler source, bootstrap-prebuilt and Bionic projects passed the existing
read-only source check again; frozen SDK hashes and the exact private owner-policy
bridge were rechecked. This is scoped input accounting, not a fresh all-1,108-
project source audit. The subsequent package/runtime step passed **292 host tests in
132.276s**, with no skips, and rechecked six relevant upstream projects, the exact
owner-policy bridge and pinned staged compiler bytes. It likewise does not claim a
fresh all-project audit. Keep host cross-linking, compiler construction, package
signatures, observed Android behavior and release assurance distinct.

**Next:** the [standalone C++ defaults follow-up](2026-09-11-cxx-defaults.md) records
the subsequent working default for ordinary executable builds and explicit
project-private shared-runtime profile. The observations above used the
previous default and are not retroactive qualification of that change. Also
account for the linker path probes without widening unrelated access, and expand
representative compiler/resource tests. Full managed package transactions, services
surviving console-process death, phone deployment and release/privacy gates remain
separate work.
