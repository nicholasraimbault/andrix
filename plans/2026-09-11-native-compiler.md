# Native ARM64/Bionic compiler

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

## Evidence and limits

New evidence is selected by `out/owner-compiler/EVIDENCE`; all prior owner/terminal
sets remain sealed. I18 supplied useful read-only corroboration of `m ndk`, CRT
placement and NDK STL mappings. Primary source/artifact checks establish the claims
here; neither the completed first research note nor its partial follow-up is an
independent compiler build/runtime PASS.

No native compiler package, on-device build or release qualification exists yet.
Keep host cross-linking, native compiler construction, packaging, emulator execution,
resource stress and supported-phone assurance distinct.
