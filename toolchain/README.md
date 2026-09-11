# Experimental native compiler inputs

See the [milestone](../plans/2026-09-11-native-compiler.md) for current results and
boundaries. Native C and C++ with a project-private runtime are demonstrated in the
emulator. **Default C++ runtime lookup is not complete**; this is not a supported
release or a full compiler-feature/resource qualification.

`native-compiler.json` pins the compiler source and release-selected bootstrap.
`AndroidBionic.cmake` prevents accidental GNU/Linux header/library use and names the
Android NDK C++ dependency explicitly. This first SDK profile targets dynamic
AArch64/API37 executables; it does not claim static Bionic linking or other CPUs.

## Procedure

1. With the normal GrapheneOS-derived ARM64/API37 lunch configuration, build `ndk`.
   Keep its log, source/build context and status. The pre-existing base sysroot may
   lack executable CRTs. Do not change release or disable LTO to avoid diagnosing
   an incomplete SDK.
2. Freeze a **new external** SDK directory:

   ```sh
   python3 -B scripts/proof/compiler_sdk.py --source-root "$ANDROID" --output "$SDK"
   sha256sum "$SDK/manifest.json"
   ```

   Preserve the manifest digest as a separate input receipt. The freezer verifies
   source pins and includes both common libc++ headers and the Android NDK target
   configuration. It explicitly excludes the common directory's **host** config
   symlink; no host `__1` ABI is substituted for Android's `__ndk1`.
3. Select and hash a compatible native Ninja input. The platform's 1.9 build tool
   rejected this CMake graph's multiple-output depfile rule. A separately frozen
   existing Ninja 1.12.1 input supports the graph; no generated Ninja-rule or
   diagnostic suppression was used to make the older tool accept it.
4. Run the build steps under the host's exclusive heavy-work lease, with a new
   evidence directory per attempt:

   ```sh
   python3 -B scripts/proof/native_compiler.py \
     --source-root "$ANDROID" --sdk "$SDK" --sdk-manifest-sha256 "$SDK_SHA256" \
     --ninja "$NINJA" --ninja-sha256 "$NINJA_SHA256" \
     --build-root "$BUILD" --evidence-dir "$EVIDENCE/host-tools-01" --stage host-tools
   ```

   Then use `--stage native-configure` and a fresh evidence directory. Inspect
   `CMakeCache.txt`, `compile_commands.json`, feature checks and linker rules before
   `--stage native-build`. Configuration success does not prove every requested
   flag was applied. The first reviewed graph had 3,496 compile commands, each with
   the AArch64/API37 target and declared compiler hardening. Host TableGen tools
   remain separate from the Android payload.
5. Freeze and inspect the native outputs, SDK/header/runtime closure and their
   licenses before packaging. Verify AArch64, Android linker, dynamic dependencies,
   alignment and actual default include/library paths. No runtime or package PASS
   follows merely from `PASS_BUILD_STEP_ONLY`.

## Opt-in APEX package candidate

`package-inputs.json` pins the already frozen native, SDK and resource manifests.
`compiler_package.py` verifies every selected file, stages the payload atomically,
and checks its public metadata against those inputs. It parses the same manifest
bytes whose digest is verified. `--generate` is an explicit source-metadata update,
not permission to accept changed manifest pins or silently rehash foreign inputs.

```sh
python3 -B scripts/proof/compiler_package.py --inputs "$FROZEN_COMPILER_INPUTS" \
  --stage "$ANDROID/vendor/andrix/toolchain/artifacts"
```

The generated Blueprint groups data by directory so APEX packaging preserves the
SDK layout rather than flattening per-file destination paths. The large binaries
and headers remain outside Git; their pinned hashes, metadata and upstream notices
are public. Preserve the notice bytes, including upstream whitespace. Individual
source/header notices and LLVM's exceptions govern the mixed upstream inputs.

`ANDRIX_OWNER_COMPILER=true` requires `ANDRIX_OWNER_SESSION=true` on the GrapheneOS
Cuttlefish product. The compiler option supplies APEX version2; unflagged builds
keep version1 and disabled compiler modules. Real Soong behavior must still be
checked; source assertions alone are not a baseline or package PASS.

`clang` is the native binary. `clang++` is a small native argument-forwarding wrapper
that executes it in C++ driver mode with the immutable NDK config. The same small
native dispatcher supplies `cc`, `ar` and ranlib aliases, preserving the archive
mode selected by `argv[0]`. It preserves argument boundaries and changes no UID,
environment or sandbox. This is not an APK
launcher or a privilege transition. The first shell-wrapper dependency triggered
a Soong APEX static-executable-check panic; the failed build is retained rather
than patching or disabling that platform check. Prebuilt-binary symlink properties
were also absent from the extracted APEX, so aliases are attached to the compiled
dispatcher and verified in the payload instead of assumed from Blueprint text. The config uses explicit target/common C++
headers and link-only NDK runtime options, retaining `/usr/lib64` as the trusted
runtime path. Compile-only mode must not add libraries. The owner policy explicitly
allows reading Andrix-labelled SDK/configuration files and mapping its immutable
runtime library; it adds no writes, app-data access or Binder authority. No owner
limit changes, global platform-policy relaxation or fabricated libc++ linker
scripts are needed.

## Observed C++ runtime boundary

The current config's global `/usr/lib64` RUNPATH did not let a home executable load
`libc++_shared.so`: Android assigns `/data` executables to an isolated system linker
namespace without `/usr` in its permitted paths. Compilation succeeded, execution
failed. Do not open that namespace globally or copy libraries into Android's system
directories to hide the failure.

An explicit owner-managed project-private runtime worked:

```sh
mkdir -p lib
cp /usr/lib64/libc++_shared.so lib/
clang++ hello.cpp -Wl,-rpath,'$ORIGIN/lib' -o hello_cpp
./hello_cpp
```

The actual copied runtime hash matched the authenticated input, and this program
compiled/ran again after reboot. This is a bounded direct owner-package operation,
not an implemented package manager, automatic runtime provisioning or a guarantee
that every project layout works. Refining those defaults is the next step.

## Retained limits

Clang/LLD source is 23.0.0git; the bootstrap and selected NDK C++ runtime are 22.0.1.
Those are different roles and versions. The initial compiler build uses ThinLTO
and **indirect-call CFI**, not all CFI modes. Compiler implementation flags such as
LLVM's default `-fno-exceptions`/`-fno-rtti` are not restrictions on the language
features the resulting compiler can produce for owner programs.

No automatic HTTP/debug-information fetcher or plugin dependency is needed in this
first profile. Zlib is explicitly resolved against the API37 target stub, not the
host. Package signatures, C++ default linkage, compiler runtime resources, observed Android
execution and resource-pressure behavior remain distinct qualification steps. The
bounded examples fit the current limits; wider pressure tests remain open.
