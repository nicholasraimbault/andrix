# Experimental native compiler inputs

See the [milestone](../plans/2026-09-11-native-compiler.md) for current results and
boundaries. These files describe a build candidate, not a delivered compiler or an
on-device compilation PASS.

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

## Retained limits

Clang/LLD source is 23.0.0git; the bootstrap and selected NDK C++ runtime are 22.0.1.
Those are different roles and versions. The initial compiler build uses ThinLTO
and **indirect-call CFI**, not all CFI modes. Compiler implementation flags such as
LLVM's default `-fno-exceptions`/`-fno-rtti` are not restrictions on the language
features the resulting compiler can produce for owner programs.

No automatic HTTP/debug-information fetcher or plugin dependency is needed in this
first profile. Zlib is explicitly resolved against the API37 target stub, not the
host. Package placement, C++ default linkage, compiler runtime resources, Android
execution and resource-pressure behavior remain distinct qualification steps.
