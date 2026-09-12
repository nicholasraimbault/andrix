# Experimental native compiler inputs

See the [compiler milestone](../plans/2026-09-11-native-compiler.md) for the prior
native C/project-private C++ result and the [C++ defaults follow-up](../plans/2026-09-11-cxx-defaults.md)
for current qualification. The standalone default and explicit shared profile now
pass bounded Android emulator checks, including relocation and return after reboot.
The default embeds the pinned NDK C++ runtime; the shared profile uses one private
runtime. [Native GNU Make](../plans/2026-09-11-native-build-tools.md) also passed
incremental project, failure-recovery and reboot checks in the subsequent APEX 4 image.
This is not a supported release or full compiler-feature/resource qualification.

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

`package-inputs.json` pins the already frozen native, SDK, resource and
[GNU Make](make/README.md) manifests. Assemble a new input directory containing the
unchanged `frozen-native-01`, `frozen-sdk-02`, `frozen-resources` directories and the
new `frozen-make-01`; do not append to an earlier sealed input set.
`compiler_package.py` verifies every selected file, stages the payload atomically,
and checks its public metadata against those inputs. It parses the same manifest
bytes whose digest is verified. `--generate` is an explicit source-metadata update,
not permission to accept changed manifest pins or silently rehash foreign inputs.

```sh
python3 -B scripts/proof/compiler_package.py --inputs "$FROZEN_TOOLCHAIN_INPUTS" \
  --stage "$ANDROID/vendor/andrix/toolchain/artifacts"
```

The generated Blueprint groups data by directory so APEX packaging preserves the
SDK layout rather than flattening per-file destination paths. The large binaries
and headers remain outside Git; their pinned hashes, metadata and upstream notices
are public. Preserve the notice bytes, including upstream whitespace. Individual
source/header notices and LLVM's exceptions govern the mixed upstream inputs.

`ANDRIX_OWNER_COMPILER=true` requires `ANDRIX_OWNER_SESSION=true` on the GrapheneOS
Cuttlefish product. The Make addition selects APEX version4; unflagged builds retain
version1 and disabled compiler/tool modules. Version3 supplied the demonstrated C++
defaults; version2 and its runtime lookup failure remain in the earlier milestone.
The [build-tools milestone](../plans/2026-09-11-native-build-tools.md) records the new
package's separate qualification. Real extracted-payload/runtime checks, not source
assertions alone, establish whether a new generation works. GNU Make has its own
GPL license metadata/notice, not the compiler payload's permissive-license aggregate.

`clang` is the native binary. `clang++` is a small native argument-forwarding wrapper
that executes it in C++ driver mode with the immutable NDK config. The same small
native dispatcher supplies `cc`, `ar` and ranlib aliases, preserving the archive
mode selected by `argv[0]`. It preserves argument boundaries and changes no UID,
environment or sandbox. This is not an APK
launcher or a privilege transition. The first shell-wrapper dependency triggered
a Soong APEX static-executable-check panic; the failed build is retained rather
than patching or disabling that platform check. Prebuilt-binary symlink properties
were also absent from the extracted APEX, so aliases are attached to the compiled
dispatcher and verified in the payload instead of assumed from Blueprint text.
The configs use explicit target/common C++ headers and link-only NDK runtime
inputs. The standalone default embeds libc++/libc++abi but keeps Bionic and the
Android linker dynamic. The shared aliases select one project-private shared STL.
Compile-only mode must not add libraries. The owner policy explicitly
allows reading Andrix-labelled SDK/configuration files and mapping its immutable
runtime library; it adds no writes, app-data access or Binder authority. No owner
limit changes, global platform-policy relaxation or fabricated libc++ linker
scripts are needed.

## C++ profiles and the observed runtime boundary

The earlier version2 config's global `/usr/lib64` RUNPATH did not let a home executable load
`libc++_shared.so`: Android assigns `/data` executables to an isolated system linker
namespace without `/usr` in its permitted paths. Compilation succeeded, execution
failed. Do not open that namespace globally or copy libraries into Android's system
directories to hide the failure.

The recorded version2 workaround copied the runtime into `lib/` and explicitly
added `$ORIGIN/lib`; it compiled/ran again after reboot. That observation does not
prove the new profiles before their own qualification.

For a standalone executable, the new default requires no runtime copy:

```sh
clang++ hello.cpp -o hello
./hello
```

Only the NDK C++ runtime is linked from static archives. This is **not** static
Bionic or a second libc. It avoids hidden project writes and global library-path
changes. Programs exchanging C++ objects/exceptions across multiple DSOs should
instead select the shared profile and one private runtime, for example:

```sh
mkdir -p lib
cp /usr/lib64/libc++_shared.so lib/
clang++-shared hello.cpp -o hello_cpp
./hello_cpp
```

`clang++-shared` and `c++-shared` select `cxx-shared.cfg`; their default RUNPATHs are
only `$ORIGIN` and `$ORIGIN/lib`, suitable for a private runtime beside a binary/DSO
or in its `lib/` subdirectory. This is an explicit runtime choice, not a package
manager or a promise that arbitrary layouts work. The standalone profile does not
promise interoperability between multiple copies of a static STL in different DSOs.

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
