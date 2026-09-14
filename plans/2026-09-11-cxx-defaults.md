# Standalone and project-private C++ runtimes

**Status:** standalone C++ defaults and the explicit project-private shared profile
passed bounded ARM64/Bionic emulator checks, including relocation and rebuilding.

## Design

Ordinary standalone `clang++` links the pinned private C++ runtime statically. That
is static **C++**, not static Bionic: Android's dynamic CRTs, system linker and libc
remain the platform ABI.

Shared-library/plugin projects use an explicit project-private runtime profile with
relative lookup. Do not widen Android's global linker namespace or copy a runtime
into every project merely to make standalone programs work.

The earlier global-runtime lookup failure remains a distinct technical result,
not a reason to weaken namespace boundaries. See [toolchain profiles](../toolchain/README.md)
and the [compiler milestone](2026-09-11-native-compiler.md).
