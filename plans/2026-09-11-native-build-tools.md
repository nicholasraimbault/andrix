# Native Make and project builds

**Status:** GNU Make is packaged in authenticated `/usr` and passed bounded Android
incremental, no-op, recursive, relocation and failed-build recovery checks.

## Selection and constraints

Use the pinned Bionic-compatible source/build profile, not a host binary requiring a
different libc. Keep serial operation as the default under the owner resource budget;
optional Guile, loadable modules and NLS are disabled in this package.

Preserve source, patch, license and configuration obligations. Packaging a build tool
does not add a native package manager or change Android's platform build system.

See [Make source/build instructions](../toolchain/make/README.md),
[project fixture](../tests/owner-project/README.md) and the later
[debugger milestone](2026-09-12-native-debugger.md).
