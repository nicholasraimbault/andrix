# Native same-owner debugging

**Status:** LLDB and its server are packaged in authenticated `/usr`. Bounded C/C++
breakpoint, stepping, backtrace, variable inspection and completion checks passed in
the emulator, alongside same-owner and cross-identity controls.

## Build approach

Use the pinned LLVM/Android source profile, explicit supported platform selection and
private dependencies. Preserve CFI/ThinLTO, strict symbol visibility and Android's
Bionic/system-linker ABI. The client remains a bounded downstream integration, not a
claim of complete upstream Android client support.

## Unchanged-policy Android baseline

The initial unchanged-policy trial established a real launch denial. Missing targets,
helper failure or unrelated permission errors are not equivalent controls. That result
motivated only the narrowly scoped same-owner tracing/owned-PTY rules.

## Observed owner-only debugging result

The owner can debug their own programs without adding capabilities, general procfs
access or cross-domain tracing. Tests retained ASLR and exercised both C and C++
state, terminal return and cleanup. Ordinary applications and the same-UID coordinator
remained separate negative controls.

## Limits

Optional JIT, scripting, compression/library combinations, all expression paths,
broad pressure/suspend and supported-phone behavior are not qualified by these tests.
See [LLDB build and provenance](../toolchain/lldb/README.md),
[debugger fixtures](../tests/owner-debugger/README.md) and
[boundary probes](../tests/owner-debug-boundary/README.md).
