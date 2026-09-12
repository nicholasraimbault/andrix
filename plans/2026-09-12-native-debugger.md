# Native same-owner debugger feasibility

**Status:** the patched native configuration includes Android host support; host
TableGen tools and the bounded child-probe's host controls passed. The first native build reached the frontend link and failed on hidden public SB
API symbols; a narrow Android API-export annotation is being tested next. No debugger
or new tracing authority is adopted or Android-qualified yet.

The maintained LLVM23 source explicitly warns that only `lldb-server` is functional
on Android and that its client is unsupported. Native Android host/local-server
paths nevertheless exist. This warrants a bounded experiment, not an assumption of
a working frontend. The selected bootstrap22 host frontend and static API30 server
are separate artifacts and are not substitutes for a phone-native debugger.

## Build approach

Use a new source copy and build directory from the pinned LLVM23 revision, keeping
the GrapheneOS checkout and qualified compiler build/profile untouched. Retain the
explicit AArch64/API37 Bionic sysroot, matching NDK libc++ and compiler hardening.
Select LLDB's Android host implementation using the `ANDROID` variable supplied by
the existing LLVM-style toolchain: its CMake host-selection condition currently
checks only the system-name string, while the compiler's `__ANDROID__` macro selects
Android headers. The isolated one-condition source adaptation makes these agree.

This deliberately avoids pretending the generated SDK is an NDK release, changing
the target to an old API, or copying CMake's outdated suggestion to allow undefined
symbols. The LLDB-specific profile rejects unresolved symbols for both frontend and
shared libraries. Actual compilation commands must include `HostInfoAndroid.cpp`
and the intended target/sysroot/hardening before a build result is accepted.

The first link failure exposed another concrete mismatch: `LLDB_API` is empty on
non-Windows targets, so the hidden-by-default build did not export the designated
public SB API. The next adaptation explicitly exports those existing API classes
on Android, rather than making all internal symbols visible or removing CFI.
Separate configuration aligns Clang resources with the existing authenticated
`/usr/etc/andrix/clang/23` and uses Android's unversioned-SONAME convention. The failed
library, symbol table, command graph and logs are retained.

Start with the CLI frontend and matching `lldb-server`, without optional Python,
Lua, libedit/curses, XML/LZMA, protocol-server or HTTP helpers. This is not a promise
of all LLDB features. Host TableGen/Python generation tools stay separate from the
Android payload. ELF identities, hardening, dependency closure and runtime behavior
must be checked independently; failures remain recorded rather than weakening checks.

## Runtime boundary, if build feasibility succeeds

The existing compiled policy has no owner-to-owner ptrace allow. First distinguish
that expected denial from debugger/tool/ABI problems with a bounded real same-owner
probe and live controls. No root/shell identity adoption, `CAP_SYS_PTRACE`, coordinator
or ordinary-app tracing is allowed. Any subsequently justified policy addition must
be Andrix-owned, owner-to-owner only and checked against cross-identity negatives.
No general procfs, linker namespace or hidden-API opening is part of this task.

Keep ASLR and current worker/resource restrictions. Basic launch/breakpoint/step/
backtrace/variable inspection comes before optional expression-JIT or scripting
features. Use actual native owner execution through the console, normal CE/PIN
lifecycle, and private local inherited-FD transport—not a public debug listener or
host-only session labelled as phone-native debugging.

The first milestone is a supportable, bounded path or a clearly retained blocker.
Packaging, Android runtime tests and any later authority change are separate gates.
The [child-tracing probe](../tests/owner-debugger/README.md) takes no PID argument
and targets only its own fresh child. Three host tests passed, including genuine
ptrace read/write/continue under the existing worker filter and a separate
ptrace-denying seccomp control. These do not prove Android SELinux behavior.

New evidence is selected by `out/owner-debugger/EVIDENCE`. Previous images, compiler
artifacts, seals, Vanadium, Pixel and accepted architecture remain untouched.
