# Native same-owner debugger feasibility

**Status:** the native frontend, matching server and private library now build and
pass artifact checks with the intended API37/Bionic ABI and hardening. They are not
yet packaged or executed in Android. No tracing-policy change or debugger adoption
is claimed.

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

## Build result

Source/profile `7bdd94d` produced these separately frozen, stripped artifacts:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `bin/lldb` | 454,184 | `cbd0a9e9819b16437bc2276d29f596f22f3621e3ed60384dd6743fc418103480` |
| `bin/lldb-server` | 4,255,328 | `b681abad5d36d61b1bc4055976d50ca475fd954262bcd8b52b8da314a6252a3a` |
| `lib64/liblldb.so` | 93,186,568 | `88621483fa3716b79fa26edc899d71ccea6103fe503174b892cd5c88260848f4` |

The first native attempt ran for 1,758.417 seconds and failed at the frontend link:
public SB symbols had been hidden, and the partial library was not a usable debugger.
The corrected incremental build completed 606 steps in 551.520 seconds. Both attempts,
including the first library and symbol table, remain separately attributed.

The actual ELF gate checked AArch64/ELF64/DYN, Bionic interpreter for executables,
PIE for executables, RELRO/NOW/NX stack, 16 KiB LOAD alignment and the sole relative
RUNPATH `$ORIGIN/../lib64`. Dependencies are Bionic `libc`/`libdl`/`libm`/`libz`, the
same pinned `libc++_shared.so` used by the compiler, and `liblldb.so` for the frontend.
The library exports the designated SB API, not the private LLDB/LLVM/Clang namespaces.
CFI symbols corroborate the retained compilation flags; this does not prove every
cross-DSO runtime path. Generated Clang resource configuration points at the existing
authenticated resource layout rather than a host build directory.

All 4,352 configured C/C++ commands were checked for target/sysroot and hardening;
that is a configuration count, not a claim that every optional target was built.
The source copy matched all 169,625 tracked entries before the two explicit changes.
Host generators remain separate: rebuilt `llvm-tblgen` and `clang-tblgen` matched the
previous compiler-preparation hashes; the new `lldb-tblgen` is also a host tool.
CMake's relative-install-path normalization warnings remain recorded; no bulk install
or warning suppression was used as a packaging shortcut.

The final repository suite passed **312 tests in 137.992 seconds**, with no skips.
The two selected source projects, complete frozen SDK, all copied source entries
and the exact existing owner-policy bridge were rechecked. This is not a fresh
whole-platform audit. The six-file frozen debugger artifact/license manifest is
`c9861597076c2d5746fe4bce6e7a3a946626ccb0ce96447e2e44d08256d2eade`.
The complete evidence set is sealed across **185 regular files**, with every file
and the frozen manifest reverified; all owned jobs are stopped and no guest was
launched in this build window.

The bounded I25/I27 follow-ups did not deliver completed independent reviews. Useful
earlier delayed source observations were checked by the primary; none supplies a
runtime PASS. Source-inferred transport/CFI concerns remain runtime test requirements,
not reasons to turn off hardening.

**Next gate:** integrate the frozen trio and required notices without changing the
current owner tracing policy, then measure native startup and the real tracing-denial
baseline. Only subsequent observed need and same-owner/cross-identity controls can
justify a narrow tracing addition. The Android-client support warning still applies.

New evidence is selected by `out/owner-debugger/EVIDENCE`. Previous images, compiler
artifacts, seals, Vanadium, Pixel and accepted architecture remain untouched.
