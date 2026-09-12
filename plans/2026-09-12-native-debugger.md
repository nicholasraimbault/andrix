# Native same-owner debugger feasibility

**Status:** native C and C++ debugging now passed bounded Android qualification:
launch, breakpoint hits, arguments, backtrace, step-over/out, variable values and
normal completion. Owner-specific PTYs and same-owner tracing passed positive and
cross-identity controls, plus paused-job return, relock, reboot and active-debugger
End cleanup. No capability, global procfs, generic devpts or linker-namespace grant
was added. This is not full LLDB-feature or supported-phone qualification.

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

Build-only evidence remains selected by `out/owner-debugger/EVIDENCE`; the separate
integration window below did not append to that seal.

## Unchanged-policy Android baseline

Package/image producer `1320801` adds the frozen trio and three licence files to the
existing explicit compiler toolset: **APEX 5, 3,646 files, 187 data directories**.
The old compiler/SDK/shared-STL/Make pins and payload rows are unchanged. New metadata
checks the debugger's source/profile/bootstrap/SDK/runtime identities and exact file
set; private dependency closure and licence bindings are explicit. I26's read-only
packaging review found no actionable defect, not an independent execution PASS.

With flags unset and staged inputs absent, the unflagged build passed in
516.756 seconds and reproduced the original small APEX byte-for-byte. The flagged
`droid hosttar` build passed in 780.194 seconds; both signatures, all pinned payload
bytes, aliases, the LLDB closure and factory terminal 6 without an `.idsig` sidecar
were verified. All 27 images and both matching host packages were frozen/rehashed
before launch. The compiled SELinux policy remained **byte-identical** to the previous
owner image. The full repository suite passed **313 tests in 143.054 seconds**, no skips.

A fresh offline ARM64 emulator then demonstrated, as native UID7500:

- Normal Setup/PIN/CE/core/Cuttlefish checks and factory console registration. First
  Attach worked after both boots, with no retry or input-transport failure in this
  window.
- `lldb --version` initialized the frontend and exited 0 with 23.0.0git. The matching
  server's version routine also exited 0. Interactive `version`, target creation and
  `quit` worked; this is not full line-editor or LLDB feature qualification.
- Five reviewed source/command files were imported through explicit owner-terminal
  input, not observer writes to home. The native compiler built the C target and
  child-tracing probe. The target ran normally with `uid=7500 value=42`.
- LLDB loaded its AArch64/DWARF metadata and found `add` at `debug.c:4:13`, file address
  `0x4740`. No breakpoint was hit: the inferior did not start under the debugger.
- Normal launch exited 1 with `DupDescriptor-open failed: Permission denied`. A matching
  AVC denied the new slave PTY labelled generic `devpts`; this did **not** establish a
  need for general access to other processes' terminals.
- The separate `target.disable-stdio=true` control got past that opening step and
  exited 1 with `ptrace failed: Permission denied`. The child probe likewise returned 2,
  errno 13, with UID/EUID7500, NNP1 and seccomp2. Matching owner-to-owner process-ptrace
  AVCs identified the MAC denial. ASLR disabling was explicitly false in both launch
  scripts; no global personality/Yama change or borrowed identity was used.
- Ordinary owner-negative/P5 probes passed and were removed, with actual native C
  positives before and after. Relock/PIN return preserved shell 5170 and
  `KEEP=lldb_baseline`. After reboot, normal unlock preceded owner availability;
  all source/binary hash checks persisted, the target still ran, and fresh shell 3485
  repeated successful LLDB startup and the same tracing denials.
- The highest sampled group peak was **147,529,728 bytes (140.6953125 MiB)**, with all
  sampled OOM-event counters 0 inside the unchanged 256 MiB limit. Worker capabilities
  remained 0 and NNP/seccomp stayed active. No leftover debugger/server child remained
  at the inspected idle points; End and controller/core/UI-loop/runner/capture/cleanup
  exit codes were 0. These are bounded observations, not exhaustion or total quota proof.

### Source-listing timestamp control

The fixture archive assigned epoch-zero modification times for determinism. An extra
source-listing test displayed no source lines; the named-function batch returned 1.
Source inspection found LLDB's `SourceManager` treating a zero `TimePoint` as missing.
The owner then observed the 1970 timestamp, touched only `debug.c` and checked the
unchanged contents hash. A fresh source-list command displayed the actual source and
returned 0. Original archive bytes and the failed attempt remain preserved. This is
an identified timestamp edge, not a source-read permission grant or blanket handling
of epoch-zero files. Future fixtures should distinguish content pinning from that
special timestamp.

The closed runtime retains **7,439 regular files**, 278,334 offline packets and no
reported drops/truncation. All 303 UI transport actions completed, but not every
native command succeeded—the expected denials and source-listing failure are explicit.
The complete set selected by `out/owner-debugger-image/EVIDENCE` is sealed across
**22,011 regular files**, with the runtime sub-seal reverified and symlinks excluded.
All owned work is stopped; earlier sealed sets, Vanadium, Pixel and accepted
architecture are unchanged.

## Owner-only tracing and PTY trial

The next candidate uses the stock `create_pty(andrix_owner)` macro. Newly allocated
owner slaves receive `andrix_owner_devpts`, with the normal unprivileged ioctl list
and TIOCSTI prohibition. This is not access to generic `devpts`. An explicit
neverallow keeps Android apps and the console APK from opening/using these slaves.
The existing inherited coordinator PTY remains separate.

Only `andrix_owner self:process ptrace` is added, with an explicit neverallow from
the owner to every other domain. This covers the whole single owner Unix domain,
not just a debugger's child. The coordinator shares UID7500 but has a different MAC
role; no capability, identity transition, worker-filter, global procfs, namespace or
resource-limit change is proposed. This scope implements the accepted owner tier,
not a boundary exemption for an Android app.

Qualification requires actual debugger launch/breakpoint hits/step/backtrace/variable
inspection and finite cleanup. The new optional ordinary-app fixture supplies a real
self-tracing positive and rejects owner/coordinator tracing and owner-PTY access;
a bounded ready interval permits reverse owner-to-app tests. External-PID probes use
non-stopping SEIZE inside a short-lived tracer, with no memory read or target-directed
signal; unexpected access is a failure and tracer exit detaches it. Target liveness,
identity, DAC/MAC, dumpability and kernel restrictions remain distinct. Missing PIDs
or helper failures are not negative-control passes.

The source-only I28 assessment found the intended boundaries in the inspected diff
and macro, but did not itself establish full policy compile or runtime behavior.
The following primary checks supply the separate bounded result.

## Observed owner-only debugging result

Policy/APK/image producer `947ba28` and fixture producer `acad906` retained the exact
APEX 5 bytes from the denial image—same LLVM/SDK/Make/LLDB/STL, aliases and notices.
The owner-only policy and optional test APK built in 600.058 seconds; the subsequent
`droid hosttar` image build passed in 258.045 seconds. Both APEX signatures and every
payload byte were rechecked, then 27 images and both matching host packages were
frozen/rehashed. The actual image's ODM policy matched the compiled review, with
no factory copy of the ordinary boundary APK and the unchanged factory terminal 6.

Compiled-policy queries found owner-to-owner ptrace only, no owner-to-coordinator/app
or app/console-to-owner/coordinator tracing, no selected capability grants, and the
owner-PTY transition and I/O rules. App/console/coordinator access to those PTYs was
absent; existing shell/app self-ptrace positives remained. The fixed platform bridge,
worker seccomp/NNP, native lease and resource limits were unchanged.

In a fresh offline ARM64 emulator, using normal Setup/PIN and native UID7500:

- The same-owner SEIZE control succeeded. A newly allocated slave had the actual
  `andrix_owner_devpts` label, passed bidirectional raw I/O, and rejected TIOCSTI with
  errno 13. The prior generic-devpts denial was not silenced with a generic grant.
- The C target launched as process 11054, stopped at `add` in `debug.c:6:15`, displayed
  arguments 19/23 and an actual backtrace, stepped to `sum=42`, stepped out with return
  value 42, and continued to `DEBUG_C uid=7500 value=42` and exit 0.
- Ordinary `clang++` built the C++ target without manual STL copying. Process 11694
  stopped at `add` in `debug.cpp:8:23`; LLDB inspected `Counter{value=19}` and amount 23,
  stepped to sum 42, stepped out with return 42 and continued to normal stdout/exit 0.
  Both script commands returned 0. ASLR disabling was explicitly false, with different
  mapped addresses in later runs; no global personality/Yama change was made.
- A separately installed, explicitly debuggable **ordinary test APK** (UID10145,
  `untrusted_app`) successfully seized its own fresh child. It could not seize the
  live owner PTY holder or coordinator (errno 1), or read-open the owner PTY (errno 13).
  No shared UID, declared permission, root or adopted shell authority was used.
- While that instrumentation remained alive in its bounded ready interval, the
  owner self-SEIZE positive succeeded but owner attempts against the app returned
  errno 1. The same-UID coordinator returned errno 13 with a matching
  `andrix_owner → andrixd` ptrace AVC. Live identities, held PTY, continued app
  instrumentation and owner positives supply the controls; different-UID DAC
  rejection is not relabelled as sole MAC proof. The fixture was removed normally.
- Ordinary owner-negative/P5 probes also passed and were removed, with real C/C++
  positives. PM implicit permission metadata remains separate from actual grants.
- An interactive C++ inferior (13768), server 13765 and frontend 13621 survived Home/
  return and normal relock/PIN unlock. The same stopped inferior stepped and still
  reported sum 42. Kernel observations showed a tracing stop and the actual tracer
  PID, all owner UIDs, empty capabilities and NNP/seccomp still active. End removed
  the complete traced workload, not just the UI; the coordinator returned idle.
- Reboot ended the old jobs. Before normal PIN unlock, CE/owner availability was
  absent; first Attach worked afterward without retry. Seven source and three binary
  hashes persisted. A fresh same-owner SEIZE positive and full C++ debugger script
  passed again (inferior 3934, sum 42, return/exit 0), while tracing the new same-UID
  coordinator was still denied. Final End and guest/core/controller/capture cleanup
  all completed normally.

The highest sampled owner-group peak was **220,553,216 bytes (210.3359375 MiB)** with
sampled OOM/max-event counters 0 inside the unchanged 256 MiB/32-task/128-FD/64 MiB-file
bounds. All 494 UI transport actions completed, with no input timeout or Attach retry.
This does not qualify pressure, total CPU/storage quotas or arbitrary workloads.

The final repository suite passed **318 tests in 145.626 seconds**, with no skips.
Eight selected source projects, unchanged pinned toolchain/stage, the existing private
platform bridge and the compiled owner-only policy were rechecked. The closed runtime
retains **11,240 regular files** and 382,470 offline packets with zero reported drops
or truncation. The complete new evidence set is sealed across **18,535 regular files**,
with its runtime sub-seal reverified and symlinks excluded. All owned work is stopped;
no fresh whole-manifest, connected privacy or supported-phone pass is implied.

### Retained limitations and attempts

- Optional LZMA support remains disabled. LLDB emitted warnings that some Android
  system-library `.gnu_debugdata` could not be read. This did not prevent the tested
  owner C/C++ debugging, but full system-library symbolication is not claimed.
- The new fixture uses a nonzero deterministic file timestamp. The earlier epoch-zero
  source-listing failure/control remains recorded, not fixed or erased.
- The first host PTY helper assertion expected EPERM/EACCES but this host returned
  EIO for TIOCSTI. The corrected helper records EIO as rejection without attributing
  it to MAC. Android's measured rejection was errno 13.
- The private APK assessment initially expected an older apksigner output prefix.
  The retained valid v3/one-signer output was parsed correctly without weakening
  signature checks. This was a fresh ordinary APK install, not a v4 update claim.
- The first closure assessment expected textual process contexts without the kernel's
  trailing NUL byte. Exact SID-plus-NUL checks corrected the assessment; original
  observations and failure remain, with no policy or runtime change.
- A writer produced only the shared helper source/header, without completed tests or
  a commit. The primary inspected and explicitly integrated those files, added the
  tests and verified behavior; no independent implementation/review PASS is implied.
- Console-process-death cleanup with a traced inferior was not repeated in this
  window. Active-debugger End was measured; previous controller-death results remain
  separate. JIT expressions, scripting, broad attach/dumpability/Yama combinations,
  full terminal compatibility and phone/release/privacy qualification remain open.

The new evidence set is selected by `out/owner-debugger-policy/EVIDENCE`; earlier
seals and the denied baseline remain untouched. The upstream Android-client support
warning still describes upstream support, despite this bounded downstream result.
