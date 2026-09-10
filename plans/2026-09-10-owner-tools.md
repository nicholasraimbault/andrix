# Usable owner terminal and programming tools

## Goal and scope

Continue from the [demonstrated owner session](2026-09-10-owner-session.md) toward
**unlock → terminal → edit → compile/run → leave → return**. Keep GrapheneOS's
Android/Bionic foundation, authority checks, encrypted home and authenticated
read-only `/usr`. Vanadium and phone services remain unchanged. This work does not
authorize Pixel deployment, new signing roots or a second userspace ABI.

Deliver incrementally:

1. A real native Android terminal view, with VT screen state, resizing, UTF-8,
   keyboard/IME input and explicit control keys. Reuse an existing terminal engine
   and renderer rather than build another escape-sequence parser.
2. A reliable, bounded stream across detach/reattach. The first prototype consumes
   bytes when sent to a socket, not when the UI has parsed them; closing that socket
   can lose unconsumed bytes. This was acceptable only as an explicitly incomplete
   line-oriented output tail, not silent screen corruption in a full-screen editor.
3. Use the existing Android Toybox `vi` for the first edit/save exercise. It is
   enabled by `external/toybox/config-device` and present in the frozen image;
   no editor replacement or extra platform patch is needed merely to try it.
4. Add a supportable on-device ARM64/Bionic compiler and API37 sysroot in a separate
   attributable toolchain step. Building an executable on the host is not proof of
   on-device compilation. Preserve hardening and qualify its resource requirements.

A full terminal/editor demonstration may precede the compiler. Do not label the
complete programming workflow delivered until compilation actually runs as the
native owner. Long-lived jobs beyond console-process reclamation remain separate.

## Terminal source candidate

Inspect the reusable `terminal-emulator` and `terminal-view` libraries at
`termux/termux-app` commit `3b66f8799635a4dba4a206563048ff0e6792c487` (tree
`41ecedc1b870ccf8e471088e6cff77b926823ef9`). The repository's license statement
identifies the Apache-2.0 terminal-library exception to its GPLv3 app license.
Retain upstream licensing/provenance and validate each selected Git blob. Do not
import Termux's APK, command services, package environment or JNI process launcher.
Its Gradle JNI flags are not our native build flags.

Adapt the session boundary to Andrix's authenticated Binder/mediated stream. The
actual PTY master and subprocess creation remain native coordinator responsibilities;
the console does not execute programs under an APK identity. A terminal's escape
sequences must not silently access Android clipboard or launch external intents.
Explicit user copy/paste is distinct from an automatic OSC clipboard request.

The terminal screen/parser state belongs to the existing console process lifetime,
not an Activity instance. Preserve that state on Activity detach/recreation when
the process survives. Controller process death still ends the native session.

## Stream continuity

Use session identity plus monotonically increasing output offsets. Retain output
until acknowledged after parsing, replay unacknowledged bytes on a replacement
attachment, and discard duplicate prefixes in the UI. Offsets and acknowledgements
are authenticated by the existing caller/generation checks; future/out-of-range or
stale acknowledgements cannot delete output. Bound frame sizes, buffered bytes and
input independently; parsing/framing must not delay lease expiry.

If output exceeds the bounded retained window, report a gap explicitly rather than
pretend VT state is complete. Input must remain disabled until that discontinuity
is resolved through a clear owner action (a fresh session is always safe). Do not
invent a universal redraw capability for arbitrary terminal programs or silently
inject shell commands. Never revive a stale socket or lease to recover output.

## Compiler observations, not a selected package

The platform's `external/llvm` source declares version 3.9.0; existence of those
legacy modules is not a supportable modern compiler choice. Current platform
Clang prebuilts include modern host toolchains (for example r596125/22.0.2 with
source/cherry-pick metadata), but they are host tools, not a demonstrated Android
ARM64 compiler installation.

A subsequent broader inspection found the full modern LLVM project already pinned
at `external/opencl/llvm-project` (`37c265b53612ef8085c15455d10ec718590bba00`). Its
CMake version is 23.0.0git; METADATA's security CPE still says 21.1.0, so that CPE
must not be treated as the source version. It includes Clang, LLD, compiler-rt and
C++ runtimes. Its current generated Soong modules serve OpenCL clients and have
restricted visibility; that is not yet a general on-device Clang/LLD installation.
The platform build also generates an NDK sysroot. These are useful existing inputs
for a separately pinned native-toolchain build, not a need to fetch an unrelated
compiler tree immediately.

Establish the Android target runtime/linker, exact sysroot provenance, licenses,
relocation paths, retained build hardening and resource budget before packaging.
Do not lower security or use an obsolete compiler merely to produce a quick
demonstration.

## Preparation checkpoint

The 42 selected terminal-library source/test/resource files are imported unchanged
under `third_party/termux-terminal`, with source/licensing pins and a verifier that
rejects changed blobs, extra files, symlink substitutions and self-rewritten
manifests. No Termux app/JNI process launcher is imported.

A host characterization using the unchanged production pump/revoke bodies
reproduced the old limitation: six bytes were sent into the receiver's socket
queue, consumed from the raw tail, then lost when that receiver closed without
reading. A replacement attachment received nothing and the tail's dropped-byte
counter remained zero. This is a real host-socket observation, not a reproduced
Android UI incident; it motivates the continuity change without overstating M4.

A C++ output journal/frame encoder and Java frame decoder/replay cursor now have
portable tests for acknowledgement ordering, partial/lost connections, duplicate
prefixes, explicit gaps, bounded lengths and offset exhaustion. A real host-socket
trial and C++→Java wire fixture passed. The same cursor feeds the actual pinned
terminal parser in tests for split UTF-8/escape sequences, duplicate title actions
and gaps that must not alter the screen.

The full repository host suite passed **278 tests in 126.702 seconds**. The separate
terminal-engine suite passed **148 tests** (145 upstream tests plus three replay
integration tests) with explicit host utility/type adapters. The upstream disabled
clipboard test is not counted. These are not Android UI, Binder integration or
permission results.

**The new components are not yet wired into the Android build or active daemon.**
The demonstrated M4 console/transport and frozen producer remain unchanged. Next
is the process-lifetime terminal-session adapter, authenticated output ACK/replay
wiring, native Android view/input integration and the real `vi` exercise. This
checkpoint does not deliver a new running terminal or on-device compiler.

## Checks and evidence

- Portable tests for framed transport, partial writes/reads, replay/ack ordering,
  stale generations, bounded queues, loss notification and daemon death.
- Upstream terminal parser tests plus adapter/input and lifecycle negatives.
- Native/Java/SELinux build and image inspection, keeping the exact one-file owner
  policy adaptation separate from unchanged upstream projects.
- Real opt-in emulator UI: resize, typing and control keys, `vi` edit/save/read,
  detach/relock/return, ordinary-app negatives and existing core regressions.
- Later compiler: compile valid and invalid C/C++, execute the produced ARM64/Bionic
  program, inspect loader/ELF, and exercise representative resource pressure.

The preparation evidence selected by `out/owner-tools/EVIDENCE` is sealed across
119 regular files. It records source revision `c2b23ab`, public-source inputs,
source observations, portable checks and the raw-stream characterization. The
completed 24,195-file owner-session seal is untouched. Public-source fetches establish
pinned bytes via HTTPS, not independent maintainer identity or runtime safety.
I16 was cancelled before completing its read-only assessment. A delayed initial
note corroborated the enabled device `vi` and legacy LLVM/Clang source versions;
primary inspection verified those details. It did not assess the modern OpenCL
LLVM tree found by the primary. This is partial static corroboration, not a
completed independent review or a build/runtime result. Portable implementation
checks are reported above; no new Android runtime PASS is claimed.
