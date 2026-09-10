# Usable owner terminal and programming tools

**Status:** native VT/editor/script workflow demonstrated in the opt-in emulator
with producer `9e5f816`. Keyboard-event input and touch control buttons work;
post-Attach focus ergonomics and full software-IME input remain open. This is not
yet on-device C/C++ compilation or complete terminal/phone qualification.

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

The retained `e02bd6a` owner build selects **clang-r584948b / Clang 22.0.1**:
`cur` inherits `aosp_current`, which aliases `cp2a`; the pinned
[`RELEASE_BUILD_CLANG_VERSION` value](https://github.com/GrapheneOS/platform_build_release/blob/fb0e00657d596e48fc45ed86c9eb6a7c4071d72c/flag_values/cp2a/RELEASE_BUILD_CLANG_VERSION.textproto)
sets that revision. The inspected retained Soong configuration agrees and records
empty `LLVM_PREBUILTS_BASE`/`LLVM_PREBUILTS_VERSION` overrides. These generated files
were inspected later, not retroactively claimed as part of the original seal.
Frozen native binaries have no `.comment`; matching-build-ID unstripped
`andrixd`/runner counterparts report Clang/LLD 22.0.1, while installed stripped
counterparts exactly match the frozen hashes. This corroborates selection for
those modules—not a claim that every prebuilt in the image used that compiler.
It is also not evidence of a native Android compiler executable. Soong's fallback
or the newest directory present must not substitute for actual release selection.

A broader inspection also found the full modern LLVM project already pinned
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

That preparation checkpoint did not wire the components into Android. The next
implementation now connects the framed journal to authenticated AIDL ACK/resume
operations and supplies a process-lifetime terminal model, a process-free session
adapter and the native Android view/control keys. The parser's automatic clipboard
callbacks are separate from explicit user selection actions. In-flight Attach is
cancelled by UI lifecycle/detach epochs; input and worker queues are bounded.

The following candidate supplies the first real terminal/editor observations.
Portable tests remain distinct from Android View/IME and Binder behavior. No
on-device compiler is delivered here.

## Native terminal/editor window

Source `9e5f816` built the native service/runner, AIDL, terminal libraries and APK
in **757.876 seconds**. The complete image/host-package build then passed in
**188.827 seconds**. All 27 images and both host packages were frozen/rehashed;
actual image inspection retained the same APEX, shell, upstream Apps and Vanadium
bytes and the exact existing owner-policy bridge. The console is version 2,
`0.2-terminal`, signed by the same non-platform lab key, with no APK-declared
permissions or packaged JNI. R8's API37 warning and host memory-stall diagnostics
remain recorded, not suppressed.

The fresh offline emulator passed core checks and normal setup with a disposable
PIN. It then demonstrated:

- The native Android terminal rendered a shell in `andrix_owner`, UID/GID 7500,
  with all five capability masks zero, `NoNewPrivs=1`, `Seccomp=2`, and the actual
  256 MiB/swap0/group-OOM bounds. `TERM=xterm-256color`, `stty size` returned 26×42,
  and `/usr/bin/andrix-hello` ran.
- `vi hello.sh` entered its full-screen buffer. Normal Android keyboard events
  inserted a script and a visible Esc button left insert mode. The **unsaved**
  editor buffer survived Detach → Home → return; both shell PID 5097 and editor
  PID 5407 remained the same. Saving/exiting restored the shell screen.
- The saved 36-byte script printed `ANDRIX_VI_OK` when executed as owner code.
  Trusted native `sha256sum` output matched
  `ba8fd63e37ba190666b437e6a74e3e80f948269f35dde05457562741340a8264`.
  Readback was observed on the actual terminal display, not by giving the host
  observer or console APK direct access to the private home.
- The same-signer/different-package ordinary negative could not obtain the service
  or open the home; the terminal executed/read the script before and after it.
  P5 retained the ordinary-app private-execution denial. Both probes were removed.
- Screen relock detached the UI while Android remained `RUNNING_UNLOCKED` and the
  same native shell survived. Normal PIN unlock, Attach and terminal focus restored
  execution of the saved script. A proposed variable control was not established
  because that earlier input never reached the unfocused view; no variable-persistence
  claim is based on it.
- A deliberate 200,000-byte detached-output burst exceeded the journal window.
  Reattachment showed an explicit gap and blocked input. An attempted command did
  not create its target file. End/new Attach restored a fresh session and the saved
  script still ran. No silent screen reset or injected redraw command was used.
- Normal ActivityManager force-stop of only the console APK removed its native
  coordinator, shell and a measured descendant in a separate Unix session. A new
  idle coordinator appeared. No native/root kill workaround was used.
- A normal reboot changed boot ID and passed core checks again. Before the first
  PIN unlock, Android was `RUNNING_LOCKED`, with no owner process or CE-prepared
  flag. Normal unlock started the owner service; the edited script then ran again
  with the same hash. Explicit End and controller/runner/stop/capture cleanup all
  returned 0.

The closed window is sealed across **5,157 regular files** and contains 155,397
offline packets with zero reported drops and zero truncated records. This is not
a networking/privacy pass.

### Remaining terminal boundaries

- Input was supplied through normal Android keyboard events from shell UID2000,
  plus visible touch controls. A tap in the terminal was required after Attach to
  restore typing focus; unfocused input attempts are retained, not counted as
  executed commands. Fix that ergonomics issue before calling the interface polished.
- Full software-keyboard presentation and touch typing remain unqualified in this
  QEMU Virtio Keyboard fixture. The physical-keyboard settings UI was inspected;
  no settings, input-device, security or sensor state was forged to force a pass.
- SGR31 and UTF-8 `éλ` rendered correctly in Android's screenshot. The QMP capture
  showed the red sample as blue; both originals are retained as a fixture color-path
  discrepancy. No terminal palette or upstream rendering/security change was made
  to compensate for the observer path.
- The view's accessibility dump did not expose the terminal text in this run.
  Screen captures and native process observations remain the evidence; there is
  no claim of a complete machine-readable transcript or full accessibility support.
- The final host suite passed 278 tests in 126.892s; the engine/adapter suite passed 151
  tests (145 upstream, three replay, three adapter/input-queue). These do not replace
  the outstanding IME, accessibility, adversarial race, resource-pressure or broader
  lifecycle/hardware gates. Long-lived jobs and the C/C++ compiler remain later work.

## Post-runtime source accounting

The release/source verifier again authenticated all 1,108 declarations. Its original
result remains FAIL for the intended private SELinux adaptation and a 120-second
`build/release` timeout. An unchanged same-contract retry passed that project in
6.023 seconds; the guarded policy receipt matched the exact existing bridge. The
assessed result is 1,107 unchanged projects plus one exact adaptation, not a claim
that all tracked source is pristine. No untracked/materialization or phone-security
assurance follows from this check.

## Checks and evidence

The terminal-integration set selected by `out/owner-terminal/EVIDENCE` is sealed
across **8,729 regular files**, with symlinks excluded and the 5,157-file runtime
sub-seal reverified. Raw APKs, captures, credentials and logs remain outside public
Git. All owned guests and captures are stopped.

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
completed 24,195-file owner-session seal is untouched. A separate 22-file compiler-
selection inspection records the public release chain, later generated-config
observations and native-artifact metadata without rewriting either earlier seal.
Public-source fetches establish
pinned bytes via HTTPS, not independent maintainer identity or runtime safety.
I16 was cancelled before completing its read-only assessment. A delayed initial
note corroborated the enabled device `vi` and legacy LLVM/Clang source versions;
primary inspection verified those details. It did not assess the modern OpenCL
LLVM tree found by the primary. This is partial static corroboration, not a
completed independent review or a build/runtime result. The later I17 integration
review was also cancelled before substantive findings; no independent-review PASS
is claimed. Primary source inspection, compiled artifacts and the bounded runtime
observations above remain distinct forms of evidence.
