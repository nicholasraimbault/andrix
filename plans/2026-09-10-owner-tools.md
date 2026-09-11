# Usable owner terminal and programming tools

**Status:** native VT/editor/script workflow demonstrated on base image `9e5f816`.
The version-3 console follow-up also demonstrated automatic typing focus, actual
software-keyboard touch editing and guarded accessibility viewport text in the
bounded emulator fixture. On-device C/C++ compilation and broader terminal/phone
qualification remain open.

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

### Initial terminal-window boundaries

These describe the `9e5f816` window; the later console-only follow-up below records
which UI gaps were subsequently exercised.

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

## Focus/IME/accessibility follow-up

The console-only revision `b874ea9` restores typing focus when an eligible attachment
becomes input-capable. Keys toggles the normal keyboard request; holding it opens
Android's ordinary input-method picker. It neither writes secure settings nor
requests extra Android permissions. The Ctrl touch modifier also applies to an
extra key and is then cleared, rather than unexpectedly affecting the next letter.

A first-party accessibility delegate exposes the actual displayed rows, including
when accessibility is enabled after view creation. Text is bounded to 8,192 UTF-16
code units, truncation is explicit and surrogate pairs are kept intact. It is a
viewport description, not a complete transcript or an editable-file API. The bound
foreground/unlocked UI check still applies; events carry no cached terminal text
and are coalesced/cancelled on lifecycle loss. No owner-home file access is added.

Qualification may update the console APK normally on the frozen `9e5f816` base:
same package/lab signer, higher version, no downgrade or verifier bypass. Record
image, APK and observer producers separately. A retained-data cold boot must permit
normal PIN unlock before waiting for Cuttlefish's CE-only boot report.

Cuttlefish's QEMU launcher includes a physical keyboard, and Android's
`InputMethodService` normally hides its input view in that configuration. A bounded
lab-only test may explicitly set `show_ime_with_hard_keyboard` to request the
software keyboard alongside that real emulated device. Record the original value,
real rendering/touch input and restoration. This is a test-fixture display preference,
not an APK permission, input-device fiction, keyguard override or default-Pixel
behavior claim. The terminal APK itself must not write that secure setting.

Compiler packaging remains a separate step; these changes do not add a native compiler.

### Observed console update and UI result

The version-3 APK (`0.3-terminal-ui`) built in **386.854 seconds**, with 279 host
checks and 154 parser/adapter checks passing. The frozen base image and host
packages remained `9e5f816`; the runtime cold-started a separately hashed copy of
its stopped disk state and used the existing disposable PIN.

The initial streamed APK-only update was **rejected** because it had no fs-verity.
GrapheneOS's system-package integrity check was not disabled. A signing derivative
using the same lab key supplied a verified v4 `.idsig` sidecar, with every
non-signature ZIP entry unchanged. A normal `adb install-multiple -r` session then
succeeded. PM reported version 3 with `UPDATED_SYSTEM_APP`, `PRIVILEGED` and
`SYSTEM_EXT` status. This is a lab update result, not a production update channel.

The installed derivative APK SHA-256 is
`ec289baed72dd1793aa7d0dd079e742a8a16a89a9c7bfc420d67b02ec49fcac7`;
its sidecar is
`1461fc26e4ee3e382abf1f85f28157d30c5d6b3768c4732e9d200697e67825af`.
The original failed artifact remains separately frozen. A corrupt-sidecar control
reported **v4=false** even though `apksigner` exited 0 through the still-valid v3
signature; the initial exit-code-only assumption was rejected. Per-scheme results,
not the overall exit alone, are the v4 oracle. The build now requests v4 sidecars
directly through Soong's `v4_signature` option rather than requiring manual signing
for later updates. The Soong follow-up `6eff213` passed its APK build in 384.431s,
produced a byte-identical copy of the original `ab815409…` APK plus a verified v4
sidecar, and retained the same signer. This exact build-produced pair was artifact-
verified, not installed in the already-closed runtime; the tested signing derivative
above remains separately identified.

After the successful update:

- Attach accepted keyboard-event input without another tap in the terminal. This
  also worked after the input-method picker and normal PIN relock/unlock return.
- The actual software keyboard rendered after the explicitly recorded fixture
  preference changed from 0 to 1. Visible key taps entered `pwd`, opened `vi touch.sh`,
  inserted `echo touch`, used the terminal's Esc control and touchscreen Shift-Z
  twice to save/quit, then entered `sh touch.sh`. The script printed `touch`.
  This touch-input sequence did not substitute `adb input text` for typing.
- The PTY changed between 27×42 with the keyboard hidden and 10×42 with it shown.
  Holding Keys opened Android's real input-method picker; focus loss detached the
  native attachment, and return recovered the same owner shell.
- Accessibility queries exposed the real, bounded current viewport, including
  output after view construction. Clearing the screen removed old history from
  that viewport description. The active picker and locked-window trees contained
  no terminal node. This is not a complete TalkBack interaction or cached-node
  attack assessment; the explicit bounds/surrogate controls also have host tests.
- Native shell PID 4001, UID7500, zero capability masks and its inherited NNP/seccomp
  state survived the relock trial. The touch-created 12-byte file's observed hash
  matched `8d809713302439ce7b96c7e0d193f4477da9c88a4bcf7223097c20d086726128`.
  The same-signer owner-negative and P5 passed and were removed, with live owner
  positive controls before and after the negative.
- The display preference was restored to its original 0 value. Core, End, real
  post-unlock CVD reporting and all runtime/capture cleanup completed successfully.

The closed window retains **3,995 regular files** and 123,646 offline packets,
zero reported drops and zero truncated records. The failed install remains FAIL;
early screenshots named “updated” were still version 2 until the separate successful
v4 install. The host queue helper was corrected to validate every submitted action,
not only the last one in a batch. No earlier seal was rewritten.

## Post-runtime source accounting

For the `9e5f816` image checkpoint, the release/source verifier again authenticated
all 1,108 declarations. Its original result remains FAIL for the intended private
SELinux adaptation and a 120-second
`build/release` timeout. An unchanged same-contract retry passed that project in
6.023 seconds; the guarded policy receipt matched the exact existing bridge. The
assessed result is 1,107 unchanged projects plus one exact adaptation, not a claim
that all tracked source is pristine. No untracked/materialization or phone-security
assurance follows from this check.

## Checks and evidence

The console-UI follow-up selected by `out/owner-terminal-ui/EVIDENCE` is sealed
across **4,280 regular files**, including the 3,995-file closed window, original
failed install/signing observations, frozen base state and separately identified
APK/sidecar pairs. Its source accounting inherits the frozen image's prior audit;
the exact private policy bridge was checked again, not relabelled as pristine
upstream. No fresh all-project source-audit result is claimed for this APK-only step.

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
Public-source fetches establish pinned bytes via HTTPS, not independent maintainer
identity or runtime safety.
I16 was cancelled before completing its read-only assessment. A delayed initial
note corroborated the enabled device `vi` and legacy LLVM/Clang source versions;
primary inspection verified those details. It did not assess the modern OpenCL
LLVM tree found by the primary. This is partial static corroboration, not a
completed independent review or a build/runtime result. The later I17 integration
review was also cancelled before substantive findings; no independent-review PASS
is claimed. Primary source inspection, compiled artifacts and the bounded runtime
observations above remain distinct forms of evidence.
