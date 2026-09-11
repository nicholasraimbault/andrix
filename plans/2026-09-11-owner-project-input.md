# Owner project builds and input readiness

**Status:** the native multi-file project workflow passed in the ARM64 emulator,
including editing, failed-build recovery, relocation and rebuilding after reboot.
The input queue correctly withheld commands during two failed first attachments.
Those failures remain part of this version 4 result. The subsequent
[cold-attachment correction](2026-09-11-cold-attachment.md) passed its own bounded
Android checks; it does not retroactively turn this window into a blanket UI PASS.

The [C++ defaults](2026-09-11-cxx-defaults.md) already work in the ARM64 emulator.
This follow-up improves the observed attachment/input timing and exercises a
repeatable multi-file project under the existing owner limits.

## Findings and bounded changes

Two long Android input commands timed out in the previous window; the old host
queue had already submitted following actions, so text and Enter interleaved. This
is a demonstrated test-driver defect, not evidence that native PTY transport loses
bytes. Early typing also preceded a stable console state; its cause remains bounded
by those observations, not assumed to be an Android shell defect.

Source inspection found that a replacement `attach()` closed its old input socket
without immediately publishing the disconnected/pending UI state. It could leave
an enabled-looking “Attached” view during a pending Binder request. An old request's
failure callback could also replace a newer detach/rebind state. The console now
publishes “Attaching” synchronously and ignores stale/ineligible failure diagnostics,
while still releasing its one pending request. Version 4 identifies this APK change.
No native protocol, Binder authority, PTY, identity, policy or limit changes are made.

The reusable [finite UI queue](../scripts/proof/ui_queue.md) sends one action at a
time and stops on failure/uncertainty. A real enabled/focused terminal UI observation
replaces guessed post-Attach delays in the test driver; input invocations are short.
This is not a production authority check, forced focus/keyboard setting, prompt
attestation or an implicit retry mechanism.

I21's read-only worker budget expired without findings. I22 stopped after questioning
the readiness predicate's view class. Actual retained and new Android hierarchies
report `android.view.View` for this terminal and satisfied the predicate when enabled,
focused and attached. Neither cancelled assignment supplies an independent review
PASS or an established defect.

## Project exercise

The [statistics fixture](../tests/owner-project/README.md) uses three translation
units, a header, response file, static archive and serial shell build. It exercises
exception propagation, vector/string parsing and nonconstant math. Temporary build
outputs are private; only a successful build/check replaces the prior executable.
It is deliberately not a new make implementation or package manager.

- Import reviewed source bytes through explicit owner terminal input, not observer
  home access. Check their hashes, then build/run using the installed native tools.
- Edit the header in `vi`, rebuild and observe the changed program. Reject invalid
  arguments. Introduce a compile error, verify failure/previous-output preservation,
  restore the source and rebuild. Relocate and rebuild/run the project.
- Inspect output ELF and group resource counters; retain 256 MiB, 32 tasks, 128 FDs and
  64MiB per-file limits. No global runtime path or unrelated directory grants.
- Repeat ordinary-app negatives with live positives, relock/return and bounded
  reboot/persistence/cleanup as relevant. Distinguish tests from full resource stress.

## Artifact/runtime procedure

Build a separately verified APK+v4 update pair for normal PM installation on a
frozen compiler image. Do not place its `.idsig` beside a factory APK. Any cold
continuation must freeze/re-hash stopped disk/config state, preserve the original
runtime, recreate only volatile endpoints and keep normal PIN/CE/boot checks.
Do not launch mutable build output or rewrite prior seals.

## Observed result

Source/APK producer `ed060a5` built the terminal and the upstream host shell in
**84.972 seconds**. The terminal version 4 update used a separately signed and explicitly
v4-verified pair through normal PackageInstaller on the unchanged frozen `a653644`
compiler image/APEX 3. PM retained appId 10101 and SYSTEM_EXT/PRIVILEGED authority and
reported UPDATED_SYSTEM_APP. No new factory image or sidecar placement is claimed.

The cold continuation froze **139 regular home/config/disk files**, excluding 35
volatile endpoints/backing files. Image hashes were checked against the prior frozen
producer; the expanded super image was independently compared with `simg2img` output.
The original runtime and all earlier seals remained untouched. Normal PIN entry,
CE availability, core checks and the real Cuttlefish boot reporter were retained.

The current host suite passed **301 tests in 131.407 seconds**, with no skips. Sixteen
additional real host-mksh PTY cases queued input before fork/controlling-terminal
setup/exec and did not reproduce byte loss. Those cases use the host ABI and are
not Android transport proof; no native launch handshake was added on that basis.
Seven relevant upstream projects, pinned compiler staging and the exact existing
owner-policy bridge were rechecked. No whole-manifest re-audit is claimed.

### Native project workflow

- The owner imported the reviewed fixture through explicit terminal input; all six
  functional source hashes checked successfully. The observer did not gain direct
  owner-home access. The serial three-translation-unit/response-file/archive build
  completed as native UID7500 in **124.67 seconds** on ARM64 TCG and printed
  `BUILD_OK v1 count=3 mean=4 rms=4.32049`.
- `vi` changed the header to `v2`; its unsaved edit survived Detach/Home/return with
  the same editor 6699 and shell 3526. Saving and rebuilding produced the changed
  `v2` result. An initial unsupported `r`-command attempt was retained; documented
  `x`/`i` editing operations were used instead, without an editor/source patch.
- Invalid input and excessive magnitude returned 2. A deliberate `#error` made the
  build return 1, kept the previous executable's hash unchanged and removed its
  temporary directory. Restoring the source and moving the project into a directory
  containing a space still allowed a successful rebuild/run. Nonconstant math and
  exception handling were exercised inside Android, not just cross-linked on a host.
- The resulting 4,390,648-byte executable was ARM64, used `/system/bin/linker64`,
  needed only Android's libc/libdl/libm, and had no shared-STL dependency or RUNPATH.
  This is the standalone C++ profile, not static Bionic or a global runtime-path grant.
- The owner-negative and P5 tests passed as ordinary apps, with actual project
  positive controls before/after. Both were removed. Relock/PIN return preserved
  shell 3526 and `KEEP=project_ready`. Reboot changed the boot ID, required normal
  unlock before the owner service/home were available, and preserved all source and
  executable hash checks. A new shell 3422 rebuilt and ran the project again.
- The highest sampled owner-group peak was **237,879,296 bytes (226.859375 MiB)**;
  sampled OOM-event counters remained 0 within the unchanged 256 MiB limit. This is
  representative build sampling, not exhaustion/pressure or total CPU/storage-quota
  proof. Native capabilities remained 0, NNP/seccomp remained active, and the existing
  task/FD/file limits stayed unchanged.
- End and normal console force-stop removed native jobs. The saved project still
  ran after restarting the console. All core, UI-loop, controller, runner, capture
  and cleanup exit codes were 0; that does **not** mean every UI action succeeded.

The `v2` executable SHA-256 was
`b002184fbc111d9e609e814f405a0d99df01278a3519c0bbec4bacc88f5fab7c`;
the edited header was
`68b276a7db3778f14280f8b4f133d2114c2e0dcd6a74eed6ad7e0dd12451acd1`.
These observations came from native commands and the real bounded terminal display.

### First-attachment finding in this window

The first Attach after **each** boot ended with `Detached: resize failed`; the actual
terminal node was disabled/unfocused. Readiness actions 0021 and 0263 failed, and the
sequential client submitted none of their pending command/key actions. After
inspection, an explicit second Attach worked and complete input was received.
Replacement attachments, return from the editor/relock, a warm End/new-native-session
control and a fresh console process on the already-running platform also worked.

Thus the predicate's class match is not the cause, and the old long-input timeout
interleaving did not recur. But the successful retries are not first-Attach success.
The current diagnostic does not establish whether cold scheduling, lease timing,
frontend setup or another resize path caused the failure. No lease extension,
namespace/policy weakening, automatic retry or guessed-delay substitute was used.
The pending-state and stale-callback fixes are source/host-checked changes; they do
not close every startup race.

**Follow-up:** the [cold Attach/resize work](2026-09-11-cold-attachment.md) records the
subsequent diagnostics, pending-lease correction and Android qualification. Broader
project/build-tool and resource testing follows that work. Long-lived services, package transactions,
full terminal compatibility and supported-phone/release/privacy qualification remain
separate work.

The closed runtime retains **7,874 regular files** and 270,465 offline packets with
zero reported drops or truncated records. The complete set selected by
`out/owner-project-input/EVIDENCE` is sealed across **8,173 regular files**, with the
runtime sub-seal reverified and symlinks excluded. All owned guests and jobs are
stopped. Old linker probes into denied unrelated shell/test directories remain
recorded; no access was granted merely to silence them.
