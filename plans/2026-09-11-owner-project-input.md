# Owner project builds and input readiness

**Status:** implementation and host checks; no new Android result yet.

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
while still releasing its one pending request. Version4 identifies this APK change.
No native protocol, Binder authority, PTY, identity, policy or limit changes are made.

The reusable [finite UI queue](../scripts/proof/ui_queue.md) sends one action at a
time and stops on failure/uncertainty. A real enabled/focused terminal UI observation
replaces guessed post-Attach delays in the test driver; input invocations are short.
This is not a production authority check, forced focus/keyboard setting, prompt
attestation or an implicit retry mechanism.

I21's read-only worker budget expired without findings. No independent review PASS
or inferred native defect follows from that cancelled assignment.

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
- Inspect output ELF and group resource counters; retain256MiB,32 tasks,128FDs and
  64MiB per-file limits. No global runtime path or unrelated directory grants.
- Repeat ordinary-app negatives with live positives, relock/return and bounded
  reboot/persistence/cleanup as relevant. Distinguish tests from full resource stress.

## Artifact/runtime procedure

Build a separately verified APK+v4 update pair for normal PM installation on a
frozen compiler image. Do not place its `.idsig` beside a factory APK. Any cold
continuation must freeze/re-hash stopped disk/config state, preserve the original
runtime, recreate only volatile endpoints and keep normal PIN/CE/boot checks.
Do not launch mutable build output or rewrite prior seals.

New raw evidence is selected by `out/owner-project-input/EVIDENCE`. Host tests of
state callbacks, queue sequencing and real host fixture builds are separate from
Android UI, compiler and isolation qualification.
