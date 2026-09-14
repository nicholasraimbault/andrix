# Owner project builds and input readiness

**Status:** bounded multi-file editing, dependency rebuild, relocation, failed-build
recovery and reboot/rebuild workflows were demonstrated in the emulator.

## Reusable findings

Serialize UI actions and wait for each matching result. A timed-out input command
must not be followed by an automatic Enter or retry: injection may still be in
progress. Observe a fresh, enabled and focused terminal before sending bounded input.

A first-attachment failure can coexist with a surviving native child and a successful
retry. Diagnose that ownership/timing boundary separately; the
[cold-attachment correction](2026-09-11-cold-attachment.md) addresses it.

## Project fixture

Use the [multi-file project](../tests/owner-project/README.md) to check header edits,
rebuild selection, previous-binary preservation on failure, directory relocation and
fresh execution. See [queue semantics and fresh capture](../scripts/proof/ui_queue.md).
These controls do not establish all IME, accessibility or scheduler behavior.
