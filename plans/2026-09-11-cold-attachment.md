# Diagnose and fix cold attachment timing

**Status:** bounded diagnostic APK preparation; no cause or fix qualified yet.

The [project trial](2026-09-11-owner-project-input.md) twice observed a first Attach
after boot ending with `Detached: resize failed`. The existing native child survived,
an explicit retry worked, and warm replacement/new-session/console-process controls
worked. The test driver withheld input while the actual view was unready.

## Diagnostic scope

Version 5 adds fixed-size, enum-only client timing records using Android elapsed
realtime, comparable to the native lease's BOOTTIME clock. It measures control-queue
entry, registration, Attach request/reply, FD setup, main-thread completion, terminal
creation, first output, first renewal, resize and closure. Each event is recorded
once; at most two fixed report categories are emitted per attempt on debuggable
builds, on closure/failure after FD teardown. No logging is done during a healthy
attachment: a warm control is explicitly detached to collect its report. No terminal
bytes, file paths, clipboard, credentials, native tokens or arbitrary exception
messages are logged. Resize errors are classified only against fixed native messages.
There is no continuous keyboard or heartbeat logging.

The diagnostic build must not change the native service, Binder/PTY protocol, lease,
eligibility, namespaces, SELinux policy, resource bounds or replay/gap contract. Logs
can perturb timing; compare their measurements with the retained uninstrumented
failures and preserve unsuccessful reproduction attempts.

## Qualification sequence

1. Host-test bounded trace state and unchanged owner contracts; build and verify a
   separate APK+v4 update pair for normal PM installation on a frozen compiler image.
2. Cold-start a verified stopped-state clone, unlock normally, install the diagnostic
   update and observe the first Attach plus an explicit warm control. Collect the
   actual timeline and failure category; do not replace readiness with a delay.
3. If evidence identifies a cause, implement the narrow correction and test its
   failure/cancellation/race edges. Do not extend the 1500ms lease, suppress errors,
   open policy or add speculative shell-readiness machinery.
4. Verify first-Attach behavior after cold boot and compare warm controls; repeat
   native project build/persistence, isolation, relock and cleanup as appropriate.
   Keep diagnostic producer, fix producer, image, observer and result provenance
   distinct. Seal a new evidence set, leaving all previous sets untouched.

New raw evidence is selected by `out/owner-attach-timing/EVIDENCE`. Pixel, Vanadium,
accepted architecture and the standalone/shared C++ profiles remain unchanged.
