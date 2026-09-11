# Diagnose and fix cold attachment timing

**Status:** diagnostic traces exposed the client ownership/renewal gap; a guarded
pending-lease correction is implemented and under qualification. No fixed Android
result is claimed yet.

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

## Diagnostic observations and correction

Diagnostic producer `fda6815` returned native FDs promptly, but left them outside the
heartbeat's ownership until Main finished preparation. In one failed attempt, FD
setup completed at361ms, Main began at983ms, the active connection was installed
at1000ms, and the first heartbeat began at1844ms/returned false at1867ms. The first
resize at1050–1082ms had succeeded, so that resize itself was not the original failure.
A later attempt took1402ms just to hand off to Main (FD-ready44ms, Main1446ms), leaving
almost none of the initial lease for preparation. A subsequent warm control worked.

These are client-observed elapsed times, not exact native grant/rejection timestamps.
The diagnostic Attach-call envelope included eligibility argument evaluation; first
stamps cannot pair later operations; untraced input-writer renewals and closure/EOF
ordering prevent broader conclusions from missing markers. I23's read-only review
identified those limits and the cancellation/promotion races a correction must cover.
No independent runtime PASS is attributed to that review.

The correction gives a validated connection **pending ownership as soon as FD setup
completes**. The control executor requests an immediate ordinary renewal, then its
existing heartbeat maintains either pending or active ownership while eligibility
holds. Pending input remains blocked. Main prepares its parser and conditionally
promotes that same object; promotion and input permission are one identity-checked
transition. False/failed renewal retires the object, and a successful late RPC cannot
restore a cancelled connection. The native1500ms duration, expiry/generation rules,
controller identity and foreground/CE guards are unchanged.

The portable `AttachmentLifecycle` owns at most one pending/active connection. A
cancelled in-flight request continues to block new requests until its completion,
preventing an unbounded RPC queue. No lifecycle lock spans eligibility/Binder/I/O
operations. Cleanup covers the original FD plus duplicated streams after ownership
transfer, including failed renewal, cancellation and failed handoff. Stale completions
cannot release a newer request or re-enable retired input. Existing replay/gap rules
still govern active input; this is not a shell-readiness barrier or automatic retry.

Version6 identifies the correction. It also separates argument preparation from
call timing and records pending ownership; these newer placements must not be
silently compared as identical to the diagnostic producer's earlier stamps.
Host ownership/race tests and extracted production renewal/retirement tests remain
separate from the pending Android qualification.

New raw evidence is selected by `out/owner-attach-timing/EVIDENCE`. Pixel, Vanadium,
accepted architecture and the standalone/shared C++ profiles remain unchanged.
