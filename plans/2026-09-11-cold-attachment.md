# Diagnose and fix cold attachment timing

**Status:** the guarded pending-lease correction passed bounded Android checks.
First Attach worked without retry after both tested boots, with ordinary renewals
already active during Main preparation. Relock, output-gap input blocking, End,
ordinary-app isolation and native C++ recompilation also passed. The previous failed
windows remain recorded; this is not a guarantee against arbitrary scheduler stalls.

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
setup completed at 361ms, Main began at 983ms, the active connection was installed
at 1000ms, and the first heartbeat began at 1844ms/returned false at 1867ms. The first
resize at 1050–1082ms had succeeded, so that resize itself was not the original failure.
A later attempt took 1402ms just to hand off to Main (FD-ready 44ms, Main 1446ms), leaving
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
restore a cancelled connection. The native 1500ms duration, expiry/generation rules,
controller identity and foreground/CE guards are unchanged.

The portable `AttachmentLifecycle` owns at most one pending/active connection. A
cancelled in-flight request continues to block new requests until its completion,
preventing an unbounded RPC queue. No lifecycle lock spans eligibility/Binder/I/O
operations. Cleanup covers the original FD plus duplicated streams after ownership
transfer, including failed renewal, cancellation and failed handoff. Stale completions
cannot release a newer request or re-enable retired input. Existing replay/gap rules
still govern active input; this is not a shell-readiness barrier or automatic retry.

Version 6 identifies the correction. It also separates argument preparation from
call timing and records pending ownership; these newer placements must not be
silently compared as identical to the diagnostic producer's earlier stamps.
Host ownership/race tests and extracted production renewal/retirement tests remain
separate from Android qualification.

## Observed fixed result

The main correction is `50987e1`. I23's read-only review found no concrete authority
or FD-ownership regression in the reviewed paths, but identified a liveness edge if
Main rejected both the handoff and diagnostic callbacks. Follow-up `a11c19e` completes
the already-retired request before posting its UI diagnostic; bookkeeping no longer
depends on Main accepting that callback. Matching-request completion stays idempotent.
The reviewed code's earlier APK was retained but not installed; the tested version 6
APK was built from `a11c19e`. No independent runtime PASS is attributed to the review.

The final APK build passed in **51.167 seconds**, after the separately retained
313.745-second intermediate build. Its verified APK+v4 pair installed normally on a
fresh copy of the same frozen `a653644` base. PM retained appId 10101,
UPDATED_SYSTEM_APP/PRIVILEGED/SYSTEM_EXT status and version 6 after reboot. No new
factory image, `.idsig` placement, native protocol, policy or compiler payload was
introduced. A busy shared-heavy slot was respected before launch.

- **First Attach after both boots passed without retry.** On the first boot, pending
  ownership was established at 509ms, ordinary renewal succeeded at 572ms, and Main
  began preparation at 1102ms. After reboot, the corresponding values were 192ms,
  204ms and 1013ms. Both received and applied output and accepted complete native
  owner commands. These are client-observed, per-attempt timings—not exact native
  grant or execution times.
- A later connection retained valid native authority through a **3269ms Main
  handoff** and then resized successfully. The unchanged heartbeat maintained its
  pending lease; the 1500ms lease duration was not lengthened or expired generations
  revived. This does not prevent legitimate expiry if the renewal path itself stalls.
- Plain native `clang++` compiled and ran the existing exception/RTTI/thread program
  as UID7500. Source and executable hashes persisted through reboot, and a new native
  shell rebuilt and ran it again. The compiler remained in authenticated `/usr` with
  the already-qualified standalone C++ profile.
- A delayed 200,000-byte output burst while detached caused an explicit gap. Input
  remained blocked across replacement attachments, End remained available, and the
  attempted `blocked-gap.txt` command did not create its file. A fresh session after
  End ran the C++ program successfully. The disabled-view key probe also triggered
  extra Attach operations, but none cleared the gap or admitted its command.
- Normal Home/return and relock/PIN return worked; relock preserved shell 4488 and
  `KEEP=pending_lease_ok`. The trace classified the lock transition as ineligible,
  and renewal refused it as expected. This is not a failure of the startup fix.
- The ordinary owner-negative and P5 probes passed with live C++ positives before
  and after, and both were removed. UID/capabilities/NNP/seccomp and the existing
  resource limits remained unchanged. The highest sampled group peak was
  **150,564,864 bytes (143.59375 MiB)**, with sampled OOM-event counters 0; this was not
  an exhaustion or total CPU/storage-quota test.
- Core checks passed before and after reboot, both real Cuttlefish completion
  reports arrived, and End/runner/controller/capture cleanup exited 0. One operator
  action supplied 61 characters to the 60-character test limit and was rejected
  **before injection**; the corrected short commands passed. It remains in the
  record, rather than making a false all-actions-PASS claim.

The final host suite passed **304 tests in 137.755 seconds**, with no skips. It includes
pending-input exclusion, cancelled-request serialization, promotion/retirement races,
stale completion, and extracted production renewal/retirement checks. Those tests do
not replace actual Android FD, Binder, keyguard or resource qualification. Live
Home/return timing did not establish every deliberately overlapped cancellation case.

The fixed runtime captured 167,326 offline packets with zero reported drops and no
truncated records. The diagnostic runtime separately retained 63,735 packets and its
failed attachments. No connected-privacy or supported-phone release claim follows.

**Next:** expand practical project/build/debug tooling and representative resource
qualification on this foundation. Long-lived services, package transactions,
full terminal/IME/accessibility coverage and hardware/release gates remain separate.

The complete set selected by `out/owner-attach-timing/EVIDENCE` is sealed across
**5,528 regular files**, with both runtime sub-seals reverified and symlinks excluded.
The diagnostic window retains 1,161 files; the fixed window retains 4,189. All owned
guests and jobs are stopped, and all earlier sealed sets remain untouched. Pixel,
Vanadium, accepted architecture and the standalone/shared C++ profiles are unchanged.
