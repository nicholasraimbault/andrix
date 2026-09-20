# Work service runtime qualification

Status: fresh Android trials at `58b9d94` and corrected `4829af5` passed the finite
controls below. The first trial's denied direct signal route remains recorded. The
correction passed a new matching image/runtime check without changing policy. This is
not complete Work API, interactive terminal, CE fault, pressure or phone qualification.

## Purpose and setup

Qualify the [selected service](2026-09-20-work-service-integration.md) with an actual
owner client, not only host metadata or supplied authority facts. A newly frozen matching
image, enforcing policy and fresh offline emulator state were used. Default Console,
plain/Keep behavior and the accepted recording policy were unchanged. No CE withdrawal
fault was invoked in this trial.

The ordinary caller was launched through the separately qualified fixed launch vehicle.
It ran as the native owner and compiled a small owner program. That program then ran
through the new registry/service path. The caller's environment and the service's work
environment were distinct captured scopes. Diagnostic IDs and locator properties were
not used as authentication or as numeric signal targets.

## Observed finite controls

- The service became active and the actual native owner client connected through the new
  authenticated endpoint. The service implementation requires init's private activation
  receipt before publishing its locator or serving requests.
- An ordinary owner program was compiled and launched with the expected UID/GID, owner
  SID, empty capability sets, NNP, seccomp restriction and no inherited management FDs.
  Owner supplied environment and working directory were preserved in the observed case.
- Already opened owner files worked as standard streams. A pipe completed with EOF, and
  an owner allocated PTY was handed to work successfully. The PTY case is descriptor
  transfer, not interactive terminal/job control qualification.
- Successful owner queries bracketed an ordinary app's rejected connections to both
  service listeners. The app could not obtain the protected locator value, and its init
  start/stop attempts returned failure. The fixture's other bundled Binder negatives
  do not acquire a separate positive control from these endpoint queries.
- Two independent work items remained alive after their submitting client commands
  returned and the caller environment retired. A separate kernel process sample retained
  the same work B PID/start time and captured cgroup location after that retirement.
- Stop of work A closed its gate and ultimately produced signal exit, initial reap and
  scope reclamation. Work B remained live and unstopped.
- A forgotten work reference was refused through the same manager's Bind path while a
  newly allocated work remained live. This is a stale reference lookup control, not a
  retained old socket capability or forced numeric PID reuse experiment.
- A detached child remained in its original work cgroup after its initial process exited
  zero. The record had a closed entry gate but no Stop source and was not complete.
  Explicit whole work Stop then retired that scope without stopping unrelated work.
- The old service environment retired before replacement activated. The CLI refused an
  old environment reference before sending it to the replacement. New owner work in the
  fresh environment succeeded. This is not a raw stale transport packet test.
- Final work discovery and the independently observed owned hierarchy were empty. Boot,
  system server identity/start time and genuine platform instance/generation bookends
  matched. VM/controller/capture shutdown completed, and frozen inputs remained unchanged.

Client loss here means completed submitting clients and subsequent caller environment
retirement. Abrupt failure during submission or loss of a Start acknowledgement was not
exercised. Finite independent process samples do not establish exhaustive process or
physical resource accounting.

## Signal routing limitation and correction

The runtime attempted `pidfd_send_signal(SIGKILL)` on the initial process even after it
was placed and transitioned into the owner role. Android denied that direct process
signal from the coordinator. The separately captured cgroup kill still terminated the
tested work, so the listed Stop/reap/reclamation controls completed.

A final retired snapshot with runtime Missing and `kill_error=0` does not prove that every
earlier attempt succeeded. The stopped AVCs remain part of the result. The first pass must
not be cited as qualification of the direct initial signal route after owner transition.
No wider signal permission is granted to silence the denial.

The correction publishes positive placement before staging/release. The termination lane
closes the actual gate itself before sampling that state, covering a requester paused
between its stop metadata bit and gate closure. A retained initial pidfd is used only for
the placement gap. Once placement is known, termination uses the captured scope. This keeps
the early trusted bootstrap cleanup path without requesting direct signal authority over
ordinary owner processes.

New host kernel controls hold a live bootstrap both before and after placement. They
check that the early case actually takes the initial pidfd route, while the placed and
entered cases do not. Successful scope termination alone would not distinguish those
routes. The correction passes 433 host tests and focused sanitizer checks. Optimized and
ThreadSanitizer real kernel executions pass these selected cases. The second Android
trial below supplies separate runtime evidence, not an inference from those host results.

Other stopped logs contain owner search denials for shell test/data directories. No
failure from them was visible in the listed controls. Their exact originating call sites
were not independently traced, and permissions were not widened.

## Corrected image and second Android trial

A fresh complete selected image at `4829af5` passed native/policy/Java artifact checks
and eleven frozen host executables. Its binary SELinux policy was byte identical to the
first service image. There was no new complete normal image; default legacy source and
retained normal artifact correspondence were checked separately.

A fresh offline emulator repeated the listed owner, app, stream, independent work,
reference, descendant and retirement controls. Stopped logs contained none of the earlier
coordinator to owner SIGKILL denials. Source routing, actual host route counts and these
Android observations are complementary evidence. The Android trial did not separately
force the unplaced initial pidfd signal path, and absence of a log line alone is not a
proof of all possible execution paths.

Two additional controls distinguish closed stdin at exec from payload runtime behavior:

- The owner compiled a small static AArch64 syscall program. An owner side ELF check
  verified that it had no `PT_INTERP`. Through the actual service and `work_entry.cpp`
  path with `--closed-stdio 1`, it observed kernel `fcntl(F_GETFD)` return `EBADF` for
  descriptor zero and emitted its success marker.
- The ordinary Bionic payload with the same declared mask observed readable stdin EOF
  and completed its owner profile checks. Its startup may establish `/dev/null` again.
  This does not contradict closure at the exec handoff and does not disable Bionic's
  startup hardening.

This directly checks one closed standard role on Android. It is not a claim that all
payload runtimes preserve closed descriptors, an exhaustive descriptor map, or a new ABI.
The other mask combinations retain their separate native protocol test scope.

The second trial again ended with an independently empty owned hierarchy, unchanged
boot/framework/platform bookends, stopped VM/capture and matching frozen inputs. No new
CE withdrawal fault was invoked.

## Assessment and remaining gates

Primary assessment checked raw numbered responses, independent process samples, stopped
init/AVC logs, matched authority bookends, final hierarchy, complete packet capture and
resource/input closure. Independent read only review corroborated the lifetime distinction
and the bracketed work API negatives. It also emphasized the reference, submission failure
and final error reporting limits above. That review did not inspect the signal AVCs or
validate the proposed correction.

The manager's lack of home file open/map/execute authority was checked in the actual
compiled policy with `open_perms`, and the loaded image matched that policy. A separate
runtime attempt by the manager to open a home path was not performed.

Next exercise genuine CE withdrawal and normal recovery through the new service,
uncertain submissions, retained stale control handles, actual Console/isolated caller
controls, broader descriptor types, failure/pressure/suspend conditions and terminal integration. The earlier CE trial does not qualify these changed service
sources. No default Console migration or phone deployment follows from this finite pass.
