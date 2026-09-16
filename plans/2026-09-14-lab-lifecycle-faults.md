# Approved lab lifecycle fault controls

**Status:** both fixed controls were exercised on the frozen Android lab image.
Cleanup and fresh work recovery were observed within the emulator scope below.
The CE operation reported busy files, not complete physical key removal. Ordinary
images omit these controls. Resource admission and artifact validation remain part
of the reusable verification procedure.

## Exact scope

An additional compile-time/product opt-in, restricted to this userdebug/eng emulator
product, selects a lab Binder adapter. Normal products select a different source
implementation containing no fault commands or storage-lock call. Artifact checks
must verify that distinction, not just trust a runtime property or an API name.

Only the actual Shell UID2000/PID>1 on a debuggable lab image may invoke either fixed
command. No arbitrary user, PID, executable, property or duration is accepted. Each
fault has one accepted use per platform-service lifetime and requires an active Keep
registration; concurrent faults are refused. Ordinary/native snapshot authorization
remains the existing coordinator UID/MAC/worker-filter boundary.

### `lock-ce-user0`

Invoke Android's real `StorageManager.lockCeStorage(0)` after endpoint authorization.
Any Binder identity clearing is the explicitly approved system_server delegation for
this fixed lab operation, not a general Shell permission grant or borrowed APK
identity. No lifecycle/storage monitor is held across the call, and key withdrawal
never waits for native cleanup. Report framework CE-cache values as cache metadata,
not continuous physical-key authority or proof that busy key removal completed.

Runtime qualification needs a live kept-work positive, actual Android/vold operation
and error/busy observations, native group cleanup and normal unlock/fresh-work recovery.
A returned method or synthetic state flag is not sufficient by itself.

### `delay-next-snapshot`

Arm one 2500 ms delay for the current platform instance/generation/work/registration.
The arm expires after a fixed 5000 ms window measured in active time. Only a matching authenticated
native snapshot can consume it; a changed target or expired arm cannot delay later
replacement work. The hook retains the actual captured response, including a genuine
positive, and delays only its reply outside all lifecycle/storage/gate monitors.

Runtime qualification needs native expiry and complete cleanup while system_server
stays alive, rejection of the late result, and fresh explicit work after normal
responses resume. The earlier AMS-global-lock/watchdog test is not substituted for
this actual snapshot-RPC control.

## Verification

- Pure gate/ordering tests: one-use budgets, arm expiry, target/epoch replacement,
  overlap, clock bounds and stale completion.
- Actual lab-adapter methods under explicit host facades: authenticated caller
  checks, exact commands/no arguments, identity restoration, real-call delegation
  shape and no monitor across external calls. These facades are not Android proof.
- Flag-on/off product expansion and Android compilation/artifact checks: fault
  code/command strings/storage-lock invocation absent from the normal owner jar;
  existing AIDL transactions and SELinux/native authority unchanged.
- Fresh frozen-image/host runtime controls and recovery, preserving failed attempts,
  sampling actual authority and cleanup rather than a guessed process ID alone.

This test facility does not enable Keep by default or qualify all pressure/suspend/
vold cases, Pixel deployment, services, SSH or package transactions. Use fresh, verified
artifacts and immutable evidence; do not reuse a consumed fixture session or substitute
a host model for an Android runtime result.

## Verified artifact checkpoint

Source `17b998c` passed 346 host checks. Both image variants were built from that
source, frozen with their matching host packages and inspected independently.

The normal image's owner jar matches the compiled variant without either lab command
or the storage lock call. The unique lab command strings were absent from the scanned
DEX containers in its installed partitions. The lab image contains the two commands
and the actual Android storage lock and delay invocations. The bundled owner APEX,
Console, native coordinator, runner and SELinux policy retain their previously checked
bytes. Keep remains an explicit product opt in, not an ordinary default.

Image and bytecode results alone do not establish actual caller identity, storage
outcomes or cleanup. The separate runtime observations follow.

## Observed Android runtime checkpoint

A fresh offline ARM64 emulator used the frozen lab image and matching host tools.
The actual Shell caller had UID 2000. Android remained enforcing. Each fault targeted
live kept work after Console had been stopped. Process identities, workload cgroups,
platform epochs and Android/kernel logs were recorded independently.

The genuine snapshot reply was delayed for 2.506 seconds. Native work ended after
1.006 seconds and init removed its cgroup after 1.194 seconds, before the late reply.
The old coordinator, tmux server, shell and background process disappeared. The late
reply did not revive work. A fresh explicit Keep request succeeded and read the saved
CE file. The platform instance and generation stayed unchanged through this trial.

The real `StorageManager.lockCeStorage(0)` call returned. Platform availability became
false with a newer generation, and the complete old workload group was removed.
Vold reported files still open after key removal and deferred their cleanup to a
worker. This demonstrates the real busy file outcome. It does not establish that all
open inodes were locked or that physical key removal was complete.

Normal lock screen PIN entry restored CE availability without reboot. A fresh explicit
Keep request read the saved file, compiled and ran a C program, and ended cleanly.
Neither fault replaced `system_server`: its PID and process start time, and the kernel
boot identity, remained unchanged. Ordinary app access to the owner home and services
was denied before and after the faults. No Keep grant returned automatically.

The first delay sampler exceeded its host deadline. Its incomplete run is retained,
not counted as a completed collector. Partial samples, independent platform/kernel
logs and subsequent observations established the cleanup and recovery sequence. The
CE trial used a separately recorded bounded operator collector. Frozen image and
fixture inputs were not modified. Failed UI readiness checks submitted no terminal
text and were retained as failures.

These results cover one lab fixture. Broader pressure/suspend behavior, abnormal
storage backend failure, complete busy inode locking and phone/release qualification
remain open.

## Approved follow-up

After these tests, separate workload lifetime from terminal attachment, as recorded
in the [architecture](../docs/architecture.md#lifecycle-and-networking). Retain Android
user/CE authority, resource supervision, process-bound Stop and independent locked-UI
gates. tmux remains an ordinary optional tool, not a condition of all retained work.
Exact foreground/detached-work defaults require explicit definition and qualification;
this direction does not itself change the current prototype's lifetime behavior.
