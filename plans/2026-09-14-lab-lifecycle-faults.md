# Approved lab lifecycle fault controls

**Status:** source, host checks and normal/lab image artifact checks passed.
Runtime qualification remains pending. The owner approved the two fixed controls
below; ordinary images omit them. Resource admission and artifact validation remain
part of the reusable verification procedure.

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

These are image and bytecode results. They do not establish actual caller identity,
key withdrawal, busy file outcomes, delayed reply cleanup or recovery on Android.
Those require the fresh runtime controls above.

## Approved follow-up

After these tests, separate workload lifetime from terminal attachment, as recorded
in the [architecture](../docs/architecture.md#lifecycle-and-networking). Retain Android
user/CE authority, resource supervision, process-bound Stop and independent locked-UI
gates. tmux remains an ordinary optional tool, not a condition of all retained work.
Exact foreground/detached-work defaults require explicit definition and qualification;
this direction does not itself change the current prototype's lifetime behavior.
