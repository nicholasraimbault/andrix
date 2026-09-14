# Approved lab lifecycle fault controls

**Status:** source implementation and host-test preparation. No fault-enabled
Android artifact or runtime result yet. The owner approved the two fixed controls
below; ordinary images must omit them. Resource admission and artifact validation
remain part of the reusable verification procedure.

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

Arm one2500ms delay for the current platform instance/generation/work/registration.
The arm expires after a fixed5000ms active-time window. Only a matching authenticated
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

This does not enable Keep by default, qualify all pressure/suspend/vold cases, alter
accepted architecture, or authorize Pixel deployment/services/SSH/package transactions.
Use fresh, verified artifacts and immutable evidence; do not reuse a consumed fixture
session or substitute a host model for an Android runtime result.
