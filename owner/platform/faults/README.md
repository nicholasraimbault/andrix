# Fixed lifecycle faults for the approved lab tests

This is test authority, not a production feature. Select only with
`ANDRIX_OWNER_FAULT_TESTS=true` on the GrapheneOS Cuttlefish userdebug/eng product;
Keep and its existing dependencies must also be enabled. Normal products select the
`disabled` Binder source, which has neither fault command nor storage-lock call.
Debuggable state alone cannot enable the facility.

The [approved scope and verification plan](../../../plans/2026-09-14-lab-lifecycle-faults.md)
remain authoritative for the experiment. Host facades do not qualify Android caller
identity, key state or cleanup. No fault-enabled Android runtime has been observed at
this source-preparation checkpoint.

In the lab image, the existing service's standard Binder Shell interface accepts:

```
adb shell cmd andrix.owner.lifecycle help
adb shell cmd andrix.owner.lifecycle delay-next-snapshot
adb shell cmd andrix.owner.lifecycle lock-ce-user0
```

Only actual Shell UID2000/PID>1 on a debuggable build may invoke these commands. No
user, PID, duration or other argument is accepted. Each fault has one accepted use
per platform-service lifetime. Both require a current active Keep grant and refuse
concurrent faults.

- `delay-next-snapshot` targets the captured platform epoch/work/registration. Its
  arm expires after5000ms active time. One matching authenticated native snapshot
  reply is delayed2500ms after its real state is captured, with no lifecycle/storage/
  gate monitor held. Changed targets and late arms are discarded; old positives
  are not rewritten as synthetic state.
- `lock-ce-user0` uses the actual `StorageManager.lockCeStorage(0)` path after
  authenticating the lab caller. It clears/restores Binder identity solely for this
  explicitly approved system_server operation. It grants Shell no general storage
  permission and never delays key withdrawal for native cleanup.

The key command reports Android's CE-cache observations under explicit cache labels.
A method return/cache change is not a universal physical-key removal, busy-file cleanup
or erasure guarantee. Runtime evidence must include Android/vold results, native
process cleanup and normal unlock/fresh-work recovery. The delay test must establish
expiry while the platform process remains alive, not substitute the earlier watchdog
platform-death test.
