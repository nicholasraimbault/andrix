# UI state read helper

The health composition of the
[component transaction](../../plans/2026-10-09-component-transaction.md) must know, for one user,
whether the device is awake, whether the keyguard shows, whether the user is locked and has a
secure credential, and whether its CE storage is unlocked. The shell user has no convenience
command for these that tells a failed call from a false answer: KeyguardManager's methods answer
false on a RemoteException. This fixed program, run as the shell user, asks the framework's
services directly and prints each answer, or why it has none. It is a test helper for the lab shell
route, not part of any image.

`UiStateRead.java` is the whole program. Through reflection it takes each service from
`android.os.ServiceManager`, gets its own Binder proxy from the interface's `Stub.asInterface`, and
calls one method by its exact AIDL signature. Reflection lets it compile without the framework's
hidden classes, and the proxy is the device's own, so the helper never names a transaction number.
A method whose signature differs on the device is not found, and its answer is unavailable. The
only argument is one bounded user ID. No path locks or unlocks a user, dismisses or disables the
keyguard, wakes or sleeps the device, reports an unlock attempt, or starts, commits or aborts a
checkpoint.

## Source basis

`signatures.json` pins each call against the pinned framework tree, with the AIDL file's SHA-256,
the declaration's line and its exact text:

| Answer | Service | Call | AIDL |
| --- | --- | --- | --- |
| `interactive` | `power` | `IPowerManager.isInteractive()` | `core/java/android/os/IPowerManager.aidl:65` |
| `keyguard_locked` | `window` | `IWindowManager.isKeyguardLocked()` | `core/java/android/view/IWindowManager.aidl:262` |
| `keyguard_secure` | `window` | `IWindowManager.isKeyguardSecure(int userId)` | `IWindowManager.aidl:264` |
| `device_locked` | `trust` | `ITrustManager.isDeviceLocked(int userId, int deviceId)` | `core/java/android/app/trust/ITrustManager.aidl:38` |
| `device_secure` | `trust` | `ITrustManager.isDeviceSecure(int userId, int deviceId)` | `ITrustManager.aidl:39` |
| `ce_unlocked` | `mount` | `IStorageManager.isCeStorageUnlocked(int userId)` | `core/java/android/os/storage/IStorageManager.aidl:138` |

The services, from the same tree:

- `PowerManagerService.java:6799-6806`: `isInteractive()` clears the calling identity and checks
  nothing.
- `WindowManagerService.java:3805-3807`: `isKeyguardLocked()` is the policy's global answer, not one
  user's. `:3813-3827`: `isKeyguardSecure(userId)` needs INTERACT_ACROSS_USERS for another user
  than the caller's.
- `TrustManagerService.java:1909-1927` and `:1929-1947`: `isDeviceLocked` and `isDeviceSecure`
  answer false for any device but `Context.DEVICE_ID_DEFAULT`, 0 (`Context.java:164`), which the
  helper always passes, and resolve the user through `handleIncomingUser` with a full cross user
  check.
- `StorageManagerService.java:3470-3475`: `isCeStorageUnlocked(userId)` is the framework's own set
  of users whose CE storage it unlocked, and checks nothing. `lockCeStorage` beside it is
  STORAGE_INTERNAL's; the helper never names it.
- `KeyguardManager.java:709-715, 737-743, 805-811, 848-854`: the convenience methods return false on
  a RemoteException, which is why the helper does not use them.

The service names are `Context.POWER_SERVICE`, `WINDOW_SERVICE` and `TRUST_SERVICE`
(`Context.java:4943, 4996, 6394`) and `mount` (`StorageManager.java:322`). The user bound is
`UserHandle.MAX_SECONDARY_USER_ID`, 21473 (`UserHandle.java:134-135`). The Shell package declares
INTERACT_ACROSS_USERS and INTERACT_ACROSS_USERS_FULL (`packages/Shell/AndroidManifest.xml:242-243`);
whether the guest grants them is a guest question.

## Protocol

The first line is always `andrix-ui-state-read-v1`, and the last `end=andrix-ui-state-read-v1`.
For a user ID, the lines between are:

```
user=<id>
capabilities=interactive,keyguard_locked,keyguard_secure,device_locked,device_secure,ce_unlocked
interactive=<answer>
keyguard_locked=<answer>
keyguard_secure=<answer>
device_locked=<answer>
device_secure=<answer>
ce_unlocked=<answer>
status=<complete or unavailable>
```

Each answer is `true`, `false` or `unavailable:` and its reason: `service-absent`, `not-boolean`,
`unknown`, or the class of the exception the call threw, a SecurityException or a RemoteException
included. Exit status 0 means every answer is a boolean and the status complete, 5 that at least
one is unavailable. Any other argument list, or a user ID with a sign, a leading zero or above the
bound, prints only `error=arguments` between the two marker lines, with exit status 2. The helper
writes nothing to standard error.

`tests/component-lab/health_compose.py` parses exactly these forms as `parse_ui_state`, and an
unavailable answer is None there, never false. Any other output, status or standard error is of no
known form, a reply cut short before its end marker included.

## Reproducing the jar

`build.json` pins every input and output: the source, the JDK 25 by its `release` file, javac's
options, the class file, the r8 jar with D8's version string, D8's options, and the jar
`andrix-ui-state-read.jar`, SHA-256 `ac428bd1...` (2740 bytes). The jar is not committed.

```sh
python3 -B tests/ui-state-read/reproduce.py --jdk <JDK 25 home> --r8 <r8.jar> --work <new directory>
```

The work directory must be new and outside the repository. Before any tool starts, the script
checks every input against its pin. It then runs javac with `--release 17 -Xlint:all -Werror`,
then D8 with `--release --min-api 30`, each in its own bounded JVM, and both outputs must equal
their pins. Exit status 0 means that the jar is byte for byte the pinned one.

The host checks run with:

```sh
python3 -B -m unittest discover -s tests/ui-state-read
```

They check the pins against the source and against the composer, the calls in the source against
`signatures.json`, that the source names no mutation, the protocol in the source, and that nothing
starts before every input is checked. Given the environment, more run:

- `ANDRIX_FRAMEWORKS_BASE`, the pinned `frameworks/base`: each pinned declaration against its AIDL
  file and line.
- `ANDRIX_UI_STATE_READ_JDK` and `ANDRIX_UI_STATE_READ_R8`, the pinned tools: the rebuild.
- `ANDRIX_UI_STATE_READ_JDK`: the pinned class file run on the host JVM against the stub services
  in `hoststubs/`, for every answer, a SecurityException and a RemoteException, an absent service,
  a wrong signature and every refused argument.
- With `ANDRIX_UI_STATE_READ_DEXDUMP` too, a dexdump: the built dex holds only the pinned method
  names and reflective calls.

They write under `ANDRIX_UI_STATE_READ_WORK`, or the system's temporary directory. A host run shows
what the helper's own code does with each answer; it shows nothing about a device's services.

## The device contract

These are fixed in `tests/component-lab/health_compose.py`. The next vehicle must keep them exactly:

- **Path.** The vehicle pushes the reproduced jar to
  `/data/local/tmp/andrix-d5/andrix-ui-state-read.jar`, and the pushed file must have the pinned
  SHA-256.
- **Invocation.** `CLASSPATH=/data/local/tmp/andrix-d5/andrix-ui-state-read.jar app_process
  /system/bin UiStateRead <user>`, over `adb shell` as the shell user, for a user ID from a whole
  typed inventory. No other class, jar, argument or app_process form is admitted.
- **Admission.** Each read is bracketed: `id`, which must show UID and GID 2000 in the
  `u:r:shell:s0` domain, and `sha256sum` of the path, which must give the pinned digest, before and
  after the helper. A failed admission gives no reading.

No guest has run this helper. Its answers on the selected image, the shell's permission to ask for
another user, and whether a refused cross user call throws or answers are guest questions.
