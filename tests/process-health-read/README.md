# Process health read helper

The health window of the [component
transaction](../../plans/2026-10-09-component-transaction.md) needs criterion bit 1, no crash or
ANR of the user's SystemUI, from evidence the shell user can read. The shell has no command that
prints Android's exit records and current error reports with every numeric field and tells a
failed read from an empty one. This fixed program, run as the shell user, makes the two reads
through the activity manager's own Binder proxy and prints every row it was given, or why it has
none. It is a test helper for the lab shell route, not part of any image.

`ProcessHealthRead.java` is the whole program, one class. Through reflection it takes the
`activity` service from `android.os.ServiceManager`, gets its proxy from
`IActivityManager.Stub.asInterface`, and calls two methods by their exact AIDL signatures:

- `getHistoricalProcessExitReasons("com.android.systemui", 0, 0, user)`, SystemUI's exit history
  for one user with no PID and no count filter;
- `getProcessesInErrorState()`, the whole list of processes now crashing or not responding.

Right before and right after each call it samples `SystemClock.elapsedRealtime()` and
`System.currentTimeMillis()`. It reads each record's fields by their public getters and fields. It
has no path that kills, crashes, stops or restarts a process, clears or writes the exit history,
sets a process state summary, or opens a trace file or a tombstone. SystemUI is fixed in the
source; the separate ordinary error control is a later part's build.

## Source basis

`signatures.json` pins both calls against the pinned framework tree, with the AIDL file's SHA-256,
each declaration's lines and their exact text, and every getter, field, constant and permission
check below by its line:

| Read | Call | AIDL |
| --- | --- | --- |
| `history` | `IActivityManager.getHistoricalProcessExitReasons(String packageName, int pid, int maxNum, int userId)` | `core/java/android/app/IActivityManager.aidl:804-805` |
| `current-errors` | `IActivityManager.getProcessesInErrorState()` | `IActivityManager.aidl:346` |

The service is `Context.ACTIVITY_SERVICE`, `activity`
(`core/java/android/content/Context.java:5027`), as `ActivityManager.getService()` takes it
(`core/java/android/app/ActivityManager.java:6140-6148`).
The service side, in `services/core/java/com/android/server/am/`:

- `ActivityManagerService.java:11069-11104`, the history. It refuses an isolated caller (:11071)
  and `USER_ALL` or `USER_CURRENT` (:11074-11076). Another user than the caller's needs
  INTERACT_ACROSS_USERS or its full form (:11081-11082, `UserController.java:3376-3471`), and the
  shell is refused a user with DISALLOW_DEBUGGING_FEATURES (`UserController.java:3464-3468`).
  Another package than the caller's needs DUMP, else a SecurityException
  (`ActivityManagerService.java:11196-11207`), so a whole history read of SystemUI shows that the
  shell held DUMP. A package of no UID for the user gives no rows at all (:11091), so an empty
  history is complete only for a user whose SystemUI package UID the process discovery reads.
- `AppExitInfoTracker.java:594-606, 1418-1470`: one record container per package and package UID,
  every record sorted most recent first. `NativeTombstoneManager.java:299-363` (in
  `services/core/java/com/android/server/os/`) only attaches tombstones to existing rows when the
  count is 0 (:334). The container keeps at most `config_app_exit_info_history_list_size`, 16
  (`core/res/res/values/config.xml:6446`), dropping the oldest
  (`AppExitInfoTracker.java:1474-1508`).
- `AppExitInfoTracker.java:298-331, 455-472, 511-516, 1803-1818`: the history is written
  asynchronously on a handler, an existing record's reason, subreason, status and time are
  overwritten in place by a later kill note, and zygote or lmkd may change a record's reason or
  status within 300 seconds of its time. `:287-296, 728-767`: the records of earlier boots are
  loaded from storage after the system is ready. History is a bounded, asynchronous record kept
  in wall time.
- `ActivityManagerService.java:10860-10910`, the current list. It refuses an isolated caller
  (:10861). Without INTERACT_ACROSS_USERS_FULL it holds only the caller's own user's processes
  (:10866-10868, 10876-10878), and without DUMP only the caller's own UID's (:10870-10871,
  10879-10881); it never says what it left out. It reports a process only while it is attached
  and crashing or not responding (:10885), and answers null, never an empty list, when none is
  (:10863, 10909; `ActivityManager.java:4015-4028`). `Parcel.java:2369-2381, 4029-4041` carry the
  null to the caller.
- `AppErrors.java:817-862`: a crash report holds the condition, process name, PID, the package
  UID and the messages; `AppErrors.java:495-502` clears it when the process is killed.

The Shell package declares DUMP, INTERACT_ACROSS_USERS and INTERACT_ACROSS_USERS_FULL
(`packages/Shell/AndroidManifest.xml:172, 242-243`), whose protection levels are
`signature|privileged|development` and `signature|installer|module|role`
(`core/res/AndroidManifest.xml:5814-5815, 3870-3871`). Whether the guest grants them is a guest
question. `getList` is declared in the package private `BaseParceledListSlice`
(`core/java/android/content/pm/BaseParceledListSlice.java:46, 165`); the helper takes it from the
public `ParceledListSlice`, whose visibility bridge the host runs exercise.

## Protocol

The first line is always `andrix-process-health-read-v1`, and the last the end marker
`end=andrix-process-health-read-v1 lines=<n> sha256=<hex>`: the number of lines before it and the
SHA-256 of their bytes. For a user ID, the lines between are:

```
user=<id>
package=com.android.systemui
capabilities=history,current-errors
history sample=before elapsed=<ms> wall=<ms>
history status=OK count=<N>
history row=<i> timestamp=<ms> pid=<pid> real-uid=<uid> package-uid=<uid> defining-uid=<uid> user=<id> process=<text> reason=<r> subreason=<s> status=<s>
history sample=after elapsed=<ms> wall=<ms>
current-errors sample=before elapsed=<ms> wall=<ms>
current-errors status=OK count=<M> returned=<null or list>
current-errors entry=<i> condition=<c> pid=<pid> uid=<uid> process=<text> tag=<text> tag-length=<n> short=<text> short-length=<n> long=<text> long-length=<n> stack=<text> stack-length=<n>
current-errors sample=after elapsed=<ms> wall=<ms>
status=<complete or unavailable>
```

- Every time is a decimal number of milliseconds: `elapsed` since boot, `wall` and `timestamp`
  since the epoch. No time is formatted, so no time zone enters a reply.
- A text is its UTF-8 bytes, letters, digits, `.`, `_` and `:` as themselves and every other byte
  as `%XX`, or `-` for null. A process name above 256 UTF-16 units is an overflow; a diagnostic
  string is cut to 256 units, never inside a surrogate pair, with its whole length, or `-1` for
  null.
- A read that fails prints `status=ERROR reason=<reason>` or, for an absent service,
  `status=UNAVAILABLE reason=service-absent`, and no rows: the class of the exception it threw, a
  SecurityException or a RemoteException included, `overflow` above 64 rows, or another form of
  reply. It is never `count=0`.
- `returned=null` is the service's answer that no process is in an error state; `returned=list`
  with no entry is a form the service never gives.

Exit status 0 means both reads are whole and the status complete, 5 that at least one is not.
Any other argument list, or a user ID with a sign, a leading zero or above 21473, prints only
`error=arguments` before the end marker, with exit status 2, and a clock that cannot be read
`error=clock`, with 3. The helper writes nothing to standard error.

`tests/component-lab/process_health.py` parses exactly these forms. A reply cut short, without its
end marker, or whose end marker does not count and digest its lines, or whose count is above the
bound, is unavailable evidence; any other output, status or standard error has no known form.
`tests/component-lab/health_witness.py` judges the readings.

## Reproducing the jar

`build.json` pins every input and output: the source, the JDK 25 by its `release` file, javac's
options, the class file, the r8 jar with D8's version string, D8's options, and the jar
`andrix-process-health-read.jar`, SHA-256 `b74f0aad...` (6072 bytes). The jar is not committed.

```sh
python3 -B tests/process-health-read/reproduce.py --jdk <JDK 25 home> --r8 <r8.jar> --work <new directory>
```

The work directory must be new and outside the repository. Before any tool starts, the script
checks every input against its pin. It then runs javac with `--release 17 -Xlint:all -Werror`,
then D8 with `--release --min-api 30`, each in its own bounded JVM, and both outputs must equal
their pins. Exit status 0 means that the jar is byte for byte the pinned one. Compiling needs no
`android.jar`: the helper reaches the framework only by reflection.

The host checks run with:

```sh
python3 -B -m unittest discover -s tests/process-health-read
```

They check the pins against the source and against the reader, the calls and their arguments in
the source against `signatures.json`, that the source names no mutation and is one class, the
protocol in the source, and that nothing starts before every input is checked. Given the
environment, more run:

- `ANDRIX_FRAMEWORKS_BASE`, the pinned `frameworks/base`: each pinned declaration against its file
  and line.
- `ANDRIX_PROCESS_HEALTH_READ_JDK` and `ANDRIX_PROCESS_HEALTH_READ_R8`, the pinned tools: the
  rebuild.
- `ANDRIX_PROCESS_HEALTH_READ_JDK`: the pinned class file run on the host JVM against the stub
  services in `hoststubs/`, for whole rows, a complete empty reply, an empty list, a denial, a
  RemoteException, an absent service, a wrong signature, an overflow, a failing getter, bounded
  strings and every refused argument. Each reply is parsed by the reader's parser, and the
  simulated guest's form must be the helper's own, byte for byte.
- With `ANDRIX_PROCESS_HEALTH_READ_DEXDUMP` too, a dexdump: the built dex holds only the pinned
  names and reflective calls.

They write under `ANDRIX_PROCESS_HEALTH_READ_WORK`, or the system's temporary directory. A host run
shows what the helper's own code does with each reply; it shows nothing about a device's services.

## The device contract

These are fixed in `tests/component-lab/process_health.py`. The next vehicle must keep them
exactly:

- **Path.** The vehicle pushes the reproduced jar to
  `/data/local/tmp/andrix-d5/andrix-process-health-read.jar`, and the pushed file must have the
  pinned SHA-256.
- **Invocation.** `CLASSPATH=/data/local/tmp/andrix-d5/andrix-process-health-read.jar app_process
  /system/bin ProcessHealthRead <user>`, over `adb shell` as the shell user, for each lab user, a
  user ID from a whole typed inventory. No other class, jar, argument or app_process form is
  admitted.
- **Admission.** Each read is bracketed: `id`, which must show UID and GID 2000 in the
  `u:r:shell:s0` domain, and `sha256sum` of the path, which must give the pinned digest, before and
  after the helper. A failed admission gives no reading.

No guest has run this helper. Until one qualifies it, the reader's positive paths are qualified by
host fixtures only. Its replies on the selected image, the shell's grants, whether reflection
reaches the hidden interface and the slice's list from `app_process`, how long a live report shows,
how late an exit row is published or updated, and whether the elapsed and wall samples agree with
the lab's clock reads are guest questions.
