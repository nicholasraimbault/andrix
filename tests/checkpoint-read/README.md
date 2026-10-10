# Checkpoint read helper

The shell observer of the [component transaction](../../plans/2026-10-09-component-transaction.md)
must know whether the current boot's userdata checkpoint has committed. The shell user cannot run
`vdc`. Instead, this fixed program, run as the shell user, asks the framework's storage service two
questions and prints the answers. It is a test helper for the lab shell route, not part of any
image.

`CheckpointRead.java` is the whole program. Through reflection it takes the `mount` service from
`android.os.ServiceManager`, gets its `IStorageManager` proxy, and calls `supportsCheckpoint()` and
`needsCheckpoint()` by name. Reflection lets it compile without the framework's hidden classes. The
proxy is the device's own, so the helper never names a Binder transaction number. It takes no
arguments and has no path that starts, commits, aborts or prepares a checkpoint.

## Source basis

From the pinned framework tree:

- `core/java/android/os/storage/IStorageManager.aidl`, SHA-256 `01c230e0…`, lines 150 to 153:
  `supportsCheckpoint()` takes no permission, and `needsCheckpoint()` is annotated with
  `@EnforcePermission("MOUNT_FORMAT_FILESYSTEMS")`.
- `services/core/java/com/android/server/StorageManagerService.java`, SHA-256 `b3c08edd…`:
  - `supportsCheckpoint()` at line 3383 returns `mVold.supportsCheckpoint()` and checks nothing.
  - `needsCheckpoint()` at line 3424 enforces MOUNT_FORMAT_FILESYSTEMS, then returns
    `mVold.needsCheckpoint()`. Its comment reads: "Check if we should be mounting with checkpointing
    or are checkpointing now".
  - `startCheckpoint()` at line 3395 admits the shell's UID. The helper never calls it, and the
    observer's allowlist refuses every `sm` command and every other `app_process` invocation.

vold, which answers both calls, was not inspected. Neither was the Shell package's manifest. The
guest showed that the shell's call of `needsCheckpoint()` passes its permission check: it gave an
answer, not a SecurityException.

## Protocol

The first line is always `andrix-checkpoint-read-v1`. Then:

| Exit | Output after the header | Meaning |
| --- | --- | --- |
| 0 | `supports=<b>` and `needs=<b>`, each `true` or `false` | Both calls answered |
| 5 | The same two lines, at least one `error:` and the failure: `not-boolean`, `unknown` or an exception class | A call failed |
| 2 | `error=arguments` | Arguments were given |
| 3 | `error=service-absent` | No `mount` service |
| 4 | `error=lookup:` and an exception class | The reflective lookup failed |

The helper writes nothing to standard error. `scripts/proof/systemui_sessions.py` parses exactly
these forms as `checkpoint_read`. Any other output, status or standard error is of no known form,
such as the runtime's own error or warning. Every reply but exit 0 is a refusal, which carries no
answer to rely on.

## Reproducing the jar

`build.json` pins every input and output. They are the source, the JDK 25 by its `release` file,
javac's options, the class file, the r8 jar with D8's version string, D8's options, and the jar
`andrix-checkpoint-read.jar`, SHA-256 `ae6743f6…`. The jar is not committed.

```sh
python3 -B tests/checkpoint-read/reproduce.py --jdk <JDK 25 home> --r8 <r8.jar> --work <new directory>
```

The work directory must be new and outside the repository. Before any tool starts, the script checks
every input against its pin. It then runs javac with `--release 17 -Xlint:all -Werror`, then D8
with `--release --min-api 30`. Each runs in its own JVM, with a capped heap, metaspace and code
cache, the serial collector and one compiler thread, a time limit, no core dumps and a file size
limit. Both outputs must equal their pins. Exit status 0 means that the jar is byte for byte the
pinned one. The record is `build-record.json` in the work directory. The class file and the jar
depend on neither the paths nor the JVM options.

The host checks run with:

```sh
python3 -B -m unittest discover -s tests/checkpoint-read
```

They check the pins against the source and against the observer, the protocol in the source, and
that nothing starts before every input is checked. The real rebuild runs only when
`ANDRIX_CHECKPOINT_READ_JDK` and `ANDRIX_CHECKPOINT_READ_R8` name the pinned tools. It writes under
`ANDRIX_CHECKPOINT_READ_WORK`, or the system's temporary directory.

## The device contract

These are fixed in `scripts/proof/systemui_observer.py`. D5's vehicle must keep them exactly:

- **Path.** The vehicle pushes the reproduced jar to
  `/data/local/tmp/andrix-d3/andrix-checkpoint-read.jar`. The pushed file must have the pinned
  SHA-256. The path is the one the D3 guest qualified, so the invocation stays byte for byte the
  qualified one.
- **Invocation.** The only one the observer may run is
  `CLASSPATH=/data/local/tmp/andrix-d3/andrix-checkpoint-read.jar app_process /system/bin CheckpointRead`,
  over `adb shell` as the shell user, never after `adb root`. The allowlist holds no other class,
  jar, argument, prefix or app_process form.
- **Admission.** The observer never pushes. Inside one boot and one framework instance it reads:
  - `id`, which must show UID and GID 2000 in the `u:r:shell:s0` domain;
  - `sha256sum` of the path, which must give the pinned digest with nothing on standard error;
  - the helper;
  - `id` and the digest again.

  A failed admission stops the read before the helper runs. A change during the run gives no fact.
  The reads before and after cannot exclude a swap of the file and a swap back between them. Only
  the shell user or root could make such a swap on the lab guest.
- **Transport.** The run function returns only for a command that completed. It returns the
  integer exit status, with standard output and standard error kept apart and whole. A timeout or
  a lost connection must raise. The observer treats any other return as incomplete and gives no
  fact.

## What a guest has shown

One D3 guest ran on the chosen test image. It was a fresh guest in its first boot, with SELinux
enforcing. `id` showed `uid=2000(shell)` in `u:r:shell:s0`. The on device digest after the push was
the pinned one. The helper ran three times, after boot completion, between unchanged reads of the
boot ID and of system_server's PID and start time. Each time it exited 0 with nothing on standard
error and printed exactly:

```
andrix-checkpoint-read-v1
supports=true
needs=false
```

- The first run followed the baseline reads.
- The second was taken while a staged SystemUI session was ready. That session did not make
  `needs` true in the same boot.
- The third came at the end of the run.

`sm supports-checkpoint` read `true` beside each run. `vold.checkpoint_committed` read `1`. That
property is never a checkpoint fact, and the observer does not read it.

These captures qualify only the committed answer and the admission reads, on that image, as the
shell user, after boot completion. The following come from the source alone. No guest has shown
them:

- the pending answer, `needs=true`;
- a device without support;
- every refusal;
- a reading before boot completion;
- any boot after an activation.

D5's activation boot must capture the pending answer, and then the change to the committed one.
