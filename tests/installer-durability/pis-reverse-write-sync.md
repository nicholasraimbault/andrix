# Package Installer reverse write payload synchronization

Status: host qualified candidate with an ordered framework companion. The files in this
directory are the host tested candidate record. The complete host module,
`test_pis_reverse_write_sync.py`, was compiled and run with JDK 25 inside the required
bounds (2 GiB memory, no swap, 2 CPUs, 256 tasks) and passed all 15 tests: both hold
branches, the red pinned fragment, the eight wrong placements, the checked descriptor sync
alternative and the refusal to run with assertions disabled. An independent source review
accepted the five line change as minimal and found the facades consistent with the Android
sources it checked. The same patch is applied only through the
[ordered companion](#ordered-companions) after package verity. The later Android image at
`cac0ba6` compiled it, and final DEX inspection verified sync on the actual writing descriptor
before close and hold release. A bounded cold boot kept the original probe APKs, UIDs and bytes.
This does not qualify every installer route, later rename durability or physical power loss.

## Source gap

In the pinned Package Installer, `PackageInstallerSession.write(name, offset, length, fd)`
with a caller descriptor uses reverse mode. `doWriteInternal` registers a placeholder hold,
opens the staged file `O_CREAT | O_WRONLY`, preallocates when a length is given and copies
the caller's bytes with `FileUtils.copy`. Its `finally` block then closes both descriptors
quietly and removes the hold. Nothing calls fsync.

The hold is a `FileBridge`, or a `RevocableFileDescriptor` when `fw.revocable_fd` is set.
`PackageInstaller.ENABLE_REVOCABLE_FD` defaults to false. While the hold is registered,
`assertNoWriteFileTransfersOpenLocked` refuses to seal the session.

The public `openWrite` contract leaves durability to the writer: it may call
`Session.fsync(OutputStream)` on the stream it received. That method accepts only
`openWrite` streams. A reverse mode caller never receives the target descriptor, so it has
no way to ask for the bytes written by the system server to be persisted.

Three install routes reach this copy. According to a separate review of
`PackageManagerShellCommand`, which this vehicle does not pin, the package shell writes each
split through `write` with a caller descriptor, both for a plain streamed install from its
input and for an install from a pushed file. Nonincremental data loader sessions reach the
same copy through `FileSystemConnector.writeData`. Incremental sessions do not: the pinned
source rejects `write` for every data loader session and creates the file system connector
only when the session is not incremental. The candidate therefore covers the plain streamed,
pushed file and nonincremental data loader routes, and not incremental installs.

The inspected Package Installer path adds no barrier for these payload bytes. The same
separate reading found none in the later stage directory rename or Package Manager
settings writes. Kernel writeback and filesystem checkpoints may persist the bytes in time,
but nothing makes that part of the write acknowledgement.

A bounded emulator trial stopped the virtual machine abruptly after reverse mode installs
had reported success. After a cold boot, the APK files could not be parsed and Package
Manager removed them, while their package settings remained. The bytes were not read before
removal, so the cause is not established. The gap above is consistent with that result. It
is not proved to be its cause.

Two existing behaviors stay unchanged. A copy that ends early because the caller's stream
ends is still accepted; rejecting a truncated file is left to later APK parsing. A failure
before the copy (name check, open, chmod, allocation or seek) skips the `finally` block. The
hold stays registered, so that session can no longer be sealed, and a target opened before
the failure is not closed on that path.

## Candidate

[`pis-reverse-write-sync.candidate.patch`](pis-reverse-write-sync.candidate.patch) adds one checked
`Os.fsync(targetPfd.getFileDescriptor())` directly after a successful copy, inside the
existing `try` block:

- Order: copy, fsync on the writing descriptor, close target, close caller descriptor,
  release the hold, return.
- The hold still blocks sealing while fsync runs. fsync runs outside the session lock and
  the progress lock.
- An fsync error becomes `ErrnoException`, then `IOException` from `doWriteInternal`, then
  the `write` failure. The write never reports success after a failed fsync.
- A copy error skips fsync. The unchanged `finally` block closes both descriptors, releases
  the hold and lets the copy error propagate.
- `openWrite`, `FileBridge`, `RevocableFileDescriptor`, sealing, callers, permissions and
  activation are unchanged. There is no policy, verity, signature, timer or capability
  change.

The candidate syncs the descriptor that performed the writes and propagates its result.
The rejected alternatives each lose part of that. `FileUtils.sync` returns false on error,
`sync(2)` reports no error, and a directory fsync does not cover the file's data. Reopening
the file by its pathname is avoided for two reasons: the name could refer to a different
file by then, and error reporting for these writes belongs to the descriptor that made them.
The reason is not that a descriptor opened for reading could not flush the file.

Not claimed: directory entry or rename durability, Package Manager settings ordering,
whole install atomicity, power loss or crash consistency, or any general PackageInstaller
API guarantee.

The namespace gap is concrete. The payload is written inside the session's stage directory,
which is later renamed to the final code path. This change syncs neither the stage entry
nor that rename. After an abrupt stop, the synced payload can survive under the old stage
name while the final code path is absent. Such an outcome does not refute the narrow
descriptor sync, but it still fails install durability.

## Provenance

[`pis-reverse-write-sync.candidate.json`](pis-reverse-write-sync.candidate.json) binds the candidate
to the accepted [package verity adaptation](../../patches/grapheneos-2026081300/package-verity.json).
The base bytes are that adaptation's candidate. Reversing its patch yields the pinned
upstream bytes. The fs-verity method in the candidate is byte identical to the
[accepted fixture](../staged-apk-verity/PackageInstallerMethod.java.inc).

The fixtures are exact byte ranges with their original license headers:

- `PisReverseWriteFragment.base.java.inc` and `.candidate.java.inc`: from `write` through
  `doWriteInternal`, plus `assertNoWriteFileTransfersOpenLocked`. They differ only by the
  five inserted lines. The base range is the same in upstream and in the verity candidate.
- `PisFileUtilsSync.pinned.java.inc`: the pinned `FileUtils.sync`.

`pis_reverse_write_sync.py` is check only. It recognizes the base or the exact candidate,
rebuilds both directions in private scratch with `patch --fuzz=0` and compares every
fragment. It never writes to an Android checkout and does not check the Git revision.
Check a checkout with:

```
python3 tests/installer-durability/pis_reverse_write_sync.py --source-root /path/to/android
```

## Host harness

`PisReverseWriteHarness.java.in` receives the exact fragments. Only Android dependencies are
facades. They record calls, back descriptors with real host files and inject failures.
The inserted source alone decides whether a write reports success. Several facades model
classes this vehicle does not pin, such as `ErrnoException`, `IoUtils`, `FileBridge`,
`RevocableFileDescriptor`, `ExceptionUtils` and two `PackageManagerService` constants.
They model only the behavior noted beside them.

Both hold branches run four cases:

- A positive reverse write checks the exact event order and that fsync used the same
  descriptor object that received the copy. It also checks that the real sealing check
  refused while fsync ran, that no session lock was held, and that the staged bytes match.
- An injected `EIO` fsync failure must fail `write` with that error, then close both
  descriptors and release the hold.
- An injected partial copy failure must propagate unchanged, with no fsync attempted and
  the same cleanup. Its missing progress update is a property of this harness case only:
  the facade copy reports progress once, at the end, while the real `FileUtils.copy`
  reports every 512 KiB, so a real failure can follow earlier progress reports.
- A forward (`openWrite` shape) control must stay unchanged: no fsync, target handed to the
  hold, sealing still refused.

The pinned fragment must fail the positive case. Wrong placements must fail with a named
check: swallowed error, `FileUtils.sync` with its result ignored, reopened read descriptor,
stage directory, caller descriptor, under the session lock, first in `finally` and after
close. A checked `FileDescriptor.sync()` on the writing descriptor is accepted. The harness
refuses to run without `-ea`, and its checks do not use Java `assert`.

## Running

Source and provenance checks, with the pinned source checks enabled:

```
ANDRIX_SOURCE_ROOT=/path/to/android \
    python3 -B -m unittest discover -s tests/installer-durability -p 'test_pis_*.py' -v
```

JVM checks start a JDK only when this process's cgroup, or an ancestor, limits memory to
2 GiB or less, swap to 0, CPU to 2 and tasks to 256. Both core dump limits must also be zero.
Otherwise they are skipped with the reason. A systemd scope with `MemoryMax=2G`,
`MemorySwapMax=0`, `CPUQuota=200%`, `TasksMax=256` and `LimitCORE=0` provides these bounds. Set `JAVAC` and `JAVA`, or put a JDK on `PATH`. Set
`ANDRIX_REQUIRE_JVM_CHECKS=1` so that a missing JDK or missing bounds fails instead of
skipping. Keep the complete output: failure messages include the full javac and java
output. The PIS module has 15 tests. Including the separate descriptor fixture gives 16 installer
checks. The retained candidate record's `integrated: false` is historical vehicle metadata, not a
checkout state oracle. Use the canonical companion adapter for current component states.

## Ordered companions

[`package-installer-payload-sync.patch`](../../patches/grapheneos-2026081300/package-installer-payload-sync.patch),
its profile and `scripts/proof/package_installer_payload_sync.py` apply this patch as a
framework companion ordered after [package verity](../staged-apk-verity/README.md):

1. Package verity comes first. Its patch and profile bytes are unchanged.
2. The payload sync candidate is derived from the pinned upstream through the exact package
   verity candidate, then this exact patch. Any other bytes are refused, including this
   patch without package verity.
3. Payload sync apply refuses unless package verity is applied. Payload sync revert removes
   only the five added lines and keeps package verity. Both are idempotent.
4. The package verity inspector reports the combined bytes as applied package verity. Its
   apply keeps the combination, and its revert refuses until payload sync has been
   reverted. Its `--require-adapted` means the verity correction is present, alone or in
   the exact combination; it does not require payload sync. Payload sync's own
   `--require-adapted` requires the exact combination, so a build that wants both requires
   both.
5. Both adapters run the whole framework fence, check the pinned revision and file
   containment, refuse unknown bytes and write fresh evidence with the state before and
   after the action. Each report names every component with its state and profile hash:
   package verity reports `payload_sync_companion`, and payload sync reports
   `package_verity_companion`.

The canonical patch is byte identical to `pis-reverse-write-sync.candidate.patch`. Its
profile pins the package verity profile bytes and binds this directory's candidate record
and fragment fixtures. The adapter also checks that both tested source ranges occur
exactly once in the bytes it applies. The files here remain the host test record, not a
second integration route.

Composition checks cover the three known states, unknown bytes, profile and fixture drift,
wrong revisions and paths, apply and revert ordering, idempotence and the unchanged
refusal of other framework changes. They run with synthetic bytes and, when
`ANDRIX_SOURCE_ROOT` is set, with the pinned bytes:

```
ANDRIX_SOURCE_ROOT=/path/to/android \
    python3 -B -m unittest scripts.proof.tests.test_package_installer_payload_sync -v
```

Source provenance, composition checks, the guarded JVM harness and independent review preceded
Android compilation and the [bounded runtime control](../../plans/2026-09-27-package-installer-durability.md).
The original artifact marker failure remains recorded: the normal image's shrinker removes
inactive native creation paths, while the actual installer sync is present in DEX. Directory entry,
rename, other artifacts, settings durability and wider failure coverage remain separate gaps.

## Classifying runtime outcomes

A trial that stops the device abruptly after acknowledged installs classifies each package
after the cold boot:

1. Final code path present, parseable and byte identical to the input. This is the only
   install durability pass.
2. Namespace orphan or missing: the final code path is absent. The payload may survive
   under the old stage name, or not at all. With the candidate applied this does not refute
   the descriptor sync, but it is still an install durability failure.
3. Final code path present but unparseable. With exact input and no later rewrite or storage
   rollback, this fails the intended payload durability result and needs diagnosis. A checked
   fsync syscall alone does not establish checkpoint authority or hardware persistence.

The earlier trial, run without the candidate, observed the third class: the code paths were
present, but their APKs could not be parsed before Package Manager removed them. Passing
the narrow descriptor sync checks is not an overall install durability pass.
