# Package Installer payload durability

Status: an observed cold boot failure, a reproduced file durability distinction, and a candidate
source correction. The candidate has guarded host tests. It is not yet applied or compiled into
Android. No permission popup, grant or native account activation was qualified by this work.

## Observation

The ordinary shell installer reported success for three disposable, correctly signed probe APKs.
Each installed APK matched its independently checked artifact hash. A command from the first APK
also ran under the expected application UID. The consent controller then failed before any UI
request because it supplied a text notification dump to a strict binary protobuf observer.

The guest was stopped through Cuttlefish's QMP quit path, without an Android shutdown or added
global sync. On the next cold boot, Android reported missing ZIP end records and invalid APK files
for all three probes. Package Manager deleted their code paths. The original package settings and
UIDs remained visible when including unavailable packages. They were not three absent mappings.

The original APK bytes were not captured between restart and deletion. Their exact damaged
contents are unknown. No reinstall, data restoration, permission reset or keystore restoration
was used to manufacture survival. A later read only diagnostic established that the original
notification was currently absent. It did not reconstruct the historical post outcome. The
separate native identity controls retained their original keys, canaries and metadata.

## Source finding

On this pinned implementation, the shell write path calls `Session.write` with an incoming file
descriptor. `PackageInstallerSession.doWriteInternal` opens its internal writing descriptor,
preallocates, copies and closes it. There is no explicit checked sync of that writing descriptor
before the write returns. The session hold is released in the existing `finally` block.

This is distinct from the public `openWrite` route, where a caller can call `Session.fsync`.
Settings file syncs are not an explicit durability boundary for the APK payload. Later stage
renames also need their own namespace publication contract. Background writeback and subsequent
checkpoints can persist an unsynced file incidentally, but do not provide an acknowledgement bound
for this operation. The source gap is established. Its role in the original APK failure remains
an inference, not a claim that those unobserved APK bytes were zero.

## Controlled file comparison

The [descriptor fixture](../tests/installer-durability/fd-copy-probe.md) used the same 37,068 byte
public APK as plain data outside Package Manager's scan paths. It created three fresh groups, with
exclusive names and no repair or replay. All immediate byte hashes matched.

After an unclean guest stop and cold boot:

| Writer sequence | Observed result |
| --- | --- |
| Actual writing descriptor sync, file entry sync, rename and parent directory sync | Identical bytes, size and inode |
| Copy and close without file sync, rename, parent directory sync only | Same file size and inode, all bytes read back as zero |
| Copy, close and rename without a subsequent sync | Neither staging nor final directory name remained |

The checked control completed first. No sync was added after the unsynced group. The later observer
only read the original names. The files were encrypted and did not have the compression flag.
Observed defaults were a 30 second dirty expiry, 5 second writeback interval and 30 second F2FS
checkpoint interval. These are observations, not chosen product tuning.

This reproduces a consequence of missing file and namespace durability boundaries. It is not a
physical power loss test, a universal failure probability or full Package Installer qualification.
The earlier native writer directory timestamp finding is different: that trial retained all its
synced file bytes and identities.

## Candidate correction and next joins

A narrow candidate adds checked `Os.fsync(targetPfd.getFileDescriptor())` after the incoming
copy, inside the existing `try` and before cleanup releases the hold. A sync error must fail the
write, not become a successful acknowledgement. It preserves the existing fs verity correction,
permission checks, forward write route and session lifecycle.

The exact source fragment passed guarded host controls on both hold implementations. The original
fragment and eight incorrect sync variants failed their controls. These checks ran with 2 GiB
memory, zero swap, 2 CPUs, 256 tasks and core dumps disabled. The worker did not start a JVM when
those controls were unavailable in its sandbox.

The candidate also affects nonincremental data loader writes that use the same branch. It does
not fix every preexisting error path, guarantee complete input length, sync later namespace
renames or make the whole install transaction crash atomic. Exact adaptation composition, Android
compilation and runtime checks remain next steps. The consent trial remains pending, separately
from this storage diagnosis.
