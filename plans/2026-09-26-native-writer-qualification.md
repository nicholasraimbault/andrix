# Native identity writer qualification

Status: bounded test vehicle implemented, host checked, compiled in a separate Android image,
and exercised through the real manager in a disposable guest. This follows the [reader and recovery observations](2026-09-26-native-identity-boot-recovery.md).
Native execution remains disabled in every image, including this test image.

## Purpose

Exercise the unchanged `NativePrincipalManager` writer inside `system_server`, under the real
filesystem and SELinux policy. Earlier device observations consumed controlled root written
records. They did not execute this manager's publication transaction.

The [optional fixture](../tests/native-identity/writer/README.md) selects one fixed ordinary test
package. It receives its app ID, user serial, version and certificate digest from the actual
Android authorities. A root test caller is not production owner designation. No package, UID,
user, signer, filesystem path or credential profile is accepted as a caller selected authority.
The fixture exposes no initializer, deletion, retirement completion or reservation release.

## Keep test authority separate

The normal framework admission guard rejects any writer fixture adaptation. Lab admission must
be explicit and match the exact optional patch and helper. The normal image already qualified at
`fec0da7` contains the real manager but neither the fixture class nor its command marker. This was
checked in its sealed `services.jar`.

The root caller and debuggable build checks are additional checks, not the separation boundary.
The lab image built at `6caeedd` contains both the route and helper in its actual `services.jar`.
The manager and fixture source adaptations were reversed only after the producer scope was empty.
The existing CE and package verity adaptations remained unchanged. Its userdata remains lab state,
including later diagnostic continuations. A persisted slot does not identify its test origin.
Keep its lineage, exact record and image/APK producers in the external operation ledger.

## Keep the original operation

A server instance and caller nonce identify one retained operation. Selection is separate from
preparation. New reservation and rebinding after restart are explicit different intents.
Continuation uses the original selection and handle. A stale instance refuses; it cannot silently
make another selection or reconstruct an old live handle from a name or ID.

Manager calls run outside the fixture monitor. The in flight marker precedes each call, and the
response is captured before another attempt may start. Attempt numbers distinguish current work
from older cached observations. First and latest acknowledgements are separate. A writer return
is saved before any later metadata observation, so observation failure cannot erase it.

A prepare exception can leave a pin without a returned handle. A commit can throw after writing.
Both retain uncertainty and the original request. A returned unexpected handle is retained
alongside the original, and an intent mismatch blocks advancement. Rebinding requires the same
handle and complete record to be compared before commit. A commit acknowledgement alone is not
success when an intent violation or failed comparison is reported.

## Bounded evidence

Host tests use the real manager and store below Android facades. They cover exact request reuse,
uncertain writes, missing prepare results, abnormal exits, acknowledgement preservation, reply
concurrency, mismatched handles and records, and explicit PENDING rebinding. The qualification
check fails without a JDK. It does not turn skipped Java execution into success.

An exact source application control proved that normal admission refuses the lab route, explicit
lab admission accepts only the pinned source, and reversal preserves the existing CE and package
verity adaptations. These are source and host checks, not Android writer execution.

The strict observer requires the captured instance, nonce, selection intent and independent Android
identity. It distinguishes direct commit replies from status based reconciliation using the issued
request ledger, not the reply's self description. Exact paired record comparison also rejects extra
slot directories, backup files, missing copies and symbolic paths. The host checks feed actual
fixture replies into this observer.

The disposable device trial completed these separately closed phases:

| Phase | Observed result |
| --- | --- |
| Caller and missing store controls | The actual shell caller was refused. The root test caller could obtain metadata, but preparation without an initialized store was not acknowledged. The diagnostic held set remained empty. A controlled original A record was then staged with checked writing descriptor sync, after the captured PMS writer exited. |
| Actual publication | The real manager selected and prepared C, then published its binding through `system_server`. A deliberately discarded reply was reconciled through the original instance and nonce. Another commit on the same handle returned true without changing the identity or counter. |
| Cold restoration and explicit rebind | The old server instance was refused. The restored C pin met the PENDING precondition. A fresh explicit rebinding operation retained the same record and native ID, and both commit and same handle retry were acknowledged. |
| Actual I/O refusal | With the existing C slot directory temporarily lacking write permission, the real manager returned false. The original handle and UID hold remained, and the records did not change. Restoring only that same directory's mode allowed commit and retry on the original handle to return true. |

The guest and host checks required the exact six files and four directories, paired canonical
records, the original lineage and the expected counter transition. The original A records retained
their bytes and metadata. Both original APK keys still signed fresh challenges verified on the host,
and the original canary identity and content matched. C's install-existing mutation was refused,
while the peer's completion succeeded in the same boot. There was no key/data restore, repeated
initialization or final UID release.

The discarded reply was intentional fixture behavior. It was not a Binder failure. The cold
restart demonstrated this persisted binding and a new designation decision, not continuation of
an old live handle or a storage power loss guarantee.

The image producer is `6caeedd`; the observer and complete snapshot controls are `5185164` and
`d315361`. The lab services jar SHA-256 is
`82d0f09dffaf8c38eefcbbeb9d49619793c4b7b6d871391614dbc0dd8fb110e2`.
The closed image seal is
`ba5e36b5f0e54b8549612585853779453f5fc1457aea9457dcea26616f258a8e`.
The publication and cold rebinding phase seals are respectively
`ce24ecc29eb941ce708f39cd70daf5e3362e6d5923b8319b47f69a00f218ca6e` and
`5fd85e448032035ab15a65e4d926c847435fc842f2e06ac6c0735f23261953b6`.
The real I/O refusal phase seal is
`41d2b31c42021e39956eb6a05bbe88b81de32e4cb25ec11229acae969c9dc994`.
The build and fixture scopes were retired. Raw captures and operating records remain private.

## Failed directory time bookend

A later cold continuation failed before its planned I/O fault. C's directory retained the same
inode, mode, ownership, size and label, but its modification and change times returned to an
earlier observed value. All six files retained their current bytes, inodes and metadata. The
original A records and canaries also matched. This failure remains separate from the successful
writer and later I/O refusal phases.

Read only continuation confirmed stable current records without invoking the writer or repairing
metadata. The observed F2FS mount used inline directory entries, barriers and `fsync_mode=posix`.
Checkpointing was enabled at the diagnostic and I/O trial bookends. The pinned kernel source at
`3ec022196c4e` distinguishes a checkpoint of directory entries from writeback of the directory
inode's in memory times. The changed file inode numbers survived alongside older directory times.
That supports stale timestamp fields as the explanation, rather than rollback of the whole
directory block. It is a source supported inference, not a general filesystem guarantee.

The Cuttlefish stop path used QMP quit, not an Android shutdown with a filesystem sync. No global
sync was added to make the writer trial pass. The old failed check was retained, and subsequent
work used the independently observed current baseline without changing record data. Full directory
timestamp persistence is not qualified. The kernel also permits successful sync returns while
userdata checkpointing is disabled. A current checkpoint observation is not a production storage
lease, and that authority join remains open before activation.

Two subsequent harness checks stopped before the I/O fault because they expected empty diagnostic
output from `vdc` and a context string without the kernel's terminating NUL. The corrected controls
accept only the exact observed diagnostic forms and context, not arbitrary errors or labels.
Those attempts remain failed. The successful I/O trial then verified the actual system UID and
filesystem UID, absence of DAC override, the original handle, unchanged records, and checkpoint
mode before and after the transaction. It is an access refusal test, not a writeback failure test.

This first writer vehicle does not qualify mid publication crashes, process loss in CREATING
without a body, retirement tails, unknown counters, multiple subjects, grant preservation or
production designation. Such tails remain held until an actual owned recovery continuation exists.
A clean restart does not prove storage power loss behavior or final resource retirement.
