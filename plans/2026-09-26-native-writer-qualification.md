# Native identity writer qualification

Status: bounded test vehicle implemented and host checked. Android compilation and the writer
runtime trial are pending. This follows the [reader and recovery observations](2026-09-26-native-identity-boot-recovery.md).
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
The actual lab artifact still needs compilation and inspection. Its userdata remains lab state,
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

## Bounded evidence and next checks

Host tests use the real manager and store below Android facades. They cover exact request reuse,
uncertain writes, missing prepare results, abnormal exits, acknowledgement preservation, reply
concurrency, mismatched handles and records, and explicit PENDING rebinding. The qualification
check fails without a JDK. It does not turn skipped Java execution into success.

An exact source application control proved that normal admission refuses the lab route, explicit
lab admission accepts only the pinned source, and reversal preserves the existing CE and package
verity adaptations. These are source and host checks, not Android writer execution.

The disposable device trial must independently verify caller refusal, the recorded starting store,
the actual selected Android identity, publication and same handle retry, unchanged unrelated
bindings, and PENDING restoration followed by a fresh explicit rebind. A deliberately discarded
reply can test reconciliation. It must not be relabeled as a Binder failure or power loss.

This first writer vehicle does not qualify mid publication crashes, process loss in CREATING
without a body, retirement tails, unknown counters, multiple subjects, grant preservation or
production designation. Such tails remain held until an actual owned recovery continuation exists.
A clean restart does not prove storage power loss behavior or final resource retirement.
