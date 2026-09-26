# Optional PMS writer fixture

This is a separate lab framework adaptation. It calls the real
`NativePrincipalManager` for one ordinary test package, `dev.andrix.proof.principalclosed`.
The native execution factory stays disabled, including in this test image.
There is no initialization, execution, permission, home, deletion, retirement marker or
final release command. Test userdata must remain disposable lab state, never product state.

The caller check requires actual Binder UID 0 and a debuggable build. This is not the separation
boundary. The route and helper are absent from normal source inputs. The shared framework guard
refuses even the exact lab adaptation unless the caller explicitly requests lab admission.
The optional patch changes only `PackageManagerShellCommand` and adds this helper. It does not
change the writer being tested. The artifact still needs independent compilation and inspection.

## Operation ownership

The route reports a random server instance. Requests also carry a fresh caller nonce. Only one
operation is retained per instance. Another nonce cannot replace it, including after failure.
A request with a previous instance is refused. Closing a shell stream or timing out does not
cancel an accepted operation, release a reservation or authorize a new request.

The operations are:

- `info`, identify this fixture instance without selecting anything.
- `select-new`, capture one exact installed selection when there is no discovered binding.
- `select-rebind`, capture a new selection decision for one discovered PENDING binding.
- `prepare`, apply the test caller's decision to that original selection.
- `commit`, call the writer with that original handle.
- `status`, observe retained operation metadata without calling the writer.

Except `info`, requests carry the server instance and caller nonce. There are no package, user,
UID or signer arguments. Selection checks the fixed test package's development signer and version.
Its app ID and user serial come from PMS and UserManager, not constants supplied by the caller.
The `select-new` observation is not a general atomic creation claim. The lab must record its initial
state and remain the only native designation producer. The manager still performs its actual
installed subject and hold checks at preparation.

The fixture marks an operation in flight before calling the manager. Concurrent requests report
that state and do not queue another call. Writer I/O runs outside the fixture monitor, and no
native Stop lane is involved. The normal manager return is recorded before later metadata reads.
A later observation failure cannot erase a returned handle or an acknowledged durable commit.
A newer uncertain confirmation also retains the historical positive acknowledgement. Every
admitted attempt has a monotonic number. Replies identify the attempt that produced their cached
observation and each acknowledgement. The final response is captured before another attempt can
start. Preparation cannot be requested after the first commit attempt. Refusals use fixed codes,
including the current instance when an old instance is rejected.

A failed or exceptional prepare may have issued a pin before a handle became available. The
original selection and request stay retained. Retrying that selection may still refuse. The
fixture does not invent a replacement handle or repair that tail. Rebinding must return the same
handle object and complete record discovered before preparation. A mismatch after preparation
retains both the original and unexpected handles and blocks further advancement, rather than
reporting a harmless refusal. A failed rebind observation also blocks commit until the original
prepare operation can confirm the complete comparison.

## Limits

The first host checks exercise the actual manager and store with Android API facades. They cover
caller checks, stale instances, retained nonces, source selection, uncertain writes, original
handle retry, concurrent replies, PENDING restoration and explicit rebinding. A package private
call adapter injects wrapper failures while forwarding to real manager handles. It checks missing
prepare results, abnormal exits, observation failures after acknowledgements and mismatched
handles or records. This adapter is not an alternate production writer. They do not
prove Android caller authentication, SELinux behavior, filesystem durability or crash recovery.

A device run can qualify the real writer path, same instance retry and metadata restoration for
this case. A clean restart is not power loss or a mid publication crash test. Partial CREATING
records and retirement tails remain held until an actual owned continuation exists. There is no
command here that fabricates that ownership or completes retirement.

The external lab ledger must retain the instance, nonce, selected subject, original record,
store lineage and exact image/APK producers. A `Slot` does not record that a test created it.
Shell exit status alone is not a commit acknowledgement. A missing reply remains unknown.
