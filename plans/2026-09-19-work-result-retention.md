# Work result retention for the first public API

Status: proposal, awaiting owner input. This does not change the accepted supervision
contract or current Console behavior.

## Goal and fixed requirements

The next step after the finite launch and CE trials is the real work registry and
client API. It must preserve exact request identity, independent Stop, ordinary Unix
lifetimes and truthful completion observations. Console loss must not end accepted work
or require recreating it. An identical retry must refer to the original request, not
silently allocate replacement work.

Android owns the enclosing environment and its cleanup. Andrix owns work records and
client authorization. Work numbers and copied metadata are not caller authentication.
Stopping, entry exit, surviving descendants, scope quiescence, reclamation and physical
accounting remain separate facts. Neither option below authorizes automatic restart.
Owner files and explicitly redirected output remain independent of work metadata.

The accepted contract scopes reservations to a manager epoch and requires bounded
results without identity reuse. It does not yet specify whether detailed work results
must survive coordinator restart or reboot. That affects both the public promise and
the storage design, not just an internal container choice.

## Proposed first contract: records tied to one manager incarnation

Keep active work records and bounded completion records in the manager. They survive
Console reclamation and rediscovery while that manager remains alive. Define explicit
forgetting or bounded retention for completed records, with backpressure rather than
unbounded storage or reused identities. Active work and uncertain cleanup retain their
ownership regardless of result retention.

When the manager is lost, report that its detailed results are unavailable. Do not
invent an exit code or claim completed cleanup from the missing endpoint. The enclosing
Android instance still owns termination and retirement; replacement remains fenced by
that cleanup. Old references never become references to replacement work. Starting again
requires a fresh explicit request under genuine current authority.

This is the recommendation for the first public API. It keeps the initial contract
honest without adding a durable storage subsystem to the execution path. It does not
delete saved files when a result is forgotten. It also does not promise a durable job
history: a completed build's exit status may be lost with the manager even when its
output files remain.

## Alternative: durable work history from the first API

Persist accepted request identities and confirmed results in a bounded journal. This
could preserve useful receipts after manager loss or reboot. It would not resurrect
processes, replay an old admission or prove an unrecorded exit code. Recovery must still
distinguish confirmed facts from interrupted transitions and unknown outcomes.

This requires a defined durable acceptance point, CE storage ownership, crash recovery,
format migration, retention quotas and deliberate handling of sensitive launch data.
Filesystem operations must remain outside Stop's control path. A stalled writer keeps
its bounded outstanding obligation; a timeout cannot manufacture a durable result or
allow unsafe reuse. Real storage and power loss tests would be additional gates.

A journal can be the right product choice, but it is not already supplied by the terminal
journal, ordinary output files or the passed finite CE trial. Adding it silently would
also create a durability promise that the current evidence cannot support.

## Evidence, failure behavior and revisit point

The finite trials establish useful execution and cleanup behavior within observed
incarnations. The fresh manager after CE recovery intentionally starts with new work,
not reconstructed old work. The earlier diagnostic output defect also shows why received
output, process exit and stored results cannot be treated as one fact.

The first option costs loss of detailed history on coordinator failure. The second costs
more persistent state, storage failure handling and qualification before its acceptance
promise can be reliable. Neither option weakens CE revocation, exact Stop or the final
cleanup boundary.

Choose before committing the public result and retry contract. Revisit the first option
when durable receipts become a requirement for owner workflows, automation or later
remote clients. A future journal must not reinterpret previously unavailable results as
confirmed success, or turn retained descriptions into permission to restart work.

**Owner question:** may the first public API keep results through Console loss but report
them unavailable after coordinator restart, with durable history added later, or is
persistence across coordinator restart and reboot required from the start?
