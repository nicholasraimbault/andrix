# Work result retention for the first public API

Status: the owner accepted separate controls for live supervision, minimal security
records, optional durable work history and output capture after discussion and
[online source review](2026-09-19-logging-defaults-review.md). The default policy is recorded
in the [architecture](../docs/architecture.md#work-records-and-diagnostics). Exact retention
values, optional durability commitments and implementation remain open. This does not
change current Console behavior.

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

## Live records tied to one manager incarnation

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

This remains the baseline when persistent work history is disabled. It keeps the
execution contract honest without making a history store mandatory. It does not delete
saved files when a result is forgotten. It also does not promise durable job history:
a completed build's exit status may be lost with the manager even when its output files
remain. Optional persistence is a separate capability, not a source of live authority.

## Optional durable work history

Persist accepted request identities and confirmed results in a bounded journal. This
could preserve useful receipts after manager loss or reboot. It would not resurrect
processes, replay an old admission or prove an unrecorded exit code. Recovery must still
distinguish confirmed facts from interrupted transitions and unknown outcomes.

This requires declared persistence and acknowledgement semantics, CE storage ownership,
crash recovery, format migration, retention quotas and deliberate handling of sensitive
launch data. A promise of durable submission additionally requires a durable acceptance
point; merely retaining observed history does not imply that stronger promise.
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

Disabling persistence costs loss of detailed history on coordinator failure. Enabling
it costs persistent state, storage failure handling and qualification before any durable
receipt promise can be reliable. Neither mode weakens CE revocation, exact Stop or the
final cleanup boundary.

The accepted default is no persistent work activity history, with explicit owner control
to enable it. Minimal security records have a different purpose and event catalogue;
they must not silently reproduce disabled work history. Strong durable acceptance or
completion receipts need their own declared commitment point and qualification before
the public API promises them.

Define those promises before committing the public result and retry contract. A journal
must not reinterpret previously unavailable results as confirmed success, or turn
retained descriptions into permission to restart work. The source review also leaves
retention values open pending workload, privacy and investigation requirements.
