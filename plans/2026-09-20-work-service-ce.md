# Work service CE withdrawal and recovery

Status: the listed finite Android controls pass at `4829af5`, using its matching selected
image and fresh emulator state. No implementation, policy, fault guard or default Console
behavior changed for this trial.

This extends the [work service runtime result](2026-09-20-work-service-runtime.md). It
qualifies genuine credential storage withdrawal for accepted work through the new service,
not every pending admission or recovery race.

## Method and authority

The existing approved `lock-ce-user0` lab command remained unchanged. Its debug Shell,
primary user, active Keep and single use guards stayed enabled. A fresh credential was
created through normal Android setup. A normal SystemUI PIN unlock succeeded before the
fault sequence. Keep was then explicitly enabled through Console, and remained active after
Console was absent. Screen relock did not itself withdraw CE availability.

An ordinary native owner caller submitted two work items through the new service. One
initial process remained live. The other exited zero while its detached child continued.
Both live owner processes held an open CE file. Before the fault, the collector captured
accepted work identities, genuine platform generation, actual process contexts and cgroup
membership. The submitting caller environment retired separately.

This preparation matters because the new manager exits on lifecycle failure. Its catalog
and terminal results are volatile. Neither a stale locator property nor a missing reply
can reconstruct those records or prove cleanup.

## Observations

- The real Android storage operation changed genuine availability from true to false and
  advanced the authority generation. Normal credential recovery later made the same new
  generation available again. Boot, system server identity/start time and platform
  instance bookends matched.
- The old manager exited zero after withdrawal. Android retired its exact enclosing
  environment. Independent reads found the old manager, live initial process and detached
  child absent, and the old scope was removed.
- Crucially, the exact old retirement was observed before any explicit Stop request for
  the new service. Stop did not manufacture the CE termination result.
- Generic init attempted replacement while CE remained unavailable. The selected service
  is disabled initially, but is not oneshot. Once started, its normal restart policy can
  run after retirement without waiting for PIN recovery. A replacement briefly activated
  and then exited. No ordinary work was submitted to those negative window replacements.
- Only after old retirement was established did the collector use ordinary init Stop to
  quiesce further replacement attempts. The owned hierarchy was then independently empty
  while genuine CE availability remained false.
- Normal SystemUI PIN recovery restored genuine availability. A fresh environment and
  actual native owner handshake succeeded with empty discovery. A locator alone was not
  accepted as this positive control.
- Connections to both old abstract endpoints returned `ECONNREFUSED`. Separately, the CLI
  refused the old environment reference before sending it to the new service. This is not
  a raw stale protocol replay control.
- Fresh owner work carried the restored generation, read the saved CE marker and returned
  complete output, including an embedded NUL and following marker. Initial exit, scope
  reclamation and runtime retirement completed. The final owned hierarchy was empty.

Android/vold also reported files still open after key removal. That observation is retained.
It does not establish complete physical key eviction, and it must not be converted into a
claim that retained file descriptors or filesystem metadata supplied execution authority.

## Assessment and implications

Primary assessment checked the raw numbered operations, genuine lifecycle observations,
independent process samples, stopped init/vold logs, exact retirement before explicit Stop,
normal keypad recovery, fresh owner output, matched frozen inputs and completed fixture
shutdown. The initial UI readiness timeout before creating a kept terminal remains recorded;
no text or fault was submitted by that failed readiness check. Normal owner interaction then
established the required consent. The storage fault was invoked once, not retried.

An independent source review identified the volatile record and restart implications before
the run. It was not runtime clearance. Collector ordering checks used supplied facts and
remain distinct from the Android observations.

The result supports the ownership boundary: genuine Android authority revokes admission,
the manager does not revive its old epoch, and Android owns complete enclosing retirement.
Init still knows no Andrix work IDs or CE policy. Generic activation and public discovery
remain distinct from permission to execute ordinary work. Manager replacement also does
not silently restart ordinary jobs or restore volatile results.

## Remaining gates

This trial did not force pending reservation, delayed creation or entry across CE recovery.
It does not qualify uncertain Start replies, retained stale control sockets, raw stale
request transport, broader storage failure, suspend/pressure or physical phones. The
[earlier fixed vehicle CE result](2026-09-19-owner-admission-ce-trial.md) retains its own
scope and does not fill those new service gaps.

Next qualify uncertain submissions and retained controls, actual Console/isolated callers,
additional descriptor types and complete terminal behavior. Minimal protected diagnostics
remain separate work. Persistent activity/output history is still off and unimplemented.
Existing plain/Keep and Console paths remain until their replacement qualifies.
