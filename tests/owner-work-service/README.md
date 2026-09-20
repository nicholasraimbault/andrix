# Selected work service

This separately selected integration connects the registry, authenticated Unix crossing,
input catalog and captured resource backend. It does not replace Console or enable Keep,
history, network listeners or wake authority. See the
[design and qualification scope](../../plans/2026-09-20-work-service-integration.md).

`ANDRIX_OWNER_WORK_SERVICE_PROOF=true` requires the existing owner launch and delegated
service selections. The debug controller activates `andrix-work-manager` through the
generic init service, not by giving owner programs init control rights. A protected
property locates the manager; kernel peer authorization and exact environment references
remain required.

The candidate native interface is:

```
andrix-work run -- /absolute/program argument
andrix-work start --cwd /owner/project -- /absolute/program argument
andrix-work list
andrix-work info BOOT.ENVIRONMENT.MANAGER.WORK
andrix-work stop BOOT.ENVIRONMENT.MANAGER.WORK
andrix-work wait BOOT.ENVIRONMENT.MANAGER.WORK
andrix-work forget BOOT.ENVIRONMENT.MANAGER.WORK
andrix-work request-info BOOT.ENVIRONMENT.MANAGER.STREAM.SEQUENCE
andrix-work stream-close BOOT.ENVIRONMENT.MANAGER.STREAM.SEQUENCE
```

`run` waits for the initial process. `wait` waits for scope completion. Neither substitutes
for terminal job control, explicit hangup or general descriptor maps. Completed volatile
records have bounded capacity and explicit Forget; this is not a durable job database.

The [initial identity recovery slice](../../plans/2026-09-20-work-request-recovery.md) adds
request lookup without allocation, provisional unused stream cleanup on conversation loss,
and early request/work references on the CLI's stderr. This is volatile, best effort output,
not a durable receipt. `stream-close` closes the whole stream, not just one sequence, and
never substitutes for work Stop. These changes have host checks but are not in the earlier
qualified Android image. The component checks supply conversation end; actual new socket
loss and CLI controls remain to be run.

The Linux `runtime_kernel.py` driver refuses execution outside its exact owned delegation.
Its supplied epoch/profile cannot establish Android authority or MAC qualification.

`transport_probe.cpp` is an ordinary owner client, not a privileged helper or installed
service. It uses the real authenticated packet and operation libraries. Its host
`--self-test` checks codec/link inputs only. The Android exercise submits Prepare and Start
from a forked owner client without receiving their replies, kills that submitter through
its retained pidfd, and reconciles the original reference/input without new work retries.
It also checks retained controls after Forget, identity capacity until actual release,
old socket failure after manager retirement and raw stale namespace rejection by a new
service. It uses no public test hook, caller selected profile or weaker authorization.

The exercise starts with a known request stream and reserved work reference. It does not
qualify loss of the OpenStream/Reserve reply or recovery after losing all local request
identity. Streams still require explicit closure; there is no durable receipt claim.
The two management workers are also exercised as a barrier so an older conversation
cannot be an unobserved alternative pin during the retained control capacity check.

The [finite Android result](../../plans/2026-09-20-work-service-uncertain-replies.md) passes
against the matching `4829af5` service, with the probe compiled by the owner SDK in the
fresh guest. The earlier compilation observer deadline remains an incomplete attempt.
Printed booleans are assertions assessed alongside source, service/kernel/lifetime and
closure observations, not blanket transport, process reuse or phone proof.
