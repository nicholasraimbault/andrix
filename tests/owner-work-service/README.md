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
```

`run` waits for the initial process. `wait` waits for scope completion. Neither substitutes
for terminal job control, explicit hangup or general descriptor maps. Completed volatile
records have bounded capacity and explicit Forget; this is not a durable job database.

The Linux `runtime_kernel.py` driver refuses execution outside its exact owned delegation.
Its supplied epoch/profile cannot establish Android authority or MAC qualification.
