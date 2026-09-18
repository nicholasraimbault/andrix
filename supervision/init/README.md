# Optional Android service adapter

**Status:** normal/selected module, policy and complete image gates passed at `40696f3`,
following the earlier actual parser and LMKD transport tests. The first fresh Android
trial reached captured LMKD registration but failed before full service readiness:
SELinux rejected re-executing init and reading the readiness socket's backing label.
That failed run is retained. The worker/channel/event retirement correction and bounded
directory ownership takeback passed module, policy and complete image gates at `c11e707`.
A second Android run kept the bootstrap held and terminated its exact process on worker
failure, but did not reach full readiness. The signal profile incorrectly asked Bionic
to reset SIGKILL/SIGSTOP. The current correction excludes those uncatchable signals,
keeps descriptor census failure distinct from spawn status 127, and handles a cancelled
activation read without dereferencing an error. It needs a fresh Android result.
No complete Android lifecycle result is claimed. The signal correction at `b05d656`
passed 400 host tests, selected Android module/policy checks, five actual init parser/event
tests and the frozen LMKD transport test. Its new Bionic signal controls are compiled,
not executed. No matching new complete image or Android trial is claimed for that fix.

`integration.patch` targets the pinned `system/core` revision and file hashes in
`integration-inputs.json`. Apply it only for the selected GrapheneOS Cuttlefish debug
proof, then restore the source before normal builds. `ANDRIX_DELEGATED_SERVICE_PROOF`
is separate from the old scope/factory/fault vehicles. It remains off by default.
No ordinary service changes its lifecycle merely because the native library exists.

## First supported boundary

A trusted named service definition selects `delegated_scope` and declares memory,
swap, descendant and depth bounds. The first profile subset requires an explicit
nonzero UID, matching primary GID, empty capability profile, SELinux context and bounded
rlimits. It rejects unsupported options before activation. In particular, temporary
exec services, reap callbacks, console/gentle kill, updatable/override and PID derived memcg options are
not supported by this proof. These are qualification limits, not permanent owner work
restrictions or a finished generic init syntax.

The platform owns an exclusive namespace and a fresh instance named root, not a reused
UID/PID path. It retains the aggregate controls and migration ancestors. The fixed
bootstrap receives a root descriptor, instance identity and readiness socket. Its
control leaf and delegated work subtree have distinct ownership. The gate requires the
actual initial child UID/GID, SID and captured root identity; a copied number is not
readiness authority.

Cleanup runs through the fixed `/system_ext/bin/andrix-scope-cleaner 3` bootstrap with its
own `andrix_scope_cleanup` SELinux transition. It does not broaden `init_exec` execution
permission. Dedicated socket labels separate cleanup and readiness traffic from ordinary
coordinator sockets. Init holds the initial child's existing activation FIFO until the
cleanup worker has actually initialized.

The worker profile is root UID/GID, no supplementary groups, only `CHOWN` in
permitted/effective/bounding sets, empty inheritable/ambient caps, no new privileges,
zero core files, bounded FDs/CPU and reduced priority. SETGID/SETPCAP are declared internal
initialization steps and are removed before any cleanup command is accepted. The worker
checks its actual identity, limits, capability sets and closed descriptor set. It accepts
captured kernel objects, never owner programs or caller selected privileged credentials.
This is a candidate process layout, not an adopted product process count. After fresh
quiescence, [directory retirement](../../plans/2026-09-18-directory-retirement.md) takes
back verified cgroup directory ownership and mode through held descriptors. General DAC
override and unlabeled proc reads remain prohibited.

## Lifecycle integration

The adapter must cover all of these, not just add a thread to `Service::Reap`:

- Capture the instance and staged process before asynchronous work can outlive setup.
  A definite failure without a process/root is not fabricated exit or removal evidence.
- Unpublish the initial numeric PID before releasing its zombie lifetime pin. LMKD
  unregister happens while that pin still exists. Later signals use captured objects.
- Keep cleanup records independent of mutable service restart fields. Start, Restart,
  timeout, stop/reset, parser override and service deletion respect the old instance.
- Keep init's critical loop progressing through bounded private IPC and deadline events.
  Timeout retains an occupied worker slot. Only actual worker exit/reap permits recovery.
- Reconcile lost replies through original captured descriptors, not a new pathname.
- Finalize restart policy and publication only after scope cleanup and worker retirement.
  Reap callbacks that rely on the old PID pin need a separate semantics extension and
  are excluded here. Existing callback and exec behavior remains unchanged for ordinary
  services; neither is silently reinterpreted as whole scope completion.
- Pump owned stopping scopes during shutdown waits without changing unrelated services.

LMKD must receive the same captured process/resource identity rather than reconstructing
an old UID/PID path. The companion patch adds that registration and incarnation qualified
removal, including existing service registration after connection recovery. A selected
memory test command invokes LMKD's real reaper for a matching service; it is not a real
memory pressure test or a production API.

The event lane retains each retired descriptor number until init's actual Epoll has
erased its deferred handler. An identity checked callback alone does not make early FD
reuse safe for that registry. Communication ends immediately through socket shutdown;
physical FD close follows dispatch. Provider failure also stops the exact known initial
process, without pretending its aggregate resource has been reclaimed.

The exact instance Stop builtin is an internal trusted init action, not a general
application API. The lab worker fault control is restricted to the matching instance
and selected debug build. Work IDs, CE authorization, owner command descriptions and
terminal policy remain outside init.

The cleanup constants and maximum simultaneous proof instances are bounded vehicle
settings. They are not product quotas. Service/bootstrap, policy, normal exclusion,
blocked worker, recovery and complete Android runtime controls still need qualification.
