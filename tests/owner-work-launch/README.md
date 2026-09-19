# Ordinary owner launch vehicle

Selected only by `ANDRIX_OWNER_WORK_PROOF=true` together with the generic delegated
service proof, owner session and real lifecycle adapter. The surrounding selection
already requires the lab product and a debug build. This is not the public work API.
The separate [CE trial composition](../../plans/2026-09-19-owner-admission-ce-trial.md)
requires `ANDRIX_OWNER_WORK_CE_PROOF=true`, existing Keep and existing fixed fault controls.
Their active consent, caller, command and one use guards remain unchanged.

The fixed service receives the generic init scope. Two unbound gate reservations and
two creator/cleanup lanes are allocated before its public readiness. Each immutable
ordinary launch request binds its original real platform/user/authority epoch before
payload allocation. Work IDs cannot be reused in the manager incarnation. The two slot
limit and single use records are finite vehicle bounds, not product quotas.

The control loop authenticates actual Shell UID/GID/SID. Its work state locks cover only
bounded metadata. Resource allocation, fork, placement, launch IPC, output reads, reaping,
cgroup kill and reclamation run on the work's separate lane. Stop closes the gate before
replying; it does not claim that a blocked kernel operation or cleanup already completed.
There is no worker replacement after a timeout. Blocked requests retain exact handles
and namespace obligations until enclosing Android service cleanup.

A creator is the sole reaper of its own direct child. Placement uses the still-owned
child PID while it cannot be reused. Stop covers late creator completion. The fixed
launcher holds authority in `andrixd`, installs the owner filter and NNP, claims the
gate, then closes all management handles before the fixed exec transition to
`andrix_owner`. Only standard streams and a read only, write sealed ordinary description
cross that transition. The final entry checks its actual profile before arbitrary exec.
See the [boundary decision](../../plans/2026-09-18-owner-launch-boundary.md).

The lane records initial exit/reap separately from group population. Detached descendants
may survive ordinary entry exit. Explicit Stop uses captured recursive group kill, not
PID/PGID reconstruction. Reclamation requires creator cessation, an accounted initial
process or explicit never-created fact, and fresh Empty. Removed resource handles are
closed before reporting retirement. No final physical accounting claim is made.

Controls are `inspect`, `start`, `release`, `continue`, `stop` and the selected fault
`exit-manager`. The latter exits the actual manager with status 37 while Android retains
complete enclosing cleanup responsibility. It is not graceful work shutdown. The
readiness field is diagnostic; every start still obtains fresh trusted admission.
`start` accepts encoded
ordinary executable/argv/env/cwd data, not a privileged executable or credential choice.
Arguments include argv[0], with no implicit shell or PATH search. Identical retries
return the original work state; conflicting descriptions are refused. Discovery uses
`BOOT.INSTANCE.0`; mutating commands require the returned exact manager reference.
Kernel credentials, not any of those numbers, authorize the lab caller.

The snapshot's output is a bounded diagnostic tail, not complete stream delivery or a
persistent transcript. `output_bytes` counts received bytes and `output_size` declares
the retained window. Protocol version 2 refuses old peers and serializes all retained
bytes, including NUL. JSON code points 0 through 255 represent byte values, so consumers
can recover bytes with a Latin-1 mapping rather than assuming UTF-8. The earlier client
silently truncated this window at a NUL during the CE trial. Fixing that observer does
not change admission, execution or cleanup policy.

Fault flags deliberately distinguish their scope:

- `HoldCreation` holds a completion after real fork and placement. It does not claim an
  uninterruptible fork or storage fault. Stop remains responsive and late completion
  cannot release payload code.
- `HoldRelease` leaves a verified trusted launcher waiting without execution permission.
- `QueueThenStop` actually stops that launcher, publishes and queues a wake, then waits
  for Stop. The controlled lane resumes it briefly to observe gate refusal before full
  captured cleanup. This is a finite ordering control, not a scheduler proof.

The ordinary APK negative probe can additionally take `work_launch_reference` with the
live `BOOT.INSTANCE`. It attempts the control endpoint, both fixed entry executables,
and exact service start/stop. Actual failed exec is distinguished from successfully
executing a helper that later refuses the caller. Matching positive controls before and
after are required. No absent endpoint is promoted to an authority denial.

Source `fbccb19` completed the [first finite Android owner launch trial](../../plans/2026-09-19-owner-launch-qualification.md)
with fresh matching images. Actual owner programs/profiles, application negatives,
queued wake rejection, independent work, detached lifetime and manager cleanup were
observed. Later [CE trials](../../plans/2026-09-19-owner-admission-ce-trial.md) observed
real withdrawal, original request refusal after normal PIN regrant, and fresh owner
execution in a new epoch. The fourth scripted trial still failed on the diagnostic
client's NUL truncation, before its final planned hierarchy census. Its useful results
and failure remain separate. The corrected full CE sequence, broader failures and the
public work/Console API remain unqualified. Source or compilation alone supplies none
of those runtime results.
