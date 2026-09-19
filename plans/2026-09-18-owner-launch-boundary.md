# Ordinary owner launch boundary

Status: the selected launcher at `fbccb19` completed its [first finite Android trial](2026-09-19-owner-launch-qualification.md),
including ordinary owner execution and cleanup controls. It is not a new public work API
or CE fault qualification. Existing Console/plain/Keep entry remains unchanged.

## Goal and ownership

Run an ordinary executable with arguments, environment, working directory and declared
streams inside its exact admitted work scope. Android owns the enclosing environment;
Andrix owns the work identity, original CE epoch, creator and cleanup obligations. A
fixed trusted bootstrap owns every credential/profile/descriptor transition internally.
Neither an arbitrary privileged exec nor separately callable credential/resource setters
are introduced. Owner code must not receive coordinator control handles.

## Inspected constraints

The existing private policy permits only `andrixd` to enter `andrix_owner` through a
fixed image entrypoint. Dynamic transition into the owner domain and coordinator
execution of writable owner files are forbidden. Those boundaries are retained.

Same Unix UID does not imply a safe bootstrap handoff. Owner programs deliberately have
debugging authority within their domain. The pinned kernel `3ec022196c4e` resets dumpability on
exec for matching UIDs/GIDs. Its `fs/exec.c` explicitly does not use `secureexec` alone
for that decision. A SELinux exec transition therefore must not be assumed to protect a
new bootstrap in the owner role before its first userspace hardening instruction.

A real unprivileged Linux test compared readable, execute-only, then readable fixed
bootstraps. Execute-only caused initial dumpability zero without a userspace setter;
inspection of the inherited control FD and process memory failed. Final readable exec
restored normal debugging after the control descriptors were closed. That is kernel
mechanism evidence, not Android MAC, immutable image metadata or a launcher qualification.

## Chosen first launch vehicle

Keep admission authority in a fixed image coordinator role bootstrap:

1. Reserve and bind the original trusted work/CE epoch before asynchronous payload
   creation. Allocate its exact resource scope. Retain every late creator obligation.
2. Create the fixed trusted launcher, with an empty bootstrap environment and only its
   declared private handoff. No owner supplied executable or environment is used here.
3. Place the still-owned child in the actual work scope while its numeric identity is
   pinned, or prove an atomic create-into-scope mechanism. Do not use an unpinned PID.
4. In the trusted launcher, verify actual UID/groups/capabilities, resource identity and
   bounds. Install the owner worker syscall filter and `no_new_privs` before leaving
   the trusted role. A complete staging acknowledgement names the original work/epoch.
5. Publish and claim the original atomic gate. A queued wake is not permission. Stop
   before the claim prevents entry; Stop after it still terminates the exact scope.
6. Close/unmap the gate, coordinator channel, resource descriptors and every other
   management handle. Retain only declared standard streams and an immutable ordinary
   launch description. Reject stream aliases of management objects.
7. Exec the fixed owner entrypoint. The kernel performs the already declared transition
   to `andrix_owner`, now with the filter and no new privileges state inherited. The
   entrypoint verifies its actual final profile before executing any owner program.
8. Close the launch description FD. Apply the owner's cwd and environment only now,
   then exec the requested program. No implicit shell evaluation or executable whitelist
   is imposed on ordinary execution. MAC and the protected aggregate remain authoritative.

The selected policy must explicitly permit this fixed `andrixd` to `andrix_owner` exec
transition under `no_new_privs`. The pinned kernel supports that through
`process2 nnp_transition`; it is not a dynamic transition or an exemption from existing
neverallows. The no new privileges state is never cleared, file capability/set ID gains remain
blocked, and the owner filter is installed earlier rather than delayed until after the
role crossing. Actual Android behavior, including loaded policy, must prove this.

Readiness terminology must remain precise. The coordinator role launcher is verified
and prepared for the fixed final transition at gate commitment. The final owner role is
verified after that kernel exec and before the arbitrary program. Neither a spawn return,
readiness label nor an EOF is a claim that the ordinary program successfully executed.
Errors keep the exact work and cleanup obligations; they do not reopen the gate.

## Alternatives and costs

- Passing a writable gate into the ordinary owner role before protection would expose
  supervisor authority to inspection by other code belonging to the owner. Do not rely on `AT_SECURE` for dumpability.
- An execute-only image bootstrap can provide kernel-established protection. It also
  depends on trusted image permissions and safe `fs.suid_dumpable` configuration. The
  coordinator cannot read generic `proc_security` under the accepted policy. Adding an
  init attestation path solely for this layout is avoidable, so it is not chosen here.
- Keeping a separate guardian in the trusted role for every work can avoid gate exposure,
  but adds a lasting process and another control/reap/resource boundary per work. It is
  an alternative to evaluate, not an inherited product process count requirement.
- Dynamic relabeling or granting the coordinator owner-data execution would weaken the
  deliberate boundary and is rejected.

The chosen path costs an additional fixed exec step, a narrowly declared NNP transition,
immutable request transport and descriptor auditing. It removes control authority before
owner-domain debugging can apply. Work scopes are not mutual isolation of code belonging to the same owner;
that does not permit tampering with the coordinator's authority or bypassing admission.

## Description and first gates

`LaunchDescription` contains only ordinary executable/argv/environment/cwd data. Its
versioned bounded byte format preserves raw non-NUL strings, empty arguments, environment
order and LD_* values. A sealed memfd makes the accepted request immutable. Those values
must not become the trusted bootstrap's startup environment. The parser exposes no UID,
SID, capability, resource path or supervisor descriptor selector.

First qualify the descriptor/profile/NNP transition with a fixed headless vehicle, genuine
UID/SID and ordinary-application negatives. Then exercise arbitrary owner program launch,
queued release and Stop, blocked creation across genuine CE revoke/regrant, detached
children, independent work and complete cleanup. Resource creation and reaping must have
one explicit owner; release permission is not cleanup completion. Terminal presentation
comes after this headless boundary works.

Revisit the helper arrangement if creation I/O blocks independent control, final profile
verification cannot be completed without exposing authority, a supported platform cannot
perform the fixed NNP transition, or the process/descriptor costs exceed the declared
bounds. Preserve failures rather than weakening a check to fit this vehicle.
