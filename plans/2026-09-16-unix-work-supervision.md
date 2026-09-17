# Unix work supervision: design candidate and proof matrix

**Initial design/proof checkpoint:** not a replacement implementation or a new accepted
process layout. Ten focused Linux host experiments exercised kernel and selected shell
behavior. Android implementation source was inspected separately. That host suite passed
354 tests, followed by ten additional repetitions of all ten process cases, 100 more
case executions. That pass introduced no Android image/runtime result, permissions,
resource policy, notification behavior or public API. The subsequent separately gated
scope experiment and its status are linked below.

This follows the [owner direction](../docs/architecture.md#design-method) and
[register R05 through R10](../docs/design-evidence.md#r05-work-and-terminal-lifetime).
The [existing prototype results](2026-09-16-work-terminal-separation.md) keep their
original qualification. In particular, the `1571c7b` UI correction still needs a fresh
Android runtime result. Tests below do not supply that result.

## 1. Observable contract

These requirements derive from the accepted Unix direction. They are not assertions
that every shell has identical policy or that every process survives hangup.

| Event | Required distinction |
| --- | --- |
| Open a work list or inspect metadata | Observe only. Do not launch a shell, grant execution, renew terminal access or select a replacement identity. |
| Explicitly start work | Create one identifiable request and a supervised work scope. A terminal is optional. |
| Hide a view, lose focus, relock, detach, or lose Console | Revoke that attachment and its queued input. This is not a terminal hangup or whole-work Stop. |
| Explicit Close terminal | Retire the exact terminal transport and perform real hangup. Normal kernel, shell and program signal dispositions apply. No automatic replacement shell. |
| Shell/entry process exits | Record its actual result. Do not add an Andrix blanket kill of remaining detached descendants. |
| `command &` | Ordinary shell background execution, not a promise of survival after hangup. |
| `nohup`, shell `disown`, `setsid`, tmux | Preserve their actual and distinct Unix semantics. They neither escape resource accounting nor confer Android authority. |
| Explicit Stop work | Irreversibly stop the exact scope, including detached descendants. Acceptance is not completed cleanup or storage durability. |
| Genuine Android user/CE authority loss or stale authority | Close launch/input gates and stop affected work. A late positive cannot revive the old identity. |
| Resource failure or supervisor failure | Report the failure and apply qualified cleanup policy. Do not disguise lost work as a successful command or restart it silently. |
| Reboot | Ordinary jobs end. Separately enabled services and their recovery policies are later work. |

A Unix process group is a job-control and signal-routing object. A session is a terminal
relationship. Neither is the authoritative Android resource/cleanup scope. Several
shell jobs may share a work scope; they are not automatically separate resource or
security domains. Programs deliberately run as the same owner can interact according
to that identity's permissions. Strong isolation for untrusted principals is separate.

## 2. Proposed responsibility model

The following is a design candidate to test, not a decision to preserve the present
coordinator classes or add this exact set of processes.

- **Android work registry:** owns explicit requests, work identities, admission state,
  resource policy and exact control capabilities. It does not run owner commands or
  parse terminal escape sequences under system authority.
- **Per-work lifetime guardian:** supervises one owned payload scope, observes real
  child exits and platform authority, and remains while detached descendants remain.
  Its failure must have an Android owned complete cleanup path independent of the UI.
- **Owner execution entry:** crosses into the owner domain, fixes inherited authority
  and descriptors, and executes the requested owner program. Arguments are not a shell
  command string unless the owner explicitly selected a shell command.
- **Terminal state/transport:** owns the PTY and presentation identity, with an explicit
  recovery contract. A work scope may have no terminal. A multiplexer is an owner tool,
  not an execution grant or a requirement for every detached program.
- **Attachment:** owns a particular client connection, parser/snapshot identity and
  foreground/unlocked read/input authority. It cannot extend work authority.

A work ID, admission/request identity, terminal ID and attachment generation remain
separate. Android platform epochs and caller registrations are also separate fences.
Names can resolve new work; a previously captured control handle cannot retarget it.
A PID or a reusable service name alone is not the work identity.

An entry process's exit status and the scope's final outcome are different results.
For example, the entry shell can have exited while a detached child is still running.
Do not invent a successful final scope status from the shell's status. Under a healthy
subreaper and a closed launch gate, `ECHILD` is useful process-tree evidence. It is not
an acknowledgement that Android removed a cgroup or durably committed files.

## 3. Proposed admission and control ordering

The current synchronous Attach/New kept calls couple creation, external admission and
presentation. A separate UI executor alone does not resolve all of those races.

1. **Reserve:** a short authenticated operation returns an exact work control handle
   and a reserved identity. It starts no owner payload and performs no external I/O
   under the registry lock. Unused reservations are bounded and can expire.
2. **Start:** the owner submits a bounded immutable launch description through that
   handle. Accept it at most once and publish an observable admitting state before
   asynchronous external operations. A lost reply means unknown outcome to inspect,
   not permission to submit a duplicate launch.
3. **Admit:** validate actual user/CE authority, resource budget and the trusted scope
   factory. The execution gate stays closed while any prerequisite is missing. Do not
   hold registry, lifecycle or storage locks across Binder, notifications or filesystem I/O.
4. **Create and release:** create the trusted scope first, bind its actual identity,
   apply and read back bounds, arrange descriptors, and only then release owner execution.
   Recheck cancellation and platform epochs at that release boundary.
5. **Cancel/Stop:** accept it in reserved, admitting, starting and running states. A
   monotonic stopping state defeats every late grant or launch completion. Late-created
   helpers must be cleaned up; they must not claim a new request accidentally.
6. **Finish:** retain a bounded terminal result/tombstone through required cleanup.
   Never recycle the identity to represent fresh work. Report cleanup completion from
   the authoritative observer, not merely from a Binder return or guardian disappearance.

Once Start has been accepted as an explicit owner request, UI navigation or process
reclamation is not cancellation. Unsubmitted reservations can be retired without
running work. This separates an abandoned UI preparation from an accepted job that
should continue. Explicit cancellation always remains effective, including before a
slow admission finishes.

Control operations need a bounded path independent of launch and terminal I/O. Stop
must not queue behind a blocked admission RPC or need its mutex. Binder thread counts
and a synchronous call wrapped in a timer are not cancellation mechanisms. A stuck
helper must not exhaust an unbounded pool of replacement threads. Test actual blocked
calls and failure containment before choosing the worker/executor mechanism.

Console cannot be the only eventual programming interface. A mediated Unix control
interface is a candidate for owner tools; it would require a scoped authenticated
crossing, not worker access to arbitrary Android Binder services or cgroup files.
The exact API, wire format and permission changes are not chosen in this pass.

## 4. What the Android source actually supplies

Inspected source anchors in the pinned foundation:

| Source | Inspected behavior | Consequence for design |
| --- | --- | --- |
| `system/core` at `84ebea5e21110f31b632473a2fdb1c656b599b24`, `init/service.cpp`, `Service::Start` and `RunService` | Child waits on an activation FIFO while init creates its group and applies configured controls before execution. | Preserve admission before payload execution; merely checking limits after a payload runs is too late. |
| Same source, `init/sigchld_handler.cpp`, `ReapOneProcess` | `waitid(... WNOWAIT)` leaves a dead service PID unreaped until `Service::Reap` and group cleanup have run. The comment explicitly identifies PID reuse risk. | Lifetime pinning through cleanup is part of the guarantee. Do not reap first and issue delayed numeric PID/PGID cleanup later. |
| Same source, `init/service.cpp`, `Service::Reap` / `KillProcessGroup` | Qualified current services are killed as complete groups on service reap. Temporary services are removed from the service list after reap handling. | An init owned lifetime guardian is a useful candidate, but arbitrary grandchildren are not automatically registered init services. |
| Same source, `libprocessgroup/processgroup.cpp` and `task_profiles.cpp`, `createProcessGroup` / `ConvertUidPidToPath` | Creation computes a UID/PID group under the hierarchy, creates it and writes the PID to `cgroup.procs`. For the current reserved UID, that is under `system/uid_*`. It does not create a nested child of the caller's group. | Moving a job there changes the cleanup topology. The existing parent's init cleanup must not be assumed to cover a new sibling group. |
| Same source, `sendSignalToProcessGroup` / `KillProcessGroup` | Even with `cgroup.kill`, code also signals the numeric process group. Cleanup observes `cgroup.events` and has a finite bound. `RemoveCgroup` removes the named directory, not an arbitrary nested directory tree. | A raw UID/PID wrapper is not a safe stale-handle API. Nested scopes also need explicit kernel/fallback and directory cleanup qualification. |
| Same source, `init/init.cpp`, `HandleControlMessage` | `ctl.start` and interface control resolve existing service entries. | They are not an existing parameterized work factory. |
| Same source, `init/builtins.cpp` / `service.cpp`, `do_exec_background` and `MakeTemporaryOneshotService` | Init can create a temporary service for an init command. It parses identity and fixed executable arguments; it does not expose all named-service resource/profile configuration through that command. | This is a factory experiment candidate, not proof that a production Binder work factory or bootstrap resource contract already exists. |
| `frameworks/base` at `aab06a8bd44c4c2b58eeec780fde83baa9d43a40`, `core/jni/android_util_Process.cpp` | Framework process-group entry points delegate to native process-group operations. | API availability does not supply request identity, authorization or safe scope lifetime ownership. |
| `external/mksh` at `71d564487c9b34f65961570073f037658e07eb06`, `src/jobs.c::j_exit` and `src/main.c` | Job exit handling distinguishes stopped/foreground jobs and login/`FNOHUP` state; startup initializes `FNOHUP`. | Host Bash results cannot define Android shell behavior. Test the actual shell and options separately. |

A subsequent source check found a stronger obstacle to using `exec_background` unchanged:
`MakeTemporaryOneshotService` leaves the capability field absent. The nonroot fallback in
`SetProcessAttributesAndCaps` calls `DropInheritableCaps`, which clears inheritable flags,
not the bounding set. In contrast, a named service's explicit empty `capabilities` field
selects `SetCapsForExec(empty)`, including bounding-set removal. The existing owner identity
guard requires every capability set, including the bounding set, to be zero. Do not relax
that guard or grant a helper capabilities to make the shortcut work.

The first [Android scope boundary experiment](../tests/owner-scope/README.md) therefore
uses two fixed named init slots with complete inherited profiles. It can test independent
cleanup, held execution, slot reuse and stale handles, but it is not a dynamic factory.
A general factory must preserve the complete trusted profile and qualify its bootstrap.
No Android execution of the discarded temporary-service draft is claimed.

These are source observations, not new Android executions or adopted framework patches.
The [current guards](../owner/native/guards.cpp) and [policy](../owner/sepolicy/andrix_owner.te)
require protected Android resource controls and forbid worker cgroup writes/Binder access.
A new mechanism must preserve those outcomes, not simply delete admission checks.

### Backend candidates and decision gate

| Candidate | Useful property | Unproved or unsuitable part |
| --- | --- | --- |
| Android registry plus one init owned guardian/group per work | Fits exact lifetime ownership and independent complete Stop; detached children need not determine the guardian's lifetime. | Needs a genuine bounded scope factory, bootstrap limits, identity handoff and cleanup after cancelled or failed creation. A serialized property trigger alone is not an acknowledged work request protocol. |
| Registry plus nested work groups inside an init owned aggregate scope | Could retain an aggregate failure boundary and separate work accounting. | Current create/kill helpers are not a nested-scope API. Must prove controller activation, trusted control ownership, recursive kill and directory cleanup without worker write authority. |
| Fixed pool of named init services | Can provide a small experimental comparison using already declared service profiles. | A fixed proof slot count is not the final general purpose model. Reusing a slot must not reuse identity or let old Stop affect new work. |
| Only fork children in the present shared group | Needs fewer implementation changes. | Cannot independently enforce complete per-work Stop/resource policy by merely tracking PIDs or Unix process groups. Not sufficient as the final multiple-work design. |

**Candidate to investigate first:** an Android registry with init owned per-work guardians.
This preference is based on the observed cleanup/identity mechanism, not a commitment to
keep today's `andrixd` or add a generic privileged exec API. A small scope-factory experiment
must settle resource admission, bootstrap limits and failed-creation cleanup before adopting
it. Compare nested scopes if they offer a more coherent qualified boundary. Do not choose
based on the smaller patch alone.

## 5. Terminal state, streams and indication

The first host probes show why ignoring hangup is not a retained terminal: the process
can survive while writes to its old PTY fail. Likewise, keeping one duplicate master
open keeps the terminal alive. PTY ownership and all trusted duplicates need an explicit
Close-terminal contract; a UI lease is not that descriptor lifetime.

Work output can be ordinary files or pipes. A terminal view additionally needs coherent
VT state. The present bounded tail does not reconstruct a lost parser. Persistent terminal
state outside the Activity and fresh multiplexer redraw are distinct candidates; neither
may be silently substituted for the other's identity/history. Keep untrusted terminal
parsing outside the component holding broad Android authority. Do not expose a new direct
terminal recovery mode before defining snapshots, gaps, resize and input eligibility.

Ordinary work inspection and exact Stop must exist independently of an optional notice.
How notifications express active work and respect muted/blocked channels is still design
work. Do not silently reinterpret the current optional Keep channel as permission for all
Unix computing. Retention, notification visibility, locked terminal access, automatic
restart and wake authority remain different decisions.

## 6. Proof matrix

`Host observed` below means the current [real process fixture](../tests/owner-work-lifetime/README.md),
not a mock Android lifecycle, a complete work manager or phone qualification. It includes
actual PTYs, fork/exec, signals, wait results and the production worker filter on Linux.
The selected shell is GNU Bash with explicit startup/options and redirected job streams.

| ID | Question/control | Current evidence | Required next level |
| --- | --- | --- | --- |
| U01 | Last PTY master closes with default HUP disposition | Host observed SIGHUP wait status | ARM64/Bionic and actual terminal engine |
| U02 | One of two master FDs closes | Host positive ping/output while duplicate survives, then last-close HUP | Descriptor ownership in the chosen Android transport |
| U03 | Program ignores HUP | Host process survives but old PTY write returns EIO | Android owner program with explicit output recovery |
| U04 | Native parent exits | Host child survives, parent-death signal cleared across fork, subreaper adopts; ECHILD only after child exit/reap | Android guardian and additional descendant topologies |
| U05 | Child creates new session and redirects streams | Host child survives root exit/hangup, observed cgroup membership unchanged | Actual Android group controls and complete Stop |
| U06 | Tracked shell background job, physical hangup | Selected host Bash job ends; actual wait status checked when available | Current Android shell, options and job table behavior |
| U07 | `nohup` background job, hangup | Host GNU nohup produces inherited SIG_IGN; child/file output survive | Android utility and ABI qualification |
| U08 | `disown` background job, hangup | Host Bash child retains default HUP disposition yet survives after removal from job table | Chosen owner shells; do not invent a builtin where absent |
| U09 | Nonlogin shell exit with huponexit off | Host child survives normal shell exit and writes its output file | Android shell/profile and natural scope completion |
| U10 | Login shell exit with huponexit on | Host child ends after actual shell exit | Shell-specific test, not a proposed Andrix default |
| C01 | Reserve then cancel before Start | Contract only | Actual registry state tests; no owner exec marker |
| C02 | Accepted Start with lost reply/UI death | Contract only | Exactly one launch or explicit failed state, discoverable by exact handle |
| C03 | Stop during blocked admission, then late successful reply | Fixed Android trial stops a held entry and refuses late release; this is not a blocked external admission RPC | General independent control, closed execution gate and actual cleanup |
| C04 | Two scopes, one Stop, detached descendants | Fixed named-slot Android trial observed init SIGKILL/group removal for A with fresh B output | Carry the same boundary into the general factory and resource policy |
| C05 | Guardian dies during creation or while work lives | Deliberate nonzero guardian exit and held-entry cancellation checked in fixed Android slots | General factory/registry failure injection and hung/abnormal failure cases |
| C06 | PID/service slot reused after old scope ends | Service slot reuse with new identity, dead old Binder and rejected old ID checked in Android; numeric PID reuse was not forced | General registry identities, delayed callbacks and PID reuse controls |
| C07 | Forking, double forks, descendant reparenting and scope emptiness | Simple host adoption observed; broader cases open | Exact group membership and natural completion under the chosen guardian |
| C08 | Cancelled helper arrives after a new request | Contract only | No retargeting, leak or premature resource-account release |
| C09 | Record/queue/descriptor exhaustion | Not exercised for a new supervisor | Bounded rejection/cleanup without creating unaccounted work |
| A01 | Ordinary app and owner worker attempt privileged control | Fixed scope trial checked compiled policy, actual UID/MAC, worker filter/cgroup denial and ordinary-app negatives with live positives | Requalify each new general factory crossing and transferred-handle cases |
| A02 | CE loss, delayed reply, platform replacement/death | Existing source-specific trials only | Repeat against the selected supervisor; no late resurrection |
| A03 | Reconnect after parser loss/output overflow/resize | Existing tmux redraw and explicit gap behavior only | Selected direct-terminal state contract, locked UI and stale input controls |
| A04 | CPU/memory/FD/process/storage/suspend behavior | Current fixed proof profile only | Representative workloads and aggregate/per-work limits, then phone measurements |
| A05 | Notification blocked/hidden, locked Stop and no restart | Current Keep controls only | New indication/control policy without conflating notice and compute authority |
| A06 | ABI, artifact and full runtime | `0e60a42` fixed-slot source has matching modules/policy/images and a completed fresh Android trial | A general factory and changed product behavior require their own qualification |

The first fixture attempts failed before the login-shell lifetime action because the
observation FD did not survive exec. A syscall trace showed the selected login shell
marking auxiliary descriptors close-on-exec, including the attempted duplication. The
corrected fixture creates its private observation connection after exec and checks actual
peer credentials. Failed setup is not a death/hangup pass. The original attempts remain
separate evidence; no production shell policy was changed to make the probe pass.

The [fixed-slot Android result](../tests/owner-scope/README.md#observed-fixed-slot-result)
is now a separate evidence checkpoint. It also observed a denied parent-death SIGKILL
across the guardian/owner MAC boundary. No broader signal permission was added: actual
init group cleanup is the mechanism relied on. The completed run does not promote the
fixed slot count, property triggers or prototype API into the long term architecture.

## 7. Adoption sequence

1. Keep this behavioral contract and the register current as observations refine it.
2. Obtain a decision on the [profile factory proposal](2026-09-17-work-factory-proposal.md)
   before extending the privileged init launch interface. Then use bounded isolated tests
   of admission, exact identities, dynamic scopes and failure cleanup. Do not begin by
   widening owner cgroup control or grafting another flag onto Attach.
3. Choose and document the resource/cleanup backend, then implement reservation/admission
   and its independent control path with adversarial completion ordering tests.
4. Add command/stream entry and the chosen terminal state component. Compatibility adapters
   may remain temporarily, but they must not dictate the final architecture.
5. Run host, artifact and new Android runtime qualification. Replace old prototype modes
   only after their intended successor satisfies the contract. A new result never edits
   sealed old evidence or silently upgrades an incomplete fixture into a pass.
